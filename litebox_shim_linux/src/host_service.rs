// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Host-owned sockets inside the guest's network stack.
//!
//! [`crate::transport::ShimTransport`] lets *host* code dial out through the guest's smoltcp
//! stack; this module is the listening-side counterpart: a host-owned TCP listener at an
//! address the guest can reach (its loopback, typically), whose accepted connections the host
//! services directly. The sockets live in the litebox descriptor table for proxy/metadata
//! purposes but are never entered in any guest process's fd table, so they are invisible to
//! the guest program.
//!
//! Everything here is non-blocking: the runner drives its service loop alongside
//! `perform_network_interaction`, polling `try_accept`/`try_read`/`try_write` between stack
//! ticks. That keeps this module free of any `WaitState`/`Task` association.

use alloc::boxed::Box;
use alloc::sync::Arc;

use litebox::net::socket_channel::{ChannelReadError, ChannelWriteError, NetworkProxy};
use litebox::net::{ReceiveFlags, SendFlags};
use litebox_common_linux::{SockFlags, SockType, errno::Errno};

use crate::syscalls::net::SocketFd;
use crate::{GlobalState, ShimFS, ShimPlatform};
use litebox::net::socket_channel::SocketState;

/// Erases the `FS` generic from the operations that need [`GlobalState`] (socket create /
/// accept / close), so [`GuestListener`] and [`GuestStream`] are generic over `Platform` only,
/// like `ShimTransport`.
trait ListenerOps<Platform: ShimPlatform>: Send + Sync {
    fn try_accept(&self) -> Option<GuestStream<Platform>>;
    fn close(&mut self);
}

struct ListenerImpl<Platform: ShimPlatform, FS: ShimFS> {
    global: Arc<GlobalState<Platform, FS>>,
    sockfd: Option<SocketFd<Platform>>,
}

impl<Platform: ShimPlatform, FS: ShimFS> ListenerOps<Platform> for ListenerImpl<Platform, FS> {
    fn try_accept(&self) -> Option<GuestStream<Platform>> {
        let sockfd = self.sockfd.as_ref()?;
        let accepted = self.global.net.lock().accept(sockfd, None).ok()?;
        let proxy = self
            .global
            .initialize_socket(&accepted, SockType::Stream, SockFlags::empty());
        proxy.set_state(SocketState::Connected);
        Some(GuestStream {
            proxy,
            drop_guard: Box::new(StreamDropGuard {
                global: self.global.clone(),
                sockfd: Some(accepted),
            }),
        })
    }

    fn close(&mut self) {
        if let Some(sockfd) = self.sockfd.take() {
            let _ = self
                .global
                .net
                .lock()
                .close(&sockfd, litebox::net::CloseBehavior::Immediate);
        }
    }
}

/// See [`ListenerOps`]; the stream's close path needs the same erasure.
trait StreamOps: Send + Sync {
    fn close(&mut self, graceful: bool);
}

struct StreamDropGuard<Platform: ShimPlatform, FS: ShimFS> {
    global: Arc<GlobalState<Platform, FS>>,
    sockfd: Option<SocketFd<Platform>>,
}

impl<Platform: ShimPlatform, FS: ShimFS> StreamOps for StreamDropGuard<Platform, FS> {
    fn close(&mut self, graceful: bool) {
        if let Some(sockfd) = self.sockfd.take() {
            // NOT `CloseBehavior::Graceful`: that removes the descriptor entry -- and with it
            // the channel proxy -- immediately, so any bytes still sitting in the TX ring are
            // orphaned before the network worker can drain them to the wire (observed live as
            // an HTTP response the guest never received). `GracefulIfNoPendingData` instead
            // defers via `consider_closed` until the ring and send queue drain, which is the
            // flush-then-FIN a byte-stream close means here; its `DataPending` "error" is that
            // deferral, not a failure.
            let behavior = if graceful {
                litebox::net::CloseBehavior::GracefulIfNoPendingData
            } else {
                litebox::net::CloseBehavior::Immediate
            };
            let _ = self.global.net.lock().close(&sockfd, behavior);
        }
    }
}

/// A host-owned TCP listener inside the guest network stack. Created via
/// [`crate::LinuxShim::listen_in_guest`].
pub struct GuestListener<Platform: ShimPlatform> {
    ops: Box<dyn ListenerOps<Platform>>,
}

impl<Platform: ShimPlatform> GuestListener<Platform> {
    /// Accept one pending guest connection, if any. Never blocks.
    #[must_use]
    pub fn try_accept(&self) -> Option<GuestStream<Platform>> {
        self.ops.try_accept()
    }
}

impl<Platform: ShimPlatform> Drop for GuestListener<Platform> {
    fn drop(&mut self) {
        self.ops.close();
    }
}

/// One accepted guest connection, serviced by host code. All I/O is non-blocking.
pub struct GuestStream<Platform: ShimPlatform> {
    proxy: Arc<NetworkProxy<Platform>>,
    drop_guard: Box<dyn StreamOps>,
}

/// What [`GuestStream::try_read`] observed.
pub enum StreamRead {
    /// `n > 0` bytes were copied out.
    Data(usize),
    /// Nothing available right now; poll again after the next stack tick.
    Empty,
    /// The guest closed its end; no more data will ever arrive.
    Closed,
}

impl<Platform: ShimPlatform> GuestStream<Platform> {
    /// Non-blocking read of whatever the guest has sent.
    pub fn try_read(&self, buf: &mut [u8]) -> StreamRead {
        match self.proxy.try_read(buf, ReceiveFlags::empty(), None) {
            Ok(0) => StreamRead::Empty,
            Ok(n) => StreamRead::Data(n),
            Err(
                ChannelReadError::ConnectionClosed
                | ChannelReadError::ReadShutdown
                | ChannelReadError::NotConnected,
            ) => StreamRead::Closed,
        }
    }

    /// Non-blocking write toward the guest. `Some(n)` bytes were queued (possibly `0` when the
    /// TX ring is full); `None` means the connection is gone.
    pub fn try_write(&self, buf: &[u8]) -> Option<usize> {
        match self.proxy.try_write(buf, SendFlags::empty(), None) {
            Ok(n) => Some(n),
            Err(ChannelWriteError::BufferFull) => Some(0),
            Err(_) => None,
        }
    }

    /// Close this end: `graceful` flushes queued data and FINs; otherwise abortive.
    pub fn close(mut self, graceful: bool) {
        self.drop_guard.close(graceful);
    }
}

impl<Platform: ShimPlatform> Drop for GuestStream<Platform> {
    fn drop(&mut self) {
        self.drop_guard.close(true);
    }
}

/// Create a host-owned TCP listener bound to `addr` inside the guest network stack.
///
/// # Errors
///
/// Fails if the socket cannot be created, bound (e.g. the guest already owns the port), or
/// put into the listening state.
pub(crate) fn listen_in_guest<Platform: ShimPlatform, FS: ShimFS>(
    global: &Arc<GlobalState<Platform, FS>>,
    addr: core::net::SocketAddr,
    backlog: u16,
) -> Result<GuestListener<Platform>, Errno> {
    let sockfd = global
        .net
        .lock()
        .socket(litebox::net::Protocol::Tcp)
        .map_err(Errno::from)?;
    let _proxy = global.initialize_socket(&sockfd, SockType::Stream, SockFlags::empty());
    {
        let mut net = global.net.lock();
        net.bind(&sockfd, &addr).map_err(Errno::from)?;
        net.listen(&sockfd, backlog).map_err(Errno::from)?;
    }
    Ok(GuestListener {
        ops: Box::new(ListenerImpl {
            global: global.clone(),
            sockfd: Some(sockfd),
        }),
    })
}
