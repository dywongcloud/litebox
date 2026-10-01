// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! NETFIX (spec section 4.3): the network worker's park/wake primitive on macOS.
//!
//! One kqueue, created before the Seatbelt sandbox is installed, carries every reason the
//! network worker has to run:
//!
//! * an `EVFILT_USER` doorbell (ident 0, `EV_CLEAR`) that guest and host threads ring through
//!   [`NetDoorbell::notify`] when they hand the worker work (a socket-channel mark, a `Network`
//!   operation's kick, a NAT dial completing);
//! * the `utun` device, and every NAT host socket (TCP streams once their dial completes, UDP
//!   flow sockets), each registered `EVFILT_READ` with `EV_CLEAR`.
//!
//! The host-socket registrations are deliberately edge-triggered here even though the NAT engine
//! keeps its own *level-triggered* kqueue for its O(ready) read scan: a stream whose data the
//! engine is holding back (the guest-side window is full) stays readable, and a level-triggered
//! registration in the worker's park would turn that back-pressure into a busy loop. Edge
//! semantics wake the worker once per arrival; the stack's own progress (the guest reading,
//! window updates, ACKs) wakes it for the rest, and the runner's safety cap bounds the rest.
//!
//! The worker parks with [`NetDoorbell::wait`]. Lost-wake-up freedom (spec 4.5): `wait` clears
//! `wake_pending` right after `kevent` returns -- before the poll that follows -- and `notify`
//! issues the trigger only on the `false -> true` transition of that flag. Every `true` the worker
//! can observe after its clear was set by a notifier that then issued a trigger, and a trigger
//! posted while the worker is not blocked stays pending in the kernel (`EV_CLEAR` resets the user
//! event only when a `kevent` call returns it), so the next park returns at once.

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicBool, Ordering};

use litebox::platform::NetworkWait;

/// The identifier of the doorbell's `EVFILT_USER` event.
const DOORBELL_IDENT: usize = 0;

/// Events collected per `kevent` call; more pending events are returned by the next park, which
/// then returns at once.
const WAIT_EVENTS: usize = 64;

/// See the module documentation.
pub struct NetDoorbell {
    kq: OwnedFd,
    /// A trigger has been issued since the worker last returned from `wait`.
    wake_pending: AtomicBool,
}

fn empty_kevent() -> libc::kevent {
    libc::kevent {
        ident: 0,
        filter: 0,
        flags: 0,
        fflags: 0,
        data: 0,
        udata: std::ptr::null_mut(),
    }
}

impl NetDoorbell {
    /// Create the kqueue and arm the doorbell.
    ///
    /// # Errors
    ///
    /// The `kqueue`/`kevent` error if either system call fails.
    pub fn new() -> std::io::Result<Self> {
        // SAFETY: plain system call; a non-negative return is a fresh descriptor we own.
        let kq = unsafe { libc::kqueue() };
        if kq < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: `kq` is a valid descriptor exclusively owned from here on.
        let kq = unsafe { OwnedFd::from_raw_fd(kq) };
        let doorbell = Self {
            kq,
            wake_pending: AtomicBool::new(false),
        };
        let mut change = empty_kevent();
        change.ident = DOORBELL_IDENT;
        change.filter = libc::EVFILT_USER;
        change.flags = libc::EV_ADD | libc::EV_CLEAR;
        doorbell.apply(&change)?;
        Ok(doorbell)
    }

    fn apply(&self, change: &libc::kevent) -> std::io::Result<()> {
        // SAFETY: one initialized change record, no event list, no timeout; `kq` is ours.
        let rc = unsafe {
            libc::kevent(
                self.kq.as_raw_fd(),
                change,
                1,
                std::ptr::null_mut(),
                0,
                std::ptr::null(),
            )
        };
        if rc < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    /// Wake the worker when `fd` becomes readable (edge-triggered; see the module docs). The
    /// registration dies with the descriptor. Returns whether the kernel accepted it.
    pub fn watch_readable(&self, fd: RawFd) -> bool {
        let Ok(ident) = usize::try_from(fd) else {
            return false;
        };
        let mut change = empty_kevent();
        change.ident = ident;
        change.filter = libc::EVFILT_READ;
        change.flags = libc::EV_ADD | libc::EV_CLEAR;
        self.apply(&change).is_ok()
    }

    /// Ring the doorbell. Callable from any thread with any lock held; at most one system call
    /// per park cycle of the worker, however many threads ring.
    pub fn notify(&self) {
        if self.wake_pending.swap(true, Ordering::AcqRel) {
            return;
        }
        let mut change = empty_kevent();
        change.ident = DOORBELL_IDENT;
        change.filter = libc::EVFILT_USER;
        change.fflags = libc::NOTE_TRIGGER;
        // A failure here (only possible if the kqueue were gone) leaves the worker to its safety
        // cap; there is nothing better to do from an arbitrary caller.
        let _ = self.apply(&change);
    }

    /// Park until the doorbell rings, a watched descriptor becomes readable, or `timeout` passes
    /// (`None`: no timeout).
    pub fn wait(&self, timeout: Option<core::time::Duration>) -> NetworkWait {
        let mut events = [empty_kevent(); WAIT_EVENTS];
        let ts = timeout.map(|t| libc::timespec {
            tv_sec: libc::time_t::try_from(t.as_secs()).unwrap_or(libc::time_t::MAX),
            tv_nsec: libc::c_long::from(t.subsec_nanos()),
        });
        let ts_ptr = ts
            .as_ref()
            .map_or(std::ptr::null(), core::ptr::from_ref::<libc::timespec>);
        // SAFETY: no change list; `events` is an exclusively borrowed array of `WAIT_EVENTS`
        // records; `ts` outlives the call.
        let n = unsafe {
            libc::kevent(
                self.kq.as_raw_fd(),
                std::ptr::null(),
                0,
                events.as_mut_ptr(),
                i32::try_from(WAIT_EVENTS).unwrap(),
                ts_ptr,
            )
        };
        // W0 of the next cycle (see the module docs): after the wait, before the poll.
        self.wake_pending.store(false, Ordering::SeqCst);
        let Ok(n) = usize::try_from(n) else {
            // EINTR (a guest signal delivered to this host thread) or a kqueue failure: report a
            // timeout, which makes the caller poll -- never wrong, at worst early.
            return NetworkWait::TimedOut;
        };
        if n == 0 {
            return NetworkWait::TimedOut;
        }
        if events[..n]
            .iter()
            .any(|event| event.filter == libc::EVFILT_USER)
        {
            NetworkWait::Woken
        } else {
            NetworkWait::PacketReady
        }
    }

    /// The kqueue descriptor, for the host-only `--net-wake-probe` witness.
    #[must_use]
    pub fn raw_fd(&self) -> RawFd {
        self.kq.as_raw_fd()
    }
}
