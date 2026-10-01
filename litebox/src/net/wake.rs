// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! NETFIX: the guest -> network-worker wake path (spec sections 3.2, 3.4, 4.5).
//!
//! A socket channel that gains work for the worker -- the guest pushed bytes into its TX ring,
//! or drained an RX ring the worker had left full -- *marks* itself: the first mark since the
//! worker last serviced that socket queues the socket's registry key on the [`NetWakeHook`]'s
//! dirty list and rings the platform's doorbell; later marks coalesce on the channel's own flag.
//! The worker takes the whole dirty list at the top of every poll and services exactly those
//! sockets, so a poll costs O(sockets with work) instead of a walk of every descriptor of every
//! guest process.
//!
//! No lost work (spec 3.4): the worker clears a channel's flag with an acquire-release swap
//! *before* it drains that channel's rings. A mark that happened before the clear is ordered
//! before the drain by that swap (the drain sees its bytes); a mark after the clear finds the flag
//! clear, queues the key again and rings the doorbell, so it is serviced by the next poll. There
//! is no interleaving in which bytes sit in a ring with the flag clear and no key queued.

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU32, Ordering};

use super::counters;
use crate::sync::{Mutex, RawSyncPrimitivesProvider};

/// Index of a socket description in the `Network`'s registry.
pub type RegistryKey = u32;

/// The key of a channel that was never attached to a registry (a `NetworkProxy::Raw`, or a
/// channel used outside a `Network`): marking it is a no-op.
pub const REGISTRY_NONE: RegistryKey = u32::MAX;

/// The per-`Network` dirty list plus the platform doorbell.
pub struct NetWakeHook<Platform: RawSyncPrimitivesProvider> {
    /// Registry keys marked since the worker last took the list. A leaf lock: nothing else is
    /// ever acquired while it is held, and it is held only for a push or a drain.
    dirty: Mutex<Platform, Vec<RegistryKey>>,
    /// Rings the worker's doorbell (`IPInterfaceProvider::notify_network_worker`). Boxed so that
    /// neither the channels nor this hook need the platform's network bound.
    notify: Box<dyn Fn() + Send + Sync>,
}

impl<Platform: RawSyncPrimitivesProvider> NetWakeHook<Platform> {
    /// A hook whose marks ring `notify`.
    #[must_use]
    pub fn new(notify: Box<dyn Fn() + Send + Sync>) -> Self {
        Self {
            dirty: Mutex::new(Vec::new()),
            notify,
        }
    }

    /// Queue `key` for the worker unless `flag` says it is already queued, and ring the doorbell
    /// on the queuing transition. Callable from any thread with any lock held except this hook's
    /// own list lock (a leaf).
    pub fn mark(&self, key: RegistryKey, flag: &AtomicBool) {
        if key == REGISTRY_NONE {
            return;
        }
        if flag.swap(true, Ordering::AcqRel) {
            counters::DIRTY_COALESCED.fetch_add(1, Ordering::Relaxed);
            return;
        }
        self.dirty.lock().push(key);
        counters::DIRTY_MARKS.fetch_add(1, Ordering::Relaxed);
        (self.notify)();
    }

    /// Clear a channel flag before servicing its socket (see the module docs for why this is a
    /// swap rather than a store).
    pub fn clear(flag: &AtomicBool) {
        let _ = flag.swap(false, Ordering::AcqRel);
    }

    /// Move every queued key into `into` (appended), leaving the list empty but keeping its
    /// capacity.
    pub fn drain_into(&self, into: &mut Vec<RegistryKey>) {
        let mut dirty = self.dirty.lock();
        into.extend(dirty.drain(..));
    }

    /// Ring the doorbell without queuing anything (a `Network` operation's kick).
    pub fn notify(&self) {
        (self.notify)();
    }
}

/// A socket channel's attachment to its `Network`'s wake path: the registry key it marks, its
/// coalescing flag, and the hook (set once, when `Network::set_socket_proxy` attaches it).
///
/// The hook is held as a raw `Arc` pointer so a mark on the guest's `write` path costs two atomic
/// loads and the flag swap, with no lock; the reference it represents is released in `Drop`.
pub(crate) struct ChannelWake<Platform: RawSyncPrimitivesProvider> {
    key: AtomicU32,
    dirty: AtomicBool,
    hook: AtomicPtr<NetWakeHook<Platform>>,
}

impl<Platform: RawSyncPrimitivesProvider> ChannelWake<Platform> {
    pub(crate) const fn new() -> Self {
        Self {
            key: AtomicU32::new(REGISTRY_NONE),
            dirty: AtomicBool::new(false),
            hook: AtomicPtr::new(core::ptr::null_mut()),
        }
    }

    /// Attach to `hook` as registry entry `key`. The first attachment wins; a later one is
    /// ignored (a description is registered exactly once).
    pub(crate) fn attach(&self, hook: &Arc<NetWakeHook<Platform>>, key: RegistryKey) {
        let raw = Arc::into_raw(Arc::clone(hook)).cast_mut();
        // The key is published before the pointer, and the pointer with release semantics, so a
        // marker that observes the hook also observes the key.
        self.key.store(key, Ordering::Relaxed);
        if self
            .hook
            .compare_exchange(
                core::ptr::null_mut(),
                raw,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            // SAFETY: `raw` came from `Arc::into_raw` just above and was never published.
            unsafe { drop(Arc::from_raw(raw)) };
        }
    }

    /// The channel gained work for the worker.
    pub(crate) fn mark(&self) {
        let hook = self.hook.load(Ordering::Acquire);
        if hook.is_null() {
            return;
        }
        // SAFETY: a non-null pointer here was published by `attach` from `Arc::into_raw`, and the
        // reference it represents is released only by `Drop`, which needs `&mut self` and so
        // cannot run concurrently with this `&self` method.
        let hook = unsafe { &*hook };
        hook.mark(self.key.load(Ordering::Relaxed), &self.dirty);
    }

    /// Called by the worker before it services the channel's socket.
    pub(crate) fn clear(&self) {
        NetWakeHook::<Platform>::clear(&self.dirty);
    }
}

impl<Platform: RawSyncPrimitivesProvider> Drop for ChannelWake<Platform> {
    fn drop(&mut self) {
        let hook = *self.hook.get_mut();
        if !hook.is_null() {
            // SAFETY: the pointer came from `Arc::into_raw` in `attach`, and this is the only
            // place that releases it.
            unsafe { drop(Arc::from_raw(hook)) };
        }
    }
}
