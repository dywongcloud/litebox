// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! NETFIX: the `Network`-owned registry of live socket descriptions (spec section 2).
//!
//! The network worker used to find the sockets it had to service by walking the process-global
//! descriptor table -- every descriptor of every guest process, twice per poll, under the table's
//! read guard and the Network mutex -- and that table never shrinks, so a long-lived desktop paid
//! for its peak descriptor count on every one of >= 1000 polls a second. The registry holds one
//! record per open socket *description* (the unit `dup`, `fork` and `SCM_RIGHTS` share), so the
//! worker's work is proportional to live sockets and never touches the table.
//!
//! A record holds a [`WeakEntryHandle`] on purpose: the descriptor layer reads an entry's strong
//! count as "descriptors (plus in-flight `SCM_RIGHTS` handles) that still name it" when it decides
//! whether a close is the last one, so a strong handle here would make every shared socket
//! unclosable. Records are created in `Network::new_socket_fd_for` and removed by
//! `Network::close_handle`, both under the Network mutex, which the worker also holds for its
//! whole poll, so the worker can never observe a record whose entry is already gone; a dead weak
//! handle is still handled (record dropped, `net.registry_dead_weak` counted).
//!
//! No lock of its own: every access happens through `&mut Network`.

use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use super::counters;
use super::wake::RegistryKey;
use crate::fd::WeakEntryHandle;
use crate::platform;
use crate::sync::RawSyncPrimitivesProvider;

pub(crate) struct RegistryRecord<Platform>
where
    Platform:
        platform::IPInterfaceProvider + platform::TimeProvider + RawSyncPrimitivesProvider,
{
    /// The open socket description. WEAK: see the module docs.
    pub(crate) entry: WeakEntryHandle<Platform, super::Network<Platform>>,
    /// Position of this record's key in `SocketRegistry::dense`.
    dense_index: u32,
    /// A deferred close (`consider_closed`) or a `SHUT_WR` FIN is waiting for the TX ring to
    /// drain; serviced on every poll while set.
    pending_close: bool,
    /// Descriptors of this description sitting in `Network::queued_for_closure`.
    queued: u32,
}

pub(crate) struct SocketRegistry<Platform>
where
    Platform:
        platform::IPInterfaceProvider + platform::TimeProvider + RawSyncPrimitivesProvider,
{
    /// Indexed by key; a key is reused after its record is removed.
    slots: Vec<Option<RegistryRecord<Platform>>>,
    /// Keys whose slot is free (removed, or reserved and never filled).
    free: Vec<RegistryKey>,
    /// The live keys, densely packed, so a full pass is O(live) however many sockets ever lived.
    dense: Vec<RegistryKey>,
    /// Live keys with `pending_close` set (small; O(pending) to service every poll).
    pending_close: Vec<RegistryKey>,
    /// Live keys with `queued > 0` (small; the queued-close pre-check walks only these).
    queued: Vec<RegistryKey>,
}

impl<Platform> SocketRegistry<Platform>
where
    Platform:
        platform::IPInterfaceProvider + platform::TimeProvider + RawSyncPrimitivesProvider,
{
    pub(crate) fn new() -> Self {
        Self {
            slots: Vec::new(),
            free: Vec::new(),
            dense: Vec::new(),
            pending_close: Vec::new(),
            queued: Vec::new(),
        }
    }

    /// Claim a key for a socket about to be inserted into the descriptor table (its `SocketHandle`
    /// carries the key, so the key must exist before the entry does); [`Self::fill`] completes it.
    pub(crate) fn reserve(&mut self) -> RegistryKey {
        if let Some(key) = self.free.pop() {
            return key;
        }
        let key = RegistryKey::try_from(self.slots.len()).expect("socket registry key space");
        self.slots.push(None);
        key
    }

    /// Complete a reserved key with the inserted entry's weak handle.
    pub(crate) fn fill(
        &mut self,
        key: RegistryKey,
        entry: WeakEntryHandle<Platform, super::Network<Platform>>,
    ) {
        let dense_index = u32::try_from(self.dense.len()).expect("socket registry size");
        let slot = &mut self.slots[key as usize];
        debug_assert!(slot.is_none(), "registry key filled twice");
        *slot = Some(RegistryRecord {
            entry,
            dense_index,
            pending_close: false,
            queued: 0,
        });
        self.dense.push(key);
        let live = self.dense.len() as u64;
        counters::REGISTRY_LIVE.store(live, Ordering::Relaxed);
        counters::REGISTRY_PEAK.fetch_max(live, Ordering::Relaxed);
    }

    /// Drop the record for `key` (its socket is being torn down). Idempotent.
    pub(crate) fn remove(&mut self, key: RegistryKey) {
        let Some(slot) = self.slots.get_mut(key as usize) else {
            return;
        };
        let Some(record) = slot.take() else {
            return;
        };
        let index = record.dense_index as usize;
        self.dense.swap_remove(index);
        if let Some(&moved) = self.dense.get(index) {
            if let Some(Some(moved_record)) = self.slots.get_mut(moved as usize) {
                moved_record.dense_index = u32::try_from(index).expect("socket registry size");
            }
        }
        if record.pending_close {
            self.pending_close.retain(|&k| k != key);
        }
        if record.queued > 0 {
            self.queued.retain(|&k| k != key);
        }
        self.free.push(key);
        counters::REGISTRY_LIVE.store(self.dense.len() as u64, Ordering::Relaxed);
        counters::PENDING_CLOSE_LIVE.store(self.pending_close.len() as u64, Ordering::Relaxed);
    }

    pub(crate) fn get(&self, key: RegistryKey) -> Option<&RegistryRecord<Platform>> {
        self.slots.get(key as usize)?.as_ref()
    }

    /// Every live key, for a full pass (copy it out first if the pass may remove records).
    pub(crate) fn live_keys(&self) -> &[RegistryKey] {
        &self.dense
    }

    /// Keys whose deferred close or `SHUT_WR` FIN is still waiting.
    pub(crate) fn pending_close_keys(&self) -> &[RegistryKey] {
        &self.pending_close
    }

    pub(crate) fn set_pending_close(&mut self, key: RegistryKey, pending: bool) {
        let Some(Some(record)) = self.slots.get_mut(key as usize) else {
            return;
        };
        if record.pending_close == pending {
            return;
        }
        record.pending_close = pending;
        if pending {
            self.pending_close.push(key);
        } else {
            self.pending_close.retain(|&k| k != key);
        }
        counters::PENDING_CLOSE_LIVE.store(self.pending_close.len() as u64, Ordering::Relaxed);
    }

    /// One more descriptor of `key`'s description was queued for a deferred last close.
    pub(crate) fn note_queued(&mut self, key: RegistryKey) {
        let Some(Some(record)) = self.slots.get_mut(key as usize) else {
            return;
        };
        if record.queued == 0 {
            self.queued.push(key);
        }
        record.queued += 1;
    }

    /// Whether some description has every one of its strong handles accounted for by queued
    /// descriptors, i.e. whether a drain of the queue would remove something. Cheap (no
    /// descriptor-table lock, O(descriptions with queued closes)) and conservative: an in-flight
    /// strong handle makes the count larger, which only delays the close (spec section 2.5).
    pub(crate) fn any_queued_close_complete(&self) -> bool {
        self.queued.iter().any(|&key| {
            self.get(key).is_some_and(|record| {
                record.queued as usize == record.entry.strong_count()
            })
        })
    }
}
