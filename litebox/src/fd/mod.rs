// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! File descriptors used in LiteBox

#![expect(
    dead_code,
    reason = "still under development, remove before merging PR"
)]

use alloc::sync::{Arc, Weak};
use alloc::vec;
use alloc::vec::Vec;
use core::marker::PhantomData;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use hashbrown::HashMap;
use thiserror::Error;

use crate::platform::DescriptorTableAccess;
use crate::sync::{RawSyncPrimitivesProvider, RwLock};
use crate::utilities::anymap::AnyMap;

#[cfg(test)]
mod tests;

/// NETFIX permanent guard: every walk of the whole process-global descriptor table names the
/// site that asked for it, so a new walk is a new variant that shows up in the `fd` counters
/// (`table_walks`) instead of silently becoming a per-poll cost again. The network worker used
/// to walk the table twice per poll (>= 1000 polls/s), which pegged a core on a long-lived
/// desktop because the table never shrinks; those two walks are gone, and their variants stay
/// listed (at zero) so a reader of the counters sees that they are gone rather than unlisted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WalkSite {
    /// `fs::layered` rebinding every open description of a lower inode that migrated to the
    /// upper layer: once per migration event, never per syscall.
    LayeredRebind,
    /// The retired `Network::close_pending_sockets` walk (per poll).
    NetClosePendingSockets,
    /// The retired `Network::drain_all_socket_channel_buffers` walk (per poll).
    NetDrainAllSocketChannels,
    /// A walk through [`Descriptors::iter`] / [`Descriptors::iter_mut`], which do not name a
    /// site; any non-zero value here is a walk somebody added without declaring it.
    Unattributed,
}

impl WalkSite {
    const ALL: [WalkSite; 4] = [
        WalkSite::LayeredRebind,
        WalkSite::NetClosePendingSockets,
        WalkSite::NetDrainAllSocketChannels,
        WalkSite::Unattributed,
    ];

    fn index(self) -> usize {
        match self {
            WalkSite::LayeredRebind => 0,
            WalkSite::NetClosePendingSockets => 1,
            WalkSite::NetDrainAllSocketChannels => 2,
            WalkSite::Unattributed => 3,
        }
    }

    fn name(self) -> &'static str {
        match self {
            WalkSite::LayeredRebind => "layered_rebind",
            WalkSite::NetClosePendingSockets => "net_close_pending_sockets",
            WalkSite::NetDrainAllSocketChannels => "net_drain_all_socket_channels",
            WalkSite::Unattributed => "unattributed",
        }
    }
}

/// Release counters for the descriptor table (NETFIX section 5.1). Plain relaxed statics: the
/// table is one per `LiteBox`, the slot counters are only changed under the table's write
/// guard, and the walk/guard counters are lock-free reads for `-Z --counters`.
mod counters {
    use core::sync::atomic::AtomicU64;

    /// Occupied slots right now (descriptors of every guest process plus host-owned ones).
    pub(super) static ENTRIES_LIVE: AtomicU64 = AtomicU64::new(0);
    /// Largest `ENTRIES_LIVE` ever observed.
    pub(super) static ENTRIES_PEAK: AtomicU64 = AtomicU64::new(0);
    /// `entries.len()`: slots ever allocated. The vector never shrinks, so this is the cost of
    /// any whole-table walk.
    pub(super) static TABLE_CAPACITY: AtomicU64 = AtomicU64::new(0);
    /// Slots filled by `insert_handle` / `duplicate`.
    pub(super) static INSERTS: AtomicU64 = AtomicU64::new(0);
    /// Slots examined by the linear free-slot scan of those two (inventory row S1).
    pub(super) static INSERT_SCAN_STEPS: AtomicU64 = AtomicU64::new(0);
    /// Slots emptied (`remove`, a unique close, a drained queued close).
    pub(super) static REMOVES: AtomicU64 = AtomicU64::new(0);
    pub(super) static TABLE_WALKS: [AtomicU64; 4] = [const { AtomicU64::new(0) }; 4];
    pub(super) static TABLE_WALK_ENTRIES: [AtomicU64; 4] = [const { AtomicU64::new(0) }; 4];
    /// The network worker took the table outside its one sanctioned scope. Must stay 0.
    pub(super) static NET_WORKER_TABLE_TAKES: AtomicU64 = AtomicU64::new(0);
    /// The network worker took the table inside the sanctioned queued-close drain.
    pub(super) static NET_WORKER_TABLE_TAKES_SANCTIONED: AtomicU64 = AtomicU64::new(0);
}

fn note_slot_filled(scan_steps: usize, capacity: usize) {
    let live = counters::ENTRIES_LIVE.fetch_add(1, Ordering::Relaxed) + 1;
    counters::ENTRIES_PEAK.fetch_max(live, Ordering::Relaxed);
    counters::INSERTS.fetch_add(1, Ordering::Relaxed);
    counters::INSERT_SCAN_STEPS.fetch_add(scan_steps as u64, Ordering::Relaxed);
    counters::TABLE_CAPACITY.store(capacity as u64, Ordering::Relaxed);
}

fn note_slot_emptied() {
    counters::ENTRIES_LIVE.fetch_sub(1, Ordering::Relaxed);
    counters::REMOVES.fetch_add(1, Ordering::Relaxed);
}

/// Called by [`crate::LiteBox::descriptor_table`] / `descriptor_table_mut` with the platform's
/// classification of the calling thread (NETFIX section 5.3). The network worker must never take
/// the global table: it is the lock every guest `open`/`close`/`socket`/`dup`/`fork` needs, and a
/// worker that held it on every poll stalled all of them. The one sanctioned exception is the
/// queued-close drain, which runs only when a removal is certain.
pub(crate) fn note_table_access(access: DescriptorTableAccess) {
    match access {
        DescriptorTableAccess::Ordinary => {}
        DescriptorTableAccess::NetworkWorker => {
            counters::NET_WORKER_TABLE_TAKES.fetch_add(1, Ordering::Relaxed);
            // Debug builds trap on the first violation; release builds keep the counter, which
            // every `-Z --counters` snapshot carries.
            #[cfg(debug_assertions)]
            panic!("NETFIX guard: the network worker took the global descriptor table");
        }
        DescriptorTableAccess::NetworkWorkerSanctioned => {
            counters::NET_WORKER_TABLE_TAKES_SANCTIONED.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// The `fd` block of the combined counters snapshot (`-Z --counters`, `/proc/litebox/counters`):
/// a complete JSON object.
#[must_use]
pub fn counters_json() -> alloc::string::String {
    use core::fmt::Write as _;
    let load = |c: &AtomicU64| c.load(Ordering::Relaxed);
    let mut out = alloc::string::String::new();
    let _ = write!(
        out,
        "{{\"entries_live\":{},\"entries_peak\":{},\"table_capacity\":{},\"inserts\":{},\"insert_scan_steps\":{},\"removes\":{},\"net_worker_table_takes\":{},\"net_worker_table_takes_sanctioned\":{},\"table_walks\":{{",
        load(&counters::ENTRIES_LIVE),
        load(&counters::ENTRIES_PEAK),
        load(&counters::TABLE_CAPACITY),
        load(&counters::INSERTS),
        load(&counters::INSERT_SCAN_STEPS),
        load(&counters::REMOVES),
        load(&counters::NET_WORKER_TABLE_TAKES),
        load(&counters::NET_WORKER_TABLE_TAKES_SANCTIONED),
    );
    for (i, site) in WalkSite::ALL.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        let _ = write!(
            out,
            "\"{}\":{}",
            site.name(),
            load(&counters::TABLE_WALKS[site.index()])
        );
    }
    out.push_str("},\"table_walk_entries\":{");
    for (i, site) in WalkSite::ALL.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        let _ = write!(
            out,
            "\"{}\":{}",
            site.name(),
            load(&counters::TABLE_WALK_ENTRIES[site.index()])
        );
    }
    out.push_str("}}");
    out
}

/// Storage of file descriptors and their entries.
pub struct Descriptors<Platform: RawSyncPrimitivesProvider> {
    entries: Vec<Option<IndividualEntry<Platform>>>,
}

impl<Platform: RawSyncPrimitivesProvider> Descriptors<Platform> {
    /// Explicitly crate-internal: Create a new empty descriptor table.
    ///
    /// This is expected to be invoked only by [`crate::LiteBox`]'s creation method, and should not
    /// be invoked anywhere else in the codebase.
    pub(crate) fn new_from_litebox_creation() -> Self {
        Self { entries: vec![] }
    }

    /// Insert `entry` into the descriptor table, returning an `OwnedFd` to this entry.
    #[must_use]
    pub fn insert<Subsystem: FdEnabledSubsystem>(
        &mut self,
        entry: impl Into<Subsystem::Entry>,
    ) -> TypedFd<Subsystem> {
        let entry = DescriptorEntry {
            entry: alloc::boxed::Box::new(entry.into()),
            metadata: AnyMap::new(),
        };
        self.insert_handle(EntryHandle(Arc::new(RwLock::new(entry)), PhantomData))
    }

    /// Insert another descriptor for an existing open file description.
    ///
    /// Entry-scoped state and metadata remain shared with the descriptor from which
    /// `handle` originated. Descriptor-scoped metadata is intentionally initialized
    /// empty, matching `dup(2)` and `SCM_RIGHTS` semantics.
    #[expect(
        clippy::missing_panics_doc,
        reason = "panics impossible due to type invariants"
    )]
    #[must_use]
    pub fn insert_handle<Subsystem: FdEnabledSubsystem>(
        &mut self,
        handle: EntryHandle<Platform, Subsystem>,
    ) -> TypedFd<Subsystem> {
        let EntryHandle(entry, PhantomData) = handle;
        let idx = self.free_slot();
        let old = self.entries[idx].replace(IndividualEntry::new(entry));
        assert!(old.is_none());
        TypedFd {
            _phantom: PhantomData,
            x: OwnedFd::new(idx),
        }
    }

    /// The lowest empty slot, appending one if every slot is occupied. Counted (inventory row
    /// S1): the scan is linear in the table's capacity and runs under the table's write guard.
    fn free_slot(&mut self) -> usize {
        let idx = self
            .entries
            .iter()
            .position(Option::is_none)
            .unwrap_or_else(|| {
                self.entries.push(None);
                self.entries.len() - 1
            });
        note_slot_filled(idx + 1, self.entries.len());
        idx
    }

    /// Create a duplicate of the provided `fd`.
    ///
    /// This newly-created FD shares all behavior with the existing FD, including (for example)
    /// offsets. Any metadata stored via [`Self::set_entry_metadata`] is (as expected) maintained as
    /// aliased metadata at the new FD. However, any metadata that was stored via
    /// [`Self::set_fd_metadata`] is **not** duplicated; if you want that data to be copied over to
    /// the new entry, you must copy it over yourself.
    ///
    /// If the fd has already been closed (potentially on a different thread), this duplication will
    /// fail and will return `None`.
    #[expect(
        clippy::missing_panics_doc,
        reason = "panic is impossible due to type invariants"
    )]
    pub fn duplicate<Subsystem: FdEnabledSubsystem>(
        &mut self,
        fd: &TypedFd<Subsystem>,
    ) -> Option<TypedFd<Subsystem>> {
        // Resolve the source before claiming a slot: a closed source used to leave a freshly
        // appended `None` behind and (now) would count a fill that never happened.
        let source = Arc::clone(&self.entries[fd.x.as_usize()?].as_ref().unwrap().x);
        let idx = self.free_slot();
        let new_ind_entry = IndividualEntry::new(source);
        let old = self.entries[idx].replace(new_ind_entry);
        assert!(old.is_none());
        Some(TypedFd {
            _phantom: PhantomData,
            x: OwnedFd::new(idx),
        })
    }

    /// Removes the entry at `fd`, closing out the file descriptor.
    ///
    /// Returns the descriptor entry if it is unique (i.e., it was not duplicated, or all duplicates
    /// have been cleared out).
    ///
    /// If the `fd` was already closed out, then (obviously) it does not return an entry.
    pub fn remove<Subsystem: FdEnabledSubsystem>(
        &mut self,
        fd: &TypedFd<Subsystem>,
    ) -> Option<Subsystem::Entry> {
        let Some(old) = self.entries[fd.x.as_usize()?].take() else {
            unreachable!();
        };
        note_slot_emptied();
        fd.x.mark_as_closed();
        Arc::into_inner(old.x)
            .map(RwLock::into_inner)
            .map(DescriptorEntry::into_subsystem_entry::<Subsystem>)
    }

    /// Reports whether `fd` is currently the only descriptor referencing its entry, i.e. whether
    /// removing/closing it right now would be that entry's true last close (the same
    /// strong-count check [`Self::remove`] and [`Self::close_and_duplicate_if_shared`] make
    /// internally). Returns `None` if `fd` is already closed.
    ///
    /// A plain point-in-time read with no side effect: calling it does not change what a
    /// subsequent `remove`/close on the same `fd` returns. A caller that also wants to read
    /// entry-scoped metadata (e.g. to learn what a true last close should release) should do so
    /// before the real close -- a unique entry's metadata does not survive it.
    pub fn is_unique_reference<Subsystem: FdEnabledSubsystem>(
        &self,
        fd: &TypedFd<Subsystem>,
    ) -> Option<bool> {
        Some(Arc::strong_count(&self.entries[fd.x.as_usize()?].as_ref()?.x) == 1)
    }

    /// Close the provided `fd`, and remove the corresponding entry if it is unique.
    /// If not unique, duplicate the `fd` for future closure.
    ///
    /// This method takes a closure `can_close_immediately` that is called with the entry to determine
    /// whether the file descriptor can be closed immediately. This allows the caller to implement
    /// custom logic (e.g., checking for pending data) before allowing the close to proceed.
    pub(crate) fn close_and_duplicate_if_shared<
        Subsystem: FdEnabledSubsystem,
        F: FnOnce(&Subsystem::Entry) -> bool,
    >(
        &mut self,
        fd: &TypedFd<Subsystem>,
        can_close_immediately: F,
    ) -> Option<CloseResult<Subsystem>> {
        let idx = fd.x.as_usize()?;
        let Some(old) = self.entries[idx].take() else {
            unreachable!();
        };
        if Arc::strong_count(&old.x) == 1 {
            // Unique, so we can just return it if allowed.
            if can_close_immediately(old.x.read().as_subsystem::<Subsystem>()) {
                note_slot_emptied();
                fd.x.mark_as_closed();
                let entry = Arc::into_inner(old.x)
                    .map(RwLock::into_inner)
                    .map(DescriptorEntry::into_subsystem_entry::<Subsystem>)
                    .unwrap();
                Some(CloseResult::Closed(entry))
            } else {
                // Put it back
                let old = self.entries[idx].replace(old);
                assert!(old.is_none());
                Some(CloseResult::Deferred)
            }
        } else {
            fd.x.mark_as_closed();
            // Shared, so we need to duplicate it.
            let old = self.entries[idx].replace(old);
            assert!(old.is_none());
            Some(CloseResult::Duplicated(TypedFd {
                _phantom: PhantomData,
                x: OwnedFd::new(idx),
            }))
        }
    }

    /// Drain all entries that are fully accounted for by the `fds`, removing those FDs from `fd`s,
    /// and returning their corresponding entries.
    ///
    /// This is similar to [`Self::remove`] except it allows draining a whole collection of FDs,
    /// which is helpful if there are duplicated FDs in the mix. This is particularly useful if one
    /// is unsure if there are ongoing operations on some entries in the FD, and thus wants to delay
    /// some sort of `close` operation.
    ///
    /// No ordering guarantees are provided by this function; the resulting entries can be
    /// arbitrarily ordered.
    ///
    /// If an FD remains in `fds` after this function finishes running, then it is guaranteed to
    /// have at least one other duplicate floating around and still accessing an entry somewhere
    /// outside of `fds`; if an entry is returned, then all possible FDs to it have been removed
    /// removed from `fds` (and no other operation was concurrently accessing an entry).
    pub(crate) fn drain_entries_full_covered_by<Subsystem: FdEnabledSubsystem>(
        &mut self,
        fds: &mut Vec<TypedFd<Subsystem>>,
    ) -> Vec<Subsystem::Entry> {
        // Each FD corresponds to an `IndividualEntry`, which has an Arc to a `DescriptorEntry`. If
        // we have the same number of FDs as matching to the strong-count of a descriptor entry,
        // then it must be the case that we have everything needed to close the entries out.
        let removable_entries: Vec<*const RwLock<_, _>> = {
            let mut strong_count_and_count = HashMap::<*const _, (usize, usize)>::new();
            for fd in fds.iter() {
                let entry = &self.entries[fd.x.as_usize().unwrap()];
                // It would not be "incorrect" to see a closed out entry, but as it currently stands, I
                // believe that we'll only see alive entries, so this `unwrap` is confirming that; if we
                // need to expand it out, we'd simply have a `continue` here.
                let entry = entry.as_ref().unwrap();
                strong_count_and_count
                    .entry(Arc::as_ptr(&entry.x))
                    .or_insert((Arc::strong_count(&entry.x), 0))
                    .1 += 1;
            }
            strong_count_and_count
                .into_iter()
                .filter(|(_ptr, (sc, c))| sc == c)
                .map(|(ptr, _)| ptr)
                .collect()
        };
        // Now we can actually go and remove every single such FD.
        let entries: Vec<Subsystem::Entry> = {
            let mut entries = vec![];
            fds.retain(|fd: &TypedFd<Subsystem>| {
                let entry = &self.entries[fd.x.as_usize().unwrap()];
                let entry = entry.as_ref().unwrap();
                let entry_ptr = Arc::as_ptr(&entry.x);
                if !removable_entries.contains(&entry_ptr) {
                    return true;
                }
                // This FD is removable
                let entry = self.remove(fd);
                if let Some(entry) = entry {
                    // This is the last of the individual entries that were holding a ref to this.
                    entries.push(entry);
                }
                false
            });
            entries
        };
        debug_assert_eq!(entries.len(), removable_entries.len());
        entries
    }

    /// Record one whole-table walk for `site` (NETFIX guard), together with the number of slots
    /// it is about to visit.
    fn note_walk(&self, site: WalkSite) {
        counters::TABLE_WALKS[site.index()].fetch_add(1, Ordering::Relaxed);
        counters::TABLE_WALK_ENTRIES[site.index()]
            .fetch_add(self.entries.len() as u64, Ordering::Relaxed);
    }

    /// An iterator of descriptors and entries for a subsystem
    ///
    /// Note: each of the entries take locks, thus should not be held on to for too long, in order
    /// to prevent dead-locks.
    ///
    /// Visits every slot of the process-global table: prefer [`Self::iter_at`], which names the
    /// caller in the `fd.table_walks` counters; this one is counted as `unattributed`.
    pub(crate) fn iter<Subsystem: FdEnabledSubsystem>(
        &self,
    ) -> impl Iterator<Item = (InternalFd, impl core::ops::Deref<Target = Subsystem::Entry>)> {
        self.iter_at::<Subsystem>(WalkSite::Unattributed)
    }

    /// [`Self::iter`], attributed to `site` in the `fd.table_walks` counters.
    pub(crate) fn iter_at<Subsystem: FdEnabledSubsystem>(
        &self,
        site: WalkSite,
    ) -> impl Iterator<Item = (InternalFd, impl core::ops::Deref<Target = Subsystem::Entry>)> {
        self.note_walk(site);
        self.entries.iter().enumerate().filter_map(|(i, entry)| {
            entry.as_ref().and_then(|e| {
                let entry = e.read();
                if entry.matches_subsystem::<Subsystem>() {
                    Some((
                        InternalFd {
                            raw: i.try_into().unwrap(),
                        },
                        crate::sync::RwLockReadGuard::map(entry, |e| e.as_subsystem::<Subsystem>()),
                    ))
                } else {
                    None
                }
            })
        })
    }

    /// An iterator of descriptors and (mutable) entries for a subsystem
    ///
    /// Note: each of the entries take locks, thus should not be held on to for too long, in order
    /// to prevent dead-locks.
    ///
    /// Visits every slot of the process-global table and write-locks every matching entry; see
    /// [`Self::iter_mut_at`].
    pub(crate) fn iter_mut<Subsystem: FdEnabledSubsystem>(
        &self,
    ) -> impl Iterator<
        Item = (
            InternalFd,
            impl core::ops::DerefMut<Target = Subsystem::Entry>,
        ),
    > {
        self.iter_mut_at::<Subsystem>(WalkSite::Unattributed)
    }

    /// [`Self::iter_mut`], attributed to `site` in the `fd.table_walks` counters.
    pub(crate) fn iter_mut_at<Subsystem: FdEnabledSubsystem>(
        &self,
        site: WalkSite,
    ) -> impl Iterator<
        Item = (
            InternalFd,
            impl core::ops::DerefMut<Target = Subsystem::Entry>,
        ),
    > {
        self.note_walk(site);
        self.entries.iter().enumerate().filter_map(|(i, entry)| {
            entry.as_ref().and_then(|e| {
                if !e.read().matches_subsystem::<Subsystem>() {
                    return None;
                }
                let entry = e.write();
                assert!(entry.matches_subsystem::<Subsystem>());
                Some((
                    InternalFd {
                        raw: i.try_into().unwrap(),
                    },
                    crate::sync::RwLockWriteGuard::map(entry, |e| {
                        e.as_subsystem_mut::<Subsystem>()
                    }),
                ))
            })
        })
    }

    /// Use the entry at `fd` as read-only.
    ///
    /// If the `fd` has been closed, then skips applying `f` and returns `None`.
    #[expect(
        clippy::missing_panics_doc,
        reason = "panics impossible due to type invariants"
    )]
    pub fn with_entry<Subsystem, F, R>(&self, fd: &TypedFd<Subsystem>, f: F) -> Option<R>
    where
        Subsystem: FdEnabledSubsystem,
        F: FnOnce(&Subsystem::Entry) -> R,
    {
        // Since the typed FD should not have been created unless we had the correct subsystem in
        // the first place, none of this should panic---if it does, someone has done a bad cast
        // somewhere.
        let entry = self.entries[fd.x.as_usize()?].as_ref().unwrap().read();
        Some(f(entry.as_subsystem::<Subsystem>()))
    }

    /// Use the entry at `fd` as mutably.
    ///
    /// If the `fd` has been closed, then skips applying `f` and returns `None`.
    #[expect(
        clippy::missing_panics_doc,
        reason = "panics impossible due to type invariants"
    )]
    pub fn with_entry_mut<Subsystem, F, R>(&self, fd: &TypedFd<Subsystem>, f: F) -> Option<R>
    where
        Subsystem: FdEnabledSubsystem,
        F: FnOnce(&mut Subsystem::Entry) -> R,
    {
        // Since the typed FD should not have been created unless we had the correct subsystem in
        // the first place, none of this should panic---if it does, someone has done a bad cast
        // somewhere.
        let mut entry = self.entries[fd.x.as_usize()?].as_ref().unwrap().write();
        Some(f(entry.as_subsystem_mut::<Subsystem>()))
    }

    /// Obtain a handle to the underlying entry for the `fd`.
    ///
    /// Similar to [`Self::with_entry`], except it does not require maintaining access to the table.
    pub fn entry_handle<Subsystem: FdEnabledSubsystem>(
        &self,
        fd: &TypedFd<Subsystem>,
    ) -> Option<EntryHandle<Platform, Subsystem>> {
        // Since the typed FD should not have been created unless we had the correct subsystem in
        // the first place, none of this should panic---if it does, someone has done a bad cast
        // somewhere.
        let entry = self.entries[fd.x.as_usize()?].as_ref()?;
        Some(EntryHandle(Arc::clone(&entry.x), PhantomData))
    }

    /// Use the entry at `internal_fd` as mutably.
    ///
    /// NOTE: Ideally, prefer using [`Self::with_entry_mut`] instead of this, since it provides a
    /// nicer experience with respect to types. This current function is only to be used with
    /// specialized usages that involve dealing with stuff around [`Self::iter`] and locking
    /// disciplines, and thus should be considered an "advanced" usage.
    ///
    /// `f` is run iff it is the correct subsystem. Returns `Some` iff it is the correct subsystem.
    pub(crate) fn with_entry_mut_via_internal_fd<Subsystem, F, R>(
        &self,
        internal_fd: InternalFd,
        f: F,
    ) -> Option<R>
    where
        Subsystem: FdEnabledSubsystem,
        F: FnOnce(&mut Subsystem::Entry) -> R,
    {
        let mut entry = self.entries[usize::try_from(internal_fd.raw).unwrap()]
            .as_ref()
            .unwrap()
            .write();
        if entry.matches_subsystem::<Subsystem>() {
            Some(f(entry.as_subsystem_mut::<Subsystem>()))
        } else {
            None
        }
    }

    /// Get the entry at `fd`.
    ///
    /// Note: this grabs a lock, thus the result should not be held for too long, to prevent
    /// deadlocks. Prefer using [`Self::with_entry`] when possible, to make life easier.
    pub(crate) fn get_entry<Subsystem: FdEnabledSubsystem>(
        &self,
        fd: &TypedFd<Subsystem>,
    ) -> Option<impl core::ops::Deref<Target = Subsystem::Entry> + use<'_, Platform, Subsystem>>
    {
        Some(crate::sync::RwLockReadGuard::map(
            self.entries[fd.x.as_usize()?].as_ref().unwrap().read(),
            |e| e.as_subsystem::<Subsystem>(),
        ))
    }

    /// Get the entry at `fd`, mutably.
    ///
    /// Note: this grabs a lock, thus the result should not be held for too long, to prevent
    /// deadlocks. Prefer using [`Self::with_entry_mut`] when possible, to make life easier.
    pub(crate) fn get_entry_mut<Subsystem: FdEnabledSubsystem>(
        &self,
        fd: &TypedFd<Subsystem>,
    ) -> Option<impl core::ops::DerefMut<Target = Subsystem::Entry> + use<'_, Platform, Subsystem>>
    {
        Some(crate::sync::RwLockWriteGuard::map(
            self.entries[fd.x.as_usize()?].as_ref().unwrap().write(),
            |e| e.as_subsystem_mut::<Subsystem>(),
        ))
    }

    /// Apply `f` on metadata at an fd, if it exists.
    ///
    /// This returns the most-specific metadata available for the file descriptor---specifically, if
    /// both [`Self::set_fd_metadata`] and [`Self::set_entry_metadata`]) are run on the same
    /// fd, this will only return the value from the fd one, which will shadow the file one. If no
    /// fd-specific one is set, this returns the entry-specific one.
    #[expect(
        clippy::missing_panics_doc,
        reason = "the invariants guarantee that the unwrap panics cannot occur"
    )]
    pub fn with_metadata<Subsystem, T, R>(
        &self,
        fd: &TypedFd<Subsystem>,
        f: impl FnOnce(&T) -> R,
    ) -> Result<R, MetadataError>
    where
        Subsystem: FdEnabledSubsystem,
        T: core::any::Any + Clone + Send + Sync,
    {
        let ind_entry = self.entries[fd.x.as_usize().ok_or(MetadataError::ClosedFd)?]
            .as_ref()
            .unwrap();
        match ind_entry.metadata.get::<T>() {
            Some(m) => Ok(f(m)),
            None => ind_entry
                .read()
                .metadata
                .get::<T>()
                .map(f)
                .ok_or(MetadataError::NoSuchMetadata),
        }
    }

    /// Similar to [`Self::with_metadata`] but mutable.
    #[expect(
        clippy::missing_panics_doc,
        reason = "the invariants guarantee that the unwrap panics cannot occur"
    )]
    pub fn with_metadata_mut<Subsystem, T, R>(
        &mut self,
        fd: &TypedFd<Subsystem>,
        f: impl FnOnce(&mut T) -> R,
    ) -> Result<R, MetadataError>
    where
        Subsystem: FdEnabledSubsystem,
        T: core::any::Any + Clone + Send + Sync,
    {
        let ind_entry = self.entries[fd.x.as_usize().ok_or(MetadataError::ClosedFd)?]
            .as_mut()
            .unwrap();
        match ind_entry.metadata.get_mut::<T>() {
            Some(m) => Ok(f(m)),
            None => ind_entry
                .write()
                .metadata
                .get_mut::<T>()
                .map(f)
                .ok_or(MetadataError::NoSuchMetadata),
        }
    }

    /// Store arbitrary metadata into a file.
    ///
    /// Such metadata is visible to any open fd on the entry associated with the fd. See similar
    /// [`Self::set_fd_metadata`] which is specific to fds, and does not alias the metadata.
    ///
    /// Returns the old metadata if any such metadata exists.
    ///
    /// Silently drops the store if the FD has been closed out.
    #[expect(
        clippy::missing_panics_doc,
        reason = "the invariants guarantee that the unwrap panics cannot occur"
    )]
    pub fn set_entry_metadata<Subsystem, T>(
        &mut self,
        fd: &TypedFd<Subsystem>,
        metadata: T,
    ) -> Option<T>
    where
        Subsystem: FdEnabledSubsystem,
        T: core::any::Any + Clone + Send + Sync,
    {
        self.entries[fd.x.as_usize()?]
            .as_ref()
            .unwrap()
            .x
            .write()
            .metadata
            .insert(metadata)
    }

    /// Store arbitrary metadata into a file descriptor.
    ///
    /// Such metadata is specific to the current fd and is NOT shared with other open fds to the
    /// same entry. See the similar [`Self::set_entry_metadata`] which aliases metadata over all fds
    /// opened for the same entry.
    ///
    /// Silently drops the store if the FD has been closed out.
    #[expect(
        clippy::missing_panics_doc,
        reason = "the invariants guarantee that the unwrap panics cannot occur"
    )]
    pub fn set_fd_metadata<Subsystem, T>(
        &mut self,
        fd: &TypedFd<Subsystem>,
        metadata: T,
    ) -> Option<T>
    where
        Subsystem: FdEnabledSubsystem,
        T: core::any::Any + Clone + Send + Sync,
    {
        self.entries[fd.x.as_usize()?]
            .as_mut()
            .unwrap()
            .metadata
            .insert(metadata)
    }
}

/// A process-local identity for one open file description.
///
/// The value stays unique for as long as either a strong or weak entry handle exists. It is
/// intentionally opaque: callers may compare or order identities, but cannot turn one back into
/// an entry without an [`EntryHandle`] or [`WeakEntryHandle`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EntryIdentity(usize);

/// A handle to a descriptor entry (via [`Descriptors::entry_handle`]) that can be used without
/// maintaining access to the descriptor table itself.
pub struct EntryHandle<Platform: RawSyncPrimitivesProvider, Subsystem: FdEnabledSubsystem>(
    Arc<RwLock<Platform, DescriptorEntry>>,
    PhantomData<fn() -> Subsystem>,
);

/// A non-owning handle to an open file description.
///
/// Unlike [`EntryHandle`], this does not keep the entry alive after the final descriptor closes.
/// It is therefore suitable for kernel-style observer registrations such as epoll interests.
pub struct WeakEntryHandle<Platform: RawSyncPrimitivesProvider, Subsystem: FdEnabledSubsystem>(
    Weak<RwLock<Platform, DescriptorEntry>>,
    PhantomData<fn() -> Subsystem>,
);

impl<Platform: RawSyncPrimitivesProvider, Subsystem: FdEnabledSubsystem> Clone
    for WeakEntryHandle<Platform, Subsystem>
{
    fn clone(&self) -> Self {
        Self(self.0.clone(), PhantomData)
    }
}

impl<Platform: RawSyncPrimitivesProvider, Subsystem: FdEnabledSubsystem>
    WeakEntryHandle<Platform, Subsystem>
{
    /// Try to acquire a strong handle. This fails after the final descriptor and in-flight strong
    /// handle to the open file description have gone away.
    #[must_use]
    pub fn upgrade(&self) -> Option<EntryHandle<Platform, Subsystem>> {
        self.0
            .upgrade()
            .map(|entry| EntryHandle(entry, PhantomData))
    }

    /// Return the stable identity of the open file description this weak handle refers to.
    #[must_use]
    pub fn identity(&self) -> EntryIdentity {
        EntryIdentity(self.0.as_ptr().addr())
    }

    /// The number of strong handles to the open file description right now: one per descriptor
    /// slot that names it plus every in-flight [`EntryHandle`] (an `SCM_RIGHTS` message in
    /// transit, a transient upgrade). It can only over-count the descriptors, never under-count,
    /// so comparing it with a count of descriptors known to be closing is a conservative
    /// "every alias is accounted for" test that never closes early.
    #[must_use]
    pub fn strong_count(&self) -> usize {
        self.0.strong_count()
    }
}

impl<Platform: RawSyncPrimitivesProvider, Subsystem: FdEnabledSubsystem> Clone
    for EntryHandle<Platform, Subsystem>
{
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0), PhantomData)
    }
}
impl<Platform: RawSyncPrimitivesProvider, Subsystem: FdEnabledSubsystem>
    EntryHandle<Platform, Subsystem>
{
    /// Create a non-owning handle to this open file description.
    #[must_use]
    pub fn downgrade(&self) -> WeakEntryHandle<Platform, Subsystem> {
        WeakEntryHandle(Arc::downgrade(&self.0), PhantomData)
    }

    /// Return the stable identity of this open file description.
    #[must_use]
    pub fn identity(&self) -> EntryIdentity {
        EntryIdentity(Arc::as_ptr(&self.0).addr())
    }

    /// Apply `f` to entry-scoped metadata.
    ///
    /// Descriptor-scoped metadata is deliberately unavailable through an entry handle because it
    /// belongs to one numeric descriptor rather than to the shared open file description.
    pub fn with_metadata<T, R>(&self, f: impl FnOnce(&T) -> R) -> Result<R, MetadataError>
    where
        T: core::any::Any + Clone + Send + Sync,
    {
        self.0
            .read()
            .metadata
            .get::<T>()
            .map(f)
            .ok_or(MetadataError::NoSuchMetadata)
    }

    /// Get the entry behind this handle.
    ///
    /// Note: this grabs a lock, thus the result should not be held for too long, to prevent
    /// deadlocks. Prefer using [`Self::with_entry`] when possible, to make life easier.
    pub fn get_entry(
        &self,
    ) -> impl core::ops::Deref<Target = Subsystem::Entry> + use<'_, Platform, Subsystem> {
        crate::sync::RwLockReadGuard::map(self.0.read(), |e| e.as_subsystem::<Subsystem>())
    }

    /// Get the entry behind this handle mutably.
    ///
    /// Note: this grabs a lock, thus the result should not be held for too long, to prevent
    /// deadlocks. Prefer using [`Self::with_entry_mut`] when possible, to make life easier.
    pub fn get_entry_mut(
        &self,
    ) -> impl core::ops::DerefMut<Target = Subsystem::Entry> + use<'_, Platform, Subsystem> {
        crate::sync::RwLockWriteGuard::map(self.0.write(), |e| e.as_subsystem_mut::<Subsystem>())
    }

    pub fn with_entry<R>(&self, f: impl FnOnce(&Subsystem::Entry) -> R) -> R {
        f(self.0.read().as_subsystem::<Subsystem>())
    }

    pub fn with_entry_mut<R>(&self, f: impl FnOnce(&mut Subsystem::Entry) -> R) -> R {
        f(self.0.write().as_subsystem_mut::<Subsystem>())
    }
}

/// Result of a [`Descriptors::close_and_duplicate_if_shared`] operation
pub(crate) enum CloseResult<Subsystem: FdEnabledSubsystem> {
    /// The FD was the last reference and has been closed, returning the entry
    Closed(Subsystem::Entry),
    /// There are other references, so a new duplicate was created for queued closure
    Duplicated(TypedFd<Subsystem>),
    /// The FD was unique but couldn't be closed immediately (e.g., due to pending data)
    Deferred,
}

/// Safe(r) conversions between safely-typed file descriptors and unsafely-typed integers.
///
/// This particular object is also able to turn safely-typed file descriptors to/from unsafely-typed
/// integers, with a reasonable amount of safety---this will not be able to check for "ABA" style
/// issues, but will at least prevent using a descriptor for an unintended subsystem at the point of
/// conversion.
pub struct RawDescriptorStorage {
    /// Stored FDs are used to provide raw integer values in a safer way.
    stored_fds: Vec<Option<StoredFd>>,
}

struct StoredFd {
    x: Arc<OwnedFd>,
    subsystem_entry_type_id: core::any::TypeId,
}
impl StoredFd {
    fn new<Subsystem: FdEnabledSubsystem>(fd: TypedFd<Subsystem>) -> Self {
        Self {
            x: Arc::new(fd.x),
            subsystem_entry_type_id: core::any::TypeId::of::<Subsystem::Entry>(),
        }
    }
    #[must_use]
    fn matches_subsystem<Subsystem: FdEnabledSubsystem>(&self) -> bool {
        self.subsystem_entry_type_id == core::any::TypeId::of::<Subsystem::Entry>()
    }
}

impl RawDescriptorStorage {
    #[expect(clippy::new_without_default)]
    /// Create a new raw descriptor store.
    pub fn new() -> Self {
        Self { stored_fds: vec![] }
    }

    /// Get the corresponding integer value of the provided `fd`.
    ///
    /// This explicitly consumes the `fd`.
    #[expect(
        clippy::missing_panics_doc,
        reason = "panics are only within assertions"
    )]
    pub fn fd_into_raw_integer<Subsystem: FdEnabledSubsystem>(
        &mut self,
        fd: TypedFd<Subsystem>,
    ) -> usize {
        let ret = self
            .stored_fds
            .iter()
            .position(Option::is_none)
            .unwrap_or(self.stored_fds.len());
        let success = self.fd_into_specific_raw_integer(fd, ret);
        assert!(success);
        ret
    }

    /// Store the provided `fd` at the provided _specific_ raw integer FD.
    ///
    /// This is similar to [`Self::fd_into_raw_integer`] except that it specifies a specific FD to
    /// be stored into.
    ///
    /// Will return with `true` iff it succeeds (i.e., nothing else was using that raw integer FD).
    /// If you want to replace a used slot, you must first consume that slot via
    /// [`Self::fd_consume_raw_integer`].
    #[must_use]
    #[expect(
        clippy::missing_panics_doc,
        reason = "not guaranteed as an API-level guarantee, but instead as a defensive panic to re-consider implementation if we hit it"
    )]
    pub fn fd_into_specific_raw_integer<Subsystem: FdEnabledSubsystem>(
        &mut self,
        fd: TypedFd<Subsystem>,
        raw_fd: usize,
    ) -> bool {
        // TODO(jayb): Should we be storing things via a HashMap to make sure this operation cannot
        // be too expensive if someone tries to store into a large raw FD?
        //
        // If this assertion failure is hit in practice, we might need to be more defensive via the
        // HashMap, rather than just silently allow big growth
        assert!(
            raw_fd < self.stored_fds.len() + 256,
            "explicit upper bound restriction for now; see implementation details"
        );
        if self.stored_fds.get(raw_fd).is_some_and(Option::is_some) {
            // There's already something at this slot.
            return false;
        }
        if raw_fd >= self.stored_fds.len() {
            self.stored_fds.resize_with(raw_fd + 1, || None);
        }
        let old = self.stored_fds[raw_fd].replace(StoredFd::new(fd));
        assert!(old.is_none());
        true
    }

    /// Get the typed FD for the raw integer value of the `fd`.
    ///
    /// To fully remove this FD from see [`Self::fd_consume_raw_integer`].
    pub fn fd_from_raw_integer<Subsystem: FdEnabledSubsystem>(
        &self,
        fd: usize,
    ) -> Result<Arc<TypedFd<Subsystem>>, ErrRawIntFd> {
        self.typed_fd_at_raw_1(fd)
    }

    /// Obtain the typed FD for the raw integer value of the `fd`, "consuming" the raw integer.
    ///
    /// Since this operation "consumes" the raw integer, future [`Self::fd_from_raw_integer`] might
    /// not refer to this file descriptor.
    ///
    /// You almost definitely want [`Self::fd_from_raw_integer`] instead, and should only use this
    /// if you really know you want to consume the descriptor.
    pub fn fd_consume_raw_integer<Subsystem: FdEnabledSubsystem>(
        &mut self,
        fd: usize,
    ) -> Result<Arc<TypedFd<Subsystem>>, ErrRawIntFd> {
        let ret = self.fd_from_raw_integer(fd)?;
        let underlying = self.stored_fds[fd].take();
        debug_assert!(underlying.is_some());
        drop(underlying);
        Ok(ret)
    }

    /// Check if there is a valid FD at the raw integer value `fd`.
    ///
    /// This function is entirely subsystem-irrelevant. If you want to check against a subsystem,
    /// you might wish to use [`Self::fd_from_raw_integer`].
    #[must_use]
    pub fn is_alive(&self, fd: usize) -> bool {
        self.stored_fds.get(fd).is_some_and(Option::is_some)
    }

    /// Returns an iterator over raw integer indices that are currently alive (i.e., occupied).
    pub fn iter_alive(&self) -> impl Iterator<Item = usize> + '_ {
        self.stored_fds
            .iter()
            .enumerate()
            .filter_map(|(i, slot)| slot.as_ref().map(|_| i))
    }
}

macro_rules! multi_subsystem_generic {
    ($ident_f:ident, $ident_i:ident, $($f:ident $subsystem:ident),+ $(,)?) => {
        /// Invoke the corresponding function that matches the subsystem.
        ///
        /// Equivalent versions of this function exist at differing number of subsystems.
        fn $ident_f<R, $($subsystem),+>(
            &self,
            fd: usize,
            $(
                $f: impl FnOnce(Arc<TypedFd<$subsystem>>) -> R
            ),+
        ) -> Result<R, ErrRawIntFd>
        where
            $($subsystem: FdEnabledSubsystem),+
        {
            let Some(Some(stored_fd)) = self.stored_fds.get(fd) else {
                return Err(ErrRawIntFd::NotFound);
            };
            $(
                if stored_fd.matches_subsystem::<$subsystem>() {
                    let typed_fd: Arc<TypedFd<$subsystem>> = {
                        let fd: Arc<OwnedFd> = Arc::clone(&stored_fd.x);
                        let fd: *const OwnedFd = Arc::into_raw(fd);
                        // SAFETY: We are effectively converting an `Arc<OwnedFd>` to an
                        // `Arc<TypedFd<Subsystem>>`.
                        //
                        // This is safe because:
                        //
                        //   - `TypedFd` is a `#[repr(transparent)]` wrapper on `OwnedFd`.
                        //
                        //   - We just confirmed that it is of the correct subsystem.
                        //
                        //   - Thus, `OwnedFd` and `TypedFd` are effectively the same type, and
                        //     thus are safely castable.
                        //
                        //   - `Arc::from_raw`'s safety documentation requires the standard safe
                        //     castability constraints between the two.
                        unsafe { Arc::from_raw(fd.cast()) }
                    };
                    return Ok($f(typed_fd));
                }
            )+
                Err(ErrRawIntFd::InvalidSubsystem)
        }

        /// Get a conversion of the typed FD for any of the N subsystems for the raw integer
        /// value of the `fd`.
        ///
        /// Equivalent versions of this function exist at differing number of subsystems.
        pub fn $ident_i<R, $($subsystem),+>(
            &self,
            fd: usize,
        ) -> Result<R, ErrRawIntFd>
        where
            $($subsystem: FdEnabledSubsystem, R: From<Arc<TypedFd<$subsystem>>>),+
        {
            self.$ident_f(fd, $(
                |x: Arc<TypedFd<$subsystem>>| R::from(x)
            ),+)
        }
    };
}

impl RawDescriptorStorage {
    multi_subsystem_generic! {invoke_matching_subsystem_1, typed_fd_at_raw_1, f1 S1}
    multi_subsystem_generic! {invoke_matching_subsystem_2, typed_fd_at_raw_2, f1 S1, f2 S2}
    multi_subsystem_generic! {invoke_matching_subsystem_3, typed_fd_at_raw_3, f1 S1, f2 S2, f3 S3}
    multi_subsystem_generic! {invoke_matching_subsystem_4, typed_fd_at_raw_4, f1 S1, f2 S2, f3 S3, f4 S4}
}

/// A LiteBox subsystem that support having file descriptors.
pub trait FdEnabledSubsystem: Sized {
    /// The per-FD entry type stored in the descriptor table for this subsystem
    type Entry: FdEnabledSubsystemEntry + 'static;
}

/// A per-FD entry stored in the descriptor table for a specific [`FdEnabledSubsystem`]
pub trait FdEnabledSubsystemEntry: Send + Sync + core::any::Any {}

/// Possible errors from [`RawDescriptorStorage::fd_from_raw_integer`] and
/// [`RawDescriptorStorage::fd_consume_raw_integer`].
#[derive(Error, Debug)]
pub enum ErrRawIntFd {
    #[error("no such file descriptor found")]
    NotFound,
    #[error("fd for invalid subsystem")]
    InvalidSubsystem,
}

/// Possible errors from getting metadata
#[derive(Error, Debug)]
pub enum MetadataError {
    #[error("no such metadata available")]
    NoSuchMetadata,
    #[error("fd has been closed")]
    ClosedFd,
}

/// A module-internal fd-specific individual entry
struct IndividualEntry<Platform: RawSyncPrimitivesProvider> {
    x: Arc<RwLock<Platform, DescriptorEntry>>,
    metadata: AnyMap,
}
impl<Platform: RawSyncPrimitivesProvider> core::ops::Deref for IndividualEntry<Platform> {
    type Target = Arc<RwLock<Platform, DescriptorEntry>>;
    fn deref(&self) -> &Self::Target {
        &self.x
    }
}
impl<Platform: RawSyncPrimitivesProvider> IndividualEntry<Platform> {
    fn new(x: Arc<RwLock<Platform, DescriptorEntry>>) -> Self {
        Self {
            x,
            metadata: AnyMap::new(),
        }
    }
}

/// A crate-internal entry for a descriptor.
pub(crate) struct DescriptorEntry {
    entry: alloc::boxed::Box<dyn FdEnabledSubsystemEntry>,
    metadata: AnyMap,
}

impl DescriptorEntry {
    /// Check if this entry matches the specified subsystem
    #[must_use]
    fn matches_subsystem<Subsystem: FdEnabledSubsystem>(&self) -> bool {
        core::any::TypeId::of::<Subsystem::Entry>() == core::any::Any::type_id(self.entry.as_ref())
    }

    /// Obtains `self` as the subsystem's entry type.
    ///
    /// # Panics
    ///
    /// Panics if invalid for the particular subsystem.
    fn as_subsystem<Subsystem: FdEnabledSubsystem>(&self) -> &Subsystem::Entry {
        (self.entry.as_ref() as &dyn core::any::Any)
            .downcast_ref()
            .unwrap()
    }

    /// Obtains `self` as the subsystem's entry type, mutably.
    ///
    /// # Panics
    ///
    /// Panics if invalid for the particular subsystem.
    fn as_subsystem_mut<Subsystem: FdEnabledSubsystem>(&mut self) -> &mut Subsystem::Entry {
        (self.entry.as_mut() as &mut dyn core::any::Any)
            .downcast_mut()
            .unwrap()
    }

    /// Obtains `self` as the subsystem's entry type.
    ///
    /// # Panics
    ///
    /// Panics if invalid for the particular subsystem.
    fn into_subsystem_entry<Subsystem: FdEnabledSubsystem>(self) -> Subsystem::Entry {
        *(self.entry as alloc::boxed::Box<dyn core::any::Any>)
            .downcast()
            .unwrap()
    }
}

/// A file descriptor that refers to entries by the `Subsystem`.
#[repr(transparent)] // this allows us to cast safely
pub struct TypedFd<Subsystem: FdEnabledSubsystem> {
    // Invariant in `Subsystem`: <https://doc.rust-lang.org/nomicon/phantom-data.html#table-of-phantomdata-patterns>
    _phantom: PhantomData<fn(Subsystem) -> Subsystem>,
    x: OwnedFd,
}

impl<Subsystem: FdEnabledSubsystem> TypedFd<Subsystem> {
    /// Get the "internal FD"
    pub(crate) fn as_internal_fd(&self) -> InternalFd {
        assert!(!self.x.is_closed());
        InternalFd { raw: self.x.raw }
    }
}

/// A crate-internal representation of file descriptors that supports cloning/copying, and does
/// *not* indicate validity/existence/ownership.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct InternalFd {
    pub(crate) raw: u32,
}

/// An explicitly-private shared-common element of [`TypedFd`], denoting an owned (non-clonable)
/// token of ownership over a file descriptor.
///
/// Note: this indicates ownership over the descriptor itself, but not necessarily the underlying
/// entry, since there might be duplicates to the underlying entry.
struct OwnedFd {
    raw: u32,
    closed: AtomicBool,
}

impl OwnedFd {
    /// Produce a new owned token from a raw index
    ///
    /// Panics if outside the u32 range
    pub(crate) fn new(raw: usize) -> Self {
        Self {
            raw: raw.try_into().unwrap(),
            closed: AtomicBool::new(false),
        }
    }

    /// Check if it is closed
    pub(crate) fn is_closed(&self) -> bool {
        self.closed.load(core::sync::atomic::Ordering::SeqCst)
    }

    /// Mark it as closed
    pub(crate) fn mark_as_closed(&self) {
        let was_closed = self
            .closed
            .fetch_or(true, core::sync::atomic::Ordering::SeqCst);
        assert!(!was_closed);
    }

    /// Obtain the raw index it was created with if it has not been closed.
    ///
    /// Returns `None` if it has already been closed.
    pub(crate) fn as_usize(&self) -> Option<usize> {
        if self.is_closed() {
            return None;
        }
        let v: usize = self.raw.try_into().unwrap();
        Some(v)
    }
}

impl Drop for OwnedFd {
    fn drop(&mut self) {
        if self.is_closed() {
            // This has been closed out by a valid close operation
        } else {
            // The owned fd is dropped without being consumed by a `close` operation that has
            // properly marked it as being safely closed
            #[cfg(feature = "panic_on_unclosed_fd_drop")]
            panic!("Un-closed OwnedFd ({}) being dropped", self.raw)
        }
    }
}

/// Enable FD support for a particular subsystem conveniently
#[doc(hidden)]
macro_rules! enable_fds_for_subsystem {
    (
        $(@ $($sys_param:ident $(: { $($sys_constraint:tt)* })?),*;)?
        $system:ty;
        $(@ $($ent_param:ident $(: { $($ent_constraint:tt)* })?),*;)?
        $entry:ty;
        $(-> $fd:ident $(<$($fd_param:ident),*>)?;)?
    ) => {
        #[doc(hidden)]
        // This wrapper type exists just to make sure `$entry` itself is not public, but we can
        // still satisfy requirements for `FdEnabledSubsystem`.
        pub struct DescriptorEntry $(< $($ent_param $(: $($ent_constraint)*)?),* >)? {
            entry: $entry,
        }
        impl $(< $($sys_param $(: $($sys_constraint)*)?),* >)? $crate::fd::FdEnabledSubsystem
            for $system
        {
            type Entry = DescriptorEntry $(< $($ent_param),* >)?;
        }
        impl $(< $($ent_param $(: $($ent_constraint)*)?),* >)? $crate::fd::FdEnabledSubsystemEntry
            for DescriptorEntry $(< $($ent_param),* >)?
        {
        }
        impl $(< $($ent_param $(: $($ent_constraint)*)?),* >)? From<$entry>
            for DescriptorEntry $(< $($ent_param),* >)?
        {
            fn from(entry: $entry) -> Self {
                Self { entry }
            }
        }
        $(
            pub type $fd $(<$($fd_param),*>)? = $crate::fd::TypedFd<$system>;
        )?
    };
}
pub(crate) use enable_fds_for_subsystem;
