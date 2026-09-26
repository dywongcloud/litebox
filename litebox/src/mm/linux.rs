// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! This module implements a virtual memory manager `Vmem` that manages virtual address spaces
//! backed by a memory [backend](PageManagementProvider). It provides functionality to create, remove, resize,
//! move, and protect memory mappings within a process's virtual address space.

use core::ops::Range;
use core::sync::atomic::{AtomicUsize, Ordering};

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use hashbrown::HashMap;
use rangemap::RangeMap;
use thiserror::Error;

use crate::platform::PageManagementProvider;
use crate::platform::RawConstPointer;
use crate::platform::page_mgmt::AllocationError;
use crate::platform::page_mgmt::FixedAddressBehavior;
use crate::platform::page_mgmt::MemoryRegionPermissions;
use crate::utils::ids::VmViewId;

/// Page size in bytes.
///
/// This is the granularity at which LiteBox maps, unmaps and re-protects guest
/// memory, so it has to be at least the host's own page size -- a host kernel
/// rejects a fixed mapping or a protection change that is not aligned to it.
///
/// Apple Silicon uses 16 KiB pages, so a macOS/aarch64 host needs the larger
/// value; every other supported host uses 4 KiB. The guest sees this through
/// `AT_PAGESZ`, which is exactly how a Linux kernel configured for 16 KiB or
/// 64 KiB pages reports itself, and aarch64 ELF images are conventionally
/// linked with a 64 KiB maximum page size so their segments stay aligned either
/// way.
#[cfg(not(all(target_vendor = "apple", target_arch = "aarch64")))]
pub const PAGE_SIZE: usize = 4096;

/// Page size in bytes. See the 4 KiB definition for details.
#[cfg(all(target_vendor = "apple", target_arch = "aarch64"))]
pub const PAGE_SIZE: usize = 16384;

bitflags::bitflags! {
    /// Flags to describe the properties of a memory region.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct VmFlags: u32 {
        /// Readable.
        const VM_READ = 1 << 0;
        /// Writable.
        const VM_WRITE = 1 << 1;
        /// Executable.
        const VM_EXEC = 1 << 2;
        /// Shared between processes.
        const VM_SHARED = 1 << 3;

        /* limits for mprotect() etc */
        /// `mprotect` can turn on VM_READ
        const VM_MAYREAD = 1 << 4;
        /// `mprotect` can turn on VM_WRITE
        const VM_MAYWRITE = 1 << 5;
        /// `mprotect` can turn on VM_EXEC
        const VM_MAYEXEC = 1 << 6;
        /// `mprotect` can turn on VM_SHARED
        const VM_MAYSHARE = 1 << 7;

        /// The area can grow downward upon page fault.
        const VM_GROWSDOWN = 1 << 8;

        /// LiteBox-internal, never guest-visible: the range is reserved in the
        /// VMA tracker only, and the platform holds no state for it yet.
        /// Set on `PROT_NONE` anonymous private mappings (pure VA reservations,
        /// e.g. V8's multi-GiB cage/sandbox), which Linux also books without
        /// any page-table state. Materialized lazily by `protect_mapping` when
        /// any access flag is first added; unmapping one never touches the
        /// platform.
        const VM_DEFERRED = 1 << 9;

        /// `MADV_WIPEONFORK`: a forked child sees this range zero-filled
        /// instead of inheriting the parent's contents (the parent keeps
        /// its own). Linux records it as `VM_WIPEONFORK` on the VMA; only
        /// private anonymous mappings can carry it, `MADV_KEEPONFORK`
        /// clears it, and a mapping created over the range drops it with
        /// the VMA it belonged to. See [`Vmem::set_wipe_on_fork`] and
        /// [`Vmem::wipe_on_fork_ranges`].
        const VM_WIPEONFORK = 1 << 10;

        /// `MADV_DONTFORK`: this range is entirely absent from a forked child's view of
        /// memory (Linux: dropped from the child's `mm`, never even reserved there).
        /// `MADV_DOFORK` clears it. Legal on any mapping, unlike `VM_WIPEONFORK` -- real
        /// Linux does not require a private anonymous backing for this one. See
        /// [`Vmem::set_dont_fork`] and [`Vmem::dont_fork_ranges`].
        const VM_DONTCOPY = 1 << 11;

        const VM_ACCESS_FLAGS = Self::VM_READ.bits()
            | Self::VM_WRITE.bits()
            | Self::VM_EXEC.bits();
        const VM_MAY_ACCESS_FLAGS = Self::VM_MAYREAD.bits()
            | Self::VM_MAYWRITE.bits()
            | Self::VM_MAYEXEC.bits();
    }
}

impl VmFlags {
    /// Compute the default `VM_MAY*` and `VM_SHARED` flags for a mapping.
    pub(super) fn may_flags_for_mapping(shared: bool, _file_backed: bool) -> Self {
        let shared_flag = if shared {
            Self::VM_SHARED
        } else {
            Self::empty()
        };
        Self::VM_MAY_ACCESS_FLAGS | shared_flag
    }
}

impl From<MemoryRegionPermissions> for VmFlags {
    fn from(value: MemoryRegionPermissions) -> Self {
        let mut flags = VmFlags::empty();
        flags.set(
            VmFlags::VM_READ,
            value.contains(MemoryRegionPermissions::READ),
        );
        flags.set(
            VmFlags::VM_WRITE,
            value.contains(MemoryRegionPermissions::WRITE),
        );
        flags.set(
            VmFlags::VM_EXEC,
            value.contains(MemoryRegionPermissions::EXEC),
        );
        if value.contains(MemoryRegionPermissions::SHARED) {
            unimplemented!("SHARED permission is not supported yet");
        }
        flags
    }
}

impl From<VmFlags> for MemoryRegionPermissions {
    fn from(value: VmFlags) -> Self {
        let mut flags = MemoryRegionPermissions::empty();
        flags.set(
            MemoryRegionPermissions::READ,
            value.contains(VmFlags::VM_READ),
        );
        flags.set(
            MemoryRegionPermissions::WRITE,
            value.contains(VmFlags::VM_WRITE),
        );
        flags.set(
            MemoryRegionPermissions::EXEC,
            value.contains(VmFlags::VM_EXEC),
        );
        flags.set(
            MemoryRegionPermissions::SHARED,
            value.contains(VmFlags::VM_SHARED),
        );
        flags
    }
}

pub const DEFAULT_RESERVED_SPACE_SIZE: usize = 0x100_0000; // 16 MiB

bitflags::bitflags! {
    /// Options for page creation.
    pub struct CreatePagesFlags: u8 {
        /// Force the mapping to be created at the given address, resulting in any
        /// existing overlapping mappings being removed.
        const FIXED_ADDR     = 1 << 0;
        /// The mapping is used for stack.
        const IS_STACK       = 1 << 1;
        /// Populate the pages immediately.
        const POPULATE_PAGES_IMMEDIATELY = 1 << 2;
        /// Ensure there is more space (i.e., `DEFAULT_RESERVED_SPACE_SIZE`) after the
        /// mapping so that user can grow the mapping later.
        const ENSURE_SPACE_AFTER = 1 << 3;
        // This flag indicates that the mapping is backed by a file.
        const MAP_FILE = 1 << 4;
        /// When combined with [`Self::FIXED_ADDR`], fail with [`AllocationError::AddressInUse`]
        /// if any part of the range is already mapped, instead of replacing existing mappings.
        const NOREPLACE = 1 << 5;
        /// The mapping is shared.
        const SHARED = 1 << 6;
    }
}

/// A non-empty range of page-aligned addresses
#[derive(Clone, Copy)]
pub struct PageRange<const ALIGN: usize> {
    /// Start page of the range.
    pub start: usize,
    /// End page of the range.
    pub end: usize,
}

impl<const ALIGN: usize> From<PageRange<ALIGN>> for Range<usize> {
    fn from(range: PageRange<ALIGN>) -> Self {
        range.start..range.end
    }
}

impl<const ALIGN: usize> IntoIterator for PageRange<ALIGN> {
    type Item = usize;
    type IntoIter = core::iter::StepBy<Range<usize>>;

    fn into_iter(self) -> Self::IntoIter {
        (self.start..self.end).step_by(ALIGN)
    }
}

impl<const ALIGN: usize> PageRange<ALIGN> {
    /// Create a new [`PageRange`].
    ///
    /// Returns `None` if the range is not `ALIGN`-aligned or empty.
    pub fn new(start: usize, end: usize) -> Option<Self> {
        if !start.is_multiple_of(ALIGN) || !end.is_multiple_of(ALIGN) {
            return None;
        }
        if start >= end {
            return None;
        }
        Some(Self { start, end })
    }

    /// Get the size of this `ALIGN`-aligned range
    pub fn len(&self) -> usize {
        self.end - self.start
    }

    /// Whether the range is empty or not
    ///
    /// Note this range is never empty.
    pub fn is_empty(&self) -> bool {
        false
    }

    /// Get the start address and length of this range as a tuple.
    #[allow(
        clippy::missing_panics_doc,
        reason = "This function should not fail as the range is guaranteed to be non-empty and aligned."
    )]
    pub fn start_and_length(&self) -> (NonZeroAddress<ALIGN>, NonZeroPageSize<ALIGN>) {
        (
            NonZeroAddress::new(self.start).unwrap(),
            NonZeroPageSize::new(self.len()).unwrap(),
        )
    }
}

/// A non-zero `ALIGN`-aligned size in bytes.
#[derive(Clone, Copy)]
pub struct NonZeroPageSize<const ALIGN: usize> {
    size: usize,
}

impl<const ALIGN: usize> NonZeroPageSize<ALIGN> {
    /// Create a new non-zero `ALIGN`-aligned size.
    ///
    /// Returns `None` if the size is zero or not `ALIGN`-aligned.
    pub fn new(size: usize) -> Option<Self> {
        if size == 0 || !size.is_multiple_of(ALIGN) {
            return None;
        }
        Some(Self { size })
    }

    /// Get the size
    #[inline]
    pub fn as_usize(self) -> usize {
        self.size
    }
}

impl<const ALIGN: usize> core::ops::Add<usize> for NonZeroPageSize<ALIGN> {
    type Output = Option<Self>;

    fn add(self, rhs: usize) -> Self::Output {
        NonZeroPageSize::new(self.size + rhs)
    }
}

/// A non-zero address that is `ALIGN`-aligned.
#[derive(Clone, Copy)]
pub struct NonZeroAddress<const ALIGN: usize>(usize);

impl<const ALIGN: usize> NonZeroAddress<ALIGN> {
    /// Create a new `NonZeroAddress`, if the address is non-zero and aligned.
    pub fn new(address: usize) -> Option<Self> {
        if address == 0 || !address.is_multiple_of(ALIGN) {
            return None;
        }
        Some(Self(address))
    }

    /// Get the address
    #[inline]
    pub fn as_usize(self) -> usize {
        self.0
    }
}

static NEXT_SHARED_FUTEX_BACKING_ID: AtomicUsize = AtomicUsize::new(1);

/// Stable identity of one shared memory backing object.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SharedFutexBacking {
    identity: usize,
}

impl SharedFutexBacking {
    /// Allocates a process-wide identity that is never reused.
    pub fn new() -> Self {
        let identity = NEXT_SHARED_FUTEX_BACKING_ID
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |identity| {
                identity.checked_add(1)
            })
            .expect("shared futex backing identity space exhausted");
        Self { identity }
    }

    /// Returns this backing object's process-wide stable identity.
    pub fn identity(self) -> usize {
        self.identity
    }
}

impl Default for SharedFutexBacking {
    fn default() -> Self {
        Self::new()
    }
}

/// Never-reused identity of a mapping while its initialization callback runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct InitializationId(usize);

/// Virtual memory area
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct VmArea {
    /// Flags describing the properties of the memory region.
    flags: VmFlags,
    /// Whether this area is backed by a file
    is_file_backed: bool,
    /// Identity and original virtual origin of shared backing, used to derive futex keys that
    /// survive virtual-address moves without aliasing unrelated shared mappings.
    shared_futex: Option<SharedFutexMapping>,
    /// Distinguishes adjacent mappings while either initialization still owns its exact range.
    initialization: Option<InitializationId>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SharedFutexPosition {
    PendingOffset(usize),
    Origin(usize),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SharedFutexMapping {
    identity: usize,
    position: SharedFutexPosition,
}

impl VmArea {
    /// Get the [flags](`VmFlags`) of this memory area.
    #[inline]
    pub(super) fn flags(self) -> VmFlags {
        self.flags
    }

    /// Check if this area is backed by a file.
    #[inline]
    pub(super) fn is_file_backed(self) -> bool {
        self.is_file_backed
    }

    /// Create a new [`VmArea`] with the given flags.
    #[inline]
    pub(super) fn new(
        flags: VmFlags,
        is_file_backed: bool,
        shared_futex_backing: Option<(SharedFutexBacking, usize)>,
    ) -> Self {
        Self {
            flags,
            is_file_backed,
            shared_futex: shared_futex_backing.map(|(backing, offset)| SharedFutexMapping {
                identity: backing.identity,
                position: SharedFutexPosition::PendingOffset(offset),
            }),
            initialization: None,
        }
    }
}

/// A pre-effect-staged record of what one [`Vmem`] mutation is about to do to a `vmas` fragment,
/// mirroring `mm/domain.rs`'s `Custody::Installing`/`Custody::Retiring` transient overlay values
/// but scoped to [`Vmem`]'s own single-writer-lock model: every `Vmem` mutation runs under one
/// [`crate::mm::mod::PageManager`]-level write lock held by the caller across the whole call
/// (including the platform effect), so -- unlike `GuestVaDomain`'s lock, which is dropped across
/// every platform callback -- no concurrent reader can ever observe this map's contents. Its job
/// is not concurrency visibility, but recording each affected fragment's pre-effect state before
/// the platform call runs, so a panic mid-effect (e.g. inside the platform's own
/// `allocate_pages`/`deallocate_pages`, which this module cannot guard against panicking) leaves a
/// forensic record of what was in flight rather than silent, unrecorded loss -- the entry is
/// always cleared again, on both the commit and rollback paths, once the platform call returns.
///
/// Scope note (deliberately not extended further): `self.vmas`'s own `RangeMap` mutation at
/// commit time (the `self.vmas.insert`/`self.vmas.remove` calls that follow every platform
/// effect) remains itself post-effect by design, and is *not* what this type protects against.
/// A sentinel-based pre-split of `vmas` (inserting a poisoned placeholder before the real
/// commit, mirroring this type) would not actually deliver a non-restructuring commit either:
/// `RangeMap::insert`'s internal remove-then-insert on its backing `BTreeMap` does not
/// guarantee node reuse (`alloc::collections::BTreeMap` deallocates a leaf node when it empties
/// on `remove` and allocates fresh on `insert` -- these are decoupled, so re-inserting the exact
/// same key range immediately after removing it is not proven allocation-free by the crate's
/// public API or by `BTreeMap`'s documented guarantees). Attempting it would add real
/// complexity (a poisoned-marker `VmArea` variant, careful `PartialEq` breakage to prevent
/// unwanted coalescing, a real split-boundaries step) for no verifiable gain. This type's
/// invariant is therefore scoped down to "the pre-effect staging itself never fails post-effect"
/// (already true, since a `RangeMap<usize, Transient>` insert/remove is exactly as fallible --
/// i.e. aborts the process on allocator OOM, never returns an error -- as every other
/// `BTreeMap`-backed structure in this module (`pending_initializations`, `reserved`) in this
/// global-allocator-aborts-on-OOM environment), not "the final commit into `vmas` is also
/// staged."
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Transient {
    /// A platform install callback (fresh `allocate_pages`/`allocate_shared_pages`, or a `Replace`
    /// overwrite) is in flight for this fragment; `publish` is the [`VmArea`] it will carry once
    /// installed.
    Installing { publish: VmArea },
    /// A platform teardown callback (`deallocate_pages`) is in flight for this fragment; `restore`
    /// is the [`VmArea`] it carried immediately before the teardown was requested.
    Retiring { restore: VmArea },
}

/// One change of [`Vmem::vmas`], as recorded by [`TrackedVmas`] and replayed into the
/// [`VmaMirror`].
#[derive(Clone, Copy, Debug)]
pub(super) enum VmaOp {
    /// `RangeMap::insert(range, value)`.
    Insert(usize, usize, VmArea),
    /// `RangeMap::remove(range)`.
    Remove(usize, usize),
}

/// [`Vmem::vmas`], with every mutation logged: each `insert`/`remove` since the last
/// [`Vmem::drain_vma_ops`], in order. Read access is the plain [`RangeMap`] (through `Deref`);
/// there is deliberately no `DerefMut`, so `insert`/`remove` below are the only ways to change it
/// and no change can escape the log. `PageManager` replays the log into its [`VmaMirror`] before
/// it releases its mapping lock (hvf-t1g-remainder-multisecond-service-guest-memory-access-
/// convoy): the mirror is what a guest-memory access checks, so an access never waits for a
/// mapping mutation's platform effect. The replay is exactly the section's own operations,
/// applied in the same order to a map that was identical before the section -- `RangeMap`'s
/// insert and remove are deterministic, so the mirror ends identical -- at a cost proportional to
/// the change: no re-read of the table, no sorting, and (the log keeps its capacity) no
/// allocation in steady state (T1h fix-up: the first version merged and re-read "dirty ranges"
/// per section).
struct TrackedVmas {
    map: RangeMap<usize, VmArea>,
    ops: Vec<VmaOp>,
}

impl TrackedVmas {
    fn new() -> Self {
        Self {
            map: RangeMap::new(),
            ops: Vec::new(),
        }
    }

    // Logged only once the table change itself returned: a change that panics (an empty range)
    // is neither applied nor replayed, so the replay the section's unwinding still runs cannot
    // panic a second time.
    fn insert(&mut self, range: Range<usize>, value: VmArea) {
        let (start, end) = (range.start, range.end);
        self.map.insert(range, value);
        self.ops.push(VmaOp::Insert(start, end, value));
    }

    fn remove(&mut self, range: Range<usize>) {
        let (start, end) = (range.start, range.end);
        self.map.remove(range);
        self.ops.push(VmaOp::Remove(start, end));
    }
}

impl core::ops::Deref for TrackedVmas {
    type Target = RangeMap<usize, VmArea>;

    fn deref(&self) -> &Self::Target {
        &self.map
    }
}

/// The memory permissions of `range` over a mapping table: those of the single entry covering all
/// of `range`, `None` when no one entry does (a hole, or pieces with different properties).
fn table_memory_permissions(
    vmas: &RangeMap<usize, VmArea>,
    range: Range<usize>,
) -> Option<MemoryRegionPermissions> {
    let (range_start, range_end) = (range.start, range.end);
    let (mapped, vma) = vmas.overlapping(range).next()?;
    if mapped.start > range_start || mapped.end < range_end {
        // partial overlap implies that the given range contains unmapped pages or
        // consists of memory pages with different permissions.
        return None;
    }
    Some(vma.flags().into())
}

/// The flags of the mapping-table entry containing `address`.
fn table_flags_at(vmas: &RangeMap<usize, VmArea>, address: usize) -> Option<VmFlags> {
    vmas.get_key_value(&address).map(|(_, vma)| vma.flags())
}

/// The shared-backing futex identity and byte offset of `address` in a mapping table.
fn table_shared_futex_key_at(
    vmas: &RangeMap<usize, VmArea>,
    address: usize,
) -> Option<(usize, usize)> {
    let (_, vma) = vmas.get_key_value(&address)?;
    let shared = vma.shared_futex?;
    let SharedFutexPosition::Origin(origin) = shared.position else {
        return None;
    };
    Some((shared.identity, address.wrapping_sub(origin)))
}

/// A copy of [`Vmem`]'s mapping table (every entry, same ranges, same values, so the same
/// coalesced form) that `PageManager` keeps behind its own short-held lock and brings up to date
/// at the end of every exclusive section of its mapping lock, by replaying the section's own
/// table operations ([`Vmem::replay_vma_ops`]). Answers the point-in-time questions a
/// guest-memory access or a futex key needs without that lock, i.e. without waiting behind a
/// mapping mutation's platform effect; it shows each mutation's result from the moment the
/// mutating section ends -- before that section's lock is released, so before the mutating
/// syscall can return.
pub(super) struct VmaMirror {
    map: RangeMap<usize, VmArea>,
}

impl VmaMirror {
    pub(super) fn new() -> Self {
        Self {
            map: RangeMap::new(),
        }
    }

    /// Applies one logged table operation, exactly as [`TrackedVmas`] applied it.
    fn apply(&mut self, op: VmaOp) {
        match op {
            VmaOp::Insert(start, end, vma) => self.map.insert(start..end, vma),
            VmaOp::Remove(start, end) => self.map.remove(start..end),
        }
    }

    /// Every entry, in address order.
    pub(super) fn iter(&self) -> impl Iterator<Item = (&Range<usize>, &VmArea)> {
        self.map.iter()
    }

    /// The permissions of `page_range`: those of the single entry covering all of it, `None`
    /// when no one entry does (a hole, or pieces with different properties).
    pub(super) fn get_memory_permissions<const ALIGN: usize>(
        &self,
        page_range: PageRange<ALIGN>,
    ) -> Option<MemoryRegionPermissions> {
        table_memory_permissions(&self.map, page_range.into())
    }

    /// The flags of the mapping containing `address`.
    pub(super) fn flags_at(&self, address: usize) -> Option<VmFlags> {
        table_flags_at(&self.map, address)
    }

    /// The shared-backing futex identity and byte offset for `address`.
    pub(super) fn shared_futex_key_at(&self, address: usize) -> Option<(usize, usize)> {
        table_shared_futex_key_at(&self.map, address)
    }
}

/// Virtual Memory Manager
///
/// This struct mantains the virtual memory ranges backed by a memory [backend](PageManagementProvider).
/// Each range needs to be `ALIGN`-aligned.
pub(super) struct Vmem<Platform: PageManagementProvider<ALIGN> + 'static, const ALIGN: usize> {
    /// Memory backend that provides the actual memory.
    pub(super) platform: &'static Platform,
    /// Current program break address.
    pub(super) brk: usize,
    /// Virtual memory areas.
    vmas: TrackedVmas,
    /// Temporary ownership of mappings whose caller callback has not returned.
    pending_initializations: RangeMap<usize, InitializationId>,
    /// Next callback identity. Zero is never issued and identities are never reused.
    next_initialization_id: usize,
    /// Address ranges a caller has claimed as logically owned without (or no longer) having a
    /// live mapping here -- disjoint per owner, start -> end. A flexible (non-`MAP_FIXED`)
    /// placement search treats an owner's own entries here exactly like a live `vmas` entry:
    /// occupied, never handed out *to that same owner*. `MAP_FIXED` requests are unaffected (see
    /// `get_unmmaped_area`'s `fixed_addr` branch), matching the narrow problem this exists for: a
    /// shared, single flat address space faking multiple guest processes by taking turns
    /// (`litebox_shim_linux`'s `SharedAddressSpace`) can have one member "parked" -- its memory
    /// copied out, its addresses momentarily absent from `vmas` -- while another member of the
    /// SAME family keeps running and, on `execve`, tears down and rebuilds its own (shared)
    /// `vmas` entries. Nothing stopped the fresh image's flexible placement from landing on
    /// exactly the addresses the parked member still remembers and will later try to restore
    /// into, corrupting or safely-but-fatally colliding with whatever is there by then. The
    /// park/restore machinery reserves a member's saved ranges here for exactly as long as it is
    /// parked, so a fresh placement *by the same family* is steered elsewhere instead.
    ///
    /// Keyed outermost by [`VmViewId`] -- the same "current memory view" identity a
    /// `SharedAddressSpace`'s own members already share (`Task::current_mem_view`), and that
    /// every other family-aware check in this codebase (`GuestVaDomain::custody_at_via_lineage`,
    /// the W^X ledger, the growsdown fault-classification fix) already uses to distinguish one
    /// family's own memory from another's. This is a real fix, not a relabeling: prior to it,
    /// this was one flat, owner-blind `BTreeMap<usize, usize>`, so ANY live reservation (made by
    /// ANY family, for its own entirely unrelated park/hand-off reasons) steered EVERY OTHER
    /// family's own flexible placement search away too -- confirmed live
    /// (`vfork-park-reserved-range-steers-unrelated-familys-flexible-mmap-confirmed`): an
    /// `OBSERVER` process, with zero relationship to a `vfork`-ing `V` beyond a common
    /// grandparent, had its own genuinely-free hinted `mmap` steered off its hint purely because
    /// `V`'s own vfork-parked reservation happened to numerically overlap it. On real Linux this
    /// is categorically impossible (separate address spaces), and it cannot happen here either
    /// now: [`Self::reserved_overlaps`] only ever consults the *querying* owner's own sub-map.
    reserved: HashMap<VmViewId, BTreeMap<usize, usize>>,
    /// Pre-effect-staged fragment bookkeeping (see [`Transient`]). Always empty except during the
    /// brief window between staging a mutation's fragments and either committing or rolling them
    /// back -- entered and cleared within the same `remove_mapping`/`insert_mapping` call, never
    /// observed by anything else since the caller holds this whole struct's own lock throughout.
    transient: RangeMap<usize, Transient>,
}

impl<Platform: PageManagementProvider<ALIGN> + 'static, const ALIGN: usize> Vmem<Platform, ALIGN> {
    pub(super) const STACK_GUARD_GAP: usize = 256 << 12;

    /// Create a new [`Vmem`] instance with the given memory [backend](PageManagementProvider).
    pub(super) fn new(platform: &'static Platform) -> Self {
        let mut vmem = Self {
            vmas: TrackedVmas::new(),
            pending_initializations: RangeMap::new(),
            next_initialization_id: 1,
            brk: 0,
            platform,
            reserved: HashMap::new(),
            transient: RangeMap::new(),
        };
        for each in platform.reserved_pages() {
            assert!(
                each.start % ALIGN == 0 && each.end % ALIGN == 0,
                "Vmem: reserved range is not aligned to {ALIGN} bytes"
            );
            vmem.vmas.insert(
                each.start..each.end,
                VmArea {
                    flags: VmFlags::empty(),
                    is_file_backed: false,
                    shared_futex: None,
                    initialization: None,
                },
            );
        }
        vmem
    }

    /// Gets an iterator over all pairs of ([`Range<usize>`], [`VmArea`]),
    /// ordered by key range.
    pub(super) fn iter(&self) -> impl Iterator<Item = (&Range<usize>, &VmArea)> {
        self.vmas.iter()
    }

    /// Whether the mapping table changed since the last [`Self::replay_vma_ops`].
    pub(super) fn has_vma_ops(&self) -> bool {
        !self.vmas.ops.is_empty()
    }

    /// Replays every mapping-table operation logged since the last call into `mirror`, in order,
    /// and empties the log (keeping a bounded capacity, so a steady state allocates nothing).
    /// Returns how many operations it replayed. See [`TrackedVmas`].
    pub(super) fn replay_vma_ops(&mut self, mirror: &mut VmaMirror) -> usize {
        /// Log capacity kept between sections; one exceptional section (an `execve` of a large
        /// image) does not pin its peak forever.
        const KEPT_CAPACITY: usize = 64;
        let replayed = self.vmas.ops.len();
        for op in self.vmas.ops.drain(..) {
            mirror.apply(op);
        }
        if self.vmas.ops.capacity() > KEPT_CAPACITY {
            self.vmas.ops.shrink_to(KEPT_CAPACITY);
        }
        replayed
    }

    /// Reserves a callback identity before publishing the mapping it will own.
    /// Consumed identities are deliberately not reused, including when allocation fails.
    pub(super) fn reserve_initialization_id(&mut self) -> Result<InitializationId, MappingError> {
        let identity = self.next_initialization_id;
        self.next_initialization_id = identity
            .checked_add(1)
            .ok_or(MappingError::InitializationIdentityExhausted)?;
        Ok(InitializationId(identity))
    }

    /// Marks a newly-published mapping as owned by one initialization callback.
    ///
    /// Pure logical bookkeeping (`self.vmas`/`self.pending_initializations` mutation only): no
    /// platform effect call of its own, so there is no pre-effect/post-effect distinction here
    /// for [`Transient`] to protect -- a panic here aborts the process exactly like any other
    /// `BTreeMap` growth in this environment.
    pub(super) fn track_initialization(
        &mut self,
        range: PageRange<ALIGN>,
        identity: InitializationId,
    ) {
        let tracked = Range::from(range);
        let mut vma = {
            let (mapped, vma) = self
                .vmas
                .get_key_value(&tracked.start)
                .expect("a newly created mapping must be tracked");
            assert!(
                mapped.end >= tracked.end,
                "a new mapping must be contiguous"
            );
            *vma
        };
        vma.initialization = Some(identity);
        self.vmas.insert(tracked.clone(), vma);
        self.pending_initializations.insert(tracked, identity);
    }

    /// Returns whether the complete range still belongs to the original callback.
    pub(super) fn owns_initialization(
        &self,
        range: PageRange<ALIGN>,
        identity: InitializationId,
    ) -> bool {
        self.pending_initializations
            .get_key_value(&range.start)
            .is_some_and(|(owned, current)| {
                *current == identity && owned.start <= range.start && owned.end >= range.end
            })
    }

    pub(super) fn has_pending_initialization(&self, range: &Range<usize>) -> bool {
        self.pending_initializations.overlaps(range)
    }

    /// Pure logical bookkeeping (`self.vmas` mutation only): no platform effect call of its
    /// own, so there is no pre-effect/post-effect distinction here for [`Transient`] to protect.
    fn clear_initialization_markers(&mut self, range: Range<usize>) {
        let pieces: Vec<(Range<usize>, VmArea)> = self
            .vmas
            .overlapping(range.clone())
            .filter(|(_, vma)| vma.initialization.is_some())
            .map(|(mapped, vma)| {
                (
                    mapped.start.max(range.start)..mapped.end.min(range.end),
                    *vma,
                )
            })
            .collect();
        for (piece, mut vma) in pieces {
            vma.initialization = None;
            self.vmas.insert(piece, vma);
        }
    }

    /// Completes a callback after its exact mapping has been finalized.
    pub(super) fn finish_initialization(
        &mut self,
        range: PageRange<ALIGN>,
        identity: InitializationId,
    ) -> bool {
        if !self.owns_initialization(range, identity) {
            return false;
        }
        let range = Range::from(range);
        self.pending_initializations.remove(range.clone());
        self.clear_initialization_markers(range);
        true
    }

    /// Removes only fragments still owned by `identity`, never a same-address replacement.
    pub(super) unsafe fn cleanup_initialization(
        &mut self,
        range: PageRange<ALIGN>,
        identity: InitializationId,
    ) -> Result<(), VmemUnmapError> {
        let requested = Range::from(range);
        let pieces: Vec<Range<usize>> = self
            .pending_initializations
            .overlapping(requested.clone())
            .filter(|(_, current)| **current == identity)
            .filter_map(|(owned, _)| {
                let piece = owned.start.max(requested.start)..owned.end.min(requested.end);
                (!piece.is_empty()).then_some(piece)
            })
            .collect();
        let mut first_error = None;
        for piece in pieces {
            // PREPARE: a panic inside `deallocate_pages` then leaves a forensic
            // `Transient::Retiring` record rather than silent, unrecorded loss. Cleared again
            // below once the platform call returns, on both the commit and the rollback path
            // (mirrors `Self::remove_mapping`'s own pattern). No entry is staged if this piece
            // has no corresponding `vmas` entry (nothing to restore either way).
            let restore = self.vmas.get_key_value(&piece.start).map(|(_, v)| *v);
            if let Some(restore) = restore {
                self.transient
                    .insert(piece.clone(), Transient::Retiring { restore });
            }
            // EFFECT
            let effect_result = unsafe { self.platform.deallocate_pages(piece.clone()) };
            self.transient.remove(piece.clone());
            match effect_result {
                Ok(()) => {
                    // COMMIT
                    self.vmas.remove(piece.clone());
                    self.pending_initializations.remove(piece);
                }
                Err(error) => {
                    first_error.get_or_insert(VmemUnmapError::UnmapError(error));
                }
            }
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    /// Pure logical bookkeeping (`self.pending_initializations` mutation only): no platform
    /// effect call of its own, so there is no pre-effect/post-effect distinction here for
    /// [`Transient`] to protect.
    fn invalidate_initializations(&mut self, range: Range<usize>) {
        self.pending_initializations.remove(range.clone());
        self.clear_initialization_markers(range);
    }

    fn assign_shared_futex_identity(&mut self, vma: &mut VmArea, origin: usize) {
        if !vma.flags.contains(VmFlags::VM_SHARED) {
            vma.shared_futex = None;
            return;
        }
        match vma.shared_futex {
            Some(SharedFutexMapping {
                identity,
                position: SharedFutexPosition::PendingOffset(offset),
            }) => {
                vma.shared_futex = Some(SharedFutexMapping {
                    identity,
                    position: SharedFutexPosition::Origin(origin.wrapping_sub(offset)),
                });
            }
            Some(SharedFutexMapping {
                position: SharedFutexPosition::Origin(_),
                ..
            }) => {}
            None => {
                vma.shared_futex = Some(SharedFutexMapping {
                    identity: SharedFutexBacking::new().identity,
                    position: SharedFutexPosition::Origin(origin),
                });
            }
        }
    }

    /// Insert an already-allocated region (e.g., via CoW) without calling the platform allocator.
    ///
    /// Any existing tracked mappings that overlap `range` are silently removed from tracking
    /// (without calling the platform deallocator) before inserting. Use [`Self::overlapping`] to
    /// check for overlap before running this if needed.
    ///
    /// No platform effect call of its own (`self.vmas` bookkeeping only, over an already
    /// materialized region): no pre-effect/post-effect distinction here for [`Transient`] to
    /// protect.
    pub(super) fn register_existing_mapping_overwrite(
        &mut self,
        range: PageRange<ALIGN>,
        mut vma: VmArea,
    ) {
        self.assign_shared_futex_identity(&mut vma, range.start);
        let range = Range::from(range);
        self.vmas.insert(range.clone(), vma);
        self.invalidate_initializations(range);
    }

    /// Gets an iterator over all the stored ranges that are
    /// either partially or completely overlapped by the given range.
    pub(super) fn overlapping(
        &self,
        range: Range<usize>,
    ) -> impl DoubleEndedIterator<Item = (&Range<usize>, &VmArea)> {
        self.vmas.overlapping(range)
    }

    /// Remove a range from its virtual address space, if all or any of it was present.
    ///
    /// If the range to be removed _partially_ overlaps any ranges, then those ranges will
    /// be contracted to no longer cover the removed range.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the memory region is no longer used by any other.
    pub(super) unsafe fn remove_mapping(
        &mut self,
        range: PageRange<ALIGN>,
    ) -> Result<(), VmemUnmapError> {
        // Trace-gated twin of `insert_mapping`'s replace log: in a
        // process-blind manager shared by several guest processes, every
        // removal is a potential cross-process teardown, and knowing exactly
        // which ranges were removed (correlated with the shim's own
        // pid/tid-stamped syscall trace) is what pins down who removed them.
        litebox_util_log::trace!(
            start:? = range.start, end:? = range.end;
            "removing mapping"
        );
        let range = Range::from(range);
        // PREPARE: collected once and reused below for both the deferred/non-deferred split
        // logic and the pre-effect staging -- no need to re-query `vmas` a second time.
        let pieces: alloc::vec::Vec<(Range<usize>, VmArea)> = self
            .overlapping(range.clone())
            .map(|(r, vma)| (r.clone(), *vma))
            .collect();
        let deferred_pieces_present = pieces
            .iter()
            .any(|(_, vma)| vma.flags.contains(VmFlags::VM_DEFERRED));
        // Every fragment that will actually receive a real platform teardown call (deferred
        // fragments never reach the platform, so nothing is staged for them) is recorded here
        // before that call runs: a panic inside `deallocate_pages` then leaves a forensic
        // `Transient::Retiring` record rather than silent, unrecorded loss. Cleared again below
        // once the platform call returns, on both the commit and the rollback path.
        let mut effect_pieces: alloc::vec::Vec<Range<usize>> = alloc::vec::Vec::new();
        for (r, vma) in &pieces {
            if vma.flags.contains(VmFlags::VM_DEFERRED) {
                continue;
            }
            let piece = r.start.max(range.start)..r.end.min(range.end);
            if piece.is_empty() {
                continue;
            }
            self.transient
                .insert(piece.clone(), Transient::Retiring { restore: *vma });
            effect_pieces.push(piece);
        }

        // EFFECT
        let effect_result: Result<(), crate::platform::page_mgmt::DeallocationError> = if !deferred_pieces_present {
            unsafe { self.platform.deallocate_pages(range.clone()) }
        } else {
            // Deferred (VM_DEFERRED) pieces have no platform state to tear
            // down; deallocating the whole range would ask the platform to
            // unmap pages it never mapped. Deallocate only the pieces that
            // were actually materialized.
            let mut first_error = None;
            for piece in &effect_pieces {
                if let Err(error) = unsafe { self.platform.deallocate_pages(piece.clone()) } {
                    first_error = Some(error);
                    break;
                }
            }
            match first_error {
                Some(error) => Err(error),
                None => Ok(()),
            }
        };

        // The platform call has returned either way: nothing is in flight any more, so every
        // staged fragment is cleared regardless of outcome (on failure this is the ROLLBACK --
        // `vmas` itself is untouched below, so there is nothing left to restore).
        for piece in &effect_pieces {
            self.transient.remove(piece.clone());
        }
        effect_result.map_err(VmemUnmapError::UnmapError)?;

        // COMMIT
        self.vmas.remove(range.clone());
        self.invalidate_initializations(range);
        Ok(())
    }

    /// Reset pages without removing its mapping (similar to Linux `madvise` with
    /// `MADV_DONTNEED` or `MADV_FREE`).
    ///
    /// Per-VMA Linux semantics (see the `madvise-dontneed-file-backed-reset` PRD row):
    /// - Private anonymous: dropped and refaulted zero-filled (the `insert_mapping`
    ///   `Replace` path below) -- for both advice values alike.
    /// - `VM_SHARED` (file-backed or anonymous -- memfd, `.pak`, shm): left completely
    ///   untouched, for both advice values. Linux's own contract is that the next access
    ///   observes the shared object's *current* bytes either way (`MADV_DONTNEED` merely
    ///   zaps the PTE; neither advice value ever discards a real shared object's content),
    ///   and `Vmem` has no lesser-effort "zap PTE, keep the same backing" primitive to
    ///   offer instead of a full deallocate/reallocate -- which would risk fabricating a
    ///   fresh backing under the reused `shared_futex` identity rather than provably
    ///   reconnecting to the live one. A no-op is strictly safe and observably correct.
    /// - Private file-backed: returns `Err(VmemResetError::FileBacked)` for both advice
    ///   values. Real Linux instead discards dirty COW'd content and refaults the file's
    ///   own original bytes on the next access -- but `VmArea` retains no durable reference
    ///   back to the source file/offset once the initial `mmap` populates a mapping (every
    ///   real file-content population site -- `do_mmap_file_memcpy`'s eager copy and
    ///   `try_cow_mmap_file`'s COW-over-`static_data` fast path alike -- lives in
    ///   `litebox_shim_linux/src/syscalls/mm.rs`, permanently read-only under this
    ///   project's standing constraints; see
    ///   `mremap-private-file-grow-content-population-shim-boundary-remainder` for the
    ///   identical architectural wall hit independently by `mremap`'s own grow path, and
    ///   `madvise-dontneed-file-backed-content-replay` for this row's own tracked
    ///   remainder). Silently substituting zero-fill instead would be objectively wrong
    ///   content -- strictly worse than a typed, loudly-returned error -- so this refuses
    ///   instead, exactly as the `anonymous_only` case below already did before this
    ///   function supported any file-backed arm at all.
    ///
    /// Delegation-covered, not a separate `Transient` staging site: every actual platform
    /// effect here runs through [`Self::insert_mapping`]'s own `Replace` call, already staged.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the memory contents in the affected region are no longer accessed or
    /// relied upon. Any pointers or references to the previous contents become invalid.
    pub(super) unsafe fn reset_pages(
        &mut self,
        range: PageRange<ALIGN>,
        anonymous_only: bool,
    ) -> Result<(), VmemResetError> {
        let _ = anonymous_only;
        let range: Range<usize> = range.into();
        // Any unmapped regions in the original range will result in this function returning `DeallocationError::AlreadyUnallocated`
        // while still resetting all of the existing vmas in the range.
        let unmapped_error = self.vmas.gaps(&range).next().is_some();
        let overlapping_ranges: Vec<(Range<usize>, VmArea)> = self
            .overlapping(range.clone())
            .map(|(r, vma)| (r.clone(), *vma))
            .collect();
        for (r, vma) in overlapping_ranges {
            if vma.flags.contains(VmFlags::VM_SHARED) {
                // MAP_SHARED file-backed and shared anonymous alike: see the doc comment
                // above. Neither advice value ever touches a shared VMA's backing.
                continue;
            }
            if vma.is_file_backed() {
                // Private file-backed: see the doc comment above. Loudly refuse instead of
                // panicking or corrupting content with zero-fill; identical for both
                // DONTNEED and FREE, since neither can correctly refault real file bytes
                // yet.
                return Err(VmemResetError::FileBacked);
            }
            if vma.flags.contains(VmFlags::VM_DEFERRED) {
                // A deferred reservation has no contents to invalidate: it is
                // still pure VA bookkeeping, exactly the state a reset would
                // restore.
                continue;
            }
            let start = r.start.max(range.start);
            let end = r.end.min(range.end);
            let new_range = PageRange::new(start, end).unwrap();
            unsafe { self.insert_mapping(new_range, vma, false, FixedAddressBehavior::Replace) }
                .map_err(VmemResetError::Platform)?;
        }
        if unmapped_error {
            Err(VmemResetError::AlreadyUnallocated)
        } else {
            Ok(())
        }
    }

    /// Insert a range to its virtual address space.
    ///
    /// If the inserted range partially or completely overlaps any
    /// existing range in the map, then the existing range (or ranges) will be
    /// partially or completely replaced by the inserted range.
    ///
    /// If the inserted range either overlaps or is immediately adjacent
    /// any existing range _mapping to the same value_, then the ranges
    /// will be coalesced into a single contiguous range.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the memory region is not used by any other (i.e., safe
    /// to unmap all overlapping mappings if any).
    pub(super) unsafe fn insert_mapping(
        &mut self,
        suggested_range: PageRange<ALIGN>,
        mut vma: VmArea,
        populate_pages_immediately: bool,
        fixed_address_behavior: FixedAddressBehavior,
    ) -> Result<Platform::RawMutPointer<u8>, AllocationError> {
        let (start, end) = (suggested_range.start, suggested_range.end);
        if start < Platform::TASK_ADDR_MIN {
            return Err(AllocationError::BelowMinAddress);
        }
        if end > Platform::TASK_ADDR_MAX {
            return Err(AllocationError::AboveMaxAddress);
        }
        if vma.flags.contains(VmFlags::VM_DEFERRED) {
            // A deferred reservation is pure VA bookkeeping: the platform is
            // engaged only when the range is materialized (see
            // `protect_mapping`). Fresh placements arrive with no overlap by
            // `get_unmmaped_area` construction, and `reset_pages` never
            // re-inserts a deferred area, so any overlap here would mean
            // skipping a live mapping's platform teardown -- refuse it loudly
            // instead of leaking it.
            if self.vmas.overlaps(&(start..end)) {
                return Err(AllocationError::AddressInUse);
            }
            self.vmas.insert(start..end, vma);
            self.invalidate_initializations(start..end);
            return Ok(Platform::RawMutPointer::from_usize(start));
        }
        let platform_fixed_address_behavior = match fixed_address_behavior {
            FixedAddressBehavior::Hint => FixedAddressBehavior::Hint,
            FixedAddressBehavior::NoReplace => {
                // Ensure there are no mappings managed by us.
                if self.vmas.overlaps(&(start..end)) {
                    return Err(AllocationError::AddressInUse);
                }
                FixedAddressBehavior::NoReplace
            }
            FixedAddressBehavior::Replace => {
                if self.vmas.overlaps(&(start..end)) {
                    // A fixed mapping quietly destroying live mappings is the
                    // correct MAP_FIXED semantic *within one process*, but in
                    // this process-blind manager it is also how one guest
                    // process can destroy another's memory -- worth a
                    // permanent record whenever it fires.
                    litebox_util_log::debug!(
                        start:? = start, end:? = end;
                        "fixed-address mapping replaces existing mapping(s)"
                    );
                    if self.vmas.gaps(&(start..end)).next().is_some() {
                        // The range is partially overlapping with existing
                        // mappings. If we call into the platform with
                        // `Replace`, then it may overwrite external mappings
                        // that are not managed by us.
                        //
                        // FUTURE: support this case, either by splitting this
                        // into multiple allocate calls or by separating VA
                        // allocation from page backing.
                        return Err(AllocationError::AddressPartiallyInUse);
                    }
                    FixedAddressBehavior::Replace
                } else {
                    // There are no mappings managed by us, so just treat this
                    // as NoReplace.
                    FixedAddressBehavior::NoReplace
                }
            }
        };
        // PREPARE (fixed-address branches only -- `Hint` placement's final address is chosen *by*
        // the platform call itself, so no exact key is known yet to stage against): record the
        // not-yet-materialized target before the platform call runs. Whatever this range's
        // previous `VmArea` was (the `Replace` case) stays directly readable from `self.vmas`
        // itself throughout -- `vmas` is not touched until the commit step below -- so nothing
        // needs to be separately duplicated here. A panic inside `allocate_pages`/
        // `allocate_shared_pages` leaves this forensic `Transient::Installing` record rather than
        // silent, unrecorded loss; cleared again once the platform call returns, on both the
        // commit and the rollback path.
        //
        // KNOWN, DISCLOSED CARVE-OUT (`Hint` only): `PageManagementProvider::allocate_pages`
        // itself performs the placement search and returns the chosen address; there is no
        // pre-effect target key available to stage against without splitting the trait's
        // placement search from its own commit step, a larger cross-trait change not attempted
        // here. A panic inside `allocate_pages` while resolving a `Hint` therefore leaves no
        // `Transient` record at all -- an accepted, narrow gap, distinct from every other branch
        // of this function.
        let staged_fixed_range = if matches!(fixed_address_behavior, FixedAddressBehavior::Hint) {
            None
        } else {
            self.transient
                .insert(start..end, Transient::Installing { publish: vma });
            Some(start..end)
        };
        if vma.flags.contains(VmFlags::VM_SHARED) && vma.shared_futex.is_none() {
            vma.shared_futex = Some(SharedFutexMapping {
                identity: SharedFutexBacking::new().identity,
                position: SharedFutexPosition::PendingOffset(0),
            });
        }
        let shared_allocation = vma.shared_futex.map(|shared| {
            let offset = match shared.position {
                SharedFutexPosition::PendingOffset(offset) => offset,
                SharedFutexPosition::Origin(origin) => start.wrapping_sub(origin),
            };
            (shared.identity, offset)
        });
        let permissions: u8 = vma
            .flags
            .intersection(VmFlags::VM_ACCESS_FLAGS)
            .bits()
            .try_into()
            .unwrap();
        let max_permissions: u8 = (vma.flags.intersection(VmFlags::VM_MAY_ACCESS_FLAGS).bits()
            >> 4)
            .try_into()
            .unwrap();
        // The `max_permissions` is tracked by `VMem::protect_mapping` and thus doesn't need to be
        // passed to `allocate_pages`.
        let _ = max_permissions;
        let permissions = MemoryRegionPermissions::from_bits(permissions).unwrap();
        let suggested_range = Range::from(suggested_range);
        let suggested_len = suggested_range.len();
        // EFFECT
        let effect_result = if let Some((identity, offset)) = shared_allocation {
            self.platform.allocate_shared_pages(
                identity,
                offset,
                suggested_range,
                permissions,
                vma.flags.contains(VmFlags::VM_GROWSDOWN),
                populate_pages_immediately,
                platform_fixed_address_behavior,
            )
        } else {
            self.platform.allocate_pages(
                suggested_range,
                permissions,
                vma.flags.contains(VmFlags::VM_GROWSDOWN),
                populate_pages_immediately,
                platform_fixed_address_behavior,
            )
        }
        .map_err(|err| match err {
            AllocationError::AddressInUse => AllocationError::AddressInUseByPlatform,
            other => other,
        });
        // The platform call has returned either way: nothing is in flight any more, so the staged
        // fragment is cleared regardless of outcome (on failure this is the ROLLBACK -- `vmas`
        // itself is untouched below, so there is nothing left to restore).
        if let Some(staged) = staged_fixed_range {
            self.transient.remove(staged);
        }
        let ret = effect_result?;
        let new_start = ret.as_usize();
        let new_end = new_start + suggested_len;
        self.assign_shared_futex_identity(&mut vma, new_start);
        let installed = new_start..new_end;
        self.vmas.insert(installed.clone(), vma);
        self.invalidate_initializations(installed);
        debug_assert!(new_start >= Platform::TASK_ADDR_MIN);
        debug_assert!(new_end <= Platform::TASK_ADDR_MAX);
        Ok(ret)
    }

    /// Create a new mapping in the virtual address space.
    ///
    /// `suggested_address` is the hint address for where to create the pages if it is not `None`.
    /// Otherwise, let the kernel choose an available memory region.
    ///
    /// `length` is the size of the pages to be created.
    ///
    /// Set `flags` to control options such as fixed address, stack, and populate pages.
    ///
    /// Return `Some(new_addr)` if the mapping is created successfully.
    /// The returned address is `ALIGN`-aligned.
    ///
    /// # Fixed Address Behavior
    ///
    /// - [`CreatePagesFlags::FIXED_ADDR`] alone: Forces allocation at the exact address, replacing
    ///   any existing overlapping mappings. Caller must ensure overlapping mappings are not in use.
    /// - [`CreatePagesFlags::FIXED_ADDR`] with [`CreatePagesFlags::NOREPLACE`]: Forces allocation at
    ///   the exact address, but fails with [`AllocationError::AddressInUse`] if any part of the
    ///   range is already mapped. This is safe to use without checking for existing mappings first.
    /// - Without [`CreatePagesFlags::FIXED_ADDR`], the address is treated as a hint.
    ///
    /// Note: `NOREPLACE` error responses (`AddressInUse` / `EEXIST`) can be used to probe memory
    /// layout. This matches Linux kernel behavior for `MAP_FIXED_NOREPLACE`.
    ///
    /// # Safety
    ///
    /// When using [`CreatePagesFlags::FIXED_ADDR`] without [`CreatePagesFlags::NOREPLACE`], the
    /// caller must ensure any overlapping mappings are not used by any other code, as they will be
    /// unmapped.
    /// `steer_owner` scopes [`Self::reserved`] steering for the flexible-placement search to this
    /// one owner's own reservations (see [`Self::reserved_overlaps`]) -- pass the calling guest
    /// task's own [`VmViewId`] (from `Platform::current_guest_access`) so an unrelated family's
    /// vfork-parked reservation can never steer this placement, or `None` from a host-internal
    /// caller with no such context (preserves this search's original, fully owner-blind
    /// steering, i.e. no behavior change for such a caller).
    pub(super) unsafe fn create_mapping(
        &mut self,
        suggested_address: Option<NonZeroAddress<ALIGN>>,
        length: NonZeroPageSize<ALIGN>,
        vma: VmArea,
        flags: CreatePagesFlags,
        steer_owner: Option<VmViewId>,
    ) -> Result<Platform::RawMutPointer<u8>, AllocationError> {
        let total_length = (length
            + if flags.contains(CreatePagesFlags::ENSURE_SPACE_AFTER) {
                DEFAULT_RESERVED_SPACE_SIZE
            } else {
                0
            })
        .unwrap();
        let new_addr = self
            .get_unmmaped_area(
                suggested_address,
                total_length,
                flags.contains(CreatePagesFlags::FIXED_ADDR),
                steer_owner,
            )
            .ok_or(AllocationError::OutOfMemory)?;
        // new_addr must be ALIGN aligned
        let new_range = PageRange::new(new_addr, new_addr + length.as_usize()).unwrap();
        unsafe {
            self.insert_mapping(
                new_range,
                vma,
                flags.contains(CreatePagesFlags::POPULATE_PAGES_IMMEDIATELY),
                if flags.contains(CreatePagesFlags::FIXED_ADDR) {
                    if flags.contains(CreatePagesFlags::NOREPLACE) {
                        FixedAddressBehavior::NoReplace
                    } else {
                        FixedAddressBehavior::Replace
                    }
                } else {
                    FixedAddressBehavior::Hint
                },
            )
        }
    }

    /// Resize a range in the virtual address space.
    /// Shrink the range if it is larger than `new_size`.
    /// Enlarge the range if it is smaller than `new_size` and will not overlap with
    /// next mapping after the expansion.
    ///
    /// It fails if it resizes more than one mapping or needs to split the current mapping
    /// (due to enlarging).
    ///
    /// See <https://elixir.bootlin.com/linux/v5.19.17/source/mm/mremap.c#L886> for reference.
    ///
    /// Delegation-covered, not a separate `Transient` staging site: both the shrink and grow
    /// paths run their actual platform effect entirely through [`Self::remove_mapping`] /
    /// [`Self::insert_mapping`], already staged.
    ///
    /// # Safety
    ///
    /// If it shrinks, the caller must ensure that the unmapped memory region is not used by any other.
    pub(super) unsafe fn resize_mapping(
        &mut self,
        range: PageRange<ALIGN>,
        new_size: NonZeroPageSize<ALIGN>,
    ) -> Result<(), VmemResizeError> {
        let range = range.start..range.end;
        // `cur_range` contains `range.start`
        let (cur_range, cur_vma) = self
            .vmas
            .get_key_value(&range.start)
            .ok_or(VmemResizeError::NotExist(range.start))?;

        let new_end = range.start + new_size.as_usize();
        if new_end == range.end {
            return Ok(());
        }
        if range.end > cur_range.end {
            return Err(VmemResizeError::InvalidAddr {
                range: cur_range.clone(),
                addr: range.end,
            });
        }
        if self.has_pending_initialization(&range) {
            return Err(VmemResizeError::InitializationPending(range));
        }
        if new_end < range.end {
            let removed = PageRange::new(new_end, range.end).unwrap();
            unsafe { self.remove_mapping(removed) }.map_err(VmemResizeError::UnmapError)?;
            return Ok(());
        }

        // grow
        if range.end == cur_range.end {
            // expand the current range
            let r = range.end..new_end;
            if self.vmas.overlaps(&r) {
                return Err(VmemResizeError::RangeOccupied(r));
            }
            // A private file-backed mapping grown past its original extent gets
            // anonymous zero-fill pages for the new range, exactly as Linux's own
            // `mremap` does: nothing re-reads more file content in just because the
            // mapping got bigger, and `insert_mapping` below never populates content
            // itself either way (the caller's initial `mmap` copies file bytes in as
            // a separate step; growing calls no such step). Tagging the new piece
            // `is_file_backed: false` -- instead of cloning `*cur_vma` verbatim --
            // matters beyond bookkeeping accuracy: `reset_pages`/`set_wipe_on_fork`
            // both refuse to touch a range they see as file-backed, and this tail is
            // genuinely anonymous memory now, so it must qualify for both.
            let new_piece_vma = if cur_vma.is_file_backed() && !cur_vma.flags.contains(VmFlags::VM_SHARED) {
                VmArea::new(cur_vma.flags, false, None)
            } else {
                *cur_vma
            };
            let range = PageRange::new(range.end, new_end).unwrap();
            // Try to extend the mapping. Although we checked that there are no
            // litebox mappings in this range, this may fail if there are
            // platform mappings in the way.
            match unsafe {
                self.insert_mapping(range, new_piece_vma, false, FixedAddressBehavior::NoReplace)
            } {
                Ok(_) => {}
                Err(AllocationError::OutOfMemory) => return Err(VmemResizeError::OutOfMemory),
                Err(
                    AllocationError::AddressInUse
                    | AllocationError::AddressInUseByPlatform
                    | AllocationError::AddressPartiallyInUse,
                ) => return Err(VmemResizeError::RangeOccupied(range.into())),
                Err(
                    AllocationError::Unaligned
                    | AllocationError::BelowMinAddress
                    | AllocationError::AboveMaxAddress,
                ) => unreachable!(),
            }
            return Ok(());
        }

        // has to split the current range and move it to somewhere else
        Err(VmemResizeError::RangeOccupied(range.end..cur_range.end))
    }

    /// Move a range from `old_range` to `suggested_new_range`.
    /// Use it together with [`Vmem::resize_mapping`] to achieve `mremap`.
    ///
    /// The `suggested_new_range.start` is used as a hint for the new address.
    /// If it is zero, kernel will choose a new suitable address freely.
    ///
    /// Returns `Some(new_addr)` if the range is moved successfully
    /// Otherwise, returns `None`.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the given `range` is safe to be unmapped.
    ///
    /// # Panics
    ///
    /// Panics if the size of `suggested_new_range` is smaller than the size of `old_range`.
    /// Panics if the `old_range` is not covered by exactly one mapping.
    pub(super) unsafe fn move_mappings(
        &mut self,
        old_range: PageRange<ALIGN>,
        suggested_new_address: Option<NonZeroAddress<ALIGN>>,
        new_size: NonZeroPageSize<ALIGN>,
    ) -> Result<Platform::RawMutPointer<u8>, VmemMoveError> {
        assert!(new_size.as_usize() >= old_range.len());

        // Check if the given range is covered by exactly one mapping
        let (cur_range, vma) = self
            .vmas
            .get_key_value(&old_range.start)
            .expect("VMEM: range not found");
        assert!(cur_range.contains(&(old_range.end - 1)));
        // Copied out to an owned value immediately: everything below needs `self.transient`
        // (a different field) mutated while still consulting the old mapping's contents, which
        // a live borrow through `self.vmas.get_key_value` would otherwise conflict with.
        let vma = *vma;
        if self.has_pending_initialization(&Range::from(old_range)) {
            return Err(VmemMoveError::OutOfMemory);
        }

        // `steer_owner: None` -- out of this fix's scope (the confirmed bug and its live
        // reproduction are both about a fresh `mmap`'s placement, not `mremap`'s), so this
        // unconditionally keeps the exact pre-fix, fully owner-blind steering: every live
        // reservation from every family still steers an `mremap`'s own placement search, same as
        // before this change.
        let new_addr = self
            .get_unmmaped_area(suggested_new_address, new_size, false, None)
            .ok_or(VmemMoveError::OutOfMemory)?;
        let new_range = PageRange::<ALIGN>::new(new_addr, new_addr + new_size.as_usize()).unwrap();
        let shared_remap = vma.shared_futex.map(|shared| {
            let SharedFutexPosition::Origin(origin) = shared.position else {
                unreachable!("installed shared futex mappings always have an origin")
            };
            (shared.identity, old_range.start.wrapping_sub(origin))
        });
        // `new_addr` is a real pre-known target (unlike `Hint` placement in `insert_mapping`,
        // which the platform call itself picks): `get_unmmaped_area` already reserved it above,
        // so the fully-computed post-move `VmArea` (including its shared-futex origin, rebased
        // onto this already-known `new_addr`) can be staged before the platform call runs.
        let mut moved_vma = vma;
        let new_start = new_range.start;
        let new_end = new_range.end;
        if let Some(shared) = &mut moved_vma.shared_futex {
            let SharedFutexPosition::Origin(origin) = &mut shared.position else {
                unreachable!("installed shared futex mappings always have an origin")
            };
            let old_offset = old_range.start.wrapping_sub(*origin);
            *origin = new_start.wrapping_sub(old_offset);
        }
        // A private file-backed mapping only reaches this function (rather than returning
        // early from `resize_mapping`) when it is also growing -- `PageManager::remap_pages`
        // only calls `move_mappings` after `resize_mapping` reports `RangeOccupied`, and
        // `resize_mapping` itself resolves a same-size request (`new_end == range.end`)
        // before any occupancy check runs, so `new_size` exceeds `old_range.len()` on every
        // real caller. The relocated head (`new_start .. new_start + old_len`) is filled by
        // the EFFECT call below with the *exact current bytes* of the old range (a byte-level
        // copy either via this platform's own override or the default `RawConstPointer`-based
        // trait body -- see both `remap_pages` doc comments), so whatever a COW fault already
        // diverged stays diverged and an untouched alias's pristine file bytes move across
        // unchanged: that portion genuinely keeps its file identity and stays tagged
        // `is_file_backed`. Any grown tail beyond that (`new_start + old_len .. new_end`) is
        // fresh platform-allocated space the EFFECT call never writes real file content into
        // -- this manager has no file/fd access below the shim syscall boundary to read
        // further file bytes (see `resize_mapping`'s identical, already-shipped tail split
        // above for the in-place-growth twin of this same gap) -- so it is tagged anonymous
        // for the same reason `resize_mapping`'s tail is: `reset_pages`/`set_wipe_on_fork`
        // must see it as anonymous, and, lacking real file content, it genuinely is.
        let old_len = old_range.len();
        let grown_tail = (moved_vma.is_file_backed()
            && !moved_vma.flags.contains(VmFlags::VM_SHARED)
            && new_size.as_usize() > old_len)
            .then(|| VmArea::new(moved_vma.flags, false, None));
        // PREPARE: a panic inside `remap_pages`/`remap_shared_pages` then leaves a forensic
        // `Transient::Retiring` at the old range and `Transient::Installing` at the new one,
        // rather than silent, unrecorded loss. Cleared again below once the platform call
        // returns, on both the commit and the rollback path.
        self.transient
            .insert(Range::from(old_range), Transient::Retiring { restore: vma });
        self.transient.insert(
            new_start..new_end,
            Transient::Installing { publish: moved_vma },
        );
        // EFFECT
        let effect_result = unsafe {
            if let Some((identity, offset)) = shared_remap {
                self.platform.remap_shared_pages(
                    identity,
                    offset,
                    old_range.into(),
                    new_range.into(),
                    vma.flags.into(),
                )
            } else {
                self.platform
                    .remap_pages(old_range.into(), new_range.into(), vma.flags.into())
            }
        };
        // The platform call has returned either way: nothing is in flight any more, so both
        // staged fragments are cleared regardless of outcome (on failure this is the ROLLBACK --
        // `vmas` itself is untouched below, so there is nothing left to restore).
        self.transient.remove(Range::from(old_range));
        self.transient.remove(new_start..new_end);
        let new_addr = effect_result.map_err(VmemMoveError::RemapError)?;

        // COMMIT
        let installed = new_start..new_end;
        match grown_tail {
            Some(tail_vma) => {
                let split = new_start + old_len;
                self.vmas.insert(new_start..split, moved_vma);
                self.vmas.insert(split..new_end, tail_vma);
            }
            None => {
                self.vmas.insert(installed.clone(), moved_vma);
            }
        }
        self.vmas.remove(old_range.into());
        self.invalidate_initializations(installed);
        self.invalidate_initializations(old_range.into());
        Ok(new_addr)
    }

    /// Commits a flag change into `self.vmas` for one already-decided fragment (splitting the
    /// original entry at its edges if needed). Called from [`Self::protect_mapping`] (post its
    /// own real platform effect, already staged there) and from [`Self::set_wipe_on_fork`] /
    /// [`Self::set_dont_fork`], neither of which calls any platform effect of their own for a
    /// flag-only change -- `self.vmas` mutation only, so there is no pre-effect/post-effect
    /// distinction here for [`Transient`] to protect in those two callers.
    fn record_protected_piece(
        &mut self,
        original: Range<usize>,
        intersection: Range<usize>,
        vma: VmArea,
        flags: VmFlags,
    ) {
        self.vmas.remove(original.clone());
        let before = original.start..intersection.start;
        let after = intersection.end..original.end;
        self.vmas.insert(
            intersection,
            VmArea {
                flags,
                is_file_backed: vma.is_file_backed,
                shared_futex: vma.shared_futex,
                initialization: vma.initialization,
            },
        );
        if !before.is_empty() {
            self.vmas.insert(before, vma);
        }
        if !after.is_empty() {
            self.vmas.insert(after, vma);
        }
    }

    /// Sets (`MADV_WIPEONFORK`) or clears (`MADV_KEEPONFORK`) [`VmFlags::VM_WIPEONFORK`] on
    /// every mapping overlapping `range`, splitting mappings at the range's edges exactly as
    /// [`Self::protect_mapping`] does for access flags.
    ///
    /// Mirrors Linux's `madvise_vma_behavior`: the flag is refused with `EINVAL` on a
    /// file-backed or shared mapping (there is no private copy to wipe), and a hole in the
    /// range is `ENOMEM`. Every mapping is validated before any is changed, so an error
    /// leaves the flags as they were. A `VM_DEFERRED` reservation can carry the flag -- it is
    /// pure bookkeeping until the reservation is materialized, and a wipe of it is a no-op
    /// because it has no contents yet.
    pub(super) fn set_wipe_on_fork(
        &mut self,
        range: PageRange<ALIGN>,
        enable: bool,
    ) -> Result<(), VmemWipeOnForkError> {
        let range = range.start..range.end;
        let pieces: Vec<(Range<usize>, Range<usize>, VmArea)> = self
            .vmas
            .overlapping(range.clone())
            .map(|(mapped, vma)| {
                (
                    mapped.clone(),
                    mapped.start.max(range.start)..mapped.end.min(range.end),
                    *vma,
                )
            })
            .collect();
        let mut covered = range.start;
        let mut holes = false;
        for (_, intersection, vma) in &pieces {
            if intersection.start != covered {
                holes = true;
            }
            covered = intersection.end;
            if enable && (vma.is_file_backed || vma.flags.contains(VmFlags::VM_SHARED)) {
                return Err(VmemWipeOnForkError::NotPrivateAnonymous(intersection.clone()));
            }
        }
        if covered != range.end {
            holes = true;
        }
        for (original, intersection, vma) in pieces {
            if vma.flags.contains(VmFlags::VM_WIPEONFORK) == enable {
                continue;
            }
            let mut flags = vma.flags;
            flags.set(VmFlags::VM_WIPEONFORK, enable);
            self.record_protected_piece(original, intersection, vma, flags);
        }
        if holes {
            return Err(VmemWipeOnForkError::Unmapped(range));
        }
        Ok(())
    }

    /// Every mapping carrying [`VmFlags::VM_WIPEONFORK`], with its flags, in address order.
    pub(super) fn wipe_on_fork_ranges(&self) -> Vec<(Range<usize>, VmFlags)> {
        self.vmas
            .iter()
            .filter(|(_, vma)| vma.flags.contains(VmFlags::VM_WIPEONFORK))
            .map(|(r, vma)| (r.clone(), vma.flags))
            .collect()
    }

    /// Sets (`MADV_DONTFORK`) or clears (`MADV_DOFORK`) [`VmFlags::VM_DONTCOPY`] on every
    /// mapping overlapping `range`, splitting mappings at the range's edges exactly as
    /// [`Self::set_wipe_on_fork`] does.
    ///
    /// Unlike [`Self::set_wipe_on_fork`], this is legal on any mapping (file-backed, shared,
    /// or private) -- real Linux's `MADV_DONTFORK` carries no such restriction. A hole in the
    /// range is still `ENOMEM`, and every mapping is validated before any is changed.
    pub(super) fn set_dont_fork(
        &mut self,
        range: PageRange<ALIGN>,
        enable: bool,
    ) -> Result<(), VmemDontForkError> {
        let range = range.start..range.end;
        let pieces: Vec<(Range<usize>, Range<usize>, VmArea)> = self
            .vmas
            .overlapping(range.clone())
            .map(|(mapped, vma)| {
                (
                    mapped.clone(),
                    mapped.start.max(range.start)..mapped.end.min(range.end),
                    *vma,
                )
            })
            .collect();
        let mut covered = range.start;
        let mut holes = false;
        for (_, intersection, _) in &pieces {
            if intersection.start != covered {
                holes = true;
            }
            covered = intersection.end;
        }
        if covered != range.end {
            holes = true;
        }
        for (original, intersection, vma) in pieces {
            if vma.flags.contains(VmFlags::VM_DONTCOPY) == enable {
                continue;
            }
            let mut flags = vma.flags;
            flags.set(VmFlags::VM_DONTCOPY, enable);
            self.record_protected_piece(original, intersection, vma, flags);
        }
        if holes {
            return Err(VmemDontForkError::Unmapped(range));
        }
        Ok(())
    }

    /// Every mapping carrying [`VmFlags::VM_DONTCOPY`], with its flags, in address order.
    pub(super) fn dont_fork_ranges(&self) -> Vec<(Range<usize>, VmFlags)> {
        self.vmas
            .iter()
            .filter(|(_, vma)| vma.flags.contains(VmFlags::VM_DONTCOPY))
            .map(|(r, vma)| (r.clone(), vma.flags))
            .collect()
    }

    /// Change the permissions ([`VmFlags::VM_ACCESS_FLAGS`]) of a range in the virtual address space.
    ///
    /// See <https://elixir.bootlin.com/linux/v5.19.17/source/mm/mprotect.c#L617> for reference.
    ///
    /// Linux-exact partial-application ordering: this walks the range in address order and
    /// applies the change to every mapping it has already walked before it returns an error. A
    /// gap or `VM_MAY`-incompatible mapping at the very start of `range` is refused before any
    /// mutation; one discovered further in still leaves every mapping walked before it changed.
    ///
    /// # Safety
    ///
    /// The caller must ensure it is safe to change the permissions of the given range, e.g., no more
    /// write access to the range if it is changed to read-only.
    pub(super) unsafe fn protect_mapping(
        &mut self,
        range: PageRange<ALIGN>,
        permissions: MemoryRegionPermissions,
    ) -> Result<(), VmemProtectError> {
        // `MemoryRegionPermissions` is a subset of `VmFlags` and we only change the access flags
        let flags =
            VmFlags::from_bits(u32::from(permissions.bits())).unwrap() & VmFlags::VM_ACCESS_FLAGS;
        let range = range.start..range.end;
        let mappings_to_change: Vec<(Range<usize>, Range<usize>, VmArea)> = self
            .vmas
            .overlapping(range.clone())
            .map(|(mapped, vma)| {
                (
                    mapped.clone(),
                    mapped.start.max(range.start)..mapped.end.min(range.end),
                    *vma,
                )
            })
            .collect();
        // Walk in address order, stopping at the first gap or `VM_MAY`-incompatible mapping.
        // Everything walked before that point is a real, contiguous, compatible prefix that gets
        // applied below; the offending fragment and anything after it never does.
        let mut covered = range.start;
        let mut applicable: Vec<(Range<usize>, Range<usize>, VmArea)> = Vec::new();
        let mut pending_error: Option<VmemProtectError> = None;
        for (original, intersection, vma) in mappings_to_change {
            if intersection.start != covered {
                pending_error = Some(VmemProtectError::InvalidRange(range.clone()));
                break;
            }
            if (!(vma.flags.bits() >> 4) & flags.bits()) & VmFlags::VM_ACCESS_FLAGS.bits() != 0 {
                pending_error = Some(VmemProtectError::NoAccess {
                    old: vma.flags,
                    new: flags,
                });
                break;
            }
            covered = intersection.end;
            applicable.push((original, intersection, vma));
        }
        if pending_error.is_none() && covered != range.end {
            pending_error = Some(VmemProtectError::InvalidRange(range.clone()));
        }

        if applicable
            .iter()
            .all(|(_, _, vma)| vma.flags & VmFlags::VM_ACCESS_FLAGS == flags)
        {
            return match pending_error {
                Some(err) => Err(err),
                None => Ok(()),
            };
        }

        let any_deferred = applicable
            .iter()
            .any(|(_, _, vma)| vma.flags.contains(VmFlags::VM_DEFERRED));

        if self.platform.has_transactional_permission_updates() && !any_deferred {
            // This provider explicitly guarantees that an ordinary error means
            // no page changed; HVF uses process-abort containment after any
            // lower publication. One call over exactly the applicable prefix
            // (never the offending fragment or anything after it) closes the
            // multi-VMA partial-progress boundary without assuming the same of
            // native providers with reservation or backing boundaries.
            if let (Some((_, first, _)), Some((_, last, _))) =
                (applicable.first(), applicable.last())
            {
                let applied_range = first.start..last.end;
                // PREPARE: one `Transient::Installing` per fragment that will actually change,
                // matching the single batched call below -- a panic inside `update_permissions`
                // then leaves a forensic record per fragment rather than silent, unrecorded loss.
                let mut staged: Vec<Range<usize>> = Vec::new();
                for (_, intersection, vma) in &applicable {
                    if vma.flags & VmFlags::VM_ACCESS_FLAGS != flags {
                        let new_flags = (vma.flags & !VmFlags::VM_ACCESS_FLAGS) | flags;
                        let publish = VmArea {
                            flags: new_flags,
                            is_file_backed: vma.is_file_backed,
                            shared_futex: vma.shared_futex,
                            initialization: vma.initialization,
                        };
                        self.transient
                            .insert(intersection.clone(), Transient::Installing { publish });
                        staged.push(intersection.clone());
                    }
                }
                // EFFECT
                let effect_result =
                    unsafe { self.platform.update_permissions(applied_range, permissions) };
                // The platform call has returned either way: nothing is in flight any more, so
                // every staged fragment is cleared regardless of outcome (on failure this is the
                // ROLLBACK -- `vmas` itself is untouched below, so there is nothing left to
                // restore).
                for staged_range in staged {
                    self.transient.remove(staged_range);
                }
                effect_result.map_err(VmemProtectError::ProtectError)?;
                // COMMIT
                for (original, intersection, vma) in applicable {
                    if vma.flags & VmFlags::VM_ACCESS_FLAGS != flags {
                        let new_flags = (vma.flags & !VmFlags::VM_ACCESS_FLAGS) | flags;
                        self.record_protected_piece(original, intersection, vma, new_flags);
                    }
                }
            }
            return match pending_error {
                Some(err) => Err(err),
                None => Ok(()),
            };
        }

        // Native providers retain their individual mapping boundaries. Only the
        // already-validated `applicable` prefix (contiguous and `VM_MAY`-compatible, address
        // order) is ever mutated; a gap or incompatible mapping past it surfaces as
        // `pending_error` below, once every fragment before it has been applied.
        //
        // A deferred (VM_DEFERRED) piece has no platform state yet: it is
        // *materialized* here -- freshly allocated with the requested access --
        // rather than permission-updated. With EXECUTE in the target, the
        // allocation is made non-executable first and then updated, because
        // platforms are entitled to refuse born-executable allocations (the
        // HVF memory manager does: `HvfMemoryError::InitialExecute`).
        for (original, intersection, vma) in applicable {
            if vma.flags & VmFlags::VM_ACCESS_FLAGS == flags {
                continue;
            }
            if vma.flags.contains(VmFlags::VM_DEFERRED) {
                let wants_exec = flags.contains(VmFlags::VM_EXEC);
                let allocate_perms = if wants_exec {
                    (permissions & !crate::platform::page_mgmt::MemoryRegionPermissions::EXEC)
                        | crate::platform::page_mgmt::MemoryRegionPermissions::READ
                } else {
                    permissions
                };
                let new_flags =
                    (vma.flags & !VmFlags::VM_ACCESS_FLAGS & !VmFlags::VM_DEFERRED) | flags;
                let publish = VmArea {
                    flags: new_flags,
                    is_file_backed: vma.is_file_backed,
                    shared_futex: vma.shared_futex,
                    initialization: vma.initialization,
                };
                // PREPARE: staged before the deferred `allocate_pages` call (and the `EXECUTE`
                // follow-up `update_permissions`, when needed) so a panic in either leaves a
                // forensic record rather than silent, unrecorded loss.
                self.transient
                    .insert(intersection.clone(), Transient::Installing { publish });
                // EFFECT
                let effect_result: Result<(), VmemProtectError> = match self.platform.allocate_pages(
                    intersection.clone(),
                    allocate_perms,
                    false,
                    false,
                    crate::platform::page_mgmt::FixedAddressBehavior::NoReplace,
                ) {
                    Ok(_) if wants_exec => unsafe {
                        self.platform
                            .update_permissions(intersection.clone(), permissions)
                    }
                    .map_err(VmemProtectError::ProtectError),
                    Ok(_) => Ok(()),
                    Err(error) => Err(VmemProtectError::DeferredAllocate(error)),
                };
                self.transient.remove(intersection.clone());
                effect_result?;
                // COMMIT
                self.record_protected_piece(original, intersection, vma, new_flags);
                continue;
            }
            let new_flags = (vma.flags & !VmFlags::VM_ACCESS_FLAGS) | flags;
            let publish = VmArea {
                flags: new_flags,
                is_file_backed: vma.is_file_backed,
                shared_futex: vma.shared_futex,
                initialization: vma.initialization,
            };
            // PREPARE
            self.transient
                .insert(intersection.clone(), Transient::Installing { publish });
            // EFFECT
            let effect_result = unsafe {
                self.platform
                    .update_permissions(intersection.clone(), permissions)
            };
            // The platform call has returned either way: nothing is in flight any more, so the
            // staged fragment is cleared regardless of outcome (on failure this is the ROLLBACK
            // -- `vmas` itself is untouched below, so there is nothing left to restore).
            self.transient.remove(intersection.clone());
            effect_result.map_err(VmemProtectError::ProtectError)?;
            // COMMIT
            self.record_protected_piece(original, intersection, vma, new_flags);
        }

        match pending_error {
            Some(err) => Err(err),
            None => Ok(()),
        }
    }

    /// [`Self::protect_mapping`]'s admission half alone: `range` must be fully mapped and every
    /// mapping there must allow `permissions` under its `VM_MAY*` flags. No effect.
    pub(super) fn check_permissions(
        &self,
        range: PageRange<ALIGN>,
        permissions: MemoryRegionPermissions,
    ) -> Result<(), VmemProtectError> {
        let flags =
            VmFlags::from_bits(u32::from(permissions.bits())).unwrap() & VmFlags::VM_ACCESS_FLAGS;
        let range = range.start..range.end;
        let mut covered = range.start;
        for (mapped, vma) in self.vmas.overlapping(range.clone()) {
            if mapped.start.max(range.start) != covered {
                return Err(VmemProtectError::InvalidRange(range));
            }
            if (!(vma.flags.bits() >> 4) & flags.bits()) & VmFlags::VM_ACCESS_FLAGS.bits() != 0 {
                return Err(VmemProtectError::NoAccess {
                    old: vma.flags,
                    new: flags,
                });
            }
            covered = mapped.end.min(range.end);
        }
        if covered != range.end {
            return Err(VmemProtectError::InvalidRange(range));
        }
        Ok(())
    }

    /// [`Self::protect_mapping`]'s bookkeeping half alone, for a change whose platform effect was
    /// already applied in the caller's own per-view address space: records `permissions` as
    /// `range`'s access flags (a reservation becoming accessible is no longer `VM_DEFERRED`),
    /// touching no platform state. `range` must have passed [`Self::check_permissions`].
    pub(super) fn record_permissions(
        &mut self,
        range: PageRange<ALIGN>,
        permissions: MemoryRegionPermissions,
    ) {
        let flags =
            VmFlags::from_bits(u32::from(permissions.bits())).unwrap() & VmFlags::VM_ACCESS_FLAGS;
        let range = range.start..range.end;
        let pieces: Vec<(Range<usize>, Range<usize>, VmArea)> = self
            .vmas
            .overlapping(range.clone())
            .map(|(mapped, vma)| {
                (
                    mapped.clone(),
                    mapped.start.max(range.start)..mapped.end.min(range.end),
                    *vma,
                )
            })
            .collect();
        for (original, intersection, vma) in pieces {
            let new_flags = if flags.is_empty() {
                vma.flags & !VmFlags::VM_ACCESS_FLAGS
            } else {
                (vma.flags & !VmFlags::VM_ACCESS_FLAGS & !VmFlags::VM_DEFERRED) | flags
            };
            if new_flags != vma.flags {
                self.record_protected_piece(original, intersection, vma, new_flags);
            }
        }
    }

    /// Create a mapping with the given flags.
    ///
    /// `suggested_new_address` is the hint address for where to create the pages if it is not `None`.
    /// Otherwise, let the kernel choose an available memory region.
    ///
    /// `length` is the size of the pages to be created.
    ///
    /// Set `flags` to control options such as fixed address, stack, and populate pages.
    ///
    /// `op` is a callback for caller to initialize the created pages.
    ///
    /// `perm` is the permissions to set for the created pages.
    ///
    /// # Safety
    ///
    /// Note that if the suggested address is given and [`CreatePagesFlags::FIXED_ADDR`] is set,
    /// the kernel uses it directly without checking if it is available, causing overlapping
    /// mappings to be unmapped. Caller must ensure any overlapping mappings are not used by any other.
    ///
    /// Also, caller must ensure flags are set correctly.
    ///
    /// `steer_owner`: see [`Self::create_mapping`]'s own doc comment -- forwarded verbatim.
    pub(super) unsafe fn create_pages(
        &mut self,
        suggested_new_address: Option<NonZeroAddress<ALIGN>>,
        length: NonZeroPageSize<ALIGN>,
        flags: CreatePagesFlags,
        perms: MemoryRegionPermissions,
        shared_futex_backing: Option<(SharedFutexBacking, usize)>,
        steer_owner: Option<VmViewId>,
    ) -> Result<Platform::RawMutPointer<u8>, MappingError> {
        let shared = flags.contains(CreatePagesFlags::SHARED);
        let file_backed = flags.contains(CreatePagesFlags::MAP_FILE);
        // A `PROT_NONE` anonymous private mapping is a pure VA reservation:
        // Linux allocates no page-table state for it either, and deferring the
        // platform allocation keeps huge reservations (observed live: V8's
        // ~4 GiB pointer-compression cage and ~32 GiB sandbox, whose per-page
        // platform tracking exceeds what the HVF memory manager is built for)
        // working on every platform. It is materialized lazily on the first
        // `mprotect` that adds access flags (see `protect_mapping`).
        let defer = perms.is_empty()
            && !shared
            && !file_backed
            && !flags.intersects(
                CreatePagesFlags::FIXED_ADDR
                    | CreatePagesFlags::POPULATE_PAGES_IMMEDIATELY
                    | CreatePagesFlags::IS_STACK,
            );
        unsafe {
            self.create_mapping(
                suggested_new_address,
                length,
                VmArea::new(
                    VmFlags::from(perms)
                        | VmFlags::may_flags_for_mapping(shared, file_backed)
                        | if defer {
                            VmFlags::VM_DEFERRED
                        } else {
                            VmFlags::empty()
                        }
                        | if flags.contains(CreatePagesFlags::IS_STACK) {
                            VmFlags::VM_GROWSDOWN
                        } else {
                            VmFlags::empty()
                        },
                    flags.contains(CreatePagesFlags::MAP_FILE),
                    shared_futex_backing,
                ),
                flags,
                steer_owner,
            )
        }
        .map_err(MappingError::MapError)
    }

    /// Visibility seam for [`super::domain::GuestVaDomain::place`]'s search callback: an
    /// identical-signature, identical-body thin wrapper around [`Self::get_unmmaped_area`],
    /// published one module level up (`pub(super)`, i.e. visible within `mm`) so
    /// `PageManager::create_pages` (in `mod.rs`) can drive `Vmem`'s own real placement search
    /// from behind the domain's placement query without making `get_unmmaped_area` itself
    /// non-private. Zero behavior change from calling `get_unmmaped_area` directly.
    ///
    /// Read-only search (`&self`), like [`Self::get_unmmaped_area`]: not a mutation site.
    ///
    /// `steer_owner`: see [`Self::create_mapping`]'s own doc comment -- forwarded verbatim to
    /// [`Self::get_unmmaped_area`]/[`Self::reserved_overlaps`].
    pub(super) fn find_unmapped_area(
        &self,
        suggested_address: Option<NonZeroAddress<ALIGN>>,
        length: NonZeroPageSize<ALIGN>,
        fixed_addr: bool,
        steer_owner: Option<VmViewId>,
    ) -> Option<usize> {
        self.get_unmmaped_area(suggested_address, length, fixed_addr, steer_owner)
    }

    /*================================Internal Functions================================ */

    /// Get an unmapped area in the virtual address space.
    /// `suggested_range` and `fixed_addr` are the hint address and MAP_FIXED flag respectively,
    /// similar to how `mmap` works.
    ///
    /// Returns `None` if no area found. Otherwise, returns the start address of a page-aligned area.
    ///
    /// Read-only search (`&self`): not a mutation site at all, so there is nothing here for
    /// [`Transient`] to protect.
    ///
    /// `steer_owner`: see [`Self::create_mapping`]'s own doc comment -- passed straight through
    /// to every [`Self::reserved_overlaps`] call this search makes (including inside
    /// [`Self::top_down_search`]), so the whole search steers around exactly one consistent
    /// owner's own reservations.
    fn get_unmmaped_area(
        &self,
        suggested_address: Option<NonZeroAddress<ALIGN>>,
        length: NonZeroPageSize<ALIGN>,
        fixed_addr: bool,
        steer_owner: Option<VmViewId>,
    ) -> Option<usize> {
        let size = length.as_usize();
        if size > Platform::TASK_ADDR_MAX {
            return None;
        }
        if let Some(suggested_address) = suggested_address {
            if fixed_addr {
                if (Platform::TASK_ADDR_MAX - size) < suggested_address.0 {
                    return None;
                }
                return Some(suggested_address.0);
            }
            // A plain (non-MAP_FIXED) hint is advisory: Linux ignores an
            // unusable hint and picks its own address rather than failing
            // the mmap, and real programs rely on exactly that -- V8's
            // GetRandomMmapAddr hands the kernel addresses randomized over a
            // wider range than any particular process can necessarily map
            // (observed live: a node:alpine guest's V8 heap-chunk hint below
            // this platform's `TASK_ADDR_MIN` was answered with `EPERM`
            // here, which V8 treats as fatal OOM during snapshot
            // deserialization). Honor the hint only when it is genuinely
            // usable; otherwise fall through to the search below, exactly as
            // if no hint had been given.
            if suggested_address.0 >= Platform::TASK_ADDR_MIN
                && (Platform::TASK_ADDR_MAX - size) >= suggested_address.0
                && !self
                    .vmas
                    .overlaps(&(suggested_address.0..(suggested_address.0 + size)))
                && !self.reserved_overlaps(
                    &(suggested_address.0..(suggested_address.0 + size)),
                    steer_owner,
                )
            {
                return Some(suggested_address.0);
            }
        } else if fixed_addr {
            // MAP_FIXED with addr=0: return 0 so insert_mapping rejects it
            // via the TASK_ADDR_MIN check (BelowMinAddress → EPERM).
            return Some(0);
        }

        // top down
        let (low_limit, unconstrained_high_limit) = (
            Platform::TASK_ADDR_MIN,
            Platform::TASK_ADDR_MAX - length.as_usize(),
        );
        debug_assert_eq!(Platform::TASK_ADDR_MIN % ALIGN, 0);
        debug_assert_eq!(Platform::TASK_ADDR_MAX % ALIGN, 0);
        // An unusable hint is advisory (see above), but that does not mean it carries no
        // information: a caller re-probing with a *lower* hint after an earlier attempt (V8's
        // code-range/pointer-compression-cage placement does exactly this, mmap-ing the same
        // size at a descending sequence of hints until one lands where it needs) means "try
        // somewhere at or below here first" -- searching the unconstrained full range would
        // return the exact same top-of-space address on every such retry (nothing about free
        // space changed), so the caller's presumably-different constraint on *this* retry could
        // never be satisfied, and it would exhaust its own retry budget and fail outright. Bias
        // the search toward staying at or below the hint first; only if nothing fits there does
        // this fall back to the unconstrained search, exactly as if no hint had been given.
        if let Some(suggested_address) = suggested_address
            && suggested_address.0 < unconstrained_high_limit
            && let Some(found) =
                self.top_down_search(low_limit, suggested_address.0, size, steer_owner)
        {
            return Some(found);
        }
        self.top_down_search(low_limit, unconstrained_high_limit, size, steer_owner)
    }

    /// The unhinted top-down search `get_unmmaped_area` falls back to: the highest gap of at
    /// least `size` bytes whose start is in `[low_limit, high_limit]`. Shared by the
    /// unconstrained search and, with a smaller `high_limit`, the hint-biased search above.
    ///
    /// `steer_owner`: see [`Self::create_mapping`]'s own doc comment -- forwarded to every
    /// [`Self::reserved_overlaps`] call below.
    fn top_down_search(
        &self,
        low_limit: usize,
        high_limit: usize,
        size: usize,
        steer_owner: Option<VmViewId>,
    ) -> Option<usize> {
        // An inverted range is empty by this function's own contract (`start
        // in [low_limit, high_limit]`) and must fail cleanly. This guards a
        // real caller mistake, not a hypothetical one: `get_unmmaped_area`'s
        // hint-biased call passes the raw hint as `high_limit`, and a hint
        // below `low_limit` (observed live: a node:alpine guest's V8
        // CodeRange hint landing below `TASK_ADDR_MIN`, entirely plausible
        // since host library mappings reported by `reserved_pages` commonly
        // sit below the guest's floor) makes `high_limit < low_limit`.
        // Without this guard, the fast path below can still return that
        // too-low `high_limit` verbatim whenever some tracked range (again,
        // typically a host mapping from `reserved_pages`) starts at or below
        // it: `last_end` then defaults no higher than `low_limit` itself, so
        // `last_end <= high_limit` can hold even though `high_limit` is
        // below `low_limit` -- silently handing the caller an address
        // outside the caller's own requested floor. `insert_mapping` still
        // catches the resulting placement (`start < TASK_ADDR_MIN`), but as
        // `AllocationError::BelowMinAddress`, which the guest sees as EPERM
        // on an ordinary hinted `mmap` -- V8 treats that as fatal OOM.
        if high_limit < low_limit {
            return None;
        }
        // 1. check [last_end, high_limit]
        // The globally last (highest-addressed) tracked range is not
        // necessarily relevant here: as the loop below already accounts for,
        // a platform's `reserved_pages` can report host mappings that sit
        // entirely above `TASK_ADDR_MAX` (e.g. a `mach_vm_region` walk that
        // finds the dyld shared cache, or some other host allocation,
        // ASLR-slid above litebox's own deliberately conservative guest
        // ceiling on macOS -- see `MacOsUserland::TASK_ADDR_MAX`'s doc
        // comment). Keying this fast path off *that* range's end would make
        // it report the very top of the guest range as occupied even when
        // nothing below `high_limit` is, and -- since it never re-checks
        // `high_limit` afterwards -- skip straight to the per-gap loop below,
        // which only ever considers the gap immediately below a *tracked*
        // range, not the gap between the ceiling and the highest range that
        // is actually within bounds. So find the highest range that could
        // actually collide with a placement ending at `high_limit`.
        let last_end = self
            .vmas
            .iter()
            .rev()
            .find(|(r, _)| r.start <= high_limit)
            .map_or(low_limit, |(r, _)| r.end);
        // `last_end <= high_limit` alone is not sufficient: it only rules out
        // a tracked range that starts at or below `high_limit` extending past
        // it, not a tracked range that starts *above* `high_limit` (which the
        // `find` above deliberately skips, per this function's own doc
        // comment, so that a host mapping entirely above `TASK_ADDR_MAX`
        // doesn't shadow this fast path). That skip is only sound when
        // nothing tracked actually falls inside `[high_limit, TASK_ADDR_MAX)`
        // itself -- true for a host mapping genuinely entirely above the
        // guest's ceiling, but not for a *guest* mapping that (on a platform
        // whose `allocate_pages` cannot always place a `Hint` at the exact
        // address requested) ended up landing inside this exact window
        // despite `Vmem` believing the window was free when it computed
        // `high_limit` for it. `overlaps` re-derives the true answer directly
        // from the candidate range instead of trusting the `r.start <=
        // high_limit` proxy.
        if last_end <= high_limit
            && !self.vmas.overlaps(&(high_limit..high_limit + size))
            && !self.reserved_overlaps(&(high_limit..high_limit + size), steer_owner)
        {
            return Some(high_limit);
        }

        // 2. check gaps between ranges
        for (r, flags) in self.vmas.iter().rev() {
            let start = r.start.checked_sub(
                size + if flags.flags.contains(VmFlags::VM_GROWSDOWN) {
                    // If it is a stack, we need to leave enough space for the stack to grow downwards.
                    Self::STACK_GUARD_GAP << 1
                } else {
                    0
                },
            )?;
            if start < low_limit {
                return None;
            }
            if start > high_limit {
                // Note we may have pre-allocated memory that are higher than `TASK_ADDR_MAX`
                // (See [`Vmem::new`]) and thus `start` may be larger than `high_limit`.
                continue;
            }
            if !self.vmas.overlaps(&(start..start + size))
                && !self.reserved_overlaps(&(start..start + size), steer_owner)
            {
                return Some(start);
            }
        }

        None
    }

    /// Whether any part of `range` is covered by a reservation (see [`Self::reserved`]) belonging
    /// to `steer_owner` -- or, if `steer_owner` is `None` (a host-internal caller with no current
    /// guest-view context; see [`Self::create_mapping`]'s own doc comment), by a reservation
    /// belonging to ANY owner, exactly matching this method's original owner-blind behavior for
    /// such a caller.
    ///
    /// `Some(owner)` deliberately consults ONLY `owner`'s own sub-map: this is the actual fix for
    /// `vfork-park-reserved-range-steers-unrelated-familys-flexible-mmap-confirmed`
    /// (`Self::reserved`'s own doc comment has the full story) -- an unrelated owner's live
    /// reservation must steer nobody's placement search but that owner's own.
    fn reserved_overlaps(&self, range: &Range<usize>, steer_owner: Option<VmViewId>) -> bool {
        fn map_overlaps(map: &BTreeMap<usize, usize>, range: &Range<usize>) -> bool {
            map.range(..range.end)
                .next_back()
                .is_some_and(|(_, &end)| range.start < end)
        }
        match steer_owner {
            Some(owner) => self.reserved.get(&owner).is_some_and(|map| map_overlaps(map, range)),
            None => self.reserved.values().any(|map| map_overlaps(map, range)),
        }
    }

    /// Marks `range` as reserved on `owner`'s own behalf: a flexible placement search steered by
    /// that same `owner` (see [`Self::reserved_overlaps`]) steers around it even though it has no
    /// live `vmas` entry; a search steered by (or on behalf of) any other owner is unaffected.
    /// Overlapping/adjacent existing reservations *of the same owner* are merged. See
    /// [`Self::reserved`].
    ///
    /// Pure logical bookkeeping (`self.reserved` mutation only): no platform effect call of its
    /// own, so there is no pre-effect/post-effect distinction here for [`Transient`] to protect.
    pub(super) fn reserve_external(&mut self, range: Range<usize>, owner: VmViewId) {
        if range.start >= range.end {
            return;
        }
        let map = self.reserved.entry(owner).or_default();
        let mut start = range.start;
        let mut end = range.end;
        let overlapping: Vec<(usize, usize)> = map
            .range(..=end)
            .rev()
            .take_while(|&(_, &e)| e >= start)
            .map(|(&s, &e)| (s, e))
            .collect();
        for (s, e) in overlapping {
            map.remove(&s);
            start = start.min(s);
            end = end.max(e);
        }
        map.insert(start, end);
    }

    /// Releases a reservation made by [`Self::reserve_external`] under the same `owner`. `range`
    /// need not exactly match what was reserved (a partial release shrinks/splits the covering
    /// reservation); releasing where `owner` has nothing reserved (including an `owner` that has
    /// never reserved anything at all) is a no-op -- in particular, this can never shrink or split
    /// a *different* owner's own reservation, even one that numerically overlaps `range`.
    ///
    /// Pure logical bookkeeping (`self.reserved` mutation only): no platform effect call of its
    /// own, so there is no pre-effect/post-effect distinction here for [`Transient`] to protect.
    pub(super) fn release_external(&mut self, range: Range<usize>, owner: VmViewId) {
        if range.start >= range.end {
            return;
        }
        let Some(map) = self.reserved.get_mut(&owner) else {
            return;
        };
        let overlapping: Vec<(usize, usize)> = map
            .range(..range.end)
            .rev()
            .take_while(|&(_, &e)| e > range.start)
            .map(|(&s, &e)| (s, e))
            .collect();
        for (s, e) in overlapping {
            map.remove(&s);
            if s < range.start {
                map.insert(s, range.start);
            }
            if range.end < e {
                map.insert(range.end, e);
            }
        }
        // Never leave a stale, permanently-empty sub-map behind: `owner` (a `VmViewId`) is never
        // reused (see the type's own doc comment), so a long-running instance with many
        // short-lived families (an interactive shell forking/exec-ing repeatedly, e.g.) would
        // otherwise accumulate one empty `BTreeMap` per family that ever existed, forever.
        if map.is_empty() {
            self.reserved.remove(&owner);
        }
    }
}

/// Error for removing mappings
#[derive(Error, Debug)]
pub enum VmemUnmapError {
    #[error("arg is not aligned")]
    UnAligned,
    #[error("failed to unmap pages: {0}")]
    UnmapError(#[from] crate::platform::page_mgmt::DeallocationError),
}

/// Error for resetting pages
#[derive(Error, Debug)]
pub enum VmemResetError {
    #[error("arg is not aligned")]
    UnAligned,
    #[error("provided range contains unallocated pages")]
    AlreadyUnallocated,
    #[error("reset file-backed mapping")]
    FileBacked,
    #[error("failed to re-create the reset mapping: {0}")]
    Platform(crate::platform::page_mgmt::AllocationError),
}

/// Error for [`Vmem::set_wipe_on_fork`] (`madvise(MADV_WIPEONFORK|MADV_KEEPONFORK)`).
#[derive(Error, Debug)]
pub enum VmemWipeOnForkError {
    #[error("arg is not aligned")]
    UnAligned,
    #[error("the range {0:?} contains unmapped pages")]
    Unmapped(Range<usize>),
    #[error("the mapping at {0:?} is file-backed or shared, so it cannot be wiped on fork")]
    NotPrivateAnonymous(Range<usize>),
}

/// Error for [`Vmem::set_dont_fork`] (`madvise(MADV_DONTFORK|MADV_DOFORK)`).
#[derive(Error, Debug)]
pub enum VmemDontForkError {
    #[error("arg is not aligned")]
    UnAligned,
    #[error("the range {0:?} contains unmapped pages")]
    Unmapped(Range<usize>),
}

/// Error for [`Vmem::resize_mapping`]
#[derive(Error, Debug)]
pub(super) enum VmemResizeError {
    #[error("no mapping containing the address {0:?}")]
    NotExist(usize),
    #[error("invalid address {addr:?} exceeds range {range:?}")]
    InvalidAddr { range: Range<usize>, addr: usize },
    #[error("range {0:?} is already (partially) occupied")]
    RangeOccupied(Range<usize>),
    #[error("range {0:?} has a pending initialization")]
    InitializationPending(Range<usize>),
    #[error("failed to unmap the removed range: {0}")]
    UnmapError(#[source] VmemUnmapError),
    #[error("out of memory")]
    OutOfMemory,
}

/// Error for moving mappings
#[derive(Error, Debug)]
pub enum VmemMoveError {
    #[error("arg is not aligned")]
    UnAligned,
    #[error("out of memory")]
    OutOfMemory,
    #[error("remap failed: {0}")]
    RemapError(#[from] crate::platform::page_mgmt::RemapError),
}

/// Error for protecting mappings
#[derive(Error, Debug)]
pub enum VmemProtectError {
    #[error("the range {0:?} is not aligned")]
    UnAligned(Range<usize>),
    #[error("the range {0:?} has no mapping memory")]
    InvalidRange(Range<usize>),
    #[error("failed to change permissions from {old:?} to {new:?}")]
    NoAccess { old: VmFlags, new: VmFlags },
    #[error("mprotect failed: {0}")]
    ProtectError(#[from] crate::platform::page_mgmt::PermissionUpdateError),
    #[error("failed to materialize a deferred reservation: {0}")]
    DeferredAllocate(#[from] crate::platform::page_mgmt::AllocationError),
}

/// Error for creating mappings
#[non_exhaustive]
#[derive(Error, Debug)]
pub enum MappingError {
    #[error("arg is not aligned")]
    UnAligned,
    #[error("not enough memory")]
    OutOfMemory,

    // Errors from mapping a file
    #[error("bad file descriptor: {0}")]
    BadFD(i32),
    #[error("file descriptor does not point to a file")]
    NotAFile,
    #[error("file not open for reading")]
    NotForReading,
    #[error("I/O error reading file: errno {0}")]
    Io(i32),

    #[error("mapping failed: {0}")]
    MapError(#[from] crate::platform::page_mgmt::AllocationError),

    /// A concurrent operation on this address space (another thread of the same
    /// `CLONE_VM` family unmapping or otherwise invalidating the range) removed a
    /// just-created mapping before its post-creation permission change could apply.
    /// See [`super::PageManager::create_pages`]'s two-phase create-then-protect
    /// sequence, which necessarily drops its lock around the caller-supplied `op`
    /// (which may itself need to re-enter the page-fault handler) between those two
    /// phases.
    #[error("mapping was concurrently removed before its permissions could be finalized")]
    ConcurrentlyRemoved,

    #[error("mapping initialization identity space is exhausted")]
    InitializationIdentityExhausted,

    #[error("mapping permission finalization failed: {0}")]
    FinalizeProtection(#[source] VmemProtectError),

    #[error("{primary}; initialization cleanup also failed: {cleanup}")]
    Cleanup {
        primary: Box<MappingError>,
        cleanup: VmemUnmapError,
    },
}

/// Enable [`super::PageManager`] to handle page faults if its platform implements this trait
pub trait VmemPageFaultHandler {
    /// Handle a page fault for the given address.
    ///
    /// # Safety
    ///
    /// This should only be called from the kernel page fault handler.
    unsafe fn handle_page_fault(
        &self,
        fault_addr: usize,
        flags: VmFlags,
        error_code: u64,
    ) -> Result<(), PageFaultError>;

    /// Check if it has access to the fault address.
    fn access_error(error_code: u64, flags: VmFlags) -> bool;
}

/// Error for handling page fault
#[derive(Error, Debug)]
pub enum PageFaultError {
    #[error("no access: {0}")]
    AccessError(&'static str),
    #[error("allocation failed")]
    AllocationFailed,
    #[error("given page is part of an already mapped huge page")]
    HugePage,
}
