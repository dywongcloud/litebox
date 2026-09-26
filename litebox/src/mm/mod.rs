// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Memory management related functionality

#[cfg(panic = "unwind")]
extern crate std;

pub mod allocator;
pub mod domain;
pub mod exception_table;
pub mod linux;
pub mod session;

#[cfg(test)]
mod tests;

use core::ops::Range;

use alloc::boxed::Box;
use alloc::vec::Vec;
use linux::{
    CreatePagesFlags, InitializationId, MappingError, PageFaultError, PageRange,
    SharedFutexBacking, VmArea, VmFlags, Vmem, VmemPageFaultHandler, VmemProtectError,
    VmemUnmapError,
};

use crate::{
    LiteBox,
    mm::linux::{
        NonZeroAddress, NonZeroPageSize, VmemDontForkError, VmemResetError, VmemWipeOnForkError,
    },
    platform::{
        PageManagementProvider, RawConstPointer,
        page_mgmt::{
            AllocationError, DeallocationError, MappingLockEvent, MemoryRegionPermissions,
            RemapError,
        },
    },
    sync::{RawSyncPrimitivesProvider, RwLock, RwLockReadGuard, RwLockWriteGuard},
    utils::ids::{MutationId, VmViewId},
};

/// Why [`PageManager::checked_guest_range`] refused a would-be guest-memory access.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuestAccessError {
    /// The byte range is empty, or falls (even partially) outside the platform's
    /// `TASK_ADDR_MIN..TASK_ADDR_MAX` aperture.
    OutOfAperture,
    /// The domain refused to admit the view (not installed, draining, or its identity is
    /// otherwise not currently valid). See [`domain::DomainConflict`].
    Domain(domain::DomainConflict),
    /// The range is not entirely mapped with at least the required permissions (`READ`, and
    /// `WRITE` too when the access is a write).
    NotMapped,
}

/// A page manager to support `mmap`, `munmap`, and etc.
pub struct PageManager<Platform, const ALIGN: usize>
where
    Platform: RawSyncPrimitivesProvider + PageManagementProvider<ALIGN>,
{
    vmem: RwLock<Platform, Vmem<Platform, ALIGN>>,
    /// [`Vmem`]'s mapping table as of the end of the last exclusive section of `vmem` (see
    /// [`linux::VmaMirror`]), kept up to date by [`VmemWrite`]'s drop. Guest-memory access
    /// admission ([`Self::checked_guest_range`]) and futex key derivation
    /// ([`Self::lock_mappings`]) read it instead of `vmem`: `vmem` is process-global and a
    /// mapping mutation holds it exclusively across its whole platform effect (a VM operation-gate
    /// wait, host VA syscalls, retirement pumps), so every guest syscall that touched guest
    /// memory used to queue behind every mm syscall of every process
    /// (hvf-t1g-remainder-multisecond-service-guest-memory-access-convoy). Lock order: `vmem`,
    /// then `mirror`; `mirror` is only ever held for one table lookup or one replay.
    mirror: RwLock<Platform, linux::VmaMirror>,
    domain: &'static domain::GuestVaDomain,
}

/// One recorded W^X custody flip, kept by [`WxLedger`].
#[derive(Clone, Copy, Debug)]
pub struct WxLedgerEntry {
    /// The view whose custody was revalidated for this flip.
    pub view: VmViewId,
    /// The page address that was flipped.
    pub page: usize,
    /// Whether the page became executable (`true`) or writable (`false`).
    pub executable: bool,
    /// This flip's own mutation identity, `0` only on the astronomically unlikely counter
    /// exhaustion of [`MutationId::next`].
    pub mutation: u64,
    /// Wall-clock duration, in nanoseconds, the real host mutation call this flip's commit
    /// took -- `0` for a racer-observed-already-done commit that never itself called into the
    /// host (see [`crate::shim::WxFlipOutcome::Committed`]).
    pub duration_nanos: u64,
}

const WX_LEDGER_SLOTS: usize = 64;

/// Number of fixed log2(ns)-keyed buckets in [`WxLedger`]'s latency histogram: bucket `i` counts
/// samples with `duration_nanos` in `[2^(i + WX_LATENCY_HISTOGRAM_SHIFT), 2^(i + 1 +
/// WX_LATENCY_HISTOGRAM_SHIFT))`, and the last bucket is the overflow catch-all for anything at or
/// past its lower bound. A real HVF `mutate_with_retry` protect-range call was independently
/// measured (this row's own live verification, the `wx_toggle` guest witness under
/// `LITEBOX_LOG=debug`) at roughly 30-47 microseconds -- comfortably inside this table's covered
/// range (`2^10`ns = ~1us through `2^21`ns = ~2ms) rather than degenerately overflowing every
/// sample into one bucket, which a naive `0..2048`ns range (this row's own first attempt) did.
const WX_LATENCY_HISTOGRAM_BUCKETS: usize = 12;
/// See [`WX_LATENCY_HISTOGRAM_BUCKETS`].
const WX_LATENCY_HISTOGRAM_SHIFT: u32 = 10;

/// A bounded, allocation-free ring of recently committed [`WxFlipRequest`](crate::shim::WxFlipRequest)s,
/// for observability -- never consulted for correctness. One process-global instance, reachable
/// via [`wx_ledger`]. Also keeps an allocation-free fixed-bucket latency histogram over every
/// recorded flip's `duration_nanos`, plus its own total sample count so a consumer can check the
/// histogram's bucket sum against an independent counter (e.g. `wx_service_settled`) rather than
/// trusting it blindly.
pub struct WxLedger {
    slots: spin::Mutex<[Option<WxLedgerEntry>; WX_LEDGER_SLOTS]>,
    next: core::sync::atomic::AtomicUsize,
    latency_histogram: [core::sync::atomic::AtomicU64; WX_LATENCY_HISTOGRAM_BUCKETS],
    latency_samples: core::sync::atomic::AtomicU64,
}

impl WxLedger {
    /// Creates an empty ledger.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            slots: spin::Mutex::new([None; WX_LEDGER_SLOTS]),
            next: core::sync::atomic::AtomicUsize::new(0),
            latency_histogram: [const { core::sync::atomic::AtomicU64::new(0) };
                WX_LATENCY_HISTOGRAM_BUCKETS],
            latency_samples: core::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Records one committed flip, overwriting the oldest slot once the ring is full, and folds
    /// `duration_nanos` into the latency histogram.
    pub fn record(&self, view: VmViewId, page: usize, executable: bool, duration_nanos: u64) {
        let mutation = MutationId::next().map(|id| id.get().get()).unwrap_or(0);
        let slot = self.next.fetch_add(1, core::sync::atomic::Ordering::Relaxed) % WX_LEDGER_SLOTS;
        self.slots.lock()[slot] = Some(WxLedgerEntry {
            view,
            page,
            executable,
            mutation,
            duration_nanos,
        });
        let log2_nanos = u64::BITS - 1 - (duration_nanos | 1).leading_zeros();
        let bucket = log2_nanos.saturating_sub(WX_LATENCY_HISTOGRAM_SHIFT) as usize;
        let bucket = bucket.min(WX_LATENCY_HISTOGRAM_BUCKETS - 1);
        self.latency_histogram[bucket].fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        self.latency_samples
            .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    }

    /// Returns every currently recorded entry, oldest first among the still-populated slots.
    #[must_use]
    pub fn snapshot(&self) -> Vec<WxLedgerEntry> {
        self.slots.lock().iter().flatten().copied().collect()
    }

    /// Returns the latency histogram's per-bucket counts, in ascending-latency order, alongside
    /// the total sample count folded into it -- always `sum(buckets) == samples`, checkable by a
    /// caller without trusting either in isolation.
    #[must_use]
    pub fn latency_histogram(&self) -> ([u64; WX_LATENCY_HISTOGRAM_BUCKETS], u64) {
        let buckets = core::array::from_fn(|i| {
            self.latency_histogram[i].load(core::sync::atomic::Ordering::Relaxed)
        });
        let samples = self.latency_samples.load(core::sync::atomic::Ordering::Relaxed);
        (buckets, samples)
    }
}

impl Default for WxLedger {
    fn default() -> Self {
        Self::new()
    }
}

static WX_LEDGER: WxLedger = WxLedger::new();

/// Returns the process-global [`WxLedger`] every [`PageManager::commit_wx_flip`] records into.
pub fn wx_ledger() -> &'static WxLedger {
    &WX_LEDGER
}

/// A read-side view of a page manager's mapping metadata for synchronization primitives (futex
/// keys, fault classification).
///
/// Each query answers from the manager's mapping-table mirror as of that query (see
/// `PageManager::mirror`): holding this value blocks nothing, exactly like Linux's futex key
/// derivation, which takes no mmap lock across the wait registration either. (It used to hold the
/// page manager's process-global mapping lock shared for its whole life, which made every futex
/// operation of every process wait behind any mapping mutation's platform effect, and made a
/// nested checked access self-deadlock behind a queued writer.)
pub struct MappingReadGuard<'a, Platform, const ALIGN: usize>
where
    Platform: RawSyncPrimitivesProvider + PageManagementProvider<ALIGN>,
{
    mirror: &'a RwLock<Platform, linux::VmaMirror>,
}

/// A held shared acquisition of [`PageManager`]'s mapping lock. Its request, grant and release
/// are reported to [`PageManagementProvider::mapping_lock_event`] (diagnostics only: who waits
/// how long for the lock, and who holds it meanwhile), with the `PageManager` source location
/// that took it.
struct VmemRead<'a, Platform, const ALIGN: usize>
where
    Platform: RawSyncPrimitivesProvider + PageManagementProvider<ALIGN>,
{
    guard: RwLockReadGuard<'a, Platform, Vmem<Platform, ALIGN>>,
    site: &'static core::panic::Location<'static>,
}

impl<Platform, const ALIGN: usize> core::ops::Deref for VmemRead<'_, Platform, ALIGN>
where
    Platform: RawSyncPrimitivesProvider + PageManagementProvider<ALIGN>,
{
    type Target = Vmem<Platform, ALIGN>;

    fn deref(&self) -> &Self::Target {
        &self.guard
    }
}

impl<Platform, const ALIGN: usize> Drop for VmemRead<'_, Platform, ALIGN>
where
    Platform: RawSyncPrimitivesProvider + PageManagementProvider<ALIGN>,
{
    fn drop(&mut self) {
        // Runs before `guard` itself drops, i.e. while the share is still held.
        Platform::mapping_lock_event(MappingLockEvent::ReadReleased, self.site);
    }
}

/// The exclusive twin of [`VmemRead`]. Dropping it first replays every mapping-table change the
/// section made into the manager's [`linux::VmaMirror`], while the lock is still held, so the
/// mirror changes in exactly the order the sections ran.
struct VmemWrite<'a, Platform, const ALIGN: usize>
where
    Platform: RawSyncPrimitivesProvider + PageManagementProvider<ALIGN>,
{
    guard: RwLockWriteGuard<'a, Platform, Vmem<Platform, ALIGN>>,
    mirror: &'a RwLock<Platform, linux::VmaMirror>,
    site: &'static core::panic::Location<'static>,
}

impl<Platform, const ALIGN: usize> core::ops::Deref for VmemWrite<'_, Platform, ALIGN>
where
    Platform: RawSyncPrimitivesProvider + PageManagementProvider<ALIGN>,
{
    type Target = Vmem<Platform, ALIGN>;

    fn deref(&self) -> &Self::Target {
        &self.guard
    }
}

impl<Platform, const ALIGN: usize> core::ops::DerefMut for VmemWrite<'_, Platform, ALIGN>
where
    Platform: RawSyncPrimitivesProvider + PageManagementProvider<ALIGN>,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.guard
    }
}

impl<Platform, const ALIGN: usize> Drop for VmemWrite<'_, Platform, ALIGN>
where
    Platform: RawSyncPrimitivesProvider + PageManagementProvider<ALIGN>,
{
    fn drop(&mut self) {
        // Runs before `guard` itself drops, i.e. while the lock is still held exclusively: the
        // mirror shows this section's changes before any later section runs and before the
        // syscall that made them can return. Replays exactly the section's own table operations
        // (see `linux::TrackedVmas`), so its cost is proportional to the change.
        if self.guard.has_vma_ops() {
            Platform::mapping_lock_event(MappingLockEvent::MirrorReplay, self.site);
            self.guard.replay_vma_ops(&mut self.mirror.write());
        }
        Platform::mapping_lock_event(MappingLockEvent::WriteReleased, self.site);
    }
}

struct InitializationGuard<'a, Platform, const ALIGN: usize>
where
    Platform: RawSyncPrimitivesProvider + PageManagementProvider<ALIGN>,
{
    manager: &'a PageManager<Platform, ALIGN>,
    range: PageRange<ALIGN>,
    identity: InitializationId,
    armed: bool,
}

impl<Platform, const ALIGN: usize> InitializationGuard<'_, Platform, ALIGN>
where
    Platform: RawSyncPrimitivesProvider + PageManagementProvider<ALIGN>,
{
    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl<Platform, const ALIGN: usize> Drop for InitializationGuard<'_, Platform, ALIGN>
where
    Platform: RawSyncPrimitivesProvider + PageManagementProvider<ALIGN>,
{
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        #[cfg(panic = "unwind")]
        {
            let cleanup = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let mut vmem = self.manager.vmem_write();
                unsafe { vmem.cleanup_initialization(self.range, self.identity) }
            }));
            if !matches!(cleanup, Ok(Ok(()))) {
                std::process::abort();
            }
        }
        #[cfg(not(panic = "unwind"))]
        {
            let mut vmem = self.manager.vmem_write();
            if let Err(error) = unsafe { vmem.cleanup_initialization(self.range, self.identity) } {
                panic!("cleaning a mapping after its initialization callback panicked: {error}");
            }
        }
    }
}

impl<Platform, const ALIGN: usize> MappingReadGuard<'_, Platform, ALIGN>
where
    Platform: RawSyncPrimitivesProvider + PageManagementProvider<ALIGN>,
{
    /// Returns the flags for the mapping containing `address`.
    pub fn flags_at(&self, address: usize) -> Option<VmFlags> {
        self.mirror.read().flags_at(address)
    }

    /// Returns the stable shared-backing identity and byte offset for `address`.
    pub fn shared_futex_key_at(&self, address: usize) -> Option<(usize, usize)> {
        self.mirror.read().shared_futex_key_at(address)
    }

    /// Reads a `u32` at `address`, relying only on a hardware fault as the safety net, without
    /// taking any page-manager lock.
    ///
    /// For a keyed futex wait's value check, run inside the futex bucket transaction: it reads
    /// the raw word exactly as the check always has. (When this guard still held the page
    /// manager's mapping lock, going through [`PageManager::checked_guest_range`] here instead
    /// would have taken a second, nested read share that self-deadlocks behind a queued writer.)
    ///
    /// Still refuses any address outside the guest's own `TASK_ADDR_MIN..TASK_ADDR_MAX` aperture,
    /// exactly like [`PageManager::checked_guest_range`]'s own first check -- an out-of-aperture
    /// address must never reach a raw read regardless of what the hardware would do with it. An
    /// in-aperture address that turns out not to be backed still only faults, which the
    /// underlying fallible read catches and reports as `None` rather than crashing.
    pub fn read_u32_unlocked(&self, address: usize) -> Option<u32> {
        if !address.is_multiple_of(core::mem::align_of::<u32>())
            || address < Platform::TASK_ADDR_MIN
            || address.checked_add(core::mem::size_of::<u32>())? > Platform::TASK_ADDR_MAX
        {
            return None;
        }
        // SAFETY: `address` was just checked to lie within the guest's own
        // `TASK_ADDR_MIN..TASK_ADDR_MAX` aperture, which is exactly the precondition
        // `read_u32_fallible` needs beyond its own hardware-fault tolerance (a genuinely
        // unbacked-but-in-aperture address still only faults, caught below as `Err`).
        unsafe { crate::mm::exception_table::read_u32_fallible(address as *const u32).ok() }
    }
}

/// How `PageManager::protect_range_for_view` treats one address-ordered piece of a range.
#[derive(Clone, Copy, PartialEq, Eq)]
enum PieceKind {
    /// Nobody else holds it: the ordinary process-wide permission change.
    Free,
    /// Another live family shares the `VmArea`: changed in the caller's own space only.
    Held,
    /// Held by the caller only through fork lineage: changed in its own space and published
    /// as its own custody.
    Inherited,
}

impl<Platform, const ALIGN: usize> PageManager<Platform, ALIGN>
where
    Platform: RawSyncPrimitivesProvider + PageManagementProvider<ALIGN>,
{
    /// Create a new `PageManager` instance.
    pub fn new(litebox: &LiteBox<Platform>) -> Self {
        let mut vmem = linux::Vmem::new(litebox.x.platform);
        let mut mirror = linux::VmaMirror::new();
        vmem.replay_vma_ops(&mut mirror);
        let domain = litebox.x.platform.guest_va_domain();
        Self {
            vmem: RwLock::new(vmem),
            mirror: RwLock::new(mirror),
            domain,
        }
    }

    /// Takes the mapping lock shared, reporting the acquisition to
    /// [`PageManagementProvider::mapping_lock_event`] with the caller's source location.
    #[track_caller]
    fn vmem_read(&self) -> VmemRead<'_, Platform, ALIGN> {
        let site = core::panic::Location::caller();
        Platform::mapping_lock_event(MappingLockEvent::ReadRequest, site);
        let guard = self.vmem.read();
        Platform::mapping_lock_event(MappingLockEvent::ReadAcquired, site);
        VmemRead { guard, site }
    }

    /// Takes the mapping lock exclusively; see [`Self::vmem_read`].
    #[track_caller]
    fn vmem_write(&self) -> VmemWrite<'_, Platform, ALIGN> {
        let site = core::panic::Location::caller();
        Platform::mapping_lock_event(MappingLockEvent::WriteRequest, site);
        let guard = self.vmem.write();
        Platform::mapping_lock_event(MappingLockEvent::WriteAcquired, site);
        VmemWrite {
            guard,
            mirror: &self.mirror,
            site,
        }
    }

    /// Returns the process-global guest-virtual-address domain backing this page manager.
    pub fn guest_va_domain(&self) -> &'static domain::GuestVaDomain {
        self.domain
    }

    /// Mirror of a freshly-created real mapping into this manager's `GuestVaDomain`: publishes
    /// `range` as the calling OS thread's current view's `Present` span, if the platform
    /// publishes a current guest-access context (see
    /// [`PageManagementProvider::current_guest_access`]).
    ///
    /// Never fails or affects the caller's real mapping -- this always goes through
    /// [`domain::GuestVaDomain::confirm_present_or_reconcile`], which self-heals a stale-fragment
    /// conflict (e.g. one left behind by a `MAP_FIXED` replace the domain was never told about)
    /// with one bounded retry before counting/logging anything still unrecoverable via
    /// [`domain::GuestVaDomain::untracked_present_events`]; an absent context is only logged.
    fn shadow_publish_present(&self, range: Range<usize>) {
        let Some((view, _task, _)) = Platform::current_guest_access() else {
            return;
        };
        let _ = self.domain.confirm_present_or_reconcile(view, range);
    }

    /// The retirement twin of [`Self::shadow_publish_present`]: mirrors a real unmap into the
    /// domain via [`domain::GuestVaDomain::confirm_retired_or_reconcile`], which walks `range` in
    /// address order and retires only the fragments that are the calling view's own `Present`
    /// span there, self-healing a benign race with one bounded retry before counting/logging
    /// anything still unrecoverable. Never fails or affects the caller's real unmap.
    fn shadow_retire_present(&self, range: Range<usize>) {
        let Some((view, _task, _)) = Platform::current_guest_access() else {
            return;
        };
        self.domain.confirm_retired_or_reconcile(view, range);
    }

    /// Services a [`crate::shim::WxFlipRequest`] a platform's fault classifier produced:
    /// revalidates the requested page's [`domain::Custody`] against the calling OS thread's
    /// current view before ever calling into [`PageManagementProvider::commit_wx_flip`], so a
    /// page whose owning view changed under a concurrent mmap/mprotect/munmap since
    /// classification is refused rather than blindly flipped -- guest virtual address alone
    /// cannot identify eligibility once the view that installed it may no longer be current.
    ///
    /// Uses [`domain::GuestVaDomain::custody_at_via_lineage`], not the strict
    /// [`domain::GuestVaDomain::custody_at`], for the same reason
    /// `PageManager::handle_page_fault_inner` already does: a freshly-forked view's own family map
    /// has nothing recorded for a page it has not yet independently touched, even though the page
    /// is legitimately hers by fork lineage (a COW read-alias inherited from an ancestor, not yet
    /// promoted to a private claim). The strict check cannot ever become true again on its own for
    /// such a page -- nothing else ever republishes it into the child's own family map -- so it
    /// would refuse forever instead of once; using the lineage-aware lookup here closes exactly
    /// that permanent-refusal gap, the same one `custody_at_via_lineage`'s own doc comment
    /// describes fixing for the ordinary page-fault path.
    ///
    /// Returns [`crate::shim::WxFlipOutcome::AliasConflictRefused`] (never panics, never crashes;
    /// the caller just resumes and re-faults) when there is no current guest-access context, or
    /// when the page's live custody -- this view's own or an ancestor's by lineage -- is not
    /// `Present`. Otherwise commits via the platform and, on
    /// [`crate::shim::WxFlipOutcome::Committed`], records one entry into the process-global
    /// [`wx_ledger`].
    pub fn commit_wx_flip(&self, req: crate::shim::WxFlipRequest) -> crate::shim::WxFlipOutcome {
        let Some((view, _task, _)) = Platform::current_guest_access() else {
            return crate::shim::WxFlipOutcome::AliasConflictRefused;
        };
        if !matches!(
            self.domain.custody_at_via_lineage(view, req.page),
            domain::Custody::Present { .. }
        ) {
            return crate::shim::WxFlipOutcome::AliasConflictRefused;
        }
        // SAFETY: the domain custody check above just confirmed this page is `view`'s own live
        // `Present` span; the platform's own generation compare-and-claim (`expected_generation`)
        // guards against a second racing commit for the same page.
        let outcome = unsafe {
            Platform::commit_wx_flip(req.page, req.want_execute, req.expected_generation)
        };
        if let crate::shim::WxFlipOutcome::Committed(duration_nanos) = outcome {
            wx_ledger().record(view, req.page, req.want_execute, duration_nanos);
        }
        outcome
    }

    fn cleanup_initialization_error(
        vmem: &mut Vmem<Platform, ALIGN>,
        range: PageRange<ALIGN>,
        identity: InitializationId,
        primary: MappingError,
    ) -> MappingError {
        match unsafe { vmem.cleanup_initialization(range, identity) } {
            Ok(()) => primary,
            Err(cleanup) => MappingError::Cleanup {
                primary: Box::new(primary),
                cleanup,
            },
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
    /// `before_perms` and `after_perms` are the permissions to set before and after the call to `op`.
    ///
    /// # Safety
    ///
    /// Note that if the suggested address is given and [`CreatePagesFlags::FIXED_ADDR`] is set,
    /// the kernel uses it directly without checking if it is available, causing overlapping
    /// mappings to be unmapped. Caller must ensure any overlapping mappings are not used by any other.
    ///
    /// Also, caller must ensure flags are set correctly.
    unsafe fn create_pages<F>(
        &self,
        suggested_address: Option<NonZeroAddress<ALIGN>>,
        length: NonZeroPageSize<ALIGN>,
        flags: CreatePagesFlags,
        before_perms: MemoryRegionPermissions,
        after_perms: MemoryRegionPermissions,
        shared_futex_backing: Option<(SharedFutexBacking, usize)>,
        op: F,
    ) -> Result<Platform::RawMutPointer<u8>, MappingError>
    where
        F: FnOnce(Platform::RawMutPointer<u8>) -> Result<usize, MappingError>,
    {
        if flags.contains(CreatePagesFlags::FIXED_ADDR)
            && let Some(addr) = suggested_address
            && let Some((view, _task, _)) = Platform::current_guest_access()
        {
            let range = addr.as_usize()..addr.as_usize() + length.as_usize();
            let fragments = self.domain.custody_fragments(view, range);
            if flags.contains(CreatePagesFlags::NOREPLACE) {
                if fragments.iter().any(|(_, c)| {
                    matches!(c, domain::Custody::Present { .. } | domain::Custody::Hole { .. })
                }) {
                    return Err(MappingError::MapError(AllocationError::AddressInUse));
                }
            } else if fragments.iter().any(|(_, c)| {
                // `custody_fragments` is scoped to `view`'s own family (see wave 12's
                // per-family split), so this can never actually observe another
                // family's `Present` span today -- kept faithful to the intended
                // cross-family check for the day the domain regains that visibility,
                // rather than silently dropping the clause.
                matches!(c, domain::Custody::Present { view: v, .. } if *v != view)
            }) {
                return Err(MappingError::MapError(AllocationError::AddressPartiallyInUse));
            }
        }
        // Non-`FIXED_ADDR` hint placement: ask the domain for a placement that is consistent
        // with both the real `Vmem` topology (via `search`, run with the domain lock released)
        // and this view's own family-scoped custody (a family-only `Reserved`/hole span the real
        // `Vmem` doesn't know about). Best-effort only -- on any `DomainConflict` this falls back
        // to the caller's original hint, so `Vmem::create_pages` below behaves exactly as it did
        // before this existed; a host-internal caller (`current_guest_access` is `None`) always
        // takes that unchanged direct path.
        let suggested_address = if !flags.contains(CreatePagesFlags::FIXED_ADDR)
            && let Some((view, _task, _)) = Platform::current_guest_access()
        {
            let hint = suggested_address.map(NonZeroAddress::as_usize);
            match self.domain.place(view, length.as_usize(), hint, |candidate_hint| {
                self.vmem_read().find_unmapped_area(
                    candidate_hint.and_then(NonZeroAddress::new),
                    length,
                    false,
                    // `Some(view)`: this candidate must only ever be steered away by a
                    // reservation this same view's own family made -- see
                    // `Vmem::reserved`'s own doc comment
                    // (vfork-park-reserved-range-steers-unrelated-familys-flexible-mmap-confirmed).
                    // An unrelated family's own vfork-parked reservation must never make the
                    // domain wrongly decline a candidate that is, for THIS view, genuinely free.
                    Some(view),
                )
            }) {
                Ok(range) => NonZeroAddress::new(range.start).or(suggested_address),
                Err(error) => {
                    litebox_util_log::debug!(
                        view:? = view, error:? = error;
                        "create_pages: domain placement declined, falling back to Vmem's own unhinted search"
                    );
                    suggested_address
                }
            }
        } else {
            suggested_address
        };
        // The same `view`, re-derived (this getter is cheap and idempotent, and `view` above is
        // not in scope this far down): this is the search that actually, authoritatively decides
        // the returned address (`suggested_address` above is only ever a hint into it, including
        // on every domain-placement fallback path), so it must be scoped identically -- see
        // `Vmem::reserved`'s own doc comment.
        let steer_owner = Platform::current_guest_access().map(|(view, _task, _)| view);
        let (addr, identity) = {
            let mut vmem = self.vmem_write();
            // Reserve before allocation so identity exhaustion cannot occur after
            // the platform has already published the new mapping.
            let identity = vmem.reserve_initialization_id()?;
            let addr = unsafe {
                vmem.create_pages(
                    suggested_address,
                    length,
                    flags,
                    before_perms,
                    shared_futex_backing,
                    steer_owner,
                )
            }?;
            let range = PageRange::new(addr.as_usize(), addr.as_usize() + length.as_usize())
                .expect("a platform allocation must retain the requested alignment and length");
            vmem.track_initialization(range, identity);
            (addr, identity)
        };
        let range = PageRange::new(addr.as_usize(), addr.as_usize() + length.as_usize())
            .expect("the tracked mapping range was already validated");
        let mut initialization = InitializationGuard {
            manager: self,
            range,
            identity,
            armed: true,
        };
        // `op` may trigger the page-fault handler, which requires the same write lock.
        #[cfg(panic = "unwind")]
        let callback = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| op(addr))) {
            Ok(callback) => callback,
            Err(payload) => {
                drop(initialization);
                std::panic::resume_unwind(payload)
            }
        };
        #[cfg(not(panic = "unwind"))]
        let callback = op(addr);
        let mut vmem = self.vmem_write();

        if let Err(primary) = callback {
            initialization.disarm();
            return Err(Self::cleanup_initialization_error(
                &mut vmem, range, identity, primary,
            ));
        }

        // A sibling sharing this address space may have unmapped, reset, or replaced the range
        // while the callback ran. The transient ID is invalidated by those mutations, so
        // identical metadata at the same address cannot pass this check after an ABA replacement.
        if !vmem.owns_initialization(range, identity) {
            initialization.disarm();
            return Err(Self::cleanup_initialization_error(
                &mut vmem,
                range,
                identity,
                MappingError::ConcurrentlyRemoved,
            ));
        }

        if let Err(error) = unsafe { vmem.protect_mapping(range, after_perms) } {
            initialization.disarm();
            return Err(Self::cleanup_initialization_error(
                &mut vmem,
                range,
                identity,
                MappingError::FinalizeProtection(error),
            ));
        }

        if !vmem.finish_initialization(range, identity) {
            initialization.disarm();
            return Err(Self::cleanup_initialization_error(
                &mut vmem,
                range,
                identity,
                MappingError::ConcurrentlyRemoved,
            ));
        }
        initialization.disarm();
        self.shadow_publish_present(range.start..range.end);
        Ok(addr)
    }

    /// Creates pages whose non-private futexes are keyed by a stable backing object and byte
    /// offset rather than by this mapping's virtual address.
    pub unsafe fn create_pages_with_shared_futex_backing<F>(
        &self,
        suggested_address: Option<NonZeroAddress<ALIGN>>,
        length: NonZeroPageSize<ALIGN>,
        flags: CreatePagesFlags,
        before_perms: MemoryRegionPermissions,
        after_perms: MemoryRegionPermissions,
        shared_futex_backing: Option<(SharedFutexBacking, usize)>,
        op: F,
    ) -> Result<Platform::RawMutPointer<u8>, MappingError>
    where
        F: FnOnce(Platform::RawMutPointer<u8>) -> Result<usize, MappingError>,
    {
        unsafe {
            self.create_pages(
                suggested_address,
                length,
                flags,
                before_perms,
                after_perms,
                shared_futex_backing,
                op,
            )
        }
    }

    /// Create readable and executable pages.
    ///
    /// `suggested_address` is the hint address for where to create the pages if it is not `None`.
    /// Otherwise, let the kernel choose an available memory region.
    ///
    /// `length` is the size of the pages to be created.
    ///
    /// Set `flags` to control options such as fixed address, stack, and populate pages.
    ///
    /// `op` is a callback for caller to initialize the created pages.
    ///
    /// # Safety
    ///
    /// If the suggested start address is given (i.e., not zero) and `fixed_addr` is set to `true`,
    /// the kernel uses it directly without checking if it is available, causing overlapping
    /// mappings to be unmapped. Caller must ensure any overlapping mappings are not used by any other.
    pub unsafe fn create_executable_pages<F>(
        &self,
        suggested_address: Option<NonZeroAddress<ALIGN>>,
        length: NonZeroPageSize<ALIGN>,
        flags: CreatePagesFlags,
        op: F,
    ) -> Result<Platform::RawMutPointer<u8>, MappingError>
    where
        F: FnOnce(Platform::RawMutPointer<u8>) -> Result<usize, MappingError>,
    {
        unsafe {
            self.create_pages(
                suggested_address,
                length,
                flags,
                // create READ | WRITE pages (as `op` may need to write to them, e.g., fill in the code)
                MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE,
                // keep READ, turn off WRITE and turn on EXEC
                MemoryRegionPermissions::READ | MemoryRegionPermissions::EXEC,
                None,
                op,
            )
        }
    }

    /// Create readable and writable pages.
    ///
    /// `suggested_address` is the hint address for where to create the pages if it is not `None`.
    /// Otherwise, let the kernel choose an available memory region.
    ///
    /// `length` is the size of the pages to be created.
    ///
    /// Set `flags` to control options such as fixed address, stack, and populate pages.
    ///
    /// `op` is a callback for caller to initialize the created pages.
    ///
    /// # Safety
    ///
    /// If the suggested start address is given (i.e., not zero) and `fixed_addr` is set to `true`,
    /// the kernel uses it directly without checking if it is available, causing overlapping
    /// mappings to be unmapped. Caller must ensure any overlapping mappings are not used by any other.
    pub unsafe fn create_writable_pages<F>(
        &self,
        suggested_address: Option<NonZeroAddress<ALIGN>>,
        length: NonZeroPageSize<ALIGN>,
        flags: CreatePagesFlags,
        op: F,
    ) -> Result<Platform::RawMutPointer<u8>, MappingError>
    where
        F: FnOnce(Platform::RawMutPointer<u8>) -> Result<usize, MappingError>,
    {
        let perms = MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE;
        unsafe { self.create_pages(suggested_address, length, flags, perms, perms, None, op) }
    }

    /// Create read-only pages.
    ///
    /// `suggested_address` is the hint address for where to create the pages if it is not `None`.
    /// Otherwise, let the kernel choose an available memory region.
    ///
    /// `length` is the size of the pages to be created.
    ///
    /// Set `flags` to control options such as fixed address, stack, and populate pages.
    ///
    /// `op` is a callback for caller to initialize the created pages.
    ///
    /// # Safety
    ///
    /// If the suggested start address is given (i.e., not zero) and `fixed_addr` is set to `true`,
    /// the kernel uses it directly without checking if it is available, causing overlapping
    /// mappings to be unmapped. Caller must ensure any overlapping mappings are not used by any other.
    pub unsafe fn create_readable_pages<F>(
        &self,
        suggested_address: Option<NonZeroAddress<ALIGN>>,
        length: NonZeroPageSize<ALIGN>,
        flags: CreatePagesFlags,
        op: F,
    ) -> Result<Platform::RawMutPointer<u8>, MappingError>
    where
        F: FnOnce(Platform::RawMutPointer<u8>) -> Result<usize, MappingError>,
    {
        unsafe {
            self.create_pages(
                suggested_address,
                length,
                flags,
                // create READ | WRITE pages (as `op` may need to write to them, e.g., fill in the data)
                MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE,
                // keep READ, turn off WRITE
                MemoryRegionPermissions::READ,
                None,
                op,
            )
        }
    }

    /// Create inaccessible pages.
    ///
    /// `suggested_address` is the hint address for where to create the pages if it is not `None`.
    /// Otherwise, let the kernel choose an available memory region.
    ///
    /// `length` is the size of the pages to be created.
    ///
    /// Set `flags` to control options such as fixed address, stack, and populate pages.
    ///
    /// `op` is a callback for caller to initialize the created pages.
    ///
    /// # Safety
    ///
    /// If the suggested start address is given (i.e., not zero) and `fixed_addr` is set to `true`,
    /// the kernel uses it directly without checking if it is available, causing overlapping
    /// mappings to be unmapped. Caller must ensure any overlapping mappings are not used by any other.
    pub unsafe fn create_inaccessible_pages<F>(
        &self,
        suggested_address: Option<NonZeroAddress<ALIGN>>,
        length: NonZeroPageSize<ALIGN>,
        flags: CreatePagesFlags,
        op: F,
    ) -> Result<Platform::RawMutPointer<u8>, MappingError>
    where
        F: FnOnce(Platform::RawMutPointer<u8>) -> Result<usize, MappingError>,
    {
        unsafe {
            self.create_pages(
                suggested_address,
                length,
                flags,
                MemoryRegionPermissions::empty(),
                MemoryRegionPermissions::empty(),
                None,
                op,
            )
        }
    }

    /// Create stack pages.
    ///
    /// `suggested_address` is the hint address for where to create the pages if it is not `None`.
    /// Otherwise, let the kernel choose an available memory region.
    ///
    /// `length` is the size of the pages to be created.
    ///
    /// Set `flags` to control options such as fixed address, stack, and populate pages.
    ///
    /// # Safety
    ///
    /// If the suggested start address is given (i.e., not zero) and `fixed_addr` is set to `true`,
    /// the kernel uses it directly without checking if it is available, causing overlapping
    /// mappings to be unmapped. Caller must ensure any overlapping mappings are not used by any other.
    pub unsafe fn create_stack_pages(
        &self,
        suggested_address: Option<NonZeroAddress<ALIGN>>,
        length: NonZeroPageSize<ALIGN>,
        flags: CreatePagesFlags,
    ) -> Result<Platform::RawMutPointer<u8>, MappingError> {
        let perms = MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE;
        let flags = CreatePagesFlags::IS_STACK | flags;
        unsafe {
            self.create_pages(suggested_address, length, flags, perms, perms, None, |_| {
                Ok(0)
            })
        }
    }

    /// Set the initial program break address.
    ///
    /// This function should be called once per image to set the initial program break,
    /// which is usually the end of the data segment.
    ///
    /// Under the per-process swap protocol described at [`Self::swap_brk`] the manager's
    /// break is 0 between operations, so a non-zero value here is a break that a previous
    /// caller published and never took back -- an `exec` that failed between publishing
    /// the new image's break and swapping it out (stack allocation is the fallible step
    /// in between, and under a spawn storm it does fail). That value belongs to nobody:
    /// its process either died or still holds its own authoritative slot. It is replaced
    /// and logged rather than asserted on, because this runs inside the mapping lock and
    /// a panic here took every other guest process's heap down with it (observed live as
    /// `initial brk is already set` under ~900 concurrent spawns).
    pub fn set_initial_brk(&self, brk: usize) {
        let mut vmem = self.vmem_write();
        if vmem.brk != 0 {
            litebox_util_log::warn!(
                stale:? = vmem.brk, new:? = brk;
                "initial brk is already set; replacing a break left behind by an aborted exec"
            );
        }
        vmem.brk = brk;
    }

    /// Installs `brk` as the current program break, returning the value it
    /// replaced.
    ///
    /// [`Self::set_initial_brk`] and [`Self::brk`] together model a *single*
    /// program break, which is correct only while one page manager backs
    /// exactly one guest process. A shim that runs more than one guest process
    /// against a shared page manager (litebox's Linux shim does, once `fork`
    /// exists: every guest process shares one host address space, at disjoint
    /// addresses) needs one break *per process*, so it keeps the authoritative
    /// value itself and swaps it in around each break operation. Returning the
    /// old value is what lets the caller both save and restore in one call, so
    /// the manager's own field can be left at the "no break set" sentinel of 0
    /// between operations and [`Self::set_initial_brk`]'s assertion keeps
    /// meaning what it says.
    pub fn swap_brk(&self, brk: usize) -> usize {
        let mut vmem = self.vmem_write();
        core::mem::replace(&mut vmem.brk, brk)
    }

    /// Set the program break to the given address.
    ///
    /// Increasing the program break has the effect of allocating memory to the process;
    /// decreasing the break deallocates memory.
    /// Calling `brk` with 0 can be used to find the current location of the program break.
    ///
    /// Note the initial program break is set to zero and the first call to `brk` would set it
    /// to the given address, which is usually the end of the data segment.
    ///
    /// ## Returns
    ///
    /// If the operation is successful, it returns the new program break address.
    ///
    /// # Panics
    ///
    /// Panics if the initial program break is not set yet.
    ///
    /// # Safety
    ///
    /// If shrinking the program break, the caller must ensure that the released memory region is no longer used.
    pub unsafe fn brk(&self, brk: usize) -> Result<usize, MappingError> {
        let mut vmem = self.vmem_write();
        if vmem.brk == 0 {
            // No break is installed. Under the shim's per-process swap protocol this means the
            // calling process's own break was never initialized (its exec skipped break
            // setup). Refusing is safe -- libc mallocs fall back to `mmap` on `brk` failure --
            // while the previous `assert!` here took down the whole runner from inside the
            // shim's global brk critical section, deadlocking every other process's heap
            // (observed live as a desktop-wide freeze).
            return Err(MappingError::OutOfMemory);
        }
        if brk == 0 {
            // Calling `brk` with 0 can be used to find the current location of the program break.
            return Ok(vmem.brk);
        }

        let old_brk = vmem.brk.next_multiple_of(linux::PAGE_SIZE);
        let new_brk = brk.next_multiple_of(linux::PAGE_SIZE);
        if vmem.brk >= brk {
            // Shrink the memory region
            if new_brk < old_brk && vmem.has_pending_initialization(&(new_brk..old_brk)) {
                return Ok(vmem.brk);
            }
            if new_brk < old_brk
                && let Some((view, _task, _)) = Platform::current_guest_access()
                && Platform::has_independent_view_space(view)
            {
                drop(vmem);
                return Ok(match self.remove_range_for_view(view, new_brk..old_brk) {
                    Ok(()) => {
                        self.vmem_write().brk = brk;
                        brk
                    }
                    Err(_) => self.vmem_read().brk,
                });
            }
            let brk = match unsafe {
                vmem.remove_mapping(
                    PageRange::new(new_brk, old_brk).ok_or(MappingError::UnAligned)?,
                )
            } {
                Ok(()) => {
                    vmem.brk = brk;
                    drop(vmem);
                    self.shadow_retire_present(new_brk..old_brk);
                    brk
                }
                Err(_) => {
                    vmem.brk // No change, return the old brk
                }
            };
            return Ok(brk);
        }

        if vmem.overlapping(old_brk..new_brk).next().is_some() {
            return Err(MappingError::OutOfMemory);
        }
        if let Some(range) = PageRange::<ALIGN>::new(old_brk, new_brk) {
            let (suggested_address, length) = range.start_and_length();
            let perms = MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE;
            unsafe {
                vmem.create_pages(
                    Some(suggested_address),
                    length,
                    CreatePagesFlags::FIXED_ADDR | CreatePagesFlags::POPULATE_PAGES_IMMEDIATELY,
                    perms,
                    None,
                    // `steer_owner` is never consulted for a `FIXED_ADDR` request (see
                    // `get_unmmaped_area`'s own `fixed_addr` branch, which returns before ever
                    // reaching `reserved_overlaps`), so its value cannot affect this call.
                    None,
                )
            }?;
            vmem.brk = brk;
            drop(vmem);
            self.shadow_publish_present(range.start..range.end);
            return Ok(brk);
        }
        vmem.brk = brk;
        Ok(brk)
    }

    /// Release memory mappings. The program break is not touched, see the note at the end.
    ///
    /// `releasable` is called once per tracked mapping and returns the *sub-ranges* of it to
    /// release, not merely whether to release the whole of it. That distinction is load-bearing,
    /// because a tracked mapping is not the same thing as a mapping the caller made: the VMA tree
    /// coalesces adjacent ranges carrying identical properties into a single entry
    /// (see [`Self::mappings`]), so one entry can span several unrelated `mmap`s -- and, when one
    /// manager backs more than one owner (litebox's Linux shim runs every guest process against
    /// one manager, at disjoint addresses in one host address space), several unrelated *owners*.
    /// A caller that only wants its own memory gone therefore has to be able to name the addresses
    /// it means; a whole-entry predicate cannot, and releasing the whole entry would unmap a
    /// neighbour's live memory. Ranges are clamped to the entry they came from, and empty ones are
    /// skipped, so an owner set that does not intersect an entry simply releases nothing of it.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the released memory regions are no longer used.
    pub unsafe fn release_memory<R>(
        &self,
        releasable: impl Fn(Range<usize>, VmFlags) -> R,
    ) -> Result<(), VmemUnmapError>
    where
        R: IntoIterator<Item = Range<usize>>,
    {
        for (r, vma) in self.mappings() {
            for part in releasable(r.clone(), vma) {
                let Some(range) = PageRange::new(part.start.max(r.start), part.end.min(r.end))
                else {
                    continue;
                };
                if let Some((view, _task, _)) = Platform::current_guest_access()
                    && Platform::has_independent_view_space(view)
                {
                    self.remove_range_for_view(view, range.start..range.end)?;
                    continue;
                }
                let mut vmem = self.vmem_write();
                unsafe { vmem.remove_mapping(range) }?;
            }
        }

        // The program break is deliberately left alone. Under the per-process swap protocol
        // ([`Self::swap_brk`]) the manager's break is 0 between operations and, during one, it
        // is *another* process's live break -- the releasing process is exiting or exec'ing on
        // its own thread and holds no break operation of its own. Zeroing it here (as this
        // used to) therefore never cleared anything of the caller's and could only clobber a
        // neighbour's, which was observed live under a 900-process spawn storm as an exec
        // reading back a zero break right after its loader published one ("execve: loader
        // left no initial brk", 2 of 900 execs), leaving that process with no heap. A caller
        // that models a single break for a single process resets it through
        // [`Self::swap_brk`] or the next [`Self::set_initial_brk`].

        Ok(())
    }

    /// Whether every byte of `range` is, right now, backed by a live [`domain::Custody::Present`]
    /// span within `view`'s OWN lineage -- an all-or-nothing check, unlike
    /// [`Self::change_page_permissions`]/[`Self::reset_pages`]'s graceful own-prefix walk. Walks
    /// [`domain::GuestVaDomain::custody_fragments_via_lineage`] (not the plain, strictly
    /// per-family [`domain::GuestVaDomain::custody_fragments`]) in address order and requires the
    /// walk to reach `range.end` with zero gaps, every fragment being `Present { .. }`; any gap,
    /// non-`Present` state, or fragment the lineage walk cannot reach fails the whole check.
    ///
    /// Deliberately lineage-aware rather than requiring `Present { view, .. }` to name `view`
    /// itself: [`domain::GuestVaDomain::custody_fragments_via_lineage`] only ever walks `view`'s
    /// own family and its true ancestor chain (see [`domain::FamilyRecord::parent`]) -- it can
    /// never cross into a sibling's or an unrelated family's map -- so any `Present` fragment it
    /// returns genuinely belongs to `view`'s own lineage, whether `view` diverged that page
    /// itself or still holds it only implicitly, by inheritance, exactly as
    /// [`Self::range_is_foreign_held`]'s doc comment describes ("a live, not-yet-diverged,
    /// not-yet-exec'd descendant holds every page of its ancestors *implicitly* ... with no
    /// custody of its own to find"). The original strict `v == view` form rejected every such
    /// not-yet-diverged inherited page outright, so a fork child's `mremap` over a range it
    /// legitimately owns by inheritance (an untouched or read-only file-COW window/alias page)
    /// was refused `EFAULT` even though the child never wrote to, and the range was never any
    /// other live actor's memory -- reproduced live by a fork child growing an inherited file-COW
    /// window (see the finding row this fixes). This walk still refuses a truly foreign range
    /// exactly as before: a fragment belonging to an unrelated family is never visible to
    /// [`domain::GuestVaDomain::custody_fragments_via_lineage`] in the first place, so it reports
    /// a gap there and the whole-range check still fails closed.
    fn whole_range_is_own_or_lineage_present(&self, view: VmViewId, range: Range<usize>) -> bool {
        if range.start >= range.end {
            return false;
        }
        let mut pos = range.start;
        for (fragment, custody, _inherited) in
            self.domain.custody_fragments_via_lineage(view, range.clone())
        {
            if fragment.start != pos || !matches!(&custody, domain::Custody::Present { .. }) {
                return false;
            }
            pos = fragment.end;
        }
        pos == range.end
    }

    /// Whether `view`'s own mutations of `range` must leave the shared `VmArea` there in place
    /// for some other live holder. `Vmem` is process-blind while the domain is per-family: a
    /// fork child's diverged page is `Present` in the child's family at the very same address
    /// the parent's family still holds it, and a live, not-yet-diverged, not-yet-exec'd
    /// descendant holds every page of its ancestors *implicitly*, by lineage, with no custody of
    /// its own to find -- the same lineage the domain's `retired_lineage_snapshot` and the
    /// platform's `keep_mirror_for_descendant` retention already serve (see
    /// [`domain::GuestVaDomain::family_has_live_inheriting_descendant_of`]). In either case
    /// deleting or re-flagging the one shared entry would break the other holder's host-side
    /// gate ([`Self::checked_guest_range`]) while its guest-side access keeps working. Always
    /// `false` for a caller without an independent view space, keeping the legacy path
    /// unchanged.
    fn range_is_foreign_held(&self, view: VmViewId, range: Range<usize>) -> bool {
        Platform::has_independent_view_space(view)
            && (self.domain.family_has_live_inheriting_descendant_of(view)
                || self.domain.foreign_family_present(view, range))
    }

    /// Splits `range` into the sub-ranges [`Self::range_is_foreign_held`] applies to (`held`)
    /// and the remainder (`free`).
    fn foreign_held_split(
        &self,
        view: VmViewId,
        range: Range<usize>,
    ) -> (Vec<Range<usize>>, Vec<Range<usize>>) {
        if !Platform::has_independent_view_space(view) {
            return (Vec::new(), alloc::vec![range]);
        }
        if self.domain.family_has_live_inheriting_descendant_of(view) {
            return (alloc::vec![range], Vec::new());
        }
        let held = self.domain.foreign_family_present_fragments(view, range.clone());
        let mut free = Vec::new();
        let mut cursor = range.start;
        for h in &held {
            if cursor < h.start {
                free.push(cursor..h.start);
            }
            cursor = h.end;
        }
        if cursor < range.end {
            free.push(cursor..range.end);
        }
        (held, free)
    }

    /// Unmaps `range` in `view`'s own address space only, leaving the shared `VmArea` in place
    /// for the other live family that still holds custody there (see
    /// [`Self::foreign_held_split`]); the entry lingers until the last holder releases it.
    fn unmap_own_view_only(&self, view: VmViewId, range: Range<usize>) {
        let vmem = self.vmem_write();
        let result = unsafe { vmem.platform.deallocate_pages(range.clone()) };
        drop(vmem);
        litebox_util_log::debug!(
            view:? = view, start:? = range.start, end:? = range.end, ok:? = result.is_ok();
            "unmapped only this view's own pages: another live family still holds the shared mapping"
        );
    }

    /// Removes `range` on behalf of `view`: foreign-held fragments are unmapped in `view`'s own
    /// space only, the rest is removed for real; `view`'s own custody is retired either way.
    fn remove_range_for_view(
        &self,
        view: VmViewId,
        range: Range<usize>,
    ) -> Result<(), VmemUnmapError> {
        let (held, free) = self.foreign_held_split(view, range);
        for h in held {
            self.unmap_own_view_only(view, h.clone());
            self.domain.confirm_retired_or_reconcile(view, h);
        }
        for f in free {
            let Some(page_range) = PageRange::new(f.start, f.end) else {
                continue;
            };
            let mut vmem = self.vmem_write();
            unsafe { vmem.remove_mapping(page_range) }?;
            drop(vmem);
            self.domain.confirm_retired_or_reconcile(view, f);
        }
        Ok(())
    }

    /// Changes `range`'s permissions on behalf of `view`. A fragment some other live holder
    /// shares (see [`Self::foreign_held_split`]) or one `view` holds only by fork lineage
    /// (`inherited`) is changed in `view`'s own address space alone, every page of it first made
    /// `view`'s own ([`PageManagementProvider::materialize_inherited_range`]), and only has its
    /// shared `VmArea` flags updated when nothing the host-side gate checks (`READ`/`WRITE`) is
    /// being taken away -- so the other holder's gate never becomes stricter than that holder's
    /// real permissions (the failure mode that spins a live process on `EFAULT`), at the price
    /// of this view's own gate staying permissive after a narrowing.
    fn protect_range_for_view(
        &self,
        view: VmViewId,
        range: Range<usize>,
        new_permissions: MemoryRegionPermissions,
        inherited: &[Range<usize>],
    ) -> Result<(), VmemProtectError> {
        let (held, _) = self.foreign_held_split(view, range.clone());
        // Address-ordered pieces: lineage-held (materialized, then published as this view's own
        // custody so its descendants resolve to it), foreign-held (materialized only), free.
        let mut marks: Vec<(usize, i8, bool)> = Vec::new();
        for r in inherited {
            marks.push((r.start, 1, true));
            marks.push((r.end, -1, true));
        }
        for r in &held {
            marks.push((r.start, 1, false));
            marks.push((r.end, -1, false));
        }
        marks.sort_by_key(|(at, delta, _)| (*at, *delta));
        let mut pieces: Vec<(Range<usize>, PieceKind)> = Vec::new();
        let (mut cursor, mut inherited_depth, mut held_depth) = (range.start, 0i32, 0i32);
        for (at, delta, is_inherited) in marks {
            let at = at.clamp(range.start, range.end);
            if at > cursor {
                let kind = if inherited_depth > 0 {
                    PieceKind::Inherited
                } else if held_depth > 0 {
                    PieceKind::Held
                } else {
                    PieceKind::Free
                };
                pieces.push((cursor..at, kind));
                cursor = at;
            }
            if is_inherited {
                inherited_depth += i32::from(delta);
            } else {
                held_depth += i32::from(delta);
            }
        }
        if cursor < range.end {
            pieces.push((cursor..range.end, PieceKind::Free));
        }
        if !Platform::has_independent_view_space(view) {
            let page_range = PageRange::new(range.start, range.end)
                .ok_or(VmemProtectError::InvalidRange(range))?;
            let mut vmem = self.vmem_write();
            return unsafe { vmem.protect_mapping(page_range, new_permissions) };
        }
        let ancestor_of = |page: usize| match self.domain.custody_at_via_lineage(view, page) {
            domain::Custody::Present { view: holder, .. }
            | domain::Custody::Retiring { view: holder, .. } => Some(holder),
            _ => None,
        };
        let gate_bits = MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE;
        // Every piece goes through the per-view materialization, a free one included: the
        // process-blind `VmArea` may already carry the requested flags because a sibling view
        // materialized the same piece first, and `protect_mapping` would then rightly change
        // nothing -- while this view still has no page of its own there.
        for (piece, kind) in pieces {
            let mut vmem = self.vmem_write();
            let areas: Vec<(Range<usize>, VmFlags)> = vmem
                .overlapping(piece.clone())
                .map(|(r, vma)| (r.start.max(piece.start)..r.end.min(piece.end), vma.flags()))
                .collect();
            let mut covered = piece.start;
            for (area, flags) in areas {
                if area.start != covered {
                    return Err(VmemProtectError::InvalidRange(covered..area.start));
                }
                covered = area.end;
                let page_range = PageRange::new(area.start, area.end)
                    .ok_or(VmemProtectError::InvalidRange(area.clone()))?;
                vmem.check_permissions(page_range, new_permissions)?;
                let current: MemoryRegionPermissions = flags.into();
                if flags.contains(VmFlags::VM_DEFERRED) && new_permissions.is_empty() {
                    continue;
                }
                Platform::materialize_inherited_range(
                    view,
                    area.clone(),
                    new_permissions,
                    &ancestor_of,
                )
                .map_err(VmemProtectError::ProtectError)?;
                let narrowing = !new_permissions.contains(current & gate_bits);
                if kind == PieceKind::Free || !narrowing {
                    vmem.record_permissions(page_range, new_permissions);
                }
                if kind == PieceKind::Inherited {
                    let _ = self.domain.confirm_present_or_reconcile(view, area);
                }
            }
            if covered != piece.end {
                return Err(VmemProtectError::InvalidRange(covered..piece.end));
            }
        }
        Ok(())
    }

    /// Materializes every fragment of `range` that `view` holds only through fork lineage (a
    /// live ancestor's page `view` has never individually touched) into `view`'s own independent
    /// [`domain::Custody::Present`] span, at each fragment's own current permissions (unchanged)
    /// -- the same [`platform::PageManagementProvider::materialize_inherited_range`] +
    /// [`domain::GuestVaDomain::confirm_present_or_reconcile`] pair
    /// [`Self::protect_range_for_view`]'s `PieceKind::Inherited` arm already uses for `mprotect`.
    /// A fragment that is already `view`'s own outright is left untouched.
    ///
    /// [`Self::remap_pages`] calls this, once [`Self::whole_range_is_own_or_lineage_present`]
    /// accepts the range, before its [`Self::range_is_foreign_held`] check: without it, a fork
    /// child growing (`MREMAP_MAYMOVE`) a range it still holds only by lineage is refused
    /// `ENOMEM` by that check -- correct for memory genuinely shared with another live process,
    /// but not for ordinary private (COW) memory, where real Linux gives a child a fully
    /// independent VMA list from the moment of `fork`, regardless of whether any byte has
    /// diverged yet. Reproduced live by a fork child growing an inherited file-COW window with
    /// its parent still alive (see the finding row this fixes).
    ///
    /// Returns `false` if any materialize call fails, with whatever earlier fragments in this
    /// same call already succeeded left materialized (matching
    /// [`Self::protect_range_for_view`]'s own non-transactional precedent for the identical
    /// primitive) -- [`Self::remap_pages`] treats `false` the same as a range it cannot touch at
    /// all, refusing the whole operation.
    fn materialize_lineage_only_fragments(&self, view: VmViewId, range: Range<usize>) -> bool {
        let ancestor_of = |page: usize| match self.domain.custody_at_via_lineage(view, page) {
            domain::Custody::Present { view: holder, .. }
            | domain::Custody::Retiring { view: holder, .. } => Some(holder),
            _ => None,
        };
        for (fragment, _custody, by_lineage) in
            self.domain.custody_fragments_via_lineage(view, range)
        {
            if !by_lineage {
                continue;
            }
            let vmem = self.vmem_read();
            let areas: Vec<(Range<usize>, MemoryRegionPermissions)> = vmem
                .overlapping(fragment.clone())
                .map(|(r, vma)| {
                    (
                        r.start.max(fragment.start)..r.end.min(fragment.end),
                        vma.flags().into(),
                    )
                })
                .collect();
            drop(vmem);
            for (area, permissions) in areas {
                if Platform::materialize_inherited_range(view, area.clone(), permissions, &ancestor_of)
                    .is_err()
                {
                    return false;
                }
                let _ = self.domain.confirm_present_or_reconcile(view, area);
            }
        }
        true
    }

    /// Expands (or shrinks) an existing memory mapping
    ///
    /// `old_addr` is the old address of the virtual memory block that you want to expand (or shrink).
    ///
    /// `old_size` is the size of the old memory block.
    ///
    /// `new_size` is the new size of the memory block.
    ///
    /// `may_move` indicates whether the memory block can be moved to a new address if there is not sufficient
    /// space to expand the old memory block at its current location.
    ///
    /// ## Returns
    ///
    /// If the operation is successful, it returns the new address of the memory block.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the memory region is no longer used by any other.
    pub unsafe fn remap_pages(
        &self,
        old_addr: Platform::RawMutPointer<u8>,
        old_size: usize,
        new_size: usize,
        may_move: bool,
    ) -> Result<Platform::RawMutPointer<u8>, RemapError> {
        let old_start = old_addr.as_usize();
        let old_end = old_start + old_size;
        if let Some((view, _task, _)) = Platform::current_guest_access() {
            if !self.whole_range_is_own_or_lineage_present(view, old_start..old_end) {
                // Actor-facing mremap rule: refuse the whole operation rather than partially
                // applying it -- unlike mprotect/madvise's graceful own-fragment walk, a caller
                // remapping across a hole or another actor's memory gets nothing done at all. Own
                // lineage (a fork child's not-yet-diverged inherited pages) counts as present
                // here; only a genuine gap or another actor's memory fails this.
                return Err(RemapError::AlreadyUnallocated);
            }
            // Diverge any lineage-only fragment into `view`'s own custody now, before the
            // `range_is_foreign_held` check below can mistake a live ancestor's still-implicit
            // sharing of ordinary private (COW) memory for genuinely foreign-shared memory. See
            // `Self::materialize_lineage_only_fragments`'s doc comment.
            if !self.materialize_lineage_only_fragments(view, old_start..old_end) {
                return Err(RemapError::AlreadyUnallocated);
            }
        }
        if let Some((view, _task, _)) = Platform::current_guest_access()
            && self.range_is_foreign_held(view, old_start..old_end)
        {
            // The shared `VmArea` cannot move or grow under another live holder; a shrink only
            // releases this view's own tail. A grow reports `ENOMEM`, which a libc realloc
            // answers with allocate-and-copy.
            if new_size < old_size {
                let tail = old_start + new_size..old_end;
                if !tail.start.is_multiple_of(ALIGN) {
                    return Err(RemapError::Unaligned);
                }
                self.remove_range_for_view(view, tail)
                    .map_err(|_| RemapError::AlreadyUnallocated)?;
            } else if new_size > old_size {
                return Err(RemapError::OutOfMemory);
            }
            return Ok(old_addr);
        }
        let mut vmem = self.vmem_write();
        let old_range = PageRange::new(old_start, old_end).ok_or(RemapError::Unaligned)?;
        match unsafe {
            vmem.resize_mapping(
                old_range,
                linux::NonZeroPageSize::new(new_size).ok_or(RemapError::Unaligned)?,
            )
        } {
            Ok(()) => {
                drop(vmem);
                if new_size < old_size {
                    self.shadow_retire_present(old_start + new_size..old_end);
                } else if new_size > old_size {
                    self.shadow_publish_present(old_start + old_size..old_start + new_size);
                }
                Ok(old_addr)
            }
            Err(linux::VmemResizeError::RangeOccupied(_)) => {
                // trying to remap a subset of an existing mapping
                if !may_move {
                    return Err(RemapError::OutOfMemory);
                }
                let move_result = unsafe {
                    vmem.move_mappings(
                        old_range,
                        None,
                        NonZeroPageSize::new(new_size).ok_or(RemapError::Unaligned)?,
                    )
                };
                drop(vmem);
                match move_result {
                    Ok(new_addr) => {
                        self.shadow_retire_present(old_start..old_end);
                        self.shadow_publish_present(
                            new_addr.as_usize()..new_addr.as_usize() + new_size,
                        );
                        Ok(new_addr)
                    }
                    Err(linux::VmemMoveError::OutOfMemory) => Err(RemapError::OutOfMemory),
                    Err(linux::VmemMoveError::UnAligned) => Err(RemapError::Unaligned),
                    Err(linux::VmemMoveError::RemapError(err)) => Err(err),
                }
            }
            Err(linux::VmemResizeError::NotExist(_)) => {
                // The old range's start is not inside a tracked VMA. For a grow,
                // degrade to `OutOfMemory` (ENOMEM) instead of the fatal
                // `AlreadyUnallocated` (EFAULT): this is exactly the errno Linux
                // returns when an mmap-region grow cannot be satisfied in place,
                // and it lets a guest heap allocator (musl grows a chunk via
                // `mremap` without `MREMAP_MAYMOVE`) fall back to allocate-and-copy
                // rather than treat it as a corrupt pointer and crash. A non-grow
                // on an untracked range is a genuine bad address and stays EFAULT.
                if new_size > old_size {
                    Err(RemapError::OutOfMemory)
                } else {
                    Err(RemapError::AlreadyUnallocated)
                }
            }
            Err(linux::VmemResizeError::InvalidAddr { .. }) => Err(RemapError::AlreadyAllocated),
            Err(linux::VmemResizeError::InitializationPending(_)) => Err(RemapError::OutOfMemory),
            Err(linux::VmemResizeError::UnmapError(
                VmemUnmapError::UnAligned
                | VmemUnmapError::UnmapError(DeallocationError::Unaligned),
            )) => Err(RemapError::Unaligned),
            Err(linux::VmemResizeError::UnmapError(VmemUnmapError::UnmapError(
                DeallocationError::AlreadyUnallocated,
            ))) => Err(RemapError::AlreadyUnallocated),
            Err(linux::VmemResizeError::OutOfMemory) => Err(RemapError::OutOfMemory),
        }
    }

    /// Remove pages from the mapping.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the memory region is no longer used by any other.
    pub unsafe fn remove_pages(
        &self,
        ptr: Platform::RawMutPointer<u8>,
        len: usize,
    ) -> Result<(), VmemUnmapError> {
        let start = ptr.as_usize();
        let range = PageRange::new(start, start + len).ok_or(VmemUnmapError::UnAligned)?;
        let Some((view, _task, _)) = Platform::current_guest_access() else {
            let mut vmem = self.vmem_write();
            unsafe { vmem.remove_mapping(range) }?;
            drop(vmem);
            self.shadow_retire_present(range.start..range.end);
            return Ok(());
        };
        let mut own_present: Vec<Range<usize>> = Vec::new();
        let mut inherited: Vec<Range<usize>> = Vec::new();
        for (r, custody, by_lineage) in self
            .domain
            .custody_fragments_via_lineage(view, range.start..range.end)
        {
            let target = match &custody {
                domain::Custody::Present { view: v, .. } if !by_lineage && *v == view => {
                    &mut own_present
                }
                domain::Custody::Present { .. } | domain::Custody::Retiring { .. } if by_lineage => {
                    &mut inherited
                }
                _ => continue,
            };
            match target.last_mut() {
                Some(last) if last.end == r.start => last.end = r.end,
                _ => target.push(r),
            }
        }
        for sub in own_present {
            if let Err(error) = self.remove_range_for_view(view, sub.clone()) {
                litebox_util_log::debug!(
                    view:? = view, start:? = sub.start, end:? = sub.end, error:% = error;
                    "remove_pages: failed to unmap an own-Present fragment"
                );
            }
        }
        // A fork child unmapping memory it holds only by lineage: gone from its own address
        // space, while the shared `VmArea` stays for the ancestor that still holds it.
        for sub in inherited {
            self.unmap_own_view_only(view, sub);
        }
        Ok(())
    }

    /// The address-ordered prefix of `range` a per-view actor may mutate: `view`'s own
    /// `Present` fragments and the `Present`/`Retiring` fragments it holds only by fork lineage
    /// (see [`domain::GuestVaDomain::custody_fragments_via_lineage`]), up to the first gap or
    /// other custody. Returns where the prefix ends and its lineage-held sub-ranges, merged.
    fn actor_prefix(&self, view: VmViewId, range: Range<usize>) -> (usize, Vec<Range<usize>>) {
        let mut end = range.start;
        let mut inherited: Vec<Range<usize>> = Vec::new();
        let per_view = Platform::has_independent_view_space(view);
        for (fragment, custody, by_lineage) in
            self.domain.custody_fragments_via_lineage(view, range)
        {
            if fragment.start != end {
                break;
            }
            let accepted = match &custody {
                domain::Custody::Present { view: v, .. } if !by_lineage => *v == view,
                domain::Custody::Present { .. } | domain::Custody::Retiring { .. } => {
                    by_lineage && per_view
                }
                _ => false,
            };
            if !accepted {
                break;
            }
            if by_lineage {
                match inherited.last_mut() {
                    Some(last) if last.end == fragment.start => last.end = fragment.end,
                    _ => inherited.push(fragment.clone()),
                }
            }
            end = fragment.end;
        }
        (end, inherited)
    }

    /// Reset pages without removing its mapping.
    ///
    /// Private anonymous pages are dropped and refault zero-filled, for either advice
    /// value. `VM_SHARED` mappings (file-backed or anonymous) are left untouched -- their
    /// canonical backing is never discarded, so a subsequent access simply keeps observing
    /// its current bytes, matching Linux's own guest-visible contract. Private file-backed
    /// pages cannot yet be correctly reset this way (see `Vmem::reset_pages`'s own doc
    /// comment in `linux.rs` for the exact reason and the tracked remainder) and return
    /// `Err(VmemResetError::FileBacked)`, exactly as `anonymous_only = true` already did
    /// for any file-backed mapping before this arm existed at all.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the memory contents in the affected region are no longer accessed or
    /// relied upon. Any pointers or references to the previous contents become invalid.
    pub unsafe fn reset_pages(
        &self,
        ptr: Platform::RawMutPointer<u8>,
        len: usize,
        anonymous_only: bool,
    ) -> Result<(), VmemResetError> {
        let start = ptr.as_usize();
        let full_range = start..start + len;
        let range = PageRange::new(start, start + len).ok_or(VmemResetError::UnAligned)?;
        let Some((view, _task, _)) = Platform::current_guest_access() else {
            let mut vmem = self.vmem_write();
            return unsafe { vmem.reset_pages(range, anonymous_only) };
        };
        // A lineage-held fragment resets the same way as an own one: the platform re-creates
        // the pages in `view`'s own address space (a fresh zero page shadows an inherited one
        // whose host slot an ancestor still holds) and the shared `VmArea` is re-inserted as is.
        let (owned_end, inherited) = self.actor_prefix(view, full_range.clone());
        if owned_end == full_range.start {
            return Err(VmemResetError::AlreadyUnallocated);
        }
        let owned_range = PageRange::new(full_range.start, owned_end)
            .ok_or(VmemResetError::AlreadyUnallocated)?;
        let mut vmem = self.vmem_write();
        unsafe { vmem.reset_pages(owned_range, anonymous_only) }?;
        drop(vmem);
        // The fresh pages are this view's own now: publish them so a descendant resolves to
        // them instead of to the ancestor's content they replaced.
        for sub in inherited {
            let _ = self.domain.confirm_present_or_reconcile(view, sub);
        }
        if owned_end != full_range.end {
            return Err(VmemResetError::AlreadyUnallocated);
        }
        Ok(())
    }

    /// `madvise(MADV_WIPEONFORK)` (`enable`) / `madvise(MADV_KEEPONFORK)` (`!enable`): marks
    /// the mappings in `[ptr, ptr + len)` so that a forked child sees them zero-filled while
    /// the parent keeps its contents. Only the flag is recorded here; the wipe itself is
    /// [`Self::wipe_on_fork_child`], which the process model calls at the point where the
    /// child's view of memory diverges from the parent's.
    ///
    /// Fails with [`VmemWipeOnForkError::NotPrivateAnonymous`] on a file-backed or shared
    /// mapping (Linux: `EINVAL`) and [`VmemWipeOnForkError::Unmapped`] on a hole (`ENOMEM`).
    pub fn set_wipe_on_fork(
        &self,
        ptr: Platform::RawMutPointer<u8>,
        len: usize,
        enable: bool,
    ) -> Result<(), VmemWipeOnForkError> {
        let mut vmem = self.vmem_write();
        let start = ptr.as_usize();
        let range = PageRange::new(start, start + len).ok_or(VmemWipeOnForkError::UnAligned)?;
        vmem.set_wipe_on_fork(range, enable)
    }

    /// Every mapping marked `MADV_WIPEONFORK`, with its flags. Like [`Self::mappings`], one
    /// entry can span more than one `mmap`; callers that act on a subset of a process's memory
    /// intersect these with their own ownership records, see [`Self::wipe_on_fork_child`].
    pub fn ranges_to_wipe_on_fork(&self) -> Vec<(Range<usize>, VmFlags)> {
        self.vmem_read().wipe_on_fork_ranges()
    }

    /// Gives the *child* of a fork the `MADV_WIPEONFORK` view of memory: every wipe-marked
    /// private anonymous mapping is dropped and re-created zero-filled, keeping its flags
    /// (including the wipe mark itself, which Linux also inherits, so grandchildren are
    /// wiped too).
    ///
    /// Written for a process model where the child runs on the parent's live pages after the
    /// parent copied its own contents out (litebox's Linux shim: `save_address_space`, then
    /// `hand_off_to`): calling this between those two steps makes the child start from zeros
    /// while the parent's saved image brings its bytes back untouched. Call order is what
    /// makes it child-only -- called before the parent's copy-out it would wipe the parent.
    ///
    /// `restrict` names the parts of each marked mapping that belong to the forking process,
    /// exactly as [`Self::release_memory`]'s predicate does, because a coalesced manager
    /// entry can cover a neighbour's memory; parts are clamped to the entry and empty ones
    /// are skipped. Only writable, materialized, private anonymous pieces are wiped: those
    /// are precisely the ones a copy-out saves, so nothing the parent cannot restore is ever
    /// zeroed. A piece that cannot be wiped is logged loudly and left as is, because fork must
    /// not fail for it, but a child then sees inherited bytes the program asked to be gone.
    ///
    /// Returns the number of bytes wiped.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the previous contents of the wiped ranges are no longer
    /// relied upon by whoever runs on these pages next (the parent's copy must already be
    /// saved).
    pub unsafe fn wipe_on_fork_child<R>(
        &self,
        restrict: impl Fn(Range<usize>, VmFlags) -> R,
    ) -> usize
    where
        R: IntoIterator<Item = Range<usize>>,
    {
        let mut wiped = 0;
        for (r, flags) in self.ranges_to_wipe_on_fork() {
            if flags.contains(VmFlags::VM_SHARED) || flags.contains(VmFlags::VM_DEFERRED) {
                // Shared: there is no private child copy to wipe. Deferred: nothing has been
                // materialized to wipe. A non-writable (e.g. `PROT_NONE` or read-only) range is
                // no longer skipped here: `Task::save_address_space` now captures its bytes
                // whenever it also carries `VM_WIPEONFORK`, so zeroing it in the child is safe
                // -- the parent's copy is no longer only implicit in its own live pages.
                litebox_util_log::debug!(
                    start:? = r.start, end:? = r.end, flags:? = flags;
                    "wipe-on-fork range skipped: shared or deferred"
                );
                continue;
            }
            for part in restrict(r.clone(), flags) {
                let Some(range) = PageRange::new(part.start.max(r.start), part.end.min(r.end))
                else {
                    continue;
                };
                let mut vmem = self.vmem_write();
                match unsafe { vmem.reset_pages(range, true) } {
                    Ok(()) => wiped += range.len(),
                    Err(error) => litebox_util_log::error!(
                        start:? = range.start, end:? = range.end, error:% = error;
                        "wipe-on-fork range could not be zeroed; the child inherits its contents"
                    ),
                }
            }
        }
        if wiped != 0 {
            litebox_util_log::debug!(bytes:? = wiped; "wiped MADV_WIPEONFORK ranges for a forked child");
        }
        wiped
    }

    /// The per-view (independent-address-space) counterpart of [`Self::wipe_on_fork_child`].
    ///
    /// [`Self::wipe_on_fork_child`] resets the pages in the CURRENT view -- correct only for the
    /// legacy park/hand-off model, where the child runs on the forking parent's own live pages
    /// after the parent has copied its image out. Under the per-view model the forking parent's
    /// view IS its own live address space and the child gets an independent one, so resetting the
    /// current view there wrongly zeroes the PARENT's own copy (Linux zeroes only the child's).
    ///
    /// This instead gives `view`'s OWN per-view space a fresh, zero-filled page for every
    /// `MADV_WIPEONFORK` range (materialized with no ancestor to copy from) and publishes Present
    /// custody there, so the child reads zero while the parent keeps its content, and -- because the
    /// wipe mark is inherited -- the child re-running this on its own fork re-zeroes the grandchild
    /// too. `view` MUST be the freshly forked child's own view. `restrict` names each marked
    /// mapping's parts that belong to the forking process, exactly as [`Self::wipe_on_fork_child`]'s
    /// does. Returns the number of bytes zeroed in the child's view.
    pub fn wipe_on_fork_child_view<R>(
        &self,
        view: VmViewId,
        restrict: impl Fn(Range<usize>, VmFlags) -> R,
    ) -> usize
    where
        R: IntoIterator<Item = Range<usize>>,
    {
        let mut wiped = 0;
        for (r, flags) in self.ranges_to_wipe_on_fork() {
            if flags.contains(VmFlags::VM_SHARED) || flags.contains(VmFlags::VM_DEFERRED) {
                continue;
            }
            let permissions: MemoryRegionPermissions = flags.into();
            for part in restrict(r.clone(), flags) {
                let start = part.start.max(r.start);
                let end = part.end.min(r.end);
                if start >= end {
                    continue;
                }
                match Platform::materialize_inherited_range(view, start..end, permissions, &|_| None)
                {
                    Ok(()) => {
                        let _ = self.domain.confirm_present_or_reconcile(view, start..end);
                        wiped += end - start;
                    }
                    Err(error) => litebox_util_log::error!(
                        start:? = start, end:? = end, error:? = error;
                        "per-view wipe-on-fork range could not be zeroed in the child's view; it inherits its contents"
                    ),
                }
            }
        }
        if wiped != 0 {
            litebox_util_log::debug!(bytes:? = wiped, view:? = view; "wiped MADV_WIPEONFORK ranges into a forked child's own per-view space");
        }
        wiped
    }

    /// `madvise(MADV_DONTFORK)` (`enable`) / `madvise(MADV_DOFORK)` (`!enable`): marks the
    /// mappings in `[ptr, ptr + len)` so that a forked child's view of memory has no mapping
    /// there at all. Only the flag is recorded here; the drop itself is
    /// [`Self::dont_fork_child`], which the process model calls at the point where the
    /// child's view of memory diverges from the parent's.
    ///
    /// Fails with [`VmemDontForkError::Unmapped`] on a hole (Linux: `ENOMEM`). Unlike
    /// [`Self::set_wipe_on_fork`], legal on any mapping.
    pub fn set_dont_fork(
        &self,
        ptr: Platform::RawMutPointer<u8>,
        len: usize,
        enable: bool,
    ) -> Result<(), VmemDontForkError> {
        let mut vmem = self.vmem_write();
        let start = ptr.as_usize();
        let range = PageRange::new(start, start + len).ok_or(VmemDontForkError::UnAligned)?;
        vmem.set_dont_fork(range, enable)
    }

    /// Every mapping marked `MADV_DONTFORK`, with its flags.
    pub fn ranges_to_dont_fork(&self) -> Vec<(Range<usize>, VmFlags)> {
        self.vmem_read().dont_fork_ranges()
    }

    /// Intends to give the *child* of a fork the `MADV_DONTFORK` view of memory (Linux drops
    /// these mappings unconditionally at `dup_mmap` time, before the child ever runs), but
    /// cannot safely do so at this call site and therefore leaves every mapping exactly as it
    /// is: a no-op, kept only so its caller ([`crate::mm`]'s fork call site) has a stable,
    /// documented place to call once a real, family-scoped implementation exists.
    ///
    /// `self.vmem` has no per-family/per-view notion of its own (see
    /// [`PageManager::handle_page_fault_inner`]'s own doc comment): one guest-wide manager backs
    /// every process, at addresses a forked-but-undiverged child necessarily still shares
    /// numerically with its parent. This is called synchronously on the *forking parent's own
    /// thread*, before the child's own family/view is ever registered (that only happens lazily,
    /// on the child's own first memory access) -- so there is no child-scoped custody entry this
    /// call could mark instead, and the previous implementation's `vmem.remove_mapping` +
    /// [`Self::shadow_retire_present`] pair had only the shared, family-blind manager to act on.
    /// Live-reproduced as a deterministic crash: the *parent* (never paused by this call --
    /// `fork()` returns to it immediately, same as real Linux, and it keeps running concurrently
    /// with the child) continuing to legitimately use exactly the range just "removed" for the
    /// child, and instead faulting into a hole with no VMA left at all
    /// (`PageFaultError::AccessError("no mapping")`, immediately fatal) -- this was the dominant
    /// failure mode of the real npm repro this fix targets (see
    /// `hvf-fork-cow-ancestor-retire-breaks-live-descendant-lineage`'s own PRD history for the
    /// unrelated, already-fixed custody/physical-layer gaps this is not a duplicate of).
    ///
    /// Consequence of the no-op: a live child that touches a `MADV_DONTFORK` range before it
    /// either diverges that memory itself or (as every process in the motivating repro does)
    /// `execve`s away -- which discards this inherited image entirely regardless -- sees the
    /// parent's ordinary fork-inherited (COW) content there instead of a fresh hole, i.e. exactly
    /// as if `MADV_DONTFORK` had not been requested. This never lets an unrelated family (one
    /// with no fork lineage to this one) see anything it could not already see, so it does not
    /// weaken cross-family isolation; it only loosens one specific parent/child memory-visibility
    /// guarantee, in exchange for the parent never losing its own live memory to its own child's
    /// fork bookkeeping. A real fix needs the child's family pre-registered (or a family-scoped
    /// block recorded some other way that survives to its later registration) before any removal
    /// runs, so only that family's own custody is ever affected -- out of this fix's scope.
    ///
    /// Returns 0 (nothing is removed).
    ///
    /// # Safety
    ///
    /// Kept `unsafe` to match this no-op's real, still-`unsafe` implementation should a future
    /// change restore one; no safety obligation exists on the current, empty body.
    pub unsafe fn dont_fork_child<R>(&self, restrict: impl Fn(Range<usize>, VmFlags) -> R) -> usize
    where
        R: IntoIterator<Item = Range<usize>>,
    {
        let _ = restrict;
        0
    }

    /// Internal common function used by `make_pages_*` to change page permissions.
    fn change_page_permissions(
        &self,
        ptr: Platform::RawMutPointer<u8>,
        len: usize,
        new_permissions: MemoryRegionPermissions,
    ) -> Result<(), VmemProtectError> {
        let start = ptr.as_usize();
        let full_range = start..start + len;
        let range = PageRange::new(start, start + len)
            .ok_or(VmemProtectError::InvalidRange(full_range.clone()))?;
        let Some((view, _task, _)) = Platform::current_guest_access() else {
            let mut vmem = self.vmem_write();
            return unsafe { vmem.protect_mapping(range, new_permissions) };
        };
        let (owned_end, inherited) = self.actor_prefix(view, full_range.clone());
        if owned_end == full_range.start {
            return Err(VmemProtectError::InvalidRange(full_range));
        }
        self.protect_range_for_view(
            view,
            full_range.start..owned_end,
            new_permissions,
            &inherited,
        )?;
        if owned_end != full_range.end {
            return Err(VmemProtectError::InvalidRange(owned_end..full_range.end));
        }
        Ok(())
    }

    /// Make pages readable and writable.
    ///
    /// # Safety
    ///
    /// The caller must ensure there is no concurrent `execute` access to the memory region.
    pub unsafe fn make_pages_writable(
        &self,
        ptr: Platform::RawMutPointer<u8>,
        len: usize,
    ) -> Result<(), VmemProtectError> {
        self.change_page_permissions(
            ptr,
            len,
            MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE,
        )
    }

    /// Make pages readable and executable.
    ///
    /// # Safety
    ///
    /// The caller must ensure there is no concurrent `write` access to the memory region.
    pub unsafe fn make_pages_executable(
        &self,
        ptr: Platform::RawMutPointer<u8>,
        len: usize,
    ) -> Result<(), VmemProtectError> {
        self.change_page_permissions(
            ptr,
            len,
            MemoryRegionPermissions::READ | MemoryRegionPermissions::EXEC,
        )
    }

    /// Make pages readable only.
    ///
    /// # Safety
    ///
    /// The caller must ensure there is no concurrent `write/execute` access to the memory region.
    pub unsafe fn make_pages_readable(
        &self,
        ptr: Platform::RawMutPointer<u8>,
        len: usize,
    ) -> Result<(), VmemProtectError> {
        self.change_page_permissions(ptr, len, MemoryRegionPermissions::READ)
    }

    /// Make pages inaccessible.
    ///
    /// # Safety
    ///
    /// The caller must ensure there is no concurrent access to the memory region.
    pub unsafe fn make_pages_inaccessible(
        &self,
        ptr: Platform::RawMutPointer<u8>,
        len: usize,
    ) -> Result<(), VmemProtectError> {
        self.change_page_permissions(ptr, len, MemoryRegionPermissions::empty())
    }

    /// Make pages readable, writable and executable.
    ///
    /// # Safety
    ///
    /// This operation is inherently dangerous and should be used with extreme caution.
    /// Allowing pages to be both writable and executable can lead to severe security vulnerabilities,
    /// such as code injection attacks or exploitation of memory corruption bugs.
    ///
    /// The caller must ensure the following:
    /// 1. The memory region is only used for legitimate purposes, such as JIT compilation,
    ///    where writable and executable permissions are strictly necessary.
    /// 2. The memory region is properly sanitized and does not contain malicious or unintended code.
    ///
    /// It is highly recommended to minimize the use of this function and to prefer safer alternatives
    /// whenever possible. If this function must be used, ensure that the memory region is locked down
    /// and access is strictly controlled.
    pub unsafe fn make_pages_rwx(
        &self,
        ptr: Platform::RawMutPointer<u8>,
        len: usize,
    ) -> Result<(), VmemProtectError> {
        self.change_page_permissions(
            ptr,
            len,
            MemoryRegionPermissions::READ
                | MemoryRegionPermissions::WRITE
                | MemoryRegionPermissions::EXEC,
        )
    }

    /// Register an already-allocated memory region in the VMA tracker.
    ///
    /// This is used when memory has been allocated by some means other than the normal
    /// `create_*_pages` path (e.g., CoW mappings created directly by the platform), so that the
    /// page manager tracks the region for future `mprotect`, `munmap`, etc.
    ///
    /// If `replace` is `true`, any overlapping tracked mappings are evicted from the tracker
    /// (without calling the platform deallocator) before inserting. Otherwise, returns `None`
    /// without registering if the provided `range` overlaps with any existing mapping.
    ///
    /// # Safety
    ///
    /// The `range` must be an already-mapped region with the given `permissions`.
    #[must_use]
    pub unsafe fn register_existing_mapping(
        &self,
        range: PageRange<ALIGN>,
        permissions: MemoryRegionPermissions,
        is_file_backed: bool,
        replace: bool,
        shared: bool,
    ) -> Option<()> {
        let vma = VmArea::new(
            VmFlags::from(permissions) | VmFlags::may_flags_for_mapping(shared, is_file_backed),
            is_file_backed,
            None,
        );
        let mut vmem = self.vmem_write();
        if !replace && vmem.overlapping(range.into()).next().is_some() {
            return None;
        }
        let published = range.start..range.end;
        vmem.register_existing_mapping_overwrite(range, vma);
        drop(vmem);
        // Same custody publication as `create_pages`: the platform mapped this range for the
        // calling view, so the view's own family records it `Present` (idempotent for a
        // `MAP_FIXED` replace of the view's own memory).
        self.shadow_publish_present(published);
        Some(())
    }

    /// A view of the mapping metadata for identity-sensitive point queries (futex keys, fault
    /// classification); see [`MappingReadGuard`] for what it does (not) hold.
    pub fn lock_mappings(&self) -> MappingReadGuard<'_, Platform, ALIGN> {
        MappingReadGuard {
            mirror: &self.mirror,
        }
    }

    /// Returns all mappings in a vector.
    ///
    /// One returned range is *not* one `mmap`: the underlying VMA tree coalesces adjacent ranges
    /// whose properties are identical, so two separately created mappings that happen to abut --
    /// which is the common case here, since `Vmem::get_unmmaped_area`'s placement search returns
    /// the address immediately below an existing range -- are reported as a single entry. Any
    /// caller that acts on a whole returned range therefore acts on memory it may not have
    /// created; see [`Self::release_memory`], which takes sub-ranges for exactly this reason.
    pub fn mappings(&self) -> Vec<(Range<usize>, VmFlags)> {
        self.vmem_read()
            .iter()
            .map(|(r, vma)| (r.start..r.end, vma.flags()))
            .collect()
    }

    /// [`Self::mappings`] answered from the mapping-table mirror (see `PageManager::mirror`):
    /// the same table as of the end of the last exclusive section, without taking the mapping
    /// lock. For readers that are not mapping mutations -- `/proc/<pid>/maps`, `/proc/<pid>/mem`
    /// bounds -- which used to queue a guest `read` behind every mm syscall of every process (T1h
    /// fix-up: `read` waited up to 0.43 s on the mapping lock in a desktop soak). A snapshot either
    /// way: the locked form also released the lock before its caller used the result.
    pub fn mappings_snapshot(&self) -> Vec<(Range<usize>, VmFlags)> {
        self.mirror
            .read()
            .iter()
            .map(|(r, vma)| (r.start..r.end, vma.flags()))
            .collect()
    }

    /// Reserves `range` on `owner`'s own behalf so a flexible (non-`MAP_FIXED`) placement search
    /// steered by that same `owner` steers around it even though it has no live mapping -- a
    /// search steered by any other owner is unaffected. See
    /// [`linux::Vmem::reserve_external`]'s doc comment for why this exists (a
    /// saved-but-currently-unmapped fork-family member's memory) and for why `owner` scoping
    /// matters (vfork-park-reserved-range-steers-unrelated-familys-flexible-mmap-confirmed).
    pub fn reserve_external(&self, range: Range<usize>, owner: VmViewId) {
        self.vmem_write().reserve_external(range, owner);
    }

    /// Releases a reservation made by [`Self::reserve_external`] under the same `owner`.
    pub fn release_external(&self, range: Range<usize>, owner: VmViewId) {
        self.vmem_write().release_external(range, owner);
    }

    /// Captures `range`'s private backing bytes via
    /// [`PageManagementProvider::capture_private_backing`], holding this manager's own mapping
    /// lock across the call so no concurrent `mmap`/`munmap`/`mprotect` can race the platform's
    /// read of these bytes.
    ///
    /// This is the standalone capture/restore primitive only -- it is not yet wired into any real
    /// fork/exec/`MAP_FIXED`-replace call site (that wiring, and `VmArea`'s own backing-identity
    /// bookkeeping across a split, are this row's disclosed remainder).
    ///
    /// # Errors
    ///
    /// See [`crate::platform::page_mgmt::CaptureBackingError`].
    pub fn capture_private_backing(
        &self,
        range: Range<usize>,
        mode: crate::platform::page_mgmt::CaptureMode,
    ) -> Result<crate::platform::page_mgmt::CapturedBackingRun, crate::platform::page_mgmt::CaptureBackingError>
    {
        let vmem = self.vmem_read();
        vmem.platform.capture_private_backing(range, mode)
    }

    /// Restores a lease captured by [`Self::capture_private_backing`] at `gva`: installs a real,
    /// freshly-materialized private mapping at `gva` for the lease's own length via the same
    /// `Vmem::insert_mapping` path any ordinary fixed `mmap` uses (so this restored range is fully
    /// visible to [`Self::mappings`]/`flags_at`/every other ordinary consumer, not a raw
    /// platform-level allocation invisible to this manager's own bookkeeping), then writes the
    /// leased bytes into it. Refuses (without installing anything) if `gva` is already mapped.
    /// `vma` describes the flags the restored mapping should carry (its `initialization`/
    /// `shared_futex` fields are ignored and reset).
    ///
    /// Holds this manager's own mapping lock across the whole call, matching "under the
    /// `PageManager` mapping lock".
    ///
    /// # Errors
    ///
    /// See [`crate::platform::page_mgmt::RestoreBackingError`].
    ///
    /// Scoped to exactly `VmArea`'s own visibility (`pub(in crate::mm)`), not `pub`: widening
    /// `VmArea` itself to cross a crate boundary is a bigger, separate decision than this
    /// standalone primitive needs to make, especially since real wiring into any cross-crate call
    /// site is explicitly out of scope for this landing.
    #[allow(
        dead_code,
        reason = "standalone primitive, not yet wired into any real call site -- \
                  see fork-private-immutable-replay-backing's disclosed remainder"
    )]
    pub(in crate::mm) fn restore_private_backing(
        &self,
        lease: crate::platform::page_mgmt::PrivateBackingLease,
        gva: usize,
        vma: VmArea,
    ) -> Result<Platform::RawMutPointer<u8>, crate::platform::page_mgmt::RestoreBackingError> {
        use crate::platform::page_mgmt::RestoreBackingError;
        if lease.is_empty() {
            return Err(RestoreBackingError::LengthMismatch);
        }
        let len = lease.len();
        let range = PageRange::new(gva, gva + len).ok_or(RestoreBackingError::LengthMismatch)?;
        let mut vmem = self.vmem_write();
        let ptr = unsafe {
            vmem.insert_mapping(
                range,
                vma,
                true,
                crate::platform::page_mgmt::FixedAddressBehavior::NoReplace,
            )
        }
        .map_err(|_| RestoreBackingError::AddressInUse)?;
        vmem.platform.restore_private_backing(lease, gva)?;
        Ok(ptr)
    }

    /// Get the memory permissions of a given address range.
    ///
    /// `ptr` specifies the start address of the memory range.
    /// `len` specifies the length of the memory range.
    /// This function returns `MemoryRegionPermissions` only if the range is valid.
    /// A memory range is invalid if it contains:
    /// - Unmapped pages
    /// - Memory pages with different permissions
    ///
    /// Answered from the mapping-table mirror (see `PageManager::mirror`), so it never waits
    /// behind a mapping mutation's platform effect: it sees every mutation whose exclusive
    /// section has ended, like a reader queued behind that section would have.
    pub fn get_memory_permissions(
        &self,
        ptr: NonZeroAddress<ALIGN>,
        len: NonZeroPageSize<ALIGN>,
    ) -> Option<MemoryRegionPermissions> {
        let start = ptr.as_usize();
        let end = start + len.as_usize();
        let page_range = PageRange::<ALIGN>::new(start, end)?;
        self.mirror.read().get_memory_permissions(page_range)
    }

    /// Confines a would-be guest-memory access to `view`'s own admitted, correctly-permissioned
    /// pages before any actual read/write/copy runs.
    ///
    /// `range` is the exact byte span the access touches (e.g. a pointer plus a type's size, or a
    /// slice's byte length). Returns a held [`domain::ViewAccessLease`] on success -- the caller
    /// must perform the real fallible access while holding it and drop it immediately afterward
    /// (never across a blocking wait).
    ///
    /// # Errors
    ///
    /// See [`GuestAccessError`].
    pub fn checked_guest_range(
        &self,
        view: VmViewId,
        range: Range<usize>,
        write: bool,
    ) -> Result<domain::ViewAccessLease<'_>, GuestAccessError> {
        if range.start >= range.end
            || range.start < Platform::TASK_ADDR_MIN
            || range.end > Platform::TASK_ADDR_MAX
        {
            return Err(GuestAccessError::OutOfAperture);
        }
        let lease = self
            .domain
            .acquire_access_lease(view)
            .map_err(GuestAccessError::Domain)?;
        let start_page = range.start & !(ALIGN - 1);
        let end_page = range
            .end
            .checked_add(ALIGN - 1)
            .ok_or(GuestAccessError::OutOfAperture)?
            & !(ALIGN - 1);
        let ptr = NonZeroAddress::<ALIGN>::new(start_page).ok_or(GuestAccessError::OutOfAperture)?;
        let len = NonZeroPageSize::<ALIGN>::new(end_page - start_page)
            .ok_or(GuestAccessError::OutOfAperture)?;
        let required = if write {
            MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE
        } else {
            MemoryRegionPermissions::READ
        };
        let perms = self.get_memory_permissions(ptr, len);
        if !perms.is_some_and(|p| p.contains(required)) {
            // A refusal for a page the view's own lineage still holds custody over means the
            // process-blind `Vmem` lost or re-flagged a mapping some live holder relies on --
            // the failure mode that spun a session daemon on `EFAULT` for a whole desktop boot.
            // Rate limited: such a spin refuses millions of times.
            static NOT_MAPPED_REFUSALS: core::sync::atomic::AtomicU64 =
                core::sync::atomic::AtomicU64::new(0);
            let n = NOT_MAPPED_REFUSALS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            if n < 256 || n % 100_000 == 0 {
                litebox_util_log::debug!(
                    n:? = n, view:? = view, start:? = range.start, end:? = range.end,
                    write:? = write, vmem_perms:? = perms,
                    custody:? = self.domain.custody_at_via_lineage(view, start_page);
                    "checked_guest_range: NotMapped refusal"
                );
            }
            return Err(GuestAccessError::NotMapped);
        }
        Ok(lease)
    }
}

/// If Backend also implements [`VmemPageFaultHandler`], it can handle page faults.
impl<Platform, const ALIGN: usize> PageManager<Platform, ALIGN>
where
    Platform: RawSyncPrimitivesProvider + PageManagementProvider<ALIGN>,
    Platform: VmemPageFaultHandler,
{
    /// Handle page fault at the given address.
    ///
    /// # Safety
    ///
    /// This should only be called from the kernel page fault handler.
    pub unsafe fn handle_page_fault(
        &self,
        fault_addr: usize,
        error_code: u64,
    ) -> Result<(), PageFaultError> {
        let result = (|| -> Result<(), PageFaultError> {
            unsafe { self.handle_page_fault_inner(fault_addr, error_code) }
        })();
        if result.is_ok() {
            Platform::record_guest_fault_serviced();
        }
        result
    }

    unsafe fn handle_page_fault_inner(
        &self,
        fault_addr: usize,
        error_code: u64,
    ) -> Result<(), PageFaultError> {
        let fault_addr = fault_addr & !(ALIGN - 1);
        if !(Platform::TASK_ADDR_MIN..Platform::TASK_ADDR_MAX).contains(&fault_addr) {
            return Err(PageFaultError::AccessError("Invalid address"));
        }

        let mut vmem = self.vmem_write();
        // Find the range closest to the fault address that the current guest access's own view
        // lineage actually has custody over, skipping any nearer VMA a family-blind lookup would
        // otherwise resolve to first but that belongs to an unrelated fork family. Real Linux
        // gives every process a fully independent address space, so an unrelated sibling's own
        // mapping is simply invisible at this address -- it must never be allowed to steal the
        // growsdown/no-mapping classification away from this view's own, genuinely-reachable
        // mapping above `fault_addr` (typically its own stack) merely because the two happen to
        // collide numerically in this process-global `Vmem`. Without this, a fault below the
        // caller's own `VM_GROWSDOWN` stack that happens to land inside (or exactly at the foot
        // of) a sibling's unrelated mapping resolves to that foreign VMA, the growsdown branch
        // below is skipped (the fault address is no longer strictly *below* the found range's
        // `start`), and the per-view custody gate refuses the caller's own legitimate stack
        // growth with a real `SIGSEGV` -- confirmed live, see
        // growsdown-fault-classification-cross-family-foreign-mapping-collision-confirmed-sigsegv.
        // This performs the identical `custody_at_via_lineage` probe the gate below performs
        // (same `fault_addr < r.start` choice of probe address, for the same reason: a
        // not-yet-resident growsdown region has nothing recorded at `fault_addr` itself, only at
        // its VMA's already-published `start`), just against each family-blind candidate in
        // address order instead of only the nearest one, so it never grants anything the gate
        // below would not independently also grant -- it only changes *which* VMA is considered
        // for classification, never who is allowed to fault it in. A platform with no
        // current-guest-access context (`current_guest_access` returning `None`) keeps today's
        // single-nearest-mapping lookup unchanged, exactly as the custody gate below already does
        // for that case.
        let (mapped_range, vma) = {
            let mut candidates = vmem.overlapping(fault_addr..Platform::TASK_ADDR_MAX);
            let found = if let Some((view, _task, _)) = Platform::current_guest_access() {
                candidates.find(|(r, _)| {
                    let probe = if fault_addr < r.start { r.start } else { fault_addr };
                    matches!(
                        self.domain.custody_at_via_lineage(view, probe),
                        domain::Custody::Present { .. } | domain::Custody::Retiring { .. }
                    )
                })
            } else {
                candidates.next()
            };
            let Some((r, vma)) = found else {
                return Err(PageFaultError::AccessError("no mapping"));
            };
            (r.clone(), *vma)
        };
        let start = mapped_range.start;

        // Per-view custody gate. `vmem` has no notion of family/view ownership: the VMA this
        // lookup just found may belong to a fork family entirely unrelated to the one currently
        // faulting (related, if at all, only through some distant common ancestor), left behind
        // by a sibling that mapped it privately and has since exited. Refuse as a real access
        // error unless the domain shows genuine custody for this view or one of its lineage
        // ancestors -- never service a fault merely because some VmArea with compatible flags
        // happens to sit at this address. `custody_at_via_lineage` returning anything other than
        // `Present`/`Retiring` (an unrelated family's own `Present`, or `Unclaimed` because no
        // family in this view's own ancestry ever published here) is exactly the case that
        // otherwise produced an unbounded fault-service loop instead of a real `SIGSEGV`. For the
        // `VM_GROWSDOWN` stack-growth branch below, the probed address is the found VMA's own
        // `start` (the already-published stack mapping being grown), not the not-yet-mapped
        // `fault_addr` itself -- growing a genuinely-owned stack must not be confused with an
        // unrelated family's adjacent growsdown region merely because both are geometrically
        // close. A platform with no current-guest-access context (`current_guest_access`
        // returning `None`) keeps today's behavior unchanged.
        if let Some((view, _task, _)) = Platform::current_guest_access() {
            let ownership_probe = if fault_addr < start { start } else { fault_addr };
            if !matches!(
                self.domain.custody_at_via_lineage(view, ownership_probe),
                domain::Custody::Present { .. } | domain::Custody::Retiring { .. }
            ) {
                return Err(PageFaultError::AccessError("no custody for this view's family"));
            }
        }

        if fault_addr < start {
            // address is out of range, test if it is next to a stack
            if !vma.flags().contains(VmFlags::VM_GROWSDOWN) {
                return Err(PageFaultError::AccessError("no mapping"));
            }
            if vmem.has_pending_initialization(&mapped_range) {
                return Err(PageFaultError::AllocationFailed);
            }

            if !vmem
                .overlapping(Platform::TASK_ADDR_MIN..fault_addr)
                .next_back()
                .is_none_or(|(prev_range, prev_vma)| {
                    // Enforce gap between stack and other preceding non-stack mappings.
                    // Either the previous mapping is also a stack mapping w/ some access flags
                    // or the previous mapping is far enough from the fault address
                    (prev_vma.flags().contains(VmFlags::VM_GROWSDOWN)
                        && !(prev_vma.flags() & VmFlags::VM_ACCESS_FLAGS).is_empty())
                        || fault_addr - prev_range.end >= Vmem::<Platform, ALIGN>::STACK_GUARD_GAP
                })
            {
                return Err(PageFaultError::AllocationFailed);
            }
            if let Some(rlimit) = Platform::current_guest_stack_rlimit()
                && mapped_range.end.saturating_sub(fault_addr) > rlimit
            {
                return Err(PageFaultError::AllocationFailed);
            }
            // Clamp the install range to the first genuinely-free prefix starting at
            // `fault_addr` instead of always spanning the WHOLE `[fault_addr, start)` gap in one
            // shot. A family-blind foreign VMA may sit anywhere in that gap -- it is exactly what
            // let the (now-fixed) custody-aware lookup above walk past a foreign candidate to
            // reach this view's own real growsdown VMA in the first place, so its real, live
            // content may still be sitting between `fault_addr` and `start`. Before this clamp,
            // ANY such foreign obstruction anywhere in a potentially enormous gap (this bug
            // pattern's own reproduction used a ~16 GiB gap) made the WHOLE install fail via
            // `vmas`'s own family-blind `NoReplace` overlap backstop below, even when
            // `fault_addr` itself was genuinely free -- see
            // growsdown-install-range-foreign-content-backstop-refusal-remainder. Installing only
            // up to the nearest obstruction mirrors real Linux's own incremental, on-demand stack
            // growth: a deeper fault later re-walks from its own (lower) `fault_addr` and
            // re-clamps against whatever is there then. `vmem` is still held here (dropped only
            // below), so this query sees the exact same snapshot the custody-aware lookup above
            // and the `NoReplace` backstop inside `insert_mapping` will also see. When no
            // obstruction exists in the gap at all, `install_end == start` and this is byte-for-
            // byte the prior single-shot behavior.
            let install_end = vmem
                .overlapping(fault_addr..start)
                .next()
                .map_or(start, |(obstruction, _)| obstruction.start);
            let Some(range) = PageRange::<ALIGN>::new(fault_addr, install_end) else {
                // The nearest obstruction sits at (or before) `fault_addr` itself: there is no
                // genuinely-free prefix at all to install. This happens when the address the
                // guest actually touched is itself inside foreign, family-blind content -- the
                // same fundamental cross-family VA collision the classification fix above cannot
                // resolve alone, since this process-global `Vmem` has only one shared, VA-keyed
                // backing store per address (full per-family VA partitioning is the explicitly
                // out-of-scope, already-accepted-elsewhere redesign, not attempted here). Refuse
                // cleanly -- never panic the host on a guest-controlled/guest-triggerable address
                // pattern like this one.
                return Err(PageFaultError::AllocationFailed);
            };
            // Route the mutation through the domain-mediated session protocol instead of a raw
            // `insert_mapping` call: no fault path may mutate topology outside a session, and no
            // fault path may panic the host on a guest-controlled condition (a full stack, or a
            // domain that has poisoned/quarantined/retired this view, are both guest-influenced,
            // not host bugs). `platform` is copied and `vmem`'s write guard dropped *before*
            // opening the session -- the same lock order the six syscall dispatch arms already
            // use (gate acquired outer, `vmem` write-lock taken inner, never the reverse) -- to
            // avoid an AB-BA deadlock against an in-flight mmap/mprotect/etc. session on another
            // thread. The real host effect is the mapping insert itself inside
            // `install_into_owned_hole`'s closure; `claim_hole`'s own `host_reserve` is a no-op,
            // since there is no separate host reservation step to take first.
            let platform = vmem.platform;
            drop(vmem);
            let grown: Result<(), ()> = (|| {
                let (view, task, _pm) = Platform::current_guest_access().ok_or(())?;
                let session = session::MemoryEffectSession::open(
                    platform.guest_va_domain(),
                    platform.effect_gate(),
                    view,
                    task,
                )
                .map_err(|_| ())?;
                let token = session
                    .claim_hole(range.start..range.end, |_| Ok(()))
                    .map_err(|_| ())?;
                let rollback_token = token.clone();
                let install_result = session.install_into_owned_hole(token, view, |r| {
                    let installed = PageRange::new(r.start, r.end).ok_or(())?;
                    let mut vmem = self.vmem_write();
                    unsafe {
                        vmem.insert_mapping(
                            installed,
                            vma,
                            false,
                            crate::platform::page_mgmt::FixedAddressBehavior::NoReplace,
                        )
                    }
                    .map(|_| ())
                    .map_err(|_| ())
                });
                let outcome = install_result.map(|_| ()).map_err(|_| ());
                if outcome.is_err() {
                    // An unreleased `Custody::Hole` would permanently wedge future growth at
                    // this address -- hand it back to `Unclaimed` so a later fault (or a real
                    // `mmap`) can claim it again.
                    let _ = session.release_hole(rollback_token, |_| Ok(()));
                }
                session.close();
                outcome
            })();
            if grown.is_err() {
                return Err(PageFaultError::AllocationFailed);
            }
            // Re-acquire: the non-growth branch below never dropped its own original guard, so
            // this reassignment (same binding, same guard type) only ever runs on the path that
            // actually dropped it above -- never a double-acquire of the same `RwLock` on this
            // thread.
            vmem = self.vmem_write();
        }

        if <Platform as VmemPageFaultHandler>::access_error(error_code, vma.flags()) {
            return Err(PageFaultError::AccessError("access error"));
        }

        unsafe {
            vmem.platform
                .handle_page_fault(fault_addr, vma.flags(), error_code)
        }
    }
}
