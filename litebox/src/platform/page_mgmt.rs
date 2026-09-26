// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Page-management related types and traits

use crate::platform::{RawConstPointer as _, RawMutPointer as _};

use super::RawPointerProvider;
use alloc::boxed::Box;
use core::ops::Range;
use thiserror::Error;

/// What [`PageManagementProvider::prepare_guest_access`] did for one host-side guest-memory
/// access.
#[derive(Debug, Default)]
pub struct GuestAccessPreparation {
    /// Every page-aligned address promoted into the view's own independent copy, for the caller
    /// to publish into the domain the way the fault path does.
    pub promoted: alloc::vec::Vec<usize>,
    /// The platform could not bring some page of the range into a state the access may use --
    /// for a write, one whose host target is the view's own page rather than an ancestor's or a
    /// shared origin's; for a read, one whose host target shows the view's own content. The
    /// caller must refuse the access (`EFAULT`) instead of performing it: performing it would
    /// write another address space's memory or read the wrong bytes.
    pub refused: bool,
}

/// One step of an acquisition or release of [`PageManager`](crate::mm::PageManager)'s own mapping
/// lock (its process-global `Vmem` reader-writer lock), reported to
/// [`PageManagementProvider::mapping_lock_event`] for diagnostics only. A `*Request` always
/// precedes the matching `*Acquired` on the same thread (the time between them is that
/// acquisition's wait), and every `*Acquired` is followed by exactly one `*Released`.
/// `MirrorReplay` (exclusive sections only) precedes the `WriteReleased` of a section that
/// changed the mapping table: the time between the two is the mirror refresh.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MappingLockEvent {
    /// A shared acquisition is about to be requested.
    ReadRequest,
    /// The shared acquisition requested last on this thread was granted.
    ReadAcquired,
    /// A shared acquisition is being released.
    ReadReleased,
    /// An exclusive acquisition is about to be requested.
    WriteRequest,
    /// The exclusive acquisition requested last on this thread was granted.
    WriteAcquired,
    /// The exclusive section is about to replay its mapping-table changes into the manager's
    /// mirror (it changed the table); its `WriteReleased` follows the replay.
    MirrorReplay,
    /// An exclusive acquisition is being released.
    WriteReleased,
}

bitflags::bitflags! {
    /// Permissions for a memory region
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct MemoryRegionPermissions: u8 {
        /// Readable
        const READ = 1 << 0;
        /// Writable
        const WRITE = 1 << 1;
        /// Executable
        const EXEC = 1 << 2;
        /// Sharable between processes
        const SHARED = 1 << 3;
    }
}

/// A provider for managing memory pages
///
/// NOTE: Due to insufficient support for associated constants in current Stable Rust, we have
/// `ALIGN` as a parameter. In the future, this may be changed to an associated constant, since each
/// platform has only one canonical alignment.
pub trait PageManagementProvider<const ALIGN: usize>: RawPointerProvider {
    /// The lower bound (inclusive) for virtual addresses that can be allocated for task memory.
    ///
    /// Note it must be aligned to `ALIGN`.
    const TASK_ADDR_MIN: usize;
    /// The upper bound (exclusive) for virtual addresses that can be allocated for task memory.
    ///
    /// Note it must be aligned to `ALIGN`.
    const TASK_ADDR_MAX: usize;

    /// Allocates new memory pages at the specified `suggested_range` with the given `initial_permissions`.
    ///
    /// # Parameters
    ///
    /// - `suggested_range`: A suggested address range for the allocation.
    /// - `initial_permissions`: The permissions to apply to the allocated memory region.
    /// - `can_grow_down`: If `true`, the region is allowed to grow downward (towards zero) upon
    ///   a page fault.
    /// - `populate_pages_immediately`: If `true`, the pages are populated immediately; otherwise,
    ///   they are populated lazily.
    /// - `fixed_address_behavior`: Specifies the required semantics of `suggested_range`.
    ///
    /// # Returns
    ///
    /// On success, returns a raw mutable pointer to the start of the allocated memory region.
    ///
    /// # Errors
    ///
    /// Returns an [`AllocationError`] if the allocation fails.
    fn allocate_pages(
        &self,
        suggested_range: Range<usize>,
        initial_permissions: MemoryRegionPermissions,
        can_grow_down: bool,
        populate_pages_immediately: bool,
        fixed_address_behavior: FixedAddressBehavior,
    ) -> Result<Self::RawMutPointer<u8>, AllocationError>;

    /// Allocates an alias of a stable shared backing object.
    ///
    /// Every call carrying the same `backing_identity` and overlapping
    /// `backing_offset` range must expose the same bytes immediately, even when
    /// the returned virtual addresses differ. Platforms without a native shared
    /// backing implementation retain the ordinary allocation behavior by
    /// default; their shims may still provide sharing through an address-space
    /// handoff, but simultaneous aliases will not be coherent until the platform
    /// overrides this method.
    #[expect(unused_variables, reason = "default body ignores backing metadata")]
    fn allocate_shared_pages(
        &self,
        backing_identity: usize,
        backing_offset: usize,
        suggested_range: Range<usize>,
        initial_permissions: MemoryRegionPermissions,
        can_grow_down: bool,
        populate_pages_immediately: bool,
        fixed_address_behavior: FixedAddressBehavior,
    ) -> Result<Self::RawMutPointer<u8>, AllocationError> {
        self.allocate_pages(
            suggested_range,
            initial_permissions,
            can_grow_down,
            populate_pages_immediately,
            fixed_address_behavior,
        )
    }

    /// Initializes portions of a shared backing object that have not been initialized before.
    ///
    /// `initialize` receives ranges relative to `backing_offset`; an implementation with a
    /// canonical shared-page store calls it only for gaps that have never been initialized. The
    /// callback runs while that store's initialization state is serialized, so two simultaneous
    /// first mappings cannot overwrite one another with stale file bytes. The default calls it for
    /// the complete range because a platform without canonical aliases allocates independent pages.
    fn initialize_shared_pages<E>(
        &self,
        backing_identity: usize,
        backing_offset: usize,
        length: usize,
        mut initialize: impl FnMut(Range<usize>) -> Result<(), E>,
    ) -> Result<(), E> {
        let _ = (backing_identity, backing_offset);
        initialize(0..length)
    }

    /// Overlays bytes currently held by a canonical shared backing onto `data`.
    ///
    /// Bytes for which the platform has no initialized canonical storage are left unchanged. The
    /// default is a no-op for platforms whose shared mappings are managed outside this provider.
    fn read_shared_pages(
        &self,
        backing_identity: usize,
        backing_offset: usize,
        data: &mut [u8],
    ) -> Result<(), SharedPageIoError> {
        let _ = (backing_identity, backing_offset, data);
        Ok(())
    }

    /// Propagates a file write into any canonical shared backing storage that already exists.
    ///
    /// A range that has never been mapped need not allocate storage; its eventual first mapping is
    /// initialized from the file itself. The default is a no-op.
    fn write_shared_pages(
        &self,
        backing_identity: usize,
        backing_offset: usize,
        data: &[u8],
    ) -> Result<(), SharedPageIoError> {
        let _ = (backing_identity, backing_offset, data);
        Ok(())
    }

    /// Zeroes any canonical shared storage intersecting `backing_range` after file truncation.
    ///
    /// This operates only on storage that already exists; future mappings obtain zero-filled bytes
    /// from the resized file. The default is a no-op.
    fn zero_shared_pages(
        &self,
        backing_identity: usize,
        backing_range: Range<usize>,
    ) -> Result<(), SharedPageIoError> {
        let _ = (backing_identity, backing_range);
        Ok(())
    }

    /// Releases the caller's pin on a stable shared backing object created via
    /// [`Self::allocate_shared_pages`]/[`Self::initialize_shared_pages`], once the filesystem
    /// object that owns `backing_identity` (a memfd, or a regular file some mapping resolved it
    /// for) has genuinely lost its last descriptor -- see the shim's own `Task::do_close`, the
    /// only correct caller, for what "genuinely lost its last descriptor" means across `dup`,
    /// `fork` and in-flight `SCM_RIGHTS` transfers.
    ///
    /// Pages a live mapping still covers survive this call regardless (an unpin only removes the
    /// floor that keeps a currently-*unmapped* page from being reclaimed early); the platform's
    /// own per-page mapping reference count frees the rest as each mapping is later torn down.
    /// Idempotent: releasing an identity with no pin outstanding (already released, or the
    /// platform never pinned it to begin with) is a no-op, not an error. The default no-ops for
    /// platforms without a canonical shared-backing registry, matching every sibling method here.
    #[expect(unused_variables, reason = "default body ignores backing metadata")]
    fn forget_shared_backing(&self, backing_identity: usize) -> Result<(), SharedPageIoError> {
        Ok(())
    }

    /// De-allocated all pages in the given `range`.
    ///
    /// # Safety
    ///
    /// The caller must ensure that these pages are not in active use.
    unsafe fn deallocate_pages(&self, range: Range<usize>) -> Result<(), DeallocationError>;

    /// Remap pages from `old_range` to `new_range`.
    ///
    /// ## Returns
    ///
    /// On success it returns a pointer to the new virtual memory area.
    ///
    /// # Safety
    ///
    /// The caller must ensure that it is safe to move the `old_range` (i.e., these pages are not in
    /// active use).
    ///
    /// The `new_range` must be larger than `old_range`, and must not overlap with `old_range`.
    ///
    /// Both ranges must be aligned to `ALIGN`.
    unsafe fn remap_pages(
        &self,
        old_range: Range<usize>,
        new_range: Range<usize>,
        permissions: MemoryRegionPermissions,
    ) -> Result<Self::RawMutPointer<u8>, RemapError> {
        debug_assert!(old_range.start.is_multiple_of(ALIGN));
        debug_assert!(new_range.start.is_multiple_of(ALIGN));
        debug_assert!(old_range.len().is_multiple_of(ALIGN));
        debug_assert!(new_range.len().is_multiple_of(ALIGN));
        debug_assert!(new_range.len() > old_range.len());
        debug_assert!(old_range.start.max(new_range.start) >= old_range.end.min(new_range.end));
        // Default implementation: allocate new pages, copy data, deallocate old pages
        let temp_permissions = permissions | MemoryRegionPermissions::WRITE;
        let new_ptr = self
            .allocate_pages(
                new_range.clone(),
                temp_permissions,
                false,
                true,
                FixedAddressBehavior::NoReplace,
            )
            .map_err(|e| match e {
                AllocationError::OutOfMemory => RemapError::OutOfMemory,
                AllocationError::AddressInUse | AllocationError::AddressInUseByPlatform => {
                    RemapError::AlreadyAllocated
                }
                AllocationError::Unaligned
                | AllocationError::BelowMinAddress
                | AllocationError::AboveMaxAddress
                | AllocationError::AddressPartiallyInUse => unreachable!(),
            })?;

        // Copy memory from old range to new range
        if !permissions.contains(MemoryRegionPermissions::READ) {
            (unsafe {
                self.update_permissions(
                    old_range.clone(),
                    permissions | MemoryRegionPermissions::READ,
                )
            })
            .expect("failed to update permissions on old range for copying");
        }
        // Copy in chunks of ALIGN bytes to handle very large memory regions
        let total_len = old_range.len();
        let mut offset = 0;
        while offset < total_len {
            let chunk_len = (total_len - offset).min(ALIGN);
            let old_ptr =
                <Self as RawPointerProvider>::RawConstPointer::from_usize(old_range.start + offset);
            new_ptr
                .write_slice_at_offset(
                    isize::try_from(offset).unwrap(),
                    &old_ptr.to_owned_slice(chunk_len).unwrap(),
                )
                .unwrap();
            offset += ALIGN;
        }

        if temp_permissions != permissions {
            (unsafe { self.update_permissions(new_range.clone(), permissions) })
                .expect("failed to restore permissions on new range");
        }

        (unsafe { self.deallocate_pages(old_range) }).expect("failed to deallocate old range");

        Ok(new_ptr)
    }

    /// Moves a stable shared backing alias while preserving its backing offset.
    ///
    /// Platforms that expose canonical shared pages override this so the destination aliases the
    /// same physical storage rather than receiving a private byte copy. Other platforms retain the
    /// ordinary remap behavior.
    unsafe fn remap_shared_pages(
        &self,
        backing_identity: usize,
        backing_offset: usize,
        old_range: Range<usize>,
        new_range: Range<usize>,
        permissions: MemoryRegionPermissions,
    ) -> Result<Self::RawMutPointer<u8>, RemapError> {
        let _ = (backing_identity, backing_offset);
        // SAFETY: this method has the same safety contract as `remap_pages` and forwards it.
        unsafe { self.remap_pages(old_range, new_range, permissions) }
    }

    /// Whether one [`Self::update_permissions`] call may span adjacent tracked
    /// mappings while retaining all-or-fail semantics.
    ///
    /// Returning `true` promises that `Err` means no part of the range changed,
    /// and that any failure after publication terminates rather than unwinds or
    /// returns. Providers whose native operation has reservation/backing
    /// boundaries must retain the default and receive one region at a time.
    fn has_transactional_permission_updates(&self) -> bool {
        false
    }

    /// Update the permissions on pages in `range` to `new_permissions`.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the permissions do not conflict with any currently active usage
    /// of these pages.
    unsafe fn update_permissions(
        &self,
        range: Range<usize>,
        new_permissions: MemoryRegionPermissions,
    ) -> Result<(), PermissionUpdateError>;

    /// Return reserved pages that are not available for allocation.
    ///
    /// Note that the returned ranges should be `ALIGN`-aligned.
    fn reserved_pages(&self) -> impl Iterator<Item = &Range<usize>>;

    /// Attempt to allocate pages with copy-on-write semantics backed by static data.
    ///
    /// This method allows platforms that support it to create CoW mappings instead of performing
    /// expensive page-by-page memory copies. This is particularly useful when mapping pre-loaded
    /// file data that was mmap'd by the host.
    ///
    /// The default implementation returns unsupported CoW. Platforms that DO support COW should
    /// override this method to unlock better performance.
    #[expect(unused_variables, reason = "default body, non-underscored param names")]
    fn try_allocate_cow_pages(
        &self,
        suggested_start: usize,
        source_data: &'static [u8],
        permissions: MemoryRegionPermissions,
        fixed_address_behavior: FixedAddressBehavior,
    ) -> Result<Self::RawMutPointer<u8>, CowAllocationError> {
        Err(CowAllocationError::UnsupportedByPlatform)
    }

    /// Captures a private (non-shared, non-file-backed) memory run's backing bytes into an opaque
    /// [`PrivateBackingLease`], addressed later by [`Self::restore_private_backing`] -- the
    /// "parked image" half of save-before-diverge for a memory run whose original mapping may be
    /// torn down entirely before the lease is ever consumed (unlike
    /// [`crate::mm::session::MemoryEffectSession`]'s divergence-save copiers, which act on a
    /// still-live mapping).
    ///
    /// The generic default is a real, always-correct owned byte snapshot (never a lossy or
    /// unsupported placeholder): every platform that does not override this with a zero-copy
    /// scheme still gets fully correct semantics, just without the copy-avoidance a platform with
    /// its own private-page reference-counting registry (e.g. HVF's `BackingRegistry`) can give.
    /// `mode` distinguishes a capture taken because a COW child is about to diverge
    /// ([`CaptureMode::ForkClone`]) from one that merely wants a second reference to the same run
    /// with no fork in progress ([`CaptureMode::Retain`]) -- a platform overriding this to bump a
    /// shared refcount instead of copying may use `mode` to decide how to charge that count; the
    /// default ignores it, since a byte copy is mode-independent.
    ///
    /// # Errors
    ///
    /// Returns [`CaptureBackingError`] if `range` is empty or its bytes cannot be read.
    fn capture_private_backing(
        &self,
        range: Range<usize>,
        mode: CaptureMode,
    ) -> Result<CapturedBackingRun, CaptureBackingError>
    where
        Self: Sized,
    {
        let _ = mode;
        if range.start >= range.end {
            return Err(CaptureBackingError::Unaligned);
        }
        let len = range.end - range.start;
        let ptr = <Self as RawPointerProvider>::RawConstPointer::<u8>::from_usize(range.start);
        let bytes = ptr.to_owned_slice(len).ok_or(CaptureBackingError::NotCapturable)?;
        let generation =
            crate::utils::ids::BackingGenerationId::next().ok_or(CaptureBackingError::NotCapturable)?;
        Ok(CapturedBackingRun {
            range,
            generation,
            lease: PrivateBackingLease::ByteSnapshot(bytes),
        })
    }

    /// Writes a lease captured by [`Self::capture_private_backing`] into `gva`, consuming it.
    ///
    /// Unlike [`Self::capture_private_backing`] (a self-contained read), this method assumes `gva`
    /// already addresses a real, writable mapping of the lease's own captured length -- installing
    /// that mapping (with real `Vmem`-level bookkeeping, not just a raw platform allocation this
    /// trait has no visibility into) is the caller's job; see
    /// [`crate::mm::PageManager::restore_private_backing`], the real entry point every caller
    /// outside this trait uses. The generic default is a plain write of the owned byte snapshot. A
    /// platform overriding this with its own private-page registry installs the retained backing
    /// directly instead.
    ///
    /// # Errors
    ///
    /// Returns [`RestoreBackingError::LengthMismatch`] if the lease is empty, or the write fails.
    fn restore_private_backing(
        &self,
        lease: PrivateBackingLease,
        gva: usize,
    ) -> Result<(), RestoreBackingError>
    where
        Self: Sized,
    {
        let PrivateBackingLease::ByteSnapshot(bytes) = lease;
        if bytes.is_empty() {
            return Err(RestoreBackingError::LengthMismatch);
        }
        let ptr = Self::RawMutPointer::<u8>::from_usize(gva);
        ptr.write_slice_at_offset(0, &bytes)
            .ok_or(RestoreBackingError::LengthMismatch)
    }

    /// Retains a second, independent reference to an already-captured lease -- an explicit,
    /// fallible operation (never a bare [`Clone`]), since a platform overriding this with a real
    /// reference-counted backing registry may need to refuse when that count is exhausted.
    ///
    /// The generic default duplicates the owned byte snapshot, which cannot fail.
    ///
    /// # Errors
    ///
    /// Returns [`RetainBackingError`] if the platform's own backing registry refuses (never for
    /// the generic default).
    fn retain_private_backing(
        &self,
        lease: &PrivateBackingLease,
    ) -> Result<PrivateBackingLease, RetainBackingError> {
        let PrivateBackingLease::ByteSnapshot(bytes) = lease;
        Ok(PrivateBackingLease::ByteSnapshot(bytes.clone()))
    }

    /// Toggle this thread's write access to code pages whose writability is
    /// gated *per thread* by the platform, on top of ordinary page permissions.
    ///
    /// Darwin's `MAP_JIT` is the motivating case: an executable mapping there
    /// is writable *or* executable per thread, never both at once, switched by
    /// `pthread_jit_write_protect_np`. Any code that writes into a mapping
    /// that is (or has ever been) executable — loading guest segments,
    /// patching syscall sites in place, writing trampoline stubs — must
    /// bracket the write between `jit_write_protect(false)` and
    /// `jit_write_protect(true)`, in addition to whatever `update_permissions`
    /// calls it makes. Platforms without per-thread code write protection keep
    /// this default no-op, so callers may bracket unconditionally.
    ///
    /// # Safety
    ///
    /// While write access is enabled (`executable == false`), no code may be
    /// executed from any per-thread-protected code mapping on this thread; the
    /// caller must restore `executable == true` before returning to any such
    /// code (including guest code).
    #[expect(unused_variables, reason = "default body, non-underscored param names")]
    unsafe fn jit_write_protect(&self, executable: bool) {}

    /// Returns the process-global [`GuestVaDomain`](crate::mm::domain::GuestVaDomain) for this
    /// platform, building it once on first use.
    ///
    /// The default lazily constructs it from this provider's own [`Self::TASK_ADDR_MIN`] /
    /// [`Self::TASK_ADDR_MAX`] aperture and [`Self::reserved_pages`] as the blocked spans, behind
    /// a function-local `spin::Once`. Rust monomorphizes a function-local `static` once per
    /// generic instantiation, so this gives exactly one domain per concrete `Self` -- which is
    /// genuinely process-global, since a real binary links exactly one concrete platform type.
    /// No implementor needs to override this.
    fn guest_va_domain(&self) -> &'static crate::mm::domain::GuestVaDomain {
        static DOMAIN: spin::Once<crate::mm::domain::GuestVaDomain> = spin::Once::new();
        DOMAIN.call_once(|| {
            let blocked = self
                .reserved_pages()
                .map(|range| crate::mm::domain::DomainBlocked(range.clone()))
                .collect();
            crate::mm::domain::GuestVaDomain::new(Self::TASK_ADDR_MIN..Self::TASK_ADDR_MAX, blocked)
        })
    }

    /// Returns the process-global [`EffectGate`](crate::mm::session::EffectGate) for this
    /// platform, building it once on first use.
    ///
    /// A function-local `static` cannot itself be typed over `Self` (unlike
    /// [`Self::guest_va_domain`]'s domain, which is a concrete, non-generic type), so this
    /// leaks one `EffectGate<Self>` behind a type-erased pointer slot instead -- sound under the
    /// same standing invariant [`Self::guest_va_domain`] already relies on: a real binary links
    /// exactly one concrete platform type, so this slot is only ever written and read back as
    /// that same `Self`.
    fn effect_gate(&self) -> &'static crate::mm::session::EffectGate<Self>
    where
        Self: crate::sync::RawSyncPrimitivesProvider + Sized,
    {
        static SLOT: spin::Once<usize> = spin::Once::new();
        let ptr = *SLOT.call_once(|| {
            let leaked = alloc::boxed::Box::leak(alloc::boxed::Box::new(
                crate::mm::session::EffectGate::<Self>::new(),
            ));
            core::ptr::from_mut(leaked) as usize
        });
        // SAFETY: `ptr` was produced above from a `Box::leak`ed `EffectGate<Self>`, giving it a
        // `'static` lifetime; the surrounding standing invariant guarantees every call to this
        // monomorphization reads it back as the same `Self` it was stored with.
        unsafe { &*(ptr as *const crate::mm::session::EffectGate<Self>) }
    }

    /// Returns the calling OS thread's current guest-memory-access context, if the platform
    /// populates one: the [`VmViewId`](crate::utils::ids::VmViewId) the calling guest task's
    /// userspace pointer accesses should be confined to, the
    /// [`TaskInstanceId`](crate::utils::ids::TaskInstanceId) of that same task (needed to open a
    /// [`MemoryEffectSession`](crate::mm::session::MemoryEffectSession), whose `EffectGate` is
    /// keyed by task for correct reentrant nesting), plus the
    /// [`PageManager`](crate::mm::PageManager) that admits it.
    ///
    /// Consulted by
    /// [`ViewConfinedAccess`](crate::platform::common_providers::userspace_pointers::ViewConfinedAccess)
    /// before every fallible userspace pointer access, in place of the no-op
    /// [`NoValidation`](crate::platform::common_providers::userspace_pointers::NoValidation), and
    /// by [`PageManager::handle_page_fault`](crate::mm::PageManager::handle_page_fault) to open a
    /// session before a stack-growth mutation. Returns `None` by default, which callers must
    /// treat as "no confinement in effect" -- every platform that does not call
    /// [`Self::set_current_guest_access`] gets this default and needs no change.
    fn current_guest_access() -> Option<(
        crate::utils::ids::VmViewId,
        crate::utils::ids::TaskInstanceId,
        &'static crate::mm::PageManager<Self, ALIGN>,
    )>
    where
        Self: crate::sync::RawSyncPrimitivesProvider + Sized,
    {
        None
    }

    /// Sets (or clears, with `None`) the calling OS thread's guest-memory-access context read
    /// back by [`Self::current_guest_access`]. Intended to be called by a shim's syscall-dispatch
    /// entry point, once per dispatched syscall, before any guest-memory access. The default is a
    /// no-op, matching [`Self::current_guest_access`]'s default of always returning `None`.
    #[expect(unused_variables, reason = "default body, non-underscored param name")]
    fn set_current_guest_access(
        context: Option<(
            crate::utils::ids::VmViewId,
            crate::utils::ids::TaskInstanceId,
            &'static crate::mm::PageManager<Self, ALIGN>,
        )>,
    ) where
        Self: crate::sync::RawSyncPrimitivesProvider + Sized,
    {
    }

    /// Resolves whether a host-pointer dereference of `page` (already page-aligned) under `view`
    /// should be redirected to a different host address to see that view's own, possibly
    /// per-view-diverged content, instead of the platform's ordinary GVA-is-the-host-address
    /// mapping. `None` -- "no redirect, `page` is its own correct host address" -- is exact for
    /// every page on every platform that never diverges per-view memory at all, and for every
    /// page on every platform before any such divergence exists; the default below matches both.
    ///
    /// Consulted by
    /// [`ViewConfinedAccess`](crate::platform::common_providers::userspace_pointers::ViewConfinedAccess)
    /// after its own [`Self::current_guest_access`]-driven logical-permission check already
    /// succeeds -- this performs no permission check of its own, only a physical-address
    /// translation for an access already known to be legitimate.
    #[expect(unused_variables, reason = "default body, non-underscored param names")]
    fn resolve_promoted_host_page(view: crate::utils::ids::VmViewId, page: usize) -> Option<usize> {
        None
    }

    /// [`Self::resolve_promoted_host_page`] for every page of `first_page..=last_page` (both
    /// page-aligned), appended to `out` in address order -- one call for a multi-page access, so
    /// a platform can answer the whole range from one snapshot of its own state instead of
    /// locking it once per page. The default is exactly that per-page loop.
    fn resolve_promoted_host_pages(
        view: crate::utils::ids::VmViewId,
        first_page: usize,
        last_page: usize,
        out: &mut alloc::vec::Vec<Option<usize>>,
    ) {
        let mut page = first_page;
        while page <= last_page {
            out.push(Self::resolve_promoted_host_page(view, page));
            match page.checked_add(ALIGN) {
                Some(next) => page = next,
                None => break,
            }
        }
    }

    /// Cheap process-wide fast path for [`Self::resolve_promoted_host_page`]: `false` means no
    /// page, for any view, has ever been redirected, so a caller may skip consulting
    /// [`Self::resolve_promoted_host_page`] (and, for a multi-page range, the per-page loop that
    /// would otherwise be needed) entirely. The default matches
    /// [`Self::resolve_promoted_host_page`]'s own default of never redirecting.
    fn any_host_redirect_active() -> bool {
        false
    }

    /// Called by
    /// [`ViewConfinedAccess`](crate::platform::common_providers::userspace_pointers::ViewConfinedAccess)
    /// immediately before a host-side access (`write` says which direction) to `view`'s guest
    /// memory at `range`, after that access has already passed the logical-permission check. A
    /// host-side copy never takes the guest's own translation or permission fault, so a platform
    /// whose fork-COW mechanism relies on those faults must apply it here explicitly: resolve a
    /// forking ancestor's own transiently write-protected pages in `range` (else the copy fails
    /// outright), and materialize a fork child's lineage-inherited pages exactly as the child's
    /// own guest fault would (else the copy reaches whatever the ancestor currently holds at
    /// that address). `ancestor_of` resolves, for one page-aligned address, the view whose
    /// custody the page currently falls under by lineage (`None` when no view holds it).
    /// Reports every page-aligned address this call promoted into `view`'s own independent copy,
    /// so the caller can publish that divergence into the domain the way the fault path does,
    /// and whether the access must be refused (see [`GuestAccessPreparation::refused`]).
    /// The default is a no-op that promotes nothing and refuses nothing: a platform with no
    /// fork-COW faults has nothing to resolve.
    #[expect(unused_variables, reason = "default body, non-underscored param names")]
    fn prepare_guest_access(
        view: crate::utils::ids::VmViewId,
        range: core::ops::Range<usize>,
        write: bool,
        ancestor_of: &dyn Fn(usize) -> Option<crate::utils::ids::VmViewId>,
    ) -> GuestAccessPreparation {
        GuestAccessPreparation::default()
    }

    /// A fork child's `mprotect` of memory it holds only by lineage: applies `permissions` to
    /// `range` in `view`'s own independent address space, first giving every page there that
    /// `view` does not yet own outright (one it has never touched, a COW read alias, a promoted
    /// copy) its own independent page -- so the change is `view`'s alone, exactly as Linux flips
    /// only the child's own VMA. `ancestor_of` resolves, for one page-aligned address, the view
    /// whose content the page currently inherits by lineage (`None` when no view holds it).
    /// Unsupported by default: a platform with no per-view address spaces has no lineage-held
    /// memory to materialize, and reports the range as unallocated.
    #[expect(unused_variables, reason = "default body, non-underscored param names")]
    fn materialize_inherited_range(
        view: crate::utils::ids::VmViewId,
        range: core::ops::Range<usize>,
        permissions: MemoryRegionPermissions,
        ancestor_of: &dyn Fn(usize) -> Option<crate::utils::ids::VmViewId>,
    ) -> Result<(), PermissionUpdateError> {
        Err(PermissionUpdateError::Unallocated)
    }

    /// Whether `view` already has its own independent, per-view host address space on this
    /// platform, distinct from every other view, rather than sharing one flat host address
    /// space with every other view. `false` by default: a platform with no per-view address
    /// spaces has none to report, so every caller gating a legacy whole-address-space-shared
    /// mechanism on this keeps running exactly as it always has.
    #[expect(unused_variables, reason = "default body, non-underscored param name")]
    fn has_independent_view_space(view: crate::utils::ids::VmViewId) -> bool {
        false
    }

    /// Releases `view`'s own independent, per-view host address space, if
    /// [`Self::has_independent_view_space`] ever reported one for it, now that `view` is
    /// permanently retired at the domain level and will never again be resolved for any live
    /// task. The default is a no-op, matching [`Self::has_independent_view_space`]'s default of
    /// never reporting one.
    ///
    /// A platform that does report per-view address spaces may defer the actual physical reclaim
    /// past this call -- this is a hint that `view` is now safe to reclaim once the platform's own
    /// remaining preconditions clear, not a demand that reclaim happen synchronously here. Intended
    /// to be called once, right after a task's last thread permanently retires `view` at the
    /// domain level (see `GuestVaDomain::unregister_view`).
    ///
    /// `domain` is the same domain `view` was just retired/unregistered from, passed explicitly so
    /// an implementor whose own reclaim is deferred past this call can keep asking family-lineage
    /// questions about OTHER, still-live views on a later retry. `family` is `view`'s own
    /// [`crate::mm::domain::GuestVaDomain::family_of_view`], resolved by the caller before it
    /// unregistered `view` -- `view` itself is no longer resolvable in `domain` by the time this
    /// is called (`GuestVaDomain::unregister_view` already ran), so a deferred implementor must
    /// carry this value forward across its own retries rather than re-deriving it from `view`.
    #[expect(unused_variables, reason = "default body, non-underscored param names")]
    fn release_view_space(
        view: crate::utils::ids::VmViewId,
        family: Option<crate::utils::ids::FamilyId>,
        domain: &crate::mm::domain::GuestVaDomain,
    ) {
    }

    /// Forces `child_view`'s own per-view space to hold a real, independent, already-diverged
    /// copy of `range` (page-aligned) -- decoupled from `ancestor_view`'s own live physical
    /// pages -- *before* `child_view`'s task is released to run concurrently with the still-live
    /// `ancestor_view` task that forked it.
    ///
    /// Exists to close a fork-time race that [`Self::has_independent_view_space`]'s own lazy,
    /// fault-driven COW materialization otherwise leaves open: nothing marks `ancestor_view`'s own
    /// claimed pages read-only at fork time (unlike real Linux's `copy_page_range`), so
    /// `ancestor_view`'s task keeps running with full read/write access to them after the fork.
    /// A child page nobody has eagerly diverged is materialized lazily, on the child's own first
    /// touch (see `try_resolve_cow_fault`'s "install a read alias, then promote on write" pair) --
    /// reading straight through to whatever `ancestor_view`'s live physical page holds *at that
    /// later moment*, not a true point-in-time snapshot as of the fork. If `ancestor_view`'s own
    /// continued execution writes to that same page first (entirely possible: the child's own OS
    /// thread starts running concurrently with the parent's from the moment this fork releases it,
    /// and a real, complex forking parent keeps running plenty of its own code -- job-control
    /// bookkeeping, more function calls reusing the same stack slots -- immediately after the
    /// fork returns), the child observes the parent's *post-fork* write instead of the correct
    /// fork-instant content. Confirmed live as the root cause of a real, deterministic guest
    /// crash: a forked shell's own callee-saved register spill slot, a few hundred bytes below its
    /// stack pointer at the fork syscall, read back a small garbage value instead of the real
    /// pointer saved there, because the still-live parent reused that exact stack slot for
    /// something else before the child's own first (lazy) read fault on it.
    ///
    /// This call closes the race only for `range`, by eagerly performing the same
    /// alias-then-promote sequence a real fault would (see [`Self::has_independent_view_space`]'s
    /// own platform-specific fault classifier), synchronously, before either side can race further
    /// -- not by write-protecting `ancestor_view`'s own pages, which would close it for the whole
    /// address space (matching real Linux) but needs `ancestor_view`'s own task to gain a new,
    /// symmetric divergence-on-write path of its own; that is intentionally out of scope here. A
    /// page `range` names that `ancestor_view` has nothing claimed at (unmapped, or already
    /// independently owned by `child_view`) is silently skipped, not an error -- this call is a
    /// best-effort narrowing of the race window, never a claim that every named page was mapped.
    ///
    /// The default is a no-op, matching [`Self::has_independent_view_space`]'s default of `false`:
    /// a platform with no per-view address spaces has no such lazily-materialized alias to race.
    #[expect(unused_variables, reason = "default body, non-underscored param names")]
    fn eagerly_diverge_fork_child_range(
        child_view: crate::utils::ids::VmViewId,
        ancestor_view: crate::utils::ids::VmViewId,
        range: core::ops::Range<usize>,
    ) {
    }

    /// General fork-time write-protection, closing the SAME lazy-COW race
    /// [`Self::eagerly_diverge_fork_child_range`] only narrows to a bounded stack window: marks
    /// every currently-writable, privately-owned page of `range` (one piece of the forking
    /// ancestor's own full `owned_ranges`, not just its stack) write-protected in
    /// `ancestor_view`'s own live address space, so `ancestor_view`'s task's own NEXT write to any
    /// of them takes a permission fault this platform's own fault classifier routes to a fresh,
    /// independent divergence -- instead of silently overwriting content a live, not-yet-diverged
    /// child might still need to lazily materialize later, which is exactly the race
    /// `eagerly_diverge_fork_child_range`'s own doc comment already describes in full, just for
    /// the whole address space here rather than one bounded window. Also stamps `child_view`'s own
    /// fork-lineage origin (which ancestor, and at what point in its own self-divergence history)
    /// so a later fault-path lookup against a page `ancestor_view` self-diverges after this fork
    /// can resolve the exact generation live as of this fork instant.
    ///
    /// Best-effort per page, matching [`Self::eagerly_diverge_fork_child_range`]'s own established
    /// "not a claim every named page is mapped" precedent: a page with nothing currently claimed,
    /// already read-only, shared (`MAP_SHARED`, which must keep reflecting the ancestor's own live
    /// writes across the fork exactly like real Linux `copy_page_range` never COW-protects one
    /// either), or momentarily lease-busy (a concurrent host-pointer alias on a same-view OS
    /// thread) is silently skipped -- this call never aborts or fails the fork.
    ///
    /// Kept alongside, never replacing, [`Self::eagerly_diverge_fork_child_range`]: that narrower,
    /// already-verified mitigation stays load-bearing (and is deliberately left wired) regardless
    /// of this general fix landing -- see that method's own call site for why.
    ///
    /// The default is a no-op, matching [`Self::has_independent_view_space`]'s default of `false`:
    /// a platform with no per-view address spaces has no such lazily-materialized alias to race.
    #[expect(unused_variables, reason = "default body, non-underscored param names")]
    fn fork_time_ancestor_protect(
        child_view: crate::utils::ids::VmViewId,
        ancestor_view: crate::utils::ids::VmViewId,
        range: core::ops::Range<usize>,
    ) {
    }

    /// `execve` is replacing `view`'s whole image: releases every private file mapping the
    /// platform serves as a window onto a shared read-only origin (its window records and
    /// origin aliases, regardless of which family's custody the range is under -- such state
    /// resolves only to immutable file bytes, never to another family's private content), so a
    /// stale window can never survive into the new image. `keep_for_descendant` is the caller's
    /// own exec-aware finding that a live descendant still inherits `view`'s pages by lineage,
    /// in which case the private copies `view` made inside those windows before this exec are
    /// retained for that descendant instead of freed. Called right after
    /// `GuestVaDomain::mark_family_exec` and before the old image's own-custody release. The
    /// default is a no-op: a platform without shared file origins has nothing to sever.
    #[expect(unused_variables, reason = "default body, non-underscored param names")]
    fn exec_sever_file_windows(view: crate::utils::ids::VmViewId, keep_for_descendant: bool) {}

    /// A host-side guest-memory access was served as more than one host-contiguous run (its
    /// pages redirect by different offsets -- see `ViewConfinedAccess::access_runs`). The
    /// default is a no-op; a platform with a counters readout overrides it.
    fn record_host_access_multi_run() {}

    /// A host-side guest-memory access split into runs failed on one of them after every run
    /// had been validated (expected never; a platform's own diagnostics counter). No-op by
    /// default.
    fn record_host_access_efault_after_runs() {}

    /// Diagnostics only: one [`MappingLockEvent`] of [`PageManager`](crate::mm::PageManager)'s
    /// own mapping lock on the calling thread, with the source location of the `PageManager`
    /// code that takes it (`site`), so a platform can time lock waits and holds and name the
    /// holder a stalled thread waited behind. Must not take the mapping lock itself, block, or
    /// call back into the page manager. No-op by default.
    #[expect(unused_variables, reason = "default body, non-underscored param names")]
    #[inline]
    fn mapping_lock_event(event: MappingLockEvent, site: &'static core::panic::Location<'static>) {}

    /// Whether the opt-in guest-access fault trace is on (`LITEBOX_GUEST_ACCESS_FAULT_TRACE=1`
    /// on platforms that read it): a host-side guest-memory access that faults after
    /// [`Self::prepare_guest_access`] approved it then logs the fault, the page state
    /// ([`Self::describe_guest_page`]) and every retry at `warn` level. `false` by default and
    /// expected to be cached by an implementor, so the untraced path costs one load.
    fn guest_access_fault_trace() -> bool {
        false
    }

    /// A process-wide counter that advances every time [`Self::fork_time_ancestor_protect`]
    /// write-protects a range, so a host-side access can tell whether a fork stripped pages
    /// between its own [`Self::prepare_guest_access`] and the copy that then faulted. `0`
    /// forever on a platform with no fork-time protection.
    fn fork_generation() -> u64 {
        0
    }

    /// Everything the platform knows about `page` (page-aligned) under `view`, for the guest-
    /// access fault trace: fork-COW alias/promotion state, fork-time write protection, W^X
    /// registration, resource usage. Empty by default.
    #[expect(unused_variables, reason = "default body, non-underscored param names")]
    fn describe_guest_page(
        view: crate::utils::ids::VmViewId,
        page: usize,
    ) -> alloc::string::String {
        alloc::string::String::new()
    }

    /// Returns the calling OS thread's current guest task's `RLIMIT_STACK` current limit, in
    /// bytes, if the platform tracks one for this thread. `None` means "no limit known to the
    /// platform" and must be treated as unlimited (never as zero).
    ///
    /// This is a plain opaque byte ceiling for a growsdown stack's total size -- litebox core
    /// never learns the concept "RLIMIT_STACK", only "a growth ceiling in bytes for this thread's
    /// stack, if any". Consulted by
    /// [`PageManager::handle_page_fault`](crate::mm::PageManager::handle_page_fault) to refuse a
    /// stack-growth fault that would grow the stack past the guest's own configured limit.
    fn current_guest_stack_rlimit() -> Option<usize> {
        None
    }

    /// Sets (or clears, with `None`) the calling OS thread's current guest task's
    /// `RLIMIT_STACK` current limit in bytes, read back by
    /// [`Self::current_guest_stack_rlimit`]. Intended to be called alongside
    /// [`Self::set_current_guest_access`] on every shim entry. The default is a no-op.
    #[expect(unused_variables, reason = "default body, non-underscored param name")]
    fn set_current_guest_stack_rlimit(rlimit_bytes: Option<usize>) {}

    /// Records that a guest page fault was resolved with no guest-visible signal -- stack
    /// growth, lazy materialization, COW-split, overlay-wait, or page-table repopulation, i.e.
    /// [`PageManager::handle_page_fault`](crate::mm::PageManager::handle_page_fault) returning
    /// `Ok(())`. The default is a no-op; a platform that wants this in its own hardware-exception
    /// counter taxonomy overrides it.
    fn record_guest_fault_serviced() {}

    /// Records that a guest page fault resulted in a real delivered signal (a `SIGSEGV` handed
    /// back to the guest, never absorbed host-side) for `task`. The default is a no-op.
    #[expect(unused_variables, reason = "default body, non-underscored param name")]
    fn record_guest_fault_delivered(task: crate::utils::ids::TaskInstanceId) {}

    /// Commits a W^X custody flip against this platform's own process-global backend (e.g. HVF's
    /// per-page real-permission toggle), after [`PageManager::commit_wx_flip`] has already
    /// revalidated the requested page's [`GuestVaDomain`](crate::mm::domain::GuestVaDomain)
    /// custody. Like [`Self::current_guest_access`], this is a process-global backend, not an
    /// instance field -- there is exactly one concrete platform backend per real binary.
    ///
    /// # Safety
    ///
    /// The caller must ensure `page` is not concurrently subject to a conflicting mutation the
    /// domain has not itself serialized against.
    ///
    /// The default is a no-op fallback for platforms without W^X toggling, consistent with
    /// [`Self::jit_write_protect`]'s default no-op.
    #[expect(unused_variables, reason = "default body, non-underscored param names")]
    unsafe fn commit_wx_flip(
        page: usize,
        want_execute: bool,
        expected_generation: u64,
    ) -> crate::shim::WxFlipOutcome
    where
        Self: Sized,
    {
        crate::shim::WxFlipOutcome::HostFailure
    }
}

/// Behavior when allocating pages at a fixed address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FixedAddressBehavior {
    /// The address is just a hint, and the platform may choose a different
    /// address if the hint is not available.
    Hint,
    /// Allocate the pages at the specified address, replacing any existing
    /// mappings.
    Replace,
    /// Allocate the pages at the specified address, failing if any part of the
    /// range is already in use.
    NoReplace,
}

/// Possible errors for [`PageManagementProvider::allocate_pages`]
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum AllocationError {
    #[error("provided range is not page-aligned")]
    Unaligned,
    #[error("provided address is below the minimum allowed address")]
    BelowMinAddress,
    #[error("provided address is above the maximum allowed address")]
    AboveMaxAddress,
    #[error("out of memory")]
    OutOfMemory,
    #[error("provided fixed address range is in use")]
    AddressInUse,
    #[error("provided fixed address range is in use by the platform")]
    AddressInUseByPlatform,
    #[error("provided fixed address range partially overlaps existing mappings")]
    AddressPartiallyInUse,
}

/// Possible errors for [`PageManagementProvider::deallocate_pages`]
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum DeallocationError {
    #[error("provided range is not page-aligned")]
    Unaligned,
    #[error("provided range contains unallocated pages")]
    AlreadyUnallocated,
}

/// Possible errors for [`PageManagementProvider::remap_pages`]
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum RemapError {
    #[error("at least one of the provided ranges was not page-aligned")]
    Unaligned,
    #[error("provided old range contains unallocated pages")]
    AlreadyUnallocated,
    #[error("provided ranges were overlapping")]
    Overlapping,
    #[error("provided new range is already allocated")]
    AlreadyAllocated,
    #[error("out of memory")]
    OutOfMemory,
}

/// Possible errors for [`PageManagementProvider::update_permissions`]
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum PermissionUpdateError {
    #[error("provided range is not page-aligned")]
    Unaligned,
    #[error("provided range contains unallocated pages")]
    Unallocated,
}

/// Failure while synchronizing a canonical shared backing with file-descriptor I/O.
#[derive(Error, Debug)]
pub enum SharedPageIoError {
    #[error("shared backing range overflow")]
    OutOfRange,
    #[error("host shared backing I/O failed")]
    Io,
}

/// Whether a [`PageManagementProvider::capture_private_backing`] call is claiming a run because a
/// COW child is about to diverge, or merely retaining a second reference with no fork in
/// progress. See that method's own doc comment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CaptureMode {
    /// The capture is being taken because a COW child's address space is about to diverge from
    /// this run (a fork).
    ForkClone,
    /// The capture is a plain retain: a second reference to the same run, no fork involved.
    Retain,
}

/// A real, opaque handle to a private (non-shared, non-file-backed) memory run's backing bytes.
/// See [`PageManagementProvider::capture_private_backing`].
#[derive(Clone)]
pub enum PrivateBackingLease {
    /// An owned copy of the captured range's bytes, restored by allocate + write. The generic,
    /// always-correct default every platform gets unless it overrides the three
    /// capture/restore/retain methods with its own zero-copy scheme.
    ByteSnapshot(Box<[u8]>),
}

impl PrivateBackingLease {
    /// The byte length this lease will occupy once restored -- the exact length a caller (e.g.
    /// [`crate::mm::PageManager::restore_private_backing`]) must install a destination mapping
    /// for before writing this lease into it.
    #[must_use]
    pub fn len(&self) -> usize {
        match self {
            Self::ByteSnapshot(bytes) => bytes.len(),
        }
    }

    /// Whether this lease is empty (zero-length).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// One captured private-backing run, returned by
/// [`PageManagementProvider::capture_private_backing`].
pub struct CapturedBackingRun {
    /// The address range this run was captured from.
    pub range: Range<usize>,
    /// This run's own captured-generation identity.
    pub generation: crate::utils::ids::BackingGenerationId,
    /// The lease that can later restore this run's bytes, at the same or a different address.
    pub lease: PrivateBackingLease,
}

/// Possible errors for [`PageManagementProvider::capture_private_backing`]
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum CaptureBackingError {
    #[error("provided range is empty")]
    Unaligned,
    #[error("provided range's bytes could not be read (unallocated, or not privately backed)")]
    NotCapturable,
}

/// Possible errors for [`PageManagementProvider::restore_private_backing`]
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum RestoreBackingError {
    #[error("the lease's captured length does not match the requested destination")]
    LengthMismatch,
    #[error("the destination range is already in use")]
    AddressInUse,
}

/// Possible errors for [`PageManagementProvider::retain_private_backing`]
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum RetainBackingError {
    #[error("the platform's own backing registry refused this retain")]
    Refused,
}

/// Possible errors for [`PageManagementProvider::try_allocate_cow_pages`]
///
/// ```text
///  ____________________
/// ( Maybe the grass is )
/// ( greener on the     )
/// ( other side?        )
///  --------------------
///         o   ^__^
///          o  (oo)\_______
///             (__)\       )\/\
///                 ||----w |
///                 ||     ||
/// ```
#[derive(Error, Debug)]
pub enum CowAllocationError {
    #[error("copy-on-write page allocation is not supported for this particular platform")]
    UnsupportedByPlatform,
    #[error("source region is not copy-on-writable")]
    UnsupportedSourceRegion,
    #[error("unaligned request")]
    Unaligned,
    #[error("internal failure in creating CoW pages")]
    InternalFailure,
}
