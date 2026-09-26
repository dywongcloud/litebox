// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Userspace Pointer Abstraction with Fallible Memory Access
//!
//! This module implements fallible userspace pointers that can safely handle invalid
//! memory accesses from userspace. The pointers use fallible memory access routines
//! internally, which relies on an exception table mechanism to recover from memory
//! faults.
//!
//! ## Exception Handling Mechanism
//!
//! **IMPORTANT**: For these pointers to behave as truly fallible (returning `None`
//! on invalid access), the platform **must** implement and register appropriate
//! exception handlers. Without proper exception handling setup, invalid memory
//! accesses will still crash the program.
//!
//! When accessing userspace memory through these pointers:
//!
//! 1. **With Exception Handling** (Required for fallible behavior): The platform
//!    must set up exception handlers (e.g., SIGSEGV signal handlers on Linux userland)
//!    that can catch memory access failures such as page faults or segmentation violations.
//!    The handler must use [`crate::mm::exception_table::search_exception_tables`] to
//!    look up the faulting instruction and redirect execution to a recovery point,
//!    allowing the operation to return `None` gracefully instead of crashing.
//!
//! 2. **Without Exception Handling** (Fallback behavior): If no exception handlers
//!    are configured, these pointers behave like slightly more expensive
//!    [`crate::platform::trivial_providers::TransparentConstPtr`] and
//!    [`crate::platform::trivial_providers::TransparentMutPtr`]. Invalid memory
//!    accesses will still cause the program to crash (e.g., with SIGSEGV), but
//!    with the additional overhead of the fallible copy mechanism.

use crate::mm::exception_table::{Fault, memcpy_fallible};
use crate::platform::{RawConstPointer, RawMutPointer};
use zerocopy::{FromBytes, IntoBytes};

/// How many times a fallible access [`ValidateAccess`] approved may fault before it is given
/// up as `None`: every retry re-validates the pointer first, which re-runs whatever page
/// preparation the validator performs (see [`ValidateAccess::retry_after_fault`]).
const ACCESS_FAULT_ATTEMPTS: u32 = 3;

/// Trait to validate that a pointer is a userspace pointer and temporarily enable
/// kernel-mode access to it.
///
/// Succeeding these operations does not guarantee that the pointer is valid to
/// access, just that it is in the userspace address range and won't be used to
/// access kernel memory.
///
/// Platforms may provide a security feature to prevent the kernel from accessing
/// userspace memory, such as x86_64's Supervisor Mode Access Prevention (SMAP) or
/// Arm's Privileged Access Never (PAN). This trait provides an interface to
/// temporarily disable such protections around supervisor-mode access to the
/// userspace pointer.
pub trait ValidateAccess {
    /// Validate that the given pointer is a valid userspace pointer.
    ///
    /// Returns `Some(ptr)` if valid. If the pointer is not valid, returns
    /// `None` or `Some(invalid)` where `invalid` is adjusted to a valid
    /// userspace address but will deterministically cause a fault on
    /// access.
    fn validate<T>(ptr: *mut T) -> Option<*mut T>;
    /// Validate that the given slice pointer is a valid userspace pointer.
    ///
    /// Returns as in `validate`. Note that only the starting pointer is
    /// returned.
    fn validate_slice<T>(ptr: *mut [T]) -> Option<*mut T>;

    /// Like [`Self::validate`], but for an access that will write through the pointer.
    ///
    /// The default treats it identically to [`Self::validate`]. Implementations whose
    /// confinement distinguishes read from write permission (e.g. requiring the target page be
    /// mapped writable) should override this instead of `validate`, since `validate` is also used
    /// on the read path.
    fn validate_for_write<T>(ptr: *mut T) -> Option<*mut T> {
        Self::validate(ptr)
    }

    /// Like [`Self::validate_slice`], but for an access that will write through the pointer. See
    /// [`Self::validate_for_write`].
    fn validate_slice_for_write<T>(ptr: *mut [T]) -> Option<*mut T> {
        Self::validate_slice(ptr)
    }

    /// Execute `f` while temporarily allowing supervisor-mode access to userspace
    /// memory.
    ///
    /// Platforms with hardware protections such as SMAP or PAN should override this
    /// to disable the protection before calling `f` and re-enable it afterwards.
    /// The default implementation simply calls `f()`, which is appropriate for
    /// platforms without such protection.
    #[inline]
    fn with_user_memory_access<R>(f: impl FnOnce() -> R) -> R {
        f()
    }

    /// The generation counter a validator's page preparation is keyed by (see
    /// [`crate::platform::PageManagementProvider::fork_generation`]), read once before an
    /// access and handed back to [`Self::retry_after_fault`] so a fault can be attributed to
    /// something that changed in between. `0` for a validator with no such notion.
    #[inline]
    fn access_generation() -> u64 {
        0
    }

    /// Called after a fallible access through a pointer `validate*` approved faulted anyway
    /// (`attempt` counts this and every earlier fault of the same access, starting at 1;
    /// `generation` is what [`Self::access_generation`] answered before the access). Returns
    /// whether the caller should validate the pointer again -- re-running whatever page
    /// preparation the validator performs -- and retry the access, or give up as `None`. The
    /// default never retries, which is exactly the pre-existing behavior of every validator
    /// that performs no preparation.
    #[expect(unused_variables, reason = "default body, non-underscored param names")]
    fn retry_after_fault(addr: usize, size: usize, write: bool, attempt: u32, generation: u64) -> bool {
        false
    }

    /// Runs one bulk access over `addr..addr + size` as one or more host-contiguous runs: `f`
    /// receives, in address order, each run's validated host pointer, its byte offset inside the
    /// access and its length, and the whole access fails closed (`None`) on the first run the
    /// validator refuses or that still faults after its retries. The default is a single run
    /// through [`Self::validate_slice`]/[`Self::validate_slice_for_write`] -- byte-identical to
    /// the one-pointer access every bulk copy used to be. A validator whose confinement can
    /// redirect individual pages to different host addresses overrides it to split the access
    /// at every redirect boundary (see [`ViewConfinedAccess`]).
    fn access_runs(
        addr: usize,
        size: usize,
        write: bool,
        f: &mut dyn FnMut(*mut u8, usize, usize) -> Result<(), Fault>,
    ) -> Option<()>
    where
        Self: Sized,
    {
        access_with_retry::<Self, u8, ()>(
            || {
                let slice = core::ptr::slice_from_raw_parts_mut(
                    core::ptr::with_exposed_provenance_mut::<u8>(addr),
                    size,
                );
                if write {
                    Self::validate_slice_for_write(slice)
                } else {
                    Self::validate_slice(slice)
                }
            },
            addr,
            size,
            write,
            |ptr| f(ptr, 0, size),
        )
    }
}

/// Runs `access` against the pointer `validate` approves for it, validating again and retrying
/// (bounded) whenever the validator says a fault the access took is worth one more attempt --
/// see [`ValidateAccess::retry_after_fault`]. `addr`/`size`/`write` describe the access for
/// that decision; `access` receives the freshly validated pointer each time.
#[inline]
fn access_with_retry<V: ValidateAccess, T, R>(
    validate: impl Fn() -> Option<*mut T>,
    addr: usize,
    size: usize,
    write: bool,
    mut access: impl FnMut(*mut T) -> Result<R, Fault>,
) -> Option<R> {
    let generation = V::access_generation();
    let mut attempt = 0;
    loop {
        let ptr = validate()?;
        match V::with_user_memory_access(|| access(ptr)) {
            Ok(value) => return Some(value),
            Err(Fault) => {
                attempt += 1;
                if !V::retry_after_fault(addr, size, write, attempt, generation) {
                    return None;
                }
            }
        }
    }
}

/// An implementiation of [`ValidateAccess`] that performs no validation. This
/// might be appropriate for purely-userland contexts.
pub struct NoValidation;

impl ValidateAccess for NoValidation {
    fn validate<T>(ptr: *mut T) -> Option<*mut T> {
        Some(ptr)
    }
    fn validate_slice<T>(ptr: *mut [T]) -> Option<*mut T> {
        Some(ptr.cast())
    }
}

/// An implementation of [`ValidateAccess`] that confines every access to the calling OS thread's
/// current guest view: the pointer's exact byte range must lie inside `Platform::TASK_ADDR_MIN
/// ..TASK_ADDR_MAX`, the view must be admitted (installed, not draining), and the range must be
/// entirely mapped with at least `READ` permission (also `WRITE`, for a write access) according to
/// that view's own [`PageManager`](crate::mm::PageManager). See
/// [`PageManagementProvider::current_guest_access`](crate::platform::PageManagementProvider::current_guest_access)
/// for how the platform supplies that context, and
/// [`PageManager::checked_guest_range`](crate::mm::PageManager::checked_guest_range) for the
/// check itself.
///
/// Any failure -- no context set, range outside the aperture, view not admitted, or the range not
/// fully and correctly mapped -- returns `None` (EFAULT to the caller) with no host pointer ever
/// exposed and no partial effect. The domain admission lease taken during the check is dropped
/// immediately after the check succeeds; it is not held across the actual fallible read/write
/// that follows, which is why that access still goes through the exception-table-backed fallible
/// primitives (this confinement is an additional, coarser gate in front of that existing hardware
/// fault recovery, not a replacement for it).
pub struct ViewConfinedAccess<Platform, const ALIGN: usize>(core::marker::PhantomData<Platform>);

impl<Platform, const ALIGN: usize> ViewConfinedAccess<Platform, ALIGN>
where
    Platform: crate::sync::RawSyncPrimitivesProvider
        + crate::platform::PageManagementProvider<ALIGN>
        + 'static,
{
    fn checked<T>(ptr: *mut T, size: usize, write: bool) -> Option<*mut T> {
        if size == 0 {
            return Some(ptr);
        }
        let (view, _task, pm) = Platform::current_guest_access()?;
        let addr = ptr.expose_provenance();
        let end = addr.checked_add(size)?;
        if let Err(error) = pm.checked_guest_range(view, addr..end, write) {
            Self::trace_refusal(view, addr, size, write, "checked_guest_range", &error);
            return None;
        }
        if !Self::prepare_pages(view, pm, addr, end, write) {
            Self::trace_refusal(view, addr, size, write, "prepare_guest_access", &"refused");
            return None;
        }
        if !Platform::any_host_redirect_active() {
            return Some(ptr);
        }
        let Some(redirected) = Self::resolve_redirect(view, addr, end) else {
            Self::trace_refusal(view, addr, size, write, "resolve_redirect (non-uniform delta)", &"");
            return None;
        };
        Some(core::ptr::with_exposed_provenance_mut(redirected))
    }

    /// The opt-in guest-access fault trace's twin for a refused (never attempted) access: which
    /// gate said no, with the per-page platform state, so a host-side `EFAULT` can be attributed
    /// without a debugger.
    fn trace_refusal(
        view: crate::utils::ids::VmViewId,
        addr: usize,
        size: usize,
        write: bool,
        gate: &str,
        error: &dyn core::fmt::Debug,
    ) {
        if !Platform::guest_access_fault_trace() {
            return;
        }
        let mut pages = alloc::string::String::new();
        let end = addr.saturating_add(size.max(1));
        let mut page = addr & !(ALIGN - 1);
        let mut shown = 0;
        while page < end && shown < 4 {
            pages.push_str(&Platform::describe_guest_page(view, page));
            pages.push_str(" | ");
            page = page.saturating_add(ALIGN);
            shown += 1;
        }
        litebox_util_log::warn!(
            view:? = view, addr:? = addr, size:? = size, write:? = write, gate:? = gate,
            error:? = error, pages:% = pages;
            "guest-access fault trace: host-side access refused by the confinement gate"
        );
    }

    /// The page-preparation half of [`Self::checked`] (a fork child's lineage-held pages and a
    /// forking ancestor's write-protected pages materialized ahead of the host-side copy, plus
    /// the custody publication of everything that promoted), factored out so a run-split access
    /// prepares its whole range once. `false`: the platform refused the access (see
    /// [`GuestAccessPreparation::refused`](crate::platform::page_mgmt::GuestAccessPreparation::refused))
    /// -- the caller must not perform it.
    fn prepare_pages(
        view: crate::utils::ids::VmViewId,
        pm: &crate::mm::PageManager<Platform, ALIGN>,
        addr: usize,
        end: usize,
        write: bool,
    ) -> bool {
        let domain = pm.guest_va_domain();
        let prepared = Platform::prepare_guest_access(view, addr..end, write, &|page| {
            match domain.custody_at_via_lineage(view, page) {
                crate::mm::domain::Custody::Present { view: holder, .. }
                | crate::mm::domain::Custody::Retiring { view: holder, .. } => Some(holder),
                _ => None,
            }
        });
        // Same gating as `EnterShim::cow_custody_publish_divergence`: a view that has itself
        // forked keeps its own family map untouched so its descendants' lineage walks still
        // reach the content they inherited. Published even for a refused access: the pages
        // that did promote are this view's own either way.
        if !prepared.promoted.is_empty() && !domain.family_has_live_descendant_of(view) {
            for page in prepared.promoted {
                let _ = domain.confirm_present_or_reconcile(view, page..page + ALIGN);
            }
        }
        !prepared.refused
    }

    /// The maximal runs of `addr..end` whose pages all redirect by one offset (a promoted
    /// shadow, a shared file origin, or no redirect at all), as `(run_start, run_end)` byte
    /// ranges in address order -- the unit a bulk access is served in once
    /// [`Self::resolve_redirect`]'s single-pointer rule cannot hold for the whole range.
    fn delta_runs(
        view: crate::utils::ids::VmViewId,
        addr: usize,
        end: usize,
    ) -> Option<alloc::vec::Vec<(usize, usize)>> {
        let start_page = addr & !(ALIGN - 1);
        let last_page = (end - 1) & !(ALIGN - 1);
        // One batched resolution for the whole range (one platform snapshot, not one lock per
        // page), indexed by page below.
        let mut targets = alloc::vec::Vec::new();
        Platform::resolve_promoted_host_pages(view, start_page, last_page, &mut targets);
        let delta_of = |page: usize| {
            targets
                .get((page - start_page) / ALIGN)
                .copied()
                .flatten()
                .map(|shadow| shadow.wrapping_sub(page))
        };
        let mut runs = alloc::vec::Vec::new();
        let mut run_start = addr;
        let mut run_delta = delta_of(start_page);
        let mut page = start_page.checked_add(ALIGN)?;
        while page <= last_page {
            let delta = delta_of(page);
            if delta != run_delta {
                runs.try_reserve(1).ok()?;
                runs.push((run_start, page));
                run_start = page;
                run_delta = delta;
            }
            page = page.checked_add(ALIGN)?;
        }
        runs.try_reserve(1).ok()?;
        runs.push((run_start, end));
        Some(runs)
    }

    /// Only reached once [`PageManagementProvider::any_host_redirect_active`] says some page,
    /// somewhere in the process, has been redirected -- resolves what host address `addr..end`
    /// (already known, by `checked`'s own gate above, to be a legitimate guest access) should
    /// actually be read or written at under `view`.
    ///
    /// A single returned pointer is valid for the whole range only if every page in it agrees:
    /// either none of them redirect (the ordinary case, even once the process-wide flag above is
    /// set, for any range that doesn't happen to touch a redirected page), or all of them
    /// redirect by the identical offset onto one contiguous run. A range straddling a redirected
    /// and a non-redirected page, or two pages redirected by different offsets, fails closed
    /// (`None`) here: the scalar fast paths and every bulk copy then fall back to
    /// [`Self::access_runs`], which serves such a range per redirect run instead of refusing it
    /// (a page promoted next to one still aliasing a file origin is ordinary state once shared
    /// file origins exist), so no part of a range is ever served from the wrong page.
    fn resolve_redirect(
        view: crate::utils::ids::VmViewId,
        addr: usize,
        end: usize,
    ) -> Option<usize> {
        let start_page = addr & !(ALIGN - 1);
        let last_page = (end - 1) & !(ALIGN - 1);
        let first_delta = if start_page == last_page {
            Platform::resolve_promoted_host_page(view, start_page)
                .map(|shadow| shadow.wrapping_sub(start_page))
        } else {
            // A multi-page range is resolved in one batched call (one platform snapshot, not
            // one lock acquisition per page).
            let mut targets = alloc::vec::Vec::new();
            Platform::resolve_promoted_host_pages(view, start_page, last_page, &mut targets);
            let mut page = start_page;
            let mut first_delta = None;
            for (index, target) in targets.iter().enumerate() {
                let delta = target.map(|shadow| shadow.wrapping_sub(page));
                if index == 0 {
                    first_delta = delta;
                } else if delta != first_delta {
                    return None;
                }
                page = page.checked_add(ALIGN)?;
            }
            first_delta
        };
        Some(match first_delta {
            None => addr,
            Some(delta) => addr.wrapping_add(delta),
        })
    }
}

impl<Platform, const ALIGN: usize> ValidateAccess for ViewConfinedAccess<Platform, ALIGN>
where
    Platform: crate::sync::RawSyncPrimitivesProvider
        + crate::platform::PageManagementProvider<ALIGN>
        + 'static,
{
    fn validate<T>(ptr: *mut T) -> Option<*mut T> {
        Self::checked(ptr, size_of::<T>(), false)
    }
    fn validate_slice<T>(ptr: *mut [T]) -> Option<*mut T> {
        let len = ptr.len();
        Self::checked(ptr.cast(), len * size_of::<T>(), false)
    }
    fn validate_for_write<T>(ptr: *mut T) -> Option<*mut T> {
        Self::checked(ptr, size_of::<T>(), true)
    }
    fn validate_slice_for_write<T>(ptr: *mut [T]) -> Option<*mut T> {
        let len = ptr.len();
        Self::checked(ptr.cast(), len * size_of::<T>(), true)
    }

    #[inline]
    fn access_generation() -> u64 {
        Platform::fork_generation()
    }

    /// Per-redirect-run bulk access: while no page anywhere redirects, exactly the single
    /// validated run of the default. Once redirects exist the whole range is gated and prepared
    /// once (a write's promotions land before the redirects are read), split at every redirect
    /// boundary, and every run is validated again -- gate, preparation, its own now-uniform
    /// redirect -- inside its own bounded retry loop, so a run is never served from a stale
    /// resolution and the access as a whole never touches a page the gate would refuse.
    fn access_runs(
        addr: usize,
        size: usize,
        write: bool,
        f: &mut dyn FnMut(*mut u8, usize, usize) -> Result<(), Fault>,
    ) -> Option<()> {
        if size == 0 {
            return Some(());
        }
        let ptr = core::ptr::with_exposed_provenance_mut::<u8>(addr);
        if !Platform::any_host_redirect_active() {
            return access_with_retry::<Self, u8, ()>(
                || Self::checked(ptr, size, write),
                addr,
                size,
                write,
                |host| f(host, 0, size),
            );
        }
        let (view, _task, pm) = Platform::current_guest_access()?;
        let end = addr.checked_add(size)?;
        let lease = pm.checked_guest_range(view, addr..end, write).ok()?;
        drop(lease);
        if !Self::prepare_pages(view, pm, addr, end, write) {
            return None;
        }
        // The runs are a PLAN over redirect state other threads keep changing: a sibling that
        // promotes a page inside a run after the split makes that run's redirect non-uniform, and
        // its validation below then fails. Such a run re-plans the rest of the range from its own
        // start (fresh redirects, fresh split), up to `RUN_REPLANS` times, before the access is
        // refused -- the same plan-then-act revalidation `prepare_guest_access` uses (T1h
        // fix-up), so a concurrent promotion costs a re-split, not a spurious EFAULT. Re-serving
        // a run from its start is idempotent: the same bytes are copied again.
        const RUN_REPLANS: usize = 2;
        let mut cursor = addr;
        let mut replans = 0;
        let mut split = false;
        'plan: loop {
            let runs = Self::delta_runs(view, cursor, end)?;
            if runs.len() > 1 && !split {
                split = true;
                Platform::record_host_access_multi_run();
            }
            for (run_start, run_end) in runs {
                let len = run_end - run_start;
                let offset = run_start - addr;
                let run_ptr = core::ptr::with_exposed_provenance_mut::<u8>(run_start);
                let served = access_with_retry::<Self, u8, ()>(
                    || Self::checked(run_ptr, len, write),
                    run_start,
                    len,
                    write,
                    |host| f(host, offset, len),
                );
                if served.is_none() {
                    if replans < RUN_REPLANS {
                        replans += 1;
                        cursor = run_start;
                        continue 'plan;
                    }
                    if split {
                        Platform::record_host_access_efault_after_runs();
                    }
                    return None;
                }
            }
            return Some(());
        }
    }

    /// A fault after `checked` approved the range means the platform's page preparation
    /// (`prepare_guest_access`) either raced a concurrent fork's write-protection of the very
    /// page, or left a state it does not cover -- either way the guest itself would resolve it
    /// with an ordinary page fault, so the access is re-validated (re-preparing the range) and
    /// retried, [`ACCESS_FAULT_ATTEMPTS`] times in all, before it is refused. Opt-in trace
    /// (`Platform::guest_access_fault_trace`) logs every fault with the per-page state.
    fn retry_after_fault(addr: usize, size: usize, write: bool, attempt: u32, generation: u64) -> bool {
        let retry = attempt < ACCESS_FAULT_ATTEMPTS;
        if Platform::guest_access_fault_trace() {
            let view = Platform::current_guest_access().map(|(view, _, _)| view);
            let mut pages = alloc::string::String::new();
            if let Some(view) = view {
                let end = addr.saturating_add(size.max(1));
                let mut page = addr & !(ALIGN - 1);
                while page < end {
                    pages.push_str(&Platform::describe_guest_page(view, page));
                    pages.push_str(" | ");
                    page = page.saturating_add(ALIGN);
                }
            }
            litebox_util_log::warn!(
                view:? = view, addr:? = addr, size:? = size, write:? = write, attempt:? = attempt,
                retry:? = retry, fork_generation_at_validate:? = generation,
                fork_generation_now:? = Platform::fork_generation(), pages:% = pages;
                "guest-access fault trace: fallible access faulted after checked() approved it"
            );
        } else {
            litebox_util_log::debug!(
                addr:? = addr, size:? = size, write:? = write, attempt:? = attempt, retry:? = retry;
                "fallible guest access faulted after checked() approved it"
            );
        }
        retry
    }
}

/// Represent a user space pointer to a read-only object
// NOTE: We explicitly write the `T: Sized` bound to explicitly document that
// these need to be "thin" pointers, and that "fat" pointers (i.e., pointers to
// DSTs) are unsupported.
#[derive(FromBytes, IntoBytes)]
#[repr(transparent)]
pub struct UserConstPtr<V, T: Sized> {
    /// An exposed-provenance address of the pointer. See [`Self::as_ptr`] for
    /// more details.
    inner: usize,
    _phantom_ptr: core::marker::PhantomData<*const T>,
    _validator: core::marker::PhantomData<V>,
}

impl<V: ValidateAccess, T> UserConstPtr<V, T> {
    pub fn from_ptr(ptr: *const T) -> Self {
        Self {
            inner: ptr.expose_provenance(),
            _phantom_ptr: core::marker::PhantomData,
            _validator: core::marker::PhantomData,
        }
    }

    /// Explicitly-private function.  This particular function exists because we
    /// store the `*const T` that would be stored in this struct instead as a
    /// `usize`.  We store `inner` as a `usize` to support
    /// `zerocopy::{FromBytes, IntoBytes}`.  Both of these _are_ sound to
    /// implement on `*const T`, but `zerocopy` currently chooses not to
    /// implement these, due to potential provenance footguns (see
    /// <https://github.com/google/zerocopy/blob/dce155c9b6004af2bdfeefc547abbcae3661909e/src/impls.rs#L955-L958>,
    /// or for a lot more details, see
    /// <https://github.com/google/zerocopy/issues/170>).  Our usage of these
    /// pointers is always through exposed provenance (see more details on
    /// [`RawConstPointer`]), and thus our provenance story is intimately linked
    /// to the design of that trait.  We are thus opting into the sound (but
    /// footgun-controlled) approach of storing a `usize` and converting it over
    /// here.
    fn as_ptr(&self) -> *const T {
        core::ptr::with_exposed_provenance(self.inner)
    }
}

impl<V, T> Clone for UserConstPtr<V, T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<V, T> Copy for UserConstPtr<V, T> {}

impl<V, T> core::fmt::Debug for UserConstPtr<V, T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("UserConstPtr").field(&self.inner).finish()
    }
}

/// Read from user space at the `off` offset, in a fallible manner.
///
/// Note that this is fallible only if recovering from exceptions (e.g., page fault or SIGSEGV)
/// is supported.
fn read_at_offset<V: ValidateAccess, T: FromBytes>(ptr: *const T, count: isize) -> Option<T> {
    let src = ptr.wrapping_add(usize::try_from(count).ok()?);
    // Match on the size of `T` to use the appropriate fallible read function to
    // ensure that small aligned reads are atomic (and faster than a full
    // memcpy). This match will be evaluated at compile time, so there is no
    // runtime overhead.
    //
    // SAFETY: The FromBytes bound on T guarantees that any byte pattern is valid for T,
    // so transmute_copy is safe. The memory access itself is fallible and returns None
    // on invalid memory access.
    let fast = access_with_retry::<V, T, T>(
        || V::validate(src.cast_mut()),
        src.expose_provenance(),
        size_of::<T>(),
        false,
        |src| {
            let src = src.cast_const();
            let val = unsafe {
                match size_of::<T>() {
                    1 => core::mem::transmute_copy(
                        &crate::mm::exception_table::read_u8_fallible(src.cast())?,
                    ),
                    2 => core::mem::transmute_copy(
                        &crate::mm::exception_table::read_u16_fallible(src.cast())?,
                    ),
                    4 => core::mem::transmute_copy(
                        &crate::mm::exception_table::read_u32_fallible(src.cast())?,
                    ),
                    #[cfg(target_pointer_width = "64")]
                    8 => core::mem::transmute_copy(
                        &crate::mm::exception_table::read_u64_fallible(src.cast())?,
                    ),
                    _ => {
                        let mut data = core::mem::MaybeUninit::<T>::uninit();
                        memcpy_fallible(
                            data.as_mut_ptr().cast(),
                            src.cast(),
                            core::mem::size_of::<T>(),
                        )?;

                        data.assume_init()
                    }
                }
            };
            Ok(val)
        },
    );
    if fast.is_some() || size_of::<T>() <= 1 {
        return fast;
    }
    // A scalar straddling two pages the validator redirects differently (only an unaligned
    // one can): assembled from per-run copies into a stack temporary. A genuinely invalid
    // pointer is refused again here, just as before.
    let mut data = core::mem::MaybeUninit::<T>::uninit();
    let dst = data.as_mut_ptr().cast::<u8>();
    V::access_runs(
        src.expose_provenance(),
        size_of::<T>(),
        false,
        &mut |host, offset, run| unsafe { memcpy_fallible(dst.add(offset), host.cast_const(), run) },
    )?;
    // SAFETY: every byte of `data` was written by the runs above (they tile the whole access),
    // and `FromBytes` makes any byte pattern a valid `T`.
    Some(unsafe { data.assume_init() })
}

/// A NUL-terminated byte string at `addr`, read one bulk access per page instead of one access
/// per byte (the trait default scans byte by byte, then copies the string again): a page-contained
/// access is admitted or refused exactly as each of its bytes would be, and a page whose bulk read
/// fails is scanned byte by byte, so the result -- including a fault before the NUL -- is the
/// byte-by-byte one (hvf-t1g-remainder-multisecond-service-guest-memory-access-convoy).
fn to_cstring_paged<V: ValidateAccess>(addr: usize) -> Option<alloc::ffi::CString> {
    const PAGE: usize = crate::mm::linux::PAGE_SIZE;
    let mut bytes: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
    let mut cursor = addr;
    loop {
        let page_end = (cursor & !(PAGE - 1)).checked_add(PAGE)?;
        let len = page_end - cursor;
        let piece = to_owned_slice::<V, u8>(core::ptr::with_exposed_provenance(cursor), len);
        match piece {
            Some(piece) => {
                if let Some(nul) = piece.iter().position(|byte| *byte == 0) {
                    bytes.extend_from_slice(&piece[..=nul]);
                    break;
                }
                bytes.extend_from_slice(&piece);
            }
            None => {
                for index in 0..len {
                    let byte = read_at_offset::<V, u8>(
                        core::ptr::with_exposed_provenance(cursor + index),
                        0,
                    )?;
                    bytes.push(byte);
                    if byte == 0 {
                        return alloc::ffi::CString::from_vec_with_nul(bytes).ok();
                    }
                }
            }
        }
        cursor = page_end;
    }
    alloc::ffi::CString::from_vec_with_nul(bytes).ok()
}

fn to_owned_slice<V: ValidateAccess, T: FromBytes>(
    ptr: *const T,
    len: usize,
) -> Option<alloc::boxed::Box<[T]>> {
    if len == 0 {
        return Some(alloc::boxed::Box::new([]));
    }
    let mut data = alloc::boxed::Box::<[T]>::new_uninit_slice(len);
    let dst = data.as_mut_ptr().cast::<u8>();
    // SAFETY: The FromBytes bound on T guarantees that any byte pattern is valid for T.
    // The memcpy_fallible operation returns None on invalid memory access; the runs tile the
    // whole `len * size_of::<T>()` bytes of `data`.
    V::access_runs(
        ptr.expose_provenance(),
        len * size_of::<T>(),
        false,
        &mut |src, offset, run| unsafe { memcpy_fallible(dst.add(offset), src.cast_const(), run) },
    )?;
    Some(unsafe { data.assume_init() })
}

impl<V: ValidateAccess, T: FromBytes> RawConstPointer<T> for UserConstPtr<V, T> {
    fn read_at_offset(self, count: isize) -> Option<T> {
        read_at_offset::<V, T>(self.as_ptr(), count)
    }

    fn to_owned_slice(self, len: usize) -> Option<alloc::boxed::Box<[T]>> {
        to_owned_slice::<V, T>(self.as_ptr(), len)
    }

    fn to_cstring(self) -> Option<alloc::ffi::CString>
    where
        T: core::cmp::PartialEq<core::ffi::c_char>,
        Self: RawConstPointer<core::ffi::c_char>,
    {
        to_cstring_paged::<V>(self.inner)
    }

    fn as_usize(&self) -> usize {
        self.inner
    }
    fn from_usize(addr: usize) -> Self {
        Self {
            inner: addr,
            _phantom_ptr: core::marker::PhantomData,
            _validator: core::marker::PhantomData,
        }
    }
}

/// Represent a user space pointer to a mutable object
// NOTE: We explicitly write the `T: Sized` bound to explicitly document that
// these need to be "thin" pointers, and that "fat" pointers (i.e., pointers to
// DSTs) are unsupported.
#[derive(FromBytes, IntoBytes)]
#[repr(transparent)]
pub struct UserMutPtr<V, T: Sized> {
    /// An exposed-provenance address of the pointer. See [`Self::as_ptr`] for
    /// more details.
    inner: usize,
    _phantom_ptr: core::marker::PhantomData<*mut T>,
    _validator: core::marker::PhantomData<V>,
}

impl<V: ValidateAccess, T> UserMutPtr<V, T> {
    pub fn from_ptr(ptr: *mut T) -> Self {
        Self {
            inner: ptr.expose_provenance(),
            _phantom_ptr: core::marker::PhantomData,
            _validator: core::marker::PhantomData,
        }
    }

    /// Explicitly-private function.  See equivalent [`UserConstPtr::as_ptr`]
    /// for more details.
    fn as_ptr(&self) -> *mut T {
        core::ptr::with_exposed_provenance_mut(self.inner)
    }
}

impl<V, T> core::fmt::Debug for UserMutPtr<V, T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("UserMutPtr").field(&self.inner).finish()
    }
}

impl<V, T> Clone for UserMutPtr<V, T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<V, T> Copy for UserMutPtr<V, T> {}

impl<V: ValidateAccess, T: FromBytes> RawConstPointer<T> for UserMutPtr<V, T> {
    fn read_at_offset(self, count: isize) -> Option<T> {
        read_at_offset::<V, T>(self.as_ptr().cast_const(), count)
    }

    fn to_owned_slice(self, len: usize) -> Option<alloc::boxed::Box<[T]>> {
        to_owned_slice::<V, T>(self.as_ptr().cast_const(), len)
    }

    fn to_cstring(self) -> Option<alloc::ffi::CString>
    where
        T: core::cmp::PartialEq<core::ffi::c_char>,
        Self: RawConstPointer<core::ffi::c_char>,
    {
        to_cstring_paged::<V>(self.inner)
    }

    fn as_usize(&self) -> usize {
        self.inner
    }
    fn from_usize(addr: usize) -> Self {
        Self {
            inner: addr,
            _phantom_ptr: core::marker::PhantomData,
            _validator: core::marker::PhantomData,
        }
    }
}

impl<V: ValidateAccess, T: FromBytes + IntoBytes> RawMutPointer<T> for UserMutPtr<V, T> {
    fn write_at_offset(self, count: isize, value: T) -> Option<()> {
        let dst = self.as_ptr().wrapping_add(usize::try_from(count).ok()?);
        // Match on the size of `T` to use the appropriate fallible write function to
        // ensure that small aligned writes are atomic (and faster than a full
        // memcpy). This match will be evaluated at compile time, so there is no
        // runtime overhead.
        //
        // SAFETY: The IntoBytes bound on T guarantees that T can be safely written as bytes.
        // The transmute_copy is safe because T implements IntoBytes. The memory access
        // itself is fallible and returns None on invalid memory access.
        let fast = access_with_retry::<V, T, ()>(
            || V::validate_for_write(dst),
            dst.expose_provenance(),
            size_of::<T>(),
            true,
            |dst| unsafe {
                match size_of::<T>() {
                    1 => crate::mm::exception_table::write_u8_fallible(
                        dst.cast(),
                        core::mem::transmute_copy(&value),
                    ),
                    2 => crate::mm::exception_table::write_u16_fallible(
                        dst.cast(),
                        core::mem::transmute_copy(&value),
                    ),
                    4 => crate::mm::exception_table::write_u32_fallible(
                        dst.cast(),
                        core::mem::transmute_copy(&value),
                    ),
                    #[cfg(target_pointer_width = "64")]
                    8 => crate::mm::exception_table::write_u64_fallible(
                        dst.cast(),
                        core::mem::transmute_copy(&value),
                    ),
                    _ => memcpy_fallible(
                        dst.cast(),
                        (&raw const value).cast(),
                        core::mem::size_of::<T>(),
                    ),
                }
            },
        );
        if fast.is_some() || size_of::<T>() <= 1 {
            return fast;
        }
        // The straddling-scalar counterpart of `read_at_offset`: written per redirect run.
        let src = (&raw const value).cast::<u8>();
        V::access_runs(
            dst.expose_provenance(),
            size_of::<T>(),
            true,
            &mut |host, offset, run| unsafe { memcpy_fallible(host, src.add(offset), run) },
        )
    }

    fn compare_exchange_u32(self, current: u32, new: u32) -> Option<Result<u32, u32>>
    where
        Self: RawMutPointer<u32>,
    {
        let dst = self.as_ptr().cast::<u32>();
        if dst.is_null() || !dst.is_aligned() {
            return None;
        }
        access_with_retry::<V, u32, Result<u32, u32>>(
            || V::validate_for_write(dst),
            dst.expose_provenance(),
            size_of::<u32>(),
            true,
            |dst| unsafe {
                crate::mm::exception_table::compare_exchange_u32_fallible(dst, current, new)
            },
        )
    }

    fn mutate_subslice_with<R>(
        self,
        _range: impl core::ops::RangeBounds<isize>,
        _f: impl FnOnce(&mut [T]) -> R,
    ) -> Option<R> {
        unimplemented!("use write_slice_at_offset instead")
    }

    fn copy_from_slice(self, start_offset: usize, buf: &[T]) -> Option<()>
    where
        T: Copy,
    {
        if buf.is_empty() {
            return Some(());
        }
        let dst = self.as_ptr().wrapping_add(start_offset);
        let src = buf.as_ptr().cast::<u8>();
        // SAFETY: the runs tile `size_of_val(buf)` bytes of `buf`, read at `src + offset`.
        V::access_runs(
            dst.expose_provenance(),
            size_of_val(buf),
            true,
            &mut |host, offset, run| unsafe { memcpy_fallible(host, src.add(offset), run) },
        )
    }
}
