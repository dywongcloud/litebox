// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! A [LiteBox platform](../litebox/platform/index.html) for running LiteBox on
//! userland macOS running on Apple Silicon.
//!
//! # Why aarch64 only
//!
//! There is no x86-64 variant of this platform. Running an x86-64 guest on an
//! Apple Silicon host would mean instruction emulation, which is exactly what
//! LiteBox exists to avoid: the whole point of the "South" platform interface is
//! that the guest's instructions are the host's instructions and only the
//! *system* interface is virtualized. An aarch64 Linux guest on an aarch64 macOS
//! host needs no emulation at all -- just this platform plus the aarch64 syscall
//! rewriting that `litebox_syscall_rewriter` already performs.
//!
//! # How Darwin differs from the other userland platforms
//!
//! * **16 KiB pages.** Apple Silicon's page size is 16 KiB, not 4 KiB, so every
//!   fixed mapping and every protection change must be 16 KiB aligned. This is
//!   why `litebox::mm::linux::PAGE_SIZE` is target-dependent; the guest learns
//!   the same value through `AT_PAGESZ`.
//! * **A 4 GiB `__PAGEZERO`.** The first 4 GiB of an arm64 Mach-O process is
//!   reserved and permanently unmapped, so no guest mapping can live below it.
//!   `MacOsUserland`'s `TASK_ADDR_MIN` reflects that, which in turn means
//!   guest images have to be position-independent or linked above 4 GiB.
//! * **W^X.** Anonymous memory cannot be both writable and executable, and
//!   memory that was ever writable cannot later become executable. The supported
//!   escape hatch is `MAP_JIT`, which requires the host process to be signed with
//!   the `com.apple.security.cs.allow-jit` entitlement and requires writes to be
//!   bracketed by `pthread_jit_write_protect_np`. Executable guest mappings
//!   therefore go through `jit_write_protect`.
//! * **No futex.** Darwin's equivalent is `__ulock_wait`/`__ulock_wake`, which
//!   provides the same compare-and-wait contract.
//! * **No `MAP_FIXED_NOREPLACE`, no `MAP_POPULATE`, no `MAP_GROWSDOWN`.** The
//!   first is emulated with an atomic `mach_vm_allocate` reservation, the second
//!   with `madvise(MADV_WILLNEED)`, and the third has no equivalent.
//! * **No vDSO.** `SystemInfoProvider::get_vdso_address` reports `None`, which
//!   means a guest signal handler must supply its own `sa_restorer`.
//!

// Restrict this crate to macOS on Apple Silicon. See the module docs for why
// there is deliberately no x86-64 variant.
#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use core::time::Duration;
use std::io::IsTerminal as _;
use std::sync::{Arc, Condvar, Mutex, OnceLock};

use litebox::platform::page_mgmt::{
    AllocationError, DeallocationError, FixedAddressBehavior, MemoryRegionPermissions,
    PermissionUpdateError,
};
use litebox::platform::{ImmediatelyWokenUp, UnblockedOrTimedOut};
use litebox::utils::TruncateExt as _;
use zerocopy::{FromBytes, IntoBytes};

extern crate alloc;

mod darwin;
mod guest;
mod net;

use darwin::{
    MAP_JIT, ReservationError, mach_vm_region_iter, release_reservation, remap_to_fixed,
    reserve_fixed, ulock_wait, ulock_wake,
};

/// The host signal LiteBox reserves for interrupting a thread out of guest
/// execution. Darwin has no realtime signals, so this has to come out of the
/// small fixed set; `SIGUSR2` is the least likely to be wanted elsewhere in a
/// process that is already dedicating itself to hosting a sandbox.
const INTERRUPT_SIGNAL: libc::c_int = libc::SIGUSR2;

/// The userland macOS platform.
///
/// This implements the main [`litebox::platform::Provider`] trait, i.e.,
/// implements all platform traits.
pub struct MacOsUserland {
    /// Host mappings that already exist and must not be handed to a guest.
    reserved_pages: alloc::vec::Vec<core::ops::Range<usize>>,
    /// The boot session identifier, if
    /// [`Self::initialize_boot_specific_kdf_support`] has been run. It is stable
    /// across processes but changes on every boot.
    boot_id: OnceLock<alloc::vec::Vec<u8>>,
    /// Whether each of stdin/stdout/stderr is a terminal, sampled once at
    /// startup so the guest cannot observe a redirect mid-flight.
    stdio_is_tty: [bool; 3],
    /// The `utun` socket used for guest networking, if one was requested.
    tun: Option<std::os::fd::OwnedFd>,
    /// CoW-eligible memory regions registered via [`Self::register_cow_region`].
    /// Maps the start address of the static slice to the info needed to re-mmap
    /// the backing file. Mirrors `litebox_platform_linux_userland`'s identical
    /// mechanism.
    cow_regions: std::sync::RwLock<alloc::collections::BTreeMap<usize, CowRegionInfo>>,
}

/// Information about a CoW-eligible memory region backed by a host file.
struct CowRegionInfo {
    /// The path to the backing file on the host filesystem.
    file_path: std::path::PathBuf,
    /// Length of the backing file's registered slice.
    file_length: usize,
}

impl core::fmt::Debug for MacOsUserland {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MacOsUserland").finish_non_exhaustive()
    }
}

impl MacOsUserland {
    /// Create a new userland-macOS platform for use in LiteBox.
    ///
    /// `tun_device_name` optionally names a `utun` interface (such as `"utun3"`)
    /// to connect guest networking to; networking is disabled when it is `None`.
    ///
    /// # Panics
    ///
    /// Panics if the requested `utun` device cannot be opened, if the fault
    /// handlers that make guest-memory accesses fallible cannot be installed,
    /// or if the guest thread-pointer TSD slot the rewriter's `Host::MacOs`
    /// gates have baked in cannot be reserved (see `reserve_guest_tpidr_tsd_slot`).
    pub fn new(tun_device_name: Option<&str>) -> &'static Self {
        install_fault_handlers();
        install_async_signal_handlers();
        reserve_guest_tpidr_tsd_slot();

        let tun = tun_device_name.map(|name| {
            net::open_utun(name).unwrap_or_else(|e| panic!("failed to open {name}: {e}"))
        });

        let platform = Self {
            reserved_pages: read_memory_maps(),
            boot_id: OnceLock::new(),
            stdio_is_tty: [
                std::io::stdin().is_terminal(),
                std::io::stdout().is_terminal(),
                std::io::stderr().is_terminal(),
            ],
            tun,
            cow_regions: std::sync::RwLock::new(alloc::collections::BTreeMap::new()),
        };

        // A platform must outlive every guest thread that can reach it, and
        // there is exactly one per process, so leaking is the cheapest way to
        // get a `'static` without reference counting on every access.
        alloc::boxed::Box::leak(alloc::boxed::Box::new(platform))
    }

    /// Populate the root key used by [`litebox::platform::DerivedKeyProvider`].
    ///
    /// The key is Darwin's boot session UUID: stable for every process in a boot
    /// and freshly generated by the kernel on the next one, which is exactly the
    /// "persistent across LiteBox invocations, reset by a true reboot" guarantee
    /// the trait describes.
    ///
    /// # Errors
    ///
    /// Returns the `sysctl` error if the boot session UUID cannot be read.
    pub fn initialize_boot_specific_kdf_support(&self) -> Result<(), std::io::Error> {
        if self.boot_id.get().is_some() {
            return Ok(());
        }
        let uuid = darwin::sysctl_string(c"kern.bootsessionuuid")?;
        // Ignore a concurrent initializer winning the race; both wrote the same
        // value.
        let _ = self.boot_id.set(uuid.into_bytes());
        Ok(())
    }

    /// Register a CoW-eligible memory region backed by a file.
    ///
    /// `data` must be a slice that was `mmap`'d in from `file_path` (typically
    /// by the initial file system's static-backing-data loader). Once
    /// registered, [`litebox::platform::PageManagementProvider::try_allocate_cow_pages`]
    /// can remap any sub-slice of `data` into the guest's address space by
    /// re-`mmap`ing the same file region `MAP_PRIVATE`, instead of allocating
    /// fresh pages and copying `data` into them.
    ///
    /// # Panics
    ///
    /// Panics if an overlapping region is already registered.
    pub fn register_cow_region(
        &self,
        data: &'static [u8],
        file_path: impl Into<std::path::PathBuf>,
    ) {
        let start = data.as_ptr() as usize;
        let info = CowRegionInfo {
            file_path: file_path.into(),
            file_length: data.len(),
        };
        let mut regions = self.cow_regions.write().unwrap();
        assert!(
            regions.range(start..start + data.len()).next().is_none(),
            "attempting to register an overlapping CoW region"
        );
        let old = regions.insert(start, info);
        assert!(old.is_none());
    }

    /// Looks up the file backing a static slice for CoW mapping.
    ///
    /// Returns `Some((file_path, offset_in_file))` if `source_data` falls
    /// entirely within a registered region, `None` otherwise.
    fn lookup_cow_region(&self, source_data: &'static [u8]) -> Option<(std::path::PathBuf, usize)> {
        let slice_start = source_data.as_ptr() as usize;
        let slice_end = slice_start.checked_add(source_data.len())?;

        let regions = self.cow_regions.read().unwrap();
        let (&region_start, info) = regions.range(..=slice_start).next_back()?;
        let region_end = region_start.checked_add(info.file_length)?;

        (slice_start >= region_start && slice_end <= region_end)
            .then(|| (info.file_path.clone(), slice_start - region_start))
    }

    /// The task parameters a runner should start the initial guest thread with.
    pub fn init_task(&self) -> litebox_common_linux::TaskParams {
        // TODO: these are synthetic, matching the other userland platforms.
        // Passing the host's real identity through is a separate decision about
        // what the guest is allowed to observe.
        litebox_common_linux::TaskParams {
            pid: 1000,
            ppid: 0,
            uid: 1000,
            gid: 1000,
            euid: 1000,
            egid: 1000,
        }
    }
}

impl litebox::platform::Provider for MacOsUserland {}

// ---------------------------------------------------------------------------
// Memory
// ---------------------------------------------------------------------------

/// Translate LiteBox permissions into Darwin `PROT_*` bits.
fn prot_flags(permissions: MemoryRegionPermissions) -> libc::c_int {
    let mut prot = libc::PROT_NONE;
    if permissions.contains(MemoryRegionPermissions::READ) {
        prot |= libc::PROT_READ;
    }
    if permissions.contains(MemoryRegionPermissions::WRITE) {
        prot |= libc::PROT_WRITE;
    }
    if permissions.contains(MemoryRegionPermissions::EXEC) {
        prot |= libc::PROT_EXEC;
    }
    prot
}

/// Whether a mapping with these permissions needs `MAP_JIT`.
///
/// Darwin refuses to make anonymous memory executable through the ordinary
/// path, and refuses to add `PROT_EXEC` to anything that was ever writable.
/// `MAP_JIT` is the supported way to get an executable mapping the process can
/// also write to, at the cost of an entitlement and of having to bracket writes
/// with [`jit_write_protect`].
fn needs_jit(permissions: MemoryRegionPermissions) -> bool {
    permissions.contains(MemoryRegionPermissions::EXEC)
}

/// Enable or disable write access to this thread's `MAP_JIT` mappings.
///
/// Darwin makes `MAP_JIT` memory writable *or* executable per thread, never
/// both at once. Pass `false` to write to a JIT mapping and `true` to execute
/// from it again. This must bracket every write LiteBox makes into guest code
/// pages -- loading segments, and applying the rewriter's patches.
///
/// # Safety
///
/// Toggling write protection off makes every `MAP_JIT` mapping in the process
/// writable and non-executable for this thread, so no code may be executed out
/// of a JIT mapping until protection is restored.
pub unsafe fn jit_write_protect(executable: bool) {
    // SAFETY: the call has no preconditions beyond the ones the caller of this
    // function is documented to uphold.
    unsafe { darwin::pthread_jit_write_protect_np(libc::c_int::from(executable)) }
}

/// Allocate a `MAP_JIT` mapping, honoring `fixed_address_behavior` despite
/// Darwin refusing to combine `MAP_FIXED` with `MAP_JIT` in one `mmap` call.
///
/// The mapping is always created at a kernel-chosen address first. If no
/// fixed address was requested, that address is the answer. Otherwise it is
/// relocated to `suggested_range.start` with [`darwin::remap_to_fixed`],
/// which preserves the mapping's JIT-capable property across the move (see
/// that function's docs for the precedent this follows).
fn allocate_jit_pages(
    suggested_range: &core::ops::Range<usize>,
    initial_permissions: MemoryRegionPermissions,
    fixed_address_behavior: FixedAddressBehavior,
) -> Result<*mut libc::c_void, AllocationError> {
    // SAFETY: `MAP_JIT` cannot be combined with `MAP_FIXED`, so this always
    // requests a kernel-chosen address; there is no caller-owned range to
    // validate here beyond what `mmap` itself checks.
    let kernel_chosen = unsafe {
        libc::mmap(
            core::ptr::null_mut(),
            suggested_range.len(),
            prot_flags(initial_permissions),
            libc::MAP_PRIVATE | libc::MAP_ANON | MAP_JIT,
            -1,
            0,
        )
    };
    if kernel_chosen == libc::MAP_FAILED {
        return Err(match std::io::Error::last_os_error().raw_os_error() {
            Some(libc::EINVAL) => AllocationError::Unaligned,
            _ => AllocationError::OutOfMemory,
        });
    }

    if fixed_address_behavior == FixedAddressBehavior::Hint {
        return Ok(kernel_chosen);
    }

    let reserved = fixed_address_behavior == FixedAddressBehavior::NoReplace;
    if reserved {
        // `remap_to_fixed`'s `VM_FLAGS_OVERWRITE` silently replaces whatever
        // already occupies the destination, so `NoReplace` has to check
        // first -- exactly like the non-JIT path below does with a plain
        // `mmap(MAP_FIXED)`. The reservation itself then occupies the
        // destination until the remap overwrites it.
        if let Err(e) = reserve_fixed(suggested_range) {
            // SAFETY: `kernel_chosen` is the mapping just created above,
            // still solely owned by this function.
            unsafe { libc::munmap(kernel_chosen, suggested_range.len()) };
            return Err(match e {
                ReservationError::AddressInUse => AllocationError::AddressInUse,
                ReservationError::OutOfMemory => AllocationError::OutOfMemory,
            });
        }
    }

    // SAFETY: `kernel_chosen` is a live mapping of exactly this length,
    // created above and not otherwise in use yet.
    let remap_result = unsafe {
        remap_to_fixed(
            kernel_chosen as usize,
            suggested_range.len(),
            suggested_range.start,
        )
    };

    // `remap_to_fixed` aliases rather than moves: `kernel_chosen` is still a
    // live mapping of the same pages after a successful remap, and a
    // pointless one after a failed one either way. Drop it now so it never
    // leaks.
    // SAFETY: `kernel_chosen` is still a valid mapping owned by this
    // function; the remap above only added a second reference to the same
    // pages, it did not invalidate this one.
    unsafe { libc::munmap(kernel_chosen, suggested_range.len()) };

    match remap_result {
        Ok(()) => Ok(suggested_range.start as *mut libc::c_void),
        Err(e) => {
            if reserved {
                release_reservation(suggested_range);
            }
            Err(match e {
                ReservationError::AddressInUse => AllocationError::AddressInUse,
                ReservationError::OutOfMemory => AllocationError::OutOfMemory,
            })
        }
    }
}

/// Move `range`'s contents onto a fresh `MAP_JIT` mapping so the range can
/// gain `PROT_EXEC`, then apply `new_permissions`.
///
/// See `update_permissions` for why this exists: `MAP_JIT`-ness is decided at
/// mapping creation, so an ordinary mapping that later needs `EXEC` has to be
/// replaced, not re-protected. The replacement preserves contents (copied
/// under a temporary read-only view of the old mapping) and address (via
/// `remap_to_fixed`), which together make it look like the `mprotect` simply
/// succeeded.
///
/// On failure the range may be left readable-only rather than with its
/// original permissions -- the original protection is not known here, and
/// every failure below is one the caller treats as the mapping being gone.
///
/// # Safety
///
/// As for `update_permissions`: the caller guarantees `range` is a live
/// mapping whose contents are not concurrently in use, and that the
/// permission change does not conflict with any active use.
unsafe fn migrate_range_to_jit(
    range: &core::ops::Range<usize>,
    new_permissions: MemoryRegionPermissions,
) -> Result<(), PermissionUpdateError> {
    // The old contents have to be readable to copy out. The caller asked for
    // this range's permissions to change anyway, so a temporary read-only
    // view is within its guarantee.
    // SAFETY: forwarded caller guarantee, per this function's safety doc.
    let rc = unsafe {
        libc::mprotect(
            range.start as *mut libc::c_void,
            range.len(),
            libc::PROT_READ,
        )
    };
    if rc != 0 {
        return Err(PermissionUpdateError::Unallocated);
    }

    // SAFETY: an anonymous mapping at a kernel-chosen address has nothing to
    // validate beyond what `mmap` itself checks.
    let jit = unsafe {
        libc::mmap(
            core::ptr::null_mut(),
            range.len(),
            libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
            libc::MAP_PRIVATE | libc::MAP_ANON | MAP_JIT,
            -1,
            0,
        )
    };
    if jit == libc::MAP_FAILED {
        return Err(PermissionUpdateError::Unallocated);
    }

    // SAFETY: no code is executed out of a JIT mapping between the toggles;
    // the copy below runs ordinary host code.
    unsafe { jit_write_protect(false) };
    // SAFETY: `jit` was just mapped with exactly this length, `range` is
    // readable per the mprotect above, and the two cannot overlap (`jit` is
    // fresh kernel-chosen pages).
    unsafe {
        core::ptr::copy_nonoverlapping(range.start as *const u8, jit.cast::<u8>(), range.len());
    }
    // SAFETY: write access was only needed for the copy above.
    unsafe { jit_write_protect(true) };

    // SAFETY: `jit` is a live mapping of exactly this length that only this
    // function references.
    let remapped = unsafe { remap_to_fixed(jit as usize, range.len(), range.start) };
    // A successful remap leaves `jit` as a second, now-redundant alias of the
    // same pages; a failed one leaves it as the only copy. Either way it must
    // not leak.
    // SAFETY: still a live mapping owned by this function.
    unsafe { libc::munmap(jit, range.len()) };
    if remapped.is_err() {
        return Err(PermissionUpdateError::Unallocated);
    }

    // SAFETY: forwarded caller guarantee, per this function's safety doc.
    let rc = unsafe {
        libc::mprotect(
            range.start as *mut libc::c_void,
            range.len(),
            prot_flags(new_permissions),
        )
    };
    if rc != 0 {
        return Err(PermissionUpdateError::Unallocated);
    }

    // The bytes now executable at `range` were written through a different
    // virtual address (the `jit` alias), so the instruction cache has no
    // reason to be coherent for them. Invalidate here rather than relying on
    // a caller: not every path that lands in `update_permissions` goes
    // through a shim-level choke point that flushes.
    // SAFETY: the range was just made executable and is mapped.
    unsafe { darwin::sys_icache_invalidate(range.start as *mut libc::c_void, range.len()) };
    Ok(())
}

impl<const ALIGN: usize> litebox::platform::PageManagementProvider<ALIGN> for MacOsUserland {
    /// The first 4 GiB of an arm64 Mach-O process is the `__PAGEZERO` segment:
    /// reserved, unmapped, and impossible to map over. Every guest address has
    /// to start above it, which is a real constraint on guest images -- an
    /// `ET_EXEC` binary linked at the customary `0x400000` cannot be loaded at
    /// its preferred address on this host.
    const TASK_ADDR_MIN: usize = 0x1_0000_0000;

    /// Deliberately conservative. The user half of an Apple Silicon address
    /// space is 47 bits wide, but the exact ceiling is a kernel implementation
    /// detail (`MACH_VM_MAX_ADDRESS`) rather than a stable interface, so this
    /// stops a bit below 2^46 -- 64 TiB of guest address space, comfortably
    /// inside any plausible limit.
    const TASK_ADDR_MAX: usize = 0x0000_4000_0000_0000;

    fn allocate_pages(
        &self,
        suggested_range: core::ops::Range<usize>,
        initial_permissions: MemoryRegionPermissions,
        _can_grow_down: bool,
        populate_pages_immediately: bool,
        fixed_address_behavior: FixedAddressBehavior,
    ) -> Result<Self::RawMutPointer<u8>, AllocationError> {
        if initial_permissions.contains(MemoryRegionPermissions::SHARED) {
            // A shared anonymous mapping needs a backing object on Darwin
            // (`MAP_SHARED|MAP_ANON` gives a per-process object, not one that
            // survives into a child), so it is not implemented rather than
            // silently wrong.
            return Err(AllocationError::OutOfMemory);
        }
        if !suggested_range.start.is_multiple_of(ALIGN)
            || !suggested_range.len().is_multiple_of(ALIGN)
        {
            return Err(AllocationError::Unaligned);
        }

        let ptr = if needs_jit(initial_permissions) {
            // See `allocate_jit_pages`: `MAP_FIXED` and `MAP_JIT` cannot be
            // combined in one `mmap` call on real Darwin.
            allocate_jit_pages(
                &suggested_range,
                initial_permissions,
                fixed_address_behavior,
            )?
        } else {
            // `MAP_FIXED_NOREPLACE` has no Darwin equivalent, so claim the
            // range through the Mach VM API first: this fails with
            // `KERN_NO_SPACE` when any part of the range is already mapped,
            // which is exactly the semantics being emulated. The `mmap` below
            // then replaces the reservation in place; if it fails, the
            // reservation is released so a failed allocation never
            // permanently claims the range.
            let reserved = fixed_address_behavior == FixedAddressBehavior::NoReplace;
            if reserved {
                reserve_fixed(&suggested_range).map_err(|e| match e {
                    ReservationError::AddressInUse => AllocationError::AddressInUse,
                    ReservationError::OutOfMemory => AllocationError::OutOfMemory,
                })?;
            }

            let mut flags = libc::MAP_PRIVATE | libc::MAP_ANON;
            if fixed_address_behavior != FixedAddressBehavior::Hint {
                flags |= libc::MAP_FIXED;
            }

            // SAFETY: an anonymous mapping has no file backing to validate,
            // and `MAP_FIXED` only replaces a range the caller has told us it
            // owns.
            let ptr = unsafe {
                libc::mmap(
                    suggested_range.start as *mut libc::c_void,
                    suggested_range.len(),
                    prot_flags(initial_permissions),
                    flags,
                    -1,
                    0,
                )
            };
            if ptr == libc::MAP_FAILED {
                if reserved {
                    release_reservation(&suggested_range);
                }
                // `EINVAL` from `mmap` here means a misaligned address or
                // length, since every other argument is fixed by this
                // function. Everything else -- `ENOMEM` included -- is
                // reported as exhaustion.
                return Err(match std::io::Error::last_os_error().raw_os_error() {
                    Some(libc::EINVAL) => AllocationError::Unaligned,
                    _ => AllocationError::OutOfMemory,
                });
            }
            ptr
        };

        if populate_pages_immediately {
            // The closest Darwin has to `MAP_POPULATE`. It is advisory, so a
            // failure only costs later faults and is not worth reporting.
            // SAFETY: the range was just mapped.
            unsafe { libc::madvise(ptr, suggested_range.len(), libc::MADV_WILLNEED) };
        }

        Ok(UserMutPtr::from_ptr(ptr.cast::<u8>()))
    }

    unsafe fn deallocate_pages(
        &self,
        range: core::ops::Range<usize>,
    ) -> Result<(), DeallocationError> {
        if !range.start.is_multiple_of(ALIGN) || !range.len().is_multiple_of(ALIGN) {
            return Err(DeallocationError::Unaligned);
        }
        // SAFETY: the caller guarantees the range is no longer in use.
        let rc = unsafe { libc::munmap(range.start as *mut libc::c_void, range.len()) };
        if rc == 0 {
            Ok(())
        } else {
            Err(DeallocationError::AlreadyUnallocated)
        }
    }

    unsafe fn update_permissions(
        &self,
        range: core::ops::Range<usize>,
        new_permissions: MemoryRegionPermissions,
    ) -> Result<(), PermissionUpdateError> {
        if !range.start.is_multiple_of(ALIGN) || !range.len().is_multiple_of(ALIGN) {
            return Err(PermissionUpdateError::Unaligned);
        }
        // SAFETY: the caller guarantees the new permissions do not conflict with
        // any active use of the range.
        let rc = unsafe {
            libc::mprotect(
                range.start as *mut libc::c_void,
                range.len(),
                prot_flags(new_permissions),
            )
        };
        if rc == 0 {
            return Ok(());
        }
        if new_permissions.contains(MemoryRegionPermissions::EXEC) {
            // Adding `PROT_EXEC` to an ordinary mapping is exactly the case
            // Darwin's W^X policy refuses: only a `MAP_JIT` mapping may become
            // executable, and `MAP_JIT`-ness can only be chosen at creation.
            // Every RW-then-RX code path in LiteBox (`create_executable_pages`
            // allocates RW and flips to RX after the loader writes the bytes,
            // and a JIT-ing guest's own mmap(RW)/mprotect(RX) does the same)
            // lands here, so this is the load-bearing path for executable
            // pages on this host, not an obscure fallback.
            //
            // SAFETY: forwarded caller guarantee, as above.
            return unsafe { migrate_range_to_jit(&range, new_permissions) };
        }
        Err(PermissionUpdateError::Unallocated)
    }

    fn reserved_pages(&self) -> impl Iterator<Item = &core::ops::Range<usize>> {
        self.reserved_pages.iter()
    }

    unsafe fn jit_write_protect(&self, executable: bool) {
        // SAFETY: forwarded caller guarantee; see the trait method's docs,
        // which describe exactly this platform's `MAP_JIT` semantics.
        unsafe { darwin::pthread_jit_write_protect_np(libc::c_int::from(executable)) }
    }

    /// Maps a registered CoW region straight from its backing file via
    /// `mmap(MAP_PRIVATE)`, instead of the default (allocate-and-memcpy)
    /// behavior. Mirrors `litebox_platform_linux_userland`'s implementation of
    /// the same trait method; see [`Self::register_cow_region`] for how a
    /// region becomes eligible.
    fn try_allocate_cow_pages(
        &self,
        suggested_start: usize,
        source_data: &'static [u8],
        permissions: MemoryRegionPermissions,
        fixed_address_behavior: FixedAddressBehavior,
    ) -> Result<Self::RawMutPointer<u8>, litebox::platform::page_mgmt::CowAllocationError> {
        use litebox::platform::page_mgmt::CowAllocationError;

        if permissions.contains(MemoryRegionPermissions::EXEC) {
            // A file-backed `PROT_EXEC` mapping on Apple Silicon must pass
            // code-signature validation, which an unsigned Linux guest image
            // cannot. The memcpy fallback path handles executable segments
            // instead: it allocates anonymous pages (which become `MAP_JIT`
            // when they gain `EXEC`) and copies the bytes in.
            return Err(CowAllocationError::UnsupportedSourceRegion);
        }

        let Some((file_path, file_offset)) = self.lookup_cow_region(source_data) else {
            return Err(CowAllocationError::UnsupportedSourceRegion);
        };
        if !file_offset.is_multiple_of(ALIGN) || !suggested_start.is_multiple_of(ALIGN) {
            return Err(CowAllocationError::Unaligned);
        }
        let mapped_range = suggested_start..suggested_start + source_data.len();

        let reserved = fixed_address_behavior == FixedAddressBehavior::NoReplace;
        if reserved && reserve_fixed(&mapped_range).is_err() {
            return Err(CowAllocationError::InternalFailure);
        }

        let Ok(file_path_cstr) = std::ffi::CString::new(file_path.as_os_str().as_encoded_bytes())
        else {
            if reserved {
                release_reservation(&mapped_range);
            }
            return Err(CowAllocationError::InternalFailure);
        };
        // SAFETY: `file_path_cstr` is a live, NUL-terminated path.
        let fd = unsafe { libc::open(file_path_cstr.as_ptr(), libc::O_RDONLY) };
        if fd < 0 {
            if reserved {
                release_reservation(&mapped_range);
            }
            // The backing file changing out from under a running LiteBox
            // instance is not a condition normal operation can recover from --
            // matches `litebox_platform_linux_userland`'s identical assumption.
            panic!(
                "CoW-registered file should remain unchanged on host: {}",
                file_path.display()
            );
        }

        let Ok(offset) = libc::off_t::try_from(file_offset) else {
            // SAFETY: `fd` is open and not used past this point.
            unsafe { libc::close(fd) };
            if reserved {
                release_reservation(&mapped_range);
            }
            return Err(CowAllocationError::InternalFailure);
        };

        let mut flags = libc::MAP_PRIVATE;
        if fixed_address_behavior != FixedAddressBehavior::Hint {
            flags |= libc::MAP_FIXED;
        }

        // SAFETY: `fd` was just opened read-only from a path this platform
        // itself registered, and `MAP_FIXED` only replaces a range the caller
        // (or the reservation above) has claimed for this mapping.
        let ptr = unsafe {
            libc::mmap(
                suggested_start as *mut libc::c_void,
                source_data.len(),
                prot_flags(permissions),
                flags,
                fd,
                offset,
            )
        };
        // SAFETY: `fd` is open and not used past this point.
        unsafe { libc::close(fd) };

        if ptr == libc::MAP_FAILED {
            if reserved {
                release_reservation(&mapped_range);
            }
            return Err(CowAllocationError::InternalFailure);
        }
        Ok(UserMutPtr::from_ptr(ptr.cast::<u8>()))
    }
}

/// Enumerate the process's existing mappings so the guest is never offered an
/// address that dyld, the shared cache or the host heap already owns.
///
/// This is the Mach counterpart of the Windows platform's `VirtualQuery` walk.
fn read_memory_maps() -> alloc::vec::Vec<core::ops::Range<usize>> {
    mach_vm_region_iter().collect()
}

// ---------------------------------------------------------------------------
// Locking
// ---------------------------------------------------------------------------

impl litebox::platform::RawMutexProvider for MacOsUserland {
    type RawMutex = RawMutex;
}

/// A futex-equivalent built on Darwin's `ulock` compare-and-wait primitives.
pub struct RawMutex {
    inner: AtomicU32,
}

impl litebox::platform::RawMutex for RawMutex {
    const INIT: Self = Self {
        inner: AtomicU32::new(0),
    };

    fn underlying_atomic(&self) -> &AtomicU32 {
        &self.inner
    }

    fn wake_many(&self, n: usize) -> usize {
        // `ulock` can wake exactly one waiter or all of them, with nothing in
        // between, so anything above one wakes all. The trait permits this: a
        // wake is allowed to be spurious, and the return value is allowed to be
        // zero on a platform that cannot count what it woke -- which Darwin
        // cannot.
        ulock_wake(&self.inner, n > 1);
        0
    }

    fn block(&self, val: u32) -> Result<(), ImmediatelyWokenUp> {
        match self.block_inner(val, None) {
            Ok(UnblockedOrTimedOut::Unblocked) => Ok(()),
            Ok(UnblockedOrTimedOut::TimedOut) => {
                unreachable!("a wait with no deadline cannot time out")
            }
            Err(ImmediatelyWokenUp) => Err(ImmediatelyWokenUp),
        }
    }

    fn block_or_timeout(
        &self,
        val: u32,
        time: Duration,
    ) -> Result<UnblockedOrTimedOut, ImmediatelyWokenUp> {
        self.block_inner(val, Some(time))
    }
}

impl RawMutex {
    fn block_inner(
        &self,
        val: u32,
        timeout: Option<Duration>,
    ) -> Result<UnblockedOrTimedOut, ImmediatelyWokenUp> {
        match ulock_wait(&self.inner, val, timeout) {
            darwin::UlockWaitResult::Woken => Ok(UnblockedOrTimedOut::Unblocked),
            darwin::UlockWaitResult::TimedOut => Ok(UnblockedOrTimedOut::TimedOut),
            darwin::UlockWaitResult::ValueChanged => Err(ImmediatelyWokenUp),
        }
    }
}

// ---------------------------------------------------------------------------
// Time
// ---------------------------------------------------------------------------

/// A point on Darwin's monotonic clock, in nanoseconds.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Instant(u64);

impl litebox::platform::Instant for Instant {
    fn checked_duration_since(&self, earlier: &Self) -> Option<Duration> {
        self.0.checked_sub(earlier.0).map(Duration::from_nanos)
    }

    fn checked_add(&self, duration: Duration) -> Option<Self> {
        u64::try_from(duration.as_nanos())
            .ok()
            .and_then(|nanos| self.0.checked_add(nanos))
            .map(Self)
    }
}

/// A point on Darwin's wall clock, relative to the Unix epoch.
pub struct SystemTime {
    nanos_since_epoch: i128,
}

impl litebox::platform::SystemTime for SystemTime {
    const UNIX_EPOCH: Self = Self {
        nanos_since_epoch: 0,
    };

    fn duration_since(&self, earlier: &Self) -> Result<Duration, Duration> {
        let delta = self.nanos_since_epoch - earlier.nanos_since_epoch;
        let magnitude = Duration::from_nanos(delta.unsigned_abs().try_into().unwrap_or(u64::MAX));
        if delta < 0 {
            Err(magnitude)
        } else {
            Ok(magnitude)
        }
    }
}

impl litebox::platform::TimeProvider for MacOsUserland {
    type Instant = Instant;
    type SystemTime = SystemTime;

    fn now(&self) -> Self::Instant {
        // `CLOCK_MONOTONIC_RAW` is unaffected by NTP slewing or wall-clock
        // adjustment, which is all `Instant` requires: monotonic, with no
        // particular relationship to wall time. (Its exact behavior across
        // system sleep is a separate question the trait does not depend on.)
        Instant(darwin::clock_gettime_nanos(libc::CLOCK_MONOTONIC_RAW))
    }

    fn current_time(&self) -> Self::SystemTime {
        SystemTime {
            nanos_since_epoch: i128::from(darwin::clock_gettime_nanos(libc::CLOCK_REALTIME)),
        }
    }
}

// ---------------------------------------------------------------------------
// Architecture-specific state
// ---------------------------------------------------------------------------

std::thread_local! {
    /// The guest's virtualized `TPIDR_EL0`.
    ///
    /// The host owns the hardware register as its own per-thread anchor, so the
    /// guest's thread pointer lives here instead. This is the slot the aarch64
    /// syscall rewriter's `MRS`/`MSR` gates read and write on the guest's behalf.
    static GUEST_TPIDR_EL0: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
}

impl litebox::platform::ArchSpecificProvider for MacOsUserland {
    fn get_arch_specific_register(
        &self,
        reg: &litebox::platform::ArchSpecificRegister,
    ) -> Result<usize, litebox::platform::ArchSpecificError> {
        match reg {
            litebox::platform::ArchSpecificRegister::TpidrEl0 => Ok(GUEST_TPIDR_EL0.get()),
            _ => Err(litebox::platform::ArchSpecificError::RegisterUnsupported),
        }
    }

    fn set_arch_specific_register(
        &self,
        reg: &litebox::platform::ArchSpecificRegister,
        val: usize,
    ) -> Result<(), litebox::platform::ArchSpecificError> {
        match reg {
            litebox::platform::ArchSpecificRegister::TpidrEl0 => {
                // No range check is needed: the value never reaches a hardware
                // register, so an invalid one can only fault the guest that
                // dereferences it.
                GUEST_TPIDR_EL0.set(val);
                Ok(())
            }
            _ => Err(litebox::platform::ArchSpecificError::RegisterUnsupported),
        }
    }
}

// ---------------------------------------------------------------------------
// Pointers
// ---------------------------------------------------------------------------

type UserConstPtr<T> = litebox::platform::common_providers::userspace_pointers::UserConstPtr<
    litebox::platform::common_providers::userspace_pointers::NoValidation,
    T,
>;
type UserMutPtr<T> = litebox::platform::common_providers::userspace_pointers::UserMutPtr<
    litebox::platform::common_providers::userspace_pointers::NoValidation,
    T,
>;

impl litebox::platform::RawPointerProvider for MacOsUserland {
    type RawConstPointer<T: FromBytes> = UserConstPtr<T>;
    type RawMutPointer<T: FromBytes + IntoBytes> = UserMutPtr<T>;
}

// ---------------------------------------------------------------------------
// Standard I/O
// ---------------------------------------------------------------------------

impl litebox::platform::StdioProvider for MacOsUserland {
    fn read_from_stdin(&self, buf: &mut [u8]) -> Result<usize, litebox::platform::StdioReadError> {
        // SAFETY: `buf` is a valid writable slice of the length passed.
        let n = unsafe {
            libc::read(
                libc::STDIN_FILENO,
                buf.as_mut_ptr().cast::<libc::c_void>(),
                buf.len(),
            )
        };
        usize::try_from(n).map_err(|_| litebox::platform::StdioReadError::Closed)
    }

    fn write_to(
        &self,
        stream: litebox::platform::StdioOutStream,
        buf: &[u8],
    ) -> Result<usize, litebox::platform::StdioWriteError> {
        let fd = match stream {
            litebox::platform::StdioOutStream::Stdout => libc::STDOUT_FILENO,
            litebox::platform::StdioOutStream::Stderr => libc::STDERR_FILENO,
        };
        // SAFETY: `buf` is a valid readable slice of the length passed.
        let n = unsafe { libc::write(fd, buf.as_ptr().cast::<libc::c_void>(), buf.len()) };
        usize::try_from(n).map_err(|_| litebox::platform::StdioWriteError::Closed)
    }

    fn is_a_tty(&self, stream: litebox::platform::StdioStream) -> bool {
        self.stdio_is_tty[stream as usize]
    }
}

// ---------------------------------------------------------------------------
// System information
// ---------------------------------------------------------------------------

impl litebox::platform::SystemInfoProvider for MacOsUserland {
    fn get_syscall_entry_point(&self) -> usize {
        guest::syscall_callback as *const () as usize
    }

    fn get_vdso_address(&self) -> Option<usize> {
        // A Linux guest's vDSO would have to be a LiteBox-provided image; the
        // host's own `commpage` is not one. Reporting `None` means the guest
        // falls back to real syscalls, which is what the shim wants anyway --
        // but it also means a guest signal handler needs its own `sa_restorer`,
        // because the kernel's fallback trampoline lives in the vDSO.
        None
    }
}

// ---------------------------------------------------------------------------
// Thread-local storage
// ---------------------------------------------------------------------------

std::thread_local! {
    static PLATFORM_TLS: core::cell::Cell<*mut ()> =
        const { core::cell::Cell::new(core::ptr::null_mut()) };
}

// SAFETY: the pointer returned is exactly the one most recently stored for this
// thread, and a thread that has stored nothing reads back the null the cell was
// initialized with.
unsafe impl litebox::platform::ThreadLocalStorageProvider for MacOsUserland {
    fn get_thread_local_storage() -> *mut () {
        PLATFORM_TLS.get()
    }

    unsafe fn replace_thread_local_storage(value: *mut ()) -> *mut () {
        PLATFORM_TLS.replace(value)
    }
}

// ---------------------------------------------------------------------------
// Randomness and derived keys
// ---------------------------------------------------------------------------

impl litebox::platform::CrngProvider for MacOsUserland {
    fn fill_bytes_crng(&self, buf: &mut [u8]) {
        // `arc4random_buf` is the platform's own CSPRNG: it cannot fail, cannot
        // block, and the kernel reseeds it across `fork` and VM snapshots. That
        // pass-through is precisely what the trait asks for.
        //
        // SAFETY: `buf` is a valid writable slice of the length passed.
        unsafe { libc::arc4random_buf(buf.as_mut_ptr().cast::<libc::c_void>(), buf.len()) };
    }
}

impl litebox::platform::DerivedKeyProvider for MacOsUserland {
    fn derive_key<E>(
        &self,
        shim_kdf: Option<fn(&[u8], litebox::platform::KDFParams) -> Result<(), E>>,
        params: litebox::platform::KDFParams,
    ) -> Result<(), litebox::platform::DerivedKeyError<E>> {
        let Some(boot_id) = self.boot_id.get() else {
            return Err(litebox::platform::DerivedKeyError::UnsupportedRebootPersistentKey);
        };
        let Some(shim_kdf) = shim_kdf else {
            // Darwin exposes no KDF of its own that is rooted in a device
            // secret, so a shim that brings none cannot be served here.
            return Err(litebox::platform::DerivedKeyError::ShimKDFRequired);
        };
        // The shim shares this platform's trust boundary, so the root key can be
        // handed to it directly rather than pre-hashed.
        Ok(shim_kdf(boot_id, params)?)
    }
}

// ---------------------------------------------------------------------------
// Signals
// ---------------------------------------------------------------------------

/// Asynchronous host signals observed since the guest last drained them.
///
/// Bit `n - 1` corresponds to signal number `n`, matching `SigSet`'s encoding.
static PENDING_SIGNALS: AtomicU64 = AtomicU64::new(0);

unsafe extern "C" fn async_signal_handler(signum: libc::c_int) {
    if let Ok(bit) = u32::try_from(signum - 1) {
        PENDING_SIGNALS.fetch_or(1u64 << bit, Ordering::Relaxed);
    }
}

/// The interrupt signal exists only to kick a thread out of a blocking call;
/// the handler itself has nothing to do.
unsafe extern "C" fn interrupt_signal_handler(_signum: libc::c_int) {}

fn install_async_signal_handlers() {
    for signum in [libc::SIGINT, libc::SIGALRM] {
        darwin::install_handler(signum, async_signal_handler as *const () as usize, false);
    }
    // `SA_RESTART` is deliberately absent: interrupting a blocking call is the
    // entire purpose of this signal.
    darwin::install_handler(
        INTERRUPT_SIGNAL,
        interrupt_signal_handler as *const () as usize,
        false,
    );
}

impl litebox::platform::SignalProvider for MacOsUserland {
    type Signal = litebox_common_linux::signal::Signal;

    fn take_pending_signals(&self, mut f: impl FnMut(Self::Signal)) {
        let mut pending = PENDING_SIGNALS.swap(0, Ordering::Relaxed);
        while pending != 0 {
            let bit = pending.trailing_zeros();
            pending &= !(1u64 << bit);
            // Host and guest signal numbers agree for the small set of
            // asynchronous signals handled here.
            if let Ok(signal) =
                litebox_common_linux::signal::Signal::try_from(bit.cast_signed() + 1)
            {
                f(signal);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Timers
// ---------------------------------------------------------------------------

/// A one-shot timer.
///
/// Darwin has neither POSIX `timer_create` nor more than one `setitimer` per
/// process, so each timer owns a thread that sleeps until its deadline and then
/// fires. The thread is parked on a condition variable when no deadline is
/// armed, so an idle timer costs nothing but its stack.
///
/// Firing has two jobs, and getting only one of them right is a bug that is
/// easy not to notice: it must both (1) record the *guest*'s chosen signal as
/// pending, and (2) actually wake the guest thread that may be blocked
/// waiting on it (in [`litebox::event::wait::WaitContext::sleep`], backed by
/// this platform's `RawMutex::block_or_timeout`). Recording the pending bit
/// alone is not observable by a thread parked in `ulock_wait2` -- nothing
/// re-evaluates its wait condition until something wakes it. So the timer
/// thread also signals the thread that created it (captured at
/// [`TimerProvider::create_timer`]-time) with `INTERRUPT_SIGNAL`, the same
/// signal [`ThreadProvider::interrupt_thread`] uses purely to interrupt a
/// blocking syscall with `EINTR` -- never `SIGALRM`, which would spuriously
/// mark the *host's* SIGALRM as pending too, even for a timer configured for
/// an unrelated guest signal.
///
/// This needs no OS-level timer or real signal payload to report which guest
/// signal fired (contrast `litebox_platform_linux_userland`, which encodes it
/// in `sigev_value` because its timer genuinely is external kernel state): the
/// timer never leaves this process, so the firing thread can just write the
/// pending-signals bitmap directly before waking the target.
///
/// [`TimerProvider::create_timer`]: litebox::platform::TimerProvider::create_timer
/// [`ThreadProvider::interrupt_thread`]: litebox::platform::ThreadProvider::interrupt_thread
pub struct TimerHandle {
    state: Arc<TimerState>,
}

struct TimerState {
    /// The deadline, or `None` when disarmed. `Condvar` wakes the timer thread
    /// whenever this changes.
    deadline: Mutex<TimerCommand>,
    changed: Condvar,
    /// The guest signal to record as pending when this timer fires.
    signal: litebox_common_linux::signal::Signal,
    /// The thread to wake on fire -- the one that called
    /// [`TimerProvider::create_timer`](litebox::platform::TimerProvider::create_timer),
    /// captured once so a guest that arms the timer and then blocks elsewhere
    /// (the common case: `timer_create` then `nanosleep`) is still reached.
    target: ThreadHandle,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum TimerCommand {
    Disarmed,
    ArmedFor(std::time::Instant),
    Deleted,
}

impl litebox::platform::TimerProvider for MacOsUserland {
    type TimerHandle = TimerHandle;
    type Signal = litebox_common_linux::signal::Signal;

    fn create_timer(
        &self,
        signal: Self::Signal,
    ) -> Result<Self::TimerHandle, litebox::platform::TimerCreationError> {
        let state = Arc::new(TimerState {
            deadline: Mutex::new(TimerCommand::Disarmed),
            changed: Condvar::new(),
            signal,
            target: ThreadHandle::current(),
        });
        let thread_state = Arc::clone(&state);
        std::thread::Builder::new()
            .name("litebox-timer".into())
            .spawn(move || timer_thread(&thread_state))
            .map_err(|_| litebox::platform::TimerCreationError::Unsupported)?;
        Ok(TimerHandle { state })
    }
}

fn timer_thread(state: &TimerState) {
    let mut command = state.deadline.lock().unwrap();
    loop {
        match *command {
            TimerCommand::Deleted => return,
            TimerCommand::Disarmed => {
                command = state.changed.wait(command).unwrap();
            }
            TimerCommand::ArmedFor(deadline) => {
                let Some(remaining) = deadline.checked_duration_since(std::time::Instant::now())
                else {
                    // Fire, then disarm -- these timers are one-shot. Record the
                    // configured guest signal, then wake the target thread; see
                    // the `TimerHandle` docs for why both steps are required and
                    // why the wakeup must not be `SIGALRM`.
                    *command = TimerCommand::Disarmed;
                    let bit = (state.signal.as_i32() - 1).cast_unsigned();
                    PENDING_SIGNALS.fetch_or(1u64 << bit, Ordering::Relaxed);
                    state.target.interrupt();
                    continue;
                };
                let (next, _) = state.changed.wait_timeout(command, remaining).unwrap();
                command = next;
            }
        }
    }
}

impl litebox::platform::TimerHandle for TimerHandle {
    fn set_timer(&self, duration: Duration) {
        let mut command = self.state.deadline.lock().unwrap();
        *command = if duration.is_zero() {
            TimerCommand::Disarmed
        } else {
            TimerCommand::ArmedFor(std::time::Instant::now() + duration)
        };
        drop(command);
        self.state.changed.notify_all();
    }

    fn delete_timer(self) {
        let mut command = self.state.deadline.lock().unwrap();
        *command = TimerCommand::Deleted;
        drop(command);
        self.state.changed.notify_all();
    }
}

// ---------------------------------------------------------------------------
// Threads
// ---------------------------------------------------------------------------

/// A `pthread_t` is an opaque pointer on Darwin, so it needs an explicit
/// `Send`/`Sync` witness to travel between threads.
#[derive(Clone, Copy)]
struct ThreadId(libc::pthread_t);

// SAFETY: the identifier is only ever handed back to `pthread_kill`, which is
// itself thread-safe, and [`ThreadHandle`] clears it before the thread it names
// can exit, so it is never used to signal a dead thread.
unsafe impl Send for ThreadId {}
// SAFETY: see the `Send` witness above.
unsafe impl Sync for ThreadId {}

/// A handle to a LiteBox-managed thread, used to interrupt it.
pub struct ThreadHandle(Arc<Mutex<Option<ThreadId>>>);

impl Clone for ThreadHandle {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

std::thread_local! {
    static CURRENT_THREAD: core::cell::RefCell<Option<ThreadHandle>> =
        const { core::cell::RefCell::new(None) };
}

impl ThreadHandle {
    /// Runs `f` with a handle registered for the current thread, so that
    /// [`litebox::platform::ThreadProvider::current_thread`] works inside it.
    fn run_with_handle<R>(f: impl FnOnce() -> R) -> R {
        // SAFETY: `pthread_self` has no preconditions.
        let handle = ThreadHandle(Arc::new(Mutex::new(Some(ThreadId(unsafe {
            libc::pthread_self()
        })))));
        CURRENT_THREAD.with_borrow_mut(|current| {
            assert!(
                current.is_none(),
                "nested run_with_handle calls are not supported"
            );
            *current = Some(handle);
        });
        let _guard = litebox::utils::defer(|| {
            let current = CURRENT_THREAD.take().expect("handle registered above");
            // Clearing before the thread exits is what makes signalling a stale
            // `pthread_t` impossible.
            *current.0.lock().unwrap() = None;
        });
        f()
    }

    fn current() -> Self {
        CURRENT_THREAD.with_borrow(|thread| {
            thread
                .clone()
                .expect("current_thread called outside of a LiteBox thread")
        })
    }

    fn interrupt(&self) {
        if let Some(thread) = *self.0.lock().unwrap() {
            // SAFETY: the identifier is live for as long as this lock is held.
            unsafe { libc::pthread_kill(thread.0, INTERRUPT_SIGNAL) };
        }
    }
}

impl litebox::platform::ThreadProvider for MacOsUserland {
    type ExecutionContext = litebox_common_linux::PtRegs;
    type ThreadSpawnError = std::io::Error;
    type ThreadHandle = ThreadHandle;

    unsafe fn spawn_thread(
        &self,
        ctx: &litebox_common_linux::PtRegs,
        init_thread: alloc::boxed::Box<
            dyn litebox::shim::InitThread<ExecutionContext = litebox_common_linux::PtRegs>,
        >,
    ) -> Result<(), Self::ThreadSpawnError> {
        let mut ctx = ctx.clone();
        std::thread::Builder::new()
            .name("litebox-guest".into())
            .spawn(move || {
                // Let the shim set up its per-thread state before the new thread
                // reaches guest code.
                let shim = init_thread.init();
                ThreadHandle::run_with_handle(|| guest::run_thread(shim.as_ref(), &mut ctx));
            })?;
        Ok(())
    }

    fn current_thread(&self) -> Self::ThreadHandle {
        ThreadHandle::current()
    }

    fn interrupt_thread(&self, thread: &Self::ThreadHandle) {
        thread.interrupt();
    }

    #[cfg(debug_assertions)]
    fn run_test_thread<R>(f: impl FnOnce() -> R) -> R {
        ThreadHandle::run_with_handle(f)
    }
}

// ---------------------------------------------------------------------------
// Networking
// ---------------------------------------------------------------------------

impl litebox::platform::IPInterfaceProvider for MacOsUserland {
    fn send_ip_packet(&self, packet: &[u8]) -> Result<(), litebox::platform::SendError> {
        // Without a `utun` device there is nowhere for the packet to go.
        // `SendError` is `#[non_exhaustive]` with no variants, so silently
        // dropping is the only representable outcome -- and it matches what a
        // guest with no configured interface should observe.
        if let Some(tun) = self.tun.as_ref() {
            net::write_packet(tun, packet);
        }
        Ok(())
    }

    fn receive_ip_packet(
        &self,
        packet: &mut [u8],
    ) -> Result<usize, litebox::platform::ReceiveError> {
        let Some(tun) = self.tun.as_ref() else {
            return Err(litebox::platform::ReceiveError::WouldBlock);
        };
        net::read_packet(tun, packet).ok_or(litebox::platform::ReceiveError::WouldBlock)
    }
}

// ---------------------------------------------------------------------------
// Guest thread pointer
// ---------------------------------------------------------------------------

/// The pthread TSD key LiteBox reserved for the guest thread pointer, or
/// `u32::MAX` before [`reserve_guest_tpidr_tsd_slot`] has run.
static GUEST_TP_TSD_KEY: AtomicU32 = AtomicU32::new(u32::MAX);

/// Reserve the pthread TSD slot the rewriter's `Host::MacOs` gates read the
/// guest thread pointer from, recording it in [`GUEST_TP_TSD_KEY`].
///
/// `litebox_syscall_rewriter::arm64`'s `Host::MacOs` gates are emitted
/// *ahead of time*, when a binary is packaged -- they have
/// `litebox_syscall_rewriter::MACOS_GUEST_TPIDR_TSD_SLOT` baked in as a fixed
/// byte offset from `TPIDRRO_EL0`. For that to line up at guest-run time, this
/// process's first `pthread_key_create` call would have to return exactly that
/// slot. **It does not, and cannot be relied upon to:** measured on real
/// hardware (Apple M3 Pro, macOS 26.3.1), the first dynamic key is 259 from a
/// Rust binary and 258 from a C `main` -- libSystem's own startup claims a few
/// dynamic keys first, and that count is undocumented and not stable across OS
/// versions or across binaries with different static initializers. The AOT
/// rewriter (a separate, earlier process) therefore cannot predict the runner's
/// slot; a fixed baked immediate is fundamentally the wrong model. The real fix
/// is load-time offset indirection (see the `macos-guest-tp-runtime-offset`
/// roadmap item and `docs/roadmap.md`).
///
/// Until that lands, this reserves a key and records it, but does **not** hard
/// fail on a mismatch: panicking here made the whole platform unconstructable
/// on real hardware, blocking everything else (memory, syscalls, the context
/// switch) that does not touch the guest thread pointer at all. Instead it
/// warns loudly. A guest that never reads/writes `TPIDR_EL0` is unaffected; a
/// guest that does would target the stale baked slot and is **not supported**
/// until the load-time fix -- no macOS runner loads guests yet, so nothing hits
/// this path in production today.
///
/// # Panics
///
/// Panics only if `pthread_key_create` itself fails (genuine resource
/// exhaustion), not on a slot-number mismatch.
fn reserve_guest_tpidr_tsd_slot() -> libc::pthread_key_t {
    let mut key: libc::pthread_key_t = 0;
    // SAFETY: `key` is a valid, uniquely-owned out-parameter; no destructor is
    // needed since the platform (not pthread teardown) manages the guest
    // thread pointer's lifetime.
    let rc = unsafe { libc::pthread_key_create(&raw mut key, None) };
    assert_eq!(
        rc, 0,
        "failed to reserve the guest thread-pointer TSD slot: pthread_key_create returned {rc}"
    );
    GUEST_TP_TSD_KEY.store(u32::try_from(key).unwrap_or(u32::MAX), Ordering::Relaxed);

    let baked = litebox_syscall_rewriter::MACOS_GUEST_TPIDR_TSD_SLOT;
    if u16::try_from(key).ok() != Some(baked) {
        litebox_util_log::warn!(
            key:? = key, baked_slot:? = baked;
            "guest thread-pointer TSD slot mismatch: pthread_key_create gave a slot the \
             AOT-rewritten Host::MacOs gates do not use. Guests that access TPIDR_EL0 are \
             unsupported until load-time offset indirection lands (see docs/roadmap.md, \
             macos-guest-tp-runtime-offset). Syscall-only guests are unaffected."
        );
    }
    key
}

/// Reserving the guest thread-pointer TSD slot must not panic on real hardware
/// even when the runtime key does not match the AOT-baked slot (it never does;
/// see [`reserve_guest_tpidr_tsd_slot`]). A hard panic here previously made the
/// whole platform unconstructable.
#[cfg(test)]
#[test]
fn reserving_the_tsd_slot_does_not_panic_on_mismatch() {
    let key = reserve_guest_tpidr_tsd_slot();
    assert_eq!(
        GUEST_TP_TSD_KEY.load(Ordering::Relaxed),
        u32::try_from(key).unwrap(),
        "the reserved key should be recorded for the future load-time-offset fix"
    );
}

// ---------------------------------------------------------------------------
// Faults
// ---------------------------------------------------------------------------

/// Install the handlers that make LiteBox's accesses to guest memory fallible.
///
/// Without these, a `UserConstPtr` read of an unmapped guest address takes the
/// process down instead of returning `None`; see
/// [`litebox::platform::common_providers::userspace_pointers`].
fn install_fault_handlers() {
    for signum in [libc::SIGSEGV, libc::SIGBUS] {
        darwin::install_handler(signum, fault_handler as *const () as usize, true);
    }
}

unsafe extern "C" fn fault_handler(
    signum: libc::c_int,
    _info: *mut libc::siginfo_t,
    ucontext: *mut libc::c_void,
) {
    // SAFETY: the kernel hands a `ucontext_t` to an `SA_SIGINFO` handler, and
    // its `uc_mcontext` points at a `_STRUCT_MCONTEXT64` on this architecture.
    let machine_context = unsafe {
        let ucontext = ucontext.cast::<libc::ucontext_t>();
        if ucontext.is_null() {
            darwin::reraise_fatally(signum);
            return;
        }
        (*ucontext).uc_mcontext.cast::<darwin::McontextPrefix64>()
    };
    if machine_context.is_null() {
        darwin::reraise_fatally(signum);
        return;
    }

    // SAFETY: checked non-null just above.
    let pc = unsafe { (*machine_context).thread_state.pc };
    if let Some(recovery) = litebox::mm::exception_table::search_exception_tables(pc.trunc()) {
        // A LiteBox access to guest memory faulted and the exception table says
        // where to continue; redirecting the program counter is what turns the
        // fault into a `None` return.
        //
        // SAFETY: checked non-null just above.
        unsafe { (*machine_context).thread_state.pc = recovery as u64 };
        return;
    }

    // Not a recoverable LiteBox access. Restore the default disposition and
    // return so the faulting instruction re-executes and takes the process down
    // exactly as it would have without this handler installed.
    darwin::reraise_fatally(signum);
}

/// Page faults are serviced by the host kernel, so LiteBox never handles one
/// itself here. Provided to satisfy the trait bound on `PageManager`.
impl litebox::mm::linux::VmemPageFaultHandler for MacOsUserland {
    unsafe fn handle_page_fault(
        &self,
        _fault_addr: usize,
        _flags: litebox::mm::linux::VmFlags,
        _error_code: u64,
    ) -> Result<(), litebox::mm::linux::PageFaultError> {
        unreachable!("host kernel handles page faults for macOS userland")
    }

    fn access_error(_error_code: u64, _flags: litebox::mm::linux::VmFlags) -> bool {
        unreachable!("host kernel handles page faults for macOS userland")
    }
}
