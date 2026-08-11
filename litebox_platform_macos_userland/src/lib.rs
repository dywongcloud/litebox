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
//! * **Seatbelt instead of seccomp.** The second line of defense behind
//!   LiteBox's own guest/host boundary is a `(deny default)` Seatbelt profile
//!   installed by [`enable_seatbelt_sandbox`], the counterpart of the Linux
//!   platform's seccomp filter. Its source module (`src/seatbelt.rs`) documents
//!   what it denies, what it deliberately cannot deny, and why a failure to
//!   install it is fatal rather than a warning.
//!
//! # Residual risk after [`enable_seatbelt_sandbox`]
//!
//! Seatbelt mediates *operations*, not syscalls, and it only mediates the
//! operations it has hooks for. Code that has already subverted the shim or this
//! platform still keeps, inside the sandbox: full read/write on every descriptor
//! that was open when the profile was installed (stdin, stdout, stderr, and the
//! `utun` device when guest networking is on -- which is a raw L3 tap onto the
//! host's network stack); the whole `mmap`/`mprotect`/`munmap`/`MAP_JIT` surface,
//! so it can map and execute arbitrary native code in-process; every byte of this
//! process's own address space, including the guest images and any key material
//! the platform holds; the ability to read every `sysctl`; and the ability to
//! crash or hang the process. What it loses is the ability to reach *outside*
//! this process: no host file may be opened, `stat`ed, created or unlinked; no
//! socket may be bound or connected and no new `utun` may be opened; no host
//! program may be executed; and no other process may be signalled. Note that
//! plain `socket()` creation still succeeds -- it is `bind`/`connect` that are
//! refused -- so "no sockets exist" is not the guarantee; "no socket can be
//! attached to an endpoint" is.

// Restrict this crate to macOS on Apple Silicon. See the module docs for why
// there is deliberately no x86-64 variant.
#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

use core::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};
use core::time::Duration;
use std::io::IsTerminal as _;
use std::sync::{Arc, Condvar, Mutex, OnceLock};

use litebox::platform::page_mgmt::{
    AllocationError, DeallocationError, FixedAddressBehavior, MemoryRegionPermissions,
    PermissionUpdateError,
};
use litebox::platform::{ImmediatelyWokenUp, ProcessOpError, UnblockedOrTimedOut};
use litebox::utils::TruncateExt as _;
use zerocopy::{FromBytes, IntoBytes};

extern crate alloc;

mod darwin;
mod guest;
mod net;
mod seatbelt;

pub use seatbelt::enable_seatbelt_sandbox;

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
    /// Real, non-blocking-observable stdin, fed by a background host thread spawned in
    /// [`Self::new`]. See [`litebox::platform::StdinPump`].
    stdin_pump: litebox::platform::StdinPump,
    /// Doorbell the stdin-pump background thread notifies after every push/EOF, so
    /// [`StdioProvider::read_from_stdin`]'s blocking path can sleep instead of busy-polling.
    stdin_doorbell: (std::sync::Mutex<()>, Condvar),
    /// Serializes real host writes to stdout, so concurrent guest threads' `write()` calls to the
    /// same stream don't interleave mid-write.
    stdout_lock: std::sync::Mutex<()>,
    /// Serializes real host writes to stderr; see [`Self::stdout_lock`].
    stderr_lock: std::sync::Mutex<()>,
    /// The `utun` socket used for guest networking, if one was requested.
    tun: Option<std::os::fd::OwnedFd>,
    /// CoW-eligible memory regions registered via [`Self::register_cow_region`].
    /// Maps the start address of the static slice to the info needed to re-mmap
    /// the backing file. Mirrors `litebox_platform_linux_userland`'s identical
    /// mechanism.
    cow_regions: std::sync::RwLock<alloc::collections::BTreeMap<usize, CowRegionInfo>>,
    /// Keeps this platform's own background threads out of their critical
    /// sections while [`Self::fork_process`] duplicates the process. See
    /// [`ForkGate`].
    fork_gate: ForkGate,
    /// How many `litebox-timer` threads [`TimerProvider::create_timer`] has ever
    /// spawned. [`Self::fork_process`] refuses while this is non-zero, because a
    /// timer thread is the one background thread here that [`ForkGate`] cannot
    /// bracket -- see `fork_process`'s docs.
    timer_threads: AtomicUsize,
}

/// A fork barrier: it lets one thread reach a point where it knows every *other*
/// thread this platform owns is outside any critical section, and holds them
/// there until it says otherwise.
///
/// # Why this and not `pthread_atfork`, or an ordinary lock
///
/// `fork(2)` gives the child only the calling thread. A lock another thread held
/// at that instant is frozen held in the child, forever, and the child of a
/// LiteBox guest is not a child that can just `exec` and be done: it re-enters
/// the shim, which allocates, takes the page manager's locks, and eventually
/// runs a whole ELF load for `execve`. So "the child touches nothing before
/// `exec`" is not available as an argument here; the locks genuinely have to be
/// free.
///
/// Darwin's own `fork` already handles the *system* allocator (libmalloc
/// registers atfork handlers and the child's zones are reinitialized), which is
/// why an ordinary `malloc` in the child works even when sibling threads were
/// hammering it. What Darwin knows nothing about is LiteBox's own locks -- the
/// `spin::Mutex`es inside [`litebox::platform::StdinPump`] above all, which are
/// bare atomics with no atfork handling and no owner tracking, so a child that
/// inherits one held will spin on it until it is killed.
///
/// `pthread_atfork` is the textbook answer and is deliberately not used: its
/// handlers run for *every* fork in the process, they cannot fail, and the
/// prepare handler would have to acquire the very locks it is protecting --
/// which turns a background thread that is blocked in `read(2)` while holding
/// nothing (the common case here) into an unbounded wait anyway. The gate below
/// instead has the background threads *declare* their critical sections, so the
/// forking thread waits only for a section that is genuinely in progress, and
/// never for a thread parked in a blocking syscall.
///
/// # Why it is sound rather than usually-sound
///
/// It is built only from atomics, so it has no internal lock of its own to
/// inherit broken, and the "closed" flag and the in-flight count live in *one*
/// word updated by compare-exchange. That single-word design is load bearing
/// rather than tidiness: with a separate flag and counter, a background thread
/// can pass the flag check and then increment the counter after a fork has
/// already begun. The forking thread is not endangered by that (such a thread
/// backs out without entering the section), but the *child* inherits a counter
/// stuck above zero with no thread left alive to decrement it -- so the child's
/// own next `fork` waits on it forever. A guest shell forks for every command it
/// runs, so "the second fork in a child hangs" is a live failure, not a
/// theoretical one. Folding both into one word makes the increment impossible
/// once the gate is closed, which makes the count the child inherits provably
/// zero.
///
/// The forking thread does not proceed until the in-flight count has actually
/// reached zero, so "no other thread is inside a critical section" is observed,
/// not assumed.
struct ForkGate {
    /// [`Self::CLOSED`] in the top bit, the number of background threads
    /// currently inside a critical section in the rest.
    state: AtomicUsize,
}

impl ForkGate {
    /// Set while a fork is pending: background threads must stay out.
    const CLOSED: usize = 1 << (usize::BITS - 1);
    /// The in-flight-critical-section count occupies every other bit.
    const COUNT: usize = !Self::CLOSED;

    const fn new() -> Self {
        Self {
            state: AtomicUsize::new(0),
        }
    }

    /// Runs `f` as a critical section that no fork may straddle.
    ///
    /// Callers must not block indefinitely inside `f`: a fork waits for it.
    fn critical_section<R>(&self, f: impl FnOnce() -> R) -> R {
        loop {
            let state = self.state.load(Ordering::Acquire);
            if state & Self::CLOSED != 0 {
                std::thread::yield_now();
                continue;
            }
            // Entering is one atomic step with the check, so a gate that closes
            // concurrently always wins: this either takes effect before the
            // close (and the closer waits for it) or fails and retries.
            if self
                .state
                .compare_exchange_weak(state, state + 1, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                break;
            }
        }
        let r = f();
        self.state.fetch_sub(1, Ordering::AcqRel);
        r
    }

    /// Closes the gate and waits until every background thread is out of its
    /// critical section. The caller must pair this with [`Self::finish_fork`].
    fn begin_fork(&self) {
        self.state.fetch_or(Self::CLOSED, Ordering::AcqRel);
        while self.state.load(Ordering::Acquire) & Self::COUNT != 0 {
            std::thread::yield_now();
        }
    }

    /// Reopens the gate.
    ///
    /// Correct on both sides of a fork, with no need to know which side it is
    /// on: the parent lets its own background threads back in, and the child --
    /// which has none, and which provably inherited a zero count because
    /// [`Self::begin_fork`] waited for exactly that and nothing could raise it
    /// afterwards -- is left with a fully open, uncontended gate, the same state
    /// a fresh process would have.
    fn finish_fork(&self) {
        self.state.fetch_and(!Self::CLOSED, Ordering::AcqRel);
    }
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
            stdin_pump: litebox::platform::StdinPump::new(
                litebox::platform::stdin_pump::DEFAULT_CAPACITY,
            ),
            stdin_doorbell: (std::sync::Mutex::new(()), Condvar::new()),
            stdout_lock: std::sync::Mutex::new(()),
            stderr_lock: std::sync::Mutex::new(()),
            tun,
            cow_regions: std::sync::RwLock::new(alloc::collections::BTreeMap::new()),
            fork_gate: ForkGate::new(),
            timer_threads: AtomicUsize::new(0),
        };

        // A platform must outlive every guest thread that can reach it, and
        // there is exactly one per process, so leaking is the cheapest way to
        // get a `'static` without reference counting on every access.
        let platform: &'static Self = alloc::boxed::Box::leak(alloc::boxed::Box::new(platform));
        spawn_stdin_pump_thread(platform);
        platform
    }

    /// Populate the root key used by [`litebox::platform::DerivedKeyProvider`].
    ///
    /// The key is Darwin's boot session UUID: stable for every process in a boot
    /// and freshly generated by the kernel on the next one, which is exactly the
    /// "persistent across LiteBox invocations, reset by a true reboot" guarantee
    /// the trait describes.
    ///
    /// Must be called *before* [`enable_seatbelt_sandbox`]: `kern.bootsessionuuid`
    /// sits outside the `hw.optional.` prefix that profile admits, so afterwards
    /// this returns `EPERM` rather than a key. No macOS runner calls it today;
    /// one that does must do so during start-up, alongside the other host
    /// resources acquired before the sandbox goes up.
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

/// Mirrors `<MacOsUserland as PageManagementProvider<ALIGN>>::TASK_ADDR_MIN`
/// (the trait impl's associated const is defined in terms of this, not the
/// other way around) so free functions outside that `impl` block --
/// `allocate_jit_pages`'s and `try_allocate_cow_pages`'s `Hint`-correction
/// bounds checks -- can see it without a `Self` to qualify through (`Self`
/// would need `ALIGN` pinned to a concrete value, which these call sites
/// have no reason to do). The value genuinely does not depend on `ALIGN`, so
/// one constant correctly serves both the associated const and these.
const GUEST_ADDR_MIN: usize = 0x1_0000_0000;
/// See [`GUEST_ADDR_MIN`]; mirrors `TASK_ADDR_MAX` the same way.
const GUEST_ADDR_MAX: usize = 0x0000_4000_0000_0000;

/// Allocate a `MAP_JIT` mapping, honoring `fixed_address_behavior` despite
/// Darwin refusing to combine `MAP_FIXED` with `MAP_JIT` in one `mmap` call.
///
/// For a [`FixedAddressBehavior::Hint`] request, `suggested_range.start` is
/// offered to `mmap` as an advisory address -- mirroring what
/// [`MacOsUserland::allocate_pages`]'s non-JIT `Hint` branch does -- so Darwin
/// gets a real chance to place the mapping there directly instead of this
/// function relying solely on the correction below. `Replace`/`NoReplace`
/// instead always request a kernel-chosen address here: both finish with an
/// exact `reserve_fixed`+[`darwin::remap_to_fixed`] pass a few lines down, and
/// if the hint got honored in this initial call, that reservation would
/// collide with the very mapping this call just created at the same address.
///
/// Whatever address the kernel actually returns is the answer -- *unless* it
/// falls outside `[TASK_ADDR_MIN, TASK_ADDR_MAX)` for a `Hint` request, in
/// which case it is relocated to `suggested_range.start` with
/// [`darwin::remap_to_fixed`] the same way `NoReplace` always is. See the
/// matching comment in `allocate_pages`'s non-JIT branch for why `Hint` needs
/// this correction (real Darwin does not reliably honor an advisory hint near
/// the top of the guest's address range) and why it is applied only when the
/// kernel-chosen address is actually out of range rather than
/// unconditionally.
fn allocate_jit_pages(
    suggested_range: &core::ops::Range<usize>,
    initial_permissions: MemoryRegionPermissions,
    fixed_address_behavior: FixedAddressBehavior,
) -> Result<*mut libc::c_void, AllocationError> {
    // Only `Hint` may offer the suggested address as a hint here -- see this
    // function's doc comment for why `Replace`/`NoReplace` must not.
    let hint = if fixed_address_behavior == FixedAddressBehavior::Hint {
        suggested_range.start as *mut libc::c_void
    } else {
        core::ptr::null_mut()
    };
    // SAFETY: `MAP_JIT` cannot be combined with `MAP_FIXED`, so `hint` is only
    // ever advisory -- Darwin remains free to place the mapping elsewhere --
    // and there is no caller-owned range to validate here beyond what `mmap`
    // itself checks.
    let kernel_chosen = unsafe {
        libc::mmap(
            hint,
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

    let must_be_exact = fixed_address_behavior == FixedAddressBehavior::NoReplace;
    let needs_correction = fixed_address_behavior == FixedAddressBehavior::Hint && {
        let start = kernel_chosen as usize;
        let end = start + suggested_range.len();
        start < GUEST_ADDR_MIN || end > GUEST_ADDR_MAX
    };
    let reserved = if must_be_exact || needs_correction {
        // `remap_to_fixed`'s `VM_FLAGS_OVERWRITE` silently replaces whatever
        // already occupies the destination, so `NoReplace` has to check
        // first -- exactly like the non-JIT path does with a plain
        // `mmap(MAP_FIXED)`. The reservation itself then occupies the
        // destination until the remap overwrites it.
        match reserve_fixed(suggested_range) {
            Ok(()) => true,
            Err(e) if must_be_exact => {
                // SAFETY: `kernel_chosen` is the mapping just created above,
                // still solely owned by this function.
                unsafe { libc::munmap(kernel_chosen, suggested_range.len()) };
                return Err(match e {
                    ReservationError::AddressInUse => AllocationError::AddressInUse,
                    ReservationError::OutOfMemory => AllocationError::OutOfMemory,
                });
            }
            // `needs_correction`: the exact candidate is refused too (see the
            // matching comment in `allocate_pages`'s non-JIT branch) --
            // `kernel_chosen` is the only address left to offer, out-of-range
            // as it is; a caller that cannot use it will find out from a real
            // fault at first access rather than this function inventing a
            // further fallback that has never been exercised.
            Err(_) => false,
        }
    } else {
        false
    };

    if !reserved {
        return Ok(kernel_chosen);
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
            release_reservation(suggested_range);
            Err(match e {
                ReservationError::AddressInUse => AllocationError::AddressInUse,
                ReservationError::OutOfMemory => AllocationError::OutOfMemory,
            })
        }
    }
}

/// `allocate_jit_pages`'s `Hint` branch has to actually offer
/// `suggested_range.start` to `mmap`, not silently discard it for a
/// kernel-chosen address (`macos-allocate-jit-pages-hint-discarded`).
///
/// A single free candidate cannot distinguish "the hint was honored" from
/// "the kernel's own unhinted choice happened to coincide with it": on this
/// hardware a bare `mmap(NULL, ...)` deterministically reuses the
/// most-recently-freed address of matching size, so a naive probe-then-free
/// address would come back from an unhinted call too, passing regardless of
/// whether the fix is present. Instead this creates two disjoint free
/// candidates, `low` and `high` (kept apart by `spacer`, still mapped, so
/// their free regions cannot coalesce), and confirms first that an unhinted
/// `mmap` of this size lands at `low` -- the kernel's natural choice -- never
/// `high`. Requesting `high` as the `Hint` must then still land exactly at
/// `high`, which is only possible if the hint was actually passed through.
#[cfg(test)]
#[test]
fn allocate_jit_pages_hint_honors_the_suggested_address() {
    const MAX_ATTEMPTS: u32 = 25;

    // This test's core guarantee -- `low`/`high` stay free across several
    // mmap/munmap round trips -- cannot be made airtight against every
    // possible source of host address-space churn: Rust's own parallel test
    // harness spawns and joins OS threads for other, unrelated tests the
    // whole time this one runs, and each thread needs a real mmap'd stack
    // from libSystem/pthread internals that this crate's own code has no way
    // to serialize against. Serializing against this crate's OWN
    // mmap/munmap-doing tests (via `TEST_SERIAL`, shared with `guest::tests`
    // and `with_signal_alt_stack_actually_registers_one`) closes the sources
    // this crate controls, but not the harness's own thread churn -- so
    // instead of a single-shot assertion, this retries: a mismatch is only
    // treated as a real bug if it reproduces across every attempt, since a
    // genuine regression (the hint never being passed through) would fail
    // every attempt identically, while a harness-thread race would not.
    let _serial = guest::tests::TEST_SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);

    let len = litebox::mm::linux::PAGE_SIZE;

    // SAFETY: each anonymous mapping with no fixed-address request has no
    // precondition beyond what `mmap` itself checks.
    let mmap_anon = || unsafe {
        libc::mmap(
            core::ptr::null_mut(),
            len,
            libc::PROT_NONE,
            libc::MAP_PRIVATE | libc::MAP_ANON,
            -1,
            0,
        )
    };

    let mut last_inconclusive_reason = String::new();

    for attempt in 0..MAX_ATTEMPTS {
        let low = mmap_anon();
        let spacer = mmap_anon();
        let high = mmap_anon();
        assert_ne!(low, libc::MAP_FAILED, "low probe mmap failed");
        assert_ne!(spacer, libc::MAP_FAILED, "spacer probe mmap failed");
        assert_ne!(high, libc::MAP_FAILED, "high probe mmap failed");

        // SAFETY: `low`/`high` are the mappings just created above, still
        // solely owned here, and each is freed exactly once; `spacer` stays
        // mapped for the rest of this attempt so `low`'s and `high`'s
        // now-free regions stay disjoint instead of coalescing into one.
        unsafe {
            libc::munmap(low, len);
            libc::munmap(high, len);
        }

        let low = low as usize;
        let high = high as usize;

        // SAFETY: `spacer` is the mapping created above, unmapped exactly
        // once on every exit path from this closure.
        let free_spacer = || unsafe {
            libc::munmap(spacer, len);
        };

        if !((GUEST_ADDR_MIN..GUEST_ADDR_MAX).contains(&low)
            && (GUEST_ADDR_MIN..GUEST_ADDR_MAX).contains(&high))
        {
            last_inconclusive_reason = format!(
                "attempt {attempt}: probe addresses low={low:#x} high={high:#x} fell \
                 outside the guest range, so this attempt could not exercise the \
                 ordinary (non-correction) Hint path"
            );
            free_spacer();
            continue;
        }

        // Confirm the kernel's natural, unhinted choice really is `low`, not
        // `high` -- otherwise the check below would not actually
        // discriminate a passed-through hint from coincidence.
        let natural = mmap_anon();
        if natural as usize != low {
            last_inconclusive_reason = format!(
                "attempt {attempt}: an unhinted mmap landed at {:#x}, not the lower \
                 free candidate low={low:#x} -- something else raced this attempt's \
                 free window, so it cannot tell a passed-through hint from a lucky \
                 coincidence",
                natural as usize
            );
            // SAFETY: `natural` is the mapping just created above, still
            // solely owned here.
            unsafe { libc::munmap(natural, len) };
            free_spacer();
            continue;
        }
        // SAFETY: `natural` is the mapping just created above, still solely
        // owned here.
        unsafe { libc::munmap(natural, len) };

        let suggested_range = high..high + len;
        let result = allocate_jit_pages(
            &suggested_range,
            MemoryRegionPermissions::READ | MemoryRegionPermissions::WRITE,
            FixedAddressBehavior::Hint,
        );
        let ptr = result.expect("allocate_jit_pages should succeed for a free, in-range hint");

        if ptr as usize == high {
            // SAFETY: `ptr` is the mapping just created above, still solely
            // owned here, unmapped exactly once.
            unsafe { libc::munmap(ptr, len) };
            free_spacer();
            return;
        }

        last_inconclusive_reason = format!(
            "attempt {attempt}: Hint placed the MAP_JIT mapping at {:#x} instead of \
             the caller's suggested address high={high:#x} -- either the hint was \
             silently discarded, or something else raced `high` free between the \
             precondition check above and this call",
            ptr as usize
        );
        // SAFETY: `ptr` is the mapping just created above, still solely
        // owned here, unmapped exactly once.
        unsafe { libc::munmap(ptr, len) };
        free_spacer();
    }

    panic!(
        "allocate_jit_pages did not honor the suggested Hint address in any of \
         {MAX_ATTEMPTS} attempts -- this many consecutive misses is not \
         explainable by test-harness thread-stack races alone, and points at a \
         real regression. Last attempt's reason: {last_inconclusive_reason}"
    );
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
    const TASK_ADDR_MIN: usize = GUEST_ADDR_MIN;

    /// Deliberately conservative. The user half of an Apple Silicon address
    /// space is 47 bits wide, but the exact ceiling is a kernel implementation
    /// detail (`MACH_VM_MAX_ADDRESS`) rather than a stable interface, so this
    /// stops a bit below 2^46 -- 64 TiB of guest address space, comfortably
    /// inside any plausible limit.
    const TASK_ADDR_MAX: usize = GUEST_ADDR_MAX;

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

            // `Hint`'s bare, unenforced `mmap(addr)` above is not reliable on
            // real Darwin: observed on real Apple Silicon hardware, a hint
            // near the top of the guest's address range (e.g. the initial
            // stack, hinted at `TASK_ADDR_MAX - 8 MiB`) is silently placed by
            // the kernel at an unrelated, kernel-chosen address instead
            // (consistently `TASK_ADDR_MAX`-relative but off by several
            // MiB) -- routinely landing the mapping *above* `TASK_ADDR_MAX`,
            // an invariant every other part of this platform and the shim
            // above it assumes holds. This is the confirmed mechanism behind
            // `macos-concurrent-guest-entry-sigsegv`'s intermittent real
            // guest `SIGSEGV`s (worse under concurrent host memory pressure,
            // which shifts exactly which address Darwin's own chooser picks)
            // -- the crash lands in a dynamic linker's own self-relocation
            // bootstrap, exactly the code most sensitive to its own placement
            // being wrong.
            //
            // Every caller in this tree reaches `Hint` only after
            // `Vmem::get_unmmaped_area` has already searched for and vetted
            // `suggested_range` against this process's own address-space
            // bookkeeping (see `litebox::mm::linux::Vmem::create_mapping`,
            // whose non-fixed path always resolves a concrete candidate
            // *before* calling down here), so when the address Darwin
            // actually chose disagrees with that already-vetted candidate,
            // retrying with an exact reservation is not a reinterpretation of
            // `Hint` -- it is honoring what the caller already committed to.
            // This retry is intentionally the exception rather than the
            // default: attempting it unconditionally regressed the common
            // case instead of only fixing the broken one -- observed on the
            // same hardware, `mach_vm_allocate(VM_FLAGS_FIXED)` refuses
            // exactly `TASK_ADDR_MIN` (the address immediately above
            // `__PAGEZERO`, where the main executable's own low-address image
            // is conventionally placed) with `KERN_INVALID_ADDRESS`, and an
            // *attempted-but-refused* fixed reservation there measurably
            // perturbs Darwin's own address-hint state for the *following*
            // hint-based `mmap` (real, reproduced on this hardware: the very
            // next allocation then lands *inside* an already-live mapping
            // instead of a free gap next to it, something no other observed
            // sequence produced) -- so the exact-reservation path below only
            // ever runs when the bare attempt already provably failed, never
            // speculatively ahead of it.
            if fixed_address_behavior == FixedAddressBehavior::Hint {
                let start = ptr as usize;
                let end = start + suggested_range.len();
                if start < GUEST_ADDR_MIN || end > GUEST_ADDR_MAX {
                    // SAFETY: `ptr` is the mapping just created above, still
                    // solely owned by this function.
                    unsafe { libc::munmap(ptr, suggested_range.len()) };
                    reserve_fixed(&suggested_range).map_err(|e| match e {
                        ReservationError::AddressInUse => AllocationError::AddressInUse,
                        ReservationError::OutOfMemory => AllocationError::OutOfMemory,
                    })?;
                    // SAFETY: `reserve_fixed` just confirmed `suggested_range`
                    // is free, so `MAP_FIXED` only replaces that reservation.
                    let fixed_ptr = unsafe {
                        libc::mmap(
                            suggested_range.start as *mut libc::c_void,
                            suggested_range.len(),
                            prot_flags(initial_permissions),
                            libc::MAP_PRIVATE | libc::MAP_ANON | libc::MAP_FIXED,
                            -1,
                            0,
                        )
                    };
                    if fixed_ptr == libc::MAP_FAILED {
                        release_reservation(&suggested_range);
                        return Err(match std::io::Error::last_os_error().raw_os_error() {
                            Some(libc::EINVAL) => AllocationError::Unaligned,
                            _ => AllocationError::OutOfMemory,
                        });
                    }
                    fixed_ptr
                } else {
                    ptr
                }
            } else {
                ptr
            }
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
        if ptr == libc::MAP_FAILED {
            // SAFETY: `fd` is open and not used past this point.
            unsafe { libc::close(fd) };
            if reserved {
                release_reservation(&mapped_range);
            }
            return Err(CowAllocationError::InternalFailure);
        }

        // See the matching comment in `MacOsUserland::allocate_pages`'s
        // non-JIT branch for why a `Hint` result that landed outside the
        // guest's range gets one corrective retry at the exact candidate,
        // applied only when the bare attempt already provably produced an
        // out-of-range address (not unconditionally, and not speculatively
        // ahead of it).
        if fixed_address_behavior == FixedAddressBehavior::Hint {
            let start = ptr as usize;
            let end = start + source_data.len();
            if start < GUEST_ADDR_MIN || end > GUEST_ADDR_MAX {
                // SAFETY: `ptr` is the mapping just created above, still
                // solely owned by this function.
                unsafe { libc::munmap(ptr, source_data.len()) };
                if reserve_fixed(&mapped_range).is_err() {
                    // SAFETY: `fd` is open and not used past this point.
                    unsafe { libc::close(fd) };
                    return Err(CowAllocationError::InternalFailure);
                }
                // SAFETY: `reserve_fixed` just confirmed `mapped_range` is
                // free, `fd` is still the same read-only file opened above,
                // and `MAP_FIXED` only replaces that fresh reservation.
                let fixed_ptr = unsafe {
                    libc::mmap(
                        suggested_start as *mut libc::c_void,
                        source_data.len(),
                        prot_flags(permissions),
                        libc::MAP_PRIVATE | libc::MAP_FIXED,
                        fd,
                        offset,
                    )
                };
                // SAFETY: `fd` is open and not used past this point.
                unsafe { libc::close(fd) };
                if fixed_ptr == libc::MAP_FAILED {
                    release_reservation(&mapped_range);
                    return Err(CowAllocationError::InternalFailure);
                }
                return Ok(UserMutPtr::from_ptr(fixed_ptr.cast::<u8>()));
            }
        }
        // SAFETY: `fd` is open and not used past this point.
        unsafe { libc::close(fd) };
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

    fn thread_cpu_time(&self) -> core::time::Duration {
        // Real per-thread CPU-time accounting from the host: Darwin's `clock_gettime` has
        // supported `CLOCK_THREAD_CPUTIME_ID` since macOS 10.12, and it genuinely stops
        // advancing while the calling thread is not scheduled on a CPU (verified: it does not
        // advance during a blocking sleep, and does advance under a busy loop).
        core::time::Duration::from_nanos(darwin::clock_gettime_nanos(libc::CLOCK_THREAD_CPUTIME_ID))
    }

    fn process_cpu_time(&self) -> core::time::Duration {
        // As above, but `CLOCK_PROCESS_CPUTIME_ID` sums CPU time across every thread of the
        // process.
        core::time::Duration::from_nanos(darwin::clock_gettime_nanos(
            libc::CLOCK_PROCESS_CPUTIME_ID,
        ))
    }
}

// ---------------------------------------------------------------------------
// Architecture-specific state
// ---------------------------------------------------------------------------

impl litebox::platform::ArchSpecificProvider for MacOsUserland {
    fn get_arch_specific_register(
        &self,
        reg: &litebox::platform::ArchSpecificRegister,
    ) -> Result<usize, litebox::platform::ArchSpecificError> {
        match reg {
            litebox::platform::ArchSpecificRegister::TpidrEl0 => {
                let key = guest_tp_tsd_key()
                    .ok_or(litebox::platform::ArchSpecificError::RegisterUnsupported)?;
                // SAFETY: `key` was reserved by `reserve_guest_tpidr_tsd_slot` via
                // `pthread_key_create`, which this process never invalidates; a
                // thread that never called `set_arch_specific_register` reads
                // back the `pthread_key_create`-guaranteed null default.
                Ok(unsafe { libc::pthread_getspecific(key) } as usize)
            }
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
                let key = guest_tp_tsd_key()
                    .ok_or(litebox::platform::ArchSpecificError::RegisterUnsupported)?;
                // This must land in the SAME pthread TSD slot the rewriter's
                // MRS/MSR gates address directly via `[TPIDRRO_EL0 + offset]`
                // (see `guest_tp_slot_byte_offset`) -- otherwise a guest thread's
                // clone(CLONE_SETTLS)-supplied thread pointer would be invisible
                // to its own later `MRS TPIDR_EL0`. No range check is needed on
                // `val`: the value never reaches a hardware register, so an
                // invalid one can only fault the guest that dereferences it.
                //
                // SAFETY: `key` was reserved by `reserve_guest_tpidr_tsd_slot`,
                // and storing an opaque `usize` as a TSD value has no
                // precondition beyond a valid key.
                let rc = unsafe { libc::pthread_setspecific(key, val as *const libc::c_void) };
                // POSIX defines only `EINVAL` for an invalid key here, which
                // `key` cannot be (it was just reserved above) -- so a nonzero
                // `rc` means host-level corruption. Every caller in this tree
                // (`litebox_shim_linux`'s execve/clone paths) already treats a
                // failure here as fatal, so propagating the error keeps that
                // boundary in one place instead of duplicating it here too.
                if rc == 0 {
                    Ok(())
                } else {
                    Err(litebox::platform::ArchSpecificError::RegisterUnsupported)
                }
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

/// Spawns the single background host thread that blockingly reads the real stdin and feeds
/// [`MacOsUserland::stdin_pump`], notifying [`MacOsUserland::stdin_doorbell`] after every push or
/// EOF so [`StdioProvider::read_from_stdin`]'s blocking path wakes promptly instead of polling.
///
/// Spawned unconditionally in [`MacOsUserland::new`] -- real host stdin (whether an interactive
/// terminal, a pipe, or a redirected file) always needs pumping so both blocking reads and
/// non-blocking/epoll-observed reads get real data, matching how `/dev/stdin` behaves on real
/// Linux regardless of what it's actually backed by.
fn spawn_stdin_pump_thread(platform: &'static MacOsUserland) {
    std::thread::Builder::new()
        .name("litebox-stdin-pump".to_owned())
        .spawn(move || {
            let mut buf = [0u8; 4096];
            loop {
                // SAFETY: `buf` is a valid writable stack buffer for the duration of this call.
                let n = unsafe {
                    libc::read(
                        libc::STDIN_FILENO,
                        buf.as_mut_ptr().cast::<libc::c_void>(),
                        buf.len(),
                    )
                };
                if n <= 0 {
                    if n < 0
                        && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted
                    {
                        continue;
                    }
                    // EOF (n == 0) or a real error: either way, real stdin will never produce
                    // more data, so mark EOF and stop pumping.
                    //
                    // Every touch of `stdin_pump` and of the doorbell runs inside the fork
                    // gate: those take a `spin::Mutex` and a `std::sync::Mutex` respectively,
                    // and a fork that straddled either would hand the child a lock nobody
                    // will ever release. The blocking `read` above is deliberately *outside*
                    // the gate -- it holds nothing, and gating it would stall every fork
                    // until the next byte of stdin arrived.
                    platform.fork_gate.critical_section(|| {
                        platform.stdin_pump.mark_eof();
                        platform.notify_stdin_doorbell();
                    });
                    break;
                }
                let mut data = &buf[..n.unsigned_abs()];
                while !data.is_empty() {
                    let pushed = platform.fork_gate.critical_section(|| {
                        let pushed = platform.stdin_pump.push(data);
                        platform.notify_stdin_doorbell();
                        pushed
                    });
                    if pushed == 0 {
                        // Ring buffer is full because the guest hasn't drained it yet; back off
                        // briefly rather than busy-spinning until it does.
                        std::thread::sleep(Duration::from_millis(1));
                        continue;
                    }
                    data = &data[pushed..];
                }
            }
        })
        .expect("failed to spawn the stdin-pump background thread");
}

impl MacOsUserland {
    /// Wakes any thread parked in [`StdioProvider::read_from_stdin`]'s blocking wait.
    fn notify_stdin_doorbell(&self) {
        let (lock, cvar) = &self.stdin_doorbell;
        drop(lock.lock().unwrap());
        cvar.notify_all();
    }
}

impl litebox::platform::StdioProvider for MacOsUserland {
    fn read_from_stdin(&self, buf: &mut [u8]) -> Result<usize, litebox::platform::StdioReadError> {
        loop {
            if let Some(n) = self.stdin_pump.try_read(buf) {
                return Ok(n);
            }
            // No data yet and not at EOF: park until the pump thread notifies. The bounded
            // timeout is a safety net against a lost wakeup in the (check, then wait) window
            // above, not the primary wakeup path.
            let (lock, cvar) = &self.stdin_doorbell;
            let guard = lock.lock().unwrap();
            let _ = cvar.wait_timeout(guard, Duration::from_millis(50)).unwrap();
        }
    }

    fn write_to(
        &self,
        stream: litebox::platform::StdioOutStream,
        buf: &[u8],
    ) -> Result<usize, litebox::platform::StdioWriteError> {
        let (fd, lock) = match stream {
            litebox::platform::StdioOutStream::Stdout => (libc::STDOUT_FILENO, &self.stdout_lock),
            litebox::platform::StdioOutStream::Stderr => (libc::STDERR_FILENO, &self.stderr_lock),
        };
        // Holding this for the whole (potentially multi-syscall) write below is what makes one
        // guest `write()` call atomic w.r.t. other guest threads' writes to the same stream.
        let _guard = lock.lock().unwrap();
        let mut written = 0usize;
        while written < buf.len() {
            // SAFETY: `buf[written..]` is a valid readable slice of the given length.
            let n = unsafe {
                libc::write(
                    fd,
                    buf[written..].as_ptr().cast::<libc::c_void>(),
                    buf.len() - written,
                )
            };
            if n < 0 {
                if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                if written > 0 {
                    // Real `write(2)` semantics: a short write due to a later error still
                    // reports the bytes actually written, and lets the caller retry the rest.
                    return Ok(written);
                }
                return Err(litebox::platform::StdioWriteError::Closed);
            }
            if n == 0 {
                break;
            }
            written += n.unsigned_abs();
        }
        Ok(written)
    }

    fn is_a_tty(&self, stream: litebox::platform::StdioStream) -> bool {
        self.stdio_is_tty[stream as usize]
    }

    fn stdin_pollable(&self) -> Option<&dyn litebox::event::IOPollable> {
        Some(&self.stdin_pump)
    }

    fn set_terminal_raw_mode(&self, stream: litebox::platform::StdioStream, raw: bool, echo: bool) {
        // Only stdin's line discipline affects how input bytes arrive at the pump thread.
        if stream != litebox::platform::StdioStream::Stdin
            || !self.stdio_is_tty[litebox::platform::StdioStream::Stdin as usize]
        {
            return;
        }
        // SAFETY: `STDIN_FILENO` is valid for the process lifetime; `term` is fully initialized
        // by `tcgetattr` before any field is read or written.
        unsafe {
            let mut term: libc::termios = core::mem::zeroed();
            if libc::tcgetattr(libc::STDIN_FILENO, &raw mut term) != 0 {
                return;
            }
            if raw {
                term.c_lflag &= !(libc::ICANON as libc::tcflag_t);
                term.c_cc[libc::VMIN] = 1;
                term.c_cc[libc::VTIME] = 0;
            } else {
                term.c_lflag |= libc::ICANON as libc::tcflag_t;
            }
            if echo {
                term.c_lflag |= libc::ECHO as libc::tcflag_t;
            } else {
                term.c_lflag &= !(libc::ECHO as libc::tcflag_t);
            }
            let _ = libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &raw const term);
        }
    }
}

// ---------------------------------------------------------------------------
// System information
// ---------------------------------------------------------------------------

impl litebox::platform::SystemInfoProvider for MacOsUserland {
    fn get_syscall_entry_point(&self) -> usize {
        // Not a single fixed function address: this platform's syscall callback
        // has to resolve the calling thread's own guest-entry state with the
        // one register the rewriter's `SVC` gate leaves free, which it does by
        // there being one entry stub per possible pthread TSD slot. See
        // `guest::syscall_entry_point`.
        guest::syscall_entry_point()
    }

    fn get_vdso_address(&self) -> Option<usize> {
        // A Linux guest's vDSO would have to be a LiteBox-provided image; the
        // host's own `commpage` is not one. Reporting `None` means the guest
        // falls back to real syscalls, which is what the shim wants anyway --
        // but it also means a guest signal handler needs its own `sa_restorer`,
        // because the kernel's fallback trampoline lives in the vDSO.
        None
    }

    fn get_guest_tp_slot_offset(&self) -> Option<usize> {
        // `Host::MacOs` gates read this offset from the trampoline rather than
        // carrying it as an immediate, because the TSD key backing it is handed
        // out by `pthread_key_create` in this process and is not knowable to the
        // rewriter that packaged the image.
        guest_tp_slot_byte_offset()
    }

    fn get_sigreturn_trampoline_address(&self) -> Option<usize> {
        // See `get_vdso_address`: this platform has no vDSO to fall back to for
        // a guest handler installed without `SA_RESTORER`, so it provides its
        // own trampoline instead -- `guest::sigreturn_trampoline`'s own doc
        // comment covers why this is safe despite there being no vDSO.
        Some(guest::sigreturn_trampoline as *const () as usize)
    }

    fn get_hwcap(&self) -> (u64, u64) {
        arm_hwcap()
    }
}

/// Darwin `hw.optional.*` sysctl name, and the Linux `AT_HWCAP`/`AT_HWCAP2` bit it maps to.
///
/// `true` selects `AT_HWCAP2`; `false` selects `AT_HWCAP`. Only features that (a) the CPU
/// genuinely implements and (b) do not change how guest code is expected to run (unlike, say,
/// pointer authentication or branch-target identification, which could interact with this
/// platform's own guest-entry control flow) are included -- see [`SystemInfoProvider::get_hwcap`]'s
/// doc comment for why any *included* bit is always safe to report.
const HWCAP_SYSCTLS: &[(&str, u8, bool)] = &[
    ("hw.optional.floatingpoint", 0, false), // HWCAP_FP
    ("hw.optional.neon", 1, false),          // HWCAP_ASIMD
    ("hw.optional.arm.FEAT_AES", 3, false),  // HWCAP_AES
    ("hw.optional.arm.FEAT_PMULL", 4, false), // HWCAP_PMULL
    ("hw.optional.arm.FEAT_SHA1", 5, false), // HWCAP_SHA1
    ("hw.optional.arm.FEAT_SHA256", 6, false), // HWCAP_SHA2
    ("hw.optional.arm.FEAT_CRC32", 7, false), // HWCAP_CRC32
    ("hw.optional.arm.FEAT_LSE", 8, false),  // HWCAP_ATOMICS
    ("hw.optional.arm.FEAT_FP16", 9, false), // HWCAP_FPHP
    ("hw.optional.neon_hpfp", 10, false),    // HWCAP_ASIMDHP
    ("hw.optional.arm.FEAT_RDM", 12, false), // HWCAP_ASIMDRDM
    ("hw.optional.arm.FEAT_JSCVT", 13, false), // HWCAP_JSCVT
    ("hw.optional.arm.FEAT_FCMA", 14, false), // HWCAP_FCMA
    ("hw.optional.arm.FEAT_LRCPC", 15, false), // HWCAP_LRCPC
    ("hw.optional.arm.FEAT_DPB", 16, false), // HWCAP_DCPOP
    ("hw.optional.arm.FEAT_SHA3", 17, false), // HWCAP_SHA3
    ("hw.optional.arm.FEAT_DotProd", 20, false), // HWCAP_ASIMDDP
    ("hw.optional.arm.FEAT_SHA512", 21, false), // HWCAP_SHA512
    ("hw.optional.arm.FEAT_FHM", 23, false), // HWCAP_ASIMDFHM
    ("hw.optional.arm.FEAT_DIT", 24, false), // HWCAP_DIT
    ("hw.optional.arm.FEAT_LSE2", 25, false), // HWCAP_USCAT
    ("hw.optional.arm.FEAT_LRCPC2", 26, false), // HWCAP_ILRCPC
    ("hw.optional.arm.FEAT_FlagM", 27, false), // HWCAP_FLAGM
    ("hw.optional.arm.FEAT_SSBS", 28, false), // HWCAP_SSBS
    ("hw.optional.arm.FEAT_SB", 29, false),  // HWCAP_SB
    ("hw.optional.arm.FEAT_DPB2", 0, true),  // HWCAP2_DCPODP
    ("hw.optional.arm.FEAT_FlagM2", 7, true), // HWCAP2_FLAGM2
    ("hw.optional.arm.FEAT_FRINTTS", 8, true), // HWCAP2_FRINT
    ("hw.optional.arm.FEAT_I8MM", 13, true), // HWCAP2_I8MM
    ("hw.optional.arm.FEAT_BF16", 14, true), // HWCAP2_BF16
    ("hw.optional.arm.FEAT_ECV", 19, true),  // HWCAP2_ECV
    ("hw.optional.arm.FEAT_AFP", 20, true),  // HWCAP2_AFP
    ("hw.optional.arm.FEAT_RPRES", 21, true), // HWCAP2_RPRES
];

/// Queries this host's real ARM64 feature set via Darwin's `hw.optional.*` sysctls and
/// translates it into the `(AT_HWCAP, AT_HWCAP2)` bitmasks a real Linux kernel would report
/// for the same CPU. Missing/unreadable sysctls are treated as unsupported (bit left clear),
/// matching a real kernel's own behavior for a feature it does not detect.
fn arm_hwcap() -> (u64, u64) {
    let mut hwcap: u64 = 0;
    let mut hwcap2: u64 = 0;
    for &(name, bit, is_hwcap2) in HWCAP_SYSCTLS {
        if sysctl_bool(name) {
            if is_hwcap2 {
                hwcap2 |= 1 << bit;
            } else {
                hwcap |= 1 << bit;
            }
        }
    }
    (hwcap, hwcap2)
}

/// Reads a Darwin `hw.optional.*`-style boolean sysctl (a 32-bit int, nonzero meaning present),
/// returning `false` if the sysctl does not exist on this host or the read otherwise fails.
fn sysctl_bool(name: &str) -> bool {
    // SAFETY: `c_name` is a valid, NUL-terminated C string for the duration of the call, and
    // `value`/`len` are valid, uniquely-owned out-parameters matching what `sysctlbyname`
    // expects for reading a fixed-size (4-byte) integer sysctl.
    unsafe {
        let Ok(c_name) = std::ffi::CString::new(name) else {
            return false;
        };
        let mut value: libc::c_int = 0;
        let mut len = core::mem::size_of::<libc::c_int>();
        let rc = libc::sysctlbyname(
            c_name.as_ptr(),
            (&raw mut value).cast(),
            &raw mut len,
            core::ptr::null_mut(),
            0,
        );
        rc == 0 && value != 0
    }
}

/// `sysctl_bool` on a name no Darwin host defines must fail closed (`false`), not panic or
/// report a false positive -- this is exactly what a genuinely-unsupported CPU feature looks
/// like to [`arm_hwcap`], and it must never be mistaken for "supported".
#[cfg(test)]
#[test]
fn sysctl_bool_is_false_for_a_nonexistent_sysctl() {
    assert!(!sysctl_bool("hw.optional.litebox_does_not_define_this_sysctl"));
}

/// Every real Apple Silicon Mac (the only hardware this platform targets) implements
/// floating point and NEON/ASIMD -- if `arm_hwcap` cannot even detect those two baseline,
/// universally-present features via the real `hw.optional.*` sysctls, its sysctl-to-HWCAP-bit
/// wiring is broken, not just conservatively reporting an optional feature as absent.
#[cfg(test)]
#[test]
fn arm_hwcap_reports_the_real_hosts_baseline_features() {
    const HWCAP_FP: u64 = 1 << 0;
    const HWCAP_ASIMD: u64 = 1 << 1;
    let (hwcap, _hwcap2) = arm_hwcap();
    assert_eq!(
        hwcap & (HWCAP_FP | HWCAP_ASIMD),
        HWCAP_FP | HWCAP_ASIMD,
        "every real Apple Silicon Mac has both FP and ASIMD"
    );
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

// Asynchronous host signals observed since the guest thread that owns this
// pointer last drained them. Bit `n - 1` corresponds to signal number `n`,
// matching `SigSet`'s encoding.
//
// The bitmap itself lives in that thread's `ThreadHandleInner`, not here --
// `timer_thread` fires on its own dedicated thread and has to mark the
// *target* thread's bit, and a bare `thread_local!` cannot be reached from
// another thread. This cell just caches, on the owning thread, a pointer to
// its own copy of that shared bitmap so `async_signal_handler` and
// `take_pending_signals` can reach it without going through
// `CURRENT_THREAD`'s `RefCell`, which is not safe to borrow from a signal
// handler that might land mid-borrow. Null while the thread has no
// `ThreadHandle::run_with_handle` registration.
thread_local! {
    static PENDING_SIGNALS: core::cell::Cell<*const AtomicU64> =
        const { core::cell::Cell::new(core::ptr::null()) };
}

unsafe extern "C" fn async_signal_handler(signum: libc::c_int) {
    if let Ok(bit) = u32::try_from(signum - 1) {
        let pending = PENDING_SIGNALS.get();
        if !pending.is_null() {
            // SAFETY: non-null only while `run_with_handle` has this thread
            // registered, and cleared before that registration is torn down,
            // so the `ThreadHandleInner` it points into is always live here.
            unsafe { (*pending).fetch_or(1u64 << bit, Ordering::Relaxed) };
        }
    }
}

/// The interrupt signal has two independent jobs. Every delivery, regardless
/// of what follows, already accomplishes the older one just by arriving: EINTR
/// -ing a blocking host call (`SA_RESTART` is deliberately absent below), the
/// mechanism [`TimerProvider::create_timer`]'s doc comment describes. The
/// newer one is routing to [`litebox::shim::EnterShim::interrupt`] when the
/// signalled thread is genuinely executing guest code, mirroring
/// `litebox_platform_linux_userland`'s `interrupt_signal_handler` (a TLS
/// `in_guest` byte plus `switch_to_guest_start`/`_end` labels) and
/// `litebox_platform_windows_userland`'s `interrupt_thread`
/// (`SuspendThread`/`GetThreadContext`/`SetThreadContext` over the same label
/// range) -- adapted to this platform's process-global, `GUEST_OWNS_CPU`-based
/// single-guest-thread bookkeeping rather than either of theirs.
///
/// Four cases, matching the Linux reference's own four-way split
/// (`litebox_platform_linux_userland::interrupt_signal_handler`'s doc
/// comment), reached in the same priority order that keeps
/// [`guest::GUEST_OWNS_CPU`]'s own ordering safe: the flag first, then a
/// PC-range check, so a captured `mcontext` is only ever handed to the guest
/// when both agree.
///
/// 1. **Not in guest** ([`guest::GUEST_OWNS_CPU`] false): includes ordinary
///    host code between guest entries, *and* the tail of
///    [`guest::syscall_callback`]/[`guest::sigreturn_trampoline`] once their
///    own first couple of instructions have already cleared the flag. Record
///    [`guest::PENDING_INTERRUPT`] for [`guest::enter_guest_asm`] to re-check
///    the next time it is about to hand control to the guest -- otherwise an
///    interrupt racing exactly this narrow window (the shim already decided
///    to signal a thread it saw as "running in guest," but the platform has
///    not yet set the flag for *this* entry) would be silently lost until the
///    guest's next syscall, defeating the entire point of interrupting a
///    compute-bound guest with no syscalls at all.
/// 2. **In guest, but inside [`guest::syscall_callback`]'s or
///    [`guest::sigreturn_trampoline`]'s own brief ownership-clearing prologue**
///    (their address ranges, checked because [`guest::GUEST_OWNS_CPU`] has not
///    been cleared yet at this exact PC -- see those functions' own doc
///    comments): the guest is about to reach the shim on its own via the
///    ordinary syscall/sigreturn path within a couple of instructions.
///    [`litebox::shim::EnterShim::interrupt`]'s own doc comment says this is
///    fine ("the platform may just call the corresponding handler instead");
///    same handling as case 1 -- record and let it proceed.
/// 3. **In guest, inside [`guest::enter_guest_asm`]'s own restore range**
///    (mid-restoring a [`litebox_common_linux::PtRegs`] that is still fully
///    authoritative -- nothing has consumed it yet): abandon this entry
///    attempt without capturing anything, since the existing `*ctx` already
///    describes exactly the state the guest would have resumed with.
/// 4. **Genuinely executing guest code** (flag true, PC outside every above
///    range): capture the interrupted `mcontext`'s general and vector
///    registers the same way [`guest::prepare_exception_delivery`] does for a
///    hardware fault, and redirect to [`guest::interrupt_callback`].
///
/// # Safety
///
/// Must be installed as an `SA_SIGINFO` handler (see [`install_fault_handlers`]
/// for why `fault_handler`'s cases don't apply symmetrically the other way:
/// `SIGSEGV`/`SIGBUS` are synchronous and this signal is masked out for their
/// duration, so they can never nest inside this function; the reverse mask on
/// this handler's own installation is what makes the converse true).
unsafe extern "C" fn interrupt_signal_handler(
    _signum: libc::c_int,
    _info: *mut libc::siginfo_t,
    ucontext: *mut libc::c_void,
) {
    // SAFETY: the kernel hands a `ucontext_t` to an `SA_SIGINFO` handler, and
    // its `uc_mcontext` points at a `_STRUCT_MCONTEXT64` on this architecture,
    // exactly as in `fault_handler`.
    let machine_context = unsafe {
        let ucontext = ucontext.cast::<libc::ucontext_t>();
        if ucontext.is_null() {
            return;
        }
        (*ucontext).uc_mcontext.cast::<darwin::McontextPrefix64>()
    };
    if machine_context.is_null() {
        return;
    }

    // Per-thread, so an interrupt aimed at one guest thread can no longer be
    // consumed by a different one (and a `SIGUSR2` landing on a thread that
    // runs no guest at all has nowhere to be recorded, which is correct: its
    // other job, `EINTR`-ing a blocking host call, is already done).
    let guest_state = guest::current_guest_state();
    if !guest::guest_owns_cpu(guest_state) {
        // Case 1.
        guest::record_pending_interrupt(guest_state);
        return;
    }

    // SAFETY: checked non-null just above.
    let pc = unsafe { (*machine_context).thread_state.pc }.trunc();

    if guest::interrupted_pc_is_in_guest_exit_prologue(pc) {
        // Case 2.
        guest::record_pending_interrupt(guest_state);
        return;
    }

    let recovery = if guest::interrupted_pc_is_in_guest_entry_restore(pc) {
        // Case 3: nothing to capture, the live `PtRegs` is already correct.
        //
        // SAFETY: `guest_owns_cpu` was true (so `guest_state` is this thread's
        // own non-null live state) and `pc` falls inside `enter_guest_asm`'s
        // own restore range, matching this function's documented precondition.
        unsafe { guest::abandon_guest_entry_for_interrupt(guest_state) }
    } else {
        // Case 4.
        //
        // SAFETY: checked non-null above.
        let (thread_state, neon_state) = unsafe {
            (
                &(*machine_context).thread_state,
                &(*machine_context).neon_state,
            )
        };
        // SAFETY: `guest_owns_cpu` true (so `guest_state` is this thread's own
        // non-null live state) and `pc` outside every switch-code range
        // checked above means the interrupted context is genuinely the guest's
        // own, matching this function's documented precondition.
        unsafe { guest::prepare_interrupt_delivery(guest_state, thread_state, neon_state) }
    };
    // SAFETY: checked non-null above.
    unsafe { (*machine_context).thread_state.pc = recovery as u64 };
}

/// `pub(crate)` (rather than private) so `guest::tests` can install the real
/// `SIGUSR2` handler directly, the same way `install_fault_handlers` already
/// lets `guest::tests` install the real `SIGSEGV`/`SIGBUS` ones without
/// constructing a whole [`MacOsUserland`].
pub(crate) fn install_async_signal_handlers() {
    for signum in [libc::SIGINT, libc::SIGALRM] {
        darwin::install_handler(
            signum,
            async_signal_handler as *const () as usize,
            false,
            &[],
        );
    }
    // `SA_RESTART` is deliberately absent: interrupting a blocking call is the
    // entire purpose of this signal. Every signal `install_fault_handlers`
    // routes -- `SIGSEGV`/`SIGBUS`, and `SIGILL` for a guest's deliberate
    // CPU-feature probe -- is masked for the duration of this handler (see
    // `darwin::install_handler`'s doc comment), so a guest fault can never nest
    // atop an in-flight interrupt delivery and race the same guest-entry state.
    darwin::install_handler(
        INTERRUPT_SIGNAL,
        interrupt_signal_handler as *const () as usize,
        true,
        &[libc::SIGSEGV, libc::SIGBUS, libc::SIGILL],
    );
}

/// Blocks the two signals [`async_signal_handler`] tracks, for a thread that
/// will never hold a [`ThreadHandle::run_with_handle`] registration -- such a
/// thread has nowhere to record one, so a real `SIGINT`/`SIGALRM` the kernel
/// happened to deliver here instead of to a guest thread would otherwise never
/// reach any guest thread at all, with nothing to show for it. Mirrors
/// `litebox_platform_linux_userland::block_guest_signals`, narrowed to the two
/// real host signals this platform installs handlers for.
fn block_guest_signals() {
    // SAFETY: `set` is fully initialized by the `sigemptyset`/`sigaddset` calls
    // before `pthread_sigmask` reads it; blocking a signal has no further
    // precondition.
    unsafe {
        let mut set: libc::sigset_t = core::mem::zeroed();
        libc::sigemptyset(&raw mut set);
        libc::sigaddset(&raw mut set, libc::SIGINT);
        libc::sigaddset(&raw mut set, libc::SIGALRM);
        libc::pthread_sigmask(libc::SIG_BLOCK, &raw const set, core::ptr::null_mut());
    }
}

impl litebox::platform::SignalProvider for MacOsUserland {
    type Signal = litebox_common_linux::signal::Signal;

    fn take_pending_signals(&self, mut f: impl FnMut(Self::Signal)) {
        let pending_ptr = PENDING_SIGNALS.get();
        if pending_ptr.is_null() {
            return;
        }
        // SAFETY: see `async_signal_handler`.
        let mut pending = unsafe { (*pending_ptr).swap(0, Ordering::Relaxed) };
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
        // A timer thread is the one background thread here that `ForkGate`
        // cannot bracket, so its mere existence disables `fork_process`. Counted
        // before returning the handle, so no window exists in which the thread
        // is running but a fork still believes it is not. Never decremented:
        // `delete_timer` retires the thread asynchronously, and a count that
        // could go stale in the permissive direction would be worse than one
        // that is merely conservative.
        self.timer_threads.fetch_add(1, Ordering::AcqRel);
        Ok(TimerHandle { state })
    }
}

fn timer_thread(state: &TimerState) {
    block_guest_signals();
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
                    state.target.record_pending_signal(bit);
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

/// The state shared behind a [`ThreadHandle`].
struct ThreadHandleInner {
    id: Mutex<Option<ThreadId>>,
    /// This thread's own pending-signals bitmap -- see [`PENDING_SIGNALS`] for
    /// why it lives here, `Arc`-shared, rather than in a bare `thread_local!`.
    /// Not gated by `id`: recording a bit into a since-exited thread's copy is
    /// harmless (nothing will ever read it), unlike signalling a stale
    /// `pthread_t`.
    pending_signals: AtomicU64,
}

/// A handle to a LiteBox-managed thread, used to interrupt it and to record a
/// pending signal on it from another thread (see [`ThreadHandle::record_pending_signal`]).
pub struct ThreadHandle(Arc<ThreadHandleInner>);

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
        let handle = ThreadHandle(Arc::new(ThreadHandleInner {
            id: Mutex::new(Some(ThreadId(unsafe { libc::pthread_self() }))),
            pending_signals: AtomicU64::new(0),
        }));
        // Points into `handle`'s own heap allocation, not `handle` itself, so
        // moving `handle` into `CURRENT_THREAD` below does not invalidate it.
        PENDING_SIGNALS.set(&raw const handle.0.pending_signals);
        CURRENT_THREAD.with_borrow_mut(|current| {
            assert!(
                current.is_none(),
                "nested run_with_handle calls are not supported"
            );
            *current = Some(handle);
        });
        let _guard = litebox::utils::defer(|| {
            // Cleared before `CURRENT_THREAD`, and before the thread can exit,
            // so `async_signal_handler` never dereferences it once the
            // `ThreadHandleInner` it names may be on its way out.
            PENDING_SIGNALS.set(core::ptr::null());
            let current = CURRENT_THREAD.take().expect("handle registered above");
            // Clearing before the thread exits is what makes signalling a stale
            // `pthread_t` impossible.
            *current.0.id.lock().unwrap() = None;
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
        if let Some(thread) = *self.0.id.lock().unwrap() {
            // SAFETY: the identifier is live for as long as this lock is held.
            unsafe { libc::pthread_kill(thread.0, INTERRUPT_SIGNAL) };
        }
    }

    /// Records a pending host signal on this thread from anywhere --
    /// in particular from [`timer_thread`], which fires on its own dedicated
    /// thread and has to mark the thread it targets, not itself.
    fn record_pending_signal(&self, bit: u32) {
        self.0
            .pending_signals
            .fetch_or(1u64 << bit, Ordering::Relaxed);
    }
}

/// Two threads' pending-signal bitmaps must stay disjoint -- the property that
/// broke when this bitmap was a single process-wide `static`, which is what
/// made the shared test-harness singleton race across concurrently-run tests.
/// Each thread records a distinct signal via [`async_signal_handler`] (the
/// same call a real signal delivery makes), a `Barrier` forces both writes to
/// land before either reads back, and each must observe only its own bit.
#[cfg(test)]
#[test]
fn pending_signals_are_disjoint_across_threads() {
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));

    let b1 = std::sync::Arc::clone(&barrier);
    let t1 = std::thread::Builder::new()
        .spawn(move || {
            ThreadHandle::run_with_handle(|| {
                // SAFETY: called from within `run_with_handle`, exactly as a
                // real `SIGINT` delivered to this thread would invoke it.
                unsafe { async_signal_handler(libc::SIGINT) };
                b1.wait();
                let ptr = PENDING_SIGNALS.get();
                // SAFETY: still inside `run_with_handle` on the thread that
                // owns this pointer.
                let pending = unsafe { (*ptr).load(Ordering::Relaxed) };
                let sigint_bit = 1u64 << u32::try_from(libc::SIGINT - 1).unwrap();
                assert_eq!(
                    pending, sigint_bit,
                    "thread 1 must observe exactly its own SIGINT, not thread 2's SIGALRM"
                );
            });
        })
        .expect("failed to spawn thread 1");

    let b2 = std::sync::Arc::clone(&barrier);
    let t2 = std::thread::Builder::new()
        .spawn(move || {
            ThreadHandle::run_with_handle(|| {
                // SAFETY: see thread 1.
                unsafe { async_signal_handler(libc::SIGALRM) };
                b2.wait();
                let ptr = PENDING_SIGNALS.get();
                // SAFETY: see thread 1.
                let pending = unsafe { (*ptr).load(Ordering::Relaxed) };
                let sigalrm_bit = 1u64 << u32::try_from(libc::SIGALRM - 1).unwrap();
                assert_eq!(
                    pending, sigalrm_bit,
                    "thread 2 must observe exactly its own SIGALRM, not thread 1's SIGINT"
                );
            });
        })
        .expect("failed to spawn thread 2");

    t1.join().expect("thread 1 panicked");
    t2.join().expect("thread 2 panicked");
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
                ThreadHandle::run_with_handle(|| {
                    with_signal_alt_stack(|| guest::run_thread(shim.as_ref(), &mut ctx));
                });
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

    fn get_fp_state(&self) -> litebox::platform::FpSimdState64 {
        guest::guest_fp_state()
    }

    fn set_fp_state(&self, state: &litebox::platform::FpSimdState64) {
        guest::set_guest_fp_state(state);
    }

    /// `fork(2)`, straight through to the host kernel.
    ///
    /// This platform runs the guest's instructions natively inside this host
    /// process, so the guest's address space *is* part of this process's address
    /// space. A host `fork` therefore duplicates every guest mapping
    /// copy-on-write, with exactly the semantics `fork(2)` is specified to have,
    /// and the child resumes inside the shim at the same point the parent did --
    /// which is precisely what the guest's `fork` needs.
    ///
    /// # What makes this safe on a multithreaded host
    ///
    /// Three separate things, in order of how much of the risk they carry:
    ///
    /// 1. **The system allocator.** Darwin's `fork` runs libmalloc's own atfork
    ///    handlers, so the child's malloc zones are reinitialized rather than
    ///    inherited mid-mutation. This is not taken on trust: it is what makes
    ///    `fork_survives_sibling_threads_hammering_the_allocator` below pass
    ///    while several threads allocate as fast as they can.
    /// 2. **This platform's own background threads.** [`ForkGate`] holds them
    ///    outside their critical sections across the duplication, so no
    ///    `StdinPump` spin lock and no doorbell mutex can come across held. See
    ///    that type's docs for why a gate rather than `pthread_atfork`.
    /// 3. **The threads it cannot gate.** A `litebox-timer` thread parks in
    ///    `Condvar::wait` holding a `std::sync::Mutex`, and there is no point in
    ///    its loop where it is both idle and lock-free for a gate to catch. So
    ///    rather than claim a guarantee that is not there, this refuses to fork
    ///    at all once any timer thread exists. A guest that has armed a timer
    ///    gets `EAGAIN` from `fork`, which is a real, expected `fork` error that
    ///    callers already handle -- not a corrupt child.
    ///
    /// The guest thread doing the forking is, by construction, not inside any
    /// shim lock: it is between two guest instructions, in a syscall handler
    /// this call is the top of.
    ///
    /// # The one hazard this cannot mediate, stated plainly
    ///
    /// Darwin runs its *own* child-side handlers inside `fork`, and some of
    /// them refuse rather than repair: measured in this crate's own test binary,
    /// a `fork` issued while another thread of the same process was driving the
    /// `posix_spawn`/XPC machinery produced a child that was `SIGKILL`ed before
    /// it executed a single instruction of its own. No user-space gate can fix
    /// that, because the kill happens inside `fork` itself.
    ///
    /// It is nevertheless unreachable in a runner, and by construction rather
    /// than by luck: a runner process installs the Seatbelt profile before the
    /// guest starts, which denies `process-exec` outright, so nothing in this
    /// process can spawn anything for the rest of its life. The only threads a
    /// runner has besides the guest are the stdin pump -- which does nothing but
    /// `read(2)` and the gated push above -- and timer threads, which disable
    /// forking entirely. The test binary is the one context where a sibling
    /// thread can be spawning processes, and there the two tests are held apart
    /// explicitly (see `guest::tests::TEST_SERIAL`).
    ///
    /// # Errors
    ///
    /// [`ProcessOpError::Unsupported`] when a timer thread exists (see 3 above),
    /// and [`ProcessOpError::Failed`] if the host `fork` itself fails -- notably
    /// `EPERM` if the Seatbelt profile in force does not admit `process-fork`.
    fn fork_process(&self) -> Result<litebox::platform::ForkOutcome, ProcessOpError> {
        use litebox::platform::ForkOutcome;

        if self.timer_threads.load(Ordering::Acquire) != 0 {
            return Err(ProcessOpError::Unsupported);
        }

        // Sampled before the fork: after it, the child's own `getppid` is the
        // only other way to learn this, and reading it here costs nothing and
        // cannot race (this process cannot be reparented mid-call).
        // SAFETY: `getpid` has no preconditions and cannot fail.
        let parent_pid = unsafe { libc::getpid() };

        self.fork_gate.begin_fork();
        // SAFETY: `fork` itself has no preconditions. What makes the *child*
        // usable is established above and documented on this function: the gate
        // is closed and drained, so no thread of this process is inside a
        // critical section, and Darwin reinitializes the child's allocator.
        let rc = unsafe { libc::fork() };
        // Runs on both sides. In the child this reopens a gate whose `active`
        // count the parent already drained to zero, so it starts life open and
        // uncontended -- see `ForkGate::finish_fork`.
        self.fork_gate.finish_fork();

        match rc {
            0 => Ok(ForkOutcome::Child {
                // SAFETY: `getpid` has no preconditions and cannot fail.
                pid: unsafe { libc::getpid() },
                parent_pid,
            }),
            -1 => Err(ProcessOpError::Failed),
            child_pid => Ok(ForkOutcome::Parent { child_pid }),
        }
    }

    /// `wait4(2)`, straight through to the host kernel.
    ///
    /// Children created by [`Self::fork_process`] are real host processes, so
    /// the host's own child bookkeeping is the only bookkeeping needed: it
    /// already knows which tasks are this one's children, already blocks until
    /// one exits, and already reports the status.
    ///
    /// Darwin and Linux encode `wstatus` identically for exit and signal
    /// deaths -- `(code << 8)` for an exit, the signal number in the low seven
    /// bits for a signal death -- so the exit case passes straight through. The
    /// *signal numbers* are not identical, so a signal death is translated with
    /// [`darwin_signal_to_linux`] rather than reported as the wrong signal.
    fn reap_child(&self, pid: i32, nohang: bool) -> Result<litebox::platform::ReapedChild, ProcessOpError> {
        let mut status: libc::c_int = 0;
        let options = if nohang { libc::WNOHANG } else { 0 };
        loop {
            // SAFETY: `status` is a live, uniquely owned out-parameter.
            let rc = unsafe { libc::waitpid(pid, &raw mut status, options) };
            if rc > 0 {
                return Ok(litebox::platform::ReapedChild {
                    pid: rc,
                    status: linux_wait_status(status),
                });
            }
            if rc == 0 {
                // Only reachable with `WNOHANG`: a child exists but has not
                // exited.
                return Err(ProcessOpError::WouldBlock);
            }
            return Err(match std::io::Error::last_os_error().raw_os_error() {
                // A host signal (this platform's own `SIGUSR2` guest-interrupt,
                // for instance) landed mid-wait. Nothing was reaped and nothing
                // was lost, so just wait again rather than surfacing an `EINTR`
                // the guest never asked about.
                Some(libc::EINTR) => continue,
                Some(libc::ECHILD) => ProcessOpError::NoChildren,
                _ => ProcessOpError::Failed,
            });
        }
    }
}

/// The central claim behind `fork_process` -- that a child forked out of this
/// multithreaded host process is actually usable -- rests on Darwin
/// reinitializing the child's allocator rather than handing it whatever state
/// libmalloc's locks happened to be in. That is a property of the host, not of
/// this crate, so it is measured here rather than asserted in a comment: sibling
/// threads allocate as fast as they can for the whole run, and every child has
/// to allocate, take a `MAP_JIT` mapping (the one mapping kind the whole
/// platform depends on) and write to its heap before exiting cleanly.
///
/// A child that inherited a frozen allocator lock does not fail this test with a
/// wrong answer; it hangs. That is deliberate: `waitpid` below would never
/// return and the harness's own timeout is what would report it, which is a far
/// louder failure than a silently-skipped assertion.
#[cfg(test)]
#[test]
fn fork_survives_sibling_threads_hammering_the_allocator() {
    use core::sync::atomic::AtomicBool;

    const HAMMER_THREADS: usize = 4;
    const ROUNDS: usize = 60;

    // Keeps this apart from the one other test in this binary that creates
    // processes; see `TEST_SERIAL`'s docs for why overlapping them makes Darwin
    // kill this test's children before they run.
    let _serial = guest::tests::TEST_SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);

    let stop = Arc::new(AtomicBool::new(false));

    let hammers: alloc::vec::Vec<_> = (0..HAMMER_THREADS)
        .map(|_| {
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                let mut sink: alloc::vec::Vec<alloc::vec::Vec<u8>> = alloc::vec::Vec::new();
                while !stop.load(Ordering::Acquire) {
                    sink.push(alloc::vec![0xa5u8; 4096]);
                    if sink.len() > 32 {
                        sink.clear();
                    }
                }
            })
        })
        .collect();

    let gate = ForkGate::new();
    let mut healthy = 0;
    for _ in 0..ROUNDS {
        gate.begin_fork();
        // SAFETY: `fork` has no preconditions; the child below only performs
        // operations this test is measuring the safety of.
        let pid = unsafe { libc::fork() };
        gate.finish_fork();
        assert_ne!(pid, -1, "fork failed: {}", std::io::Error::last_os_error());
        if pid == 0 {
            // A heap allocation, a real `MAP_JIT` mapping, and a write through
            // both. Any of these would hang or fail on a broken child.
            let mut owned = alloc::vec![0u8; 1 << 16];
            owned[0xfff] = 0x5a;
            // SAFETY: a fresh anonymous `MAP_JIT` mapping request with no fixed
            // address.
            let jit = unsafe {
                libc::mmap(
                    core::ptr::null_mut(),
                    litebox::mm::linux::PAGE_SIZE,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANON | MAP_JIT,
                    -1,
                    0,
                )
            };
            let code = i32::from(jit == libc::MAP_FAILED || owned[0xfff] != 0x5a);
            // `_exit`, not `std::process::exit`: the latter runs atexit handlers
            // registered by the parent's test harness, which is exactly the
            // class of inherited state a forked child must not touch.
            // SAFETY: `_exit` performs no cleanup and cannot fail.
            unsafe { libc::_exit(code) };
        }
        let mut status: libc::c_int = 0;
        // SAFETY: `status` is a live, uniquely owned out-parameter.
        let reaped = unsafe { libc::waitpid(pid, &raw mut status, 0) };
        assert_eq!(
            reaped,
            pid,
            "waitpid({pid}) did not reap the child it was asked for: {}",
            std::io::Error::last_os_error()
        );
        assert_eq!(
            status,
            0,
            "a child forked from this multithreaded process did not exit cleanly \
             (raw wait status {status:#x}: exit code {}, killing signal {})",
            (status >> 8) & 0xff,
            status & 0x7f
        );
        healthy += 1;
    }

    stop.store(true, Ordering::Release);
    for h in hammers {
        h.join().expect("a hammer thread panicked");
    }
    assert_eq!(healthy, ROUNDS);
}

/// [`ForkGate`] only earns its place if a fork genuinely cannot straddle a
/// declared critical section. This drives a background thread through the gate
/// continuously and checks the two properties the child's correctness rests on:
/// `begin_fork` never returns while a section is in progress, and `active` is
/// zero at that moment -- which is the exact state the child inherits.
#[cfg(test)]
#[test]
fn the_fork_gate_never_lets_a_fork_straddle_a_critical_section() {
    use core::sync::atomic::AtomicBool;

    let gate = Arc::new(ForkGate::new());
    let stop = Arc::new(AtomicBool::new(false));
    // Set for as long as the background thread is inside its critical section.
    let inside = Arc::new(AtomicBool::new(false));

    let worker = {
        let (gate, stop, inside) = (Arc::clone(&gate), Arc::clone(&stop), Arc::clone(&inside));
        std::thread::spawn(move || {
            while !stop.load(Ordering::Acquire) {
                gate.critical_section(|| {
                    inside.store(true, Ordering::Release);
                    // Long enough that a `begin_fork` which ignored the gate
                    // would land inside this window rather than missing it by
                    // luck.
                    for _ in 0..200 {
                        core::hint::spin_loop();
                    }
                    inside.store(false, Ordering::Release);
                });
            }
        })
    };

    for _ in 0..2000 {
        gate.begin_fork();
        assert!(
            !inside.load(Ordering::Acquire),
            "begin_fork returned while a critical section was in progress"
        );
        // The state a forked child would inherit at exactly this point. It has
        // to be a zero count, because the child has no thread left that could
        // ever decrement it, and its own next `fork` waits for it to reach zero.
        // A separate flag-and-counter gate fails right here.
        assert_eq!(
            gate.state.load(Ordering::Acquire) & ForkGate::COUNT,
            0,
            "a child forked now would inherit a non-zero in-flight count and hang on its own \
             next fork"
        );
        gate.finish_fork();
    }

    stop.store(true, Ordering::Release);
    worker.join().expect("the gated worker panicked");
}

/// The wait-status translation has to keep Linux's encoding exactly: a normal
/// exit must survive untouched (the two kernels already agree there), and a
/// signal death must report the *Linux* signal number, not Darwin's.
#[cfg(test)]
#[test]
fn wait_statuses_are_translated_into_linuxs_encoding() {
    // Exit statuses are identical on both kernels, so they must pass through
    // bit for bit -- including a zero exit, and including the high bits.
    assert_eq!(linux_wait_status(0), 0);
    assert_eq!(linux_wait_status(42 << 8), 42 << 8);
    assert_eq!(linux_wait_status(255 << 8), 255 << 8);

    // A signal both kernels number the same way is unchanged...
    assert_eq!(linux_wait_status(libc::SIGSEGV), 11);
    assert_eq!(linux_wait_status(libc::SIGKILL), 9);
    // ...including its core-dump bit.
    assert_eq!(linux_wait_status(libc::SIGSEGV | 0x80), 0xb | 0x80);

    // A signal they number differently is translated. Darwin's SIGBUS is 10,
    // Linux's is 7; reporting 10 unchanged would name Linux's SIGUSR1.
    assert_eq!(libc::SIGBUS, 10, "this test is pinned to Darwin's numbering");
    assert_eq!(linux_wait_status(libc::SIGBUS), 7);
    assert_eq!(libc::SIGCHLD, 20, "this test is pinned to Darwin's numbering");
    assert_eq!(linux_wait_status(libc::SIGCHLD), 17);

    // "Stopped" is not a killing signal and must not be run through the signal
    // translation at all.
    let stopped = (libc::SIGTSTP << 8) | 0x7f;
    assert_eq!(linux_wait_status(stopped), stopped);
}

/// Rewrites a Darwin `wait` status into the encoding Linux's `wait4` writes.
///
/// The layout is already shared -- both put an exit code in bits 8..16 with the
/// low seven bits clear, and a killing signal in the low seven bits with bit 7
/// as the core-dump flag -- so only the signal *number* needs translating, and
/// only when the child actually died from one.
fn linux_wait_status(status: libc::c_int) -> i32 {
    let termsig = status & 0x7f;
    // 0 is a normal exit and 0x7f is "stopped"; neither carries a killing
    // signal in these bits.
    if termsig == 0 || termsig == 0x7f {
        return status;
    }
    let core_dumped = status & 0x80;
    (status & !0xff) | core_dumped | darwin_signal_to_linux(termsig)
}

/// Maps a Darwin signal number onto the Linux one with the same meaning.
///
/// Most of the numbers agree (`SIGSEGV` is 11 on both, `SIGKILL` 9, `SIGTERM`
/// 15, `SIGPIPE` 13, `SIGINT` 2, `SIGABRT` 6), which is why only the handful
/// that genuinely differ are listed. Anything unrecognized is passed through
/// unchanged: reporting the raw number is strictly better than inventing a
/// different signal for it.
fn darwin_signal_to_linux(darwin: libc::c_int) -> i32 {
    match darwin {
        libc::SIGBUS => 7,     // Linux SIGBUS
        libc::SIGUSR1 => 10,   // Linux SIGUSR1
        libc::SIGUSR2 => 12,   // Linux SIGUSR2
        libc::SIGCHLD => 17,   // Linux SIGCHLD
        libc::SIGCONT => 18,   // Linux SIGCONT
        libc::SIGSTOP => 19,   // Linux SIGSTOP
        libc::SIGTSTP => 20,   // Linux SIGTSTP
        libc::SIGURG => 23,    // Linux SIGURG
        libc::SIGIO => 29,     // Linux SIGIO
        libc::SIGSYS => 31,    // Linux SIGSYS
        other => other,
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
/// Both halves of that fix have landed: `Host::MacOs` gates no longer bake the
/// slot number in, they read a byte offset from the trampoline header at run
/// time, and `litebox_shim_linux`'s ELF loader (`loader/elf.rs`) already reads
/// [`guest_tp_slot_byte_offset`] and writes it there via
/// `litebox_common_linux::loader::ElfParsedFile::parse_trampoline` /
/// `load_trampoline`, on every macOS load path. The mismatch below is
/// therefore no longer live for a guest reached through this platform's
/// loader; it stays as a defensive warning for any other embedder of this
/// crate that constructs a trampoline without going through that path.
///
/// This reserves a key and records it, but does **not** hard fail on a mismatch:
/// panicking here made the whole platform unconstructable on real hardware,
/// blocking everything else (memory, syscalls, the context switch) that does not
/// touch the guest thread pointer at all. Instead it warns loudly. A guest that
/// never reads/writes `TPIDR_EL0` is unaffected; a guest that does would target
/// the stale baked slot and is **not supported** until a loader fills the header
/// slot. `litebox_runner_linux_on_macos_userland` already calls
/// [`MacOsUserland::new`] for every guest it runs (see `docs/roadmap.md`'s
/// "Running a guest on macOS"), so this path runs in production on every
/// syscall-only guest today; only a `TPIDR_EL0`-using guest is unsupported.
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

/// The pthread TSD key [`ArchSpecificRegister::TpidrEl0`] accessors and
/// [`guest_tp_slot_byte_offset`] both address, or `None` before
/// [`reserve_guest_tpidr_tsd_slot`] has run.
///
/// [`ArchSpecificRegister::TpidrEl0`]: litebox::platform::ArchSpecificRegister::TpidrEl0
fn guest_tp_tsd_key() -> Option<libc::pthread_key_t> {
    let key = GUEST_TP_TSD_KEY.load(Ordering::Relaxed);
    if key == u32::MAX {
        return None;
    }
    Some(libc::pthread_key_t::from(key))
}

/// The byte offset a `Host::MacOs` gate must add to `TPIDRRO_EL0` to reach this
/// process's guest thread-pointer slot, or `None` before
/// [`reserve_guest_tpidr_tsd_slot`] has run.
///
/// This is the number a loader writes into the trampoline's guest-TP header slot
/// so the ahead-of-time gates address the key this process actually reserved,
/// rather than the one the rewriter guessed at packaging time. Darwin's TSD array
/// is indexed by key with 8-byte elements and no low-bit masking on arm64
/// (verified against xnu's `libsyscall/os/tsd.h` `_os_tsd_get_base`), so the
/// offset is simply the key scaled by the element size -- the same key
/// [`ArchSpecificProvider::get_arch_specific_register`]/[`set_arch_specific_register`]
/// reach via `pthread_getspecific`/`pthread_setspecific` instead, since a gate is
/// raw bytes patched into an arbitrary guest binary and cannot call either.
///
/// [`ArchSpecificProvider::get_arch_specific_register`]: litebox::platform::ArchSpecificProvider::get_arch_specific_register
/// [`set_arch_specific_register`]: litebox::platform::ArchSpecificProvider::set_arch_specific_register
// This crate is aarch64-only (see the module docs), so `usize` is always 64
// bits wide and a `pthread_key_t` always fits; a fallible conversion here
// would only relocate an unreachable failure, never remove it.
#[allow(clippy::cast_possible_truncation)]
pub fn guest_tp_slot_byte_offset() -> Option<usize> {
    Some(guest_tp_tsd_key()? as usize * size_of::<usize>())
}

/// Runs a guest thread with the given shim and initial context, returning when
/// the thread terminates.
///
/// This is how a runner starts the *initial* guest thread; every thread the
/// guest creates afterwards arrives through
/// [`litebox::platform::ThreadProvider::spawn_thread`] instead. It mirrors
/// `litebox_platform_linux_userland::run_thread`, so a runner reads the same on
/// either host.
///
/// # Safety
///
/// `ctx` must describe a runnable guest context: a valid entry `pc`, and an `sp`
/// addressing a guest stack with at least 16 usable bytes below it (see the
/// `guest` module's below-`SP` staging note). Only one guest thread may run at a
/// time on this platform; a second is a loud panic rather than corruption.
pub unsafe fn run_thread<T>(shim: T, ctx: &mut litebox_common_linux::PtRegs)
where
    T: litebox::shim::EnterShim<ExecutionContext = litebox_common_linux::PtRegs>,
{
    // The handle has to exist before the shim runs, not merely before the guest
    // does: `EnterShim::init` attaches an interrupt handle to the thread, which
    // reads `current_thread()`, and that panics on a thread this was never
    // called on. `spawn_thread` wraps its own entry the same way.
    ThreadHandle::run_with_handle(|| {
        with_signal_alt_stack(|| guest::run_thread(&shim, ctx));
    });
}

/// The reserved key must convert into a byte offset the gates can actually use:
/// non-zero (offset zero is pthread TSD slot 0, live libpthread state) and scaled
/// by the 8-byte TSD element size.
#[cfg(test)]
#[test]
fn the_guest_tp_slot_offset_is_a_scaled_nonzero_byte_offset() {
    let key = reserve_guest_tpidr_tsd_slot();
    let offset = guest_tp_slot_byte_offset().expect("the key is recorded by now");
    assert_eq!(
        offset,
        usize::try_from(key).unwrap() * 8,
        "offset is the key scaled by 8"
    );
    assert_ne!(offset, 0, "offset zero would address live libpthread state");
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

/// `ArchSpecificProvider::{get,set}_arch_specific_register` for `TpidrEl0`
/// route through `pthread_setspecific`/`pthread_getspecific` on
/// [`guest_tp_tsd_key`] -- the same key the rewriter's gates address via
/// `[TPIDRRO_EL0 + guest_tp_slot_byte_offset()]`. A value stored that way must
/// round-trip on this hardware, and a second read must not change it
/// (`macos-tpidr-archspecific-reconciliation`: this used to write a
/// disconnected thread-local instead).
#[cfg(test)]
#[test]
fn guest_tp_tsd_key_round_trips_a_pthread_specific_value() {
    reserve_guest_tpidr_tsd_slot();
    let key = guest_tp_tsd_key().expect("the key is recorded by now");

    // SAFETY: `key` was just reserved above and is live for this thread.
    let initial = unsafe { libc::pthread_getspecific(key) };
    assert!(
        initial.is_null(),
        "a freshly reserved key starts null, matching clone(2)'s no-CLONE_SETTLS default"
    );

    let sentinel = 0xDEAD_BEEFusize as *mut libc::c_void;
    // SAFETY: `key` is a live, reserved key; storing an opaque pointer-sized
    // value has no precondition beyond that.
    assert_eq!(unsafe { libc::pthread_setspecific(key, sentinel) }, 0);
    // SAFETY: same key, same thread as the store above.
    assert_eq!(
        unsafe { libc::pthread_getspecific(key) },
        sentinel,
        "the value set_arch_specific_register would store must read back unchanged"
    );
    // Replay: a second read must not itself mutate the stored value.
    // SAFETY: same key, same thread.
    assert_eq!(unsafe { libc::pthread_getspecific(key) }, sentinel);

    // A guest fully controls this value (it is the argument to a guest-issued
    // `MSR TPIDR_EL0` or `clone(CLONE_SETTLS)`), so the full `usize` range
    // must survive the round trip losslessly -- no truncation at either the
    // `val as *const c_void` store or the `as usize` load.
    for adversarial in [0usize, usize::MAX, usize::MAX / 2] {
        let ptr = adversarial as *mut libc::c_void;
        // SAFETY: same key; an opaque store has no precondition on the value.
        assert_eq!(unsafe { libc::pthread_setspecific(key, ptr) }, 0);
        // SAFETY: same key, same thread as the store above.
        assert_eq!(
            unsafe { libc::pthread_getspecific(key) } as usize,
            adversarial,
            "boundary value {adversarial:#x} must round-trip without truncation"
        );
    }
}

/// Two threads sharing the SAME reserved key must observe independent
/// values -- the disjointness property a real deployment depends on, since
/// [`reserve_guest_tpidr_tsd_slot`] reserves one key for the whole process and
/// every guest thread's [`ArchSpecificProvider::set_arch_specific_register`]
/// writes through it. A shared global instead of per-thread TSD storage would
/// let one guest thread's `TPIDR_EL0` leak into another's. A `Barrier` forces
/// both threads' writes to land before either reads back, so the assertion
/// cannot pass merely because of a lucky non-overlapping schedule.
///
/// [`ArchSpecificProvider::set_arch_specific_register`]: litebox::platform::ArchSpecificProvider::set_arch_specific_register
#[cfg(test)]
#[test]
fn guest_tp_tsd_key_is_disjoint_across_threads() {
    reserve_guest_tpidr_tsd_slot();
    let key = guest_tp_tsd_key().expect("the key is recorded by now");
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));

    let b1 = std::sync::Arc::clone(&barrier);
    let t1 = std::thread::Builder::new()
        .spawn(move || {
            let sentinel = 0x1111_1111usize as *mut libc::c_void;
            // SAFETY: `key` is a live, process-wide-reserved key; each thread
            // owns its own TSD slot for it.
            assert_eq!(unsafe { libc::pthread_setspecific(key, sentinel) }, 0);
            b1.wait();
            // SAFETY: same key, same thread as the store above.
            assert_eq!(unsafe { libc::pthread_getspecific(key) }, sentinel);
        })
        .expect("failed to spawn thread 1");

    let b2 = std::sync::Arc::clone(&barrier);
    let t2 = std::thread::Builder::new()
        .spawn(move || {
            let sentinel = 0x2222_2222usize as *mut libc::c_void;
            // SAFETY: `key` is a live, process-wide-reserved key; each thread
            // owns its own TSD slot for it.
            assert_eq!(unsafe { libc::pthread_setspecific(key, sentinel) }, 0);
            b2.wait();
            // SAFETY: same key, same thread as the store above.
            assert_eq!(unsafe { libc::pthread_getspecific(key) }, sentinel);
        })
        .expect("failed to spawn thread 2");

    t1.join().expect("thread 1 panicked");
    t2.join().expect("thread 2 panicked");
}

// ---------------------------------------------------------------------------
// Faults
// ---------------------------------------------------------------------------

/// Install the handlers that make LiteBox's accesses to guest memory fallible,
/// and that route a genuine guest hardware fault to
/// [`litebox::shim::EnterShim::exception`] instead of taking the whole process
/// down.
///
/// Without these, a `UserConstPtr` read of an unmapped guest address takes the
/// process down instead of returning `None`; see
/// [`litebox::platform::common_providers::userspace_pointers`].
///
/// `INTERRUPT_SIGNAL` is masked for the duration of both handlers -- see
/// `darwin::install_handler`'s doc comment -- so a cross-thread
/// `ThreadHandle::interrupt` call can never nest an interrupt-delivery signal
/// atop an in-flight fault delivery and race the same process-global
/// guest-entry state (`guest::GUEST_OWNS_CPU`/`LIVE_PTREGS`/`GUEST_FP`/
/// `PENDING_EXCEPTION_INFO`).
/// `SIGILL` is installed alongside the memory faults because a guest can raise
/// it deliberately and expect to survive: probing for an optional CPU feature by
/// executing an instruction from it and catching the resulting `SIGILL` is a
/// real, widespread idiom. Node's bundled OpenSSL does exactly this with
/// `sm3partw1` (`_armv8_sm3_probe`), and Apple Silicon implements no
/// FEAT_SM3/FEAT_SM4, so the instruction genuinely traps. Without a handler here
/// that trap killed the whole runner instead of reaching the guest's own
/// handler. Nothing downstream needed changing: an undefined instruction raises
/// ESR exception class 0 (`UNKNOWN`), which
/// `litebox_shim_linux::syscalls::signal::aarch64::exception_signal` already
/// maps to `Signal::SIGILL`, mirroring the kernel's own `do_el0_undef`.
pub(crate) fn install_fault_handlers() {
    for signum in [libc::SIGSEGV, libc::SIGBUS, libc::SIGILL] {
        darwin::install_handler(
            signum,
            fault_handler as *const () as usize,
            true,
            &[INTERRUPT_SIGNAL],
        );
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
        // A LiteBox access to guest memory faulted -- either one of this
        // crate's own recoverable accesses to guest memory, or one of
        // `guest::GUEST_OWNS_CPU`'s boundary windows -- and the exception
        // table says where to continue; redirecting the program counter is
        // what turns the fault into either a `None` return or a loud abort.
        // This check always takes priority over the GUEST_OWNS_CPU check
        // below: every guest-memory touch this platform's own switch code
        // makes while that flag could read true is covered by an entry here,
        // which is exactly what makes the flag-based check below safe.
        //
        // SAFETY: checked non-null just above.
        unsafe { (*machine_context).thread_state.pc = recovery as u64 };
        return;
    }

    // Per-thread: null on any thread that is not inside `guest::run_thread`,
    // and each guest thread's own state is disjoint from every other's.
    let guest_state = guest::current_guest_state();
    if guest::guest_owns_cpu(guest_state) {
        // The exception table missed and the guest genuinely owns the CPU at
        // this pc (not merely mid-switch -- see the ordering note above), so
        // this is a real guest fault: hand it to the guest via
        // `EnterShim::exception` instead of taking the process down.
        //
        // SAFETY: checked non-null just above.
        let (thread_state, exception_state, neon_state) = unsafe {
            (
                &(*machine_context).thread_state,
                &(*machine_context).exception_state,
                &(*machine_context).neon_state,
            )
        };
        let esr = u64::from(exception_state.esr);
        let info = litebox::shim::ExceptionInfo {
            // ESR_EL1's exception class occupies bits [31:26]; see
            // `litebox::shim::ExceptionInfo::exception`'s own doc comment.
            exception: litebox::shim::Exception(((esr >> 26) & 0x3f) as u8),
            fault_address: exception_state.far.trunc(),
            esr,
            // This platform's guest always runs at EL0; there is no
            // "kernel-mode access faulted" case for a userland host to model.
            kernel_mode: false,
        };
        // SAFETY: `guest_owns_cpu` just returned true, which also means
        // `guest_state` is this thread's own non-null live state -- this
        // function's own documented precondition.
        let recovery = unsafe {
            guest::prepare_exception_delivery(guest_state, thread_state, neon_state, info)
        };
        // SAFETY: checked non-null just above.
        unsafe { (*machine_context).thread_state.pc = recovery as u64 };
        return;
    }

    // Not a recoverable LiteBox access, and not a genuine guest fault either.
    // Restore the default disposition and return so the faulting instruction
    // re-executes and takes the process down exactly as it would have without
    // this handler installed.
    darwin::reraise_fatally(signum);
}

/// Detects heap activity performed *inside* [`fault_handler`] or
/// [`interrupt_signal_handler`], so a test can assert that this platform's
/// fault- and interrupt-delivery paths stay async-signal-safe.
///
/// Everything reachable from a POSIX signal handler must be async-signal-safe,
/// and `malloc`/`free` are the canonical counter-example: Darwin's allocator
/// takes a non-reentrant `os_unfair_lock`, so allocating in a handler that
/// interrupted the same thread mid-`malloc` deadlocks the process. The
/// interesting allocations are not this crate's own explicit ones (there are
/// none on that path) but the *hidden* ones a future edit could reintroduce --
/// a `format!`, a `Vec`, or a logging macro whose backend allocates. A
/// pass-through [`core::alloc::GlobalAlloc`] catches all of them uniformly,
/// which is why this is an allocator rather than a call-site assertion.
///
/// "Inside a handler" is detected from the signal mask rather than from a flag
/// the handler sets, because the handler must not be modified to be
/// measurable: [`install_fault_handlers`] installs `SIGSEGV`/`SIGBUS` with
/// `sa_mask = { INTERRUPT_SIGNAL }` and without `SA_NODEFER`, so the kernel
/// runs [`fault_handler`] with both the delivered fault signal *and*
/// [`INTERRUPT_SIGNAL`] blocked; [`install_async_signal_handlers`] installs
/// `INTERRUPT_SIGNAL` with `sa_mask = { SIGSEGV, SIGBUS }`, so
/// [`interrupt_signal_handler`] runs with the same combination in force.
/// Nothing else in this crate ever blocks any of the three
/// ([`block_guest_signals`] blocks only `SIGINT`/`SIGALRM`), so that
/// combination is a precise, self-updating test for "the calling thread is
/// executing one of this platform's guest-delivery signal handlers right now"
/// -- and it keeps working unchanged if the masks are ever widened further.
///
/// The mask query is a real syscall, so it only runs while
/// [`ProbeAllocator::arm`] has turned it on; outside that window every
/// allocation in the test binary pays one relaxed atomic load.
///
/// The probe's own state lives in [`ProbeAllocator`]'s fields rather than in
/// free `static`s purely to keep `dev_tests`' `ratchet_globals` count honest:
/// `#[global_allocator]` requires exactly one `static`, and there is no reason
/// for this test scaffolding to cost three.
#[cfg(test)]
mod signal_handler_alloc_probe {
    use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    /// Whether the calling thread is currently running
    /// [`super::fault_handler`] or [`super::interrupt_signal_handler`], per
    /// this module's doc comment.
    fn inside_signal_handler() -> bool {
        // SAFETY: `current` is fully initialized by `sigemptyset` before
        // `pthread_sigmask` writes it, a null `set` argument makes the call a
        // pure query, and `sigismember` only reads it.
        unsafe {
            let mut current: libc::sigset_t = core::mem::zeroed();
            libc::sigemptyset(&raw mut current);
            if libc::pthread_sigmask(libc::SIG_BLOCK, core::ptr::null(), &raw mut current) != 0 {
                return false;
            }
            libc::sigismember(&raw const current, super::INTERRUPT_SIGNAL) == 1
                && (libc::sigismember(&raw const current, libc::SIGSEGV) == 1
                    || libc::sigismember(&raw const current, libc::SIGBUS) == 1)
        }
    }

    /// The pass-through allocator this module installs for the test binary.
    pub(crate) struct ProbeAllocator {
        /// Whether each allocation should be checked. Off outside a test that
        /// explicitly asked for the check.
        armed: AtomicBool,
        /// How many allocations were made from inside a signal handler while
        /// armed.
        inside_handler: AtomicUsize,
    }

    impl ProbeAllocator {
        pub(crate) const fn new() -> Self {
            Self {
                armed: AtomicBool::new(false),
                inside_handler: AtomicUsize::new(0),
            }
        }

        /// Records one allocation if it is happening inside a signal handler.
        fn note_allocation(&self) {
            if self.armed.load(Ordering::Relaxed) && inside_signal_handler() {
                self.inside_handler.fetch_add(1, Ordering::Relaxed);
            }
        }

        /// Starts checking, resetting the count first so each armed window
        /// reports only its own allocations.
        pub(crate) fn arm(&self) {
            self.inside_handler.store(0, Ordering::Relaxed);
            self.armed.store(true, Ordering::Relaxed);
        }

        /// Stops checking and reports how many allocations happened inside a
        /// signal handler since [`Self::arm`].
        pub(crate) fn disarm(&self) -> usize {
            self.armed.store(false, Ordering::Relaxed);
            self.inside_handler.load(Ordering::Relaxed)
        }
    }

    // SAFETY: every method forwards to `std::alloc::System` with the caller's
    // own arguments unchanged, so the allocator contract is exactly
    // `System`'s; `note_allocation` neither allocates nor touches the
    // returned block.
    unsafe impl core::alloc::GlobalAlloc for ProbeAllocator {
        unsafe fn alloc(&self, layout: core::alloc::Layout) -> *mut u8 {
            self.note_allocation();
            // SAFETY: forwarded caller guarantee.
            unsafe { core::alloc::GlobalAlloc::alloc(&std::alloc::System, layout) }
        }

        unsafe fn alloc_zeroed(&self, layout: core::alloc::Layout) -> *mut u8 {
            self.note_allocation();
            // SAFETY: forwarded caller guarantee.
            unsafe { core::alloc::GlobalAlloc::alloc_zeroed(&std::alloc::System, layout) }
        }

        unsafe fn dealloc(&self, ptr: *mut u8, layout: core::alloc::Layout) {
            self.note_allocation();
            // SAFETY: forwarded caller guarantee.
            unsafe { core::alloc::GlobalAlloc::dealloc(&std::alloc::System, ptr, layout) }
        }

        unsafe fn realloc(
            &self,
            ptr: *mut u8,
            layout: core::alloc::Layout,
            new_size: usize,
        ) -> *mut u8 {
            self.note_allocation();
            // SAFETY: forwarded caller guarantee.
            unsafe { core::alloc::GlobalAlloc::realloc(&std::alloc::System, ptr, layout, new_size) }
        }
    }
}

/// See [`signal_handler_alloc_probe`]; only the crate's own test binary gets
/// this allocator, production builds keep the default one.
#[cfg(test)]
#[global_allocator]
static PROBE_ALLOCATOR: signal_handler_alloc_probe::ProbeAllocator =
    signal_handler_alloc_probe::ProbeAllocator::new();

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

// ---------------------------------------------------------------------------
// Guest-directed signal delivery
// ---------------------------------------------------------------------------

/// Guard page below the alternate signal stack, sized to this platform's 16
/// KiB pages so a stack-overflowing handler faults instead of corrupting
/// whatever mapping [`with_signal_alt_stack`] happened to place below it.
const ALT_STACK_GUARD_SIZE: usize = litebox::mm::linux::PAGE_SIZE;

/// Runs `f` with an alternate signal stack installed on the calling thread.
///
/// `guest::enter_guest_asm` stages the guest `PC` and `X0` in the 16 bytes
/// below the guest `SP` for the brief window before it branches there, and
/// AArch64 has no red zone protecting that staging area from a signal handler
/// that runs on the interrupted stack. `darwin::install_handler` sets
/// `SA_ONSTACK` on every handler this platform installs precisely so that risk
/// is avoidable, but `SA_ONSTACK` only takes effect once a thread has actually
/// registered a stack for it to use -- every entry point that can run guest
/// code ([`ThreadProvider::spawn_thread`](litebox::platform::ThreadProvider::spawn_thread)
/// and the free [`run_thread`]) wraps its call in this so that registration
/// always happens first.
fn with_signal_alt_stack<R>(f: impl FnOnce() -> R) -> R {
    let alt_stack_size = libc::SIGSTKSZ * 2;
    // SAFETY: an anonymous mapping with no fixed-address request has no
    // precondition beyond what `mmap` itself checks.
    let stack_base = unsafe {
        libc::mmap(
            core::ptr::null_mut(),
            ALT_STACK_GUARD_SIZE + alt_stack_size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANON,
            -1,
            0,
        )
    };
    assert!(
        stack_base != libc::MAP_FAILED,
        "failed to allocate the alternate signal stack: {}",
        std::io::Error::last_os_error()
    );
    let _unmap_guard = litebox::utils::defer(|| {
        // SAFETY: `stack_base` is the mapping created above, unmapped exactly
        // once here.
        let rc = unsafe { libc::munmap(stack_base, ALT_STACK_GUARD_SIZE + alt_stack_size) };
        assert!(
            rc == 0,
            "failed to unmap the alternate signal stack: {}",
            std::io::Error::last_os_error()
        );
    });

    // SAFETY: `stack_base` is a live mapping of at least `ALT_STACK_GUARD_SIZE`
    // bytes, still solely owned by this function.
    let rc = unsafe { libc::mprotect(stack_base, ALT_STACK_GUARD_SIZE, libc::PROT_NONE) };
    assert!(
        rc == 0,
        "failed to guard the alternate signal stack: {}",
        std::io::Error::last_os_error()
    );

    let alt_stack = libc::stack_t {
        // SAFETY: `stack_base` addresses a mapping at least
        // `ALT_STACK_GUARD_SIZE + alt_stack_size` bytes long, so this stays
        // within it.
        ss_sp: unsafe { stack_base.add(ALT_STACK_GUARD_SIZE) },
        ss_size: alt_stack_size,
        ss_flags: 0,
    };
    // SAFETY: a zeroed `stack_t` is a valid, if meaningless, initial value;
    // `sigaltstack` below overwrites every field that matters.
    let mut previous: libc::stack_t = unsafe { core::mem::zeroed() };
    // SAFETY: `alt_stack` addresses the mapping above, which outlives this
    // call; `previous` is a live, correctly typed out-parameter.
    let rc = unsafe { libc::sigaltstack(&raw const alt_stack, &raw mut previous) };
    assert!(
        rc == 0,
        "failed to install the alternate signal stack: {}",
        std::io::Error::last_os_error()
    );
    let _restore_guard = litebox::utils::defer(|| {
        // SAFETY: `previous` was filled in by the `sigaltstack` call above and
        // describes whatever stack (if any) this thread had before it.
        let rc = unsafe { libc::sigaltstack(&raw const previous, core::ptr::null_mut()) };
        assert!(
            rc == 0,
            "failed to restore the previous signal stack: {}",
            std::io::Error::last_os_error()
        );
    });

    f()
}

#[cfg(test)]
fn current_signal_stack() -> libc::stack_t {
    // SAFETY: a null `ss` argument only queries the current stack, it does not
    // install one.
    unsafe {
        let mut oss: libc::stack_t = core::mem::zeroed();
        libc::sigaltstack(core::ptr::null(), &raw mut oss);
        oss
    }
}

/// Rust's own runtime already installs a guard-page alternate stack on every
/// thread it starts (for its stack-overflow handler), so a fresh test thread
/// does *not* reliably start with [`libc::SS_DISABLE`] -- this compares
/// against whatever `before` actually was rather than assuming it is
/// disabled.
#[cfg(test)]
#[test]
fn with_signal_alt_stack_actually_registers_one() {
    // `with_signal_alt_stack` does a real host `mmap`/`munmap` of its own,
    // which can race `allocate_jit_pages_hint_honors_the_suggested_address`'s
    // address-space probing under the parallel test harness; serialize
    // against it the same way guest-entry tests already do.
    let _serial = guest::tests::TEST_SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);

    let before = current_signal_stack();
    let during = with_signal_alt_stack(current_signal_stack);
    let after = current_signal_stack();

    assert_ne!(
        during.ss_sp, before.ss_sp,
        "with_signal_alt_stack must install a stack distinct from whatever \
         (if any) the thread already had"
    );
    assert_eq!(
        during.ss_flags & libc::SS_DISABLE,
        0,
        "the installed stack must actually be enabled"
    );
    assert!(
        during.ss_size >= libc::SIGSTKSZ,
        "the installed stack must be large enough to actually run a handler"
    );
    assert_eq!(
        (after.ss_sp, after.ss_size, after.ss_flags),
        (before.ss_sp, before.ss_size, before.ss_flags),
        "the previous stack (if any) must be restored exactly once f returns"
    );
}
