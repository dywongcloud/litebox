// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Thin bindings to the Darwin interfaces that have no `libc` crate coverage or
//! no direct POSIX equivalent.
//!
//! Everything here is either a documented libSystem entry point or a stable
//! kernel ABI. The `__ulock_*` family is the exception: it is not in a public
//! header, but it is the primitive libdispatch, libc++ and Rust's own standard
//! library have used for the same purpose for years, and it is the only
//! compare-and-wait facility available on every Apple Silicon release. The
//! public `os_sync_wait_on_address` alternative only exists from macOS 14.4,
//! which would leave earlier M-series machines with no implementation at all.

use core::sync::atomic::AtomicU32;
use core::time::Duration;

/// `MAP_JIT` from `<sys/mman.h>`: an anonymous mapping that may hold executable
/// code the process also writes to, subject to the per-thread write protection
/// toggled by [`pthread_jit_write_protect_np`].
pub(crate) const MAP_JIT: libc::c_int = 0x0800;

pub(crate) const KERN_SUCCESS: libc::c_int = 0;
pub(crate) const KERN_NO_SPACE: libc::c_int = 3;

/// `VM_FLAGS_FIXED`: allocate exactly at the requested address, failing with
/// `KERN_NO_SPACE` rather than relocating.
pub(crate) const VM_FLAGS_FIXED: libc::c_int = 0x0000;

/// `VM_REGION_BASIC_INFO_64` flavor selector for `mach_vm_region`.
const VM_REGION_BASIC_INFO_64: libc::c_int = 9;

type MachPort = u32;
type KernReturn = libc::c_int;

unsafe extern "C" {
    /// The Mach port naming this task. libSystem exports it as a global; the
    /// familiar `mach_task_self()` is a macro over exactly this symbol.
    static mach_task_self_: MachPort;

    /// # Safety
    ///
    /// `address` must point at a writable `u64` holding the requested address.
    pub(crate) fn mach_vm_allocate(
        target: MachPort,
        address: *mut u64,
        size: u64,
        flags: libc::c_int,
    ) -> KernReturn;

    fn mach_vm_region(
        target: MachPort,
        address: *mut u64,
        size: *mut u64,
        flavor: libc::c_int,
        info: *mut libc::c_int,
        info_count: *mut u32,
        object_name: *mut MachPort,
    ) -> KernReturn;

    fn mach_port_deallocate(task: MachPort, name: MachPort) -> KernReturn;

    /// Toggles this thread's access to `MAP_JIT` mappings between writable and
    /// executable. Available since macOS 11, which predates every Apple Silicon
    /// machine.
    pub(crate) fn pthread_jit_write_protect_np(enabled: libc::c_int);

    fn __ulock_wait2(
        operation: u32,
        addr: *mut libc::c_void,
        value: u64,
        timeout_ns: u64,
        value2: u64,
    ) -> libc::c_int;

    fn __ulock_wake(operation: u32, addr: *mut libc::c_void, wake_value: u64) -> libc::c_int;
}

/// The Mach port naming this task.
pub(crate) fn mach_task_self() -> MachPort {
    // SAFETY: reading an immutable global libSystem publishes for this purpose.
    unsafe { mach_task_self_ }
}

/// Walk every mapped region of this process, yielding its address range.
///
/// This is the Mach counterpart of Windows' `VirtualQuery` loop: it reports what
/// the host already occupies so those addresses are never offered to a guest.
pub(crate) fn mach_vm_region_iter() -> impl Iterator<Item = core::ops::Range<usize>> {
    let mut address: u64 = 0;
    core::iter::from_fn(move || {
        loop {
            let mut size: u64 = 0;
            // `vm_region_basic_info_data_64_t` is a plain struct of `int`-sized
            // fields plus one 64-bit offset; the count is in units of `int`.
            let mut info = [0i32; 16];
            let mut info_count = u32::try_from(info.len()).expect("fixed small length");
            let mut object_name: MachPort = 0;
            // SAFETY: every out-parameter points at a live local of the right
            // type, and `info_count` bounds the writes into `info`.
            let kr = unsafe {
                mach_vm_region(
                    mach_task_self(),
                    &raw mut address,
                    &raw mut size,
                    VM_REGION_BASIC_INFO_64,
                    info.as_mut_ptr(),
                    &raw mut info_count,
                    &raw mut object_name,
                )
            };
            if kr != KERN_SUCCESS {
                return None;
            }
            if object_name != 0 {
                // `mach_vm_region` hands back a send right that would otherwise
                // leak a port for every region walked.
                //
                // SAFETY: the port was just produced by the call above.
                unsafe { mach_port_deallocate(mach_task_self(), object_name) };
            }
            let start = usize::try_from(address).ok()?;
            let len = usize::try_from(size).ok()?;
            // Advance past this region before yielding, so the next call
            // resumes after it.
            address = address.checked_add(size)?;
            if len == 0 {
                // A zero-length region would not advance the walk; skip it
                // rather than spin.
                continue;
            }
            return Some(start..start + len);
        }
    })
}

// `ulock` operation codes and flags, from xnu's `sys/ulock.h`.
const UL_COMPARE_AND_WAIT_SHARED: u32 = 3;
const ULF_WAKE_ALL: u32 = 0x0000_0100;
/// Return `-errno` directly instead of setting `errno`, which keeps these calls
/// free of thread-local access on the wait path.
const ULF_NO_ERRNO: u32 = 0x0100_0000;

/// Outcome of a [`ulock_wait`].
pub(crate) enum UlockWaitResult {
    /// The thread slept and was woken (possibly spuriously).
    Woken,
    /// The deadline passed without a wake.
    TimedOut,
    /// The value had already changed, so the thread never slept.
    ValueChanged,
}

/// Sleep while `*atomic == value`, in the manner of `FUTEX_WAIT`.
///
/// A `None` timeout waits indefinitely.
pub(crate) fn ulock_wait(
    atomic: &AtomicU32,
    value: u32,
    timeout: Option<Duration>,
) -> UlockWaitResult {
    // `__ulock_wait2` takes nanoseconds, with zero meaning "no deadline". A
    // non-zero requested duration must therefore never round down to zero, or
    // a timed wait would silently become an infinite one.
    let timeout_ns = match timeout {
        None => 0,
        Some(duration) => u64::try_from(duration.as_nanos())
            .unwrap_or(u64::MAX)
            .max(1),
    };
    let addr = core::ptr::from_ref(atomic)
        .cast_mut()
        .cast::<libc::c_void>();
    // SAFETY: `addr` points at a live `AtomicU32`, which is what the
    // compare-and-wait operation reads.
    let rc = unsafe {
        __ulock_wait2(
            UL_COMPARE_AND_WAIT_SHARED | ULF_NO_ERRNO,
            addr,
            u64::from(value),
            timeout_ns,
            0,
        )
    };
    if rc >= 0 {
        // The return value counts the waiters still parked; any of them is a
        // successful sleep-and-wake for this thread.
        return UlockWaitResult::Woken;
    }
    match -rc {
        // A signal cut the wait short. The caller must tolerate spurious
        // wakeups anyway, so this is indistinguishable from a real one.
        libc::EINTR => UlockWaitResult::Woken,
        libc::ETIMEDOUT => UlockWaitResult::TimedOut,
        // `EAGAIN` means the compare failed, and any other error means the
        // thread did not sleep either. Both are reported to the caller as "the
        // value moved", which is the only non-sleeping outcome the trait models.
        _ => UlockWaitResult::ValueChanged,
    }
}

/// Wake one or all threads parked on `atomic`, in the manner of `FUTEX_WAKE`.
pub(crate) fn ulock_wake(atomic: &AtomicU32, all: bool) {
    let mut operation = UL_COMPARE_AND_WAIT_SHARED | ULF_NO_ERRNO;
    if all {
        operation |= ULF_WAKE_ALL;
    }
    let addr = core::ptr::from_ref(atomic)
        .cast_mut()
        .cast::<libc::c_void>();
    // SAFETY: `addr` points at a live `AtomicU32`.
    //
    // A failure here is `-ENOENT` ("nobody was waiting"), which is not an error
    // for the caller: the trait already allows a wake to report nothing woken.
    unsafe { __ulock_wake(operation, addr, 0) };
}

/// Read a clock as whole nanoseconds.
pub(crate) fn clock_gettime_nanos(clock: libc::clockid_t) -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `ts` is a live, correctly typed out-parameter.
    let rc = unsafe { libc::clock_gettime(clock, &raw mut ts) };
    assert_eq!(rc, 0, "clock_gettime failed for clock {clock}");
    let secs = u64::try_from(ts.tv_sec).unwrap_or(0);
    let nsecs = u64::try_from(ts.tv_nsec).unwrap_or(0);
    secs.saturating_mul(1_000_000_000).saturating_add(nsecs)
}

/// Read a string-valued `sysctl` by name.
pub(crate) fn sysctl_string(
    name: &core::ffi::CStr,
) -> Result<alloc::string::String, std::io::Error> {
    let mut len: usize = 0;
    // SAFETY: passing a null buffer asks only for the required length.
    let rc = unsafe {
        libc::sysctlbyname(
            name.as_ptr(),
            core::ptr::null_mut(),
            &raw mut len,
            core::ptr::null_mut(),
            0,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut buf = alloc::vec![0u8; len];
    // SAFETY: `buf` has exactly the length the call above asked for.
    let rc = unsafe {
        libc::sysctlbyname(
            name.as_ptr(),
            buf.as_mut_ptr().cast::<libc::c_void>(),
            &raw mut len,
            core::ptr::null_mut(),
            0,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // The value is NUL-terminated and `len` counts the terminator.
    buf.truncate(len.saturating_sub(1));
    alloc::string::String::from_utf8(buf)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "sysctl value not UTF-8"))
}

/// Install `handler` for `signum`.
///
/// `siginfo` selects the three-argument handler form, which is what a fault
/// handler needs in order to reach the interrupted machine context.
///
/// # Panics
///
/// Panics if the handler cannot be installed, which would leave LiteBox unable
/// to recover from a faulting guest-memory access.
pub(crate) fn install_handler(signum: libc::c_int, handler: usize, siginfo: bool) {
    // SAFETY: `sigaction` is a plain-old-data struct; zero is a valid initial
    // value for every field, and the fields that matter are set below.
    let mut action: libc::sigaction = unsafe { core::mem::zeroed() };
    action.sa_sigaction = handler;
    action.sa_flags = if siginfo { libc::SA_SIGINFO } else { 0 };
    // SAFETY: `sa_mask` is a live, correctly typed out-parameter, and installing
    // a handler for a signal number the caller chose has no other precondition.
    let rc = unsafe {
        libc::sigemptyset(&raw mut action.sa_mask);
        libc::sigaction(signum, &raw const action, core::ptr::null_mut())
    };
    assert_eq!(rc, 0, "failed to install a handler for signal {signum}");
}

/// Restore the default disposition of `signum` so that returning from a
/// synchronous fault handler lets the fault kill the process, exactly as it
/// would have without a handler installed.
pub(crate) fn reraise_fatally(signum: libc::c_int) {
    // SAFETY: as in `install_handler`.
    unsafe {
        let mut action: libc::sigaction = core::mem::zeroed();
        action.sa_sigaction = libc::SIG_DFL;
        libc::sigemptyset(&raw mut action.sa_mask);
        libc::sigaction(signum, &raw const action, core::ptr::null_mut());
    }
}

/// The leading fields of Darwin's `_STRUCT_MCONTEXT64` for arm64.
///
/// Only the exception and thread states are declared; the NEON state that
/// follows them is never touched, and a pointer to a prefix of the real struct
/// is all the fault handler needs.
#[repr(C)]
pub(crate) struct McontextPrefix64 {
    pub(crate) exception_state: ArmExceptionState64,
    pub(crate) thread_state: ArmThreadState64,
}

/// Darwin's `_STRUCT_ARM_EXCEPTION_STATE64`.
#[repr(C)]
pub(crate) struct ArmExceptionState64 {
    /// Faulting virtual address (`FAR_EL1`).
    pub(crate) far: u64,
    /// Exception syndrome (`ESR_EL1`).
    pub(crate) esr: u32,
    /// The Mach exception number the fault was reported as.
    pub(crate) exception: u32,
}

/// Darwin's `_STRUCT_ARM_THREAD_STATE64`.
#[repr(C)]
pub(crate) struct ArmThreadState64 {
    /// General-purpose registers `x0`-`x28`.
    pub(crate) x: [u64; 29],
    /// Frame pointer, `x29`.
    pub(crate) fp: u64,
    /// Link register, `x30`.
    pub(crate) lr: u64,
    pub(crate) sp: u64,
    pub(crate) pc: u64,
    pub(crate) cpsr: u32,
    pub(crate) pad: u32,
}
