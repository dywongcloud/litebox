// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! `cf-02-seccomp-production-attester`'s execve target. `attester_guest.rs`'s
//! `probe_exec_preserves_seccomp` execve's this binary in a forked child while a filter denying
//! `nanosleep` (and `no_new_privs`) is already installed; if `litebox_shim_linux::sys_execve`
//! correctly leaves the calling thread's `ThreadRemote::security` slot untouched (it never
//! touches `security` at all -- confirmed by reading its current body before writing this), both
//! survive the image replacement exactly as real Linux requires. `no_std`/`no_main`/crt-free
//! static-PIE per `litebox-guest-test-binary-recipe`; the exit code alone is this process's whole
//! report, read back by the parent's own `wait4`.
//!
//! Exit codes: 0 = nanosleep denied AND NNP still set (both inherited correctly); 1 = nanosleep
//! was allowed (seccomp lost); 2 = NNP was cleared; 3 = both lost; 210 = execve itself failed
//! (written by the caller, never by this binary).

#![no_std]
#![no_main]

const NR_NANOSLEEP: i64 = 101;
const NR_PRCTL: i64 = 167;
const NR_EXIT_GROUP: i64 = 94;
const PR_GET_NO_NEW_PRIVS: i64 = 39;

#[inline(always)]
unsafe fn syscall6(nr: i64, a0: i64, a1: i64, a2: i64, a3: i64, a4: i64, a5: i64) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") nr,
            inlateout("x0") a0 => ret,
            in("x1") a1,
            in("x2") a2,
            in("x3") a3,
            in("x4") a4,
            in("x5") a5,
            options(nostack)
        );
    }
    ret
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    let ts = [0i64, 0i64];
    let nanosleep_ret = unsafe { syscall6(NR_NANOSLEEP, ts.as_ptr() as i64, 0, 0, 0, 0, 0) };
    let nnp = unsafe { syscall6(NR_PRCTL, PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0, 0) };
    let nanosleep_denied = nanosleep_ret == -1;
    let nnp_set = nnp == 1;
    let code: i64 = match (nanosleep_denied, nnp_set) {
        (true, true) => 0,
        (false, true) => 1,
        (true, false) => 2,
        (false, false) => 3,
    };
    unsafe {
        syscall6(NR_EXIT_GROUP, code, 0, 0, 0, 0, 0);
    }
    loop {
        unsafe { core::arch::asm!("yield", options(nomem, nostack)) };
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    unsafe {
        syscall6(NR_EXIT_GROUP, 220, 0, 0, 0, 0, 0);
    }
    loop {
        unsafe { core::arch::asm!("yield", options(nomem, nostack)) };
    }
}
