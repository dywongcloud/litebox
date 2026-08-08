// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Guest entry for Darwin on aarch64.
//!
//! This is the transfer of control *into* guest code and back out of it -- the
//! counterpart of the other platforms' `run_thread_arch`. Everything else of
//! the macOS platform (memory, locking, time, signals, threads, TLS,
//! randomness, stdio, networking) was already complete; this module closes the
//! last seam so a guest thread can actually execute.
//!
//! # The context-switch mechanism
//!
//! AArch64 has no userland instruction that atomically restores every general
//! register *and* the program counter (that is `ERET`, EL1+ only). Every
//! indirect branch (`BR`/`RET`) reads a general register, so entering the guest
//! must sacrifice exactly one register as the branch vehicle. The
//! [`litebox_syscall_rewriter`] `SVC` gate already treats **`X16`** as a
//! scratch register (it spills and reuses it), and the Linux syscall ABI does
//! not keep a live value in `X16`/`X17` across an `SVC` in practice, so `X16`
//! is the safe vehicle: [`enter_guest_asm`] restores all of `X0`-`X30`, `SP`
//! and the `NZCV` flags from a [`PtRegs`], then branches through `X16` to the
//! guest `PC`.
//!
//! Coming back is the reverse. A rewritten guest `SVC` branches (via its gate
//! and the shared handler) to [`syscall_callback`], which captures the full
//! guest register file into the run loop's `PtRegs`, restores the host's
//! callee-saved registers and stack, and returns *normally* into the run loop
//! -- a hand-rolled `swapcontext`. The run loop ([`run_thread`]) then calls the
//! shim and, on [`ContinueOperation::Resume`], re-enters with the updated
//! `PtRegs`. This avoids `setjmp`/`longjmp` (unsound across Rust frames) and
//! the deprecated `ucontext` API (whose `setcontext` resumes via `__lr`, which
//! would clobber the guest's live `X30` -- worse than clobbering `X16`).
//!
//! # Current limitations
//!
//! * **One guest thread at a time.** The host save area and the live-`PtRegs`
//!   pointer are process-global, reached from [`syscall_callback`] by absolute
//!   (`ADRP`) address because a naked callback on the guest stack cannot read a
//!   Rust `thread_local!` without a call. A second concurrent guest thread
//!   panics loudly ([`GUEST_ACTIVE`]) rather than corrupting the first. Lifting
//!   this needs a per-thread save area reached without a function call -- the
//!   same `TPIDRRO_EL0`-relative direct-TSD mechanism the rewriter's gates need
//!   (see `docs/roadmap.md`); it is deliberately out of scope here.
//! * **Only the syscall path is wired.** Guest hardware faults still reach the
//!   existing `SIGSEGV`/`SIGBUS` fault handler (host-access recovery), and the
//!   interrupt path (`SIGUSR2`) is not yet routed to [`litebox::shim::EnterShim::interrupt`].
//!   A guest that only issues syscalls (the common case) runs end to end.
//! * **Below-`SP` staging.** [`enter_guest_asm`] stages the guest `PC` and `X0`
//!   in the 16 bytes just below the guest `SP` before branching. AArch64 Linux
//!   has no red zone, so a signal delivered in that window could clobber them;
//!   the platform must therefore keep guest-directed signals on a
//!   `sigaltstack` (its async handlers already run there). Documented so it is
//!   not mistaken for safe on a shared stack.
//!
//! Darwin's W^X rules still apply: the guest's executable pages are `MAP_JIT`
//! mappings and every patch is bracketed by
//! [`litebox::platform::PageManagementProvider::jit_write_protect`] (the shim's
//! code-writing paths already do this), with the host binary signed for the
//! `com.apple.security.cs.allow-jit` entitlement.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, Ordering};

use litebox::shim::ContinueOperation;
use litebox_common_linux::PtRegs;

// The naked assembly below hard-codes byte offsets into `PtRegs` and its total
// size. These assertions tie those literals to the struct definition so a
// layout change fails the build instead of silently miscompiling the switch.
const _: () = assert!(core::mem::offset_of!(PtRegs, regs) == 0);
const _: () = assert!(core::mem::offset_of!(PtRegs, sp) == 248);
const _: () = assert!(core::mem::offset_of!(PtRegs, pc) == 256);
const _: () = assert!(core::mem::offset_of!(PtRegs, pstate) == 264);
const _: () = assert!(core::mem::size_of::<PtRegs>() == 288);

/// A `Sync` cell for state that only the single active guest thread touches,
/// mutated from naked assembly by absolute address.
#[repr(transparent)]
struct RawCell<T>(UnsafeCell<T>);
// SAFETY: access is serialized by the single-guest-thread invariant enforced by
// `GUEST_ACTIVE`; there is no concurrent reader/writer.
unsafe impl<T> Sync for RawCell<T> {}

/// Host callee-saved registers, `LR` and `SP`, saved by [`enter_guest_asm`] and
/// restored by [`syscall_callback`]. Layout (u64 indices): `x19..x28` at 0..72,
/// `x29` at 80, `lr` at 88, `sp` at 96.
static HOST_SAVE: RawCell<[u64; 13]> = RawCell(UnsafeCell::new([0; 13]));

/// Pointer to the run loop's live [`PtRegs`], stashed by [`enter_guest_asm`] so
/// [`syscall_callback`] can write the captured guest state back into it.
static LIVE_PTREGS: RawCell<*mut PtRegs> = RawCell(UnsafeCell::new(core::ptr::null_mut()));

/// Guards the single-guest-thread invariant the process-global save area relies
/// on: a second concurrent [`run_thread`] is a hard error, not silent
/// corruption.
static GUEST_ACTIVE: AtomicBool = AtomicBool::new(false);

/// Enter (or resume) the guest with the register state in `ctx`.
///
/// Saves the host's callee-saved registers, `LR` and `SP` into [`HOST_SAVE`],
/// records `ctx` in [`LIVE_PTREGS`], restores every guest register from `ctx`,
/// and branches to `ctx.pc` through `X16`. It "returns" -- with callee-saved
/// registers preserved, ABI-correctly -- only when [`syscall_callback`]
/// restores the host context after a guest syscall, at which point `*ctx` holds
/// the guest state at the syscall.
///
/// # Safety
///
/// `ctx` must point to a valid, writable [`PtRegs`] describing a runnable guest
/// context whose `sp` addresses a valid guest stack with 16 usable bytes below
/// it. Only one guest thread may be active (see [`GUEST_ACTIVE`]).
#[unsafe(naked)]
unsafe extern "C" fn enter_guest_asm(ctx: *mut PtRegs) {
    core::arch::naked_asm!(
        // Save host callee-saved registers, LR and SP.
        "adrp x1, {host_save}@PAGE",
        "add  x1, x1, {host_save}@PAGEOFF",
        "stp  x19, x20, [x1, #0]",
        "stp  x21, x22, [x1, #16]",
        "stp  x23, x24, [x1, #32]",
        "stp  x25, x26, [x1, #48]",
        "stp  x27, x28, [x1, #64]",
        "str  x29, [x1, #80]",
        "str  x30, [x1, #88]",
        "mov  x2, sp",
        "str  x2, [x1, #96]",
        // Record the live PtRegs pointer for the callback.
        "adrp x2, {live}@PAGE",
        "add  x2, x2, {live}@PAGEOFF",
        "str  x0, [x2]",
        // Stage guest PC and X0 in the 16 bytes below the guest SP.
        "ldr  x1, [x0, #248]",       // guest sp
        "ldr  x16, [x0, #256]",      // guest pc
        "str  x16, [x1, #-8]",
        "ldr  x16, [x0, #0]",        // guest x0
        "str  x16, [x1, #-16]",
        "ldr  x16, [x0, #264]",      // pstate -> NZCV
        "msr  nzcv, x16",
        "mov  sp, x1",
        // Restore x1..x30 (x0 and x16 handled last; skip regs[16]).
        "ldr  x1,  [x0, #8]",
        "ldp  x2,  x3,  [x0, #16]",
        "ldp  x4,  x5,  [x0, #32]",
        "ldp  x6,  x7,  [x0, #48]",
        "ldp  x8,  x9,  [x0, #64]",
        "ldp  x10, x11, [x0, #80]",
        "ldp  x12, x13, [x0, #96]",
        "ldp  x14, x15, [x0, #112]",
        "ldr  x17, [x0, #136]",
        "ldp  x18, x19, [x0, #144]",
        "ldp  x20, x21, [x0, #160]",
        "ldp  x22, x23, [x0, #176]",
        "ldp  x24, x25, [x0, #192]",
        "ldp  x26, x27, [x0, #208]",
        "ldp  x28, x29, [x0, #224]",
        "ldr  x30, [x0, #240]",
        // Restore x0 and branch to the guest PC through the X16 vehicle.
        "ldr  x0,  [sp, #-16]",
        "ldr  x16, [sp, #-8]",
        "br   x16",
        host_save = sym HOST_SAVE,
        live = sym LIVE_PTREGS,
    )
}

/// The entry point a rewritten guest's `SVC` gate branches to.
///
/// [`litebox::platform::SystemInfoProvider::get_syscall_entry_point`] hands this
/// address to the loader, which writes it into the trampoline the rewriter
/// appended to the guest image. On entry the [`litebox_syscall_rewriter`] `SVC`
/// gate has: saved the guest `X16` at `[SP]` and the post-`SVC` return address
/// at `[SP, #8]`, decremented `SP` by 16, and left every other guest register
/// (and `NZCV`) intact. This captures that state into the live [`PtRegs`],
/// restores the host context from [`HOST_SAVE`], and returns into the run loop.
///
/// # Safety
///
/// Reached only from a guest `SVC` gate with the register/stack state described
/// above; not callable as an ordinary function.
#[unsafe(naked)]
pub(crate) unsafe extern "C" fn syscall_callback() {
    core::arch::naked_asm!(
        // Capture the guest register file into a PtRegs on the guest stack.
        "sub  sp, sp, #288",
        "stp  x0,  x1,  [sp, #0]",
        "stp  x2,  x3,  [sp, #16]",
        "stp  x4,  x5,  [sp, #32]",
        "stp  x6,  x7,  [sp, #48]",
        "stp  x8,  x9,  [sp, #64]",
        "stp  x10, x11, [sp, #80]",
        "stp  x12, x13, [sp, #96]",
        "stp  x14, x15, [sp, #112]",
        "ldr  x9, [sp, #288]",       // guest x16, saved by the gate at [old_sp]
        "str  x9, [sp, #128]",
        "str  x17, [sp, #136]",
        "stp  x18, x19, [sp, #144]",
        "stp  x20, x21, [sp, #160]",
        "stp  x22, x23, [sp, #176]",
        "stp  x24, x25, [sp, #192]",
        "stp  x26, x27, [sp, #208]",
        "stp  x28, x29, [sp, #224]",
        "str  x30, [sp, #240]",
        "ldr  x9, [sp, #296]",       // post-SVC return address = guest pc
        "str  x9, [sp, #256]",
        "add  x9, sp, #304",         // old_sp + 16 = guest sp
        "str  x9, [sp, #248]",
        "mrs  x9, nzcv",
        "str  x9, [sp, #264]",       // pstate
        // Copy the captured PtRegs into the run loop's live buffer.
        "adrp x9, {live}@PAGE",
        "add  x9, x9, {live}@PAGEOFF",
        "ldr  x9, [x9]",             // dst = *LIVE_PTREGS
        "mov  x10, sp",              // src
        "mov  x11, #288",
        "2:",
        "ldr  x12, [x10], #8",
        "str  x12, [x9], #8",
        "subs x11, x11, #8",
        "b.ne 2b",
        // Restore host callee-saved registers, LR and SP, then return into the
        // run loop (as though enter_guest_asm had returned).
        "adrp x1, {host_save}@PAGE",
        "add  x1, x1, {host_save}@PAGEOFF",
        "ldp  x19, x20, [x1, #0]",
        "ldp  x21, x22, [x1, #16]",
        "ldp  x23, x24, [x1, #32]",
        "ldp  x25, x26, [x1, #48]",
        "ldp  x27, x28, [x1, #64]",
        "ldr  x29, [x1, #80]",
        "ldr  x30, [x1, #88]",
        "ldr  x2, [x1, #96]",
        "mov  sp, x2",
        "ret",
        live = sym LIVE_PTREGS,
        host_save = sym HOST_SAVE,
    )
}

/// Runs a guest thread with the given shim and initial context.
///
/// Calls [`litebox::shim::EnterShim::init`], then loops: enter the guest, and on
/// each syscall dispatch to [`litebox::shim::EnterShim::syscall`], resuming
/// until a handler returns [`ContinueOperation::Terminate`].
pub(crate) fn run_thread(
    shim: &dyn litebox::shim::EnterShim<ExecutionContext = PtRegs>,
    ctx: &mut PtRegs,
) {
    // The host save area and live-PtRegs pointer are process-global, so exactly
    // one guest thread may run at a time. Make a second one a loud failure.
    assert!(
        !GUEST_ACTIVE.swap(true, Ordering::Acquire),
        "a second concurrent guest thread reached macOS guest entry; only one \
         is supported today (see litebox_platform_macos_userland::guest)"
    );
    let _reset = litebox::utils::defer(|| GUEST_ACTIVE.store(false, Ordering::Release));

    if shim.init(ctx) == ContinueOperation::Terminate {
        return;
    }

    loop {
        // Enter/resume the guest. Returns after a guest syscall with `*ctx`
        // holding the guest state captured by `syscall_callback`.
        //
        // SAFETY: `ctx` is a valid writable PtRegs; `GUEST_ACTIVE` guarantees
        // this is the only active guest thread, so the global save area is not
        // raced.
        unsafe { enter_guest_asm(core::ptr::from_mut(ctx)) };

        if shim.syscall(ctx) == ContinueOperation::Terminate {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::RefCell;
    use litebox::shim::{EnterShim, ExceptionInfo};

    /// A stub shim that records the syscalls a guest makes. `write` (nr 64)
    /// returns its length and resumes; `exit` (nr 93) terminates.
    struct RecordingShim {
        seen: RefCell<Vec<(usize, usize, usize)>>, // (nr, x0, x1)
    }

    impl EnterShim for RecordingShim {
        type ExecutionContext = PtRegs;
        fn init(&self, _ctx: &mut PtRegs) -> ContinueOperation {
            ContinueOperation::Resume
        }
        fn syscall(&self, ctx: &mut PtRegs) -> ContinueOperation {
            let nr = ctx.regs[8];
            self.seen.borrow_mut().push((nr, ctx.regs[0], ctx.regs[1]));
            if nr == 93 {
                return ContinueOperation::Terminate;
            }
            // Emulate write(): return the byte count in x0, then resume.
            ctx.regs[0] = ctx.regs[2];
            ContinueOperation::Resume
        }
        fn exception(&self, _ctx: &mut PtRegs, _info: &ExceptionInfo) -> ContinueOperation {
            ContinueOperation::Terminate
        }
        fn interrupt(&self, _ctx: &mut PtRegs) -> ContinueOperation {
            ContinueOperation::Terminate
        }
    }

    /// A hand-assembled guest reproducing exactly what the rewriter emits: two
    /// syscalls whose `SVC`s have been replaced by the `SVC`-gate sequence
    /// (`emit_svc_gate` + shared handler) branching to [`syscall_callback`].
    /// `write(1, 0xABC, 7)` then `exit(42)`.
    #[unsafe(naked)]
    unsafe extern "C" fn test_guest() {
        core::arch::naked_asm!(
            // write(1, 0xABC, 7)
            "movz x8, #64",
            "movz x0, #1",
            "movz x1, #0xABC",
            "movz x2, #7",
            // SVC gate: save x16, record return address, jump to the callback.
            "sub  sp, sp, #16",
            "str  x16, [sp]",
            "adrp x16, 20f@PAGE",
            "add  x16, x16, 20f@PAGEOFF",
            "str  x16, [sp, #8]",
            "adrp x16, {cb}@PAGE",
            "add  x16, x16, {cb}@PAGEOFF",
            "br   x16",
            "20:", // resume point after the write syscall
            // exit(42)
            "movz x8, #93",
            "movz x0, #42",
            "sub  sp, sp, #16",
            "str  x16, [sp]",
            "adrp x16, 21f@PAGE",
            "add  x16, x16, 21f@PAGEOFF",
            "str  x16, [sp, #8]",
            "adrp x16, {cb}@PAGE",
            "add  x16, x16, {cb}@PAGEOFF",
            "br   x16",
            "21:",
            "brk  #0",
            cb = sym syscall_callback,
        )
    }

    #[test]
    fn runs_a_guest_through_two_syscalls_and_exit() {
        let mut stack = vec![0u8; 1 << 16];
        let top = stack.as_mut_ptr() as usize + stack.len();
        let sp = (top - 256) & !15;

        let mut ctx = PtRegs {
            pc: test_guest as *const () as usize,
            sp,
            ..Default::default()
        };

        let shim = RecordingShim {
            seen: RefCell::new(Vec::new()),
        };
        run_thread(&shim, &mut ctx);

        let seen = shim.seen.into_inner();
        assert_eq!(
            seen,
            vec![(64, 1, 0xABC), (93, 42, 0xABC)],
            "guest should have made write(1,0xABC,..) then exit(42)"
        );
    }
}
