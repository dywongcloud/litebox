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
//! The vector registers travel separately, in [`GUEST_FP`], because [`PtRegs`]
//! has nowhere to put them: it mirrors Linux's `struct pt_regs`, which carries
//! no FP state because the kernel is built without it. Leaving them in the
//! hardware would not work either -- the shim is ordinary Rust and uses vector
//! registers freely -- and Linux preserves user FPSIMD across a syscall, so a
//! guest may hold live values in any of them across its `SVC`.
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
//!   (see `docs/roadmap.md`); it is deliberately out of scope here. This
//!   includes [`GUEST_OWNS_CPU`]: lifting the single-thread restriction would
//!   need this to become per-thread state too, reached the same
//!   `TPIDRRO_EL0`-relative way.
//! * **Guest hardware faults (`SIGSEGV`/`SIGBUS`) are routed** to
//!   [`litebox::shim::EnterShim::exception`] via [`GUEST_OWNS_CPU`] and
//!   `lib.rs`'s `fault_handler`; the interrupt path (`SIGUSR2`) is not yet
//!   routed to [`litebox::shim::EnterShim::interrupt`] -- a separate problem
//!   (see `docs/roadmap.md`). A delivered exception's captured general
//!   registers/`PSTATE` are exact (read straight from the kernel's own signal
//!   `mcontext`, not re-derived); its vector/FPSIMD state is *not* refreshed
//!   from the fault -- [`GUEST_FP`] still holds whatever it captured at the
//!   guest's last syscall, since Darwin's `mcontext` NEON state is not yet
//!   modelled (see [`darwin::McontextPrefix64`]'s own doc comment) -- so a
//!   guest that resumes from a delivered signal after touching a vector
//!   register since its last syscall observes stale FP/SIMD content. This
//!   mirrors the interrupt path's identical, already-documented gap.
//! * **Below-`SP` staging.** [`enter_guest_asm`] stages the guest `PC` and `X0`
//!   in the 16 bytes just below the guest `SP` before branching. AArch64 Linux
//!   has no red zone, so a signal delivered in that window could clobber them;
//!   the platform therefore keeps guest-directed signals on a `sigaltstack`,
//!   not merely as a documented assumption -- every handler this platform
//!   installs carries `SA_ONSTACK` (`darwin::install_handler`), and both
//!   entry points that can reach here (`ThreadProvider::spawn_thread` and the
//!   free `run_thread`) install the alternate stack itself
//!   (`with_signal_alt_stack`) before either can run. The same below-`SP`
//!   reads are also the last guest-memory touches inside [`GUEST_OWNS_CPU`]'s
//!   "owns" window before the branch to guest code; a fault there is caught by
//!   an exception-table entry (see [`GUEST_OWNS_CPU`]) rather than ever being
//!   weighed as a guest-delivery candidate.
//!
//! Darwin's W^X rules still apply: the guest's executable pages are `MAP_JIT`
//! mappings and every patch is bracketed by
//! [`litebox::platform::PageManagementProvider::jit_write_protect`] (the shim's
//! code-writing paths already do this), with the host binary signed for the
//! `com.apple.security.cs.allow-jit` entitlement.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, Ordering};

use litebox::shim::ContinueOperation;
use litebox::utils::TruncateExt as _;
use litebox_common_linux::PtRegs;

// The naked assembly below hard-codes byte offsets into `PtRegs` and its total
// size. These assertions tie those literals to the struct definition so a
// layout change fails the build instead of silently miscompiling the switch.
const _: () = assert!(core::mem::offset_of!(PtRegs, regs) == 0);
const _: () = assert!(core::mem::offset_of!(PtRegs, sp) == 248);
const _: () = assert!(core::mem::offset_of!(PtRegs, pc) == 256);
const _: () = assert!(core::mem::offset_of!(PtRegs, pstate) == 264);
const _: () = assert!(core::mem::offset_of!(PtRegs, orig_x0) == 272);
const _: () = assert!(core::mem::offset_of!(PtRegs, syscallno) == 280);
const _: () = assert!(core::mem::size_of::<PtRegs>() == 288);

/// A `Sync` cell for state that only the single active guest thread touches,
/// mutated from naked assembly by absolute address.
#[repr(transparent)]
struct RawCell<T>(UnsafeCell<T>);
// SAFETY: access is serialized by the single-guest-thread invariant enforced by
// `GUEST_ACTIVE`; there is no concurrent reader/writer.
unsafe impl<T> Sync for RawCell<T> {}

/// Host callee-saved state, saved by [`enter_guest_asm`] and restored by
/// [`syscall_callback`]. Byte layout: `x19..x28` at 0..72, `x29` at 80, `lr` at
/// 88, `sp` at 96, `d8..d15` at 104..160, `FPCR` at 168, `FPSR` at 176.
///
/// `d8`-`d15` are here because AAPCS makes their low 64 bits callee-saved, so
/// `run_thread`'s caller is entitled to find them intact; the guest is free to
/// write every vector register.
static HOST_SAVE: RawCell<[u64; HOST_SAVE_SLOTS]> = RawCell(UnsafeCell::new([0; HOST_SAVE_SLOTS]));

/// `u64` slots in [`HOST_SAVE`]; see its layout.
const HOST_SAVE_SLOTS: usize = 23;
/// Byte offsets the naked assembly hard-codes. `HOST_SAVE` is a flat array
/// rather than a struct, so there is no `offset_of!` to check these against;
/// the assertions below check instead that the regions are contiguous and that
/// the last one ends exactly at the end of the array, which is what would break
/// if a slot were added without resizing it.
const HOST_SAVE_OFF_D8: usize = 104;
const HOST_SAVE_OFF_FPCR: usize = 168;
const HOST_SAVE_OFF_FPSR: usize = 176;
/// `d8`-`d15`, eight 64-bit slots, run from `HOST_SAVE_OFF_D8` up to `FPCR`.
const _: () = assert!(HOST_SAVE_OFF_D8 + 8 * 8 == HOST_SAVE_OFF_FPCR);
const _: () = assert!(HOST_SAVE_OFF_FPCR + 8 == HOST_SAVE_OFF_FPSR);
const _: () = assert!(HOST_SAVE_OFF_FPSR + 8 == HOST_SAVE_SLOTS * 8);

/// The guest's floating-point and SIMD state, held across a syscall.
///
/// The guest's own registers cannot stay in the hardware while the host runs:
/// the shim is ordinary Rust and uses the vector registers freely, so anything
/// left live would be destroyed. [`PtRegs`] cannot carry this state -- it mirrors
/// Linux's `struct pt_regs`, which has no FP fields because the kernel is built
/// without them and manages user FPSIMD out of band -- so it lives beside it.
///
/// The whole file is preserved, not just the callee-saved half, because Linux
/// preserves user FPSIMD across a syscall: a guest is entitled to hold live
/// values in *any* vector register across its `SVC`, and glibc's and musl's
/// string and memory routines do exactly that.
#[repr(C, align(16))]
struct GuestFpState {
    /// `v0`-`v31`, full 128 bits each.
    v: [u128; 32],
    fpcr: u64,
    fpsr: u64,
}

/// The live guest's FP/SIMD state while the host runs. Restored by
/// [`enter_guest_asm`], captured by [`syscall_callback`]. Zero is the correct
/// initial value: a fresh guest thread starts with a cleared vector file and the
/// default rounding mode, which is what `FPCR == 0` means.
static GUEST_FP: RawCell<GuestFpState> = RawCell(UnsafeCell::new(GuestFpState {
    v: [0; 32],
    fpcr: 0,
    fpsr: 0,
}));

const GUEST_FP_OFF_FPCR: usize = 512;
const GUEST_FP_OFF_FPSR: usize = 520;
const _: () = assert!(core::mem::offset_of!(GuestFpState, v) == 0);
const _: () = assert!(core::mem::offset_of!(GuestFpState, fpcr) == GUEST_FP_OFF_FPCR);
const _: () = assert!(core::mem::offset_of!(GuestFpState, fpsr) == GUEST_FP_OFF_FPSR);

/// Pointer to the run loop's live [`PtRegs`], stashed by [`enter_guest_asm`] so
/// [`syscall_callback`] can write the captured guest state back into it.
static LIVE_PTREGS: RawCell<*mut PtRegs> = RawCell(UnsafeCell::new(core::ptr::null_mut()));

/// Whether the CPU is genuinely executing guest instructions right now, as
/// opposed to running this platform's own [`enter_guest_asm`]/
/// [`syscall_callback`] switch code with the guest's registers not yet (or no
/// longer) authoritative. `lib.rs`'s `fault_handler` consults this -- *after*
/// its existing exception-table check, which always takes priority -- to
/// decide whether a captured `mcontext` is safe to hand to the guest via
/// [`litebox::shim::EnterShim::exception`], or must instead be left alone as
/// an internal/unattributable fault (today's behavior: the process dies).
///
/// Set `true` by [`enter_guest_asm`] once every guest register but the branch
/// vehicle has been restored, and cleared `false` as the first instructions of
/// [`syscall_callback`] and by `fault_handler` itself when it delivers an
/// exception. Both entry points still touch a couple of guest-stack bytes
/// *inside* that window (the below-`SP` staging reads at the end of
/// `enter_guest_asm`, and the `SVC`-gate-stashed-word reads at the start of
/// `syscall_callback`) -- deliberately, because by the time every other guest
/// register is live there is no register left free to place this flag's own
/// store with any tighter precision. Both windows are covered instead by an
/// exception-table entry recovering to [`abort_on_boundary_stack_fault`],
/// which the exception-table check `fault_handler` runs first always finds
/// before this flag is ever consulted -- so a fault there can never be
/// misattributed to the guest, regardless of what this flag reads at the time.
///
/// A future per-thread port needs this to move to the same `TPIDRRO_EL0`-
/// relative direct-TSD storage [`GUEST_ACTIVE`]'s doc comment describes for
/// the rest of this file's process-global state; it is not a new obstacle
/// beyond what was already true here.
pub(crate) static GUEST_OWNS_CPU: AtomicBool = AtomicBool::new(false);

/// The [`litebox::shim::ExceptionInfo`] for the fault [`exception_callback`]
/// is about to report to the run loop, filled in by [`prepare_exception_delivery`]
/// before `lib.rs`'s `fault_handler` redirects there. Like
/// [`HOST_SAVE`]/[`LIVE_PTREGS`]/[`GUEST_FP`], this relies on the single-
/// guest-thread invariant [`GUEST_ACTIVE`] enforces: at most one exception is
/// ever in flight.
static PENDING_EXCEPTION_INFO: RawCell<litebox::shim::ExceptionInfo> =
    RawCell(UnsafeCell::new(litebox::shim::ExceptionInfo {
        exception: litebox::shim::Exception(0),
        fault_address: 0,
        esr: 0,
        kernel_mode: false,
    }));

/// Guards the single-guest-thread invariant the process-global save area relies
/// on: a second concurrent [`run_thread`] is a hard error, not silent
/// corruption.
static GUEST_ACTIVE: AtomicBool = AtomicBool::new(false);

/// Enter (or resume) the guest with the register state in `ctx`.
///
/// Saves the host's callee-saved registers, `LR` and `SP` into [`HOST_SAVE`],
/// records `ctx` in [`LIVE_PTREGS`], restores every guest register from `ctx`,
/// and branches to `ctx.pc` through `X16`. It "returns" -- with callee-saved
/// registers preserved, ABI-correctly -- only when [`syscall_callback`] or
/// [`exception_callback`] restores the host context after a guest syscall or a
/// genuine guest hardware fault, at which point `*ctx` holds the guest state
/// at that event and the return value says which kind it was: `0` for a
/// syscall, `1` for an exception (see [`GuestExit`]).
///
/// # Safety
///
/// `ctx` must point to a valid, writable [`PtRegs`] describing a runnable guest
/// context whose `sp` addresses a valid guest stack with 16 usable bytes below
/// it. Only one guest thread may be active (see [`GUEST_ACTIVE`]).
#[unsafe(naked)]
unsafe extern "C" fn enter_guest_asm(ctx: *mut PtRegs) -> u64 {
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
        // Save the host's callee-saved FP registers and its FP control/status.
        "stp  d8,  d9,  [x1, #104]",
        "stp  d10, d11, [x1, #120]",
        "stp  d12, d13, [x1, #136]",
        "stp  d14, d15, [x1, #152]",
        "mrs  x2, fpcr",
        "str  x2, [x1, #168]",
        "mrs  x2, fpsr",
        "str  x2, [x1, #176]",
        // Restore the guest's whole vector file and FP control/status. Done here,
        // while x1 is still scratch and before any guest GPR is live.
        "adrp x1, {guest_fp}@PAGE",
        "add  x1, x1, {guest_fp}@PAGEOFF",
        "ldp  q0,  q1,  [x1, #0]",
        "ldp  q2,  q3,  [x1, #32]",
        "ldp  q4,  q5,  [x1, #64]",
        "ldp  q6,  q7,  [x1, #96]",
        "ldp  q8,  q9,  [x1, #128]",
        "ldp  q10, q11, [x1, #160]",
        "ldp  q12, q13, [x1, #192]",
        "ldp  q14, q15, [x1, #224]",
        "ldp  q16, q17, [x1, #256]",
        "ldp  q18, q19, [x1, #288]",
        "ldp  q20, q21, [x1, #320]",
        "ldp  q22, q23, [x1, #352]",
        "ldp  q24, q25, [x1, #384]",
        "ldp  q26, q27, [x1, #416]",
        "ldp  q28, q29, [x1, #448]",
        "ldp  q30, q31, [x1, #480]",
        "ldr  x2, [x1, #512]",
        "msr  fpcr, x2",
        "ldr  x2, [x1, #520]",
        "msr  fpsr, x2",
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
        // Mark the guest as genuinely owning the CPU from here on (see
        // GUEST_OWNS_CPU's doc comment for why this is not placed immediately
        // before the branch instead: by the time every guest register but the
        // branch vehicle is restored, no register is left free to compute
        // this store's address with). x1 and x16 are the only registers still
        // free at this specific point (x1's job above is done; x16 has not
        // been loaded with a real guest value yet).
        "adrp x16, {owns}@PAGE",
        "add  x16, x16, {owns}@PAGEOFF",
        "mov  w1, #1",
        "strb w1, [x16]",
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
        // Restore x0 and branch to the guest PC through the X16 vehicle. These
        // two below-SP reads are the last guest-memory touches inside the
        // "owns" window opened above; a fault here is redirected to
        // {abort} instead of ever reaching the GUEST_OWNS_CPU check (see that
        // flag's doc comment) -- the exception table is always consulted
        // first.
        "90:",
        "ldr  x0,  [sp, #-16]",
        "ldr  x16, [sp, #-8]",
        "91:",
        ".pushsection __TEXT,__ex_table,regular,no_dead_strip",
        ".balign 4",
        ".long 90b - .",
        ".long 91b - .",
        ".long {abort} - .",
        ".popsection",
        "br   x16",
        host_save = sym HOST_SAVE,
        live = sym LIVE_PTREGS,
        guest_fp = sym GUEST_FP,
        owns = sym GUEST_OWNS_CPU,
        abort = sym abort_on_boundary_stack_fault,
    )
}

/// Which of [`syscall_callback`] or [`exception_callback`] restored the host
/// context, i.e. what [`enter_guest_asm`]'s return value means. `run_thread`'s
/// loop dispatches on this instead of always assuming a syscall.
enum GuestExit {
    Syscall,
    Exception,
}

impl GuestExit {
    /// Decodes [`enter_guest_asm`]'s return value. Both callbacks set exactly
    /// `0` or `1`, so anything else would mean the asm and this decoder have
    /// drifted apart -- a build-time bug, not a runtime condition to handle
    /// gracefully.
    fn from_asm_return(value: u64) -> Self {
        match value {
            0 => Self::Syscall,
            1 => Self::Exception,
            _ => unreachable!("enter_guest_asm returned an undefined GuestExit code {value}"),
        }
    }
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
        // Clear ownership before touching anything else -- see GUEST_OWNS_CPU's
        // doc comment. This is the very first memory write this function makes,
        // and it targets a fixed host address that never depends on the
        // (possibly-corrupt) guest sp read below.
        "adrp x16, {owns}@PAGE",
        "add  x16, x16, {owns}@PAGEOFF",
        "strb wzr, [x16]",
        // Load the destination PtRegs (host-owned, set by enter_guest_asm) and
        // capture every guest GPR straight into it through this dedicated base
        // register, x16, held for the whole capture. sp is deliberately never
        // used as the capture buffer -- it still holds the guest's own
        // (possibly-corrupt) value at this point -- so nothing below can fault
        // by dereferencing it, other than the two gate-stashed-word reads
        // further down.
        "adrp x16, {live}@PAGE",
        "add  x16, x16, {live}@PAGEOFF",
        "ldr  x16, [x16]",
        "stp  x0,  x1,  [x16, #0]",
        "stp  x2,  x3,  [x16, #16]",
        "stp  x4,  x5,  [x16, #32]",
        "stp  x6,  x7,  [x16, #48]",
        "stp  x8,  x9,  [x16, #64]",
        "stp  x10, x11, [x16, #80]",
        "stp  x12, x13, [x16, #96]",
        "stp  x14, x15, [x16, #112]",
        // The SVC gate stashed the guest's real x16 at [sp] and the post-SVC
        // return address at [sp, #8] before jumping here (having decremented
        // sp by 16 first) -- the only guest-memory reads in this function, and
        // the only reason a bad guest sp can still fault inside it. x9 and x11
        // are free to use as scratch: their real guest values are already
        // captured above. GUEST_OWNS_CPU is already false by this point (see
        // above), so if either fault, fault_handler's fallback (today's
        // behavior: the process dies) runs, never guest delivery.
        "80:",
        "ldr  x9,  [sp]",
        "ldr  x11, [sp, #8]",
        "81:",
        ".pushsection __TEXT,__ex_table,regular,no_dead_strip",
        ".balign 4",
        ".long 80b - .",
        ".long 81b - .",
        ".long {abort} - .",
        ".popsection",
        "str  x9,  [x16, #128]",
        "str  x17, [x16, #136]",
        "stp  x18, x19, [x16, #144]",
        "stp  x20, x21, [x16, #160]",
        "stp  x22, x23, [x16, #176]",
        "stp  x24, x25, [x16, #192]",
        "stp  x26, x27, [x16, #208]",
        "stp  x28, x29, [x16, #224]",
        "str  x30, [x16, #240]",
        "str  x11, [x16, #256]",     // pc = post-SVC return address = guest pc
        "add  x9, sp, #16",          // sp = guest's pre-gate sp
        "str  x9, [x16, #248]",
        "mrs  x9, nzcv",
        "str  x9, [x16, #264]",      // pstate
        // The shim reads the syscall number from `syscallno`, not from `regs[8]`
        // -- that is where a Linux kernel entry path records it, and the shim is
        // written against `pt_regs`. Likewise `orig_x0` keeps the first argument,
        // which the return value overwrites in `regs[0]`. Neither is a copy of a
        // register the guest can see, so both have to be filled here or the
        // dispatcher reads whatever the buffer happened to hold. x0 and x8 are
        // still exactly their original guest values: nothing above wrote them.
        "str  x0, [x16, #272]",      // orig_x0
        "str  w8, [x16, #280]",      // syscallno (32-bit field)
        // Capture the guest's whole vector file and FP control/status before any
        // host code runs, since the host is free to use every vector register.
        "adrp x9, {guest_fp}@PAGE",
        "add  x9, x9, {guest_fp}@PAGEOFF",
        "stp  q0,  q1,  [x9, #0]",
        "stp  q2,  q3,  [x9, #32]",
        "stp  q4,  q5,  [x9, #64]",
        "stp  q6,  q7,  [x9, #96]",
        "stp  q8,  q9,  [x9, #128]",
        "stp  q10, q11, [x9, #160]",
        "stp  q12, q13, [x9, #192]",
        "stp  q14, q15, [x9, #224]",
        "stp  q16, q17, [x9, #256]",
        "stp  q18, q19, [x9, #288]",
        "stp  q20, q21, [x9, #320]",
        "stp  q22, q23, [x9, #352]",
        "stp  q24, q25, [x9, #384]",
        "stp  q26, q27, [x9, #416]",
        "stp  q28, q29, [x9, #448]",
        "stp  q30, q31, [x9, #480]",
        "mrs  x10, fpcr",
        "str  x10, [x9, #512]",
        "mrs  x10, fpsr",
        "str  x10, [x9, #520]",
        // Restore host callee-saved registers, LR and SP, then return into the
        // run loop (as though enter_guest_asm had returned), reporting a syscall.
        "adrp x1, {host_save}@PAGE",
        "add  x1, x1, {host_save}@PAGEOFF",
        "ldp  x19, x20, [x1, #0]",
        "ldp  x21, x22, [x1, #16]",
        "ldp  x23, x24, [x1, #32]",
        "ldp  x25, x26, [x1, #48]",
        "ldp  x27, x28, [x1, #64]",
        "ldr  x29, [x1, #80]",
        "ldr  x30, [x1, #88]",
        // Hand the host back its callee-saved FP registers and FP control/status.
        "ldp  d8,  d9,  [x1, #104]",
        "ldp  d10, d11, [x1, #120]",
        "ldp  d12, d13, [x1, #136]",
        "ldp  d14, d15, [x1, #152]",
        "ldr  x9, [x1, #168]",
        "msr  fpcr, x9",
        "ldr  x9, [x1, #176]",
        "msr  fpsr, x9",
        "ldr  x2, [x1, #96]",
        "mov  sp, x2",
        "mov  x0, #0",
        "ret",
        live = sym LIVE_PTREGS,
        host_save = sym HOST_SAVE,
        guest_fp = sym GUEST_FP,
        owns = sym GUEST_OWNS_CPU,
        abort = sym abort_on_boundary_stack_fault,
    )
}

/// The recovery target [`lib.rs`'s `fault_handler`] redirects a genuine guest
/// hardware fault to, once [`prepare_exception_delivery`] has already copied
/// the guest's captured register file (from the signal `mcontext`, not from
/// any guest-stack dereference) into `*`[`LIVE_PTREGS`] and filled in
/// [`PENDING_EXCEPTION_INFO`]. Unlike [`syscall_callback`], this never touches
/// guest memory at all -- everything it needs was already captured in Rust --
/// so it is simply [`syscall_callback`]'s host-state-restore tail, reporting
/// exception (`1`) instead of syscall (`0`).
///
/// # Safety
///
/// Reached only via a `pc` redirect from `fault_handler`, with
/// [`GUEST_OWNS_CPU`] already cleared and `*`[`LIVE_PTREGS`]/
/// [`PENDING_EXCEPTION_INFO`] already populated by [`prepare_exception_delivery`];
/// not callable as an ordinary function.
#[unsafe(naked)]
unsafe extern "C" fn exception_callback() {
    core::arch::naked_asm!(
        "adrp x1, {host_save}@PAGE",
        "add  x1, x1, {host_save}@PAGEOFF",
        "ldp  x19, x20, [x1, #0]",
        "ldp  x21, x22, [x1, #16]",
        "ldp  x23, x24, [x1, #32]",
        "ldp  x25, x26, [x1, #48]",
        "ldp  x27, x28, [x1, #64]",
        "ldr  x29, [x1, #80]",
        "ldr  x30, [x1, #88]",
        "ldp  d8,  d9,  [x1, #104]",
        "ldp  d10, d11, [x1, #120]",
        "ldp  d12, d13, [x1, #136]",
        "ldp  d14, d15, [x1, #152]",
        "ldr  x9, [x1, #168]",
        "msr  fpcr, x9",
        "ldr  x9, [x1, #176]",
        "msr  fpsr, x9",
        "ldr  x2, [x1, #96]",
        "mov  sp, x2",
        "mov  x0, #1",
        "ret",
        host_save = sym HOST_SAVE,
    )
}

/// Reached only via one of the exception-table entries emitted inline within
/// [`enter_guest_asm`] and [`syscall_callback`]: a fault at one of the handful
/// of instructions where this platform's own switch code must still touch the
/// bytes at/below a *guest*-controlled `sp`, before the guest is genuinely
/// executing (or after it has stopped). `lib.rs`'s `fault_handler` always
/// checks the exception table before [`GUEST_OWNS_CPU`], so a fault here is
/// redirected to this recovery point instead of ever being weighed as a
/// candidate for guest delivery -- the `pc`/`x30` a naive "guest owns the CPU"
/// check would otherwise see there point inside this platform's own binary,
/// which is exactly the ASLR-disclosure/return-to-host-code hazard this file
/// exists to avoid. Every such window is only a couple of instructions wide
/// and touches bytes this same code (or the syscall-rewriter's `SVC` gate)
/// just finished proving mapped, so reaching here at all means something
/// beyond an ordinary bad guest pointer has gone wrong; a loud, unambiguous
/// abort is safer than guessing whose fault it was.
#[unsafe(naked)]
unsafe extern "C" fn abort_on_boundary_stack_fault() -> ! {
    core::arch::naked_asm!(
        "adrp x0, {host_save}@PAGE",
        "add  x0, x0, {host_save}@PAGEOFF",
        "ldr  x1, [x0, #96]",
        "mov  sp, x1",
        "b {abort}",
        host_save = sym HOST_SAVE,
        abort = sym abort_boundary_stack_fault,
    )
}

/// The Rust half of [`abort_on_boundary_stack_fault`], once a valid (host) `sp`
/// has been restored.
extern "C" fn abort_boundary_stack_fault() -> ! {
    // A raw abort, not a Rust panic: unwinding out of a function reached by a
    // hand-redirected program counter (never a real call site, so no unwind
    // table covers the jump that got here) would corrupt the process, and
    // this condition is meant to be unmistakable on stderr either way.
    eprintln!(
        "litebox_platform_macos_userland: a fault landed on the guest/host \
         entry-exit boundary's own instructions rather than genuine guest \
         code; aborting instead of guessing which side owns it"
    );
    std::process::abort()
}

/// Delivers a genuine guest hardware fault as a
/// [`litebox::shim::EnterShim::exception`] event. Called by `lib.rs`'s
/// `fault_handler` only after its exception-table check has already missed
/// and [`GUEST_OWNS_CPU`] reads true (so this instant's `pc` is guest code,
/// not this platform's own switch code -- see that flag's doc comment for why
/// the ordering matters).
///
/// Copies the guest's captured GPRs/`SP`/`PC`/`PSTATE` straight from
/// `thread_state` into the run loop's live [`PtRegs`] (never re-deriving them
/// from the guest's own stack, unlike `syscall_callback` -- the kernel already
/// captured the true hardware state into `thread_state` at the moment of the
/// fault, a strictly more trustworthy source than anything this function could
/// read back off guest memory), records `info` for [`exception_callback`] to
/// hand to the run loop, clears the ownership flag, and returns the address
/// the caller should redirect the faulting `pc` to.
///
/// # Safety
///
/// Must be called with [`GUEST_OWNS_CPU`] genuinely true and `thread_state`
/// genuinely describing the interrupted guest, per the caller's own
/// exception-table-then-flag check.
pub(crate) unsafe fn prepare_exception_delivery(
    thread_state: &crate::darwin::ArmThreadState64,
    info: litebox::shim::ExceptionInfo,
) -> usize {
    // SAFETY: `GUEST_OWNS_CPU` was true (the caller's precondition), so
    // LIVE_PTREGS points at the one live PtRegs for the single active guest
    // thread, per the single-guest-thread invariant GUEST_ACTIVE enforces.
    let live = unsafe { &mut *(*LIVE_PTREGS.0.get()) };
    for (dst, src) in live.regs[..29].iter_mut().zip(thread_state.x.iter()) {
        *dst = src.trunc();
    }
    live.regs[29] = thread_state.fp.trunc();
    live.regs[30] = thread_state.lr.trunc();
    live.sp = thread_state.sp.trunc();
    live.pc = thread_state.pc.trunc();
    live.pstate = u64::from(thread_state.cpsr);
    live.orig_x0 = live.regs[0];
    // No syscall is in flight at a hardware fault, matching the kernel's own
    // `NO_SYSCALL` convention `litebox_shim_linux` relies on elsewhere.
    live.syscallno = -1;

    // SAFETY: single-guest-thread invariant, as for HOST_SAVE/GUEST_FP/LIVE_PTREGS.
    unsafe { *PENDING_EXCEPTION_INFO.0.get() = info };

    GUEST_OWNS_CPU.store(false, Ordering::Relaxed);

    exception_callback as *const () as usize
}

/// Runs a guest thread with the given shim and initial context.
///
/// Calls [`litebox::shim::EnterShim::init`], then loops: enter the guest, and
/// dispatch to [`litebox::shim::EnterShim::syscall`] or
/// [`litebox::shim::EnterShim::exception`] depending on why it returned,
/// resuming until a handler returns [`ContinueOperation::Terminate`].
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
        // Enter/resume the guest. Returns after a guest syscall or a genuine
        // guest hardware fault, with `*ctx` holding the guest state captured
        // by `syscall_callback` or `prepare_exception_delivery` respectively.
        //
        // SAFETY: `ctx` is a valid writable PtRegs; `GUEST_ACTIVE` guarantees
        // this is the only active guest thread, so the global save area is not
        // raced.
        let exit = GuestExit::from_asm_return(unsafe { enter_guest_asm(core::ptr::from_mut(ctx)) });

        let op = match exit {
            GuestExit::Syscall => shim.syscall(ctx),
            GuestExit::Exception => {
                // SAFETY: `prepare_exception_delivery` filled this in just
                // before redirecting here, and the single-guest-thread
                // invariant `GUEST_ACTIVE` enforces means nothing else can
                // have overwritten it since.
                let info = unsafe { *PENDING_EXCEPTION_INFO.0.get() };
                shim.exception(ctx, &info)
            }
        };
        if op == ContinueOperation::Terminate {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::RefCell;
    use litebox::shim::{EnterShim, Exception, ExceptionInfo};

    /// Only one guest thread may run at a time (see [`GUEST_ACTIVE`]), so the
    /// guest-entry tests must not run concurrently with each other under the
    /// parallel test harness.
    static TEST_SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

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
        let _serial = TEST_SERIAL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
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

    /// The guest stack region [`syscall_survives_a_guest_stack_with_only_16_valid_bytes_below_sp`]
    /// builds: a single valid page for the guest's usable stack, with an
    /// unmapped guard page immediately below it.
    struct GuardedStack {
        base: usize,
        page_size: usize,
    }

    impl GuardedStack {
        fn new() -> Self {
            // SAFETY: `sysconf` has no preconditions for this name.
            let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) }
                .try_into()
                .unwrap_or_else(|_| std::process::abort());
            // SAFETY: an anonymous mapping with no fixed-address request has no
            // precondition beyond what `mmap` itself checks.
            let base = unsafe {
                libc::mmap(
                    core::ptr::null_mut(),
                    page_size * 2,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANON,
                    -1,
                    0,
                )
            };
            assert_ne!(base, libc::MAP_FAILED, "failed to map the guarded stack");
            let base = base as usize;
            // SAFETY: `base` is the mapping just created, exactly `page_size`
            // bytes of which (the first page) this call alone will ever touch.
            let rc =
                unsafe { libc::mprotect(base as *mut libc::c_void, page_size, libc::PROT_NONE) };
            assert_eq!(rc, 0, "failed to guard the first page");
            Self { base, page_size }
        }

        /// The lowest address a guest occupying this stack may validly touch:
        /// the start of the second (mapped) page.
        fn valid_floor(&self) -> usize {
            self.base + self.page_size
        }
    }

    impl Drop for GuardedStack {
        fn drop(&mut self) {
            // SAFETY: `self.base` is this struct's own mapping, unmapped
            // exactly once here.
            unsafe { libc::munmap(self.base as *mut libc::c_void, self.page_size * 2) };
        }
    }

    /// The *original* `syscall_callback` carved 288 bytes for its own `PtRegs`
    /// capture out of the guest's stack, below the 16 bytes the `SVC` gate
    /// itself needs -- so a guest stack with fewer than `16 + 288` valid bytes
    /// below `sp` would fault *inside host code*, not guest code (see
    /// `docs/roadmap.md`'s "A guest fault kills the host"). The fixed version
    /// captures directly into the host-owned live `PtRegs` and never
    /// dereferences anything below `sp - 16`, so a syscall must still complete
    /// cleanly with only those 16 bytes valid: this guest's `sp` sits with
    /// nothing but an unmapped guard page below that 16-byte floor. A build
    /// still carrying the original capture-on-the-guest-stack code would crash
    /// this whole test process with `SIGSEGV` instead of returning.
    #[test]
    fn syscall_survives_a_guest_stack_with_only_16_valid_bytes_below_sp() {
        let _serial = TEST_SERIAL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let stack = GuardedStack::new();
        let sp = stack.valid_floor() + 16;

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
            "guest should have made write(1,0xABC,..) then exit(42) even with a \
             guest stack that has only 16 valid bytes below sp"
        );
    }

    /// A shim that records a genuinely-delivered guest hardware fault: the
    /// [`ExceptionInfo`], the full captured register file, and the captured
    /// `pc` -- everything a naive "guest owns the CPU" check could instead
    /// fill with host state if it misattributed a host-side fault as the
    /// guest's own.
    struct FaultRecordingShim {
        reported_pc: core::cell::Cell<usize>,
        delivered: RefCell<Option<(ExceptionInfo, [usize; 31], usize)>>,
    }

    impl EnterShim for FaultRecordingShim {
        type ExecutionContext = PtRegs;
        fn init(&self, _ctx: &mut PtRegs) -> ContinueOperation {
            ContinueOperation::Resume
        }
        fn syscall(&self, ctx: &mut PtRegs) -> ContinueOperation {
            // The guest reports the address it is about to fault at (computed
            // with `adr`, immediately before the faulting instruction) via
            // write(1, that_address, 0).
            self.reported_pc.set(ctx.regs[1]);
            ctx.regs[0] = 0;
            ContinueOperation::Resume
        }
        fn exception(&self, ctx: &mut PtRegs, info: &ExceptionInfo) -> ContinueOperation {
            *self.delivered.borrow_mut() = Some((*info, ctx.regs, ctx.pc));
            // There is no guest signal handler to resume into in this test.
            ContinueOperation::Terminate
        }
        fn interrupt(&self, _ctx: &mut PtRegs) -> ContinueOperation {
            ContinueOperation::Terminate
        }
    }

    /// A guest that seeds sentinels into a caller-saved register (`x9`) and
    /// the link register (`x30`, singled out because a leaked host `x30` is
    /// exactly the return-to-host-code hazard this file exists to avoid),
    /// reports its own about-to-fault `pc` through a syscall, then genuinely
    /// faults by loading through a null pointer.
    #[unsafe(naked)]
    unsafe extern "C" fn faulting_guest() {
        core::arch::naked_asm!(
            "movz x9,  #0xCAFE",
            "movz x30, #0xBEEF",
            "movz x4,  #0",
            // write(1, &50f, 0): report the address about to fault.
            "movz x8, #64",
            "movz x0, #1",
            "adr  x1, 50f",
            "movz x2, #0",
            "sub  sp, sp, #16",
            "str  x16, [sp]",
            "adrp x16, 50f@PAGE",
            "add  x16, x16, 50f@PAGEOFF",
            "str  x16, [sp, #8]",
            "adrp x16, {cb}@PAGE",
            "add  x16, x16, {cb}@PAGEOFF",
            "br   x16",
            "50:",
            "ldr  x3, [x4]",  // deliberate fault: load through a null pointer
            "brk  #0",        // unreachable
            cb = sym syscall_callback,
        )
    }

    /// The end-to-end fault-routing path this file exists to implement: a
    /// genuine guest hardware fault must reach [`EnterShim::exception`] with
    /// the guest's own state, and the host process must not die.
    #[test]
    fn delivers_a_genuine_guest_fault_to_the_shim_without_leaking_host_state() {
        let _serial = TEST_SERIAL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // Unlike the other tests in this module, this one deliberately faults,
        // so the platform's SIGSEGV/SIGBUS handler must actually be installed
        // -- production always does this via `MacOsUserland::new`, which this
        // test intentionally does not otherwise construct. Idempotent: safe to
        // call again if another test in this process already has.
        crate::install_fault_handlers();
        let mut stack = vec![0u8; 1 << 16];
        let top = stack.as_mut_ptr() as usize + stack.len();
        let sp = (top - 256) & !15;

        let mut ctx = PtRegs {
            pc: faulting_guest as *const () as usize,
            sp,
            ..Default::default()
        };
        let shim = FaultRecordingShim {
            reported_pc: core::cell::Cell::new(0),
            delivered: RefCell::new(None),
        };
        // If this platform ever again misrouted a guest fault, this call
        // itself would take the whole test process down with a raw signal --
        // reaching the assertions below is already most of the proof.
        run_thread(&shim, &mut ctx);

        let reported_pc = shim.reported_pc.get();
        assert_ne!(reported_pc, 0, "guest never reported its expected fault pc");

        let (info, regs, pc) = shim
            .delivered
            .into_inner()
            .expect("EnterShim::exception was never invoked");

        assert_eq!(
            pc, reported_pc,
            "delivered pc must be exactly the guest's own faulting instruction \
             (self-reported via adr moments before faulting), never a host address"
        );
        assert_eq!(
            regs[9], 0xCAFE,
            "delivered x9 must be the guest's own sentinel, not host garbage"
        );
        assert_eq!(
            regs[30], 0xBEEF,
            "delivered x30 must be the guest's own sentinel, never a host return address"
        );
        assert_eq!(info.fault_address, 0, "guest dereferenced address 0");
        assert!(
            !info.kernel_mode,
            "this platform's guest never runs kernel-mode"
        );
        assert!(
            matches!(
                info.exception,
                Exception::DATA_ABORT_LOWER_EL | Exception::DATA_ABORT_CURRENT_EL
            ),
            "expected a data-abort exception class for a null-pointer load, got {:?}",
            info.exception
        );
    }

    /// A shim that captures the full register file at the first syscall and the
    /// first argument at the second, to check context-switch fidelity.
    struct FidelityShim {
        first: RefCell<Option<[usize; 31]>>,
        second_x1: core::cell::Cell<usize>,
        calls: core::cell::Cell<u32>,
    }

    impl EnterShim for FidelityShim {
        type ExecutionContext = PtRegs;
        fn init(&self, _ctx: &mut PtRegs) -> ContinueOperation {
            ContinueOperation::Resume
        }
        fn syscall(&self, ctx: &mut PtRegs) -> ContinueOperation {
            let n = self.calls.get();
            self.calls.set(n + 1);
            match n {
                0 => {
                    *self.first.borrow_mut() = Some(ctx.regs);
                    ctx.regs[0] = 0;
                    ContinueOperation::Resume
                }
                1 => {
                    self.second_x1.set(ctx.regs[1]);
                    ctx.regs[0] = 0;
                    ContinueOperation::Resume
                }
                _ => ContinueOperation::Terminate,
            }
        }
        fn exception(&self, _ctx: &mut PtRegs, _info: &ExceptionInfo) -> ContinueOperation {
            ContinueOperation::Terminate
        }
        fn interrupt(&self, _ctx: &mut PtRegs) -> ContinueOperation {
            ContinueOperation::Terminate
        }
    }

    /// A guest that seeds sentinels into a spread of callee- and caller-saved
    /// registers, makes a syscall (so the callback captures them), then -- after
    /// resuming -- passes the callee-saved `x19` sentinel as a syscall argument
    /// (so we can confirm it survived the enter/capture/resume round trip),
    /// then exits.
    #[unsafe(naked)]
    unsafe extern "C" fn fidelity_guest() {
        core::arch::naked_asm!(
            // Seed sentinels: x19 = 0x2222_1111 (callee-saved), x20/x28
            // (callee-saved), x9 (caller-saved).
            "movz x19, #0x1111",
            "movk x19, #0x2222, lsl #16",
            "movz x20, #0xBEEF",
            "movz x9,  #0xCAFE",
            "movz x28, #0xF00D",
            // syscall 1: write(1, 0xABC, 7)
            "movz x8, #64",
            "movz x0, #1",
            "movz x1, #0xABC",
            "movz x2, #7",
            "sub  sp, sp, #16",
            "str  x16, [sp]",
            "adrp x16, 30f@PAGE",
            "add  x16, x16, 30f@PAGEOFF",
            "str  x16, [sp, #8]",
            "adrp x16, {cb}@PAGE",
            "add  x16, x16, {cb}@PAGEOFF",
            "br   x16",
            "30:",
            // syscall 2: write(2, x19, 0) -- x19 must still hold its sentinel.
            "movz x8, #64",
            "movz x0, #2",
            "mov  x1, x19",
            "movz x2, #0",
            "sub  sp, sp, #16",
            "str  x16, [sp]",
            "adrp x16, 31f@PAGE",
            "add  x16, x16, 31f@PAGEOFF",
            "str  x16, [sp, #8]",
            "adrp x16, {cb}@PAGE",
            "add  x16, x16, {cb}@PAGEOFF",
            "br   x16",
            "31:",
            // exit(0)
            "movz x8, #93",
            "movz x0, #0",
            "sub  sp, sp, #16",
            "str  x16, [sp]",
            "adrp x16, 32f@PAGE",
            "add  x16, x16, 32f@PAGEOFF",
            "str  x16, [sp, #8]",
            "adrp x16, {cb}@PAGE",
            "add  x16, x16, {cb}@PAGEOFF",
            "br   x16",
            "32:",
            "brk  #0",
            cb = sym syscall_callback,
        )
    }

    /// A guest that leaves a sentinel in `v8` and a non-default rounding mode in
    /// `FPCR` across a syscall, then reports both back through a second syscall.
    ///
    /// Linux preserves user FPSIMD across an `SVC`, so a real guest is entitled
    /// to do exactly this -- glibc's and musl's string routines hold live vector
    /// values across calls that may syscall.
    #[unsafe(naked)]
    unsafe extern "C" fn fp_fidelity_guest() {
        core::arch::naked_asm!(
            // v8 = 0x5555_4444, FPCR = round-toward-plus-infinity (RMode = 0b01).
            "movz x3, #0x4444",
            "movk x3, #0x5555, lsl #16",
            "fmov d8, x3",
            "movz x3, #0x40, lsl #16",
            "msr  fpcr, x3",
            // syscall 1: write(1, 0, 0) -- just a trip through the host.
            "movz x8, #64",
            "movz x0, #1",
            "movz x1, #0",
            "movz x2, #0",
            "sub  sp, sp, #16",
            "str  x16, [sp]",
            "adrp x16, 40f@PAGE",
            "add  x16, x16, 40f@PAGEOFF",
            "str  x16, [sp, #8]",
            "adrp x16, {cb}@PAGE",
            "add  x16, x16, {cb}@PAGEOFF",
            "br   x16",
            "40:",
            // syscall 2: write(2, v8_low, fpcr) -- both must have survived.
            "movz x8, #64",
            "movz x0, #2",
            "fmov x1, d8",
            "mrs  x2, fpcr",
            "sub  sp, sp, #16",
            "str  x16, [sp]",
            "adrp x16, 41f@PAGE",
            "add  x16, x16, 41f@PAGEOFF",
            "str  x16, [sp, #8]",
            "adrp x16, {cb}@PAGE",
            "add  x16, x16, {cb}@PAGEOFF",
            "br   x16",
            "41:",
            // exit(0)
            "movz x8, #93",
            "movz x0, #0",
            "sub  sp, sp, #16",
            "str  x16, [sp]",
            "adrp x16, 42f@PAGE",
            "add  x16, x16, 42f@PAGEOFF",
            "str  x16, [sp, #8]",
            "adrp x16, {cb}@PAGE",
            "add  x16, x16, {cb}@PAGEOFF",
            "br   x16",
            "42:",
            "brk  #0",
            cb = sym syscall_callback,
        )
    }

    /// Scribble over the FP state a guest might be holding, the way ordinary
    /// host code does incidentally. Explicit here so the test proves the switch
    /// protects the guest rather than depending on whether this build's shim
    /// happened to touch a vector register.
    fn clobber_host_fp() {
        // SAFETY: writes only scratch FP state, all of it declared clobbered.
        unsafe {
            core::arch::asm!(
                "movi v8.16b, #0xFF",
                "msr  fpcr, xzr",
                out("v8") _,
                options(nostack),
            );
        }
    }

    /// The guest's FP/SIMD state must survive a syscall, because Linux's does.
    /// Before the switch saved it, the host's own use of the vector registers
    /// destroyed whatever the guest was holding.
    #[test]
    fn preserves_fp_state_across_capture_and_resume() {
        let _serial = TEST_SERIAL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut stack = vec![0u8; 1 << 16];
        let top = stack.as_mut_ptr() as usize + stack.len();
        let sp = (top - 256) & !15;

        let mut ctx = PtRegs {
            pc: fp_fidelity_guest as *const () as usize,
            sp,
            ..Default::default()
        };
        let shim = FpFidelityShim {
            reported: core::cell::Cell::new(None),
            calls: core::cell::Cell::new(0),
        };
        run_thread(&shim, &mut ctx);

        let (v8_low, fpcr) = shim.reported.get().expect("second syscall not seen");
        assert_eq!(v8_low, 0x5555_4444, "v8 survived the round trip");
        assert_eq!(
            fpcr, 0x40_0000,
            "FPCR rounding mode survived the round trip"
        );
        assert_eq!(shim.calls.get(), 3, "expected write, write, exit");
    }

    struct FpFidelityShim {
        reported: core::cell::Cell<Option<(usize, usize)>>,
        calls: core::cell::Cell<u32>,
    }

    impl litebox::shim::EnterShim for FpFidelityShim {
        type ExecutionContext = PtRegs;
        fn init(&self, _ctx: &mut PtRegs) -> ContinueOperation {
            ContinueOperation::Resume
        }
        fn syscall(&self, ctx: &mut PtRegs) -> ContinueOperation {
            let n = self.calls.get();
            self.calls.set(n + 1);
            // Stand in for the ordinary host code that runs between guest entries.
            clobber_host_fp();
            match n {
                0 => {
                    ctx.regs[0] = 0;
                    ContinueOperation::Resume
                }
                1 => {
                    self.reported.set(Some((ctx.regs[1], ctx.regs[2])));
                    ctx.regs[0] = 0;
                    ContinueOperation::Resume
                }
                _ => ContinueOperation::Terminate,
            }
        }
        fn exception(&self, _ctx: &mut PtRegs, _info: &ExceptionInfo) -> ContinueOperation {
            ContinueOperation::Terminate
        }
        fn interrupt(&self, _ctx: &mut PtRegs) -> ContinueOperation {
            ContinueOperation::Terminate
        }
    }

    #[test]
    fn preserves_registers_across_capture_and_resume() {
        let _serial = TEST_SERIAL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut stack = vec![0u8; 1 << 16];
        let top = stack.as_mut_ptr() as usize + stack.len();
        let sp = (top - 256) & !15;

        let mut ctx = PtRegs {
            pc: fidelity_guest as *const () as usize,
            sp,
            ..Default::default()
        };
        let shim = FidelityShim {
            first: RefCell::new(None),
            second_x1: core::cell::Cell::new(0),
            calls: core::cell::Cell::new(0),
        };
        run_thread(&shim, &mut ctx);

        let first = shim.first.into_inner().expect("first syscall not seen");
        // Capture fidelity: every seeded register reached the callback intact.
        assert_eq!(first[19], 0x2222_1111, "x19 (callee-saved) captured");
        assert_eq!(first[20], 0xBEEF, "x20 (callee-saved) captured");
        assert_eq!(first[9], 0xCAFE, "x9 (caller-saved) captured");
        assert_eq!(first[28], 0xF00D, "x28 (callee-saved) captured");
        // Resume fidelity: x19 still held its sentinel after resuming, and the
        // guest passed it as the second syscall's x1.
        assert_eq!(
            shim.second_x1.get(),
            0x2222_1111,
            "x19 survived the enter/capture/resume round trip"
        );
        assert_eq!(shim.calls.get(), 3, "expected write, write, exit");
    }
}
