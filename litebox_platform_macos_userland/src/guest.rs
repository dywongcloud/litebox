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
//!   includes [`GUEST_OWNS_CPU`] and [`PENDING_INTERRUPT`]: lifting the
//!   single-thread restriction would need both to become per-thread state
//!   too, reached the same `TPIDRRO_EL0`-relative way.
//! * **Guest hardware faults (`SIGSEGV`/`SIGBUS`) are routed** to
//!   [`litebox::shim::EnterShim::exception`] via [`GUEST_OWNS_CPU`] and
//!   `lib.rs`'s `fault_handler`. A delivered exception's captured general
//!   registers/`PSTATE`/vector state are all exact, read straight from the
//!   kernel's own signal `mcontext` (see [`prepare_exception_delivery`]).
//! * **The interrupt path (`SIGUSR2`) is routed** to
//!   [`litebox::shim::EnterShim::interrupt`] via `lib.rs`'s
//!   `interrupt_signal_handler`, [`interrupted_pc_is_in_guest_entry_restore`]/
//!   [`interrupted_pc_is_in_guest_exit_prologue`], [`PENDING_INTERRUPT`] and
//!   [`prepare_interrupt_delivery`]/[`abandon_guest_entry_for_interrupt`] --
//!   see those items' own doc comments for the four-case dispatch this needed
//!   (mirroring `litebox_platform_linux_userland`'s and
//!   `litebox_platform_windows_userland`'s own four-case interrupt handling,
//!   adapted to this platform's process-global `GUEST_OWNS_CPU` bookkeeping).
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

/// Reads [`GUEST_FP`] in the shim-facing shape, for `lib.rs`'s
/// `ThreadProvider::get_fp_state` implementation.
///
/// Callable any time no guest is concurrently mutating [`GUEST_FP`] via
/// `enter_guest_asm`/`syscall_callback`/`exception_callback` -- i.e. whenever an
/// `EnterShim` method is running, which is the only time the shim can call
/// this, since [`GUEST_OWNS_CPU`] is false throughout.
pub(crate) fn guest_fp_state() -> litebox::platform::FpSimdState64 {
    // SAFETY: single-guest-thread invariant (`GUEST_ACTIVE`), as for every
    // other `GUEST_FP` access in this file; not concurrently written while an
    // `EnterShim` method (and therefore this function) can run.
    let fp = unsafe { &*GUEST_FP.0.get() };
    litebox::platform::FpSimdState64 {
        v: fp.v,
        fpsr: fp.fpsr.trunc(),
        fpcr: fp.fpcr.trunc(),
    }
}

/// Writes [`GUEST_FP`] from the shim-facing shape, for `lib.rs`'s
/// `ThreadProvider::set_fp_state` implementation (e.g. restoring what a guest
/// signal handler left in its frame on `rt_sigreturn`).
///
/// Same calling window as [`guest_fp_state`].
pub(crate) fn set_guest_fp_state(state: &litebox::platform::FpSimdState64) {
    // SAFETY: as `guest_fp_state`.
    let fp = unsafe { &mut *GUEST_FP.0.get() };
    fp.v = state.v;
    fp.fpcr = u64::from(state.fpcr);
    fp.fpsr = u64::from(state.fpsr);
}

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

/// Set by `lib.rs`'s `interrupt_signal_handler` whenever a `SIGUSR2` arrives
/// at a moment it cannot redirect immediately (the thread was not genuinely
/// executing guest code -- [`GUEST_OWNS_CPU`] false, or `SIGUSR2` landed
/// inside [`syscall_callback`]'s/[`sigreturn_trampoline`]'s own brief
/// ownership-clearing prologue), so the delivery is not simply lost. Checked
/// and cleared by [`enter_guest_asm`] immediately after it sets
/// [`GUEST_OWNS_CPU`] true for a fresh entry, *before* restoring any guest
/// register -- mirroring `litebox_platform_linux_userland::switch_to_guest`'s
/// own `cmp .../jne interrupt_callback` placed immediately after its `in_guest
/// := 1` store, for the identical reason: without this re-check, an interrupt
/// that races the narrow window between the shim deciding a thread is
/// "running in guest" (and so signalling it) and this platform's own
/// `GUEST_OWNS_CPU` actually becoming true for *that* entry would be silently
/// dropped until the guest's next syscall -- arbitrarily far away for a
/// compute-bound guest, defeating the entire point of interrupting one.
pub(crate) static PENDING_INTERRUPT: AtomicBool = AtomicBool::new(false);

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
        // switch_to_guest_start: from here on, a SIGUSR2 arriving must not be
        // treated as "genuinely executing guest code" even once GUEST_OWNS_CPU
        // reads true below -- interrupted_pc_is_in_guest_entry_restore checks
        // this exact range (up to switch_to_guest_end) for that reason. See
        // `lib.rs`'s `interrupt_signal_handler` doc comment for the full
        // four-case dispatch this label range is one input to.
        //
        // `_`-prefixed and `.globl`, matching Darwin's (unlike Linux's)
        // leading-underscore C symbol convention -- verified against this
        // build by `interrupted_pc_is_in_guest_entry_restore`'s own hardware
        // test, not merely assumed.
        ".globl _switch_to_guest_start",
        "_switch_to_guest_start:",
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
        // Re-check PENDING_INTERRUPT immediately after opening the "owns"
        // window, before restoring any guest register -- mirrors
        // litebox_platform_linux_userland::switch_to_guest's own pending-
        // interrupt check placed right after its `in_guest := 1` store (see
        // PENDING_INTERRUPT's doc comment for why this re-check exists at
        // all). x1 and x16 are still free for the same reason as above; ctx
        // (x0) is untouched, so abandoning the entry here needs no capture --
        // interrupt_callback is reached with `*ctx` exactly as the caller left
        // it.
        "adrp x16, {pending}@PAGE",
        "add  x16, x16, {pending}@PAGEOFF",
        "ldrb w1, [x16]",
        "cbz  w1, 92f",
        "strb wzr, [x16]",
        "adrp x16, {owns}@PAGE",
        "add  x16, x16, {owns}@PAGEOFF",
        "strb wzr, [x16]",
        "adrp x16, {interrupt_cb}@PAGE",
        "add  x16, x16, {interrupt_cb}@PAGEOFF",
        "br   x16",
        "92:",
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
        // switch_to_guest_end: a label, never reached by falling through (the
        // branch above always diverts first) -- its only purpose is to give
        // interrupted_pc_is_in_guest_entry_restore an end address for the
        // range starting at switch_to_guest_start.
        ".globl _switch_to_guest_end",
        "_switch_to_guest_end:",
        host_save = sym HOST_SAVE,
        live = sym LIVE_PTREGS,
        guest_fp = sym GUEST_FP,
        owns = sym GUEST_OWNS_CPU,
        pending = sym PENDING_INTERRUPT,
        interrupt_cb = sym interrupt_callback,
        abort = sym abort_on_boundary_stack_fault,
    )
}

/// Which of [`syscall_callback`], [`exception_callback`] or
/// [`interrupt_callback`] restored the host context, i.e. what
/// [`enter_guest_asm`]'s return value means. `run_thread`'s loop dispatches on
/// this instead of always assuming a syscall -- the second return path
/// [`Self::Interrupt`] needed on top of the original syscall/exception split.
enum GuestExit {
    Syscall,
    Exception,
    Interrupt,
}

impl GuestExit {
    /// Decodes [`enter_guest_asm`]'s return value. All three callbacks set
    /// exactly `0`, `1` or `2`, so anything else would mean the asm and this
    /// decoder have drifted apart -- a build-time bug, not a runtime condition
    /// to handle gracefully.
    fn from_asm_return(value: u64) -> Self {
        match value {
            0 => Self::Syscall,
            1 => Self::Exception,
            2 => Self::Interrupt,
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
        // syscall_callback_start: covers this whole function, used by
        // interrupted_pc_is_in_guest_exit_prologue. Only the first couple of
        // instructions below (before GUEST_OWNS_CPU is cleared) are the
        // window that check actually needs to distinguish -- the rest of this
        // function already reads GUEST_OWNS_CPU false by the time it runs, so
        // `lib.rs`'s `interrupt_signal_handler` never reaches the PC-range
        // check for it (see that function's case-1 priority ordering); using
        // the whole function as the range is simpler than a second, tighter
        // label pair and no less correct.
        ".globl _syscall_callback_start",
        "_syscall_callback_start:",
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
        // syscall_callback_end: never reached (the `ret` above always leaves
        // first); see syscall_callback_start's comment.
        ".globl _syscall_callback_end",
        "_syscall_callback_end:",
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

/// The recovery target `lib.rs`'s `interrupt_signal_handler` redirects an
/// interrupted guest thread to, once either [`prepare_interrupt_delivery`]
/// (genuinely-executing-guest case) has captured state or
/// [`abandon_guest_entry_for_interrupt`] (mid-restore case) has decided no
/// capture is needed. Identical in structure to [`exception_callback`] --
/// [`syscall_callback`]'s host-state-restore tail -- reporting interrupt (`2`)
/// instead of exception (`1`) or syscall (`0`).
///
/// # Safety
///
/// Reached only via a `pc` redirect from `interrupt_signal_handler`, with
/// [`GUEST_OWNS_CPU`] already cleared and `*`[`LIVE_PTREGS`] already either
/// left as the caller's still-accurate context or freshly populated; not
/// callable as an ordinary function.
#[unsafe(naked)]
unsafe extern "C" fn interrupt_callback() {
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
        "mov  x0, #2",
        "ret",
        host_save = sym HOST_SAVE,
    )
}

/// aarch64 Linux's `__NR_rt_sigreturn`, hardcoded into [`sigreturn_trampoline`]
/// because the guest never sets `x8` on the way in (there is no real `SVC`,
/// so no C library gets a chance to). Verified against the vendored
/// `syscalls-0.6.18` crate source
/// (`src/arch/aarch64.rs:286`, `rt_sigreturn = 139`) -- the same crate
/// `litebox_common_linux::SyscallRequest::try_from_raw` decodes `PtRegs::syscallno`
/// through, so this is guaranteed to route to `Sysno::rt_sigreturn` there.
const AARCH64_RT_SIGRETURN: u32 = 139;

/// This platform's own sigreturn trampoline: what
/// [`litebox::platform::SystemInfoProvider::get_sigreturn_trampoline_address`]
/// reports, and what `litebox_shim_linux` installs as a guest signal handler's
/// return address (`x30`) when the guest registered the handler without
/// `SA_RESTORER`. There is no vDSO on macOS to fall back to the way a real
/// Linux kernel does (see `darwin.rs`'s and `lib.rs`'s `get_vdso_address`
/// docs), so this *is* the fallback -- reached the same way
/// [`syscall_callback`] is, by handing a host code address to a
/// guest-controlled register (there `x16` via the rewriter's gate, here `x30`
/// via the signal frame `litebox_shim_linux` builds), an "absolute address"
/// reachable from any guest regardless of branch-range limits (see
/// `litebox_syscall_rewriter::arm64`'s "Signal returns" module-doc section,
/// which anticipated exactly this).
///
/// Unlike [`syscall_callback`], this never touches guest memory at all, and
/// needs no exception-table entry: a real `SVC` gate stashes the guest's `x16`
/// and a return address below `sp` because it has no free register to carry
/// them in, but this trampoline is reached directly by `RET` (no gate ran),
/// so nothing needs recovering from the guest stack. It captures only `sp`
/// (via the real `SP` register, exactly as the guest's `ret` left it) and sets
/// `syscallno` to [`AARCH64_RT_SIGRETURN`] -- deliberately capturing *no other
/// register*, unlike every other guest-exit path in this file. This is safe
/// only because of what `sys_rt_sigreturn`/`restore_sigcontext`
/// (`litebox_shim_linux/src/syscalls/signal/{mod.rs,aarch64.rs}`) actually do
/// with the `PtRegs` this hands them: `Sysno::rt_sigreturn` takes no register
/// arguments (confirmed against `SyscallRequest::try_from_raw`'s dispatch, which
/// extracts zero fields for it), the frame is located purely from `ctx.sp`, and
/// every other field (`regs`, `pc`, `pstate`) is overwritten wholesale from the
/// frame's saved `sigcontext` before anything downstream reads it -- including
/// `regs[0]`, which the generic "write the syscall result into `x0`" step then
/// re-writes with the exact value `restore_sigcontext` just placed there,
/// making that generic step a no-op for this syscall specifically. A stale
/// `pc`/`regs`/`pstate` left over from whatever this `PtRegs` last held is
/// therefore never observed.
///
/// # Safety
///
/// Reached only via a guest `RET` with `x30` holding this function's own
/// address (installed by `litebox_shim_linux` as a signal frame's return
/// slot) and [`GUEST_OWNS_CPU`] genuinely true; not callable as an ordinary
/// function.
#[unsafe(naked)]
pub(crate) unsafe extern "C" fn sigreturn_trampoline() {
    core::arch::naked_asm!(
        // sigreturn_trampoline_start: covers this whole function, same
        // reasoning as syscall_callback_start.
        ".globl _sigreturn_trampoline_start",
        "_sigreturn_trampoline_start:",
        // Clear ownership before touching anything else -- see
        // GUEST_OWNS_CPU's doc comment; same first-instruction placement and
        // reasoning as syscall_callback.
        "adrp x9, {owns}@PAGE",
        "add  x9, x9, {owns}@PAGEOFF",
        "strb wzr, [x9]",
        // Load the destination PtRegs (host-owned, set by enter_guest_asm).
        "adrp x9, {live}@PAGE",
        "add  x9, x9, {live}@PAGEOFF",
        "ldr  x9, [x9]",
        // sp: the guest's real SP, exactly as its own `ret` left it (SP
        // cannot be a direct STR source operand, hence the mov through x10).
        "mov  x10, sp",
        "str  x10, [x9, #248]",
        // syscallno: force dispatch to sys_rt_sigreturn regardless of
        // whatever this guest's x8 last held (no real SVC ran).
        "movz w10, #{rt_sigreturn}",
        "str  w10, [x9, #280]",
        // Restore host state and return reporting a syscall (0), exactly like
        // syscall_callback's own tail, so run_thread's loop calls
        // shim.syscall -- which dispatches sys_rt_sigreturn purely from the
        // sp/syscallno just written (see this function's own doc comment for
        // why nothing else needs capturing).
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
        "mov  x0, #0",
        "ret",
        // sigreturn_trampoline_end: never reached, same reasoning as
        // syscall_callback_end.
        ".globl _sigreturn_trampoline_end",
        "_sigreturn_trampoline_end:",
        host_save = sym HOST_SAVE,
        live = sym LIVE_PTREGS,
        owns = sym GUEST_OWNS_CPU,
        rt_sigreturn = const AARCH64_RT_SIGRETURN,
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
        // Belt-and-suspenders: this path is headed for a fatal abort
        // regardless, but clearing GUEST_OWNS_CPU here too (rather than
        // leaving it however it read at the fault) closes the otherwise-real
        // possibility of a SIGUSR2 landing in the couple of instructions
        // between here and the abort call and misreading a stale `true`.
        "adrp x2, {owns}@PAGE",
        "add  x2, x2, {owns}@PAGEOFF",
        "strb wzr, [x2]",
        "adrp x0, {host_save}@PAGE",
        "add  x0, x0, {host_save}@PAGEOFF",
        "ldr  x1, [x0, #96]",
        "mov  sp, x1",
        "b {abort}",
        host_save = sym HOST_SAVE,
        owns = sym GUEST_OWNS_CPU,
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
/// read back off guest memory), refreshes [`GUEST_FP`] from `neon_state` for
/// the same reason (the kernel's own capture, not whatever `GUEST_FP` held
/// from the guest's last syscall), records `info` for [`exception_callback`]
/// to hand to the run loop, clears the ownership flag, and returns the address
/// the caller should redirect the faulting `pc` to.
///
/// # Safety
///
/// Must be called with [`GUEST_OWNS_CPU`] genuinely true and `thread_state`/
/// `neon_state` genuinely describing the interrupted guest, per the caller's
/// own exception-table-then-flag check.
pub(crate) unsafe fn prepare_exception_delivery(
    thread_state: &crate::darwin::ArmThreadState64,
    neon_state: &crate::darwin::ArmNeonState64,
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

    // Logs the full guest register state whenever a hardware fault is
    // delivered to the guest. Gated behind trace level
    // (`LITEBOX_LOG=litebox_platform_macos_userland=trace`), so it is inert by
    // default; kept as a permanent debug aid (originally added for the
    // macos-concurrent-guest-entry-sigsegv investigation, see
    // `docs/roadmap.md`) since a guest fault's registers are otherwise not
    // observable without an attached debugger, and the previous investigation
    // passes on that bug were slowed down by not having this.
    litebox_util_log::trace!(
        regs:? = &live.regs, sp:? = live.sp, pc:? = live.pc,
        fault_address:? = info.fault_address, esr:? = info.esr,
        exception:? = info.exception;
        "guest fault: captured register state"
    );

    // SAFETY: single-guest-thread invariant, as for HOST_SAVE/GUEST_FP/LIVE_PTREGS.
    let fp = unsafe { &mut *GUEST_FP.0.get() };
    fp.v = neon_state.v;
    fp.fpsr = u64::from(neon_state.fpsr);
    fp.fpcr = u64::from(neon_state.fpcr);

    // SAFETY: single-guest-thread invariant, as for HOST_SAVE/GUEST_FP/LIVE_PTREGS.
    unsafe { *PENDING_EXCEPTION_INFO.0.get() = info };

    GUEST_OWNS_CPU.store(false, Ordering::Relaxed);

    exception_callback as *const () as usize
}

// Address markers this file's own naked `asm!` blocks define (see
// `enter_guest_asm`'s `switch_to_guest_start`/`_end`, `syscall_callback`'s
// `syscall_callback_start`/`_end` and `sigreturn_trampoline`'s
// `sigreturn_trampoline_start`/`_end`), never called -- only their addresses
// are taken, by `interrupted_pc_is_in_guest_entry_restore`/
// `interrupted_pc_is_in_guest_exit_prologue` below.
unsafe extern "C" {
    fn switch_to_guest_start();
    fn switch_to_guest_end();
    fn syscall_callback_start();
    fn syscall_callback_end();
    fn sigreturn_trampoline_start();
    fn sigreturn_trampoline_end();
}

/// Whether an interrupted `pc` falls inside [`enter_guest_asm`]'s own
/// restore range -- "mid-restoring a [`PtRegs`] that is still authoritative,"
/// in `lib.rs`'s `interrupt_signal_handler` doc comment's terms. Used only
/// while [`GUEST_OWNS_CPU`] already reads true (that flag is checked first,
/// same ordering as `fault_handler`'s exception-table-before-flag priority);
/// this function does not re-check it.
pub(crate) fn interrupted_pc_is_in_guest_entry_restore(pc: usize) -> bool {
    let start = switch_to_guest_start as *const () as usize;
    let end = switch_to_guest_end as *const () as usize;
    (start..end).contains(&pc)
}

/// Whether an interrupted `pc` falls inside [`syscall_callback`]'s or
/// [`sigreturn_trampoline`]'s own address range -- the exit-side counterpart
/// of [`interrupted_pc_is_in_guest_entry_restore`]. Only the first couple of
/// instructions of either function are the genuine hazard window (before
/// [`GUEST_OWNS_CPU`] is cleared); the rest of each function's range is
/// screened out by that flag already reading false by the time `pc` lands
/// there, so `interrupt_signal_handler` never reaches this check for it. Using
/// the whole function as the range is deliberately imprecise in the caller's
/// favor: it can only make this function return `true` in cases where the
/// flag-based check would already have returned early, never the reverse.
pub(crate) fn interrupted_pc_is_in_guest_exit_prologue(pc: usize) -> bool {
    let syscall_start = syscall_callback_start as *const () as usize;
    let syscall_end = syscall_callback_end as *const () as usize;
    let sigreturn_start = sigreturn_trampoline_start as *const () as usize;
    let sigreturn_end = sigreturn_trampoline_end as *const () as usize;
    (syscall_start..syscall_end).contains(&pc) || (sigreturn_start..sigreturn_end).contains(&pc)
}

/// Delivers a genuine guest interrupt (`SIGUSR2` arriving while the guest is
/// truly executing, not mid-switch) as a [`litebox::shim::EnterShim::interrupt`]
/// event. Called by `lib.rs`'s `interrupt_signal_handler` only after
/// [`GUEST_OWNS_CPU`] reads true and `pc` falls outside every switch-code
/// range (see [`interrupted_pc_is_in_guest_entry_restore`]/
/// [`interrupted_pc_is_in_guest_exit_prologue`]).
///
/// Structurally [`prepare_exception_delivery`] minus the [`ExceptionInfo`]:
/// same register/vector-state copy from the kernel's own captured `mcontext`,
/// same ownership-flag clear, same "return the recovery address" contract.
/// There is no [`PENDING_EXCEPTION_INFO`]-equivalent to fill in --
/// [`litebox::shim::EnterShim::interrupt`] takes only a `ctx`, no side
/// channel.
///
/// [`ExceptionInfo`]: litebox::shim::ExceptionInfo
///
/// # Safety
///
/// Must be called with [`GUEST_OWNS_CPU`] genuinely true and `thread_state`/
/// `neon_state` genuinely describing the interrupted guest, and with `pc`
/// already confirmed outside every switch-code range, per the caller's own
/// checks.
pub(crate) unsafe fn prepare_interrupt_delivery(
    thread_state: &crate::darwin::ArmThreadState64,
    neon_state: &crate::darwin::ArmNeonState64,
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
    // No syscall is in flight at an interrupt either, same NO_SYSCALL
    // convention as prepare_exception_delivery.
    live.syscallno = -1;

    litebox_util_log::trace!(
        regs:? = &live.regs, sp:? = live.sp, pc:? = live.pc;
        "guest interrupt: captured register state"
    );

    // SAFETY: single-guest-thread invariant, as for HOST_SAVE/GUEST_FP/LIVE_PTREGS.
    let fp = unsafe { &mut *GUEST_FP.0.get() };
    fp.v = neon_state.v;
    fp.fpsr = u64::from(neon_state.fpsr);
    fp.fpcr = u64::from(neon_state.fpcr);

    GUEST_OWNS_CPU.store(false, Ordering::Relaxed);

    interrupt_callback as *const () as usize
}

/// Abandons an in-flight [`enter_guest_asm`] call for interrupt delivery
/// without capturing anything: called by `lib.rs`'s `interrupt_signal_handler`
/// only when [`interrupted_pc_is_in_guest_entry_restore`] says `pc` is inside
/// [`enter_guest_asm`]'s own restore range, where `*`[`LIVE_PTREGS`] has not
/// been consumed by anything yet and so is still exactly the context the
/// guest would have resumed with -- see that function's own doc comment for
/// why no register capture is needed or correct here (capturing the
/// in-progress `mcontext` instead would hand the shim a mix of already-
/// restored guest registers and this platform's own still-live host state,
/// including a `pc` inside this platform's own binary).
///
/// # Safety
///
/// Must be called with [`GUEST_OWNS_CPU`] genuinely true and `pc` already
/// confirmed inside [`enter_guest_asm`]'s restore range, per the caller's own
/// check.
pub(crate) unsafe fn abandon_guest_entry_for_interrupt() -> usize {
    GUEST_OWNS_CPU.store(false, Ordering::Relaxed);
    interrupt_callback as *const () as usize
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
        // Enter/resume the guest. Returns after a guest syscall, a genuine
        // guest hardware fault, or a genuine guest interrupt, with `*ctx`
        // holding the guest state captured by `syscall_callback`,
        // `prepare_exception_delivery`, `prepare_interrupt_delivery` or
        // `abandon_guest_entry_for_interrupt` respectively.
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
            GuestExit::Interrupt => shim.interrupt(ctx),
        };
        if op == ContinueOperation::Terminate {
            return;
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use core::cell::RefCell;
    use litebox::shim::{EnterShim, Exception, ExceptionInfo};

    /// Shared between a spawned guest thread and the test driving it: the
    /// guest thread's own `pthread_t`, filled in from `EnterShim::init`
    /// (reached before any guest instruction runs) and a `Condvar` the driver
    /// waits on for it. Used by every test below that sends a real
    /// cross-thread `SIGUSR2`.
    type ReadySignal = std::sync::Arc<(
        std::sync::Mutex<Option<libc::pthread_t>>,
        std::sync::Condvar,
    )>;
    /// The `(regs, pc)` an interrupted guest's `EnterShim::interrupt` was
    /// called with, shared the same way [`ReadySignal`] is.
    type DeliveredInterrupt = std::sync::Arc<std::sync::Mutex<Option<([usize; 31], usize)>>>;

    /// Only one guest thread may run at a time (see [`GUEST_ACTIVE`]), so the
    /// guest-entry tests must not run concurrently with each other under the
    /// parallel test harness. `pub(crate)` and reused by every test
    /// elsewhere in this crate that does real host `mmap`/`munmap`
    /// (`allocate_jit_pages_hint_honors_the_suggested_address` and
    /// `with_signal_alt_stack_actually_registers_one` in `lib.rs`) -- those
    /// mutate the same real address space guest-entry tests do, and would
    /// otherwise race it.
    pub(crate) static TEST_SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

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

    /// A shim that captures [`guest_fp_state`] the instant a fault is
    /// delivered -- the same accessor `lib.rs`'s `ThreadProvider::get_fp_state`
    /// exposes to the shim, so this is exactly what a real signal-frame build
    /// would see if it ran at this point.
    struct FpFaultShim {
        delivered: RefCell<Option<litebox::platform::FpSimdState64>>,
    }

    impl EnterShim for FpFaultShim {
        type ExecutionContext = PtRegs;
        fn init(&self, _ctx: &mut PtRegs) -> ContinueOperation {
            ContinueOperation::Resume
        }
        fn syscall(&self, _ctx: &mut PtRegs) -> ContinueOperation {
            ContinueOperation::Terminate
        }
        fn exception(&self, _ctx: &mut PtRegs, _info: &ExceptionInfo) -> ContinueOperation {
            *self.delivered.borrow_mut() = Some(guest_fp_state());
            ContinueOperation::Terminate
        }
        fn interrupt(&self, _ctx: &mut PtRegs) -> ContinueOperation {
            ContinueOperation::Terminate
        }
    }

    /// A guest that broadcasts three distinct sentinel patterns into `v0`
    /// (first vector register), `v15` (middle), and `v31` (last) -- so a
    /// capture that silently only covered a subrange of the file would still
    /// be caught -- then genuinely faults through a null-pointer load, exactly
    /// like [`faulting_guest`]. `dup Vd.2d, Xn` broadcasts one sentinel into
    /// *both* 64-bit lanes of a register, which is what lets the test's
    /// expected value stay agnostic to which lane the capture code treats as
    /// low/high: both lanes are identical, so there is only one possible
    /// 128-bit result regardless.
    #[unsafe(naked)]
    unsafe extern "C" fn fp_faulting_guest() {
        core::arch::naked_asm!(
            "movz x9, #0xBEEF",
            "movk x9, #0xCAFE, lsl #16",
            "movk x9, #0xF00D, lsl #32",
            "movk x9, #0xFACE, lsl #48",
            "dup  v0.2d, x9",
            "movz x9, #0x1111",
            "movk x9, #0x2222, lsl #16",
            "movk x9, #0x3333, lsl #32",
            "movk x9, #0x4444, lsl #48",
            "dup  v15.2d, x9",
            "movz x9, #0xAAAA",
            "movk x9, #0xBBBB, lsl #16",
            "movk x9, #0xCCCC, lsl #32",
            "movk x9, #0xDDDD, lsl #48",
            "dup  v31.2d, x9",
            "movz x4, #0",
            "ldr  x3, [x4]", // deliberate fault: load through a null pointer
            "brk  #0",       // unreachable
        )
    }

    /// The Darwin-specific half of the FP/SIMD signal-frame gap this module's
    /// doc comment used to describe as open: a delivered exception's vector
    /// state must be the guest's own real state *at the moment of the fault*,
    /// read from the kernel's own `mcontext` (`darwin::ArmNeonState64`), not
    /// whatever [`GUEST_FP`] happened to hold from the guest's last syscall.
    /// If [`prepare_exception_delivery`] ever again skipped refreshing
    /// [`GUEST_FP`] from `neon_state`, this test would still pass by
    /// accident only if the guest's last syscall (there is none here) had
    /// coincidentally left the same sentinels -- it does not, so a regression
    /// here is a hard failure, not a flake.
    #[test]
    fn captures_real_vector_register_state_from_the_darwin_mcontext_on_a_guest_fault() {
        let _serial = TEST_SERIAL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        crate::install_fault_handlers();
        let mut stack = vec![0u8; 1 << 16];
        let top = stack.as_mut_ptr() as usize + stack.len();
        let sp = (top - 256) & !15;

        let mut ctx = PtRegs {
            pc: fp_faulting_guest as *const () as usize,
            sp,
            ..Default::default()
        };
        let shim = FpFaultShim {
            delivered: RefCell::new(None),
        };
        run_thread(&shim, &mut ctx);

        let fp = shim
            .delivered
            .into_inner()
            .expect("EnterShim::exception was never invoked");

        let expect_broadcast = |sentinel: u128| sentinel | (sentinel << 64);
        assert_eq!(
            fp.v[0],
            expect_broadcast(0xFACE_F00D_CAFE_BEEF),
            "v0 (first register) must be the guest's real pre-fault state"
        );
        assert_eq!(
            fp.v[15],
            expect_broadcast(0x4444_3333_2222_1111),
            "v15 (middle register) must be the guest's real pre-fault state"
        );
        assert_eq!(
            fp.v[31],
            expect_broadcast(0xDDDD_CCCC_BBBB_AAAA),
            "v31 (last register) must be the guest's real pre-fault state"
        );
    }

    /// A shim that records the syscall a guest reaches, to check what
    /// [`sigreturn_trampoline`] hands off to the run loop.
    struct SigreturnRecordingShim {
        seen: RefCell<Option<(i32, usize)>>, // (syscallno, sp)
    }

    impl EnterShim for SigreturnRecordingShim {
        type ExecutionContext = PtRegs;
        fn init(&self, _ctx: &mut PtRegs) -> ContinueOperation {
            ContinueOperation::Resume
        }
        fn syscall(&self, ctx: &mut PtRegs) -> ContinueOperation {
            *self.seen.borrow_mut() = Some((ctx.syscallno, ctx.sp));
            ContinueOperation::Terminate
        }
        fn exception(&self, _ctx: &mut PtRegs, _info: &ExceptionInfo) -> ContinueOperation {
            ContinueOperation::Terminate
        }
        fn interrupt(&self, _ctx: &mut PtRegs) -> ContinueOperation {
            ContinueOperation::Terminate
        }
    }

    /// A guest that branches straight into [`sigreturn_trampoline`] -- exactly
    /// what a real guest signal handler installed *without* `SA_RESTORER`
    /// does when it `ret`s, since `litebox_shim_linux`'s `write_signal_frame`
    /// installs this trampoline's address as `x30` in that case. A plain `B`
    /// (not `BL`) matches `RET`'s semantics: no return address is pushed,
    /// `SP` is left completely untouched, which is exactly the property the
    /// test below checks.
    #[unsafe(naked)]
    unsafe extern "C" fn returns_via_sigreturn_trampoline_guest() {
        core::arch::naked_asm!(
            "b {tramp}",
            tramp = sym sigreturn_trampoline,
        )
    }

    /// The no-`SA_RESTORER` half of the signal-delivery gap this module's doc
    /// comment used to describe as open: macOS has no vDSO to fall back to,
    /// so [`sigreturn_trampoline`] is LiteBox's own replacement -- reached the
    /// same way a real guest's `ret` from a handler would reach it, and
    /// proven here to hand off to `sys_rt_sigreturn`'s dispatch (syscall 139)
    /// with the guest's real, untouched `sp` -- never a guest-memory read (see
    /// the trampoline's own doc comment for why none of its other registers
    /// need to be captured for this specific syscall to dispatch correctly).
    /// If this ever crashed the host process instead of reaching
    /// `EnterShim::syscall`, this test would take the whole process down with
    /// it, the same proof-by-survival property
    /// [`delivers_a_genuine_guest_fault_to_the_shim_without_leaking_host_state`]
    /// relies on.
    #[test]
    fn a_guest_signal_handler_without_sa_restorer_resumes_correctly_via_the_sigreturn_trampoline() {
        let _serial = TEST_SERIAL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut stack = vec![0u8; 1 << 16];
        let top = stack.as_mut_ptr() as usize + stack.len();
        let sp = (top - 256) & !15;

        let mut ctx = PtRegs {
            pc: returns_via_sigreturn_trampoline_guest as *const () as usize,
            sp,
            ..Default::default()
        };
        let shim = SigreturnRecordingShim {
            seen: RefCell::new(None),
        };
        run_thread(&shim, &mut ctx);

        let (syscallno, reported_sp) = shim
            .seen
            .into_inner()
            .expect("EnterShim::syscall was never invoked");
        assert_eq!(
            syscallno,
            AARCH64_RT_SIGRETURN.cast_signed(),
            "trampoline must dispatch rt_sigreturn regardless of the guest's x8"
        );
        assert_eq!(
            reported_sp, sp,
            "trampoline must report the guest's real sp, unmoved by the \
             trampoline itself (RET touches no memory and no SP)"
        );
    }

    /// Pure logic, no guest involved: the two PC-range checks
    /// `lib.rs`'s `interrupt_signal_handler` relies on must agree with the
    /// addresses the labels they read actually resolve to, and the two
    /// ranges must not bleed into each other.
    #[test]
    fn interrupted_pc_range_checks_agree_with_the_known_switch_code_addresses() {
        let entry_restore_start = switch_to_guest_start as *const () as usize;
        let exit_syscall_start = syscall_callback_start as *const () as usize;
        let exit_sigreturn_start = sigreturn_trampoline_start as *const () as usize;
        // A small integer address is never a real code address any of this
        // platform's binary occupies.
        let unrelated = 1usize;

        assert!(
            interrupted_pc_is_in_guest_entry_restore(entry_restore_start),
            "the labelled start of enter_guest_asm's own restore range must \
             read as inside it"
        );
        assert!(
            !interrupted_pc_is_in_guest_entry_restore(unrelated),
            "an address with nothing to do with guest entry must read as \
             outside the restore range"
        );
        assert!(
            interrupted_pc_is_in_guest_exit_prologue(exit_syscall_start),
            "syscall_callback's own start must read as inside the \
             exit-prologue range"
        );
        assert!(
            interrupted_pc_is_in_guest_exit_prologue(exit_sigreturn_start),
            "sigreturn_trampoline's own start must read as inside the \
             exit-prologue range"
        );
        assert!(
            !interrupted_pc_is_in_guest_exit_prologue(unrelated),
            "an address with nothing to do with either exit path must read \
             as outside the exit-prologue range"
        );
        assert!(
            !interrupted_pc_is_in_guest_entry_restore(exit_syscall_start),
            "the two ranges must not overlap: syscall_callback's start is not \
             inside enter_guest_asm's restore range"
        );
        assert!(
            !interrupted_pc_is_in_guest_exit_prologue(entry_restore_start),
            "the two ranges must not overlap: enter_guest_asm's restore start \
             is not inside syscall_callback's/sigreturn_trampoline's range"
        );
    }

    /// A shim that records a genuinely-delivered guest interrupt: the full
    /// captured register file and `pc` -- everything a naive "guest owns the
    /// CPU" check could instead fill with host state if it misattributed the
    /// moment `SIGUSR2` arrived, the same disclosure-class concern
    /// [`delivers_a_genuine_guest_fault_to_the_shim_without_leaking_host_state`]
    /// already established for the fault path. `ready` hands the real guest
    /// thread's `pthread_t` back to the test as soon as it is known (from
    /// [`EnterShim::init`], reached before any guest instruction runs), so the
    /// test can target the real interrupt-delivery mechanism
    /// (`libc::pthread_kill`) exactly as `ThreadProvider::interrupt_thread`
    /// does, rather than a substitute.
    struct InterruptRecordingShim {
        ready: ReadySignal,
        delivered: DeliveredInterrupt,
    }

    impl EnterShim for InterruptRecordingShim {
        type ExecutionContext = PtRegs;
        fn init(&self, _ctx: &mut PtRegs) -> ContinueOperation {
            // SAFETY: `pthread_self` has no preconditions.
            let self_id = unsafe { libc::pthread_self() };
            let (lock, cvar) = &*self.ready;
            *lock
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(self_id);
            cvar.notify_one();
            ContinueOperation::Resume
        }
        fn syscall(&self, ctx: &mut PtRegs) -> ContinueOperation {
            ctx.regs[0] = 0;
            ContinueOperation::Resume
        }
        fn exception(&self, _ctx: &mut PtRegs, _info: &ExceptionInfo) -> ContinueOperation {
            ContinueOperation::Terminate
        }
        fn interrupt(&self, ctx: &mut PtRegs) -> ContinueOperation {
            *self
                .delivered
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some((ctx.regs, ctx.pc));
            ContinueOperation::Terminate
        }
    }

    /// A guest that seeds sentinels into a caller-saved register (`x9`) and
    /// the link register (`x30`, singled out because a leaked host `x30` is
    /// exactly the return-to-host-code hazard this file exists to avoid,
    /// mirroring `faulting_guest`'s identical check for the fault path),
    /// reports it is about to start via a syscall, then spins in a large but
    /// bounded counting loop. Bounded, not infinite: a build that regressed
    /// interrupt delivery fails this test loudly (via the guest's own
    /// `exit(99)` below, observed as `EnterShim::interrupt` never firing)
    /// instead of hanging the whole suite.
    #[unsafe(naked)]
    unsafe extern "C" fn interrupt_spin_guest() {
        core::arch::naked_asm!(
            "movz x9,  #0xCAFE",
            "movz x30, #0xBEEF",
            // write(1, 0, 0): just a trip through the host so the test knows
            // (via EnterShim::init, already reached by this point) that the
            // guest thread exists, and (once this syscall itself completes)
            // that it is about to enter the spin loop below.
            "movz x8, #64",
            "movz x0, #1",
            "movz x1, #0",
            "movz x2, #0",
            "sub  sp, sp, #16",
            "str  x16, [sp]",
            "adrp x16, 70f@PAGE",
            "add  x16, x16, 70f@PAGEOFF",
            "str  x16, [sp, #8]",
            "adrp x16, {cb}@PAGE",
            "add  x16, x16, {cb}@PAGEOFF",
            "br   x16",
            "70:",
            // ~400 million iterations: comfortably longer (by roughly an
            // order of magnitude on this hardware) than the delay the test
            // waits after the syscall above before sending SIGUSR2, so the
            // signal lands squarely inside this loop (genuinely executing
            // guest code) rather than racing the syscall_callback exit-
            // prologue window this test does not target. Still finite.
            "movz x5, #0x8400",
            "movk x5, #0x17D7, lsl #16",
            "71:",
            "subs x5, x5, #1",
            "bne  71b",
            // Only reached if the interrupt was never delivered in time.
            "movz x8, #93",
            "movz x0, #99",
            "sub  sp, sp, #16",
            "str  x16, [sp]",
            "adrp x16, 72f@PAGE",
            "add  x16, x16, 72f@PAGEOFF",
            "str  x16, [sp, #8]",
            "adrp x16, {cb}@PAGE",
            "add  x16, x16, {cb}@PAGEOFF",
            "br   x16",
            "72:",
            "brk  #0",
            cb = sym syscall_callback,
        )
    }

    /// The end-to-end interrupt-routing path this row exists to implement: a
    /// genuine `SIGUSR2` delivered while the guest is truly executing (not
    /// mid-switch) must reach [`EnterShim::interrupt`] with the guest's own
    /// state, on real hardware, via the real `libc::pthread_kill` delivery
    /// mechanism -- not a substitute.
    #[test]
    fn delivers_a_genuine_guest_interrupt_to_the_shim_without_leaking_host_state() {
        let _serial = TEST_SERIAL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        crate::install_fault_handlers();
        crate::install_async_signal_handlers();
        // PENDING_INTERRUPT is process-global (same single-guest-thread
        // storage as GUEST_OWNS_CPU/LIVE_PTREGS/GUEST_FP -- see that flag's
        // own doc comment), so a stray SIGUSR2 left over from another test
        // that ran earlier in this same test binary (e.g. a hammer thread's
        // last, unavoidably-racy send in
        // `concurrent_sigusr2_delivery_does_not_corrupt_a_running_syscall_stream`,
        // landing on some *other* thread entirely) could otherwise make this
        // test's guest appear interrupted before it ever runs. `TEST_SERIAL`
        // (held for this whole test) rules out a *concurrent* leak; this
        // reset rules out a stale *prior* one.
        PENDING_INTERRUPT.store(false, Ordering::Relaxed);

        let ready = std::sync::Arc::new((std::sync::Mutex::new(None), std::sync::Condvar::new()));
        let delivered = std::sync::Arc::new(std::sync::Mutex::new(None));
        let shim = InterruptRecordingShim {
            ready: std::sync::Arc::clone(&ready),
            delivered: std::sync::Arc::clone(&delivered),
        };

        let mut stack = vec![0u8; 1 << 16];
        let top = stack.as_mut_ptr() as usize + stack.len();
        let sp = (top - 256) & !15;
        let mut ctx = PtRegs {
            pc: interrupt_spin_guest as *const () as usize,
            sp,
            ..Default::default()
        };

        let guest_thread = std::thread::Builder::new()
            .spawn(move || {
                // SAFETY: `ctx` describes a runnable guest context with >= 16
                // valid bytes below `sp`; `TEST_SERIAL` (held by the caller
                // for this whole test) enforces the single-guest-thread
                // invariant this crate's guest-entry state relies on.
                unsafe { crate::run_thread(shim, &mut ctx) };
            })
            .expect("failed to spawn the guest thread");

        let (lock, cvar) = &*ready;
        let guard = lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (guard, timeout) = cvar
            .wait_timeout_while(guard, std::time::Duration::from_secs(5), |id| id.is_none())
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert!(
            !timeout.timed_out(),
            "guest thread never reported ready within 5s"
        );
        let guest_tid = guard.expect("condition guarantees Some once not timed out");
        drop(guard);

        // Give the guest a generous head start into its spin loop -- orders
        // of magnitude past enter_guest_asm's own restore window (tens of
        // nanoseconds) and well short of the ~400M-iteration loop's own
        // duration, so the signal below lands in genuine guest execution.
        std::thread::sleep(std::time::Duration::from_millis(10));

        // SAFETY: `guest_tid` is the live guest thread's own id, captured
        // moments ago; it cannot have exited yet (its only exit path is the
        // ~100ms-away exit(99) fallback).
        let rc = unsafe { libc::pthread_kill(guest_tid, libc::SIGUSR2) };
        assert_eq!(rc, 0, "pthread_kill(SIGUSR2) failed with errno {rc}");

        guest_thread.join().expect("guest thread panicked");

        let (regs, pc) = delivered
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .expect(
                "EnterShim::interrupt was never invoked -- SIGUSR2 delivery \
                 regressed (the guest fell through to its own exit(99))",
            );

        assert_eq!(
            regs[9], 0xCAFE,
            "delivered x9 must be the guest's own sentinel, not host garbage"
        );
        assert_eq!(
            regs[30], 0xBEEF,
            "delivered x30 must be the guest's own sentinel, never a host \
             return address"
        );
        let spin_start = interrupt_spin_guest as *const () as usize;
        assert!(
            (spin_start..spin_start + 0x200).contains(&pc),
            "delivered pc ({pc:#x}) must be inside the guest's own spin loop \
             ({spin_start:#x}..), never a host address"
        );
    }

    /// A shim whose `syscall` handler synchronously self-signals with
    /// `SIGUSR2` the moment it observes the guest's first syscall (marker
    /// `0xAAAA` in `x1`) -- at that exact instant [`GUEST_OWNS_CPU`] genuinely
    /// reads false (ordinary Rust host code, well past `syscall_callback`'s
    /// own clear), so this deterministically exercises
    /// `interrupt_signal_handler`'s case 1 and [`PENDING_INTERRUPT`]'s
    /// re-check in [`enter_guest_asm`], rather than racing real concurrent
    /// timing the way
    /// [`delivers_a_genuine_guest_interrupt_to_the_shim_without_leaking_host_state`]
    /// does for the genuinely-executing case.
    struct PendingInterruptRecheckShim {
        syscall_markers: std::sync::Mutex<Vec<usize>>,
        interrupted_ctx: std::sync::Mutex<Option<(usize, usize, i32)>>,
    }

    impl EnterShim for PendingInterruptRecheckShim {
        type ExecutionContext = PtRegs;
        fn init(&self, _ctx: &mut PtRegs) -> ContinueOperation {
            ContinueOperation::Resume
        }
        fn syscall(&self, ctx: &mut PtRegs) -> ContinueOperation {
            self.syscall_markers
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(ctx.regs[1]);
            if ctx.regs[1] == 0xAAAA {
                // SAFETY: `raise` has no preconditions beyond a valid signal
                // number; `SIGUSR2` is not blocked on this thread outside
                // another handler's own execution (see
                // `darwin::install_handler`'s doc comment for the two
                // handlers this *is* masked against, neither of which is
                // running here), so this is delivered synchronously, before
                // `raise` returns, exactly as a real cross-thread
                // `pthread_kill` arriving in this same narrow window would be
                // -- this test just makes the race deterministic instead of
                // leaving it to timing.
                unsafe { libc::raise(libc::SIGUSR2) };
            }
            ctx.regs[0] = 0;
            ContinueOperation::Resume
        }
        fn exception(&self, _ctx: &mut PtRegs, _info: &ExceptionInfo) -> ContinueOperation {
            ContinueOperation::Terminate
        }
        fn interrupt(&self, ctx: &mut PtRegs) -> ContinueOperation {
            *self
                .interrupted_ctx
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) =
                Some((ctx.pc, ctx.sp, ctx.syscallno));
            ContinueOperation::Terminate
        }
    }

    /// A guest that makes one syscall (marker `0xAAAA`), then -- only if it
    /// ever genuinely resumes, which a correct [`PENDING_INTERRUPT`] re-check
    /// must prevent -- makes a second, distinctly-marked syscall (`0xBBBB`)
    /// so the test can detect and fail on that instead of silently
    /// mismatching.
    #[unsafe(naked)]
    unsafe extern "C" fn interrupt_pending_recheck_guest() {
        core::arch::naked_asm!(
            "movz x8, #64",
            "movz x0, #1",
            "movz x1, #0xAAAA",
            "movz x2, #0",
            "sub  sp, sp, #16",
            "str  x16, [sp]",
            "adrp x16, 73f@PAGE",
            "add  x16, x16, 73f@PAGEOFF",
            "str  x16, [sp, #8]",
            "adrp x16, {cb}@PAGE",
            "add  x16, x16, {cb}@PAGEOFF",
            "br   x16",
            "73:",
            "movz x8, #64",
            "movz x0, #1",
            "movz x1, #0xBBBB",
            "movz x2, #0",
            "sub  sp, sp, #16",
            "str  x16, [sp]",
            "adrp x16, 74f@PAGE",
            "add  x16, x16, 74f@PAGEOFF",
            "str  x16, [sp, #8]",
            "adrp x16, {cb}@PAGE",
            "add  x16, x16, {cb}@PAGEOFF",
            "br   x16",
            "74:",
            "brk  #0",
            cb = sym syscall_callback,
        )
    }

    /// Piece 4 of this row's design (see [`PENDING_INTERRUPT`]'s doc
    /// comment): an interrupt that cannot be redirected immediately (here,
    /// because it arrives while genuinely between guest entries) must not be
    /// silently dropped -- it has to be honored the next time
    /// [`enter_guest_asm`] is about to hand control back to the guest,
    /// *before* the guest executes another instruction. Deterministic (no
    /// real concurrency, no timing dependency): the self-signal in
    /// [`PendingInterruptRecheckShim::syscall`] is synchronous.
    #[test]
    fn an_interrupt_racing_a_fresh_guest_entry_is_honored_before_any_further_guest_instruction_runs()
     {
        let _serial = TEST_SERIAL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        crate::install_fault_handlers();
        crate::install_async_signal_handlers();
        // See the identical reset in
        // `delivers_a_genuine_guest_interrupt_to_the_shim_without_leaking_host_state`
        // for why this is needed even though this test's own signal is
        // synchronous and self-contained.
        PENDING_INTERRUPT.store(false, Ordering::Relaxed);

        let mut stack = vec![0u8; 1 << 16];
        let top = stack.as_mut_ptr() as usize + stack.len();
        let sp = (top - 256) & !15;
        let mut ctx = PtRegs {
            pc: interrupt_pending_recheck_guest as *const () as usize,
            sp,
            ..Default::default()
        };
        let shim = PendingInterruptRecheckShim {
            syscall_markers: std::sync::Mutex::new(Vec::new()),
            interrupted_ctx: std::sync::Mutex::new(None),
        };

        // `SIGUSR2` here is only ever `raise()`d synchronously from host Rust
        // code inside `PendingInterruptRecheckShim::syscall` (never async,
        // never while the host is on the guest's own stack), so this test
        // does not need `with_signal_alt_stack`/`crate::run_thread`'s full
        // wrapping the way the genuinely-concurrent test above does; the
        // module-local `run_thread` (taking `&dyn EnterShim`, not consuming
        // `shim`) lets this test read `shim`'s fields back afterward.
        run_thread(&shim, &mut ctx);

        let markers = shim
            .syscall_markers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert_eq!(
            *markers,
            vec![0xAAAA],
            "the guest must never reach its second syscall (0xBBBB) -- \
             PENDING_INTERRUPT must redirect to EnterShim::interrupt before \
             any guest instruction after the first syscall runs"
        );
        drop(markers);

        let (pc, interrupted_sp, syscallno) = shim
            .interrupted_ctx
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .expect("EnterShim::interrupt was never invoked");
        assert_eq!(
            pc, ctx.pc,
            "the interrupted ctx must be exactly what the first syscall's \
             handler left it as -- nothing captured or overwritten it"
        );
        assert_eq!(interrupted_sp, sp, "sp must be unchanged from the syscall");
        assert_eq!(
            syscallno, 64,
            "syscallno must still be the first syscall's own (write), not \
             clobbered by an aborted second entry"
        );
    }

    /// How many round trips [`interrupt_stress_guest`] makes; large enough to
    /// give a concurrent `SIGUSR2` hammer many thousands of chances to land
    /// inside every one of `enter_guest_asm`'s/`syscall_callback`'s/
    /// `sigreturn_trampoline`'s ownership-boundary windows over the life of
    /// one test run, small enough that the test still finishes quickly.
    const STRESS_ITERATIONS: u16 = 4000;

    /// A shim that records the full syscall trace and exit code of
    /// [`interrupt_stress_guest`], plus how many times
    /// [`EnterShim::interrupt`] actually fired -- shared via `Arc`/`Mutex`
    /// rather than the plain `RefCell`/`Cell` the rest of this module's shims
    /// use, because this one is moved into a spawned thread by
    /// [`crate::run_thread`] (which takes its shim by value and never hands
    /// it back) while the test still needs to read the results afterward.
    struct StressRecordingShim {
        ready: ReadySignal,
        seen: std::sync::Arc<std::sync::Mutex<Vec<usize>>>,
        exit_code: std::sync::Arc<std::sync::Mutex<Option<usize>>>,
        interrupts_seen: std::sync::Arc<std::sync::atomic::AtomicU32>,
    }

    impl EnterShim for StressRecordingShim {
        type ExecutionContext = PtRegs;
        fn init(&self, _ctx: &mut PtRegs) -> ContinueOperation {
            // SAFETY: `pthread_self` has no preconditions.
            let self_id = unsafe { libc::pthread_self() };
            let (lock, cvar) = &*self.ready;
            *lock
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(self_id);
            cvar.notify_one();
            ContinueOperation::Resume
        }
        fn syscall(&self, ctx: &mut PtRegs) -> ContinueOperation {
            if ctx.regs[8] == 93 {
                *self
                    .exit_code
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(ctx.regs[0]);
                return ContinueOperation::Terminate;
            }
            self.seen
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(ctx.regs[1]);
            ctx.regs[0] = 0;
            ContinueOperation::Resume
        }
        fn exception(&self, _ctx: &mut PtRegs, _info: &ExceptionInfo) -> ContinueOperation {
            // A real exception here would mean a fault got misattributed as
            // this guest's own -- it never touches memory beyond its own
            // stack slots -- so terminating (rather than trying to recover)
            // is deliberate: the test's assertions on `seen`/`exit_code`
            // catch the resulting desync.
            ContinueOperation::Terminate
        }
        fn interrupt(&self, _ctx: &mut PtRegs) -> ContinueOperation {
            self.interrupts_seen.fetch_add(1, Ordering::Relaxed);
            ContinueOperation::Resume
        }
    }

    /// A guest that performs [`STRESS_ITERATIONS`] syscalls in a tight loop,
    /// each carrying its own loop index in `x1` (so the test can verify the
    /// full sequence landed exactly once, in order), then exits with a
    /// distinctive code.
    #[unsafe(naked)]
    unsafe extern "C" fn interrupt_stress_guest() {
        core::arch::naked_asm!(
            "movz x19, #0", // loop counter -- callee-saved, survives each round trip
            "75:",
            "movz x8, #64",
            "movz x0, #1",
            "mov  x1, x19",
            "movz x2, #0",
            "sub  sp, sp, #16",
            "str  x16, [sp]",
            "adrp x16, 76f@PAGE",
            "add  x16, x16, 76f@PAGEOFF",
            "str  x16, [sp, #8]",
            "adrp x16, {cb}@PAGE",
            "add  x16, x16, {cb}@PAGEOFF",
            "br   x16",
            "76:",
            "add  x19, x19, #1",
            "cmp  x19, #{iters}",
            "bne  75b",
            "movz x8, #93",
            "movz x0, #55",
            "sub  sp, sp, #16",
            "str  x16, [sp]",
            "adrp x16, 77f@PAGE",
            "add  x16, x16, 77f@PAGEOFF",
            "str  x16, [sp, #8]",
            "adrp x16, {cb}@PAGE",
            "add  x16, x16, {cb}@PAGEOFF",
            "br   x16",
            "77:",
            "brk  #0",
            cb = sym syscall_callback,
            iters = const STRESS_ITERATIONS,
        )
    }

    /// Defense-in-depth, proof-by-survival (the same property
    /// [`delivers_a_genuine_guest_fault_to_the_shim_without_leaking_host_state`]
    /// relies on): a concurrent thread hammers real `SIGUSR2` at the guest
    /// thread throughout its whole run, landing at essentially random points
    /// across thousands of `enter_guest_asm`/`syscall_callback` round trips --
    /// including, over enough iterations, the narrow entry-restore and
    /// exit-prologue windows the two deterministic tests above exercise one
    /// at a time. A misattribution here would either desynchronize the
    /// asserted trace/exit-code below or crash the process outright; this
    /// test does not attempt to prove any *specific* interrupt landed in any
    /// *specific* window (unlike the two deterministic tests above), only
    /// that heavy, realistic concurrent pressure never corrupts the syscall
    /// stream.
    #[test]
    fn concurrent_sigusr2_delivery_does_not_corrupt_a_running_syscall_stream() {
        let _serial = TEST_SERIAL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        crate::install_fault_handlers();
        crate::install_async_signal_handlers();
        // See the identical reset in
        // `delivers_a_genuine_guest_interrupt_to_the_shim_without_leaking_host_state`.
        // This test's own hammer thread is also the one most likely to *leave
        // behind* a stray pending flag for a later test (its last send races
        // the guest's own exit with no way to fully close that window -- see
        // the cleanup after `hammer.join()` below), so it resets on the way
        // in too, defensively.
        PENDING_INTERRUPT.store(false, Ordering::Relaxed);

        let ready = std::sync::Arc::new((std::sync::Mutex::new(None), std::sync::Condvar::new()));
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let exit_code = std::sync::Arc::new(std::sync::Mutex::new(None));
        let interrupts_seen = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
        let shim = StressRecordingShim {
            ready: std::sync::Arc::clone(&ready),
            seen: std::sync::Arc::clone(&seen),
            exit_code: std::sync::Arc::clone(&exit_code),
            interrupts_seen: std::sync::Arc::clone(&interrupts_seen),
        };

        let mut stack = vec![0u8; 1 << 16];
        let top = stack.as_mut_ptr() as usize + stack.len();
        let sp = (top - 256) & !15;
        let mut ctx = PtRegs {
            pc: interrupt_stress_guest as *const () as usize,
            sp,
            ..Default::default()
        };

        let guest_thread = std::thread::Builder::new()
            .spawn(move || {
                // SAFETY: `ctx` describes a runnable guest context with >= 16
                // valid bytes below `sp`; `TEST_SERIAL` enforces the single-
                // guest-thread invariant for the duration of this test.
                unsafe { crate::run_thread(shim, &mut ctx) };
            })
            .expect("failed to spawn the guest thread");

        let (lock, cvar) = &*ready;
        let guard = lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (guard, timeout) = cvar
            .wait_timeout_while(guard, std::time::Duration::from_secs(5), |id| id.is_none())
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert!(
            !timeout.timed_out(),
            "guest thread never reported ready within 5s"
        );
        let guest_tid = guard.expect("condition guarantees Some once not timed out");
        drop(guard);

        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let hammer_stop = std::sync::Arc::clone(&stop);
        let hammer = std::thread::Builder::new()
            .spawn(move || {
                while !hammer_stop.load(Ordering::Relaxed) {
                    // SAFETY: `guest_tid` was captured from a live thread
                    // above and is only ever signalled while that thread (or
                    // its exit race, harmless for `pthread_kill`) is still
                    // within this test's scope.
                    unsafe { libc::pthread_kill(guest_tid, libc::SIGUSR2) };
                }
            })
            .expect("failed to spawn the hammer thread");

        guest_thread.join().expect("guest thread panicked");
        stop.store(true, Ordering::Relaxed);
        hammer.join().expect("hammer thread panicked");
        // The hammer thread's own last `pthread_kill` call races the guest
        // thread's exit with no way to fully close that window from here (it
        // may land after the guest thread has already exited, on whatever
        // unrelated thread the OS has since reused that `pthread_t` for) --
        // if that lands with GUEST_OWNS_CPU false (the only case it possibly
        // can, since TEST_SERIAL rules out a second concurrent guest), it
        // sets PENDING_INTERRUPT with nothing left in *this* test to consume
        // it. Reset it explicitly (this was found by a real failure of
        // `syscall_survives_a_guest_stack_with_only_16_valid_bytes_below_sp`,
        // running afterward with an empty trace, before this reset existed)
        // instead of leaving that residue for `TEST_SERIAL`'s release to
        // silently hand to whichever guest-entry test runs next.
        PENDING_INTERRUPT.store(false, Ordering::Relaxed);

        let seen = std::mem::take(
            &mut *seen
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
        let expected: Vec<usize> = (0..usize::from(STRESS_ITERATIONS)).collect();
        assert_eq!(
            seen, expected,
            "the full syscall trace must land exactly once, in order, \
             despite continuous concurrent SIGUSR2 pressure"
        );
        assert_eq!(
            *exit_code
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
            Some(55),
            "the guest must reach its own real exit, not a fault/misrouted \
             path"
        );
        // Not a strict correctness requirement -- resend timing is not
        // controlled -- but a run that never once actually reached
        // EnterShim::interrupt across this many round trips under continuous
        // hammering would mean this test is not exercising the path it
        // claims to; observed in practice to land in the thousands on this
        // hardware.
        assert!(
            interrupts_seen.load(Ordering::Relaxed) > 0,
            "expected at least one real interrupt delivery under continuous \
             concurrent SIGUSR2 pressure across {STRESS_ITERATIONS} round trips"
        );
    }
}
