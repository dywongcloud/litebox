// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! aarch64 signal-frame construction and teardown.
//!
//! The aarch64 frame differs from the x86-64 one in three ways that matter
//! here, all dictated by `arch/arm64/kernel/signal.c`:
//!
//! * `siginfo` comes *before* `ucontext` in `struct rt_sigframe`, and the frame
//!   sits exactly at `sp` -- there is no return address pushed below it, so
//!   `rt_sigreturn` reads the frame straight off `sp`.
//! * The trampoline is handed to the handler in `x30` rather than pushed, and a
//!   `frame_record` (a saved `x29`/`x30` pair) is written just above the frame
//!   so an unwinder can chain out of the handler.
//! * AAPCS64 has no red zone, so nothing below `sp` needs to be stepped over.

use crate::ShimPlatform;
use crate::UserPtrMut;
use crate::syscalls::signal::{DeliverFault, SignalState};
use core::mem::offset_of;
use litebox::shim::{Exception, ExceptionInfo};
use litebox::utils::{ReinterpretUnsignedExt as _, TruncateExt as _};
use litebox_common_linux::{
    AARCH64_GENERAL_REGISTER_COUNT, PtRegs,
    signal::{SaFlags, SigAction, SigSet, Siginfo, Signal, Ucontext, aarch64::Sigcontext},
};
use zerocopy::{FromBytes, IntoBytes};

/// `pt_regs::syscallno` value meaning "no syscall is in flight", matching the
/// kernel's `NO_SYSCALL`.
const NO_SYSCALL: i32 = -1;

/// The kernel's `struct rt_sigframe` for aarch64.
#[repr(C)]
#[derive(Clone, FromBytes, IntoBytes)]
struct SignalFrame {
    siginfo: Siginfo,
    ucontext: Ucontext,
}

/// The kernel's `struct frame_record`: the saved frame pointer and link
/// register an unwinder follows to step from the handler back into the
/// interrupted frame.
#[repr(C)]
#[derive(Clone, FromBytes, IntoBytes)]
struct FrameRecord {
    fp: usize,
    lr: usize,
}

/// The frame is placed at a 16-byte-aligned `sp` and the frame record sits
/// immediately above it, so the frame's own size has to preserve that
/// alignment. `sys_rt_sigreturn` rejects a misaligned `sp` outright.
const _: () = assert!(size_of::<SignalFrame>().is_multiple_of(16));
const _: () = assert!(size_of::<FrameRecord>().is_multiple_of(16));

/// State recorded for a thread that has taken no exception yet.
pub(super) const NO_EXCEPTION: ExceptionInfo = ExceptionInfo {
    exception: Exception(0),
    fault_address: 0,
    esr: 0,
    kernel_mode: false,
};

/// Maps an aarch64 exception class to the signal Linux raises for it, together
/// with the address reported in the accompanying `si_addr`.
pub(super) fn exception_signal(info: &ExceptionInfo) -> (Signal, usize) {
    let signal = match info.exception {
        // A `BRK` or a hardware breakpoint is a debug trap.
        Exception::BRK64 | Exception::BREAKPOINT_LOWER_EL | Exception::BREAKPOINT_CURRENT_EL => {
            Signal::SIGTRAP
        }
        // Class 0 is "unknown reason", which is what an undefined instruction
        // raises; the kernel's `do_el0_undef` turns it into SIGILL. A trapped
        // system-register access lands in the same place.
        Exception::UNKNOWN | Exception::SYSTEM_REGISTER_TRAP => Signal::SIGILL,
        Exception::FP_EXCEPTION_A64 => Signal::SIGFPE,
        // Aborts and anything unclassified become SIGSEGV, mirroring how the
        // x86-64 path treats page faults and unknown vectors. There may be a
        // more appropriate signal in some cases (e.g., SIGBUS for an alignment
        // fault), which needs the abort's fault-status code to distinguish.
        _ => Signal::SIGSEGV,
    };
    let fault_address = match info.exception {
        Exception::DATA_ABORT_LOWER_EL
        | Exception::DATA_ABORT_CURRENT_EL
        | Exception::INSTRUCTION_ABORT_LOWER_EL
        | Exception::INSTRUCTION_ABORT_CURRENT_EL => info.fault_address,
        _ => 0,
    };
    (signal, fault_address)
}

pub(super) fn uctx_addr(ctx: &PtRegs) -> usize {
    // `sp` points at the whole frame, whose first member is the `siginfo`.
    ctx.sp.wrapping_add(offset_of!(SignalFrame, ucontext))
}

pub(super) fn sp(ctx: &PtRegs) -> usize {
    ctx.sp
}

pub(super) fn get_signal_frame(sp: usize, _action: &SigAction) -> usize {
    // Reserve the frame record at the top, then the frame below it. Both sizes
    // are 16-byte multiples (asserted above), so a 16-aligned result stays
    // aligned all the way down.
    let next_frame = sp.wrapping_sub(size_of::<FrameRecord>()) & !15;
    next_frame.wrapping_sub(size_of::<SignalFrame>())
}

/// Address of the frame record belonging to the frame at `frame_addr`.
fn frame_record_addr(frame_addr: usize) -> usize {
    frame_addr.wrapping_add(size_of::<SignalFrame>())
}

impl<Platform: ShimPlatform> SignalState<Platform> {
    pub(super) fn write_signal_frame(
        &self,
        frame_addr: usize,
        siginfo: &Siginfo,
        action: &SigAction,
        ctx: &mut PtRegs,
    ) -> Result<(), DeliverFault> {
        // The kernel falls back to the vDSO's `sigtramp` when the guest supplies
        // no `sa_restorer` -- but LiteBox exposes no vDSO to the guest, so a
        // handler registered without a restorer has nowhere to return to.
        // Refusing delivery is better than entering the handler with a wild
        // `x30`, and it is what the x86-64 path already does.
        if !action.flags.contains(SaFlags::RESTORER) {
            return Err(DeliverFault);
        }

        let mut regs = [0u64; AARCH64_GENERAL_REGISTER_COUNT];
        for (slot, value) in regs.iter_mut().zip(ctx.regs.iter()) {
            *slot = *value as u64;
        }

        let last_exception = self.last_exception.get();
        let frame = SignalFrame {
            siginfo: siginfo.clone(),
            ucontext: Ucontext {
                flags: 0,
                link: 0, // core::ptr::null_mut()
                stack: self.altstack.get(),
                sigmask: self.blocked.get(),
                __unused: [0; 1024 / 8 - size_of::<SigSet>()],
                __align_pad: [0; 8],
                mcontext: Sigcontext {
                    fault_address: last_exception.fault_address as u64,
                    regs,
                    sp: ctx.sp as u64,
                    pc: ctx.pc as u64,
                    pstate: ctx.pstate,
                    __reserved_pad: [0; 8],
                    // The reserved area holds a chain of context records
                    // terminated by a zeroed header, so leaving it zeroed is a
                    // well-formed empty chain. FP/SIMD state is not yet saved
                    // or restored here (the same gap the x86-64 path has with
                    // `fpstate`).
                    __reserved: [0; 4096],
                },
            },
        };

        let frame_ptr = UserPtrMut::from_usize(frame_addr);
        frame_ptr
            .write_at_offset::<Platform>(0, frame)
            .ok_or(DeliverFault)?;

        let record_addr = frame_record_addr(frame_addr);
        let record_ptr = UserPtrMut::<FrameRecord>::from_usize(record_addr);
        record_ptr
            .write_at_offset::<Platform>(
                0,
                FrameRecord {
                    fp: ctx.regs[29],
                    lr: ctx.regs[30],
                },
            )
            .ok_or(DeliverFault)?;

        ctx.sp = frame_addr;
        ctx.pc = action.sigaction;
        ctx.regs[0] = siginfo.signo.reinterpret_as_unsigned() as usize;
        if action.flags.contains(SaFlags::SIGINFO) {
            ctx.regs[1] = frame_addr.wrapping_add(offset_of!(SignalFrame, siginfo));
            ctx.regs[2] = frame_addr.wrapping_add(offset_of!(SignalFrame, ucontext));
        }
        ctx.regs[29] = record_addr;
        ctx.regs[30] = action.restorer;
        Ok(())
    }
}

pub(super) fn restore_sigcontext(ctx: &mut PtRegs, sigctx: &Sigcontext) -> usize {
    let Sigcontext {
        fault_address: _,
        ref regs,
        sp,
        pc,
        pstate,
        __reserved_pad: _,
        // FP/SIMD state is not restored; see `write_signal_frame`.
        __reserved: _,
    } = *sigctx;

    for (slot, value) in ctx.regs.iter_mut().zip(regs.iter()) {
        *slot = (*value).trunc();
    }
    ctx.sp = sp.trunc();
    ctx.pc = pc.trunc();
    // Keep only the PSTATE bits a guest is allowed to own. Everything else --
    // exception level, execution state, mask bits, illegal-state, single-step --
    // is imposed by the ABI, which is what the kernel's `valid_user_regs` check
    // enforces on this path.
    ctx.pstate = pstate & litebox_common_linux::arch::SAFE_USER_PSTATE;
    // Returning from a handler leaves no syscall in flight, so no restart logic
    // should re-issue the interrupted call.
    ctx.syscallno = NO_SYSCALL;

    ctx.regs[0]
}
