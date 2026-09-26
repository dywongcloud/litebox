// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Wait state management.
//!
//! Use a dedicated module to prevent code from accidentally accessing
//! `wait_state` without going through `wait_cx()`.

use crate::{ShimFS, ShimPlatform, Task};
use core::cell::Cell;
use litebox::platform::Instant as _;
#[cfg(target_arch = "aarch64")]
use litebox::utils::ReinterpretUnsignedExt as _;
use litebox_common_linux::errno::Errno;

pub(crate) struct WaitState<Platform: ShimPlatform>(litebox::event::wait::WaitState<Platform>);

impl<Platform: ShimPlatform> WaitState<Platform> {
    pub(crate) fn new(platform: &'static Platform) -> Self {
        WaitState(litebox::event::wait::WaitState::new(platform))
    }

    /// Returns the thread handle used to interrupt waits.
    pub(crate) fn thread_handle(&self) -> litebox::event::wait::ThreadHandle<Platform> {
        self.0.thread_handle()
    }
}

impl<Platform: ShimPlatform, FS: ShimFS> Task<Platform, FS> {
    /// Returns a wait context to use to perform interruptible waits.
    pub(crate) fn wait_cx(&self) -> litebox::event::wait::WaitContext<'_, Platform> {
        self.wait_state.0.context().with_check_for_interrupt(self)
    }

    /// Marks that the task has just returned from running guest code.
    pub(crate) fn enter_from_guest(&self) {
        self.wait_state.0.finish_running_guest();
    }

    /// Prepares to return to run guest code. Returns `false` if the task should
    /// exit instead.
    #[must_use]
    pub(crate) fn prepare_to_run_guest(&self, ctx: &mut litebox_common_linux::PtRegs) -> bool {
        // The safe `ptrace` stop rendezvous: this is the one point every guest thread reaches,
        // after every syscall/exception/interrupt return and strictly before guest re-entry,
        // with its vCPU lane already released and `ctx` holding its complete, authoritative
        // logical register state -- see `syscalls::ptrace`'s module documentation. A no-op
        // (single atomic load) when untraced or not currently stop-requested; ahead of the fork
        // gate below so a tracer observing a stop never has to reason about a concurrent `fork`
        // interleaving with it.
        #[cfg(target_arch = "aarch64")]
        self.ptrace_rendezvous(ctx);
        // A sibling `fork` in flight must not see this thread touch guest
        // memory (see `Process::fork_gate`); park here, before re-entering
        // guest code, until the forker's turn completes. No-op single load
        // when no fork is in flight.
        self.park_while_fork_gate_closed();
        // A member of a shared address space whose turn another member is waiting for hands
        // it over here, before touching guest memory again (see `Task::quiesce_and_hand_off`).
        self.yield_address_space_to_waiters();
        self.wait_state.0.prepare_to_run_guest(|| {
            self.global.platform.take_pending_signals(|signal| {
                self.queue_signals(signal);
            });
            #[cfg(feature = "alarm_fallback")]
            self.check_alarm_deadline();
            self.process_signals(ctx);
            // After delivery: a delivered handler has taken the saved mask into its frame (and
            // runs under the temporary one), so this only fires when nothing was delivered.
            self.restore_saved_signal_mask();
            !self.is_exiting()
        })
    }
}

impl<Platform: ShimPlatform, FS: ShimFS> litebox::event::wait::CheckForInterrupt
    for Task<Platform, FS>
{
    fn check_for_interrupt(&self) -> bool {
        // See `Process::fork_gate`: a woken waiter passes through here before
        // re-blocking, which is what lets a forking sibling park a thread that
        // was asleep in a futex/epoll/read wait. Parking blocks on a raw
        // (non-interruptible) word, satisfying this hook's no-interruptible-
        // wait contract.
        self.park_while_fork_gate_closed();
        self.yield_address_space_to_waiters();
        self.global.platform.take_pending_signals(|sig| {
            self.queue_signals(sig);
        });
        #[cfg(feature = "alarm_fallback")]
        self.check_alarm_deadline();
        // A pending `PTRACE_ATTACH` stop request is as much a reason to stop waiting as an exit
        // or a pending signal: the request's CAS to `STOP_REQUESTED` happens before
        // `ThreadHandle::interrupt`'s kick (see `PtraceState::request_stop`), but that kick alone
        // only wakes this wait -- it does not change `ready`'s own condition, so without this
        // check the wait would just consume the kick and re-block on the same condition forever
        // instead of unwinding toward `Task::prepare_to_run_guest`'s rendezvous. See
        // `PtraceState::is_stop_requested`'s own doc comment.
        #[cfg(target_arch = "aarch64")]
        if self.thread_remote().ptrace.is_stop_requested() {
            return true;
        }
        self.is_exiting() || self.has_pending_signals()
    }

    /// Hands a shared guest address space to whichever other guest process wants it, for as long
    /// as this task is asleep.
    ///
    /// This is the hook that lets a `fork`ed child and its parent make progress in turn instead
    /// of the parent being suspended for the child's whole lifetime; see
    /// `syscalls::process::SharedAddressSpace`. It is a no-op -- a single predictable branch --
    /// for the overwhelmingly common case of a task that has never `fork`ed.
    fn yield_while_blocking(&self) {
        self.release_address_space();
    }

    fn resume_after_blocking(&self) {
        self.acquire_address_space();
    }
}

/// Linux's `TASK_KILLABLE` interrupt policy for a wait through the same [`WaitContext`] plumbing
/// as every other blocking wait: only this task exiting, or a pending signal that will terminate
/// it, ends the wait; a caught or ignored signal stays pending until the wait finishes on its
/// own. Nothing this task holds is yielded while it sleeps -- the vfork wait this exists for
/// guards memory its child is running on. `Task::cred_guard_lock` is the raw-word form of the
/// same policy.
pub(crate) struct KillableWait<'a, Platform: ShimPlatform, FS: ShimFS>(
    pub(crate) &'a Task<Platform, FS>,
);

impl<Platform: ShimPlatform, FS: ShimFS> litebox::event::wait::CheckForInterrupt
    for KillableWait<'_, Platform, FS>
{
    fn check_for_interrupt(&self) -> bool {
        self.0.global.platform.take_pending_signals(|sig| {
            self.0.queue_signals(sig);
        });
        #[cfg(feature = "alarm_fallback")]
        self.0.check_alarm_deadline();
        self.0.is_exiting() || self.0.pending_fatal_signal().is_some()
    }
}

impl<Platform: ShimPlatform, FS: ShimFS> Task<Platform, FS> {
    /// A wait context with [`KillableWait`]'s policy in place of this task's ordinary one.
    pub(crate) fn killable_wait_cx<'a>(
        &'a self,
        killable: &'a KillableWait<'a, Platform, FS>,
    ) -> litebox::event::wait::WaitContext<'a, Platform> {
        self.wait_state.0.context().with_check_for_interrupt(killable)
    }
}

/// Linux's restart classification of a blocking syscall whose wait was interrupted
/// (`WaitError::Interrupted`: a deliverable signal, an in-process ptrace stop request, or this
/// task exiting). The interrupted call site classifies itself and returns `EINTR` in the
/// meantime; the classification is decided on the way back to the guest, by
/// [`Task::process_signals`], against the first handler it delivers -- or the absence of one --
/// exactly as `arch/arm64/kernel/signal.c`'s `do_signal` decides it.
#[derive(Clone, Copy)]
#[cfg_attr(not(target_arch = "aarch64"), allow(dead_code))]
pub(crate) enum SyscallRestart<Instant> {
    /// `ERESTARTSYS`: restarts unless a handler without `SA_RESTART` runs.
    Sys,
    /// `ERESTARTNOHAND`: restarts only when no handler runs at all.
    NoHand,
    /// `ERESTART_RESTARTBLOCK`: as `NoHand`, but re-entered through `restart_syscall(2)` so the
    /// restarted relative-timeout wait ends at its original deadline, not a full timeout later.
    Block(Instant),
}

/// A restart `handle_syscall_request` has already rewound the guest to, awaiting
/// `process_signals`'s decision.
#[cfg(target_arch = "aarch64")]
#[derive(Clone, Copy)]
pub(crate) struct PreparedSyscallRestart<Instant> {
    kind: SyscallRestart<Instant>,
    /// The `svc` the rewind returned to. A tracer that moved the pc at the ptrace rendezvous in
    /// between takes precedence over any later revert, as in Linux.
    restart_pc: usize,
    syscall_number: usize,
}

/// Linux's `current->restart_block`: what the `restart_syscall(2)` the guest was pointed at
/// re-runs.
#[cfg(target_arch = "aarch64")]
#[derive(Clone, Copy)]
struct RestartBlock<Instant> {
    syscall_number: usize,
    deadline: Instant,
}

/// Per-task syscall-restart bookkeeping; see [`SyscallRestart`].
pub(crate) struct SyscallRestartState<Instant> {
    /// Classified by the interrupted call site; taken by `handle_syscall_request`.
    requested: Cell<Option<SyscallRestart<Instant>>>,
    /// Rewound by `handle_syscall_request`; settled by `process_signals`.
    #[cfg(target_arch = "aarch64")]
    prepared: Cell<Option<PreparedSyscallRestart<Instant>>>,
    /// Armed for the `restart_syscall(2)` the guest was pointed at.
    #[cfg(target_arch = "aarch64")]
    block: Cell<Option<RestartBlock<Instant>>>,
    /// The armed deadline, exposed to the wait being restarted for this one syscall entry.
    restarted_deadline: Cell<Option<Instant>>,
}

impl<Instant> Default for SyscallRestartState<Instant> {
    fn default() -> Self {
        Self {
            requested: Cell::new(None),
            #[cfg(target_arch = "aarch64")]
            prepared: Cell::new(None),
            #[cfg(target_arch = "aarch64")]
            block: Cell::new(None),
            restarted_deadline: Cell::new(None),
        }
    }
}

impl<Platform: ShimPlatform, FS: ShimFS> Task<Platform, FS> {
    /// Records `kind` for the syscall in flight and returns the `EINTR` its call site returns in
    /// the meantime. Only for a wait that just observed `WaitError::Interrupted`.
    pub(crate) fn interrupted_syscall(&self, kind: SyscallRestart<Platform::Instant>) -> Errno {
        self.syscall_restart.requested.set(Some(kind));
        Errno::EINTR
    }

    /// [`Self::interrupted_syscall`] for a result whose only `EINTR` source is its own wait's
    /// `WaitError::Interrupted`.
    pub(crate) fn restart_on_eintr<T>(
        &self,
        kind: SyscallRestart<Platform::Instant>,
        result: Result<T, Errno>,
    ) -> Result<T, Errno> {
        if matches!(result, Err(Errno::EINTR)) {
            self.interrupted_syscall(kind);
        }
        result
    }

    /// Withdraws a restart an inner wait requested: for a caller that turned that wait's `EINTR`
    /// into a partial success (the bytes already transferred are returned, never re-issued) or
    /// into a plain `EINTR` (Linux's "sticky" `poll_select_finish` fallback).
    pub(crate) fn cancel_syscall_restart(&self) {
        self.syscall_restart.requested.set(None);
    }

    /// The deadline of a relative-timeout wait: the one saved for the `restart_syscall(2)` being
    /// served, else `timeout` from now (`None`, meaning no deadline, on overflow).
    pub(crate) fn deadline_after(&self, timeout: core::time::Duration) -> Option<Platform::Instant> {
        self.syscall_restart
            .restarted_deadline
            .take()
            .or_else(|| self.global.platform.now().checked_add(timeout))
    }

    /// How long `deadline` is still away, zero once it has passed.
    pub(crate) fn time_until(&self, deadline: Platform::Instant) -> core::time::Duration {
        deadline
            .checked_duration_since(&self.global.platform.now())
            .unwrap_or(core::time::Duration::ZERO)
    }

    /// `do_syscall`'s `restart_syscall(2)`: the number of the syscall being restarted, with its
    /// saved deadline exposed to it through [`Self::deadline_after`]; `None` when nothing is
    /// armed (Linux's `do_no_restart_syscall`).
    #[cfg(target_arch = "aarch64")]
    pub(crate) fn enter_restart_syscall(&self) -> Option<usize> {
        let block = self.syscall_restart.block.take();
        litebox_util_log::debug!(
            pid:? = self.pid, tid:? = self.tid.get(),
            syscall:? = block.map(|block| block.syscall_number);
            "restart_syscall: resuming at the saved deadline"
        );
        let block = block?;
        self.syscall_restart
            .restarted_deadline
            .set(Some(block.deadline));
        Some(block.syscall_number)
    }

    /// Linux `do_signal`'s "prepare for system call restart", run by `handle_syscall_request` on
    /// every syscall exit: for a wait that classified itself, rewinds `ctx` to the `svc` (Linux's
    /// own arm64 idiom, `regs->regs[0] = regs->orig_x0; regs->pc -= 4;`) so that a handler frame
    /// built on the way out captures the restart, and leaves [`Self::settle_syscall_restart`] to
    /// revert it if the handler forbids it. Returns whether it rewound -- the syscall's return
    /// value is then not written.
    #[cfg(target_arch = "aarch64")]
    pub(crate) fn prepare_syscall_restart(&self, ctx: &mut litebox_common_linux::PtRegs) -> bool {
        self.syscall_restart.restarted_deadline.set(None);
        let Some(kind) = self.syscall_restart.requested.take() else {
            return false;
        };
        ctx.regs[0] = ctx.orig_x0;
        ctx.pc = ctx.pc.wrapping_sub(4);
        self.syscall_restart
            .prepared
            .set(Some(PreparedSyscallRestart {
                kind,
                restart_pc: ctx.pc,
                syscall_number: (ctx.syscallno as isize).reinterpret_as_unsigned(),
            }));
        true
    }

    /// No restart is ever applied outside aarch64 (the only architecture whose syscall entry
    /// this shim rewinds); an interrupted wait there keeps returning its `EINTR`.
    #[cfg(not(target_arch = "aarch64"))]
    pub(crate) fn prepare_syscall_restart(&self, _ctx: &mut litebox_common_linux::PtRegs) -> bool {
        self.syscall_restart.restarted_deadline.set(None);
        self.syscall_restart.requested.set(None);
        false
    }

    #[cfg(target_arch = "aarch64")]
    pub(crate) fn take_prepared_syscall_restart(
        &self,
    ) -> Option<PreparedSyscallRestart<Platform::Instant>> {
        self.syscall_restart.prepared.take()
    }

    /// Settles a prepared restart the way `do_signal` does once `get_signal` has answered:
    /// `handler` is the first handler this return to the guest delivers, `None` if it delivers
    /// none. `ERESTARTSYS` survives a handler only with `SA_RESTART`; `ERESTARTNOHAND` and
    /// `ERESTART_RESTARTBLOCK` never do (the guest then sees `EINTR` at the instruction after the
    /// `svc`, the frame capturing that), and the latter, when it does restart, points the guest's
    /// `x8` at `restart_syscall(2)` with its deadline armed (`setup_restart_syscall`).
    #[cfg(target_arch = "aarch64")]
    pub(crate) fn settle_syscall_restart(
        &self,
        ctx: &mut litebox_common_linux::PtRegs,
        prepared: PreparedSyscallRestart<Platform::Instant>,
        handler: Option<&litebox_common_linux::signal::SigAction>,
    ) {
        if ctx.pc != prepared.restart_pc {
            return;
        }
        let outcome = match handler {
            Some(action) => {
                let restarts = matches!(prepared.kind, SyscallRestart::Sys)
                    && action
                        .flags
                        .contains(litebox_common_linux::signal::SaFlags::RESTART);
                if restarts {
                    "restarts after the handler (SA_RESTART)"
                } else {
                    ctx.regs[0] = (Errno::EINTR.as_neg() as isize).reinterpret_as_unsigned();
                    ctx.pc = prepared.restart_pc.wrapping_add(4);
                    "EINTR after the handler"
                }
            }
            None => match prepared.kind {
                SyscallRestart::Block(deadline) => {
                    ctx.regs[8] = syscalls::Sysno::restart_syscall as usize;
                    self.syscall_restart.block.set(Some(RestartBlock {
                        syscall_number: prepared.syscall_number,
                        deadline,
                    }));
                    "restarts through restart_syscall at the saved deadline"
                }
                SyscallRestart::Sys | SyscallRestart::NoHand => "restarts, no handler ran",
            },
        };
        litebox_util_log::debug!(
            pid:? = self.pid, tid:? = self.tid.get(), syscall:? = prepared.syscall_number,
            outcome:% = outcome;
            "syscall restart"
        );
    }
}
