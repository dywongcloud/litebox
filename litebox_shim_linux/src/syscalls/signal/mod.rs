// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Signal handling syscalls and support.

#[cfg(target_arch = "aarch64")]
mod aarch64;
#[cfg(target_arch = "x86_64")]
mod x86_64;

#[cfg(target_arch = "aarch64")]
use aarch64 as arch;
use litebox_common_linux::signal::SignalDisposition;
#[cfg(target_arch = "x86_64")]
use x86_64 as arch;
use zerocopy::FromZeros;

use crate::syscalls::process::{ExitStatus, encode_sigchld_disposition};
use crate::wait::SyscallRestart;
use crate::{ShimFS, ShimPlatform, Task, UserPtr, UserPtrMut};
use alloc::collections::vec_deque::VecDeque;
use alloc::sync::Arc;
use core::cell::{Cell, RefCell};
use litebox::{sync::Mutex, utils::ReinterpretUnsignedExt as _};
use litebox_common_linux::signal::{
    MINSIGSTKSZ, NSIG, SEGV_ACCERR, SEGV_MAPERR, SI_KERNEL, SI_TKILL, SI_USER, SIG_DFL, SIG_IGN,
    SaFlags, SigAction, SigAltStack,
    SigSet, Siginfo, SiginfoData, SigmaskHow, Signal, SsFlags, Ucontext,
};
use litebox::event::wait::WaitError;
use litebox_common_linux::{PtRegs, errno::Errno};

pub(crate) struct SignalState<Platform: ShimPlatform> {
    /// Pending thread signals.
    pending: RefCell<PendingSignals>,
    /// Pending process signals (shared across all threads).
    shared_pending: Arc<Mutex<Platform, PendingSignals>>,
    /// Currently blocked signals.
    blocked: Cell<SigSet>,
    /// Signal handlers.
    handlers: RefCell<Arc<SignalHandlers<Platform>>>,
    /// Alternate signal stack.
    altstack: Cell<SigAltStack>,
    /// The last exception info recorded for signal delivery.
    last_exception: Cell<litebox::shim::ExceptionInfo>,
    /// The signal mask to put back once the signal that ended an `rt_sigsuspend` has been
    /// delivered.
    ///
    /// `rt_sigsuspend(2)` installs a temporary mask, blocks, and must run the handler that woke
    /// it *under that temporary mask* -- restoring the caller's mask any earlier would re-block
    /// the very signal the caller was waiting for, and the guest would spin calling
    /// `rt_sigsuspend` forever. Linux solves this with `saved_sigmask` plus
    /// `TIF_RESTORE_SIGMASK`; this is that saved mask, and
    /// [`Task::restore_saved_signal_mask`] is the restore, run once signals have been processed
    /// on the way back to guest code.
    saved_blocked: Cell<Option<SigSet>>,
    /// The set an in-progress `rt_sigtimedwait` is waiting for: Linux's `real_blocked`.
    ///
    /// While the wait lasts these signals count as deliverable for wakeup purposes even though
    /// they stay in `blocked` (so a `SIG_IGN`'d member is queued rather than discarded, exactly
    /// as `sig_ignored()` consults `real_blocked`), and the waiter dequeues them itself instead
    /// of `process_signals`. Empty outside such a wait.
    sigwait_set: Cell<SigSet>,
}

impl<Platform: ShimPlatform> SignalState<Platform> {
    pub fn new_process() -> Self {
        Self {
            pending: RefCell::new(PendingSignals::new()),
            shared_pending: Arc::new(Mutex::new(PendingSignals::new())),
            blocked: Cell::new(SigSet::empty()),
            handlers: RefCell::new(Arc::new(SignalHandlers::new())),
            altstack: Cell::new(SigAltStack {
                sp: 0,
                flags: SsFlags::DISABLE,
                size: 0,
                #[cfg(target_pointer_width = "64")]
                __pad: 0,
            }),
            last_exception: Cell::new(arch::NO_EXCEPTION),
            saved_blocked: Cell::new(None),
            sigwait_set: Cell::new(SigSet::empty()),
        }
    }

    pub fn clone_for_new_task(&self) -> Self {
        Self {
            // Reset pending
            pending: RefCell::new(PendingSignals::new()),
            // Share process-wide pending signals
            shared_pending: self.shared_pending.clone(),
            // Preserve blocked
            blocked: Cell::new(self.blocked.get()),
            // Share handlers across tasks
            handlers: self.handlers.clone(),
            // Clear altstack
            altstack: SigAltStack {
                flags: SsFlags::DISABLE,
                sp: 0,
                size: 0,
                #[cfg(target_pointer_width = "64")]
                __pad: 0,
            }
            .into(),
            // Preserve last exception
            last_exception: self.last_exception.clone(),
            saved_blocked: Cell::new(None),
            sigwait_set: Cell::new(SigSet::empty()),
        }
    }

    /// Returns the signal state a `fork`ed child starts with.
    ///
    /// Unlike [`Self::clone_for_new_task`], which models `CLONE_THREAD` and therefore keeps the
    /// process-wide parts shared, a new process gets private copies: its own pending queues (a
    /// child does not inherit pending signals) and its own handler table (so a later
    /// `rt_sigaction` in either process cannot be seen by the other). The blocked mask *is*
    /// inherited, as `fork(2)` specifies.
    pub fn clone_for_new_process(&self) -> Self {
        Self {
            pending: RefCell::new(PendingSignals::new()),
            shared_pending: Arc::new(Mutex::new(PendingSignals::new())),
            blocked: Cell::new(self.blocked.get()),
            handlers: RefCell::new(Arc::new((**self.handlers.borrow()).clone())),
            altstack: SigAltStack {
                flags: SsFlags::DISABLE,
                sp: 0,
                size: 0,
                #[cfg(target_pointer_width = "64")]
                __pad: 0,
            }
            .into(),
            last_exception: Cell::new(arch::NO_EXCEPTION),
            saved_blocked: Cell::new(None),
            sigwait_set: Cell::new(SigSet::empty()),
        }
    }

    /// Resets signal state for an `execve` call.
    pub(crate) fn reset_for_exec(&self) {
        let mut handlers = self.handlers.borrow_mut();
        // Ensure that the signal handlers are no longer shared.
        let handlers = Arc::make_mut(&mut handlers);
        // Reset the handlers to defaults.
        for handler in &mut handlers.inner.get_mut().handlers {
            handler.action = SigAction {
                sigaction: if handler.action.sigaction == SIG_IGN {
                    SIG_IGN
                } else {
                    SIG_DFL
                },
                restorer: 0,
                flags: SaFlags::empty(),
                mask: SigSet::empty(),
                #[cfg(target_pointer_width = "64")]
                __pad: 0,
            };
        }
        self.clear_sigaltstack();
    }

    /// This process's current `SIGCHLD` action -- `sigchld-ignored-autoreap`'s own read of the
    /// live disposition (see `crate::syscalls::process::encode_sigchld_disposition`). A plain,
    /// side-effect-free read, unlike `Task::sys_rt_sigaction`; safe to call any time no
    /// `reset_for_exec`/`sys_rt_sigaction` call on this same task is already mid-flight (both
    /// take `handlers` themselves, and `RefCell` forbids an overlapping borrow).
    pub(crate) fn sigchld_action(&self) -> SigAction {
        self.handlers.borrow().inner.lock()[Signal::SIGCHLD].action
    }
}

/// A handle for posting a process-directed signal to a *different* guest process.
///
/// The sending thread cannot touch the target's [`SignalState`] -- that is full of `Cell`s owned
/// by the target's own host thread -- but the process-wide pending queue behind it is an
/// ordinary `Arc<Mutex<..>>` and is safe to push into from anywhere. Whether the signal is
/// actually deliverable is decided by the target, on its own thread, in
/// [`Task::process_signals`] and [`Task::has_pending_signals`], because only it can read its live
/// handler table.
pub(crate) struct RemoteSignalTarget<Platform: ShimPlatform> {
    shared_pending: Arc<Mutex<Platform, PendingSignals>>,
}

impl<Platform: ShimPlatform> Clone for RemoteSignalTarget<Platform> {
    fn clone(&self) -> Self {
        Self {
            shared_pending: self.shared_pending.clone(),
        }
    }
}

impl<Platform: ShimPlatform> RemoteSignalTarget<Platform> {
    /// Queues a shim-generated `siginfo` on the target process.
    ///
    /// # Panics
    ///
    /// Panics unless `signal` is a standard (non-realtime) signal with a kernel-originated
    /// `si_code`. Those are the ones Linux exempts from `RLIMIT_SIGPENDING`
    /// (`__send_signal_locked`'s `override_rlimit`), and exempting them is what lets this bypass
    /// the target's rlimits -- which the sender cannot read anyway, since they live in the
    /// target's `Process`.
    pub(crate) fn post(&self, signal: Signal, siginfo: Siginfo) {
        assert!(!signal.is_rt_signal() && siginfo.code >= 0);
        self.shared_pending.lock().push_from_kernel(signal, siginfo);
    }

    pub(crate) fn post_from_user(
        &self,
        limits: &super::process::ResourceLimits,
        signal: Signal,
        siginfo: Siginfo,
    ) {
        self.shared_pending.lock().push(limits, signal, siginfo);
    }

    /// Follows a [`Self::post`]/[`Self::post_from_user`] of `signal` with Linux's
    /// `complete_signal`/`signal_wake_up`: wakes exactly one thread of the target that can take
    /// it (see `super::process::wake_one_eligible_thread`), never every thread.
    pub(crate) fn wake_one_eligible(
        &self,
        process_inner: &Mutex<Platform, super::process::ProcessInner<Platform>>,
        signal: Signal,
    ) {
        super::process::wake_one_eligible_thread(process_inner, &self.shared_pending, signal);
    }
}

struct SignalHandlers<Platform: ShimPlatform> {
    inner: Mutex<Platform, SignalHandlersInner>,
}

#[derive(Clone)]
struct SignalHandlersInner {
    handlers: [Handler; NSIG],
}

impl SignalHandlersInner {
    /// Returns the array index for the given signal.
    fn sig_index(signal: Signal) -> usize {
        (signal.as_i32().reinterpret_as_unsigned() - 1) as usize
    }
}

impl core::ops::Index<Signal> for SignalHandlersInner {
    type Output = Handler;

    fn index(&self, signal: Signal) -> &Self::Output {
        &self.handlers[Self::sig_index(signal)]
    }
}

impl core::ops::IndexMut<Signal> for SignalHandlersInner {
    fn index_mut(&mut self, signal: Signal) -> &mut Self::Output {
        &mut self.handlers[Self::sig_index(signal)]
    }
}

#[derive(Clone)]
struct Handler {
    action: SigAction,
    /// The user cannot change this action.
    immutable: bool,
}

impl<Platform: ShimPlatform> SignalHandlers<Platform> {
    fn new() -> Self {
        Self {
            inner: Mutex::new(SignalHandlersInner {
                handlers: core::array::from_fn(|i| Handler {
                    action: SigAction {
                        sigaction: SIG_DFL,
                        restorer: 0,
                        flags: SaFlags::empty(),
                        mask: SigSet::empty(),
                        #[cfg(target_pointer_width = "64")]
                        __pad: 0,
                    },
                    immutable: i == SignalHandlersInner::sig_index(Signal::SIGKILL)
                        || i == SignalHandlersInner::sig_index(Signal::SIGSTOP),
                }),
            }),
        }
    }
}

impl<Platform: ShimPlatform> Clone for SignalHandlers<Platform> {
    fn clone(&self) -> Self {
        Self {
            inner: Mutex::new(self.inner.lock().clone()),
        }
    }
}

pub(crate) struct PendingSignals {
    /// The set of pending signals.
    pending: SigSet,
    /// The queue of pending siginfo structures.
    queue: VecDeque<Siginfo>,
}

impl PendingSignals {
    pub(crate) fn new() -> Self {
        Self {
            pending: SigSet::empty(),
            queue: VecDeque::new(),
        }
    }

    pub(crate) fn is_pending(&self, signal: Signal) -> bool {
        self.pending.contains(signal)
    }

    pub(crate) fn pending_set(&self) -> SigSet {
        self.pending
    }

    /// Linux `dequeue_synchronous_signal` then `next_signal`: a synchronous signal (Linux's
    /// `SYNCHRONOUS_MASK`) queued with a positive `si_code` -- a hardware exception, or the
    /// `SYS_SECCOMP` `SIGSYS` a `SECCOMP_RET_TRAP` forces -- is dequeued first, in queue order,
    /// because it must be delivered against the user context of the instruction that raised
    /// it, ahead of any async signal; otherwise the lowest-numbered pending synchronous signal,
    /// then the lowest-numbered pending signal.
    fn next(&self, blocked: SigSet) -> Option<Signal> {
        const SYNCHRONOUS_SIGNALS: SigSet = SigSet::empty()
            .with(Signal::SIGSEGV)
            .with(Signal::SIGBUS)
            .with(Signal::SIGFPE)
            .with(Signal::SIGILL)
            .with(Signal::SIGTRAP)
            .with(Signal::SIGSYS);

        let pending = self.pending & !blocked;

        if !(pending & SYNCHRONOUS_SIGNALS).is_empty() {
            let synchronous = self.queue.iter().find_map(|info| {
                let signal = Signal::try_from(info.signo).ok()?;
                (info.code > SI_USER && (pending & SYNCHRONOUS_SIGNALS).contains(signal))
                    .then_some(signal)
            });
            if synchronous.is_some() {
                return synchronous;
            }
        }

        (pending & SYNCHRONOUS_SIGNALS)
            .lowest_set()
            .or_else(|| pending.lowest_set())
    }

    fn remove(&mut self, signal: Signal) -> Siginfo {
        // Find the entry.
        let pos = self
            .queue
            .iter()
            .position(|info| info.signo == signal.as_i32())
            .expect("removing non-pending signal");

        // If there are no more entries with this signal number, remove it from
        // the pending mask.
        let more = self
            .queue
            .iter()
            .skip(pos + 1)
            .any(|info| info.signo == signal.as_i32());
        if !more {
            self.pending.remove(signal);
        }

        self.queue.remove(pos).unwrap()
    }

    /// Queues a standard signal generated by the shim itself, with no `RLIMIT_SIGPENDING` check.
    ///
    /// Linux applies that limit only to signals a *user* queued (`si_code < 0`, e.g. `SI_QUEUE`)
    /// and to realtime signals; a kernel-generated `SIGCHLD` is never dropped for it. The
    /// standard-signal dedup below means at most one such entry can be outstanding anyway.
    fn push_from_kernel(&mut self, signal: Signal, siginfo: Siginfo) {
        assert_eq!(signal.as_i32(), siginfo.signo);
        assert!(!signal.is_rt_signal());
        if self.pending.contains(signal) {
            return;
        }
        self.queue.push_back(siginfo);
        self.pending.add(signal);
    }

    pub(crate) fn push(
        &mut self,
        rlimits: &super::process::ResourceLimits,
        signal: Signal,
        siginfo: Siginfo,
    ) {
        assert_eq!(signal.as_i32(), siginfo.signo);

        // Don't queue duplicates for standard signals.
        if !signal.is_rt_signal() && self.pending.contains(signal) {
            return;
        }

        // Restrict maximum queued signals via rlimits when Linux would do so
        // (`__send_signal_locked`'s `override_rlimit`: a standard signal with a non-negative,
        // kernel-originated `si_code` is never dropped for it; realtime and user-queued ones are).
        if signal.is_rt_signal() || siginfo.code < 0 {
            let limit = rlimits.get_rlimit_cur(litebox_common_linux::RlimitResource::SIGPENDING);
            if self.queue.len() >= limit {
                // Drop the signal.
                return;
            }
        }
        self.queue.push_back(siginfo);
        self.pending.add(signal);
    }

    /// Moves every entry queued here into `dest`, preserving standard-signal dedup (an entry
    /// whose signal is already pending in `dest` is dropped, matching `push`'s own dedup rule --
    /// this can only apply to standard signals, since `push`'s realtime-signal branch never
    /// hits `pending.contains` at all). Does not re-apply an `RLIMIT_SIGPENDING` check: the
    /// limit was already enforced when each entry was queued here.
    pub(crate) fn drain_into(&mut self, dest: &mut Self) {
        for siginfo in self.queue.drain(..) {
            let signal = Signal::try_from(siginfo.signo).expect("queued an invalid signal");
            if !signal.is_rt_signal() && dest.pending.contains(signal) {
                continue;
            }
            dest.queue.push_back(siginfo);
            dest.pending.add(signal);
        }
        self.pending = SigSet::empty();
    }
}

/// Returns whether `sp` is within the given signal stack.
fn is_on_stack(stack: &SigAltStack, sp: usize) -> bool {
    if stack.flags.contains(SsFlags::DISABLE) {
        return false;
    }
    let stack_start = stack.sp;
    let stack_end = stack.sp + stack.size;
    sp >= stack_start && sp < stack_end
}

/// Creates a `Siginfo` for an exception signal. `code` is `SI_KERNEL` for every
/// exception that is not itself an address-space custody question (`SIGBUS`,
/// `SIGILL`, ...); a `SIGSEGV` passes its real `SEGV_MAPERR`/`SEGV_ACCERR`
/// classification instead (see `arch::segv_code`).
fn siginfo_exception(signal: Signal, fault_address: usize, code: i32) -> Siginfo {
    Siginfo {
        signo: signal.as_i32(),
        errno: 0,
        code,
        #[cfg(target_pointer_width = "64")]
        __pad: 0,
        data: SiginfoData::new_addr(fault_address),
    }
}

/// Creates a `Siginfo` for a signal sent by a user process via `kill()`,
/// `tkill()`, or `tgkill()`.
pub(crate) fn siginfo_kill(signal: Signal) -> Siginfo {
    Siginfo {
        signo: signal.as_i32(),
        errno: 0,
        code: SI_USER,
        #[cfg(target_pointer_width = "64")]
        __pad: 0,
        data: SiginfoData::new_zeroed(),
    }
}

/// Creates the kernel-originated signal requested through `PR_SET_PDEATHSIG`.
pub(crate) fn siginfo_parent_death(signal: Signal) -> Siginfo {
    Siginfo {
        signo: signal.as_i32(),
        errno: 0,
        code: SI_KERNEL,
        #[cfg(target_pointer_width = "64")]
        __pad: 0,
        data: SiginfoData::new_zeroed(),
    }
}

/// Creates the `SIGCHLD` a parent gets when one of its children becomes a zombie, and the
/// `siginfo_t` a `waitid` call reaping (or peeking at) the same zombie fills in -- see
/// `Task::sys_waitid`, which shares this exact construction rather than duplicating it.
pub(crate) fn siginfo_child_exited(child: i32, status: ExitStatus, uid: u32) -> Siginfo {
    let (code, status) = match status {
        ExitStatus::Exit(code) => (
            litebox_common_linux::signal::CLD_EXITED,
            i32::from(code) & 0xff,
        ),
        ExitStatus::Signal(signal) => (litebox_common_linux::signal::CLD_KILLED, signal.as_i32()),
    };
    Siginfo {
        signo: Signal::SIGCHLD.as_i32(),
        errno: 0,
        code,
        #[cfg(target_pointer_width = "64")]
        __pad: 0,
        data: SiginfoData::new_child(child, uid, status),
    }
}

impl<Platform: ShimPlatform> SignalState<Platform> {
    /// Updates the blocked signal mask. Every caller outside [`Self::deliver_signal`] goes
    /// through `Task::set_signal_mask` instead, and `Task::process_signals` runs
    /// `Task::signal_mask_changed` after a delivery, so that a sender's view of this mask
    /// (`ThreadRemote::blocked`) and the wakeups that depend on it never go stale.
    fn set_signal_mask(&self, mask: SigSet) {
        self.blocked.set(mask);
    }

    /// The mask a process-directed signal is actually delivered against: `blocked`, less what an
    /// in-progress `rt_sigtimedwait` is waiting for (Linux's `real_blocked` carve-out).
    fn effective_blocked(&self) -> SigSet {
        self.blocked.get() & !self.sigwait_set.get()
    }

    /// Sets the alternate signal stack.
    fn set_sigaltstack(&self, ss: SigAltStack) -> Result<(), Errno> {
        if !ss
            .flags
            .difference(SsFlags::DISABLE | SsFlags::ONSTACK | SsFlags::AUTODISARM)
            .is_empty()
        {
            Err(Errno::EINVAL)
        } else if ss.flags.contains(SsFlags::DISABLE) {
            self.clear_sigaltstack();
            Ok(())
        } else if ss.sp.checked_add(ss.size).is_none() {
            Err(Errno::EINVAL)
        } else if ss.size < MINSIGSTKSZ {
            Err(Errno::ENOMEM)
        } else {
            self.altstack.set(SigAltStack {
                sp: ss.sp,
                flags: ss.flags & SsFlags::AUTODISARM,
                size: ss.size,
                #[cfg(target_pointer_width = "64")]
                __pad: 0,
            });
            Ok(())
        }
    }

    /// Clears the alternate signal stack.
    fn clear_sigaltstack(&self) {
        self.altstack.set(SigAltStack {
            sp: 0,
            flags: SsFlags::DISABLE,
            size: 0,
            #[cfg(target_pointer_width = "64")]
            __pad: 0,
        });
    }

    fn deliver_signal(
        &self,
        platform: &Platform,
        signal: Signal,
        siginfo: &Siginfo,
        action: &SigAction,
        ctx: &mut PtRegs,
        frame_sigmask: SigSet,
    ) -> Result<(), DeliverFault> {
        let sp = arch::sp(ctx);
        let on_alt_stack = is_on_stack(&self.altstack.get(), sp);
        let altstack = self.altstack.get();
        let switch_stacks = action.flags.contains(SaFlags::ONSTACK)
            && !on_alt_stack
            && !altstack.flags.contains(SsFlags::DISABLE);
        let sp = if switch_stacks {
            altstack.sp + altstack.size
        } else {
            sp
        };

        let frame_addr = arch::get_signal_frame(sp, action);

        if (switch_stacks || on_alt_stack) && !is_on_stack(&altstack, frame_addr) {
            return Err(DeliverFault);
        }

        self.write_signal_frame(platform, frame_addr, siginfo, action, ctx, frame_sigmask)?;

        let mut mask = self.blocked.get() | action.mask;
        if !action.flags.contains(SaFlags::NODEFER) {
            mask.add(signal);
        }
        self.set_signal_mask(mask);

        if altstack.flags.contains(SsFlags::AUTODISARM) {
            self.clear_sigaltstack();
        }
        Ok(())
    }
}

/// A fault when delivering a signal.
struct DeliverFault;

impl<Platform: ShimPlatform, FS: ShimFS> Task<Platform, FS> {
    /// Updates this thread's blocked set; see [`Self::signal_mask_changed`].
    fn set_signal_mask(&self, mask: SigSet) {
        let old = self.signals.effective_blocked();
        self.signals.set_signal_mask(mask);
        self.signal_mask_changed(old);
    }

    /// Publishes this thread's current effective mask for senders (see `ThreadRemote::blocked`)
    /// with no further bookkeeping: for a task whose queues are known to be empty (a `fork`
    /// child's leader, whose `ThreadRemote` was built before its inherited mask existed).
    pub(crate) fn publish_signal_mask(&self) {
        self.thread_remote()
            .publish_blocked_mask(self.signals.effective_blocked());
    }

    /// Linux's `__set_task_blocked` + `recalc_sigpending`, run after every change to this
    /// thread's effective blocked set (`old` is the previous one): publishes the new mask for
    /// senders, marks this thread `sigpending` if the change exposed a queued process-directed
    /// signal it previously blocked (so it dequeues it before returning to guest code, or the
    /// wait it is about to enter ends at once), and -- if this thread was itself marked to take
    /// signals it now blocks -- hands those off to a sibling (`retarget_shared_pending`).
    ///
    /// The publish happens under the `shared_pending` lock and the re-scan in the same critical
    /// section: a sender pushes and then reads the mask under that lock, so it either sees the
    /// new mask, or this re-scan sees its push -- there is no interleaving in which a signal is
    /// queued, aimed at this thread on a stale mask, and then blocked here with nobody marked.
    fn signal_mask_changed(&self, old: SigSet) {
        self.signal_mask_changed_with(old, false);
    }

    /// [`Self::signal_mask_changed`] for a caller that is itself mid-way through draining the
    /// shared queue with the mark already consumed (`process_signals`): `marked` says so.
    fn signal_mask_changed_with(&self, old: SigSet, marked: bool) {
        let new = self.signals.effective_blocked();
        let remote = self.thread_remote();
        let retarget = {
            let shared = self.signals.shared_pending.lock();
            remote.publish_blocked_mask(new);
            let pending = shared.pending_set();
            if !(pending & old & !new).is_empty() {
                remote.set_sigpending();
            }
            if marked || remote.has_sigpending() {
                pending & new & !old
            } else {
                SigSet::empty()
            }
        };
        if !retarget.is_empty() {
            self.retarget_shared_pending(retarget);
        }
    }

    /// Linux's `retarget_shared_pending`: for each of `which` still queued process-wide, wakes
    /// one sibling that can take it instead of this thread (which now blocks it, or is exiting).
    fn retarget_shared_pending(&self, which: SigSet) {
        let targets = self.process().signal_targets();
        let woken: alloc::vec::Vec<_> = {
            let shared = self.signals.shared_pending.lock();
            (shared.pending_set() & which)
                .into_iter()
                .filter_map(|signal| super::process::complete_signal(&targets, signal))
                .collect()
        };
        for thread in woken {
            thread.interrupt();
        }
    }

    /// Linux's `exit_signals`: a thread marked to take process-directed signals that exits
    /// before dequeuing them hands them to a sibling first. Called once `is_exiting` is visible.
    pub(crate) fn retarget_shared_pending_on_exit(&self) {
        if self.thread_remote().has_sigpending() {
            self.retarget_shared_pending(!self.signals.effective_blocked());
        }
    }

    /// This thread's read of the process-wide queue, gated on `ThreadRemote::sigpending` exactly
    /// as Linux's `signal_pending()` is on `TIF_SIGPENDING`: a thread nobody marked never sees a
    /// signal aimed at a sibling. Returns the deliverable subset not in `blocked`, leaving the
    /// mark set when there is one so [`Self::process_signals`] dequeues it; an unblocked signal
    /// whose disposition is to ignore it is discarded here instead (Linux never queues one --
    /// `sig_ignored` at send time -- but a sender in another process cannot see this handler
    /// table), never counting as pending and never keeping the mark set.
    fn consult_shared_pending(&self, blocked: SigSet) -> SigSet {
        let remote = self.thread_remote();
        if !remote.take_sigpending() {
            return SigSet::empty();
        }
        let unblocked = self.signals.shared_pending.lock().pending_set() & !blocked;
        if unblocked.is_empty() {
            return SigSet::empty();
        }
        let mut deliverable = SigSet::empty();
        let mut ignored = SigSet::empty();
        for signal in unblocked {
            if self.is_signal_ignored(signal) {
                ignored.add(signal);
            } else {
                deliverable.add(signal);
            }
        }
        if !ignored.is_empty() {
            let mut shared = self.signals.shared_pending.lock();
            for signal in ignored {
                while shared.is_pending(signal) {
                    shared.remove(signal);
                }
            }
        }
        if !deliverable.is_empty() {
            remote.set_sigpending();
        }
        deliverable
    }

    /// Runs `f` with the calling thread's blocked set temporarily replaced by `mask` (the
    /// `ppoll`/`pselect6`/`epoll_pwait` mask argument), restoring the caller's original mask
    /// afterward -- except when `is_interrupted` says `f`'s result means a signal is what ended
    /// the wait. In that case a signal that only becomes deliverable under the temporary mask
    /// still needs to see that mask in place when [`Task::process_signals`] looks for a handler
    /// to run; restoring synchronously here would re-block it first, so the restore is deferred
    /// into [`SignalState::saved_blocked`] instead (the same stash `sys_rt_sigsuspend` uses) and
    /// happens later, via [`Task::restore_saved_signal_mask`] on the generic return-to-guest path,
    /// *after* a handler frame has had the chance to be built under the still-temporary mask.
    /// Linux only defers the restore when a signal is genuinely what ended the wait -- fds
    /// becoming ready or a plain timeout restore synchronously, exactly as before.
    pub(crate) fn with_temporary_signal_mask<R>(
        &self,
        mask: SigSet,
        f: impl FnOnce() -> R,
        is_interrupted: impl FnOnce(&R) -> bool,
    ) -> R {
        let old = self.signals.blocked.get();
        self.set_signal_mask(mask);
        let result = f();
        if is_interrupted(&result) {
            if self.signals.saved_blocked.get().is_none() {
                self.signals.saved_blocked.set(Some(old));
            }
        } else {
            self.set_signal_mask(old);
        }
        result
    }

    pub(crate) fn sys_rt_sigprocmask(
        &self,
        how: SigmaskHow,
        set_ptr: Option<UserPtr<SigSet>>,
        oldset_ptr: Option<UserPtrMut<SigSet>>,
        sigsetsize: usize,
    ) -> Result<usize, Errno> {
        if sigsetsize != core::mem::size_of::<SigSet>() {
            return Err(Errno::EINVAL);
        }
        let set = if let Some(set_ptr) = set_ptr {
            Some(set_ptr.read_at_offset::<Platform>(0).ok_or(Errno::EFAULT)?)
        } else {
            None
        };

        if let Some(oldset_ptr) = oldset_ptr {
            let oldset = self.signals.blocked.get();
            oldset_ptr
                .write_at_offset::<Platform>(0, oldset)
                .ok_or(Errno::EFAULT)?;
        }

        if let Some(set) = set {
            let mut blocked = self.signals.blocked.get();
            match how {
                SigmaskHow::SIG_BLOCK => {
                    blocked = blocked | set;
                }
                SigmaskHow::SIG_UNBLOCK => {
                    blocked = blocked & !set;
                }
                SigmaskHow::SIG_SETMASK => {
                    blocked = set;
                }
            }
            self.set_signal_mask(blocked);
        }

        Ok(0)
    }

    /// Handle syscall `rt_sigsuspend`.
    ///
    /// Installs `mask_ptr` as the blocked set, blocks until a signal that is *not* in it becomes
    /// deliverable, and fails with `EINTR` once one is -- `rt_sigsuspend(2)` has no success
    /// return. A wait that ends with no handler run (`ERESTARTNOHAND`: an in-process ptrace stop,
    /// or a process-directed signal a sibling took first -- see `crate::wait::SyscallRestart`)
    /// instead restarts the syscall transparently: the guest never observes a return at all, and
    /// re-enters with the same `mask_ptr` once continued.
    ///
    /// The caller's original mask is not put back here. It is stashed in
    /// [`SignalState::saved_blocked`] and restored by [`Task::restore_saved_signal_mask`] after
    /// the return path has delivered the signal that ended the wait, so that the handler runs
    /// under the temporary mask exactly as Linux specifies. Restoring it here instead would
    /// re-block the awaited signal before its handler could observe it, which is precisely the
    /// livelock busybox's `ash` hits: its `waitproc` loops
    /// `while (!got_sigchld && !pending_sig) sigsuspend(&mask);`, and `got_sigchld` is only ever
    /// set by the `SIGCHLD` handler.
    pub(crate) fn sys_rt_sigsuspend(
        &self,
        mask_ptr: Option<UserPtr<SigSet>>,
        sigsetsize: usize,
    ) -> Result<usize, Errno> {
        if sigsetsize != core::mem::size_of::<SigSet>() {
            return Err(Errno::EINVAL);
        }
        let mask = mask_ptr
            .ok_or(Errno::EFAULT)?
            .read_at_offset::<Platform>(0)
            .ok_or(Errno::EFAULT)?;
        // `SIGKILL` and `SIGSTOP` cannot be blocked, here or anywhere else.
        let mask = {
            let mut mask = mask;
            mask.remove(Signal::SIGKILL);
            mask.remove(Signal::SIGSTOP);
            mask
        };

        let previous = self.signals.blocked.get();
        // A nested `rt_sigsuspend` (only reachable from a signal handler) must not lose the
        // outermost caller's mask, so keep the first one stashed.
        if self.signals.saved_blocked.get().is_none() {
            self.signals.saved_blocked.set(Some(previous));
        }
        self.set_signal_mask(mask);

        // A `SIGCHLD` posted by an exiting child in another host thread reaches this task's
        // pending set directly, but nothing would nudge *this* thread out of its wait. Registering
        // here is what turns a child's exit into a wakeup; it is the same list `wait4` uses.
        let table = &self.global.processes;
        let token = table.register_waiter(self.pid, self.wait_cx().waker().clone());
        let _unregister = litebox::utils::defer(|| table.unregister_waiter(token));

        // `wait_cx` interrupts on any deliverable signal, task teardown, or (aarch64) an
        // in-process ptrace stop request; the condition is never true on its own. No deadline is
        // ever set, so the only possible error is `Interrupted`.
        if let Err(WaitError::Interrupted) = self.wait_cx().wait_until(|| false) {
            return Err(self.interrupted_syscall(SyscallRestart::NoHand));
        }
        Err(Errno::EINTR)
    }

    /// Puts back the mask an `rt_sigsuspend` replaced, if one is still outstanding -- i.e. no
    /// handler was delivered meanwhile (Linux's `restore_saved_sigmask` on the no-signal path).
    ///
    /// Called from the return-to-guest path *after* `process_signals`: a delivery in there takes
    /// the saved mask into the handler frame instead, for `rt_sigreturn` to restore once the
    /// handler -- which runs under the temporary mask -- returns. See
    /// [`SignalState::saved_blocked`].
    pub(crate) fn restore_saved_signal_mask(&self) {
        if let Some(previous) = self.signals.saved_blocked.take() {
            self.set_signal_mask(previous);
        }
    }

    pub(crate) fn sys_sigaltstack(
        &self,
        ss_ptr: Option<UserPtr<SigAltStack>>,
        old_ss_ptr: Option<UserPtrMut<SigAltStack>>,
        ctx: &PtRegs,
    ) -> Result<usize, Errno> {
        let mut old_ss = self.signals.altstack.get();
        let is_on_stack = is_on_stack(&old_ss, arch::sp(ctx));
        if let Some(old_ss_ptr) = old_ss_ptr {
            if is_on_stack {
                old_ss.flags |= SsFlags::ONSTACK;
            }
            old_ss_ptr
                .write_at_offset::<Platform>(0, old_ss)
                .ok_or(Errno::EFAULT)?;
        }
        if let Some(ss_ptr) = ss_ptr {
            if is_on_stack {
                return Err(Errno::EPERM);
            }
            let ss = ss_ptr.read_at_offset::<Platform>(0).ok_or(Errno::EFAULT)?;
            self.signals.set_sigaltstack(ss)?;
        }
        Ok(0)
    }

    pub(crate) fn sys_rt_sigreturn(&self, ctx: &mut PtRegs) -> Result<usize, Errno> {
        let uctx_addr = arch::uctx_addr(ctx);
        let uctx_ptr = UserPtr::<Ucontext>::from_usize(uctx_addr);
        let Some(uctx) = uctx_ptr.read_at_offset::<Platform>(0) else {
            self.force_signal(Signal::SIGSEGV, false);
            return Err(Errno::EFAULT);
        };

        // Restore the alternate signal stack, ignoring errors.
        self.signals.set_sigaltstack(uctx.stack).ok();

        self.set_signal_mask(uctx.sigmask);

        Ok(arch::restore_sigcontext(
            self.global.platform,
            ctx,
            &uctx.mcontext,
        ))
    }

    pub(crate) fn sys_rt_sigaction(
        &self,
        signal: Signal,
        act_ptr: Option<UserPtr<SigAction>>,
        oldact_ptr: Option<UserPtrMut<SigAction>>,
        sigsetsize: usize,
    ) -> Result<usize, Errno> {
        if signal == Signal::SIGKILL || signal == Signal::SIGSTOP {
            return Err(Errno::EINVAL);
        }
        if sigsetsize != core::mem::size_of::<SigSet>() {
            return Err(Errno::EINVAL);
        }
        let act = if let Some(act_ptr) = act_ptr {
            Some(act_ptr.read_at_offset::<Platform>(0).ok_or(Errno::EFAULT)?)
        } else {
            None
        };

        let handlers = self.signals.handlers.borrow();
        let old_act = {
            let mut inner = handlers.inner.lock();
            let handler = &mut inner[signal];
            if handler.immutable {
                return Err(Errno::EINVAL);
            }
            let old_act = handler.action;
            if let Some(act) = act {
                handler.action = act;
            }
            old_act
        };

        if let Some(oldact_ptr) = oldact_ptr {
            oldact_ptr
                .write_at_offset::<Platform>(0, old_act)
                .ok_or(Errno::EFAULT)?;
        }

        // `sigchld-ignored-autoreap`: republish the process-wide auto-reap disposition whenever
        // this call actually installed a new `SIGCHLD` action (a bare query -- `act_ptr` null --
        // changes nothing).
        if signal == Signal::SIGCHLD && act.is_some() {
            self.process()
                .set_sigchld_disposition(encode_sigchld_disposition(self.signals.sigchld_action()));
        }

        Ok(0)
    }

    /// Handle syscall `kill`, with Linux's reading of `pid`: `> 0` names one process, `0` the
    /// caller's process group, `-1` every process but the caller (and init), and `< -1` the
    /// process group `-pid`. A group or broadcast target reports `ESRCH` only when nothing at all
    /// matched.
    pub(crate) fn sys_kill(&self, pid: i32, signal: i32) -> Result<usize, Errno> {
        // Diagnostic only (no behavior change): caller->target attribution at the syscall
        // entry point, for correlating with `process.rs`'s "fatal signal: terminating task" /
        // "process lifecycle: tracked role exit observed" lines, which log only the victim's
        // own pid at its own death time and say nothing about who sent the signal.
        litebox_util_log::debug!(
            caller_pid:% = self.pid, caller_tid:% = self.tid.get(),
            target_pid:% = pid, signal:% = signal;
            "signal syscall entry: kill"
        );
        let processes = &self.global.processes;
        let own_group = self.process().process_group_id();
        // A positive pid or pgid names its target in the CALLER's own pid-namespace view (Linux's
        // `find_vpid`), and `-1`'s broadcast reaches only what that view can see, minus that
        // view's own init -- unchanged for a root-namespace caller, whose view is the real one.
        // `pid` is `i32::MIN` only for a group nothing can be in.
        let target_group = (pid < -1)
            .then(|| pid.checked_neg())
            .flatten()
            .and_then(|group| self.global_pid_from_current_ns(group));
        let target_pid = (pid > 0)
            .then(|| self.global_pid_from_current_ns(pid))
            .flatten();
        let visible_non_init = |candidate: i32| self.translate_pid_for_current_ns(candidate) > 1;
        if signal == 0 {
            let exists = match pid {
                0 => true,
                -1 => processes.has_other_live_process(self.pid, visible_non_init),
                pid if pid < -1 => target_group.is_some_and(|group| {
                    own_group == group
                        || processes.has_process_group_member(group, self.pid)
                        || processes.has_zombie_process_group_member(group)
                }),
                _ => target_pid.is_some_and(|pid| {
                    pid == self.pid || processes.is_live(pid) || processes.is_zombie(pid)
                }),
            };
            return exists.then_some(0).ok_or(Errno::ESRCH);
        }
        let signal = Signal::try_from(signal)?;
        let delivered = match pid {
            0 => {
                self.send_shared_signal(signal, siginfo_kill(signal));
                processes.send_process_group_signal(
                    own_group,
                    self.pid,
                    signal,
                    siginfo_kill(signal),
                ) + 1
            }
            -1 => processes.send_signal_to_all_processes(
                self.pid,
                signal,
                siginfo_kill(signal),
                visible_non_init,
            ),
            pid if pid < -1 => {
                let Some(group) = target_group else {
                    return Err(Errno::ESRCH);
                };
                let mut delivered = processes.send_process_group_signal(
                    group,
                    self.pid,
                    signal,
                    siginfo_kill(signal),
                );
                if own_group == group {
                    self.send_shared_signal(signal, siginfo_kill(signal));
                    delivered += 1;
                }
                if delivered == 0 && processes.has_zombie_process_group_member(group) {
                    delivered = 1;
                }
                delivered
            }
            _ => {
                let Some(pid) = target_pid else {
                    return Err(Errno::ESRCH);
                };
                if pid == self.pid {
                    return self.do_kill(Some(pid), None, signal.as_i32());
                }
                usize::from(
                    processes.send_process_signal(pid, signal, siginfo_kill(signal))
                        || processes.is_zombie(pid),
                )
            }
        };
        (delivered > 0).then_some(0).ok_or(Errno::ESRCH)
    }

    pub(crate) fn sys_tkill(&self, tid: i32, signal: i32) -> Result<usize, Errno> {
        // Diagnostic only (no behavior change): see `sys_kill`'s matching comment.
        litebox_util_log::debug!(
            caller_pid:% = self.pid, caller_tid:% = self.tid.get(),
            target_tid:% = tid, signal:% = signal;
            "signal syscall entry: tkill"
        );
        self.do_kill(None, Some(tid), signal)
    }

    /// `pid` (the thread group) is named in the caller's own pid-namespace view, like `kill`'s;
    /// `tid` is a raw thread id, which this shim never namespaces (see `Task::sys_gettid`).
    pub(crate) fn sys_tgkill(&self, pid: i32, tid: i32, signal: i32) -> Result<usize, Errno> {
        // Diagnostic only (no behavior change): see `sys_kill`'s matching comment. Logged
        // before the pid-namespace translation below so it always fires, even for a `pid`
        // that resolves to nothing (`ESRCH`).
        litebox_util_log::debug!(
            caller_pid:% = self.pid, caller_tid:% = self.tid.get(),
            target_pid:% = pid, target_tid:% = tid, signal:% = signal;
            "signal syscall entry: tgkill"
        );
        let Some(pid) = self.global_pid_from_current_ns(pid) else {
            return Err(Errno::ESRCH);
        };
        self.do_kill(Some(pid), Some(tid), signal)
    }

    /// Handle syscall `rt_sigtimedwait`.
    ///
    /// Linux's `do_sigtimedwait`: dequeue a pending signal in `set` (thread-directed first, then
    /// process-directed; the caller's block mask is irrelevant to the dequeue), and if none is
    /// pending and `timeout` allows, sleep with `set` treated as unblocked until one arrives
    /// (`EAGAIN` when the timeout runs out first, `EINTR` when a signal outside `set` wakes the
    /// sleep instead). `SIGKILL`/`SIGSTOP` cannot be waited for. On success the signal number
    /// is returned and its `siginfo` is copied out to `info`.
    pub(crate) fn sys_rt_sigtimedwait(
        &self,
        set: Option<UserPtr<SigSet>>,
        info: Option<UserPtrMut<Siginfo>>,
        timeout: litebox_common_linux::TimeParam,
        sigsetsize: usize,
    ) -> Result<usize, Errno> {
        if sigsetsize != core::mem::size_of::<SigSet>() {
            return Err(Errno::EINVAL);
        }
        let mut which = set
            .ok_or(Errno::EFAULT)?
            .read_at_offset::<Platform>(0)
            .ok_or(Errno::EFAULT)?;
        which.remove(Signal::SIGKILL);
        which.remove(Signal::SIGSTOP);
        // Read the timeout up front: a bad pointer is `EFAULT` even when a signal is ready.
        let timeout = timeout.read::<Platform>()?;
        let wait_allowed = match timeout {
            None => true,
            Some(t) => !t.is_zero(),
        };
        let deadline = timeout.and_then(|t| self.deadline_after(t));

        if let Some((signal, siginfo)) = self.dequeue_signal_in(which) {
            self.copy_siginfo_out(info, &siginfo)?;
            return Ok(signal.as_i32().cast_unsigned() as usize);
        }
        if !wait_allowed {
            return Err(Errno::EAGAIN);
        }

        // Sleep with `which` acting as unblocked (see `SignalState::sigwait_set`): the arrival
        // of any member interrupts the wait through `check_for_interrupt`, as does any other
        // deliverable signal or task teardown. Both edges are effective-mask changes a sender
        // must see (Linux temporarily narrows `blocked` itself here).
        let old = self.signals.effective_blocked();
        self.signals.sigwait_set.set(which);
        self.signal_mask_changed(old);
        let _restore = litebox::utils::defer(|| {
            let old = self.signals.effective_blocked();
            self.signals.sigwait_set.set(SigSet::empty());
            self.signal_mask_changed(old);
        });
        let outcome = self.wait_cx().with_deadline(deadline).sleep();
        if let Some((signal, siginfo)) = self.dequeue_signal_in(which) {
            self.copy_siginfo_out(info, &siginfo)?;
            return Ok(signal.as_i32().cast_unsigned() as usize);
        }
        match outcome {
            WaitError::TimedOut => Err(Errno::EAGAIN),
            // A wake that ran no handler resumes the wait -- timed, for what is left of it.
            // (Linux's own `do_sigtimedwait` answers every such wake with a plain `EINTR`; a
            // guest cannot tell this superset apart from the signal simply not having arrived.)
            WaitError::Interrupted => Err(self.interrupted_syscall(match deadline {
                Some(deadline) => SyscallRestart::Block(deadline),
                None => SyscallRestart::NoHand,
            })),
        }
    }

    /// Dequeues the first pending signal that is a member of `which`, thread-directed queue
    /// first (a remote `tkill` is drained in), then the process-wide queue -- the order
    /// `process_signals` uses. Ignores the block mask, like Linux's `dequeue_signal` with the
    /// caller's mask.
    fn dequeue_signal_in(&self, which: SigSet) -> Option<(Signal, Siginfo)> {
        self.thread_remote()
            .drain_remote_signals_into(&mut self.signals.pending.borrow_mut());
        let not_wanted = !which;
        {
            let mut pending = self.signals.pending.borrow_mut();
            if let Some(signal) = pending.next(not_wanted) {
                let siginfo = pending.remove(signal);
                return Some((signal, siginfo));
            }
        }
        let mut shared = self.signals.shared_pending.lock();
        let signal = shared.next(not_wanted)?;
        let siginfo = shared.remove(signal);
        Some((signal, siginfo))
    }

    fn copy_siginfo_out(
        &self,
        info: Option<UserPtrMut<Siginfo>>,
        siginfo: &Siginfo,
    ) -> Result<(), Errno> {
        if let Some(info) = info {
            info.write_at_offset::<Platform>(0, siginfo.clone())
                .ok_or(Errno::EFAULT)?;
        }
        Ok(())
    }

    /// Reads and validates the caller-supplied `siginfo` of `rt_sigqueueinfo`/
    /// `rt_tgsigqueueinfo`: `si_signo` is forced to `sig`, and a kernel-looking `si_code`
    /// (`>= 0`, or `SI_TKILL`) may only be sent to one's own process (`EPERM`), as Linux's
    /// `do_rt_sigqueueinfo` checks.
    fn read_queued_siginfo(
        &self,
        info: Option<UserPtr<Siginfo>>,
        sig: i32,
        target_pid: i32,
    ) -> Result<Siginfo, Errno> {
        let mut siginfo = info
            .ok_or(Errno::EFAULT)?
            .read_at_offset::<Platform>(0)
            .ok_or(Errno::EFAULT)?;
        if (siginfo.code >= 0 || siginfo.code == SI_TKILL) && target_pid != self.pid {
            return Err(Errno::EPERM);
        }
        siginfo.signo = sig;
        Ok(siginfo)
    }

    /// Handle syscall `rt_sigqueueinfo`: `kill(pid, sig)` carrying the caller's `siginfo`.
    pub(crate) fn sys_rt_sigqueueinfo(
        &self,
        pid: i32,
        sig: i32,
        info: Option<UserPtr<Siginfo>>,
    ) -> Result<usize, Errno> {
        // `pid > 0` names its target in the caller's own pid-namespace view, exactly as `kill`'s.
        let target = if pid > 0 {
            self.global_pid_from_current_ns(pid)
        } else {
            Some(pid)
        };
        let siginfo = self.read_queued_siginfo(info, sig, target.unwrap_or(-1))?;
        if sig == 0 {
            // Existence/permission probe only, exactly as `kill(pid, 0)`.
            return self.sys_kill(pid, 0);
        }
        let signal = Signal::try_from(sig)?;
        let Some(pid) = target else {
            return Err(Errno::ESRCH);
        };
        if pid == self.pid {
            self.send_shared_signal(signal, siginfo);
            return Ok(0);
        }
        if pid <= 0 {
            log_unsupported!("rt_sigqueueinfo to a process group");
            return Err(Errno::EPERM);
        }
        let processes = &self.global.processes;
        (processes.send_process_signal(pid, signal, siginfo) || processes.is_zombie(pid))
            .then_some(0)
            .ok_or(Errno::ESRCH)
    }

    /// Handle syscall `rt_tgsigqueueinfo`: `tgkill(tgid, tid, sig)` carrying the caller's
    /// `siginfo` -- how crashpad's handler re-raises a crash signal with its original
    /// `siginfo` intact.
    pub(crate) fn sys_rt_tgsigqueueinfo(
        &self,
        tgid: i32,
        tid: i32,
        sig: i32,
        info: Option<UserPtr<Siginfo>>,
    ) -> Result<usize, Errno> {
        if tgid <= 0 || tid <= 0 {
            return Err(Errno::EINVAL);
        }
        // `tgid` is named in the caller's own pid-namespace view, exactly as `tgkill`'s.
        let Some(tgid) = self.global_pid_from_current_ns(tgid) else {
            return Err(Errno::ESRCH);
        };
        let siginfo = self.read_queued_siginfo(info, sig, tgid)?;
        if sig == 0 {
            return self.do_kill(Some(tgid), Some(tid), 0).or_else(|err| {
                // `do_kill` rejects signal 0 as `EINVAL`; the probe form only needs existence.
                if err == Errno::EINVAL {
                    self.tgkill_target_exists(tgid, tid)
                        .then_some(0)
                        .ok_or(Errno::ESRCH)
                } else {
                    Err(err)
                }
            });
        }
        let signal = Signal::try_from(sig)?;
        if tgid != self.pid {
            let Some((remote, limits)) = self.global.processes.remote_thread(tgid, tid) else {
                return self.zombie_leader_signalled(tgid, tid);
            };
            remote.deliver_remote_signal(&limits, signal, siginfo);
            return Ok(0);
        }
        if tid == self.tid.get() {
            self.send_signal(signal, siginfo);
            return Ok(0);
        }
        let Some(remote) = self.process().thread_remote(tid) else {
            return Err(Errno::ESRCH);
        };
        remote.deliver_remote_signal(&self.process().limits, signal, siginfo);
        Ok(0)
    }

    fn tgkill_target_exists(&self, tgid: i32, tid: i32) -> bool {
        if tgid == self.pid {
            tid == self.tid.get() || self.process().thread_remote(tid).is_some()
        } else {
            self.global.processes.remote_thread(tgid, tid).is_some()
                || self.zombie_leader_signalled(tgid, tid).is_ok()
        }
    }

    /// The thread-directed form (`tgkill`/`rt_tgsigqueueinfo`) of a signal to a zombie: a
    /// thread group that has exited but is not yet reaped still has its leader's task, so Linux
    /// accepts (and discards) a signal addressed to `(tgid, tgid)` until the reap; a non-leader
    /// thread of an exited group is already gone and stays `ESRCH`.
    fn zombie_leader_signalled(&self, tgid: i32, tid: i32) -> Result<usize, Errno> {
        (tid == tgid && self.global.processes.is_zombie(tgid))
            .then_some(0)
            .ok_or(Errno::ESRCH)
    }

    fn do_kill(&self, pid: Option<i32>, tid: Option<i32>, signal: i32) -> Result<usize, Errno> {
        // Signal `0` is Linux's existence probe (`do_send_specific` with `sig == 0`): the target
        // is resolved exactly as for a real signal -- `ESRCH` if it is gone -- and nothing is
        // queued.
        let signal = if signal == 0 {
            None
        } else {
            Some(Signal::try_from(signal)?)
        };
        if let Some(pid) = pid
            && pid != self.pid
        {
            // `tgkill` at another process's thread: crashpad's handler does this to the crashed
            // client's threads. Delivered thread-directed through that thread's remote queue,
            // exactly as a sibling's is below.
            let tid = tid.unwrap_or(pid);
            let Some((remote, limits)) = self.global.processes.remote_thread(pid, tid) else {
                return self.zombie_leader_signalled(pid, tid);
            };
            if let Some(signal) = signal {
                remote.deliver_remote_signal(&limits, signal, siginfo_kill(signal));
            }
            return Ok(0);
        }
        let Some(tid) = tid else {
            // `kill(getpid(), sig)` (or `kill(pid, sig)` for one's own pid): process-directed,
            // exactly like a remote `kill(other_pid, sig)` would be -- any eligible sibling
            // thread may be the one that dequeues it, not necessarily the caller. Routing this
            // through the caller's own private `pending` queue (as `send_signal` does) made the
            // signal invisible to every other thread and woke nobody.
            if let Some(signal) = signal {
                self.send_shared_signal(signal, siginfo_kill(signal));
            }
            return Ok(0);
        };
        if tid == self.tid.get() {
            if let Some(signal) = signal {
                self.send_signal(signal, siginfo_kill(signal));
            }
            return Ok(0);
        }
        // A sibling thread's `SignalState.pending` is a bare `RefCell`, not `Send`/`Sync` --
        // only reachable from the thread it belongs to -- so delivery goes through
        // `ThreadRemote::remote_pending`, the one piece of a thread's signal state built to be
        // touched remotely. `thread_remote` returns `None` once the target has detached
        // (exited), which is exactly when a real `tkill` would also report ESRCH: Linux never
        // resurrects a reaped tid.
        let Some(remote) = self.process().thread_remote(tid) else {
            return Err(Errno::ESRCH);
        };
        if let Some(signal) = signal {
            remote.deliver_remote_signal(&self.process().limits, signal, siginfo_kill(signal));
        }
        Ok(0)
    }

    /// Returns whether there are any pending signals that can be delivered.
    ///
    /// A signal whose disposition is "ignore" does not count. It is pending only in the sense
    /// that [`Task::process_signals`] has not got round to discarding it yet, and treating it as
    /// deliverable would make it interrupt waits (`check_for_interrupt`) and hand the guest a
    /// spurious `EINTR` from a syscall that nothing actually interrupted. Linux never queues such
    /// a signal in the first place; this is where that is enforced, rather than at the sending
    /// end, because a sender in another guest process cannot see the target's live handler table.
    pub(crate) fn has_pending_signals(&self) -> bool {
        self.thread_remote()
            .drain_remote_signals_into(&mut self.signals.pending.borrow_mut());
        // A signal an `rt_sigtimedwait` is waiting for must wake the wait even while blocked.
        let blocked = self.signals.effective_blocked();
        let thread_pending = self.signals.pending.borrow().pending & !blocked;
        let shared_pending = self.consult_shared_pending(blocked);
        let pending = thread_pending | shared_pending;
        if pending.is_empty() {
            return false;
        }
        let handlers = self.signals.handlers.borrow();
        let inner = handlers.inner.lock();
        pending
            .into_iter()
            .any(|signal| match inner[signal].action.sigaction {
                SIG_IGN => false,
                SIG_DFL => !matches!(signal.default_disposition(), SignalDisposition::Ignore),
                _ => true,
            })
    }

    /// The first pending, unblocked signal that [`Task::process_signals`] would act on by
    /// terminating this process: `SIG_DFL` with a terminate/core/stop default (stop is terminate
    /// there). A `TASK_KILLABLE` wait consults this instead of [`Self::has_pending_signals`]: a
    /// caught or ignored signal must not end it.
    pub(crate) fn pending_fatal_signal(&self) -> Option<Signal> {
        self.thread_remote()
            .drain_remote_signals_into(&mut self.signals.pending.borrow_mut());
        let blocked = self.signals.blocked.get();
        let pending = (self.signals.pending.borrow().pending
            | self.signals.shared_pending.lock().pending)
            & !blocked;
        if pending.is_empty() {
            return None;
        }
        let handlers = self.signals.handlers.borrow();
        let inner = handlers.inner.lock();
        pending.into_iter().find(|&signal| {
            inner[signal].action.sigaction == SIG_DFL
                && matches!(
                    signal.default_disposition(),
                    SignalDisposition::Terminate | SignalDisposition::Core | SignalDisposition::Stop
                )
        })
    }

    /// Returns the set of all pending (deliverable) signals.
    #[cfg(test)]
    pub(crate) fn pending_signal_set(&self) -> SigSet {
        let blocked = self.signals.blocked.get();
        let thread = self.signals.pending.borrow().pending & !blocked;
        let shared = self.signals.shared_pending.lock().pending & !blocked;
        thread | shared
    }

    /// Deliver any pending signals.
    pub(crate) fn process_signals(&self, ctx: &mut PtRegs) {
        self.thread_remote()
            .drain_remote_signals_into(&mut self.signals.pending.borrow_mut());
        let mut consult_shared = false;
        // Linux `do_signal`: a syscall restart `handle_syscall_request` prepared is decided
        // against the first handler delivered below, or kept if none is.
        #[cfg(target_arch = "aarch64")]
        let mut restart = self.take_prepared_syscall_restart();
        loop {
            if self.is_exiting() {
                // Don't deliver any more signals if exiting -- and don't dequeue either: a
                // process-directed one belongs to a surviving sibling (see
                // `retarget_shared_pending_on_exit`).
                return;
            }
            let blocked = self.signals.blocked.get();
            let (signal, siginfo) = {
                let mut pending = self.signals.pending.borrow_mut();
                if let Some(signal) = pending.next(blocked) {
                    (signal, pending.remove(signal))
                } else {
                    // Then the process-wide queue, only if this thread was marked to take from
                    // it (`ThreadRemote::sigpending`, consumed here before the read). Sticky
                    // for the rest of this call, so a second queued signal is not left behind
                    // once the mark is consumed.
                    consult_shared = consult_shared || self.thread_remote().take_sigpending();
                    if !consult_shared {
                        break;
                    }
                    let mut shared = self.signals.shared_pending.lock();
                    if let Some(signal) = shared.next(blocked) {
                        (signal, shared.remove(signal))
                    } else {
                        break;
                    }
                }
            };

            let action = self.signals.handlers.borrow().inner.lock()[signal].action;
            #[expect(clippy::match_same_arms)]
            match action.sigaction {
                SIG_DFL => {
                    match signal.default_disposition() {
                        SignalDisposition::Terminate
                        | SignalDisposition::Core
                        | SignalDisposition::Stop => {
                            // STOP is not currently supported, so treat as
                            // terminate. Core dumps are also not currently
                            // supported.
                            litebox_util_log::error!(
                                signal:? = signal,
                                pid:% = self.pid,
                                tid:% = self.tid.get();
                                "fatal signal: terminating task"
                            );
                            self.exit_group(ExitStatus::Signal(signal));
                        }
                        SignalDisposition::Ignore => {}
                        SignalDisposition::Continue => {
                            // Stop is not supported, so continue does nothing.
                        }
                    }
                }
                SIG_IGN => {}
                _ => {
                    #[cfg(target_arch = "aarch64")]
                    if let Some(prepared) = restart.take() {
                        self.settle_syscall_restart(ctx, prepared, Some(&action));
                    }
                    let old = self.signals.effective_blocked();
                    // Linux's `sigmask_to_save` + `clear_restore_sigmask`: the frame `rt_sigreturn`
                    // restores from carries the mask the caller had BEFORE an `rt_sigsuspend`/
                    // `ppoll`-style temporary mask went in, and taking it here is what stops
                    // `restore_saved_signal_mask` from putting it back underneath the handler --
                    // which still runs under the temporary mask (plus `sa_mask`), as specified.
                    let frame_sigmask = self.signals.saved_blocked.take().unwrap_or(blocked);
                    if let Err(DeliverFault) = self.signals.deliver_signal(
                        self.global.platform,
                        signal,
                        &siginfo,
                        &action,
                        ctx,
                        frame_sigmask,
                    ) {
                        // Failed to deliver signal. Inject a SIGSEGV
                        // (terminating the process if we were trying to deliver
                        // a SIGSEGV). The frame push itself already re-prepared
                        // and retried its guest-stack pages after a host-side
                        // fault (`ViewConfinedAccess::retry_after_fault`), so
                        // reaching here means the frame range is genuinely not
                        // writable for this task.
                        if Platform::guest_access_fault_trace() {
                            let altstack = self.signals.altstack.get();
                            litebox_util_log::warn!(
                                signal:? = signal, pid:% = self.pid, tid:% = self.tid.get(),
                                sp:? = arch::sp(ctx), altstack_sp:? = altstack.sp,
                                altstack_size:? = altstack.size,
                                altstack_disabled:? = altstack.flags.contains(SsFlags::DISABLE),
                                sa_onstack:? = action.flags.contains(SaFlags::ONSTACK),
                                si_code:? = siginfo.code, view:? = self.current_mem_view();
                                "guest-access fault trace: signal frame push failed -- forcing SIGSEGV"
                            );
                        }
                        self.force_signal(Signal::SIGSEGV, signal == Signal::SIGSEGV);
                    } else {
                        // The handler's `sa_mask` (plus the signal itself) is now blocked: a
                        // second process-directed signal this thread was marked to take may
                        // have just become one a sibling has to take instead.
                        self.signal_mask_changed_with(old, consult_shared);
                    }
                }
            }
        }
        #[cfg(target_arch = "aarch64")]
        if let Some(prepared) = restart {
            self.settle_syscall_restart(ctx, prepared, None);
        }
    }

    /// Check whether the process-wide alarm deadline has passed and, if so,
    /// enqueue `SIGALRM`.
    ///
    /// Note this is a fallback in case the platform does not support timers.
    #[cfg(feature = "alarm_fallback")]
    #[inline]
    pub(crate) fn check_alarm_deadline(&self) {
        let mut alarm = self.process().alarm_timer.lock();
        if alarm.handle.is_some() {
            // If the platform supports timers, we rely on those to trigger SIGALRM, so we don't need
            // to check the deadline here.
            return;
        }
        if alarm
            .deadline
            .is_some_and(|deadline| self.global.platform.now() >= deadline)
        {
            alarm.deadline = None;
            self.send_shared_signal(
                litebox_common_linux::signal::Signal::SIGALRM,
                siginfo_kill(litebox_common_linux::signal::Signal::SIGALRM),
            );
        }
    }

    pub(crate) fn queue_signals(&self, signal: litebox_common_linux::signal::Signal) {
        if signal == litebox_common_linux::signal::Signal::SIGALRM {
            // The platform timer fired; clear the stored deadline so that a
            // subsequent `alarm()` call does not see a stale positive remaining
            // time due to timer imprecision (the timer can fire slightly before
            // the exact deadline).
            self.process().alarm_timer.lock().deadline = None;
        }
        self.send_shared_signal(signal, siginfo_kill(signal));
    }

    /// Returns whether the given signal is currently being ignored.
    fn is_signal_ignored(&self, signal: Signal) -> bool {
        // SIGKILL and SIGSTOP can never be ignored.
        if signal == Signal::SIGKILL || signal == Signal::SIGSTOP {
            return false;
        }
        // Blocked signals are never ignored, since the signal handler may
        // change by the time it is unblocked. Nor is a signal an `rt_sigtimedwait` is
        // waiting for (Linux checks `real_blocked` here too).
        if (self.signals.blocked.get() | self.signals.sigwait_set.get()).contains(signal) {
            return false;
        }
        let handlers = self.signals.handlers.borrow();
        let inner = handlers.inner.lock();
        match inner[signal].action.sigaction {
            SIG_IGN => true,
            SIG_DFL => matches!(signal.default_disposition(), SignalDisposition::Ignore),
            _ => false,
        }
    }

    /// Returns a handle other guest processes can use to post a signal to this one.
    pub(crate) fn remote_signal_target(&self) -> RemoteSignalTarget<Platform> {
        RemoteSignalTarget {
            shared_pending: self.signals.shared_pending.clone(),
        }
    }

    /// Only supports sending signals to self for now.
    pub(crate) fn send_signal(&self, signal: Signal, siginfo: Siginfo) {
        if self.is_signal_ignored(signal) {
            return;
        }
        self.signals
            .pending
            .borrow_mut()
            .push(&self.process().limits, signal, siginfo);
    }

    /// Sends a process-directed signal (stored in shared_pending).
    pub(crate) fn send_shared_signal(&self, signal: Signal, siginfo: Siginfo) {
        if self.is_signal_ignored(signal) {
            return;
        }
        self.signals
            .shared_pending
            .lock()
            .push(&self.process().limits, signal, siginfo);
        // Whichever sibling Linux's `complete_signal` would pick (e.g. a dedicated `sigwaitinfo`
        // thread with everything else blocked) -- the same selection the remote (cross-process)
        // path's `post_to_targets` makes after its own push. The lock above is already released
        // (a temporary dropped at the end of the previous statement), so this does not nest
        // under it.
        self.process()
            .wake_one_for_shared_signal(&self.signals.shared_pending, signal);
    }

    /// Forces a signal to be delivered on next call to `check_for_signals`.
    fn force_signal(&self, signal: Signal, force_exit: bool) {
        let siginfo = Siginfo {
            signo: signal.as_i32(),
            errno: 0,
            code: SI_KERNEL,
            #[cfg(target_pointer_width = "64")]
            __pad: 0,
            data: SiginfoData::new_zeroed(),
        };
        self.force_signal_with_info(signal, force_exit, siginfo);
    }

    pub(crate) fn force_signal_with_info(&self, signal: Signal, force_exit: bool, siginfo: Siginfo) {
        // This function resets the handler to `SIG_DFL` when forcing delivery,
        // so the signal must be fatal by default; otherwise the guest would
        // never actually see it acted on. `handle_exception_request` reaches
        // this with any signal `arch::exception_signal` can decode a hardware
        // exception into -- not just `SIGSEGV` (e.g. `SIGILL` for an
        // undefined instruction, `SIGTRAP` for a breakpoint, `SIGFPE` for a
        // floating-point exception) -- so the check has to match on
        // disposition rather than enumerate specific signals.
        assert!(matches!(
            signal.default_disposition(),
            SignalDisposition::Core | SignalDisposition::Terminate
        ));

        // Linux `force_sig_info_to_task`: a standard signal already pending on this thread
        // keeps its first `siginfo` (`legacy_queue`), and a forced signal is never dropped for
        // `RLIMIT_SIGPENDING` (kernel-originated `si_code`).
        self.signals
            .pending
            .borrow_mut()
            .push_from_kernel(signal, siginfo);

        // Update the handler if necessary to ensure the signal is handled: only `sa_handler`
        // becomes `SIG_DFL` -- `sa_flags`/`sa_mask` stay as installed and remain observable
        // through a later `sigaction` (Linux's `HANDLER_CURRENT` forcing) -- and the action is
        // pinned (`SA_IMMUTABLE`) only for the `force_exit` case (`HANDLER_EXIT`).
        let force_default = {
            let handlers = self.signals.handlers.borrow();
            let mut inner = handlers.inner.lock();
            let handler = &mut inner[signal];
            let force_default = force_exit
                || self.signals.blocked.get().contains(signal)
                || handler.action.sigaction == SIG_IGN;
            if force_default {
                handler.action.sigaction = SIG_DFL;
                handler.immutable = force_exit;
            }
            force_default
        };
        if force_default {
            let mut blocked = self.signals.blocked.get();
            blocked.remove(signal);
            self.set_signal_mask(blocked);
        }
    }

    /// Linux `seccomp_send_sigsys`: the `SYS_SECCOMP` `SIGSYS` a `SECCOMP_RET_TRAP` forces on
    /// the calling thread, carrying the filter's 16-bit `data` in `si_errno` and the denied
    /// call's post-syscall pc, raw number and audit arch in `_sigsys`. Signals a sibling already
    /// aimed at this thread (`tgkill`) are drained first so an earlier `SIGSYS` keeps its own
    /// `siginfo`, exactly as it was queued first on Linux; stale hardware-exception metadata is
    /// cleared so the frame cannot carry a previous fault's address. Delivered like every other
    /// forced signal ([`Self::force_signal_with_info`]): to an installed, unblocked handler with
    /// `SA_SIGINFO`/`SA_ONSTACK`/`SA_NODEFER` honored, or -- if blocked or ignored -- reset to
    /// `SIG_DFL` and unblocked so the default action terminates.
    pub(crate) fn force_seccomp_sigsys(&self, data: u32, call_addr: usize, nr: i32, arch: u32) {
        const SYS_SECCOMP: i32 = 1;
        self.thread_remote()
            .drain_remote_signals_into(&mut self.signals.pending.borrow_mut());
        self.signals.last_exception.set(arch::NO_EXCEPTION);
        let siginfo = Siginfo {
            signo: Signal::SIGSYS.as_i32(),
            errno: data.cast_signed(),
            code: SYS_SECCOMP,
            #[cfg(target_pointer_width = "64")]
            __pad: 0,
            data: SiginfoData::new_sigsys(call_addr, nr, arch),
        };
        self.force_signal_with_info(Signal::SIGSYS, false, siginfo);
    }

    pub(crate) fn handle_exception_request(&self, info: &litebox::shim::ExceptionInfo) {
        // Decoding an exception vector into a signal is entirely architectural,
        // so it lives alongside the rest of the per-architecture frame handling.
        let (signal, fault_address) = arch::exception_signal(info);
        litebox_util_log::error!(
            info:? = info,
            signal:? = signal,
            fault_address:? = fault_address,
            pid:% = self.pid,
            tid:% = self.tid.get();
            "guest hardware exception"
        );
        self.signals.last_exception.set(*info);
        // Classify a `SIGSEGV` the way a real Linux `do_page_fault` does: a
        // `find_vma`-shaped lookup, not the hardware's own current PTE state --
        // `PROT_NONE` is realized on this platform by removing the stage-1
        // translation entirely (see `hvf_memory.rs`'s "PROT_NONE reservation"),
        // so a raw ESR/error-code fault-status read would misreport a `mmap` +
        // `mprotect(PROT_NONE)` region as `SEGV_MAPERR` instead of the
        // `SEGV_ACCERR` Linux guests expect. `Vmem`'s own tracked mappings are
        // this process's one real, authoritative address-space state (unlike
        // `GuestVaDomain`'s best-effort shadow mirror), so this needs no view
        // lookup and carries no staleness risk.
        let code = if signal == Signal::SIGSEGV {
            if self.global.pm.lock_mappings().flags_at(fault_address).is_some() {
                SEGV_ACCERR
            } else {
                SEGV_MAPERR
            }
        } else {
            SI_KERNEL
        };
        self.force_signal_with_info(signal, false, siginfo_exception(signal, fault_address, code));
    }

    /// Delivers a real `SIGSEGV` for a guest-controlled failure from
    /// [`litebox::mm::PageManager::handle_page_fault`] (e.g. a refused stack-growth demand),
    /// instead of the host silently terminating the guest with no signal at all -- exactly
    /// Linux's own `expand_stack`-failure behavior. Reuses the same `SEGV_MAPERR`/`SEGV_ACCERR`
    /// classification [`Self::handle_exception_request`] already established (`Vmem`'s own
    /// authoritative `flags_at`, never a raw ESR/error-code read -- see that method's own doc
    /// comment for why).
    pub(crate) fn deliver_page_fault_segv(
        &self,
        fault_address: usize,
        err: litebox::mm::linux::PageFaultError,
    ) {
        litebox_util_log::debug!(
            fault_address:? = fault_address, err:? = err, pid:% = self.pid, tid:% = self.tid.get();
            "guest page fault refused -- delivering SIGSEGV"
        );
        let code = if self.global.pm.lock_mappings().flags_at(fault_address).is_some() {
            SEGV_ACCERR
        } else {
            SEGV_MAPERR
        };
        Platform::record_guest_fault_delivered(self.task_id);
        self.force_signal_with_info(
            Signal::SIGSEGV,
            false,
            siginfo_exception(Signal::SIGSEGV, fault_address, code),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    extern crate std;

    #[test]
    fn kill_zero_signals_only_the_callers_process_group() {
        let caller = crate::syscalls::tests::init_platform(None);
        let peer = caller
            .global
            .clone()
            .new_test_task(caller.files.borrow().fs.clone());
        let outsider = caller
            .global
            .clone()
            .new_test_task(caller.files.borrow().fs.clone());

        caller.register_for_remote_signals();
        peer.register_for_remote_signals();
        outsider.register_for_remote_signals();
        assert_eq!(caller.sys_setpgid(0, 3131), Ok(()));
        assert_eq!(peer.sys_setpgid(0, 3131), Ok(()));
        assert_eq!(outsider.sys_setpgid(0, 4242), Ok(()));
        assert_eq!(caller.sys_kill(0, 0), Ok(0));
        assert!(caller.pending_signal_set().is_empty());
        assert!(peer.pending_signal_set().is_empty());
        assert!(outsider.pending_signal_set().is_empty());

        assert_eq!(caller.sys_kill(0, Signal::SIGUSR1.as_i32()), Ok(0));
        assert!(caller.pending_signal_set().contains(Signal::SIGUSR1));
        assert!(peer.pending_signal_set().contains(Signal::SIGUSR1));
        assert!(!outsider.pending_signal_set().contains(Signal::SIGUSR1));
    }
}
