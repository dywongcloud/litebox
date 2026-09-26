// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! `ptrace(2)`: attach/seize, genuine stop rendezvous,
//! `NT_PRSTATUS`/`NT_ARM_TLS`/`NT_PRFPREG` `GETREGSET`/`SETREGSET`,
//! `PTRACE_CONT`, `PTRACE_DETACH`, `wait4`-visible stop reporting, and a
//! `ptrace_may_access`-equivalent cross-credential permission gate.
//!
//! # Scope
//!
//! A tracer targets any thread in the shim by `tid` (ptrace addresses individual threads, not
//! thread groups), same-process or not: same-process resolution goes through
//! [`super::process::Process::thread_remote`] (the same PID/TID-reuse-safe mechanism
//! `tkill`/`tgkill` already use -- a `tid` that has exited is simply not found; a `tid` later
//! reused by an unrelated new thread gets a distinct `ThreadRemote`, so a tracer holding a
//! reference to the old one can never observe or mutate the new thread's state); a `tid` outside
//! the caller's own process falls back to [`super::process::ProcessTable::thread_remote_by_tid`],
//! a flat, process-blind lookup mirroring how real Linux's `find_task_by_vpid` resolves `ptrace`'s
//! `pid` argument in the first place. `PTRACE_ATTACH`/`PTRACE_SEIZE` additionally gate on
//! [`Task::ptrace_may_access`], this shim's `ptrace_may_access`-equivalent permission check (see
//! its own doc comment for exactly what it enforces and the two divergences it discloses).
//! `PTRACE_PEEKDATA`/`PTRACE_POKEDATA` remain same-process-only regardless (see "What this does
//! not implement" below) -- every other request (`GETREGSET`/`SETREGSET`/`PTRACE_CONT`/
//! `PTRACE_DETACH`) works identically whether or not the tracee shares the tracer's process, since
//! none of them ever touch the tracee's own memory through the tracer's address space.
//!
//! # Stop rendezvous
//!
//! A "ptrace stop" is requested by setting [`PtraceState`]'s word to
//! [`STATE_STOP_REQUESTED`] and kicking the target thread's [`super::process::ThreadRemote`]
//! handle (the exact mechanism `tkill`/interrupt already use to reach a thread that may be deep
//! inside `hv_vcpu_run`). The target only actually parks -- and only then is its register state
//! read into [`PtraceState`] for the tracer to observe -- from
//! [`crate::wait::Task::prepare_to_run_guest`], which runs after every `syscall`/`exception`/
//! `interrupt` return and strictly before the thread re-enters guest code. At that point the
//! HVF backend has already released the thread's vCPU lane back to the pool (see
//! `HvfBackend::run_thread`: `release_lane` happens before `dispatch`, which is what eventually
//! calls `shim.syscall`/`shim.interrupt`/`shim.exception` and, through those, `prepare_to_run_guest`)
//! and captured its architectural state out of the vCPU into `ctx: &mut PtRegs` -- so the thread
//! is provably not mid-`hv_vcpu_run`, and `ctx` is the authoritative, complete, host-boundary-safe
//! snapshot of its logical Linux-guest state. This is exactly the "safe rendezvous point" pattern
//! `ThreadHandle::interrupt`/`HvfThreadSlot::kick` already establish for interrupts, reused rather
//! than reinvented: no new HVF-backend primitive is needed, and no Darwin host register state is
//! ever exposed (only `ctx`, the shim's own logical `PtRegs`, plus `TPIDR_EL0` read through the
//! existing [`litebox::platform::ArchSpecificProvider`] accessor while still running as the
//! tracee's own thread).
//!
//! # What this does not implement
//!
//! `PTRACE_SEIZE`'s only real difference from `PTRACE_ATTACH` here is that it does not force an
//! immediate stop (matching Linux). `PTRACE_INTERRUPT` (seize-only stop-on-demand) and hardware
//! single-step/breakpoint regsets (`NT_ARM_HW_BREAK`/`NT_ARM_HW_WATCH`) are not implemented --
//! `PTRACE_SETOPTIONS`/`PTRACE_PEEKTEXT`/`PTRACE_POKETEXT`/`PTRACE_SINGLESTEP` and any other
//! request return `ENOSYS`. `PTRACE_PEEKDATA`/`PTRACE_POKEDATA` are implemented as plain
//! word-exact reads/writes through the tracer's own `UserPtr`/`UserPtrMut`, which is only ever
//! correct when tracer and tracee share one address space -- unlike every other request, these
//! two are therefore refused (`EIO`) for a cross-process target rather than silently touching the
//! TRACER's own memory at `addr` instead of the TRACEE's; real Linux's own `PEEKDATA`/`POKEDATA`
//! are cross-process by design (`access_process_vm`, copying through the target's own
//! `mm_struct`), which a genuine cross-view copier would be needed to match here (not implemented
//! by this row -- a disclosed scope limit, not a correctness gap: refusing outright is the safe
//! choice over silently reading/writing the wrong process). Every hardware-debug regset
//! (`NT_ARM_HW_BREAK`/`NT_ARM_HW_WATCH`) and the 32-bit-compat `NT_ARM_VFP` return `ENODEV` from
//! `GETREGSET`/`SETREGSET`, explicitly, rather than silently returning zeroed or partial data.
//!
//! A ptrace stop is visible to the tracer's own `wait4`/`waitpid` the moment it completes
//! (`Task::sys_wait4`'s own ptrace-stop branch, fed by [`super::process::PtraceRegistry`]),
//! unconditionally with respect to `WUNTRACED`/`__WALL` -- matching real Linux's own
//! `wait_task_stopped`/`eligible_child`, which treat a genuine ptrace relationship as sufficient
//! on its own regardless of either flag -- for a tracee tid that need not be (and, cross-process,
//! is not) a `ChildRecord` child of the tracer at all. No true job-control `SIGSTOP`/`SIGCONT`
//! group-stop is modelled, and a plain `PTRACE_CONT` is not itself a `SIGCONT`-driven continue on
//! real Linux either, so `WIFCONTINUED`/`WCONTINUED` never has anything to report (this matches
//! Linux, not merely this shim's own limitation).

use crate::{ShimFS, ShimPlatform, Task, UserPtr, UserPtrMut};
use litebox::platform::{ArchSpecificRegister, RawMutex as _};
use litebox::sync::Mutex;
use litebox_common_linux::PtRegs;
use litebox_common_linux::errno::Errno;
use litebox_common_linux::ptrace::{
    NT_ARM_TLS, NT_PRFPREG, NT_PRSTATUS, PTRACE_ATTACH, PTRACE_CONT, PTRACE_DETACH,
    PTRACE_GETREGSET, PTRACE_PEEKDATA, PTRACE_POKEDATA, PTRACE_SEIZE, PTRACE_SETREGSET,
    UserFpsimdState, UserPtRegs,
};
use zerocopy::{FromBytes, Immutable, IntoBytes};

/// Process-global count of successful `PTRACE_ATTACH`/`PTRACE_SEIZE` calls, for the lifecycle
/// counters readout surface. Exact, monotonic, never sampled from logs.
static PTRACE_ATTACH_EVENTS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
/// Process-global count of successful `PTRACE_DETACH` calls; see [`PTRACE_ATTACH_EVENTS`].
static PTRACE_DETACH_EVENTS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Snapshot of this process's ptrace attach/detach lifecycle counters.
#[derive(Debug, Clone, Copy)]
pub struct PtraceLifecycleCounters {
    pub attach_events: u64,
    pub detach_events: u64,
}

/// Loads both ptrace lifecycle counters in one pass (each independently `Acquire`; no ordering
/// is claimed between the two loads themselves).
pub fn ptrace_lifecycle_counters() -> PtraceLifecycleCounters {
    PtraceLifecycleCounters {
        attach_events: PTRACE_ATTACH_EVENTS.load(core::sync::atomic::Ordering::Acquire),
        detach_events: PTRACE_DETACH_EVENTS.load(core::sync::atomic::Ordering::Acquire),
    }
}

/// The real Linux `struct iovec` layout (`{ void *iov_base; size_t iov_len; }`), read/written
/// generically as two machine words. `ptrace`'s `data` argument for `GETREGSET`/`SETREGSET`
/// points at one of these; unlike [`litebox_common_linux::IoReadVec`]/`IoWriteVec` (each fixed to
/// one access direction), this same iovec is both read from (`SETREGSET`) and written to
/// (`GETREGSET`), so a single direction-neutral raw layout is the correct fit rather than either
/// existing typed alias.
#[derive(Clone, Copy, FromBytes, IntoBytes, Immutable)]
#[repr(C)]
struct RawIovec {
    iov_base: usize,
    iov_len: usize,
}

/// No tracer attached.
const STATE_DETACHED: u32 = 0;
/// A tracer is attached and the tracee runs normally.
const STATE_RUNNING: u32 = 1;
/// A stop was requested; the tracee has not yet reached the rendezvous point in
/// `prepare_to_run_guest`.
const STATE_STOP_REQUESTED: u32 = 2;
/// The tracee has parked at the rendezvous point; `registers`/`tpidr_el0` are a valid, stable
/// snapshot the tracer may read, and (before the tracee resumes) mutate.
const STATE_STOPPED: u32 = 3;

/// Bits `0..STATE_BITS` of [`PtraceState`]'s word hold one of the `STATE_*` values above; bit
/// [`REPORTED_BIT`] holds the current stop's `wait4`-reported flag (see that constant's own doc
/// comment); every bit above that holds a generation counter bumped on every transition *into*
/// [`STATE_DETACHED`] (`PTRACE_DETACH`, a thread's own exit, or an exit-cancelled stop below).
/// Packing all three into one word lets every transition -- including exit-cancellation and a
/// `wait4` report's own claim -- be a single atomic compare-exchange against a value read once,
/// so it can only ever apply to the exact attach/stop instance that word still holds, never to a
/// later, unrelated instance that happens to read the same bare `STATE_*` value.
const STATE_BITS: u32 = 2;
const STATE_MASK: u32 = (1 << STATE_BITS) - 1;
/// Set once this instance's current [`STATE_STOPPED`] has been claimed by a `wait4` report (see
/// [`PtraceState::try_claim_reported_stop`]); meaningless in every other state. Every *existing*
/// transition below already clears it as a side effect of going through [`pack`] (which never
/// sets this bit), which is exactly correct: `request_stop`'s own `RUNNING -> STOP_REQUESTED`
/// clears it well before any observer could see the state bits as `STOPPED` again, so a future,
/// distinct stop within one attach instance (not built by this row -- `PTRACE_INTERRUPT`) would
/// already be unclaimed the moment it begins, with no extra plumbing needed here.
const REPORTED_BIT: u32 = 1 << STATE_BITS;
const GENERATION_SHIFT: u32 = STATE_BITS + 1;

const fn pack(state: u32, generation: u32) -> u32 {
    (generation << GENERATION_SHIFT) | state
}

const fn unpack_state(word: u32) -> u32 {
    word & STATE_MASK
}

const fn unpack_generation(word: u32) -> u32 {
    word >> GENERATION_SHIFT
}

const fn unpack_reported(word: u32) -> bool {
    word & REPORTED_BIT != 0
}

/// `ptrace` attach/stop state carried on every thread's [`super::process::ThreadRemote`].
///
/// The state word is a [`litebox::platform::RawMutex`] used purely as a blockable atomic (the
/// same idiom `Process::fork_gate`/`ProcessLaunch`/`VforkCompletion` already use for cross-thread,
/// non-interruptible rendezvous): every transition is a `compare_exchange` on the word followed by
/// `wake_all`, and every wait is a loop of `load` -> `block(observed)`. `tracer_task`/`registers`/
/// `tpidr_el0` are guarded by their own mutex separately from the word so that a tracer reading a
/// stopped snapshot never has to hold the word's own (raw, non-reentrant) lock.
pub(crate) struct PtraceState<Platform: ShimPlatform> {
    word: <Platform as litebox::platform::RawMutexProvider>::RawMutex,
    /// The attached tracer's own [`litebox::utils::ids::TaskInstanceId`], valid whenever
    /// `word != STATE_DETACHED`. Only this task may `GETREGSET`/`SETREGSET`/`PTRACE_CONT`/
    /// `PTRACE_DETACH` -- Linux's own "only the tracer may act on its tracee" rule.
    ///
    /// Keyed by task instance rather than a bare, kernel-recyclable `tid` (contrast
    /// `super::process::PtraceRegistry`, which already keys its own reverse-direction
    /// tracer-to-tracees map by `TaskInstanceId` for the identical reason): a raw-tid comparison
    /// here would misattribute ownership if this tracer's `tid` were later reused by an unrelated
    /// task, and independently would spuriously drop the CURRENT tracer's own standing the moment
    /// its `tid` is rekeyed in place by a non-leader `execve` (`Process::rekey_sole_thread`),
    /// since `TaskInstanceId` -- unlike `tid` -- "stays fixed for its whole lifetime" (see
    /// `Task`'s own doc comment on its `task_id` field).
    ///
    /// Stored as the identity's own raw `NonZeroU64` in an `AtomicU64` with `0` meaning no
    /// tracer (a `TaskInstanceId` is never zero) -- the same raw-word encoding
    /// `litebox::mm::session::EffectGate::owner` already uses to hold a `TaskInstanceId`
    /// lock-free; see this type's own [`Self::raw`].
    tracer_task: core::sync::atomic::AtomicU64,
    /// Valid only while `word == STATE_STOPPED`.
    snapshot: Mutex<Platform, StoppedSnapshot>,
}

#[derive(Clone)]
struct StoppedSnapshot {
    registers: PtRegs,
    tpidr_el0: u64,
    fp: litebox::platform::FpSimdState64,
}

impl<Platform: ShimPlatform> PtraceState<Platform> {
    pub(crate) fn new() -> Self {
        Self {
            word: <Platform as litebox::platform::RawMutexProvider>::RawMutex::INIT,
            tracer_task: core::sync::atomic::AtomicU64::new(0),
            snapshot: Mutex::new(StoppedSnapshot {
                registers: PtRegs::default(),
                tpidr_el0: 0,
                fp: litebox::platform::FpSimdState64::default(),
            }),
        }
    }

    /// The raw `NonZeroU64` backing `tracer`, matching
    /// [`litebox::mm::session::EffectGate::raw`]'s identical encoding for the identical purpose.
    fn raw(tracer: litebox::utils::ids::TaskInstanceId) -> u64 {
        tracer.get().get()
    }

    fn state(&self) -> u32 {
        unpack_state(
            self.word
                .underlying_atomic()
                .load(core::sync::atomic::Ordering::Acquire),
        )
    }

    /// `PTRACE_ATTACH`/`PTRACE_SEIZE`: claims this (detached) tracee for `tracer`.
    ///
    /// Returns the generation this attach instance landed at, or `None` if a tracer is already
    /// attached (Linux: `EPERM`). The generation only ever changes together with a transition
    /// into `DETACHED` (see this type's own doc comment), so it stays valid across any number of
    /// future `PTRACE_CONT`/stop-request round trips for this exact attach instance -- a caller
    /// that needs to find this attach again later (the process-global ptrace registry; see
    /// [`Self::is_live_at`]/[`Self::detach_if_live_at`]) records it once, here.
    fn attach(&self, tracer: litebox::utils::ids::TaskInstanceId) -> Option<u32> {
        let atomic = self.word.underlying_atomic();
        let mut cur = atomic.load(core::sync::atomic::Ordering::Acquire);
        loop {
            if unpack_state(cur) != STATE_DETACHED {
                return None;
            }
            let generation = unpack_generation(cur);
            match atomic.compare_exchange_weak(
                cur,
                pack(STATE_RUNNING, generation),
                core::sync::atomic::Ordering::AcqRel,
                core::sync::atomic::Ordering::Acquire,
            ) {
                Ok(_) => {
                    self.tracer_task
                        .store(Self::raw(tracer), core::sync::atomic::Ordering::Release);
                    return Some(generation);
                }
                Err(actual) => cur = actual,
            }
        }
    }

    /// Whether `tracer` is this tracee's currently-attached tracer.
    pub(crate) fn is_tracer(&self, tracer: litebox::utils::ids::TaskInstanceId) -> bool {
        self.state() != STATE_DETACHED
            && self.tracer_task.load(core::sync::atomic::Ordering::Acquire) == Self::raw(tracer)
    }

    /// Whether SOME tracer is currently attached, regardless of which one or which of
    /// `STATE_RUNNING`/`STATE_STOP_REQUESTED`/`STATE_STOPPED` -- `sigchld-ignored-autoreap`'s own
    /// ptrace exemption (`ProcessTable::record_exit`): real Linux's `do_notify_parent` never
    /// auto-reaps a task with `tsk->ptrace` set, because `PTRACE_ATTACH` redirects exit
    /// notification to the tracer (`tsk->parent`), which needs the zombie to `wait4` for like any
    /// other -- so this deliberately does not narrow to any particular tracer the way
    /// [`Self::is_tracer`] does.
    pub(crate) fn is_attached(&self) -> bool {
        self.state() != STATE_DETACHED
    }

    /// `PTRACE_ATTACH`'s stop request: publishes [`STATE_STOP_REQUESTED`] (from
    /// [`STATE_RUNNING`]) with a `compare_exchange`, deliberately *before* the caller kicks the
    /// tracee (`ThreadRemote::interrupt`) -- so the kick can never race ahead of the request it
    /// is meant to deliver. A tracee that wakes from the kick before `STOP_REQUESTED` is visible
    /// would otherwise sail past the one place ([`Self::rendezvous`]) that checks for it, and
    /// not stop until whatever syscall/exception/interrupt it happens to hit next instead of
    /// immediately, which is what `PTRACE_ATTACH` promises. Idempotent against an
    /// already-requested or already-stopped tracee. Returns `false` only if the tracee is not
    /// attached at all (raced a concurrent detach/exit between `attach` and here).
    fn request_stop(&self) -> bool {
        let atomic = self.word.underlying_atomic();
        let mut cur = atomic.load(core::sync::atomic::Ordering::Acquire);
        loop {
            match unpack_state(cur) {
                STATE_STOPPED | STATE_STOP_REQUESTED => return true,
                STATE_DETACHED => return false,
                STATE_RUNNING => {
                    match atomic.compare_exchange_weak(
                        cur,
                        pack(STATE_STOP_REQUESTED, unpack_generation(cur)),
                        core::sync::atomic::Ordering::AcqRel,
                        core::sync::atomic::Ordering::Acquire,
                    ) {
                        Ok(_) => return true,
                        Err(actual) => cur = actual,
                    }
                }
                _ => unreachable!("invalid ptrace state"),
            }
        }
    }

    /// Blocks until a tracee reaches [`STATE_STOPPED`] after [`Self::request_stop`], or gives
    /// up. `false` means either the tracee detached/exited first, or `is_exiting` (the
    /// *tracer's own*, checked fresh every iteration like `Task::cred_guard_lock`'s identical
    /// discipline) went true first -- in which case a tracee that reached `STOPPED` anyway is
    /// exit-cancelled (CAS to `DETACHED` for the exact generation observed) rather than left
    /// stranded under a tracer that is about to report failure and walk away believing it never
    /// attached. A tracee still only `STOP_REQUESTED` (not yet `STOPPED`) when the tracer gives
    /// up is deliberately left as-is: it either reaches `STOPPED` and is cancelled by
    /// [`Self::rendezvous`]'s own `is_exiting` check if it is *itself* exiting, or remains
    /// validly attached to a tracer that no longer services it, which the tracer's own future
    /// exit is responsible for unwinding (a separate, broader mechanism this narrower primitive
    /// does not attempt to replace).
    fn wait_until_stopped(&self, is_exiting: impl Fn() -> bool) -> bool {
        let atomic = self.word.underlying_atomic();
        loop {
            let cur = atomic.load(core::sync::atomic::Ordering::Acquire);
            match unpack_state(cur) {
                STATE_DETACHED => return false,
                STATE_STOPPED if is_exiting() => {
                    self.force_detach_from(cur);
                    return false;
                }
                STATE_STOPPED => return true,
                STATE_STOP_REQUESTED if is_exiting() => return false,
                STATE_STOP_REQUESTED => {
                    let _ = self.word.block(cur);
                }
                _ => unreachable!("invalid ptrace state"),
            }
        }
    }

    /// CAS `word` from exactly `observed` to `DETACHED` at the next generation, and wake on
    /// success. Shared by every exit/interruption-triggered cancellation path in this module. A
    /// failed CAS means some other, equally valid transition (a genuine `PTRACE_CONT`/
    /// `PTRACE_DETACH`, or a racing cancellation) already landed and already woke everyone
    /// waiting on this word -- never a correctness problem, since every caller's own loop
    /// re-reads the word regardless of this method's return value.
    fn force_detach_from(&self, observed: u32) -> bool {
        let cancelled = self
            .word
            .underlying_atomic()
            .compare_exchange(
                observed,
                pack(STATE_DETACHED, unpack_generation(observed).wrapping_add(1)),
                core::sync::atomic::Ordering::AcqRel,
                core::sync::atomic::Ordering::Acquire,
            )
            .is_ok();
        if cancelled {
            self.word.wake_all();
        }
        cancelled
    }

    /// Whether the attach instance recorded as `generation` (see [`Self::attach`]'s own return
    /// value) is still the one live for this tracee -- read-only, safe to call at any time, no
    /// side effect. A stale generation means this tracee has since been detached by some other
    /// path (an explicit `PTRACE_DETACH`, an exit-cancellation, or its own exit), and possibly
    /// even re-attached to a different tracer since: not this caller's to act on either way.
    pub(crate) fn is_live_at(&self, generation: u32) -> bool {
        let cur = self
            .word
            .underlying_atomic()
            .load(core::sync::atomic::Ordering::Acquire);
        unpack_generation(cur) == generation && unpack_state(cur) != STATE_DETACHED
    }

    /// `Task::detach_owned_tracees`'s own primitive (Linux's own `exit_ptrace`): detaches this
    /// tracee (resuming it if it was stopped) only if `generation` is still the live attach
    /// instance -- see [`Self::is_live_at`]. A single attempt, not a retry loop: if the word has
    /// already moved on, some other, equally valid transition already landed and already woke
    /// anyone parked on it (see [`Self::force_detach_from`]'s own doc comment), so there is
    /// nothing left for this call to do.
    pub(crate) fn detach_if_live_at(&self, generation: u32) -> bool {
        let cur = self
            .word
            .underlying_atomic()
            .load(core::sync::atomic::Ordering::Acquire);
        if unpack_generation(cur) != generation || unpack_state(cur) == STATE_DETACHED {
            return false;
        }
        self.force_detach_from(cur)
    }

    /// Called only by the tracee's own thread, from
    /// [`crate::wait::Task::prepare_to_run_guest`] -- the safe rendezvous point where the vCPU
    /// lane has already been released and `ctx`/`tpidr_el0` are the authoritative, complete
    /// logical guest state. Parks (genuine host blocking, not a spin) while a stop is requested
    /// or in effect, capturing the snapshot on entry and re-applying any tracer mutation on exit.
    ///
    /// Checks `is_exiting` (this *tracee's own*, checked fresh both before the initial
    /// transition and on every iteration of the park loop below) before every transition or
    /// block: a thread that is itself exiting never publishes a `STOPPED` snapshot it cannot be
    /// trusted to still honor, and never stays parked past the point its own group needs it to
    /// detach -- either case exit-cancels straight to `DETACHED` (bumping the generation) rather
    /// than leaving `STOP_REQUESTED`/`STOPPED` for a later observer to "resurrect". This is the
    /// same before-and-after-every-block discipline `Task::cred_guard_lock` uses, and is woken
    /// by the identical mechanism: `Task::exit_group`/`Task::kill_other_threads` call
    /// [`Self::wake_for_exit`] on this exact word at the same point they mark this thread
    /// `is_exiting` and `interrupt()` it, because `interrupt()` alone never wakes a raw
    /// `block()` on a foreign word (the same class of gap `Process::cred_guard` was fixed for --
    /// without that explicit wake, a ptrace-stopped tracee whose process is being torn down
    /// would never notice and would hang `kill_other_threads`'/`exit_group`'s own wait for it to
    /// detach forever).
    ///
    /// The `STOP_REQUESTED` -> `STOPPED` transition itself is a `compare_exchange` against the
    /// exact word observed at entry, not an unconditional store: `PTRACE_DETACH` can legally
    /// land while this tracee is still merely `STOP_REQUESTED` (`is_tracer`/`detach` do not
    /// require `STOPPED` first), and an unconditional store here would silently clobber that
    /// already-published `DETACHED`, leaving the tracee incorrectly parked with a fresh snapshot
    /// under a tracer that already walked away.
    fn rendezvous(
        &self,
        platform: &Platform,
        ctx: &mut PtRegs,
        tpidr_el0: u64,
        is_exiting: impl Fn() -> bool,
    ) -> u64 {
        let atomic = self.word.underlying_atomic();
        let cur = atomic.load(core::sync::atomic::Ordering::Acquire);
        if unpack_state(cur) != STATE_STOP_REQUESTED {
            return tpidr_el0;
        }
        if is_exiting() {
            self.force_detach_from(cur);
            return tpidr_el0;
        }
        *self.snapshot.lock() = StoppedSnapshot {
            registers: ctx.clone(),
            tpidr_el0,
            fp: platform.get_fp_state(),
        };
        if atomic
            .compare_exchange(
                cur,
                pack(STATE_STOPPED, unpack_generation(cur)),
                core::sync::atomic::Ordering::AcqRel,
                core::sync::atomic::Ordering::Acquire,
            )
            .is_err()
        {
            // Lost the race: a tracer's `PTRACE_DETACH` (or a concurrent exit-cancellation)
            // already moved this word on between the load above and here. The snapshot just
            // captured is simply discarded, `ctx` is untouched, and this tracee runs on exactly
            // as if it had never been asked to stop.
            return tpidr_el0;
        }
        self.word.wake_all();
        loop {
            let cur = atomic.load(core::sync::atomic::Ordering::Acquire);
            match unpack_state(cur) {
                STATE_STOPPED if is_exiting() => {
                    self.force_detach_from(cur);
                    break;
                }
                STATE_STOPPED => {
                    let _ = self.word.block(cur);
                }
                STATE_RUNNING | STATE_DETACHED => break,
                _ => unreachable!("invalid ptrace state"),
            }
        }
        // The tracer may have mutated `snapshot` (`PTRACE_SETREGSET`) any time before this
        // resumed the tracee; apply it now, on the tracee's own thread, before guest re-entry.
        // If this was an exit-cancelled stop rather than a genuine resume, `snapshot` still
        // holds exactly what was captured above (never touched by any tracer), so this is a
        // no-op restore of the tracee's own unmodified state.
        let snapshot = self.snapshot.lock().clone();
        *ctx = snapshot.registers;
        platform.set_fp_state(&snapshot.fp);
        snapshot.tpidr_el0
    }

    /// `PTRACE_CONT`: resumes a stopped tracee. Returns `false` if it was not stopped.
    fn resume(&self) -> bool {
        let atomic = self.word.underlying_atomic();
        let cur = atomic.load(core::sync::atomic::Ordering::Acquire);
        if unpack_state(cur) != STATE_STOPPED {
            return false;
        }
        let resumed = atomic
            .compare_exchange(
                cur,
                pack(STATE_RUNNING, unpack_generation(cur)),
                core::sync::atomic::Ordering::AcqRel,
                core::sync::atomic::Ordering::Acquire,
            )
            .is_ok();
        if resumed {
            self.word.wake_all();
        }
        resumed
    }

    /// `PTRACE_DETACH`: releases the tracee unconditionally (stopped or running) and resumes it
    /// if it was stopped.
    fn detach(&self) {
        let atomic = self.word.underlying_atomic();
        let cur = atomic.load(core::sync::atomic::Ordering::Acquire);
        atomic.store(
            pack(STATE_DETACHED, unpack_generation(cur).wrapping_add(1)),
            core::sync::atomic::Ordering::Release,
        );
        self.tracer_task
            .store(0, core::sync::atomic::Ordering::Release);
        self.word.wake_all();
    }

    /// Called from the two sibling-teardown loops (`Task::exit_group`, `Task::kill_other_threads`)
    /// for every *other* thread they mark `is_exiting`, at the same point they call
    /// `ThreadRemote::interrupt` on it. `interrupt()` alone never wakes a thread parked in this
    /// word's own raw `block()` (only a `wake_all()` on this exact word does -- the same class
    /// of gap `Process::cred_guard` was fixed for), so without this call a ptrace-stopped
    /// tracee, or a tracer mid-`PTRACE_ATTACH` blocked waiting for one to stop, would never
    /// notice its own thread group is exiting and would hang the caller's own wait for it to
    /// detach forever. Safe to call unconditionally regardless of this word's current state
    /// (untraced, already detached, running, or already terminal): `wake_all` on a word nothing
    /// is blocked on is a no-op.
    pub(crate) fn wake_for_exit(&self) {
        self.word.wake_all();
    }

    /// Reads the stopped snapshot's `NT_PRSTATUS` view. Caller must have already confirmed
    /// `word == STATE_STOPPED` under the tracer's own serialized use of this state (ptrace
    /// requests from one tracer are not concurrent with each other by construction: they are
    /// ordinary syscalls on the tracer's single thread).
    fn read_prstatus(&self) -> UserPtRegs {
        UserPtRegs::from(&self.snapshot.lock().registers)
    }

    fn write_prstatus(&self, regs: &UserPtRegs) {
        regs.write_into(&mut self.snapshot.lock().registers);
    }

    fn read_fpregs(&self) -> UserFpsimdState {
        UserFpsimdState::from(&self.snapshot.lock().fp)
    }

    fn write_fpregs(&self, regs: &UserFpsimdState) {
        regs.write_into(&mut self.snapshot.lock().fp);
    }

    fn read_tls(&self) -> u64 {
        self.snapshot.lock().tpidr_el0
    }

    fn write_tls(&self, value: u64) {
        self.snapshot.lock().tpidr_el0 = value;
    }

    pub(crate) fn is_stopped(&self) -> bool {
        self.state() == STATE_STOPPED
    }

    /// Whether this instance is `STOPPED` right now with its current stop not yet claimed by any
    /// `wait4` report -- a read-only peek `Task::sys_wait4`'s blocking condition can poll
    /// cheaply, paired with [`Self::try_claim_reported_stop`] for the one call that actually
    /// consumes it.
    pub(crate) fn has_unclaimed_stop(&self) -> bool {
        let cur = self
            .word
            .underlying_atomic()
            .load(core::sync::atomic::Ordering::Acquire);
        unpack_state(cur) == STATE_STOPPED && !unpack_reported(cur)
    }

    /// Attempts to claim this instance's current stop for one `wait4` report: an atomic CAS
    /// (never a plain check-then-set) that also re-verifies `STATE_STOPPED` at the exact moment
    /// of the claim, so a concurrent `PTRACE_CONT`/`PTRACE_DETACH`/exit-cancellation landing in
    /// between a caller's own `has_unclaimed_stop` peek and this call can never be raced into a
    /// stale report. Of any number of concurrent observers (multiple threads of one
    /// multi-threaded tracer process, all sharing `wait4`'s process-wide visibility), exactly one
    /// ever wins for a given stop -- matching real Linux's own `wait_task_stopped` clearing
    /// `p->exit_code` after the first successful report. Returns `false` when this is not
    /// currently a claimable stop (not `STOPPED` at all, or `STOPPED` but already claimed);
    /// `Task::sys_wait4` treats that exactly like "nothing new from this tracee right now", the
    /// same as an unmatched `ChildRecord`.
    pub(crate) fn try_claim_reported_stop(&self) -> bool {
        let atomic = self.word.underlying_atomic();
        let mut cur = atomic.load(core::sync::atomic::Ordering::Acquire);
        loop {
            if unpack_state(cur) != STATE_STOPPED || unpack_reported(cur) {
                return false;
            }
            match atomic.compare_exchange_weak(
                cur,
                cur | REPORTED_BIT,
                core::sync::atomic::Ordering::AcqRel,
                core::sync::atomic::Ordering::Acquire,
            ) {
                Ok(_) => return true,
                Err(actual) => cur = actual,
            }
        }
    }

    /// Whether a stop is currently requested or already in effect for this tracee -- a single
    /// Acquire load of the state bits; there is no separate observed value to compare against,
    /// so this is exact for whichever generation currently occupies the word. Used by
    /// `Task::check_for_interrupt` so a tracee parked in any `WaitContext`-based wait (futex,
    /// epoll/poll/select, pipe/socket read, `wait4`, `sigsuspend`) notices a pending
    /// `PTRACE_ATTACH` stop request instead of consuming `ThreadHandle::interrupt`'s kick and
    /// re-blocking on the exact same wait forever.
    pub(crate) fn is_stop_requested(&self) -> bool {
        self.state() == STATE_STOP_REQUESTED
    }

    /// Called when the tracee thread detaches from its process (exits): unconditionally
    /// releases any attached tracer rather than leaving it blocked forever on a rendezvous that
    /// can now never happen. A tracer's next request against this `tid` finds no `ThreadRemote`
    /// (`Process::thread_remote` returns `None`, since `detach_thread` has already removed it)
    /// and fails `ESRCH`, exactly like `tkill` against an exited thread.
    pub(crate) fn on_thread_exit(&self) {
        let atomic = self.word.underlying_atomic();
        let cur = atomic.load(core::sync::atomic::Ordering::Acquire);
        atomic.store(
            pack(STATE_DETACHED, unpack_generation(cur).wrapping_add(1)),
            core::sync::atomic::Ordering::Release,
        );
        self.word.wake_all();
    }
}

impl<Platform: ShimPlatform, FS: ShimFS> Task<Platform, FS> {
    /// Handle syscall `ptrace`.
    pub(crate) fn sys_ptrace(
        &self,
        request: i64,
        pid: i32,
        addr: usize,
        data: usize,
    ) -> Result<usize, Errno> {
        // `pid` here is a Linux `tid` (ptrace addresses individual threads, not thread groups).
        if pid == self.tid.get() {
            // A thread may not trace itself: Linux's own `ptrace_attach` rejects
            // `task == current`.
            return Err(Errno::EPERM);
        }
        // Same-process threads are resolved directly (no table lookup needed); a tid this task's
        // own process does not own may still be a live thread of some OTHER process -- ptrace's
        // cross-process case (`tracee_pid` here is that thread's own owning pid/tgid, needed by
        // the permission check below and by `Task::sys_wait4`'s own registry lookups). See this
        // module's own doc comment for the one place this distinction still matters:
        // `PTRACE_PEEKDATA`/`PTRACE_POKEDATA` remain same-process-only.
        let (tracee_pid, remote, same_process) = if let Some(remote) = self.process().thread_remote(pid) {
            (self.pid, remote, true)
        } else if let Some((owner_pid, remote)) = self.global.processes.thread_remote_by_tid(pid) {
            (owner_pid, remote, false)
        } else {
            // Not found (exited, or never existed anywhere in the shim): PID-reuse-safe by
            // construction, since both lookups walk live `threads` maps, never a reusable slot
            // index.
            return Err(Errno::ESRCH);
        };

        match request {
            PTRACE_ATTACH | PTRACE_SEIZE => {
                if request == PTRACE_SEIZE && (addr != 0 || data != 0) {
                    // Real Linux's `ptrace_seize` requires `addr == 0` and validates `data`
                    // (the `PTRACE_O_*` option bitmask) against the supported option bits
                    // before touching any attach state at all, failing `EIO` for either
                    // violation. `PTRACE_SETOPTIONS` always fails here (falls through to the
                    // catch-all `ENOSYS` arm below, so `PTRACE_O_TRACESECCOMP` can never be
                    // observed enabled) -- nothing in `data` is ever supported, so any nonzero
                    // `data` is equally invalid.
                    return Err(Errno::EIO);
                }
                // The `ptrace_may_access`-equivalent permission gate: same-process or not, real
                // Linux never special-cases a same-thread-group attach here either. See
                // `Task::ptrace_may_access`'s own doc comment for exactly what this checks (and
                // deliberately does not).
                if !self.ptrace_may_access(tracee_pid, &remote) {
                    return Err(Errno::EPERM);
                }
                let Some(generation) = remote.ptrace.attach(self.task_id) else {
                    return Err(Errno::EPERM);
                };
                // Records this attach in the process-global ptrace registry so a later exit of
                // *this* tracer thread (`Task::detach_owned_tracees`, Linux's own `exit_ptrace`)
                // can find and release this tracee even if it never issues its own
                // `PTRACE_DETACH` -- `PtraceState` itself stores only the reverse direction (this
                // tracee's own attached tracer) -- and so `Task::sys_wait4` can find it too.
                self.global
                    .ptrace_registry
                    .record_attach(self.task_id, pid, &remote, generation);
                if request == PTRACE_ATTACH {
                    // PTRACE_ATTACH stops the tracee immediately (Linux delivers a synthetic
                    // group-stop the tracer observes via `waitpid`); this shim's tracer instead
                    // observes it by the stop having genuinely completed before this call
                    // returns. The stop request is published *before* the kick below -- see
                    // `PtraceState::request_stop`'s own doc comment for why the order matters.
                    if !remote.ptrace.request_stop() {
                        return Err(Errno::ESRCH);
                    }
                    remote.interrupt();
                    if !remote.ptrace.wait_until_stopped(|| self.is_exiting()) {
                        return Err(Errno::ESRCH);
                    }
                    // The stop is now genuinely in effect; make it visible to this tracer's own
                    // `wait4` immediately -- a sibling thread of this (the tracer's) process
                    // already blocked in `wait4(..., __WALL)` must not wait for some unrelated
                    // later wake to notice. This shim's only stop-inducing path today is this
                    // forced attach-stop (no `PTRACE_INTERRUPT`/signal-delivery-stop yet -- see
                    // this module's own doc comment), so this one call site is the only place
                    // that ever needs to do this; a future stop-inducing path would need to call
                    // `wake_waiters` at its own point of confirming `STATE_STOPPED` too.
                    self.global.processes.wake_waiters(self.pid);
                }
                // PTRACE_SEIZE attaches without forcing a stop; the tracee keeps running until a
                // later PTRACE_ATTACH-style stop request. `PTRACE_INTERRUPT` (seize-only
                // stop-on-demand) is not implemented.
                PTRACE_ATTACH_EVENTS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
                let counters = ptrace_lifecycle_counters();
                litebox_util_log::debug!(
                    tracer:? = self.tid.get(), tracee:? = pid,
                    attach_events:? = counters.attach_events, detach_events:? = counters.detach_events;
                    "ptrace: attach/seize event recorded"
                );
                Ok(0)
            }
            PTRACE_GETREGSET | PTRACE_SETREGSET => {
                if !remote.ptrace.is_tracer(self.task_id) {
                    return Err(Errno::ESRCH);
                }
                if !remote.ptrace.is_stopped() {
                    return Err(Errno::ESRCH);
                }
                // `addr` carries the small `NT_*` type identifier here (never a real address,
                // per the real ptrace ABI for GETREGSET/SETREGSET); a value with no `i32`
                // representation cannot match any known `NT_*` constant and correctly falls
                // through to the explicit `ENODEV` arm below, so truncation is the intended
                // matching behavior, not a truncation bug.
                #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
                let nt_type = addr as i32;
                // `data` is `struct iovec *`: `{ void *iov_base; size_t iov_len; }`. Read
                // generically as two machine words -- unlike `IoReadVec`/`IoWriteVec`, ptrace's
                // iovec is read *and* written back through the same pointer direction, so
                // neither of those (each fixed to one direction) applies cleanly here.
                let iovec = UserPtr::<RawIovec>::from_usize(data)
                    .read_at_offset::<Platform>(0)
                    .ok_or(Errno::EFAULT)?;
                let write_len = |actual: usize| {
                    // Linux writes the regset's actual byte length back into `iov_len` on a
                    // successful GETREGSET. Best-effort: a tracer that only reads `iov_base`'s
                    // contents (the common case) is unaffected if this padding write races
                    // something odd.
                    let len_field = UserPtrMut::<usize>::from_usize(
                        data + core::mem::offset_of!(RawIovec, iov_len),
                    );
                    let _ = len_field.write_at_offset::<Platform>(0, actual);
                };
                match nt_type {
                    NT_PRSTATUS => {
                        if iovec.iov_len < UserPtRegs::SIZE {
                            return Err(Errno::EINVAL);
                        }
                        if request == PTRACE_GETREGSET {
                            let regs = remote.ptrace.read_prstatus();
                            UserPtrMut::<UserPtRegs>::from_usize(iovec.iov_base)
                                .write_at_offset::<Platform>(0, regs)
                                .ok_or(Errno::EFAULT)?;
                            write_len(UserPtRegs::SIZE);
                        } else {
                            let regs = UserPtr::<UserPtRegs>::from_usize(iovec.iov_base)
                                .read_at_offset::<Platform>(0)
                                .ok_or(Errno::EFAULT)?;
                            remote.ptrace.write_prstatus(&regs);
                        }
                        Ok(0)
                    }
                    NT_ARM_TLS => {
                        if iovec.iov_len < core::mem::size_of::<u64>() {
                            return Err(Errno::EINVAL);
                        }
                        if request == PTRACE_GETREGSET {
                            let value = remote.ptrace.read_tls();
                            UserPtrMut::<u64>::from_usize(iovec.iov_base)
                                .write_at_offset::<Platform>(0, value)
                                .ok_or(Errno::EFAULT)?;
                            write_len(core::mem::size_of::<u64>());
                        } else {
                            let value = UserPtr::<u64>::from_usize(iovec.iov_base)
                                .read_at_offset::<Platform>(0)
                                .ok_or(Errno::EFAULT)?;
                            remote.ptrace.write_tls(value);
                        }
                        Ok(0)
                    }
                    NT_PRFPREG => {
                        if iovec.iov_len < UserFpsimdState::SIZE {
                            return Err(Errno::EINVAL);
                        }
                        if request == PTRACE_GETREGSET {
                            let regs = remote.ptrace.read_fpregs();
                            UserPtrMut::<UserFpsimdState>::from_usize(iovec.iov_base)
                                .write_at_offset::<Platform>(0, regs)
                                .ok_or(Errno::EFAULT)?;
                            write_len(UserFpsimdState::SIZE);
                        } else {
                            let regs = UserPtr::<UserFpsimdState>::from_usize(iovec.iov_base)
                                .read_at_offset::<Platform>(0)
                                .ok_or(Errno::EFAULT)?;
                            remote.ptrace.write_fpregs(&regs);
                        }
                        Ok(0)
                    }
                    // Real, distinct Linux regset types this shim does not populate:
                    // hardware debug/watch state (`NT_ARM_HW_BREAK`/`NT_ARM_HW_WATCH`), the
                    // 32-bit-compat `NT_ARM_VFP`, and so on. Fail explicitly rather than
                    // returning zeroed or partial data.
                    _ => Err(Errno::ENODEV),
                }
            }
            PTRACE_PEEKDATA => {
                if !remote.ptrace.is_tracer(self.task_id) {
                    return Err(Errno::ESRCH);
                }
                if !remote.ptrace.is_stopped() {
                    return Err(Errno::ESRCH);
                }
                if !same_process {
                    // Real Linux's `PEEKDATA`/`POKEDATA` are cross-process by design
                    // (`access_process_vm`, copying through the TARGET's own `mm_struct`) --
                    // this shim's implementation instead reuses the TRACER's own `UserPtr`
                    // accessor directly, which is only ever correct when tracer and tracee share
                    // one address space (`pid == self.tid.get()` is already rejected above, and a
                    // same-process tracee necessarily does). A cross-process target would
                    // silently read the TRACER's OWN memory at `addr` instead of the TRACEE's;
                    // refused explicitly instead of risking that (disclosed scope limit: a
                    // genuine cross-view copier is not implemented by this row).
                    return Err(Errno::EIO);
                }
                let value = UserPtr::<u64>::from_usize(addr)
                    .read_at_offset::<Platform>(0)
                    .ok_or(Errno::EFAULT)?;
                UserPtrMut::<u64>::from_usize(data)
                    .write_at_offset::<Platform>(0, value)
                    .ok_or(Errno::EFAULT)?;
                Ok(0)
            }
            PTRACE_POKEDATA => {
                if !remote.ptrace.is_tracer(self.task_id) {
                    return Err(Errno::ESRCH);
                }
                if !remote.ptrace.is_stopped() {
                    return Err(Errno::ESRCH);
                }
                if !same_process {
                    // See `PTRACE_PEEKDATA`'s identical guard just above: this would otherwise
                    // silently write into the TRACER's OWN memory at `addr` rather than the
                    // TRACEE's.
                    return Err(Errno::EIO);
                }
                // Unlike PEEKDATA, `data` here is the value to write itself, not a pointer to it.
                #[allow(clippy::cast_possible_truncation)]
                let value = data as u64;
                UserPtrMut::<u64>::from_usize(addr)
                    .write_at_offset::<Platform>(0, value)
                    .ok_or(Errno::EFAULT)?;
                Ok(0)
            }
            PTRACE_CONT => {
                if !remote.ptrace.is_tracer(self.task_id) {
                    return Err(Errno::ESRCH);
                }
                // `data` as a pending signal to deliver on resume is not implemented; only 0
                // (no signal) is accepted, matching every other unsupported nonzero-argument
                // case in this shim.
                if data != 0 {
                    return Err(Errno::EINVAL);
                }
                if !remote.ptrace.resume() {
                    return Err(Errno::ESRCH);
                }
                Ok(0)
            }
            PTRACE_DETACH => {
                if !remote.ptrace.is_tracer(self.task_id) {
                    return Err(Errno::ESRCH);
                }
                remote.ptrace.detach();
                // This tracer no longer needs `Task::detach_owned_tracees` to find this tracee;
                // drop it (and any other of this tracer's entries that have gone stale for any
                // other reason) from the process-global ptrace registry now, rather than letting
                // it sit there unbounded until this tracer eventually exits.
                self.global.ptrace_registry.forget_stale(self.task_id);
                PTRACE_DETACH_EVENTS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
                let counters = ptrace_lifecycle_counters();
                litebox_util_log::debug!(
                    tracer:? = self.tid.get(), tracee:? = pid,
                    attach_events:? = counters.attach_events, detach_events:? = counters.detach_events;
                    "ptrace: detach event recorded"
                );
                Ok(0)
            }
            _ => {
                let _ = addr;
                Err(Errno::ENOSYS)
            }
        }
    }

    /// The `ptrace_may_access`-equivalent permission gate for `PTRACE_ATTACH`/`PTRACE_SEIZE`:
    /// this task's (the prospective tracer's) real/effective/saved uid AND gid triples must each
    /// equal the target's, and the target's owning process must be dumpable -- exactly the
    /// mutable rule this row's own precondition specifies, read against litebox's actual
    /// credential model (`super::process::Credentials`, `Process::dumpable`) rather than ported
    /// wholesale from real Linux's own, broader `__ptrace_may_access`. Two deliberate,
    /// disclosed divergences, matching this shim's actual threat model:
    ///
    /// * No `CAP_SYS_PTRACE` bypass. Real Linux lets a process holding that capability attach
    ///   regardless of credential mismatch; this shim models no capability set at all (see
    ///   `Task::is_privileged`'s identical stance elsewhere in this file), so a
    ///   privileged-looking but mismatched-creds tracer is still refused here.
    /// * No Yama/`PR_SET_PTRACER` ancestor-relationship restriction. This shim enforces no such
    ///   policy in either direction, so there is nothing narrower to layer on top of the
    ///   same-credential rule.
    ///
    /// `tracee_pid` is the target thread's OWNING process id (its tgid) -- `self.pid` for a
    /// same-process target, the resolved owner for a cross-process one (see `Self::sys_ptrace`'s
    /// own resolution) -- used only to find the right `dumpable` flag: same-process reads
    /// `Process::dumpable()` directly (no table lookup needed, and correct even mid-fork, since
    /// this task's own `Process` handle is already live), cross-process goes through
    /// `ProcessTable::is_dumpable`.
    fn ptrace_may_access(
        &self,
        tracee_pid: i32,
        tracee: &super::process::ThreadRemote<Platform>,
    ) -> bool {
        let tracer = self.credentials.borrow();
        let tracee_creds = tracee.credentials();
        let same_identity = tracer.uid == tracee_creds.uid
            && tracer.euid == tracee_creds.euid
            && tracer.suid == tracee_creds.suid
            && tracer.gid == tracee_creds.gid
            && tracer.egid == tracee_creds.egid
            && tracer.sgid == tracee_creds.sgid;
        if !same_identity {
            return false;
        }
        if tracee_pid == self.pid {
            self.process().dumpable()
        } else {
            self.global
                .processes
                .is_dumpable(tracee_pid)
                .unwrap_or(false)
        }
    }

    /// Called from [`crate::wait::Task::prepare_to_run_guest`]: parks this thread at the ptrace
    /// stop rendezvous if a tracer has requested one, applying any tracer register mutation on
    /// resume. No-op (a single atomic load) when untraced or not currently stop-requested.
    pub(crate) fn ptrace_rendezvous(&self, ctx: &mut litebox_common_linux::PtRegs) {
        let tpidr_el0 = self
            .global
            .platform
            .get_arch_specific_register(&ArchSpecificRegister::TpidrEl0)
            .unwrap_or(0) as u64;
        let new_tpidr = self.thread_remote().ptrace.rendezvous(
            self.global.platform,
            ctx,
            tpidr_el0,
            || self.is_exiting(),
        );
        if new_tpidr != tpidr_el0 {
            // `TpidrEl0` is aarch64-only (this whole module is arch-gated), where `usize` is
            // 64-bit and this cast is exact; no fallible conversion is warranted for a target
            // this code never runs on.
            #[allow(clippy::cast_possible_truncation)]
            let value = new_tpidr as usize;
            let _ = self
                .global
                .platform
                .set_arch_specific_register(&ArchSpecificRegister::TpidrEl0, value);
        }
    }
}
