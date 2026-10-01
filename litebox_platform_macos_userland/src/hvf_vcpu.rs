// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Owner-thread-affine HVF vCPU lanes.
//!
//! Every Hypervisor.framework vCPU is created, driven, and destroyed on one
//! dedicated owner thread (the SDK is owner-affine for everything except
//! `hv_vcpus_exit`).  Other threads talk to a lane through a bounded command
//! queue; the only cross-thread operation is a cancellation kick, which is a
//! request to the owner rather than a mutation of vCPU state.
//!
//! Ownership rules this module enforces:
//!
//! * A lane's registry slot and reaper slot are reserved before the owner
//!   thread is spawned and are released only by the process reaper after the
//!   owner thread has been joined, so capacity accounting is exact.
//! * A vCPU that could not be destroyed is quarantined under its creator
//!   thread identity by the SDK; the owner thread therefore stays alive as a
//!   cleanup custodian, retrying in bounded waves, until nothing owner-keyed
//!   remains.  Retry exhaustion never orphans a resource.
//! * Cancellation attempts are linear, epoch-bound records; a kick that lands
//!   after the run it targeted has already exited is remembered so that the
//!   spurious `Canceled` exit it may produce on the next run is consumed
//!   instead of misattributed.
//! * The command queue owns the closed/drain transition under its own lock, so
//!   a sender that passed its liveness check can never enqueue after the
//!   owner's final drain: the push itself is refused and the sender finishes
//!   its own attachment.

use core::fmt;
use std::cell::Cell;
use std::collections::VecDeque;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock, mpsc};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::hvf::{
    HvfArchitecturalState, HvfEl1State, HvfError, HvfFpInstall, HvfGuestFp, HvfOperationError,
    HvfPstateContext, HvfRunScope, HvfVcpu, HvfVcpuCancellation, HvfVcpuExit, process_hvf_vm,
};
use crate::hvf_memory::{HvfMemoryError, HvfVcpuRunAttachment};

const COMMAND_WAIT_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_COMMAND_QUEUE_CAPACITY: usize = 64;
const MAX_SHUTDOWN_CANCELLATION_ATTEMPTS: usize = 3;
const OWNER_CLEANUP_RETRY_INTERVAL: Duration = Duration::from_secs(1);
/// Owner-affine destroy retries per custody wave before the lane reports
/// residual vCPUs and settles into cleanup custody.
pub(crate) const OWNER_CLEANUP_WAVE_ATTEMPTS: usize = 8;
const CONTROL_WAIT_POLL: Duration = Duration::from_millis(10);
const STAGE_ONE_TABLE_ALIGNMENT: u64 = 16 * 1024;
const STAGE_ONE_TTBR_BASE_MASK: u64 = 0x0000_ffff_ffff_c000;
const LANE_LIVE: u8 = 0;
const LANE_CLOSING: u8 = 1;
const LANE_ABANDONED: u8 = 2;
const LANE_CLOSED: u8 = 3;

/// Failure injection for the owner-panic-containment witness.  While the
/// counter is nonzero, the next command an owner thread pops consumes one
/// unit and panics synthetically instead of executing it, so the diagnostic
/// can prove `catch_unwind` in [`owner_thread`] contains the unwind: the
/// panic must not escape past this module, must not abort the process, and
/// the lane's own cleanup (vCPU destroy/quarantine, registry release, reaper
/// join) must still run to completion afterwards. Pure Rust, consumed inside
/// the owner thread itself, so no FFI/SDK boundary is touched by the
/// injection.
static OWNER_PANIC_INJECTION: AtomicU8 = AtomicU8::new(0);

struct SynchronizationBarrierState {
    generation: u64,
    armed: Option<u64>,
    reached: Option<u64>,
}

struct SynchronizationBarrier {
    state: Mutex<SynchronizationBarrierState>,
    changed: Condvar,
}

static SYNCHRONIZATION_BARRIER: OnceLock<SynchronizationBarrier> = OnceLock::new();

fn synchronization_barrier() -> &'static SynchronizationBarrier {
    SYNCHRONIZATION_BARRIER.get_or_init(|| SynchronizationBarrier {
        state: Mutex::new(SynchronizationBarrierState {
            generation: 0,
            armed: None,
            reached: None,
        }),
        changed: Condvar::new(),
    })
}

#[must_use]
pub(crate) struct HvfVcpuSynchronizationBarrier {
    generation: u64,
    active: bool,
}

pub(crate) fn arm_vcpu_synchronization_barrier()
-> Result<HvfVcpuSynchronizationBarrier, HvfVcpuLaneError> {
    let barrier = synchronization_barrier();
    let mut state = barrier
        .state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if state.armed.is_some() {
        return Err(HvfVcpuLaneError::RegistryAccounting);
    }
    let generation = state
        .generation
        .checked_add(1)
        .ok_or(HvfVcpuLaneError::RegistryAccounting)?;
    state.generation = generation;
    state.armed = Some(generation);
    state.reached = None;
    barrier.changed.notify_all();
    Ok(HvfVcpuSynchronizationBarrier {
        generation,
        active: true,
    })
}

impl HvfVcpuSynchronizationBarrier {
    pub(crate) fn wait_until_reached(&self) -> Result<(), HvfVcpuLaneError> {
        if !self.active {
            return Err(HvfVcpuLaneError::LaneClosed);
        }
        let deadline = operation_deadline()?;
        let barrier = synchronization_barrier();
        let mut state = barrier
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        loop {
            if state.reached == Some(self.generation) {
                return Ok(());
            }
            if state.armed != Some(self.generation) {
                return Err(HvfVcpuLaneError::LaneClosed);
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(HvfVcpuLaneError::OperationTimeout);
            }
            crate::diagnostics_counters::rank_note_blocking_wait(
                crate::diagnostics_counters::RK_WAIT_WHILE_HOLDING,
                std::panic::Location::caller(),
            );
            let (next, _) = barrier
                .changed
                .wait_timeout(state, remaining.min(CONTROL_WAIT_POLL))
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state = next;
        }
    }

    pub(crate) fn release(mut self) {
        self.disarm();
    }

    fn disarm(&mut self) {
        if !self.active {
            return;
        }
        let barrier = synchronization_barrier();
        let mut state = barrier
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.armed == Some(self.generation) {
            state.armed = None;
        }
        self.active = false;
        barrier.changed.notify_all();
    }
}

impl Drop for HvfVcpuSynchronizationBarrier {
    fn drop(&mut self) {
        self.disarm();
    }
}

#[track_caller]
fn hold_vcpu_synchronization_barrier() {
    let barrier = synchronization_barrier();
    let mut state = barrier
        .state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(generation) = state.armed else {
        return;
    };
    state.reached = Some(generation);
    barrier.changed.notify_all();
    while state.armed == Some(generation) {
        crate::diagnostics_counters::rank_note_blocking_wait(
            crate::diagnostics_counters::RK_WAIT_WHILE_HOLDING,
            std::panic::Location::caller(),
        );
        state = barrier
            .changed
            .wait(state)
            .unwrap_or_else(std::sync::PoisonError::into_inner);
    }
    if state.reached == Some(generation) {
        state.reached = None;
    }
    barrier.changed.notify_all();
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct RunCompletionBarrierTarget {
    generation: u64,
    lane_generation: u64,
    run_epoch: u64,
}

struct RunCompletionBarrierState {
    generation: u64,
    armed: Option<RunCompletionBarrierTarget>,
    reached: Option<u64>,
}

struct RunCompletionBarrier {
    state: Mutex<RunCompletionBarrierState>,
    changed: Condvar,
}

static RUN_COMPLETION_BARRIER: OnceLock<RunCompletionBarrier> = OnceLock::new();
/// Keeps the ordinary multi-lane exit path free of a process-global mutex when
/// the deterministic completion witness is not armed.
static RUN_COMPLETION_BARRIER_ARMED: AtomicBool = AtomicBool::new(false);

fn run_completion_barrier() -> &'static RunCompletionBarrier {
    RUN_COMPLETION_BARRIER.get_or_init(|| RunCompletionBarrier {
        state: Mutex::new(RunCompletionBarrierState {
            generation: 0,
            armed: None,
            reached: None,
        }),
        changed: Condvar::new(),
    })
}

#[must_use]
pub(crate) struct HvfVcpuRunCompletionBarrier {
    target: RunCompletionBarrierTarget,
    active: bool,
}

pub(crate) fn arm_vcpu_run_completion_barrier(
    lane_generation: u64,
    run_epoch: u64,
) -> Result<HvfVcpuRunCompletionBarrier, HvfVcpuLaneError> {
    if lane_generation == 0 || run_epoch == 0 {
        return Err(HvfVcpuLaneError::RegistryAccounting);
    }
    let barrier = run_completion_barrier();
    let mut state = barrier
        .state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if state.armed.is_some() {
        return Err(HvfVcpuLaneError::RegistryAccounting);
    }
    let generation = state
        .generation
        .checked_add(1)
        .ok_or(HvfVcpuLaneError::RegistryAccounting)?;
    let target = RunCompletionBarrierTarget {
        generation,
        lane_generation,
        run_epoch,
    };
    state.generation = generation;
    state.armed = Some(target);
    state.reached = None;
    RUN_COMPLETION_BARRIER_ARMED.store(true, Ordering::Release);
    barrier.changed.notify_all();
    Ok(HvfVcpuRunCompletionBarrier {
        target,
        active: true,
    })
}

impl HvfVcpuRunCompletionBarrier {
    pub(crate) fn wait_until_reached(&self) -> Result<(), HvfVcpuLaneError> {
        if !self.active {
            return Err(HvfVcpuLaneError::LaneClosed);
        }
        let deadline = operation_deadline()?;
        let barrier = run_completion_barrier();
        let mut state = barrier
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        loop {
            if state.reached == Some(self.target.generation) {
                return Ok(());
            }
            if state.armed != Some(self.target) {
                return Err(HvfVcpuLaneError::LaneClosed);
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(HvfVcpuLaneError::OperationTimeout);
            }
            crate::diagnostics_counters::rank_note_blocking_wait(
                crate::diagnostics_counters::RK_WAIT_WHILE_HOLDING,
                std::panic::Location::caller(),
            );
            let (next, _) = barrier
                .changed
                .wait_timeout(state, remaining.min(CONTROL_WAIT_POLL))
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state = next;
        }
    }

    pub(crate) fn release(mut self) {
        self.disarm();
    }

    fn disarm(&mut self) {
        if !self.active {
            return;
        }
        let barrier = run_completion_barrier();
        let mut state = barrier
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.armed == Some(self.target) {
            state.armed = None;
            RUN_COMPLETION_BARRIER_ARMED.store(false, Ordering::Release);
        }
        self.active = false;
        barrier.changed.notify_all();
    }
}

impl Drop for HvfVcpuRunCompletionBarrier {
    fn drop(&mut self) {
        self.disarm();
    }
}

/// Deterministic-completion rendezvous. Diagnostic-only: returns immediately unless a witness
/// armed the barrier (no armer runs in an ordinary run).
///
/// The wait is bounded (T2d fix-up): this runs *inside* the run scope's single existing-vCPU
/// operation, so parking here holds that operation, an `active_vcpu_owners` slot and a published
/// frame, and keeps `promote_poison_if_quiescent` / `abandoned_cleanup_ready` from seeing the VM
/// as quiescent. An armed-but-never-released arm must therefore not be able to park the owner
/// indefinitely; the deadline is the same one the arming side's `wait_until_reached` uses.
fn hold_vcpu_run_completion_barrier(lane_generation: u64, run_epoch: u64) {
    if !RUN_COMPLETION_BARRIER_ARMED.load(Ordering::Acquire) {
        return;
    }
    let Ok(deadline) = operation_deadline() else {
        return;
    };
    let barrier = run_completion_barrier();
    let mut state = barrier
        .state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(target) = state.armed else {
        return;
    };
    if target.lane_generation != lane_generation || target.run_epoch != run_epoch {
        return;
    }
    state.reached = Some(target.generation);
    barrier.changed.notify_all();
    while state.armed == Some(target) {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            // Give up the hold rather than park the owner inside the admission; the arming
            // witness reports a timeout instead of a hang.
            crate::diagnostics_counters::record_barrier_hold_timeout();
            break;
        }
        crate::diagnostics_counters::rank_note_blocking_wait(
            crate::diagnostics_counters::RK_WAIT_WHILE_HOLDING,
            std::panic::Location::caller(),
        );
        let (next, _) = barrier
            .changed
            .wait_timeout(state, remaining.min(CONTROL_WAIT_POLL))
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state = next;
    }
    if state.reached == Some(target.generation) {
        state.reached = None;
    }
    barrier.changed.notify_all();
}

/// Arms (or disarms with `0`) the owner-panic injection; returns the
/// previously armed count.  Diagnostic-only, crate-private.
pub(crate) fn inject_owner_panic(count: u8) -> u8 {
    OWNER_PANIC_INJECTION.swap(count, Ordering::AcqRel)
}

fn raise_lane_lifecycle(lifecycle: &AtomicU8, target: u8) {
    let mut current = lifecycle.load(Ordering::Acquire);
    while current < target {
        match lifecycle.compare_exchange_weak(current, target, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) => break,
            Err(observed) => current = observed,
        }
    }
}

pub(crate) fn hvf_vcpu_lane_is_live(lifecycle: &AtomicU8, owner_stopped: &AtomicBool) -> bool {
    lifecycle.load(Ordering::Acquire) == LANE_LIVE && !owner_stopped.load(Ordering::Acquire)
}

#[derive(Debug)]
pub enum HvfVcpuLaneError {
    Hvf(HvfError),
    Memory(HvfMemoryError),
    Capacity {
        active: u32,
        limit: u32,
    },
    QueueCapacity(usize),
    QueueOverloaded,
    LaneClosed,
    LaneTerminal,
    /// Internal: a cancellation latched while the lane was still entering the
    /// guest, so the run completes as `Canceled` without ever entering it.
    LatchedCancellation,
    VcpuNotRunning,
    CancellationInFlight {
        sequence: u64,
        run_epoch: u64,
    },
    CancellationTooLate {
        sequence: u64,
        run_epoch: u64,
    },
    UnexpectedCancellation {
        run_epoch: u64,
    },
    OperationTimeout,
    ThreadSpawn(std::io::Error),
    OwnerPanicked,
    RejectedExit(HvfVcpuExit),
    InvalidExecutionState {
        exit: HvfVcpuExit,
        state: HvfSynchronizationExitState,
    },
    InvalidContinuation {
        pc: u64,
        cpsr: u64,
        esr_el1: u64,
    },
    InvalidSynchronizationExit {
        exit: HvfVcpuExit,
        lane_generation: u64,
        request: HvfSynchronizationRequest,
        state: HvfSynchronizationExitState,
    },
    Cleanup {
        primary: Box<HvfVcpuLaneError>,
        cleanup: Box<HvfVcpuLaneError>,
    },
    RegistryAccounting,
    ResidualVcpus {
        current_thread: usize,
        process: usize,
    },
    /// FXR: a guest run claimed a resident SIMD/FP file this lane does not hold for it and
    /// carried no host copy either, so no correct SIMD/FP state exists to run with.
    FpResidency {
        lane_generation: u64,
        claimed_seq: Option<u64>,
    },
}

impl fmt::Display for HvfVcpuLaneError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Hvf(error) => write!(f, "{error}"),
            Self::Memory(error) => write!(f, "{error}"),
            Self::Capacity { active, limit } => {
                write!(f, "HVF vCPU lane capacity {active}/{limit} is exhausted")
            }
            Self::QueueCapacity(capacity) => write!(
                f,
                "HVF vCPU command queue capacity {capacity} is outside 1..={MAX_COMMAND_QUEUE_CAPACITY}"
            ),
            Self::QueueOverloaded => write!(f, "the bounded HVF vCPU command queue is full"),
            Self::LaneClosed => write!(f, "the HVF vCPU owner lane is closed"),
            Self::LaneTerminal => write!(
                f,
                "the HVF vCPU owner lane reached a terminal execution state"
            ),
            Self::LatchedCancellation => write!(
                f,
                "a cancellation latched before the HVF vCPU entered the guest"
            ),
            Self::VcpuNotRunning => write!(f, "the HVF vCPU owner lane has no active run"),
            Self::CancellationInFlight {
                sequence,
                run_epoch,
            } => write!(
                f,
                "HVF vCPU cancellation {sequence} is already pending for run epoch {run_epoch}"
            ),
            Self::CancellationTooLate {
                sequence,
                run_epoch,
            } => write!(
                f,
                "HVF vCPU cancellation {sequence} arrived too late for run epoch {run_epoch}"
            ),
            Self::UnexpectedCancellation { run_epoch } => write!(
                f,
                "HVF vCPU run epoch {run_epoch} returned an unauthenticated cancellation"
            ),
            Self::OperationTimeout => write!(
                f,
                "timed out waiting for the HVF vCPU owner lane after 30 seconds"
            ),
            Self::ThreadSpawn(error) => write!(f, "failed to spawn HVF vCPU owner lane: {error}"),
            Self::OwnerPanicked => write!(f, "the HVF vCPU owner lane panicked"),
            Self::RejectedExit(exit) => {
                write!(f, "the HVF vCPU returned rejected exit {exit:?}")
            }
            Self::InvalidExecutionState { exit, state } => write!(
                f,
                "the HVF vCPU returned {exit:?} with phase-invalid architectural state {state:?}"
            ),
            Self::InvalidContinuation { pc, cpsr, esr_el1 } => write!(
                f,
                "the HVF vCPU continuation has pc={pc:#x}, cpsr={cpsr:#x}, esr_el1={esr_el1:#x}"
            ),
            Self::InvalidSynchronizationExit {
                exit,
                lane_generation,
                request,
                state,
            } => write!(
                f,
                "HVF synchronization monitor returned {exit:?} on lane {lane_generation} for {request:?}; architectural state={state:?}"
            ),
            Self::Cleanup { primary, cleanup } => {
                write!(f, "{primary}; cleanup also failed: {cleanup}")
            }
            Self::RegistryAccounting => write!(f, "HVF vCPU lane registry accounting failed"),
            Self::ResidualVcpus {
                current_thread,
                process,
            } => write!(
                f,
                "HVF vCPU cleanup retained {current_thread} owner-thread and {process} process-wide quarantined vCPUs; the owner lane stays alive as cleanup custodian"
            ),
            Self::FpResidency {
                lane_generation,
                claimed_seq,
            } => write!(
                f,
                "HVF lane {lane_generation} does not hold the guest thread's resident SIMD/FP registers (claimed residency {claimed_seq:?}) and the run carried no host copy"
            ),
        }
    }
}

impl HvfVcpuLaneError {
    fn with_cleanup(self, cleanup: impl Into<Self>) -> Self {
        Self::Cleanup {
            primary: Box::new(self),
            cleanup: Box::new(cleanup.into()),
        }
    }

    /// Errors after which the vCPU's architectural state can no longer be
    /// trusted and the vCPU must be retired rather than resumed.
    fn terminalizes_vcpu(&self) -> bool {
        match self {
            Self::RejectedExit(_)
            | Self::InvalidExecutionState { .. }
            | Self::InvalidSynchronizationExit { .. }
            | Self::UnexpectedCancellation { .. } => true,
            Self::Cleanup { primary, cleanup } => {
                primary.terminalizes_vcpu() || cleanup.terminalizes_vcpu()
            }
            _ => false,
        }
    }

    fn terminalizes_execution_vcpu(&self) -> bool {
        match self {
            Self::Hvf(_) => true,
            Self::Cleanup { primary, cleanup } => {
                primary.terminalizes_execution_vcpu() || cleanup.terminalizes_execution_vcpu()
            }
            _ => self.terminalizes_vcpu(),
        }
    }
}

impl std::error::Error for HvfVcpuLaneError {}

/// T2d: the run scope's single existing-vCPU operation ([`HvfVcpu::with_run_scope`]) is generic
/// over its body's error, and a failure observed after the frame was published has to be tagged
/// exactly as the per-operation path tagged it.
impl HvfOperationError for HvfVcpuLaneError {
    fn after_hvf_publication(self) -> Self {
        match self {
            Self::Hvf(error) => Self::Hvf(error.after_hvf_publication()),
            other => other,
        }
    }
}

impl From<HvfError> for HvfVcpuLaneError {
    fn from(value: HvfError) -> Self {
        Self::Hvf(value)
    }
}

impl From<HvfMemoryError> for HvfVcpuLaneError {
    fn from(value: HvfMemoryError) -> Self {
        Self::Memory(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HvfSynchronizationRequest {
    pub address_space_id: u64,
    pub participant_id: u64,
    pub asid: u8,
    pub asid_epoch: u64,
    pub synchronization_ttbr0_el1: u64,
    pub ttbr0_el1: u64,
    pub tcr_el1: u64,
    pub mair_el1: u64,
    pub root_generation: u64,
    pub executable_generation: u64,
    pub tlbi_generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HvfSynchronizationExitState {
    pub pc: u64,
    pub cpsr: u64,
    pub spsr_el1: u64,
    pub elr_el1: u64,
    pub esr_el1: u64,
    pub far_el1: u64,
}

impl From<&HvfArchitecturalState> for HvfSynchronizationExitState {
    fn from(state: &HvfArchitecturalState) -> Self {
        Self {
            pc: state.pc,
            cpsr: state.cpsr,
            spsr_el1: state.spsr_el1,
            elr_el1: state.elr_el1,
            esr_el1: state.esr_el1,
            far_el1: state.far_el1,
        }
    }
}

/// Proof, minted only by an owner thread that actually ran the EL1
/// synchronization monitor under the immutable ASID-zero bootstrap root, that
/// the requested nonzero ASID was invalidated, and that the requested target
/// root was installed afterwards. Deliberately not `Clone`/`Copy`: one monitor
/// trip yields exactly one acknowledgement.
#[derive(Debug, Eq, PartialEq)]
pub struct HvfOwnerSynchronizationProof {
    lane_generation: u64,
    request: HvfSynchronizationRequest,
    synchronization_epoch: u64,
    execution_time: u64,
}

impl HvfOwnerSynchronizationProof {
    pub const fn lane_generation(&self) -> u64 {
        self.lane_generation
    }

    pub const fn request(&self) -> HvfSynchronizationRequest {
        self.request
    }

    pub const fn synchronization_epoch(&self) -> u64 {
        self.synchronization_epoch
    }

    pub const fn execution_time(&self) -> u64 {
        self.execution_time
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HvfVcpuExitState {
    DirectGuest(HvfArchitecturalState),
    LowerElMonitor(HvfArchitecturalState),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HvfVcpuRunResult {
    pub exit: HvfVcpuExit,
    pub state: HvfVcpuExitState,
    pub run_epoch: u64,
    /// Wall nanoseconds the owner thread spent inside `hv_vcpu_run` for this result (summed
    /// over reruns): the subtrahend of `diagnostics_counters`' exit-to-reentry handoff cost.
    pub run_wall_ns: u64,
    /// Wall nanoseconds of the owner thread's whole `execute_attached` service for this result
    /// (synchronization trip, state marshalling, the run, settle/finish); `0` for a result that
    /// never went through an owner thread (a diagnostic's direct construction).
    pub owner_ns: u64,
    /// Operation-gate mutex acquisitions the owner thread made for this result.
    pub owner_gate_locks: u64,
    /// Host ticks from the guest stamping the command to the owner starting it.
    pub owner_wake_ticks: u64,
    /// Host tick at which the owner finished `execute_attached`.
    pub owner_end_ticks: u64,
    /// Host tick at which the owner sent the reply; `0` when no owner thread was involved.
    pub replied_at_ticks: u64,
    /// FXR: where the thread's SIMD/FP file is after this run.
    pub fp: HvfExitFp,
}

/// FXR: where a guest thread's SIMD/FP file (Q0-Q31, FPCR, FPSR) is after a run.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HvfExitFp {
    /// The result's architectural state carries it.
    Materialized,
    /// It stayed resident in the lane's vCPU under this identity; the result state's
    /// Q/FPCR/FPSR are zero and must never be read. The lane hands it back to the thread's
    /// [`HvfGuestRegisterCell`] before anything overwrites it, or on request.
    Resident { lane_generation: u64, seq: u64 },
}

/// FXR: how a guest thread's run treats its SIMD/FP file (see
/// [`HvfVcpuLaneHandle::run_guest_reserved`]).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HvfGuestFpClaim {
    /// The residency sequence of the SIMD file the thread believes this lane holds for it.
    pub resident_seq: Option<u64>,
    /// The run state's Q/FPCR/FPSR are the thread's current SIMD file.
    pub host_valid: bool,
}

/// FXR: a SIMD/FP file a lane handed back to its thread, or `fp: None` when the vCPU holding it
/// was already gone (the thread must fail loudly rather than run on with invented values).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HvfFpDeposit {
    pub lane_generation: u64,
    pub seq: u64,
    pub(crate) fp: Option<HvfGuestFp>,
    /// The lane still holds the same values resident (a requested materialization).
    pub still_resident: bool,
}

/// FXR: one guest thread's SIMD/FP custody cell for the resident-register cache -- its identity
/// (pointer identity of the `Arc`) and the mailbox a lane hands the thread's SIMD file back
/// through when that file was left resident in the lane's vCPU (exit reads skip it) and the lane
/// must give it up: another thread's run, a synchronization trip, the lane closing, or the thread
/// asking for it.
pub struct HvfGuestRegisterCell {
    mailbox: Mutex<Vec<HvfFpDeposit>>,
    deposited: Condvar,
    /// Deposits pushed so far, so the owning thread can skip the mailbox lock while none arrived.
    deposits: AtomicU64,
}

impl fmt::Debug for HvfGuestRegisterCell {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HvfGuestRegisterCell")
            .field("deposits", &self.deposits.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl HvfGuestRegisterCell {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            mailbox: Mutex::new(Vec::new()),
            deposited: Condvar::new(),
            deposits: AtomicU64::new(0),
        })
    }

    fn deposit(&self, deposit: HvfFpDeposit) {
        let mut mailbox = self
            .mailbox
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        mailbox.push(deposit);
        self.deposits.fetch_add(1, Ordering::Release);
        drop(mailbox);
        self.deposited.notify_all();
    }

    /// Deposits pushed so far.
    pub fn deposit_count(&self) -> u64 {
        self.deposits.load(Ordering::Acquire)
    }

    fn take_locked(
        mailbox: &mut Vec<HvfFpDeposit>,
        lane_generation: u64,
        seq: u64,
    ) -> (Option<HvfFpDeposit>, usize) {
        let position = mailbox
            .iter()
            .rposition(|deposit| deposit.lane_generation == lane_generation && deposit.seq == seq);
        let taken = position.map(|position| mailbox.swap_remove(position));
        let stale = mailbox.len();
        mailbox.clear();
        (taken, stale)
    }

    /// Removes the deposit for residency `(lane_generation, seq)` if one arrived, discarding every
    /// other (stale) deposit; returns it and the number discarded. A thread has exactly one
    /// residency at a time, so a deposit for any other identity is out of date.
    pub fn take(&self, lane_generation: u64, seq: u64) -> (Option<HvfFpDeposit>, usize) {
        let mut mailbox = self
            .mailbox
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Self::take_locked(&mut mailbox, lane_generation, seq)
    }

    /// Discards every deposit (the thread's SIMD file is authoritative on the host).
    pub fn discard_all(&self) -> usize {
        let mut mailbox = self
            .mailbox
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let discarded = mailbox.len();
        mailbox.clear();
        discarded
    }

    /// [`Self::take`], waiting until `deadline` for the deposit to arrive.
    pub fn wait_take(
        &self,
        lane_generation: u64,
        seq: u64,
        deadline: Instant,
    ) -> (Option<HvfFpDeposit>, usize) {
        let mut mailbox = self
            .mailbox
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut discarded = 0;
        loop {
            let (taken, stale) = Self::take_locked(&mut mailbox, lane_generation, seq);
            discarded += stale;
            if taken.is_some() {
                return (taken, discarded);
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return (None, discarded);
            }
            crate::diagnostics_counters::rank_note_blocking_wait(
                crate::diagnostics_counters::RK_WAIT_WHILE_HOLDING,
                std::panic::Location::caller(),
            );
            mailbox = self
                .deposited
                .wait_timeout(mailbox, remaining)
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .0;
        }
    }
}

/// FXR, owner-thread-local: the guest thread whose SIMD/FP file this lane's vCPU holds resident
/// (left unread by that thread's last exit read).
struct LaneFpHolder {
    cell: Arc<HvfGuestRegisterCell>,
    seq: u64,
    /// The thread already holds a host copy (a requested materialization handed it one while the
    /// file stayed resident): giving the file up needs no read.
    saved: bool,
}

/// FXR, owner-thread-local residency bookkeeping of one lane.
struct LaneResidency {
    lane_generation: u64,
    holder: Option<LaneFpHolder>,
    next_seq: u64,
}

impl LaneResidency {
    const fn new(lane_generation: u64) -> Self {
        Self {
            lane_generation,
            holder: None,
            next_seq: 1,
        }
    }

    fn deposit(&self, holder: &LaneFpHolder, fp: Option<HvfGuestFp>, still_resident: bool) {
        holder.cell.deposit(HvfFpDeposit {
            lane_generation: self.lane_generation,
            seq: holder.seq,
            fp,
            still_resident,
        });
    }

    /// Gives the resident SIMD file up: hands it back to its thread (reading it out of the vCPU
    /// unless the thread already has a copy) and forgets the holder, after which the vCPU's SIMD
    /// file may be overwritten. `reason` is the `RESIDENT_DEPOSITS_*` counter to credit. A failed
    /// read deposits a loss marker (the thread fails at its next SIMD use) and returns the error.
    fn surrender(&mut self, vcpu: &mut HvfVcpu, reason: usize) -> Result<(), HvfVcpuLaneError> {
        let Some(holder) = self.holder.take() else {
            // Unsaved SIMD state with no holder is an orphan: only a run that failed after
            // entering the guest leaves one, and that run's thread received the failure. Nobody
            // can ever claim it.
            vcpu.discard_unsaved_fp();
            return Ok(());
        };
        if holder.saved {
            // Review fix-up (FXR-c1): `saved` is set only by [`Self::materialize`], right after a
            // successful `read_guest_fp()` that already cleared this flag, so this is a no-op
            // today. Clearing it here anyway makes the invariant local: whatever the vCPU still
            // holds after a `saved` holder is by definition already in the thread's copy, so no
            // later `HvfFpInstall::Install` may be refused for it. Without it the proof that
            // [`HvfError::ResidentFpUnsaved`] is unreachable here needs a non-local argument about
            // how `saved` is set and cleared.
            vcpu.discard_unsaved_fp();
            return Ok(());
        }
        match vcpu.read_guest_fp() {
            Ok(fp) => {
                self.deposit(&holder, Some(fp), false);
                crate::diagnostics_counters::record_resident(reason, 1);
                Ok(())
            }
            Err(error) => {
                self.deposit(&holder, None, false);
                crate::diagnostics_counters::record_resident(
                    crate::diagnostics_counters::RESIDENT_FP_LOST,
                    1,
                );
                Err(error.into())
            }
        }
    }

    /// The lane is going away: hand the resident SIMD file back while the vCPU can still be read,
    /// or record its loss.
    fn surrender_at_close(&mut self, mut vcpu: Option<&mut HvfVcpu>) {
        let Some(holder) = self.holder.as_ref() else {
            return;
        };
        if holder.saved {
            // Same local invariant as [`Self::surrender`]: a `saved` holder's file is already in
            // the thread's copy, so the vCPU holds nothing that must not be overwritten.
            if let Some(vcpu) = vcpu.as_deref_mut() {
                vcpu.discard_unsaved_fp();
            }
            self.holder = None;
            return;
        }
        match vcpu {
            Some(vcpu) if vcpu.is_live() => {
                let _ = self.surrender(vcpu, crate::diagnostics_counters::RESIDENT_DEPOSITS_CLOSE);
            }
            _ => {
                if let Some(holder) = self.holder.take() {
                    self.deposit(&holder, None, false);
                    crate::diagnostics_counters::record_resident(
                        crate::diagnostics_counters::RESIDENT_FP_LOST,
                        1,
                    );
                }
            }
        }
    }

    /// `MaterializeFp`: hands a copy of the resident SIMD file `(cell, seq)` to its thread while it
    /// stays resident. Not held (already handed back, or never here): nothing to do -- the
    /// deposit that gave it up is already in the thread's mailbox.
    fn materialize(
        &mut self,
        vcpu: &mut HvfVcpu,
        cell: &Arc<HvfGuestRegisterCell>,
        seq: u64,
    ) -> Result<(), HvfVcpuLaneError> {
        let Some(holder) = self.holder.as_mut() else {
            return Ok(());
        };
        if !Arc::ptr_eq(&holder.cell, cell) || holder.seq != seq {
            return Ok(());
        }
        match vcpu.read_guest_fp() {
            Ok(fp) => {
                holder.saved = true;
                holder.cell.deposit(HvfFpDeposit {
                    lane_generation: self.lane_generation,
                    seq,
                    fp: Some(fp),
                    still_resident: true,
                });
                crate::diagnostics_counters::record_resident(
                    crate::diagnostics_counters::RESIDENT_DEPOSITS_MATERIALIZE,
                    1,
                );
                Ok(())
            }
            Err(error) => {
                if let Some(holder) = self.holder.take() {
                    self.deposit(&holder, None, false);
                }
                crate::diagnostics_counters::record_resident(
                    crate::diagnostics_counters::RESIDENT_FP_LOST,
                    1,
                );
                Err(error.into())
            }
        }
    }
}

/// FXR: the guest-thread part of an `Execute` command (absent for full-mode runs).
struct HvfGuestRun {
    cell: Arc<HvfGuestRegisterCell>,
    claim: HvfGuestFpClaim,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HvfVtimerState {
    pub masked: bool,
    pub offset: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HvfVcpuLaneCloseReport {
    pub lane_generation: u64,
    pub cleanup_attempts: usize,
    pub residual_vcpus: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HvfVcpuCancellationReceipt {
    pub lane_generation: u64,
    pub sequence: u64,
    pub observed_run_epoch: u64,
}

impl HvfVcpuCancellationReceipt {
    const fn from_key(key: CancellationAttemptKey) -> Self {
        Self {
            lane_generation: key.lane_generation,
            sequence: key.sequence,
            observed_run_epoch: key.target.epoch(),
        }
    }
}

// ---------------------------------------------------------------------------
// Run control: the owner's execution phase plus linear cancellation attempts.
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExecutionPhase {
    Idle,
    Reserved {
        run_epoch: u64,
    },
    Synchronizing {
        synchronization_epoch: u64,
        run_epoch: Option<u64>,
    },
    Entering {
        run_epoch: u64,
    },
    Running {
        run_epoch: u64,
    },
    /// The run outcome is fixed: either `hv_vcpu_run` returned or a pre-entry
    /// cancellation was already applied. Owner-side exit/state validation and
    /// reservation settlement are not complete, but another public cancellation
    /// is too late and must not be mistaken for pre-entry.
    Completing {
        run_epoch: u64,
    },
    Terminal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CancellationTarget {
    Synchronization { synchronization_epoch: u64 },
    Run { run_epoch: u64 },
}

impl CancellationTarget {
    const fn epoch(self) -> u64 {
        match self {
            Self::Synchronization {
                synchronization_epoch,
            } => synchronization_epoch,
            Self::Run { run_epoch } => run_epoch,
        }
    }
}

#[derive(Clone, Debug)]
enum CancellationCompletion {
    /// The targeted run exited with `Canceled` because of this attempt.
    Applied,
    /// The targeted run had already exited when the kick landed.
    TooLate,
    /// The kick itself could not be issued.
    Failed(HvfError),
    /// The requester stopped waiting before the owner observed the outcome.
    Expired,
    Terminalized,
}

#[derive(Clone, Debug)]
enum CancellationProgress {
    Issuing,
    Issued,
    Completed(CancellationCompletion),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CancellationAttemptKey {
    lane_generation: u64,
    sdk_generation: u64,
    sequence: u64,
    target: CancellationTarget,
}

struct CancellationAttempt {
    key: CancellationAttemptKey,
    progress: Mutex<CancellationProgress>,
    changed: Condvar,
}

impl CancellationAttempt {
    fn new(key: CancellationAttemptKey) -> Self {
        Self {
            key,
            progress: Mutex::new(CancellationProgress::Issuing),
            changed: Condvar::new(),
        }
    }

    const fn key(&self) -> CancellationAttemptKey {
        self.key
    }

    fn progress(&self) -> CancellationProgress {
        self.progress
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    fn mark_issued(&self) -> Result<(), HvfVcpuLaneError> {
        let mut progress = self
            .progress
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !matches!(*progress, CancellationProgress::Issuing) {
            return Err(HvfVcpuLaneError::RegistryAccounting);
        }
        *progress = CancellationProgress::Issued;
        self.changed.notify_all();
        Ok(())
    }

    /// Records the outcome exactly once; returns `false` if it was already
    /// completed by the other side.
    fn complete(&self, completion: CancellationCompletion) -> bool {
        let mut progress = self
            .progress
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !matches!(
            *progress,
            CancellationProgress::Issuing | CancellationProgress::Issued
        ) {
            return false;
        }
        *progress = CancellationProgress::Completed(completion);
        self.changed.notify_all();
        true
    }

    fn wait_until(&self, deadline: Instant) -> Option<CancellationCompletion> {
        let mut progress = self
            .progress
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        loop {
            if let CancellationProgress::Completed(completion) = &*progress {
                return Some(completion.clone());
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return None;
            }
            crate::diagnostics_counters::rank_note_blocking_wait(
                crate::diagnostics_counters::RK_WAIT_WHILE_HOLDING,
                std::panic::Location::caller(),
            );
            let (next, _) = self
                .changed
                .wait_timeout(progress, remaining.min(CONTROL_WAIT_POLL))
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            progress = next;
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RunDisposition {
    /// Deliver the exit to the requester.
    Deliver,
    /// The exit was a spurious `Canceled` produced by a stale kick; run again.
    Rerun,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SynchronizationDisposition {
    Completed,
    Rerun,
    Canceled(HvfVcpuCancellationReceipt),
}

struct RunControlState {
    phase: ExecutionPhase,
    synchronization_epoch: u64,
    run_epoch: u64,
    cancellation_sequence: u64,
    cancellation: Option<Arc<CancellationAttempt>>,
    /// A public cancellation that arrived while the owner was between
    /// admitting a run and entering the guest (synchronizing or entering).
    /// No SDK kick is issued for it; `begin_running` consumes it and the run
    /// completes as `Canceled` without entering the guest.  This closes the
    /// window in which an interrupt aimed at a run in progress would otherwise
    /// be reported as "not running" and lost until the guest's next exit.
    latched: Option<Arc<CancellationAttempt>>,
    shutdown_requested: bool,
    /// BCORE-2: a kick was issued after its target run had already exited; the SDK may
    /// deliver it as an immediate `Canceled` on the next `hv_vcpu_run`.
    ///
    /// This is a COUNT, not a bool. A bound run is ~2-3 us wide where a pooled run is ~2.2 us
    /// of `hv_vcpu_run` plus ~11 us of hand-off, so on the bound path kicks arrive while the
    /// same vCPU is already several runs further along and each of them owes one spurious
    /// `Canceled`; a bool merged them and the accounting was not exact. Lane behaviour is
    /// unchanged: at most one attempt exists per epoch (`next_cancellation_attempt` refuses a
    /// second) and every epoch's first exit resolves the previous count, so outside the
    /// shutdown / issue-failure arms `n <= 1` and `n > 0` is exactly the old bool.
    pending_stale_kicks: u32,
    /// BCORE-2: kicks issued for this vCPU that no exit has resolved yet (the debit ledger of
    /// the identity `issued == consumed + drained + expired_unlatched + expired_terminal +
    /// expired_latched + abandoned`).
    /// Maintained only while [`RunControl::bound`]. Every resolution discharges one debit
    /// (`note_consumed_kick`, `note_expired_kick`, or `note_stale_kick`, which moves it onto
    /// `pending_stale_kicks` until a later `drain_stale_kick` / `expire_unlatched` /
    /// `terminalize` resolves it); `terminalize` is the discharger of last resort, and a bound
    /// vCPU's `unbind`/`Drop` call it before destroying the vCPU, so a bound teardown reports
    /// what it abandoned instead of dropping the debit in silence.
    issued_unresolved: u32,
    /// BCORE-2: whether this control drives a bound vCPU (kick accounting is published).
    bound: bool,
    /// The terminal phase was reached because the vCPU's state can no longer
    /// be trusted (inconsistent phase, unauthenticated exit, lost kick), as
    /// opposed to an orderly shutdown.  Only an untrusted vCPU is quarantined;
    /// a shut-down one is destroyed normally.
    untrusted: bool,
}

pub(crate) struct RunControl {
    state: Mutex<RunControlState>,
    changed: Condvar,
}

impl RunControl {
    /// A pooled lane's control (`bound = false`: lane kick behaviour, no published
    /// accounting).
    fn new() -> Self {
        Self::new_bound(false)
    }

    /// BCORE-2: `bound = true` for a control that drives a bound vCPU, which publishes the
    /// kick identity `issued == consumed + drained + expired_unlatched + expired_terminal +
    /// expired_latched + abandoned`.
    pub(crate) fn new_bound(bound: bool) -> Self {
        Self {
            state: Mutex::new(RunControlState {
                phase: ExecutionPhase::Idle,
                synchronization_epoch: 0,
                run_epoch: 0,
                cancellation_sequence: 0,
                cancellation: None,
                latched: None,
                shutdown_requested: false,
                pending_stale_kicks: 0,
                issued_unresolved: 0,
                bound,
                untrusted: false,
            }),
            changed: Condvar::new(),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, RunControlState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// BCORE-2: one kick was issued for this vCPU. Charges the debit ledger.
    fn note_issued_kick(&self, state: &mut RunControlState) {
        if state.bound {
            state.issued_unresolved = state.issued_unresolved.saturating_add(1);
            crate::diagnostics_counters::add_stat(
                crate::diagnostics_counters::BOUND_KICKS_ISSUED,
                1,
            );
        }
    }

    /// BCORE-2: an exit came back `Canceled` and this attempt caused it. Discharges the debit.
    fn note_consumed_kick(&self, state: &mut RunControlState) {
        if state.bound {
            state.issued_unresolved = state.issued_unresolved.saturating_sub(1);
            crate::diagnostics_counters::add_stat(
                crate::diagnostics_counters::BOUND_KICKS_CONSUMED,
                1,
            );
        }
    }

    /// BCORE-2: a kick landed too late (or its requester stopped waiting), so the SDK may
    /// still deliver it as a spurious `Canceled` on a later run. Moves one debit onto
    /// `pending_stale_kicks`.
    fn note_stale_kick(&self, state: &mut RunControlState) {
        state.pending_stale_kicks = state.pending_stale_kicks.saturating_add(1);
        if state.bound {
            state.issued_unresolved = state.issued_unresolved.saturating_sub(1);
        }
    }

    /// BCORE-2 (fix-up): a kick whose requester gave up waiting is discharged as `expired`
    /// rather than moved onto `pending_stale_kicks`: the attempt that expired here had already
    /// been taken out of the kick slot (`state.latched`), so no SDK `hv_vcpus_exit` was ever
    /// issued for it and there is no spurious `Canceled` still owed. Without this the debit
    /// `note_issued_kick` charged stays on `issued_unresolved` until the vCPU is terminalized,
    /// which is why the identity used to close only "once the vCPU is idle".
    fn note_expired_kick(&self, state: &mut RunControlState) {
        if state.bound {
            state.issued_unresolved = state.issued_unresolved.saturating_sub(1);
            crate::diagnostics_counters::add_stat(
                crate::diagnostics_counters::BOUND_KICKS_EXPIRED_LATCHED,
                1,
            );
        }
    }

    /// BCORE-2: a spurious `Canceled` was consumed by `pending_stale_kicks`, so the run is
    /// rerun instead of delivered. Returns `false` when nothing was pending (a genuinely
    /// unauthenticated cancellation).
    fn drain_stale_kick(&self, state: &mut RunControlState) -> bool {
        match state.pending_stale_kicks.checked_sub(1) {
            Some(pending) => {
                state.pending_stale_kicks = pending;
                if state.bound {
                    crate::diagnostics_counters::add_stat(
                        crate::diagnostics_counters::BOUND_KICKS_DRAINED,
                        1,
                    );
                }
                true
            }
            None => false,
        }
    }

    /// BCORE-2: a non-`Canceled` exit proves no HVF latch was pending at entry (a latched
    /// kick ends the next run as `Canceled` before guest entry), so every still-pending stale
    /// kick expired without ever latching.
    fn expire_unlatched(&self, state: &mut RunControlState) {
        let pending = core::mem::take(&mut state.pending_stale_kicks);
        if state.bound && pending != 0 {
            crate::diagnostics_counters::add_stat(
                crate::diagnostics_counters::BOUND_KICKS_EXPIRED_UNLATCHED,
                u64::from(pending),
            );
        }
    }

    fn phase(&self) -> ExecutionPhase {
        self.lock().phase
    }

    fn is_running(&self) -> bool {
        matches!(self.phase(), ExecutionPhase::Running { .. })
    }

    fn is_terminal(&self) -> bool {
        self.phase() == ExecutionPhase::Terminal
    }

    fn is_untrusted(&self) -> bool {
        self.lock().untrusted
    }

    fn is_reusable(&self) -> bool {
        let state = self.lock();
        state.phase == ExecutionPhase::Idle
            && state.cancellation.is_none()
            && state.latched.is_none()
            && !state.shutdown_requested
            && !state.untrusted
    }

    fn run_epoch(&self) -> u64 {
        self.lock().run_epoch
    }

    fn complete_attempt(
        slot: &mut Option<Arc<CancellationAttempt>>,
        completion: CancellationCompletion,
    ) {
        if let Some(attempt) = slot.take() {
            let _ = attempt.complete(completion);
        }
    }

    fn terminalize(
        &self,
        state: &mut RunControlState,
        untrusted: bool,
        latched_completion: CancellationCompletion,
    ) {
        Self::complete_attempt(
            &mut state.cancellation,
            CancellationCompletion::Terminalized,
        );
        Self::complete_attempt(&mut state.latched, latched_completion);
        state.phase = ExecutionPhase::Terminal;
        // BCORE-2: `terminalize` is the discharger of last resort -- a vCPU that is going
        // away can never consume a stale kick, and the debits it still owes move onto
        // `expired_terminal` so the identity closes.
        let pending = core::mem::take(&mut state.pending_stale_kicks);
        let unresolved = core::mem::take(&mut state.issued_unresolved);
        if state.bound {
            if pending != 0 {
                crate::diagnostics_counters::add_stat(
                    crate::diagnostics_counters::BOUND_KICKS_EXPIRED_TERMINAL,
                    u64::from(pending),
                );
            }
            if unresolved != 0 {
                crate::diagnostics_counters::add_stat(
                    crate::diagnostics_counters::BOUND_KICKS_ABANDONED,
                    u64::from(unresolved),
                );
            }
        }
        state.untrusted |= untrusted;
        self.changed.notify_all();
    }

    fn set_terminal(&self, state: &mut RunControlState) {
        self.terminalize(state, true, CancellationCompletion::Terminalized);
    }

    fn set_orderly_terminal(&self, state: &mut RunControlState) {
        self.terminalize(state, false, CancellationCompletion::Applied);
    }

    fn settle_synchronization(
        &self,
        state: &mut RunControlState,
        run_epoch: Option<u64>,
        failed: bool,
    ) {
        if failed {
            self.set_terminal(state);
        } else if state.shutdown_requested {
            self.set_orderly_terminal(state);
        } else {
            state.phase = match run_epoch {
                Some(run_epoch) => ExecutionPhase::Reserved { run_epoch },
                None => ExecutionPhase::Idle,
            };
            self.changed.notify_all();
        }
    }

    fn settle_run(&self, state: &mut RunControlState, run_epoch: u64, failed: bool) {
        if failed {
            self.set_terminal(state);
        } else if state.shutdown_requested {
            self.set_orderly_terminal(state);
        } else {
            state.phase = ExecutionPhase::Completing { run_epoch };
            self.changed.notify_all();
        }
    }

    fn next_cancellation_attempt(
        state: &mut RunControlState,
        lane_generation: u64,
        cancellation: &HvfVcpuCancellation,
        target: CancellationTarget,
    ) -> Result<Arc<CancellationAttempt>, HvfVcpuLaneError> {
        if let Some(attempt) = state.cancellation.as_ref() {
            return Err(HvfVcpuLaneError::CancellationInFlight {
                sequence: attempt.key().sequence,
                run_epoch: attempt.key().target.epoch(),
            });
        }
        let sequence = state
            .cancellation_sequence
            .checked_add(1)
            .ok_or(HvfVcpuLaneError::RegistryAccounting)?;
        let attempt = Arc::new(CancellationAttempt::new(CancellationAttemptKey {
            lane_generation,
            sdk_generation: cancellation.generation(),
            sequence,
            target,
        }));
        state.cancellation_sequence = sequence;
        state.cancellation = Some(Arc::clone(&attempt));
        Ok(attempt)
    }

    /// Issues the SDK kick while the control lock is held, so the owner's
    /// `finish_*` (which needs the same lock) observes the attempt either
    /// fully issued or fully withdrawn, never half-way.
    fn issue_cancellation(
        &self,
        state: &mut RunControlState,
        attempt: &Arc<CancellationAttempt>,
        cancellation: &HvfVcpuCancellation,
    ) -> Result<(), HvfVcpuLaneError> {
        match cancellation.cancel() {
            Ok(()) => match attempt.mark_issued() {
                Ok(()) => Ok(()),
                Err(error) => {
                    let _ = attempt.complete(CancellationCompletion::Terminalized);
                    state.shutdown_requested = true;
                    self.expire_unlatched(state);
                    self.note_stale_kick(state);
                    state.untrusted = true;
                    self.changed.notify_all();
                    Err(error)
                }
            },
            Err(error) => {
                if !attempt.complete(CancellationCompletion::Failed(error.clone())) {
                    state.shutdown_requested = true;
                    self.expire_unlatched(state);
                    self.note_stale_kick(state);
                    state.untrusted = true;
                    self.changed.notify_all();
                    return Err(HvfVcpuLaneError::RegistryAccounting);
                }
                state.shutdown_requested = true;
                self.expire_unlatched(state);
                self.note_stale_kick(state);
                state.untrusted = true;
                self.changed.notify_all();
                Err(error.into())
            }
        }
    }

    fn abandon_timed_out_attempt(&self, attempt: &CancellationAttempt) {
        let _ = attempt.complete(CancellationCompletion::Expired);
        let mut state = self.lock();
        state.shutdown_requested = true;
        state.untrusted = true;
        self.changed.notify_all();
    }

    fn await_attempt(
        &self,
        attempt: &CancellationAttempt,
        deadline: Instant,
    ) -> Result<HvfVcpuCancellationReceipt, HvfVcpuLaneError> {
        let key = attempt.key();
        let completion = if let Some(completion) = attempt.wait_until(deadline) {
            completion
        } else if attempt.complete(CancellationCompletion::Expired) {
            self.abandon_timed_out_attempt(attempt);
            return Err(HvfVcpuLaneError::OperationTimeout);
        } else {
            match attempt.progress() {
                CancellationProgress::Completed(completion) => completion,
                CancellationProgress::Issuing | CancellationProgress::Issued => {
                    return Err(HvfVcpuLaneError::RegistryAccounting);
                }
            }
        };
        match completion {
            CancellationCompletion::Applied => Ok(HvfVcpuCancellationReceipt::from_key(key)),
            CancellationCompletion::TooLate => Err(HvfVcpuLaneError::CancellationTooLate {
                sequence: key.sequence,
                run_epoch: key.target.epoch(),
            }),
            CancellationCompletion::Failed(error) => Err(error.into()),
            CancellationCompletion::Expired => {
                self.abandon_timed_out_attempt(attempt);
                Err(HvfVcpuLaneError::OperationTimeout)
            }
            CancellationCompletion::Terminalized => Err(HvfVcpuLaneError::LaneClosed),
        }
    }

    fn reserve_run(&self) -> Result<u64, HvfVcpuLaneError> {
        let mut state = self.lock();
        if state.shutdown_requested {
            return Err(HvfVcpuLaneError::LaneClosed);
        }
        match state.phase {
            ExecutionPhase::Idle => {}
            ExecutionPhase::Terminal => return Err(HvfVcpuLaneError::LaneTerminal),
            _ => return Err(HvfVcpuLaneError::RegistryAccounting),
        }
        if state.cancellation.is_some() || state.latched.is_some() || state.untrusted {
            self.set_terminal(&mut state);
            return Err(HvfVcpuLaneError::RegistryAccounting);
        }
        let run_epoch = state
            .run_epoch
            .checked_add(1)
            .ok_or(HvfVcpuLaneError::RegistryAccounting)?;
        state.run_epoch = run_epoch;
        state.phase = ExecutionPhase::Reserved { run_epoch };
        self.changed.notify_all();
        Ok(run_epoch)
    }

    fn begin_synchronizing(&self, run_epoch: Option<u64>) -> Result<u64, HvfVcpuLaneError> {
        let mut state = self.lock();
        if state.shutdown_requested {
            return Err(HvfVcpuLaneError::LaneClosed);
        }
        match (state.phase, run_epoch) {
            (ExecutionPhase::Idle, None) => {}
            (
                ExecutionPhase::Reserved {
                    run_epoch: reserved,
                },
                Some(run_epoch),
            ) if reserved == run_epoch => {}
            (ExecutionPhase::Terminal, _) => return Err(HvfVcpuLaneError::LaneTerminal),
            _ => return Err(HvfVcpuLaneError::RegistryAccounting),
        }
        if state.cancellation.is_some() || (run_epoch.is_none() && state.latched.is_some()) {
            self.set_terminal(&mut state);
            return Err(HvfVcpuLaneError::RegistryAccounting);
        }
        let synchronization_epoch = state
            .synchronization_epoch
            .checked_add(1)
            .ok_or(HvfVcpuLaneError::RegistryAccounting)?;
        state.synchronization_epoch = synchronization_epoch;
        state.phase = ExecutionPhase::Synchronizing {
            synchronization_epoch,
            run_epoch,
        };
        self.changed.notify_all();
        Ok(synchronization_epoch)
    }

    fn finish_synchronizing(
        &self,
        synchronization_epoch: u64,
        exit: &Result<HvfVcpuExit, HvfError>,
    ) -> Result<SynchronizationDisposition, HvfVcpuLaneError> {
        let mut state = self.lock();
        let run_epoch = match state.phase {
            ExecutionPhase::Synchronizing {
                synchronization_epoch: active_epoch,
                run_epoch,
            } if active_epoch == synchronization_epoch => run_epoch,
            _ => {
                self.set_terminal(&mut state);
                return Err(HvfVcpuLaneError::RegistryAccounting);
            }
        };
        let target = CancellationTarget::Synchronization {
            synchronization_epoch,
        };
        let canceled = matches!(exit, Ok(HvfVcpuExit::Canceled));
        let attempt = state
            .cancellation
            .as_ref()
            .filter(|attempt| attempt.key().target == target)
            .cloned();
        match (canceled, attempt) {
            (true, Some(attempt)) => {
                match attempt.progress() {
                    CancellationProgress::Issued => {
                        if !attempt.complete(CancellationCompletion::Applied) {
                            self.set_terminal(&mut state);
                            return Err(HvfVcpuLaneError::RegistryAccounting);
                        }
                    }
                    CancellationProgress::Completed(CancellationCompletion::Expired) => {}
                    _ => {
                        self.set_terminal(&mut state);
                        return Err(HvfVcpuLaneError::UnexpectedCancellation {
                            run_epoch: synchronization_epoch,
                        });
                    }
                }
                state.cancellation = None;
                self.note_consumed_kick(&mut state);
                self.set_orderly_terminal(&mut state);
                Ok(SynchronizationDisposition::Canceled(
                    HvfVcpuCancellationReceipt::from_key(attempt.key()),
                ))
            }
            (true, None) => {
                if self.drain_stale_kick(&mut state) {
                    self.settle_synchronization(&mut state, run_epoch, false);
                    Ok(SynchronizationDisposition::Rerun)
                } else {
                    self.set_terminal(&mut state);
                    Err(HvfVcpuLaneError::UnexpectedCancellation {
                        run_epoch: synchronization_epoch,
                    })
                }
            }
            (false, Some(attempt)) => {
                match attempt.progress() {
                    CancellationProgress::Issued => {
                        if !attempt.complete(CancellationCompletion::TooLate) {
                            self.set_terminal(&mut state);
                            return Err(HvfVcpuLaneError::RegistryAccounting);
                        }
                        self.expire_unlatched(&mut state);
                        self.note_stale_kick(&mut state);
                    }
                    CancellationProgress::Completed(CancellationCompletion::Expired) => {
                        self.expire_unlatched(&mut state);
                        self.note_stale_kick(&mut state);
                    }
                    CancellationProgress::Completed(CancellationCompletion::Failed(_)) => {}
                    _ => {
                        self.set_terminal(&mut state);
                        return Err(HvfVcpuLaneError::RegistryAccounting);
                    }
                }
                state.cancellation = None;
                self.settle_synchronization(&mut state, run_epoch, exit.is_err());
                Ok(SynchronizationDisposition::Completed)
            }
            (false, None) => {
                self.expire_unlatched(&mut state);
                self.settle_synchronization(&mut state, run_epoch, exit.is_err());
                Ok(SynchronizationDisposition::Completed)
            }
        }
    }

    fn begin_run(&self, run_epoch: u64) -> Result<(), HvfVcpuLaneError> {
        let mut state = self.lock();
        if state.shutdown_requested {
            self.set_orderly_terminal(&mut state);
            return Err(HvfVcpuLaneError::LaneClosed);
        }
        match state.phase {
            ExecutionPhase::Reserved {
                run_epoch: reserved,
            } if reserved == run_epoch => {}
            ExecutionPhase::Terminal => return Err(HvfVcpuLaneError::LaneTerminal),
            _ => {
                self.set_terminal(&mut state);
                return Err(HvfVcpuLaneError::RegistryAccounting);
            }
        }
        if state.cancellation.is_some() {
            self.set_terminal(&mut state);
            return Err(HvfVcpuLaneError::RegistryAccounting);
        }
        state.phase = ExecutionPhase::Entering { run_epoch };
        self.changed.notify_all();
        Ok(())
    }

    fn consume_latched(
        &self,
        state: &mut RunControlState,
        run_epoch: u64,
    ) -> Result<bool, HvfVcpuLaneError> {
        let Some(attempt) = state.latched.take() else {
            return Ok(false);
        };
        if attempt.key().target != (CancellationTarget::Run { run_epoch }) {
            let _ = attempt.complete(CancellationCompletion::Terminalized);
            self.set_terminal(state);
            return Err(HvfVcpuLaneError::RegistryAccounting);
        }
        match attempt.progress() {
            CancellationProgress::Issued => {
                if !attempt.complete(CancellationCompletion::Applied) {
                    self.set_terminal(state);
                    return Err(HvfVcpuLaneError::RegistryAccounting);
                }
                // BCORE-2: the latched kick is what ends this run as `Canceled`.
                self.note_consumed_kick(state);
            }
            CancellationProgress::Completed(CancellationCompletion::Expired) => {
                self.note_expired_kick(state);
            }
            _ => {
                self.set_terminal(state);
                return Err(HvfVcpuLaneError::RegistryAccounting);
            }
        }
        Ok(true)
    }

    fn begin_running(&self, run_epoch: u64) -> Result<(), HvfVcpuLaneError> {
        let mut state = self.lock();
        if state.shutdown_requested {
            self.set_orderly_terminal(&mut state);
            return Err(HvfVcpuLaneError::LaneClosed);
        }
        if state.phase != (ExecutionPhase::Entering { run_epoch }) {
            self.set_terminal(&mut state);
            return Err(HvfVcpuLaneError::RegistryAccounting);
        }
        if self.consume_latched(&mut state, run_epoch)? {
            self.settle_run(&mut state, run_epoch, false);
            return Err(HvfVcpuLaneError::LatchedCancellation);
        }
        state.phase = ExecutionPhase::Running { run_epoch };
        self.changed.notify_all();
        Ok(())
    }

    /// BCORE-4: settles a run reservation directly. A lane does this through its
    /// `HvfVcpuRunReservation`; a bound vCPU has no lane object, so it calls this.
    pub(crate) fn settle_reservation(
        &self,
        run_epoch: u64,
        lane_live: bool,
        untrusted: bool,
    ) -> Result<(), HvfVcpuLaneError> {
        let mut state = self.lock();
        match state.phase {
            ExecutionPhase::Reserved {
                run_epoch: reserved,
            }
            | ExecutionPhase::Entering {
                run_epoch: reserved,
            }
            | ExecutionPhase::Completing {
                run_epoch: reserved,
            } if reserved == run_epoch => {
                let preentry = !matches!(state.phase, ExecutionPhase::Completing { .. });
                if untrusted {
                    self.set_terminal(&mut state);
                    return Ok(());
                }
                if state.cancellation.is_some() {
                    self.set_terminal(&mut state);
                    return Err(HvfVcpuLaneError::RegistryAccounting);
                }
                if let Some(attempt) = state.latched.take() {
                    if !preentry {
                        let _ = attempt.complete(CancellationCompletion::Terminalized);
                        self.set_terminal(&mut state);
                        return Err(HvfVcpuLaneError::RegistryAccounting);
                    }
                    if attempt.key().target != (CancellationTarget::Run { run_epoch }) {
                        let _ = attempt.complete(CancellationCompletion::Terminalized);
                        self.set_terminal(&mut state);
                        return Err(HvfVcpuLaneError::RegistryAccounting);
                    }
                    match attempt.progress() {
                        CancellationProgress::Issued => {
                            if !attempt.complete(CancellationCompletion::Applied) {
                                self.set_terminal(&mut state);
                                return Err(HvfVcpuLaneError::RegistryAccounting);
                            }
                            // BCORE-2: a pre-entry latch consumed here.
                            self.note_consumed_kick(&mut state);
                        }
                        CancellationProgress::Completed(CancellationCompletion::Expired) => {
                            self.note_expired_kick(&mut state);
                        }
                        _ => {
                            self.set_terminal(&mut state);
                            return Err(HvfVcpuLaneError::RegistryAccounting);
                        }
                    }
                }
                if lane_live && !state.shutdown_requested {
                    state.phase = ExecutionPhase::Idle;
                    self.changed.notify_all();
                } else {
                    self.set_orderly_terminal(&mut state);
                }
                Ok(())
            }
            ExecutionPhase::Terminal => {
                let was_untrusted = state.untrusted;
                self.terminalize(
                    &mut state,
                    was_untrusted,
                    CancellationCompletion::Terminalized,
                );
                Ok(())
            }
            ExecutionPhase::Synchronizing {
                run_epoch: Some(active),
                ..
            }
            | ExecutionPhase::Running { run_epoch: active }
                if active == run_epoch =>
            {
                self.set_terminal(&mut state);
                Err(HvfVcpuLaneError::RegistryAccounting)
            }
            _ => {
                self.set_terminal(&mut state);
                Err(HvfVcpuLaneError::RegistryAccounting)
            }
        }
    }

    fn finish_run(
        &self,
        run_epoch: u64,
        exit: &Result<HvfVcpuExit, HvfError>,
    ) -> Result<RunDisposition, HvfVcpuLaneError> {
        let mut state = self.lock();
        if state.phase != (ExecutionPhase::Running { run_epoch }) {
            self.set_terminal(&mut state);
            return Err(HvfVcpuLaneError::RegistryAccounting);
        }
        let target = CancellationTarget::Run { run_epoch };
        let canceled = matches!(exit, Ok(HvfVcpuExit::Canceled));
        let attempt = state
            .cancellation
            .as_ref()
            .filter(|attempt| attempt.key().target == target)
            .cloned();
        match (canceled, attempt) {
            (true, Some(attempt)) => {
                match attempt.progress() {
                    CancellationProgress::Issued => {
                        if !attempt.complete(CancellationCompletion::Applied) {
                            self.set_terminal(&mut state);
                            return Err(HvfVcpuLaneError::RegistryAccounting);
                        }
                    }
                    CancellationProgress::Completed(CancellationCompletion::Expired) => {}
                    _ => {
                        self.set_terminal(&mut state);
                        return Err(HvfVcpuLaneError::UnexpectedCancellation { run_epoch });
                    }
                }
                state.cancellation = None;
                self.note_consumed_kick(&mut state);
                self.settle_run(&mut state, run_epoch, false);
                Ok(RunDisposition::Deliver)
            }
            (true, None) => {
                if self.drain_stale_kick(&mut state) {
                    if state.shutdown_requested {
                        self.set_orderly_terminal(&mut state);
                        Ok(RunDisposition::Deliver)
                    } else {
                        state.phase = ExecutionPhase::Reserved { run_epoch };
                        self.changed.notify_all();
                        Ok(RunDisposition::Rerun)
                    }
                } else {
                    self.set_terminal(&mut state);
                    Err(HvfVcpuLaneError::UnexpectedCancellation { run_epoch })
                }
            }
            (false, Some(attempt)) => {
                match attempt.progress() {
                    CancellationProgress::Issued => {
                        if !attempt.complete(CancellationCompletion::TooLate) {
                            self.set_terminal(&mut state);
                            return Err(HvfVcpuLaneError::RegistryAccounting);
                        }
                        self.expire_unlatched(&mut state);
                        self.note_stale_kick(&mut state);
                    }
                    CancellationProgress::Completed(CancellationCompletion::Expired) => {
                        self.expire_unlatched(&mut state);
                        self.note_stale_kick(&mut state);
                    }
                    CancellationProgress::Completed(CancellationCompletion::Failed(_)) => {}
                    _ => {
                        self.set_terminal(&mut state);
                        return Err(HvfVcpuLaneError::RegistryAccounting);
                    }
                }
                state.cancellation = None;
                self.settle_run(&mut state, run_epoch, exit.is_err());
                Ok(RunDisposition::Deliver)
            }
            (false, None) => {
                self.expire_unlatched(&mut state);
                self.settle_run(&mut state, run_epoch, exit.is_err());
                Ok(RunDisposition::Deliver)
            }
        }
    }

    fn request_public(
        &self,
        lane_generation: u64,
        cancellation: &HvfVcpuCancellation,
        requested_run_epoch: Option<u64>,
    ) -> Result<Arc<CancellationAttempt>, HvfVcpuLaneError> {
        let mut state = self.lock();
        if state.shutdown_requested {
            return Err(HvfVcpuLaneError::LaneClosed);
        }
        let (run_epoch, running) = match state.phase {
            ExecutionPhase::Reserved { run_epoch } | ExecutionPhase::Entering { run_epoch } => {
                (run_epoch, false)
            }
            ExecutionPhase::Synchronizing {
                run_epoch: Some(run_epoch),
                ..
            } => (run_epoch, false),
            ExecutionPhase::Running { run_epoch } => (run_epoch, true),
            ExecutionPhase::Idle
            | ExecutionPhase::Synchronizing {
                run_epoch: None, ..
            }
            | ExecutionPhase::Completing { .. }
            | ExecutionPhase::Terminal => return Err(HvfVcpuLaneError::VcpuNotRunning),
        };
        if requested_run_epoch.is_some_and(|requested| requested != run_epoch) {
            return Err(HvfVcpuLaneError::VcpuNotRunning);
        }
        let target = CancellationTarget::Run { run_epoch };
        if running {
            if state.latched.is_some() {
                self.set_terminal(&mut state);
                return Err(HvfVcpuLaneError::RegistryAccounting);
            }
            let attempt =
                match Self::next_cancellation_attempt(&mut state, lane_generation, cancellation, target)
                {
                    Ok(attempt) => attempt,
                    Err(error @ HvfVcpuLaneError::CancellationInFlight { .. }) => {
                        // BCORE-2: a bound run's second kick merges into the one already in
                        // flight -- no second `hv_vcpus_exit`, so no second debit.
                        if state.bound {
                            crate::diagnostics_counters::add_stat(
                                crate::diagnostics_counters::BOUND_KICKS_MERGED,
                                1,
                            );
                        }
                        return Err(error);
                    }
                    Err(error) => return Err(error),
                };
            self.issue_cancellation(&mut state, &attempt, cancellation)?;
            // BCORE-2: charged exactly where the SDK kick lands, so
            // `issued == consumed + drained + expired_unlatched + expired_terminal +
            // expired_latched + abandoned` closes once the vCPU is idle or terminalized.
            self.note_issued_kick(&mut state);
            // hvf-exit-overhead-instrumentation: a real `hv_vcpus_exit` against a running lane.
            crate::diagnostics_counters::record_kick_issued();
            Ok(attempt)
        } else {
            let attempt =
                Self::latch_cancellation(&mut state, lane_generation, cancellation, target)?;
            if state.bound {
                self.note_issued_kick(&mut state);
                crate::diagnostics_counters::add_stat(
                    crate::diagnostics_counters::BOUND_KICKS_LATCHED,
                    1,
                );
            }
            // hvf-exit-overhead-instrumentation: latched -- the imminent run returns `Canceled`
            // without entering the guest (see `execute_once`).
            crate::diagnostics_counters::record_kick_latched();
            Ok(attempt)
        }
    }

    /// BCORE-4: a kick aimed at this vCPU from another thread (a mutation's settle does this
    /// to every running lane and every bound vCPU). The same admission path a lane's
    /// `HvfVcpuLaneCancellation::request_attempt` takes.
    pub(crate) fn request_kick(
        &self,
        generation: u64,
        cancellation: &HvfVcpuCancellation,
        requested_run_epoch: Option<u64>,
    ) -> Result<(), HvfVcpuLaneError> {
        self.request_public(generation, cancellation, requested_run_epoch)
            .map(|_| ())
    }

    fn latch_cancellation(
        state: &mut RunControlState,
        lane_generation: u64,
        cancellation: &HvfVcpuCancellation,
        target: CancellationTarget,
    ) -> Result<Arc<CancellationAttempt>, HvfVcpuLaneError> {
        if let Some(latched) = state.latched.as_ref() {
            return Err(HvfVcpuLaneError::CancellationInFlight {
                sequence: latched.key().sequence,
                run_epoch: latched.key().target.epoch(),
            });
        }
        let attempt =
            Self::next_cancellation_attempt(state, lane_generation, cancellation, target)?;
        // Not an SDK kick: move it out of the kick slot into the latch.
        state.cancellation = None;
        attempt.mark_issued()?;
        state.latched = Some(Arc::clone(&attempt));
        Ok(attempt)
    }

    fn request_shutdown(
        &self,
        lane_generation: u64,
        cancellation: &HvfVcpuCancellation,
    ) -> Result<(), HvfVcpuLaneError> {
        let mut state = self.lock();
        state.shutdown_requested = true;
        self.changed.notify_all();
        let target = match state.phase {
            ExecutionPhase::Synchronizing {
                synchronization_epoch,
                ..
            } => CancellationTarget::Synchronization {
                synchronization_epoch,
            },
            ExecutionPhase::Running { run_epoch } => CancellationTarget::Run { run_epoch },
            ExecutionPhase::Idle
            | ExecutionPhase::Reserved { .. }
            | ExecutionPhase::Entering { .. }
            | ExecutionPhase::Completing { .. } => {
                self.set_orderly_terminal(&mut state);
                return Ok(());
            }
            ExecutionPhase::Terminal => {
                let was_untrusted = state.untrusted;
                self.terminalize(
                    &mut state,
                    was_untrusted,
                    CancellationCompletion::Terminalized,
                );
                return Ok(());
            }
        };
        if let Some(attempt) = state.cancellation.as_ref().cloned() {
            if attempt.key().target != target {
                self.set_terminal(&mut state);
                return Err(HvfVcpuLaneError::RegistryAccounting);
            }
            match attempt.progress() {
                CancellationProgress::Issuing | CancellationProgress::Issued => {
                    let _ = attempt.complete(CancellationCompletion::Terminalized);
                    state.cancellation = None;
                    self.expire_unlatched(&mut state);
                    self.note_stale_kick(&mut state);
                }
                CancellationProgress::Completed(
                    CancellationCompletion::Expired
                    | CancellationCompletion::Failed(_)
                    | CancellationCompletion::Terminalized,
                ) => {
                    state.cancellation = None;
                }
                CancellationProgress::Completed(
                    CancellationCompletion::Applied | CancellationCompletion::TooLate,
                ) => {
                    self.set_terminal(&mut state);
                    return Err(HvfVcpuLaneError::RegistryAccounting);
                }
            }
        }
        let attempt =
            Self::next_cancellation_attempt(&mut state, lane_generation, cancellation, target)?;
        self.issue_cancellation(&mut state, &attempt, cancellation)
    }

    fn cancel_for_shutdown(
        &self,
        lane_generation: u64,
        cancellation: &HvfVcpuCancellation,
    ) -> Result<(), HvfVcpuLaneError> {
        let deadline = operation_deadline()?;
        let mut issued = 0usize;
        let mut state = self.lock();
        state.shutdown_requested = true;
        self.changed.notify_all();
        loop {
            let target = match state.phase {
                ExecutionPhase::Idle
                | ExecutionPhase::Reserved { .. }
                | ExecutionPhase::Entering { .. }
                | ExecutionPhase::Completing { .. } => {
                    self.set_orderly_terminal(&mut state);
                    return Ok(());
                }
                ExecutionPhase::Terminal => return Ok(()),
                ExecutionPhase::Synchronizing {
                    synchronization_epoch,
                    ..
                } => CancellationTarget::Synchronization {
                    synchronization_epoch,
                },
                ExecutionPhase::Running { run_epoch } => CancellationTarget::Run { run_epoch },
            };
            let pending = if let Some(attempt) = state.cancellation.as_ref().cloned() {
                if attempt.key().target != target {
                    self.set_terminal(&mut state);
                    return Err(HvfVcpuLaneError::RegistryAccounting);
                }
                match attempt.progress() {
                    CancellationProgress::Issuing | CancellationProgress::Issued => Some(attempt),
                    CancellationProgress::Completed(
                        CancellationCompletion::Expired
                        | CancellationCompletion::Failed(_)
                        | CancellationCompletion::Terminalized,
                    ) => {
                        state.cancellation = None;
                        None
                    }
                    CancellationProgress::Completed(
                        CancellationCompletion::Applied | CancellationCompletion::TooLate,
                    ) => {
                        self.set_terminal(&mut state);
                        return Err(HvfVcpuLaneError::RegistryAccounting);
                    }
                }
            } else {
                None
            };
            let attempt = if let Some(attempt) = pending {
                attempt
            } else {
                if issued >= MAX_SHUTDOWN_CANCELLATION_ATTEMPTS {
                    state.untrusted = true;
                    self.changed.notify_all();
                    return Err(HvfVcpuLaneError::OperationTimeout);
                }
                issued += 1;
                let attempt = Self::next_cancellation_attempt(
                    &mut state,
                    lane_generation,
                    cancellation,
                    target,
                )?;
                self.issue_cancellation(&mut state, &attempt, cancellation)?;
                attempt
            };
            drop(state);
            let completion = attempt.wait_until(deadline);
            state = self.lock();
            match completion {
                None => {
                    let _ = attempt.complete(CancellationCompletion::Expired);
                    state.untrusted = true;
                    self.changed.notify_all();
                    return Err(HvfVcpuLaneError::OperationTimeout);
                }
                Some(CancellationCompletion::Failed(error)) => return Err(error.into()),
                Some(
                    CancellationCompletion::Applied
                    | CancellationCompletion::TooLate
                    | CancellationCompletion::Expired
                    | CancellationCompletion::Terminalized,
                ) => {}
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                state.untrusted = true;
                self.changed.notify_all();
                return Err(HvfVcpuLaneError::OperationTimeout);
            }
            crate::diagnostics_counters::rank_note_blocking_wait(
                crate::diagnostics_counters::RK_WAIT_WHILE_HOLDING,
                std::panic::Location::caller(),
            );
            let (next, _) = self
                .changed
                .wait_timeout(state, remaining.min(CONTROL_WAIT_POLL))
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state = next;
        }
    }
}

// ---------------------------------------------------------------------------
// Capabilities handed to the memory manager.
// ---------------------------------------------------------------------------

/// Opaque, single-use proof that a lane is live, minted only by a live lane
/// handle.  The memory manager consumes it to register a vCPU participant; no
/// numeric generation is ever accepted in its place.
#[must_use = "an HVF vCPU participant capability must be registered or explicitly discarded"]
pub struct HvfVcpuLaneParticipantCapability {
    generation: u64,
    lifecycle: Arc<AtomicU8>,
    owner_stopped: Arc<AtomicBool>,
    admission: Arc<Mutex<()>>,
}

pub(crate) struct HvfVcpuLaneRegistration {
    pub(crate) generation: u64,
    pub(crate) lifecycle: Arc<AtomicU8>,
    pub(crate) owner_stopped: Arc<AtomicBool>,
}

impl HvfVcpuLaneRegistration {
    pub(crate) fn is_live(&self) -> bool {
        hvf_vcpu_lane_is_live(&self.lifecycle, &self.owner_stopped)
    }
}

impl fmt::Debug for HvfVcpuLaneParticipantCapability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HvfVcpuLaneParticipantCapability")
            .field("generation", &self.generation)
            .field("lifecycle", &self.lifecycle.load(Ordering::Acquire))
            .field("owner_stopped", &self.owner_stopped.load(Ordering::Acquire))
            .finish_non_exhaustive()
    }
}

impl HvfVcpuLaneParticipantCapability {
    pub(crate) const fn generation(&self) -> u64 {
        self.generation
    }

    /// BCORE-4: the same capability for a bound vCPU (created and driven on one guest
    /// thread). The memory manager only ever sees the resulting
    /// [`HvfVcpuLaneRegistration`], so a bound participant is indistinguishable from a lane's
    /// -- `owner_stopped` is the bound vCPU's own flag and is what makes
    /// `deregister_vcpu_participant` acknowledge owed retirements on the way out.
    pub(crate) fn for_bound(
        generation: u64,
        lifecycle: Arc<AtomicU8>,
        owner_stopped: Arc<AtomicBool>,
    ) -> Self {
        Self {
            generation,
            lifecycle,
            owner_stopped,
            admission: Arc::new(Mutex::new(())),
        }
    }

    pub(crate) fn with_live_registration<R>(
        self,
        register: impl FnOnce(HvfVcpuLaneRegistration) -> R,
    ) -> Result<R, HvfVcpuLaneError> {
        let _admission = self
            .admission
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !hvf_vcpu_lane_is_live(&self.lifecycle, &self.owner_stopped) {
            return Err(HvfVcpuLaneError::LaneClosed);
        }
        Ok(register(HvfVcpuLaneRegistration {
            generation: self.generation,
            lifecycle: Arc::clone(&self.lifecycle),
            owner_stopped: Arc::clone(&self.owner_stopped),
        }))
    }
}

#[must_use]
pub struct HvfVcpuRunReservation {
    lane_generation: u64,
    run_epoch: u64,
    cancellation: HvfVcpuLaneCancellation,
    active: bool,
}

impl fmt::Debug for HvfVcpuRunReservation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HvfVcpuRunReservation")
            .field("lane_generation", &self.lane_generation)
            .field("run_epoch", &self.run_epoch)
            .field("active", &self.active)
            .finish_non_exhaustive()
    }
}

impl HvfVcpuRunReservation {
    pub const fn lane_generation(&self) -> u64 {
        self.lane_generation
    }

    pub const fn run_epoch(&self) -> u64 {
        self.run_epoch
    }

    pub fn cancellation(&self) -> HvfVcpuLaneCancellation {
        self.cancellation.clone()
    }

    fn belongs_to(&self, handle: &HvfVcpuLaneHandle) -> bool {
        self.active
            && self.lane_generation == handle.generation
            && Arc::ptr_eq(&self.cancellation.control, &handle.control)
            && Arc::ptr_eq(&self.cancellation.lifecycle, &handle.lifecycle)
    }

    fn settle(&mut self, untrusted: bool) -> Result<(), HvfVcpuLaneError> {
        if !self.active {
            return Ok(());
        }
        let lane_live = self.cancellation.lifecycle.load(Ordering::Acquire) == LANE_LIVE;
        let result =
            self.cancellation
                .control
                .settle_reservation(self.run_epoch, lane_live, untrusted);
        self.active = false;
        if result.is_err() || self.cancellation.control.is_untrusted() {
            raise_lane_lifecycle(&self.cancellation.lifecycle, LANE_ABANDONED);
            self.cancellation.wake_recovery();
        }
        result
    }
}

impl Drop for HvfVcpuRunReservation {
    fn drop(&mut self) {
        let _ = self.settle(false);
    }
}

/// T2e: where a cancellation handle memoizes the [`CancellationAttempt`] it asked
/// [`RunControl`] for, so repeated kick requests within one run issue one attempt.
#[derive(Clone)]
enum AttemptCell {
    /// The lane's cell, shared by every run on that lane and keyed by run epoch: an attempt is
    /// reused only for the run that minted it. Created once per lane, so a run's first request
    /// no longer allocates. Epoch `0` means nothing cached; [`RunControl::reserve_run`] hands out
    /// `1, 2, ..` and never `0`.
    Lane(Arc<Mutex<(u64, Option<Arc<CancellationAttempt>>)>>),
    /// A cell private to this handle: a kick-round cancellation ([`HvfVcpuLaneCancellation`] with
    /// `run_epoch == None`, which names no run) and a BCORE bound vCPU's.
    Own(Arc<Mutex<Option<Arc<CancellationAttempt>>>>),
}

#[derive(Clone)]
pub struct HvfVcpuLaneCancellation {
    lane_generation: u64,
    run_epoch: Option<u64>,
    cancellation: HvfVcpuCancellation,
    attempt: AttemptCell,
    lifecycle: Arc<AtomicU8>,
    control: Arc<RunControl>,
    /// The lane's owner-thread command queue; `None` for a BCORE bound vCPU, which has no
    /// owner thread to wake.
    command_queue: Option<Arc<CommandQueue>>,
    /// The process reaper's thread; `None` for a bound vCPU (no reaper slot).
    reaper: Option<std::thread::Thread>,
}

impl fmt::Debug for HvfVcpuLaneCancellation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HvfVcpuLaneCancellation")
            .field("lane_generation", &self.lane_generation)
            .field("run_epoch", &self.run_epoch)
            .field("lifecycle", &self.lifecycle.load(Ordering::Acquire))
            .field("running", &self.control.is_running())
            .field("run_epoch", &self.control.run_epoch())
            .finish_non_exhaustive()
    }
}

impl HvfVcpuLaneCancellation {
    /// BCORE-2: a bound vCPU's cancellation handle. It has no owner thread to wake and no
    /// reaper slot, so those two fields are `None`; every kick path goes through
    /// [`RunControl::request_public`] exactly as a lane's does.
    fn for_bound(
        lane_generation: u64,
        run_epoch: Option<u64>,
        cancellation: HvfVcpuCancellation,
        lifecycle: Arc<AtomicU8>,
        control: Arc<RunControl>,
    ) -> Self {
        Self {
            lane_generation,
            run_epoch,
            cancellation,
            attempt: AttemptCell::Own(Arc::new(Mutex::new(None))),
            lifecycle,
            control,
            command_queue: None,
            reaper: None,
        }
    }

    pub const fn lane_generation(&self) -> u64 {
        self.lane_generation
    }

    /// Wakes whatever can retire this vCPU after a failed kick: a lane's owner thread and
    /// reaper.  A bound vCPU has neither -- its owner thread *is* the caller -- so this is a
    /// no-op there.
    fn wake_recovery(&self) {
        if let Some(queue) = self.command_queue.as_ref() {
            queue.wake();
        }
        if let Some(reaper) = self.reaper.as_ref() {
            reaper.unpark();
        }
    }

    pub(crate) fn is_same_run(&self, other: &Self) -> bool {
        // T2e: the attempt cell is shared per lane and keyed by run epoch, so its pointer identity
        // no longer separates two runs of one lane -- `run_epoch` does, and it is `Some` for
        // exactly the handles that name a run.
        self.run_epoch.is_some()
            && self.lane_generation == other.lane_generation
            && self.run_epoch == other.run_epoch
            && self.cancellation.generation() == other.cancellation.generation()
            && Arc::ptr_eq(&self.lifecycle, &other.lifecycle)
            && Arc::ptr_eq(&self.control, &other.control)
    }

    fn request_attempt(&self) -> Result<Arc<CancellationAttempt>, HvfVcpuLaneError> {
        match &self.attempt {
            AttemptCell::Own(cell) => {
                let mut requested = cell
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if let Some(attempt) = requested.as_ref() {
                    return Ok(Arc::clone(attempt));
                }
                let result = self.mint_attempt();
                if let Ok(attempt) = &result {
                    *requested = Some(Arc::clone(attempt));
                }
                self.note_refused_request(&result);
                result
            }
            AttemptCell::Lane(cell) => {
                let epoch = self.run_epoch;
                let mut requested = cell
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                // T2e: reuse only an attempt minted for THIS run. `epoch` is `Some` for every
                // reservation, so the guard also keeps a `None`-epoch handle (impossible on this
                // variant) from ever reusing a cached attempt.
                if epoch.is_some_and(|epoch| requested.0 == epoch)
                    && let Some(attempt) = requested.1.as_ref()
                {
                    return Ok(Arc::clone(attempt));
                }
                let result = self.mint_attempt();
                if let Ok(attempt) = &result {
                    requested.0 = epoch.unwrap_or(0);
                    requested.1 = Some(Arc::clone(attempt));
                }
                self.note_refused_request(&result);
                result
            }
        }
    }

    /// The uncached half of [`Self::request_attempt`]: asks [`RunControl`] for this run's
    /// cancellation attempt.
    fn mint_attempt(&self) -> Result<Arc<CancellationAttempt>, HvfVcpuLaneError> {
        if self.lifecycle.load(Ordering::Acquire) != LANE_LIVE {
            return Err(HvfVcpuLaneError::LaneClosed);
        }
        self.control
            .request_public(self.lane_generation, &self.cancellation, self.run_epoch)
    }

    /// Shared tail of [`Self::request_attempt`]: a refused request that left the run untrusted
    /// retires the lane and wakes whatever can reap it.
    fn note_refused_request(&self, result: &Result<Arc<CancellationAttempt>, HvfVcpuLaneError>) {
        if result.is_err() && self.control.is_untrusted() {
            raise_lane_lifecycle(&self.lifecycle, LANE_ABANDONED);
            self.wake_recovery();
        }
    }

    pub fn request(&self) -> Result<(), HvfVcpuLaneError> {
        self.request_attempt().map(|_| ())
    }

    pub fn cancel(&self) -> Result<HvfVcpuCancellationReceipt, HvfVcpuLaneError> {
        let deadline = operation_deadline()?;
        let attempt = self.request_attempt()?;
        let result = self.control.await_attempt(&attempt, deadline);
        if result.is_err() && self.control.is_untrusted() {
            raise_lane_lifecycle(&self.lifecycle, LANE_ABANDONED);
            self.wake_recovery();
        }
        result
    }
}

// ---------------------------------------------------------------------------
// T2c: bounded adaptive spin-then-park for the lane hand-off.
// ---------------------------------------------------------------------------

/// The most one wait may spin before it parks. This is what makes the mechanism safe: a spinning
/// thread can burn at most this much CPU per wait, and it never holds a core for long enough to
/// delay the other side it is waiting for.
const SPIN_BUDGET_MAX_NS: u64 = 20_000;
/// Where a new waiter starts.
const SPIN_BUDGET_START_NS: u32 = 10_000;
/// The floor: a budget is never set below this, and halving one that is already here turns
/// spinning off instead.
const SPIN_BUDGET_MIN_NS: u32 = 2_000;
/// What a waiter with spinning turned off pays every [`SPIN_PROBE_EVERY_PARKS`]-th wait so a lane
/// that becomes busy again is noticed. It is the start budget rather than a token 2 us for a
/// measured reason: a probe smaller than the wait it is probing for can never hit, so turning
/// spinning off would be permanent. Measured with a 2 us probe every 64 waits on cg2 `single`
/// (5 runs x ~100 k hand-offs): 105453 of 107134 owner waits and 105437 guest waits took the
/// disabled branch, 1648 probes all missed, and 23 of 107134 hand-offs hit -- the budget
/// collapsed during the boot phase (seconds-long waits) and never came back.
const SPIN_PROBE_NS: u64 = SPIN_BUDGET_START_NS as u64;
/// Consecutive misses that halve the budget.
const SPIN_MISS_LIMIT: u8 = 4;
/// How many waits a turned-off waiter skips between probes. 16 keeps the worst case at
/// [`SPIN_PROBE_NS`] / 16 = 625 ns per wait, and bounds how long a lane that has gone hot again
/// spins nothing at all.
const SPIN_PROBE_EVERY_PARKS: u16 = 16;
/// Iterations between clock reads inside a spin (`spin_loop` is a few cycles; `Instant::elapsed`
/// is not).
const SPIN_CLOCK_CHECK_MASK: u32 = 31;

/// One thread's spin budget for one wait site, adapted to how long that site's waits take.
///
/// A hit (the wait finished inside the budget) sets the budget to twice what this wait cost:
/// the next wait of the same shape still fits, and a wait that is habitually short stops paying
/// for a kernel wakeup without ever spinning for long. A miss counts towards halving the budget,
/// and four in a row below the floor turn spinning off entirely -- a waiter that keeps missing is
/// waiting on something that cannot arrive quickly (a mutation, a stalled lane, a lane that is
/// not running at all), and burning a core there delays the very work it waits for.
#[derive(Clone, Copy)]
struct AdaptiveSpin {
    budget_ns: u32,
    misses: u8,
    parks_since_probe: u16,
}

impl AdaptiveSpin {
    const fn new() -> Self {
        Self {
            budget_ns: SPIN_BUDGET_START_NS,
            misses: 0,
            parks_since_probe: 0,
        }
    }

    /// Spins until `ready()` is true, the budget runs out, or `cap_ns` is reached. Returns
    /// whether `ready()` became true, in which case the caller consumes whatever it spun for.
    ///
    /// Both call sites are outside any VM-operation frame and hold no pool or queue mutex while
    /// this runs (asserted in debug builds at both); the owner side holds nothing at all.
    fn try_spin(&mut self, owner: bool, cap_ns: u64, ready: impl Fn() -> bool) -> bool {
        // A spin inside a VM-operation frame would burn CPU while holding an admission every
        // other mutator waits for. Debug builds catch that loudly; release builds just park.
        let operation_depth = crate::hvf::operation_depth();
        debug_assert_eq!(
            operation_depth, 0,
            "T2c: an adaptive hand-off spin must not run inside a VM-operation frame"
        );
        if operation_depth != 0 {
            return false;
        }
        let budget = if self.budget_ns == 0 {
            self.parks_since_probe = self.parks_since_probe.wrapping_add(1);
            if self.parks_since_probe % SPIN_PROBE_EVERY_PARKS != 0 {
                crate::diagnostics_counters::record_handoff_spin_disabled(owner);
                return false;
            }
            SPIN_PROBE_NS
        } else {
            u64::from(self.budget_ns)
        }
        .min(cap_ns)
        .min(SPIN_BUDGET_MAX_NS);
        if budget == 0 {
            return false;
        }
        let start = Instant::now();
        let mut iterations = 0u32;
        loop {
            if ready() {
                let waited_ns = start.elapsed().as_nanos() as u64;
                self.budget_ns = waited_ns
                    .saturating_mul(2)
                    .clamp(u64::from(SPIN_BUDGET_MIN_NS), SPIN_BUDGET_MAX_NS)
                    as u32;
                self.misses = 0;
                crate::diagnostics_counters::record_handoff_spin(owner, true, waited_ns);
                return true;
            }
            iterations = iterations.wrapping_add(1);
            if iterations & SPIN_CLOCK_CHECK_MASK == 0
                && start.elapsed().as_nanos() as u64 >= budget
            {
                break;
            }
            std::hint::spin_loop();
        }
        let spun_ns = start.elapsed().as_nanos() as u64;
        self.misses = self.misses.saturating_add(1);
        if self.misses >= SPIN_MISS_LIMIT {
            self.misses = 0;
            let halved = self.budget_ns / 2;
            self.budget_ns = if halved < SPIN_BUDGET_MIN_NS {
                0
            } else {
                halved
            };
        }
        crate::diagnostics_counters::record_handoff_spin(owner, false, spun_ns);
        false
    }
}

thread_local! {
    /// T2c: this thread's guest-side reply-wait spin budget. One per thread, because how long a
    /// thread waits for a reply is a property of what that thread is running, not of the lane.
    static GUEST_REPLY_SPIN: Cell<AdaptiveSpin> = const { Cell::new(AdaptiveSpin::new()) };
}

// ---------------------------------------------------------------------------
// Bounded command queue with an owner-driven closed/drain transition.
// ---------------------------------------------------------------------------

struct CommandQueueState {
    commands: VecDeque<Command>,
    closed: bool,
}

struct CommandQueue {
    capacity: usize,
    state: Mutex<CommandQueueState>,
    /// T2c: how many commands are queued, published (Release) together with the push or pop that
    /// changed it so the owner's adaptive spin can see work without taking `state`. Always exact:
    /// every mutation of `commands` inside `state` publishes the new length before releasing it.
    queued: AtomicUsize,
    owner: OnceLock<std::thread::Thread>,
}

enum PushRejection {
    Closed(Command),
    Full(Command),
}

impl CommandQueue {
    fn new(capacity: usize) -> Result<Self, HvfVcpuLaneError> {
        let mut commands = VecDeque::new();
        commands
            .try_reserve_exact(capacity)
            .map_err(|_| HvfVcpuLaneError::RegistryAccounting)?;
        Ok(Self {
            capacity,
            state: Mutex::new(CommandQueueState {
                commands,
                closed: false,
            }),
            queued: AtomicUsize::new(0),
            owner: OnceLock::new(),
        })
    }

    fn register_owner(&self) -> Result<(), HvfVcpuLaneError> {
        self.owner
            .set(std::thread::current())
            .map_err(|_| HvfVcpuLaneError::RegistryAccounting)
    }

    #[allow(
        clippy::result_large_err,
        reason = "the rejected command is handed back so the sender can finish its own attachment; boxing would put an allocation on the syscall path"
    )]
    fn try_push(&self, command: Command) -> Result<(), PushRejection> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.closed {
            return Err(PushRejection::Closed(command));
        }
        if state.commands.len() >= self.capacity {
            return Err(PushRejection::Full(command));
        }
        state.commands.push_back(command);
        // T2c: published while `state` is still held, so a spinning owner that sees a non-zero
        // count is guaranteed to find the command when it takes the lock.
        self.queued.store(state.commands.len(), Ordering::Release);
        drop(state);
        self.wake();
        Ok(())
    }

    fn pop(&self) -> Option<Command> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let command = state.commands.pop_front();
        self.queued.store(state.commands.len(), Ordering::Release);
        drop(state);
        command
    }

    /// Refuses every future push and returns everything still queued.  The
    /// closed flag and the drain are one critical section, so no sender that
    /// already passed its liveness check can slip a command in afterwards.
    fn close_and_drain(&self) -> VecDeque<Command> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.closed = true;
        let drained = core::mem::take(&mut state.commands);
        self.queued.store(0, Ordering::Release);
        drained
    }

    fn wake(&self) {
        if let Some(owner) = self.owner.get() {
            owner.unpark();
        }
    }
}

// ---------------------------------------------------------------------------
// Process registry and reaper.
// ---------------------------------------------------------------------------

struct RegistryState {
    next_generation: u64,
    active: u32,
    custodial: u32,
    /// BCORE-1: vCPUs a guest thread created and drives on its own host thread (the bound
    /// path).  They hold the same registry capacity a lane does -- the SDK's own caps count
    /// every live vCPU of the VM -- but they are not lanes: no owner thread, no command
    /// queue, no reaper slot.
    bound: u32,
    /// BCORE-1: bound vCPUs whose owner thread unwound past its own vCPU, so the bound path
    /// can no longer destroy them.  Counted forever (they never come back) so the budget a
    /// later bind sees is honest.
    lost: u32,
}

struct RegistryShared {
    limit: u32,
    state: Mutex<RegistryState>,
}

fn release_registry_lane(shared: &RegistryShared) -> bool {
    let mut state = shared
        .state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    match state.active.checked_sub(1) {
        Some(active) => {
            state.active = active;
            true
        }
        None => false,
    }
}

fn adjust_registry_custodial(shared: &RegistryShared, delta: i32) -> bool {
    let mut state = shared
        .state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let next = if delta >= 0 {
        state.custodial.checked_add(delta.unsigned_abs())
    } else {
        state.custodial.checked_sub(delta.unsigned_abs())
    };
    match next {
        Some(custodial) => {
            state.custodial = custodial;
            true
        }
        None => false,
    }
}

/// BCORE-1: registry slots the bound path keeps clear of the lane pool, so binding a hot
/// guest thread can never take the last slot a lane replacement needs.
pub(crate) const BOUND_RESERVE: u32 = 8;

/// BCORE-1: takes one bound-vCPU slot under the registry lock.
///
/// Refused when the VM's own cap is already reached on the same
/// `active + custodial + bound + lost` sum every other admission uses, or when the bound
/// reservation would eat into [`BOUND_RESERVE`].  Never waits: a refusal just leaves the
/// thread on the pooled path.
fn reserve_registry_bound(shared: &RegistryShared) -> bool {
    let mut state = shared
        .state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let used = state
        .active
        .saturating_add(state.custodial)
        .saturating_add(state.bound)
        .saturating_add(state.lost);
    let ceiling = shared
        .limit
        .saturating_sub(BOUND_RESERVE)
        .saturating_sub(state.active)
        .saturating_sub(state.custodial)
        .saturating_sub(state.lost);
    if used >= shared.limit || state.bound.saturating_add(1) > ceiling {
        return false;
    }
    state.bound = state.bound.saturating_add(1);
    true
}

/// BCORE-1: gives one bound-vCPU slot back (a successful destroy on the owner thread).
fn release_registry_bound(shared: &RegistryShared) -> bool {
    let mut state = shared
        .state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    match state.bound.checked_sub(1) {
        Some(bound) => {
            state.bound = bound;
            true
        }
        None => false,
    }
}

/// BCORE-1: moves one bound slot to `lost` -- the vCPU still exists (the SDK still counts
/// it) but nothing on our side can destroy it any more.
fn record_registry_lost(shared: &RegistryShared) -> bool {
    let mut state = shared
        .state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    match state.bound.checked_sub(1) {
        Some(bound) => {
            state.bound = bound;
            state.lost = state.lost.saturating_add(1);
            true
        }
        None => false,
    }
}

struct VcpuReapEntry {
    lane_generation: u64,
    owner: JoinHandle<()>,
    lifecycle: Arc<AtomicU8>,
    owner_stopped: Arc<AtomicBool>,
    registry_reaped: Arc<AtomicBool>,
    custody: Arc<AtomicBool>,
    queue: Arc<CommandQueue>,
    control: Arc<RunControl>,
    cancellation: Arc<Mutex<Option<HvfVcpuCancellation>>>,
    registry: Arc<RegistryShared>,
    reaped: mpsc::SyncSender<Result<(), HvfVcpuLaneError>>,
}

enum ReapSlot {
    Vacant,
    Reserved,
    Occupied(VcpuReapEntry),
}

struct ReaperSlots {
    slots: Mutex<Vec<ReapSlot>>,
}

/// A reaper slot reserved for a lane whose owner thread is about to be
/// spawned.  Filling it cannot fail; that is the whole point.
struct ReapSlotReservation {
    index: usize,
}

struct VcpuReaper {
    limit: u32,
    slots: Arc<ReaperSlots>,
    owner: JoinHandle<()>,
    thread: std::thread::Thread,
}

impl VcpuReaper {
    fn start(limit: u32) -> Result<Self, HvfVcpuLaneError> {
        let capacity = limit as usize;
        let mut slots = Vec::new();
        slots
            .try_reserve_exact(capacity)
            .map_err(|_| HvfVcpuLaneError::RegistryAccounting)?;
        for _ in 0..capacity {
            slots.push(ReapSlot::Vacant);
        }
        let mut finished = Vec::new();
        finished
            .try_reserve_exact(capacity)
            .map_err(|_| HvfVcpuLaneError::RegistryAccounting)?;
        let slots = Arc::new(ReaperSlots {
            slots: Mutex::new(slots),
        });
        let loop_slots = Arc::clone(&slots);
        let owner = std::thread::Builder::new()
            .name("litebox-hvf-vcpu-reaper".to_owned())
            .spawn(move || vcpu_reaper_loop(&loop_slots, finished))
            .map_err(HvfVcpuLaneError::ThreadSpawn)?;
        let thread = owner.thread().clone();
        Ok(Self {
            limit,
            slots,
            owner,
            thread,
        })
    }

    fn reserve_slot(&self) -> Result<ReapSlotReservation, HvfVcpuLaneError> {
        let mut slots = self
            .slots
            .slots
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let index = slots
            .iter()
            .position(|slot| matches!(slot, ReapSlot::Vacant))
            .ok_or(HvfVcpuLaneError::RegistryAccounting)?;
        slots[index] = ReapSlot::Reserved;
        Ok(ReapSlotReservation { index })
    }

    fn fill_slot(&self, reservation: ReapSlotReservation, entry: VcpuReapEntry) {
        {
            let mut slots = self
                .slots
                .slots
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            slots[reservation.index] = ReapSlot::Occupied(entry);
        }
        self.thread.unpark();
    }

    fn release_slot(&self, reservation: ReapSlotReservation) {
        let mut slots = self
            .slots
            .slots
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if matches!(slots[reservation.index], ReapSlot::Reserved) {
            slots[reservation.index] = ReapSlot::Vacant;
        }
    }
}

static PROCESS_VCPU_REAPER: OnceLock<VcpuReaper> = OnceLock::new();
static PROCESS_VCPU_REAPER_INIT: Mutex<()> = Mutex::new(());

fn process_vcpu_reaper(limit: u32) -> Result<&'static VcpuReaper, HvfVcpuLaneError> {
    let _initialization = PROCESS_VCPU_REAPER_INIT
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if PROCESS_VCPU_REAPER.get().is_none() {
        let reaper = VcpuReaper::start(limit)?;
        PROCESS_VCPU_REAPER
            .set(reaper)
            .map_err(|_| HvfVcpuLaneError::RegistryAccounting)?;
    }
    let reaper = PROCESS_VCPU_REAPER
        .get()
        .ok_or(HvfVcpuLaneError::RegistryAccounting)?;
    if reaper.limit != limit || reaper.owner.is_finished() {
        return Err(HvfVcpuLaneError::RegistryAccounting);
    }
    Ok(reaper)
}

#[track_caller]
fn vcpu_reaper_loop(slots: &ReaperSlots, mut finished: Vec<VcpuReapEntry>) {
    loop {
        let mut custodial = false;
        let mut shutting_down = false;
        {
            let mut guard = slots
                .slots
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            for slot in guard.iter_mut() {
                let ReapSlot::Occupied(entry) = slot else {
                    continue;
                };
                if entry.lifecycle.load(Ordering::Acquire) != LANE_LIVE {
                    shutting_down = true;
                    entry.queue.wake();
                    let cancellation = entry
                        .cancellation
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .clone();
                    if let Some(cancellation) = cancellation {
                        let _ = entry
                            .control
                            .request_shutdown(entry.lane_generation, &cancellation);
                    }
                }
                if entry.custody.load(Ordering::Acquire) {
                    custodial = true;
                    entry.owner.thread().unpark();
                }
                // `owner_stopped` is published with Release immediately before
                // the owner returns, so it is sufficient to join; `is_finished`
                // covers an owner that unwound before publishing it.
                let stopped =
                    entry.owner_stopped.load(Ordering::Acquire) || entry.owner.is_finished();
                if stopped
                    && finished.len() < finished.capacity()
                    && let ReapSlot::Occupied(entry) = core::mem::replace(slot, ReapSlot::Vacant)
                {
                    finished.push(entry);
                }
            }
        }
        for entry in finished.drain(..) {
            let joined = entry.owner.join();
            entry.owner_stopped.store(true, Ordering::Release);
            if joined.is_err() {
                raise_lane_lifecycle(&entry.lifecycle, LANE_ABANDONED);
            }
            let released = release_registry_lane(&entry.registry);
            if released {
                entry.registry_reaped.store(true, Ordering::Release);
            }
            let _ = entry.reaped.send(match (joined, released) {
                (Ok(()), true) => Ok(()),
                (Err(_), _) => Err(HvfVcpuLaneError::OwnerPanicked),
                (Ok(()), false) => Err(HvfVcpuLaneError::RegistryAccounting),
            });
        }
        if custodial || shutting_down {
            std::thread::park_timeout(OWNER_CLEANUP_RETRY_INTERVAL);
        } else {
            crate::diagnostics_counters::rank_note_blocking_wait(
                crate::diagnostics_counters::RK_WAIT_WHILE_HOLDING,
                std::panic::Location::caller(),
            );
            std::thread::park();
        }
    }
}

#[derive(Clone)]
pub struct HvfVcpuRegistry {
    shared: Arc<RegistryShared>,
}

static PROCESS_VCPU_REGISTRY: OnceLock<Arc<RegistryShared>> = OnceLock::new();

impl fmt::Debug for HvfVcpuRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = self
            .shared
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        f.debug_struct("HvfVcpuRegistry")
            .field("limit", &self.shared.limit)
            .field("active", &state.active)
            .field("custodial", &state.custodial)
            .finish()
    }
}

impl HvfVcpuRegistry {
    pub fn process() -> Result<Self, HvfVcpuLaneError> {
        let vm = process_hvf_vm()?;
        let limit = vm.report().max_vcpu_count;
        process_vcpu_reaper(limit)?;
        let shared = PROCESS_VCPU_REGISTRY.get_or_init(|| {
            Arc::new(RegistryShared {
                limit,
                state: Mutex::new(RegistryState {
                    next_generation: 1,
                    active: 0,
                    custodial: 0,
                    bound: 0,
                    lost: 0,
                }),
            })
        });
        if shared.limit != limit {
            return Err(HvfVcpuLaneError::RegistryAccounting);
        }
        Ok(Self {
            shared: Arc::clone(shared),
        })
    }

    pub fn capacity(&self) -> u32 {
        self.shared.limit
    }

    pub fn active(&self) -> u32 {
        self.shared
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .active
    }

    /// Lanes whose owner thread is alive only to retry owner-keyed vCPU
    /// cleanup.  They still hold registry capacity.
    pub fn custodial(&self) -> u32 {
        self.shared
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .custodial
    }

    /// BCORE-1: vCPUs created on a guest thread itself (the bound path).  They hold registry
    /// capacity but are not lanes.
    pub fn bound(&self) -> u32 {
        self.shared
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .bound
    }

    /// BCORE-1: bound vCPUs no thread can destroy any more (an owner unwound past its own
    /// vCPU).  Permanent, and still counted against the SDK's cap.
    pub fn lost(&self) -> u32 {
        self.shared
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .lost
    }

    /// BCORE-1: reserves one bound-vCPU slot, or refuses (never waits).
    pub fn reserve_bound(&self) -> bool {
        reserve_registry_bound(&self.shared)
    }

    /// BCORE-1: releases one bound-vCPU slot after a successful destroy.
    pub fn release_bound(&self) -> bool {
        release_registry_bound(&self.shared)
    }

    /// BCORE-1: moves one bound slot to `lost`.
    pub fn record_lost(&self) -> bool {
        record_registry_lost(&self.shared)
    }

    /// BCORE-4: allocates the next vCPU generation from the same counter the lanes use, so a
    /// bound vCPU's participant generation can never collide with a lane's (the memory
    /// manager compares `lane_generation` to detect a stale participant record).
    pub fn next_generation(&self) -> Result<u64, HvfVcpuLaneError> {
        let mut state = self
            .shared
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let generation = state.next_generation;
        state.next_generation = generation
            .checked_add(1)
            .ok_or(HvfVcpuLaneError::RegistryAccounting)?;
        Ok(generation)
    }

    /// Triggers an immediate custodial retry wave instead of waiting for the
    /// reaper's next tick.
    pub fn wake_custodians(&self) {
        if let Some(reaper) = PROCESS_VCPU_REAPER.get() {
            reaper.thread.unpark();
        }
    }

    pub fn create_lane(&self, queue_capacity: usize) -> Result<HvfVcpuLane, HvfVcpuLaneError> {
        if !(1..=MAX_COMMAND_QUEUE_CAPACITY).contains(&queue_capacity) {
            return Err(HvfVcpuLaneError::QueueCapacity(queue_capacity));
        }
        let generation = {
            let mut state = self
                .shared
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            // BCORE-1: a lane creation and a bind draw on the same capacity, so a lane can
            // never take a slot the bound path is holding (and vice versa). Identical to the
            // old test while `bound` and `lost` are 0.
            let used = state
                .active
                .saturating_add(state.custodial)
                .saturating_add(state.bound)
                .saturating_add(state.lost);
            if used >= self.shared.limit {
                return Err(HvfVcpuLaneError::Capacity {
                    active: state.active,
                    limit: self.shared.limit,
                });
            }
            let generation = state.next_generation;
            state.next_generation = generation
                .checked_add(1)
                .ok_or(HvfVcpuLaneError::RegistryAccounting)?;
            state.active = state
                .active
                .checked_add(1)
                .ok_or(HvfVcpuLaneError::RegistryAccounting)?;
            generation
        };
        let release_registry = |error: HvfVcpuLaneError| {
            if release_registry_lane(&self.shared) {
                error
            } else {
                HvfVcpuLaneError::RegistryAccounting
            }
        };

        let reaper = match process_vcpu_reaper(self.shared.limit) {
            Ok(reaper) => reaper,
            Err(error) => return Err(release_registry(error)),
        };
        // Durable reaper ownership is reserved before anything is spawned, so
        // the owner thread is never left without a reaper.
        let reservation = match reaper.reserve_slot() {
            Ok(reservation) => reservation,
            Err(error) => return Err(release_registry(error)),
        };

        let lifecycle = Arc::new(AtomicU8::new(LANE_LIVE));
        let owner_stopped = Arc::new(AtomicBool::new(false));
        let registry_reaped = Arc::new(AtomicBool::new(false));
        let custody = Arc::new(AtomicBool::new(false));
        let admission = Arc::new(Mutex::new(()));
        let control = Arc::new(RunControl::new());
        let cancellation_slot = Arc::new(Mutex::new(None));
        let command_queue = match CommandQueue::new(queue_capacity) {
            Ok(queue) => Arc::new(queue),
            Err(error) => {
                reaper.release_slot(reservation);
                return Err(release_registry(error));
            }
        };
        let reaper_thread = reaper.thread.clone();
        let (created, creation) = mpsc::sync_channel(1);
        let (completed, completion) = mpsc::sync_channel(1);
        let (reaped_sender, reaping) = mpsc::sync_channel(1);
        let thread_registry = Arc::clone(&self.shared);
        let thread_lifecycle = Arc::clone(&lifecycle);
        let thread_owner_stopped = Arc::clone(&owner_stopped);
        let thread_custody = Arc::clone(&custody);
        let thread_reaper = reaper_thread.clone();
        let thread_control = Arc::clone(&control);
        let thread_command_queue = Arc::clone(&command_queue);
        let thread_cancellation_slot = Arc::clone(&cancellation_slot);
        let thread = match std::thread::Builder::new()
            .name(format!("litebox-hvf-vcpu-{generation}"))
            .spawn(move || {
                owner_thread(OwnerThreadContext {
                    lane_generation: generation,
                    registry: thread_registry,
                    lifecycle: thread_lifecycle,
                    owner_stopped: thread_owner_stopped,
                    custody: thread_custody,
                    reaper: thread_reaper,
                    control: thread_control,
                    cancellation_slot: thread_cancellation_slot,
                    command_queue: thread_command_queue,
                    created,
                    completed,
                });
            }) {
            Ok(thread) => thread,
            Err(error) => {
                reaper.release_slot(reservation);
                return Err(release_registry(HvfVcpuLaneError::ThreadSpawn(error)));
            }
        };
        reaper.fill_slot(
            reservation,
            VcpuReapEntry {
                lane_generation: generation,
                owner: thread,
                lifecycle: Arc::clone(&lifecycle),
                owner_stopped: Arc::clone(&owner_stopped),
                registry_reaped: Arc::clone(&registry_reaped),
                custody: Arc::clone(&custody),
                queue: Arc::clone(&command_queue),
                control: Arc::clone(&control),
                cancellation: Arc::clone(&cancellation_slot),
                registry: Arc::clone(&self.shared),
                reaped: reaped_sender,
            },
        );
        // From here on the reaper owns the thread and the registry slot;
        // every failure path just abandons the lane and lets it reap.
        let abandon = |error: HvfVcpuLaneError| {
            raise_lane_lifecycle(&lifecycle, LANE_ABANDONED);
            command_queue.wake();
            reaper_thread.unpark();
            error
        };
        let deadline = match operation_deadline() {
            Ok(deadline) => deadline,
            Err(error) => return Err(abandon(error)),
        };
        let cancellation = match receive_until(creation, deadline) {
            Ok(Ok(cancellation)) => cancellation,
            Ok(Err(error)) | Err(error) => return Err(abandon(error)),
        };
        let handle = HvfVcpuLaneHandle {
            generation,
            command_queue,
            cancellation,
            lifecycle,
            owner_stopped,
            custody,
            reaper: reaper_thread,
            admission,
            control,
            execute_reply: Arc::new(ExecuteReplySlot::new()),
            run_attempt: Arc::new(Mutex::new((0, None))),
        };
        Ok(HvfVcpuLane {
            handle,
            completion: Some(completion),
            reaping: Some(reaping),
            registry_reaped,
        })
    }
}

// ---------------------------------------------------------------------------
// Lane handles.
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct HvfVcpuLaneHandle {
    generation: u64,
    command_queue: Arc<CommandQueue>,
    cancellation: HvfVcpuCancellation,
    lifecycle: Arc<AtomicU8>,
    owner_stopped: Arc<AtomicBool>,
    custody: Arc<AtomicBool>,
    reaper: std::thread::Thread,
    admission: Arc<Mutex<()>>,
    control: Arc<RunControl>,
    /// T2e: this lane's reply cell for [`Command::Execute`], created once with the lane.
    execute_reply: Arc<ExecuteReplySlot>,
    /// T2e: this lane's cancellation-attempt cell, created once with the lane and keyed by run
    /// epoch (see [`AttemptCell::Lane`]).
    run_attempt: Arc<Mutex<(u64, Option<Arc<CancellationAttempt>>)>>,
}

impl fmt::Debug for HvfVcpuLaneHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HvfVcpuLaneHandle")
            .field("generation", &self.generation)
            .field("lifecycle", &self.lifecycle.load(Ordering::Acquire))
            .field("running", &self.is_running())
            .field("custodial", &self.custody.load(Ordering::Acquire))
            .finish_non_exhaustive()
    }
}

impl HvfVcpuLaneHandle {
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    pub fn is_live(&self) -> bool {
        hvf_vcpu_lane_is_live(&self.lifecycle, &self.owner_stopped)
    }

    pub fn is_custodial(&self) -> bool {
        self.custody.load(Ordering::Acquire)
    }

    pub fn participant_capability(
        &self,
    ) -> Result<HvfVcpuLaneParticipantCapability, HvfVcpuLaneError> {
        let _admission = self
            .admission
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !hvf_vcpu_lane_is_live(&self.lifecycle, &self.owner_stopped) {
            return Err(HvfVcpuLaneError::LaneClosed);
        }
        Ok(HvfVcpuLaneParticipantCapability {
            generation: self.generation,
            lifecycle: Arc::clone(&self.lifecycle),
            owner_stopped: Arc::clone(&self.owner_stopped),
            admission: Arc::clone(&self.admission),
        })
    }

    pub fn is_running(&self) -> bool {
        self.control.is_running()
    }

    /// Whether no command owns this lane and its architectural state remains
    /// eligible for another pooled checkout.
    pub(crate) fn is_reusable(&self) -> bool {
        self.is_live() && self.control.is_reusable()
    }

    pub fn run_epoch(&self) -> u64 {
        self.control.run_epoch()
    }

    /// The raw SDK kick, bypassing the lane's epoch binding.  Crate-private:
    /// only the failure witness uses it, to prove that an unauthenticated
    /// `Canceled` exit retires the vCPU instead of being resumed.
    pub(crate) fn sdk_cancellation(&self) -> HvfVcpuCancellation {
        self.cancellation.clone()
    }

    pub fn cancellation(&self) -> HvfVcpuLaneCancellation {
        HvfVcpuLaneCancellation {
            lane_generation: self.generation,
            run_epoch: None,
            cancellation: self.cancellation.clone(),
            // T2e: a kick-round handle names no run, so it must not share the lane's epoch-keyed
            // cell; it memoizes in a cell of its own (as every reservation did before).
            attempt: AttemptCell::Own(Arc::new(Mutex::new(None))),
            lifecycle: Arc::clone(&self.lifecycle),
            control: Arc::clone(&self.control),
            command_queue: Some(Arc::clone(&self.command_queue)),
            reaper: Some(self.reaper.clone()),
        }
    }

    pub fn reserve_run(&self) -> Result<HvfVcpuRunReservation, HvfVcpuLaneError> {
        let _admission = self
            .admission
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if self.lifecycle.load(Ordering::Acquire) != LANE_LIVE {
            return Err(HvfVcpuLaneError::LaneClosed);
        }
        let run_epoch = self.control.reserve_run()?;
        Ok(HvfVcpuRunReservation {
            lane_generation: self.generation,
            run_epoch,
            cancellation: HvfVcpuLaneCancellation {
                lane_generation: self.generation,
                run_epoch: Some(run_epoch),
                cancellation: self.cancellation.clone(),
                attempt: AttemptCell::Lane(Arc::clone(&self.run_attempt)),
                lifecycle: Arc::clone(&self.lifecycle),
                control: Arc::clone(&self.control),
                command_queue: Some(Arc::clone(&self.command_queue)),
                reaper: Some(self.reaper.clone()),
            },
            active: true,
        })
    }

    pub fn initialize_el1(
        &self,
        configuration: HvfEl1State,
    ) -> Result<HvfEl1State, HvfVcpuLaneError> {
        self.dispatch(|reply| Command::InitializeEl1 {
            configuration,
            reply,
        })
    }

    pub fn el1_state(&self) -> Result<HvfEl1State, HvfVcpuLaneError> {
        self.dispatch(|reply| Command::ReadEl1 { reply })
    }

    pub fn run(
        &self,
        attachment: HvfVcpuRunAttachment,
        state: &HvfArchitecturalState,
    ) -> Result<HvfVcpuRunResult, HvfVcpuLaneError> {
        let reservation = self.reserve_run()?;
        self.execute(ExecutionKind::Start, reservation, attachment, state, None, None)
    }

    /// FXR resident-register run of one guest thread (the backend's per-exit path): like
    /// [`Self::run_with_deadline_reserved`], but the owner installs only the registers its
    /// resident cache does not already hold, keeps the thread's SIMD/FP file resident when
    /// `claim` names the file this lane holds for `cell`, reads back only the 39 exit registers,
    /// and leaves the SIMD file resident (the result reports [`HvfExitFp::Resident`]).
    pub fn run_guest_reserved(
        &self,
        reservation: HvfVcpuRunReservation,
        attachment: HvfVcpuRunAttachment,
        state: &HvfArchitecturalState,
        cell: Arc<HvfGuestRegisterCell>,
        claim: HvfGuestFpClaim,
        vtimer_deadline: u64,
    ) -> Result<HvfVcpuRunResult, HvfVcpuLaneError> {
        self.execute(
            ExecutionKind::Start,
            reservation,
            attachment,
            state,
            Some(HvfGuestRun { cell, claim }),
            Some(vtimer_deadline),
        )
    }

    /// FXR: asks this lane to hand a copy of the resident SIMD/FP file `(cell, seq)` back to its
    /// thread (deposited into `cell`; the caller waits there, not for a reply).
    pub fn request_fp_materialization(
        &self,
        cell: &Arc<HvfGuestRegisterCell>,
        seq: u64,
    ) -> Result<(), HvfVcpuLaneError> {
        self.admit(Command::MaterializeFp {
            cell: Arc::clone(cell),
            seq,
        })
        .map_err(|(_, error)| error)
    }

    /// [`Self::run`] with the virtual timer armed to `vtimer_deadline` (a
    /// guest `CNTVCT_EL0` value) so the run exits with `VtimerActivated` no
    /// later than that, bounding one time slice.
    pub fn run_with_deadline(
        &self,
        attachment: HvfVcpuRunAttachment,
        state: &HvfArchitecturalState,
        vtimer_deadline: u64,
    ) -> Result<HvfVcpuRunResult, HvfVcpuLaneError> {
        let reservation = self.reserve_run()?;
        self.run_with_deadline_reserved(reservation, attachment, state, vtimer_deadline)
    }

    pub fn run_with_deadline_reserved(
        &self,
        reservation: HvfVcpuRunReservation,
        attachment: HvfVcpuRunAttachment,
        state: &HvfArchitecturalState,
        vtimer_deadline: u64,
    ) -> Result<HvfVcpuRunResult, HvfVcpuLaneError> {
        self.execute(
            ExecutionKind::Start,
            reservation,
            attachment,
            state,
            None,
            Some(vtimer_deadline),
        )
    }

    pub fn resume(
        &self,
        attachment: HvfVcpuRunAttachment,
        state: &HvfArchitecturalState,
    ) -> Result<HvfVcpuRunResult, HvfVcpuLaneError> {
        let reservation = self.reserve_run()?;
        self.execute(ExecutionKind::Resume, reservation, attachment, state, None, None)
    }

    /// Brings this lane's vCPU onto the attachment's current root and
    /// generations (the same monitor TLBI trip a run would perform first) and
    /// acknowledges them, without executing guest code.  Used by the backend
    /// to complete a shootdown promptly on idle pooled lanes.
    pub fn synchronize(&self, attachment: HvfVcpuRunAttachment) -> Result<(), HvfVcpuLaneError> {
        self.synchronize_before(attachment, operation_deadline()?)
    }

    /// [`Self::synchronize`], bounded by an externally supplied deadline
    /// rather than the lane's own default operation timeout, so a caller
    /// iterating many lanes under its own overall time budget (the backend's
    /// shootdown loop) cannot have a single stalled lane consume the whole
    /// budget on its own.
    pub fn synchronize_before(
        &self,
        attachment: HvfVcpuRunAttachment,
        deadline: Instant,
    ) -> Result<(), HvfVcpuLaneError> {
        attachment.submit(self.generation)?;
        let (reply, response) = mpsc::sync_channel(1);
        let command = Command::Synchronize { attachment, reply };
        if let Err((command, primary)) = self.admit(command) {
            return Err(match command {
                Command::Synchronize { attachment, .. } => {
                    finish_attachment_with_error(attachment, primary)
                }
                _ => HvfVcpuLaneError::RegistryAccounting,
            });
        }
        match receive_until(response, deadline) {
            Err(error @ (HvfVcpuLaneError::OperationTimeout | HvfVcpuLaneError::LaneClosed)) => {
                self.abandon_after_wait_failure();
                Err(error)
            }
            result => result?,
        }
    }

    fn execute(
        &self,
        kind: ExecutionKind,
        reservation: HvfVcpuRunReservation,
        attachment: HvfVcpuRunAttachment,
        state: &HvfArchitecturalState,
        guest: Option<HvfGuestRun>,
        vtimer_deadline: Option<u64>,
    ) -> Result<HvfVcpuRunResult, HvfVcpuLaneError> {
        // T2d: `attach_submitted_vcpu` hands this a SUBMITTED attachment, so every early return
        // from here on must finish it: a SUBMITTED lease's `Drop` calls `abandon()`, which flags
        // the address space so every mutator stays refused until recovery runs. The two returns
        // below used to precede `submit` and were harmless on an ALLOCATED lease.
        if !reservation.belongs_to(self) {
            return Err(finish_attachment_with_error(
                attachment,
                HvfVcpuLaneError::RegistryAccounting,
            ));
        }
        let deadline = match operation_deadline() {
            Ok(deadline) => deadline,
            Err(error) => return Err(finish_attachment_with_error(attachment, error)),
        };
        let submit_start = crate::diagnostics_counters::ticks();
        if !attachment.is_submitted() {
            attachment.submit(self.generation)?;
        } else if attachment.lane_generation() != self.generation {
            return Err(finish_attachment_with_error(
                attachment,
                HvfVcpuLaneError::RegistryAccounting,
            ));
        }
        let submit_end = crate::diagnostics_counters::ticks();
        // T2e: the reply comes back through the lane's preallocated slot, so this path allocates
        // nothing (the channel it replaces cost three allocations per syscall).
        let ticket = self.execute_reply.next_ticket();
        let stamped = crate::diagnostics_counters::ticks();
        let command = Command::Execute {
            kind,
            reservation,
            attachment,
            state: *state,
            guest,
            vtimer_deadline,
            stamped_at: stamped,
            reply: ExecuteReply {
                slot: Arc::clone(&self.execute_reply),
                ticket,
                answered: false,
            },
        };
        if let Err((command, primary)) = self.admit(command) {
            return Err(match command {
                Command::Execute {
                    mut reservation,
                    attachment,
                    ..
                } => {
                    let primary = finish_attachment_with_error(attachment, primary);
                    match reservation.settle(false) {
                        Ok(()) => primary,
                        Err(cleanup) => primary.with_cleanup(cleanup),
                    }
                }
                _ => HvfVcpuLaneError::RegistryAccounting,
            });
        }
        // T2e: `None` is the only wait failure (the deadline passed with no reply); every reply
        // the owner or a dropped command posted, `LaneClosed` included, comes back in `Some`.
        let Some(outcome) = self.execute_reply.wait(ticket, deadline) else {
            self.abandon_after_wait_failure();
            return Err(HvfVcpuLaneError::OperationTimeout);
        };
        if let Ok(run) = &outcome
            && run.replied_at_ticks != 0
        {
            let resumed = crate::diagnostics_counters::ticks();
            crate::diagnostics_counters::record_channel([
                submit_end.wrapping_sub(submit_start),
                stamped.wrapping_sub(submit_end),
                run.owner_wake_ticks,
                run.replied_at_ticks.wrapping_sub(run.owner_end_ticks),
                resumed.wrapping_sub(run.replied_at_ticks),
            ]);
        }
        outcome
    }

    pub fn set_pending_interrupt(&self, fiq: bool, pending: bool) -> Result<(), HvfVcpuLaneError> {
        self.dispatch(|reply| Command::SetPendingInterrupt {
            fiq,
            pending,
            reply,
        })
    }

    pub fn pending_interrupt(&self, fiq: bool) -> Result<bool, HvfVcpuLaneError> {
        self.dispatch(|reply| Command::ReadPendingInterrupt { fiq, reply })
    }

    pub fn set_vtimer(
        &self,
        masked: bool,
        offset: u64,
    ) -> Result<HvfVtimerState, HvfVcpuLaneError> {
        self.dispatch(|reply| Command::SetVtimer {
            masked,
            offset,
            reply,
        })
    }

    pub fn vtimer(&self) -> Result<HvfVtimerState, HvfVcpuLaneError> {
        self.dispatch(|reply| Command::ReadVtimer { reply })
    }

    fn dispatch<T: Send + 'static>(
        &self,
        command: impl FnOnce(mpsc::SyncSender<Result<T, HvfVcpuLaneError>>) -> Command,
    ) -> Result<T, HvfVcpuLaneError> {
        let deadline = operation_deadline()?;
        let (reply, response) = mpsc::sync_channel(1);
        if let Err((command, error)) = self.admit(command(reply)) {
            command.reject(HvfVcpuLaneError::LaneClosed);
            return Err(error);
        }
        match receive_until(response, deadline) {
            Err(error @ (HvfVcpuLaneError::OperationTimeout | HvfVcpuLaneError::LaneClosed)) => {
                self.abandon_after_wait_failure();
                Err(error)
            }
            result => result?,
        }
    }

    /// Liveness check plus enqueue.  The queue's own closed flag is what makes
    /// this safe against a concurrent final drain; the admission lock only
    /// orders it against capability minting and close.
    fn admit(&self, command: Command) -> Result<(), (Command, HvfVcpuLaneError)> {
        let _admission = self
            .admission
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if self.lifecycle.load(Ordering::Acquire) != LANE_LIVE {
            return Err((command, HvfVcpuLaneError::LaneClosed));
        }
        match self.command_queue.try_push(command) {
            Ok(()) => Ok(()),
            Err(PushRejection::Closed(command)) => Err((command, HvfVcpuLaneError::LaneClosed)),
            Err(PushRejection::Full(command)) => Err((command, HvfVcpuLaneError::QueueOverloaded)),
        }
    }

    fn cancel_for_shutdown(&self) -> Result<(), HvfVcpuLaneError> {
        self.control
            .cancel_for_shutdown(self.generation, &self.cancellation)
    }

    fn abandon_after_wait_failure(&self) {
        raise_lane_lifecycle(&self.lifecycle, LANE_ABANDONED);
        self.command_queue.wake();
        self.reaper.unpark();
        let _ = self
            .control
            .request_shutdown(self.generation, &self.cancellation);
    }
}

pub struct HvfVcpuLane {
    handle: HvfVcpuLaneHandle,
    completion: Option<mpsc::Receiver<Result<HvfVcpuLaneCloseReport, HvfVcpuLaneError>>>,
    reaping: Option<mpsc::Receiver<Result<(), HvfVcpuLaneError>>>,
    registry_reaped: Arc<AtomicBool>,
}

impl fmt::Debug for HvfVcpuLane {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HvfVcpuLane")
            .field("handle", &self.handle)
            .field("completion_pending", &self.completion.is_some())
            .field("reaping_pending", &self.reaping.is_some())
            .finish()
    }
}

impl HvfVcpuLane {
    pub fn handle(&self) -> HvfVcpuLaneHandle {
        self.handle.clone()
    }

    pub(crate) fn request_retirement(&self) {
        self.handle.abandon_after_wait_failure();
    }

    pub(crate) fn try_reaped(&mut self) -> Result<bool, HvfVcpuLaneError> {
        let Some(reaping) = self.reaping.as_ref() else {
            return if self.registry_reaped.load(Ordering::Acquire) {
                Ok(true)
            } else {
                Err(HvfVcpuLaneError::RegistryAccounting)
            };
        };
        match reaping.try_recv() {
            Ok(Ok(())) => {
                if !self.registry_reaped.load(Ordering::Acquire) {
                    return Err(HvfVcpuLaneError::RegistryAccounting);
                }
                self.reaping = None;
                Ok(true)
            }
            Ok(Err(error)) => Err(error),
            Err(mpsc::TryRecvError::Empty) => Ok(false),
            Err(mpsc::TryRecvError::Disconnected) => Err(HvfVcpuLaneError::LaneClosed),
        }
    }

    pub fn close(mut self) -> Result<HvfVcpuLaneCloseReport, HvfVcpuLaneError> {
        let deadline = operation_deadline()?;
        {
            let _admission = self
                .handle
                .admission
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            self.handle
                .lifecycle
                .compare_exchange(LANE_LIVE, LANE_CLOSING, Ordering::AcqRel, Ordering::Acquire)
                .map_err(|_| HvfVcpuLaneError::LaneClosed)?;
        }
        self.handle.command_queue.wake();
        self.handle.reaper.unpark();

        let mut failures = None;
        if let Err(error) = self.handle.cancel_for_shutdown() {
            append_lane_error(&mut failures, error);
            self.handle.abandon_after_wait_failure();
        }
        let completion = self.completion.take().ok_or(HvfVcpuLaneError::LaneClosed)?;
        let reaping = self.reaping.take().ok_or(HvfVcpuLaneError::LaneClosed)?;
        let mut report = None;
        let mut custodial = false;
        match receive_until(completion, deadline) {
            Ok(Ok(completed)) => report = Some(completed),
            Ok(Err(error)) => {
                custodial = matches!(error, HvfVcpuLaneError::ResidualVcpus { .. });
                append_lane_error(&mut failures, error);
            }
            Err(error) => {
                append_lane_error(&mut failures, error);
                self.handle.abandon_after_wait_failure();
            }
        }
        // A custodial owner deliberately stays alive; nothing to reap yet.
        if !custodial {
            match receive_until(reaping, deadline) {
                Ok(Ok(())) => {}
                Ok(Err(error)) => append_lane_error(&mut failures, error),
                Err(error) => {
                    append_lane_error(&mut failures, error);
                    self.handle.abandon_after_wait_failure();
                }
            }
        }
        match (report, failures) {
            (Some(report), None) => Ok(report),
            (_, Some(error)) => Err(error),
            (None, None) => Err(HvfVcpuLaneError::RegistryAccounting),
        }
    }
}

impl Drop for HvfVcpuLane {
    fn drop(&mut self) {
        if self.handle.lifecycle.load(Ordering::Acquire) != LANE_CLOSED {
            self.request_retirement();
        }
    }
}

// ---------------------------------------------------------------------------
// Commands.
// ---------------------------------------------------------------------------

type Reply<T> = mpsc::SyncSender<Result<T, HvfVcpuLaneError>>;

/// How long one [`ExecuteReplySlot::wait`] park may last before the deadline is re-checked.
/// The deadline is the real bound; this only bounds the cost of a park whose wakeup was spent by
/// an unrelated `unpark`, and it is the hook T2c's adaptive spin replaces.
const REPLY_PARK_SLICE: Duration = Duration::from_millis(10);

/// T2e: one lane's preallocated reply cell for [`Command::Execute`].
///
/// A pooled lane carries at most one Execute at a time ([`RunControl::reserve_run`] refuses a
/// second reservation while a run is outstanding), so a single slot per lane suffices and the
/// per-syscall `mpsc::sync_channel(1)` -- three allocations plus the channel protocol, measured
/// with a counting allocator by `.gm/syscall-bench/t2ealloc/allocprobe.rs` -- is gone from the
/// execute path. `ticket` numbers each Execute; a waiter accepts the stored value only
/// when `posted == ticket`, so a reply that arrives after its waiter gave up (a timeout, or a
/// lane the owner rejected after the wait) can never be read as the next run's.
///
/// Lost-wakeup-free: the waiter registers under `waiter` and *then* re-reads `posted`, while the
/// poster stores the value, publishes `posted` (Release) and only then takes and unparks the
/// registered waiter. Either order is covered by `std`'s park token, which an unpark sets
/// whether or not the target is parked yet.
struct ExecuteReplySlot {
    /// The ticket whose value sits in `value`. Monotonic; `0` means nothing posted yet.
    posted: AtomicU64,
    next_ticket: AtomicU64,
    value: Mutex<Option<(u64, Result<HvfVcpuRunResult, HvfVcpuLaneError>)>>,
    waiter: Mutex<Option<std::thread::Thread>>,
}

impl ExecuteReplySlot {
    fn new() -> Self {
        Self {
            posted: AtomicU64::new(0),
            next_ticket: AtomicU64::new(0),
            value: Mutex::new(None),
            waiter: Mutex::new(None),
        }
    }

    /// The next Execute ticket. Tickets start at 1, so `posted == 0` means "nothing posted".
    fn next_ticket(&self) -> u64 {
        self.next_ticket
            .fetch_add(1, Ordering::Relaxed)
            .wrapping_add(1)
    }

    fn take_value(&self, ticket: u64) -> Option<Result<HvfVcpuRunResult, HvfVcpuLaneError>> {
        let mut value = self
            .value
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match value.as_ref() {
            Some((posted_ticket, _)) if *posted_ticket == ticket => {
                value.take().map(|(_, result)| result)
            }
            _ => None,
        }
    }

    /// Owner side: hand `result` to `ticket`'s waiter.
    fn post(&self, ticket: u64, result: Result<HvfVcpuRunResult, HvfVcpuLaneError>) {
        let mut value = self
            .value
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *value = Some((ticket, result));
        drop(value);
        self.posted.store(ticket, Ordering::Release);
        let waiter = self
            .waiter
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        match waiter {
            Some(waiter) => {
                crate::diagnostics_counters::record_reply_slot_post(false);
                waiter.unpark();
            }
            // Nobody was registered. Three cases, all of which still deliver the reply:
            //   1. T2c, the ordinary one and now by far the largest: the waiter was spinning and
            //      read `posted` itself, so it never registered. Counted on the waiter side as
            //      `spin_posts` -- subtract it before reading anything into this arm.
            //   2. The waiter had not registered yet -- it re-reads `posted` immediately after
            //      registering and still takes this value.
            //   3. The waiter timed out (a late post into a lane that is already abandoned, so no
            //      further Execute can be issued on it); the value is left for a stale reader.
            // Only (2) and (3) -- i.e. `late_posts - spin_posts` -- are interesting, and neither
            // is a lost reply. `unpark` is never missed: the waiter registers before it parks and
            // re-reads `posted` after registering, under this same mutex.
            None => crate::diagnostics_counters::record_reply_slot_post(true),
        }
    }

    /// Guest side: wait for `ticket`'s reply, bounded by `deadline`.
    ///
    /// `Some` is the reply itself -- an `Err` in it is a run failure, not a wait failure, exactly
    /// as the old channel delivered it. `None` means the deadline passed with no reply at all,
    /// which is the only case that leaves the lane's own liveness in question (the caller
    /// abandons it). A command dropped unanswered posts `LaneClosed` instead, so an owner that
    /// died mid-run is reported at once rather than after the whole timeout.
    #[track_caller]
    fn wait(
        &self,
        ticket: u64,
        deadline: Instant,
    ) -> Option<Result<HvfVcpuRunResult, HvfVcpuLaneError>> {
        if self.posted.load(Ordering::Acquire) == ticket
            && let Some(value) = self.take_value(ticket)
        {
            // T2c: read without registering, so `post` counts this reply in its `late` arm. It is
            // not late -- it is the fast path -- and `spin_posts` says so.
            crate::diagnostics_counters::record_reply_slot_direct_read();
            return Some(value);
        }
        // T2c: the owner answers a run in a few microseconds (its share of the hand-off is the
        // marshalling plus one `hv_vcpu_run`), far less than a park/unpark pair costs, so spin
        // for the reply before registering as a waiter. The spin is bounded by this wait's own
        // deadline as well as by the budget, so it can never delay a timeout. It holds no lock
        // and no operation frame: the attachment was submitted and finished before `execute()`
        // got here, and the pool mutex was released by `acquire_lane`.
        let remaining_ns = u64::try_from(
            deadline
                .saturating_duration_since(Instant::now())
                .as_nanos(),
        )
        .unwrap_or(u64::MAX);
        if remaining_ns != 0
            && GUEST_REPLY_SPIN.with(|cell| {
                let mut spin = cell.get();
                let hit = spin.try_spin(false, remaining_ns, || {
                    self.posted.load(Ordering::Acquire) == ticket
                });
                cell.set(spin);
                hit
            })
            && let Some(value) = self.take_value(ticket)
        {
            // T2c: the spin won, again without registering -- counted as `spin_posts` so that
            // `post`'s growing `late` share is not mistaken for lost wakeups or timeouts.
            crate::diagnostics_counters::record_reply_slot_direct_read();
            return Some(value);
        }
        crate::diagnostics_counters::rank_note_blocking_wait(
            crate::diagnostics_counters::RK_WAIT_WHILE_HOLDING,
            std::panic::Location::caller(),
        );
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                // Do not leave this thread registered: a late post would then unpark a thread
                // that is already back in its guest loop.
                self.waiter
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .take();
                return None;
            }
            let mut waiter = self
                .waiter
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            *waiter = Some(std::thread::current());
            drop(waiter);
            // Re-read after registering: `post` publishes `posted` before it takes the
            // registration, so a reply landing in between is found here instead of parked on.
            if self.posted.load(Ordering::Acquire) == ticket
                && let Some(value) = self.take_value(ticket)
            {
                self.waiter
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .take();
                return Some(value);
            }
            crate::diagnostics_counters::record_reply_slot_park();
            std::thread::park_timeout(remaining.min(REPLY_PARK_SLICE));
        }
    }
}

/// T2e: an Execute command's half of [`ExecuteReplySlot`].
///
/// Dropping one that was never posted posts `LaneClosed`, which is exactly what the old
/// `mpsc::SyncSender` did when the command was dropped unanswered (an owner panic inside a run,
/// or the final drain): the waiter saw a disconnected channel at once instead of hanging for the
/// whole 30 s command timeout.
struct ExecuteReply {
    slot: Arc<ExecuteReplySlot>,
    ticket: u64,
    answered: bool,
}

impl ExecuteReply {
    fn post(mut self, result: Result<HvfVcpuRunResult, HvfVcpuLaneError>) {
        self.answered = true;
        self.slot.post(self.ticket, result);
    }
}

impl Drop for ExecuteReply {
    fn drop(&mut self) {
        if !self.answered {
            self.answered = true;
            self.slot
                .post(self.ticket, Err(HvfVcpuLaneError::LaneClosed));
        }
    }
}

#[derive(Clone, Copy)]
enum ExecutionKind {
    Start,
    Resume,
}

enum Command {
    InitializeEl1 {
        configuration: HvfEl1State,
        reply: Reply<HvfEl1State>,
    },
    ReadEl1 {
        reply: Reply<HvfEl1State>,
    },
    Execute {
        kind: ExecutionKind,
        reservation: HvfVcpuRunReservation,
        attachment: HvfVcpuRunAttachment,
        state: HvfArchitecturalState,
        /// FXR: `Some` for a resident-register guest-thread run, `None` for a full-mode run
        /// (full install, full read).
        guest: Option<HvfGuestRun>,
        vtimer_deadline: Option<u64>,
        stamped_at: u64,
        /// T2e: the lane's preallocated reply slot plus this run's ticket. The other commands
        /// keep their `sync_channel`: none of them is on the per-syscall path.
        reply: ExecuteReply,
    },
    /// FXR: hand a copy of the resident SIMD/FP file `(cell, seq)` back to its thread's cell.
    /// No reply: the requester waits on its cell, which every path that gives the file up
    /// (this command, an eviction, a synchronization trip, the lane closing) deposits into.
    MaterializeFp {
        cell: Arc<HvfGuestRegisterCell>,
        seq: u64,
    },
    /// Synchronize this lane onto the attachment's root/generations (monitor
    /// TLBI trip plus acknowledgement) without running guest code.
    Synchronize {
        attachment: HvfVcpuRunAttachment,
        reply: Reply<()>,
    },
    SetPendingInterrupt {
        fiq: bool,
        pending: bool,
        reply: Reply<()>,
    },
    ReadPendingInterrupt {
        fiq: bool,
        reply: Reply<bool>,
    },
    SetVtimer {
        masked: bool,
        offset: u64,
        reply: Reply<HvfVtimerState>,
    },
    ReadVtimer {
        reply: Reply<HvfVtimerState>,
    },
}

impl Command {
    fn reject(self, error: HvfVcpuLaneError) {
        match self {
            Self::InitializeEl1 { reply, .. } | Self::ReadEl1 { reply } => {
                reply_result(reply, Err(error));
            }
            Self::Execute {
                mut reservation,
                attachment,
                reply,
                ..
            } => {
                let error = finish_attachment_with_error(attachment, error);
                let error = match reservation.settle(false) {
                    Ok(()) => error,
                    Err(cleanup) => error.with_cleanup(cleanup),
                };
                reply.post(Err(error));
            }
            Self::Synchronize { attachment, reply } => {
                reply_result(reply, Err(finish_attachment_with_error(attachment, error)))
            }
            Self::SetPendingInterrupt { reply, .. } => reply_result(reply, Err(error)),
            Self::ReadPendingInterrupt { reply, .. } => reply_result(reply, Err(error)),
            Self::SetVtimer { reply, .. } | Self::ReadVtimer { reply } => {
                reply_result(reply, Err(error));
            }
            // The requester waits on its cell; the owner's close path hands the file back (or
            // records its loss) whether or not this request ever ran.
            Self::MaterializeFp { .. } => {}
        }
    }
}

fn append_lane_error(failures: &mut Option<HvfVcpuLaneError>, error: HvfVcpuLaneError) {
    *failures = Some(match failures.take() {
        Some(primary) => primary.with_cleanup(error),
        None => error,
    });
}

fn operation_deadline() -> Result<Instant, HvfVcpuLaneError> {
    Instant::now()
        .checked_add(COMMAND_WAIT_TIMEOUT)
        .ok_or(HvfVcpuLaneError::OperationTimeout)
}

#[track_caller]
fn receive_until<T>(receiver: mpsc::Receiver<T>, deadline: Instant) -> Result<T, HvfVcpuLaneError> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return match receiver.try_recv() {
            Ok(value) => Ok(value),
            Err(mpsc::TryRecvError::Empty) => Err(HvfVcpuLaneError::OperationTimeout),
            Err(mpsc::TryRecvError::Disconnected) => Err(HvfVcpuLaneError::LaneClosed),
        };
    }
    crate::diagnostics_counters::rank_note_blocking_wait(
        crate::diagnostics_counters::RK_WAIT_WHILE_HOLDING,
        std::panic::Location::caller(),
    );
    match receiver.recv_timeout(remaining) {
        Ok(value) => Ok(value),
        Err(mpsc::RecvTimeoutError::Timeout) => Err(HvfVcpuLaneError::OperationTimeout),
        Err(mpsc::RecvTimeoutError::Disconnected) => Err(HvfVcpuLaneError::LaneClosed),
    }
}

// ---------------------------------------------------------------------------
// Owner thread.
// ---------------------------------------------------------------------------

struct OwnerThreadContext {
    lane_generation: u64,
    registry: Arc<RegistryShared>,
    lifecycle: Arc<AtomicU8>,
    owner_stopped: Arc<AtomicBool>,
    custody: Arc<AtomicBool>,
    reaper: std::thread::Thread,
    control: Arc<RunControl>,
    cancellation_slot: Arc<Mutex<Option<HvfVcpuCancellation>>>,
    command_queue: Arc<CommandQueue>,
    created: mpsc::SyncSender<Result<HvfVcpuCancellation, HvfVcpuLaneError>>,
    completed: mpsc::SyncSender<Result<HvfVcpuLaneCloseReport, HvfVcpuLaneError>>,
}

fn owner_thread(context: OwnerThreadContext) {
    let OwnerThreadContext {
        lane_generation,
        registry,
        lifecycle,
        owner_stopped,
        custody,
        reaper,
        control,
        cancellation_slot,
        command_queue,
        created,
        completed,
    } = context;
    let mut vcpu = None;
    let mut residency = LaneResidency::new(lane_generation);
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        let setup = (|| {
            command_queue.register_owner()?;
            let vm = process_hvf_vm()?;
            let raw = vm.create_vcpu()?;
            let cancellation = raw.cancellation()?;
            vcpu = Some(raw);
            Ok::<_, HvfVcpuLaneError>(cancellation)
        })();
        let cancellation = match setup {
            Ok(cancellation) => cancellation,
            Err(error) => {
                if created.send(Err(error)).is_err() {
                    raise_lane_lifecycle(&lifecycle, LANE_ABANDONED);
                }
                return Ok(());
            }
        };
        *cancellation_slot
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(cancellation.clone());
        if created.send(Ok(cancellation)).is_err() {
            raise_lane_lifecycle(&lifecycle, LANE_ABANDONED);
        }
        owner_loop(
            lane_generation,
            &lifecycle,
            &control,
            &command_queue,
            &mut vcpu,
            &mut residency,
        )
    }));
    if outcome.is_err() || lifecycle.load(Ordering::Acquire) == LANE_LIVE {
        raise_lane_lifecycle(&lifecycle, LANE_ABANDONED);
    }

    // Final drain: from here no sender can enqueue, and every command that
    // made it in is answered.
    for command in command_queue.close_and_drain() {
        command.reject(HvfVcpuLaneError::LaneClosed);
    }

    // FXR: a guest thread's SIMD/FP file still resident here goes back to it before the vCPU is
    // destroyed (or is recorded lost when the vCPU is already gone, or after an owner panic).
    residency.surrender_at_close(if outcome.is_ok() { vcpu.as_mut() } else { None });

    let mut cleanup_attempts = 0usize;
    let mut cleanup_error: Option<HvfVcpuLaneError> = None;
    if let Some(raw) = vcpu.take()
        && raw.is_live()
    {
        cleanup_attempts = 1;
        if let Err(error) = raw.destroy() {
            cleanup_error = Some(error.into());
        }
    }
    let vm = match process_hvf_vm() {
        Ok(vm) => Some(vm),
        Err(error) => {
            if cleanup_error.is_none() {
                cleanup_error = Some(error.into());
            }
            None
        }
    };

    // Owner-affine cleanup custody: the SDK quarantines a vCPU under its
    // creator thread, so this thread is the only one that can ever retire it.
    let mut report_sent = false;
    let mut custodial = false;
    if let Some(vm) = vm {
        loop {
            for _ in 0..OWNER_CLEANUP_WAVE_ATTEMPTS {
                if vm.quarantined_vcpu_count_for_current_thread() == 0 {
                    break;
                }
                cleanup_attempts = cleanup_attempts.saturating_add(1);
                if let Err(error) = vm.retry_quarantined_vcpus_for_current_thread()
                    && cleanup_error.is_none()
                {
                    cleanup_error = Some(error.into());
                }
                if vm.quarantined_vcpu_count_for_current_thread() == 0 {
                    break;
                }
                std::thread::park_timeout(OWNER_CLEANUP_RETRY_INTERVAL);
            }
            let residual = vm.quarantined_vcpu_count_for_current_thread();
            if residual == 0 {
                break;
            }
            if !custodial {
                custodial = true;
                custody.store(true, Ordering::Release);
                raise_lane_lifecycle(&lifecycle, LANE_ABANDONED);
                if !adjust_registry_custodial(&registry, 1) && cleanup_error.is_none() {
                    cleanup_error = Some(HvfVcpuLaneError::RegistryAccounting);
                }
                let _ = completed.send(Err(HvfVcpuLaneError::ResidualVcpus {
                    current_thread: residual,
                    process: vm.quarantined_vcpu_count(),
                }));
                report_sent = true;
                reaper.unpark();
            }
            // The reaper unparks custodians every retry interval; this bound
            // only guards against a missed wake.
            std::thread::park_timeout(OWNER_CLEANUP_RETRY_INTERVAL);
        }
    }
    if custodial {
        custody.store(false, Ordering::Release);
        if !adjust_registry_custodial(&registry, -1) && cleanup_error.is_none() {
            cleanup_error = Some(HvfVcpuLaneError::RegistryAccounting);
        }
    }

    *cancellation_slot
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
    let mut final_error = match outcome {
        Ok(Ok(())) => None,
        Ok(Err(error)) => Some(error),
        Err(_) => Some(HvfVcpuLaneError::OwnerPanicked),
    };
    if let Some(cleanup) = cleanup_error {
        final_error = Some(match final_error.take() {
            Some(primary) => primary.with_cleanup(cleanup),
            None => cleanup,
        });
    }
    let residual_vcpus = match vm {
        Some(vm) => vm.quarantined_vcpu_count(),
        None => 0,
    };
    let report = HvfVcpuLaneCloseReport {
        lane_generation,
        cleanup_attempts,
        residual_vcpus,
    };
    if lifecycle.load(Ordering::Acquire) == LANE_ABANDONED && final_error.is_none() {
        final_error = Some(HvfVcpuLaneError::LaneClosed);
    }
    if let Some(error) = final_error {
        lifecycle.store(LANE_ABANDONED, Ordering::Release);
        if !report_sent {
            let _ = completed.send(Err(error));
        }
    } else {
        lifecycle.store(LANE_CLOSED, Ordering::Release);
        if !report_sent {
            let _ = completed.send(Ok(report));
        }
    }
    // Published with Release before returning: the reaper joins on this.
    owner_stopped.store(true, Ordering::Release);
    reaper.unpark();
}

#[track_caller]
fn owner_loop(
    lane_generation: u64,
    lifecycle: &AtomicU8,
    control: &RunControl,
    command_queue: &CommandQueue,
    vcpu: &mut Option<HvfVcpu>,
    residency: &mut LaneResidency,
) -> Result<(), HvfVcpuLaneError> {
    // T2c: this owner's own spin budget. It is a loop local, so it dies with the lane: a lane
    // that is replaced starts again from [`SPIN_BUDGET_START_NS`] rather than inheriting a
    // budget tuned for the vCPU it used to have.
    let mut spin = AdaptiveSpin::new();
    loop {
        if lifecycle.load(Ordering::Acquire) != LANE_LIVE {
            return Ok(());
        }
        let Some(command) = command_queue.pop() else {
            if vcpu.as_ref().is_some_and(|raw| !raw.is_live()) {
                vcpu.take();
                raise_lane_lifecycle(lifecycle, LANE_ABANDONED);
                return Ok(());
            }
            // T2c: an owner whose lane is hot usually has the next command within a couple of
            // microseconds, far less than the two kernel wakeups a park costs, so spin for it
            // first. The budget adapts down (to nothing) when this lane is genuinely idle, which
            // is what keeps an idle desktop's owners off the CPU. This holds no lock and no
            // operation frame: the only thing it reads is the queue's published length.
            if spin.try_spin(true, SPIN_BUDGET_MAX_NS, || {
                command_queue.queued.load(Ordering::Acquire) != 0
                    || lifecycle.load(Ordering::Acquire) != LANE_LIVE
            }) {
                continue;
            }
            crate::diagnostics_counters::rank_note_blocking_wait(
                crate::diagnostics_counters::RK_WAIT_WHILE_HOLDING,
                std::panic::Location::caller(),
            );
            std::thread::park();
            continue;
        };
        if lifecycle.load(Ordering::Acquire) != LANE_LIVE {
            command.reject(HvfVcpuLaneError::LaneClosed);
            return Ok(());
        }
        if OWNER_PANIC_INJECTION
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |remaining| {
                remaining.checked_sub(1)
            })
            .is_ok()
        {
            panic!("injected HVF owner-lane panic for the containment witness");
        }
        let Some(raw) = vcpu.as_mut() else {
            command.reject(HvfVcpuLaneError::LaneClosed);
            return Err(HvfVcpuLaneError::LaneClosed);
        };
        if !raw.is_live() || control.is_terminal() {
            command.reject(HvfVcpuLaneError::LaneTerminal);
            raise_lane_lifecycle(lifecycle, LANE_ABANDONED);
            return Ok(());
        }
        match command {
            Command::InitializeEl1 {
                configuration,
                reply,
            } => {
                let result = raw.initialize_el1(&configuration).map_err(Into::into);
                reply_simple_command(vcpu, lifecycle, reply, result);
            }
            Command::ReadEl1 { reply } => {
                let result = raw.el1_state().map_err(Into::into);
                reply_simple_command(vcpu, lifecycle, reply, result);
            }
            Command::Execute {
                kind,
                reservation,
                attachment,
                state,
                guest,
                vtimer_deadline,
                stamped_at,
                reply,
            } => {
                let owner_wake_ticks =
                    crate::diagnostics_counters::ticks().wrapping_sub(stamped_at);
                let mut result = execute_attached(
                    raw,
                    control,
                    lane_generation,
                    kind,
                    reservation,
                    attachment,
                    &state,
                    guest,
                    residency,
                    vtimer_deadline,
                );
                let untrusted = result
                    .as_ref()
                    .is_err_and(HvfVcpuLaneError::terminalizes_execution_vcpu)
                    || control.is_untrusted();
                // FXR: a run whose lane leaves service right after it (retired as untrusted,
                // quarantined by the SDK, or shut down) must not strand the thread's SIMD file in
                // the dying vCPU: read it into the result now, while the vCPU still answers.
                if untrusted || !raw.is_live() || control.is_terminal() {
                    materialize_result_fp(raw, residency, &mut result);
                }
                if untrusted {
                    // The architectural state can no longer be trusted: retire
                    // the vCPU now, on its owner thread, unless the SDK already
                    // did so while reporting the failure.
                    if let Some(raw) = vcpu.take()
                        && raw.is_live()
                        && let Err(cleanup) = raw.quarantine_rejected_exit()
                    {
                        result = Err(match result {
                            Ok(_) => cleanup.into(),
                            Err(primary) => primary.with_cleanup(cleanup),
                        });
                    }
                    raise_lane_lifecycle(lifecycle, LANE_ABANDONED);
                } else if vcpu.as_ref().is_some_and(|raw| !raw.is_live()) {
                    // The SDK quarantined the vCPU inside the run; the lane is
                    // finished even though the error itself is not terminal.
                    vcpu.take();
                    raise_lane_lifecycle(lifecycle, LANE_ABANDONED);
                } else if control.is_terminal() {
                    // Orderly shutdown reached during this run: the vCPU is
                    // still trustworthy and is destroyed normally by cleanup.
                    raise_lane_lifecycle(lifecycle, LANE_ABANDONED);
                }
                if let Ok(run) = result.as_mut() {
                    run.owner_wake_ticks = owner_wake_ticks;
                    run.replied_at_ticks = crate::diagnostics_counters::ticks();
                }
                // T2e: into the lane's slot instead of a per-run channel.
                reply.post(result);
            }
            Command::MaterializeFp { cell, seq } => {
                if let Err(error) = residency.materialize(raw, &cell, seq) {
                    litebox_util_log::error!(error:% = error;
                        "HVF lane could not read a guest thread's resident SIMD/FP registers back");
                }
                if !raw.is_live() {
                    vcpu.take();
                    raise_lane_lifecycle(lifecycle, LANE_ABANDONED);
                    return Ok(());
                }
            }
            Command::Synchronize { attachment, reply } => {
                // FXR: the trip installs an all-zero scratch state; the resident SIMD file goes
                // back to its thread first.
                if let Err(error) = residency.surrender(
                    raw,
                    crate::diagnostics_counters::RESIDENT_DEPOSITS_SYNC,
                ) {
                    reply_result(reply, Err(finish_attachment_with_error(attachment, error)));
                    if !raw.is_live() {
                        vcpu.take();
                    }
                    raise_lane_lifecycle(lifecycle, LANE_ABANDONED);
                    continue;
                }
                let mut result = synchronize_attached(raw, control, lane_generation, attachment);
                let untrusted = result
                    .as_ref()
                    .is_err_and(HvfVcpuLaneError::terminalizes_execution_vcpu)
                    || control.is_untrusted();
                if untrusted {
                    if let Some(raw) = vcpu.take()
                        && raw.is_live()
                        && let Err(cleanup) = raw.quarantine_rejected_exit()
                    {
                        result = Err(match result {
                            Ok(()) => cleanup.into(),
                            Err(primary) => primary.with_cleanup(cleanup),
                        });
                    }
                    raise_lane_lifecycle(lifecycle, LANE_ABANDONED);
                } else if vcpu.as_ref().is_some_and(|raw| !raw.is_live()) {
                    vcpu.take();
                    raise_lane_lifecycle(lifecycle, LANE_ABANDONED);
                } else if control.is_terminal() {
                    raise_lane_lifecycle(lifecycle, LANE_ABANDONED);
                }
                reply_result(reply, result);
            }
            Command::SetPendingInterrupt {
                fiq,
                pending,
                reply,
            } => {
                let result = raw.set_pending_interrupt(fiq, pending).map_err(Into::into);
                reply_simple_command(vcpu, lifecycle, reply, result);
            }
            Command::ReadPendingInterrupt { fiq, reply } => {
                let result = raw.pending_interrupt(fiq).map_err(Into::into);
                reply_simple_command(vcpu, lifecycle, reply, result);
            }
            Command::SetVtimer {
                masked,
                offset,
                reply,
            } => {
                let result = set_vtimer(raw, masked, offset);
                reply_simple_command(vcpu, lifecycle, reply, result);
            }
            Command::ReadVtimer { reply } => {
                let result = read_vtimer(raw);
                reply_simple_command(vcpu, lifecycle, reply, result);
            }
        }
    }
}

fn finish_attachment_with_error(
    attachment: HvfVcpuRunAttachment,
    primary: HvfVcpuLaneError,
) -> HvfVcpuLaneError {
    match attachment.finish() {
        Ok(()) => primary,
        Err(cleanup) => primary.with_cleanup(cleanup),
    }
}

fn reply_simple_command<T>(
    vcpu: &mut Option<HvfVcpu>,
    lifecycle: &AtomicU8,
    reply: Reply<T>,
    result: Result<T, HvfVcpuLaneError>,
) {
    let raw_died = vcpu.as_ref().is_some_and(|raw| !raw.is_live());
    let result = if raw_died {
        vcpu.take();
        raise_lane_lifecycle(lifecycle, LANE_ABANDONED);
        match result {
            Ok(_) => Err(HvfVcpuLaneError::LaneTerminal),
            Err(error) => Err(error),
        }
    } else {
        result
    };
    reply_result(reply, result);
}

fn reply_result<T>(reply: Reply<T>, result: Result<T, HvfVcpuLaneError>) {
    let _ = reply.send(result);
}

// ---------------------------------------------------------------------------
// Execution on the owner thread.
// ---------------------------------------------------------------------------

/// FXR: the SIMD/FP half of a run's install, decided by [`reconcile_fp`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RunFp {
    /// Full-mode run: full 74-register install, full read, no residency.
    Full,
    /// Guest run: keep the SIMD file resident / install it from the run state.
    Guest(HvfFpInstall),
}

/// FXR: settles who owns the vCPU's SIMD file before a run. A full-mode run, or a guest run of a
/// different thread, first hands the resident file back to its thread (owner change); a guest run
/// of the holding thread keeps it when its claim names exactly this residency, and otherwise
/// (its host copy superseded the resident one) installs its host copy -- which it must carry.
fn reconcile_fp(
    vcpu: &mut HvfVcpu,
    residency: &mut LaneResidency,
    guest: Option<&HvfGuestRun>,
) -> Result<RunFp, HvfVcpuLaneError> {
    use crate::diagnostics_counters::{
        RESIDENT_DEPOSITS_EVICT, RESIDENT_FP_CLAIM_FALLBACK, RESIDENT_FP_FROM_HOST,
        RESIDENT_FP_KEPT, record_resident,
    };
    let Some(guest) = guest else {
        residency.surrender(vcpu, RESIDENT_DEPOSITS_EVICT)?;
        return Ok(RunFp::Full);
    };
    let same_thread = residency
        .holder
        .as_ref()
        .is_some_and(|holder| Arc::ptr_eq(&holder.cell, &guest.cell));
    if same_thread {
        let holds_claim = residency
            .holder
            .as_ref()
            .is_some_and(|holder| Some(holder.seq) == guest.claim.resident_seq);
        if holds_claim {
            record_resident(RESIDENT_FP_KEPT, 1);
            return Ok(RunFp::Guest(HvfFpInstall::Keep));
        }
        // The thread's own resident file, superseded by the host copy it now runs with (a
        // sigreturn / ptrace / clone-setup `set_fp_state`): dead, nobody wants it back.
        residency.holder = None;
        vcpu.discard_unsaved_fp();
    } else {
        residency.surrender(vcpu, RESIDENT_DEPOSITS_EVICT)?;
    }
    if !guest.claim.host_valid {
        return Err(HvfVcpuLaneError::FpResidency {
            lane_generation: residency.lane_generation,
            claimed_seq: guest.claim.resident_seq,
        });
    }
    record_resident(
        if guest.claim.resident_seq.is_some() {
            RESIDENT_FP_CLAIM_FALLBACK
        } else {
            RESIDENT_FP_FROM_HOST
        },
        1,
    );
    Ok(RunFp::Guest(HvfFpInstall::Install))
}

/// FXR: before a lane leaves service after an `Ok` guest run, reads the thread's still-resident
/// SIMD file into the result (so nothing is stranded in a dying vCPU); an unreadable file turns
/// the result into the error.
fn materialize_result_fp(
    vcpu: &mut HvfVcpu,
    residency: &mut LaneResidency,
    result: &mut Result<HvfVcpuRunResult, HvfVcpuLaneError>,
) {
    let Ok(run) = result.as_mut() else {
        return;
    };
    let HvfExitFp::Resident { seq, .. } = run.fp else {
        return;
    };
    if !residency.holder.as_ref().is_some_and(|holder| holder.seq == seq) {
        return;
    }
    residency.holder = None;
    let fp = if vcpu.is_live() {
        vcpu.read_guest_fp().map_err(HvfVcpuLaneError::from)
    } else {
        Err(HvfVcpuLaneError::Hvf(HvfError::VcpuNotLive))
    };
    match fp {
        Ok(fp) => {
            let state = match &mut run.state {
                HvfVcpuExitState::DirectGuest(state) | HvfVcpuExitState::LowerElMonitor(state) => {
                    state
                }
            };
            fp.write_into(state);
            run.fp = HvfExitFp::Materialized;
            crate::diagnostics_counters::record_resident(
                crate::diagnostics_counters::RESIDENT_RESULTS_MATERIALIZED,
                1,
            );
        }
        Err(error) => {
            crate::diagnostics_counters::record_resident(
                crate::diagnostics_counters::RESIDENT_FP_LOST,
                1,
            );
            *result = Err(error);
        }
    }
}

fn execute_attached(
    vcpu: &mut HvfVcpu,
    control: &RunControl,
    lane_generation: u64,
    kind: ExecutionKind,
    mut reservation: HvfVcpuRunReservation,
    attachment: HvfVcpuRunAttachment,
    state: &HvfArchitecturalState,
    guest: Option<HvfGuestRun>,
    residency: &mut LaneResidency,
    vtimer_deadline: Option<u64>,
) -> Result<HvfVcpuRunResult, HvfVcpuLaneError> {
    use crate::diagnostics_counters::{
        OWNER_ARM_VTIMER, OWNER_ATTACHMENT_FINISH, OWNER_BEGIN_RUNNING, OWNER_SETTLE, OWNER_SYNC,
    };
    // Owner-side service span for `HvfVcpuRunResult::owner_ns` (see its doc comment).
    let mut trace = crate::diagnostics_counters::OwnerTrace::start();
    let gate_locks_before = crate::diagnostics_counters::gate_locks_this_thread();
    let run_epoch = reservation.run_epoch();
    // RUNWALL FC2: arm the run's time slice only when the arm is actually due -- once per slice
    // instead of once per run. `None` here means "do not touch the timer this run", which leaves
    // the deadline of the last arm in force. See [`HvfVcpu::vtimer_arm_due`].
    let vtimer_deadline = vtimer_deadline.filter(|cval| vcpu.vtimer_arm_due(*cval));
    let result = (|| {
        let mut desired = *state;
        let mut run_fp = reconcile_fp(vcpu, residency, guest.as_ref())?;
        if attachment.requires_synchronization() {
            crate::diagnostics_counters::record_sync_trip();
            // FXR: the trip installs an all-zero scratch state over the whole register file.
            // Keep the running thread's own resident SIMD file across it by reading it out
            // now and installing it again with the run (every other holder was already
            // handed back by `reconcile_fp`).
            if run_fp == RunFp::Guest(HvfFpInstall::Keep) {
                let fp = vcpu.read_guest_fp()?;
                fp.write_into(&mut desired);
                residency.holder = None;
                run_fp = RunFp::Guest(HvfFpInstall::Install);
                crate::diagnostics_counters::record_resident(
                    crate::diagnostics_counters::RESIDENT_DEPOSITS_SYNC,
                    1,
                );
            }
            attachment.begin_synchronizing(lane_generation)?;
            let proof = synchronize_once(
                vcpu,
                control,
                lane_generation,
                Some(run_epoch),
                attachment.synchronization_request(),
            )?;
            attachment.acknowledge_owner_synchronization(proof)?;
            trace.spans.mark(OWNER_SYNC);
        }
        attachment.begin_running(lane_generation)?;
        trace.spans.mark(OWNER_BEGIN_RUNNING);
        // T2d: one existing-vCPU operation for the whole run -- the vtimer arm, the state install,
        // `hv_vcpu_run`, the execution-time read and the exit read. Ten gate mutex acquisitions
        // become three. Everything before it (the FP reconciliation and the synchronization trip)
        // keeps its own operations: the first is a per-lane-tenant change, the second is rare.
        vcpu.with_run_scope(|scope| {
            // A guest run arms its time slice inside its resident install (one entry point, one
            // admission); a full-mode run keeps the separate arm.
            if run_fp == RunFp::Full
                && let Some(cval) = vtimer_deadline
            {
                scope.arm_vtimer(cval)?;
            }
            trace.spans.mark(OWNER_ARM_VTIMER);
            match (kind, run_fp) {
                (ExecutionKind::Start, RunFp::Full) => run_once(
                    scope,
                    control,
                    lane_generation,
                    run_epoch,
                    &desired,
                    HvfPstateContext::UserEl0t,
                    &mut trace,
                ),
                (ExecutionKind::Start, RunFp::Guest(fp)) => {
                    let Some(guest) = guest.as_ref() else {
                        return Err(HvfVcpuLaneError::RegistryAccounting);
                    };
                    run_guest_once(
                        scope,
                        control,
                        lane_generation,
                        run_epoch,
                        &desired,
                        fp,
                        vtimer_deadline,
                        guest,
                        residency,
                        &mut trace,
                    )
                }
                (ExecutionKind::Resume, RunFp::Full) => {
                    resume_once(scope, control, lane_generation, run_epoch, &desired, &mut trace)
                }
                (ExecutionKind::Resume, RunFp::Guest(_)) => Err(HvfVcpuLaneError::RegistryAccounting),
            }
        })
    })();
    // RUNWALL FC2 review fix-up: `vtimer_arm_due` only decides; the deadline the vCPU actually
    // holds is recorded here, after the run scope that issues the arm has succeeded. Every path
    // that refuses in between quarantines the vCPU, so this was latent rather than live, but the
    // cache must not claim a deadline hardware never received.
    if result.is_ok()
        && let Some(cval) = vtimer_deadline
    {
        vcpu.mark_vtimer_armed(cval);
    }
    let untrusted = result
        .as_ref()
        .is_err_and(HvfVcpuLaneError::terminalizes_execution_vcpu)
        || control.is_untrusted();
    let mut cleanup_error = reservation.settle(untrusted).err();
    trace.spans.mark(OWNER_SETTLE);
    if let Err(error) = attachment.finish().map_err(HvfVcpuLaneError::from) {
        append_lane_error(&mut cleanup_error, error);
    }
    trace.spans.mark(OWNER_ATTACHMENT_FINISH);
    match (result, cleanup_error) {
        (Ok(mut result), None) => {
            result.owner_ns = trace.total_ns();
            result.owner_gate_locks = crate::diagnostics_counters::gate_locks_this_thread()
                .wrapping_sub(gate_locks_before);
            result.owner_end_ticks = trace.spans.last();
            crate::diagnostics_counters::record_owner_run(&trace);
            Ok(result)
        }
        (Err(primary), None) => Err(primary),
        (Err(primary), Some(cleanup)) => Err(primary.with_cleanup(cleanup)),
        (Ok(_), Some(cleanup)) => Err(cleanup),
    }
}

fn synchronize_attached(
    vcpu: &mut HvfVcpu,
    control: &RunControl,
    lane_generation: u64,
    attachment: HvfVcpuRunAttachment,
) -> Result<(), HvfVcpuLaneError> {
    let result = (|| {
        if attachment.requires_synchronization() {
            attachment.begin_synchronizing(lane_generation)?;
            let proof = synchronize_once(
                vcpu,
                control,
                lane_generation,
                None,
                attachment.synchronization_request(),
            )?;
            attachment.acknowledge_owner_synchronization(proof)?;
        }
        Ok(())
    })();
    let cleanup = attachment.finish().map_err(HvfVcpuLaneError::from);
    match (result, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(primary), Ok(())) => Err(primary),
        (Err(primary), Err(cleanup)) => Err(primary.with_cleanup(cleanup)),
        (Ok(()), Err(cleanup)) => Err(cleanup),
    }
}

fn execute_once(
    scope: &mut HvfRunScope<'_, '_>,
    control: &RunControl,
    lane_generation: u64,
    run_epoch: u64,
    trace: &mut crate::diagnostics_counters::OwnerTrace,
) -> Result<(HvfVcpuExit, u64, u64), HvfVcpuLaneError> {
    use crate::diagnostics_counters::{
        OWNER_EXECUTION_TIME, OWNER_RUN_CONTROL_BEGIN, OWNER_RUN_CONTROL_FINISH,
        OWNER_RUN_WRAPPER, RUN_CLASS_AFTER_FULL_SET, RUN_CLASS_NO_SET,
    };
    // Wall time inside `hv_vcpu_run`, summed over reruns: `HvfVcpuRunResult::run_wall_ns`.
    let mut run_wall_ns = 0u64;
    loop {
        control.begin_run(run_epoch)?;
        match control.begin_running(run_epoch) {
            Ok(()) => {}
            Err(HvfVcpuLaneError::LatchedCancellation) => {
                crate::diagnostics_counters::record_canceled(
                    crate::diagnostics_counters::CanceledKind::Latched,
                );
                trace.latched = true;
                trace.spans.mark(OWNER_RUN_CONTROL_BEGIN);
                // T2d: the per-run `hv_vcpu_get_exec_time` is gone -- its only consumer was
                // `HvfVcpuRunResult::execution_time`, which no reader ever read (the one live
                // `execution_time` field belongs to `HvfOwnerSynchronizationProof`, and the
                // synchronization trip still calls the SDK for its own).
                trace.spans.mark(OWNER_EXECUTION_TIME);
                return Ok((HvfVcpuExit::Canceled, run_epoch, run_wall_ns));
            }
            Err(error) => return Err(error),
        }
        trace.spans.mark(OWNER_RUN_CONTROL_BEGIN);
        let run = scope.run();
        let wrapper_ticks = trace.spans.mark(OWNER_RUN_WRAPPER);
        run_wall_ns =
            run_wall_ns.saturating_add(crate::diagnostics_counters::ticks_to_ns(wrapper_ticks));
        if run.is_ok() {
            let (raw_ticks, installs_before) = scope.last_run_profile();
            crate::diagnostics_counters::record_run_split(
                if installs_before == 0 {
                    RUN_CLASS_NO_SET
                } else {
                    RUN_CLASS_AFTER_FULL_SET
                },
                raw_ticks,
                wrapper_ticks,
            );
        }
        let disposition = control.finish_run(run_epoch, &run);
        trace.spans.mark(OWNER_RUN_CONTROL_FINISH);
        let exit = match (run, disposition) {
            (Ok(exit), Ok(RunDisposition::Deliver)) => exit,
            (Ok(_), Ok(RunDisposition::Rerun)) => {
                trace.reruns += 1;
                continue;
            }
            (Err(primary), Ok(_)) => return Err(primary.into()),
            (Ok(_), Err(error)) => return Err(error),
            (Err(primary), Err(cleanup)) => {
                return Err(HvfVcpuLaneError::from(primary).with_cleanup(cleanup));
            }
        };
        hold_vcpu_run_completion_barrier(lane_generation, run_epoch);
        // T2d: dropped, see the `LatchedCancellation` arm above.
        trace.spans.mark(OWNER_EXECUTION_TIME);
        return Ok((exit, run_epoch, run_wall_ns));
    }
}

fn run_once(
    scope: &mut HvfRunScope<'_, '_>,
    control: &RunControl,
    lane_generation: u64,
    run_epoch: u64,
    state: &HvfArchitecturalState,
    context: HvfPstateContext,
    trace: &mut crate::diagnostics_counters::OwnerTrace,
) -> Result<HvfVcpuRunResult, HvfVcpuLaneError> {
    use crate::diagnostics_counters::{OWNER_CLASSIFY, OWNER_GET_STATE, OWNER_SET_STATE};
    scope.set_architectural_state(state, context)?;
    crate::diagnostics_counters::record_set_state(trace.spans.mark(OWNER_SET_STATE));
    let (exit, run_epoch, run_wall_ns) =
        execute_once(scope, control, lane_generation, run_epoch, trace)?;
    if matches!(exit, HvfVcpuExit::Unknown | HvfVcpuExit::Malformed { .. }) {
        return Err(HvfVcpuLaneError::RejectedExit(exit));
    }
    let raw_state = scope.architectural_state_unclassified()?;
    crate::diagnostics_counters::record_get_state(trace.spans.mark(OWNER_GET_STATE));
    let state = classify_exit_state(exit, raw_state)?;
    trace.spans.mark(OWNER_CLASSIFY);
    Ok(HvfVcpuRunResult {
        exit,
        state,
        run_epoch,
        run_wall_ns,
        owner_ns: 0,
        owner_gate_locks: 0,
        owner_wake_ticks: 0,
        owner_end_ticks: 0,
        replied_at_ticks: 0,
        fp: HvfExitFp::Materialized,
    })
}

fn classify_exit_state(
    exit: HvfVcpuExit,
    raw_state: HvfArchitecturalState,
) -> Result<HvfVcpuExitState, HvfVcpuLaneError> {
    match raw_state.cpsr_context() {
        Ok(HvfPstateContext::UserEl0t) => Ok(HvfVcpuExitState::DirectGuest(raw_state)),
        Ok(HvfPstateContext::MonitorEl1h)
            if raw_state
                .require_spsr_el1(HvfPstateContext::UserEl0t)
                .is_ok() =>
        {
            Ok(HvfVcpuExitState::LowerElMonitor(raw_state))
        }
        _ => Err(HvfVcpuLaneError::InvalidExecutionState {
            exit,
            state: (&raw_state).into(),
        }),
    }
}

/// FXR resident-register run of one guest thread: installs only what the vCPU's resident cache
/// does not already hold (`fp` decides the SIMD file), runs, reads back the 39 exit registers,
/// and leaves the SIMD file resident under a fresh identity recorded as this lane's holder.
fn run_guest_once(
    scope: &mut HvfRunScope<'_, '_>,
    control: &RunControl,
    lane_generation: u64,
    run_epoch: u64,
    state: &HvfArchitecturalState,
    fp: HvfFpInstall,
    vtimer_deadline: Option<u64>,
    guest: &HvfGuestRun,
    residency: &mut LaneResidency,
    trace: &mut crate::diagnostics_counters::OwnerTrace,
) -> Result<HvfVcpuRunResult, HvfVcpuLaneError> {
    use crate::diagnostics_counters::{OWNER_CLASSIFY, OWNER_GET_STATE, OWNER_SET_STATE};
    scope.install_guest_state(state, HvfPstateContext::UserEl0t, fp, vtimer_deadline)?;
    crate::diagnostics_counters::record_set_state(trace.spans.mark(OWNER_SET_STATE));
    let (exit, run_epoch, run_wall_ns) =
        execute_once(scope, control, lane_generation, run_epoch, trace)?;
    if matches!(exit, HvfVcpuExit::Unknown | HvfVcpuExit::Malformed { .. }) {
        return Err(HvfVcpuLaneError::RejectedExit(exit));
    }
    let raw_state = scope.read_guest_exit_state()?;
    crate::diagnostics_counters::record_get_state(trace.spans.mark(OWNER_GET_STATE));
    let state = classify_exit_state(exit, raw_state)?;
    let seq = residency.next_seq;
    residency.next_seq = residency.next_seq.wrapping_add(1).max(1);
    match residency.holder.as_mut() {
        // The same thread again (the common case): keep the cell reference already held.
        Some(holder) if Arc::ptr_eq(&holder.cell, &guest.cell) => {
            holder.seq = seq;
            holder.saved = false;
        }
        _ => {
            residency.holder = Some(LaneFpHolder {
                cell: Arc::clone(&guest.cell),
                seq,
                saved: false,
            });
        }
    }
    trace.spans.mark(OWNER_CLASSIFY);
    Ok(HvfVcpuRunResult {
        exit,
        state,
        run_epoch,
        run_wall_ns,
        owner_ns: 0,
        owner_gate_locks: 0,
        owner_wake_ticks: 0,
        owner_end_ticks: 0,
        replied_at_ticks: 0,
        fp: HvfExitFp::Resident {
            lane_generation,
            seq,
        },
    })
}

fn resume_once(
    scope: &mut HvfRunScope<'_, '_>,
    control: &RunControl,
    lane_generation: u64,
    run_epoch: u64,
    state: &HvfArchitecturalState,
    trace: &mut crate::diagnostics_counters::OwnerTrace,
) -> Result<HvfVcpuRunResult, HvfVcpuLaneError> {
    if state.pc != process_hvf_vm()?.monitor().resume_offset() as u64
        || state.esr_el1 != 0x5600_0000
    {
        return Err(HvfVcpuLaneError::InvalidContinuation {
            pc: state.pc,
            cpsr: state.cpsr,
            esr_el1: state.esr_el1,
        });
    }
    state.require_cpsr(HvfPstateContext::MonitorEl1h)?;
    state.require_spsr_el1(HvfPstateContext::UserEl0t)?;
    run_once(
        scope,
        control,
        lane_generation,
        run_epoch,
        state,
        HvfPstateContext::MonitorEl1h,
        trace,
    )
}

#[derive(Clone, Copy)]
struct HvfInternalSideState {
    irq: bool,
    fiq: bool,
    vtimer: HvfVtimerState,
}

fn capture_internal_side_state(
    vcpu: &mut HvfVcpu,
) -> Result<HvfInternalSideState, HvfVcpuLaneError> {
    Ok(HvfInternalSideState {
        irq: vcpu.pending_interrupt(false)?,
        fiq: vcpu.pending_interrupt(true)?,
        vtimer: read_vtimer(vcpu)?,
    })
}

fn suppress_internal_interrupts(vcpu: &mut HvfVcpu) -> Result<(), HvfVcpuLaneError> {
    vcpu.set_pending_interrupt(false, false)?;
    vcpu.set_pending_interrupt(true, false)?;
    vcpu.set_vtimer_mask(true)?;
    Ok(())
}

fn append_cleanup(failures: &mut Option<HvfVcpuLaneError>, result: Result<(), HvfError>) {
    if let Err(error) = result {
        let cleanup = HvfVcpuLaneError::from(error);
        *failures = Some(match failures.take() {
            Some(primary) => primary.with_cleanup(cleanup),
            None => cleanup,
        });
    }
}

fn restore_internal_side_state(
    vcpu: &mut HvfVcpu,
    side: HvfInternalSideState,
) -> Result<(), HvfVcpuLaneError> {
    let mut failures = None;
    append_cleanup(&mut failures, vcpu.set_vtimer_offset(side.vtimer.offset));
    append_cleanup(&mut failures, vcpu.set_vtimer_mask(side.vtimer.masked));
    append_cleanup(&mut failures, vcpu.set_pending_interrupt(true, side.fiq));
    append_cleanup(&mut failures, vcpu.set_pending_interrupt(false, side.irq));
    match failures {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

/// Runs the EL1 synchronization monitor once from the immutable ASID-zero
/// bootstrap root, invalidates the requested nonzero ASID, installs its target
/// stage-one root with an architectural context synchronization event, and then
/// returns through `HVC`. The trip uses canonical scratch architectural state
/// and restores only interrupt/timer side state; every subsequent guest run
/// installs its caller-owned architectural state first.
fn synchronize_once(
    vcpu: &mut HvfVcpu,
    control: &RunControl,
    lane_generation: u64,
    run_epoch: Option<u64>,
    request: HvfSynchronizationRequest,
) -> Result<HvfOwnerSynchronizationProof, HvfVcpuLaneError> {
    if request.address_space_id == 0
        || request.participant_id == 0
        || request.asid == 0
        || request.synchronization_ttbr0_el1 == 0
        || request.synchronization_ttbr0_el1 >> 48 != 0
        || request.synchronization_ttbr0_el1 & STAGE_ONE_TTBR_BASE_MASK == 0
        || request.synchronization_ttbr0_el1 & (STAGE_ONE_TABLE_ALIGNMENT - 1) != 0
        || request.ttbr0_el1 & STAGE_ONE_TTBR_BASE_MASK == 0
        || request.ttbr0_el1 & (STAGE_ONE_TABLE_ALIGNMENT - 1) != 0
        || request.ttbr0_el1 >> 48 != u64::from(request.asid)
        || request.tcr_el1 == 0
        || request.mair_el1 == 0
        || request.root_generation == 0
        || request.tlbi_generation == 0
    {
        return Err(HvfVcpuLaneError::RegistryAccounting);
    }
    let side = capture_internal_side_state(vcpu)?;
    let synchronize_offset = process_hvf_vm()?.monitor().synchronize_offset() as u64;
    let outcome = (|| {
        vcpu.program_stage_one(
            request.synchronization_ttbr0_el1,
            request.tcr_el1,
            request.mair_el1,
        )?;
        loop {
            let mut monitor = HvfArchitecturalState::default();
            monitor.x[0] = u64::from(request.asid) << 48;
            monitor.x[1] = request.ttbr0_el1;
            monitor.pc = synchronize_offset;
            monitor.cpsr = 0x3c5;
            monitor.spsr_el1 = 0;
            vcpu.set_architectural_state(&monitor, HvfPstateContext::MonitorEl1h)?;
            suppress_internal_interrupts(vcpu)?;
            let synchronization_epoch = control.begin_synchronizing(run_epoch)?;
            hold_vcpu_synchronization_barrier();
            let wrapper_start = crate::diagnostics_counters::ticks();
            let run = vcpu.run();
            if run.is_ok() {
                let wrapper_ticks = crate::diagnostics_counters::ticks().wrapping_sub(wrapper_start);
                crate::diagnostics_counters::record_run_split(
                    crate::diagnostics_counters::RUN_CLASS_SYNC_TRIP,
                    vcpu.last_run_profile().0,
                    wrapper_ticks,
                );
            }
            let disposition = control.finish_synchronizing(synchronization_epoch, &run);
            let exit = match (run, disposition) {
                (Ok(exit), Ok(SynchronizationDisposition::Completed)) => exit,
                (Ok(_), Ok(SynchronizationDisposition::Rerun)) => {
                    // FXR: the trip only ever runs the scratch state installed above (the caller
                    // handed every guest thread's resident SIMD file back first), so what the
                    // interrupted attempt left in the SIMD file is scratch too: nothing to save
                    // before the next attempt's full install.
                    vcpu.discard_unsaved_fp();
                    continue;
                }
                (Ok(_), Ok(SynchronizationDisposition::Canceled(_))) => {
                    return Err(HvfVcpuLaneError::LaneClosed);
                }
                (Err(primary), Ok(_)) => return Err(primary.into()),
                (Ok(_), Err(error)) => return Err(error),
                (Err(primary), Err(cleanup)) => {
                    return Err(HvfVcpuLaneError::from(primary).with_cleanup(cleanup));
                }
            };
            let execution_time = vcpu.execution_time()?;
            let exited = vcpu.architectural_state_unclassified()?;
            let valid = matches!(
                exit,
                HvfVcpuExit::Exception(exception)
                    if exception.syndrome == 0x5a00_4c43
                        && exception.virtual_address == 0
                        && exception.physical_address == 0
            ) && exited.pc == synchronize_offset + 32
                && exited.cpsr == 0x3c5;
            if !valid {
                return Err(HvfVcpuLaneError::InvalidSynchronizationExit {
                    exit,
                    lane_generation,
                    request,
                    state: (&exited).into(),
                });
            }
            vcpu.verify_stage_one(request.ttbr0_el1, request.tcr_el1, request.mair_el1)?;
            return Ok((synchronization_epoch, execution_time));
        }
    })();
    let restore = restore_internal_side_state(vcpu, side);
    let (synchronization_epoch, execution_time) = match (outcome, restore) {
        (Ok(outcome), Ok(())) => outcome,
        (Err(primary), Ok(())) => return Err(primary),
        (Err(primary), Err(cleanup)) => return Err(primary.with_cleanup(cleanup)),
        (Ok(_), Err(cleanup)) => return Err(cleanup),
    };
    Ok(HvfOwnerSynchronizationProof {
        lane_generation,
        request,
        synchronization_epoch,
        execution_time,
    })
}

fn set_vtimer(
    vcpu: &mut HvfVcpu,
    masked: bool,
    offset: u64,
) -> Result<HvfVtimerState, HvfVcpuLaneError> {
    vcpu.set_vtimer_offset(offset)?;
    vcpu.set_vtimer_mask(masked)?;
    read_vtimer(vcpu)
}

fn read_vtimer(vcpu: &mut HvfVcpu) -> Result<HvfVtimerState, HvfVcpuLaneError> {
    Ok(HvfVtimerState {
        masked: vcpu.vtimer_mask()?,
        offset: vcpu.vtimer_offset()?,
    })
}

// ---------------------------------------------------------------------------
// BCORE: a vCPU a guest thread creates and drives on its own host thread.
// ---------------------------------------------------------------------------
//
// The whole point of the pooled lane is that Hypervisor.framework is owner-affine: only the
// thread that called `hv_vcpu_create` may run or destroy the vCPU. A lane pays for that with
// two kernel wakeups per guest exit (task thread -> owner thread -> task thread), ~7.1-7.6 us
// of the ~12 us a guest syscall costs. A BOUND vCPU removes the round trip: the guest thread
// *is* the owner thread, so `hv_vcpu_run` is called directly and there is no channel, no
// reply, no second wakeup.
//
// Everything else is unchanged. The bound vCPU registers an ordinary memory-manager
// participant, attaches and submits through `attach_submitted_vcpu`, takes a synchronization
// monitor trip when the space's generations moved, and is cancelled through the same
// `RunControl` a lane uses (`hv_vcpus_exit` is the one SDK call that is not owner-affine).
// Behind `LITEBOX_HVF_BOUND=0` (the default) none of this code runs.

/// BCORE-4: one guest thread's own vCPU.
///
/// Held in thread-local storage, so it is never `Send`. `Drop` is the containment of last
/// resort: dropping a live `HvfVcpu` silently would poison the VM (`impl Drop for HvfVcpu`
/// requests poison when it cannot destroy), so the destructor tries to destroy it on this
/// thread and, failing that, records the slot as `lost`.
pub(crate) struct HvfBoundVcpu {
    vcpu: Option<HvfVcpu>,
    generation: u64,
    control: Arc<RunControl>,
    cancellation: HvfVcpuCancellation,
    lifecycle: Arc<AtomicU8>,
    owner_stopped: Arc<AtomicBool>,
    registry: HvfVcpuRegistry,
}

impl fmt::Debug for HvfBoundVcpu {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HvfBoundVcpu")
            .field("generation", &self.generation)
            .field("live", &self.vcpu.is_some())
            .finish_non_exhaustive()
    }
}

impl HvfBoundVcpu {
    /// Creates and initializes a vCPU on the CALLING thread, which becomes its owner and is
    /// therefore the only thread that may run or destroy it.
    pub(crate) fn bind(
        registry: &HvfVcpuRegistry,
        el1: &HvfEl1State,
    ) -> Result<Self, HvfVcpuLaneError> {
        if !registry.reserve_bound() {
            return Err(HvfVcpuLaneError::Capacity {
                active: registry.active(),
                limit: registry.capacity(),
            });
        }
        let generation = match registry.next_generation() {
            Ok(generation) => generation,
            Err(error) => {
                registry.release_bound();
                return Err(error);
            }
        };
        let vm = process_hvf_vm()?;
        let mut vcpu = match vm.create_vcpu() {
            Ok(vcpu) => vcpu,
            Err(error) => {
                registry.release_bound();
                return Err(error.into());
            }
        };
        let lifecycle = Arc::new(AtomicU8::new(LANE_LIVE));
        let owner_stopped = Arc::new(AtomicBool::new(false));
        let control = Arc::new(RunControl::new_bound(true));
        let cancellation = match Self::initialize(&mut vcpu, el1) {
            Ok(cancellation) => cancellation,
            Err(error) => {
                // `vcpu` is still live here, so the only way to retire it is the explicit
                // destroy; letting it drop would poison the VM.
                let _ = vcpu.destroy();
                registry.release_bound();
                return Err(error);
            }
        };
        crate::diagnostics_counters::add_stat(crate::diagnostics_counters::BOUND_BINDS, 1);
        Ok(Self {
            vcpu: Some(vcpu),
            generation,
            control,
            cancellation,
            lifecycle,
            owner_stopped,
            registry: registry.clone(),
        })
    }

    /// EL1 setup plus the vtimer baseline of a freshly created bound vCPU. Split out of
    /// [`Self::bind`] so every failure path there can still destroy the vCPU it created.
    fn initialize(
        vcpu: &mut HvfVcpu,
        el1: &HvfEl1State,
    ) -> Result<HvfVcpuCancellation, HvfVcpuLaneError> {
        vcpu.initialize_el1(el1)?;
        // Guest `CNTVCT_EL0` with offset 0: `mach_absolute_time` reads the same counter the
        // guest sees, so a deadline computed from it is directly a `CNTV_CVAL_EL0`.
        set_vtimer(vcpu, true, 0)?;
        vcpu.cancellation().map_err(HvfVcpuLaneError::from)
    }

    pub(crate) const fn generation(&self) -> u64 {
        self.generation
    }

    pub(crate) fn control(&self) -> Arc<RunControl> {
        Arc::clone(&self.control)
    }

    /// The raw SDK cancellation handle, for a kick aimed at this vCPU from another thread
    /// (`HvfBackend::kick_running_lanes`).
    pub(crate) fn sdk_cancellation(&self) -> HvfVcpuCancellation {
        self.cancellation.clone()
    }

    pub(crate) fn participant_capability(&self) -> HvfVcpuLaneParticipantCapability {
        HvfVcpuLaneParticipantCapability::for_bound(
            self.generation,
            Arc::clone(&self.lifecycle),
            Arc::clone(&self.owner_stopped),
        )
    }

    /// Reserves one run epoch. `Ok` moves the control to `Reserved`; the caller must settle it
    /// (directly, or through [`Self::execute`], which always does).
    pub(crate) fn reserve_run(&self) -> Result<u64, HvfVcpuLaneError> {
        if self.lifecycle.load(Ordering::Acquire) != LANE_LIVE {
            return Err(HvfVcpuLaneError::LaneClosed);
        }
        self.control.reserve_run()
    }

    /// The cancellation handle this thread publishes into its `HvfThreadSlot` for one run, so
    /// an interrupt aimed at the running guest thread reaches this vCPU.
    pub(crate) fn cancellation_for(&self, run_epoch: u64) -> HvfVcpuLaneCancellation {
        HvfVcpuLaneCancellation::for_bound(
            self.generation,
            Some(run_epoch),
            self.cancellation.clone(),
            Arc::clone(&self.lifecycle),
            Arc::clone(&self.control),
        )
    }

    /// BCORE-4: one guest run, Start shape, full architectural install and full exit read.
    ///
    /// The resident-state diff-and-set and the 39-get exit read are BRES's job; until then a
    /// bound run installs and reads the same 74 registers a pooled full-mode run does, so the
    /// only difference from the lane path is that no thread boundary is crossed.
    pub(crate) fn execute(
        &mut self,
        run_epoch: u64,
        attachment: HvfVcpuRunAttachment,
        state: &HvfArchitecturalState,
        vtimer_deadline: Option<u64>,
    ) -> Result<HvfVcpuRunResult, HvfVcpuLaneError> {
        let vcpu = self
            .vcpu
            .as_mut()
            .ok_or(HvfVcpuLaneError::LaneClosed)?;
        execute_bound_attached(
            vcpu,
            &self.control,
            self.generation,
            run_epoch,
            attachment,
            state,
            vtimer_deadline,
        )
    }

    /// BCORE-5: marks this vCPU's owner stopped, which is what lets
    /// `deregister_vcpu_participant` acknowledge retirements this participant still owes
    /// instead of refusing with `ParticipantRetirementPending`.
    pub(crate) fn stop_owner(&self) {
        self.owner_stopped.store(true, Ordering::Release);
    }

    /// BCORE-2 (fix-up): discharges this vCPU's control BEFORE the vCPU is destroyed.
    ///
    /// Every other `terminalize` call site is a lane/phase path, none of which is reachable
    /// from a bound vCPU's teardown -- so before this existed, a bound vCPU destroyed while a
    /// kick was still outstanding silently dropped the debit. That is why
    /// `BOUND_KICKS_ABANDONED` and `BOUND_KICKS_EXPIRED_TERMINAL` were 0 in every bound run
    /// ever taken: not because nothing was ever abandoned, but because the counter that would
    /// report it never ran. It also completes any in-flight `CancellationAttempt` with
    /// `Terminalized`, so a thread that kicked this vCPU and is still waiting gets
    /// `HvfVcpuLaneError::LaneClosed` instead of waiting on a vCPU that no longer exists.
    fn terminalize_control(&self, untrusted: bool) {
        let mut state = self.control.lock();
        self.control.terminalize(
            &mut state,
            untrusted,
            CancellationCompletion::Terminalized,
        );
    }

    /// BCORE-5: destroys the vCPU on this (owner) thread and gives the registry slot back.
    /// Called only after the participant has been deregistered.
    ///
    /// BCORE2-FX: takes `&mut self` instead of `self` because `BoundThread` now has its own
    /// destructor (it is what discharges the participant on the unwind arm), and a type with a
    /// `Drop` impl does not let a field be moved out of it. Semantics are unchanged: the vCPU
    /// is taken out of the `Option`, so the destructor that follows is a no-op.
    ///
    /// `untrusted` is true when the unbind follows a run error rather than an orderly thread
    /// exit: it is the same distinction the lane paths make, and it is what `terminalize`
    /// records so a teardown that lost track of a kick is not reported as a clean one.
    pub(crate) fn unbind(&mut self, untrusted: bool) -> Result<(), HvfVcpuLaneError> {
        self.stop_owner();
        self.terminalize_control(untrusted);
        let Some(vcpu) = self.vcpu.take() else {
            return Ok(());
        };
        let result = vcpu.destroy().map_err(HvfVcpuLaneError::from);
        if result.is_ok() {
            self.registry.release_bound();
        } else {
            self.registry.record_lost();
        }
        result
    }
}

impl Drop for HvfBoundVcpu {
    fn drop(&mut self) {
        let Some(vcpu) = self.vcpu.take() else {
            return;
        };
        self.owner_stopped.store(true, Ordering::Release);
        // BCORE-2 (fix-up): same discharger as `unbind`. A `Drop` is an unwind, so it is
        // untrusted by definition: this thread is not completing an orderly teardown.
        self.terminalize_control(true);
        // Best-effort: this is the TLS destructor of a thread that is already unwinding. Any
        // other outcome would drop a live `HvfVcpu`, whose own destructor poisons the VM.
        let destroyed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| vcpu.destroy()));
        // BCORE-5: this vCPU's `BoundEntry` -- the row `kick_running_lanes` and pressure
        // eviction walk -- lives on the backend, not on the vCPU, and an owner thread that
        // unwinds never reaches `unbind_current_thread`. A destructor that left it behind
        // would keep a dead generation in that list for the rest of the process: kicked on
        // every mutation round, and eligible to be picked as an eviction victim no thread
        // can honour. Removing it here is what makes the two teardown paths equivalent AS FAR
        // AS THE ENTRY LIST GOES -- the participant half of the teardown is discharged by
        // `Drop for BoundThread`, which runs before this one because `BoundThread` owns both
        // fields. If either half is missing, an unwound owner strands its address space
        // (`begin_destroy` refuses with `AddressSpaceBusy` while a participant record
        // remains).
        if let Some(backend) = crate::hvf_backend::active() {
            backend.remove_bound_entry(self.generation);
        }
        // `BOUND_LIVE` is a gauge of live bound vCPUs, so it comes down in BOTH arms: a vCPU
        // that could not be destroyed is gone from this process's point of view just the same
        // (it was recorded as lost, and the VM is asked to poison rather than keep it).
        crate::diagnostics_counters::add_stat(crate::diagnostics_counters::BOUND_LIVE, u64::MAX);
        match destroyed {
            Ok(Ok(())) => {
                self.registry.release_bound();
                crate::diagnostics_counters::add_stat(
                    crate::diagnostics_counters::BOUND_UNBINDS_DROP,
                    1,
                );
            }
            _ => {
                self.registry.record_lost();
                crate::diagnostics_counters::add_stat(crate::diagnostics_counters::BOUND_LOST, 1);
            }
        }
    }
}

/// BCORE-4: the owner-side body of one bound run.
///
/// Shaped exactly like `execute_attached`, minus everything a lane needs and a bound vCPU does
/// not: no reservation object (the caller settles `control` directly), no resident SIMD/FP
/// custody (the install and the read are both full, so `FpLocation` stays `Host`), no
/// `ExecutionKind::Resume` (a bound vCPU is never mid-monitor, so it always starts from EL0).
fn execute_bound_attached(
    vcpu: &mut HvfVcpu,
    control: &RunControl,
    generation: u64,
    run_epoch: u64,
    attachment: HvfVcpuRunAttachment,
    state: &HvfArchitecturalState,
    vtimer_deadline: Option<u64>,
) -> Result<HvfVcpuRunResult, HvfVcpuLaneError> {
    use crate::diagnostics_counters::{
        OWNER_ARM_VTIMER, OWNER_ATTACHMENT_FINISH, OWNER_BEGIN_RUNNING, OWNER_SETTLE, OWNER_SYNC,
    };
    let mut trace = crate::diagnostics_counters::OwnerTrace::start();
    let gate_locks_before = crate::diagnostics_counters::gate_locks_this_thread();
    // BCORE-3: arm only when the previous slice's deadline is spent (or nothing is armed).
    // `vtimer_arm_due` is a pure predicate; `mark_vtimer_armed` records what hardware got.
    let vtimer_deadline = vtimer_deadline.filter(|cval| vcpu.vtimer_arm_due(*cval));
    let result = (|| {
        if attachment.requires_synchronization() {
            crate::diagnostics_counters::record_sync_trip();
            crate::diagnostics_counters::add_stat(
                crate::diagnostics_counters::BOUND_SYNC_TRIPS,
                1,
            );
            // BCORE-3: the trip's own `suppress_internal_interrupts` /
            // `restore_internal_side_state` pair can leave `CNTV_CVAL_EL0` in the past (the
            // timer fired and auto-masked inside the trip), so the cached armed deadline is
            // not trustworthy afterwards: force a fresh arm on the next run.
            vcpu.clear_vtimer_armed();
            attachment.begin_synchronizing(generation)?;
            let proof = synchronize_once(
                vcpu,
                control,
                generation,
                Some(run_epoch),
                attachment.synchronization_request(),
            )?;
            attachment.acknowledge_owner_synchronization(proof)?;
            trace.spans.mark(OWNER_SYNC);
        }
        attachment.begin_running(generation)?;
        trace.spans.mark(OWNER_BEGIN_RUNNING);
        // T2d: one existing-vCPU operation for the arm, the install, `hv_vcpu_run` and the
        // exit read -- the same shape the pooled path gets after T2d.
        vcpu.with_run_scope(|scope| {
            if let Some(cval) = vtimer_deadline {
                scope.arm_vtimer(cval)?;
                crate::diagnostics_counters::add_stat(
                    crate::diagnostics_counters::BOUND_VTIMER_REARMS,
                    1,
                );
            }
            trace.spans.mark(OWNER_ARM_VTIMER);
            run_once(
                scope,
                control,
                generation,
                run_epoch,
                state,
                HvfPstateContext::UserEl0t,
                &mut trace,
            )
        })
    })();
    if result.is_ok()
        && let Some(cval) = vtimer_deadline
    {
        vcpu.mark_vtimer_armed(cval);
    }
    if trace.latched {
        // BCORE-2: an interrupt aimed at this run arrived before the guest was entered, so the
        // run completed as `Canceled` without ever executing guest code.
        crate::diagnostics_counters::add_stat(
            crate::diagnostics_counters::BOUND_INTERRUPTS_LATCHED_PRE_ENTRY,
            1,
        );
    }
    let untrusted = result
        .as_ref()
        .is_err_and(HvfVcpuLaneError::terminalizes_execution_vcpu)
        || control.is_untrusted();
    let mut cleanup_error = control.settle_reservation(run_epoch, true, untrusted).err();
    trace.spans.mark(OWNER_SETTLE);
    if let Err(error) = attachment.finish().map_err(HvfVcpuLaneError::from) {
        append_lane_error(&mut cleanup_error, error);
    }
    trace.spans.mark(OWNER_ATTACHMENT_FINISH);
    match (result, cleanup_error) {
        (Ok(mut result), None) => {
            result.owner_ns = trace.total_ns();
            result.owner_gate_locks = crate::diagnostics_counters::gate_locks_this_thread()
                .wrapping_sub(gate_locks_before);
            result.owner_end_ticks = trace.spans.last();
            crate::diagnostics_counters::record_owner_run(&trace);
            Ok(result)
        }
        (Err(primary), None) => Err(primary),
        (Err(primary), Some(cleanup)) => Err(primary.with_cleanup(cleanup)),
        (Ok(_), Some(cleanup)) => Err(cleanup),
    }
}

