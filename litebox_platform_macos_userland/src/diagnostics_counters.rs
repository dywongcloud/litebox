// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Shared, lock-free production counters backing the HVF side of the
//! `diagnostics-counter-readout-surface`: per-[`HvfAddressSpaceId`] SVC-exit counts and a
//! syscall-cost histogram (`hvf-per-space-syscall-cost-and-handoff-counters`), a fixed-size
//! structured per-syscall ring, the W^X service-latency histogram fields on
//! [`crate::hvf_backend::HvfExceptionCounters`] read back through
//! [`crate::hvf_backend::HvfBackend::exception_counters_snapshot`]
//! (`wx-service-latency-measurement`), and the JSON assembly
//! ([`full_snapshot_json`]) that folds all of the above together with the pre-existing
//! `hvf_backend` exception/lifecycle counters into one generation-stamped snapshot that
//! `litebox_runner_linux_on_macos_userland` publishes and that `litebox::fs::proc`'s
//! `/proc/litebox/counters` reads back through the same registered provider.
//!
//! Every table here is a fixed-size array of plain atomics, `Default`/const-zeroed for the
//! process's whole lifetime -- no lock, no allocation on the syscall hot path -- matching the
//! existing `DELIVERED_TASK_RING` convention in `hvf_backend`. A slot that fills (extremely
//! unlikely: the space table has far more slots than `HvfMemoryLimits::max_address_spaces`
//! (254) permits live spaces) is dropped silently rather than blocking or panicking a real
//! syscall path; this is a best-effort diagnostic, never a correctness dependency, exactly like
//! the ring it shares that property with.

use std::cell::Cell;
use std::panic::Location;
use std::sync::atomic::{AtomicI64, AtomicU8, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError, TryLockError};
use std::time::Instant;

use crate::hvf_memory::HvfAddressSpaceId;

/// Number of bit-length-of-nanoseconds-scale buckets shared by every latency/cost histogram in
/// this module: bucket `0` is exactly `ns == 0`; for `i >= 1`, bucket `i` counts samples with
/// `2^(i-1) <= ns < 2^i` (`i` is `ns`'s own bit length, `64 - ns.leading_zeros()`). Live example
/// verified against a real HVF Node run: a `990_791`ns sample (`0b1111_0001_1000_0100_0111`, 20
/// significant bits) landed in bucket 20, i.e. `[2^19, 2^20)` = `[524_288, 1_048_576)`, not
/// `[2^20, 2^21)` -- read bucket index as "how many bits", not "which power of two starts it".
/// Bucket 31 alone already covers durations over 1 second -- far past anything a real syscall or
/// W^X service call should ever take -- so the top bucket is a safe overflow catch-all in
/// practice, never actually reached by a real sample.
pub(crate) const LATENCY_BUCKETS: usize = 32;

pub(crate) const fn latency_bucket_index(ns: u64) -> usize {
    if ns == 0 {
        0
    } else {
        let bits = (64 - ns.leading_zeros()) as usize;
        if bits < LATENCY_BUCKETS { bits } else { LATENCY_BUCKETS - 1 }
    }
}

const fn zeroed_u64_array<const N: usize>() -> [AtomicU64; N] {
    const ZERO: AtomicU64 = AtomicU64::new(0);
    [ZERO; N]
}

const fn zeroed_i64_array<const N: usize>() -> [AtomicI64; N] {
    const ZERO: AtomicI64 = AtomicI64::new(0);
    [ZERO; N]
}

// ---------------------------------------------------------------------------
// Per-space SVC exit counts + syscall cost histogram (hvf-per-space-syscall-cost-and-
// handoff-counters, sub-piece 1).
// ---------------------------------------------------------------------------

/// Fixed-size open-addressed table of per-[`HvfAddressSpaceId`] SVC-exit accounting: a
/// syscall-cost histogram plus exit count, sum and max nanoseconds, keyed by
/// `space_id.value() + 1` (`0` marks an empty slot; the `+1` shift means a real id of `0` is
/// still representable). Sized well past `HvfMemoryLimits::max_address_spaces` (254) so
/// collisions needing more than a handful of probes are effectively impossible over a space's
/// whole lifetime.
const SPACE_TABLE_LEN: usize = 320;

struct SpaceSlot {
    tag: AtomicU64,
    svc_exits: AtomicU64,
    total_ns: AtomicU64,
    max_ns: AtomicU64,
    /// hvf-exit-overhead-instrumentation: `total_ns` minus the time the syscall spent parked in
    /// an interruptible wait (see [`SYSCALL_SERVICE`]), so `service_ns / svc_exits` is this
    /// space's mean shim *service* time rather than its mean blocked time.
    service_ns: AtomicU64,
    buckets: [AtomicU64; LATENCY_BUCKETS],
}

impl SpaceSlot {
    const fn new() -> Self {
        Self {
            tag: AtomicU64::new(0),
            svc_exits: AtomicU64::new(0),
            total_ns: AtomicU64::new(0),
            max_ns: AtomicU64::new(0),
            service_ns: AtomicU64::new(0),
            buckets: zeroed_u64_array(),
        }
    }
}

static SPACE_TABLE: [SpaceSlot; SPACE_TABLE_LEN] = {
    const SLOT: SpaceSlot = SpaceSlot::new();
    [SLOT; SPACE_TABLE_LEN]
};

/// Diagnostic samples dropped because [`SPACE_TABLE`] was somehow completely full (every slot
/// already claimed by a different space) -- counted so an operator can tell whether the table
/// ever actually saturated rather than the readout silently under-reporting.
static SPACE_TABLE_OVERFLOWS: AtomicU64 = AtomicU64::new(0);

static GLOBAL_SVC_EXITS: AtomicU64 = AtomicU64::new(0);
static GLOBAL_SVC_TOTAL_NS: AtomicU64 = AtomicU64::new(0);
static GLOBAL_SVC_MAX_NS: AtomicU64 = AtomicU64::new(0);
static GLOBAL_SVC_BUCKETS: [AtomicU64; LATENCY_BUCKETS] = zeroed_u64_array();

/// Records one completed `EC_SVC64` dispatch (see `HvfBackend::dispatch_monitor_exit`) against
/// its address space's slot and the global totals. Lock-free: an open-addressing linear probe
/// from a multiplicative hash of the tag, claiming an empty slot with one `compare_exchange`.
/// Called on every guest syscall, so deliberately just a handful of relaxed atomic RMWs -- no
/// lock, no allocation.
fn record_space_syscall(space_id: HvfAddressSpaceId, elapsed_ns: u64, blocked_ns: u64) {
    GLOBAL_SVC_EXITS.fetch_add(1, Ordering::Relaxed);
    GLOBAL_SVC_TOTAL_NS.fetch_add(elapsed_ns, Ordering::Relaxed);
    GLOBAL_SVC_MAX_NS.fetch_max(elapsed_ns, Ordering::Relaxed);
    GLOBAL_SVC_BUCKETS[latency_bucket_index(elapsed_ns)].fetch_add(1, Ordering::Relaxed);
    // hvf-exit-overhead-instrumentation: the blocked/service split. `blocked_ns` is the wall time
    // this syscall's host thread spent between `WaitContext::start_wait` and `end_wait` (an
    // interruptible guest-condition wait: futex, poll/epoll, blocking read, nanosleep, ...), so
    // `elapsed - blocked` is the shim's own service time for it.
    let service_ns = elapsed_ns.saturating_sub(blocked_ns);
    SYSCALL_SERVICE.record(service_ns);
    if blocked_ns != 0 {
        SYSCALL_BLOCKED_NS.fetch_add(blocked_ns, Ordering::Relaxed);
        SYSCALL_BLOCKED_COUNT.fetch_add(1, Ordering::Relaxed);
    }

    let tag = space_id.value().wrapping_add(1);
    // Fibonacci/multiplicative hashing (Knuth): spreads sequential ids (the common case, since
    // `HvfAddressSpaceId` is minted from an incrementing counter) evenly across the table
    // instead of clustering them, with no dependency and no real hash function needed.
    let start = (tag.wrapping_mul(0x9E37_79B9_7F4A_7C15) as usize) % SPACE_TABLE_LEN;
    for offset in 0..SPACE_TABLE_LEN {
        let idx = (start + offset) % SPACE_TABLE_LEN;
        let slot = &SPACE_TABLE[idx];
        let existing = slot.tag.load(Ordering::Acquire);
        let owns = existing == tag
            || (existing == 0
                && slot
                    .tag
                    .compare_exchange(0, tag, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok());
        if owns {
            slot.svc_exits.fetch_add(1, Ordering::Relaxed);
            slot.total_ns.fetch_add(elapsed_ns, Ordering::Relaxed);
            slot.max_ns.fetch_max(elapsed_ns, Ordering::Relaxed);
            slot.service_ns.fetch_add(service_ns, Ordering::Relaxed);
            slot.buckets[latency_bucket_index(elapsed_ns)].fetch_add(1, Ordering::Relaxed);
            return;
        }
    }
    SPACE_TABLE_OVERFLOWS.fetch_add(1, Ordering::Relaxed);
}

// ---------------------------------------------------------------------------
// vCPU lane wait + exit-to-reentry handoff cost (k2p-exit-handoff-lane-wait-counters).
// ---------------------------------------------------------------------------

/// One lock-free `(count, sum, max, log2 buckets)` cost histogram: a [`SpaceSlot`]'s shape for
/// a cost that has no per-space key. Same bucket convention as every other histogram here
/// ([`latency_bucket_index`]), same relaxed-atomic hot path as [`record_space_syscall`].
struct CostHistogram {
    count: AtomicU64,
    sum_ns: AtomicU64,
    max_ns: AtomicU64,
    buckets: [AtomicU64; LATENCY_BUCKETS],
}

impl CostHistogram {
    const fn new() -> Self {
        Self {
            count: AtomicU64::new(0),
            sum_ns: AtomicU64::new(0),
            max_ns: AtomicU64::new(0),
            buckets: zeroed_u64_array(),
        }
    }

    fn record(&self, ns: u64) {
        self.count.fetch_add(1, Ordering::Relaxed);
        self.sum_ns.fetch_add(ns, Ordering::Relaxed);
        self.max_ns.fetch_max(ns, Ordering::Relaxed);
        self.buckets[latency_bucket_index(ns)].fetch_add(1, Ordering::Relaxed);
    }

    fn snapshot(&self) -> (u64, u64, u64, [u64; LATENCY_BUCKETS]) {
        (
            self.count.load(Ordering::Relaxed),
            self.sum_ns.load(Ordering::Relaxed),
            self.max_ns.load(Ordering::Relaxed),
            core::array::from_fn(|i| self.buckets[i].load(Ordering::Relaxed)),
        )
    }
}

/// Wall time a guest host thread spent inside `HvfBackend::acquire_lane_for_thread` per
/// `run_thread` loop iteration: near zero while a lane is free, FIFO queueing behind other
/// runnable guest threads (10 ms time slices) once the pool is oversubscribed. One sample per
/// acquisition attempt, including one cut short by a pending thread interrupt.
static LANE_WAIT: CostHistogram = CostHistogram::new();

/// The per-exit overhead the syscall histogram cannot see: everything a guest host thread pays
/// from the moment it holds a lane to the moment it has released it, MINUS the wall time the
/// owner thread spent inside `hv_vcpu_run` itself (the guest actually executing). That is: run
/// reservation, view attachment/migration, the `execute()` command round trip (queue + unpark +
/// park + reply channel), the owner's own marshalling (architectural-state set/readback, vtimer,
/// a synchronization monitor trip when the lane changed view) and the lane release. One sample
/// per completed run; the sums below split it further.
static HANDOFF: CostHistogram = CostHistogram::new();

/// Split of [`HANDOFF`]'s sum: `execute()` round trip minus the owner thread's own service time
/// (`execute_attached` entry to result) = the two cross-thread wakeups plus queueing/scheduling.
static HANDOFF_CHANNEL_NS: AtomicU64 = AtomicU64::new(0);
/// Split of [`HANDOFF`]'s sum: owner-side service time minus `hv_vcpu_run` wall time = state
/// marshalling, vtimer arming, synchronization trips, reservation settle, attachment finish.
static HANDOFF_OWNER_NS: AtomicU64 = AtomicU64::new(0);
/// The subtrahend itself, summed: wall time inside `hv_vcpu_run` (guest execution plus the
/// hypervisor's own entry/exit), so a reader can close the accounting against the wall clock.
static GUEST_RUN_WALL_NS: AtomicU64 = AtomicU64::new(0);
/// Owner-thread synchronization monitor trips (an extra `hv_vcpu_run` with TLBI + TTBR
/// reprogramming, paid whenever a lane attaches to a view other than the one it last ran).
static SYNC_TRIPS: AtomicU64 = AtomicU64::new(0);

pub(crate) fn elapsed_ns(start: Instant) -> u64 {
    u64::try_from(start.elapsed().as_nanos()).unwrap_or(u64::MAX)
}

pub(crate) fn record_lane_wait(ns: u64) {
    LANE_WAIT.record(ns);
}

/// `lane_held_ns` spans acquire-to-release on the guest thread, `execute_ns` the `execute()`
/// round trip inside it, `owner_ns` the owner thread's `execute_attached` service inside that,
/// and `run_wall_ns` the `hv_vcpu_run` wall time inside that -- four nested host-tick spans, so
/// the saturating subtractions only guard against two threads' clock reads disagreeing.
pub(crate) fn record_handoff(lane_held_ns: u64, execute_ns: u64, owner_ns: u64, run_wall_ns: u64) {
    HANDOFF.record(lane_held_ns.saturating_sub(run_wall_ns));
    HANDOFF_CHANNEL_NS.fetch_add(execute_ns.saturating_sub(owner_ns), Ordering::Relaxed);
    HANDOFF_OWNER_NS.fetch_add(owner_ns.saturating_sub(run_wall_ns), Ordering::Relaxed);
    GUEST_RUN_WALL_NS.fetch_add(run_wall_ns, Ordering::Relaxed);
}

pub(crate) fn record_sync_trip() {
    SYNC_TRIPS.fetch_add(1, Ordering::Relaxed);
}

// ---------------------------------------------------------------------------
// hvf-exit-overhead-instrumentation: the rest of the unmeasured exit path -- whole-iteration
// overhead, view migrations, mutation kicks and the canceled runs they cause, and the
// blocked/service split of the syscall histogram. Same relaxed-atomic, lock-free shape as above.
// ---------------------------------------------------------------------------

/// Wall time of one `run_thread` loop iteration -- from `run_with_deadline_reserved` returning
/// to the next `run_with_deadline_reserved` submit on the same guest thread -- MINUS the
/// `shim.syscall` elapsed (blocked time included) that `syscall_global` already accounts for.
/// One sample per iteration whose dispatch was an `EC_SVC64` syscall: lane release, retirement
/// pumping, `dispatch` bookkeeping around the shim call, loop-top interrupt checks, the lane wait
/// ([`LANE_WAIT`]), run reservation, view attachment/migration ([`LANE_MIGRATION`]) and the
/// `attach_vcpu` handshake. Everything the guest pays per syscall that is neither the shim nor
/// the owner thread's own service ([`HANDOFF`] covers the latter from the lane-held side).
static EXIT_OVERHEAD: CostHistogram = CostHistogram::new();
/// Iterations whose dispatch was NOT a syscall (page fault service, W^X flip, `WFx` yield, a
/// canceled or time-sliced run): counted and summed separately so fault/flip service time never
/// pollutes [`EXIT_OVERHEAD`]. The sum is the whole iteration wall time (nothing subtracted).
static NONSYSCALL_ITERATIONS: AtomicU64 = AtomicU64::new(0);
static NONSYSCALL_ITERATION_NS: AtomicU64 = AtomicU64::new(0);

/// `ensure_lane_attached_to_view`'s migrate arm: the lane's last view differs from this thread's,
/// so its participant is re-registered in the target space (two exclusive VM operations); the
/// following attach then also `requires_synchronization` (a [`SYNC_TRIPS`] monitor trip on the
/// owner). `count / handoff.count` is the migrations-per-run ratio the LRU lane handout produces.
static LANE_MIGRATION: CostHistogram = CostHistogram::new();

/// `kick_running_lanes` rounds (one per Protect/Unmap mutation, plus lane-pool failures and
/// shootdowns) and the per-lane outcomes of each: `KICK_REQUESTS` is the number of lanes asked,
/// `KICK_IDLE` those that reported `VcpuNotRunning` (no run in flight, nothing to do),
/// `KICK_ERRORS` any other refusal.
static KICK_ROUNDS: AtomicU64 = AtomicU64::new(0);
static KICK_REQUESTS: AtomicU64 = AtomicU64::new(0);
static KICK_IDLE: AtomicU64 = AtomicU64::new(0);
static KICK_ERRORS: AtomicU64 = AtomicU64::new(0);
/// `RunControl::request_public` outcomes for every cancellation request that reached it (mutation
/// kicks from `kick_running_lanes` are the overwhelming majority; thread interrupts also pass
/// through here, so `issued + latched` can slightly exceed `KICK_REQUESTS - KICK_IDLE -
/// KICK_ERRORS`): `issued` = a real `hv_vcpus_exit` against a lane in `Running`, `latched` = a
/// lane in `Reserved`/`Entering`/`Synchronizing` whose imminent run will return `Canceled`
/// without ever entering the guest.
static KICKS_ISSUED: AtomicU64 = AtomicU64::new(0);
static KICKS_LATCHED: AtomicU64 = AtomicU64::new(0);
/// Guest-side cost of those kicks, from `dispatch`: `CANCELED_EXITS` is the `(Canceled,
/// DirectGuest)` arm with no thread interrupt pending -- a whole wasted loop iteration (release,
/// re-acquire, re-attach, synchronize, re-run) that resumes at the same PC; `CANCELED_INTERRUPTS`
/// the same arm with a real interrupt to deliver; `CANCELED_MONITOR_EXITS` the kick that landed
/// right after EL0 exception entry (dispatched as the syscall it interrupted, not wasted);
/// `CANCELED_LATCHED` the owner-side `LatchedCancellation` short-circuit (counted there, and
/// again in `CANCELED_EXITS` once the guest thread dispatches it).
static CANCELED_EXITS: AtomicU64 = AtomicU64::new(0);
static CANCELED_INTERRUPTS: AtomicU64 = AtomicU64::new(0);
static CANCELED_MONITOR_EXITS: AtomicU64 = AtomicU64::new(0);
static CANCELED_LATCHED: AtomicU64 = AtomicU64::new(0);

/// Shim service time per syscall: `syscall_global`'s elapsed minus the time the syscall's host
/// thread spent parked in an interruptible wait. `syscall_global.total_ns` on a real desktop is
/// dominated by multi-second futex/epoll waits (a 600 s max was observed live), which made its
/// mean meaningless as a service-time figure; this histogram is the real one.
static SYSCALL_SERVICE: CostHistogram = CostHistogram::new();
/// Sum of blocked nanoseconds over all syscalls and the number of syscalls that blocked at all
/// (`syscall_global.total_ns - SYSCALL_BLOCKED_NS == SYSCALL_SERVICE.sum_ns`, up to saturation).
static SYSCALL_BLOCKED_NS: AtomicU64 = AtomicU64::new(0);
static SYSCALL_BLOCKED_COUNT: AtomicU64 = AtomicU64::new(0);

thread_local! {
    /// Blocked-time accounting for the current host thread: the `Instant` at which its current
    /// interruptible wait began (`WaitContext::start_wait` -> `RawMutexProvider::update_waker`
    /// with `Some`), and the nanoseconds accumulated over completed waits since the last
    /// [`take_blocked_ns`]. A guest thread's syscalls run on its own host thread, so a per-thread
    /// cell IS a per-task cell here, with no lock and no task lookup.
    static WAIT_START: Cell<Option<Instant>> = const { Cell::new(None) };
    static BLOCKED_NS: Cell<u64> = const { Cell::new(0) };
    /// The `shim.syscall` elapsed of the most recent `EC_SVC64` dispatch on this thread, `None`
    /// when the most recent dispatch was not a syscall -- read (and cleared) by `run_thread` to
    /// split the next iteration's wall time into [`EXIT_OVERHEAD`] vs [`NONSYSCALL_ITERATIONS`].
    static LAST_SYSCALL_NS: Cell<Option<u64>> = const { Cell::new(None) };
}

/// `RawMutexProvider::update_waker(Some(_))` on this thread: an interruptible wait is starting.
/// `WaitContext::wait_until` calls `start_wait` again on EVERY wakeup of one logical wait (each
/// loop iteration re-evaluates `ready` after re-arming), and `end_wait` only once at the end, so
/// an already-armed start is kept -- resetting it here would keep only the last wakeup-to-end
/// slice and under-report a spuriously-woken futex/epoll wait by its whole earlier span (seen
/// live: 40 s `epoll_pwait` elapsed with a fraction of it banked, before this guard).
pub(crate) fn wait_started() {
    WAIT_START.with(|start| {
        if start.get().is_none() {
            start.set(Some(Instant::now()));
        }
    });
}

/// `RawMutexProvider::update_waker(None)` on this thread: the wait ended; bank its wall time.
pub(crate) fn wait_ended() {
    if let Some(start) = WAIT_START.with(Cell::take) {
        BLOCKED_NS.with(|blocked| blocked.set(blocked.get().saturating_add(elapsed_ns(start))));
    }
}

/// Returns and clears the blocked nanoseconds banked on this thread since the previous call.
pub(crate) fn take_blocked_ns() -> u64 {
    BLOCKED_NS.with(Cell::take)
}

/// Returns and clears this thread's last-dispatch syscall elapsed (see [`LAST_SYSCALL_NS`]).
pub(crate) fn take_last_syscall_ns() -> Option<u64> {
    LAST_SYSCALL_NS.with(Cell::take)
}

/// `iteration_ns` is the wall time from the previous `run_with_deadline_reserved` return to this
/// submit; `last_syscall_ns` the shim elapsed of the dispatch in between, if it was a syscall.
pub(crate) fn record_iteration(iteration_ns: u64, last_syscall_ns: Option<u64>) {
    match last_syscall_ns {
        Some(syscall_ns) => EXIT_OVERHEAD.record(iteration_ns.saturating_sub(syscall_ns)),
        None => {
            NONSYSCALL_ITERATIONS.fetch_add(1, Ordering::Relaxed);
            NONSYSCALL_ITERATION_NS.fetch_add(iteration_ns, Ordering::Relaxed);
        }
    }
}

pub(crate) fn record_lane_migration(ns: u64) {
    LANE_MIGRATION.record(ns);
}

pub(crate) fn record_kick_round() {
    KICK_ROUNDS.fetch_add(1, Ordering::Relaxed);
}

pub(crate) fn record_kick_request(outcome: KickOutcome) {
    KICK_REQUESTS.fetch_add(1, Ordering::Relaxed);
    match outcome {
        KickOutcome::Requested => {}
        KickOutcome::Idle => {
            KICK_IDLE.fetch_add(1, Ordering::Relaxed);
        }
        KickOutcome::Error => {
            KICK_ERRORS.fetch_add(1, Ordering::Relaxed);
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) enum KickOutcome {
    Requested,
    Idle,
    Error,
}

pub(crate) fn record_kick_issued() {
    KICKS_ISSUED.fetch_add(1, Ordering::Relaxed);
}

pub(crate) fn record_kick_latched() {
    KICKS_LATCHED.fetch_add(1, Ordering::Relaxed);
}

#[derive(Clone, Copy)]
pub(crate) enum CanceledKind {
    /// `(Canceled, DirectGuest)` with no thread interrupt pending: a wasted iteration.
    Exit,
    /// `(Canceled, DirectGuest)` with a thread interrupt to deliver.
    Interrupt,
    /// `(Canceled, LowerElMonitor)` at the sync entry: dispatched as the interrupted exception.
    MonitorExit,
    /// Owner-side `LatchedCancellation`: the run never entered the guest.
    Latched,
}

pub(crate) fn record_canceled(kind: CanceledKind) {
    let counter = match kind {
        CanceledKind::Exit => &CANCELED_EXITS,
        CanceledKind::Interrupt => &CANCELED_INTERRUPTS,
        CanceledKind::MonitorExit => &CANCELED_MONITOR_EXITS,
        CanceledKind::Latched => &CANCELED_LATCHED,
    };
    counter.fetch_add(1, Ordering::Relaxed);
}

// ---------------------------------------------------------------------------
// hvf-run-wall-cold-reentry-instrumentation-rev2 and the operation-gate / retirement /
// mutation-origin evidence counters. Spans are host ticks (`mach_absolute_time`), converted to
// nanoseconds only when rendered. Per-event sums land on the calling thread's own shard line;
// histograms and per-site / per-origin tables are shared relaxed atomics. No lock, no
// allocation on any recording path.
// ---------------------------------------------------------------------------

unsafe extern "C" {
    fn mach_absolute_time() -> u64;
}

/// The counter `Instant` reads (24 MHz on Apple Silicon), at ~5 ns per read instead of ~21 ns.
#[inline(always)]
pub(crate) fn ticks() -> u64 {
    // SAFETY: reads the host's monotonic tick counter; no preconditions.
    unsafe { mach_absolute_time() }
}

static TIMEBASE: std::sync::OnceLock<(u64, u64)> = std::sync::OnceLock::new();

fn timebase() -> (u64, u64) {
    *TIMEBASE.get_or_init(|| crate::vdso::host_timebase().unwrap_or((125, 3)))
}

pub(crate) fn ticks_to_ns(ticks: u64) -> u64 {
    let (numer, denom) = timebase();
    ticks.saturating_mul(numer) / denom
}

pub(crate) const OWNER_SYNC: usize = 0;
pub(crate) const OWNER_BEGIN_RUNNING: usize = 1;
pub(crate) const OWNER_ARM_VTIMER: usize = 2;
pub(crate) const OWNER_SET_STATE: usize = 3;
pub(crate) const OWNER_RUN_CONTROL_BEGIN: usize = 4;
pub(crate) const OWNER_RUN_WRAPPER: usize = 5;
pub(crate) const OWNER_RUN_CONTROL_FINISH: usize = 6;
pub(crate) const OWNER_EXECUTION_TIME: usize = 7;
pub(crate) const OWNER_GET_STATE: usize = 8;
pub(crate) const OWNER_CLASSIFY: usize = 9;
pub(crate) const OWNER_SETTLE: usize = 10;
pub(crate) const OWNER_ATTACHMENT_FINISH: usize = 11;
const OWNER_SPAN_NAMES: [&str; 12] = [
    "sync_trip",
    "begin_running",
    "arm_vtimer",
    "set_state",
    "run_control_begin",
    "run_wrapper",
    "run_control_finish",
    "execution_time",
    "get_state",
    "classify",
    "settle",
    "attachment_finish",
];

pub(crate) const GUEST_LOOP_TOP: usize = 0;
pub(crate) const GUEST_LANE_WAIT: usize = 1;
pub(crate) const GUEST_RESERVE: usize = 2;
pub(crate) const GUEST_VIEW_ATTACH: usize = 3;
pub(crate) const GUEST_SPACE_LOOKUP: usize = 4;
pub(crate) const GUEST_STATE_BUILD: usize = 5;
pub(crate) const GUEST_ATTACH: usize = 6;
pub(crate) const GUEST_PRE_EXECUTE: usize = 7;
pub(crate) const GUEST_EXECUTE: usize = 8;
pub(crate) const GUEST_RELEASE: usize = 9;
pub(crate) const GUEST_RECORD: usize = 10;
pub(crate) const GUEST_PUMP: usize = 11;
pub(crate) const GUEST_DISPATCH: usize = 12;
const GUEST_SPAN_NAMES: [&str; 13] = [
    "loop_top",
    "lane_wait",
    "reserve",
    "view_attach",
    "space_lookup",
    "state_build",
    "attach",
    "pre_execute",
    "execute",
    "release",
    "record",
    "pump",
    "dispatch",
];

const CHANNEL_SPAN_NAMES: [&str; 5] =
    ["submit", "reply_channel", "owner_wake", "owner_post", "guest_wake"];

pub(crate) const RUN_CLASS_AFTER_FULL_SET: usize = 0;
pub(crate) const RUN_CLASS_NO_SET: usize = 1;
pub(crate) const RUN_CLASS_SYNC_TRIP: usize = 2;
const RUN_CLASS_NAMES: [&str; 3] = ["after_full_set", "no_set", "sync_trip"];

pub(crate) const GATE_EXISTING_BEGIN: usize = 0;
pub(crate) const GATE_EXISTING_FINISH: usize = 1;
pub(crate) const GATE_PUBLISH: usize = 2;
pub(crate) const GATE_SHARED_BEGIN: usize = 3;
pub(crate) const GATE_SHARED_REQUIRE_LIVE: usize = 4;
pub(crate) const GATE_SHARED_FINISH: usize = 5;
pub(crate) const GATE_EXCLUSIVE_BEGIN: usize = 6;
pub(crate) const GATE_EXCLUSIVE_REQUIRE_LIVE: usize = 7;
pub(crate) const GATE_EXCLUSIVE_FINISH: usize = 8;
const GATE_LOCK_SITES: usize = 9;
const GATE_LOCK_SITE_NAMES: [&str; GATE_LOCK_SITES] = [
    "existing_begin",
    "existing_finish",
    "publish",
    "shared_begin",
    "shared_require_live",
    "shared_finish",
    "exclusive_begin",
    "exclusive_require_live",
    "exclusive_finish",
];

const STAT_OWNER_SPANS: usize = 0;
const STAT_OWNER_TOTAL: usize = STAT_OWNER_SPANS + OWNER_SPAN_NAMES.len();
const STAT_OWNER_RUNS: usize = STAT_OWNER_TOTAL + 1;
const STAT_OWNER_RERUNS: usize = STAT_OWNER_RUNS + 1;
const STAT_OWNER_LATCHED: usize = STAT_OWNER_RERUNS + 1;
const STAT_GUEST_SPANS: usize = STAT_OWNER_LATCHED + 1;
const STAT_GUEST_ITERATIONS: usize = STAT_GUEST_SPANS + GUEST_SPAN_NAMES.len();
const STAT_CHANNEL_SPANS: usize = STAT_GUEST_ITERATIONS + 1;
const STAT_CHANNEL_RUNS: usize = STAT_CHANNEL_SPANS + CHANNEL_SPAN_NAMES.len();
const STAT_RUN_CLASS: usize = STAT_CHANNEL_RUNS + 1;
const STAT_GATE_LOCKS: usize = STAT_RUN_CLASS + 3 * RUN_CLASS_NAMES.len();
const STAT_GATE_CONTENDED: usize = STAT_GATE_LOCKS + GATE_LOCK_SITES;
const STAT_GATE_WAIT: usize = STAT_GATE_CONTENDED + GATE_LOCK_SITES;
const STAT_EXISTING_OPS: usize = STAT_GATE_WAIT + GATE_LOCK_SITES;
const STAT_SHARED_OPS: usize = STAT_EXISTING_OPS + 1;
const STAT_SHARED_TICKS: usize = STAT_SHARED_OPS + 1;
const STAT_EXCLUSIVE_OPS: usize = STAT_SHARED_TICKS + 1;
const STAT_EXCLUSIVE_NESTED: usize = STAT_EXCLUSIVE_OPS + 1;
const STAT_RUN_GATE_RUNS: usize = STAT_EXCLUSIVE_NESTED + 1;
const STAT_RUN_GATE_GUEST: usize = STAT_RUN_GATE_RUNS + 1;
const STAT_RUN_GATE_OWNER: usize = STAT_RUN_GATE_GUEST + 1;
const STAT_PUMP_CALLS: usize = STAT_RUN_GATE_OWNER + 1;
const STAT_PUMP_NONZERO: usize = STAT_PUMP_CALLS + 1;
const STAT_PUMP_RELEASED: usize = STAT_PUMP_NONZERO + 1;
const STAT_PUMP_TICKS: usize = STAT_PUMP_RELEASED + 1;
const STAT_PENDING_CALLS: usize = STAT_PUMP_TICKS + 1;
const STAT_PENDING_TICKS: usize = STAT_PENDING_CALLS + 1;
pub(crate) const STAT_ACK_LOCK_CONTENDED: usize = STAT_PENDING_TICKS + 1;
pub(crate) const STAT_PUMP_LOCK_CONTENDED: usize = STAT_ACK_LOCK_CONTENDED + 2;
const STAT_PUMP_PRECHECK_SKIPS: usize = STAT_PUMP_LOCK_CONTENDED + 2;
const STAT_PUMP_ADMISSIONS: usize = STAT_PUMP_PRECHECK_SKIPS + 1;
const STAT_PUMP_EMPTY_ADMISSIONS: usize = STAT_PUMP_ADMISSIONS + 1;
const STAT_PUMP_ADMISSION_FAILURES: usize = STAT_PUMP_EMPTY_ADMISSIONS + 1;
const STAT_PUMP_PASS_TRIED: usize = STAT_PUMP_ADMISSION_FAILURES + 1;
const STAT_PUMP_PASS_RELEASED: usize = STAT_PUMP_PASS_TRIED + 1;
const STAT_PUMP_PASSES_ADMITTED: usize = STAT_PUMP_PASS_RELEASED + 1;
const STAT_PUMP_PASSES_FAILED: usize = STAT_PUMP_PASSES_ADMITTED + 1;
const STAT_PUMP_OWNER_BYPASSES: usize = STAT_PUMP_PASSES_FAILED + 1;
/// Shared acquisitions of litebox's mapping lock (T1h; per-thread shard lines, so the counting
/// write never contends across threads).
const STAT_VMEM_READS: usize = STAT_PUMP_OWNER_BYPASSES + 1;
/// Per-exit retirement checks skipped because the ledger was held (count, then ticks spent).
const STAT_PENDING_SKIPPED: usize = STAT_VMEM_READS + 1;
/// FXR resident-register cache counters (`RESIDENT_*` offsets, [`RESIDENT_STAT_NAMES`]).
const STAT_RESIDENT: usize = STAT_PENDING_SKIPPED + 2;
const STAT_COUNT: usize = STAT_RESIDENT + RESIDENT_STAT_NAMES.len();

// FXR resident-register cache: one relaxed counter per event, on the calling thread's shard line.
/// Full 74-register installs (`set_architectural_state`: synchronization trips, full-mode runs).
pub(crate) const RESIDENT_INSTALLS_FULL_STATE: usize = 0;
/// Resident installs that covered every integer register AND the SIMD file.
pub(crate) const RESIDENT_INSTALLS_FULL: usize = 1;
/// Resident installs of an integer subset plus the SIMD file (the host copy superseded it).
pub(crate) const RESIDENT_INSTALLS_WITH_FP: usize = 2;
/// Resident installs of an integer subset with the SIMD file kept resident.
pub(crate) const RESIDENT_INSTALLS_PARTIAL: usize = 3;
/// Resident installs with nothing to install: no SDK call, no operation admission.
pub(crate) const RESIDENT_INSTALLS_NONE: usize = 4;
/// Registers the resident installs set (the SIMD file counts as its 34 registers).
pub(crate) const RESIDENT_REGISTERS_SET: usize = 5;
/// 39-get exit reads.
pub(crate) const RESIDENT_EXIT_READS: usize = 6;
/// 74-get full reads.
pub(crate) const RESIDENT_FULL_READS: usize = 7;
/// 34-get SIMD reads (deposits and materializations).
pub(crate) const RESIDENT_FP_READS: usize = 8;
pub(crate) const RESIDENT_VERIFY_READBACKS: usize = 9;
pub(crate) const RESIDENT_VERIFY_MISMATCHES: usize = 10;
pub(crate) const RESIDENT_SAMPLED_VERIFIES: usize = 11;
pub(crate) const RESIDENT_SAMPLED_MISMATCHES: usize = 12;
/// Guest runs that kept the thread's SIMD file resident (no FP install).
pub(crate) const RESIDENT_FP_KEPT: usize = 13;
/// Guest runs that installed the SIMD file from the thread's host copy.
pub(crate) const RESIDENT_FP_FROM_HOST: usize = 14;
/// Guest runs whose resident claim the lane no longer held (host copy installed instead).
pub(crate) const RESIDENT_FP_CLAIM_FALLBACK: usize = 15;
/// SIMD files handed back to their thread because another thread's run took the lane.
pub(crate) const RESIDENT_DEPOSITS_EVICT: usize = 16;
/// ... because a synchronization trip was about to overwrite them.
pub(crate) const RESIDENT_DEPOSITS_SYNC: usize = 17;
/// ... because the thread asked (`MaterializeFp`).
pub(crate) const RESIDENT_DEPOSITS_MATERIALIZE: usize = 18;
/// ... because the lane was closing.
pub(crate) const RESIDENT_DEPOSITS_CLOSE: usize = 19;
/// SIMD files that could not be handed back (the vCPU was already gone): the thread fails
/// loudly at its next SIMD use.
pub(crate) const RESIDENT_FP_LOST: usize = 20;
/// Run results whose SIMD file was read into the result because the lane was leaving service.
pub(crate) const RESIDENT_RESULTS_MATERIALIZED: usize = 21;
/// Guest-side materializations that had to ask a lane (a round trip).
pub(crate) const RESIDENT_GUEST_MATERIALIZE_REQUESTS: usize = 22;
/// Host ticks guest threads spent waiting for requested SIMD files.
pub(crate) const RESIDENT_GUEST_MATERIALIZE_TICKS: usize = 23;
/// Deposits a guest thread absorbed into its host copy.
pub(crate) const RESIDENT_GUEST_DEPOSITS_ABSORBED: usize = 24;
/// Deposits a guest thread discarded as stale (its host copy was already newer).
pub(crate) const RESIDENT_GUEST_DEPOSITS_STALE: usize = 25;
/// Lane checkouts that returned the lane holding the thread's resident state.
pub(crate) const RESIDENT_AFFINITY_HITS: usize = 26;
/// Lane checkouts of a thread with resident state elsewhere that got a different lane.
pub(crate) const RESIDENT_AFFINITY_MISSES: usize = 27;
/// Guest-side materializations made for a run on a lane other than the one holding the file
/// (the rest are for the shim: signal frames, clone/fork capture, ptrace stops).
pub(crate) const RESIDENT_GUEST_MATERIALIZE_FOR_RUN: usize = 28;
const RESIDENT_STAT_NAMES: [&str; 29] = [
    "installs_full_state",
    "installs_full",
    "installs_with_fp",
    "installs_partial",
    "installs_none",
    "registers_set",
    "exit_reads",
    "full_reads",
    "fp_reads",
    "verify_readbacks",
    "verify_mismatches",
    "sampled_verifies",
    "sampled_mismatches",
    "fp_kept",
    "fp_from_host",
    "fp_claim_fallback",
    "deposits_evict",
    "deposits_sync",
    "deposits_materialize",
    "deposits_close",
    "fp_lost",
    "results_materialized",
    "guest_materialize_requests",
    "guest_materialize_wait_ns",
    "guest_deposits_absorbed",
    "guest_deposits_stale",
    "affinity_hits",
    "affinity_misses",
    "guest_materialize_for_run",
];

/// Log2(ns) histogram and maximum of guest-side materialization waits (FXR).
static MATERIALIZE_WAIT_LOG2: [AtomicU64; LATENCY_BUCKETS] = zeroed_u64_array();
static MATERIALIZE_WAIT_MAX_NS: AtomicU64 = AtomicU64::new(0);

/// One guest-side materialization that asked a lane, and how long it waited (host ticks).
pub(crate) fn record_guest_materialize_wait(ticks: u64) {
    record_resident(RESIDENT_GUEST_MATERIALIZE_TICKS, ticks);
    let ns = ticks_to_ns(ticks);
    MATERIALIZE_WAIT_MAX_NS.fetch_max(ns, Ordering::Relaxed);
    record_log2(&MATERIALIZE_WAIT_LOG2, ns);
}

const SHARD_COUNT: usize = 32;

#[repr(C, align(128))]
struct StatShard {
    values: [AtomicU64; STAT_COUNT],
}

static STAT_SHARDS: [StatShard; SHARD_COUNT] = {
    const SHARD: StatShard = StatShard {
        values: zeroed_u64_array(),
    };
    [SHARD; SHARD_COUNT]
};
static NEXT_SHARD: AtomicUsize = AtomicUsize::new(0);

thread_local! {
    static SHARD_INDEX: Cell<usize> = const { Cell::new(usize::MAX) };
    static GATE_LOCKS_HERE: Cell<u64> = const { Cell::new(0) };
    static PENDING_CONTENTION: Cell<Option<(usize, u16, u64)>> = const { Cell::new(None) };
    static ORIGIN: Cell<u8> = const { Cell::new(ORIGIN_UNSCOPED) };
    static SYSCALL_ORIGIN: Cell<u8> = const { Cell::new(ORIGIN_UNSCOPED) };
}

fn shard_index() -> usize {
    SHARD_INDEX.with(|cell| {
        let index = cell.get();
        if index < SHARD_COUNT {
            return index;
        }
        let index = NEXT_SHARD.fetch_add(1, Ordering::Relaxed) % SHARD_COUNT;
        cell.set(index);
        index
    })
}

fn stat_shard() -> &'static StatShard {
    &STAT_SHARDS[shard_index() % SHARD_COUNT]
}

#[inline]
fn add_stat(stat: usize, value: u64) {
    if let Some(counter) = stat_shard().values.get(stat) {
        counter.fetch_add(value, Ordering::Relaxed);
    }
}

fn stat_total(stat: usize) -> u64 {
    STAT_SHARDS.iter().fold(0u64, |sum, shard| {
        sum.wrapping_add(shard.values.get(stat).map_or(0, |v| v.load(Ordering::Relaxed)))
    })
}

const TICK_LINEAR: usize = 768;
const HIST_SHARD_COUNT: usize = 16;
const HIST_RESIDUE: usize = 0;
const HIST_SET_STATE: usize = 1;
const HIST_GET_STATE: usize = 2;
const HIST_RUN_RAW: usize = 3;
const HIST_RUN_WRAPPER: usize = HIST_RUN_RAW + RUN_CLASS_NAMES.len();
const HIST_RUN_EXCESS: usize = HIST_RUN_WRAPPER + RUN_CLASS_NAMES.len();
const HIST_OWNER_WAKE: usize = HIST_RUN_EXCESS + RUN_CLASS_NAMES.len();
const HIST_GUEST_WAKE: usize = HIST_OWNER_WAKE + 1;
const HIST_COUNT: usize = HIST_GUEST_WAKE + 1;
const RUN_GATE_BUCKETS: usize = 128;

/// Exact-resolution tick histogram: one bucket per tick below `TICK_LINEAR` (32 us), then
/// bit-length buckets. Percentiles are exact at the counter's own 41.67 ns resolution.
struct TickHist {
    linear: [AtomicU64; TICK_LINEAR],
    over: [AtomicU64; 64],
}

impl TickHist {
    const fn new() -> Self {
        Self {
            linear: zeroed_u64_array(),
            over: zeroed_u64_array(),
        }
    }

    #[inline]
    fn record(&self, ticks: u64) {
        let bucket = match usize::try_from(ticks) {
            Ok(tick) if tick < TICK_LINEAR => self.linear.get(tick),
            _ => self.over.get((64 - ticks.leading_zeros()) as usize & 63),
        };
        if let Some(bucket) = bucket {
            bucket.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Every histogram written on a per-run path, one copy per thread shard so concurrent owner and
/// guest threads never share a bucket line; rendering sums the shards.
#[repr(C, align(128))]
struct HistShard {
    hists: [TickHist; HIST_COUNT],
    run_gate: [AtomicU64; RUN_GATE_BUCKETS],
}

static HIST_SHARDS: [HistShard; HIST_SHARD_COUNT] = [const {
    HistShard {
        hists: [const { TickHist::new() }; HIST_COUNT],
        run_gate: zeroed_u64_array(),
    }
}; HIST_SHARD_COUNT];

fn hist_shard() -> &'static HistShard {
    &HIST_SHARDS[shard_index() % HIST_SHARD_COUNT]
}

#[inline]
fn record_hist(id: usize, ticks: u64) {
    if let Some(hist) = hist_shard().hists.get(id) {
        hist.record(ticks);
    }
}

fn render_hist(out: &mut String, id: usize) {
    use std::fmt::Write as _;
    let mut linear = vec![0u64; TICK_LINEAR];
    let mut over = vec![0u64; 64];
    for shard in &HIST_SHARDS {
        if let Some(hist) = shard.hists.get(id) {
            for (sum, bucket) in linear.iter_mut().zip(hist.linear.iter()) {
                *sum = sum.wrapping_add(bucket.load(Ordering::Relaxed));
            }
            for (sum, bucket) in over.iter_mut().zip(hist.over.iter()) {
                *sum = sum.wrapping_add(bucket.load(Ordering::Relaxed));
            }
        }
    }
    {
        let count = linear.iter().chain(over.iter()).fold(0u64, |a, b| a.wrapping_add(*b));
        let percentile = |per_mille: u64| -> u64 {
            if count == 0 {
                return 0;
            }
            let target = (count.saturating_mul(per_mille)).div_ceil(1000);
            let mut cumulative = 0u64;
            for (tick, value) in linear.iter().enumerate() {
                cumulative = cumulative.wrapping_add(*value);
                if cumulative >= target {
                    return tick as u64;
                }
            }
            for (bits, value) in over.iter().enumerate() {
                cumulative = cumulative.wrapping_add(*value);
                if cumulative >= target {
                    return if bits == 0 { 0 } else { 1u64 << (bits - 1) };
                }
            }
            0
        };
        let _ = write!(
            out,
            "{{\"count\":{},\"p50_ns\":{},\"p90_ns\":{},\"p99_ns\":{},\"lin\":[",
            count,
            ticks_to_ns(percentile(500)),
            ticks_to_ns(percentile(900)),
            ticks_to_ns(percentile(990)),
        );
        push_sparse(out, &linear);
        out.push_str("],\"over\":[");
        push_sparse(out, &over);
        out.push_str("]}");
    }
}

fn push_sparse(out: &mut String, values: &[u64]) {
    use std::fmt::Write as _;
    let mut first = true;
    for (index, value) in values.iter().enumerate() {
        if *value == 0 {
            continue;
        }
        if !first {
            out.push(',');
        }
        first = false;
        let _ = write!(out, "[{index},{value}]");
    }
}

fn record_log2(buckets: &[AtomicU64; LATENCY_BUCKETS], ns: u64) {
    if let Some(bucket) = buckets.get(latency_bucket_index(ns)) {
        bucket.fetch_add(1, Ordering::Relaxed);
    }
}

fn load_all(buckets: &[AtomicU64]) -> Vec<u64> {
    buckets.iter().map(|b| b.load(Ordering::Relaxed)).collect()
}

static GATE_CONTENDED_LOG2: [[AtomicU64; LATENCY_BUCKETS]; GATE_LOCK_SITES] = {
    const ROW: [AtomicU64; LATENCY_BUCKETS] = zeroed_u64_array();
    [ROW; GATE_LOCK_SITES]
};

/// Accumulates consecutive spans of one run on one thread; flushed once per run.
pub(crate) struct SpanClock<const N: usize> {
    start: u64,
    last: u64,
    sums: [u64; N],
}

impl<const N: usize> SpanClock<N> {
    pub(crate) fn start() -> Self {
        let now = ticks();
        Self {
            start: now,
            last: now,
            sums: [0; N],
        }
    }

    /// Closes the span that began at the previous mark and returns its length in ticks.
    #[inline]
    pub(crate) fn mark(&mut self, span: usize) -> u64 {
        let now = ticks();
        let length = now.wrapping_sub(self.last);
        if let Some(sum) = self.sums.get_mut(span) {
            *sum = sum.wrapping_add(length);
        }
        self.last = now;
        length
    }

    pub(crate) fn last(&self) -> u64 {
        self.last
    }

    pub(crate) fn span(&self, span: usize) -> u64 {
        self.sums.get(span).copied().unwrap_or(0)
    }

    fn total(&self) -> u64 {
        self.last.wrapping_sub(self.start)
    }

    fn flush(&self, base: usize) {
        let shard = stat_shard();
        for (index, sum) in self.sums.iter().enumerate() {
            if *sum != 0
                && let Some(counter) = shard.values.get(base + index)
            {
                counter.fetch_add(*sum, Ordering::Relaxed);
            }
        }
    }
}

pub(crate) type GuestSpans = SpanClock<13>;

/// The owner thread's view of one run: consecutive spans plus rerun / latched-cancel counts.
pub(crate) struct OwnerTrace {
    pub(crate) spans: SpanClock<12>,
    pub(crate) reruns: u64,
    pub(crate) latched: bool,
}

impl OwnerTrace {
    pub(crate) fn start() -> Self {
        Self {
            spans: SpanClock::start(),
            reruns: 0,
            latched: false,
        }
    }

    pub(crate) fn total_ns(&self) -> u64 {
        ticks_to_ns(self.spans.total())
    }
}

/// One completed owner-side `execute_attached` (Ok result only): its span sums, its total and the
/// residue histogram (total minus the `vcpu.run()` wrapper span).
pub(crate) fn record_owner_run(trace: &OwnerTrace) {
    flush_contention();
    trace.spans.flush(STAT_OWNER_SPANS);
    let total = trace.spans.total();
    add_stat(STAT_OWNER_TOTAL, total);
    add_stat(STAT_OWNER_RUNS, 1);
    if trace.reruns != 0 {
        add_stat(STAT_OWNER_RERUNS, trace.reruns);
    }
    if trace.latched {
        add_stat(STAT_OWNER_LATCHED, 1);
    }
    record_hist(HIST_RESIDUE, total.saturating_sub(trace.spans.span(OWNER_RUN_WRAPPER)));
}

pub(crate) fn record_set_state(ticks: u64) {
    record_hist(HIST_SET_STATE, ticks);
}

/// One FXR resident-register cache event (`RESIDENT_*` index), `value` added to it.
#[inline]
pub(crate) fn record_resident(index: usize, value: u64) {
    add_stat(STAT_RESIDENT + index, value);
}

/// One resident install decision: `mask` is the install mask issued (0 = nothing installed),
/// `full` whether it covered every integer register and the SIMD file.
pub(crate) fn record_resident_install(mask: u64, full: bool) {
    const SIMD: u64 = 1 << 35;
    const SCALAR: u64 = ((1 << 41) - 1) & !SIMD;
    let class = if mask == 0 {
        RESIDENT_INSTALLS_NONE
    } else if full {
        RESIDENT_INSTALLS_FULL
    } else if mask & SIMD != 0 {
        RESIDENT_INSTALLS_WITH_FP
    } else {
        RESIDENT_INSTALLS_PARTIAL
    };
    record_resident(class, 1);
    let registers = u64::from((mask & SCALAR).count_ones()) + if mask & SIMD != 0 { 34 } else { 0 };
    if registers != 0 {
        record_resident(RESIDENT_REGISTERS_SET, registers);
    }
}

/// One `LITEBOX_HVF_VERIFY_STATE=1` comparison of the vCPU against the cache.
pub(crate) fn record_resident_verify(exact: bool) {
    record_resident(RESIDENT_VERIFY_READBACKS, 1);
    if !exact {
        record_resident(RESIDENT_VERIFY_MISMATCHES, 1);
    }
}

/// One sampled (release) comparison of the vCPU against the cache.
pub(crate) fn record_resident_sampled(exact: bool) {
    record_resident(RESIDENT_SAMPLED_VERIFIES, 1);
    if !exact {
        record_resident(RESIDENT_SAMPLED_MISMATCHES, 1);
    }
}

fn render_resident_state(out: &mut String) {
    use std::fmt::Write as _;
    let _ = write!(
        out,
        "\"resident_state\":{{\"verify_enabled\":{},\"sample_interval\":64",
        u8::from(crate::hvf::state_verify_enabled())
    );
    for (index, name) in RESIDENT_STAT_NAMES.iter().enumerate() {
        let value = stat_total(STAT_RESIDENT + index);
        let value = if index == RESIDENT_GUEST_MATERIALIZE_TICKS {
            ticks_to_ns(value)
        } else {
            value
        };
        let _ = write!(out, ",\"{name}\":{value}");
    }
    let _ = write!(
        out,
        ",\"guest_materialize_wait_max_ns\":{},\"guest_materialize_wait_log2\":",
        MATERIALIZE_WAIT_MAX_NS.load(Ordering::Relaxed)
    );
    render_log2(out, &MATERIALIZE_WAIT_LOG2);
    out.push_str("},");
}

pub(crate) fn record_get_state(ticks: u64) {
    record_hist(HIST_GET_STATE, ticks);
}

/// One `vcpu.run()`: `raw_ticks` brackets only the `litebox_hvf_vcpu_run` FFI call,
/// `wrapper_ticks` the whole `with_existing_operation` admission around it.
pub(crate) fn record_run_split(class: usize, raw_ticks: u64, wrapper_ticks: u64) {
    let class = class.min(RUN_CLASS_NAMES.len() - 1);
    let shard = stat_shard();
    let base = STAT_RUN_CLASS + 3 * class;
    for (offset, value) in [1, raw_ticks, wrapper_ticks].into_iter().enumerate() {
        if let Some(counter) = shard.values.get(base + offset) {
            counter.fetch_add(value, Ordering::Relaxed);
        }
    }
    record_hist(HIST_RUN_RAW + class, raw_ticks);
    record_hist(HIST_RUN_WRAPPER + class, wrapper_ticks);
    record_hist(HIST_RUN_EXCESS + class, wrapper_ticks.saturating_sub(raw_ticks));
}

/// The `execute()` round trip split: guest-side submit, reply-channel creation, command stamp
/// -> owner start (command build, admit and the owner's wakeup), the owner's tail after
/// `execute_attached` before the reply, and reply -> guest resumed.
pub(crate) fn record_channel(spans: [u64; 5]) {
    let shard = stat_shard();
    for (index, value) in spans.iter().enumerate() {
        if let Some(counter) = shard.values.get(STAT_CHANNEL_SPANS + index) {
            counter.fetch_add(*value, Ordering::Relaxed);
        }
    }
    add_stat(STAT_CHANNEL_RUNS, 1);
    record_hist(HIST_OWNER_WAKE, spans[2]);
    record_hist(HIST_GUEST_WAKE, spans[4]);
}

pub(crate) fn record_guest_iteration(spans: &GuestSpans) {
    flush_contention();
    spans.flush(STAT_GUEST_SPANS);
    add_stat(STAT_GUEST_ITERATIONS, 1);
}

/// Operation-gate mutex acquisitions of one run: the guest thread's attach..execute window plus
/// the owner thread's whole `execute_attached`.
pub(crate) fn record_run_gate_locks(guest: u64, owner: u64) {
    add_stat(STAT_RUN_GATE_RUNS, 1);
    add_stat(STAT_RUN_GATE_GUEST, guest);
    add_stat(STAT_RUN_GATE_OWNER, owner);
    let total = usize::try_from(guest.saturating_add(owner)).unwrap_or(usize::MAX);
    if let Some(bucket) = hist_shard().run_gate.get(total.min(RUN_GATE_BUCKETS - 1)) {
        bucket.fetch_add(1, Ordering::Relaxed);
    }
}

pub(crate) fn gate_locks_this_thread() -> u64 {
    GATE_LOCKS_HERE.with(Cell::get)
}

/// Publishes this thread's last contended gate acquisition, if any. Runs outside every gate
/// critical section (before the next gate lock, and at run / iteration end), so the shared
/// lines it writes never lengthen a hold of the gate mutex.
fn flush_contention() {
    let Some((lock_site, op_site, waited)) = PENDING_CONTENTION.with(Cell::take) else {
        return;
    };
    add_stat(STAT_GATE_CONTENDED + lock_site, 1);
    add_stat(STAT_GATE_WAIT + lock_site, waited);
    let ns = ticks_to_ns(waited);
    if let Some(buckets) = GATE_CONTENDED_LOG2.get(lock_site) {
        record_log2(buckets, ns);
    }
    if let Some(slot) = SITES.get(usize::from(op_site)) {
        slot.contended.fetch_add(1, Ordering::Relaxed);
        slot.contended_ticks.fetch_add(waited, Ordering::Relaxed);
        record_log2(&slot.contended_log2, ns);
    }
}

/// Locks `mutex`, counting the acquisition against `lock_site` for this thread and, only when
/// the uncontended `try_lock` fails, timing the blocking wait (attributed to `op_site` too).
/// Inside the critical section only thread-local cells are written.
pub(crate) fn lock_gate<'a, T>(
    mutex: &'a Mutex<T>,
    lock_site: usize,
    op_site: u16,
) -> MutexGuard<'a, T> {
    flush_contention();
    GATE_LOCKS_HERE.with(|cell| cell.set(cell.get().wrapping_add(1)));
    add_stat(STAT_GATE_LOCKS + lock_site, 1);
    match mutex.try_lock() {
        Ok(guard) => guard,
        Err(TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
        Err(TryLockError::WouldBlock) => {
            let started = ticks();
            let guard = mutex.lock().unwrap_or_else(PoisonError::into_inner);
            let waited = ticks().wrapping_sub(started);
            PENDING_CONTENTION.with(|cell| cell.set(Some((lock_site, op_site, waited))));
            thread_work(|work| work.gate_mutex_wait_ticks += waited);
            guard
        }
    }
}

/// `mutex.lock()` whose contended wait (only) is added to the stat pair at `contended_stat`
/// (count) and `contended_stat + 1` (ticks).
pub(crate) fn lock_timed<'a, T>(mutex: &'a Mutex<T>, contended_stat: usize) -> MutexGuard<'a, T> {
    match mutex.try_lock() {
        Ok(guard) => guard,
        Err(TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
        Err(TryLockError::WouldBlock) => {
            let started = ticks();
            let guard = mutex.lock().unwrap_or_else(PoisonError::into_inner);
            let waited = ticks().wrapping_sub(started);
            add_stat(contended_stat, 1);
            add_stat(contended_stat + 1, waited);
            thread_work(|work| work.lock_wait_ticks += waited);
            guard
        }
    }
}

pub(crate) const SITE_KIND_EXCLUSIVE: u8 = 1;
pub(crate) const SITE_KIND_SHARED: u8 = 2;
pub(crate) const SITE_KIND_EXISTING: u8 = 3;
pub(crate) const SITE_KIND_PUMP: u8 = 4;
const SITE_KIND_NAMES: [&str; 5] = ["none", "exclusive", "shared", "existing", "pump"];
pub(crate) const SITE_NONE: u16 = u16::MAX;
const SITE_TABLE_LEN: usize = 192;
const SITE_SLOW_TICKS: u64 = 480;

/// One operation call site (the `#[track_caller]` location of a `with_*_operation` or
/// `pump_retirements` call). Counts and duration sums live in [`SITE_SHARDS`]; this row holds
/// the shared slow-path detail.
struct SiteSlot {
    contended: AtomicU64,
    contended_ticks: AtomicU64,
    contended_log2: [AtomicU64; LATENCY_BUCKETS],
    nested: AtomicU64,
    admit_waited: AtomicU64,
    admit_rounds: AtomicU64,
    admit_wait_ticks: AtomicU64,
    admit_wait_max: AtomicU64,
    admit_wait_log2: [AtomicU64; LATENCY_BUCKETS],
    hold_max: AtomicU64,
    hold_log2: [AtomicU64; LATENCY_BUCKETS],
    slow: AtomicU64,
    slow_ticks: AtomicU64,
    slow_log2: [AtomicU64; LATENCY_BUCKETS],
}

impl SiteSlot {
    const fn new() -> Self {
        Self {
            contended: AtomicU64::new(0),
            contended_ticks: AtomicU64::new(0),
            contended_log2: zeroed_u64_array(),
            nested: AtomicU64::new(0),
            admit_waited: AtomicU64::new(0),
            admit_rounds: AtomicU64::new(0),
            admit_wait_ticks: AtomicU64::new(0),
            admit_wait_max: AtomicU64::new(0),
            admit_wait_log2: zeroed_u64_array(),
            hold_max: AtomicU64::new(0),
            hold_log2: zeroed_u64_array(),
            slow: AtomicU64::new(0),
            slow_ticks: AtomicU64::new(0),
            slow_log2: zeroed_u64_array(),
        }
    }
}

static SITES: [SiteSlot; SITE_TABLE_LEN] = {
    const SLOT: SiteSlot = SiteSlot::new();
    [SLOT; SITE_TABLE_LEN]
};
/// Read-mostly lookup keys (`&'static Location` addresses) and kinds, kept apart from [`SITES`]
/// so a slow-path statistics write never invalidates the line a concurrent lookup reads.
#[repr(C, align(128))]
struct SiteKeys {
    keys: [AtomicUsize; SITE_TABLE_LEN],
    kinds: [AtomicU8; SITE_TABLE_LEN],
}
static SITE_KEYS: SiteKeys = SiteKeys {
    keys: [const { AtomicUsize::new(0) }; SITE_TABLE_LEN],
    kinds: [const { AtomicU8::new(0) }; SITE_TABLE_LEN],
};
static SITE_OVERFLOWS: AtomicU64 = AtomicU64::new(0);

#[repr(C, align(128))]
struct SiteShard {
    count: [AtomicU64; SITE_TABLE_LEN],
    ticks: [AtomicU64; SITE_TABLE_LEN],
}

static SITE_SHARDS: [SiteShard; SHARD_COUNT] = {
    const SHARD: SiteShard = SiteShard {
        count: zeroed_u64_array(),
        ticks: zeroed_u64_array(),
    };
    [SHARD; SHARD_COUNT]
};

/// The row for `caller`, claimed on first use (lock-free linear probe keyed by the
/// `&'static Location` address); `SITE_NONE` once the table is full.
pub(crate) fn site_index(caller: &'static Location<'static>, kind: u8) -> u16 {
    let key = core::ptr::from_ref(caller) as usize;
    let start = (key as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15) >> 56;
    let start = usize::try_from(start).unwrap_or(0) % SITE_TABLE_LEN;
    for offset in 0..SITE_TABLE_LEN {
        let index = (start + offset) % SITE_TABLE_LEN;
        let (Some(slot_key), Some(slot_kind)) =
            (SITE_KEYS.keys.get(index), SITE_KEYS.kinds.get(index))
        else {
            break;
        };
        let existing = slot_key.load(Ordering::Acquire);
        let owns = existing == key
            || (existing == 0
                && match slot_key.compare_exchange(0, key, Ordering::AcqRel, Ordering::Acquire) {
                    Ok(_) => {
                        slot_kind.store(kind, Ordering::Release);
                        true
                    }
                    Err(actual) => actual == key,
                });
        if owns {
            return u16::try_from(index).unwrap_or(SITE_NONE);
        }
    }
    SITE_OVERFLOWS.fetch_add(1, Ordering::Relaxed);
    SITE_NONE
}

/// One completed operation at `site`, `duration_ticks` from admission request to finish.
pub(crate) fn record_site_op(site: u16, duration_ticks: u64) {
    let index = usize::from(site);
    let shard = &SITE_SHARDS[shard_index() % SHARD_COUNT];
    if let (Some(count), Some(sum)) = (shard.count.get(index), shard.ticks.get(index)) {
        count.fetch_add(1, Ordering::Relaxed);
        sum.fetch_add(duration_ticks, Ordering::Relaxed);
    }
    if duration_ticks >= SITE_SLOW_TICKS
        && let Some(slot) = SITES.get(index)
    {
        slot.slow.fetch_add(1, Ordering::Relaxed);
        slot.slow_ticks.fetch_add(duration_ticks, Ordering::Relaxed);
        record_log2(&slot.slow_log2, ticks_to_ns(duration_ticks));
    }
}

pub(crate) fn record_existing_op() {
    add_stat(STAT_EXISTING_OPS, 1);
}

pub(crate) fn record_shared_op(site: u16, duration_ticks: u64) {
    add_stat(STAT_SHARED_OPS, 1);
    add_stat(STAT_SHARED_TICKS, duration_ticks);
    record_site_op(site, duration_ticks);
}

/// An exclusive (`with_operation`-class) admission: `wait_ticks` from the admission request to
/// ownership, `rounds` condvar waits on the way, `nested` for a same-owner re-entry.
pub(crate) fn record_exclusive_admission(
    site: u16,
    origin: u8,
    nested: bool,
    wait_ticks: u64,
    rounds: u64,
) {
    add_stat(if nested { STAT_EXCLUSIVE_NESTED } else { STAT_EXCLUSIVE_OPS }, 1);
    if !nested {
        thread_work(|work| {
            work.excl_admissions += 1;
            work.excl_wait_ticks += wait_ticks;
        });
    }
    let ns = ticks_to_ns(wait_ticks);
    if let Some(slot) = SITES.get(usize::from(site)) {
        if nested {
            slot.nested.fetch_add(1, Ordering::Relaxed);
        } else {
            if rounds != 0 {
                slot.admit_waited.fetch_add(1, Ordering::Relaxed);
                slot.admit_rounds.fetch_add(rounds, Ordering::Relaxed);
            }
            slot.admit_wait_ticks.fetch_add(wait_ticks, Ordering::Relaxed);
            slot.admit_wait_max.fetch_max(wait_ticks, Ordering::Relaxed);
            record_log2(&slot.admit_wait_log2, ns);
        }
    }
    if !nested && let Some(row) = ORIGINS.get(usize::from(origin)) {
        row.excl_count.fetch_add(1, Ordering::Relaxed);
        if rounds != 0 {
            row.excl_waited.fetch_add(1, Ordering::Relaxed);
        }
        row.excl_wait_ticks.fetch_add(wait_ticks, Ordering::Relaxed);
        row.excl_wait_max.fetch_max(wait_ticks, Ordering::Relaxed);
        record_log2(&row.excl_wait_log2, ns);
    }
}

/// The outermost exclusive admission's hold (admission to release of ownership).
pub(crate) fn record_exclusive_hold(site: u16, origin: u8, hold_ticks: u64) {
    thread_work(|work| work.excl_hold_ticks += hold_ticks);
    let ns = ticks_to_ns(hold_ticks);
    record_site_op(site, hold_ticks);
    if let Some(slot) = SITES.get(usize::from(site)) {
        slot.hold_max.fetch_max(hold_ticks, Ordering::Relaxed);
        record_log2(&slot.hold_log2, ns);
    }
    if let Some(row) = ORIGINS.get(usize::from(origin)) {
        row.excl_hold_ticks.fetch_add(hold_ticks, Ordering::Relaxed);
        row.excl_hold_max.fetch_max(hold_ticks, Ordering::Relaxed);
        record_log2(&row.excl_hold_log2, ns);
    }
}

/// One `pump_retirements` call from `caller`: count, released tickets and wall time.
pub(crate) fn record_pump(caller: &'static Location<'static>, started: u64, released: Option<usize>) {
    let duration = ticks().wrapping_sub(started);
    add_stat(STAT_PUMP_CALLS, 1);
    add_stat(STAT_PUMP_TICKS, duration);
    if let Some(released) = released.filter(|released| *released != 0) {
        add_stat(STAT_PUMP_NONZERO, 1);
        add_stat(STAT_PUMP_RELEASED, u64::try_from(released).unwrap_or(u64::MAX));
    }
    record_site_op(site_index(caller, SITE_KIND_PUMP), duration);
}

pub(crate) fn record_pending(started: u64) {
    add_stat(STAT_PENDING_CALLS, 1);
    add_stat(STAT_PENDING_TICKS, ticks().wrapping_sub(started));
}

/// A non-waiting per-exit retirement check that found the ledger held and skipped (T1h).
pub(crate) fn record_pending_skipped(started: u64) {
    add_stat(STAT_PENDING_SKIPPED, 1);
    add_stat(STAT_PENDING_SKIPPED + 1, ticks().wrapping_sub(started));
}

// hvf-retirement-pump-exclusive-gate-lock-order-inversion (T1g) and its fix-up: a pump pass holds
// its space's `retirement_pump` mutex (the per-space serialization it always had) and gives every
// ticket its own cleanup admission (the per-ticket panic/poison scope of `acknowledge_retirement`);
// a caller that already owns the exclusive gate never waits for the mutex (`owner_bypasses`).
// Every `pump_retirements` call ends exactly one way -- `calls == precheck_skips + passes_admitted
// + passes_failed + empty_passes` (failed = the ticket collection or the first admission failed;
// empty = nothing left to release once the pass got the mutex) -- and `pump_mutex_wait` records
// every acquisition (0 when uncontended); a gate owner never waits on a contended mutex.
static PUMP_MUTEX_WAIT: CostHistogram = CostHistogram::new();
/// A ticket's admission request to its body starting: the gate FIFO wait of a caller that does
/// not own the gate (the same wait `acknowledge_retirement` always took per ticket), ~0 for one
/// that does (nested).
static PUMP_ADMISSION_WAIT: CostHistogram = CostHistogram::new();
/// One ticket's admission body, start to end: how long a pump holds the gate per ticket.
static PUMP_TICKET_HOLD: CostHistogram = CostHistogram::new();

/// The precheck found no deferred, fully acknowledged row: returned without the gate.
pub(crate) fn record_pump_precheck_skip() {
    add_stat(STAT_PUMP_PRECHECK_SKIPS, 1);
}

/// A ticket admission began its body; returns the tick its hold is measured from.
pub(crate) fn record_pump_admission(requested: u64) -> u64 {
    let admitted = ticks();
    add_stat(STAT_PUMP_ADMISSIONS, 1);
    PUMP_ADMISSION_WAIT.record(ticks_to_ns(admitted.wrapping_sub(requested)));
    admitted
}

/// A ticket admission itself failed (e.g. `OperationWaitTimeout`); its body never ran and the
/// pass stopped there. `first` = before any ticket of the pass was admitted.
pub(crate) fn record_pump_admission_failure(first: bool) {
    add_stat(STAT_PUMP_ADMISSION_FAILURES, 1);
    if first {
        add_stat(STAT_PUMP_PASSES_FAILED, 1);
    }
}

/// One ticket admission's body finished.
pub(crate) fn record_pump_ticket_hold(admitted: u64) {
    PUMP_TICKET_HOLD.record(ticks_to_ns(ticks().wrapping_sub(admitted)));
}

/// One pass that admitted at least one ticket: `tried` tickets acknowledged or refused under
/// their admissions, `released` of them released.
pub(crate) fn record_pump_pass(tried: usize, released: usize) {
    add_stat(STAT_PUMP_PASSES_ADMITTED, 1);
    add_stat(STAT_PUMP_PASS_TRIED, u64::try_from(tried).unwrap_or(u64::MAX));
    add_stat(STAT_PUMP_PASS_RELEASED, u64::try_from(released).unwrap_or(u64::MAX));
}

/// A pass that found nothing left to release once it held the mutex (another pass got there
/// between the precheck and the collection): no admission at all.
pub(crate) fn record_pump_empty_pass() {
    add_stat(STAT_PUMP_EMPTY_ADMISSIONS, 1);
}

/// A pass whose ticket collection failed (metadata allocation) before any admission.
pub(crate) fn record_pump_collect_failure() {
    add_stat(STAT_PUMP_PASSES_FAILED, 1);
}

/// How many pump passes proceeded without the space's `retirement_pump` mutex because their
/// caller owned the exclusive gate while another thread held the mutex (the
/// `hvf_pump_owner_bypass_probe` witness reads it around its staged inversion).
pub(crate) fn pump_owner_bypasses() -> u64 {
    stat_total(STAT_PUMP_OWNER_BYPASSES)
}

/// Locks a space's `retirement_pump` for one pass, recording the wait of every acquisition (a
/// contended one also feeds the `pump_lock_contended` pair) -- unless the mutex is contended and
/// `owns_gate()` says the caller already owns the exclusive gate: the holder may be waiting in the
/// gate FIFO for that very caller, so the caller proceeds without the mutex (`None`) instead of
/// waiting (hvf-retirement-pump-exclusive-gate-lock-order-inversion). `owns_gate` runs only on
/// contention.
pub(crate) fn lock_pump_unless_gate_owner<'a, T>(
    mutex: &'a Mutex<T>,
    owns_gate: impl FnOnce() -> bool,
) -> Option<MutexGuard<'a, T>> {
    match mutex.try_lock() {
        Ok(guard) => {
            PUMP_MUTEX_WAIT.record(0);
            Some(guard)
        }
        Err(TryLockError::Poisoned(poisoned)) => {
            PUMP_MUTEX_WAIT.record(0);
            Some(poisoned.into_inner())
        }
        Err(TryLockError::WouldBlock) => {
            if owns_gate() {
                add_stat(STAT_PUMP_OWNER_BYPASSES, 1);
                return None;
            }
            let started = ticks();
            let guard = mutex.lock().unwrap_or_else(PoisonError::into_inner);
            let waited = ticks().wrapping_sub(started);
            add_stat(STAT_PUMP_LOCK_CONTENDED, 1);
            add_stat(STAT_PUMP_LOCK_CONTENDED + 1, waited);
            PUMP_MUTEX_WAIT.record(ticks_to_ns(waited));
            thread_work(|work| work.lock_wait_ticks += waited);
            Some(guard)
        }
    }
}

fn render_cost_histogram(out: &mut String, name: &str, histogram: &CostHistogram) {
    use std::fmt::Write as _;
    let (count, sum_ns, max_ns, buckets) = histogram.snapshot();
    let _ = write!(
        out,
        "\"{name}\":{{\"count\":{count},\"sum_ns\":{sum_ns},\"max_ns\":{max_ns},\"buckets\":"
    );
    push_buckets(out, &buckets);
    out.push('}');
}

fn render_retirement_pump(out: &mut String) {
    use std::fmt::Write as _;
    let _ = write!(
        out,
        concat!(
            "\"retirement_pump\":{{\"calls\":{},\"precheck_skips\":{},\"passes_admitted\":{},",
            "\"passes_failed\":{},\"admissions\":{},\"empty_passes\":{},\"admission_failures\":{},",
            "\"tickets_tried\":{},\"tickets_released\":{},\"owner_bypasses\":{},",
            "\"pump_mutex_contended\":{},\"pump_mutex_contended_ns\":{},"
        ),
        stat_total(STAT_PUMP_CALLS),
        stat_total(STAT_PUMP_PRECHECK_SKIPS),
        stat_total(STAT_PUMP_PASSES_ADMITTED),
        stat_total(STAT_PUMP_PASSES_FAILED),
        stat_total(STAT_PUMP_ADMISSIONS),
        stat_total(STAT_PUMP_EMPTY_ADMISSIONS),
        stat_total(STAT_PUMP_ADMISSION_FAILURES),
        stat_total(STAT_PUMP_PASS_TRIED),
        stat_total(STAT_PUMP_PASS_RELEASED),
        stat_total(STAT_PUMP_OWNER_BYPASSES),
        stat_total(STAT_PUMP_LOCK_CONTENDED),
        ticks_to_ns(stat_total(STAT_PUMP_LOCK_CONTENDED + 1)),
    );
    render_cost_histogram(out, "pump_mutex_wait", &PUMP_MUTEX_WAIT);
    out.push(',');
    render_cost_histogram(out, "admission_wait", &PUMP_ADMISSION_WAIT);
    out.push(',');
    render_cost_histogram(out, "ticket_hold", &PUMP_TICKET_HOLD);
    out.push_str("},");
}

pub(crate) const ORIGIN_UNSCOPED: u8 = 0;
pub(crate) const ORIGIN_OTHER_SYSCALL: u8 = 11;
pub(crate) const ORIGIN_GUEST_FAULT: u8 = 12;
pub(crate) const ORIGIN_WX_TOGGLE: u8 = 13;
pub(crate) const ORIGIN_FORK_COW_FAULT: u8 = 14;
pub(crate) const ORIGIN_FILE_COW: u8 = 15;
pub(crate) const ORIGIN_FILE_MMAP: u8 = 16;
pub(crate) const ORIGIN_FORK_PROTECT: u8 = 17;
pub(crate) const ORIGIN_FORK_DIVERGE: u8 = 18;
pub(crate) const ORIGIN_REAP: u8 = 19;
pub(crate) const ORIGIN_RETIREMENT: u8 = 20;
pub(crate) const ORIGIN_TEARDOWN: u8 = 21;
pub(crate) const ORIGIN_LANE_MAINTENANCE: u8 = 22;
const ORIGIN_NAMES: [&str; 23] = [
    "unscoped",
    "mmap",
    "munmap",
    "mprotect",
    "madvise",
    "mremap",
    "brk",
    "clone",
    "execve",
    "exit",
    "shm",
    "other_syscall",
    "guest_fault",
    "wx_toggle",
    "fork_cow_fault",
    "file_cow",
    "file_mmap",
    "fork_protect",
    "fork_diverge",
    "reap",
    "retirement",
    "teardown",
    "lane_maintenance",
];

fn origin_for_syscall(nr: i32) -> u8 {
    match nr {
        222 => 1,
        215 => 2,
        226 => 3,
        233 => 4,
        216 => 5,
        214 => 6,
        220 | 435 => 7,
        221 | 281 => 8,
        93 | 94 => 9,
        194..=197 => 10,
        _ => ORIGIN_OTHER_SYSCALL,
    }
}

/// Which code path requested the stage-2 mutations and exclusive VM operations of this row.
struct OriginSlot {
    mutations: [AtomicU64; 3],
    changed: AtomicU64,
    mutate_count: AtomicU64,
    mutate_ticks: AtomicU64,
    mutate_max: AtomicU64,
    mutate_log2: [AtomicU64; LATENCY_BUCKETS],
    excl_count: AtomicU64,
    excl_waited: AtomicU64,
    excl_wait_ticks: AtomicU64,
    excl_wait_max: AtomicU64,
    excl_wait_log2: [AtomicU64; LATENCY_BUCKETS],
    excl_hold_ticks: AtomicU64,
    excl_hold_max: AtomicU64,
    excl_hold_log2: [AtomicU64; LATENCY_BUCKETS],
    by_syscall: [AtomicU64; 3],
}

impl OriginSlot {
    const fn new() -> Self {
        Self {
            mutations: zeroed_u64_array(),
            changed: AtomicU64::new(0),
            mutate_count: AtomicU64::new(0),
            mutate_ticks: AtomicU64::new(0),
            mutate_max: AtomicU64::new(0),
            mutate_log2: zeroed_u64_array(),
            excl_count: AtomicU64::new(0),
            excl_waited: AtomicU64::new(0),
            excl_wait_ticks: AtomicU64::new(0),
            excl_wait_max: AtomicU64::new(0),
            excl_wait_log2: zeroed_u64_array(),
            excl_hold_ticks: AtomicU64::new(0),
            excl_hold_max: AtomicU64::new(0),
            excl_hold_log2: zeroed_u64_array(),
            by_syscall: zeroed_u64_array(),
        }
    }
}

static ORIGINS: [OriginSlot; ORIGIN_NAMES.len()] = {
    const SLOT: OriginSlot = OriginSlot::new();
    [SLOT; ORIGIN_NAMES.len()]
};

/// Restores the previous innermost origin (and outer syscall origin) when dropped.
pub(crate) struct OriginScope {
    previous: u8,
    previous_syscall: Option<u8>,
}

impl Drop for OriginScope {
    fn drop(&mut self) {
        ORIGIN.with(|cell| cell.set(self.previous));
        if let Some(previous) = self.previous_syscall {
            SYSCALL_ORIGIN.with(|cell| cell.set(previous));
        }
    }
}

pub(crate) fn enter_origin(origin: u8) -> OriginScope {
    OriginScope {
        previous: ORIGIN.with(|cell| cell.replace(origin)),
        previous_syscall: None,
    }
}

pub(crate) fn enter_syscall_origin(nr: i32) -> OriginScope {
    let origin = origin_for_syscall(nr);
    // The syscall-entry point on the syscall's own host thread: snapshot this thread's HVF work
    // sums so `record_syscall_exit` can attribute a slow syscall's service time.
    SYSCALL_ENTRY_WORK.with(|entry| entry.set(THREAD_WORK.with(Cell::get)));
    // T1h: this syscall's own longest lock waits (and whom they queued behind) start empty, and
    // a lock this thread takes from here on is attributed to this syscall number.
    let _ = VMEM_BLAME.try_with(|cell| cell.set(WaitBlame::NONE));
    let _ = CELL_BLAME.try_with(|cell| cell.set(WaitBlame::NONE));
    let _ = CURRENT_NR.try_with(|cell| cell.set(i64::from(nr)));
    OriginScope {
        previous: ORIGIN.with(|cell| cell.replace(origin)),
        previous_syscall: Some(SYSCALL_ORIGIN.with(|cell| cell.replace(origin))),
    }
}

// ---------------------------------------------------------------------------
// Slow-syscall attribution (hvf-retirement-pump-exclusive-gate-lock-order-inversion follow-up):
// which syscalls reach multi-second SERVICE times, and how much of that is exclusive-gate wait,
// exclusive hold, gate-mutex / ledger-lock waits and settled mutations on the syscall's own
// thread. Only syscalls at or over `SLOW_SYSCALL_NS` of service are recorded; the per-thread
// sums below cost a thread-local add at each (already rare) admission / hold / contended lock.
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
pub(crate) struct ThreadWork {
    excl_admissions: u64,
    excl_wait_ticks: u64,
    excl_hold_ticks: u64,
    gate_mutex_wait_ticks: u64,
    lock_wait_ticks: u64,
    mutations: u64,
    mutate_ticks: u64,
    /// Contended waits for litebox's mapping lock (`PageManager`'s `vmem`), T1h.
    vmem_wait_ticks: u64,
    vmem_waits: u64,
    /// Contended waits for any address space's `cell.state` mutex ([`TimedMutex`]), T1h.
    cell_wait_ticks: u64,
    cell_waits: u64,
}

impl ThreadWork {
    const ZERO: Self = Self {
        excl_admissions: 0,
        excl_wait_ticks: 0,
        excl_hold_ticks: 0,
        gate_mutex_wait_ticks: 0,
        lock_wait_ticks: 0,
        mutations: 0,
        mutate_ticks: 0,
        vmem_wait_ticks: 0,
        vmem_waits: 0,
        cell_wait_ticks: 0,
        cell_waits: 0,
    };

    /// Every lock-class wait: exclusive-gate admission, gate mutex, ledger/pump mutexes, the
    /// mapping lock and `cell.state`.
    fn lock_class_wait_ticks(&self) -> u64 {
        self.excl_wait_ticks
            .wrapping_add(self.gate_mutex_wait_ticks)
            .wrapping_add(self.lock_wait_ticks)
            .wrapping_add(self.vmem_wait_ticks)
            .wrapping_add(self.cell_wait_ticks)
    }

    fn delta(&self, earlier: &Self) -> Self {
        Self {
            excl_admissions: self.excl_admissions.wrapping_sub(earlier.excl_admissions),
            excl_wait_ticks: self.excl_wait_ticks.wrapping_sub(earlier.excl_wait_ticks),
            excl_hold_ticks: self.excl_hold_ticks.wrapping_sub(earlier.excl_hold_ticks),
            gate_mutex_wait_ticks: self
                .gate_mutex_wait_ticks
                .wrapping_sub(earlier.gate_mutex_wait_ticks),
            lock_wait_ticks: self.lock_wait_ticks.wrapping_sub(earlier.lock_wait_ticks),
            mutations: self.mutations.wrapping_sub(earlier.mutations),
            mutate_ticks: self.mutate_ticks.wrapping_sub(earlier.mutate_ticks),
            vmem_wait_ticks: self.vmem_wait_ticks.wrapping_sub(earlier.vmem_wait_ticks),
            vmem_waits: self.vmem_waits.wrapping_sub(earlier.vmem_waits),
            cell_wait_ticks: self.cell_wait_ticks.wrapping_sub(earlier.cell_wait_ticks),
            cell_waits: self.cell_waits.wrapping_sub(earlier.cell_waits),
        }
    }
}

thread_local! {
    /// This host thread's running HVF work sums (never reset; read as deltas).
    static THREAD_WORK: Cell<ThreadWork> = const { Cell::new(ThreadWork::ZERO) };
    /// `THREAD_WORK` at the current syscall's entry.
    static SYSCALL_ENTRY_WORK: Cell<ThreadWork> = const { Cell::new(ThreadWork::ZERO) };
}

fn thread_work(update: impl FnOnce(&mut ThreadWork)) {
    THREAD_WORK.with(|cell| {
        let mut work = cell.get();
        update(&mut work);
        cell.set(work);
    });
}

const SLOW_SYSCALL_NS: u64 = 100_000_000;
const SLOW_RING_LEN: usize = 512;
const SLOW_FIELD_NAMES: [&str; 30] = [
    "wall_ms",
    "nr",
    "space_id",
    "lane_tid",
    "elapsed_ns",
    "blocked_ns",
    "service_ns",
    "excl_admissions",
    "excl_wait_ns",
    "excl_hold_ns",
    "gate_mutex_wait_ns",
    "lock_wait_ns",
    "mutations",
    "mutate_ns",
    // T1h: the syscall number at entry (`nr` above is read after the call, -1 for execve/exit),
    // this syscall's mapping-lock and `cell.state` waits, and for the longest of each the holder
    // it queued behind -- its host thread, syscall number (`-1000 - origin` outside a syscall),
    // `lock_sites` index of the code that held it, and how long it had held it by then.
    "entry_nr",
    "vmem_wait_ns",
    "vmem_waits",
    "vmem_max_wait_ns",
    "vmem_blame_tid",
    "vmem_blame_nr",
    "vmem_blame_site",
    "vmem_blame_held_ns",
    "cell_wait_ns",
    "cell_waits",
    "cell_max_wait_ns",
    "cell_blame_tid",
    "cell_blame_nr",
    "cell_blame_site",
    "cell_blame_held_ns",
    "cell_blame_space",
];
const SLOW_FIELDS: usize = SLOW_FIELD_NAMES.len();
static SLOW_RING: [[AtomicU64; SLOW_FIELDS]; SLOW_RING_LEN] =
    [const { [const { AtomicU64::new(0) }; SLOW_FIELDS] }; SLOW_RING_LEN];
static SLOW_CURSOR: AtomicUsize = AtomicUsize::new(0);
static SLOWEST: [AtomicU64; SLOW_FIELDS] = [const { AtomicU64::new(0) }; SLOW_FIELDS];
static SLOWEST_SERVICE_NS: AtomicU64 = AtomicU64::new(0);

/// Records one syscall whose service time reached `SLOW_SYSCALL_NS`, attributed with this
/// thread's HVF work since the syscall's entry (`enter_syscall_origin`).
fn record_slow_syscall(space_id: HvfAddressSpaceId, nr: i32, elapsed_ns: u64, blocked_ns: u64) {
    let service_ns = elapsed_ns.saturating_sub(blocked_ns);
    let entry = SYSCALL_ENTRY_WORK.with(Cell::get);
    let now = THREAD_WORK.with(Cell::get);
    let wall_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0);
    let vmem = VMEM_BLAME.try_with(Cell::get).unwrap_or(WaitBlame::NONE);
    let cell = CELL_BLAME.try_with(Cell::get).unwrap_or(WaitBlame::NONE);
    let entry_nr = CURRENT_NR.try_with(Cell::get).unwrap_or(-1);
    let blame_site = |blame: &WaitBlame, kind: u8| -> u64 {
        if blame.holder.site == 0 {
            return u64::MAX;
        }
        lock_site_index(blame.holder.site, kind) as u64
    };
    let fields: [u64; SLOW_FIELDS] = [
        wall_ms,
        u64::from(nr.cast_unsigned()),
        space_id.value(),
        thread_id_u64(),
        elapsed_ns,
        blocked_ns,
        service_ns,
        now.excl_admissions.wrapping_sub(entry.excl_admissions),
        ticks_to_ns(now.excl_wait_ticks.wrapping_sub(entry.excl_wait_ticks)),
        ticks_to_ns(now.excl_hold_ticks.wrapping_sub(entry.excl_hold_ticks)),
        ticks_to_ns(now.gate_mutex_wait_ticks.wrapping_sub(entry.gate_mutex_wait_ticks)),
        ticks_to_ns(now.lock_wait_ticks.wrapping_sub(entry.lock_wait_ticks)),
        now.mutations.wrapping_sub(entry.mutations),
        ticks_to_ns(now.mutate_ticks.wrapping_sub(entry.mutate_ticks)),
        entry_nr.cast_unsigned(),
        ticks_to_ns(now.vmem_wait_ticks.wrapping_sub(entry.vmem_wait_ticks)),
        now.vmem_waits.wrapping_sub(entry.vmem_waits),
        ticks_to_ns(vmem.max_wait),
        vmem.holder.tid,
        vmem.holder.nr.cast_unsigned(),
        blame_site(&vmem, LOCK_KIND_VMEM_WRITE),
        ticks_to_ns(vmem.held_at_end),
        ticks_to_ns(now.cell_wait_ticks.wrapping_sub(entry.cell_wait_ticks)),
        now.cell_waits.wrapping_sub(entry.cell_waits),
        ticks_to_ns(cell.max_wait),
        cell.holder.tid,
        cell.holder.nr.cast_unsigned(),
        blame_site(&cell, LOCK_KIND_CELL_STATE),
        ticks_to_ns(cell.held_at_end),
        cell.space,
    ];
    let slot = SLOW_CURSOR.fetch_add(1, Ordering::Relaxed) % SLOW_RING_LEN;
    for (cell, value) in SLOW_RING[slot].iter().zip(fields) {
        cell.store(value, Ordering::Relaxed);
    }
    if SLOWEST_SERVICE_NS.fetch_max(service_ns, Ordering::Relaxed) < service_ns {
        for (cell, value) in SLOWEST.iter().zip(fields) {
            cell.store(value, Ordering::Relaxed);
        }
    }
}

fn render_slow_row(out: &mut String, cells: &[AtomicU64; SLOW_FIELDS]) {
    use std::fmt::Write as _;
    out.push('{');
    for (index, (name, cell)) in SLOW_FIELD_NAMES.iter().zip(cells.iter()).enumerate() {
        if index > 0 {
            out.push(',');
        }
        let value = cell.load(Ordering::Relaxed);
        if *name == "nr" {
            let _ = write!(out, "\"nr\":{}", (value as u32).cast_signed());
        } else if matches!(*name, "entry_nr" | "vmem_blame_nr" | "cell_blame_nr") {
            let _ = write!(out, "\"{name}\":{}", value.cast_signed());
        } else if matches!(*name, "vmem_blame_site" | "cell_blame_site") && value == u64::MAX {
            let _ = write!(out, "\"{name}\":-1");
        } else {
            let _ = write!(out, "\"{name}\":{value}");
        }
    }
    out.push('}');
}

fn render_slow_syscalls(out: &mut String) {
    use std::fmt::Write as _;
    let recorded = SLOW_CURSOR.load(Ordering::Acquire);
    let live = recorded.min(SLOW_RING_LEN);
    let oldest = if recorded > SLOW_RING_LEN { recorded % SLOW_RING_LEN } else { 0 };
    let _ = write!(
        out,
        "\"slow_syscalls\":{{\"threshold_ns\":{SLOW_SYSCALL_NS},\"recorded\":{recorded},\"slowest\":"
    );
    render_slow_row(out, &SLOWEST);
    out.push_str(",\"ring\":[");
    for i in 0..live {
        if i > 0 {
            out.push(',');
        }
        render_slow_row(out, &SLOW_RING[(oldest + i) % SLOW_RING_LEN]);
    }
    out.push_str("]},");
}

// ---------------------------------------------------------------------------
// hvf-t1g-remainder-multisecond-service-guest-memory-access-convoy (T1h): lock-holder attribution
// for the two locks a host-side guest-memory access (and every mm syscall) can stall on --
// litebox's process-global mapping lock (`PageManager`'s `vmem` reader-writer lock, reported
// through `PageManagementProvider::mapping_lock_event`) and each address space's `cell.state`
// mutex ([`TimedMutex`]). A contended wait is timed and charged to the waiting thread (and to its
// syscall's slow-ring row) together with the holder it queued behind: that holder's host thread,
// syscall number (`-1000 - origin` outside a syscall) and the source location that took the lock.
// A hold at or over `LONG_HOLD_NS` lands in `lock_holds` with what the holder itself waited on
// meanwhile (its own `ThreadWork` delta over the hold). Every syscall that took `LONG_SYSCALL_NS`
// or more is classified in `long_syscalls`. Uncontended cost: thread-local work and one tick read
// per acquisition and per release; shared lines are written only on contention and long holds.
// ---------------------------------------------------------------------------

pub(crate) const LOCK_KIND_VMEM_READ: u8 = 0;
pub(crate) const LOCK_KIND_VMEM_WRITE: u8 = 1;
pub(crate) const LOCK_KIND_CELL_STATE: u8 = 2;
const LOCK_KIND_NAMES: [&str; 3] = ["vmem_read", "vmem_write", "cell_state"];
/// A wait at or over this is contended (below it: the uncontended path plus the lock's spin).
const LOCK_CONTENDED_NS: u64 = 2_000;
/// A hold at or over this is recorded individually in `lock_holds`.
const LONG_HOLD_NS: u64 = 10_000_000;
/// A syscall whose elapsed time reaches this is classified in `long_syscalls`.
const LONG_SYSCALL_NS: u64 = 1_000_000_000;

/// `(contended, long_hold)` thresholds in host ticks.
fn lock_thresholds() -> (u64, u64) {
    static THRESHOLDS: std::sync::OnceLock<(u64, u64)> = std::sync::OnceLock::new();
    *THRESHOLDS.get_or_init(|| {
        let (numer, denom) = timebase();
        let to_ticks = |ns: u64| (ns.saturating_mul(denom) / numer.max(1)).max(1);
        (to_ticks(LOCK_CONTENDED_NS), to_ticks(LONG_HOLD_NS))
    })
}

/// Who holds a lock (as last published; `tid == 0` = nobody). Fields are independent relaxed
/// atomics, so a concurrent reader can see a torn identity -- acceptable for attribution.
pub(crate) struct LockHolder {
    tid: AtomicU64,
    nr: AtomicI64,
    site: AtomicUsize,
    since: AtomicU64,
}

#[derive(Clone, Copy)]
struct HolderSnapshot {
    tid: u64,
    nr: i64,
    site: usize,
    since: u64,
}

impl HolderSnapshot {
    const NONE: Self = Self {
        tid: 0,
        nr: 0,
        site: 0,
        since: 0,
    };
}

impl LockHolder {
    pub(crate) const fn new() -> Self {
        Self {
            tid: AtomicU64::new(0),
            nr: AtomicI64::new(0),
            site: AtomicUsize::new(0),
            since: AtomicU64::new(0),
        }
    }

    fn set(&self, site: &'static Location<'static>, since: u64) {
        self.nr.store(current_actor(), Ordering::Relaxed);
        self.site
            .store(core::ptr::from_ref(site) as usize, Ordering::Relaxed);
        self.since.store(since, Ordering::Relaxed);
        self.tid.store(thread_id_u64(), Ordering::Release);
    }

    fn clear(&self) {
        self.tid.store(0, Ordering::Release);
    }

    fn snapshot(&self) -> HolderSnapshot {
        let tid = self.tid.load(Ordering::Acquire);
        if tid == 0 {
            return HolderSnapshot::NONE;
        }
        HolderSnapshot {
            tid,
            nr: self.nr.load(Ordering::Relaxed),
            site: self.site.load(Ordering::Relaxed),
            since: self.since.load(Ordering::Relaxed),
        }
    }
}

/// The longest contended wait of one kind in the current syscall, and whom it queued behind.
#[derive(Clone, Copy)]
struct WaitBlame {
    max_wait: u64,
    holder: HolderSnapshot,
    /// How long `holder` had held the lock when this wait ended (0 when no holder was seen).
    held_at_end: u64,
    space: u64,
}

impl WaitBlame {
    const NONE: Self = Self {
        max_wait: 0,
        holder: HolderSnapshot::NONE,
        held_at_end: 0,
        space: 0,
    };
}

thread_local! {
    /// The syscall number this thread is servicing (`-1` outside a syscall).
    static CURRENT_NR: Cell<i64> = const { Cell::new(-1) };
    static VMEM_BLAME: Cell<WaitBlame> = const { Cell::new(WaitBlame::NONE) };
    static CELL_BLAME: Cell<WaitBlame> = const { Cell::new(WaitBlame::NONE) };
    /// This thread's pending mapping-lock request: when, and who held (or was queued for) the
    /// write side at that moment.
    static VMEM_REQUEST: Cell<(u64, HolderSnapshot)> =
        const { Cell::new((0, HolderSnapshot::NONE)) };
    /// Shared mapping-lock nesting depth on this thread, when the outermost share was granted,
    /// and this thread's work sums at that moment.
    static VMEM_READ_DEPTH: Cell<u32> = const { Cell::new(0) };
    static VMEM_READ_START: Cell<(u64, ThreadWork)> = const { Cell::new((0, ThreadWork::ZERO)) };
    /// This thread's work sums when it was granted the mapping lock exclusively.
    static VMEM_WRITE_WORK: Cell<ThreadWork> = const { Cell::new(ThreadWork::ZERO) };
}

/// The syscall number this thread is servicing, or `-1000 - origin` outside a syscall.
fn current_actor() -> i64 {
    let nr = CURRENT_NR.try_with(Cell::get).unwrap_or(-1);
    if nr >= 0 {
        return nr;
    }
    -1000 - i64::from(ORIGIN.try_with(Cell::get).unwrap_or(ORIGIN_UNSCOPED))
}

fn current_thread_work() -> ThreadWork {
    THREAD_WORK.try_with(Cell::get).unwrap_or(ThreadWork::ZERO)
}

/// The mapping lock's current exclusive holder, and the most recent writer still queued for it.
static VMEM_WRITER: LockHolder = LockHolder::new();
static VMEM_QUEUED_WRITER: LockHolder = LockHolder::new();

static VMEM_READ_WAIT: CostHistogram = CostHistogram::new();
static VMEM_WRITE_WAIT: CostHistogram = CostHistogram::new();
static VMEM_WRITE_HOLD: CostHistogram = CostHistogram::new();
/// The mapping-table mirror refresh of each exclusive section that changed the table
/// (`MappingLockEvent::MirrorReplay` to its `WriteReleased`): the mirror write-lock acquisition
/// plus the replay of the section's own table operations (T1h fix-up).
static MIRROR_REPLAY: CostHistogram = CostHistogram::new();

thread_local! {
    /// When this thread's pending mirror replay started (0: none pending).
    static MIRROR_REPLAY_START: Cell<u64> = const { Cell::new(0) };
}
static CELL_WAIT: CostHistogram = CostHistogram::new();
static VMEM_WRITES: AtomicU64 = AtomicU64::new(0);

const LOCK_SITE_TABLE_LEN: usize = 512;

/// One lock-taking source location: its own contended waits, the waits it caused as a blamed
/// holder, and its long holds.
struct LockSiteSlot {
    contended: AtomicU64,
    wait_ticks: AtomicU64,
    wait_max: AtomicU64,
    caused_waits: AtomicU64,
    caused_wait_ticks: AtomicU64,
    long_holds: AtomicU64,
    long_hold_ticks: AtomicU64,
    hold_max: AtomicU64,
}

impl LockSiteSlot {
    const fn new() -> Self {
        Self {
            contended: AtomicU64::new(0),
            wait_ticks: AtomicU64::new(0),
            wait_max: AtomicU64::new(0),
            caused_waits: AtomicU64::new(0),
            caused_wait_ticks: AtomicU64::new(0),
            long_holds: AtomicU64::new(0),
            long_hold_ticks: AtomicU64::new(0),
            hold_max: AtomicU64::new(0),
        }
    }
}

static LOCK_SITES: [LockSiteSlot; LOCK_SITE_TABLE_LEN] =
    [const { LockSiteSlot::new() }; LOCK_SITE_TABLE_LEN];

#[repr(C, align(128))]
struct LockSiteKeys {
    keys: [AtomicUsize; LOCK_SITE_TABLE_LEN],
    kinds: [AtomicU8; LOCK_SITE_TABLE_LEN],
}

static LOCK_SITE_KEYS: LockSiteKeys = LockSiteKeys {
    keys: [const { AtomicUsize::new(0) }; LOCK_SITE_TABLE_LEN],
    kinds: [const { AtomicU8::new(0) }; LOCK_SITE_TABLE_LEN],
};
static LOCK_SITE_OVERFLOWS: AtomicU64 = AtomicU64::new(0);

/// The `lock_sites` row of a `&'static Location` (as its address), claimed on first use;
/// `LOCK_SITE_TABLE_LEN` once the table is full. Slow paths only.
fn lock_site_index(key: usize, kind: u8) -> usize {
    if key == 0 {
        return LOCK_SITE_TABLE_LEN;
    }
    let start = ((key as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15) >> 55) as usize % LOCK_SITE_TABLE_LEN;
    for offset in 0..LOCK_SITE_TABLE_LEN {
        let index = (start + offset) % LOCK_SITE_TABLE_LEN;
        let (Some(slot_key), Some(slot_kind)) = (
            LOCK_SITE_KEYS.keys.get(index),
            LOCK_SITE_KEYS.kinds.get(index),
        ) else {
            break;
        };
        let existing = slot_key.load(Ordering::Acquire);
        let owns = existing == key
            || (existing == 0
                && match slot_key.compare_exchange(0, key, Ordering::AcqRel, Ordering::Acquire) {
                    Ok(_) => {
                        slot_kind.store(kind, Ordering::Release);
                        true
                    }
                    Err(actual) => actual == key,
                });
        if owns {
            return index;
        }
    }
    LOCK_SITE_OVERFLOWS.fetch_add(1, Ordering::Relaxed);
    LOCK_SITE_TABLE_LEN
}

/// A contended wait of `waited` ticks for a lock of `kind`, taken at `site`, that started while
/// `blame` held (or was queued for) it; `space` is the address space for `cell.state`.
fn note_lock_wait(
    kind: u8,
    site: &'static Location<'static>,
    waited: u64,
    blame: HolderSnapshot,
    now: u64,
    space: u64,
) {
    let cell_kind = kind == LOCK_KIND_CELL_STATE;
    thread_work(|work| {
        if cell_kind {
            work.cell_wait_ticks += waited;
            work.cell_waits += 1;
        } else {
            work.vmem_wait_ticks += waited;
            work.vmem_waits += 1;
        }
    });
    let blame_cell = if cell_kind { &CELL_BLAME } else { &VMEM_BLAME };
    let _ = blame_cell.try_with(|cell| {
        if waited > cell.get().max_wait {
            cell.set(WaitBlame {
                max_wait: waited,
                holder: blame,
                held_at_end: if blame.tid != 0 { now.saturating_sub(blame.since) } else { 0 },
                space,
            });
        }
    });
    let ns = ticks_to_ns(waited);
    match kind {
        LOCK_KIND_CELL_STATE => CELL_WAIT.record(ns),
        LOCK_KIND_VMEM_READ => VMEM_READ_WAIT.record(ns),
        _ => VMEM_WRITE_WAIT.record(ns),
    }
    if let Some(slot) = LOCK_SITES.get(lock_site_index(core::ptr::from_ref(site) as usize, kind)) {
        slot.contended.fetch_add(1, Ordering::Relaxed);
        slot.wait_ticks.fetch_add(waited, Ordering::Relaxed);
        slot.wait_max.fetch_max(waited, Ordering::Relaxed);
    }
    let holder_kind = if cell_kind { LOCK_KIND_CELL_STATE } else { LOCK_KIND_VMEM_WRITE };
    if let Some(slot) = LOCK_SITES.get(lock_site_index(blame.site, holder_kind)) {
        slot.caused_waits.fetch_add(1, Ordering::Relaxed);
        slot.caused_wait_ticks.fetch_add(waited, Ordering::Relaxed);
    }
}

const HOLD_RING_LEN: usize = 256;
const HOLD_FIELD_NAMES: [&str; 15] = [
    "wall_ms",
    "kind",
    "tid",
    "nr",
    "site",
    "space",
    "hold_ns",
    "excl_wait_ns",
    "excl_hold_ns",
    "gate_mutex_wait_ns",
    "lock_wait_ns",
    "vmem_wait_ns",
    "cell_wait_ns",
    "mutations",
    "mutate_ns",
];
const HOLD_FIELDS: usize = HOLD_FIELD_NAMES.len();
static HOLD_RING: [[AtomicU64; HOLD_FIELDS]; HOLD_RING_LEN] =
    [const { [const { AtomicU64::new(0) }; HOLD_FIELDS] }; HOLD_RING_LEN];
static HOLD_CURSOR: AtomicUsize = AtomicUsize::new(0);

/// A hold of `hold` ticks (at or over the long-hold threshold) that began with this thread's work
/// sums at `work_at`.
fn record_long_hold(
    kind: u8,
    site: &'static Location<'static>,
    hold: u64,
    work_at: &ThreadWork,
    space: u64,
) {
    let delta = current_thread_work().delta(work_at);
    let site_index = lock_site_index(core::ptr::from_ref(site) as usize, kind);
    if let Some(slot) = LOCK_SITES.get(site_index) {
        slot.long_holds.fetch_add(1, Ordering::Relaxed);
        slot.long_hold_ticks.fetch_add(hold, Ordering::Relaxed);
        slot.hold_max.fetch_max(hold, Ordering::Relaxed);
    }
    let wall_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0);
    let fields: [u64; HOLD_FIELDS] = [
        wall_ms,
        u64::from(kind),
        thread_id_u64(),
        current_actor().cast_unsigned(),
        site_index as u64,
        space,
        ticks_to_ns(hold),
        ticks_to_ns(delta.excl_wait_ticks),
        ticks_to_ns(delta.excl_hold_ticks),
        ticks_to_ns(delta.gate_mutex_wait_ticks),
        ticks_to_ns(delta.lock_wait_ticks),
        ticks_to_ns(delta.vmem_wait_ticks),
        ticks_to_ns(delta.cell_wait_ticks),
        delta.mutations,
        ticks_to_ns(delta.mutate_ticks),
    ];
    let slot = HOLD_CURSOR.fetch_add(1, Ordering::Relaxed) % HOLD_RING_LEN;
    for (cell, value) in HOLD_RING[slot].iter().zip(fields) {
        cell.store(value, Ordering::Relaxed);
    }
}

/// `PageManagementProvider::mapping_lock_event` for this platform.
pub(crate) fn mapping_lock_event(
    event: litebox::platform::page_mgmt::MappingLockEvent,
    site: &'static Location<'static>,
) {
    use litebox::platform::page_mgmt::MappingLockEvent;
    match event {
        MappingLockEvent::ReadRequest | MappingLockEvent::WriteRequest => {
            let now = ticks();
            let mut blame = VMEM_WRITER.snapshot();
            if blame.tid == 0 {
                blame = VMEM_QUEUED_WRITER.snapshot();
            }
            let _ = VMEM_REQUEST.try_with(|cell| cell.set((now, blame)));
            if event == MappingLockEvent::WriteRequest {
                VMEM_QUEUED_WRITER.set(site, now);
            }
        }
        MappingLockEvent::ReadAcquired | MappingLockEvent::WriteAcquired => {
            let now = ticks();
            let write = event == MappingLockEvent::WriteAcquired;
            let (requested, blame) = VMEM_REQUEST
                .try_with(Cell::get)
                .unwrap_or((now, HolderSnapshot::NONE));
            let waited = now.wrapping_sub(requested);
            if waited >= lock_thresholds().0 {
                let kind = if write { LOCK_KIND_VMEM_WRITE } else { LOCK_KIND_VMEM_READ };
                note_lock_wait(kind, site, waited, blame, now, 0);
            }
            if write {
                VMEM_WRITES.fetch_add(1, Ordering::Relaxed);
                if VMEM_QUEUED_WRITER.tid.load(Ordering::Relaxed) == thread_id_u64() {
                    VMEM_QUEUED_WRITER.clear();
                }
                VMEM_WRITER.set(site, now);
                let _ = VMEM_WRITE_WORK.try_with(|cell| cell.set(current_thread_work()));
            } else {
                add_stat(STAT_VMEM_READS, 1);
                let _ = VMEM_READ_DEPTH.try_with(|depth| {
                    if depth.get() == 0 {
                        let _ = VMEM_READ_START.try_with(|start| start.set((now, current_thread_work())));
                    }
                    depth.set(depth.get().saturating_add(1));
                });
            }
        }
        MappingLockEvent::ReadReleased => {
            let outermost = VMEM_READ_DEPTH
                .try_with(|depth| {
                    let next = depth.get().saturating_sub(1);
                    depth.set(next);
                    next == 0
                })
                .unwrap_or(false);
            if outermost
                && let Ok((started, work_at)) = VMEM_READ_START.try_with(Cell::get)
            {
                let hold = ticks().wrapping_sub(started);
                if hold >= lock_thresholds().1 {
                    record_long_hold(LOCK_KIND_VMEM_READ, site, hold, &work_at, 0);
                }
            }
        }
        MappingLockEvent::MirrorReplay => {
            let _ = MIRROR_REPLAY_START.try_with(|cell| cell.set(ticks()));
        }
        MappingLockEvent::WriteReleased => {
            if let Ok(started) = MIRROR_REPLAY_START.try_with(|cell| cell.replace(0))
                && started != 0
            {
                MIRROR_REPLAY.record(ticks_to_ns(ticks().wrapping_sub(started)));
            }
            let holder = VMEM_WRITER.snapshot();
            let hold = ticks().wrapping_sub(holder.since);
            VMEM_WRITE_HOLD.record(ticks_to_ns(hold));
            if hold >= lock_thresholds().1 {
                let work_at = VMEM_WRITE_WORK.try_with(Cell::get).unwrap_or(ThreadWork::ZERO);
                record_long_hold(LOCK_KIND_VMEM_WRITE, site, hold, &work_at, 0);
            }
            VMEM_WRITER.clear();
        }
    }
}

/// A `std::sync::Mutex` whose contended waits and long holds are attributed like the mapping
/// lock's (see this section's header): an address space's `cell.state`. `lock()` keeps
/// `Mutex::lock`'s signature, so call sites only change the field's type; `tag` names the owner
/// (the address-space id) in the records.
pub(crate) struct TimedMutex<T> {
    inner: Mutex<T>,
    holder: LockHolder,
    tag: u64,
}

pub(crate) struct TimedGuard<'a, T> {
    guard: MutexGuard<'a, T>,
    owner: &'a TimedMutex<T>,
    site: &'static Location<'static>,
    since: u64,
    work_at: ThreadWork,
}

impl<T> TimedMutex<T> {
    pub(crate) const fn new(value: T, tag: u64) -> Self {
        Self {
            inner: Mutex::new(value),
            holder: LockHolder::new(),
            tag,
        }
    }

    #[track_caller]
    pub(crate) fn lock(&self) -> std::sync::LockResult<TimedGuard<'_, T>> {
        let site = Location::caller();
        let (guard, poisoned) = match self.inner.try_lock() {
            Ok(guard) => (guard, false),
            Err(TryLockError::Poisoned(poisoned)) => (poisoned.into_inner(), true),
            Err(TryLockError::WouldBlock) => {
                let blame = self.holder.snapshot();
                let started = ticks();
                let (guard, poisoned) = match self.inner.lock() {
                    Ok(guard) => (guard, false),
                    Err(poisoned) => (poisoned.into_inner(), true),
                };
                let now = ticks();
                let waited = now.wrapping_sub(started);
                if waited >= lock_thresholds().0 {
                    note_lock_wait(LOCK_KIND_CELL_STATE, site, waited, blame, now, self.tag);
                }
                (guard, poisoned)
            }
        };
        let since = ticks();
        self.holder.set(site, since);
        let guard = TimedGuard {
            guard,
            owner: self,
            site,
            since,
            work_at: current_thread_work(),
        };
        if poisoned {
            Err(PoisonError::new(guard))
        } else {
            Ok(guard)
        }
    }
}

impl<T> core::ops::Deref for TimedGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.guard
    }
}

impl<T> core::ops::DerefMut for TimedGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.guard
    }
}

impl<T> Drop for TimedGuard<'_, T> {
    fn drop(&mut self) {
        // Runs before `guard` itself unlocks: the holder record never names a thread that no
        // longer holds the mutex once a waiter is admitted.
        let hold = ticks().wrapping_sub(self.since);
        if hold >= lock_thresholds().1 {
            record_long_hold(
                LOCK_KIND_CELL_STATE,
                self.site,
                hold,
                &self.work_at,
                self.owner.tag,
            );
        }
        self.owner.holder.clear();
    }
}

/// Every syscall with `elapsed >= LONG_SYSCALL_NS`, split by what its time went to: `legit`
/// (service below the threshold -- the rest was an interruptible guest-condition wait: futex,
/// poll/epoll, a pipe or socket, wait4, nanosleep, ...), `lock` (service at or over it, at least
/// half of it lock-class waits) or `other` (service at or over it, mostly work).
const LONG_TOTAL: usize = 0;
const LONG_LEGIT: usize = 1;
const LONG_LOCK: usize = 2;
const LONG_OTHER: usize = 3;
const LONG_MAX_SERVICE_LOCK: usize = 4;
const LONG_MAX_SERVICE_OTHER: usize = 5;
const LONG_MAX_ELAPSED_LEGIT: usize = 6;
const LONG_SUM_SERVICE_LOCK: usize = 7;
const LONG_SUM_SERVICE_OTHER: usize = 8;
const LONG_LOCK_VMEM: usize = 9;
const LONG_LOCK_CELL: usize = 10;
const LONG_LOCK_GATE: usize = 11;
const LONG_LOCK_LEDGER: usize = 12;
const LONG_MAX_SERVICE_LEGIT: usize = 13;
const LONG_FIELD_NAMES: [&str; 14] = [
    "total",
    "legit",
    "lock",
    "other",
    "max_service_lock_ns",
    "max_service_other_ns",
    "max_elapsed_legit_ns",
    "sum_service_lock_ns",
    "sum_service_other_ns",
    "lock_vmem_wait_ns",
    "lock_cell_wait_ns",
    "lock_gate_wait_ns",
    "lock_ledger_wait_ns",
    "max_service_legit_ns",
];
static LONG_SYSCALLS: [AtomicU64; LONG_FIELD_NAMES.len()] =
    [const { AtomicU64::new(0) }; LONG_FIELD_NAMES.len()];
const LONG_NR_TABLE: usize = 512;
/// Per entry syscall number (`% 512`): `[legit, lock, other]` long-syscall counts.
static LONG_BY_NR: [[AtomicU64; 3]; LONG_NR_TABLE] =
    [const { [const { AtomicU64::new(0) }; 3] }; LONG_NR_TABLE];

fn record_long_syscall(elapsed_ns: u64, blocked_ns: u64) {
    let service_ns = elapsed_ns.saturating_sub(blocked_ns);
    let entry = SYSCALL_ENTRY_WORK.try_with(Cell::get).unwrap_or(ThreadWork::ZERO);
    let delta = current_thread_work().delta(&entry);
    let lock_ns = ticks_to_ns(delta.lock_class_wait_ticks());
    let nr = CURRENT_NR.try_with(Cell::get).unwrap_or(-1);
    LONG_SYSCALLS[LONG_TOTAL].fetch_add(1, Ordering::Relaxed);
    let class = if service_ns < LONG_SYSCALL_NS {
        LONG_SYSCALLS[LONG_LEGIT].fetch_add(1, Ordering::Relaxed);
        LONG_SYSCALLS[LONG_MAX_ELAPSED_LEGIT].fetch_max(elapsed_ns, Ordering::Relaxed);
        LONG_SYSCALLS[LONG_MAX_SERVICE_LEGIT].fetch_max(service_ns, Ordering::Relaxed);
        0
    } else if lock_ns.saturating_mul(2) >= service_ns {
        LONG_SYSCALLS[LONG_LOCK].fetch_add(1, Ordering::Relaxed);
        LONG_SYSCALLS[LONG_MAX_SERVICE_LOCK].fetch_max(service_ns, Ordering::Relaxed);
        LONG_SYSCALLS[LONG_SUM_SERVICE_LOCK].fetch_add(service_ns, Ordering::Relaxed);
        LONG_SYSCALLS[LONG_LOCK_VMEM]
            .fetch_add(ticks_to_ns(delta.vmem_wait_ticks), Ordering::Relaxed);
        LONG_SYSCALLS[LONG_LOCK_CELL]
            .fetch_add(ticks_to_ns(delta.cell_wait_ticks), Ordering::Relaxed);
        LONG_SYSCALLS[LONG_LOCK_GATE].fetch_add(
            ticks_to_ns(delta.excl_wait_ticks.wrapping_add(delta.gate_mutex_wait_ticks)),
            Ordering::Relaxed,
        );
        LONG_SYSCALLS[LONG_LOCK_LEDGER]
            .fetch_add(ticks_to_ns(delta.lock_wait_ticks), Ordering::Relaxed);
        1
    } else {
        LONG_SYSCALLS[LONG_OTHER].fetch_add(1, Ordering::Relaxed);
        LONG_SYSCALLS[LONG_MAX_SERVICE_OTHER].fetch_max(service_ns, Ordering::Relaxed);
        LONG_SYSCALLS[LONG_SUM_SERVICE_OTHER].fetch_add(service_ns, Ordering::Relaxed);
        2
    };
    if let Some(row) = LONG_BY_NR.get(nr.rem_euclid(LONG_NR_TABLE as i64) as usize) {
        row[class].fetch_add(1, Ordering::Relaxed);
    }
}

fn render_lock_attribution(out: &mut String) {
    use std::fmt::Write as _;
    let (contended_ticks, long_hold_ticks) = lock_thresholds();
    let _ = write!(
        out,
        "\"lock_attribution\":{{\"contended_ns\":{},\"long_hold_ns\":{},\"kind_names\":[\"vmem_read\",\"vmem_write\",\"cell_state\"],\"vmem_reads\":{},\"vmem_writes\":{},\"site_overflows\":{},",
        ticks_to_ns(contended_ticks),
        ticks_to_ns(long_hold_ticks),
        stat_total(STAT_VMEM_READS),
        VMEM_WRITES.load(Ordering::Relaxed),
        LOCK_SITE_OVERFLOWS.load(Ordering::Relaxed),
    );
    render_cost_histogram(out, "vmem_read_wait", &VMEM_READ_WAIT);
    out.push(',');
    render_cost_histogram(out, "vmem_write_wait", &VMEM_WRITE_WAIT);
    out.push(',');
    render_cost_histogram(out, "vmem_write_hold", &VMEM_WRITE_HOLD);
    out.push(',');
    render_cost_histogram(out, "mirror_replay", &MIRROR_REPLAY);
    out.push(',');
    render_cost_histogram(out, "cell_wait", &CELL_WAIT);
    out.push_str(",\"lock_sites\":[");
    let mut first = true;
    for (index, slot) in LOCK_SITES.iter().enumerate() {
        let key = LOCK_SITE_KEYS.keys[index].load(Ordering::Acquire);
        if key == 0 {
            continue;
        }
        // SAFETY: every nonzero key was stored from a `&'static Location<'static>` by
        // `lock_site_index` and is never changed afterwards.
        let location = unsafe { &*(key as *const Location<'static>) };
        let file = location.file().rsplit('/').next().unwrap_or("");
        let kind = LOCK_KIND_NAMES
            .get(usize::from(LOCK_SITE_KEYS.kinds[index].load(Ordering::Acquire)))
            .copied()
            .unwrap_or("?");
        if !first {
            out.push(',');
        }
        first = false;
        let _ = write!(
            out,
            "{{\"index\":{index},\"site\":\"{file}:{}:{}\",\"kind\":\"{kind}\",\"contended\":{},\"wait_ns\":{},\"wait_max_ns\":{},\"caused_waits\":{},\"caused_wait_ns\":{},\"long_holds\":{},\"long_hold_ns\":{},\"hold_max_ns\":{}}}",
            location.line(),
            location.column(),
            slot.contended.load(Ordering::Relaxed),
            ticks_to_ns(slot.wait_ticks.load(Ordering::Relaxed)),
            ticks_to_ns(slot.wait_max.load(Ordering::Relaxed)),
            slot.caused_waits.load(Ordering::Relaxed),
            ticks_to_ns(slot.caused_wait_ticks.load(Ordering::Relaxed)),
            slot.long_holds.load(Ordering::Relaxed),
            ticks_to_ns(slot.long_hold_ticks.load(Ordering::Relaxed)),
            ticks_to_ns(slot.hold_max.load(Ordering::Relaxed)),
        );
    }
    let recorded = HOLD_CURSOR.load(Ordering::Acquire);
    let live = recorded.min(HOLD_RING_LEN);
    let oldest = if recorded > HOLD_RING_LEN { recorded % HOLD_RING_LEN } else { 0 };
    let _ = write!(out, "],\"lock_holds\":{{\"recorded\":{recorded},\"ring\":[");
    for i in 0..live {
        if i > 0 {
            out.push(',');
        }
        out.push('{');
        for (index, (name, cell)) in HOLD_FIELD_NAMES
            .iter()
            .zip(HOLD_RING[(oldest + i) % HOLD_RING_LEN].iter())
            .enumerate()
        {
            if index > 0 {
                out.push(',');
            }
            let value = cell.load(Ordering::Relaxed);
            if *name == "nr" {
                let _ = write!(out, "\"nr\":{}", value.cast_signed());
            } else {
                let _ = write!(out, "\"{name}\":{value}");
            }
        }
        out.push('}');
    }
    out.push_str("]},\"long_syscalls\":{");
    for (index, name) in LONG_FIELD_NAMES.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        let _ = write!(out, "\"{name}\":{}", LONG_SYSCALLS[index].load(Ordering::Relaxed));
    }
    out.push_str(",\"by_nr\":[");
    let mut first = true;
    for (nr, row) in LONG_BY_NR.iter().enumerate() {
        let counts: [u64; 3] = core::array::from_fn(|class| row[class].load(Ordering::Relaxed));
        if counts == [0, 0, 0] {
            continue;
        }
        if !first {
            out.push(',');
        }
        first = false;
        let _ = write!(
            out,
            "{{\"nr\":{nr},\"legit\":{},\"lock\":{},\"other\":{}}}",
            counts[0], counts[1], counts[2]
        );
    }
    out.push_str("]}},");
}

pub(crate) fn current_origin() -> u8 {
    ORIGIN.with(Cell::get)
}

/// One settled Map (0) / Protect (1) / Unmap (2) mutation, attributed to the innermost origin
/// and, separately, to the enclosing syscall.
pub(crate) fn record_mutation(kind: usize, changed: bool) {
    if let Some(row) = ORIGINS.get(usize::from(current_origin())) {
        if let Some(counter) = row.mutations.get(kind) {
            counter.fetch_add(1, Ordering::Relaxed);
        }
        if changed {
            row.changed.fetch_add(1, Ordering::Relaxed);
        }
    }
    if let Some(row) = ORIGINS.get(usize::from(SYSCALL_ORIGIN.with(Cell::get)))
        && let Some(counter) = row.by_syscall.get(kind)
    {
        counter.fetch_add(1, Ordering::Relaxed);
    }
}

/// Wall time of one `mutate_with_retry` / `settle_single_page_mutation` (mutation plus settle).
pub(crate) fn record_mutation_duration(started: u64) {
    let duration = ticks().wrapping_sub(started);
    thread_work(|work| {
        work.mutations += 1;
        work.mutate_ticks += duration;
    });
    if let Some(row) = ORIGINS.get(usize::from(current_origin())) {
        row.mutate_count.fetch_add(1, Ordering::Relaxed);
        row.mutate_ticks.fetch_add(duration, Ordering::Relaxed);
        row.mutate_max.fetch_max(duration, Ordering::Relaxed);
        record_log2(&row.mutate_log2, ticks_to_ns(duration));
    }
}

fn render_log2(out: &mut String, buckets: &[AtomicU64]) {
    out.push('[');
    push_sparse(out, &load_all(buckets));
    out.push(']');
}

fn render_instrumentation(out: &mut String) {
    use std::fmt::Write as _;
    let (numer, denom) = timebase();
    let ns = |stat: usize| ticks_to_ns(stat_total(stat));
    let _ = write!(
        out,
        "\"hvf_instr\":{{\"version\":1,\"tick_numer\":{numer},\"tick_denom\":{denom},\"run_split\":{{\"full_set_registers\":74,\"full_set_simd_registers\":32,\"classes\":["
    );
    for (class, name) in RUN_CLASS_NAMES.iter().enumerate() {
        if class > 0 {
            out.push(',');
        }
        let base = STAT_RUN_CLASS + 3 * class;
        let _ = write!(
            out,
            "{{\"class\":\"{name}\",\"count\":{},\"raw_sum_ns\":{},\"wrapper_sum_ns\":{}",
            stat_total(base),
            ns(base + 1),
            ns(base + 2),
        );
        for (label, base) in [
            ("raw", HIST_RUN_RAW),
            ("wrapper", HIST_RUN_WRAPPER),
            ("wrapper_minus_raw", HIST_RUN_EXCESS),
        ] {
            let _ = write!(out, ",\"{label}\":");
            render_hist(out, base + class);
        }
        out.push('}');
    }
    let _ = write!(
        out,
        "]}},\"owner\":{{\"runs\":{},\"reruns\":{},\"latched\":{},\"total_ns\":{},\"spans_ns\":{{",
        stat_total(STAT_OWNER_RUNS),
        stat_total(STAT_OWNER_RERUNS),
        stat_total(STAT_OWNER_LATCHED),
        ns(STAT_OWNER_TOTAL),
    );
    for (index, name) in OWNER_SPAN_NAMES.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        let _ = write!(out, "\"{name}\":{}", ns(STAT_OWNER_SPANS + index));
    }
    out.push_str("},\"residue\":");
    render_hist(out, HIST_RESIDUE);
    out.push_str(",\"set_state\":");
    render_hist(out, HIST_SET_STATE);
    out.push_str(",\"get_state\":");
    render_hist(out, HIST_GET_STATE);
    let _ = write!(
        out,
        "}},\"guest\":{{\"iterations\":{},\"spans_ns\":{{",
        stat_total(STAT_GUEST_ITERATIONS)
    );
    for (index, name) in GUEST_SPAN_NAMES.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        let _ = write!(out, "\"{name}\":{}", ns(STAT_GUEST_SPANS + index));
    }
    let _ = write!(
        out,
        "}}}},\"channel\":{{\"runs\":{},\"spans_ns\":{{",
        stat_total(STAT_CHANNEL_RUNS)
    );
    for (index, name) in CHANNEL_SPAN_NAMES.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        let _ = write!(out, "\"{name}\":{}", ns(STAT_CHANNEL_SPANS + index));
    }
    out.push_str("},\"owner_wake\":");
    render_hist(out, HIST_OWNER_WAKE);
    out.push_str(",\"guest_wake\":");
    render_hist(out, HIST_GUEST_WAKE);
    let _ = write!(
        out,
        "}},\"gate\":{{\"existing_ops\":{},\"shared_ops\":{},\"shared_ops_ns\":{},\"exclusive_ops\":{},\"exclusive_nested\":{},\"per_run\":{{\"runs\":{},\"guest_locks\":{},\"owner_locks\":{},\"hist\":[",
        stat_total(STAT_EXISTING_OPS),
        stat_total(STAT_SHARED_OPS),
        ns(STAT_SHARED_TICKS),
        stat_total(STAT_EXCLUSIVE_OPS),
        stat_total(STAT_EXCLUSIVE_NESTED),
        stat_total(STAT_RUN_GATE_RUNS),
        stat_total(STAT_RUN_GATE_GUEST),
        stat_total(STAT_RUN_GATE_OWNER),
    );
    let mut run_gate = vec![0u64; RUN_GATE_BUCKETS];
    for shard in &HIST_SHARDS {
        for (sum, bucket) in run_gate.iter_mut().zip(shard.run_gate.iter()) {
            *sum = sum.wrapping_add(bucket.load(Ordering::Relaxed));
        }
    }
    push_sparse(out, &run_gate);
    out.push_str("]},\"locks\":{");
    for (index, (name, buckets)) in GATE_LOCK_SITE_NAMES
        .iter()
        .zip(GATE_CONTENDED_LOG2.iter())
        .enumerate()
    {
        if index > 0 {
            out.push(',');
        }
        let _ = write!(
            out,
            "\"{name}\":{{\"locks\":{},\"contended\":{},\"wait_ns\":{},\"wait_log2\":",
            stat_total(STAT_GATE_LOCKS + index),
            stat_total(STAT_GATE_CONTENDED + index),
            ns(STAT_GATE_WAIT + index),
        );
        render_log2(out, buckets);
        out.push('}');
    }
    let _ = write!(
        out,
        "}},\"site_overflows\":{}}},\"retirements\":{{\"pump_calls\":{},\"pump_nonzero\":{},\"pump_released\":{},\"pump_ns\":{},\"pending_calls\":{},\"pending_ns\":{},\"pending_skipped\":{},\"pending_skipped_ns\":{},\"ack_lock_contended\":{},\"ack_lock_wait_ns\":{},\"pump_lock_contended\":{},\"pump_lock_wait_ns\":{}}},\"sites\":[",
        SITE_OVERFLOWS.load(Ordering::Relaxed),
        stat_total(STAT_PUMP_CALLS),
        stat_total(STAT_PUMP_NONZERO),
        stat_total(STAT_PUMP_RELEASED),
        ns(STAT_PUMP_TICKS),
        stat_total(STAT_PENDING_CALLS),
        ns(STAT_PENDING_TICKS),
        stat_total(STAT_PENDING_SKIPPED),
        ns(STAT_PENDING_SKIPPED + 1),
        stat_total(STAT_ACK_LOCK_CONTENDED),
        ns(STAT_ACK_LOCK_CONTENDED + 1),
        stat_total(STAT_PUMP_LOCK_CONTENDED),
        ns(STAT_PUMP_LOCK_CONTENDED + 1),
    );
    let mut first = true;
    for (index, (slot, (slot_key, slot_kind))) in SITES
        .iter()
        .zip(SITE_KEYS.keys.iter().zip(SITE_KEYS.kinds.iter()))
        .enumerate()
    {
        let key = slot_key.load(Ordering::Acquire);
        if key == 0 {
            continue;
        }
        // SAFETY: every nonzero key was stored from a `&'static Location<'static>` by
        // `site_index` and is never changed afterwards.
        let location = unsafe { &*(key as *const Location<'static>) };
        let file = location.file().rsplit('/').next().unwrap_or("");
        let (count, sum) = SITE_SHARDS.iter().fold((0u64, 0u64), |(count, sum), shard| {
            (
                count.wrapping_add(shard.count.get(index).map_or(0, |v| v.load(Ordering::Relaxed))),
                sum.wrapping_add(shard.ticks.get(index).map_or(0, |v| v.load(Ordering::Relaxed))),
            )
        });
        let kind = SITE_KIND_NAMES
            .get(usize::from(slot_kind.load(Ordering::Acquire)))
            .copied()
            .unwrap_or("none");
        if !first {
            out.push(',');
        }
        first = false;
        let _ = write!(
            out,
            "{{\"site\":\"{file}:{}:{}\",\"kind\":\"{kind}\",\"count\":{count},\"sum_ns\":{},\"nested\":{},\"contended\":{},\"contended_ns\":{},\"contended_log2\":",
            location.line(),
            location.column(),
            ticks_to_ns(sum),
            slot.nested.load(Ordering::Relaxed),
            slot.contended.load(Ordering::Relaxed),
            ticks_to_ns(slot.contended_ticks.load(Ordering::Relaxed)),
        );
        render_log2(out, &slot.contended_log2);
        let _ = write!(
            out,
            ",\"admit_waited\":{},\"admit_rounds\":{},\"admit_wait_ns\":{},\"admit_wait_max_ns\":{},\"admit_wait_log2\":",
            slot.admit_waited.load(Ordering::Relaxed),
            slot.admit_rounds.load(Ordering::Relaxed),
            ticks_to_ns(slot.admit_wait_ticks.load(Ordering::Relaxed)),
            ticks_to_ns(slot.admit_wait_max.load(Ordering::Relaxed)),
        );
        render_log2(out, &slot.admit_wait_log2);
        let _ = write!(
            out,
            ",\"hold_max_ns\":{},\"hold_log2\":",
            ticks_to_ns(slot.hold_max.load(Ordering::Relaxed))
        );
        render_log2(out, &slot.hold_log2);
        let _ = write!(
            out,
            ",\"slow\":{},\"slow_ns\":{},\"slow_log2\":",
            slot.slow.load(Ordering::Relaxed),
            ticks_to_ns(slot.slow_ticks.load(Ordering::Relaxed)),
        );
        render_log2(out, &slot.slow_log2);
        out.push('}');
    }
    out.push_str("],\"origins\":[");
    let mut first = true;
    for (index, row) in ORIGINS.iter().enumerate() {
        let mutations: [u64; 3] = core::array::from_fn(|kind| row.mutations[kind].load(Ordering::Relaxed));
        let by_syscall: [u64; 3] =
            core::array::from_fn(|kind| row.by_syscall[kind].load(Ordering::Relaxed));
        let excl = row.excl_count.load(Ordering::Relaxed);
        let mutate = row.mutate_count.load(Ordering::Relaxed);
        if excl == 0
            && mutate == 0
            && mutations.iter().chain(by_syscall.iter()).all(|v| *v == 0)
        {
            continue;
        }
        if !first {
            out.push(',');
        }
        first = false;
        let _ = write!(
            out,
            "{{\"origin\":\"{}\",\"map\":{},\"protect\":{},\"unmap\":{},\"changed\":{},\"syscall_map\":{},\"syscall_protect\":{},\"syscall_unmap\":{},\"mutate_count\":{mutate},\"mutate_ns\":{},\"mutate_max_ns\":{},\"mutate_log2\":",
            ORIGIN_NAMES.get(index).copied().unwrap_or("?"),
            mutations[0],
            mutations[1],
            mutations[2],
            row.changed.load(Ordering::Relaxed),
            by_syscall[0],
            by_syscall[1],
            by_syscall[2],
            ticks_to_ns(row.mutate_ticks.load(Ordering::Relaxed)),
            ticks_to_ns(row.mutate_max.load(Ordering::Relaxed)),
        );
        render_log2(out, &row.mutate_log2);
        let _ = write!(
            out,
            ",\"excl_count\":{excl},\"excl_waited\":{},\"excl_wait_ns\":{},\"excl_wait_max_ns\":{},\"excl_wait_log2\":",
            row.excl_waited.load(Ordering::Relaxed),
            ticks_to_ns(row.excl_wait_ticks.load(Ordering::Relaxed)),
            ticks_to_ns(row.excl_wait_max.load(Ordering::Relaxed)),
        );
        render_log2(out, &row.excl_wait_log2);
        let _ = write!(
            out,
            ",\"excl_hold_ns\":{},\"excl_hold_max_ns\":{},\"excl_hold_log2\":",
            ticks_to_ns(row.excl_hold_ticks.load(Ordering::Relaxed)),
            ticks_to_ns(row.excl_hold_max.load(Ordering::Relaxed)),
        );
        render_log2(out, &row.excl_hold_log2);
        out.push('}');
    }
    out.push_str("]},");
}

// ---------------------------------------------------------------------------
// Fixed-size structured per-syscall ring (sub-piece 2).
// ---------------------------------------------------------------------------

/// The last `RING_LEN` completed `EC_SVC64` dispatches, replacing log-text tracing for the
/// first-CHECK re-derivation acceptance witness. Five parallel atomic arrays rather than one
/// array of a struct (atomics have no atomic multi-field store): a concurrent reader can
/// therefore observe a torn entry (fields from two different writes at the same slot) exactly
/// like `DELIVERED_TASK_RING` already can -- acceptable for a best-effort diagnostic ring, never
/// load-bearing for correctness.
const RING_LEN: usize = 256;

static RING_NR: [AtomicI64; RING_LEN] = zeroed_i64_array();
static RING_RESULT: [AtomicI64; RING_LEN] = zeroed_i64_array();
/// The host lane thread that serviced this syscall (`std::thread::ThreadId::as_u64`), NOT the
/// guest Linux tid -- no cheap accessor for the live guest tid exists at this call site
/// (`HvfBackend::dispatch_monitor_exit` sees only `&dyn EnterShim` + raw `PtRegs`, neither of
/// which carries task identity today). Still a real, useful correlation key: lane assignment is
/// stable for a guest thread's whole run in this backend's cooperative-lane scheduling model, so
/// entries sharing a `lane_tid` come from the same guest execution context.
static RING_LANE_TID: [AtomicU64; RING_LEN] = zeroed_u64_array();
static RING_TS_NS: [AtomicU64; RING_LEN] = zeroed_u64_array();
static RING_ELAPSED_NS: [AtomicU64; RING_LEN] = zeroed_u64_array();
/// hvf-exit-overhead-instrumentation: the interruptible-wait share of `RING_ELAPSED_NS` for the
/// same entry, so a reader can tell a syscall that blocked on a guest condition from one whose
/// shim service itself stalled (host preemption, lock contention, HVF mapping work).
static RING_BLOCKED_NS: [AtomicU64; RING_LEN] = zeroed_u64_array();
static RING_CURSOR: AtomicUsize = AtomicUsize::new(0);

static TIME_EPOCH: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();

/// Nanoseconds since this process's first call into this module -- monotonic and free of the
/// "no epoch" limitation of a bare [`Instant`], real enough to order/correlate ring entries
/// against each other and against the periodic publisher's own generation bumps.
fn now_ns() -> u64 {
    let epoch = *TIME_EPOCH.get_or_init(Instant::now);
    u64::try_from(Instant::now().saturating_duration_since(epoch).as_nanos()).unwrap_or(u64::MAX)
}

/// Records one completed `EC_SVC64` dispatch: the per-space table (sub-piece 1), the global
/// syscall-cost histogram, and the structured ring (sub-piece 2). One call site
/// (`HvfBackend::dispatch_monitor_exit`'s `EC_SVC64` arm) times the real `shim.syscall(ctx)`
/// dispatch with `Instant::now()`/`Instant::elapsed()` and calls this exactly once per syscall.
/// `blocked_ns` is the interruptible-wait time banked on this thread during that dispatch (see
/// [`take_blocked_ns`]); `elapsed_ns - blocked_ns` feeds the service-time split.
pub(crate) fn record_syscall_exit(
    space_id: HvfAddressSpaceId,
    nr: i32,
    result: i64,
    elapsed_ns: u64,
    blocked_ns: u64,
) {
    record_space_syscall(space_id, elapsed_ns, blocked_ns);
    if elapsed_ns.saturating_sub(blocked_ns) >= SLOW_SYSCALL_NS {
        record_slow_syscall(space_id, nr, elapsed_ns, blocked_ns);
    }
    if elapsed_ns >= LONG_SYSCALL_NS {
        record_long_syscall(elapsed_ns, blocked_ns);
    }
    let _ = CURRENT_NR.try_with(|cell| cell.set(-1));
    LAST_SYSCALL_NS.with(|last| last.set(Some(elapsed_ns)));
    let slot = RING_CURSOR.fetch_add(1, Ordering::Relaxed) % RING_LEN;
    let lane_tid = thread_id_u64();
    RING_NR[slot].store(i64::from(nr), Ordering::Relaxed);
    RING_RESULT[slot].store(result, Ordering::Relaxed);
    RING_LANE_TID[slot].store(lane_tid, Ordering::Relaxed);
    RING_TS_NS[slot].store(now_ns(), Ordering::Relaxed);
    RING_ELAPSED_NS[slot].store(elapsed_ns, Ordering::Relaxed);
    RING_BLOCKED_NS[slot].store(blocked_ns, Ordering::Relaxed);
}

fn thread_id_u64() -> u64 {
    // `std::thread::ThreadId::as_u64` is still unstable (`thread_id_value`, rust#67939); the
    // real POSIX thread id is a stable, always-available substitute and, unlike an opaque
    // `ThreadId`, is also what a host-side debugger/`sample`(1) capture during the same run
    // would show, so it is directly cross-referenceable.
    // SAFETY: `pthread_self` has no preconditions -- it only reads the calling thread's own
    // identity, valid on every thread including ones HVF/litebox itself spawned.
    (unsafe { libc::pthread_self() }) as u64
}

/// One row per address space that has ever taken an `EC_SVC64` exit: `(space_id, svc_exits,
/// total_ns, max_ns, service_ns, log2_ns_buckets)`.
pub(crate) fn space_syscall_snapshot() -> Vec<(u64, u64, u64, u64, u64, [u64; LATENCY_BUCKETS])> {
    let mut rows = Vec::new();
    for slot in &SPACE_TABLE {
        let tag = slot.tag.load(Ordering::Acquire);
        if tag == 0 {
            continue;
        }
        let buckets = core::array::from_fn(|i| slot.buckets[i].load(Ordering::Relaxed));
        rows.push((
            tag - 1,
            slot.svc_exits.load(Ordering::Relaxed),
            slot.total_ns.load(Ordering::Relaxed),
            slot.max_ns.load(Ordering::Relaxed),
            slot.service_ns.load(Ordering::Relaxed),
            buckets,
        ));
    }
    rows
}

/// One row per live ring entry, oldest-first, `(nr, result, lane_tid, ts_ns, elapsed_ns,
/// blocked_ns)`. `RING_CURSOR` only ever increments (the `% RING_LEN` happens only when
/// indexing, not when storing), so its raw value IS the total write count -- `min(RING_LEN)` of
/// that is exactly how many slots are real rather than still zero-initialized, with no separate
/// "empty" sentinel needed (a real syscall number can legitimately be `0`, e.g. AArch64
/// `io_setup`, so `0` cannot double as one).
pub(crate) fn ring_snapshot() -> Vec<(i64, i64, u64, u64, u64, u64)> {
    let total_writes = RING_CURSOR.load(Ordering::Acquire);
    let live = total_writes.min(RING_LEN);
    let oldest = if total_writes > RING_LEN { total_writes % RING_LEN } else { 0 };
    let mut rows = Vec::with_capacity(live);
    for i in 0..live {
        let idx = (oldest + i) % RING_LEN;
        rows.push((
            RING_NR[idx].load(Ordering::Relaxed),
            RING_RESULT[idx].load(Ordering::Relaxed),
            RING_LANE_TID[idx].load(Ordering::Relaxed),
            RING_TS_NS[idx].load(Ordering::Relaxed),
            RING_ELAPSED_NS[idx].load(Ordering::Relaxed),
            RING_BLOCKED_NS[idx].load(Ordering::Relaxed),
        ));
    }
    rows
}

// ---------------------------------------------------------------------------
// Runner generation + image/runner identity (diagnostics-counter-readout-surface).
// ---------------------------------------------------------------------------

static RUNNER_GENERATION: std::sync::OnceLock<u64> = std::sync::OnceLock::new();

/// A value unique to this one process launch (this process's start time in nanoseconds since
/// the Unix epoch) -- what a witness compares across two counter reads to confirm both came from
/// the same running instance rather than accidentally mixing a stale published file left over
/// from an earlier run at the same path.
pub fn runner_generation() -> u64 {
    *RUNNER_GENERATION.get_or_init(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| u64::try_from(d.as_nanos()).unwrap_or(0))
            .unwrap_or(0)
    })
}

fn fnv1a(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in bytes {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(0x0000_0100_0000_01B3);
    }
    hash
}

/// A cheap proxy hash over a file's own path + byte length + modified time -- deliberately NOT a
/// full cryptographic hash of its content: this runs on every launch, and a guest image tar for
/// a full desktop can run into the gigabytes, so hashing real bytes here would impose a
/// multi-second-to-minutes cost just to publish a diagnostic. Good enough for its one job --
/// telling a witness whether two counter reads came from the same build/image -- not proving
/// tamper-evidence.
fn path_identity_hash(path: &std::path::Path) -> u64 {
    let Ok(meta) = std::fs::metadata(path) else {
        return 0;
    };
    let mut buf = path.to_string_lossy().into_owned().into_bytes();
    buf.extend_from_slice(&meta.len().to_le_bytes());
    if let Ok(modified) = meta.modified()
        && let Ok(since_epoch) = modified.duration_since(std::time::UNIX_EPOCH)
    {
        buf.extend_from_slice(&since_epoch.as_nanos().to_le_bytes());
    }
    fnv1a(&buf)
}

static IMAGE_PATH: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();

/// Records the guest image tar path (the runner's own `--initial-files`), so [`image_hash`] has
/// something to hash. Call once, early in `run()`; a second call is a no-op (first writer wins,
/// matching every other `OnceLock` in this module).
pub fn set_image_path(path: std::path::PathBuf) {
    let _ = IMAGE_PATH.set(path);
}

pub fn image_hash() -> u64 {
    IMAGE_PATH.get().map(|p| path_identity_hash(p)).unwrap_or(0)
}

pub fn runner_hash() -> u64 {
    static CACHE: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *CACHE.get_or_init(|| {
        std::env::current_exe().map(|p| path_identity_hash(&p)).unwrap_or(0)
    })
}

/// `litebox_shim_linux::LinuxShim::task_diagnostics_json`, wired in once by the runner (see
/// [`register_shim_task_diagnostics`]) -- read fresh on every [`full_snapshot_json`] call, never
/// cached, so this stays current rather than a registration-time snapshot. `None` until that
/// first registration (or for any future non-shim caller of this crate).
static SHIM_TASK_DIAGNOSTICS: std::sync::OnceLock<Box<dyn Fn() -> String + Send + Sync>> =
    std::sync::OnceLock::new();

/// Wires in `litebox_shim_linux`'s own diagnostics (peak tasks/threads,
/// desktop-peak-task-count-witness) without this crate ever depending on that one (which, the
/// other way around, already depends on this crate -- see [`SHIM_TASK_DIAGNOSTICS`]'s own doc
/// comment). Call once, right after the shim is built; a second call is a no-op (first writer
/// wins, matching every other `OnceLock` in this module).
pub fn register_shim_task_diagnostics(f: impl Fn() -> String + Send + Sync + 'static) {
    let _ = SHIM_TASK_DIAGNOSTICS.set(Box::new(f));
}

/// The concrete guest-visible provider: `litebox_runner_linux_on_macos_userland` registers one
/// of these through `shim.proc_handle().set_counters(...)` at startup so
/// `/proc/litebox/counters` renders [`full_snapshot_json`] on every read.
#[derive(Default)]
pub struct GuestCountersProvider;

impl litebox::fs::proc::ProcCounters for GuestCountersProvider {
    fn snapshot_json(&self) -> String {
        full_snapshot_json()
    }
}

// ---------------------------------------------------------------------------
// JSON assembly (diagnostics-counter-readout-surface).
// ---------------------------------------------------------------------------

fn push_buckets(out: &mut String, buckets: &[u64]) {
    out.push('[');
    for (i, b) in buckets.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        let _ = std::fmt::Write::write_fmt(out, format_args!("{b}"));
    }
    out.push(']');
}

/// One versioned, generation-stamped JSON snapshot of every counter and ring head this crate
/// exposes: the pre-existing `HvfExceptionCountersSnapshot`/`HvfLifecycleResidualSnapshot` (via
/// `crate::hvf_backend::active()`, when an HVF backend has actually been installed in this
/// process) plus the per-space syscall table, the syscall ring, and the global syscall
/// histogram this module owns. This is the one function
/// `litebox_runner_linux_on_macos_userland` calls both for its periodic mmap-file publisher and
/// for `litebox::fs::proc::register_counters_provider` (the guest-visible
/// `/proc/litebox/counters` surface) -- both readers see exactly the same bytes.
pub fn full_snapshot_json() -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(4096);
    out.push('{');
    let _ = write!(out, "\"surface_version\":1,");
    // desktop-peak-task-count-witness: see `SHIM_TASK_DIAGNOSTICS`'s own doc comment. `null`
    // when no shim handle was ever wired in (e.g. a future non-shim caller of this function).
    match SHIM_TASK_DIAGNOSTICS.get() {
        Some(f) => {
            let _ = write!(out, "\"shim_task_diagnostics\":{},", f());
        }
        None => {
            let _ = write!(out, "\"shim_task_diagnostics\":null,");
        }
    }
    let _ = write!(out, "\"runner_generation\":{},", runner_generation());
    let _ = write!(out, "\"runner_hash\":{},", runner_hash());
    let _ = write!(out, "\"image_hash\":{},", image_hash());
    let _ = write!(
        out,
        "\"snapshot_wall_ns\":{},",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    );

    if let Some(backend) = crate::hvf_backend::active() {
        let e = backend.exception_counters_snapshot();
        let l = backend.lifecycle_residual_snapshot();
        let _ = write!(
            out,
            concat!(
                "\"hvf_exception_counters\":{{",
                "\"raw_exception_exits\":{},\"stale_view_reruns\":{},",
                "\"wx_service_requests\":{},\"wx_service_settled\":{},",
                "\"wx_service_refaulted\":{},\"wx_alias_conflict_refusals\":{},",
                "\"guest_faults_serviced\":{},\"guest_faults_delivered\":{},",
                "\"fatal_faults\":{},\"in_flight\":{},\"generation\":{},",
                "\"quarantine_pump_runs\":{},\"quarantine_pump_reclaimed\":{},",
                "\"quarantine_permanent_failures\":{},",
                "\"wx_service_latency_count\":{},\"wx_service_latency_sum_ns\":{},",
                "\"wx_service_latency_max_ns\":{},\"wx_service_latency_buckets\":"
            ),
            e.raw_exception_exits,
            e.stale_view_reruns,
            e.wx_service_requests,
            e.wx_service_settled,
            e.wx_service_refaulted,
            e.wx_alias_conflict_refusals,
            e.guest_faults_serviced,
            e.guest_faults_delivered,
            e.fatal_faults,
            e.in_flight,
            e.generation,
            e.quarantine_pump_runs,
            e.quarantine_pump_reclaimed,
            e.quarantine_permanent_failures,
            e.wx_service_latency_count,
            e.wx_service_latency_sum_ns,
            e.wx_service_latency_max_ns,
        );
        push_buckets(&mut out, &e.wx_service_latency_buckets);
        out.push('}');
        out.push(',');

        let _ = write!(
            out,
            concat!(
                "\"hvf_lifecycle_residual\":{{",
                "\"active_lanes\":{},\"custodial_lanes\":{},\"retired_generations\":{},",
                "\"address_spaces\":{},\"host_slots\":{},\"backing_objects\":{},",
                "\"alias_quarantine_reservations\":{},\"data_quarantine_reservations\":{},",
                "\"quarantined_resources\":{},\"page_settlement_rows_pending\":{},",
                "\"pinned_shared_backings\":{},\"claimed_pages\":{},\"live_data_pages\":{}}},"
            ),
            l.active_lanes,
            l.custodial_lanes,
            l.retired_generations,
            l.address_spaces,
            l.host_slots,
            l.backing_objects,
            l.alias_quarantine_reservations,
            l.data_quarantine_reservations,
            l.quarantined_resources,
            l.page_settlement_rows_pending,
            l.pinned_shared_backings,
            l.claimed_pages,
            l.live_data_pages,
        );
        let _ = write!(out, "\"hvf_file_cow\":{},", backend.file_cow_counters_json());
    } else {
        let _ = write!(
            out,
            "\"hvf_exception_counters\":null,\"hvf_lifecycle_residual\":null,\"hvf_file_cow\":null,"
        );
    }

    let _ = write!(
        out,
        concat!(
            "\"syscall_global\":{{\"svc_exits\":{},\"total_ns\":{},\"max_ns\":{},\"buckets\":"
        ),
        GLOBAL_SVC_EXITS.load(Ordering::Relaxed),
        GLOBAL_SVC_TOTAL_NS.load(Ordering::Relaxed),
        GLOBAL_SVC_MAX_NS.load(Ordering::Relaxed),
    );
    let global_buckets: [u64; LATENCY_BUCKETS] =
        core::array::from_fn(|i| GLOBAL_SVC_BUCKETS[i].load(Ordering::Relaxed));
    push_buckets(&mut out, &global_buckets);
    out.push('}');
    out.push(',');

    // k2p-exit-handoff-lane-wait-counters: the lane-wait and exit-to-reentry handoff cost that
    // `syscall_global` (shim dispatch only) leaves out -- see `LANE_WAIT`/`HANDOFF`'s own docs.
    let (count, sum_ns, max_ns, buckets) = LANE_WAIT.snapshot();
    let _ = write!(
        out,
        "\"lane_wait\":{{\"count\":{},\"sum_ns\":{},\"max_ns\":{},\"buckets\":",
        count, sum_ns, max_ns,
    );
    push_buckets(&mut out, &buckets);
    out.push_str("},");
    let (count, sum_ns, max_ns, buckets) = HANDOFF.snapshot();
    let _ = write!(
        out,
        concat!(
            "\"handoff\":{{\"count\":{},\"sum_ns\":{},\"max_ns\":{},",
            "\"channel_sum_ns\":{},\"owner_sum_ns\":{},\"guest_run_wall_sum_ns\":{},",
            "\"sync_trips\":{},\"buckets\":"
        ),
        count,
        sum_ns,
        max_ns,
        HANDOFF_CHANNEL_NS.load(Ordering::Relaxed),
        HANDOFF_OWNER_NS.load(Ordering::Relaxed),
        GUEST_RUN_WALL_NS.load(Ordering::Relaxed),
        SYNC_TRIPS.load(Ordering::Relaxed),
    );
    push_buckets(&mut out, &buckets);
    out.push_str("},");

    // hvf-exit-overhead-instrumentation: the remaining exit-path costs (see each static's doc).
    let (count, sum_ns, max_ns, buckets) = EXIT_OVERHEAD.snapshot();
    let _ = write!(
        out,
        concat!(
            "\"exit_overhead\":{{\"count\":{},\"sum_ns\":{},\"max_ns\":{},",
            "\"nonsyscall_iterations\":{},\"nonsyscall_sum_ns\":{},\"buckets\":"
        ),
        count,
        sum_ns,
        max_ns,
        NONSYSCALL_ITERATIONS.load(Ordering::Relaxed),
        NONSYSCALL_ITERATION_NS.load(Ordering::Relaxed),
    );
    push_buckets(&mut out, &buckets);
    out.push_str("},");
    let (count, sum_ns, max_ns, buckets) = LANE_MIGRATION.snapshot();
    let _ = write!(
        out,
        "\"lane_migration\":{{\"count\":{},\"sum_ns\":{},\"max_ns\":{},\"buckets\":",
        count, sum_ns, max_ns,
    );
    push_buckets(&mut out, &buckets);
    out.push_str("},");
    let _ = write!(
        out,
        concat!(
            "\"lane_kicks\":{{\"rounds\":{},\"requests\":{},\"idle\":{},\"errors\":{},",
            "\"issued\":{},\"latched\":{},\"canceled_exits\":{},\"canceled_interrupts\":{},",
            "\"canceled_monitor_exits\":{},\"canceled_latched\":{}}},"
        ),
        KICK_ROUNDS.load(Ordering::Relaxed),
        KICK_REQUESTS.load(Ordering::Relaxed),
        KICK_IDLE.load(Ordering::Relaxed),
        KICK_ERRORS.load(Ordering::Relaxed),
        KICKS_ISSUED.load(Ordering::Relaxed),
        KICKS_LATCHED.load(Ordering::Relaxed),
        CANCELED_EXITS.load(Ordering::Relaxed),
        CANCELED_INTERRUPTS.load(Ordering::Relaxed),
        CANCELED_MONITOR_EXITS.load(Ordering::Relaxed),
        CANCELED_LATCHED.load(Ordering::Relaxed),
    );
    let (count, sum_ns, max_ns, buckets) = SYSCALL_SERVICE.snapshot();
    let _ = write!(
        out,
        concat!(
            "\"syscall_service\":{{\"count\":{},\"sum_ns\":{},\"max_ns\":{},",
            "\"blocked_sum_ns\":{},\"blocked_syscalls\":{},\"buckets\":"
        ),
        count,
        sum_ns,
        max_ns,
        SYSCALL_BLOCKED_NS.load(Ordering::Relaxed),
        SYSCALL_BLOCKED_COUNT.load(Ordering::Relaxed),
    );
    push_buckets(&mut out, &buckets);
    out.push_str("},");
    render_retirement_pump(&mut out);
    render_slow_syscalls(&mut out);
    render_lock_attribution(&mut out);
    render_resident_state(&mut out);
    render_instrumentation(&mut out);

    let _ = write!(
        out,
        "\"space_table_overflows\":{},",
        SPACE_TABLE_OVERFLOWS.load(Ordering::Relaxed)
    );

    out.push_str("\"per_space_syscalls\":[");
    for (i, (space_id, svc_exits, total_ns, max_ns, service_ns, buckets)) in
        space_syscall_snapshot().into_iter().enumerate()
    {
        if i > 0 {
            out.push(',');
        }
        let _ = write!(
            out,
            "{{\"space_id\":{space_id},\"svc_exits\":{svc_exits},\"total_ns\":{total_ns},\"max_ns\":{max_ns},\"service_ns\":{service_ns},\"buckets\":"
        );
        push_buckets(&mut out, &buckets);
        out.push('}');
    }
    out.push_str("],");

    out.push_str("\"syscall_ring\":[");
    for (i, (nr, result, lane_tid, ts_ns, elapsed_ns, blocked_ns)) in
        ring_snapshot().into_iter().enumerate()
    {
        if i > 0 {
            out.push(',');
        }
        let _ = write!(
            out,
            "{{\"nr\":{nr},\"result\":{result},\"lane_tid\":{lane_tid},\"ts_ns\":{ts_ns},\"elapsed_ns\":{elapsed_ns},\"blocked_ns\":{blocked_ns}}}"
        );
    }
    out.push(']');

    out.push('}');
    out
}
