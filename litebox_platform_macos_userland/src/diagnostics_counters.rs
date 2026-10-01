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
use std::mem::ManuallyDrop;
use std::sync::{Condvar, Mutex, MutexGuard, OnceLock, PoisonError, RwLock, TryLockError};
use std::time::Duration;
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
    /// Step G: this space's runnable-not-running intervals -- count, sum, max and log2 buckets --
    /// plus the per-span split of the intervals long enough to have one, the foreign pump work
    /// charged in those iterations, and the pid / `comm` of the last guest thread that recorded
    /// here (the space -> process name mapping every other row of the inventory needed).
    rbnr_count: AtomicU64,
    rbnr_sum_ns: AtomicU64,
    rbnr_max_ns: AtomicU64,
    rbnr_buckets: [AtomicU64; LATENCY_BUCKETS],
    rbnr_spans: [AtomicU64; RBNR_SPANS],
    /// The same intervals credited whole to their dominant span: an overlap-free share.
    rbnr_dom_ns: [AtomicU64; RBNR_SPANS],
    rbnr_pump_ns: AtomicU64,
    pid: AtomicU64,
    comm: [AtomicU64; 2],
    /// T1f-a: this space's settled mutations (every `settle_mutation` call, whatever its outcome)
    /// and committed root generations (one per `commit_retirement`). Paired with `svc_exits`, the
    /// ratio is the "how much VM mutation does one guest syscall cost" question this step exists
    /// to answer per process, not just globally.
    mutations: AtomicU64,
    root_generations: AtomicU64,
    /// T1f-a: faults serviced for this space, and of those, the ones whose page sits within
    /// [`FAULT_ADJACENT_PAGES`] of this space's own immediately preceding fault within
    /// [`FAULT_ADJACENT_TICKS`] -- the fault-around opportunity (F1/F2/F3).
    faults: AtomicU64,
    faults_adjacent: AtomicU64,
    /// The last faulted page of this space + 1 (`0` = none yet) and the tick it was recorded at.
    fault_last_page: AtomicU64,
    fault_last_ticks: AtomicU64,
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
            rbnr_count: AtomicU64::new(0),
            rbnr_sum_ns: AtomicU64::new(0),
            rbnr_max_ns: AtomicU64::new(0),
            rbnr_buckets: zeroed_u64_array(),
            rbnr_spans: zeroed_u64_array(),
            rbnr_dom_ns: zeroed_u64_array(),
            rbnr_pump_ns: AtomicU64::new(0),
            pid: AtomicU64::new(0),
            comm: [AtomicU64::new(0), AtomicU64::new(0)],
            mutations: AtomicU64::new(0),
            root_generations: AtomicU64::new(0),
            faults: AtomicU64::new(0),
            faults_adjacent: AtomicU64::new(0),
            fault_last_page: AtomicU64::new(0),
            fault_last_ticks: AtomicU64::new(0),
        }
    }
}

static SPACE_TABLE: [SpaceSlot; SPACE_TABLE_LEN] = {
    const SLOT: SpaceSlot = SpaceSlot::new();
    [SLOT; SPACE_TABLE_LEN]
};

/// Diagnostic samples dropped because [`SPACE_TABLE`] was completely full -- every slot already
/// claimed by a space that has not been released. Counted so an operator can tell whether the
/// table ever saturated rather than the readout silently under-reporting. Step G fix-up: it does
/// saturate unless [`space_slot_release`] runs on destroy, because a claimed tag used to be
/// permanent -- see [`SPACE_SLOT_RELEASES`].
static SPACE_TABLE_OVERFLOWS: AtomicU64 = AtomicU64::new(0);
/// Slots handed back by [`space_slot_release`] when their address space was destroyed. Without
/// this the table filled after the first `SPACE_TABLE_LEN` address spaces that ever existed: one
/// 10-minute desktop drive mints hundreds of them (ids past 900 were observed), and 84.8 M of
/// 89.1 M slot lookups on that run failed with every later space left without a per-space row.
static SPACE_SLOT_RELEASES: AtomicU64 = AtomicU64::new(0);

static GLOBAL_SVC_EXITS: AtomicU64 = AtomicU64::new(0);
static GLOBAL_SVC_TOTAL_NS: AtomicU64 = AtomicU64::new(0);
static GLOBAL_SVC_MAX_NS: AtomicU64 = AtomicU64::new(0);
static GLOBAL_SVC_BUCKETS: [AtomicU64; LATENCY_BUCKETS] = zeroed_u64_array();

/// The [`SPACE_TABLE`] slot for `tag` (`space_id.value() + 1`), claiming an empty one with a
/// single `compare_exchange` the first time this space records anything. `None` only when the
/// table is somehow completely full -- shared by [`record_space_syscall`] and [`rbnr_record`],
/// which must land on the same row for the same space.
fn space_slot(tag: u64) -> Option<&'static SpaceSlot> {
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
            return Some(slot);
        }
    }
    SPACE_TABLE_OVERFLOWS.fetch_add(1, Ordering::Relaxed);
    None
}

/// Zeroes every counter in `slot` so the next space to claim it starts from a clean row instead
/// of inheriting a destroyed space's totals. Only ever called with the slot owned by the caller
/// (immediately before its tag is released, i.e. after no live space can be recording into it).
fn reset_space_slot(slot: &SpaceSlot) {
    slot.svc_exits.store(0, Ordering::Relaxed);
    slot.total_ns.store(0, Ordering::Relaxed);
    slot.max_ns.store(0, Ordering::Relaxed);
    slot.service_ns.store(0, Ordering::Relaxed);
    for bucket in &slot.buckets {
        bucket.store(0, Ordering::Relaxed);
    }
    slot.rbnr_count.store(0, Ordering::Relaxed);
    slot.rbnr_sum_ns.store(0, Ordering::Relaxed);
    slot.rbnr_max_ns.store(0, Ordering::Relaxed);
    for bucket in &slot.rbnr_buckets {
        bucket.store(0, Ordering::Relaxed);
    }
    for cell in &slot.rbnr_spans {
        cell.store(0, Ordering::Relaxed);
    }
    for cell in &slot.rbnr_dom_ns {
        cell.store(0, Ordering::Relaxed);
    }
    slot.rbnr_pump_ns.store(0, Ordering::Relaxed);
    slot.pid.store(0, Ordering::Relaxed);
    for cell in &slot.comm {
        cell.store(0, Ordering::Relaxed);
    }
    slot.mutations.store(0, Ordering::Relaxed);
    slot.root_generations.store(0, Ordering::Relaxed);
    slot.faults.store(0, Ordering::Relaxed);
    slot.faults_adjacent.store(0, Ordering::Relaxed);
    slot.fault_last_page.store(0, Ordering::Relaxed);
    slot.fault_last_ticks.store(0, Ordering::Relaxed);
}

/// Hands the [`SPACE_TABLE`] slot of a destroyed address space back to the free pool. Called from
/// `HvfAddressSpace::destroy` once the destroy has committed; a slot is only ever released by the
/// space that owns it, and the counters are zeroed first so the next claimer cannot inherit them.
pub(crate) fn space_slot_release(space_id: HvfAddressSpaceId) {
    let tag = space_id.value().wrapping_add(1);
    let start = (tag.wrapping_mul(0x9E37_79B9_7F4A_7C15) as usize) % SPACE_TABLE_LEN;
    for offset in 0..SPACE_TABLE_LEN {
        let slot = &SPACE_TABLE[(start + offset) % SPACE_TABLE_LEN];
        if slot.tag.load(Ordering::Acquire) != tag {
            continue;
        }
        reset_space_slot(slot);
        if slot
            .tag
            .compare_exchange(tag, 0, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            SPACE_SLOT_RELEASES.fetch_add(1, Ordering::Relaxed);
        }
        return;
    }
}

thread_local! {
    /// Step G fix-up: the [`SPACE_TABLE`] slot this host thread resolved for the address space it
    /// is currently running, with that space's tag (`u64::MAX` = nothing cached). A guest host
    /// thread runs one guest thread at a time, so the steady-state lookup is one relaxed load of
    /// the cached slot's tag instead of an open-addressing walk -- and the walk was not just slow
    /// but failing outright once the table saturated.
    static SPACE_SLOT_CACHE: Cell<(u64, Option<&'static SpaceSlot>)> =
        const { Cell::new((u64::MAX, None)) };
}

/// [`space_slot`] through the per-thread cache: one relaxed load when this thread is still on the
/// same space, a full probe when it is not (or when the cached slot was released and re-claimed by
/// a later space, which the tag re-check catches).
fn cached_space_slot(tag: u64) -> Option<&'static SpaceSlot> {
    let cached = SPACE_SLOT_CACHE
        .try_with(|cell| {
            let (cached_tag, slot) = cell.get();
            if cached_tag == tag
                && let Some(slot) = slot
                && slot.tag.load(Ordering::Acquire) == tag
            {
                return Some(slot);
            }
            let resolved = space_slot(tag);
            cell.set((tag, resolved));
            resolved
        })
        .ok();
    match cached {
        Some(slot) => slot,
        // A host thread with no thread-local storage left (teardown): fall back to the probe.
        None => space_slot(tag),
    }
}

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
    let Some(slot) = cached_space_slot(tag) else {
        return;
    };
    slot.svc_exits.fetch_add(1, Ordering::Relaxed);
    slot.total_ns.fetch_add(elapsed_ns, Ordering::Relaxed);
    slot.max_ns.fetch_max(elapsed_ns, Ordering::Relaxed);
    slot.service_ns.fetch_add(service_ns, Ordering::Relaxed);
    slot.buckets[latency_bucket_index(elapsed_ns)].fetch_add(1, Ordering::Relaxed);
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

    /// A whole batch of samples at once: the same four histograms updated with `count` samples
    /// whose sum is `sum_ns`, whose largest is `max_ns` and whose bucket counts are `buckets`.
    /// Step G fix-up: lets a per-iteration measurement accumulate on its own thread and touch
    /// these shared lines once per [`RBNR_FLUSH_INTERVALS`] intervals instead of once per
    /// interval -- 8 contended relaxed RMWs per guest iteration measured 0.3-1.2 us.
    fn record_bulk(&self, count: u64, sum_ns: u64, max_ns: u64, buckets: &[u64; LATENCY_BUCKETS]) {
        self.count.fetch_add(count, Ordering::Relaxed);
        self.sum_ns.fetch_add(sum_ns, Ordering::Relaxed);
        self.max_ns.fetch_max(max_ns, Ordering::Relaxed);
        for (index, ns) in buckets.iter().enumerate() {
            if *ns != 0 {
                self.buckets[index].fetch_add(*ns, Ordering::Relaxed);
            }
        }
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
/// T1b (hvf-kick-only-lanes-in-mutated-space): rounds split into `scoped` (a mutated address
/// space was named, so only its participants are asked) and `global` (the lane-pool failure path,
/// which has no single space to scope to). `considered` counts the lanes and bound vCPUs that
/// passed the scope filter -- one `requests` each -- and `skipped_other_space` those the filter
/// dropped because they are participants of a different space. Identity, exact per round:
/// `requests == considered` and `requests + skipped_other_space == live lanes + bound vCPUs`.
/// `requests / rounds` is the fan-out a mutation costs: 11 before T1b, the mutated space's
/// in-flight lane count after it.
static KICK_SCOPED_ROUNDS: AtomicU64 = AtomicU64::new(0);
static KICK_GLOBAL_ROUNDS: AtomicU64 = AtomicU64::new(0);
static KICK_CONSIDERED: AtomicU64 = AtomicU64::new(0);
static KICK_SKIPPED_OTHER_SPACE: AtomicU64 = AtomicU64::new(0);
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
/// Shim service time per delivered exception: wall time of one `shim.exception(ctx, &info)` call
/// on the guest thread (page-fault service or real signal delivery, including the signal-frame
/// write). One sample per call; the three call sites are the direct-guest `BRK` arm, the
/// direct-guest abort arm and the monitor-exception arm of `HvfBackend`'s exit dispatch. This is
/// the figure the syscall histograms cannot see, and the one T1e's lazy formatting moves.
static EXCEPTION_SERVICE: CostHistogram = CostHistogram::new();
/// Sum of blocked nanoseconds over all syscalls and the number of syscalls that blocked at all
/// (`syscall_global.total_ns - SYSCALL_BLOCKED_NS == SYSCALL_SERVICE.sum_ns`, up to saturation).
static SYSCALL_BLOCKED_NS: AtomicU64 = AtomicU64::new(0);
static SYSCALL_BLOCKED_COUNT: AtomicU64 = AtomicU64::new(0);

pub(crate) fn record_exception_service(ns: u64) {
    EXCEPTION_SERVICE.record(ns);
}

thread_local! {
    /// Blocked-time accounting for the current host thread: the `Instant` at which its current
    /// interruptible wait began (`WaitContext::start_wait` -> `RawMutexProvider::update_waker`
    /// with `Some`), and the nanoseconds accumulated over completed waits since the last
    /// [`take_blocked_ns`]. A guest thread's syscalls run on its own host thread, so a per-thread
    /// cell IS a per-task cell here, with no lock and no task lookup.
    static WAIT_START: Cell<Option<Instant>> = const { Cell::new(None) };
    static BLOCKED_NS: Cell<u64> = const { Cell::new(0) };
    /// Step G: whether this host thread is inside an interruptible guest-condition wait right now
    /// (as opposed to parked on the same primitive for the shim's own service locks), which is
    /// what tells `RawMutex::block_inner` that a wake is a runnable-not-running transition.
    static WAIT_ACTIVE: Cell<bool> = const { Cell::new(false) };
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
    WAIT_ACTIVE.with(|active| active.set(true));
}

/// Whether this host thread is currently inside an interruptible guest-condition wait (see
/// [`WAIT_ACTIVE`]).
pub(crate) fn in_interruptible_wait() -> bool {
    WAIT_ACTIVE.try_with(Cell::get).unwrap_or(false)
}

/// `RawMutexProvider::update_waker(None)` on this thread: the wait ended; bank its wall time.
pub(crate) fn wait_ended() {
    WAIT_ACTIVE.with(|active| active.set(false));
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

/// T1b: `scoped` = the round was restricted to one mutated address space, `global` = VM-wide.
pub(crate) fn record_kick_round_scope(scoped: bool) {
    if scoped {
        KICK_SCOPED_ROUNDS.fetch_add(1, Ordering::Relaxed);
    } else {
        KICK_GLOBAL_ROUNDS.fetch_add(1, Ordering::Relaxed);
    }
}

/// T1b: one lane or bound vCPU that passed the space filter and is about to be asked.
pub(crate) fn record_kick_considered() {
    KICK_CONSIDERED.fetch_add(1, Ordering::Relaxed);
}

/// T1b: one lane or bound vCPU dropped by the space filter (a participant of another space).
pub(crate) fn record_kick_skip_other_space() {
    KICK_SKIPPED_OTHER_SPACE.fetch_add(1, Ordering::Relaxed);
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

static BARRIER_HOLD_TIMEOUTS: AtomicU64 = AtomicU64::new(0);

/// T2d fix-up: the in-admission run-completion barrier hold hit its deadline and released the
/// owner rather than parking it inside the run scope. Diagnostic-only; `0` in ordinary runs.
pub(crate) fn record_barrier_hold_timeout() {
    BARRIER_HOLD_TIMEOUTS.fetch_add(1, Ordering::Relaxed);
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
// Runnable-not-running (RBNR) accounting -- step G of
// `hvf-guest-runnable-not-running-guard-and-class-fix`.
//
// A guest thread is *runnable* from the moment it is woken / its wait times out / its exit is
// serviced, and *running* from the moment `run_thread` hands it to the vCPU. Everything in
// between is invisible to every per-syscall counter this module already keeps (those measure
// either the shim's service or the lane handoff), and it is exactly where the desktop
// input-consumer-lag class lives: an Xorg / xfwm4 / xfce4-panel / Chromium UI thread that was
// made runnable by an input event and then sat in a lane queue, behind the exclusive VM gate,
// parked at a sibling's fork gate, or simply waiting for the host kernel to schedule it.
//
// Two stamps bracket the interval, both host ticks:
//   * ready_at    -- set where the thread becomes runnable: `RawMutex::block_inner` returning
//                    from a wait (woken: the tick the waker stored; timed out: the deadline),
//                    the end of a `run_thread` iteration whose dispatch did not wait, and
//                    `run_thread` entry (thread start).
//   * running_at  -- `run_thread`'s `GUEST_PRE_EXECUTE` mark, just before the vCPU is entered.
// Between them the interval is split into named spans: the six shim-side waits reported through
// `Provider::note_rbnr_wait` (W1..W6), the iteration's own lane wait / view attach / attach
// spans (R1..R3), the service-lock and exclusive-gate time this thread paid (R5, R6, from
// `ThreadWork`, which already accumulates them per thread), the shim's tail after `ready_at`,
// and whatever is left as `unattributed`. The pump (R4) is foreign work the thread pays in the
// same iteration but *after* `running_at`, so it is reported next to the interval, not inside it.
//
// R5 and R6 are each published as their own terms rather than one sum, because the sum mixes
// blocking with working: `r6_excl_hold` is this thread *doing* an exclusive VM operation (real
// work every other lane is waiting for), while `r6_excl_wait` and `r6_gate_mutex_wait` are it
// queueing for one. Collapsed into a single 52.6 % row, STEP F could not tell which half to aim
// at. The three `r6_*` rows sum to the old `r6_exclusive_gate`, the three `r5_*` rows to the old
// `r5_service_locks`.
//
// The spans are NOT a partition of the interval and their sum is not the interval: `r6` is mostly
// *inside* `r2` (view attach / lane migration takes the exclusive gate), so `sum(spans)` over-covers
// `sum(rbnr_ns)` by ~1.9x on a real desktop run. `unattributed = rbnr_ns - named` therefore
// saturates at 0 and is only a *one-sided* check: nonzero means an interval no named span covers
// (a new blocking point), while 0 means "covered", not "measured exactly". Both sides are
// published -- `named_sum_ns` and `credited_ns` -- so the over-cover factor is visible.
//
// Cost: ONE tick read and a thread-local accumulation per iteration on the ordinary path. Step G
// fix-up: the global histogram, the per-space slot and the pid/comm publish used to run per
// iteration *before* the `RBNR_RING_MIN_NS` early return (8 contended relaxed RMWs on lines the
// guest host thread shares with the vCPU owner thread, plus an open-addressing probe that walked
// all 320 slots once the table saturated) and cost 0.3-1.2 us per guest syscall under an
// order-balanced paired measurement. They now run once per [`RBNR_FLUSH_INTERVALS`] intervals.
// The span vector, the per-space span sums and the ring entry are still only built for an interval
// at or over [`RBNR_RING_MIN_NS`].
// ---------------------------------------------------------------------------

/// Below this, an interval is not worth a span vector: it is inside the noise of the two clock
/// reads themselves, and a desktop at 15 us/exit produces millions of them per minute.
const RBNR_RING_MIN_NS: u64 = 1_000_000;
/// One RBNR over this is a stall a user could see (xfwm4's own double-click constant is 250 ms);
/// log the dominant span, rate-limited to one line per [`RBNR_WARN_INTERVAL_MS`].
const RBNR_WARN_NS: u64 = 100_000_000;
const RBNR_WARN_INTERVAL_MS: u64 = 2_000;
/// An input event that took longer than this to be read by a guest consumer is a stall; the same
/// 250 ms X constant.
const INPUT_CONSUME_WARN_NS: u64 = 250_000_000;

pub(crate) const RBNR_W_HOST_WAKE: usize = 0;
pub(crate) const RBNR_W_FORK_GATE: usize = 1;
pub(crate) const RBNR_W_AS_HANDOFF: usize = 2;
pub(crate) const RBNR_W_AS_ACQUIRE: usize = 3;
pub(crate) const RBNR_W_PTRACE: usize = 4;
pub(crate) const RBNR_W_SIGNAL_FRAME: usize = 5;
pub(crate) const RBNR_R1_LANE_WAIT: usize = 6;
pub(crate) const RBNR_R2_VIEW_ATTACH: usize = 7;
pub(crate) const RBNR_R3_ATTACH: usize = 8;
/// R5's three terms, published apart: contended waits for litebox's mapping lock
/// (`PageManager`'s `vmem`), for an address space's `cell.state` mutex, and for every other
/// instrumented service lock (ledger / pump / EffectGate).
pub(crate) const RBNR_R5_VMEM_WAIT: usize = 9;
pub(crate) const RBNR_R5_CELL_WAIT: usize = 10;
pub(crate) const RBNR_R5_LOCK_WAIT: usize = 11;
/// R6's three terms, published apart: queueing to be ADMITTED to the exclusive VM operation
/// (blocking), HOLDING it (work, and what every other lane queues behind), and waiting for the
/// gate mutex itself.
pub(crate) const RBNR_R6_EXCL_WAIT: usize = 12;
pub(crate) const RBNR_R6_EXCL_HOLD: usize = 13;
pub(crate) const RBNR_R6_GATE_MUTEX_WAIT: usize = 14;
/// The part of the previous iteration that ran after `ready_at` and is not one of W1..W6: the
/// shim finishing the syscall that woke this thread, the guest register write-back, and any
/// dispatch bookkeeping.
pub(crate) const RBNR_SHIM_TAIL: usize = 15;
/// The iteration's own un-named head spans: run reservation, per-view space lookup and the
/// architectural-state build.
pub(crate) const RBNR_LOOP_OTHER: usize = 16;
/// RBNR minus every named span: what this guard cannot yet see -- see the module comment for why
/// this is a one-sided check (the named spans over-cover the interval).
pub(crate) const RBNR_UNATTRIBUTED: usize = 17;
const RBNR_SPANS: usize = 18;
const RBNR_SPAN_NAMES: [&str; RBNR_SPANS] = [
    "w1_host_wake",
    "w2_fork_gate",
    "w3_as_handoff",
    "w4_as_acquire",
    "w5_ptrace",
    "w6_signal_frame",
    "r1_lane_wait",
    "r2_view_attach",
    "r3_attach_handoff",
    "r5_vmem_wait",
    "r5_cell_wait",
    "r5_lock_wait",
    "r6_excl_wait",
    "r6_excl_hold",
    "r6_gate_mutex_wait",
    "shim_tail",
    "loop_other",
    "unattributed",
];

/// Intervals batched on one host thread before they are folded into [`RBNR`] and the space's row.
/// The batch is the fix for the guard's measured hot-path cost: at 512, a 15 us desktop iteration
/// touches the shared lines once every ~8 ms of wall time instead of once per iteration.
const RBNR_FLUSH_INTERVALS: u64 = 512;

#[derive(Clone, Copy)]
struct RbnrBatch {
    /// The address space the batched intervals belong to (`u64::MAX` = the batch is empty). A
    /// batch is flushed before it takes a sample from a different space, so every sample in it
    /// belongs to the same row.
    space_id: u64,
    count: u64,
    sum_ns: u64,
    max_ns: u64,
    buckets: [u64; LATENCY_BUCKETS],
}

impl RbnrBatch {
    const EMPTY: Self = Self {
        space_id: u64::MAX,
        count: 0,
        sum_ns: 0,
        max_ns: 0,
        buckets: [0; LATENCY_BUCKETS],
    };
}

static RBNR: CostHistogram = CostHistogram::new();
/// Intervals at or over [`RBNR_WARN_NS`], and how many of those went unlogged by the rate limit.
static RBNR_WARNED: AtomicU64 = AtomicU64::new(0);
static RBNR_WARNS_SUPPRESSED: AtomicU64 = AtomicU64::new(0);
static RBNR_LAST_WARN_MS: AtomicU64 = AtomicU64::new(0);
/// Per-space totals: `rbnr_spans[i]` is the nanoseconds of span `i` over this space's intervals.
static RBNR_SPAN_TOTALS: [AtomicU64; RBNR_SPANS] = zeroed_u64_array();
/// The overlap-free share: every interval at or over [`RBNR_RING_MIN_NS`] is credited WHOLE to its
/// dominant span (the largest one). The per-span totals above are not additive -- `r6` (the
/// exclusive VM gate) is mostly *inside* `r2` (view attach / lane migration), which is itself how
/// the sample's 4.3 thread-s/s of migration gate wait shows up -- so `sum(rbnr_dominant_ns) ==
/// sum(rbnr_ns over the same intervals)` is the identity that makes the shares meaningful.
static RBNR_DOMINANT_NS: [AtomicU64; RBNR_SPANS] = zeroed_u64_array();
static RBNR_DOMINANT_COUNT: [AtomicU64; RBNR_SPANS] = zeroed_u64_array();
/// Foreign retirement-pump work charged to a thread in the same iteration (R4), summed over the
/// intervals that were long enough to get a span vector.
static RBNR_PUMP_NS: AtomicU64 = AtomicU64::new(0);
/// Attribution health, the two sides that `unattributed`'s saturating subtraction hides: the sum
/// of the named spans over the intervals that got a span vector, the intervals' own total, and
/// `named - credited` when the spans over-cover (which they do, by ~1.9x: `r6` is inside `r2`).
/// `unattributed_ns > 0` remains the "a blocking point this guard cannot see" signal;
/// `named_sum_ns / credited_ns` is the overlap factor a reader needs to read the span table.
static RBNR_NAMED_SUM_NS: AtomicU64 = AtomicU64::new(0);
static RBNR_CREDITED_NS: AtomicU64 = AtomicU64::new(0);
static RBNR_OVER_COVER_NS: AtomicU64 = AtomicU64::new(0);

const RBNR_RING_LEN: usize = 16;
/// One ring row: `wall_ms`, `space_id`, `pid`, `tid`, `rbnr_ns`, the dominant span's index, the
/// [`RBNR_SPAN_NAMES`] splits, and that iteration's pump (R4) nanoseconds.
const RBNR_RING_FIELDS: usize = 6 + RBNR_SPANS + 1;
static RBNR_RING: [[AtomicU64; RBNR_RING_FIELDS]; RBNR_RING_LEN] =
    [const { [const { AtomicU64::new(0) }; RBNR_RING_FIELDS] }; RBNR_RING_LEN];
static RBNR_RING_CURSOR: AtomicUsize = AtomicUsize::new(0);

/// Every interval at or over [`RBNR_WARN_NS`], with NO rate limit -- the WARN log line stays
/// rate-limited (one per [`RBNR_WARN_INTERVAL_MS`] globally) because it is for a human reading a
/// live log, but that limit dropped 68 % of the >= 100 ms stalls on a real desktop run (1 067 of
/// 2 624), which left per-event attribution matching against a 1-in-3 sample and made a wide
/// match window indistinguishable from coincidence. Step G fix-up: the ring is the complete
/// record; every such interval lands in it with its wall clock, space, pid, tid and span vector.
/// Sized so one counter snapshot's ring reaches back well past the snapshot interval (a real run
/// produces ~1.3 of these per second) -- and every snapshot is written to the run's counter log,
/// so the union of the snapshots is the run's whole stall timeline.
const RBNR_STALL_RING_LEN: usize = 512;
static RBNR_STALL_RING: [[AtomicU64; RBNR_RING_FIELDS]; RBNR_STALL_RING_LEN] =
    [const { [const { AtomicU64::new(0) }; RBNR_RING_FIELDS] }; RBNR_STALL_RING_LEN];
static RBNR_STALL_CURSOR: AtomicUsize = AtomicUsize::new(0);
/// How many >= [`RBNR_WARN_NS`] intervals were recorded, and how many of those fell outside the
/// ring's window at the time it was read (`recorded - ring capacity`, never a loss of the row
/// itself -- every row is in the ring at the moment it is written).
static RBNR_STALL_RECORDED: AtomicU64 = AtomicU64::new(0);

/// Input events: inject -> the read that drained them (`INPUT_CONSUME`), and the count over
/// [`INPUT_CONSUME_WARN_NS`].
static INPUT_CONSUME: CostHistogram = CostHistogram::new();
static INPUT_CONSUME_WARNED: AtomicU64 = AtomicU64::new(0);
static INPUT_CONSUME_WARNS_SUPPRESSED: AtomicU64 = AtomicU64::new(0);
static INPUT_CONSUME_LAST_WARN_MS: AtomicU64 = AtomicU64::new(0);

thread_local! {
    /// Host tick at which this thread's guest thread became runnable; `0` when it is not (or no
    /// longer) waiting to be accounted for.
    static RBNR_READY_AT: Cell<u64> = const { Cell::new(0) };
    /// Nanoseconds of the previous iteration that ran at or after [`RBNR_READY_AT`] (the shim's
    /// tail: syscall return, guest re-entry checks, dispatch bookkeeping).
    static RBNR_TAIL_NS: Cell<u64> = const { Cell::new(0) };
    /// `THREAD_WORK` at [`RBNR_READY_AT`], so the interval can be split into the service-lock and
    /// exclusive-gate shares this thread paid itself.
    static RBNR_READY_WORK: Cell<ThreadWork> = const { Cell::new(ThreadWork::ZERO) };
    /// The six shim-side waits (W1..W6) accumulated since [`RBNR_READY_AT`], in nanoseconds.
    static RBNR_W_NS: Cell<[u64; 6]> = const { Cell::new([0; 6]) };
    /// The previous iteration's retirement-pump span (R4), reported with the next interval.
    static RBNR_LAST_PUMP_NS: Cell<u64> = const { Cell::new(0) };
    /// The calling guest thread's pid (`0` = unknown) and `comm`.
    static RBNR_IDENTITY: Cell<(i32, [u8; 16])> = const { Cell::new((0, [0; 16])) };
    /// Step G fix-up: intervals under [`RBNR_RING_MIN_NS`] waiting to be folded into [`RBNR`] and
    /// their space's row, so an ordinary iteration costs no shared atomic at all. Flushed every
    /// [`RBNR_FLUSH_INTERVALS`] intervals, on a space change, and before any >= 1 ms interval.
    static RBNR_BATCH: Cell<RbnrBatch> = const { Cell::new(RbnrBatch::EMPTY) };
}

fn wall_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

/// Step G fix-up 2: the guard's own switch, so ONE binary measures both arms of its cost
/// (reviewer correction: `gr-b0` is a different tree, not a control). `LITEBOX_HVF_RBNR=0` turns
/// the accounting off; anything else, including unset, leaves it ON -- the permanent default the
/// step's spec requires. Read once, cached, the same way `LITEBOX_HVF_BOUND` is.
///
/// What it gates is the accounting and its shared-line writes, not the guard's mechanism: with
/// it off, every entry point below is one predicted branch and the run loop is the pre-step-G
/// loop. The one thing it cannot remove is the shim's own call-site work (one `Cell` read of
/// `comm` is now behind the platform call -- see `Provider::note_task_identity`), so the A/B it
/// gives bounds the platform-side accounting, which is what the reviewers' measured ~30% loaded
/// delta had to be tested against.
pub(crate) fn rbnr_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| !std::env::var_os("LITEBOX_HVF_RBNR").is_some_and(|v| v == "0"))
}

/// Step GC: the CLASS C switch, so ONE signed runner is both arms of the interleaved protocol.
/// `LITEBOX_HVF_CLASSC=0` restores the pre-step admission class at every site this step migrated;
/// anything else, including unset, leaves CLASS C ON -- the shipped default. Read once, cached,
/// the same way `LITEBOX_HVF_RBNR` and `LITEBOX_HVF_BOUND` are.
///
/// Reason it exists: a BEFORE runner built from an older tree is a different tree, not a control
/// (the same correction step G's reviewers made about `gr-b0`). Steps GA and GB landed after this
/// step's own `gc-b0` was built, so the only way to measure the class on today's tree is to switch
/// the class off inside it.
///
/// What `=0` restores, per site: `view_was_stale` takes the exclusive `vcpu_snapshot` again; the
/// retirement pump takes one admission per ticket; a lane migration registers under the exclusive
/// operation; the per-space retirement-row mirror is ignored so the per-exit check takes the
/// process-global `acknowledgements` ledger; and a `FUTEX_PRIVATE` futex takes the mapping read
/// guard again. Two sites are deliberately NOT switched (`view_spaces` `RwLock` and the
/// `vcpu_ownership` memo): they are additive and their off-path is a shape edit rather than a
/// branch, so the delta this knob measures is a conservative lower bound on the step's effect.
pub fn class_c_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| !std::env::var_os("LITEBOX_HVF_CLASSC").is_some_and(|v| v == "0"))
}

/// One shim-side blocking point ([`litebox::platform::RunnableWaitKind`]) the calling guest
/// thread passed through after becoming runnable. Relaxed add to a thread-local array, called
/// only from paths that actually waited.
pub(crate) fn note_rbnr_wait(kind: litebox::platform::RunnableWaitKind, ns: u64) {
    if !rbnr_enabled() {
        return;
    }
    let index = kind as usize;
    RBNR_W_NS.try_with(|cell| {
        let mut waits = cell.get();
        if let Some(slot) = waits.get_mut(index) {
            *slot = slot.saturating_add(ns);
        }
        cell.set(waits);
    })
    .ok();
}

/// The input device drained an event that was injected `ns` nanoseconds ago.
pub(crate) fn note_input_consume(ns: u64) {
    if !rbnr_enabled() {
        return;
    }
    INPUT_CONSUME.record(ns);
    if ns >= INPUT_CONSUME_WARN_NS {
        INPUT_CONSUME_WARNED.fetch_add(1, Ordering::Relaxed);
        let now = wall_ms();
        let last = INPUT_CONSUME_LAST_WARN_MS.load(Ordering::Relaxed);
        if now.saturating_sub(last) >= RBNR_WARN_INTERVAL_MS
            && INPUT_CONSUME_LAST_WARN_MS
                .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            litebox_util_log::warn!(
                ns:? = ns, threshold_ns:? = INPUT_CONSUME_WARN_NS;
                "input event took {ns} ns from inject to the read that drained it"
            );
        } else {
            INPUT_CONSUME_WARNS_SUPPRESSED.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// The calling guest thread's identity, published by the shim on every entry; stored only when it
/// differs from what this host thread last reported. Step G fix-up: compared on BOTH fields --
/// a pid-only compare never republishes an `exec` under the same pid, which is exactly the case
/// that matters (the process named in the readout is the one that took the pid over).
///
/// `comm` is passed as the `Cell` itself so the 16 bytes are read here, after the guard's own
/// switch, instead of at the call site: with `LITEBOX_HVF_RBNR=0` a shim entry copies nothing.
pub(crate) fn note_task_identity(pid: i32, comm: &Cell<[u8; 16]>) {
    if !rbnr_enabled() {
        return;
    }
    let _ = RBNR_IDENTITY.try_with(|cell| {
        let name = comm.get();
        if cell.get() == (pid, name) {
            return;
        }
        cell.set((pid, name));
    });
}

/// This thread's guest thread became runnable at host tick `ready`; `wake_ns` is the host wake
/// latency already measured for it (0 when the stamp is not a wake: a timeout expiry, a serviced
/// exit, or thread start). Resets the W1..W6 accumulator, so those only ever cover the interval
/// that starts here.
pub(crate) fn rbnr_became_ready(ready: u64, wake_ns: u64) {
    if !rbnr_enabled() {
        return;
    }
    let _ = RBNR_W_NS.try_with(|cell| {
        let mut waits = [0u64; 6];
        waits[RBNR_W_HOST_WAKE] = wake_ns;
        cell.set(waits);
    });
    let _ = RBNR_TAIL_NS.try_with(|cell| cell.set(0));
    let _ = RBNR_READY_AT.try_with(|cell| cell.set(ready));
    let _ = RBNR_READY_WORK.try_with(|cell| cell.set(current_thread_work()));
}

/// `run_thread` reached the end of an iteration. If the dispatch in between left this thread
/// runnable without a wait, it became runnable now; otherwise bank the tail the shim spent after
/// the wake that made it runnable.
pub(crate) fn rbnr_iteration_end(now: u64, pump_ns: u64) {
    if !rbnr_enabled() {
        return;
    }
    let _ = RBNR_LAST_PUMP_NS.try_with(|cell| cell.set(pump_ns));
    let ready = RBNR_READY_AT.try_with(Cell::get).unwrap_or(0);
    if ready == 0 {
        rbnr_became_ready(now, 0);
    } else {
        let _ = RBNR_TAIL_NS.try_with(|cell| cell.set(ticks_to_ns(now.saturating_sub(ready))));
    }
}

/// The guest thread on this host thread is about to run: close the runnable-not-running interval
/// that opened at [`rbnr_became_ready`] and account for it against `space`. `spans` must have
/// been marked through `GUEST_PRE_EXECUTE` (so `spans.last()` is `running_at`).
pub(crate) fn rbnr_record(space_id: HvfAddressSpaceId, spans: &SpanClock<13>) {
    if !rbnr_enabled() {
        return;
    }
    let ready = RBNR_READY_AT.try_with(Cell::take).unwrap_or(0);
    if ready == 0 {
        return;
    }
    let rbnr_ns = ticks_to_ns(spans.last().wrapping_sub(ready));
    // Fast path: an interval too short to be worth a span vector is banked on this thread and
    // reaches the shared counters at the next flush (or at the next >= 1 ms interval). Nothing
    // here touches a line another thread writes -- see [`RBNR_FLUSH_INTERVALS`].
    if rbnr_ns < RBNR_RING_MIN_NS {
        let _ = RBNR_BATCH.try_with(|cell| {
            let mut batch = cell.get();
            if batch.count != 0 && batch.space_id != space_id.value() {
                rbnr_flush_batch_from(&mut batch);
            }
            batch.space_id = space_id.value();
            batch.count = batch.count.wrapping_add(1);
            batch.sum_ns = batch.sum_ns.saturating_add(rbnr_ns);
            if rbnr_ns > batch.max_ns {
                batch.max_ns = rbnr_ns;
            }
            batch.buckets[latency_bucket_index(rbnr_ns)] += 1;
            if batch.count >= RBNR_FLUSH_INTERVALS {
                rbnr_flush_batch_from(&mut batch);
            }
            cell.set(batch);
        });
        return;
    }
    // An interval worth naming: flush the batch first so the row this interval lands in is not
    // missing the intervals that preceded it, then record this one sample directly (it is rare --
    // once per >= 1 ms interval -- so it can afford the shared lines).
    rbnr_flush_batch();
    RBNR.record(rbnr_ns);
    let tag = space_id.value().wrapping_add(1);
    let slot = cached_space_slot(tag);
    if let Some(slot) = slot {
        slot.rbnr_count.fetch_add(1, Ordering::Relaxed);
        slot.rbnr_sum_ns.fetch_add(rbnr_ns, Ordering::Relaxed);
        slot.rbnr_max_ns.fetch_max(rbnr_ns, Ordering::Relaxed);
        slot.rbnr_buckets[latency_bucket_index(rbnr_ns)].fetch_add(1, Ordering::Relaxed);
    }

    // Slow path: one interval long enough to be worth naming. Every term below is a thread-local
    // read or a relaxed add, and this branch runs once per >= 1 ms interval.
    let waits = RBNR_W_NS.try_with(Cell::take).unwrap_or([0; 6]);
    let tail_ns = RBNR_TAIL_NS.try_with(Cell::take).unwrap_or(0);
    let pump_ns = RBNR_LAST_PUMP_NS.try_with(Cell::get).unwrap_or(0);
    let work_at = RBNR_READY_WORK.try_with(Cell::get).unwrap_or(ThreadWork::ZERO);
    let delta = current_thread_work().delta(&work_at);
    let (pid, _) = RBNR_IDENTITY.try_with(Cell::get).unwrap_or((0, [0; 16]));

    let mut span_ns = [0u64; RBNR_SPANS];
    for (index, ns) in span_ns.iter_mut().enumerate().take(waits.len()) {
        *ns = waits[index];
    }
    span_ns[RBNR_R1_LANE_WAIT] = ticks_to_ns(spans.span(GUEST_LANE_WAIT));
    span_ns[RBNR_R2_VIEW_ATTACH] = ticks_to_ns(spans.span(GUEST_VIEW_ATTACH));
    span_ns[RBNR_R3_ATTACH] = ticks_to_ns(
        spans
            .span(GUEST_ATTACH)
            .wrapping_add(spans.span(GUEST_PRE_EXECUTE)),
    );
    span_ns[RBNR_R5_VMEM_WAIT] = ticks_to_ns(delta.vmem_wait_ticks);
    span_ns[RBNR_R5_CELL_WAIT] = ticks_to_ns(delta.cell_wait_ticks);
    span_ns[RBNR_R5_LOCK_WAIT] = ticks_to_ns(delta.lock_wait_ticks);
    span_ns[RBNR_R6_EXCL_WAIT] = ticks_to_ns(delta.excl_wait_ticks);
    span_ns[RBNR_R6_EXCL_HOLD] = ticks_to_ns(delta.excl_hold_ticks);
    span_ns[RBNR_R6_GATE_MUTEX_WAIT] = ticks_to_ns(delta.gate_mutex_wait_ticks);
    span_ns[RBNR_SHIM_TAIL] = tail_ns.saturating_sub(
        waits[RBNR_W_HOST_WAKE].saturating_add(waits[RBNR_W_FORK_GATE])
            .saturating_add(waits[RBNR_W_AS_HANDOFF])
            .saturating_add(waits[RBNR_W_AS_ACQUIRE])
            .saturating_add(waits[RBNR_W_PTRACE])
            .saturating_add(waits[RBNR_W_SIGNAL_FRAME]),
    );
    span_ns[RBNR_LOOP_OTHER] = ticks_to_ns(
        spans
            .span(GUEST_LOOP_TOP)
            .wrapping_add(spans.span(GUEST_RESERVE))
            .wrapping_add(spans.span(GUEST_SPACE_LOOKUP))
            .wrapping_add(spans.span(GUEST_STATE_BUILD)),
    );
    let named = span_ns[..RBNR_UNATTRIBUTED]
        .iter()
        .fold(0u64, |sum, ns| sum.saturating_add(*ns));
    span_ns[RBNR_UNATTRIBUTED] = rbnr_ns.saturating_sub(named);
    // Both sides of the attribution identity, so `unattributed == 0` is never read as "exactly
    // measured": the named spans over-cover the interval (`r6` is inside `r2`), which is why the
    // subtraction above saturates. `unattributed > 0` is the one-sided "unnamed blocking point"
    // signal; `named_sum / credited` is the overlap factor.
    RBNR_CREDITED_NS.fetch_add(rbnr_ns, Ordering::Relaxed);
    RBNR_NAMED_SUM_NS.fetch_add(named, Ordering::Relaxed);
    if named > rbnr_ns {
        RBNR_OVER_COVER_NS.fetch_add(named - rbnr_ns, Ordering::Relaxed);
    }

    let dominant = span_ns
        .iter()
        .enumerate()
        .filter(|(index, _)| *index != RBNR_UNATTRIBUTED)
        .max_by_key(|(_, ns)| **ns)
        .map(|(index, _)| index)
        .unwrap_or(RBNR_UNATTRIBUTED);
    for (index, ns) in span_ns.iter().enumerate() {
        if *ns != 0
            && let Some(total) = RBNR_SPAN_TOTALS.get(index)
        {
            total.fetch_add(*ns, Ordering::Relaxed);
        }
    }
    if let Some(total) = RBNR_DOMINANT_NS.get(dominant) {
        total.fetch_add(rbnr_ns, Ordering::Relaxed);
    }
    if let Some(total) = RBNR_DOMINANT_COUNT.get(dominant) {
        total.fetch_add(1, Ordering::Relaxed);
    }
    if pump_ns != 0 {
        RBNR_PUMP_NS.fetch_add(pump_ns, Ordering::Relaxed);
    }
    if let Some(slot) = slot {
        // The space -> process name mapping the inventory needs: published for every space that
        // records an interval, here (the >= 1 ms path) and at each batch flush.
        publish_space_identity(slot);
        for (index, ns) in span_ns.iter().enumerate() {
            if *ns != 0
                && let Some(total) = slot.rbnr_spans.get(index)
            {
                total.fetch_add(*ns, Ordering::Relaxed);
            }
        }
        if pump_ns != 0 {
            slot.rbnr_pump_ns.fetch_add(pump_ns, Ordering::Relaxed);
        }
        if let Some(total) = slot.rbnr_dom_ns.get(dominant) {
            total.fetch_add(rbnr_ns, Ordering::Relaxed);
        }
    }

    let mut fields = [0u64; RBNR_RING_FIELDS];
    fields[0] = wall_ms();
    fields[1] = space_id.value();
    fields[2] = pid.cast_unsigned().into();
    fields[3] = thread_id_u64();
    fields[4] = rbnr_ns;
    fields[5] = dominant as u64;
    fields[6..6 + RBNR_SPANS].copy_from_slice(&span_ns);
    fields[6 + RBNR_SPANS] = pump_ns;
    let row = RBNR_RING_CURSOR.fetch_add(1, Ordering::Relaxed) % RBNR_RING_LEN;
    for (cell, value) in RBNR_RING[row].iter().zip(fields) {
        cell.store(value, Ordering::Relaxed);
    }

    if rbnr_ns >= RBNR_WARN_NS {
        RBNR_WARNED.fetch_add(1, Ordering::Relaxed);
        RBNR_STALL_RECORDED.fetch_add(1, Ordering::Relaxed);
        // The complete record: every >= 100 ms interval, with no rate limit. The WARN line below
        // is for a live log reader and stays limited to one per 2 s; this row is what per-event
        // attribution matches against, and suppressing 68 % of them is what made a wide match
        // window indistinguishable from coincidence.
        let row = RBNR_STALL_CURSOR.fetch_add(1, Ordering::Relaxed) % RBNR_STALL_RING_LEN;
        for (cell, value) in RBNR_STALL_RING[row].iter().zip(fields) {
            cell.store(value, Ordering::Relaxed);
        }
        let now = fields[0];
        let last = RBNR_LAST_WARN_MS.load(Ordering::Relaxed);
        if now.saturating_sub(last) >= RBNR_WARN_INTERVAL_MS
            && RBNR_LAST_WARN_MS
                .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            litebox_util_log::warn!(
                rbnr_ns:? = rbnr_ns, space:? = space_id.value(), pid:? = pid,
                tid:? = thread_id_u64(), dominant:% = RBNR_SPAN_NAMES[dominant],
                dominant_ns:? = span_ns[dominant], pump_ns:? = pump_ns;
                "guest thread was runnable but not running for {rbnr_ns} ns"
            );
        } else {
            RBNR_WARNS_SUPPRESSED.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Publishes this host thread's current guest pid / `comm` into `slot`, comparing first so the
/// steady state is three relaxed loads.
fn publish_space_identity(slot: &SpaceSlot) {
    let (pid, comm) = RBNR_IDENTITY.try_with(Cell::get).unwrap_or((0, [0; 16]));
    if pid == 0 {
        return;
    }
    let pid_u = pid.cast_unsigned().into();
    let mut name = [0u64; 2];
    name[0] = u64::from_le_bytes(
        comm[..8].try_into().expect("16-byte comm splits into two 8-byte halves"),
    );
    name[1] = u64::from_le_bytes(
        comm[8..].try_into().expect("16-byte comm splits into two 8-byte halves"),
    );
    let stored = [
        slot.comm[0].load(Ordering::Relaxed),
        slot.comm[1].load(Ordering::Relaxed),
    ];
    if slot.pid.load(Ordering::Relaxed) != pid_u || stored != name {
        slot.pid.store(pid_u, Ordering::Relaxed);
        for (cell, value) in slot.comm.iter().zip(name) {
            cell.store(value, Ordering::Relaxed);
        }
    }
}

/// Folds `batch` into [`RBNR`] and into its space's row, leaving it empty.
fn rbnr_flush_batch_from(batch: &mut RbnrBatch) {
    let count = batch.count;
    if count == 0 {
        return;
    }
    RBNR.record_bulk(count, batch.sum_ns, batch.max_ns, &batch.buckets);
    if let Some(slot) = cached_space_slot(batch.space_id.wrapping_add(1)) {
        slot.rbnr_count.fetch_add(count, Ordering::Relaxed);
        slot.rbnr_sum_ns.fetch_add(batch.sum_ns, Ordering::Relaxed);
        slot.rbnr_max_ns.fetch_max(batch.max_ns, Ordering::Relaxed);
        for (index, added) in batch.buckets.iter().enumerate() {
            if *added != 0 {
                slot.rbnr_buckets[index].fetch_add(*added, Ordering::Relaxed);
            }
        }
        publish_space_identity(slot);
    }
    *batch = RbnrBatch::EMPTY;
}

/// Flushes this thread's pending [`RBNR_BATCH`], if it has one.
fn rbnr_flush_batch() {
    let _ = RBNR_BATCH.try_with(|cell| {
        let mut batch = cell.get();
        rbnr_flush_batch_from(&mut batch);
        cell.set(batch);
    });
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

/// [`ticks_to_ns`]'s inverse, for a caller that only has a nanosecond duration to add to a tick
/// stamp (a wait's deadline, in step G's timeout arm).
pub(crate) fn ns_to_ticks(ns: u64) -> u64 {
    let (numer, denom) = timebase();
    ns.saturating_mul(denom) / numer
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
/// CLASS C batching: pump passes that took ONE cleanup admission for all their tickets.
const STAT_PUMP_PASSES_BATCHED: usize = STAT_PUMP_OWNER_BYPASSES + 1;
const STAT_PUMP_TICKETS_BATCHED: usize = STAT_PUMP_PASSES_BATCHED + 1;
/// CLASS C fix-up: a migration's departure half that fell back from the counting shared
/// admission to the cleanup class because the shared one was refused (poison-requested / poisoned
/// / abandoned). Must stay low: it is the window the shared class cannot cover.
pub(crate) const STAT_MIGRATION_DEPART_FALLBACK: usize = STAT_PUMP_TICKETS_BATCHED + 1;
/// A migration whose arrival unwind ALSO failed: the lane has two live registrations.
pub(crate) const STAT_MIGRATION_UNWIND_FAILED: usize = STAT_MIGRATION_DEPART_FALLBACK + 1;
/// CLASS C: vCPU-ownership membership checks served from the per-vCPU memo, i.e. without the
/// VM-global `vcpu_ownership` mutex ([`HvfVcpu::require_owner_live`]).
const STAT_VCPU_OWNERSHIP_MEMO: usize = STAT_MIGRATION_UNWIND_FAILED + 1;
/// ... and the ones that had to take the mutex because the ownership version moved.
const STAT_VCPU_OWNERSHIP_SCAN: usize = STAT_VCPU_OWNERSHIP_MEMO + 1;
/// Contended `vcpu_ownership` acquisitions (count, then ticks blocked).
const STAT_VCPU_OWNERSHIP_CONTENDED: usize = STAT_VCPU_OWNERSHIP_SCAN + 1;
/// CLASS C per-iteration retirement check: exits whose per-space row-count hint was zero, so
/// neither the ledger lock nor a scan ran (T1c-i), and exits where it was nonzero.
const STAT_RETIREMENT_HINT_ZERO: usize = STAT_VCPU_OWNERSHIP_CONTENDED + 2;
const STAT_RETIREMENT_HINT_NONZERO: usize = STAT_RETIREMENT_HINT_ZERO + 1;
/// Shared acquisitions of litebox's mapping lock (T1h; per-thread shard lines, so the counting
/// write never contends across threads).
const STAT_VMEM_READS: usize = STAT_RETIREMENT_HINT_NONZERO + 1;
/// Per-exit retirement checks skipped because the ledger was held (count, then ticks spent).
const STAT_PENDING_SKIPPED: usize = STAT_VMEM_READS + 1;
/// BCORE: the bound-vCPU path (`LITEBOX_HVF_BOUND=1`). One relaxed counter per event, on the
/// calling thread's shard line, indexed by the `BOUND_*` constants below and rendered with
/// [`BOUND_STAT_NAMES`].
const STAT_BOUND: usize = STAT_PENDING_SKIPPED + 2;
/// `LITEBOX_HVF_BOUND=1` was in effect when this process started (0/1).
pub(crate) const BOUND_ENABLED: usize = STAT_BOUND + 0;
/// Bound vCPUs currently alive (a gauge, not a counter: incremented on bind, decremented on
/// unbind).
pub(crate) const BOUND_LIVE: usize = STAT_BOUND + 1;
pub(crate) const BOUND_BINDS: usize = STAT_BOUND + 2;
/// A bind the registry refused (its budget was spent): the thread stays on the pooled path.
pub(crate) const BOUND_BIND_REFUSED: usize = STAT_BOUND + 3;
/// Unbinds, by reason: the guest thread is exiting, ... went idle, ... was evicted under
/// pressure, ... became bind-ineligible (the vfork window), ... was dropped by a TLS
/// destructor.
pub(crate) const BOUND_UNBINDS_EXIT: usize = STAT_BOUND + 4;
pub(crate) const BOUND_UNBINDS_IDLE: usize = STAT_BOUND + 5;
pub(crate) const BOUND_UNBINDS_PRESSURE: usize = STAT_BOUND + 6;
pub(crate) const BOUND_UNBINDS_INELIGIBLE: usize = STAT_BOUND + 7;
pub(crate) const BOUND_UNBINDS_DROP: usize = STAT_BOUND + 8;
/// An unbind whose participant deregistration or vCPU destroy failed.
pub(crate) const BOUND_UNBINDS_FAILED: usize = STAT_BOUND + 9;
pub(crate) const BOUND_DEREGISTER_FAILED: usize = STAT_BOUND + 10;
/// A failed deregistration that `recover_stopped_vcpu_participants` also failed to repair.
pub(crate) const BOUND_DEREGISTER_RECOVERY_FAILED: usize = STAT_BOUND + 11;
/// Runs executed on a bound vCPU.
pub(crate) const BOUND_RUNS: usize = STAT_BOUND + 12;
/// Loop iterations on which the thread was bound-eligible but ran on the pool anyway (the
/// bind trigger had not fired, or the bind was refused): the denominator of
/// `runs / (runs + eligible_handoffs)`.
pub(crate) const BOUND_ELIGIBLE_HANDOFFS: usize = STAT_BOUND + 13;
/// Operation-gate mutex acquisitions attributable to bound runs.
pub(crate) const BOUND_GATE_LOCKS: usize = STAT_BOUND + 14;
pub(crate) const BOUND_SYNC_TRIPS: usize = STAT_BOUND + 15;
/// Kick accounting. Identity (exact once the vCPU is idle or terminalized):
/// `issued == consumed + drained + expired_unlatched + expired_terminal + expired_latched +
/// abandoned`.
/// `latched` and `merged` are outside it: a latched kick is an issued one that the pre-entry
/// latch consumed, and a merged one never reached the SDK. `abandoned` IS inside it -- it
/// counts the debits a `terminalize` discharged with no corresponding `Canceled` exit, and a
/// bound vCPU's `unbind`/`Drop` now call `terminalize` before destroying the vCPU, so a
/// teardown that happens while a kick is outstanding reports it here instead of dropping it.
/// Before that fix-up `abandoned` and `expired_terminal` were structurally unreachable, i.e.
/// 0 in every bound run ever taken: they counted nothing rather than proving nothing was
/// abandoned, and the identity held only because a leaked debit was invisible.
pub(crate) const BOUND_KICKS_ISSUED: usize = STAT_BOUND + 16;
pub(crate) const BOUND_KICKS_LATCHED: usize = STAT_BOUND + 17;
pub(crate) const BOUND_KICKS_MERGED: usize = STAT_BOUND + 18;
pub(crate) const BOUND_KICKS_CONSUMED: usize = STAT_BOUND + 19;
pub(crate) const BOUND_KICKS_DRAINED: usize = STAT_BOUND + 20;
pub(crate) const BOUND_KICKS_EXPIRED_UNLATCHED: usize = STAT_BOUND + 21;
pub(crate) const BOUND_KICKS_EXPIRED_TERMINAL: usize = STAT_BOUND + 22;
pub(crate) const BOUND_KICKS_ABANDONED: usize = STAT_BOUND + 23;
/// A thread interrupt that arrived between `reserve_run` and `hv_vcpu_run`, so the run
/// completes as `Canceled` without ever entering the guest.
pub(crate) const BOUND_INTERRUPTS_LATCHED_PRE_ENTRY: usize = STAT_BOUND + 24;
pub(crate) const BOUND_CANCELED_EXITS: usize = STAT_BOUND + 25;
pub(crate) const BOUND_CANCELED_INTERRUPTS: usize = STAT_BOUND + 26;
pub(crate) const BOUND_VTIMER_EXITS: usize = STAT_BOUND + 27;
pub(crate) const BOUND_VTIMER_REARMS: usize = STAT_BOUND + 28;
/// BCORE-3: a `VtimerActivated` exit on which a host signal was already pending, so the exit
/// was turned into a `shim.interrupt` instead of a bare `yield_now` + resume.
pub(crate) const BOUND_HOST_SIGNAL_FASTPATH: usize = STAT_BOUND + 29;
/// Bound vCPUs no thread can destroy any more (an owner unwound past its own vCPU).
pub(crate) const BOUND_LOST: usize = STAT_BOUND + 30;
/// BCORE-2 (fix-up): a kick whose requester gave up waiting before any exit resolved it (a
/// latched attempt completed `Expired`). No SDK `hv_vcpus_exit` was ever issued for it, so it
/// is discharged here instead of staying on the debit ledger until the vCPU is terminalized.
pub(crate) const BOUND_KICKS_EXPIRED_LATCHED: usize = STAT_BOUND + 31;
/// BCORE-5 (fix-up): a thread-exit unbind the shim asked for while this thread was inside its
/// own bound dispatch, so taking the vCPU away here would drop that iteration's exit. Deferred
/// to this thread's own loop top, where the unbind is safe.
pub(crate) const BOUND_UNBINDS_DEFERRED: usize = STAT_BOUND + 32;
/// BCORE-4 (fix-up): a mapping mutation's shootdown asked a bound vCPU to re-evaluate at its
/// loop top (the bound counterpart of an idle lane's forced `synchronize_before`).
pub(crate) const BOUND_SHOOTDOWN_SYNC_REQUESTS: usize = STAT_BOUND + 33;
const BOUND_STAT_COUNT: usize = 34;

const BOUND_STAT_NAMES: [&str; BOUND_STAT_COUNT] = [
    "enabled",
    "live",
    "binds",
    "bind_refused",
    "unbinds_exit",
    "unbinds_idle",
    "unbinds_pressure",
    "unbinds_ineligible",
    "unbinds_drop",
    "unbinds_failed",
    "deregister_failed",
    "deregister_recovery_failed",
    "runs",
    "eligible_handoffs",
    "gate_locks",
    "sync_trips",
    "kicks_issued",
    "kicks_latched",
    "kicks_merged",
    "kicks_consumed",
    "kicks_drained",
    "kicks_expired_unlatched",
    "kicks_expired_terminal",
    "kicks_abandoned",
    "interrupts_latched_pre_entry",
    "canceled_exits",
    "canceled_interrupts",
    "vtimer_exits",
    "vtimer_rearms",
    "host_signal_fastpath",
    "lost",
    "kicks_expired_latched",
    "unbinds_deferred",
    "shootdown_sync_requests",
];

/// BCORE: wall time inside `hv_vcpu_run` on a bound vCPU.
static BOUND_RUN_WALL: CostHistogram = CostHistogram::new();
/// BCORE: the whole bound loop iteration minus the shim's own syscall service -- the number
/// that has to come down for the per-syscall target.
static BOUND_EXIT_OVERHEAD: CostHistogram = CostHistogram::new();

/// BCORE: one bound run's `hv_vcpu_run` wall time.
pub(crate) fn record_bound_run_wall(ns: u64) {
    BOUND_RUN_WALL.record(ns);
}

/// BCORE: one bound loop iteration's overhead (everything but the shim's service).
pub(crate) fn record_bound_exit_overhead(ns: u64) {
    BOUND_EXIT_OVERHEAD.record(ns);
}

/// BCORE: the `"bound"` JSON object, or `null` when the knob was never on and nothing bound.
pub(crate) fn bound_counters_json() -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(1024);
    out.push('{');
    for (index, name) in BOUND_STAT_NAMES.iter().enumerate() {
        let _ = write!(out, "\"{name}\":{},", stat_total(STAT_BOUND + index));
    }
    let (count, sum_ns, max_ns, buckets) = BOUND_RUN_WALL.snapshot();
    let _ = write!(
        out,
        "\"run_wall\":{{\"count\":{},\"sum_ns\":{},\"max_ns\":{},\"buckets\":",
        count, sum_ns, max_ns
    );
    push_buckets(&mut out, &buckets);
    out.push_str("},");
    let (count, sum_ns, max_ns, buckets) = BOUND_EXIT_OVERHEAD.snapshot();
    let _ = write!(
        out,
        "\"exit_overhead\":{{\"count\":{},\"sum_ns\":{},\"max_ns\":{},\"buckets\":",
        count, sum_ns, max_ns
    );
    push_buckets(&mut out, &buckets);
    out.push_str("}}");
    out
}

/// FXR resident-register cache counters (`RESIDENT_*` offsets, [`RESIDENT_STAT_NAMES`]).
const STAT_RESIDENT: usize = STAT_BOUND + BOUND_STAT_COUNT;
/// Step GF (b) lane-stickiness counters (`LANE_STICKY_*` offsets, [`LANE_STICKY_STAT_NAMES`]).
const STAT_LANE_STICKY: usize = STAT_RESIDENT + RESIDENT_STAT_NAMES.len();
/// T2e: the preallocated per-lane Execute reply slot's counters.
const STAT_REPLY_SLOT: usize = STAT_LANE_STICKY + LANE_STICKY_STAT_NAMES.len();
/// T2e: the preallocated per-lane Execute reply slot ([`crate::hvf_vcpu::ExecuteReplySlot`]),
/// which replaces the per-syscall `mpsc::sync_channel(1)`.
/// Replies handed to a waiter (one per Execute the owner answered, including the `LaneClosed`
/// posts a dropped command makes).
pub(crate) const REPLY_SLOT_POSTS: usize = STAT_REPLY_SLOT + 0;
/// Posts that found no waiter registered. T2c split this: the ordinary, now-dominant case is
/// T2c's spinning waiter, which reads `posted` itself and never registers -- counted separately in
/// [`REPLY_SLOT_SPIN_POSTS`], so `late_posts - spin_posts` is the part that still means something:
/// the waiter had timed out (the lane is already abandoned, so no further Execute can be issued on
/// it) or it had not registered yet and takes the value on its own re-read. Never a lost reply.
///
/// Read `late_posts / posts` as "nobody was parked" -- NOT as a lost-wakeup or timeout signal. It
/// was 0.000-0.001 before T2c and is 0.92-0.97 after it purely because the fast path no longer
/// needs a park; the semantic signal lives in the difference now.
pub(crate) const REPLY_SLOT_LATE_POSTS: usize = STAT_REPLY_SLOT + 1;
/// `park_timeout` calls: waits that did not complete on the first lock-free read of `posted`.
pub(crate) const REPLY_SLOT_PARKS: usize = STAT_REPLY_SLOT + 2;
/// T2c: the subset of [`REPLY_SLOT_LATE_POSTS`] that is ordinary -- the waiter took the reply off
/// `posted` itself (it was already published when `wait` looked, or the bounded spin saw it land)
/// and so was never registered to be unparked. Counted on the waiter side, at the two direct-read
/// returns in `ExecuteReplySlot::wait`.
pub(crate) const REPLY_SLOT_SPIN_POSTS: usize = STAT_REPLY_SLOT + 3;
const REPLY_SLOT_STAT_NAMES: [&str; 4] = ["posts", "late_posts", "parks", "spin_posts"];

/// T2c: the bounded adaptive spin-then-park hand-off counters (`HANDOFF_SPIN_*` offsets,
/// [`HANDOFF_SPIN_STAT_NAMES`]).
const STAT_HANDOFF_SPIN: usize = STAT_REPLY_SLOT + REPLY_SLOT_STAT_NAMES.len();
/// Owner-side spins that saw work before the budget ran out: the wakeup `try_push` would have
/// paid for is not paid.
pub(crate) const HANDOFF_SPIN_OWNER_HITS: usize = STAT_HANDOFF_SPIN + 0;
/// Owner-side spins that ran out of budget (the lane really was idle; the park follows).
pub(crate) const HANDOFF_SPIN_OWNER_MISSES: usize = STAT_HANDOFF_SPIN + 1;
/// Host nanoseconds owner threads spent spinning (hit and miss together).
pub(crate) const HANDOFF_SPIN_OWNER_NS: usize = STAT_HANDOFF_SPIN + 2;
/// Guest-side spins that saw the reply before the budget ran out.
pub(crate) const HANDOFF_SPIN_GUEST_HITS: usize = STAT_HANDOFF_SPIN + 3;
/// Guest-side spins that ran out of budget.
pub(crate) const HANDOFF_SPIN_GUEST_MISSES: usize = STAT_HANDOFF_SPIN + 4;
/// Host nanoseconds guest threads spent spinning.
pub(crate) const HANDOFF_SPIN_GUEST_NS: usize = STAT_HANDOFF_SPIN + 5;
/// Waits that found spinning turned off for this thread (four consecutive misses halved the
/// budget below the floor). One probe every 16 of these (a single 10 us start budget, i.e. at most
/// 625 ns amortized per wait); the rest go straight to the park.
pub(crate) const HANDOFF_SPIN_OWNER_DISABLED: usize = STAT_HANDOFF_SPIN + 6;
pub(crate) const HANDOFF_SPIN_GUEST_DISABLED: usize = STAT_HANDOFF_SPIN + 7;
const HANDOFF_SPIN_STAT_NAMES: [&str; 8] = [
    "owner_hits",
    "owner_misses",
    "owner_spin_ns",
    "guest_hits",
    "guest_misses",
    "guest_spin_ns",
    "owner_disabled",
    "guest_disabled",
];

const STAT_COUNT: usize = STAT_HANDOFF_SPIN + HANDOFF_SPIN_STAT_NAMES.len();

/// T2c: one adaptive spin at a lane hand-off site. `hit` is whether the wait finished inside
/// the budget; `spin_ns` is what it cost either way (the CPU bound of the whole mechanism is
/// `owner_spin_ns + guest_spin_ns <= 20 us x (hits + misses)`).
pub(crate) fn record_handoff_spin(owner: bool, hit: bool, spin_ns: u64) {
    let (hits, misses, ns) = if owner {
        (
            HANDOFF_SPIN_OWNER_HITS,
            HANDOFF_SPIN_OWNER_MISSES,
            HANDOFF_SPIN_OWNER_NS,
        )
    } else {
        (
            HANDOFF_SPIN_GUEST_HITS,
            HANDOFF_SPIN_GUEST_MISSES,
            HANDOFF_SPIN_GUEST_NS,
        )
    };
    add_stat(if hit { hits } else { misses }, 1);
    add_stat(ns, spin_ns);
}

/// T2c: one wait that skipped its spin because this thread's budget had converged to zero.
pub(crate) fn record_handoff_spin_disabled(owner: bool) {
    add_stat(
        if owner {
            HANDOFF_SPIN_OWNER_DISABLED
        } else {
            HANDOFF_SPIN_GUEST_DISABLED
        },
        1,
    );
}

/// T2e: one reply handed over through a lane's slot.
pub(crate) fn record_reply_slot_post(late: bool) {
    add_stat(REPLY_SLOT_POSTS, 1);
    if late {
        add_stat(REPLY_SLOT_LATE_POSTS, 1);
    }
}

/// T2c: one reply the waiter took off `posted` itself, so it was never registered here and
/// `post`'s `late` arm counted it. This is the ordinary fast path now, and it is the only reason
/// `late_posts` is large; `late_posts - spin_posts` is the part worth investigating.
pub(crate) fn record_reply_slot_direct_read() {
    add_stat(REPLY_SLOT_SPIN_POSTS, 1);
}

/// T2e: one guest-side park on a lane's reply slot.
pub(crate) fn record_reply_slot_park() {
    add_stat(REPLY_SLOT_PARKS, 1);
}

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
/// RUNWALL FC2: per-run time-slice arms that were actually written into the virtual timer.
pub(crate) const RESIDENT_VTIMER_ARMS: usize = 29;
/// RUNWALL FC2: per-run time-slice arms skipped because the timer already held a deadline less
/// than one slice old (the arm is a no-op for the run's deadline, and each write costs the next
/// `hv_vcpu_run`).
pub(crate) const RESIDENT_VTIMER_ARM_SKIPS: usize = 30;
const RESIDENT_STAT_NAMES: [&str; 31] = [
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
    "vtimer_arms",
    "vtimer_arm_skips",
];

/// Step GF (b): the lane-stickiness switch, so ONE signed runner is both arms of the interleaved
/// protocol (`LITEBOX_HVF_LANE_STICKY=0` releases every lane back to the pool at the end of each
/// run, which is what the pooled path did before this step). Read once, cached, the same way
/// `LITEBOX_HVF_RBNR` and `LITEBOX_HVF_CLASSC` are.
pub fn lane_sticky_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| {
        !std::env::var_os("LITEBOX_HVF_LANE_STICKY").is_some_and(|v| v == "0")
    })
}

/// Step GF (b) lane-stickiness counters.
/// A guest thread whose run ended without an interruptible wait keeps its vCPU lane lease -- and
/// with it the lane's participant registration in the thread's view -- instead of handing the lane
/// back to the pool, so the next short syscall pays no pool round trip, no lane migration and no
/// re-attach. The G inventory measured `r2_view_attach` (lane migration) at 71-76 % of the
/// X-connected spaces' runnable-not-running credit and `r1_lane_wait` at 9-15 %; both are the
/// pool round trip this removes.
/// Runs served by a lease this thread already held: no pool acquisition at all.
pub(crate) const LANE_STICKY_REUSED: usize = STAT_LANE_STICKY + 0;
/// Runs that had to take a lane from the pool (the first run, or the previous lease was given
/// back). `reused / (reused + acquired)` is the retention rate.
pub(crate) const LANE_STICKY_ACQUIRED: usize = STAT_LANE_STICKY + 1;
/// Leases kept at the end of a run.
pub(crate) const LANE_STICKY_KEPT: usize = STAT_LANE_STICKY + 2;
/// Leases given back at the end of a run because another thread was already waiting for a lane.
pub(crate) const LANE_STICKY_RELEASED_WAITERS: usize = STAT_LANE_STICKY + 3;
/// ... because this thread was about to park on a host wait (an interruptible guest wait or one
/// of the shim's own locks), where keeping the lane would starve every other thread.
pub(crate) const LANE_STICKY_RELEASED_BLOCK: usize = STAT_LANE_STICKY + 4;
/// ... because a shootdown or lane maintenance asked every retained lane back.
pub(crate) const LANE_STICKY_RELEASED_YIELD: usize = STAT_LANE_STICKY + 5;
/// ... because the lease reached its retention cap (runs or wall time).
pub(crate) const LANE_STICKY_RELEASED_CAP: usize = STAT_LANE_STICKY + 6;
/// ... because the lease reached its wall-clock bound (step GF fix-up). Distinct from the cap so
/// the two bounds can be told apart in a run: `released_cap` counts leases that served
/// [`crate::hvf_backend::LANE_STICKY_MAX_RUNS`] runs, this one leases held across a single long
/// iteration or a block no release site covers.
pub(crate) const LANE_STICKY_RELEASED_TIME: usize = STAT_LANE_STICKY + 7;
/// ... because this thread joined the exclusive-VM-operation admission FIFO (step GF fix-up):
/// `HvfVm::wait_for_operation_state`, the desktop's largest blocked wait.
pub(crate) const LANE_STICKY_RELEASED_GATE: usize = STAT_LANE_STICKY + 8;
/// ... because the lane generation is no longer reusable (the lane is being retired).
pub(crate) const LANE_STICKY_RELEASED_RETIRE: usize = STAT_LANE_STICKY + 9;
/// ... because the thread left `run_thread` altogether.
pub(crate) const LANE_STICKY_RELEASED_EXIT: usize = STAT_LANE_STICKY + 10;
const LANE_STICKY_STAT_NAMES: [&str; 11] = [
    "reused",
    "acquired",
    "kept",
    "released_waiters",
    "released_block",
    "released_yield",
    "released_cap",
    "released_time",
    "released_gate",
    "released_retire",
    "released_exit",
];

/// One lane-stickiness outcome; see [`LANE_STICKY_REUSED`].
pub(crate) fn record_lane_sticky(stat: usize) {
    add_stat(stat, 1);
}

fn render_lane_sticky(out: &mut String) {
    use std::fmt::Write as _;
    out.push_str("\"lane_sticky\":{\"enabled\":");
    out.push_str(if lane_sticky_enabled() { "1" } else { "0" });
    for (index, name) in LANE_STICKY_STAT_NAMES.iter().enumerate() {
        let value = stat_total(STAT_LANE_STICKY + index);
        let _ = write!(out, ",\"{name}\":{value}");
    }
    out.push_str("},");
}

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
pub(crate) fn add_stat(stat: usize, value: u64) {
    if let Some(counter) = stat_shard().values.get(stat) {
        counter.fetch_add(value, Ordering::Relaxed);
    }
}

fn stat_total(stat: usize) -> u64 {
    STAT_SHARDS.iter().fold(0u64, |sum, shard| {
        sum.wrapping_add(shard.values.get(stat).map_or(0, |v| v.load(Ordering::Relaxed)))
    })
}

/// BCORE-4: one named bound counter's running total, for the in-repo bound-vCPU witnesses
/// (they assert their own effect on a counter rather than on a log line).
pub(crate) fn bound_stat_total(stat: usize) -> u64 {
    stat_total(stat)
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
#[track_caller]
pub(crate) fn lock_gate<'a, T>(
    mutex: &'a Mutex<T>,
    lock_site: usize,
    op_site: u16,
) -> MutexGuard<'a, T> {
    // CLASS A: the gate mutex is the order's leaf (rank `RANK_GATE_MUTEX`), taken inside mutation
    // bodies that hold `cell.state` / `arenas` / `backings` / `acknowledgements`. Naming it here
    // is what makes that nesting legal instead of an out-of-rank violation, and it is never
    // registered in the held set, so the FIFO check still sees everything the body holds.
    rank_check(RANK_GATE_MUTEX, Location::caller());
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
/// (count) and `contended_stat + 1` (ticks). The mutex is a [`RankedMutex`], so the acquisition
/// also joins the CLASS A held set.
#[track_caller]
pub(crate) fn lock_timed<'a, T>(mutex: &'a RankedMutex<T>, contended_stat: usize) -> RankedGuard<'a, T> {
    let site = Location::caller();
    rank_check(mutex.rank(), site);
    match mutex.try_lock_unchecked() {
        Ok(guard) => guard,
        Err(TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
        Err(TryLockError::WouldBlock) => {
            rank_note_blocked_acquire(mutex.rank(), site);
            let started = ticks();
            let guard = mutex.lock_unchecked().unwrap_or_else(PoisonError::into_inner);
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
/// CLASS C: the lightest admission class. A site of this kind reads state whose own lock already
/// serializes it (`AddressSpaceCell::state`) and takes **no** VM operation at all. Declared by
/// [`record_read_class`]; an exclusive or shared admission ever observed at such a site is a
/// class regression (see [`note_class_regression`]).
pub(crate) const SITE_KIND_READ: u8 = 5;
/// CLASS C: one exclusive/cleanup admission deliberately covering N items (the retirement
/// pump), so the gate is admitted once per pass instead of once per item.
pub(crate) const SITE_KIND_BATCHED: u8 = 6;
const SITE_KIND_NAMES: [&str; 7] = [
    "none",
    "exclusive",
    "shared",
    "existing",
    "pump",
    "read",
    "batched",
];
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
    /// CLASS C positive guard: publications (`mark_published` successes) at this site. A site
    /// with many exclusive admissions and ~0 publications is an exclusive admission with no HVF
    /// effect -- the class shape, whatever the site declared itself to be.
    published: AtomicU64,
    /// Exclusive admissions at this site (the denominator of the positive guard).
    exclusive: AtomicU64,
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
            published: AtomicU64::new(0),
            exclusive: AtomicU64::new(0),
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

/// CLASS C positive guard: how many exclusive admissions a site may take with zero publications
/// before the (debug-only) trap names it. Power-of-two steps from here, so a site that publishes
/// routinely is never tested again.
const SITE_NONPUBLISHING_TRAP_AT: u64 = 1024;

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

/// One successful `mark_published` at `site`: that admission had an HVF effect. Paired with the
/// site's `count`, this is the CLASS C positive guard (see `SiteSlot::published`).
pub(crate) fn record_site_publication(site: u16) {
    if let Some(slot) = SITES.get(usize::from(site)) {
        slot.published.fetch_add(1, Ordering::Relaxed);
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

// ---- CLASS C: admission-class declarations and the permanent guard --------------------------
//
// Every operation call site has a class: what its body actually needs of the VM operation gate.
// `Read` (no admission at all; the state's own lock serializes it), `Shared` (counting
// admission), `Batched` (one exclusive admission for N items), `Exclusive` (true exclusion).
// The class is *declared* by the site choosing the entry point, and the choice is recorded in
// the site table so a regression -- a site that the inventory classified `Read` or `Shared`
// taking an exclusive admission -- is counted in release and trapped in debug the first time it
// happens, instead of being rediscovered by a future soak.

// A read-classified body is running on this thread: it must not mutate the address-space state
// domain, and it takes no VM admission.
thread_local! {
    static READ_CLASS_DEPTH: Cell<u32> = const { Cell::new(0) };
    static READ_CLASS_SITE: Cell<Option<&'static Location<'static>>> = const { Cell::new(None) };
}

static READ_CLASS_READS: AtomicU64 = AtomicU64::new(0);
/// A read-classified body mutated the address-space state domain (`TimedGuard::deref_mut`).
static READ_CLASS_MUTATIONS: AtomicU64 = AtomicU64::new(0);
/// An exclusive/cleanup admission at a site declared `Read` or `Shared`: a NEW instance of
/// CLASS C (a hot path taking a heavier admission than the access needs).
static CLASS_REGRESSIONS: AtomicU64 = AtomicU64::new(0);
static CLASS_REGRESSION_FIRST: AtomicUsize = AtomicUsize::new(0);

/// RAII marker for a read-classified body (see the section header above).
pub(crate) struct ReadClassGuard {
    saved: u32,
}

impl Drop for ReadClassGuard {
    fn drop(&mut self) {
        let _ = READ_CLASS_DEPTH.try_with(|depth| depth.set(self.saved));
    }
}

/// Declares `caller` a read-classified site and marks this thread as inside one until the
/// returned guard drops. One relaxed counter and one TLS write; the site row is claimed once.
#[inline]
#[track_caller]
pub(crate) fn enter_read_class() -> ReadClassGuard {
    let caller = Location::caller();
    site_index(caller, SITE_KIND_READ);
    READ_CLASS_READS.fetch_add(1, Ordering::Relaxed);
    let _ = READ_CLASS_SITE.try_with(|cell| cell.set(Some(caller)));
    let saved = READ_CLASS_DEPTH
        .try_with(|depth| {
            let saved = depth.get();
            depth.set(saved.saturating_add(1));
            saved
        })
        .unwrap_or(0);
    ReadClassGuard { saved }
}

/// Whether a read-classified body is running on this thread.
#[inline]
pub(crate) fn read_class_active() -> bool {
    READ_CLASS_DEPTH
        .try_with(|depth| depth.get() != 0)
        .unwrap_or(false)
}

/// Called from the address-space state domain's `DerefMut`: the one way to mutate it. A
/// read-classified body reaching it means the classification is wrong.
#[inline]
pub(crate) fn note_read_class_mutation(site: &'static Location<'static>) {
    READ_CLASS_MUTATIONS.fetch_add(1, Ordering::Relaxed);
    let in_read = READ_CLASS_SITE.try_with(Cell::get).unwrap_or(None);
    let in_read_file = in_read
        .map(|l| l.file().rsplit('/').next().unwrap_or(""))
        .unwrap_or("<unknown>");
    let in_read_line = in_read.map_or(0, |l| l.line());
    debug_assert!(
        false,
        "CLASS C: read-classified body at {in_read_file}:{in_read_line} mutated the \
         address-space state domain (deref_mut at {}:{}:{})",
        site.file().rsplit('/').next().unwrap_or(""),
        site.line(),
        site.column(),
    );
}

/// Overrides a site's declared class (used by the batched pump to name its one admission).
pub(crate) fn declare_site_class(site: u16, kind: u8) {
    if let Some(slot_kind) = SITE_KEYS.kinds.get(usize::from(site)) {
        slot_kind.store(kind, Ordering::Release);
    }
}

/// An exclusive/cleanup admission at `site`: CLASS C regression if the site was declared a
/// lighter class. Counted in release; the first one names itself in a debug build.
pub(crate) fn note_class_regression(site: u16) {
    let Some(slot_kind) = SITE_KEYS.kinds.get(usize::from(site)) else {
        return;
    };
    let declared = slot_kind.load(Ordering::Acquire);
    if declared != SITE_KIND_READ && declared != SITE_KIND_SHARED {
        return;
    }
    CLASS_REGRESSIONS.fetch_add(1, Ordering::Relaxed);
    if let Some(slot_key) = SITE_KEYS.keys.get(usize::from(site))
        && CLASS_REGRESSION_FIRST
            .compare_exchange(0, slot_key.load(Ordering::Acquire), Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        && slot_key.load(Ordering::Acquire) != 0
    {
        // SAFETY: stored by `site_index` from a `&'static Location<'static>` and never changed.
        let location = unsafe { &*(slot_key.load(Ordering::Acquire) as *const Location<'static>) };
        debug_assert!(
            false,
            "CLASS C regression: site {}:{}:{} declared {:?} took an exclusive admission",
            location.file().rsplit('/').next().unwrap_or(""),
            location.line(),
            location.column(),
            declared,
        );
    }
}

/// Reads of the CLASS C guard, surfaced in `--counters` JSON as `admission_class`.
///
/// `vcpu_ownership_{memo,lock}` is the same class measured at the VM-global `vcpu_ownership`
/// mutex: `memo` checks served from a vCPU's own cached verdict (no VM-global lock at all) and
/// `lock` the ones that still had to take it because the ownership table moved. The ratio is the
/// guard for "a process-wide lock guarding one object's private data".
pub(crate) fn admission_class_json(out: &mut String) {
    use std::fmt::Write as _;
    let _ = write!(
        out,
        concat!(
            "\"admission_class\":{{\"read_class_reads\":{},\"read_class_mutations\":{},",
            "\"class_regressions\":{},\"class_regression_first\":{},",
            "\"vcpu_ownership_memo\":{},\"vcpu_ownership_lock\":{},",
            "\"vcpu_ownership_contended\":{},\"vcpu_ownership_contended_ns\":{},",
            "\"migration_depart_fallback\":{},\"migration_unwind_failed\":{},",
            "\"pump_admissions_per_ticket_permille\":{}}},"
        ),
        READ_CLASS_READS.load(Ordering::Relaxed),
        READ_CLASS_MUTATIONS.load(Ordering::Relaxed),
        CLASS_REGRESSIONS.load(Ordering::Relaxed),
        CLASS_REGRESSION_FIRST.load(Ordering::Relaxed),
        stat_total(STAT_VCPU_OWNERSHIP_MEMO),
        stat_total(STAT_VCPU_OWNERSHIP_SCAN),
        stat_total(STAT_VCPU_OWNERSHIP_CONTENDED),
        ticks_to_ns(stat_total(STAT_VCPU_OWNERSHIP_CONTENDED + 1)),
        stat_total(STAT_MIGRATION_DEPART_FALLBACK),
        stat_total(STAT_MIGRATION_UNWIND_FAILED),
        pump_admissions_per_ticket_permille(),
    );
}

/// Locks the VM-global `vcpu_ownership` mutex with the standard contended accounting.
/// Every acquisition of that mutex is a CLASS C instance (a process-wide lock consulted for one
/// vCPU's own record), so the acquisition is counted, not just the contended ones.
pub(crate) fn lock_vcpu_ownership<'a, T>(mutex: &'a RankedMutex<T>) -> RankedGuard<'a, T> {
    add_stat(STAT_VCPU_OWNERSHIP_SCAN, 1);
    lock_timed(mutex, STAT_VCPU_OWNERSHIP_CONTENDED)
}

/// A vCPU-ownership membership check served without the VM-global mutex (see
/// [`crate::hvf_sdk::HvfVcpu::require_owner_live`]).
pub(crate) fn record_vcpu_ownership_memo() {
    add_stat(STAT_VCPU_OWNERSHIP_MEMO, 1);
}

/// A vCPU's ownership memo: `(version << 1) | live`. Only the vCPU's own thread reads and writes
/// it, so relaxed ordering is exact; version 0 is never a real version, so slot 0 always misses.
pub(crate) const fn vcpu_ownership_memo(version: u64, live: bool) -> u64 {
    (version << 1) | if live { 1 } else { 0 }
}

pub(crate) const fn vcpu_ownership_memo_version(memo: u64) -> u64 {
    memo >> 1
}

pub(crate) const fn vcpu_ownership_memo_live(memo: u64) -> bool {
    memo & 1 == 1
}

/// The class-shaped pump metric: exclusive admissions per retirement ITEM, not per pass
/// (`admissions / tickets_released`, x1000). `admissions / passes_admitted` cannot see the class
/// at all -- one pass carries ~1.05 tickets, so it reads 1.000 whether or not per-item batching
/// happened. This one is 1000 when the pump takes an admission per ticket and falls as tickets
/// share an admission.
fn pump_admissions_per_ticket_permille() -> u64 {
    let released = stat_total(STAT_PUMP_PASS_RELEASED);
    if released == 0 {
        return 0;
    }
    stat_total(STAT_PUMP_ADMISSIONS)
        .saturating_mul(1000)
        .div_euclid(released)
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
        note_class_regression(site);
    }
    if !nested {
        thread_work(|work| {
            work.excl_admissions += 1;
            work.excl_wait_ticks += wait_ticks;
        });
    }
    let ns = ticks_to_ns(wait_ticks);
    if let Some(slot) = SITES.get(usize::from(site)) {
        // CLASS C positive guard with teeth: an exclusive admission that never publishes had no
        // HVF effect, i.e. it is a read (or a loop admitting per item) whatever `kind` it
        // declared. `note_class_regression` cannot see that -- a new `with_operation` site
        // declares Exclusive -- so this counts admissions against publications instead. The test
        // runs only when the admission count crosses a power of two, so the release cost is
        // `log2(n)` relaxed loads over the site's lifetime.
        let admissions = slot.exclusive.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
        if admissions >= SITE_NONPUBLISHING_TRAP_AT
            && admissions.is_power_of_two()
            && slot.published.load(Ordering::Relaxed) == 0
        {
            let name = SITE_KEYS
                .keys
                .get(usize::from(site))
                .and_then(|key| {
                    let key = key.load(Ordering::Acquire);
                    (key != 0).then(|| {
                        // SAFETY: stored by `site_index` from a `&'static Location<'static>`.
                        let location = unsafe { &*(key as *const Location<'static>) };
                        (
                            location.file().rsplit('/').next().unwrap_or("").to_string(),
                            location.line(),
                        )
                    })
                })
                .unwrap_or(("<unknown>".to_string(), 0));
            debug_assert!(
                false,
                "CLASS C: site {}:{} took {admissions} exclusive admissions and published none \
                 -- an exclusive admission with no HVF effect is a read, a per-item loop, or a \
                 lock taken for data it does not need",
                name.0,
                name.1,
            );
        }
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

/// CLASS C: the per-exit retirement check took the per-space row-count hint instead of the
/// process-global `acknowledgements` lock plus its two full ledger scans. `nonzero` = the hint
/// said a row exists for this space (the pass still runs, exactly as today).
pub(crate) fn record_retirement_hint(nonzero: bool) {
    add_stat(
        if nonzero {
            STAT_RETIREMENT_HINT_NONZERO
        } else {
            STAT_RETIREMENT_HINT_ZERO
        },
        1,
    );
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
/// CLASS C batching: one pass's single admission body, start to end (all its tickets).
static PUMP_BATCH_HOLD: CostHistogram = CostHistogram::new();

/// The precheck found no deferred, fully acknowledged row: returned without the gate.
pub(crate) fn record_pump_precheck_skip() {
    add_stat(STAT_PUMP_PRECHECK_SKIPS, 1);
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

// CLASS C batching (`hvf-exclusive-gate-saturation-shrink`): the pass takes ONE cleanup
// admission for all of its tickets instead of one per ticket. `passes_batched` counts those
// passes, `tickets_batched` the tickets acknowledged inside them, so
// `tickets_batched / passes_batched` is the batching factor and `admissions / passes_admitted`
// is the guard: it must fall to 1 (today it is the number of tickets a pass releases).
pub(crate) fn record_pump_batch_admission(requested: u64) -> u64 {
    let admitted = ticks();
    add_stat(STAT_PUMP_ADMISSIONS, 1);
    add_stat(STAT_PUMP_PASSES_BATCHED, 1);
    PUMP_ADMISSION_WAIT.record(ticks_to_ns(admitted.wrapping_sub(requested)));
    admitted
}

pub(crate) fn record_pump_batch_hold(admitted: u64) {
    PUMP_BATCH_HOLD.record(ticks_to_ns(ticks().wrapping_sub(admitted)));
}

/// CLASS C: how many tickets the largest single batched pump admission covered (the tail that
/// sets `batch_hold`'s max, and the bound `PUMP_TICKETS_PER_ADMISSION` exists to cap).
static PUMP_BATCH_TICKETS_MAX: AtomicU64 = AtomicU64::new(0);

pub(crate) fn record_pump_batch_tickets(count: usize) {
    let count = u64::try_from(count).unwrap_or(u64::MAX);
    PUMP_BATCH_TICKETS_MAX.fetch_max(count, Ordering::Relaxed);
    add_stat(STAT_PUMP_TICKETS_BATCHED, count);
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
    mutex: &'a RankedMutex<T>,
    owns_gate: impl FnOnce() -> bool,
) -> Option<RankedGuard<'a, T>> {
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
            rank_note_blocked_acquire(mutex.rank(), Location::caller());
            let started = ticks();
            let guard = mutex.lock_unchecked().unwrap_or_else(PoisonError::into_inner);
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
    out.push(',');
    render_cost_histogram(out, "batch_hold", &PUMP_BATCH_HOLD);
    out.push(',');
    let _ = write!(
        out,
        "\"pump_batch_tickets_max\":{},\"pump_admissions_per_ticket_permille\":{}}},",
        PUMP_BATCH_TICKETS_MAX.load(Ordering::Relaxed),
        pump_admissions_per_ticket_permille(),
    );
    admission_class_json(out);
    let _ = write!(
        out,
        "\"retirement_hint\":{{\"zero\":{},\"nonzero\":{}}},\"pump_batching\":{{\"passes_batched\":{},\"tickets_batched\":{}}},",
        stat_total(STAT_RETIREMENT_HINT_ZERO),
        stat_total(STAT_RETIREMENT_HINT_NONZERO),
        stat_total(STAT_PUMP_PASSES_BATCHED),
        stat_total(STAT_PUMP_TICKETS_BATCHED),
    );
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

// ---------------------------------------------------------------------------
// Per-syscall host-thread CPU time (hvf-glive-unattributed-slow-syscall-mass).
//
// A slow syscall's wall time splits into named waits (exclusive-gate admission, holds, the
// mapping lock, `cell.state`, an interruptible guest wait) and whatever is left.  The leftovers
// were 34-49% of all slow-syscall time on the desktop and could not be attributed: they are the
// difference between "the guest is waiting on us" and "the host thread was not running at all".
//
// This is the discriminator: `mach` thread CPU time over the same interval.  If a 1.9 s
// `mprotect` burns ~1.9 s of CPU, the time is work (or a spin) inside the shim/platform; if it
// burns ~5 ms, the thread was OFF-CPU for 1.9 s -- preempted by the host scheduler or parked on
// a lock no counter covers -- and no serialization counter will ever explain it.
//
// Two mach traps per syscall is not free on a ~13 us syscall, so this is OFF unless
// `LITEBOX_HVF_SYSCALL_CPU=1`: the shipped path is one relaxed load on a `OnceLock`.
// ---------------------------------------------------------------------------

// `mach_port_t` of the calling thread; `thread_info(THREAD_BASIC_INFO)` fills user+system time.
unsafe extern "C" {
    fn mach_thread_self() -> u32;
    fn thread_info(thread: u32, flavor: u32, info: *mut u32, count: *mut u32) -> i32;
}

const THREAD_BASIC_INFO_FLAVOR: u32 = 3;
const THREAD_BASIC_INFO_COUNT: u32 = 10;

static SYSCALL_CPU_ENABLED: OnceLock<bool> = OnceLock::new();

fn syscall_cpu_enabled() -> bool {
    *SYSCALL_CPU_ENABLED.get_or_init(|| {
        std::env::var_os("LITEBOX_HVF_SYSCALL_CPU").is_some_and(|value| value == "1")
    })
}

/// This host thread's accumulated CPU time in nanoseconds, or 0 when the probe is disabled (or
/// `thread_info` fails, which must never perturb a guest syscall).
pub(crate) fn thread_cpu_ns() -> u64 {
    if !syscall_cpu_enabled() {
        return 0;
    }
    // `thread_basic_info` = { user_time{seconds, microseconds}, system_time{...}, policy,
    // run_state, flags, suspend_count, sleep_time }: 10 `integer_t` words.
    let mut info = [0u32; 10];
    let mut count = THREAD_BASIC_INFO_COUNT;
    let kr = unsafe {
        thread_info(
            mach_thread_self(),
            THREAD_BASIC_INFO_FLAVOR,
            info.as_mut_ptr(),
            &mut count,
        )
    };
    if kr != 0 || count < 4 {
        return 0;
    }
    let us = u64::from(info[0]) * 1_000_000
        + u64::from(info[1])
        + u64::from(info[2]) * 1_000_000
        + u64::from(info[3]);
    us * 1_000
}

/// CPU nanoseconds between `start` (from [`thread_cpu_ns`]) and now; 0 when disabled.
pub(crate) fn thread_cpu_ns_since(start: u64) -> u64 {
    if start == 0 {
        return 0;
    }
    thread_cpu_ns().saturating_sub(start)
}

/// Session totals so the on-CPU share of guest-syscall wall time is readable without the ring.
static SYSCALL_CPU_NS: AtomicU64 = AtomicU64::new(0);
static SYSCALL_CPU_ACCOUNTED: AtomicU64 = AtomicU64::new(0);
static SYSCALL_CPU_OFF_NS: AtomicU64 = AtomicU64::new(0);

pub(crate) fn record_syscall_cpu(elapsed_ns: u64, cpu_ns: u64) {
    if cpu_ns == 0 {
        return;
    }
    SYSCALL_CPU_NS.fetch_add(cpu_ns, Ordering::Relaxed);
    SYSCALL_CPU_ACCOUNTED.fetch_add(1, Ordering::Relaxed);
    SYSCALL_CPU_OFF_NS.fetch_add(elapsed_ns.saturating_sub(cpu_ns), Ordering::Relaxed);
}

const SLOW_SYSCALL_NS: u64 = 100_000_000;
const SLOW_RING_LEN: usize = 512;
const SLOW_FIELD_NAMES: [&str; 31] = [
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
    // hvf-glive-unattributed-slow-syscall-mass: this host thread's CPU time over the same
    // interval (0 when LITEBOX_HVF_SYSCALL_CPU is not set). `elapsed - cpu` is time the thread
    // spent NOT running: host preemption or a lock no counter covers. Granularity is
    // THREAD_BASIC_INFO's microseconds, which is amply fine for a >=100 ms record.
    "cpu_ns",
];
const SLOW_FIELDS: usize = SLOW_FIELD_NAMES.len();
static SLOW_RING: [[AtomicU64; SLOW_FIELDS]; SLOW_RING_LEN] =
    [const { [const { AtomicU64::new(0) }; SLOW_FIELDS] }; SLOW_RING_LEN];
static SLOW_CURSOR: AtomicUsize = AtomicUsize::new(0);
static SLOWEST: [AtomicU64; SLOW_FIELDS] = [const { AtomicU64::new(0) }; SLOW_FIELDS];
static SLOWEST_SERVICE_NS: AtomicU64 = AtomicU64::new(0);

/// Records one syscall whose service time reached `SLOW_SYSCALL_NS`, attributed with this
/// thread's HVF work since the syscall's entry (`enter_syscall_origin`).
fn record_slow_syscall(
    space_id: HvfAddressSpaceId,
    nr: i32,
    elapsed_ns: u64,
    blocked_ns: u64,
    cpu_ns: u64,
) {
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
        cpu_ns,
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

fn render_rbnr(out: &mut String) {
    use std::fmt::Write as _;
    let (count, sum_ns, max_ns, buckets) = RBNR.snapshot();
    let _ = write!(
        out,
        "\"rbnr\":{{\"enabled\":{},\"count\":{},\"sum_ns\":{},\"max_ns\":{},\"buckets\":",
        u8::from(rbnr_enabled()),
        count, sum_ns, max_ns,
    );
    push_buckets(out, &buckets);
    let _ = write!(
        out,
        ",\"warned\":{},\"warns_suppressed\":{},\"warn_ns\":{},\"ring_min_ns\":{},\"pump_ns\":{},",
        RBNR_WARNED.load(Ordering::Relaxed),
        RBNR_WARNS_SUPPRESSED.load(Ordering::Relaxed),
        RBNR_WARN_NS,
        RBNR_RING_MIN_NS,
        RBNR_PUMP_NS.load(Ordering::Relaxed),
    );
    // Attribution health: `credited_ns` is the total of the intervals that got a span vector,
    // `named_sum_ns` the sum of their named spans (which OVER-cover, because `r6` is inside `r2`),
    // and `unattributed_ns` (below) is only the one-sided shortfall. `named/credited` is the
    // overlap factor; `batch_flush_intervals` is how many intervals a host thread banks before it
    // touches the shared lines.
    let _ = write!(
        out,
        "\"credited_ns\":{},\"named_sum_ns\":{},\"over_cover_ns\":{},\"batch_flush_intervals\":{},",
        RBNR_CREDITED_NS.load(Ordering::Relaxed),
        RBNR_NAMED_SUM_NS.load(Ordering::Relaxed),
        RBNR_OVER_COVER_NS.load(Ordering::Relaxed),
        RBNR_FLUSH_INTERVALS,
    );
    let _ = write!(
        out,
        "\"space_table\":{{\"len\":{},\"overflows\":{},\"releases\":{}}},",
        SPACE_TABLE_LEN,
        SPACE_TABLE_OVERFLOWS.load(Ordering::Relaxed),
        SPACE_SLOT_RELEASES.load(Ordering::Relaxed),
    );
    let _ = write!(
        out,
        "\"stall_ring\":{{\"recorded\":{},\"len\":{},\"warn_ns\":{}}},",
        RBNR_STALL_RECORDED.load(Ordering::Relaxed),
        RBNR_STALL_RING_LEN,
        RBNR_WARN_NS,
    );
    out.push_str("\"spans\":{");
    for (index, name) in RBNR_SPAN_NAMES.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        let _ = write!(
            out,
            "\"{name}\":{}",
            RBNR_SPAN_TOTALS[index].load(Ordering::Relaxed)
        );
    }
    out.push_str("},\"dominant\":{");
    for (index, name) in RBNR_SPAN_NAMES.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        let _ = write!(
            out,
            "\"{name}\":{{\"ns\":{},\"intervals\":{}}}",
            RBNR_DOMINANT_NS[index].load(Ordering::Relaxed),
            RBNR_DOMINANT_COUNT[index].load(Ordering::Relaxed)
        );
    }
    out.push_str("}},");

    let (count, sum_ns, max_ns, buckets) = INPUT_CONSUME.snapshot();
    let _ = write!(
        out,
        concat!(
            "\"input_consume\":{{\"count\":{},\"sum_ns\":{},\"max_ns\":{},",
            "\"warned\":{},\"warns_suppressed\":{},\"warn_ns\":{},\"buckets\":"
        ),
        count,
        sum_ns,
        max_ns,
        INPUT_CONSUME_WARNED.load(Ordering::Relaxed),
        INPUT_CONSUME_WARNS_SUPPRESSED.load(Ordering::Relaxed),
        INPUT_CONSUME_WARN_NS,
    );
    push_buckets(out, &buckets);
    out.push_str("},");
}

/// Renders `ring`'s live rows (oldest first). Step G fix-up: `rbnr_ring` is the most recent 16
/// intervals at or over 1 ms -- NOT the worst 16, and on a loaded desktop most of those land
/// between 1 and 2 ms, so it is a recency window, not a top-N. The worst-of window is the stall
/// ring ([`RBNR_STALL_RING`]), which keeps every interval at or over [`RBNR_WARN_NS`].
fn render_rbnr_ring_rows(
    out: &mut String,
    ring: &[[AtomicU64; RBNR_RING_FIELDS]],
    cursor: &AtomicUsize,
    len: usize,
) {
    let total_writes = cursor.load(Ordering::Acquire);
    let live = total_writes.min(len);
    let oldest = if total_writes > len {
        total_writes % len
    } else {
        0
    };
    out.push('[');
    for i in 0..live {
        if i > 0 {
            out.push(',');
        }
        let row = &ring[(oldest + i) % len];
        render_rbnr_row(out, row);
    }
    out.push(']');
}

fn render_rbnr_row(out: &mut String, row: &[AtomicU64; RBNR_RING_FIELDS]) {
    use std::fmt::Write as _;
    let values: [u64; RBNR_RING_FIELDS] = core::array::from_fn(|f| row[f].load(Ordering::Relaxed));
    let dominant = usize::try_from(values[5])
        .unwrap_or(0)
        .min(RBNR_SPAN_NAMES.len() - 1);
    let _ = write!(
        out,
        "{{\"wall_ms\":{},\"space_id\":{},\"pid\":{},\"tid\":{},\"rbnr_ns\":{},\"dominant\":\"{}\",\"pump_ns\":{},\"spans\":{{",
        values[0], values[1], values[2], values[3], values[4],
        RBNR_SPAN_NAMES[dominant], values[6 + RBNR_SPANS],
    );
    for (index, name) in RBNR_SPAN_NAMES.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        let _ = write!(out, "\"{name}\":{}", values[6 + index]);
    }
    out.push_str("}}");
}

fn render_rbnr_ring(out: &mut String) {
    render_rbnr_ring_rows(out, &RBNR_RING, &RBNR_RING_CURSOR, RBNR_RING_LEN);
}

fn render_rbnr_spaces(out: &mut String) {
    use std::fmt::Write as _;
    out.push('[');
    let mut first = true;
    for slot in &SPACE_TABLE {
        let tag = slot.tag.load(Ordering::Acquire);
        if tag == 0 || slot.rbnr_count.load(Ordering::Relaxed) == 0 {
            continue;
        }
        if !first {
            out.push(',');
        }
        first = false;
        let mut name = [0u8; 16];
        for (half, cell) in slot.comm.iter().enumerate() {
            name[half * 8..half * 8 + 8].copy_from_slice(&cell.load(Ordering::Relaxed).to_le_bytes());
        }
        let end = name.iter().position(|&b| b == 0).unwrap_or(name.len());
        let comm = core::str::from_utf8(&name[..end]).unwrap_or("");
        let buckets: [u64; LATENCY_BUCKETS] =
            core::array::from_fn(|i| slot.rbnr_buckets[i].load(Ordering::Relaxed));
        let _ = write!(
            out,
            "{{\"space_id\":{},\"pid\":{},\"comm\":\"{}\",\"count\":{},\"sum_ns\":{},\"max_ns\":{},\"pump_ns\":{},\"buckets\":",
            tag - 1,
            slot.pid.load(Ordering::Relaxed),
            comm,
            slot.rbnr_count.load(Ordering::Relaxed),
            slot.rbnr_sum_ns.load(Ordering::Relaxed),
            slot.rbnr_max_ns.load(Ordering::Relaxed),
            slot.rbnr_pump_ns.load(Ordering::Relaxed),
        );
        push_buckets(out, &buckets);
        out.push_str(",\"spans\":{");
        for (index, span_name) in RBNR_SPAN_NAMES.iter().enumerate() {
            if index > 0 {
                out.push(',');
            }
            let _ = write!(
                out,
                "\"{span_name}\":{}",
                slot.rbnr_spans[index].load(Ordering::Relaxed)
            );
        }
        out.push_str("},\"dominant\":{");
        for (index, span_name) in RBNR_SPAN_NAMES.iter().enumerate() {
            if index > 0 {
                out.push(',');
            }
            let _ = write!(
                out,
                "\"{span_name}\":{}",
                slot.rbnr_dom_ns[index].load(Ordering::Relaxed)
            );
        }
        out.push_str("}}");
    }
    out.push_str("],");
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
    /// CLASS A: this lock's rank in the global order ([`RANK_CELL_STATE`] today). `lock()`
    /// checks it and registers the hold, so an address space's state cannot be taken while a
    /// higher-ranked lock is held and the gate admission inside a `state` body is visible.
    rank: u32,
    /// CLASS R: this domain's mutation counter (see [`TimedGuard::drop`]). A reader that records
    /// it BEFORE the data it describes and finds it unchanged afterwards knows no mutation of this
    /// domain has completed since -- the whole basis of [`crate::hvf_memory::Versioned`]. Only
    /// ever bumped while `inner` is still locked.
    generation: AtomicU64,
}

pub(crate) struct TimedGuard<'a, T> {
    guard: MutexGuard<'a, T>,
    owner: &'a TimedMutex<T>,
    site: &'static Location<'static>,
    since: u64,
    work_at: ThreadWork,
    /// Whether this acquisition registered its rank in the held set (`false` for an unpublished
    /// cell; see [`TimedMutex::lock_unpublished`]).
    ranked_lock: bool,
    /// Set by [`Self::deref_mut`] (this domain's only mutation path), performed by [`Self::drop`].
    bump: bool,
}

impl<T> TimedMutex<T> {
    pub(crate) const fn new(value: T, tag: u64, rank: u32) -> Self {
        Self {
            inner: Mutex::new(value),
            holder: LockHolder::new(),
            tag,
            rank,
            generation: AtomicU64::new(0),
        }
    }

    /// This domain's mutation counter, readable without the lock. Only ever combined with a data
    /// read the way [`crate::hvf_memory::HvfAddressSpace::plan_locked`] and
    /// [`crate::hvf_memory::HvfAddressSpace::plan_lockless`] combine them.
    pub(crate) fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    /// [`Self::lock`] for a cell that is NOT yet reachable by any other thread: its `Arc` has not
    /// been published into `HvfMemory::spaces`, so no other thread can be inside this mutex and
    /// taking it cannot deadlock whatever the caller already holds. `create_address_space_with`
    /// takes it while it still holds `spaces` and `arenas` (the reverse of the usual order); that
    /// is safe by construction, and this is how the inventory says so instead of a rank that
    /// would be a lie. No rank check, and no held-set entry: nothing acquired inside such a body
    /// can be part of a cycle through this cell.
    #[track_caller]
    pub(crate) fn lock_unpublished(&self) -> std::sync::LockResult<TimedGuard<'_, T>> {
        self.lock_inner(Location::caller(), false)
    }

    #[track_caller]
    pub(crate) fn lock(&self) -> std::sync::LockResult<TimedGuard<'_, T>> {
        let site = Location::caller();
        rank_check(self.rank, site);
        self.lock_inner(site, true)
    }

    fn lock_inner(
        &self,
        site: &'static Location<'static>,
        ranked: bool,
    ) -> std::sync::LockResult<TimedGuard<'_, T>> {
        let (guard, poisoned) = match self.inner.try_lock() {
            Ok(guard) => (guard, false),
            Err(TryLockError::Poisoned(poisoned)) => (poisoned.into_inner(), true),
            Err(TryLockError::WouldBlock) => {
                rank_note_blocked_acquire(self.rank, site);
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
        if ranked {
            rank_hold(self.rank);
        }
        let guard = TimedGuard {
            guard,
            owner: self,
            site,
            since,
            work_at: current_thread_work(),
            ranked_lock: ranked,
            bump: false,
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
        // CLASS C guard: the address-space state domain's only mutation path. A body the
        // inventory classified `Read` (no VM admission, no mutation) must never reach it.
        if read_class_active() {
            note_read_class_mutation(self.site);
        }
        // CLASS R: arm this domain's mutation counter. The bump itself is performed by `drop`, so
        // it lands while `self.guard` is still held -- no reader admitted afterwards can miss a
        // completed mutation, and a reader admitted before cannot have seen its effects.
        self.bump = true;
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
        // CLASS R: runs before `guard` itself unlocks, so the counter reaches its new value while
        // this thread still holds the mutex.
        if self.bump {
            self.owner.generation.fetch_add(1, Ordering::Release);
        }
        self.owner.holder.clear();
        if self.ranked_lock {
            rank_release(self.owner.rank);
        }
    }
}

// ===========================================================================================
// CLASS A: one global lock rank, enforced by the lock wrapper (step GA).
//
// A thread must never block while it holds a lock. "Block" covers four shapes: waiting for
// another lock, joining the VM operation-gate FIFO (a wait of up to `OPERATION_WAIT_TIMEOUT`),
// waiting on a condvar / channel / park, and making a slow host call. This section gives every
// lock in the HVF memory and vCPU path a rank, keeps a per-thread held set, and counts (release)
// plus asserts (debug) each shape at its call site, so a new instance of the class is named the
// first time it happens instead of by a future soak. The fix therefore lives in the shared
// primitive ([`RankedMutex`] / [`RankedRwLock`] / [`TimedMutex`] / the gate admission wrappers),
// not at one site: converting a field's type is the only change a call site needs.
//
// WHAT IS ENFORCED AND WHAT IS ONLY INSTRUMENTED (stated here because the section's title is
// broader than its guarantee). Two of the five kinds are counted and reported but NEVER fatal:
//   * [`RK_BLOCK_ACQUIRE`] -- a thread blocked acquiring lock L while holding locks ranked below
//     L. Legal and deadlock-free (it is a convoy, not a cycle); it is the shape every mutation
//     body performs, and removing it is `hvf-exclusive-gate-saturation-shrink`, not this step.
//   * [`RK_HOST_CALL`] -- a host `hv_vm_map` / `mach_vm_*` call made while holding a lock. Also
//     legal, also the ordinary body of a mutation.
// The other three -- [`RK_OUT_OF_RANK`] (the ABBA shape: acquiring a rank at or below one already
// held), [`RK_WAIT_WHILE_HOLDING`] and [`RK_GATE_ADMIT`] -- are the class proper and are asserted
// to be zero. So the honest headline is: "no thread blocks while holding a ranked lock" is
// ENFORCED for the three cycle-bearing shapes and INSTRUMENTED for the two convoy shapes, whose
// counts are published per call site rather than claimed to be zero.
// ===========================================================================================

/// The rank order, derived from the inventory (`.gm/syscall-bench/steps/GA2/inventory.md` §1): a
/// lock may only be acquired while every lock this thread already holds ranks strictly lower.
///
/// Ranks 0-8 are the `HvfBackend` locks a guest thread takes on its way INTO a run (thread slot,
/// participant recovery, the lane's own lock, view retirement, vDSO, shared init, participant,
/// view spaces); 9-21 bracket the VM operation frame and the address-space manager's own order
/// (the order `acknowledge_retirement` already used inside its admission) plus the file-origin and
/// host-VA registries a mutation body takes while it holds them; 22-24 are the SDK's; 25-27 are the
/// LANE POOL GROUP and sit ABOVE all of those, for a reason the previous pass had backwards; 28 is
/// the gate mutex leaf.
///
/// Why the lane pool group is last: a lane lease is released from wherever the lease happens to
/// drop, and that includes inside a mutation body -- `release_retained_lane` runs before every
/// host wait, before the exclusive-operation FIFO join and before every contended
/// [`RankedMutex`], so `release_lane` takes the pool and the lane slot while the calling thread
/// holds `gate_own` / `pump` / `cell_state` / `arenas` / `backings`. Ranking the pool BELOW the
/// memory order (its position in the first pass) made every one of those releases an asserted
/// `out_of_rank` -- 703 of them on one desktop drive -- not a rare race but the ordinary release
/// path. The pool is a scheduler resource acquired on both sides of every VM operation, so it
/// cannot sit inside the order those operations nest in; it ranks above it. This is safe because a
/// thread holding the pool acquires nothing but the lane slot (every pool body is pure), so no
/// cycle is introduced and none is hidden: a pool holder that went on to take `gate_own` would
/// still be flagged, which is the ABBA shape this order exists to catch.
pub(crate) const RANK_BACKEND_INSTALL: u32 = 0;
pub(crate) const RANK_THREAD_SLOT: u32 = 1;
pub(crate) const RANK_PARTICIPANT_RECOVERY: u32 = 2;
pub(crate) const RANK_LANE: u32 = 3;
pub(crate) const RANK_VIEW_RETIREMENT: u32 = 4;
pub(crate) const RANK_VDSO_CLOCK: u32 = 5;
pub(crate) const RANK_SHARED_INIT: u32 = 6;
pub(crate) const RANK_PARTICIPANT: u32 = 7;
pub(crate) const RANK_VIEW_SPACES: u32 = 8;
/// The VM operation frame: exclusive / cleanup / capability / batched AND the existing-vCPU
/// ("shared") frame. Not a mutex -- a frame a thread owns while its body runs, registered by
/// [`rank_hold_gate_own`]. Both frame kinds share one rank because the class is the same: a
/// thread that owns a frame must not block on anything below it.
pub(crate) const RANK_GATE_OWN: u32 = 9;
/// The two process-global residual slots (`PROCESS_HVF_MEMORY_CREATE_RESIDUAL`,
/// `PROCESS_MIRROR_PLAN_RESIDUAL`). Both are locked *inside* a mutation body -- i.e. after
/// `rank_hold_gate_own()` -- and `retry_hvf_memory_create_residual` blocks on the first one for
/// up to `OPERATION_WAIT_TIMEOUT`, which is T1g's exact shape. They therefore rank just ABOVE
/// `gate_own` (and below the space locks a body takes while holding them), so that holding one
/// and then joining the FIFO is flagged as [`RK_GATE_ADMIT`] without flagging the body's own
/// legal `create_residual -> cell_state -> ... -> gate_mutex` descent.
pub(crate) const RANK_CREATE_RESIDUAL: u32 = 10;
pub(crate) const RANK_MIRROR_RESIDUAL: u32 = 11;
pub(crate) const RANK_PUMP: u32 = 12;
pub(crate) const RANK_CELL_STATE: u32 = 13;
pub(crate) const RANK_SPACES: u32 = 14;
pub(crate) const RANK_ARENAS: u32 = 15;
pub(crate) const RANK_BACKINGS: u32 = 16;
pub(crate) const RANK_SHARED_BACKINGS: u32 = 17;
pub(crate) const RANK_ACKS: u32 = 18;
/// The process-global file-origin registry (`FILE_ORIGINS.table`). Its doc comment used to call
/// it "the innermost lock of this module", which is exactly why it needs a rank: it is taken
/// inside a space's `state`-locked commit closures, i.e. above `acks` in the commit order.
pub(crate) const RANK_FILE_ORIGINS: u32 = 19;
/// The host-VA registry (`hvf_backing::HOST_RESOURCES`) and the host-VA acquisition serializer
/// (`hvf_backing::HOST_ADDRESS_ACQUISITION`): taken INSIDE a mutation body, i.e. after
/// `rank_hold_gate_own()` and above the space's own locks, and held ACROSS the `mach_vm_*` /
/// `mmap` host calls that make up the bulk of a mutation's hold time (T2d-x3/x4). Ranking them is
/// what turns those calls from invisible into `host_call_while_holding` rows that name a lock.
/// `host_address_acq` is the LOWER of the two: `HvfHostBacking::allocate` takes the acquisition
/// serializer first and the resource registry inside it (hvf_backing.rs ~1508).
pub(crate) const RANK_HOST_ADDRESS_ACQ: u32 = 20;
pub(crate) const RANK_HOST_RESOURCES: u32 = 21;
pub(crate) const RANK_MAPPING_REGISTRY: u32 = 22;
pub(crate) const RANK_SDK_CALL: u32 = 23;
pub(crate) const RANK_VCPU_OWNERSHIP: u32 = 24;
// --- The lane pool group: above the memory order, see the block comment above. ---------------
/// `HvfBackend::free`: the lane pool. Acquired on the way into a run (nothing held) and released
/// from whatever the lease's drop site holds, so it ranks above every lock it can be nested in.
pub(crate) const RANK_LANE_POOL: u32 = 25;
/// `PooledLane::state`: the lane slot. Always taken with the pool already held, so it ranks just
/// above it.
pub(crate) const RANK_LANE_SLOT: u32 = 26;
pub(crate) const RANK_LANE_MAINTENANCE: u32 = 27;
/// The operation-gate mutex: a LEAF. It is held for a handful of instructions and never across
/// another acquisition or a wait, so it ranks highest and is deliberately NOT added to the held
/// set -- otherwise every `mark_published` / `require_live` inside a mutation body would hide
/// from the FIFO check the locks the body really holds. Named here so the rank list is the
/// complete order; no `RankedMutex` carries it, because `lock_gate` is the gate's only acquisition
/// path and it never registers (see [`lock_gate`]).
pub(crate) const RANK_GATE_MUTEX: u32 = 28;
const RANK_SLOTS: u32 = 29;
/// Ranks per held-set word: 0..[`RANK_WORD0`]-1 live in `lo`, the rest in `hi`.
const RANK_WORD0: u32 = 16;
const RANK_NAMES: [&str; RANK_SLOTS as usize] = [
    "backend_install",
    "thread_slot",
    "participant_recovery",
    "lane",
    "view_retirement",
    "vdso_clock",
    "shared_init",
    "participant",
    "view_spaces",
    "gate_own",
    "create_residual",
    "mirror_residual",
    "pump",
    "cell_state",
    "spaces",
    "arenas",
    "backings",
    "shared_backings",
    "acks",
    "file_origins",
    "host_address_acq",
    "host_resources",
    "mapping_registry",
    "sdk_call",
    "vcpu_ownership",
    "lane_pool",
    "lane_slot",
    "lane_maintenance",
    "gate_mutex",
];

/// Violation kinds. `RK_BLOCK_ACQUIRE` (blocking on a *higher-ranked* lock while holding a
/// lower-ranked one) and `RK_HOST_CALL` are counted and reported but NOT asserted: both are
/// deadlock-free legal shapes that a real mutation body performs on every mutation (a host
/// `hv_vm_map` / `hv_vm_protect` under `cell.state`), and removing them is the work of
/// `hvf-exclusive-gate-saturation-shrink` (T2d-x3/x4), not of the rank discipline. The other
/// three are the class proper and must be zero (§inventory).
pub(crate) const RK_OUT_OF_RANK: usize = 0;
pub(crate) const RK_BLOCK_ACQUIRE: usize = 1;
pub(crate) const RK_WAIT_WHILE_HOLDING: usize = 2;
pub(crate) const RK_GATE_ADMIT: usize = 3;
pub(crate) const RK_HOST_CALL: usize = 4;
const RK_COUNT: usize = 5;
const RK_NAMES: [&str; RK_COUNT] = [
    "out_of_rank",
    "block_acquire",
    "wait_while_holding",
    "gate_admit_while_holding",
    "host_call_while_holding",
];
const RK_ASSERTED_MASK: u32 = (1 << RK_OUT_OF_RANK) | (1 << RK_WAIT_WHILE_HOLDING) | (1 << RK_GATE_ADMIT);

/// 8 bits of hold count per rank, packed 16 ranks per word across two 128-bit words held in ONE
/// thread-local cell (so the hot path is still a single TLS read), for [`RANK_SLOTS`] ranks.
/// Nesting (two different address spaces' `cell.state`, a same-owner nested gate admission, an
/// existing-vCPU frame inside an exclusive one) is exact rather than collapsing to a bit, and all
/// 27 ranks fit with room to spare. A hold that would overflow its field is never dropped
/// silently: it saturates at 255 and is counted in `rank_hold_overflows`, and `rank_release`
/// never decrements past 0 -- so a saturated or released-twice field can never wrap into its
/// neighbour's field and never masquerade as a zero.
const RANK_BITS: u32 = 8;
const RANK_MASK: u128 = 0xFF;
const RANK_HOLD_MAX: u128 = RANK_MASK;

thread_local! {
    static HELD_RANKS: Cell<(u128, u128)> = const { Cell::new((0, 0)) };
}

/// A hold that saturated instead of being recorded (see [`RANK_BITS`]). Published in
/// `--counters` as `rank_hold_overflows`, so "the held set is exact" is a checkable claim.
// ===========================================================================================
// The lock inventory is ENFORCEABLE (step GA2).
//
// The first pass enumerated the locks once, in prose, in a scratch file -- and rotted: two of its
// own findings were "a lock the enumeration missed" and "no lint makes it enforceable". This
// section moves the enumeration into the build, as a TABLE OF INDIVIDUAL LOCKS, not a count.
//
// [`lock_inventory_selfcheck`] re-derives the table from each covered file's source AT RUN TIME
// (the source is embedded with `include_str!`, so the check cannot be skipped or fall out of date
// with the file it guards) and reports a difference as an error plus
// `lock_inventory.mismatches`, asserted in a debug build. A count would not do: a per-file delta
// is blind to `Mutex::default()` / `RwLock::default()`, to a commit that adds one unranked and one
// ranked lock, and it false-positives on a `Mutex::new(` written inside a comment -- which in a
// debug build is a hard abort. So the check strips comments and string literals, classifies each
// construction by the type token that owns it (`Mutex` / `RankedMutex` / `TimedMutex` / `RwLock` /
// `RankedRwLock`, read as a whole token rather than by substring), names it by the binding it is
// assigned to, and reads the `RANK_*` constant out of its arguments. Every lock in a covered file
// is in the table, ranked or not; adding or removing any one of them, or changing any one's rank,
// is a deliberate edit to a row that names the lock.
//
// Unranked rows and why they may stay unranked (each is a written disposition, not an omission):
//
// * `hvf_backend.rs` -- `bound_entries`: cannot block. Touched only under `LITEBOX_HVF_BOUND=1`
//   (off by default), only for a `Vec` push / remove of an `Arc<BoundEntry>`; the eviction it
//   names is signalled through an `AtomicBool`, not through this lock.
// * `hvf_sdk.rs` -- `state`: `HvfVmOperationState`'s own mutex, i.e. the gate mutex itself, the
//   order's leaf, deliberately never entered into the held set, taken only through [`lock_gate`].
// * `hvf_vcpu.rs` -- the vCPU control-plane leaves (`SYNCHRONIZATION_BARRIER`,
//   `RUN_COMPLETION_BARRIER`, `PROCESS_VCPU_REAPER_INIT`, `PROCESS_VCPU_REGISTRY`, `slots`,
//   `state` x4, `mailbox`, `progress`, `admission` x2, `attempt` x2, `cancellation_slot`,
//   `run_attempt`, `value`, `waiter`). Cannot block: each is held for a handful of instructions,
//   and every park on a condvar paired with one of them is already a named
//   [`rank_note_blocking_wait`] site (11 of them in this file) -- which is what makes the one REAL
//   instance among them (`hold_vcpu_run_completion_barrier`, witness-only) visible.
// * `hvf_backing.rs` -- `start`: `wait_for_preclaim_start`'s coordination mutex, for the file's own
//   host-only preclaim witness (a thread waiting for another thread's preclaim to start); no guest
//   path, no mutation and no VM operation reaches it.
//
// Outside the covered set (documented boundary, not silently excluded): `lib.rs` (the platform's
// own thread/IO locks: `stdin_doorbell`, `stdout_lock`, `stderr_lock`, `shared_page_registry`,
// `cow_regions`, the timer `deadline`, `ThreadHandle::id`, the NAT engine) and `hvf.rs` (the
// smoke-witness statics). They are not part of the VM-operation / memory-mutation path this order
// describes; `lib.rs`'s own parks are instrumented individually.
// ===========================================================================================

/// One lock construction site, as the source states it: what kind of lock, the binding it is
/// assigned to, and the `RANK_*` constant in its arguments (`"-"` when it has none).
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
struct LockSite {
    kind: &'static str,
    name: String,
    rank: String,
}

const fn is_ident_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// `source` with comments and string literals blanked out (newlines kept, so every offset still
/// means the same line): the inventory counts CONSTRUCTIONS, and a `Mutex::new(` written in prose
/// or in a string is not one.
fn strip_comments_and_strings(source: &str) -> String {
    let chars: Vec<char> = source.chars().collect();
    let mut out = String::with_capacity(chars.len());
    let mut i = 0;
    while i < chars.len() {
        match chars[i] {
            '/' if chars.get(i + 1) == Some(&'/') => {
                while i < chars.len() && chars[i] != '\n' {
                    out.push(' ');
                    i += 1;
                }
            }
            '/' if chars.get(i + 1) == Some(&'*') => {
                let mut depth = 1usize;
                out.push_str("  ");
                i += 2;
                while i < chars.len() && depth > 0 {
                    if chars.get(i + 1) == Some(&'*') && chars[i] == '/' {
                        depth += 1;
                        out.push_str("  ");
                        i += 2;
                    } else if chars.get(i + 1) == Some(&'/') && chars[i] == '*' {
                        depth -= 1;
                        out.push_str("  ");
                        i += 2;
                    } else {
                        out.push(if chars[i] == '\n' { '\n' } else { ' ' });
                        i += 1;
                    }
                }
            }
            '"' => {
                out.push(' ');
                i += 1;
                while i < chars.len() && chars[i] != '"' {
                    if chars[i] == '\\' {
                        out.push(' ');
                        i += 1;
                    }
                    if i < chars.len() {
                        out.push(if chars[i] == '\n' { '\n' } else { ' ' });
                        i += 1;
                    }
                }
                if i < chars.len() {
                    out.push(' ');
                    i += 1;
                }
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    out
}

/// The identifier starting at or after `start`.
fn ident_at(chars: &[char], start: usize) -> String {
    let mut i = start.min(chars.len());
    while i < chars.len() && !is_ident_char(chars[i]) {
        i += 1;
    }
    let mut out = String::new();
    while i < chars.len() && is_ident_char(chars[i]) {
        out.push(chars[i]);
        i += 1;
    }
    out
}

/// The identifier ending at or before `end`.
fn ident_before(chars: &[char], end: usize) -> String {
    let mut i = end.min(chars.len());
    while i > 0 && !is_ident_char(chars[i - 1]) {
        i -= 1;
    }
    let mut j = i;
    while j > 0 && is_ident_char(chars[j - 1]) {
        j -= 1;
    }
    chars[j..i].iter().collect()
}

/// The binding a construction at `at` is assigned to: `static NAME:`, `let NAME =`, `NAME:` /
/// `field:` on the same statement, or `NAME.get_or_init(...)` for a lazily built static. Falls
/// back to `line:<n>` for a shape that binds no name, which is itself identity-bearing (the row
/// moves when the line does, and that is the point).
fn lock_name(chars: &[char], at: usize) -> String {
    let window_start = at.saturating_sub(300);
    let window = &chars[window_start..at];
    let line = chars[..at].iter().filter(|&&c| c == '\n').count() + 1;
    let cut = window
        .iter()
        .rposition(|&c| c == ';' || c == '{' || c == '}')
        .map_or(0, |i| i + 1);
    let stmt = &window[cut..];
    // `FOO.get_or_init(|| { Ctor::new(..) })`: the name is before the `.get_or_init`.
    if let Some(at) = find_str(window, ".get_or_init(") {
        let name = ident_before(window, at);
        if !name.is_empty() {
            return name;
        }
    }
    for marker in ["static ", "let "] {
        if let Some(at) = find_str(stmt, marker) {
            let name = ident_at(stmt, at + marker.len());
            if !name.is_empty() {
                return name;
            }
        }
    }
    // `name:` -- but not the `:` of a `Type::` path, which would yield the type's name.
    let mut index = stmt.len();
    while index > 0 {
        index -= 1;
        if stmt[index] != ':' {
            continue;
        }
        let previous = index.checked_sub(1).and_then(|i| stmt.get(i));
        if previous == Some(&':') || stmt.get(index + 1) == Some(&':') {
            continue;
        }
        let name = ident_before(stmt, index);
        if !name.is_empty() {
            return name;
        }
    }
    format!("line:{line}")
}

/// The last occurrence of `needle` in `chars`, as a char index.
fn find_str(chars: &[char], needle: &str) -> Option<usize> {
    let needle: Vec<char> = needle.chars().collect();
    if needle.is_empty() || needle.len() > chars.len() {
        return None;
    }
    (0..=chars.len() - needle.len())
        .rev()
        .find(|&at| &chars[at..at + needle.len()] == needle.as_slice())
}

/// The `RANK_*` constant named anywhere in a construction's argument list, or `"-"`.
fn lock_rank(chars: &[char], open: usize) -> String {
    let mut depth = 0usize;
    let mut i = open;
    while i < chars.len() {
        match chars[i] {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    break;
                }
            }
            _ => {}
        }
        i += 1;
    }
    let args: String = chars[open..i.min(chars.len())].iter().collect();
    match args.find("RANK_") {
        Some(at) => {
            let rest = &args[at..];
            let end = rest
                .find(|c: char| !is_ident_char(c))
                .unwrap_or(rest.len());
            rest[..end].to_string()
        }
        None => "-".to_string(),
    }
}

/// Every lock construction in `source`, sorted: `Mutex::new` / `Mutex::default` (unranked),
/// `RankedMutex::new` / `TimedMutex::new` (ranked mutexes), `RwLock::new` / `RankedRwLock::new`.
/// The owner is read as a whole identifier token, so `RankedMutex::new(` is NOT counted as a
/// `Mutex::new(` -- the substring arithmetic the first pass used was the reason the check could
/// not tell the two apart.
fn lock_sites(source: &str) -> Vec<LockSite> {
    let clean = strip_comments_and_strings(source);
    let chars: Vec<char> = clean.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i + 5 < chars.len() {
        if chars[i] == ':' && chars[i + 1] == ':' {
            let rest: String = chars[i..(i + 12).min(chars.len())].iter().collect();
            let open_rel = if rest.starts_with("::new(") {
                5
            } else if rest.starts_with("::default(") {
                9
            } else {
                i += 1;
                continue;
            };
            let mut start = i;
            while start > 0 && is_ident_char(chars[start - 1]) {
                start -= 1;
            }
            let owner: String = chars[start..i].iter().collect();
            let (kind, ranked) = match owner.as_str() {
                "Mutex" => ("mutex", false),
                "RwLock" => ("rwlock", false),
                "RankedMutex" | "TimedMutex" => ("mutex", true),
                "RankedRwLock" | "TimedRwLock" => ("rwlock", true),
                _ => {
                    i += 1;
                    continue;
                }
            };
            let open = i + open_rel;
            let rank = if ranked {
                lock_rank(&chars, open)
            } else {
                "-".to_string()
            };
            out.push(LockSite {
                kind,
                name: lock_name(&chars, start),
                rank,
            });
            i = open;
        }
        i += 1;
    }
    out.sort();
    out
}

/// The inventory itself: every lock in a covered file, as `(kind, binding, rank)`. The source of
/// each file is embedded in the binary by `include_str!`, so the check cannot drift from the file
/// it guards and needs no filesystem access at run time.
const LOCK_INVENTORY: [(&str, &str, &[(&str, &str, &str)]); 5] = [
    // hvf_backend.rs -- 14 locks
    ("hvf_backend.rs", include_str!("hvf_backend.rs"), &[
        ("mutex", "HVF_BACKEND_INSTALL", "RANK_BACKEND_INSTALL"),
        ("mutex", "bound_entries", "-"),
        ("mutex", "current", "RANK_THREAD_SLOT"),
        ("mutex", "free", "RANK_LANE_POOL"),
        ("mutex", "lane", "RANK_LANE"),
        ("mutex", "owner", "RANK_LANE_MAINTENANCE"),
        ("mutex", "participant", "RANK_PARTICIPANT"),
        ("mutex", "participant_recovery", "RANK_PARTICIPANT_RECOVERY"),
        ("mutex", "pending_view_retirement", "RANK_VIEW_RETIREMENT"),
        ("mutex", "requested", "RANK_LANE_MAINTENANCE"),
        ("mutex", "shared_initialization", "RANK_SHARED_INIT"),
        ("mutex", "state", "RANK_LANE_SLOT"),
        ("mutex", "vdso_clock", "RANK_VDSO_CLOCK"),
        ("rwlock", "view_spaces", "RANK_VIEW_SPACES"),
    ]),
    // hvf_memory.rs -- 12 locks
    ("hvf_memory.rs", include_str!("hvf_memory.rs"), &[
        ("mutex", "PROCESS_HVF_MEMORY_CREATE_RESIDUAL", "RANK_CREATE_RESIDUAL"),
        ("mutex", "PROCESS_MIRROR_PLAN_RESIDUAL", "RANK_MIRROR_RESIDUAL"),
        ("mutex", "acknowledgements", "RANK_ACKS"),
        ("mutex", "arenas", "RANK_ARENAS"),
        ("mutex", "backings", "RANK_BACKINGS"),
        ("mutex", "retirement_pump", "RANK_PUMP"),
        ("mutex", "retirement_pump", "RANK_PUMP"),
        ("mutex", "shared_backings", "RANK_SHARED_BACKINGS"),
        ("mutex", "spaces", "RANK_SPACES"),
        ("mutex", "state", "RANK_CELL_STATE"),
        ("mutex", "state", "RANK_CELL_STATE"),
        ("mutex", "table", "RANK_FILE_ORIGINS"),
    ]),
    // hvf_sdk.rs -- 4 locks
    ("hvf_sdk.rs", include_str!("hvf_sdk.rs"), &[
        ("mutex", "mapping_registry", "RANK_MAPPING_REGISTRY"),
        ("mutex", "sdk_call", "RANK_SDK_CALL"),
        ("mutex", "state", "-"),
        ("mutex", "vcpu_ownership", "RANK_VCPU_OWNERSHIP"),
    ]),
    // hvf_vcpu.rs -- 17 locks
    ("hvf_vcpu.rs", include_str!("hvf_vcpu.rs"), &[
        ("mutex", "PROCESS_VCPU_REAPER_INIT", "-"),
        ("mutex", "PROCESS_VCPU_REGISTRY", "-"),
        ("mutex", "RUN_COMPLETION_BARRIER", "-"),
        ("mutex", "SYNCHRONIZATION_BARRIER", "-"),
        ("mutex", "admission", "-"),
        ("mutex", "admission", "-"),
        ("mutex", "attempt", "-"),
        ("mutex", "attempt", "-"),
        ("mutex", "cancellation_slot", "-"),
        ("mutex", "mailbox", "-"),
        ("mutex", "progress", "-"),
        ("mutex", "run_attempt", "-"),
        ("mutex", "slots", "-"),
        ("mutex", "state", "-"),
        ("mutex", "state", "-"),
        ("mutex", "value", "-"),
        ("mutex", "waiter", "-"),
    ]),
    // hvf_backing.rs -- 3 locks
    ("hvf_backing.rs", include_str!("hvf_backing.rs"), &[
        ("mutex", "HOST_ADDRESS_ACQUISITION", "RANK_HOST_ADDRESS_ACQ"),
        ("mutex", "HOST_RESOURCES", "RANK_HOST_RESOURCES"),
        ("mutex", "start", "-"),
    ]),
];

static LOCK_INVENTORY_MISMATCHES: AtomicU64 = AtomicU64::new(0);

fn render_lock_site(site: &LockSite) -> String {
    format!("{}/{}:{}", site.kind, site.name, site.rank)
}

/// Verifies [`LOCK_INVENTORY`] against the sources it names, once per process, LOCK BY LOCK. A
/// lock that appears without a rank -- i.e. one the table above does not list -- is reported as an
/// error, counted (published as `lock_inventory.mismatches`) and asserted in a debug build, so
/// "the enumeration cannot silently rot" is a checked property and not a promise. Callers:
/// [`crate::hvf_backend::HvfBackend::create`] (every runner start, release included) and the
/// `--counters` readout.
pub(crate) fn lock_inventory_selfcheck() -> usize {
    static CHECKED: OnceLock<usize> = OnceLock::new();
    *CHECKED.get_or_init(|| {
        let mut mismatches = 0usize;
        for (name, source, expected) in LOCK_INVENTORY {
            let actual = lock_sites(source);
            let expected: Vec<LockSite> = expected
                .iter()
                .map(|(kind, name, rank)| LockSite {
                    kind,
                    name: (*name).to_string(),
                    rank: (*rank).to_string(),
                })
                .collect();
            if actual == expected {
                continue;
            }
            mismatches += 1;
            LOCK_INVENTORY_MISMATCHES.fetch_add(1, Ordering::Relaxed);
            let added: Vec<String> = actual
                .iter()
                .filter(|site| !expected.contains(site))
                .map(render_lock_site)
                .collect();
            let missing: Vec<String> = expected
                .iter()
                .filter(|site| !actual.contains(site))
                .map(render_lock_site)
                .collect();
            litebox_util_log::error!(
                file:? = name,
                added:? = added.join(","),
                missing:? = missing.join(",");
                "CLASS A lock inventory: this file's locks do not match the table -- every lock must carry a rank or be listed here"
            );
        }
        debug_assert_eq!(
            mismatches,
            0,
            "CLASS A lock inventory out of date: a lock appeared, disappeared or changed rank in a covered file"
        );
        mismatches
    })
}

static RANK_HOLD_OVERFLOWS: AtomicU64 = AtomicU64::new(0);

/// `(lo, hi)`: the held set as two words of [`RANK_WORD0`] ranks each.
fn held_ranks() -> (u128, u128) {
    HELD_RANKS.try_with(Cell::get).unwrap_or((0, 0))
}

/// Which word of the held set `rank` lives in, and its bit offset inside that word.
const fn rank_word_offset(rank: u32) -> (bool, u32) {
    if rank < RANK_WORD0 {
        (false, rank * RANK_BITS)
    } else {
        (true, (rank - RANK_WORD0) * RANK_BITS)
    }
}

fn rank_hold(rank: u32) {
    if rank >= RANK_SLOTS {
        return;
    }
    let (high, shift) = rank_word_offset(rank);
    if shift >= 128 {
        return;
    }
    let _ = HELD_RANKS.try_with(|cell| {
        let (mut lo, mut hi) = cell.get();
        let word = if high { &mut hi } else { &mut lo };
        if (*word >> shift) & RANK_MASK == RANK_HOLD_MAX {
            RANK_HOLD_OVERFLOWS.fetch_add(1, Ordering::Relaxed);
        } else {
            *word += 1u128 << shift;
        }
        cell.set((lo, hi));
    });
}

fn rank_release(rank: u32) {
    if rank >= RANK_SLOTS {
        return;
    }
    let (high, shift) = rank_word_offset(rank);
    if shift >= 128 {
        return;
    }
    let _ = HELD_RANKS.try_with(|cell| {
        let (mut lo, mut hi) = cell.get();
        let word = if high { &mut hi } else { &mut lo };
        if (*word >> shift) & RANK_MASK != 0 {
            *word -= 1u128 << shift;
        }
        cell.set((lo, hi));
    });
}

/// The bits of every rank strictly above `rank`, as `(lo, hi)` masks: if any is set in the held
/// set, acquiring `rank` here closes a cycle (the ABBA shape T1g was).
fn ranks_above(rank: u32) -> (u128, u128) {
    if rank + 1 >= RANK_SLOTS {
        return (0, 0);
    }
    if rank + 1 >= RANK_WORD0 {
        let shift = (rank + 1 - RANK_WORD0) * RANK_BITS;
        (0, if shift >= 128 { 0 } else { u128::MAX << shift })
    } else {
        (u128::MAX << ((rank + 1) * RANK_BITS), u128::MAX)
    }
}

/// True when any rank strictly above `rank` is held: the only test the hot path needs.
fn held_above(held: (u128, u128), rank: u32) -> bool {
    let (lo_mask, hi_mask) = ranks_above(rank);
    (held.0 & lo_mask) | (held.1 & hi_mask) != 0
}

fn held_rank_names(held: (u128, u128)) -> String {
    let mut out = String::new();
    for rank in 0..RANK_SLOTS {
        let (high, shift) = rank_word_offset(rank);
        let word = if high { held.1 } else { held.0 };
        let count = (word >> shift) & RANK_MASK;
        if count == 0 {
            continue;
        }
        if !out.is_empty() {
            out.push(',');
        }
        out.push_str(RANK_NAMES[usize::try_from(rank).unwrap_or(0)]);
        if count > 1 {
            out.push_str(&format!("x{count}"));
        }
    }
    if out.is_empty() {
        out.push('-');
    }
    out
}

const RANK_SITE_LEN: usize = 96;
struct RankSite {
    key: AtomicUsize,
    counts: [AtomicU64; RK_COUNT],
    /// The held set of the first occurrence of any kind here, so the JSON names what was held:
    /// the two words of [`held_ranks`] as four `u64`s (`lo[0..1]`, `hi[2..3]`).
    held: [AtomicU64; 4],
    /// The rank being acquired / waited for (`u32::MAX` when there is none: a park or a bare host
    /// call), so the JSON names the other end of the wait, not only what was held.
    target_rank: AtomicU64,
}
impl RankSite {
    const fn new() -> Self {
        Self {
            key: AtomicUsize::new(0),
            counts: [const { AtomicU64::new(0) }; RK_COUNT],
            held: [const { AtomicU64::new(0) }; 4],
            target_rank: AtomicU64::new(u32::MAX as u64),
        }
    }
}
static RANK_SITES: [RankSite; RANK_SITE_LEN] = {
    const SLOT: RankSite = RankSite::new();
    [SLOT; RANK_SITE_LEN]
};
static RANK_SITE_OVERFLOWS: AtomicU64 = AtomicU64::new(0);
static RANK_VIOLATIONS: [AtomicU64; RK_COUNT] = [const { AtomicU64::new(0) }; RK_COUNT];
static RANK_LOGGED: AtomicU64 = AtomicU64::new(0);

fn rank_site_slot(key: usize) -> Option<usize> {
    if key == 0 {
        return None;
    }
    let start = (key as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15) >> 56;
    let start = usize::try_from(start).unwrap_or(0) % RANK_SITE_LEN;
    for offset in 0..RANK_SITE_LEN {
        let index = (start + offset) % RANK_SITE_LEN;
        let Some(slot) = RANK_SITES.get(index) else {
            break;
        };
        let existing = slot.key.load(Ordering::Acquire);
        let owns = existing == key
            || (existing == 0
                && match slot.key.compare_exchange(0, key, Ordering::AcqRel, Ordering::Acquire) {
                    Ok(_) => true,
                    Err(actual) => actual == key,
                });
        if owns {
            return Some(index);
        }
    }
    RANK_SITE_OVERFLOWS.fetch_add(1, Ordering::Relaxed);
    None
}

/// `LITEBOX_HVF_RANK_PANIC=<mask>`: a `1<<RK_*` bitmask that makes a signed release runner panic
/// on the first violation of those kinds (`31` = every kind). Off by default.
fn rank_panic_mask() -> u32 {
    static MASK: OnceLock<u32> = OnceLock::new();
    *MASK.get_or_init(|| {
        std::env::var("LITEBOX_HVF_RANK_PANIC")
            .ok()
            .and_then(|value| value.trim().parse::<u32>().ok())
            .unwrap_or(0)
    })
}

/// `LITEBOX_HVF_RANK_ASSERT=<mask>`: which kinds `debug_assert!` on the first occurrence
/// (default [`RK_ASSERTED_MASK`]; `0` disables, for a debug run whose own purpose is something
/// else).
fn rank_assert_mask() -> u32 {
    static MASK: OnceLock<u32> = OnceLock::new();
    *MASK.get_or_init(|| {
        match std::env::var("LITEBOX_HVF_RANK_ASSERT") {
            Ok(value) => value.trim().parse::<u32>().unwrap_or(0),
            Err(_) => RK_ASSERTED_MASK,
        }
    })
}

/// One CLASS A instance of `kind` at `site`, with `held` the caller's held set and `target` the
/// rank being acquired, waited for or called into (`None` for a bare host call / park). Counted
/// per kind and per call site in EVERY build; the two legal-but-reported kinds
/// ([`RK_BLOCK_ACQUIRE`], [`RK_HOST_CALL`]) are NEVER fatal here, and the three class-proper kinds
/// are fatal only under [`rank_assert_mask`] (debug) or [`rank_panic_mask`] (any build, off by
/// default). Release therefore records and continues -- the previous pass panicked in a debug
/// runner on the operation-gate convoy the inventory itself declares out of scope, which is
/// exactly what the per-kind masks exist to prevent.
fn record_rank_violation(
    kind: usize,
    site: &'static Location<'static>,
    held: (u128, u128),
    target: Option<u32>,
) {
    let bit = 1u64 << kind;
    if let Some(counter) = RANK_VIOLATIONS.get(kind) {
        counter.fetch_add(1, Ordering::Relaxed);
    }
    let name = RK_NAMES.get(kind).copied().unwrap_or("?");
    let file = site.file().rsplit('/').next().unwrap_or("");
    if let Some(index) = rank_site_slot(core::ptr::from_ref(site) as usize)
        && let Some(slot) = RANK_SITES.get(index)
    {
        if let Some(counter) = slot.counts.get(kind) {
            if counter.fetch_add(1, Ordering::Relaxed) == 0 {
                slot.held[0].store(held.0 as u64, Ordering::Relaxed);
                slot.held[1].store((held.0 >> 64) as u64, Ordering::Relaxed);
                slot.held[2].store(held.1 as u64, Ordering::Relaxed);
                slot.held[3].store((held.1 >> 64) as u64, Ordering::Relaxed);
                slot.target_rank
                    .store(u64::from(target.unwrap_or(u32::MAX)), Ordering::Relaxed);
            }
        }
        if RANK_LOGGED.load(Ordering::Relaxed) & bit == 0
            && RANK_LOGGED.fetch_or(bit, Ordering::AcqRel) & bit == 0
        {
            let where_ = format!("{file}:{}:{}", site.line(), site.column());
            let held_names = held_rank_names(held);
            litebox_util_log::warn!(
                kind:? = name, at:? = where_, holding:? = held_names;
                "CLASS A: a thread blocked while holding a lock"
            );
        }
    }
    // Opt-in only: a signed runner aborts on the first violation of the masked kinds.
    if rank_panic_mask() & (bit as u32) != 0 {
        panic!(
            "CLASS A lock-rank violation: {name} at {file}:{}:{} holding [{}]",
            site.line(),
            site.column(),
            held_rank_names(held),
        );
    }
    // Debug-only, and only for the kinds whose count must be zero. `debug_assert!` is compiled
    // out of release entirely, so a release run records and continues.
    debug_assert!(
        rank_assert_mask() & (bit as u32) == 0,
        "CLASS A lock-rank violation: {name} at {file}:{}:{} holding [{}]",
        site.line(),
        site.column(),
        held_rank_names(held),
    );
}

/// A lock of `rank` is about to be acquired at `site`. Flags the ABBA shape only: acquiring a
/// rank at or below one this thread already holds. Cheap on the common path (one TLS read and a
/// test against 0 while nothing is held).
#[inline]
pub(crate) fn rank_check(rank: u32, site: &'static Location<'static>) {
    let held = held_ranks();
    if (held.0 | held.1) != 0 && held_above(held, rank) {
        record_rank_violation(RK_OUT_OF_RANK, site, held, Some(rank));
    }
}

/// The acquisition of a rank-`rank` lock at `site` is about to BLOCK while `held` is this
/// thread's held set: the convoy shape (legal, deadlock-free, still the class).
#[inline]
pub(crate) fn rank_note_blocked_acquire(rank: u32, site: &'static Location<'static>) {
    let held = held_ranks();
    if (held.0 | held.1) != 0 {
        record_rank_violation(RK_BLOCK_ACQUIRE, site, held, Some(rank));
        // Also the ABBA shape, if it is one, so a blocked out-of-rank acquisition is visible
        // without reading two counters together.
        if held_above(held, rank) {
            record_rank_violation(RK_OUT_OF_RANK, site, held, Some(rank));
        }
    }
}

/// A blocking wait (gate FIFO, condvar, channel, park) is about to start at `site`. `kind` is
/// [`RK_GATE_ADMIT`] for the gate FIFO and [`RK_WAIT_WHILE_HOLDING`] for everything else.
#[inline]
pub(crate) fn rank_note_blocking_wait(kind: usize, site: &'static Location<'static>) {
    let held = held_ranks();
    if (held.0 | held.1) != 0 {
        record_rank_violation(kind, site, held, None);
    }
}

/// A [`std::sync::Condvar`] wait paired with a lock of `own_rank` is about to start at `site`.
///
/// `Condvar::wait` RELEASES that mutex for the duration of the park, so `own_rank` is removed from
/// this thread's held set for the wait: what is checked is everything ELSE the thread holds. This
/// is the difference between a real finding and a false positive -- without it, ranking a condvar's
/// mutex turns every legitimate park into an asserted [`RK_WAIT_WHILE_HOLDING`], which in a debug
/// build aborts the runner (and on the lane-maintenance thread that abort is caught by
/// `start_lane_maintenance`'s `catch_unwind`, which then poisons the lane pool permanently). With
/// it, "parked on the pool while still holding `cell_state`" is still a violation and "parked on
/// the pool holding nothing else" is not. The caller re-registers `own_rank` with [`rank_hold`]
/// when the park returns -- callers use [`RankedMutex::wait_on`] / [`RankedMutex::wait_timeout_on`],
/// which do that for them, rather than this function directly.
pub(crate) fn rank_note_condvar_wait(kind: usize, site: &'static Location<'static>, own_rank: u32) {
    // `own_rank` is released for the park; anything else this thread holds stays in the set and
    // is what the two notes below are checked against.
    rank_release(own_rank);
    // The re-acquisition the condvar performs on wake is an acquisition like any other: check it
    // against what is left, so "waited for the pool while holding a higher rank" is both an
    // out-of-rank acquisition and a park-while-holding rather than only the latter.
    rank_check(own_rank, site);
    rank_note_blocking_wait(kind, site);
}

/// Runs `body` (an HVF / Mach host call) and counts it at the CALLER's site when the caller holds
/// a lock: the class's fourth shape, invisible to the other kinds because no lock is acquired and
/// no condvar is waited on in between.
#[track_caller]
pub(crate) fn rank_host_call<T>(body: impl FnOnce() -> T) -> T {
    rank_note_host_call(Location::caller());
    body()
}

/// An HVF / Mach host call is about to be made at `site` (the class's fourth shape: no lock is
/// acquired and no condvar is waited on, so the other kinds cannot see it).
#[inline]
pub(crate) fn rank_note_host_call(site: &'static Location<'static>) {
    let held = held_ranks();
    if (held.0 | held.1) != 0 {
        record_rank_violation(RK_HOST_CALL, site, held, None);
    }
}

/// RAII: `rank` is in this thread's held set for as long as this guard is alive. Used for the VM
/// operation frame: a frame is not a mutex, so there is no guard type to carry the hold.
///
/// It is deliberately NOT used for a `Condvar` wait any more. `std::sync::Condvar::wait` releases
/// the paired mutex for the park, so a scoped hold around one reported every legitimate park as
/// `wait_while_holding`; a condvar paired with a ranked lock now waits through
/// [`RankedMutex::wait_on`], which releases and re-takes the rank around the park itself.
pub(crate) struct RankHold {
    rank: u32,
}

impl Drop for RankHold {
    #[inline]
    fn drop(&mut self) {
        rank_release(self.rank);
    }
}

/// Register that the calling thread now owns a VM operation frame. Registered so a gate body
/// acquiring a lower-ranked lock (the legal direction, and the direction T1g inverted) is
/// visible, and so a FIFO join or a condvar / channel / park wait inside a body is caught as
/// [`RK_GATE_ADMIT`] / [`RK_WAIT_WHILE_HOLDING`]. Hold the returned guard for as long as the
/// frame is owned; `drop` it (or let it fall out of scope) to release.
#[inline]
pub(crate) fn rank_hold_gate_own() -> RankHold {
    rank_hold(RANK_GATE_OWN);
    RankHold {
        rank: RANK_GATE_OWN,
    }
}

/// A `std::sync::Mutex` that declares its rank and joins the per-thread held set, mirroring
/// `std::sync::Mutex`'s API so converting a field's type is the only change a call site needs.
pub(crate) struct RankedMutex<T> {
    inner: Mutex<T>,
    rank: u32,
}

pub(crate) struct RankedGuard<'a, T> {
    guard: MutexGuard<'a, T>,
    rank: u32,
    /// Whether this acquisition registered its rank in the held set (`false` only for
    /// [`RankedMutex::lock_unregistered`]).
    registered: bool,
}

impl<T> RankedMutex<T> {
    pub(crate) const fn new(value: T, rank: u32) -> Self {
        Self {
            inner: Mutex::new(value),
            rank,
        }
    }

    #[track_caller]
    pub(crate) fn lock(&self) -> std::sync::LockResult<RankedGuard<'_, T>> {
        let site = Location::caller();
        rank_check(self.rank, site);
        let (guard, poisoned) = match self.inner.try_lock() {
            Ok(guard) => (guard, false),
            Err(TryLockError::Poisoned(poisoned)) => (poisoned.into_inner(), true),
            Err(TryLockError::WouldBlock) => {
                rank_note_blocked_acquire(self.rank, site);
                // Step GF (fix-up): `self.inner.lock()` parks. A guest thread that blocks here is
                // not making progress towards its next run, so it must not keep the vCPU lane it
                // retained -- same invariant as `RawMutex::block_inner`, which only covers the
                // ulock waits. (`RANK_*` order is unaffected: the lease is released before any
                // lock is taken, and `release_lane` only takes the pool's own lock, which ranks
                // below every `RankedMutex` here.)
                crate::hvf_backend::release_retained_lane(LANE_STICKY_RELEASED_BLOCK);
                match self.inner.lock() {
                    Ok(guard) => (guard, false),
                    Err(poisoned) => (poisoned.into_inner(), true),
                }
            }
        };
        rank_hold(self.rank);
        let guard = RankedGuard {
            guard,
            rank: self.rank,
            registered: true,
        };
        if poisoned {
            Err(PoisonError::new(guard))
        } else {
            Ok(guard)
        }
    }

    /// [`Self::lock`] for a process-start serialization lock: the acquisition is still
    /// rank-CHECKED, but the hold is NOT registered in the held set. Used where the only waits
    /// inside the body are the bounded, uncontended barriers of the thing being created -- today
    /// exactly one site, `hvf_backend::install`, whose body parks twice per lane on the vCPU
    /// creation barriers (`hvf_vcpu.rs` `hold_vcpu_synchronization_barrier` /
    /// `hold_vcpu_run_completion_barrier`). Registering it would make every one of those startup
    /// parks an asserted `wait_while_holding` for the whole life of the process, which is the
    /// failure the previous pass was reverted for; and no other thread can contend for this lock
    /// while it is held (it is taken once, before the backend is published), so nothing can be
    /// waiting on it. This is the same shape as [`TimedMutex::lock_unpublished`].
    #[track_caller]
    pub(crate) fn lock_unregistered(&self) -> std::sync::LockResult<RankedGuard<'_, T>> {
        rank_check(self.rank, Location::caller());
        let (guard, poisoned) = match self.inner.lock() {
            Ok(guard) => (guard, false),
            Err(poisoned) => (poisoned.into_inner(), true),
        };
        let guard = RankedGuard {
            guard,
            rank: self.rank,
            registered: false,
        };
        if poisoned {
            Err(PoisonError::new(guard))
        } else {
            Ok(guard)
        }
    }

    /// [`Self::try_lock`] without the rank check: for a wrapper that has already checked
    /// (a violation must be counted once per acquisition, not once per wrapper layer).
    fn try_lock_unchecked(&self) -> std::sync::TryLockResult<RankedGuard<'_, T>> {
        match self.inner.try_lock() {
            Ok(guard) => {
                rank_hold(self.rank);
                Ok(RankedGuard {
                    guard,
                    rank: self.rank,
                    registered: true,
                })
            }
            Err(TryLockError::Poisoned(poisoned)) => {
                rank_hold(self.rank);
                Err(TryLockError::Poisoned(PoisonError::new(RankedGuard {
                    guard: poisoned.into_inner(),
                    rank: self.rank,
                    registered: true,
                })))
            }
            Err(TryLockError::WouldBlock) => Err(TryLockError::WouldBlock),
        }
    }

    /// The blocking acquisition without the rank check ([`Self::try_lock_unchecked`]'s reason).
    fn lock_unchecked(&self) -> std::sync::LockResult<RankedGuard<'_, T>> {
        match self.inner.lock() {
            Ok(guard) => {
                rank_hold(self.rank);
                Ok(RankedGuard {
                    guard,
                    rank: self.rank,
                    registered: true,
                })
            }
            Err(poisoned) => {
                rank_hold(self.rank);
                Err(PoisonError::new(RankedGuard {
                    guard: poisoned.into_inner(),
                    rank: self.rank,
                    registered: true,
                }))
            }
        }
    }

    #[track_caller]
    pub(crate) fn try_lock(&self) -> std::sync::TryLockResult<RankedGuard<'_, T>> {
        rank_check(self.rank, Location::caller());
        self.try_lock_unchecked()
    }

    pub(crate) fn rank(&self) -> u32 {
        self.rank
    }

    /// Parks on `condvar` until notified, consuming `guard` and returning the re-acquired guard.
    ///
    /// ONE primitive for the one shape [`RankedGuard`] cannot express: `std::sync::Condvar::wait`
    /// must consume and return a plain [`MutexGuard`]. This is the only way to wait on a ranked
    /// lock's condvar, and it does the bookkeeping itself -- [`rank_note_condvar_wait`] masks
    /// `self.rank` out of the held set for the park (because the condvar releases it) and
    /// re-registers it on return, so the park is checked against everything else this thread
    /// holds. There is deliberately NO accessor for the bare mutex: an unchecked acquisition is
    /// not expressible.
    #[track_caller]
    pub(crate) fn wait_on<'a>(
        &'a self,
        condvar: &Condvar,
        guard: RankedGuard<'a, T>,
    ) -> std::sync::LockResult<RankedGuard<'a, T>> {
        let site = Location::caller();
        rank_note_condvar_wait(RK_WAIT_WHILE_HOLDING, site, self.rank);
        self.park(condvar, guard, |c, g| match c.wait(g) {
            Ok(guard) => Ok((guard, false)),
            Err(poisoned) => Err(PoisonError::new((poisoned.into_inner(), false))),
        })
        .map(|(guard, _)| guard)
        .map_err(|poisoned| PoisonError::new(poisoned.into_inner().0))
    }

    /// [`Self::wait_on`] with a timeout: returns the guard plus whether the wait timed out.
    /// (`bool` rather than [`WaitTimeoutResult`] because that type cannot be constructed outside
    /// `std`; no caller needs anything else.)
    #[track_caller]
    pub(crate) fn wait_timeout_on<'a>(
        &'a self,
        condvar: &Condvar,
        guard: RankedGuard<'a, T>,
        dur: Duration,
    ) -> std::sync::LockResult<(RankedGuard<'a, T>, bool)> {
        let site = Location::caller();
        rank_note_condvar_wait(RK_WAIT_WHILE_HOLDING, site, self.rank);
        self.park(condvar, guard, |c, g| match c.wait_timeout(g, dur) {
            Ok((guard, timed_out)) => Ok((guard, timed_out.timed_out())),
            Err(poisoned) => {
                let (guard, timed_out) = poisoned.into_inner();
                Err(PoisonError::new((guard, timed_out.timed_out())))
            }
        })
    }

    /// The shared body of [`Self::wait_on`] / [`Self::wait_timeout_on`]: hands the plain guard to
    /// `wait`, then re-registers this rank in the held set (the condvar re-acquired the mutex).
    fn park<'a>(
        &'a self,
        condvar: &Condvar,
        guard: RankedGuard<'a, T>,
        wait: impl FnOnce(
            &Condvar,
            MutexGuard<'a, T>,
        ) -> std::sync::LockResult<(MutexGuard<'a, T>, bool)>,
    ) -> std::sync::LockResult<(RankedGuard<'a, T>, bool)> {
        let (inner, rank, registered) = guard.into_parts();
        match wait(condvar, inner) {
            Ok((inner, extra)) => {
                if registered {
                    rank_hold(rank);
                }
                Ok((
                    RankedGuard {
                        guard: inner,
                        rank,
                        registered,
                    },
                    extra,
                ))
            }
            Err(poisoned) => {
                let (inner, extra) = poisoned.into_inner();
                if registered {
                    rank_hold(rank);
                }
                Err(PoisonError::new((
                    RankedGuard {
                        guard: inner,
                        rank,
                        registered,
                    },
                    extra,
                )))
            }
        }
    }

    /// The value back out of the mutex (construction / teardown only: no rank bookkeeping, so it
    /// never lands in a path that holds anything).
    pub(crate) fn into_inner(self) -> std::sync::LockResult<T> {
        self.inner.into_inner()
    }
}

impl<'a, T> RankedGuard<'a, T> {
    /// Splits this guard into the plain [`MutexGuard`] a [`Condvar`] needs plus its rank
    /// bookkeeping, WITHOUT running [`Drop`] -- so the rank is not released here.
    /// [`RankedMutex::park`] re-registers it once the condvar has re-acquired the mutex.
    fn into_parts(self) -> (MutexGuard<'a, T>, u32, bool) {
        let this = ManuallyDrop::new(self);
        // SAFETY: `this` is never dropped (it is a `ManuallyDrop`), so the guard field is moved
        // out exactly once and never dropped twice.
        let guard = unsafe { core::ptr::read(&(*this).guard) };
        (guard, this.rank, this.registered)
    }
}

impl<T> core::ops::Deref for RankedGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.guard
    }
}

impl<T> core::ops::DerefMut for RankedGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.guard
    }
}

impl<T> Drop for RankedGuard<'_, T> {
    fn drop(&mut self) {
        if self.registered {
            rank_release(self.rank);
        }
    }
}

/// [`RankedMutex`] for the reader-parallel locks (`HvfBackend::view_spaces`).
pub(crate) struct RankedRwLock<T> {
    inner: RwLock<T>,
    rank: u32,
}

pub(crate) struct RankedReadGuard<'a, T> {
    guard: std::sync::RwLockReadGuard<'a, T>,
    rank: u32,
}

pub(crate) struct RankedWriteGuard<'a, T> {
    guard: std::sync::RwLockWriteGuard<'a, T>,
    rank: u32,
}

impl<T> RankedRwLock<T> {
    pub(crate) const fn new(value: T, rank: u32) -> Self {
        Self {
            inner: RwLock::new(value),
            rank,
        }
    }

    #[track_caller]
    pub(crate) fn read(&self) -> std::sync::LockResult<RankedReadGuard<'_, T>> {
        let site = Location::caller();
        rank_check(self.rank, site);
        match self.inner.try_read() {
            Ok(guard) => {
                rank_hold(self.rank);
                Ok(RankedReadGuard {
                    guard,
                    rank: self.rank,
                })
            }
            Err(TryLockError::Poisoned(poisoned)) => {
                rank_hold(self.rank);
                Err(PoisonError::new(RankedReadGuard {
                    guard: poisoned.into_inner(),
                    rank: self.rank,
                }))
            }
            Err(TryLockError::WouldBlock) => {
                rank_note_blocked_acquire(self.rank, site);
                match self.inner.read() {
                    Ok(guard) => {
                        rank_hold(self.rank);
                        Ok(RankedReadGuard {
                            guard,
                            rank: self.rank,
                        })
                    }
                    Err(poisoned) => {
                        rank_hold(self.rank);
                        Err(PoisonError::new(RankedReadGuard {
                            guard: poisoned.into_inner(),
                            rank: self.rank,
                        }))
                    }
                }
            }
        }
    }

    #[track_caller]
    pub(crate) fn write(&self) -> std::sync::LockResult<RankedWriteGuard<'_, T>> {
        let site = Location::caller();
        rank_check(self.rank, site);
        match self.inner.try_write() {
            Ok(guard) => {
                rank_hold(self.rank);
                Ok(RankedWriteGuard {
                    guard,
                    rank: self.rank,
                })
            }
            Err(TryLockError::Poisoned(poisoned)) => {
                rank_hold(self.rank);
                Err(PoisonError::new(RankedWriteGuard {
                    guard: poisoned.into_inner(),
                    rank: self.rank,
                }))
            }
            Err(TryLockError::WouldBlock) => {
                rank_note_blocked_acquire(self.rank, site);
                match self.inner.write() {
                    Ok(guard) => {
                        rank_hold(self.rank);
                        Ok(RankedWriteGuard {
                            guard,
                            rank: self.rank,
                        })
                    }
                    Err(poisoned) => {
                        rank_hold(self.rank);
                        Err(PoisonError::new(RankedWriteGuard {
                            guard: poisoned.into_inner(),
                            rank: self.rank,
                        }))
                    }
                }
            }
        }
    }

}

impl<T> core::ops::Deref for RankedReadGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.guard
    }
}

impl<T> core::ops::Deref for RankedWriteGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.guard
    }
}

impl<T> core::ops::DerefMut for RankedWriteGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.guard
    }
}

impl<T> Drop for RankedReadGuard<'_, T> {
    fn drop(&mut self) {
        rank_release(self.rank);
    }
}

impl<T> Drop for RankedWriteGuard<'_, T> {
    fn drop(&mut self) {
        rank_release(self.rank);
    }
}

/// The `--counters` readout for this section: per-kind totals and per-call-site rows.
fn render_rank_discipline(out: &mut String) {
    use std::fmt::Write as _;
    out.push_str("\"rank_violations\":{");
    for (kind, name) in RK_NAMES.iter().enumerate() {
        if kind > 0 {
            out.push(',');
        }
        let _ = write!(
            out,
            "\"{name}\":{}",
            RANK_VIOLATIONS.get(kind).map_or(0, |c| c.load(Ordering::Relaxed))
        );
    }
    out.push_str("},\"rank_sites\":[");
    let mut first = true;
    for slot in RANK_SITES.iter() {
        let key = slot.key.load(Ordering::Acquire);
        if key == 0 {
            continue;
        }
        // SAFETY: every nonzero key was stored from a `&'static Location<'static>` by
        // `rank_site_slot` and is never changed afterwards.
        let location = unsafe { &*(key as *const Location<'static>) };
        let file = location.file().rsplit('/').next().unwrap_or("");
        if !first {
            out.push(',');
        }
        first = false;
        let target = slot.target_rank.load(Ordering::Relaxed);
        let held = (
            u128::from(slot.held[0].load(Ordering::Relaxed))
                | (u128::from(slot.held[1].load(Ordering::Relaxed)) << 64),
            u128::from(slot.held[2].load(Ordering::Relaxed))
                | (u128::from(slot.held[3].load(Ordering::Relaxed)) << 64),
        );
        let _ = write!(
            out,
            "{{\"site\":\"{file}:{}:{}\",\"held\":\"{}\",\"target\":\"{}\",",
            location.line(),
            location.column(),
            held_rank_names(held),
            usize::try_from(target)
                .ok()
                .and_then(|rank| RANK_NAMES.get(rank))
                .copied()
                .unwrap_or("-"),
        );
        for (kind, name) in RK_NAMES.iter().enumerate() {
            if kind > 0 {
                out.push(',');
            }
            let _ = write!(
                out,
                "\"{name}\":{}",
                slot.counts.get(kind).map_or(0, |c| c.load(Ordering::Relaxed))
            );
        }
        out.push('}');
    }
    let _ = write!(
        out,
        "],\"rank_site_overflows\":{},\"rank_hold_overflows\":{},\"lock_inventory\":{{\"mismatches\":{}}},",
        RANK_SITE_OVERFLOWS.load(Ordering::Relaxed),
        RANK_HOLD_OVERFLOWS.load(Ordering::Relaxed),
        LOCK_INVENTORY_MISMATCHES.load(Ordering::Relaxed)
    );
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
    out.push_str(",\"reply_slot\":{");
    for (index, name) in REPLY_SLOT_STAT_NAMES.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        let _ = write!(out, "\"{name}\":{}", stat_total(STAT_REPLY_SLOT + index));
    }
    out.push('}');
    out.push_str(",\"handoff_spin\":{");
    for (index, name) in HANDOFF_SPIN_STAT_NAMES.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        let _ = write!(out, "\"{name}\":{}", stat_total(STAT_HANDOFF_SPIN + index));
    }
    out.push('}');
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
            ",\"exclusive\":{},\"published\":{},\"slow\":{},\"slow_ns\":{},\"slow_log2\":",
            slot.exclusive.load(Ordering::Relaxed),
            slot.published.load(Ordering::Relaxed),
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
    cpu_ns: u64,
) {
    record_syscall_cpu(elapsed_ns, cpu_ns);
    record_space_syscall(space_id, elapsed_ns, blocked_ns);
    if elapsed_ns.saturating_sub(blocked_ns) >= SLOW_SYSCALL_NS {
        record_slow_syscall(space_id, nr, elapsed_ns, blocked_ns, cpu_ns);
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
/// T1f-a: one settled mutation in `space`'s own row (`SpaceSlot`'s counters are private to this
/// module, so the backend records through here).
pub(crate) fn record_space_mutation(space_id: HvfAddressSpaceId) {
    if let Some(slot) = cached_space_slot(space_id.value().wrapping_add(1)) {
        slot.mutations.fetch_add(1, Ordering::Relaxed);
    }
}

// ---------------------------------------------------------------------------
// T1f-a -- idle-mutation attribution (`hvf-idle-mutation-attribution-and-removal`)
//
// The idle desktop settles a few hundred mutations per second for 0.036 core of guest execution,
// and every one of them costs an exclusive VM admission, a kick round and -- because each commit
// mints a new root generation -- a later synchronization trip on every lane registered in the
// space. Before this section the only number was `hvf_exception_counters.generation`: how many,
// never who asked. This attributes each mutation along the three axes a removal decision needs:
//
// * `fault_arms` -- which arm of `try_resolve_cow_fault` produced it, and whether the faulting
//   page was adjacent to this space's own immediately preceding fault: the fault-around
//   opportunity of F1/F2/F3 (`fault_is_adjacent`, `FAULT_ARM_ADJACENT`).
// * `mutation_sites` -- the `#[track_caller]` site of `mutate_with_retry` /
//   `settle_single_page_mutation`, crossed with the origin that requested it (syscall number,
//   fault, teardown, ...) and the mutation kind, with the closure's own time, whether it kicked,
//   and whether it hit the resource limit.
// * `root_generation_sites` -- the `commit_retirement` call sites, which also cover the
//   mutations minted inside `hvf_memory` that never reach `settle_mutation` at all.
//
// Plus `view_spaces` (per-view churn) and `kick_sites` (which path kicks how often).
//
// Instrumentation only: fixed-size tables, relaxed atomics, no allocation, and no value here is
// ever read by a decision -- a dropped sample (`*_OVERFLOWS`) is counted, not acted on.
// ---------------------------------------------------------------------------

pub(crate) const FAULT_ARM_SELF_DIVERGE: u8 = 0;
pub(crate) const FAULT_ARM_FILE_PROMOTE: u8 = 1;
pub(crate) const FAULT_ARM_COW_PROMOTE: u8 = 2;
pub(crate) const FAULT_ARM_COW_ALIAS_DIRECT: u8 = 3;
pub(crate) const FAULT_ARM_COW_ALIAS_CUSTODY: u8 = 4;
pub(crate) const FAULT_ARM_FILE_ALIAS: u8 = 5;
pub(crate) const FAULT_ARM_ALREADY_ALIASED: u8 = 6;
pub(crate) const FAULT_ARM_DECLINED: u8 = 7;
/// GSIGSEGV: the terminal repair arm -- a page this space owns whose stage-2 translation is
/// absent or installed at the wrong authority, which every lineage/file arm declines and which
/// therefore used to have no outcome but `PAGE_FAULT_FALLBACK_RETRY_LIMIT` identical faults and
/// a real, fatal `SIGSEGV` delivered to the guest.
pub(crate) const FAULT_ARM_REPAIR_OWN: u8 = 8;
const FAULT_ARM_NAMES: [&str; 9] = [
    "self_diverge",
    "file_promote",
    "cow_promote",
    "cow_alias_direct",
    "cow_alias_custody",
    "file_alias",
    "already_aliased",
    "declined",
    "repair_own",
];
static FAULT_ARM_OK: [AtomicU64; 9] = [const { AtomicU64::new(0) }; 9];
static FAULT_ARM_ERR: [AtomicU64; 9] = [const { AtomicU64::new(0) }; 9];
/// The fault-around opportunity: faults at this arm whose page was within
/// [`FAULT_ADJACENT_BYTES`] of this space's own previous fault within [`FAULT_ADJACENT_NS`].
static FAULT_ARM_ADJACENT: [AtomicU64; 9] = [const { AtomicU64::new(0) }; 9];
/// 4 x 16 KiB guest pages, i.e. Linux's default `fault_around_bytes`.
const FAULT_ADJACENT_BYTES: u64 = 64 * 1024;
const FAULT_ADJACENT_NS: u64 = 1_000_000;

/// Whether `page` sits next to where this space faulted last (and soon after): the direct
/// measurement of how much of the fault stream a fault-around would absorb.
pub(crate) fn fault_is_adjacent(space: HvfAddressSpaceId, page: usize) -> bool {
    let Some(slot) = cached_space_slot(space.value().wrapping_add(1)) else {
        return false;
    };
    let last = slot.fault_last_page.load(Ordering::Relaxed);
    if last == 0 {
        return false;
    }
    let last_page = usize::try_from(last.wrapping_sub(1)).unwrap_or(usize::MAX);
    let near = page.abs_diff(last_page) <= usize::try_from(FAULT_ADJACENT_BYTES).unwrap_or(0);
    let soon = ticks().wrapping_sub(slot.fault_last_ticks.load(Ordering::Relaxed))
        <= ns_to_ticks(FAULT_ADJACENT_NS);
    near && soon
}

/// One fault-service outcome: `arm` resolved (`ok`) or declined (`!ok`) `page` for `space`.
pub(crate) fn record_fault_arm(arm: u8, ok: bool, space: HvfAddressSpaceId, page: usize) {
    let adjacent = fault_is_adjacent(space, page);
    if let Some(counter) = FAULT_ARM_OK.get(usize::from(arm)) {
        if ok {
            counter.fetch_add(1, Ordering::Relaxed);
        }
    }
    if let Some(counter) = FAULT_ARM_ERR.get(usize::from(arm)) {
        if !ok {
            counter.fetch_add(1, Ordering::Relaxed);
        }
    }
    if adjacent && let Some(counter) = FAULT_ARM_ADJACENT.get(usize::from(arm)) {
        counter.fetch_add(1, Ordering::Relaxed);
    }
    if let Some(slot) = cached_space_slot(space.value().wrapping_add(1)) {
        slot.faults.fetch_add(1, Ordering::Relaxed);
        if adjacent {
            slot.faults_adjacent.fetch_add(1, Ordering::Relaxed);
        }
        slot.fault_last_page
            .store(u64::try_from(page).unwrap_or(0).wrapping_add(1), Ordering::Relaxed);
        slot.fault_last_ticks.store(ticks(), Ordering::Relaxed);
    }
}

// -- mutation call sites (site x origin x kind) ------------------------------------------------

const MUTATION_SITE_LEN: usize = 256;
pub(crate) const MUTATION_SITE_NONE: u16 = u16::MAX;
/// `Map` / `Protect` / `Unmap`, the same encoding `record_mutation` takes.
pub(crate) const MUTATION_KIND_NAMES: [&str; 3] = ["map", "protect", "unmap"];

struct MutationSiteSlot {
    count: AtomicU64,
    changed: AtomicU64,
    kicked: AtomicU64,
    closure_ticks: AtomicU64,
    resource_limit: AtomicU64,
}

impl MutationSiteSlot {
    const fn new() -> Self {
        Self {
            count: AtomicU64::new(0),
            changed: AtomicU64::new(0),
            kicked: AtomicU64::new(0),
            closure_ticks: AtomicU64::new(0),
            resource_limit: AtomicU64::new(0),
        }
    }
}

static MUTATION_SITES: [MutationSiteSlot; MUTATION_SITE_LEN] = {
    const SLOT: MutationSiteSlot = MutationSiteSlot::new();
    [SLOT; MUTATION_SITE_LEN]
};
#[repr(C, align(128))]
struct MutationSiteKeys {
    keys: [AtomicUsize; MUTATION_SITE_LEN],
    /// `origin | kind << 8`: the context the site was called in.
    tags: [AtomicU64; MUTATION_SITE_LEN],
}
static MUTATION_SITE_KEYS: MutationSiteKeys = MutationSiteKeys {
    keys: [const { AtomicUsize::new(0) }; MUTATION_SITE_LEN],
    tags: [const { AtomicU64::new(0) }; MUTATION_SITE_LEN],
};
static MUTATION_SITE_OVERFLOWS: AtomicU64 = AtomicU64::new(0);

/// A row's tag is stored as `tag + 1`, so `0` means "claimed, tag not yet published" rather than
/// a real `origin == 0 && kind == 0` row: a claim is a CAS on `keys` followed by a store to
/// `tags`, so a second thread can observe the key a few instructions before the tag, and without
/// a distinguishable "not yet published" value it would decide the row is not its own and mint a
/// SECOND row carrying the same (site, context, kind) label. Harmless for a readout, but it makes
/// `mutation_sites` rows non-unique, so a consumer must never sum rows by label.
const MUTATION_SITE_TAG_UNPUBLISHED: u64 = 0;
/// How long a thread whose key and tag both match an unpublished row waits for that tag to land
/// before minting its own row. A claim is a CAS plus one store, so this resolves in a handful of
/// spins unless the claimer is descheduled; the fallback is one duplicate label, never a wrong
/// count, so the bound is deliberately short.
const MUTATION_SITE_CLAIM_SPINS: u32 = 256;

/// Whether `slot` holds `published_tag`, waiting out the window in which another thread has
/// claimed the row but not yet stored its tag.
fn mutation_site_tag_is_ours(slot: &AtomicU64, published_tag: u64) -> bool {
    let mut stored = slot.load(Ordering::Acquire);
    let mut spins = 0u32;
    while stored == MUTATION_SITE_TAG_UNPUBLISHED && spins < MUTATION_SITE_CLAIM_SPINS {
        core::hint::spin_loop();
        stored = slot.load(Ordering::Acquire);
        spins += 1;
    }
    stored == published_tag
}

/// The row for (`caller`, `kind`, `origin`), claimed on first use. Rows are per (site, context,
/// kind) triple, so one call site that is reached from several guests activities gets one row
/// each instead of a blended average.
pub(crate) fn mutation_site_index(caller: &'static Location<'static>, kind: u8, origin: u8) -> u16 {
    let key = core::ptr::from_ref(caller) as usize;
    let tag = u64::from(origin) | (u64::from(kind) << 8);
    let published_tag = tag + 1;
    let start = ((key as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15) >> 52) as usize
        % MUTATION_SITE_LEN;
    for offset in 0..MUTATION_SITE_LEN {
        let index = (start + offset) % MUTATION_SITE_LEN;
        let (Some(slot_key), Some(slot_tag)) = (
            MUTATION_SITE_KEYS.keys.get(index),
            MUTATION_SITE_KEYS.tags.get(index),
        ) else {
            break;
        };
        let existing = slot_key.load(Ordering::Acquire);
        let owns = if existing == 0 {
            match slot_key.compare_exchange(0, key, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => {
                    slot_tag.store(published_tag, Ordering::Release);
                    true
                }
                // Lost the claim: the winner may still be publishing its tag, so wait it out
                // rather than minting a second row for the same (site, context, kind).
                Err(actual) => actual == key && mutation_site_tag_is_ours(slot_tag, published_tag),
            }
        } else {
            existing == key && mutation_site_tag_is_ours(slot_tag, published_tag)
        };
        if owns {
            return u16::try_from(index).unwrap_or(MUTATION_SITE_NONE);
        }
    }
    MUTATION_SITE_OVERFLOWS.fetch_add(1, Ordering::Relaxed);
    MUTATION_SITE_NONE
}

/// One settled mutation at `site`: whether it changed anything, whether it kicked the lanes, how
/// long its own closure (the stage-1/stage-2 work, before settling) took, and whether it hit the
/// resource limit and had to drain.
pub(crate) fn record_mutation_site(
    site: u16,
    changed: bool,
    kicked: bool,
    closure_ticks: u64,
    resource_limit: bool,
) {
    let Some(slot) = MUTATION_SITES.get(usize::from(site)) else {
        return;
    };
    slot.count.fetch_add(1, Ordering::Relaxed);
    if changed {
        slot.changed.fetch_add(1, Ordering::Relaxed);
    }
    if kicked {
        slot.kicked.fetch_add(1, Ordering::Relaxed);
    }
    slot.closure_ticks.fetch_add(closure_ticks, Ordering::Relaxed);
    if resource_limit {
        slot.resource_limit.fetch_add(1, Ordering::Relaxed);
    }
}

// -- root-generation commit sites ---------------------------------------------------------------

const ROOTGEN_SITE_LEN: usize = 128;
static ROOTGEN_SITE_KEYS: [AtomicUsize; ROOTGEN_SITE_LEN] =
    [const { AtomicUsize::new(0) }; ROOTGEN_SITE_LEN];
static ROOTGEN_SITE_COUNTS: [AtomicU64; ROOTGEN_SITE_LEN] =
    [const { AtomicU64::new(0) }; ROOTGEN_SITE_LEN];
static ROOTGEN_TOTAL: AtomicU64 = AtomicU64::new(0);
static ROOTGEN_SITE_OVERFLOWS: AtomicU64 = AtomicU64::new(0);

/// One committed root generation (a new stage-1 root published to every lane), attributed to the
/// `commit_retirement` call site that minted it.
pub(crate) fn record_root_generation(caller: &'static Location<'static>, space: HvfAddressSpaceId) {
    ROOTGEN_TOTAL.fetch_add(1, Ordering::Relaxed);
    if let Some(slot) = cached_space_slot(space.value().wrapping_add(1)) {
        slot.root_generations.fetch_add(1, Ordering::Relaxed);
    }
    let key = core::ptr::from_ref(caller) as usize;
    let start =
        ((key as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15) >> 52) as usize % ROOTGEN_SITE_LEN;
    for offset in 0..ROOTGEN_SITE_LEN {
        let index = (start + offset) % ROOTGEN_SITE_LEN;
        let Some(slot_key) = ROOTGEN_SITE_KEYS.get(index) else {
            break;
        };
        let existing = slot_key.load(Ordering::Acquire);
        let owns = existing == key
            || (existing == 0
                && match slot_key.compare_exchange(0, key, Ordering::AcqRel, Ordering::Acquire) {
                    Ok(_) => true,
                    Err(actual) => actual == key,
                });
        if owns {
            if let Some(count) = ROOTGEN_SITE_COUNTS.get(index) {
                count.fetch_add(1, Ordering::Relaxed);
            }
            return;
        }
    }
    ROOTGEN_SITE_OVERFLOWS.fetch_add(1, Ordering::Relaxed);
}

// -- view-space lifecycle and kick sites --------------------------------------------------------

pub(crate) const VIEW_SPACE_CREATED: u8 = 0;
pub(crate) const VIEW_SPACE_DESTROYED: u8 = 1;
pub(crate) const VIEW_SPACE_DESTROY_DEFERRED: u8 = 2;
const VIEW_SPACE_NAMES: [&str; 3] = ["created", "destroyed", "destroy_deferred"];
static VIEW_SPACES: [AtomicU64; 3] = [const { AtomicU64::new(0) }; 3];

pub(crate) fn record_view_space(event: u8) {
    if let Some(counter) = VIEW_SPACES.get(usize::from(event)) {
        counter.fetch_add(1, Ordering::Relaxed);
    }
}

const KICK_SITE_LEN: usize = 32;
static KICK_SITE_KEYS: [AtomicUsize; KICK_SITE_LEN] = [const { AtomicUsize::new(0) }; KICK_SITE_LEN];
static KICK_SITE_ROUNDS: [AtomicU64; KICK_SITE_LEN] = [const { AtomicU64::new(0) }; KICK_SITE_LEN];
static KICK_SITE_OVERFLOWS: AtomicU64 = AtomicU64::new(0);

/// One kick round, attributed to the `kick_running_lanes` call site that issued it.
pub(crate) fn record_kick_round_at(caller: &'static Location<'static>) {
    let key = core::ptr::from_ref(caller) as usize;
    let start = ((key as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15) >> 52) as usize % KICK_SITE_LEN;
    for offset in 0..KICK_SITE_LEN {
        let index = (start + offset) % KICK_SITE_LEN;
        let Some(slot_key) = KICK_SITE_KEYS.get(index) else {
            break;
        };
        let existing = slot_key.load(Ordering::Acquire);
        let owns = existing == key
            || (existing == 0
                && match slot_key.compare_exchange(0, key, Ordering::AcqRel, Ordering::Acquire) {
                    Ok(_) => true,
                    Err(actual) => actual == key,
                });
        if owns {
            if let Some(rounds) = KICK_SITE_ROUNDS.get(index) {
                rounds.fetch_add(1, Ordering::Relaxed);
            }
            return;
        }
    }
    KICK_SITE_OVERFLOWS.fetch_add(1, Ordering::Relaxed);
}

fn render_t1f(out: &mut String) {
    use std::fmt::Write as _;
    out.push_str("\"t1f\":{");
    out.push_str("\"fault_arms\":[");
    let mut first = true;
    for (arm, name) in FAULT_ARM_NAMES.iter().enumerate() {
        let ok = FAULT_ARM_OK[arm].load(Ordering::Relaxed);
        let err = FAULT_ARM_ERR[arm].load(Ordering::Relaxed);
        if ok == 0 && err == 0 {
            continue;
        }
        if !first {
            out.push(',');
        }
        first = false;
        let _ = write!(
            out,
            "{{\"arm\":\"{name}\",\"ok\":{ok},\"err\":{err},\"adjacent\":{}}}",
            FAULT_ARM_ADJACENT[arm].load(Ordering::Relaxed)
        );
    }
    out.push_str("],\"mutation_sites\":[");
    let mut first = true;
    for (index, slot) in MUTATION_SITES.iter().enumerate() {
        let key = MUTATION_SITE_KEYS.keys[index].load(Ordering::Acquire);
        if key == 0 {
            continue;
        }
        let count = slot.count.load(Ordering::Relaxed);
        if count == 0 {
            continue;
        }
        // SAFETY: every nonzero key was stored from a `&'static Location<'static>` by
        // `mutation_site_index` and is never changed afterwards.
        let location = unsafe { &*(key as *const Location<'static>) };
        let file = location.file().rsplit('/').next().unwrap_or("");
        // `mutation_site_index` stores every tag as `tag + 1` (see
        // `MUTATION_SITE_TAG_UNPUBLISHED`), so undo that here; a row is only ever published
        // once its tag has landed, so the subtraction cannot underflow.
        let tag = MUTATION_SITE_KEYS.tags[index]
            .load(Ordering::Acquire)
            .saturating_sub(1);
        let origin = ORIGIN_NAMES
            .get(usize::try_from(tag & 0xff).unwrap_or(0))
            .copied()
            .unwrap_or("?");
        let kind = MUTATION_KIND_NAMES
            .get(usize::try_from((tag >> 8) & 0xff).unwrap_or(0))
            .copied()
            .unwrap_or("?");
        if !first {
            out.push(',');
        }
        first = false;
        let _ = write!(
            out,
            concat!(
                "{{\"site\":\"{file}:{line}\",\"context\":\"{origin}\",\"kind\":\"{kind}\",",
                "\"count\":{count},\"changed\":{changed},\"kicked\":{kicked},\"closure_ns\":{closure},",
                "\"resource_limit\":{limited}}}"
            ),
            line = location.line(),
            file = file,
            origin = origin,
            kind = kind,
            count = count,
            changed = slot.changed.load(Ordering::Relaxed),
            kicked = slot.kicked.load(Ordering::Relaxed),
            closure = ticks_to_ns(slot.closure_ticks.load(Ordering::Relaxed)),
            limited = slot.resource_limit.load(Ordering::Relaxed),
        );
    }
    out.push_str("],\"root_generation_sites\":[");
    let mut first = true;
    for (index, count) in ROOTGEN_SITE_COUNTS.iter().enumerate() {
        let key = ROOTGEN_SITE_KEYS[index].load(Ordering::Acquire);
        let value = count.load(Ordering::Relaxed);
        if key == 0 || value == 0 {
            continue;
        }
        let location = unsafe { &*(key as *const Location<'static>) };
        let file = location.file().rsplit('/').next().unwrap_or("");
        if !first {
            out.push(',');
        }
        first = false;
        let _ = write!(
            out,
            "{{\"site\":\"{file}:{line}\",\"count\":{value}}}",
            file = file,
            line = location.line(),
            value = value
        );
    }
    out.push_str("],\"kick_sites\":[");
    let mut first = true;
    for (index, rounds) in KICK_SITE_ROUNDS.iter().enumerate() {
        let key = KICK_SITE_KEYS[index].load(Ordering::Acquire);
        let value = rounds.load(Ordering::Relaxed);
        if key == 0 || value == 0 {
            continue;
        }
        let location = unsafe { &*(key as *const Location<'static>) };
        let file = location.file().rsplit('/').next().unwrap_or("");
        if !first {
            out.push(',');
        }
        first = false;
        let _ = write!(
            out,
            "{{\"site\":\"{file}:{line}\",\"rounds\":{value}}}",
            file = file,
            line = location.line(),
            value = value
        );
    }
    out.push_str("],\"view_spaces\":{");
    let mut first = true;
    for (event, name) in VIEW_SPACE_NAMES.iter().enumerate() {
        if !first {
            out.push(',');
        }
        first = false;
        let _ = write!(
            out,
            "\"{name}\":{value}",
            name = name,
            value = VIEW_SPACES[event].load(Ordering::Relaxed)
        );
    }
    let _ = write!(
        out,
        concat!(
            "}},\"root_generations_total\":{},",
            "\"mutation_site_overflows\":{},\"rootgen_site_overflows\":{},",
            "\"kick_site_overflows\":{}}},"
        ),
        ROOTGEN_TOTAL.load(Ordering::Relaxed),
        MUTATION_SITE_OVERFLOWS.load(Ordering::Relaxed),
        ROOTGEN_SITE_OVERFLOWS.load(Ordering::Relaxed),
        KICK_SITE_OVERFLOWS.load(Ordering::Relaxed),
    );
}

/// The [`ORIGINS`] table: for each requester, the mutations it asked for by kind, its closure
/// time, and the exclusive admissions / waits / holds it paid for them. Rendered here because
/// T1f's attribution question ("which guest activity produces the idle mutations?") is exactly
/// this partition, and it was being collected but never published.
fn render_origins(out: &mut String) {
    use std::fmt::Write as _;
    out.push_str("\"origins\":[");
    let mut first = true;
    for (index, name) in ORIGIN_NAMES.iter().enumerate() {
        let Some(row) = ORIGINS.get(index) else {
            continue;
        };
        let mutations: [u64; 3] = core::array::from_fn(|i| row.mutations[i].load(Ordering::Relaxed));
        let by_syscall: [u64; 3] = core::array::from_fn(|i| row.by_syscall[i].load(Ordering::Relaxed));
        let count = row.mutate_count.load(Ordering::Relaxed);
        if mutations == [0, 0, 0] && count == 0 && by_syscall == [0, 0, 0] {
            continue;
        }
        if !first {
            out.push(',');
        }
        first = false;
        let _ = write!(
            out,
            concat!(
                "{{\"origin\":\"{name}\",\"mutations_map\":{m0},\"mutations_protect\":{m1},",
                "\"mutations_unmap\":{m2},\"changed\":{changed},\"mutate_calls\":{calls},",
                "\"mutate_ns\":{ns},\"mutate_max_ns\":{max},\"by_syscall_map\":{s0},",
                "\"by_syscall_protect\":{s1},\"by_syscall_unmap\":{s2},",
                "\"excl_admissions\":{excl},\"excl_wait_ns\":{wait},\"excl_hold_ns\":{hold}}}"
            ),
            name = name,
            m0 = mutations[0],
            m1 = mutations[1],
            m2 = mutations[2],
            changed = row.changed.load(Ordering::Relaxed),
            calls = count,
            ns = ticks_to_ns(row.mutate_ticks.load(Ordering::Relaxed)),
            max = ticks_to_ns(row.mutate_max.load(Ordering::Relaxed)),
            s0 = by_syscall[0],
            s1 = by_syscall[1],
            s2 = by_syscall[2],
            excl = row.excl_count.load(Ordering::Relaxed),
            wait = ticks_to_ns(row.excl_wait_ticks.load(Ordering::Relaxed)),
            hold = ticks_to_ns(row.excl_hold_ticks.load(Ordering::Relaxed)),
        );
    }
    out.push_str("],");
}

// ---------------------------------------------------------------------------
// CLASS R -- check-then-act (TOCTOU) over shared memory-subsystem state
// ---------------------------------------------------------------------------
//
// A *plan* is a read of memory-subsystem state (`AddressSpaceState`, or one of the
// generation-less mirrors of it in `AddressSpaceCell`). Acting on a plan after the lock that
// protected it was released -- or after a possibly-blocking call (VM operation gate admission, a
// retirement pump, a host VA syscall) -- is the defect: the act applies a decision made about
// state that no longer exists. This section carries the two things the repair needs: the
// domain's mutation counter (`TimedMutex::generation`, above) and the per-site accounting of
// every plan taken, checked, re-planned and acted on (`hvf_gr` in the counters JSON).
//
// The ORDERING rule itself lives in exactly one place --
// `HvfAddressSpace::plan` / `::plan_lockless` / `::settle_gate`: generation -> data ->
// generation, retry on mismatch. A stamp taken after the data it describes can name a generation
// a later mutation already reached, which is precisely how `check_plan` comes to accept a plan
// whose data predates that mutation. Nothing in this section can enforce the rule for code that
// does not go through those three.

/// How many times a planning caller re-takes its plan after `check_plan` reports it stale, before
/// it acts anyway. Exhausting it is a real, counted class-R escape
/// (`hvf_gr.plan_bound_exhausted`): a space that never stops mutating still has to make progress.
pub(crate) const GR_REPLAN_BOUND: u32 = 4;

/// How many times `HvfAddressSpace::plan` re-reads after a generation mismatch (a mutation
/// completed inside the window the two reads bracket) before it hands back the last read, still
/// stamped with the generation it was taken at so `check_plan` judges it.
pub(crate) const GR_PLAN_RETRY_BOUND: u32 = 4;

/// A planning site. Every `Versioned` plan names one, so `hvf_gr.by_site` attributes every
/// re-plan. Hand-maintained by design: a NEW planning site has no name to appear under until it
/// is added here, which is why `steps/GR2/census.md` (and its executable check) re-counts the
/// `Versioned` / `check_plan` call sites against this list -- the primitive is silent, not wrong,
/// about a site that never names itself.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum GrSite {
    /// `HvfAddressSpace::page_kinds` (the `mprotect` / materialize / W^X-flip walks).
    PageKinds,
    /// `HvfAddressSpace::has_cow_pages_in` (which act `protect_view_range` runs).
    HasCowPagesIn,
    /// `HvfAddressSpace::host_access_plan` (the whole host-side access preparation).
    HostAccessPlan,
    /// `HvfAddressSpace::fork_write_protected_pages_in` (the ancestor-side divergence gate).
    ForkWriteProtectedPagesIn,
    /// `HvfAddressSpace::page_writable_now` (a guest RESUME is decided on it).
    PageWritableNow,
    /// `HvfAddressSpace::is_fork_write_protected` (the fault classifier's dispatch).
    IsForkWriteProtected,
    /// `HvfAddressSpace::is_file_aliased` (fatal on a wrong answer: `return false` is a SIGSEGV).
    IsFileAliased,
    /// `HvfAddressSpace::is_cow_aliased` (same shape).
    IsCowAliased,
    /// `HvfAddressSpace::is_any_aliased` (the one of the three whose act is a resume).
    IsAnyAliased,
    /// `HvfAddressSpace::file_window_at` (drives installs in a SECOND space).
    FileWindowAt,
    /// `HvfAddressSpace::has_fork_cow_retention` (gates a reap, or a whole `destroy`).
    HasForkCowRetention,
    /// `HvfAddressSpace::host_storage_address` (N-by-construction; named so it is never "missing").
    HostStorageAddress,
    /// The invariant checker at a mutation boundary (`map_range` / `protect_range` /
    /// `unmap_range`).
    MutationBoundary,
    /// The invariant checker at the host-access boundary in `prepare_guest_access`.
    HostAccessBoundary,
    /// The invariant checker at the fault-resolution boundary in `try_resolve_cow_fault`.
    FaultBoundary,
}

impl GrSite {
    pub(crate) const ALL: [GrSite; Self::COUNT] = [
        GrSite::PageKinds,
        GrSite::HasCowPagesIn,
        GrSite::HostAccessPlan,
        GrSite::ForkWriteProtectedPagesIn,
        GrSite::PageWritableNow,
        GrSite::IsForkWriteProtected,
        GrSite::IsFileAliased,
        GrSite::IsCowAliased,
        GrSite::IsAnyAliased,
        GrSite::FileWindowAt,
        GrSite::HasForkCowRetention,
        GrSite::HostStorageAddress,
        GrSite::MutationBoundary,
        GrSite::HostAccessBoundary,
        GrSite::FaultBoundary,
    ];

    pub(crate) const COUNT: usize = 15;

    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::PageKinds => "page_kinds",
            Self::HasCowPagesIn => "has_cow_pages_in",
            Self::HostAccessPlan => "host_access_plan",
            Self::ForkWriteProtectedPagesIn => "fork_write_protected_pages_in",
            Self::PageWritableNow => "page_writable_now",
            Self::IsForkWriteProtected => "is_fork_write_protected",
            Self::IsFileAliased => "is_file_aliased",
            Self::IsCowAliased => "is_cow_aliased",
            Self::IsAnyAliased => "is_any_aliased",
            Self::FileWindowAt => "file_window_at",
            Self::HasForkCowRetention => "has_fork_cow_retention",
            Self::HostStorageAddress => "host_storage_address",
            Self::MutationBoundary => "mutation_boundary",
            Self::HostAccessBoundary => "host_access_boundary",
            Self::FaultBoundary => "fault_boundary",
        }
    }

    pub(crate) const fn index(self) -> usize {
        self as usize
    }
}

pub(crate) struct GrCounters {
    /// Plans taken, per site (one per `plan` / `plan_lockless` call).
    pub(crate) plan_calls: [AtomicU64; GrSite::COUNT],
    /// `plan` calls that found a mutation inside the window they bracketed and re-took the plan.
    pub(crate) plan_retries: [AtomicU64; GrSite::COUNT],
    /// `check_plan` calls, per site. The denominator of every ratio below.
    pub(crate) plan_checks: [AtomicU64; GrSite::COUNT],
    /// `check_plan` calls that found the domain had moved since the plan was taken, per site.
    pub(crate) plan_stale: [AtomicU64; GrSite::COUNT],
    /// Plans ACTED ON while `check_plan` still called them stale (the bound was spent), per site.
    /// This is a class-R escape, not bookkeeping -- see `plan_round_budget_exhausted`.
    pub(crate) plan_bound_exhausted: [AtomicU64; GrSite::COUNT],
    /// Nanoseconds spent inside `plan` + `check_plan`, per site. Zero unless
    /// `LITEBOX_HVF_GR_TIME=1` (the per-exit track's per-site cost isolation; the two `ticks()`
    /// reads it costs are not on any hot path otherwise).
    pub(crate) check_ns: [AtomicU64; GrSite::COUNT],
    /// Pages actually examined by the invariant checker (see `invariant_pages_span`).
    pub(crate) invariant_checks: AtomicU64,
    pub(crate) invariant_violations: AtomicU64,
    pub(crate) invariant_pages_checked: AtomicU64,
    /// Pages spanned by every range the checker was handed -- the denominator of the coverage a
    /// "0 violations" figure carries.
    pub(crate) invariant_pages_span: AtomicU64,
    pub(crate) violation_claim_alias: AtomicU64,
    pub(crate) violation_multi_redirect: AtomicU64,
    pub(crate) violation_wx: AtomicU64,
    /// The two legitimate claim+redirect combinations the checker exempts, counted apart (D4): a
    /// "0 violations" bound that rested on an exemption that fired would be a different claim.
    pub(crate) exempt_claim_promoted: AtomicU64,
    pub(crate) exempt_claim_file_alias: AtomicU64,
    /// A page that lies inside a file WINDOW range and also carries a redirect (a claim, a lineage
    /// alias, a promoted shadow or a file alias). The window is a RANGE record, not a page-level
    /// holder, so this is the steady state of every windowed page that has been touched since --
    /// counted apart (D4) because counting the window as a holder turns all of them into
    /// "violations" (measured: 6,680 on one desktop arm, all of them one page).
    pub(crate) exempt_window_redirect: AtomicU64,
    /// `hvf_backing`'s fresh-claim preclaim scan answering "overlaps a managed range" -- routine
    /// reclaim/retry traffic, attributable here rather than corrected (PRD
    /// `hvf-materialize-fresh-claim-overlaps-managed-range`).
    pub(crate) reservation_overlap: AtomicU64,
    /// A caller JUDGED (not acted on) a final snapshot the domain had already moved on.
    pub(crate) judged_on_stale_plan: AtomicU64,
    /// `revalidated_rounds` spending its acting rounds and handing a snapshot to the caller to
    /// judge: ordinary progress bookkeeping, deliberately separate from `plan_bound_exhausted`.
    pub(crate) plan_round_budget_exhausted: AtomicU64,
}

pub(crate) static GR_COUNTERS: GrCounters = GrCounters {
    plan_calls: zeroed_u64_array(),
    plan_retries: zeroed_u64_array(),
    plan_checks: zeroed_u64_array(),
    plan_stale: zeroed_u64_array(),
    plan_bound_exhausted: zeroed_u64_array(),
    check_ns: zeroed_u64_array(),
    invariant_checks: AtomicU64::new(0),
    invariant_violations: AtomicU64::new(0),
    invariant_pages_checked: AtomicU64::new(0),
    invariant_pages_span: AtomicU64::new(0),
    violation_claim_alias: AtomicU64::new(0),
    violation_multi_redirect: AtomicU64::new(0),
    violation_wx: AtomicU64::new(0),
    exempt_claim_promoted: AtomicU64::new(0),
    exempt_claim_file_alias: AtomicU64::new(0),
    exempt_window_redirect: AtomicU64::new(0),
    reservation_overlap: AtomicU64::new(0),
    judged_on_stale_plan: AtomicU64::new(0),
    plan_round_budget_exhausted: AtomicU64::new(0),
};

fn gr_flag(name: &str, default: bool) -> bool {
    match std::env::var(name) {
        Ok(value) => value != "0" && !value.is_empty(),
        Err(_) => default,
    }
}

/// The invariant checker: on unconditionally in a debug build (`debug_assertions`), on demand in
/// release (`LITEBOX_HVF_GR_CHECK=1`). It is NOT a class guard -- it checks two properties of a
/// steady state, and none of the historical class-R bugs would trip it (they were races over
/// time, not contradictions).
pub(crate) fn gr_invariants_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| gr_flag("LITEBOX_HVF_GR_CHECK", cfg!(debug_assertions)))
}

/// Whether `check_plan` re-validates at `site`.
///
/// D3: the control is PER SITE, not one global switch. `LITEBOX_HVF_GR_DISABLE_SITES` takes a
/// comma-separated list of [`GrSite::name`]s (or `all`); disabling one site leaves every other
/// site's revalidation armed, so the guest still boots and the ONE disarmed site's own race is
/// what the harness reproduces. The previous single global switch was degenerate: turning it off
/// restored a never-refreshed snapshot process-wide, which broke the guest at ELF load before any
/// workload ran, so no harness could show a workload-level difference.
pub(crate) fn gr_check_plan_enabled(site: GrSite) -> bool {
    static DISABLED: OnceLock<[bool; GrSite::COUNT]> = OnceLock::new();
    let disabled = DISABLED.get_or_init(|| {
        let mut disabled = [false; GrSite::COUNT];
        let listed = std::env::var("LITEBOX_HVF_GR_DISABLE_SITES").unwrap_or_default();
        for name in listed.split(',') {
            let name = name.trim();
            if name.is_empty() {
                continue;
            }
            if name == "all" {
                return [true; GrSite::COUNT];
            }
            if let Some(site) = GrSite::ALL.iter().find(|site| site.name() == name) {
                disabled[site.index()] = true;
            }
        }
        disabled
    });
    !disabled[site.index()]
}

/// `LITEBOX_HVF_GR_TIME=1`: per-site nanoseconds for `plan` + `check_plan` (off by default, so
/// the two `ticks()` reads are not paid on any path that does not ask for them).
pub(crate) fn gr_time_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| gr_flag("LITEBOX_HVF_GR_TIME", false))
}

/// `LITEBOX_HVF_GR_STALE_SKIPS_ROUND=1`: the CONTROL ARM for the host-access site. It restores the
/// spending shape the reverted pass of this step shipped and measures it against the shipped one on
/// the SAME binary and the SAME workload.
///
/// The shape: a round whose plan the domain has moved on from ABANDONS the round (it reports
/// "acted" and lets `revalidated_rounds` re-snapshot) instead of re-planning in place. Because
/// `revalidated_rounds` spends one of its `HOST_PREPARE_ROUNDS` acting rounds on every `true` it
/// gets, a round spent re-planning is a round not spent preparing, and the budget can run out with
/// the preparation unfinished. Measured on `grs2 stress secs=300 workers=3 pages=8`:
/// `iov_wrong_data` 5,042 and 6,187 with this shape, **0** with the shipped one, on the same tree.
///
/// Note what this does NOT show: `LITEBOX_HVF_GR_DISABLE_SITES=host_access_plan` (no re-validation
/// at that site at all) also reports 0, because it degenerates to the pre-step shape, which is
/// correct here -- `revalidated_rounds`' own per-round re-snapshot is the T1h fix-up's and is not
/// what was wrong. The class-R hole this step closed was in how the verdict is SPENT.
pub(crate) fn gr_stale_skips_round() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| gr_flag("LITEBOX_HVF_GR_STALE_SKIPS_ROUND", false))
}

/// A `ticks()` reading for the per-site cost accounting; `0` when that is off.
pub(crate) fn gr_time_start() -> u64 {
    if gr_time_enabled() { ticks() } else { 0 }
}

pub(crate) fn gr_note_time(site: GrSite, started: u64) {
    if started != 0 {
        GR_COUNTERS.check_ns[site.index()]
            .fetch_add(ticks_to_ns(ticks().wrapping_sub(started)), Ordering::Relaxed);
    }
}

pub(crate) fn gr_counters_json() -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(2048);
    let sum = |table: &[AtomicU64; GrSite::COUNT]| -> u64 {
        table.iter().map(|cell| cell.load(Ordering::Relaxed)).sum()
    };
    let c = &GR_COUNTERS;
    let _ = write!(
        out,
        concat!(
            "{{\"plan_calls\":{},\"plan_retries\":{},\"plan_checks\":{},\"plan_stale\":{},",
            "\"plan_bound_exhausted\":{},\"plan_round_budget_exhausted\":{},",
            "\"judged_on_stale_plan\":{},",
            "\"invariant_checks\":{},\"invariant_violations\":{},",
            "\"invariant_pages_checked\":{},\"invariant_pages_span\":{},",
            "\"violation_claim_alias\":{},\"violation_multi_redirect\":{},",
            "\"violation_wx\":{},\"exempt_claim_promoted\":{},",
            "\"exempt_claim_file_alias\":{},\"exempt_window_redirect\":{},\"reservation_overlap\":{},\"by_site\":{{"
        ),
        sum(&c.plan_calls),
        sum(&c.plan_retries),
        sum(&c.plan_checks),
        sum(&c.plan_stale),
        sum(&c.plan_bound_exhausted),
        c.plan_round_budget_exhausted.load(Ordering::Relaxed),
        c.judged_on_stale_plan.load(Ordering::Relaxed),
        c.invariant_checks.load(Ordering::Relaxed),
        c.invariant_violations.load(Ordering::Relaxed),
        c.invariant_pages_checked.load(Ordering::Relaxed),
        c.invariant_pages_span.load(Ordering::Relaxed),
        c.violation_claim_alias.load(Ordering::Relaxed),
        c.violation_multi_redirect.load(Ordering::Relaxed),
        c.violation_wx.load(Ordering::Relaxed),
        c.exempt_claim_promoted.load(Ordering::Relaxed),
        c.exempt_claim_file_alias.load(Ordering::Relaxed),
        c.exempt_window_redirect.load(Ordering::Relaxed),
        c.reservation_overlap.load(Ordering::Relaxed),
    );
    for (index, site) in GrSite::ALL.iter().enumerate() {
        let _ = write!(
            out,
            "\"{}\":{{\"plan_calls\":{},\"plan_retries\":{},\"plan_checks\":{},\"plan_stale\":{},\"plan_bound_exhausted\":{},\"check_ns\":{}}},",
            site.name(),
            c.plan_calls[index].load(Ordering::Relaxed),
            c.plan_retries[index].load(Ordering::Relaxed),
            c.plan_checks[index].load(Ordering::Relaxed),
            c.plan_stale[index].load(Ordering::Relaxed),
            c.plan_bound_exhausted[index].load(Ordering::Relaxed),
            c.check_ns[index].load(Ordering::Relaxed),
        );
    }
    if !out.ends_with('{') {
        out.pop();
    }
    out.push_str("}}");
    out
}

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
                "\"pinned_shared_backings\":{},\"claimed_pages\":{},\"live_data_pages\":{},",
                "\"file_origin_objects\":{},\"file_windows_live\":{},\"file_alias_pages_live\":{},",
                "\"bound_vcpus\":{},\"lost_vcpus\":{}}},"
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
            l.file_origin_objects,
            l.file_windows_live,
            l.file_alias_pages_live,
            l.bound_vcpus,
            l.lost_vcpus,
        );
        let _ = write!(out, "\"hvf_file_cow\":{},", backend.file_cow_counters_json());
        let _ = write!(out, "\"hvf_gr\":{},", gr_counters_json());
    } else {
        let _ = write!(
            out,
            concat!(
                "\"hvf_exception_counters\":null,\"hvf_lifecycle_residual\":null,",
                "\"hvf_file_cow\":null,\"hvf_gr\":{}"
            ),
            gr_counters_json()
        );
    }
    // BCORE: the bound-vCPU path (all zeroes when `LITEBOX_HVF_BOUND` was never enabled).
    let _ = write!(out, "\"bound\":{},", bound_counters_json());

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
            "\"canceled_monitor_exits\":{},\"canceled_latched\":{},",
            // T1b: absent on runners built before it -> 0 there.
            "\"scoped_rounds\":{},\"global_rounds\":{},\"considered\":{},",
            "\"skipped_other_space\":{}}},"
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
        KICK_SCOPED_ROUNDS.load(Ordering::Relaxed),
        KICK_GLOBAL_ROUNDS.load(Ordering::Relaxed),
        KICK_CONSIDERED.load(Ordering::Relaxed),
        KICK_SKIPPED_OTHER_SPACE.load(Ordering::Relaxed),
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
    let (count, sum_ns, max_ns, buckets) = EXCEPTION_SERVICE.snapshot();
    let _ = write!(
        out,
        "\"exception_service\":{{\"count\":{},\"sum_ns\":{},\"max_ns\":{},\"buckets\":",
        count, sum_ns, max_ns,
    );
    push_buckets(&mut out, &buckets);
    out.push_str("},");
    // hvf-glive-unattributed-slow-syscall-mass: the on-CPU/off-CPU split of guest-syscall wall
    // time over the whole session. Only populated when LITEBOX_HVF_SYSCALL_CPU=1 (otherwise
    // `accounted` stays 0 and the row must be ignored, not read as "zero CPU").
    let _ = write!(
        out,
        "\"syscall_cpu\":{{\"accounted\":{},\"cpu_sum_ns\":{},\"off_cpu_sum_ns\":{}}},",
        SYSCALL_CPU_ACCOUNTED.load(Ordering::Relaxed),
        SYSCALL_CPU_NS.load(Ordering::Relaxed),
        SYSCALL_CPU_OFF_NS.load(Ordering::Relaxed),
    );
    render_retirement_pump(&mut out);
    render_rbnr(&mut out);
    render_slow_syscalls(&mut out);
    render_lock_attribution(&mut out);
    render_rank_discipline(&mut out);
    render_resident_state(&mut out);
    render_lane_sticky(&mut out);
    render_instrumentation(&mut out);
    render_origins(&mut out);
    render_t1f(&mut out);

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

    // Step G: the per-space runnable-not-running readout (with each space's pid/comm), the most
    // recent 16 intervals at or over 1 ms, and every interval at or over 100 ms (`rbnr_stall_ring`,
    // the rate-limit-free record per-event attribution matches on).
    out.push_str(",\"rbnr_spaces\":");
    render_rbnr_spaces(&mut out);
    out.push_str("\"rbnr_ring\":");
    render_rbnr_ring(&mut out);
    out.push_str(",\"rbnr_stall_ring\":");
    render_rbnr_ring_rows(&mut out, &RBNR_STALL_RING, &RBNR_STALL_CURSOR, RBNR_STALL_RING_LEN);

    out.push('}');
    out
}
