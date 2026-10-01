// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! NETFIX permanent guard: release counters for the network worker and the socket registry
//! (spec section 5.1 + Addendum A), rendered as the `net` block of the combined counters snapshot
//! (`<runner> -Z --counters <run-dir>`, `/proc/litebox/counters`).
//!
//! Plain relaxed atomics: every reader is a diagnostics snapshot, and the hot increments
//! (`dirty_marks`, `dirty_coalesced`) are one uncontended-in-practice RMW on a path that already
//! takes a ring mutex. The worker-side counters are written by the single network worker thread.

use core::sync::atomic::{AtomicU64, Ordering};

/// `Network::perform_platform_interaction` calls (one smoltcp poll each).
pub(crate) static POLLS: AtomicU64 = AtomicU64::new(0);
/// Polls whose smoltcp result was `SocketStateChanged`.
pub(crate) static POLLS_CHANGED: AtomicU64 = AtomicU64::new(0);
/// Polls that answered `CallAgainImmediately` (no park before the next one). With
/// `polls_changed` and the sleep time this separates "each poll is slow" from "the worker spins".
pub(crate) static POLLS_IMMEDIATE: AtomicU64 = AtomicU64::new(0);
/// Times the runner's loop hit its cap on consecutive immediate re-polls and yielded.
pub(crate) static IMMEDIATE_CAP_HITS: AtomicU64 = AtomicU64::new(0);
/// Wall time spent inside polls (the worker's busy time), and the longest single poll.
pub(crate) static POLL_NS_SUM: AtomicU64 = AtomicU64::new(0);
pub(crate) static POLL_NS_MAX: AtomicU64 = AtomicU64::new(0);
/// What ended each park of the worker (see [`WorkerWake`]).
pub(crate) static WAKES: [AtomicU64; 7] = [const { AtomicU64::new(0) }; 7];
/// Wall time the worker spent parked (or in the legacy sleep).
pub(crate) static SLEEP_NS: AtomicU64 = AtomicU64::new(0);
/// Channel marks that queued a socket for the next poll, marks that found it already queued,
/// and queued keys the worker serviced.
pub(crate) static DIRTY_MARKS: AtomicU64 = AtomicU64::new(0);
pub(crate) static DIRTY_COALESCED: AtomicU64 = AtomicU64::new(0);
pub(crate) static DIRTY_DRAINED: AtomicU64 = AtomicU64::new(0);
/// `Network` operations that asked the worker for a poll (connect, close, shutdown, send, ...).
pub(crate) static KICKS: AtomicU64 = AtomicU64::new(0);
/// Live socket descriptions in the registry, the most ever live at once, and records whose
/// descriptor entry was found dead without having been closed through `Network` (must stay 0).
pub(crate) static REGISTRY_LIVE: AtomicU64 = AtomicU64::new(0);
pub(crate) static REGISTRY_PEAK: AtomicU64 = AtomicU64::new(0);
pub(crate) static REGISTRY_DEAD_WEAK: AtomicU64 = AtomicU64::new(0);
/// Whole-registry passes (after a poll that moved packets, or one a socket timer was due for),
/// and the socket services those passes performed.
pub(crate) static REGISTRY_SCANS: AtomicU64 = AtomicU64::new(0);
pub(crate) static REGISTRY_SCANNED: AtomicU64 = AtomicU64::new(0);
/// Every per-socket service (dirty, queued by an operation, pending close, or a scan).
pub(crate) static SERVICES: AtomicU64 = AtomicU64::new(0);
/// Sockets waiting for their deferred close / `SHUT_WR` FIN, and descriptors queued for a close
/// that has to wait for another alias (dup, fork child, `SCM_RIGHTS`).
pub(crate) static PENDING_CLOSE_LIVE: AtomicU64 = AtomicU64::new(0);
pub(crate) static QUEUED_CLOSE_LIVE: AtomicU64 = AtomicU64::new(0);
/// Queued-close drains that took the descriptor table (each one removes something).
pub(crate) static QUEUED_CLOSE_DRAINS: AtomicU64 = AtomicU64::new(0);

/// What ended one park of the network worker; recorded by the runner's loop.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WorkerWake {
    /// A doorbell wake after at least one channel mark (guest/host data to move).
    Dirty,
    /// A doorbell wake after a `Network` operation's kick and no mark.
    Kick,
    /// A doorbell wake with neither (a NAT dial completing, or a wake left over from the
    /// previous cycle).
    Other,
    /// A device or host-side flow became readable.
    Packet,
    /// The park ended at the stack's own timer deadline (shorter than the safety cap).
    Timer,
    /// The park ended at the safety cap.
    Cap,
    /// The platform has no wake mechanism; the runner slept its legacy bounded interval.
    UnsupportedSleep,
}

impl WorkerWake {
    const ALL: [WorkerWake; 7] = [
        WorkerWake::Dirty,
        WorkerWake::Kick,
        WorkerWake::Other,
        WorkerWake::Packet,
        WorkerWake::Timer,
        WorkerWake::Cap,
        WorkerWake::UnsupportedSleep,
    ];

    fn index(self) -> usize {
        match self {
            WorkerWake::Dirty => 0,
            WorkerWake::Kick => 1,
            WorkerWake::Other => 2,
            WorkerWake::Packet => 3,
            WorkerWake::Timer => 4,
            WorkerWake::Cap => 5,
            WorkerWake::UnsupportedSleep => 6,
        }
    }

    fn name(self) -> &'static str {
        match self {
            WorkerWake::Dirty => "dirty",
            WorkerWake::Kick => "kick",
            WorkerWake::Other => "other",
            WorkerWake::Packet => "packet",
            WorkerWake::Timer => "timer",
            WorkerWake::Cap => "cap",
            WorkerWake::UnsupportedSleep => "unsupported_sleep",
        }
    }
}

/// Record what ended one park of the worker and how long it lasted.
pub fn note_worker_wake(wake: WorkerWake, slept_ns: u64) {
    WAKES[wake.index()].fetch_add(1, Ordering::Relaxed);
    SLEEP_NS.fetch_add(slept_ns, Ordering::Relaxed);
}

/// Record that the runner's loop yielded after its cap of consecutive immediate re-polls.
pub fn note_worker_immediate_cap_hit() {
    IMMEDIATE_CAP_HITS.fetch_add(1, Ordering::Relaxed);
}

/// `(dirty marks, kicks)` so far: the runner snapshots this around a park to tell a data wake
/// from an operation wake.
#[must_use]
pub fn worker_wake_sources() -> (u64, u64) {
    (
        DIRTY_MARKS.load(Ordering::Relaxed),
        KICKS.load(Ordering::Relaxed),
    )
}

pub(crate) fn note_poll(changed: bool, immediate: bool, ns: u64) {
    POLLS.fetch_add(1, Ordering::Relaxed);
    if changed {
        POLLS_CHANGED.fetch_add(1, Ordering::Relaxed);
    }
    if immediate {
        POLLS_IMMEDIATE.fetch_add(1, Ordering::Relaxed);
    }
    POLL_NS_SUM.fetch_add(ns, Ordering::Relaxed);
    POLL_NS_MAX.fetch_max(ns, Ordering::Relaxed);
}

/// The `net` block of the combined counters snapshot: a complete JSON object.
#[must_use]
pub fn counters_json() -> alloc::string::String {
    use core::fmt::Write as _;
    let load = |c: &AtomicU64| c.load(Ordering::Relaxed);
    let polls = load(&POLLS);
    let changed = load(&POLLS_CHANGED);
    let mut out = alloc::string::String::new();
    let _ = write!(
        out,
        "{{\"polls\":{polls},\"polls_changed\":{changed},\"polls_none\":{},\"polls_immediate\":{},\"immediate_cap_hits\":{},\"poll_ns_sum\":{},\"poll_ns_max\":{},\"sleep_ns\":{},\"wakes\":{{",
        polls.saturating_sub(changed),
        load(&POLLS_IMMEDIATE),
        load(&IMMEDIATE_CAP_HITS),
        load(&POLL_NS_SUM),
        load(&POLL_NS_MAX),
        load(&SLEEP_NS),
    );
    for (i, wake) in WorkerWake::ALL.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        let _ = write!(out, "\"{}\":{}", wake.name(), load(&WAKES[wake.index()]));
    }
    let _ = write!(
        out,
        "}},\"dirty_marks\":{},\"dirty_coalesced\":{},\"dirty_drained\":{},\"kicks\":{},\"services\":{},\"registry_live\":{},\"registry_peak\":{},\"registry_dead_weak\":{},\"registry_scans\":{},\"registry_scanned\":{},\"pending_close_live\":{},\"queued_close_live\":{},\"queued_close_drains\":{}}}",
        load(&DIRTY_MARKS),
        load(&DIRTY_COALESCED),
        load(&DIRTY_DRAINED),
        load(&KICKS),
        load(&SERVICES),
        load(&REGISTRY_LIVE),
        load(&REGISTRY_PEAK),
        load(&REGISTRY_DEAD_WEAK),
        load(&REGISTRY_SCANS),
        load(&REGISTRY_SCANNED),
        load(&PENDING_CLOSE_LIVE),
        load(&QUEUED_CLOSE_LIVE),
        load(&QUEUED_CLOSE_DRAINS),
    );
    out
}
