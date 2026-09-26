// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Opt-in latency trace points for the input -> guest -> framebuffer -> browser pipeline.
//!
//! Off by default: unless `LITEBOX_LATENCY_TRACE=<path>` is set in the runner's environment,
//! every trace point in this process is one relaxed atomic load plus a branch -- no clock read,
//! no allocation, no file, no lock. Set, each point appends one text line to `<path>`:
//!
//! ```text
//! kind,seq,extra,t_ns
//! ```
//!
//! * `kind` -- the trace point's name: one of the `pub const`s below for everything this crate
//!   records (the runner may add its own kinds through [`record`]).
//! * `seq` -- the number joining one input's or one frame's records across threads: the input
//!   sequence number of a browser connection (from 1, per connection) or the frame sequence
//!   number of a browser connection (from 1, per connection; the number that frame's WebSocket
//!   ping carries and, while tracing is on, its message trailer).
//! * `extra` -- a per-kind payload, documented on each `kind` constant; `0` when it has none.
//! * `t_ns` -- nanoseconds since one process-wide [`std::time::Instant`] epoch ([`epoch`]),
//!   shared by every trace point on every thread, so any two records subtract directly.
//!
//! The first line of a process's run is `EPOCH,<pid>,<unix wall-clock ns>,<t_ns>`: the wall
//! clock as read at trace-relative time `t_ns`, so an external harness on the same machine
//! (Python's `time.time_ns()`) can place its own timestamps on this timeline. The file is opened
//! in append mode (a path reused across runs keeps every run, each starting with its own `EPOCH`
//! line) and bounded: at most `LITEBOX_LATENCY_TRACE_LINES` lines (default
//! [`DEFAULT_LINE_BUDGET`]) follow `EPOCH`; if that bound is reached, the last of them is
//! `TRACE_TRUNCATED,<budget>,0,<t_ns>` and every later point is again a single atomic load. Each
//! line is one `write(2)`, flushed immediately, so a run killed mid-trial loses nothing already
//! recorded; while tracing is on, that syscall (a few microseconds, paid on the recording thread)
//! is the cost of a point.

use std::fs::{File, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock, PoisonError};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

/// Environment variable naming the trace file; unset or empty means tracing is off.
pub const ENV_PATH: &str = "LITEBOX_LATENCY_TRACE";
/// Environment variable overriding [`DEFAULT_LINE_BUDGET`] (a positive integer).
pub const ENV_LINE_BUDGET: &str = "LITEBOX_LATENCY_TRACE_LINES";
/// Lines one process may append after its `EPOCH` line, the closing `TRACE_TRUNCATED` included.
pub const DEFAULT_LINE_BUDGET: u64 = 1_000_000;

/// A key or pointer message was parsed off a browser connection, before the runner's input
/// handler ran. `seq`: that connection's input number, from 1. `extra`: the message, packed by
/// [`key_extra`] or [`pointer_extra`].
pub const INPUT_RECV: &str = "INPUT_RECV";
/// The runner's input handler returned for that message. It runs synchronously on the
/// connection's reader thread, so `INPUT_HANDLED - INPUT_RECV` is the whole host-side injection
/// (evdev queue included). `seq`/`extra`: as `INPUT_RECV`.
pub const INPUT_HANDLED: &str = "INPUT_HANDLED";
/// The pusher poll that found this frame's changed bands began its framebuffer snapshot at
/// `t_ns`. `seq`: the frame number those bands were sent as. `extra`: `t_ns` of the previous
/// poll's snapshot -- the last look at the framebuffer that did NOT include this change (0 when
/// this was the connection's first poll) -- so the guest's write landed between the two.
pub const FRAME_SNAPSHOT: &str = "FRAME_SNAPSHOT";
/// The snapshot and band diff finished and found changed bands. `extra`:
/// `(band count << 32) | (first band y << 16) | first band height`, see [`bands_extra`].
pub const FRAME_DIRTY: &str = "FRAME_DIRTY";
/// The frame's WebSocket message is fully encoded. `extra`: its payload length in bytes.
pub const FRAME_ENCODED: &str = "FRAME_ENCODED";
/// The message and the ping that follows it were written to the socket. `extra`: payload bytes.
pub const FRAME_SENT: &str = "FRAME_SENT";
/// The browser's pong for that ping arrived (its network stack has read past the frame; see
/// `web.rs`'s `FrameAcks`). `extra`: the highest frame acknowledged before this one.
pub const FRAME_ACKED: &str = "FRAME_ACKED";
/// The trace-aware viewer page reported that this frame's message reached its `onmessage`
/// handler. `t_ns`: when that report reached the server (the same instant as the matching
/// `VIEWER_DISPLAYED`). `extra`: the page's `performance.now()` at `onmessage` entry, in whole
/// microseconds of the page's own clock.
pub const VIEWER_RECEIVED: &str = "VIEWER_RECEIVED";
/// The page reported that all of this frame's bands were painted (`putImageData`) and the
/// `requestAnimationFrame` callback after them ran. `t_ns`: server receipt of the report.
/// `extra`: the page's `performance.now()` in that callback, whole microseconds of the page's
/// clock; `VIEWER_DISPLAYED.extra - VIEWER_RECEIVED.extra` is the page's own decode + paint +
/// animation-frame wait. Bias: the callback runs before that animation frame is composited, so
/// the pixels reach the screen up to one display refresh (~16.7ms at 60Hz) after this point,
/// never before.
pub const VIEWER_DISPLAYED: &str = "VIEWER_DISPLAYED";

const UNRESOLVED: u8 = 0;
const OFF: u8 = 1;
const ON: u8 = 2;

/// The hot-path cache of "is tracing on", resolved from the environment by the first trace point.
static STATE: AtomicU8 = AtomicU8::new(UNRESOLVED);
/// The process-wide time origin every `t_ns` counts from.
static EPOCH: OnceLock<Instant> = OnceLock::new();
/// The open trace file, `None` once resolved as off.
static SINK: OnceLock<Option<Mutex<Sink>>> = OnceLock::new();
/// See [`last_input_seq`].
static LAST_INPUT_SEQ: AtomicU64 = AtomicU64::new(0);

struct Sink {
    writer: BufWriter<File>,
    budget: u64,
    remaining: u64,
}

impl Sink {
    fn append(&mut self, kind: &str, seq: u64, extra: u64, t_ns: u64) -> io::Result<()> {
        writeln!(self.writer, "{kind},{seq},{extra},{t_ns}")?;
        self.writer.flush()
    }
}

/// The process-wide time origin of every `t_ns`: fixed the first time any trace function needs
/// it, shared by every thread and every crate that records through this module.
#[must_use]
pub fn epoch() -> Instant {
    *EPOCH.get_or_init(Instant::now)
}

/// Nanoseconds since [`epoch`]: the timeline every record's `t_ns` is on.
#[must_use]
pub fn now_ns() -> u64 {
    u64::try_from(epoch().elapsed().as_nanos()).unwrap_or(u64::MAX)
}

/// Whether tracing is on. One relaxed atomic load once resolved; the first call in the process
/// reads the environment and opens the file.
#[inline]
#[must_use]
pub fn enabled() -> bool {
    match STATE.load(Ordering::Relaxed) {
        ON => true,
        OFF => false,
        _ => resolve(),
    }
}

#[cold]
fn resolve() -> bool {
    let on = SINK.get_or_init(open_sink).is_some();
    STATE.store(if on { ON } else { OFF }, Ordering::Relaxed);
    on
}

fn open_sink() -> Option<Mutex<Sink>> {
    let path = std::env::var_os(ENV_PATH).filter(|path| !path.is_empty())?;
    let file = match OpenOptions::new().create(true).append(true).open(&path) {
        Ok(file) => file,
        Err(error) => {
            litebox_util_log::warn!(path:? = path, error:% = error; "latency trace: cannot open the trace file; tracing stays off");
            return None;
        }
    };
    let budget = std::env::var(ENV_LINE_BUDGET)
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .filter(|&lines| lines > 0)
        .unwrap_or(DEFAULT_LINE_BUDGET);
    // Read back-to-back so the header pairs one wall-clock reading with its trace-relative time.
    let t_ns = now_ns();
    let wall_ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| u64::try_from(since.as_nanos()).unwrap_or(u64::MAX));
    let mut sink = Sink {
        writer: BufWriter::new(file),
        budget,
        remaining: budget,
    };
    if let Err(error) = sink.append("EPOCH", u64::from(std::process::id()), wall_ns, t_ns) {
        litebox_util_log::warn!(path:? = path, error:% = error; "latency trace: cannot write the trace file; tracing stays off");
        return None;
    }
    litebox_util_log::info!(path:? = path, line_budget:% = budget; "latency trace on");
    Some(Mutex::new(sink))
}

/// Appends `kind,seq,extra,<now>` when tracing is on; otherwise one relaxed atomic load.
pub fn record(kind: &str, seq: u64, extra: u64) {
    if enabled() {
        append(kind, seq, extra, now_ns());
    }
}

/// [`record`] with a caller-supplied `t_ns` (from [`now_ns`]): for a point whose instant is
/// captured before work it must not delay, with the line written afterwards.
pub fn record_at(kind: &str, seq: u64, extra: u64, t_ns: u64) {
    if enabled() {
        append(kind, seq, extra, t_ns);
    }
}

fn append(kind: &str, seq: u64, extra: u64, t_ns: u64) {
    let Some(sink) = SINK.get_or_init(open_sink) else {
        return;
    };
    let mut sink = sink.lock().unwrap_or_else(PoisonError::into_inner);
    if sink.remaining == 0 {
        // Truncated (or failed) already; a caller that passed `enabled()` just before the flag
        // flipped lands here once.
        return;
    }
    sink.remaining -= 1;
    let result = if sink.remaining == 0 {
        STATE.store(OFF, Ordering::Relaxed);
        let budget = sink.budget;
        sink.append("TRACE_TRUNCATED", budget, 0, t_ns)
    } else {
        sink.append(kind, seq, extra, t_ns)
    };
    if let Err(error) = result {
        STATE.store(OFF, Ordering::Relaxed);
        sink.remaining = 0;
        litebox_util_log::warn!(error:% = error; "latency trace: write failed; tracing is now off");
    }
}

/// The input sequence number of the browser message whose handling is in progress (or most
/// recently began): the side channel through which the runner's input handler -- invoked
/// synchronously on the connection's reader thread, between that message's `INPUT_RECV` and
/// `INPUT_HANDLED` -- tags its own records with the same `seq`. Written just before the handler
/// is invoked, only while tracing is on; last writer wins, so it identifies an input unambiguously
/// only while a single input-sending client is connected (the trial configuration).
#[must_use]
pub fn last_input_seq() -> u64 {
    LAST_INPUT_SEQ.load(Ordering::Relaxed)
}

pub(crate) fn set_last_input_seq(seq: u64) {
    LAST_INPUT_SEQ.store(seq, Ordering::Relaxed);
}

/// `INPUT_RECV`/`INPUT_HANDLED` `extra` for a key message: `(1 << 48) | (down << 32) | keysym`.
#[must_use]
pub fn key_extra(down: bool, keysym: u32) -> u64 {
    (1 << 48) | (u64::from(down) << 32) | u64::from(keysym)
}

/// `INPUT_RECV`/`INPUT_HANDLED` `extra` for a pointer message:
/// `(2 << 48) | (button_mask << 32) | (x << 16) | y`.
#[must_use]
pub fn pointer_extra(button_mask: u8, x: u16, y: u16) -> u64 {
    (2 << 48) | (u64::from(button_mask) << 32) | (u64::from(x) << 16) | u64::from(y)
}

/// `FRAME_DIRTY`'s `extra`: `(band_count << 32) | (first_y << 16) | first_height`.
#[must_use]
pub fn bands_extra(band_count: usize, first_y: u16, first_height: u16) -> u64 {
    let count = u64::try_from(band_count)
        .unwrap_or(u64::MAX)
        .min(u64::from(u32::MAX));
    (count << 32) | (u64::from(first_y) << 16) | u64::from(first_height)
}
