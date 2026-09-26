// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! A browser-based viewer for the guest framebuffer: one tiny HTTP server that serves an
//! embedded single-page canvas client at `/` and speaks a WebSocket protocol at `/ws`.
//!
//! Rationale: macOS's built-in Screen Sharing refuses to dial localhost (it treats a
//! self-connection as controlling your own screen), so "just point a VNC viewer at
//! 127.0.0.1" fails on exactly the machine the runner runs on. A browser has no such rule,
//! ships on every host, and needs no install. The page and the wire protocol are both ours,
//! so this sidesteps RFB client compatibility entirely.
//!
//! Wire protocol, deliberately simpler than RFB:
//! * server -> client, binary: `[u16 width BE][u16 height BE][u16 rect count BE]` then, per
//!   rect, `[u16 y BE][u16 height BE][width*height*4 RGBA bytes]` -- only the full-width bands
//!   that actually changed since the last frame sent to *this* client (the same incremental-
//!   update banding the native RFB server already does; see `server.rs`'s `dirty_bands`, reused
//!   here), sent as soon as one of the pusher's polls (every `POLL_INTERVAL`) finds a changed band,
//!   never two frames closer together than `MIN_FRAME_SPACING`, and only once the browser has
//!   acknowledged the previous frame: each frame is followed by a
//!   WebSocket ping carrying the frame's sequence number, and every browser answers pings with a
//!   pong automatically (RFC 6455 §5.5.2), so the pong is a frame-consumed signal that needs
//!   nothing from the page's own script (see `FrameAcks`). Banding, not full-frame resends, matters
//!   here for more than bandwidth: the pusher thread's own encode+write work runs on the same host
//!   process (and competes for the same host CPU) as the guest's vCPU threads in this userland
//!   hypervisor, so a full 1024x768+ frame re-encoded on every changed tick -- which a single
//!   blinking cursor or one typed character triggered just as often as a full repaint -- was
//!   directly taking host CPU away from the guest making forward progress.
//! * client -> server, binary: `[1u8][down u8][keysym u32 BE]` for keys (X11 keysyms, same
//!   values RFB uses, so the runner's existing translation applies unchanged), and
//!   `[2u8][button_mask u8][x u16 BE][y u16 BE]` for pointer state (RFB-style mask: bit 0
//!   left, bit 1 middle, bit 2 right, bits 3/4 wheel up/down edges).
//! * latency trace only (`LITEBOX_LATENCY_TRACE` set in the runner's environment, see
//!   [`crate::trace`]; unset, every byte above stays exactly as documented): each server ->
//!   client frame message ends with a trailer `[u64 frame seq BE]` after its last band -- the
//!   same number the frame's ping carries -- placed there rather than in the header so a client
//!   that walks the bands by count (this page before the trailer existed, the Python harnesses)
//!   never sees it; the embedded page recognizes it as exactly 8 bytes remaining after the bands
//!   and answers every such frame, once its bands are painted, with `[3u8][u64 frame seq BE][f64
//!   display ms BE][f64 receive ms BE]` (25 bytes; the `f64`s are the page's `performance.now()`
//!   in the `requestAnimationFrame` callback after the frame's `putImageData` calls, and at
//!   `onmessage` entry). The server accepts opcode 3 whether or not tracing is on and records it
//!   (`VIEWER_RECEIVED`, `VIEWER_DISPLAYED`) only when it is.
//!
//! Hand-rolled HTTP/WebSocket (RFC 6455) rather than a crate dependency, for the same reason
//! the RFB server is hand-rolled (see the crate docs): the handshake needs only SHA-1 +
//! base64, both small enough to carry inline, and the framing needed here is a strict subset
//! of the RFC.

use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::time::{Duration, Instant};

use crate::server::{
    dirty_bands, FramebufferSource, InputClient, InputEvent, InputHandler, InputMessage, KeyEvent,
    PointerEvent,
};
use crate::trace;

/// How often the pusher looks for a changed band while it has nothing to send. The framebuffer
/// is plain guest RAM that Xorg stores into directly (nothing traps per write), so a change can
/// only be discovered by diffing, and this period bounds how long a visual update waits before it
/// is noticed: at most one poll, ~5ms on average. One quiet poll is one snapshot plus band
/// compare, ~0.1-0.25ms at 1024x768 on an Apple Silicon host, so polling at 100 Hz costs ~1-2.5%
/// of one host core per connected client. (The fixed 50ms tick this replaces paid 25ms of mean
/// latency on every update, and a 20 fps ceiling on any motion, to save that ~2%.)
const POLL_INTERVAL: Duration = Duration::from_millis(10);

/// Minimum spacing between two frames sent to one client: the frame-rate ceiling (~60 Hz) a
/// browser is asked to paint at. Only ever waited for right after a frame went out; a quiet
/// screen never pays it.
const MIN_FRAME_SPACING: Duration = Duration::from_millis(16);

/// Longest the pusher waits for the pong acknowledging the previous frame before sending the next
/// one regardless. Bounds the damage a client that never answers pings can do to its own frame
/// rate (1 fps) without letting it hold a frame back forever.
const FRAME_ACK_TIMEOUT: Duration = Duration::from_secs(1);

/// Maximum time a client may spend completing its HTTP request head.
const HTTP_HEAD_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// The embedded viewer page served at `/`.
const VIEWER_HTML: &str = include_str!("viewer.html");

/// A browser-viewer server for a guest framebuffer. Mirrors [`crate::RfbServer`]'s lifecycle:
/// bind before any sandbox comes up, then `run` the accept loop on its own thread.
pub struct WebServer<F: FramebufferSource> {
    listener: TcpListener,
    framebuffer: Arc<F>,
    shutdown: Arc<AtomicBool>,
}

impl<F: FramebufferSource> WebServer<F> {
    /// Binds a new server. `addr` defaults to `127.0.0.1` (localhost-only) when `None`,
    /// matching the RFB server's default-closed posture.
    ///
    /// # Errors
    ///
    /// Fails if the TCP listener cannot bind.
    pub fn bind(addr: Option<IpAddr>, port: u16, framebuffer: Arc<F>) -> io::Result<Self> {
        let addr = addr.unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST));
        let listener = TcpListener::bind((addr, port))?;
        Ok(Self {
            listener,
            framebuffer,
            shutdown: Arc::new(AtomicBool::new(false)),
        })
    }

    /// The address this server actually bound to.
    ///
    /// # Errors
    ///
    /// Propagates the socket's `local_addr` failure.
    pub fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.listener.local_addr()
    }

    /// See [`crate::RfbServer::shutdown_handle`].
    #[must_use]
    pub fn shutdown_handle(&self) -> crate::ShutdownHandle {
        crate::ShutdownHandle {
            flag: Arc::clone(&self.shutdown),
        }
    }

    /// Accepts connections until shut down, serving each on its own spawned thread; same
    /// contract as [`crate::RfbServer::run`].
    ///
    /// # Errors
    ///
    /// Returns any accept-loop error other than the polling `WouldBlock`.
    pub fn run(&self, on_input: impl Fn(InputMessage) + Send + Sync + 'static) -> io::Result<()> {
        self.listener.set_nonblocking(true)?;
        let on_input: Arc<InputHandler> = Arc::new(on_input);
        while !self.shutdown.load(Ordering::Relaxed) {
            match self.listener.accept() {
                Ok((stream, peer)) => {
                    litebox_util_log::info!(peer:% = peer; "web viewer client connecting");
                    let framebuffer = Arc::clone(&self.framebuffer);
                    let on_input = Arc::clone(&on_input);
                    std::thread::spawn(move || {
                        if let Err(e) = serve_connection(stream, &framebuffer, &on_input) {
                            litebox_util_log::debug!(peer:% = peer, error:% = e; "web viewer client done");
                        }
                    });
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(500));
                }
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
}

/// Reads one HTTP request head (through `\r\n\r\n`) and routes it.
fn serve_connection<F: FramebufferSource>(
    stream: TcpStream,
    framebuffer: &Arc<F>,
    on_input: &Arc<InputHandler>,
) -> io::Result<()> {
    serve_connection_with_head_timeout(stream, framebuffer, on_input, HTTP_HEAD_TIMEOUT)
}

fn serve_connection_with_head_timeout<F: FramebufferSource>(
    mut stream: TcpStream,
    framebuffer: &Arc<F>,
    on_input: &Arc<InputHandler>,
    budget: std::time::Duration,
) -> io::Result<()> {
    stream.set_nonblocking(false)?;
    stream.set_nodelay(true)?;
    let local_addr = stream.local_addr()?;
    let deadline = std::time::Instant::now()
        .checked_add(budget)
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "HTTP head timeout too large")
        })?;

    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() > 16 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "header too long",
            ));
        }
        let remaining = deadline
            .checked_duration_since(std::time::Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "HTTP head timed out"))?;
        stream.set_read_timeout(Some(remaining))?;
        stream.read_exact(&mut byte)?;
        head.push(byte[0]);
    }
    stream.set_read_timeout(None)?;
    let head = String::from_utf8_lossy(&head).into_owned();
    let request_line = head.lines().next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("");

    let header = |name: &str| -> Option<&str> {
        let mut values = head.lines().filter_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.trim().eq_ignore_ascii_case(name).then(|| value.trim())
        });
        let value = values.next()?;
        values.next().is_none().then_some(value)
    };

    if !method.eq_ignore_ascii_case("GET") {
        stream.write_all(b"HTTP/1.1 405 Method Not Allowed\r\nConnection: close\r\n\r\n")?;
        return Ok(());
    }

    match path {
        "/" | "/index.html" => {
            let body = VIEWER_HTML.as_bytes();
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            stream.write_all(resp.as_bytes())?;
            stream.write_all(body)?;
            Ok(())
        }
        "/ws" => {
            let Some(key) = header("Sec-WebSocket-Key").filter(|key| !key.is_empty()) else {
                stream.write_all(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")?;
                return Ok(());
            };
            let valid_upgrade = header("Upgrade")
                .is_some_and(|value| value.eq_ignore_ascii_case("websocket"))
                && header("Connection").is_some_and(|value| {
                    value
                        .split(',')
                        .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
                })
                && header("Sec-WebSocket-Version") == Some("13");
            if !valid_upgrade {
                stream.write_all(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")?;
                return Ok(());
            }
            let valid_origin = match (header("Host"), header("Origin")) {
                (Some(host), Some(origin)) => {
                    let endpoint_host = local_addr.to_string();
                    let loopback_host = format!("localhost:{}", local_addr.port());
                    let host_allowed = host.eq_ignore_ascii_case(&endpoint_host)
                        || (local_addr.ip().is_loopback()
                            && host.eq_ignore_ascii_case(&loopback_host));
                    host_allowed && origin.eq_ignore_ascii_case(&format!("http://{host}"))
                }
                _ => false,
            };
            if !valid_origin {
                stream.write_all(b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n")?;
                return Ok(());
            }
            let accept = websocket_accept_value(key);
            let resp = format!(
                "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
            );
            stream.write_all(resp.as_bytes())?;
            serve_websocket(stream, framebuffer, on_input)
        }
        _ => {
            stream.write_all(b"HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n")?;
            Ok(())
        }
    }
}

/// Serializes every server-to-client operation on one connection.
struct WsWriter {
    stream: std::sync::Mutex<TcpStream>,
}

impl WsWriter {
    fn new(stream: TcpStream) -> Self {
        Self {
            stream: std::sync::Mutex::new(stream),
        }
    }

    fn write(&self, operation: impl FnOnce(&mut TcpStream) -> io::Result<()>) -> io::Result<()> {
        let mut stream = self
            .stream
            .lock()
            .map_err(|_| io::Error::other("WebSocket writer lock poisoned"))?;
        if let Err(error) = operation(&mut stream) {
            let _ = stream.shutdown(std::net::Shutdown::Both);
            return Err(error);
        }
        Ok(())
    }

    fn write_binary(&self, payload: &[u8]) -> io::Result<()> {
        self.write(|stream| write_ws_binary_frames(stream, payload))
    }

    fn write_control(&self, opcode: u8, payload: &[u8]) -> io::Result<()> {
        // 0x8 close, 0x9 ping (the pusher's frame-consumed probe, see `FrameAcks`), 0xa pong.
        if !matches!(opcode, 0x8..=0xa) || payload.len() > 125 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid WebSocket control frame",
            ));
        }
        self.write(|stream| write_ws_frame(stream, true, opcode, payload))
    }

    fn try_write_control(&self, opcode: u8, payload: &[u8]) -> io::Result<()> {
        if !matches!(opcode, 0x8..=0xa) || payload.len() > 125 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid WebSocket control frame",
            ));
        }
        let Ok(mut stream) = self.stream.try_lock() else {
            // A framebuffer write can fill the socket after the peer has stopped reading. Input
            // teardown must never wait behind it; closing the TCP stream is itself a valid close
            // response when the best-effort control frame cannot be written immediately.
            return Ok(());
        };
        write_ws_frame(&mut stream, true, opcode, payload)
    }
}

/// Frame acknowledgements for one browser connection: the highest frame sequence number whose
/// ping the client has answered, shared between the reader thread (which records pongs) and the
/// pusher (which waits for them). The wire protocol carries no application-level ack and the
/// page's script must not change, but a browser pongs only once its network stack has read
/// past the frame, and Chromium/Firefox read from the socket only as fast as the page consumes
/// messages -- so waiting for the pong keeps at most one frame in flight per client and lets
/// the pusher snapshot the newest frame at the moment the browser is ready for it. Without it,
/// TCP alone lets a slow page queue seconds of stale frames in socket and browser buffers.
struct FrameAcks {
    state: Mutex<AckState>,
    changed: Condvar,
}

#[derive(Default)]
struct AckState {
    acked: u64,
    stop: bool,
}

impl FrameAcks {
    fn new() -> Self {
        Self {
            state: Mutex::new(AckState::default()),
            changed: Condvar::new(),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, AckState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn ack(&self, seq: u64) {
        // Latency trace: stamp the pong's arrival before taking the lock, write the line after
        // the pusher has been woken (one relaxed load when tracing is off).
        let received_ns = trace::enabled().then(trace::now_ns);
        let previously_acked = {
            let mut state = self.lock();
            let previously_acked = state.acked;
            state.acked = previously_acked.max(seq);
            self.changed.notify_all();
            previously_acked
        };
        if let Some(t_ns) = received_ns {
            trace::record_at(trace::FRAME_ACKED, seq, previously_acked, t_ns);
        }
    }

    fn stop(&self) {
        self.lock().stop = true;
        self.changed.notify_all();
    }

    /// Waits until frame `seq` is acknowledged or `timeout` passes; `false` once stopped.
    fn wait_acked(&self, seq: u64, timeout: Duration) -> bool {
        let (state, _) = self
            .changed
            .wait_timeout_while(self.lock(), timeout, |state| {
                state.acked < seq && !state.stop
            })
            .unwrap_or_else(PoisonError::into_inner);
        !state.stop
    }
}

/// After the 101: a pusher thread streams changed frames while this thread reads input
/// messages -- the same two-thread split as the RFB server's `serve_client`.
fn serve_websocket<F: FramebufferSource>(
    stream: TcpStream,
    framebuffer: &Arc<F>,
    on_input: &Arc<InputHandler>,
) -> io::Result<()> {
    let write_stream = stream.try_clone()?;
    write_stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let writer = Arc::new(WsWriter::new(write_stream));
    let mut input_client = InputClient::connect(&**on_input);
    let acks = Arc::new(FrameAcks::new());
    let pusher = {
        let framebuffer = Arc::clone(framebuffer);
        let writer = Arc::clone(&writer);
        let acks = Arc::clone(&acks);
        std::thread::spawn(move || {
            let mut pixels = Vec::new();
            // Pixels of the last frame sent to this client, so the next tick's diff is always
            // against exactly what is currently on its screen (not just "did anything change").
            let mut sent = Vec::new();
            let mut sent_dims = (0u16, 0u16);
            let mut message = Vec::new();
            let mut seq = 0u64;
            let mut last_sent: Option<Instant> = None;
            // Latency trace only: when the previous poll's snapshot began (`trace::now_ns`
            // units), carried by a dirty frame's `FRAME_SNAPSHOT` record to bracket the guest's
            // write between two looks at the framebuffer.
            let mut previous_poll_ns = 0u64;
            loop {
                // The previous frame's ack comes first, ahead of any snapshot work: a client that
                // has not consumed that frame yet gets nothing done on its behalf (at most one
                // frame in flight, see `FrameAcks`), and the snapshot below is then taken at the
                // moment the browser is ready for it rather than a poll earlier.
                if !acks.wait_acked(seq, FRAME_ACK_TIMEOUT) {
                    break;
                }
                if let Some(at) = last_sent {
                    std::thread::sleep(MIN_FRAME_SPACING.saturating_sub(at.elapsed()));
                }
                // One relaxed load per poll while tracing is off; the clock is read only when on.
                let traced = trace::enabled();
                let poll_ns = if traced { trace::now_ns() } else { 0 };
                let dims = framebuffer.dimensions();
                framebuffer.snapshot_into(&mut pixels);
                let stride = usize::from(dims.0) * 4;
                // Defensive against a transient dims/buffer-length mismatch, matching
                // `serve_updates`'s identical guard: never index past what was actually snapshotted.
                let rows = pixels
                    .len()
                    .checked_div(stride)
                    .map_or(0, |rows| u16::try_from(rows).unwrap_or(u16::MAX).min(dims.1));
                let full = dims != sent_dims || pixels.len() != sent.len();
                let rects: Vec<(u16, u16)> = if rows == 0 {
                    Vec::new()
                } else if full {
                    vec![(0, rows)]
                } else {
                    dirty_bands(&sent, &pixels, stride, rows)
                };
                if rects.is_empty() && !full {
                    // Quiet screen: look again one poll later. Nothing else paces this loop, so
                    // this wait is all a change ever waits for before it is noticed.
                    previous_poll_ns = poll_ns;
                    std::thread::sleep(POLL_INTERVAL);
                    continue;
                }
                seq += 1;
                if traced {
                    trace::record_at(trace::FRAME_SNAPSHOT, seq, previous_poll_ns, poll_ns);
                    let (first_y, first_height) = rects.first().copied().unwrap_or((0, 0));
                    trace::record(
                        trace::FRAME_DIRTY,
                        seq,
                        trace::bands_extra(rects.len(), first_y, first_height),
                    );
                }
                previous_poll_ns = poll_ns;
                message.clear();
                // Exact size up front: the 6-byte header, then per band its 4-byte header plus
                // its pixels (RGBA out is the same byte count as BGRX in), then the 8-byte
                // frame-sequence trailer while tracing is on.
                message.reserve(
                    6 + usize::from(traced) * 8
                        + rects
                            .iter()
                            .map(|&(_, band_height)| 4 + usize::from(band_height) * stride)
                            .sum::<usize>(),
                );
                message.extend_from_slice(&dims.0.to_be_bytes());
                message.extend_from_slice(&dims.1.to_be_bytes());
                message.extend_from_slice(&u16::try_from(rects.len()).unwrap_or(u16::MAX).to_be_bytes());
                for &(y, band_height) in &rects {
                    message.extend_from_slice(&y.to_be_bytes());
                    message.extend_from_slice(&band_height.to_be_bytes());
                    let band =
                        &pixels[usize::from(y) * stride..usize::from(y + band_height) * stride];
                    // XRGB8888 little-endian memory order is B,G,R,X; the canvas wants R,G,B,A.
                    // Swizzled as whole little-endian u32 pixels into the band's pre-sized tail
                    // rather than pushed four bytes at a time: the per-pixel `extend_from_slice`
                    // was a capacity check plus a 4-byte copy per pixel that never vectorized,
                    // ~4x the cost of this loop for a full 1024x768 frame (measured on the host).
                    let start = message.len();
                    message.resize(start + band.len(), 0);
                    for (out, px) in message[start..]
                        .as_chunks_mut::<4>()
                        .0
                        .iter_mut()
                        .zip(band.as_chunks::<4>().0)
                    {
                        let bgrx = u32::from_le_bytes(*px);
                        let rgba = ((bgrx >> 16) & 0xff)
                            | (bgrx & 0xff00)
                            | ((bgrx & 0xff) << 16)
                            | 0xff00_0000;
                        *out = rgba.to_le_bytes();
                    }
                }
                if traced {
                    // The trace-only trailer (module docs): the frame's sequence number after the
                    // last band, where a client walking the bands by count never looks.
                    message.extend_from_slice(&seq.to_be_bytes());
                    trace::record(
                        trace::FRAME_ENCODED,
                        seq,
                        u64::try_from(message.len()).unwrap_or(u64::MAX),
                    );
                }
                if writer.write_binary(&message).is_err()
                    || writer.write_control(0x9, &seq.to_be_bytes()).is_err()
                {
                    break;
                }
                if traced {
                    trace::record(
                        trace::FRAME_SENT,
                        seq,
                        u64::try_from(message.len()).unwrap_or(u64::MAX),
                    );
                }
                last_sent = Some(Instant::now());
                std::mem::swap(&mut sent, &mut pixels);
                sent_dims = dims;
            }
        })
    };

    let result = read_ws_loop(stream, &writer, &acks, &mut input_client);
    // Input cleanup must not wait behind a framebuffer writer blocked on the disconnected socket.
    drop(input_client);
    acks.stop();
    let _ = pusher.join();
    result
}

/// One logical server-to-client binary message, split into bounded RFC 6455 fragments.
fn write_ws_binary_frames(stream: &mut TcpStream, payload: &[u8]) -> io::Result<()> {
    const FRAME_PAYLOAD_LIMIT: usize = u16::MAX as usize;

    if payload.is_empty() {
        return write_ws_frame(stream, true, 0x2, payload);
    }

    let mut chunks = payload.chunks(FRAME_PAYLOAD_LIMIT).peekable();
    let mut opcode = 0x2;
    while let Some(chunk) = chunks.next() {
        write_ws_frame(stream, chunks.peek().is_none(), opcode, chunk)?;
        opcode = 0x0;
    }
    Ok(())
}

fn write_ws_frame(stream: &mut TcpStream, fin: bool, opcode: u8, payload: &[u8]) -> io::Result<()> {
    let mut header = [0u8; 4];
    header[0] = (if fin { 0x80 } else { 0 }) | opcode;
    let header_len = if payload.len() < 126 {
        #[allow(clippy::cast_possible_truncation)]
        {
            header[1] = payload.len() as u8;
        }
        2
    } else {
        let len = u16::try_from(payload.len()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "oversized WebSocket fragment")
        })?;
        header[1] = 126;
        header[2..].copy_from_slice(&len.to_be_bytes());
        4
    };
    stream.write_all(&header[..header_len])?;
    stream.write_all(payload)
}

/// Client-to-server frames: masked per RFC 6455. Handles binary input messages, answers ping
/// with pong, records the frame acknowledged by a pong, exits on close.
fn read_ws_loop(
    mut stream: TcpStream,
    writer: &WsWriter,
    acks: &FrameAcks,
    input_client: &mut InputClient<'_>,
) -> io::Result<()> {
    // Latency trace only: this connection's input count, the `seq` of its `INPUT_*` records.
    let mut input_seq = 0u64;
    // Permanent guard: this connection's own view of which keysyms are currently down. A
    // keyup for a keysym that is not down means some link in the chain lost a keydown (or
    // delivered a release twice) -- the exact failure that leaves a modifier stuck down in
    // the guest. Counting it here catches it for every client, including ones that do not
    // run our own viewer page, and the count lands in the runner log rather than in a
    // browser console nobody has open.
    let mut held_keysyms = std::collections::HashSet::<u32>::new();
    let mut stray_keyups = 0u64;
    loop {
        let mut hdr = [0u8; 2];
        match stream.read_exact(&mut hdr) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e),
        }
        let fin = hdr[0] & 0x80 != 0;
        let opcode = hdr[0] & 0x0f;
        let masked = hdr[1] & 0x80 != 0;
        if hdr[0] & 0x70 != 0 || !fin || !masked {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid WebSocket client frame",
            ));
        }
        let mut len = u64::from(hdr[1] & 0x7f);
        if len == 126 {
            let mut ext = [0u8; 2];
            stream.read_exact(&mut ext)?;
            len = u64::from(u16::from_be_bytes(ext));
        } else if len == 127 {
            let mut ext = [0u8; 8];
            stream.read_exact(&mut ext)?;
            len = u64::from_be_bytes(ext);
        }
        if (opcode >= 0x8 && (len > 125 || (opcode == 0x8 && len == 1))) || len > 4096 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid WebSocket frame length",
            ));
        }
        let mut mask = [0u8; 4];
        stream.read_exact(&mut mask)?;
        #[allow(clippy::cast_possible_truncation)]
        let mut payload = vec![0u8; len as usize];
        stream.read_exact(&mut payload)?;
        for (i, b) in payload.iter_mut().enumerate() {
            *b ^= mask[i % 4];
        }
        match opcode {
            // Binary: our input messages, plus the trace-aware page's display reports.
            0x2 => match payload.first() {
                Some(1) if payload.len() == 6 => {
                    let down = payload[1] != 0;
                    let key = u32::from_be_bytes([payload[2], payload[3], payload[4], payload[5]]);
                    if down {
                        held_keysyms.insert(key);
                    } else if !held_keysyms.remove(&key) {
                        stray_keyups += 1;
                        litebox_util_log::debug!(
                            keysym:% = key, stray_keyups;
                            "rfb: keyup for a keysym this client never pressed (lost keydown)"
                        );
                    }
                    deliver_input(
                        input_client,
                        InputEvent::Key(KeyEvent { down, key }),
                        trace::enabled().then(|| trace::key_extra(down, key)),
                        &mut input_seq,
                    );
                }
                Some(2) if payload.len() == 6 => {
                    let button_mask = payload[1];
                    let x = u16::from_be_bytes([payload[2], payload[3]]);
                    let y = u16::from_be_bytes([payload[4], payload[5]]);
                    deliver_input(
                        input_client,
                        InputEvent::Pointer(PointerEvent { button_mask, x, y }),
                        trace::enabled().then(|| trace::pointer_extra(button_mask, x, y)),
                        &mut input_seq,
                    );
                }
                Some(3) if payload.len() == 25 => record_viewer_report(&payload),
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid WebSocket input message",
                    ));
                }
            },
            // Ping -> pong with the same payload.
            0x9 => writer.write_control(0xa, &payload)?,
            // Close -> close with the same payload.
            0x8 => {
                if !held_keysyms.is_empty() {
                    litebox_util_log::debug!(
                        count = held_keysyms.len(), stray_keyups;
                        "rfb: client closed with keys still down (released by the handler)"
                    );
                }
                input_client.disconnect();
                writer.try_write_control(0x8, &payload)?;
                return Ok(());
            }
            // Pong: the answer to the ping sent after a frame carries that frame's sequence
            // number (see `FrameAcks`); any other pong is a no-op.
            0xa => {
                if let Ok(seq) = <[u8; 8]>::try_from(payload.as_slice()) {
                    acks.ack(u64::from_be_bytes(seq));
                }
            }
            // This endpoint accepts binary input only.
            0x1 => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unsupported WebSocket text message",
                ));
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unsupported WebSocket opcode",
                ));
            }
        }
    }
}

/// Hands one parsed input message to the runner's handler, wrapped in the latency trace's
/// `INPUT_RECV` / `INPUT_HANDLED` pair when tracing is on (`extra` is `Some` exactly then, packed
/// by `trace::key_extra` / `trace::pointer_extra`). The handler runs synchronously on this thread
/// (the runner's `InputRouter::handle`), so the pair brackets the whole host-side injection, and
/// `trace::last_input_seq` -- set just before the call -- lets that handler tag its own records
/// with the same `seq`.
fn deliver_input(
    input_client: &InputClient<'_>,
    event: InputEvent,
    extra: Option<u64>,
    input_seq: &mut u64,
) {
    let Some(extra) = extra else {
        input_client.send(event);
        return;
    };
    *input_seq += 1;
    trace::record(trace::INPUT_RECV, *input_seq, extra);
    trace::set_last_input_seq(*input_seq);
    input_client.send(event);
    trace::record(trace::INPUT_HANDLED, *input_seq, extra);
}

/// Opcode-3 client message (module docs): `[3u8][u64 frame seq BE][f64 display ms BE][f64 receive
/// ms BE]`, the trace-aware page's report that a traced frame's bands are painted. Recorded as
/// `VIEWER_RECEIVED` and `VIEWER_DISPLAYED` (both stamped with the report's arrival here, each
/// carrying its own page-clock reading in `extra`); ignored while tracing is off. `payload` is
/// exactly 25 bytes.
fn record_viewer_report(payload: &[u8]) {
    if !trace::enabled() {
        return;
    }
    let field = |at: usize| -> [u8; 8] { payload[at..at + 8].try_into().unwrap_or([0; 8]) };
    let seq = u64::from_be_bytes(field(1));
    let displayed_us = client_ms_to_us(f64::from_be_bytes(field(9)));
    let received_us = client_ms_to_us(f64::from_be_bytes(field(17)));
    let arrived_ns = trace::now_ns();
    trace::record_at(trace::VIEWER_RECEIVED, seq, received_us, arrived_ns);
    trace::record_at(trace::VIEWER_DISPLAYED, seq, displayed_us, arrived_ns);
}

/// The page's `performance.now()` milliseconds as whole microseconds (finer than any browser's
/// resolution for it); 0 for anything that is not a finite, non-negative number.
fn client_ms_to_us(ms: f64) -> u64 {
    if ms.is_finite() && ms >= 0.0 {
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        {
            (ms * 1000.0) as u64
        }
    } else {
        0
    }
}

/// RFC 6455 §4.2.2: `base64(SHA1(key ++ magic GUID))`.
fn websocket_accept_value(key: &str) -> String {
    let mut input = key.as_bytes().to_vec();
    input.extend_from_slice(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    base64(&sha1(&input))
}

/// SHA-1 (RFC 3174). Used only for the WebSocket handshake, where SHA-1's cryptographic
/// weakness is irrelevant (the value is an anti-cache token, not a security boundary).
fn sha1(data: &[u8]) -> [u8; 20] {
    let mut state: [u32; 5] = [
        0x6745_2301,
        0xefcd_ab89,
        0x98ba_dcfe,
        0x1032_5476,
        0xc3d2_e1f0,
    ];
    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());
    for chunk in msg.as_chunks::<64>().0 {
        let mut sched = [0u32; 80];
        for (i, word) in chunk.as_chunks::<4>().0.iter().enumerate() {
            sched[i] = u32::from_be_bytes(*word);
        }
        for i in 16..80 {
            sched[i] = (sched[i - 3] ^ sched[i - 8] ^ sched[i - 14] ^ sched[i - 16]).rotate_left(1);
        }
        // RFC 3174's own variable names for the working state and round function.
        let (mut va, mut vb, mut vc, mut vd, mut ve) =
            (state[0], state[1], state[2], state[3], state[4]);
        for (i, &word) in sched.iter().enumerate() {
            let (round_fn, round_k) = match i {
                0..=19 => ((vb & vc) | (!vb & vd), 0x5a82_7999u32),
                20..=39 => (vb ^ vc ^ vd, 0x6ed9_eba1),
                40..=59 => ((vb & vc) | (vb & vd) | (vc & vd), 0x8f1b_bcdc),
                _ => (vb ^ vc ^ vd, 0xca62_c1d6),
            };
            let temp = va
                .rotate_left(5)
                .wrapping_add(round_fn)
                .wrapping_add(ve)
                .wrapping_add(round_k)
                .wrapping_add(word);
            ve = vd;
            vd = vc;
            vc = vb.rotate_left(30);
            vb = va;
            va = temp;
        }
        state[0] = state[0].wrapping_add(va);
        state[1] = state[1].wrapping_add(vb);
        state[2] = state[2].wrapping_add(vc);
        state[3] = state[3].wrapping_add(vd);
        state[4] = state[4].wrapping_add(ve);
    }
    let mut out = [0u8; 20];
    for (i, word) in state.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

/// Standard base64 with padding.
fn base64(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(ALPHABET[(n >> 18) as usize & 63] as char);
        out.push(ALPHABET[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}
