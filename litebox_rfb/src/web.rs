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
//! * server -> client, binary: `[u16 width BE][u16 height BE][width*height*4 RGBA bytes]` --
//!   one whole frame per message, sent only when the frame content changed (cheap sum hash),
//!   at most every `FRAME_INTERVAL` (50ms).
//! * client -> server, binary: `[1u8][down u8][keysym u32 BE]` for keys (X11 keysyms, same
//!   values RFB uses, so the runner's existing translation applies unchanged), and
//!   `[2u8][button_mask u8][x u16 BE][y u16 BE]` for pointer state (RFB-style mask: bit 0
//!   left, bit 1 middle, bit 2 right, bits 3/4 wheel up/down edges).
//!
//! Hand-rolled HTTP/WebSocket (RFC 6455) rather than a crate dependency, for the same reason
//! the RFB server is hand-rolled (see the crate docs): the handshake needs only SHA-1 +
//! base64, both small enough to carry inline, and the framing needed here is a strict subset
//! of the RFC.

use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::server::{
    FramebufferSource, InputClient, InputEvent, InputHandler, InputMessage, KeyEvent, PointerEvent,
};

/// Interval between frame pushes to a connected browser. Same cadence as the RFB server's
/// `UPDATE_INTERVAL`; unchanged frames are skipped entirely, so idle cost is one snapshot+hash
/// per tick.
const FRAME_INTERVAL: std::time::Duration = std::time::Duration::from_millis(50);

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
        if !matches!(opcode, 0x8 | 0xa) || payload.len() > 125 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid WebSocket control frame",
            ));
        }
        self.write(|stream| write_ws_frame(stream, true, opcode, payload))
    }

    fn try_write_control(&self, opcode: u8, payload: &[u8]) -> io::Result<()> {
        if !matches!(opcode, 0x8 | 0xa) || payload.len() > 125 {
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

/// After the 101: a pusher thread streams changed frames while this thread reads input
/// messages -- the same two-thread split as the RFB server's `serve_client`.
fn serve_websocket<F: FramebufferSource>(
    stream: TcpStream,
    framebuffer: &Arc<F>,
    on_input: &Arc<InputHandler>,
) -> io::Result<()> {
    let write_stream = stream.try_clone()?;
    write_stream.set_write_timeout(Some(std::time::Duration::from_secs(5)))?;
    let writer = Arc::new(WsWriter::new(write_stream));
    let mut input_client = InputClient::connect(&**on_input);
    let pusher_stop = Arc::new(AtomicBool::new(false));
    let pusher = {
        let framebuffer = Arc::clone(framebuffer);
        let writer = Arc::clone(&writer);
        let stop = Arc::clone(&pusher_stop);
        std::thread::spawn(move || {
            let mut pixels = Vec::new();
            let mut message = Vec::new();
            let mut last_hash = 0u64;
            while !stop.load(Ordering::Relaxed) {
                std::thread::sleep(FRAME_INTERVAL);
                let (width, height) = framebuffer.dimensions();
                framebuffer.snapshot_into(&mut pixels);
                // FNV-1a over the raw pixels: cheap, and a stale positive only costs one
                // skipped frame that the next real change replaces.
                let mut hash = 0xcbf2_9ce4_8422_2325u64;
                for &b in &pixels {
                    hash = (hash ^ u64::from(b)).wrapping_mul(0x0000_0100_0000_01b3);
                }
                if hash == last_hash {
                    continue;
                }
                last_hash = hash;
                message.clear();
                message.extend_from_slice(&width.to_be_bytes());
                message.extend_from_slice(&height.to_be_bytes());
                // XRGB8888 little-endian memory order is B,G,R,X; the canvas wants R,G,B,A.
                for px in pixels.as_chunks::<4>().0 {
                    message.extend_from_slice(&[px[2], px[1], px[0], 0xff]);
                }
                if writer.write_binary(&message).is_err() {
                    break;
                }
            }
        })
    };

    let result = read_ws_loop(stream, &writer, &mut input_client);
    // Input cleanup must not wait behind a framebuffer writer blocked on the disconnected socket.
    drop(input_client);
    pusher_stop.store(true, Ordering::Relaxed);
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
/// with pong, exits on close.
fn read_ws_loop(
    mut stream: TcpStream,
    writer: &WsWriter,
    input_client: &mut InputClient<'_>,
) -> io::Result<()> {
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
            // Binary: our input messages.
            0x2 => match payload.first() {
                Some(1) if payload.len() == 6 => {
                    let key = u32::from_be_bytes([payload[2], payload[3], payload[4], payload[5]]);
                    input_client.send(InputEvent::Key(KeyEvent {
                        down: payload[1] != 0,
                        key,
                    }));
                }
                Some(2) if payload.len() == 6 => {
                    input_client.send(InputEvent::Pointer(PointerEvent {
                        button_mask: payload[1],
                        x: u16::from_be_bytes([payload[2], payload[3]]),
                        y: u16::from_be_bytes([payload[4], payload[5]]),
                    }));
                }
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
                input_client.disconnect();
                writer.try_write_control(0x8, &payload)?;
                return Ok(());
            }
            // Pong has no application effect.
            0xa => {}
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

#[cfg(test)]
mod tests {
    use std::io::{Read as _, Write as _};
    use std::net::{Ipv4Addr, TcpListener, TcpStream};
    use std::sync::{Arc, Barrier};

    fn capture_ws_binary(payload: &[u8]) -> Vec<u8> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let mut reader = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (writer, _) = listener.accept().unwrap();
        let payload = payload.to_vec();
        let sender = std::thread::spawn(move || {
            super::WsWriter::new(writer).write_binary(&payload).unwrap();
        });
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes).unwrap();
        sender.join().unwrap();
        bytes
    }

    fn capture_concurrent_binary_and_pong(payload: &[u8]) -> Vec<u8> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let mut reader = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (stream, _) = listener.accept().unwrap();
        let writer = Arc::new(super::WsWriter::new(stream));
        let barrier = Arc::new(Barrier::new(3));

        let binary_writer = Arc::clone(&writer);
        let binary_barrier = Arc::clone(&barrier);
        let payload = payload.to_vec();
        let binary = std::thread::spawn(move || {
            binary_barrier.wait();
            binary_writer.write_binary(&payload).unwrap();
        });

        let control_writer = Arc::clone(&writer);
        let control_barrier = Arc::clone(&barrier);
        let control = std::thread::spawn(move || {
            control_barrier.wait();
            control_writer.write_control(0xa, b"probe").unwrap();
        });

        barrier.wait();
        drop(writer);
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes).unwrap();
        binary.join().unwrap();
        control.join().unwrap();
        bytes
    }

    fn parse_ws_frames(mut bytes: &[u8]) -> Vec<(bool, u8, Vec<u8>)> {
        let mut frames = Vec::new();
        while !bytes.is_empty() {
            assert!(bytes.len() >= 2);
            let fin = bytes[0] & 0x80 != 0;
            let opcode = bytes[0] & 0x0f;
            assert_eq!(bytes[1] & 0x80, 0);
            let (header_len, payload_len) = match bytes[1] & 0x7f {
                len @ 0..=125 => (2, usize::from(len)),
                126 => {
                    assert!(bytes.len() >= 4);
                    (4, usize::from(u16::from_be_bytes([bytes[2], bytes[3]])))
                }
                127 => panic!("server fragment used a 64-bit payload length"),
                _ => unreachable!(),
            };
            let frame_len = header_len + payload_len;
            assert!(bytes.len() >= frame_len);
            frames.push((fin, opcode, bytes[header_len..frame_len].to_vec()));
            bytes = &bytes[frame_len..];
        }
        frames
    }

    fn masked_client_frame(first_byte: u8, payload: &[u8]) -> Vec<u8> {
        let mut frame = vec![first_byte];
        if payload.len() < 126 {
            frame.push(0x80 | u8::try_from(payload.len()).unwrap());
        } else {
            frame.push(0x80 | 0x7e);
            frame.extend_from_slice(&u16::try_from(payload.len()).unwrap().to_be_bytes());
        }
        let mask = [0x12, 0x34, 0x56, 0x78];
        frame.extend_from_slice(&mask);
        frame.extend(
            payload
                .iter()
                .enumerate()
                .map(|(index, byte)| byte ^ mask[index % mask.len()]),
        );
        frame
    }

    fn run_client_bytes(bytes: &[u8]) -> (std::io::Result<()>, usize) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (stream, _) = listener.accept().unwrap();
        let writer = super::WsWriter::new(stream.try_clone().unwrap());
        let count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let callback_count = Arc::clone(&count);
        let on_input: Arc<super::InputHandler> = Arc::new(move |_| {
            callback_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        });
        client.write_all(bytes).unwrap();
        client.shutdown(std::net::Shutdown::Write).unwrap();
        let result = super::read_ws_loop(stream, &writer, &on_input);
        (result, count.load(std::sync::atomic::Ordering::Relaxed))
    }

    struct OnePixelFramebuffer;

    impl crate::server::FramebufferSource for OnePixelFramebuffer {
        fn dimensions(&self) -> (u16, u16) {
            (1, 1)
        }

        fn snapshot_into(&self, dst: &mut Vec<u8>) {
            dst.clear();
            dst.resize(4, 0);
        }
    }

    fn websocket_request(host: &str, origin: Option<&str>, upgrade: &str, version: &str) -> String {
        let origin = origin
            .map(|value| format!("Origin: {value}\r\n"))
            .unwrap_or_default();
        format!(
            "GET /ws HTTP/1.1\r\nHost: {host}\r\nUpgrade: {upgrade}\r\nConnection: keep-alive, Upgrade\r\nSec-WebSocket-Version: {version}\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n{origin}\r\n"
        )
    }

    fn run_http_request(build_request: impl FnOnce(std::net::SocketAddr) -> String) -> Vec<u8> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let addr = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(addr).unwrap();
        let (stream, _) = listener.accept().unwrap();
        let framebuffer = Arc::new(OnePixelFramebuffer);
        let on_input: Arc<super::InputHandler> = Arc::new(|_| {});
        let server = std::thread::spawn(move || {
            super::serve_connection(stream, &framebuffer, &on_input).unwrap();
        });
        client.write_all(build_request(addr).as_bytes()).unwrap();
        client.shutdown(std::net::Shutdown::Write).unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).unwrap();
        server.join().unwrap();
        response
    }

    #[test]
    fn websocket_binary_fragment_boundaries_and_replay() {
        const LIMIT: usize = u16::MAX as usize;
        const DESKTOP_MESSAGE_LEN: usize = 4 + 1024 * 768 * 4;

        for len in [
            0,
            1,
            125,
            126,
            LIMIT - 1,
            LIMIT,
            LIMIT + 1,
            LIMIT * 2,
            LIMIT * 2 + 1,
            DESKTOP_MESSAGE_LEN,
        ] {
            let payload: Vec<_> = (0u8..=250).cycle().take(len).collect();
            let encoded = capture_ws_binary(&payload);
            let frames = parse_ws_frames(&encoded);
            let expected_count = if payload.is_empty() {
                1
            } else {
                payload.len().div_ceil(LIMIT)
            };
            assert_eq!(frames.len(), expected_count);
            for (index, (fin, opcode, fragment)) in frames.iter().enumerate() {
                assert_eq!(*fin, index + 1 == expected_count);
                assert_eq!(*opcode, if index == 0 { 0x2 } else { 0x0 });
                assert!(fragment.len() <= LIMIT);
            }
            let reassembled: Vec<_> = frames
                .iter()
                .flat_map(|(_, _, fragment)| fragment.iter().copied())
                .collect();
            assert_eq!(reassembled, payload);
            assert_eq!(capture_ws_binary(&payload), encoded);
        }
    }

    #[test]
    fn websocket_server_writes_are_serialized() {
        const LIMIT: usize = u16::MAX as usize;
        let payload: Vec<_> = (0u8..=250).cycle().take(LIMIT * 2 + 1).collect();

        for _ in 0..8 {
            let captures = std::thread::scope(|scope| {
                let writers: Vec<_> = (0..8)
                    .map(|_| scope.spawn(|| capture_concurrent_binary_and_pong(&payload)))
                    .collect();
                writers
                    .into_iter()
                    .map(|writer| writer.join().unwrap())
                    .collect::<Vec<_>>()
            });
            for bytes in captures {
                let frames = parse_ws_frames(&bytes);
                let pong_index = frames
                    .iter()
                    .position(|(_, opcode, _)| *opcode == 0xa)
                    .unwrap();
                assert!(pong_index == 0 || pong_index + 1 == frames.len());
                assert_eq!(frames[pong_index], (true, 0xa, b"probe".to_vec()));

                let binary: Vec<_> = frames
                    .iter()
                    .filter(|(_, opcode, _)| *opcode != 0xa)
                    .collect();
                assert_eq!(binary.len(), 3);
                for (index, (fin, opcode, fragment)) in binary.iter().enumerate() {
                    assert_eq!(*fin, index + 1 == binary.len());
                    assert_eq!(*opcode, if index == 0 { 0x2 } else { 0x0 });
                    assert!(fragment.len() <= LIMIT);
                }
                let reassembled: Vec<_> = binary
                    .iter()
                    .flat_map(|(_, _, fragment)| fragment.iter().copied())
                    .collect();
                assert_eq!(reassembled, payload);
            }
        }
    }

    #[test]
    fn websocket_handshake_enforces_same_origin() {
        let accepted = run_http_request(|addr| {
            let host = addr.to_string();
            websocket_request(&host, Some(&format!("http://{host}")), "websocket", "13")
        });
        assert!(accepted.starts_with(b"HTTP/1.1 101 Switching Protocols\r\n"));

        let localhost = run_http_request(|addr| {
            let host = format!("localhost:{}", addr.port());
            websocket_request(&host, Some(&format!("http://{host}")), "websocket", "13")
        });
        assert!(localhost.starts_with(b"HTTP/1.1 101 Switching Protocols\r\n"));

        let foreign_origin = run_http_request(|addr| {
            websocket_request(
                &addr.to_string(),
                Some("http://attacker.example"),
                "websocket",
                "13",
            )
        });
        assert!(foreign_origin.starts_with(b"HTTP/1.1 403 Forbidden\r\n"));

        let rebinding_host = run_http_request(|_| {
            websocket_request(
                "attacker.example",
                Some("http://attacker.example"),
                "websocket",
                "13",
            )
        });
        assert!(rebinding_host.starts_with(b"HTTP/1.1 403 Forbidden\r\n"));

        let missing_origin =
            run_http_request(|addr| websocket_request(&addr.to_string(), None, "websocket", "13"));
        assert!(missing_origin.starts_with(b"HTTP/1.1 403 Forbidden\r\n"));

        let wrong_upgrade = run_http_request(|addr| {
            let host = addr.to_string();
            websocket_request(&host, Some(&format!("http://{host}")), "invalid", "13")
        });
        assert!(wrong_upgrade.starts_with(b"HTTP/1.1 400 Bad Request\r\n"));

        let wrong_version = run_http_request(|addr| {
            let host = addr.to_string();
            websocket_request(&host, Some(&format!("http://{host}")), "websocket", "12")
        });
        assert!(wrong_version.starts_with(b"HTTP/1.1 400 Bad Request\r\n"));

        let duplicate_host = run_http_request(|addr| {
            let host = addr.to_string();
            let mut request =
                websocket_request(&host, Some(&format!("http://{host}")), "websocket", "13");
            request.insert_str(request.len() - 2, "Host: attacker.example\r\n");
            request
        });
        assert!(duplicate_host.starts_with(b"HTTP/1.1 403 Forbidden\r\n"));

        let duplicate_origin = run_http_request(|addr| {
            let host = addr.to_string();
            let mut request =
                websocket_request(&host, Some(&format!("http://{host}")), "websocket", "13");
            request.insert_str(request.len() - 2, "Origin: http://attacker.example\r\n");
            request
        });
        assert!(duplicate_origin.starts_with(b"HTTP/1.1 403 Forbidden\r\n"));

        let encoded_separator = run_http_request(|addr| {
            let host = addr.to_string();
            websocket_request(
                &host,
                Some(&format!("http://{host}%0d%0aX-LiteBox: injected")),
                "websocket",
                "13",
            )
        });
        assert!(encoded_separator.starts_with(b"HTTP/1.1 403 Forbidden\r\n"));

        let host_separator = run_http_request(|addr| {
            let host = format!("{addr};attacker.example");
            websocket_request(&host, Some(&format!("http://{host}")), "websocket", "13")
        });
        assert!(host_separator.starts_with(b"HTTP/1.1 403 Forbidden\r\n"));
    }

    #[test]
    fn websocket_incomplete_http_head_is_bounded() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (stream, _) = listener.accept().unwrap();
        let framebuffer = Arc::new(OnePixelFramebuffer);
        let on_input: Arc<super::InputHandler> = Arc::new(|_| {});
        let started = std::time::Instant::now();
        let server = std::thread::spawn(move || {
            super::serve_connection_with_head_timeout(
                stream,
                &framebuffer,
                &on_input,
                std::time::Duration::from_millis(50),
            )
        });

        client.write_all(b"GET /ws HTTP/1.1\r\nHost: ").unwrap();
        let error = server.join().unwrap().unwrap_err();
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
        assert!(matches!(
            error.kind(),
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
        ));
        client
            .set_read_timeout(Some(std::time::Duration::from_secs(1)))
            .unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).unwrap();
        assert!(response.is_empty());
    }

    #[test]
    fn websocket_client_frames_fail_closed() {
        let input = [1, 1, 0, 0, 0, 0x41];
        let valid = masked_client_frame(0x82, &input);
        let (result, count) = run_client_bytes(&valid);
        assert!(result.is_ok());
        assert_eq!(count, 1);

        let mut replay = valid.clone();
        replay.extend_from_slice(&valid);
        let (result, count) = run_client_bytes(&replay);
        assert!(result.is_ok());
        assert_eq!(count, 2);

        let mut unmasked = vec![0x82, u8::try_from(input.len()).unwrap()];
        unmasked.extend_from_slice(&input);
        let malformed = [
            unmasked,
            masked_client_frame(0x02, &input),
            masked_client_frame(0xc2, &input),
            masked_client_frame(0x81, b"text"),
            masked_client_frame(0x82, b"bad"),
            masked_client_frame(0x83, &[]),
            masked_client_frame(0x89, &[0; 126]),
            masked_client_frame(0x88, &[0]),
        ];
        for frame in malformed {
            let (result, count) = run_client_bytes(&frame);
            assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::InvalidData);
            assert_eq!(count, 0);
        }
    }

    #[test]
    fn websocket_write_timeout_closes_connection() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let mut reader = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (stream, _) = listener.accept().unwrap();
        stream
            .set_write_timeout(Some(std::time::Duration::from_millis(100)))
            .unwrap();
        let writer = super::WsWriter::new(stream);
        let payload = vec![0; 32 * 1024 * 1024];
        let started = std::time::Instant::now();
        let error = writer.write_binary(&payload).unwrap_err();
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
        assert!(matches!(
            error.kind(),
            std::io::ErrorKind::WouldBlock
                | std::io::ErrorKind::TimedOut
                | std::io::ErrorKind::BrokenPipe
                | std::io::ErrorKind::ConnectionReset
        ));
        drop(writer);
        reader
            .set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes).unwrap();
        assert!(bytes.len() < payload.len());
    }

    #[test]
    fn websocket_control_payload_is_bounded() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let _reader = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (stream, _) = listener.accept().unwrap();
        let error = super::WsWriter::new(stream)
            .write_control(0xa, &[0; 126])
            .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    }

    /// RFC 6455 §1.3's worked handshake example -- proves the SHA-1 and base64 above against
    /// the spec's own vector.
    #[test]
    fn rfc6455_accept_vector() {
        assert_eq!(
            super::websocket_accept_value("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }
}
