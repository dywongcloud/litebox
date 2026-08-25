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

use crate::server::{FramebufferSource, InputEvent, KeyEvent, PointerEvent};

type InputHandler = dyn Fn(InputEvent) + Send + Sync;

/// Interval between frame pushes to a connected browser. Same cadence as the RFB server's
/// `UPDATE_INTERVAL`; unchanged frames are skipped entirely, so idle cost is one snapshot+hash
/// per tick.
const FRAME_INTERVAL: std::time::Duration = std::time::Duration::from_millis(50);

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
    pub fn run(&self, on_input: impl Fn(InputEvent) + Send + Sync + 'static) -> io::Result<()> {
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
    mut stream: TcpStream,
    framebuffer: &Arc<F>,
    on_input: &Arc<InputHandler>,
) -> io::Result<()> {
    stream.set_nonblocking(false)?;
    stream.set_nodelay(true)?;

    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() > 16 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "header too long",
            ));
        }
        stream.read_exact(&mut byte)?;
        head.push(byte[0]);
    }
    let head = String::from_utf8_lossy(&head).into_owned();
    let request_line = head.lines().next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("");

    let header = |name: &str| -> Option<&str> {
        head.lines().find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.trim().eq_ignore_ascii_case(name).then(|| v.trim())
        })
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
            let Some(key) = header("Sec-WebSocket-Key") else {
                stream.write_all(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")?;
                return Ok(());
            };
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

/// After the 101: a pusher thread streams changed frames while this thread reads input
/// messages -- the same two-thread split as the RFB server's `serve_client`.
fn serve_websocket<F: FramebufferSource>(
    stream: TcpStream,
    framebuffer: &Arc<F>,
    on_input: &Arc<InputHandler>,
) -> io::Result<()> {
    let mut write_stream = stream.try_clone()?;
    let pusher_stop = Arc::new(AtomicBool::new(false));
    let pusher = {
        let framebuffer = Arc::clone(framebuffer);
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
                if write_ws_binary(&mut write_stream, &message).is_err() {
                    break;
                }
            }
        })
    };

    let result = read_ws_loop(stream, on_input);
    pusher_stop.store(true, Ordering::Relaxed);
    let _ = pusher.join();
    result
}

/// One server-to-client binary message (FIN, opcode 2, unmasked, 64-bit length form for
/// anything over 64KiB -- which every frame is).
fn write_ws_binary(stream: &mut TcpStream, payload: &[u8]) -> io::Result<()> {
    let mut header = Vec::with_capacity(10);
    header.push(0x82);
    if payload.len() < 126 {
        #[allow(clippy::cast_possible_truncation)]
        header.push(payload.len() as u8);
    } else if let Ok(len16) = u16::try_from(payload.len()) {
        header.push(126);
        header.extend_from_slice(&len16.to_be_bytes());
    } else {
        header.push(127);
        header.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    }
    stream.write_all(&header)?;
    stream.write_all(payload)
}

/// Client-to-server frames: masked per RFC 6455. Handles binary input messages, answers ping
/// with pong, exits on close.
fn read_ws_loop(mut stream: TcpStream, on_input: &Arc<InputHandler>) -> io::Result<()> {
    loop {
        let mut hdr = [0u8; 2];
        match stream.read_exact(&mut hdr) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e),
        }
        let opcode = hdr[0] & 0x0f;
        let masked = hdr[1] & 0x80 != 0;
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
        if len > 4096 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "oversized ws frame",
            ));
        }
        let mask = if masked {
            let mut m = [0u8; 4];
            stream.read_exact(&mut m)?;
            m
        } else {
            [0u8; 4]
        };
        #[allow(clippy::cast_possible_truncation)]
        let mut payload = vec![0u8; len as usize];
        stream.read_exact(&mut payload)?;
        if masked {
            for (i, b) in payload.iter_mut().enumerate() {
                *b ^= mask[i % 4];
            }
        }
        match opcode {
            // Binary: our input messages.
            0x2 => match payload.first() {
                Some(1) if payload.len() == 6 => {
                    let key = u32::from_be_bytes([payload[2], payload[3], payload[4], payload[5]]);
                    on_input(InputEvent::Key(KeyEvent {
                        down: payload[1] != 0,
                        key,
                    }));
                }
                Some(2) if payload.len() == 6 => {
                    on_input(InputEvent::Pointer(PointerEvent {
                        button_mask: payload[1],
                        x: u16::from_be_bytes([payload[2], payload[3]]),
                        y: u16::from_be_bytes([payload[4], payload[5]]),
                    }));
                }
                _ => {}
            },
            // Ping -> pong with the same payload.
            0x9 => {
                let mut pong = Vec::with_capacity(2 + payload.len());
                pong.push(0x8a);
                #[allow(clippy::cast_possible_truncation)]
                pong.push(payload.len() as u8);
                pong.extend_from_slice(&payload);
                stream.write_all(&pong)?;
            }
            // Close.
            0x8 => return Ok(()),
            // Text/continuation/pong: nothing to do.
            _ => {}
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
