//! Demo VNC bridge: an X11 client (over TCP, to a remote Xvfb box) on one
//! side and a minimal RFB 3.8 server (over TCP, for external VNC viewers) on
//! the other. Every framebuffer update is a live `GetImage` against the real
//! X server -- there is no cached/synthetic frame.
//!
//! Deliberately minimal: raw encoding only, always sends the whole
//! framebuffer, single client at a time. Enough to prove the protocol chain
//! for real; not a production VNC server.

// Shared with x11-app and x11-server; this binary only needs
// `connect`/`get_image`.
#[path = "../x11proto.rs"]
#[allow(dead_code)]
mod x11proto;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::Duration;

/// Applied once handshake completes, for the main message loop: generous,
/// since a real client legitimately idles between `FramebufferUpdateRequest`s
/// and a client crash/network drop must not wedge `write_all` forever.
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);
/// Applied only during the initial RFB handshake, see `handshake`'s doc
/// comment for why this must be much shorter than `IDLE_TIMEOUT`.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

fn parse_display(display: &str) -> (String, u16) {
    let (host, num) = display
        .split_once(':')
        .expect("DISPLAY must be host:displaynum");
    (host.to_string(), num.parse().expect("bad display number"))
}

/// Read exactly `len` bytes, retrying on `WouldBlock`/`Interrupted` -- a
/// real EAGAIN was observed here under litebox's guest TCP stack even on a
/// nominally-blocking socket, so this must not treat it as fatal.
fn read_exact(stream: &mut TcpStream, len: usize) -> std::io::Result<Vec<u8>> {
    let mut buf = vec![0u8; len];
    let mut filled = 0;
    while filled < len {
        match stream.read(&mut buf[filled..]) {
            Ok(0) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "connection closed mid-read",
                ));
            }
            Ok(n) => filled += n,
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::Interrupted =>
            {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            Err(e) => return Err(e),
        }
    }
    Ok(buf)
}

/// RFB PIXEL_FORMAT matching Xvfb's native TrueColor layout established by
/// direct measurement: 32bpp, depth 24, little-endian, red/green/blue
/// shifts 16/8/0 -- so `GetImage` bytes pass straight through unmodified.
fn write_pixel_format(out: &mut Vec<u8>) {
    out.push(32); // bits-per-pixel
    out.push(24); // depth
    out.push(0); // big-endian-flag = false
    out.push(1); // true-color-flag = true
    out.extend_from_slice(&255u16.to_be_bytes()); // red-max
    out.extend_from_slice(&255u16.to_be_bytes()); // green-max
    out.extend_from_slice(&255u16.to_be_bytes()); // blue-max
    out.push(16); // red-shift
    out.push(8); // green-shift
    out.push(0); // blue-shift
    out.extend_from_slice(&[0, 0, 0]); // padding
}

fn handshake(stream: &mut TcpStream, width: u16, height: u16) -> std::io::Result<()> {
    // This server is single-threaded and single-client (see module doc): the
    // `listener.incoming()` loop in `main` cannot accept a new connection
    // until `serve_client` returns for the current one. A stream that
    // connects and then sends nothing -- a stale capability probe, a client
    // that reconnects after a hiccup -- would otherwise sit on the caller's
    // full 30s per-message timeout before the server frees up, which reads
    // as "connects but shows nothing" to anyone trying right after. A real
    // client completes this handshake in well under a second, so a short
    // timeout here doesn't cost a real client anything; `serve_client`
    // restores `IDLE_TIMEOUT` before the main loop, where waiting on the
    // next client message is normal.
    stream.set_read_timeout(Some(HANDSHAKE_TIMEOUT))?;

    stream.write_all(b"RFB 003.008\n")?;
    let _client_version = read_exact(stream, 12)?;

    // Security: offer only "None" (type 1).
    stream.write_all(&[1u8, 1u8])?;
    let chosen = read_exact(stream, 1)?;
    if chosen[0] != 1 {
        return Err(std::io::Error::other("client did not choose None security"));
    }
    // RFB 3.8 requires a SecurityResult even for None.
    stream.write_all(&0u32.to_be_bytes())?;

    let _client_init = read_exact(stream, 1)?; // shared-flag

    let mut init = Vec::new();
    init.extend_from_slice(&width.to_be_bytes());
    init.extend_from_slice(&height.to_be_bytes());
    write_pixel_format(&mut init);
    let name = b"litebox-compose-demo";
    init.extend_from_slice(&(name.len() as u32).to_be_bytes());
    init.extend_from_slice(name);
    stream.write_all(&init)
}

/// Consume and discard one client->server message after its type byte has
/// already been read. Returns `Ok(true)` when this was a
/// FramebufferUpdateRequest (the caller sends an update in response).
fn handle_message(stream: &mut TcpStream, msg_type: u8) -> std::io::Result<bool> {
    match msg_type {
        0 => {
            // SetPixelFormat: 3 pad + 16-byte pixel format.
            read_exact(stream, 19)?;
            Ok(false)
        }
        2 => {
            // SetEncodings: 1 pad + count(u16) + count * int32.
            let head = read_exact(stream, 3)?;
            let count = u16::from_be_bytes([head[1], head[2]]) as usize;
            read_exact(stream, count * 4)?;
            Ok(false)
        }
        3 => {
            // FramebufferUpdateRequest: incremental(1) + x,y,w,h (2 each).
            read_exact(stream, 9)?;
            Ok(true)
        }
        4 => {
            // KeyEvent: down-flag(1) + pad(2) + key(4).
            read_exact(stream, 7)?;
            Ok(false)
        }
        5 => {
            // PointerEvent: button-mask(1) + x(2) + y(2).
            read_exact(stream, 5)?;
            Ok(false)
        }
        6 => {
            // ClientCutText: pad(3) + length(4) + length bytes.
            let head = read_exact(stream, 7)?;
            let len = u32::from_be_bytes(head[3..7].try_into().unwrap()) as usize;
            read_exact(stream, len)?;
            Ok(false)
        }
        other => Err(std::io::Error::other(format!(
            "unsupported client message type {other}"
        ))),
    }
}

fn serve_client(mut client: TcpStream, x: &mut x11proto::Connection) -> std::io::Result<()> {
    handshake(&mut client, x.width, x.height)?;
    client.set_read_timeout(Some(IDLE_TIMEOUT))?;
    eprintln!("vnc-bridge: client handshake complete");

    loop {
        let ty = match read_exact(&mut client, 1) {
            Ok(b) => b[0],
            Err(_) => {
                eprintln!("vnc-bridge: client disconnected");
                return Ok(());
            }
        };
        if handle_message(&mut client, ty)? {
            let pixels = x.get_image(x.root, 0, 0, x.width, x.height)?;

            let mut update = Vec::with_capacity(16 + pixels.len());
            update.push(0); // FramebufferUpdate
            update.push(0); // padding
            update.extend_from_slice(&1u16.to_be_bytes()); // number-of-rectangles
            update.extend_from_slice(&0u16.to_be_bytes()); // x
            update.extend_from_slice(&0u16.to_be_bytes()); // y
            update.extend_from_slice(&x.width.to_be_bytes());
            update.extend_from_slice(&x.height.to_be_bytes());
            update.extend_from_slice(&0i32.to_be_bytes()); // encoding: Raw
            update.extend_from_slice(&pixels);
            x11proto::write_all_retrying(&mut client, &update)?;
            eprintln!("vnc-bridge: sent framebuffer update ({} bytes)", pixels.len());
        }
    }
}

fn main() {
    let display = std::env::var("DISPLAY").expect("DISPLAY not set");
    let (host, num) = parse_display(&display);
    eprintln!("vnc-bridge: connecting to X server at {host}:{num}");

    let mut x = loop {
        match x11proto::Connection::connect(&host, num) {
            Ok(c) => break c,
            Err(e) => {
                eprintln!("vnc-bridge: X connect failed ({e}), retrying");
                std::thread::sleep(std::time::Duration::from_millis(500));
            }
        }
    };
    eprintln!(
        "vnc-bridge: X connected, root=0x{:x} screen={}x{}",
        x.root, x.width, x.height
    );

    // litebox's TCP bind treats a `0.0.0.0` listen address as a literal
    // exact-match endpoint, not a wildcard (smoltcp's own wildcard is
    // `addr: None`, which litebox's bind() never passes) -- a real client
    // connecting to this box's actual guest IP gets refused even though the
    // listener reports success. Bind the specific guest IP instead.
    let bind_ip = std::env::var("BIND_IP").unwrap_or_else(|_| String::from("0.0.0.0"));
    let listener = TcpListener::bind((bind_ip.as_str(), 5900)).expect("bind :5900 failed");
    eprintln!("vnc-bridge: RFB server listening on {bind_ip}:5900");

    for incoming in listener.incoming() {
        match incoming {
            Ok(client) => {
                eprintln!("vnc-bridge: client connected from {:?}", client.peer_addr());
                // A client that stops reading (crashes, network drop) would
                // otherwise block this single-threaded server's write_all
                // forever, wedging every future connection behind it.
                // `handshake` (inside `serve_client`) tightens the read
                // timeout further for the handshake itself, then widens it
                // back to this once the client is talking normally.
                let _ = client.set_read_timeout(Some(IDLE_TIMEOUT));
                let _ = client.set_write_timeout(Some(IDLE_TIMEOUT));
                if let Err(e) = serve_client(client, &mut x) {
                    eprintln!("vnc-bridge: client session ended: {e}");
                }
            }
            Err(e) => eprintln!("vnc-bridge: accept failed: {e}"),
        }
    }
}
