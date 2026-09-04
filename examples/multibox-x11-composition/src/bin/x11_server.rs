//! Minimal from-scratch X11 server: connection setup, CreateGC,
//! PolyFillRectangle, GetImage against a shared in-memory framebuffer.
//! Not a general X server -- it implements exactly the subset of the core
//! protocol this demo's own client boxes (x11-app, vnc-bridge) use, nothing
//! more. Real Xvfb needs guest uid 0 for its lock-file `link()` call, which
//! litebox's shim does not support (guests always run as a stable non-root
//! uid, and `link`/`linkat`/`rename`/`symlink` are unimplemented there
//! entirely); this avoids that whole dependency by not needing a lock file,
//! shared libraries, or root at all.

// Shared with x11-app and vnc-bridge, which use the rest of this module
// (the client-side `Connection`); this binary only needs its
// `write_all_retrying` helper.
#[path = "../x11proto.rs"]
#[allow(dead_code)]
mod x11proto;

use std::collections::HashMap;
use std::io::Read;
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};

const ROOT_WINDOW: u32 = 0x0000_0001;
const RESOURCE_ID_BASE: u32 = 0x0040_0000;
const RESOURCE_ID_MASK: u32 = 0x001f_ffff;

struct Framebuffer {
    width: u16,
    height: u16,
    /// Little-endian 0x00RRGGBB per pixel, matching real X TrueColor
    /// visuals with red/green/blue shifts 16/8/0 (verified empirically
    /// against a real Xvfb instance during development).
    pixels: Vec<u8>,
    gcs: HashMap<u32, u32>,
}

impl Framebuffer {
    fn new(width: u16, height: u16) -> Self {
        Self {
            width,
            height,
            pixels: vec![0u8; usize::from(width) * usize::from(height) * 4],
            gcs: HashMap::new(),
        }
    }

    fn fill_rect(&mut self, gc: u32, x: i32, y: i32, w: u16, h: u16) {
        let color = self.gcs.get(&gc).copied().unwrap_or(0);
        let (r, g, b) = (
            ((color >> 16) & 0xff) as u8,
            ((color >> 8) & 0xff) as u8,
            (color & 0xff) as u8,
        );
        for py in y.max(0)..(y + i32::from(h)).min(i32::from(self.height)) {
            for px in x.max(0)..(x + i32::from(w)).min(i32::from(self.width)) {
                let off = (py as usize * usize::from(self.width) + px as usize) * 4;
                self.pixels[off] = b;
                self.pixels[off + 1] = g;
                self.pixels[off + 2] = r;
                self.pixels[off + 3] = 0;
            }
        }
    }

    /// Raw ZPixmap bytes for the requested rectangle, row-major, same
    /// layout as `pixels`.
    fn get_image(&self, x: i32, y: i32, w: u16, h: u16) -> Vec<u8> {
        let mut out = vec![0u8; usize::from(w) * usize::from(h) * 4];
        for row in 0..i32::from(h) {
            let sy = y + row;
            if sy < 0 || sy >= i32::from(self.height) {
                continue;
            }
            for col in 0..i32::from(w) {
                let sx = x + col;
                if sx < 0 || sx >= i32::from(self.width) {
                    continue;
                }
                let src = (sy as usize * usize::from(self.width) + sx as usize) * 4;
                let dst = (row as usize * usize::from(w) + col as usize) * 4;
                out[dst..dst + 4].copy_from_slice(&self.pixels[src..src + 4]);
            }
        }
        out
    }
}

fn pad4(n: usize) -> usize {
    (4 - (n % 4)) % 4
}

/// How many bytes of `buf` the connection-setup request occupies (fixed
/// 12-byte prefix -- byte-order(1) unused(1) major(2) minor(2)
/// auth-name-len(2) auth-data-len(2) unused(2) -- plus the padded auth name
/// and data, whose contents nothing here uses), or `None` if `buf` doesn't
/// hold that many bytes yet.
///
/// Never blocks to get more: `main`'s single guest thread cooperatively
/// multiplexes every connected client (macOS ARM supports exactly one guest
/// thread today, see `litebox_platform_macos_userland::guest`, so the
/// one-thread-per-client model this demo used until now -- fine on
/// Linux -- panics there on a second concurrent client), so parsing can only
/// ever act on bytes that have already arrived.
fn setup_request_len(buf: &[u8]) -> Option<usize> {
    if buf.len() < 12 {
        return None;
    }
    let auth_name_len = u16::from_le_bytes([buf[6], buf[7]]) as usize;
    let auth_data_len = u16::from_le_bytes([buf[8], buf[9]]) as usize;
    let total = 12 + auth_name_len + pad4(auth_name_len) + auth_data_len + pad4(auth_data_len);
    (buf.len() >= total).then_some(total)
}

/// Reply to the X11 connection setup handshake. The request itself
/// (`setup_request_len` bytes, already consumed by the caller) carries
/// nothing this server needs -- every client here always gets the same
/// screen/vendor info back.
fn write_setup_reply(stream: &mut TcpStream, width: u16, height: u16) -> std::io::Result<()> {
    let vendor = b"litebox-compose-demo-x11-server";
    let mut body = Vec::new();
    body.extend_from_slice(&0u32.to_le_bytes()); // release-number
    body.extend_from_slice(&RESOURCE_ID_BASE.to_le_bytes());
    body.extend_from_slice(&RESOURCE_ID_MASK.to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes()); // motion-buffer-size
    body.extend_from_slice(&(vendor.len() as u16).to_le_bytes());
    body.extend_from_slice(&(u16::MAX).to_le_bytes()); // max-request-length
    body.push(1); // number of SCREENS
    body.push(1); // number of FORMATS
    body.push(0); // image-byte-order: LSBFirst
    body.push(0); // bitmap-format-bit-order: LeastSignificant
    body.push(32); // bitmap-format-scanline-unit
    body.push(32); // bitmap-format-scanline-pad
    body.push(8); // min-keycode
    body.push(255); // max-keycode
    body.extend_from_slice(&[0u8; 4]); // unused
    body.extend_from_slice(vendor);
    body.extend(std::iter::repeat_n(0u8, pad4(vendor.len())));

    // One FORMAT record: depth 24, 32bpp, scanline-pad 32.
    body.extend_from_slice(&[24, 32, 32, 0, 0, 0, 0, 0]);

    // One SCREEN record.
    body.extend_from_slice(&ROOT_WINDOW.to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes()); // default-colormap
    body.extend_from_slice(&0x00ff_ffffu32.to_le_bytes()); // white-pixel
    body.extend_from_slice(&0u32.to_le_bytes()); // black-pixel
    body.extend_from_slice(&0u32.to_le_bytes()); // current-input-masks
    body.extend_from_slice(&width.to_le_bytes());
    body.extend_from_slice(&height.to_le_bytes());
    body.extend_from_slice(&(u16::from(width) * 254 / 96).to_le_bytes()); // width-mm (~96dpi)
    body.extend_from_slice(&(u16::from(height) * 254 / 96).to_le_bytes());
    body.extend_from_slice(&1u16.to_le_bytes()); // min-installed-maps
    body.extend_from_slice(&1u16.to_le_bytes()); // max-installed-maps
    body.extend_from_slice(&1u32.to_le_bytes()); // root-visual
    body.push(0); // backing-stores
    body.push(0); // save-unders
    body.push(24); // root-depth
    body.push(1); // number of DEPTHS
    // One DEPTH record: depth=24, unused(1), num-visuals=1, unused(4).
    body.extend_from_slice(&[24, 0, 1, 0, 0, 0, 0, 0]);
    // One VISUALTYPE: visual-id, class, bits-per-rgb, colormap-entries,
    // red/green/blue masks, unused(4).
    body.extend_from_slice(&1u32.to_le_bytes()); // visual-id
    body.push(4); // class: TrueColor
    body.push(8); // bits-per-rgb-value
    body.extend_from_slice(&256u16.to_le_bytes()); // colormap-entries
    body.extend_from_slice(&0x00ff_0000u32.to_le_bytes()); // red-mask
    body.extend_from_slice(&0x0000_ff00u32.to_le_bytes()); // green-mask
    body.extend_from_slice(&0x0000_00ffu32.to_le_bytes()); // blue-mask
    body.extend_from_slice(&[0u8; 4]); // unused

    let mut head_out = Vec::with_capacity(8);
    head_out.push(1); // success
    head_out.push(0); // unused
    head_out.extend_from_slice(&11u16.to_le_bytes()); // protocol-major
    head_out.extend_from_slice(&0u16.to_le_bytes()); // protocol-minor
    head_out.extend_from_slice(&((body.len() / 4) as u16).to_le_bytes());

    x11proto::write_all_retrying(stream, &head_out)?;
    x11proto::write_all_retrying(stream, &body)
}

/// One request's total byte length (4-byte header + body), or `None` if
/// `buf` doesn't hold that many bytes yet. Same never-block constraint as
/// `setup_request_len`.
fn request_len(buf: &[u8]) -> Option<usize> {
    if buf.len() < 4 {
        return None;
    }
    let len_words = u16::from_le_bytes([buf[2], buf[3]]) as usize;
    let total = len_words * 4;
    (buf.len() >= total).then_some(total)
}

/// Handle one already-fully-received request (`request_len` bytes: 4-byte
/// header, `opcode` is its first byte, `body` is everything after it).
fn handle_request(
    fb: &Arc<Mutex<Framebuffer>>,
    stream: &mut TcpStream,
    opcode: u8,
    body: &[u8],
) -> std::io::Result<()> {
    match opcode {
        55 => {
            // CreateGC: cid(4) drawable(4) value-mask(4) values...
            let cid = u32::from_le_bytes(body[0..4].try_into().unwrap());
            let mask = u32::from_le_bytes(body[8..12].try_into().unwrap());
            // Only GCForeground (bit 0x04) is honored; find its slot by
            // counting set bits below it among the handled ones we care
            // about -- since we only ever look at foreground, and it is
            // the only bit these demo clients ever set, its value is
            // simply the first value word when present.
            if mask & 0x0000_0004 != 0 {
                let foreground = u32::from_le_bytes(body[12..16].try_into().unwrap());
                fb.lock().unwrap().gcs.insert(cid, foreground);
            }
        }
        70 => {
            // PolyFillRectangle: drawable(4) gc(4) then 8-byte rects.
            let gc = u32::from_le_bytes(body[4..8].try_into().unwrap());
            let mut off = 8;
            while off + 8 <= body.len() {
                let x = i16::from_le_bytes(body[off..off + 2].try_into().unwrap());
                let y = i16::from_le_bytes(body[off + 2..off + 4].try_into().unwrap());
                let w = u16::from_le_bytes(body[off + 4..off + 6].try_into().unwrap());
                let h = u16::from_le_bytes(body[off + 6..off + 8].try_into().unwrap());
                fb.lock().unwrap().fill_rect(gc, i32::from(x), i32::from(y), w, h);
                off += 8;
            }
        }
        73 => {
            // GetImage: drawable(4) x(2) y(2) w(2) h(2) plane-mask(4).
            let x = i16::from_le_bytes(body[4..6].try_into().unwrap());
            let y = i16::from_le_bytes(body[6..8].try_into().unwrap());
            let w = u16::from_le_bytes(body[8..10].try_into().unwrap());
            let h = u16::from_le_bytes(body[10..12].try_into().unwrap());
            let pixels = fb.lock().unwrap().get_image(i32::from(x), i32::from(y), w, h);

            let mut reply = Vec::with_capacity(32 + pixels.len());
            reply.push(1); // reply
            reply.push(24); // depth
            reply.extend_from_slice(&0u16.to_le_bytes()); // sequence number
            reply.extend_from_slice(&((pixels.len() / 4) as u32).to_le_bytes());
            reply.extend_from_slice(&1u32.to_le_bytes()); // visual
            reply.extend_from_slice(&[0u8; 20]); // unused pad to 32 bytes
            reply.extend_from_slice(&pixels);
            x11proto::write_all_retrying(stream, &reply)?;
        }
        other => {
            eprintln!("x11-server: ignoring unsupported opcode {other}");
        }
    }
    Ok(())
}

/// One connected client's cooperative-multiplexing state: everything
/// received but not yet parsed into a complete setup request or protocol
/// request, and whether the setup handshake has completed.
struct Client {
    stream: TcpStream,
    peer: std::net::SocketAddr,
    buf: Vec<u8>,
    setup_done: bool,
}

fn main() {
    eprintln!("x11-server: process started");
    let width: u16 = std::env::var("SCREEN_WIDTH")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(800);
    let height: u16 = std::env::var("SCREEN_HEIGHT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(600);

    let bind_ip = std::env::var("BIND_IP").unwrap_or_else(|_| String::from("0.0.0.0"));
    eprintln!("x11-server: binding {bind_ip}:6000");
    let fb = Arc::new(Mutex::new(Framebuffer::new(width, height)));
    let listener = TcpListener::bind((bind_ip.as_str(), 6000)).expect("bind :6000 failed");
    listener
        .set_nonblocking(true)
        .expect("set_nonblocking failed");
    eprintln!("x11-server: listening on {bind_ip}:6000, screen {width}x{height}, root=0x{ROOT_WINDOW:x}");

    // Cooperative multiplexing across every connected client (app, and
    // separately vnc-bridge, both stay connected for the composition's whole
    // lifetime) on this single loop -- macOS ARM supports exactly one guest
    // thread today (see `litebox_platform_macos_userland::guest`), so the
    // one-thread-per-client model this used until now panicked there the
    // moment a second client connected.
    let mut clients: Vec<Client> = Vec::new();
    let mut scratch = [0u8; 4096];
    loop {
        match listener.accept() {
            Ok((stream, peer)) => {
                stream
                    .set_nonblocking(true)
                    .expect("set_nonblocking failed");
                eprintln!("x11-server: client {peer:?} connected");
                clients.push(Client {
                    stream,
                    peer,
                    buf: Vec::new(),
                    setup_done: false,
                });
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(e) => eprintln!("x11-server: accept failed: {e}"),
        }

        let mut any_progress = false;
        let mut i = 0;
        while i < clients.len() {
            let mut remove = false;
            {
                let client = &mut clients[i];
                match client.stream.read(&mut scratch) {
                    Ok(0) => {
                        eprintln!("x11-server: client {:?} disconnected", client.peer);
                        remove = true;
                    }
                    Ok(n) => {
                        client.buf.extend_from_slice(&scratch[..n]);
                        any_progress = true;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(e) => {
                        eprintln!("x11-server: client {:?} read error: {e}", client.peer);
                        remove = true;
                    }
                }

                while !remove {
                    if !client.setup_done {
                        let Some(consumed) = setup_request_len(&client.buf) else {
                            break;
                        };
                        client.buf.drain(..consumed);
                        if let Err(e) = write_setup_reply(&mut client.stream, width, height) {
                            eprintln!("x11-server: client {:?} setup write failed: {e}", client.peer);
                            remove = true;
                            break;
                        }
                        client.setup_done = true;
                        eprintln!("x11-server: client {:?} setup complete", client.peer);
                        any_progress = true;
                        continue;
                    }
                    let Some(total) = request_len(&client.buf) else {
                        break;
                    };
                    let request: Vec<u8> = client.buf.drain(..total).collect();
                    if let Err(e) =
                        handle_request(&fb, &mut client.stream, request[0], &request[4..])
                    {
                        eprintln!("x11-server: client {:?} request failed: {e}", client.peer);
                        remove = true;
                        break;
                    }
                    any_progress = true;
                }
            }
            if remove {
                clients.remove(i);
            } else {
                i += 1;
            }
        }

        if !any_progress {
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }
}
