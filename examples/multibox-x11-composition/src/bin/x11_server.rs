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

fn pad4(n: usize) -> usize {
    (4 - (n % 4)) % 4
}

/// Consume and reply to the X11 connection setup handshake.
fn do_setup(stream: &mut TcpStream, width: u16, height: u16) -> std::io::Result<()> {
    // Fixed 12-byte prefix: byte-order(1) unused(1) major(2) minor(2)
    // auth-name-len(2) auth-data-len(2) unused(2). byte-order (head[0]) is
    // echoed back implicitly by us always speaking little-endian.
    let head = read_exact(stream, 12)?;
    let auth_name_len = u16::from_le_bytes([head[6], head[7]]) as usize;
    let auth_data_len = u16::from_le_bytes([head[8], head[9]]) as usize;
    read_exact(stream, auth_name_len + pad4(auth_name_len))?;
    read_exact(stream, auth_data_len + pad4(auth_data_len))?;

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

fn serve_client(mut stream: TcpStream, fb: Arc<Mutex<Framebuffer>>) -> std::io::Result<()> {
    let (width, height) = {
        let fb = fb.lock().unwrap();
        (fb.width, fb.height)
    };
    do_setup(&mut stream, width, height)?;
    eprintln!("x11-server: client {:?} setup complete", stream.peer_addr());

    loop {
        let mut head = [0u8; 4];
        if stream.read_exact(&mut head).is_err() {
            eprintln!("x11-server: client {:?} disconnected", stream.peer_addr());
            return Ok(());
        }
        let opcode = head[0];
        let len_words = u16::from_le_bytes([head[2], head[3]]) as usize;
        let body_len = len_words.saturating_sub(1) * 4;
        let body = read_exact(&mut stream, body_len)?;

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
                x11proto::write_all_retrying(&mut stream, &reply)?;
            }
            other => {
                eprintln!("x11-server: ignoring unsupported opcode {other}");
            }
        }
    }
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
    eprintln!("x11-server: listening on {bind_ip}:6000, screen {width}x{height}, root=0x{ROOT_WINDOW:x}");

    for incoming in listener.incoming() {
        match incoming {
            Ok(stream) => {
                let fb = Arc::clone(&fb);
                std::thread::spawn(move || {
                    if let Err(e) = serve_client(stream, fb) {
                        eprintln!("x11-server: client session ended: {e}");
                    }
                });
            }
            Err(e) => eprintln!("x11-server: accept failed: {e}"),
        }
    }
}
