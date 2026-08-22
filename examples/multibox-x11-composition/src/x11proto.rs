//! Minimal X11 core protocol client, from scratch, no libX11.
//!
//! Implements exactly the requests these demo binaries need: connection
//! setup, CreateGC, PolyFillRectangle, and GetImage. Wire formats are the
//! stable X Window System core protocol (X11R6+), byte-for-byte.

use std::io::{Read, Write};
use std::net::TcpStream;

pub struct Connection {
    pub stream: TcpStream,
    pub root: u32,
    pub width: u16,
    pub height: u16,
    next_id: u32,
    id_mask: u32,
}

/// Read exactly `len` bytes, retrying on `WouldBlock`/`Interrupted` instead
/// of treating them as fatal. A transient EAGAIN on what the caller treats
/// as a blocking socket is legitimate to see (e.g. under litebox's guest TCP
/// stack) and must be retried, not surfaced as a connection failure.
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

/// A large single write across a routed box-to-box connection (two separate
/// litebox guest TCP stacks bridged by host IP forwarding between distinct
/// TUN devices) was observed to vanish in transit -- the sender's write()
/// calls report full success (every byte accepted) but the receiver's
/// read() never sees any of it, hanging forever. A tiny reply on the same
/// connection arrives fine. Capping each write to a small chunk with a
/// short pause between chunks works around it reliably; this is a real
/// litebox core-network gap (see the README), not merely defensive coding.
const CHUNK_SIZE: usize = 256;

/// Write all of `data`, retrying on `WouldBlock`/`Interrupted` the same way
/// [`read_exact`] does, and capped to [`CHUNK_SIZE`] per underlying write()
/// call (see its doc comment for why).
pub fn write_all_retrying(stream: &mut TcpStream, data: &[u8]) -> std::io::Result<()> {
    let mut sent = 0;
    while sent < data.len() {
        let end = (sent + CHUNK_SIZE).min(data.len());
        match stream.write(&data[sent..end]) {
            Ok(0) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "connection closed mid-write",
                ));
            }
            Ok(n) => {
                sent += n;
                std::thread::sleep(std::time::Duration::from_millis(15));
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::Interrupted =>
            {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

impl Connection {
    /// Connect to `host:display` (TCP only; port is 6000 + display number).
    pub fn connect(host: &str, display: u16) -> std::io::Result<Self> {
        let mut stream = TcpStream::connect((host, 6000 + display))?;
        stream.set_nodelay(true)?;

        // Connection setup request: byte-order 'l' (little-endian), proto
        // 11.0, no auth.
        let mut req = Vec::new();
        req.push(b'l');
        req.push(0); // unused
        req.extend_from_slice(&11u16.to_le_bytes()); // major
        req.extend_from_slice(&0u16.to_le_bytes()); // minor
        req.extend_from_slice(&0u16.to_le_bytes()); // auth-name length
        req.extend_from_slice(&0u16.to_le_bytes()); // auth-data length
        req.extend_from_slice(&0u16.to_le_bytes()); // unused pad
        write_all_retrying(&mut stream, &req)?;

        // Fixed 8-byte header of the response.
        let head = read_exact(&mut stream, 8)?;
        let success = head[0];
        let reason_len = head[1]; // only meaningful on failure
        let additional_len_words = u16::from_le_bytes([head[6], head[7]]) as usize;
        let body = read_exact(&mut stream, additional_len_words * 4)?;

        if success != 1 {
            let reason = String::from_utf8_lossy(&body[..reason_len as usize]).into_owned();
            return Err(std::io::Error::other(format!(
                "X11 connection setup refused: {reason}"
            )));
        }

        // Body layout (after the 8-byte head):
        // 4 release-number, 4 resource-id-base, 4 resource-id-mask,
        // 4 motion-buffer-size, 2 vendor-len(v), 2 max-request-length,
        // 1 num-screens(r), 1 num-formats(n), 1 image-byte-order,
        // 1 bitmap-bit-order, 1 scanline-unit, 1 scanline-pad,
        // 1 min-keycode, 1 max-keycode, 4 unused, then vendor (v, padded to
        // 4), then n * 8-byte FORMAT records, then r SCREEN records.
        let resource_id_base = u32::from_le_bytes(body[4..8].try_into().unwrap());
        let resource_id_mask = u32::from_le_bytes(body[8..12].try_into().unwrap());
        let vendor_len = u16::from_le_bytes([body[16], body[17]]) as usize;
        let num_formats = body[21] as usize;

        let mut off = 32; // end of the fixed part
        off += vendor_len + pad4(vendor_len);
        off += num_formats * 8;

        // First SCREEN record starts here.
        let root = u32::from_le_bytes(body[off..off + 4].try_into().unwrap());
        let width = u16::from_le_bytes([body[off + 20], body[off + 21]]);
        let height = u16::from_le_bytes([body[off + 22], body[off + 23]]);

        Ok(Self {
            stream,
            root,
            width,
            height,
            next_id: 0,
            id_mask: resource_id_mask,
            // resource_id_base folded into alloc_id below via closure state
        }
        .with_base(resource_id_base))
    }

    fn with_base(mut self, base: u32) -> Self {
        self.next_id = base;
        self
    }

    fn alloc_id(&mut self) -> u32 {
        // Client-allocatable resource IDs are `base | (n & mask)` for
        // increasing n; a plain increasing counter under the mask suffices
        // for a short-lived demo client that only ever allocates a handful.
        let base = self.next_id & !self.id_mask;
        let counter = (self.next_id & self.id_mask) + 1;
        let id = base | (counter & self.id_mask);
        self.next_id = id;
        id
    }

    /// CreateGC with just GCForeground set (value-mask bit 0x00000004).
    pub fn create_gc(&mut self, drawable: u32, foreground: u32) -> std::io::Result<u32> {
        let gc = self.alloc_id();
        let mut req = Vec::with_capacity(20);
        req.push(55); // opcode
        req.push(0); // unused
        req.extend_from_slice(&5u16.to_le_bytes()); // request length in 4-byte units (4 + 1 value)
        req.extend_from_slice(&gc.to_le_bytes());
        req.extend_from_slice(&drawable.to_le_bytes());
        req.extend_from_slice(&0x0000_0004u32.to_le_bytes()); // value-mask: GCForeground
        req.extend_from_slice(&foreground.to_le_bytes());
        write_all_retrying(&mut self.stream, &req)?;
        Ok(gc)
    }

    pub fn poly_fill_rectangle(
        &mut self,
        drawable: u32,
        gc: u32,
        x: i16,
        y: i16,
        w: u16,
        h: u16,
    ) -> std::io::Result<()> {
        let mut req = Vec::with_capacity(16);
        req.push(70); // opcode
        req.push(0);
        req.extend_from_slice(&5u16.to_le_bytes()); // 3 + 2*1 rectangles
        req.extend_from_slice(&drawable.to_le_bytes());
        req.extend_from_slice(&gc.to_le_bytes());
        req.extend_from_slice(&x.to_le_bytes());
        req.extend_from_slice(&y.to_le_bytes());
        req.extend_from_slice(&w.to_le_bytes());
        req.extend_from_slice(&h.to_le_bytes());
        write_all_retrying(&mut self.stream, &req)
    }

    /// GetImage in ZPixmap format over the whole requested rectangle.
    /// Returns the raw framebuffer bytes (depth 24 in 32bpp, little-endian
    /// 0x00RRGGBB per pixel, matching Xvfb's native TrueColor layout).
    pub fn get_image(
        &mut self,
        drawable: u32,
        x: i16,
        y: i16,
        w: u16,
        h: u16,
    ) -> std::io::Result<Vec<u8>> {
        const ZPIXMAP: u8 = 2;
        let mut req = Vec::with_capacity(20);
        req.push(73); // opcode
        req.push(ZPIXMAP);
        req.extend_from_slice(&5u16.to_le_bytes());
        req.extend_from_slice(&drawable.to_le_bytes());
        req.extend_from_slice(&x.to_le_bytes());
        req.extend_from_slice(&y.to_le_bytes());
        req.extend_from_slice(&w.to_le_bytes());
        req.extend_from_slice(&h.to_le_bytes());
        req.extend_from_slice(&0xffff_ffffu32.to_le_bytes()); // plane-mask
        write_all_retrying(&mut self.stream, &req)?;

        // Reply: 1 (reply-type) + depth + seq(2) + reply-length(4, in 4-byte
        // units) + visual(4) + 20 unused = 32-byte header, then the pixel
        // data.
        let head = read_exact(&mut self.stream, 32)?;
        if head[0] != 1 {
            return Err(std::io::Error::other(format!(
                "GetImage failed (reply type {})",
                head[0]
            )));
        }
        let reply_len_words = u32::from_le_bytes(head[4..8].try_into().unwrap()) as usize;
        read_exact(&mut self.stream, reply_len_words * 4)
    }
}
