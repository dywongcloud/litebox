// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::io;
use std::net::{IpAddr, Ipv4Addr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::proto::{self, PixelFormat};

/// A boxed input-event handler, shared across every connected client's serving thread.
type InputHandler = dyn Fn(InputEvent) + Send + Sync;

/// A pointer (mouse) event received from a connected client (RFC 6143 §7.5.5).
#[derive(Debug, Clone, Copy)]
pub struct PointerEvent {
    /// Bit N set = button N+1 currently pressed (bit 0 = left, bit 1 = middle, bit 2 = right,
    /// bits 3/4 = scroll wheel up/down on most clients).
    pub button_mask: u8,
    pub x: u16,
    pub y: u16,
}

/// A key event received from a connected client (RFC 6143 §7.5.4). `key` is an X11 keysym
/// value, which is what every RFB client sends -- interpreting it into a guest scancode is the
/// caller's responsibility (litebox's evdev-emulation layer, once it exists).
#[derive(Debug, Clone, Copy)]
pub struct KeyEvent {
    pub down: bool,
    pub key: u32,
}

/// An input event this server received from a connected client, handed to
/// [`RfbServer::run`]'s caller-supplied handler.
#[derive(Debug, Clone, Copy)]
pub enum InputEvent {
    Pointer(PointerEvent),
    Key(KeyEvent),
}

/// What this server needs from a caller-owned framebuffer: current dimensions and a snapshot of
/// the pixel bytes. Kept minimal and decoupled from any concrete framebuffer type (in
/// particular, `litebox::fs::devices::framebuffer::Framebuffer<Platform>` is generic over a
/// platform type this crate has no reason to depend on) -- the caller adapts its own
/// framebuffer type to this trait.
pub trait FramebufferSource: Send + Sync + 'static {
    /// Current `(width, height)` in pixels.
    fn dimensions(&self) -> (u16, u16);

    /// Copy the current frame's pixel bytes (32bpp, litebox's native in-memory XRGB8888 layout,
    /// row-major, `dimensions().0 * 4` stride, no padding between rows) into `dst`, resizing it
    /// to fit exactly.
    fn snapshot_into(&self, dst: &mut Vec<u8>);
}

/// A minimal RFB server bound to one address, presenting one [`FramebufferSource`] to any number
/// of concurrently connected clients (each served on its own thread).
pub struct RfbServer<F: FramebufferSource> {
    listener: TcpListener,
    framebuffer: Arc<F>,
    shutdown: Arc<AtomicBool>,
}

impl<F: FramebufferSource> RfbServer<F> {
    /// Binds a new server. `addr` defaults to `127.0.0.1` (localhost-only) when `None` --
    /// callers wanting LAN/remote access must opt in explicitly by passing an address that says
    /// so, matching this feature's default-closed security posture (see the `--vnc` flag's own
    /// doc comment in the runner that constructs this).
    pub fn bind(addr: Option<IpAddr>, port: u16, framebuffer: Arc<F>) -> io::Result<Self> {
        let addr = addr.unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST));
        let listener = TcpListener::bind((addr, port))?;
        Ok(Self {
            listener,
            framebuffer,
            shutdown: Arc::new(AtomicBool::new(false)),
        })
    }

    /// The address this server actually bound to (useful when `port` was `0`, letting the OS
    /// pick one).
    pub fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.listener.local_addr()
    }

    /// A handle that, when [`ShutdownHandle::signal`] is called, makes every in-progress and
    /// future `accept()` in [`Self::run`] return promptly (checked once per `accept()` timeout
    /// tick -- see [`Self::run`]'s doc comment for the exact latency bound).
    pub fn shutdown_handle(&self) -> ShutdownHandle {
        ShutdownHandle {
            flag: Arc::clone(&self.shutdown),
        }
    }

    /// Accepts connections until shut down, serving each on its own spawned thread. `on_input`
    /// is called from whichever client thread received the event -- callers that need to
    /// serialize input from multiple concurrent clients (only one guest to drive, potentially
    /// several attached viewers) must do so themselves (e.g. route through a single mpsc
    /// channel), matching this server's single-writer-elsewhere design rather than imposing one
    /// here.
    ///
    /// Checks the shutdown flag once per accept-loop iteration; `accept()` itself is given a
    /// 500ms read timeout via a raw socket option so a call to [`ShutdownHandle::signal`] is
    /// noticed within that bound rather than blocking forever on a `TcpListener` with no pending
    /// connection.
    pub fn run(&self, on_input: impl Fn(InputEvent) + Send + Sync + 'static) -> io::Result<()> {
        self.listener.set_nonblocking(true)?;
        let on_input: Arc<InputHandler> = Arc::new(on_input);
        while !self.shutdown.load(Ordering::Relaxed) {
            match self.listener.accept() {
                Ok((stream, peer)) => {
                    litebox_util_log::info!(peer:% = peer; "rfb client connecting");
                    let framebuffer = Arc::clone(&self.framebuffer);
                    let on_input = Arc::clone(&on_input);
                    let shutdown = Arc::clone(&self.shutdown);
                    std::thread::spawn(move || {
                        if let Err(e) = serve_client(stream, &framebuffer, &on_input, &shutdown) {
                            litebox_util_log::debug!(peer:% = peer, error:% = e; "rfb client disconnected");
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

/// A handle to request shutdown of a running [`RfbServer::run`] loop.
#[derive(Clone)]
pub struct ShutdownHandle {
    flag: Arc<AtomicBool>,
}

impl ShutdownHandle {
    pub fn signal(&self) {
        self.flag.store(true, Ordering::Relaxed);
    }
}

/// Interval between unsolicited `FramebufferUpdate` pushes to a connected client. RFB is
/// technically pull-based (the client sends `FramebufferUpdateRequest`), but every real client
/// sends one immediately after `SetEncodings` and again immediately upon receiving each update
/// (`incremental=1`), so pushing on a fixed timer is equivalent in practice to answering those
/// requests promptly and is far simpler than tracking per-client request/incremental state.
const UPDATE_INTERVAL: std::time::Duration = std::time::Duration::from_millis(50);

fn serve_client<F: FramebufferSource>(
    mut stream: TcpStream,
    framebuffer: &Arc<F>,
    on_input: &Arc<InputHandler>,
    shutdown: &AtomicBool,
) -> io::Result<()> {
    // `TcpStream`s returned from `TcpListener::accept()` inherit the listener's non-blocking
    // mode (set in `RfbServer::run` so the accept loop itself can poll the shutdown flag) --
    // this thread wants ordinary blocking reads/writes for the handshake and message loop below.
    stream.set_nonblocking(false)?;
    stream.set_nodelay(true)?;
    handshake(&mut stream)?;

    // A second thread on the same connection pushes framebuffer updates on a timer while this
    // (the original) thread blocks reading client input -- RFB is bidirectional on one TCP
    // connection, and cloning a `TcpStream` yields an independent handle to the same underlying
    // socket, safe to read/write from different threads concurrently.
    let mut write_stream = stream.try_clone()?;
    let (width, height) = framebuffer.dimensions();
    write_server_init(&mut stream, width, height)?;

    let pusher_shutdown_flag = Arc::new(AtomicBool::new(false));
    let pusher_stop = Arc::clone(&pusher_shutdown_flag);
    let pusher = {
        let framebuffer = Arc::clone(framebuffer);
        std::thread::spawn(move || {
            let mut pixels = Vec::new();
            while !pusher_stop.load(Ordering::Relaxed) {
                std::thread::sleep(UPDATE_INTERVAL);
                if pusher_stop.load(Ordering::Relaxed) {
                    break;
                }
                // Dimensions are re-read every tick so a mid-session `FBIOPUT_VSCREENINFO`
                // resize is picked up without a dedicated notification channel; the client sees
                // it as an ordinary FramebufferUpdate whose rectangle now covers the new size
                // (real RFB has no in-band "the size changed" message in this server's scope --
                // `DesktopSize` pseudo-encoding is out of scope, see the module doc comment).
                let (width, height) = framebuffer.dimensions();
                framebuffer.snapshot_into(&mut pixels);
                if write_framebuffer_update(&mut write_stream, width, height, &pixels).is_err() {
                    break;
                }
            }
        })
    };

    let result = read_client_loop(&mut stream, &**on_input, shutdown);

    pusher_shutdown_flag.store(true, Ordering::Relaxed);
    let _ = pusher.join();
    result
}

/// RFC 6143 §7.1: version negotiation, security handshake (`None` only), `ClientInit`.
fn handshake(stream: &mut (impl io::Read + io::Write)) -> io::Result<()> {
    // §7.1.1: server sends its supported version first.
    stream.write_all(proto::PROTOCOL_VERSION)?;
    let mut client_version = [0u8; 12];
    stream.read_exact(&mut client_version)?;
    // Accept any client-claimed version -- this server only ever speaks the 3.8 message set
    // regardless of what the client says, which is compatible with every RFB client in
    // practice (3.3/3.7/3.8 client message framing for the subset used here is identical).

    // §7.1.2: security-types list, one type (`None`), then read the client's chosen type back.
    stream.write_all(&[1u8, proto::SECURITY_TYPE_NONE])?;
    let mut chosen = [0u8; 1];
    stream.read_exact(&mut chosen)?;

    // §7.1.3: SecurityResult -- always OK, since `None` cannot fail.
    stream.write_all(&proto::SECURITY_RESULT_OK.to_be_bytes())?;

    // §7.3.1: ClientInit (one byte, shared-flag) -- read and ignore; this server always allows
    // shared access (multiple simultaneous viewers), matching the single-guest/many-observers
    // shape the framebuffer feature is built for.
    let mut shared_flag = [0u8; 1];
    stream.read_exact(&mut shared_flag)?;

    Ok(())
}

/// RFC 6143 §7.3.2: `ServerInit` -- framebuffer dimensions, pixel format, name.
fn write_server_init(stream: &mut impl io::Write, width: u16, height: u16) -> io::Result<()> {
    /// Desktop name sent in `ServerInit`. Fixed at compile time, so casting its `len()` to `u32`
    /// below can never truncate.
    const NAME: &[u8] = b"litebox";
    #[allow(clippy::cast_possible_truncation)]
    const NAME_LEN: u32 = NAME.len() as u32;

    stream.write_all(&width.to_be_bytes())?;
    stream.write_all(&height.to_be_bytes())?;
    PixelFormat::write(stream)?;
    stream.write_all(&NAME_LEN.to_be_bytes())?;
    stream.write_all(NAME)?;
    stream.flush()
}

/// RFC 6143 §7.6.1: one `FramebufferUpdate` message, one rectangle covering the whole
/// framebuffer, Raw encoding.
fn write_framebuffer_update(
    stream: &mut impl io::Write,
    width: u16,
    height: u16,
    pixels: &[u8],
) -> io::Result<()> {
    stream.write_all(&[proto::SERVER_FRAMEBUFFER_UPDATE, 0 /* padding */])?;
    stream.write_all(&1u16.to_be_bytes())?; // number-of-rectangles
    // Rectangle header: x, y, width, height, encoding-type.
    stream.write_all(&0u16.to_be_bytes())?;
    stream.write_all(&0u16.to_be_bytes())?;
    stream.write_all(&width.to_be_bytes())?;
    stream.write_all(&height.to_be_bytes())?;
    stream.write_all(&proto::ENCODING_RAW.to_be_bytes())?;
    stream.write_all(pixels)?;
    stream.flush()
}

/// Reads and dispatches client-to-server messages until the connection closes or a fatal I/O
/// error occurs. RFC 6143 §7.5.
fn read_client_loop(
    stream: &mut impl io::Read,
    on_input: &InputHandler,
    shutdown: &AtomicBool,
) -> io::Result<()> {
    let mut msg_type = [0u8; 1];
    loop {
        if shutdown.load(Ordering::Relaxed) {
            return Ok(());
        }
        match stream.read_exact(&mut msg_type) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e),
        }
        match msg_type[0] {
            proto::CLIENT_SET_PIXEL_FORMAT => {
                // 3 bytes padding + 16-byte PIXEL_FORMAT the client wants -- ignored; this
                // server always sends its own fixed 32bpp format (RFC 6143 permits a server to
                // do this; a compliant client must be able to consume it).
                proto::skip(stream, 3 + 16)?;
            }
            proto::CLIENT_SET_ENCODINGS => {
                proto::skip(stream, 1)?; // padding
                let count = proto::read_u16(stream)?;
                proto::skip(stream, usize::from(count) * 4)?; // each encoding is an i32
            }
            proto::CLIENT_FRAMEBUFFER_UPDATE_REQUEST => {
                // incremental(1) + x,y,w,h (u16 each) -- ignored; this server pushes on a fixed
                // timer instead of tracking per-client request state (see `UPDATE_INTERVAL`).
                proto::skip(stream, 1 + 2 + 2 + 2 + 2)?;
            }
            proto::CLIENT_KEY_EVENT => {
                let mut down_byte = [0u8; 1];
                stream.read_exact(&mut down_byte)?;
                proto::skip(stream, 2)?; // padding
                let key = proto::read_u32(stream)?;
                on_input(InputEvent::Key(KeyEvent {
                    down: down_byte[0] != 0,
                    key,
                }));
            }
            proto::CLIENT_POINTER_EVENT => {
                let mut mask = [0u8; 1];
                stream.read_exact(&mut mask)?;
                let x = proto::read_u16(stream)?;
                let y = proto::read_u16(stream)?;
                on_input(InputEvent::Pointer(PointerEvent {
                    button_mask: mask[0],
                    x,
                    y,
                }));
            }
            proto::CLIENT_CUT_TEXT => {
                proto::skip(stream, 3)?; // padding
                let len = proto::read_u32(stream)?;
                proto::skip(stream, len as usize)?;
            }
            unknown => {
                litebox_util_log::warn!(msg_type:% = unknown; "rfb: unrecognized client message type, closing connection");
                return Ok(());
            }
        }
    }
}
