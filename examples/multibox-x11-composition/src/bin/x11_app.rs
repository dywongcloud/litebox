//! Demo X11 "app": connects to a remote Xvfb over TCP and draws a solid
//! rectangle directly onto the root window, then keeps redrawing so a VNC
//! viewer watching the framebuffer sees continuous, live content.
//!
//! No window manager is involved -- drawing straight onto the root window
//! needs none, and this box's only job is to prove a client box can reach
//! a server box's X11 TCP port and mutate what it renders.

// Shared with vnc-bridge and x11-server; this binary only needs
// `connect`/`create_gc`/`poly_fill_rectangle`.
#[path = "../x11proto.rs"]
#[allow(dead_code)]
mod x11proto;

use std::time::Duration;

fn parse_display(display: &str) -> (String, u16) {
    // "host:N" (TCP form); the demo compose config always sets this shape.
    let (host, num) = display
        .split_once(':')
        .expect("DISPLAY must be host:displaynum");
    (host.to_string(), num.parse().expect("bad display number"))
}

fn main() {
    let display = std::env::var("DISPLAY").expect("DISPLAY not set");
    let (host, num) = parse_display(&display);
    eprintln!("x11-app: connecting to {host}:{num}");

    let mut conn = loop {
        match x11proto::Connection::connect(&host, num) {
            Ok(c) => break c,
            Err(e) => {
                eprintln!("x11-app: connect failed ({e}), retrying");
                std::thread::sleep(Duration::from_millis(500));
            }
        }
    };
    eprintln!(
        "x11-app: connected, root=0x{:x} screen={}x{}",
        conn.root, conn.width, conn.height
    );

    // A distinct, easily-recognized fill color: RGB (0x11, 0xcc, 0x66).
    let fg = 0x0011_cc66u32;
    let gc = conn
        .create_gc(conn.root, fg)
        .expect("CreateGC failed");

    let (rw, rh) = (
        (conn.width / 2).max(10),
        (conn.height / 2).max(10),
    );
    let (rx, ry) = (
        i16::try_from(conn.width / 4).unwrap_or(0),
        i16::try_from(conn.height / 4).unwrap_or(0),
    );

    let mut tick: u64 = 0;
    loop {
        conn.poly_fill_rectangle(conn.root, gc, rx, ry, rw, rh)
            .expect("PolyFillRectangle failed");
        tick += 1;
        eprintln!("x11-app: drew frame {tick}");
        std::thread::sleep(Duration::from_secs(2));
    }
}
