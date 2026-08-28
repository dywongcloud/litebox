//! Graphics demo: soft-rasterizer framebuffer with animated patterns.
//! Serves via RFB to a VNC client.

#[path = "../graphics.rs"]
mod graphics;

use graphics::{Color, Graphics, SoftRasterizer};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;
use std::time::Duration;

fn read_exact(stream: &mut std::net::TcpStream, len: usize) -> std::io::Result<Vec<u8>> {
    let mut buf = vec![0u8; len];
    let mut filled = 0;
    while filled < len {
        match stream.read(&mut buf[filled..]) {
            Ok(0) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "connection closed",
                ));
            }
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::Interrupted => {
                thread::sleep(Duration::from_millis(10));
            }
            Err(e) => return Err(e),
        }
    }
    Ok(buf)
}

fn write_pixel_format(out: &mut Vec<u8>) {
    out.push(32);
    out.push(24);
    out.push(0);
    out.push(1);
    out.extend_from_slice(&255u16.to_be_bytes());
    out.extend_from_slice(&255u16.to_be_bytes());
    out.extend_from_slice(&255u16.to_be_bytes());
    out.push(16);
    out.push(8);
    out.push(0);
    out.extend_from_slice(&[0, 0, 0]);
}

fn handshake(stream: &mut std::net::TcpStream, width: u16, height: u16) -> std::io::Result<()> {
    stream.write_all(b"RFB 003.008\n")?;
    let _client_version = read_exact(stream, 12)?;
    stream.write_all(&[1u8, 1u8])?;
    let chosen = read_exact(stream, 1)?;
    if chosen[0] != 1 {
        return Err(std::io::Error::other("client did not choose None security"));
    }
    stream.write_all(&0u32.to_be_bytes())?;
    let _client_init = read_exact(stream, 1)?;

    let mut init = Vec::new();
    init.extend_from_slice(&width.to_be_bytes());
    init.extend_from_slice(&height.to_be_bytes());
    write_pixel_format(&mut init);
    let name = b"litebox-graphics-demo";
    init.extend_from_slice(&(name.len() as u32).to_be_bytes());
    init.extend_from_slice(name);
    stream.write_all(&init)
}

fn handle_message(stream: &mut std::net::TcpStream, msg_type: u8) -> std::io::Result<bool> {
    match msg_type {
        0 => {
            read_exact(stream, 19)?;
            Ok(false)
        }
        2 => {
            let head = read_exact(stream, 3)?;
            let count = u16::from_be_bytes([head[1], head[2]]) as usize;
            read_exact(stream, count * 4)?;
            Ok(false)
        }
        3 => {
            read_exact(stream, 9)?;
            Ok(true)
        }
        4 => {
            read_exact(stream, 7)?;
            Ok(false)
        }
        5 => {
            read_exact(stream, 5)?;
            Ok(false)
        }
        6 => {
            let head = read_exact(stream, 7)?;
            let len = u32::from_be_bytes(head[3..7].try_into().unwrap()) as usize;
            read_exact(stream, len)?;
            Ok(false)
        }
        _ => Err(std::io::Error::other(format!("unsupported message type {msg_type}"))),
    }
}

fn draw_frame(gfx: &Graphics, frame: u32) {
    let width = gfx.width();
    let height = gfx.height();
    let t = (frame as f32) * 0.05;

    gfx.clear(Color::rgb(20, 20, 30));

    let c1 = Color::rgb(
        (80.0 + 80.0 * t.cos()) as u8,
        (100.0 + 100.0 * (t * 0.7).sin()) as u8,
        (150.0 + 80.0 * (t * 1.3).cos()) as u8,
    );
    let c2 = Color::rgb(
        (100.0 + 100.0 * (t * 0.5).sin()) as u8,
        (80.0 + 80.0 * (t * 0.8).cos()) as u8,
        (120.0 + 120.0 * (t * 1.1).sin()) as u8,
    );

    gfx.horizontal_gradient(10, 10, (width / 3) as u16, 40, c1, c2);
    gfx.vertical_gradient((width / 3 + 20) as u16, 10, (width / 3) as u16, 40, c1, c2);
    gfx.horizontal_gradient(
        (2 * width / 3 + 30) as u16,
        10,
        (width / 3 - 30) as u16,
        40,
        c2,
        c1,
    );

    let cx = (width as f32 / 2.0 + 40.0 * t.cos()) as u16;
    let cy = (height as f32 / 2.0 + 30.0 * (t * 0.8).sin()) as u16;
    let r = (20.0 + 15.0 * (t * 0.6).sin().abs()) as u16;
    gfx.fill_circle(cx, cy, r, Color::rgb(255, 100, 150));

    for i in 0..8 {
        let angle = (i as f32) * std::f32::consts::PI / 4.0 + t;
        let x0 = (width as f32 / 2.0) as u16;
        let y0 = (height as f32 / 2.0) as u16;
        let x1 = (width as f32 / 2.0 + 50.0 * angle.cos()) as u16;
        let y1 = (height as f32 / 2.0 + 50.0 * angle.sin()) as u16;
        let line_color = Color::rgb(
            (128.0 + 127.0 * angle.cos()) as u8,
            (128.0 + 127.0 * (angle + 2.0).sin()) as u8,
            (128.0 + 127.0 * (angle + 4.0).cos()) as u8,
        );
        gfx.draw_line(x0, y0, x1, y1, line_color, 2);
    }

    let rect_x = (30.0 + 20.0 * (t * 0.3).cos()) as u16;
    let rect_y = (height - 50) as u16;
    gfx.fill_rect(rect_x, rect_y, 40, 30, Color::rgb(100, 200, 100));

    let rect_x2 = ((width - 70) as f32 + 15.0 * (t * 0.4).sin()) as u16;
    gfx.fill_rect(rect_x2, rect_y, 40, 30, Color::rgb(200, 100, 200));
}

fn serve_client(mut client: std::net::TcpStream, gfx: &Graphics) -> std::io::Result<()> {
    handshake(&mut client, gfx.width(), gfx.height())?;
    eprintln!("graphics-demo: client handshake complete");

    let mut frame_num = 0u32;
    loop {
        let ty = match read_exact(&mut client, 1) {
            Ok(b) => b[0],
            Err(_) => {
                eprintln!("graphics-demo: client disconnected");
                return Ok(());
            }
        };

        if handle_message(&mut client, ty)? {
            draw_frame(gfx, frame_num);
            let pixels = gfx.as_bytes();

            let mut update = Vec::with_capacity(16 + pixels.len());
            update.push(0);
            update.push(0);
            update.extend_from_slice(&1u16.to_be_bytes());
            update.extend_from_slice(&0u16.to_be_bytes());
            update.extend_from_slice(&0u16.to_be_bytes());
            update.extend_from_slice(&gfx.width().to_be_bytes());
            update.extend_from_slice(&gfx.height().to_be_bytes());
            update.extend_from_slice(&0i32.to_be_bytes());
            update.extend_from_slice(&pixels);

            client.write_all(&update)?;
            eprintln!("graphics-demo: sent frame {}", frame_num);
            frame_num += 1;
        }
    }
}

fn main() {
    let width = 320u16;
    let height = 240u16;

    let rasterizer = SoftRasterizer::new(width, height);
    let gfx = Graphics::new(Box::new(rasterizer));

    let bind_ip = std::env::var("BIND_IP").unwrap_or_else(|_| String::from("0.0.0.0"));
    let listener = TcpListener::bind((bind_ip.as_str(), 5900)).expect("bind :5900 failed");
    eprintln!("graphics-demo: RFB server listening on {bind_ip}:5900");

    for incoming in listener.incoming() {
        match incoming {
            Ok(client) => {
                eprintln!("graphics-demo: client connected from {:?}", client.peer_addr());
                let timeout = Some(Duration::from_secs(30));
                let _ = client.set_read_timeout(timeout);
                let _ = client.set_write_timeout(timeout);
                if let Err(e) = serve_client(client, &gfx) {
                    eprintln!("graphics-demo: client session ended: {e}");
                }
            }
            Err(e) => eprintln!("graphics-demo: accept failed: {e}"),
        }
    }
}
