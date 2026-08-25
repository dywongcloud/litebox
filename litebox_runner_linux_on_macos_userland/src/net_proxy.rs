// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Guest web access without root: an HTTP proxy on the guest's loopback, bridged to real host
//! sockets.
//!
//! The macOS host has no `tun` device without root, so the guest's IP packets normally have
//! nowhere to go. But the *host* owns the guest's smoltcp stack, so it can terminate guest TCP
//! itself: `LinuxShim::listen_in_guest` plants a host-owned listener at `127.0.0.1:3128`
//! inside the guest's network, and this module speaks just enough HTTP-proxy protocol on the
//! accepted connections to re-originate each request as an ordinary host connection
//! (`CONNECT host:port` tunnels for TLS, absolute-URI requests for plain HTTP). A guest
//! browser pointed at `http_proxy=http://127.0.0.1:3128` browses the real web; the guest
//! itself still cannot emit a single raw packet.
//!
//! Hostname resolution happens here, over UDP directly to the resolvers snapshotted from
//! `/etc/resolv.conf` before the sandbox came up -- deliberately not `getaddrinfo`, whose
//! mDNSResponder path stays closed under the widened Seatbelt profile (see
//! `RUNNER_PROFILE_WITH_OUTBOUND_NETWORK`).

use std::collections::HashMap;
use std::io::{Read as _, Write as _};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, UdpSocket};
use std::time::{Duration, Instant};

use litebox_platform_macos_userland::MacOsUserland as Platform;
use litebox_shim_linux::host_service::{GuestListener, GuestStream, StreamRead};

/// Where the proxy listens inside the guest network. Fixed rather than configurable until
/// something needs it to move: 3128 is squid's conventional port, and the guest loopback is
/// the one address every guest can already reach.
pub const PROXY_ADDR: (Ipv4Addr, u16) = (Ipv4Addr::LOCALHOST, 3128);

/// Snapshot the host's DNS resolvers while `/etc/resolv.conf` is still readable (pre-sandbox).
/// Falls back to well-known public resolvers when the file is unreadable or empty.
pub fn snapshot_resolvers() -> Vec<Ipv4Addr> {
    let mut out = Vec::new();
    if let Ok(text) = std::fs::read_to_string("/etc/resolv.conf") {
        for line in text.lines() {
            let mut it = line.split_whitespace();
            if it.next() == Some("nameserver")
                && let Some(addr) = it.next()
                && let Ok(IpAddr::V4(v4)) = addr.parse::<IpAddr>()
            {
                out.push(v4);
            }
        }
    }
    if out.is_empty() {
        out.extend([Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(8, 8, 8, 8)]);
    }
    out
}

/// A minimal, cache-backed A-record resolver over plain UDP port 53.
struct Resolver {
    servers: Vec<Ipv4Addr>,
    cache: HashMap<String, (Ipv4Addr, Instant)>,
}

impl Resolver {
    const TTL: Duration = Duration::from_mins(2);

    fn resolve(&mut self, host: &str) -> Option<Ipv4Addr> {
        if let Ok(ip) = host.parse::<Ipv4Addr>() {
            return Some(ip);
        }
        if let Some((ip, at)) = self.cache.get(host)
            && at.elapsed() < Self::TTL
        {
            return Some(*ip);
        }
        let ip = self.query(host)?;
        self.cache.insert(host.to_owned(), (ip, Instant::now()));
        Some(ip)
    }

    fn query(&self, host: &str) -> Option<Ipv4Addr> {
        let mut packet = vec![
            0x13, 0x37, // id
            0x01, 0x00, // RD
            0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 1 question
        ];
        for label in host.split('.') {
            let bytes = label.as_bytes();
            if bytes.is_empty() || bytes.len() > 63 {
                return None;
            }
            packet.push(u8::try_from(bytes.len()).unwrap_or(0));
            packet.extend_from_slice(bytes);
        }
        packet.extend_from_slice(&[0, 0x00, 0x01, 0x00, 0x01]); // root, A, IN
        let sock = match UdpSocket::bind("0.0.0.0:0") {
            Ok(s) => s,
            Err(e) => {
                litebox_util_log::debug!(error:% = e; "net-proxy: dns udp bind failed");
                return None;
            }
        };
        sock.set_read_timeout(Some(Duration::from_secs(3))).ok()?;
        for server in &self.servers {
            if let Err(e) = sock.send_to(&packet, SocketAddr::from((*server, 53))) {
                litebox_util_log::debug!(error:% = e; "net-proxy: dns send failed");
                continue;
            }
            let mut buf = [0u8; 1024];
            let (n, _) = match sock.recv_from(&mut buf) {
                Ok(v) => v,
                Err(e) => {
                    litebox_util_log::debug!(error:% = e; "net-proxy: dns recv failed");
                    continue;
                }
            };
            if let Some(ip) = parse_dns_a_answer(&buf[..n]) {
                return Some(ip);
            }
        }
        None
    }
}

/// Extract the first A record from a DNS response. Enough of RFC 1035 for a proxy resolver:
/// skips the question section, walks answers honoring name compression only to the extent of
/// skipping over it.
fn parse_dns_a_answer(msg: &[u8]) -> Option<Ipv4Addr> {
    if msg.len() < 12 {
        return None;
    }
    let qdcount = u16::from_be_bytes([msg[4], msg[5]]) as usize;
    let ancount = u16::from_be_bytes([msg[6], msg[7]]) as usize;
    let mut pos = 12;
    let skip_name = |pos: &mut usize| -> Option<()> {
        loop {
            let len = *msg.get(*pos)? as usize;
            if len == 0 {
                *pos += 1;
                return Some(());
            }
            if len & 0xc0 == 0xc0 {
                *pos += 2;
                return Some(());
            }
            *pos += 1 + len;
        }
    };
    for _ in 0..qdcount {
        skip_name(&mut pos)?;
        pos += 4; // qtype + qclass
    }
    for _ in 0..ancount {
        skip_name(&mut pos)?;
        let rtype = u16::from_be_bytes([*msg.get(pos)?, *msg.get(pos + 1)?]);
        let rdlen = u16::from_be_bytes([*msg.get(pos + 8)?, *msg.get(pos + 9)?]) as usize;
        pos += 10;
        if rtype == 1 && rdlen == 4 {
            return Some(Ipv4Addr::new(
                *msg.get(pos)?,
                *msg.get(pos + 1)?,
                *msg.get(pos + 2)?,
                *msg.get(pos + 3)?,
            ));
        }
        pos += rdlen;
    }
    None
}

/// One proxied connection's lifecycle.
enum ConnState {
    /// Accumulating the request head until `\r\n\r\n`.
    ReadingRequest(Vec<u8>),
    /// Pumping bytes both ways.
    Relaying,
}

struct Conn {
    guest: GuestStream<Platform>,
    host: Option<TcpStream>,
    state: ConnState,
    /// Bytes destined for the host socket that its kernel buffer hasn't taken yet.
    to_host: Vec<u8>,
    /// Bytes destined for the guest that its TX ring hasn't taken yet.
    to_guest: Vec<u8>,
    /// The host side saw EOF; once `to_guest` drains, the connection is done.
    host_eof: bool,
}

/// Drive the proxy forever. Runs on its own host thread, spawned before the sandbox comes up
/// (thread creation is unmediated, and the widened profile keeps `connect` working after).
pub fn serve(listener: &GuestListener<Platform>, resolvers: Vec<Ipv4Addr>) {
    let mut resolver = Resolver {
        servers: resolvers,
        cache: HashMap::new(),
    };
    let mut conns: Vec<Conn> = Vec::new();
    let mut scratch = vec![0u8; 64 * 1024];
    loop {
        while let Some(guest) = listener.try_accept() {
            litebox_util_log::debug!("net-proxy: accepted a guest connection");
            conns.push(Conn {
                guest,
                host: None,
                state: ConnState::ReadingRequest(Vec::new()),
                to_host: Vec::new(),
                to_guest: Vec::new(),
                host_eof: false,
            });
        }
        let mut progressed = false;
        conns.retain_mut(|conn| match step(conn, &mut resolver, &mut scratch) {
            StepOutcome::Progressed => {
                progressed = true;
                true
            }
            StepOutcome::Idle => true,
            StepOutcome::Done => false,
        });
        if !progressed {
            std::thread::sleep(Duration::from_millis(2));
        }
    }
}

enum StepOutcome {
    Progressed,
    Idle,
    Done,
}

fn step(conn: &mut Conn, resolver: &mut Resolver, scratch: &mut [u8]) -> StepOutcome {
    let mut progressed = false;
    match &mut conn.state {
        ConnState::ReadingRequest(head) => match conn.guest.try_read(scratch) {
            StreamRead::Data(n) => {
                head.extend_from_slice(&scratch[..n]);
                if let Some(split) = find_header_end(head) {
                    let body = head.split_off(split);
                    let head = std::mem::take(head);
                    litebox_util_log::debug!(
                        head:% = String::from_utf8_lossy(&head);
                        "net-proxy: request head complete"
                    );
                    let Some((stream, forward, reply)) = open_upstream(&head, resolver) else {
                        let _ = conn
                            .guest
                            .try_write(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n");
                        return StepOutcome::Done;
                    };
                    litebox_util_log::debug!("net-proxy: upstream dialed");
                    conn.host = Some(stream);
                    conn.to_host = forward;
                    conn.to_host.extend_from_slice(&body);
                    conn.to_guest = reply;
                    conn.state = ConnState::Relaying;
                } else if head.len() > 64 * 1024 {
                    // A request head this large is not a real browser's; drop it.
                    return StepOutcome::Done;
                }
                StepOutcome::Progressed
            }
            StreamRead::Empty => StepOutcome::Idle,
            StreamRead::Closed => StepOutcome::Done,
        },
        ConnState::Relaying => {
            let Some(host) = conn.host.as_mut() else {
                return StepOutcome::Done;
            };
            // guest -> host
            if conn.to_host.is_empty() {
                match conn.guest.try_read(scratch) {
                    StreamRead::Data(n) => {
                        conn.to_host.extend_from_slice(&scratch[..n]);
                        progressed = true;
                    }
                    StreamRead::Empty => {}
                    StreamRead::Closed => return StepOutcome::Done,
                }
            }
            if !conn.to_host.is_empty() {
                match host.write(&conn.to_host) {
                    Ok(n) if n > 0 => {
                        conn.to_host.drain(..n);
                        progressed = true;
                    }
                    Ok(_) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(_) => return StepOutcome::Done,
                }
            }
            // host -> guest
            if conn.to_guest.is_empty() && !conn.host_eof {
                match host.read(scratch) {
                    Ok(0) => {
                        conn.host_eof = true;
                        progressed = true;
                    }
                    Ok(n) => {
                        litebox_util_log::debug!(n:% = n; "net-proxy: read from host");
                        conn.to_guest.extend_from_slice(&scratch[..n]);
                        progressed = true;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(_) => return StepOutcome::Done,
                }
            }
            if !conn.to_guest.is_empty() {
                match conn.guest.try_write(&conn.to_guest) {
                    Some(n) if n > 0 => {
                        conn.to_guest.drain(..n);
                        progressed = true;
                    }
                    Some(_) => {}
                    None => return StepOutcome::Done,
                }
            }
            if conn.host_eof && conn.to_guest.is_empty() {
                // Everything the origin had to say is queued toward the guest; the drop path's
                // deferred close FINs once the stack drains it.
                return StepOutcome::Done;
            }
            if progressed {
                StepOutcome::Progressed
            } else {
                StepOutcome::Idle
            }
        }
    }
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

/// Parse the request head, dial the origin, and produce `(stream, bytes_to_forward,
/// immediate_reply_to_guest)`. `CONNECT` forwards nothing and replies `200`; plain requests
/// forward a rewritten origin-form request and reply nothing.
fn open_upstream(head: &[u8], resolver: &mut Resolver) -> Option<(TcpStream, Vec<u8>, Vec<u8>)> {
    let text = core::str::from_utf8(head).ok()?;
    let mut lines = text.split("\r\n");
    let request_line = lines.next()?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next()?;
    let target = parts.next()?;
    let version = parts.next().unwrap_or("HTTP/1.1");

    if method.eq_ignore_ascii_case("CONNECT") {
        let (host, port) = split_host_port(target, 443)?;
        let stream = dial(resolver, host, port)?;
        return Some((
            stream,
            Vec::new(),
            b"HTTP/1.1 200 Connection established\r\n\r\n".to_vec(),
        ));
    }

    // Absolute-URI request: `GET http://host[:port]/path HTTP/1.1`.
    let rest = target.strip_prefix("http://")?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = split_host_port(authority, 80)?;
    let stream = dial(resolver, host, port)?;

    let mut forward = format!("{method} {path} {version}\r\n").into_bytes();
    for line in lines {
        if line.is_empty() {
            break;
        }
        // The proxy manages its own hop: per-hop headers don't travel to the origin, and
        // keep-alive re-use across requests isn't implemented, so say so.
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("proxy-connection:") || lower.starts_with("connection:") {
            continue;
        }
        forward.extend_from_slice(line.as_bytes());
        forward.extend_from_slice(b"\r\n");
    }
    forward.extend_from_slice(b"Connection: close\r\n\r\n");
    Some((stream, forward, Vec::new()))
}

fn split_host_port(authority: &str, default_port: u16) -> Option<(&str, u16)> {
    match authority.rsplit_once(':') {
        Some((host, port)) if port.chars().all(|c| c.is_ascii_digit()) => {
            Some((host, port.parse().ok()?))
        }
        _ => Some((authority, default_port)),
    }
}

fn dial(resolver: &mut Resolver, host: &str, port: u16) -> Option<TcpStream> {
    let Some(ip) = resolver.resolve(host) else {
        litebox_util_log::debug!(host:% = host; "net-proxy: dns resolution failed");
        return None;
    };
    litebox_util_log::debug!(host:% = host, ip:% = ip; "net-proxy: resolved");
    let stream =
        match TcpStream::connect_timeout(&SocketAddr::from((ip, port)), Duration::from_secs(10)) {
            Ok(s) => s,
            Err(e) => {
                litebox_util_log::debug!(error:% = e; "net-proxy: connect failed");
                return None;
            }
        };
    stream.set_nonblocking(true).ok()?;
    Some(stream)
}
