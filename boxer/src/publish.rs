// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Publishing a box's ports to the host.
//!
//! A box's workload listens on the guest address behind LiteBox's TUN
//! interface, which the host can already route to. Publishing puts a listener
//! on a host port and forwards each connection to the guest, so `-p 8080:80`
//! reaches the workload the same way it would under a container runtime,
//! without callers needing to know the guest address.
//!
//! Forwarding is async because a published port is inherently concurrent: many
//! clients at once, each streaming in both directions for as long as it likes,
//! and one slow or stuck peer must not stall the others. Each connection is a
//! task, each direction is a copy that propagates its own half-close, and a
//! guest that refuses a connection fails that connection only.

use std::net::{Ipv4Addr, SocketAddrV4};
// Only the linux+x86_64 forwarding paths name the enum directly.
#[cfg(any(
    all(target_os = "linux", target_arch = "x86_64"),
    all(target_os = "macos", target_arch = "aarch64")
))]
use std::net::SocketAddr;

use anyhow::{Context, bail};

/// Default address LiteBox's network stack answers on, used unless
/// `boxer run --net-guest-ip` overrides it, matching the guest IP the shim
/// configures for the TUN interface by default.
pub const GUEST_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);

/// Transport protocol of a published port.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Udp,
}

impl Protocol {
    /// The lowercase name used in `-p` specs and messages.
    pub fn as_str(self) -> &'static str {
        match self {
            Protocol::Tcp => "tcp",
            Protocol::Udp => "udp",
        }
    }
}

/// One `-p` mapping: a host bind address plus the guest port to forward to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortMapping {
    pub host_addr: SocketAddrV4,
    pub guest_port: u16,
    pub protocol: Protocol,
}

impl PortMapping {
    /// Parse docker's `-p` shapes: `GUEST`, `HOST:GUEST`, `IP:HOST:GUEST`,
    /// each optionally suffixed `/tcp` or `/udp` (TCP is the default).
    pub fn parse(spec: &str) -> anyhow::Result<Self> {
        let (addr_part, proto) = match spec.rsplit_once('/') {
            Some((addr, proto)) => (addr, proto.to_ascii_lowercase()),
            None => (spec, String::from("tcp")),
        };
        let protocol = match proto.as_str() {
            "tcp" => Protocol::Tcp,
            "udp" => Protocol::Udp,
            other => bail!("port protocol must be tcp or udp, got '{other}' (in '{spec}')"),
        };

        let parse_port = |text: &str| -> anyhow::Result<u16> {
            text.trim()
                .parse::<u16>()
                .ok()
                .filter(|port| *port != 0)
                .with_context(|| format!("'{text}' is not a port in 1-65535 (in '{spec}')"))
        };

        let fields: Vec<&str> = addr_part.split(':').collect();
        let (host_ip, host_port, guest_port) = match fields.as_slice() {
            [guest] => {
                let port = parse_port(guest)?;
                (Ipv4Addr::LOCALHOST, port, port)
            }
            [host, guest] => (Ipv4Addr::LOCALHOST, parse_port(host)?, parse_port(guest)?),
            [ip, host, guest] => (
                ip.parse::<Ipv4Addr>()
                    .with_context(|| format!("'{ip}' is not an IPv4 address (in '{spec}')"))?,
                parse_port(host)?,
                parse_port(guest)?,
            ),
            _ => bail!("expected PORT, HOST:GUEST or IP:HOST:GUEST, got '{spec}'"),
        };

        Ok(Self {
            host_addr: SocketAddrV4::new(host_ip, host_port),
            guest_port,
            protocol,
        })
    }

    /// The mapping that `--publish-all` derives from an `EXPOSE`d port, which
    /// keeps the same number on both sides and its declared protocol (tcp or
    /// udp). A malformed entry yields `None`.
    pub fn from_exposed(exposed: &str) -> Option<Self> {
        let (port, proto) = match exposed.split_once('/') {
            Some((port, proto)) => (port, proto),
            None => (exposed, "tcp"),
        };
        let protocol = match proto.to_ascii_lowercase().as_str() {
            "tcp" => Protocol::Tcp,
            "udp" => Protocol::Udp,
            _ => return None,
        };
        let port: u16 = port.trim().parse().ok().filter(|p| *p != 0)?;
        Some(Self {
            host_addr: SocketAddrV4::new(Ipv4Addr::LOCALHOST, port),
            guest_port: port,
            protocol,
        })
    }
}

/// A running set of published ports. Dropping it stops accepting; connections
/// already in flight end with the process.
#[cfg(any(
    all(target_os = "linux", target_arch = "x86_64"),
    all(target_os = "macos", target_arch = "aarch64")
))]
pub struct PublishedPorts {
    _runtime: tokio::runtime::Runtime,
}

/// Bind every mapping on the host and forward accepted connections to the
/// guest. Binding happens before this returns, so a port that is already in
/// use is reported before the workload starts rather than racing it.
#[cfg(any(
    all(target_os = "linux", target_arch = "x86_64"),
    all(target_os = "macos", target_arch = "aarch64")
))]
pub fn publish(
    mappings: &[PortMapping],
    verbose: bool,
    guest_ip: Ipv4Addr,
) -> anyhow::Result<PublishedPorts> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .context("failed to start the port-publishing runtime")?;

    for mapping in mappings {
        match mapping.protocol {
            Protocol::Tcp => publish_tcp(&runtime, *mapping, verbose, guest_ip)?,
            Protocol::Udp => publish_udp(&runtime, *mapping, verbose, guest_ip)?,
        }
    }

    Ok(PublishedPorts { _runtime: runtime })
}

/// Bind a host TCP listener and forward each accepted connection to the guest.
#[cfg(any(
    all(target_os = "linux", target_arch = "x86_64"),
    all(target_os = "macos", target_arch = "aarch64")
))]
fn publish_tcp(
    runtime: &tokio::runtime::Runtime,
    mapping: PortMapping,
    verbose: bool,
    guest_ip: Ipv4Addr,
) -> anyhow::Result<()> {
    use tokio::io::AsyncWriteExt as _;
    use tokio::net::{TcpListener, TcpStream};

    let host_addr = mapping.host_addr;
    let guest_addr = SocketAddr::V4(SocketAddrV4::new(guest_ip, mapping.guest_port));

    // Bind on this thread's runtime context so the error surfaces here, before
    // the guest is started.
    let listener = runtime
        .block_on(async { TcpListener::bind(host_addr).await })
        .with_context(|| format!("failed to bind published port {host_addr}/tcp"))?;

    eprintln!("Publishing {host_addr}/tcp -> {guest_addr}/tcp");

    runtime.spawn(async move {
        loop {
            let (mut client, peer) = match listener.accept().await {
                Ok(accepted) => accepted,
                Err(e) => {
                    eprintln!("warning: accept failed on {host_addr}: {e}");
                    continue;
                }
            };
            tokio::spawn(async move {
                let mut guest = match TcpStream::connect(guest_addr).await {
                    Ok(stream) => stream,
                    Err(e) => {
                        // The workload may not be listening yet, or not at all:
                        // that is this connection's failure, not the listener's.
                        eprintln!("warning: {peer} -> {guest_addr} failed: {e}");
                        let _ = client.shutdown().await;
                        return;
                    }
                };
                if verbose {
                    eprintln!("  {peer} -> {guest_addr}");
                }
                // copy_bidirectional forwards each direction independently and
                // shuts down the far side when its own side ends, so a workload
                // that half-closes after its response is seen as such.
                if let Err(e) = tokio::io::copy_bidirectional(&mut client, &mut guest).await
                    && verbose
                {
                    eprintln!("  {peer} closed: {e}");
                }
            });
        }
    });
    Ok(())
}

/// A hard ceiling on concurrently tracked UDP clients, so a flood of distinct
/// (possibly spoofed) source addresses cannot exhaust sockets between reaps.
/// Idle entries are reclaimed continuously (see [`UDP_CLIENT_IDLE_TIMEOUT`]),
/// so this bounds live clients, not the number ever seen.
#[cfg(any(
    all(target_os = "linux", target_arch = "x86_64"),
    all(target_os = "macos", target_arch = "aarch64")
))]
const MAX_UDP_CLIENTS: usize = 1024;

/// How long a UDP client entry may sit idle -- no datagram in either direction
/// -- before its guest-side socket and reply task are reclaimed. UDP has no
/// connection to close, so entries are reaped on inactivity; without this a
/// long-running relay would leak a socket, task, and buffer per distinct source
/// address forever (a well-behaved DNS resolver alone cycles through thousands
/// of ephemeral source ports).
#[cfg(any(
    all(target_os = "linux", target_arch = "x86_64"),
    all(target_os = "macos", target_arch = "aarch64")
))]
const UDP_CLIENT_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_mins(1);

/// How often the relay sweeps its client table for idle entries.
#[cfg(any(
    all(target_os = "linux", target_arch = "x86_64"),
    all(target_os = "macos", target_arch = "aarch64")
))]
const UDP_REAP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(15);

/// Bind a host UDP socket and relay datagrams to the guest, one guest-side
/// socket per client source address so replies route back to the right client.
#[cfg(any(
    all(target_os = "linux", target_arch = "x86_64"),
    all(target_os = "macos", target_arch = "aarch64")
))]
fn publish_udp(
    runtime: &tokio::runtime::Runtime,
    mapping: PortMapping,
    verbose: bool,
    guest_ip: Ipv4Addr,
) -> anyhow::Result<()> {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};
    use std::time::Instant;

    use tokio::net::UdpSocket;

    /// One tracked client flow. `last_seen` is shared with the reply task so
    /// traffic in either direction keeps the flow alive; the reaper aborts
    /// `reply_task` when the flow goes idle.
    struct Client {
        guest: Arc<UdpSocket>,
        last_seen: Arc<Mutex<Instant>>,
        reply_task: tokio::task::JoinHandle<()>,
    }

    let host_addr = mapping.host_addr;
    let guest_addr = SocketAddr::V4(SocketAddrV4::new(guest_ip, mapping.guest_port));

    let socket = runtime
        .block_on(async { UdpSocket::bind(host_addr).await })
        .with_context(|| format!("failed to bind published port {host_addr}/udp"))?;
    let socket = Arc::new(socket);

    eprintln!("Publishing {host_addr}/udp -> {guest_addr}/udp");

    runtime.spawn(async move {
        // Only this task mutates the table, so no lock on the map is needed;
        // each entry's `last_seen` is the one value the reply tasks also touch.
        let mut clients: HashMap<SocketAddr, Client> = HashMap::new();
        let mut buf = vec![0u8; 65_536];
        let mut reaper = tokio::time::interval(UDP_REAP_INTERVAL);
        reaper.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                received = socket.recv_from(&mut buf) => {
                    let (len, client) = match received {
                        Ok(received) => received,
                        Err(e) => {
                            eprintln!("warning: recv failed on {host_addr}: {e}");
                            continue;
                        }
                    };

                    // Reuse a live entry, bumping its activity clock.
                    if let Some(existing) = clients.get(&client) {
                        *existing.last_seen.lock().unwrap() = Instant::now();
                        let _ = existing.guest.send(&buf[..len]).await;
                        continue;
                    }

                    if clients.len() >= MAX_UDP_CLIENTS {
                        eprintln!(
                            "warning: {host_addr}/udp is tracking {MAX_UDP_CLIENTS} clients; \
                             dropping datagram from {client}"
                        );
                        continue;
                    }

                    // A fresh guest-side socket bound to an ephemeral port,
                    // connected so its replies come only from the guest workload.
                    let guest_socket =
                        match UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)).await {
                            Ok(guest_socket) => guest_socket,
                            Err(e) => {
                                eprintln!("warning: {client} -> {guest_addr} setup failed: {e}");
                                continue;
                            }
                        };
                    if let Err(e) = guest_socket.connect(guest_addr).await {
                        eprintln!("warning: {client} -> {guest_addr} connect failed: {e}");
                        continue;
                    }
                    let guest_socket = Arc::new(guest_socket);
                    if verbose {
                        eprintln!("  {client} -> {guest_addr}");
                    }

                    let last_seen = Arc::new(Mutex::new(Instant::now()));

                    // Relay the guest's replies back to this client.
                    let back_socket = Arc::clone(&socket);
                    let reply_from = Arc::clone(&guest_socket);
                    let reply_seen = Arc::clone(&last_seen);
                    let reply_task = tokio::spawn(async move {
                        let mut reply = vec![0u8; 65_536];
                        // A connected UDP socket reports a queued ICMP error
                        // (e.g. port-unreachable before the workload binds its
                        // port) as a one-shot recv error. Loop past it and keep
                        // serving rather than abandoning the client for the life
                        // of the process -- the earlier `while let Ok` form broke
                        // out permanently here. A genuinely idle flow is reclaimed
                        // by the reaper instead.
                        loop {
                            if let Ok(reply_len) = reply_from.recv(&mut reply).await {
                                *reply_seen.lock().unwrap() = Instant::now();
                                let _ = back_socket.send_to(&reply[..reply_len], client).await;
                            }
                        }
                    });

                    clients.insert(
                        client,
                        Client { guest: Arc::clone(&guest_socket), last_seen, reply_task },
                    );
                    let _ = guest_socket.send(&buf[..len]).await;
                }
                _ = reaper.tick() => {
                    let now = Instant::now();
                    clients.retain(|_, entry| {
                        let idle = now.duration_since(*entry.last_seen.lock().unwrap());
                        let keep = idle < UDP_CLIENT_IDLE_TIMEOUT;
                        if !keep {
                            entry.reply_task.abort();
                        }
                        keep
                    });
                }
            }
        }
    });
    Ok(())
}

#[cfg(not(any(
    all(target_os = "linux", target_arch = "x86_64"),
    all(target_os = "macos", target_arch = "aarch64")
)))]
pub struct PublishedPorts;

#[cfg(not(any(
    all(target_os = "linux", target_arch = "x86_64"),
    all(target_os = "macos", target_arch = "aarch64")
)))]
pub fn publish(
    _mappings: &[PortMapping],
    _verbose: bool,
    _guest_ip: Ipv4Addr,
) -> anyhow::Result<PublishedPorts> {
    bail!("publishing ports needs the x86_64 Linux runner")
}
