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

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use anyhow::{Context, bail};

/// The address LiteBox's network stack answers on, matching the guest IP the
/// shim configures for the TUN interface.
pub const GUEST_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);

/// One `-p` mapping: a host bind address plus the guest port to forward to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortMapping {
    pub host_addr: SocketAddrV4,
    pub guest_port: u16,
}

impl PortMapping {
    /// Parse docker's `-p` shapes: `GUEST`, `HOST:GUEST`, `IP:HOST:GUEST`,
    /// each optionally suffixed `/tcp` or `/udp`.
    ///
    /// UDP is rejected rather than silently forwarded over TCP.
    pub fn parse(spec: &str) -> anyhow::Result<Self> {
        let (addr_part, proto) = match spec.rsplit_once('/') {
            Some((addr, proto)) => (addr, proto.to_ascii_lowercase()),
            None => (spec, String::from("tcp")),
        };
        if proto != "tcp" {
            bail!("only tcp ports can be published today, got '{spec}'");
        }

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
        })
    }

    /// The mapping that `--publish-all` derives from an `EXPOSE`d port, which
    /// keeps the same number on both sides. Non-TCP entries have no TCP
    /// mapping and yield `None`.
    pub fn from_exposed(exposed: &str) -> Option<Self> {
        let (port, proto) = match exposed.split_once('/') {
            Some((port, proto)) => (port, proto),
            None => (exposed, "tcp"),
        };
        if !proto.eq_ignore_ascii_case("tcp") {
            return None;
        }
        let port: u16 = port.trim().parse().ok().filter(|p| *p != 0)?;
        Some(Self {
            host_addr: SocketAddrV4::new(Ipv4Addr::LOCALHOST, port),
            guest_port: port,
        })
    }
}

/// A running set of published ports. Dropping it stops accepting; connections
/// already in flight end with the process.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub struct PublishedPorts {
    _runtime: tokio::runtime::Runtime,
}

/// Bind every mapping on the host and forward accepted connections to the
/// guest. Binding happens before this returns, so a port that is already in
/// use is reported before the workload starts rather than racing it.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub fn publish(mappings: &[PortMapping], verbose: bool) -> anyhow::Result<PublishedPorts> {
    use tokio::io::AsyncWriteExt as _;
    use tokio::net::{TcpListener, TcpStream};

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .context("failed to start the port-publishing runtime")?;

    for mapping in mappings {
        let host_addr = mapping.host_addr;
        let guest_addr = SocketAddr::V4(SocketAddrV4::new(GUEST_IP, mapping.guest_port));

        // Bind on this thread's runtime context so the error surfaces here,
        // before the guest is started.
        let listener = runtime
            .block_on(async { TcpListener::bind(host_addr).await })
            .with_context(|| format!("failed to bind published port {host_addr}"))?;

        eprintln!("Publishing {host_addr} -> {guest_addr}");

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
                            // The workload may not be listening yet, or not at
                            // all: that is this connection's failure, not the
                            // listener's.
                            eprintln!("warning: {peer} -> {guest_addr} failed: {e}");
                            let _ = client.shutdown().await;
                            return;
                        }
                    };
                    if verbose {
                        eprintln!("  {peer} -> {guest_addr}");
                    }
                    // copy_bidirectional forwards each direction independently
                    // and shuts down the far side when its own side ends, so a
                    // workload that half-closes after its response is seen as
                    // such by the client.
                    if let Err(e) = tokio::io::copy_bidirectional(&mut client, &mut guest).await
                        && verbose
                    {
                        eprintln!("  {peer} closed: {e}");
                    }
                });
            }
        });
    }

    Ok(PublishedPorts { _runtime: runtime })
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
pub struct PublishedPorts;

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
pub fn publish(_mappings: &[PortMapping], _verbose: bool) -> anyhow::Result<PublishedPorts> {
    bail!("publishing ports needs the x86_64 Linux runner")
}
