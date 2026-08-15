// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Creating the TUN device a box's workload needs to be reachable.
//!
//! LiteBox's network stack speaks to the host through a TUN interface: the
//! guest answers on [`crate::publish::GUEST_IP`] and the host side owns the
//! other address on that subnet. Setting one up is otherwise a separate
//! privileged step with `ip tuntap`, which makes serving a port a two-command
//! affair with a script that boxer does not own.
//!
//! So boxer does it itself, with the same ioctls `ip` uses: `TUNSETIFF` to
//! create the interface, `TUNSETPERSIST` so it outlives the process that made
//! it, and the classic `SIOCSIF*` address/flags calls on an ordinary socket.
//! No child process and no `iproute2` on the host.

use std::os::fd::{AsRawFd as _, OwnedFd};

use anyhow::{Context, bail};

/// Host-side address of the point-to-point link, matching the address the
/// LiteBox shim expects to talk to.
pub const HOST_IP: std::net::Ipv4Addr = std::net::Ipv4Addr::new(10, 0, 0, 1);
/// Prefix length of the link's subnet, which must contain both the host
/// address and [`crate::publish::GUEST_IP`].
const PREFIX_LEN: u32 = 24;

// `ioctl` request numbers. The TUN ones are `_IOW('T', n, int)`; the socket
// ones are Linux's stable `SIOCSIF*` constants.
const TUNSETIFF: libc::c_ulong = 0x4004_54ca;
const TUNSETPERSIST: libc::c_ulong = 0x4004_54cb;
const SIOCSIFADDR: libc::c_ulong = 0x8916;
const SIOCSIFNETMASK: libc::c_ulong = 0x891c;
const SIOCGIFFLAGS: libc::c_ulong = 0x8913;
const SIOCSIFFLAGS: libc::c_ulong = 0x8914;

const IFNAMSIZ: usize = 16;

/// `struct ifreq` as the kernel reads it for the calls used here. The union
/// tail is widened to its full size so every variant fits.
#[repr(C)]
struct IfReq {
    name: [libc::c_char; IFNAMSIZ],
    union: [u8; 24],
}

impl IfReq {
    fn new(name: &str) -> anyhow::Result<Self> {
        if name.len() >= IFNAMSIZ {
            bail!(
                "network device name '{name}' is longer than {} bytes",
                IFNAMSIZ - 1
            );
        }
        let mut req = Self {
            name: [0; IFNAMSIZ],
            union: [0; 24],
        };
        for (slot, byte) in req.name.iter_mut().zip(name.as_bytes()) {
            *slot = byte.cast_signed();
        }
        Ok(req)
    }
}

/// Ensure `device` exists, carries the host address, and is up.
///
/// Returns `Ok(true)` when this call created the device and `Ok(false)` when
/// it was already there, so callers can say which happened.
pub fn ensure_device(device: &str) -> anyhow::Result<bool> {
    let existed = device_exists(device);
    if existed {
        // A name that already exists might be a real NIC or bridge. Configuring
        // it would replace its address with boxer's and bring it up -- severing
        // host connectivity on a typo like `--net eth0`. Only reuse an existing
        // interface when it is a TUN; refuse anything else rather than clobber
        // a device boxer did not create.
        if !is_tun_device(device) {
            bail!(
                "network device '{device}' already exists and is not a TUN device; \
                 boxer will not reconfigure it. Pass a different --net name."
            );
        }
    } else {
        create_device(device)?;
    }
    configure_device(device)?;
    Ok(!existed)
}

/// Is there already an interface with this name?
fn device_exists(device: &str) -> bool {
    std::path::Path::new("/sys/class/net").join(device).exists()
}

/// Is this interface a TUN/TAP device? The kernel exposes `tun_flags` in sysfs
/// only for tun/tap interfaces, so its presence tells a TUN from an ordinary
/// NIC, veth, or bridge without opening a socket.
fn is_tun_device(device: &str) -> bool {
    std::path::Path::new("/sys/class/net")
        .join(device)
        .join("tun_flags")
        .exists()
}

/// Create a persistent TUN interface via `/dev/net/tun`.
fn create_device(device: &str) -> anyhow::Result<()> {
    let tun = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/net/tun")
        .context(
            "cannot open /dev/net/tun to create the network device; \
             the tun module must be loaded and this process needs access to it",
        )?;
    let tun = OwnedFd::from(tun);

    let mut req = IfReq::new(device)?;
    // ifr_flags is the first union member: IFF_TUN (a point-to-point IP
    // device) with IFF_NO_PI (no per-packet prefix), which is what LiteBox's
    // platform expects to read.
    let flags = libc::c_short::try_from(libc::IFF_TUN | libc::IFF_NO_PI)
        .expect("IFF_TUN | IFF_NO_PI fits in ifr_flags");
    req.union[..2].copy_from_slice(&flags.to_ne_bytes());

    // SAFETY: `req` is a correctly-shaped `ifreq` living for the call, and
    // `tun` is an open file descriptor for /dev/net/tun.
    if unsafe { libc::ioctl(tun.as_raw_fd(), TUNSETIFF, &raw mut req) } < 0 {
        return Err(std::io::Error::last_os_error()).with_context(|| {
            format!(
                "failed to create TUN device '{device}' (creating a network \
                 device needs CAP_NET_ADMIN, usually root)"
            )
        });
    }

    // Without this the interface disappears when this fd closes, taking the
    // guest's connectivity with it.
    // SAFETY: `tun` is the descriptor just bound to the new interface.
    if unsafe { libc::ioctl(tun.as_raw_fd(), TUNSETPERSIST, 1) } < 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("failed to make TUN device '{device}' persistent"));
    }

    Ok(())
}

/// Give the device its host address and bring it up.
fn configure_device(device: &str) -> anyhow::Result<()> {
    // SAFETY: creating a socket with constant arguments; the result is checked.
    let socket = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if socket < 0 {
        return Err(std::io::Error::last_os_error())
            .context("failed to open a socket to configure the network device");
    }
    // SAFETY: `socket` is the descriptor just returned above and is not used
    // after this guard drops it.
    let socket = unsafe { OwnedFd::from_raw_fd_checked(socket) };

    set_address(socket.as_raw_fd(), device, SIOCSIFADDR, HOST_IP)
        .with_context(|| format!("failed to set {HOST_IP} on '{device}'"))?;
    set_address(
        socket.as_raw_fd(),
        device,
        SIOCSIFNETMASK,
        netmask(PREFIX_LEN),
    )
    .with_context(|| format!("failed to set the netmask on '{device}'"))?;
    bring_up(socket.as_raw_fd(), device)
        .with_context(|| format!("failed to bring '{device}' up"))?;
    Ok(())
}

/// Write an IPv4 address into one of the `SIOCSIF*` address slots.
fn set_address(
    socket: libc::c_int,
    device: &str,
    request: libc::c_ulong,
    address: std::net::Ipv4Addr,
) -> anyhow::Result<()> {
    let mut req = IfReq::new(device)?;
    // The union holds a `sockaddr_in`: family, port, then the address.
    let family = u16::try_from(libc::AF_INET).expect("AF_INET fits in u16");
    req.union[..2].copy_from_slice(&family.to_ne_bytes());
    req.union[2..4].copy_from_slice(&0u16.to_ne_bytes());
    req.union[4..8].copy_from_slice(&address.octets());

    // SAFETY: `req` is a correctly-shaped `ifreq` and `socket` is open.
    if unsafe { libc::ioctl(socket, request, &raw mut req) } < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

/// Set `IFF_UP | IFF_RUNNING`, preserving the flags already there.
fn bring_up(socket: libc::c_int, device: &str) -> anyhow::Result<()> {
    let mut req = IfReq::new(device)?;
    // SAFETY: `req` is a correctly-shaped `ifreq` and `socket` is open.
    if unsafe { libc::ioctl(socket, SIOCGIFFLAGS, &raw mut req) } < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let current = i16::from_ne_bytes([req.union[0], req.union[1]]);
    let up = i16::try_from(libc::IFF_UP | libc::IFF_RUNNING)
        .expect("IFF_UP | IFF_RUNNING fits in ifr_flags");
    let wanted = current | up;
    req.union[..2].copy_from_slice(&wanted.to_ne_bytes());

    // SAFETY: as above, with the flags field updated in place.
    if unsafe { libc::ioctl(socket, SIOCSIFFLAGS, &raw mut req) } < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

/// The dotted-quad netmask for a prefix length.
fn netmask(prefix_len: u32) -> std::net::Ipv4Addr {
    let bits = if prefix_len == 0 {
        0
    } else {
        u32::MAX << (32 - prefix_len)
    };
    std::net::Ipv4Addr::from(bits)
}

/// `OwnedFd::from_raw_fd` with the safety precondition spelled out at the
/// single place it is used.
trait FromRawFdChecked {
    /// # Safety
    /// `fd` must be an open descriptor that nothing else owns.
    unsafe fn from_raw_fd_checked(fd: libc::c_int) -> Self;
}

impl FromRawFdChecked for OwnedFd {
    unsafe fn from_raw_fd_checked(fd: libc::c_int) -> Self {
        use std::os::fd::FromRawFd as _;
        // SAFETY: guaranteed by this function's own contract.
        unsafe { Self::from_raw_fd(fd) }
    }
}
