// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Connection to the physical (i.e., "lower") side for networking.

// TODO(jayb): Do we need to wrap/unwrap the IPv4 header here, or is a better place within the
// implementer of the `platform::IPInterfaceProvider` trait?

use core::cell::RefCell;

use alloc::collections::VecDeque;
use alloc::vec::Vec;

use crate::platform;

/// The maximum transmission unit for a device
pub(crate) const DEVICE_MTU: usize = 1600;

/// Upper bound on packets held in the loopback queue. A guest that pushes more
/// than this into loopback faster than the interface drains it loses the
/// excess (TCP retransmits; UDP is lossy by contract), which is strictly
/// better than unbounded host-memory growth from a runaway guest.
const LOOPBACK_QUEUE_CAP: usize = 256;

pub(crate) struct Device<Platform: platform::IPInterfaceProvider + 'static> {
    pub(crate) platform: &'static Platform,
    receive_buffer: [u8; DEVICE_MTU],
    send_buffer: [u8; DEVICE_MTU],
    /// Packets the guest sent to a local interface address (`127.0.0.0/8`, or
    /// the interface's own IP), queued to be handed straight back to the same
    /// interface's receive path instead of out to the platform. This is the
    /// whole of loopback: one interface, one socket set, the real TCP state
    /// machine driving both ends. `RefCell` because a single `Device::receive`
    /// borrow hands out a `TxToken` (which may push here) and an `RxToken`
    /// (drained from here) together.
    loopback: RefCell<VecDeque<Vec<u8>>>,
}

impl<Platform: platform::IPInterfaceProvider> Device<Platform> {
    pub(crate) fn new(platform: &'static Platform) -> Self {
        Self {
            platform,
            receive_buffer: [0u8; DEVICE_MTU],
            send_buffer: [0u8; DEVICE_MTU],
            loopback: RefCell::new(VecDeque::new()),
        }
    }
}

/// Whether an IPv4 packet's destination address is one the interface loops
/// back to itself: any `127.0.0.0/8` address, or its own external IP (so a
/// guest connecting to its own `10.0.0.2` also reaches its local servers). A
/// malformed/short packet is not looped.
fn is_loopback_destination(packet: &[u8]) -> bool {
    // The IPv4 destination address is bytes 16..20; require at least an IPv4
    // header's worth of bytes and IP version 4.
    if packet.len() < 20 || packet[0] >> 4 != 4 {
        return false;
    }
    let dst = [packet[16], packet[17], packet[18], packet[19]];
    dst[0] == 127 || dst == super::INTERFACE_IP_ADDR.octets()
}

impl<Platform: platform::IPInterfaceProvider> smoltcp::phy::Device for Device<Platform> {
    type RxToken<'a>
        = RxToken<'a>
    where
        Self: 'a;
    type TxToken<'a>
        = TxToken<'a, Platform>
    where
        Self: 'a;

    fn receive(
        &mut self,
        _timestamp: smoltcp::time::Instant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        // Drain the loopback queue ahead of the platform: a busy external
        // device must never starve in-process loopback, and a looped packet is
        // always ready. The `TxToken` handed out alongside can push a reply
        // right back into the same queue within this `poll()`.
        let looped = self.loopback.borrow_mut().pop_front();
        if let Some(packet) = looped {
            return Some((
                RxToken::Owned(packet),
                TxToken {
                    platform: self.platform,
                    buffer: &mut self.send_buffer,
                    loopback: &self.loopback,
                },
            ));
        }
        match self.platform.receive_ip_packet(&mut self.receive_buffer) {
            Ok(size) => Some((
                RxToken::Borrowed(&self.receive_buffer[..size]),
                TxToken {
                    platform: self.platform,
                    buffer: &mut self.send_buffer,
                    loopback: &self.loopback,
                },
            )),
            Err(platform::ReceiveError::WouldBlock) => None,
        }
    }

    fn transmit(&mut self, _timestamp: smoltcp::time::Instant) -> Option<Self::TxToken<'_>> {
        Some(TxToken {
            platform: self.platform,
            buffer: &mut self.send_buffer,
            loopback: &self.loopback,
        })
    }

    fn capabilities(&self) -> smoltcp::phy::DeviceCapabilities {
        let mut caps = smoltcp::phy::DeviceCapabilities::default();
        caps.medium = smoltcp::phy::Medium::Ip;
        caps.max_transmission_unit = DEVICE_MTU;
        caps
    }
}

/// A received packet: either borrowed from the platform's receive buffer (the
/// external path, no copy) or owned from the loopback queue.
pub(crate) enum RxToken<'a> {
    Borrowed(&'a [u8]),
    Owned(Vec<u8>),
}

impl smoltcp::phy::RxToken for RxToken<'_> {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        match self {
            RxToken::Borrowed(buffer) => f(buffer),
            RxToken::Owned(packet) => f(&packet),
        }
    }
}

pub(crate) struct TxToken<'a, Platform: platform::IPInterfaceProvider> {
    platform: &'a Platform,
    buffer: &'a mut [u8],
    loopback: &'a RefCell<VecDeque<Vec<u8>>>,
}

impl<Platform: platform::IPInterfaceProvider> smoltcp::phy::TxToken for TxToken<'_, Platform> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let packet = &mut self.buffer[..len];
        let res = f(packet);
        if is_loopback_destination(packet) {
            // Loop it back into this interface's own receive path instead of
            // handing it to the platform. The copy is required: `buffer` is
            // the device's reused `send_buffer`.
            let mut queue = self.loopback.borrow_mut();
            if queue.len() < LOOPBACK_QUEUE_CAP {
                queue.push_back(packet.to_vec());
            }
            // Over the cap: drop, as a real loopback would under memory
            // pressure; TCP retransmits.
        } else {
            self.platform
                .send_ip_packet(packet)
                .expect("Sending IP packet failed");
        }
        res
    }
}
