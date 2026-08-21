# Multi-Box X11 Composition Example

This example demonstrates how to use boxer's multi-box composition capability with the new `--net-guest-ip` and `--net-host-ip` flags to run networked desktop-class workloads like X11 display servers and clients across multiple boxes on separate subnets.

## Motivation

Before the introduction of `--net-guest-ip` and `--net-host-ip`, every box ran with the same hardcoded network configuration:
- Guest interface IP: 10.0.0.2
- Gateway IP: 10.0.0.1

This meant two boxes on different TUN devices could not directly address each other—they both thought they were at the same IP address and had the same gateway.

The new flags allow each box to have its own distinct subnet, enabling direct box-to-box communication necessary for multi-process desktop-class workloads like:
- X11 display server + X11 client applications
- Wayland display server + Wayland applications
- VNC server + VNC clients

## Architecture

```
Host Machine
├── TUN device tun98 (10.0.1.1 gateway)
│   └── X11 Server Box (10.0.1.2)
│       └── Xvfb :0 (listening on TCP port 6000)
│
└── TUN device tun99 (10.0.2.1 gateway)
    └── X11 Client Box (10.0.2.2)
        └── xeyes (connecting to 10.0.1.2:6000)
```

X11 Protocol Flow:
1. X11 client (xeyes) resolves DISPLAY=10.0.1.2:0 to TCP port 6000
2. Establishes connection to 10.0.1.2:6000
3. Host's routing table bridges the TUN devices
4. X11 server (Xvfb) accepts the connection on port 6000
5. Client and server communicate over the established TCP connection

## Prerequisites

1. **boxer** binary with `--net-guest-ip` and `--net-host-ip` support
2. **tun-setup.sh** script (installed with boxer)
3. **Docker** for building container images
4. **Linux with TUN support** (most modern distributions)
5. **Root/sudo access** (required for TUN device management)

## Quick Start

### 1. Prepare TUN Devices

```bash
# Create server TUN device (10.0.1.1 gateway)
sudo tun-setup.sh -t tun98 -i 10.0.1.1

# Create client TUN device (10.0.2.1 gateway)
sudo tun-setup.sh -t tun99 -i 10.0.2.1

# Verify
ip link show tun98 tun99
ip addr show tun98 tun99
```

### 2. Build Docker Images

```bash
cd examples/multibox-x11-composition
docker build -f Dockerfile.x11-server -t multibox-x11-server .
docker build -f Dockerfile.x11-client -t multibox-x11-client .
```

### 3. Run the Composition

Terminal 1 - Start X11 Server Box:
```bash
sudo boxer \
  --net tun98 \
  --net-guest-ip 10.0.1.2 \
  --net-host-ip 10.0.1.1 \
  docker run \
    --rm \
    multibox-x11-server
```

Terminal 2 - Start X11 Client Box (after server is ready):
```bash
sleep 2  # Give server time to initialize

sudo boxer \
  --net tun99 \
  --net-guest-ip 10.0.2.2 \
  --net-host-ip 10.0.2.1 \
  docker run \
    --rm \
    -e DISPLAY=10.0.1.2:0 \
    multibox-x11-client
```

Terminal 1 should see:
```
Server listening on display :0 (TCP port 6000)
```

Terminal 2 should see:
```
X11 client starting, connecting to remote display: 10.0.1.2:0
Client connected successfully
```

## How It Works

### Addressing and Routing

- **Server box**: Uses subnet 10.0.1.0/24 (interface IP 10.0.1.2, gateway 10.0.1.1)
- **Client box**: Uses subnet 10.0.2.0/24 (interface IP 10.0.2.2, gateway 10.0.2.1)
- **Host routing**: Each box's TUN device is configured on the host with the respective subnet
- **Guest routing**: Without the new flags, each guest would only know about 10.0.0.0/24, preventing cross-subnet communication

With `--net-guest-ip` and `--net-host-ip`, the guest's routing table is configured correctly:
- Server guest: knows about 10.0.1.0/24, routes to 10.0.1.1
- Client guest: knows about 10.0.2.0/24, routes to 10.0.2.1

### X11 Protocol Details

X11 clients connect to a server using the `DISPLAY` environment variable:
- Format: `[hostname]:displaynumber[.screennumber]`
- Default protocol: UNIX socket for local connections
- Network protocol: TCP to port 6000 + displaynumber for remote connections
- Example: `DISPLAY=10.0.1.2:0` means:
  - Connect to host 10.0.1.2 via TCP
  - Port: 6000 + 0 = 6000
  - This is exactly what the X11 client library does

## Troubleshooting

### Connection Refused

If the client box cannot connect to the server:
1. Verify TUN devices are up: `ip link show tun98 tun99`
2. Verify addresses are configured: `ip addr show tun98 tun99`
3. Test connectivity from host: `ping -I tun98 10.0.1.2` (should work via the server box's routing)
4. Check server logs for startup errors

### Server Not Starting

If the server box doesn't start:
1. Ensure the TUN device exists and is up
2. Check that the host gateway address (10.0.1.1) doesn't conflict with existing network configuration
3. Verify Docker image built correctly: `docker images | grep multibox`

### Client Can't Find Server

If the client starts but can't connect:
1. Verify the DISPLAY environment variable is set correctly: `echo $DISPLAY`
2. Check that the server box is still running
3. Try connecting from client box shell: `nc -zv 10.0.1.2 6000`
4. Check if the host's routing table has routes for both subnets

## Advanced: Multiple Clients

To run multiple client boxes connecting to the same server:

```bash
for i in {2..4}; do
  TUN="tun$((98+i))"
  IP="10.0.$((1+i))"
  
  sudo tun-setup.sh -t "$TUN" -i "${IP}.1"
  
  sudo boxer \
    --net "$TUN" \
    --net-guest-ip "${IP}.2" \
    --net-host-ip "${IP}.1" \
    docker run --rm -e DISPLAY=10.0.1.2:0 multibox-x11-client &
done
```

## Files

- **Dockerfile.x11-server**: Container image for X11 server (Xvfb)
- **Dockerfile.x11-client**: Container image for X11 client (xeyes)
- **run.sh**: Convenience script for setup and launching

## Related

- `docs/boxer.md`: Documentation of `--net-host-ip` and `--net-guest-ip` flags
- `docs/roadmap.md`: Section describing the multi-box composition limitation and fix
- `litebox/src/net/tests.rs`: Unit test verifying the addressing functionality
