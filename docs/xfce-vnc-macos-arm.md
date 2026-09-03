# XFCE + VNC + Multi-Boxer on macOS ARM

## Overview

This document describes how to run XFCE desktop + VNC server + X11 client applications on macOS ARM using litebox boxer containers.

## Architecture

The system uses a 3-box composition:

```
Host (macOS ARM)
    |
    +-- [Port 5900 VNC] 
    |
    +-- VNC Bridge Box (10.90.2.2)
         |
         +-- TCP:6000 ---> X11 Server Box (10.90.0.2)
                               |
                               +-- TCP:6000 <--- App Box (10.90.1.2)
```

### Components

1. **X11 Server Box** - Minimal X11 protocol server
   - Listens on TCP port 6000 (DISPLAY=:0)
   - Implements X11 core protocol (CreateGC, PolyFillRectangle, GetImage)
   - Maintains in-memory framebuffer (configurable resolution)
   - Can run XFCE window manager or minimal X11 server

2. **VNC Bridge Box** - RFB 3.8 VNC server
   - Connects to X11 server via TCP port 6000
   - Pulls framebuffer via X11 GetImage requests
   - Serves RFB 3.8 protocol on TCP port 5900
   - Publishes port 5900 to host for external VNC clients

3. **App Box(es)** - X11 client applications
   - Connect to X11 server via TCP DISPLAY variable
   - Can run XFCE, xclock, xterm, or any X11 app
   - Multiple app boxes can connect to same X11 server
   - Each runs in isolated boxer container

## Why TCP-based X11 (not Unix sockets)?

Traditional X11 uses Unix domain sockets in `/tmp/.X11-unix/`. LiteBox on macOS has constraints:

- Guest filesystem `/tmp` is isolated (can't share `/tmp/.X11-unix` with host)
- W^X (Write-XOR-Execute) enforcement requires special handling for JIT code
- No `link()`, `symlink()`, `rename()` syscalls available in guest
- Xvfb fails because it uses `link()` for PID locks and requires root (`getuid() == 0`)

**Solution**: Use TCP-based X11 protocol instead. Leverages existing litebox inter-box networking:
- Each box gets its own TUN subnet (e.g., 10.90.0.0/24, 10.90.1.0/24)
- TCP connections routed over host kernel TUN devices
- No Unix sockets needed
- Scales to multiple app boxes connecting to same X11 server

## Composition Configuration

Example `compose.json`, matching the actual `boxer compose` schema
(`InstanceConfig` in `boxer/src/compose.rs`) and the real, tested config at
`examples/multibox-x11-composition/compose.json`:

```json
{
  "instances": [
    {
      "name": "x11server",
      "box": "images/x11server.box.wasm",
      "net_host_ip": "10.90.0.1",
      "net_guest_ip": "10.90.0.2",
      "tun_device": "utun90",
      "env": { "BIND_IP": "${x11server.guest_ip}" }
    },
    {
      "name": "app",
      "box": "images/app.box.wasm",
      "net_host_ip": "10.90.1.1",
      "net_guest_ip": "10.90.1.2",
      "tun_device": "utun91",
      "depends_on": ["x11server"],
      "env": { "DISPLAY": "${x11server.guest_ip}:0" }
    },
    {
      "name": "vncbridge",
      "box": "images/vncbridge.box.wasm",
      "net_host_ip": "10.90.2.1",
      "net_guest_ip": "10.90.2.2",
      "tun_device": "utun92",
      "depends_on": ["x11server"],
      "env": {
        "DISPLAY": "${x11server.guest_ip}:0",
        "BIND_IP": "${vncbridge.guest_ip}"
      },
      "publish": ["5900:5900"]
    }
  ]
}
```

`tun_device` is optional (auto-derived as `utun9<n>` if omitted), but note
the naming constraint: Linux's `ip tuntap` accepts any name, while macOS's
`utun` interfaces only ever exist as `utun<unit>` (see
`litebox_platform_macos_userland::net`) -- `utun90`/`utun91`/`utun92` here
satisfies both, so the same config runs unmodified on either host.

### Environment Variable Templating

- `${x11server.guest_ip}` - Automatically substituted with X11 server's guest IP
- `${service_name.guest_ip}` - Works for any service
- Used in `DISPLAY`, `X11_HOST`, etc.

## Building Boxes

### 1. X11 Server Box

Dockerfile (minimal):
```dockerfile
FROM alpine:latest
RUN apk add --no-cache gcc musl-dev
COPY x11_server /usr/local/bin/
ENTRYPOINT ["/usr/local/bin/x11_server"]
```

Build:
```bash
cargo build --release --target x86_64-unknown-linux-musl -p x11_server
cd /path/to/dockerfile
docker build -t x11server .
boxer build -o x11server.box.wasm -f Dockerfile
```

### 2. VNC Bridge Box

```dockerfile
FROM alpine:latest
COPY vnc_bridge /usr/local/bin/
ENTRYPOINT ["/usr/local/bin/vnc_bridge"]
```

Build:
```bash
cargo build --release --target x86_64-unknown-linux-musl -p vnc_bridge
docker build -t vncbridge .
boxer build -o vncbridge.box.wasm -f Dockerfile
```

### 3. App Box (XFCE or X11 clients)

```dockerfile
FROM alpine:latest
RUN apk add --no-cache xfce4-session xfce4-panel xfce4-terminal
ENTRYPOINT ["startxfce4"]
```

Or for X11 apps:
```dockerfile
FROM alpine:latest
RUN apk add --no-cache x11-apps # xclock, xterm, etc
ENTRYPOINT ["xclock", "-display", "${DISPLAY}"]
```

## Running the Composition

Two macOS-specific prerequisites, both easy to miss because each fails deep
inside a spawned instance rather than at the compose command itself:

```bash
# 1. Sign for MAP_JIT. Apple Silicon refuses executable guest mappings unless
#    the binary carries com.apple.security.cs.allow-jit, and `cargo build`
#    drops the signature -- so re-run this after every build. Without it the
#    guest dies with "Memory mapping error / EPERM". See docs/macos.md.
litebox_platform_macos_userland/scripts/codesign-jit.sh target/release/boxer

# 2. Run as root: creating a `utun` interface needs it, and without it the
#    guest dies with "failed to open utun90: Operation not permitted".
sudo ./target/release/boxer compose compose.json
```

This:
1. Starts x11server and waits for TCP:6000 to be accessible
2. Starts app and vncbridge (both depend on x11server)
3. Publishes port 5900 from vncbridge to host localhost:5900
4. Templating injects `DISPLAY=${x11server.guest_ip}:0` into app environment

## Accessing VNC

From macOS host:
```bash
# Option 1: VNC viewer (GUI)
open vnc://localhost:5900

# Option 2: Command line with Python RFB client
python3 -c "
import socket, time
s = socket.socket()
s.connect(('127.0.0.1', 5900))
print(s.recv(1024))  # RFB handshake
"
```

Expected RFB greeting:
```
RFB 003.008
```

## macOS ARM Specific Notes

### Platform Constraints

| Constraint | Solution |
|-----------|----------|
| 16 KiB pages | Platform layer handles (transparent) |
| W^X enforcement | Static binaries only (no JIT code) |
| Guest `/tmp` isolation | Use TCP, not Unix sockets |
| No fork() | Pre-start all services |
| Single guest thread per box | Use separate boxes for concurrent tasks |

### Capability status

The full composition (X11 server + app + VNC bridge, `boxer compose`) is
verified end-to-end on x86_64 Linux, the platform this was actually built
and tested against -- see `examples/multibox-x11-composition/README.md`.
The pieces specific to macOS ARM (native `boxer run`/`boxer compose`, guest
stdio forwarding, `utun` device creation and addressing) are implemented
and type-check against the real `aarch64-apple-darwin` target, but this
development environment has no macOS ARM hardware to run them on, so the
macOS-specific path itself is untested on real hardware. Treat "should
work" and "does work" as distinct until someone runs it on an actual Mac.

- [x] Direct aarch64 instruction execution (no emulation) -- implemented
- [x] Memory isolation via Mach VM -- implemented
- [x] `utun`-based inter-box networking, including IP address assignment --
      implemented (`litebox_platform_macos_userland::net::configure_utun_address`)
- [x] Port publishing from guest to host -- implemented (platform-agnostic,
      shared with the verified Linux path)
- [x] Environment variable injection -- implemented (shared with Linux)
- [x] Graceful startup/shutdown -- implemented (shared with Linux)
- [x] Multiple isolated instances simultaneously -- implemented
- [ ] Real-time pixel-level rendering over VNC on real macOS ARM hardware --
      verified on Linux only; not yet run on a Mac

### Known Limitations

- No fork() - each box is single-threaded
- No hardlinks/symlinks in guest filesystem
- Large TCP payloads (tens of KB) across two-hop routed connections can have gaps (workaround: chunk writes)
- Xvfb not supported (syscall gaps)
- Guest always runs as uid 1000 (non-root)

## Testing

### Quick Test

```bash
# 1. Build boxes
boxer build -o x11server.box.wasm -f Dockerfile.x11
boxer build -o app.box.wasm -f Dockerfile.app

# 2. Start composition
timeout 30 boxer compose compose.json &

# 3. Connect VNC (in another terminal)
python3 rfb_client_witness.py 127.0.0.1 5900

# Expected output:
# RFB end-to-end verified, real pixels from app box visible
# Pixel at center (80,60): R=0x11 G=0xcc B=0x66
```

### End-to-End Verification

The `examples/multibox-x11-composition/rfb_client_witness.py` script proves:
- RFB handshake succeeds
- Framebuffer updates received
- Pixel colors match expected values from rendering

This verifies:
1. X11 server rendering works
2. VNC bridge framebuffer capture works
3. Network routing between boxes works
4. Graphics data integrity maintained

## Troubleshooting

### VNC port not accessible

```bash
# Check if vncbridge box is running
ps aux | grep boxer

# Check if port is published
ss -tlnp | grep 5900

# Check vncbridge logs (if available)
```

### No framebuffer updates

```bash
# Verify X11 server is running and listening
nc -zv 127.0.0.1 6000  # Should succeed after 2-3 sec

# Verify app box has DISPLAY set
# Check app box logs for connection errors
```

### Mouse/keyboard not responding

Current VNC bridge implementation receives input but doesn't forward to X11 server. This is by design for initial verification. To add input:
1. Parse PointerEvent/KeyEvent messages in vnc_bridge.rs
2. Convert to X11 protocol events
3. Send to X11 server

## Further Reading

- LiteBox architecture: `/home/user/litebox/docs/boxer.md`
- Platform constraints: `/home/user/litebox/docs/macos.md`
- Example code: `/home/user/litebox/examples/multibox-x11-composition/`
- RFB 3.8 spec: https://tools.ietf.org/html/rfc6143

## Future Enhancements

1. **Input forwarding** - Mouse and keyboard events from VNC to X11
2. **Encodings** - Support RFB encodings beyond raw (ZRLE, tight) for bandwidth reduction
3. **Multiple clients** - Handle multiple simultaneous VNC connections
4. **Xvfb support** - Implement missing syscalls (link, symlink, rename) to run real Xvfb
5. **Hardware acceleration** - Extend graphics surface trait for GL/Vulkan rendering
6. **Clipboard** - Bi-directional clipboard sync via RFB ClientCutText/ServerCutText
