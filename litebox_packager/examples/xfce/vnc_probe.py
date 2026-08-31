#!/usr/bin/env python3
"""Minimal RFB (VNC) liveness probe for watch-desktop.sh.

No third-party dependencies (pure stdlib socket), because vncdotool/xdotool
are not guaranteed to be installed on the host running the watchdog. Speaks
just enough of RFB 3.3-3.8 (server-chosen version, no-auth or VNC-auth-less
setups only -- litebox's --vnc server requires no password) to:

  1. Request an incremental FramebufferUpdate over one fixed pixel region
     and return a hash of the returned pixel bytes.
  2. Optionally send a synthetic PointerEvent (button click or move) first.

Exit code 0 with a hash line on stdout means the round trip completed within
the timeout. Exit code 1 means the RFB session itself failed or timed out --
that alone is a strong freeze signal (see watch-desktop.sh) since litebox's
own VNC server thread answering FramebufferUpdateRequest is independent of
whatever guest-side X11 client is stuck.

Usage:
    vnc_probe.py hash HOST PORT X Y W H [--click X Y] [--timeout SECS]

Prints one line "HASH <hex>" on success.
"""

import argparse
import hashlib
import socket
import struct
import sys


def recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("RFB connection closed early")
        buf += chunk
    return bytes(buf)


def rfb_handshake(sock: socket.socket) -> None:
    # ProtocolVersion: server sends "RFB 00x.00y\n" (12 bytes).
    server_version = recv_exact(sock, 12)
    if not server_version.startswith(b"RFB "):
        raise ConnectionError(f"unexpected RFB greeting: {server_version!r}")
    # Echo back the same version litebox_rfb advertises.
    sock.sendall(server_version)

    # Security handshake. RFB 3.7+ sends a list of security types; 3.3 sends
    # a single 4-byte type directly. litebox's --vnc has no password, so we
    # only need to accept "None" (type 1).
    if server_version[:11] in (b"RFB 003.003", b"RFB 003.003\n"[:11]):
        sec_type = struct.unpack(">I", recv_exact(sock, 4))[0]
        if sec_type == 0:
            raise ConnectionError("RFB server refused connection")
    else:
        num_types = recv_exact(sock, 1)[0]
        if num_types == 0:
            # Server sends a failure reason string instead.
            reason_len = struct.unpack(">I", recv_exact(sock, 4))[0]
            reason = recv_exact(sock, reason_len)
            raise ConnectionError(f"RFB security failure: {reason!r}")
        types = recv_exact(sock, num_types)
        if 1 not in types:
            raise ConnectionError(f"no None auth offered, got {list(types)}")
        sock.sendall(bytes([1]))  # choose "None"
        # RFB 3.8 sends a SecurityResult after this; 3.7 does not.
        if server_version.rstrip(b"\n") != b"RFB 003.007":
            result = struct.unpack(">I", recv_exact(sock, 4))[0]
            if result != 0:
                reason_len = struct.unpack(">I", recv_exact(sock, 4))[0]
                reason = recv_exact(sock, reason_len)
                raise ConnectionError(f"RFB auth failed: {reason!r}")

    # ClientInit: non-shared (exclusive) so we don't disturb the real VNC
    # viewer's session state any more than a synthetic click already does.
    sock.sendall(bytes([1]))

    # ServerInit: width(2) height(2) pixel-format(16) name-length(4) name(...)
    fixed = recv_exact(sock, 2 + 2 + 16 + 4)
    name_len = struct.unpack(">I", fixed[20:24])[0]
    recv_exact(sock, name_len)


def send_pointer_event(sock: socket.socket, x: int, y: int, button_mask: int) -> None:
    # message-type(1)=5, button-mask(1), x(2), y(2)
    sock.sendall(struct.pack(">BBHH", 5, button_mask, x, y))


def request_framebuffer_region(
    sock: socket.socket, x: int, y: int, w: int, h: int, timeout: float
) -> bytes:
    # FramebufferUpdateRequest: type(1)=3, incremental(1)=0, x(2) y(2) w(2) h(2)
    sock.sendall(struct.pack(">BBHHHH", 3, 0, x, y, w, h))

    sock.settimeout(timeout)
    msg_type = recv_exact(sock, 1)[0]
    if msg_type != 0:
        raise ConnectionError(f"expected FramebufferUpdate(0), got {msg_type}")
    recv_exact(sock, 1)  # padding
    num_rects = struct.unpack(">H", recv_exact(sock, 2))[0]

    pixels = bytearray()
    for _ in range(num_rects):
        hdr = recv_exact(sock, 12)  # x,y,w,h,encoding
        rw, rh, encoding = struct.unpack(">HHi", hdr[4:12])
        if encoding != 0:
            raise ConnectionError(f"unsupported encoding {encoding} (want Raw=0)")
        # litebox_rfb's ServerInit pixel-format is assumed 32bpp (bytes-per-pixel=4),
        # matching litebox_rfb's framebuffer adapter (RGBX/BGRX host framebuffer).
        rect_bytes = recv_exact(sock, rw * rh * 4)
        pixels += rect_bytes
    return bytes(pixels)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=["hash"])
    parser.add_argument("host")
    parser.add_argument("port", type=int)
    parser.add_argument("x", type=int)
    parser.add_argument("y", type=int)
    parser.add_argument("w", type=int)
    parser.add_argument("h", type=int)
    parser.add_argument("--click", nargs=2, type=int, metavar=("X", "Y"), default=None)
    parser.add_argument("--timeout", type=float, default=4.0)
    args = parser.parse_args()

    try:
        with socket.create_connection((args.host, args.port), timeout=args.timeout) as sock:
            sock.settimeout(args.timeout)
            rfb_handshake(sock)
            if args.click is not None:
                cx, cy = args.click
                send_pointer_event(sock, cx, cy, button_mask=1)  # press
                send_pointer_event(sock, cx, cy, button_mask=0)  # release
            pixels = request_framebuffer_region(
                sock, args.x, args.y, args.w, args.h, args.timeout
            )
    except (OSError, ConnectionError, struct.error) as exc:
        print(f"ERROR {exc}", file=sys.stderr)
        return 1

    print(f"HASH {hashlib.sha256(pixels).hexdigest()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
