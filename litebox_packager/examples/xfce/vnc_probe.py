#!/usr/bin/env python3
"""Minimal RFB (VNC) liveness probe for watch-desktop.sh.

No third-party dependencies (pure stdlib socket), because vncdotool/xdotool
are not guaranteed to be installed on the host running the watchdog. Speaks
just enough of RFB 3.3-3.8 (server-chosen version, no-auth or VNC-auth-less
setups only -- litebox's --vnc server requires no password) to:

  1. Request an incremental FramebufferUpdate over one fixed pixel region
     and return a hash of that region's pixel bytes.
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
import time


def recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("RFB connection closed early")
        buf += chunk
    return bytes(buf)


def rfb_handshake(sock: socket.socket) -> tuple[int, int, int]:
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

    # ClientInit: shared session so the probe does not disconnect a real viewer.
    sock.sendall(bytes([1]))

    # ServerInit: width(2) height(2) pixel-format(16) name-length(4) name(...)
    fixed = recv_exact(sock, 2 + 2 + 16 + 4)
    framebuffer_width, framebuffer_height = struct.unpack(">HH", fixed[:4])
    bits_per_pixel = fixed[4]
    if bits_per_pixel == 0 or bits_per_pixel % 8 != 0:
        raise ConnectionError(f"unsupported bits-per-pixel {bits_per_pixel}")
    name_len = struct.unpack(">I", fixed[20:24])[0]
    recv_exact(sock, name_len)
    return framebuffer_width, framebuffer_height, bits_per_pixel // 8


def send_pointer_event(sock: socket.socket, x: int, y: int, button_mask: int) -> None:
    # message-type(1)=5, button-mask(1), x(2), y(2)
    sock.sendall(struct.pack(">BBHH", 5, button_mask, x, y))


def request_framebuffer_region(
    sock: socket.socket,
    x: int,
    y: int,
    w: int,
    h: int,
    bytes_per_pixel: int,
    timeout: float,
) -> bytes:
    # FramebufferUpdateRequest: type(1)=3, incremental(1)=0, x(2) y(2) w(2) h(2)
    sock.sendall(struct.pack(">BBHHHH", 3, 0, x, y, w, h))

    sock.settimeout(timeout)
    msg_type = recv_exact(sock, 1)[0]
    if msg_type != 0:
        raise ConnectionError(f"expected FramebufferUpdate(0), got {msg_type}")
    recv_exact(sock, 1)  # padding
    num_rects = struct.unpack(">H", recv_exact(sock, 2))[0]

    # Servers may legally return rectangles larger than the requested region. LiteBox currently
    # returns the whole framebuffer, so crop each raw rectangle by its response coordinates rather
    # than hashing cursor movement or unrelated repaints elsewhere on screen.
    pixels = bytearray(w * h * bytes_per_pixel)
    covered = bytearray(w * h)
    for _ in range(num_rects):
        hdr = recv_exact(sock, 12)  # x,y,w,h,encoding
        rx, ry, rw, rh, encoding = struct.unpack(">HHHHi", hdr)
        if encoding != 0:
            raise ConnectionError(f"unsupported encoding {encoding} (want Raw=0)")
        rect_bytes = recv_exact(sock, rw * rh * bytes_per_pixel)

        left = max(x, rx)
        top = max(y, ry)
        right = min(x + w, rx + rw)
        bottom = min(y + h, ry + rh)
        if left >= right or top >= bottom:
            continue

        copy_width = right - left
        copy_bytes = copy_width * bytes_per_pixel
        for row in range(top, bottom):
            src = ((row - ry) * rw + left - rx) * bytes_per_pixel
            dst = ((row - y) * w + left - x) * bytes_per_pixel
            pixels[dst : dst + copy_bytes] = rect_bytes[src : src + copy_bytes]
            coverage_row = (row - y) * w + left - x
            covered[coverage_row : coverage_row + copy_width] = b"\x01" * copy_width

    if not all(covered):
        missing = covered.count(0)
        raise ConnectionError(
            f"FramebufferUpdate did not cover requested region ({missing} pixels missing)"
        )
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
            framebuffer_width, framebuffer_height, bytes_per_pixel = rfb_handshake(sock)
            if (
                args.x < 0
                or args.y < 0
                or args.w <= 0
                or args.h <= 0
                or args.x + args.w > framebuffer_width
                or args.y + args.h > framebuffer_height
            ):
                raise ValueError(
                    f"region {args.x},{args.y} {args.w}x{args.h} exceeds "
                    f"framebuffer {framebuffer_width}x{framebuffer_height}"
                )
            if args.click is not None:
                cx, cy = args.click
                if not (0 <= cx < framebuffer_width and 0 <= cy < framebuffer_height):
                    raise ValueError(
                        f"click {cx},{cy} exceeds framebuffer "
                        f"{framebuffer_width}x{framebuffer_height}"
                    )
                send_pointer_event(sock, cx, cy, button_mask=1)  # press
                time.sleep(0.05)
                send_pointer_event(sock, cx, cy, button_mask=0)  # release
            pixels = request_framebuffer_region(
                sock,
                args.x,
                args.y,
                args.w,
                args.h,
                bytes_per_pixel,
                args.timeout,
            )
    except (OSError, ConnectionError, ValueError, struct.error) as exc:
        print(f"ERROR {exc}", file=sys.stderr)
        return 1

    print(f"HASH {hashlib.sha256(pixels).hexdigest()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
