#!/usr/bin/env python3
"""Minimal RFB (VNC) liveness probe for watch-desktop.sh.

No third-party dependencies (pure stdlib socket), because vncdotool/xdotool
are not guaranteed to be installed on the host running the watchdog. Speaks
just enough of RFB 3.3-3.8 (server-chosen version, no-auth or VNC-auth-less
setups only -- litebox's --vnc server requires no password) to:

  1. Request an incremental FramebufferUpdate over one fixed pixel region
     and return a hash of that region's pixel bytes (`hash`), or write the
     region out as a PNG (`png --out FILE`) so a human or an image-reading
     tool can look at what the guest actually painted.
  2. Optionally send synthetic input first: PointerEvents (`--move X Y`,
     `--click X Y`, `--drag X1 Y1 X2 Y2 [STEPS]`, `--wheel-up X Y [TICKS]`,
     `--wheel-down X Y [TICKS]`) and KeyEvents (`--key KEYSYM ...`,
     `--chord MOD [MOD...] KEY`, `--ctrl KEY`, `--key-hold KEYSYM SECS`,
     `--type TEXT`), in a fixed order, so one invocation can drive a small
     interaction and then capture its result.

Exit code 0 with a hash line on stdout means the round trip completed within
the timeout. Exit code 1 means the RFB session itself failed or timed out --
that alone is a strong freeze signal (see watch-desktop.sh) since litebox's
own VNC server thread answering FramebufferUpdateRequest is independent of
whatever guest-side X11 client is stuck.

Usage:
    vnc_probe.py hash HOST PORT X Y W H [input options] [--timeout SECS]
    vnc_probe.py png  HOST PORT X Y W H --out FILE [input options] [--timeout SECS]

Input options (applied before the capture, in this fixed order):
    --move X Y                 pointer motion, no buttons
    --click X Y                left button press+release at X Y
    --drag X1 Y1 X2 Y2 [STEPS] press at X1,Y1, move through STEPS
                                interpolated points (default 10) to X2,Y2
                                with the button held, then release
    --wheel-up X Y [TICKS]     scroll wheel up TICKS times (default 3) at X Y
    --wheel-down X Y [TICKS]   scroll wheel down TICKS times (default 3) at X Y
    --chord MOD [MOD...] KEY   hold each MOD keysym, tap KEY, release MODs
                                in reverse order (e.g. --chord Control_L
                                Shift_L t, or --chord Alt_L Tab)
    --ctrl KEY                 convenience alias for --chord Control_L KEY
    --key KEYSYM [...]         X11 keysyms, each pressed then released in
                                turn; a keysym may be given as a name from
                                the small table below, a single character,
                                or hex (0xff0d)
    --key-hold KEYSYM SECS     press KEYSYM, hold for SECS, then release --
                                for held-key acceptance scenarios distinct
                                from a quick tap
    --type TEXT                each printable ASCII character of TEXT as a
                                key tap
    --hold SECS                down/up hold duration used by --key, --chord,
                                --ctrl and --type taps (default 0.03)
    --settle SECS               wait after the last input before capturing
                                (default 1.0)

`hash` prints one line "HASH <hex>" on success; `png` prints "PNG <file> WxH".
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


# RFC 6143 button-mask bits: bit 3 = button 4 (wheel up), bit 4 = button 5 (wheel down).
WHEEL_UP_BIT = 1 << 3
WHEEL_DOWN_BIT = 1 << 4


def send_wheel_event(sock: socket.socket, x: int, y: int, button_bit: int, ticks: int) -> None:
    send_pointer_event(sock, x, y, button_mask=0)  # move there first
    time.sleep(0.05)
    for _ in range(ticks):
        send_pointer_event(sock, x, y, button_mask=button_bit)
        time.sleep(0.03)
        send_pointer_event(sock, x, y, button_mask=0)
        time.sleep(0.03)


def drag(
    sock: socket.socket, x1: int, y1: int, x2: int, y2: int, steps: int, button_mask: int = 1
) -> None:
    send_pointer_event(sock, x1, y1, button_mask=0)
    time.sleep(0.05)
    send_pointer_event(sock, x1, y1, button_mask=button_mask)
    time.sleep(0.05)
    for i in range(1, steps + 1):
        t = i / steps
        send_pointer_event(sock, round(x1 + (x2 - x1) * t), round(y1 + (y2 - y1) * t), button_mask=button_mask)
        time.sleep(0.02)
    send_pointer_event(sock, x2, y2, button_mask=button_mask)
    time.sleep(0.05)
    send_pointer_event(sock, x2, y2, button_mask=0)


KEYSYM_NAMES = {
    "Return": 0xFF0D, "Enter": 0xFF0D, "Tab": 0xFF09, "Escape": 0xFF1B, "BackSpace": 0xFF08,
    "Delete": 0xFFFF, "Home": 0xFF50, "End": 0xFF57, "Left": 0xFF51, "Up": 0xFF52,
    "Right": 0xFF53, "Down": 0xFF54, "Page_Up": 0xFF55, "Page_Down": 0xFF56,
    "F1": 0xFFBE, "F5": 0xFFC2, "F11": 0xFFC8, "F12": 0xFFC9, "space": 0x20,
    "Shift_L": 0xFFE1, "Control_L": 0xFFE3, "Alt_L": 0xFFE9, "Super_L": 0xFFEB,
}


def parse_keysym(token: str) -> int:
    if token in KEYSYM_NAMES:
        return KEYSYM_NAMES[token]
    if token.lower().startswith("0x"):
        return int(token, 16)
    if len(token) == 1:
        return ord(token)
    raise ValueError(f"unknown keysym {token!r}")


def send_key_event(sock: socket.socket, keysym: int, down: bool) -> None:
    # message-type(1)=4, down-flag(1), padding(2), keysym(4)
    sock.sendall(struct.pack(">BBxxI", 4, 1 if down else 0, keysym))


def send_key_hold(sock: socket.socket, keysym: int, secs: float) -> None:
    send_key_event(sock, keysym, True)
    time.sleep(secs)
    send_key_event(sock, keysym, False)


def tap_keys(sock: socket.socket, keysyms: list[int], hold: float = 0.03) -> None:
    for keysym in keysyms:
        send_key_event(sock, keysym, True)
        time.sleep(hold)
        send_key_event(sock, keysym, False)
        time.sleep(hold)


def chord(sock: socket.socket, modifiers: list[int], keysym: int, hold: float = 0.03) -> None:
    """Hold `modifiers`, tap `keysym`, release the modifiers (e.g. Control_L + l)."""
    for m in modifiers:
        send_key_event(sock, m, True)
    time.sleep(hold)
    send_key_event(sock, keysym, True)
    time.sleep(hold)
    send_key_event(sock, keysym, False)
    for m in reversed(modifiers):
        send_key_event(sock, m, False)
    time.sleep(hold)


def write_png(path: str, pixels: bytes, w: int, h: int, bytes_per_pixel: int) -> None:
    """Raw RFB pixels (litebox sends 32 bpp BGRX little-endian) to an RGB PNG, stdlib only."""
    import zlib

    rows = bytearray()
    for y in range(h):
        rows.append(0)  # filter type: none
        row = pixels[y * w * bytes_per_pixel : (y + 1) * w * bytes_per_pixel]
        if bytes_per_pixel == 4:
            for x in range(w):
                b, g, r = row[x * 4], row[x * 4 + 1], row[x * 4 + 2]
                rows += bytes((r, g, b))
        elif bytes_per_pixel == 2:
            for x in range(w):
                v = row[x * 2] | (row[x * 2 + 1] << 8)
                rows += bytes((((v >> 11) & 0x1F) << 3, ((v >> 5) & 0x3F) << 2, (v & 0x1F) << 3))
        else:
            for x in range(w):
                rows += bytes((row[x], row[x], row[x]))

    def chunk(tag: bytes, data: bytes) -> bytes:
        return (
            struct.pack(">I", len(data))
            + tag
            + data
            + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)
        )

    png = b"\x89PNG\r\n\x1a\n"
    png += chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0))
    png += chunk(b"IDAT", zlib.compress(bytes(rows), 6))
    png += chunk(b"IEND", b"")
    with open(path, "wb") as f:
        f.write(png)


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
    parser.add_argument("mode", choices=["hash", "png"])
    parser.add_argument("host")
    parser.add_argument("port", type=int)
    parser.add_argument("x", type=int)
    parser.add_argument("y", type=int)
    parser.add_argument("w", type=int)
    parser.add_argument("h", type=int)
    parser.add_argument("--move", nargs=2, type=int, metavar=("X", "Y"), default=None)
    parser.add_argument("--click", nargs=2, type=int, metavar=("X", "Y"), default=None)
    parser.add_argument("--drag", nargs="+", type=int, metavar="X1 Y1 X2 Y2 [STEPS]", default=None)
    parser.add_argument("--wheel-up", nargs="+", type=int, metavar="X Y [TICKS]", default=None)
    parser.add_argument("--wheel-down", nargs="+", type=int, metavar="X Y [TICKS]", default=None)
    parser.add_argument("--chord", nargs="+", metavar="MOD [MOD...] KEY", default=None)
    parser.add_argument("--key", nargs="+", metavar="KEYSYM", default=None)
    parser.add_argument("--ctrl", metavar="KEY", default=None, help="Control_L chord with KEY")
    parser.add_argument("--key-hold", nargs=2, metavar=("KEYSYM", "SECS"), default=None)
    parser.add_argument("--type", dest="type_text", metavar="TEXT", default=None)
    parser.add_argument("--hold", type=float, default=0.03, help="down/up hold duration for key taps/chords")
    parser.add_argument("--settle", type=float, default=1.0)
    parser.add_argument("--out", default=None, help="png mode: output file")
    parser.add_argument("--timeout", type=float, default=4.0)
    args = parser.parse_args()
    if args.mode == "png" and not args.out:
        parser.error("png mode requires --out FILE")

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
            sent_input = False
            if args.move is not None:
                mx, my = args.move
                send_pointer_event(sock, mx, my, button_mask=0)
                sent_input = True
            if args.click is not None:
                cx, cy = args.click
                if not (0 <= cx < framebuffer_width and 0 <= cy < framebuffer_height):
                    raise ValueError(
                        f"click {cx},{cy} exceeds framebuffer "
                        f"{framebuffer_width}x{framebuffer_height}"
                    )
                send_pointer_event(sock, cx, cy, button_mask=0)  # move there first
                time.sleep(0.05)
                send_pointer_event(sock, cx, cy, button_mask=1)  # press
                time.sleep(0.05)
                send_pointer_event(sock, cx, cy, button_mask=0)  # release
                sent_input = True
            if args.drag is not None:
                if len(args.drag) not in (4, 5):
                    parser.error("--drag takes X1 Y1 X2 Y2 [STEPS]")
                dx1, dy1, dx2, dy2 = args.drag[:4]
                steps = args.drag[4] if len(args.drag) == 5 else 10
                for dx, dy in ((dx1, dy1), (dx2, dy2)):
                    if not (0 <= dx < framebuffer_width and 0 <= dy < framebuffer_height):
                        raise ValueError(
                            f"drag point {dx},{dy} exceeds framebuffer "
                            f"{framebuffer_width}x{framebuffer_height}"
                        )
                drag(sock, dx1, dy1, dx2, dy2, steps)
                sent_input = True
            if args.wheel_up is not None:
                if len(args.wheel_up) not in (2, 3):
                    parser.error("--wheel-up takes X Y [TICKS]")
                wx, wy = args.wheel_up[0], args.wheel_up[1]
                ticks = args.wheel_up[2] if len(args.wheel_up) == 3 else 3
                if not (0 <= wx < framebuffer_width and 0 <= wy < framebuffer_height):
                    raise ValueError(
                        f"wheel-up {wx},{wy} exceeds framebuffer "
                        f"{framebuffer_width}x{framebuffer_height}"
                    )
                send_wheel_event(sock, wx, wy, WHEEL_UP_BIT, ticks)
                sent_input = True
            if args.wheel_down is not None:
                if len(args.wheel_down) not in (2, 3):
                    parser.error("--wheel-down takes X Y [TICKS]")
                wx, wy = args.wheel_down[0], args.wheel_down[1]
                ticks = args.wheel_down[2] if len(args.wheel_down) == 3 else 3
                if not (0 <= wx < framebuffer_width and 0 <= wy < framebuffer_height):
                    raise ValueError(
                        f"wheel-down {wx},{wy} exceeds framebuffer "
                        f"{framebuffer_width}x{framebuffer_height}"
                    )
                send_wheel_event(sock, wx, wy, WHEEL_DOWN_BIT, ticks)
                sent_input = True
            if args.chord is not None:
                if len(args.chord) < 2:
                    parser.error("--chord takes MOD [MOD...] KEY")
                *mod_tokens, key_token = args.chord
                chord(sock, [parse_keysym(m) for m in mod_tokens], parse_keysym(key_token), hold=args.hold)
                sent_input = True
            if args.ctrl is not None:
                chord(sock, [KEYSYM_NAMES["Control_L"]], parse_keysym(args.ctrl), hold=args.hold)
                sent_input = True
            if args.key is not None:
                tap_keys(sock, [parse_keysym(k) for k in args.key], hold=args.hold)
                sent_input = True
            if args.key_hold is not None:
                keysym_token, secs_token = args.key_hold
                send_key_hold(sock, parse_keysym(keysym_token), float(secs_token))
                sent_input = True
            if args.type_text is not None:
                shifted = {
                    "!": "1", "@": "2", "#": "3", "$": "4", "%": "5",
                    "^": "6", "&": "7", "*": "8", "(": "9", ")": "0",
                    "_": "-", "+": "=", "{": "[", "}": "]", "|": "\\",
                    ":": ";", '"': "'", "<": ",", ">": ".", "?": "/",
                }
                for ch in args.type_text:
                    if not (0x20 <= ord(ch) < 0x7F):
                        raise ValueError(f"--type only takes printable ASCII, got {ch!r}")
                    if ch.isupper():
                        chord(sock, [KEYSYM_NAMES["Shift_L"]], ord(ch.lower()), hold=args.hold)
                    elif ch in shifted:
                        chord(sock, [KEYSYM_NAMES["Shift_L"]], ord(shifted[ch]), hold=args.hold)
                    else:
                        tap_keys(sock, [ord(ch)], hold=args.hold)
                sent_input = True
            if sent_input:
                time.sleep(args.settle)
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

    if args.mode == "png":
        write_png(args.out, pixels, args.w, args.h, bytes_per_pixel)
        print(f"PNG {args.out} {args.w}x{args.h}")
        return 0
    print(f"HASH {hashlib.sha256(pixels).hexdigest()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
