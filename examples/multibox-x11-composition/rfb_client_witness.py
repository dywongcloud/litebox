#!/usr/bin/env python3
"""Hand-rolled RFB 3.8 client, used only to verify the demo VNC bridge end to
end. Connects, performs the real handshake, requests one framebuffer update,
and checks the drawn rectangle's color is actually present in the pixels
received over the wire.
"""
import socket
import struct
import sys

host, port = sys.argv[1], int(sys.argv[2])
expect_rgb = bytes.fromhex(sys.argv[3]) if len(sys.argv) > 3 else bytes.fromhex("11cc66")

s = socket.create_connection((host, port), timeout=10)

server_version = s.recv(12)
assert server_version.startswith(b"RFB 003."), server_version
s.sendall(b"RFB 003.008\n")

n_types = s.recv(1)[0]
types = s.recv(n_types)
assert 1 in types, f"server does not offer None security: {types}"
s.sendall(bytes([1]))

result = s.recv(4)
assert struct.unpack(">I", result)[0] == 0, "security handshake failed"

s.sendall(bytes([1]))  # ClientInit: shared

def recvn(n):
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            raise EOFError("connection closed early")
        buf += chunk
    return buf

init = recvn(2 + 2 + 16 + 4)
width, height = struct.unpack(">HH", init[0:4])
pf = init[4:20]
bpp, depth, big_endian, true_color = pf[0], pf[1], pf[2], pf[3]
red_max, green_max, blue_max = struct.unpack(">HHH", pf[4:10])
red_shift, green_shift, blue_shift = pf[10], pf[11], pf[12]
name_len = struct.unpack(">I", init[20:24])[0]
name = recvn(name_len).decode()
print(f"ServerInit: {width}x{height} bpp={bpp} depth={depth} name={name!r}")
print(f"pixel format: shifts R={red_shift} G={green_shift} B={blue_shift} max={red_max},{green_max},{blue_max} big_endian={big_endian}")

# FramebufferUpdateRequest: incremental=0, whole screen.
s.sendall(struct.pack(">BBHHHH", 3, 0, 0, 0, width, height))

msg_type = recvn(1)[0]
assert msg_type == 0, f"expected FramebufferUpdate, got {msg_type}"
_, n_rects = struct.unpack(">BH", recvn(3))
print(f"FramebufferUpdate: {n_rects} rect(s)")

pixels_by_pos = {}
for _ in range(n_rects):
    rx, ry, rw, rh, encoding = struct.unpack(">HHHHi", recvn(12))
    assert encoding == 0, f"only Raw encoding supported by this witness, got {encoding}"
    data = recvn(rw * rh * (bpp // 8))
    for py in range(rh):
        for px in range(rw):
            off = (py * rw + px) * 4
            b, g, r, _ = data[off:off + 4]
            pixels_by_pos[(rx + px, ry + py)] = (r, g, b)

# Verify: the app box fills a rect at (width/4, height/4, width/2, height/2)
# with RGB 0x11,0xcc,0x66. Sample its center.
cx, cy = width // 2, height // 2
r, g, b = pixels_by_pos.get((cx, cy), (None, None, None))
print(f"pixel at center ({cx},{cy}): R={r:#04x} G={g:#04x} B={b:#04x}" if r is not None else "MISSING pixel")

exp_r, exp_g, exp_b = expect_rgb[0], expect_rgb[1], expect_rgb[2]
ok = (r, g, b) == (exp_r, exp_g, exp_b)
print(f"expected: R={exp_r:#04x} G={exp_g:#04x} B={exp_b:#04x}")
print("RESULT:", "PASS -- VNC end-to-end verified, real pixels from the app box visible" if ok else "FAIL")
sys.exit(0 if ok else 1)
