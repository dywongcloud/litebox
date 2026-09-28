#!/usr/bin/env python3
"""View a demo VNC session in a web browser -- no noVNC, no dependencies.

Serves browser_vnc.html (a small canvas RFB client) and a WebSocket-to-TCP
proxy from one local port. The proxy only ever connects to the single VNC
address given on the command line, never to one chosen by the browser.

    python3 browser_vnc.py                      # proxies 127.0.0.1:5901
    python3 browser_vnc.py --vnc 127.0.0.1:5901 --listen 127.0.0.1:6080

then open http://127.0.0.1:6080/

The browser client speaks RFB security type "None", so leave VNC_PASSWORD
unset on the bridge (that setting is only for viewers, like macOS Screen
Sharing, that insist on a password).

Security: binds to loopback by default, and rejects WebSocket upgrades whose
Origin is not this server (so another website open in your browser cannot
reach the VNC session through it).
"""
import argparse
import base64
import hashlib
import os
import socket
import socketserver
import struct
import threading
import urllib.parse

GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
HTML_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "browser_vnc.html")
MAX_FRAME = 1 << 20  # a client->server RFB message is tiny; refuse huge frames


def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise EOFError
        buf += chunk
    return buf


def ws_send(sock, opcode, payload):
    head = bytes([0x80 | opcode])
    n = len(payload)
    if n < 126:
        head += bytes([n])
    elif n < 65536:
        head += bytes([126]) + struct.pack(">H", n)
    else:
        head += bytes([127]) + struct.pack(">Q", n)
    sock.sendall(head + payload)


def ws_recv(sock):
    """Return (opcode, payload) of the next complete message. Handles
    fragmentation; raises EOFError/ValueError on close or a bad frame."""
    message, msg_op = b"", None
    while True:
        b0, b1 = recv_exact(sock, 2)
        fin, opcode = b0 & 0x80, b0 & 0x0F
        if not b1 & 0x80:
            raise ValueError("unmasked client frame")
        n = b1 & 0x7F
        if n == 126:
            n = struct.unpack(">H", recv_exact(sock, 2))[0]
        elif n == 127:
            n = struct.unpack(">Q", recv_exact(sock, 8))[0]
        if n > MAX_FRAME or len(message) + n > MAX_FRAME:
            raise ValueError("frame too large")
        mask = recv_exact(sock, 4)
        data = bytes(b ^ mask[i % 4] for i, b in enumerate(recv_exact(sock, n)))
        if opcode >= 8:  # control frame, never fragmented
            return opcode, data
        if opcode != 0:
            msg_op = opcode
        message += data
        if fin:
            return msg_op, message


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        sock = self.request
        sock.settimeout(30)
        try:
            raw = b""
            while b"\r\n\r\n" not in raw:
                chunk = sock.recv(4096)
                if not chunk or len(raw) > 16384:
                    return
                raw += chunk
            lines = raw.split(b"\r\n\r\n")[0].decode("latin-1").split("\r\n")
            method, target, _ = lines[0].split(" ", 2)
            headers = {}
            for line in lines[1:]:
                k, _, v = line.partition(":")
                headers[k.strip().lower()] = v.strip()
            path = urllib.parse.urlsplit(target).path
            if headers.get("upgrade", "").lower() == "websocket":
                self.websocket(sock, path, headers)
            elif method == "GET" and path in ("/", "/index.html"):
                with open(HTML_PATH, "rb") as f:
                    body = f.read()
                sock.sendall(
                    b"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n"
                    b"Cache-Control: no-store\r\nConnection: close\r\n"
                    b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body
                )
            else:
                sock.sendall(b"HTTP/1.1 404 Not Found\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
        except (OSError, EOFError, ValueError, UnicodeDecodeError):
            pass

    def websocket(self, sock, path, headers):
        origin = headers.get("origin")
        host = headers.get("host", "")
        if path != "/websockify" or (origin is not None and urllib.parse.urlsplit(origin).netloc != host):
            sock.sendall(b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
            return
        key = headers.get("sec-websocket-key", "").encode()
        accept = base64.b64encode(hashlib.sha1(key + GUID).digest())
        sock.sendall(
            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
            b"Sec-WebSocket-Accept: " + accept + b"\r\n\r\n"
        )
        try:
            upstream = socket.create_connection(self.server.vnc_addr, timeout=10)
        except OSError as e:
            ws_send(sock, 8, struct.pack(">H", 1011) + f"cannot reach VNC server: {e}".encode()[:100])
            return
        upstream.settimeout(None)
        sock.settimeout(None)
        lock = threading.Lock()

        def down():  # VNC -> browser
            try:
                while True:
                    data = upstream.recv(65536)
                    if not data:
                        break
                    with lock:
                        ws_send(sock, 2, data)
            except OSError:
                pass
            finally:
                try:
                    with lock:
                        ws_send(sock, 8, struct.pack(">H", 1000))
                except OSError:
                    pass
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

        t = threading.Thread(target=down, daemon=True)
        t.start()
        try:
            while True:  # browser -> VNC
                opcode, data = ws_recv(sock)
                if opcode == 8:
                    break
                if opcode == 9:
                    with lock:
                        ws_send(sock, 10, data)
                elif opcode in (1, 2):
                    upstream.sendall(data)
        except (OSError, EOFError, ValueError):
            pass
        finally:
            upstream.close()
            t.join(timeout=2)


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def parse_addr(s):
    host, _, port = s.rpartition(":")
    return host, int(port)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--vnc", default="127.0.0.1:5901", help="VNC server to proxy to (default %(default)s)")
    ap.add_argument("--listen", default="127.0.0.1:6080", help="address to serve on (default %(default)s)")
    args = ap.parse_args()
    server = Server(parse_addr(args.listen), Handler)
    server.vnc_addr = parse_addr(args.vnc)
    host, port = server.server_address
    print(f"browser_vnc: open http://{host}:{port}/  (proxying to {args.vnc})", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
