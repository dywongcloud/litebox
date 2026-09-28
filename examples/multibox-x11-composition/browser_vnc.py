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

Security: binds to loopback by default (a non-loopback --listen prints a
warning). Requests are only answered for a loopback Host (or the --listen
host), which defeats DNS rebinding, and WebSocket upgrades whose Origin is not
this server are rejected, so other websites open in your browser cannot reach
the VNC session through it. There is no other authentication.
"""
import argparse
import base64
import hashlib
import os
import socket
import socketserver
import struct
import threading
import time
import urllib.parse

GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
HTML_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "browser_vnc.html")
MAX_FRAME = 1 << 20  # a client->server RFB message is tiny; refuse huge frames
HEADER_DEADLINE = 10  # seconds allowed for the whole HTTP request head
IDLE_TIMEOUT = 120  # seconds of client silence before a session is dropped
MAX_SESSIONS = 8
LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}


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


def ws_read_frame(sock):
    """Return (fin, opcode, payload) for one client frame; ValueError on a
    protocol violation (unmasked, RSV bits, oversized, bad control frame)."""
    b0, b1 = recv_exact(sock, 2)
    fin, rsv, opcode = bool(b0 & 0x80), b0 & 0x70, b0 & 0x0F
    if not b1 & 0x80:
        raise ValueError("unmasked client frame")
    if rsv or opcode in (3, 4, 5, 6, 7) or opcode > 10:
        raise ValueError("reserved bits or opcode")
    n = b1 & 0x7F
    if n == 126:
        n = struct.unpack(">H", recv_exact(sock, 2))[0]
    elif n == 127:
        n = struct.unpack(">Q", recv_exact(sock, 8))[0]
    if opcode >= 8 and (n > 125 or not fin):
        raise ValueError("bad control frame")
    if n > MAX_FRAME:
        raise ValueError("frame too large")
    mask = recv_exact(sock, 4)
    data = bytes(b ^ mask[i % 4] for i, b in enumerate(recv_exact(sock, n)))
    return fin, opcode, data


def host_allowed(host_header, listen_host):
    """DNS-rebinding defence: only answer requests addressed to a loopback
    name or the address we were told to listen on."""
    host = host_header.strip().lower()
    if host.startswith("["):
        name = host[1:].split("]")[0]
    else:
        name = host.rsplit(":", 1)[0] if host.count(":") == 1 else host
    return name in LOOPBACK_HOSTS or name == listen_host.lower()


class Handler(socketserver.BaseRequestHandler):
    def read_head(self, sock):
        """Read the HTTP request head under an overall deadline."""
        deadline = time.monotonic() + HEADER_DEADLINE
        raw = b""
        while b"\r\n\r\n" not in raw:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or len(raw) > 16384:
                return None
            sock.settimeout(remaining)
            chunk = sock.recv(4096)
            if not chunk:
                return None
            raw += chunk
        return raw.split(b"\r\n\r\n")[0]

    def handle(self):
        sock = self.request
        try:
            head = self.read_head(sock)
            if head is None:
                return
            lines = head.decode("latin-1").split("\r\n")
            method, target, _ = lines[0].split(" ", 2)
            headers = {}
            for line in lines[1:]:
                k, _, v = line.partition(":")
                headers[k.strip().lower()] = v.strip()
            if not host_allowed(headers.get("host", ""), self.server.listen_host):
                sock.sendall(b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
                return
            path = urllib.parse.urlsplit(target).path
            if headers.get("upgrade", "").lower() == "websocket":
                self.websocket(sock, path, headers)
            elif method == "GET" and path in ("/", "/index.html"):
                with open(HTML_PATH, "rb") as f:
                    body = f.read()
                sock.sendall(
                    b"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n"
                    b"Cache-Control: no-store\r\nX-Frame-Options: DENY\r\n"
                    b"Content-Security-Policy: frame-ancestors 'none'\r\n"
                    b"X-Content-Type-Options: nosniff\r\nConnection: close\r\n"
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
        if not self.server.sessions.acquire(blocking=False):
            sock.sendall(b"HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
            return
        try:
            self.serve_session(sock, headers)
        finally:
            self.server.sessions.release()

    def serve_session(self, sock, headers):
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
        sock.settimeout(IDLE_TIMEOUT)
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
        message = b""
        try:
            while True:  # browser -> VNC
                fin, opcode, data = ws_read_frame(sock)
                if opcode == 8:
                    with lock:
                        ws_send(sock, 8, data[:2])
                    break
                if opcode == 9:
                    with lock:
                        ws_send(sock, 10, data)
                elif opcode == 10:
                    pass
                elif opcode in (1, 2) or (opcode == 0 and message):
                    if opcode != 0 and message:
                        raise ValueError("new data frame inside a fragmented message")
                    message += data
                    if len(message) > MAX_FRAME:
                        raise ValueError("message too large")
                    if fin:
                        upstream.sendall(message)
                        message = b""
                else:
                    raise ValueError("stray continuation frame")
        except (OSError, EOFError, ValueError):
            pass
        finally:
            # close() alone does not wake a recv() blocked in down(); without
            # shutdown() the upstream connection (and its thread) would leak,
            # and the single-client VNC bridge would stay wedged.
            try:
                upstream.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            upstream.close()
            t.join(timeout=2)


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    sessions = threading.BoundedSemaphore(MAX_SESSIONS)


def parse_addr(s):
    host, sep, port = s.rpartition(":")
    if not sep or not port.isdigit():
        raise SystemExit(f"expected HOST:PORT, got {s!r}")
    return host or "127.0.0.1", int(port)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--vnc", default="127.0.0.1:5901", help="VNC server to proxy to (default %(default)s)")
    ap.add_argument("--listen", default="127.0.0.1:6080", help="address to serve on (default %(default)s)")
    args = ap.parse_args()
    listen = parse_addr(args.listen)
    server = Server(listen, Handler)
    server.vnc_addr = parse_addr(args.vnc)
    server.listen_host = listen[0]
    host, port = server.server_address
    if host not in LOOPBACK_HOSTS:
        print(f"browser_vnc: WARNING listening on {host}: anyone who can reach it can view the session", flush=True)
    print(f"browser_vnc: open http://{host}:{port}/  (proxying to {args.vnc})", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
