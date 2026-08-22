# Multi-box X11 + VNC composition

A real, working, end-to-end example of `boxer compose`: three independent
litebox-sandboxed boxes, each its own `boxer run` process on its own TUN
subnet, coordinating over TCP to serve a live VNC session.

Everything here was actually built and run in this repository's own dev
container -- no Docker, no `docker save`, no image registry beyond a single
MCR-mirrored Alpine base pulled once during earlier exploration and then
abandoned (see "Why not real Xvfb" below). It reflects what is verified
working today, not an aspirational design.

## What it proves

- LiteBox is single-process/thread-only per box (no `fork`): a workload made
  of several cooperating processes has to be several boxes.
- Two boxes on distinct `--net-guest-ip` subnets can address each other
  directly, with the host kernel routing between them (`net.ipv4.ip_forward`
  on) -- no shared filesystem, no shared unix socket, just IP.
- `boxer compose` drives that composition from one JSON config: dependency
  ordering, per-box TUN/IP allocation, `${name.guest_ip}` templating so no
  box's own image bakes in another box's address, port publishing, log
  prefixing, and clean Ctrl+C teardown.
- A real external VNC client, connecting to a real published host port,
  receives real pixels that a *different* box drew into a *third* box's
  framebuffer over the network. `rfb_client_witness.py` is a from-scratch
  RFB 3.8 client that verifies this by checking the actual received pixel
  color, not just that bytes arrived.

## Layout

- `src/x11proto.rs` -- minimal X11 core protocol client (connection setup,
  `CreateGC`, `PolyFillRectangle`, `GetImage`), from scratch, no libX11.
- `src/bin/x11_server.rs` -- minimal X11 *server*: implements exactly the
  request subset the two client binaries below use, against a real
  in-memory framebuffer. See "Why not real Xvfb" for why this exists instead
  of packaging the real X server.
- `src/bin/x11_app.rs` -- connects to the server over TCP, fills a rectangle
  into the root window, keeps redrawing.
- `src/bin/vnc_bridge.rs` -- connects to the server over TCP (`GetImage`),
  serves the result as a minimal RFB 3.8 server (raw encoding) for real VNC
  clients.
- `build-images.py` -- packages each binary as a `.box.wasm` (docker-save
  layout, no Docker installed) and runs it through `boxer build --archive`.
- `compose.json` -- the composition: three instances, `x11server` first,
  `app`/`vncbridge` depending on it and referencing its address via
  `${x11server.guest_ip}`.
- `rfb_client_witness.py` -- a real RFB client (not a mock) that performs the
  actual handshake and checks the actual received pixel color.

## Running it

```sh
cd examples/multibox-x11-composition
cargo build --release --target x86_64-unknown-linux-musl
python3 build-images.py                 # -> images/{x11server,app,vncbridge}.box.wasm
cd ../..
cargo build --release -p boxer
./target/release/boxer compose examples/multibox-x11-composition/compose.json
```

In another terminal, once the log shows `composition up, press Ctrl+C to
stop`:

```sh
python3 examples/multibox-x11-composition/rfb_client_witness.py 127.0.0.1 5900
```

Expect:

```
ServerInit: 160x120 bpp=32 depth=24 name='litebox-compose-demo'
FramebufferUpdate: 1 rect(s)
pixel at center (80,60): R=0x11 G=0xcc B=0x66
RESULT: PASS -- VNC end-to-end verified, real pixels from the app box visible
```

Ctrl+C the `boxer compose` process to tear the whole composition down
cleanly.

## Why not real Xvfb

The first version of this example packaged the host's real, already-built
`Xvfb` binary (plus its ~30 shared libraries, resolved via `ldd`, and
`xkbcomp`) straight into a box rootfs -- no `apt`/`apk` network access
needed, since the binaries already existed on the build host. It worked as
far as `litebox_syscall_rewriter` rewriting a real dynamically-linked glibc
binary with a real `PT_INTERP` loader, running inside the sandbox: genuine
evidence litebox's ELF loader and dynamic linking support are real. It
failed at Xvfb's own startup: Xvfb creates a PID lock file via the classic
Unix `link()`-based atomic-lock pattern, and:

1. `litebox_shim_linux` has no `link`/`linkat` syscall handler at all (nor
   `symlink`/`rename`) -- the call returns `ENOSYS`.
2. Xvfb's `-nolock` flag, which would skip that entirely, refuses unless
   `getuid() == 0` -- and litebox guests always run as a fixed non-root uid
   (1000) regardless of the image's `USER`, by design
   (`litebox_runner_linux_userland::DEFAULT_GUEST_UID`).

Both are real, separately-scoped litebox gaps (documented in
`docs/boxer.md`'s "Known costs and limits"), not something this example can
work around from userspace. Rather than leave the composition blocked on
them, `x11_server.rs` hand-implements exactly the X11 requests this
composition's own two client boxes need, against a real framebuffer -- the
same spirit as Xvfb (a "fake" X server needing no display hardware), just
scoped to what is actually exercised here instead of the full protocol.

## A real network caveat this composition ran into

Early testing sent a `GetImage` reply as one large write (tens of KB). It
vanished: `x11-server`'s `write()` reported full success, but `vnc-bridge`'s
`read()` never saw a single byte and hung forever -- while a *tiny* reply
(a 1x1-pixel `GetImage`, ~20 bytes) on the exact same connection arrived
immediately. This reproduces specifically for a *routed* connection (two
separate `boxer run` processes on distinct `--net-guest-ip` subnets, bridged
by the host's IP forwarding) -- the same code works fine over a bare host
TCP socket. `x11proto::write_all_retrying` works around it by capping each
underlying `write()` to a small chunk (256 bytes) with a short pause between
chunks. This is a real gap in litebox's guest network stack, most likely in
how its poll/wake loop handles a receive spanning more than one incoming
packet on the two-TUN-hop path -- worth a focused follow-up session, not
something this example's chunking workaround should be mistaken for having
fixed.

## Multiple clients / more instances

`compose.json`'s `instances` array is not limited to three -- add another
entry depending on `x11server` (another `app`-like box drawing something
different, say) and it starts alongside the existing two, each on its own
auto-allocated `/24` if `net_host_ip`/`net_guest_ip` are omitted.
