# Boxer: OCI workloads as wasm-carried boxes

Boxer completes the [dphilla/boxer](https://github.com/dphilla/boxer) idea on
top of LiteBox: any OCI container image or Dockerfile becomes a single
`.box.wasm` artifact -- a genuine WebAssembly module that carries the image's
rootfs with every executable pre-rewritten by the LiteBox syscall rewriter.
`boxer run` executes the workload under the LiteBox sandbox; any wasm runtime
can load the artifact and print its self-description.

## Install

Boxer is a workspace member, so it builds with the rest of LiteBox:

```sh
cargo build --release -p boxer          # ./target/release/boxer
cargo install --path boxer              # or put it on PATH
cargo run -p boxer -- build -f Dockerfile   # or run without installing
```

## Quickstart

```sh
# From a Dockerfile or Containerfile (either name is found automatically)
boxer build -o app.box.wasm

# From a registry image, for both architectures
boxer build -i mcr.microsoft.com/cbl-mariner/busybox:2.0 --platform linux/amd64,linux/arm64

# From a `docker save` archive or an OCI layout directory/tar
boxer build --archive image.tar

# Inspect and run
boxer inspect app.box.wasm
boxer run app.box.wasm            # image ENTRYPOINT/CMD
boxer run app.box.wasm /bin/echo hi   # override CMD

# Serve: publish every EXPOSEd port, or map one explicitly
boxer run -P app.box.wasm
boxer run -p 8080:80 app.box.wasm
```

## Ports

`EXPOSE` is carried end to end. The Dockerfile form accepts a bare port, an
explicit protocol, and ranges (`EXPOSE 80`, `EXPOSE 53/udp`,
`EXPOSE 9000-9002`), all normalized to `port/proto`; images pulled from a
registry contribute their config's `ExposedPorts` the same way. The result
lands in the box metadata, so `boxer inspect` lists it without running
anything.

Serving needs the workload on a network, which LiteBox reaches through a TUN
device -- and boxer creates that device itself, with the same ioctls `ip`
uses, so serving a box is one command with no setup step and no `iproute2` on
the host. Creating a network interface needs `CAP_NET_ADMIN` (usually root);
that is a kernel requirement, not a missing feature, and boxer says so when it
is absent. An interface that already exists is reused rather than replaced.

`boxer run -P` (or `-p`) attaches the workload to that device -- the guest
answers on `10.0.0.2` -- and publishes each mapping on the host, so clients
connect to `127.0.0.1:<port>` without knowing the guest address. `-p` takes
docker's shapes: `PORT`, `HOST:GUEST`, `IP:HOST:GUEST`, each optionally
suffixed `/tcp` or `/udp` (TCP by default). Both protocols are published:
TCP forwards each connection with independent half-close, and UDP relays
datagrams with one guest-side socket per client source address so replies
route back to the right client. `--net <device>` selects a different TUN
device, and is implied by publishing.

Every box otherwise answers on the same hardcoded `10.0.0.2`/`10.0.0.1` pair
regardless of which `--net <device>` it is attached to, so two boxes on
distinct devices look identical from each other's point of view and cannot
address each other directly. `--net-host-ip <IP> --net-guest-ip <IP>`
(given together, in the same /24) override that pair per box -- e.g.
`boxer run --net tun98 --net-host-ip 10.0.1.1 --net-guest-ip 10.0.1.2 ...`
alongside a second box on `--net tun99` with a distinct pair -- so composing
several boxes into one multi-process workload (an X11 display server plus
clients, say) gives each guest a distinguishing address instead of aliasing
onto the same one.

Forwarding is async (tokio): every connection is its own task, each direction
is copied independently so a half-close propagates, and a workload that
refuses one connection fails only that connection. This is where async earns
its place -- a published port is concurrent by nature. The carrier wasm
module deliberately stays a small synchronous WASI command: its job is to
describe the box under any runtime, and async there would buy nothing real.

Two LiteBox fixes were needed before any of this worked, both witnessed with
a real HTTP server inside a box:

- `close(2)` on a TCP socket dropped whatever the guest had written but the
  network worker had not yet moved into the send buffer, so the
  `write()`-then-`close()` that ends nearly every HTTP response delivered an
  empty reply. A graceful close now flushes the socket channel first.
- `shutdown(2)` returned `EOPNOTSUPP` for TCP, so a guest could not even
  half-close explicitly. It is implemented: `SHUT_WR` flushes and sends FIN,
  `SHUT_RD` makes later receives report end-of-file.

## The box format

A box is a valid wasm module (binary format v1):

- The executable part is a minimal WASI preview1 program: `_start` writes the
  box's banner and metadata JSON to stdout via `fd_write` and returns, so
  `wasmtime app.box.wasm` (or a browser/node embedding with a `fd_write`
  stub) reports what the artifact holds without touching the payload.
- `box.meta.v1` custom section: metadata JSON (platform, entrypoint, cmd,
  env, workdir, source, rootfs size and SHA-256). See `BoxMeta` in
  `boxer/src/boxfmt.rs`.
- `box.rootfs.v1` custom section: the LiteBox-packaged rootfs tar, i.e.
  exactly what `litebox-packager` produces -- syscall-rewritten executables
  plus `litebox/config.json` (the OCI image config) and
  `litebox/config_and_run.sh` (ENV/WORKDIR/ENTRYPOINT wrapper).

Custom sections are skipped at instantiation, so load cost is independent of
image size. Boxes are deterministic: identical inputs produce byte-identical
artifacts (ordered tar, fixed uid/gid, no timestamps).

Integrity: `parse` verifies the payload length and SHA-256 against the
metadata before running anything.

## Architecture support

| | build (package) | run natively |
|---|---|---|
| x86-64 Linux | yes | yes (`litebox_runner_linux_userland`, in-process) |
| arm64 Linux | -- | not yet (no LiteBox arm64-linux userland runner) |
| macOS Apple Silicon | yes | via `litebox_runner_linux_on_macos_userland` (manual; see docs/macos.md) |
| anything with a wasm runtime | -- | self-description only (witnessed under wasmtime 29 and node 22) |

Cross-architecture packaging works because the syscall rewriter dispatches on
each ELF's own `e_machine`: building `--platform linux/arm64` on an x86-64
host rewrites the aarch64 binaries (anchored per `--rewrite-host`, default
`linux`; use `macos` for boxes that will run under the macOS runner).
`boxer run` refuses a box whose platform differs from the host, naming both.

A workload that is itself a wasm binary (detected by magic) runs in boxer's
own embedded wasmtime instead of the native runner, so it needs no wasm
runtime installed. It gets WASI preview 1 with the box's argv, the box's
environment and the host's stdio -- but no filesystem and no network, because
a box does not yet describe those capabilities and granting them silently
would be worse than refusing.

## What boxer needs from the host

Nothing but a kernel. Image pulls, layer decompression, Dockerfile
evaluation, `ADD <url>` fetches, TUN device creation, port publishing, the
native sandbox and the wasm runtime are all in the binary: no `curl`, no
`iproute2`, no `docker`/`podman`, no wasm runtime on `PATH`. Two things still
come from outside, both by nature rather than by omission: `RUN` executes
programs from the image itself and needs root for `chroot`, and creating a
network device needs `CAP_NET_ADMIN`.

## Dockerfile support

`Containerfile` and `Dockerfile` are the same language here; with no source
flag, `boxer build` uses whichever the build context holds, preferring
`Containerfile` as podman does.

The parser and evaluator are dependency-free and total (line-numbered errors,
no panics on user input): parser directives (`# escape=`), comments, line
continuations, multi-stage `FROM ... AS`, `--platform=` on FROM, exec and
shell command forms, heredocs (`RUN <<EOF`, `COPY <<EOF dest`), variable
substitution (`$V`, `${V}`, `${V:-def}`, `${V:+alt}`, `--build-arg`),
`.dockerignore`, COPY/ADD flags (`--from` stage or external image,
`--chmod`, globs), ADD tar auto-extraction (gzip/zstd/plain) and URL fetch,
and ENV/ARG/LABEL/WORKDIR/USER/EXPOSE/VOLUME/SHELL/STOPSIGNAL recorded into
the synthesized OCI config (HEALTHCHECK/ONBUILD recorded, not executed).

`RUN` executes in a chroot of the in-progress rootfs. That is a deliberate
divergence from "everything under LiteBox": the LiteBox tar filesystem is
in-memory and read-only by design, so guest filesystem mutations cannot
persist back out of the sandbox -- a builder needs real writes. Consequences:

- `RUN` needs root (chroot) and a build host matching the target platform;
  cross-platform builds with `RUN` fail with a named error.
- The final workload still gets the LiteBox sandbox at run time.

## Image acquisition

- Registry pulls are anonymous, honor `--platform`, and accept gzip, zstd,
  and uncompressed layers (whiteouts, opaque dirs, hard links, and symlink
  chains are handled by `litebox_packager::oci`). A missing platform is
  reported with the list the registry actually offers.
- `--archive` accepts `docker save` tars and OCI image layouts (directory or
  tar), including nested indexes, with the same layer pipeline. An archive
  whose config declares a different architecture than `--platform` is
  refused rather than mislabeled.

## Known costs and limits

- The LiteBox tar filesystem supports neither symlinks nor hard links, so
  every applet-style link materializes as a full copy: a busybox image
  (hundreds of applet links to one binary) expands to a multi-GB box. This
  is a LiteBox filesystem roadmap item, not a box format limit.
- Boxes above 2 GiB stay valid wasm and run fine natively, but JS engines cap
  single buffers at 2 GiB; `boxer build` warns when crossing that line.
  `boxer` enforces a 3.5 GiB ceiling, held safely below the ~4 GiB that u32
  section sizes impose so the section header and metadata always fit.
- Private registries are supported: credentials come from `REGISTRY_TOKEN`
  (a bearer token), a `REGISTRY_USERNAME`/`REGISTRY_PASSWORD` pair, or the
  `auth` entry docker/podman's `config.json` holds for the registry
  (honoring `DOCKER_CONFIG`). Public pulls stay anonymous. Credentials are
  used only for the request and never logged or stored in the box.
- `USER` is recorded in the config but not enforced by the runner.
- Upstream boxer's `compile` subcommand (marcotte-based C-to-wasm) is not
  reproduced here; its repository does not include the marcotte sources.
