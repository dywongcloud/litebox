# @openclew/litebox

Boot an interactive Linux shell inside [LiteBox](https://github.com/dywongcloud/litebox),
a userspace syscall-translation sandbox.

```sh
npx @openclew/litebox
```

## What this actually does

LiteBox runs unmodified Linux programs by translating their syscalls, rather than
by emulating instructions or booting a VM. Guest code executes natively on your
CPU. This package:

1. downloads a **pinned** source revision of LiteBox,
2. builds the runner and packager for your host with `cargo`,
3. packages a guest root filesystem from a public OCI image, and
4. starts a shell inside it, attached to your terminal.

The first run takes a few minutes. Everything is cached per source revision
afterwards; `npx @openclew/litebox --where` prints the cache directory.

## Requirements

- **Node.js 18+**
- **A Rust toolchain** (`cargo`, `rustc`) — <https://rustup.rs>
- **Network access on first run**, for the source archive and the guest image

This package builds from source instead of shipping prebuilt binaries. That is a
deliberate trade: prebuilt binaries would mean publishing five platform/arch
combinations that cannot all be tested, and a binary nobody has ever executed is
not a nicer user experience than a build.

## Usage modes

The pinned revision implements `fork(2)`, so the interactive shell can launch
external commands. Direct execution remains useful for scripts and automation
because the guest program's output goes straight to the host process:

```sh
npx @openclew/litebox
npx @openclew/litebox -- /bin/busybox cat /etc/alpine-release
npx @openclew/litebox -- /bin/busybox ls -l /etc
```

## Platform support

Stated at the level it has actually been verified, not at the level the code
implies:

| Host | Status | Notes |
|---|---|---|
| macOS arm64 | **verified** | Developed and tested here |
| macOS x64 | builds, unverified | The macOS platform is aarch64-only in places |
| Linux x64 / arm64 | builds, unverified | Two known-failing tests upstream |
| Windows x64 / arm64 | builds, unverified | Guest networking is an unimplemented stub; console input incomplete |

"Builds, unverified" means the runner exists and is expected to compile, but no
guest has been run there by us. It may work. Reports welcome.

On macOS arm64, LiteBox rewrites Linux guests' use of `x18`, allowing Node.js and
its child processes to run. A separate Node shutdown issue can print `pure virtual
method called` and discard buffered `console.log` output; use `fs.writeSync` when
the final output must be observed synchronously.

## Usage

```sh
npx @openclew/litebox                                  # interactive shell
npx @openclew/litebox -- /bin/busybox uname -a         # run one command
npx @openclew/litebox --image public.ecr.aws/docker/library/node:alpine
```

| Option | Meaning |
|---|---|
| `--image <ref>` | Guest OCI image (public registries only) |
| `--shell <path>` | Guest shell to start |
| `--rev <sha>` | Build a specific source revision |
| `--rebuild` | Rebuild even if cached |
| `--refresh-image` | Re-package the guest image even if cached |
| `--where` | Print the cache directory |
| `-q, --quiet` | Suppress progress output |

`LITEBOX_SRC=/path/to/checkout` builds from a local tree instead of downloading.
`LITEBOX_CACHE_DIR` overrides the cache location.

## License

MIT. Copyright (c) Microsoft Corporation.
