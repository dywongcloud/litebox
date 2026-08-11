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

## Known limitations — please read this before trying it

**`fork(2)` is not implemented on any platform yet, and this severely limits the
interactive shell.** An interactive shell must fork for every external command,
because it has to outlive the child it starts. Without `fork`, it cannot.

| Mode | What works |
|---|---|
| `npx @openclew/litebox`<br>(interactive shell) | **Builtins only** — `echo`, `cd`, `pwd`, `test`, `exit`. Every external command (`ls`, `cat`, …) silently produces nothing. Pipes, `$(…)`, background jobs and job control all fail. |
| `npx @openclew/litebox -- <program>`<br>(direct exec) | **Fully works.** The runner execs the program as the guest's only process, so no fork is needed. This is the mode to use for anything real. |

Concretely:

```sh
npx @openclew/litebox -- /bin/busybox cat /etc/alpine-release   # -> 3.24.1
npx @openclew/litebox -- /bin/busybox ls -l /etc                # works
npx @openclew/litebox        # shell starts, but `ls` inside it does nothing
```

So the interactive shell is real — it starts, it's attached to your terminal, and
builtins work — but it is close to a demonstration until `fork` lands. Direct
exec is the useful mode today. This is stated plainly because discovering it at a
silent prompt is worse than reading it here.

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

Additionally on macOS arm64: XNU zeroes the AArch64 platform register `x18` on
every return to EL0, and Linux binaries use `x18` freely as a general-purpose
register. Programs that keep a live value there — Node.js among them — crash.
Small static binaries such as BusyBox are usually unaffected. See `docs/roadmap.md`
in the repository.

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
