# LiteBox

> A security-focused library OS supporting kernel- and user-mode execution

> [!NOTE]
> LiteBox is actively evolving. APIs, interfaces, and platform support may change as the design continues to mature. This repository is a fork of the upstream project and has been extended with additional work, including changes around P2P support and related platform integration.

LiteBox is a sandboxing library OS that reduces the host-facing interface to help shrink attack surface. It is designed to make it easier to connect different **North** shims and **South** platforms while keeping the core execution environment small and security-oriented.

LiteBox exposes a Rust-inspired [`nix`](https://docs.rs/nix)/[`rustix`](https://docs.rs/rustix)-style **North** interface when provided a `Platform` interface at the **South**. These layers make it possible to adapt LiteBox to different host environments and execution targets.

## What LiteBox is for

Example use cases include:

- Running unmodified Linux programs on Windows
- Running unmodified Linux programs on macOS (Apple Silicon) — see [docs/macos.md](./docs/macos.md)
- Sandboxing Linux applications on Linux
- Running programs on top of SEV-SNP
- Running OP-TEE programs on Linux
- Running on LVBS
- P2P-related support and platform experimentation introduced in this fork

## Notable changes in this fork

This fork has diverged from upstream `microsoft/litebox`. The main goals of the fork appear to include:

- Extending the project with P2P-related support
- Adding or refining supporting crates for platform interoperability
- Continuing work on platform-specific integration and shared abstractions
- Keeping the codebase moving toward broader runtime flexibility

If you are reading this as a new contributor or user, treat this repository as the fork-specific version of LiteBox rather than a drop-in mirror of upstream.

## Repository layout

This repository contains multiple crates and supporting components for different parts of the LiteBox stack, including:

- `litebox_common_linux` — shared elements for Linux-y systems
- `litebox_common_optee` — common elements used to enable OP-TEE-like functionality
- platform, shim, and runner crates for the supported environments

## Documentation

Helpful docs and project files:

- [CONTRIBUTING.md](./CONTRIBUTING.md)
- [CODE_OF_CONDUCT.md](./CODE_OF_CONDUCT.md)
- [SECURITY.md](./SECURITY.md)
- [SUPPORT.md](./SUPPORT.md)
- [docs/roadmap.md](./docs/roadmap.md) — known gaps and follow-up work
- [docs/macos.md](./docs/macos.md) — macOS notes

## Project status

LiteBox is still under active development. Some areas are experimental, and the exact behavior of platform integrations may change as the fork evolves.



LiteBox is a sandboxing library OS that drastically cuts down the interface to the host, thereby reducing attack surface.  It focuses on easy interop of various "North" shims and "South" platforms.  LiteBox is designed for usage in both kernel and non-kernel scenarios.

LiteBox exposes a Rust-y [`nix`](https://docs.rs/nix)/[`rustix`](https://docs.rs/rustix)-inspired "North" interface when it is provided a `Platform` interface at its "South".  These interfaces allow for a wide variety of use-cases, easily allowing for connection between any of the North--South pairs.

Example use cases include:
- Running unmodified Linux programs on Windows
- Running unmodified Linux programs on macOS (Apple Silicon) -- see [docs/macos.md](./docs/macos.md)
- Sandboxing Linux applications on Linux
- Run programs on top of SEV SNP
- Running OP-TEE programs on Linux
- Running on LVBS

![LiteBox and related projects](./.figures/litebox.svg)

## Contributing

See the following files for details:

- [CONTRIBUTING.md](./CONTRIBUTING.md)
- [CODE_OF_CONDUCT.md](./CODE_OF_CONDUCT.md)
- [SECURITY.md](./SECURITY.md)
- [SUPPORT.md](./SUPPORT.md)
- [docs/roadmap.md](./docs/roadmap.md) for known gaps and follow-up work

## License

MIT License.  See [./LICENSE](./LICENSE) for details.

## Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft 
trademarks or logos is subject to and must follow 
[Microsoft's Trademark & Brand Guidelines](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general).
Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship.
Any use of third-party trademarks or logos are subject to those third-party's policies.
