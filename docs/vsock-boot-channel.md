# `litebox_runner_snp` boot channel: migrating TCP+9P to a vsock-style channel

Tracks `docs/roadmap.md`'s "Larger architectural work" item: *"`litebox_runner_snp`'s
TCP+9P bootstrap migrated to a vsock-style channel, following Firecracker's
precedent, to avoid exposing the boot channel on a real network interface."*

This document exists because that migration cannot be completed from inside
this repository alone (see "Why this isn't done yet" below), and records:
what's actually true about the current channel, what was built this pass
that's usable regardless of how the rest lands, and the exact contract a
future change to the out-of-repo privileged component would need to
implement to finish it.

## Current state (as of this writing)

`litebox_runner_snp` is not a VMM; it's the freestanding guest kernel image
that runs inside the SEV-SNP VM itself (`litebox_runner_snp/src/main.rs`).
After boot, `sandbox_process_init` opens a TCP connection to a hardcoded
`10.0.0.1:8888` (`main.rs`, `GATEWAY_IP_ADDR` in `litebox/src/net/mod.rs`)
and layers a 9P filesystem (`litebox::fs::nine_p`) over it to back the
sandboxed guest program's root/`/tmp` filesystem. This is **not** a kernel
image/initrd/attestation boot loader -- `argv`/`envp` and boot parameters
already arrive separately, via `vmpl2_boot_params`, before this channel
opens. It exists purely as the transport for ordinary file I/O once the
sandboxed program is about to start.

That TCP connection runs over `litebox::net::Network`, a full smoltcp
IP/Ethernet stack, whose only physical-layer backing on SNP is
`HostSnpInterface::send_ip_packet`/`receive_ip_packet`
(`litebox_platform_linux_kernel/src/host/snp/snp_impl.rs`), which issue
`SNP_VMPL_TUN_WRITE_REQ`/`READ_REQ` VTL-call hypercalls
(`vmmcall`-based, `litebox_platform_linux_kernel/src/host/snp/snp_impl.rs`)
to the privileged component that actually launched the VM. Whatever
terminates that TUN traffic on the host side decides whether it's bridged
onto a real network interface -- nothing in this repo constrains that,
which is exactly the roadmap's stated concern.

## Why this isn't done yet

The privileged, VMPL0-level component that answers these hypercalls --
referred to in this repo only as `sandbox_driver`, whose header
(`litebox_platform_linux_kernel/src/host/snp/snp-sandbox.h`) is vendored
verbatim with an explicit `// This file is copied from
sandbox_driver/include/snp-sandbox.h` provenance comment -- **is not in
this repository**. A vsock-style channel needs a new, non-IP,
point-to-point primitive on *that* side: a new VTL request code, handled by
new code in `sandbox_driver` that this repo cannot see, modify, or verify
boots correctly on real SEV-SNP hardware.

Concretely, nothing safe could be shipped this pass that:

- adds a new, presently-unassigned request code to the vendored header (it
  would desync from the actual upstream file and mislead future readers
  into thinking it reflects `sandbox_driver`'s real, current protocol), or
- issues a `vmmcall` with a request code `sandbox_driver` doesn't
  recognize, against real (or even correctly emulated) SEV-SNP hardware,
  with no way to observe what an unrecognized code actually does there.

So this pass built the part that *is* fully in-repo, testable, and safe:
the guest-side transport abstraction the new channel will plug into, with
zero changes needed to the 9P protocol layer above it. The hypercall
plumbing below it is specified here, precisely enough to implement once
`sandbox_driver` support exists, rather than guessed at.

## What this pass built

`litebox_shim_linux/src/vsock_transport.rs`:

- `ByteChannel`: a trait for a point-to-point, non-IP, non-blocking byte
  channel (`try_read`/`try_write`, `Ok(0)` meaning "nothing right now," no
  addressing, no stream-EOF concept -- matching a vsock-style channel's
  actual shape, unlike a TCP socket's).
- `PointToPointTransport<C: ByteChannel>`: implements
  `litebox::fs::nine_p::transport::Read`/`Write` generically over any
  `ByteChannel`, the same way
  `transport::ShimTransport` does for a raw TCP `SocketFd` today. The 9P
  client (`litebox::fs::nine_p::FileSystem`) is already fully
  transport-agnostic, so **no changes are needed above this layer** --
  swapping `sandbox_process_init`'s `shim.tcp_connection(...)` for a future
  `shim.vsock_connection(...)` (once one exists) is the entire remaining
  call-site change.
- Tests (`litebox_shim_linux/src/vsock_transport.rs`, `mod tests`, no
  `target_os` gate and no external tooling -- runs anywhere, including this
  session's macOS host) exercise `PointToPointTransport` against an
  in-process mock `ByteChannel`: both directions round-trip correctly, a
  read that has nothing available yet spins rather than erroring or
  hanging (the exact behavior the boot channel depends on -- see
  `ShimTransport::read`'s identical spin-poll shape), and a genuinely
  disconnected channel reports a transport error rather than hanging
  forever.

## The remaining contract: what `sandbox_driver` would need to add

Modeled directly on the existing `SNP_VMPL_TUN_READ_REQ`/`WRITE_REQ` pair
(`snp-sandbox.h`) and `HostSnpInterface::send_ip_packet`/`receive_ip_packet`
(`snp_impl.rs`), which this design deliberately mirrors rather than
inventing a new shape for:

1. **Two new VTL request codes**, in `sandbox_driver`'s copy of
   `snp-sandbox.h` (this repo's copy would then be re-synced from there,
   as it already is for every other code): the current header defines
   codes through `0x11` (`SNP_VMPL_SEND_INTERRUPT_REQ`) with `0xff`
   (`SNP_VMPL_IDLE_REQ`) and `0x100` (`SNP_VMPL_TERMINATE_REQ`) reserved
   at the top of the range. `0x12`/`0x13` are free and are what this
   design proposes:
   - `SNP_VMPL_VSOCK_WRITE_REQ = 0x12`
   - `SNP_VMPL_VSOCK_READ_REQ = 0x13`

   These are proposed values, not yet real -- they exist nowhere in
   `sandbox_driver` today, and must not be used to issue a live hypercall
   until they are.

2. **A new `HostInterface` trait method pair**
   (`litebox_platform_linux_kernel/src/lib.rs`, alongside the existing
   `send_ip_packet`/`receive_ip_packet`):

   ```rust
   /// Sends bytes over the vsock-style boot channel. Returns the number of
   /// bytes accepted (may be less than `buf.len()`).
   fn send_vsock_frame(buf: &[u8]) -> Result<usize, Errno>;

   /// Reads up to `buf.len()` bytes from the vsock-style boot channel.
   /// Returns 0 if none are available right now, matching
   /// `receive_ip_packet`'s non-blocking contract.
   fn receive_vsock_frame(buf: &mut [u8]) -> Result<usize, Errno>;
   ```

3. **`HostSnpInterface`'s implementation** of those two methods, in
   `litebox_platform_linux_kernel/src/host/snp/snp_impl.rs`, issuing the
   two new request codes with the exact same `SnpVmplRequestArgs::new_request`
   / `Self::request` / `Self::parse_result` shape
   `send_ip_packet`/`receive_ip_packet` already use -- this part is a
   direct, low-risk copy of an existing, working pattern once the codes
   above are real on the `sandbox_driver` side.

4. **A `ByteChannel` implementation over `HostSnpInterface`**, in or near
   `litebox_shim_linux`, wrapping the new `HostInterface` methods --
   mechanical, since `ByteChannel`'s `try_read`/`try_write` contract was
   designed to match `send_vsock_frame`/`receive_vsock_frame` field for
   field.

5. **`GlobalState::vsock_connection`** (parallel to today's
   `tcp_connection`, `litebox_shim_linux/src/lib.rs`), returning a
   `vsock_transport::PointToPointTransport` over that channel.

6. **The one call-site change**: `litebox_runner_snp/src/main.rs`'s
   `sandbox_process_init`, replacing `shim.tcp_connection(addr)` with
   `shim.vsock_connection()` (no address -- vsock-style channels are
   point-to-point, not addressed) once 1-5 exist and have been verified
   against real or emulated SEV-SNP hardware. **Do not flip this default
   before that verification** -- until then, `litebox_runner_snp` boots
   over TCP+9P as it does today, and this document's job is to make step 6
   the only thing left to do, not to have silently attempted it already.

## Testing note

`litebox_runner_snp` itself is a `#![no_std] #![no_main]` freestanding
binary with no test harness -- it can't host `cargo test`, and it can't be
exercised in this repo without real or emulated SEV-SNP hardware. The 9P
protocol tests (`litebox/src/fs/nine_p/tests.rs`) and the existing
TCP-transport integration test
(`litebox_shim_linux/src/transport.rs`, `#[cfg(target_os = "linux")]`,
needs `diod`) already cover everything above the transport boundary and
don't need to change for this migration. The new `vsock_transport` tests
cover the new transport boundary itself, honestly, without needing SNP
hardware or an out-of-repo component -- that is deliberately the
full extent of what can be verified from here.
