# Roadmap: known gaps and follow-up work

This is a working list of gaps found while porting LiteBox to macOS/Apple
Silicon and auditing the rest of the tree for related issues. Each entry
below was deliberately **not** implemented in that pass, because doing it
correctly needs either real hardware/kernel verification this repo's CI
cannot provide from a Linux-hosted sandbox, or a genuine design decision
rather than a mechanical fix. Implementing any of these without that
verification risks the exact kind of half-finished, silently-wrong change
this list exists to avoid.

Items are grouped by how much verification they need before landing, not by
subsystem.

## Resolved on real hardware this pass

* **The `TPIDR_EL0` anchor question is answered.** Measured on an Apple M3
  Pro (macOS 26.3.1): `TPIDR_EL0` does not survive a context switch (XNU
  overwrites it with its own value, not merely leaves it stale) and cannot
  anchor the guest thread pointer. `TPIDRRO_EL0` is stable across a reschedule
  and distinct per thread, matching Apple's documented pthread-self-pointer
  use. See [`docs/macos.md`](./macos.md#remaining-work) for the full
  measurement and the resulting design (a reserved pthread TSD slot read via
  a `TPIDRRO_EL0`-relative direct-TSD sequence, mirroring libSystem's own
  fast accessors). What's left is implementation, not research:

## Needs real Apple Silicon hardware (implementation, not open questions)

* **`Host::MacOs` in the rewriter is complete** (anchor register *and* slot
  addressing). Gates anchor on `TPIDRRO_EL0` and address the guest
  thread-pointer slot at pthread TSD slot `MACOS_GUEST_TPIDR_TSD_SLOT` (index
  256, the first dynamic `pthread_key_create` key on macOS, verified against
  apple-oss-distributions/libpthread) -- a LiteBox-owned slot, not a raw
  offset into Apple's own pthread structure, so it does not corrupt libpthread
  state. `litebox_packager::rewrite_host` selects it when packaging on macOS.
  The remaining runtime obligation (reserve exactly slot 256 with
  `pthread_key_create` at init and confirm it was handed that slot;
  `pthread_setspecific` each guest thread's pointer) is part of guest entry,
  below.
* **The platform's *own* per-thread context-switch bookkeeping** — a separate
  problem from the rewriter's guest slot above. Studying
  `litebox_platform_linux_userland`'s x86_64
  `run_thread_arch`/`switch_to_guest`/`syscall_callback` (the closest thing to
  a template) surfaced why: that code doesn't only virtualize the *guest's*
  thread pointer -- it also stashes its own bookkeeping (`host_sp`, `host_bp`,
  `guest_context_top`, `in_guest`) in `fs:`-relative TLS slots, because by the
  time `syscall_callback` runs, every general-purpose register holds live
  guest state and there is nothing else durable to read "where was the host
  stack" from. A macOS port needs the equivalent, and `x86_64`'s raw
  `@tpoff`-relative asm syntax is ELF/Linux-specific with no Mach-O equivalent
  to copy directly. The two pieces need *different* Darwin solutions:
  - The rewriter's gates are raw bytes patched into an arbitrary guest binary
    and cannot call into Rust — hence the reserved direct-TSD slot above (now
    done).
  - The platform's own `run_thread_arch`/`switch_to_guest`/`syscall_callback`
    equivalent is code LiteBox writes and compiles itself, so it isn't bound
    by "no function calls": it can use an ordinary Rust `thread_local!` static
    (Darwin's TLV-based thread-locals are mature and compiler/OS-verified) for
    its `host_sp`/`host_fp`/`host_lr`/`in_guest`-equivalent bookkeeping,
    updated from normal (non-naked) Rust immediately around the naked-asm call
    sites rather than from inside the asm. Lower-risk than matching x86_64's
    raw-TLS-in-asm style, and independently buildable/unit-testable.
* **The guest-entry context switch itself**, once the bookkeeping primitive
  above lands. AArch64 guest entry (`run_thread_arch` / `switch_to_guest` in
  the Linux terminology) is not implemented for *any* host in this repo yet,
  macOS included -- `litebox_platform_linux_userland`'s version is entirely
  `#[cfg(target_arch = "x86_64")]`, and LVBS's AArch64 scaffolding (the
  `Exception`/`ExceptionInfo` types in `litebox/src/shim.rs` already have
  AArch64 variants, which *is* directly reusable) stops short of a working
  context switch too. There is no existing full AArch64 reference
  implementation anywhere in the tree to adapt; a macOS implementation would
  be pioneering this for the whole project, not porting an existing pattern.
  This is the one seam standing between the current macOS port and actually
  running a guest.
* **The `jit_write_protect` bracketing gap** documented in
  [`docs/macos.md`](./macos.md#wx-map_jit-and-code-signing): nothing in
  `litebox_shim_linux`'s ELF loader or syscall-rewriter patching calls
  `pthread_jit_write_protect_np` around its writes into a `MAP_JIT` mapping.
  The fix is a `PageManagementProvider` hook (no-op default, macOS override)
  wrapping the write call sites in `litebox_shim_linux/src/syscalls/mm.rs`
  (`maybe_patch_exec_segment`, `apply_trap_fallback`) -- straightforward to
  write, but only real hardware can confirm it actually resolves the SIGBUS
  this gap implies rather than papering over a misunderstanding of the API.
* **Darwin ABI drift beyond what `darwin_abi_probe.c` already checks.** The
  probe (added this pass, see the `Build and Test macOS` CI job) covers the
  three hand-written struct layouts the fault handler depends on. Anything
  else hand-written against Darwin/Mach headers in the future should get the
  same treatment rather than trusting a one-time reading of the headers.

## Needs a real multi-threaded guest to exercise

* **Per-thread `PENDING_SIGNALS`.** Currently process-wide (see
  `docs/macos.md`'s note on `SignalProvider`); correct for the single guest
  thread that's reachable today, wrong once guest entry supports more than
  one. Fix: per-thread pending-signal state plus the signal-mask discipline
  `litebox_platform_linux_userland` already uses, or `pthread_sigqueue` if it
  turns out to support the needed payload delivery.
* **`sa_restorer` and FP/SIMD signal-frame state** (`docs/macos.md`): no
  vDSO means a guest handler without `SA_RESTORER` has nowhere to return to,
  and the signal frame's vector-state area is zeroed rather than populated.
  Both are inert until a guest actually installs a handler and executes.

## Needs a design decision, not just an errno swap

Found while sweeping `litebox_shim_linux` for `unimplemented!()`/`todo!()`
panics reachable from guest syscall arguments (most of the sweep landed
directly -- see the commit that added this file for what did). Left alone:

* `sys_prlimit`/`sys_get_robust_list`'s "specific pid" handling
  (`litebox_shim_linux/src/syscalls/process.rs`) treats any non-`None`/
  non-zero pid as unsupported, but a guest calling with its own real pid
  (rather than the `0`/`None` "self" sentinel) is equally valid on real Linux
  and should be treated as self, not rejected. Needs comparing against the
  caller's own pid, not a blanket errno.
* `do_mmap_file_memcpy`'s `Errno -> MappingError` mapping
  (`litebox_shim_linux/src/syscalls/mm.rs`) has a catch-all `unimplemented!()`
  for any `sys_read` errno beyond the three it explicitly handles.
  `MappingError` (`litebox/src/mm/linux.rs`) has no generic "underlying I/O
  error" variant to map onto -- needs a new variant, which is an API change
  to `litebox` core, not a local fix.
* IPv6 `copy_sockaddr_to_user`, unnamed-Unix-socket autobind, `O_DIRECT`,
  `SO_BROADCAST` disable, non-TCP `SO_KEEPALIVE`, and several other
  `net.rs`/`pipe.rs`/`unix.rs` gaps (grep for `todo!`/`unimplemented!` in
  those files) are genuine missing features, not missing error paths --
  each needs its own implementation, not a blanket conversion.
* `EpollDescriptor::Epoll` in `epoll.rs` and a handful of `_ =>
  unimplemented!()` catch-alls in `net.rs`/`process.rs` are exhaustiveness
  arms over enums with variants the current code paths don't construct;
  confirm actual unreachability (or handle it) case by case rather than
  assuming.

## Larger architectural work, out of scope for a single pass

These came out of researching how comparable sandboxes (gVisor, Firecracker,
WASI/wasmtime, Seatbelt/Landlock) solve problems LiteBox has today. Each is
a real, multi-day project on its own:

* **Seatbelt (`sandbox_init`) defense-in-depth for the macOS platform**,
  mirroring the existing Linux seccomp filter -- macOS currently has no
  second sandboxing layer behind LiteBox's own guest/host boundary.
* **Landlock integration** for the existing Linux seccomp filter, which
  currently has no path-scoping: a compromised guest that finds a seccomp
  gap can still reach any path the host process can.
* **A WASI-style capability redesign for `litebox_broker_host`'s filesystem
  and socket authorization** -- preopen-style directory capabilities and a
  per-destination socket policy hook, replacing today's coarser
  per-principal rights.
* **`litebox_runner_snp`'s TCP+9P bootstrap migrated to a vsock-style
  channel**, following Firecracker's precedent, to avoid exposing the boot
  channel on a real network interface.
* **Process-level jailing of `litebox_broker_host`** itself (Firecracker's
  jailer, or crosvm's minijail, are the precedents), so a broken broker isn't
  a fully-privileged process.
* **An async-signal-safety audit** across every platform's signal handlers --
  none of the platform crates currently have one, and LiteBox's whole fault
  and interrupt-delivery model runs inside handlers.
* **CI checks that `CallerCredential::Unauthenticated` can't reach the broker
  in non-test builds**, and that malformed/truncated broker messages fail
  closed -- currently enforced by code review, not by an automated check.
