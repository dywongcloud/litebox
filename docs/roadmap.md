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

* **`Host::MacOs`'s guest-slot addressing is a live correctness bug, not just
  an unfinished feature.** The anchor-register half landed
  (`litebox_syscall_rewriter::Host::MacOs`, real `MRS Xd, TPIDRRO_EL0`,
  tested), but its gates still address the guest thread-pointer slot at
  `[TPIDRRO_EL0-value + GUEST_TPIDR_OFFSET]` -- the same scheme `Host::Linux`
  uses, which only works there because the runtime owns the block
  `TPIDR_EL0` points at. `TPIDRRO_EL0` instead already points at Apple's own
  `pthread` structure, so that write corrupts live libpthread state rather
  than merely failing. `litebox_packager::rewrite_host` was reverted to
  always return `Host::Linux` (even on macOS) specifically to keep this out
  of anything that runs for real, until the fix below lands. Needed: a
  genuinely LiteBox-owned per-thread slot reached through a documented-safe
  indirection from `TPIDRRO_EL0` -- reserve a slot with `pthread_key_create`
  at platform-init time, `pthread_setspecific` the guest pointer into it once
  per guest thread, and have gates read it back through the same
  `TPIDRRO_EL0`-relative "direct TSD" sequence libSystem's own
  `errno`/QoS-class accessors use (not a full `pthread_getspecific` call,
  which would give up the single-instruction-anchor property that was the
  entire point). See [`docs/macos.md`](./macos.md#remaining-work) for the
  full writeup.
* **The actual next primitive to build: a Darwin per-thread runtime-owned
  slot, reusable by both the rewriter's gates and the platform's own
  context-switch bookkeeping.** Studying `litebox_platform_linux_userland`'s
  x86_64 `run_thread_arch`/`switch_to_guest`/`syscall_callback` (the closest
  thing to a template) surfaced why this is more foundational than it looked:
  that code doesn't only virtualize the *guest's* thread pointer -- it also
  stashes its own bookkeeping (`host_sp`, `host_bp`, `guest_context_top`,
  `in_guest`) in `fs:`-relative (i.e. anchor-relative) TLS slots, because by
  the time `syscall_callback` runs, every general-purpose register holds live
  guest state and there is nothing else durable to read "where was the host
  stack" from. A macOS port needs the equivalent for its own bookkeeping, not
  just for `Host::MacOs`'s guest slot -- and `x86_64`'s raw `@tpoff`-relative
  asm syntax is ELF/Linux-specific and has no Mach-O equivalent to copy
  directly.
  
  Two different pieces end up needing two different solutions to
  "per-thread state reachable without a function call, on Darwin":
  - The rewriter's gates are raw bytes patched into an arbitrary guest
    binary; they cannot call into Rust. They need the real fix above --
    a reserved, verified-safe direct-TSD offset from `TPIDRRO_EL0`.
  - The *platform's own* `run_thread_arch`/`switch_to_guest`/
    `syscall_callback` equivalent is code LiteBox writes and compiles itself,
    so it isn't bound by "no function calls": it can safely use an ordinary
    Rust `thread_local!` static (Darwin's TLV-based thread-local mechanism is
    mature, compiler- and OS-verified, and does not need to be hand-rolled)
    for `host_sp`/`host_fp`/`host_lr`/`in_guest`-equivalent bookkeeping,
    updated from normal (non-naked) Rust immediately around the naked-asm
    call sites rather than from inside the naked asm itself. This is a
    materially lower-risk design than matching x86_64's raw-TLS-in-asm style,
    and is real, buildable, unit-testable work independent of the harder
    rewriter-side fix above.
* **The guest-entry context switch itself**, once the above land. Also
  discovered this pass: AArch64 guest entry (`run_thread_arch` /
  `switch_to_guest` in the Linux terminology) is not implemented for *any*
  host in this repo yet, macOS included -- `litebox_platform_linux_userland`'s
  version is entirely `#[cfg(target_arch = "x86_64")]`, and LVBS's AArch64
  scaffolding (the `Exception`/`ExceptionInfo` types in `litebox/src/shim.rs`
  already have AArch64 variants, which *is* directly reusable) stops short of
  a working context switch too. There is no existing full AArch64 reference
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
