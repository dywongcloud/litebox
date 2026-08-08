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

* **`Host::MacOs`'s anchor register is right; the fixed TSD slot number is
  not, and the whole "bake one number in at packaging time" approach has a
  deeper problem than the number being wrong.** Gates anchor on `TPIDRRO_EL0`
  (real, tested) and address the guest thread pointer at pthread TSD slot
  `MACOS_GUEST_TPIDR_TSD_SLOT` (hardcoded to 256, sourced from
  apple-oss-distributions/libpthread as "the first dynamic
  `pthread_key_create` key") -- a LiteBox-owned slot rather than a raw offset
  into Apple's own pthread structure, so it no longer risks corrupting
  libpthread state the way the earlier design did.
  
  `litebox_platform_macos_userland::new` calls `pthread_key_create` at startup
  and records the key. It originally *asserted* the key equalled the baked slot
  -- **which always fails on real hardware**, making the platform
  unconstructable -- so that was softened (this pass) to a loud warning that
  leaves construction working (regression test
  `reserving_the_tsd_slot_does_not_panic_on_mismatch`); a syscall-only guest is
  unaffected, a `TPIDR_EL0`-using guest is unsupported until the real fix below.
  Measured on this M3 Pro (macOS 26.3.1): a minimal Rust binary's first
  `pthread_key_create` call returns 259; a plain C `main`'s first call
  returns 258. Neither is 256. Something in libSystem's startup path claims a
  few dynamic keys before user code runs, undocumented and not guaranteed
  stable across macOS versions or across binaries with different statically
  linked dependencies (each with their own static initializers, potentially
  claiming more). This means the actual slot a real runner binary gets is a
  property of *that specific binary's* full startup sequence -- not knowable
  by the rewriter, which runs separately, earlier, packaging the guest image
  with no visibility into what the eventual runner process will look like.
  
  The failure mode is safe (a loud warning at `MacOsUserland::new()`, not
  silent corruption), so this does not need the same "keep it out of anything
  that runs for real" mitigation the previous corruption bug did.

  **The rewriter half of the fix has landed; the loader half has not.**
  `Host::MacOs` gates no longer bake the slot number in. They read a byte offset
  from the trampoline header slot `HEADER_GUEST_TP_OFFSET_MACOS` and address
  `[TPIDRRO_EL0 + offset]`, which is what makes the number a load-time rather
  than a packaging-time decision. `Host::Linux` is untouched and still bakes its
  immediate, since its offset is genuine compile-time ABI; the two are now
  distinguished explicitly by `GuestTpAddressing`.

  The slot holds an *offset*, never a thread-pointer value. The loader maps the
  trampoline writable, fills the header, then flips it to read+execute
  (`litebox_common_linux`'s `load_trampoline`), so nothing can rewrite that word
  once a guest is running -- and one word could not serve two threads anyway. The
  per-thread part comes from `TPIDRRO_EL0`, which is already per-thread, so this
  design stays compatible with per-thread guest TPs rather than foreclosing them.

  **The loader half has landed too.** `SystemInfoProvider::get_guest_tp_slot_offset`
  reports the offset a host decides at run time (`None` on every host that bakes
  it in); `litebox_platform_macos_userland` answers with
  `guest_tp_slot_byte_offset()`, the reserved `pthread_key_create` key scaled by
  8. `litebox_common_linux`'s `load_trampoline` publishes it into the header slot
  in the same window it already writes the syscall entry point -- while the
  trampoline is still writable and before the flip to read+execute. That window
  is the only correct place for it. `litebox_common_linux` cannot depend on the
  rewriter, so `litebox_shim_linux` holds the two slot constants together with a
  `const` assertion rather than a comment.

  What remains for a `TPIDR_EL0`-using guest: `pthread_setspecific` of each guest
  thread's pointer into the reserved key, and a macOS runner to exercise any of
  it -- none wires `MacOsUserland` into `litebox_shim_linux` today, so this whole
  path is still unexercised end to end on hardware.
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
## Guest-entry context switch — DONE (implemented and hardware-tested)

AArch64 guest entry is implemented in `litebox_platform_macos_userland::guest`
and validated by the crate test `runs_a_guest_through_two_syscalls_and_exit`,
which drives a hand-assembled guest (reproducing the rewriter's exact `SVC`-gate
output) through the real `run_thread` on an M3 Pro: `write` syscall, resume,
`exit`, with every register faithfully round-tripped. There was no existing
AArch64 reference anywhere in the tree (`litebox_platform_linux_userland`'s
switch is entirely `#[cfg(target_arch = "x86_64")]`), so this pioneered it for
the project.

The mechanism, and why, established empirically on this hardware:

* **No userland instruction atomically restores all GPRs + `PC`** (`ERET` is
  EL1+), and every indirect branch (`BR`/`RET`) reads a GPR, so entry must
  sacrifice exactly one register as the branch vehicle.
* **`setcontext` (the `ucontext` API) was ruled out.** A probe showed Darwin's
  `setcontext` resumes by `ret`-ing to `__ss.__lr` (its `__pc` stays 0),
  forcing `X30 == PC` on arrival. glibc/musl keep a live `X30` across an `SVC`,
  so that clobber breaks real guests — strictly worse than the chosen vehicle.
  (It is also deprecated since macOS 10.6.) `getcontext`/`swapcontext` do work
  (verified), but this property makes them unfit for *resume*.
* **`setjmp`/`longjmp` is UB across Rust frames**, so the exit/return path uses
  a normal Rust return instead.

Implemented design (a hand-rolled `swapcontext`): `enter_guest_asm` restores
all of `X0`-`X30`, `SP` and `NZCV` from `PtRegs` and branches through **`X16`**
as the vehicle — safe because the rewriter's own `SVC` gate already treats
`X16` as scratch and neither glibc nor musl keeps a live `X16`/`X17` across an
`SVC`. `syscall_callback` captures the full guest file back into `PtRegs`
(a straight `STP` chain, the same spill-then-reuse shape as `emit_msr_gate`),
restores the host callee-saved state from a save area, and returns *normally*
into the Rust run loop. The whole enter→SVC→gate→callback→resume→exit loop was
prototyped in C on this hardware before porting, then re-proven by the crate
test. `PtRegs` field offsets are pinned to the asm by `const` assertions.

The switch also carries the guest's FP/SIMD state. `PtRegs` has nowhere to put
it -- it mirrors Linux's `struct pt_regs`, which has no FP fields because the
kernel is built without them -- so `GUEST_FP` holds the full `v0`-`v31` plus
`FPCR`/`FPSR` beside it, and `HOST_SAVE` gained the host's callee-saved `d8`-`d15`
and its own `FPCR`/`FPSR`. This was missing when the switch first landed, and
nothing caught it: the register-fidelity test checked only general-purpose
registers, so a guest holding live vector state across its `SVC` -- which Linux
permits, and which glibc's and musl's string routines actually do -- got host
garbage back, while host code lost `d8`-`d15` to the guest.
`preserves_fp_state_across_capture_and_resume` covers it now; removing the
restore makes that test fail on hardware while the two older ones still pass.

Remaining, smaller, follow-ups on top of the working switch:
* Host bookkeeping (save area + live-`PtRegs` pointer) is process-global, so
  **one guest thread at a time** (a second panics loudly). Per-thread needs the
  same `TPIDRRO_EL0` direct-TSD reach the rewriter gates need (below).
* Only the **syscall** event path is wired; guest hardware faults and the
  `SIGUSR2` interrupt path are not yet routed to `EnterShim::exception`/
  `interrupt`.
* `enter_guest_asm` stages `PC`/`X0` in the 16 bytes below the guest `SP`
  (AArch64 has no red zone), so guest-directed signals must stay on a
  `sigaltstack`.

These, plus the guest thread-pointer plumbing, are what stand between "a
syscall-only guest runs end to end" (true today) and "an arbitrary unmodified
Linux binary runs."
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

## The test suite's own macOS gaps

Running `cargo test` on an Apple Silicon machine surfaced defects in the tests
rather than in the code they cover. Three are fixed; one is not.

* **Fixed:** the globals ratchet listed no prefix for
  `litebox_platform_macos_userland`, so the check failed on three files and
  `cargo test` could not pass on any macOS machine. The copyright check had no
  header rule for the vendored `tencent-bd-dashboard/` tree (135 TypeScript/TSX
  files), which is not LiteBox's to license; it is skipped by directory now.
  `litebox/src/mm/tests.rs` hardcoded the Linux `TASK_ADDR_MIN`, which is below
  `__PAGEZERO` on arm64 Mach-O, so every mapping failed with `BelowMinAddress`;
  it derives the floor from the backend now. The 9P tests drive a real `diod`
  server, packaged for Linux only, and panicked on the missing binary rather than
  testing anything -- they are gated to Linux.

* **Fixed since:** `litebox_shim_linux` now passes in full on this host. Its mm
  tests had written sizes as literal `0x1000`/`0x2000`, which are page-sized only
  where `PAGE_SIZE` is 4096; they derive from `PAGE_SIZE` now. The ELF loader
  test built a synthetic image claiming `EM_X86_64` and asking to load at
  `0x400000` -- rejected outright on this host, the first for the wrong machine
  and the second for sitting under `__PAGEZERO`. Both derive from the host now,
  and it releases its images before returning.

* **The remaining flakiness is two timer tests, and it is a real property of the
  host.** `test_timer_delivers_correct_signal` and `test_alarm_with_sigign` pass
  every time alone and fail intermittently under a loaded parallel run. Darwin
  has no POSIX timers, so the platform runs a thread per timer parked on a
  condition variable (see `docs/macos.md`); that is inherently more
  schedule-sensitive than a kernel timer, and a busy test binary can miss the
  window. Worth deciding whether the tests should assert a looser bound or the
  platform should hold a deadline more firmly -- not worth papering over with a
  retry.

* **A per-task VMM does not model the host's own mappings.** Every task maps into
  one host address space while its virtual-memory manager tracks only what it
  allocated, so two tasks in a process place addresses without seeing each other.
  This is invisible where the guest range sits clear of the host's own image, and
  routine on arm64 macOS where both live above the 4 GiB floor -- the loader test
  leaked two images and broke five later tests that way. Serializing the mapping
  tests (`address_space_guard`) makes the suite deterministic, but the underlying
  gap is real: `test_collision_with_global_allocator` covers exactly this and is
  still gated to Linux and Windows, so macOS has never been checked for it.

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
