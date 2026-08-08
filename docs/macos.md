# LiteBox on macOS (Apple Silicon)

LiteBox runs guest instructions natively; only the *system* interface is
virtualized. On an Apple Silicon Mac that means the only sensible configuration
is an **AArch64 Linux guest on an AArch64 macOS host** — no emulation anywhere.
There is deliberately no x86-64 macOS platform: an x86-64 guest would need
instruction emulation, which is the thing this design exists to avoid.

This document covers what works today, what the host imposes, and what is left
before a guest can actually execute.

## What is in the tree

| Piece | State |
| --- | --- |
| `litebox_platform_macos_userland` | The macOS "South" platform: memory, locking, time, signals, timers, threads, TLS, randomness, derived keys, stdio, `utun` networking, fault recovery. |
| `litebox` core | Builds for `aarch64-apple-darwin`, including the Mach-O exception table. |
| `litebox_shim_linux` | The Linux "North" shim, ported to AArch64: signal frames, syscall entry/return, thread-pointer handling, `stat`/`uname` ABI, exception decoding. |
| `litebox_syscall_rewriter` | Already had AArch64 support (`arm64.rs`) for rewriting `SVC` and `TPIDR_EL0` accesses in Linux ELF images. |
| `litebox_packager` | OCI mode now pulls the image matching the host architecture, and builds on Apple Silicon. |
| Guest entry | **Not implemented.** See [Remaining work](#remaining-work). |

## Building

```sh
rustup target add aarch64-apple-darwin
cargo build --workspace --exclude litebox_runner_lvbs --exclude litebox_runner_snp
```

`litebox_runner_lvbs` and `litebox_runner_snp` are freestanding images for
custom targets and are not built for a hosted target on any platform.

CI covers this in the `Build and Test macOS (Apple Silicon)` job, which also
compiles and runs `litebox_platform_macos_userland/tests/darwin_abi_probe.c`
against the runner's real SDK headers -- the only check in this repo that
verifies the crate's hand-written Mach/BSD struct layouts (used by the fault
handler to read `ucontext_t::uc_mcontext`) against an actual Darwin toolchain,
since nothing else in a Linux-hosted development loop can.

## What the host imposes

### 16 KiB pages

Apple Silicon's page size is 16 KiB. Every fixed mapping and every protection
change must be aligned to it, so `litebox::mm::linux::PAGE_SIZE` is 16384 on
this target rather than 4096. The guest sees the same value through `AT_PAGESZ`,
which is exactly how a Linux kernel configured for 16 KiB or 64 KiB pages
reports itself.

AArch64 ELF images are conventionally linked with a 64 KiB maximum page size, so
their `PT_LOAD` segments stay aligned either way. An image built with 4 KiB
segment alignment will not map cleanly.

### The first 4 GiB is unusable

An arm64 Mach-O process reserves `[0, 4 GiB)` as the `__PAGEZERO` segment:
unmapped and impossible to map over. `TASK_ADDR_MIN` is therefore `0x1_0000_0000`.

The practical consequence is that guest images must be position-independent, or
linked above 4 GiB. An `ET_EXEC` binary linked at the customary `0x400000`
cannot be loaded at its preferred address on this host.

### W^X, `MAP_JIT`, and code signing

macOS refuses to make anonymous memory executable through the ordinary path, and
refuses to add `PROT_EXEC` to anything that was ever writable. The supported
escape hatch is `MAP_JIT`, which the platform passes whenever a mapping requests
`EXEC`. Using it has two consequences:

1. **The JIT entitlement is only load-bearing under the Hardened Runtime.**
   Per Apple's own documentation, `com.apple.security.cs.allow-jit` is required
   only when a binary has the Hardened Runtime enabled (`codesign --options
   runtime`, which in turn is what notarization requires); without it,
   `MAP_JIT` works with or without the entitlement present. The command below
   ad-hoc-signs with the entitlement anyway -- it costs nothing and future-proofs
   a later `--options runtime`, notarized build -- but for local development
   outside Gatekeeper, neither the entitlement nor notarization is actually
   required for `MAP_JIT` itself to work. Create an entitlements file:

   ```xml
   <?xml version="1.0" encoding="UTF-8"?>
   <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
     "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
   <plist version="1.0">
   <dict>
       <key>com.apple.security.cs.allow-jit</key>
       <true/>
   </dict>
   </plist>
   ```

   and sign the runner with it:

   ```sh
   codesign --sign - --entitlements litebox.entitlements --force <binary>
   ```

2. **Writes must be bracketed.** A `MAP_JIT` mapping is writable *or* executable
   per thread, never both. The platform exposes this through
   `PageManagementProvider::jit_write_protect` (a no-op on every other host),
   and `litebox_shim_linux` routes all of its code writes — the rewriter's
   patches, trampoline stubs, trap fallback — through a `write_code_bytes`
   helper that brackets each one with it.

3. **A mapping only becomes `MAP_JIT` by being created that way**, but LiteBox's
   universal pattern for code pages is allocate-RW, write, then flip to RX
   (`create_executable_pages`), and a JIT-ing guest's own
   `mmap(RW)`/`mprotect(RX)` is the same shape. `update_permissions` therefore
   treats a refused `mprotect(+EXEC)` as the signal to *migrate*: it copies the
   contents to a fresh `MAP_JIT` mapping, moves it over the original range with
   `mach_vm_remap`, applies the requested protection, and invalidates the
   instruction cache for the range (`sys_icache_invalidate`) — after which it
   looks as if the `mprotect` simply succeeded. This is the load-bearing path
   for all executable guest pages on this host.

4. **`MAP_JIT` cannot be combined with `MAP_FIXED`.** Real Darwin rejects an
   `mmap` that requests both flags in one call, so a fixed-address allocation
   that needs `EXEC` (`PageManagementProvider::allocate_pages`'s
   `allocate_jit_pages` path) creates the mapping at a kernel-chosen address
   first, then relocates it with `mach_vm_remap`
   (`VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE`, `copy = FALSE`). This is the same
   create-then-remap sequence used by OpenJDK's fix for
   [JDK-8234930](https://bugs.openjdk.org/browse/JDK-8234930) and by V8's
   `OS::RemapPages`; `mach_vm_remap`'s entry-copy path preserves the mapping's
   `used_for_jit` property across the move rather than re-deriving it from the
   flags passed to the remap call itself.

### Instruction-cache maintenance

Apple Silicon does not keep the instruction cache coherent with the data
cache automatically. Every write into memory that is about to execute --
loading a segment, the rewriter patching syscall instructions or trampolines
in place -- has to be followed by an explicit cache-maintenance sequence
before the CPU can safely fetch from it, or a core can execute stale
instructions left over from before the write. `litebox_shim_linux`'s
`sys_mprotect_raw` is the single choke point every transition to `PROT_EXEC`
passes through (the public `sys_mprotect`, the ELF loader, and the syscall
rewriter's in-place patching all end up calling it), so that is where
`clear_icache_range` runs: `dc cvau` over the range at the host's D-cache line
size (read from `CTR_EL0`), a `dsb ish`, then `ic ivau` at the I-cache line
size, and a final `dsb ish` + `isb`. This is AArch64-specific and a no-op on
other architectures, where cache coherency between store and fetch is
maintained by the hardware.

### Missing Linux primitives, and what replaces them

| Linux | macOS |
| --- | --- |
| `futex` | `__ulock_wait2` / `__ulock_wake` with `UL_COMPARE_AND_WAIT_SHARED`. The public `os_sync_wait_on_address` only exists from macOS 14.4, which would exclude earlier M-series machines. |
| `MAP_FIXED_NOREPLACE` | `mach_vm_allocate` with `VM_FLAGS_FIXED`, which fails with `KERN_NO_SPACE` when the range is occupied, then `mmap(MAP_FIXED)` over the reservation. |
| `MAP_POPULATE` | `madvise(MADV_WILLNEED)`. |
| `MAP_GROWSDOWN` | No equivalent; guest stacks must be pre-sized. |
| `timer_create` | A thread per timer parked on a condition variable. Darwin has no POSIX timers and only one `setitimer` per process. |
| `/dev/net/tun` | A `utun` kernel-control socket. Every datagram carries a 4-byte address-family header, which the platform adds and strips so the rest of LiteBox sees bare IP packets. Creating the interface needs root. |
| `/proc/sys/kernel/random/boot_id` | The `kern.bootsessionuuid` sysctl, used as the `DerivedKeyProvider` root key. |
| `getrandom` | `arc4random_buf`, a direct pass-through to the platform CSPRNG. |
| `__start_ex_table` / `__stop_ex_table` | `getsectiondata` over `__TEXT,__ex_table` via `__dso_handle`. Mach-O has no linker-synthesized bounds for arbitrary sections, so the table is found from the image headers, the same way the Windows platform finds its PE section. |
| vDSO | None. `get_vdso_address` reports `None`, so a guest signal handler must supply its own `sa_restorer` — the kernel's fallback trampoline lives in the vDSO. |

The host reserves `SIGUSR2` for interrupting a thread out of guest execution;
Darwin has no realtime signals to take it from instead.

## Remaining work

See also [`docs/roadmap.md`](./roadmap.md) for this and everything else
outstanding across the tree, grouped by how much verification each item
needs before it can land.

Guest entry is the one seam that is not implemented. It lives in
`litebox_platform_macos_userland::guest` and is documented there; the summary:

1. **A host thread-pointer anchor.** **Resolved on real hardware (Apple M3
   Pro, macOS 26.3.1): `TPIDR_EL0` does *not* survive a context switch and
   cannot be used as the guest thread-pointer anchor.** A probe that wrote a
   sentinel into `TPIDR_EL0`, then read it back after `thread::sleep` (a
   voluntary reschedule) and again from inside a `SIGUSR1` handler, found the
   register already overwritten by the time execution resumed in both cases
   -- overwritten with the *same* small value (`0x1009` in the run that
   established this) each time, meaning XNU's own scheduler or pthread
   runtime actively repurposes this register for its own bookkeeping rather
   than merely leaving it stale. `TPIDRRO_EL0`, by contrast, was confirmed
   stable across the same reschedule (`0x1fda871e0` before and after
   `thread::sleep`) and distinct per thread (a second thread read
   `0x16dd330e0`) -- consistent with Apple's own documented use of it as the
   pthread self-pointer. The anchor therefore has to move to a Darwin-owned
   per-thread slot reachable from `TPIDRRO_EL0` (the same "direct TSD" fast
   path libSystem's own `errno`/QoS-class accessors use: read `TPIDRRO_EL0`,
   index a small fixed offset into the per-thread block it points at), and
   the rewriter needs a `Host::MacOs` variant emitting gates against that
   instead of `TPIDR_EL0`. Concretely: reserve one pthread TSD slot for
   LiteBox's guest-pointer value (`pthread_key_create` at platform-init time
   is the safe, public way to reserve a slot number rather than guessing an
   unused "direct" index), have the platform's thread-entry path
   `pthread_setspecific` the guest thread pointer into it once per guest
   thread, and have the rewriter's gates read it back through the same
   `TPIDRRO_EL0`-relative sequence libSystem uses internally for a direct-TSD
   read, rather than going through the full `pthread_getspecific` call --
   the whole reason `TPIDR_EL0` looked attractive originally was a
   single-instruction anchor, and a fast, inlined `TPIDRRO_EL0`-relative read
   is the only replacement that keeps that property.

   `litebox_syscall_rewriter::Host::MacOs` now implements **both** halves of
   this: the anchor register (`MRS Xd, TPIDRRO_EL0`, real-toolchain verified)
   and the slot addressing -- gates address the guest thread pointer at
   pthread TSD slot `MACOS_GUEST_TPIDR_TSD_SLOT` (index 256, sourced from
   apple-oss-distributions/libpthread as the first dynamic
   `pthread_key_create` key), i.e. `[TPIDRRO_EL0 + 256 * 8]`, **not** a raw
   offset into Apple's own pthread structure, so it no longer risks
   corrupting libpthread state. `litebox_platform_macos_userland::new` now
   calls `pthread_key_create` at startup and asserts the returned key matches
   -- and **that assertion currently always fails on real hardware.** A
   minimal Rust binary's first `pthread_key_create` call returns **259**, not
   256, measured on this same Apple M3 Pro/macOS 26.3.1 (a plain C `main`'s
   first call returns 258 -- still not 256, so this isn't even Rust-runtime-
   specific). Something in libSystem's own startup path claims a few dynamic
   keys before any user code runs, and that count is not part of any
   documented contract -- it can plausibly differ across macOS versions, or
   across different binaries depending on exactly what else gets statically
   linked in and runs its own static initializers first. This means the
   entire "bake one fixed slot number into the rewriter's gates at packaging
   time" design has a deeper problem than picking the wrong constant: the
   actual slot `pthread_key_create` returns is a property of the *specific
   runner binary's* full startup sequence, which the rewriter (a separate
   process, running separately, earlier, with no visibility into that) cannot
   know in advance. The failure mode is safe -- a loud panic at
   `MacOsUserland::new()`, not silent corruption, since the assertion added
   this pass exists precisely to catch this -- but the feature does not work
   yet. Fixing it needs either verifying the actual runner binary's granted
   slot empirically and keeping the rewriter and runtime in lockstep on it
   (fragile, breaks on any dependency change), or a different mechanism
   entirely that doesn't require the AOT-rewritten gates to predict a
   runtime-assigned number. What remains before a guest actually runs also
   still includes `pthread_setspecific`-ing each guest thread's pointer into
   whichever slot is actually reserved -- part of guest entry (item 3 below),
   still unimplemented.
2. **Filling the trampoline.** The rewriter writes the syscall-callback address
   at offset 0 of the trampoline it appends to the image; the loader must write
   `SystemInfoProvider::get_syscall_entry_point` there before any guest `SVC`
   runs.
3. **The context switch itself** — save host state, load the guest's from
   `PtRegs`, branch to `pc`, and reverse it in the callback. This is the
   counterpart of the other platforms' `run_thread_arch`.

Three smaller gaps worth recording:

* `sa_restorer` is required. With no vDSO, a guest that registers a handler
  without `SA_RESTORER` has nowhere to return to, and delivery is refused rather
  than entering the handler with a wild `x30`. AArch64 glibc relies on the vDSO
  trampoline, so a runtime-provided sigreturn trampoline is the real fix.
* FP/SIMD state is not saved into or restored from the signal frame. The
  reserved area is left zeroed, which is a well-formed empty record chain, but a
  handler that inspects or modifies vector state will not see it. The x86-64 path
  has the same gap with `fpstate`.
* `SignalProvider`'s pending-signal bitmap (`PENDING_SIGNALS`) is process-wide,
  not per-thread. A `TimerProvider::create_timer` timer always wakes the
  specific thread that created it (see the `TimerHandle` docs in
  `litebox_platform_macos_userland/src/lib.rs` for why, and why it deliberately
  does *not* go through a real `SIGALRM`), so that path is correct even with a
  single guest thread active. A genuinely external asynchronous signal (a real
  host `SIGINT`/`SIGALRM` arriving from outside the process) instead relies on
  whichever thread the kernel happens to deliver it to also being the one
  that's actually blocked -- the same imprecision `litebox_platform_linux_userland`
  has without its `SIGALRM`/`SIGINT`-blocked-on-non-guest-threads discipline
  (see its `register_exception_handlers`). Neither of these is reachable by a
  real multi-threaded guest yet, since guest entry itself isn't implemented
  (above), but a proper fix -- per-thread pending-signal state plus the same
  signal-mask discipline Linux uses, or `pthread_sigqueue` if Darwin's payload
  delivery turns out to support it -- is worth doing before multi-threaded
  guest signal delivery is trusted.
* ~~`jit_write_protect` is not called from anywhere that writes guest code.~~
  Closed: `PageManagementProvider::jit_write_protect` (no-op default,
  `MacOsUserland` override) now brackets every code write in
  `litebox_shim_linux` via its `write_code_bytes` helper, and
  `update_permissions`' migrate-to-`MAP_JIT` path brackets its own copy.
  Still unverified on real hardware, like everything else on this list.
