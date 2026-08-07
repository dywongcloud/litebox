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

CI covers this in the `Build and Test macOS (Apple Silicon)` job.

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

1. **The host binary must be signed with the JIT entitlement.** Create an
   entitlements file:

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
   per thread, never both. `litebox_platform_macos_userland::jit_write_protect`
   wraps `pthread_jit_write_protect_np`; every write into guest code pages —
   loading segments, applying the rewriter's patches — has to sit between
   `jit_write_protect(false)` and `jit_write_protect(true)`.

   A corollary for `update_permissions`: a region that has to become executable
   *later* must still be allocated with `EXEC` in its initial permissions, since
   only a `MAP_JIT` mapping can gain `PROT_EXEC`.

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

Guest entry is the one seam that is not implemented. It lives in
`litebox_platform_macos_userland::guest` and is documented there; the summary:

1. **A host thread-pointer anchor.** The rewriter's gates read `TPIDR_EL0` and
   expect the guest's own thread pointer at `[TPIDR_EL0 + GUEST_TPIDR_OFFSET]`.
   Darwin keeps the thread self-pointer in `TPIDRRO_EL0` and does not document
   `TPIDR_EL0` as available to userland, so **whether Darwin preserves
   `TPIDR_EL0` across a context switch has to be established on real hardware
   before it can be used as the anchor.** If it does not, the anchor must move to
   a Darwin-owned per-thread slot and the rewriter needs a `Host::MacOs` variant
   emitting gates against it.
2. **Filling the trampoline.** The rewriter writes the syscall-callback address
   at offset 0 of the trampoline it appends to the image; the loader must write
   `SystemInfoProvider::get_syscall_entry_point` there before any guest `SVC`
   runs.
3. **The context switch itself** — save host state, load the guest's from
   `PtRegs`, branch to `pc`, and reverse it in the callback. This is the
   counterpart of the other platforms' `run_thread_arch`.

Two smaller gaps worth recording:

* `sa_restorer` is required. With no vDSO, a guest that registers a handler
  without `SA_RESTORER` has nowhere to return to, and delivery is refused rather
  than entering the handler with a wild `x30`. AArch64 glibc relies on the vDSO
  trampoline, so a runtime-provided sigreturn trampoline is the real fix.
* FP/SIMD state is not saved into or restored from the signal frame. The
  reserved area is left zeroed, which is a well-formed empty record chain, but a
  handler that inspects or modifies vector state will not see it. The x86-64 path
  has the same gap with `fpstate`.
