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

  **Update, now exercised end to end on real hardware (Apple M-series, macOS
  ARM, this project's own `boxer`):** the gap above is real and reproduces
  exactly as predicted, now that two unrelated blockers that had prevented any
  guest from getting this far are separately fixed (see `docs/macos.md`'s "The
  first 4 GiB is unusable" -- a plain `cargo build` produces an `ET_EXEC`
  binary that can't load on this host at all -- and `boxer build`'s
  `--rewrite-host` default, which previously always anchored arm64 gates on
  `Host::Linux` regardless of the actual build host). With both fixed, a
  static-PIE musl guest now loads and starts executing -- and the first
  `MSR TPIDR_EL0`/`MRS TPIDR_EL0` gate it hits (musl's own TLS bootstrap, which
  every real guest does, not just an unusual one) segfaults reading/writing
  `[TPIDRRO_EL0 + baked_slot * 8]`, because the process's actual
  `pthread_key_create` key (261, measured once on this session's `boxer`
  build) doesn't match `MACOS_GUEST_TPIDR_TSD_SLOT` (256, baked) -- confirmed
  by instrumenting `reserve_guest_tpidr_tsd_slot` directly and reading the
  mismatch it already detects and warns about. The exact key number is
  itself an artifact of this specific binary's static-initializer order (see
  `reserve_guest_tpidr_tsd_slot`'s own doc comment on why it's "undocumented
  and not stable"), so it will drift across rebuilds/toolchain versions and
  is not worth chasing as a number -- what's durable is that it drifts *at
  all*, since the rewriter's gates need it fixed at AOT-rewrite time. In
  practice this makes every real guest's own TLS bootstrap a coin flip on
  this host today, not a hard 100% failure: `boxer compose` on the
  multibox-x11-composition example, same session, same binaries, had
  `x11server` and `app` both reach their own `main()` (bind/connect
  succeeded) on one run and not on others. **So: every real-world guest on
  this platform is at risk of this gap, unreliably** -- not just one that
  unusually happens to touch `TPIDR_EL0`, and not reliably enough to call
  "working" until the key is read at runtime instead of baked in.

  **Correction, traced further this session: "the key is read at runtime
  instead of baked in" is not what's missing -- that part already works.**
  `MacOsUserland::get_guest_tp_slot_offset` calls
  `guest_tp_slot_byte_offset()`, which computes the offset from the *actual*
  `pthread_key_create` key this process got (`guest_tp_tsd_key() *
  size_of::<usize>()`), not the baked constant; `litebox_shim_linux`'s ELF
  loader threads that real value into the trampoline header at load time
  (`ElfFile::new` → `parse_trampoline` → `load_trampoline`'s
  `mem.write(slot, &offset.to_ne_bytes())`). Every gate the rewriter actually
  patched reads its anchor from that header at guest-run time, so it sees the
  real key regardless of what got baked at package time -- the "read
  at runtime instead of baked in" fix described above is already landed and
  wired correctly, verified by tracing the full call chain, not by rerunning
  the failing case. Given that, a *patched* `MSR`/`MRS TPIDR_EL0` gate cannot
  be what's segfaulting on the real key.

  **Second correction, same session: the "AOT rewriter misses an unpatched
  occurrence" hypothesis this paragraph previously offered is also wrong --
  checked directly, not left as a guess.** Built a standalone tool
  (`litebox_packager::rewrite_elf_for(data, path, EM_AARCH64, Host::MacOs,
  true)` invoked outside the packaging pipeline, dumping the rewritten ELF to
  a plain file) and scanned every 4-byte-aligned word in a rewritten
  `x11-server` for the exact instruction encodings
  `litebox_syscall_rewriter::arm64` itself defines
  (`MSR_TPIDR_EL0_MASK`/`_BITS`, `MRS_TPIDR_EL0_MASK`/`_BITS`): zero matches,
  anywhere in the file. Every raw `TPIDR_EL0` touch was found and patched --
  the earlier live crash trace showing `mrs x16, TPIDR_EL0` (the wrong,
  Host::Linux-style register) was from a build made *before* this session's
  `--rewrite-host` default fix (`docs/macos.md`'s entry above), not evidence
  of anything still broken today. Also confirmed the *correct*
  `Host::MacOs` pattern (`MRS_TPIDRRO_EL0_BITS`) is present -- 35 occurrences
  -- and disassembled one with `capstone`: `mrs x8, tpidrro_el0` followed by
  `ldr x8, [x8, x16]`, where `x16` was itself just loaded via `ldr x16,
  #<trampoline+8>` -- a genuine memory load of the offset, not a baked
  immediate, and `<trampoline+8>` matches
  `litebox_common_linux::loader::TRAMPOLINE_GUEST_TP_SLOT_OFFSET` (`8`)
  exactly. Every piece of this mechanism -- correct register, correct
  patching, correct memory-indirect offset read, correct header slot address
  -- checks out under direct inspection.

  **So the mechanism is structurally sound and the live crash (`boxer run`
  on this exact rewritten box, same session, same key mismatch: 259 actual
  vs. 256 baked) is still real and still unexplained.** Either the loader's
  `load_trampoline` write of the real offset into that header slot isn't
  actually landing at runtime for some reason not yet identified, or the
  crash has nothing to do with `TPIDR_EL0` at all and only coincided with
  the slot-mismatch warning by observation bias. Getting a live disassembly
  of the actual faulting instruction to settle this needs `lldb` attached to
  the guest process at the moment of the fault; this session's sudo access
  is scoped to running `boxer run`/`boxer compose` directly (see the
  `NOPASSWD` entry this session added), which `sudo lldb -- boxer run ...`
  cannot use (sudoers matches the exact command invoked, and that command
  would be `lldb`, not `boxer`) -- and no macOS crash report was generated
  to inspect after the fact either (litebox's own `SIGSEGV` handler catches
  the fault and exits cleanly before the OS reporter would see it). Widening
  that `NOPASSWD` rule to cover `lldb` attached to a `boxer`-spawned guest,
  or adding a way to dump the faulting register state from inside litebox's
  own fault handler, is the concrete next step -- not another guess at what
  the rewriter might have missed, since direct inspection now rules that
  out specifically.

  **Third correction, same session: the live fault has nothing to do with
  `TPIDR_EL0`/TSD at all -- it's musl's static-PIE self-relocation applying a
  zero load bias.** Took the second concrete next step above (dumping the
  faulting register state from litebox's own fault handler, via temporary
  `libc::write(2, ...)` instrumentation in the `guest::GUEST_OWNS_CPU` branch
  of `fault_handler`, `litebox_platform_macos_userland/src/lib.rs` -- added,
  used, and cleanly reverted this session; `git diff` on that file is empty)
  instead of chasing `lldb`/sudoers scope. The captured live crash: `pc =
  0x103a933f8`, `far = 0x81468`, `esr = 0x92000046` (a data abort, write),
  `x0 = 0x81468`. Disassembling the code at `pc` (via the standalone
  `litebox_packager::rewrite_elf_for` tool described above, applied to the
  same `x11-server` binary) shows:

  ```
  mov x4, x0
  adrp x0, #0x103acf000
  mov x2, #0
  ldr x0, [x0, #0xec8]
  str x19, [x0]        <-- faults here, writing through x0 = 0x81468
  ldr x3, [x19, x2, lsl #3]
  add x2, x2, #1
  cbnz x3, ...
  ```

  This is musl's `environ = envp` bootstrap in `__libc_start_main`/`_start_c`
  (the `str` writing the incoming `envp` pointer into the global `environ`
  slot), not TLS/TSD setup at all -- matching a pattern seen earlier in this
  same session before the other fixes landed, previously misattributed.
  Cross-referencing the *original*, unrewritten `x11-server` ELF's
  `.rela.dyn` table (`DT_RELA` at vaddr `0x2b0`, 573 entries, `entsize 24`)
  turns up the exact relocation this load is meant to have already resolved:
  `r_offset = 0x7fec8`, `r_type = 1027` (`R_AARCH64_RELATIVE`), `r_addend =
  0x81468` -- `0x7fec8` is exactly the `adrp`-page (`0x103acf000` relative to
  the load base) plus the `#0xec8` immediate above, so this is unambiguously
  *that* GOT slot. `R_AARCH64_RELATIVE`'s defined semantics are `*(base +
  r_offset) = base + r_addend`; the value musl's own self-relocation loop
  should have already written there, before `main` ever runs, is `base_addr +
  0x81468`. The value actually read back at the fault is the bare addend,
  `0x81468`, completely unrelocated -- i.e. **musl's static-PIE self-relocation
  computed and applied a load bias of exactly zero to this (and by
  construction, likely every) `R_AARCH64_RELATIVE` entry**, even though the
  surrounding code is demonstrably executing at the real, correct, high load
  address (`pc` and the `adrp` target both sit at `0x103a...`/`0x103ac...`,
  nowhere near a zero-based image) -- so this is not a case of the whole
  binary accidentally running unrelocated. The same unmodified binary was
  independently confirmed (earlier this session, via `podman run --platform
  linux/arm64`) to self-relocate correctly under a real, unmodified Linux
  kernel, so this is not a defect in the binary or in musl's relocation logic
  in general -- it reproduces specifically when run under litebox on macOS
  ARM.

  This conclusively rules out both prior hypotheses in this item (missing
  runtime-offset wiring; an AOT-rewriter-missed `TPIDR_EL0` gate) as the
  cause of *this* crash -- neither touches `.rela.dyn` processing at all --
  and narrows the open question to a different, more fundamental mechanism:
  why musl's own `_dlstart_c`/self-relocation bias computation (which is
  ordinarily just "the runtime load address minus the linked base address,"
  read via a PC-relative address-of-self trick before any relocation has run)
  comes out as zero specifically under litebox's guest-entry path, despite
  litebox's own segment placement and the guest's subsequent execution both
  being at the correct address. Candidates not yet checked: whether
  `litebox_common_linux::loader`'s auxv (`AT_PHDR`/`AT_BASE`/`AT_ENTRY`/
  `AT_PHNUM`) or initial register state (`sp`, `pc`) at guest entry differs
  from what a real Linux kernel hands a static-PIE `_start` in some way this
  bias computation depends on; and whether `MacOsUserland`'s guest-entry
  context switch clobbers or fails to set up something musl's self-relocation
  code reads before it has any other means of establishing its own load
  address. This is the concrete next step, and is more precise than -- and
  supersedes -- the `TPIDR_EL0`/TSD framing the rest of this item is written
  in: the guest's TLS/TSD bootstrap is never reached at all while its own
  `environ` setup, running moments earlier, is already faulting on unrelocated
  GOT data.
* **The platform's *own* per-thread context-switch bookkeeping** —
  REATTEMPTED and correctly deferred rather than force-implemented. A separate
  problem from the rewriter's guest slot above. Studying
  `litebox_platform_linux_userland`'s x86_64
  `run_thread_arch`/`switch_to_guest`/`syscall_callback` (the closest thing to
  a template) surfaced why: that code doesn't only virtualize the *guest's*
  thread pointer -- it also stashes its own bookkeeping (`host_sp`, `host_bp`,
  `guest_context_top`, `in_guest`) in `fs:`-relative TLS slots, because by the
  time `syscall_callback` runs, every general-purpose register holds live
  guest state and there is nothing else durable to read "where was the host
  stack" from. That mechanism is entirely x86_64-ELF-specific (raw
  `@tpoff`-relative local-exec TLS addressing, resolved to a link-time-fixed
  offset with no function call and no runtime-determined value at all) and has
  no Mach-O equivalent to copy directly.

  **What this pass confirmed is genuinely usable, on real Apple M3 Pro
  hardware:** a raw `mrs tpidrro_el0` + `[base, #(key * 8)]` read/write reaches
  the *same* per-thread storage `pthread_getspecific`/`pthread_setspecific` do,
  for a **second**, independently `pthread_key_create`-reserved dynamic TSD
  key (not just the one already relied on for the guest's own `TPIDR_EL0`
  shadow) -- in both directions, across the full `usize` range, and disjointly
  across two genuinely concurrent OS threads. Previously only the key-to-offset
  *formula* had been checked against XNU header source; this pass wrote and
  ran a standalone hardware probe (raw inline `asm!`, `pthread_key_create`
  twice in the same process to reproduce the real deployment order, both
  directions of the round trip, boundary values, cross-thread disjointness)
  that exercises the *raw MRS-based read/write itself*, closing the gap the
  `macos-guest-tp-runtime-offset` item above flagged as "still unexercised end
  to end on hardware." This means a **second** reserved TSD key, read via the
  same direct-TSD mechanism, is a sound building block for host-side per-thread
  storage reachable from naked asm without a function call -- reusable beyond
  this specific attempt.

  **Register-budget analysis for `litebox_platform_macos_userland::guest`'s
  six naked functions**, checking whether each has two free registers to spare
  for that lookup (one for the runtime-determined TSD byte offset, one for the
  `TPIDRRO_EL0` value) at the point it would need to resolve a per-thread
  pointer:
  - `enter_guest_asm`: ample. At entry only `X0` (`ctx`) is live; the lookup
    can run before any guest register is restored, and its result (kept in one
    register for the rest of the function) needs no further register pressure
    at the later `GUEST_OWNS_CPU`/`PENDING_INTERRUPT` check either, since `X1`
    and `X16` are already established as free there.
  - `exception_callback`/`interrupt_callback`/`abort_on_boundary_stack_fault`:
    ample. Each is reached via a `pc` redirect (not a guest branch), so *every*
    register is free -- no guest state to preserve at all.
  - `sigreturn_trampoline`: ample. Its own doc comment already establishes
    that every register but `SP` is "don't care" here (only `sp` and a forced
    `syscallno` are captured), so any register is available as scratch.
  - **`syscall_callback`: genuinely constrained, and this is the blocker.** At
    entry, exactly one register (`X16`) is free -- the rewriter's `SVC` gate
    sacrifices it as its own branch vehicle. `X17` is *not* free: unlike
    `X16`, the gate never touches it, so it still holds the guest's real
    value, which real Linux AArch64 preserves across a syscall (the kernel's
    own entry path saves/restores every GPR faithfully; only this rewriter's
    *own* gate mechanism sacrifices `X16` specifically) and which this file's
    own fidelity philosophy (`preserves_registers_across_capture_and_resume`)
    otherwise commits to capturing faithfully. Two free registers are needed
    to combine a runtime-loaded TSD offset with `TPIDRRO_EL0`; one is not
    enough.

  **A candidate workaround was designed, implemented, and hardware-tested --
  and disproven, not merely judged risky.** The idea: since `enter_guest_asm`
  has registers to spare, let it pre-resolve the per-thread pointer once and
  stage it in a third word below the guest `SP` (extending the existing
  16-byte `PC`/`X0` staging area to 24 bytes), so `syscall_callback` only ever
  needs to *re-read* that word with its one free register, never re-derive it.
  Implemented in full (all six naked functions converted, a new
  `PerThreadGuestState` struct, `GUEST_ACTIVE`/`PENDING_EXCEPTION_INFO`
  converted to ordinary per-thread storage, `lib.rs` call sites updated) and
  run against the full existing hardware test suite. After fixing two
  self-inflicted bugs during iteration (a wrong relative offset, and an
  `SP`-alignment violation in a boundary test unrelated to the mechanism
  itself, both confirmed and fixed via `lldb`), **every existing test passed**
  -- including the exact-boundary `syscall_survives_a_guest_stack_with_only_16_valid_bytes_below_sp`
  test (extended to 24, later 32 for 16-byte `SP` alignment). This looked like
  success. It was not: a **targeted diagnostic guest**, added specifically to
  probe the one assumption the whole design rests on -- that the guest's `SP`
  at its *next* syscall equals what it was at the *most recent resume* -- push-
  es a 64-byte local-variable-style stack frame (`sub sp, sp, #64`, exactly
  what a real compiled function does before calling a library routine that
  issues a syscall) between the first syscall's resume point and the second
  syscall. It reproducibly crashed with `SIGSEGV`. Root cause, confirmed via
  `lldb`: the staged pointer lives at a fixed offset below the guest `SP` *as
  of the resume that staged it*; the `SVC` gate decrements `SP` from whatever
  the guest's `SP` actually is *at the moment of the syscall*, which shifts
  independently of that once the guest does any of its own stack management in
  between (i.e. essentially any real, non-trivial compiled program).
  `syscall_callback` then reads back a stale/wrong address, dereferences it,
  and crashes -- or, on an unluckier layout, would not crash and would instead
  write captured guest state through a wild pointer, a silent-corruption
  failure mode strictly worse than the crash actually observed. This is an
  architectural flaw in the *approach*, not an off-by-one in the
  implementation: no adjustment of the staging offset or word count fixes it.
  All code from this attempt was reverted; `litebox_platform_macos_userland`'s
  build/clippy/tests are unaffected (verified clean on real hardware after the
  revert).

  **What would need to be true for a future pass to succeed** -- this is the
  precise target the next attempt needs, not a repeat of "process-global,
  needs per-thread storage": `syscall_callback` needs a way to resolve its own
  thread's per-thread pointer using at most one spare register, in a way that
  does not depend on the guest's `SP` value staying constant between a resume
  and the guest's own next syscall. None of the following were pursued this
  pass, each for a stated reason, and any of them is a legitimate next step:
  - Extend `litebox_syscall_rewriter`'s `SVC` gate itself to also sacrifice
    `X17` (matching `X16`) or to relay the per-thread pointer freshly at
    *every* gate site (computed from the guest's own, always-correct-at-that-
    instant `SP`, not a stale resume-time snapshot) -- structurally sound,
    since the gate runs at the exact right moment, but this is a change to the
    AOT-rewritten guest-binary format in a *different* crate, affecting
    already-packaged binaries; out of scope for a pass scoped to
    `litebox_platform_macos_userland`.
  - Deliberately sacrifice `X17` fidelity in `syscall_callback` only (accept
    that `regs[17]` is no longer trustworthy after a syscall) -- structurally
    simple (frees a second register with no `SP`-dependent staging needed at
    all) but a real, if narrow, behavioral regression from today's faithful
    round-tripping that would need to be a deliberate, disclosed design
    decision (and a test update), not a side effect.
  - Some other mechanism not yet found. Self-modifying the crate's own compiled
    `.text` (to bake the TSD offset in as a patched immediate after
    `pthread_key_create` returns, needing only one register at each site) was
    considered and set aside as introducing a materially different, higher-risk
    class of complexity (mutating the host's own running code section, with no
    existing precedent anywhere in this codebase) than the rest of this
    attempt, not evaluated further.

  `GUEST_ACTIVE` and `PENDING_EXCEPTION_INFO` (2 of the 7 statics
  `dev_tests/src/ratchet.rs` counts here) are touched only from ordinary Rust,
  never from naked asm, and would convert to per-thread `thread_local!`s
  trivially in isolation -- but doing so without the other 5 would be actively
  harmful: `GUEST_ACTIVE` specifically exists to stop two threads from
  corrupting `HOST_SAVE`/`GUEST_FP`/`LIVE_PTREGS`/`GUEST_OWNS_CPU`, which stay
  process-global until `syscall_callback` can reach per-thread storage too, so
  it cannot be safely weakened alone.
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
  **one guest thread at a time** (a second panics loudly). Reattempted and
  correctly deferred (see "The platform's own per-thread context-switch
  bookkeeping" above): the `TPIDRRO_EL0` direct-TSD reach the rewriter gates
  need is confirmed sound for a second key, but `syscall_callback` cannot
  reach it with only its one free register, and the one workaround found
  (staging the pointer below `SP` at resume time) was hardware-disproven for
  guests that shift `SP` before their next syscall -- see that section for the
  precise remaining gap.
* **Resolved in a later pass:** the **syscall**, guest hardware fault
  (`SIGSEGV`/`SIGBUS`), and `SIGUSR2` interrupt event paths are all now wired
  to `EnterShim::syscall`/`exception`/`interrupt` respectively -- see "A guest
  fault no longer kills the host" and "The interrupt path (`SIGUSR2`) is not
  routed" below for the hardware-verified detail (the latter section's own
  heading predates its resolution; kept for the paragraph-level history it
  still documents).
* `enter_guest_asm` stages `PC`/`X0` in the 16 bytes below the guest `SP`
  (AArch64 has no red zone), so guest-directed signals must stay on a
  `sigaltstack`.

These, plus the guest thread-pointer plumbing, are what stand between "a
syscall-only guest runs end to end" (true today) and "an arbitrary unmodified
Linux binary runs."
* **The `jit_write_protect` bracketing gap is implemented; hardware
  confirmation is still outstanding.** `litebox_shim_linux`'s
  `write_code_bytes` helper now brackets every code write with
  `jit_write_protect(false)`/`(true)`, and both `maybe_patch_exec_segment` and
  `apply_trap_fallback` in `litebox_shim_linux/src/syscalls/mm.rs` route
  through it at every call site; `update_permissions`' own migrate-to-`MAP_JIT`
  path brackets its own copy independently. What remains: no automated test
  (in `mm.rs`'s own test module, `syscalls/tests.rs`, or
  `litebox_runner_linux_on_macos_userland`, which CI builds but never
  executes) exercises the JIT-migrate-then-patch-then-execute path end to end,
  so there is still no empirical evidence this actually resolves the SIGBUS
  the gap implied rather than papering over a misunderstanding of the API --
  see [`docs/macos.md`](./macos.md#wx-map_jit-and-code-signing), which
  correctly still marks this "unverified on real hardware."
* **Darwin ABI drift beyond what `darwin_abi_probe.c` already checks.** The
  probe (added this pass, see the `Build and Test macOS` CI job) covers the
  three hand-written struct layouts the fault handler depends on. Anything
  else hand-written against Darwin/Mach headers in the future should get the
  same treatment rather than trusting a one-time reading of the headers.

## Running a guest on macOS: what works, and the one thing left

`litebox_runner_linux_on_macos_userland` exists now, modelled on the
Windows-host runner: it builds, links and runs on Apple Silicon, and drives the
same North shim through `litebox_platform_macos_userland::run_thread`. Feeding it
a rewritten guest gets as far as the ELF loader, which is where the remaining
blocker is, and it is the documented one rather than a defect:

**A Linux guest now loads and executes.** `litebox_packager --oci-image
docker.io/library/alpine:latest` runs on this host (OCI mode is enabled for Apple
Silicon on purpose -- see the `cfg` on the OCI dependency block, whose comment
explains that `native-tls` is backed by Security.framework there), pulls the
arm64 image, and rewrites its 327 executables for `Host::MacOs`. The runner then
loads `/bin/busybox` out of that tar and reaches real syscall dispatch: the trace
shows the guest issuing `io_setup`, which the shim answers.

* **A guest image must be position-independent.** `hello-aarch64`, the fixture in
  `litebox_syscall_rewriter/tests`, is a static `ET_EXEC` linked at `0x400000`;
  an arm64 Mach-O process reserves the first 4 GiB as `__PAGEZERO`, so that fixed
  mapping is refused with `EPERM`. The OCI images are PIE and load fine.

Real Alpine programs run. `busybox uname -a` prints
`LiteBox litebox 5.11.0 5.11.0 aarch64 Linux`, `busybox cat /etc/alpine-release`
reads `3.24.1` out of the tar filesystem, `busybox pwd` and `busybox id` are
correct, and exit statuses propagate (a guest calling `exit(42)` gives the runner
exit 42).

**`x18` was not the blocker, contrary to what an earlier revision of this file
said.** The garbage syscall numbers that made a distro binary die with `SIGSEGV`
came from `syscall_callback` never filling `pt_regs::syscallno`: the shim reads
the AArch64 syscall number from that field, not from `regs[8]`, so every guest
syscall dispatched as whatever the guest stack happened to hold -- usually 0,
which is `io_setup`. Filling it, and `orig_x0` beside it, fixed both the
hand-written guest and Alpine. The 91 `x18`/`w18` references counted in `busybox`
are real, but they were not what broke it; XNU's `x18` zeroing remains a
documented restriction that has simply not bitten yet.

A shell runs: `busybox sh -c 'echo shell works; echo $((6*7))'` prints both
lines, and `ls`, `ls -l`, `wc` and `grep` all behave. Reaching that needed one
more fix, which was not macOS-specific: `sys_newfstatat` permitted only
`AT_EMPTY_PATH` and rejected `AT_SYMLINK_NOFOLLOW` with `EINVAL`, even though the
`do_fstatat` it delegates to already acts on that flag and both `statx` and
`faccessat` already accepted it. Every directory walker passes it, so `lstat`
failed on paths `stat` handled.

Known gaps a real guest hits now:

* **A guest fault no longer kills the host -- resolved on real hardware this
  pass.** `busybox sh -c 'f() { f; }; f'` overflows the guest stack; the guest
  `sh` task is now cleanly terminated (`litebox_shim_linux::syscalls::signal`
  logs `fatal signal: terminating task signal=Signal(11)`) and the *runner*
  exits normally (`exit(11)`) instead of the whole process dying with a raw
  signal. Verified against the exact scenario above through the real
  `litebox_packager --oci-image docker.io/library/alpine:latest` /
  `litebox_runner_linux_on_macos_userland` pipeline on an Apple M3 Pro, 3
  consecutive runs, plus two new hardware-run unit tests in
  `litebox_platform_macos_userland::guest::tests`:
  `delivers_a_genuine_guest_fault_to_the_shim_without_leaking_host_state` (a
  hand-assembled guest self-reports its about-to-fault `pc` via a syscall
  before dereferencing a null pointer, and seeds sentinels into `x9`/`x30`; the
  delivered `ExceptionInfo`/`PtRegs` are asserted to match the guest's own
  state exactly, closing the disclosure this item used to describe) and
  `syscall_survives_a_guest_stack_with_only_16_valid_bytes_below_sp` (a regression
  guard: a build that reverted to capturing onto the guest stack would crash
  this test with a raw `SIGSEGV`).

  The naive fix really was worse than the crash, for exactly the reason this
  entry used to describe: a "guest owns the CPU" flag the handler consults, with
  `syscall_callback` still writing its capture **onto the guest stack** before
  clearing it, lets a guest with `SP` near an unmapped page turn a safe crash
  into an ASLR disclosure and a return path into host code. The fix ported both
  pieces of `litebox_platform_linux_userland`'s ordering -- `GUEST_OWNS_CPU`
  cleared as the first instructions of `syscall_callback`, before any memory
  write -- but adapted the second piece (switching off the guest stack) to
  AArch64's register-pressure reality rather than copying it directly:
  `syscall_callback` now captures every guest GPR straight into the host-owned
  live `PtRegs` through a dedicated base register (loaded from `LIVE_PTREGS`),
  never decrementing `SP` at all, so it needs zero bytes of guest-stack headroom
  instead of the original 304. The two guest-stack reads that remain structurally
  necessary either side of the switch (the `SVC` gate's stashed `x16`/return
  address in `syscall_callback`; the below-`SP` staged `PC`/`X0` in
  `enter_guest_asm`) are bracketed with new exception-table entries recovering to
  a loud `std::process::abort()` -- both windows only ever touch bytes a write
  earlier in the *same* synchronous instruction stream just proved mapped, so
  they are unreachable by a bad guest `SP` in the normal case, and the
  exception-table check (which always runs before the `GUEST_OWNS_CPU` check)
  means they can never be misattributed to the guest even if that reasoning has
  a gap. This entry-side hazard -- symmetric to the exit-side one the task that
  produced this fix was originally scoped around -- was found during
  implementation, not anticipated going in; see
  `litebox_platform_macos_userland::guest::GUEST_OWNS_CPU`'s doc comment for the
  full mechanism.

  Known gap left deliberately open: a delivered exception's vector/FPSIMD state
  is not refreshed from the fault (Darwin's `mcontext` NEON state is not yet
  modelled, mirroring the interrupt path's identical, already-documented gap
  below), so a guest that resumes from a delivered signal after touching a
  vector register since its last syscall observes stale FP/SIMD content. This is
  a guest-observable correctness gap, not a host-state-disclosure one -- no host
  information crosses the boundary either way -- and today a guest fault never
  resumes at all, so it is a new, narrow rough edge on newly-added behavior,
  never a regression of anything that worked before.

  **Resolved in a later pass:** `darwin::McontextPrefix64` now carries the real
  `ArmNeonState64`, and `prepare_exception_delivery` refreshes `GUEST_FP` from
  it, so a delivered exception's vector state is the guest's genuine
  pre-fault state, not stale syscall-boundary content. See "`sa_restorer` and
  FP/SIMD signal-frame state" below for the hardware-verified detail.

* **The interrupt path (`SIGUSR2`) is not routed to `EnterShim::interrupt`
  either -- and it is a different problem from the fault one above, not the
  same one.** `litebox::event::wait::ThreadHandle::interrupt` only calls
  `ThreadProvider::interrupt_thread` while the target thread is between the
  shim's `prepare_to_run_guest`/`finish_running_guest` (state
  `RUNNING_IN_GUEST`), i.e. only while the platform's own guest-entry call is
  on the stack. On macOS that call is `guest::run_thread`'s
  `enter_guest_asm`/`syscall_callback` pair, and `interrupt_signal_handler`
  today takes no context and does nothing: `SIGUSR2` here currently only does
  its other job, EINTR-ing a blocking host call (see the
  `TimerProvider::create_timer` doc comment), which is a different thread
  state entirely.

  Unlike the fault case, a conservative "not in guest, do nothing but remember
  it happened" fallback is genuinely safe here -- it never copies host state
  into the guest's `PtRegs`, so getting the boundary slightly wrong in that
  direction is not an ASLR/host-return hazard. What is missing is still real
  new machinery, not a flag flip: both `litebox_platform_linux_userland` (a
  TLS `in_guest` byte plus `switch_to_guest_start`/`_end` labels) and
  `litebox_platform_windows_userland` (`SuspendThread`/`GetThreadContext`/
  `SetThreadContext` plus the same split) distinguish "mid-restoring a
  `PtRegs` that is still authoritative" from "genuinely executing guest code,
  where the live registers are now the truth" before they redirect, and
  `enter_guest_asm` has no labelled window today to make that distinction.
  The genuinely-in-guest case also needs the guest's live NEON/FPSIMD state
  out of the signal `ucontext_t`, which `darwin::McontextPrefix64`
  deliberately does not expose ("the NEON state that follows them is never
  touched," per its own doc comment), so it needs a new, independently
  verified struct alongside it. And `guest::run_thread`'s loop has no way
  today to tell "returned because of a syscall" from "returned because of an
  interrupt" -- unlike the Linux/Windows versions, whose asm calls a different
  native handler directly for each case, it always calls `shim.syscall` after
  `enter_guest_asm` returns, so a second return path needs a real signal
  between the two, not an inferred one. None of this touches a guest that only
  issues syscalls, which is still the common case and still runs end to end.

  **Resolved in a later pass (2026-08-10), on the third attempt at this exact
  row -- the first two correctly declined rather than forcing it.** What
  changed this time: the FP/SIMD signal-frame pass above had already landed
  `darwin::ArmNeonState64`, closing piece 2 for real (confirmed reusable, not
  just assumed -- `guest::prepare_interrupt_delivery` copies from it exactly
  the way `prepare_exception_delivery` already did). That still left pieces 1
  and 3, plus a genuinely new piece 4 this pass's own implementation found
  along the way (below), all implemented:

  1. **The labelled boundary.** `enter_guest_asm` gained a `switch_to_guest_start`/
     `_end` label pair around its own restore tail (from where `GUEST_OWNS_CPU`
     is set true through the branch to guest `pc`), and `syscall_callback`/
     `sigreturn_trampoline` each gained a whole-function `_start`/`_end` pair
     covering their own brief ownership-clearing prologue. `lib.rs`'s
     `interrupt_signal_handler` checks these ranges against the interrupted
     `pc` (from the real signal `mcontext`, the same source `fault_handler`
     already trusts) *after* checking `GUEST_OWNS_CPU`, mirroring the
     exception-table-then-flag priority `GUEST_OWNS_CPU`'s own doc comment
     established for the fault path: the flag alone is precise enough for a
     *synchronous* fault (which can only land on an instruction that faults,
     all of which are already either genuinely guest or covered by an
     exception-table entry), but not for an *asynchronous* `SIGUSR2`, which can
     land on any instruction in the handful-of-instructions-wide window between
     the flag flipping true and the guest's own registers actually becoming
     live -- a real, narrow, but genuine gap `GUEST_OWNS_CPU` alone does not
     close, confirmed by walking that exact instruction sequence rather than
     assumed by analogy to the fault case.
  2. Confirmed reusable, not duplicated: see above.
  3. **The second return path.** A third `guest::GuestExit` variant
     (`Interrupt`), a new `interrupt_callback` naked function (structurally
     `exception_callback`'s twin, reporting `2` instead of `1`), and
     `run_thread`'s loop now matches on it and calls `shim.interrupt(ctx)`.
  4. **Found during implementation, not anticipated going in:** a labelled
     boundary alone still loses an interrupt that races the narrow window
     between the shim deciding a thread is "running in guest" (and signalling
     it) and this platform's own `GUEST_OWNS_CPU` becoming true for *that*
     specific entry -- `SIGUSR2` arrives while `GUEST_OWNS_CPU` still reads
     false, the handler correctly does nothing per case 1/2, and nothing was
     left behind to retry it. `litebox_platform_linux_userland`'s own
     `switch_to_guest` re-checks a persistent `interrupt` flag immediately
     after its `in_guest := 1` store for exactly this reason; the port adds
     the equivalent `guest::PENDING_INTERRUPT`, checked and cleared by
     `enter_guest_asm` immediately after it sets `GUEST_OWNS_CPU` true, before
     restoring any guest register.

  A second, independent new finding: `darwin::install_handler` always called
  `sigemptyset` on `sa_mask`, so nothing blocked `SIGUSR2` from nesting a
  second signal handler invocation atop an in-flight `SIGSEGV`/`SIGBUS`
  delivery on the same thread (or the reverse) -- dormant before this pass
  because the interrupt handler's body was empty, but a real hazard the moment
  it starts mutating the same process-global `GUEST_OWNS_CPU`/`LIVE_PTREGS`/
  `GUEST_FP` state `fault_handler`/`prepare_exception_delivery` also touch.
  Fixed by threading an explicit `extra_mask` through `install_handler`:
  `SIGSEGV`/`SIGBUS` now mask `SIGUSR2` for their duration and vice versa.

  Verified via cargo build/clippy `-D warnings`/test/fmt --check on real M3
  Pro hardware, including three new hardware-run tests in
  `litebox_platform_macos_userland::guest::tests`:
  `delivers_a_genuine_guest_interrupt_to_the_shim_without_leaking_host_state`
  (a genuinely-executing guest, interrupted via a real cross-thread
  `pthread_kill(SIGUSR2)`, resumes via `EnterShim::interrupt` with the exact
  captured sentinels -- same disclosure-class check as the fault test),
  `an_interrupt_racing_a_fresh_guest_entry_is_honored_before_any_further_guest_instruction_runs`
  (deterministic: a synchronous self-`raise(SIGUSR2)` from inside a syscall
  handler proves `PENDING_INTERRUPT` is honored on the very next guest entry,
  before the guest executes another instruction), and
  `concurrent_sigusr2_delivery_does_not_corrupt_a_running_syscall_stream`
  (defense-in-depth, proof-by-survival: a background thread hammers real
  `SIGUSR2` throughout thousands of syscall round trips; the full trace still
  lands exactly once, in order). A fourth test,
  `interrupted_pc_range_checks_agree_with_the_known_switch_code_addresses`, is
  pure logic (no guest), checking the range helpers directly. One genuine
  residual gap, disclosed rather than hidden: no test deterministically forces
  a `SIGUSR2` into the single-digit-instruction-wide
  `switch_to_guest_start`/`_end` window itself (case 3, "mid-restoring") --
  the two deterministic tests exercise cases 1/2 and 4, and the stress test
  exercises case 3 only probabilistically (real, repeated concurrent pressure
  across thousands of round trips, but not a forced hit). Forcing that exact
  window deterministically would need either a debugger-driven single-step or
  a test-only instrumentation hook widening the window in a way that would no
  longer test the real production timing; neither was judged worth the
  fidelity trade-off for this pass.

* `touch` still fails: `utimensat` is unimplemented. Unrelated to the `/proc`
  entry below -- see that entry's own dated correction for what changed there.

* **`df`, `free` and `ps` no longer fail for lack of `/proc` -- resolved this
  pass (2026-08-10), and, as this entry originally said, it was never
  macOS-specific: it was a gap in the shared VFS/shim layer.** A minimal,
  read-only `/proc` (`litebox::fs::proc::Proc`, mounted at `/proc` in
  `default_fs` the same way `litebox::fs::devices::Devices` is mounted at
  `/dev`) now serves `/proc/meminfo`, `/proc/mounts`, and
  `/proc/<pid>/{stat,status,cmdline}` for the single guest task LiteBox's
  Linux shim ever runs: `clone` requires `CLONE_THREAD` and there is no
  `fork`, so there is exactly one pid to publish, not a real process tree --
  this backend intentionally does not invent multi-process support the shim
  doesn't have. `df` also needed a real `statfs`/`fstatfs` syscall, previously
  a deliberate `ENOSYS`: BusyBox's `df` enumerates `/proc/mounts` (Alpine's
  BusyBox has no `/etc/mtab`, so it reads this directly rather than falling
  back to it) and calls `statvfs` on each mount point; both syscalls now
  return the same synthetic-but-plausible free/total figures LiteBox already
  used for `sysinfo()`.

  Making `free` actually reach its own output (rather than dying first at the
  missing-file open) surfaced a real, previously-unobservable bug the same
  size as the `/proc` gap itself: `Sysinfo` (the `sysinfo()` ABI struct) had
  no `#[repr(C)]`, so `repr(Rust)`'s free field reordering silently scrambled
  the struct written into guest memory. `free` calls `sysinfo()` before ever
  touching `/proc/meminfo`, but always died at the missing-file open first, so
  the already-scrambled `totalram`/`freeram` were never actually printed
  until `/proc` existed to get `free` past that point -- at which point it
  printed multi-exabyte garbage instead of a number. `Sysinfo` is
  `#[repr(C)]` now, with the same kind of now-explicit padding fields
  `FileStat` and the new `Statfs` already needed for the same reason.

  Verified against the real `litebox_packager` / `litebox_runner_linux_on_macos_userland`
  pipeline on an Apple M3 Pro. `docker.io`'s own anonymous-pull auth endpoint
  (`auth.docker.io`) was unreachable from this host -- unrelated to LiteBox,
  general internet access was otherwise fine -- so the image came from
  `public.ecr.aws/docker/library/alpine:latest` instead, which mirrors the
  same image. Real output:

  ```
  $ busybox df
  Filesystem           1K-blocks      Used Available Use% Mounted on
  litebox                8388608   4194304   4194304  50% /
  devtmpfs               8388608   4194304   4194304  50% /dev
  proc                   8388608   4194304   4194304  50% /proc

  $ busybox free
                total        used        free      shared  buff/cache   available
  Mem:        4194304     2097152     2097152           0           0     2097152
  Swap:             0           0           0

  $ busybox ps
  PID   USER     TIME  COMMAND
   1000 1000      0:00 /bin/busybox ps
  ```

  `ps`'s `USER` column and `/proc/<pid>`'s owner both come from `stat`-ing the
  `/proc/<pid>` directory itself (matching BusyBox's `procps_scan`, which gets
  uid/gid that way rather than parsing `/proc/<pid>/status`), and `COMMAND`
  round-trips the real `argv` through `/proc/<pid>/cmdline`.

  An intermittent guest-fault `SIGSEGV` (exit 11) was also observed on this
  same run a few times across roughly a dozen individual `ps`/`free`
  invocations this session -- but 5 concurrent runs of each were clean every
  time, it reproduces with no `/proc`-specific error in the trace, and
  `busybox cat` on an unrelated file flaked identically once in the same
  session. **This was later shown (`macos-concurrent-guest-entry-sigsegv`,
  below) to be at least partly a real, root-caused platform bug, not merely
  scheduling sensitivity** -- see that entry for what was actually found and
  fixed, and what remains open.

* **A real guest-entry `SIGSEGV` under concurrent invocation, confirmed and
  partially root-caused (`macos-concurrent-guest-entry-sigsegv`).** The
  intermittent `SIGSEGV` noted above turned out to reproduce far more
  reliably under genuine concurrent invocation (12 real, separate
  `litebox_runner_linux_on_macos_userland` processes launched at once against
  the same packaged image): roughly 30-50% of concurrent runs failed on this
  Apple M3 Pro, versus 0-1 in 30 sequential runs, for a completely trivial
  guest (`busybox pwd`) with no relation to `/proc`. It is a genuine guest
  hardware fault, correctly routed through the fault-delivery path
  `73e5071847` added (`SIGSEGV`, `Signal(11)`, exit code 11 is
  `signal.as_i32() + 256`, truncated to a `u8` by `std::process::exit` --
  not a raw host crash), so `RUST_LOG=trace` (the env var an earlier
  investigation used) never showed anything: this crate's tracing is gated on
  `LITEBOX_LOG`, not `RUST_LOG`.

  Two distinct bugs were found investigating this, addressed with different
  confidence:

  1. **Root-caused and fixed.** Darwin's `mmap(addr, ...)` without
     `MAP_FIXED` does not reliably honor `addr` as a hint the way this
     platform's `FixedAddressBehavior::Hint` assumed. Traced on real
     hardware: a `Hint` request for the initial guest stack (8 MiB, hinted at
     `TASK_ADDR_MAX - 8 MiB` by `Vmem::get_unmmaped_area`'s top-down search)
     was silently placed by the kernel at a different, kernel-chosen address
     instead -- consistently just under the real top of the process's usable
     address space, which put the *end* of the 8 MiB stack mapping several
     MiB *above* `TASK_ADDR_MAX`, an invariant the rest of this platform (and
     `Vmem`'s own address-space bookkeeping) assumes always holds. A second,
     compounding bug in `Vmem::get_unmmaped_area`'s top-down fast path meant
     that once *one* allocation (e.g. the `ET_EXEC` interpreter's own
     "load high" placement) ended up above `TASK_ADDR_MAX` this way, later
     placements didn't reliably avoid it either: the fast path deliberately
     skips tracked ranges that start above `high_limit` (added by
     `17a5b14` to stop a host mapping entirely above `TASK_ADDR_MAX`, such as
     the dyld shared cache, from shadowing this path), but that skip isn't
     sound when the "range above `high_limit`" is a *guest* mapping that
     landed there because of the same Darwin quirk. Fixed in both places:
     `allocate_pages`/`allocate_jit_pages`/`try_allocate_cow_pages` now
     retry a `Hint` placement that lands outside
     `[TASK_ADDR_MIN, TASK_ADDR_MAX)` with an exact `mach_vm_allocate
     (VM_FLAGS_FIXED)` reservation at the originally-requested address (the
     same mechanism `NoReplace` already used, applied only on the
     already-provably-broken path so the common case is untouched), and
     `get_unmmaped_area`'s fast path now also checks
     `!vmas.overlaps(high_limit..TASK_ADDR_MAX)` directly instead of trusting
     the `r.start <= high_limit` proxy. Verified on real hardware: the
     stack/interpreter placement is now deterministic and in-bounds on every
     run observed (dozens of runs, both sequential and concurrent), where it
     previously varied and regularly exceeded `TASK_ADDR_MAX` by several MiB
     under concurrent load.

     The exact-reservation retry deliberately only fires when the bare
     `Hint` `mmap` already produced an out-of-range result, not
     unconditionally: attempting the exact reservation *first* for every
     `Hint` (tried during this investigation) regressed a previously-working
     case -- `mach_vm_allocate(VM_FLAGS_FIXED)` refuses exactly
     `TASK_ADDR_MIN` itself (`KERN_INVALID_ADDRESS`, not `KERN_NO_SPACE`;
     that address is real, ASLR-slid, host-reserved space this platform's
     conservative `TASK_ADDR_MIN` doesn't and can't statically account for),
     and an attempted-but-refused reservation there measurably perturbed
     Darwin's own address-hint state for the *next* `mmap` call in a way that
     made it land inside an already-live mapping instead of a free gap.

  2. **Found, precisely characterized, `TPIDR_EL0` hypothesis definitively
     refuted by a third investigation pass -- exact host-level trigger still
     unconfirmed, and deliberately not fixed here.** Even with the placement
     bug above fixed (stack and interpreter verified in-bounds and at
     deterministic addresses), guest processes still crash under concurrent
     invocation, at a rate not meaningfully lower than before the fix
     (30-50%-of-16-20-concurrent-runs range on this hardware, reproduced
     fresh: 8/16, 10/16, 10/20 across independent campaigns). Every
     occurrence observed had an identical, deterministic signature:
     `fault_address = 0` (a `NULL` dereference), `ESR_EL1` decoding to a
     stage-1 translation fault (`DFSC = 0b000110`), and a `PC` exactly 832
     bytes into `ld-musl-aarch64.so.1`'s entry point (`_dlstart+0x340`,
     disassembled from the packaged Alpine image as `ldrb w4, [x3, x1]`).

     **The previous hypothesis linking this to `macos-guest-tp-runtime-offset`
     (a `TPIDR_EL0` read landing in the wrong pthread TSD slot) is now
     refuted, not merely unconfirmed.** Temporary trace-level instrumentation
     added to `litebox_platform_macos_userland::guest::prepare_exception_delivery`
     captured the real hardware register state at the fault
     (`x1=0, x3=0, x4=<dso->syms>, ...`, identical across every capture), and
     a full `objdump -d` of the actual packaged `ld-musl-aarch64.so.1`
     confirms: (a) the crash site is not stack-protector or TLS setup as
     previously guessed, but musl's dynamic-symbol relocation/hash-lookup
     machinery -- `do_relocs` (resolving a non-`RELATIVE` relocation)
     calling `find_sym`/`find_sym2`, which calls `gnu_hash_lookup` (or
     `sysv_lookup`), whose byte-by-byte symbol-name-comparison loop is the
     faulting `ldrb w4, [x3, x1]`; `x1` is simply the loop's own index
     (`mov x1, #0` two instructions earlier -- expected and correct), and
     `x3` is `dso->strings + sym->st_name`, i.e. the pointer to the symbol
     name musl is looking up, computed entirely from ELF dynamic-linking
     metadata; and (b) **`ld-musl-aarch64.so.1`'s entire ~801 KB image contains
     exactly 33 `MRS`/`MSR` instructions, and every one of them targets
     `FPCR`, `FPSR`, or `DCZID_EL0` -- none targets `TPIDR_EL0` or
     `TPIDRRO_EL0`.** The crash's whole call path (`do_relocs` →
     `find_sym`/`find_sym2` → `gnu_hash_lookup`/`sysv_lookup`) never reads the
     thread pointer at all, so a wrong TSD slot cannot be the cause here,
     confirmed rather than merely argued from the disassembly of the actual
     faulting binary. This also rules out two other concrete candidate
     mechanisms checked directly against the source: the main executable's
     `AT_PHDR`/`base_addr` (`litebox_common_linux::loader::ElfParsedFile::load`,
     `litebox_shim_linux::loader::elf::ElfFile::reserve`) is computed solely
     from the real `sys_mmap` return value, never from the pre-flight
     placement hint, so this is not a Bug-A-style "used the hint instead of
     the actual address" bug; and the vDSO struct musl's loader would
     populate from `AT_SYSINFO_EHDR` is unreachable, since
     `MacOsUserland::get_vdso_address` unconditionally returns `None` on this
     platform (`litebox_platform_macos_userland/src/lib.rs`), so
     `AT_SYSINFO_EHDR` is never present in the guest's auxv.

     What live-memory inspection (reading the guest's own `struct dso` fields
     and stack directly out of host memory -- valid because this platform
     runs the guest in-process) additionally showed: in the large majority of
     captures, the `dso` being relocated is `&ldso` itself (`do_relocs`'s own
     `dso` parameter matches the same address the hash lookup searches),
     consistent with `ld-musl`'s very first `do_relocs(&ldso, ...)` call in
     `__dls2`, immediately after its own address-independent self-relocation
     -- i.e. this is `ld-musl` resolving its *own* remaining (non-`RELATIVE`)
     relocations against itself, only a few hundred instructions into guest
     execution. Reading `ldso.strings` directly out of guest memory
     *after* the fault always shows the correct value (`base + 0xf810`,
     matching the real `ld-musl-aarch64.so.1` `DT_STRTAB`), including in
     `do_relocs`'s own stack-spilled cache of that same field -- so the
     struct is not durably corrupted; the wrong (`NULL`) value was only
     visible to the guest at the exact instant it was used. That is
     consistent with a transient, host/Darwin-level write-visibility gap on
     a freshly-populated page of the guest's own data segment under
     concurrent system load (structurally the same category of "Darwin's
     memory subsystem does not behave the same under concurrent load" as
     Bug A, but a data-visibility anomaly rather than an address-placement
     one) rather than any logic bug in musl or in how LiteBox computes
     addresses -- but the exact host-level trigger for that gap was not
     pinned down further (would need a live debugger attached across a real
     concurrent crash, which this pass did not have set up); a minority of
     captures instead showed `do_relocs`'s `dso` parameter pointing at a
     *different* static `struct dso` a few hundred bytes away within the same
     `ld-musl` image (plausibly `__dls3`'s local-static `app`, i.e. the same
     failure recurring later, against the main executable's own relocations)
     without changing the diagnosis above.

     This was reproduced fresh on real hardware this pass (Apple M3 Pro) with
     the exact `litebox_packager --oci-image
     public.ecr.aws/docker/library/alpine:latest` / `busybox pwd` pipeline
     before touching anything, confirming the same signature the previous
     pass found. The diagnostic instrumentation used to capture the register
     state was trimmed to a small, permanent, trace-gated addition (logs the
     full guest `PtRegs` plus `ESR`/`FAR_EL1`/exception class whenever a
     hardware fault is delivered to the guest, at
     `litebox_platform_macos_userland::guest::prepare_exception_delivery`,
     visible via `LITEBOX_LOG=litebox_platform_macos_userland=trace`); the
     more speculative, `ld-musl`-struct-specific memory-dump diagnostics used
     during the investigation were removed rather than kept, since they
     hardcoded musl's internal `struct dso` layout and would not generalize.
     Confirming the exact host-level write-visibility mechanism, and fixing
     it if confirmed, remains follow-up work -- separate from, and no longer
     entangled with, `macos-guest-tp-runtime-offset`.

  Reproduced and verified with the real `litebox_packager --oci-image
  public.ecr.aws/docker/library/alpine:latest` / `busybox pwd` pipeline
  (`docker.io`'s auth endpoint was unreachable from this host, as in the
  `/proc` entry above) via a shell loop backgrounding N real, separate
  `litebox_runner_linux_on_macos_userland` invocations against the same
  packaged tar and waiting on all of them, run repeatedly at N=12-24 both
  before and after the fix.

* `setuid`/`setgid` are unimplemented, but that is *not* why `id` was failing --
  an earlier revision of this file said so and was wrong. `getgroups` was the
  cause, and `id` is correct now. BusyBox 1.37 discards both return values
  (`bb_applet.c`: "Don't check for errors"), so implementing them changes no
  guest-visible behaviour at all; their only current effect is two `WARN` lines.

* The two flaky timer tests do not flake in CI, which runs `cargo nextest`
  (`.github/workflows/ci.yml`) -- that is process-per-test, so the cross-test
  interference only appears under `cargo test`.

Three things had to be fixed to get that far, each of which would have stopped
any guest:

* **The rewriter aligned the appended trampoline to 4 KiB.** The loader maps the
  trampoline as its own page-granular mapping and rejects a header whose `vaddr`
  is not aligned to the *host's* page size, so a 4 KiB-aligned trampoline is
  unloadable wherever the page is larger -- every Apple Silicon host, and any
  Linux built for 16 KiB or 64 KiB pages. `Arch::trampoline_align` now gives
  AArch64 64 KiB, the maximum page size AArch64 ELF images are conventionally
  linked for anyway, and leaves x86-64 at 4 KiB. The file offset carries the same
  alignment, since the trampoline is mapped straight out of the file.
* **`litebox_packager`'s *host* mode refuses to run on macOS**, bailing with
  "only supported on Linux" because it shells out to `ldd` for dependency
  discovery. OCI mode works and is the supported path here, so this is a gap
  rather than a blocker: packaging a local, statically linked binary needs no
  dependency discovery at all and could be allowed.

* **The loader asked for an address below the host's floor.**
  `DEFAULT_LOW_ADDR` was a bare `0x1000_0000`, which is under `__PAGEZERO`, so
  every image -- including a position-independent one, which is otherwise free to
  land anywhere -- failed with `EPERM` before any guest code ran. It is raised to
  the platform's `TASK_ADDR_MIN` now.

* **The public `run_thread` did not establish a thread handle.**
  `EnterShim::init` attaches an interrupt handle, which reads `current_thread()`,
  which panics on a thread that `run_with_handle` was never called on --
  `spawn_thread` wraps its entry for exactly this reason and the new initial-thread
  entry did not. It was latent only because the load failure above happened first.
* **An archive built with the host's own `tar` does not load**, because macOS's
  bsdtar puts a metadata entry first. By default that is `._name`, an AppleDouble
  entry carrying extended attributes; with `COPYFILE_DISABLE=1` it is instead
  `PaxHeader/name`, a pax extended header. `tar_no_std`, which backs
  `litebox::fs::tar_ro`, handles neither, so the real file is never reached.

  The archive *format* is not the problem, though it is an easy thing to blame:
  measured on this host, bsdtar's default, its `COPYFILE_DISABLE=1` output, and
  both of Python's `USTAR_FORMAT` and `GNU_FORMAT` all carry identical magic at
  offset 257, and both Python archives load while both bsdtar ones fail. The
  distinguishing factor is the leading metadata entry, not `ustar` versus GNU.
  `litebox_packager` sidesteps this by writing `Header::new_ustar()` itself; a
  hand-built archive needs a writer that emits no extended headers.

## Failures unmasked by fixing the `litebox_shim_linux` test compile error

`litebox_shim_linux`'s test target did not compile (`E0793`: a reference to a
packed `stat` field inside `assert_eq!`), so CI stopped at the clippy step and
every test in that crate was unreachable. With the compile error fixed, two
genuine failures surfaced. Both reproduce at the commit before that fix once
the same one-line change is applied, so neither is a regression from it.

* **`loader::elf::tests::et_exec_interpreter_loads_top_down_above_low_heap`
  panics in `sys_munmap`.** On Linux the platform's `munmap` returns `EINVAL`
  (`litebox_platform_linux_userland/src/lib.rs:1661`); on Windows the same test
  trips `litebox_platform_windows_userland`'s "Trying to deallocate a free
  region" assertion. The two platforms disagreeing about the same unmap points
  at the loader's top-down interpreter placement releasing a range it does not
  own, rather than at either platform's allocator.

* **`test_runner_broker_integration_with_rewriter` exits with status 14.**
  The runner-under-broker path with the syscall rewriter enabled fails during
  the integration run; the exit status is the guest's, not a harness error.

Both need a real diagnosis rather than a test adjustment: an unmap of an
unowned range is exactly the class of bug the platform assertions exist to
catch.

## Consecutive TUN socket tests hang in the same process (fixed)

`syscalls::net::tests::test_tun_*` passed one at a time but hung the second
of any back-to-back pair in one test binary: with `--test-threads=1`,
`test_tun_blocking_recvfrom_tcp_socket` passed and `..._with_truncation`
never returned.

The cause was a leaked pump thread. Every `init_platform(Some(tun))` spawned
a detached, immortal loop reading the one shared host TUN fd (the platform is
a process-wide `OnceLock`), with no stop signal and no join. When the next
test started, the previous test's pump was still reading that fd; a TUN read
is destructive, so the leaked reader swallowed the new test's inbound SYN and
its `accept()` blocked forever. `--exact`/nextest masked it because each test
then ran in its own process with no prior reader.

Fixed: the pump is now generation-gated. Each `init_platform` bumps a counter,
joins the previous pump, and starts its own; the pump checks the generation
every iteration and exits when a newer one supersedes it, so exactly one
thread ever reads the shared fd. The full `test_tun_*` set now passes under
`--test-threads=1` in one process (the only remaining failures on a bare host
are the 9P tests, which need `diod` installed).

## A guest's read after its own SHUT_WR sees ECONNRESET, not EOF

A guest that half-closes with `shutdown(fd, SHUT_WR)` and then keeps reading
until end-of-stream gets `ECONNRESET` (errno 104) on the terminal read where
Linux would deliver a clean `EOF` (0), once the peer sends its own FIN. Any
data still in flight before that point is delivered correctly; only the final
end-of-stream indication has the wrong shape.

The cause is that the LiteBox TCP stack is built on smoltcp, which has no
half-close: `shutdown_send` maps `SHUT_WR` onto smoltcp's `close()`, a
full-duplex teardown that sends FIN and moves the socket to a closing state,
so the peer's subsequent clean FIN arrives at a socket smoltcp already
considers closed and is reported as a reset rather than an orderly shutdown.

This is not fixable at the shim layer without smoltcp support for a true
half-open state: translating every post-`SHUT_WR` reset into EOF would hide
genuine resets, trading one wrong answer for another. The correct fix is
either a smoltcp half-close (an upstream change) or a LiteBox TCP state that
tracks the local write-shutdown and distinguishes a peer's orderly FIN from a
real RST. Reproduced with a guest that does `SHUT_WR`, reads the peer's
in-flight bytes (delivered fine), then reads again after the peer's clean FIN
(`errno 104`).

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
  tests (`address_space_guard`) makes the suite deterministic.

* **Fixed since:** `test_collision_with_global_allocator` now runs on macOS too.
  Its search for a host mapping outside LiteBox's view assumed the host scatters
  successive anonymous `mmap`s the way Linux's ASLR does; Darwin instead packs
  them back to back, so the page the test needs free right before its candidate
  address was always still occupied by the previous iteration's own mapping, and
  the search never terminated. The macOS probe now frees exactly the page it
  needs itself, by construction rather than by chance, and the setup `mmap` that
  must land at an exact address uses `MAP_FIXED_NOREPLACE` instead of a hint
  Darwin does not reliably honor.

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

  **Both resolved this pass, verified on real M3 Pro hardware.** The FP/SIMD
  half: `darwin::ArmNeonState64` now models Darwin's `__darwin_arm_neon_state64`
  (verified field-for-field against this machine's own SDK headers --
  `mach/arm/_structs.h`, `arm/_mcontext.h` -- not assumed), and
  `guest::prepare_exception_delivery` refreshes `GUEST_FP` from it at fault
  time instead of leaving it stale from the guest's last syscall.
  `litebox_shim_linux`'s `write_signal_frame`/`restore_sigcontext` now round-trip
  real vector state through a new `ThreadProvider::get_fp_state`/`set_fp_state`
  pair (default zeroed/no-op on every other platform, so this is additive, not
  a behavior change elsewhere) into a real aarch64 Linux `fpsimd_context`
  record -- verified field-for-field against the kernel's own
  `arch/arm64/include/uapi/asm/sigcontext.h` (`fpsr`/`fpcr` *before* `vregs`,
  the opposite order from Darwin's struct -- confirmed by fetching the header
  directly rather than assumed from the two structs' surface similarity).
  Hardware-run test:
  `guest::tests::captures_real_vector_register_state_from_the_darwin_mcontext_on_a_guest_fault`
  seeds three distinct sentinels into `v0`/`v15`/`v31`, faults, and asserts the
  delivered state matches exactly.

  The `sa_restorer` half: `guest::sigreturn_trampoline` is LiteBox's own
  replacement for the vDSO `sigtramp` a real Linux kernel would fall back to --
  exactly the mechanism `litebox_syscall_rewriter::arm64`'s "Signal returns"
  module doc already anticipated ("The runtime installs its own sigreturn
  trampoline address..."), now actually implemented. `SystemInfoProvider::
  get_sigreturn_trampoline_address` reports its host address (default `None`
  everywhere else, preserving every other platform's current refuse-delivery
  behavior byte-for-byte), and `write_signal_frame` falls back to it instead of
  refusing delivery when `SA_RESTORER` is absent. Unlike `syscall_callback`,
  the trampoline never touches guest memory at all: `sys_rt_sigreturn` takes no
  register arguments and locates its frame purely from `ctx.sp`, so the
  trampoline only needs to capture the real `SP` register and set `syscallno`
  to `139` (verified against the vendored `syscalls` crate's own aarch64 table,
  not assumed) before handing off -- no exception-table entry needed, since
  there is no guest-memory access left to fault. Hardware-run test:
  `guest::tests::a_guest_signal_handler_without_sa_restorer_resumes_correctly_via_the_sigreturn_trampoline`
  branches straight into the trampoline (as a guest's `ret` would) and asserts
  the shim receives exactly `rt_sigreturn` with the guest's real, untouched
  `sp`.

  Scope note: this closes the two gaps as stated above (both are about the
  *macOS platform's own* contribution -- Darwin state capture and the
  trampoline). It does not touch x86-64's parallel, structurally identical
  `fpstate: 0 // TODO` gap in `litebox_shim_linux/src/syscalls/signal/x86_64.rs`
  -- unverifiable on this Apple Silicon hardware and out of this pass's scope.
  The `write_signal_frame`/`restore_sigcontext` signatures gained a `platform`
  parameter on x86-64 too, purely for the two architectures' call sites in
  `mod.rs` to share one signature; its behavior is untouched.

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

## Every box's guest network identity is hardcoded, blocking direct box-to-box addressing

Found while proving out a multi-box composition (several `boxer` instances,
each running one single-process workload, wired together over TCP -- the
shape multi-process desktop-class workloads like an X11 display server plus
clients need, since LiteBox has no `fork`). `litebox/src/net/mod.rs:36,40`
hardcodes `INTERFACE_IP_ADDR = 10.0.0.2` and `GATEWAY_IP_ADDR = 10.0.0.1` as
compile-time constants (each already marked `// TODO: Make this
configurable` in the source), and `boxer/src/publish.rs:27`'s `GUEST_IP`
mirrors the same hardcoded `10.0.0.2` as the forward target for published
ports. Every box's guest network stack believes this is its address and its
only gateway, regardless of which `--net <device>` the box is attached to or
what host-side IP `tun-setup.sh -i` assigned that device.

Confirmed live: `boxer` also flatly refuses two processes attaching to the
same TUN device concurrently (`tun device 'tun99' is already in use`,
matching the fork-less, one-guest-thread-of-one-process model
`litebox_shim_linux/src/lib.rs:1430` documents), so composing two boxes at
all requires two separate TUN devices. `tun-setup.sh -t tun98 -i 10.0.1.1`
correctly assigns a second device its own distinct host-side address. But a
box attached via `--net tun98` never learns that its own gateway is
`10.0.1.1` -- its guest routing table only ever contains the hardcoded
`10.0.0.0/24`, so a guest `connect()` aimed at `10.0.1.1` (a different
subnet, from the guest's point of view) has no route and hangs indefinitely
rather than failing fast. This was verified by elimination: a plain host
process binding and self-connecting to `10.0.0.1` (the first, default
device) round-trips correctly; the same pattern against a correctly-assigned
second device's `10.0.1.1` does not, and the guest-side hang was traced to
the missing route rather than to any transport-layer failure.

Practical consequence: a box can only ever reach *its own* device's fixed
`10.0.0.1` -- it cannot be pointed at a different box's host address to
reach it directly. The composition shape that *does* work today (proven live
this pass) is host-mediated: each box's guest talks only to a process bound
on its own `10.0.0.1`, and that host-side process is free to relay onward
however it likes (including to a different box's published port on the
host's loopback, which the host itself can always reach regardless of which
TUN device is involved). True peer-addressed box-to-box networking -- box A's
guest directly reaching box B's guest by a distinguishing address -- needs
`GATEWAY_IP_ADDR`/`INTERFACE_IP_ADDR` parameterized per `--net` device (the
TODO already on record) or per-box network namespaces, either a real
`litebox`/`boxer` core change, not something expressible from the CLI today.
