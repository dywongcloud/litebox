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
* **The platform's *own* per-thread context-switch bookkeeping** —
  **RESOLVED on real hardware.** A separate problem from the rewriter's guest
  slot above, and the thing that limited this platform to one guest thread at a
  time. `litebox_platform_linux_userland`'s x86_64
  `run_thread_arch`/`switch_to_guest`/`syscall_callback` (the closest thing to
  a template) does not only virtualize the *guest's* thread pointer -- it also
  stashes its own bookkeeping (`host_sp`, `host_bp`, `guest_context_top`,
  `in_guest`) in `fs:`-relative TLS slots, because by the time
  `syscall_callback` runs, every general-purpose register holds live guest
  state and there is nothing else durable to read "where was the host stack"
  from. That mechanism is entirely x86_64-ELF-specific (raw `@tpoff`-relative
  local-exec TLS addressing, resolved to a link-time-fixed offset with no
  function call and no runtime-determined value at all) and has no Mach-O
  equivalent to copy directly.

  **The building block, confirmed on real Apple M3 Pro hardware:** a raw
  `mrs tpidrro_el0` (masked, `& ~7`, matching libSystem's own
  `_os_tsd_get_base`) plus a `[base, #(key * 8)]` read/write reaches the *same*
  per-thread storage `pthread_getspecific`/`pthread_setspecific` do, for a
  **second**, independently `pthread_key_create`-reserved dynamic TSD key (not
  just the one already relied on for the guest's own `TPIDR_EL0` shadow) -- in
  both directions, across the full `usize` range, and disjointly across two
  genuinely concurrent OS threads. Measured again this pass: the first dynamic
  key a Rust binary gets is 259 and the pool is exhausted at key 767.

  **The blocker, and how it was actually solved.** Of the six naked functions
  in `litebox_platform_macos_userland::guest`, five are reached with registers
  to spare (three of them by a signal handler's `pc` redirect, so *every*
  register is free) and can simply do a two-register lookup: one register for
  the run-time-determined TSD byte offset, one for the `TPIDRRO_EL0` value. The
  syscall callback cannot: the rewriter's `SVC` gate leaves exactly **one**
  register free (`X16`), because `X17` still holds the guest's real value,
  which real Linux AArch64 preserves across a syscall and which this file's own
  fidelity philosophy (`preserves_registers_across_capture_and_resume`) commits
  to capturing faithfully. One register is enough for
  `mrs`/`and`/`ldr [x16, #imm]` **only if the immediate is a compile-time
  constant**, and the key is not knowable until run time.

  A previous pass bought the second register by staging the per-thread pointer
  in a word below the guest `SP` at resume time. That design passed every
  existing test and was then hardware-disproven: the staged word's address is
  relative to `SP` *as of the resume*, and any real compiled program moves `SP`
  (opens a stack frame) before its next syscall, so the callback read back a
  stale address. Architectural, not an off-by-one.

  **The fix that landed instead makes the immediate a compile-time constant by
  enumerating every possible one.** `guest::syscall_entry_stubs` is a table of
  768 identical four-instruction stubs -- one per pthread TSD slot Darwin can
  hand out -- emitted with assembler `.rept`/`.set` directives, stub `N` being
  `mrs x16, tpidrro_el0` / `and x16, x16, #~7` / `ldr x16, [x16, #(N*8)]` /
  `b <shared callback body>`. `SystemInfoProvider::get_syscall_entry_point`
  reports the address of the *one* stub matching the key this process actually
  reserved, so the loader writes that into the guest trampoline's callback slot
  like any other entry point. One register, no function call, no dependence on
  the guest's `SP`, no self-modifying code, and **no change to the
  ahead-of-time-rewritten guest binary format** -- which is what made this
  implementable inside `litebox_platform_macos_userland` alone, unlike the
  "extend the `SVC` gate" and "sacrifice `X17`" candidates the previous pass
  recorded. (Sacrificing `X17` was rejected on its merits, not merely as extra
  work: it is a real, if narrow, ABI regression, and it turned out to be
  unnecessary.) The stubs branch to the shared body via an `L`-prefixed local
  label in the same assembly fragment, so the assembler resolves it with no
  relocation and the linker cannot interpose a range-extension veneer -- which
  would clobber `X16`, the one register carrying the whole mechanism. Verified
  by disassembling the shipped binary: 768 stubs, `0x3000` bytes, last one
  loading `[x16, #0x17f8]` (= slot 767), every `b` landing directly on the body.
  Cost: 12 KiB of otherwise-inert `.text`.

  `HOST_SAVE`, `GUEST_FP`, `LIVE_PTREGS`, `GUEST_OWNS_CPU`, `PENDING_INTERRUPT`,
  `PENDING_EXCEPTION_INFO` and the `GUEST_ACTIVE` guard that existed only to
  stop two threads racing them are all gone, replaced by one per-thread
  `GuestThreadState` allocated on each guest thread's own host stack. The
  crate's `dev_tests/src/ratchet.rs` static budget drops from 13 to 8
  accordingly. `PENDING_INTERRUPT` becoming per-thread also fixes a real (if
  minor) latent bug on the way past: a `SIGUSR2` that landed on a thread which
  was not in guest code used to set a *process-global* flag that some
  *different* guest thread would then consume at its next entry.

  **Proof, on this hardware, beyond the crate's own tests** (the previous pass
  fooled itself by stopping at those): a freestanding aarch64 Linux guest that
  `clone(2)`s three more guest threads, has all four print an identity byte
  re-derived every iteration from a callee-saved register, out of a buffer on
  each thread's own stack, 500 iterations each, and -- deliberately -- opens a
  64-byte stack frame between every resume and the next syscall, i.e. exactly
  the shape that killed the staged-pointer design. Under the fixed build it
  exits 0 with an exact 500/500/500/500 histogram, repeatably. Under a build of
  clean `HEAD` the same binary panics with "a second concurrent guest thread
  reached macOS guest entry" and hangs. Two negative controls confirm the new
  crate tests are not vacuous: republishing a single shared `GuestThreadState`
  for all threads makes `concurrent_guest_threads_each_keep_their_own_context`
  die with `SIGBUS`, and reinstating the resume-time below-`SP` staging makes
  `a_guest_that_moves_its_sp_between_a_resume_and_its_next_syscall_still_round_trips`
  fail *while* `runs_a_guest_through_two_syscalls_and_exit` still passes --
  precisely how the earlier attempt was misled.

  **Still open, and unrelated to this row:** a guest that *uses* `TPIDR_EL0`
  still needs `pthread_setspecific` of each guest thread's own pointer into the
  guest-TP key (see the item above); and the intermittent
  `macos-concurrent-guest-entry-sigsegv` remains, measured this pass at 3/100
  runs of `busybox uname -a` on clean `HEAD` and 2/100 on the fixed build --
  i.e. untouched, neither fixed nor worsened, by per-thread bookkeeping.
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
* **Resolved in a later pass:** host bookkeeping (save area, live-`PtRegs`
  pointer, guest vector file, ownership and pending-interrupt flags) used to be
  process-global, so only **one guest thread at a time** could run (a second
  panicked loudly). It is now a per-thread `GuestThreadState` on each guest
  thread's own host stack, reached from naked assembly through a reserved
  pthread TSD slot; the syscall callback gets there with its single free
  register via a per-slot entry-stub table. See "The platform's own per-thread
  context-switch bookkeeping" above for the mechanism, why the earlier
  below-`SP` staging attempt was architecturally wrong, and the real
  multi-guest-thread hardware proof.
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
are real, but they were not what broke it.

**It has since bitten, hard.** The sentence that stood here previously -- that
XNU's `x18` zeroing "remains a documented restriction that has simply not bitten
yet" -- is now false, and its confident tone is part of why three separate
investigation passes looked elsewhere. XNU's `x18` zeroing is the root cause of
*both* the intermittent concurrent-launch `SIGSEGV` and the total failure of
Node.js to boot; see "XNU destroys a live guest `x18`" below for the measured
evidence.

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
     metadata
     [**CORRECTION: that identification of `x3` is wrong, and it is the single
     mistake that kept this bug unsolved across three passes. `dso->strings +
     st_name` is in `x9` (`ldr x9,[x2,#0x60]` then `add x9,x9,x1`). `x3` is the
     *other* operand: `s`, the name being searched for, which `find_sym2` parks
     in `x18` (`mov x18, x1` at entry, `mov x3, x18` immediately before each of
     its two call sites). Everything downstream of the mis-read -- including the
     "transient Darwin write-visibility gap" hypothesis -- followed from it. See
     "XNU destroys a live guest `x18`" below.**]; and (b) **`ld-musl-aarch64.so.1`'s entire ~801 KB image contains
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

### XNU destroys a live guest `x18`

This is the root cause of both the intermittent concurrent-launch `SIGSEGV` and
Node.js failing to boot. Two agents investigating those two symptoms
independently, in separate worktrees, converged on the same mechanism, and each
finding was then re-derived from scratch by adversarial verifiers on this
hardware.

`x18` is the AArch64 *platform register*, reserved by Apple. XNU zeroes it on
every return to EL0. LiteBox executes guest instructions natively, so a guest
holding a live value in `x18` loses it at an arbitrary instruction boundary,
asynchronously, with no notification and no userspace hook to intercept.

Measured directly on an M3 Pro (a sentinel placed in `x18`, then observed):

| Event | Sentinel survives |
| --- | --- |
| No trap at all | 500/500 |
| Anonymous first-touch page fault | 0/500 |
| Signal round trip | 0/500 |
| Pure timer preemption of an asm-only loop touching no memory | lost |

A handler writing `uc_mcontext->__ss.__x[18]` is ignored on return -- the kernel
exposes the original value to the handler but discards a write. The
`com.apple.security.cs.allow-jit` entitlement makes no difference. The in-tree
test `guest::tests::xnu_zeroes_guest_x18_on_every_return_to_el0` pins this fact
so it cannot quietly stop being true.

Why it presents as "concurrency": the driver is *host preemption rate*, not other
LiteBox processes. Sequential idle runs failed 0/60; sequential runs under CPU
hogs failed 3/40. Concurrency merely raises the trap rate.

Why Node and not busybox: window size. `x18`/`w18` operand counts are `node`
19,010, `libstdc++.so.6` 199, `ld-musl` 82, `busybox` 91. Node's relocation
workload guarantees a trap lands inside a live-`x18` window.

LiteBox's own save/restore is *not* the leak --
`guest::tests::liteboxs_own_syscall_gate_round_trip_preserves_guest_x18` proves
both directions. The loss happens on kernel-serviced returns where no LiteBox
instruction executes.

**Two corrections to what an earlier draft of this section claimed**, both from
adversarial verification rather than from the original investigation:

1. "The whole guest userland would have to be rebuilt with `-ffixed-x18`" is
   **not** established. Patching only four instructions in musl's `find_sym2`
   (spilling `s` to the stack instead of parking it in `x18`) eliminated the
   `SIGSEGV` in 5/5 runs and carried Node through its *entire* relocation phase.
   The blast radius may be far smaller than a full userland rebuild.
2. Fixing `x18` alone will not boot Node; it exposes a **second, distinct
   blocker that is fixable inside LiteBox**. Node's bundled OpenSSL deliberately
   executes `sm3partw1` (encoding `0xce63c004`) as a CPU-feature probe,
   *expecting* to catch its own `SIGILL`. This host implements no
   FEAT_SM3/FEAT_SM4, and `install_fault_handlers` covers only `SIGSEGV` and
   `SIGBUS`, so that intentional `SIGILL` kills the runner outright instead of
   being delivered to the guest. It runs in the `init_array` constructor loop,
   strictly after relocation.

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

**The blast radius is the whole stock userland, not just relocation windows
(measured 2026-08, XFCE image on this M-series host).** Stock Alpine busybox's
`sha256sum` over a 7 MB in-image library returned a *different wrong digest on
every invocation* -- four runs, four hashes -- while `cat` of the same file was
byte-perfect every time, isolating the corruption to the guest's own hot-loop
*arithmetic* (a live `x18` in the SHA-256 round computation), not litebox's
read path. The same busybox rebuilt with `-ffixed-x18` produced the correct
digest 4/4 in the same session. Consequences observed live before the
diagnosis: musl's ld.so intermittently reporting `Exec format error` for
byte-intact libraries, GTK components (xfwm4/xfdesktop/xfce4-panel) running
but never painting, and an X client wedged awaiting a reply the server never
sent -- all the same mechanism landing in different hot loops.
`litebox_packager/scripts/build-x18-desktop-repo.sh` rebuilds the
rendering-critical Alpine package closure (~55 packages: glib/GTK/cairo/
pixman/pango/harfbuzz, the X client libraries, Xorg and its drivers, the XFCE
components, busybox, dbus) with `-ffixed-x18` into a local APK repository an
image build overlays via `apk upgrade`; `-ffixed-x18` code is ABI-compatible
with stock code (`x18` is caller-saved), so partial coverage degrades
gracefully rather than breaking. Off-path packages (webkit2gtk, ffmpeg, mesa,
librsvg) stay stock and can still misbehave internally; the true fix for
arbitrary binaries remains the binary-rewriting work tracked above.

### A further, distinct crash past both the `x18` and `SIGILL` fixes

With a `-ffixed-x18`-rebuilt `ld-musl-aarch64.so.1`/`libc.musl-aarch64.so.1`
swapped into a packaged `node:alpine` image (getting the guest through
relocation) and `SIGILL` delivery to the guest working (getting past
OpenSSL's `sm3partw1`/`sm3partw2`/`sm3tt1a`/`sm3tt1b`/`sm3ss1` CPU-feature
probes -- five distinct probe faults observed per run, each a clean
deliver-and-resume round trip), `node --version` still does not boot: it
reaches roughly 250 further syscalls of real bootstrap (an early
`getpid`/`capget`/`getuid`/`geteuid`/`getgid`/`getegid` privilege check,
dozens of `rt_sigaction` calls installing/restoring each CPU-probe's own
`SIGILL` handler, `openat`/`mmap`/`mprotect` for the one dynamically-loaded
library) and then dies with a genuine hardware instruction-abort
(`ESR=0x82000006`, translation fault at the faulted address) whose captured
`PC` is not a valid guest address at all -- observed as exactly `0`, or as
raw ASCII bytes off a nearby path string (`/run\0\0\0\0`, `/usr/loc`),
varying non-deterministically run to run.

**Ruled out, with a live diagnostic, not merely argued.** A trace log added
immediately before `enter_guest_asm` (logging `ctx.pc`/`ctx.regs[16]`/`ctx.sp`
for every resume, kept as a permanent `trace`-gated aid) shows the `pc`
litebox hands to the guest for the fatal resume is always valid -- a real,
previously-executed guest address, matching the same resume point several
earlier (successful) iterations of the same privilege-check loop used. So
this is not `enter_guest_asm` resuming the guest at an already-corrupt `PC`
(one candidate an earlier pass of this investigation could not rule out
without this instrumentation), and it is not a host-side fault
misattributed as a guest one either (`owns_cpu` was continuously true across
the ~250 syscalls between the last valid resume and the fault, and the
guest visibly kept making real forward progress in between).

**A further experiment, also run live, ruled out this platform's own
context-switch mechanism as the direct cause.** The captured `PC` at the
fatal fault is always bit-identical to the captured `X16` -- across three
independent runs with three different garbage values (`0`, a `/run`-prefixed
value, a `/usr/loc`-prefixed value), never differing. That is exactly the
signature [`enter_guest_asm`]'s own resume vehicle would produce if litebox
itself branched through a corrupt `X16` (see this file's `guest.rs` doc
comment on why `X17`, not `X16`, is now that vehicle) -- so this was tested
directly: switching the vehicle register from `X16` to `X17` (restoring the
guest's real `X16` correctly on every resume, a genuine, confirmed,
independently-worthwhile ABI fix in its own right, verified against the
existing register round-trip tests with zero regressions) left the crash
*byte-for-byte identical*, still landing on `X16` specifically, in five
further live re-runs. Litebox no longer supplies `X16`'s value at the point
of the crash under either vehicle choice, so the guest's own code is
holding `X16` live across the intervening syscalls and something else is
corrupting it.

**Leading hypothesis, not yet confirmed: this is the same failure class as
"XNU destroys a live guest `x18`" above, hitting a second register.** `X16`
is exactly the AArch64 ELF ABI's canonical PLT/lazy-binding scratch register
(confirmed against this guest's own disassembled `ld-musl-aarch64.so.1`:
its PLT stubs load the GOT slot address into `X16`, then branch through
`X17`) -- a plausible, if unconfirmed, mechanism for real compiled code
(Node's own ~90 MB binary and V8's JIT output, neither built with
`-ffixed-x18`/an equivalent `X16` restriction, unlike the patched musl) to
hold `X16` live across a syscall the same way `find_sym2` held `X18` live
across one. The non-determinism (sometimes `0`, sometimes readable path-string
bytes) is also consistent with a read of a stale/uninitialized value rather
than a fixed corruption pattern, matching how XNU's `x18`-zeroing was
measured to be probabilistic under preemption, not a deterministic
per-syscall event. Not proven: no capture yet pins down *which* instruction
or memory location supplies `X16`'s bad value, and it has not been checked
whether XNU's documented `x18`-zeroing behavior extends to `x16` under the
same conditions, or whether this is instead a distinct, litebox-specific
memory-initialization bug (e.g. a not-reliably-zeroed anonymous mapping).
Confirming the exact mechanism needs either a kernel-level trace across the
fault (this pass did not have one available) or a targeted sentinel-register
experiment analogous to `guest::tests::xnu_zeroes_guest_x18_on_every_return_to_el0`,
extended to `x16`.

Reproduced fresh this pass, 8/8 runs, with the exact repro command:
`LITEBOX_LOG=litebox_shim_linux=trace,litebox_platform_macos_userland=trace
litebox_runner_linux_on_macos_userland --initial-files <node:alpine tar with
the `-ffixed-x18` musl swapped in> -- /usr/local/bin/node --version`.

**A follow-up pass tried, and disproved, the obvious next move: picking a
"safer" vehicle register instead of `X17`.** An independent research pass over
`https://github.com/AnEntrypoint/litebox` (a derivative under active,
unrelated development -- x86-64/Windows only, no macOS or AArch64 code at all
as of its HEAD `8065258`, so nothing in it addresses this bug directly)
surfaced the exact structural parallel on that platform
(`372f9f4`, "Preserve guest xmm0-xmm5 across the guest-to-host syscall
trampoline") and, in the course of comparing it, an independently-confirmed
fact about *this* codebase: `enter_guest_asm`'s `X17` sacrifice (the state as
of commit `697e927`) means `X17`'s real guest value is silently discarded on
*every* resume, exactly as `X16` was before that commit -- `X16`/`X17` are
AArch64's canonical PLT/lazy-binding scratch pair (`ADRP X16, ...; LDR X17,
[X16, ...]; BR X17`), so a dynamically-linked guest exercises both on every
lazily-bound call.

The natural next step -- restore both `X16` and `X17` correctly, moving the
sacrifice to a register with no PLT/ABI-special role (`X9` was tried) --
**was implemented, tested, and reverted this pass**, because it is not a
fix, only a relocation of the same gap: with `X9` as the vehicle,
`guest::tests::delivers_a_genuine_guest_fault_to_the_shim_without_leaking_host_state`
and `delivers_an_undefined_instruction_to_the_shim_as_a_guest_exception`
(both pre-existing, both pass on `697e927`, both do a real, litebox-mediated
`write(2)` syscall with a live sentinel in `X9` immediately beforehand)
started failing -- deterministically confirmed via `git stash` A/B on this
same hardware, not merely suspected. `X9` turned out to be exactly as "live
across a syscall" as `X16`/`X17` were, just in a different, narrower way
(these two tests happen to hold a value there; real guest code plausibly does
too). This is the general case, not a coincidence: **AArch64 has no
instruction that atomically restores all 31 GPRs *and* the PC from EL0
(`ERET` requires EL1+); every indirect-branch-based resume needs one GPR to
carry the target address, and there is no register general-purpose code is
*guaranteed* never to hold live across an arbitrary syscall.** Trying
successive single-register vehicles is provably a dead end -- three now
tried (`X16`, `X17`, `X9`), all three demonstrated-live in some real scenario
-- not merely three unlucky guesses. A vehicle change also still would not
have addressed the Node crash regardless: that was already tested directly
(`X16` vs. `X17`, byte-identical crash) before this pass even started.

**What an actual fix needs**, left for follow-up rather than attempted here
given the blast radius (this platform's *only* guest-resume path,
risking every currently-working guest, not only Node) and the remaining time
budget: eliminate the sacrifice entirely rather than relocate it, by
borrowing a real EL1-privileged atomic restore instead of a raw userspace
indirect branch. Darwin's own `sigreturn` syscall does exactly this --
restore an entire `mcontext_t` (all GPRs plus `PC`) atomically, from EL1, on
behalf of EL0 -- and this platform already has the supporting pieces for
signal *delivery* (`sigreturn_trampoline`,
`get_sigreturn_trampoline_address`). Reusing that mechanism for *every*
ordinary resume (not just returning from a delivered signal) would need: a
real `ucontext_t`/signal-frame-shaped structure built from `PtRegs` on each
resume (today's plain register restore is far cheaper, so this is a real
performance trade, not a free win), a decision on which stack it is safe to
stage that frame on (the guest's own -- matching how signal delivery already
works -- or a dedicated per-thread alternate stack, avoiding any assumption
about the guest `SP`'s validity at an arbitrary resume point), and
verification that Darwin's `sigreturn` is actually callable in this shape
from a context that did not arrive via a real signal delivery in the first
place. None of this was implemented or verified this pass -- it is a design
sketch, not a plan vetted against the real API.

**A follow-up pass ruled out three more candidate mechanisms for the further
crash, with direct evidence for each, and fixed one real, separate bug found
along the way.** None of the three explain the crash; it remains open.

1. *Is XNU's `x18`-zeroing a general "any scratch register" phenomenon,
   just not yet observed for `x16`/`x17`?* No -- tested directly with the
   same proven-reliable methodology the `x18` test above uses (a raw Darwin
   `SVC`, 256 rounds), but for `x17` instead: `x17` survives every round
   (`guest::tests::xnu_svc_x17_probe`, now a permanent regression pin). `x18`
   is Apple's own uniquely-reserved AArch64 platform register -- the ABI
   basis for XNU zeroing it does not extend to an ordinary scratch register
   like `x17`. This refutes the leading hypothesis two sections up (that the
   further crash is the same XNU mechanism hitting a different register) at
   the mechanism level, not just for the specific vehicle-choice angle
   already ruled out there.

2. *Does the host's own memory allocator alias the guest's address space?*
   This was a real, confirmed, **separately worthwhile** bug, independent of
   whether it explains the further crash (it does not -- see below), found by
   comparing this platform's `reserved_pages` mechanism against
   `AnEntrypoint/litebox`'s own independent discovery of the identical bug
   class on its (Windows) backend (commits `8b1a0fb`/`ab383ff`: the host's
   global allocator committing pages inside the guest's own claimed address
   range, because their equivalent of `reserved_pages` was also only a
   one-time startup snapshot with no visibility into allocations made later,
   during guest execution). Measured directly on this Darwin host before
   trusting the parallel: 200,000 ordinary Rust heap allocations and 50 real
   `std::thread::spawn` stacks landed at addresses from ~4 GiB to ~39 GiB --
   **100% inside** the then-current `GUEST_ADDR_MIN..GUEST_ADDR_MAX` range of
   `[4 GiB, 64 TiB)`. Unsurprising in hindsight: 4 GiB is approximately where
   an ordinary 64-bit process's own heap begins, immediately adjacent to
   where the guest was also claiming its first pages. Fixed by raising
   `GUEST_ADDR_MIN` to 1 TiB (roughly 25x the worst address measured, leaving
   63 TiB of guest headroom on top of the unchanged 64 TiB ceiling -- wide
   margin on both sides, not tuned to just barely clear what was measured).
   Verified live: full `node:alpine` re-run against the raised floor produces
   the byte-for-byte **same** crash (`pc=0`, `esr=0x82000006`,
   `exception=Exception(32)`) -- so this was not the cause of the further
   crash specifically, but it closes a real, demonstrated, previously
   unprotected collision window regardless, at zero regression (full
   `litebox_platform_macos_userland` suite green, a fresh `busybox`/Alpine
   OCI repackage-and-boot still clean).

3. *Is the guest thread-pointer TSD-slot mismatch (the `WARN` logged on
   every run: "`pthread_key_create` gave a slot the AOT-rewritten `Host::MacOs`
   gates do not use") actually live for a `TPIDR_EL0`-using guest like
   Node's musl, contrary to `reserve_guest_tpidr_tsd_slot`'s own doc comment
   claiming the runtime load-time-offset-indirection fix already closes it?*
   Reviewed the wiring (`litebox_shim_linux/src/loader/elf.rs`'s
   `FileAndParsed::new` calls `get_guest_tp_slot_offset` and
   `parse_trampoline` for every ELF loaded, main and interpreter and shared
   libraries alike) and it is architecturally consistent with that claim --
   plus circumstantial support: a guest whose TLS access were genuinely
   reading the wrong slot would plausibly fail far earlier than 250+ clean
   syscalls into a real Node boot, not at this specific late point. Not
   exhaustively verified (would need confirming the patched offset actually
   lands in Node's own trampoline header at load time, not just that the
   call chain exists) -- flagged as the one thread in this list not run to
   ground, in case a future pass wants to finish it rather than re-derive
   the wiring from scratch.

None of the three redirect where the real fix effort should go next. The
concrete next diagnostic remains what it was before this pass: a debug
V8/Node build with real symbols, so a captured `PC`/corrupted-register value
resolves to an actual function name instead of a bare address -- the
un-symbolized guesswork this and the prior pass's investigations have been
constrained to is close to exhausted as a technique on its own.

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

* **Widening the macOS Seatbelt profile's coverage.** The second sandboxing
  layer behind LiteBox's own guest/host boundary now exists on macOS --
  `litebox_platform_macos_userland::enable_seatbelt_sandbox` installs a
  `(deny default)` SBPL profile, mirroring the Linux seccomp filter's posture
  and lifecycle -- but Seatbelt mediates *operations*, not syscalls, and there
  are three things it structurally cannot reach: descriptors that were already
  open when the profile was installed (stdio, and the `utun` tap when guest
  networking is on), the whole `mmap`/`mprotect`/`MAP_JIT` surface, and this
  process's own address space. Narrowing those needs a different mechanism
  (a separate broker process holding the `utun` descriptor, for instance), not
  a bigger profile.
* **Landlock integration** for the existing Linux seccomp filter, which
  currently has no path-scoping: a compromised guest that finds a seccomp
  gap can still reach any path the host process can. Partially done:
  `LinuxUserland::enable_landlock_filesystem_ruleset`
  (`litebox_platform_linux_userland/src/lib.rs`) exists, is unit-tested
  (`test_landlock_filesystem_ruleset`, a real, live test asserting actual
  `EACCES` on a never-granted path), and cross-compile-verified
  (`cargo check`/`clippy --target x86_64-unknown-linux-gnu`) from a macOS
  host, where this Linux-only code cannot be built natively -- but it is
  **not called** from `litebox_runner_linux_userland`'s startup. Wiring it
  in broke a real, working integration test
  (`test_runner_broker_integration_with_rewriter`, exit status 14, no
  seccomp-trap warning -- consistent with Landlock returning a plain
  `EACCES` somewhere in the broker/rewriter path) the one time real Linux
  CI actually exercised it end to end, and this macOS host's local x86_64
  Linux VM was unresponsive under host load for the entire session that
  attempted this, leaving no way to live-debug which specific access
  Landlock was denying before shipping it. Left disabled rather than
  merged in a state that broke real functionality and was never actually
  verified working -- see the call site's own comment in
  `litebox_runner_linux_userland/src/lib.rs` for exactly what wiring it
  back in needs. Re-enabling this needs a session with working local
  Linux execution.
* **A WASI-style capability redesign for `litebox_broker_host`'s filesystem
  and socket authorization** -- preopen-style directory capabilities and a
  per-destination socket policy hook, replacing today's coarser
  per-principal rights.
* **`litebox_runner_snp`'s TCP+9P bootstrap migrated to a vsock-style
  channel**, following Firecracker's precedent, to avoid exposing the boot
  channel on a real network interface. The guest-side half (a
  transport-agnostic `ByteChannel`/`PointToPointTransport` abstraction,
  tested) is done; the rest needs a new hypercall implemented in the
  out-of-repo privileged `sandbox_driver` component, which this repo can't
  add or verify. See `docs/vsock-boot-channel.md` for the exact remaining
  contract.
* **Process-level jailing of `litebox_broker_host`** itself (Firecracker's
  jailer, or crosvm's minijail, are the precedents), so a broken broker isn't
  a fully-privileged process.
* **An async-signal-safety audit** across every platform's signal handlers --
  none of the platform crates currently have one, and LiteBox's whole fault
  and interrupt-delivery model runs inside handlers.
* **CI checks that `CallerCredential::Unauthenticated` can't reach the broker
  in non-test builds**, and that malformed/truncated broker messages fail
  closed -- currently enforced by code review, not by an automated check.
