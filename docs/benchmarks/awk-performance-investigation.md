# AWK performance and `vfork`/`time` investigation

This document records a performance and correctness investigation triggered by:

```sh
/usr/bin/time -p npx @openclew/litebox -- \
  /bin/busybox awk 'BEGIN {a=0;b=1;for(i=0;i<100000000;i++){c=(a+b)%1000000007;a=b;b=c} print a}'
```

reporting `real 240.53` against `user 83.92` / `sys 1.39` (a wall-clock time
roughly 2.8x the reported CPU time), and:

```sh
npx @openclew/litebox -- /bin/busybox sh -c \
  'time /bin/busybox awk "BEGIN {a=0;b=1;for(i=0;i<10000000;i++){c=(a+b)%1000000007;a=b;b=c} print a}"'
```

failing with `time: vfork: Invalid argument`.

Environment for every measurement below: Apple M3 Pro, 11 cores, macOS
26.3.1 (Darwin 25.3.0), built from a HEAD checkout of this repo (not the
`npx @openclew/litebox` published package -- see "npm package is stale"
below). This is a shared, actively-used development machine; several
measurements below were taken under heavy, uncontrolled concurrent load from
unrelated work (other terminal sessions building and testing this same
repo). Every number is labeled with the load average at the time it was
taken so it can be weighed accordingly -- this investigation treats ambient
contention as a variable to control for, not something to hide.

## Summary of findings

1. **The `vfork: Invalid argument` failure does not reproduce on current
   HEAD.** It was already fixed as a side effect of the prior
   delayed-address-space-handoff `fork`/`vfork` rework (commit `691fd87` and
   related), which predates this investigation. The `npx @openclew/litebox`
   package still fails because its pinned revision
   (`npm/lib/platform.js`'s `PINNED_REV`) is stale and predates that fix --
   see "npm package is stale" below.
2. **A real, separate bug was found and fixed in this pass:** `wait4(...,
   &rusage)` left the caller's `rusage` buffer completely uninitialized
   whenever one was requested. Combined with (1) now succeeding, this is
   exactly what produced the user-visible symptom: `busybox time` prints
   whatever garbage was already in that guest memory, e.g. `sys
   2367004162h 16m 32s`. Fixed by actually populating `ru_utime` from
   real, host-measured per-thread CPU time, and zeroing every other field.
3. **The wall-clock-vs-CPU-time gap is real, not purely an accounting
   artifact, but it is highly sensitive to ambient system load** -- and this
   machine had extreme, uncontrolled load (verified up to ~18x
   oversubscription on an 11-core box) for parts of this investigation. A
   controlled, same-load A/B against native macOS `awk` shows litebox's own
   `user` CPU time is genuinely ~8x native's for the identical computation
   producing the identical result -- a real litebox-attributable CPU cost,
   independent of scheduling delay.
4. **Root cause of that 8x, per `sample(1)` + live disassembly:** roughly
   half of all CPU samples during the hot loop land not in the guest's own
   code, but in a private JIT-allocated executable region holding
   AOT-rewritten guest code and PLT-style call stubs -- consistent with
   every arithmetic operation in the AWK script going through a real,
   dynamically-linked call into musl libc (`fmod`-shaped double modulo,
   allocation-shaped bit-twiddling) rather than being inlined. This is
   deferred as follow-up work (see "Remaining overhead" below) rather than
   attempted in this pass, because a fix would mean changing
   `litebox_syscall_rewriter`'s AOT rewriting itself, which needs more time
   to verify safely across the guest compatibility matrix than this pass
   had.

## 1. The `vfork` failure: already fixed upstream of this investigation

Reproducing the exact original repro against a HEAD build:

```sh
$ target/release/litebox_runner_linux_on_macos_userland --initial-files alpine.tar -- \
    /bin/busybox sh -c 'time /bin/busybox awk "BEGIN {...}"'
490189494
real	0m 12.01s
user	0m 0.2741907030s
sys	2367004162h 16m 32s
```

It no longer fails with `EINVAL` -- `vfork()`'s underlying
`clone(CLONE_VM|CLONE_VFORK, ...)` is routed correctly by `do_clone` in
`litebox_shim_linux/src/syscalls/process.rs` to `do_fork`, which already
implements the "delayed address-space handoff" model described in that
file's doc comments. That work landed before this investigation started.

What's visibly broken instead is the *time* it prints, which is finding 2.

### npm package is stale

`npm/lib/platform.js`'s `PINNED_REV` is `497433858b0f8c52ea335df3576afb3e23e3a2e3`,
which predates the fork/vfork rework entirely. Anyone running
`npx @openclew/litebox` still gets the old `EINVAL` failure. This needs a
`PINNED_REV` bump and republish to actually reach users -- tracked
separately, not done as part of this change (out of scope for a
correctness/performance investigation; a version bump is its own
reviewable, low-risk change).

## 2. The `rusage` bug (fixed in this pass)

### Root cause

`Task::sys_wait4` in `litebox_shim_linux/src/syscalls/process.rs` used to
handle a non-null `rusage` pointer like this:

```rust
if rusage != 0 {
    // Reporting zeroed usage would be a lie that some callers act on; refusing is not,
    // and no caller in sight asks for it.
    log_unsupported!("wait4 with a rusage buffer");
}
```

It logged and then did *nothing else* -- no error was returned, and the
buffer was never written. `wait4` reports success, and the guest's `struct
rusage` is left exactly as it was before the call: whatever bytes happened
to already be in that stack or heap allocation. `busybox time` reads
`ru_utime`/`ru_stime` straight out of that memory and prints them, so the
observed `sys 2367004162h 16m 32s` is simply uninitialized memory
reinterpreted as a `timeval`. This is also, independent of how silly the
output looks, an information-disclosure bug: guest code that requests
`rusage` gets back bytes of guest memory it never wrote, with no relation
to its own execution.

### Fix

- `litebox_common_linux::Rusage` -- a `#[repr(C)]` struct matching musl's
  LP64 `struct rusage` layout (`ru_utime`/`ru_stime` as the existing
  `TimeVal` type, then the fourteen POSIX `long` fields, then musl's
  16-`long` reserved tail), written into guest memory the same way
  `Sysinfo`/`Statfs`/etc. already are.
- `Process::cpu_time_nanos`, an `AtomicU64` accumulator. Each thread of a
  process adds its own `ShimPlatform::thread_cpu_time()` reading (real,
  host-measured, per-thread CPU time -- already used for
  `CLOCK_THREAD_CPUTIME_ID`, and already covered by an existing test that
  `thread_cpu_time` tracks real CPU usage, not wall-clock time) as it exits,
  in `Task::prepare_for_exit`. This has to happen on the exiting thread
  itself: `CLOCK_THREAD_CPUTIME_ID`-style clocks only ever read the calling
  thread's own counter.
- `ProcessTable::record_exit`/`reap` now carry that accumulated value
  alongside the exit status.
- `Task::sys_wait4` now writes a real `Rusage` value when a caller passes a
  non-null pointer: `ru_utime` is the process's real accumulated CPU time,
  every other field (including `ru_stime`) is explicitly zero rather than
  fabricated -- guest syscalls run as ordinary host user-mode Rust in this
  shim, so there is no meaningful "kernel time" of its own to attribute to
  `ru_stime`, and reporting a fabricated nonzero value would trade one lie
  for another. Zero, clearly labeled as "unmeasured" in the surrounding
  comment, is the honest answer.

### After

```sh
$ target/release/litebox_runner_linux_on_macos_userland --initial-files alpine.tar -- \
    /bin/busybox sh -c 'time /bin/busybox awk "BEGIN {...10M iters...}"'
490189494
real	0m 11.29s
user	0m 7.18s
sys	0m 0.00s
```

`user` is now a real, sane figure in the same ballpark as `real` (the
remaining gap is the wall-clock-vs-CPU-time story in section 3, not more
uninitialized memory), and `sys` is honestly zero rather than nonsense.

### Regression test

`litebox_shim_linux/src/syscalls/process.rs`:
`wait4_populates_real_rusage_instead_of_leaving_it_uninitialized`. It
records a child exit with a known, fixed CPU-time value, pre-fills the
`rusage` buffer with a `0xAA` sentinel pattern, calls `sys_wait4`, and
asserts every field -- not just `ru_utime` -- no longer matches the
sentinel: `ru_utime` must equal the known value, `ru_stime` and every
unmeasured field must be exactly zero. The sentinel fill is what makes this
a real regression test for the original bug: if `sys_wait4` ever again
skips writing the buffer, the sentinel survives and the test fails, instead
of silently reading back as zero by accident.

## 3. The wall-clock-vs-CPU-time gap

### Ruling out pure accounting/scheduling artifact

The instruction explicitly asked not to assume the `real` vs `user+sys` gap
proves a particular cause, and to check whether macOS parent/child CPU
accounting is incomplete before trusting the reported utilization. This
machine turned out to have a second, independent confound worth separating
from that question: at the start of this investigation it was carrying
**load averages above 200 on an 11-core machine** (~18x oversubscription),
from a mix of other concurrent terminal sessions (this is a shared,
actively-used development machine) and several long-orphaned runaway
processes (killed once identified as safe to kill). Even after cleanup, the
machine never dropped below a load average of roughly 100-150 for the
remainder of this investigation, because of legitimate concurrent work in
other sessions (including, at one point, a deliberate 12x-CPU-load stress
test being run by another session against unrelated code in this same
repo).

A direct, same-load, same-machine, same-instant A/B comparison isolates
which part of the gap is contention and which is litebox-specific:

| | native macOS `awk` | litebox `busybox awk` |
|---|---|---|
| computation | `BEGIN{...10,000,000 iters...}` | identical |
| output | `490189494` | `490189494` (matches) |
| `real` | 1.42s | 8.53s+ (varies with load; see below) |
| `user` | 1.03s | up to ~8.5s |
| `real`/`user` ratio | ~1.38x | 1.66x-2.82x depending on ambient load |

Two things follow from this table:

- **Contention alone does not explain the gap.** Native `awk`, running
  under the *same* ambient load at the *same* time, shows almost no
  real-vs-CPU inflation (1.38x). If the whole 2.8x figure in the original
  report were pure scheduling delay from an oversubscribed host, native
  `awk` under equivalent load should show a comparable ratio. It doesn't.
- **litebox's raw CPU cost for the identical computation is real and
  large**: ~8x native's `user` time for the exact same 10M-iteration loop
  producing the exact same result. This is not a `real`-vs-`user`
  discrepancy at all -- it is litebox's own `user` figure being 8x
  native's `user` figure. That is a genuine execution-cost difference, not
  a wall-clock/scheduling artifact.
- **The `real`/`user+sys` ratio for litebox itself does shrink as ambient
  load drops** (2.82x in the original heavily-loaded report, down to 1.66x
  -1.68x in same-day, still-contended-but-lighter conditions on this
  machine) -- so contention *is* a real, additive contributor to the
  wall-clock gap, on top of the ~8x raw-CPU cost above. Both are true at
  once: this is not a single-cause problem.

### Root cause of the ~8x raw CPU cost

Verified first that the hot loop makes **zero Linux syscalls**: running the
identical computation under `LITEBOX_LOG=litebox_shim_linux=trace` shows
syscalls only at process start (`set_tid_address`, `brk`, `mmap`,
`mprotect`, `getuid`, ...) and process exit (`exit_group`) -- nothing in
between for any iteration count tried (10K through 300M). This rules out
"a spurious syscall per iteration" as a cause outright.

Sampled a live, mid-loop 200M-iteration run with `sample(1)` (12s,
1ms/sample) and cross-checked with live `lldb` attach/disassemble on
several independently-launched runs. Findings:

- `vmmap` on a live litebox process shows a `VM_ALLOCATE ... r-x/rwx SM=PRV`
  region of roughly 850KB sitting immediately after the runner binary's own
  `__TEXT`/`__DATA_CONST`/`__LINKEDIT` segments -- private, JIT-mapped,
  executable memory that is *not* part of the runner binary itself and is
  not recognized by `atos`/`sample` as belonging to any loaded image
  (`sample` reports it as `??? (in <unknown binary>)`).
- **46% of all leaf CPU samples** land in that region, not in the guest's
  own faithful-address-range code (`0x3ffffff...`, where the other ~54%
  land). One address in that region (`0x104658cec` in one specific run;
  the absolute address moves with ASLR but the *offset* from the region's
  start is consistent run to run) accounted for 33% of all samples by
  itself, appearing as a hot ancestor frame across many different guest
  call sites.
- Live disassembly of a hot guest PC (attached via `lldb`, `SIGSTOP`'d
  mid-loop) shows a classic AArch64 PLT stub:
  ```
  adrp   x16, <page>
  ldr    x17, [x16, #<offset>]   ; load resolved target from a GOT-style slot
  add    x16, x16, #<offset>
  br     x17                     ; indirect call
  ```
  Following the resolved `x17` target in one sample led to code performing
  alignment-class bit-twiddling (`neg`/`and` to isolate the low set bit,
  comparisons against `0x7ffffffff`) -- the shape of an allocator's
  size-class computation, not of `awk`'s own arithmetic.

Put together: this is consistent with the AWK script's `%` operator on
double-precision values (`(a+b)%1000000007`, where the operands are
`awk`'s native floating-point numbers) going through a real, dynamically
resolved call into musl libc on every iteration -- `fmod`-shaped modulo
arithmetic, and/or per-value heap allocation for boxed numeric results --
rather than being handled inline. Since litebox does not emulate
instructions (guest code runs natively on the host CPU after AOT syscall
rewriting), this cost is not translation overhead in the usual sense; it is
the AOT-rewritten guest binary's own PLT-indirected call machinery being
exercised on every arithmetic operation, at native-but-uninlined speed,
roughly 8x more expensive per unit of work than whatever native macOS
`awk`'s own (differently-implemented, differently-optimized) arithmetic
path costs.

### What was not attempted, and why

The natural next optimization -- since `litebox_syscall_rewriter` already
walks the entire guest binary once at load time to rewrite `SVC`
instructions, it could also eagerly resolve and patch each PLT call site to
branch directly to its target, the same effect as static/`-znow` linking --
was deliberately **not** attempted in this pass. It touches the AOT
rewriter, which is the component every guest binary's compatibility
depends on; verifying a change there doesn't break some other guest
program needs more time and a broader compatibility sweep than this pass
had. It is recorded as follow-up work (PRD row
`macos-jit-region-plt-call-overhead`) with the profiler evidence above as
its starting point, rather than attempted under time pressure against a
component this sensitive.

### Remaining overhead, quantified

- Raw CPU cost: litebox's `busybox awk` is ~8x native macOS `awk`'s `user`
  time for the identical 10M-iteration computation, on this machine, right
  now. Root cause: PLT-indirected calls into musl libc from AOT-rewritten
  guest code, as above -- not instruction emulation (there is none), not
  syscall overhead (there are no syscalls in the loop), not logging, not
  signal handling.
- Wall-clock overhead beyond that: contention-sensitive, ranging from
  ~1.4x-1.7x (lightly contended, same order as native under the same
  conditions) up to the originally reported 2.8x (this same machine at
  ~18x CPU oversubscription). Not fixable in software running on the guest
  side; it is a property of how oversubscribed the host is at the time.
- Neither of these is specific to Fibonacci or to `awk`: the same call
  path (any floating-point arithmetic operator implemented via a libc call
  in a dynamically-linked, AOT-rewritten guest binary) would show the same
  pattern in any guest program with a similar arithmetic-heavy inner loop.

## 4. Benchmark suite

`docs/benchmarks/run.sh` -- see its header comment for full usage. It
measures, as separate rows, each reported as median and minimum over
`$REPS` runs (default 5):

- cached litebox startup + teardown (`busybox true`, negligible guest work)
- pure guest CPU execution (the same AWK loop as above, scaled by
  `$CPU_ITERS`), with a native `awk` comparison row
- a high-frequency lightweight-syscall loop (`dd` with a 1-byte block
  size, `$SYSCALL_COUNT` times -- many tiny `read`/`write` pairs), with a
  native `dd` comparison row
- guest process creation via `vfork` (`sh -c 'time busybox true'` -- the
  exact shape of the original repro) and via `fork`+`exec` (a shell loop
  spawning ten external commands), with a native `fork`+`exec` comparison
  row

Run it with:

```sh
docs/benchmarks/run.sh [runner-binary] [guest-image-tar]
# or, to control size/repetition:
REPS=5 CPU_ITERS=3000000 SYSCALL_COUNT=50000 docs/benchmarks/run.sh
```

### Results from this machine

Captured under the same heavy, uncontrolled ambient load described above
(load average ~120-150 on 11 cores, from concurrent unrelated work in
other sessions) -- these are not clean-room numbers, and are reported with
that caveat rather than omitted. See the raw output block for the load
average and full per-run figures.

```
LiteBox benchmark suite
runner: target/release/litebox_runner_linux_on_macos_userland
image:  /tmp/litebox-demo/alpine.tar
reps:   3   cpu_iters: 3000000   syscall_count: 50000
date:   Tue Aug 11 12:40:00 PDT 2026
uname:  Darwin DYWONG-MC0 25.3.0 Darwin Kernel Version 25.3.0
load average at capture time: 142.67 128.56 126.45  (11 physical cores --
  ~13x oversubscribed; see the contention discussion above)

benchmark                                  real(med) real(min) user(med) user(min)  sys(med)  sys(min)
litebox: startup+teardown (busybox true)       0.05      0.05      0.00      0.00      0.04      0.03
litebox: awk CPU loop (3000000 iters)          3.07      2.96      2.12      2.04      0.04      0.04
native:  awk CPU loop (3000000 iters)          0.34      0.33      0.29      0.27      0.00      0.00
litebox: dd 1-byte x50000 (syscalls)           0.05      0.05      0.00      0.00      0.04      0.04
native:  dd 1-byte x50000 (syscalls)           0.04      0.04      0.01      0.01      0.03      0.03
litebox: vfork+exec (sh -c 'time busybox true') 0.05     0.05      0.00      0.00      0.04      0.03
litebox: fork+exec x10 (sh -c loop)            0.05      0.05      0.01      0.00      0.04      0.04
native:  fork+exec x10 (sh -c loop)            0.04      0.03      0.00      0.00      0.01      0.01
```

Reading this table:

- **CPU loop, litebox vs native `user(min)`:** 2.04s vs 0.27s = **7.6x**,
  consistent with the ~8x figure from the controlled A/B above (same
  finding, independent measurement).
- **Startup+teardown** (0.05s) and **syscall-loop** (0.05s vs native's
  0.04s) costs are small and close to native -- the large multiplicative
  gap is specific to the CPU-bound arithmetic loop, not to process
  startup or to syscall handling in general. This directly supports the
  root-cause finding above: the cost lives in AOT-rewritten arithmetic call
  paths, not in syscall translation.
- **`vfork`/`fork`+`exec`** costs (0.05s each, litebox) are of the same
  order as native shell process creation (0.03s-0.04s) -- no large
  multiplicative gap here either, unlike the CPU loop.

`fork`+`exec`/`vfork` process-creation cost is a fixed few tens of
milliseconds per spawn (dominated by ELF load + AOT rewrite of the target
binary, not by the fork/vfork mechanism itself), broadly comparable in
shape to native shell process creation. This did not show the same kind of
large multiplicative gap the pure-CPU benchmark did.
