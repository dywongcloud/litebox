#! /bin/bash

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

# LiteBox performance benchmark suite.
#
# Measures, separately: cached startup/teardown, pure guest CPU execution, a
# high-frequency lightweight-syscall loop, guest process creation (fork /
# vfork / exec), and (where a native equivalent exists) the same workload run
# directly on the host for comparison. Each benchmark runs $REPS times
# (default 5) and reports the median and minimum of wall/user/sys time.
#
# Usage:
#   docs/benchmarks/run.sh [runner] [image-tar]
#
# Defaults: runner = target/release/litebox_runner_linux_on_macos_userland,
# image-tar = the first of $LITEBOX_BENCH_IMAGE, /tmp/litebox-demo/alpine.tar,
# ./alpine.tar that exists.
#
# Environment overrides: REPS (run count, default 5), CPU_ITERS (AWK loop
# iteration count, default 3000000), SYSCALL_COUNT (dd byte count, default
# 50000).
#
# Requires: a codesigned litebox runner binary (see docs/macos.md for the
# entitlement/codesign step), busybox on the guest image (any recent Alpine
# image has one), and for the "native" comparison rows: /usr/bin/awk, dd.

set -eu

RUNNER="${1:-target/release/litebox_runner_linux_on_macos_userland}"
IMAGE="${2:-${LITEBOX_BENCH_IMAGE:-}}"
if [ -z "$IMAGE" ]; then
  for candidate in /tmp/litebox-demo/alpine.tar ./alpine.tar; do
    if [ -f "$candidate" ]; then
      IMAGE="$candidate"
      break
    fi
  done
fi
if [ -z "$IMAGE" ] || [ ! -f "$IMAGE" ]; then
  echo "error: no guest image tar found (pass one as \$2, or set LITEBOX_BENCH_IMAGE)" >&2
  exit 1
fi
if [ ! -x "$RUNNER" ]; then
  echo "error: runner not found or not executable: $RUNNER" >&2
  exit 1
fi

REPS="${REPS:-5}"
CPU_ITERS="${CPU_ITERS:-3000000}"
SYSCALL_COUNT="${SYSCALL_COUNT:-50000}"

LB() { "$RUNNER" --initial-files "$IMAGE" -- "$@"; }

# Runs `$*` $REPS times under `/usr/bin/time -p`, parses real/user/sys from
# each run, and prints "label median-real min-real median-user min-user
# median-sys min-sys" as one row. Individual run times go to stderr so a
# human watching the run can see progress; only the summary row goes to
# stdout, so this composes with the table printers below.
bench_row() {
  label="$1"
  shift
  reals="" users="" syss=""
  i=1
  while [ "$i" -le "$REPS" ]; do
    out=$(mktemp)
    /usr/bin/time -p "$@" >/dev/null 2>"$out" || true
    r=$(awk '/^real /{print $2}' "$out")
    u=$(awk '/^user /{print $2}' "$out")
    s=$(awk '/^sys /{print $2}' "$out")
    rm -f "$out"
    reals="$reals $r"
    users="$users $u"
    syss="$syss $s"
    echo "  [$label] run $i/$REPS: real=${r}s user=${u}s sys=${s}s" >&2
    i=$((i + 1))
  done
  med_real=$(med_min "$reals" med)
  min_real=$(med_min "$reals" min)
  med_user=$(med_min "$users" med)
  min_user=$(med_min "$users" min)
  med_sys=$(med_min "$syss" med)
  min_sys=$(med_min "$syss" min)
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$label" "$med_real" "$min_real" "$med_user" "$min_user" "$med_sys" "$min_sys"
}

# med_min "1.2 0.9 1.5" med|min -> the median or minimum of the given
# whitespace-separated numbers.
med_min() {
  printf '%s\n' "$1" | tr ' ' '\n' | grep -v '^$' | sort -n | awk -v which="$2" '
    { a[NR] = $1 }
    END {
      if (which == "min") {
        print a[1]
      } else if (NR % 2 == 1) {
        print a[(NR + 1) / 2]
      } else {
        print (a[NR / 2] + a[NR / 2 + 1]) / 2
      }
    }'
}

print_header() {
  printf '%-38s %10s %10s %10s %10s %10s %10s\n' \
    "benchmark" "real(med)" "real(min)" "user(med)" "user(min)" "sys(med)" "sys(min)"
}
print_row() {
  old_ifs="$IFS"
  IFS="$(printf '\t')"
  set -- $1
  IFS="$old_ifs"
  printf '%-38s %10s %10s %10s %10s %10s %10s\n' "$1" "$2" "$3" "$4" "$5" "$6" "$7"
}

echo "LiteBox benchmark suite"
echo "runner: $RUNNER"
echo "image:  $IMAGE"
echo "reps:   $REPS   cpu_iters: $CPU_ITERS   syscall_count: $SYSCALL_COUNT"
echo "date:   $(date)"
echo "uname:  $(uname -a)"
echo

print_header

# 1. Cached startup + teardown: the guest does the least possible work, so
#    wall time is dominated by runner process spawn, image mount, guest
#    process init, and teardown.
row=$(bench_row "litebox: startup+teardown (busybox true)" \
  "$RUNNER" --initial-files "$IMAGE" -- /bin/busybox true)
print_row "$row"

# 2. Pure guest CPU execution: no syscalls in the hot loop (verified via
#    LITEBOX_LOG=litebox_shim_linux=trace), so this isolates guest
#    instruction-execution + AOT-rewritten-code cost from syscall overhead.
row=$(bench_row "litebox: awk CPU loop (${CPU_ITERS} iters)" \
  "$RUNNER" --initial-files "$IMAGE" -- /bin/busybox awk \
  "BEGIN {a=0;b=1;for(i=0;i<${CPU_ITERS};i++){c=(a+b)%1000000007;a=b;b=c} print a}")
print_row "$row"

if command -v awk >/dev/null 2>&1; then
  row=$(bench_row "native: awk CPU loop (${CPU_ITERS} iters)" \
    awk "BEGIN {a=0;b=1;for(i=0;i<${CPU_ITERS};i++){c=(a+b)%1000000007;a=b;b=c} print a}")
  print_row "$row"
fi

# 3. High-frequency lightweight syscalls: many tiny read()/write() pairs,
#    the opposite profile from (2) -- syscall-translation-bound, not
#    compute-bound.
row=$(bench_row "litebox: dd 1-byte x${SYSCALL_COUNT} (read+write syscalls)" \
  "$RUNNER" --initial-files "$IMAGE" -- /bin/busybox dd \
  if=/dev/zero of=/dev/null bs=1 "count=${SYSCALL_COUNT}")
print_row "$row"

if command -v dd >/dev/null 2>&1; then
  row=$(bench_row "native: dd 1-byte x${SYSCALL_COUNT} (read+write syscalls)" \
    dd if=/dev/zero of=/dev/null bs=1 "count=${SYSCALL_COUNT}")
  print_row "$row"
fi

# 4. Process creation: vfork (via the shell's own `time` keyword, which is
#    exactly the originally-reported "vfork: Invalid argument" repro) and
#    fork+exec (via a small loop of external commands).
row=$(bench_row "litebox: vfork+exec (sh -c 'time busybox true')" \
  "$RUNNER" --initial-files "$IMAGE" -- /bin/busybox sh -c \
  'time /bin/busybox true' )
print_row "$row"

row=$(bench_row "litebox: fork+exec x10 (sh -c loop of busybox true)" \
  "$RUNNER" --initial-files "$IMAGE" -- /bin/busybox sh -c \
  'i=0; while [ $i -lt 10 ]; do /bin/busybox true; i=$((i+1)); done')
print_row "$row"

if [ -x /bin/sh ]; then
  row=$(bench_row "native: fork+exec x10 (sh -c loop of /usr/bin/true)" \
    /bin/sh -c 'i=0; while [ $i -lt 10 ]; do /usr/bin/true; i=$((i+1)); done')
  print_row "$row"
fi

echo
echo "throughput (guest CPU loop): see the 'awk CPU loop' row's user(min) above;"
echo "iterations/sec = ${CPU_ITERS} / user(min)."
