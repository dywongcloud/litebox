#!/usr/bin/env bash
# host_contention_snapshot.sh -- host (macOS) CPU/memory contention snapshot,
# meant to be captured alongside any HVF guest responsiveness witness
# (e.g. vnc_probe.py) so a "slow" result can be attributed correctly.
#
# Why this exists (lanmower):
# Perceived slowness inside a litebox HVF guest (e.g. the XFCE+Chromium
# desktop) can come from host scheduling contention that has nothing to do
# with litebox -- cloud-sync daemons, Spotlight indexing, corporate VPN/MDM
# agents, this workflow's own agent-runner daemon, etc. -- rather than from
# anything actually fixable inside the guest or the hypervisor backend. This
# script has no opinion and makes no guest-side change; it just captures the
# host-side facts (load averages, free-RAM accounting, swap headroom, and the
# top host CPU consumers by process) at one point in time, so a future perf
# witness can separate host-external slowness from a real litebox regression
# instead of conflating the two.
#
# Usage:
#   ./host_contention_snapshot.sh [label]
#
# Run it immediately before (and ideally again immediately after) any guest
# responsiveness probe and keep both outputs alongside that probe's own
# evidence. Exit status is always 0: this is best-effort diagnostics and must
# never fail (or be treated as failing) a witness run.

set -u
label="${1:-snapshot}"
ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

echo "===== host-contention-snapshot: ${label} @ ${ts} ====="

echo "--- uptime / load averages ---"
uptime

echo "--- cpu core count ---"
sysctl -n hw.ncpu 2>/dev/null

echo "--- free memory (vm_stat) ---"
vm_stat_out="$(vm_stat 2>/dev/null)"
echo "$vm_stat_out"
free_pages="$(printf '%s\n' "$vm_stat_out" | awk '/^Pages free:/ {gsub("\\.", "", $3); print $3}')"
if [ -n "${free_pages:-}" ]; then
  free_bytes=$((free_pages * 16384))
  free_mb=$((free_bytes / 1024 / 1024))
  echo "free_pages=${free_pages} free_bytes=${free_bytes} free_mb=${free_mb}"
  # Mirrors this project's own standing HVF-guest-launch memory-safety gate
  # (see STANDING_CONSTRAINTS: do not launch a test guest under ~1GB free).
  if [ "$free_bytes" -lt 1073741824 ]; then
    echo "WARNING: free RAM below ~1GB -- project rule says do not launch a test HVF guest right now"
  fi
fi

echo "--- swap ---"
sysctl vm.swapusage 2>/dev/null

echo "--- top host CPU consumers (ps, %cpu desc, top 20) ---"
ps -Ao pid,ppid,pcpu,pmem,comm -r 2>/dev/null | head -21

echo "===== end host-contention-snapshot: ${label} ====="
