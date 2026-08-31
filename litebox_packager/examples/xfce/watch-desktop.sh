#!/bin/sh

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

# Standing watchdog for the litebox XFCE desktop demo.
#
# Launches litebox_runner_linux_on_macos_userland (running
# /usr/bin/start-desktop.sh as the guest init) with the same arguments used
# for interactive sessions, then polls its VNC server for liveness. On a
# detected freeze it kills and cleanly relaunches the runner, logging every
# restart with a timestamp so recurrences accumulate forensic evidence
# instead of being silently papered over.
#
# Detection mechanism (see docs/roadmap.md's X16/freeze investigation for
# background on what was ruled out): poll over the RFB/VNC protocol itself
# rather than X11, since the desktop is already observed to go partially
# unresponsive (panel clock frozen, clicks dead) while still being alive at
# the process level -- an X11 round trip would be ambiguous with the very
# freeze being diagnosed. Each poll:
#   1. Hashes the pixel region under the panel clock via an incremental
#      FramebufferUpdateRequest.
#   2. If that hash hasn't changed for FREEZE_SECONDS, sends a synthetic
#      click at the Applications-menu button's coordinates and re-samples
#      the menu popup region shortly after.
# A freeze is declared only when BOTH the clock is stale AND the click probe
# produces no visible change -- this avoids false positives during genuine
# idle periods (clock coincidentally sampled the same minute twice) and
# exploits the documented asymmetry (cursor motion keeps working even when
# clicks/clock don't) as the actual liveness proof, since passive
# clock-watching alone can't distinguish "idle" from "frozen".
#
# If the RFB session itself fails or times out (the runner's VNC-server
# thread not answering at all), that alone counts as a freeze -- it is a
# stronger signal than a within-session pixel-hash staleness.

set -euo pipefail

script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
probe="$script_dir/vnc_probe.py"

# --- configurable knobs (script arguments, in order) -----------------------
TAR_PATH="${1:-/tmp/litebox-xfce-64-patched.tar}"
VNC_PORT="${2:-5900}"
VNC_WEB_PORT="${3:-6080}"

RUNNER_BIN="${RUNNER_BIN:-$script_dir/../../../target/release/litebox_runner_linux_on_macos_userland}"
POLL_SECONDS="${POLL_SECONDS:-5}"
FREEZE_SECONDS="${FREEZE_SECONDS:-65}"
CLICK_SETTLE_SECONDS="${CLICK_SETTLE_SECONDS:-3}"
STARTUP_GRACE_SECONDS="${STARTUP_GRACE_SECONDS:-45}"

# Fixed screen coordinates for the panel clock and the Applications-menu
# button, matching the packaged panel.xml layout (top panel, clock at the
# far right, Applications button at the far left) on the default 1024x768
# Xorg fbdev mode configured in xorg.conf. Override via env if the layout
# or resolution changes.
CLOCK_REGION="${CLOCK_REGION:-930 0 90 24}"      # x y w h
MENU_BUTTON="${MENU_BUTTON:-10 10}"              # x y to click
MENU_POPUP_REGION="${MENU_POPUP_REGION:-0 24 200 300}"  # x y w h, post-click

LOG_DIR="${LOG_DIR:-$script_dir/watchdog-logs}"
mkdir -p "$LOG_DIR"
EVENT_LOG="$LOG_DIR/watchdog-events.log"

log_event() {
    ts="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    printf '[%s] %s\n' "$ts" "$1" | tee -a "$EVENT_LOG" >&2
}

runner_pid=""

cleanup() {
    if [ -n "$runner_pid" ] && kill -0 "$runner_pid" 2>/dev/null; then
        kill -TERM "$runner_pid" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

launch_runner() {
    run_log="$LOG_DIR/runner-$(date -u '+%Y%m%dT%H%M%SZ').log"
    log_event "launching runner: $RUNNER_BIN --unstable --guest-root --net-proxy --initial-files $TAR_PATH --vnc --vnc-port $VNC_PORT --vnc-web $VNC_WEB_PORT -- /usr/bin/start-desktop.sh (log: $run_log)"
    "$RUNNER_BIN" \
        --unstable \
        --guest-root \
        --net-proxy \
        --initial-files "$TAR_PATH" \
        --vnc \
        --vnc-port "$VNC_PORT" \
        --vnc-web "$VNC_WEB_PORT" \
        -- /usr/bin/start-desktop.sh \
        >"$run_log" 2>&1 &
    runner_pid=$!
    log_event "runner started, pid=$runner_pid"
}

# Terminate the current runner: SIGTERM, wait up to 5s for graceful guest
# shutdown/socket cleanup, then SIGKILL if it's still alive.
kill_runner() {
    reason="$1"
    if [ -z "$runner_pid" ] || ! kill -0 "$runner_pid" 2>/dev/null; then
        return 0
    fi
    log_event "killing runner pid=$runner_pid ($reason)"
    kill -TERM "$runner_pid" 2>/dev/null || true
    i=0
    while kill -0 "$runner_pid" 2>/dev/null; do
        i=$((i + 1))
        if [ "$i" -ge 10 ]; then
            log_event "runner pid=$runner_pid did not exit after SIGTERM, sending SIGKILL"
            kill -KILL "$runner_pid" 2>/dev/null || true
            break
        fi
        sleep 0.5
    done
    wait "$runner_pid" 2>/dev/null || true
    runner_pid=""
}

# Query the clock-region pixel hash. Prints "HASH <hex>" on stdout, or
# "ERROR ..." on stderr and returns non-zero if the RFB round trip failed
# outright (itself a freeze signal).
probe_clock() {
    # shellcheck disable=SC2086
    python3 "$probe" hash 127.0.0.1 "$VNC_PORT" $CLOCK_REGION --timeout 4
}

# Click the Applications-menu button, then sample the popup region.
probe_click_menu() {
    # shellcheck disable=SC2086
    python3 "$probe" hash 127.0.0.1 "$VNC_PORT" $MENU_POPUP_REGION \
        --click $MENU_BUTTON --timeout 4
}

wait_for_vnc_ready() {
    i=0
    max=$((STARTUP_GRACE_SECONDS * 2))
    while ! probe_clock >/dev/null 2>&1; do
        if ! kill -0 "$runner_pid" 2>/dev/null; then
            log_event "runner exited during startup before VNC became reachable"
            return 1
        fi
        i=$((i + 1))
        if [ "$i" -ge "$max" ]; then
            log_event "VNC server did not become reachable within ${STARTUP_GRACE_SECONDS}s"
            return 1
        fi
        sleep 0.5
    done
    return 0
}

# --- main watchdog loop -----------------------------------------------------
log_event "watchdog starting: tar=$TAR_PATH vnc_port=$VNC_PORT vnc_web=$VNC_WEB_PORT"

while :; do
    launch_runner

    if ! wait_for_vnc_ready; then
        kill_runner "failed to come up"
        sleep "$POLL_SECONDS"
        continue
    fi
    log_event "VNC reachable, entering steady-state monitoring"

    last_hash=""
    last_change_epoch="$(date +%s)"

    while :; do
        sleep "$POLL_SECONDS"

        if ! kill -0 "$runner_pid" 2>/dev/null; then
            log_event "runner pid=$runner_pid exited unexpectedly; relaunching"
            break
        fi

        result="$(probe_clock 2>&1)" || {
            log_event "FREEZE detected: RFB probe failed/timed out ($result)"
            kill_runner "RFB probe failure"
            break
        }
        hash="${result#HASH }"
        now="$(date +%s)"

        if [ "$hash" != "$last_hash" ]; then
            last_hash="$hash"
            last_change_epoch="$now"
            continue
        fi

        stale_for=$((now - last_change_epoch))
        if [ "$stale_for" -lt "$FREEZE_SECONDS" ]; then
            continue
        fi

        # Clock has been static for FREEZE_SECONDS: this alone could just be
        # an idle desktop, so run the click probe as the actual liveness
        # test before declaring a freeze.
        log_event "clock region stale for ${stale_for}s, running click probe"
        pre_click_result="$(probe_click_menu 2>&1)" || {
            log_event "FREEZE detected: click-probe RFB round trip failed ($pre_click_result)"
            kill_runner "click-probe RFB failure"
            break
        }
        pre_click_hash="${pre_click_result#HASH }"
        sleep "$CLICK_SETTLE_SECONDS"
        post_click_result="$(probe_click_menu 2>&1)" || {
            log_event "FREEZE detected: post-click RFB round trip failed ($post_click_result)"
            kill_runner "post-click RFB failure"
            break
        }
        post_click_hash="${post_click_result#HASH }"

        if [ "$pre_click_hash" != "$post_click_hash" ]; then
            # Menu popup rendered -> the desktop is alive; the clock region
            # just happened not to change (unlikely but possible if the
            # region coordinates are slightly off). Reset the staleness
            # timer and keep monitoring rather than false-triggering.
            log_event "click probe shows the desktop is responsive; resetting staleness timer"
            last_change_epoch="$now"
            continue
        fi

        log_event "FREEZE detected: panel clock static for ${stale_for}s AND Applications-menu click produced no visible change"
        kill_runner "confirmed freeze (clock + click probes both stale)"
        break
    done

    sleep "$POLL_SECONDS"
done
