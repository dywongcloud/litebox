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
# Repeated RFB session failures or timeouts count as a freeze because the
# VNC-server thread is independent of the guest panel. A bounded retry absorbs
# transient protocol/connection races before recovery.

set -euo pipefail

script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
probe="$script_dir/vnc_probe.py"

# --- configurable knobs (script arguments, in order) -----------------------
TAR_PATH="${1:-/tmp/litebox-xfce-64.tar}"
VNC_PORT="${2:-5900}"
VNC_WEB_PORT="${3:-6080}"

RUNNER_BIN="${RUNNER_BIN:-$script_dir/../../../target/release/litebox_runner_linux_on_macos_userland}"
POLL_SECONDS="${POLL_SECONDS:-5}"
FREEZE_SECONDS="${FREEZE_SECONDS:-65}"
CLICK_SETTLE_SECONDS="${CLICK_SETTLE_SECONDS:-3}"
STARTUP_GRACE_SECONDS="${STARTUP_GRACE_SECONDS:-45}"
RFB_PROBE_ATTEMPTS="${RFB_PROBE_ATTEMPTS:-3}"
RESTART_STORM_LIMIT="${RESTART_STORM_LIMIT:-3}"
RESTART_STORM_WINDOW_SECONDS="${RESTART_STORM_WINDOW_SECONDS:-300}"
RESTART_STORM_BACKOFF_SECONDS="${RESTART_STORM_BACKOFF_SECONDS:-30}"

# Fixed screen coordinates for the panel clock and the Applications-menu
# button, matching the packaged panel.xml layout (top panel, clock at the
# far right, Applications button at the far left) on the default 1024x768
# Xorg fbdev mode configured in xorg.conf. Override via env if the layout
# or resolution changes.
CLOCK_REGION="${CLOCK_REGION:-930 0 90 24}"      # x y w h
MENU_BUTTON="${MENU_BUTTON:-10 10}"              # x y to click
MENU_DISMISS="${MENU_DISMISS:-500 500}"           # x y outside the popup
MENU_POPUP_REGION="${MENU_POPUP_REGION:-0 24 200 300}"  # x y w h, post-click

LOG_DIR="${LOG_DIR:-$script_dir/watchdog-logs}"
mkdir -p "$LOG_DIR"
EVENT_LOG="$LOG_DIR/watchdog-events.log"

log_event() {
    ts="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    printf '[%s] %s\n' "$ts" "$1" | tee -a "$EVENT_LOG" >&2
}

runner_pid=""
run_log=""
runner_started_at=""
runner_started_epoch=0
runner_recovery_reason=""
runner_stop_action="none"
runner_wait_status=""
restart_window_started_epoch=0
restart_count=0

cleanup() {
    if [ -n "$runner_pid" ]; then
        kill_runner "watchdog exit" "watchdog shutdown"
    fi
}
trap cleanup EXIT
trap 'exit 0' INT TERM

launch_runner() {
    run_log="$LOG_DIR/runner-$(date -u '+%Y%m%dT%H%M%SZ').log"
    runner_started_at="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    runner_started_epoch="$(date +%s)"
    runner_recovery_reason=""
    runner_stop_action="none"
    runner_wait_status=""
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
    log_event "runner started, pid=$runner_pid launch_time=$runner_started_at log=$run_log"
}

reap_runner() {
    outcome="$1"
    [ -n "$runner_pid" ] || return 0
    reaped_pid="$runner_pid"
    reaped_log="$run_log"
    reaped_started_at="$runner_started_at"
    reaped_started_epoch="$runner_started_epoch"
    reaped_recovery_reason="${runner_recovery_reason:-none}"
    reaped_stop_action="$runner_stop_action"
    if wait "$reaped_pid"; then
        runner_wait_status=0
    else
        runner_wait_status=$?
    fi
    reaped_epoch="$(date +%s)"
    reaped_runtime=$((reaped_epoch - reaped_started_epoch))
    log_event "runner reaped: outcome=$outcome pid=$reaped_pid launch_time=$reaped_started_at runtime=${reaped_runtime}s log=$reaped_log recovery_intent=$reaped_recovery_reason termination_action=$reaped_stop_action wait_status=$runner_wait_status"
    runner_pid=""
}

# Terminate the current runner: SIGTERM, wait up to 5s for graceful guest
# shutdown/socket cleanup, then SIGKILL if it's still alive.
kill_runner() {
    reason="$1"
    outcome="${2:-watchdog recovery}"
    [ -n "$runner_pid" ] || return 0
    runner_recovery_reason="$reason"
    runner_stop_action="none"
    if kill -0 "$runner_pid" 2>/dev/null; then
        log_event "killing runner pid=$runner_pid ($reason)"
        if kill -TERM "$runner_pid" 2>/dev/null; then
            runner_stop_action="TERM"
        fi
        i=0
        while kill -0 "$runner_pid" 2>/dev/null; do
            i=$((i + 1))
            if [ "$i" -ge 10 ]; then
                log_event "runner pid=$runner_pid did not exit after SIGTERM, sending SIGKILL"
                if kill -KILL "$runner_pid" 2>/dev/null; then
                    if [ "$runner_stop_action" = TERM ]; then
                        runner_stop_action="TERM->KILL"
                    else
                        runner_stop_action="KILL"
                    fi
                fi
                break
            fi
            sleep 0.5
        done
    fi
    reap_runner "$outcome"
}

delay_before_restart() {
    restart_now="$(date +%s)"
    restart_window_age=$((restart_now - restart_window_started_epoch))
    if [ "$restart_window_started_epoch" -eq 0 ] || \
        [ "$restart_window_age" -ge "$RESTART_STORM_WINDOW_SECONDS" ]
    then
        restart_window_started_epoch="$restart_now"
        restart_count=1
    elif [ "$restart_count" -lt "$RESTART_STORM_LIMIT" ]; then
        restart_count=$((restart_count + 1))
    fi

    if [ "$restart_count" -ge "$RESTART_STORM_LIMIT" ]; then
        log_event "RESTART STORM: at least $restart_count runner restarts within ${RESTART_STORM_WINDOW_SECONDS}s; backing off ${RESTART_STORM_BACKOFF_SECONDS}s before continuing recovery"
        sleep "$RESTART_STORM_BACKOFF_SECONDS"
    else
        log_event "runner restart scheduled: count=$restart_count/$RESTART_STORM_LIMIT within ${RESTART_STORM_WINDOW_SECONDS}s; retrying in ${POLL_SECONDS}s"
        sleep "$POLL_SECONDS"
    fi
}

# Query the clock-region pixel hash. Prints "HASH <hex>" on stdout, or
# "ERROR ..." on stderr and returns non-zero if the RFB round trip failed
# outright (itself a freeze signal).
probe_clock() {
    # shellcheck disable=SC2086
    python3 "$probe" hash 127.0.0.1 "$VNC_PORT" $CLOCK_REGION --timeout 4
}

probe_menu_region() {
    # shellcheck disable=SC2086
    python3 "$probe" hash 127.0.0.1 "$VNC_PORT" $MENU_POPUP_REGION --timeout 4
}

probe_click_menu() {
    # shellcheck disable=SC2086
    python3 "$probe" hash 127.0.0.1 "$VNC_PORT" $MENU_POPUP_REGION \
        --click $MENU_BUTTON --timeout 4
}

probe_dismiss_menu() {
    # shellcheck disable=SC2086
    python3 "$probe" hash 127.0.0.1 "$VNC_PORT" $MENU_POPUP_REGION \
        --click $MENU_DISMISS --timeout 4
}

probe_with_retry() {
    probe_name="$1"
    attempt=1
    while :; do
        result="$($probe_name 2>&1)" && {
            printf '%s\n' "$result"
            return 0
        }
        if [ "$attempt" -ge "$RFB_PROBE_ATTEMPTS" ]; then
            printf '%s\n' "$result" >&2
            return 1
        fi
        attempt=$((attempt + 1))
        sleep 0.25
    done
}

wait_for_vnc_ready() {
    i=0
    max=$((STARTUP_GRACE_SECONDS * 2))
    while ! probe_clock >/dev/null 2>&1; do
        if ! kill -0 "$runner_pid" 2>/dev/null; then
            log_event "runner exited without watchdog intervention during startup before VNC became reachable"
            reap_runner "natural guest exit during startup"
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
        delay_before_restart
        continue
    fi
    log_event "VNC reachable, entering steady-state monitoring"

    last_hash=""
    last_change_epoch="$(date +%s)"

    while :; do
        sleep "$POLL_SECONDS"

        if ! kill -0 "$runner_pid" 2>/dev/null; then
            log_event "runner pid=$runner_pid exited without watchdog intervention; relaunching"
            reap_runner "natural guest exit during monitoring"
            break
        fi

        result="$(probe_with_retry probe_clock 2>&1)" || {
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
        dismiss_result="$(probe_with_retry probe_dismiss_menu 2>&1)" || {
            log_event "FREEZE detected: dismiss-click RFB round trip failed ($dismiss_result)"
            kill_runner "dismiss-click RFB failure"
            break
        }
        sleep "$CLICK_SETTLE_SECONDS"
        closed_result="$(probe_with_retry probe_menu_region 2>&1)" || {
            log_event "FREEZE detected: closed-state RFB round trip failed ($closed_result)"
            kill_runner "closed-state RFB failure"
            break
        }
        closed_hash="${closed_result#HASH }"

        click_result="$(probe_with_retry probe_click_menu 2>&1)" || {
            log_event "FREEZE detected: menu-click RFB round trip failed ($click_result)"
            kill_runner "menu-click RFB failure"
            break
        }
        sleep "$CLICK_SETTLE_SECONDS"
        opened_result="$(probe_with_retry probe_menu_region 2>&1)" || {
            log_event "FREEZE detected: opened-state RFB round trip failed ($opened_result)"
            kill_runner "opened-state RFB failure"
            break
        }
        opened_hash="${opened_result#HASH }"

        if [ "$closed_hash" != "$opened_hash" ]; then
            probe_dismiss_menu >/dev/null 2>&1 || true
            log_event "click probe shows the desktop is responsive; resetting staleness timer"
            last_change_epoch="$(date +%s)"
            continue
        fi

        log_event "FREEZE detected: panel clock static for ${stale_for}s AND Applications-menu click produced no visible change"
        kill_runner "confirmed freeze (clock + click probes both stale)"
        break
    done

    delay_before_restart
done
