#!/bin/sh

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

set -eu
umask 077

SESSION_DIR="$(mktemp -d /tmp/litebox-xfce.XXXXXX)"
LOG_DIR="$SESSION_DIR/log"
export DISPLAY=:0
export HOME="$SESSION_DIR/home"
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export SHELL=/bin/sh
export XDG_RUNTIME_DIR="$SESSION_DIR/xdg"
export XDG_CONFIG_HOME="$HOME/.config"
export XDG_CACHE_HOME="$HOME/.cache"
export XDG_DATA_HOME="$HOME/.local/share"
export XDG_CONFIG_DIRS=/etc/xdg
export XDG_DATA_DIRS=/usr/local/share:/usr/share
export XDG_MENU_PREFIX=xfce-
export XDG_CURRENT_DESKTOP=XFCE
export XDG_SESSION_DESKTOP=xfce
export XDG_SESSION_TYPE=x11
export DESKTOP_SESSION=xfce
export GDK_BACKEND=x11
export GDK_GL=disable
export LIBGL_ALWAYS_SOFTWARE=1
export NO_AT_BRIDGE=1

mkdir -p "$LOG_DIR" "$XDG_RUNTIME_DIR" "$HOME/Desktop" \
    "$XDG_CONFIG_HOME" "$XDG_CACHE_HOME" "$XDG_DATA_HOME"
chmod 700 "$SESSION_DIR" "$LOG_DIR" "$XDG_RUNTIME_DIR" "$HOME"

fail() {
    printf '%s\n' "$1" >&2
    exit 1
}

print_log() {
    name="$1"
    path="$2"
    printf '%s\n' "--- BEGIN $name ---"
    [ ! -f "$path" ] || cat "$path"
    printf '%s\n' "--- END $name ---"
}

require_alive() {
    name="$1"
    pid="$2"
    log="$3"
    if ! kill -0 "$pid" 2>/dev/null; then
        wait "$pid" 2>/dev/null || true
        printf '%s\n' "$name FAILED" >&2
        [ ! -f "$log" ] || cat "$log" >&2
        exit 1
    fi
}

if [ -L /tmp/.X11-unix ]; then
    fail "refusing symlinked X11 socket directory"
elif [ -e /tmp/.X11-unix ]; then
    [ -d /tmp/.X11-unix ] || fail "X11 socket path is not a directory"
else
    mkdir /tmp/.X11-unix
fi
chmod 1777 /tmp/.X11-unix
[ ! -e /tmp/.X11-unix/X0 ] && [ ! -L /tmp/.X11-unix/X0 ] || \
    fail "display :0 already has an X11 socket"
[ ! -e /tmp/.X0-lock ] && [ ! -L /tmp/.X0-lock ] || \
    fail "display :0 already has an X lock"

panel_config_dir="$XDG_CONFIG_HOME/xfce4/xfconf/xfce-perchannel-xml"
panel_config="$panel_config_dir/xfce4-panel.xml"
panel_staging="$panel_config.new"
mkdir -p "$panel_config_dir"
cp /etc/xdg/litebox/xfce4-panel.xml "$panel_staging"
[ -s "$panel_staging" ] || fail "packaged panel configuration is empty"
chmod 600 "$panel_staging"
mv "$panel_staging" "$panel_config"

XORG_LOG="$LOG_DIR/xorg.log"
XORG_ERR="$LOG_DIR/xorg.err"
/usr/libexec/Xorg :0 \
    -config /etc/X11/xorg.conf \
    -novtswitch -sharevts -keeptty -noreset -nolock -nolisten tcp \
    -logfile "$XORG_LOG" \
    2>"$XORG_ERR" </dev/null &
xorg_pid=$!

i=0
while ! xset q >/dev/null 2>&1; do
    require_alive Xorg "$xorg_pid" "$XORG_LOG"
    i=$((i + 1))
    if [ "$i" -ge 120 ]; then
        print_log xorg.err "$XORG_ERR" >&2
        print_log xorg.log "$XORG_LOG" >&2
        fail "Xorg protocol readiness timed out"
    fi
    sleep 0.25
done
printf '%s\n' "X UP"

export DBUS_SESSION_BUS_ADDRESS="unix:path=$SESSION_DIR/dbus.sock"
DBUS_ERR="$LOG_DIR/dbus.err"
dbus-daemon --session --address="$DBUS_SESSION_BUS_ADDRESS" \
    --nofork --nopidfile 2>"$DBUS_ERR" &
dbus_pid=$!

i=0
while ! dbus-send --session --type=method_call --print-reply \
    --dest=org.freedesktop.DBus / org.freedesktop.DBus.ListNames \
    >/dev/null 2>&1
do
    require_alive dbus-daemon "$dbus_pid" "$DBUS_ERR"
    i=$((i + 1))
    if [ "$i" -ge 80 ]; then
        print_log dbus.err "$DBUS_ERR" >&2
        fail "D-Bus protocol readiness timed out"
    fi
    sleep 0.25
done

dbus-update-activation-environment \
    DISPLAY DESKTOP_SESSION XDG_CACHE_HOME XDG_CONFIG_DIRS XDG_CONFIG_HOME \
    XDG_CURRENT_DESKTOP XDG_DATA_DIRS XDG_DATA_HOME XDG_MENU_PREFIX \
    XDG_RUNTIME_DIR XDG_SESSION_DESKTOP XDG_SESSION_TYPE

set_xfconf() {
    channel="$1"
    property="$2"
    type="$3"
    value="$4"
    xfconf-query -c "$channel" -p "$property" -s "$value" >/dev/null 2>&1 || \
        xfconf-query -c "$channel" -p "$property" -n -t "$type" -s "$value"
}

set_xfconf xfce4-desktop /desktop-icons/show-thumbnails bool false
set_xfconf xfce4-desktop /desktop-icons/style int 2
set_xfconf xfce4-desktop /desktop-icons/file-icons/show-home bool true
set_xfconf xfce4-desktop /desktop-icons/file-icons/show-filesystem bool true
set_xfconf xfce4-desktop /desktop-icons/file-icons/show-trash bool true
output_name="$(xrandr --query | awk '$2 == "connected" { print $1; exit }')"
[ -n "$output_name" ] || output_name=default
for monitor in monitor0 "monitor$output_name"; do
    set_xfconf xfce4-desktop \
        "/backdrop/screen0/$monitor/workspace0/image-style" int 5
    set_xfconf xfce4-desktop \
        "/backdrop/screen0/$monitor/workspace0/last-image" string \
        /usr/share/backgrounds/xfce/xfce-teal.svg
done

XFWM_LOG="$LOG_DIR/xfwm4.log"
xfwm4 --compositor=off >"$XFWM_LOG" 2>&1 &
xfwm_pid=$!
sleep 1
require_alive xfwm4 "$xfwm_pid" "$XFWM_LOG"

XFSETTINGSD_LOG="$LOG_DIR/xfsettingsd.log"
xfsettingsd >"$XFSETTINGSD_LOG" 2>&1 &
xfsettingsd_pid=$!
sleep 1
require_alive xfsettingsd "$xfsettingsd_pid" "$XFSETTINGSD_LOG"

XFDESKTOP_LOG="$LOG_DIR/xfdesktop.log"
xfdesktop >"$XFDESKTOP_LOG" 2>&1 &
xfdesktop_pid=$!
sleep 2
require_alive xfdesktop "$xfdesktop_pid" "$XFDESKTOP_LOG"

PANEL_LOG="$LOG_DIR/xfce4-panel.log"
xfce4-panel >"$PANEL_LOG" 2>&1 &
panel_pid=$!
sleep 2
require_alive xfce4-panel "$panel_pid" "$PANEL_LOG"
require_alive Xorg "$xorg_pid" "$XORG_LOG"

THUNAR_LOG="$LOG_DIR/thunar.log"
thunar "$HOME" >"$THUNAR_LOG" 2>&1 &
thunar_pid=$!
sleep 2
require_alive Thunar "$thunar_pid" "$THUNAR_LOG"

XTERM_LOG="$LOG_DIR/xterm.log"
xterm -geometry 80x24+360+320 -title "LiteBox Terminal" -e /bin/sh \
    >"$XTERM_LOG" 2>&1 &
xterm_pid=$!
sleep 2
require_alive xterm "$xterm_pid" "$XTERM_LOG"

print_log xorg.err "$XORG_ERR"
print_log xorg.log "$XORG_LOG"
print_log dbus.err "$DBUS_ERR"
print_log xfwm4.log "$XFWM_LOG"
print_log xfsettingsd.log "$XFSETTINGSD_LOG"
print_log xfdesktop.log "$XFDESKTOP_LOG"
print_log xfce4-panel.log "$PANEL_LOG"
print_log thunar.log "$THUNAR_LOG"
print_log xterm.log "$XTERM_LOG"
printf '%s\n' "DESKTOP UP"

# Diagnostic-only heartbeat (never calls fail -- purely observational): a
# host-visible timestamped record of whether Xorg's own core protocol round
# trip (the same xset q the health-check loop below already gates on) keeps
# succeeding through a freeze. CONFIRMED LIVE (2026-08-30/31): during an
# actual panel-click freeze (clock static, Applications menu and taskbar
# buttons both dead), this heartbeat kept logging "xset q: OK" every 5s for
# 3.5+ minutes straight, and a titlebar drag (an xfwm4-owned operation) still
# worked during the same freeze -- Xorg and xfwm4 are NOT the wedged party.
# Only xfce4-panel-owned widgets (Applications menu, Show Desktop, taskbar
# icons) stopped responding. Kept as a standing diagnostic so any future
# freeze investigation gets this confirmation for free from the ordinary
# runner log, instead of needing a bespoke instrumented rebuild each time.
(
    while :; do
        sleep 5
        if xset q >/dev/null 2>&1; then
            printf '%s heartbeat: xset q OK\n' "$(date -u +%H:%M:%S)"
        else
            printf '%s heartbeat: xset q FAILED\n' "$(date -u +%H:%M:%S)"
        fi
    done
) &
heartbeat_pid=$!

while :; do
    sleep 5
    require_alive Xorg "$xorg_pid" "$XORG_LOG"
    xset q >/dev/null 2>&1 || fail "Xorg stopped answering protocol requests"
    require_alive dbus-daemon "$dbus_pid" "$DBUS_ERR"
    require_alive xfwm4 "$xfwm_pid" "$XFWM_LOG"
    require_alive xfsettingsd "$xfsettingsd_pid" "$XFSETTINGSD_LOG"
    require_alive xfdesktop "$xfdesktop_pid" "$XFDESKTOP_LOG"
    require_alive xfce4-panel "$panel_pid" "$PANEL_LOG"
done
