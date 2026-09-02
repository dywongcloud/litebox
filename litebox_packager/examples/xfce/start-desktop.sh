#!/bin/sh

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

set -eu
umask 077

SESSION_UID=1000
SESSION_GID=1000
SESSION_DIR="$(mktemp -d /tmp/litebox-xfce.XXXXXX)"
LOG_DIR="$SESSION_DIR/log"
export DISPLAY=:0
export HOME="$SESSION_DIR/home"
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export SHELL=/bin/sh
export USER=litebox
export LOGNAME=litebox
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
CONTROL_DIR="$(mktemp -d /tmp/litebox-control.XXXXXX)"
chmod 700 "$CONTROL_DIR"
CONTROL_BUSYBOX="$CONTROL_DIR/busybox"
/bin/busybox cp /bin/busybox "$CONTROL_BUSYBOX"
chmod 700 "$CONTROL_BUSYBOX"

fail() {
    printf '%s\n' "$1" >&2
    exit 1
}

run_user() {
    /bin/setpriv --reuid="$SESSION_UID" --regid="$SESSION_GID" \
        --clear-groups -- "$@"
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

for log_name in xorg.log xorg.err dbus.err xfwm4.log xfsettingsd.log \
    xfdesktop.log xfce4-panel.log thunar.log xterm.log chromium.log
do
    : > "$LOG_DIR/$log_name"
done
chown -R "$SESSION_UID:$SESSION_GID" "$SESSION_DIR"
[ "$(run_user /bin/busybox id -u)" = "$SESSION_UID" ] || \
    fail "desktop credential drop did not set uid $SESSION_UID"
[ "$(run_user /bin/busybox id -g)" = "$SESSION_GID" ] || \
    fail "desktop credential drop did not set gid $SESSION_GID"

XORG_LOG="$LOG_DIR/xorg.log"
XORG_ERR="$LOG_DIR/xorg.err"
/usr/libexec/Xorg :0 \
    -config /etc/X11/xorg.conf \
    -novtswitch -sharevts -keeptty -noreset -nolock -nolisten tcp \
    -logfile "$XORG_LOG" \
    2>"$XORG_ERR" </dev/null &
xorg_pid=$!

i=0
while ! run_user xset q >/dev/null 2>&1; do
    require_alive Xorg "$xorg_pid" "$XORG_ERR"
    i=$((i + 1))
    if [ "$i" -ge 120 ]; then
        print_log xorg.err "$XORG_ERR" >&2
        print_log xorg.log "$XORG_LOG" >&2
        fail "Xorg protocol readiness timed out"
    fi
    "$CONTROL_BUSYBOX" sleep 0.25
done
printf '%s\n' "X UP"

export DBUS_SESSION_BUS_ADDRESS="unix:path=$SESSION_DIR/dbus.sock"
DBUS_ERR="$LOG_DIR/dbus.err"
run_user dbus-daemon --session --address="$DBUS_SESSION_BUS_ADDRESS" \
    --nofork --nopidfile 2>"$DBUS_ERR" &
dbus_pid=$!

i=0
while ! run_user dbus-send --session --type=method_call --print-reply \
    --dest=org.freedesktop.DBus / org.freedesktop.DBus.ListNames \
    >/dev/null 2>&1
do
    require_alive dbus-daemon "$dbus_pid" "$DBUS_ERR"
    i=$((i + 1))
    if [ "$i" -ge 80 ]; then
        print_log dbus.err "$DBUS_ERR" >&2
        fail "D-Bus protocol readiness timed out"
    fi
    "$CONTROL_BUSYBOX" sleep 0.25
done

run_user dbus-update-activation-environment \
    DISPLAY DESKTOP_SESSION XDG_CACHE_HOME XDG_CONFIG_DIRS XDG_CONFIG_HOME \
    XDG_CURRENT_DESKTOP XDG_DATA_DIRS XDG_DATA_HOME XDG_MENU_PREFIX \
    XDG_RUNTIME_DIR XDG_SESSION_DESKTOP XDG_SESSION_TYPE

set_xfconf() {
    channel="$1"
    property="$2"
    type="$3"
    value="$4"
    run_user xfconf-query -c "$channel" -p "$property" -s "$value" >/dev/null 2>&1 || \
        run_user xfconf-query -c "$channel" -p "$property" -n -t "$type" -s "$value"
}

set_xfconf xfce4-desktop /desktop-icons/show-thumbnails bool false
set_xfconf xfce4-desktop /desktop-icons/style int 2
set_xfconf xfce4-desktop /desktop-icons/file-icons/show-home bool true
set_xfconf xfce4-desktop /desktop-icons/file-icons/show-filesystem bool true
set_xfconf xfce4-desktop /desktop-icons/file-icons/show-trash bool true
output_name="$(run_user xrandr --query | awk '$2 == "connected" { print $1; exit }')"
[ -n "$output_name" ] || output_name=default
for monitor in monitor0 "monitor$output_name"; do
    set_xfconf xfce4-desktop \
        "/backdrop/screen0/$monitor/workspace0/image-style" int 5
    set_xfconf xfce4-desktop \
        "/backdrop/screen0/$monitor/workspace0/last-image" string \
        /usr/share/backgrounds/xfce/xfce-teal.svg
done

XFWM_LOG="$LOG_DIR/xfwm4.log"
run_user xfwm4 --compositor=off >"$XFWM_LOG" 2>&1 &
xfwm_pid=$!
"$CONTROL_BUSYBOX" sleep 1
require_alive xfwm4 "$xfwm_pid" "$XFWM_LOG"

XFSETTINGSD_LOG="$LOG_DIR/xfsettingsd.log"
run_user xfsettingsd >"$XFSETTINGSD_LOG" 2>&1 &
xfsettingsd_pid=$!
"$CONTROL_BUSYBOX" sleep 1
require_alive xfsettingsd "$xfsettingsd_pid" "$XFSETTINGSD_LOG"

XFDESKTOP_LOG="$LOG_DIR/xfdesktop.log"
run_user xfdesktop >"$XFDESKTOP_LOG" 2>&1 &
xfdesktop_pid=$!
"$CONTROL_BUSYBOX" sleep 2
require_alive xfdesktop "$xfdesktop_pid" "$XFDESKTOP_LOG"

PANEL_LOG="$LOG_DIR/xfce4-panel.log"
run_user xfce4-panel >"$PANEL_LOG" 2>&1 &
panel_pid=$!
"$CONTROL_BUSYBOX" sleep 2
require_alive xfce4-panel "$panel_pid" "$PANEL_LOG"
require_alive Xorg "$xorg_pid" "$XORG_ERR"

THUNAR_LOG="$LOG_DIR/thunar.log"
run_user thunar "$HOME" >"$THUNAR_LOG" 2>&1 &
thunar_pid=$!
"$CONTROL_BUSYBOX" sleep 2
require_alive Thunar "$thunar_pid" "$THUNAR_LOG"

XTERM_LOG="$LOG_DIR/xterm.log"
run_user xterm -geometry 80x24+360+320 -title "LiteBox Terminal" -e /bin/sh \
    >"$XTERM_LOG" 2>&1 &
xterm_pid=$!
"$CONTROL_BUSYBOX" sleep 2
require_alive xterm "$xterm_pid" "$XTERM_LOG"

CHROMIUM_LOG="$LOG_DIR/chromium.log"
run_user /bin/sh -c '
    uid=$(/bin/busybox id -u)
    gid=$(/bin/busybox id -g)
    if [ "$uid:$gid" != "1000:1000" ]; then
        printf "refusing Chromium identity %s:%s\n" "$uid" "$gid" >&2
        exit 126
    fi
    exec /usr/bin/chromium-browser \
        --disable-gpu \
        --disable-dev-shm-usage \
        --no-first-run \
        --no-default-browser-check \
        about:blank
' >"$CHROMIUM_LOG" 2>&1 &
chromium_pid=$!
"$CONTROL_BUSYBOX" sleep 5
require_alive Chromium "$chromium_pid" "$CHROMIUM_LOG"

print_log xorg.err "$XORG_ERR"
print_log xorg.log "$XORG_LOG"
print_log dbus.err "$DBUS_ERR"
print_log xfwm4.log "$XFWM_LOG"
print_log xfsettingsd.log "$XFSETTINGSD_LOG"
print_log xfdesktop.log "$XFDESKTOP_LOG"
print_log xfce4-panel.log "$PANEL_LOG"
print_log thunar.log "$THUNAR_LOG"
print_log xterm.log "$XTERM_LOG"
print_log chromium.log "$CHROMIUM_LOG"
printf '%s\n' "DESKTOP UP"

while :; do
    if ! "$CONTROL_BUSYBOX" sleep 5; then
        printf '%s\n' "heartbeat: degraded-delay private BusyBox sleep failed; continuing checks" >&2
    fi
    require_alive Xorg "$xorg_pid" "$XORG_ERR"
    if run_user xset q >/dev/null 2>&1; then
        printf '%s\n' "heartbeat: xset q OK"
    else
        fail "Xorg stopped answering protocol requests"
    fi
    require_alive dbus-daemon "$dbus_pid" "$DBUS_ERR"
    require_alive xfwm4 "$xfwm_pid" "$XFWM_LOG"
    require_alive xfsettingsd "$xfsettingsd_pid" "$XFSETTINGSD_LOG"
    require_alive xfdesktop "$xfdesktop_pid" "$XFDESKTOP_LOG"
    require_alive xfce4-panel "$panel_pid" "$PANEL_LOG"
done
