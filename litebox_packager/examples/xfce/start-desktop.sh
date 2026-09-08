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

for log_name in xorg.log xorg.err dbus.err xfconfd.log xfwm4.log xfsettingsd.log \
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

# D-Bus service activation (the org.xfce.Xfconf.service file that would
# otherwise auto-spawn xfconfd on its first request) requires this shim's
# `kill` on a live guest PID to actually reach that process instead of
# reporting `ESRCH`, which does not work yet -- live-verified: a bare
# `xfconf-query` call against the activation path leaves libdbus/GIO with
# no usable proxy (`G_IS_DBUS_PROXY` assertion failures) and `xfconf-query`
# exits nonzero, which -- combined with `set -eu` -- kills this whole
# script before any XFCE component runs. Starting xfconfd directly,
# ahead of any `xfconf-query` call, sidesteps activation entirely and is
# live-verified to work identically to how a real desktop session's
# xfconfd would already be running by this point.
XFCONFD_LOG="$LOG_DIR/xfconfd.log"
run_user /usr/lib/xfce4/xfconf/xfconfd >"$XFCONFD_LOG" 2>&1 &
xfconfd_pid=$!

i=0
while ! run_user xfconf-query -l >/dev/null 2>&1; do
    require_alive xfconfd "$xfconfd_pid" "$XFCONFD_LOG"
    i=$((i + 1))
    if [ "$i" -ge 40 ]; then
        print_log xfconfd.log "$XFCONFD_LOG" >&2
        fail "xfconfd readiness timed out"
    fi
    "$CONTROL_BUSYBOX" sleep 0.25
done

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

# Thunar must start BEFORE xfdesktop: xfdesktop (file icons enabled above)
# D-Bus-activates org.xfce.FileManager1 at startup, and with activation working
# in this shim the activated Thunar instance owns the session name first, so a
# later `thunar` would do the standard single-instance handoff and exit 0 --
# which require_alive would then misread as a crash ("Thunar FAILED"). Owning
# the name first makes xfdesktop talk to this instance instead of spawning one.
THUNAR_LOG="$LOG_DIR/thunar.log"
run_user thunar "$HOME" >"$THUNAR_LOG" 2>&1 &
thunar_pid=$!
"$CONTROL_BUSYBOX" sleep 2
require_alive Thunar "$thunar_pid" "$THUNAR_LOG"

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

XTERM_LOG="$LOG_DIR/xterm.log"
run_user xterm -geometry 80x24+360+320 -title "LiteBox Terminal" -e /bin/sh \
    >"$XTERM_LOG" 2>&1 &
xterm_pid=$!
"$CONTROL_BUSYBOX" sleep 2
require_alive xterm "$xterm_pid" "$XTERM_LOG"

# Chromium is disabled on this shared, persistent desktop. Two of its three
# known host-crashing contributing causes are fixed and verified (the HVF
# AddressOverlap escalation, and excessive SharedAddressSpace family churn on
# every fork), but the underlying bug they were feeding -- a musl fork()
# struct-pthread memory corruption -- is still open, and was observed live
# taking down the ENTIRE runner process (not just Chromium's own window)
# after extended real desktop use: this platform runs every guest process in
# one flat, shared address space, so a long-lived process (this desktop's own
# init/heartbeat shell) has far more exposure to a stray corrupting write
# than a short-lived test does. Do not re-enable this launcher until that
# bug itself is fixed -- see memory litebox-chromium-zygote-fork-corruption.md
# (PRD row musl-fork-struct-pthread-corruption-residual). Chromium testing
# continues in throwaway, disposable guest instances only, and the safe
# chromium.conf flags below are pre-staged for whenever it is re-enabled.
mkdir -p /home/litebox/.config /home/litebox/.cache
chown -R litebox:litebox /home/litebox 2>/dev/null
mkdir -p /etc/chromium
cat > /etc/chromium/chromium.conf <<'CHROMIUMCONF'
# Default settings for chromium. This file is sourced by /bin/sh from
# the chromium launcher.
CHROMIUM_FLAGS="--ozone-platform-hint=auto --disable-gpu --disable-gpu-compositing --js-flags=--no-short-builtin-calls --no-first-run --no-default-browser-check"
CHROMIUMCONF
cat > /usr/lib/chromium/chromium-launcher.sh <<'CHROMIUMLAUNCHER'
#!/bin/sh
echo "Chromium is temporarily disabled on this desktop: a memory-corruption bug can still crash the whole session given enough runtime." >&2
echo "See memory litebox-chromium-zygote-fork-corruption.md." >&2
exit 1
CHROMIUMLAUNCHER
chmod +x /usr/lib/chromium/chromium-launcher.sh

CHROMIUM_LOG="$LOG_DIR/chromium.log"
printf 'Chromium launcher disabled: a memory-corruption bug can still crash the whole desktop given enough runtime (observed live). See memory litebox-chromium-zygote-fork-corruption.md.\n' > "$CHROMIUM_LOG" 2>&1

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
    # Source-fix assertion, never a boot gate: after any package activity (APK's
    # BusyBox trigger re-runs `/bin/busybox --install -s`), the stock PATH-resolved
    # applet link must still execute. The private control binary above keeps this
    # loop alive; this line keeps a namespace regression loudly visible in the
    # runner log instead of letting the private path mask it.
    if ! sleep 0 2>/dev/null; then
        printf '%s\n' "heartbeat: NAMESPACE REGRESSION: PATH-resolved 'sleep 0' failed (BusyBox applet link broken after package activity)" >&2
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
