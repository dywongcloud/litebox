#!/bin/sh

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

set -eu

export DISPLAY=:0
export HOME=/tmp/home
export SHELL=/bin/sh
export XDG_RUNTIME_DIR=/tmp/xdg
export GDK_BACKEND=x11
# The accessibility bus is outside this direct XFCE session and would start
# another process closure needlessly.
export NO_AT_BRIDGE=1

mkdir -p /tmp/.X11-unix "$XDG_RUNTIME_DIR" "$HOME"
chmod 1777 /tmp/.X11-unix
chmod 700 "$XDG_RUNTIME_DIR" "$HOME"

/usr/libexec/Xorg :0 \
    -config /etc/X11/xorg.conf \
    -novtswitch -sharevts -keeptty -noreset -nolock \
    -logfile /tmp/xorg.log \
    2>/tmp/xorg.err </dev/null &

# litebox's in-memory fs does not expose socket-type inode bits yet: X0 is
# deliberately represented by an existing regular entry, so test -e, not -S.
i=0
while [ ! -e /tmp/.X11-unix/X0 ] && [ "$i" -lt 240 ]; do
    sleep 0.5
    i=$((i + 1))
done
if [ ! -e /tmp/.X11-unix/X0 ]; then
    echo "X FAILED"
    cat /tmp/xorg.err
    exit 1
fi
echo "X UP"

dbus-daemon --session --address=unix:path=/tmp/dbus.sock \
    --nofork --nopidfile 2>/tmp/dbus.err &
export DBUS_SESSION_BUS_ADDRESS=unix:path=/tmp/dbus.sock
sleep 2

xfwm4 --compositor=off >/tmp/xfwm4.log 2>&1 &
sleep 2
xfdesktop >/tmp/xfdesktop.log 2>&1 &
sleep 2
xfce4-panel >/tmp/xfce4-panel.log 2>&1 &
echo "DESKTOP LAUNCHED"

while :; do sleep 3600; done
