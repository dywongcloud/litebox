#! /bin/bash

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

# Rebuilds the Alpine packages on a desktop guest's rendering-critical path
# with `-ffixed-x18`, producing a local APK repository that an image build
# can install over the stock packages.
#
# Why: XNU zeroes the AArch64 platform register `x18` on every return to
# EL0 (see docs/roadmap.md, "XNU destroys a live guest x18"). Stock Alpine
# userland is compiled with `x18` as an ordinary allocatable register, so
# any hot loop that parks a live value there computes garbage whenever the
# host preempts the guest. Measured live on this repo's XFCE image: busybox
# `sha256sum` of a 7 MB file returns a different wrong digest on every run
# while `cat` of the same file is byte-perfect -- the reads are fine, the
# *arithmetic* corrupts. The same mechanism randomly breaks ld.so
# relocation ("Exec format error" loading an intact library) and leaves
# GTK/Xorg paint loops silently wrong. `-ffixed-x18` removes the register
# from the allocation pool; code built with it is ABI-compatible with stock
# code (x18 is caller-saved on Linux), so a partial rebuild is safe -- each
# rebuilt library strictly shrinks the corruption surface.
#
# The companion `build-musl-x18-fixed.sh` covers musl itself via the
# packager's content-addressed cache. This script covers everything else a
# desktop paints through. It does NOT try to rebuild the whole rootfs:
# webkit2gtk/ffmpeg/mesa/llvm are hours of build time and off the paint
# path; a crash in a thumbnailer does not take the desktop down.
#
# The build container is kept around (litebox-x18-repo-build) and packages
# already present in its output directory are skipped, so re-running after
# a failure resumes rather than starting over.
#
# Usage: build-x18-desktop-repo.sh [ALPINE_BRANCH] [OUT_DIR] [PKG ...]
#   ALPINE_BRANCH  aports branch (default 3.24-stable); must match the
#                  Alpine version of the image being packaged.
#   OUT_DIR        where the finished repo is copied
#                  (default ~/.cache/litebox/x18-desktop-repo).
#   PKG ...        override the package list entirely (aports dir names).

set -eo pipefail

RED="\033[0;31m"; YELLOW="\033[0;33m"; GREEN="\033[0;32m"; BOLD="\033[1m"; RESET="\033[0m"
fatal() { echo -e "${RED}${BOLD}[!]${RESET} $1" 1>&2; exit 1; }
info()  { echo -e "${BOLD}[i]${RESET} $1" 1>&2; }
success() { echo -e "${GREEN}${BOLD}[+]${RESET} $1" 1>&2; }

ALPINE_BRANCH="${1:-3.24-stable}"
ALPINE_TAG="${ALPINE_BRANCH%-stable}"
OUT_DIR="${2:-$HOME/.cache/litebox/x18-desktop-repo}"
shift 2 2>/dev/null || shift $# # remaining args, if any, replace the list

# The rendering-critical closure of the XFCE image, by aports directory
# name. Ordered roughly leaf-first only for nicer progress output; build
# order does not matter (each abuild installs stock -dev packages for its
# build deps; only the produced runtime artifacts differ).
DEFAULT_PACKAGES=(
    # core plumbing every process touches
    busybox zlib libpng expat pcre2 libffi gettext dbus json-glib libxml2
    libjpeg-turbo fribidi graphite2 libevdev
    # font + text stack
    freetype fontconfig harfbuzz
    # glib/gtk stack
    glib gdk-pixbuf pango cairo pixman at-spi2-core gtk+3.0
    # X client libraries
    libxau libxdmcp libxcb libx11 libxext libxrender libxft libxi
    libxrandr libxcursor libxfixes libxdamage libxcomposite libxinerama
    libxtst libice libsm libxt libxmu libxaw libxkbfile libfontenc
    libxfont2
    # X server + drivers + keymap compiler
    xorg-server xf86-video-fbdev xf86-input-evdev xkbcomp
    # XFCE
    startup-notification libwnck3 vte3 xfconf libxfce4util libxfce4ui
    garcon exo xfce4-session xfce4-settings xfce4-panel xfwm4 xfdesktop
    xfce4-appfinder xfce4-terminal thunar
    # small X utilities the start script / smoke tests use
    xclock xmessage xterm xset xrandr xeyes
)
if [ $# -gt 0 ]; then PACKAGES=("$@"); else PACKAGES=("${DEFAULT_PACKAGES[@]}"); fi

CONTAINER_ENGINE=""
for candidate in podman docker; do
    command -v "$candidate" &> /dev/null && { CONTAINER_ENGINE="$candidate"; break; }
done
[ -n "$CONTAINER_ENGINE" ] || fatal "Requires podman or docker; neither found on PATH"

BASE_IMAGE="public.ecr.aws/docker/library/alpine:${ALPINE_TAG}"
BUILD_CONTAINER="litebox-x18-repo-build"

info "Using ${BOLD}${CONTAINER_ENGINE}${RESET}, aports ${BOLD}${ALPINE_BRANCH}${RESET}, ${#PACKAGES[@]} packages"

# --- Container setup (idempotent: reused if already running) ---
# Everything runs as root with `abuild -F`: fakeroot is broken inside these
# containers ("libfakeroot internal error: payload not recognized"), and
# root needs no fakeroot to set package file ownership anyway.
if ! "$CONTAINER_ENGINE" exec "$BUILD_CONTAINER" true &> /dev/null; then
    "$CONTAINER_ENGINE" rm -f "$BUILD_CONTAINER" &> /dev/null || true
    "$CONTAINER_ENGINE" run -d --name "$BUILD_CONTAINER" --platform linux/arm64 \
        "$BASE_IMAGE" sleep 604800 > /dev/null
    "$CONTAINER_ENGINE" exec "$BUILD_CONTAINER" sh -c '
        set -e
        apk update > /dev/null
        apk add --no-cache alpine-sdk git linux-headers > /dev/null
        # abuild-keygen derives the key name from PACKAGER and does not
        # reliably register it in abuild.conf, so pin both explicitly.
        echo "PACKAGER=litebox" >> /etc/abuild.conf
        openssl genrsa -out /root/litebox-x18.rsa 2048 2> /dev/null
        # abuild-sign expects the public half next to the private key as
        # <PRIVKEY>.pub; apk verification wants it under /etc/apk/keys.
        openssl rsa -in /root/litebox-x18.rsa -pubout -out /root/litebox-x18.rsa.pub 2> /dev/null
        cp /root/litebox-x18.rsa.pub /etc/apk/keys/
        echo "PACKAGER_PRIVKEY=\"/root/litebox-x18.rsa\"" >> /etc/abuild.conf
        # Append -ffixed-x18 in abuild config rather than the environment:
        # /usr/share/abuild/default.conf assigns CFLAGS unconditionally
        # (clobbering any env var), and /etc/abuild.conf is sourced after
        # it, so appending the override there wins for every build.
        printf "export CFLAGS=\"\$CFLAGS -ffixed-x18\"\nexport CXXFLAGS=\"\$CXXFLAGS -ffixed-x18\"\n" >> /etc/abuild.conf
        grep -q ffixed-x18 /etc/abuild.conf || { echo "abuild.conf edit failed" >&2; exit 1; }
        git config --global --add safe.directory /root/aports
        git clone --depth 1 --branch '"$ALPINE_BRANCH"' \
            https://gitlab.alpinelinux.org/alpine/aports.git /root/aports > /dev/null 2>&1
    ' || fatal "container setup failed"
    info "Build container ready (aports cloned, abuild.conf patched)"
else
    info "Reusing existing build container"
fi

# --- Build loop: skip already-built, continue past failures, report ---
FAILED=()
BUILT=0
SKIPPED=0
for pkg in "${PACKAGES[@]}"; do
    if "$CONTAINER_ENGINE" exec "$BUILD_CONTAINER" sh -c \
        "ls /root/packages/*/aarch64/${pkg}-[0-9]*.apk" &> /dev/null; then
        SKIPPED=$((SKIPPED + 1))
        continue
    fi
    info "building ${BOLD}${pkg}${RESET}..."
    if "$CONTAINER_ENGINE" exec "$BUILD_CONTAINER" sh -c '
        set -e
        pkg="'"$pkg"'"
        dir="$(ls -d /root/aports/*/"$pkg" 2>/dev/null | head -1)"
        [ -n "$dir" ] || { echo "no aports dir for $pkg" >&2; exit 1; }
        # Appended assignments win when the APKBUILD is sourced: bump
        # pkgrel so apk treats ours as an upgrade over the stock package,
        # keep any existing option flags, drop the test suite.
        grep -q "litebox-x18" "$dir/APKBUILD" || printf "\n# litebox-x18\noptions=\"\$options !check\"\npkgrel=999\n" >> "$dir/APKBUILD"
        # busybox is Kbuild: it ignores CFLAGS and only honors its own
        # CONFIG_EXTRA_CFLAGS, fed from a local that starts empty.
        if [ "$pkg" = busybox ]; then
            sed -i "s/local _extra_cflags= _extra_libs=/local _extra_cflags=\"\$CFLAGS\" _extra_libs=/" "$dir/APKBUILD"
        fi
        cd "$dir" && REPODEST=/root/packages abuild -rF > /tmp/build-$pkg.log 2>&1 \
            || { tail -30 /tmp/build-$pkg.log >&2; exit 1; }
    '; then
        BUILT=$((BUILT + 1))
    else
        FAILED+=("$pkg")
        echo -e "${RED}${BOLD}[!]${RESET} $pkg FAILED (see /tmp/build-$pkg.log in $BUILD_CONTAINER)" 1>&2
    fi
done
info "built $BUILT, skipped $SKIPPED already-built, failed ${#FAILED[@]}"

# --- Verify the rebuild actually removed x18 from the artifacts ---
"$CONTAINER_ENGINE" exec "$BUILD_CONTAINER" sh -c '
    apk add --no-cache binutils > /dev/null 2>&1
    cd /root/packages
    total=0
    for apk in */aarch64/*.apk; do
        case "$apk" in *-dev-*|*-doc-*|*-dbg-*|*-lang-*|*-static-*) continue;; esac
        rm -rf /tmp/x18scan && mkdir -p /tmp/x18scan
        tar -xzf "$apk" -C /tmp/x18scan 2>/dev/null
        n=$(find /tmp/x18scan -type f \( -name "*.so*" -o -perm -111 \) \
            -exec sh -c "objdump -d \"\$0\" 2>/dev/null | grep -oE \"\\b[wx]18\\b\" | wc -l" {} \; \
            | awk "{s+=\$1} END {print s+0}")
        [ "$n" -gt 0 ] && echo "  residual x18 refs in $apk: $n"
        total=$((total + n))
    done
    echo "total residual x18 register references across repo: $total"
'

# --- Export the repo ---
mkdir -p "$OUT_DIR"
"$CONTAINER_ENGINE" exec "$BUILD_CONTAINER" tar -C /root/packages -cf - . \
    | tar -C "$OUT_DIR" -xf -
success "Repo exported to ${BOLD}${OUT_DIR}${RESET}"
if [ ${#FAILED[@]} -gt 0 ]; then
    fatal "failed packages: ${FAILED[*]} -- re-run to retry just those"
fi
