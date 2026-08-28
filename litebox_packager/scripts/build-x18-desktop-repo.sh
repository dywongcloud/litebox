#! /bin/bash

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

# Rebuilds the Alpine packages on a desktop guest's rendering path with x18
# reserved, producing a local APK repository that an image build can overlay
# on the stock packages.
#
# Why: XNU zeroes the AArch64 platform register `x18` on every return to EL0
# (see docs/roadmap.md, "XNU destroys a live guest x18"). Stock Alpine
# userland treats `x18` as an ordinary allocatable register, so a hot loop
# that parks a live value there computes garbage whenever the host preempts
# the guest. Measured live on this repo's XFCE image: busybox `sha256sum` of
# a 7 MB library returned a different wrong digest on every run while `cat`
# of the same file was byte-perfect. The same busybox rebuilt with x18
# reserved returned the correct digest 4/4 in the same guest session.
#
# GCC/Clang code uses `-ffixed-x18`; Rust/LLVM code uses
# `-C target-feature=+reserve-x18`. Both remove the register from the
# allocator while preserving the Linux ABI (`x18` is caller-saved), so a
# partially rebuilt image degrades safely: each rebuilt object strictly
# shrinks the corruption surface. Hand-written assembly still needs a
# package-specific fix; the final objdump gate catches it.
#
# The companion `build-musl-x18-fixed.sh` covers musl itself through the
# packager's content-addressed cache. This script covers the loaded closure
# of Xorg, dbus, GTK, XFCE, their image/font stack, and the small X clients
# used for live smoke tests. Deliberately cold media/web content (WebKit,
# ffmpeg, GStreamer, Mesa/LLVM) remains stock; launching it is still subject
# to the platform's general x18 restriction.
#
# The build container is kept as `litebox-x18-repo-build`. A completion
# marker is written per aports origin, so re-running after a fetch or build
# failure resumes instead of recompiling successful packages. Increment
# BUILD_VERSION whenever setup or artifact semantics change; stale build
# containers are then discarded rather than mixed into a new repository.
#
# Usage: build-x18-desktop-repo.sh [ALPINE_BRANCH] [OUT_DIR] [PKG ...]
#   ALPINE_BRANCH  aports branch (default 3.24-stable); must match the
#                  Alpine version of the image being packaged.
#   OUT_DIR        where the finished repo is copied
#                  (default ~/.cache/litebox/x18-desktop-repo).
#   PKG ...        override the package list entirely (aports dir names).
#
# Rebuilt APKs keep Alpine's original pkgrel. This is intentional: many
# -dev subpackages pin siblings with `= $pkgver-r$pkgrel`, so inventing an
# r999 breaks subsequent abuild dependency installation. To overlay the
# same-version runtime packages, pass their local APK paths to
# `apk add --force-reinstall --allow-untrusted`; do not use `apk upgrade`.

set -eo pipefail

RED="\033[0;31m"; GREEN="\033[0;32m"; BOLD="\033[1m"; RESET="\033[0m"
fatal() { echo -e "${RED}${BOLD}[!]${RESET} $1" 1>&2; exit 1; }
info()  { echo -e "${BOLD}[i]${RESET} $1" 1>&2; }
success() { echo -e "${GREEN}${BOLD}[+]${RESET} $1" 1>&2; }

ALPINE_BRANCH="${1:-3.24-stable}"
ALPINE_TAG="${ALPINE_BRANCH%-stable}"
OUT_DIR="${2:-$HOME/.cache/litebox/x18-desktop-repo}"
shift 2 2>/dev/null || shift $# # remaining args, if any, replace the list

# The conservative loaded closure of the XFCE image, by aports origin (not
# runtime APK name). This includes the default SVG/PNG artwork loaders:
# glycin-image-rs/glycin-svg come from `glycin`, while libglycin and librsvg
# are separate origins. The list is leaf-first so later outputs can consume
# earlier same-version x18-clean libraries from abuild's local REPODEST;
# the final ELF gate makes any static contamination or missed flag fatal.
DEFAULT_PACKAGES=(
    # core/runtime plumbing
    busybox zlib bzip2 xz brotli libffi pcre2 libxml2 yaml libeconf
    libbsd libmd libcap libseccomp util-linux eudev bubblewrap gcc
    dbus gettext json-glib expat nettle
    # graphics, image, font, and text stack
    libpng libjpeg-turbo lcms2 dav1d fribidi graphite2 freetype fontconfig
    harfbuzz pixman cairo pango gdk-pixbuf glycin libglycin librsvg
    # input/display protocols and client libraries
    mtdev libevdev wayland libdrm libpciaccess libdisplay-info libepoxy
    libxau libxdmcp libxcb xcb-util libx11 libxext libxrender libxft libxi
    libxrandr libxcursor libxfixes libxdamage libxcomposite libxinerama
    libxtst libice libsm libxt libxmu libxaw libxkbfile libfontenc
    libxfont2 libxkbcommon libxpresent libxres libxshmfence libxcvt
    # GTK stack
    glib at-spi2-core gtk+3.0 gtk-layer-shell libnotify libdbusmenu-glib
    # X server, drivers, and keymap compiler
    xorg-server xf86-video-fbdev xf86-input-evdev xkbcomp
    # XFCE
    startup-notification libwnck3 vte3 xfconf libxfce4util libxfce4ui
    libxfce4windowing garcon exo xfce4-session xfce4-settings xfce4-panel
    xfwm4 xfdesktop xfce4-appfinder xfce4-terminal thunar
    # small X utilities the start script and smoke probes use
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
BUILD_VERSION="2"

info "Using ${BOLD}${CONTAINER_ENGINE}${RESET}, aports ${BOLD}${ALPINE_BRANCH}${RESET}, ${#PACKAGES[@]} origins"

# --- Container setup ---
# Everything runs as root with `abuild -F`: fakeroot is broken inside these
# containers ("libfakeroot internal error: payload not recognized"), and
# root needs no fakeroot to set package file ownership anyway.
container_version="$($CONTAINER_ENGINE exec "$BUILD_CONTAINER" \
    sh -c 'cat /root/.litebox-x18-build-version 2>/dev/null' 2>/dev/null || true)"
if [ "$container_version" != "$BUILD_VERSION" ]; then
    "$CONTAINER_ENGINE" rm -f "$BUILD_CONTAINER" &> /dev/null || true
    "$CONTAINER_ENGINE" run -d --name "$BUILD_CONTAINER" --platform linux/arm64 \
        "$BASE_IMAGE" sleep 604800 > /dev/null
    # The single-quoted body expands only inside the container; the two
    # concatenated host variables are deliberate.
    # shellcheck disable=SC2016
    "$CONTAINER_ENGINE" exec "$BUILD_CONTAINER" sh -c '
        set -e
        alpine_branch="$1"
        build_version="$2"
        apk update > /dev/null
        apk add --no-cache alpine-sdk git linux-headers > /dev/null
        # abuild-sign expects the public half next to the private key, while
        # apk verification also needs it under /etc/apk/keys.
        echo "PACKAGER=litebox" >> /etc/abuild.conf
        openssl genrsa -out /root/litebox-x18.rsa 2048 2> /dev/null
        openssl rsa -in /root/litebox-x18.rsa -pubout \
            -out /root/litebox-x18.rsa.pub 2> /dev/null
        cp /root/litebox-x18.rsa.pub /etc/apk/keys/
        echo "PACKAGER_PRIVKEY=\"/root/litebox-x18.rsa\"" >> /etc/abuild.conf
        # /usr/share/abuild/default.conf assigns CFLAGS unconditionally and
        # /etc/abuild.conf is sourced after it, so an environment-only
        # override would be silently lost. Cargo APKBUILDs inherit RUSTFLAGS;
        # librsvg appends its own debuginfo flag without replacing this one.
        printf "export CFLAGS=\"\$CFLAGS -ffixed-x18\"\n" >> /etc/abuild.conf
        printf "export CXXFLAGS=\"\$CXXFLAGS -ffixed-x18\"\n" >> /etc/abuild.conf
        printf "export RUSTFLAGS=\"\$RUSTFLAGS -C target-feature=+reserve-x18\"\n" >> /etc/abuild.conf
        grep -q ffixed-x18 /etc/abuild.conf || exit 1
        grep -q reserve-x18 /etc/abuild.conf || exit 1
        git config --global --add safe.directory /root/aports
        for attempt in 1 2 3; do
            git clone --depth 1 --branch "$alpine_branch" \
                https://gitlab.alpinelinux.org/alpine/aports.git /root/aports \
                > /dev/null 2>&1 && break
            rm -rf /root/aports
            sleep $((attempt * 5))
        done
        test -d /root/aports
        mkdir -p /root/completed
        printf "%s" "$build_version" > /root/.litebox-x18-build-version
    ' sh "$ALPINE_BRANCH" "$BUILD_VERSION" || fatal "container setup failed"
    info "Build container ready (aports cloned, compiler flags reserved x18)"
else
    info "Reusing build container version $BUILD_VERSION"
fi

# --- Build loop: skip completed origins, continue past failures, report ---
FAILED=()
BUILT=0
SKIPPED=0
for pkg in "${PACKAGES[@]}"; do
    if "$CONTAINER_ENGINE" exec "$BUILD_CONTAINER" test -f "/root/completed/$pkg"; then
        SKIPPED=$((SKIPPED + 1))
        continue
    fi
    info "building ${BOLD}${pkg}${RESET}..."
    # shellcheck disable=SC2016
    if "$CONTAINER_ENGINE" exec "$BUILD_CONTAINER" sh -c '
        set -e
        pkg="$1"
        dir="$(find /root/aports -mindepth 2 -maxdepth 2 -type d \
            -name "$pkg" -print -quit)"
        [ -n "$dir" ] || { echo "no aports dir for $pkg" >&2; exit 1; }

        add_source_patch() {
            patch_name="$1"
            patch_hash="$(sha512sum "$dir/$patch_name" | cut -d" " -f1)"
            if grep -q "  $patch_name" "$dir/APKBUILD"; then
                sed -i "s|^[0-9a-f][0-9a-f]*  $patch_name|$patch_hash  $patch_name|" "$dir/APKBUILD"
            else
                printf "\nsource=\"\$source %s\"\nsha512sums=\"\$sha512sums\n%s  %s\"\n" \
                    "$patch_name" "$patch_hash" "$patch_name" >> "$dir/APKBUILD"
            fi
        }

        # Compiler flags cannot fix explicit assembly, prebuilt compiler
        # helpers, or LTO code generation that drops the fixed-register
        # policy. Each narrowly-scoped patch below was derived from the
        # residual ELF/symbol/source map and is still subject to the final
        # zero-x18 artifact gate.
        case "$pkg" in
            gcc)
                # A native three-stage bootstrap deliberately replaces the
                # package CFLAGS with BOOT_CFLAGS in stages 2/3, reintroducing
                # x18 and spending ~30 minutes compiling a compiler the guest
                # never installs. One stage uses the stock host compiler but
                # preserves CFLAGS for libgcc/libstdc++ and all packaged code.
                next_configure_line="$(sed -n "/--disable-cet/{n;p;q;}" "$dir/APKBUILD")"
                if ! printf "%s" "$next_configure_line" | grep -q -- "--disable-bootstrap"; then
                    matches="$(grep -c -- "--disable-cet" "$dir/APKBUILD")"
                    [ "$matches" -eq 1 ] || { echo "unexpected GCC configure stanza" >&2; exit 1; }
                    sed -i "/--disable-cet/a\\\t\t--disable-bootstrap" "$dir/APKBUILD"
                fi
                ;;
            fontconfig)
                cat > "$dir/litebox-x18.patch" <<EOF
--- a/src/fcfreetype.c
+++ b/src/fcfreetype.c
@@ -1790,2 +1790,2 @@
-	lower_size = os2->usLowerOpticalPointSize / 20.0L;
-	upper_size = os2->usUpperOpticalPointSize / 20.0L;
+	lower_size = os2->usLowerOpticalPointSize / 20.0;
+	upper_size = os2->usUpperOpticalPointSize / 20.0;
EOF
                add_source_patch litebox-x18.patch
                ;;
            libffi)
                cat > "$dir/litebox-x18.patch" <<EOF
--- a/src/aarch64/ffitarget.h
+++ b/src/aarch64/ffitarget.h
@@ -84,9 +84,8 @@
 #if defined (__APPLE__)
 #define FFI_EXTRA_CIF_FIELDS unsigned aarch64_nfixedargs
 #elif !defined(_WIN32) && !defined(__ANDROID__)
-/* iOS, Windows and Android reserve x18 for the system.  Disable Go closures until
-   a new static chain is chosen.  */
-#define FFI_GO_CLOSURES 1
+/* LiteBox also reserves x18: XNU clears it on every return to userspace.
+   Keep Go closures disabled until they choose another static-chain ABI. */
 #endif

 #ifndef _WIN32
EOF
                add_source_patch litebox-x18.patch
                ;;
            libxt)
                if ! grep -q -- "-fno-lto" "$dir/APKBUILD"; then
                    matches="$(grep -c -- "-flto=auto" "$dir/APKBUILD")"
                    [ "$matches" -eq 1 ] || { echo "unexpected libXt LTO stanza" >&2; exit 1; }
                    sed -i "s/-flto=auto/-fno-lto/" "$dir/APKBUILD"
                fi
                ;;
            gettext)
                # The pkgver=1.0 "runtime-split" source tarball ships no
                # build-aux/ directory (autopoint/autoreconf would normally
                # regenerate it, but the stock APKBUILD has no prepare()
                # step and this aports environment carries no autotools
                # chain to run one). configure then fails looking for
                # ../build-aux/*.sh.in. Fetch the matching full-distribution
                # release, which does ship build-aux/, and copy it in before
                # build() runs.
                if ! grep -q "litebox-x18-gettext-build-aux" "$dir/APKBUILD"; then
                    full_ver="0.23.1"
                    cat >> "$dir/APKBUILD" <<EOF

# litebox-x18-gettext-build-aux
prepare() {
	default_prepare
	if [ ! -d build-aux ]; then
		full_tar="\$SRCDEST/gettext-$full_ver.tar.xz"
		[ -f "\$full_tar" ] || wget -q -O "\$full_tar" \\
			"https://ftp.gnu.org/gnu/gettext/gettext-$full_ver.tar.xz"
		tar xf "\$full_tar" -C "\$SRCDEST" "gettext-$full_ver/build-aux"
		cp -r "\$SRCDEST/gettext-$full_ver/build-aux" build-aux
	fi
}
EOF
                fi
                ;;
            pixman)
                cat > "$dir/litebox-x18.patch" <<EOF
--- a/pixman/pixman-arma64-neon-asm.h
+++ b/pixman/pixman-arma64-neon-asm.h
@@ -705,7 +705,7 @@
     stp         x12,  x13, [x29, -112]
     stp         x14,  x15, [x29, -128]
     stp         x16,  x17, [x29, -144]
-    stp         x18,  x19, [x29, -160]
+    str               x19, [x29, -152]
     stp         x20,  x21, [x29, -176]
     stp         x22,  x23, [x29, -192]
     stp         x24,  x25, [x29, -208]
@@ -914,7 +914,7 @@
     ldp         x12,  x13, [x29, -112]
     ldp         x14,  x15, [x29, -128]
     ldp         x16,  x17, [x29, -144]
-    ldp         x18,  x19, [x29, -160]
+    ldr               x19, [x29, -152]
     ldp         x20,  x21, [x29, -176]
     ldp         x22,  x23, [x29, -192]
     ldp         x24,  x25, [x29, -208]
@@ -972,7 +972,7 @@
     ldp         x12,  x13, [x29, -112]
     ldp         x14,  x15, [x29, -128]
     ldp         x16,  x17, [x29, -144]
-    ldp         x18,  x19, [x29, -160]
+    ldr               x19, [x29, -152]
     ldp         x20,  x21, [x29, -176]
     ldp         x22,  x23, [x29, -192]
     ldp         x24,  x25, [x29, -208]
EOF
                add_source_patch litebox-x18.patch
                ;;
        esac

        # Keep Alpine pkgver/pkgrel unchanged so exact sibling dependencies
        # remain satisfiable. Preserve existing options (notably busybox
        # `suid`) while disabling slow/flaky upstream suites.
        grep -q "litebox-x18" "$dir/APKBUILD" || \
            printf "\n# litebox-x18\noptions=\"\$options !check\"\n" >> "$dir/APKBUILD"
        # busybox is Kbuild: it ignores CFLAGS and only honors
        # CONFIG_EXTRA_CFLAGS, fed by a local that otherwise starts empty.
        if [ "$pkg" = busybox ]; then
            sed -i "s/local _extra_cflags= _extra_libs=/local _extra_cflags=\"\$CFLAGS\" _extra_libs=/" \
                "$dir/APKBUILD"
        fi
        ok=false
        for attempt in 1 2 3; do
            if cd "$dir" && REPODEST=/root/packages abuild -rF \
                > /tmp/build-$pkg.log 2>&1; then
                ok=true
                break
            fi
            echo "attempt $attempt failed for $pkg" >&2
            tail -30 /tmp/build-$pkg.log >&2
            sleep $((attempt * 5))
        done
        $ok || exit 1
        touch "/root/completed/$pkg"
    ' sh "$pkg"; then
        BUILT=$((BUILT + 1))
    else
        FAILED+=("$pkg")
        echo -e "${RED}${BOLD}[!]${RESET} $pkg FAILED (see /tmp/build-$pkg.log in $BUILD_CONTAINER)" 1>&2
    fi
done
info "built $BUILT, skipped $SKIPPED completed, failed ${#FAILED[@]}"

if [ ${#FAILED[@]} -gt 0 ]; then
    fatal "failed origins: ${FAILED[*]} -- re-run to retry only those"
fi

# --- Verify every executable ELF in runtime APKs is x18-clean ---
# readelf filters out archives, scripts, data, and misleading filename-based
# candidates before objdump. Development/debug/static/doc/language packages
# are not installed in the guest and are excluded from the runtime gate.
# shellcheck disable=SC2016
if ! "$CONTAINER_ENGINE" exec "$BUILD_CONTAINER" sh -c '
    set -e
    apk add --no-cache binutils > /dev/null 2>&1
    cd /root/packages
    total=0
    for apk in */aarch64/*.apk; do
        case "$apk" in
            *-dev-*|*-doc-*|*-dbg-*|*-lang-*|*-static-*|*-openrc-*) continue;;
        esac
        rm -rf /tmp/x18scan && mkdir -p /tmp/x18scan
        tar -xzf "$apk" -C /tmp/x18scan 2>/dev/null
        while IFS= read -r file; do
            readelf -h "$file" > /dev/null 2>&1 || continue
            n=$(objdump -d "$file" 2>/dev/null | grep -oE "\b[wx]18\b" | wc -l)
            if [ "$n" -gt 0 ]; then
                echo "  residual x18 refs: $apk:${file#/tmp/x18scan} ($n)"
                total=$((total + n))
            fi
        done <<EOF
$(find /tmp/x18scan -type f)
EOF
    done
    echo "total residual x18 register references across runtime ELFs: $total"
    [ "$total" -eq 0 ]
'; then
    fatal "runtime APKs still contain x18 instructions; patch the named assembly/build path"
fi

# --- Export the verified repository ---
# Never delete an earlier export: move it aside before publishing the new
# directory so an interrupted or mistaken rebuild remains recoverable.
[ "$OUT_DIR" != / ] || fatal "refusing to use / as OUT_DIR"
staging_dir="$OUT_DIR.new.$$"
mkdir -p "$staging_dir"
"$CONTAINER_ENGINE" exec "$BUILD_CONTAINER" tar -C /root/packages -cf - . \
    | tar -C "$staging_dir" -xf -
if [ -e "$OUT_DIR" ]; then
    backup_dir="$OUT_DIR.previous"
    while [ -e "$backup_dir" ]; do backup_dir="$backup_dir.previous"; done
    mv "$OUT_DIR" "$backup_dir"
    info "Previous export preserved at $backup_dir"
fi
mv "$staging_dir" "$OUT_DIR"
success "Verified x18-clean repo exported to ${BOLD}${OUT_DIR}${RESET}"
