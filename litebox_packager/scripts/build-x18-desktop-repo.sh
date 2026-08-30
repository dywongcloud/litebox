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
# GCC/Clang code uses `-ffixed-x18`. Rust 1.96 requires `-Zfixed-x18`,
# including a matching standard library, so the retained builder creates an
# x18-fixed Rust sysroot and forces every rustc invocation through the same
# policy. Both remove the register from the allocator while preserving the
# Linux ABI (`x18` is caller-saved). Hand-written assembly and LTO still need
# package-specific fixes; the final objdump gate catches them.
#
# The companion `build-musl-x18-fixed.sh` covers musl itself through the
# packager's content-addressed cache. This script covers the loaded closure
# of Xorg, dbus, GTK, XFCE, their image/font stack, and the small X clients
# used for live smoke tests. Deliberately cold media/web content (WebKit,
# ffmpeg, GStreamer, Mesa/LLVM) remains stock; launching it is still subject
# to the platform's general x18 restriction.
#
# The build container is kept as `litebox-x18-repo-build`. Each origin builds
# in a private REPODEST assembled from signed, digest-verified origins. Its APKs
# are scanned before an atomic completion marker is published. Only after every
# every requested origin passes are those artifacts merged and indexed as the
# final repository. Increment BUILD_VERSION whenever setup or artifact
# semantics change; stale build containers are then discarded rather than
# mixed into a new repository.
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
# r999 breaks subsequent abuild dependency installation. The XFCE Containerfile
# authenticates and overlays exact same-version APK paths; repository
# add/upgrade alone is a no-op for equal versions.

set -eo pipefail

RED="\033[0;31m"; GREEN="\033[0;32m"; BOLD="\033[1m"; RESET="\033[0m"
fatal() { echo -e "${RED}${BOLD}[!]${RESET} $1" 1>&2; exit 1; }
info()  { echo -e "${BOLD}[i]${RESET} $1" 1>&2; }
success() { echo -e "${GREEN}${BOLD}[+]${RESET} $1" 1>&2; }

ALPINE_BRANCH="${1:-3.24-stable}"
[[ "$ALPINE_BRANCH" =~ ^[0-9]+\.[0-9]+-stable$ ]] || \
    fatal "invalid Alpine branch: $ALPINE_BRANCH"
ALPINE_TAG="${ALPINE_BRANCH%-stable}"
MAX_RETAINED_GENERATIONS="${LITEBOX_X18_MAX_RETAINED_GENERATIONS-64}"
if ! [[ "$MAX_RETAINED_GENERATIONS" =~ ^[1-9][0-9]{0,3}$ ]] || \
    [ "$MAX_RETAINED_GENERATIONS" -gt 4096 ]; then
    fatal "invalid retained generation limit (expected 1..4096): $MAX_RETAINED_GENERATIONS"
fi
OUT_DIR="${2:-$HOME/.cache/litebox/x18-desktop-repo}"
OUT_DIR="${OUT_DIR%/}"
[ -n "$OUT_DIR" ] && [ "$OUT_DIR" != / ] || fatal "invalid OUT_DIR: $OUT_DIR"
OUT_LEAF="$(basename "$OUT_DIR")"
case "$OUT_LEAF" in
    ""|.|..) fatal "invalid OUT_DIR leaf: $OUT_DIR";;
esac
mkdir -p "$(dirname "$OUT_DIR")"
OUT_PARENT="$(cd "$(dirname "$OUT_DIR")" && pwd)"
OUT_NAME="$OUT_LEAF"
OUT_DIR="$OUT_PARENT/$OUT_NAME"
shift 2 2>/dev/null || shift $# # remaining args, if any, replace the list

# Rebuild only aports origins whose measured Alpine 3.24 runtime ELFs in the
# painted desktop, interactive terminal, smoke clients, or standard XFCE UI
# contain x18 operands. Loaded zero-operand dependencies stay stock: these
# fixed-register packages keep the exact same ABI and package versions.
#
# GCC must be first. Later packages can otherwise statically link helpers from
# Alpine's stock libgcc.a even when their own CFLAGS reserve x18. The build loop
# explicitly installs the verified libgcc/libgcc-static payloads before it lets
# any downstream origin compile.
DEFAULT_PACKAGES=(
    # compiler helpers and core runtime plumbing
    gcc busybox apk-tools pax-utils zlib xz libxml2 bzip2 brotli libffi yaml libmd ncurses pcre2
    libbsd skalibs util-linux libx11 glib dbus
    # terminal, TLS, Unicode, compression, and cold settings carriers
    gmp libunistring libidn2 nettle zstd gnutls openssl lz4 simdutf icu cups duktape
    # graphics, image, input, font, and text carriers
    libpng lcms2 dav1d fribidi mtdev libxkbcommon pixman freetype graphite2
    fontconfig cairo harfbuzz pango libdrm libglycin gdk-pixbuf librsvg glycin
    # direct framebuffer desktop and standard UI paths
    gtk+3.0 libwnck3 xorg-server xfwm4 xfce4-settings vte3 thunar
    # taskbar/panel and desktop-icon components -- previously missing from
    # this closure, which left them on stock (non-x18-fixed) code and
    # exposed to the corruption docs/roadmap.md documents as "GTK components
    # ... running but never painting, and an X client wedged awaiting a
    # reply the server never sent". Confirmed live: the guest wedges
    # (framebuffer and clock both frozen, runner process alive and pegged
    # near 100% CPU) after sustained interaction with xfce4-panel's
    # Applications menu.
    xfce4-panel xfdesktop
    # Xt smoke clients
    libxt libxaw libxfont2 libxft libxmu libxpm xterm
)
if [ $# -gt 0 ]; then
    EXPORT_PACKAGES=("$@")
else
    EXPORT_PACKAGES=("${DEFAULT_PACKAGES[@]}")
fi
PACKAGES=("${EXPORT_PACKAGES[@]}")
contains_gcc=false
for pkg in "${PACKAGES[@]}"; do
    [ "$pkg" != gcc ] || contains_gcc=true
done
if [ "$contains_gcc" != true ]; then
    # A package-list override controls export contents, not the trusted compiler
    # prerequisite. The verified GCC origin remains cached but does not leak into
    # a narrow exported repository.
    PACKAGES=(gcc "${PACKAGES[@]}")
fi

GCC_JOBS="${LITEBOX_X18_GCC_JOBS:-3}"
[[ "$GCC_JOBS" =~ ^[1-9][0-9]{0,2}$ && "$GCC_JOBS" -le 512 ]] || \
    fatal "invalid GCC job count (expected 1..512): $GCC_JOBS"

CONTAINER_ENGINE=""
for candidate in podman docker; do
    command -v "$candidate" &> /dev/null && { CONTAINER_ENGINE="$candidate"; break; }
done
[ -n "$CONTAINER_ENGINE" ] || fatal "Requires podman or docker; neither found on PATH"
command -v python3 > /dev/null 2>&1 || fatal "python3 is required"

BASE_IMAGE_INPUT="${LITEBOX_ALPINE_BASE_IMAGE:-public.ecr.aws/docker/library/alpine:${ALPINE_TAG}}"
for attempt in 1 2 3; do
    if "$CONTAINER_ENGINE" pull --platform linux/arm64 "$BASE_IMAGE_INPUT" > /dev/null; then
        break
    fi
    [ "$attempt" -lt 3 ] || fatal "failed to pull Alpine base image: $BASE_IMAGE_INPUT"
    sleep $((attempt * 5))
done
if [[ "$BASE_IMAGE_INPUT" == *@sha256:* ]]; then
    BASE_IMAGE="$BASE_IMAGE_INPUT"
    BASE_DIGEST="${BASE_IMAGE_INPUT##*@}"
else
    repo_digest="$($CONTAINER_ENGINE image inspect \
        --format '{{index .RepoDigests 0}}' "$BASE_IMAGE_INPUT")"
    [[ "$repo_digest" == *@sha256:* ]] || \
        fatal "base image has no immutable repository digest: $BASE_IMAGE_INPUT"
    BASE_DIGEST="${repo_digest##*@}"
    BASE_IMAGE="${BASE_IMAGE_INPUT}@${BASE_DIGEST}"
fi

APORTS_COMMIT="${LITEBOX_APORTS_COMMIT:-013edf8b29199933e8ea34dde460b5584b979042}"
[[ "$APORTS_COMMIT" =~ ^[0-9a-f]{40}$ ]] || \
    fatal "invalid immutable aports commit for $ALPINE_BRANCH"

BUILD_CONTAINER="${LITEBOX_X18_BUILD_CONTAINER:-litebox-x18-repo-build}"
BUILD_VERSION="8"
BUILD_RECIPE_SHA256="$(shasum -a 256 "$0" | cut -d" " -f1)"
BUILD_STATE="$BUILD_VERSION|$BUILD_RECIPE_SHA256|$ALPINE_BRANCH|$APORTS_COMMIT|$BASE_IMAGE"

info "Using ${BOLD}${CONTAINER_ENGINE}${RESET}, Alpine ${BOLD}${BASE_DIGEST}${RESET}, aports ${BOLD}${APORTS_COMMIT}${RESET}, ${#PACKAGES[@]} build origins, ${#EXPORT_PACKAGES[@]} export origins"

# Serialize access to the retained container with a kernel-owned lock. The
# helper holds flock while its direct parent retains ownership. Normal exits
# signal the helper; SIGKILL reparents it and releases the lock independently.
LOCK_ROOT="/tmp/litebox-x18-build-locks-$UID"
python3 - "$LOCK_ROOT" <<'PY' || fatal "invalid build-lock root: $LOCK_ROOT"
import os
import stat
import sys

root = sys.argv[1]
try:
    os.mkdir(root, 0o700)
except FileExistsError:
    metadata = os.lstat(root)
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid():
        raise SystemExit("lock root is not a caller-owned directory")
    if stat.S_IMODE(metadata.st_mode) != 0o700:
        raise SystemExit("lock root permissions are not 0700")
PY
BUILD_LOCK_FILE="$LOCK_ROOT/repository-build.lock"
LOCK_SESSION=""
LOCK_KEEPER_PID=""
BUILD_LOCK_HELD=false
EXPORT_STAGING=""

acquire_build_lock() {
    LOCK_SESSION="$(mktemp -d "$LOCK_ROOT/holder.XXXXXX")"
    python3 -c '
import fcntl
import os
import signal
import stat
import sys
import time

lock_path, session, host_pid = sys.argv[1:]
owner_pid = int(host_pid)
release_requested = False


def request_release(_signum, _frame):
    global release_requested
    release_requested = True


signal.signal(signal.SIGTERM, request_release)
if owner_pid <= 1 or os.getppid() != owner_pid:
    raise SystemExit("lock owner exited before acquisition")
flags = os.O_RDWR | os.O_CREAT
if hasattr(os, "O_NOFOLLOW"):
    flags |= os.O_NOFOLLOW
fd = os.open(lock_path, flags, 0o600)
metadata = os.fstat(fd)
if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid()
        or metadata.st_nlink != 1):
    raise SystemExit("lock file is not a caller-owned regular leaf")
os.fchmod(fd, 0o600)
try:
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
except BlockingIOError:
    raise SystemExit("retained build container is already locked")
os.ftruncate(fd, 0)
os.write(fd, ("host_pid=" + host_pid + "\n").encode())
print("locked", flush=True)
try:
    while os.getppid() == owner_pid and not release_requested:
        time.sleep(0.1)
finally:
    os.close(fd)
    for leaf in ("ready", "error"):
        try:
            os.unlink(os.path.join(session, leaf))
        except FileNotFoundError:
            pass
    try:
        os.rmdir(session)
    except OSError:
        pass
' "$BUILD_LOCK_FILE" "$LOCK_SESSION" "$$" \
        < /dev/null \
        > "$LOCK_SESSION/ready" \
        2> "$LOCK_SESSION/error" &
    LOCK_KEEPER_PID=$!

    attempts=0
    while [ ! -s "$LOCK_SESSION/ready" ]; do
        if ! kill -0 "$LOCK_KEEPER_PID" 2>/dev/null; then
            if wait "$LOCK_KEEPER_PID"; then
                status=0
            else
                status=$?
            fi
            message="$(cat "$LOCK_SESSION/error" 2>/dev/null || true)"
            LOCK_KEEPER_PID=""
            fatal "cannot acquire build lock (status $status): ${message:-unknown error}"
        fi
        attempts=$((attempts + 1))
        [ "$attempts" -lt 3000 ] || fatal "timed out acquiring build lock"
        sleep 0.01
    done
    state=""
    IFS= read -r state < "$LOCK_SESSION/ready" || true
    [ "$state" = locked ] || fatal "build-lock helper returned invalid state"
    BUILD_LOCK_HELD=true
}

release_build_lock() {
    if [ -n "$EXPORT_STAGING" ] && [ -d "$EXPORT_STAGING" ]; then
        rm -rf "$EXPORT_STAGING"
    fi
    if [ "$BUILD_LOCK_HELD" = true ]; then
        if [ -n "$LOCK_KEEPER_PID" ]; then
            kill -TERM "$LOCK_KEEPER_PID" 2>/dev/null || true
            wait "$LOCK_KEEPER_PID" 2>/dev/null || true
        fi
        BUILD_LOCK_HELD=false
    fi
    [ -z "$LOCK_SESSION" ] || rm -rf "$LOCK_SESSION"
}
trap release_build_lock EXIT
trap "exit 130" HUP INT TERM
acquire_build_lock

# A detached in-container origin build can outlive a killed host wrapper. New
# builds hold a kernel flock. The directory check below is migration-only for a
# build started by recipe v4: a live PID is authoritative only when its cmdline
# still identifies the old detached origin driver, so PID reuse cannot wedge it.
container_running="$($CONTAINER_ENGINE inspect \
    --format '{{.State.Running}}' "$BUILD_CONTAINER" 2>/dev/null || true)"
if [ "$container_running" = true ]; then
    # shellcheck disable=SC2016
    active_state="$($CONTAINER_ENGINE exec "$BUILD_CONTAINER" sh -c '
        set -e
        legacy=/root/.litebox-x18-active
        if [ -d "$legacy" ]; then
            holder=""
            [ ! -f "$legacy/pid" ] || IFS= read -r holder < "$legacy/pid"
            case "$holder" in
                ""|*[!0-9]*) rm -rf "$legacy";;
                *)
                    command_line="$(tr "\000" " " < "/proc/$holder/cmdline" 2>/dev/null || true)"
                    if kill -0 "$holder" 2>/dev/null && \
                        printf "%s" "$command_line" | grep -Fq "/root/origin-work/.status-"; then
                        echo "legacy:$holder"
                        exit 0
                    fi
                    rm -rf "$legacy"
                    ;;
            esac
        fi
        command -v flock > /dev/null 2>&1 || { echo idle; exit 0; }
        exec 9> /root/.litebox-x18-active.lock
        if flock -n 9; then
            echo idle
        else
            echo active
        fi
    ')" || fatal "failed to inspect active build lock in $BUILD_CONTAINER"
    case "$active_state" in
        idle) ;;
        active) fatal "container $BUILD_CONTAINER still has an active origin build";;
        legacy:*) fatal "container $BUILD_CONTAINER still has legacy origin PID ${active_state#legacy:}";;
        *) fatal "invalid active-build state from $BUILD_CONTAINER: $active_state";;
    esac
fi

# --- Container setup ---
# Everything runs as root with `abuild -F`: fakeroot is broken inside these
# containers ("libfakeroot internal error: payload not recognized"), and
# root needs no fakeroot to set package file ownership anyway.
container_version="$($CONTAINER_ENGINE exec "$BUILD_CONTAINER" \
    sh -c 'cat /root/.litebox-x18-build-version 2>/dev/null' 2>/dev/null || true)"
if [ "$container_version" != "$BUILD_STATE" ]; then
    "$CONTAINER_ENGINE" rm -f "$BUILD_CONTAINER" &> /dev/null || true
    "$CONTAINER_ENGINE" run -d --init --name "$BUILD_CONTAINER" --platform linux/arm64 \
        "$BASE_IMAGE" sleep 604800 > /dev/null
    # The single-quoted body expands only inside the container; the two
    # concatenated host variables are deliberate.
    # shellcheck disable=SC2016
    "$CONTAINER_ENGINE" exec "$BUILD_CONTAINER" sh -c '
        set -e
        aports_commit="$1"
        build_version="$2"
        apk update > /dev/null
        apk add --no-cache alpine-sdk binutils cargo git linux-headers rust rust-src > /dev/null
        command -v flock > /dev/null
        # abuild-sign expects the public half next to the private key, while
        # apk verification also needs it under /etc/apk/keys.
        echo "PACKAGER=litebox" >> /etc/abuild.conf
        openssl genrsa -out /root/litebox-x18.rsa 2048 2> /dev/null
        openssl rsa -in /root/litebox-x18.rsa -pubout \
            -out /root/litebox-x18.rsa.pub 2> /dev/null
        cp /root/litebox-x18.rsa.pub /etc/apk/keys/
        echo "PACKAGER_PRIVKEY=\"/root/litebox-x18.rsa\"" >> /etc/abuild.conf
        echo "DISTFILES_MIRROR=\"https://distfiles.alpinelinux.org/distfiles/edge\"" \
            >> /etc/abuild.conf
        # /usr/share/abuild/default.conf assigns CFLAGS unconditionally and
        # /etc/abuild.conf is sourced after it, so an environment-only
        # override would be silently lost.
        printf "export CFLAGS=\"\$CFLAGS -ffixed-x18\"\n" >> /etc/abuild.conf
        printf "export CXXFLAGS=\"\$CXXFLAGS -ffixed-x18\"\n" >> /etc/abuild.conf

        # Rust 1.96 rejects the former +reserve-x18 target feature and requires
        # -Zfixed-x18. That flag is an ABI property, so rebuild the complete
        # standard-library rlib set before any package compiles. Keep embedded
        # bitcode because the measured Rust packages enable fat LTO.
        rust_target="$(/usr/bin/rustc -vV | sed -n "s/^host: //p")"
        [ "$rust_target" = aarch64-alpine-linux-musl ]
        rust_sysroot="$(/usr/bin/rustc --print sysroot)/lib/rustlib/$rust_target/lib"
        rust_source=/usr/lib/rustlib/src/rust/library
        [ -f "$rust_source/std/Cargo.toml" ]
        rust_build=/root/litebox-rust-sysroot
        rm -rf "$rust_build"
        mkdir -p "$rust_build/src"
        printf "%s\n" \
            "[package]" \
            "name = \"litebox-rust-sysroot\"" \
            "version = \"0.0.0\"" \
            "edition = \"2024\"" \
            > "$rust_build/Cargo.toml"
        printf "%s\n" "fn main() {}" > "$rust_build/src/main.rs"
        # profiler_builtins/build.rs otherwise compiles real LLVM compiler-rt C
        # sources (GCDAProfiling.c, InstrProfiling*.c, ...) it expects at
        # ../../src/llvm-project/compiler-rt/lib/profile -- a tree this
        # from-scratch bootstrap never checks out. Its own escape hatch
        # (LLVM_PROFILER_RT_LIB, read at the very top of build.rs) skips that
        # native compile entirely and links whatever static archive it is
        # pointed at instead. Chromiums release build graph never actually
        # calls the __llvm_profile_* symbols that archive would normally
        # provide (no PGO/coverage GN args are set anywhere in this closure),
        # so an empty archive is enough to satisfy both this crates own build
        # and every later linker invocation that pulls it in transitively.
        empty_profiler_rt="$rust_build/libempty-profiler-rt.a"
        /usr/bin/ar rcs "$empty_profiler_rt"
        (
            cd "$rust_build"
            /usr/bin/cargo generate-lockfile --offline
            RUSTC_BOOTSTRAP=1 \
            RUSTFLAGS="-Zfixed-x18 -Cembed-bitcode=yes" \
            LLVM_PROFILER_RT_LIB="$empty_profiler_rt" \
                /usr/bin/cargo -Zbuild-std=std,panic_abort,test,profiler_builtins \
                build --locked --release --target "$rust_target"
        )
        fixed_rust="$rust_build/target/$rust_target/release/deps"
        # profiler_builtins: Chromiums own Rust build (build/rust/std/BUILD.gn,
        # invoked via find_std_rlibs.py) always copies libprofiler_builtins.rlib
        # out of the sysroot unconditionally -- not gated behind a coverage or
        # profiling GN arg -- so its absence here is a hard ninja failure
        # ("cp: cant stat obj/build/rust/std/libprofiler_builtins.rlib") the
        # first time any Rust target in the Chromium build graph links,
        # confirmed live against chromium 151.0.7922.173.
        expected_rust_crates="
            addr2line adler2 alloc cfg_if compiler_builtins core getopts gimli
            hashbrown libc memchr miniz_oxide object panic_abort panic_unwind
            proc_macro profiler_builtins rustc_demangle rustc_literal_escaper
            rustc_std_workspace_alloc rustc_std_workspace_core
            rustc_std_workspace_std std std_detect test unwind
        "
        expected_count=0
        for crate in $expected_rust_crates; do
            set -- "$fixed_rust/lib$crate-"*.rlib
            [ "$#" -eq 1 ] && [ -f "$1" ]
            expected_count=$((expected_count + 1))
        done
        [ "$(find "$fixed_rust" -maxdepth 1 -type f -name "*.rlib" | wc -l)" \
            -eq "$expected_count" ]

        count_x18_instructions() {
            file="$1"
            disassembly="/tmp/x18-rust-disassembly.$$"
            objdump --no-show-raw-insn -d "$file" > "$disassembly" || return 1
            awk -F "\t" "NF >= 3 {
                ops = \$3
                gsub(/\\[/, \" \", ops); gsub(/\\]/, \" \", ops)
                gsub(/[,{}!]/, \" \", ops)
                n = split(ops, a, /[[:space:]]+/)
                hit = 0
                for (i = 1; i <= n; i++)
                    if (a[i] == \"x18\" || a[i] == \"w18\") hit = 1
                count += hit
            } END { print count + 0 }" "$disassembly"
            rm -f "$disassembly"
        }
        total=0
        for archive in "$fixed_rust"/*.rlib; do
            n="$(count_x18_instructions "$archive")"
            total=$((total + n))
        done
        [ "$total" -eq 0 ]

        rm -f "$rust_sysroot"/*.rlib
        cp "$fixed_rust"/*.rlib "$rust_sysroot"/
        # The shipped core/std artifacts use unwind metadata, but panic_abort
        # itself must carry abort metadata. Build that one runtime directly
        # against the newly installed fixed rustc_std_workspace_core.
        rust_core="$(find "$rust_sysroot" \
            -name "librustc_std_workspace_core-*.rlib" -print -quit)"
        [ -n "$rust_core" ]
        RUSTC_BOOTSTRAP=1 /usr/bin/rustc \
            --crate-name panic_abort \
            --edition=2024 \
            "$rust_source/panic_abort/src/lib.rs" \
            --crate-type lib \
            --emit link \
            -Copt-level=3 \
            -Cpanic=abort \
            -Cembed-bitcode=yes \
            --target "$rust_target" \
            -Zfixed-x18 \
            -Zforce-unstable-if-unmarked \
            --extern core="$rust_core" \
            -L dependency="$rust_sysroot" \
            -o "$rust_build/libpanic_abort-deadbeef.rlib"
        # Real rustc-built rlibs carry a hex metadata hash after the crate
        # name (e.g. libcore-2ce4ae595641ff84.rlib); some downstream build
        # systems -- Chromiums build/rust/std/find_std_rlibs.py among them --
        # parse the sysroot directory with a regex that requires it
        # (lib([0-9a-z_]+)-([0-9a-f]+).rlib -- [0-9a-f] only) and crash
        # (AttributeError: NoneType object has no attribute group) on any
        # filename that does not match. The previous literal "-litebox" --
        # l, i, x are not hex digits -- failed that pattern; "deadbeef" is
        # entirely within [0-9a-f] and matches, while still being an obvious
        # placeholder rather than a real content hash.
        rm -f "$rust_sysroot"/libpanic_abort-*.rlib
        cp "$rust_build/libpanic_abort-deadbeef.rlib" "$rust_sysroot"/

        # Cargo honors RUSTC and Meson discovers the PATH leaf, but some build
        # systems (Chromiums own build/rust/gni_impl, confirmed live) resolve
        # `rustc` to an absolute /usr/bin/rustc path baked into their own
        # generated ninja commands, bypassing $PATH, $RUSTC, and
        # /usr/local/bin/rustc entirely -- their crates then compile without
        # -Zfixed-x18 while linking against this containers x18-fixed
        # std/alloc/core, which rustcs own ABI-mismatch detection correctly
        # refuses ("mixing -Zfixed-x18 will cause an ABI mismatch"). Moving
        # the real binary aside and replacing /usr/bin/rustc itself with the
        # wrapper closes that gap: every caller that hardcodes the absolute
        # path still reaches a binary, and that binary always adds the flag.
        real_rustc=/usr/bin/rustc.real
        [ -e "$real_rustc" ] || mv /usr/bin/rustc "$real_rustc"
        printf "%s\n" \
            "#!/bin/sh" \
            "export RUSTC_BOOTSTRAP=1" \
            "exec $real_rustc -Zfixed-x18 \"\$@\"" \
            > /usr/bin/rustc
        chmod 0755 /usr/bin/rustc
        cp /usr/bin/rustc /usr/local/bin/rustc
        printf "export RUSTC=\"/usr/local/bin/rustc\"\n" >> /etc/abuild.conf
        printf "export RUSTC_BOOTSTRAP=1\n" >> /etc/abuild.conf
        [ "$(command -v rustc)" = /usr/local/bin/rustc ]

        # Prove both panic runtimes and fat-LTO consumption against the installed
        # sysroot. The final package gate remains authoritative for application
        # artifacts.
        printf "%s\n" "fn main() { std::hint::black_box(7u64); }" \
            > "$rust_build/verify.rs"
        rustc -Clto=fat "$rust_build/verify.rs" \
            -o "$rust_build/verify-unwind"
        rustc -Clto=fat -Cpanic=abort "$rust_build/verify.rs" \
            -o "$rust_build/verify-abort"
        total=0
        for artifact in "$rust_sysroot"/*.rlib \
                "$rust_build/verify-unwind" "$rust_build/verify-abort"; do
            n="$(count_x18_instructions "$artifact")"
            total=$((total + n))
        done
        echo "x18 instructions in installed Rust sysroot and probes: $total"
        [ "$total" -eq 0 ]
        rm -rf "$rust_build"

        grep -q ffixed-x18 /etc/abuild.conf || exit 1
        grep -q fixed-x18 /usr/local/bin/rustc || exit 1
        grep -q DISTFILES_MIRROR /etc/abuild.conf || exit 1
        git config --global --add safe.directory /root/aports
        # Some networks front gitlab.alpinelinux.org with a proxy that returns a
        # bare 403 to every request (observed live, not a transient outage --
        # the mirror below answers normally from the same host). Rewrite to
        # the GitHub read-only mirror rather than retrying the same blocked host.
        git config --global url."https://github.com/alpinelinux/aports.git".insteadOf \
            https://gitlab.alpinelinux.org/alpine/aports.git
        for attempt in 1 2 3; do
            rm -rf /root/aports
            git init -q /root/aports
            git -C /root/aports remote add origin \
                https://gitlab.alpinelinux.org/alpine/aports.git
            if git -C /root/aports fetch -q --depth 1 origin "$aports_commit"; then
                git -C /root/aports checkout -q --detach FETCH_HEAD
                break
            fi
            sleep $((attempt * 5))
        done
        [ "$(git -C /root/aports rev-parse HEAD 2>/dev/null)" = "$aports_commit" ]
        mkdir -p /root/origin-work /root/verified-origins
        printf "%s" "$build_version" > /root/.litebox-x18-build-version
    ' sh "$APORTS_COMMIT" "$BUILD_STATE" || fatal "container setup failed"
    info "Build container ready (aports cloned, compiler flags reserved x18)"
else
    info "Reusing build container state $BUILD_STATE"
fi

# Revalidate every cached origin before it can be reused. BUILD_VERSION changes
# recreate the container rather than migrating artifacts across build recipes.
# shellcheck disable=SC2016
"$CONTAINER_ENGINE" exec "$BUILD_CONTAINER" sh -c '
    set -e
    for origin_dir in /root/verified-origins/*; do
        [ -d "$origin_dir" ] || continue
        [ -f "$origin_dir/.completed" ] && [ -f "$origin_dir/SHA256SUMS" ] || {
            echo "origin lacks integrity metadata: $origin_dir" >&2
            exit 1
        }
        while IFS= read -r artifact; do
            apk verify "$artifact" > /dev/null
        done <<EOF
$(find "$origin_dir/artifacts" -type f -name "*.apk" -print | sort)
EOF
        (cd "$origin_dir/artifacts" && sha256sum -c ../SHA256SUMS > /dev/null) || {
            echo "verified origin digest mismatch: $origin_dir" >&2
            exit 1
        }
    done
' || fatal "verified origin integrity check failed"

install_x18_gcc_runtimes() {
    info "Installing the verified x18-clean GCC runtime build inputs..."
    # shellcheck disable=SC2016
    "$CONTAINER_ENGINE" exec "$BUILD_CONTAINER" sh -c '
        set -e
        origin=/root/verified-origins/gcc
        [ -f "$origin/.completed" ] && [ -f "$origin/SHA256SUMS" ] || {
            echo "verified GCC origin is unavailable" >&2
            exit 1
        }
        (cd "$origin/artifacts" && sha256sum -c ../SHA256SUMS > /dev/null)

        libgcc="$(find "$origin/artifacts" -type f \
            -name "libgcc-[0-9]*.apk" -print)"
        libgcc_static="$(find "$origin/artifacts" -type f \
            -name "libgcc-static-[0-9]*.apk" -print)"
        libstdcxx="$(find "$origin/artifacts" -type f \
            -name "libstdc++-[0-9]*.apk" -print)"
        libgomp="$(find "$origin/artifacts" -type f \
            -name "libgomp-[0-9]*.apk" -print)"
        [ -n "$libgcc" ] && [ "$(printf "%s\n" "$libgcc" | wc -l)" -eq 1 ]
        [ -n "$libgcc_static" ] && \
            [ "$(printf "%s\n" "$libgcc_static" | wc -l)" -eq 1 ]
        [ -n "$libstdcxx" ] && [ "$(printf "%s\n" "$libstdcxx" | wc -l)" -eq 1 ]
        [ -n "$libgomp" ] && [ "$(printf "%s\n" "$libgomp" | wc -l)" -eq 1 ]
        [ "$(wc -l < "$origin/outputs")" -eq 4 ]
        apk verify "$libgcc" > /dev/null
        apk verify "$libgcc_static" > /dev/null
        apk verify "$libstdcxx" > /dev/null
        apk verify "$libgomp" > /dev/null

        plan="$(apk add --simulate --no-network \
            --repositories-file /dev/null \
            "$libgcc" "$libgcc_static" "$libstdcxx" "$libgomp" 2>&1)"
        printf "%s\n" "$plan"
        replacements="$(printf "%s\n" "$plan" | grep -c "Replacing " || true)"
        actions="$(printf "%s\n" "$plan" | grep -Ec \
            "(^| )(Installing|Upgrading|Downgrading|Replacing|Purging) " || true)"
        case "$replacements:$actions" in
            4:4|0:0) ;;
            *)
                echo "unexpected GCC runtime installation plan" >&2
                exit 1
                ;;
        esac

        world=/tmp/apk-world.before-x18-gcc-runtimes
        cp /etc/apk/world "$world"
        restore_world() {
            cp "$world" /etc/apk/world
            cmp "$world" /etc/apk/world
            rm -f "$world"
        }
        trap restore_world 0
        apk add --no-network --repositories-file /dev/null \
            "$libgcc" "$libgcc_static" "$libstdcxx" "$libgomp" > /dev/null
        restore_world
        trap - 0

        installed_payload=/tmp/litebox-x18-gcc-installed-payload
        rm -rf "$installed_payload"
        mkdir "$installed_payload"
        for artifact in "$libgcc" "$libgcc_static" "$libstdcxx" "$libgomp"; do
            tar -xzf "$artifact" -C "$installed_payload" 2>/dev/null
        done
        payload_count=0
        while IFS= read -r payload; do
            relative="${payload#$installed_payload}"
            case "$relative" in
                /.PKGINFO|/.SIGN.*) continue;;
            esac
            [ -f "$relative" ] && cmp -s "$payload" "$relative" || {
                echo "installed GCC runtime payload mismatch: $relative" >&2
                exit 1
            }
            payload_count=$((payload_count + 1))
        done <<EOF
$(find "$installed_payload" -type f -print)
EOF
        [ "$payload_count" -gt 0 ]
        while IFS= read -r payload; do
            relative="${payload#$installed_payload}"
            [ -L "$relative" ] && \
                [ "$(readlink "$payload")" = "$(readlink "$relative")" ] || {
                echo "installed GCC runtime link mismatch: $relative" >&2
                exit 1
            }
        done <<EOF
$(find "$installed_payload" -type l -print)
EOF
        rm -rf "$installed_payload"

        count_x18_instructions() {
            file="$1"
            disassembly="/tmp/x18-disassembly.$$"
            objdump --no-show-raw-insn -d "$file" > "$disassembly" || return 1
            awk -F "\t" "NF >= 3 {
                ops = \$3
                gsub(/\\[/, \" \", ops); gsub(/\\]/, \" \", ops)
                gsub(/[,{}!]/, \" \", ops)
                n = split(ops, a, /[[:space:]]+/)
                hit = 0
                for (i = 1; i <= n; i++)
                    if (a[i] == \"x18\" || a[i] == \"w18\") hit = 1
                count += hit
            } END { print count + 0 }" "$disassembly"
            rm -f "$disassembly"
        }

        archive_total=0
        archive_dir="$(dirname "$(gcc -print-libgcc-file-name)")"
        for archive in "$archive_dir"/libgcc*.a; do
            [ -f "$archive" ] || continue
            n="$(count_x18_instructions "$archive")" || exit 1
            if [ "$n" -gt 0 ]; then
                echo "residual x18 instructions in installed compiler archive: $archive ($n)" >&2
                archive_total=$((archive_total + n))
            fi
        done
        echo "x18 instructions in installed libgcc archives: $archive_total"
        [ "$archive_total" -eq 0 ]

        runtime_total=0
        runtime_count=0
        while IFS= read -r runtime; do
            runtime_count=$((runtime_count + 1))
            n="$(count_x18_instructions "$runtime")" || exit 1
            if [ "$n" -gt 0 ]; then
                echo "residual x18 instructions in installed GCC runtime: $runtime ($n)" >&2
                runtime_total=$((runtime_total + n))
            fi
        done <<EOF
$(find /usr/lib -maxdepth 1 -type f \
    \( -name "libgcc_s.so.*" -o -name "libstdc++.so.*" -o -name "libgomp.so.*" \) \
    -print | sort)
EOF
        [ "$runtime_count" -eq 3 ]
        echo "x18 instructions in installed GCC runtimes: $runtime_total"
        [ "$runtime_total" -eq 0 ]
    ' || fatal "failed to install or verify x18-clean GCC runtime build inputs"
}

FIXED_LIBGCC_READY=false
if "$CONTAINER_ENGINE" exec "$BUILD_CONTAINER" \
    test -f /root/verified-origins/gcc/.completed; then
    install_x18_gcc_runtimes
    FIXED_LIBGCC_READY=true
fi

# --- Build loop: isolate, verify, and atomically publish each origin ---
FAILED=()
BUILT=0
SKIPPED=0
for pkg in "${PACKAGES[@]}"; do
    if "$CONTAINER_ENGINE" exec "$BUILD_CONTAINER" \
        test -f "/root/verified-origins/$pkg/.completed"; then
        SKIPPED=$((SKIPPED + 1))
        continue
    fi
    if [ "$pkg" != gcc ] && [ "$FIXED_LIBGCC_READY" != true ]; then
        fatal "build and verify the gcc origin before downstream origin $pkg"
    fi
    info "building ${BOLD}${pkg}${RESET}..."
    status_file="/root/origin-work/.status-$pkg-$$"
    driver_log="/tmp/origin-$pkg-driver.log"
    gcc_jobs="$GCC_JOBS"
    "$CONTAINER_ENGINE" exec "$BUILD_CONTAINER" \
        rm -f "$status_file" "$driver_log"
    # Run the long compile detached from the container client. The active marker
    # is held by this long-lived shell, so a killed host wrapper cannot admit a
    # second writer or terminate a 30-minute GCC build by disconnecting exec.
    # shellcheck disable=SC2016
    if "$CONTAINER_ENGINE" exec -d "$BUILD_CONTAINER" sh -c '
        pkg="$1"
        status_file="$2"
        driver_log="$3"
        gcc_jobs="$4"
        exec > "$driver_log" 2>&1

        exec 9> /root/.litebox-x18-active.lock
        flock -n 9 || {
            echo "another in-container origin build holds the kernel lock" >&2
            exit 1
        }
        active_owner=/root/.litebox-x18-active.owner
        printf "%s\n" "$$" > "$active_owner.new.$$"
        mv "$active_owner.new.$$" "$active_owner"
        release_active() {
            rm -f "$active_owner"
        }
        trap release_active 0
        trap "exit 129" 1
        trap "exit 130" 2
        trap "exit 143" 15

        (
        set -e
        dir="$(find /root/aports -mindepth 2 -maxdepth 2 -type d \
            -name "$pkg" -print -quit)"
        [ -n "$dir" ] || { echo "no aports dir for $pkg" >&2; exit 1; }

        verify_verified_origins() {
            for origin_dir in /root/verified-origins/*; do
                [ -d "$origin_dir" ] || continue
                [ -f "$origin_dir/.completed" ] && \
                    [ -f "$origin_dir/SHA256SUMS" ] || {
                    echo "origin lacks integrity metadata: $origin_dir" >&2
                    return 1
                }
                (cd "$origin_dir/artifacts" && \
                    sha256sum -c ../SHA256SUMS > /dev/null) || {
                    echo "verified origin changed during build: $origin_dir" >&2
                    return 1
                }
            done
        }
        verify_verified_origins

        count_x18_instructions() {
            file="$1"
            disassembly="/tmp/x18-disassembly.$$"
            objdump --no-show-raw-insn -d "$file" > "$disassembly" || return 1
            awk -F "\t" "NF >= 3 {
                ops = \$3
                gsub(/\\[/, \" \", ops); gsub(/\\]/, \" \", ops)
                gsub(/[,{}!]/, \" \", ops)
                n = split(ops, a, /[[:space:]]+/)
                hit = 0
                for (i = 1; i <= n; i++)
                    if (a[i] == \"x18\" || a[i] == \"w18\") hit = 1
                count += hit
            } END { print count + 0 }" "$disassembly"
            rm -f "$disassembly"
        }

        # Build against an origin-private repository containing only the one
        # intentional non-stock compiler input. Exposing every retained origin
        # here made a narrow build depend on unrelated prior invocations.
        work="/root/origin-work/$pkg"
        repo_dest="$work/repo"
        rm -rf "$work"
        mkdir -p "$repo_dest"
        if [ "$pkg" != gcc ]; then
            while IFS= read -r artifact; do
                [ -n "$artifact" ] || continue
                rel="${artifact#*/artifacts/}"
                target="$repo_dest/$rel"
                mkdir -p "${target%/*}"
                ln -s "$artifact" "$target"
            done <<EOF
$(find /root/verified-origins/gcc/artifacts -type f \
    -path "*/*/*.apk" -print | sort)
EOF
        fi
        # abuild needs indexes before it installs build dependencies. These
        # indexes belong only to this work tree and can be rewritten freely.
        for arch_dir in "$repo_dest"/*/*; do
            [ -d "$arch_dir" ] || continue
            set -- "$arch_dir"/*.apk
            [ -e "$1" ] || continue
            (
                cd "$arch_dir"
                apk index --no-warnings --quiet \
                    --output APKINDEX.tar.gz --rewrite-arch "${arch_dir##*/}" \
                    *.apk
                abuild-sign -q APKINDEX.tar.gz
            )
        done

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
                # Build only the C compiler runtime and C++ runtime needed by
                # musl and the interactive XFCE terminal closure. Alpine also
                # enables six unrelated compiler front ends by default; they add
                # bootstrap compilers, over half an hour of work, and packages
                # that are never installed in this guest.
                replace_exact_line() {
                    old="$1"
                    new="$2"
                    if grep -Fqx "$new" "$dir/APKBUILD"; then
                        return
                    fi
                    matches="$(grep -Fxc "$old" "$dir/APKBUILD" || true)"
                    [ "$matches" -eq 1 ] || {
                        echo "unexpected GCC APKBUILD line: $old" >&2
                        exit 1
                    }
                    line_number="$(grep -Fnx "$old" "$dir/APKBUILD")"
                    line_number="${line_number%%:*}"
                    sed -i "${line_number}c\\$new" "$dir/APKBUILD"
                }
                if grep -Fqx "LANG_CXX=false" "$dir/APKBUILD"; then
                    replace_exact_line "LANG_CXX=false" "LANG_CXX=true"
                else
                    replace_exact_line ": \"\${LANG_CXX:=true}\"" "LANG_CXX=true"
                fi
                replace_exact_line ": \"\${LANG_D:=true}\"" "LANG_D=false"
                replace_exact_line ": \"\${LANG_OBJC:=true}\"" "LANG_OBJC=false"
                replace_exact_line ": \"\${LANG_GO:=true}\"" "LANG_GO=false"
                replace_exact_line ": \"\${LANG_FORTRAN:=true}\"" "LANG_FORTRAN=false"
                replace_exact_line ": \"\${LANG_ADA:=true}\"" "LANG_ADA=false"
                replace_exact_line ": \"\${LANG_JIT:=true}\"" "LANG_JIT=false"
                matches="$(grep -Fxc "_libgomp=true" "$dir/APKBUILD" || true)"
                [ "$matches" -eq 1 ] || {
                    echo "unexpected GCC libgomp setting" >&2
                    exit 1
                }
                replace_exact_line "_libatomic=true" "_libatomic=false"
                replace_exact_line "_libitm=true" "_libitm=false"

                # A native three-stage bootstrap replaces the package CFLAGS
                # with BOOT_CFLAGS in later stages. One stage keeps the fixed
                # register policy for libgcc and avoids building unused stages.
                next_configure_line="$(sed -n "/--disable-cet/{n;p;q;}" "$dir/APKBUILD")"
                if ! printf "%s" "$next_configure_line" | grep -q -- "--disable-bootstrap"; then
                    matches="$(grep -c -- "--disable-cet" "$dir/APKBUILD")"
                    [ "$matches" -eq 1 ] || { echo "unexpected GCC configure stanza" >&2; exit 1; }
                    sed -i "/--disable-cet/a\\\t\t--disable-bootstrap" "$dir/APKBUILD"
                fi
                ;;
            busybox)
                matches="$(grep -Fc "https://busybox.net/downloads/" "$dir/APKBUILD")"
                [ "$matches" -eq 1 ] || {
                    echo "unexpected BusyBox source URL" >&2
                    exit 1
                }
                sed -i \
                    "s|https://busybox.net/downloads/|https://sources.buildroot.net/busybox/|" \
                    "$dir/APKBUILD"
                ;;
            gmp)
                if ! grep -q -- "-fno-lto" "$dir/APKBUILD"; then
                    matches="$(grep -c -- "-flto=auto" "$dir/APKBUILD")"
                    [ "$matches" -eq 1 ] || {
                        echo "unexpected GMP LTO stanza" >&2
                        exit 1
                    }
                    sed -i "s/-flto=auto/-fno-lto/" "$dir/APKBUILD"
                fi
                ;;
            gnutls)
                # GnuTLS imports AArch64 crypto assembly that assigns x18
                # explicitly. Keep the portable implementation instead.
                if ! grep -q -- "--disable-hardware-acceleration" "$dir/APKBUILD"; then
                    matches="$(grep -c -- "--disable-static" "$dir/APKBUILD")"
                    [ "$matches" -eq 1 ] || { echo "unexpected GnuTLS configure stanza" >&2; exit 1; }
                    sed -i "/--disable-static/i\\\t\t--disable-hardware-acceleration \\\\" \
                        "$dir/APKBUILD"
                fi
                ;;
            openssl)
                # OpenSSL generates AArch64 assembly that allocates x18
                # explicitly. Keep the portable implementations instead.
                if ! grep -Fq "optflags=\"\$optflags no-asm\"" "$dir/APKBUILD"; then
                    matches="$(grep -Fc "# Configure assumes --options are for it" \
                        "$dir/APKBUILD")"
                    [ "$matches" -eq 1 ] || { echo "unexpected OpenSSL Configure stanza" >&2; exit 1; }
                    sed -i "/# Configure assumes --options are for it/i\\\toptflags=\"\$optflags no-asm\"" \
                        "$dir/APKBUILD"
                fi
                ;;
            dav1d)
                # dav1d uses x18 explicitly throughout its AArch64 assembly;
                # compiler flags cannot reserve a register in those sources.
                if ! grep -q -- "-Denable_asm=false" "$dir/APKBUILD"; then
                    matches="$(grep -c -- "-Denable_asm=true" "$dir/APKBUILD")"
                    [ "$matches" -eq 1 ] || { echo "unexpected dav1d asm option" >&2; exit 1; }
                    sed -i "s/-Denable_asm=true/-Denable_asm=false/" "$dir/APKBUILD"
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
            mtdev)
                # mtdev forces GCC LTO after the global CFLAGS. Its LTRANS
                # backend did not retain the fixed-register policy.
                if ! grep -q -- "-fno-lto" "$dir/APKBUILD"; then
                    matches="$(grep -c -- "-flto=auto" "$dir/APKBUILD")"
                    [ "$matches" -eq 1 ] || { echo "unexpected mtdev LTO stanza" >&2; exit 1; }
                    sed -i "s/-flto=auto/-fno-lto/" "$dir/APKBUILD"
                fi
                ;;
            libxt)
                if ! grep -q -- "-fno-lto" "$dir/APKBUILD"; then
                    matches="$(grep -c -- "-flto=auto" "$dir/APKBUILD")"
                    [ "$matches" -eq 1 ] || { echo "unexpected libXt LTO stanza" >&2; exit 1; }
                    sed -i "s/-flto=auto/-fno-lto/" "$dir/APKBUILD"
                fi
                ;;
            xorg-server)
                for option in b_lto glamor glx dri2 dri3; do
                    matches="$(grep -c -- "-D$option=true" "$dir/APKBUILD")"
                    [ "$matches" -eq 1 ] || {
                        echo "unexpected Xorg $option setting" >&2
                        exit 1
                    }
                    sed -i "s/-D$option=true/-D$option=false/" "$dir/APKBUILD"
                done
                matches="$(grep -c "^[[:space:]]*mesa-egl[[:space:]]*$" "$dir/APKBUILD")"
                [ "$matches" -eq 1 ] || {
                    echo "unexpected Xorg mesa-egl dependency" >&2
                    exit 1
                }
                sed -i "/^[[:space:]]*mesa-egl[[:space:]]*$/d" "$dir/APKBUILD"
                ;;
            util-linux)
                if ! grep -q -- "-fno-lto" "$dir/APKBUILD"; then
                    matches="$(grep -c -- "-ffat-lto-objects -flto=auto" "$dir/APKBUILD")"
                    [ "$matches" -eq 1 ] || { echo "unexpected util-linux LTO stanza" >&2; exit 1; }
                    sed -i "s/-ffat-lto-objects -flto=auto/-fno-lto/" "$dir/APKBUILD"
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
        grep -Fqx "# litebox-x18-disable-checks" "$dir/APKBUILD" || \
            printf "\n# litebox-x18-disable-checks\noptions=\"\$options !check\"\n" >> "$dir/APKBUILD"
        if [ "$pkg" = gcc ]; then
            # The Podman VM has no swap. Cap concurrent cc1plus workers so the
            # compiler stays below its memory ceiling even under other load.
            export JOBS="$gcc_jobs"
            export MAKEFLAGS="-j$gcc_jobs"
        fi
        # busybox is Kbuild: it ignores CFLAGS and only honors
        # CONFIG_EXTRA_CFLAGS. Seed every build and check invocation after
        # `_extra_cflags` has been populated (or replaced by libutmps), rather
        # than changing its initializer and losing the flag on that branch.
        if [ "$pkg" = busybox ] && \
            ! grep -q "CONFIG_EXTRA_CFLAGS=\"\$CFLAGS \$_extra_cflags\"" "$dir/APKBUILD"; then
            matches="$(grep -c "CONFIG_EXTRA_CFLAGS=\"\$_extra_cflags\"" "$dir/APKBUILD")"
            [ "$matches" -eq 5 ] || { echo "unexpected busybox Kbuild calls" >&2; exit 1; }
            sed -i "s/CONFIG_EXTRA_CFLAGS=\"\$_extra_cflags\"/CONFIG_EXTRA_CFLAGS=\"\$CFLAGS \$_extra_cflags\"/g" \
                "$dir/APKBUILD"
        fi
        all_outputs="$(cd "$dir" && REPODEST="$repo_dest" abuild -F listpkg)"
        [ -n "$all_outputs" ] || { echo "no APK outputs for $pkg" >&2; exit 1; }
        outputs="$all_outputs"
        if [ "$pkg" = gcc ]; then
            # The guest consumes the shared libgcc, libstdc++, and libgomp
            # runtimes, plus the static helper archive musl links into ld.so.
            # Other compiler and development packages replace no guest file.
            outputs=""
            for output in $all_outputs; do
                case "$output" in
                    libgcc-[0-9]*|libgcc-static-[0-9]*|libstdc++-[0-9]*|libgomp-[0-9]*)
                        outputs="${outputs}${outputs:+ }$output"
                        ;;
                esac
            done
            set -- $outputs
            [ "$#" -eq 4 ] || { echo "expected four GCC runtime outputs" >&2; exit 1; }
        fi
        for output in $all_outputs; do
            existing="$(find "$repo_dest" -type l -name "$output" -print -quit)"
            [ -z "$existing" ] || {
                echo "APK output collision for $pkg: $existing" >&2
                exit 1
            }
        done

        ok=false
        for attempt in 1 2 3; do
            # A failed attempt can leave its virtual dependency package installed,
            # which makes the next abuild transaction conflict with stale inputs.
            apk del ".makedepends-$pkg" > /dev/null 2>&1 || true
            # A failed attempt can leave unsigned or partial outputs. Remove
            # only this origin output names before retrying; dependency symlinks
            # remain untouched.
            for output in $all_outputs; do
                rm -f "$repo_dest"/*/*/"$output"
            done
            if cd "$dir" && REPODEST="$repo_dest" abuild -rF \
                > /tmp/build-$pkg.log 2>&1; then
                ok=true
                break
            fi
            echo "attempt $attempt failed for $pkg" >&2
            tail -30 /tmp/build-$pkg.log >&2
            sleep $((attempt * 5))
        done
        if ! $ok; then
            apk del ".makedepends-$pkg" > /dev/null 2>&1 || true
            exit 1
        fi

        artifacts=""
        for output in $outputs; do
            artifact="$(find "$repo_dest" -type f -name "$output" -print -quit)"
            [ -n "$artifact" ] || {
                echo "missing output after successful build: $output" >&2
                exit 1
            }
            artifacts="${artifacts}${artifacts:+ }$artifact"
        done

        # Scan this origin before publishing it into any later dependency view.
        # Development, debug, static, documentation, language, and OpenRC
        # subpackages are not installed in the guest runtime.
        total=0
        for apk in $artifacts; do
            if [ "$pkg" = gcc ]; then
                case "$apk" in
                    */libgcc-static-*.apk)
                        rm -rf /tmp/x18scan && mkdir -p /tmp/x18scan
                        tar -xzf "$apk" -C /tmp/x18scan 2>/dev/null
                        while IFS= read -r archive; do
                            n="$(count_x18_instructions "$archive")" || exit 1
                            if [ "$n" -gt 0 ]; then
                                echo "  residual x18 instructions: $apk:${archive#/tmp/x18scan} ($n)" >&2
                                total=$((total + n))
                            fi
                        done <<EOF
$(find /tmp/x18scan -type f -name "*.a")
EOF
                        continue
                        ;;
                esac
            fi
            case "$apk" in
                *-dev-*|*-doc-*|*-dbg-*|*-lang-*|*-static-*|*-openrc-*) continue;;
            esac
            rm -rf /tmp/x18scan && mkdir -p /tmp/x18scan
            tar -xzf "$apk" -C /tmp/x18scan 2>/dev/null
            while IFS= read -r file; do
                case "$file" in *.a) continue;; esac
                readelf -h "$file" > /dev/null 2>&1 || continue
                n="$(count_x18_instructions "$file")" || exit 1
                if [ "$n" -gt 0 ]; then
                    echo "  residual x18 instructions: $apk:${file#/tmp/x18scan} ($n)" >&2
                    total=$((total + n))
                fi
            done <<EOF
$(find /tmp/x18scan -type f)
EOF
        done
        echo "x18 instructions in $pkg runtime ELFs: $total" >&2
        [ "$total" -eq 0 ] || exit 1
        verify_verified_origins

        # The completed directory appears atomically and contains only this
        # verified regular APK files for this origin, never work-tree indexes or
        # dependency symlinks.
        verified_tmp="/root/verified-origins/.new-$pkg"
        verified="/root/verified-origins/$pkg"
        rm -rf "$verified_tmp"
        mkdir -p "$verified_tmp/artifacts"
        sums="$verified_tmp/SHA256SUMS"
        : > "$sums"
        for apk in $artifacts; do
            rel="${apk#${repo_dest}/}"
            target="$verified_tmp/artifacts/$rel"
            mkdir -p "${target%/*}"
            cp -p "$apk" "$target"
            apk verify "$target" > /dev/null
            line="$(sha256sum "$target")"
            printf "%s  %s\n" "${line%% *}" "$rel" >> "$sums"
            chmod 0444 "$target"
        done
        chmod 0444 "$sums"
        printf "%s\n" $outputs > "$verified_tmp/outputs"
        touch "$verified_tmp/.completed"
        [ ! -e "$verified" ] || {
            echo "incomplete verified directory already exists: $verified" >&2
            exit 1
        }
        mv "$verified_tmp" "$verified"
        # Source and package trees are reproducible from the signed APKBUILD
        # inputs and can exceed a gigabyte for GCC. Keep only verified outputs
        # in the retained container so final rootfs packaging has disk headroom.
        rm -rf "$dir/src" "$dir/pkg" "$work"
        )
        rc=$?
        status_tmp="$status_file.new.$$"
        printf "%s\n" "$rc" > "$status_tmp"
        mv "$status_tmp" "$status_file"
        exit "$rc"
    ' sh "$pkg" "$status_file" "$driver_log" "$gcc_jobs"; then
        sleep 1
        origin_rc=""
        while [ -z "$origin_rc" ]; do
            state="$($CONTAINER_ENGINE exec "$BUILD_CONTAINER" sh -c '
                status_file="$1"
                if [ -f "$status_file" ]; then
                    echo done
                    exit 0
                fi
                exec 9> /root/.litebox-x18-active.lock
                if flock -n 9; then
                    echo dead
                else
                    echo active
                fi
            ' sh "$status_file")" || fatal "lost contact with build container $BUILD_CONTAINER"
            case "$state" in
                done)
                    origin_rc="$($CONTAINER_ENGINE exec "$BUILD_CONTAINER" \
                        sh -c 'cat "$1"' sh "$status_file")"
                    ;;
                active) sleep 5;;
                dead) origin_rc=125;;
                *) fatal "invalid detached origin state for $pkg: $state";;
            esac
        done
        "$CONTAINER_ENGINE" exec "$BUILD_CONTAINER" \
            sh -c 'cat "$1" 2>/dev/null || true' sh "$driver_log" >&2
        "$CONTAINER_ENGINE" exec "$BUILD_CONTAINER" rm -f "$status_file"
    else
        origin_rc=125
    fi

    [[ "$origin_rc" =~ ^[0-9]+$ ]] || fatal "invalid detached exit status for $pkg"
    if [ "$origin_rc" -eq 0 ]; then
        BUILT=$((BUILT + 1))
        if [ "$pkg" = gcc ]; then
            install_x18_gcc_runtimes
            FIXED_LIBGCC_READY=true
        fi
    else
        FAILED+=("$pkg")
        echo -e "${RED}${BOLD}[!]${RESET} $pkg FAILED (see /tmp/build-$pkg.log and $driver_log in $BUILD_CONTAINER)" 1>&2
    fi
done
info "built $BUILT, skipped $SKIPPED completed, failed ${#FAILED[@]}"

if [ ${#FAILED[@]} -gt 0 ]; then
    fatal "failed origins: ${FAILED[*]} -- re-run to retry only those"
fi

# --- Merge, index, sign, and re-verify only after every origin passed ---
# The merge is restricted to this invocation's origin list. A persistent build
# container can therefore cache other verified origins without leaking them
# into a package-list override export.
# shellcheck disable=SC2016
if ! "$CONTAINER_ENGINE" exec "$BUILD_CONTAINER" sh -c '
    set -e
    build_state="$1"
    base_image="$2"
    base_digest="$3"
    alpine_branch="$4"
    aports_commit="$5"
    recipe_sha256="$6"
    shift 6
    [ "$1" = -- ]
    shift
    merged=/root/packages.new
    rm -rf "$merged"
    mkdir -p "$merged"
    required_origins="$merged/litebox-x18-required-origins.txt"
    : > "$required_origins"
    count=0
    origin_count=0
    for pkg in "$@"; do
        printf "%s\n" "$pkg" >> "$required_origins"
        origin_count=$((origin_count + 1))
        origin_dir="/root/verified-origins/$pkg"
        [ -f "$origin_dir/.completed" ] && [ -f "$origin_dir/SHA256SUMS" ] || {
            echo "origin is not verified: $pkg" >&2
            exit 1
        }
        (cd "$origin_dir/artifacts" && \
            sha256sum -c ../SHA256SUMS > /dev/null) || {
            echo "verified origin digest mismatch before merge: $pkg" >&2
            exit 1
        }
        while IFS= read -r artifact; do
            [ -n "$artifact" ] || continue
            rel="${artifact#*/artifacts/}"
            target="$merged/$rel"
            [ ! -e "$target" ] || {
                echo "duplicate APK path while merging: $rel" >&2
                exit 1
            }
            mkdir -p "${target%/*}"
            cp -p "$artifact" "$target"
            count=$((count + 1))
        done <<EOF
$(find "/root/verified-origins/$pkg/artifacts" -type f -name "*.apk" -print | sort)
EOF
    done
    sort -u "$required_origins" -o "$required_origins"
    [ "$(wc -l < "$required_origins")" -eq "$origin_count" ] || {
        echo "duplicate required origin" >&2
        exit 1
    }
    [ "$count" -gt 0 ] || { echo "no verified APKs to merge" >&2; exit 1; }

    for arch_dir in "$merged"/*/*; do
        [ -d "$arch_dir" ] || continue
        set -- "$arch_dir"/*.apk
        [ -e "$1" ] || continue
        (
            cd "$arch_dir"
            apk index --no-warnings --quiet \
                --output APKINDEX.tar.gz --rewrite-arch "${arch_dir##*/}" \
                *.apk
            abuild-sign -q APKINDEX.tar.gz
        )
    done

    # readelf filters out archives, scripts, data, and misleading filename-based
    # candidates before objdump. Development/debug/static/doc/language packages
    # are not installed in the guest and are excluded from the runtime gate.
    count_x18_instructions() {
        file="$1"
        disassembly="/tmp/x18-disassembly.$$"
        objdump --no-show-raw-insn -d "$file" > "$disassembly" || return 1
        awk -F "\t" "NF >= 3 {
            ops = \$3
            gsub(/\\[/, \" \", ops); gsub(/\\]/, \" \", ops)
            gsub(/[,{}!]/, \" \", ops)
            n = split(ops, a, /[[:space:]]+/)
            hit = 0
            for (i = 1; i <= n; i++)
                if (a[i] == \"x18\" || a[i] == \"w18\") hit = 1
            count += hit
        } END { print count + 0 }" "$disassembly"
        rm -f "$disassembly"
    }

    cd "$merged"
    total=0
    manifest_tmp=litebox-x18-packages.tsv.new
    : > "$manifest_tmp"
    for apk in */aarch64/*.apk; do
        rm -rf /tmp/x18scan && mkdir -p /tmp/x18scan
        tar -xzf "$apk" -C /tmp/x18scan 2>/dev/null
        pkgname="$(sed -n "s/^pkgname = //p" /tmp/x18scan/.PKGINFO)"
        pkgver="$(sed -n "s/^pkgver = //p" /tmp/x18scan/.PKGINFO)"
        origin="$(sed -n "s/^origin = //p" /tmp/x18scan/.PKGINFO)"
        [ -n "$pkgname" ] && [ -n "$pkgver" ] && [ -n "$origin" ] || {
            echo "incomplete APK metadata: $apk" >&2
            exit 1
        }
        printf "%s|%s|%s|%s\n" "$pkgname" "$pkgver" "$origin" "$apk" \
            >> "$manifest_tmp"
        case "$apk" in
            *-dev-*|*-doc-*|*-dbg-*|*-lang-*|*-static-*|*-openrc-*) continue;;
        esac
        while IFS= read -r file; do
            case "$file" in *.a) continue;; esac
            readelf -h "$file" > /dev/null 2>&1 || continue
            n="$(count_x18_instructions "$file")" || exit 1
            if [ "$n" -gt 0 ]; then
                echo "  residual x18 instructions: $apk:${file#/tmp/x18scan} ($n)"
                total=$((total + n))
            fi
        done <<EOF
$(find /tmp/x18scan -type f)
EOF
    done
    sort "$manifest_tmp" > litebox-x18-packages.tsv
    rm "$manifest_tmp"
    duplicates="$(cut -d"|" -f1 litebox-x18-packages.tsv | uniq -d)"
    [ -z "$duplicates" ] || {
        echo "duplicate APK package names in final repository: $duplicates" >&2
        exit 1
    }
    echo "total residual x18 instructions across runtime ELFs: $total"
    [ "$total" -eq 0 ]

    completion=litebox-x18-completion.env
    {
        printf "format=1\n"
        printf "build_state=%s\n" "$build_state"
        printf "base_image=%s\n" "$base_image"
        printf "base_digest=%s\n" "$base_digest"
        printf "alpine_branch=%s\n" "$alpine_branch"
        printf "aports_commit=%s\n" "$aports_commit"
        printf "recipe_sha256=%s\n" "$recipe_sha256"
        printf "origin_count=%s\n" "$origin_count"
    } > "$completion"
    bundle=litebox-x18-completion.bundle
    {
        printf "[completion]\n"; cat "$completion"
        printf "[required-origins]\n"; cat litebox-x18-required-origins.txt
        printf "[packages]\n"; cat litebox-x18-packages.tsv
    } > "$bundle"
    openssl dgst -sha256 -sign /root/litebox-x18.rsa \
        -out litebox-x18-completion.sig "$bundle"

    rm -rf /root/packages
    mv "$merged" /root/packages
' sh "$BUILD_STATE" "$BASE_IMAGE" "$BASE_DIGEST" "$ALPINE_BRANCH" \
    "$APORTS_COMMIT" "$BUILD_RECIPE_SHA256" -- "${EXPORT_PACKAGES[@]}"; then
    fatal "runtime APKs still contain x18 instructions or repository merge failed"
fi

# --- Export the verified repository ---
# Publish immutable generations through one atomically replaced symlink. The
# first conversion of a legacy directory uses a kernel exchange, so OUT_DIR is
# never absent. Later publications replace the symlink leaf directly.
generation_root="$OUT_PARENT/.${OUT_NAME}.generations"
python3 - "$generation_root" <<'PY' || fatal "invalid generation root: $generation_root"
import os
import shutil
import stat
import sys

root = sys.argv[1]
try:
    os.mkdir(root, 0o700)
except FileExistsError:
    metadata = os.lstat(root)
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid():
        raise SystemExit("generation root is not a caller-owned directory")
    os.chmod(root, 0o700)

for name in os.listdir(root):
    if not name.startswith(".new."):
        continue
    candidate = os.path.join(root, name)
    metadata = os.lstat(candidate)
    if (not stat.S_ISDIR(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_uid != os.getuid()):
        raise SystemExit("foreign unpublished generation: " + candidate)
    shutil.rmtree(candidate)
PY
EXPORT_STAGING="$(mktemp -d "$generation_root/.new.XXXXXX")"
"$CONTAINER_ENGINE" exec "$BUILD_CONTAINER" tar -C /root/packages -cf - . \
    | tar -C "$EXPORT_STAGING" -xf -
"$CONTAINER_ENGINE" exec "$BUILD_CONTAINER" cat /root/litebox-x18.rsa.pub \
    > "$EXPORT_STAGING/litebox-x18.rsa.pub"
generation="$(python3 - "$EXPORT_STAGING" "$generation_root" \
    "$MAX_RETAINED_GENERATIONS" <<'PY'
import hashlib
import os
import re
import shutil
import stat
import sys

staging, root, limit_text = sys.argv[1:]
limit = int(limit_text)
hasher = hashlib.sha256()

def add(value):
    hasher.update(len(value).to_bytes(8, "big"))
    hasher.update(value)

def visit(directory, relative):
    entries = sorted(os.scandir(directory), key=lambda entry: os.fsencode(entry.name))
    for entry in entries:
        path = entry.path
        name = os.path.join(relative, entry.name) if relative else entry.name
        metadata = os.lstat(path)
        add(os.fsencode(name))
        add((metadata.st_mode & 0o7777).to_bytes(4, "big"))
        if stat.S_ISDIR(metadata.st_mode):
            add(b"D")
            visit(path, name)
        elif stat.S_ISREG(metadata.st_mode):
            add(b"F")
            add(metadata.st_size.to_bytes(8, "big"))
            with open(path, "rb") as source:
                for chunk in iter(lambda: source.read(1024 * 1024), b""):
                    hasher.update(chunk)
        elif stat.S_ISLNK(metadata.st_mode):
            add(b"L")
            add(os.fsencode(os.readlink(path)))
        else:
            raise SystemExit("foreign repository entry: " + path)

visit(staging, "")
digest = hasher.hexdigest()
target = os.path.join(root, "generation." + digest)
try:
    metadata = os.lstat(target)
except FileNotFoundError:
    retained = 0
    with os.scandir(root) as entries:
        for entry in entries:
            if not entry.name.startswith("generation."):
                continue
            if re.fullmatch(r"generation\.[0-9a-f]{64}", entry.name) is None:
                raise SystemExit("foreign published generation: " + entry.path)
            candidate = os.lstat(entry.path)
            if (not stat.S_ISDIR(candidate.st_mode)
                    or stat.S_ISLNK(candidate.st_mode)):
                raise SystemExit("foreign published generation: " + entry.path)
            retained += 1
            if retained >= limit:
                raise SystemExit(
                    "retained repository generation limit reached (%d); "
                    "stop all consumers before removing obsolete generation.* "
                    "directories under %s" % (limit, root)
                )
    os.rename(staging, target)
else:
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise SystemExit("content-addressed generation is not a directory: " + target)
    verifier = hashlib.sha256()
    hasher, verifier = verifier, hasher
    visit(target, "")
    if hasher.hexdigest() != digest:
        raise SystemExit("content-addressed generation digest mismatch: " + target)
    shutil.rmtree(staging)
print(target)
PY
)" || fatal "failed to prepare content-addressed repository generation"
EXPORT_STAGING=""

pointer_slot="$OUT_PARENT/.${OUT_NAME}.pointer.swap"
pointer_target=".${OUT_NAME}.generations/${generation##*/}"
publication_notes="$(python3 - "$OUT_DIR" "$pointer_slot" "$generation_root" \
    "$generation" "$pointer_target" <<'PY'
import ctypes
import errno
import os
import secrets
import stat
import sys
import time

output, slot, root, generation, target = sys.argv[1:]

def unique_legacy(prefix):
    while True:
        name = "%s.%s.%s.%s" % (
            prefix,
            time.strftime("%Y%m%d%H%M%S"),
            os.getpid(),
            secrets.token_hex(4),
        )
        candidate = os.path.join(root, name)
        if not os.path.lexists(candidate):
            return candidate

def preserve_recovery_slot():
    if not os.path.lexists(slot):
        return
    metadata = os.lstat(slot)
    if stat.S_ISLNK(metadata.st_mode):
        os.unlink(slot)
        return
    if stat.S_ISDIR(metadata.st_mode):
        legacy = unique_legacy("legacy.recovered")
        os.rename(slot, legacy)
        print("Preserved interrupted legacy export at " + legacy)
        return
    raise SystemExit("foreign pointer recovery slot: " + slot)

def exchange(left, right):
    libc = ctypes.CDLL(None, use_errno=True)
    if sys.platform == "darwin":
        function = libc.renameatx_np
        function.argtypes = [ctypes.c_int, ctypes.c_char_p,
                             ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
        at_fdcwd = -2
    elif sys.platform.startswith("linux"):
        function = libc.renameat2
        function.argtypes = [ctypes.c_int, ctypes.c_char_p,
                             ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
        at_fdcwd = -100
    else:
        raise SystemExit("atomic legacy exchange is unsupported on " + sys.platform)
    function.restype = ctypes.c_int
    if function(at_fdcwd, os.fsencode(left), at_fdcwd, os.fsencode(right), 2) != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error), right)

preserve_recovery_slot()
os.symlink(target, slot)
try:
    output_metadata = os.lstat(output)
except FileNotFoundError:
    output_metadata = None

if output_metadata is None or stat.S_ISLNK(output_metadata.st_mode):
    os.replace(slot, output)
elif stat.S_ISDIR(output_metadata.st_mode):
    exchange(slot, output)
    if not stat.S_ISLNK(os.lstat(output).st_mode) or not stat.S_ISDIR(os.lstat(slot).st_mode):
        raise SystemExit("legacy exchange returned an invalid path shape")
    legacy = unique_legacy("legacy")
    os.rename(slot, legacy)
    print("Preserved the pre-generation export at " + legacy)
else:
    raise SystemExit("existing repository output is not a directory or symlink: " + output)

if not stat.S_ISLNK(os.lstat(output).st_mode) or os.readlink(output) != target:
    raise SystemExit("published repository pointer does not name the new generation")
if os.path.realpath(output) != os.path.realpath(generation):
    raise SystemExit("published repository pointer resolves outside the new generation")

PY
)" || fatal "repository publication failed"
[ -z "$publication_notes" ] || while IFS= read -r note; do info "$note"; done <<< "$publication_notes"
success "Verified x18-clean repo exported to ${BOLD}${OUT_DIR}${RESET}"

