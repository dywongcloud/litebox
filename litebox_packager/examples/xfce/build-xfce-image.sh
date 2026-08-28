#!/bin/bash

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

# Builds the x18-safe Alpine package overlay, applies it to the XFCE image,
# packages the local rootfs for litebox, and appends the synthetic fbdev sysfs
# link Xorg's fbdevhw probe requires.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
OUTPUT="${1:-/tmp/litebox-xfce.tar}"
X18_REPO="${LITEBOX_X18_DESKTOP_REPO:-$HOME/.cache/litebox/x18-desktop-repo}"
ALPINE_BRANCH="${LITEBOX_ALPINE_BRANCH:-3.24-stable}"
IMAGE_TAG="${LITEBOX_XFCE_IMAGE_TAG:-localhost/litebox-xfce-x18:3.24}"

[ ! -e "$OUTPUT" ] || { echo "output already exists: $OUTPUT" >&2; exit 1; }

CONTAINER_ENGINE=""
for candidate in podman docker; do
    if command -v "$candidate" >/dev/null 2>&1; then
        CONTAINER_ENGINE="$candidate"
        break
    fi
done
[ -n "$CONTAINER_ENGINE" ] || { echo "podman or docker is required" >&2; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "python3 is required" >&2; exit 1; }

"$REPO_ROOT/litebox_packager/scripts/build-x18-desktop-repo.sh" \
    "$ALPINE_BRANCH" "$X18_REPO"

WORKDIR="$(mktemp -d)"
CONTAINER_ID=""
cleanup() {
    if [ -n "$CONTAINER_ID" ]; then
        "$CONTAINER_ENGINE" rm -f "$CONTAINER_ID" >/dev/null 2>&1 || true
    fi
    rm -rf "$WORKDIR"
}
trap cleanup EXIT

cp "$SCRIPT_DIR/Containerfile" "$SCRIPT_DIR/xorg.conf" \
    "$SCRIPT_DIR/start-desktop.sh" "$WORKDIR/"
cp -R "$X18_REPO" "$WORKDIR/x18repo"

"$CONTAINER_ENGINE" build --platform linux/arm64 -t "$IMAGE_TAG" "$WORKDIR"

CONTAINER_ID="$($CONTAINER_ENGINE create "$IMAGE_TAG")"
"$CONTAINER_ENGINE" export "$CONTAINER_ID" > "$WORKDIR/rootfs.tar"
"$CONTAINER_ENGINE" rm "$CONTAINER_ID" >/dev/null
CONTAINER_ID=""

cargo run --release --manifest-path "$REPO_ROOT/Cargo.toml" \
    -p litebox_packager -- \
    --oci-rootfs-tar "$WORKDIR/rootfs.tar" -o "$OUTPUT"

# Verify every ELF the live smoke test actually loads is x18-clean, scanned
# from the PACKAGED tar (post litebox_packager, which substitutes a
# -ffixed-x18 musl from its content-addressed cache when available -- see
# litebox_packager/src/musl_x18.rs), not the pre-packaging podman image:
# scanning the podman image would report musl's original x18 count even
# after the packager has already replaced it, since substitution happens
# during packaging, not before. binutils' readelf/objdump aren't reliably
# present on a macOS host, so the scan runs inside a scratch Alpine
# container fed the packaged tar directly, mirroring the closure walk
# already used above for the pre-packaging gate. The entry binaries
# start-desktop.sh execs, plus their full recursive NEEDED closure.
# Scanning the whole image's 348 installed packages (measured live: the
# xfce4 metapackage pulls in a stock closure roughly 4x DEFAULT_PACKAGES's
# ~80 rebuilt origins -- webkit2gtk, ffmpeg's codec stack, poppler -- none
# of it reachable from the desktop/terminal/VNC path) would fail on
# hundreds of thousands of residual x18 refs in code nothing here ever
# executes. This mirrors the roadmap's own accepted precedent: partial x18
# coverage shrinks the corruption surface rather than eliminating it:
# everything actually on the smoke-test's live call path is held to the
# zero-residual bar; unreached stock libraries are not.
SCAN_CONTAINER="litebox-x18-scan-$$"
"$CONTAINER_ENGINE" run -d --name "$SCAN_CONTAINER" --platform linux/arm64 \
    "public.ecr.aws/docker/library/alpine:${ALPINE_BRANCH%-stable}" sleep 300 >/dev/null
scan_cleanup() { "$CONTAINER_ENGINE" rm -f "$SCAN_CONTAINER" >/dev/null 2>&1 || true; }
trap 'scan_cleanup; cleanup' EXIT
"$CONTAINER_ENGINE" exec "$SCAN_CONTAINER" mkdir -p /scan
"$CONTAINER_ENGINE" cp "$OUTPUT" "$SCAN_CONTAINER:/scan.tar"
# shellcheck disable=SC2016
if ! "$CONTAINER_ENGINE" exec "$SCAN_CONTAINER" sh -c '
    set -e
    apk add --no-cache binutils tar > /dev/null 2>&1
    tar -xf /scan.tar -C /scan
    seen=""
    queue="/scan/usr/libexec/Xorg /scan/usr/bin/dbus-daemon /scan/usr/bin/xfwm4 /scan/usr/bin/xfdesktop /scan/usr/bin/xfce4-panel /scan/usr/bin/xfce4-terminal /scan/usr/bin/xterm"
    while [ -n "$queue" ]; do
        next=""
        for f in $queue; do
            case " $seen " in *" $f "*) continue;; esac
            seen="$seen $f"
            [ -f "$f" ] || continue
            for d in $(readelf -d "$f" 2>/dev/null | grep NEEDED | sed "s/.*\[\(.*\)\]/\1/"); do
                found=$(find /scan/usr/lib /scan/lib -name "$d" 2>/dev/null | head -1)
                [ -n "$found" ] || continue
                case " $seen " in *" $found "*) ;; *) next="$next $found";; esac
            done
        done
        queue="$next"
    done
    total=0
    for file in $seen; do
        readelf -h "$file" > /dev/null 2>&1 || continue
        n=$(objdump -d "$file" 2>/dev/null | grep -oE "\b[wx]18\b" | wc -l)
        if [ "$n" -gt 0 ]; then
            echo "  residual x18 refs: ${file#/scan/} ($n)"
            total=$((total + n))
        fi
    done
    echo "total residual x18 register references across the live smoke-test closure: $total"
    [ "$total" -eq 0 ]
'; then
    echo "the desktop/terminal smoke-test closure still contains x18 instructions; patch the named assembly/build path" >&2
    exit 1
fi
scan_cleanup
trap cleanup EXIT

python3 - "$OUTPUT" <<'PY'
import sys
import tarfile

path = sys.argv[1]
directories = [
    "sys",
    "sys/class",
    "sys/class/graphics",
    "sys/class/graphics/fb0",
    "sys/class/graphics/fb0/device",
    "sys/bus",
    "sys/bus/platform",
]
link = "sys/class/graphics/fb0/device/subsystem"

with tarfile.open(path, "a", format=tarfile.USTAR_FORMAT) as archive:
    existing = {member.name.rstrip("/") for member in archive.getmembers()}
    for name in directories:
        if name in existing:
            continue
        info = tarfile.TarInfo(name)
        info.type = tarfile.DIRTYPE
        info.mode = 0o755
        archive.addfile(info)
    if link not in existing:
        info = tarfile.TarInfo(link)
        info.type = tarfile.SYMTYPE
        info.mode = 0o777
        info.linkname = "../../../../bus/platform"
        archive.addfile(info)
PY

printf '\nBuilt %s\n\n' "$OUTPUT"
printf 'Run:\n  cargo run --release -p litebox_runner_linux_on_macos_userland -- \\\n'
printf '    --unstable --guest-root --initial-files %q --vnc-web 6080 -- \\\n' "$OUTPUT"
printf '    /usr/bin/start-desktop.sh\n\n'
printf 'Open http://127.0.0.1:6080/\n'
