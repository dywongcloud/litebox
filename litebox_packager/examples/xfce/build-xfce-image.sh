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

# Verify every executable ELF actually shipped in the built image is
# x18-clean. Scanning here (the built image's real filesystem), not the raw
# x18-repo build's REPODEST, is required: rebuilding an origin can emit far
# more than what Containerfile's overlay step ends up installing (gcc also
# produces gcc-gnat/gcc-go/gcc-gdc and their runtime libs as side products,
# none of which this image installs), and scanning unshipped byproducts
# produces irrelevant failures unrelated to what actually runs as this guest.
# shellcheck disable=SC2016
if ! "$CONTAINER_ENGINE" run --rm --platform linux/arm64 "$IMAGE_TAG" sh -c '
    set -e
    apk add --no-cache binutils > /dev/null 2>&1
    total=0
    while IFS= read -r file; do
        readelf -h "$file" > /dev/null 2>&1 || continue
        n=$(objdump -d "$file" 2>/dev/null | grep -oE "\b[wx]18\b" | wc -l)
        if [ "$n" -gt 0 ]; then
            echo "  residual x18 refs: $file ($n)"
            total=$((total + n))
        fi
    done <<EOF
$(find / -xdev -type f -perm -u+x 2>/dev/null)
EOF
    echo "total residual x18 register references across shipped ELFs: $total"
    [ "$total" -eq 0 ]
'; then
    echo "shipped image still contains x18 instructions; patch the named assembly/build path" >&2
    exit 1
fi

CONTAINER_ID="$($CONTAINER_ENGINE create "$IMAGE_TAG")"
"$CONTAINER_ENGINE" export "$CONTAINER_ID" > "$WORKDIR/rootfs.tar"
"$CONTAINER_ENGINE" rm "$CONTAINER_ID" >/dev/null
CONTAINER_ID=""

cargo run --release --manifest-path "$REPO_ROOT/Cargo.toml" \
    -p litebox_packager -- \
    --oci-rootfs-tar "$WORKDIR/rootfs.tar" -o "$OUTPUT"

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
