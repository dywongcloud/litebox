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
OUTPUT="${OUTPUT%/}"
[ -n "$OUTPUT" ] && [ "$OUTPUT" != / ] || { echo "invalid output path: $OUTPUT" >&2; exit 1; }
OUTPUT_NAME="$(basename "$OUTPUT")"
case "$OUTPUT_NAME" in
    ""|.|..) echo "invalid output leaf: $OUTPUT" >&2; exit 1;;
esac
OUTPUT_PARENT="$(cd "$(dirname "$OUTPUT")" && pwd)" || {
    echo "output parent does not exist: $OUTPUT" >&2
    exit 1
}
OUTPUT="$OUTPUT_PARENT/$OUTPUT_NAME"
OUTPUT_LOCK_ROOT="$OUTPUT_PARENT/.litebox-xfce-build-locks"
OUTPUT_LOCK_NAME="$(printf '%s' "$OUTPUT" | shasum -a 256 | cut -d' ' -f1)"
OUTPUT_LOCK_FILE="$OUTPUT_LOCK_ROOT/$OUTPUT_LOCK_NAME.lock"
STAGING_OUTPUT=""
X18_REPO="${LITEBOX_X18_DESKTOP_REPO:-$HOME/.cache/litebox/x18-desktop-repo}"
MUSL_X18_CACHE="${LITEBOX_MUSL_X18_CACHE:-$HOME/.cache/litebox/musl-x18-fixed}"
ALPINE_BRANCH="${LITEBOX_ALPINE_BRANCH:-3.24-stable}"
IMAGE_TAG="${LITEBOX_XFCE_IMAGE_TAG:-localhost/litebox-xfce-x18:3.24}"
[[ "$ALPINE_BRANCH" =~ ^[0-9]+\.[0-9]+-stable$ ]] || {
    echo "invalid Alpine branch: $ALPINE_BRANCH" >&2
    exit 1
}
ALPINE_TAG="${ALPINE_BRANCH%-stable}"

CONTAINER_ENGINE=""
for candidate in podman docker; do
    if command -v "$candidate" >/dev/null 2>&1; then
        CONTAINER_ENGINE="$candidate"
        break
    fi
done
[ -n "$CONTAINER_ENGINE" ] || { echo "podman or docker is required" >&2; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "python3 is required" >&2; exit 1; }

WORKDIR=""
CONTAINER_ID=""
IMAGE_ID=""
LOCK_SESSION=""
LOCK_KEEPER_PID=""
OUTPUT_LOCK_HELD=false
STAGING_OWNED=false
cleanup() {
    if [ -n "$CONTAINER_ID" ]; then
        "$CONTAINER_ENGINE" rm -f "$CONTAINER_ID" >/dev/null 2>&1 || true
    fi
    [ -z "$WORKDIR" ] || rm -rf "$WORKDIR"
    if [ "$STAGING_OWNED" = true ] && [ -n "$STAGING_OUTPUT" ]; then
        rm -f "$STAGING_OUTPUT"
    fi
    if [ "$OUTPUT_LOCK_HELD" = true ]; then
        exec 9>&-
        [ -z "$LOCK_KEEPER_PID" ] || wait "$LOCK_KEEPER_PID" 2>/dev/null || true
        OUTPUT_LOCK_HELD=false
    fi
    [ -z "$LOCK_SESSION" ] || rm -rf "$LOCK_SESSION"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

python3 - "$OUTPUT_LOCK_ROOT" <<'PY'
import os
import stat
import sys

root = sys.argv[1]
try:
    os.mkdir(root, 0o700)
except FileExistsError:
    metadata = os.lstat(root)
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid():
        raise SystemExit("output lock root is not a caller-owned directory")
    if stat.S_IMODE(metadata.st_mode) != 0o700:
        raise SystemExit("output lock root permissions are not 0700")
PY

LOCK_SESSION="$(mktemp -d "$OUTPUT_LOCK_ROOT/holder.XXXXXX")"
mkfifo "$LOCK_SESSION/control"
python3 -c '
import fcntl
import os
import stat
import sys

lock_path, session, host_pid = sys.argv[1:]
flags = os.O_RDWR | os.O_CREAT
if hasattr(os, "O_NOFOLLOW"):
    flags |= os.O_NOFOLLOW
fd = os.open(lock_path, flags, 0o600)
metadata = os.fstat(fd)
if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid()
        or metadata.st_nlink != 1):
    raise SystemExit("output lock file is not a caller-owned regular leaf")
os.fchmod(fd, 0o600)
try:
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
except BlockingIOError:
    raise SystemExit("output is already being built")
os.ftruncate(fd, 0)
os.write(fd, ("host_pid=" + host_pid + "\n").encode())
print("locked", flush=True)
try:
    sys.stdin.buffer.read()
finally:
    os.close(fd)
    for leaf in ("control", "ready", "error"):
        try:
            os.unlink(os.path.join(session, leaf))
        except FileNotFoundError:
            pass
    try:
        os.rmdir(session)
    except OSError:
        pass
' "$OUTPUT_LOCK_FILE" "$LOCK_SESSION" "$$" \
    < "$LOCK_SESSION/control" \
    > "$LOCK_SESSION/ready" \
    2> "$LOCK_SESSION/error" &
LOCK_KEEPER_PID=$!
exec 9> "$LOCK_SESSION/control"
attempts=0
while [ ! -s "$LOCK_SESSION/ready" ]; do
    if ! kill -0 "$LOCK_KEEPER_PID" 2>/dev/null; then
        if wait "$LOCK_KEEPER_PID"; then status=0; else status=$?; fi
        message="$(cat "$LOCK_SESSION/error" 2>/dev/null || true)"
        LOCK_KEEPER_PID=""
        echo "cannot acquire output lock (status $status): ${message:-unknown error}" >&2
        exit 1
    fi
    attempts=$((attempts + 1))
    [ "$attempts" -lt 3000 ] || { echo "timed out acquiring output lock" >&2; exit 1; }
    sleep 0.01
done
lock_state=""
IFS= read -r lock_state < "$LOCK_SESSION/ready" || true
[ "$lock_state" = locked ] || { echo "output-lock helper returned invalid state" >&2; exit 1; }
OUTPUT_LOCK_HELD=true

python3 - "$OUTPUT_LOCK_ROOT" "staging.$OUTPUT_LOCK_NAME." <<'PY'
import os
import stat
import sys

root, prefix = sys.argv[1:]
for entry in os.scandir(root):
    if not entry.name.startswith(prefix):
        continue
    metadata = entry.stat(follow_symlinks=False)
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid():
        raise SystemExit("foreign stale staging path: " + entry.path)
    os.unlink(entry.path)
PY

[ ! -e "$OUTPUT" ] && [ ! -L "$OUTPUT" ] || {
    echo "output already exists: $OUTPUT" >&2
    exit 1
}
STAGING_OUTPUT="$(mktemp "$OUTPUT_LOCK_ROOT/staging.$OUTPUT_LOCK_NAME.XXXXXX")"
STAGING_OWNED=true

BASE_IMAGE_INPUT="${LITEBOX_ALPINE_BASE_IMAGE:-public.ecr.aws/docker/library/alpine:${ALPINE_TAG}}"
for attempt in 1 2 3; do
    if "$CONTAINER_ENGINE" pull --platform linux/arm64 "$BASE_IMAGE_INPUT" >/dev/null; then
        break
    fi
    [ "$attempt" -lt 3 ] || {
        echo "failed to pull Alpine base image: $BASE_IMAGE_INPUT" >&2
        exit 1
    }
    sleep $((attempt * 5))
done
if [[ "$BASE_IMAGE_INPUT" == *@sha256:* ]]; then
    BASE_IMAGE="$BASE_IMAGE_INPUT"
else
    repo_digest="$($CONTAINER_ENGINE image inspect \
        --format '{{index .RepoDigests 0}}' "$BASE_IMAGE_INPUT")"
    [[ "$repo_digest" == *@sha256:* ]] || {
        echo "base image has no immutable repository digest: $BASE_IMAGE_INPUT" >&2
        exit 1
    }
    BASE_IMAGE="${BASE_IMAGE_INPUT}@${repo_digest##*@}"
fi

APORTS_COMMIT="${LITEBOX_APORTS_COMMIT:-013edf8b29199933e8ea34dde460b5584b979042}"
[[ "$APORTS_COMMIT" =~ ^[0-9a-f]{40}$ ]] || {
    echo "invalid immutable aports commit for $ALPINE_BRANCH" >&2
    exit 1
}
X18_RECIPE_SHA256="$(shasum -a 256 \
    "$REPO_ROOT/litebox_packager/scripts/build-x18-desktop-repo.sh" | cut -d' ' -f1)"

LITEBOX_ALPINE_BASE_IMAGE="$BASE_IMAGE" \
LITEBOX_APORTS_COMMIT="$APORTS_COMMIT" \
    "$REPO_ROOT/litebox_packager/scripts/build-x18-desktop-repo.sh" \
    "$ALPINE_BRANCH" "$X18_REPO"
X18_REPO="$(cd "$X18_REPO" && pwd -P)" || {
    echo "x18 repository generation is unavailable: $X18_REPO" >&2
    exit 1
}
LITEBOX_ALPINE_BASE_IMAGE="$BASE_IMAGE" \
LITEBOX_APORTS_COMMIT="$APORTS_COMMIT" \
    "$REPO_ROOT/litebox_packager/scripts/build-musl-x18-fixed.sh" \
    "$ALPINE_BRANCH" "$MUSL_X18_CACHE" "$X18_REPO"

WORKDIR="$(mktemp -d)"
cp "$SCRIPT_DIR/Containerfile" "$SCRIPT_DIR/panel.xml" "$SCRIPT_DIR/xorg.conf" \
    "$SCRIPT_DIR/start-desktop.sh" "$WORKDIR/"
mkdir -p "$WORKDIR/x18repo"
cp -R "$X18_REPO/." "$WORKDIR/x18repo"

IMAGE_ID_FILE="$WORKDIR/image.iid"
"$CONTAINER_ENGINE" build --platform linux/arm64 \
    --iidfile "$IMAGE_ID_FILE" \
    --build-arg "LITEBOX_ALPINE_BASE_IMAGE=$BASE_IMAGE" \
    --build-arg "LITEBOX_ALPINE_BRANCH=$ALPINE_BRANCH" \
    --build-arg "LITEBOX_APORTS_COMMIT=$APORTS_COMMIT" \
    --build-arg "LITEBOX_X18_RECIPE_SHA256=$X18_RECIPE_SHA256" \
    -t "$IMAGE_TAG" "$WORKDIR"

image_id_raw=""
IFS= read -r image_id_raw < "$IMAGE_ID_FILE" || true
if [[ "$image_id_raw" =~ ^[0-9a-f]{64}$ ]]; then
    IMAGE_ID="sha256:$image_id_raw"
elif [[ "$image_id_raw" =~ ^sha256:[0-9a-f]{64}$ ]]; then
    IMAGE_ID="$image_id_raw"
else
    echo "container build returned an invalid immutable image ID: $image_id_raw" >&2
    exit 1
fi
inspect_id="$($CONTAINER_ENGINE image inspect --format '{{.Id}}' "$IMAGE_ID")"
[[ "$inspect_id" == sha256:* ]] || inspect_id="sha256:$inspect_id"
image_arch="$($CONTAINER_ENGINE image inspect --format '{{.Architecture}}' "$IMAGE_ID")"
[ "$inspect_id" = "$IMAGE_ID" ] && [ "$image_arch" = arm64 ] || {
    echo "built image identity or architecture mismatch: $inspect_id $image_arch" >&2
    exit 1
}

loader_hash="$($CONTAINER_ENGINE run --rm --platform linux/arm64 "$IMAGE_ID" \
    sha256sum /lib/ld-musl-aarch64.so.1 | cut -d' ' -f1)"
image_musl_pkgver="$($CONTAINER_ENGINE run --rm --platform linux/arm64 "$IMAGE_ID" \
    sh -c 'apk info --installed -v musl | sed -n "s/^musl-//p"')"
[[ "$loader_hash" =~ ^[0-9a-f]{64}$ ]] && [ -n "$image_musl_pkgver" ] || {
    echo "failed to read the built image musl identity" >&2
    exit 1
}
musl_manifest="$MUSL_X18_CACHE/${loader_hash}.v2.meta"
[ -s "$musl_manifest" ] || {
    echo "missing recipe-v2 musl manifest for built image loader: $musl_manifest" >&2
    exit 1
}
expected_musl_keys='aports_commit arch base_image musl_pkgver patched_sha256 payload recipe size stock_sha256 '
actual_musl_keys="$(cut -d= -f1 "$musl_manifest" | LC_ALL=C sort | tr '\n' ' ')"
[ "$actual_musl_keys" = "$expected_musl_keys" ] || {
    echo "invalid recipe-v2 musl metadata fields: $musl_manifest" >&2
    exit 1
}
musl_value() { sed -n "s/^$1=//p" "$musl_manifest"; }
[ "$(musl_value recipe)" = 2 ]
[ "$(musl_value stock_sha256)" = "$loader_hash" ]
[ "$(musl_value musl_pkgver)" = "$image_musl_pkgver" ]
[ "$(musl_value arch)" = aarch64 ]
[ "$(musl_value base_image)" = "$BASE_IMAGE" ]
[ "$(musl_value aports_commit)" = "$APORTS_COMMIT" ]
patched_hash="$(musl_value patched_sha256)"
[[ "$patched_hash" =~ ^[0-9a-f]{64}$ ]] && [ "$patched_hash" != "$loader_hash" ] || {
    echo "invalid patched musl hash in $musl_manifest" >&2
    exit 1
}
payload_name="${loader_hash}.v2.${patched_hash}.so"
[ "$(musl_value payload)" = "$payload_name" ]
payload_path="$MUSL_X18_CACHE/$payload_name"
[ -f "$payload_path" ]
payload_size="$(wc -c < "$payload_path" | tr -d '[:space:]')"
[ "$payload_size" = "$(musl_value size)" ]
[ "$(shasum -a 256 "$payload_path" | cut -d' ' -f1)" = "$patched_hash" ]

CONTAINER_ID="$($CONTAINER_ENGINE create "$IMAGE_ID")"
"$CONTAINER_ENGINE" export "$CONTAINER_ID" | \
    LITEBOX_MUSL_X18_CACHE="$MUSL_X18_CACHE" \
    LITEBOX_REQUIRE_MUSL_X18=1 \
    cargo run --release --manifest-path "$REPO_ROOT/Cargo.toml" \
        -p litebox_packager -- \
        --oci-rootfs-tar /dev/stdin -o "$STAGING_OUTPUT"
"$CONTAINER_ENGINE" rm "$CONTAINER_ID" >/dev/null
CONTAINER_ID=""

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
    "$BASE_IMAGE" sleep 300 >/dev/null
scan_cleanup() { "$CONTAINER_ENGINE" rm -f "$SCAN_CONTAINER" >/dev/null 2>&1 || true; }
trap 'scan_cleanup; cleanup' EXIT
"$CONTAINER_ENGINE" exec "$SCAN_CONTAINER" mkdir -p /scan
"$CONTAINER_ENGINE" cp "$STAGING_OUTPUT" "$SCAN_CONTAINER:/scan.tar"
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

python3 - "$STAGING_OUTPUT" <<'PY'
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

python3 - "$STAGING_OUTPUT" "$OUTPUT" <<'PY'
import errno
import os
import stat
import sys

staging, output = sys.argv[1:]
source = os.lstat(staging)
if not stat.S_ISREG(source.st_mode) or source.st_uid != os.getuid():
    raise SystemExit("staging output is not a caller-owned regular file")
try:
    os.link(staging, output, follow_symlinks=False)
except FileExistsError:
    raise SystemExit("output appeared while the image was being built: " + output)
except OSError as error:
    if error.errno in (errno.EEXIST, errno.EISDIR):
        raise SystemExit("output appeared while the image was being built: " + output)
    raise
published = os.lstat(output)
if (not stat.S_ISREG(published.st_mode)
        or (published.st_dev, published.st_ino) != (source.st_dev, source.st_ino)):
    raise SystemExit("published output is not the staging inode")
os.unlink(staging)
PY
STAGING_OWNED=false

printf '\nBuilt %s\n\n' "$OUTPUT"
printf 'Run:\n  cargo run --release -p litebox_runner_linux_on_macos_userland -- \\\n'
printf '    --unstable --guest-root --initial-files %q --vnc-web 6080 -- \\\n' "$OUTPUT"
printf '    /usr/bin/start-desktop.sh\n\n'
printf 'Open http://127.0.0.1:6080/\n'
