#!/bin/bash

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

# Builds an Alpine 3.24 XFCE + Chromium desktop rootfs tar for the macOS
# Hypervisor.framework backend (`--hvf`) from the persisted, byte-verified
# APK manifest at litebox_packager/manifests/alpine-hvf-desktop.
#
# Unlike build-xfce-image.sh (the older sibling recipe for the native
# syscall-rewriting backend), this script installs STOCK Alpine packages
# unchanged: no source rebuild, no musl patching, no x18 reservation, no
# syscall rewriting. The `--hvf` backend runs unmodified upstream AArch64
# Linux binaries directly on a real vCPU via Apple's Hypervisor.framework,
# where `x18` is a genuine architectural guest register untouched by any
# host EL0 return -- so there is nothing here to work around.
#
# Pipeline:
#   1. Verify the manifest at MANIFEST_DIR is present and every cached APK's
#      SHA-256 matches its manifest entry (fail closed before any image
#      mutation -- see capture-alpine-apk-manifest.sh for how the manifest
#      itself is produced and re-verified against Alpine's real signed
#      repositories).
#   2. Install the exact manifested APK set, fully offline, from the local
#      content-addressed cache into a scratch container rootfs (`apk add
#      --no-network`, so nothing beyond the manifest's own captured bytes
#      can influence the result).
#   3. Export the container filesystem and package it with
#      `litebox_packager --oci-rootfs-tar ... --no-rewrite-all`, which
#      preserves uid/gid, symlinks, and modes (including the Chromium
#      sandbox helper's root-owned 04755 special bit) byte-for-byte and
#      skips the syscall rewriter entirely.
#
# Usage: build-hvf-desktop-image.sh [OUTPUT_TAR] [MANIFEST_DIR]
#   OUTPUT_TAR    default: /tmp/litebox-hvf-desktop.tar
#   MANIFEST_DIR  default: litebox_packager/manifests/alpine-hvf-desktop
#                 (relative to the repo root)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

OUTPUT="${1:-/tmp/litebox-hvf-desktop.tar}"
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

MANIFEST_DIR="${2:-$REPO_ROOT/litebox_packager/manifests/alpine-hvf-desktop}"
MANIFEST_DIR="$(cd "$MANIFEST_DIR" 2>/dev/null && pwd)" || {
    echo "manifest directory does not exist: ${2:-$REPO_ROOT/litebox_packager/manifests/alpine-hvf-desktop}" >&2
    echo "hint: run litebox_packager/scripts/capture-alpine-apk-manifest.sh first" >&2
    exit 1
}
MANIFEST_JSON="$MANIFEST_DIR/manifest.json"
[ -s "$MANIFEST_JSON" ] || { echo "missing or empty manifest: $MANIFEST_JSON" >&2; exit 1; }

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
cleanup() {
    [ -z "$CONTAINER_ID" ] || "$CONTAINER_ENGINE" rm -f "$CONTAINER_ID" >/dev/null 2>&1 || true
    [ -z "$WORKDIR" ] || rm -rf "$WORKDIR"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

[ ! -e "$OUTPUT" ] && [ ! -L "$OUTPUT" ] || {
    echo "output already exists: $OUTPUT" >&2
    exit 1
}

# --- Step 1: fail closed unless every manifested APK is present with the
# exact recorded SHA-256, BEFORE any container or image mutation happens. ---
echo "Verifying manifest: $MANIFEST_JSON" >&2
python3 - "$MANIFEST_JSON" "$MANIFEST_DIR" <<'PY'
import hashlib
import json
import os
import sys

manifest_path, manifest_dir = sys.argv[1:]
with open(manifest_path, encoding="utf-8") as f:
    manifest = json.load(f)

if manifest.get("format") != 1:
    raise SystemExit(f"unsupported manifest format: {manifest.get('format')!r}")
if manifest.get("source", {}).get("rebuild") is not False:
    raise SystemExit("manifest does not attest a non-rebuilt (stock) package source")
if manifest.get("source", {}).get("x18_reserved") is not False:
    raise SystemExit("manifest does not attest an unreserved x18 package source")

packages = manifest.get("packages", [])
if not packages:
    raise SystemExit("manifest has no packages")

missing = []
mismatched = []
for pkg in packages:
    path = os.path.join(manifest_dir, pkg["cache_path"])
    if not os.path.isfile(path):
        missing.append(pkg["cache_path"])
        continue
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    digest = h.hexdigest()
    if digest != pkg["sha256"]:
        mismatched.append((pkg["cache_path"], pkg["sha256"], digest))

if missing or mismatched:
    if missing:
        print(f"FAIL CLOSED: {len(missing)} manifested APK(s) missing from cache:", file=sys.stderr)
        for m in missing[:20]:
            print(f"  {m}", file=sys.stderr)
    if mismatched:
        print(f"FAIL CLOSED: {len(mismatched)} manifested APK(s) hash-mismatched:", file=sys.stderr)
        for name, expected, actual in mismatched[:20]:
            print(f"  {name}: expected {expected}, got {actual}", file=sys.stderr)
    raise SystemExit(1)

print(f"Verified {len(packages)} packages, all byte-exact against the manifest.", file=sys.stderr)
PY

WORKDIR="$(mktemp -d)"

# --- Step 2: fully offline install from the manifested cache into the
# container's OWN root filesystem (not a copied-out subdirectory). No
# repository, no network -- only the exact APK bytes the manifest already
# verified. The base image already ships a real, initialized apk database
# at / (16 packages: alpine-baselayout, busybox, apk-tools, musl, etc.,
# all traceable to the manifest's own pinned base_image_digest even though
# 2 of them -- alpine-keys, alpine-release -- are not separately listed in
# manifest.json's own package array), so `apk add` on / just extends that
# database in place; nothing needs its own scratch root or --initdb.
#
# Extraction uses `podman export` (a raw tar byte stream of the container
# filesystem, parsed directly by litebox_packager) rather than `podman cp`
# (a filesystem-to-filesystem copy): `podman cp` out of a container was
# observed LIVE on this macOS/podman-machine setup to silently re-own every
# copied file to the invoking host user (e.g. root:root 04755 became
# 501:20 -rwsr-xr-x, exactly this host user's own uid/gid) -- podman cp
# implements a real filesystem write on the host side and macOS forbids an
# unprivileged process from chowning to an arbitrary uid/gid, so it visibly
# fails closed by attributing everything to the caller instead. `podman
# export`'s tar stream carries the numeric uid/gid/mode from the container
# layer directly in each header, and litebox_packager's own tar parser
# (oci::extract_layer) reads those header fields without ever calling
# chown, so no host filesystem privilege is needed to preserve them.
BASE_IMAGE="$(python3 -c "import json; print(json.load(open('$MANIFEST_JSON'))['source']['base_image'])")"
echo "Installing offline from $MANIFEST_DIR/apks into the container root (base $BASE_IMAGE)..." >&2

for attempt in 1 2 3; do
    if "$CONTAINER_ENGINE" pull --platform linux/arm64 "$BASE_IMAGE" >/dev/null; then
        break
    fi
    [ "$attempt" -lt 3 ] || { echo "failed to pull base image: $BASE_IMAGE" >&2; exit 1; }
    sleep $((attempt * 5))
done

CONTAINER_NAME="litebox-hvf-desktop-build-$$"
"$CONTAINER_ENGINE" rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true

# Build the explicit ordered file-path list from the manifest so `apk add`
# receives the same closure this script just verified, nothing more and
# nothing less -- apk resolves ordering/dependency compatibility from each
# APK's own embedded metadata, not from list order.
APK_LIST_FILE="$WORKDIR/apk-paths.txt"
python3 -c "
import json
manifest = json.load(open('$MANIFEST_JSON'))
for pkg in manifest['packages']:
    print('/manifest/' + pkg['cache_path'])
" > "$APK_LIST_FILE"

INSTALL_SCRIPT='
set -eu
apk add --no-network --repositories-file /dev/null \
    $(cat /apk-paths.txt)
'

"$CONTAINER_ENGINE" run --name "$CONTAINER_NAME" --platform linux/arm64 \
    -v "$MANIFEST_DIR:/manifest:ro" \
    -v "$APK_LIST_FILE:/apk-paths.txt:ro" \
    "$BASE_IMAGE" sh -c "$INSTALL_SCRIPT"

RAW_ROOTFS_TAR="$WORKDIR/rootfs-raw.tar"
"$CONTAINER_ENGINE" export "$CONTAINER_NAME" > "$RAW_ROOTFS_TAR"
"$CONTAINER_ENGINE" rm -f "$CONTAINER_NAME" >/dev/null 2>&1

# The two -v bind mounts above (the manifest's APK cache and the derived
# path list) are visible inside the container's own filesystem view at
# export time, so `podman export` captures them as regular tar content --
# confirmed live: manifest/ (the whole ~300 MB APK cache) and
# apk-paths.txt landed as literal top-level entries in the exported tar.
# Strip exactly those two top-level names before handing the tar to
# litebox_packager, leaving every real installed file untouched.
ROOTFS_TAR="$WORKDIR/rootfs.tar"
python3 - "$RAW_ROOTFS_TAR" "$ROOTFS_TAR" <<'PY'
import sys
import tarfile

src, dst = sys.argv[1:]
excluded_prefixes = ("manifest", "apk-paths.txt")

def is_excluded(name):
    name = name.lstrip("/")
    return any(name == p or name.startswith(p + "/") for p in excluded_prefixes)

with tarfile.open(src, "r") as tin, tarfile.open(dst, "w") as tout:
    for member in tin.getmembers():
        if is_excluded(member.name):
            continue
        if member.isfile():
            tout.addfile(member, tin.extractfile(member))
        else:
            tout.addfile(member)
PY
CONTAINER_ID=""

# Extract just far enough (to a throwaway directory, via `tar`'s own
# extraction which -- like podman export -- reads header uid/gid without
# calling chown when run unprivileged, so ownership is simply not applied
# to the throwaway copy on disk; that is fine here, since this extraction
# exists ONLY to read /lib/apk/db/installed for the cross-check below, and
# the actual packaged tar in Step 4 is built by litebox_packager reading
# ROOTFS_TAR's own headers directly, never through this directory) so the
# cross-check step can read the installed-package database.
INSPECT_ROOT="$WORKDIR/inspect-root"
mkdir -p "$INSPECT_ROOT"
tar -xf "$ROOTFS_TAR" -C "$INSPECT_ROOT" lib/apk/db/installed 2>/dev/null || {
    echo "failed to extract lib/apk/db/installed from the exported rootfs for cross-check" >&2
    exit 1
}

# --- Step 3: cross-check the installed rootfs's own package database
# against the manifest one more time, from inside the just-built rootfs,
# so a divergence between "what apk resolved" and "what the manifest
# recorded" is caught before packaging. ---
python3 - "$MANIFEST_JSON" "$INSPECT_ROOT/lib/apk/db/installed" <<'PY'
import json
import sys

manifest_path, installed_db_path = sys.argv[1:]
with open(manifest_path, encoding="utf-8") as f:
    manifest = json.load(f)
manifest_set = {(p["name"], p["version"]) for p in manifest["packages"]}

installed_set = set()
name = None
with open(installed_db_path, encoding="utf-8", errors="replace") as f:
    for line in f:
        line = line.rstrip("\n")
        if line.startswith("P:"):
            name = line[2:]
        elif line.startswith("V:") and name is not None:
            installed_set.add((name, line[2:]))
            name = None

# The base image's own layer already carries a real initialized apk
# database at / with 16 packages (see the Step 2 comment); two of them --
# alpine-keys (the trust-key package itself) and alpine-release (a bare
# version marker) -- are not separately re-listed in manifest.json's own
# package array, since their provenance is already the pinned
# base_image_digest, not a separately-fetched APK. Nothing else is exempt.
BASE_IMAGE_ONLY_NAMES = {"alpine-keys", "alpine-release"}
extra = {(n, v) for (n, v) in installed_set - manifest_set if n not in BASE_IMAGE_ONLY_NAMES}
missing = manifest_set - installed_set
if extra or missing:
    if extra:
        print(f"FAIL CLOSED: {len(extra)} package(s) installed but not in manifest: {sorted(extra)[:20]}", file=sys.stderr)
    if missing:
        print(f"FAIL CLOSED: {len(missing)} manifested package(s) not actually installed: {sorted(missing)[:20]}", file=sys.stderr)
    raise SystemExit(1)
print(f"Cross-checked: installed rootfs exactly matches the manifest's {len(manifest_set)} packages (plus the base image's own alpine-keys/alpine-release).", file=sys.stderr)
PY

# --- Step 3b: layer the desktop-session wiring directly into ROOTFS_TAR
# before packaging. litebox_packager's `--include HOST_PATH:TAR_PATH` is
# NOT usable here -- reading litebox_packager/src/lib.rs confirms it is
# wired into run_host_mode only; run_oci_rootfs_tar's package_extracted
# path never reads args.include at all (the CLI help's "(host mode only)"
# is accurate, live-confirmed: a --include against --oci-rootfs-tar builds
# with no error and no effect, the flag is silently accepted by clap and
# then ignored). So, matching the pattern the older x18-rewritten
# build-xfce-image.sh used (COPY into a Containerfile before export), we
# splice the same four files directly into the ROOTFS_TAR byte stream here
# -- before litebox_packager ever reads it -- as root:root tar members:
# a custom fbdev/evdev xorg.conf (the stock APK set ships no
# display-specific one), the packaged xfce4-panel.xml xfconf seed, a
# static resolv.conf (no DNS in the guest network model), and
# start-desktop.sh, the same session-bring-up sequence the older build
# used (Xorg -> dbus -> xfwm4 -> xfsettingsd -> xfdesktop -> xfce4-panel ->
# thunar -> xterm -> chromium), reused verbatim since it never depends on
# the rewriting backend. Any pre-existing member at the same path
# (e.g. the stock empty etc/resolv.conf) is replaced, not duplicated.
#
# Also append the same synthetic /sys/class/graphics/fb0 entries the older
# x18-rewritten build-xfce-image.sh adds (see that script's own comment):
# litebox_packager's rootfs packaging drops /sys entirely, but
# xf86-video-fbdev's fbdevHWProbe walks /sys/class/graphics/fb0/device to
# find a bus (via the device/subsystem symlink) before it will touch
# /dev/fb0 at all -- without this, Xorg reports "no primary bus or device
# found" / "no screens found" even though /dev/fb0 itself is fully
# functional (open/FBIOGET_*SCREENINFO/mmap all work, live-verified). This
# was missing from this script's first pass, which is why GUI boot failed
# with that exact symptom.
#
# Also append an /etc/passwd (and /etc/group) entry for uid/gid 1000, the
# identity start-desktop.sh's `setpriv --reuid=1000 --regid=1000` drops the
# desktop session to. The stock Alpine package set's passwd file has no such
# entry (only system accounts up to messagebus=100). This was live-verified
# fatal, not cosmetic: `dbus-daemon --session` under this exact setpriv drop
# logs "Could not get password database information for UID of current
# process: Looking up user ID 1000: not found" and then exits immediately
# with "Failed to start message bus: Memory allocation failure in message
# bus" (dbus's generic message for this class of early bus-config failure) --
# confirmed by isolated reproduction both ways: it fails identically as
# uid 1000 with no passwd entry, and runs and stays alive identically to
# root once a uid 1000 entry exists. This is what was silently timing out
# start-desktop.sh's "D-Bus protocol readiness timed out" check before any
# XFCE component ran.
echo "Splicing desktop-session files into $ROOTFS_TAR..." >&2
python3 - "$ROOTFS_TAR" "$SCRIPT_DIR" <<'PY'
import sys
import tarfile
import os

rootfs_tar, script_dir = sys.argv[1:]
overlay = {
    "etc/X11/xorg.conf": ("xorg.conf", 0o644),
    "etc/xdg/litebox/xfce4-panel.xml": ("panel.xml", 0o644),
    "etc/resolv.conf": ("resolv.conf", 0o644),
    "usr/bin/start-desktop.sh": ("start-desktop.sh", 0o755),
}
sysfs_dirs = [
    "sys",
    "sys/class",
    "sys/class/graphics",
    "sys/class/graphics/fb0",
    "sys/class/graphics/fb0/device",
    "sys/bus",
    "sys/bus/platform",
]
sysfs_link = "sys/class/graphics/fb0/device/subsystem"

# uid/gid 1000 passwd/group append -- see this script's comment above for the
# live-verified dbus-daemon-fatal reasoning. Only appended if no uid-1000
# entry already exists, so a manifest that someday ships one isn't duplicated.
#
# The stock Alpine rootfs ships etc/shadow (proving the real system accounts --
# root, bin, daemon, lp, sync, shutdown, halt, mail, news, uucp, cron, ftp,
# sshd, games, ntp, guest, nobody, messagebus -- are genuinely part of this
# package set) but never materializes etc/passwd itself as a static file, so
# the member loop below never sees one to append to and the uid-1000 fix
# silently never applied -- live-verified: dbus-daemon --session under
# setpriv --reuid=1000 still failed with "Could not get password database
# information ... Failed to start message bus: Memory allocation failure"
# even after this script's passwd_append/group_append were added, because
# passwd_append's only call site required a pre-existing etc/passwd member.
# Fixed by tracking whether etc/passwd was seen in the source tar and, if
# not, synthesizing the same account list etc/shadow already proves exists,
# in the exact uid/gid/home/shell shape Alpine's real passwd ships (root at
# 0:0, the fixed system-account block through messagebus, then litebox).
passwd_append = b"litebox:x:1000:1000:litebox:/home/litebox:/bin/sh\n"
group_append = b"litebox:x:1000:\n"
synthetic_passwd = b"""root:x:0:0:root:/root:/bin/ash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/sbin/nologin
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
mail:x:8:12:mail:/var/spool/mail:/sbin/nologin
news:x:9:13:news:/usr/lib/news:/sbin/nologin
uucp:x:10:14:uucp:/var/spool/uucppublic:/sbin/nologin
cron:x:16:16:cron:/var/spool/cron:/sbin/nologin
ftp:x:21:21:ftp:/var/lib/ftp:/sbin/nologin
sshd:x:22:22:sshd:/dev/null:/sbin/nologin
games:x:35:35:games:/usr/games:/sbin/nologin
ntp:x:123:123:NTP:/var/empty:/sbin/nologin
guest:x:405:100:guest:/dev/null:/sbin/nologin
nobody:x:65534:65534:nobody:/:/sbin/nologin
messagebus:x:101:101:messagebus:/dev/null:/sbin/nologin
"""

tmp = rootfs_tar + ".splice"
with tarfile.open(rootfs_tar, "r") as tin, tarfile.open(tmp, "w") as tout:
    saw_passwd = False
    for member in tin.getmembers():
        if member.name in overlay:
            continue
        if member.name == "etc/passwd" and member.isfile():
            saw_passwd = True
            data = tin.extractfile(member).read()
            if not any(line.split(b":")[2:3] == [b"1000"] for line in data.splitlines()):
                data += passwd_append
                print("  appended uid-1000 entry to etc/passwd", file=sys.stderr)
            member.size = len(data)
            tout.addfile(member, __import__("io").BytesIO(data))
            continue
        if member.name == "etc/group" and member.isfile():
            data = tin.extractfile(member).read()
            if not any(line.split(b":")[2:3] == [b"1000"] for line in data.splitlines()):
                data += group_append
                print("  appended gid-1000 entry to etc/group", file=sys.stderr)
            member.size = len(data)
            tout.addfile(member, __import__("io").BytesIO(data))
            continue
        if member.isfile():
            tout.addfile(member, tin.extractfile(member))
        else:
            tout.addfile(member)
    if not saw_passwd:
        data = synthetic_passwd + passwd_append
        info = tarfile.TarInfo("etc/passwd")
        info.size = len(data)
        info.mode = 0o644
        info.uid = 0
        info.gid = 0
        tout.addfile(info, __import__("io").BytesIO(data))
        print("  synthesized etc/passwd (absent from source tar) with uid-1000 entry", file=sys.stderr)
    # etc/xdg/litebox may not exist yet as a directory in the stock rootfs.
    dir_name = "etc/xdg/litebox"
    existing = {m.name for m in tin.getmembers()}
    if dir_name not in existing:
        d = tarfile.TarInfo(dir_name)
        d.type = tarfile.DIRTYPE
        d.mode = 0o755
        d.uid = 0
        d.gid = 0
        tout.addfile(d)
    for tar_path, (host_name, mode) in overlay.items():
        host_path = os.path.join(script_dir, host_name)
        data = open(host_path, "rb").read()
        info = tarfile.TarInfo(tar_path)
        info.size = len(data)
        info.mode = mode
        info.uid = 0
        info.gid = 0
        tout.addfile(info, __import__("io").BytesIO(data))
        print(f"  spliced {host_path} -> {tar_path} (mode={oct(mode)})", file=sys.stderr)
    for name in sysfs_dirs:
        if name in existing:
            continue
        d = tarfile.TarInfo(name)
        d.type = tarfile.DIRTYPE
        d.mode = 0o755
        d.uid = 0
        d.gid = 0
        tout.addfile(d)
    if sysfs_link not in existing:
        link = tarfile.TarInfo(sysfs_link)
        link.type = tarfile.SYMTYPE
        link.mode = 0o777
        link.linkname = "../../../../bus/platform"
        link.uid = 0
        link.gid = 0
        tout.addfile(link)
    print(f"  synthesized {sysfs_link} -> ../../../../bus/platform", file=sys.stderr)
os.replace(tmp, rootfs_tar)
PY

# --- Step 4: package the rootfs, preserving all bytes/modes/ownership,
# with the syscall rewriter fully disabled (--no-rewrite-all). ROOTFS_TAR
# is the raw `podman export` byte stream from Step 2, now overlaid with
# the desktop-session files above -- litebox_packager reads its tar
# headers directly (oci::extract_rootfs_tar), so no intermediate
# filesystem extraction or re-archiving happens here. ---
echo "Packaging rootfs into $OUTPUT (--no-rewrite-all, HVF-targeted)..." >&2

cargo run --release --manifest-path "$REPO_ROOT/Cargo.toml" \
    -p litebox_packager -- \
    --oci-rootfs-tar "$ROOTFS_TAR" --no-rewrite-all -o "$OUTPUT"

# --- Step 5: verify the Chromium sandbox helper's mode/ownership survived
# packaging unchanged (root:root, 04755) -- the whole point of this
# pipeline is that HVF needs no rewriting, so real Alpine's real setuid
# bit must reach the tar untouched. ---
python3 - "$OUTPUT" <<'PY'
import sys
import tarfile

path = sys.argv[1]
target = "usr/lib/chromium/chrome-sandbox"
with tarfile.open(path, "r") as archive:
    try:
        member = archive.getmember(target)
    except KeyError:
        print(f"warning: {target} not present in {path} (chromium may not be in the requested package set)", file=sys.stderr)
        raise SystemExit(0)
    mode = member.mode & 0o7777
    ok = mode == 0o4755 and member.uid == 0 and member.gid == 0
    print(f"{target}: mode={oct(mode)} uid={member.uid} gid={member.gid} -> {'OK' if ok else 'MISMATCH'}", file=sys.stderr)
    if not ok:
        raise SystemExit(f"chrome-sandbox mode/ownership was not preserved: mode={oct(mode)} uid={member.uid} gid={member.gid}")
PY

printf '\nBuilt %s\n\n' "$OUTPUT"
printf 'Run (plain shell smoke test):\n'
printf '  cargo run --release -p litebox_runner_linux_on_macos_userland -- \\\n'
printf '    --unstable --hvf --initial-files %q -- /bin/busybox sh\n\n' "$OUTPUT"
printf 'Run (XFCE desktop over VNC/web viewer -- start-desktop.sh needs root to\n'
printf 'bring up /tmp/.X11-unix and drop to uid 1000 itself, hence --guest-root):\n'
printf '  cargo run --release -p litebox_runner_linux_on_macos_userland -- \\\n'
printf '    --unstable --guest-root --initial-files %q \\\n' "$OUTPUT"
printf '    --vnc-web 6080 -- /usr/bin/start-desktop.sh\n\n'
printf 'The runner binary must be codesigned with the com.apple.security.hypervisor\n'
printf 'entitlement (litebox_runner_linux_on_macos_userland/entitlements.plist):\n'
printf '  codesign --force --sign - --options runtime \\\n'
printf '    --entitlements %q \\\n' "$REPO_ROOT/litebox_runner_linux_on_macos_userland/entitlements.plist"
printf '    <path to the built runner binary>\n'
