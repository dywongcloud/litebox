#!/usr/bin/env python3
"""Surgical tar splice: copy every entry of the canonical desktop tar through
unchanged, except a named set of paths whose CONTENT is swapped in from newly
extracted files (metadata -- mode/uid/gid/mtime -- kept from the canonical
entry). Canonical tar is opened strictly read-only and never written to.
Authored for the chromium-gpu-seccomp-pwritev2 GPU-policy-fix packaging wave.
"""
import os
import sys
import tarfile
import hashlib

CANONICAL = "/tmp/litebox-hvf-desktop-canonical.tar"
NEWFILES_ROOT = "/private/tmp/claude-501/-Users-dylanwong-litebox/f6d44897-7afe-4476-a55f-3bde77ed8ef2/scratchpad/gpu-fix-newfiles"
OUTPUT = "/tmp/litebox-hvf-desktop-gpu-seccomp-fix.tar"

SWAP_PATHS = [
    "usr/lib/chromium/chromium",
    "usr/lib/chromium/chrome-sandbox",
    "usr/lib/chromium/chrome_crashpad_handler",
    "usr/lib/chromium/chrome_100_percent.pak",
    "usr/lib/chromium/chrome_200_percent.pak",
    "usr/lib/chromium/resources.pak",
    "usr/lib/chromium/icudtl.dat",
    "usr/lib/chromium/snapshot_blob.bin",
    "usr/lib/chromium/chromium-launcher.sh",
    "usr/lib/chromium/MEIPreload/manifest.json",
    "usr/lib/chromium/MEIPreload/preloaded_data.pb",
    "usr/lib/chromium/locales/en-US.pak",
    "usr/lib/chromium/v8_context_snapshot.bin",
    "usr/lib/chromium/headless_command_resources.pak",
    "usr/lib/chromium/libEGL.so",
    "usr/lib/chromium/libGLESv2.so",
    "usr/lib/chromium/libvulkan.so.1",
]

def sha256_of(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

def main():
    canonical_before = sha256_of(CANONICAL)
    swap_set = set(SWAP_PATHS)
    found = {p: False for p in SWAP_PATHS}

    tar_in = tarfile.open(CANONICAL, "r:")
    tar_out = tarfile.open(OUTPUT, "w:", format=tar_in.format)

    n_total = 0
    n_swapped = 0
    for member in tar_in:
        n_total += 1
        if member.name in swap_set and member.isfile():
            newfile_path = os.path.join(NEWFILES_ROOT, member.name)
            if not os.path.isfile(newfile_path):
                raise SystemExit(f"FATAL: expected replacement file missing: {newfile_path}")
            new_member = tarfile.TarInfo(name=member.name)
            new_member.mode = member.mode
            new_member.uid = member.uid
            new_member.gid = member.gid
            new_member.uname = member.uname
            new_member.gname = member.gname
            new_member.mtime = member.mtime
            new_member.type = member.type
            new_member.size = os.path.getsize(newfile_path)
            with open(newfile_path, "rb") as fh:
                tar_out.addfile(new_member, fileobj=fh)
            found[member.name] = True
            n_swapped += 1
            print(f"SWAPPED  {member.name}  old_size={member.size} new_size={new_member.size} mode={oct(member.mode)}")
        else:
            if member.isfile():
                src = tar_in.extractfile(member)
                tar_out.addfile(member, fileobj=src)
            else:
                tar_out.addfile(member)

    tar_out.close()
    tar_in.close()

    canonical_after = sha256_of(CANONICAL)

    print("---")
    print("total_members_copied:", n_total)
    print("members_swapped:", n_swapped, "/", len(SWAP_PATHS))
    missing = [p for p, v in found.items() if not v]
    if missing:
        print("WARNING: never found in canonical tar (not swapped):", missing)
    print("canonical_sha256_before:", canonical_before)
    print("canonical_sha256_after: ", canonical_after)
    print("canonical_unchanged:", canonical_before == canonical_after)
    print("output_tar:", OUTPUT)
    print("output_tar_size:", os.path.getsize(OUTPUT))

if __name__ == "__main__":
    main()
