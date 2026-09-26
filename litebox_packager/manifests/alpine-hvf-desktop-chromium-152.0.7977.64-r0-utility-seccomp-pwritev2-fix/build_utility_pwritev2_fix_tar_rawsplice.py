#!/usr/bin/env python3
"""Raw-byte tar splice (the technique wave175's own v2 splice actually used,
per gpu-seccomp-fix-tar-stale-thunar-liveness-gate's own witness text --
NOT the tarfile-addfile()-passthrough technique in build-gpu-seccomp-fix-tar.py,
which that same witness documents as BROKEN: it re-serializes headers via
Python's tarfile writer for every member including byte-identical passthrough
ones, which live-broke litebox's own tar_no_std guest parser on an unrelated
ca-certificates PAX long-name entry (confirmed again this wave: reproduced the
exact same 'Unparsable size' / ENOENT failure by naively reusing that script
against the v2 base).

Method: the ENTIRE base tar is copied byte-for-byte verbatim first (a plain
file copy, headers included, nothing parsed or re-emitted). Only then, for
each of the 17 swap targets, the file is opened for read+write and the exact
`size` bytes at `offset_data` (both read via a READ-ONLY tarfile parse pass,
never used to drive any write) are overwritten in place with the new file's
content. Every one of the 17 new files is byte-length-identical to its v2
counterpart (confirmed separately, compare_v2_vs_new.py), so this is a pure
in-place content substitution: no header field ever changes, no subsequent
byte offset in the archive ever shifts, and the checksum stored in each
target's own header (computed over header bytes only, never content) stays
valid unchanged. Base tar is opened read-only for the parse pass and its own
file is never opened for writing.
"""
import os
import shutil
import tarfile
import hashlib

BASE = "/tmp/litebox-hvf-desktop-gpu-seccomp-fix-v2.tar"
NEWFILES_ROOT = "/private/tmp/claude-501/-Users-dylanwong-litebox/f6d44897-7afe-4476-a55f-3bde77ed8ef2/scratchpad/utility-fix-newfiles"
OUTPUT = "/tmp/litebox-hvf-desktop-utility-pwritev2-fix.tar"

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
    base_before = sha256_of(BASE)

    # Pass 1 (read-only): find offset_data + size for each swap target.
    swap_set = set(SWAP_PATHS)
    offsets = {}
    tar_in = tarfile.open(BASE, "r:")
    for member in tar_in:
        if member.name in swap_set and member.isfile():
            offsets[member.name] = (member.offset_data, member.size)
    tar_in.close()

    missing = [p for p in SWAP_PATHS if p not in offsets]
    if missing:
        raise SystemExit(f"FATAL: swap targets never found in base tar: {missing}")

    for p in SWAP_PATHS:
        newfile_path = os.path.join(NEWFILES_ROOT, p)
        if not os.path.isfile(newfile_path):
            raise SystemExit(f"FATAL: expected replacement file missing: {newfile_path}")
        new_size = os.path.getsize(newfile_path)
        _, old_size = offsets[p]
        if new_size != old_size:
            raise SystemExit(
                f"FATAL: {p} size changed ({old_size} -> {new_size}); this script only "
                f"supports same-size in-place content substitution, refusing to corrupt "
                f"subsequent tar offsets. Use a full header-patching splice instead."
            )

    # Pass 2: verbatim whole-file byte copy, base tar opened read-only throughout.
    print("copying base tar verbatim (byte-for-byte) ...")
    shutil.copyfile(BASE, OUTPUT)

    base_after_copy = sha256_of(BASE)
    if base_after_copy != base_before:
        raise SystemExit("FATAL: base tar changed during copy -- aborting, not touching OUTPUT further")

    # Pass 3: in-place content substitution at the exact byte ranges, output file only.
    with open(OUTPUT, "r+b") as out_f:
        for p in SWAP_PATHS:
            offset_data, size = offsets[p]
            newfile_path = os.path.join(NEWFILES_ROOT, p)
            with open(newfile_path, "rb") as nf:
                new_content = nf.read()
            assert len(new_content) == size
            out_f.seek(offset_data)
            out_f.write(new_content)
            print(f"SUBSTITUTED  {p}  offset_data={offset_data} size={size}")

    base_after = sha256_of(BASE)

    print("---")
    print("swap_targets_substituted:", len(SWAP_PATHS), "/", len(SWAP_PATHS))
    print("base_sha256_before:", base_before)
    print("base_sha256_after_copy:", base_after_copy)
    print("base_sha256_final:", base_after)
    print("base_unchanged_throughout:", base_before == base_after_copy == base_after)
    print("output_tar:", OUTPUT)
    print("output_tar_size:", os.path.getsize(OUTPUT))
    print("base_tar_size:", os.path.getsize(BASE))
    print("sizes_match:", os.path.getsize(OUTPUT) == os.path.getsize(BASE))

if __name__ == "__main__":
    main()
