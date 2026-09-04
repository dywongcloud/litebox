#!/usr/bin/env python3
"""Package the three demo box images as `boxer build --archive` inputs
(docker-save layout: manifest.json + config.json + layer.tar) and build each
into a .box.wasm. Each box is one statically-linked musl binary from this
directory's own Cargo project -- no dynamic linking, no package-manager
network access, no root requirement. (An earlier version of this script
packaged the host's real Xvfb instead of x11-server; Xvfb's lock-file
creation needs `link()`, which litebox's shim does not implement, and its
`-nolock` escape hatch requires guest uid 0, which litebox guests
deliberately never have -- see the README for the full story.)
"""
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
BOXER = os.path.join(HERE, "..", "..", "target", "release", "boxer")
OUT_DIR = os.path.join(HERE, "images")

# `boxer build --archive` (no --platform) targets the host platform by
# default and refuses an archive whose declared config.json architecture
# doesn't match it (litebox_packager::oci::verify_config_architecture). So
# the guest binaries and the OCI architecture baked into each box must both
# track whatever machine is actually running this script -- x86_64 Linux or
# Apple Silicon macOS (the only two `boxer run` natively supports).
_HOST_MACHINE = platform.machine()
if _HOST_MACHINE in ("arm64", "aarch64"):
    RUST_TARGET = "aarch64-unknown-linux-musl"
    OCI_ARCH = "arm64"
elif _HOST_MACHINE in ("x86_64", "amd64"):
    RUST_TARGET = "x86_64-unknown-linux-musl"
    OCI_ARCH = "amd64"
else:
    sys.exit(f"unsupported host architecture {_HOST_MACHINE!r}: boxer runs natively on x86_64 Linux and aarch64 macOS only")


def copy_real(src, dst):
    """Copy a file, dereferencing symlinks, preserving the executable bit."""
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    real = os.path.realpath(src)
    shutil.copyfile(real, dst)
    os.chmod(dst, os.stat(real).st_mode)


def write_box_archive(rootfs_dir, entrypoint, cmd, env, exposed_ports, out_archive_dir):
    os.makedirs(out_archive_dir, exist_ok=True)
    layer_path = os.path.join(out_archive_dir, "layer.tar")
    with tarfile.open(layer_path, "w") as tar:
        tar.add(rootfs_dir, arcname=".")
    with open(layer_path, "rb") as f:
        diff_id = "sha256:" + hashlib.sha256(f.read()).hexdigest()

    config = {
        "architecture": OCI_ARCH,
        "os": "linux",
        "config": {
            "Env": env,
            "Entrypoint": entrypoint,
            "Cmd": cmd,
            "WorkingDir": "/",
            "ExposedPorts": {p: {} for p in exposed_ports},
        },
        "rootfs": {"type": "layers", "diff_ids": [diff_id]},
        "history": [{"created_by": "build-images.py"}],
    }
    with open(os.path.join(out_archive_dir, "config.json"), "w") as f:
        json.dump(config, f)

    manifest = [{"Config": "config.json", "RepoTags": [], "Layers": ["layer.tar"]}]
    with open(os.path.join(out_archive_dir, "manifest.json"), "w") as f:
        json.dump(manifest, f)


def build_box(archive_dir, output_box):
    subprocess.run([BOXER, "build", "--archive", archive_dir, "-o", output_box, "-v"], check=True)


# ELF header offsets (64-bit, little-endian), enough to read e_type without a
# parsing dependency.
_ELF_TYPE_OFFSET = 16
_ET_EXEC = 2
_ET_DYN = 3
# An arm64 Mach-O process reserves [0, 4 GiB) as __PAGEZERO, so this is the
# lowest address a guest mapping can occupy on macOS ARM
# (MacOsUserland's TASK_ADDR_MIN).
_MACOS_TASK_ADDR_MIN = 0x1_0000_0000


def check_loadable(path):
    """Refuse a guest binary macOS ARM could never map.

    A non-PIE ET_EXEC has to load at its recorded p_vaddr. Static musl links
    those low (0x400000 and friends), which is inside macOS's __PAGEZERO --
    the mapping is refused with BelowMinAddress and the guest dies as
    "failed to load the ELF file: Memory mapping error: EPERM", naming
    neither the address nor the fix. Linux has no such floor, so the same
    binary loads there and the problem only shows up on a Mac.

    This project's own .cargo/config.toml already forces a genuinely
    self-relocating static-PIE build for this target (see its comment, and
    litebox_platform_macos_userland/scripts/aarch64-musl-static-pie-linker.sh
    for why a plain `-C link-args=-static-pie` alone is not enough -- it gets
    the ET_DYN file type right while still linking the wrong, non-self-
    relocating crt1.o, which then segfaults at guest startup instead of
    failing the check below). A binary reaching this check as ET_EXEC means
    something bypassed that config -- most commonly a
    CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER env var, which overrides
    it.
    """
    with open(path, "rb") as f:
        header = f.read(18)
    if len(header) < 18 or header[:4] != b"\x7fELF":
        sys.exit(f"{path} is not an ELF file")
    e_type = int.from_bytes(header[_ELF_TYPE_OFFSET:_ELF_TYPE_OFFSET + 2], "little")
    if e_type == _ET_DYN:
        return
    if e_type != _ET_EXEC:
        sys.exit(f"{path}: unexpected ELF type {e_type}; expected a PIE (ET_DYN)")
    if OCI_ARCH != "arm64":
        # Linux has no __PAGEZERO floor, so a fixed low load address is fine.
        return
    sys.exit(
        f"{path} is a non-PIE executable (ET_EXEC), which macOS ARM cannot load:\n"
        f"  a fixed load address below {_MACOS_TASK_ADDR_MIN:#x} lands in the 4 GiB\n"
        f"  __PAGEZERO an arm64 Mach-O process reserves, and the guest fails with\n"
        f'  "failed to load the ELF file: Memory mapping error: EPERM".\n'
        f"A plain `cargo build --release --target {RUST_TARGET}` should already\n"
        f"produce a static-PIE binary via this directory's own .cargo/config.toml --\n"
        f"if you got ET_EXEC anyway, check for a\n"
        f"CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER env var overriding it\n"
        f"(see docs/macos.md's __PAGEZERO section)."
    )


def check_no_linker_override():
    """A CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER env var silently wins
    over this directory's own .cargo/config.toml `linker =` setting -- Cargo
    always prefers the env var over a config file, undocumented in a way
    that's easy to miss -- bypassing
    aarch64-musl-static-pie-linker.sh's crt1.o -> rcrt1.o substitution.

    This is a *worse* failure than the ET_EXEC case check_loadable() already
    catches: the resulting binary still links and still reports ET_DYN
    ("static-pie linked", `-C link-args=-static-pie` alone is unaffected by
    which linker ends up invoked), so nothing in this pipeline's own checks
    flags it -- but it silently keeps the non-self-relocating crt1.o musl
    startup object, and the guest segfaults inside musl's own environ/argv
    setup the instant it runs. Confirmed on real Apple Silicon hardware by
    disassembling the actual linked entry point: with the env var set, `b
    _start_c` in `_start` resolves to code whose first instruction is `mov
    x2, x0` (crt1.o's non-relocating `_start_c`); with it unset, the same
    symbol resolves to `mov x3, x0` (rcrt1.o's real, self-relocating
    `_start_c`) -- see docs/roadmap.md's guest-thread-pointer item history.
    """
    var = "CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER"
    value = os.environ.get(var)
    if value is None or os.path.basename(value) == "aarch64-musl-static-pie-linker.sh":
        return
    sys.exit(
        f"{var}={value!r} is set in this environment and overrides this\n"
        f"directory's own .cargo/config.toml linker setting (Cargo always\n"
        f"prefers the env var over a config file) -- the guest binaries were\n"
        f"almost certainly built with the wrong, non-self-relocating crt1.o.\n"
        f"The resulting ELF still reports as a valid static-PIE (ET_DYN), so\n"
        f"nothing else in this pipeline catches it, but the guest will\n"
        f"segfault inside musl's own environ/argv setup the instant it runs.\n"
        f"Fix: unset {var} (or point it at\n"
        f"litebox_platform_macos_userland/scripts/aarch64-musl-static-pie-linker.sh)\n"
        f"and rebuild: `env -u {var} cargo build --release --target {RUST_TARGET}`."
    )


def build_static_bin_box(binary_name, out_name, env, exposed_ports):
    target_bin = os.path.join(HERE, "target", RUST_TARGET, "release", binary_name)
    if not os.path.exists(target_bin):
        sys.exit(f"missing {target_bin}; run cargo build --release --target {RUST_TARGET} first")
    check_loadable(target_bin)
    with tempfile.TemporaryDirectory() as tmp:
        rootfs = os.path.join(tmp, "rootfs")
        os.makedirs(rootfs + "/bin", exist_ok=True)
        copy_real(target_bin, rootfs + f"/bin/{binary_name}")

        archive_dir = os.path.join(tmp, "archive")
        write_box_archive(
            rootfs,
            entrypoint=[f"/bin/{binary_name}"],
            cmd=[],
            env=env,
            exposed_ports=exposed_ports,
            out_archive_dir=archive_dir,
        )
        os.makedirs(OUT_DIR, exist_ok=True)
        build_box(archive_dir, os.path.join(OUT_DIR, out_name))


if __name__ == "__main__":
    if OCI_ARCH == "arm64":
        check_no_linker_override()
    # DISPLAY/BIND_IP are deliberately NOT baked in here -- they depend on
    # the composition's topology (which subnet each instance lands on),
    # which only `boxer compose` knows. It injects them at spawn time via
    # -e, resolving ${instance.guest_ip} templates from compose.json. Only
    # topology-independent settings are baked into the image itself.
    print("Building x11server.box.wasm ...")
    build_static_bin_box("x11-server", "x11server.box.wasm", ["SCREEN_WIDTH=160", "SCREEN_HEIGHT=120"], ["6000/tcp"])
    print("Building app.box.wasm ...")
    build_static_bin_box("x11-app", "app.box.wasm", [], [])
    print("Building vncbridge.box.wasm ...")
    build_static_bin_box("vnc-bridge", "vncbridge.box.wasm", [], ["5900/tcp"])
    print("Building graphics_demo.box.wasm ...")
    build_static_bin_box("graphics-demo", "graphics_demo.box.wasm", [], ["5900/tcp"])
    print("Done:", OUT_DIR)
