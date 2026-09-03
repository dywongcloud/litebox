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


def build_static_bin_box(binary_name, out_name, env, exposed_ports):
    target_bin = os.path.join(HERE, "target", RUST_TARGET, "release", binary_name)
    if not os.path.exists(target_bin):
        sys.exit(f"missing {target_bin}; run cargo build --release --target {RUST_TARGET} first")
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
