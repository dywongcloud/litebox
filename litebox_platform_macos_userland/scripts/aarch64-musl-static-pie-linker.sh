#! /bin/bash

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

# A `cargo` `-C linker=` replacement that links an `aarch64-unknown-linux-musl`
# guest binary as static-PIE (`ET_DYN`, self-relocating), for guests that will
# run on this platform.
#
# macOS ARM reserves the first 4 GiB of every process's address space as the
# arm64 Mach-O `__PAGEZERO` segment (see docs/macos.md, "The first 4 GiB is
# unusable") -- permanently unmapped, impossible to map over. A plain
# `cargo build --release --target aarch64-unknown-linux-musl` produces an
# `ET_EXEC` binary linked at the customary low address (`0x400000` on this
# target), which this platform's loader then refuses with
# `AllocationError::BelowMinAddress` (surfaced to the guest as a bare "EPERM:
# Operation not permitted" -- see `litebox_common_linux::errno`) the moment it
# tries to map a segment there. The fix per that doc is: "guest images must be
# position-independent, or linked above 4 GiB" -- this script gets the first.
#
# Combine with `-C link-args=-static-pie` (needed *in addition* to this
# script: it is what actually asks the linker for an `ET_DYN`/`-static-pie`
# output in the first place -- this script alone would still produce an
# `ET_EXEC`, just linked against the wrong startup object). Wire both into
# `.cargo/config.toml`'s `[target.aarch64-unknown-linux-musl]` section rather
# than passing them by hand on every build; see
# examples/multibox-x11-composition/.cargo/config.toml for the reference
# setup this project actually runs.
#
# Rustc's own crt-object selection for this target does not respond to
# `-C relocation-model=pie` (nor `=pic`): verified on this project's toolchain
# (`rustc 1.98.1`, `aarch64-unknown-linux-musl-gcc` 15.2.0 from
# `messense/macos-cross-toolchains`) that both leave `crt1.o` -- the plain,
# non-self-relocating startup object -- in rustc's own `-nostartfiles`-guarded,
# manually-specified link line regardless. `-C link-args=-static-pie` alone
# does make the linker emit `ET_DYN`/`static-pie linked` output (confirmed via
# `file`), but with the *same* wrong `crt1.o` still linked in -- producing a
# binary that LOOKS like static-PIE but crashes immediately (confirmed via
# `lldb`: SIGSEGV inside musl's own environ/argv setup, dereferencing a
# `.bss`-relative pointer that plain `crt1.o`'s `_start` never self-relocated)
# on a REAL, unmodified Linux kernel too (confirmed via `podman run
# --platform linux/arm64`) -- this is a build-toolchain gap, not anything
# platform- or litebox-specific. `rcrt1.o`, present in both this cross
# toolchain's own sysroot and rustc's bundled musl `self-contained/` libs, is
# the startup object that actually self-relocates; substituting it here (the
# one object file that needs to differ) is more robust than hand-assembling
# the rest of rustc's link line, which is subject to change across toolchain
# versions.
args=()
for arg in "$@"; do
    if [[ "$arg" == *"self-contained/crt1.o" ]]; then
        args+=("${arg%crt1.o}rcrt1.o")
    else
        args+=("$arg")
    fi
done
exec aarch64-unknown-linux-musl-gcc "${args[@]}"
