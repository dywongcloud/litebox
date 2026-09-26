#!/bin/sh
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.
#
# Builds the two cf-02-seccomp-production-attester guest binaries (attester_guest, exec_child)
# following litebox-guest-test-binary-recipe exactly: no_std/no_main/crt-free static-PIE,
# compiled to a bare object then linked by hand (rustc keeps adding crt1.o otherwise, and
# -nostartfiles is a cc-driver flag lld rejects), targeting aarch64-unknown-linux-musl. Under
# --hvf (stock SVC path, real EL1 monitor) no litebox_packager rewrite pass is needed -- a raw
# static-PIE runs as-is. Then packages both plus a writable /tmp into one minimal ustar tar (not
# PAX -- macOS bsdtar's default PAX headers make the runner's tar loader skip entries).
#
# Usage: build.sh <output-dir>
# Produces: <output-dir>/attester_guest, <output-dir>/exec_child, <output-dir>/seccomp-attester.tar

set -eu

HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="${1:?usage: build.sh <output-dir>}"
mkdir -p "$OUT"

RUSTLLD="${RUSTLLD:-}"
if [ -z "$RUSTLLD" ]; then
    # The active/default toolchain's own `rust-lld` can be broken on this host (dyld:
    # `@rpath/libLLVM.dylib` not loaded -- litebox-guest-test-binary-recipe's own 2026-09-05
    # addendum, live-reproduced again while building this very tool). Prefer a pinned-version
    # toolchain known to work, falling back to the active one only if that pin is absent. Checked
    # by existence only (not a `--version` probe): lld's own "generic driver" mode -- entered
    # whenever a flavor isn't yet pinned -- exits non-zero-ish unpredictably across invocations,
    # which is irrelevant here since every real invocation below always passes `-flavor gnu`.
    PINNED="$HOME/.rustup/toolchains/1.97.0-aarch64-apple-darwin/lib/rustlib/aarch64-apple-darwin/bin/rust-lld"
    if [ -x "$PINNED" ]; then
        RUSTLLD="$PINNED"
    else
        RUSTLLD="$(rustc --print sysroot)/lib/rustlib/aarch64-apple-darwin/bin/rust-lld"
    fi
fi
if [ ! -x "$RUSTLLD" ]; then
    echo "build.sh: no working rust-lld found at $RUSTLLD (pass RUSTLLD=... to override)" >&2
    exit 1
fi

SYSROOT="$(rustc --print sysroot)"
TARGET_LIB="$SYSROOT/lib/rustlib/aarch64-unknown-linux-musl/lib"
CORE_RLIB="$(ls "$TARGET_LIB"/libcore-*.rlib | head -1)"
COMPILER_BUILTINS_RLIB="$(ls "$TARGET_LIB"/libcompiler_builtins-*.rlib | head -1)"
if [ ! -f "$CORE_RLIB" ] || [ ! -f "$COMPILER_BUILTINS_RLIB" ]; then
    echo "build.sh: missing prebuilt core/compiler_builtins rlibs under $TARGET_LIB" >&2
    echo "build.sh: run: rustup target add aarch64-unknown-linux-musl" >&2
    exit 1
fi

for NAME in attester_guest exec_child; do
    rustc --edition 2021 --target aarch64-unknown-linux-musl \
        -C relocation-model=pic -C panic=abort -O \
        --emit=obj "$HERE/$NAME.rs" -o "$OUT/$NAME.o"
    # `rustc --emit=obj` compiles only this one crate; `core`'s own generic Display/fmt/memcpy/
    # bounds-check machinery it calls into comes from the target's prebuilt rlibs (plain `ar`
    # archives -- lld pulls in only the object members an undefined symbol actually needs).
    "$RUSTLLD" -flavor gnu -pie --gc-sections -o "$OUT/$NAME" "$OUT/$NAME.o" \
        "$CORE_RLIB" "$COMPILER_BUILTINS_RLIB"
    chmod 755 "$OUT/$NAME"
done

STAGE="$OUT/tar-stage"
rm -rf "$STAGE"
mkdir -p "$STAGE/tmp"
chmod 1777 "$STAGE/tmp"
cp "$OUT/attester_guest" "$STAGE/attester_guest"
cp "$OUT/exec_child" "$STAGE/exec_child"
chmod 755 "$STAGE/attester_guest" "$STAGE/exec_child"

TAR_OUT="$OUT/seccomp-attester.tar"
rm -f "$TAR_OUT"
( cd "$STAGE" && COPYFILE_DISABLE=1 tar --format ustar --no-mac-metadata -cf "$TAR_OUT" tmp attester_guest exec_child )

echo "built: $OUT/attester_guest"
echo "built: $OUT/exec_child"
echo "packaged: $TAR_OUT"
