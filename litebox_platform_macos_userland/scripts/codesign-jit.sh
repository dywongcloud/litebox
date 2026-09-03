#! /bin/bash

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

# Ad-hoc code-sign a binary with the JIT entitlement this platform's
# `MAP_JIT` mappings need on Apple Silicon.
#
# Every executable guest mapping goes through `MAP_JIT` (see the crate's
# module docs on W^X), and on Apple Silicon the kernel refuses `MAP_JIT` to a
# process whose signature lacks `com.apple.security.cs.allow-jit` -- the guest
# then dies at load time with "Memory mapping error / EPERM: Operation not
# permitted".
#
# `cargo build` writes a fresh, unsigned binary every time, which drops the
# signature, so this has to run after each build -- not once at setup.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENTITLEMENTS="$HERE/litebox.entitlements"

if [ "$#" -eq 0 ]; then
    echo "Usage: $0 <binary> [binary ...]" 1>&2
    echo "  e.g. $0 target/release/boxer" 1>&2
    exit 2
fi

if [ "$(uname -s)" != "Darwin" ]; then
    echo "error: this script only applies to macOS hosts (uname -s is $(uname -s))" 1>&2
    exit 1
fi

for binary in "$@"; do
    if [ ! -f "$binary" ]; then
        echo "error: no such file: $binary" 1>&2
        exit 1
    fi
    codesign --sign - --entitlements "$ENTITLEMENTS" --force "$binary"
    echo "signed $binary with com.apple.security.cs.allow-jit"
done
