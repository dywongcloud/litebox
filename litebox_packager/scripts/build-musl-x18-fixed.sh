#! /bin/bash

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

# Rebuilds Alpine's musl package with `-ffixed-x18` and populates
# litebox_packager's content-addressed cache (see `src/musl_x18.rs`) so a
# subsequent `litebox_packager --oci-image ...` run targeting a macOS host
# picks up the fix automatically -- no manual file swapping.
#
# Why this is needed at all: XNU zeroes the AArch64 platform register `x18`
# on every return to EL0. musl's dynamic linker holds a live value in `x18`
# across exactly that kind of boundary during its own relocation bootstrap,
# so an ordinary Alpine musl (built assuming Linux's ABI, where `x18` is a
# ordinary allocatable register) reliably crashes early under LiteBox on
# macOS. See `docs/roadmap.md`'s "XNU destroys a live guest x18" section for
# the full measured root cause.
#
# This rebuilds the *exact* Alpine `musl` package (same upstream source
# tarball, same `handle-aux-at_base.patch`/CVE patches, same package
# metadata) via the real `aports` `APKBUILD`, adding only `-ffixed-x18` to
# `CFLAGS` -- not a from-scratch or hand-patched musl, so the result stays a
# faithful match for whatever Alpine version it targets.
#
# Usage: build-musl-x18-fixed.sh [ALPINE_BRANCH] [CACHE_DIR]
#   ALPINE_BRANCH  aports git branch to build against (default: 3.24-stable).
#                  Must match the Alpine version of the image(s) being
#                  packaged -- musl's ABI is stable across an Alpine version
#                  but not guaranteed across major bumps.
#   CACHE_DIR      where to write the result, keyed by the stock musl's own
#                  content hash (default: ~/.cache/litebox/musl-x18-fixed,
#                  matching src/musl_x18.rs's own default; override both the
#                  same way via LITEBOX_MUSL_X18_CACHE if you use a custom
#                  cache location).

set -eo pipefail

RED="\033[0;31m"
YELLOW="\033[0;33m"
GREEN="\033[0;32m"
BOLD="\033[1m"
RESET="\033[0m"

fatal() { echo -e "${RED}${BOLD}[!]${RESET} $1" 1>&2; exit 1; }
warn()  { echo -e "${YELLOW}${BOLD}[!]${RESET} $1" 1>&2; }
info()  { echo -e "${BOLD}[i]${RESET} $1" 1>&2; }
info2() { echo -e "      $1" 1>&2; }
success() { echo -e "${GREEN}${BOLD}[+]${RESET} $1" 1>&2; }

ALPINE_BRANCH="${1:-3.24-stable}"
# aports branches are named "<major.minor>-stable"; the matching Docker Hub
# tag drops the "-stable" suffix.
ALPINE_TAG="${ALPINE_BRANCH%-stable}"
CACHE_DIR="${2:-${LITEBOX_MUSL_X18_CACHE:-$HOME/.cache/litebox/musl-x18-fixed}}"

CONTAINER_ENGINE=""
for candidate in podman docker; do
    if command -v "$candidate" &> /dev/null; then
        CONTAINER_ENGINE="$candidate"
        break
    fi
done
[ -n "$CONTAINER_ENGINE" ] || fatal "Requires podman or docker; neither found on PATH"

info "Using ${BOLD}${CONTAINER_ENGINE}${RESET} against Alpine ${BOLD}${ALPINE_TAG}${RESET} (aports ${ALPINE_BRANCH})"

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

BASE_IMAGE="public.ecr.aws/docker/library/alpine:${ALPINE_TAG}"
BUILD_CONTAINER="litebox-musl-x18-build-$$"

cleanup_container() {
    "$CONTAINER_ENGINE" rm -f "$BUILD_CONTAINER" &> /dev/null || true
}
trap 'cleanup_container; rm -rf "$WORKDIR"' EXIT

# --- Step 1: the stock musl's content hash is the cache key. Extracted from
# the same base image litebox_packager's own --oci-image example targets, so
# it matches what a real packaging run will hash. ---
info "Reading the stock musl from ${BASE_IMAGE} to derive the cache key..."
"$CONTAINER_ENGINE" run --rm --platform linux/arm64 "$BASE_IMAGE" \
    cat /lib/ld-musl-aarch64.so.1 > "$WORKDIR/stock-ld-musl-aarch64.so.1"
[ -s "$WORKDIR/stock-ld-musl-aarch64.so.1" ] || fatal "failed to read stock musl from $BASE_IMAGE"
STOCK_HASH="$(shasum -a 256 "$WORKDIR/stock-ld-musl-aarch64.so.1" | cut -d' ' -f1)"
info "Stock musl content hash (cache key): ${BOLD}${STOCK_HASH}${RESET}"

# --- Step 2: rebuild musl with -ffixed-x18 via the real Alpine APKBUILD. ---
info "Building musl with -ffixed-x18 (this runs a real compile, ~1 minute)..."
"$CONTAINER_ENGINE" run -d --name "$BUILD_CONTAINER" --platform linux/arm64 "$BASE_IMAGE" sleep 3600 > /dev/null

"$CONTAINER_ENGINE" exec "$BUILD_CONTAINER" sh -c '
    set -e
    apk add --no-cache alpine-sdk git doas > /dev/null 2>&1
    adduser -D builder
    addgroup builder abuild
    echo "permit nopass builder" > /etc/doas.d/doas.conf
    mkdir -p /home/builder
    chown -R builder:builder /home/builder
    su -s /bin/sh builder -c "cd /home/builder && abuild-keygen -a -i -n" > /dev/null 2>&1
    su -s /bin/sh builder -c "git clone --depth 1 --branch '"$ALPINE_BRANCH"' https://gitlab.alpinelinux.org/alpine/aports.git /home/builder/aports" > /dev/null 2>&1
    su -s /bin/sh builder -c "cd /home/builder/aports/main/musl && CFLAGS=-ffixed-x18 abuild -r"
' || fatal "musl rebuild failed -- see the container output above"

"$CONTAINER_ENGINE" exec "$BUILD_CONTAINER" sh -c '
    set -e
    mkdir -p /tmp/musl-extract
    apk_path="$(find /home/builder/packages -name "musl-*.apk" ! -name "musl-dev-*" ! -name "musl-dbg-*" ! -name "musl-utils-*" ! -name "musl-libintl-*")"
    tar -xzf "$apk_path" -C /tmp/musl-extract
' || fatal "failed to extract the built musl package"

# --- Step 3: pull the patched .so back out and populate the cache. ---
"$CONTAINER_ENGINE" cp "$BUILD_CONTAINER:/tmp/musl-extract/lib/ld-musl-aarch64.so.1" \
    "$WORKDIR/patched-ld-musl-aarch64.so.1"
[ -s "$WORKDIR/patched-ld-musl-aarch64.so.1" ] || fatal "failed to copy the built musl out of the container"

mkdir -p "$CACHE_DIR"
CACHE_ENTRY="$CACHE_DIR/${STOCK_HASH}.so"
cp "$WORKDIR/patched-ld-musl-aarch64.so.1" "$CACHE_ENTRY"

success "Wrote ${BOLD}${CACHE_ENTRY}${RESET}"
info2 "The next 'litebox_packager --oci-image <alpine-${ALPINE_TAG}-based image>' run"
info2 "targeting a macOS host will pick this up automatically."
