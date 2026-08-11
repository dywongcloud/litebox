// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

'use strict';

/// The commit this package builds. Pinned rather than tracking a branch so a
/// given npm version always produces the same binaries.
const PINNED_REV = '497433858b0f8c52ea335df3576afb3e23e3a2e3';

/// Which runner crate serves a Linux guest on each host OS.
///
/// LiteBox is a syscall-translation layer, not an instruction emulator: guest
/// instructions execute natively. The guest architecture is therefore always the
/// host architecture, and a host/guest arch mismatch is not something a runner
/// can paper over.
const RUNNERS = {
  darwin: 'litebox_runner_linux_on_macos_userland',
  linux: 'litebox_runner_linux_userland',
  win32: 'litebox_runner_linux_on_windows_userland',
};

/// Support status per (os, arch), stated at the level it has actually been
/// verified rather than at the level the crate list implies.
///
/// `verified` means a real guest was run on that exact host and arch and its
/// output observed. `builds-unverified` means the runner crate exists and is
/// expected to compile, but no guest has been run there by this package's
/// authors -- it may work, and it may not. Being honest here is the difference
/// between a user filing a useful bug and concluding the whole thing is broken.
const SUPPORT = {
  'darwin/arm64': { status: 'verified', note: 'Apple Silicon; developed and tested here.' },
  'darwin/x64': {
    status: 'builds-unverified',
    note: 'Intel Mac. The macOS platform is aarch64-only in places; expect build or runtime failures.',
  },
  'linux/x64': { status: 'builds-unverified', note: 'Two known-failing tests in this crate upstream.' },
  'linux/arm64': { status: 'builds-unverified', note: 'Two known-failing tests in this crate upstream.' },
  'win32/x64': {
    status: 'builds-unverified',
    note: 'Guest networking is an unimplemented stub on Windows, and console input is incomplete.',
  },
  'win32/arm64': {
    status: 'builds-unverified',
    note: 'Guest networking is an unimplemented stub on Windows, and console input is incomplete.',
  },
};

function detect() {
  const os = process.platform;
  const arch = process.arch;
  const key = `${os}/${arch}`;
  const runner = RUNNERS[os];
  return {
    os,
    arch,
    key,
    runner,
    supported: Boolean(runner),
    support: SUPPORT[key] || { status: 'unknown', note: 'No support information recorded.' },
    /// Only macOS needs the guest's executable pages signed for JIT: Darwin
    /// enforces W^X, so the runner maps guest code `MAP_JIT` and must carry the
    /// `com.apple.security.cs.allow-jit` entitlement to write to it.
    needsJitCodesign: os === 'darwin',
    exeSuffix: os === 'win32' ? '.exe' : '',
  };
}

module.exports = { detect, PINNED_REV, RUNNERS, SUPPORT };
