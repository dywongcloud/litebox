// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

'use strict';

const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');
const { revDir, ensureDir } = require('./cache');

const PACKAGER = 'litebox_packager';

function have(cmd) {
  const probe = spawnSync(cmd, ['--version'], { stdio: 'ignore' });
  return !probe.error && probe.status === 0;
}

/// Rust is a hard prerequisite rather than something this package vendors.
///
/// Shipping prebuilt binaries would mean shipping five platform/arch
/// combinations that cannot all be tested; building from a pinned source
/// revision on the user's own machine is the honest alternative, and it costs
/// one dependency the user can see and audit.
function requireToolchain() {
  if (have('cargo') && have('rustc')) return;
  throw new Error(
    'A Rust toolchain is required to build LiteBox.\n\n' +
      '  Install it with:  curl --proto =https --tlsv1.2 -sSf https://sh.rustup.rs | sh\n' +
      '  (Windows: https://rustup.rs)\n\n' +
      'This package builds from a pinned source revision rather than shipping prebuilt\n' +
      'binaries, so that every supported platform runs code built for it on the machine\n' +
      'it will run on.'
  );
}

/// Darwin enforces W^X, so the runner maps guest code `MAP_JIT` and needs the
/// `com.apple.security.cs.allow-jit` entitlement to write to those pages. An
/// ad-hoc signature (`-`) is enough; this is not distribution signing and needs
/// no Apple Developer account.
function codesignForJit(binary, workDir, log) {
  const plist = path.join(workDir, 'litebox.entitlements');
  fs.writeFileSync(
    plist,
    '<?xml version="1.0" encoding="UTF-8"?>\n' +
      '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n' +
      '<plist version="1.0">\n<dict>\n' +
      '    <key>com.apple.security.cs.allow-jit</key>\n    <true/>\n' +
      '</dict>\n</plist>\n'
  );
  const res = spawnSync('codesign', ['--sign', '-', '--entitlements', plist, '--force', binary], {
    encoding: 'utf8',
  });
  if (res.error || res.status !== 0) {
    throw new Error(
      `codesign failed for ${binary}: ${(res.stderr || res.error || '').toString().trim()}\n` +
        'Without the JIT entitlement the guest cannot execute on macOS.'
    );
  }
  log('signed runner with the JIT entitlement');
}

/// Build the runner and packager for this host, caching per revision.
function buildBinaries({ rev, srcDir, plat, rebuild, log }) {
  const outDir = ensureDir(path.join(revDir(rev), 'bin'));
  const runnerOut = path.join(outDir, plat.runner + plat.exeSuffix);
  const packagerOut = path.join(outDir, PACKAGER + plat.exeSuffix);

  if (!rebuild && fs.existsSync(runnerOut) && fs.existsSync(packagerOut)) {
    log('using cached binaries');
    return { runner: runnerOut, packager: packagerOut };
  }

  requireToolchain();
  log(`building ${plat.runner} and ${PACKAGER} (first run; this takes a few minutes)`);

  // A dedicated target directory keeps this out of the user's own build
  // artifacts if they happen to be pointing LITEBOX_SRC at a real checkout.
  const targetDir = path.join(revDir(rev), 'target');
  const res = spawnSync(
    'cargo',
    ['build', '--release', '-p', plat.runner, '-p', PACKAGER, '--target-dir', targetDir],
    { cwd: srcDir, stdio: 'inherit' }
  );
  if (res.error || res.status !== 0) {
    throw new Error(
      `cargo build failed for ${plat.key}.\n` +
        `Support status for this platform is "${plat.support.status}": ${plat.support.note}`
    );
  }

  for (const [built, dest] of [
    [path.join(targetDir, 'release', plat.runner + plat.exeSuffix), runnerOut],
    [path.join(targetDir, 'release', PACKAGER + plat.exeSuffix), packagerOut],
  ]) {
    if (!fs.existsSync(built)) throw new Error(`cargo reported success but ${built} is missing.`);
    fs.copyFileSync(built, dest);
    fs.chmodSync(dest, 0o755);
  }

  if (plat.needsJitCodesign) codesignForJit(runnerOut, revDir(rev), log);
  return { runner: runnerOut, packager: packagerOut };
}

module.exports = { buildBinaries, requireToolchain };
