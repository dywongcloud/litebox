// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

'use strict';

const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');
const { revDir, ensureDir } = require('./cache');

const TARBALL = (rev) => `https://codeload.github.com/dywongcloud/litebox/tar.gz/${rev}`;

/// A marker written only after extraction fully succeeds, so an interrupted
/// download can never be mistaken for a usable tree on the next run.
const STAMP = '.litebox-source-complete';

/// Resolve the source tree to build from.
///
/// `LITEBOX_SRC` short-circuits everything and points at a working checkout.
/// That exists for two reasons: developing this package without a network round
/// trip, and letting someone build a revision other than the pinned one without
/// republishing.
async function resolveSource(rev, log) {
  if (process.env.LITEBOX_SRC) {
    const local = path.resolve(process.env.LITEBOX_SRC);
    if (!fs.existsSync(path.join(local, 'Cargo.toml'))) {
      throw new Error(`LITEBOX_SRC=${local} does not look like a litebox checkout (no Cargo.toml).`);
    }
    log(`using local source tree: ${local}`);
    return local;
  }

  const dest = path.join(revDir(rev), 'src');
  if (fs.existsSync(path.join(dest, STAMP))) return dest;

  ensureDir(path.dirname(dest));
  const url = TARBALL(rev);
  log(`downloading source ${rev.slice(0, 12)} ...`);

  const res = await fetch(url);
  if (!res.ok) {
    throw new Error(`could not download source from ${url} (HTTP ${res.status}).`);
  }
  const tarPath = path.join(revDir(rev), 'source.tar.gz');
  fs.writeFileSync(tarPath, Buffer.from(await res.arrayBuffer()));

  // Extract into a staging directory first, then rename: a half-extracted tree
  // that happens to contain Cargo.toml would otherwise look buildable.
  const staging = path.join(revDir(rev), 'src.partial');
  fs.rmSync(staging, { recursive: true, force: true });
  ensureDir(staging);

  // `tar` is present on macOS and Linux, and Windows 10+ ships bsdtar as
  // `tar.exe`. `--strip-components=1` drops GitHub's `<repo>-<sha>/` wrapper.
  const untar = spawnSync('tar', ['-xzf', tarPath, '--strip-components=1', '-C', staging], {
    stdio: 'inherit',
  });
  if (untar.error || untar.status !== 0) {
    throw new Error(
      'could not extract the source archive. A `tar` command is required ' +
        '(present by default on macOS, Linux, and Windows 10 and later).'
    );
  }
  fs.writeFileSync(path.join(staging, STAMP), rev);
  fs.rmSync(dest, { recursive: true, force: true });
  fs.renameSync(staging, dest);
  fs.rmSync(tarPath, { force: true });
  return dest;
}

module.exports = { resolveSource };
