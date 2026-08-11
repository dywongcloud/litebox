// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

'use strict';

const os = require('os');
const path = require('path');
const fs = require('fs');

/// Everything this package produces is derived, reproducible from `PINNED_REV`,
/// and potentially large (a Rust target directory and packaged guest images), so
/// it belongs in a cache directory rather than beside the installed module: an
/// `npx` invocation may install into a throwaway directory, and re-downloading
/// and rebuilding on every run would make the tool unusable.
function cacheRoot() {
  if (process.env.LITEBOX_CACHE_DIR) return path.resolve(process.env.LITEBOX_CACHE_DIR);
  if (process.platform === 'win32') {
    return path.join(process.env.LOCALAPPDATA || path.join(os.homedir(), 'AppData', 'Local'), 'litebox');
  }
  if (process.platform === 'darwin') {
    return path.join(os.homedir(), 'Library', 'Caches', 'litebox');
  }
  return path.join(process.env.XDG_CACHE_HOME || path.join(os.homedir(), '.cache'), 'litebox');
}

/// Keyed by revision so a package upgrade never silently reuses binaries built
/// from a different source tree.
function revDir(rev) {
  return path.join(cacheRoot(), rev);
}

function ensureDir(p) {
  fs.mkdirSync(p, { recursive: true });
  return p;
}

module.exports = { cacheRoot, revDir, ensureDir };
