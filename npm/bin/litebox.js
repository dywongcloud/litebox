#!/usr/bin/env node
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

'use strict';

const { spawn } = require('child_process');
const { detect, PINNED_REV } = require('../lib/platform');
const { resolveSource } = require('../lib/source');
const { buildBinaries } = require('../lib/build');
const { ensureImage, DEFAULT_IMAGE } = require('../lib/image');
const { revDir } = require('../lib/cache');

const USAGE = `litebox -- boot an interactive Linux shell inside LiteBox

Usage:
  npx @openclew/litebox [options] [-- <program> [args...]]

Options:
  --image <ref>     Guest OCI image (default: ${DEFAULT_IMAGE})
  --shell <path>    Guest shell to start (default: /bin/busybox sh)
  --rev <sha>       Build a specific source revision (default: pinned)
  --rebuild         Rebuild the binaries even if cached
  --refresh-image   Re-package the guest image even if cached
  --where           Print the cache directory and exit
  -q, --quiet       Suppress progress output
  -h, --help        Show this help
  -V, --version     Show version

Examples:
  npx @openclew/litebox                      # interactive shell
  npx @openclew/litebox -- /bin/busybox uname -a
  npx @openclew/litebox --image public.ecr.aws/docker/library/node:alpine

First run downloads a pinned source revision and builds it with cargo, which
takes a few minutes. Later runs reuse the cache. A Rust toolchain is required.
`;

function parseArgs(argv) {
  const opts = {
    image: DEFAULT_IMAGE,
    shell: null,
    rev: PINNED_REV,
    rebuild: false,
    refreshImage: false,
    quiet: false,
    where: false,
    command: null,
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--') {
      opts.command = argv.slice(i + 1);
      break;
    } else if (a === '--image') opts.image = argv[++i];
    else if (a === '--shell') opts.shell = argv[++i];
    else if (a === '--rev') {
      const rev = argv[++i];
      if (!/^[0-9a-f]{40}$/i.test(rev || '')) {
        return { error: '--rev requires a full 40-character hexadecimal commit SHA.' };
      }
      opts.rev = rev.toLowerCase();
    }
    else if (a === '--rebuild') opts.rebuild = true;
    else if (a === '--refresh-image') opts.refreshImage = true;
    else if (a === '--where') opts.where = true;
    else if (a === '-q' || a === '--quiet') opts.quiet = true;
    else if (a === '-h' || a === '--help') {
      process.stdout.write(USAGE);
      process.exit(0);
    } else if (a === '-V' || a === '--version') {
      process.stdout.write(`${require('../package.json').version}\n`);
      process.exit(0);
    } else {
      throw new Error(`unknown option: ${a}\n\n${USAGE}`);
    }
  }
  if (opts.command && opts.command.length === 0) opts.command = null;
  return opts;
}

async function main() {
  const opts = parseArgs(process.argv.slice(2));
  if (opts.error) {
    process.stderr.write(`litebox: ${opts.error}\n`);
    return 1;
  }
  const plat = detect();

  if (opts.where) {
    process.stdout.write(revDir(opts.rev) + '\n');
    return 0;
  }

  // Progress goes to stderr so `-- <program>` output on stdout stays clean and
  // pipeable on the host side.
  const log = opts.quiet ? () => {} : (m) => process.stderr.write(`litebox: ${m}\n`);

  if (!plat.supported) {
    throw new Error(
      `unsupported host platform: ${plat.os}/${plat.arch}\n` +
        'LiteBox has runners for macOS, Linux and Windows.'
    );
  }
  if (plat.support.status !== 'verified') {
    log(`warning: ${plat.key} is "${plat.support.status}" -- ${plat.support.note}`);
  }

  const srcDir = await resolveSource(opts.rev, log);
  const { runner, packager } = buildBinaries({
    rev: opts.rev,
    srcDir,
    plat,
    rebuild: opts.rebuild,
    log,
  });
  const imageTar = await ensureImage({
    rev: opts.rev,
    packager,
    image: opts.image,
    refresh: opts.refreshImage,
    log,
  });

  const guestArgv = opts.command
    ? opts.command
    : [opts.shell || '/bin/busybox', ...(opts.shell ? [] : ['sh'])];

  if (!opts.command) log(`starting ${guestArgv.join(' ')}`);

  // `inherit` hands the guest the real terminal, which is what makes this an
  // interactive session rather than a pipe: the shim's terminal support reads
  // the host tty directly, including raw mode when the guest asks for it.
  const child = spawn(runner, ['--initial-files', imageTar, '--', ...guestArgv], {
    stdio: 'inherit',
  });

  return await new Promise((resolve) => {
    child.on('error', (e) => {
      process.stderr.write(`litebox: could not start the runner: ${e.message}\n`);
      resolve(70);
    });
    // A guest killed by a signal is reported the way a shell reports it, so
    // `echo $?` after a guest segfault reads the same as it would on Linux.
    child.on('exit', (code, signal) => resolve(signal ? 128 + (require('os').constants.signals[signal] || 0) : code));
  });
}

main().then(
  (code) => process.exit(code),
  (err) => {
    process.stderr.write(`litebox: ${err && err.message ? err.message : err}\n`);
    process.exit(1);
  }
);
