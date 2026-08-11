// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { spawnSync } = require('child_process');
const { revDir, ensureDir } = require('./cache');

/// Docker Hub's anonymous-pull endpoint is not reachable from every network, and
/// the packager supports only public registries, so the default points at the
/// AWS public mirror of the same image.
const DEFAULT_IMAGE = 'public.ecr.aws/docker/library/alpine:latest';

/// Public mirrors rate-limit anonymous pulls per client, and a first run that
/// happens to land inside a limit window is otherwise indistinguishable from a
/// broken install. Retrying is correct here specifically because the failure is
/// transient and the request is idempotent; the cap keeps a genuinely blocked
/// network from hanging the command.
const PULL_ATTEMPTS = 3;
const BACKOFF_MS = [4000, 12000];

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function looksRateLimited(text) {
  return /rate exceeded|too many requests|\b429\b|toomanyrequests/i.test(text || '');
}

/// Package a guest root filesystem, caching per (revision, image reference).
///
/// The packager rewrites every executable ELF in the image for this host's
/// syscall-gate flavour, so a packaged tar is specific to the revision that
/// produced it and must not be shared across revisions.
async function ensureImage({ rev, packager, image, refresh, log }) {
  const imagesDir = ensureDir(path.join(revDir(rev), 'images'));
  const key = crypto.createHash('sha256').update(image).digest('hex').slice(0, 16);
  const tarPath = path.join(imagesDir, `${key}.tar`);

  if (!refresh && fs.existsSync(tarPath)) {
    log(`using cached guest image (${image})`);
    return tarPath;
  }

  log(`packaging guest image ${image} (first time for this image)`);
  const partial = tarPath + '.partial';
  let lastOutput = '';

  for (let attempt = 1; attempt <= PULL_ATTEMPTS; attempt++) {
    fs.rmSync(partial, { force: true });
    // Captured rather than inherited so the rate-limit case can be recognised
    // and explained; the packager's own output is echoed on the final failure.
    const res = spawnSync(packager, ['--oci-image', image, '-o', partial], { encoding: 'utf8' });
    if (!res.error && res.status === 0) {
      fs.renameSync(partial, tarPath);
      return tarPath;
    }
    lastOutput = `${res.stdout || ''}${res.stderr || ''}${res.error ? res.error.message : ''}`;
    if (attempt < PULL_ATTEMPTS && looksRateLimited(lastOutput)) {
      const wait = BACKOFF_MS[attempt - 1];
      log(`registry rate-limited the pull; retrying in ${wait / 1000}s (${attempt}/${PULL_ATTEMPTS - 1})`);
      await sleep(wait);
      continue;
    }
    break;
  }

  fs.rmSync(partial, { force: true });
  const rateLimited = looksRateLimited(lastOutput);
  throw new Error(
    `could not package the guest image "${image}".\n\n` +
      lastOutput.trim() +
      '\n\n' +
      (rateLimited
        ? 'The registry rate-limited anonymous pulls, which is transient and not a\n' +
          'problem with your install. The build is already cached, so simply running the\n' +
          'command again in a minute usually succeeds. You can also pass a different\n' +
          'image with --image.'
        : 'Only public registries are supported, and network access is required the first\n' +
          'time an image is used. Docker Hub anonymous pulls are blocked on some networks;\n' +
          `the default (${DEFAULT_IMAGE}) is a public mirror that usually works.`)
  );
}

module.exports = { ensureImage, DEFAULT_IMAGE };
