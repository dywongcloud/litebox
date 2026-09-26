# alpine-hvf-desktop-chromium-152.0.7977.64-r0-gpu-seccomp-pwritev2-fix

Targeted-swap manifest variant for PRD rows `chromium-gpu-process-seccomp-crashsigsys-nr-0x11f-exit-11`
and `chromium-gpu-seccomp-pwritev2-gpu-policy-patch-scoped-rebuild`. Structural precedent:
`../alpine-hvf-desktop-busybox-1.38.0-r6/`.

This directory does NOT replace or modify the canonical `alpine-hvf-desktop/` manifest or the
canonical `/tmp/litebox-hvf-desktop-canonical.tar` (verified byte-identical, sha256
`e5863408642ce05691b978ae9bb29558f0beb6c050fe599e9e9aafedb4adc2c7`, before and after this wave).

- `manifest.json` -- full package-provenance record (canonical's 276 packages, 3 updated) plus a
  `chromium_gpu_seccomp_pwritev2_fix` block with the exact patch diff, remote build provenance,
  and the list of 17 swapped files with old/new size+sha256.
- `apks/` -- the 3 newly built Alpine packages actually used (chromium, chromium-common,
  chromium-angle), retrieved from the remote build host's durable "chromiumbuild" podman container.
- `build-gpu-seccomp-fix-tar.py` -- the exact script used to produce the output tar: a surgical
  splice of the canonical tar's 7234 entries, swapping content for only the 17 files under
  `usr/lib/chromium/` that the new packages provide (metadata kept from the canonical entry,
  including chrome-sandbox's setuid 04755 bit). NOT `build-hvf-desktop-image.sh`'s apk-add
  rootfs rebuild -- see `manifest.json`'s own `source.rebuild_note` for why.

Output tar: `/tmp/litebox-hvf-desktop-gpu-seccomp-fix.tar` (not checked into this directory --
same convention as the canonical tar living outside its manifest dir).
