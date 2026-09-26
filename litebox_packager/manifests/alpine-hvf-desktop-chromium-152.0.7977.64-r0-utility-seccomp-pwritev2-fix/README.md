# alpine-hvf-desktop-chromium-152.0.7977.64-r0-utility-seccomp-pwritev2-fix

Targeted-swap manifest variant for PRD row `chromium-utility-policy-pwritev2-seccomp-fix`.
Structural precedent: `../alpine-hvf-desktop-chromium-152.0.7977.64-r0-gpu-seccomp-pwritev2-fix/`
(the GPU-policy fix wave) and the wave175 stale-Thunar `-v2` splice
(`gpu-seccomp-fix-tar-stale-thunar-liveness-gate`).

## What changed

`sandbox/policy/linux/bpf_utility_policy_linux.cc`'s `UtilityProcessPolicy::EvaluateSyscall`
gained `case __NR_pwritev2:` immediately after the existing `case __NR_pwrite64:` (the same
one-line fallthrough-case pattern as the already-shipped GPU and Alpine-stock renderer fixes),
patch integrated into the community/chromium APKBUILD's `source=` list right after
`gpu-policy-pwritev2.patch` on the remote build host (`clawwong@192.168.1.81`, podman container
`chromiumbuild`, aports pin `247f5b9d76448b24b0cfb1782ba8a3881ced4c4f`) by an earlier wave of this
same PRD row. That wave's `abuild -r` finished this wave: `BUILD_EXIT=0`,
`BUILD_END=2026-09-19T20:41:07Z`, elapsed ~17h24m (re-verified live this wave via
`podman exec chromiumbuild tail -c 2000 build-utility.log`, not trusted from memory).

## Retrieval + splice (this wave)

Retrieved the 4 freshly-built apks from `/home/builder/.local/share/abuild/community/aarch64/`
inside the `chromiumbuild` container (found via `grep PKGDEST /etc/abuild.conf`, since
`~/packages/` does not exist on this host -- abuild's default `REPODEST` is
`$XDG_DATA_HOME/abuild`), all timestamped `2026-09-19 20:40:*`, matching `BUILD_END`:
`chromium-152.0.7977.64-r0.apk`, `chromium-common-152.0.7977.64-r0.apk`,
`chromium-angle-152.0.7977.64-r0.apk` (the same 3 packages the GPU-fix wave's own
`build-gpu-seccomp-fix-tar.py` swap-path set maps to), plus `chromium-dbg-152.0.7977.64-r0.apk`
(for a symbol-address lookup, see Verification below; not itself spliced into the tar).
`podman cp` off the container -> `scp` to this host's scratchpad -> `tar -xzf <apk> <paths>`
for the same 17 `usr/lib/chromium/*` swap paths the GPU-fix wave used.

**Base tar: `/tmp/litebox-hvf-desktop-gpu-seccomp-fix-v2.tar`** (NOT canonical, NOT the v1
GPU-only tar) -- the already-correct current base per `gpu-seccomp-fix-tar-stale-thunar-liveness-gate`'s
own resolution: carries both the GPU/seccomp/pwritev2 chromium payload AND the 2026-09-16
Thunar bounded-poll liveness-gate fix in its packaged `usr/bin/start-desktop.sh`, plus the
libFLAC.so.14 SONAME-bump fix. This wave's splice must not regress either.

**Splice method: raw-byte, NOT `tarfile.addfile()` passthrough.** A first attempt (literally
copying `build-gpu-seccomp-fix-tar.py`, which round-trips every member -- including untouched
ones -- through `tarfile.TarInfo`/`addfile()`) reproduced the *exact* documented v1 failure mode:
`tar_no_std::archive: Unparsable size` on an unrelated ca-certificates PAX long-name entry, then
`Error: failed to open the ELF file / Caused by: ENOENT` before any guest code ran -- live
re-confirmed this wave, not assumed from the GPU-fix manifest's own account of it. Root cause is
the same either time: Python's tarfile writer re-serializes every header it re-emits, even for
byte-identical passthrough content, and that re-serialization does not always round-trip a PAX
long-name entry back to the exact bytes litebox's minimal `tar_no_std` parser expects.

Fixed the same way `gpu-seccomp-fix-tar-stale-thunar-liveness-gate`'s own v2 splice was built
(per its witness text) but implemented fresh this wave since that exact script was session-scratch
and not preserved: `build_utility_pwritev2_fix_tar_rawsplice.py` (this directory) copies the
**entire base tar byte-for-byte** first (`shutil.copyfile`, no parsing at all), then opens the
output file `r+b` and overwrites only the exact `(offset_data, size)` byte range of each of the 17
swap targets in place -- offsets/sizes obtained from a read-only `tarfile` parse pass over the base
tar that is never used to drive any write. Every one of the 17 new files is byte-length-identical
to its v2 counterpart (see Delta below), so this is a pure same-length content substitution: no
header byte ever changes, no subsequent offset in the archive ever shifts, and each target's own
header checksum (computed over header bytes only, never content) stays valid unchanged. The base
tar is opened read-only throughout and reconfirmed byte-identical (sha256) before, mid-way, and
after.

## Delta vs. v2 (all 17 usual swap-path files compared by content sha256)

Only **`usr/lib/chromium/chromium`** actually differs from v2 (264244872 bytes both before and
after -- same size, new content, carrying the compiled fix). All other 16 files in the swap-path
set (`chrome-sandbox`, `chrome_crashpad_handler`, both `chrome_*_percent.pak`, `resources.pak`,
`icudtl.dat`, `snapshot_blob.bin`, `chromium-launcher.sh`, both `MEIPreload/*`, `locales/en-US.pak`,
`v8_context_snapshot.bin`, `headless_command_resources.pak`, `libEGL.so`, `libGLESv2.so`,
`libvulkan.so.1`) came back byte-for-byte identical to v2 from this fresh rebuild -- expected,
since only the one sandbox-policy source file changed between the GPU-fix build and this one, and
confirms this Alpine chromium build is otherwise deterministic given identical sources.

## Output

`/tmp/litebox-hvf-desktop-utility-pwritev2-fix.tar` -- **not checked into this directory**, same
convention as every other tar this project produces (canonical, gpu-seccomp-fix, gpu-seccomp-fix-v2
all live outside their manifest dirs too). See the PRD row `chromium-utility-policy-pwritev2-seccomp-fix`
for the exact size/sha256/md5 recorded at resolution time, and for the full live-measurement
witness (compiled-fix disassembly verification, per-member tar verification, and the real-download
workload comparison against the v2 baseline under the same workload).

## Verification performed this wave

1. **Per-member tar integrity**: every one of the base tar's 7237 members present in the output
   with the same name-order; the 7220 members outside the 17-path swap set are byte-identical to
   v2 (content hash + mode/uid/gid/mtime, all four); the 17 swap-set members keep v2's exact
   metadata (chrome-sandbox's `04755` setuid bit included) with only `chromium`'s content differing.
2. **Compiled-fix disassembly** (aarch64-linux-musl-objdump/readelf, cross toolchain via
   Homebrew): resolved `UtilityProcessPolicy::EvaluateSyscall`'s address from the matching
   `chromium-dbg` package's split debug symbols (`_ZNK7sandbox6policy20UtilityProcessPolicy15EvaluateSyscallEi`,
   since the release binary itself is stripped with a `.gnu_debuglink`), then disassembled that
   exact address range in the real (non-debug) `chromium` binary. Found `cmp w1, #0x11f` /
   `b.eq <target>` branching to the identical shared allow-path target
   (`b a4797e0`) that the already-known-correct `cmp w1, #0x44` (`__NR_pwrite64`) case in the same
   function also falls through to -- `0x11f` = 287 = `__NR_pwritev2` on aarch64, independently
   confirmed against the upstream kernel's own `include/uapi/asm-generic/unistd.h`
   (`torvalds/linux`, live-fetched). Cross-checked `GpuProcessPolicy::EvaluateSyscall` in the same
   new binary (regression check: still present) and `NetworkProcessPolicy::EvaluateSyscall`
   (negative control: no `#0x11f` compare anywhere in the case-chain/jump-table structure inspected,
   and 287 falls structurally outside every range-bound this function checks) -- confirms the
   disassembly method actually distinguishes a fixed function from an unfixed one on this exact
   binary, rather than always matching something.
3. **Live boot + real-download workload measurement**: see the PRD row's `witness_evidence` for
   the full account (a genuine, correctly-sized `Content-Disposition: attachment` GitHub-release
   download driven through Chromium's own UI-equivalent navigation, `/proc/*/cmdline` polled
   through the run, `chromium.log` grepped for every seccomp/SIGSYS/pwritev2 signature, compared
   against an identical-workload run on the unfixed v2 baseline).
