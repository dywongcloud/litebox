// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Host side of `diagnostics-counter-readout-surface`: a live instance mmaps a fixed-size file
//! under its run directory and a background thread periodically rewrites it with the current
//! generation-stamped counters snapshot; the signed runner binary's own `--unstable --counters
//! <run-dir>` subcommand (a separate, short-lived process -- see [`read_published`]) mmaps the
//! same file read-only and prints it as JSON. No network, no RPC, no new process privileges:
//! both sides are plain `mmap(2)` over one ordinary file.
//!
//! Layout: an 8-byte little-endian length prefix followed by that many JSON bytes, zero-padded
//! to [`REGION_LEN`]. [`REGION_LEN`] is comfortably larger than any real snapshot this crate
//! produces (the syscall ring alone is bounded at 256 entries; the address-space table at 320),
//! so truncation in practice never happens -- [`publish_once`] saturates to the region's
//! capacity rather than writing out of bounds if it ever would.

use std::fs::OpenOptions;
use std::path::{Path, PathBuf};

/// Total mapped region size: an 8-byte length header plus 8 MiB of JSON payload capacity.
const REGION_LEN: usize = 8 + 8 * 1024 * 1024;

/// The file name published under the run directory.
pub const COUNTERS_FILE_NAME: &str = "litebox-counters.bin";

struct MappedFile {
    ptr: *mut libc::c_void,
    len: usize,
}

// SAFETY container: the raw pointer is a `mmap` mapping this process owns exclusively for its
// lifetime (never handed to guest code or another allocator); reads/writes go through volatile
// byte-level accessors below, so ordinary `Send` reasoning about the pointee doesn't apply --
// only one thread (the publisher thread) ever writes it, matching `Sync`'s real requirement here
// (immutable access) trivially since nothing else touches it before that thread starts.
unsafe impl Send for MappedFile {}

impl Drop for MappedFile {
    fn drop(&mut self) {
        // SAFETY: `self.ptr`/`self.len` are exactly the values `mmap` returned and accepted,
        // never mutated after construction, and this is the only owner (never cloned).
        unsafe {
            libc::munmap(self.ptr, self.len);
        }
    }
}

fn map_file(file: &std::fs::File, len: usize) -> std::io::Result<MappedFile> {
    use std::os::fd::AsRawFd as _;
    // SAFETY: `file` is a valid, open fd for the whole call; `len` matches the file's own
    // guaranteed length (the caller `set_len`s it first); `MAP_SHARED` is exactly what makes
    // writes in one process visible to a concurrent `mmap` of the same file in another, which is
    // the entire point of this module.
    let ptr = unsafe {
        libc::mmap(
            core::ptr::null_mut(),
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            file.as_raw_fd(),
            0,
        )
    };
    if ptr == libc::MAP_FAILED {
        return Err(std::io::Error::last_os_error());
    }
    Ok(MappedFile { ptr, len })
}

fn map_file_read_only(file: &std::fs::File, len: usize) -> std::io::Result<MappedFile> {
    use std::os::fd::AsRawFd as _;
    // SAFETY: same as `map_file`, `PROT_READ`-only.
    let ptr = unsafe {
        libc::mmap(core::ptr::null_mut(), len, libc::PROT_READ, libc::MAP_SHARED, file.as_raw_fd(), 0)
    };
    if ptr == libc::MAP_FAILED {
        return Err(std::io::Error::last_os_error());
    }
    Ok(MappedFile { ptr, len })
}

fn counters_path(run_dir: &Path) -> PathBuf {
    run_dir.join(COUNTERS_FILE_NAME)
}

/// Writes one snapshot into the mapped region: an 8-byte little-endian length prefix, then the
/// JSON bytes (saturated to the region's capacity -- see this module's own doc comment for why
/// that never actually triggers in practice).
fn publish_once(mapped: &MappedFile, json: &str) {
    let bytes = json.as_bytes();
    let capacity = mapped.len - 8;
    let write_len = bytes.len().min(capacity);
    // SAFETY: `mapped.ptr` is a valid `PROT_READ | PROT_WRITE` mapping of at least
    // `mapped.len` bytes for this whole call; `write_len + 8 <= mapped.len` by construction.
    unsafe {
        let base = mapped.ptr.cast::<u8>();
        core::ptr::copy_nonoverlapping((write_len as u64).to_le_bytes().as_ptr(), base, 8);
        core::ptr::copy_nonoverlapping(bytes.as_ptr(), base.add(8), write_len);
    }
}

/// Creates (or truncates) and mmaps the counters file under `run_dir`, then spawns a daemon
/// thread that rewrites it with a fresh [`litebox_platform_macos_userland::diagnostics_counters::full_snapshot_json`]
/// snapshot every `interval`. Returns the run directory actually used (identical to `run_dir`);
/// errors only if the directory/file/mapping itself cannot be created, never once the loop has
/// started (a transient snapshot-building issue there would be a bug in `full_snapshot_json`
/// itself, not something this loop can meaningfully recover from mid-run).
pub fn spawn_publisher(run_dir: PathBuf, interval: std::time::Duration) -> std::io::Result<()> {
    std::fs::create_dir_all(&run_dir)?;
    let path = counters_path(&run_dir);
    let file = OpenOptions::new().read(true).write(true).create(true).truncate(false).open(&path)?;
    file.set_len(u64::try_from(REGION_LEN).unwrap_or(u64::MAX))?;
    let mapped = map_file(&file, REGION_LEN)?;
    // Publish an initial snapshot synchronously so a reader racing the very first tick still
    // sees real content (a valid, if early, generation) rather than an all-zero region.
    publish_once(&mapped, &litebox_platform_macos_userland::diagnostics_counters::full_snapshot_json());
    std::thread::Builder::new()
        .name("litebox-counters-pub".into())
        .spawn(move || {
            let _file = file; // keep the fd (and its mapping) alive for the process's whole life
            loop {
                std::thread::sleep(interval);
                let json = litebox_platform_macos_userland::diagnostics_counters::full_snapshot_json();
                publish_once(&mapped, &json);
            }
        })?;
    litebox_util_log::info!(run_dir:? = path; "diagnostics-counter-readout-surface: publishing counters");
    Ok(())
}

/// Reads back whatever [`spawn_publisher`] most recently wrote under `run_dir`, from a separate
/// process (the `--unstable --counters <run-dir>` CLI subcommand) mmapping the same file
/// read-only. Real, current content as of the moment of this call -- `MAP_SHARED` makes the
/// writer's stores visible here with no RPC, no lock file, no polling loop on the writer's side.
pub fn read_published(run_dir: &Path) -> anyhow::Result<String> {
    let path = counters_path(run_dir);
    let file = std::fs::File::open(&path).map_err(|e| {
        anyhow::anyhow!(
            "opening {path:?}: {e} (is a litebox instance running with --run-dir {run_dir:?}, \
             or did one publish here before exiting?)"
        )
    })?;
    let mapped = map_file_read_only(&file, REGION_LEN)?;
    // SAFETY: `mapped.ptr` is a valid `PROT_READ` mapping of `REGION_LEN` bytes for this whole
    // call.
    let bytes = unsafe {
        let base = mapped.ptr.cast::<u8>();
        let mut len_buf = [0_u8; 8];
        core::ptr::copy_nonoverlapping(base, len_buf.as_mut_ptr(), 8);
        let len = (u64::from_le_bytes(len_buf) as usize).min(REGION_LEN - 8);
        let mut out = alloc_vec(len);
        core::ptr::copy_nonoverlapping(base.add(8), out.as_mut_ptr(), len);
        out
    };
    String::from_utf8(bytes).map_err(|e| anyhow::anyhow!("published counters file is not valid UTF-8: {e}"))
}

fn alloc_vec(len: usize) -> Vec<u8> {
    let mut v = Vec::with_capacity(len);
    // SAFETY: `v` has capacity `len`, `u8` needs no initialization invariant, and every byte is
    // immediately overwritten by the `copy_nonoverlapping` call at this function's one call site
    // before being read.
    unsafe {
        v.set_len(len);
    }
    v
}

/// A fresh default run directory under the system temp dir, used when neither `--run-dir` nor
/// `--counters` names one explicitly: `$TMPDIR/litebox-run-<pid>`.
pub fn default_run_dir() -> PathBuf {
    std::env::temp_dir().join(format!("litebox-run-{}", std::process::id()))
}

/// One last, guaranteed-current publish, independent of [`spawn_publisher`]'s own periodic
/// thread (which `run`'s own `std::process::exit` at the very end tears down mid-sleep with no
/// chance to run its loop body again). Without this, a guest run shorter than one publish
/// interval would only ever be observed pre-workload -- real for that instant, but not what a
/// witness reading counters right after the run actually wants. Call once, right after the
/// guest's root task has been waited on. Re-opens and re-mmaps the same file rather than
/// reusing the publisher thread's own mapping (there is no cheap way to reach into another
/// thread's locals from here); a few extra syscalls on the one-shot exit path is a fine trade
/// for not needing a shared handle threaded back out of `spawn_publisher`.
pub fn publish_final(run_dir: &Path) {
    let path = counters_path(run_dir);
    // `map_file` always requests `PROT_READ | PROT_WRITE` (see its own doc comment: it is shared
    // with `spawn_publisher`'s writer mapping), which `mmap` refuses with `EACCES` against a
    // write-only fd on a POSIX host (confirmed live on this host's own mmap(2): a fd opened
    // `O_WRONLY` cannot back a `PROT_READ` mapping) -- so `.write(true)` alone here silently
    // broke every call to this function (the `Ok(mapped)` match always failed, this always
    // returned early, and no final snapshot was ever actually written; live-discovered verifying
    // GM row hvf-fork-private-address-space, where a real <300ms guest run's `--counters`
    // readout came back an all-zero pre-workload snapshot instead of the accurate post-workload
    // one already computed and logged in-process at this same call site).
    let Ok(file) = OpenOptions::new().read(true).write(true).open(&path) else {
        return;
    };
    let Ok(mapped) = map_file(&file, REGION_LEN) else {
        return;
    };
    publish_once(&mapped, &litebox_platform_macos_userland::diagnostics_counters::full_snapshot_json());
}
