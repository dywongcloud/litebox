// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Substitutes a `-ffixed-x18`-rebuilt musl libc when packaging for a macOS
//! host, closing the gap documented in `docs/roadmap.md`'s "XNU destroys a
//! live guest `x18`" section.
//!
//! XNU zeroes the AArch64 platform register `x18` on every return to EL0.
//! musl's dynamic linker holds a live value in `x18` across exactly that kind
//! of boundary during its own relocation bootstrap (`find_sym2`), so a guest
//! whose musl was built for ordinary Linux -- where `x18` is an ordinary
//! allocatable register -- reliably crashes early under
//! [`litebox_syscall_rewriter::Host::MacOs`]. Rebuilding musl with
//! `-ffixed-x18` (this module's companion script,
//! `litebox_packager/scripts/build-musl-x18-fixed.sh`) removes the register
//! from the compiler's allocation pool entirely, closing the gap for musl's
//! own code (a real, remaining gap for the *guest's* own `x18` use, e.g. a
//! large binary's own compiled code or JIT output, is a separate, harder
//! problem -- see `docs/roadmap.md`).
//!
//! Rebuilding musl needs a real build toolchain (`abuild`/`podman`) this
//! packaging step does not want as a hard, synchronous dependency, so the fix
//! is a *cache lookup*: the build script is a one-time (or per-Alpine-version)
//! step that populates a local cache keyed by the exact stock musl bytes it
//! replaces, and this module only ever reads that cache. A cache miss is
//! never silently wrong -- packaging still succeeds with the stock musl (the
//! `x18` bug is real but was already present before this integration existed,
//! so proceeding is strictly no worse), and a clear, actionable warning names
//! the exact command to close the gap.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use sha2::{Digest as _, Sha256};

/// Env var overriding the cache directory `lookup_patched_musl` reads from
/// and the build script (`build-musl-x18-fixed.sh`) writes into. Unset
/// defaults to [`default_cache_dir`].
const CACHE_DIR_ENV: &str = "LITEBOX_MUSL_X18_CACHE";

/// Returns `true` if `path`'s file name matches musl's standard Alpine
/// naming convention (`ld-musl-<arch>.so.1` or `libc.musl-<arch>.so.1` --
/// package `musl`'s own `APKBUILD` installs both, one a symlink to the
/// other, so either name identifies the same library regardless of which
/// one a rootfs scan happened to read through).
pub(crate) fn is_musl_libc_filename(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    (name.starts_with("ld-musl-") || name.starts_with("libc.musl-")) && name.contains(".so")
}

/// Hex-encoded SHA-256 of `data`, used as the cache key: keying on the exact
/// stock bytes (rather than a version string) means a cache hit is only ever
/// used against the identical musl build it was produced from, and a
/// mismatched or stale cache entry is structurally impossible to apply by
/// accident.
fn content_hash(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let digest = hasher.finalize();
    digest.iter().fold(String::new(), |mut acc, b| {
        let _ = write!(acc, "{b:02x}");
        acc
    })
}

/// The cache directory `lookup_patched_musl` reads from when
/// [`CACHE_DIR_ENV`] is unset: `~/.cache/litebox/musl-x18-fixed`, following
/// the XDG-ish convention most Linux/macOS CLI tools already use for a
/// local, per-user artifact cache. Falls back to a relative path if `HOME`
/// is not set (e.g. some CI sandboxes), so a lookup never panics.
fn default_cache_dir() -> PathBuf {
    let home = std::env::var_os("HOME").map_or_else(|| PathBuf::from("."), PathBuf::from);
    home.join(".cache").join("litebox").join("musl-x18-fixed")
}

fn cache_dir() -> PathBuf {
    std::env::var_os(CACHE_DIR_ENV).map_or_else(default_cache_dir, PathBuf::from)
}

/// Looks up a pre-built, `-ffixed-x18` replacement for `original_data` (the
/// stock musl bytes about to be packaged), keyed by their exact content
/// hash. Returns `None` on a cache miss or an unreadable cache file --
/// never an error, since a miss is a normal, expected state before the
/// build script has been run for this exact musl build.
pub(crate) fn lookup_patched_musl(original_data: &[u8]) -> Option<Vec<u8>> {
    let hash = content_hash(original_data);
    let candidate = cache_dir().join(format!("{hash}.so"));
    std::fs::read(&candidate).ok()
}

/// Prints the one-time warning steering a user toward closing the gap,
/// naming the exact hash this musl build would be cached under so the
/// warning is directly actionable (copy the printed hash, or just re-run the
/// build script -- it derives the same hash itself).
pub(crate) fn warn_missing_patch(path: &Path, original_data: &[u8]) {
    let hash = content_hash(original_data);
    eprintln!(
        "warning: packaging {} for a macOS host without the -ffixed-x18 musl fix \
         (see docs/roadmap.md's \"XNU destroys a live guest x18\" section) -- \
         this guest's musl relocation bootstrap will likely crash under LiteBox on macOS.\n\
         \x20 to fix: litebox_packager/scripts/build-musl-x18-fixed.sh, which populates \
         {}/{hash}.so for this exact musl build; re-run this packaging command afterward \
         and it will be picked up automatically.",
        path.display(),
        cache_dir().display(),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_both_musl_alpine_names() {
        assert!(is_musl_libc_filename(Path::new(
            "/lib/ld-musl-aarch64.so.1"
        )));
        assert!(is_musl_libc_filename(Path::new(
            "/lib/libc.musl-aarch64.so.1"
        )));
        assert!(is_musl_libc_filename(Path::new("/lib/ld-musl-x86_64.so.1")));
    }

    #[test]
    fn rejects_unrelated_filenames() {
        assert!(!is_musl_libc_filename(Path::new("/usr/bin/node")));
        assert!(!is_musl_libc_filename(Path::new(
            "/lib/x86_64-linux-gnu/libc.so.6"
        )));
        assert!(!is_musl_libc_filename(Path::new("/lib/ld-musl-notice.txt")));
    }

    #[test]
    fn cache_miss_on_empty_directory_returns_none() {
        let dir =
            std::env::temp_dir().join(format!("litebox-musl-x18-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        // SAFETY-equivalent: test-only env mutation, single-threaded test binary
        // per crate (see cargo's default test harness), no concurrent reader.
        unsafe {
            std::env::set_var(CACHE_DIR_ENV, &dir);
        }
        assert!(lookup_patched_musl(b"stock musl bytes").is_none());
        unsafe {
            std::env::remove_var(CACHE_DIR_ENV);
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn cache_hit_returns_the_cached_bytes_keyed_by_content_hash() {
        let dir =
            std::env::temp_dir().join(format!("litebox-musl-x18-test-hit-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let original = b"stock musl bytes for the hit test";
        let hash = content_hash(original);
        std::fs::write(dir.join(format!("{hash}.so")), b"patched bytes").unwrap();
        unsafe {
            std::env::set_var(CACHE_DIR_ENV, &dir);
        }
        assert_eq!(
            lookup_patched_musl(original),
            Some(b"patched bytes".to_vec())
        );
        unsafe {
            std::env::remove_var(CACHE_DIR_ENV);
        }
        std::fs::remove_dir_all(&dir).ok();
    }
}
