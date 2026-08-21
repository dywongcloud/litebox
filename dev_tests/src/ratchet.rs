// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use anyhow::{Result, bail};
use fs::File;
use fs_err as fs;
use std::io::BufRead as _;
use std::io::BufReader;

#[test]
fn ratchet_transmutes() -> Result<()> {
    ratchet(
        &[
            ("dev_tests/", 2),
            ("litebox/", 8),
            ("litebox_platform_linux_userland/", 2),
        ],
        |file| {
            Ok(file
                .lines()
                .filter(|line| {
                    let line = line.as_ref().unwrap();
                    // Only check the code portion (before any // comment)
                    let code_part = line.split("//").next().unwrap_or(line);
                    code_part.contains("transmute")
                })
                .count())
        },
    )
}

#[test]
fn ratchet_globals() -> Result<()> {
    ratchet(
        &[
            ("dev_bench/", 1),
            ("litebox_broker_core/", 1),
            ("litebox_broker_transport_linux_userland/", 1),
            // 10, not 9: the macOS port added `extern "C" { static __dso_handle }`
            // to `litebox/src/mm/exception_table.rs`. Mach-O has no
            // linker-synthesized bounds for an arbitrary section, so the
            // exception table is found via `getsectiondata` off the image
            // handle. It is a link-time symbol reference, not the mutable global
            // state this ratchet exists to discourage; the heuristic counts any
            // line starting with `static`, including the two extern table bounds
            // already in this count.
            ("litebox/", 10),
            ("litebox_platform_linux_kernel/", 6),
            ("litebox_platform_linux_userland/", 5),
            ("litebox_platform_lvbs/", 24),
            // Was 13 while the guest-entry save area was process-global (a
            // naked callback running on the guest stack could not reach a
            // `thread_local!` without a call, so `HOST_SAVE`, `GUEST_FP`,
            // `LIVE_PTREGS`, `GUEST_OWNS_CPU`, `PENDING_INTERRUPT`,
            // `PENDING_EXCEPTION_INFO` and the `GUEST_ACTIVE` guard that kept
            // them from being raced all had to be statics). Lifting the
            // single-guest-thread limit retired all seven at once, in favour of
            // a per-thread `GuestThreadState` reached through a reserved
            // pthread TSD slot; the one static left in their place holds that
            // slot's byte offset. That accounts for 8: `mach_task_self_` (a
            // link-time `extern` symbol, not mutable state), three
            // `thread_local!`s, `GUEST_TP_TSD_KEY`, that new offset, and two
            // test-only statics in `guest::tests`.
            //
            // The ninth is `PROBE_ALLOCATOR`, which is `#[cfg(test)]`-only and
            // never exists in a production build: it is the
            // `#[global_allocator]` behind
            // `delivering_a_guest_fault_allocates_nothing_inside_the_signal_handler`,
            // which enforces that nothing reachable from the SIGSEGV/SIGBUS
            // handler allocates. `#[global_allocator]` can only be applied to a
            // `static`, so it cannot be expressed any other way; its own armed
            // flag and counter are deliberately struct fields rather than
            // further `static`s so the scaffolding costs exactly one.
            //
            // The tenth is `JIT_FAULT` (661ecea's MAP_JIT W^X fault-toggling
            // and CTR_EL0 emulation): JIT region bounds, the overflow
            // warn-once flag, and the synthesized CTR_EL0, all read from
            // inside the SIGSEGV/SIGBUS/SIGILL handler, which receives no
            // user-data pointer and may not lock, allocate, or touch TLS --
            // so the state must be static-reachable -- and is process-wide
            // (V8 threads execute code written by other threads), so
            // per-thread state is wrong. Its three fields are struct fields
            // rather than further `static`s so the scaffolding costs one.
            ("litebox_platform_macos_userland/", 10),
            ("litebox_platform_multiplex/", 1),
            ("litebox_platform_windows_userland/", 8),
            ("litebox_runner_lvbs/", 5),
            ("litebox_runner_snp/", 2),
            // 5, not 4: includes the test-only `ADDRESS_SPACE` and
            // `ASYNC_SIGNAL` mutexes that serialize tests (see
            // `address_space_guard`), the `EPOLL_NEST_LOCK` global lock
            // guarding nested-epoll registration, and `AUTOBIND_COUNTER`,
            // the monotonic counter Unix-socket autobind draws candidate
            // abstract addresses from (retried against the shared address
            // table on collision -- see `UnixSocketAddr::bind_and_reserve`).
            ("litebox_shim_linux/", 5),
            // 5, not 4: `static INIT_FUNC` arrived with the OP-TEE syscall
            // support in 071841e and the table was never updated, so this count
            // has been stale since well before the macOS work.
            ("litebox_shim_optee/", 5),
            ("litebox_shim_windows/", 1),
        ],
        |file| {
            Ok(file
                .lines()
                .filter(|line| {
                    // Heuristic: detect "static" at the start of a line, excluding whitespace. This should
                    // prevent us from accidentally including code that contains the word in a comment, or
                    // is referring to the `'static` lifetime.
                    let trimmed = line.as_ref().unwrap().trim_start();
                    trimmed.starts_with("static ")
                        || trimmed.split_once(' ').is_some_and(|(a, b)| {
                            // Account for `pub`, `pub(crate)`, ...
                            a.starts_with("pub") && b.starts_with("static ")
                        })
                })
                .count())
        },
    )
}

#[test]
fn ratchet_maybe_uninit() -> Result<()> {
    ratchet(
        &[
            ("dev_tests/", 1),
            ("litebox/", 1),
            ("litebox_broker_transport_linux_userland/", 3),
            // 4, not 2: `TimeProvider::thread_cpu_time`/`process_cpu_time` (added to back real
            // `CLOCK_THREAD_CPUTIME_ID`/`CLOCK_PROCESS_CPUTIME_ID` support) each read a
            // `libc::timespec` out-parameter via `clock_gettime`, following the exact same
            // pattern `now`/`current_time` already used in this file.
            ("litebox_platform_linux_userland/", 4),
        ],
        |file| {
            Ok(file
                .lines()
                .filter(|line| line.as_ref().unwrap().contains("MaybeUninit"))
                .count())
        },
    )
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/// Convenience function to set up a ratchet test, see below for examples.
///
/// `expected` is a list of (file name prefix, expected count) pairs.
#[track_caller]
fn ratchet(expected: &[(&str, usize)], f: impl Fn(BufReader<File>) -> Result<usize>) -> Result<()> {
    let all_rs_files = crate::all_rs_files()?.collect::<Vec<std::path::PathBuf>>();
    let mut errors = Vec::new();

    for (i, (prefix_i, _)) in expected.iter().enumerate() {
        if !prefix_i.ends_with('/') {
            errors.push(format!(
                "The prefix '{prefix_i}' should end with a '/'. Please make sure all prefixes end with a '/' to avoid accidental overlaps."
            ));
        }
        for (j, (prefix_j, _)) in expected.iter().enumerate() {
            if i != j && prefix_i.starts_with(prefix_j) {
                errors.push(format!(
                    "The prefix '{prefix_j}' is a prefix of '{prefix_i}'. Please make sure the prefixes are unique and non-overlapping."
                ));
            }
        }
        for (prefix, _) in expected {
            if !all_rs_files
                .iter()
                .any(|p| p.to_string_lossy().starts_with(prefix))
            {
                errors.push(format!(
                    "The prefix '{prefix}' does not match any file. Please make sure all prefixes match at least one file."
                ));
            }
        }
    }
    for p in &all_rs_files {
        let file_name = p.to_string_lossy();
        if !expected
            .iter()
            .any(|(prefix, _)| file_name.starts_with(prefix))
            && f(BufReader::new(File::open(p).unwrap()))? > 0
        {
            errors.push(format!(
                "The file '{file_name}'  that with a non-zero ratchet value is not covered by any prefix.\nPlease make sure all files are covered by some prefix."
            ));
        }
    }

    for (prefix, expected_count) in expected {
        let count = all_rs_files
            .iter()
            .filter(|p| p.to_string_lossy().starts_with(prefix))
            .map(|p| BufReader::new(File::open(p).unwrap()))
            .map(&f)
            .sum::<Result<usize>>()?;

        match count.cmp(expected_count) {
            std::cmp::Ordering::Less => {
                errors.push(format!(
                    "Good news!! Ratched count for paths starting with '{prefix}' decreased! :)\n\nPlease reduce the expected count in the ratchet to {count}"
                ));
            }
            std::cmp::Ordering::Equal => {
                if count == 0 {
                    errors.push(format!(
                        "The prefix {prefix} should be removed from the list since the ratchet has succesfully worked! :)"
                    ));
                }
            }
            std::cmp::Ordering::Greater => {
                errors.push(format!(
                    "Ratcheted count for paths starting with '{prefix}' increased by {} :(\n\nYou might be using a feature that is ratcheted (i.e., we are aiming to reduce usage of in the codebase).\nTips:\n\tTry if you can work without using this feature.\n\tIf you think the heuristic detection is incorrect, you might need to update the ratchet's heuristic.\n\tIf the heuristic is correct, you might need to update the count.",
                    count - expected_count
                ));
            }
        }
    }

    if !errors.is_empty() {
        bail!(
            "Ratchet test failed in {}:\n{}",
            std::panic::Location::caller(),
            errors.join("\n\n")
        );
    }

    Ok(())
}
