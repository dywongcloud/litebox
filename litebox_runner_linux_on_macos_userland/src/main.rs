// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Restricted to Apple Silicon macOS: see the crate docs for why there is no
// x86-64 variant.

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn main() -> anyhow::Result<()> {
    use clap::Parser as _;
    use litebox_runner_linux_on_macos_userland::CliArgs;

    // Two internal modes, recognized before `clap` ever sees the command line
    // because neither is part of this program's user interface: both exist only
    // so the runner can re-execute itself to give the guest a real `fork`. See
    // `litebox_platform_macos_userland::hostproc` for what each one is for.
    //
    // They are matched on the raw first argument rather than declared as `clap`
    // flags so that a user who types one by hand gets a plain "unexpected
    // argument" error rather than a half-initialized guest.
    match std::env::args().nth(1).as_deref() {
        Some(litebox_platform_macos_userland::SPAWN_HELPER_ARG) => {
            litebox_platform_macos_userland::run_spawn_helper()
        }
        Some(litebox_platform_macos_userland::SPAWNED_CHILD_ARG) => {
            litebox_runner_linux_on_macos_userland::run_spawned_child()
        }
        _ => litebox_runner_linux_on_macos_userland::run(CliArgs::parse()),
    }
}

#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
fn main() {
    eprintln!("This program is only supported on macOS on Apple Silicon");
    std::process::exit(1);
}
