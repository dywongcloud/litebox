// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Runs an AArch64 Linux guest on an unmodified Apple Silicon macOS host.
//!
//! There is deliberately no x86-64 variant. LiteBox runs guest instructions
//! natively and virtualizes only the system interface, so an x86-64 guest here
//! would need instruction emulation -- the thing the design exists to avoid. An
//! AArch64 guest on an AArch64 host needs none.
#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

extern crate alloc;

use anyhow::{Result, anyhow};
use clap::Parser;
use litebox_platform_macos_userland::MacOsUserland as Platform;
use std::path::PathBuf;

/// Run Linux programs with LiteBox on unmodified macOS.
///
/// The program binary and all its dependencies must be provided inside a tar
/// archive via `--initial-files`. The program path refers to a path inside the
/// tar archive.
#[derive(Parser, Debug)]
pub struct CliArgs {
    /// The program and arguments passed to it (e.g., `/bin/ls --color`).
    ///
    /// The program path refers to a path inside the tar archive provided via
    /// `--initial-files`. All binaries must be pre-rewritten with the syscall
    /// rewriter.
    #[arg(required = true, trailing_var_arg = true, value_hint = clap::ValueHint::CommandWithArguments)]
    pub program_and_arguments: Vec<String>,
    /// Environment variables passed to the program (`K=V` pairs; can be invoked multiple times)
    #[arg(long = "env")]
    pub environment_variables: Vec<String>,
    /// Forward the existing environment variables
    #[arg(long = "forward-env")]
    pub forward_environment_variables: bool,
    /// Tar archive containing the program and its shared libraries.
    ///
    /// All ELF binaries should be pre-rewritten with the syscall rewriter
    /// (e.g., via `litebox-packager`), for `Host::MacOs`.
    #[arg(long = "initial-files", value_name = "PATH_TO_TAR", value_hint = clap::ValueHint::FilePath)]
    pub initial_files: PathBuf,
    /// Allow using unstable options
    #[arg(short = 'Z', long = "unstable")]
    pub unstable: bool,
    /// Connect to a `utun` device with this name (e.g. `utun4`).
    ///
    /// Creating the interface needs root on this host, so the guest has no
    /// network unless one is named.
    #[arg(
        long = "tun-device-name",
        requires = "unstable",
        help_heading = "Unstable Options"
    )]
    pub tun_device_name: Option<String>,
}

/// Run a Linux program with LiteBox on unmodified macOS.
///
/// # Errors
///
/// Returns an error when the tar archive cannot be read, or when the shim
/// cannot load the requested program out of it.
///
/// # Panics
///
/// Panics if the host is not set up as expected -- notably if a second guest
/// thread starts, which this platform's process-global guest-entry save area
/// does not yet support (see `docs/roadmap.md`).
pub fn run(cli_args: CliArgs) -> Result<()> {
    init_logging();

    let tar_file = &cli_args.initial_files;
    if tar_file.extension().and_then(|x| x.to_str()) != Some("tar") {
        anyhow::bail!("Expected a .tar file, found {}", tar_file.display());
    }

    let argv = cli_args
        .program_and_arguments
        .iter()
        .map(|x| std::ffi::CString::new(x.bytes().collect::<Vec<u8>>()).unwrap())
        .collect();
    let envp: Vec<_> = cli_args
        .environment_variables
        .iter()
        .map(|x| std::ffi::CString::new(x.bytes().collect::<Vec<u8>>()).unwrap())
        .collect();
    let envp = if cli_args.forward_environment_variables {
        envp.into_iter()
            .chain(std::env::vars().map(|(k, v)| {
                std::ffi::CString::new(k.bytes().chain(*b"=").chain(v.bytes()).collect::<Vec<u8>>())
                    .unwrap()
            }))
            .collect()
    } else {
        envp
    };

    run_guest(
        tar_file.clone(),
        cli_args.program_and_arguments[0].clone(),
        argv,
        envp,
        cli_args.tun_device_name.as_deref(),
    )
}

/// Runs this process as a guest child of another runner.
///
/// The parent runner, jailed by Seatbelt, cannot `exec` anything; its spawn
/// helper started this process instead and piped in a
/// [`litebox_platform_macos_userland::ChildSpec`] describing what to run. See
/// that crate's `hostproc` module for the whole mechanism, and the shim's
/// `syscalls::fork` module for the `fork` semantics it backs.
///
/// The descriptors this process should hand the guest are already in place at
/// their guest numbers, put there by the helper's `posix_spawn` file actions,
/// which is why nothing here mentions them.
///
/// # Errors
///
/// Returns an error if the spec cannot be read or the program cannot be loaded.
///
/// # Panics
///
/// Panics if an argument or environment string in the spec contains an interior
/// NUL byte, which the `execve` that produced it could not have accepted.
pub fn run_spawned_child() -> Result<()> {
    init_logging();
    let spec = litebox_platform_macos_userland::read_child_spec()
        .map_err(|e| anyhow!("could not read the child spec from the spawn helper: {e}"))?;
    let program = String::from_utf8(spec.program.clone())
        .map_err(|_| anyhow!("the guest program path is not valid UTF-8"))?;
    let to_cstring = |bytes: &Vec<u8>| std::ffi::CString::new(bytes.clone()).unwrap();
    run_guest(
        PathBuf::from(<std::ffi::OsString as std::os::unix::ffi::OsStringExt>::from_vec(
            spec.initial_files.clone(),
        )),
        program,
        spec.argv.iter().map(to_cstring).collect(),
        spec.envp.iter().map(to_cstring).collect(),
        None,
    )
}

fn init_logging() {
    tracing_subscriber::fmt()
        .with_timer(tracing_subscriber::fmt::time::uptime())
        .with_level(true)
        .with_env_filter(
            tracing_subscriber::EnvFilter::builder()
                .with_env_var("LITEBOX_LOG")
                .from_env_lossy(),
        )
        .init();
}

/// Loads `prog_path` out of the `tar_file` archive and runs it to completion.
fn run_guest(
    tar_file: PathBuf,
    prog_path: String,
    argv: Vec<std::ffi::CString>,
    envp: Vec<std::ffi::CString>,
    tun_device_name: Option<&str>,
) -> Result<()> {
    let tar_data = std::fs::read(&tar_file)
        .map_err(|e| anyhow!("Could not read tar file at {}: {}", tar_file.display(), e))?;

    let platform = Platform::new(tun_device_name);

    // Start the spawn helper that backs the guest's `fork`. This has to happen
    // before `enable_seatbelt_sandbox` below, which permanently denies this
    // process `process-fork` and `process-exec`; it is the counterpart of
    // reading the tar archive and opening the `utun` device up here rather than
    // later. A failure is not fatal -- the guest simply gets the pre-existing
    // behavior, `fork` failing with `EINVAL` -- but it is worth a warning,
    // because every `fork`ing guest will then break in a way that has nothing to
    // do with the guest.
    if let Err(err) = platform.enable_host_process_support(std::os::unix::ffi::OsStrExt::as_bytes(
        tar_file.as_os_str(),
    )) {
        litebox_util_log::warn!(err:% = err;
            "could not start the spawn helper; the guest's fork() will fail with EINVAL");
    }
    let shim_builder = litebox_shim_linux::LinuxShimBuilder::new(platform);
    let litebox = shim_builder.litebox();

    // The program path is a Unix-style path inside the tar archive.
    let prog_path = &prog_path;

    let initial_file_system = {
        let mut in_mem = litebox::fs::in_mem::FileSystem::new(litebox);
        in_mem.with_root_privileges(|fs| {
            use litebox::fs::FileSystem as _;
            fs.mkdir(
                "/tmp",
                litebox::fs::Mode::RWXU | litebox::fs::Mode::RWXG | litebox::fs::Mode::RWXO,
            )
            .unwrap();
            fs.chown("/tmp", Some(1000), Some(1000)).unwrap();
        });

        shim_builder.default_fs(in_mem, tar_data.into())
    };
    let initial_file_system = std::sync::Arc::new(initial_file_system);

    let shim = shim_builder.build();

    // Drop into the Seatbelt sandbox before any guest-controlled byte is parsed.
    // This is the exact counterpart, and the exact lifecycle position, of the
    // Linux runner's `enable_seccomp_filter` call: every host resource this
    // process will ever need has been acquired by now (the tar archive is read
    // into memory above, the `utun` device was opened in `Platform::new`, stdio
    // was sampled there too), and the very next thing that happens is
    // `load_program` running an ELF parser over attacker-chosen bytes.
    //
    // This panics rather than warning if the sandbox cannot be installed; see
    // `enable_seatbelt_sandbox`'s doc comment for the fail-safe argument.
    litebox_platform_macos_userland::enable_seatbelt_sandbox();

    let program = shim.load_program(
        initial_file_system,
        platform.init_task(),
        prog_path,
        argv,
        envp,
    )?;

    // SAFETY: `load_program` produced the entry context, so its `pc` and `sp`
    // describe a loaded, runnable guest image.
    unsafe {
        litebox_platform_macos_userland::run_thread(
            program.entrypoints,
            &mut litebox_common_linux::PtRegs::default(),
        );
    }
    std::process::exit(program.process.wait())
}
