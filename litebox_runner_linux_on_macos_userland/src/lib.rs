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
    /// Override this guest's own address (default: `10.0.0.2`). Needed to run
    /// more than one instance on the same host at once, each independently
    /// reachable — a CLI flag rather than an env var so it survives a
    /// `sudo`-invoked launch even under `env_reset` (the default policy),
    /// which strips arbitrary environment variables but never argv.
    #[arg(
        long = "guest-ip",
        requires = "unstable",
        help_heading = "Unstable Options"
    )]
    pub guest_ip: Option<std::net::Ipv4Addr>,
    /// Override this guest's default-route gateway (default: `10.0.0.1`).
    /// See `--guest-ip`.
    #[arg(
        long = "gateway-ip",
        requires = "unstable",
        help_heading = "Unstable Options"
    )]
    pub gateway_ip: Option<std::net::Ipv4Addr>,
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
    tracing_subscriber::fmt()
        .with_timer(tracing_subscriber::fmt::time::uptime())
        .with_level(true)
        .with_env_filter(
            tracing_subscriber::EnvFilter::builder()
                .with_env_var("LITEBOX_LOG")
                .from_env_lossy(),
        )
        .init();

    let tar_file = &cli_args.initial_files;
    if tar_file.extension().and_then(|x| x.to_str()) != Some("tar") {
        anyhow::bail!("Expected a .tar file, found {}", tar_file.display());
    }
    let tar_data = std::fs::read(tar_file)
        .map_err(|e| anyhow!("Could not read tar file at {}: {}", tar_file.display(), e))?;

    let platform = Platform::new(cli_args.tun_device_name.as_deref());
    let shim_builder = litebox_shim_linux::LinuxShimBuilder::new(platform);
    let litebox = shim_builder.litebox();

    // The program path is a Unix-style path inside the tar archive.
    let prog_path = &cli_args.program_and_arguments[0];

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

            // Standard FHS directories that guest tools expect to already exist (e.g. `apk`
            // opens a log file under `/var/log`) but that don't survive as empty-directory
            // entries when an OCI image's rootfs is scanned into a file-based tar: an empty
            // directory has no file contents, so it produces no tar entry, and `TarRo`'s
            // directory tree is inferred purely from file paths.
            for dir in ["/run", "/var", "/var/log", "/var/cache", "/var/tmp"] {
                fs.mkdir(
                    dir,
                    litebox::fs::Mode::RWXU | litebox::fs::Mode::RWXG | litebox::fs::Mode::RWXO,
                )
                .unwrap_or_else(|_| {
                    panic!("{dir} creation cannot fail on a fresh in-memory file system")
                });
            }
        });

        shim_builder.default_fs(in_mem, tar_data.into())
    };
    let initial_file_system = std::sync::Arc::new(initial_file_system);

    // Per-invocation network identity override (mirrors the Linux host
    // runner's fleet-hive patch): lets many concurrent litebox processes on
    // one host each own a distinct, independently-reachable address instead
    // of all defaulting to the same hardcoded 10.0.0.2/10.0.0.1. Unset =
    // identical to upstream behavior. CLI flags rather than env vars
    // (`--guest-ip`/`--gateway-ip`, `CliArgs`) — a `sudo`-invoked launch
    // under the default `env_reset` policy strips arbitrary env vars
    // (confirmed live: "sudo: sorry, you are not allowed to set the
    // following environment variables") but always passes argv through.
    let shim =
        shim_builder.build_with_net_config(cli_args.guest_ip, cli_args.gateway_ip);
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

    // Drive the network stack. The shim keeps its smoltcp interface in
    // `Manual` mode -- nothing polls it unless a runner does -- and the Linux
    // runner spawns this exact loop, but only when a `--tun` device is
    // present. macOS has no tun by default, yet still needs the poll to run:
    // in-process loopback (a guest binding a server on `127.0.0.1` and
    // reaching it from the same process -- a Node `http` server, and the many
    // test frameworks and IPC paths that assume a working loopback) is entirely
    // driven by this poll. Without it every TCP handshake stalls, because the
    // SYN a `connect` queues is never egressed. A short bounded sleep between
    // polls keeps loopback latency low without a hot spin; there is no tun to
    // block on here.
    let shutdown = std::sync::Arc::new(core::sync::atomic::AtomicBool::new(false));
    let net_worker = {
        let shim = shim.clone();
        let shutdown = shutdown.clone();
        std::thread::spawn(move || {
            const IDLE_SLEEP: core::time::Duration = core::time::Duration::from_micros(200);
            const MAX_SLEEP: core::time::Duration = core::time::Duration::from_millis(1);
            while !shutdown.load(core::sync::atomic::Ordering::Relaxed) {
                let timeout = loop {
                    match shim.perform_network_interaction() {
                        litebox::net::PlatformInteractionReinvocationAdvice::CallAgainImmediately => {}
                        litebox::net::PlatformInteractionReinvocationAdvice::WaitOnDeviceOrSocketInteraction { timeout } => {
                            break timeout;
                        }
                    }
                };
                std::thread::sleep(timeout.unwrap_or(IDLE_SLEEP).min(MAX_SLEEP));
            }
            // Final flush so a socket with data still queued at guest exit gets
            // one last chance to drain.
            while shim.perform_network_interaction().call_again_immediately() {}
        })
    };

    // SAFETY: `load_program` produced the entry context, so its `pc` and `sp`
    // describe a loaded, runnable guest image.
    unsafe {
        litebox_platform_macos_userland::run_thread(
            program.entrypoints,
            &mut litebox_common_linux::PtRegs::default(),
        );
    }
    let exit_code = program.process.wait();
    shutdown.store(true, core::sync::atomic::Ordering::Relaxed);
    let _ = net_worker.join();
    std::process::exit(exit_code)
}
