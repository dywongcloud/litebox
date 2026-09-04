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
use std::io::Write as _;
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
    /// Host-side address of the attached --tun-device-name link, i.e. the
    /// guest's default gateway. Assigned to the `utun` interface itself
    /// (with a /24 netmask) since a `utun` device, unlike Linux's TUN, has no
    /// separate persistent existence to pre-configure. Must be given
    /// together with --net-guest-ip.
    #[arg(
        long = "net-host-ip",
        value_name = "IP",
        requires_all = ["unstable", "net_guest_ip"],
        help_heading = "Unstable Options"
    )]
    pub net_host_ip: Option<std::net::Ipv4Addr>,
    /// The guest's own address on the attached --tun-device-name link. Every
    /// guest otherwise answers on the same hardcoded pair, so two boxes on
    /// distinct devices can't address each other directly; overriding this
    /// (and --net-host-ip, to match the device's actual host-side address)
    /// is what makes that possible. Must be given together with
    /// --net-host-ip, in the same /24.
    #[arg(
        long = "net-guest-ip",
        value_name = "IP",
        requires_all = ["unstable", "net_host_ip"],
        help_heading = "Unstable Options"
    )]
    pub net_guest_ip: Option<std::net::Ipv4Addr>,
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

    let platform = Platform::new(
        cli_args.tun_device_name.as_deref(),
        cli_args.net_host_ip,
        cli_args.net_guest_ip,
    );

    // Verify that stdio forwarding is set up correctly.
    // This ensures guest writes to stdout/stderr will reach the host.
    if !platform.verify_stdio_accessible() {
        eprintln!("Warning: host stdout/stderr may not be accessible for guest stdio forwarding");
    }

    let shim_builder = litebox_shim_linux::LinuxShimBuilder::new(platform);
    if let (Some(guest_ip), Some(host_ip)) = (cli_args.net_guest_ip, cli_args.net_host_ip) {
        if guest_ip.octets()[..3] != host_ip.octets()[..3] {
            anyhow::bail!(
                "--net-guest-ip {guest_ip} and --net-host-ip {host_ip} must be in the same /24 subnet"
            );
        }
        if guest_ip == host_ip {
            anyhow::bail!("--net-guest-ip and --net-host-ip must be different addresses");
        }
        shim_builder.net_addrs(guest_ip, host_ip);
    }
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
        });

        shim_builder.default_fs(in_mem, tar_data.into())
    };
    let initial_file_system = std::sync::Arc::new(initial_file_system);

    let shim = shim_builder.build();
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

    let program = shim
        .load_program(
            initial_file_system,
            platform.init_task(),
            prog_path,
            "/",
            argv,
            envp,
        )
        .map_err(|e| {
            // A non-PIE `ET_EXEC` guest must load at its recorded p_vaddr,
            // and static musl links those low (0x400000 and friends) --
            // inside the 4 GiB `__PAGEZERO` an arm64 Mach-O process
            // reserves. The mapping is refused with `BelowMinAddress`,
            // which reaches the guest as a bare `EPERM` naming neither the
            // address nor the fix, and the same binary loads fine on Linux
            // (no such floor), so the cause is easy to miss here.
            anyhow!(
                "{e}\n\nnote: on Apple Silicon a guest image must be \
                 position-independent -- the first 4 GiB is __PAGEZERO, so a \
                 non-PIE ET_EXEC linked below it cannot be mapped and fails \
                 exactly this way. Check with `readelf -h <binary>` (want \
                 \"DYN\", not \"EXEC\") or `file` (want \"pie executable, \
                 ... static-pie linked\"); neither alone proves the binary \
                 actually self-relocates, only running it does -- see \
                 litebox_platform_macos_userland/scripts/\
                 aarch64-musl-static-pie-linker.sh, wired into a guest \
                 project's own .cargo/config.toml, for how this project \
                 builds a genuinely working static-PIE guest (a bare \
                 `-C link-args=-static-pie` produces the right file type \
                 while still crashing at guest startup). See docs/macos.md."
            )
        })?;

    // Wire up stdio forwarding: ensure host stdout/stderr are accessible to the guest.
    // This is needed because guest write(fd=1) and write(fd=2) syscalls are routed
    // through the platform's StdioProvider::write_to, which forwards to the host's fds.
    // The platform is already initialized with the host's stdio information, so guest
    // writes via /dev/stdout and /dev/stderr will reach the host.
    std::io::stdout().flush().ok();
    std::io::stderr().flush().ok();

    // Nothing drives `Net`'s smoltcp interface unless something calls
    // `perform_network_interaction()` in a loop (see its own doc comment:
    // "This function should be invoked in a loop, based on the returned
    // advice"). `litebox_runner_linux_userland` does this on a dedicated
    // host thread; this runner never did, on any platform it targets, which
    // silently made the entire `utun` device a dead end -- confirmed on real
    // hardware: correct interface config (point-to-point peer address,
    // `netstat -nr`), correct routing, `net.inet.ip.forwarding=1`, and still
    // not one packet ever reached this platform's own
    // `IPInterfaceProvider::send_ip_packet`/`receive_ip_packet` (checked
    // directly, not inferred from a hang), for either a host-to-guest
    // connection or a guest connecting to another guest through the host
    // kernel -- because nothing had ever asked `Net` to look at the `utun`
    // fd at all. Unlike the Linux runner, this platform has no
    // `wait_on_tun`-style efficient blocking wait yet, so this loop plain
    // polls; correctness first, since without it there is no networking on
    // macOS ARM whatsoever, guest-to-guest or host-published.
    if cli_args.tun_device_name.is_some() {
        let shim = shim.clone();
        std::thread::spawn(move || {
            loop {
                let advice = shim.perform_network_interaction();
                if !advice.call_again_immediately() {
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
            }
        });
    }

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
