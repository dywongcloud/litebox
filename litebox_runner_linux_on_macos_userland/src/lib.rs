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

/// Adapts [`litebox::fs::devices::Framebuffer`] to [`litebox_rfb::FramebufferSource`] --
/// `litebox_rfb` deliberately doesn't depend on `litebox` (see its own crate doc comment), so
/// this thin wrapper lives on the runner side of that boundary instead.
struct FramebufferAdapter(litebox::fs::devices::Framebuffer<Platform>);

impl litebox_rfb::FramebufferSource for FramebufferAdapter {
    fn dimensions(&self) -> (u16, u16) {
        let geo = self.0.geometry();
        // A real fbdev geometry is always well within u16 range (RFB's own wire format caps
        // width/height at u16 too); truncation here would only ever fire on a geometry no real
        // client could display anyway.
        (
            u16::try_from(geo.xres).unwrap_or(u16::MAX),
            u16::try_from(geo.yres).unwrap_or(u16::MAX),
        )
    }

    fn snapshot_into(&self, dst: &mut Vec<u8>) {
        self.0.read_visible_into(dst);
    }
}

/// Run Linux programs with LiteBox on unmodified macOS.
///
/// The program binary and all its dependencies must be provided inside a tar
/// archive via `--initial-files`. The program path refers to a path inside the
/// tar archive.
#[derive(Parser, Debug)]
#[allow(clippy::struct_excessive_bools)]
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
    /// Serve the guest's `/dev/fb0` framebuffer over VNC (RFB), for a real desktop viewer to
    /// connect to. Binds `127.0.0.1` only by default -- see `--vnc-bind-all` to widen that.
    #[arg(long = "vnc", requires = "unstable", help_heading = "Unstable Options")]
    pub vnc: bool,
    /// Port the VNC server listens on when `--vnc` is set (default: `5900`, the conventional RFB
    /// display-0 port).
    #[arg(
        long = "vnc-port",
        requires = "vnc",
        default_value_t = 5900,
        help_heading = "Unstable Options"
    )]
    pub vnc_port: u16,
    /// Bind the VNC server to all interfaces (`0.0.0.0`) instead of the localhost-only default.
    /// Off by default: the guest framebuffer is unauthenticated RFB with no encryption, so
    /// widening past localhost exposes it to the local network without so much as a password.
    #[arg(
        long = "vnc-bind-all",
        requires = "vnc",
        help_heading = "Unstable Options"
    )]
    pub vnc_bind_all: bool,
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
    let shim = shim_builder.build_with_net_config(cli_args.guest_ip, cli_args.gateway_ip);

    // Bind AND run the VNC server's whole accept loop before the Seatbelt sandbox below, which
    // denies every syscall not explicitly allowed -- and unlike a plain read/write on an
    // already-open fd (stdio, the `utun` device -- see the sandbox call's own comment below),
    // `accept()` on a listening socket is itself a mediated network operation with no `allow`
    // rule in this profile, so it cannot run post-sandbox. This mirrors the tar-file read and
    // `utun` device open above: every host resource the process will ever need must be acquired
    // -- and here, USED -- before `enable_seatbelt_sandbox()` runs. Concretely: spawn the whole
    // `RfbServer::run` (bind already happened in `RfbServer::bind`, accept-loop-and-serve
    // happens in the spawned thread) before the sandbox call; Seatbelt restrictions apply
    // process-wide and are inherited by every thread (per this crate's own seatbelt module doc
    // comment), so a thread spawned pre-sandbox keeps running exactly as before after the main
    // thread sandboxes itself.
    let vnc_worker = if cli_args.vnc {
        let framebuffer = shim
            .framebuffer()
            .ok_or_else(|| anyhow!("--vnc requires a filesystem that mounts /dev/fb0"))?;
        let bind_addr = cli_args
            .vnc_bind_all
            .then_some(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
        let server = litebox_rfb::RfbServer::bind(
            bind_addr,
            cli_args.vnc_port,
            std::sync::Arc::new(FramebufferAdapter(framebuffer)),
        )
        .map_err(|e| anyhow!("failed to bind VNC listener: {e}"))?;
        litebox_util_log::info!(
            addr:% = server.local_addr().map_err(|e| anyhow!("{e}"))?;
            "vnc server listening"
        );
        let shutdown_handle = server.shutdown_handle();
        let input_registry = shim.input_registry();
        let input_framebuffer = shim.framebuffer();
        let worker = std::thread::spawn(move || {
            // RFB `PointerEvent`s carry a whole button-state mask per event; evdev wants
            // per-button transitions. Tracked under a mutex because `on_input` can be called
            // concurrently from several connected clients' threads -- last-writer-wins on the
            // shared mask matches how a real single mouse would behave with two hands on it.
            let last_buttons = std::sync::Mutex::new(0u8);
            // Timestamps only need to be monotonic with microsecond-ish resolution; consumers
            // compare deltas, never absolute values.
            let epoch = std::time::Instant::now();
            if let Err(e) = server.run(move |event| {
                let Some(registry) = input_registry.as_ref() else {
                    return;
                };
                let now = epoch.elapsed();
                match event {
                    litebox_rfb::InputEvent::Key(key) => {
                        if let Some(code) = litebox_rfb::keymap::keysym_to_evdev(key.key) {
                            registry.inject_key(code, key.down, now);
                        }
                    }
                    litebox_rfb::InputEvent::Pointer(p) => {
                        // Scale the RFB screen coordinate into the tablet's fixed 0..=32767
                        // range against the *current* framebuffer geometry (resizes included).
                        let (width, height) =
                            input_framebuffer.as_ref().map_or((1024, 768), |fb| {
                                let geo = fb.geometry();
                                (geo.xres.max(1), geo.yres.max(1))
                            });
                        let range = i64::from(litebox::fs::devices::ABS_RANGE_MAX);
                        let scale = |v: u16, extent: u32| -> i32 {
                            let clamped = i64::from(v).min(i64::from(extent) - 1);
                            i32::try_from(clamped * range / i64::from(extent.max(1)))
                                .unwrap_or(litebox::fs::devices::ABS_RANGE_MAX)
                        };
                        let x = scale(p.x, width);
                        let y = scale(p.y, height);
                        let mut last = last_buttons
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        let changed = *last ^ p.button_mask;
                        let mut transitions = Vec::new();
                        for (bit, btn) in [
                            (0u8, litebox::fs::devices::BTN_LEFT),
                            (1, litebox::fs::devices::BTN_MIDDLE),
                            (2, litebox::fs::devices::BTN_RIGHT),
                        ] {
                            if changed & (1 << bit) != 0 {
                                transitions.push((btn, p.button_mask & (1 << bit) != 0));
                            }
                        }
                        // RFB encodes each scroll click as a press+release of button 4/5; a
                        // press edge is one wheel step.
                        if changed & (1 << 3) != 0 && p.button_mask & (1 << 3) != 0 {
                            registry.inject_wheel(1, now);
                        }
                        if changed & (1 << 4) != 0 && p.button_mask & (1 << 4) != 0 {
                            registry.inject_wheel(-1, now);
                        }
                        *last = p.button_mask;
                        drop(last);
                        registry.inject_pointer_abs(x, y, &transitions, now);
                    }
                }
            }) {
                litebox_util_log::warn!(error:% = e; "vnc server stopped");
            }
        });
        Some((worker, shutdown_handle))
    } else {
        None
    };

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
    if let Some((worker, shutdown_handle)) = vnc_worker {
        shutdown_handle.signal();
        let _ = worker.join();
    }
    std::process::exit(exit_code)
}
