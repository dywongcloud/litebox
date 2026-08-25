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

mod net_proxy;
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
    /// Serve a browser-based viewer for the guest's `/dev/fb0` on this HTTP port: open
    /// `http://127.0.0.1:<port>/` for a canvas with full keyboard and mouse. Same
    /// framebuffer/input plumbing as `--vnc` without needing a VNC client (macOS's built-in
    /// Screen Sharing refuses to dial localhost). Binds `127.0.0.1` only.
    #[arg(
        long = "vnc-web",
        value_name = "PORT",
        requires = "unstable",
        help_heading = "Unstable Options"
    )]
    pub vnc_web: Option<u16>,
    /// Give the guest web access without root: an HTTP proxy (CONNECT + absolute-URI) on the
    /// guest's loopback at `127.0.0.1:3128`, bridged to real host connections. Point the guest
    /// at it (`http_proxy=http://127.0.0.1:3128`, `links -http-proxy 127.0.0.1:3128`). Widens
    /// the Seatbelt profile with `(allow network-outbound)` -- outbound only; inbound stays
    /// denied.
    #[arg(
        long = "net-proxy",
        requires = "unstable",
        help_heading = "Unstable Options"
    )]
    pub net_proxy: bool,
    /// Present the guest with root identity (uid/gid 0) instead of the default synthetic
    /// uid 1000. The identity is synthetic either way -- isolation comes from the litebox
    /// layer, not the guest uid -- but a desktop stack (Xorg's `-nolock`, dbus, session
    /// managers) hard-checks for root in places a single-user appliance image never needs
    /// to distinguish.
    #[arg(
        long = "guest-root",
        requires = "unstable",
        help_heading = "Unstable Options"
    )]
    pub guest_root: bool,
}

/// Translate an RFB `KeyEvent` keysym into the byte sequence a Linux console keyboard would
/// deliver on that key, for feeding the guest's stdin. Latin-1 keysyms are their own byte
/// (X11 keysyms already encode the shifted character); control keys map to the `linux`
/// terminfo sequences. `ctrl` folds letters onto C0 controls the way a terminal does.
/// Returns `None` for keysyms with no console byte representation (bare modifiers,
/// multimedia keys).
fn keysym_to_tty_bytes(keysym: u32, ctrl: bool) -> Option<Vec<u8>> {
    if ctrl {
        // ^A..^Z (either letter case), plus the punctuation controls a terminal produces.
        let c = if (0x61..=0x7a).contains(&keysym) {
            keysym - 0x20
        } else {
            keysym
        };
        if (0x40..=0x5f).contains(&c) {
            return Some(vec![u8::try_from(c & 0x1f).unwrap_or(0)]);
        }
    }
    match keysym {
        // Latin-1 printables (X keysyms 0x20..=0xff are the characters themselves).
        0x20..=0x7e | 0xa0..=0xff => Some(vec![u8::try_from(keysym).unwrap_or(b'?')]),
        0xff0d | 0xff8d => Some(vec![b'\r']), // Return / KP_Enter
        0xff08 => Some(vec![0x7f]),           // BackSpace (linux console sends DEL)
        0xff09 => Some(vec![b'\t']),          // Tab
        0xff1b => Some(vec![0x1b]),           // Escape
        0xff51 => Some(b"\x1b[D".to_vec()),   // Left
        0xff52 => Some(b"\x1b[A".to_vec()),   // Up
        0xff53 => Some(b"\x1b[C".to_vec()),   // Right
        0xff54 => Some(b"\x1b[B".to_vec()),   // Down
        0xff50 => Some(b"\x1b[1~".to_vec()),  // Home
        0xff57 => Some(b"\x1b[4~".to_vec()),  // End
        0xff55 => Some(b"\x1b[5~".to_vec()),  // Page Up
        0xff56 => Some(b"\x1b[6~".to_vec()),  // Page Down
        0xff63 => Some(b"\x1b[2~".to_vec()),  // Insert
        0xffff => Some(b"\x1b[3~".to_vec()),  // Delete
        0xffbe => Some(b"\x1b[[A".to_vec()),  // F1 (linux console)
        0xffbf => Some(b"\x1b[[B".to_vec()),  // F2
        0xffc0 => Some(b"\x1b[[C".to_vec()),  // F3
        0xffc1 => Some(b"\x1b[[D".to_vec()),  // F4
        0xffc2 => Some(b"\x1b[[E".to_vec()),  // F5
        0xffc3 => Some(b"\x1b[17~".to_vec()), // F6
        0xffc4 => Some(b"\x1b[18~".to_vec()), // F7
        0xffc5 => Some(b"\x1b[19~".to_vec()), // F8
        0xffc6 => Some(b"\x1b[20~".to_vec()), // F9
        0xffc7 => Some(b"\x1b[21~".to_vec()), // F10
        _ => None,
    }
}

/// Build the closure that routes one viewer's [`litebox_rfb::InputEvent`]s into the guest:
/// evdev + PS/2-mice injection for pointer events, evdev + tty-byte injection for keys. Each
/// attached viewer (RFB or web) gets its own instance; the small per-viewer state (button
/// mask, Ctrl) means two concurrent viewers behave like two hands on one mouse, exactly as
/// the RFB server's `run` doc comment describes.
fn build_input_handler(
    input_registry: Option<litebox::fs::devices::InputRegistry<Platform>>,
    input_framebuffer: Option<litebox::fs::devices::Framebuffer<Platform>>,
    platform: &'static Platform,
) -> impl Fn(litebox_rfb::InputEvent) + Send + Sync + 'static {
    // RFB `PointerEvent`s carry a whole button-state mask per event; evdev wants
    // per-button transitions. Tracked under a mutex because the handler can be called
    // concurrently from several connected clients' threads.
    let last_buttons = std::sync::Mutex::new(0u8);
    // Control-key state for the tty translation: RFB sends Control_L down, then the letter
    // with its plain keysym, so the modifier must be remembered.
    let ctrl_held = std::sync::atomic::AtomicBool::new(false);
    // Timestamps only need to be monotonic; consumers compare deltas, never absolute values.
    let epoch = std::time::Instant::now();
    move |event| {
        let Some(registry) = input_registry.as_ref() else {
            return;
        };
        let now = epoch.elapsed();
        match event {
            litebox_rfb::InputEvent::Key(key) => {
                if let Some(code) = litebox_rfb::keymap::keysym_to_evdev(key.key) {
                    registry.inject_key(code, key.down, now);
                }
                // Also deliver the key to the guest tty: fbdev-console programs
                // (links2 -g, shells, editors) read the keyboard from stdin, not
                // evdev. Dual delivery is harmless -- a given program only ever
                // consumes one of the two.
                match key.key {
                    0xffe3 | 0xffe4 => {
                        ctrl_held.store(key.down, std::sync::atomic::Ordering::Relaxed);
                    }
                    _ if key.down => {
                        let ctrl = ctrl_held.load(std::sync::atomic::Ordering::Relaxed);
                        if let Some(bytes) = keysym_to_tty_bytes(key.key, ctrl) {
                            platform.inject_stdin(&bytes);
                        }
                    }
                    _ => {}
                }
            }
            litebox_rfb::InputEvent::Pointer(p) => {
                // Scale the RFB screen coordinate into the tablet's fixed 0..=32767
                // range against the *current* framebuffer geometry (resizes included).
                let (width, height) = input_framebuffer.as_ref().map_or((1024, 768), |fb| {
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
                // Also feed `/dev/input/mice` (PS/2 button byte: bit0 left, bit1
                // right, bit2 middle; wheel +1 = scroll down). Consumers read one
                // device or the other, never both.
                let ps2_buttons = (p.button_mask & 0x01)
                    | ((p.button_mask >> 2) & 0x01) << 1
                    | ((p.button_mask >> 1) & 0x01) << 2;
                let wheel = if changed & (1 << 3) != 0 && p.button_mask & (1 << 3) != 0 {
                    -1i8
                } else {
                    i8::from(changed & (1 << 4) != 0 && p.button_mask & (1 << 4) != 0)
                };
                registry.inject_mice_pointer(i32::from(p.x), i32::from(p.y), ps2_buttons, wheel);
            }
        }
    }
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

    // `--vnc`/`--vnc-web` make the viewer keyboard a second stdin producer, so a
    // closed/redirected host stdin must not read as EOF to the guest (a console program
    // would exit on it).
    let platform = Platform::new_with_options(
        cli_args.tun_device_name.as_deref(),
        cli_args.vnc || cli_args.vnc_web.is_some(),
    );
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
        let on_input = build_input_handler(shim.input_registry(), shim.framebuffer(), platform);
        let worker = std::thread::spawn(move || {
            if let Err(e) = server.run(on_input) {
                litebox_util_log::warn!(error:% = e; "vnc server stopped");
            }
        });
        Some((worker, shutdown_handle))
    } else {
        None
    };

    // The browser-based viewer: identical lifecycle to the VNC server (bind + spawn before
    // the sandbox; Seatbelt denies post-sandbox `accept()`), identical input plumbing.
    if let Some(port) = cli_args.vnc_web {
        let framebuffer = shim
            .framebuffer()
            .ok_or_else(|| anyhow!("--vnc-web requires a filesystem that mounts /dev/fb0"))?;
        let server = litebox_rfb::web::WebServer::bind(
            None,
            port,
            std::sync::Arc::new(FramebufferAdapter(framebuffer)),
        )
        .map_err(|e| anyhow!("failed to bind the web viewer listener: {e}"))?;
        litebox_util_log::info!(
            addr:% = server.local_addr().map_err(|e| anyhow!("{e}"))?;
            "web viewer listening -- open http://127.0.0.1 at this port"
        );
        let on_input = build_input_handler(shim.input_registry(), shim.framebuffer(), platform);
        std::thread::spawn(move || {
            if let Err(e) = server.run(on_input) {
                litebox_util_log::warn!(error:% = e; "web viewer server stopped");
            }
        });
    }

    // The guest-web-access bridge. Same lifecycle position and reasoning as the VNC server
    // above: the in-guest listener and the resolver snapshot (`/etc/resolv.conf` becomes
    // unreadable under the sandbox) must both exist before `enable_seatbelt_sandbox*` runs;
    // the widened profile then keeps the bridge's outbound `connect`s working after.
    if cli_args.net_proxy {
        let listener = shim
            .listen_in_guest(std::net::SocketAddr::from(net_proxy::PROXY_ADDR), 16)
            .map_err(|e| anyhow!("failed to start the in-guest proxy listener: {e:?}"))?;
        let resolvers = net_proxy::snapshot_resolvers();
        litebox_util_log::info!(
            addr:? = net_proxy::PROXY_ADDR, resolvers:? = resolvers;
            "guest http proxy listening"
        );
        std::thread::spawn(move || net_proxy::serve(&listener, resolvers));
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
    if cli_args.net_proxy {
        litebox_platform_macos_userland::enable_seatbelt_sandbox_with_outbound_network();
    } else {
        litebox_platform_macos_userland::enable_seatbelt_sandbox();
    }

    let mut task_params = platform.init_task();
    if cli_args.guest_root {
        task_params.uid = 0;
        task_params.euid = 0;
        task_params.gid = 0;
        task_params.egid = 0;
    }
    let program = shim.load_program(initial_file_system, task_params, prog_path, argv, envp)?;

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
