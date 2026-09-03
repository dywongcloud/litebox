// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Execute and inspect built boxes.
//!
//! A box declares its platform; `run` refuses a mismatched host by name
//! instead of letting the runner fault on foreign instructions. Native
//! workloads execute in-process under the litebox Linux userland runner
//! (x86_64-linux hosts today). A workload that is itself a wasm binary is
//! delegated to a wasm runtime found on PATH.

use std::io::Read as _;
use std::path::Path;

use anyhow::{Context, bail};

use crate::boxfmt::{BoxMeta, ParsedBox};

/// Print a box's metadata.
pub fn inspect(box_path: &Path) -> anyhow::Result<()> {
    let parsed = parse_box_file(box_path)?;
    let meta = &parsed.meta;
    println!("format:       {} v{}", meta.format, meta.version);
    println!("platform:     {}/{}", meta.os, meta.architecture);
    println!("rewrite host: {}", meta.rewrite_host);
    println!("source:       {}", meta.source);
    if let Some(entrypoint) = &meta.entrypoint {
        println!("entrypoint:   {entrypoint:?}");
    }
    if let Some(cmd) = &meta.cmd {
        println!("cmd:          {cmd:?}");
    }
    if let Some(workdir) = meta.working_dir.as_deref().filter(|w| !w.is_empty()) {
        println!("workdir:      {workdir}");
    }
    if let Some(user) = meta.user.as_deref().filter(|u| !u.is_empty()) {
        println!("user:         {user}");
    }
    for env in &meta.env {
        println!("env:          {env}");
    }
    if !meta.exposed_ports.is_empty() {
        println!("exposed:      {}", meta.exposed_ports.join(", "));
    }
    println!(
        "rootfs:       {} entries, {} bytes",
        meta.tar_entries, meta.tar_size
    );
    println!("rootfs sha:   {}", meta.tar_sha256);
    Ok(())
}

/// Networking for a run: which TUN device the workload attaches to, and which
/// of its ports are published to the host.
#[derive(Debug, Default)]
pub struct NetOptions {
    pub tun_device: Option<String>,
    /// Host-side address of `tun_device` (the guest's gateway). Paired with
    /// `net_guest_ip`; `None` keeps the default ([`DEFAULT_NET_HOST_IP`]).
    pub net_host_ip: Option<std::net::Ipv4Addr>,
    /// The guest's own address on `tun_device`. Paired with `net_host_ip`;
    /// `None` keeps the default ([`crate::publish::GUEST_IP`]).
    pub net_guest_ip: Option<std::net::Ipv4Addr>,
    pub publish: Vec<String>,
    pub publish_all: bool,
    pub verbose: bool,
}

/// The TUN device used when ports are published without naming one, matching
/// the default in `litebox_platform_linux_userland/scripts/tun-setup.sh`.
const DEFAULT_TUN_DEVICE: &str = "tun99";

/// Default host-side address of a `--net` device (the guest's gateway).
///
/// Defined here, rather than in [`crate::tun`], because that module only
/// compiles on Linux (it configures a real device with Linux-only ioctls),
/// while this default is needed on every host to resolve `--net-host-ip`
/// before `run_native` is called.
pub(crate) const DEFAULT_NET_HOST_IP: std::net::Ipv4Addr = std::net::Ipv4Addr::new(10, 0, 0, 1);

/// Whether two port mappings would try to bind the same host socket -- same
/// host address and transport. TCP and UDP on one port are distinct listeners.
fn clashes(a: &crate::publish::PortMapping, b: &crate::publish::PortMapping) -> bool {
    a.host_addr == b.host_addr && a.protocol == b.protocol
}

/// Run a box: `extra_args` override the image CMD (docker semantics).
/// `extra_env` entries are `KEY=VALUE` pairs merged on top of the image's
/// own baked environment, last-wins on a repeated key -- the mechanism a
/// composition orchestrator uses to inject a peer's address into a box
/// without rebuilding it.
pub fn run(
    box_path: &Path,
    extra_args: &[String],
    extra_env: &[String],
    net: &NetOptions,
) -> anyhow::Result<()> {
    let parsed = parse_box_file(box_path)?;
    let meta = &parsed.meta;

    let host_arch = if cfg!(target_arch = "aarch64") {
        "arm64"
    } else {
        "amd64"
    };
    if meta.architecture != host_arch {
        bail!(
            "this box targets linux/{} but the host is linux/{host_arch}; \
             build a matching variant with `boxer build --platform linux/{host_arch}`",
            meta.architecture
        );
    }

    // Resolve the networking flags before anything else, so a bad -p or an
    // empty --publish-all is reported without first resolving a workload.
    let host_ip = net.net_host_ip.unwrap_or(DEFAULT_NET_HOST_IP);
    let guest_ip = net.net_guest_ip.unwrap_or(crate::publish::GUEST_IP);
    if host_ip == guest_ip {
        bail!("--net-host-ip and --net-guest-ip must be different addresses");
    }
    if host_ip.octets()[..3] != guest_ip.octets()[..3] {
        bail!(
            "--net-host-ip {host_ip} and --net-guest-ip {guest_ip} must be in the same /24 subnet"
        );
    }

    let mut mappings: Vec<crate::publish::PortMapping> = net
        .publish
        .iter()
        .map(|spec| crate::publish::PortMapping::parse(spec))
        .collect::<anyhow::Result<_>>()?;

    // Two explicit -p on the same host address and protocol would otherwise
    // fail later with a bare EADDRINUSE that reads like an external conflict.
    for (i, first) in mappings.iter().enumerate() {
        if let Some(dup) = mappings[i + 1..].iter().find(|other| clashes(first, other)) {
            bail!(
                "host port {}/{} is published more than once",
                dup.host_addr,
                dup.protocol.as_str()
            );
        }
    }

    if net.publish_all {
        if meta.exposed_ports.is_empty() {
            // -P has nothing to add. That is a fatal mistake only when no
            // explicit -p was given either; otherwise the -p mappings stand.
            if mappings.is_empty() {
                bail!(
                    "--publish-all was given but this box EXPOSEs no ports; \
                     publish one explicitly with -p HOST:GUEST"
                );
            }
        } else {
            let from_exposed: Vec<crate::publish::PortMapping> = meta
                .exposed_ports
                .iter()
                .filter_map(|port| crate::publish::PortMapping::from_exposed(port))
                .collect();
            // Guard against a silent no-op: if nothing mappable came out of the
            // EXPOSEd set, -P would set up no listener and no device while the
            // user believes something is served.
            if from_exposed.is_empty() {
                eprintln!(
                    "warning: --publish-all matched no publishable ports from ({})",
                    meta.exposed_ports.join(", ")
                );
            }
            // An explicit -p wins over the same host port derived from EXPOSE,
            // so `-p 8080:80 -P` on a box that EXPOSEs 8080 keeps the 8080->80
            // mapping instead of colliding with a derived 8080->8080.
            for mapping in from_exposed {
                if !mappings.iter().any(|existing| clashes(existing, &mapping)) {
                    mappings.push(mapping);
                }
            }
        }
    }

    let entry_names = tar_entry_names(&parsed.rootfs_tar)?;
    let has_shell = entry_names
        .iter()
        .any(|n| n == "bin/sh" || n == "usr/bin/sh");
    let has_config_script = entry_names.iter().any(|n| n == "litebox/config_and_run.sh");

    // Wasm-native workload? Delegate to a wasm runtime.
    let argv = effective_argv(meta, extra_args)?;
    let program_tar_path = argv
        .first()
        .map(|p| p.trim_start_matches('/').to_string())
        .context("box has no entrypoint, no cmd, and no arguments were given")?;
    if let Some(program_bytes) = tar_entry_bytes(&parsed.rootfs_tar, &program_tar_path)?
        && program_bytes.starts_with(&[0x00, 0x61, 0x73, 0x6d])
    {
        // The wasm runtime has no TUN device, so any publishing or --net flag
        // would be silently dropped -- the user would think a port was served.
        if !mappings.is_empty() || net.tun_device.is_some() {
            bail!(
                "port publishing and --net are not supported for a wasm workload \
                 (the wasm runtime has no network device); run a native box to \
                 publish ports"
            );
        }
        return run_wasm_workload(&program_bytes, &argv, &meta.env);
    }

    // Publishing needs the workload on the network, so it selects a TUN device
    // when none was named rather than binding host ports that reach nothing.
    let tun_device = match (&net.tun_device, mappings.is_empty()) {
        (Some(device), _) => Some(device.clone()),
        (None, false) => Some(String::from(DEFAULT_TUN_DEVICE)),
        (None, true) => None,
    };

    // Create the network device before anything binds to it, so serving a box
    // takes one command rather than a privileged setup step first.
    #[cfg(target_os = "linux")]
    if let Some(device) = &tun_device {
        let created = crate::tun::ensure_device(device, host_ip)?;
        if created {
            eprintln!("Created network device {device} ({host_ip})");
        }
    }

    // Bind before the workload starts: a taken host port is reported now, not
    // after the guest is already running.
    let _published = if mappings.is_empty() {
        None
    } else {
        Some(crate::publish::publish(&mappings, net.verbose, guest_ip)?)
    };

    if tun_device.is_some() && !meta.exposed_ports.is_empty() {
        eprintln!(
            "Box exposes {} on {guest_ip}",
            meta.exposed_ports.join(", "),
        );
    }

    let (program, program_args): (String, Vec<String>) = if has_shell && has_config_script {
        // The config script exports ENV, cds to WORKDIR, and execs either the
        // caller's command or the image default.
        (
            String::from("/litebox/config_and_run.sh"),
            extra_args.to_vec(),
        )
    } else {
        // Shell-less image (e.g. FROM scratch): exec the argv directly. There is
        // no config script to `cd` into WORKDIR first, so the runner's own
        // initial working directory carries that (below) -- including letting a
        // relative ENTRYPOINT/CMD (`["./server"]`) resolve against it, the same
        // way a real exec resolves a relative path against the caller's cwd.
        let mut argv = argv;
        (argv.remove(0), argv)
    };

    run_native(
        &parsed,
        program,
        program_args,
        &merge_env(&meta.env, extra_env),
        meta.working_dir.as_deref(),
        NativeNet {
            tun_device: tun_device.as_deref(),
            guest_ip,
            host_ip,
        },
    )
}

/// Merge `overrides` (`KEY=VALUE`, as given to `-e`) onto `base` (the
/// image's own baked env), last-wins on a repeated key, preserving `base`'s
/// relative order for untouched keys and appending genuinely new keys.
fn merge_env(base: &[String], overrides: &[String]) -> Vec<String> {
    let key = |entry: &str| entry.split('=').next().unwrap_or(entry).to_string();
    let mut merged: Vec<String> = base
        .iter()
        .filter(|entry| !overrides.iter().any(|o| key(o) == key(entry)))
        .cloned()
        .collect();
    merged.extend(overrides.iter().cloned());
    merged
}

/// ENTRYPOINT + (args-or-CMD) merge per OCI semantics.
fn effective_argv(meta: &BoxMeta, extra_args: &[String]) -> anyhow::Result<Vec<String>> {
    let mut argv: Vec<String> = meta.entrypoint.clone().unwrap_or_default();
    if extra_args.is_empty() {
        argv.extend(meta.cmd.clone().unwrap_or_default());
    } else {
        argv.extend(extra_args.iter().cloned());
    }
    if argv.is_empty() {
        bail!("box has no entrypoint, no cmd, and no arguments were given");
    }
    Ok(argv)
}

/// The resolved networking parameters for a native run, grouped so
/// `run_native` takes one struct instead of three separate scalars.
struct NativeNet<'a> {
    tun_device: Option<&'a str>,
    guest_ip: std::net::Ipv4Addr,
    host_ip: std::net::Ipv4Addr,
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn run_native(
    parsed: &ParsedBox,
    program: String,
    args: Vec<String>,
    env: &[String],
    working_dir: Option<&str>,
    net: NativeNet<'_>,
) -> anyhow::Result<()> {
    use std::io::Write as _;

    // The runner mmaps the tar from a path and requires a .tar suffix.
    let mut tar_file = tempfile::Builder::new()
        .suffix(".tar")
        .tempfile()
        .context("failed to create temp tar")?;
    tar_file
        .write_all(&parsed.rootfs_tar)
        .context("failed to write rootfs tar")?;
    tar_file.flush()?;

    let mut program_and_arguments = vec![program];
    program_and_arguments.extend(args);

    let cli = litebox_runner_linux_userland::CliArgs {
        program_and_arguments,
        environment_variables: env.to_vec(),
        forward_environment_variables: false,
        unstable: true,
        insert_files: Vec::new(),
        initial_files: Some(tar_file.path().to_path_buf()),
        rewrite_syscalls: false,
        tun_device_name: net.tun_device.map(String::from),
        program_from_tar: true,
        broker_control_socket: None,
        working_directory: working_dir.filter(|w| !w.is_empty()).map(String::from),
        net_guest_ip: Some(net.guest_ip),
        net_host_ip: Some(net.host_ip),
    };
    litebox_runner_linux_userland::run(cli)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn run_native(
    parsed: &ParsedBox,
    program: String,
    args: Vec<String>,
    env: &[String],
    _working_dir: Option<&str>,
    net: NativeNet<'_>,
) -> anyhow::Result<()> {
    use std::io::Write as _;

    // The runner requires a .tar suffix.
    let mut tar_file = tempfile::Builder::new()
        .suffix(".tar")
        .tempfile()
        .context("failed to create temp tar")?;
    tar_file
        .write_all(&parsed.rootfs_tar)
        .context("failed to write rootfs tar")?;
    tar_file.flush()?;

    let mut program_and_arguments = vec![program];
    program_and_arguments.extend(args);

    let cli = litebox_runner_linux_on_macos_userland::CliArgs {
        program_and_arguments,
        environment_variables: env.to_vec(),
        forward_environment_variables: false,
        unstable: true,
        initial_files: tar_file.path().to_path_buf(),
        tun_device_name: net.tun_device.map(String::from),
    };
    litebox_runner_linux_on_macos_userland::run(cli)
}

#[cfg(not(any(all(target_os = "linux", target_arch = "x86_64"), all(target_os = "macos", target_arch = "aarch64"))))]
fn run_native(
    _parsed: &ParsedBox,
    _program: String,
    _args: Vec<String>,
    _env: &[String],
    _working_dir: Option<&str>,
    _net: NativeNet<'_>,
) -> anyhow::Result<()> {
    bail!(
        "running boxes natively is supported on x86_64 Linux and aarch64 macOS hosts only"
    );
}

/// The workload is itself a wasm module: run it in boxer's own embedded
/// runtime, so a wasm box needs nothing installed on the host.
///
/// The module gets WASI preview 1 with the box's argv, the box's environment,
/// and the host's stdio. It gets no filesystem and no network: a wasm workload
/// that needs those wants capabilities this box format does not describe yet,
/// and silently granting them would be worse than refusing.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn run_wasm_workload(program_bytes: &[u8], argv: &[String], env: &[String]) -> anyhow::Result<()> {
    use wasmtime::{Config, Engine, Linker, Module, Store};
    use wasmtime_wasi::WasiCtxBuilder;
    use wasmtime_wasi::p1::{self, WasiP1Ctx};

    let mut config = Config::new();
    config.wasm_backtrace_details(wasmtime::WasmBacktraceDetails::Enable);
    let engine = Engine::new(&config).context("failed to start the embedded wasm engine")?;
    let module = Module::from_binary(&engine, program_bytes)
        .context("the box workload is not a valid wasm module")?;

    let mut linker: Linker<WasiP1Ctx> = Linker::new(&engine);
    p1::add_to_linker_sync(&mut linker, |ctx: &mut WasiP1Ctx| ctx)
        .context("failed to provide WASI to the workload")?;

    let mut wasi = WasiCtxBuilder::new();
    wasi.inherit_stdio().args(argv);
    for pair in env {
        if let Some((key, value)) = pair.split_once('=') {
            wasi.env(key, value);
        }
    }
    let mut store = Store::new(&engine, wasi.build_p1());

    let instance = linker
        .instantiate(&mut store, &module)
        .context("failed to instantiate the wasm workload")?;
    let start = instance
        .get_typed_func::<(), ()>(&mut store, "_start")
        .context("the wasm workload exports no _start; it is a library, not a command")?;

    match start.call(&mut store, ()) {
        Ok(()) => Ok(()),
        Err(e) => {
            // A WASI command that calls proc_exit unwinds with an exit status
            // rather than a trap; a zero status is a normal return.
            if let Some(exit) = e.downcast_ref::<wasmtime_wasi::I32Exit>() {
                let status: i32 = exit.0;
                if status == 0 {
                    return Ok(());
                }
                bail!("wasm workload exited with status {status}");
            }
            Err(e).context("the wasm workload trapped")
        }
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn run_wasm_workload(program_bytes: &[u8], argv: &[String], env: &[String]) -> anyhow::Result<()> {
    use wasmtime::{Config, Engine, Linker, Module, Store};
    use wasmtime_wasi::WasiCtxBuilder;
    use wasmtime_wasi::p1::{self, WasiP1Ctx};

    let mut config = Config::new();
    config.wasm_backtrace_details(wasmtime::WasmBacktraceDetails::Enable);
    let engine = Engine::new(&config).context("failed to start the embedded wasm engine")?;
    let module = Module::from_binary(&engine, program_bytes)
        .context("the box workload is not a valid wasm module")?;

    let mut linker: Linker<WasiP1Ctx> = Linker::new(&engine);
    p1::add_to_linker_sync(&mut linker, |ctx: &mut WasiP1Ctx| ctx)
        .context("failed to provide WASI to the workload")?;

    let mut wasi = WasiCtxBuilder::new();
    wasi.inherit_stdio().args(argv);
    for pair in env {
        if let Some((key, value)) = pair.split_once('=') {
            wasi.env(key, value);
        }
    }
    let mut store = Store::new(&engine, wasi.build_p1());

    let instance = linker
        .instantiate(&mut store, &module)
        .context("failed to instantiate the wasm workload")?;
    let start = instance
        .get_typed_func::<(), ()>(&mut store, "_start")
        .context("the wasm workload exports no _start; it is a library, not a command")?;

    match start.call(&mut store, ()) {
        Ok(()) => Ok(()),
        Err(e) => {
            // A WASI command that calls proc_exit unwinds with an exit status
            // rather than a trap; a zero status is a normal return.
            if let Some(exit) = e.downcast_ref::<wasmtime_wasi::I32Exit>() {
                let status: i32 = exit.0;
                if status == 0 {
                    return Ok(());
                }
                bail!("wasm workload exited with status {status}");
            }
            Err(e).context("the wasm workload trapped")
        }
    }
}

#[cfg(not(any(all(target_os = "linux", target_arch = "x86_64"), all(target_os = "macos", target_arch = "aarch64"))))]
fn run_wasm_workload(
    _program_bytes: &[u8],
    _argv: &[String],
    _env: &[String],
) -> anyhow::Result<()> {
    bail!("running a wasm workload is supported on x86_64 Linux and aarch64 macOS hosts only")
}

fn parse_box_file(path: &Path) -> anyhow::Result<ParsedBox> {
    let bytes =
        std::fs::read(path).with_context(|| format!("cannot read box {}", path.display()))?;
    crate::boxfmt::parse(&bytes).with_context(|| format!("{} is not a valid box", path.display()))
}

fn tar_entry_names(tar_bytes: &[u8]) -> anyhow::Result<Vec<String>> {
    let mut archive = tar::Archive::new(tar_bytes);
    let mut names = Vec::new();
    for entry in archive.entries().context("box rootfs tar is unreadable")? {
        let entry = entry?;
        names.push(entry.path()?.to_string_lossy().into_owned());
    }
    Ok(names)
}

fn tar_entry_bytes(tar_bytes: &[u8], wanted: &str) -> anyhow::Result<Option<Vec<u8>>> {
    let mut archive = tar::Archive::new(tar_bytes);
    for entry in archive.entries().context("box rootfs tar is unreadable")? {
        let mut entry = entry?;
        if entry.path()?.to_string_lossy() == wanted {
            let mut data = Vec::new();
            entry.read_to_end(&mut data)?;
            return Ok(Some(data));
        }
    }
    Ok(None)
}
