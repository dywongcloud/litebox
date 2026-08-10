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
    println!(
        "rootfs:       {} entries, {} bytes",
        meta.tar_entries, meta.tar_size
    );
    println!("rootfs sha:   {}", meta.tar_sha256);
    Ok(())
}

/// Run a box: `extra_args` override the image CMD (docker semantics).
pub fn run(box_path: &Path, extra_args: &[String]) -> anyhow::Result<()> {
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
        return run_wasm_workload(&program_bytes, &argv);
    }

    let (program, program_args): (String, Vec<String>) = if has_shell && has_config_script {
        // The config script exports ENV, cds to WORKDIR, and execs either the
        // caller's command or the image default.
        (
            String::from("/litebox/config_and_run.sh"),
            extra_args.to_vec(),
        )
    } else {
        // Shell-less image (e.g. FROM scratch): exec the argv directly.
        let mut argv = argv;
        (argv.remove(0), argv)
    };

    run_native(&parsed, program, program_args)
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

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn run_native(parsed: &ParsedBox, program: String, args: Vec<String>) -> anyhow::Result<()> {
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
        environment_variables: parsed.meta.env.clone(),
        forward_environment_variables: false,
        unstable: true,
        insert_files: Vec::new(),
        initial_files: Some(tar_file.path().to_path_buf()),
        rewrite_syscalls: false,
        tun_device_name: None,
        program_from_tar: true,
        broker_control_socket: None,
    };
    litebox_runner_linux_userland::run(cli)
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
fn run_native(_parsed: &ParsedBox, _program: String, _args: Vec<String>) -> anyhow::Result<()> {
    bail!(
        "running boxes natively is supported on x86_64 Linux hosts today; \
         on macOS use litebox_runner_linux_on_macos_userland with the extracted rootfs tar \
         (`boxer inspect` shows the box contents)"
    );
}

/// The workload is itself a wasm module: hand it to a wasm runtime on PATH.
fn run_wasm_workload(program_bytes: &[u8], argv: &[String]) -> anyhow::Result<()> {
    let runtime = ["wasmtime", "wasmer", "wasmedge"]
        .iter()
        .find(|name| which(name).is_some())
        .context(
            "the box workload is a wasm binary but no wasm runtime \
             (wasmtime, wasmer, wasmedge) is on PATH",
        )?;
    let dir = std::env::temp_dir();
    let wasm_path = dir.join(format!("boxer-workload-{}.wasm", std::process::id()));
    std::fs::write(&wasm_path, program_bytes).context("failed to stage wasm workload")?;
    let status = std::process::Command::new(runtime)
        .arg("run")
        .arg(&wasm_path)
        .arg("--")
        .args(&argv[1..])
        .status()
        .with_context(|| format!("failed to launch {runtime}"))?;
    let _ = std::fs::remove_file(&wasm_path);
    if !status.success() {
        bail!("{runtime} exited with {status}");
    }
    Ok(())
}

fn which(name: &str) -> Option<std::path::PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(name))
        .find(|candidate| candidate.is_file())
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
