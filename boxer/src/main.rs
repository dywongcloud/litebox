// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! boxer: build and run OCI container workloads as wasm-carried "boxes".
//!
//! `boxer build` turns a Dockerfile, a registry image, or a local image
//! archive into a `.box.wasm` artifact: a genuine wasm module carrying the
//! image's rootfs with every executable pre-rewritten by the litebox syscall
//! rewriter, for x86-64 or arm64 (or both at once). `boxer run` executes a
//! box under the litebox sandbox on a matching host. See `docs/boxer.md`.

mod boxfmt;
mod dockerfile;
mod publish;
mod run;
#[cfg(target_os = "linux")]
mod tun;

#[cfg(all(
    unix,
    any(
        target_arch = "x86_64",
        all(target_arch = "aarch64", target_vendor = "apple")
    )
))]
mod build;
#[cfg(any(
    target_arch = "x86_64",
    all(target_arch = "aarch64", target_vendor = "apple")
))]
mod image;

use std::path::PathBuf;

use anyhow::bail;
use clap::Parser;

#[derive(Parser, Debug)]
#[command(
    name = "boxer",
    about = "Build and run OCI container workloads as wasm-carried boxes"
)]
enum Cli {
    /// Build a box from a Dockerfile, a registry image, or an image archive.
    Build(BuildArgs),
    /// Run a built box under the litebox sandbox.
    Run {
        /// Path to the .box.wasm artifact.
        box_path: PathBuf,
        /// Attach the workload to this TUN device so its ports are reachable
        /// (see litebox_platform_linux_userland/scripts/tun-setup.sh).
        #[arg(long = "net", value_name = "TUN_DEVICE")]
        net: Option<String>,
        /// Publish a port to the host: PORT, HOST:GUEST, or IP:HOST:GUEST.
        /// Implies --net.
        #[arg(short = 'p', long = "publish", value_name = "SPEC")]
        publish: Vec<String>,
        /// Publish every port the box EXPOSEs, on the same host port.
        /// Implies --net.
        #[arg(short = 'P', long = "publish-all")]
        publish_all: bool,
        /// Print each published connection as it is forwarded.
        #[arg(short = 'v', long = "verbose")]
        verbose: bool,
        /// Arguments overriding the image CMD.
        #[arg(trailing_var_arg = true)]
        args: Vec<String>,
    },
    /// Print a box's embedded metadata.
    Inspect {
        /// Path to the .box.wasm artifact.
        box_path: PathBuf,
    },
}

#[derive(clap::Args, Debug)]
struct BuildArgs {
    /// Build from a Dockerfile or Containerfile. With no source flag at all,
    /// the Containerfile or Dockerfile in the build context is used.
    #[arg(
        short = 'f',
        long = "file",
        value_name = "DOCKERFILE",
        group = "source"
    )]
    dockerfile: Option<PathBuf>,
    /// Build from a registry image reference (e.g. docker.io/library/alpine:latest).
    #[arg(
        short = 'i',
        long = "image",
        value_name = "IMAGE_REF",
        group = "source"
    )]
    image: Option<String>,
    /// Build from a `docker save` archive or OCI layout (directory or tar).
    #[arg(long = "archive", value_name = "PATH", group = "source")]
    archive: Option<PathBuf>,
    /// Target platform(s): linux/amd64, linux/arm64, or both (repeat or
    /// comma-separate). Defaults to the host platform.
    #[arg(long = "platform", value_delimiter = ',')]
    platforms: Vec<String>,
    /// Build context directory for Dockerfile builds (defaults to the
    /// Dockerfile's directory).
    #[arg(long = "context", value_name = "DIR")]
    context: Option<PathBuf>,
    /// Dockerfile ARG values (KEY=VALUE, repeatable).
    #[arg(long = "build-arg", value_name = "KEY=VALUE")]
    args: Vec<String>,
    /// Output path. With multiple platforms, the architecture is suffixed
    /// before the extension. Defaults to `<name>.box.wasm`.
    #[arg(short = 'o', long = "output", value_name = "PATH")]
    output: Option<PathBuf>,
    /// AArch64 syscall-rewrite anchor: the OS that will run arm64 boxes.
    #[arg(long = "rewrite-host", value_parser = ["linux", "macos"], default_value = "linux")]
    rewrite_host: String,
    /// Skip rewriting specific files, named by their image path inside the
    /// rootfs (e.g. /usr/bin/busybox).
    #[arg(long = "no-rewrite", value_name = "PATH")]
    no_rewrite: Vec<PathBuf>,
    /// Verbose progress output.
    #[arg(short = 'v', long = "verbose")]
    verbose: bool,
}

fn main() -> anyhow::Result<()> {
    match Cli::parse() {
        Cli::Build(args) => build_command(&args),
        Cli::Run {
            box_path,
            net,
            publish,
            publish_all,
            verbose,
            args,
        } => run::run(
            &box_path,
            &args,
            &run::NetOptions {
                tun_device: net,
                publish,
                publish_all,
                verbose,
            },
        ),
        Cli::Inspect { box_path } => run::inspect(&box_path),
    }
}

#[cfg(all(
    unix,
    any(
        target_arch = "x86_64",
        all(target_arch = "aarch64", target_vendor = "apple")
    )
))]
fn build_command(args: &BuildArgs) -> anyhow::Result<()> {
    use anyhow::Context as _;
    use image::TargetPlatform;

    let platforms: Vec<TargetPlatform> = if args.platforms.is_empty() {
        vec![TargetPlatform::host()]
    } else {
        let mut list = Vec::new();
        for spec in &args.platforms {
            let platform = if spec == "both" || spec == "all" {
                list.push(TargetPlatform::Amd64);
                list.push(TargetPlatform::Arm64);
                continue;
            } else {
                TargetPlatform::parse(spec)?
            };
            list.push(platform);
        }
        // Drop duplicate platforms regardless of position -- `Vec::dedup` only
        // removes *consecutive* repeats, so `--platform a,b,a` would otherwise
        // build `a` twice (and write the same output file twice).
        let mut seen: Vec<TargetPlatform> = Vec::new();
        list.retain(|p| {
            let fresh = !seen.contains(p);
            if fresh {
                seen.push(*p);
            }
            fresh
        });
        list
    };

    let rewrite_host = match args.rewrite_host.as_str() {
        "macos" => litebox_syscall_rewriter::Host::MacOs,
        _ => litebox_syscall_rewriter::Host::Linux,
    };

    let build_args: Vec<(String, String)> = args
        .args
        .iter()
        .map(|spec| {
            spec.split_once('=')
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .with_context(|| format!("--build-arg expects KEY=VALUE, got: {spec}"))
        })
        .collect::<anyhow::Result<_>>()?;

    // With no source named at all, fall back to the build context's
    // Containerfile or Dockerfile, the way podman and docker do.
    let discovered = match (&args.dockerfile, &args.image, &args.archive) {
        (None, None, None) => Some(discover_container_file(args.context.as_deref())?),
        _ => None,
    };
    let dockerfile_arg = args.dockerfile.clone().or(discovered);

    let multi = platforms.len() > 1;
    for platform in platforms {
        let (extracted, source_label) = match (&dockerfile_arg, &args.image, &args.archive) {
            (Some(dockerfile_path), None, None) => {
                let text = std::fs::read_to_string(dockerfile_path).with_context(|| {
                    format!("cannot read Dockerfile {}", dockerfile_path.display())
                })?;
                let parsed = dockerfile::parse(&text)
                    .with_context(|| format!("parsing {}", dockerfile_path.display()))?;
                let context_dir = match &args.context {
                    Some(dir) => dir.clone(),
                    None => dockerfile_path
                        .parent()
                        .filter(|p| !p.as_os_str().is_empty())
                        .unwrap_or_else(|| std::path::Path::new("."))
                        .to_path_buf(),
                };
                let source_label = format!("dockerfile:{}", dockerfile_path.display());
                let outcome = build::evaluate(
                    &parsed,
                    &build::BuildOptions {
                        context_dir,
                        platform,
                        build_args: build_args.clone(),
                        source_label: source_label.clone(),
                        verbose: args.verbose,
                    },
                )?;
                (outcome, source_label)
            }
            (None, Some(image_ref), None) => {
                eprintln!("Pulling {image_ref} for {platform}...");
                (
                    image::from_registry(image_ref, platform, args.verbose)?,
                    image_ref.clone(),
                )
            }
            (None, None, Some(archive)) => (
                image::from_archive(archive, platform, args.verbose)?,
                archive.display().to_string(),
            ),
            _ => bail!("exactly one of -f/--file, -i/--image, or --archive is required"),
        };

        let output = output_path(args, &source_label, platform, multi);
        emit_box(
            &extracted,
            platform,
            rewrite_host,
            &source_label,
            &args.no_rewrite,
            &output,
            args.verbose,
        )?;
        eprintln!("Built {} ({platform})", output.display());
    }
    Ok(())
}

/// Find the build file when none was named: `Containerfile` first (podman's
/// preference), then `Dockerfile`.
#[cfg(all(
    unix,
    any(
        target_arch = "x86_64",
        all(target_arch = "aarch64", target_vendor = "apple")
    )
))]
fn discover_container_file(context: Option<&std::path::Path>) -> anyhow::Result<PathBuf> {
    let dir = context.unwrap_or_else(|| std::path::Path::new("."));
    for name in ["Containerfile", "Dockerfile"] {
        let candidate = dir.join(name);
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    bail!(
        "no Containerfile or Dockerfile in {}; name one with -f, or build an \
         image with -i/--archive",
        dir.display()
    )
}

#[cfg(all(
    unix,
    any(
        target_arch = "x86_64",
        all(target_arch = "aarch64", target_vendor = "apple")
    )
))]
fn output_path(
    args: &BuildArgs,
    source_label: &str,
    platform: image::TargetPlatform,
    multi: bool,
) -> PathBuf {
    let base = args.output.clone().unwrap_or_else(|| {
        // Derive a name from the source: image ref tail or Dockerfile dir.
        let name: String = source_label
            .rsplit('/')
            .next()
            .unwrap_or("workload")
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == '_' {
                    c
                } else {
                    '-'
                }
            })
            .collect();
        PathBuf::from(format!("{name}.box.wasm"))
    });
    if !multi {
        return base;
    }
    let stem = base
        .to_string_lossy()
        .trim_end_matches(".box.wasm")
        .trim_end_matches(".wasm")
        .to_string();
    PathBuf::from(format!("{stem}-{}.box.wasm", platform.oci_arch_name()))
}

#[cfg(all(
    unix,
    any(
        target_arch = "x86_64",
        all(target_arch = "aarch64", target_vendor = "apple")
    )
))]
fn emit_box(
    extracted: &litebox_packager::oci::ExtractedImage,
    platform: image::TargetPlatform,
    rewrite_host: litebox_syscall_rewriter::Host,
    source_label: &str,
    no_rewrite: &[PathBuf],
    output: &std::path::Path,
    verbose: bool,
) -> anyhow::Result<()> {
    use anyhow::Context as _;

    // `--no-rewrite` names an image path (the files live in an ephemeral temp
    // dir); match on the rootfs-relative tar-path, not a host path.
    let no_rewrite = no_rewrite
        .iter()
        .map(|p| litebox_packager::image_tar_path(p))
        .collect();
    let tar_entries = litebox_packager::package_extracted_image(
        extracted,
        &litebox_packager::PackageOptions {
            elf_machine: platform.elf_machine(),
            rewrite_host,
            no_rewrite,
            verbose,
        },
    )?;

    // Build the rootfs tar in a temp file, then embed it.
    let tar_temp = tempfile::NamedTempFile::new().context("failed to create temp tar")?;
    litebox_packager::build_tar(&tar_entries, tar_temp.path())?;
    let tar_bytes = std::fs::read(tar_temp.path()).context("failed to read packaged tar")?;

    let meta = boxfmt::BoxMeta {
        format: String::from("litebox-box"),
        version: 1,
        os: String::from("linux"),
        architecture: platform.oci_arch_name().to_string(),
        rewrite_host: match rewrite_host {
            litebox_syscall_rewriter::Host::MacOs => String::from("macos"),
            litebox_syscall_rewriter::Host::Linux => String::from("linux"),
        },
        source: source_label.to_string(),
        entrypoint: extracted.config.entrypoint.clone(),
        cmd: extracted.config.cmd.clone(),
        env: extracted.config.env.clone().unwrap_or_default(),
        working_dir: extracted.config.working_dir.clone(),
        exposed_ports: extracted.config.exposed_ports.clone(),
        user: extracted.config.user.clone(),
        tar_entries: tar_entries.len() as u64,
        tar_size: tar_bytes.len() as u64,
        tar_sha256: boxfmt::sha256_hex(&tar_bytes),
    };

    let module = boxfmt::encode(&meta, &tar_bytes)?;
    std::fs::write(output, &module)
        .with_context(|| format!("failed to write {}", output.display()))?;
    Ok(())
}

#[cfg(not(all(
    unix,
    any(
        target_arch = "x86_64",
        all(target_arch = "aarch64", target_vendor = "apple")
    )
)))]
fn build_command(_args: &BuildArgs) -> anyhow::Result<()> {
    bail!(
        "boxer build needs the OCI toolchain, which is available on x86-64 \
         and Apple Silicon Unix hosts (see litebox_packager's Cargo.toml for why); \
         boxer run and boxer inspect work everywhere"
    );
}
