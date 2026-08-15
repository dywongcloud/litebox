// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Dockerfile evaluation: turn a parsed [`Dockerfile`] into a rootfs plus an
//! OCI image config, without a container engine.
//!
//! `FROM` bases come from registries (or `scratch`, or earlier stages),
//! `COPY`/`ADD` move files from the build context, and `RUN` executes inside
//! a chroot of the in-progress rootfs. The final workload gets the litebox
//! sandbox at run time; the build itself needs real filesystem mutation,
//! which litebox's in-memory tar filesystem deliberately does not persist,
//! so chroot -- requiring root and a host-matching architecture -- is the
//! honest builder substrate.

use std::collections::HashMap;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use litebox_packager::oci::{ExtractedImage, ImageConfig};

use crate::dockerfile::{self, ArgDecl, Command, CopyFlags, Dockerfile, Heredoc, Instruction};
use crate::image::TargetPlatform;

pub struct BuildOptions {
    /// Build context directory; COPY/ADD sources resolve under it.
    pub context_dir: PathBuf,
    pub platform: TargetPlatform,
    /// `--build-arg KEY=VALUE` values.
    pub build_args: Vec<(String, String)>,
    /// Description recorded in the box metadata (e.g. `dockerfile:./Dockerfile`).
    pub source_label: String,
    pub verbose: bool,
}

/// Evaluate a Dockerfile to the final stage's extracted image.
pub fn evaluate(dockerfile: &Dockerfile, options: &BuildOptions) -> anyhow::Result<ExtractedImage> {
    let context_dir = std::fs::canonicalize(&options.context_dir).with_context(|| {
        format!(
            "build context {} does not exist",
            options.context_dir.display()
        )
    })?;
    let ignore = DockerIgnore::load(&context_dir);
    let build_args: HashMap<String, String> = options.build_args.iter().cloned().collect();

    // Stage names must be unique: a duplicate would make `COPY --from=<name>`
    // ambiguous, silently resolving to the first. Reject it as buildkit does.
    // Names are case-insensitive, matching docker.
    let mut seen_stage_names: HashMap<String, usize> = HashMap::new();
    for stage in &dockerfile.stages {
        if let Some(name) = &stage.name
            && let Some(prev) = seen_stage_names.insert(name.to_ascii_lowercase(), stage.line)
        {
            bail!(
                "line {}: duplicate stage name '{name}' (already defined at line {prev})",
                stage.line
            );
        }
    }

    let mut stages: Vec<StageState> = Vec::new();
    // Extracted external images pulled for `COPY --from=<image>`.
    let mut external_images: HashMap<String, ExtractedImage> = HashMap::new();

    for stage in &dockerfile.stages {
        // FROM arguments see the pre-FROM ARG scope only.
        let from_lookup = |name: &str| -> Option<String> {
            build_args.get(name).cloned().or_else(|| {
                dockerfile
                    .pre_from_args
                    .iter()
                    .find(|a| a.name == name)
                    .and_then(|a| a.default.clone())
            })
        };
        let base_ref = dockerfile::substitute(&stage.base, &from_lookup);
        let stage_platform = match &stage.platform {
            Some(raw) => {
                let expanded = dockerfile::substitute(raw, &from_lookup);
                TargetPlatform::parse(&expanded)
                    .with_context(|| format!("line {}: FROM --platform={expanded}", stage.line))?
            }
            None => options.platform,
        };

        let mut state = base_stage_state(&base_ref, stage_platform, &stages, options.verbose)
            .with_context(|| format!("line {}: FROM {base_ref}", stage.line))?;
        state.name.clone_from(&stage.name);

        for (line, instruction) in &stage.instructions {
            apply_instruction(
                instruction,
                &mut state,
                &context_dir,
                &ignore,
                &build_args,
                &stages,
                &mut external_images,
                options,
            )
            .with_context(|| format!("line {line}"))?;
        }

        stages.push(state);
    }

    let last = stages.pop().expect("parser guarantees at least one stage");
    finalize_stage(last, options)
}

/// Per-stage mutable state.
struct StageState {
    name: Option<String>,
    tempdir: tempfile::TempDir,
    rootfs: PathBuf,
    /// Symlink map inherited from the base image extraction (dir symlinks are
    /// expanded from it at scan time).
    symlink_map: HashMap<PathBuf, PathBuf>,
    platform: TargetPlatform,
    config: ConfigState,
}

/// Accumulated image-config state.
#[derive(Clone, Default)]
struct ConfigState {
    env: Vec<(String, String)>,
    /// ARGs declared in this stage, with their effective values.
    args: HashMap<String, Option<String>>,
    labels: Vec<(String, String)>,
    entrypoint: Option<Vec<String>>,
    cmd: Option<Vec<String>>,
    workdir: String,
    user: Option<String>,
    exposed: Vec<String>,
    volumes: Vec<String>,
    shell: Vec<String>,
    stop_signal: Option<String>,
    healthcheck: Option<String>,
    onbuild: Vec<String>,
}

impl ConfigState {
    fn lookup(&self, build_args: &HashMap<String, String>, name: &str) -> Option<String> {
        if let Some((_, v)) = self.env.iter().rev().find(|(k, _)| k == name) {
            return Some(v.clone());
        }
        if let Some(declared) = self.args.get(name) {
            if let Some(value) = build_args.get(name) {
                return Some(value.clone());
            }
            return declared.clone();
        }
        None
    }

    fn shell(&self) -> Vec<String> {
        if self.shell.is_empty() {
            vec![String::from("/bin/sh"), String::from("-c")]
        } else {
            self.shell.clone()
        }
    }
}

fn base_stage_state(
    base_ref: &str,
    platform: TargetPlatform,
    stages: &[StageState],
    verbose: bool,
) -> anyhow::Result<StageState> {
    // Previous stage by name or index?
    if let Some(previous) = resolve_stage(stages, base_ref) {
        let tempdir = tempfile::tempdir().context("failed to create stage directory")?;
        let rootfs = tempdir.path().join("rootfs");
        copy_tree(&stages[previous].rootfs, &rootfs)?;
        return Ok(StageState {
            name: None,
            rootfs,
            tempdir,
            symlink_map: stages[previous].symlink_map.clone(),
            platform: stages[previous].platform,
            config: stages[previous].config.clone(),
        });
    }

    if base_ref == "scratch" {
        let tempdir = tempfile::tempdir().context("failed to create stage directory")?;
        let rootfs = tempdir.path().join("rootfs");
        std::fs::create_dir_all(&rootfs)?;
        return Ok(StageState {
            name: None,
            rootfs,
            tempdir,
            symlink_map: HashMap::new(),
            platform,
            config: ConfigState::default(),
        });
    }

    let extracted = crate::image::from_registry(base_ref, platform, verbose)?;
    let config = config_state_from_image(&extracted.config);
    let ExtractedImage {
        tempdir,
        rootfs_path,
        symlink_map,
        ..
    } = extracted;
    materialize_os_symlinks(&rootfs_path, &symlink_map)?;
    Ok(StageState {
        name: None,
        rootfs: rootfs_path,
        tempdir,
        symlink_map,
        platform,
        config,
    })
}

/// The packager's cross-platform extraction records symlinks in a map and
/// leaves directory symlinks as empty placeholder directories (they are
/// expanded at tar-scan time). A chroot RUN, though, resolves paths through
/// the real filesystem -- `/bin/sh` must actually reach `usr/bin/sh` on disk.
/// On the Linux build host we can afford real OS symlinks: replace empty
/// placeholders (and create missing link paths) with genuine symlinks, whose
/// absolute targets resolve correctly inside the chroot.
fn materialize_os_symlinks(
    rootfs: &Path,
    symlink_map: &HashMap<PathBuf, PathBuf>,
) -> anyhow::Result<()> {
    for (rel, target) in symlink_map {
        let host = rootfs.join(rel);
        match std::fs::symlink_metadata(&host) {
            Err(_) => {}
            Ok(metadata) if metadata.is_dir() => {
                // Only an EMPTY directory is a placeholder; a populated one
                // was really extracted as a directory in an upper layer.
                if std::fs::read_dir(&host).is_ok_and(|mut d| d.next().is_some()) {
                    continue;
                }
                std::fs::remove_dir(&host)
                    .with_context(|| format!("replacing placeholder dir {}", host.display()))?;
            }
            Ok(_) => continue,
        }
        if let Some(parent) = host.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::os::unix::fs::symlink(target, &host).with_context(|| {
            format!(
                "materializing symlink {} -> {}",
                host.display(),
                target.display()
            )
        })?;
    }
    Ok(())
}

fn config_state_from_image(image: &ImageConfig) -> ConfigState {
    ConfigState {
        env: image
            .env
            .iter()
            .flatten()
            .filter_map(|pair| {
                pair.split_once('=')
                    .map(|(k, v)| (k.to_string(), v.to_string()))
            })
            .collect(),
        entrypoint: image.entrypoint.clone(),
        cmd: image.cmd.clone(),
        workdir: image.working_dir.clone().unwrap_or_default(),
        ..ConfigState::default()
    }
}

fn resolve_stage(stages: &[StageState], reference: &str) -> Option<usize> {
    if let Ok(index) = reference.parse::<usize>()
        && index < stages.len()
    {
        return Some(index);
    }
    stages
        .iter()
        .position(|s| s.name.as_deref() == Some(reference))
}

#[allow(
    clippy::too_many_arguments,
    reason = "single dispatch point for all instruction kinds"
)]
fn apply_instruction(
    instruction: &Instruction,
    state: &mut StageState,
    context_dir: &Path,
    ignore: &DockerIgnore,
    build_args: &HashMap<String, String>,
    stages: &[StageState],
    external_images: &mut HashMap<String, ExtractedImage>,
    options: &BuildOptions,
) -> anyhow::Result<()> {
    let expand = |state: &StageState, text: &str| -> String {
        dockerfile::substitute(text, &|name| state.config.lookup(build_args, name))
    };

    match instruction {
        Instruction::Env(pairs) => {
            for (key, value) in pairs {
                let value = expand(state, value);
                state.config.env.retain(|(k, _)| k != key);
                state.config.env.push((key.clone(), value));
            }
        }
        Instruction::Arg(decls) => {
            for ArgDecl { name, default } in decls {
                let default = default.as_ref().map(|d| expand(state, d));
                state.config.args.insert(name.clone(), default);
            }
        }
        Instruction::Label(pairs) => {
            for (key, value) in pairs {
                let value = expand(state, value);
                state.config.labels.retain(|(k, _)| k != key);
                state.config.labels.push((key.clone(), value));
            }
        }
        Instruction::Maintainer(name) => {
            let value = expand(state, name);
            state
                .config
                .labels
                .retain(|(k, _)| k != "org.opencontainers.image.authors");
            state
                .config
                .labels
                .push((String::from("org.opencontainers.image.authors"), value));
        }
        Instruction::Workdir(dir) => {
            let dir = expand(state, dir);
            let new_workdir = if dir.starts_with('/') {
                dir
            } else if state.config.workdir.is_empty() {
                format!("/{dir}")
            } else {
                format!("{}/{dir}", state.config.workdir.trim_end_matches('/'))
            };
            let host_dir = state.rootfs.join(normalize_rel(&new_workdir));
            std::fs::create_dir_all(&host_dir).with_context(|| format!("WORKDIR {new_workdir}"))?;
            state.config.workdir = new_workdir;
        }
        Instruction::User(user) => state.config.user = Some(expand(state, user)),
        Instruction::Expose(ports) => {
            for port in ports {
                for normalized in expand_exposed_port(&expand(state, port))? {
                    state.config.exposed.push(normalized);
                }
            }
            // Dedupe once, not with a linear scan per port: EXPOSE of a large
            // range (a valid single line) is otherwise quadratic.
            state.config.exposed.sort();
            state.config.exposed.dedup();
        }
        Instruction::Volume(volumes) => {
            for volume in volumes {
                let volume = expand(state, volume);
                if !state.config.volumes.contains(&volume) {
                    state.config.volumes.push(volume);
                }
            }
        }
        Instruction::Shell(shell) => state.config.shell.clone_from(shell),
        Instruction::StopSignal(signal) => {
            state.config.stop_signal = Some(expand(state, signal));
        }
        Instruction::Healthcheck(spec) => state.config.healthcheck = Some(spec.clone()),
        Instruction::Onbuild(spec) => state.config.onbuild.push(spec.clone()),
        Instruction::Cmd(command) => {
            state.config.cmd = Some(command_to_argv(command, &state.config));
        }
        Instruction::Entrypoint(command) => {
            state.config.entrypoint = Some(command_to_argv(command, &state.config));
            // Docker semantics: a new ENTRYPOINT resets any CMD inherited
            // from the base image.
            state.config.cmd = None;
        }
        Instruction::Copy {
            flags,
            sources,
            dest,
            heredocs,
        } => {
            let dest = expand(state, dest);
            let sources: Vec<String> = sources.iter().map(|s| expand(state, s)).collect();
            let source_root = copy_source_root(
                flags,
                stages,
                external_images,
                state.platform,
                options.verbose,
            )?;
            apply_copy(
                state,
                &sources,
                &dest,
                flags,
                heredocs,
                source_root.as_deref(),
                context_dir,
                ignore,
                false,
            )?;
        }
        Instruction::Add {
            flags,
            sources,
            dest,
            heredocs,
        } => {
            let dest = expand(state, dest);
            let sources: Vec<String> = sources.iter().map(|s| expand(state, s)).collect();
            let source_root = copy_source_root(
                flags,
                stages,
                external_images,
                state.platform,
                options.verbose,
            )?;
            apply_copy(
                state,
                &sources,
                &dest,
                flags,
                heredocs,
                source_root.as_deref(),
                context_dir,
                ignore,
                true,
            )?;
        }
        Instruction::Run { command, heredocs } => {
            run_in_chroot(state, command, heredocs, build_args, options)?;
        }
    }
    Ok(())
}

/// Normalize one `EXPOSE` argument into `port/proto` entries: a bare port
/// means TCP, `port/proto` keeps its protocol, and `lo-hi` expands to every
/// port in the range. Ports outside 1-65535, empty ranges, reversed ranges and
/// protocols other than tcp/udp are rejected by name.
fn expand_exposed_port(spec: &str) -> anyhow::Result<Vec<String>> {
    let spec = spec.trim();
    if spec.is_empty() {
        bail!("EXPOSE needs a port");
    }
    let (ports, proto) = match spec.split_once('/') {
        Some((ports, proto)) => (ports, proto.to_ascii_lowercase()),
        None => (spec, String::from("tcp")),
    };
    if proto != "tcp" && proto != "udp" {
        bail!("EXPOSE protocol must be tcp or udp, got '{proto}' in '{spec}'");
    }

    let parse_port = |text: &str| -> anyhow::Result<u16> {
        let port: u32 = text
            .trim()
            .parse()
            .with_context(|| format!("EXPOSE port '{text}' is not a number"))?;
        u16::try_from(port)
            .ok()
            .filter(|p| *p != 0)
            .with_context(|| format!("EXPOSE port {port} is outside 1-65535"))
    };

    let (first, last) = if let Some((lo, hi)) = ports.split_once('-') {
        (parse_port(lo)?, parse_port(hi)?)
    } else {
        let only = parse_port(ports)?;
        (only, only)
    };
    if first > last {
        bail!("EXPOSE range '{spec}' ends before it starts");
    }
    Ok((first..=last)
        .map(|port| format!("{port}/{proto}"))
        .collect())
}

fn command_to_argv(command: &Command, config: &ConfigState) -> Vec<String> {
    match command {
        Command::Exec(argv) => argv.clone(),
        Command::Shell(text) => {
            let mut argv = config.shell();
            argv.push(text.clone());
            argv
        }
    }
}

/// Resolve `COPY --from=`: a previous stage's rootfs or an external image
/// (pulled once and cached). Returns the rootfs to copy from, or None for the
/// build context.
fn copy_source_root(
    flags: &CopyFlags,
    stages: &[StageState],
    external_images: &mut HashMap<String, ExtractedImage>,
    platform: TargetPlatform,
    verbose: bool,
) -> anyhow::Result<Option<PathBuf>> {
    let Some(from) = &flags.from else {
        return Ok(None);
    };
    if let Some(stage) = resolve_stage(stages, from) {
        return Ok(Some(stages[stage].rootfs.clone()));
    }
    if !external_images.contains_key(from) {
        let extracted = crate::image::from_registry(from, platform, verbose)
            .with_context(|| format!("COPY --from={from}: not a stage and not a pullable image"))?;
        external_images.insert(from.clone(), extracted);
    }
    Ok(Some(
        external_images
            .get(from)
            .expect("inserted above")
            .rootfs_path
            .clone(),
    ))
}

#[allow(
    clippy::too_many_arguments,
    reason = "COPY and ADD share every parameter"
)]
fn apply_copy(
    state: &mut StageState,
    sources: &[String],
    dest: &str,
    flags: &CopyFlags,
    heredocs: &[Heredoc],
    source_root: Option<&Path>,
    context_dir: &Path,
    ignore: &DockerIgnore,
    is_add: bool,
) -> anyhow::Result<()> {
    let chmod: Option<u32> = flags
        .chmod
        .as_ref()
        .map(|m| u32::from_str_radix(m, 8).with_context(|| format!("invalid --chmod={m}")))
        .transpose()?;

    // Destination resolves against the workdir, inside the rootfs.
    let dest_is_dir = dest.ends_with('/') || sources.len() + heredocs.len() > 1;
    let abs_dest = if dest.starts_with('/') {
        dest.to_string()
    } else if state.config.workdir.is_empty() {
        format!("/{dest}")
    } else {
        format!("{}/{dest}", state.config.workdir.trim_end_matches('/'))
    };
    let dest_rel = normalize_rel(&abs_dest);
    let dest_host = state.rootfs.join(&dest_rel);

    // Heredoc form: each heredoc becomes a file.
    if !heredocs.is_empty() {
        for heredoc in heredocs {
            let target = if dest_is_dir {
                dest_host.join(&heredoc.name)
            } else {
                dest_host.clone()
            };
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&target, heredoc.body.as_bytes())
                .with_context(|| format!("writing heredoc to {}", target.display()))?;
            set_mode(&target, chmod.unwrap_or(0o644))?;
        }
        return Ok(());
    }

    let (walk_root, enforce_ignore): (&Path, bool) = match source_root {
        Some(root) => (root, false),
        None => (context_dir, true),
    };

    for source in sources {
        if is_add && (source.starts_with("http://") || source.starts_with("https://")) {
            add_url(source, &dest_host, dest_is_dir, chmod)?;
            continue;
        }

        let matches = match_sources(walk_root, source, enforce_ignore.then_some(ignore))
            .with_context(|| format!("COPY/ADD source {source}"))?;
        if matches.is_empty() {
            bail!(
                "source {source} matches no files in {}",
                walk_root.display()
            );
        }

        for matched in matches {
            // Containment: the matched path must stay under the source root
            // even through symlinks.
            let canonical = std::fs::canonicalize(&matched)
                .with_context(|| format!("cannot resolve {}", matched.display()))?;
            let canonical_root = std::fs::canonicalize(walk_root)?;
            if !canonical.starts_with(&canonical_root) {
                bail!(
                    "source {} escapes the build context via symlink",
                    matched.display()
                );
            }

            if canonical.is_dir() {
                // Directory sources copy their contents into dest. A context
                // copy filters each file through .dockerignore; the tree's
                // context-relative path is the ignore base.
                let dir_ignore = if enforce_ignore {
                    let base = canonical
                        .strip_prefix(&canonical_root)
                        .unwrap_or(Path::new(""));
                    Some((ignore, base))
                } else {
                    None
                };
                copy_dir_contents(&canonical, &dest_host, chmod, dir_ignore)?;
            } else {
                let is_archive = is_add && looks_like_tar(&canonical)?;
                if is_archive {
                    extract_local_tar(&canonical, &dest_host)?;
                } else {
                    let file_dest = if dest_is_dir || dest_host.is_dir() {
                        dest_host.join(canonical.file_name().context("source has no file name")?)
                    } else {
                        dest_host.clone()
                    };
                    if let Some(parent) = file_dest.parent() {
                        std::fs::create_dir_all(parent)?;
                    }
                    std::fs::copy(&canonical, &file_dest).with_context(|| {
                        format!("copy {} -> {}", canonical.display(), file_dest.display())
                    })?;
                    if let Some(mode) = chmod {
                        set_mode(&file_dest, mode)?;
                    }
                }
            }
        }
    }
    Ok(())
}

/// ADD with a URL source: fetch it in-process, following redirects and
/// honouring the proxy environment, so the build host needs no `curl`.
fn add_url(
    url: &str,
    dest_host: &Path,
    dest_is_dir: bool,
    chmod: Option<u32>,
) -> anyhow::Result<()> {
    let file_name = url
        .rsplit('/')
        .next()
        .filter(|n| !n.is_empty())
        .unwrap_or("download");
    let target = if dest_is_dir || dest_host.is_dir() {
        dest_host.join(file_name)
    } else {
        dest_host.to_path_buf()
    };
    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let client = reqwest::blocking::Client::builder()
        .build()
        .context("failed to build the HTTP client for ADD")?;
    let response = client
        .get(url)
        .send()
        .with_context(|| format!("ADD {url} failed"))?;
    let status = response.status();
    if !status.is_success() {
        bail!("ADD {url} failed: server returned {status}");
    }
    let body = response
        .bytes()
        .with_context(|| format!("ADD {url} failed while reading the response"))?;
    std::fs::write(&target, &body)
        .with_context(|| format!("failed to write {}", target.display()))?;

    set_mode(&target, chmod.unwrap_or(0o600))?;
    Ok(())
}

/// Match a COPY/ADD source pattern against the filesystem. Supports `*` and
/// `?` within path components (Go filepath.Match semantics, no `**`).
fn match_sources(
    root: &Path,
    pattern: &str,
    ignore: Option<&DockerIgnore>,
) -> anyhow::Result<Vec<PathBuf>> {
    let pattern = pattern.trim_start_matches('/');
    let pattern_rel = normalize_rel(pattern);
    if !pattern.contains(['*', '?']) {
        let direct = root.join(&pattern_rel);
        if direct.exists() {
            if let Some(ignore) = ignore
                && ignore.excluded(&pattern_rel)
            {
                return Ok(Vec::new());
            }
            return Ok(vec![direct]);
        }
        return Ok(Vec::new());
    }

    let components: Vec<String> = pattern_rel
        .components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect();
    let mut matches = Vec::new();
    glob_walk(root, &components, PathBuf::new(), ignore, &mut matches)?;
    Ok(matches)
}

fn glob_walk(
    dir: &Path,
    components: &[String],
    rel_so_far: PathBuf,
    ignore: Option<&DockerIgnore>,
    matches: &mut Vec<PathBuf>,
) -> anyhow::Result<()> {
    let Some((first, rest)) = components.split_first() else {
        return Ok(());
    };
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Ok(());
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if !component_match(first, &name) {
            continue;
        }
        let rel = rel_so_far.join(&name);
        if let Some(ignore) = ignore
            && ignore.excluded(&rel)
        {
            continue;
        }
        let path = entry.path();
        if rest.is_empty() {
            matches.push(path);
        } else if path.is_dir() {
            glob_walk(&path, rest, rel, ignore, matches)?;
        }
    }
    Ok(())
}

/// Single-component glob: `*` any run, `?` one char.
fn component_match(pattern: &str, name: &str) -> bool {
    fn matcher(p: &[char], n: &[char]) -> bool {
        match (p.first(), n.first()) {
            (None, None) => true,
            (Some('*'), _) => matcher(&p[1..], n) || (!n.is_empty() && matcher(p, &n[1..])),
            (Some('?'), Some(_)) => matcher(&p[1..], &n[1..]),
            (Some(pc), Some(nc)) if pc == nc => matcher(&p[1..], &n[1..]),
            _ => false,
        }
    }
    let p: Vec<char> = pattern.chars().collect();
    let n: Vec<char> = name.chars().collect();
    matcher(&p, &n)
}

/// Copy a directory tree into `dest`. When `ignore` is `Some((rules, base))`,
/// each file is filtered by `.dockerignore` using its path relative to the
/// build context -- `base` is the tree's own context-relative path, so a
/// `COPY .` and a `COPY subdir` both match ignore patterns the same way docker
/// does. `base` is empty for a whole-context copy.
fn copy_dir_contents(
    src: &Path,
    dest: &Path,
    chmod: Option<u32>,
    ignore: Option<(&DockerIgnore, &Path)>,
) -> anyhow::Result<()> {
    std::fs::create_dir_all(dest)?;
    for entry in walkdir::WalkDir::new(src).follow_links(false) {
        let entry = entry.context("walking source directory")?;
        let rel = entry
            .path()
            .strip_prefix(src)
            .expect("walkdir yields children of src");
        if rel.as_os_str().is_empty() {
            continue;
        }
        if let Some((rules, base)) = ignore
            && rules.excluded(&base.join(rel))
        {
            continue;
        }
        let target = dest.join(rel);
        if entry.file_type().is_dir() {
            std::fs::create_dir_all(&target)?;
        } else if entry.file_type().is_symlink() {
            // Preserve symlinks inside copied trees (Linux build hosts).
            let link = std::fs::read_link(entry.path())?;
            let _ = std::fs::remove_file(&target);
            std::os::unix::fs::symlink(&link, &target).with_context(|| {
                format!(
                    "creating symlink {} -> {}",
                    target.display(),
                    link.display()
                )
            })?;
        } else {
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::copy(entry.path(), &target).with_context(|| {
                format!("copy {} -> {}", entry.path().display(), target.display())
            })?;
            if let Some(mode) = chmod {
                set_mode(&target, mode)?;
            }
        }
    }
    Ok(())
}

/// Copy a whole tree preserving modes and symlinks (stage snapshots).
fn copy_tree(src: &Path, dest: &Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(dest)?;
    copy_dir_contents(src, dest, None, None)?;
    // Preserve modes from the source tree.
    for entry in walkdir::WalkDir::new(src).follow_links(false) {
        let entry = entry?;
        if !entry.file_type().is_file() {
            continue;
        }
        let rel = entry.path().strip_prefix(src).expect("child of src");
        if let Ok(metadata) = entry.metadata() {
            set_mode(&dest.join(rel), metadata.mode() & 0o7777)?;
        }
    }
    Ok(())
}

fn looks_like_tar(path: &Path) -> anyhow::Result<bool> {
    let data = std::fs::read(path)?;
    // gzip and zstd archives are assumed to be tarballs in ADD position.
    if data.len() >= 2 && data[..2] == [0x1f, 0x8b] {
        return Ok(true);
    }
    if data.len() >= 4 && data[..4] == [0x28, 0xb5, 0x2f, 0xfd] {
        return Ok(true);
    }
    // ustar magic at offset 257.
    Ok(data.len() > 262 && &data[257..262] == b"ustar")
}

fn extract_local_tar(path: &Path, dest: &Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(dest)?;
    let data = std::fs::read(path)?;
    let unpack = |reader: Box<dyn std::io::Read>| -> anyhow::Result<()> {
        let mut archive = tar::Archive::new(reader);
        archive.set_preserve_permissions(true);
        for entry in archive.entries()? {
            let mut entry = entry?;
            let rel = normalize_rel(&entry.path()?.to_string_lossy());
            let target = dest.join(rel);
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent)?;
            }
            entry.unpack(&target)?;
        }
        Ok(())
    };
    if data.len() >= 2 && data[..2] == [0x1f, 0x8b] {
        unpack(Box::new(flate2::read::GzDecoder::new(&data[..])))
    } else if data.len() >= 4 && data[..4] == [0x28, 0xb5, 0x2f, 0xfd] {
        let decoder = ruzstd::decoding::StreamingDecoder::new(&data[..])
            .context("initializing zstd decoder for ADD archive")?;
        unpack(Box::new(decoder))
    } else {
        unpack(Box::new(&data[..]))
    }
    .with_context(|| format!("extracting {} into {}", path.display(), dest.display()))
}

/// The RUN shell-form command line with its heredoc marker tokens
/// (`<<NAME`, `<<-NAME`, `<<"NAME"`, ...) removed, trimmed. Empty means the
/// RUN had no command of its own -- a `RUN <<EOF` whose body is the script --
/// versus `RUN python3 <<EOF`, which runs `python3` with the body as input.
fn command_without_heredoc_markers(line: &str, heredocs: &[Heredoc]) -> String {
    let mut remaining = line.to_string();
    for heredoc in heredocs {
        let name = &heredoc.name;
        for marker in [
            format!("<<{name}"),
            format!("<<-{name}"),
            format!("<<\"{name}\""),
            format!("<<-\"{name}\""),
            format!("<<'{name}'"),
            format!("<<-'{name}'"),
        ] {
            if let Some(pos) = remaining.find(&marker) {
                remaining.replace_range(pos..pos + marker.len(), "");
                break;
            }
        }
    }
    remaining.trim().to_string()
}

/// Execute RUN inside a chroot of the stage rootfs.
fn run_in_chroot(
    state: &mut StageState,
    command: &Command,
    heredocs: &[Heredoc],
    build_args: &HashMap<String, String>,
    options: &BuildOptions,
) -> anyhow::Result<()> {
    if state.platform != TargetPlatform::host() {
        bail!(
            "RUN requires executing {} binaries, but this build host is {}; \
             build the {} variant on a matching host or drop the RUN instructions",
            state.platform,
            TargetPlatform::host(),
            state.platform
        );
    }

    // Build the argv. Heredoc RUN bodies become a script file inside the
    // rootfs; plain shell form goes through the stage shell.
    let script_path = state.rootfs.join("tmp/.boxer-run-script");
    let mut cleanup_script = false;
    let argv: Vec<String> = if let Some(first) = heredocs.first() {
        std::fs::create_dir_all(state.rootfs.join("tmp"))?;

        // `RUN <<EOF` with an empty command line runs the body itself as a
        // script; `RUN cmd <<EOF` runs `cmd` with the body as its heredoc
        // input (Docker's `RUN python3 <<EOF` feeds the body to python3, not
        // /bin/sh). Distinguish by whether anything survives removing the
        // heredoc markers from the shell-form command line.
        let command_line = match command {
            Command::Shell(text) => Some(text.clone()),
            Command::Exec(_) => None,
        };
        let leading = command_line
            .as_deref()
            .map(|line| command_without_heredoc_markers(line, heredocs))
            .unwrap_or_default();

        let has_command = !leading.is_empty();
        let script_content = if has_command {
            // Reconstruct the shell heredoc so a real shell runs the named
            // command with the body(ies) as its input, in order.
            let mut script = command_line.clone().unwrap_or_default();
            script.push('\n');
            for heredoc in heredocs {
                script.push_str(&heredoc.body);
                script.push_str(&heredoc.name);
                script.push('\n');
            }
            script
        } else {
            // No command: the first body is the script.
            first.body.clone()
        };
        std::fs::write(&script_path, script_content.as_bytes())?;
        set_mode(&script_path, 0o755)?;
        cleanup_script = true;

        if !has_command && first.body.starts_with("#!") {
            // A shebang body executes directly; the interpreter is its own.
            vec![String::from("/tmp/.boxer-run-script")]
        } else {
            // The script is a file, not a command string: interpreter + path,
            // without the shell's `-c` flag.
            let shell = state.config.shell();
            let interpreter = shell
                .first()
                .cloned()
                .unwrap_or_else(|| String::from("/bin/sh"));
            vec![interpreter, String::from("/tmp/.boxer-run-script")]
        }
    } else {
        command_to_argv(command, &state.config)
    };

    let program = argv.first().context("RUN with empty command")?.clone();
    if options.verbose {
        eprintln!("  RUN {argv:?}");
    }

    // Environment: image env overlaid with in-scope ARG values.
    let mut env: Vec<(String, String)> = state.config.env.clone();
    for (name, default) in &state.config.args {
        let value = build_args.get(name).cloned().or_else(|| default.clone());
        if let Some(value) = value
            && !env.iter().any(|(k, _)| k == name)
        {
            env.push((name.clone(), value));
        }
    }
    if !env.iter().any(|(k, _)| k == "PATH") {
        env.push((
            String::from("PATH"),
            String::from("/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"),
        ));
    }

    let workdir = if state.config.workdir.is_empty() {
        String::from("/")
    } else {
        state.config.workdir.clone()
    };
    std::fs::create_dir_all(state.rootfs.join(normalize_rel(&workdir)))?;

    let rootfs = state.rootfs.clone();
    let workdir_for_child = workdir.clone();
    let mut command_builder = std::process::Command::new(&program);
    command_builder.args(&argv[1..]).env_clear().envs(env);
    {
        use std::os::unix::process::CommandExt as _;
        // SAFETY: pre_exec runs in the forked child before exec. chroot(2) and
        // chdir are async-signal-safe; only libc calls and stack data are used.
        unsafe {
            command_builder.pre_exec(move || {
                let root = std::ffi::CString::new(rootfs.as_os_str().as_encoded_bytes())
                    .map_err(|_| std::io::Error::other("rootfs path contains NUL"))?;
                if libc::chroot(root.as_ptr()) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                let dir = std::ffi::CString::new(workdir_for_child.as_bytes())
                    .map_err(|_| std::io::Error::other("workdir contains NUL"))?;
                if libc::chdir(dir.as_ptr()) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }

    let status = command_builder.status().with_context(|| {
        format!(
            "RUN failed to start {program} (chroot requires root; \
             the command must exist inside the image)"
        )
    })?;

    if cleanup_script {
        let _ = std::fs::remove_file(&script_path);
    }

    if !status.success() {
        bail!("RUN {argv:?} exited with {status}");
    }
    Ok(())
}

/// Convert a finished stage into an [`ExtractedImage`] with a synthesized OCI
/// config, ready for the shared packaging pipeline.
fn finalize_stage(state: StageState, options: &BuildOptions) -> anyhow::Result<ExtractedImage> {
    let StageState {
        tempdir,
        rootfs,
        symlink_map,
        config,
        platform,
        ..
    } = state;

    // On the Linux build host the disk carries real modes; scan_rootfs's
    // permission map is rebuilt from it so chmods and RUN-created files keep
    // their bits.
    let mut permissions: HashMap<PathBuf, u32> = HashMap::new();
    for entry in walkdir::WalkDir::new(&rootfs).follow_links(false) {
        let entry = entry?;
        if !entry.file_type().is_file() {
            continue;
        }
        let rel = entry
            .path()
            .strip_prefix(&rootfs)
            .expect("child of rootfs")
            .to_path_buf();
        permissions.insert(rel, entry.metadata()?.mode() & 0o7777);
    }

    let env_pairs: Vec<String> = config.env.iter().map(|(k, v)| format!("{k}={v}")).collect();

    let mut oci_config = serde_json::json!({
        "architecture": platform.oci_arch_name(),
        "os": "linux",
        "config": {},
        "rootfs": { "type": "layers", "diff_ids": [] },
        "history": [ { "created_by": format!("boxer build ({})", options.source_label) } ],
    });
    let config_object = oci_config
        .get_mut("config")
        .expect("inserted above")
        .as_object_mut()
        .expect("config is an object");
    if !env_pairs.is_empty() {
        config_object.insert("Env".into(), serde_json::json!(env_pairs));
    }
    if let Some(entrypoint) = &config.entrypoint {
        config_object.insert("Entrypoint".into(), serde_json::json!(entrypoint));
    }
    if let Some(cmd) = &config.cmd {
        config_object.insert("Cmd".into(), serde_json::json!(cmd));
    }
    if !config.workdir.is_empty() {
        config_object.insert("WorkingDir".into(), serde_json::json!(config.workdir));
    }
    if let Some(user) = &config.user {
        config_object.insert("User".into(), serde_json::json!(user));
    }
    if !config.labels.is_empty() {
        let labels: serde_json::Map<String, serde_json::Value> = config
            .labels
            .iter()
            .map(|(k, v)| (k.clone(), serde_json::json!(v)))
            .collect();
        config_object.insert("Labels".into(), serde_json::Value::Object(labels));
    }
    if !config.exposed.is_empty() {
        let ports: serde_json::Map<String, serde_json::Value> = config
            .exposed
            .iter()
            .map(|p| (p.clone(), serde_json::json!({})))
            .collect();
        config_object.insert("ExposedPorts".into(), serde_json::Value::Object(ports));
    }
    if !config.volumes.is_empty() {
        let volumes: serde_json::Map<String, serde_json::Value> = config
            .volumes
            .iter()
            .map(|v| (v.clone(), serde_json::json!({})))
            .collect();
        config_object.insert("Volumes".into(), serde_json::Value::Object(volumes));
    }
    if let Some(signal) = &config.stop_signal {
        config_object.insert("StopSignal".into(), serde_json::json!(signal));
    }
    if let Some(healthcheck) = &config.healthcheck {
        config_object.insert("Healthcheck".into(), serde_json::json!(healthcheck));
    }
    if !config.onbuild.is_empty() {
        config_object.insert("OnBuild".into(), serde_json::json!(config.onbuild));
    }

    let image_config = ImageConfig {
        entrypoint: config.entrypoint.clone(),
        cmd: config.cmd.clone(),
        env: if env_pairs.is_empty() {
            None
        } else {
            Some(env_pairs)
        },
        working_dir: if config.workdir.is_empty() {
            None
        } else {
            Some(config.workdir.clone())
        },
        exposed_ports: config.exposed.clone(),
        user: config.user.clone(),
    };

    Ok(ExtractedImage {
        tempdir,
        rootfs_path: rootfs,
        config: image_config,
        config_json: serde_json::to_vec(&oci_config)?,
        symlink_map,
        permissions,
    })
}

fn set_mode(path: &Path, mode: u32) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .with_context(|| format!("chmod {mode:o} {}", path.display()))
}

/// Resolve `.`/`..` without touching the filesystem; result is always
/// relative, so joining it to a rootfs cannot escape.
fn normalize_rel(path: &str) -> PathBuf {
    let mut result = Vec::new();
    for component in Path::new(path).components() {
        match component {
            std::path::Component::ParentDir => {
                result.pop();
            }
            std::path::Component::CurDir
            | std::path::Component::RootDir
            | std::path::Component::Prefix(_) => {}
            c @ std::path::Component::Normal(_) => result.push(c),
        }
    }
    result.iter().collect()
}

/// `.dockerignore` handling: docker's pattern language restricted to the
/// forms that appear in practice (component globs, leading-dir matches, `!`
/// negation; last match wins).
struct DockerIgnore {
    patterns: Vec<(bool, Vec<String>)>,
}

impl DockerIgnore {
    fn load(context_dir: &Path) -> Self {
        let path = context_dir.join(".dockerignore");
        let mut patterns = Vec::new();
        if let Ok(text) = std::fs::read_to_string(&path) {
            for line in text.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                let (negated, pattern) = match line.strip_prefix('!') {
                    Some(rest) => (true, rest),
                    None => (false, line),
                };
                let components = pattern
                    .trim_matches('/')
                    .split('/')
                    .map(str::to_string)
                    .collect();
                patterns.push((negated, components));
            }
        }
        Self { patterns }
    }

    fn excluded(&self, rel: &Path) -> bool {
        let components: Vec<String> = rel
            .components()
            .map(|c| c.as_os_str().to_string_lossy().into_owned())
            .collect();
        let mut excluded = false;
        for (negated, pattern) in &self.patterns {
            if Self::pattern_matches(pattern, &components) {
                excluded = !negated;
            }
        }
        excluded
    }

    fn pattern_matches(pattern: &[String], components: &[String]) -> bool {
        // A pattern matches the path itself or any parent directory of it.
        if pattern.len() > components.len() {
            return false;
        }
        pattern
            .iter()
            .zip(components)
            .all(|(p, c)| p == "**" || component_match(p, c))
    }
}
