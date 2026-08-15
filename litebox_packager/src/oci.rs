// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! OCI image pulling and rootfs extraction.
//!
//! Pulls an OCI container image from a registry (e.g., Docker Hub, GHCR),
//! extracts its filesystem layers into a temporary rootfs directory, then
//! walks the rootfs to discover all ELF files for syscall rewriting.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::Context;
use oci_client::client::{ClientConfig, ClientProtocol, ImageData};
use oci_client::config::ConfigFile;
use oci_client::secrets::RegistryAuth;
use oci_client::{Client, Reference};

/// Parsed OCI image execution configuration (ENTRYPOINT, CMD, ENV, WORKDIR).
#[derive(Debug, Default)]
pub struct ImageConfig {
    pub entrypoint: Option<Vec<String>>,
    pub cmd: Option<Vec<String>>,
    pub env: Option<Vec<String>>,
    pub working_dir: Option<String>,
    /// `EXPOSE`d ports, normalized to `port/proto` (e.g. `8080/tcp`), sorted.
    pub exposed_ports: Vec<String>,
    /// The image's `USER`, if it declares one.
    pub user: Option<String>,
}

/// Result of pulling and extracting an OCI image.
pub struct ExtractedImage {
    /// Temporary directory holding the extracted rootfs.
    /// Cleaned up when this struct is dropped.
    pub tempdir: tempfile::TempDir,
    /// Path to the rootfs inside the temp directory.
    pub rootfs_path: PathBuf,
    /// Parsed image config (ENTRYPOINT, CMD, ENV, WORKDIR).
    pub config: ImageConfig,
    /// Raw OCI image config JSON blob (the full config descriptor data).
    pub config_json: Vec<u8>,
    /// Symlink map from layer extraction: maps relative paths inside the
    /// rootfs to their (Unix-style) link targets for cross-platform resolution.
    pub symlink_map: HashMap<PathBuf, PathBuf>,
    /// Unix permission modes captured from tar headers during extraction.
    /// Keyed by relative path inside the rootfs. Used instead of querying
    /// filesystem metadata, which loses Unix mode bits on non-Unix hosts.
    pub permissions: HashMap<PathBuf, u32>,
}

/// Result of scanning an extracted rootfs for files to package.
pub struct RootfsFileMap {
    /// Map from host path (inside the extracted rootfs) to the tar path
    /// (the path the file should appear at inside the output tar).
    /// Files with executable permission bits are candidates for rewriting.
    pub files: BTreeMap<PathBuf, RootfsEntry>,
}

/// A single file discovered in the rootfs.
pub struct RootfsEntry {
    /// Path inside the tar archive (relative, no leading `/`).
    pub tar_path: String,
    /// Host path to read the file data from.
    /// For regular files this equals the map key; for symlinks this is the
    /// resolved target path (which may differ from the map key).
    pub read_path: PathBuf,
    /// Whether the file has executable permission bits set.
    pub is_executable: bool,
    /// Unix permission mode (lower 12 bits).
    pub mode: u32,
}

/// A single image layer as pulled from a registry or read from an archive:
/// the (possibly compressed) tar bytes plus the media type that names the
/// compression.
pub struct LayerData {
    pub data: Vec<u8>,
    pub media_type: String,
}

/// Pull an OCI image from a registry and extract its layers into a temp directory.
///
/// Selects the Linux image whose architecture matches the host. LiteBox runs
/// guest instructions natively rather than emulating them, so a guest of any
/// other architecture could not execute here -- pulling one would only defer
/// the failure to run time. Use [`pull_and_extract_for_platform`] to select a
/// different architecture explicitly (e.g. to package a box for another host).
///
/// Supports standard image references like:
/// - `docker.io/library/alpine:latest`
/// - `alpine:latest` (defaults to docker.io/library/)
/// - `ghcr.io/org/repo:tag`
///
/// Layers are applied in order (bottom-up), handling whiteout files for
/// layer deletions per the OCI image spec.
///
/// # Authentication
///
/// Currently only anonymous (unauthenticated) pulls are supported. Private
/// registries or images that require credentials will fail with an
/// authorization error from the registry.
pub fn pull_and_extract(image_ref: &str, verbose: bool) -> anyhow::Result<ExtractedImage> {
    pull_and_extract_for_platform(image_ref, None, verbose)
}

/// The OCI architecture name for the host LiteBox is running on.
fn host_image_arch() -> oci_spec::image::Arch {
    if cfg!(target_arch = "aarch64") {
        oci_spec::image::Arch::ARM64
    } else {
        oci_spec::image::Arch::Amd64
    }
}

/// As [`pull_and_extract`], but selecting an explicit target architecture
/// (`None` selects the host architecture). When the registry's manifest list
/// has no Linux entry for the requested architecture, the error names the
/// platforms that were available.
pub fn pull_and_extract_for_platform(
    image_ref: &str,
    arch: Option<oci_spec::image::Arch>,
    verbose: bool,
) -> anyhow::Result<ExtractedImage> {
    // Parse the image reference
    let reference: Reference = image_ref
        .parse()
        .with_context(|| format!("invalid OCI image reference: {image_ref}"))?;

    if verbose {
        eprintln!("Pulling image: {reference}");
    }

    let wanted_arch = arch.unwrap_or_else(host_image_arch);

    // Captures the platforms present in the manifest list so a failed
    // selection can name what was actually available. Written from inside the
    // resolver closure, read after the pull fails.
    let seen_platforms: std::sync::Arc<std::sync::Mutex<Vec<String>>> =
        std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));

    // Create async runtime for the OCI client (which is async-based)
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("failed to create tokio runtime")?;

    let image_data = rt.block_on(async {
        let resolver_arch = wanted_arch.clone();
        let resolver_seen = std::sync::Arc::clone(&seen_platforms);
        let config = ClientConfig {
            protocol: ClientProtocol::Https,
            platform_resolver: Some(Box::new(move |entries| {
                if let Ok(mut seen) = resolver_seen.lock() {
                    *seen = entries
                        .iter()
                        .filter_map(|entry| entry.platform.as_ref())
                        .map(|p| format!("{}/{}", p.os, p.architecture))
                        .collect();
                }
                entries
                    .iter()
                    .find(|entry| {
                        entry.platform.as_ref().is_some_and(|p| {
                            p.os == oci_spec::image::Os::Linux && p.architecture == resolver_arch
                        })
                    })
                    .map(|e| e.digest.clone())
            })),
            ..Default::default()
        };
        let client = Client::new(config);

        // Anonymous for public images; private registries take credentials
        // from the environment or the docker/podman credential store.
        let auth = registry_auth_for(&reference);

        if verbose {
            eprintln!("  Fetching manifest...");
        }

        // Pull the full image (manifest + all layers)
        let image_data: ImageData = client
            .pull(
                &reference,
                &auth,
                vec![
                    oci_client::manifest::IMAGE_LAYER_GZIP_MEDIA_TYPE,
                    oci_client::manifest::IMAGE_LAYER_MEDIA_TYPE,
                    oci_client::manifest::IMAGE_DOCKER_LAYER_GZIP_MEDIA_TYPE,
                    IMAGE_LAYER_ZSTD_MEDIA_TYPE,
                    IMAGE_LAYER_NONDISTRIBUTABLE_ZSTD_MEDIA_TYPE,
                ],
            )
            .await
            .map_err(|e| {
                let seen = seen_platforms.lock().map(|s| s.clone()).unwrap_or_default();
                if seen.is_empty() {
                    anyhow::Error::new(e).context(format!("failed to pull image {reference}"))
                } else {
                    anyhow::Error::new(e).context(format!(
                        "failed to pull image {reference} for platform linux/{wanted_arch}; \
                         available platforms: {}",
                        seen.join(", ")
                    ))
                }
            })?;

        if verbose {
            eprintln!("  Pulled {} layer(s)", image_data.layers.len());
        }

        Ok::<_, anyhow::Error>(image_data)
    })?;

    let layers: Vec<LayerData> = image_data
        .layers
        .into_iter()
        .map(|layer| LayerData {
            data: layer.data.to_vec(),
            media_type: layer.media_type,
        })
        .collect();

    extract_image_layers(&layers, image_data.config.data.to_vec(), verbose)
}

/// Resolve the credentials to authenticate a pull with.
///
/// Precedence, highest first: an explicit `REGISTRY_TOKEN` bearer token; a
/// `REGISTRY_USERNAME`/`REGISTRY_PASSWORD` pair; then the entry the docker or
/// podman credential store (`config.json`) holds for this registry. Anonymous
/// when none is present, so public pulls are unaffected. Credentials are used
/// only for the request and never logged or stored in the box.
fn registry_auth_for(reference: &Reference) -> RegistryAuth {
    if let Ok(token) = std::env::var("REGISTRY_TOKEN")
        && !token.is_empty()
    {
        return RegistryAuth::Bearer(token);
    }
    if let (Ok(username), Ok(password)) = (
        std::env::var("REGISTRY_USERNAME"),
        std::env::var("REGISTRY_PASSWORD"),
    ) && !username.is_empty()
    {
        return RegistryAuth::Basic(username, password);
    }
    if let Some((username, password)) = docker_config_credentials(reference.registry()) {
        return RegistryAuth::Basic(username, password);
    }
    RegistryAuth::Anonymous
}

/// Read `username:password` for `registry` from docker/podman `config.json`.
///
/// Honors `DOCKER_CONFIG`, then `~/.docker/config.json`. The `auth` field is
/// base64-encoded `username:password`, matching what `docker login` writes.
fn docker_config_credentials(registry: &str) -> Option<(String, String)> {
    use base64::Engine as _;

    let config_path = if let Ok(dir) = std::env::var("DOCKER_CONFIG") {
        PathBuf::from(dir).join("config.json")
    } else {
        PathBuf::from(std::env::var("HOME").ok()?)
            .join(".docker")
            .join("config.json")
    };
    let text = std::fs::read_to_string(config_path).ok()?;
    let parsed: serde_json::Value = serde_json::from_str(&text).ok()?;
    let auths = parsed.get("auths")?.as_object()?;

    // docker keys the store by host, sometimes with a scheme or a trailing
    // slash; match the bare registry host against the key's host part.
    let entry = auths.iter().find_map(|(key, value)| {
        let host = key
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .trim_end_matches('/');
        (host == registry).then_some(value)
    })?;

    let encoded = entry.get("auth")?.as_str()?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .ok()?;
    let pair = String::from_utf8(decoded).ok()?;
    let (username, password) = pair.split_once(':')?;
    Some((username.to_string(), password.to_string()))
}

/// Extract already-fetched image layers into a temp-directory rootfs and parse
/// the image config. This is the registry-independent tail of
/// [`pull_and_extract`]; archive-based sources (`docker save` tars, OCI layout
/// directories) feed their layers through here so every input shares one
/// whiteout/symlink/permission implementation.
pub fn extract_image_layers(
    layers: &[LayerData],
    config_json: Vec<u8>,
    verbose: bool,
) -> anyhow::Result<ExtractedImage> {
    // Create temp directory for extraction
    let tempdir = tempfile::tempdir().context("failed to create temporary directory for rootfs")?;
    let rootfs_path = tempdir.path().join("rootfs");
    std::fs::create_dir_all(&rootfs_path).context("failed to create rootfs directory")?;

    // Extract layers in order (bottom layer first)
    let mut symlinks: Vec<DeferredSymlink> = Vec::new();
    let mut permissions: HashMap<PathBuf, u32> = HashMap::new();
    for (i, layer) in layers.iter().enumerate() {
        if verbose {
            eprintln!(
                "  Extracting layer {}/{} ({} bytes)...",
                i + 1,
                layers.len(),
                layer.data.len()
            );
        }
        extract_layer(
            &layer.data,
            &layer.media_type,
            &rootfs_path,
            &mut symlinks,
            &mut permissions,
        )
        .with_context(|| format!("failed to extract layer {}", i + 1))?;
    }

    // Build the symlink map once for O(1) lookup during resolution.
    let symlink_map: HashMap<PathBuf, PathBuf> = symlinks
        .iter()
        .map(|s| (s.rel_path.clone(), s.link_target.clone()))
        .collect();

    // Materialize symlinks cross-platform: resolve chains through the in-memory
    // map and copy target files (or create directories) instead of OS symlinks.
    if verbose {
        eprintln!("  Resolving {} symlinks...", symlinks.len());
    }
    materialize_symlinks(&symlink_map, &rootfs_path, &mut permissions, verbose)?;

    if verbose {
        eprintln!("  Rootfs extracted to {}", rootfs_path.display());
    }

    // Parse image config for ENTRYPOINT, CMD, ENV, WORKDIR.
    let config = match serde_json::from_slice::<ConfigFile>(&config_json) {
        Ok(cf) => {
            let exec_config = cf.config.as_ref();
            let mut exposed_ports: Vec<String> = exec_config
                .and_then(|c| c.exposed_ports.clone())
                .unwrap_or_default()
                .into_iter()
                .map(|port| normalize_exposed_port(&port))
                .collect();
            exposed_ports.sort();
            exposed_ports.dedup();
            let ic = ImageConfig {
                entrypoint: exec_config.and_then(|c| c.entrypoint.clone()),
                cmd: exec_config.and_then(|c| c.cmd.clone()),
                env: exec_config.and_then(|c| c.env.clone()),
                working_dir: exec_config.and_then(|c| c.working_dir.clone()),
                exposed_ports,
                user: exec_config.and_then(|c| c.user.clone()),
            };
            if verbose {
                eprintln!(
                    "  Image config: ENTRYPOINT={:?} CMD={:?} WORKDIR={:?} ENV=({} vars)",
                    ic.entrypoint,
                    ic.cmd,
                    ic.working_dir,
                    ic.env.as_ref().map_or(0, Vec::len)
                );
            }
            ic
        }
        Err(e) => {
            eprintln!(
                "warning: failed to parse image config: {e}; config_and_run.sh will not be generated"
            );
            ImageConfig::default()
        }
    };

    Ok(ExtractedImage {
        tempdir,
        rootfs_path,
        config,
        config_json,
        symlink_map,
        permissions,
    })
}

/// Generate a `litebox/config_and_run.sh` shell script from the OCI image config.
///
/// The script:
/// 1. Exports all `ENV` variables from the image config
/// 2. `cd`s to `WORKDIR` (defaults to `/`)
/// 3. If the caller passes arguments, runs them with the image ENTRYPOINT still
///    prepended (`exec ENTRYPOINT "$@"`) -- caller args replace CMD but keep the
///    ENTRYPOINT, matching docker's run semantics. With no ENTRYPOINT they run
///    directly (`exec "$@"`).
/// 4. Otherwise falls back to the image's ENTRYPOINT + CMD as the default command
///
/// This allows the runner to either pass a command explicitly, appended to the
/// ENTRYPOINT prefix:
///   `/litebox/config_and_run.sh app.py`  (an ENTRYPOINT `["python3"]` image runs
///   `python3 app.py`)
/// or rely on the image default:
///   `/litebox/config_and_run.sh`
///
/// Always generates a script — even if the image has no ENV, WORKDIR,
/// ENTRYPOINT, or CMD, the script will simply `exec "$@"` so callers can
/// use `config_and_run.sh` uniformly without checking whether it exists.
pub fn generate_config_and_run_script(config: &ImageConfig) -> String {
    use std::fmt::Write as _;

    let has_entrypoint = config.entrypoint.as_ref().is_some_and(|v| !v.is_empty());
    let has_cmd = config.cmd.as_ref().is_some_and(|v| !v.is_empty());

    let mut script = String::from("#!/bin/sh\n");

    // Export ENV vars.
    if let Some(env_vars) = &config.env {
        for var in env_vars {
            // Each var is "KEY=VALUE". Shell-quote the value.
            if let Some(eq_idx) = var.find('=') {
                let key = &var[..eq_idx];
                let value = &var[eq_idx + 1..];
                let _ = writeln!(script, "export {key}='{}'", shell_escape(value));
            }
        }
    }

    // cd to WORKDIR.
    let workdir = config
        .working_dir
        .as_deref()
        .filter(|w| !w.is_empty())
        .unwrap_or("/");
    let _ = writeln!(script, "cd '{}'", shell_escape(workdir));

    // Build the exec line.
    //
    // If the caller passes arguments, run those as the command.
    // Otherwise fall back to the image's ENTRYPOINT + CMD.
    let quote = |args: &[String]| -> String {
        args.iter()
            .map(|a| format!("'{}'", shell_escape(a)))
            .collect::<Vec<_>>()
            .join(" ")
    };

    // ENTRYPOINT is the fixed prefix; CMD is the default set of arguments.
    let ep = if has_entrypoint {
        quote(config.entrypoint.as_deref().unwrap_or_default())
    } else {
        String::new()
    };

    // The default command run when the caller passes no arguments: ENTRYPOINT
    // followed by CMD (either may be absent).
    let default_cmd = match (has_entrypoint, has_cmd) {
        (true, true) => format!("{ep} {}", quote(config.cmd.as_deref().unwrap_or_default())),
        (true, false) => ep.clone(),
        (false, true) => quote(config.cmd.as_deref().unwrap_or_default()),
        (false, false) => String::new(),
    };

    // Docker semantics: arguments passed to the container replace CMD but keep
    // the ENTRYPOINT prefix. Only `--entrypoint` (which boxer does not expose)
    // would drop it. So caller args run as `ENTRYPOINT "$@"`, not `"$@"` alone.
    let caller_cmd = if has_entrypoint {
        format!("{ep} \"$@\"")
    } else {
        String::from("\"$@\"")
    };

    if default_cmd.is_empty() {
        // No ENTRYPOINT and no CMD -- there is nothing to prepend, so just exec
        // whatever the caller passes (and error at runtime if they pass nothing).
        let _ = writeln!(script, "exec \"$@\"");
    } else {
        let _ = write!(
            script,
            "if [ $# -gt 0 ]; then\n  exec {caller_cmd}\nelse\n  exec {default_cmd}\nfi\n",
        );
    }

    script
}

/// Normalize an OCI `ExposedPorts` key to `port/proto`. The spec's keys are
/// already `port/proto`, but images in the wild also carry a bare `port`,
/// which docker reads as TCP.
fn normalize_exposed_port(port: &str) -> String {
    let port = port.trim();
    if port.contains('/') {
        port.to_ascii_lowercase()
    } else {
        format!("{port}/tcp")
    }
}

/// Escape single quotes for use inside single-quoted shell strings.
fn shell_escape(s: &str) -> String {
    s.replace('\'', "'\\''")
}

/// OCI zstd-compressed layer media type (OCI image spec v1.1).
const IMAGE_LAYER_ZSTD_MEDIA_TYPE: &str = "application/vnd.oci.image.layer.v1.tar+zstd";
/// Non-distributable variant of the zstd layer media type.
const IMAGE_LAYER_NONDISTRIBUTABLE_ZSTD_MEDIA_TYPE: &str =
    "application/vnd.oci.image.layer.nondistributable.v1.tar+zstd";

/// Extract a single OCI layer (tar, tar+gzip, or tar+zstd) into the rootfs
/// directory.
///
/// Handles OCI whiteout files (`.wh.*` prefixed entries) which indicate
/// files deleted in upper layers. Symlinks are collected into `symlinks` for
/// cross-platform resolution after all layers are extracted. Permission modes
/// from tar headers are recorded in `permissions` for cross-platform use.
fn extract_layer(
    data: &[u8],
    media_type: &str,
    rootfs: &Path,
    symlinks: &mut Vec<DeferredSymlink>,
    permissions: &mut HashMap<PathBuf, u32>,
) -> anyhow::Result<()> {
    // The media type names the compression, but sniff magic bytes too: layers
    // read back from `docker save` archives carry generic tar media types
    // regardless of their actual on-disk compression.
    if media_type.contains("gzip") || is_gzip_data(data) {
        let decoder = flate2::read::GzDecoder::new(data);
        extract_tar(decoder, rootfs, symlinks, permissions)
    } else if media_type.contains("zstd") || is_zstd_data(data) {
        let decoder = ruzstd::decoding::StreamingDecoder::new(data)
            .context("failed to initialize zstd decoder for layer")?;
        extract_tar(decoder, rootfs, symlinks, permissions)
    } else {
        extract_tar(data, rootfs, symlinks, permissions)
    }
}

/// Check if data starts with the gzip magic bytes.
fn is_gzip_data(data: &[u8]) -> bool {
    data.len() >= 2 && data[0] == 0x1f && data[1] == 0x8b
}

/// Check if data starts with the zstd frame magic bytes.
fn is_zstd_data(data: &[u8]) -> bool {
    data.len() >= 4 && data[..4] == [0x28, 0xb5, 0x2f, 0xfd]
}

/// A hard link whose target was not yet extracted when encountered.
struct DeferredHardLink {
    /// Destination path inside the rootfs (where the hard link should be created).
    target: PathBuf,
    /// Source path inside the rootfs (the file the hard link points to).
    link_source: PathBuf,
    /// Original link name from the tar header (used for permission lookup).
    link_name: PathBuf,
}

/// Tracked symlink from a container image layer.
struct DeferredSymlink {
    /// Relative path inside the rootfs (e.g., `usr/lib64/ld-linux-x86-64.so.2`).
    rel_path: PathBuf,
    /// Symlink target as stored in the tar (Unix-style, may be relative or absolute).
    link_target: PathBuf,
}

/// Extract a tar archive into the rootfs, handling OCI whiteout files.
///
/// Symlinks are NOT created as OS symlinks. Instead they are tracked in
/// `symlinks` so the caller can resolve them cross-platform after all layers
/// are extracted. Hard links whose targets appear later in the archive are
/// collected during the first pass and resolved after all regular entries
/// have been extracted. Permission modes from tar headers are recorded in
/// `permissions` keyed by relative path.
fn extract_tar<R: Read>(
    reader: R,
    rootfs: &Path,
    symlinks: &mut Vec<DeferredSymlink>,
    permissions: &mut HashMap<PathBuf, u32>,
) -> anyhow::Result<()> {
    let mut archive = tar::Archive::new(reader);
    // Preserve Unix permissions when running on Unix hosts.
    // On non-Unix platforms permissions are tracked separately in the
    // `permissions` HashMap from tar headers.
    #[cfg(unix)]
    {
        archive.set_preserve_permissions(true);
    }

    let mut deferred_links: Vec<DeferredHardLink> = Vec::new();

    for entry_result in archive.entries()? {
        let mut entry = entry_result.context("failed to read tar entry")?;
        // Normalize the path to prevent path traversal (../ and absolute paths)
        // and to strip inconsistent ./ prefixes that tar entries may carry.
        let path = normalize_path(&entry.path()?);
        let path_str = path.to_string_lossy();

        // Handle OCI whiteout files
        if let Some(file_name) = path.file_name().and_then(|n| n.to_str()) {
            if file_name == ".wh..wh..opq" {
                // Opaque whiteout: clear the entire parent directory contents
                if let Some(parent) = path.parent() {
                    let target = rootfs.join(parent);
                    if target.exists() {
                        // Remove all children but keep the directory itself
                        for child in std::fs::read_dir(&target)? {
                            let child = child?;
                            let ft = child.file_type()?;
                            if ft.is_dir() {
                                std::fs::remove_dir_all(child.path())?;
                            } else {
                                std::fs::remove_file(child.path())?;
                            }
                        }
                    }
                    // Also prune in-memory symlinks under this directory so
                    // they are not resurrected by materialize_symlinks.
                    // Guard: Path::starts_with("") matches everything, so skip
                    // pruning when parent is empty (root-level opaque whiteout
                    // already cleared the filesystem above).
                    if parent.as_os_str().is_empty() {
                        symlinks.clear();
                        permissions.clear();
                    } else {
                        symlinks.retain(|s| !s.rel_path.starts_with(parent));
                        // Prune permissions for files under the cleared directory.
                        permissions.retain(|p, _| !p.starts_with(parent));
                    }
                }
                continue;
            }
            if let Some(target_name) = file_name.strip_prefix(".wh.") {
                // Regular whiteout: delete the specific file/directory.
                //
                // The name after `.wh.` must be a plain child filename. A
                // crafted marker like `.wh..` (target `.`) or `.wh...` (target
                // `..`) would otherwise join, unnormalized, to the directory
                // itself or an ancestor -- and `rootfs.join("..")` escapes the
                // rootfs entirely, so remove_dir_all/remove_file could delete
                // data outside the extracted image. Refuse anything that is not
                // a single normal path component (no `.`, `..`, `/`, or empty).
                let plain_child = !target_name.is_empty()
                    && target_name != "."
                    && target_name != ".."
                    && !target_name.contains('/');
                if let Some(parent) = path.parent()
                    && plain_child
                {
                    let whiteout_rel = parent.join(target_name);
                    let target = rootfs.join(&whiteout_rel);
                    if target.is_dir() {
                        let _ = std::fs::remove_dir_all(&target);
                        // Prune symlinks under the removed directory.
                        symlinks.retain(|s| !s.rel_path.starts_with(&whiteout_rel));
                        // Prune permissions under the removed directory.
                        permissions.retain(|p, _| !p.starts_with(&whiteout_rel));
                    } else {
                        let _ = std::fs::remove_file(&target);
                        // Prune the exact symlink entry if present.
                        symlinks.retain(|s| s.rel_path != whiteout_rel);
                        // Prune the exact permissions entry.
                        permissions.remove(&whiteout_rel);
                    }
                }
                continue;
            }
        }

        let target = rootfs.join(&path);

        // Ensure parent directory exists
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let entry_type = entry.header().entry_type();

        // Handle hard links: copy the link target instead of creating an OS
        // hard link. The tar crate's unpack() tries std::fs::hard_link which
        // can fail if the target hasn't been extracted yet (ordering issue),
        // and the litebox filesystem doesn't support hard links anyway.
        if entry_type == tar::EntryType::Link {
            let link_name = normalize_path(
                &entry
                    .link_name()?
                    .context("hard link entry has no link name")?,
            );
            let link_source = rootfs.join(&link_name);
            if link_source.exists() {
                std::fs::copy(&link_source, &target).with_context(|| {
                    format!(
                        "failed to copy hard link target {} -> {}",
                        link_source.display(),
                        target.display()
                    )
                })?;
                // Copy permission mode from the link source.
                let link_rel = normalize_path(&link_name);
                if let Some(&mode) = permissions.get(&link_rel) {
                    permissions.insert(path.clone(), mode);
                }
            } else {
                // Target hasn't been extracted yet — defer to second pass.
                deferred_links.push(DeferredHardLink {
                    target,
                    link_source,
                    link_name: link_name.clone(),
                });
            }
            continue;
        }

        // Track symlinks in memory instead of creating OS symlinks.
        // OS symlinks on Windows require special privileges and don't handle
        // Unix-style relative paths reliably, so we resolve them ourselves
        // after all layers are extracted.
        if entry_type == tar::EntryType::Symlink {
            let link_target = entry
                .link_name()?
                .context("symlink entry has no link name")?
                .into_owned();
            // A later layer may override this symlink, so remove any stale
            // entry with the same rel_path.
            symlinks.retain(|s| s.rel_path != path);
            // If a previous layer extracted a file or directory at this path,
            // remove it so the symlink takes precedence.
            if target.is_dir() {
                if let Err(e) = std::fs::remove_dir_all(&target) {
                    eprintln!(
                        "  warning: failed to remove directory for symlink override {path_str}: {e}"
                    );
                }
            } else if target.exists()
                && let Err(e) = std::fs::remove_file(&target)
            {
                eprintln!("  warning: failed to remove file for symlink override {path_str}: {e}");
            }
            symlinks.push(DeferredSymlink {
                rel_path: path.clone(),
                link_target,
            });
            continue;
        }

        // Normal file/directory: use the standard unpack.
        // If a previous layer recorded a symlink at this path, as a child of
        // this path, or as an ancestor of this path, the real file/directory
        // from an upper layer takes precedence — remove the stale symlink
        // entries. The ancestor check prevents stale symlinks from being
        // resolved during scan_rootfs and incorrectly pulling in lower-layer
        // content.
        symlinks.retain(|s| {
            s.rel_path != path && !s.rel_path.starts_with(&path) && !path.starts_with(&s.rel_path)
        });
        entry
            .unpack(&target)
            .with_context(|| format!("failed to unpack entry: {path_str}"))?;

        // Record the permission mode from the tar header for cross-platform use.
        if let Ok(mode) = entry.header().mode() {
            permissions.insert(path.clone(), mode);
        }
    }

    // Second pass: resolve deferred hard links now that all entries are extracted.
    for link in &deferred_links {
        if link.link_source.exists() {
            if let Some(parent) = link.target.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::copy(&link.link_source, &link.target).with_context(|| {
                format!(
                    "failed to copy deferred hard link {} -> {}",
                    link.link_source.display(),
                    link.target.display()
                )
            })?;
            // Copy permission mode from the link source.
            let link_rel = normalize_path(&link.link_name);
            if let Some(&mode) = permissions.get(&link_rel) {
                let target_rel = link.target.strip_prefix(rootfs).unwrap_or(&link.target);
                permissions.insert(target_rel.to_path_buf(), mode);
            }
        } else {
            // Target still doesn't exist after the full layer extraction —
            // this is unusual but not fatal; warn and skip.
            eprintln!(
                "  warning: hard link target {} not found after full extraction, skipping {}",
                link.link_source.display(),
                link.target.display()
            );
        }
    }

    Ok(())
}

/// Resolve a symlink target within the rootfs using the symlink map.
///
/// Handles both absolute targets (e.g., `/lib/x86_64-linux-gnu/ld.so`) and
/// relative targets (e.g., `../lib/x86_64-linux-gnu/ld.so`). Follows symlink
/// chains up to `max_depth` hops.
fn resolve_symlink_in_rootfs(
    rel_path: &Path,
    rootfs: &Path,
    symlink_map: &HashMap<PathBuf, PathBuf>,
    max_depth: u32,
) -> Option<PathBuf> {
    if max_depth == 0 {
        return None;
    }

    // Empty rel_path would resolve to the rootfs directory itself — treat
    // as unresolvable to avoid accidentally matching the entire rootfs.
    if rel_path.as_os_str().is_empty() {
        return None;
    }

    // Check if this rel_path is itself a symlink
    if let Some(link_target) = symlink_map.get(rel_path) {
        // Resolve the target to a new rel_path
        let resolved_rel = if is_unix_absolute(link_target) {
            normalize_path(link_target)
        } else {
            // Relative target: resolve from parent of the symlink
            let parent = rel_path.parent().unwrap_or(Path::new(""));
            normalize_path(&parent.join(link_target))
        };
        // Recurse to follow chains
        return resolve_symlink_in_rootfs(&resolved_rel, rootfs, symlink_map, max_depth - 1);
    }

    // Not a symlink — check if any ancestor is a symlink (e.g., `lib64/foo` where
    // `lib64` → `usr/lib64`).
    let components: Vec<_> = rel_path.components().collect();
    for i in 1..components.len() {
        let prefix: PathBuf = components[..i].iter().collect();
        if let Some(link_target) = symlink_map.get(&prefix) {
            let resolved_prefix = if is_unix_absolute(link_target) {
                normalize_path(link_target)
            } else {
                let parent = prefix.parent().unwrap_or(Path::new(""));
                normalize_path(&parent.join(link_target))
            };
            let suffix: PathBuf = components[i..].iter().collect();
            let new_rel = resolved_prefix.join(suffix);
            return resolve_symlink_in_rootfs(&new_rel, rootfs, symlink_map, max_depth - 1);
        }
    }

    let host_path = rootfs.join(rel_path);
    if host_path.exists() {
        Some(host_path)
    } else {
        None
    }
}

/// Check if a path starts with `/` (Unix-style absolute).
///
/// On Windows, `Path::is_absolute()` requires a drive letter, so Unix-style
/// paths like `/lib/foo` are not detected as absolute. This helper checks
/// the raw string instead.
fn is_unix_absolute(path: &Path) -> bool {
    path.as_os_str()
        .to_str()
        .is_some_and(|s| s.starts_with('/'))
}

/// Normalize a path by resolving `.` and `..` components without touching the
/// filesystem (no symlink resolution, no existence checks). Strips any root
/// component so the result is always a relative path.
fn normalize_path(path: &Path) -> PathBuf {
    let mut result = Vec::new();
    for component in path.components() {
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

/// Materialize all deferred symlinks by copying or creating directories.
///
/// This is called after all OCI layers have been extracted, so every real file
/// should be on disk. Symlinks are resolved through the in-memory map (handling
/// chains like `lib64` → `usr/lib64` → real dir) and then:
/// - File symlinks: the target file is copied to the symlink location.
///   The resolved target's permission mode is also recorded for the symlink path.
/// - Directory symlinks: an empty directory is created (its contents will be
///   expanded by `scan_rootfs`'s dir-symlink logic).
fn materialize_symlinks(
    symlink_map: &HashMap<PathBuf, PathBuf>,
    rootfs: &Path,
    permissions: &mut HashMap<PathBuf, u32>,
    verbose: bool,
) -> anyhow::Result<()> {
    for (rel_path, link_target) in symlink_map {
        let host_path = rootfs.join(rel_path);
        if host_path.exists() {
            // A later layer may have replaced the symlink with a real file.
            continue;
        }

        if let Some(resolved) = resolve_symlink_in_rootfs(
            rel_path,
            rootfs,
            symlink_map,
            32, // max chain depth
        ) {
            if let Some(parent) = host_path.parent() {
                std::fs::create_dir_all(parent)?;
            }

            if resolved.is_dir() {
                // Directory symlink: create directory placeholder.
                // scan_rootfs will discover this is a "dir symlink" and expand
                // it through the symlink_map.
                std::fs::create_dir_all(&host_path)?;
                if verbose {
                    eprintln!(
                        "  [symlink→dir] {} -> {}",
                        rel_path.display(),
                        link_target.display()
                    );
                }
            } else if resolved.is_file() {
                std::fs::copy(&resolved, &host_path).with_context(|| {
                    format!(
                        "failed to materialize symlink {} -> {}",
                        rel_path.display(),
                        resolved.display()
                    )
                })?;
                // Record the resolved target's permission mode for this symlink path.
                let resolved_rel = resolved
                    .strip_prefix(rootfs)
                    .unwrap_or(&resolved)
                    .to_path_buf();
                if let Some(&mode) = permissions.get(&resolved_rel) {
                    permissions.insert(rel_path.clone(), mode);
                }
                if verbose {
                    eprintln!(
                        "  [symlink→file] {} -> {}",
                        rel_path.display(),
                        link_target.display()
                    );
                }
            }
        } else if verbose {
            eprintln!(
                "  [symlink-broken] {} -> {} (unresolvable)",
                rel_path.display(),
                link_target.display()
            );
        }
    }

    Ok(())
}

/// Look up the Unix permission mode for a file.
///
/// Look up the Unix file mode for a rootfs-relative path from the OCI tar
/// header permissions map. Defaults to 0o644 if not found.
fn lookup_mode(rel_path: &Path, permissions: &HashMap<PathBuf, u32>) -> u32 {
    if let Some(&mode) = permissions.get(rel_path) {
        mode & 0o7777
    } else {
        0o644
    }
}

/// Scan an extracted rootfs directory and build a file map for packaging.
///
/// Walks the rootfs directory tree and collects all regular files with their
/// paths and permission bits. After `materialize_symlinks` has been called,
/// file symlinks are already materialized as regular file copies on disk.
///
/// `symlink_map` provides the original symlink mapping from extraction so
/// that **directory symlinks** (e.g., `lib64` → `usr/lib64`) can be expanded:
/// all files under the target directory are duplicated under the symlink's
/// path prefix so that paths like `lib64/ld-linux-x86-64.so.2` exist in the tar.
///
/// `permissions` provides Unix permission modes captured from tar headers
/// during extraction, so permission bits are accurate on non-Unix hosts.
#[allow(clippy::implicit_hasher)]
pub fn scan_rootfs(
    rootfs: &Path,
    symlink_map: &HashMap<PathBuf, PathBuf>,
    permissions: &HashMap<PathBuf, u32>,
    verbose: bool,
) -> anyhow::Result<RootfsFileMap> {
    let mut files = BTreeMap::new();

    // Identify directory symlinks and their resolved targets on disk.
    let mut dir_symlinks: Vec<(PathBuf, PathBuf)> = Vec::new();
    for (rel_path, link_target) in symlink_map {
        let host_path = rootfs.join(rel_path);
        if host_path.is_dir() {
            // This dir symlink was materialized as an empty directory.
            // Resolve the target to find the real directory to expand from.
            if let Some(resolved) =
                resolve_symlink_in_rootfs(rel_path, rootfs, symlink_map, 32).filter(|r| r.is_dir())
            {
                if verbose {
                    eprintln!(
                        "  [dir-symlink] {} -> {}",
                        rel_path.display(),
                        link_target.display()
                    );
                }
                dir_symlinks.push((host_path, resolved));
            }
        }
    }

    for entry in walkdir::WalkDir::new(rootfs)
        .follow_links(false)
        .into_iter()
        .filter_map(std::result::Result::ok)
    {
        let rel_path = entry.path().strip_prefix(rootfs).unwrap_or(entry.path());

        // Skip the root itself
        if rel_path == Path::new("") {
            continue;
        }

        let tar_path = rel_path.to_string_lossy().to_string();
        // Normalize path separators to Unix-style for the tar archive.
        let tar_path = tar_path.replace('\\', "/");

        if entry.file_type().is_file() {
            let mode = lookup_mode(rel_path, permissions);
            let is_executable = mode & 0o111 != 0;

            if verbose && is_executable {
                eprintln!("  [exec] {tar_path}");
            }

            files.insert(
                entry.path().to_path_buf(),
                RootfsEntry {
                    tar_path,
                    read_path: entry.path().to_path_buf(),
                    is_executable,
                    mode,
                },
            );
        } else if entry.file_type().is_symlink() {
            // On platforms that still have OS symlinks (Linux), resolve them.
            if let Some(resolved) = resolve_in_rootfs(entry.path(), rootfs, 16) {
                if resolved.is_file() {
                    let resolved_rel = resolved.strip_prefix(rootfs).unwrap_or(&resolved);
                    let mode = lookup_mode(resolved_rel, permissions);
                    let is_executable = mode & 0o111 != 0;

                    files.insert(
                        entry.path().to_path_buf(),
                        RootfsEntry {
                            tar_path,
                            read_path: resolved.clone(),
                            is_executable,
                            mode,
                        },
                    );
                } else if resolved.is_dir() {
                    if verbose {
                        eprintln!("  [dir-symlink] {tar_path} -> {}", resolved.display());
                    }
                    dir_symlinks.push((entry.path().to_path_buf(), resolved));
                }
            } else if verbose {
                eprintln!("  [skip] broken symlink: {tar_path}");
            }
        }
        // Directories are created implicitly by the tar builder
    }

    // Expand directory symlinks: walk the resolved target directory and create
    // additional tar entries under the symlink's path prefix. For example, if
    // `lib64` → `usr/lib64`, then `usr/lib64/ld-linux-x86-64.so.2` also
    // appears as `lib64/ld-linux-x86-64.so.2` in the tar.

    // Build a set of existing tar paths for O(1) duplicate checks.
    let mut tar_paths: HashSet<String> = files.values().map(|e| e.tar_path.clone()).collect();

    for (symlink_host_path, resolved_dir) in &dir_symlinks {
        let symlink_rel = symlink_host_path
            .strip_prefix(rootfs)
            .unwrap_or(symlink_host_path);

        for entry in walkdir::WalkDir::new(resolved_dir)
            .follow_links(false)
            .into_iter()
            .filter_map(std::result::Result::ok)
        {
            if !entry.file_type().is_file() && !entry.file_type().is_symlink() {
                continue;
            }

            // Determine the host path to read from and whether it's a file.
            let (read_path, is_file) = if entry.file_type().is_symlink() {
                if let Some(resolved) = resolve_in_rootfs(entry.path(), rootfs, 16) {
                    let is_file = resolved.is_file();
                    (resolved, is_file)
                } else {
                    continue;
                }
            } else {
                (entry.path().to_path_buf(), true)
            };

            if !is_file {
                continue;
            }

            // Build the tar path: replace the resolved_dir prefix with symlink_rel.
            let entry_rel = entry
                .path()
                .strip_prefix(resolved_dir)
                .unwrap_or(entry.path());
            let tar_path = symlink_rel.join(entry_rel).to_string_lossy().to_string();
            // Normalize path separators to Unix-style for the tar archive.
            let tar_path = tar_path.replace('\\', "/");

            // Use symlink_host_path-based key to avoid colliding with the
            // original entry under the resolved directory.
            let map_key = symlink_host_path.join(entry_rel);

            // Skip if we already have this tar path.
            if !tar_paths.insert(tar_path.clone()) {
                continue;
            }

            let read_rel = read_path.strip_prefix(rootfs).unwrap_or(&read_path);
            let mode = lookup_mode(read_rel, permissions);
            let is_executable = mode & 0o111 != 0;

            if verbose {
                eprintln!("  [dir-symlink-expand] {tar_path}");
            }

            files.insert(
                map_key,
                RootfsEntry {
                    tar_path,
                    read_path,
                    is_executable,
                    mode,
                },
            );
        }
    }

    if verbose {
        let exec_count = files.values().filter(|e| e.is_executable).count();
        eprintln!("  Found {} files ({} executables)", files.len(), exec_count);
    }

    Ok(RootfsFileMap { files })
}

/// Resolve a symlink within the rootfs context, handling absolute symlinks
/// that would otherwise escape the rootfs boundary.
fn resolve_in_rootfs(path: &Path, rootfs: &Path, max_depth: u32) -> Option<PathBuf> {
    if max_depth == 0 {
        return None;
    }

    let metadata = path.symlink_metadata().ok()?;
    if !metadata.file_type().is_symlink() {
        return if path.exists() {
            Some(path.to_path_buf())
        } else {
            None
        };
    }

    let link_target = std::fs::read_link(path).ok()?;
    let resolved = if is_unix_absolute(&link_target) {
        // Absolute symlink: resolve within rootfs (normalize to prevent traversal)
        rootfs.join(normalize_path(&link_target))
    } else {
        // Relative symlink — join with parent, then canonicalize `..` components
        // to prevent escaping the rootfs boundary.
        let joined = path.parent()?.join(&link_target);
        // Normalize to strip `..` then re-root inside rootfs.
        let normalized = normalize_path(joined.strip_prefix(rootfs).unwrap_or(&joined));
        rootfs.join(normalized)
    };

    resolve_in_rootfs(&resolved, rootfs, max_depth - 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_symlink_in_rootfs_happy_paths() {
        let tmp = tempfile::tempdir().unwrap();
        let rootfs = tmp.path();
        std::fs::create_dir_all(rootfs.join("usr/lib64")).unwrap();
        std::fs::create_dir_all(rootfs.join("usr/lib")).unwrap();
        std::fs::create_dir_all(rootfs.join("usr/bin")).unwrap();
        std::fs::write(rootfs.join("usr/lib64/libc.so"), b"fake").unwrap();
        std::fs::write(rootfs.join("usr/lib64/foo.so"), b"elf").unwrap();
        std::fs::write(rootfs.join("usr/lib/libfoo.so"), b"elf").unwrap();
        std::fs::write(rootfs.join("usr/bin/sh"), b"elf").unwrap();
        std::fs::write(rootfs.join("c"), b"data").unwrap();

        let mut symlink_map = HashMap::new();
        symlink_map.insert(PathBuf::from("lib64"), PathBuf::from("usr/lib64"));
        symlink_map.insert(PathBuf::from("a"), PathBuf::from("b"));
        symlink_map.insert(PathBuf::from("b"), PathBuf::from("c"));
        symlink_map.insert(PathBuf::from("bin/sh"), PathBuf::from("/usr/bin/sh"));
        symlink_map.insert(
            PathBuf::from("usr/lib64/libfoo.so"),
            PathBuf::from("../lib/libfoo.so"),
        );

        // Direct symlink: lib64 -> usr/lib64
        let r = resolve_symlink_in_rootfs(Path::new("lib64"), rootfs, &symlink_map, 32);
        assert_eq!(r, Some(rootfs.join("usr/lib64")));

        // Chain: a -> b -> c
        let r = resolve_symlink_in_rootfs(Path::new("a"), rootfs, &symlink_map, 32);
        assert_eq!(r, Some(rootfs.join("c")));

        // Absolute target: bin/sh -> /usr/bin/sh
        let r = resolve_symlink_in_rootfs(Path::new("bin/sh"), rootfs, &symlink_map, 32);
        assert_eq!(r, Some(rootfs.join("usr/bin/sh")));

        // Relative target: usr/lib64/libfoo.so -> ../lib/libfoo.so
        let r =
            resolve_symlink_in_rootfs(Path::new("usr/lib64/libfoo.so"), rootfs, &symlink_map, 32);
        assert_eq!(r, Some(rootfs.join("usr/lib/libfoo.so")));

        // Ancestor is symlink: lib64/foo.so resolves via lib64 -> usr/lib64
        let r = resolve_symlink_in_rootfs(Path::new("lib64/foo.so"), rootfs, &symlink_map, 32);
        assert_eq!(r, Some(rootfs.join("usr/lib64/foo.so")));
    }

    #[test]
    fn resolve_symlink_in_rootfs_edge_cases() {
        let tmp = tempfile::tempdir().unwrap();
        let rootfs = tmp.path();
        std::fs::write(rootfs.join("hello.txt"), b"hi").unwrap();

        // Cycle: a -> b -> a
        let mut cycle_map = HashMap::new();
        cycle_map.insert(PathBuf::from("a"), PathBuf::from("b"));
        cycle_map.insert(PathBuf::from("b"), PathBuf::from("a"));
        assert!(resolve_symlink_in_rootfs(Path::new("a"), rootfs, &cycle_map, 32).is_none());

        let empty_map = HashMap::new();

        // Empty path
        assert!(resolve_symlink_in_rootfs(Path::new(""), rootfs, &empty_map, 32).is_none());

        // Nonexistent path
        assert!(
            resolve_symlink_in_rootfs(Path::new("does/not/exist"), rootfs, &empty_map, 32)
                .is_none()
        );

        // Regular file (not a symlink) returns host path directly
        let r = resolve_symlink_in_rootfs(Path::new("hello.txt"), rootfs, &empty_map, 32);
        assert_eq!(r, Some(rootfs.join("hello.txt")));
    }

    fn config_with(entrypoint: Option<&[&str]>, cmd: Option<&[&str]>) -> ImageConfig {
        ImageConfig {
            entrypoint: entrypoint.map(|v| v.iter().copied().map(String::from).collect()),
            cmd: cmd.map(|v| v.iter().copied().map(String::from).collect()),
            ..ImageConfig::default()
        }
    }

    #[test]
    fn config_script_keeps_entrypoint_when_caller_overrides_cmd() {
        // Docker semantics: caller arguments replace CMD but keep the ENTRYPOINT
        // prefix. The old script did `exec "$@"`, dropping ENTRYPOINT entirely
        // (sweep F16). The caller branch must prepend the entrypoint.
        let script =
            generate_config_and_run_script(&config_with(Some(&["python3"]), Some(&["app.py"])));
        assert!(
            script.contains("exec 'python3' \"$@\""),
            "caller args must keep the entrypoint prefix:\n{script}"
        );
        assert!(
            script.contains("exec 'python3' 'app.py'"),
            "default command must be entrypoint + cmd:\n{script}"
        );
    }

    #[test]
    fn config_script_entrypoint_only_prepends_to_caller_args() {
        let script = generate_config_and_run_script(&config_with(Some(&["/tini", "--"]), None));
        assert!(
            script.contains("exec '/tini' '--' \"$@\""),
            "entrypoint-only image must still prepend the entrypoint:\n{script}"
        );
    }

    #[test]
    fn config_script_cmd_only_replaces_fully() {
        // With no ENTRYPOINT, caller args replace CMD outright -- `exec "$@"`.
        let script = generate_config_and_run_script(&config_with(None, Some(&["nginx"])));
        assert!(
            script.contains("exec \"$@\""),
            "cmd-only image replaces the whole command:\n{script}"
        );
        assert!(
            script.contains("exec 'nginx'"),
            "cmd-only default runs the cmd:\n{script}"
        );
        assert!(
            !script.contains("exec 'nginx' \"$@\""),
            "cmd must not be prepended to caller args:\n{script}"
        );
    }

    #[test]
    fn config_script_no_entrypoint_no_cmd_execs_caller() {
        let script = generate_config_and_run_script(&config_with(None, None));
        assert!(script.contains("exec \"$@\""), "{script}");
        assert!(!script.contains("if [ $# -gt 0 ]"), "{script}");
    }

    /// Build an in-memory tar containing a single empty regular-file entry with
    /// the exact name given (used to plant crafted whiteout markers).
    fn tar_with_regular_entry(name: &str) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_size(0);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_mode(0o644);
        builder
            .append_data(&mut header, name, std::io::empty())
            .unwrap();
        builder.into_inner().unwrap()
    }

    #[test]
    fn whiteout_cannot_delete_outside_rootfs() {
        // A crafted whiteout `.wh...` strips to the target `..`. The old code
        // joined it unnormalized as rootfs/.. and remove_dir_all'd it, escaping
        // the rootfs to delete sibling data (sweep F9). Extraction must refuse
        // a whiteout whose target is not a plain child name.
        let tmp = tempfile::tempdir().unwrap();
        // A sibling of the rootfs, OUTSIDE it, that must survive extraction.
        let outside = tmp.path().join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("secret.txt"), b"host data").unwrap();

        let rootfs = tmp.path().join("rootfs");
        std::fs::create_dir_all(&rootfs).unwrap();

        let tar_bytes = tar_with_regular_entry(".wh...");
        let mut symlinks = Vec::new();
        let mut permissions = HashMap::new();
        extract_tar(&tar_bytes[..], &rootfs, &mut symlinks, &mut permissions).unwrap();

        assert!(
            outside.join("secret.txt").exists(),
            "whiteout escaped the rootfs and deleted data in a sibling directory"
        );
        assert!(
            rootfs.exists(),
            "the rootfs itself must survive a malformed whiteout"
        );
    }

    #[test]
    fn whiteout_removes_named_child_only() {
        // A legitimate whiteout `.wh.gone.txt` deletes exactly its target and
        // leaves siblings untouched.
        let tmp = tempfile::tempdir().unwrap();
        let rootfs = tmp.path().join("rootfs");
        std::fs::create_dir_all(&rootfs).unwrap();
        std::fs::write(rootfs.join("gone.txt"), b"x").unwrap();
        std::fs::write(rootfs.join("stays.txt"), b"y").unwrap();

        let tar_bytes = tar_with_regular_entry(".wh.gone.txt");
        let mut symlinks = Vec::new();
        let mut permissions = HashMap::new();
        extract_tar(&tar_bytes[..], &rootfs, &mut symlinks, &mut permissions).unwrap();

        assert!(
            !rootfs.join("gone.txt").exists(),
            "a legitimate whiteout must delete its named target"
        );
        assert!(
            rootfs.join("stays.txt").exists(),
            "a whiteout must not touch siblings"
        );
    }
}
