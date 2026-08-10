// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Image acquisition: turn any image source -- registry reference,
//! `docker save` archive, or OCI layout directory/tar -- into an extracted
//! rootfs via `litebox_packager::oci`'s shared layer-extraction path.

use std::collections::HashMap;
use std::io::Read as _;
use std::path::Path;

use anyhow::{Context, bail};
use litebox_packager::oci::{ExtractedImage, LayerData, extract_image_layers};

/// The platform a box is built for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetPlatform {
    Amd64,
    Arm64,
}

impl TargetPlatform {
    /// Parse `linux/amd64`, `amd64`, `x86_64`, `linux/arm64`, `arm64`,
    /// `aarch64`. Anything else is rejected naming the accepted values.
    pub fn parse(text: &str) -> anyhow::Result<Self> {
        let arch = text.strip_prefix("linux/").unwrap_or(text);
        match arch {
            "amd64" | "x86_64" | "x86-64" => Ok(Self::Amd64),
            "arm64" | "aarch64" | "arm64/v8" => Ok(Self::Arm64),
            other => bail!(
                "unsupported platform '{other}': accepted values are linux/amd64 and linux/arm64"
            ),
        }
    }

    /// The platform of the machine boxer is running on.
    pub fn host() -> Self {
        if cfg!(target_arch = "aarch64") {
            Self::Arm64
        } else {
            Self::Amd64
        }
    }

    /// OCI image-spec architecture name.
    pub fn oci_arch_name(self) -> &'static str {
        match self {
            Self::Amd64 => "amd64",
            Self::Arm64 => "arm64",
        }
    }

    /// ELF `e_machine` for this platform's binaries.
    pub fn elf_machine(self) -> u16 {
        match self {
            Self::Amd64 => litebox_packager::EM_X86_64,
            Self::Arm64 => litebox_packager::EM_AARCH64,
        }
    }

    pub fn oci_spec_arch(self) -> oci_spec::image::Arch {
        match self {
            Self::Amd64 => oci_spec::image::Arch::Amd64,
            Self::Arm64 => oci_spec::image::Arch::ARM64,
        }
    }
}

impl std::fmt::Display for TargetPlatform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "linux/{}", self.oci_arch_name())
    }
}

/// Pull an image from a registry for the requested platform and extract it.
pub fn from_registry(
    image_ref: &str,
    platform: TargetPlatform,
    verbose: bool,
) -> anyhow::Result<ExtractedImage> {
    litebox_packager::oci::pull_and_extract_for_platform(
        image_ref,
        Some(platform.oci_spec_arch()),
        verbose,
    )
}

/// Load an image from a `docker save` archive or an OCI layout (directory or
/// tar), selecting the requested platform, and extract its rootfs.
pub fn from_archive(
    path: &Path,
    platform: TargetPlatform,
    verbose: bool,
) -> anyhow::Result<ExtractedImage> {
    let blobs = read_source_blobs(path)?;
    let (layers, config_json) = select_image(&blobs, platform)
        .with_context(|| format!("no usable image in {}", path.display()))?;

    // The archive's config records the image's actual architecture; refuse a
    // silent platform mismatch instead of building a mislabeled box.
    if let Ok(config) = serde_json::from_slice::<serde_json::Value>(&config_json)
        && let Some(arch) = config.get("architecture").and_then(|a| a.as_str())
        && arch != platform.oci_arch_name()
    {
        bail!(
            "archive {} contains a {arch} image but --platform requested {}",
            path.display(),
            platform
        );
    }

    extract_image_layers(&layers, config_json, verbose)
}

/// All files reachable from the source: tar entries, or directory contents
/// keyed by their layout-relative path.
fn read_source_blobs(path: &Path) -> anyhow::Result<HashMap<String, Vec<u8>>> {
    let mut blobs = HashMap::new();
    if path.is_dir() {
        collect_dir(path, path, &mut blobs)?;
        return Ok(blobs);
    }
    let file = std::fs::File::open(path)
        .with_context(|| format!("cannot open image archive {}", path.display()))?;
    let mut archive = tar::Archive::new(file);
    for entry in archive
        .entries()
        .with_context(|| format!("{} is not a tar archive", path.display()))?
    {
        let mut entry = entry.context("failed to read archive entry")?;
        if !entry.header().entry_type().is_file() {
            continue;
        }
        let name = entry
            .path()
            .context("archive entry has an unreadable path")?
            .to_string_lossy()
            .trim_start_matches("./")
            .to_string();
        let mut data = Vec::new();
        entry
            .read_to_end(&mut data)
            .with_context(|| format!("failed to read archive entry {name}"))?;
        blobs.insert(name, data);
    }
    Ok(blobs)
}

fn collect_dir(
    root: &Path,
    dir: &Path,
    blobs: &mut HashMap<String, Vec<u8>>,
) -> anyhow::Result<()> {
    for entry in std::fs::read_dir(dir).with_context(|| format!("cannot read {}", dir.display()))? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_dir(root, &path, blobs)?;
        } else if path.is_file() {
            let rel = path
                .strip_prefix(root)
                .unwrap_or(&path)
                .to_string_lossy()
                .replace('\\', "/");
            let data = std::fs::read(&path)
                .with_context(|| format!("failed to read {}", path.display()))?;
            blobs.insert(rel, data);
        }
    }
    Ok(())
}

/// Select the image matching `platform` and return its ordered layers and
/// config JSON. Understands OCI layout (`index.json` + `blobs/`) and the
/// legacy `docker save` format (`manifest.json` with layer paths).
fn select_image(
    blobs: &HashMap<String, Vec<u8>>,
    platform: TargetPlatform,
) -> anyhow::Result<(Vec<LayerData>, Vec<u8>)> {
    if let Some(index) = blobs.get("index.json") {
        return select_from_oci_index(blobs, index, platform);
    }
    if let Some(manifest) = blobs.get("manifest.json") {
        return select_from_docker_manifest(blobs, manifest);
    }
    bail!("neither index.json (OCI layout) nor manifest.json (docker save) found");
}

fn blob_by_digest<'a>(
    blobs: &'a HashMap<String, Vec<u8>>,
    digest: &str,
) -> anyhow::Result<&'a Vec<u8>> {
    let (algo, hex) = digest
        .split_once(':')
        .with_context(|| format!("malformed digest: {digest}"))?;
    let path = format!("blobs/{algo}/{hex}");
    blobs
        .get(&path)
        .with_context(|| format!("blob {path} missing from archive"))
}

fn select_from_oci_index(
    blobs: &HashMap<String, Vec<u8>>,
    index: &[u8],
    platform: TargetPlatform,
) -> anyhow::Result<(Vec<LayerData>, Vec<u8>)> {
    let index: serde_json::Value =
        serde_json::from_slice(index).context("index.json is not valid JSON")?;
    let manifests = index
        .get("manifests")
        .and_then(|m| m.as_array())
        .context("index.json has no manifests array")?;

    // Depth-1 nested index resolution: pick the entry matching the platform,
    // recursing through one nested index level (docker buildx emits these).
    let mut available = Vec::new();
    let mut chosen: Option<&serde_json::Value> = None;
    let mut fallback: Option<&serde_json::Value> = None;
    for manifest in manifests {
        let entry_platform = manifest.get("platform");
        let os = entry_platform
            .and_then(|p| p.get("os"))
            .and_then(|o| o.as_str());
        let arch = entry_platform
            .and_then(|p| p.get("architecture"))
            .and_then(|a| a.as_str());
        match (os, arch) {
            (Some(os), Some(arch)) => {
                available.push(format!("{os}/{arch}"));
                if os == "linux" && arch == platform.oci_arch_name() {
                    chosen = Some(manifest);
                }
            }
            _ => {
                // No platform on the entry (single-image index): usable as
                // fallback when nothing matched explicitly.
                fallback.get_or_insert(manifest);
            }
        }
    }
    let manifest_entry = chosen.or(fallback).with_context(|| {
        format!(
            "no linux/{} image in archive index; available platforms: {}",
            platform.oci_arch_name(),
            if available.is_empty() {
                String::from("(none declared)")
            } else {
                available.join(", ")
            }
        )
    })?;

    let digest = manifest_entry
        .get("digest")
        .and_then(|d| d.as_str())
        .context("index manifest entry has no digest")?;
    let manifest_bytes = blob_by_digest(blobs, digest)?;
    let manifest: serde_json::Value =
        serde_json::from_slice(manifest_bytes).context("image manifest is not valid JSON")?;

    // A nested index (manifest list) resolves one level down.
    if manifest.get("manifests").is_some() {
        return select_from_oci_index(blobs, manifest_bytes, platform);
    }

    let config_digest = manifest
        .get("config")
        .and_then(|c| c.get("digest"))
        .and_then(|d| d.as_str())
        .context("image manifest has no config digest")?;
    let config_json = blob_by_digest(blobs, config_digest)?.clone();

    let layer_descriptors = manifest
        .get("layers")
        .and_then(|l| l.as_array())
        .context("image manifest has no layers array")?;
    let mut layers = Vec::with_capacity(layer_descriptors.len());
    for descriptor in layer_descriptors {
        let digest = descriptor
            .get("digest")
            .and_then(|d| d.as_str())
            .context("layer descriptor has no digest")?;
        let media_type = descriptor
            .get("mediaType")
            .and_then(|m| m.as_str())
            .unwrap_or("application/vnd.oci.image.layer.v1.tar")
            .to_string();
        layers.push(LayerData {
            data: blob_by_digest(blobs, digest)?.clone(),
            media_type,
        });
    }
    Ok((layers, config_json))
}

fn select_from_docker_manifest(
    blobs: &HashMap<String, Vec<u8>>,
    manifest: &[u8],
) -> anyhow::Result<(Vec<LayerData>, Vec<u8>)> {
    let manifest: serde_json::Value =
        serde_json::from_slice(manifest).context("manifest.json is not valid JSON")?;
    let images = manifest
        .as_array()
        .context("manifest.json is not an array")?;
    let image = images
        .first()
        .context("manifest.json lists no images (empty archive)")?;

    let config_path = image
        .get("Config")
        .and_then(|c| c.as_str())
        .context("manifest.json entry has no Config")?;
    let config_json = blobs
        .get(config_path)
        .with_context(|| format!("config {config_path} missing from archive"))?
        .clone();

    let layer_paths = image
        .get("Layers")
        .and_then(|l| l.as_array())
        .context("manifest.json entry has no Layers")?;
    let mut layers = Vec::with_capacity(layer_paths.len());
    for layer_path in layer_paths {
        let layer_path = layer_path
            .as_str()
            .context("manifest.json layer path is not a string")?;
        let data = blobs
            .get(layer_path)
            .with_context(|| format!("layer {layer_path} missing from archive"))?
            .clone();
        layers.push(LayerData {
            // docker save layers carry no media type; extract_layer sniffs
            // the compression from magic bytes.
            media_type: String::from("application/vnd.docker.image.rootfs.diff.tar"),
            data,
        });
    }
    Ok((layers, config_json))
}
