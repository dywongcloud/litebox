// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The `.box.wasm` artifact format.
//!
//! A box is a genuine WebAssembly module. Its executable part is a minimal
//! WASI preview1 program whose `_start` writes the box's self-description to
//! stdout, so any wasm runtime can run the artifact and report what it holds.
//! The container payload rides in two custom sections, which runtimes skip
//! during instantiation, so instantiation cost is independent of image size:
//!
//! - `box.meta.v1` -- the [`BoxMeta`] JSON document
//! - `box.rootfs.v1` -- the litebox-packaged rootfs tar (syscall-rewritten
//!   binaries plus `litebox/config.json` and `litebox/config_and_run.sh`)
//!
//! `boxer run` reads the payload back and executes the workload natively
//! under the litebox runner on a matching host.

use anyhow::{Context, bail};
use serde::{Deserialize, Serialize};

/// Custom section carrying the [`BoxMeta`] JSON.
pub const META_SECTION: &str = "box.meta.v1";
/// Custom section carrying the packaged rootfs tar.
pub const ROOTFS_SECTION: &str = "box.rootfs.v1";

/// Upper bound on the rootfs payload. Wasm section sizes are u32-LEB encoded,
/// so 4 GiB is the hard format ceiling; stay comfortably under it so the
/// section header and metadata always fit.
pub const MAX_ROOTFS_BYTES: u64 = 3_758_096_384; // 3.5 GiB

/// The metadata document embedded in every box.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BoxMeta {
    /// Always `"litebox-box"`.
    pub format: String,
    /// Format version, `1`.
    pub version: u32,
    /// Target OS, always `"linux"`.
    pub os: String,
    /// Target architecture: `"amd64"` or `"arm64"`.
    pub architecture: String,
    /// AArch64 syscall-rewrite anchor: `"linux"` or `"macos"`.
    /// x86-64 boxes are always `"linux"`.
    pub rewrite_host: String,
    /// What the box was built from (image reference, archive path, or
    /// `dockerfile:<path>`).
    pub source: String,
    /// Image ENTRYPOINT, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entrypoint: Option<Vec<String>>,
    /// Image CMD, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cmd: Option<Vec<String>>,
    /// Image environment (`KEY=VALUE` entries).
    #[serde(default)]
    pub env: Vec<String>,
    /// Image working directory, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub working_dir: Option<String>,
    /// Image USER, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    /// Number of entries in the rootfs tar.
    pub tar_entries: u64,
    /// Size of the rootfs tar in bytes.
    pub tar_size: u64,
    /// SHA-256 of the rootfs tar, lowercase hex.
    pub tar_sha256: String,
}

/// A parsed box: metadata plus the rootfs tar bytes.
pub struct ParsedBox {
    pub meta: BoxMeta,
    pub rootfs_tar: Vec<u8>,
}

// --- wasm encoding -----------------------------------------------------

fn leb128(mut value: u64, out: &mut Vec<u8>) {
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

fn section(id: u8, body: &[u8], out: &mut Vec<u8>) {
    out.push(id);
    leb128(body.len() as u64, out);
    out.extend_from_slice(body);
}

fn custom_section(name: &str, payload: &[u8], out: &mut Vec<u8>) {
    let mut body = Vec::with_capacity(name.len() + payload.len() + 8);
    leb128(name.len() as u64, &mut body);
    body.extend_from_slice(name.as_bytes());
    body.extend_from_slice(payload);
    section(0, &body, out);
}

/// Emit a `_start` body that fd_writes `banner_len` bytes from linear-memory
/// offset 8 to stdout. Memory layout: iovec at 0 (base=8, len=banner_len),
/// nwritten scratch right after the banner, 4-byte aligned.
fn start_function_body(banner_len: u32) -> Vec<u8> {
    let nwritten_ptr = (8 + banner_len).next_multiple_of(4);
    let mut body = Vec::new();
    body.push(0x00); // no locals
    let mut instr = |bytes: &[u8]| body.extend_from_slice(bytes);
    // i32.store at 0: iov_base = 8
    instr(&[0x41, 0x00]); // i32.const 0
    instr(&[0x41, 0x08]); // i32.const 8
    instr(&[0x36, 0x02, 0x00]); // i32.store align=2 offset=0
    // i32.store at 4: iov_len = banner_len
    instr(&[0x41, 0x04]); // i32.const 4
    let mut len_const = vec![0x41];
    leb128_signed(i64::from(banner_len), &mut len_const);
    instr(&len_const);
    instr(&[0x36, 0x02, 0x00]);
    // fd_write(1, 0, 1, nwritten_ptr)
    instr(&[0x41, 0x01]); // fd = stdout
    instr(&[0x41, 0x00]); // iovs = 0
    instr(&[0x41, 0x01]); // iovs_len = 1
    let mut ptr_const = vec![0x41];
    leb128_signed(i64::from(nwritten_ptr), &mut ptr_const);
    instr(&ptr_const);
    instr(&[0x10, 0x00]); // call 0 (fd_write import)
    instr(&[0x1a]); // drop errno
    instr(&[0x0b]); // end
    let mut framed = Vec::with_capacity(body.len() + 4);
    leb128(body.len() as u64, &mut framed);
    framed.extend_from_slice(&body);
    framed
}

fn leb128_signed(mut value: i64, out: &mut Vec<u8>) {
    loop {
        #[allow(
            clippy::cast_sign_loss,
            reason = "masked to the low 7 bits, always in 0..=0x7f"
        )]
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        let sign_clear = byte & 0x40 == 0;
        if (value == 0 && sign_clear) || (value == -1 && !sign_clear) {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

/// Encode a complete `.box.wasm` module from metadata and the packaged tar.
pub fn encode(meta: &BoxMeta, rootfs_tar: &[u8]) -> anyhow::Result<Vec<u8>> {
    if rootfs_tar.len() as u64 > MAX_ROOTFS_BYTES {
        bail!(
            "rootfs tar is {} bytes, above the {} byte box format ceiling",
            rootfs_tar.len(),
            MAX_ROOTFS_BYTES
        );
    }
    if rootfs_tar.len() as u64 > 2 * 1024 * 1024 * 1024 {
        eprintln!(
            "warning: box payload is {} bytes; the module stays valid wasm, but JS engines \
             (node, browsers) cap single buffers at 2 GiB, so only native tools like \
             `boxer run` will load it",
            rootfs_tar.len()
        );
    }
    let meta_json = serde_json::to_vec(meta).context("failed to serialize box metadata")?;

    let banner = format!(
        "litebox box: linux/{} from {}\nrun natively with `boxer run <this file>` on a matching host\n{}\n",
        meta.architecture,
        meta.source,
        String::from_utf8_lossy(&meta_json),
    );
    let banner = banner.into_bytes();
    let banner_len =
        u32::try_from(banner.len()).context("box banner exceeds u32 (metadata too large)")?;
    // One 64 KiB wasm page covers iovec + banner + scratch unless the banner
    // itself is huge; size pages to fit.
    let pages = (u64::from(banner_len) + 16).div_ceil(65536).max(1);

    let mut module = Vec::with_capacity(rootfs_tar.len() + banner.len() + 512);
    module.extend_from_slice(&[0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]);

    // type section: [0] () -> (), [1] (i32,i32,i32,i32) -> (i32)
    let mut types = Vec::new();
    leb128(2, &mut types);
    types.extend_from_slice(&[0x60, 0x00, 0x00]);
    types.extend_from_slice(&[0x60, 0x04, 0x7f, 0x7f, 0x7f, 0x7f, 0x01, 0x7f]);
    section(1, &types, &mut module);

    // import section: wasi_snapshot_preview1.fd_write : type 1
    let mut imports = Vec::new();
    leb128(1, &mut imports);
    let module_name = b"wasi_snapshot_preview1";
    let field_name = b"fd_write";
    leb128(module_name.len() as u64, &mut imports);
    imports.extend_from_slice(module_name);
    leb128(field_name.len() as u64, &mut imports);
    imports.extend_from_slice(field_name);
    imports.push(0x00); // func import
    leb128(1, &mut imports); // type index 1
    section(2, &imports, &mut module);

    // function section: one function of type 0
    let mut funcs = Vec::new();
    leb128(1, &mut funcs);
    leb128(0, &mut funcs);
    section(3, &funcs, &mut module);

    // memory section: one memory, min `pages`
    let mut memory = Vec::new();
    leb128(1, &mut memory);
    memory.push(0x00); // no max
    leb128(pages, &mut memory);
    section(5, &memory, &mut module);

    // export section: "memory" mem 0, "_start" func 1 (imports precede)
    let mut exports = Vec::new();
    leb128(2, &mut exports);
    let mem_name = b"memory";
    leb128(mem_name.len() as u64, &mut exports);
    exports.extend_from_slice(mem_name);
    exports.push(0x02); // memory
    leb128(0, &mut exports);
    let start_name = b"_start";
    leb128(start_name.len() as u64, &mut exports);
    exports.extend_from_slice(start_name);
    exports.push(0x00); // func
    leb128(1, &mut exports);
    section(7, &exports, &mut module);

    // code section
    let mut code = Vec::new();
    leb128(1, &mut code);
    code.extend_from_slice(&start_function_body(banner_len));
    section(10, &code, &mut module);

    // data section: banner at offset 8
    let mut data = Vec::new();
    leb128(1, &mut data);
    data.push(0x00); // active, memory 0
    data.extend_from_slice(&[0x41, 0x08, 0x0b]); // i32.const 8; end
    leb128(banner.len() as u64, &mut data);
    data.extend_from_slice(&banner);
    section(11, &data, &mut module);

    custom_section(META_SECTION, &meta_json, &mut module);
    custom_section(ROOTFS_SECTION, rootfs_tar, &mut module);

    Ok(module)
}

// --- wasm parsing ------------------------------------------------------

struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn u8(&mut self) -> anyhow::Result<u8> {
        let Some(&b) = self.bytes.get(self.pos) else {
            bail!("truncated wasm module at offset {}", self.pos);
        };
        self.pos += 1;
        Ok(b)
    }

    fn leb128_u32(&mut self) -> anyhow::Result<u32> {
        let mut result: u32 = 0;
        for shift in (0..).step_by(7) {
            if shift >= 35 {
                bail!("oversized LEB128 value at offset {}", self.pos);
            }
            let byte = self.u8()?;
            let bits = u32::from(byte & 0x7f);
            result |= bits
                .checked_shl(shift)
                .filter(|_| shift < 32 || bits == 0)
                .with_context(|| format!("LEB128 overflow at offset {}", self.pos))?;
            if byte & 0x80 == 0 {
                return Ok(result);
            }
        }
        unreachable!("loop always returns or bails");
    }

    fn slice(&mut self, len: usize) -> anyhow::Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(len)
            .filter(|&end| end <= self.bytes.len())
            .with_context(|| {
                format!(
                    "wasm section at offset {} claims {len} bytes past end of file",
                    self.pos
                )
            })?;
        let slice = &self.bytes[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    fn done(&self) -> bool {
        self.pos >= self.bytes.len()
    }
}

/// Find a custom section by name. Returns `Ok(None)` when the module is valid
/// wasm but has no such section.
fn find_custom_section<'a>(bytes: &'a [u8], wanted: &str) -> anyhow::Result<Option<&'a [u8]>> {
    if bytes.len() < 8 || bytes[..4] != [0x00, 0x61, 0x73, 0x6d] {
        bail!("not a WebAssembly module (bad magic)");
    }
    if bytes[4..8] != [0x01, 0x00, 0x00, 0x00] {
        bail!("unsupported WebAssembly version");
    }
    let mut cursor = Cursor { bytes, pos: 8 };
    while !cursor.done() {
        let id = cursor.u8()?;
        let size = cursor.leb128_u32()? as usize;
        let body = cursor.slice(size)?;
        if id == 0 {
            let mut inner = Cursor {
                bytes: body,
                pos: 0,
            };
            let name_len = inner.leb128_u32()? as usize;
            let name = inner.slice(name_len)?;
            if name == wanted.as_bytes() {
                return Ok(Some(&body[inner.pos..]));
            }
        }
    }
    Ok(None)
}

/// Parse a `.box.wasm` file into its metadata and rootfs tar.
pub fn parse(bytes: &[u8]) -> anyhow::Result<ParsedBox> {
    let meta_bytes = find_custom_section(bytes, META_SECTION)?
        .context("wasm module has no box.meta.v1 section; not a litebox box")?;
    let meta: BoxMeta = serde_json::from_slice(meta_bytes).context("box.meta.v1 is not valid")?;
    if meta.format != "litebox-box" {
        bail!("box metadata names unknown format '{}'", meta.format);
    }
    if meta.version != 1 {
        bail!(
            "box format version {} is not supported (want 1)",
            meta.version
        );
    }
    let rootfs = find_custom_section(bytes, ROOTFS_SECTION)?
        .context("wasm module has no box.rootfs.v1 section; not a litebox box")?;
    if rootfs.len() as u64 != meta.tar_size {
        bail!(
            "box.rootfs.v1 is {} bytes but metadata declares {}; corrupt box",
            rootfs.len(),
            meta.tar_size
        );
    }
    let digest = sha256_hex(rootfs);
    if digest != meta.tar_sha256 {
        bail!("box.rootfs.v1 digest mismatch: corrupt or tampered box");
    }
    Ok(ParsedBox {
        meta,
        rootfs_tar: rootfs.to_vec(),
    })
}

/// Lowercase-hex SHA-256.
pub fn sha256_hex(data: &[u8]) -> String {
    use sha2::Digest as _;
    let digest = sha2::Sha256::digest(data);
    let mut hex = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}
