//! RFB security negotiation shared by the demo's two RFB servers.
//!
//! Without `VNC_PASSWORD` the server offers only security type 1 ("None"),
//! which is what `rfb_client_witness.py` and most third-party viewers accept.
//! Apple's built-in Screen Sharing client refuses such servers outright
//! ("Unable to communicate with ..."), so when `VNC_PASSWORD` is set the
//! server offers only type 2 (classic VNC Authentication, RFC 6143 7.2.2): a
//! 16-byte random challenge the client encrypts with DES, keyed by the
//! password. No dependencies: DES is implemented here from the FIPS 46-3
//! tables.

use std::io::{Read, Write};
use std::net::TcpStream;

const IP: [u8; 64] = [
    58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
];
const FP: [u8; 64] = [
    40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25,
];
const E: [u8; 48] = [
    32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18,
    19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1,
];
const P: [u8; 32] = [
    16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19,
    13, 30, 6, 22, 11, 4, 25,
];
const PC1: [u8; 56] = [
    57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3,
    60, 52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37,
    29, 21, 13, 5, 28, 20, 12, 4,
];
const PC2: [u8; 48] = [
    14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41,
    52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32,
];
const SHIFTS: [u8; 16] = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1];
const SBOX: [[u8; 64]; 8] = [
    [
        14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7, 0, 15, 7, 4, 14, 2, 13, 1, 10, 6,
        12, 11, 9, 5, 3, 8, 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0, 15, 12, 8, 2, 4,
        9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13,
    ],
    [
        15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10, 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1,
        10, 6, 9, 11, 5, 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15, 13, 8, 10, 1, 3,
        15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9,
    ],
    [
        10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8, 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5,
        14, 12, 11, 15, 1, 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7, 1, 10, 13, 0, 6,
        9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12,
    ],
    [
        7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15, 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2,
        12, 1, 10, 14, 9, 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4, 3, 15, 0, 6, 10,
        1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14,
    ],
    [
        2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9, 14, 11, 2, 12, 4, 7, 13, 1, 5, 0,
        15, 10, 3, 9, 8, 6, 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14, 11, 8, 12, 7, 1,
        14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3,
    ],
    [
        12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11, 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13,
        14, 0, 11, 3, 8, 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6, 4, 3, 2, 12, 9, 5,
        15, 10, 11, 14, 1, 7, 6, 0, 8, 13,
    ],
    [
        4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1, 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5,
        12, 2, 15, 8, 6, 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2, 6, 11, 13, 8, 1, 4,
        10, 7, 9, 5, 0, 15, 14, 2, 3, 12,
    ],
    [
        13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7, 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6,
        11, 0, 14, 9, 2, 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8, 2, 1, 14, 7, 4, 10,
        8, 13, 15, 12, 9, 0, 3, 5, 6, 11,
    ],
];

/// Output bit `i` (MSB first) is input bit `table[i]` (1-based, MSB first).
fn permute(input: u64, in_bits: u32, table: &[u8]) -> u64 {
    let mut out = 0u64;
    for &pos in table {
        out = (out << 1) | ((input >> (in_bits - u32::from(pos))) & 1);
    }
    out
}

fn subkeys(key: [u8; 8]) -> [u64; 16] {
    let permuted = permute(u64::from_be_bytes(key), 64, &PC1);
    let mut c = (permuted >> 28) & 0x0fff_ffff;
    let mut d = permuted & 0x0fff_ffff;
    let mut keys = [0u64; 16];
    for (round, &shift) in SHIFTS.iter().enumerate() {
        for _ in 0..shift {
            c = ((c << 1) | (c >> 27)) & 0x0fff_ffff;
            d = ((d << 1) | (d >> 27)) & 0x0fff_ffff;
        }
        keys[round] = permute((c << 28) | d, 56, &PC2);
    }
    keys
}

fn des_encrypt_block(keys: &[u64; 16], block: [u8; 8]) -> [u8; 8] {
    let ip = permute(u64::from_be_bytes(block), 64, &IP);
    let mut l = (ip >> 32) as u32;
    let mut r = ip as u32;
    for key in keys {
        let x = permute(u64::from(r), 32, &E) ^ key;
        let mut s_out = 0u32;
        for (i, sbox) in SBOX.iter().enumerate() {
            let six = ((x >> (42 - 6 * i)) & 0x3f) as usize;
            let row = ((six >> 4) & 0b10) | (six & 1);
            let col = (six >> 1) & 0xf;
            s_out = (s_out << 4) | u32::from(sbox[row * 16 + col]);
        }
        let f = permute(u64::from(s_out), 32, &P) as u32;
        (l, r) = (r, l ^ f);
    }
    let preoutput = (u64::from(r) << 32) | u64::from(l);
    permute(preoutput, 64, &FP).to_be_bytes()
}

/// The response a client must send for `challenge` under `password`: DES-ECB
/// of both 8-byte halves, keyed by the password truncated or zero-padded to 8
/// bytes with each key byte's bits reversed (VNC's long-standing quirk).
pub fn expected_response(password: &str, challenge: &[u8; 16]) -> [u8; 16] {
    let mut key = [0u8; 8];
    for (slot, byte) in key.iter_mut().zip(password.bytes()) {
        *slot = byte.reverse_bits();
    }
    let keys = subkeys(key);
    let mut out = [0u8; 16];
    for (half, chunk) in challenge.chunks_exact(8).enumerate() {
        let block: [u8; 8] = chunk.try_into().expect("chunks_exact(8)");
        out[half * 8..half * 8 + 8].copy_from_slice(&des_encrypt_block(&keys, block));
    }
    out
}

/// Not cryptographic-grade, but unpredictable enough for a demo challenge:
/// `RandomState` is seeded from the OS (`getrandom`), then mixed with time.
fn random_challenge() -> [u8; 16] {
    use std::hash::{BuildHasher, Hasher};
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let mut out = [0u8; 16];
    for (i, chunk) in out.chunks_exact_mut(8).enumerate() {
        let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
        hasher.write_u128(nanos);
        hasher.write_usize(i);
        chunk.copy_from_slice(&hasher.finish().to_be_bytes());
    }
    out
}

fn read_exact(stream: &mut TcpStream, buf: &mut [u8]) -> std::io::Result<()> {
    let mut filled = 0;
    while filled < buf.len() {
        match stream.read(&mut buf[filled..]) {
            Ok(0) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "connection closed mid-read",
                ));
            }
            Ok(n) => filled += n,
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::Interrupted =>
            {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Read `VNC_PASSWORD`; empty counts as unset.
pub fn password_from_env() -> Option<String> {
    std::env::var("VNC_PASSWORD").ok().filter(|p| !p.is_empty())
}

/// RFB 3.8 security handshake, called right after the version exchange:
/// offers type 2 if `password` is set, else type 1, and sends the
/// SecurityResult. A wrong response gets SecurityResult=1 plus a reason and
/// an `Err`.
pub fn negotiate_security(stream: &mut TcpStream, password: Option<&str>) -> std::io::Result<()> {
    let offered: u8 = if password.is_some() { 2 } else { 1 };
    stream.write_all(&[1, offered])?;
    let mut chosen = [0u8; 1];
    read_exact(stream, &mut chosen)?;
    if chosen[0] != offered {
        return Err(std::io::Error::other(format!(
            "client chose security type {}, only {offered} was offered",
            chosen[0]
        )));
    }
    if let Some(password) = password {
        let challenge = random_challenge();
        stream.write_all(&challenge)?;
        let mut response = [0u8; 16];
        read_exact(stream, &mut response)?;
        if response != expected_response(password, &challenge) {
            stream.write_all(&1u32.to_be_bytes())?;
            let reason = b"authentication failed";
            stream.write_all(&(reason.len() as u32).to_be_bytes())?;
            stream.write_all(reason)?;
            return Err(std::io::Error::other("VNC authentication failed"));
        }
    }
    stream.write_all(&0u32.to_be_bytes())
}
