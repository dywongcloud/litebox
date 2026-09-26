// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! A classic-BPF verifier and interpreter for `seccomp(SECCOMP_SET_MODE_FILTER)` programs,
//! matching Linux 5.11's `seccomp_check_filter`/`bpf_check_classic`
//! (`net/core/filter.c`/`kernel/seccomp.c`) and the classic `sock_filter` interpreter exactly.
//!
//! Self-contained and allocation-light: every function here takes already-copied bytes (never a
//! guest pointer) and does no locking, no I/O, and no guest-memory access, so it is exercised the
//! same way whether called from the real install/enforcement path or from a throwaway host-side
//! diagnostic. [`verify_program`] is the only way a program is ever accepted; [`run_program`]
//! trusts its input was already verified and is safe (never panics, never runs unbounded) even if
//! that trust turns out to be misplaced, by construction (see its own doc comment).

use litebox_common_linux::errno::Errno;

/// `sizeof(struct seccomp_data)`: `nr`(4) + `arch`(4) + `instruction_pointer`(8) + `args[6]`(48).
pub(crate) const SECCOMP_DATA_LEN: usize = 64;

/// `BPF_MAXINSNS`: the maximum instruction count of a single installed program.
pub(crate) const BPF_MAXINSNS: usize = 4096;

/// The stacked-chain-length charge cap (`MAX_INSNS_PER_PATH` in Linux): a new install is refused
/// once `new_len + sum(existing filters' (len + 4))` would exceed this. With every filter at the
/// legal minimum length (1), this permits at most 6554 total chain nodes (1 + 6553 existing, each
/// costing `1 + 4 = 5`): `1 + 5 * 6553 = 32766 <= 32768 < 1 + 5 * 6554`.
pub(crate) const SECCOMP_MAX_STACKED_INSNS: u64 = 32768;

pub(crate) const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
pub(crate) const SECCOMP_RET_KILL_THREAD: u32 = 0x0000_0000;
pub(crate) const SECCOMP_RET_TRAP: u32 = 0x0003_0000;
pub(crate) const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
pub(crate) const SECCOMP_RET_USER_NOTIF: u32 = 0x7fc0_0000;
pub(crate) const SECCOMP_RET_TRACE: u32 = 0x7ff0_0000;
pub(crate) const SECCOMP_RET_LOG: u32 = 0x7ffc_0000;
pub(crate) const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
/// Masks off the low 16 "data" bits, isolating the action.
pub(crate) const SECCOMP_RET_ACTION_FULL: u32 = 0xffff_0000;
/// The low 16 bits an action (`ERRNO`, `USER_NOTIF`, `TRACE`, `LOG`) may carry as auxiliary data.
pub(crate) const SECCOMP_RET_DATA: u32 = 0x0000_ffff;
/// `ERRNO`'s data is additionally capped here (`SECCOMP_RET_ERRNO`'s own real-Linux limit).
pub(crate) const SECCOMP_RET_ERRNO_DATA_MAX: u32 = 4095;

/// Builds the exact 64-byte, native-endian `struct seccomp_data` a verified program's `LD|W|ABS`
/// reads index into -- never big-endian/packet semantics (see [`run_program`]'s own doc comment
/// for why `LD|W|ABS` is a plain native struct-field read here, not a packet load).
pub(crate) fn build_seccomp_data(nr: i32, arch: u32, ip: u64, args: [u64; 6]) -> [u8; SECCOMP_DATA_LEN] {
    let mut buf = [0u8; SECCOMP_DATA_LEN];
    buf[0..4].copy_from_slice(&nr.to_ne_bytes());
    buf[4..8].copy_from_slice(&arch.to_ne_bytes());
    buf[8..16].copy_from_slice(&ip.to_ne_bytes());
    for (index, arg) in args.iter().enumerate() {
        let offset = 16 + index * 8;
        buf[offset..offset + 8].copy_from_slice(&arg.to_ne_bytes());
    }
    buf
}

/// One raw `struct sock_filter` (`{ u16 code; u8 jt; u8 jf; u32 k; }`), parsed from its 8-byte
/// wire form by plain byte indexing rather than a zerocopy reinterpret -- the source byte buffer
/// (guest-copied, `Box<[u8]>`) is only ever guaranteed `u8` alignment, and this avoids relying on
/// any stronger alignment ever holding.
#[derive(Clone, Copy, Debug)]
struct RawInsn {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

fn parse_insn(chunk: &[u8; 8]) -> RawInsn {
    RawInsn {
        code: u16::from_ne_bytes([chunk[0], chunk[1]]),
        jt: chunk[2],
        jf: chunk[3],
        k: u32::from_ne_bytes([chunk[4], chunk[5], chunk[6], chunk[7]]),
    }
}

/// Parses `bytes` into instructions, or `None` if its length is not a positive multiple of 8 not
/// exceeding [`BPF_MAXINSNS`] instructions -- the same shape [`verify_program`] itself requires,
/// but written as a totally separate, structural first gate so a malformed length can never even
/// reach opcode-level validation.
fn parse_program(bytes: &[u8]) -> Option<alloc::vec::Vec<RawInsn>> {
    if bytes.len() % 8 != 0 {
        return None;
    }
    let len = bytes.len() / 8;
    if len == 0 || len > BPF_MAXINSNS {
        return None;
    }
    let mut insns = alloc::vec::Vec::new();
    insns.try_reserve_exact(len).ok()?;
    for chunk in bytes.chunks_exact(8) {
        let array: [u8; 8] = chunk.try_into().expect("chunks_exact(8) yields 8-byte chunks");
        insns.push(parse_insn(&array));
    }
    Some(insns)
}

const BPF_MEMWORDS: u32 = 16;

/// Whitelist of every opcode byte `seccomp_check_filter` accepts, encoded as `(class|mode|op|src)`
/// byte values. Deliberately narrower than the generic classic-BPF checker `bpf_check_classic`
/// alone would allow (no `MOD`, no `H`/`B`-sized or `IND` loads, no `MSH`) -- matching real
/// Linux's own additional seccomp-specific restriction on top of it.
fn is_allowed_opcode(code: u16) -> bool {
    matches!(
        code,
        0x06 | 0x16 // RET|K, RET|A
        | 0x00 | 0x01 // LD|IMM, LDX|IMM
        | 0x60 | 0x61 // LD|MEM, LDX|MEM
        | 0x02 | 0x03 // ST, STX
        | 0x07 | 0x87 // MISC|TAX, MISC|TXA
        | 0x04 | 0x0c // ALU|ADD|K, ALU|ADD|X
        | 0x14 | 0x1c // ALU|SUB|K, ALU|SUB|X
        | 0x24 | 0x2c // ALU|MUL|K, ALU|MUL|X
        | 0x34 | 0x3c // ALU|DIV|K, ALU|DIV|X
        | 0x44 | 0x4c // ALU|OR|K,  ALU|OR|X
        | 0x54 | 0x5c // ALU|AND|K, ALU|AND|X
        | 0x64 | 0x6c // ALU|LSH|K, ALU|LSH|X
        | 0x74 | 0x7c // ALU|RSH|K, ALU|RSH|X
        | 0x84 // ALU|NEG
        | 0xa4 | 0xac // ALU|XOR|K, ALU|XOR|X
        | 0x05 // JMP|JA
        | 0x15 | 0x1d // JMP|JEQ|K,  JMP|JEQ|X
        | 0x25 | 0x2d // JMP|JGT|K,  JMP|JGT|X
        | 0x35 | 0x3d // JMP|JGE|K,  JMP|JGE|X
        | 0x45 | 0x4d // JMP|JSET|K, JMP|JSET|X
        | 0x20 // LD|W|ABS  (rewritten internally to a `seccomp_data`-relative indexed load)
        | 0x80 | 0x81 // LD|W|LEN, LDX|W|LEN (both read back the constant `SECCOMP_DATA_LEN`)
    )
}

fn is_conditional_jump(code: u16) -> bool {
    matches!(code, 0x15 | 0x1d | 0x25 | 0x2d | 0x35 | 0x3d | 0x45 | 0x4d)
}

/// `bpf_check_classic`'s per-instruction pass: opcode whitelist, `DIV|K`-by-zero and
/// oversized-immediate-shift rejection, in-range scratch (`M[]`) indices, forward-only in-range
/// jump targets, 4-byte-aligned in-bounds `seccomp_data` loads, and a `RET`-terminal program.
fn check_instructions(insns: &[RawInsn]) -> Result<(), Errno> {
    let flen = insns.len();
    for (pc, insn) in insns.iter().enumerate() {
        if !is_allowed_opcode(insn.code) {
            return Err(Errno::EINVAL);
        }
        match insn.code {
            0x34 if insn.k == 0 => return Err(Errno::EINVAL), // ALU|DIV|K, k == 0
            0x64 | 0x74 if insn.k >= 32 => return Err(Errno::EINVAL), // ALU|LSH|K, ALU|RSH|K
            0x60 | 0x61 | 0x02 | 0x03 if insn.k >= BPF_MEMWORDS => return Err(Errno::EINVAL),
            0x05 => {
                // JMP|JA: unconditional, always forward (`k` is unsigned), so this alone rules
                // out any loop -- there is no encoding for a backward classic-BPF jump at all.
                if insn.k as usize >= flen - pc - 1 {
                    return Err(Errno::EINVAL);
                }
            }
            code if is_conditional_jump(code) => {
                let jt = insn.jt as usize;
                let jf = insn.jf as usize;
                if pc + jt + 1 >= flen || pc + jf + 1 >= flen {
                    return Err(Errno::EINVAL);
                }
            }
            0x20 => {
                // LD|W|ABS: 4-byte aligned and fully inside `struct seccomp_data`.
                if insn.k >= SECCOMP_DATA_LEN as u32 || insn.k % 4 != 0 {
                    return Err(Errno::EINVAL);
                }
            }
            _ => {}
        }
    }
    match insns[flen - 1].code {
        0x06 | 0x16 => Ok(()),
        _ => Err(Errno::EINVAL),
    }
}

/// `check_load_and_stores`: a forward dataflow pass proving every `LD|MEM`/`LDX|MEM` reads a
/// scratch slot some preceding `ST`/`STX` definitely wrote on every path that can reach it.
/// `masks[pc]` accumulates (by AND) the requirement every jump edge into `pc` imposes; falling
/// off a jump resets the running `memvalid` to "no requirement" (`!0`), since only an edge
/// explicitly recorded in `masks` may be relied on from that point forward.
fn check_definite_scratch_init(insns: &[RawInsn]) -> Result<(), Errno> {
    let flen = insns.len();
    let mut masks: alloc::vec::Vec<u16> = alloc::vec::Vec::new();
    masks.try_reserve_exact(flen).map_err(|_| Errno::ENOMEM)?;
    masks.resize(flen, 0xffff);
    let mut memvalid: u16 = 0;
    for (pc, insn) in insns.iter().enumerate() {
        memvalid &= masks[pc];
        match insn.code {
            0x02 | 0x03 => memvalid |= 1u16 << insn.k, // ST, STX
            0x60 | 0x61 => {
                // LD|MEM, LDX|MEM
                if memvalid & (1u16 << insn.k) == 0 {
                    return Err(Errno::EINVAL);
                }
            }
            0x05 => {
                // JMP|JA: bounds already proven by `check_instructions`.
                let target = pc + 1 + insn.k as usize;
                masks[target] &= memvalid;
                memvalid = !0;
            }
            code if is_conditional_jump(code) => {
                let jt_target = pc + 1 + insn.jt as usize;
                let jf_target = pc + 1 + insn.jf as usize;
                masks[jt_target] &= memvalid;
                masks[jf_target] &= memvalid;
                memvalid = !0;
            }
            _ => {}
        }
    }
    Ok(())
}

/// Verifies a raw, already-copied classic-BPF program byte-for-byte against Linux 5.11's
/// `seccomp_check_filter`/`bpf_check_classic`/`check_load_and_stores`. This is the *only* path
/// that ever accepts a program: [`run_program`] trusts its input was verified here first.
pub(crate) fn verify_program(bytes: &[u8]) -> Result<(), Errno> {
    let insns = parse_program(bytes).ok_or(Errno::EINVAL)?;
    check_instructions(&insns)?;
    check_definite_scratch_init(&insns)
}

/// Charges a new program of `new_len` instructions against the existing chain's own summed
/// `(len + 4)` cost (`existing_prev_plus_four_sum`), refusing the install with `ENOMEM` -- Linux's
/// own errno for this charge -- if the stacked total would exceed [`SECCOMP_MAX_STACKED_INSNS`].
pub(crate) fn stacked_charge_ok(new_len: u64, existing_prev_plus_four_sum: u64) -> bool {
    match new_len.checked_add(existing_prev_plus_four_sum) {
        Some(total) => total <= SECCOMP_MAX_STACKED_INSNS,
        None => false,
    }
}

/// Runs an already-[`verify_program`]-accepted classic-BPF program against `data` (a
/// [`build_seccomp_data`]-shaped 64-byte buffer), returning its raw 32-bit result.
///
/// `LD|W|ABS` is a plain native-endian 4-byte read off `data` at the verified offset -- *not*
/// big-endian/packet-load semantics. Real Linux rewrites this opcode to an eBPF indexed
/// (`ctx`-relative) memory load rather than the skb-oriented absolute-load helper precisely so
/// that a `struct seccomp_data*` context is read as a plain struct, never as network packet data;
/// this interpreter reproduces that same native-struct-read behavior directly, with no
/// intermediate eBPF form.
///
/// Never panics and never runs unbounded, even given a hypothetically-unverified or corrupted
/// `bytes` argument: `DIV|X`-by-zero returns `0` immediately (matching real classic BPF, not a
/// trap), every dynamic shift count is masked with `& 31` before use, every scratch/jump index is
/// bounds-checked at each step with a fail-closed [`SECCOMP_RET_KILL_THREAD`] default, and
/// execution is bounded by an explicit fuel counter seeded from the instruction count -- a
/// property [`verify_program`]'s forward-only jump bounds already guarantee structurally (no
/// classic-BPF encoding can express a backward jump at all), but which this defends explicitly
/// rather than only by construction.
pub(crate) fn run_program(bytes: &[u8], data: &[u8; SECCOMP_DATA_LEN]) -> u32 {
    let Some(insns) = parse_program(bytes) else {
        return SECCOMP_RET_KILL_THREAD;
    };
    let mut fuel = insns.len();
    let mut a: u32 = 0;
    let mut x: u32 = 0;
    let mut mem = [0u32; BPF_MEMWORDS as usize];
    let mut pc: usize = 0;
    loop {
        if fuel == 0 || pc >= insns.len() {
            return SECCOMP_RET_KILL_THREAD;
        }
        fuel -= 1;
        let insn = insns[pc];
        match insn.code {
            0x06 => return insn.k,  // RET|K
            0x16 => return a,       // RET|A
            0x00 => {
                a = insn.k;
                pc += 1;
            } // LD|IMM
            0x01 => {
                x = insn.k;
                pc += 1;
            } // LDX|IMM
            0x20 => {
                // LD|W|ABS: verified 4-byte-aligned, in-bounds offset into `data`.
                let offset = insn.k as usize;
                let Some(word) = data.get(offset..offset + 4) else {
                    return SECCOMP_RET_KILL_THREAD;
                };
                a = u32::from_ne_bytes(word.try_into().expect("4-byte slice"));
                pc += 1;
            }
            0x80 => {
                a = SECCOMP_DATA_LEN as u32;
                pc += 1;
            } // LD|W|LEN
            0x81 => {
                x = SECCOMP_DATA_LEN as u32;
                pc += 1;
            } // LDX|W|LEN
            0x60 => {
                let Some(&word) = mem.get(insn.k as usize) else {
                    return SECCOMP_RET_KILL_THREAD;
                };
                a = word;
                pc += 1;
            } // LD|MEM
            0x61 => {
                let Some(&word) = mem.get(insn.k as usize) else {
                    return SECCOMP_RET_KILL_THREAD;
                };
                x = word;
                pc += 1;
            } // LDX|MEM
            0x02 => {
                let Some(slot) = mem.get_mut(insn.k as usize) else {
                    return SECCOMP_RET_KILL_THREAD;
                };
                *slot = a;
                pc += 1;
            } // ST
            0x03 => {
                let Some(slot) = mem.get_mut(insn.k as usize) else {
                    return SECCOMP_RET_KILL_THREAD;
                };
                *slot = x;
                pc += 1;
            } // STX
            0x04 => {
                a = a.wrapping_add(insn.k);
                pc += 1;
            }
            0x0c => {
                a = a.wrapping_add(x);
                pc += 1;
            }
            0x14 => {
                a = a.wrapping_sub(insn.k);
                pc += 1;
            }
            0x1c => {
                a = a.wrapping_sub(x);
                pc += 1;
            }
            0x24 => {
                a = a.wrapping_mul(insn.k);
                pc += 1;
            }
            0x2c => {
                a = a.wrapping_mul(x);
                pc += 1;
            }
            0x34 => {
                // ALU|DIV|K: verified `k != 0`.
                a = if insn.k == 0 { 0 } else { a / insn.k };
                pc += 1;
            }
            0x3c => {
                // ALU|DIV|X: real classic-BPF semantics -- a runtime-zero divisor makes the
                // *whole program* return 0 immediately, not a trap and not "skip this insn".
                if x == 0 {
                    return 0;
                }
                a /= x;
                pc += 1;
            }
            0x44 => {
                a |= insn.k;
                pc += 1;
            }
            0x4c => {
                a |= x;
                pc += 1;
            }
            0x54 => {
                a &= insn.k;
                pc += 1;
            }
            0x5c => {
                a &= x;
                pc += 1;
            }
            0x64 => {
                a = a.wrapping_shl(insn.k & 31);
                pc += 1;
            }
            0x6c => {
                a = a.wrapping_shl(x & 31);
                pc += 1;
            }
            0x74 => {
                a = a.wrapping_shr(insn.k & 31);
                pc += 1;
            }
            0x7c => {
                a = a.wrapping_shr(x & 31);
                pc += 1;
            }
            0x84 => {
                a = a.wrapping_neg();
                pc += 1;
            }
            0xa4 => {
                a ^= insn.k;
                pc += 1;
            }
            0xac => {
                a ^= x;
                pc += 1;
            }
            0x07 => {
                x = a;
                pc += 1;
            } // MISC|TAX
            0x87 => {
                a = x;
                pc += 1;
            } // MISC|TXA
            0x05 => pc = pc + 1 + insn.k as usize, // JMP|JA
            0x15 => pc = pc + 1 + usize::from(if a == insn.k { insn.jt } else { insn.jf }),
            0x1d => pc = pc + 1 + usize::from(if a == x { insn.jt } else { insn.jf }),
            0x25 => pc = pc + 1 + usize::from(if a > insn.k { insn.jt } else { insn.jf }),
            0x2d => pc = pc + 1 + usize::from(if a > x { insn.jt } else { insn.jf }),
            0x35 => pc = pc + 1 + usize::from(if a >= insn.k { insn.jt } else { insn.jf }),
            0x3d => pc = pc + 1 + usize::from(if a >= x { insn.jt } else { insn.jf }),
            0x45 => pc = pc + 1 + usize::from(if a & insn.k != 0 { insn.jt } else { insn.jf }),
            0x4d => pc = pc + 1 + usize::from(if a & x != 0 { insn.jt } else { insn.jf }),
            _ => return SECCOMP_RET_KILL_THREAD, // structurally unreachable past `verify_program`
        }
    }
}

/// Real Linux's own chain-evaluation precedence rule (`action_precedence`/`ACTION_ONLY` in
/// `kernel/seccomp.c`): the *lowest* signed value among the masked action bits always wins, which
/// is exactly why `KILL_PROCESS` (`0x8000_0000`, the most negative `i32`) outranks everything.
/// Returns whether `candidate` is strictly more severe than `current` -- equal severity must never
/// replace, so a caller walking newest-to-oldest and calling this for each older node naturally
/// keeps the newest node's own data on a tie.
pub(crate) fn is_strictly_more_severe(candidate: u32, current: u32) -> bool {
    ((candidate & SECCOMP_RET_ACTION_FULL) as i32) < ((current & SECCOMP_RET_ACTION_FULL) as i32)
}
