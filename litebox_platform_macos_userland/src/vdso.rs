// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The guest vDSO the HVF backend maps into every guest address space, so that
//! `clock_gettime`/`gettimeofday`/`clock_getres` stop being VM exits.
//!
//! Under HVF a guest runs unchanged stock code on a real vCPU, and every
//! `SVC` is a full exit (lane hand-off, architectural-state marshalling,
//! shim dispatch) that costs on the order of 10 µs. A Linux libc only makes
//! `clock_gettime` a syscall when the auxv carries no `AT_SYSINFO_EHDR`; with
//! one, musl (`__vdsosym`) and glibc (`dl_vdso_vsym`) resolve
//! `__kernel_clock_gettime@LINUX_2.6.39` out of the ELF image at that address
//! and call it instead. Chromium's `TimeTicks::Now` traffic alone made
//! `clock_gettime` 65-75% of every guest syscall on the desktop image.
//!
//! The image is a real `ET_DYN` built at runtime by [`build_image`]: one
//! `PT_LOAD` covering the whole (file offset == virtual address) image, a
//! `PT_DYNAMIC` with `DT_HASH`/`DT_SYMTAB`/`DT_STRTAB`/`DT_SONAME` and the
//! `DT_VERSYM`/`DT_VERDEF` tables carrying the `LINUX_2.6.39` version both
//! libcs look up, and the position-independent AArch64 text assembled below.
//! It occupies the first 16 KiB page; the page right after it is the clock
//! data page (layout: the `CLOCK_*` offsets), which the host keeps current
//! through its own writable storage alias while every guest maps it
//! read-only (see `HvfBackend::install_vdso`). The page carries no seqlock:
//! `numer`/`denom`/`mono_epoch_ns` are published before the first guest
//! instruction ever runs and never change afterwards, and the only word the
//! host rewrites while guests run is `real_offset_ns`, one aligned 64-bit
//! store, so a guest reader can never be made to spin on a host writer --
//! which matters, because a host thread (unlike a kernel) can be preempted
//! mid-update, and a seqlock reader spinning on that would mean every
//! guest clock reader burning its vCPU lane until the host thread runs
//! again -- a whole-desktop stall for as long as the host scheduler
//! pleases. Plain loads have no such failure mode.
//!
//! Clock derivation. Hypervisor.framework defines the guest's counter as
//! `CNTVCT_EL0 = mach_absolute_time() - vtimer_offset` and the backend
//! programs a zero offset on every lane, so the guest reads exactly the
//! host's `mach_absolute_time()`, at `CNTFRQ_EL0 == 24 MHz` on every Apple
//! Silicon Mac (verified live on a host whose physical counter runs at
//! 1 GHz: the guest still sees the 24 MHz `mach_absolute_time` value). The
//! host's own `clock_gettime(CLOCK_MONOTONIC_RAW)` -- the source of this
//! platform's `Instant`, hence of the shim's `CLOCK_MONOTONIC` -- is exactly
//! `floor(mach_absolute_time() * numer / denom)` with `mach_timebase_info`'s
//! `numer`/`denom` (verified on 300 000/300 000 bracketed samples), so the
//! text computes the identical function of the identical counter:
//!
//! * `raw_ns = CNTVCT_EL0 * numer / denom`
//! * `CLOCK_MONOTONIC` (and `MONOTONIC_RAW`/`MONOTONIC_COARSE`/`BOOTTIME`,
//!   which the shim serves from the same clock) `= raw_ns - mono_epoch_ns`,
//!   where `mono_epoch_ns` is the shim's own boot instant, handed over via
//!   `TimeProvider::publish_monotonic_epoch` -- the same epoch, the same
//!   arithmetic, so a guest mixing vDSO and syscall reads never sees the
//!   clock step in either direction.
//! * `CLOCK_REALTIME` (and `REALTIME_COARSE`) `= raw_ns + real_offset_ns`,
//!   where `real_offset_ns = CLOCK_REALTIME - CLOCK_MONOTONIC_RAW` on the
//!   host, republished by the backend's refresher every
//!   [`CLOCK_REFRESH_INTERVAL`]. Between refreshes the vDSO's realtime can
//!   lag a host NTP slew or step by at most that interval's worth of
//!   adjustment; the host's own realtime is itself allowed to step, so no
//!   guest contract is weakened by this.
//!
//! Every other clock id (the CPU-time clocks, alarms, TAI, anything
//! unknown) and a NULL `timespec` fall through to the real `svc #0`, exactly
//! like Linux's own aarch64 vDSO, so the shim's answers (`EINVAL`, `EFAULT`,
//! genuine CPU-time accounting) are unchanged for them. `clock_getres`
//! serves the same resolutions the shim reports (4 ms for the coarse
//! clocks, 1 ns otherwise) and falls through likewise.

use core::sync::atomic::{AtomicU64, Ordering};
use core::time::Duration;

/// How often the backend republishes the realtime offset.
pub(crate) const CLOCK_REFRESH_INTERVAL: Duration = Duration::from_millis(100);

/// Clock data page layout, in bytes from the page start. `LITEBOX_VDSO_READ_CLOCK`
/// in the assembly below loads exactly these slots at exactly these offsets.
pub(crate) const CLOCK_NUMER: usize = 0;
pub(crate) const CLOCK_DENOM: usize = 8;
pub(crate) const CLOCK_MONO_EPOCH_NS: usize = 16;
pub(crate) const CLOCK_REAL_OFFSET_NS: usize = 24;

// The `.quad` table at `_litebox_vdso_text_start` records where each function and the end
// of the text lie relative to the table itself, so Rust can copy the code without any of the
// labels being global (a second global symbol would let the Mach-O linker split or reorder
// the atom). Everything after the table is position-independent AArch64: the only address
// it ever forms is its own page (via `adr`) plus one page, which is the clock data page.
core::arch::global_asm!(
    ".text",
    ".balign 16",
    ".globl _litebox_vdso_text_start",
    "_litebox_vdso_text_start:",
    ".quad Llitebox_vdso_clock_gettime - _litebox_vdso_text_start",
    ".quad Llitebox_vdso_gettimeofday - _litebox_vdso_text_start",
    ".quad Llitebox_vdso_clock_getres - _litebox_vdso_text_start",
    ".quad Llitebox_vdso_text_end - _litebox_vdso_text_start",
    // Reads the clock data page and leaves x9 = host CLOCK_MONOTONIC_RAW
    // nanoseconds derived from CNTVCT_EL0, x15 = the CLOCK_MONOTONIC epoch
    // (ns), x16 = the CLOCK_REALTIME offset (ns). Clobbers x10, x12, x13.
    // Plain loads on purpose -- see the module docs for why there is no
    // seqlock to spin on.
    ".macro LITEBOX_VDSO_READ_CLOCK",
    "0:",
    "    adr x10, 0b",
    "    and x10, x10, #0xffffffffffffc000",
    "    add x10, x10, #4, lsl #12",
    "    ldp x12, x13, [x10]",
    "    ldp x15, x16, [x10, #16]",
    "    isb",
    "    mrs x9, cntvct_el0",
    "    mul x9, x9, x12",
    "    udiv x9, x9, x13",
    ".endm",
    // int __kernel_clock_gettime(clockid_t clk, struct timespec *ts)
    ".balign 4",
    "Llitebox_vdso_clock_gettime:",
    "    cbz x1, 9f",
    "    cmp w0, #7",
    "    b.hi 9f",
    "    mov w9, #0xf3",
    "    lsr w9, w9, w0",
    "    tbz w9, #0, 9f",
    "    LITEBOX_VDSO_READ_CLOCK",
    "    sub x11, x9, x15",
    "    add x12, x9, x16",
    "    cmp w0, #0",
    "    ccmp w0, #5, #4, ne",
    "    csel x9, x12, x11, eq",
    "    mov x12, #0xca00",
    "    movk x12, #0x3b9a, lsl #16",
    "    udiv x13, x9, x12",
    "    msub x14, x13, x12, x9",
    "    stp x13, x14, [x1]",
    "    mov w0, #0",
    "    ret",
    "9:",
    "    mov x8, #113",
    "    svc #0",
    "    ret",
    // int __kernel_gettimeofday(struct timeval *tv, struct timezone *tz)
    ".balign 4",
    "Llitebox_vdso_gettimeofday:",
    "    cbz x0, 2f",
    "    LITEBOX_VDSO_READ_CLOCK",
    "    add x9, x9, x16",
    "    mov x12, #0xca00",
    "    movk x12, #0x3b9a, lsl #16",
    "    udiv x13, x9, x12",
    "    msub x14, x13, x12, x9",
    "    mov x12, #1000",
    "    udiv x14, x14, x12",
    "    stp x13, x14, [x0]",
    "2:",
    "    cbz x1, 3f",
    "    str xzr, [x1]",
    "3:",
    "    mov w0, #0",
    "    ret",
    // int __kernel_clock_getres(clockid_t clk, struct timespec *res)
    ".balign 4",
    "Llitebox_vdso_clock_getres:",
    "    cmp w0, #7",
    "    b.hi 9f",
    "    cmp w0, #5",
    "    ccmp w0, #6, #4, ne",
    "    mov x9, #0x0900",
    "    movk x9, #0x3d, lsl #16",
    "    mov x10, #1",
    "    csel x9, x9, x10, eq",
    "    cbz x1, 5f",
    "    stp xzr, x9, [x1]",
    "5:",
    "    mov w0, #0",
    "    ret",
    "9:",
    "    mov x8, #114",
    "    svc #0",
    "    ret",
    "Llitebox_vdso_text_end:",
);

unsafe extern "C" {
    static litebox_vdso_text_start: u8;
}

/// The assembled text and the offset of each exported function within it.
struct Text {
    bytes: &'static [u8],
    clock_gettime: usize,
    gettimeofday: usize,
    clock_getres: usize,
}

fn text() -> Text {
    const TABLE: usize = 4 * 8;
    let start = &raw const litebox_vdso_text_start;
    // SAFETY: the assembly above lays out four `.quad` offsets at the symbol, every one of
    // them within the same contiguous block, followed by the text they describe.
    let table = unsafe { core::ptr::read_unaligned(start.cast::<[u64; 4]>()) };
    let [clock_gettime, gettimeofday, clock_getres, end] =
        table.map(|offset| usize::try_from(offset).expect("vDSO text offset fits usize"));
    Text {
        // SAFETY: `[TABLE, end)` is the assembled text right after the table.
        bytes: unsafe { core::slice::from_raw_parts(start.add(TABLE), end - TABLE) },
        clock_gettime: clock_gettime - TABLE,
        gettimeofday: gettimeofday - TABLE,
        clock_getres: clock_getres - TABLE,
    }
}

/// The System V ELF hash, as `DT_HASH` and `vd_hash` want it.
fn elf_hash(name: &[u8]) -> u32 {
    let mut h: u32 = 0;
    for &byte in name {
        h = (h << 4).wrapping_add(u32::from(byte));
        let g = h & 0xf000_0000;
        if g != 0 {
            h ^= g >> 24;
        }
        h &= !g;
    }
    h
}

fn align_up(value: usize, alignment: usize) -> usize {
    (value + alignment - 1) & !(alignment - 1)
}

fn put(image: &mut [u8], at: usize, bytes: &[u8]) -> Result<(), &'static str> {
    image
        .get_mut(at..at + bytes.len())
        .ok_or("vDSO image does not fit its page")?
        .copy_from_slice(bytes);
    Ok(())
}

fn put_u16(image: &mut [u8], at: usize, value: u16) -> Result<(), &'static str> {
    put(image, at, &value.to_le_bytes())
}

fn put_u32(image: &mut [u8], at: usize, value: u32) -> Result<(), &'static str> {
    put(image, at, &value.to_le_bytes())
}

fn put_u64(image: &mut [u8], at: usize, value: u64) -> Result<(), &'static str> {
    put(image, at, &value.to_le_bytes())
}

fn u64_of(value: usize) -> u64 {
    u64::try_from(value).expect("usize fits u64")
}

/// Appends `name` (NUL-terminated) to a string table and returns its offset.
fn intern(strtab: &mut Vec<u8>, name: &[u8]) -> usize {
    let offset = strtab.len();
    strtab.extend_from_slice(name);
    strtab.push(0);
    offset
}

/// Writes the vDSO ELF image into `image` (one page, already zeroed) and returns its length.
///
/// `page_size` is the alignment the single `PT_LOAD` advertises; the image never exceeds one
/// page. Layout, in file-offset order: ELF header, two program headers, `.hash`, `.dynsym`,
/// `.dynstr`, `.gnu.version`, `.gnu.version_d`, `.dynamic`, text. No section headers: neither
/// libc reads them for the vDSO, and they are not what `dl_iterate_phdr` reports.
pub(crate) fn build_image(image: &mut [u8], page_size: usize) -> Result<usize, &'static str> {
    const EHDR_SIZE: usize = 64;
    const PHDR_SIZE: usize = 56;
    const PHNUM: usize = 2;
    const SYM_SIZE: usize = 24;
    const NSYMS: usize = 4;
    const DYN_SIZE: usize = 16;
    const NDYN: usize = 10;
    const VERDEF_SIZE: usize = 20;
    const VERDAUX_SIZE: usize = 8;
    const VERSION_INDEX: u16 = 2;

    let text = text();

    let mut strtab = vec![0u8];
    let soname = intern(&mut strtab, b"linux-vdso.so.1");
    let version = intern(&mut strtab, b"LINUX_2.6.39");
    let names = [
        (
            intern(&mut strtab, b"__kernel_clock_gettime"),
            text.clock_gettime,
            text.gettimeofday,
        ),
        (
            intern(&mut strtab, b"__kernel_gettimeofday"),
            text.gettimeofday,
            text.clock_getres,
        ),
        (
            intern(&mut strtab, b"__kernel_clock_getres"),
            text.clock_getres,
            text.bytes.len(),
        ),
    ];

    let phdr_off = EHDR_SIZE;
    let hash_off = phdr_off + PHNUM * PHDR_SIZE;
    let hash_len = 4 * (2 + 1 + NSYMS);
    let sym_off = align_up(hash_off + hash_len, 8);
    let str_off = sym_off + NSYMS * SYM_SIZE;
    let versym_off = align_up(str_off + strtab.len(), 2);
    let verdef_off = align_up(versym_off + NSYMS * 2, 4);
    let dyn_off = align_up(verdef_off + 2 * (VERDEF_SIZE + VERDAUX_SIZE), 8);
    let text_off = align_up(dyn_off + NDYN * DYN_SIZE, 16);
    let image_len = text_off + text.bytes.len();
    if image_len > image.len() || image.len() > page_size {
        return Err("vDSO image does not fit its page");
    }

    // ELF header: ELFCLASS64, little-endian, EV_CURRENT, ELFOSABI_SYSV; ET_DYN for EM_AARCH64.
    put(image, 0, &[0x7f, b'E', b'L', b'F', 2, 1, 1, 0])?;
    put_u16(image, 16, 3)?;
    put_u16(image, 18, 183)?;
    put_u32(image, 20, 1)?;
    put_u64(image, 32, u64_of(phdr_off))?;
    put_u16(image, 52, 64)?;
    put_u16(image, 54, 56)?;
    put_u16(image, 56, 2)?;
    put_u16(image, 58, 64)?;

    // PT_LOAD (R+X) over the whole image at vaddr 0, then PT_DYNAMIC (R).
    let load = phdr_off;
    put_u32(image, load, 1)?;
    put_u32(image, load + 4, 5)?;
    put_u64(image, load + 32, u64_of(image_len))?;
    put_u64(image, load + 40, u64_of(image_len))?;
    put_u64(image, load + 48, u64_of(page_size))?;
    let dynamic = phdr_off + PHDR_SIZE;
    put_u32(image, dynamic, 2)?;
    put_u32(image, dynamic + 4, 4)?;
    put_u64(image, dynamic + 8, u64_of(dyn_off))?;
    put_u64(image, dynamic + 16, u64_of(dyn_off))?;
    put_u64(image, dynamic + 24, u64_of(dyn_off))?;
    put_u64(image, dynamic + 32, u64_of(NDYN * DYN_SIZE))?;
    put_u64(image, dynamic + 40, u64_of(NDYN * DYN_SIZE))?;
    put_u64(image, dynamic + 48, 8)?;

    // .hash: one bucket chaining every symbol (3 -> 2 -> 1 -> 0), so any name is found.
    for (index, word) in [1u32, 4, 3, 0, 0, 1, 2].iter().enumerate() {
        put_u32(image, hash_off + index * 4, *word)?;
    }

    // .dynsym: the null symbol, then one STB_GLOBAL/STT_FUNC per exported function, in a
    // non-zero (fake) section so neither libc takes it for undefined or absolute.
    for (index, (name, start, end)) in names.iter().enumerate() {
        let sym = sym_off + (index + 1) * SYM_SIZE;
        put_u32(
            image,
            sym,
            u32::try_from(*name).expect("dynstr offset fits u32"),
        )?;
        put(image, sym + 4, &[0x12, 0, 1, 0])?;
        put_u64(image, sym + 8, u64_of(text_off + start))?;
        put_u64(image, sym + 16, u64_of(end - start))?;
    }

    put(image, str_off, &strtab)?;

    // .gnu.version: every exported symbol carries version index 2 (`LINUX_2.6.39`).
    for index in 1..NSYMS {
        put_u16(image, versym_off + index * 2, VERSION_INDEX)?;
    }

    // .gnu.version_d: the VER_FLG_BASE entry naming the soname, then `LINUX_2.6.39`.
    for (index, (flags, ndx, name, next)) in [
        (1u16, 1u16, soname, VERDEF_SIZE + VERDAUX_SIZE),
        (0, VERSION_INDEX, version, 0),
    ]
    .iter()
    .enumerate()
    {
        let def = verdef_off + index * (VERDEF_SIZE + VERDAUX_SIZE);
        put_u16(image, def, 1)?;
        put_u16(image, def + 2, *flags)?;
        put_u16(image, def + 4, *ndx)?;
        put_u16(image, def + 6, 1)?;
        let tail = &strtab[*name..];
        let label = &tail[..tail.iter().position(|&b| b == 0).unwrap_or(tail.len())];
        put_u32(image, def + 8, elf_hash(label))?;
        put_u32(image, def + 12, u32::try_from(VERDEF_SIZE).expect("fits"))?;
        put_u32(image, def + 16, u32::try_from(*next).expect("fits"))?;
        put_u32(
            image,
            def + VERDEF_SIZE,
            u32::try_from(*name).expect("dynstr offset fits u32"),
        )?;
    }

    // .dynamic.
    for (index, (tag, value)) in [
        (4u64, hash_off),
        (5, str_off),
        (6, sym_off),
        (10, strtab.len()),
        (11, SYM_SIZE),
        (14, soname),
        (0x6fff_fff0, versym_off),
        (0x6fff_fffc, verdef_off),
        (0x6fff_fffd, 2),
        (0, 0),
    ]
    .iter()
    .enumerate()
    {
        let entry = dyn_off + index * DYN_SIZE;
        put_u64(image, entry, *tag)?;
        put_u64(image, entry + 8, u64_of(*value))?;
    }

    put(image, text_off, text.bytes)?;
    Ok(image_len)
}

/// The values the clock data page carries; see the module docs for what each means.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ClockValues {
    pub(crate) numer: u64,
    pub(crate) denom: u64,
    pub(crate) mono_epoch_ns: u64,
    pub(crate) real_offset_ns: u64,
}

/// `<mach/mach_time.h>`'s `mach_timebase_info_data_t`; declared here because the `libc`
/// crate's own binding is deprecated in favor of a crate this platform does not depend on.
#[repr(C)]
struct MachTimebaseInfo {
    numer: u32,
    denom: u32,
}

unsafe extern "C" {
    fn mach_timebase_info(info: *mut MachTimebaseInfo) -> libc::c_int;
}

/// `mach_timebase_info` as the `(numer, denom)` the host's own `CLOCK_MONOTONIC_RAW` scales
/// `mach_absolute_time()` by.
pub(crate) fn host_timebase() -> Result<(u64, u64), &'static str> {
    let mut info = MachTimebaseInfo { numer: 0, denom: 0 };
    // SAFETY: `info` is a live, correctly typed out-parameter.
    let rc = unsafe { mach_timebase_info(&raw mut info) };
    if rc != 0 || info.numer == 0 || info.denom == 0 {
        return Err("mach_timebase_info failed");
    }
    Ok((u64::from(info.numer), u64::from(info.denom)))
}

/// `CLOCK_REALTIME - CLOCK_MONOTONIC_RAW` on the host right now, with the realtime read
/// bracketed by two raw reads so the offset is anchored at the midpoint of the read gap.
pub(crate) fn host_real_offset_ns() -> u64 {
    let before = crate::darwin::clock_gettime_nanos(libc::CLOCK_MONOTONIC_RAW);
    let real = crate::darwin::clock_gettime_nanos(libc::CLOCK_REALTIME);
    let after = crate::darwin::clock_gettime_nanos(libc::CLOCK_MONOTONIC_RAW);
    real.wrapping_sub(before + (after.saturating_sub(before)) / 2)
}

/// Publishes `values` into the clock data page at `page`: every word is one aligned 64-bit
/// store a concurrent guest reader observes either wholly before or wholly after, and
/// `real_offset_ns` -- the only word that ever changes once guests run -- is stored last.
///
/// # Safety
///
/// `page` must be the host-writable, 8-byte-aligned address of the whole clock data page,
/// and no other writer may run concurrently (the backend serializes writers behind one
/// mutex).
pub(crate) unsafe fn publish_clock(page: *mut u64, values: ClockValues) {
    // SAFETY: the caller promises `page` covers every slot; every offset is a multiple of 8.
    let slot = |offset: usize| unsafe { AtomicU64::from_ptr(page.add(offset / 8)) };
    slot(CLOCK_NUMER).store(values.numer, Ordering::SeqCst);
    slot(CLOCK_DENOM).store(values.denom, Ordering::SeqCst);
    slot(CLOCK_MONO_EPOCH_NS).store(values.mono_epoch_ns, Ordering::SeqCst);
    slot(CLOCK_REAL_OFFSET_NS).store(values.real_offset_ns, Ordering::SeqCst);
}
