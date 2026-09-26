// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! cf-02-seccomp-production-attester: the guest-side half of the seccomp production diagnostic.
//!
//! `no_std`/`no_main`/crt-free static-PIE per `litebox-guest-test-binary-recipe`: raw `svc #0`
//! syscalls only, no musl/libc startup. Run under a real `litebox_runner_linux_on_macos_userland
//! --hvf` boot (the only backend `MacOsUserland::seccomp_mediation_capability` reports as
//! `Complete`, per `litebox_platform_macos_userland/src/lib.rs`), this exercises the REAL
//! `litebox_shim_linux` pipeline end to end: `sys_seccomp`
//! (`litebox_shim_linux/src/syscalls/process.rs`) installing classic-BPF programs verified by
//! `syscalls::seccomp_bpf::verify_program`, `Task::seccomp_check_entry` mediating every raw
//! syscall entry before any side effect, `syscalls::seccomp_bpf::run_program` interpreting the
//! installed chain, and `Task::force_seccomp_sigsys`/`dispatch_seccomp_action` delivering the
//! exact AArch64 TRAP/KILL_THREAD/KILL_PROCESS dispositions. Nothing here calls into litebox's
//! own Rust code directly -- every check is a real Linux syscall dispatched exactly the way a
//! genuine sandboxed guest binary (Chromium's own zygote/renderer included) would make it.
//!
//! Companion binary: `exec_child.rs` (the execve target for the exec-inheritance probe). Host
//! orchestrator: `litebox_platform_macos_userland/src/bin/seccomp_production_attester.rs`, which
//! builds both through `build.sh`, packages a minimal ustar tar, and launches the real signed HVF
//! runner against it.
//!
//! Output protocol (read by the host orchestrator): one `PROBE <name> <PASS|FAIL> <detail>\n`
//! line per check, and a final `SUMMARY total=<n> pass=<n> fail=<n>\n` line. All written via a
//! single `write(1, ...)` syscall per line (message bodies stay well under `PIPE_BUF`, so
//! concurrent writers -- the probe threads this file itself spawns -- never interleave mid-line).
//!
//! Deliberately avoids `core::fmt`/`write!`/`format_args!` entirely (live-confirmed fatal: a bare
//! static-PIE binary with no dynamic loader never runs the `R_AARCH64_RELATIVE` self-relocation
//! pass a real crt startup would, so the function-pointer table `core::fmt::Arguments` bakes into
//! read-only data resolves to link-time, not load-time, addresses -- a call through one jumped to
//! PC 0 the first time this was tried live). Every reported value is composed by hand from plain,
//! directly-called (never vtable-dispatched) integer/hex/string pushes instead -- matching
//! `litebox-guest-test-binary-recipe`'s own hard-won "format ints by hand" rule exactly.

#![no_std]
#![no_main]

use core::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, Ordering};

// ---------------------------------------------------------------------------
// Raw AArch64 Linux syscall numbers actually used here (asm-generic/unistd.h, unchanged since
// the arm64 syscall ABI was frozen -- the same numbers `litebox_shim_linux` itself dispatches on).
// ---------------------------------------------------------------------------
const NR_READ: i64 = 63;
const NR_WRITE: i64 = 64;
const NR_CLOSE: i64 = 57;
const NR_OPENAT: i64 = 56;
const NR_NANOSLEEP: i64 = 101;
const NR_RT_SIGACTION: i64 = 134;
const NR_GETPID: i64 = 172;
const NR_GETTID: i64 = 178;
const NR_EXIT: i64 = 93;
const NR_EXIT_GROUP: i64 = 94;
const NR_CLONE: i64 = 220;
const NR_EXECVE: i64 = 221;
const NR_WAIT4: i64 = 260;
const NR_PRCTL: i64 = 167;
const NR_SECCOMP: i64 = 277;

const AT_FDCWD: i64 = -100;
const O_RDONLY: i64 = 0;

const PR_SET_NO_NEW_PRIVS: i64 = 38;
const PR_GET_NO_NEW_PRIVS: i64 = 39;

const SECCOMP_SET_MODE_STRICT: i64 = 0;
const SECCOMP_SET_MODE_FILTER: i64 = 1;
const SECCOMP_GET_ACTION_AVAIL: i64 = 2;
const SECCOMP_GET_NOTIF_SIZES: i64 = 3;
const SECCOMP_FILTER_FLAG_TSYNC: i64 = 1;

const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
const SECCOMP_RET_KILL_THREAD: u32 = 0x0000_0000;
const SECCOMP_RET_TRAP: u32 = 0x0003_0000;
const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;

const TRAP_DATA: u32 = 0x1234;
const SYS_SECCOMP_CODE: i32 = 1;
const AUDIT_ARCH_AARCH64: u32 = 0xc000_00b7;

const SIGSYS: i64 = 31;
const SA_SIGINFO: u32 = 4;
const SA_RESTORER: u32 = 0x0400_0000;

const CLONE_VM: i64 = 0x0000_0100;
const CLONE_FS: i64 = 0x0000_0200;
const CLONE_FILES: i64 = 0x0000_0400;
const CLONE_SIGHAND: i64 = 0x0000_0800;
const CLONE_THREAD: i64 = 0x0001_0000;
const CLONE_SYSVSEM: i64 = 0x0004_0000;
const CLONE_VFORK: i64 = 0x0000_4000;
const SIGCHLD: i64 = 17;
const THREAD_FLAGS: i64 =
    CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD | CLONE_SYSVSEM;
const VFORK_FLAGS: i64 = CLONE_VFORK | CLONE_VM | SIGCHLD;

const EPERM: i64 = -1;
const EBADF: i64 = -9;
const EACCES: i64 = -13;
const EFAULT: i64 = -14;
const EINVAL: i64 = -22;
const ENOSYS: i64 = -38;
const EOPNOTSUPP: i64 = -95;

// ---------------------------------------------------------------------------
// Raw syscall plumbing.
// ---------------------------------------------------------------------------

#[inline(always)]
unsafe fn syscall6(nr: i64, a0: i64, a1: i64, a2: i64, a3: i64, a4: i64, a5: i64) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") nr,
            inlateout("x0") a0 => ret,
            in("x1") a1,
            in("x2") a2,
            in("x3") a3,
            in("x4") a4,
            in("x5") a5,
            options(nostack)
        );
    }
    ret
}

fn sleep_ms(ms: i64) {
    let ts = [0i64, ms.saturating_mul(1_000_000)];
    unsafe {
        syscall6(NR_NANOSLEEP, ts.as_ptr() as i64, 0, 0, 0, 0, 0);
    }
}

fn sleep_short() {
    sleep_ms(2);
}

fn sys_exit_group(code: i64) -> ! {
    unsafe {
        syscall6(NR_EXIT_GROUP, code, 0, 0, 0, 0, 0);
    }
    loop {
        unsafe { core::arch::asm!("yield", options(nomem, nostack)) };
    }
}

/// The kernel/shim writes `status` through a bare address erased to `i64` before reaching
/// `syscall6` -- the compiler's alias analysis has no way to see that integer secretly aliases
/// this stack slot, so an ordinary read straight back out of `status` here is free to be
/// constant-folded (live-confirmed elsewhere in this file: `GET_NOTIF_SIZES`'s own output buffer,
/// read back the same naive way, came back all-zero despite the syscall itself succeeding). A
/// volatile read forces a genuine reload instead of trusting the pre-syscall value.
fn sys_wait4(pid: i64) -> (i64, i32) {
    let mut status: i32 = 0;
    let ret = unsafe {
        syscall6(
            NR_WAIT4,
            pid,
            core::ptr::addr_of_mut!(status) as i64,
            0,
            0,
            0,
            0,
        )
    };
    let status = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(status)) };
    (ret, status)
}

// ---------------------------------------------------------------------------
// Allocation-free, `core::fmt`-free output: every push is a direct, statically-resolved call
// (never a vtable/function-pointer-table lookup), flushed with one `write(1, ...)` syscall per
// report line. See this file's own top doc comment for why `core::fmt` cannot be used here.
// ---------------------------------------------------------------------------

struct OutBuf {
    data: [u8; 320],
    len: usize,
}

impl OutBuf {
    const fn new() -> Self {
        Self {
            data: [0; 320],
            len: 0,
        }
    }

    fn push_byte(&mut self, byte: u8) {
        if self.len < self.data.len() {
            self.data[self.len] = byte;
            self.len += 1;
        }
    }

    fn push_bytes(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            self.push_byte(byte);
        }
    }

    fn s(&mut self, text: &str) -> &mut Self {
        self.push_bytes(text.as_bytes());
        self
    }

    fn u(&mut self, value: u64) -> &mut Self {
        let mut digits = [0u8; 20];
        let mut n = 0;
        let mut x = value;
        if x == 0 {
            digits[0] = b'0';
            n = 1;
        } else {
            while x > 0 {
                digits[n] = b'0' + (x % 10) as u8;
                x /= 10;
                n += 1;
            }
        }
        for i in (0..n).rev() {
            self.push_byte(digits[i]);
        }
        self
    }

    fn i(&mut self, value: i64) -> &mut Self {
        if value < 0 {
            self.push_byte(b'-');
        }
        self.u(value.unsigned_abs())
    }

    fn h(&mut self, value: u64) -> &mut Self {
        self.s("0x");
        let mut digits = [0u8; 16];
        let mut n = 0;
        let mut x = value;
        if x == 0 {
            digits[0] = b'0';
            n = 1;
        } else {
            while x > 0 {
                let d = (x & 0xf) as u8;
                digits[n] = if d < 10 { b'0' + d } else { b'a' + (d - 10) };
                x >>= 4;
                n += 1;
            }
        }
        for i in (0..n).rev() {
            self.push_byte(digits[i]);
        }
        self
    }

    fn b(&mut self, value: bool) -> &mut Self {
        self.s(if value { "true" } else { "false" })
    }

    fn flush(&mut self) {
        if self.len > 0 {
            unsafe {
                syscall6(
                    NR_WRITE,
                    1,
                    self.data.as_ptr() as i64,
                    self.len as i64,
                    0,
                    0,
                    0,
                );
            }
            self.len = 0;
        }
    }

    fn finish(&mut self) {
        self.push_byte(b'\n');
        self.flush();
    }
}

static PASS: AtomicU32 = AtomicU32::new(0);
static FAIL: AtomicU32 = AtomicU32::new(0);

/// Plain load+store, not `fetch_add`: this file's whole `report` call sequence is already
/// serialized by the stage/done rendezvous around every thread spawn (see `wait_stage`), so no two
/// threads ever race a counter update -- and a plain load+store avoids pulling in the outlined-LSE
/// atomic runtime helper (`__aarch64_ldadd4_relax`) this freestanding binary links against no libc
/// or compiler-rt to provide.
fn record_result(pass: bool) {
    let counter = if pass { &PASS } else { &FAIL };
    counter.store(counter.load(Ordering::Relaxed) + 1, Ordering::Relaxed);
}

/// Starts one `PROBE <name> <PASS|FAIL> ` line; the caller appends whatever detail fields matter
/// via `OutBuf`'s own chained `s`/`i`/`u`/`h`/`b` pushes, then must call `.finish()` to terminate
/// and flush the line exactly once.
fn begin_report(name: &str, pass: bool) -> OutBuf {
    let mut buf = OutBuf::new();
    buf.s("PROBE ").s(name).s(if pass { " PASS " } else { " FAIL " });
    record_result(pass);
    buf
}

/// Writes `bytes` into `buf` starting at `offset`, one `write_volatile` byte at a time. A syscall
/// reads bytes like these through an address erased to a plain `i64` (see `sys_wait4`'s own doc
/// comment for the read-side mirror of this same hazard) -- from the optimizer's point of view
/// nothing "observably" reads an ordinary `copy_from_slice` into a buffer no real Rust code reads
/// again, so it is free to treat those writes as dead and drop them. Live-confirmed: exactly this
/// pattern, for `install_sigsys_handler`'s `sa_restorer` field, left the syscall reading a
/// zeroed restorer address; litebox correctly used that as the real restorer (`SaFlags::RESTORER`
/// was set), so the handler's own `ret` landed on a null `x30` the instant it returned.
/// `write_volatile` forces every byte to actually land before the syscall that reads it.
fn vwrite(buf: &mut [u8], offset: usize, bytes: &[u8]) {
    for (i, &b) in bytes.iter().enumerate() {
        unsafe { core::ptr::write_volatile(buf.as_mut_ptr().add(offset + i), b) };
    }
}

// ---------------------------------------------------------------------------
// Classic-BPF program encoding, matching `litebox_shim_linux::syscalls::seccomp_bpf`'s own
// whitelisted opcode bytes (`is_allowed_opcode`) exactly -- this is real classic BPF, not a
// litebox-specific dialect.
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
struct SockFilter {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

const BPF_LD_W_ABS: u16 = 0x20;
const BPF_JEQ_K: u16 = 0x15;
const BPF_RET_K: u16 = 0x06;

/// `out`'s bytes are read back only via a syscall, through a pointer this whole file otherwise
/// treats as opaque to the optimizer (see `vwrite`'s own doc comment for the general hazard this
/// avoids): `write_volatile` throughout, not `copy_from_slice`, even though `out` arrives as a
/// genuine `&mut [u8]` here -- if this call ever gets inlined into a caller whose own only later
/// use of the buffer is an address fed to a further syscall, the same dead-store elimination risk
/// applies transitively.
fn encode(prog: &[SockFilter], out: &mut [u8]) -> usize {
    let mut n = 0;
    for insn in prog {
        vwrite(out, n, &insn.code.to_ne_bytes());
        vwrite(out, n + 2, &[insn.jt]);
        vwrite(out, n + 3, &[insn.jf]);
        vwrite(out, n + 4, &insn.k.to_ne_bytes());
        n += 8;
    }
    n
}

/// `seccomp_data.nr == nr` selects `action`, anything else `ALLOW`.
fn nr_action_filter(nr: u32, action: u32) -> [SockFilter; 4] {
    [
        SockFilter {
            code: BPF_LD_W_ABS,
            jt: 0,
            jf: 0,
            k: 0,
        },
        SockFilter {
            code: BPF_JEQ_K,
            jt: 0,
            jf: 1,
            k: nr,
        },
        SockFilter {
            code: BPF_RET_K,
            jt: 0,
            jf: 0,
            k: action,
        },
        SockFilter {
            code: BPF_RET_K,
            jt: 0,
            jf: 0,
            k: SECCOMP_RET_ALLOW,
        },
    ]
}

const ALLOW_ALL: [SockFilter; 1] = [SockFilter {
    code: BPF_RET_K,
    jt: 0,
    jf: 0,
    k: SECCOMP_RET_ALLOW,
}];

/// `seccomp(SECCOMP_SET_MODE_FILTER)`: builds the 16-byte `sock_fprog` header pointing at the
/// encoded program and issues the real syscall. Returns the raw syscall return value.
fn install_filter(flags: i64, prog: &[SockFilter]) -> i64 {
    let mut prog_bytes = [0u8; 64];
    let len = encode(prog, &mut prog_bytes);
    let mut fprog = [0u8; 16];
    vwrite(&mut fprog, 0, &(prog.len() as u16).to_ne_bytes());
    let filter_addr = prog_bytes.as_ptr() as u64;
    vwrite(&mut fprog, 8, &filter_addr.to_ne_bytes());
    let _ = len;
    unsafe {
        syscall6(
            NR_SECCOMP,
            SECCOMP_SET_MODE_FILTER,
            flags,
            fprog.as_ptr() as i64,
            0,
            0,
            0,
        )
    }
}

fn allow_all_prog_bytes() -> [u8; 8] {
    let mut buf = [0u8; 8];
    encode(&ALLOW_ALL, &mut buf);
    buf
}

// ---------------------------------------------------------------------------
// Phase 0/1: null/flag probes (run before any filter exists) and NNP gating.
// ---------------------------------------------------------------------------

fn probe_flags_and_nulls() {
    let r = unsafe { syscall6(NR_SECCOMP, SECCOMP_SET_MODE_FILTER, 0, 0, 0, 0, 0) };
    begin_report("null_args_set_mode_filter_efault", r == EFAULT)
        .s("ret=")
        .i(r)
        .finish();

    let bad_flag: i64 = 0x2000; // outside SECCOMP_ACCEPTED_FLAGS
    let r = unsafe { syscall6(NR_SECCOMP, SECCOMP_SET_MODE_FILTER, bad_flag, 0, 0, 0, 0) };
    begin_report("bad_flag_bit_einval", r == EINVAL)
        .s("ret=")
        .i(r)
        .finish();

    let r = unsafe { syscall6(NR_SECCOMP, 42, 0, 0, 0, 0, 0) };
    begin_report("unknown_seccomp_op_einval", r == EINVAL)
        .s("ret=")
        .i(r)
        .finish();

    let mut avail = [0u8; 4];
    vwrite(&mut avail, 0, &SECCOMP_RET_ALLOW.to_ne_bytes());
    let r = unsafe {
        syscall6(
            NR_SECCOMP,
            SECCOMP_GET_ACTION_AVAIL,
            1,
            avail.as_ptr() as i64,
            0,
            0,
            0,
        )
    };
    begin_report("get_action_avail_bad_flags_einval", r == EINVAL)
        .s("ret=")
        .i(r)
        .finish();

    let r = unsafe {
        syscall6(
            NR_SECCOMP,
            SECCOMP_GET_ACTION_AVAIL,
            0,
            avail.as_ptr() as i64,
            0,
            0,
            0,
        )
    };
    begin_report("get_action_avail_allow_ok", r == 0)
        .s("ret=")
        .i(r)
        .finish();

    let mut unknown = [0u8; 4];
    vwrite(&mut unknown, 0, &0xdead_beefu32.to_ne_bytes());
    let r = unsafe {
        syscall6(
            NR_SECCOMP,
            SECCOMP_GET_ACTION_AVAIL,
            0,
            unknown.as_ptr() as i64,
            0,
            0,
            0,
        )
    };
    begin_report("get_action_avail_unknown_eopnotsupp", r == EOPNOTSUPP)
        .s("ret=")
        .i(r)
        .finish();

    let sizes = [0u8; 6];
    let r = unsafe {
        syscall6(
            NR_SECCOMP,
            SECCOMP_GET_NOTIF_SIZES,
            0,
            sizes.as_ptr() as i64,
            0,
            0,
            0,
        )
    };
    // See `sys_wait4`'s own doc comment: the syscall writes through an address erased to `i64`,
    // so reading `sizes` back out must be volatile or the compiler is free to trust the
    // pre-syscall (all-zero) initializer instead of the bytes the shim actually wrote.
    let sizes = {
        let mut out = [0u8; 6];
        for (i, slot) in out.iter_mut().enumerate() {
            *slot = unsafe { core::ptr::read_volatile(sizes.as_ptr().add(i)) };
        }
        out
    };
    let s0 = u16::from_ne_bytes([sizes[0], sizes[1]]);
    let s1 = u16::from_ne_bytes([sizes[2], sizes[3]]);
    let s2 = u16::from_ne_bytes([sizes[4], sizes[5]]);
    begin_report(
        "get_notif_sizes_ok",
        r == 0 && s0 == 80 && s1 == 24 && s2 == 64,
    )
    .s("ret=")
    .i(r)
    .s(" sizes=(")
    .u(u64::from(s0))
    .s(",")
    .u(u64::from(s1))
    .s(",")
    .u(u64::from(s2))
    .s(")")
    .finish();

    let r = unsafe { syscall6(NR_SECCOMP, SECCOMP_SET_MODE_STRICT, 0, 0, 0, 0, 0) };
    begin_report("set_mode_strict_valid_shape_enosys", r == ENOSYS)
        .s("ret=")
        .i(r)
        .finish();

    let r = unsafe { syscall6(NR_SECCOMP, SECCOMP_SET_MODE_STRICT, 1, 0, 0, 0, 0) };
    begin_report("set_mode_strict_bad_shape_einval", r == EINVAL)
        .s("ret=")
        .i(r)
        .finish();

    // A syntactically valid fprog header (nonzero len, pointer at real readable memory) so this
    // reaches the NNP gate rather than failing earlier on shape alone.
    let allow = allow_all_prog_bytes();
    let mut fprog = [0u8; 16];
    vwrite(&mut fprog, 0, &1u16.to_ne_bytes());
    vwrite(&mut fprog, 8, &(allow.as_ptr() as u64).to_ne_bytes());
    let r = unsafe {
        syscall6(
            NR_SECCOMP,
            SECCOMP_SET_MODE_FILTER,
            0,
            fprog.as_ptr() as i64,
            0,
            0,
            0,
        )
    };
    begin_report("install_before_nnp_eacces", r == EACCES)
        .s("ret=")
        .i(r)
        .finish();
}

// ---------------------------------------------------------------------------
// Phase 2: policy-before-side-effect denial + filter stacking (a newer, weaker filter can never
// loosen what an older, stricter one already decided).
// ---------------------------------------------------------------------------

fn probe_policy_before_side_effect() {
    let path = b"/proc/self/status\0";
    let fd = unsafe {
        syscall6(
            NR_OPENAT,
            AT_FDCWD,
            path.as_ptr() as i64,
            O_RDONLY,
            0,
            0,
            0,
        )
    };
    if fd < 0 {
        begin_report("baseline_openat_sane", false)
            .s("openat ret=")
            .i(fd)
            .finish();
        return;
    }
    unsafe {
        syscall6(NR_CLOSE, fd, 0, 0, 0, 0, 0);
    }
    begin_report("baseline_openat_sane", true).s("fd=").i(fd).finish();

    let deny_openat = nr_action_filter(NR_OPENAT as u32, SECCOMP_RET_ERRNO | 1);
    let r = install_filter(0, &deny_openat);
    begin_report("install_deny_openat_filter", r == 0)
        .s("ret=")
        .i(r)
        .finish();

    let denied = unsafe {
        syscall6(
            NR_OPENAT,
            AT_FDCWD,
            path.as_ptr() as i64,
            O_RDONLY,
            0,
            0,
            0,
        )
    };
    begin_report("policy_before_side_effect_openat_denied", denied == EPERM)
        .s("ret=")
        .i(denied)
        .finish();

    // The fd number a successful open would have reused (lowest-free-fd) must still be unopened:
    // the syscall's real body -- allocating a file description -- never ran.
    let mut scratch = [0u8; 1];
    let probe_read = unsafe { syscall6(NR_READ, fd, scratch.as_mut_ptr() as i64, 1, 0, 0, 0) };
    begin_report(
        "policy_before_side_effect_no_fd_leaked",
        probe_read == EBADF,
    )
    .s("read_ret=")
    .i(probe_read)
    .s(" fd=")
    .i(fd)
    .finish();

    let r = install_filter(0, &ALLOW_ALL);
    if r == 0 {
        let still_denied = unsafe {
            syscall6(
                NR_OPENAT,
                AT_FDCWD,
                path.as_ptr() as i64,
                O_RDONLY,
                0,
                0,
                0,
            )
        };
        begin_report(
            "filter_stacking_stricter_older_wins",
            still_denied == EPERM,
        )
        .s("ret=")
        .i(still_denied)
        .finish();
    } else {
        begin_report("filter_stacking_stricter_older_wins", false)
            .s("stack install ret=")
            .i(r)
            .finish();
    }
}

// ---------------------------------------------------------------------------
// Thread spawning. A pthread-style `CLONE_VM` thread must not fall through into ordinary
// Rust-generated code after `clone()` returns in the child: the kernel switches SP to the fresh
// child stack the instant the child resumes, so any Rust local living on the OLD stack becomes
// unreachable garbage. This drives the whole clone+dispatch from one inline-asm block: the entry
// function's address is kept in a register (registers, unlike stack slots, survive the switch
// intact) and branched to directly, before any compiler-generated stack-relative code can run.
// ---------------------------------------------------------------------------

fn spawn_thread(entry: extern "C" fn() -> !, stack_top: u64) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            "cbnz x0, 2f",
            "blr {entry}",
            "brk #1",
            "2:",
            entry = in(reg) entry as *const () as u64,
            inlateout("x0") THREAD_FLAGS => ret,
            in("x1") stack_top as i64,
            in("x2") 0i64,
            in("x3") 0i64,
            in("x4") 0i64,
            in("x8") NR_CLONE,
            options(nostack)
        );
    }
    ret
}

fn wait_flag(flag: &AtomicBool, want: bool) {
    for _ in 0..2000 {
        if flag.load(Ordering::SeqCst) == want {
            return;
        }
        sleep_short();
    }
}

fn wait_stage(stage: &AtomicU32, want: u32) {
    for _ in 0..2000 {
        if stage.load(Ordering::SeqCst) >= want {
            return;
        }
        sleep_short();
    }
}

// ---- T2: shares the main thread's own lineage throughout; proves pre-install inheritance,
// TSYNC success propagation, post-install-without-TSYNC non-propagation, and rollback isolation.

static T2_STAGE: AtomicU32 = AtomicU32::new(0);
static T2_DONE: AtomicU32 = AtomicU32::new(0);
static mut T2_STACK: [u8; 65536] = [0; 65536];

fn t2_stack_top() -> u64 {
    let base = core::ptr::addr_of!(T2_STACK) as u64;
    (base + 65536) & !0xF
}

extern "C" fn thread_entry_t2() -> ! {
    wait_stage(&T2_STAGE, 1);
    let path = b"/proc/self/status\0";
    let r = unsafe {
        syscall6(
            NR_OPENAT,
            AT_FDCWD,
            path.as_ptr() as i64,
            O_RDONLY,
            0,
            0,
            0,
        )
    };
    begin_report("thread_preinstall_inherits_chain", r == EPERM)
        .s("t2 openat ret=")
        .i(r)
        .finish();
    T2_DONE.store(1, Ordering::SeqCst);

    wait_stage(&T2_STAGE, 2);
    let r = unsafe { syscall6(NR_GETPID, 0, 0, 0, 0, 0, 0) };
    begin_report("tsync_success_propagates_to_sibling", r == EPERM)
        .s("t2 getpid ret=")
        .i(r)
        .finish();
    T2_DONE.store(2, Ordering::SeqCst);

    wait_stage(&T2_STAGE, 3);
    let ts = [0i64, 0i64];
    let r = unsafe { syscall6(NR_NANOSLEEP, ts.as_ptr() as i64, 0, 0, 0, 0, 0) };
    begin_report("post_install_without_tsync_does_not_propagate", r == 0)
        .s("t2 nanosleep ret=")
        .i(r)
        .finish();
    T2_DONE.store(3, Ordering::SeqCst);

    wait_stage(&T2_STAGE, 4);
    let r = unsafe { syscall6(NR_GETTID, 0, 0, 0, 0, 0, 0) };
    begin_report("tsync_incompatible_rollback_sibling_unaffected", r > 0)
        .s("t2 gettid ret=")
        .i(r)
        .finish();
    T2_DONE.store(4, Ordering::SeqCst);

    wait_stage(&T2_STAGE, 5);
    unsafe {
        syscall6(NR_EXIT, 0, 0, 0, 0, 0, 0);
    }
    loop {
        unsafe { core::arch::asm!("yield", options(nomem, nostack)) };
    }
}

// ---- T3: deliberately diverges from main's lineage (its own independent filter), making it the
// TSYNC-incompatible sibling.

static T3_STAGE: AtomicU32 = AtomicU32::new(0);
static T3_DONE: AtomicU32 = AtomicU32::new(0);
static mut T3_STACK: [u8; 65536] = [0; 65536];

fn t3_stack_top() -> u64 {
    let base = core::ptr::addr_of!(T3_STACK) as u64;
    (base + 65536) & !0xF
}

extern "C" fn thread_entry_t3() -> ! {
    wait_stage(&T3_STAGE, 1);
    // nr=999 never actually gets called by anything in this suite: this filter's only job is to
    // give T3 a chain node main's own lineage doesn't share, making T3 TSYNC-ineligible.
    let divergent = nr_action_filter(999, SECCOMP_RET_ERRNO | 1);
    let r = install_filter(0, &divergent);
    begin_report("thread_installs_independent_filter", r == 0)
        .s("t3 install ret=")
        .i(r)
        .finish();
    T3_DONE.store(1, Ordering::SeqCst);

    wait_stage(&T3_STAGE, 2);
    unsafe {
        syscall6(NR_EXIT, 0, 0, 0, 0, 0, 0);
    }
    loop {
        unsafe { core::arch::asm!("yield", options(nomem, nostack)) };
    }
}

// ---- T4: KILL_THREAD victim. Installed and triggered entirely on T4 itself (never TSYNC'd), so
// only T4 dies; main and every other sibling must be unaffected.

static T4_STARTED: AtomicBool = AtomicBool::new(false);
static T4_PROCEED: AtomicBool = AtomicBool::new(false);
static T4_ALIVE: AtomicBool = AtomicBool::new(false);
static mut T4_STACK: [u8; 65536] = [0; 65536];

fn t4_stack_top() -> u64 {
    let base = core::ptr::addr_of!(T4_STACK) as u64;
    (base + 65536) & !0xF
}

extern "C" fn thread_entry_t4() -> ! {
    T4_STARTED.store(true, Ordering::SeqCst);
    wait_flag(&T4_PROCEED, true);
    let kill_thread = nr_action_filter(NR_NANOSLEEP as u32, SECCOMP_RET_KILL_THREAD);
    install_filter(0, &kill_thread);
    let ts = [0i64, 0i64];
    unsafe {
        syscall6(NR_NANOSLEEP, ts.as_ptr() as i64, 0, 0, 0, 0, 0);
    }
    // Reached only if KILL_THREAD did NOT terminate this thread.
    T4_ALIVE.store(true, Ordering::SeqCst);
    unsafe {
        syscall6(NR_EXIT, 0, 0, 0, 0, 0, 0);
    }
    loop {
        unsafe { core::arch::asm!("yield", options(nomem, nostack)) };
    }
}

fn probe_kill_thread() {
    let t4_tid = spawn_thread(thread_entry_t4, t4_stack_top());
    if t4_tid <= 0 {
        begin_report("kill_thread_silently_ends_only_that_thread", false)
            .s("spawn failed ret=")
            .i(t4_tid)
            .finish();
        return;
    }
    wait_flag(&T4_STARTED, true);
    T4_PROCEED.store(true, Ordering::SeqCst);
    let mut still_alive = false;
    for _ in 0..40 {
        sleep_ms(50);
        if T4_ALIVE.load(Ordering::SeqCst) {
            still_alive = true;
            break;
        }
    }
    begin_report(
        "kill_thread_silently_ends_only_that_thread",
        !still_alive,
    )
    .s("still_alive=")
    .b(still_alive)
    .finish();
    let my_pid = unsafe { syscall6(NR_GETPID, 0, 0, 0, 0, 0, 0) };
    begin_report("main_survives_sibling_kill_thread", my_pid > 0)
        .s("pid=")
        .i(my_pid)
        .finish();
}

// ---------------------------------------------------------------------------
// Exact AArch64 TRAP/SIGSYS ABI. The `adr`+`str` pair publishes the exact post-`svc` resume
// address to `EXPECTED_IP` before the syscall executes, so the handler's `si_call_addr` can be
// checked for bit-exact equality rather than a plausibility bound.
// ---------------------------------------------------------------------------

static EXPECTED_IP: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static TRAP_FIRED: AtomicBool = AtomicBool::new(false);
static TRAP_SIGNO_OK: AtomicBool = AtomicBool::new(false);
static TRAP_ERRNO_OK: AtomicBool = AtomicBool::new(false);
static TRAP_CODE_OK: AtomicBool = AtomicBool::new(false);
static TRAP_NR_OK: AtomicBool = AtomicBool::new(false);
static TRAP_ARCH_OK: AtomicBool = AtomicBool::new(false);
static TRAP_ADDR_OK: AtomicBool = AtomicBool::new(false);
static TRAP_X0_ROLLBACK: AtomicI32 = AtomicI32::new(-1);

const NR_GETTID_I32: i32 = 178;

core::arch::global_asm!(
    ".global attester_sigreturn_trampoline",
    "attester_sigreturn_trampoline:",
    "mov x8, #139", // rt_sigreturn
    "svc #0",
);
unsafe extern "C" {
    fn attester_sigreturn_trampoline();
}

extern "C" fn sigsys_handler(sig: i32, info: *const u8, _ucontext: *const u8) {
    TRAP_FIRED.store(true, Ordering::SeqCst);
    if info.is_null() {
        return;
    }
    unsafe {
        let signo = core::ptr::read_unaligned(info.cast::<i32>());
        let errno = core::ptr::read_unaligned(info.add(4).cast::<i32>());
        let code = core::ptr::read_unaligned(info.add(8).cast::<i32>());
        let call_addr = core::ptr::read_unaligned(info.add(16).cast::<u64>());
        let syscall_nr = core::ptr::read_unaligned(info.add(24).cast::<i32>());
        let arch = core::ptr::read_unaligned(info.add(28).cast::<u32>());
        TRAP_SIGNO_OK.store(
            sig as i64 == SIGSYS && signo as i64 == SIGSYS,
            Ordering::SeqCst,
        );
        TRAP_ERRNO_OK.store(errno == TRAP_DATA as i32, Ordering::SeqCst);
        TRAP_CODE_OK.store(code == SYS_SECCOMP_CODE, Ordering::SeqCst);
        TRAP_NR_OK.store(syscall_nr == NR_GETTID_I32, Ordering::SeqCst);
        TRAP_ARCH_OK.store(arch == AUDIT_ARCH_AARCH64, Ordering::SeqCst);
        TRAP_ADDR_OK.store(
            call_addr == EXPECTED_IP.load(Ordering::SeqCst),
            Ordering::SeqCst,
        );
    }
}

fn install_sigsys_handler() -> i64 {
    let mut act = [0u8; 32];
    vwrite(&mut act, 0, &(sigsys_handler as *const () as u64).to_ne_bytes());
    let flags: u32 = SA_SIGINFO | SA_RESTORER;
    vwrite(&mut act, 8, &flags.to_ne_bytes());
    vwrite(
        &mut act,
        16,
        &(attester_sigreturn_trampoline as *const () as u64).to_ne_bytes(),
    );
    unsafe { syscall6(NR_RT_SIGACTION, SIGSYS, act.as_ptr() as i64, 0, 8, 0, 0) }
}

/// Issues `gettid()` after publishing the exact expected post-`svc` resume address. When a
/// `SECCOMP_RET_TRAP` filter is active for this syscall, control never "returns" here in the
/// normal sense: the SIGSYS handler fires instead, and only its own `sigreturn` resumes execution
/// at the `2:` label below -- with `x0` rolled back to this call's own `a0` input (real Linux
/// `syscall_rollback`), which is why the return value is discarded rather than asserted here.
fn probe_trap_call() -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "adr x9, 2f",
            "str x9, [{expected_ip}]",
            "svc #0",
            "2:",
            expected_ip = in(reg) EXPECTED_IP.as_ptr(),
            inlateout("x0") 0i64 => ret,
            in("x8") NR_GETTID,
            out("x9") _,
            options(nostack)
        );
    }
    ret
}

fn probe_trap_abi() {
    let r = install_sigsys_handler();
    begin_report("sigsys_handler_installed", r == 0)
        .s("ret=")
        .i(r)
        .finish();

    let trap_filter = nr_action_filter(NR_GETTID as u32, SECCOMP_RET_TRAP | TRAP_DATA);
    let r = install_filter(0, &trap_filter);
    begin_report("install_trap_filter", r == 0).s("ret=").i(r).finish();

    let _ = probe_trap_call();

    let mut ok = TRAP_FIRED.load(Ordering::SeqCst);
    for _ in 0..500 {
        if ok {
            break;
        }
        sleep_short();
        ok = TRAP_FIRED.load(Ordering::SeqCst);
    }
    begin_report("trap_sigsys_delivered", ok).s("fired=").b(ok).finish();
    begin_report("trap_sigsys_signo_exact", TRAP_SIGNO_OK.load(Ordering::SeqCst))
        .s("expected=")
        .i(SIGSYS)
        .finish();
    begin_report(
        "trap_sigsys_errno_carries_filter_data",
        TRAP_ERRNO_OK.load(Ordering::SeqCst),
    )
    .s("expected=")
    .h(u64::from(TRAP_DATA))
    .finish();
    begin_report(
        "trap_sigsys_code_is_sys_seccomp",
        TRAP_CODE_OK.load(Ordering::SeqCst),
    )
    .s("expected=")
    .i(i64::from(SYS_SECCOMP_CODE))
    .finish();
    begin_report(
        "trap_sigsys_syscall_nr_exact",
        TRAP_NR_OK.load(Ordering::SeqCst),
    )
    .s("expected=")
    .i(i64::from(NR_GETTID_I32))
    .finish();
    begin_report(
        "trap_sigsys_arch_is_aarch64",
        TRAP_ARCH_OK.load(Ordering::SeqCst),
    )
    .s("expected=")
    .h(u64::from(AUDIT_ARCH_AARCH64))
    .finish();
    begin_report(
        "trap_sigsys_call_addr_exact_post_svc_pc",
        TRAP_ADDR_OK.load(Ordering::SeqCst),
    )
    .s("expected_ip=")
    .h(EXPECTED_IP.load(Ordering::SeqCst))
    .finish();
    let _ = TRAP_X0_ROLLBACK.load(Ordering::SeqCst);
}

// ---------------------------------------------------------------------------
// KILL_PROCESS / unknown-action fail-closed: both must silently end the WHOLE process via SIGSYS,
// so each runs inside its own disposable forked child; the parent observes the death via wait4.
// ---------------------------------------------------------------------------

fn probe_process_death(name: &'static str, action: u32) {
    let pid = unsafe { syscall6(NR_CLONE, SIGCHLD, 0, 0, 0, 0, 0) };
    if pid == 0 {
        let filter = nr_action_filter(NR_NANOSLEEP as u32, action);
        install_filter(0, &filter);
        let ts = [0i64, 0i64];
        unsafe {
            syscall6(NR_NANOSLEEP, ts.as_ptr() as i64, 0, 0, 0, 0, 0);
        }
        // Reached only if the action did NOT terminate the process as expected.
        sys_exit_group(77);
    } else if pid > 0 {
        let (_, status) = sys_wait4(pid);
        let signaled = (status & 0x7f) != 0 && (status & 0x7f) != 0x7f;
        let termsig = status & 0x7f;
        let pass = signaled && i64::from(termsig) == SIGSYS;
        begin_report(name, pass)
            .s("status=")
            .h(status as u64)
            .s(" signaled=")
            .b(signaled)
            .s(" termsig=")
            .i(i64::from(termsig))
            .finish();
    } else {
        begin_report(name, false).s("clone failed ret=").i(pid).finish();
    }
}

// ---------------------------------------------------------------------------
// fork()/vfork() inheritance: the child must see the same already-installed chain (denying
// nanosleep) main established earlier, with no re-install needed.
// ---------------------------------------------------------------------------

fn probe_process_inherit(name: &'static str, flags: i64) {
    let pid = unsafe { syscall6(NR_CLONE, flags, 0, 0, 0, 0, 0) };
    if pid == 0 {
        let ts = [0i64, 0i64];
        let r = unsafe { syscall6(NR_NANOSLEEP, ts.as_ptr() as i64, 0, 0, 0, 0, 0) };
        begin_report(name, r == EPERM)
            .s("child nanosleep ret=")
            .i(r)
            .finish();
        sys_exit_group(0);
    } else if pid > 0 {
        let (_, status) = sys_wait4(pid);
        let exited_ok = (status & 0x7f) == 0 && ((status >> 8) & 0xff) == 0;
        if !exited_ok {
            begin_report(name, false)
                .s("child did not exit cleanly, status=")
                .h(status as u64)
                .finish();
        }
    } else {
        begin_report(name, false).s("clone failed ret=").i(pid).finish();
    }
}

// ---------------------------------------------------------------------------
// execve() inheritance: seccomp (and NNP) must survive replacing the program image -- the whole
// point of the mechanism. `exec_child` is a tiny separate no_std binary whose exit code alone
// reports the outcome (0 = nanosleep denied and NNP still set).
// ---------------------------------------------------------------------------

fn probe_exec_preserves_seccomp() {
    let pid = unsafe { syscall6(NR_CLONE, SIGCHLD, 0, 0, 0, 0, 0) };
    if pid == 0 {
        let path = b"/exec_child\0";
        // Same hazard `vwrite`'s own doc comment describes, for pointer-sized slots instead of
        // bytes: `argv`/`envp` are read by `execve` only through an address erased to `i64`, so
        // an ordinary array-literal initializer is free to be treated as dead by the optimizer.
        let mut argv: [*const u8; 2] = [core::ptr::null(); 2];
        let mut envp: [*const u8; 1] = [core::ptr::null(); 1];
        unsafe {
            core::ptr::write_volatile(&mut argv[0], path.as_ptr());
            core::ptr::write_volatile(&mut argv[1], core::ptr::null());
            core::ptr::write_volatile(&mut envp[0], core::ptr::null());
        }
        unsafe {
            syscall6(
                NR_EXECVE,
                path.as_ptr() as i64,
                argv.as_ptr() as i64,
                envp.as_ptr() as i64,
                0,
                0,
                0,
            );
        }
        sys_exit_group(210); // reached only if execve itself failed
    } else if pid > 0 {
        let (_, status) = sys_wait4(pid);
        let exited = (status & 0x7f) == 0;
        let code = (status >> 8) & 0xff;
        begin_report("exec_preserves_seccomp_and_nnp", exited && code == 0)
            .s("status=")
            .h(status as u64)
            .s(" code=")
            .i(i64::from(code))
            .finish();
    } else {
        begin_report("exec_preserves_seccomp_and_nnp", false)
            .s("fork failed ret=")
            .i(pid)
            .finish();
    }
}

// ---------------------------------------------------------------------------
// Orchestration.
// ---------------------------------------------------------------------------

fn main_probes() {
    probe_flags_and_nulls();

    let r = unsafe { syscall6(NR_PRCTL, PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0, 0) };
    begin_report("set_no_new_privs", r == 0).s("ret=").i(r).finish();
    let g = unsafe { syscall6(NR_PRCTL, PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0, 0) };
    begin_report("get_no_new_privs_reads_back", g == 1)
        .s("ret=")
        .i(g)
        .finish();

    let r = install_filter(0, &ALLOW_ALL);
    begin_report("install_after_nnp_succeeds", r == 0)
        .s("depth_ret=")
        .i(r)
        .finish();

    probe_policy_before_side_effect();

    let t2_tid = spawn_thread(thread_entry_t2, t2_stack_top());
    begin_report("spawn_t2", t2_tid > 0).s("tid=").i(t2_tid).finish();

    T2_STAGE.store(1, Ordering::SeqCst);
    wait_stage(&T2_DONE, 1);

    let y1 = nr_action_filter(NR_GETPID as u32, SECCOMP_RET_ERRNO | 1);
    let r = install_filter(SECCOMP_FILTER_FLAG_TSYNC, &y1);
    begin_report("tsync_install_succeeds_returns_zero", r == 0)
        .s("ret=")
        .i(r)
        .finish();
    let my_getpid = unsafe { syscall6(NR_GETPID, 0, 0, 0, 0, 0, 0) };
    begin_report("tsync_denies_installer_too", my_getpid == EPERM)
        .s("ret=")
        .i(my_getpid)
        .finish();

    T2_STAGE.store(2, Ordering::SeqCst);
    wait_stage(&T2_DONE, 2);

    let m4 = nr_action_filter(NR_NANOSLEEP as u32, SECCOMP_RET_ERRNO | 1);
    let r = install_filter(0, &m4);
    begin_report("plain_install_after_thread_exists_succeeds", r == 0)
        .s("ret=")
        .i(r)
        .finish();

    T2_STAGE.store(3, Ordering::SeqCst);
    wait_stage(&T2_DONE, 3);

    let t3_tid = spawn_thread(thread_entry_t3, t3_stack_top());
    begin_report("spawn_t3", t3_tid > 0).s("tid=").i(t3_tid).finish();
    T3_STAGE.store(1, Ordering::SeqCst);
    wait_stage(&T3_DONE, 1);

    let my_gettid_before = unsafe { syscall6(NR_GETTID, 0, 0, 0, 0, 0, 0) };

    let y2 = nr_action_filter(NR_GETTID as u32, SECCOMP_RET_ERRNO | 1);
    let r = install_filter(SECCOMP_FILTER_FLAG_TSYNC, &y2);
    begin_report("tsync_incompatible_returns_sibling_tid", r == t3_tid)
        .s("ret=")
        .i(r)
        .s(" expected=")
        .i(t3_tid)
        .finish();

    let my_gettid_after = unsafe { syscall6(NR_GETTID, 0, 0, 0, 0, 0, 0) };
    begin_report(
        "tsync_incompatible_installer_unaffected",
        my_gettid_after > 0 && my_gettid_after == my_gettid_before,
    )
    .s("before=")
    .i(my_gettid_before)
    .s(" after=")
    .i(my_gettid_after)
    .finish();

    T2_STAGE.store(4, Ordering::SeqCst);
    wait_stage(&T2_DONE, 4);
    T2_STAGE.store(5, Ordering::SeqCst);
    T3_STAGE.store(2, Ordering::SeqCst);
    sleep_ms(50);

    probe_trap_abi();
    probe_kill_thread();
    probe_process_death(
        "kill_process_terminates_whole_process",
        SECCOMP_RET_KILL_PROCESS,
    );
    probe_process_death(
        "unknown_action_fails_closed_like_kill_process",
        0x4000_0000,
    );
    probe_process_inherit("fork_inherits_seccomp_chain", SIGCHLD);
    probe_process_inherit("vfork_inherits_seccomp_chain", VFORK_FLAGS);
    probe_exec_preserves_seccomp();
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    main_probes();
    let pass = PASS.load(Ordering::SeqCst);
    let fail = FAIL.load(Ordering::SeqCst);
    let mut buf = OutBuf::new();
    buf.s("SUMMARY total=")
        .u(u64::from(pass) + u64::from(fail))
        .s(" pass=")
        .u(u64::from(pass))
        .s(" fail=")
        .u(u64::from(fail));
    buf.finish();
    sys_exit_group(if fail == 0 { 0 } else { 1 })
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    unsafe {
        syscall6(
            NR_WRITE,
            1,
            c"PANIC in seccomp attester guest\n".as_ptr() as i64,
            33,
            0,
            0,
            0,
        );
    }
    sys_exit_group(200)
}

// ---------------------------------------------------------------------------
// This freestanding binary links against no libc and no compiler-rt: `core`'s own prebuilt rlib
// calls into a small number of C-ABI runtime symbols it normally expects the platform to supply
// (`mem*` from libc; `rust_eh_personality` from an unwinder, never actually invoked since this
// crate builds with `panic = "abort"`). Providing trivial definitions here, rather than trying to
// eliminate every `core` path that might reference them, is the same "read the actual current
// requirement, don't guess around it" approach applied to the guest binary's own link step.
// ---------------------------------------------------------------------------

use core::ffi::c_void;

#[unsafe(no_mangle)]
unsafe extern "C" fn memcpy(dest: *mut c_void, src: *const c_void, n: usize) -> *mut c_void {
    let d = dest.cast::<u8>();
    let s = src.cast::<u8>();
    let mut i = 0;
    while i < n {
        unsafe {
            *d.add(i) = *s.add(i);
        }
        i += 1;
    }
    dest
}

#[unsafe(no_mangle)]
unsafe extern "C" fn memset(dest: *mut c_void, value: i32, n: usize) -> *mut c_void {
    let d = dest.cast::<u8>();
    let mut i = 0;
    while i < n {
        unsafe {
            *d.add(i) = value as u8;
        }
        i += 1;
    }
    dest
}

#[unsafe(no_mangle)]
unsafe extern "C" fn memmove(dest: *mut c_void, src: *const c_void, n: usize) -> *mut c_void {
    let d = dest.cast::<u8>();
    let s = src.cast::<u8>();
    if (d as usize) <= (s as usize) {
        unsafe { memcpy(dest, src, n) };
    } else {
        let mut i = n;
        while i > 0 {
            i -= 1;
            unsafe {
                *d.add(i) = *s.add(i);
            }
        }
    }
    dest
}

#[unsafe(no_mangle)]
extern "C" fn rust_eh_personality() {}
