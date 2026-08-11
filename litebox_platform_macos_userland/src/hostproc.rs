// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Real host processes for the guest's `fork(2)`, via an out-of-jail spawn helper.
//!
//! # Why a helper process at all
//!
//! A guest `fork()` followed by `execve()` needs a *second host process*: LiteBox
//! runs guest instructions natively, so the second guest image needs its own
//! address space, and on this platform that means its own `litebox_runner`.
//!
//! The runner cannot create one itself. By the time any guest code runs, the
//! runner has installed the `(deny default)` Seatbelt profile in
//! [`crate::seatbelt`], and that profile denies `process-fork` and
//! `process-exec` outright -- deliberately, and measured: the profile's own test
//! asserts that `Command::new("/bin/echo")` fails with `EPERM` after the profile
//! goes up. Widening the profile to re-admit `exec` was tried and rejected: a
//! usable `exec` needs `(allow process*)` *plus* a blanket `(allow file-read*)`
//! (measured on this host: restricting reads to `/usr/lib` + `/System` still
//! leaves the child dying on `SIGABRT` in `dyld`), and "the guest can read every
//! file on the host" gives up most of what the profile is for.
//!
//! So the runner instead spawns one small **helper process before the sandbox
//! goes up**, keeps a `socketpair` to it, and asks the helper to do the
//! spawning. The runner's own profile is completely unchanged by this work.
//! Three properties of the jail make it work, each measured on this host rather
//! than assumed (see `hostproc_probes` at the bottom of this file):
//!
//! * `pipe(2)` and `socketpair(2)` still succeed inside the jail -- they are not
//!   Seatbelt-mediated operations.
//! * A descriptor may still be *passed out* over an already-open `AF_UNIX`
//!   socket with `SCM_RIGHTS`, and the receiver gets a working descriptor.
//! * The jailed process therefore never needs `fork`, `exec`, `open`, or
//!   `connect` to give a child process a set of descriptors and a program to run.
//!
//! # Fork safety
//!
//! LiteBox's host process is always multithreaded while a guest runs (the stdin
//! pump, the timer threads, every guest thread), so a raw `fork(2)` would hand
//! the child a single thread plus whatever locks the others held -- including
//! the allocator's. **Nothing here ever calls `fork(2)`.** Both spawn paths use
//! `posix_spawn(2)`, which on Darwin is a single kernel operation that builds the
//! new process image directly (`__posix_spawn`) rather than duplicating the
//! caller: no page tables are copied, no threads are dropped, and no lock state
//! is inherited. `POSIX_SPAWN_CLOEXEC_DEFAULT` additionally guarantees the child
//! starts with *only* the descriptors named in its file actions.
//!
//! # Protocol
//!
//! Runner -> helper, one `sendmsg` per request, with the descriptors to install
//! in the new process attached as `SCM_RIGHTS`:
//!
//! ```text
//! u32 payload_len | u8 op=SPAWN | u64 request_id | u32 n_fds | n_fds * i32 target_fd | u32 blob_len | blob
//! ```
//!
//! Helper -> runner:
//!
//! ```text
//! u32 payload_len | u8 op=SPAWNED | u64 request_id | i64 pid | i32 errno
//! u32 payload_len | u8 op=EXITED  | i64 pid | i32 wait_status
//! ```
//!
//! `blob` is the [`ChildSpec`] the new runner reads back from its own fd 3: the
//! tar archive to load, the guest program path, `argv` and `envp`. It travels as
//! opaque bytes so that non-UTF-8 guest arguments survive intact, which they
//! would not if they were passed as host command-line arguments.

use core::ffi::c_int;
use std::collections::{BTreeMap, VecDeque};
use std::sync::{Condvar, Mutex};

use litebox::platform::{HostFd, HostProcessError, HostProcessSpec, StdioStream};

/// Apple's extension that makes `posix_spawn` close every descriptor the file
/// actions do not name, instead of inheriting all non-`FD_CLOEXEC` ones.
/// Declared here because the `libc` crate does not expose it.
const POSIX_SPAWN_CLOEXEC_DEFAULT: libc::c_short = 0x4000;

/// The descriptor the helper reads its requests from, and the one a spawned
/// runner reads its [`ChildSpec`] from. Both are placed there by an explicit
/// `posix_spawn` `dup2` file action.
pub const HELPER_SOCKET_FD: c_int = 3;

/// Argument that turns this executable into the spawn helper.
pub const SPAWN_HELPER_ARG: &str = "--litebox-spawn-helper";
/// Argument that turns this executable into a guest child process.
pub const SPAWNED_CHILD_ARG: &str = "--litebox-spawned-child";

const OP_SPAWN: u8 = 1;
const OP_SPAWNED: u8 = 2;
const OP_EXITED: u8 = 3;

/// Upper bound on descriptors handed to one child, which bounds the `SCM_RIGHTS`
/// control buffer on both sides. A guest child only ever gets stdin, stdout and
/// stderr today (see the shim's `export_fds_for_spawn`), so this is slack.
const MAX_PASSED_FDS: usize = 8;

/// Bytes of `SCM_RIGHTS` payload for [`MAX_PASSED_FDS`] descriptors.
const MAX_CONTROL_PAYLOAD: u32 = 32;
const _: () = assert!(MAX_CONTROL_PAYLOAD as usize == MAX_PASSED_FDS * size_of::<c_int>());

/// Size of the `SCM_RIGHTS` control buffer on both sides, for [`MAX_PASSED_FDS`]
/// descriptors.
// SAFETY: `CMSG_SPACE` is pure arithmetic over its argument.
const CONTROL_BUFFER_LEN: usize = unsafe { libc::CMSG_SPACE(MAX_CONTROL_PAYLOAD) } as usize;

/// Bytes of `SCM_RIGHTS` payload for `count` descriptors, in the `u32` the
/// `CMSG_*` helpers take.
fn control_payload_bytes(count: usize) -> u32 {
    u32::try_from(count * size_of::<c_int>()).expect("at most MAX_PASSED_FDS descriptors")
}

/// One message off the helper socket: its payload, and any descriptors that
/// arrived with it.
type ReceivedMessage = (Vec<u8>, Vec<c_int>);

// ---------------------------------------------------------------------------
// Byte-level encoding helpers
// ---------------------------------------------------------------------------

fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_le_bytes());
}
fn put_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_le_bytes());
}
fn put_i64(out: &mut Vec<u8>, v: i64) {
    out.extend_from_slice(&v.to_le_bytes());
}
fn put_i32(out: &mut Vec<u8>, v: i32) {
    out.extend_from_slice(&v.to_le_bytes());
}
fn put_bytes(out: &mut Vec<u8>, v: &[u8]) {
    put_u32(out, u32::try_from(v.len()).expect("byte string fits in u32"));
    out.extend_from_slice(v);
}

/// A cursor over a received message. Every getter returns `None` on truncation
/// rather than panicking, so a malformed message can only fail a request.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.0.len() < n {
            return None;
        }
        let (head, tail) = self.0.split_at(n);
        self.0 = tail;
        Some(head)
    }
    fn u8(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }
    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_le_bytes(self.take(4)?.try_into().ok()?))
    }
    fn u64(&mut self) -> Option<u64> {
        Some(u64::from_le_bytes(self.take(8)?.try_into().ok()?))
    }
    fn i32(&mut self) -> Option<i32> {
        Some(i32::from_le_bytes(self.take(4)?.try_into().ok()?))
    }
    fn i64(&mut self) -> Option<i64> {
        Some(i64::from_le_bytes(self.take(8)?.try_into().ok()?))
    }
    fn bytes(&mut self) -> Option<&'a [u8]> {
        let n = self.u32()? as usize;
        self.take(n)
    }
}

// ---------------------------------------------------------------------------
// The child specification a spawned runner reads from its fd 3
// ---------------------------------------------------------------------------

/// Everything a freshly spawned runner needs in order to become the guest
/// child: which archive to build the guest filesystem from, and what to run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChildSpec {
    /// Host path of the tar archive holding the guest root filesystem, i.e. the
    /// parent runner's own `--initial-files`.
    pub initial_files: Vec<u8>,
    /// Guest path of the program to execute.
    pub program: Vec<u8>,
    /// Full `argv`, including `argv[0]`.
    pub argv: Vec<Vec<u8>>,
    /// Full environment as `KEY=VALUE` byte strings.
    pub envp: Vec<Vec<u8>>,
}

impl ChildSpec {
    /// Serializes to the wire form the helper pipes into the child's fd 3.
    ///
    /// # Panics
    ///
    /// Panics if `argv` or `envp` has more than `u32::MAX` entries, or any
    /// single entry is longer than `u32::MAX` bytes -- neither of which a Linux
    /// `execve` can produce, since it caps the whole block far below that.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        put_bytes(&mut out, &self.initial_files);
        put_bytes(&mut out, &self.program);
        put_u32(&mut out, u32::try_from(self.argv.len()).unwrap());
        for a in &self.argv {
            put_bytes(&mut out, a);
        }
        put_u32(&mut out, u32::try_from(self.envp.len()).unwrap());
        for e in &self.envp {
            put_bytes(&mut out, e);
        }
        out
    }

    /// Parses the wire form produced by [`Self::encode`].
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let mut r = Reader(bytes);
        let initial_files = r.bytes()?.to_vec();
        let program = r.bytes()?.to_vec();
        let argument_count = r.u32()? as usize;
        let mut argv = Vec::with_capacity(argument_count);
        for _ in 0..argument_count {
            argv.push(r.bytes()?.to_vec());
        }
        let variable_count = r.u32()? as usize;
        let mut envp = Vec::with_capacity(variable_count);
        for _ in 0..variable_count {
            envp.push(r.bytes()?.to_vec());
        }
        Some(Self {
            initial_files,
            program,
            argv,
            envp,
        })
    }
}

/// Reads the [`ChildSpec`] a spawned runner was started with, from
/// [`HELPER_SOCKET_FD`], and closes it.
///
/// # Errors
///
/// Returns an error if the descriptor cannot be read to end of file or the bytes
/// do not decode.
pub fn read_child_spec() -> std::io::Result<ChildSpec> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        // SAFETY: `chunk` is a live, uniquely owned buffer of exactly this size.
        let n = unsafe {
            libc::read(
                HELPER_SOCKET_FD,
                chunk.as_mut_ptr().cast(),
                chunk.len(),
            )
        };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n.cast_unsigned()]);
    }
    // SAFETY: closing a descriptor this process owns and will not touch again.
    unsafe { libc::close(HELPER_SOCKET_FD) };
    ChildSpec::decode(&buf).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "malformed litebox child spec",
        )
    })
}

// ---------------------------------------------------------------------------
// Small libc wrappers
// ---------------------------------------------------------------------------

fn last_error() -> HostProcessError {
    HostProcessError::Host(std::io::Error::last_os_error().raw_os_error().unwrap_or(0))
}

/// Sends `payload` plus `fds` (as `SCM_RIGHTS`) on `sock` in a single `sendmsg`.
fn send_with_fds(sock: c_int, payload: &[u8], fds: &[c_int]) -> Result<(), HostProcessError> {
    assert!(fds.len() <= MAX_PASSED_FDS);
    let mut control = [0u8; CONTROL_BUFFER_LEN];
    let mut sent = 0usize;
    while sent < payload.len() {
        let mut iov = libc::iovec {
            iov_base: payload[sent..].as_ptr() as *mut _,
            iov_len: payload.len() - sent,
        };
        // SAFETY: `msghdr` is a plain C struct with no invalid bit patterns.
        let mut msg: libc::msghdr = unsafe { core::mem::zeroed() };
        msg.msg_iov = &raw mut iov;
        msg.msg_iovlen = 1;
        // The descriptors ride along with the first byte of the stream segment,
        // which is where the receiver's `recvmsg` collects them; a short send
        // must not re-attach them to the remainder.
        if sent == 0 && !fds.is_empty() {
            // SAFETY: `control` is a live buffer sized by `CMSG_SPACE` for the
            // maximum number of descriptors, and `fds.len()` is at most that.
            let controllen = unsafe { libc::CMSG_SPACE(control_payload_bytes(fds.len())) };
            msg.msg_control = control.as_mut_ptr().cast();
            msg.msg_controllen = controllen;
            // SAFETY: `msg_control`/`msg_controllen` were just set to a live
            // buffer big enough for this many descriptors.
            unsafe {
                let cmsg = libc::CMSG_FIRSTHDR(&raw const msg);
                (*cmsg).cmsg_level = libc::SOL_SOCKET;
                (*cmsg).cmsg_type = libc::SCM_RIGHTS;
                (*cmsg).cmsg_len = libc::CMSG_LEN(control_payload_bytes(fds.len()));
                // Copied as bytes rather than as `c_int`s: `CMSG_DATA` is a
                // `*mut u8`, and casting it to a more strictly aligned pointer
                // would be a promise about the control buffer's alignment that
                // this code does not need to make.
                core::ptr::copy_nonoverlapping(
                    fds.as_ptr().cast::<u8>(),
                    libc::CMSG_DATA(cmsg),
                    control_payload_bytes(fds.len()) as usize,
                );
            }
        }
        // SAFETY: `msg` describes live buffers for the duration of the call.
        let n = unsafe { libc::sendmsg(sock, &raw const msg, 0) };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(HostProcessError::Host(err.raw_os_error().unwrap_or(0)));
        }
        sent += n.cast_unsigned();
    }
    Ok(())
}

/// Reads exactly `buf.len()` bytes, returning `false` at a clean end of stream.
fn read_exact(sock: c_int, buf: &mut [u8]) -> Result<bool, HostProcessError> {
    let mut got = 0;
    while got < buf.len() {
        // SAFETY: writing into a live, uniquely owned slice.
        let n = unsafe { libc::read(sock, buf[got..].as_mut_ptr().cast(), buf.len() - got) };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(HostProcessError::Host(err.raw_os_error().unwrap_or(0)));
        }
        if n == 0 {
            return Ok(false);
        }
        got += n.cast_unsigned();
    }
    Ok(true)
}

/// Receives one message: the 4-byte length header comes back through `recvmsg`
/// so that any `SCM_RIGHTS` attached to it is collected with it, and the body is
/// then read as plain stream bytes.
fn recv_message(sock: c_int) -> Result<Option<ReceivedMessage>, HostProcessError> {
    let mut header = [0u8; 4];
    let mut control = [0u8; CONTROL_BUFFER_LEN];
    let mut iov = libc::iovec {
        iov_base: header.as_mut_ptr().cast(),
        iov_len: header.len(),
    };
    // SAFETY: `msghdr` is a plain C struct with no invalid bit patterns.
    let mut msg: libc::msghdr = unsafe { core::mem::zeroed() };
    msg.msg_iov = &raw mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast();
    msg.msg_controllen = u32::try_from(control.len()).unwrap();
    let n = loop {
        // SAFETY: `msg` describes live buffers for the duration of the call.
        let n = unsafe { libc::recvmsg(sock, &raw mut msg, 0) };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(HostProcessError::Host(err.raw_os_error().unwrap_or(0)));
        }
        break n.cast_unsigned();
    };
    if n == 0 {
        return Ok(None);
    }
    let mut fds = Vec::new();
    // SAFETY: `msg` was just filled in by `recvmsg`, so its control buffer is
    // whatever the kernel wrote there.
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(&raw const msg);
        while !cmsg.is_null() {
            if (*cmsg).cmsg_level == libc::SOL_SOCKET && (*cmsg).cmsg_type == libc::SCM_RIGHTS {
                let payload_len = (*cmsg).cmsg_len as usize - libc::CMSG_LEN(0) as usize;
                let count = payload_len / size_of::<c_int>();
                let data = libc::CMSG_DATA(cmsg);
                // Read byte-wise for the same reason `send_with_fds` writes
                // byte-wise: no alignment claim about the control buffer.
                for i in 0..count {
                    let mut raw = [0u8; size_of::<c_int>()];
                    core::ptr::copy_nonoverlapping(
                        data.add(i * size_of::<c_int>()),
                        raw.as_mut_ptr(),
                        size_of::<c_int>(),
                    );
                    fds.push(c_int::from_ne_bytes(raw));
                }
            }
            cmsg = libc::CMSG_NXTHDR(&raw const msg, cmsg);
        }
    }
    if n < header.len() && !read_exact(sock, &mut header[n..])? {
        return Ok(None);
    }
    let len = u32::from_le_bytes(header) as usize;
    let mut body = vec![0u8; len];
    if !read_exact(sock, &mut body)? {
        return Ok(None);
    }
    Ok(Some((body, fds)))
}

/// `posix_spawn`s `program` with `argv`, installing `fds` as `(target, source)`
/// pairs and closing everything else in the child.
///
/// Never forks: see this module's fork-safety note.
fn posix_spawn_with_fds(
    program: &std::ffi::CStr,
    argv: &[&std::ffi::CStr],
    fds: &[(c_int, c_int)],
) -> Result<libc::pid_t, HostProcessError> {
    // SAFETY: both are opaque C structs initialized by their `_init` calls below.
    let mut actions: libc::posix_spawn_file_actions_t = unsafe { core::mem::zeroed() };
    // SAFETY: `actions` is a live, uniquely owned out-parameter.
    if unsafe { libc::posix_spawn_file_actions_init(&raw mut actions) } != 0 {
        return Err(last_error());
    }
    // SAFETY: `attr` is a live, uniquely owned out-parameter.
    let mut attr: libc::posix_spawnattr_t = unsafe { core::mem::zeroed() };
    // SAFETY: as above.
    if unsafe { libc::posix_spawnattr_init(&raw mut attr) } != 0 {
        // SAFETY: `actions` was successfully initialized just above.
        unsafe { libc::posix_spawn_file_actions_destroy(&raw mut actions) };
        return Err(last_error());
    }
    // SAFETY: `attr` is initialized.
    unsafe { libc::posix_spawnattr_setflags(&raw mut attr, POSIX_SPAWN_CLOEXEC_DEFAULT) };
    for &(target, source) in fds {
        // SAFETY: `actions` is initialized; the descriptors are plain integers
        // that the child, not this call, will act on.
        unsafe { libc::posix_spawn_file_actions_adddup2(&raw mut actions, source, target) };
    }
    let mut c_argv: Vec<*mut libc::c_char> = argv
        .iter()
        .map(|a| a.as_ptr().cast_mut())
        .collect();
    c_argv.push(core::ptr::null_mut());
    let mut pid: libc::pid_t = 0;
    // SAFETY: every pointer is live for the duration of the call, and `c_argv`
    // and the environment are NULL-terminated pointer arrays.
    let rc = unsafe {
        libc::posix_spawn(
            &raw mut pid,
            program.as_ptr(),
            &raw const actions,
            &raw const attr,
            c_argv.as_mut_ptr(),
            core::ptr::null_mut(),
        )
    };
    // SAFETY: both objects were successfully initialized above.
    unsafe {
        libc::posix_spawn_file_actions_destroy(&raw mut actions);
        libc::posix_spawnattr_destroy(&raw mut attr);
    }
    if rc != 0 {
        return Err(HostProcessError::Host(rc));
    }
    Ok(pid)
}

fn close_fd(fd: c_int) {
    // SAFETY: closing a descriptor the caller has given up.
    unsafe { libc::close(fd) };
}

// ---------------------------------------------------------------------------
// Runner side
// ---------------------------------------------------------------------------

/// The runner's live connection to its spawn helper.
pub(crate) struct HostProcesses {
    /// Send half of the helper socket. Held under a mutex so two guest threads
    /// cannot interleave the bytes of two requests.
    send_lock: Mutex<()>,
    socket: c_int,
    /// Host path of the tar archive to hand to every spawned child.
    initial_files: Vec<u8>,
    state: Mutex<State>,
    doorbell: Condvar,
}

#[derive(Default)]
struct State {
    /// Bumped for every event a `wait4` caller might care about.
    generation: u32,
    /// Spawned processes that have exited and not yet been collected.
    exited: VecDeque<(i64, i32)>,
    /// In-flight spawn requests, by request id, filled in by the reader thread.
    replies: BTreeMap<u64, Option<Result<i64, i32>>>,
    next_request_id: u64,
    /// Set when the helper connection is gone; unblocks anyone waiting on it.
    helper_lost: bool,
}

impl HostProcesses {
    /// Starts the helper process and the thread that listens to it.
    ///
    /// Must be called before the Seatbelt profile goes up, because this is the
    /// one and only `exec` the runner performs.
    pub(crate) fn start(initial_files: &[u8]) -> std::io::Result<Self> {
        let exe = std::env::current_exe()?;
        let exe = std::ffi::CString::new(
            std::os::unix::ffi::OsStrExt::as_bytes(exe.as_os_str()).to_vec(),
        )
        .map_err(|_| std::io::Error::other("executable path contains a NUL"))?;
        let mut sv = [0 as c_int; 2];
        // SAFETY: `sv` is a live, uniquely owned two-element out-parameter.
        if unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sv.as_mut_ptr()) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        let helper_arg = std::ffi::CString::new(SPAWN_HELPER_ARG).unwrap();
        let pid = posix_spawn_with_fds(&exe, &[&exe, &helper_arg], &[(HELPER_SOCKET_FD, sv[1])])
            .map_err(|e| std::io::Error::other(alloc::format!("{e}")))?;
        close_fd(sv[1]);
        litebox_util_log::debug!(pid:? = pid; "started the litebox spawn helper");
        Ok(Self {
            send_lock: Mutex::new(()),
            socket: sv[0],
            initial_files: initial_files.to_vec(),
            state: Mutex::new(State::default()),
            doorbell: Condvar::new(),
        })
    }

    /// Consumes helper messages until the connection ends. Runs on its own host
    /// thread, started by [`crate::MacOsUserland::enable_host_process_support`].
    pub(crate) fn reader_loop(&self) {
        while let Ok(Some((body, _fds))) = recv_message(self.socket) {
            self.handle_message(&body);
        }
        let mut state = self.state.lock().unwrap();
        state.helper_lost = true;
        state.generation = state.generation.wrapping_add(1);
        drop(state);
        self.doorbell.notify_all();
    }

    fn handle_message(&self, body: &[u8]) {
        let mut r = Reader(body);
        let Some(op) = r.u8() else { return };
        let mut state = self.state.lock().unwrap();
        match op {
            OP_SPAWNED => {
                let (Some(id), Some(pid), Some(err)) = (r.u64(), r.i64(), r.i32()) else {
                    return;
                };
                state
                    .replies
                    .insert(id, Some(if pid < 0 { Err(err) } else { Ok(pid) }));
            }
            OP_EXITED => {
                let (Some(pid), Some(status)) = (r.i64(), r.i32()) else {
                    return;
                };
                state.exited.push_back((pid, status));
            }
            _ => return,
        }
        state.generation = state.generation.wrapping_add(1);
        drop(state);
        self.doorbell.notify_all();
    }

    pub(crate) fn spawn(&self, spec: &HostProcessSpec<'_>) -> Result<i64, HostProcessError> {
        let child = ChildSpec {
            initial_files: self.initial_files.clone(),
            program: spec.program.as_bytes().to_vec(),
            argv: spec.argv.iter().map(|a| a.to_vec()).collect(),
            envp: spec.envp.iter().map(|e| e.to_vec()).collect(),
        };
        let blob = child.encode();
        if spec.fds.len() > MAX_PASSED_FDS {
            return Err(HostProcessError::Host(libc::EMFILE));
        }

        let request_id = {
            let mut state = self.state.lock().unwrap();
            if state.helper_lost {
                return Err(HostProcessError::Host(libc::ECHILD));
            }
            state.next_request_id += 1;
            let id = state.next_request_id;
            state.replies.insert(id, None);
            id
        };

        let mut payload = Vec::new();
        payload.push(OP_SPAWN);
        put_u64(&mut payload, request_id);
        put_u32(&mut payload, u32::try_from(spec.fds.len()).unwrap());
        for (target, _) in spec.fds {
            put_i32(&mut payload, *target);
        }
        put_bytes(&mut payload, &blob);
        let mut framed = Vec::with_capacity(payload.len() + 4);
        put_u32(&mut framed, u32::try_from(payload.len()).unwrap());
        framed.extend_from_slice(&payload);
        let raw_fds: Vec<c_int> = spec.fds.iter().map(|(_, fd)| fd.0).collect();

        let send_result = {
            let _guard = self.send_lock.lock().unwrap();
            send_with_fds(self.socket, &framed, &raw_fds)
        };
        // The helper owns these descriptors now (or nobody does, if the send
        // failed); either way this process is done with them.
        for fd in raw_fds {
            close_fd(fd);
        }
        if let Err(err) = send_result {
            self.state.lock().unwrap().replies.remove(&request_id);
            return Err(err);
        }

        let mut state = self.state.lock().unwrap();
        loop {
            match state.replies.get(&request_id) {
                Some(Some(_)) => {
                    let reply = state.replies.remove(&request_id).flatten().unwrap();
                    return reply.map_err(HostProcessError::Host);
                }
                Some(None) => {
                    if state.helper_lost {
                        state.replies.remove(&request_id);
                        return Err(HostProcessError::Host(libc::ECHILD));
                    }
                    state = self.doorbell.wait(state).unwrap();
                }
                None => return Err(HostProcessError::Host(libc::ECHILD)),
            }
        }
    }

    pub(crate) fn take_exited(&self) -> Option<(i64, i32)> {
        self.state.lock().unwrap().exited.pop_front()
    }

    pub(crate) fn generation(&self) -> u32 {
        self.state.lock().unwrap().generation
    }

    pub(crate) fn notify(&self) {
        let mut state = self.state.lock().unwrap();
        state.generation = state.generation.wrapping_add(1);
        drop(state);
        self.doorbell.notify_all();
    }

    pub(crate) fn block_on_event(&self, seen: u32) {
        let mut state = self.state.lock().unwrap();
        while state.generation == seen && !state.helper_lost {
            state = self.doorbell.wait(state).unwrap();
        }
    }
}

/// Creates a host pipe with both ends marked `FD_CLOEXEC`.
///
/// Close-on-exec matters here: these descriptors live in the runner while a
/// guest runs, and `POSIX_SPAWN_CLOEXEC_DEFAULT` means an unrelated later spawn
/// would not leak them anyway, but the flag keeps that from depending on the
/// spawn flags.
pub(crate) fn create_pipe() -> Result<(HostFd, HostFd), HostProcessError> {
    let mut fds = [0 as c_int; 2];
    // SAFETY: `fds` is a live, uniquely owned two-element out-parameter.
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return Err(last_error());
    }
    for fd in fds {
        // SAFETY: `fd` was just returned by `pipe`.
        unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
    }
    Ok((HostFd(fds[0]), HostFd(fds[1])))
}

pub(crate) fn duplicate_stdio(stream: StdioStream) -> Result<HostFd, HostProcessError> {
    let fd = match stream {
        StdioStream::Stdin => 0,
        StdioStream::Stdout => 1,
        StdioStream::Stderr => 2,
    };
    // SAFETY: duplicating one of this process's own standard descriptors.
    let dup = unsafe { libc::dup(fd) };
    if dup < 0 {
        return Err(last_error());
    }
    Ok(HostFd(dup))
}

pub(crate) fn read_fd(fd: &HostFd, buf: &mut [u8]) -> Result<usize, HostProcessError> {
    loop {
        // SAFETY: writing into a live, uniquely owned slice.
        let n = unsafe { libc::read(fd.0, buf.as_mut_ptr().cast(), buf.len()) };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(HostProcessError::Host(err.raw_os_error().unwrap_or(0)));
        }
        return Ok(n.cast_unsigned());
    }
}

pub(crate) fn write_fd(fd: &HostFd, buf: &[u8]) -> Result<usize, HostProcessError> {
    loop {
        // SAFETY: reading out of a live slice.
        let n = unsafe { libc::write(fd.0, buf.as_ptr().cast(), buf.len()) };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(HostProcessError::Host(err.raw_os_error().unwrap_or(0)));
        }
        return Ok(n.cast_unsigned());
    }
}

pub(crate) fn close_host_fd(fd: HostFd) {
    close_fd(fd.0);
}

// ---------------------------------------------------------------------------
// Helper side
// ---------------------------------------------------------------------------

/// Runs this process as the spawn helper, until the runner goes away.
///
/// The helper is deliberately tiny and deliberately outside the Seatbelt jail:
/// it parses only its own fixed-shape protocol, never looks at guest memory, and
/// its whole job is `posix_spawn` plus `waitpid`.
///
/// # Panics
///
/// Panics if this executable's own path cannot be determined, which would make
/// every spawn request unserviceable.
pub fn run_spawn_helper() -> ! {
    let exe = std::env::current_exe().expect("the helper knows its own path");
    let exe = std::ffi::CString::new(std::os::unix::ffi::OsStrExt::as_bytes(exe.as_os_str()).to_vec())
        .expect("executable path contains no NUL");
    let child_arg = std::ffi::CString::new(SPAWNED_CHILD_ARG).unwrap();
    let socket = HELPER_SOCKET_FD;
    let send_lock = std::sync::Arc::new(Mutex::new(()));
    while let Ok(Some((body, fds))) = recv_message(socket) {
        let mut r = Reader(&body);
        let ok = (|| {
            if r.u8()? != OP_SPAWN {
                return None;
            }
            let request_id = r.u64()?;
            let n_fds = r.u32()? as usize;
            let mut targets = Vec::with_capacity(n_fds);
            for _ in 0..n_fds {
                targets.push(r.i32()?);
            }
            let blob = r.bytes()?.to_vec();
            Some((request_id, targets, blob))
        })();
        let Some((request_id, targets, blob)) = ok else {
            for fd in fds {
                close_fd(fd);
            }
            continue;
        };
        if targets.len() != fds.len() {
            for fd in fds {
                close_fd(fd);
            }
            continue;
        }

        // A pipe carrying the child's spec to its fd 3.
        let mut spec_pipe = [0 as c_int; 2];
        // SAFETY: `spec_pipe` is a live, uniquely owned out-parameter.
        if unsafe { libc::pipe(spec_pipe.as_mut_ptr()) } != 0 {
            let _ = reply_spawned(socket, &send_lock, request_id, -1, errno());
            for fd in fds {
                close_fd(fd);
            }
            continue;
        }
        let mut actions: Vec<(c_int, c_int)> = vec![(HELPER_SOCKET_FD, spec_pipe[0])];
        for (target, fd) in targets.iter().zip(fds.iter()) {
            actions.push((*target, *fd));
        }
        let spawned = posix_spawn_with_fds(&exe, &[&exe, &child_arg], &actions);
        close_fd(spec_pipe[0]);
        for fd in fds {
            close_fd(fd);
        }
        match spawned {
            Ok(pid) => {
                // Write the spec from a thread: it is small in practice, but a
                // blocking write here would stall the helper if it ever were not.
                let write_end = spec_pipe[1];
                std::thread::spawn(move || {
                    let mut written = 0;
                    while written < blob.len() {
                        // SAFETY: reading out of a live, owned buffer.
                        let n = unsafe {
                            libc::write(
                                write_end,
                                blob[written..].as_ptr().cast(),
                                blob.len() - written,
                            )
                        };
                        if n <= 0 {
                            break;
                        }
                        written += n.cast_unsigned();
                    }
                    close_fd(write_end);
                });
                let _ = reply_spawned(socket, &send_lock, request_id, i64::from(pid), 0);
                let send_lock = std::sync::Arc::clone(&send_lock);
                std::thread::spawn(move || {
                    let mut status: c_int = 0;
                    // SAFETY: `status` is a live, uniquely owned out-parameter,
                    // and `pid` is a child of this process.
                    let rc = unsafe { libc::waitpid(pid, &raw mut status, 0) };
                    let status = if rc < 0 { 0 } else { status };
                    let mut payload = Vec::new();
                    payload.push(OP_EXITED);
                    put_i64(&mut payload, i64::from(pid));
                    put_i32(&mut payload, status);
                    let mut framed = Vec::new();
                    put_u32(&mut framed, u32::try_from(payload.len()).unwrap());
                    framed.extend_from_slice(&payload);
                    let _guard = send_lock.lock().unwrap();
                    let _ = send_with_fds(socket, &framed, &[]);
                });
            }
            Err(HostProcessError::Host(err)) => {
                close_fd(spec_pipe[1]);
                let _ = reply_spawned(socket, &send_lock, request_id, -1, err);
            }
            Err(_) => {
                close_fd(spec_pipe[1]);
                let _ = reply_spawned(socket, &send_lock, request_id, -1, libc::EINVAL);
            }
        }
    }
    std::process::exit(0)
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn reply_spawned(
    socket: c_int,
    send_lock: &Mutex<()>,
    request_id: u64,
    pid: i64,
    err: i32,
) -> Result<(), HostProcessError> {
    let mut payload = Vec::new();
    payload.push(OP_SPAWNED);
    put_u64(&mut payload, request_id);
    put_i64(&mut payload, pid);
    put_i32(&mut payload, err);
    let mut framed = Vec::new();
    put_u32(&mut framed, u32::try_from(payload.len()).unwrap());
    framed.extend_from_slice(&payload);
    let _guard = send_lock.lock().unwrap();
    send_with_fds(socket, &framed, &[])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The wire form has to survive arguments a Linux guest is allowed to have
    /// and a host command line is not: non-UTF-8 bytes and embedded spaces.
    /// This is the reason the spec travels down a pipe instead of as `argv`.
    #[test]
    fn child_spec_round_trips_non_utf8_arguments() {
        let spec = ChildSpec {
            initial_files: b"/tmp/litebox-demo/alpine.tar".to_vec(),
            program: b"/bin/busybox".to_vec(),
            argv: vec![b"ls".to_vec(), vec![0xff, 0xfe, b' ', b'x'], Vec::new()],
            envp: vec![b"PATH=/bin".to_vec(), vec![b'A', b'=', 0x80]],
        };
        let encoded = spec.encode();
        assert_eq!(ChildSpec::decode(&encoded), Some(spec));
    }

    /// A truncated spec must be reported, not silently half-parsed into a
    /// child that then runs the wrong program.
    #[test]
    fn a_truncated_child_spec_is_rejected() {
        let spec = ChildSpec {
            initial_files: b"/tmp/x.tar".to_vec(),
            program: b"/bin/sh".to_vec(),
            argv: vec![b"sh".to_vec()],
            envp: Vec::new(),
        };
        let encoded = spec.encode();
        for cut in 0..encoded.len() {
            assert_eq!(
                ChildSpec::decode(&encoded[..cut]),
                None,
                "a spec truncated to {cut} bytes must not decode"
            );
        }
        assert!(ChildSpec::decode(&encoded).is_some());
    }

    /// The claim the whole helper design rests on: inside the runner's real
    /// Seatbelt profile a process can still make a pipe and hand it to another
    /// process over an already-open socket, even though it can no longer `exec`
    /// anything itself.
    ///
    /// This runs in a re-executed child, for the same reason
    /// `seatbelt::the_runner_profile_denies_host_access_without_breaking_jit_or_hwcap`
    /// does: the sandbox is process-wide and irreversible.
    #[test]
    fn scm_rights_and_pipes_still_work_inside_the_runner_jail() {
        const CHILD_VAR: &str = "LITEBOX_HOSTPROC_SELFTEST_CHILD";
        const TEST_NAME: &str =
            "hostproc::tests::scm_rights_and_pipes_still_work_inside_the_runner_jail";
        if std::env::var_os(CHILD_VAR).is_none() {
            let exe = std::env::current_exe().expect("the test binary has a path");
            let output = std::process::Command::new(&exe)
                .args(["--exact", "--nocapture", "--test-threads=1", TEST_NAME])
                .env(CHILD_VAR, "1")
                .output()
                .expect("re-executing the test binary");
            assert!(
                output.status.success(),
                "jailed child failed.\n--- stdout ---\n{}\n--- stderr ---\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            );
            assert!(
                String::from_utf8_lossy(&output.stdout).contains("hostproc-selftest: ok"),
                "jailed child did not reach its verdict line",
            );
            return;
        }

        // The helper stand-in, started *before* the jail goes up, exactly as the
        // real runner starts its spawn helper before `enable_seatbelt_sandbox`.
        let mut sv = [0 as c_int; 2];
        // SAFETY: `sv` is a live, uniquely owned two-element out-parameter.
        assert_eq!(
            unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sv.as_mut_ptr()) },
            0
        );
        let peer = sv[1];
        let reader = std::thread::spawn(move || {
            let (body, fds) = recv_message(peer)
                .expect("helper stand-in reads a message")
                .expect("the message is not an EOF");
            assert_eq!(body, b"litebox");
            assert_eq!(fds.len(), 1);
            let msg = b"through-the-passed-fd";
            // SAFETY: `fds[0]` is the pipe write end the jailed side passed.
            let n = unsafe { libc::write(fds[0], msg.as_ptr().cast(), msg.len()) };
            assert_eq!(n, isize::try_from(msg.len()).unwrap());
            close_fd(fds[0]);
        });

        crate::seatbelt::apply_runner_profile_for_test();

        let (read_end, write_end) = create_pipe().expect("pipe(2) must still work inside the jail");
        let mut framed = Vec::new();
        put_u32(&mut framed, 7);
        framed.extend_from_slice(b"litebox");
        send_with_fds(sv[0], &framed, &[write_end.0])
            .expect("SCM_RIGHTS must still work inside the jail");
        close_host_fd(write_end);
        let mut buf = [0u8; 64];
        let n = read_fd(&read_end, &mut buf).expect("reading the pipe back");
        assert_eq!(&buf[..n], b"through-the-passed-fd");
        close_host_fd(read_end);
        reader.join().expect("the helper stand-in thread");

        // ...and the thing that makes the helper necessary in the first place.
        assert_eq!(
            std::process::Command::new("/bin/echo")
                .output()
                .expect_err("exec must be denied inside the jail")
                .raw_os_error(),
            Some(libc::EPERM),
        );
        println!("hostproc-selftest: ok");
    }
}
