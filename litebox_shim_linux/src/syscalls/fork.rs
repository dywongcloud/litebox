// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! `fork(2)`, `wait4(2)`, and the `execve` that turns a forked child into a real
//! host process.
//!
//! # What this implements, precisely
//!
//! LiteBox runs guest instructions natively, so a guest process is a host
//! address space. A faithful `fork` would therefore need a *second host address
//! space* holding a copy of the first, which no userland API on this host
//! provides without `fork(2)` itself -- and `fork(2)` is unusable here, because
//! the runner is always multithreaded (stdin pump, timer threads, guest threads)
//! and the child of a multithreaded `fork` inherits every lock in whatever state
//! it was, including the allocator's.
//!
//! What this implements instead is the shape of `fork` that shells actually use,
//! `fork`-then-`execve`, with `vfork(2)` memory semantics up to the `execve`:
//!
//! * `fork()` creates a new guest **process** -- new pid, new [`Process`], its
//!   own copy of the file-descriptor table, its own copy of the working
//!   directory and umask, its own copy of the signal dispositions -- running on
//!   a new host thread **in the same address space, on the same guest stack**.
//! * The parent is **suspended** at the `fork` until the child `execve`s or
//!   exits, which is exactly `vfork(2)`'s contract and is what makes sharing one
//!   address space and one stack safe: only one of the two runs at a time, and
//!   the child only ever pushes frames *below* the parent's suspended frame.
//! * When the child `execve`s, the shim does **not** load the new image into
//!   this address space. It asks the platform to start a real host process
//!   running a fresh runner for that program, hands it the child's descriptors,
//!   and lets the parent go. The child's guest task then ends; its exit status
//!   comes from the host process, reported through
//!   [`HostProcessProvider::take_exited_host_process`].
//! * `wait4()` reports both kinds of child: one that exited before `execve`
//!   (whose status the shim recorded itself) and one that became a host process.
//!
//! # What this does NOT implement, and how each failure is made loud
//!
//! * **True per-process memory *while the child runs*.** The child writes into
//!   the parent's address space; what makes that safe for the parent is
//!   [`MemorySnapshot`], which copies the parent's writable memory before the
//!   child starts and puts it back after the child stops. So the parent sees
//!   real `fork` semantics, and the child sees them until it `execve`s -- but a
//!   program that forks in order to *diverge* and keep running, rather than to
//!   `exec`, gets neither. There is no way to detect that from inside, so it is
//!   documented rather than trapped.
//! * **Parent/child concurrency before `execve`.** The parent does not run until
//!   the child `execve`s or exits, so a pipeline whose producer is a shell
//!   *builtin* writing more than one pipe buffer's worth of data before the
//!   consumer is even forked would deadlock. External commands (which `execve`
//!   immediately) are unaffected.
//! * **Inheriting descriptors above 2.** A spawned host process is a fresh
//!   runner, so a descriptor reaches it either as a host descriptor or through
//!   a relay thread, and only descriptors 0, 1 and 2 are set up either way.
//!   `execve` in a forked child that still holds a higher one, or holds a
//!   socket, epoll set or eventfd, **fails with `ENOSYS` and logs an error
//!   naming the descriptor** rather than starting a child that would silently
//!   see the wrong thing. Close-on-exec descriptors are exempt: `execve` closes
//!   them, so they are never the child's to inherit.
//! * **Sharing the parent's writable filesystem.** The spawned runner rebuilds
//!   the guest filesystem from the same tar archive, so writes the parent made
//!   to its in-memory layer are not visible to the child, and files the child
//!   creates are not visible to the parent. A redirection like `cmd > f` does
//!   put `f` in the *forking* process's filesystem, which is where it belongs,
//!   but a later `cat f` runs in a child that cannot see it.
//! * **`SIGCHLD`.** A child's exit does not raise `SIGCHLD` in the parent; the
//!   only way to observe it is `wait4`. That is enough for a foreground command
//!   or a pipeline, where `busybox ash` blocks in `waitpid`, but not for its
//!   `wait` builtin, which arms `SIGCHLD` and blocks in `rt_sigsuspend` -- a
//!   syscall this shim does not implement at all, independently of this module.
//!   `wait` for a background job therefore hangs.
//! * **`fork` on any platform without host-process support**, which is every
//!   platform but macOS: `EINVAL`, as before this module existed.

use alloc::boxed::Box;
use alloc::collections::btree_map::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use litebox::fd::TypedFd;
use litebox::platform::{
    HostFd, HostProcessSpec, RawMutex as _, RawMutexProvider, StdioStream,
};
use litebox_common_linux::{CloneFlags, FileDescriptorFlags, WaitOptions, errno::Errno};

use crate::syscalls::file::FilesState;
use crate::syscalls::process::{ExitStatus, ThreadState};
use crate::{GlobalState, ShimFS, ShimPlatform, Task, UserPtrMut};

/// The `SIGCHLD` a `fork()`ing caller passes as `clone`'s exit signal.
const SIGCHLD: u64 = 17;

/// Buffer size for the descriptor relays. One page is enough to keep a pipeline
/// moving without making each relay thread expensive.
const RELAY_BUFFER: usize = 4096;

/// Granularity at which [`MemorySnapshot`] copies, so that one unreadable page
/// costs one chunk rather than a whole mapping, and so that no single
/// allocation is proportional to a mapping's full size.
const SNAPSHOT_CHUNK: usize = 64 * 1024;

/// Refuse to `fork` rather than copy more than this much guest memory. A guest
/// whose writable footprint is larger than this is not one this mechanism can
/// serve, and saying so is better than stalling on a multi-gigabyte copy.
const SNAPSHOT_LIMIT: usize = 256 * 1024 * 1024;

/// A copy of every writable byte of guest memory the parent can still see at the
/// moment it `fork`s.
///
/// # Why this exists
///
/// The child runs in the parent's address space, on the parent's stack, because
/// there is no second address space to run it in. That is `vfork(2)`, and
/// `vfork`'s contract -- the child must not return from the function that called
/// it -- is one that real programs break. `busybox ash` breaks it: its child
/// path returns out of `forkshell()` and runs a good deal of shell code before
/// `execve`, all of it in stack frames the suspended parent still owns. Measured
/// directly on this host: without this snapshot the parent resumes from `fork`
/// with a clobbered frame and jumps to `pc == 1`.
///
/// Taking a copy before the child starts and putting it back after the child
/// stops turns that into something much closer to real `fork`: the *parent*
/// observes none of the child's writes, which is exactly `fork` semantics, and
/// the child's writes are discarded at the point `execve` would have discarded
/// them anyway.
///
/// What it does not restore is the address-space *layout*: a region the child
/// `mmap`s or `brk`s stays mapped in the parent, and one it `munmap`s stays
/// gone. Failing to restore a range is logged as an error rather than passed
/// over in silence.
struct MemorySnapshot {
    chunks: Vec<(usize, Vec<u8>)>,
}

impl MemorySnapshot {
    /// Copies every writable mapping, except the part of the stack below
    /// `stack_pointer`, which is dead to the parent (it is exactly the region
    /// the child is about to use for its own frames) and would otherwise cost a
    /// full 8 MiB stack reservation on every `fork`.
    fn capture<Platform: ShimPlatform, FS: ShimFS>(
        global: &GlobalState<Platform, FS>,
        stack_pointer: usize,
    ) -> Result<Self, Errno> {
        let mut chunks = Vec::new();
        let mut total = 0usize;
        for (range, flags) in global.pm.mappings() {
            if !flags.contains(litebox::mm::linux::VmFlags::VM_WRITE) {
                continue;
            }
            let start = if range.contains(&stack_pointer) {
                // Round down to a chunk boundary so the parent's own frame is
                // covered whole.
                stack_pointer & !(SNAPSHOT_CHUNK - 1)
            } else {
                range.start
            };
            let mut addr = start;
            while addr < range.end {
                let len = SNAPSHOT_CHUNK.min(range.end - addr);
                total += len;
                if total > SNAPSHOT_LIMIT {
                    litebox_util_log::error!(limit:? = SNAPSHOT_LIMIT;
                        "refusing to fork: the guest's writable memory exceeds the snapshot limit");
                    return Err(Errno::ENOMEM);
                }
                if let Some(bytes) =
                    crate::UserPtr::<u8>::from_usize(addr).to_owned_slice::<Platform>(len)
                {
                    chunks.push((addr, bytes.into_vec()));
                }
                addr += len;
            }
        }
        Ok(Self { chunks })
    }

    /// Total bytes copied, for diagnostics.
    fn bytes(&self) -> usize {
        self.chunks.iter().map(|(_, b)| b.len()).sum()
    }

    /// Puts the parent's memory back the way it was before the child ran.
    fn restore<Platform: ShimPlatform>(&self) {
        for (addr, bytes) in &self.chunks {
            if crate::UserPtrMut::<u8>::from_usize(*addr)
                .copy_from_slice::<Platform>(0, bytes)
                .is_none()
            {
                litebox_util_log::error!(addr:? = *addr, len:? = bytes.len();
                    "could not restore guest memory after fork: the child unmapped it");
            }
        }
    }
}

/// Where a child created by [`Task::do_fork`] currently is.
#[derive(Debug, Clone, Copy)]
pub(crate) enum ChildState {
    /// Still running guest code in this process, before its `execve`.
    InProcess,
    /// Running as a host process with this platform-assigned identifier.
    HostProcess(i64),
    /// Finished; the value is a wait status in `wait4(2)` encoding.
    Exited(i32),
}

/// One child of some guest process in this runner.
#[derive(Debug)]
pub(crate) struct ChildEntry {
    /// Pid of the process that forked it, i.e. who may `wait4` for it.
    parent_pid: i32,
    state: ChildState,
}

/// Every live child of every guest process in this runner, by child pid.
///
/// This is process-wide rather than per-[`Process`] because the platform reports
/// an exited host process by its own identifier, with no idea which guest parent
/// was waiting for it; keeping one table means that report can be routed with a
/// single lookup.
#[derive(Debug, Default)]
pub(crate) struct ChildTable {
    entries: BTreeMap<i32, ChildEntry>,
}

impl ChildTable {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    fn insert(&mut self, child_pid: i32, parent_pid: i32) {
        let previous = self.entries.insert(
            child_pid,
            ChildEntry {
                parent_pid,
                state: ChildState::InProcess,
            },
        );
        assert!(previous.is_none(), "child pid {child_pid} reused");
    }

    fn set_state(&mut self, child_pid: i32, state: ChildState) {
        if let Some(entry) = self.entries.get_mut(&child_pid) {
            entry.state = state;
        }
    }

    /// Records that a child exited *before* it ever became a host process. A
    /// child that already `execve`d keeps the host process's status instead.
    fn record_in_process_exit(&mut self, child_pid: i32, status: i32) -> bool {
        match self.entries.get_mut(&child_pid) {
            Some(entry @ ChildEntry {
                state: ChildState::InProcess,
                ..
            }) => {
                entry.state = ChildState::Exited(status);
                true
            }
            _ => false,
        }
    }

    /// Routes a platform exit report to whichever child became that host process.
    fn record_host_exit(&mut self, host_id: i64, status: i32) {
        for entry in self.entries.values_mut() {
            if matches!(entry.state, ChildState::HostProcess(id) if id == host_id) {
                entry.state = ChildState::Exited(status);
                return;
            }
        }
    }

    /// Whether `parent_pid` has any child matching the `wait4` pid selector.
    fn has_child(&self, parent_pid: i32, selector: i32) -> bool {
        self.entries
            .iter()
            .any(|(pid, e)| e.parent_pid == parent_pid && (selector == -1 || selector == *pid))
    }

    /// Removes and returns one exited child of `parent_pid` matching `selector`.
    fn take_exited(&mut self, parent_pid: i32, selector: i32) -> Option<(i32, i32)> {
        let found = self.entries.iter().find_map(|(pid, e)| {
            match e.state {
                ChildState::Exited(status)
                    if e.parent_pid == parent_pid && (selector == -1 || selector == *pid) =>
                {
                    Some((*pid, status))
                }
                _ => None,
            }
        })?;
        self.entries.remove(&found.0);
        Some(found)
    }
}

/// The `vfork`-style gate a forked child uses to release its suspended parent.
///
/// The parent blocks on it immediately after the child is spawned; the child
/// opens it exactly once, at `execve` or at exit, whichever comes first.
pub(crate) struct ForkGate<Platform: ShimPlatform> {
    word: <Platform as RawMutexProvider>::RawMutex,
}

impl<Platform: ShimPlatform> ForkGate<Platform> {
    fn new() -> Self {
        Self {
            word: <Platform as RawMutexProvider>::RawMutex::INIT,
        }
    }

    /// Lets the parent continue. Idempotent: `execve` opens the gate and the
    /// child's subsequent exit path harmlessly opens it again.
    pub(crate) fn open(&self) {
        self.word.underlying_atomic().store(1, Ordering::Release);
        self.word.wake_all();
    }

    fn wait(&self) {
        while self.word.underlying_atomic().load(Ordering::Acquire) == 0 {
            let _ = self.word.block(0);
        }
    }
}

/// Encodes a normal exit the way `wait4(2)` reports it.
fn exited_status(code: i32) -> i32 {
    (code & 0xff) << 8
}

/// Encodes a death by signal the way `wait4(2)` reports it.
fn signaled_status(signal: i32) -> i32 {
    signal & 0x7f
}

pub(crate) fn wait_status_for(status: ExitStatus) -> i32 {
    match status {
        ExitStatus::Exit(code) => exited_status(i32::from(code)),
        ExitStatus::Signal(signal) => signaled_status(signal.as_i32()),
    }
}

impl<Platform: ShimPlatform, FS: ShimFS> Task<Platform, FS> {
    /// Whether this task is a child created by [`Self::do_fork`], as opposed to
    /// the runner's initial task or a `clone`d thread of it.
    pub(crate) fn is_forked_child(&self) -> bool {
        self.forked.is_some()
    }

    /// `fork(2)`: the `clone` path that creates a process rather than a thread.
    ///
    /// See the module docs for the semantics this does and does not provide.
    pub(crate) fn do_fork(
        &self,
        ctx: &litebox_common_linux::PtRegs,
        args: &litebox_common_linux::CloneArgs,
    ) -> Result<usize, Errno> {
        if !self.global.platform.supports_host_processes() {
            log_unsupported!("fork on a platform with no host-process support");
            return Err(Errno::EINVAL);
        }
        // `fork()` and `vfork()` are the two shapes accepted. Anything else --
        // a partial-sharing `clone` -- is refused rather than silently given
        // full-copy semantics it did not ask for.
        let accepted = CloneFlags::VFORK | CloneFlags::VM;
        if args.flags.intersects(!accepted) {
            log_unsupported!(
                "fork-like clone with unsupported flags: {:?}",
                args.flags & !accepted
            );
            return Err(Errno::EINVAL);
        }
        if args.exit_signal != SIGCHLD {
            log_unsupported!("fork-like clone with exit signal {}", args.exit_signal);
            return Err(Errno::EINVAL);
        }
        if args.stack != 0 || args.set_tid != 0 || args.cgroup != 0 {
            log_unsupported!("fork-like clone with a stack, set_tid or cgroup");
            return Err(Errno::EINVAL);
        }

        // Take the snapshot before anything else can run: from here to
        // `gate.wait()` below, only this thread touches guest memory.
        let snapshot = MemorySnapshot::capture(&self.global, guest_stack_pointer(ctx))?;

        let child_pid = self.global.next_pid.fetch_add(1, Ordering::Relaxed);
        let files = self.clone_files_for_fork()?;
        let fs = Arc::new((**self.fs.borrow()).clone());
        let gate = Arc::new(ForkGate::new());

        self.global.children.lock().insert(child_pid, self.pid);

        let child = Task {
            global: self.global.clone(),
            wait_state: crate::wait::WaitState::new(self.global.platform),
            thread: ThreadState::new_process(child_pid),
            pid: child_pid,
            tid: child_pid,
            ppid: self.pid,
            credentials: core::cell::RefCell::new(self.credentials.borrow().clone()),
            comm: self.comm.clone(),
            fs: fs.into(),
            files: files.into(),
            signals: self.signals.clone_for_new_process(),
            forked: Some(gate.clone()),
        };
        // The child resumes at the same `pc` and on the same `sp` as the parent
        // with `x0 == 0`: `NewThread` with no stack override is exactly that.
        //
        // The thread pointer has to be carried across by hand. The platform
        // keeps the guest's `TPIDR_EL0`/`FS.base` per *host* thread, and the
        // child is a new host thread, so without this it would start with a null
        // thread pointer -- and a libc that reaches through it (musl's
        // `pthread_self`, and therefore `errno`) dereferences a small negative
        // offset from zero and takes a `SIGSEGV` on its first step. `fork(2)`
        // inherits the thread pointer, so copy the parent's.
        let tls = self
            .global
            .platform
            .get_arch_specific_register(&crate::syscalls::process::GUEST_TLS_REGISTER)
            .ok()
            .filter(|tp| *tp != 0)
            .map(UserPtrMut::<u8>::from_usize);
        child.thread.set_new_thread_init_state(None, tls, None);

        // SAFETY: `ctx` is the parent's live syscall context, which is what the
        // platform copies into the new thread, exactly as `do_clone` does.
        let spawned = unsafe {
            self.global.platform.spawn_thread(
                ctx,
                Box::new(crate::syscalls::process::new_thread_args(child)),
            )
        };
        if let Err(err) = spawned {
            litebox_util_log::error!(err:% = err; "failed to spawn a forked child task");
            self.global.children.lock().entries.remove(&child_pid);
            return Err(Errno::ENOMEM);
        }

        // `vfork` semantics: the child has the address space to itself until it
        // `execve`s or exits. It has stopped touching guest memory by the time
        // the gate opens, so undoing its writes here is race-free.
        gate.wait();
        snapshot.restore::<Platform>();
        litebox_util_log::debug!(
            parent:? = self.pid, child:? = child_pid, bytes:? = snapshot.bytes();
            "fork: child released the parent and its memory writes were undone"
        );
        Ok(usize::try_from(child_pid).unwrap())
    }

    /// Duplicates this task's descriptor table for a forked child, so that the
    /// child's `dup2`/`close` dance before `execve` cannot touch the parent's.
    fn clone_files_for_fork(&self) -> Result<Arc<FilesState<Platform, FS>>, Errno> {
        fn dup_into<Platform: ShimPlatform, FS: ShimFS, S: litebox::fd::FdEnabledSubsystem>(
            global: &GlobalState<Platform, FS>,
            destination: &FilesState<Platform, FS>,
            raw_fd: usize,
            fd: &TypedFd<S>,
            close_on_exec: bool,
        ) -> Result<(), Errno> {
            let mut dt = global.litebox.descriptor_table_mut();
            let copy: TypedFd<S> = dt.duplicate(fd).ok_or(Errno::EBADF)?;
            if close_on_exec {
                let old = dt.set_fd_metadata(&copy, FileDescriptorFlags::FD_CLOEXEC);
                assert!(old.is_none());
            }
            drop(dt);
            let placed = destination
                .raw_descriptor_store
                .write()
                .fd_into_specific_raw_integer(copy, raw_fd);
            assert!(placed, "the child's table is empty at {raw_fd}");
            Ok(())
        }

        let files = self.files.borrow();
        let destination = FilesState::new(files.fs.clone());
        destination.set_max_fd(crate::syscalls::process::RLIMIT_NOFILE_CUR - 1);
        let alive: Vec<usize> = files.raw_descriptor_store.read().iter_alive().collect();
        for raw_fd in alive {
            let close_on_exec =
                crate::syscalls::file::get_file_descriptor_flags(raw_fd, &self.global, &files)
                    .is_ok_and(|f| f.contains(FileDescriptorFlags::FD_CLOEXEC));
            files.run_on_raw_fd(
                raw_fd,
                |fd| dup_into(&self.global, &destination, raw_fd, fd, close_on_exec),
                |fd| dup_into(&self.global, &destination, raw_fd, fd, close_on_exec),
                |fd| dup_into(&self.global, &destination, raw_fd, fd, close_on_exec),
                |fd| dup_into(&self.global, &destination, raw_fd, fd, close_on_exec),
                |fd| dup_into(&self.global, &destination, raw_fd, fd, close_on_exec),
                |fd| dup_into(&self.global, &destination, raw_fd, fd, close_on_exec),
            )??;
        }
        Ok(Arc::new(destination))
    }

    /// The `execve` of a forked child: start a real host process instead of
    /// loading the new image into the shared address space.
    ///
    /// On success this never returns to guest code -- the calling task is marked
    /// exiting, so the shim tears the thread down on its way out.
    pub(crate) fn spawn_execve(
        &self,
        path: &str,
        argv: Vec<alloc::ffi::CString>,
        envp: Vec<alloc::ffi::CString>,
    ) -> Result<usize, Errno> {
        // Report a missing or unreadable program the way a real `execve` would,
        // *before* anything irreversible happens, so the shell prints its own
        // "not found" rather than a child mysteriously failing later.
        let probe = self.do_open(path, litebox::fs::OFlags::RDONLY, litebox::fs::Mode::empty())?;
        let _ = self.files.borrow().fs.close(&probe);

        // Work out the child's descriptors *before* touching anything. A failed
        // `execve` has to leave the calling process exactly as it was -- that is
        // what lets a shell print "not found" and carry on -- so nothing here
        // may mutate state until the spawn is known to be possible.
        let fds = self.export_fds_for_spawn()?;

        // Past this point the call is committed: `execve` closes close-on-exec
        // descriptors.
        self.close_on_exec();

        let argv_bytes: Vec<&[u8]> = argv.iter().map(alloc::ffi::CString::as_bytes).collect();
        let envp_bytes: Vec<&[u8]> = envp.iter().map(alloc::ffi::CString::as_bytes).collect();
        let spec = HostProcessSpec {
            program: path,
            argv: &argv_bytes,
            envp: &envp_bytes,
            fds: &fds,
        };
        let host_id = self
            .global
            .platform
            .spawn_host_process(&spec)
            .map_err(|err| {
                litebox_util_log::error!(err:% = err, program:% = path; "could not spawn a host process for execve");
                Errno::ENOMEM
            })?;

        self.global
            .children
            .lock()
            .set_state(self.pid, ChildState::HostProcess(host_id));
        litebox_util_log::debug!(
            child:? = self.pid, host:? = host_id, program:% = path;
            "fork: a forked child became a host process"
        );

        // The image is running elsewhere now, so this task is done: stop.
        // `exit_group` marks the task exiting, which makes
        // `prepare_to_run_guest` tear the thread down instead of resuming guest
        // code in an address space this process no longer owns a program in.
        //
        // The parent is *not* released here. It is released from the teardown
        // path (`finish_forked_child`), which is the last thing this task does
        // and the first moment at which it is guaranteed to touch no more guest
        // memory -- signal delivery on the way out of this syscall would
        // otherwise still write a frame to the shared guest stack while the
        // parent was already restoring it.
        self.exit_group(ExitStatus::Exit(0));
        Ok(0)
    }

    /// Turns this task's descriptor table into host descriptors for a spawned
    /// child, failing loudly on anything that cannot be represented as one.
    ///
    /// Close-on-exec descriptors are skipped rather than rejected: a real
    /// `execve` closes them, so they are not the child's to inherit. That is why
    /// `busybox ash`'s saved script descriptor -- which it marks close-on-exec
    /// precisely so children do not see it -- does not make every `execve` fail.
    fn export_fds_for_spawn(&self) -> Result<Vec<(i32, HostFd)>, Errno> {
        let files = self.files.borrow();
        let alive: Vec<usize> = files
            .raw_descriptor_store
            .read()
            .iter_alive()
            .filter(|raw_fd| {
                !crate::syscalls::file::get_file_descriptor_flags(*raw_fd, &self.global, &files)
                    .is_ok_and(|f| f.contains(FileDescriptorFlags::FD_CLOEXEC))
            })
            .collect();
        let mut exported: Vec<(i32, HostFd)> = Vec::new();
        let mut result = Ok(());
        for raw_fd in alive {
            if raw_fd > 2 {
                litebox_util_log::error!(fd:? = raw_fd;
                    "cannot hand descriptor to a spawned child: only 0, 1 and 2 can be inherited");
                result = Err(Errno::ENOSYS);
                break;
            }
            let host = files.run_on_raw_fd(
                raw_fd,
                |fd| self.export_file_fd(raw_fd, fd),
                |_| Err(unsupported_export(raw_fd, "socket")),
                |fd| self.export_pipe_fd(fd),
                |_| Err(unsupported_export(raw_fd, "eventfd")),
                |_| Err(unsupported_export(raw_fd, "epoll set")),
                |_| Err(unsupported_export(raw_fd, "unix socket")),
            );
            match host.and_then(|r| r) {
                Ok(host) => exported.push((i32::try_from(raw_fd).unwrap(), host)),
                Err(err) => {
                    result = Err(err);
                    break;
                }
            }
        }
        if let Err(err) = result {
            for (_, fd) in exported {
                self.global.platform.close_host_fd(fd);
            }
            return Err(err);
        }
        Ok(exported)
    }

    /// A filesystem-backed descriptor.
    ///
    /// One of the host's own standard streams is handed over directly, which is
    /// both the common case and the cheap one. Anything else -- a redirection
    /// onto a file, or the `/dev/null` a shell gives a background job -- lives
    /// in the *guest* filesystem, which the spawned process (a fresh runner with
    /// its own filesystem) cannot see, so it is relayed the same way a pipe is.
    fn export_file_fd(&self, raw_fd: usize, fd: &TypedFd<FS>) -> Result<HostFd, Errno> {
        if let Ok(stream) = self
            .global
            .litebox
            .descriptor_table()
            .with_metadata(fd, |stream: &StdioStream| *stream)
        {
            return self
                .global
                .platform
                .duplicate_host_stdio(stream)
                .map_err(|err| {
                    litebox_util_log::error!(err:% = err; "could not duplicate a standard stream");
                    Errno::ENOMEM
                });
        }
        // Direction comes from the descriptor number, which is the whole
        // meaning of the three standard descriptors and the only ones that get
        // here (`export_fds_for_spawn` refuses the rest): 0 is what the child
        // reads, 1 and 2 are what it writes. The alternative -- the open file's
        // access mode -- is not recorded for filesystem descriptors in this
        // shim, so it is not available to consult.
        let relay_fd: TypedFd<FS> = self
            .global
            .litebox
            .descriptor_table_mut()
            .duplicate(fd)
            .ok_or(Errno::EBADF)?;
        let endpoint = RelayEndpoint::File {
            fs: self.files.borrow().fs.clone(),
            fd: relay_fd,
        };
        if raw_fd == 0 {
            self.start_relay(endpoint, RelayDirection::GuestToHost)
        } else {
            self.start_relay(endpoint, RelayDirection::HostToGuest)
        }
    }

    /// Creates the host pipe a spawned child will use for one descriptor, starts
    /// the relay that connects it to `endpoint`, and returns the end the child
    /// gets.
    fn start_relay(
        &self,
        endpoint: RelayEndpoint<Platform, FS>,
        direction: RelayDirection,
    ) -> Result<HostFd, Errno> {
        let (host_read, host_write) = self.global.platform.create_host_pipe().map_err(|err| {
            litebox_util_log::error!(err:% = err; "could not create a host pipe");
            Errno::ENOMEM
        })?;
        let (child_end, relay_end) = match direction {
            // The child writes into the host pipe; the relay drains it.
            RelayDirection::HostToGuest => (host_write, host_read),
            // The child reads from the host pipe; the relay fills it.
            RelayDirection::GuestToHost => (host_read, host_write),
        };
        let relay = Relay {
            global: self.global.clone(),
            host: relay_end,
            endpoint,
            direction,
        };
        match self
            .global
            .platform
            .spawn_host_helper_thread(Box::new(move || relay.run()))
        {
            Ok(()) => Ok(child_end),
            Err(err) => {
                litebox_util_log::error!(err:% = err; "could not start a descriptor relay");
                self.global.platform.close_host_fd(child_end);
                Err(Errno::ENOMEM)
            }
        }
    }

    /// A pipe end becomes a real host pipe plus a relay thread that shuttles
    /// bytes between it and the shim's in-process pipe object, so a pipeline
    /// spanning two host processes works.
    fn export_pipe_fd(&self, fd: &litebox::pipes::PipeFd<Platform>) -> Result<HostFd, Errno> {
        let half = self.global.pipes.half_pipe_type(fd)?;
        // The relay owns its own duplicate of the pipe end, so tearing down this
        // task's table (which happens moments from now) does not close the pipe
        // out from under it.
        let relay_fd: litebox::pipes::PipeFd<Platform> = self
            .global
            .litebox
            .descriptor_table_mut()
            .duplicate(fd)
            .ok_or(Errno::EBADF)?;
        let direction = match half {
            // The child holds the write end, so it writes and the shim reads.
            litebox::pipes::HalfPipeType::SenderHalf => RelayDirection::HostToGuest,
            // The child holds the read end, so it reads and the shim writes.
            litebox::pipes::HalfPipeType::ReceiverHalf => RelayDirection::GuestToHost,
        };
        self.start_relay(RelayEndpoint::Pipe(relay_fd), direction)
    }

    /// Records the exit of a forked child that never reached `execve`, and
    /// releases its parent if it was still suspended in `fork`.
    ///
    /// Called from the task teardown path once the child's last thread is gone,
    /// so the descriptors it held (pipe ends in particular) are already closed
    /// and a waiting parent sees a consistent picture.
    pub(crate) fn finish_forked_child(&self, status: ExitStatus) {
        let Some(gate) = &self.forked else {
            return;
        };
        let recorded = self
            .global
            .children
            .lock()
            .record_in_process_exit(self.pid, wait_status_for(status));
        litebox_util_log::debug!(
            child:? = self.pid, status:? = status, recorded:? = recorded;
            "fork: a forked child's task finished"
        );
        gate.open();
        if recorded {
            // Wake `wait4`, which blocks on the same generation counter the
            // platform bumps when a spawned host process exits.
            self.global.platform.notify_host_process_event();
        }
    }

    /// `wait4(2)`.
    ///
    /// Blocking here is not interruptible by a guest signal: the wait is on the
    /// platform's host-process event counter rather than on the shim's
    /// interruptible [`crate::wait::WaitState`]. A guest that expects `SIGINT`
    /// to break a blocking `wait4` will not see it until the child exits.
    pub(crate) fn sys_wait4(
        &self,
        pid: i32,
        wstatus: UserPtrMut<i32>,
        options: WaitOptions,
        _rusage: UserPtrMut<u8>,
    ) -> Result<usize, Errno> {
        if pid == 0 || pid < -1 {
            log_unsupported!("wait4 for a process group");
            return Err(Errno::EINVAL);
        }
        if options.intersects(WaitOptions::WUNTRACED | WaitOptions::WCONTINUED) {
            // Nothing in this shim ever stops or continues a child, so these
            // would silently never fire; say so instead.
            log_unsupported!("wait4 with WUNTRACED/WCONTINUED");
        }
        if options.contains(WaitOptions::WNOWAIT) {
            log_unsupported!("wait4 with WNOWAIT");
            return Err(Errno::EINVAL);
        }

        loop {
            // Read the generation *before* looking, so an exit that lands
            // between the look and the block still unblocks us.
            let generation = self.global.platform.host_process_event_generation();
            while let Some((host_id, status)) =
                self.global.platform.take_exited_host_process()
            {
                self.global.children.lock().record_host_exit(host_id, status);
            }
            {
                let mut children = self.global.children.lock();
                litebox_util_log::debug!(
                    waiter:? = self.pid, selector:? = pid, options:? = options.bits(),
                    generation:? = generation, table:? = &*children;
                    "wait4: looking for an exited child"
                );
                if let Some((child_pid, status)) = children.take_exited(self.pid, pid) {
                    drop(children);
                    if wstatus.as_usize() != 0 {
                        wstatus
                            .write_at_offset::<Platform>(0, status)
                            .ok_or(Errno::EFAULT)?;
                    }
                    return Ok(usize::try_from(child_pid).unwrap());
                }
                if !children.has_child(self.pid, pid) {
                    return Err(Errno::ECHILD);
                }
            }
            if options.contains(WaitOptions::WNOHANG) {
                return Ok(0);
            }
            self.global
                .platform
                .block_on_host_process_event(generation);
        }
    }
}

/// The guest stack pointer recorded in a syscall context.
fn guest_stack_pointer(ctx: &litebox_common_linux::PtRegs) -> usize {
    #[cfg(target_arch = "x86_64")]
    {
        ctx.rsp
    }
    #[cfg(target_arch = "aarch64")]
    {
        ctx.sp
    }
}

fn unsupported_export(raw_fd: usize, kind: &str) -> Errno {
    litebox_util_log::error!(fd:? = raw_fd, kind:% = kind;
        "cannot hand descriptor to a spawned child: unsupported descriptor kind");
    Errno::ENOSYS
}

/// Which way a [`Relay`] copies.
enum RelayDirection {
    /// The spawned child writes into the host pipe; copy what arrives into the
    /// guest-side object.
    HostToGuest,
    /// The spawned child reads from the host pipe; copy the guest-side object
    /// into it.
    GuestToHost,
}

/// The guest-side end of a [`Relay`]: whatever the descriptor really was in the
/// forking process.
enum RelayEndpoint<Platform: ShimPlatform, FS: ShimFS> {
    /// A shim pipe end, which is what makes `a | b` work across two host
    /// processes.
    Pipe(litebox::pipes::PipeFd<Platform>),
    /// A file or device in the guest filesystem, which is what makes `> file`
    /// and a background job's `/dev/null` work.
    File { fs: Arc<FS>, fd: TypedFd<FS> },
}

/// Connects one host pipe end to one guest-side descriptor, on its own host
/// thread.
///
/// A spawned child is a separate host process, so the only descriptors it can
/// be handed are host descriptors. Everything the guest opened lives inside
/// this process instead, so the child gets a real host pipe and this thread
/// copies between the two ends. That costs a copy and a thread per redirected
/// descriptor, and it is why a pipeline works at all here.
struct Relay<Platform: ShimPlatform, FS: ShimFS> {
    global: Arc<GlobalState<Platform, FS>>,
    host: HostFd,
    endpoint: RelayEndpoint<Platform, FS>,
    direction: RelayDirection,
}

impl<Platform: ShimPlatform, FS: ShimFS> Relay<Platform, FS> {
    fn run(self) {
        let Self {
            global,
            host,
            endpoint,
            direction,
        } = self;
        // A relay is not a guest task, so it gets its own wait state rather than
        // borrowing one; nothing can interrupt it but end of file.
        let wait_state = litebox::event::wait::WaitState::new(global.platform);
        let cx = wait_state.context();
        let mut buf = [0u8; RELAY_BUFFER];
        loop {
            let filled = match direction {
                RelayDirection::HostToGuest => global
                    .platform
                    .read_host_fd(&host, &mut buf)
                    .unwrap_or_default(),
                RelayDirection::GuestToHost => match &endpoint {
                    RelayEndpoint::Pipe(pipe) => {
                        global.read_linux_pipe(&cx, pipe, &mut buf).unwrap_or(0)
                    }
                    RelayEndpoint::File { fs, fd } => fs.read(fd, &mut buf, None).unwrap_or(0),
                },
            };
            if filled == 0 {
                break;
            }
            let mut written = 0;
            while written < filled {
                let chunk = &buf[written..filled];
                let wrote = match direction {
                    RelayDirection::HostToGuest => match &endpoint {
                        RelayEndpoint::Pipe(pipe) => {
                            global.write_linux_pipe(&cx, pipe, chunk).unwrap_or(0)
                        }
                        RelayEndpoint::File { fs, fd } => fs.write(fd, chunk, None).unwrap_or(0),
                    },
                    RelayDirection::GuestToHost => {
                        global.platform.write_host_fd(&host, chunk).unwrap_or(0)
                    }
                };
                if wrote == 0 {
                    break;
                }
                written += wrote;
            }
            if written < filled {
                // The far side went away mid-transfer; there is nowhere left to
                // put the rest.
                break;
            }
        }
        // Closing both ends is what propagates end of file onwards: a shim pipe's
        // peer sees the write end go away, and the spawned child sees its host
        // pipe close.
        match endpoint {
            RelayEndpoint::Pipe(pipe) => {
                let _ = global.close_linux_pipe(&pipe);
            }
            RelayEndpoint::File { fs, fd } => {
                let _ = fs.close(&fd);
            }
        }
        global.platform.close_host_fd(host);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::syscalls::tests::init_platform;

    /// A `clone` that asks for a new process must keep failing with `EINVAL` on
    /// a platform that cannot start host processes -- which is every platform
    /// but macOS. This is the pre-existing behavior, and the one thing this
    /// module must not change for them.
    #[test]
    fn fork_is_refused_when_the_platform_cannot_spawn_host_processes() {
        let task = init_platform(None);
        assert!(
            !litebox::platform::HostProcessProvider::supports_host_processes(task.global.platform),
            "the test platform must not claim host-process support"
        );
        let args = litebox_common_linux::CloneArgs {
            // What musl's `fork()` issues on aarch64: `clone(SIGCHLD, 0)`.
            flags: CloneFlags::empty(),
            pidfd: 0,
            child_tid: 0,
            parent_tid: 0,
            exit_signal: SIGCHLD,
            stack: 0,
            stack_size: 0,
            tls: 0,
            set_tid: 0,
            set_tid_size: 0,
            cgroup: 0,
        };
        assert_eq!(
            task.sys_clone(&litebox_common_linux::PtRegs::default(), &args),
            Err(Errno::EINVAL)
        );
    }

    /// `wait4` has to say `ECHILD` when the caller has no children at all,
    /// rather than blocking forever: that is what tells a shell its job list is
    /// empty.
    #[test]
    fn wait4_reports_echild_with_no_children() {
        let task = init_platform(None);
        let mut status = 0i32;
        assert_eq!(
            task.sys_wait4(
                -1,
                UserPtrMut::from_ptr(&raw mut status),
                WaitOptions::empty(),
                UserPtrMut::from_usize(0),
            ),
            Err(Errno::ECHILD)
        );
        // ...including the non-blocking form, and for a specific pid.
        assert_eq!(
            task.sys_wait4(
                1234,
                UserPtrMut::from_usize(0),
                WaitOptions::WNOHANG,
                UserPtrMut::from_usize(0),
            ),
            Err(Errno::ECHILD)
        );
    }

    /// The pid selector forms this shim does not model must be refused rather
    /// than quietly treated as "any child".
    #[test]
    fn wait4_refuses_process_group_selectors() {
        let task = init_platform(None);
        for selector in [0, -2, -100] {
            assert_eq!(
                task.sys_wait4(
                    selector,
                    UserPtrMut::from_usize(0),
                    WaitOptions::empty(),
                    UserPtrMut::from_usize(0),
                ),
                Err(Errno::EINVAL),
                "wait4({selector}) must be refused"
            );
        }
    }

    /// `wait4` statuses are what the guest's `WIFEXITED`/`WEXITSTATUS` macros
    /// decode, so the encoding has to match Linux's exactly.
    #[test]
    fn wait_statuses_match_the_linux_encoding() {
        // WIFEXITED(s) is (s & 0x7f) == 0, WEXITSTATUS(s) is (s >> 8) & 0xff.
        let status = exited_status(0);
        assert_eq!(status & 0x7f, 0);
        assert_eq!((status >> 8) & 0xff, 0);
        let status = exited_status(42);
        assert_eq!(status & 0x7f, 0);
        assert_eq!((status >> 8) & 0xff, 42);
        // A `wait4` status only carries the low 8 bits of an exit code.
        assert_eq!((exited_status(0x1_2a) >> 8) & 0xff, 0x2a);
        // WIFSIGNALED(s) is ((s & 0x7f) + 1) >> 1 > 0, WTERMSIG(s) is s & 0x7f.
        let status = signaled_status(9);
        assert_eq!(status & 0x7f, 9);
        assert!(((status & 0x7f) + 1) >> 1 > 0);
    }

    /// The table has to keep two parents' children apart, and must not let a
    /// `wait4(-1)` in one process reap another process's child.
    #[test]
    fn the_child_table_routes_by_parent_and_selector() {
        let mut table = ChildTable::new();
        table.insert(10, 1);
        table.insert(11, 1);
        table.insert(12, 2);
        assert!(table.has_child(1, -1));
        assert!(table.has_child(1, 11));
        assert!(!table.has_child(1, 12));
        assert!(!table.has_child(3, -1));

        assert_eq!(table.take_exited(1, -1), None);
        assert!(table.record_in_process_exit(11, exited_status(3)));
        assert_eq!(table.take_exited(2, -1), None, "not this parent's child");
        assert_eq!(table.take_exited(1, 10), None, "not the selected child");
        assert_eq!(table.take_exited(1, -1), Some((11, exited_status(3))));
        assert_eq!(table.take_exited(1, -1), None, "already reaped");
        assert!(!table.has_child(1, 11));
    }

    /// A child that has already become a host process must take its status from
    /// that process, not from the guest task that spawned it and then exited.
    #[test]
    fn a_spawned_childs_status_comes_from_its_host_process() {
        let mut table = ChildTable::new();
        table.insert(10, 1);
        table.set_state(10, ChildState::HostProcess(4242));
        assert!(
            !table.record_in_process_exit(10, exited_status(0)),
            "the guest task's own exit must not overwrite a spawned child's status"
        );
        table.record_host_exit(9999, exited_status(1));
        assert_eq!(table.take_exited(1, -1), None, "wrong host identifier");
        table.record_host_exit(4242, exited_status(7));
        assert_eq!(table.take_exited(1, -1), Some((10, exited_status(7))));
    }
}
