// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! A shim that provides a Linux-compatible ABI via LiteBox.
//!
//! This shim is generic over the choice of [LiteBox platform](../litebox/platform/index.html).
//! The concrete platform is threaded in by the runner via [`LinuxShimBuilder::new`].

#![no_std]
#![expect(
    clippy::unused_self,
    reason = "by convention, syscalls and related methods take &self even if unused"
)]

extern crate alloc;

use alloc::borrow::Cow;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use core::cell::{Cell, RefCell};
use litebox::{
    LiteBox,
    fd::TypedFd,
    mm::{PageManager, linux::PAGE_SIZE},
    net::Network,
    pipes::Pipes,
    platform::TimeProvider,
    shim::ContinueOperation,
    sync::futex::FutexManager,
    utils::{ReinterpretSignedExt as _, ReinterpretUnsignedExt as _},
};
use litebox_common_linux::{
    SyscallRequest,
    errno::Errno,
    user_pointers::{UserPtr, UserPtrMut},
};

/// On debug builds, logs that the user attempted to use an unsupported feature.
// DEVNOTE: this is before the `mod` declarations so that it can be used within them.
macro_rules! log_unsupported {
    ($($arg:tt)*) => {
        $crate::log_unsupported_fmt(core::format_args!($($arg)*));
    };
}

pub(crate) mod channel;
pub mod loader;
pub(crate) mod stdio;
pub mod syscalls;
pub mod transport;
pub mod vsock_transport;
mod wait;

use crate::syscalls::file::get_file_descriptor_flags;

pub type DefaultFS<Platform> = LinuxFS<Platform>;

pub(crate) type LinuxFS<Platform> = litebox::fs::layered::FileSystem<
    Platform,
    litebox::fs::in_mem::FileSystem<Platform>,
    litebox::fs::layered::FileSystem<
        Platform,
        litebox::fs::resolver::Resolver<Platform, litebox::fs::composer::Composer>,
        litebox::fs::resolver::Resolver<Platform, litebox::fs::composer::Composer>,
    >,
>;

pub(crate) type FileFd<FS> = litebox::fd::TypedFd<FS>;

/// A trait required for file systems to be used in the shim.
pub trait ShimFS: litebox::fs::FileSystem + Send + Sync + 'static {}
impl<T: litebox::fs::FileSystem + Send + Sync + 'static> ShimFS for T {}

/// Aggregate bound capturing everything the shim requires of a platform.
///
/// This exists so that the (many) `impl` blocks throughout the shim can be written
/// as `impl<Platform: ShimPlatform, ..>` rather than repeating a large `where` clause.
pub trait ShimPlatform:
    litebox::platform::RawPointerProvider
    + litebox::platform::TimeProvider
    + litebox::platform::PageManagementProvider<{ PAGE_SIZE }>
    + litebox::mm::linux::VmemPageFaultHandler
    + litebox::platform::RawMutexProvider
    + litebox::sync::RawSyncPrimitivesProvider
    + litebox::platform::CrngProvider
    + litebox::platform::SystemInfoProvider
    + litebox::platform::StdioProvider
    + litebox::platform::ArchSpecificProvider
    + litebox::platform::ThreadProvider<ExecutionContext = litebox_common_linux::PtRegs>
    + litebox::platform::TimerProvider<Signal = litebox_common_linux::signal::Signal>
    + litebox::platform::SignalProvider<Signal = litebox_common_linux::signal::Signal>
    + litebox::platform::IPInterfaceProvider
    + 'static
{
}

impl<T> ShimPlatform for T where
    T: litebox::platform::RawPointerProvider
        + litebox::platform::TimeProvider
        + litebox::platform::PageManagementProvider<{ PAGE_SIZE }>
        + litebox::mm::linux::VmemPageFaultHandler
        + litebox::platform::RawMutexProvider
        + litebox::sync::RawSyncPrimitivesProvider
        + litebox::platform::CrngProvider
        + litebox::platform::SystemInfoProvider
        + litebox::platform::StdioProvider
        + litebox::platform::ArchSpecificProvider
        + litebox::platform::ThreadProvider<ExecutionContext = litebox_common_linux::PtRegs>
        + litebox::platform::TimerProvider<Signal = litebox_common_linux::signal::Signal>
        + litebox::platform::SignalProvider<Signal = litebox_common_linux::signal::Signal>
        + litebox::platform::IPInterfaceProvider
        + 'static
{
}

/// On debug builds, logs that the user attempted to use an unsupported feature.
fn log_unsupported_fmt(args: core::fmt::Arguments<'_>) {
    if cfg!(debug_assertions) {
        litebox_util_log::warn!(feature:% = args; "unsupported");
    }
}

#[cfg(target_pointer_width = "64")]
fn preadv_pwritev_offset(pos_l: usize, _pos_h: usize) -> i64 {
    pos_l.reinterpret_as_signed() as i64
}

#[cfg(target_pointer_width = "32")]
fn preadv_pwritev_offset(pos_l: usize, pos_h: usize) -> i64 {
    ((pos_h as u64) << 32 | pos_l as u64).reinterpret_as_signed()
}

pub struct LinuxShimEntrypoints<Platform: ShimPlatform, FS: ShimFS> {
    task: Task<Platform, FS>,
    // The task should not be moved once it's bound to a platform thread so that
    // we preserve the ability to use TLS in the future.
    _not_send: core::marker::PhantomData<*const ()>,
}

/// Decodes a host exception into the pair the memory manager needs to service a
/// demand fault -- the faulting address and the architecture's raw fault status
/// word -- or `None` when the exception is not a memory fault at all.
///
/// x86-64 reports the address in `CR2` and the status in the hardware error
/// code; aarch64 reports them in `FAR_EL1` and `ESR_EL1`. Both are opaque here:
/// the platform's [`VmemPageFaultHandler`](litebox::mm::linux::VmemPageFaultHandler)
/// is what decodes the status word.
#[cfg(target_arch = "x86_64")]
fn page_fault_info(info: &litebox::shim::ExceptionInfo) -> Option<(usize, u64)> {
    (info.exception == litebox::shim::Exception::PAGE_FAULT)
        .then(|| (info.cr2, u64::from(info.error_code)))
}

#[cfg(target_arch = "aarch64")]
fn page_fault_info(info: &litebox::shim::ExceptionInfo) -> Option<(usize, u64)> {
    use litebox::shim::Exception;

    // Both abort classes are memory faults; the current-EL variants are the
    // ones raised by LiteBox's own accesses to guest memory.
    let is_abort = matches!(
        info.exception,
        Exception::DATA_ABORT_CURRENT_EL
            | Exception::DATA_ABORT_LOWER_EL
            | Exception::INSTRUCTION_ABORT_CURRENT_EL
            | Exception::INSTRUCTION_ABORT_LOWER_EL
    );
    is_abort.then_some((info.fault_address, info.esr))
}

impl<Platform: ShimPlatform, FS: ShimFS> litebox::shim::EnterShim
    for LinuxShimEntrypoints<Platform, FS>
{
    type ExecutionContext = litebox_common_linux::PtRegs;

    fn init(&self, ctx: &mut Self::ExecutionContext) -> ContinueOperation {
        self.enter_shim(true, ctx, Task::handle_init_request)
    }

    fn syscall(&self, ctx: &mut Self::ExecutionContext) -> ContinueOperation {
        self.enter_shim(false, ctx, Task::handle_syscall_request)
    }

    fn exception(
        &self,
        ctx: &mut Self::ExecutionContext,
        info: &litebox::shim::ExceptionInfo,
    ) -> ContinueOperation {
        if info.kernel_mode
            && let Some((fault_address, error_code)) = page_fault_info(info)
        {
            if unsafe {
                self.task
                    .global
                    .pm
                    .handle_page_fault(fault_address, error_code)
            }
            .is_ok()
            {
                return ContinueOperation::Resume;
            } else {
                return ContinueOperation::Terminate;
            }
        }
        // Best-effort symbolization of a genuine guest fault: name the guest
        // ELF image (and image-relative offset) containing the fault PC and
        // the return address, in the `path+0xoffset` form `llvm-symbolizer`
        // resolves directly against the guest's own binaries. Debug level so
        // it is inert unless logging is enabled -- guests also take faults on
        // purpose (e.g. OpenSSL's SIGILL CPU-feature probes).
        {
            let symbolize = |addr: usize| match self.task.find_guest_image(addr) {
                Some((path, offset)) => alloc::format!("{path}+{offset:#x}"),
                None => alloc::format!("{addr:#x} (no image)"),
            };
            #[cfg(target_arch = "aarch64")]
            litebox_util_log::debug!(
                pc:% = symbolize(ctx.pc), x30:% = symbolize(ctx.regs[30]),
                exception:? = info.exception;
                "guest fault location"
            );
            #[cfg(target_arch = "x86_64")]
            litebox_util_log::debug!(
                rip:% = symbolize(ctx.rip), exception:? = info.exception;
                "guest fault location"
            );
        }
        self.enter_shim(false, ctx, |task, _ctx| task.handle_exception_request(info))
    }

    fn interrupt(&self, ctx: &mut Self::ExecutionContext) -> ContinueOperation {
        self.enter_shim(false, ctx, |_, _| {})
    }
}

impl<Platform: ShimPlatform, FS: ShimFS> LinuxShimEntrypoints<Platform, FS> {
    fn enter_shim(
        &self,
        is_init: bool,
        ctx: &mut litebox_common_linux::PtRegs,
        f: impl FnOnce(&Task<Platform, FS>, &mut litebox_common_linux::PtRegs),
    ) -> ContinueOperation {
        if !is_init {
            self.task.enter_from_guest();
        }
        // Recorded on every entry so that a snapshot taken later -- at a blocking point deep
        // inside a syscall, where no `PtRegs` is in reach -- knows where this task's live guest
        // stack starts. See `syscalls::process::Task::save_address_space`.
        self.task
            .record_guest_sp(syscalls::process::guest_stack_pointer(ctx));
        f(&self.task, ctx);
        if self.task.prepare_to_run_guest(ctx) {
            ContinueOperation::Resume
        } else {
            ContinueOperation::Terminate
        }
    }
}

/// The shim entry point structure.
pub struct LinuxShimBuilder<Platform: ShimPlatform> {
    platform: &'static Platform,
    litebox: LiteBox<Platform>,
    /// Handle to the `/proc` backend mounted by [`Self::default_fs`], if it was called.
    /// [`Self::build`] moves this into [`GlobalState`] so the shim can publish the guest task's
    /// identity into it as that becomes known (see `syscalls::process::Task::set_task_comm`).
    proc_handle: Cell<Option<litebox::fs::proc::Proc<Platform>>>,
}

impl<Platform: ShimPlatform> LinuxShimBuilder<Platform> {
    /// Returns a new shim builder using the given platform.
    pub fn new(platform: &'static Platform) -> Self {
        Self::new_with_litebox(platform, LiteBox::new(platform))
    }

    /// Returns a new shim builder using an already-created LiteBox instance.
    pub fn new_with_litebox(platform: &'static Platform, litebox: LiteBox<Platform>) -> Self {
        Self {
            platform,
            litebox,
            proc_handle: Cell::new(None),
        }
    }

    /// Returns the litebox object for the shim.
    pub fn litebox(&self) -> &LiteBox<Platform> {
        &self.litebox
    }

    /// Create a default layered file system with the given in-memory layer and tar data.
    ///
    /// Also mounts a `/proc` backend and stashes a handle to it on `self`; [`Self::build`] moves
    /// that handle into the built shim's [`GlobalState`] so the guest task's identity can be
    /// published into `/proc/<pid>/*` once it's known. Calling this more than once replaces the
    /// stashed handle with the most recent call's -- only the `/proc` mounted by the filesystem
    /// actually passed to `LinuxShim::load_program` should be kept live.
    pub fn default_fs(
        &self,
        in_mem_fs: litebox::fs::in_mem::FileSystem<Platform>,
        tar_data: Cow<'static, [u8]>,
    ) -> DefaultFS<Platform> {
        let (fs, proc_handle) = default_fs(&self.litebox, in_mem_fs, tar_data);
        self.proc_handle.set(Some(proc_handle));
        fs
    }

    /// Build the shim.
    pub fn build<FS: ShimFS>(self) -> LinuxShim<Platform, FS> {
        self.build_with_net_config(None, None)
    }

    /// Same as [`Self::build`], but lets the caller override this instance's
    /// interface/gateway addresses (`None` = use `Network::new`'s default of
    /// `10.0.0.2`/`10.0.0.1`). Needed to run more than one shim on the same
    /// host at once, each independently reachable.
    pub fn build_with_net_config<FS: ShimFS>(
        self,
        interface_ip: Option<core::net::Ipv4Addr>,
        gateway_ip: Option<core::net::Ipv4Addr>,
    ) -> LinuxShim<Platform, FS> {
        let mut net = Network::new_with_addrs(&self.litebox, interface_ip, gateway_ip);
        net.set_platform_interaction(litebox::net::PlatformInteraction::Manual);
        let global = Arc::new(GlobalState {
            platform: self.platform,
            pm: PageManager::new(&self.litebox),
            futex_manager: FutexManager::new(),
            pipes: Pipes::new(&self.litebox),
            net: litebox::sync::Mutex::new(net),
            boot_time: self.platform.now(),
            next_thread_id: 2.into(), // start from 2, as 1 is used by the main thread
            proc_handle: self.proc_handle.take(),
            litebox: self.litebox,
            unix_addr_table: litebox::sync::RwLock::new(syscalls::unix::UnixAddrTable::new()),
            elf_patch_cache: litebox::sync::Mutex::new(alloc::collections::BTreeMap::new()),
            guest_images: litebox::sync::Mutex::new(alloc::vec::Vec::new()),
            // Overwritten with the initial task's pid in `load_program`; `0` is not a valid pid
            // so it's an obviously-uninitialized placeholder if ever observed.
            pgid: 0.into(),
            termios: litebox::sync::Mutex::new(litebox_common_linux::Termios::default_cooked()),
            processes: syscalls::process::ProcessTable::new(),
            brk_lock: litebox::sync::Mutex::new(()),
        });
        LinuxShim(global)
    }
}

pub struct LinuxShim<Platform: ShimPlatform, FS: ShimFS>(Arc<GlobalState<Platform, FS>>);
impl<Platform: ShimPlatform, FS: ShimFS> Clone for LinuxShim<Platform, FS> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<Platform: ShimPlatform, FS: ShimFS> LinuxShim<Platform, FS> {
    /// Loads the program at `path` as the shim's initial task, returning the
    /// initial register state.
    pub fn load_program(
        &self,
        fs: alloc::sync::Arc<FS>,
        task: litebox_common_linux::TaskParams,
        path: &str,
        argv: Vec<alloc::ffi::CString>,
        envp: Vec<alloc::ffi::CString>,
    ) -> Result<LoadedProgram<Platform, FS>, loader::elf::ElfLoaderError> {
        let litebox_common_linux::TaskParams {
            pid,
            ppid,
            uid,
            euid,
            gid,
            egid,
        } = task;

        let files = syscalls::file::FilesState::new(fs);
        files.set_max_fd(syscalls::process::RLIMIT_NOFILE_CUR - 1);
        let files = Arc::new(files);
        files.initialize_stdio_in_shared_descriptors_table(&self.0);

        // Keep the pid/tid allocator clear of the initial task's own pid, so that no `fork`ed
        // child can ever collide with it.
        self.0
            .next_thread_id
            .fetch_max(pid.saturating_add(1), core::sync::atomic::Ordering::Relaxed);

        // A freshly started process becomes its own process-group (and session) leader, absent
        // some other mechanism (e.g. a shell explicitly calling `setpgid`) putting it into an
        // existing group -- matching real Linux's default for the first process in a new job.
        self.0
            .pgid
            .store(pid, core::sync::atomic::Ordering::Relaxed);

        let entrypoints = crate::LinuxShimEntrypoints {
            _not_send: core::marker::PhantomData,
            task: Task {
                global: self.0.clone(),
                thread: syscalls::process::ThreadState::new_process(pid),
                wait_state: wait::WaitState::new(self.0.platform),
                pid,
                ppid,
                tid: pid,
                credentials: RefCell::new(
                    syscalls::process::Credentials {
                        uid,
                        euid,
                        gid,
                        egid,
                    }
                    .into(),
                ),
                comm: [0; litebox_common_linux::TASK_COMM_LEN].into(), // set at load time
                fs: Arc::new(syscalls::file::FsState::new()).into(),
                files: files.into(),
                signals: syscalls::signal::SignalState::new_process(),
                address_space: RefCell::new(None),
                guest_sp: Cell::new(0),
            },
        };

        let (path, argv) = entrypoints
            .task
            .resolve_shebang(alloc::string::String::from(path), argv)
            .map_err(loader::elf::ElfLoaderError::OpenError)?;

        entrypoints.task.load_program(
            loader::elf::ElfLoader::new(&entrypoints.task, &path)?,
            argv,
            envp,
        )?;
        let process = LinuxShimProcess(entrypoints.task.process().clone());
        Ok(LoadedProgram {
            entrypoints,
            process,
        })
    }

    /// Get the global page manager
    pub fn page_manager(&self) -> &PageManager<Platform, PAGE_SIZE> {
        &self.0.pm
    }

    /// Perform queued network interactions with the outside world.
    ///
    /// This function should be invoked in a loop, based on the returned advice.
    pub fn perform_network_interaction(
        &self,
    ) -> litebox::net::PlatformInteractionReinvocationAdvice {
        self.0.net.lock().perform_platform_interaction()
    }

    /// Establish a TCP connection to the given address.
    ///
    /// Returns a [`transport::ShimTransport`] that can be used as a
    /// byte-stream transport (e.g., for a 9P filesystem client).
    pub fn tcp_connection(
        &self,
        addr: core::net::SocketAddr,
    ) -> Result<transport::ShimTransport<Platform>, Errno> {
        transport::ShimTransport::connect(self.0.clone(), addr)
    }

    pub fn litebox(&self) -> &LiteBox<Platform> {
        &self.0.litebox
    }

    /// Returns the platform this shim was built with.
    pub fn platform(&self) -> &'static Platform {
        self.0.platform
    }
}

pub struct LoadedProgram<Platform: ShimPlatform, FS: ShimFS> {
    pub entrypoints: LinuxShimEntrypoints<Platform, FS>,
    pub process: LinuxShimProcess<Platform>,
}

/// A handle to a process loaded via [`LinuxShim::load_program`].
///
/// This can be used to wait for the process to exit.
pub struct LinuxShimProcess<Platform: ShimPlatform>(Arc<syscalls::process::Process<Platform>>);

impl<Platform: ShimPlatform> LinuxShimProcess<Platform> {
    /// Wait for the process to exit, returning its exit code.
    pub fn wait(&self) -> i32 {
        match self.0.wait_for_exit() {
            syscalls::process::ExitStatus::Exit(v) => v.into(),
            // TODO: return the enum instead of just a code?
            syscalls::process::ExitStatus::Signal(signal) => signal.as_i32() + 256,
        }
    }
}

/// Create a default layered file system with the given in-memory layer and tar data.
///
/// Also returns a handle to the mounted `/proc` backend; the caller (`LinuxShimBuilder`) is
/// responsible for keeping it reachable so the guest task's identity can be published into it
/// once known -- see `syscalls::process::Task::set_task_comm`.
fn default_fs<Platform: ShimPlatform>(
    litebox: &LiteBox<Platform>,
    in_mem_fs: litebox::fs::in_mem::FileSystem<Platform>,
    tar_data: Cow<'static, [u8]>,
) -> (LinuxFS<Platform>, litebox::fs::proc::Proc<Platform>) {
    let mut proc_handle = None;
    let dev_stdio = litebox::fs::resolver::Resolver::new(
        litebox,
        litebox::fs::composer::Composer::builder()
            .mount("/dev", |allocator| {
                litebox::fs::devices::Devices::new(litebox, allocator)
            })
            .mount("/proc", |allocator| {
                let proc = litebox::fs::proc::Proc::new(allocator);
                proc_handle = Some(proc.clone());
                proc
            })
            .build()
            .unwrap(),
    );
    let proc_handle = proc_handle.expect("mounted immediately above");
    let tar_ro = litebox::fs::resolver::Resolver::new(
        litebox,
        litebox::fs::composer::Composer::builder()
            .mount("/", |allocator| {
                litebox::fs::tar_ro::TarRo::new(tar_data, allocator)
            })
            .build()
            .unwrap(),
    );
    let fs = litebox::fs::layered::FileSystem::new(
        litebox,
        in_mem_fs,
        litebox::fs::layered::FileSystem::new(
            litebox,
            dev_stdio,
            tar_ro,
            litebox::fs::layered::LayeringSemantics::LowerLayerReadOnly,
        ),
        litebox::fs::layered::LayeringSemantics::LowerLayerWritableFiles,
    );
    (fs, proc_handle)
}

// Special override so that `GETFL` can return stdio-specific flags
#[derive(Clone)]
pub(crate) struct StdioStatusFlags(litebox::fs::OFlags);

impl<Platform: ShimPlatform, FS: ShimFS> syscalls::file::FilesState<Platform, FS> {
    fn initialize_stdio_in_shared_descriptors_table(&self, global: &GlobalState<Platform, FS>) {
        use litebox::fs::{Mode, OFlags};
        let stdin = self
            .fs
            .open("/dev/stdin", OFlags::RDONLY, Mode::empty())
            .unwrap();
        let stdout = self
            .fs
            .open("/dev/stdout", OFlags::WRONLY, Mode::empty())
            .unwrap();
        let stderr = self
            .fs
            .open("/dev/stderr", OFlags::WRONLY, Mode::empty())
            .unwrap();
        let mut dt = global.litebox.descriptor_table_mut();
        let mut rds = self.raw_descriptor_store.write();
        for (raw_fd, fd, stream) in [
            (0, stdin, litebox::platform::StdioStream::Stdin),
            (1, stdout, litebox::platform::StdioStream::Stdout),
            (2, stderr, litebox::platform::StdioStream::Stderr),
        ] {
            let status_flags = OFlags::APPEND | OFlags::RDWR;
            debug_assert_eq!(OFlags::STATUS_FLAGS_MASK & status_flags, status_flags);
            let old = dt.set_entry_metadata(&fd, StdioStatusFlags(status_flags));
            assert!(old.is_none());
            let old = dt.set_entry_metadata(&fd, stream);
            assert!(old.is_none());
            let success = rds.fd_into_specific_raw_integer(fd, raw_fd);
            assert!(success);
        }
    }
}

impl<Platform: ShimPlatform, FS: ShimFS> Task<Platform, FS> {
    fn close_on_exec(&self) {
        let files = self.files.borrow();
        let alive_fds: Vec<usize> = files.raw_descriptor_store.read().iter_alive().collect();
        for raw_fd in alive_fds {
            if let Ok(flags) = get_file_descriptor_flags(raw_fd, &self.global, &files)
                && flags.contains(litebox_common_linux::FileDescriptorFlags::FD_CLOEXEC)
            {
                let _ = self.do_close(raw_fd);
            }
        }
    }

    /// Explicitly closes every fd still alive in this (process-wide-last) file table.
    ///
    /// See `syscalls::process::Task::prepare_for_exit` for why this has to be explicit rather
    /// than relying on `FilesState`'s `Drop`.
    pub(crate) fn close_all_fds_on_exit(&self) {
        let files = self.files.borrow();
        let alive_fds: Vec<usize> = files.raw_descriptor_store.read().iter_alive().collect();
        for raw_fd in alive_fds {
            let _ = self.do_close(raw_fd);
        }
    }
}

impl<Platform: ShimPlatform, FS: ShimFS> syscalls::file::FilesState<Platform, FS> {
    #[expect(clippy::too_many_arguments)]
    pub(crate) fn run_on_raw_fd<R>(
        &self,
        fd: usize,
        fs: impl FnOnce(&TypedFd<FS>) -> R,
        net: impl FnOnce(&TypedFd<Network<Platform>>) -> R,
        pipes: impl FnOnce(&TypedFd<Pipes<Platform>>) -> R,
        eventfd: impl FnOnce(&TypedFd<syscalls::eventfd::EventfdSubsystem<Platform>>) -> R,
        epoll: impl FnOnce(&TypedFd<syscalls::epoll::EpollSubsystem<Platform, FS>>) -> R,
        unix: impl FnOnce(&TypedFd<syscalls::unix::UnixSocketSubsystem<Platform, FS>>) -> R,
    ) -> Result<R, Errno> {
        let rds = self.raw_descriptor_store.read();
        if let Ok(fd) = rds.fd_from_raw_integer(fd) {
            drop(rds);
            return Ok(fs(&fd));
        }
        if let Ok(fd) = rds.fd_from_raw_integer(fd) {
            drop(rds);
            return Ok(net(&fd));
        }
        if let Ok(fd) = rds.fd_from_raw_integer(fd) {
            drop(rds);
            return Ok(pipes(&fd));
        }
        if let Ok(fd) = rds.fd_from_raw_integer(fd) {
            drop(rds);
            return Ok(eventfd(&fd));
        }
        if let Ok(fd) = rds.fd_from_raw_integer(fd) {
            drop(rds);
            return Ok(epoll(&fd));
        }
        if let Ok(fd) = rds.fd_from_raw_integer(fd) {
            drop(rds);
            return Ok(unix(&fd));
        }
        Err(Errno::EBADF)
    }
}

// This places size limits on maximum read/write sizes that might occur; it exists primarily to
// prevent OOM due to the user asking for a _massive_ read or such at once. Keeping this too small
// has the downside of requiring too many syscalls, while having it be too large allows for massive
// allocations to be triggered by the userland program. For now, this is set to a
// hopefully-reasonable middle ground.
const MAX_KERNEL_BUF_SIZE: usize = 0x80_000;

trait ToSyscallResult {
    fn to_syscall_result(self) -> Result<usize, Errno>;
}
impl ToSyscallResult for Result<(), Errno> {
    fn to_syscall_result(self) -> Result<usize, Errno> {
        self.map(|()| 0)
    }
}
impl ToSyscallResult for Result<usize, Errno> {
    fn to_syscall_result(self) -> Result<usize, Errno> {
        self
    }
}
impl ToSyscallResult for Result<u32, Errno> {
    fn to_syscall_result(self) -> Result<usize, Errno> {
        self.map(|v| v as usize)
    }
}

impl<Platform: ShimPlatform, FS: ShimFS> Task<Platform, FS> {
    /// A wrapper function around `sys_pread64` that copies data in chunks to avoid OOMing.
    fn pread_with_user_buf(
        &self,
        fd: i32,
        buf: UserPtrMut<u8>,
        count: usize,
        offset: i64,
    ) -> Result<usize, Errno> {
        let mut kernel_buf = vec![0u8; count.min(MAX_KERNEL_BUF_SIZE)];
        let mut read_total = 0;
        while read_total < count {
            let to_read = (count - read_total).min(kernel_buf.len());
            match self.sys_pread64(
                fd,
                &mut kernel_buf[..to_read],
                offset + (read_total.reinterpret_as_signed() as i64),
            ) {
                Ok(0) => break, // EOF
                Ok(size) => {
                    buf.copy_from_slice::<Platform>(read_total, &kernel_buf[..size])
                        .ok_or(Errno::EFAULT)?;
                    read_total += size;
                }
                Err(e) => return Err(e),
            }
        }
        assert!(read_total <= count);
        Ok(read_total)
    }

    /// A wrapper around `sys_write`/`sys_pwrite64` that copies the guest buffer
    /// in bounded chunks to avoid a single unbounded allocation for a huge
    /// guest-supplied `count`, mirroring [`Self::pread_with_user_buf`].
    ///
    /// Unlike the read direction, a write is not itself retried past a short
    /// result: `sys_write` may legitimately write fewer bytes than asked (a
    /// pipe or socket at capacity), and real `write(2)` semantics leave
    /// retrying a short write to the caller, not the kernel. So only the
    /// copy-from-guest-memory step is chunked; a chunk that is not fully
    /// consumed ends the loop, exactly as a single unchunked write to that
    /// same destination would have.
    fn write_with_user_buf(
        &self,
        fd: i32,
        buf: UserPtr<u8>,
        count: usize,
        offset: Option<usize>,
    ) -> Result<usize, Errno> {
        let mut written_total = 0;
        while written_total < count {
            let to_write = (count - written_total).min(MAX_KERNEL_BUF_SIZE);
            let chunk_ptr = UserPtr::<u8>::from_usize(buf.as_usize() + written_total);
            let Some(chunk) = chunk_ptr.to_owned_slice::<Platform>(to_write) else {
                return if written_total > 0 {
                    Ok(written_total)
                } else {
                    Err(Errno::EFAULT)
                };
            };
            match self.sys_write(fd, &chunk, offset.map(|o| o + written_total)) {
                Ok(size) => {
                    written_total += size;
                    if size < to_write {
                        // A short write: the destination could not currently
                        // accept the full chunk. Stop here, matching what a
                        // single unchunked write to the same destination
                        // would have returned.
                        break;
                    }
                }
                Err(e) => {
                    return if written_total > 0 {
                        Ok(written_total)
                    } else {
                        Err(e)
                    };
                }
            }
        }
        assert!(written_total <= count);
        Ok(written_total)
    }

    /// Handle Linux syscalls and dispatch them to LiteBox implementations.
    ///
    /// # Panics
    ///
    /// Unsupported syscalls or arguments would trigger a panic for development purposes.
    fn handle_syscall_request(&self, ctx: &mut litebox_common_linux::PtRegs) {
        let result = self.do_syscall(ctx);
        // The request-side twin of this line lives in `do_syscall` (the
        // `req=` trace). Logging the result too is what turns the trace into
        // a usable differential record: a guest that aborts after a burst of
        // syscalls (libuv's `uv_loop_init` cleanup was the motivating case)
        // is undiagnosable from requests alone, because the failing call and
        // the cleanup that follows it look identical without return values.
        litebox_util_log::trace!(pid:? = self.pid, tid:? = self.tid, ret:? = result; "sysret");
        let return_value = match result {
            Ok(v) => v,
            Err(err) => (err.as_neg() as isize).reinterpret_as_unsigned(),
        };
        #[cfg(target_arch = "x86_64")]
        {
            ctx.rax = return_value;
        }
        #[cfg(target_arch = "aarch64")]
        {
            // The aarch64 Linux syscall ABI returns in x0.
            ctx.regs[0] = return_value;
        }
    }

    fn do_syscall(&self, ctx: &mut litebox_common_linux::PtRegs) -> Result<usize, Errno> {
        // Helper macro to unify the return value from `sys_*`.
        macro_rules! syscall {
            ($func:ident($($args:expr),*)) => {
                self.$func($($args),*).to_syscall_result()
            };
        }

        #[cfg(target_arch = "x86_64")]
        let syscall_number = ctx.orig_rax;
        // The aarch64 Linux syscall ABI passes the number in x8, which the entry
        // path records in `pt_regs::syscallno`. Sign-extending keeps an
        // out-of-range value (the kernel writes -1 for "no syscall") looking the
        // same as it does in x86-64's `orig_rax`, so the dispatch below rejects
        // it identically on both architectures.
        #[cfg(target_arch = "aarch64")]
        let syscall_number = (ctx.syscallno as isize).reinterpret_as_unsigned();
        let request = SyscallRequest::try_from_raw(syscall_number, ctx, log_unsupported_fmt)?;
        // A permanent, trace-gated record of every decoded syscall
        // (`LITEBOX_LOG=litebox_shim_linux=trace`). Off by default and a single level check when
        // it is off, but it is the only view of what a real guest is actually asking for: it is
        // what showed that busybox's blocking `wait` is a `sigsuspend` loop, and that the shim
        // was answering `sigsuspend` with an unimplemented-syscall error that release builds did
        // not even log (`log_unsupported_fmt` is `debug_assertions`-only).
        litebox_util_log::trace!(pid:? = self.pid, tid:? = self.tid, req:? = request; "syscall");

        match request {
            SyscallRequest::Exit { status } => {
                self.sys_exit(status);
                Ok(0)
            }
            SyscallRequest::ExitGroup { status } => {
                self.sys_exit_group(status);
                Ok(0)
            }
            SyscallRequest::Execve {
                pathname,
                argv,
                envp,
            } => self.sys_execve(pathname, argv, envp, ctx),
            SyscallRequest::Read { fd, buf, count } => {
                // Note some applications (e.g., `node`) seem to assume that getting fewer bytes than
                // requested indicates EOF.
                if count <= MAX_KERNEL_BUF_SIZE {
                    let mut kernel_buf = vec![0u8; count.min(MAX_KERNEL_BUF_SIZE)];
                    self.sys_read(fd, &mut kernel_buf, None).and_then(|size| {
                        buf.copy_from_slice::<Platform>(0, &kernel_buf[..size])
                            .map(|()| size)
                            .ok_or(Errno::EFAULT)
                    })
                } else {
                    // If the read size is too large, we need to do some extra work to avoid OOMing.
                    // We read data in chunks and update the file offset ourselves only if the read succeeds.
                    self.sys_lseek(fd, 0, litebox::fs::SeekWhence::RelativeToCurrentOffset)
                    .inspect_err(|e| {
                        match *e {
                            Errno::EBADF => (), // safe errors to return
                            Errno::ESPIPE => {
                                unimplemented!("read on non-seekable fds with large buffers");
                            }
                            Errno::EINVAL => {
                                unreachable!("seekable file should not return EINVAL when getting current offset");
                            }
                            _ => {
                                unimplemented!("unexpected error from lseek: {}", e);
                            }
                        }
                    })
                    .and_then(|cur_loc| {
                        self.pread_with_user_buf(fd, buf, count, i64::try_from(cur_loc).unwrap())
                            .inspect(|read_total| {
                                // Update the file offset to reflect the read we just did.
                                self.sys_lseek(
                                    fd,
                                    (cur_loc + read_total).reinterpret_as_signed(),
                                    litebox::fs::SeekWhence::RelativeToBeginning,
                                )
                                // Given that previous lseek and pread succeeded, this lseek should also succeed.
                                .expect("lseek failed");
                            })
                    })
                }
            }
            SyscallRequest::Write { fd, buf, count } => {
                self.write_with_user_buf(fd, buf, count, None)
            }
            SyscallRequest::Close { fd } => syscall!(sys_close(fd)),
            SyscallRequest::Lseek { fd, offset, whence } => {
                use litebox::utils::TruncateExt as _;
                syscalls::file::try_into_whence(whence.trunc())
                    .map_err(|_| Errno::EINVAL)
                    .and_then(|seekwhence| self.sys_lseek(fd, offset, seekwhence))
            }
            SyscallRequest::Mkdirat {
                dirfd,
                pathname,
                mode,
            } => pathname
                .to_cstring::<Platform>()
                .map_or(Err(Errno::EFAULT), |path| {
                    syscall!(sys_mkdirat(dirfd, path, mode))
                }),
            SyscallRequest::Chdir { pathname } => pathname
                .to_cstring::<Platform>()
                .map_or(Err(Errno::EINVAL), |path| syscall!(sys_chdir(path))),
            SyscallRequest::RtSigprocmask {
                how,
                set,
                oldset,
                sigsetsize,
            } => self.sys_rt_sigprocmask(how, set, oldset, sigsetsize),
            SyscallRequest::RtSigaction {
                signum,
                act,
                oldact,
                sigsetsize,
            } => self.sys_rt_sigaction(signum, act, oldact, sigsetsize),
            SyscallRequest::RtSigreturn => self.sys_rt_sigreturn(ctx),
            SyscallRequest::RtSigsuspend { mask, sigsetsize } => {
                self.sys_rt_sigsuspend(mask, sigsetsize)
            }
            SyscallRequest::Ioctl { fd, arg } => syscall!(sys_ioctl(fd, arg)),
            SyscallRequest::Pread64 {
                fd,
                buf,
                count,
                offset,
            } => self.pread_with_user_buf(fd, buf, count, offset),
            SyscallRequest::Pwrite64 {
                fd,
                buf,
                count,
                offset,
            } => {
                let pos = usize::try_from(offset).map_err(|_| Errno::EINVAL)?;
                self.write_with_user_buf(fd, buf, count, Some(pos))
            }
            SyscallRequest::Sendfile {
                out_fd,
                in_fd,
                offset,
                count,
            } => syscall!(sys_sendfile(out_fd, in_fd, offset, count)),
            SyscallRequest::Mmap {
                addr,
                length,
                prot,
                flags,
                fd,
                offset,
            } => self
                .sys_mmap(addr, length, prot, flags, fd, offset)
                .map(|ptr| ptr.as_usize()),
            SyscallRequest::Mprotect { addr, length, prot } => {
                syscall!(sys_mprotect(addr, length, prot))
            }
            SyscallRequest::Mremap {
                old_addr,
                old_size,
                new_size,
                flags,
                new_addr,
            } => self
                .sys_mremap(old_addr, old_size, new_size, flags, new_addr)
                .map(|ptr| ptr.as_usize()),
            SyscallRequest::Munmap { addr, length } => syscall!(sys_munmap(addr, length)),
            SyscallRequest::Brk { addr } => self.sys_brk(addr),
            SyscallRequest::Readv { fd, iovec, iovcnt } => self.sys_readv(fd, iovec, iovcnt),
            SyscallRequest::Writev { fd, iovec, iovcnt } => self.sys_writev(fd, iovec, iovcnt),
            SyscallRequest::Preadv {
                fd,
                iovec,
                iovcnt,
                pos_l,
                pos_h,
            } => self.sys_preadv(fd, iovec, iovcnt, preadv_pwritev_offset(pos_l, pos_h)),
            SyscallRequest::Pwritev {
                fd,
                iovec,
                iovcnt,
                pos_l,
                pos_h,
            } => self.sys_pwritev(fd, iovec, iovcnt, preadv_pwritev_offset(pos_l, pos_h)),
            SyscallRequest::Faccessat {
                dirfd,
                pathname,
                mode,
                flags,
            } => pathname
                .to_cstring::<Platform>()
                .map_or(Err(Errno::EFAULT), |path| {
                    syscall!(sys_faccessat(dirfd, path, mode, flags))
                }),
            SyscallRequest::Madvise {
                addr,
                length,
                behavior,
            } => syscall!(sys_madvise(addr, length, behavior)),
            SyscallRequest::Dup {
                oldfd,
                newfd,
                flags,
            } => syscall!(sys_dup(oldfd, newfd, flags)),
            SyscallRequest::Socket {
                domain,
                type_and_flags,
                protocol,
            } => syscall!(sys_socket(domain, type_and_flags, protocol)),
            SyscallRequest::Socketpair {
                domain,
                type_and_flags,
                protocol,
                sockvec,
            } => syscall!(sys_socketpair(domain, type_and_flags, protocol, sockvec)),
            SyscallRequest::Connect {
                sockfd,
                sockaddr,
                addrlen,
            } => syscall!(sys_connect(sockfd, sockaddr, addrlen)),
            SyscallRequest::Accept {
                sockfd,
                addr,
                addrlen,
                flags,
            } => syscall!(sys_accept(sockfd, addr, addrlen, flags)),
            SyscallRequest::Sendto {
                sockfd,
                buf,
                len,
                flags,
                addr,
                addrlen,
            } => self.sys_sendto(sockfd, buf, len, flags, addr, addrlen),
            SyscallRequest::Sendmsg { sockfd, msg, flags } => self.sys_sendmsg(sockfd, msg, flags),
            SyscallRequest::Sendmmsg {
                sockfd,
                msgvec,
                vlen,
                flags,
            } => self.sys_sendmmsg(sockfd, msgvec, vlen, flags),
            SyscallRequest::Recvfrom {
                sockfd,
                buf,
                len,
                flags,
                addr,
                addrlen,
            } => self.sys_recvfrom(sockfd, buf, len, flags, addr, addrlen),
            SyscallRequest::Recvmsg { sockfd, msg, flags } => self.sys_recvmsg(sockfd, msg, flags),
            SyscallRequest::Recvmmsg {
                sockfd,
                msgvec,
                vlen,
                flags,
                timeout,
            } => self.sys_recvmmsg(sockfd, msgvec, vlen, flags, timeout),
            SyscallRequest::Shutdown { sockfd, how } => syscall!(sys_shutdown(sockfd, how)),
            SyscallRequest::Bind {
                sockfd,
                sockaddr,
                addrlen,
            } => syscall!(sys_bind(sockfd, sockaddr, addrlen)),
            SyscallRequest::Listen { sockfd, backlog } => {
                syscall!(sys_listen(sockfd, backlog))
            }
            SyscallRequest::Setsockopt {
                sockfd,
                level,
                optname,
                optval,
                optlen,
            } => syscall!(sys_setsockopt(sockfd, level, optname, optval, optlen)),
            SyscallRequest::Getsockopt {
                sockfd,
                level,
                optname,
                optval,
                optlen,
            } => syscall!(sys_getsockopt(sockfd, level, optname, optval, optlen)),
            SyscallRequest::Getsockname {
                sockfd,
                addr,
                addrlen,
            } => syscall!(sys_getsockname(sockfd, addr, addrlen)),
            SyscallRequest::Getpeername {
                sockfd,
                addr,
                addrlen,
            } => syscall!(sys_getpeername(sockfd, addr, addrlen)),
            SyscallRequest::Uname { buf } => syscall!(sys_uname(buf)),
            SyscallRequest::Fcntl { fd, arg } => syscall!(sys_fcntl(fd, arg)),
            SyscallRequest::Flock { fd, operation } => syscall!(sys_flock(fd, operation)),
            SyscallRequest::Getcwd { buf, size: count } => {
                let mut kernel_buf = vec![0u8; count.min(MAX_KERNEL_BUF_SIZE)];
                self.sys_getcwd(&mut kernel_buf).and_then(|size| {
                    buf.copy_from_slice::<Platform>(0, &kernel_buf[..size])
                        .map(|()| size)
                        .ok_or(Errno::EFAULT)
                })
            }
            SyscallRequest::EpollCtl {
                epfd,
                op,
                fd,
                event,
            } => syscall!(sys_epoll_ctl(epfd, op, fd, event)),
            SyscallRequest::EpollCreate { size, flags } => {
                // the `size` argument is ignored, but must be greater than zero;
                if size > 0 {
                    syscall!(sys_epoll_create(flags))
                } else {
                    Err(Errno::EINVAL)
                }
            }
            SyscallRequest::EpollPwait {
                epfd,
                events,
                maxevents,
                timeout,
                sigmask,
                sigsetsize,
            } => self.sys_epoll_pwait(epfd, events, maxevents, timeout, sigmask, sigsetsize),
            SyscallRequest::Prctl { args } => self.sys_prctl(args),
            SyscallRequest::ArchPrctl { arg } => syscall!(sys_arch_prctl(arg)),
            SyscallRequest::Readlink {
                pathname,
                buf,
                bufsiz,
            } => pathname
                .to_cstring::<Platform>()
                .map_or(Err(Errno::EFAULT), |path| {
                    let mut kernel_buf = vec![0u8; bufsiz.min(MAX_KERNEL_BUF_SIZE)];
                    self.sys_readlink(path, &mut kernel_buf).and_then(|size| {
                        buf.copy_from_slice::<Platform>(0, &kernel_buf[..size])
                            .map(|()| size)
                            .ok_or(Errno::EFAULT)
                    })
                }),
            SyscallRequest::Ppoll {
                fds,
                nfds,
                timeout,
                sigmask,
                sigsetsize,
            } => self.sys_ppoll(fds, nfds, timeout, sigmask, sigsetsize),
            SyscallRequest::Pselect {
                nfds,
                readfds,
                writefds,
                exceptfds,
                timeout,
                sigsetpack,
            } => self.sys_pselect(nfds, readfds, writefds, exceptfds, timeout, sigsetpack),
            SyscallRequest::Readlinkat {
                dirfd,
                pathname,
                buf,
                bufsiz,
            } => pathname
                .to_cstring::<Platform>()
                .map_or(Err(Errno::EFAULT), |path| {
                    let mut kernel_buf = vec![0u8; bufsiz.min(MAX_KERNEL_BUF_SIZE)];
                    self.sys_readlinkat(dirfd, path, &mut kernel_buf)
                        .and_then(|size| {
                            buf.copy_from_slice::<Platform>(0, &kernel_buf[..size])
                                .map(|()| size)
                                .ok_or(Errno::EFAULT)
                        })
                }),
            SyscallRequest::Gettimeofday { tv, tz } => syscall!(sys_gettimeofday(tv, tz)),
            SyscallRequest::ClockGettime { clockid, tp } => {
                litebox_common_linux::ClockId::try_from(clockid)
                    .map_err(|_| {
                        log_unsupported!("clock_gettime(clockid = {clockid})");
                        Errno::EINVAL
                    })
                    .and_then(|clock_id| syscall!(sys_clock_gettime(clock_id, tp)))
            }
            SyscallRequest::ClockGetres { clockid, res } => {
                litebox_common_linux::ClockId::try_from(clockid)
                    .map_err(|_| {
                        log_unsupported!("clock_getres(clockid = {clockid})");
                        Errno::EINVAL
                    })
                    .and_then(|clock_id| syscall!(sys_clock_getres(clock_id, res)))
            }
            SyscallRequest::ClockNanosleep {
                clockid,
                flags,
                request,
                remain,
            } => litebox_common_linux::ClockId::try_from(clockid)
                .map_err(|_| {
                    log_unsupported!("clock_nanosleep(clockid = {clockid})");
                    Errno::EINVAL
                })
                .and_then(|clock_id| {
                    syscall!(sys_clock_nanosleep(clock_id, flags, request, remain))
                }),
            SyscallRequest::Time { tloc } => self
                .sys_time(tloc)
                .and_then(|second| usize::try_from(second).or(Err(Errno::EOVERFLOW))),
            SyscallRequest::Openat {
                dirfd,
                pathname,
                flags,
                mode,
            } => pathname
                .to_cstring::<Platform>()
                .map_or(Err(Errno::EFAULT), |path| {
                    syscall!(sys_openat(dirfd, path, flags, mode))
                }),
            SyscallRequest::Ftruncate { fd, length } => syscall!(sys_ftruncate(fd, length)),
            SyscallRequest::Mknodat {
                dirfd,
                pathname,
                mode_and_type,
                dev,
            } => pathname
                .to_cstring::<Platform>()
                .map_or(Err(Errno::EFAULT), |path| {
                    syscall!(sys_mknodat(dirfd, path, mode_and_type, dev))
                }),
            SyscallRequest::Unlinkat {
                dirfd,
                pathname,
                flags,
            } => pathname
                .to_cstring::<Platform>()
                .map_or(Err(Errno::EFAULT), |path| {
                    syscall!(sys_unlinkat(dirfd, path, flags))
                }),
            SyscallRequest::Symlinkat {
                target,
                newdirfd,
                linkpath,
            } => match (
                target.to_cstring::<Platform>(),
                linkpath.to_cstring::<Platform>(),
            ) {
                (Some(target), Some(linkpath)) => {
                    syscall!(sys_symlinkat(target, newdirfd, linkpath))
                }
                _ => Err(Errno::EFAULT),
            },
            SyscallRequest::Fchmodat {
                dirfd,
                pathname,
                mode,
                flags,
            } => pathname
                .to_cstring::<Platform>()
                .map_or(Err(Errno::EFAULT), |path| {
                    syscall!(sys_fchmodat(dirfd, path, mode, flags))
                }),
            SyscallRequest::Fchmod { fd, mode } => syscall!(sys_fchmod(fd, mode)),
            SyscallRequest::Utimensat {
                dirfd,
                pathname,
                times,
                flags,
            } => {
                let times = times
                    .map(|ptr| -> Result<_, Errno> {
                        let a = ptr.read_at_offset::<Platform>(0).ok_or(Errno::EFAULT)?;
                        let b = ptr.read_at_offset::<Platform>(1).ok_or(Errno::EFAULT)?;
                        Ok([a, b])
                    })
                    .transpose()?;
                match pathname {
                    Some(pathname) => pathname
                        .to_cstring::<Platform>()
                        .map_or(Err(Errno::EFAULT), |path| {
                            syscall!(sys_utimensat(dirfd, path, times, flags))
                        }),
                    // `futimens(fd, times)`, emulated by glibc as `utimensat(fd, NULL, times, 0)`.
                    None => syscall!(sys_futimens(dirfd, times)),
                }
            }
            SyscallRequest::Stat { pathname, buf } => {
                pathname
                    .to_cstring::<Platform>()
                    .map_or(Err(Errno::EFAULT), |path| {
                        self.sys_stat(path).and_then(|stat| {
                            buf.write_at_offset::<Platform>(0, stat)
                                .ok_or(Errno::EFAULT)
                                .map(|()| 0)
                        })
                    })
            }
            SyscallRequest::Lstat { pathname, buf } => {
                pathname
                    .to_cstring::<Platform>()
                    .map_or(Err(Errno::EFAULT), |path| {
                        self.sys_lstat(path).and_then(|stat| {
                            buf.write_at_offset::<Platform>(0, stat)
                                .ok_or(Errno::EFAULT)
                                .map(|()| 0)
                        })
                    })
            }
            SyscallRequest::Fstat { fd, buf } => self.sys_fstat(fd).and_then(|stat| {
                buf.write_at_offset::<Platform>(0, stat)
                    .ok_or(Errno::EFAULT)
                    .map(|()| 0)
            }),
            // Reached through `newfstatat` on x86-64 and `fstatat` on aarch64,
            // where it is the only path-based stat syscall the kernel offers.
            SyscallRequest::Newfstatat {
                dirfd,
                pathname,
                buf,
                flags,
            } => pathname
                .to_cstring::<Platform>()
                .map_or(Err(Errno::EFAULT), |path| {
                    self.sys_newfstatat(dirfd, path, flags).and_then(|stat| {
                        buf.write_at_offset::<Platform>(0, stat)
                            .ok_or(Errno::EFAULT)
                            .map(|()| 0)
                    })
                }),
            SyscallRequest::Statx {
                dirfd,
                pathname,
                flags,
                mask,
                statxbuf,
            } => {
                let (path, flags) = match pathname {
                    // Linux 6.11+ treats a NULL statx path as a request to stat dirfd.
                    None => (
                        Ok(c"".into()),
                        flags | litebox_common_linux::AtFlags::AT_EMPTY_PATH,
                    ),
                    Some(p) => (p.to_cstring::<Platform>().ok_or(Errno::EFAULT), flags),
                };
                path.and_then(|path| {
                    self.sys_statx(dirfd, path, flags, mask).and_then(|sx| {
                        statxbuf
                            .write_at_offset::<Platform>(0, sx)
                            .ok_or(Errno::EFAULT)
                            .map(|()| 0)
                    })
                })
            }
            SyscallRequest::Statfs { pathname, buf } => pathname
                .to_cstring::<Platform>()
                .map_or(Err(Errno::EFAULT), |path| syscall!(sys_statfs(path, buf))),
            SyscallRequest::Fstatfs { fd, buf } => syscall!(sys_fstatfs(fd, buf)),
            SyscallRequest::Eventfd2 { initval, flags } => {
                syscall!(sys_eventfd2(initval, flags))
            }
            SyscallRequest::Pipe2 { pipefd, flags } => {
                self.sys_pipe2(flags).and_then(|(read_fd, write_fd)| {
                    pipefd
                        .write_at_offset::<Platform>(0, read_fd)
                        .ok_or(Errno::EFAULT)?;
                    pipefd
                        .write_at_offset::<Platform>(1, write_fd)
                        .ok_or(Errno::EFAULT)?;
                    Ok(0)
                })
            }
            SyscallRequest::Clone { args } => self.sys_clone(ctx, &args),
            SyscallRequest::Clone3 { args } => self.sys_clone3(ctx, args),
            SyscallRequest::SetThreadArea { user_desc } => {
                #[cfg(target_arch = "x86_64")]
                {
                    let _ = user_desc;
                    Err(Errno::ENOSYS) // x86_64 does not support set_thread_area
                }
                #[cfg(target_arch = "aarch64")]
                {
                    // aarch64 has no `set_thread_area` either; the thread
                    // pointer is `TPIDR_EL0`, set through `clone`'s `tls`
                    // argument.
                    let _ = user_desc;
                    Err(Errno::ENOSYS)
                }
            }
            SyscallRequest::SetTidAddress { tidptr } => {
                Ok(self.sys_set_tid_address(tidptr).reinterpret_as_unsigned() as usize)
            }
            SyscallRequest::Gettid => Ok(self.sys_gettid().reinterpret_as_unsigned() as usize),
            SyscallRequest::Getrlimit { resource, rlim } => {
                syscall!(sys_getrlimit(resource, rlim))
            }
            SyscallRequest::Setrlimit { resource, rlim } => {
                syscall!(sys_setrlimit(resource, rlim))
            }
            SyscallRequest::Prlimit {
                pid,
                resource,
                new_limit,
                old_limit,
            } => syscall!(sys_prlimit(pid, resource, new_limit, old_limit)),
            SyscallRequest::SetRobustList { head } => {
                self.sys_set_robust_list(head);
                Ok(0)
            }
            SyscallRequest::GetRobustList { pid, head, len } => self
                .sys_get_robust_list(pid, head)
                .and_then(|()| {
                    len.write_at_offset::<Platform>(
                        0,
                        size_of::<litebox_common_linux::RobustListHead>(),
                    )
                    .ok_or(Errno::EFAULT)
                })
                .map(|()| 0),
            SyscallRequest::GetRandom { buf, count, flags } => {
                self.sys_getrandom(buf, count, flags)
            }
            SyscallRequest::Getpid => Ok(self.sys_getpid().reinterpret_as_unsigned() as usize),
            SyscallRequest::Getppid => Ok(self.sys_getppid().reinterpret_as_unsigned() as usize),
            SyscallRequest::Getpgid { pid } => self
                .sys_getpgid(pid)
                .map(|pgid| pgid.reinterpret_as_unsigned() as usize),
            SyscallRequest::Setpgid { pid, pgid } => syscall!(sys_setpgid(pid, pgid)),
            SyscallRequest::Wait4 {
                pid,
                wstatus,
                options,
                rusage,
            } => self
                .sys_wait4(pid, wstatus, options, rusage)
                .map(|pid| pid.reinterpret_as_unsigned() as usize),
            SyscallRequest::Getuid => Ok(self.sys_getuid() as usize),
            SyscallRequest::Getgid => Ok(self.sys_getgid() as usize),
            SyscallRequest::Geteuid => Ok(self.sys_geteuid() as usize),
            SyscallRequest::Getegid => Ok(self.sys_getegid() as usize),
            SyscallRequest::Getgroups { size, list } => syscall!(sys_getgroups(size, list)),
            SyscallRequest::Setuid { uid } => syscall!(sys_setuid(uid)),
            SyscallRequest::Setgid { gid } => syscall!(sys_setgid(gid)),
            SyscallRequest::Sysinfo { buf } => {
                let sysinfo = self.sys_sysinfo();
                buf.write_at_offset::<Platform>(0, sysinfo)
                    .ok_or(Errno::EFAULT)
                    .map(|()| 0)
            }
            SyscallRequest::Getrusage { who, usage } => {
                let rusage = self.sys_getrusage(who);
                usage
                    .write_at_offset::<Platform>(0, rusage)
                    .ok_or(Errno::EFAULT)
                    .map(|()| 0)
            }
            SyscallRequest::CapGet { header, data } => syscall!(sys_capget(header, data)),
            SyscallRequest::GetDirent64 { fd, dirp, count } => {
                self.sys_getdirent64(fd, dirp, count)
            }
            SyscallRequest::SchedGetAffinity { pid, len, mask } => {
                const BITS_PER_BYTE: usize = 8;
                let cpuset = self.sys_sched_getaffinity(pid);
                if len * BITS_PER_BYTE < cpuset.len()
                    || len & (core::mem::size_of::<usize>() - 1) != 0
                {
                    Err(Errno::EINVAL)
                } else {
                    let raw_bytes = cpuset.as_bytes();
                    mask.copy_from_slice::<Platform>(0, raw_bytes)
                        .map(|()| raw_bytes.len())
                        .ok_or(Errno::EFAULT)
                }
            }
            SyscallRequest::SchedYield => {
                // Do nothing until we have more scheduler integration with the
                // platform.
                Ok(0)
            }
            SyscallRequest::SchedGetParam { pid, param } => {
                syscall!(sys_sched_getparam(pid, param))
            }
            SyscallRequest::SchedSetParam { pid, param } => {
                syscall!(sys_sched_setparam(pid, param))
            }
            SyscallRequest::SchedGetScheduler { pid } => syscall!(sys_sched_getscheduler(pid)),
            SyscallRequest::SchedSetScheduler { pid, policy, param } => {
                syscall!(sys_sched_setscheduler(pid, policy, param))
            }
            SyscallRequest::Futex { args } => self.sys_futex(args),
            SyscallRequest::Umask { mask } => {
                let old_mask = self.sys_umask(mask);
                Ok(old_mask.bits() as usize)
            }
            SyscallRequest::Kill { pid, sig } => self.sys_kill(pid, sig),
            SyscallRequest::Tkill { tid, sig } => self.sys_tkill(tid, sig),
            SyscallRequest::Tgkill { tgid, tid, sig } => self.sys_tgkill(tgid, tid, sig),
            SyscallRequest::Sigaltstack { ss, old_ss } => self.sys_sigaltstack(ss, old_ss, ctx),
            SyscallRequest::Alarm { seconds } => syscall!(sys_alarm(seconds)),
            SyscallRequest::Pause => syscall!(sys_pause()),
            SyscallRequest::GetITimer { which, curr_value } => {
                syscall!(sys_getitimer(which, curr_value))
            }
            SyscallRequest::SetITimer {
                which,
                new_value,
                old_value,
            } => syscall!(sys_setitimer(which, new_value, old_value)),
            _ => {
                log_unsupported!("{request:?}");
                Err(Errno::ENOSYS)
            }
        }
    }
}

/// Global shim state, shared across all tasks.
struct GlobalState<Platform: ShimPlatform, FS: ShimFS> {
    /// The platform instance used throughout the shim.
    platform: &'static Platform,
    /// The LiteBox instance used throughout the shim.
    litebox: litebox::LiteBox<Platform>,
    /// The page manager for managing virtual memory.
    pm: litebox::mm::PageManager<Platform, { PAGE_SIZE }>,
    /// The futex manager for handling futex operations.
    futex_manager: FutexManager<Platform>,
    /// The anonymous pipe implementation.
    pipes: Pipes<Platform>,
    /// The network subsystem.
    net: litebox::sync::Mutex<Platform, Network<Platform>>,
    /// The time when the shim was started.
    boot_time: <Platform as TimeProvider>::Instant,
    /// Next thread ID to assign.
    // TODO: better management of thread IDs
    next_thread_id: core::sync::atomic::AtomicI32,
    /// UNIX domain socket address table
    unix_addr_table: litebox::sync::RwLock<Platform, syscalls::unix::UnixAddrTable<Platform, FS>>,
    /// Per-process collection of ELF patching state for runtime syscall rewriting.
    elf_patch_cache: litebox::sync::Mutex<Platform, syscalls::mm::ElfPatchCache>,
    /// Guest ELF images recorded at map time, for fault symbolization. Grows
    /// monotonically (never pruned on unmap) and survives the mapping fd's
    /// close, unlike [`Self::elf_patch_cache`]. See `Task::find_guest_image`.
    guest_images: litebox::sync::Mutex<Platform, alloc::vec::Vec<syscalls::mm::GuestImage>>,
    /// Handle to the `/proc` backend mounted by [`LinuxShimBuilder::default_fs`], if any --
    /// `None` when the shim was built with a filesystem that doesn't mount one.
    /// `Task::set_task_comm` publishes the guest task's identity here as it becomes known.
    proc_handle: Option<litebox::fs::proc::Proc<Platform>>,
    /// The process group ID both of the controlling terminal's foreground group (as set by
    /// `TIOCSPGRP` / read by `TIOCGPGRP`) and of every guest process (as set by `setpgid` / read
    /// by `getpgid` -- see `syscalls::process::Task::sys_setpgid`/`sys_getpgid`). All four
    /// syscalls share this one field.
    ///
    /// This is a single shim-wide value rather than a per-process-group one: `fork` (see
    /// `syscalls::process::Task::do_fork`) does now produce tasks with distinct pids, but they
    /// all inherit the one process group, so `setpgid` can only ever move a task into *the*
    /// group, never a second, distinct one -- matching `WaitFilter::Any`'s existing "this shim
    /// has a single process group" simplification for `wait4`. [`LinuxShim::load_program`]
    /// initializes this to the initial task's `pid`, matching real Linux's convention that a
    /// freshly started process (as opposed to one that inherited an existing group via `fork`)
    /// becomes its own process-group leader.
    pgid: core::sync::atomic::AtomicI32,
    /// Real termios state for the process's controlling terminal (shared by stdin/stdout/stderr,
    /// like a real Linux `tty_struct`), as read by `TCGETS` and written by `TCSETS`.
    termios: litebox::sync::Mutex<Platform, litebox_common_linux::Termios>,
    /// Parent/child relationships and exit statuses for every guest process, so that `fork`ed
    /// children can be reaped by `wait4`.
    processes: syscalls::process::ProcessTable<Platform>,
    /// Serializes the swap-operate-restore sequence that gives each guest process its own program
    /// break on top of the single break [`litebox::mm::PageManager`] tracks. See
    /// `Task::sys_brk`.
    brk_lock: litebox::sync::Mutex<Platform, ()>,
}

struct Task<Platform: ShimPlatform, FS: ShimFS> {
    global: Arc<GlobalState<Platform, FS>>,
    wait_state: wait::WaitState<Platform>,
    thread: syscalls::process::ThreadState<Platform>,
    /// Process ID
    pid: i32,
    /// Parent Process ID
    ppid: i32,
    /// Thread ID
    tid: i32,
    /// Task credentials. These are set per task but are Arc'd to save space
    /// since most tasks never change their credentials. `setuid`/`setgid`
    /// replace the `Arc` rather than mutate through it, so a thread that
    /// still shares the old one (e.g. a sibling from `clone`) is unaffected
    /// -- matching the raw syscall, which (unlike glibc's thread-broadcasting
    /// wrapper) only ever updates the calling thread's credentials.
    credentials: RefCell<Arc<syscalls::process::Credentials>>,
    /// Command name (usually the executable name, excluding the path)
    comm: Cell<[u8; litebox_common_linux::TASK_COMM_LEN]>,
    /// Filesystem state. `RefCell` to support `unshare` in the future.
    fs: RefCell<Arc<syscalls::file::FsState<Platform>>>,
    /// File descriptors. `RefCell` to support `unshare` in the future.
    files: RefCell<Arc<syscalls::file::FilesState<Platform, FS>>>,
    /// Signal state
    signals: syscalls::signal::SignalState<Platform>,
    /// Set while this task shares one guest address space with other guest processes, which is
    /// what `fork` produces here.
    ///
    /// See `syscalls::process::SharedAddressSpace` for why, and for the hand-off protocol that
    /// keeps exactly one member running on the shared memory at a time.
    address_space: RefCell<Option<syscalls::process::AddressSpaceMembership<Platform>>>,
    /// The guest stack pointer as of the most recent entry into the shim.
    ///
    /// Needed because a snapshot of this task's memory can be taken at any blocking point, not
    /// just at a syscall that was handed a `PtRegs`; see
    /// `syscalls::process::Task::save_address_space` for what it is used for.
    guest_sp: Cell<usize>,
}

impl<Platform: ShimPlatform, FS: ShimFS> Drop for Task<Platform, FS> {
    fn drop(&mut self) {
        self.prepare_for_exit();
    }
}

#[cfg(test)]
mod test_utils {
    extern crate std;
    use super::*;

    impl<Platform: ShimPlatform, FS: ShimFS> GlobalState<Platform, FS> {
        /// Make a new task with default values for testing.
        pub(crate) fn new_test_task(
            self: Arc<Self>,
            fs: alloc::sync::Arc<FS>,
        ) -> Task<Platform, FS> {
            let pid = self
                .next_thread_id
                .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            let files = Arc::new(syscalls::file::FilesState::new(fs));
            files.initialize_stdio_in_shared_descriptors_table(&self);
            Task {
                wait_state: wait::WaitState::new(self.platform),
                thread: syscalls::process::ThreadState::new_process(pid),
                pid,
                ppid: 0,
                tid: pid,
                credentials: RefCell::new(Arc::new(syscalls::process::Credentials {
                    uid: 0,
                    euid: 0,
                    gid: 0,
                    egid: 0,
                })),
                comm: Cell::new(*b"test\0\0\0\0\0\0\0\0\0\0\0\0"),
                fs: Arc::new(syscalls::file::FsState::new()).into(),
                files: files.into(),
                signals: syscalls::signal::SignalState::new_process(),
                address_space: RefCell::new(None),
                guest_sp: Cell::new(0),
                global: self,
            }
        }
    }

    impl<Platform: ShimPlatform, FS: ShimFS> Task<Platform, FS> {
        /// Returns a clone of this task with a new TID for testing.
        pub(crate) fn clone_for_test(&self) -> Option<Self> {
            let tid = self
                .global
                .next_thread_id
                .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            let task = Task {
                wait_state: wait::WaitState::new(self.global.platform),
                global: self.global.clone(),
                thread: self.thread.new_thread(tid)?,
                pid: self.pid,
                ppid: self.ppid,
                tid,
                credentials: RefCell::new(self.credentials.borrow().clone()),
                comm: self.comm.clone(),
                fs: self.fs.clone(),
                files: self.files.clone(),
                signals: self.signals.clone_for_new_task(),
                address_space: RefCell::new(None),
                guest_sp: Cell::new(0),
            };
            Some(task)
        }

        /// Spawns a thread that runs with a clone of this task and a new TID.
        ///
        /// # Panics
        /// Panics if the test process is already terminating.
        pub(crate) fn spawn_clone_for_test<R>(
            &self,
            f: impl 'static + Send + FnOnce(Task<Platform, FS>) -> R,
        ) -> std::thread::JoinHandle<R>
        where
            R: 'static + Send,
        {
            let task = self.clone_for_test().unwrap();
            std::thread::spawn(move || f(task))
        }
    }
}
