// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! A minimal `/proc` [`super::backend::Backend`].
//!
//! Exposes just enough of `/proc` for a real guest's `df`, `free` and `ps` to work:
//! `/proc/meminfo`, `/proc/mounts`, and `/proc/<pid>/{stat,status,cmdline}` for the single guest
//! task this backend is told about (see [`Proc::set_identity`]/[`Proc::set_comm`]/
//! [`Proc::set_cmdline`]). LiteBox's Linux shim currently only ever runs one guest task per
//! process -- `clone` requires `CLONE_THREAD` (no `fork`), so there is exactly one pid to publish,
//! not a real process tree; this backend intentionally does not invent one.
//!
//! Content is computed fresh on every [`super::backend::Backend::read`], the same way
//! [`super::devices::Devices`]' `/dev/urandom` computes its bytes on every read, so a second read
//! of a growing/changing value (e.g. after `execve` changes `comm`) observes the live value.

use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::sync::{RawSyncPrimitivesProvider, RwLock};
use crate::utils::TruncateExt as _;

use super::backend::{
    Backend, BackendHandles, DirHandle, FileHandle, PermissionCheck, PermissionInfo, Permissioned,
    SeekBehavior, WalkOutcome, WalkStopReason, WalkedComponent, WalkingDirHandle,
};
use super::errors::{
    ChmodError, ChownError, FileStatusError, MkdirError, OpenError, PathError, ReadDirError,
    ReadError, RmdirError, TruncateError, UnlinkError, UtimeError, WalkError, WriteError,
};
use super::inode_allocator::InodeAllocator;
use super::{DirEntry, FileStatus, FileType, Mode, NodeInfo, OFlags, Timestamp, UserInfo};

/// Block size reported for `/proc` files: they're computed, not backed by real storage.
const PROC_BLOCK_SIZE: usize = 0;

/// Total "physical memory" `/proc/meminfo` (and [`crate::platform::SystemInfoProvider`]-less
/// `sysinfo()` callers) report. Kept in one place so `/proc/meminfo` and the `sysinfo` syscall
/// can't silently drift apart -- see `litebox_shim_linux/src/syscalls/misc.rs`'s `sys_sysinfo`,
/// which reads these same constants.
pub const SYNTHETIC_TOTAL_RAM_BYTES: u64 = 4 * 1024 * 1024 * 1024;
/// Free "physical memory" `/proc/meminfo` and `sysinfo()` report. See
/// [`SYNTHETIC_TOTAL_RAM_BYTES`].
pub const SYNTHETIC_FREE_RAM_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// Identity of the single guest task `/proc/<pid>/*` describes.
///
/// Published by the shim as each piece becomes known: `pid`/`ppid`/`uid`/`gid` at task
/// construction (never change afterward -- this process model has no `fork` and does not track
/// live `setuid`/`setgid`), `comm` at load and on every `execve`/`prctl(PR_SET_NAME)`, `cmdline`
/// at load and on every `execve`.
#[derive(Clone, Default)]
struct ProcTaskInfo {
    pid: i32,
    ppid: i32,
    uid: u32,
    gid: u32,
    /// Command name, trimmed of trailing NULs (not NUL-terminated itself).
    comm: Vec<u8>,
    /// NUL-separated `argv`, NUL-terminated (matches `/proc/<pid>/cmdline`'s on-disk form
    /// exactly, so [`ProcFile::PidCmdline`]'s `read` can serve it unmodified).
    cmdline: Vec<u8>,
}

/// A [`Backend`] exposing a minimal, computed `/proc`.
///
/// Cheap to [`Clone`] (an `Arc` handle to shared state): the shim keeps one clone mounted at
/// `/proc` via [`super::composer::Composer`] and another to call [`Self::set_identity`]/
/// [`Self::set_comm`]/[`Self::set_cmdline`] on as the guest task's identity becomes known.
pub struct Proc<Platform: RawSyncPrimitivesProvider + 'static> {
    inner: Arc<ProcInner<Platform>>,
}

struct ProcInner<Platform: RawSyncPrimitivesProvider + 'static> {
    root_inode: NodeInfo,
    pid_dir_inode: NodeInfo,
    sys_dir_inode: NodeInfo,
    sys_kernel_dir_inode: NodeInfo,
    meminfo_inode: NodeInfo,
    mounts_inode: NodeInfo,
    stat_system_inode: NodeInfo,
    cpuinfo_inode: NodeInfo,
    overflowuid_inode: NodeInfo,
    overflowgid_inode: NodeInfo,
    stat_inode: NodeInfo,
    statm_inode: NodeInfo,
    status_inode: NodeInfo,
    cmdline_inode: NodeInfo,
    net_dir_inode: NodeInfo,
    net_dev_inode: NodeInfo,
    task: RwLock<Platform, ProcTaskInfo>,
}

impl<Platform: RawSyncPrimitivesProvider + 'static> Clone for Proc<Platform> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<Platform: RawSyncPrimitivesProvider + 'static> Proc<Platform> {
    /// Construct a new `Proc` backend using a caller-provided inode allocator.
    #[must_use]
    pub fn new(allocator: InodeAllocator) -> Self {
        Self {
            inner: Arc::new(ProcInner {
                root_inode: allocator.next(),
                pid_dir_inode: allocator.next(),
                sys_dir_inode: allocator.next(),
                sys_kernel_dir_inode: allocator.next(),
                meminfo_inode: allocator.next(),
                mounts_inode: allocator.next(),
                stat_system_inode: allocator.next(),
                cpuinfo_inode: allocator.next(),
                overflowuid_inode: allocator.next(),
                overflowgid_inode: allocator.next(),
                stat_inode: allocator.next(),
                statm_inode: allocator.next(),
                status_inode: allocator.next(),
                cmdline_inode: allocator.next(),
                net_dir_inode: allocator.next(),
                net_dev_inode: allocator.next(),
                task: RwLock::new(ProcTaskInfo::default()),
            }),
        }
    }

    /// Publish the guest task's pid/ppid/uid/gid. Idempotent; call as often as convenient (the
    /// shim calls it every time `comm` changes too, since both are cheap and it avoids needing a
    /// separate "first publish" flag).
    #[allow(clippy::similar_names)]
    pub fn set_identity(&self, pid: i32, ppid: i32, uid: u32, gid: u32) {
        let mut task = self.inner.task.write();
        task.pid = pid;
        task.ppid = ppid;
        task.uid = uid;
        task.gid = gid;
    }

    /// Publish the guest task's command name (`/proc/<pid>/comm`, and `stat`'s `(comm)` field).
    pub fn set_comm(&self, comm: &[u8]) {
        let end = comm.iter().position(|&b| b == 0).unwrap_or(comm.len());
        self.inner.task.write().comm = comm[..end].to_vec();
    }

    /// Publish the guest task's `argv`, joined and NUL-terminated exactly as
    /// `/proc/<pid>/cmdline` serves it.
    pub fn set_cmdline<A: AsRef<[u8]>>(&self, argv: &[A]) {
        let mut cmdline = Vec::new();
        for arg in argv {
            cmdline.extend_from_slice(arg.as_ref());
            cmdline.push(0);
        }
        self.inner.task.write().cmdline = cmdline;
    }

    fn task_pid(&self) -> i32 {
        self.inner.task.read().pid
    }

    fn task_owner(&self) -> UserInfo {
        let task = self.inner.task.read();
        UserInfo {
            user: task.uid.trunc(),
            group: task.gid.trunc(),
        }
    }

    fn render(&self, file: ProcFile) -> Vec<u8> {
        match file {
            ProcFile::Meminfo => render_meminfo(),
            ProcFile::Mounts => render_mounts(),
            ProcFile::StatSystem => render_stat_system(),
            ProcFile::Cpuinfo => render_cpuinfo(),
            ProcFile::OverflowUid | ProcFile::OverflowGid => b"65534\n".to_vec(),
            ProcFile::PidStat => render_stat(&self.inner.task.read()),
            ProcFile::PidStatm => render_statm(),
            ProcFile::PidStatus => render_status(&self.inner.task.read()),
            ProcFile::PidCmdline => self.inner.task.read().cmdline.clone(),
            ProcFile::NetDev => render_net_dev(),
        }
    }
}

/// `/proc/meminfo` content. `Cached`/`MemAvailable`/`SReclaimable` are the three fields
/// `busybox free` actually parses out of this file (the total/free/shared/buffer columns come
/// from the `sysinfo()` syscall instead); the rest are included for any other real reader.
fn render_meminfo() -> Vec<u8> {
    let total_kb = SYNTHETIC_TOTAL_RAM_BYTES / 1024;
    let free_kb = SYNTHETIC_FREE_RAM_BYTES / 1024;
    format!(
        "MemTotal:       {total_kb:>10} kB\n\
         MemFree:        {free_kb:>10} kB\n\
         MemAvailable:   {free_kb:>10} kB\n\
         Buffers:                 0 kB\n\
         Cached:                  0 kB\n\
         SwapCached:              0 kB\n\
         SwapTotal:               0 kB\n\
         SwapFree:                0 kB\n\
         Shmem:                   0 kB\n\
         SReclaimable:            0 kB\n"
    )
    .into_bytes()
}

/// `/proc/mounts` content: one line per synthetic mount, in `fstab`(5)/`getmntent`(3) format
/// (`device mountpoint fstype options freq passno`). `df` (via `setmntent`/`getmntent`, since
/// Alpine's BusyBox has no `/etc/mtab`, so it reads this file directly) enumerates these and
/// calls `statvfs` on each mount point. The root device is deliberately not named `rootfs` --
/// `busybox df` skips a `rootfs`-named entry by default (`CONFIG_FEATURE_SKIP_ROOTFS`), which
/// would otherwise make `df` print only a header with no data rows.
fn render_mounts() -> Vec<u8> {
    String::from(
        "litebox / litebox rw 0 0\n\
         devtmpfs /dev devtmpfs rw 0 0\n\
         proc /proc proc rw 0 0\n",
    )
    .into_bytes()
}

/// Number of logical CPUs the synthetic `/proc` reports. Kept in step with
/// `sched_getaffinity`'s `NR_CPUS` in `litebox_shim_linux` so `os.cpus()` (which
/// counts `/proc/stat` `cpuN` lines) agrees with `os.availableParallelism()`
/// (which counts the affinity mask).
const SYNTHETIC_NUM_CPUS: usize = 2;

/// System-wide `/proc/stat` content. libuv's `uv_cpu_info` -- what Node's
/// `os.cpus()` calls -- enumerates CPUs by counting the `cpuN` lines here and
/// reads their jiffy counters; without this file `os.cpus()` returns an empty
/// array. The counters are zero (this process model has no per-CPU scheduler
/// accounting), and the aggregate `cpu` line plus the trailing bookkeeping
/// fields are included for any other real reader.
fn render_stat_system() -> Vec<u8> {
    use core::fmt::Write as _;
    let mut out = String::from("cpu  0 0 0 0 0 0 0 0 0 0\n");
    for cpu in 0..SYNTHETIC_NUM_CPUS {
        let _ = writeln!(out, "cpu{cpu} 0 0 0 0 0 0 0 0 0 0");
    }
    out.push_str(
        "intr 0\n\
         ctxt 0\n\
         btime 0\n\
         processes 1\n\
         procs_running 1\n\
         procs_blocked 0\n",
    );
    out.into_bytes()
}

/// `/proc/cpuinfo` content, AArch64 flavour (one stanza per CPU). Node reads this
/// after `/proc/stat` for each CPU's model/speed. The AArch64 layout carries no
/// `model name`/`cpu MHz` line (unlike x86), so `os.cpus()[i].model` reports the
/// generic implementer identity and `.speed` is 0 -- exactly as on real AArch64
/// Linux.
fn render_cpuinfo() -> Vec<u8> {
    use core::fmt::Write as _;
    let mut out = String::new();
    for cpu in 0..SYNTHETIC_NUM_CPUS {
        let _ = write!(
            out,
            "processor\t: {cpu}\n\
             BogoMIPS\t: 48.00\n\
             Features\t: fp asimd\n\
             CPU implementer\t: 0x61\n\
             CPU architecture: 8\n\
             CPU variant\t: 0x0\n\
             CPU part\t: 0x000\n\
             CPU revision\t: 0\n\n",
        );
    }
    out.into_bytes()
}

/// `/proc/<pid>/stat` content: the standard 52 space-separated fields (see `proc_pid_stat(5)`).
/// `busybox ps` (non-desktop build) parses this for `state`/`comm`/`vsz`; other fields are filled
/// with the least-wrong constant for a single always-running, threadless-as-far-as-`/proc`-cares
/// task, since this process model has no real scheduler accounting to report.
fn render_stat(task: &ProcTaskInfo) -> Vec<u8> {
    let comm = String::from_utf8_lossy(&task.comm);
    format!(
        "{pid} ({comm}) R {ppid} {pgrp} {sid} 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 0 {vsize} {rss} \
         18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0 0 0 0 0 0 0 0\n",
        pid = task.pid,
        ppid = task.ppid,
        pgrp = task.pid,
        sid = task.pid,
        vsize = 4 * 1024 * 1024_u64,
        rss = 256,
    )
    .into_bytes()
}

/// `/proc/<pid>/statm` content: `size resident shared text lib data dt`, all in
/// pages (see `proc_pid_statm(5)`). `resident` (field 2) mirrors the RSS pages
/// `/proc/<pid>/stat` reports in its 24th field (256), which is what libuv's
/// `uv_resident_set_memory` actually reads for `process.memoryUsage().rss`, so a
/// reader consulting either file sees the same resident-set size.
fn render_statm() -> Vec<u8> {
    String::from("512 256 64 64 0 256 0\n").into_bytes()
}

/// `/proc/<pid>/status` content: the handful of `Name:`/`State:`/`Pid:`/`PPid:`/`Uid:`/`Gid:`
/// lines real tools most commonly parse (`sscanf`-style single-token-per-field, so extra
/// whitespace is harmless).
fn render_status(task: &ProcTaskInfo) -> Vec<u8> {
    let comm = String::from_utf8_lossy(&task.comm);
    format!(
        "Name:\t{comm}\n\
         State:\tR (running)\n\
         Tgid:\t{pid}\n\
         Pid:\t{pid}\n\
         PPid:\t{ppid}\n\
         Uid:\t{uid}\t{uid}\t{uid}\t{uid}\n\
         Gid:\t{gid}\t{gid}\t{gid}\t{gid}\n\
         Threads:\t1\n\
         VmSize:\t    4096 kB\n\
         VmRSS:\t     1024 kB\n",
        pid = task.pid,
        ppid = task.ppid,
        uid = task.uid,
        gid = task.gid,
    )
    .into_bytes()
}

/// `/proc/net/dev` content: the two-line header plus one row per interface (see
/// `proc_net_dev(5)`), receive/transmit byte and packet counters. `busybox ifconfig` with no
/// arguments reads this to enumerate interface names before querying each one's address/flags
/// through the `SIOCGIF*` ioctls (see `litebox_shim_linux::syscalls::file::sys_ioctl_siocgif`);
/// without it, `ifconfig`'s no-args form fails at this file open, never reaching those ioctls.
/// Matches the fixed `lo` + `eth0` table both that ioctl handler and the netlink `getifaddrs`
/// path already synthesise. All counters are zero: this process model keeps no real packet
/// accounting, and zero is the same "no traffic yet" shape a freshly booted real interface
/// reports.
fn render_net_dev() -> Vec<u8> {
    String::from(
        "Inter-|   Receive                                                |  Transmit\n \
         face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n \
         lo:       0       0    0    0    0     0          0         0        0       0    0    0    0     0       0          0\n\
         eth0:      0       0    0    0    0     0          0         0        0       0    0    0    0     0       0          0\n",
    )
    .into_bytes()
}

/// Which synthetic directory a walk/dir handle refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcDir {
    /// `/proc` itself.
    Root,
    /// `/proc/<pid>`, the single guest task's directory.
    PidDir,
    /// `/proc/sys`.
    SysDir,
    /// `/proc/sys/kernel`.
    SysKernelDir,
    /// `/proc/net`.
    NetDir,
}

/// Which synthetic file a file handle refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcFile {
    Meminfo,
    Mounts,
    /// System-wide `/proc/stat`.
    StatSystem,
    /// `/proc/cpuinfo`.
    Cpuinfo,
    /// `/proc/sys/kernel/overflowuid`.
    OverflowUid,
    /// `/proc/sys/kernel/overflowgid`.
    OverflowGid,
    PidStat,
    /// `/proc/<pid>/statm`.
    PidStatm,
    PidStatus,
    PidCmdline,
    /// `/proc/net/dev`.
    NetDev,
}

impl ProcFile {
    const ROOT_FILES: &'static [(&'static str, ProcFile)] = &[
        ("meminfo", ProcFile::Meminfo),
        ("mounts", ProcFile::Mounts),
        ("stat", ProcFile::StatSystem),
        ("cpuinfo", ProcFile::Cpuinfo),
    ];
    const PID_DIR_FILES: &'static [(&'static str, ProcFile)] = &[
        ("stat", ProcFile::PidStat),
        ("statm", ProcFile::PidStatm),
        ("status", ProcFile::PidStatus),
        ("cmdline", ProcFile::PidCmdline),
    ];
    const SYS_KERNEL_FILES: &'static [(&'static str, ProcFile)] = &[
        ("overflowuid", ProcFile::OverflowUid),
        ("overflowgid", ProcFile::OverflowGid),
    ];
    const NET_DIR_FILES: &'static [(&'static str, ProcFile)] = &[("dev", ProcFile::NetDev)];

    fn in_dir(dir: ProcDir, name: &str) -> Option<ProcFile> {
        let table = match dir {
            ProcDir::Root => Self::ROOT_FILES,
            ProcDir::PidDir => Self::PID_DIR_FILES,
            ProcDir::SysDir => &[],
            ProcDir::SysKernelDir => Self::SYS_KERNEL_FILES,
            ProcDir::NetDir => Self::NET_DIR_FILES,
        };
        table.iter().find(|(n, _)| *n == name).map(|(_, f)| *f)
    }
}

impl<Platform: RawSyncPrimitivesProvider + 'static> super::backend::private::Sealed
    for Proc<Platform>
{
}

impl<Platform: RawSyncPrimitivesProvider + 'static> BackendHandles for Proc<Platform> {
    type WalkingDirHandle<'a> = ProcDir;
    type FileHandle = ProcFile;
    type DirHandle = ProcDir;
}

const READONLY_DIR_MODE: Mode = Mode::from_bits(
    Mode::RWXU.bits()
        | Mode::RGRP.bits()
        | Mode::XGRP.bits()
        | Mode::ROTH.bits()
        | Mode::XOTH.bits(),
)
.unwrap();
const READONLY_FILE_MODE: Mode =
    Mode::from_bits(Mode::RUSR.bits() | Mode::RGRP.bits() | Mode::ROTH.bits()).unwrap();

impl<Platform: RawSyncPrimitivesProvider + 'static> Backend for Proc<Platform> {
    fn root(&self) -> WalkingDirHandle<'_> {
        WalkingDirHandle::from_typed::<Self>(ProcDir::Root)
    }

    fn walk_directories<'a>(
        &'a self,
        from: WalkingDirHandle<'a>,
        components: &[&str],
    ) -> Result<WalkOutcome<WalkingDirHandle<'a>>, WalkError> {
        let mut current = from.into_typed::<Self>();
        let mut walked = Vec::with_capacity(components.len());
        let mut index = 0;
        while index < components.len() {
            let component = components[index];
            match current {
                ProcDir::Root => {
                    // `/proc/self` is the calling task's own directory. LiteBox
                    // hosts a single guest task, so it resolves to the same
                    // `PidDir` as the numeric pid -- as a directory alias rather
                    // than the symlink real Linux uses, which is enough for the
                    // common `/proc/self/<file>` open (e.g. libuv reading
                    // `/proc/self/statm` for `process.memoryUsage()`).
                    if component == "self"
                        || component
                            .parse::<i32>()
                            .is_ok_and(|pid| pid == self.task_pid())
                    {
                        walked.push(WalkedComponent {
                            permissions: PermissionCheck::ByResolver(PermissionInfo {
                                mode: READONLY_DIR_MODE,
                                owner: self.task_owner(),
                            }),
                        });
                        current = ProcDir::PidDir;
                        index += 1;
                    } else if component == "sys" {
                        walked.push(WalkedComponent {
                            permissions: PermissionCheck::ByResolver(PermissionInfo {
                                mode: READONLY_DIR_MODE,
                                owner: UserInfo::ROOT,
                            }),
                        });
                        current = ProcDir::SysDir;
                        index += 1;
                    } else if component == "net" {
                        walked.push(WalkedComponent {
                            permissions: PermissionCheck::ByResolver(PermissionInfo {
                                mode: READONLY_DIR_MODE,
                                owner: UserInfo::ROOT,
                            }),
                        });
                        current = ProcDir::NetDir;
                        index += 1;
                    } else if ProcFile::in_dir(ProcDir::Root, component).is_some() {
                        return Ok(WalkOutcome {
                            components: walked,
                            last: WalkingDirHandle::from_typed::<Self>(current),
                            stop_reason: WalkStopReason::StoppedAtNonDirectory,
                        });
                    } else {
                        return Err(WalkError::PathError(PathError::NoSuchFileOrDirectory));
                    }
                }
                ProcDir::PidDir => {
                    if ProcFile::in_dir(ProcDir::PidDir, component).is_some() {
                        return Ok(WalkOutcome {
                            components: walked,
                            last: WalkingDirHandle::from_typed::<Self>(current),
                            stop_reason: WalkStopReason::StoppedAtNonDirectory,
                        });
                    }
                    return Err(WalkError::PathError(PathError::NoSuchFileOrDirectory));
                }
                ProcDir::SysDir if component == "kernel" => {
                    walked.push(WalkedComponent {
                        permissions: PermissionCheck::ByResolver(PermissionInfo {
                            mode: READONLY_DIR_MODE,
                            owner: UserInfo::ROOT,
                        }),
                    });
                    current = ProcDir::SysKernelDir;
                    index += 1;
                }
                ProcDir::SysKernelDir => {
                    if ProcFile::in_dir(ProcDir::SysKernelDir, component).is_some() {
                        return Ok(WalkOutcome {
                            components: walked,
                            last: WalkingDirHandle::from_typed::<Self>(current),
                            stop_reason: WalkStopReason::StoppedAtNonDirectory,
                        });
                    }
                    return Err(WalkError::PathError(PathError::NoSuchFileOrDirectory));
                }
                ProcDir::SysDir => {
                    return Err(WalkError::PathError(PathError::NoSuchFileOrDirectory));
                }
                ProcDir::NetDir => {
                    if ProcFile::in_dir(ProcDir::NetDir, component).is_some() {
                        return Ok(WalkOutcome {
                            components: walked,
                            last: WalkingDirHandle::from_typed::<Self>(current),
                            stop_reason: WalkStopReason::StoppedAtNonDirectory,
                        });
                    }
                    return Err(WalkError::PathError(PathError::NoSuchFileOrDirectory));
                }
            }
        }
        Ok(WalkOutcome {
            components: walked,
            last: WalkingDirHandle::from_typed::<Self>(current),
            stop_reason: WalkStopReason::CompleteDirectory,
        })
    }

    fn owned_dir_at(
        &self,
        dir: WalkingDirHandle<'_>,
        _flags: OFlags,
    ) -> Result<DirHandle, OpenError> {
        Ok(DirHandle::from_typed::<Self>(dir.into_typed::<Self>()))
    }

    fn walking_dir_at<'a>(&'a self, dir: &DirHandle) -> Option<WalkingDirHandle<'a>> {
        Some(WalkingDirHandle::from_typed::<Self>(
            *dir.get_typed::<Self>(),
        ))
    }

    fn open_file_at(
        &self,
        dir: WalkingDirHandle<'_>,
        name: &str,
        flags: OFlags,
    ) -> Result<Permissioned<FileHandle>, OpenError> {
        let dir = dir.into_typed::<Self>();
        let file = ProcFile::in_dir(dir, name)
            .ok_or(OpenError::PathError(PathError::NoSuchFileOrDirectory))?;
        if flags.contains(OFlags::DIRECTORY) {
            return Err(OpenError::PathError(PathError::ComponentNotADirectory));
        }
        if flags.intersects(OFlags::CREAT | OFlags::TRUNC | OFlags::WRONLY | OFlags::RDWR) {
            return Err(OpenError::ReadOnlyFileSystem);
        }
        let owner = match dir {
            ProcDir::PidDir => self.task_owner(),
            ProcDir::Root | ProcDir::SysDir | ProcDir::SysKernelDir | ProcDir::NetDir => {
                UserInfo::ROOT
            }
        };
        Ok(Permissioned {
            item: FileHandle::from_typed::<Self>(file),
            permissions: PermissionCheck::ByResolver(PermissionInfo {
                mode: READONLY_FILE_MODE,
                owner,
            }),
        })
    }

    fn list_dir_at(&self, handle: DirHandle) -> Result<Vec<DirEntry>, ReadDirError> {
        let handle = handle.into_typed::<Self>();
        match handle {
            ProcDir::Root => {
                let mut entries: Vec<DirEntry> = ProcFile::ROOT_FILES
                    .iter()
                    .map(|(name, _)| DirEntry {
                        name: String::from(*name),
                        file_type: FileType::RegularFile,
                        ino_info: None,
                    })
                    .collect();
                entries.push(DirEntry {
                    name: format!("{}", self.task_pid()),
                    file_type: FileType::Directory,
                    ino_info: Some(self.inner.pid_dir_inode.clone()),
                });
                entries.push(DirEntry {
                    name: String::from("sys"),
                    file_type: FileType::Directory,
                    ino_info: Some(self.inner.sys_dir_inode.clone()),
                });
                entries.push(DirEntry {
                    name: String::from("net"),
                    file_type: FileType::Directory,
                    ino_info: Some(self.inner.net_dir_inode.clone()),
                });
                Ok(entries)
            }
            ProcDir::PidDir => Ok(ProcFile::PID_DIR_FILES
                .iter()
                .map(|(name, _)| DirEntry {
                    name: String::from(*name),
                    file_type: FileType::RegularFile,
                    ino_info: None,
                })
                .collect()),
            ProcDir::SysDir => Ok(alloc::vec![DirEntry {
                name: String::from("kernel"),
                file_type: FileType::Directory,
                ino_info: Some(self.inner.sys_kernel_dir_inode.clone()),
            }]),
            ProcDir::SysKernelDir => Ok(ProcFile::SYS_KERNEL_FILES
                .iter()
                .map(|(name, _)| DirEntry {
                    name: String::from(*name),
                    file_type: FileType::RegularFile,
                    ino_info: None,
                })
                .collect()),
            ProcDir::NetDir => Ok(ProcFile::NET_DIR_FILES
                .iter()
                .map(|(name, _)| DirEntry {
                    name: String::from(*name),
                    file_type: FileType::RegularFile,
                    ino_info: None,
                })
                .collect()),
        }
    }

    fn read(&self, h: &FileHandle, buf: &mut [u8], offset: usize) -> Result<usize, ReadError> {
        let file = *h.get_typed::<Self>();
        let content = self.render(file);
        let start = offset.min(content.len());
        let end = offset.saturating_add(buf.len()).min(content.len());
        let len = end - start;
        buf[..len].copy_from_slice(&content[start..end]);
        Ok(len)
    }

    fn write(&self, _h: &FileHandle, _buf: &[u8], _offset: usize) -> Result<usize, WriteError> {
        Err(WriteError::NotForWriting)
    }

    fn truncate(&self, _h: &FileHandle, _length: usize) -> Result<(), TruncateError> {
        Err(TruncateError::NotForWriting)
    }

    fn seek_behavior(&self, _h: &FileHandle) -> SeekBehavior {
        SeekBehavior::PositionBased
    }

    fn file_status(&self, h: &FileHandle) -> Result<FileStatus, FileStatusError> {
        let file = *h.get_typed::<Self>();
        let (node_info, owner) = match file {
            ProcFile::Meminfo => (self.inner.meminfo_inode.clone(), UserInfo::ROOT),
            ProcFile::Mounts => (self.inner.mounts_inode.clone(), UserInfo::ROOT),
            ProcFile::StatSystem => (self.inner.stat_system_inode.clone(), UserInfo::ROOT),
            ProcFile::Cpuinfo => (self.inner.cpuinfo_inode.clone(), UserInfo::ROOT),
            ProcFile::OverflowUid => (self.inner.overflowuid_inode.clone(), UserInfo::ROOT),
            ProcFile::OverflowGid => (self.inner.overflowgid_inode.clone(), UserInfo::ROOT),
            ProcFile::PidStat => (self.inner.stat_inode.clone(), self.task_owner()),
            ProcFile::PidStatm => (self.inner.statm_inode.clone(), self.task_owner()),
            ProcFile::PidStatus => (self.inner.status_inode.clone(), self.task_owner()),
            ProcFile::PidCmdline => (self.inner.cmdline_inode.clone(), self.task_owner()),
            ProcFile::NetDev => (self.inner.net_dev_inode.clone(), UserInfo::ROOT),
        };
        Ok(FileStatus {
            file_type: FileType::RegularFile,
            mode: READONLY_FILE_MODE,
            // Real `/proc` files report a fixed small size (often 0) since content is computed;
            // reporting the *actual* rendered length here would require rendering on every
            // `stat`, which real `/proc` doesn't do either. Readers loop on `read` to EOF.
            size: 0,
            owner,
            node_info,
            blksize: PROC_BLOCK_SIZE,
            atime: Timestamp::default(),
            mtime: Timestamp::default(),
            ctime: Timestamp::default(),
        })
    }

    fn dir_status(&self, h: &DirHandle) -> Result<FileStatus, FileStatusError> {
        let dir = *h.get_typed::<Self>();
        let (node_info, owner) = match dir {
            ProcDir::Root => (self.inner.root_inode.clone(), UserInfo::ROOT),
            // `busybox ps` gets a process's uid/gid by `stat`-ing `/proc/<pid>` itself
            // (`PSSCAN_UIDGID`), not by parsing `/proc/<pid>/status` -- this owner is load-bearing.
            ProcDir::PidDir => (self.inner.pid_dir_inode.clone(), self.task_owner()),
            ProcDir::SysDir => (self.inner.sys_dir_inode.clone(), UserInfo::ROOT),
            ProcDir::SysKernelDir => (self.inner.sys_kernel_dir_inode.clone(), UserInfo::ROOT),
            ProcDir::NetDir => (self.inner.net_dir_inode.clone(), UserInfo::ROOT),
        };
        Ok(FileStatus {
            file_type: FileType::Directory,
            mode: READONLY_DIR_MODE,
            size: super::DEFAULT_DIRECTORY_SIZE,
            owner,
            node_info,
            blksize: PROC_BLOCK_SIZE,
            atime: Timestamp::default(),
            mtime: Timestamp::default(),
            ctime: Timestamp::default(),
        })
    }

    fn create_file_at(
        &self,
        _dir: DirHandle,
        _name: &str,
        _mode: Mode,
    ) -> Result<FileHandle, OpenError> {
        Err(OpenError::ReadOnlyFileSystem)
    }

    fn mkdir_at(&self, _dir: DirHandle, _name: &str, _mode: Mode) -> Result<DirHandle, MkdirError> {
        Err(MkdirError::ReadOnlyFileSystem)
    }

    fn unlink_at(&self, _dir: DirHandle, _name: &str) -> Result<(), UnlinkError> {
        Err(UnlinkError::ReadOnlyFileSystem)
    }

    fn rmdir_at(&self, _dir: DirHandle, _name: &str) -> Result<(), RmdirError> {
        Err(RmdirError::ReadOnlyFileSystem)
    }

    fn chmod_at(&self, _dir: DirHandle, _name: &str, _mode: Mode) -> Result<(), ChmodError> {
        Err(ChmodError::ReadOnlyFileSystem)
    }

    fn chmod_file(&self, _h: &FileHandle, _mode: Mode) -> Result<(), ChmodError> {
        Err(ChmodError::ReadOnlyFileSystem)
    }

    fn chmod_dir(&self, _h: &DirHandle, _mode: Mode) -> Result<(), ChmodError> {
        Err(ChmodError::ReadOnlyFileSystem)
    }

    fn chown_at(
        &self,
        _dir: DirHandle,
        _name: &str,
        _user: Option<u16>,
        _group: Option<u16>,
    ) -> Result<(), ChownError> {
        Err(ChownError::ReadOnlyFileSystem)
    }

    fn utimensat_at(
        &self,
        _dir: DirHandle,
        _name: &str,
        _atime: Option<Timestamp>,
        _mtime: Option<Timestamp>,
    ) -> Result<(), UtimeError> {
        Err(UtimeError::ReadOnlyFileSystem)
    }

    fn utimensat_file(
        &self,
        _h: &FileHandle,
        _atime: Option<Timestamp>,
        _mtime: Option<Timestamp>,
    ) -> Result<(), UtimeError> {
        Err(UtimeError::ReadOnlyFileSystem)
    }

    fn utimensat_dir(
        &self,
        _h: &DirHandle,
        _atime: Option<Timestamp>,
        _mtime: Option<Timestamp>,
    ) -> Result<(), UtimeError> {
        Err(UtimeError::ReadOnlyFileSystem)
    }
}
