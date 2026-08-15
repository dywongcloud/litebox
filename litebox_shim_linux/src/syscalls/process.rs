// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Process/thread related syscalls.

use crate::{ShimFS, ShimPlatform, Task, UserPtr, UserPtrMut};
use alloc::boxed::Box;
use alloc::collections::btree_map::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::cell::{Cell, RefCell};
use core::mem::offset_of;
use core::ops::Range;
use core::sync::atomic::{AtomicBool, Ordering};
use core::time::Duration;
use litebox::event::wait::WaitError;
use litebox::mm::linux::VmFlags;
use litebox::platform::TimerHandle;
use litebox::platform::{ArchSpecificRegister, RawMutex as _};
use litebox::platform::{Instant as _, SystemTime as _, TimeProvider};
use litebox::sync::Mutex;
use litebox::utils::TruncateExt as _;
use litebox_common_linux::{
    ArchPrctlArg, CloneFlags, FutexArgs, IntervalTimer, ItimerVal, PrctlArg, TimeParam,
    errno::Errno,
};

/// Process-management-related state on [`Task`].
pub(crate) struct ThreadState<Platform: ShimPlatform> {
    init_state: Cell<ThreadInitState>,
    process: Arc<Process<Platform>>,
    /// Thread state that can be accessed from a remote thread.
    remote: Arc<ThreadRemote<Platform>>,
    attached_tid: Cell<Option<i32>>,
    /// When a thread whose `clear_child_tid` is not `None` terminates, and it shares memory with other threads,
    /// the kernel writes 0 to the address specified by `clear_child_tid` and then executes:
    ///
    /// futex(clear_child_tid, FUTEX_WAKE, 1, NULL, NULL, 0);
    ///
    /// This operation wakes a single thread waiting on the specified memory location via futex.
    /// Any errors from the futex wake operation are ignored.
    clear_child_tid: Cell<Option<UserPtrMut<i32>>>,
    /// The purpose of the robust futex list is to ensure that if a thread accidentally fails to unlock a futex before
    /// terminating or calling execve(2), another thread that is waiting on that futex is notified that the former owner
    /// of the futex has died. This notification consists of two pieces: the FUTEX_OWNER_DIED bit is set in the futex word,
    /// and the kernel performs a futex(2) FUTEX_WAKE operation on one of the threads waiting on the futex.
    robust_list: Cell<Option<UserPtr<litebox_common_linux::RobustListHead>>>,
}

// TODO: remove once we figure out how to handle Send/Sync for raw pointers.
unsafe impl<Platform: ShimPlatform> Send for ThreadState<Platform> {}

impl<Platform: ShimPlatform> ThreadState<Platform> {
    pub fn new_process(pid: i32) -> Self {
        let remote = Arc::new(ThreadRemote::new());
        Self {
            init_state: Cell::new(ThreadInitState::None),
            process: Arc::new(Process::new(pid, remote.clone())),
            remote,
            attached_tid: Cell::new(Some(pid)),
            clear_child_tid: Cell::new(None),
            robust_list: Cell::new(None),
        }
    }

    pub(crate) fn new_thread(&self, tid: i32) -> Option<Self> {
        let remote = self.process.attach_thread(tid)?;
        Some(Self {
            init_state: Cell::new(ThreadInitState::None),
            process: self.process.clone(),
            remote,
            attached_tid: Cell::new(Some(tid)),
            clear_child_tid: Cell::new(None),
            robust_list: Cell::new(None),
        })
    }

    /// Detaches this thread from its process.
    ///
    /// Returns `true` if this was the last thread of the process to detach (i.e., the whole
    /// process is now gone), `false` otherwise -- including when this thread was already
    /// detached (so callers relying on this to run exactly-once cleanup, like closing every fd
    /// on process exit, don't double-run it if `Drop` invokes this a second time).
    fn detach_from_process(&self) -> bool {
        if let Some(tid) = self.attached_tid.take() {
            self.process.detach_thread(tid)
        } else {
            false
        }
    }
}

impl<Platform: ShimPlatform> Drop for ThreadState<Platform> {
    fn drop(&mut self) {
        self.detach_from_process();
    }
}

/// Thread state that can be accessed from a remote thread.
/// Closed bit of [`Process::fork_gate`]'s word; the low 31 bits count parked
/// threads.
const FORK_GATE_CLOSED: u32 = 1 << 31;

/// Reopens a [`Process::fork_gate`] closed by
/// [`Task::park_sibling_threads_for_fork`] when dropped, releasing every
/// parked sibling. Held across the whole of `do_fork`'s remaining body --
/// including the parent's suspension for the child's address-space turn -- so
/// the gate reopens on success, on any error return, and on panic alike.
struct ForkGateGuard<'a, Platform: ShimPlatform> {
    process: &'a Process<Platform>,
}

impl<Platform: ShimPlatform> Drop for ForkGateGuard<'_, Platform> {
    fn drop(&mut self) {
        self.process
            .fork_gate
            .underlying_atomic()
            .fetch_and(!FORK_GATE_CLOSED, Ordering::AcqRel);
        self.process.fork_gate.wake_all();
    }
}

struct ThreadRemote<Platform: ShimPlatform> {
    /// Always set under the process `inner` lock, but can be read without
    /// locking.
    is_exiting: AtomicBool,
    /// Handle to interrupt waits on this thread.
    handle: once_cell::race::OnceBox<litebox::event::wait::ThreadHandle<Platform>>,
}

impl<Platform: ShimPlatform> ThreadRemote<Platform> {
    fn new() -> Self {
        Self {
            is_exiting: AtomicBool::new(false),
            handle: once_cell::race::OnceBox::new(),
        }
    }

    fn interrupt(&self) {
        if let Some(handle) = self.handle.get() {
            handle.interrupt();
        }
    }
}

/// A Linux process, which may have multiple threads.
pub(crate) struct Process<Platform: ShimPlatform> {
    /// Number of threads in this process. Always updated under the `inner`
    /// mutex lock.
    nr_threads: <Platform as litebox::platform::RawMutexProvider>::RawMutex,
    /// Stop-the-world gate for `fork` from a multithreaded process.
    ///
    /// The delayed-address-space-handoff fork model (see [`SharedAddressSpace`])
    /// requires that no sibling thread touches guest memory during the child's
    /// turn: the parent's private memory is snapshotted at `fork` and restored
    /// when the turn comes back, so a sibling that kept running would have its
    /// writes silently rolled back. Rather than refusing `fork` outright for
    /// multithreaded guests (which breaks every libuv/Node `spawn`, whose
    /// child does nothing but the classic dup2/close/execve dance), the
    /// forking thread closes this gate: every sibling parks here -- woken out
    /// of any interruptible wait by [`ThreadRemote::interrupt`] and caught at
    /// the [`CheckForInterrupt::check_for_interrupt`]/
    /// [`Task::prepare_to_run_guest`] choke points before it can touch guest
    /// memory again -- until the parent's turn resumes and the gate reopens.
    ///
    /// Word layout: bit 31 = closed; low 31 bits = number of currently-parked
    /// threads. Mirrors how `nr_threads` uses its `RawMutex` word purely as a
    /// blockable atomic.
    fork_gate: <Platform as litebox::platform::RawMutexProvider>::RawMutex,
    inner: Mutex<Platform, ProcessInner<Platform>>,
    /// Resource limits for this process.
    pub(crate) limits: ResourceLimits,
    /// Process-wide alarm timer.
    pub(crate) alarm_timer: Mutex<Platform, Alarm<Platform>>,
    /// The address ranges this process (as opposed to some other guest process sharing the same
    /// host address space) had mapped.
    ///
    /// Needed because `fork` has to be able to save and restore *this* process's memory without
    /// touching a sibling's -- see [`Task::save_address_space`]. The page manager's own view is
    /// process-blind: it is one flat map of every guest mapping in the shim.
    pub(crate) owned_ranges: Mutex<Platform, OwnedRanges>,
    /// This process's program break.
    ///
    /// Every guest process shares one [`litebox::mm::PageManager`] (they live at disjoint
    /// addresses in the one host address space), and that manager tracks a single break, so the
    /// authoritative per-process value has to live here and be swapped into the manager around
    /// each break operation. See `Task::sys_brk`.
    pub(crate) brk: core::sync::atomic::AtomicUsize,
    /// Total host CPU time (nanoseconds) consumed by every thread of this process so far.
    ///
    /// Each thread adds its own [`litebox::platform::TimeProvider::thread_cpu_time`] reading
    /// here as it exits (see
    /// `Task::prepare_for_exit`), since that clock is only readable by the thread it measures.
    /// Reported to a `wait4(..., &rusage)` caller as `ru_utime` once the whole process is a
    /// zombie -- see `Task::sys_wait4`.
    pub(crate) cpu_time_nanos: core::sync::atomic::AtomicU64,
}

/// A set of address ranges, kept sorted and non-overlapping.
///
/// Small and linear on purpose: it holds one entry per live mapping of a single guest process,
/// which is a handful for the programs this shim runs, and it is only walked when that process
/// `fork`s.
#[derive(Clone, Default)]
pub(crate) struct OwnedRanges {
    ranges: Vec<Range<usize>>,
}

impl OwnedRanges {
    /// Adds `range`, replacing anything it overlaps.
    pub(crate) fn insert(&mut self, range: Range<usize>) {
        if range.is_empty() {
            return;
        }
        self.remove(range.clone());
        let at = self.ranges.partition_point(|r| r.start < range.start);
        self.ranges.insert(at, range);
    }

    /// Removes `range`, splitting any entry that only partially overlaps it.
    pub(crate) fn remove(&mut self, range: Range<usize>) {
        if range.is_empty() {
            return;
        }
        let mut out = Vec::with_capacity(self.ranges.len() + 1);
        for r in self.ranges.drain(..) {
            if r.end <= range.start || r.start >= range.end {
                out.push(r);
                continue;
            }
            if r.start < range.start {
                out.push(r.start..range.start);
            }
            if r.end > range.end {
                out.push(range.end..r.end);
            }
        }
        self.ranges = out;
    }

    pub(crate) fn clear(&mut self) {
        self.ranges.clear();
    }

    /// The parts of `range` that this set covers.
    fn intersect(&self, range: &Range<usize>) -> impl Iterator<Item = Range<usize>> + '_ {
        let range = range.clone();
        self.ranges.iter().filter_map(move |r| {
            let start = r.start.max(range.start);
            let end = r.end.min(range.end);
            (start < end).then_some(start..end)
        })
    }
}

/// One guest address space, shared by a `fork`ed child and its parent, plus the hand-off that
/// keeps exactly one of them running on it at a time.
///
/// LiteBox executes guest code natively, so a guest virtual address *is* a host virtual address
/// (see `litebox::mm::linux::Vmem::insert_mapping`, which passes the guest's own range straight to
/// the platform allocator). One host address space therefore cannot hold two guest processes that
/// both believe they own the same addresses, which is exactly what a copying `fork` would have to
/// produce. So the child runs in the parent's address space, on the parent's stack.
///
/// What this type adds is that the parent does not have to stay suspended for the child's whole
/// lifetime. The address space is a *token*. Its holder is the one member whose memory is
/// currently live in it; every other member is parked, holding a host-memory copy of its own view
/// (see [`AddressSpaceMembership::parked`]). A member gives the token up whenever it is about to
/// block -- `litebox::event::wait::CheckForInterrupt::yield_while_blocking`, which fires for every
/// interruptible wait in the shim -- and takes it back before it looks at guest memory again.
/// Since a member only ever reads or writes guest memory while it holds the token, and taking the
/// token restores that member's own copy, each member sees exactly the memory `fork(2)` promises
/// it.
///
/// That is what makes a `fork`ed child that never `execve`s -- a shell builtin on the left of a
/// pipeline, a background subshell -- able to run concurrently with its parent: when it blocks on
/// a full pipe, the parent gets the address space back and can fork the stage that drains it.
///
/// A member leaves for good when it `execve`s (the new image is loaded at addresses no other
/// member owns, so it no longer needs the token) or when it exits.
///
/// Known limits, all of them "it hangs", never "it silently returns the wrong bytes":
///
/// * A member that never blocks and never exits starves the others. The token is only ever
///   yielded voluntarily; there is no preemption, because memory cannot be taken away from a
///   thread that is in the middle of executing guest instructions on it.
/// * `CLONE_THREAD` threads of a member do not join the family, so a guest that `fork`s from a
///   multithreaded process still gets the old, single-holder behaviour for its extra threads.
///   Guests in scope here (shells) are single-threaded when they fork.
pub(crate) struct SharedAddressSpace<Platform: ShimPlatform> {
    /// [`ADDRESS_SPACE_FREE`], or the tid of the member holding the token. Used directly as the
    /// word members block on while waiting to acquire.
    holder: <Platform as litebox::platform::RawMutexProvider>::RawMutex,
}

/// A copy of a guest process's private memory, as `(start address, contents)` pairs.
type MemoryImage = Vec<(usize, alloc::boxed::Box<[u8]>)>;

/// One member's place in a [`SharedAddressSpace`].
pub(crate) struct AddressSpaceMembership<Platform: ShimPlatform> {
    shared: Arc<SharedAddressSpace<Platform>>,
    /// Whether this member currently holds the token.
    holding: Cell<bool>,
    /// This member's copy of its own private memory, taken when it gave the token up. `Some`
    /// exactly while [`Self::holding`] is false and the member still intends to come back.
    parked: RefCell<Option<MemoryImage>>,
}

/// The value of [`SharedAddressSpace::holder`] when no member holds the token. No tid is ever
/// zero, so this cannot collide with one.
const ADDRESS_SPACE_FREE: u32 = 0;

/// Encodes a tid as a [`SharedAddressSpace::holder`] value.
fn tid_as_holder(tid: i32) -> u32 {
    let raw = tid.cast_unsigned();
    assert_ne!(raw, ADDRESS_SPACE_FREE, "tid 0 cannot own an address space");
    raw
}

impl<Platform: ShimPlatform> SharedAddressSpace<Platform> {
    /// How long to block before re-checking whether this task is being torn down. The token is
    /// handed over explicitly, so this only bounds how long a *dying* task waits for a holder
    /// that will never release; it is not a polling interval in the normal case.
    const ABANDON_CHECK_INTERVAL: Duration = Duration::from_millis(20);

    fn new(initial_holder: i32) -> Self {
        let holder = <Platform as litebox::platform::RawMutexProvider>::RawMutex::INIT;
        holder
            .underlying_atomic()
            .store(tid_as_holder(initial_holder), Ordering::Relaxed);
        Self { holder }
    }

    /// Blocks until the token is free and takes it for `tid`.
    ///
    /// Returns `false` if `abandon` became true first, which only happens when the caller is
    /// being torn down and will never run guest code again.
    fn acquire(&self, tid: i32, mut abandon: impl FnMut() -> bool) -> bool {
        let me = tid_as_holder(tid);
        loop {
            match self.holder.underlying_atomic().compare_exchange(
                ADDRESS_SPACE_FREE,
                me,
                Ordering::Acquire,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(current) => {
                    if abandon() {
                        return false;
                    }
                    let _ = self
                        .holder
                        .block_or_timeout(current, Self::ABANDON_CHECK_INTERVAL);
                }
            }
        }
    }

    /// Gives the token up, waking anything waiting for it.
    fn release(&self) {
        self.holder
            .underlying_atomic()
            .store(ADDRESS_SPACE_FREE, Ordering::Release);
        self.holder.wake_all();
    }

    /// Passes the token straight to `tid` without ever making it free.
    ///
    /// Used by `fork`: the child is not running yet and so cannot [`Self::acquire`] for itself,
    /// and a free window here would let some other member take the address space out from under
    /// it before its first instruction.
    fn hand_off_to(&self, tid: i32) {
        self.holder
            .underlying_atomic()
            .store(tid_as_holder(tid), Ordering::Release);
    }
}

/// Parent/child relationships and exit statuses of every guest process in the shim.
///
/// This is the bookkeeping `wait4` reaps from. It is deliberately separate from [`Process`],
/// which models a *thread group*: a zombie has to outlive its `Process` (the parent may not call
/// `wait4` until long after the child's last thread is gone), and a waiting parent has to be able
/// to name a child it holds no reference to.
pub(crate) struct ProcessTable<Platform: ShimPlatform> {
    inner: Mutex<Platform, ProcessTableInner<Platform>>,
}

struct ProcessTableInner<Platform: ShimPlatform> {
    /// Every live or zombie child, keyed by its pid.
    children: BTreeMap<i32, ChildRecord>,
    /// Parents currently blocked in `wait4`, as (parent pid, registration token, waker).
    waiters: Vec<(i32, u64, litebox::event::wait::Waker<Platform>)>,
    next_waiter_token: u64,
    /// Every live guest process, so that a signal can be posted to one of them from another.
    live: BTreeMap<i32, LiveProcess<Platform>>,
}

/// The handle needed to post a process-directed signal to another guest process.
///
/// Deliberately not a `Task`: the sender runs on a different host thread, and a `Task` is
/// full of `Cell`s and `RefCell`s that only its own thread may touch. Everything here is
/// `Sync`.
struct LiveProcess<Platform: ShimPlatform> {
    /// The target's process-wide pending queue -- the same one its own threads drain from.
    /// Survives `execve` (which replaces the handler table, not this).
    signals: crate::syscalls::signal::RemoteSignalTarget<Platform>,
}

struct ChildRecord {
    ppid: i32,
    /// `None` while the child is still running; `Some` once it is a zombie awaiting `wait4`.
    status: Option<ExitStatus>,
    /// Total host CPU time (nanoseconds) the child consumed, set alongside `status`. See
    /// `Process::cpu_time_nanos`.
    cpu_time_nanos: u64,
}

impl<Platform: ShimPlatform> ProcessTable<Platform> {
    pub(crate) fn new() -> Self {
        Self {
            inner: Mutex::new(ProcessTableInner {
                children: BTreeMap::new(),
                waiters: Vec::new(),
                next_waiter_token: 0,
                live: BTreeMap::new(),
            }),
        }
    }

    /// Records a newly `fork`ed child of `parent`.
    fn add_child(&self, child: i32, parent: i32) {
        let old = self.inner.lock().children.insert(
            child,
            ChildRecord {
                ppid: parent,
                status: None,
                cpu_time_nanos: 0,
            },
        );
        assert!(old.is_none(), "pid {child} is already live");
    }

    /// Registers a live guest process so signals can be posted to it.
    fn register_process(
        &self,
        pid: i32,
        signals: crate::syscalls::signal::RemoteSignalTarget<Platform>,
    ) {
        self.inner.lock().live.insert(pid, LiveProcess { signals });
    }

    /// Removes a process that has exited from the live set.
    fn unregister_process(&self, pid: i32) {
        self.inner.lock().live.remove(&pid);
    }

    /// Turns `child` into a zombie carrying `status`, wakes its parent if one is waiting, and
    /// posts `SIGCHLD` to that parent.
    ///
    /// Does nothing for a pid with no recorded parent (the initial process, or a child whose
    /// parent already exited and dropped it).
    fn record_exit(&self, child: i32, status: ExitStatus, cpu_time_nanos: u64) {
        let mut inner = self.inner.lock();
        let Some(record) = inner.children.get_mut(&child) else {
            return;
        };
        record.status = Some(status);
        record.cpu_time_nanos = cpu_time_nanos;
        let parent = record.ppid;
        let wakers: Vec<_> = inner
            .waiters
            .iter()
            .filter(|(waiting, _, _)| *waiting == parent)
            .map(|(_, _, waker)| waker.clone())
            .collect();
        // Queue the parent's `SIGCHLD` before the wakeups, so that whichever of its threads wakes
        // first already finds the signal pending.
        //
        // Without this, a guest that blocks waiting for `SIGCHLD` -- which is exactly how
        // busybox's `ash` implements a blocking `wait`, via `sigsuspend` -- never wakes up. The
        // signal is discarded harmlessly by a parent that has no `SIGCHLD` handler; see
        // [`Task::has_pending_signals`].
        if let Some(live) = inner.live.get(&parent) {
            live.signals.post(
                litebox_common_linux::signal::Signal::SIGCHLD,
                crate::syscalls::signal::siginfo_child_exited(child, status),
            );
        }
        drop(inner);
        for waker in wakers {
            waker.wake();
        }
    }

    /// Drops every record naming `parent` as a parent.
    ///
    /// Real Linux reparents orphans to init, which then reaps them; this shim has no init, and a
    /// record nobody can ever wait on is just a leak, so they are discarded instead.
    fn discard_children_of(&self, parent: i32) {
        self.inner.lock().children.retain(|_, r| r.ppid != parent);
    }

    /// Whether `parent` has any child matching `filter`, zombie or not.
    fn has_child(&self, parent: i32, filter: WaitFilter) -> bool {
        self.inner
            .lock()
            .children
            .iter()
            .any(|(&child, r)| r.ppid == parent && filter.matches(child))
    }

    /// Reaps one zombie child of `parent` matching `filter`, removing it from the table.
    fn reap(&self, parent: i32, filter: WaitFilter) -> Option<(i32, ExitStatus, u64)> {
        let mut inner = self.inner.lock();
        let (child, status, cpu_time_nanos) = inner.children.iter().find_map(|(&child, r)| {
            (r.ppid == parent && filter.matches(child))
                .then_some(r.status)
                .flatten()
                .map(|status| (child, status, r.cpu_time_nanos))
        })?;
        inner.children.remove(&child);
        Some((child, status, cpu_time_nanos))
    }

    /// Whether [`Self::reap`] would find something right now, without consuming it.
    fn reap_ready(&self, parent: i32, filter: WaitFilter) -> bool {
        self.inner
            .lock()
            .children
            .iter()
            .any(|(&child, r)| r.ppid == parent && filter.matches(child) && r.status.is_some())
    }

    /// Drops `child`'s record entirely, waited for or not.
    fn forget(&self, child: i32) {
        self.inner.lock().children.remove(&child);
    }

    pub(crate) fn register_waiter(
        &self,
        parent: i32,
        waker: litebox::event::wait::Waker<Platform>,
    ) -> u64 {
        let mut inner = self.inner.lock();
        let token = inner.next_waiter_token;
        inner.next_waiter_token += 1;
        inner.waiters.push((parent, token, waker));
        token
    }

    pub(crate) fn unregister_waiter(&self, token: u64) {
        self.inner.lock().waiters.retain(|(_, t, _)| *t != token);
    }
}

/// The guest stack pointer recorded in a saved register context.
pub(crate) fn guest_stack_pointer(ctx: &litebox_common_linux::PtRegs) -> usize {
    #[cfg(target_arch = "x86_64")]
    {
        ctx.rsp
    }
    #[cfg(target_arch = "aarch64")]
    {
        ctx.sp
    }
}

/// Packs an exit status into the `int` layout `wait4`'s `wstatus` uses, as decoded by libc's
/// `WIFEXITED`/`WEXITSTATUS`/`WTERMSIG` macros: a normal exit puts the code in bits 8..16 and
/// leaves the low seven bits (the terminating signal) zero, while a signal death puts the signal
/// number in those low bits.
fn encode_wait_status(status: ExitStatus) -> i32 {
    match status {
        ExitStatus::Exit(code) => (i32::from(code) & 0xff) << 8,
        ExitStatus::Signal(signal) => signal.as_i32() & 0x7f,
    }
}

/// Which children a `wait4` call is willing to reap.
#[derive(Clone, Copy)]
enum WaitFilter {
    /// `pid < -1` and `pid == 0` (process-group waits) are not distinguished from `-1` here:
    /// this shim has a single process group.
    Any,
    Pid(i32),
}

impl WaitFilter {
    fn matches(self, pid: i32) -> bool {
        match self {
            WaitFilter::Any => true,
            WaitFilter::Pid(p) => p == pid,
        }
    }
}

pub(crate) struct Alarm<Platform: ShimPlatform> {
    /// Handle for the alarm timer.
    pub(crate) handle: Option<<Platform as litebox::platform::TimerProvider>::TimerHandle>,
    /// The deadline for the alarm.
    pub(crate) deadline: Option<<Platform as litebox::platform::TimeProvider>::Instant>,
}

impl<Platform: ShimPlatform> Alarm<Platform> {
    /// Returns the time remaining until [`Self::deadline`], or zero if the
    /// alarm is not armed or its deadline has already passed.
    pub(crate) fn remaining(
        &self,
        now: <Platform as litebox::platform::TimeProvider>::Instant,
    ) -> Duration {
        self.deadline
            .as_ref()
            .and_then(|d| d.checked_duration_since(&now))
            .unwrap_or(Duration::ZERO)
    }
}

/// The locked portion of the process state.
struct ProcessInner<Platform: ShimPlatform> {
    /// If true, the whole process is exiting.
    group_exit: bool,
    /// If true, one thread is waiting for other threads to exit.
    is_killing_other_threads: bool,
    /// The exit code of the last exited thread in the process. Not updated once
    /// `group_exit` is set.
    exit_status: ExitStatus,
    /// The thread list for the process, mapped by thread ID.
    threads: BTreeMap<i32, Arc<ThreadRemote<Platform>>>,
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum ExitStatus {
    Exit(i8),
    Signal(litebox_common_linux::signal::Signal),
}

impl<Platform: ShimPlatform> Process<Platform> {
    /// Creates a new process with the given initial thread.
    fn new(pid: i32, remote: Arc<ThreadRemote<Platform>>) -> Self {
        let nr_threads = <Platform as litebox::platform::RawMutexProvider>::RawMutex::INIT;
        nr_threads.underlying_atomic().store(1, Ordering::Relaxed);
        let fork_gate = <Platform as litebox::platform::RawMutexProvider>::RawMutex::INIT;
        fork_gate.underlying_atomic().store(0, Ordering::Relaxed);
        Self {
            nr_threads,
            fork_gate,
            inner: Mutex::new(ProcessInner {
                exit_status: ExitStatus::Exit(0),
                group_exit: false,
                is_killing_other_threads: false,
                threads: BTreeMap::from_iter([(pid, remote)]),
            }),
            limits: ResourceLimits::default(),
            alarm_timer: Mutex::new(Alarm {
                handle: None,
                deadline: None,
            }),
            brk: core::sync::atomic::AtomicUsize::new(0),
            owned_ranges: Mutex::new(OwnedRanges::default()),
            cpu_time_nanos: core::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Returns the current number of threads in this process.
    pub fn nr_threads(&self) -> u32 {
        self.nr_threads.underlying_atomic().load(Ordering::Relaxed)
    }

    /// Parks the calling thread while this process's fork gate is closed.
    ///
    /// The fast path -- gate open, the only case any thread sees outside a
    /// concurrent multithreaded `fork` -- is a single atomic load. A parked
    /// thread blocks on the raw gate word (never an interruptible wait: this
    /// is called from [`CheckForInterrupt::check_for_interrupt`], whose
    /// contract forbids interruptible waiting) and resumes when
    /// [`ForkGateGuard`] reopens the gate. An exiting thread never parks --
    /// it proceeds to detach, and `detach_thread` wakes the gate so the
    /// forker re-evaluates how many siblings it is still waiting for.
    fn park_while_fork_gate_closed(&self, is_exiting: bool) {
        let word = self.fork_gate.underlying_atomic();
        if word.load(Ordering::Acquire) & FORK_GATE_CLOSED == 0 {
            return;
        }
        if is_exiting {
            return;
        }
        word.fetch_add(1, Ordering::AcqRel);
        // The forker blocks on this same word until enough siblings are
        // parked; every increment must wake it to re-count.
        self.fork_gate.wake_all();
        loop {
            let cur = word.load(Ordering::Acquire);
            if cur & FORK_GATE_CLOSED == 0 {
                break;
            }
            let _ = self.fork_gate.block(cur);
        }
        word.fetch_sub(1, Ordering::AcqRel);
    }

    /// Waits for all threads in this process to exit, returning the exit code.
    pub fn wait_for_exit(&self) -> ExitStatus {
        loop {
            let n = self.nr_threads.underlying_atomic().load(Ordering::Acquire);
            if n == 0 {
                break;
            }
            let _ = self.nr_threads.block(n);
        }
        self.inner.lock().exit_status
    }

    /// Attaches a new thread to this process, returning a new remote state for
    /// the thread.
    fn attach_thread(&self, tid: i32) -> Option<Arc<ThreadRemote<Platform>>> {
        // Allocate outside the lock.
        let remote = Arc::new(ThreadRemote::new());
        let mut inner = self.inner.lock();
        if inner.group_exit || inner.is_killing_other_threads {
            return None;
        }
        let old_thread = inner.threads.insert(tid, remote.clone());
        assert!(old_thread.is_none(), "thread ID {tid} already exists");
        let nr_threads = self.nr_threads.underlying_atomic();
        nr_threads.store(nr_threads.load(Ordering::Relaxed) + 1, Ordering::Release);
        Some(remote)
    }

    /// Detaches a thread from this process.
    ///
    /// Returns `true` if this was the last thread in the process (i.e., the process as a whole
    /// is now exiting), `false` if other threads remain.
    ///
    /// # Panics
    /// Panics if the thread ID does not exist in this process.
    fn detach_thread(&self, tid: i32) -> bool {
        let data;
        let (notify, is_last_thread) = {
            let mut inner = self.inner.lock();
            data = inner.threads.remove(&tid);
            assert!(data.is_some());

            let nr_threads = self.nr_threads.underlying_atomic();
            let n = nr_threads.load(Ordering::Relaxed);
            let new_count = n.checked_sub(1).expect("decrementing from zero threads");
            nr_threads.store(new_count, Ordering::Release);
            let is_last_thread = new_count == 0;
            if is_last_thread {
                assert!(inner.threads.is_empty());
                // The last thread exited. Prevent new threads.
                inner.group_exit = true;
            }

            // Notify waiters if this is the last thread of the process
            // (`wait_for_exit`) or if this is the last thread being killed
            // during an exec (`kill_other_threads`).
            (
                is_last_thread || (new_count == 1 && inner.is_killing_other_threads),
                is_last_thread,
            )
        };
        if notify {
            self.nr_threads.wake_all();
        }
        // A forker blocked in `park_sibling_threads_for_fork` counts parked
        // siblings against `nr_threads`; an exiting sibling shrinks the
        // latter without ever parking, so the forker must recount.
        if self.fork_gate.underlying_atomic().load(Ordering::Acquire) & FORK_GATE_CLOSED != 0 {
            self.fork_gate.wake_all();
        }
        is_last_thread
    }
}

impl<Platform: ShimPlatform, FS: ShimFS> Task<Platform, FS> {
    /// Updates the process exit status for a thread exit.
    fn exit_thread(&self, code: i8) {
        let mut inner = self.thread.process.inner.lock();
        if self.is_exiting() {
            return;
        }
        inner.exit_status = ExitStatus::Exit(code);
        self.thread.remote.is_exiting.store(true, Ordering::Relaxed);
    }

    /// Updates the process exit status for a group exit and signals all threads
    /// to exit.
    pub(crate) fn exit_group(&self, status: ExitStatus) {
        let mut inner = self.thread.process.inner.lock();
        if self.is_exiting() {
            return;
        }
        assert!(!inner.group_exit);
        inner.exit_status = status;
        inner.group_exit = true;
        for thread in inner.threads.values() {
            thread.is_exiting.store(true, Ordering::Relaxed);
            thread.interrupt();
        }
    }

    /// Closes the process's fork gate and waits until every sibling thread is
    /// parked at it, so the caller can take the address-space turn (see
    /// [`SharedAddressSpace`]) with the same guarantees a single-threaded
    /// process has: nothing else will touch guest memory until the returned
    /// guard reopens the gate.
    ///
    /// Modeled on [`Self::kill_other_threads`]'s stop-the-world shape:
    /// interrupt every sibling ([`ThreadRemote::interrupt`] wakes a thread
    /// blocked in any interruptible shim wait, and yanks one executing guest
    /// code back into the shim via the platform interrupt), then block on the
    /// gate word until the parked count accounts for every sibling. A sibling
    /// mid-syscall parks at the next
    /// [`CheckForInterrupt::check_for_interrupt`] or
    /// [`Task::prepare_to_run_guest`] point -- in particular, one mid-copy
    /// into guest memory finishes that copy *before* parking, so the snapshot
    /// taken after this returns cannot lose an in-flight write. Siblings that
    /// exit instead of parking are handled by `detach_thread` waking the gate
    /// so the count converges either way.
    /// [`Process::park_while_fork_gate_closed`] for this task; see
    /// `Process::fork_gate`. Called from the two guest-memory choke points in
    /// `crate::wait`.
    pub(crate) fn park_while_fork_gate_closed(&self) {
        self.process()
            .park_while_fork_gate_closed(self.is_exiting());
    }

    fn park_sibling_threads_for_fork(&self) -> ForkGateGuard<'_, Platform> {
        let process = self.process();
        let word = process.fork_gate.underlying_atomic();
        // If another thread is mid-fork, park like any other sibling until
        // its gate reopens, then take our own turn.
        loop {
            let prev = word.fetch_or(FORK_GATE_CLOSED, Ordering::AcqRel);
            if prev & FORK_GATE_CLOSED == 0 {
                break;
            }
            process.park_while_fork_gate_closed(self.is_exiting());
        }
        let guard = ForkGateGuard { process };
        {
            let inner = process.inner.lock();
            for (&tid, thread) in &inner.threads {
                if tid != self.tid {
                    thread.interrupt();
                }
            }
        }
        loop {
            let cur = word.load(Ordering::Acquire);
            let parked = cur & !FORK_GATE_CLOSED;
            let others = process.nr_threads().saturating_sub(1);
            if parked >= others {
                break;
            }
            let _ = process.fork_gate.block(cur);
        }
        guard
    }

    /// Kills all other threads in the process, waiting for them to exit.
    ///
    /// Returns false if this thread is already exiting.
    #[must_use]
    fn kill_other_threads(&self) -> bool {
        {
            let mut inner = self.thread.process.inner.lock();
            if self.is_exiting() {
                return false;
            }
            for (&tid, thread) in &inner.threads {
                if tid == self.tid {
                    continue;
                }
                thread.is_exiting.store(true, Ordering::Relaxed);
                thread.interrupt();
            }
            assert!(!inner.is_killing_other_threads);
            inner.is_killing_other_threads = true;
        }
        // Wait for other threads to exit.
        loop {
            let n = self
                .thread
                .process
                .nr_threads
                .underlying_atomic()
                .load(Ordering::Acquire);
            if n == 1 {
                break;
            }
            let _ = self.thread.process.nr_threads.block(n);
        }
        self.thread.process.inner.lock().is_killing_other_threads = false;
        true
    }

    /// Returns true if the task is exiting and should not continue running
    /// guest code.
    pub fn is_exiting(&self) -> bool {
        self.thread.remote.is_exiting.load(Ordering::Relaxed)
    }
}

#[derive(Default)]
enum ThreadInitState {
    #[default]
    None,
    NewProcess(crate::loader::elf::ElfLoadInfo),
    NewThread {
        stack: Option<usize>,
        tls: Option<ThreadLocalDescriptor>,
        set_child_tid: Option<UserPtrMut<i32>>,
    },
}

/// Credentials of a process
#[derive(Clone)]
pub(crate) struct Credentials {
    pub uid: u32,
    pub euid: u32,
    pub gid: u32,
    pub egid: u32,
}

impl<Platform: ShimPlatform, FS: ShimFS> Task<Platform, FS> {
    pub(crate) fn process(&self) -> &Arc<Process<Platform>> {
        &self.thread.process
    }

    /// Set the current task's command name.
    pub(crate) fn set_task_comm(&self, comm: &[u8]) {
        let mut new_comm = [0u8; litebox_common_linux::TASK_COMM_LEN];
        let comm = &comm[..comm.len().min(litebox_common_linux::TASK_COMM_LEN - 1)];
        new_comm[..comm.len()].copy_from_slice(comm);
        self.comm.set(new_comm);

        // Publish to `/proc/<pid>/{stat,status,comm}`, if a `/proc` is mounted. `pid`/`ppid`
        // never change after task construction, and live `setuid`/`setgid` credential changes
        // are not tracked here (out of this call's scope); re-publishing them on every `comm`
        // change is simply cheaper than a separate first-publish flag, not a claim that they can
        // change. Note that this backend is shim-wide while pids now are not: with `fork`, the
        // last task to publish wins, so `/proc/self` describes whichever process most recently
        // `exec`ed rather than the reader.
        if let Some(proc) = &self.global.proc_handle {
            let credentials = self.credentials.borrow();
            proc.set_identity(self.pid, self.ppid, credentials.uid, credentials.gid);
            proc.set_comm(&new_comm);
        }
    }

    /// Handle syscall `prctl`.
    pub(crate) fn sys_prctl(&self, arg: PrctlArg) -> Result<usize, Errno> {
        match arg {
            PrctlArg::GetName(name) => name
                .write_slice_at_offset::<Platform>(0, &self.comm.get())
                .ok_or(Errno::EFAULT)
                .map(|()| 0),
            PrctlArg::SetName(name) => {
                let mut name_buf = [0u8; litebox_common_linux::TASK_COMM_LEN - 1];
                // strncpy
                for (i, byte) in name_buf.iter_mut().enumerate() {
                    let b = name
                        .read_at_offset::<Platform>(isize::try_from(i).unwrap())
                        .ok_or(Errno::EFAULT)?;
                    if b == 0 {
                        break;
                    }
                    *byte = b;
                }
                self.set_task_comm(&name_buf);
                Ok(0)
            }
            PrctlArg::CapBSetRead(cap) => {
                // Return 1 if the capability specified in cap is in the calling
                // thread's capability bounding set, or 0 if it is not.
                if cap
                    > litebox_common_linux::CapSet::LAST_CAP
                        .bits()
                        .trailing_zeros() as usize
                {
                    return Err(Errno::EINVAL);
                }
                // Note we don't support capabilities in LiteBox, so we always return 0.
                Ok(0)
            }
            // `PrctlArg` is `#[non_exhaustive]` but only declares these three variants, all
            // matched above; the syscall decoder rejects any other `prctl` option with `EINVAL`
            // before a `PrctlArg` is ever constructed.
            _ => unreachable!(),
        }
    }

    /// Handle syscall `arch_prctl`.
    pub(crate) fn sys_arch_prctl(&self, arg: ArchPrctlArg) -> Result<(), Errno> {
        match arg {
            #[cfg(target_arch = "x86_64")]
            ArchPrctlArg::SetFs(addr) => self
                .global
                .platform
                .set_arch_specific_register(&ArchSpecificRegister::FsBase, addr)
                .map_err(Errno::from),
            #[cfg(target_arch = "x86_64")]
            ArchPrctlArg::GetFs(addr) => {
                let fsbase = self
                    .global
                    .platform
                    .get_arch_specific_register(&ArchSpecificRegister::FsBase)?;
                addr.write_at_offset::<Platform>(0, fsbase)
                    .ok_or(Errno::EFAULT)?;
                Ok(())
            }
            ArchPrctlArg::CETStatus | ArchPrctlArg::CETDisable | ArchPrctlArg::CETLock => {
                Err(Errno::EINVAL)
            }
            // `ArchPrctlArg` is `#[non_exhaustive]`, but on every target it declares (`SetFs`/
            // `GetFs` exist only under x86_64) every variant is matched above, and the syscall
            // decoder itself only runs `#[cfg(target_arch = "x86_64")]`, so on other targets this
            // is never even reachable via a real `arch_prctl` syscall.
            _ => unreachable!(),
        }
    }
}

const ROBUST_LIST_LIMIT: isize = 2048;

/// Bit set in a robust futex word's low bits by the kernel (here, the shim) when the thread
/// that held the lock dies without releasing it, so the next owner can detect the previous
/// holder died mid-critical-section. Matches Linux's `FUTEX_OWNER_DIED`.
const FUTEX_OWNER_DIED: u32 = 0x4000_0000;
/// Bit set in a robust futex word's low bits when at least one thread is (or might be) sleeping
/// in `FUTEX_WAIT` on it, so the unlocker knows to `FUTEX_WAKE`. Matches Linux's `FUTEX_WAITERS`.
const FUTEX_WAITERS: u32 = 0x8000_0000;
/// Mask isolating the TID stored in a robust futex word's low bits. Matches Linux's
/// `FUTEX_TID_MASK`.
const FUTEX_TID_MASK: u32 = 0x3fff_ffff;

impl<Platform: ShimPlatform, FS: ShimFS> Task<Platform, FS> {
    /// Processes a single robust-futex-list entry belonging to a dying thread: if the futex word
    /// still records this thread as the owner, marks it dead (setting [`FUTEX_OWNER_DIED`] and
    /// clearing the TID) and, if a waiter may be present, wakes one -- mirroring Linux's
    /// `handle_futex_death` (`kernel/futex/core.c`). Without this, a thread that dies while
    /// still holding a robust `pthread_mutex_t` would leave every future waiter on that lock
    /// blocked forever, since its owner can never call `FUTEX_WAKE` again.
    fn handle_futex_death(&self, futex_addr: UserPtr<u32>, _pending_op: bool) -> Result<(), Errno> {
        if !futex_addr.as_usize().is_multiple_of(4) {
            return Err(Errno::EINVAL);
        }
        let futex_addr = UserPtrMut::from_usize(futex_addr.as_usize());

        let Some(word) = futex_addr.read_at_offset::<Platform>(0) else {
            return Err(Errno::EFAULT);
        };

        // Only touch the word if it's still (nominally) owned by this dying thread -- a lock
        // that was already unlocked and re-acquired by someone else, or never actually locked by
        // us despite being linked into our robust list, must be left alone.
        #[expect(
            clippy::cast_sign_loss,
            reason = "tid is always non-negative; only ever compared against another tid read \
                      back from a futex word, never used arithmetically"
        )]
        if (word & FUTEX_TID_MASK) != self.tid as u32 {
            return Ok(());
        }

        let had_waiters = word & FUTEX_WAITERS != 0;
        let new_word = (word & FUTEX_WAITERS) | FUTEX_OWNER_DIED;
        if futex_addr
            .write_at_offset::<Platform>(0, new_word)
            .is_none()
        {
            return Err(Errno::EFAULT);
        }

        if had_waiters {
            let _ = self.sys_futex(FutexArgs::Wake {
                addr: futex_addr,
                flags: litebox_common_linux::FutexFlags::PRIVATE,
                count: 1,
            });
        }
        Ok(())
    }
}

fn fetch_robust_entry(
    head: UserPtr<litebox_common_linux::RobustList>,
) -> (UserPtr<litebox_common_linux::RobustList>, bool) {
    let next = head.as_usize();
    (UserPtr::from_usize(next & !1), next & 1 != 0)
}

impl<Platform: ShimPlatform, FS: ShimFS> Task<Platform, FS> {
    fn wake_robust_list(
        &self,
        head: UserPtr<litebox_common_linux::RobustListHead>,
    ) -> Result<(), Errno> {
        let mut limit = ROBUST_LIST_LIMIT;
        let head_ptr = head.as_usize();
        let head = head.read_at_offset::<Platform>(0).ok_or(Errno::EFAULT)?;
        let (mut entry, _pi) = fetch_robust_entry(UserPtr::from_usize(head.list.next));
        let (pending, _ppi) = fetch_robust_entry(UserPtr::from_usize(head.list_op_pending));
        let futex_offset = head.futex_offset;
        let entry_head = head_ptr + offset_of!(litebox_common_linux::RobustListHead, list);
        while entry.as_usize() != entry_head && limit > 0 {
            let nxt = entry
                .read_at_offset::<Platform>(0)
                .map(|e| fetch_robust_entry(UserPtr::from_usize(e.next)));
            if entry.as_usize() != pending.as_usize() {
                self.handle_futex_death(
                    UserPtr::from_usize(entry.as_usize() + futex_offset),
                    false,
                )?;
            }
            let Some((next_entry, _next_pi)) = nxt else {
                return Err(Errno::EFAULT);
            };

            entry = next_entry;
            limit -= 1;
        }

        if pending.as_usize() != 0 {
            let _ = self
                .handle_futex_death(UserPtr::from_usize(pending.as_usize() + futex_offset), true);
        }
        Ok(())
    }
}

impl<Platform: ShimPlatform, FS: ShimFS> Task<Platform, FS> {
    /// Called when the task is exiting.
    pub(crate) fn prepare_for_exit(&mut self) {
        // `CLOCK_THREAD_CPUTIME_ID` only ever reads the calling thread's own clock, so this has
        // to happen here, on the exiting thread itself, rather than later from whichever thread
        // ends up reaping it. Accumulated into the process (rather than overwritten) so that a
        // multithreaded process's rusage reflects every thread that has exited so far, not just
        // the last one.
        self.thread.process.cpu_time_nanos.fetch_add(
            self.global
                .platform
                .thread_cpu_time()
                .as_nanos()
                .try_into()
                .unwrap_or(u64::MAX),
            Ordering::Relaxed,
        );

        let is_last_thread = self.thread.detach_from_process();

        if let Some(clear_child_tid) = self.thread.clear_child_tid.take() {
            // Clear the child TID if requested
            // TODO: if we are the last thread, we don't need to clear it
            let _ = clear_child_tid.write_at_offset::<Platform>(0, 0);
            // Cast from *i32 to *u32
            let clear_child_tid = UserPtrMut::from_usize(clear_child_tid.as_usize());
            let _ = self.sys_futex(litebox_common_linux::FutexArgs::Wake {
                addr: clear_child_tid,
                flags: litebox_common_linux::FutexFlags::PRIVATE,
                count: 1,
            });
        }
        if let Some(robust_list) = self.thread.robust_list.take() {
            let _ = self.wake_robust_list(robust_list);
        }

        // Every write to guest memory above is done, so a task that shares its address space can
        // now hand it back -- which it must, or the members still alive would wait for it
        // forever. See [`SharedAddressSpace`].
        let _ = self.leave_address_space();

        // `FilesState` is shared (via `Arc`) across every `CLONE_FILES` thread of the process,
        // and closing an fd is only ever done explicitly (via `do_close`, which routes through
        // `Descriptors::remove` and the resource's own `Drop` impl -- e.g. a pipe write-end's
        // `Drop` firing its `HUP` notification). Just letting `FilesState`/`RawDescriptorStorage`
        // fall out of scope does NOT do this: `OwnedFd::drop` is a no-op for any fd that was
        // never explicitly closed, so any fd still open when the process exits would otherwise
        // leak forever at the descriptor-table level -- e.g. hanging a reader elsewhere in the
        // process that is blocked in `read()` waiting for a pipe write-end's `EOF`, regardless of
        // whether something else (like an epoll registration, see `epoll.rs`) also still
        // references the fd. Real Linux closes every fd of a process as part of process exit, so
        // mirror that here -- but only once, when the *last* thread sharing this file table is
        // the one exiting, matching `CLONE_FILES` semantics (a single thread of a still-running
        // multithreaded process exiting must NOT close fds out from under its siblings).
        if is_last_thread {
            self.close_all_fds_on_exit();
            // The process is gone: become a zombie its parent can `wait4`, and let go of any
            // children of our own (nothing can ever reap them now).
            let status = self.thread.process.inner.lock().exit_status;
            let cpu_time_nanos = self.thread.process.cpu_time_nanos.load(Ordering::Relaxed);
            self.global.processes.unregister_process(self.pid);
            self.global
                .processes
                .record_exit(self.pid, status, cpu_time_nanos);
            self.global.processes.discard_children_of(self.pid);
        }
    }

    pub(crate) fn sys_exit(&self, status: i32) {
        // The `Task` will be dropped on the way out of the shim, which will
        // call `self.prepare_for_exit()`.
        self.exit_thread(status.trunc());
    }

    pub(crate) fn sys_exit_group(&self, status: i32) {
        // Tear down occurs similarly to `sys_exit`.
        self.exit_group(ExitStatus::Exit(status.trunc()));
    }
}

/// A descriptor for thread-local storage (TLS).
///
/// On both `x86_64` and `aarch64` this is a `*mut u8` pointing at an
/// arbitrarily sized memory region: the value `clone(CLONE_SETTLS)` supplies
/// becomes `FS.base` on x86-64 and `TPIDR_EL0` on aarch64.
type ThreadLocalDescriptor = UserPtrMut<u8>;

/// The architecture register holding the guest's thread pointer.
///
/// The platform owns the hardware register in both cases and virtualizes the
/// guest's view of it, so the shim always goes through [`ArchSpecificRegister`]
/// rather than touching it directly.
#[cfg(target_arch = "x86_64")]
const GUEST_TLS_REGISTER: ArchSpecificRegister = ArchSpecificRegister::FsBase;
#[cfg(target_arch = "aarch64")]
const GUEST_TLS_REGISTER: ArchSpecificRegister = ArchSpecificRegister::TpidrEl0;

struct NewThreadArgs<Platform: ShimPlatform, FS: ShimFS> {
    /// Task struct that maintains all per-thread data
    task: Task<Platform, FS>,
}

impl<Platform: ShimPlatform, FS: ShimFS> litebox::shim::InitThread for NewThreadArgs<Platform, FS> {
    type ExecutionContext = litebox_common_linux::PtRegs;

    fn init(
        self: alloc::boxed::Box<Self>,
    ) -> alloc::boxed::Box<dyn litebox::shim::EnterShim<ExecutionContext = Self::ExecutionContext>>
    {
        let Self { task } = *self;

        Box::new(crate::LinuxShimEntrypoints {
            task,
            _not_send: core::marker::PhantomData,
        })
    }
}

impl<Platform: ShimPlatform, FS: ShimFS> Task<Platform, FS> {
    pub(crate) fn sys_clone(
        &self,
        ctx: &litebox_common_linux::PtRegs,
        args: &litebox_common_linux::CloneArgs,
    ) -> Result<usize, Errno> {
        self.do_clone(ctx, args, false)
    }

    pub(crate) fn sys_clone3(
        &self,
        ctx: &litebox_common_linux::PtRegs,
        args: UserPtr<litebox_common_linux::CloneArgs>,
    ) -> Result<usize, Errno> {
        let args = args.read_at_offset::<Platform>(0).ok_or(Errno::EFAULT)?;
        self.do_clone(ctx, &args, true)
    }

    /// Creates a new thread or process.
    ///
    /// Note we currently only support creating threads with the VM, FS, and FILES flags set.
    fn do_clone(
        &self,
        ctx: &litebox_common_linux::PtRegs,
        args: &litebox_common_linux::CloneArgs,
        clone3: bool,
    ) -> Result<usize, Errno> {
        const MAX_SIGNAL_NUMBER: u64 = 64;

        let litebox_common_linux::CloneArgs {
            mut flags,
            pidfd: _,
            child_tid,
            parent_tid,
            exit_signal,
            stack,
            stack_size,
            tls,
            set_tid,
            set_tid_size,
            cgroup,
        } = *args;

        // `CLONE_DETACHED` is ignored but has been reserved for reuse with
        // `clone3` or in combination with `CLONE_PIDFD`.
        if !clone3 && !flags.contains(CloneFlags::PIDFD) {
            flags.remove(CloneFlags::DETACHED);
        }

        // A `fork(2)`: libc issues it as a bare `clone(exit_signal, 0)` with no sharing flags at
        // all. `vfork(2)` and `posix_spawn` add `CLONE_VM | CLONE_VFORK`, which asks for exactly
        // the semantics this shim implements anyway (see `SharedAddressSpace`), so accept those --
        // but only together, and only without `CLONE_THREAD`, which would mean a thread rather
        // than a process.
        let fork_optional_flags = CloneFlags::VM | CloneFlags::VFORK;
        if !flags.intersects(!fork_optional_flags)
            && (flags & fork_optional_flags).bits() != CloneFlags::VM.bits()
        {
            return self.do_fork(ctx, args);
        }

        let required_clone_flags =
            CloneFlags::VM | CloneFlags::THREAD | CloneFlags::SIGHAND | CloneFlags::FILES;

        let supported_clone_flags = CloneFlags::VM
            | CloneFlags::FS
            | CloneFlags::FILES
            | CloneFlags::SIGHAND
            | CloneFlags::PARENT
            | CloneFlags::THREAD
            | CloneFlags::SETTLS
            | CloneFlags::PARENT_SETTID
            | CloneFlags::CHILD_CLEARTID
            | CloneFlags::CHILD_SETTID
            // Ignored since we don't support sysv semaphores anyway.
            | CloneFlags::SYSVSEM;

        if flags.intersects(!supported_clone_flags) {
            log_unsupported!(
                "clone with unsupported flags: {:?}",
                flags & !supported_clone_flags
            );
            return Err(Errno::EINVAL);
        }
        if !flags.contains(required_clone_flags) {
            log_unsupported!(
                "clone with missing required flags: {:?}",
                required_clone_flags & !flags
            );
            return Err(Errno::EINVAL);
        }

        if cgroup != 0 {
            log_unsupported!("clone with cgroup");
            return Err(Errno::EINVAL);
        }

        if set_tid != 0 || set_tid_size != 0 {
            log_unsupported!("clone with set_tid");
            return Err(Errno::EINVAL);
        }

        // `exit_signal` names the signal to send the parent when this task dies. Only its range
        // is checked: this shim always sends `SIGCHLD` (see `ProcessTable::record_exit`), and a
        // parent that asked for something else would learn of its children through `wait4`
        // anyway (see `Task::sys_wait4`).
        if exit_signal > MAX_SIGNAL_NUMBER {
            return Err(Errno::EINVAL);
        }

        // A new thread would run on memory this task only holds a *turn* on (see
        // `SharedAddressSpace`), and it has no turn of its own: it and the token holder would
        // both write to the same pages, and one of them would later have its writes rolled back
        // by a restore it knows nothing about. There is no way to support that here, so refuse
        // rather than corrupt the guest silently.
        if self.shares_address_space() {
            log_unsupported!("clone of a new thread from a process that has forked");
            return Err(Errno::ENOSYS);
        }

        let tls = if flags.contains(CloneFlags::SETTLS) {
            let addr = tls.trunc();
            #[cfg(target_arch = "x86_64")]
            {
                // Validate the user-controlled TLS base before spawning the
                // thread: `wrfsbase` faults on a non-canonical address, so an
                // unchecked value would take down the host, not the guest.
                // aarch64 needs no equivalent check -- the guest thread pointer
                // is virtualized into a memory slot rather than written to the
                // hardware register, so any value is inert until the guest
                // dereferences it. Linux's `copy_thread` likewise stores the
                // aarch64 value unvalidated.
                if !litebox_common_linux::arch::is_valid_user_fs_base(addr) {
                    return Err(Errno::EPERM);
                }
            }
            Some(ThreadLocalDescriptor::from_usize(addr))
        } else {
            None
        };

        let child_tid = if child_tid == 0 {
            None
        } else {
            Some(UserPtrMut::from_usize(child_tid.trunc()))
        };
        let set_child_tid = if flags.contains(CloneFlags::CHILD_SETTID) {
            child_tid
        } else {
            None
        };
        let clear_child_tid = if flags.contains(CloneFlags::CHILD_CLEARTID) {
            child_tid
        } else {
            None
        };
        let set_parent_tid = if flags.contains(CloneFlags::PARENT_SETTID) && parent_tid != 0 {
            Some(UserPtrMut::from_usize(parent_tid.trunc()))
        } else {
            None
        };

        let fs = if flags.contains(CloneFlags::FS) {
            self.fs.borrow().clone()
        } else {
            alloc::sync::Arc::new((**self.fs.borrow()).clone())
        };

        let child_tid = self.global.next_thread_id.fetch_add(1, Ordering::Relaxed);
        if let Some(parent_tid_ptr) = set_parent_tid {
            let _ = parent_tid_ptr.write_at_offset::<Platform>(0, child_tid);
        }

        if (stack == 0 && stack_size != 0) || (stack != 0 && clone3 && stack_size == 0) {
            return Err(Errno::EINVAL);
        }
        let sp = if stack != 0 {
            let stack: usize = stack.trunc();
            Some(stack.wrapping_add(stack_size.trunc()))
        } else {
            None
        };

        let thread = self.thread.new_thread(child_tid).ok_or(Errno::EBUSY)?;
        thread.init_state.set(ThreadInitState::NewThread {
            stack: sp,
            tls,
            set_child_tid,
        });
        thread.clear_child_tid.set(clear_child_tid);

        let r = unsafe {
            self.global.platform.spawn_thread(
                ctx,
                Box::new(NewThreadArgs {
                    task: Task {
                        global: self.global.clone(),
                        wait_state: crate::wait::WaitState::new(self.global.platform),
                        thread,
                        pid: self.pid,
                        tid: child_tid,
                        ppid: self.ppid,
                        credentials: RefCell::new(self.credentials.borrow().clone()),
                        comm: self.comm.clone(),
                        fs: fs.into(),
                        files: self.files.clone(), // TODO: !CLONE_FILES support
                        signals: self.signals.clone_for_new_task(),
                        address_space: RefCell::new(None),
                        guest_sp: Cell::new(0),
                    },
                }),
            )
        };
        if let Err(err) = r {
            litebox_util_log::error!(err:% = err; "failed to spawn thread");
            // Treat all spawn errors as `ENOMEM`. `EAGAIN` and other errors are
            // for conditions the user can control (such as "in-shim" rlimit
            // violations).
            return Err(Errno::ENOMEM);
        }

        Ok(usize::try_from(child_tid).unwrap())
    }

    /// Creates a new *process* sharing this one's address space, and suspends the caller until
    /// that child hands the address space back -- which it does as soon as it blocks, `execve`s
    /// or exits, not only at the end of its life. See [`SharedAddressSpace`] for why a copying
    /// `fork` is not representable here and how the sharing works.
    ///
    /// Unlike `vfork`, and like `fork`, the child gets its own copy of everything that is not
    /// memory: its own pid, its own file-descriptor table (so the shell's `dup2`/`close` dance
    /// between `fork` and `exec` cannot reach back into the parent's stdio), its own working
    /// directory and umask, and its own signal dispositions.
    fn do_fork(
        &self,
        ctx: &litebox_common_linux::PtRegs,
        args: &litebox_common_linux::CloneArgs,
    ) -> Result<usize, Errno> {
        const MAX_SIGNAL_NUMBER: u64 = 64;
        if args.exit_signal > MAX_SIGNAL_NUMBER {
            return Err(Errno::EINVAL);
        }
        if args.stack != 0 || args.set_tid != 0 || args.cgroup != 0 {
            log_unsupported!("fork with a stack, set_tid or cgroup");
            return Err(Errno::EINVAL);
        }
        // The child runs on this process's memory and takes a turn at it (see
        // `SharedAddressSpace`), which only works while nothing else is running on that memory.
        // A sibling thread has no turn to lose and would keep writing to pages the child is
        // about to have rolled back under it -- so for a multithreaded caller (libuv's
        // fork/dup2/execve spawn path is the motivating case: Node's threadpool exists by the
        // time the first `child_process` call forks), park every sibling at the process's fork
        // gate for the duration of the child's turn. The guard reopens the gate when this
        // thread's turn resumes, on error, and on panic alike.
        let _fork_gate_guard = if self.process().nr_threads() > 1 {
            Some(self.park_sibling_threads_for_fork())
        } else {
            None
        };

        // The child runs on this thread's guest stack, below this thread's current `sp`, and gets
        // the address-space token, so the parent must not touch guest memory again until it takes
        // the token back. Everything else about the child is copied here, in the parent, before
        // it can run.
        let child_pid = self.global.next_thread_id.fetch_add(1, Ordering::Relaxed);
        let files = self.files.borrow().fork_copy(self)?;
        let fs = alloc::sync::Arc::new((**self.fs.borrow()).clone());

        // The guest's thread pointer lives in a per-host-thread slot, so the new host thread has
        // to be told the value the parent is running with -- the libc data it points at is in the
        // address space the child is about to share.
        let tls = self
            .global
            .platform
            .get_arch_specific_register(&GUEST_TLS_REGISTER)
            .ok()
            .filter(|tls| *tls != 0)
            .map(ThreadLocalDescriptor::from_usize);

        // This task becomes a member of a shared address space if it was not one already, with
        // itself as the current holder -- it is, after all, the thread running right now.
        let shared = self.join_address_space();

        let thread = ThreadState::new_process(child_pid);
        thread.init_state.set(ThreadInitState::NewThread {
            // No stack of its own: it runs on the parent's, below the parent's `sp`.
            stack: None,
            tls,
            set_child_tid: None,
        });

        let child = Task {
            global: self.global.clone(),
            wait_state: crate::wait::WaitState::new(self.global.platform),
            thread,
            pid: child_pid,
            tid: child_pid,
            ppid: self.pid,
            credentials: RefCell::new(self.credentials.borrow().clone()),
            comm: self.comm.clone(),
            fs: fs.into(),
            files: Arc::new(files).into(),
            signals: self.signals.clone_for_new_process(),
            // The child starts out holding the token: it is about to run on this memory, and the
            // hand-off below transfers it without ever letting the token go free.
            address_space: RefCell::new(Some(AddressSpaceMembership {
                shared: shared.clone(),
                holding: Cell::new(true),
                parked: RefCell::new(None),
            })),
            guest_sp: Cell::new(guest_stack_pointer(ctx)),
        };
        child.process().brk.store(
            self.process().brk.load(Ordering::Relaxed),
            Ordering::Relaxed,
        );
        // The child is running on this memory, so it owns it in the same sense the parent does --
        // which matters if the child `fork`s again before it `exec`s.
        *child.process().owned_ranges.lock() = self.process().owned_ranges.lock().clone();
        self.global.processes.add_child(child_pid, self.pid);
        // Registered before the child can run, so a child that exits immediately still finds its
        // parent (this one) in the live set and can post it a `SIGCHLD`.
        self.register_for_remote_signals();
        self.global
            .processes
            .register_process(child_pid, child.remote_signal_target());

        // Done last, so that the copy captures memory exactly as the child will find it.
        self.park_and_hand_off(guest_stack_pointer(ctx), child_pid);

        let r = unsafe {
            self.global
                .platform
                .spawn_thread(ctx, Box::new(NewThreadArgs { task: child }))
        };
        if let Err(err) = r {
            litebox_util_log::error!(err:% = err; "failed to spawn forked process");
            // Dropping the child's `Task` on the way out of `spawn_thread` already gave the token
            // back and turned the child into a zombie; since the child never existed as far as
            // the guest is concerned, drop the record too rather than leave an unwaitable pid.
            self.global.processes.forget(child_pid);
            self.acquire_address_space();
            return Err(Errno::ENOMEM);
        }

        // Blocks until some member -- the child, or whoever it in turn handed on to -- gives the
        // address space back, then puts this task's own memory into it. Unlike a real `vfork`
        // this does not have to be the end of the child's life: it is enough for the child to
        // block on something.
        self.acquire_address_space();
        Ok(usize::try_from(child_pid).unwrap())
    }

    /// Returns this task's shared address space, creating one (with this task as its first
    /// member and current holder) if it is not in one yet.
    fn join_address_space(&self) -> Arc<SharedAddressSpace<Platform>> {
        let mut slot = self.address_space.borrow_mut();
        if let Some(membership) = slot.as_ref() {
            debug_assert!(
                membership.holding.get(),
                "forking without holding the address space"
            );
            return membership.shared.clone();
        }
        let shared = Arc::new(SharedAddressSpace::new(self.tid));
        *slot = Some(AddressSpaceMembership {
            shared: shared.clone(),
            holding: Cell::new(true),
            parked: RefCell::new(None),
        });
        shared
    }

    /// Copies this task's memory out and passes the address space directly to `tid`.
    ///
    /// # Panics
    ///
    /// Panics if this task is not currently a member holding the token; `fork` is the only
    /// caller and it has just made sure of both.
    fn park_and_hand_off(&self, sp: usize, tid: i32) {
        let slot = self.address_space.borrow();
        let membership = slot.as_ref().expect("forking outside an address space");
        assert!(membership.holding.get());
        let saved = self.save_address_space(sp);
        *membership.parked.borrow_mut() = Some(saved);
        membership.holding.set(false);
        membership.shared.hand_off_to(tid);
    }

    /// Gives the address space up for as long as this task is blocked, so that another member can
    /// run on it. Paired with [`Task::acquire_address_space`].
    ///
    /// Does nothing if this task is not sharing an address space, or is already parked. If it is
    /// the *only* remaining member, membership is dropped instead of parked: nobody can take the
    /// token, so copying memory out and back would be pure cost. (A new member can only appear
    /// via `fork`, which requires holding the token, so no member can turn up while this runs.)
    pub(crate) fn release_address_space(&self) {
        let mut slot = self.address_space.borrow_mut();
        let Some(membership) = slot.as_ref() else {
            return;
        };
        if !membership.holding.get() {
            return;
        }
        if Arc::strong_count(&membership.shared) == 1 {
            *slot = None;
            return;
        }
        let saved = self.save_address_space(self.guest_sp.get());
        *membership.parked.borrow_mut() = Some(saved);
        membership.holding.set(false);
        membership.shared.release();
    }

    /// Takes the address space back and restores this task's memory into it, blocking until the
    /// current holder gives it up.
    ///
    /// Does nothing if this task is not sharing an address space, or already holds it.
    pub(crate) fn acquire_address_space(&self) {
        let slot = self.address_space.borrow();
        let Some(membership) = slot.as_ref() else {
            return;
        };
        if membership.holding.get() {
            return;
        }
        if !membership.shared.acquire(self.tid, || self.is_exiting()) {
            // Being torn down. Nothing will run guest code on this task's behalf again, so its
            // copy of the address space is worthless; drop it and let the members that are still
            // alive have the space.
            drop(slot);
            *self.address_space.borrow_mut() = None;
            return;
        }
        membership.holding.set(true);
        if let Some(saved) = membership.parked.borrow_mut().take() {
            self.restore_address_space(saved);
        }
    }

    /// Leaves the shared address space for good, waking anything waiting for it.
    ///
    /// Returns `true` if, afterwards, this task's guest memory is its alone -- either it was
    /// never shared, or this was the last member -- and so is safe to tear down. Called from
    /// `execve`, whose new image lives at addresses no other member owns, and from task exit.
    fn leave_address_space(&self) -> bool {
        let Some(membership) = self.address_space.borrow_mut().take() else {
            return true;
        };
        if membership.holding.get() {
            membership.shared.release();
        }
        // The only other strong reference is this one, so no other member is left to care about
        // the memory. A member can only be created by `fork`, which needs the token, and this
        // task held it until the line above.
        Arc::strong_count(&membership.shared) == 1
    }

    /// Whether this task's guest memory is shared with another guest process.
    fn shares_address_space(&self) -> bool {
        self.address_space.borrow().is_some()
    }

    /// Leaves the shared address space if this task is its only remaining member, and reports
    /// whether this task's guest memory is now unshared.
    ///
    /// `execve` uses this to decide whether the old mappings are its to tear down. A sole member
    /// still holds the token, so no new member can appear while this runs.
    fn leave_address_space_if_alone(&self) -> bool {
        let mut slot = self.address_space.borrow_mut();
        let Some(membership) = slot.as_ref() else {
            return true;
        };
        if Arc::strong_count(&membership.shared) != 1 {
            return false;
        }
        debug_assert!(membership.holding.get());
        *slot = None;
        true
    }

    /// Records the guest stack pointer for the current trip through the shim.
    pub(crate) fn record_guest_sp(&self, sp: usize) {
        self.guest_sp.set(sp);
    }

    /// Copies this process's private writable memory out into host memory.
    ///
    /// This is what makes a shared-address-space `fork` behave like a real one for a guest that
    /// was built for a real one. The child necessarily runs on the parent's memory (see
    /// [`SharedAddressSpace`]), and `vfork(2)`'s contract -- "the child may only `exec` or
    /// `_exit`" -- is one a `fork(2)`-using program has no reason to honour. busybox's shell, for
    /// instance, *returns* out of the function that called `fork`, overwriting the frames its
    /// parent is parked in, and its `forkchild` frees the parent's job list on the shared heap.
    /// But only the token holder ever runs on that memory, so none of that has to be visible to
    /// anyone else: this copies the memory out, and [`Task::restore_address_space`] puts it back
    /// before the task executes another guest instruction. Each member then sees exactly what
    /// `fork(2)` promises -- its own memory, untouched -- while the child saw a faithful copy of
    /// the parent's, because it *was* it.
    ///
    /// Two deliberate limits on what is saved:
    ///
    /// * Only ranges this process owns, so that a sibling guest process running concurrently at
    ///   other addresses is never rolled back. See [`Process::owned_ranges`].
    /// * Of the mapping holding the stack pointer, only `[sp, end)`. Everything below `sp` is
    ///   dead memory on both supported architectures (neither the AArch64 nor the x86-64 Linux
    ///   ABI keeps live data below the stack pointer across a call), and it is where the child
    ///   does most of its work -- saving the whole 8 MiB stack mapping would make every `fork`
    ///   pointlessly expensive to preserve nothing.
    fn save_address_space(&self, sp: usize) -> MemoryImage {
        let owned = self.process().owned_ranges.lock();
        let mut saved = Vec::new();
        for (range, flags) in self.global.pm.mappings() {
            if !flags.contains(VmFlags::VM_WRITE) || flags.contains(VmFlags::VM_SHARED) {
                continue;
            }
            let stack = range.contains(&sp);
            for part in owned.intersect(&range) {
                let start = if stack {
                    part.start.max(sp)
                } else {
                    part.start
                };
                if start >= part.end {
                    continue;
                }
                match UserPtr::<u8>::from_usize(start).to_owned_slice::<Platform>(part.end - start)
                {
                    Some(bytes) => saved.push((start, bytes)),
                    // Only reachable if a mapping this process owns is no longer readable, which
                    // no correct program arranges. Loud, because the consequence is that this
                    // task's own writes to that range are silently lost the next time another
                    // member of the address space runs.
                    None => litebox_util_log::error!(
                        pid:? = self.pid, start:? = start, end:? = part.end;
                        "could not copy a mapping out before giving up the address space; this \
                         process's data in it will be whatever the next process to run leaves \
                         there"
                    ),
                }
            }
        }
        saved
    }

    /// Puts back what [`Task::save_address_space`] took, undoing everything a forked child did to
    /// its parent's memory.
    fn restore_address_space(&self, saved: MemoryImage) {
        for (start, bytes) in saved {
            if UserPtrMut::<u8>::from_usize(start)
                .copy_from_slice::<Platform>(0, &bytes)
                .is_none()
            {
                // Only reachable if another member of the address space unmapped or
                // write-protected memory belonging to this process, which no correct program
                // does; this process is left with whatever that member made of it.
                let pm_view = self
                    .global
                    .pm
                    .mappings()
                    .into_iter()
                    .find(|(range, _)| range.contains(&start))
                    .map(|(range, flags)| (range.start, range.end, flags));
                litebox_util_log::error!(
                    pid:? = self.pid, start:? = start, len:? = bytes.len(), pm_view:? = pm_view;
                    "failed to restore a mapping when taking the address space back"
                );
            }
        }
    }

    /// Publishes this process in the shim's live-process set so other processes can post signals
    /// to it. Idempotent: re-registering simply replaces the entry with an identical one.
    ///
    /// Done at `fork` rather than at task construction because that is the first moment a process
    /// can acquire a child, and a process with no children has nothing to receive.
    fn register_for_remote_signals(&self) {
        self.global
            .processes
            .register_process(self.pid, self.remote_signal_target());
    }

    /// Handle syscall `wait4`.
    pub(crate) fn sys_wait4(
        &self,
        pid: i32,
        wstatus: Option<UserPtrMut<i32>>,
        options: i32,
        rusage: usize,
    ) -> Result<i32, Errno> {
        /// `WNOHANG`: return immediately if no child has exited.
        const WNOHANG: u32 = 0x1;
        /// `WUNTRACED`/`WCONTINUED`: accepted and then never acted on, because this shim has no
        /// way to stop or continue a process in the first place, so a wait for either event
        /// simply never has one to report.
        const WUNTRACED: u32 = 0x2;
        const WCONTINUED: u32 = 0x8;
        /// `__WNOTHREAD`/`__WALL`/`__WCLONE`: which *kinds* of child to consider. Every child
        /// here is an ordinary one belonging to the caller alone, so all three are no-ops.
        const WNOTHREAD: u32 = 0x2000_0000;
        const WALL: u32 = 0x4000_0000;
        const WCLONE: u32 = 0x8000_0000;
        /// Deliberately absent: `WNOWAIT` (leave the child reapable), which this cannot honour
        /// -- the reap below is destructive -- and `WEXITED`/`WSTOPPED`, which are `waitid`'s,
        /// not `wait4`'s.
        const SUPPORTED: u32 = WNOHANG | WUNTRACED | WCONTINUED | WNOTHREAD | WALL | WCLONE;

        let options = options.cast_unsigned();
        if options & !SUPPORTED != 0 {
            log_unsupported!("wait4 with options {options:#x}");
            return Err(Errno::EINVAL);
        }
        let rusage =
            (rusage != 0).then(|| UserPtrMut::<litebox_common_linux::Rusage>::from_usize(rusage));

        let filter = if pid > 0 {
            WaitFilter::Pid(pid)
        } else {
            // `-1` (any child), `0` (any child in my process group) and `< -1` (a named process
            // group) all mean the same thing in a shim with one process group.
            WaitFilter::Any
        };
        let table = &self.global.processes;

        // Registered before the first check so that a child exiting in the gap between the check
        // and the block cannot be missed.
        let token = table.register_waiter(self.pid, self.wait_cx().waker().clone());
        let _unregister = litebox::utils::defer(|| table.unregister_waiter(token));

        loop {
            if let Some((pid, status, cpu_time_nanos)) = table.reap(self.pid, filter) {
                if let Some(wstatus) = wstatus {
                    wstatus
                        .write_at_offset::<Platform>(0, encode_wait_status(status))
                        .ok_or(Errno::EFAULT)?;
                }
                if let Some(rusage) = rusage {
                    // `ru_utime` is the one field real scripts actually consume (`busybox time`
                    // among them) and the one this shim can measure honestly: real, host-metered
                    // CPU time summed across every thread the child ever ran (see
                    // `Process::cpu_time_nanos`). `ru_stime` is left at zero rather than
                    // fabricated -- guest syscalls run as ordinary host user-mode Rust, so this
                    // shim has no meaningful "kernel time" of its own to attribute, and reporting
                    // a fake nonzero value would be worse than reporting none. Every other field
                    // (`ru_maxrss` etc.) is zeroed for the same reason. This is still a strict
                    // improvement over leaving the caller's buffer untouched: reading uninitialized
                    // guest memory back as a `struct rusage` is both a correctness bug (nonsensical
                    // output, as seen from `busybox time`) and an information disclosure.
                    let value = litebox_common_linux::Rusage {
                        ru_utime: core::time::Duration::from_nanos(cpu_time_nanos).into(),
                        ..Default::default()
                    };
                    rusage
                        .write_at_offset::<Platform>(0, value)
                        .ok_or(Errno::EFAULT)?;
                }
                return Ok(pid);
            }
            if !table.has_child(self.pid, filter) {
                return Err(Errno::ECHILD);
            }
            if options & WNOHANG != 0 {
                return Ok(0);
            }
            self.wait_cx()
                .wait_until(|| table.reap_ready(self.pid, filter))
                .map_err(|_| Errno::EINTR)?;
        }
    }

    /// Records `range` as mapped by this process. See [`Process::owned_ranges`].
    pub(crate) fn record_mapped(&self, start: usize, len: usize) {
        if len != 0 {
            self.process()
                .owned_ranges
                .lock()
                .insert(start..start.saturating_add(len));
        }
    }

    /// Records `range` as no longer mapped by this process.
    pub(crate) fn record_unmapped(&self, start: usize, len: usize) {
        if len != 0 {
            self.process()
                .owned_ranges
                .lock()
                .remove(start..start.saturating_add(len));
        }
    }

    /// Handle syscall `set_tid_address`.
    pub(crate) fn sys_set_tid_address(&self, tidptr: UserPtrMut<i32>) -> i32 {
        self.thread.clear_child_tid.set(Some(tidptr));
        self.tid
    }

    /// Handle syscall `gettid`.
    pub(crate) fn sys_gettid(&self) -> i32 {
        self.tid
    }
}

// TODO: enforce the following limits:
pub(crate) const RLIMIT_NOFILE_CUR: usize = 1024 * 1024;
const RLIMIT_NOFILE_MAX: usize = 1024 * 1024;

struct AtomicRlimit {
    cur: core::sync::atomic::AtomicUsize,
    max: core::sync::atomic::AtomicUsize,
}

impl AtomicRlimit {
    const fn new(cur: usize, max: usize) -> Self {
        Self {
            cur: core::sync::atomic::AtomicUsize::new(cur),
            max: core::sync::atomic::AtomicUsize::new(max),
        }
    }
}

pub(crate) struct ResourceLimits {
    limits: [AtomicRlimit; litebox_common_linux::RlimitResource::RLIM_NLIMITS],
}

impl ResourceLimits {
    const fn default() -> Self {
        seq_macro::seq!(N in 0..16 {
            let mut limits = [
                #(
                    AtomicRlimit::new(0, 0),
                )*
            ];
        });
        limits[litebox_common_linux::RlimitResource::NOFILE as usize] = AtomicRlimit {
            cur: core::sync::atomic::AtomicUsize::new(RLIMIT_NOFILE_CUR),
            max: core::sync::atomic::AtomicUsize::new(RLIMIT_NOFILE_MAX),
        };
        limits[litebox_common_linux::RlimitResource::STACK as usize] = AtomicRlimit {
            cur: core::sync::atomic::AtomicUsize::new(crate::loader::DEFAULT_STACK_SIZE),
            max: core::sync::atomic::AtomicUsize::new(litebox_common_linux::rlim_t::MAX),
        };
        Self { limits }
    }

    pub(crate) fn get_rlimit(
        &self,
        resource: litebox_common_linux::RlimitResource,
    ) -> litebox_common_linux::Rlimit {
        let r = &self.limits[resource as usize];
        litebox_common_linux::Rlimit {
            rlim_cur: r.cur.load(Ordering::Relaxed),
            rlim_max: r.max.load(Ordering::Relaxed),
        }
    }

    pub(crate) fn get_rlimit_cur(&self, resource: litebox_common_linux::RlimitResource) -> usize {
        let r = &self.limits[resource as usize];
        r.cur.load(Ordering::Relaxed)
    }

    fn set_rlimit(
        &self,
        resource: litebox_common_linux::RlimitResource,
        new_limit: litebox_common_linux::Rlimit,
    ) {
        let r = &self.limits[resource as usize];
        r.cur.store(new_limit.rlim_cur, Ordering::Relaxed);
        r.max.store(new_limit.rlim_max, Ordering::Relaxed);
    }
}

impl<Platform: ShimPlatform, FS: ShimFS> Task<Platform, FS> {
    /// Get resource limits, and optionally set new limits.
    pub(crate) fn do_prlimit(
        &self,
        resource: litebox_common_linux::RlimitResource,
        new_limit: Option<litebox_common_linux::Rlimit>,
    ) -> Result<litebox_common_linux::Rlimit, Errno> {
        let old_rlimit = match resource {
            litebox_common_linux::RlimitResource::NOFILE
            | litebox_common_linux::RlimitResource::STACK => {
                self.thread.process.limits.get_rlimit(resource)
            }
            _ => {
                log_unsupported!("Unsupported resource for get_rlimit: {:?}", resource);
                return Err(Errno::EINVAL);
            }
        };
        if let Some(new_limit) = new_limit {
            if new_limit.rlim_cur > new_limit.rlim_max {
                return Err(Errno::EINVAL);
            }
            if let litebox_common_linux::RlimitResource::NOFILE = resource
                && new_limit.rlim_max > RLIMIT_NOFILE_MAX
            {
                return Err(Errno::EPERM);
            }
            // Note process with `CAP_SYS_RESOURCE` can increase the hard limit, but we don't
            // support capabilities in LiteBox, so we don't check for that here.
            if new_limit.rlim_max > old_rlimit.rlim_max {
                return Err(Errno::EPERM);
            }
            if let litebox_common_linux::RlimitResource::NOFILE = resource {
                let new_max_fd = new_limit.rlim_cur.saturating_sub(1);
                self.thread.process.limits.set_rlimit(resource, new_limit);
                self.files.borrow().set_max_fd(new_max_fd);
            } else {
                log_unsupported!("Unsupported resource for set_rlimit: {:?}", resource);
                return Err(Errno::EINVAL);
            }
        }
        Ok(old_rlimit)
    }

    /// Handle syscall `prlimit64`.
    ///
    /// Note for now setting new limits is not supported yet, and thus returning constant values
    /// for the requested resource. Getting resources for a specific PID is also not supported yet.
    pub(crate) fn sys_prlimit(
        &self,
        pid: i32,
        resource: litebox_common_linux::RlimitResource,
        new_rlim: Option<UserPtr<litebox_common_linux::Rlimit64>>,
        old_rlim: Option<UserPtrMut<litebox_common_linux::Rlimit64>>,
    ) -> Result<(), Errno> {
        if pid != 0 && pid != self.pid {
            unimplemented!("prlimit for a specific PID is not supported yet");
        }
        let new_limit = match new_rlim {
            Some(rlim) => {
                let rlim = rlim.read_at_offset::<Platform>(0).ok_or(Errno::EINVAL)?;
                Some(litebox_common_linux::rlimit64_to_rlimit(rlim))
            }
            None => None,
        };
        let old_limit =
            litebox_common_linux::rlimit_to_rlimit64(self.do_prlimit(resource, new_limit)?);
        if let Some(old_rlim) = old_rlim {
            old_rlim
                .write_at_offset::<Platform>(0, old_limit)
                .ok_or(Errno::EINVAL)?;
        }
        Ok(())
    }

    /// Handle syscall `setrlimit`.
    pub(crate) fn sys_getrlimit(
        &self,
        resource: litebox_common_linux::RlimitResource,
        rlim: UserPtrMut<litebox_common_linux::Rlimit>,
    ) -> Result<(), Errno> {
        let old_limit = self.do_prlimit(resource, None)?;
        rlim.write_at_offset::<Platform>(0, old_limit)
            .ok_or(Errno::EINVAL)
    }

    /// Handle syscall `setrlimit`.
    pub(crate) fn sys_setrlimit(
        &self,
        resource: litebox_common_linux::RlimitResource,
        rlim: UserPtr<litebox_common_linux::Rlimit>,
    ) -> Result<(), Errno> {
        let new_limit = rlim.read_at_offset::<Platform>(0).ok_or(Errno::EFAULT)?;
        let _ = self.do_prlimit(resource, Some(new_limit))?;
        Ok(())
    }

    /// Handle syscall `set_robust_list`.
    pub(crate) fn sys_set_robust_list(&self, head: usize) {
        let head = UserPtr::from_usize(head);
        self.thread.robust_list.set(Some(head));
    }

    /// Handle syscall `get_robust_list`.
    pub(crate) fn sys_get_robust_list(
        &self,
        pid: Option<i32>,
        head_ptr: UserPtrMut<usize>,
    ) -> Result<(), Errno> {
        if pid.is_some_and(|pid| pid != self.tid) {
            unimplemented!("Getting robust list for a specific PID is not supported yet");
        }
        let head = self
            .thread
            .robust_list
            .get()
            .map_or(0, |ptr| ptr.as_usize());
        head_ptr
            .write_at_offset::<Platform>(0, head)
            .ok_or(Errno::EFAULT)
    }

    pub(crate) fn real_time_as_duration_since_epoch(&self) -> core::time::Duration {
        let now = self.global.platform.current_time();
        let unix_epoch = <Platform as TimeProvider>::SystemTime::UNIX_EPOCH;
        now.duration_since(&unix_epoch)
            .expect("must be after unix epoch")
    }

    /// Handle syscall `clock_gettime`.
    pub(crate) fn sys_clock_gettime(
        &self,
        clockid: litebox_common_linux::ClockId,
        tp: TimeParam,
    ) -> Result<(), Errno> {
        let duration = self.gettime_as_duration(clockid)?;
        tp.write::<Platform>(duration)
    }

    fn gettime_as_duration(
        &self,
        clockid: litebox_common_linux::ClockId,
    ) -> Result<core::time::Duration, Errno> {
        let duration = match clockid {
            litebox_common_linux::ClockId::RealTime => {
                // CLOCK_REALTIME
                self.real_time_as_duration_since_epoch()
            }
            litebox_common_linux::ClockId::RealTimeCoarse => {
                // CLOCK_REALTIME_COARSE - a faster, lower-resolution CLOCK_REALTIME.
                // Simplification: we have no cheaper coarse clock source, so we reuse the exact
                // same (full-precision) value as CLOCK_REALTIME; see `sys_clock_getres` for the
                // (still coarse) resolution we report for this clock.
                self.real_time_as_duration_since_epoch()
            }
            litebox_common_linux::ClockId::Monotonic
            | litebox_common_linux::ClockId::MonotonicCoarse
            | litebox_common_linux::ClockId::MonotonicRaw
            | litebox_common_linux::ClockId::Boottime => {
                // CLOCK_MONOTONIC / CLOCK_MONOTONIC_COARSE / CLOCK_MONOTONIC_RAW /
                // CLOCK_BOOTTIME.
                //
                // Simplification: LiteBox tracks only a single monotonic clock, so all four map
                // onto it. This is exact for CLOCK_MONOTONIC; for the others it elides real
                // Linux's distinctions (COARSE trades precision for speed; RAW excludes NTP
                // slewing; BOOTTIME additionally counts suspend time) -- see the `ClockId`
                // variant docs for why each is a legitimate simplification here.
                self.global
                    .platform
                    .now()
                    .duration_since(&self.global.boot_time)
            }
            litebox_common_linux::ClockId::ProcessCpuTime => {
                // CLOCK_PROCESS_CPUTIME_ID - genuine per-process CPU-time accounting, sourced
                // from the host (not wall-clock time).
                self.global.platform.process_cpu_time()
            }
            litebox_common_linux::ClockId::ThreadCpuTime => {
                // CLOCK_THREAD_CPUTIME_ID - genuine per-thread CPU-time accounting, sourced from
                // the host (not wall-clock time).
                self.global.platform.thread_cpu_time()
            }
            _ => {
                log_unsupported!("gettime for {clockid:?}");
                return Err(Errno::EINVAL);
            }
        };
        Ok(duration)
    }

    /// Convert an absolute time, specified as a duration since the epoch of the
    /// given clock, to a `Platform::Instant` suitable for use as a deadline.
    ///
    /// If the time is so far in the future that it cannot be represented as an
    /// `Instant`, returns `Ok(None)`. If the time occurs in the past, returns
    /// the current time.
    fn duration_since_epoch_to_deadline(
        &self,
        clock_id: litebox_common_linux::ClockId,
        duration: Duration,
    ) -> Result<Option<<Platform as TimeProvider>::Instant>, Errno> {
        match clock_id {
            litebox_common_linux::ClockId::Monotonic
            | litebox_common_linux::ClockId::MonotonicCoarse
            | litebox_common_linux::ClockId::MonotonicRaw
            | litebox_common_linux::ClockId::Boottime => {
                // No need to compute the current time since the offset from the
                // request to `Instant` is known.
                Ok(self.global.boot_time.checked_add(duration))
            }
            _ => {
                // Convert between time domains. If the requested time is in the past,
                // return the current time.
                let current_time = self.gettime_as_duration(clock_id)?;
                Ok(self
                    .global
                    .platform
                    .now()
                    .checked_add(duration.checked_sub(current_time).unwrap_or(Duration::ZERO)))
            }
        }
    }

    /// Handle syscall `clock_getres`.
    pub(crate) fn sys_clock_getres(
        &self,
        clockid: litebox_common_linux::ClockId,
        res: TimeParam,
    ) -> Result<(), Errno> {
        // Return the resolution of the clock
        let resolution = match clockid {
            litebox_common_linux::ClockId::MonotonicCoarse
            | litebox_common_linux::ClockId::RealTimeCoarse => {
                // Coarse clocks typically have lower resolution (e.g., 4 millisecond). We report
                // this even though we actually source these from the full-precision clock (see
                // `gettime_as_duration`), matching the resolution real coarse clocks advertise.
                Duration::from_millis(4)
            }
            litebox_common_linux::ClockId::RealTime
            | litebox_common_linux::ClockId::Monotonic
            | litebox_common_linux::ClockId::MonotonicRaw
            | litebox_common_linux::ClockId::Boottime
            | litebox_common_linux::ClockId::ProcessCpuTime
            | litebox_common_linux::ClockId::ThreadCpuTime => {
                // For most modern systems, the resolution is typically 1 nanosecond
                // This is a reasonable default for high-resolution timers
                Duration::from_nanos(1)
            }
            // `ClockId` is `#[non_exhaustive]` but only declares the variants matched above;
            // `clockid` only reaches here via `ClockId::try_from`, which rejects anything else
            // with `EINVAL` before construction.
            _ => unreachable!(),
        };

        res.write::<Platform>(resolution)
    }

    /// Handle syscall `clock_nanosleep`.
    pub(crate) fn sys_clock_nanosleep(
        &self,
        clockid: litebox_common_linux::ClockId,
        flags: litebox_common_linux::TimerFlags,
        request: TimeParam,
        remain: TimeParam,
    ) -> Result<(), Errno> {
        if matches!(
            clockid,
            litebox_common_linux::ClockId::ProcessCpuTime
                | litebox_common_linux::ClockId::ThreadCpuTime
        ) {
            // Real Linux rejects sleeping against a CPU-time clock: a blocked (not-running)
            // thread cannot accumulate CPU time, so waiting for one of these clocks to reach a
            // given value could never wake up.
            return Err(Errno::EINVAL);
        }
        let request = request.read::<Platform>()?.ok_or(Errno::EFAULT)?;
        if flags.intersects(litebox_common_linux::TimerFlags::ABSTIME.complement()) {
            return Err(Errno::EINVAL);
        }
        let is_abs = flags.contains(litebox_common_linux::TimerFlags::ABSTIME);

        // Set up a wait context with the right deadline/timeout.
        let wait_cx = self.wait_cx();
        let wait_cx = if is_abs {
            wait_cx.with_deadline(self.duration_since_epoch_to_deadline(clockid, request)?)
        } else {
            // Relative. Treat all clocks the same. TODO: handle the different clocks differently.
            wait_cx.with_timeout(request)
        };

        match wait_cx.sleep() {
            WaitError::TimedOut => {}
            WaitError::Interrupted => {
                if is_abs {
                    return Err(Errno::EINTR);
                }
                if let Some(remaining_timeout) = wait_cx.remaining_timeout() {
                    remain.write::<Platform>(remaining_timeout)?;
                    return Err(Errno::EINTR);
                }
                // Whoops, time ran out after getting interrupted. Treat this as a timeout.
            }
        }

        Ok(())
    }

    /// Handle syscall `gettimeofday`.
    pub(crate) fn sys_gettimeofday(
        &self,
        tv: Option<UserPtrMut<litebox_common_linux::TimeVal>>,
        tz: Option<UserPtrMut<litebox_common_linux::TimeZone>>,
    ) -> Result<(), Errno> {
        if let Some(tz) = tz {
            // `man 2 gettimeofday`: The use of the timezone structure is obsolete; the tz argument
            // should normally be specified as NULL. Linux still accepts a non-NULL tz and fills it
            // in (typically with zeros for UTC systems) rather than returning an error.
            let utc_tz = litebox_common_linux::TimeZone::new(0, 0);
            tz.write_at_offset::<Platform>(0, utc_tz)
                .ok_or(Errno::EFAULT)?;
        }
        if let Some(tv) = tv {
            tv.write_at_offset::<Platform>(0, self.real_time_as_duration_since_epoch().into())
                .ok_or(Errno::EFAULT)?;
        }
        Ok(())
    }

    /// Handle syscall `time`.
    pub(crate) fn sys_time(
        &self,
        tloc: Option<UserPtrMut<litebox_common_linux::time_t>>,
    ) -> Result<litebox_common_linux::time_t, Errno> {
        let time = self.real_time_as_duration_since_epoch();
        let seconds: u64 = time.as_secs();
        let seconds: litebox_common_linux::time_t = seconds.try_into().or(Err(Errno::EOVERFLOW))?;
        if let Some(tloc) = tloc {
            tloc.write_at_offset::<Platform>(0, seconds)
                .ok_or(Errno::EFAULT)?;
        }
        Ok(seconds)
    }

    /// Handle syscall `alarm`.
    ///
    /// Sets a process-wide timer to deliver SIGALRM after `seconds` seconds. If
    /// `seconds` is 0, any pending alarm is cancelled. Returns the number of
    /// seconds remaining on a previously set alarm (rounded up), or 0 if none
    /// was set.
    ///
    /// The alarm is per-process: all threads share the same alarm timer.
    pub(crate) fn sys_alarm(&self, seconds: u32) -> Result<u32, Errno> {
        let prev = self.arm_real_timer(Duration::from_secs(u64::from(seconds)))?;
        // Round remaining time up to whole seconds, saturating to u32::MAX.
        if prev.is_zero() {
            Ok(0)
        } else {
            let extra = u64::from(prev.subsec_nanos() > 0);
            Ok(u32::try_from(prev.as_secs() + extra).unwrap_or(u32::MAX))
        }
    }

    /// Arm or disarm the per-process `ITIMER_REAL` timer. Returns the raw
    /// `Duration` remaining on the previous arming; zero means "was not
    /// armed". `delay = 0` disarms.
    fn arm_real_timer(&self, delay: Duration) -> Result<Duration, Errno> {
        let mut alarm = self.process().alarm_timer.lock();
        let now = self.global.platform.now();
        let prev = alarm.remaining(now);
        let new_deadline = if delay.is_zero() {
            None
        } else {
            Some(now.checked_add(delay).ok_or(Errno::EINVAL)?)
        };
        if alarm.handle.is_none() {
            match self
                .global
                .platform
                .create_timer(litebox_common_linux::signal::Signal::SIGALRM)
            {
                Ok(handle) => alarm.handle = Some(handle),
                Err(litebox::platform::TimerCreationError::Unsupported) => {}
                // `TimerCreationError` is `#[non_exhaustive]` but only declares this one
                // variant, already matched above.
                Err(_) => unreachable!(),
            }
        }
        if let Some(handle) = &alarm.handle {
            handle.set_timer(delay);
        }
        alarm.deadline = new_deadline;
        Ok(prev)
    }

    /// Handle syscall `setitimer`.
    pub(crate) fn sys_setitimer(
        &self,
        which: IntervalTimer,
        new_value: Option<UserPtr<ItimerVal>>,
        old_value: Option<UserPtrMut<ItimerVal>>,
    ) -> Result<(), Errno> {
        let new = match new_value {
            Some(ptr) => ptr.read_at_offset::<Platform>(0).ok_or(Errno::EFAULT)?,
            // Linux supports NULL `new_value` but says it would be removed in the future.
            None => ItimerVal::default(),
        };
        // tv_usec range check is performed by `Duration::try_from(TimeVal)`.
        let new_interval = Duration::try_from(new.it_interval())?;
        let new_remaining = Duration::try_from(new.it_value())?;

        let prev = match which {
            IntervalTimer::Real => {
                if new_remaining.is_zero() {
                    ItimerVal::single_shot(self.arm_real_timer(Duration::ZERO)?)
                } else if !new_interval.is_zero() {
                    // TODO: support periodic timers
                    log_unsupported!("setitimer: nonzero it_interval not supported");
                    return Err(Errno::ENOSYS);
                } else {
                    ItimerVal::single_shot(self.arm_real_timer(new_remaining)?)
                }
            }
            IntervalTimer::Virtual | IntervalTimer::Prof => {
                log_unsupported!("setitimer: ITIMER_VIRTUAL/PROF not supported");
                return Err(Errno::ENOSYS);
            }
        };

        if let Some(out) = old_value {
            out.write_at_offset::<Platform>(0, prev)
                .ok_or(Errno::EFAULT)?;
        }
        Ok(())
    }

    /// Handle syscall `getitimer`.
    pub(crate) fn sys_getitimer(
        &self,
        which: IntervalTimer,
        curr_value: UserPtrMut<ItimerVal>,
    ) -> Result<(), Errno> {
        let value = match which {
            IntervalTimer::Real => {
                let alarm = self.process().alarm_timer.lock();
                let now = self.global.platform.now();
                alarm.remaining(now)
            }
            IntervalTimer::Virtual | IntervalTimer::Prof => {
                log_unsupported!("getitimer: ITIMER_VIRTUAL/PROF not supported");
                Duration::ZERO
            }
        };
        curr_value
            .write_at_offset::<Platform>(0, ItimerVal::single_shot(value))
            .ok_or(Errno::EFAULT)
    }

    /// Handle syscall `pause`.
    pub(crate) fn sys_pause(&self) -> Result<(), Errno> {
        match self.wait_cx().sleep() {
            WaitError::Interrupted => Err(Errno::EINTR),
            WaitError::TimedOut => unreachable!("pause sleep has no deadline"),
        }
    }

    /// Handle syscall `getpid`.
    pub(crate) fn sys_getpid(&self) -> i32 {
        self.pid
    }

    pub(crate) fn sys_getppid(&self) -> i32 {
        self.ppid
    }

    /// Whether `pid`, as passed to `setpgid`/`getpgid`, names the calling process or one of its
    /// recorded children -- the only targets this shim can meaningfully answer for (it has no
    /// registry of unrelated processes; see [`Self::sys_getpgid`]).
    fn pgid_target_is_self_or_child(&self, pid: i32) -> bool {
        pid == 0
            || pid == self.pid
            || self
                .global
                .processes
                .has_child(self.pid, WaitFilter::Pid(pid))
    }

    /// Handle syscall `getpgid`.
    ///
    /// `pid == 0` means "the calling process", matching `setpgid`/`getpgid`'s own convention
    /// (distinct from the `sched_*` family's thread-granularity `pid == 0`; this one is
    /// process-granularity, compared against `self.pid`).
    ///
    /// LiteBox's process group is a single shim-wide value (see [`crate::GlobalState::pgid`])
    /// rather than a genuine per-process-group model, so any pid this shim can vouch for --
    /// itself or a recorded child -- reports that same group. A pid it cannot vouch for is
    /// `ESRCH`, matching what real Linux does for a genuinely nonexistent target (real Linux
    /// additionally permits querying *any* live pid, not just self/children; we cannot, since we
    /// keep no general pid registry to check existence against).
    pub(crate) fn sys_getpgid(&self, pid: i32) -> Result<i32, Errno> {
        if !self.pgid_target_is_self_or_child(pid) {
            log_unsupported!("getpgid for a pid that is not self or a known child");
            return Err(Errno::ESRCH);
        }
        Ok(self.global.pgid.load(Ordering::Acquire))
    }

    /// Handle syscall `setpgid`.
    ///
    /// Real Linux additionally restricts this to processes in the same session and forbids
    /// retargeting a child that has already called `execve` (`EACCES`); LiteBox tracks neither
    /// sessions nor an exec-generation per child, so only the target-identity check in
    /// [`Self::pgid_target_is_self_or_child`] is enforced. `pgid == 0` means "use the target's
    /// own pid as its new group", matching real `setpgid`.
    #[allow(clippy::similar_names)]
    pub(crate) fn sys_setpgid(&self, pid: i32, pgid: i32) -> Result<(), Errno> {
        if pgid < 0 {
            return Err(Errno::EINVAL);
        }
        if !self.pgid_target_is_self_or_child(pid) {
            log_unsupported!("setpgid for a pid that is not self or a known child");
            return Err(Errno::ESRCH);
        }
        let target_pid = if pid == 0 { self.pid } else { pid };
        let new_pgid = if pgid == 0 { target_pid } else { pgid };
        self.global.pgid.store(new_pgid, Ordering::Release);
        Ok(())
    }

    /// Handle syscall `getuid`.
    pub(crate) fn sys_getuid(&self) -> u32 {
        self.credentials.borrow().uid
    }

    /// Handle syscall `geteuid`.
    pub(crate) fn sys_geteuid(&self) -> u32 {
        self.credentials.borrow().euid
    }

    /// Handle syscall `getgid`.
    pub(crate) fn sys_getgid(&self) -> u32 {
        self.credentials.borrow().gid
    }

    /// Handle syscall `getegid`.
    pub(crate) fn sys_getegid(&self) -> u32 {
        self.credentials.borrow().egid
    }

    /// Whether this task may change its uid/gid to an arbitrary value.
    ///
    /// LiteBox models no capability set, so `CAP_SETUID`/`CAP_SETGID` have
    /// nothing to check. An effective uid of 0 is used as the stand-in,
    /// mirroring the classic pre-capabilities Unix kernel, which gated the
    /// same operations on `suser()` (effective uid 0) alone.
    fn is_privileged(&self) -> bool {
        self.credentials.borrow().euid == 0
    }

    /// Handle syscall `setuid`.
    ///
    /// A privileged task may become any uid; this also sets `euid` to match,
    /// since with no saved-set-uid tracked here there is nothing else for a
    /// privileged `setuid` to leave behind for a later drop-and-reclaim. An
    /// unprivileged task may only switch its effective uid to its current
    /// real or effective uid, same as the raw Linux syscall (the POSIX
    /// behavior of applying this to every thread in the process is a glibc
    /// wrapper feature this shim, operating at the raw-syscall level, does
    /// not need to reproduce).
    ///
    /// # Errors
    ///
    /// `EPERM` if the task is unprivileged and `uid` is neither its current
    /// uid nor euid.
    pub(crate) fn sys_setuid(&self, uid: u32) -> Result<(), Errno> {
        let mut new = self.credentials.borrow().as_ref().clone();
        if self.is_privileged() {
            new.uid = uid;
            new.euid = uid;
        } else if uid == new.uid || uid == new.euid {
            new.euid = uid;
        } else {
            return Err(Errno::EPERM);
        }
        *self.credentials.borrow_mut() = Arc::new(new);
        Ok(())
    }

    /// Handle syscall `setgid`.
    ///
    /// See [`Self::sys_setuid`]; the same policy applies with `gid`/`egid` in
    /// place of `uid`/`euid`, gated on the same privilege check (Linux
    /// privileges `setgid` on `CAP_SETGID` rather than `CAP_SETUID`, but
    /// LiteBox tracks neither, so both fall back to the one uid-0 check).
    ///
    /// # Errors
    ///
    /// `EPERM` if the task is unprivileged and `gid` is neither its current
    /// gid nor egid.
    pub(crate) fn sys_setgid(&self, gid: u32) -> Result<(), Errno> {
        let mut new = self.credentials.borrow().as_ref().clone();
        if self.is_privileged() {
            new.gid = gid;
            new.egid = gid;
        } else if gid == new.gid || gid == new.egid {
            new.egid = gid;
        } else {
            return Err(Errno::EPERM);
        }
        *self.credentials.borrow_mut() = Arc::new(new);
        Ok(())
    }

    /// Handle syscall `getgroups`.
    ///
    /// The supplementary set is exactly the task's own gid. There is no group
    /// database to consult, and this is what `initgroups` leaves a process with
    /// when the only group it belongs to is its primary one -- so it is a
    /// faithful state rather than a placeholder. Deriving it from `credentials`
    /// instead of storing it also means the two cannot drift apart.
    ///
    /// # Errors
    ///
    /// `EINVAL` if `size` is negative, or positive but too small to hold the
    /// set, both as Linux does. `EFAULT` if `list` is not writable. `size == 0`
    /// is the "how many?" query and writes nothing.
    pub(crate) fn sys_getgroups(&self, size: i32, list: UserPtrMut<u32>) -> Result<usize, Errno> {
        let groups = [self.credentials.borrow().gid];
        if size < 0 {
            return Err(Errno::EINVAL);
        }
        let size = usize::try_from(size).map_err(|_| Errno::EINVAL)?;
        if size == 0 {
            return Ok(groups.len());
        }
        if size < groups.len() {
            return Err(Errno::EINVAL);
        }
        list.write_slice_at_offset::<Platform>(0, &groups)
            .ok_or(Errno::EFAULT)?;
        Ok(groups.len())
    }
}

/// Number of CPUs
const NR_CPUS: usize = 2;

pub(crate) struct CpuSet {
    bits: bitvec::vec::BitVec<u8>,
}

impl CpuSet {
    pub(crate) fn len(&self) -> usize {
        self.bits.len()
    }
    pub(crate) fn as_bytes(&self) -> &[u8] {
        self.bits.as_raw_slice()
    }
}

impl<Platform: ShimPlatform, FS: ShimFS> Task<Platform, FS> {
    /// Handle syscall `sched_getaffinity`.
    ///
    /// Note this is a dummy implementation that always returns the same CPU set
    pub(crate) fn sys_sched_getaffinity(&self, _pid: Option<i32>) -> CpuSet {
        let mut cpuset = bitvec::bitvec![u8, bitvec::order::Lsb0; 0; NR_CPUS];
        cpuset.iter_mut().for_each(|mut b| *b = true);
        CpuSet { bits: cpuset }
    }

    /// Returns whether `pid`, as passed to one of the `sched_*` syscalls below, refers to the
    /// calling thread. `pid == 0` (as with all four `sched_*` syscalls per their man pages) means
    /// "the calling thread"; `sched_*` operates at thread (not process) granularity on Linux, so
    /// this compares against `self.tid`, not a process-wide id.
    fn sched_target_is_self(&self, pid: Option<i32>) -> bool {
        pid.is_none_or(|pid| pid == self.tid)
    }

    /// Handle syscall `sched_getparam`.
    ///
    /// LiteBox's process model has no real scheduling-class enforcement to expose, so every
    /// thread is always reported as `SCHED_OTHER` with priority 0 -- the same default every
    /// unprivileged Linux thread starts with, and the only priority `SCHED_OTHER` ever accepts.
    pub(crate) fn sys_sched_getparam(
        &self,
        pid: Option<i32>,
        param: UserPtrMut<litebox_common_linux::SchedParam>,
    ) -> Result<usize, Errno> {
        if !self.sched_target_is_self(pid) {
            log_unsupported!("sched_getparam for a remote pid");
            return Err(Errno::ESRCH);
        }
        param
            .write_at_offset::<Platform>(0, litebox_common_linux::SchedParam { sched_priority: 0 })
            .ok_or(Errno::EFAULT)?;
        Ok(0)
    }

    /// Handle syscall `sched_setparam`.
    ///
    /// Since every thread is always `SCHED_OTHER` (see [`Self::sys_sched_getparam`]), and
    /// `SCHED_OTHER`'s only valid priority is 0, this accepts a priority-0 request as a no-op and
    /// rejects anything else with `EINVAL`, matching what real Linux would do to a process that
    /// never leaves `SCHED_OTHER`.
    pub(crate) fn sys_sched_setparam(
        &self,
        pid: Option<i32>,
        param: UserPtr<litebox_common_linux::SchedParam>,
    ) -> Result<usize, Errno> {
        if !self.sched_target_is_self(pid) {
            log_unsupported!("sched_setparam for a remote pid");
            return Err(Errno::ESRCH);
        }
        let param = param.read_at_offset::<Platform>(0).ok_or(Errno::EFAULT)?;
        if param.sched_priority != 0 {
            return Err(Errno::EINVAL);
        }
        Ok(0)
    }

    /// Handle syscall `sched_getscheduler`.
    pub(crate) fn sys_sched_getscheduler(&self, pid: Option<i32>) -> Result<usize, Errno> {
        if !self.sched_target_is_self(pid) {
            log_unsupported!("sched_getscheduler for a remote pid");
            return Err(Errno::ESRCH);
        }
        // The return value of `sched_getscheduler` IS the policy (unlike most syscalls, it is
        // not a separate out-parameter), so no bitwise cast/sign issues arise turning a small
        // non-negative `i32` constant into a `usize` success value.
        Ok(usize::try_from(litebox_common_linux::sched_policy::SCHED_OTHER).unwrap())
    }

    /// Handle syscall `sched_setscheduler`.
    ///
    /// Non-real-time policies (`SCHED_OTHER`/`SCHED_BATCH`/`SCHED_IDLE`) are accepted as no-ops,
    /// same as a real unprivileged Linux process switching between them would experience.
    /// Real-time policies (`SCHED_FIFO`/`SCHED_RR`/`SCHED_DEADLINE`) are rejected with `EPERM`,
    /// matching real Linux's behavior for a process without `CAP_SYS_NICE` -- a real, accurate
    /// constraint here, since LiteBox guests never have that capability, not a shortcut.
    pub(crate) fn sys_sched_setscheduler(
        &self,
        pid: Option<i32>,
        policy: i32,
        param: UserPtr<litebox_common_linux::SchedParam>,
    ) -> Result<usize, Errno> {
        use litebox_common_linux::sched_policy::{
            SCHED_BATCH, SCHED_DEADLINE, SCHED_FIFO, SCHED_IDLE, SCHED_OTHER, SCHED_RESET_ON_FORK,
            SCHED_RR,
        };

        if !self.sched_target_is_self(pid) {
            log_unsupported!("sched_setscheduler for a remote pid");
            return Err(Errno::ESRCH);
        }
        match policy & !SCHED_RESET_ON_FORK {
            SCHED_OTHER | SCHED_BATCH | SCHED_IDLE => {}
            SCHED_FIFO | SCHED_RR | SCHED_DEADLINE => {
                log_unsupported!(
                    "sched_setscheduler(policy = {policy}): real-time scheduling is never available to a LiteBox guest"
                );
                return Err(Errno::EPERM);
            }
            _ => return Err(Errno::EINVAL),
        }
        let param = param.read_at_offset::<Platform>(0).ok_or(Errno::EFAULT)?;
        if param.sched_priority != 0 {
            return Err(Errno::EINVAL);
        }
        Ok(0)
    }
}

impl<Platform: ShimPlatform, FS: ShimFS> Task<Platform, FS> {
    /// Handle syscall `futex`
    pub(crate) fn sys_futex(&self, arg: litebox_common_linux::FutexArgs) -> Result<usize, Errno> {
        /// Note our mutex implementation assumes futexes are private as we don't support shared memory yet.
        /// It should be fine to treat shared futexes as private for now.
        macro_rules! warn_shared_futex {
            ($flag:ident) => {
                if !$flag.contains(litebox_common_linux::FutexFlags::PRIVATE) {
                    log_unsupported!("shared futex");
                }
            };
        }

        let res = match arg {
            FutexArgs::Wake { addr, flags, count } => {
                warn_shared_futex!(flags);
                let Some(count) = core::num::NonZeroU32::new(count) else {
                    return Ok(0);
                };
                self.global
                    .futex_manager
                    .wake(addr.to_platform_ptr::<Platform>(), count, None)? as usize
            }
            FutexArgs::Wait {
                addr,
                flags,
                val,
                timeout,
            } => {
                warn_shared_futex!(flags);
                let timeout = timeout.read::<Platform>()?;
                self.global.futex_manager.wait(
                    &self.wait_cx().with_timeout(timeout),
                    addr.to_platform_ptr::<Platform>(),
                    val,
                    None,
                )?;
                0
            }
            litebox_common_linux::FutexArgs::WaitBitset {
                addr,
                flags,
                val,
                timeout,
                bitmask,
            } => {
                warn_shared_futex!(flags);
                let deadline = if let Some(timeout) = timeout.read::<Platform>()? {
                    let clock_id =
                        if flags.contains(litebox_common_linux::FutexFlags::CLOCK_REALTIME) {
                            litebox_common_linux::ClockId::RealTime
                        } else {
                            litebox_common_linux::ClockId::Monotonic
                        };
                    self.duration_since_epoch_to_deadline(clock_id, timeout)?
                } else {
                    None
                };
                self.global.futex_manager.wait(
                    &self.wait_cx().with_deadline(deadline),
                    addr.to_platform_ptr::<Platform>(),
                    val,
                    core::num::NonZeroU32::new(bitmask),
                )?;
                0
            }
            litebox_common_linux::FutexArgs::Requeue {
                addr,
                flags,
                num_to_wake,
                num_to_requeue,
                addr2,
            } => {
                warn_shared_futex!(flags);
                self.global.futex_manager.requeue(
                    addr.to_platform_ptr::<Platform>(),
                    addr2.to_platform_ptr::<Platform>(),
                    num_to_wake,
                    num_to_requeue,
                    None,
                )? as usize
            }
            litebox_common_linux::FutexArgs::CmpRequeue {
                addr,
                flags,
                num_to_wake,
                num_to_requeue,
                addr2,
                expected_value,
            } => {
                warn_shared_futex!(flags);
                self.global.futex_manager.requeue(
                    addr.to_platform_ptr::<Platform>(),
                    addr2.to_platform_ptr::<Platform>(),
                    num_to_wake,
                    num_to_requeue,
                    Some(expected_value),
                )? as usize
            }
            _ => {
                log_unsupported!("futex operation {:?}", arg);
                return Err(Errno::ENOSYS);
            }
        };
        Ok(res)
    }
}

const MAX_VEC: usize = 4096; // limit count
const MAX_TOTAL_BYTES: usize = 256 * 1024; // size cap

/// Maximum shebang (#!) recursion depth (from Linux's `exec_binprm`)
const SHEBANG_MAX_RECURSION: u32 = 6;

/// Maximum length of a shebang line that we inspect. Matches Linux `BINPRM_BUF_SIZE`.
const SHEBANG_MAX_LINE: usize = 256;

/// Parse a `#!interpreter [optional-arg]` line from a file header buffer.
///
/// Returns `Some((interpreter, optional_arg))` when `buf` starts with `#!` and
/// contains a non-empty interpreter path. The optional argument, if present, is everything
/// between the first whitespace after the interpreter and the end of the line
/// (trimmed), treated as a single token — matching Linux kernel semantics.
fn parse_shebang(buf: &[u8]) -> Option<(&str, Option<&str>)> {
    if buf.len() < 2 || buf[0] != b'#' || buf[1] != b'!' {
        return None;
    }
    let line_end = buf[2..]
        .iter()
        .position(|&b| b == b'\n')
        .map_or(buf.len(), |p| p + 2);
    let line = core::str::from_utf8(&buf[2..line_end]).ok()?;
    let line = line.trim();
    if line.is_empty() {
        return None;
    }
    match line.find([' ', '\t']) {
        Some(i) => {
            let arg = line[i..].trim();
            Some((&line[..i], if arg.is_empty() { None } else { Some(arg) }))
        }
        None => Some((line, None)),
    }
}

impl<Platform: ShimPlatform, FS: ShimFS> Task<Platform, FS> {
    /// Resolve shebang (`#!`) chains for the given path and argv if the file starts with a shebang line.
    /// Otherwise, returns the original path and argv.
    pub(crate) fn resolve_shebang(
        &self,
        mut path: alloc::string::String,
        mut argv: alloc::vec::Vec<alloc::ffi::CString>,
    ) -> Result<(alloc::string::String, alloc::vec::Vec<alloc::ffi::CString>), Errno> {
        for _ in 0..SHEBANG_MAX_RECURSION {
            let full_path = self.resolve_path(&path)?;
            let file = self.do_open(
                full_path,
                litebox::fs::OFlags::RDONLY,
                litebox::fs::Mode::empty(),
            )?;
            let mut header = [0u8; SHEBANG_MAX_LINE];
            let files = self.files.borrow();
            let n = match files.fs.read(&file, &mut header, Some(0)) {
                Ok(n) => n,
                Err(e) => {
                    let _ = files.fs.close(&file);
                    return Err(Errno::from(e));
                }
            };
            let _ = files.fs.close(&file);

            match parse_shebang(&header[..n]) {
                Some((interp, opt_arg)) => {
                    let mut new_argv = alloc::vec::Vec::new();
                    new_argv.push(alloc::ffi::CString::new(interp).map_err(|_| Errno::EINVAL)?);
                    if let Some(arg) = opt_arg {
                        new_argv.push(alloc::ffi::CString::new(arg).map_err(|_| Errno::EINVAL)?);
                    }
                    new_argv
                        .push(alloc::ffi::CString::new(path.as_str()).map_err(|_| Errno::EINVAL)?);
                    if argv.len() > 1 {
                        new_argv.extend_from_slice(&argv[1..]);
                    }
                    path = alloc::string::String::from(interp);
                    argv = new_argv;
                }
                None => return Ok((path, argv)),
            }
        }
        Err(Errno::ELOOP)
    }

    /// Handle syscall `execve`.
    // `c_char` rather than a fixed `i8`: it is signed on x86-64 and on Apple's
    // AArch64 ABI but unsigned on AArch64 Linux, and `SyscallRequest::Execve`
    // hands these over as `UserPtr<c_char>`.
    pub(crate) fn sys_execve(
        &self,
        pathname: UserPtr<core::ffi::c_char>,
        argv: UserPtr<UserPtr<core::ffi::c_char>>,
        envp: UserPtr<UserPtr<core::ffi::c_char>>,
        ctx: &mut litebox_common_linux::PtRegs,
    ) -> Result<usize, Errno> {
        fn copy_vector<Platform: ShimPlatform>(
            mut base: UserPtr<UserPtr<core::ffi::c_char>>,
            _which: &str,
        ) -> Result<alloc::vec::Vec<alloc::ffi::CString>, Errno> {
            let mut out = alloc::vec::Vec::new();
            let mut total = 0usize;
            for _ in 0..MAX_VEC {
                let p: UserPtr<core::ffi::c_char> = {
                    // read pointer-sized entries
                    match base.read_at_offset::<Platform>(0) {
                        Some(ptr) => ptr,
                        None => return Err(Errno::EFAULT),
                    }
                };
                if p.as_usize() == 0 {
                    break;
                }
                let Some(cs) = p.to_cstring::<Platform>() else {
                    return Err(Errno::EFAULT);
                };
                total += cs.as_bytes().len() + 1;
                if total > MAX_TOTAL_BYTES {
                    return Err(Errno::E2BIG);
                }
                out.push(cs);
                // advance to next pointer
                base = UserPtr::from_usize(base.as_usize() + core::mem::size_of::<usize>());
            }
            Ok(out)
        }

        // Copy pathname
        let Some(path_cstr) = pathname.to_cstring::<Platform>() else {
            return Err(Errno::EFAULT);
        };
        let path = path_cstr.to_str().map_err(|_| Errno::ENOENT)?;

        // Copy argv and envp vectors
        let argv_vec = if argv.as_usize() == 0 {
            alloc::vec::Vec::new()
        } else {
            copy_vector::<Platform>(argv, "argv")?
        };
        let envp_vec = if envp.as_usize() == 0 {
            alloc::vec::Vec::new()
        } else {
            copy_vector::<Platform>(envp, "envp")?
        };

        let (path, argv_vec) = self.resolve_shebang(alloc::string::String::from(path), argv_vec)?;

        let loader = crate::loader::elf::ElfLoader::new(self, &path)?;

        // After this point, the old program is torn down and failures must terminate the process.

        // Kill all the other threads in this process and wait for them to exit.
        if !self.kill_other_threads() {
            // Another thread is already in the process of execve. This thread
            // will exit; return any error code.
            return Err(Errno::EBUSY);
        }

        // Close CLOEXEC descriptors
        self.close_on_exec();

        // unmmap all memory mappings and reset brk
        if let Some(robust_list) = self.thread.robust_list.take() {
            let _ = self.wake_robust_list(robust_list);
        }
        self.thread.clear_child_tid.set(None);

        self.signals.reset_for_exec();

        if self.leave_address_space_if_alone() {
            // Release only the mappings this process owns, not everything the
            // (process-blind) page manager tracks. "Alone in the shared
            // address space" -- or never having shared at all -- does not
            // mean alone in the page manager: a forked child that already
            // completed one exec has left the shared space, yet its suspended
            // parent's entire live memory is still in the manager, and a
            // release-everything here destroys it. Observed live as Node's
            // `execSync("/bin/sh -c ...")`: fork, exec /bin/sh (first exec
            // keeps the parent's memory via the branch below), sh execs the
            // command (second exec took this branch and unmapped the
            // suspended parent wholesale -- every one of its subsequent
            // address-space restores failed and it died on the first libc
            // global it touched). `owned_ranges` exists precisely to name
            // which mappings are this process's, and the fork/exec paths
            // maintain it for every mapping source (mmap, mremap, brk, the
            // loader's stack); reserved mappings carry empty `VmFlags` and
            // are skipped as before.
            //
            // What is released is the *intersection* with `owned_ranges`, never a whole tracked
            // mapping that merely overlaps it. The page manager coalesces adjacent ranges with
            // identical properties into a single entry (see `PageManager::mappings`), and
            // adjacency between this process's memory and a suspended sibling's is not a
            // coincidence here: `Vmem::get_unmmaped_area` hands out the address immediately below
            // an existing range, so a forked child's very first anonymous `mmap` lands flush
            // against whatever its parent had there. Observed live, exactly so: the
            // `execSync("/bin/sh -c ...")` child `mmap`ed 16 KiB that abutted 48 KiB of its
            // parent's musl heap, and (via `mprotect`) another 16 KiB that abutted 160 KiB more
            // of it -- four of the parent's ranges the manager had silently merged into two of
            // this process's -- and a whole-entry release then unmapped all 208 KiB of the
            // parent's, which died on the first libc global it touched after taking its address
            // space back.
            let owned = self.process().owned_ranges.lock();
            let release = |r: Range<usize>, vm: VmFlags| {
                if vm.is_empty() {
                    Vec::new()
                } else {
                    owned.intersect(&r).collect::<Vec<_>>()
                }
            };
            unsafe { self.global.pm.release_memory(release) }
                .expect("failed to release memory mappings");
        } else {
            // Another guest process is still living in this address space (see
            // `SharedAddressSpace`), so these mappings are not this task's alone to tear down:
            // doing so would destroy the process this one is about to hand the space back to. The
            // new image is loaded alongside them instead -- it is position-independent, and
            // `Vmem::get_unmmaped_area` places it where nobody else is.
        }

        // Either the old mappings are gone or (for a `fork`ed child) they were never this
        // process's to begin with. `load_program` re-populates this as it maps the new image.
        self.process().owned_ranges.lock().clear();

        self.global
            .platform
            .set_arch_specific_register(&GUEST_TLS_REGISTER, 0)
            .expect("failed to clear guest TLS on execve");

        self.load_program(loader, argv_vec, envp_vec)
            .expect("TODO: terminate the process cleanly");

        self.init_thread_context(ctx);
        // The new image is fully built, at addresses no other member of the old address space
        // owns, so this task no longer needs the shared one. Handing it back here rather than
        // earlier means no other member ever observes a half-built image.
        let _ = self.leave_address_space();
        Ok(0)
    }

    /// Loads the specified program into the process's address space and prepares the thread
    /// to start executing it.
    pub(crate) fn load_program(
        &self,
        mut loader: crate::loader::elf::ElfLoader<'_, Platform, FS>,
        argv: Vec<alloc::ffi::CString>,
        envp: Vec<alloc::ffi::CString>,
    ) -> Result<(), crate::loader::elf::ElfLoaderError> {
        // Captured before `argv` moves into `loader.load` below: publishes
        // `/proc/<pid>/cmdline` for this load (initial program load, or `execve`).
        if let Some(proc) = &self.global.proc_handle {
            let argv_bytes: alloc::vec::Vec<&[u8]> =
                argv.iter().map(alloc::ffi::CString::as_bytes).collect();
            proc.set_cmdline(&argv_bytes);
        }

        // The loader publishes the new image's initial break through the (single, shared) page
        // manager; take it back out into this process's own slot, restoring the manager's
        // "no break set" sentinel, so that a sibling process's break is unaffected. See
        // `Process::brk`.
        let load_info = {
            let _guard = self.global.brk_lock.lock();
            let load_info = loader.load(argv, envp, self.init_auxv())?;
            self.process()
                .brk
                .store(self.global.pm.swap_brk(0), Ordering::Relaxed);
            load_info
        };

        self.set_task_comm(loader.comm());

        self.thread
            .init_state
            .set(ThreadInitState::NewProcess(load_info));
        Ok(())
    }

    pub(crate) fn handle_init_request(&self, ctx: &mut litebox_common_linux::PtRegs) {
        self.init_thread_context(ctx);
        // Attach the thread handle so that the thread can be interrupted.
        self.thread
            .remote
            .handle
            .set(Box::new(self.wait_state.thread_handle()))
            .ok();
    }

    /// Initialize the thread context for a new process or thread, and perform any
    /// other initial setup required.
    fn init_thread_context(&self, ctx: &mut litebox_common_linux::PtRegs) {
        match self.thread.init_state.take() {
            ThreadInitState::None => {}
            ThreadInitState::NewProcess(load_info) => {
                #[cfg(target_arch = "x86_64")]
                {
                    *ctx = litebox_common_linux::PtRegs {
                        r15: 0,
                        r14: 0,
                        r13: 0,
                        r12: 0,
                        rbp: 0,
                        rbx: 0,
                        r11: 0,
                        r10: 0,
                        r9: 0,
                        r8: 0,
                        rax: 0,
                        rcx: 0,
                        rdx: 0,
                        rsi: 0,
                        rdi: 0,
                        orig_rax: 0,
                        rip: load_info.entry_point,
                        cs: 0x33, // __USER_CS
                        eflags: 0,
                        rsp: load_info.user_stack_top,
                        ss: 0x2b, // __USER_DS
                    };
                }
                #[cfg(target_arch = "aarch64")]
                {
                    // A fresh aarch64 process starts with every general-purpose
                    // register cleared, `sp` at the top of the initial stack and
                    // `pc` at the entry point. `pstate` starts at 0, which is
                    // EL0t/AArch64 with no flags set and nothing masked --
                    // exactly what `SAFE_USER_PSTATE` permits.
                    *ctx = litebox_common_linux::PtRegs {
                        regs: [0; litebox_common_linux::AARCH64_GENERAL_REGISTER_COUNT],
                        sp: load_info.user_stack_top,
                        pc: load_info.entry_point,
                        pstate: 0,
                        orig_x0: 0,
                        // No syscall is in flight on entry.
                        syscallno: -1,
                        unused2: 0,
                    };
                }
            }
            ThreadInitState::NewThread {
                tls,
                stack,
                set_child_tid,
            } => {
                // Set the stack and the return value from clone().
                #[cfg(target_arch = "x86_64")]
                {
                    if let Some(stack) = stack {
                        ctx.rsp = stack;
                    }
                    ctx.rax = 0;
                }
                #[cfg(target_arch = "aarch64")]
                {
                    if let Some(stack) = stack {
                        ctx.sp = stack;
                    }
                    // `clone` returns 0 in the child, in x0.
                    ctx.regs[0] = 0;
                }

                // Set the TLS for the new thread.
                if let Some(tls) = tls {
                    self.global
                        .platform
                        .set_arch_specific_register(&GUEST_TLS_REGISTER, tls.as_usize())
                        .expect("failed to set guest TLS for new thread");
                }

                if let Some(child_tid_ptr) = set_child_tid {
                    // Set the child TID if requested.
                    let _ = child_tid_ptr.write_at_offset::<Platform>(0, self.tid);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{UserPtr, UserPtrMut};
    use core::time::Duration;

    extern crate std;

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_arch_prctl() {
        use crate::syscalls::tests::init_platform;
        use litebox_common_linux::ArchPrctlArg;

        let task = init_platform(None);

        // Save old FS base
        let mut old_fs_base: usize = 0;
        let ptr = UserPtrMut::from_ptr(&raw mut old_fs_base);
        task.sys_arch_prctl(ArchPrctlArg::GetFs(ptr))
            .expect("Failed to get FS base");

        // Set new FS base
        let mut new_fs_base: [u8; 16] = [0; 16];
        let ptr = UserPtrMut::from_ptr(new_fs_base.as_mut_ptr());
        task.sys_arch_prctl(ArchPrctlArg::SetFs(ptr.as_usize()))
            .expect("Failed to set FS base");

        // Verify new FS base
        let mut current_fs_base: usize = 0;
        let ptr = UserPtrMut::from_ptr(&raw mut current_fs_base);
        task.sys_arch_prctl(ArchPrctlArg::GetFs(ptr))
            .expect("Failed to get FS base");
        assert_eq!(current_fs_base, new_fs_base.as_ptr() as usize);

        // Restore old FS base
        let ptr: UserPtrMut<u8> = UserPtrMut::from_usize(old_fs_base);
        task.sys_arch_prctl(ArchPrctlArg::SetFs(ptr.as_usize()))
            .expect("Failed to restore FS base");
    }

    #[test]
    fn test_sched_getaffinity() {
        let task = crate::syscalls::tests::init_platform(None);

        let cpuset = task.sys_sched_getaffinity(None);
        assert_eq!(cpuset.bits.len(), super::NR_CPUS);
        cpuset.bits.iter().for_each(|b| assert!(*b));
        let ones: usize = cpuset
            .as_bytes()
            .iter()
            .map(|b| b.count_ones() as usize)
            .sum();
        assert_eq!(ones, super::NR_CPUS);
    }

    /// Reproduces the V8-startup-abort scenario this row was filed for: V8's own startup code
    /// aborts the whole process if `clock_gettime` returns an error for any of these clock IDs.
    /// Before this change, `ClockId::try_from` rejected everything but `RealTime`/`Monotonic`/
    /// `MonotonicCoarse`, so a real guest binary probing any of the other five clocks at startup
    /// (as V8 does) would see `clock_gettime` fail and abort. Verifies every clock ID Linux
    /// actually defines round-trips successfully through the real syscall path (`sys_clock_gettime`
    /// on `MacOsUserland`/`LinuxUserland`/`WindowsUserland`, backed by real host clocks -- not a
    /// mock), and returns a plausible (non-negative) value.
    #[test]
    fn test_clock_gettime_and_getres_succeed_for_every_clock_id() {
        use litebox_common_linux::{ClockId, TimeParam, Timespec};

        let task = crate::syscalls::tests::init_platform(None);

        for clock_id in [
            ClockId::RealTime,
            ClockId::Monotonic,
            ClockId::ProcessCpuTime,
            ClockId::ThreadCpuTime,
            ClockId::MonotonicRaw,
            ClockId::RealTimeCoarse,
            ClockId::MonotonicCoarse,
            ClockId::Boottime,
        ] {
            let mut ts = Timespec {
                tv_sec: -1,
                tv_nsec: 0,
            };
            let ptr = UserPtrMut::from_ptr(&raw mut ts);
            task.sys_clock_gettime(clock_id, TimeParam::Timespec64(ptr))
                .unwrap_or_else(|e| {
                    panic!(
                        "clock_gettime({clock_id:?}) unexpectedly failed with {e:?} -- this is \
                         exactly the error that makes V8 abort at startup"
                    )
                });
            assert!(
                ts.tv_sec >= 0,
                "clock_gettime({clock_id:?}) returned a nonsensical negative tv_sec: {}",
                ts.tv_sec
            );
            assert!(
                ts.tv_nsec < 1_000_000_000,
                "clock_gettime({clock_id:?}) returned an out-of-range tv_nsec: {}",
                ts.tv_nsec
            );

            let mut res = Timespec {
                tv_sec: -1,
                tv_nsec: 0,
            };
            let res_ptr = UserPtrMut::from_ptr(&raw mut res);
            task.sys_clock_getres(clock_id, TimeParam::Timespec64(res_ptr))
                .unwrap_or_else(|e| {
                    panic!("clock_getres({clock_id:?}) unexpectedly failed: {e:?}")
                });
            assert!(
                res.tv_sec > 0 || res.tv_nsec > 0,
                "clock_getres({clock_id:?}) reported a zero resolution"
            );
        }
    }

    /// The newly added monotonic-family clocks (`CLOCK_MONOTONIC_RAW`, `CLOCK_BOOTTIME`) must
    /// behave like real monotonic clocks: never go backwards, and actually advance across real
    /// elapsed wall-clock time.
    #[test]
    fn test_clock_gettime_monotonic_raw_and_boottime_are_monotonic() {
        use litebox_common_linux::{ClockId, TimeParam, Timespec};

        let task = crate::syscalls::tests::init_platform(None);

        let read = |clock_id: ClockId| -> Duration {
            let mut ts = Timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };
            let ptr = UserPtrMut::from_ptr(&raw mut ts);
            task.sys_clock_gettime(clock_id, TimeParam::Timespec64(ptr))
                .unwrap_or_else(|e| panic!("clock_gettime({clock_id:?}) failed: {e:?}"));
            Duration::try_from(ts).expect("valid timespec")
        };

        for clock_id in [ClockId::MonotonicRaw, ClockId::Boottime] {
            let before = read(clock_id);
            std::thread::sleep(Duration::from_millis(50));
            let after = read(clock_id);
            assert!(
                after > before,
                "{clock_id:?} did not advance across a real 50ms sleep: before={before:?} after={after:?}"
            );
        }
    }

    /// Real, host-sourced CPU-time accounting: `CLOCK_THREAD_CPUTIME_ID` must genuinely advance
    /// while the thread burns real CPU, and must *not* advance (by anywhere close to the same
    /// amount) while the thread is merely sleeping -- proving this isn't wall-clock time
    /// silently mislabeled as CPU time.
    #[test]
    fn test_clock_gettime_thread_cpu_time_tracks_real_cpu_usage_not_wall_clock() {
        use litebox_common_linux::{ClockId, TimeParam, Timespec};

        let task = crate::syscalls::tests::init_platform(None);

        let read_thread_cpu_time = || -> Duration {
            let mut ts = Timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };
            let ptr = UserPtrMut::from_ptr(&raw mut ts);
            task.sys_clock_gettime(ClockId::ThreadCpuTime, TimeParam::Timespec64(ptr))
                .expect("clock_gettime(CLOCK_THREAD_CPUTIME_ID) failed");
            Duration::try_from(ts).expect("valid timespec")
        };

        let before_busy = read_thread_cpu_time();

        // Burn real CPU on this thread. `std::hint::black_box` keeps the optimizer from
        // eliminating the loop.
        let mut acc: u64 = 0;
        for i in 0..300_000_000u64 {
            acc = std::hint::black_box(acc.wrapping_add(std::hint::black_box(i)));
        }
        std::hint::black_box(acc);

        let after_busy = read_thread_cpu_time();
        assert!(
            after_busy > before_busy,
            "thread CPU time did not increase after a real busy loop: before={before_busy:?} \
             after={after_busy:?}"
        );
        let consumed_by_busy_loop = after_busy.saturating_sub(before_busy);
        assert!(
            consumed_by_busy_loop > Duration::from_millis(1),
            "expected a meaningful amount of CPU time consumed by the busy loop, got \
             {consumed_by_busy_loop:?}"
        );

        // Sleep for much longer than the busy loop took, without doing any CPU work, and
        // confirm thread CPU time barely moves.
        std::thread::sleep(Duration::from_millis(300));
        let after_sleep = read_thread_cpu_time();
        let consumed_by_sleep = after_sleep.saturating_sub(after_busy);
        assert!(
            consumed_by_sleep < Duration::from_millis(100),
            "thread CPU time advanced by {consumed_by_sleep:?} across a 300ms *sleep* (no CPU \
             work performed) -- real CPU-time accounting should barely move here, this looks \
             like wall-clock time mislabeled as CPU time"
        );
    }

    /// `CLOCK_PROCESS_CPUTIME_ID` sums CPU time across the whole process; it must at least
    /// reflect the real CPU work done by the calling thread (the only thread in this test).
    #[test]
    fn test_clock_gettime_process_cpu_time_tracks_real_cpu_usage() {
        use litebox_common_linux::{ClockId, TimeParam, Timespec};

        let task = crate::syscalls::tests::init_platform(None);

        let read_process_cpu_time = || -> Duration {
            let mut ts = Timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };
            let ptr = UserPtrMut::from_ptr(&raw mut ts);
            task.sys_clock_gettime(ClockId::ProcessCpuTime, TimeParam::Timespec64(ptr))
                .expect("clock_gettime(CLOCK_PROCESS_CPUTIME_ID) failed");
            Duration::try_from(ts).expect("valid timespec")
        };

        let before = read_process_cpu_time();
        let mut acc: u64 = 0;
        for i in 0..300_000_000u64 {
            acc = std::hint::black_box(acc.wrapping_add(std::hint::black_box(i)));
        }
        std::hint::black_box(acc);
        let after = read_process_cpu_time();

        assert!(
            after > before,
            "process CPU time did not increase after a real busy loop: before={before:?} \
             after={after:?}"
        );
    }

    /// `clock_nanosleep` against a CPU-time clock can never wake up (a blocked thread cannot
    /// accumulate CPU time), so real Linux rejects it outright; confirm LiteBox does too now that
    /// these clock IDs are otherwise recognized.
    #[test]
    fn test_clock_nanosleep_rejects_cpu_time_clocks() {
        use litebox_common_linux::{ClockId, TimeParam, Timespec};

        let task = crate::syscalls::tests::init_platform(None);

        for clock_id in [ClockId::ProcessCpuTime, ClockId::ThreadCpuTime] {
            let mut request = Timespec {
                tv_sec: 0,
                tv_nsec: 1,
            };
            let result = task.sys_clock_nanosleep(
                clock_id,
                litebox_common_linux::TimerFlags::empty(),
                TimeParam::Timespec64(UserPtrMut::from_ptr(&raw mut request)),
                TimeParam::None,
            );
            assert_eq!(
                result,
                Err(litebox_common_linux::errno::Errno::EINVAL),
                "clock_nanosleep({clock_id:?}) should be rejected with EINVAL"
            );
        }
    }

    /// `sched_getscheduler`/`sched_setscheduler` round-trip: every thread is always reported as
    /// (and can always be, as a no-op, "set" to) `SCHED_OTHER`, matching what any real guest
    /// program checking "did the syscall succeed, and is the policy the plain default" would
    /// see.
    #[test]
    fn test_sched_getscheduler_and_setscheduler_round_trip() {
        use litebox_common_linux::sched_policy::SCHED_OTHER;

        let task = crate::syscalls::tests::init_platform(None);

        assert_eq!(
            task.sys_sched_getscheduler(None),
            Ok(usize::try_from(SCHED_OTHER).unwrap())
        );

        let param = litebox_common_linux::SchedParam { sched_priority: 0 };
        let param_ptr = UserPtr::from_ptr(&raw const param);
        assert_eq!(
            task.sys_sched_setscheduler(None, SCHED_OTHER, param_ptr),
            Ok(0)
        );

        // Also works when explicitly targeting our own tid (pid == 0 and pid == self.tid are
        // both "self", matching real Linux semantics for these thread-granularity syscalls).
        assert_eq!(
            task.sys_sched_getscheduler(Some(task.sys_gettid())),
            Ok(usize::try_from(SCHED_OTHER).unwrap())
        );
    }

    /// Real, unprivileged-process-accurate rejection: LiteBox guests never have `CAP_SYS_NICE`,
    /// so real-time policies must be rejected with `EPERM`, exactly as they would be on a real
    /// unprivileged Linux process. Also checks the ordinary `EINVAL` cases (unknown policy,
    /// out-of-range priority for `SCHED_OTHER`).
    #[test]
    fn test_sched_setscheduler_rejects_real_time_policies_and_bad_priority() {
        use litebox_common_linux::errno::Errno;
        use litebox_common_linux::sched_policy::{
            SCHED_DEADLINE, SCHED_FIFO, SCHED_OTHER, SCHED_RR,
        };

        let task = crate::syscalls::tests::init_platform(None);

        let param_zero = litebox_common_linux::SchedParam { sched_priority: 0 };
        let param_zero_ptr = UserPtr::from_ptr(&raw const param_zero);

        for policy in [SCHED_FIFO, SCHED_RR, SCHED_DEADLINE] {
            assert_eq!(
                task.sys_sched_setscheduler(None, policy, param_zero_ptr),
                Err(Errno::EPERM),
                "real-time policy {policy} should be rejected with EPERM (no CAP_SYS_NICE)"
            );
        }

        // An unrecognized policy value is EINVAL, not EPERM.
        assert_eq!(
            task.sys_sched_setscheduler(None, 0x1234, param_zero_ptr),
            Err(Errno::EINVAL)
        );

        // SCHED_OTHER only accepts priority 0.
        let param_nonzero = litebox_common_linux::SchedParam { sched_priority: 5 };
        let param_nonzero_ptr = UserPtr::from_ptr(&raw const param_nonzero);
        assert_eq!(
            task.sys_sched_setscheduler(None, SCHED_OTHER, param_nonzero_ptr),
            Err(Errno::EINVAL)
        );
    }

    /// `sched_getparam`/`sched_setparam` round-trip.
    #[test]
    fn test_sched_getparam_setparam_round_trip() {
        use litebox_common_linux::errno::Errno;

        let task = crate::syscalls::tests::init_platform(None);

        let mut got = litebox_common_linux::SchedParam { sched_priority: -1 };
        let got_ptr = UserPtrMut::from_ptr(&raw mut got);
        assert_eq!(task.sys_sched_getparam(None, got_ptr), Ok(0));
        assert_eq!(got.sched_priority, 0);

        let set = litebox_common_linux::SchedParam { sched_priority: 0 };
        let set_ptr = UserPtr::from_ptr(&raw const set);
        assert_eq!(task.sys_sched_setparam(None, set_ptr), Ok(0));

        let bad = litebox_common_linux::SchedParam { sched_priority: 1 };
        let bad_ptr = UserPtr::from_ptr(&raw const bad);
        assert_eq!(task.sys_sched_setparam(None, bad_ptr), Err(Errno::EINVAL));
    }

    /// None of the four `sched_*` syscalls can honestly answer for a thread other than the
    /// caller (LiteBox tracks no state for one), so a pid that isn't "self" must fail with
    /// `ESRCH`, matching what real Linux would do for a genuinely nonexistent target thread.
    #[test]
    fn test_sched_calls_reject_a_remote_pid() {
        use litebox_common_linux::errno::Errno;

        let task = crate::syscalls::tests::init_platform(None);
        let remote_pid = task.sys_gettid().wrapping_add(999_999);

        assert_eq!(
            task.sys_sched_getscheduler(Some(remote_pid)),
            Err(Errno::ESRCH)
        );

        let mut param = litebox_common_linux::SchedParam { sched_priority: 0 };
        let param_ptr = UserPtrMut::from_ptr(&raw mut param);
        assert_eq!(
            task.sys_sched_getparam(Some(remote_pid), param_ptr),
            Err(Errno::ESRCH)
        );

        let set_param = litebox_common_linux::SchedParam { sched_priority: 0 };
        let set_param_ptr = UserPtr::from_ptr(&raw const set_param);
        assert_eq!(
            task.sys_sched_setparam(Some(remote_pid), set_param_ptr),
            Err(Errno::ESRCH)
        );
        assert_eq!(
            task.sys_sched_setscheduler(
                Some(remote_pid),
                litebox_common_linux::sched_policy::SCHED_OTHER,
                set_param_ptr
            ),
            Err(Errno::ESRCH)
        );
    }

    /// `setpgid(0, N)` followed by `getpgid` (both `pid == 0` and the caller's own pid) must
    /// observe `N`.
    #[test]
    fn test_setpgid_getpgid_self_round_trip() {
        let task = crate::syscalls::tests::init_platform(None);

        assert_eq!(task.sys_setpgid(0, 4242), Ok(()));
        assert_eq!(task.sys_getpgid(0), Ok(4242));
        assert_eq!(task.sys_getpgid(task.pid), Ok(4242));
    }

    /// `setpgid(pid, 0)` means "make `pid` its own group leader" -- real `setpgid`'s
    /// well-known zero-pgid convention, used by busybox `ash` to start a new job.
    #[test]
    fn test_setpgid_zero_pgid_targets_own_pid() {
        let task = crate::syscalls::tests::init_platform(None);

        assert_eq!(task.sys_setpgid(0, 4242), Ok(()));
        assert_eq!(task.sys_setpgid(0, 0), Ok(()));
        assert_eq!(task.sys_getpgid(0), Ok(task.pid));
    }

    #[test]
    fn test_setpgid_rejects_negative_pgid() {
        use litebox_common_linux::errno::Errno;

        let task = crate::syscalls::tests::init_platform(None);

        assert_eq!(task.sys_setpgid(0, -1), Err(Errno::EINVAL));
    }

    /// A pid this shim cannot vouch for (neither the caller nor a recorded child) is `ESRCH` for
    /// both syscalls, matching real Linux's response to a genuinely nonexistent target.
    #[test]
    fn test_setpgid_getpgid_reject_unrelated_pid() {
        use litebox_common_linux::errno::Errno;

        let task = crate::syscalls::tests::init_platform(None);
        let unrelated_pid = task.pid.wrapping_add(999_999);

        assert_eq!(task.sys_getpgid(unrelated_pid), Err(Errno::ESRCH));
        assert_eq!(task.sys_setpgid(unrelated_pid, 4242), Err(Errno::ESRCH));
    }

    /// A recorded child (see `ProcessTable::add_child`, the same bookkeeping `wait4` reaps from)
    /// is a permitted `setpgid`/`getpgid` target, matching real Linux allowing a parent to move
    /// its own child into a group.
    #[test]
    fn test_setpgid_getpgid_accept_a_known_child() {
        let task = crate::syscalls::tests::init_platform(None);
        let child = task.pid.wrapping_add(1);
        task.global.processes.add_child(child, task.pid);

        assert_eq!(task.sys_setpgid(child, 4242), Ok(()));
        assert_eq!(task.sys_getpgid(child), Ok(4242));
    }

    /// `setpgid`/`getpgid` and the `TIOCSPGRP`/`TIOCGPGRP` ioctls (`syscalls::file::Task::
    /// stdio_ioctl`) read/write the exact same `global.pgid` field -- confirm each observes the
    /// other's writes, without needing the ioctl's own fd plumbing (which has no existing unit
    /// test harness in this codebase).
    #[test]
    fn test_setpgid_getpgid_share_state_with_tiocspgrp_tiocgpgrp() {
        let task = crate::syscalls::tests::init_platform(None);

        assert_eq!(task.sys_setpgid(0, 4242), Ok(()));
        assert_eq!(
            task.global.pgid.load(core::sync::atomic::Ordering::Acquire),
            4242,
            "a setpgid write must be visible to a TIOCGPGRP read"
        );

        task.global
            .pgid
            .store(99, core::sync::atomic::Ordering::Release);
        assert_eq!(
            task.sys_getpgid(0),
            Ok(99),
            "a TIOCSPGRP write must be visible to a getpgid read"
        );
    }

    #[test]
    fn test_prctl_set_get_name() {
        let task = crate::syscalls::tests::init_platform(None);

        // Prepare a null-terminated name to set
        let name: &[u8] = b"litebox-test\0";

        // Call prctl(PR_SET_NAME, set_buf)
        let set_ptr = UserPtr::from_ptr(name.as_ptr());
        task.sys_prctl(litebox_common_linux::PrctlArg::SetName(set_ptr))
            .expect("sys_prctl SetName failed");

        // Prepare buffer for prctl(PR_GET_NAME, get_buf)
        let mut get_buf = [0u8; litebox_common_linux::TASK_COMM_LEN];
        let get_ptr = UserPtrMut::from_ptr(get_buf.as_mut_ptr());

        task.sys_prctl(litebox_common_linux::PrctlArg::GetName(get_ptr))
            .expect("sys_prctl GetName failed");
        assert_eq!(
            &get_buf[..name.len()],
            name,
            "prctl get_name returned unexpected comm"
        );

        // Test too long name
        let long_name = [b'a'; litebox_common_linux::TASK_COMM_LEN + 10];
        let long_name_ptr = UserPtr::from_ptr(long_name.as_ptr());
        task.sys_prctl(litebox_common_linux::PrctlArg::SetName(long_name_ptr))
            .expect("sys_prctl SetName failed");

        // Get the name again
        let mut get_buf = [0u8; litebox_common_linux::TASK_COMM_LEN];
        let get_ptr = UserPtrMut::from_ptr(get_buf.as_mut_ptr());
        task.sys_prctl(litebox_common_linux::PrctlArg::GetName(get_ptr))
            .expect("sys_prctl GetName failed");
        assert_eq!(
            get_buf[litebox_common_linux::TASK_COMM_LEN - 1],
            0,
            "prctl get_name did not null-terminate the comm"
        );
        assert_eq!(
            &get_buf[..litebox_common_linux::TASK_COMM_LEN - 1],
            &long_name[..litebox_common_linux::TASK_COMM_LEN - 1],
            "prctl get_name returned unexpected comm for too long name"
        );
    }

    /// Installing a custom handler for SIGINT: a background OS thread sends
    /// a real SIGINT via `libc::kill`, which should interrupt a blocking sleep
    /// with `EINTR`.
    /// Target Linux only because it use tgkill syscall to send signal to specific thread.
    #[cfg(all(target_os = "linux", debug_assertions))]
    #[test]
    fn test_sigint_with_custom_handler() {
        use litebox_common_linux::signal::{SaFlags, SigAction, SigSet, Signal};
        use litebox_common_linux::{ClockId, TimerFlags, Timespec};

        let callback_addr = 0x1000usize; // dummy non-null address for the callback
        let task = crate::syscalls::tests::init_platform(None);
        <crate::syscalls::tests::TestPlatform as litebox::platform::ThreadProvider>::run_test_thread(|| {
            let act = SigAction {
                sigaction: callback_addr,
                flags: SaFlags::RESTORER,
                #[cfg(target_pointer_width = "64")]
                __pad: 0,
                restorer: 0,
                mask: SigSet::empty(),
            };
            let act_ptr = UserPtr::from_ptr(&raw const act);
            task.sys_rt_sigaction(
                Signal::SIGINT,
                Some(act_ptr),
                None,
                core::mem::size_of::<SigSet>(),
            )
            .expect("rt_sigaction failed");

            // Spawn a plain OS thread that sends a real SIGINT to this
            // specific thread after a short delay, giving it time to enter nanosleep.
            let pid = unsafe { libc::getpid() };
            let tid = unsafe { libc::syscall(libc::SYS_gettid) };
            let handle = std::thread::spawn(move || {
                std::thread::sleep(std::time::Duration::from_millis(200));
                // Safety: sending a signal to a thread in our own process is always valid.
                let ret = unsafe { libc::syscall(libc::SYS_tgkill, pid, tid, libc::SIGINT) };
                assert_eq!(ret, 0, "tgkill failed");
            });

            let mut request = Timespec {
                tv_sec: 10,
                tv_nsec: 0,
            };
            let result = task.sys_clock_nanosleep(
                ClockId::Monotonic,
                TimerFlags::empty(),
                litebox_common_linux::TimeParam::Timespec64(UserPtrMut::from_ptr(
                    &raw mut request,
                )),
                litebox_common_linux::TimeParam::None,
            );
            assert_eq!(
                result,
                Err(litebox_common_linux::errno::Errno::EINTR),
                "nanosleep should be interrupted by SIGINT from background thread"
            );

             // `process_signals` is called when about to switch back to userspace, so simulate that here.
             let mut stack = [0u8; 4096];
             #[cfg(target_arch = "x86_64")]
             let mut regs = litebox_common_linux::PtRegs { rsp: stack.as_mut_ptr() as usize + stack.len(), ..Default::default() };
             task.process_signals(&mut regs);
            assert_eq!(
                regs.get_ip(), callback_addr,
                "after processing signals, execution should be redirected to the custom handler"
            );

            handle.join().expect("background thread panicked");
        });
    }

    /// After the alarm deadline passes, a blocking operation should be
    /// interrupted and SIGALRM should be pending.
    #[test]
    fn test_alarm_fires_after_deadline() {
        use litebox::platform::{Instant as _, TimeProvider};
        use litebox_common_linux::{ClockId, TimerFlags, Timespec};

        let _guard = crate::syscalls::tests::async_signal_guard();
        let task = crate::syscalls::tests::init_platform(None);
        <crate::syscalls::tests::TestPlatform as litebox::platform::ThreadProvider>::run_test_thread(|| {
            let platform = task.global.platform;

            // Set a 1-second alarm.
            assert_eq!(task.sys_alarm(1).unwrap(), 0);

            let start = platform.now();

            // Block in a nanosleep longer than the alarm
            let mut remain = Timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };
            let mut request = Timespec {
                tv_sec: 3,
                tv_nsec: 0,
            };
            let result = task.sys_clock_nanosleep(
                ClockId::Monotonic,
                TimerFlags::empty(),
                litebox_common_linux::TimeParam::Timespec64(UserPtrMut::from_ptr(&raw mut request)),
                litebox_common_linux::TimeParam::Timespec64(UserPtrMut::from_ptr(&raw mut remain)),
            );

            let elapsed = platform.now().duration_since(&start);

            // The nanosleep should have been interrupted by SIGALRM.
            assert_eq!(
                result,
                Err(litebox_common_linux::errno::Errno::EINTR),
                "nanosleep should have been interrupted"
            );
            let millis = remain.tv_sec.cast_unsigned() * 1000 + remain.tv_nsec / 1_000_000;
            // Allow tolerance for timer imprecision (especially on Windows).
            assert!(
                (1900..=2100).contains(&millis),
                "expected ~2s remaining, got {millis:?}"
            );

            let elapsed_ms = elapsed.as_millis();
            std::println!("Alarm fired after {elapsed_ms} ms");
            assert!(
                (900..=1100).contains(&elapsed_ms),
                "expected alarm after ~1000 ms, got {elapsed_ms} ms"
            );

            // The alarm should be consumed (deadline cleared).
            let remaining = task.sys_alarm(0).unwrap();
            assert_eq!(remaining, 0, "alarm should have been cleared by check");
        });
    }

    /// Cancelling an alarm before it fires should prevent signal delivery
    /// even if a blocking operation runs past the original deadline.
    #[test]
    fn test_alarm_cancel_prevents_signal() {
        use litebox_common_linux::{ClockId, TimerFlags, Timespec};

        let _guard = crate::syscalls::tests::async_signal_guard();
        let task = crate::syscalls::tests::init_platform(None);
        <crate::syscalls::tests::TestPlatform as litebox::platform::ThreadProvider>::run_test_thread(|| {
            assert_eq!(task.sys_alarm(1).unwrap(), 0);
            // Cancel before it fires.
            let remaining = task.sys_alarm(0).unwrap();
            assert!(remaining >= 1, "alarm should still have had time remaining");

            // A short nanosleep past the original deadline should complete
            // normally — no signal should interrupt it.
            let mut request = Timespec {
                tv_sec: 2,
                tv_nsec: 0,
            };
            let result = task.sys_clock_nanosleep(
                ClockId::Monotonic,
                TimerFlags::empty(),
                litebox_common_linux::TimeParam::Timespec64(UserPtrMut::from_ptr(&raw mut request)),
                litebox_common_linux::TimeParam::None,
            );
            assert_eq!(result, Ok(()), "nanosleep should not have been interrupted");

            assert!(
                !task.has_pending_signals(),
                "cancelled alarm should not produce SIGALRM"
            );
        });
    }

    #[test]
    fn test_pause_wakes_on_pending_signal() {
        use litebox_common_linux::{
            PtRegs,
            errno::Errno,
            signal::{SigSet, SigmaskHow, Signal},
        };

        let _guard = crate::syscalls::tests::async_signal_guard();
        let task = crate::syscalls::tests::init_platform(None);
        <crate::syscalls::tests::TestPlatform as litebox::platform::ThreadProvider>::run_test_thread(|| {
            let block_set = SigSet::empty().with(Signal::SIGUSR1);
            task.sys_rt_sigprocmask(
                SigmaskHow::SIG_BLOCK,
                Some(UserPtr::from_ptr(&raw const block_set)),
                None,
                core::mem::size_of::<SigSet>(),
            )
            .expect("block SIGUSR1 failed");

            assert_eq!(task.sys_alarm(1).unwrap(), 0);
            task.sys_tkill(task.tid, Signal::SIGUSR1.as_i32())
                .expect("tkill failed");
            assert!(!task.has_pending_signals(), "blocked SIGUSR1 should not be deliverable");

            let mut regs = PtRegs::default();
            task.process_signals(&mut regs);
            assert!(!task.has_pending_signals(), "blocked SIGUSR1 should remain undeliverable");

            task.sys_rt_sigprocmask(
                SigmaskHow::SIG_UNBLOCK,
                Some(UserPtr::from_ptr(&raw const block_set)),
                None,
                core::mem::size_of::<SigSet>(),
            )
            .expect("unblock SIGUSR1 failed");

            assert_eq!(task.sys_pause(), Err(Errno::EINTR));
            task.sys_alarm(0).unwrap();

            let pending = task.pending_signal_set();
            assert!(pending.contains(Signal::SIGUSR1), "expected SIGUSR1 pending");
            assert!(
                !pending.contains(Signal::SIGALRM),
                "SIGALRM must not be what woke pause()"
            );
        });
    }

    /// Setting alarm with SIG_IGN for SIGALRM: a blocking operation is still
    /// interrupted, but `process_signals` discards the signal.
    #[test]
    fn test_alarm_with_sigign() {
        use litebox_common_linux::signal::{SIG_IGN, SaFlags, SigAction, SigSet, Signal};
        use litebox_common_linux::{ClockId, TimerFlags, Timespec};

        let _guard = crate::syscalls::tests::async_signal_guard();
        let task = crate::syscalls::tests::init_platform(None);
        <crate::syscalls::tests::TestPlatform as litebox::platform::ThreadProvider>::run_test_thread(|| {
            // Install SIG_IGN for SIGALRM.
            let act = SigAction {
                sigaction: SIG_IGN,
                flags: SaFlags::empty(),
                #[cfg(target_pointer_width = "64")]
                __pad: 0,
                restorer: 0,
                mask: SigSet::empty(),
            };
            let act_ptr = UserPtr::from_ptr(&raw const act);
            task.sys_rt_sigaction(
                Signal::SIGALRM,
                Some(act_ptr),
                None,
                core::mem::size_of::<SigSet>(),
            )
            .expect("rt_sigaction failed");

            // Set a 1-second alarm and block in a short nanosleep.
            assert_eq!(task.sys_alarm(1).unwrap(), 0);
            let mut request = Timespec {
                tv_sec: 3,
                tv_nsec: 0,
            };
            let result = task.sys_clock_nanosleep(
                ClockId::Monotonic,
                TimerFlags::empty(),
                litebox_common_linux::TimeParam::Timespec64(UserPtrMut::from_ptr(&raw mut request)),
                litebox_common_linux::TimeParam::None,
            );

            // With SIG_IGN, nanosleep should NOT be interrupted — matching real
            // Linux behaviour where ignored signals are silently dropped at
            // send time and never make blocking syscalls return EINTR.
            assert_eq!(
                result,
                Ok(()),
                "nanosleep should complete normally when SIGALRM is ignored"
            );

            // No pending signals because the ignored SIGALRM was silently dropped.
            assert!(
                !task.has_pending_signals(),
                "SIG_IGN should cause SIGALRM to be silently dropped"
            );
        });
    }

    #[test]
    fn test_timer_delivers_correct_signal() {
        use litebox::platform::{TimerHandle as _, TimerProvider as _};
        use litebox_common_linux::signal::Signal;
        use litebox_common_linux::{ClockId, TimerFlags, Timespec};

        let _guard = crate::syscalls::tests::async_signal_guard();
        let task = crate::syscalls::tests::init_platform(None);
        <crate::syscalls::tests::TestPlatform as litebox::platform::ThreadProvider>::run_test_thread(|| {
            let platform = task.global.platform;

            // Create a timer that requests SIGUSR1
            let handle = platform
                .create_timer(Signal::SIGUSR1)
                .expect("create_timer failed");
            handle.set_timer(core::time::Duration::from_secs(1));

            // Block in a nanosleep longer than the timer.
            let mut request = Timespec {
                tv_sec: 5,
                tv_nsec: 0,
            };
            let result = task.sys_clock_nanosleep(
                ClockId::Monotonic,
                TimerFlags::empty(),
                litebox_common_linux::TimeParam::Timespec64(UserPtrMut::from_ptr(
                    &raw mut request,
                )),
                litebox_common_linux::TimeParam::None,
            );
            // The nanosleep should have been interrupted.
            assert_eq!(
                result,
                Err(litebox_common_linux::errno::Errno::EINTR),
                "nanosleep should be interrupted by the timer"
            );

            // Verify that SIGUSR1 (not SIGALRM) is the pending signal.
            let pending = task.pending_signal_set();
            assert!(
                pending.contains(Signal::SIGUSR1),
                "expected SIGUSR1 pending"
            );
            assert!(
                !pending.contains(Signal::SIGALRM),
                "SIGALRM should NOT be pending — the timer should have delivered SIGUSR1 instead"
            );

            // Clean up the timer.
            handle.delete_timer();
        });
    }

    #[test]
    fn test_parse_shebang_basic() {
        use super::parse_shebang;

        // Basic interpreter only
        assert_eq!(
            parse_shebang(b"#!/bin/bash\necho hello\n"),
            Some(("/bin/bash", None))
        );

        // Interpreter with single argument
        assert_eq!(
            parse_shebang(b"#!/usr/bin/env python3\nimport sys\n"),
            Some(("/usr/bin/env", Some("python3")))
        );

        // Leading spaces after #!
        assert_eq!(parse_shebang(b"#!  /bin/sh\n"), Some(("/bin/sh", None)));

        // Trailing spaces
        assert_eq!(parse_shebang(b"#!/bin/sh  \n"), Some(("/bin/sh", None)));

        // Argument with extra whitespace
        assert_eq!(
            parse_shebang(b"#!/usr/bin/env  -S python3\n"),
            Some(("/usr/bin/env", Some("-S python3")))
        );

        // No newline (truncated line — still valid)
        assert_eq!(parse_shebang(b"#!/bin/bash"), Some(("/bin/bash", None)));

        // Not a shebang
        assert_eq!(parse_shebang(b"\x7fELF"), None);

        // Empty after #!
        assert_eq!(parse_shebang(b"#!\n"), None);

        // Too short
        assert_eq!(parse_shebang(b"#"), None);
        assert_eq!(parse_shebang(b""), None);

        // Tab separator
        assert_eq!(
            parse_shebang(b"#!/usr/bin/env\tpython3\n"),
            Some(("/usr/bin/env", Some("python3")))
        );
    }

    #[test]
    fn test_setuid_privileged_sets_uid_and_euid() {
        let task = crate::syscalls::tests::init_platform(None);
        assert_eq!(task.sys_getuid(), 0);

        task.sys_setuid(1000)
            .expect("privileged setuid to an arbitrary uid should succeed");
        assert_eq!(task.sys_getuid(), 1000);
        assert_eq!(task.sys_geteuid(), 1000);
    }

    #[test]
    fn test_setuid_unprivileged_restricted_to_current_ids() {
        use litebox_common_linux::errno::Errno;

        let task = crate::syscalls::tests::init_platform(None);
        task.sys_setuid(1000)
            .expect("privileged setuid should succeed");

        // No longer privileged: switching to its own uid is a no-op success...
        task.sys_setuid(1000)
            .expect("setuid to the caller's own uid should succeed");
        // ...but becoming any other uid is not.
        let err = task.sys_setuid(0).unwrap_err();
        assert_eq!(err, Errno::EPERM);
        assert_eq!(task.sys_getuid(), 1000);
    }

    #[test]
    fn test_setgid_privileged_sets_gid_and_egid() {
        let task = crate::syscalls::tests::init_platform(None);
        assert_eq!(task.sys_getgid(), 0);

        task.sys_setgid(1000)
            .expect("privileged setgid to an arbitrary gid should succeed");
        assert_eq!(task.sys_getgid(), 1000);
        assert_eq!(task.sys_getegid(), 1000);
    }

    #[test]
    fn test_setgid_unprivileged_restricted_to_current_ids() {
        use litebox_common_linux::errno::Errno;

        let task = crate::syscalls::tests::init_platform(None);
        // The privilege check keys off euid, not gid, so pick a gid while
        // still privileged, then drop uid to make the calls below run
        // unprivileged and confirm the gid check isn't secretly keying off uid.
        task.sys_setgid(2000)
            .expect("privileged setgid should succeed");
        task.sys_setuid(1000)
            .expect("privileged setuid should succeed");

        task.sys_setgid(2000)
            .expect("setgid to the caller's own gid should succeed");
        let err = task.sys_setgid(0).unwrap_err();
        assert_eq!(err, Errno::EPERM);
        assert_eq!(task.sys_getgid(), 2000);
    }

    #[test]
    fn test_setuid_does_not_affect_sibling_thread_credentials() {
        let task = crate::syscalls::tests::init_platform(None);
        let sibling = task
            .clone_for_test()
            .expect("clone_for_test should succeed");

        task.sys_setuid(1000).expect("setuid should succeed");

        assert_eq!(task.sys_getuid(), 1000);
        assert_eq!(sibling.sys_getuid(), 0);
    }

    #[test]
    fn test_prlimit_own_pid_is_self() {
        let task = crate::syscalls::tests::init_platform(None);

        task.sys_prlimit(
            task.pid,
            litebox_common_linux::RlimitResource::NOFILE,
            None,
            None,
        )
        .expect("own pid should be treated the same as pid 0");
        task.sys_prlimit(0, litebox_common_linux::RlimitResource::NOFILE, None, None)
            .expect("pid 0 should still mean self");
    }

    #[test]
    fn test_get_robust_list_own_tid_is_self() {
        let task = crate::syscalls::tests::init_platform(None);

        let mut head_via_tid: usize = 0;
        task.sys_get_robust_list(Some(task.tid), UserPtrMut::from_ptr(&raw mut head_via_tid))
            .expect("own tid should be treated the same as pid None");

        let mut head_via_none: usize = 0;
        task.sys_get_robust_list(None, UserPtrMut::from_ptr(&raw mut head_via_none))
            .expect("None should still mean self");

        assert_eq!(head_via_tid, head_via_none);
    }

    /// Real threads, real `sys_futex` syscalls: `FUTEX_REQUEUE` must wake exactly
    /// `num_to_wake` waiters directly and *move* the rest onto the second futex word's own wait
    /// queue without waking them -- provable only by observing that the requeued waiters stay
    /// blocked until a separate, later `FUTEX_WAKE` on the new address, not merely that every
    /// thread eventually finishes.
    #[test]
    fn test_futex_requeue_across_real_threads() {
        use litebox_common_linux::{FutexArgs, FutexFlags, TimeParam};
        use std::sync::Barrier;
        use std::sync::atomic::{AtomicUsize, Ordering};

        const N: usize = 4;
        const NUM_TO_WAKE: u32 = 1;

        let task = crate::syscalls::tests::init_platform(None);

        // Real, shared guest-visible memory for both futex words; each spawned thread reaches it
        // via the raw address (a `Send` `usize`), reconstructing the pointer on its own thread,
        // exactly as translated syscall arguments would be.
        let mut futex1: u32 = 0;
        let mut futex2: u32 = 0;
        let futex1_addr = core::ptr::from_mut(&mut futex1) as usize;
        let futex2_addr = core::ptr::from_mut(&mut futex2) as usize;

        let completed = std::sync::Arc::new(AtomicUsize::new(0));
        let ready = std::sync::Arc::new(Barrier::new(N + 1));

        let waiters: std::vec::Vec<_> = (0..N)
            .map(|_| {
                let completed = std::sync::Arc::clone(&completed);
                let ready = std::sync::Arc::clone(&ready);
                task.spawn_clone_for_test(move |task| {
                    ready.wait();
                    let result = task.sys_futex(FutexArgs::Wait {
                        addr: UserPtrMut::from_usize(futex1_addr),
                        flags: FutexFlags::PRIVATE,
                        val: 0,
                        timeout: TimeParam::Milliseconds(10_000),
                    });
                    completed.fetch_add(1, Ordering::SeqCst);
                    result
                })
            })
            .collect();

        ready.wait(); // release all N waiters together
        std::thread::sleep(core::time::Duration::from_millis(100)); // let them genuinely block

        let woken = task
            .sys_futex(FutexArgs::Requeue {
                addr: UserPtrMut::from_usize(futex1_addr),
                flags: FutexFlags::PRIVATE,
                num_to_wake: NUM_TO_WAKE,
                num_to_requeue: u32::try_from(N).unwrap() - NUM_TO_WAKE,
                addr2: UserPtrMut::from_usize(futex2_addr),
            })
            .expect("futex requeue failed");
        assert_eq!(
            usize::try_from(NUM_TO_WAKE).unwrap(),
            woken,
            "futex(FUTEX_REQUEUE) returns the wake count, not the requeue count"
        );

        // Give the directly-woken waiter(s) ample time to actually return, and any
        // incorrectly-also-woken requeued waiters a real chance to (wrongly) return too.
        std::thread::sleep(core::time::Duration::from_millis(150));
        assert_eq!(
            completed.load(Ordering::SeqCst),
            usize::try_from(NUM_TO_WAKE).unwrap(),
            "only the directly-woken waiter(s) should have returned -- the requeued ones must \
             still be genuinely blocked, now waiting on futex2, not woken early by the requeue \
             call itself"
        );

        // A stale wake on the *original* address must find nobody left there.
        let woken_on_stale_addr = task
            .sys_futex(FutexArgs::Wake {
                addr: UserPtrMut::from_usize(futex1_addr),
                flags: FutexFlags::PRIVATE,
                count: u32::MAX,
            })
            .expect("wake on stale addr failed");
        assert_eq!(
            woken_on_stale_addr, 0,
            "the requeued waiters must have genuinely moved off futex1's wait queue"
        );

        // Now wake the requeued waiters via their new address.
        let woken_on_addr2 = task
            .sys_futex(FutexArgs::Wake {
                addr: UserPtrMut::from_usize(futex2_addr),
                flags: FutexFlags::PRIVATE,
                count: u32::MAX,
            })
            .expect("wake on addr2 failed");
        assert_eq!(
            woken_on_addr2,
            N - usize::try_from(NUM_TO_WAKE).unwrap(),
            "every requeued waiter must be discoverable, and wakeable, via the new address"
        );

        for waiter in waiters {
            waiter
                .join()
                .expect("waiter thread panicked")
                .expect("sys_futex(Wait) should not have errored");
        }
        assert_eq!(completed.load(Ordering::SeqCst), N);
    }

    /// Real threads, real `sys_futex` syscalls: `FUTEX_CMP_REQUEUE` must actually check the
    /// futex word before requeuing and fail with `EAGAIN` (never wake or move anyone) once it no
    /// longer matches -- the documented race-closing behavior that plain `FUTEX_REQUEUE` does
    /// not perform.
    #[test]
    fn test_futex_cmp_requeue_rejects_stale_value_across_real_threads() {
        use litebox_common_linux::errno::Errno;
        use litebox_common_linux::{FutexArgs, FutexFlags, TimeParam};

        let task = crate::syscalls::tests::init_platform(None);

        let mut futex1: u32 = 5;
        let mut futex2: u32 = 0;
        let futex1_addr = core::ptr::from_mut(&mut futex1) as usize;
        let futex2_addr = core::ptr::from_mut(&mut futex2) as usize;

        let waiter = task.spawn_clone_for_test(move |task| {
            task.sys_futex(FutexArgs::Wait {
                addr: UserPtrMut::from_usize(futex1_addr),
                flags: FutexFlags::PRIVATE,
                val: 5,
                timeout: TimeParam::Milliseconds(10_000),
            })
        });

        std::thread::sleep(core::time::Duration::from_millis(100)); // let it genuinely block

        let err = task
            .sys_futex(FutexArgs::CmpRequeue {
                addr: UserPtrMut::from_usize(futex1_addr),
                flags: FutexFlags::PRIVATE,
                num_to_wake: 1,
                num_to_requeue: 0,
                addr2: UserPtrMut::from_usize(futex2_addr),
                expected_value: 999, // stale on purpose: the real word is still 5
            })
            .expect_err("a value-mismatched CMP_REQUEUE must fail, not silently requeue");
        assert_eq!(err, Errno::EAGAIN);

        // The waiter must still be genuinely blocked on the original address.
        let woken = task
            .sys_futex(FutexArgs::Wake {
                addr: UserPtrMut::from_usize(futex1_addr),
                flags: FutexFlags::PRIVATE,
                count: 1,
            })
            .expect("wake on futex1 failed");
        assert_eq!(
            woken, 1,
            "the waiter must still be on futex1's own wait queue -- a mismatched CMP_REQUEUE \
             must not have moved it"
        );

        waiter
            .join()
            .expect("waiter thread panicked")
            .expect("sys_futex(Wait) should not have errored");
    }

    /// Regression test for a thread that dies while still recorded as the owner of a robust
    /// futex: [`Task::handle_futex_death`] must set [`FUTEX_OWNER_DIED`] on the futex word and
    /// wake a waiter -- mirroring Linux's `handle_futex_death`/`exit_robust_list`
    /// (`kernel/futex/core.c`). Before this fix, `handle_futex_death` was `todo!()`, so any
    /// dying thread whose robust list was non-empty would panic mid-teardown instead of
    /// notifying waiters, permanently stranding a sibling thread blocked in `FUTEX_WAIT` on that
    /// lock.
    ///
    /// This drives `Task::handle_futex_death` directly (rather than round-tripping through a
    /// hand-built `RobustListHead`/`RobustList` guest-memory layout, which is real guest-ABI
    /// plumbing already covered by `wake_robust_list`'s straightforward list-walking logic) to
    /// isolate exactly the piece that was unimplemented: does processing one owned, waited-on
    /// futex entry correctly mark it dead and wake the waiter, without panicking.
    #[test]
    fn test_handle_futex_death_wakes_waiter_and_sets_owner_died() {
        use litebox_common_linux::{FutexArgs, FutexFlags, TimeParam};
        use std::sync::Barrier;
        use std::sync::atomic::{AtomicU32, Ordering};

        let task = crate::syscalls::tests::init_platform(None);

        let mut futex_word: u32 = 0;
        let futex_addr = core::ptr::from_mut(&mut futex_word) as usize;
        let barrier = std::sync::Arc::new(Barrier::new(2));

        let bg = {
            let barrier = std::sync::Arc::clone(&barrier);
            task.spawn_clone_for_test(move |bg_task| {
                // Simulate this (cloned) thread having locked a robust mutex: the futex word
                // records this thread as owner, with the waiters bit set since the main thread
                // is about to block on it.
                #[expect(clippy::cast_sign_loss, reason = "tid is always non-negative")]
                let owner_word = (bg_task.tid as u32) | super::FUTEX_WAITERS;
                let futex_atomic = unsafe { &*(futex_addr as *const AtomicU32) };
                futex_atomic.store(owner_word, Ordering::SeqCst);

                barrier.wait();
                // Give the main thread time to actually park in FUTEX_WAIT before "dying" --
                // otherwise this would trivially pass even with the pre-fix `todo!()` never
                // running (there would be nothing parked to prove got woken).
                std::thread::sleep(core::time::Duration::from_millis(100));

                bg_task
                    .handle_futex_death(UserPtr::from_usize(futex_addr), false)
                    .expect("handle_futex_death should not error for a well-formed entry");
            })
        };

        barrier.wait();
        let owner_word = {
            let futex_atomic = unsafe { &*(futex_addr as *const AtomicU32) };
            futex_atomic.load(Ordering::SeqCst)
        };
        let result = task.sys_futex(FutexArgs::Wait {
            addr: UserPtrMut::from_usize(futex_addr),
            flags: FutexFlags::PRIVATE,
            val: owner_word,
            timeout: TimeParam::Milliseconds(10_000),
        });
        assert_eq!(
            result,
            Ok(0),
            "main thread's FUTEX_WAIT on the robust futex should be woken once \
             handle_futex_death runs for its dying owner, not hang forever"
        );

        let final_word = {
            let futex_atomic = unsafe { &*(futex_addr as *const AtomicU32) };
            futex_atomic.load(Ordering::SeqCst)
        };
        assert_eq!(
            final_word & super::FUTEX_OWNER_DIED,
            super::FUTEX_OWNER_DIED,
            "the futex word should have FUTEX_OWNER_DIED set once its owner dies without \
             unlocking"
        );

        bg.join().expect("background thread panicked");
    }

    /// Real process-exit teardown (`prepare_for_exit`), a real pipe, and a real epoll
    /// registration on its write end: proves a still-open write-end fd left behind when the
    /// *last* thread of a process exits -- with no explicit `close()` from the guest, exactly
    /// how a real Linux program that just calls `_exit()` (or crashes) behaves, relying on the
    /// kernel to close its fds -- is unconditionally closed, so a reader elsewhere gets `EOF`
    /// instead of hanging forever, regardless of the epoll registration.
    #[test]
    fn test_process_exit_closes_pipe_write_end_even_with_epoll_registered() {
        use litebox::fd::TypedFd;
        use litebox::fs::OFlags;
        use litebox::pipes::Pipes;
        use litebox_common_linux::{EpollCreateFlags, EpollEvent, EpollOp};

        let writer_task = crate::syscalls::tests::init_platform(None);
        let fs = writer_task.files.borrow().fs.clone();
        // A second, wholly independent process -- its own `Process` and its own `FilesState` --
        // sharing only the same underlying `GlobalState`/`litebox` object, exactly as two real
        // OS processes sharing one machine would. This is what makes "the reader is unaffected
        // by the writer's own fd-table teardown" a meaningful, non-tautological claim: the
        // reader's fd table is not the one `prepare_for_exit` walks.
        let reader_task = writer_task.global.clone().new_test_task(fs);

        let (read_fd, write_fd) = writer_task
            .sys_pipe2(OFlags::empty())
            .expect("pipe2 failed");
        let write_fd_i32 = i32::try_from(write_fd).unwrap();

        // Register the write end with an epoll instance the writer also owns -- the exact
        // scenario under investigation: an epoll registration must not keep the write end alive
        // past the writer's exit.
        let epfd = writer_task
            .sys_epoll_create(EpollCreateFlags::empty())
            .expect("epoll_create failed");
        let event = EpollEvent::new(litebox::event::Events::OUT.bits(), 0);
        writer_task
            .sys_epoll_ctl(
                i32::try_from(epfd).unwrap(),
                EpollOp::EpollCtlAdd,
                write_fd_i32,
                UserPtr::from_ptr(&raw const event),
            )
            .expect("epoll_ctl(ADD) on the write end failed");

        // Hand the *read* end to the independent reader process, mirroring what real fd
        // inheritance (fork, or SCM_RIGHTS over a Unix socket) would produce: a second,
        // independent owning reference to the same underlying pipe object, reachable through a
        // completely different process's fd table.
        let dup_read_fd = {
            let writer_files = writer_task.files.borrow();
            let rds = writer_files.raw_descriptor_store.read();
            let original: alloc::sync::Arc<TypedFd<Pipes<crate::syscalls::tests::TestPlatform>>> =
                rds.fd_from_raw_integer(read_fd as usize).unwrap();
            drop(rds);
            writer_task
                .global
                .litebox
                .descriptor_table_mut()
                .duplicate(&original)
                .expect("duplicating the read end should succeed")
        };
        let reader_raw_fd = {
            let reader_files = reader_task.files.borrow();
            let mut rds = reader_files.raw_descriptor_store.write();
            rds.fd_into_raw_integer(dup_read_fd)
        };
        let reader_raw_fd = i32::try_from(reader_raw_fd).unwrap();

        // The reader blocks in a real `read()` on its own, independent fd, waiting for EOF.
        let reader = reader_task.spawn_clone_for_test(move |task| {
            let mut buf = [0u8; 1];
            task.sys_read(reader_raw_fd, &mut buf, None)
        });

        std::thread::sleep(core::time::Duration::from_millis(100)); // let it genuinely block
        assert!(
            !reader.is_finished(),
            "the reader should still be blocked: the write end is still open"
        );

        // The writer "process" exits -- its last (only) thread -- *without* explicitly closing
        // either the pipe write end or the epoll fd.
        drop(writer_task);

        let result = reader
            .join()
            .expect("reader thread panicked")
            .expect("read() should not have errored");
        assert_eq!(
            result, 0,
            "the reader should observe EOF (a 0-byte read) once the writer's process exits, not \
             hang forever"
        );
    }

    /// [`super::OwnedRanges`] has to be a real set -- inserting over, and removing out of the
    /// middle of, an existing range must split rather than drop or duplicate it -- because a
    /// stale entry would let `fork`'s snapshot roll back memory that by then belongs to a
    /// different guest process.
    #[test]
    fn owned_ranges_splits_on_partial_overlap() {
        let mut ranges = super::OwnedRanges::default();
        ranges.insert(0x1000..0x5000);

        // A hole punched out of the middle leaves the two ends.
        ranges.remove(0x2000..0x3000);
        assert_eq!(
            ranges
                .intersect(&(0..0x10000))
                .collect::<std::vec::Vec<_>>(),
            std::vec![0x1000..0x2000, 0x3000..0x5000]
        );

        // Re-inserting across the hole coalesces back into one entry, replacing what it overlaps
        // rather than duplicating it.
        ranges.insert(0x1000..0x5000);
        assert_eq!(
            ranges
                .intersect(&(0..0x10000))
                .collect::<std::vec::Vec<_>>(),
            std::vec![0x1000..0x5000]
        );

        // `intersect` clips to the queried range, since callers use it to pick the owned parts of
        // a mapping that may extend past them.
        assert_eq!(
            ranges
                .intersect(&(0x4000..0x9000))
                .collect::<std::vec::Vec<_>>(),
            std::vec![0x4000..0x5000]
        );

        ranges.remove(0..usize::MAX);
        assert_eq!(ranges.intersect(&(0..0x10000)).count(), 0);
    }

    /// The `wstatus` word `wait4` writes is what libc's `WIFEXITED`/`WEXITSTATUS`/`WTERMSIG`
    /// decode, so the packing has to match theirs exactly -- a shell reports `$?` straight out of
    /// it.
    #[test]
    fn wait_status_matches_the_libc_macros() {
        use litebox_common_linux::signal::Signal;

        let exited = super::encode_wait_status(super::ExitStatus::Exit(42));
        assert_eq!(exited & 0x7f, 0, "WIFEXITED: low seven bits clear");
        assert_eq!((exited >> 8) & 0xff, 42, "WEXITSTATUS");

        let zero = super::encode_wait_status(super::ExitStatus::Exit(0));
        assert_eq!(zero, 0);

        // An exit code is truncated to 8 bits by the kernel, so `exit(-1)` reads back as 255.
        assert_eq!(
            (super::encode_wait_status(super::ExitStatus::Exit(-1)) >> 8) & 0xff,
            255
        );

        let killed = super::encode_wait_status(super::ExitStatus::Signal(Signal::SIGSEGV));
        assert_eq!(killed & 0x7f, Signal::SIGSEGV.as_i32(), "WTERMSIG");
        assert_ne!(
            killed & 0x7f,
            0,
            "WIFEXITED must be false for a signal death"
        );
    }

    /// `wait4` has to distinguish "no children at all" (`ECHILD`) from "children, none finished"
    /// (block, or return 0 under `WNOHANG`), and must reap exactly once.
    #[test]
    fn wait4_reports_no_children_children_running_and_a_finished_child() {
        use litebox_common_linux::errno::Errno;
        const WNOHANG: i32 = 1;
        let task = crate::syscalls::tests::init_platform(None);
        let table = &task.global.processes;

        assert_eq!(
            task.sys_wait4(-1, None, 0, 0).unwrap_err(),
            Errno::ECHILD,
            "a task with no children cannot wait for one"
        );

        let child = 0x4242;
        table.add_child(child, task.pid);
        assert_eq!(
            task.sys_wait4(-1, None, WNOHANG, 0).unwrap(),
            0,
            "a running child is not reapable, and WNOHANG must not block for it"
        );
        assert_eq!(
            task.sys_wait4(child + 1, None, WNOHANG, 0).unwrap_err(),
            Errno::ECHILD,
            "waiting for a pid that is not our child is ECHILD even though we have one"
        );

        table.record_exit(child, super::ExitStatus::Exit(7), 0);
        let mut status = 0i32;
        let status_ptr = UserPtrMut::from_ptr(&raw mut status);
        assert_eq!(task.sys_wait4(-1, Some(status_ptr), 0, 0).unwrap(), child);
        assert_eq!((status >> 8) & 0xff, 7);

        assert_eq!(
            task.sys_wait4(-1, None, 0, 0).unwrap_err(),
            Errno::ECHILD,
            "a reaped child is gone: waiting again is ECHILD, not a second reap"
        );
    }

    /// Regression test for a `wait4(..., &rusage)` bug: the buffer used to be left completely
    /// untouched whenever a caller passed one, so a reader like `busybox time` printed whatever
    /// was already sitting in that guest memory -- observed in practice as `sys 2367004162h 16m
    /// 32s`. `sys_wait4` must now populate it for real, using each thread's host-measured CPU
    /// time (see `Process::cpu_time_nanos`), and must not leave any field -- including the ones
    /// this shim cannot measure -- as leftover uninitialized memory.
    #[test]
    fn wait4_populates_real_rusage_instead_of_leaving_it_uninitialized() {
        use litebox_common_linux::{Rusage, TimeVal};
        use zerocopy::{FromBytes as _, IntoBytes as _};

        let task = crate::syscalls::tests::init_platform(None);
        let table = &task.global.processes;

        let child = 0x4343;
        table.add_child(child, task.pid);
        // As if the child had genuinely consumed 2.5s of host CPU time across its threads.
        let cpu_time = Duration::from_millis(2500);
        table.record_exit(
            child,
            super::ExitStatus::Exit(0),
            u64::try_from(cpu_time.as_nanos()).unwrap(),
        );

        // A sentinel fill: if `sys_wait4` ever again leaves the buffer untouched, this pattern
        // survives every assertion below rather than silently reading back as zero.
        let mut buf = [0xAAu8; core::mem::size_of::<Rusage>()];
        let rusage_ptr = UserPtrMut::<Rusage>::from_ptr(buf.as_mut_ptr().cast());

        assert_eq!(
            task.sys_wait4(-1, None, 0, rusage_ptr.as_usize()).unwrap(),
            child
        );

        let rusage = Rusage::read_from_bytes(&buf).unwrap();
        assert_eq!(
            rusage.ru_utime.as_bytes(),
            TimeVal::from(cpu_time).as_bytes(),
            "ru_utime must be the real, host-measured CPU time, not the sentinel or garbage"
        );
        assert_eq!(
            rusage.ru_stime.as_bytes(),
            TimeVal::default().as_bytes(),
            "ru_stime is honestly zero (this shim has no meaningful kernel time of its own to \
             attribute), not the sentinel"
        );
        assert_eq!(
            rusage.ru_maxrss, 0,
            "unmeasured fields are zeroed, not sentinel garbage"
        );
        assert_eq!(
            rusage._reserved, [0i64; 16],
            "the musl reserved tail is zeroed too, not left as sentinel garbage"
        );
    }

    /// A `fork`ed child gets its own descriptor *table* over the same open file *descriptions*.
    /// The shell relies on both halves: it rearranges fds 0/1/2 for the command it is about to
    /// `exec` (which must not reach back into the shell), and it expects the descriptions
    /// themselves -- offsets, pipe ends -- to be shared with what it forked from.
    #[test]
    fn fork_copies_the_descriptor_table_but_shares_the_descriptions() {
        let _guard = crate::syscalls::tests::address_space_guard();
        let task = crate::syscalls::tests::init_platform(None);

        let (read_fd, write_fd) = task.sys_pipe2(litebox::fs::OFlags::empty()).unwrap();
        let (read_fd, write_fd) = (
            i32::try_from(read_fd).unwrap(),
            i32::try_from(write_fd).unwrap(),
        );

        let child_files = task.files.borrow().fork_copy(&task).unwrap();
        let child_fds: std::vec::Vec<usize> = child_files
            .raw_descriptor_store
            .read()
            .iter_alive()
            .collect();
        let parent_fds: std::vec::Vec<usize> = task
            .files
            .borrow()
            .raw_descriptor_store
            .read()
            .iter_alive()
            .collect();
        assert_eq!(
            child_fds, parent_fds,
            "every descriptor is duplicated at the same number"
        );

        // Closing in the child's table leaves the parent's number alive...
        let parent_files = task.files.replace(alloc::sync::Arc::new(child_files));
        task.sys_close(write_fd).unwrap();
        let child_files = task.files.replace(parent_files);
        assert!(
            !child_files
                .raw_descriptor_store
                .read()
                .iter_alive()
                .any(|fd| fd == usize::try_from(write_fd).unwrap())
        );
        assert!(
            task.files
                .borrow()
                .raw_descriptor_store
                .read()
                .iter_alive()
                .any(|fd| fd == usize::try_from(write_fd).unwrap()),
            "the parent's write end must survive the child closing its own"
        );

        // ...and the shared description is still open, so the read end has not seen EOF: a write
        // through the parent's still-open write end is readable.
        assert_eq!(task.sys_write(write_fd, b"hi", None).unwrap(), 2);
        let mut buf = [0u8; 2];
        assert_eq!(task.sys_read(read_fd, &mut buf, None).unwrap(), 2);
        assert_eq!(&buf, b"hi");

        task.sys_close(read_fd).unwrap();
        task.sys_close(write_fd).unwrap();
    }

    /// The address-space token is a strict hand-off: only one member holds it at a time, a
    /// waiter takes it the moment it is released, and `hand_off_to` never lets it go free (which
    /// is what stops a third member from stealing a freshly `fork`ed child's memory before its
    /// first instruction).
    #[test]
    fn address_space_token_is_held_by_exactly_one_member() {
        use super::{ADDRESS_SPACE_FREE, Ordering, SharedAddressSpace};
        use litebox::platform::RawMutex as _;

        let shared: SharedAddressSpace<crate::syscalls::tests::TestPlatform> =
            SharedAddressSpace::new(1000);
        let word = || shared.holder.underlying_atomic().load(Ordering::Relaxed);
        assert_eq!(word(), 1000);

        // Acquiring while another member holds it must not succeed; `abandon` is the only way
        // out, and it must not have taken the token.
        assert!(!shared.acquire(1001, || true));
        assert_eq!(word(), 1000);

        // A direct hand-off never passes through the free state.
        shared.hand_off_to(1001);
        assert_eq!(word(), 1001);

        shared.release();
        assert_eq!(word(), ADDRESS_SPACE_FREE);
        assert!(shared.acquire(1002, || panic!("should not have had to block")));
        assert_eq!(word(), 1002);
    }

    /// A child becoming a zombie posts `SIGCHLD` to its parent.
    ///
    /// Without this, busybox `ash`'s blocking `wait` -- which is a `sigsuspend` loop waiting for
    /// its `SIGCHLD` handler to set a flag -- spins forever.
    #[test]
    fn child_exit_posts_sigchld_to_the_parent() {
        use litebox_common_linux::signal::{SaFlags, SigAction, SigSet, Signal};

        let task = crate::syscalls::tests::init_platform(None);
        let table = &task.global.processes;
        let child = task.pid + 1;
        table.register_process(task.pid, task.remote_signal_target());
        table.add_child(child, task.pid);

        // With the default disposition (ignore), the signal must not make blocking syscalls
        // return `EINTR`, exactly as on Linux, where an ignored signal is never queued at all.
        table.record_exit(child, super::ExitStatus::Exit(0), 0);
        assert!(
            !task.has_pending_signals(),
            "an ignored SIGCHLD must not count as deliverable"
        );

        // With a handler installed it must be deliverable.
        let act = SigAction {
            sigaction: 0x1234,
            flags: SaFlags::empty(),
            #[cfg(target_pointer_width = "64")]
            __pad: 0,
            restorer: 0,
            mask: SigSet::empty(),
        };
        task.sys_rt_sigaction(
            Signal::SIGCHLD,
            Some(UserPtr::from_ptr(&raw const act)),
            None,
            core::mem::size_of::<SigSet>(),
        )
        .expect("rt_sigaction failed");
        assert!(
            task.has_pending_signals(),
            "a handled SIGCHLD must be deliverable"
        );
        assert!(task.pending_signal_set().contains(Signal::SIGCHLD));
    }

    /// `rt_sigsuspend` always fails with `EINTR`, and leaves the caller's original mask to be put
    /// back by the return-to-guest path rather than restoring it itself -- restoring it early
    /// would re-block the signal whose handler the caller is waiting to run.
    #[test]
    fn rt_sigsuspend_defers_restoring_the_callers_mask() {
        use litebox_common_linux::{
            errno::Errno,
            signal::{SigSet, SigmaskHow, Signal},
        };

        let _guard = crate::syscalls::tests::async_signal_guard();
        let task = crate::syscalls::tests::init_platform(None);
        <crate::syscalls::tests::TestPlatform as litebox::platform::ThreadProvider>::run_test_thread(
            || {
                // Block everything, as busybox's `waitproc` does before it suspends.
                let everything = !SigSet::empty();
                task.sys_rt_sigprocmask(
                    SigmaskHow::SIG_SETMASK,
                    Some(UserPtr::from_ptr(&raw const everything)),
                    None,
                    core::mem::size_of::<SigSet>(),
                )
                .expect("block everything failed");

                // Suspend under a mask that leaves everything through, and let the alarm end it.
                let allow_everything = SigSet::empty();
                assert_eq!(task.sys_alarm(1).unwrap(), 0);
                assert_eq!(
                    task.sys_rt_sigsuspend(
                        Some(UserPtr::from_ptr(&raw const allow_everything)),
                        core::mem::size_of::<SigSet>()
                    ),
                    Err(Errno::EINTR)
                );
                task.sys_alarm(0).unwrap();

                // Still under the temporary mask, so the signal that ended the wait is still
                // deliverable and its handler would run with SIGALRM unblocked.
                assert!(
                    task.pending_signal_set().contains(Signal::SIGALRM),
                    "the suspending mask must still be in effect on return"
                );

                // The return-to-guest path puts the caller's mask back.
                task.restore_saved_signal_mask();
                let mut current = SigSet::empty();
                task.sys_rt_sigprocmask(
                    SigmaskHow::SIG_BLOCK,
                    None,
                    Some(UserPtrMut::from_ptr(&raw mut current)),
                    core::mem::size_of::<SigSet>(),
                )
                .expect("read mask failed");
                assert_eq!(
                    current.as_u64(),
                    everything.as_u64(),
                    "the mask in force before rt_sigsuspend must be restored afterwards"
                );
            },
        );
    }
}
