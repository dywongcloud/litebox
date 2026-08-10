// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use core::{convert::Infallible, sync::atomic::AtomicBool};

use alloc::{
    collections::{btree_map::BTreeMap, vec_deque::VecDeque},
    sync::{Arc, Weak},
    vec::Vec,
};
use litebox::{
    event::{
        Events, IOPollable,
        observer::Observer,
        polling::{Pollee, TryOpError},
        wait::{WaitContext, WaitError, Waker},
    },
    fd::{FdEnabledSubsystem, FdEnabledSubsystemEntry, TypedFd},
    utils::ReinterpretUnsignedExt,
};
use litebox_common_linux::{EpollEvent, EpollOp, errno::Errno};

use super::file::FilesState;
use crate::{GlobalState, ShimFS, ShimPlatform};

/// Serializes every nested-epoll `epoll_ctl(ADD)` across the whole process, mirroring real
/// Linux's `epmutex`. Cycle detection (walking the nested-epoll DAG) and the edge insertion it
/// guards have to happen as one atomic step: checking and inserting under separate locks lets two
/// concurrent adds that each individually look cycle-free still complete a cycle together (e.g.
/// thread 1 adds B into A, thread 2 concurrently adds A into B; neither sees the other's
/// not-yet-committed edge during its own check). A single global lock removes the race by only
/// ever allowing one such check-then-insert to be in flight anywhere in the process. It is not
/// taken for plain (non-nested) adds or for readiness polling, so the common case pays nothing
/// for it.
static EPOLL_NEST_LOCK: spin::Mutex<()> = spin::Mutex::new(());

pub(crate) struct EpollSubsystem<Platform: ShimPlatform, FS: ShimFS>(
    core::marker::PhantomData<(Platform, FS)>,
);
impl<Platform: ShimPlatform, FS: ShimFS> FdEnabledSubsystem for EpollSubsystem<Platform, FS> {
    type Entry = EpollFile<Platform, FS>;
}
impl<Platform: ShimPlatform, FS: ShimFS> FdEnabledSubsystemEntry for EpollFile<Platform, FS> {}

bitflags::bitflags! {
    /// Linux's epoll flags.
    #[derive(Debug)]
    struct EpollFlags: u32 {
        const EXCLUSIVE      = (1 << 28);
        const WAKE_UP        = (1 << 29);
        const ONE_SHOT       = (1 << 30);
        const EDGE_TRIGGER   = (1 << 31);
    }
}

pub(crate) enum EpollDescriptor<Platform: ShimPlatform, FS: ShimFS> {
    Eventfd(Arc<TypedFd<super::eventfd::EventfdSubsystem<Platform>>>),
    Epoll(Arc<TypedFd<super::epoll::EpollSubsystem<Platform, FS>>>),
    File(Arc<crate::FileFd<FS>>),
    Socket(Arc<super::net::SocketFd<Platform>>),
    Pipe(Arc<litebox::pipes::PipeFd<Platform>>),
    Unix(Arc<TypedFd<crate::syscalls::unix::UnixSocketSubsystem<Platform, FS>>>),
}

impl<Platform: ShimPlatform, FS: ShimFS> EpollDescriptor<Platform, FS> {
    pub fn try_from(files: &FilesState<Platform, FS>, raw_fd: usize) -> Result<Self, Errno> {
        let rds = files.raw_descriptor_store.read();
        if let Ok(fd) = rds.fd_from_raw_integer::<FS>(raw_fd) {
            return Ok(EpollDescriptor::File(fd));
        }
        if let Ok(fd) = rds.fd_from_raw_integer::<crate::Network<Platform>>(raw_fd) {
            return Ok(EpollDescriptor::Socket(fd));
        }
        if let Ok(fd) = rds.fd_from_raw_integer::<litebox::pipes::Pipes<Platform>>(raw_fd) {
            return Ok(EpollDescriptor::Pipe(fd));
        }
        if let Ok(fd) =
            rds.fd_from_raw_integer::<super::eventfd::EventfdSubsystem<Platform>>(raw_fd)
        {
            return Ok(EpollDescriptor::Eventfd(fd));
        }
        if let Ok(fd) = rds.fd_from_raw_integer::<EpollSubsystem<Platform, FS>>(raw_fd) {
            return Ok(EpollDescriptor::Epoll(fd));
        }
        if let Ok(fd) =
            rds.fd_from_raw_integer::<super::unix::UnixSocketSubsystem<Platform, FS>>(raw_fd)
        {
            return Ok(EpollDescriptor::Unix(fd));
        }
        Err(Errno::EBADF)
    }
}

enum DescriptorRef<Platform: ShimPlatform, FS: ShimFS> {
    Eventfd(Weak<TypedFd<super::eventfd::EventfdSubsystem<Platform>>>),
    Epoll(Weak<TypedFd<super::epoll::EpollSubsystem<Platform, FS>>>),
    File(Weak<crate::FileFd<FS>>),
    Socket(Weak<super::net::SocketFd<Platform>>),
    Pipe(Weak<litebox::pipes::PipeFd<Platform>>),
    Unix(Weak<TypedFd<crate::syscalls::unix::UnixSocketSubsystem<Platform, FS>>>),
}

impl<Platform: ShimPlatform, FS: ShimFS> DescriptorRef<Platform, FS> {
    fn from(value: &EpollDescriptor<Platform, FS>) -> Self {
        match value {
            EpollDescriptor::Eventfd(file) => Self::Eventfd(Arc::downgrade(file)),
            EpollDescriptor::Epoll(file) => Self::Epoll(Arc::downgrade(file)),
            EpollDescriptor::File(file) => Self::File(Arc::downgrade(file)),
            EpollDescriptor::Socket(socket) => Self::Socket(Arc::downgrade(socket)),
            EpollDescriptor::Pipe(pipe) => Self::Pipe(Arc::downgrade(pipe)),
            EpollDescriptor::Unix(unix) => Self::Unix(Arc::downgrade(unix)),
        }
    }

    fn upgrade(&self) -> Option<EpollDescriptor<Platform, FS>> {
        match self {
            DescriptorRef::Eventfd(eventfd) => eventfd.upgrade().map(EpollDescriptor::Eventfd),
            DescriptorRef::Epoll(epoll) => epoll.upgrade().map(EpollDescriptor::Epoll),
            DescriptorRef::File(file) => file.upgrade().map(EpollDescriptor::File),
            DescriptorRef::Socket(socket) => socket.upgrade().map(EpollDescriptor::Socket),
            DescriptorRef::Pipe(pipe) => pipe.upgrade().map(EpollDescriptor::Pipe),
            DescriptorRef::Unix(unix) => unix.upgrade().map(EpollDescriptor::Unix),
        }
    }
}

impl<Platform: ShimPlatform, FS: ShimFS> EpollDescriptor<Platform, FS> {
    /// Returns the interesting events now and monitors their occurrence in the future if the
    /// observer is provided.
    fn poll(
        &self,
        global: &GlobalState<Platform, FS>,
        mask: Events,
        observer: Option<Weak<dyn Observer<Events>>>,
    ) -> Option<Events> {
        let poll = |iop: &dyn IOPollable| {
            if let Some(observer) = observer {
                iop.register_observer(observer, mask);
            }
            iop.check_io_events() & (mask | Events::ALWAYS_POLLED)
        };
        match self {
            EpollDescriptor::Eventfd(fd) => {
                let handle = global.litebox.descriptor_table().entry_handle(fd)?;
                Some(handle.with_entry(|entry| poll(entry)))
            }
            EpollDescriptor::Epoll(fd) => {
                let handle = global.litebox.descriptor_table().entry_handle(fd)?;
                Some(handle.with_entry(|entry| poll(entry)))
            }
            EpollDescriptor::File(file) => {
                // TODO: File polling returns dummy events for now, but distinguish stdio enough for REPLs.
                let events = match global
                    .litebox
                    .descriptor_table()
                    .with_metadata(file, |stream: &litebox::platform::StdioStream| *stream)
                {
                    Ok(litebox::platform::StdioStream::Stdin) => Events::IN,
                    Ok(
                        litebox::platform::StdioStream::Stdout
                        | litebox::platform::StdioStream::Stderr,
                    )
                    | Err(_) => Events::OUT,
                };
                Some(events & mask)
            }
            EpollDescriptor::Socket(fd) => {
                let proxy = match global.get_proxy(fd) {
                    Ok(p) => p,
                    Err(e) => {
                        log_unsupported!("epoll poll with socket fd: {:?}", e);
                        return None;
                    }
                };
                Some(poll(&proxy))
            }
            EpollDescriptor::Pipe(fd) => global.with_linux_pipe_iopollable(fd, poll).ok(),
            EpollDescriptor::Unix(fd) => {
                let handle = global.litebox.descriptor_table().entry_handle(fd)?;
                Some(handle.with_entry(|entry| poll(entry)))
            }
        }
    }
}

pub(crate) struct EpollFile<Platform: ShimPlatform, FS: ShimFS> {
    interests: litebox::sync::Mutex<
        Platform,
        BTreeMap<EpollEntryKey, alloc::sync::Arc<EpollEntry<Platform, FS>>>,
    >,
    ready: Arc<ReadySet<Platform, FS>>,
    status: core::sync::atomic::AtomicU32,
}

impl<Platform: ShimPlatform, FS: ShimFS> EpollFile<Platform, FS> {
    pub(crate) fn new() -> Self {
        EpollFile {
            interests: litebox::sync::Mutex::new(BTreeMap::new()),
            ready: Arc::new(ReadySet::new()),
            status: core::sync::atomic::AtomicU32::new(0),
        }
    }

    pub(crate) fn wait(
        &self,
        global: &GlobalState<Platform, FS>,
        cx: &WaitContext<'_, Platform>,
        maxevents: usize,
    ) -> Result<Vec<EpollEvent>, WaitError> {
        let mut events = Vec::new();
        match self.ready.pollee.wait(cx, false, Events::IN, || {
            self.ready.pop_multiple(global, maxevents, &mut events);
            if events.is_empty() {
                return Err(TryOpError::<Infallible>::TryAgain);
            }
            Ok(())
        }) {
            Ok(()) => Ok(events),
            Err(TryOpError::TryAgain) => unreachable!(),
            Err(TryOpError::WaitError(e)) => Err(e),
        }
    }

    pub(crate) fn epoll_ctl(
        &self,
        global: &GlobalState<Platform, FS>,
        self_fd: &Arc<TypedFd<EpollSubsystem<Platform, FS>>>,
        op: EpollOp,
        fd: u32,
        file: &EpollDescriptor<Platform, FS>,
        event: Option<EpollEvent>,
    ) -> Result<(), Errno> {
        match op {
            EpollOp::EpollCtlAdd => self.add_interest(global, self_fd, fd, file, event.unwrap()),
            EpollOp::EpollCtlMod => {
                log_unsupported!("epoll_ctl mod");
                Err(Errno::EINVAL)
            }
            EpollOp::EpollCtlDel => {
                let mut interests = self.interests.lock();
                let _ = interests
                    .remove(&EpollEntryKey::new(fd, file))
                    .ok_or(Errno::ENOENT)?;
                Ok(())
            }
        }
    }

    fn add_interest(
        &self,
        global: &GlobalState<Platform, FS>,
        self_fd: &Arc<TypedFd<EpollSubsystem<Platform, FS>>>,
        fd: u32,
        file: &EpollDescriptor<Platform, FS>,
        event: EpollEvent,
    ) -> Result<(), Errno> {
        // A cycle can only be formed by nesting one epoll inside another, so only that case needs
        // the global lock; a plain fd add can't create one and stays as cheap as before. The guard
        // is held across both the cycle check and the insert below -- see `EPOLL_NEST_LOCK` for why
        // splitting those into separate critical sections would reopen the race this closes.
        let _nest_guard = matches!(file, EpollDescriptor::Epoll(_)).then(|| EPOLL_NEST_LOCK.lock());
        if let EpollDescriptor::Epoll(inner_fd) = file
            && Self::nested_epoll_reaches(global, self_fd, inner_fd, 1)?
        {
            return Err(Errno::ELOOP);
        }

        let mut interests = self.interests.lock();
        let key = EpollEntryKey::new(fd, file);
        if let Some(entry) = interests.get(&key)
            && entry.desc.upgrade().is_some()
        {
            return Err(Errno::EEXIST);
        }
        // we may have stale entry because we don't remove it immediately after the file is closed;
        // `insert` below will replace it with a new entry.

        let mask = Events::from_bits_truncate(event.events);
        let entry = EpollEntry::new(
            DescriptorRef::from(file),
            mask,
            EpollFlags::from_bits_truncate(event.events),
            event.data,
            self.ready.clone(),
        );
        let events = file
            .poll(global, mask, Some(entry.weak_self.clone() as _))
            .ok_or(Errno::EBADF)?;
        // Add the new entry to the ready list if the file is ready
        if !events.is_empty() {
            self.ready.push(&entry);
        }
        interests.insert(key, entry);
        Ok(())
    }

    /// Returns whether `self_fd` is reachable by following already-registered nested-epoll
    /// interests starting at `fd`, i.e. whether accepting `fd` as a new interest of `self_fd`
    /// would close a cycle.
    ///
    /// Must be called with `EPOLL_NEST_LOCK` held. Under that lock, every edge in the existing
    /// nested-epoll graph got there by passing this same check, so the graph is acyclic by
    /// induction going in -- the walk below can therefore only ever revisit `self_fd` itself
    /// (caught up front via `Arc::ptr_eq`, before `self_fd`'s own entry is ever locked), never an
    /// intermediate node, so it can't re-lock an entry it is already holding on this call stack.
    /// Depth is also capped, mirroring real Linux's nesting limit, so a long acyclic chain can't
    /// blow the stack either.
    fn nested_epoll_reaches(
        global: &GlobalState<Platform, FS>,
        self_fd: &Arc<TypedFd<EpollSubsystem<Platform, FS>>>,
        fd: &Arc<TypedFd<EpollSubsystem<Platform, FS>>>,
        depth: u32,
    ) -> Result<bool, Errno> {
        const MAX_NESTED_EPOLL_DEPTH: u32 = 5;
        if Arc::ptr_eq(self_fd, fd) {
            return Ok(true);
        }
        if depth > MAX_NESTED_EPOLL_DEPTH {
            return Err(Errno::ELOOP);
        }
        let Some(handle) = global.litebox.descriptor_table().entry_handle(fd) else {
            return Ok(false);
        };
        handle.with_entry(|entry: &Self| {
            for nested in entry.interests.lock().values() {
                if let Some(EpollDescriptor::Epoll(inner_fd)) = nested.desc.upgrade()
                    && Self::nested_epoll_reaches(global, self_fd, &inner_fd, depth + 1)?
                {
                    return Ok(true);
                }
            }
            Ok(false)
        })
    }

    #[expect(dead_code, reason = "currently unused, but might want to use soon")]
    fn mod_interest(
        &self,
        global: &GlobalState<Platform, FS>,
        fd: u32,
        file: &EpollDescriptor<Platform, FS>,
        event: EpollEvent,
    ) -> Result<(), Errno> {
        // EPOLLEXCLUSIVE is not allowed for a EPOLL_CTL_MOD operation
        let flags = EpollFlags::from_bits_truncate(event.events);
        if flags.contains(EpollFlags::EXCLUSIVE) {
            return Err(Errno::EINVAL);
        }

        let mut interests = self.interests.lock();
        let key = EpollEntryKey::new(fd, file);
        let entry = interests.get(&key).ok_or(Errno::ENOENT)?;
        if entry.desc.upgrade().is_none() {
            // The file descriptor is closed, remove the entry
            interests.remove(&key);
            return Err(Errno::ENOENT);
        }

        let mut inner = entry.inner.lock();
        if inner.flags.contains(EpollFlags::EXCLUSIVE) {
            // If EPOLLEXCLUSIVE has been set using epoll_ctl(), then a
            // subsequent EPOLL_CTL_MOD on the same epfd, fd pair yields an error.
            return Err(Errno::EINVAL);
        }

        let mask = Events::from_bits_truncate(event.events);
        inner.mask = mask;
        inner.flags = flags;
        inner.data = event.data;

        entry
            .is_enabled
            .store(true, core::sync::atomic::Ordering::Relaxed);
        let observer = entry.weak_self.clone();
        drop(inner);

        // re-register the observer with the new mask
        if let Some(events) = file.poll(global, mask, Some(observer as _)) {
            if !events.is_empty() {
                // Add the updated entry to the ready list if the file is ready
                self.ready.push(entry);
            }

            Ok(())
        } else {
            // The file descriptor is closed, remove the entry
            interests.remove(&key);
            Err(Errno::ENOENT)
        }
    }

    super::common_functions_for_file_status!();
}

impl<Platform: ShimPlatform, FS: ShimFS> IOPollable for EpollFile<Platform, FS> {
    fn check_io_events(&self) -> Events {
        if self.ready.entries.lock().is_empty() {
            Events::empty()
        } else {
            Events::IN
        }
    }

    fn register_observer(&self, observer: Weak<dyn Observer<Events>>, mask: Events) {
        self.ready.pollee.register_observer(observer, mask);
    }
}

#[derive(PartialEq, Eq, PartialOrd, Ord)]
struct EpollEntryKey(u32, usize);
impl EpollEntryKey {
    fn new<Platform: ShimPlatform, FS: ShimFS>(
        fd: u32,
        desc: &EpollDescriptor<Platform, FS>,
    ) -> Self {
        let ptr = match desc {
            EpollDescriptor::Eventfd(file) => Arc::as_ptr(file).addr(),
            EpollDescriptor::Epoll(file) => Arc::as_ptr(file).addr(),
            EpollDescriptor::File(file) => Arc::as_ptr(file).addr(),
            EpollDescriptor::Socket(socket_fd) => Arc::as_ptr(socket_fd).addr(),
            EpollDescriptor::Pipe(pipe_fd) => Arc::as_ptr(pipe_fd).addr(),
            EpollDescriptor::Unix(unix) => Arc::as_ptr(unix).addr(),
        };
        Self(fd, ptr)
    }
}

struct EpollEntry<Platform: ShimPlatform, FS: ShimFS> {
    desc: DescriptorRef<Platform, FS>,
    inner: litebox::sync::Mutex<Platform, EpollEntryInner>,
    ready: Arc<ReadySet<Platform, FS>>,
    is_ready: AtomicBool,
    is_enabled: AtomicBool,
    weak_self: Weak<Self>,
}

struct EpollEntryInner {
    mask: Events,
    flags: EpollFlags,
    data: u64,
}

impl<Platform: ShimPlatform, FS: ShimFS> EpollEntry<Platform, FS> {
    fn new(
        desc: DescriptorRef<Platform, FS>,
        mask: Events,
        flags: EpollFlags,
        data: u64,
        ready: Arc<ReadySet<Platform, FS>>,
    ) -> Arc<Self> {
        Arc::new_cyclic(|weak_self| EpollEntry {
            desc,
            inner: litebox::sync::Mutex::new(EpollEntryInner { mask, flags, data }),
            ready,
            is_ready: AtomicBool::new(false),
            is_enabled: AtomicBool::new(true),
            weak_self: weak_self.clone(),
        })
    }

    fn poll(&self, global: &GlobalState<Platform, FS>) -> Option<(Option<EpollEvent>, bool)> {
        let file = self.desc.upgrade()?;
        let inner = self.inner.lock();

        if !self.is_enabled.load(core::sync::atomic::Ordering::Relaxed) {
            // the entry is disabled
            return None;
        }

        let events = file.poll(global, inner.mask, None)?;
        if events.is_empty() {
            Some((None, false))
        } else {
            let event = Some(EpollEvent {
                events: events.bits(),
                data: inner.data,
            });

            // keep the entry in the ready list if it is not edge-triggered or one-shot
            let is_still_ready = event.is_some()
                && !inner
                    .flags
                    .intersects(EpollFlags::EDGE_TRIGGER | EpollFlags::ONE_SHOT);

            // disable the entry if it is one-shot
            if inner.flags.contains(EpollFlags::ONE_SHOT) {
                self.is_enabled
                    .store(false, core::sync::atomic::Ordering::Relaxed);
            }

            Some((event, is_still_ready))
        }
    }
}

impl<Platform: ShimPlatform, FS: ShimFS> Observer<Events> for EpollEntry<Platform, FS> {
    fn on_events(&self, _events: &Events) {
        self.ready.push(self);
    }
}

struct ReadySet<Platform: ShimPlatform, FS: ShimFS> {
    entries: litebox::sync::Mutex<Platform, VecDeque<alloc::sync::Weak<EpollEntry<Platform, FS>>>>,
    pollee: Pollee<Platform>,
}

impl<Platform: ShimPlatform, FS: ShimFS> ReadySet<Platform, FS> {
    fn new() -> Self {
        Self {
            entries: litebox::sync::Mutex::new(VecDeque::new()),
            pollee: Pollee::new(),
        }
    }

    fn push(&self, entry: &EpollEntry<Platform, FS>) {
        if !entry.is_enabled.load(core::sync::atomic::Ordering::Relaxed) {
            // the entry is disabled
            return;
        }

        if !entry
            .is_ready
            .swap(true, core::sync::atomic::Ordering::Relaxed)
        {
            let mut entries = self.entries.lock();
            entries.push_back(entry.weak_self.clone());
        }

        self.pollee.notify_observers(Events::IN);
    }

    fn pop_multiple(
        &self,
        global: &GlobalState<Platform, FS>,
        maxevents: usize,
        events: &mut Vec<EpollEvent>,
    ) {
        let mut nums = self.entries.lock().len();
        while nums > 0 {
            nums -= 1;
            if events.len() >= maxevents {
                break;
            }

            // Note the lock operation is performed inside the loop to avoid holding the lock while calling `poll()`.
            // e.g., `poll` on a socket requires lock on network, and a deadlock may happen if another thread
            // holds the network lock and tries to add an entry to the same epoll instance upon new events.
            let Some(weak_entry) = self.entries.lock().pop_front() else {
                // no more entries
                break;
            };

            let Some(entry) = weak_entry.upgrade() else {
                // the entry has been deleted
                continue;
            };
            entry
                .is_ready
                .store(false, core::sync::atomic::Ordering::Relaxed);

            let Some((event, is_still_ready)) = entry.poll(global) else {
                // the entry is disabled or the associated file is closed
                continue;
            };

            if let Some(event) = event {
                events.push(event);
            }

            if is_still_ready {
                // if another event happened and already pushed the entry (i.e., marked it as ready)
                // while we were processing, we don't need to push it again.
                if !entry
                    .is_ready
                    .swap(true, core::sync::atomic::Ordering::Relaxed)
                {
                    self.entries.lock().push_back(weak_entry);
                }
            }
        }
    }
}

/// A poll set used for transient polling of a set of files. Designed for use
/// with the `poll` and `ppoll` syscalls.
pub(crate) struct PollSet<Platform: ShimPlatform> {
    entries: Vec<PollEntry<Platform>>,
}

struct PollEntry<Platform: ShimPlatform> {
    fd: i32,
    mask: Events,
    revents: Events,
    observer: Option<Arc<PollEntryObserver<Platform>>>,
}

struct PollEntryObserver<Platform: ShimPlatform>(Waker<Platform>);

impl<Platform: ShimPlatform> Clone for PollEntryObserver<Platform> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<Platform: ShimPlatform> PollSet<Platform> {
    /// Returns a new empty `PollSet` with the given interest capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            entries: Vec::with_capacity(capacity),
        }
    }

    /// Adds an fd to the poll set with the given event mask.
    ///
    /// If fd is negative, it is ignored during polling.
    pub fn add_fd(&mut self, fd: i32, mask: Events) {
        self.entries.push(PollEntry {
            fd,
            mask: mask | Events::ALWAYS_POLLED,
            revents: Events::empty(),
            observer: None,
        });
    }

    fn scan_once<FS: ShimFS>(
        &mut self,
        global: &GlobalState<Platform, FS>,
        files: &FilesState<Platform, FS>,
        waker: Option<&Waker<Platform>>,
    ) -> bool {
        let mut is_ready = false;
        for entry in &mut self.entries {
            entry.revents = if entry.fd < 0 {
                continue;
            } else if let Ok(poll_descriptor) =
                EpollDescriptor::try_from(files, entry.fd.reinterpret_as_unsigned() as usize)
            {
                let observer = if !is_ready && let Some(waker) = waker {
                    // TODO: a separate allocation is necessary here
                    // because registering an observer twice with two
                    // different event masks results in the last one
                    // replacing the first. If this is changed to
                    // instead combine the new event mask into the existing
                    // registration's mask, then we can use a single observer
                    // for all entries.
                    let observer = Arc::new(PollEntryObserver(waker.clone()));
                    let weak = Arc::downgrade(&observer);
                    entry.observer = Some(observer);
                    Some(weak as _)
                } else {
                    // The poll set is already ready, or we have already
                    // registered the observer for this entry.
                    None
                };
                // TODO: add machinery to unregister the observer to avoid leaks.
                poll_descriptor
                    .poll(global, entry.mask, observer)
                    .unwrap_or(Events::NVAL)
            } else {
                Events::NVAL
            };
            if !entry.revents.is_empty() {
                is_ready = true;
            }
        }
        is_ready
    }

    /// Scans the poll set for ready fds once.
    pub fn scan<FS: ShimFS>(
        &mut self,
        global: &GlobalState<Platform, FS>,
        files: &FilesState<Platform, FS>,
    ) {
        self.scan_once(global, files, None);
    }

    /// Waits for any of the fds in the poll set to become ready.
    pub fn wait<FS: ShimFS>(
        &mut self,
        global: &GlobalState<Platform, FS>,
        cx: &WaitContext<'_, Platform>,
        files: &FilesState<Platform, FS>,
    ) -> Result<(), WaitError> {
        if self.scan_once(global, files, None) {
            return Ok(());
        }

        let mut register = true;
        cx.wait_until(|| {
            if self.scan_once(global, files, register.then_some(cx.waker())) {
                return true;
            }
            // Don't register observers again in the next iteration.
            register = false;
            false
        })
    }

    /// Returns the accumulated `revents` for each entry in the poll set.
    ///
    /// These are only valid after a call to `wait_or_timeout`.
    pub fn revents(&self) -> impl Iterator<Item = Events> + '_ {
        self.entries.iter().map(|entry| entry.revents)
    }

    /// Returns the accumulated `revents` and corresponding fds for each entry in the poll set.
    ///
    /// These are only valid after a call to `wait_or_timeout`.
    pub fn revents_with_fds(&self) -> impl Iterator<Item = (i32, Events)> + '_ {
        self.entries.iter().map(|entry| (entry.fd, entry.revents))
    }
}

impl<Platform: ShimPlatform> Observer<Events> for PollEntryObserver<Platform> {
    fn on_events(&self, _events: &Events) {
        self.0.wake();
    }
}

#[cfg(test)]
mod test {
    use crate::syscalls::tests::TestPlatform;
    use alloc::sync::Arc;
    use litebox::event::Events;
    use litebox::event::wait::WaitState;
    use litebox::fd::TypedFd;
    use litebox_common_linux::EpollEvent;
    use litebox_common_linux::errno::Errno;

    use super::{EpollFile, EpollSubsystem};
    use crate::syscalls::file::FilesState;

    extern crate std;

    fn platform() -> &'static TestPlatform {
        crate::syscalls::tests::test_platform(None)
    }

    type TestEpollFd = Arc<TypedFd<EpollSubsystem<TestPlatform, crate::DefaultFS<TestPlatform>>>>;

    fn new_epoll_fd(
        task: &crate::Task<TestPlatform, crate::DefaultFS<TestPlatform>>,
    ) -> TestEpollFd {
        Arc::new(
            task.global
                .litebox
                .descriptor_table_mut()
                .insert::<EpollSubsystem<TestPlatform, crate::DefaultFS<TestPlatform>>>(
                    EpollFile::new(),
                ),
        )
    }

    fn setup_epoll() -> (
        crate::Task<TestPlatform, crate::DefaultFS<TestPlatform>>,
        TestEpollFd,
    ) {
        let task = crate::syscalls::tests::init_platform(None);
        let epoll_fd = new_epoll_fd(&task);
        (task, epoll_fd)
    }

    #[test]
    fn test_epoll_with_pipe() {
        let (task, epoll_fd) = setup_epoll();
        let (producer, consumer) = task
            .global
            .pipes
            .create_pipe(2, litebox::pipes::Flags::empty(), None)
            .unwrap();
        let consumer = Arc::new(consumer);
        let reader = super::EpollDescriptor::Pipe(Arc::clone(&consumer));
        let handle = task
            .global
            .litebox
            .descriptor_table()
            .entry_handle(&epoll_fd)
            .unwrap();
        handle
            .with_entry(|epoll| {
                epoll.add_interest(
                    &task.global,
                    &epoll_fd,
                    10,
                    &reader,
                    EpollEvent {
                        events: Events::IN.bits(),
                        data: 0,
                    },
                )
            })
            .unwrap();

        // spawn a thread to write to the pipe
        let global = task.global.clone();
        std::thread::spawn(move || {
            std::thread::sleep(core::time::Duration::from_millis(100));
            assert_eq!(
                global
                    .pipes
                    .write(&WaitState::new(platform()).context(), &producer, &[1, 2])
                    .unwrap(),
                2
            );
        });
        handle
            .with_entry(|epoll| {
                epoll.wait(&task.global, &WaitState::new(platform()).context(), 1024)
            })
            .unwrap();
        let mut buf = [0; 2];
        task.global
            .pipes
            .read(&WaitState::new(platform()).context(), &consumer, &mut buf)
            .unwrap();
        assert_eq!(buf, [1, 2]);
    }

    #[test]
    fn test_epoll_nested() {
        let task = crate::syscalls::tests::init_platform(None);

        let inner_fd = new_epoll_fd(&task);
        let (producer, consumer) = task
            .global
            .pipes
            .create_pipe(2, litebox::pipes::Flags::empty(), None)
            .unwrap();
        let consumer = Arc::new(consumer);
        let reader = super::EpollDescriptor::Pipe(Arc::clone(&consumer));
        let inner_handle = task
            .global
            .litebox
            .descriptor_table()
            .entry_handle(&inner_fd)
            .unwrap();
        inner_handle
            .with_entry(|inner| {
                inner.add_interest(
                    &task.global,
                    &inner_fd,
                    20,
                    &reader,
                    EpollEvent {
                        events: Events::IN.bits(),
                        data: 0,
                    },
                )
            })
            .unwrap();

        let outer_fd = new_epoll_fd(&task);
        let nested = super::EpollDescriptor::Epoll(Arc::clone(&inner_fd));
        let outer_handle = task
            .global
            .litebox
            .descriptor_table()
            .entry_handle(&outer_fd)
            .unwrap();
        outer_handle
            .with_entry(|outer| {
                outer.add_interest(
                    &task.global,
                    &outer_fd,
                    10,
                    &nested,
                    EpollEvent {
                        events: Events::IN.bits(),
                        data: 42,
                    },
                )
            })
            .unwrap();

        // Writing to the pipe should make the inner epoll ready, which in turn should make the
        // outer epoll (which has the inner epoll nested inside it) ready.
        task.global
            .pipes
            .write(&WaitState::new(platform()).context(), &producer, &[1, 2])
            .unwrap();

        let events = outer_handle
            .with_entry(|outer| {
                outer.wait(&task.global, &WaitState::new(platform()).context(), 1024)
            })
            .unwrap();
        assert_eq!(events.len(), 1);
        let data = events[0].data;
        assert_eq!(data, 42);
    }

    #[test]
    fn test_epoll_nested_cycle_rejected() {
        let task = crate::syscalls::tests::init_platform(None);

        let a_fd = new_epoll_fd(&task);
        let b_fd = new_epoll_fd(&task);

        let a_handle = task
            .global
            .litebox
            .descriptor_table()
            .entry_handle(&a_fd)
            .unwrap();
        a_handle
            .with_entry(|a| {
                a.add_interest(
                    &task.global,
                    &a_fd,
                    20,
                    &super::EpollDescriptor::Epoll(Arc::clone(&b_fd)),
                    EpollEvent {
                        events: Events::IN.bits(),
                        data: 0,
                    },
                )
            })
            .unwrap();

        // B adding A back would close a 2-fd cycle; this must be rejected synchronously with
        // ELOOP rather than being allowed to form (which would only surface as a hang later,
        // on the first event delivered into the cycle).
        let b_handle = task
            .global
            .litebox
            .descriptor_table()
            .entry_handle(&b_fd)
            .unwrap();
        let result = b_handle.with_entry(|b| {
            b.add_interest(
                &task.global,
                &b_fd,
                10,
                &super::EpollDescriptor::Epoll(Arc::clone(&a_fd)),
                EpollEvent {
                    events: Events::IN.bits(),
                    data: 0,
                },
            )
        });
        assert_eq!(result, Err(Errno::ELOOP));
    }

    /// Reproduces, under real concurrency, the exact race a prior cycle-detection attempt
    /// missed: thread 1 adds B into A while thread 2 concurrently adds A into B. Checking for a
    /// cycle and committing the new edge are two different critical sections unless a single
    /// process-wide lock spans both, so each thread's check can run before the other's insert is
    /// visible -- both threads see an acyclic graph, both commit, and together they still close
    /// the cycle. Since A adding B and B adding A are reciprocal, the only two correct outcomes
    /// per iteration are "exactly one add wins, the other gets ELOOP" -- never both winning
    /// (that would be the cycle itself), never both losing, and never neither thread returning at
    /// all. A `Barrier` lines both threads up right before their `add_interest` call to maximize
    /// the chance of hitting the race, and `recv_timeout` bounds each attempt so a regression
    /// that reintroduces the deadlock fails this test quickly instead of hanging the run.
    #[test]
    fn test_epoll_nested_concurrent_add_never_forms_cycle() {
        let task = crate::syscalls::tests::init_platform(None);
        let global = task.global.clone();

        for iteration in 0..30u32 {
            let a_fd = new_epoll_fd(&task);
            let b_fd = new_epoll_fd(&task);
            let barrier = Arc::new(std::sync::Barrier::new(2));

            let (tx_a, rx_a) = std::sync::mpsc::channel();
            let g = global.clone();
            let (a, b) = (Arc::clone(&a_fd), Arc::clone(&b_fd));
            let bar = Arc::clone(&barrier);
            std::thread::spawn(move || {
                let handle = g.litebox.descriptor_table().entry_handle(&a).unwrap();
                bar.wait();
                let result = handle.with_entry(|entry| {
                    entry.add_interest(
                        &g,
                        &a,
                        1000 + iteration,
                        &super::EpollDescriptor::Epoll(Arc::clone(&b)),
                        EpollEvent {
                            events: Events::IN.bits(),
                            data: 0,
                        },
                    )
                });
                let _ = tx_a.send(result);
            });

            let (tx_b, rx_b) = std::sync::mpsc::channel();
            let g = global.clone();
            let (a, b) = (Arc::clone(&a_fd), Arc::clone(&b_fd));
            let bar = Arc::clone(&barrier);
            std::thread::spawn(move || {
                let handle = g.litebox.descriptor_table().entry_handle(&b).unwrap();
                bar.wait();
                let result = handle.with_entry(|entry| {
                    entry.add_interest(
                        &g,
                        &b,
                        2000 + iteration,
                        &super::EpollDescriptor::Epoll(Arc::clone(&a)),
                        EpollEvent {
                            events: Events::IN.bits(),
                            data: 0,
                        },
                    )
                });
                let _ = tx_b.send(result);
            });

            let timeout = core::time::Duration::from_secs(5);
            let Ok(result_a) = rx_a.recv_timeout(timeout) else {
                panic!(
                    "iteration {iteration}: thread adding B into A never returned -- \
                     a cycle likely formed and something is stuck on it"
                );
            };
            let Ok(result_b) = rx_b.recv_timeout(timeout) else {
                panic!(
                    "iteration {iteration}: thread adding A into B never returned -- \
                     a cycle likely formed and something is stuck on it"
                );
            };

            match (result_a, result_b) {
                (Ok(()), Err(Errno::ELOOP)) | (Err(Errno::ELOOP), Ok(())) => {}
                other => panic!(
                    "iteration {iteration}: expected exactly one add to win and the other to be \
                     rejected with ELOOP, got {other:?} instead"
                ),
            }
        }
    }

    #[test]
    fn test_poll() {
        let task = crate::syscalls::tests::init_platform(None);

        let mut set = super::PollSet::with_capacity(0);
        let (rfd_u, wfd_u) = task
            .sys_pipe2(litebox::fs::OFlags::empty())
            .expect("pipe2 failed");
        let rfd = i32::try_from(rfd_u).unwrap();
        let wfd = i32::try_from(wfd_u).unwrap();
        let no_fds = FilesState::new(task.files.borrow().fs.clone());
        let fds = task.files.borrow().clone();
        set.add_fd(rfd, Events::IN);

        let revents = |set: &super::PollSet<TestPlatform>| {
            let revents: std::vec::Vec<_> = set.revents().collect();
            assert_eq!(revents.len(), 1);
            revents[0]
        };

        set.wait(&task.global, &WaitState::new(platform()).context(), &no_fds)
            .unwrap();
        assert_eq!(revents(&set), Events::NVAL);

        task.sys_write(wfd, &[1], None).unwrap();
        set.wait(&task.global, &WaitState::new(platform()).context(), &fds)
            .unwrap();
        assert_eq!(revents(&set), Events::IN);

        let mut buf = [0; 1];
        assert_eq!(task.sys_read(rfd, &mut buf, None).unwrap(), 1);
        assert_eq!(buf, [1]);
        set.wait(
            &task.global,
            &WaitState::new(platform())
                .context()
                .with_timeout(core::time::Duration::from_millis(100)),
            &fds,
        )
        .unwrap_err();
        assert!(revents(&set).is_empty());

        task.spawn_clone_for_test(move |task| {
            std::thread::sleep(core::time::Duration::from_millis(100));
            assert_eq!(task.sys_write(wfd, &[1], None).unwrap(), 1);
        });

        set.wait(&task.global, &WaitState::new(platform()).context(), &fds)
            .unwrap();
        assert_eq!(revents(&set), Events::IN);

        let _ = task.sys_close(rfd);
        let _ = task.sys_close(wfd);
    }

    #[test]
    fn test_pselect() {
        let task = crate::syscalls::tests::init_platform(None);

        let (rfd_u, wfd_u) = task
            .sys_pipe2(litebox::fs::OFlags::empty())
            .expect("pipe2 failed");
        let rfd = i32::try_from(rfd_u).unwrap();
        let wfd = i32::try_from(wfd_u).unwrap();

        task.spawn_clone_for_test(move |task| {
            std::thread::sleep(core::time::Duration::from_millis(100));
            // write a byte
            let buf = [0x41u8];
            let written = task.sys_write(wfd, &buf, None).expect("write failed");
            assert_eq!(written, 1);
        });

        // prepare fd_set for read
        let mut rfds = bitvec::bitvec![0; rfd_u.next_multiple_of(64) as usize];
        rfds.set(rfd_u as usize, true);

        // Call pselect
        let ret = task
            .do_pselect(rfd_u + 1, Some(&mut rfds), None, None, None)
            .expect("pselect failed");
        assert!(ret > 0, "pselect should report ready");
        assert!(rfds.iter_ones().all(|fd| fd == rfd_u as usize));

        // read
        let mut out = [0u8; 8];
        let n = task.sys_read(rfd, &mut out, None).expect("read failed");
        assert_eq!(n, 1);
        assert_eq!(out[0], 0x41);

        let _ = task.sys_close(rfd);
        let _ = task.sys_close(wfd);
    }

    #[test]
    fn test_pselect_read_hup() {
        let task = crate::syscalls::tests::init_platform(None);

        let (rfd_u, wfd_u) = task
            .sys_pipe2(litebox::fs::OFlags::empty())
            .expect("pipe2 failed");
        let rfd = i32::try_from(rfd_u).unwrap();
        let wfd = i32::try_from(wfd_u).unwrap();

        task.spawn_clone_for_test(move |task| {
            std::thread::sleep(core::time::Duration::from_millis(100));
            task.sys_close(wfd).expect("close writer failed");
        });

        // prepare fd_set for read
        let mut rfds = bitvec::bitvec![0; rfd_u.next_multiple_of(64) as usize];
        rfds.set(rfd_u as usize, true);

        let ret = task
            .do_pselect(
                rfd_u + 1,
                Some(&mut rfds),
                None,
                None,
                Some(core::time::Duration::from_mins(1)),
            )
            .expect("pselect failed");

        // Expect pselect to indicate readiness (HUP should cause revents)
        assert!(ret > 0, "pselect should report ready for EOF/HUP");
        assert!(rfds.iter_ones().all(|fd| fd == rfd_u as usize));

        // read should return 0 (EOF)
        let mut out = [0u8; 8];
        let n = task.sys_read(rfd, &mut out, None).expect("read failed");
        assert_eq!(n, 0, "read should return 0 on EOF");

        let _ = task.sys_close(rfd);
    }

    #[test]
    fn test_pselect_invalid_fd() {
        let task = crate::syscalls::tests::init_platform(None);

        let invalid_fd_u = 100u32;

        // prepare fd_set for read
        let mut rfds = bitvec::bitvec![0; invalid_fd_u.next_multiple_of(64) as usize];
        rfds.set(invalid_fd_u as usize, true);

        let ret = task.do_pselect(
            invalid_fd_u + 1,
            Some(&mut rfds),
            None,
            None,
            Some(core::time::Duration::from_secs(1)),
        );

        // Expect pselect to return EBADF
        assert!(ret.is_err(), "pselect should fail for invalid fd");
        assert_eq!(
            ret.err().unwrap(),
            litebox_common_linux::errno::Errno::EBADF
        );
    }
}
