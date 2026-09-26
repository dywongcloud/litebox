// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Fallible, iteratively-destroyed storage for an immutable seccomp classic-BPF filter chain.
//!
//! A chain is a singly-linked list of [`Node`]s, newest first: installing a new filter never
//! mutates an existing node, it only ever builds one new node whose `prev` is the previous head.
//! Real Linux evaluates such a chain newest-to-oldest (the most recently installed filter runs
//! first), which [`SeccompFilterChain::evaluate_newest_to_oldest`] mirrors.
//!
//! Every live reference to a node -- the head a caller holds, a node's own `prev` link, a
//! temporary produced while cloning -- is one [`OwnedChainHandle`]: a `triomphe::Arc<Node>`
//! paired *inseparably* with one [`HandlePermit`], a token against the single process-wide
//! [`GLOBAL_PERMITTED`] counter. Neither half may ever exist without the other (see
//! [`OwnedChainHandle`]'s own doc comment). That pairing, plus reserving the permit *before* the
//! `Arc` it accounts for is created or cloned, is what keeps every strong owner backed by exactly
//! one permit with the total checked below the clone-abort threshold without a race:
//! `triomphe::Arc::clone` is itself infallible and aborts the process outright past
//! `isize::MAX` references (see `arc.rs:610-646` in the pinned `triomphe` 0.1.16 source), so the
//! only way to keep it from ever approaching that threshold is to refuse the clone before it
//! happens whenever this module's own, far tighter, checked cap is already exhausted.
//!
//! Teardown never uses `Arc`'s own recursive `Drop` -- chain depth is guest-controlled (a guest
//! may install as many filters as it can pass allocation/permit checks for), so a naive recursive
//! drop could blow the stack. Instead [`OwnedChainHandle::drop`] is one flat loop: at each step it
//! calls `triomphe::Arc::into_unique` on the current node. If that node has another owner
//! (`None`), only this handle's own one permit is released and the walk stops -- the other owner
//! will in turn walk the rest once *it* becomes the last one. If this handle was the last owner
//! (`Some`), the node's whole `prev` handle is lifted out first (through `DerefMut`, before
//! `UniqueArc::into_inner` consumes the node), the now-`prev`-less node is dropped (freeing its
//! own leaf storage), this handle's permit is released, and the lifted `prev` handle -- via its
//! own private [`OwnedChainHandle::into_parts`] -- becomes the next loop iteration's cursor. No
//! step recurses, so an arbitrarily long chain is torn down in one constant-stack pass.

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::mem::ManuallyDrop;
use core::ops::ControlFlow;
use core::sync::atomic::{AtomicUsize, Ordering};

use litebox_common_linux::errno::Errno;
use triomphe::{Arc as TArc, UniqueArc};

/// Process-wide count of currently-live [`HandlePermit`]s -- one per live [`OwnedChainHandle`],
/// i.e. one per live strong reference to any [`Node`] of any chain, across every thread and every
/// chain. Deliberately global and not per-node/per-chain, so it bounds aggregate reference
/// pressure from seccomp storage regardless of how it happens to be distributed.
static GLOBAL_PERMITTED: AtomicUsize = AtomicUsize::new(0);

/// The permit cap: far below `isize::MAX` (`triomphe::Arc::clone`'s own abort threshold -- see
/// this module's doc comment) by many orders of magnitude. No consumer install path exists yet to
/// calibrate this against a real seccomp resource limit (that is `chromium-linux-seccomp-bpf`'s
/// own future work); this is a generously-sized defensive ceiling, not a tuned production value.
const MAX_LIVE_PERMITS: usize = 1 << 20;

/// The current live permit count, i.e. the total number of live strong references to any [`Node`]
/// of any chain right now. Diagnostic only -- never consulted to decide the correctness of any
/// operation; that is always the checked acquire in [`HandlePermit::try_acquire`] itself.
pub(crate) fn live_permit_count() -> usize {
    GLOBAL_PERMITTED.load(Ordering::Relaxed)
}

/// One capacity-accounting token against [`GLOBAL_PERMITTED`]. Always held paired with exactly
/// one `triomphe::Arc<Node>` strong reference inside an [`OwnedChainHandle`] -- see there. Holds
/// no data of its own and guards no other memory, so `Relaxed` ordering is enough for both the
/// acquire and the release: the counter only bounds admission, it never publishes anything else.
struct HandlePermit(());

impl HandlePermit {
    /// Reserves one permit, or returns `ENOMEM` if [`MAX_LIVE_PERMITS`] is already reached. Never
    /// allocates and never touches any `Arc` -- callers reserve a permit with this *before*
    /// creating or cloning the raw `Arc` it will account for, never after.
    fn try_acquire() -> Result<Self, Errno> {
        let mut observed = GLOBAL_PERMITTED.load(Ordering::Relaxed);
        loop {
            if observed >= MAX_LIVE_PERMITS {
                return Err(Errno::ENOMEM);
            }
            match GLOBAL_PERMITTED.compare_exchange_weak(
                observed,
                observed + 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return Ok(Self(())),
                Err(current) => observed = current,
            }
        }
    }
}

impl Drop for HandlePermit {
    fn drop(&mut self) {
        GLOBAL_PERMITTED.fetch_sub(1, Ordering::Relaxed);
    }
}

/// One installed filter: the verified raw `sock_filter` program bytes
/// (`super::seccomp_bpf::run_program` executes them), the install flags, whether
/// `SECCOMP_FILTER_FLAG_LOG` was requested for it, and the tids of the sibling threads a TSYNC
/// install published it onto (empty for an ordinary install). What this type owns is the
/// fallible storage and the newest-to-oldest linkage; the BPF semantics live in `seccomp_bpf`.
pub(crate) struct Node {
    flags: u32,
    log: bool,
    program_bytes: Box<[u8]>,
    tsync_targets: Box<[i32]>,
    /// The chain this node was installed on top of, i.e. the next-oldest filter. `None` at the
    /// chain's root. Moving this whole field out of a uniquely-owned `Node` (via `DerefMut`,
    /// before that node is itself consumed) -- never dropping it in place -- is the mechanism
    /// [`OwnedChainHandle`]'s iterative `Drop` reclaims an entire chain through.
    prev: Option<OwnedChainHandle>,
}

impl Node {
    pub(crate) fn flags(&self) -> u32 {
        self.flags
    }

    pub(crate) fn log(&self) -> bool {
        self.log
    }

    pub(crate) fn program_bytes(&self) -> &[u8] {
        &self.program_bytes
    }

    pub(crate) fn tsync_targets(&self) -> &[i32] {
        &self.tsync_targets
    }
}

/// One live strong reference to a [`Node`], inseparable from the one [`HandlePermit`] that
/// accounts for it: every reachable state has both halves or neither, never one without the
/// other -- a raw `Arc` or a bare permit must never independently escape this type. Both fields
/// are [`ManuallyDrop`] so that ordinary field-by-field `Drop` -- which would recurse through
/// `Node::prev` (see this module's own doc comment) -- never runs. [`OwnedChainHandle::drop`] and
/// [`OwnedChainHandle::into_parts`] are the only two places either field is ever read out, and
/// each does so exactly once.
struct OwnedChainHandle {
    arc: ManuallyDrop<TArc<Node>>,
    permit: ManuallyDrop<HandlePermit>,
}

impl OwnedChainHandle {
    fn new(arc: TArc<Node>, permit: HandlePermit) -> Self {
        Self {
            arc: ManuallyDrop::new(arc),
            permit: ManuallyDrop::new(permit),
        }
    }

    fn node(&self) -> &Node {
        &self.arc
    }

    /// Consumes `self` into its raw parts without ever running [`OwnedChainHandle::drop`] on it.
    /// Private: the only caller is `Drop::drop` itself, continuing the iterative teardown loop
    /// one predecessor at a time.
    fn into_parts(self) -> (TArc<Node>, HandlePermit) {
        let mut this = ManuallyDrop::new(self);
        // SAFETY: wrapping `self` above suppresses `OwnedChainHandle::drop` for it, so these two
        // `ManuallyDrop::take` calls are the only reads of either field and cannot double-free.
        unsafe {
            (
                ManuallyDrop::take(&mut this.arc),
                ManuallyDrop::take(&mut this.permit),
            )
        }
    }

    /// Reserves a fresh permit, then clones the `Arc` -- in that order, never the reverse, so a
    /// refused clone (cap exhausted) never touches `self.arc`'s strong count at all.
    fn try_clone(&self) -> Result<Self, Errno> {
        let permit = HandlePermit::try_acquire()?;
        let arc = TArc::clone(&self.arc);
        Ok(Self::new(arc, permit))
    }
}

impl Drop for OwnedChainHandle {
    fn drop(&mut self) {
        // SAFETY: `self` is mid-drop; nothing else observes these two fields again afterward, so
        // taking both out here (the only read of either for this `self`) cannot race or
        // double-free.
        let mut cursor = unsafe {
            (
                ManuallyDrop::take(&mut self.arc),
                ManuallyDrop::take(&mut self.permit),
            )
        };
        loop {
            let (arc, permit) = cursor;
            let Some(mut unique) = TArc::into_unique(arc) else {
                // Another owner is still alive: only this handle's own one permit is ours to
                // release. That other owner will walk the rest of the chain when it becomes the
                // last one -- recursing into it here would double-reclaim it.
                drop(permit);
                return;
            };
            let prev = unique.prev.take();
            drop(UniqueArc::into_inner(unique));
            drop(permit);
            match prev {
                None => return,
                Some(prev_handle) => cursor = prev_handle.into_parts(),
            }
        }
    }
}

/// The outcome of one [`SeccompFilterChain::evaluate_newest_to_oldest`] walk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SeccompEvalWalk {
    pub(crate) nodes_visited: u32,
    pub(crate) fuel_exhausted: bool,
}

/// A private, non-`Clone` handle onto an immutable seccomp filter chain. `owned` is `None` only
/// transiently within this module's own construction paths -- every chain returned by
/// [`SeccompFilterChain::try_install`] is `Some`.
pub(crate) struct SeccompFilterChain {
    owned: Option<OwnedChainHandle>,
}

impl SeccompFilterChain {
    /// Builds one new head node on top of `prev` (`None` for a chain's first filter), performing
    /// every fallible step -- program/TSYNC storage reservation, the permit-and-clone needed to
    /// retain `prev`, the new node's own permit, and its own `Arc` allocation -- before
    /// constructing the value this returns. Nothing here mutates any externally-shared state, so
    /// a caller holding `prev` under its own lock (revalidated by reading it fresh right before
    /// this call) can commit an `Ok` result with one plain assignment, while an `Err` leaves
    /// whatever that lock currently guards completely untouched: there is no partially-visible
    /// chain state for a concurrent reader to ever observe either way.
    pub(crate) fn try_install(
        prev: Option<&SeccompFilterChain>,
        flags: u32,
        log: bool,
        program_bytes: &[u8],
        tsync_targets: &[i32],
    ) -> Result<Self, Errno> {
        let mut program_owned = Vec::new();
        program_owned
            .try_reserve_exact(program_bytes.len())
            .map_err(|_| Errno::ENOMEM)?;
        program_owned.extend_from_slice(program_bytes);

        let mut tsync_owned = Vec::new();
        tsync_owned
            .try_reserve_exact(tsync_targets.len())
            .map_err(|_| Errno::ENOMEM)?;
        tsync_owned.extend_from_slice(tsync_targets);

        let prev_owned = match prev.and_then(|chain| chain.owned.as_ref()) {
            None => None,
            Some(handle) => Some(handle.try_clone()?),
        };

        let permit = HandlePermit::try_acquire()?;
        let node = Node {
            flags,
            log,
            program_bytes: program_owned.into_boxed_slice(),
            tsync_targets: tsync_owned.into_boxed_slice(),
            prev: prev_owned,
        };
        let arc = TArc::try_new(node).map_err(|_| Errno::ENOMEM)?;

        Ok(Self {
            owned: Some(OwnedChainHandle::new(arc, permit)),
        })
    }

    /// Fallibly duplicates this handle: the clone observes the identical chain (the same nodes,
    /// by identity, all the way down) and can be dropped independently of the original.
    pub(crate) fn try_clone(&self) -> Result<Self, ()> {
        let owned = match &self.owned {
            None => None,
            Some(handle) => Some(handle.try_clone().map_err(|_| ())?),
        };
        Ok(Self { owned })
    }

    /// The number of filters on this chain.
    pub(crate) fn depth(&self) -> u32 {
        self.evaluate_newest_to_oldest(u32::MAX, |_| ControlFlow::Continue(()))
            .nodes_visited
    }

    /// Linux `is_ancestor(parent = self, child = descendant)`: whether this chain's head node is
    /// one of `descendant`'s nodes by exact identity (reflexively: a chain is its own ancestor).
    /// A chain with no head (never the case for an installed chain) is every chain's ancestor,
    /// as a `NULL` parent is in Linux. Used by TSYNC eligibility: a sibling thread's chain must
    /// be an ancestor-or-equal of the installing thread's chain for the sibling to be
    /// synchronizable.
    pub(crate) fn is_ancestor_of(&self, descendant: &SeccompFilterChain) -> bool {
        let Some(head) = self.owned.as_ref() else {
            return true;
        };
        let mut cursor = descendant.owned.as_ref();
        while let Some(handle) = cursor {
            if TArc::ptr_eq(&handle.arc, &head.arc) {
                return true;
            }
            cursor = handle.node().prev.as_ref();
        }
        false
    }

    /// Walks the chain newest-to-oldest (the most recently installed filter first, matching real
    /// Linux), calling `visit` on each node until either `visit` returns [`ControlFlow::Break`],
    /// the chain is exhausted, or `fuel` -- this call's own independent budget, unrelated to any
    /// other call, past or concurrent -- runs out first.
    pub(crate) fn evaluate_newest_to_oldest<F: FnMut(&Node) -> ControlFlow<()>>(
        &self,
        fuel: u32,
        mut visit: F,
    ) -> SeccompEvalWalk {
        let mut remaining_fuel = fuel;
        let mut nodes_visited = 0u32;
        let mut cursor = self.owned.as_ref();
        while let Some(handle) = cursor {
            if remaining_fuel == 0 {
                return SeccompEvalWalk {
                    nodes_visited,
                    fuel_exhausted: true,
                };
            }
            remaining_fuel -= 1;
            nodes_visited += 1;
            let node = handle.node();
            if visit(node).is_break() {
                break;
            }
            cursor = node.prev.as_ref();
        }
        SeccompEvalWalk {
            nodes_visited,
            fuel_exhausted: false,
        }
    }
}
