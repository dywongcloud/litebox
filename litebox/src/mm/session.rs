// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The memory-mutation-effect transaction protocol: an admission gate plus an RAII session that
//! brackets a `prepare -> effect -> apply` cycle against one [`GuestVaDomain`], built on the
//! platform's raw futex primitive rather than a new one.

use core::ops::Range;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use core::time::Duration;

use crate::mm::domain::{
    ClaimHostError, Custody, DomainConflict, GuestVaDomain, HoleToken, ObligationRollback,
    PoisonObligation, TerminalScope, ViewOverlay,
};
use crate::platform::{RawMutex as _, RawMutexProvider};
use crate::sync::RawSyncPrimitivesProvider;
use crate::utils::ids::{FailureId, MemorySessionId, MutationId, TaskInstanceId, VmViewId};

const ACQUIRE_BACKOFF: Duration = Duration::from_millis(20);

/// A process-global mutual-exclusion gate over memory-effect transactions, built directly on the
/// platform's raw futex word rather than [`crate::sync::Mutex`]: ownership lives in its own
/// `owner` word, and the raw mutex's atomic is used purely as a wake/generation counter so a
/// blocked acquirer never loses a concurrent release's wakeup.
pub struct EffectGate<Platform: RawMutexProvider> {
    owner: AtomicU64,
    depth: AtomicU32,
    futex: Platform::RawMutex,
}

impl<Platform: RawMutexProvider> EffectGate<Platform> {
    /// Creates a new, unheld gate.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            owner: AtomicU64::new(0),
            depth: AtomicU32::new(0),
            futex: Platform::RawMutex::INIT,
        }
    }

    fn raw(task: TaskInstanceId) -> u64 {
        task.get().get()
    }

    /// Returns the raw id of the task currently holding this gate, or `0` if it is free.
    #[must_use]
    fn current_owner_raw(&self) -> u64 {
        self.owner.load(Ordering::Acquire)
    }

    /// Blocks until `task` holds the gate. No domain/family lock may be held by the caller across
    /// this call: it may genuinely park the calling thread.
    fn acquire(&self, task: TaskInstanceId) {
        let me = Self::raw(task);
        loop {
            if self
                .owner
                .compare_exchange(0, me, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
            {
                self.depth.store(1, Ordering::Relaxed);
                return;
            }
            let generation = self.futex.underlying_atomic().load(Ordering::Acquire);
            if self.owner.load(Ordering::Relaxed) == 0 {
                continue;
            }
            let _ = self.futex.block_or_timeout(generation, ACQUIRE_BACKOFF);
        }
    }

    /// Releases the gate unconditionally: the caller must already know it is uncontested (either
    /// the sole owner at reentrant depth zero, or forcing recovery of an abandoned gate).
    fn release(&self) {
        self.depth.store(0, Ordering::Relaxed);
        self.owner.store(0, Ordering::Release);
        self.futex.underlying_atomic().fetch_add(1, Ordering::Release);
        self.futex.wake_all();
    }

    /// Recovers the gate when a caller has independently confirmed (via its own live-task table,
    /// outside this module's knowledge) that `expected`'s task has exited without releasing it.
    ///
    /// Returns `true` if this call actually performed the recovery.
    pub fn steal_if_abandoned(&self, expected: TaskInstanceId) -> bool {
        let expected_raw = Self::raw(expected);
        if self
            .owner
            .compare_exchange(expected_raw, 0, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
        {
            self.depth.store(0, Ordering::Relaxed);
            self.futex.underlying_atomic().fetch_add(1, Ordering::Release);
            self.futex.wake_all();
            true
        } else {
            false
        }
    }
}

impl<Platform: RawMutexProvider> Default for EffectGate<Platform> {
    fn default() -> Self {
        Self::new()
    }
}

/// The fallible state a [`MemoryEffectSession`] pre-reserves at [`MemoryEffectSession::open`]
/// time, so that an abnormal [`Drop`] never needs to mint anything (a `FailureId` allocation
/// failing inside `Drop` would leave a poisoned family with no obligation to explain it).
struct ObligationDraft {
    failure: FailureId,
    pre_op_snapshot: crate::mm::domain::VmViewSnapshot,
    touched_range: core::cell::RefCell<Option<Range<usize>>>,
    /// A token this session currently holds custody of but has not yet consumed (set on a
    /// successful `claim_hole`/`retire_to_owned_hole`, cleared the moment
    /// `install_into_owned_hole`/`release_hole` is called to consume it). Left `Some` only if the
    /// session unwinds between claiming and consuming -- exactly the case
    /// [`ObligationRollback::Recoverable`] exists for.
    pending_token: core::cell::RefCell<Option<HoleToken>>,
}

/// One `prepare -> effect -> apply` memory-mutation transaction against a [`GuestVaDomain`],
/// bracketed by an [`EffectGate`]. A session pins its `view` (which must be
/// [`ViewOverlay::Active`], not poisoned/quarantined/retiring) for its whole lifetime, and
/// reentrantly nests for the common case of the same task opening a session while it already
/// holds the gate.
pub struct MemoryEffectSession<'a, Platform: RawSyncPrimitivesProvider> {
    domain: &'a GuestVaDomain,
    gate: &'a EffectGate<Platform>,
    view: VmViewId,
    task: TaskInstanceId,
    id: MemorySessionId,
    depth: u32,
    closed: bool,
    /// Pre-reserved obligation-capture state. `touched_range` is set the moment one of the five
    /// provider-operation forwarding methods below is called, before the domain/platform effect
    /// it wraps can run. Distinguishes, on an abnormal `Drop`, "this session never attempted any
    /// host effect" (plain cleanup, no poison -- opening a session and dropping it on an early
    /// error return is an ordinary, non-ambiguous outcome) from "a host effect was genuinely in
    /// flight when this session's stack unwound" (the real ambiguous-mid-flight case `Drop` must
    /// still poison the family for and capture an obligation about).
    draft: ObligationDraft,
}

impl<'a, Platform: RawSyncPrimitivesProvider> MemoryEffectSession<'a, Platform> {
    /// Opens a session over `view` on behalf of `task`, pinning the view and (unless `task`
    /// already holds `gate`, in which case this nests reentrantly at zero extra lock/block cost)
    /// blocking until the gate is free with no domain/family lock held while it does.
    ///
    /// # Errors
    ///
    /// Returns [`DomainConflict::NotFound`] if `view` is not registered, or
    /// [`DomainConflict::NotInstalled`] if it is not currently [`ViewOverlay::Active`].
    pub fn open(
        domain: &'a GuestVaDomain,
        gate: &'a EffectGate<Platform>,
        view: VmViewId,
        task: TaskInstanceId,
    ) -> Result<Self, DomainConflict> {
        let snapshot = domain.query_view(view).ok_or(DomainConflict::NotFound)?;
        if snapshot.overlay != ViewOverlay::Active {
            return Err(DomainConflict::NotInstalled);
        }
        let me = EffectGate::<Platform>::raw(task);
        let depth = if gate.current_owner_raw() == me {
            gate.depth.fetch_add(1, Ordering::Relaxed) + 1
        } else {
            gate.acquire(task);
            1
        };
        let id = MemorySessionId::next().ok_or(DomainConflict::IdentityExhausted)?;
        // Minted here, at open time, rather than lazily inside `Drop`: the one fallible
        // allocation this session will ever need for its obligation is now done up front, so an
        // abnormal `Drop` never has to fail to mint one.
        let failure = FailureId::next().ok_or(DomainConflict::IdentityExhausted)?;
        Ok(Self {
            domain,
            gate,
            view,
            task,
            id,
            depth,
            closed: false,
            draft: ObligationDraft {
                failure,
                pre_op_snapshot: snapshot,
                touched_range: core::cell::RefCell::new(None),
                pending_token: core::cell::RefCell::new(None),
            },
        })
    }

    /// This session's own identity.
    #[must_use]
    pub fn id(&self) -> MemorySessionId {
        self.id
    }

    /// The view this session is pinned to.
    #[must_use]
    pub fn view(&self) -> VmViewId {
        self.view
    }

    /// The task this session was opened for.
    #[must_use]
    pub fn task(&self) -> TaskInstanceId {
        self.task
    }

    /// This session's reentrant nesting depth (1 for the outermost session on this gate).
    #[must_use]
    pub fn depth(&self) -> u32 {
        self.depth
    }

    /// See [`GuestVaDomain::claim_hole`].
    ///
    /// # Errors
    ///
    /// See [`DomainConflict`].
    pub fn claim_hole(
        &self,
        range: Range<usize>,
        host_reserve: impl FnOnce(Range<usize>) -> Result<(), ClaimHostError>,
    ) -> Result<HoleToken, DomainConflict> {
        self.draft.touched_range.replace(Some(range.clone()));
        let result = self.domain.claim_hole(self.view, range, host_reserve);
        if let Ok(token) = &result {
            self.draft.pending_token.replace(Some(token.clone()));
        }
        result
    }

    /// See [`GuestVaDomain::install_into_owned_hole`].
    ///
    /// # Errors
    ///
    /// See [`DomainConflict`].
    pub fn install_into_owned_hole(
        &self,
        token: HoleToken,
        view: VmViewId,
        install: impl FnOnce(Range<usize>) -> Result<(), ()>,
    ) -> Result<MutationId, DomainConflict> {
        self.draft.touched_range.replace(Some(token.range()));
        self.draft.pending_token.replace(Some(token.clone()));
        let result = self.domain.install_into_owned_hole(token, view, install);
        self.draft.pending_token.replace(None);
        result
    }

    /// See [`GuestVaDomain::replace_present`].
    ///
    /// # Errors
    ///
    /// See [`DomainConflict`].
    pub fn replace_present(
        &self,
        view: VmViewId,
        range: Range<usize>,
        replace: impl FnOnce(Range<usize>) -> Result<(), ()>,
    ) -> Result<MutationId, DomainConflict> {
        self.draft.touched_range.replace(Some(range.clone()));
        self.domain.replace_present(view, range, replace)
    }

    /// See [`GuestVaDomain::retire_to_owned_hole`].
    ///
    /// # Errors
    ///
    /// See [`DomainConflict`].
    pub fn retire_to_owned_hole(
        &self,
        view: VmViewId,
        range: Range<usize>,
        host_reset: impl FnOnce(Range<usize>) -> Result<(), ()>,
    ) -> Result<HoleToken, DomainConflict> {
        self.draft.touched_range.replace(Some(range.clone()));
        let result = self.domain.retire_to_owned_hole(view, range, host_reset);
        if let Ok(token) = &result {
            self.draft.pending_token.replace(Some(token.clone()));
        }
        result
    }

    /// See [`GuestVaDomain::release_hole`].
    ///
    /// # Errors
    ///
    /// See [`DomainConflict`].
    pub fn release_hole(
        &self,
        token: HoleToken,
        host_release: impl FnOnce(Range<usize>) -> Result<(), ()>,
    ) -> Result<(), DomainConflict> {
        self.draft.touched_range.replace(Some(token.range()));
        self.draft.pending_token.replace(Some(token.clone()));
        let result = self.domain.release_hole(token, host_release);
        self.draft.pending_token.replace(None);
        result
    }

    /// SwitchAccess: a real hard-failing refusal layered strictly UNDER a fork-family
    /// address-space hand-off's existing per-syscall cross-process guards
    /// (`overlaps_another_process`/`touches_another_process` in
    /// `litebox_shim_linux/src/syscalls/process.rs`, which stay exactly as they are, unchanged,
    /// and are never replaced by this) -- runs `write` (the real, raw guest-memory copy) only
    /// when `range` is not a genuine foreign-view [`Custody::Present`]/[`Custody::Retiring`] hit
    /// (now checked both within `view`'s own family via [`GuestVaDomain::custody_fragments`] and,
    /// since `switch-divergence-hard-gate-once-domain-authoritative`, across every other live
    /// family via [`GuestVaDomain::foreign_family_present`]), or permanently
    /// [`Custody::DomainBlocked`]. `Task::restore_address_space` (see
    /// `address-space-membership-domain-authoritative-wiring`) confirms/reconciles the domain's
    /// own custody for every range it touches via [`GuestVaDomain::confirm_present_or_reconcile`]
    /// before and after this call, so a refusal here reflects the domain's own authoritative
    /// state, not a stale mirror: returning `None` is a real, hard skip of this piece, not merely
    /// a logged pass-through.
    pub fn switch_write<T>(&self, range: Range<usize>, write: impl FnOnce() -> Option<T>) -> Option<T> {
        self.own_or_untracked("switch_write", range).then(write).flatten()
    }

    /// DivergenceSave: the save-before-diverge twin of [`Self::switch_write`], for the read side
    /// of a fork-family address-space hand-off's own copy-out. Same hard-refusal rule: a `None`
    /// here is a real, hard skip of saving this piece, not merely a logged pass-through.
    pub fn divergence_save_read<T>(&self, range: Range<usize>, read: impl FnOnce() -> Option<T>) -> Option<T> {
        self.own_or_untracked("divergence_save_read", range).then(read).flatten()
    }

    /// Shared hard-refusal rule for [`Self::switch_write`]/[`Self::divergence_save_read`]: `true`
    /// unless `range` overlaps a genuine `Present`/`Retiring` custody fragment belonging to
    /// another view -- checked two ways, since neither alone is complete. First, across every
    /// other currently-live fork family via [`GuestVaDomain::foreign_family_present`]: this is
    /// the real cross-family primitive this row adds, since [`GuestVaDomain::custody_fragments`]
    /// is structurally scoped to `view`'s own family and can never itself observe a different
    /// family's custody (see that method's docs). Second, the pre-existing same-family walk over
    /// [`GuestVaDomain::custody_fragments`] below, kept unchanged for forward-compatibility (its
    /// foreign-view arm is unreachable today against a single-view-per-family shape, exactly as
    /// documented, but is deliberately never deleted). A permanently
    /// [`Custody::DomainBlocked`] span is refused either way. `Custody::Installing` carries no
    /// view identity to check against, so it is never treated as foreign; a fully unrecorded
    /// range (no fragments at all) is the common, expected, non-foreign case today.
    ///
    /// This check is layered strictly under, and never replaces, the pre-existing
    /// `overlaps_another_process`/`touches_another_process` diagnostic guards in
    /// `litebox_shim_linux/src/syscalls/process.rs` -- both keep firing exactly as before.
    fn own_or_untracked(&self, site: &'static str, range: Range<usize>) -> bool {
        if range.start >= range.end {
            return true;
        }
        if self.domain.foreign_family_present(self.view, range.clone()) {
            litebox_util_log::error!(
                site, view:? = self.view, start:? = range.start, end:? = range.end;
                "switch/divergence-save access refused: domain shows a different live family's Present custody over this range"
            );
            return false;
        }
        for (_, custody) in self.domain.custody_fragments(self.view, range.clone()) {
            let foreign = match custody {
                Custody::DomainBlocked(_) => true,
                Custody::Present { view, .. } | Custody::Retiring { view, .. } => view != self.view,
                Custody::Unclaimed
                | Custody::Hole { .. }
                | Custody::Installing { .. }
                | Custody::Reserved { .. } => false,
            };
            if foreign {
                litebox_util_log::error!(
                    site, view:? = self.view, start:? = range.start, end:? = range.end;
                    "switch/divergence-save access refused: domain shows a foreign view's custody over this range"
                );
                return false;
            }
        }
        true
    }

    /// Closes the session in the ordinary, well-nested case: decrements the gate's reentrant
    /// depth, releasing it only when the outermost session on this gate closes.
    pub fn close(mut self) {
        self.close_ordinary();
    }

    fn close_ordinary(&mut self) {
        if self.closed {
            return;
        }
        let remaining = self.gate.depth.fetch_sub(1, Ordering::Relaxed) - 1;
        if remaining == 0 {
            self.gate.owner.store(0, Ordering::Release);
            self.gate.futex.underlying_atomic().fetch_add(1, Ordering::Release);
            self.gate.futex.wake_all();
        }
        self.closed = true;
    }
}

impl<Platform: RawSyncPrimitivesProvider> Drop for MemoryEffectSession<'_, Platform> {
    fn drop(&mut self) {
        if self.closed {
            return;
        }
        // Dropped without an explicit `close`: the nested reentrant-depth bookkeeping can no
        // longer be trusted to unwind in the order it was built, so recovery here is a full,
        // idempotent reset of the gate rather than a depth decrement -- regardless of whether an
        // effect was ever attempted (an abandoned gate must never stay held either way).
        self.gate.release();
        self.closed = true;
        // Poison only when a host effect was genuinely attempted: a session opened and dropped
        // (error return, early `?`, or a panic before any of the five provider-operation methods
        // ran) without ever calling into the domain's claim/install/replace/retire/release methods
        // has nothing ambiguous to recover from, so it must not poison the family it merely
        // pinned. Only a real effect left mid-flight -- the domain/platform callback panicking, or
        // this whole session's stack unwinding while one of those five calls was still on it -- is
        // the ambiguous case this poison exists for.
        let Some(range) = self.draft.touched_range.borrow().clone() else {
            return;
        };
        let post_op_snapshot = self.domain.query_view(self.view);
        let touched_custody = self.domain.custody_fragments(self.view, range.clone());
        let admission_snapshot = self.domain.admission_snapshot(self.view);
        let rollback = match self.draft.pending_token.borrow_mut().take() {
            Some(token) => ObligationRollback::Recoverable { token },
            None => ObligationRollback::Terminal,
        };
        let obligation = PoisonObligation {
            view: self.view,
            family: self.draft.pre_op_snapshot.family,
            owner: post_op_snapshot.map_or(self.draft.pre_op_snapshot.owner, |s| s.owner),
            pre_op_snapshot: self.draft.pre_op_snapshot,
            post_op_snapshot,
            touched_range: range,
            touched_custody,
            admission_snapshot,
            failure: self.draft.failure,
            scope: TerminalScope::FamilyScoped,
            rollback,
        };
        let _ = self.domain.mark_poison_with_obligation(obligation);
    }
}
