// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The process-global guest-virtual-address domain.
//!
//! One [`GuestVaDomain`] owns a fixed aperture of guest virtual addresses for the whole process.
//! Fork families ([`FamilyId`]) register logical [`VmView`]s of that aperture; two unrelated
//! views may numerically overlap at the logical layer (see [`GuestVaDomain::publish_reserved`]),
//! but the domain's `installed` set -- the views that are actually, physically mapped right now
//! -- is kept pairwise disjoint for [`SpanKind::Present`] spans by
//! [`GuestVaDomain::publish_present`].
//!
//! This module lands the registry data model only. The transaction protocol that will retire the
//! disjoint-family interval registry currently living in `litebox_shim_linux` (its
//! `family_id`/`overlaps_another_process` checks and `Vmem::reserved`) is separate, dependent
//! work; nothing here is wired into those call sites yet.
//!
//! Every method takes this domain's own [`spin::Mutex`] for one short critical section: no
//! provider call, guest copy, callback, wait, kick, or drain ever runs while it is held.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::ops::Range;
use core::sync::atomic::{AtomicU64, Ordering};

use hashbrown::HashMap;
use rangemap::RangeMap;
use spin::Mutex;

use crate::utils::ids::{
    EffectEpoch, FailureId, FamilyId, HoleGenerationId, MemoryDomainId, MutationId,
    ProcessInstanceId, TaskInstanceId, VmViewId,
};

fn overlaps(a: &Range<usize>, b: &Range<usize>) -> bool {
    a.start < b.end && b.start < a.end
}

/// One platform-reserved span inside a [`GuestVaDomain`]'s aperture that no [`VmView`] may ever
/// claim (e.g. guard pages, or spans the platform itself already owns).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DomainBlocked(pub Range<usize>);

/// The kind of guest-virtual-address span a [`VmView`] currently claims.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpanKind {
    /// Backed by real memory: eligible to be published into the domain's installed set, and
    /// checked for pairwise disjointness against every other view's `Present` spans there.
    Present,
    /// Logical-only custody for a deferred reservation (e.g. a V8 cage). Never installed, and
    /// never checked against the installed set or any other view's spans -- unrelated views may
    /// claim identical guest addresses this way.
    Reserved,
}

/// Where a [`VmView`] sits in its own lifecycle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ViewOverlay {
    /// Registered, but has not yet published a `Present` span.
    Installing,
    /// Has at least one `Present` span currently in the domain's installed set.
    Active,
    /// Had its installed spans removed by [`GuestVaDomain::retire_view`]; its logical topology
    /// (and identity) still exist until [`GuestVaDomain::unregister_view`].
    Retiring,
    /// The owning family has been marked poisoned via [`GuestVaDomain::mark_poison`].
    Poisoned,
    /// The owning family has been marked quarantined via [`GuestVaDomain::mark_quarantine`].
    Quarantined,
}

/// A typed conflict returned instead of ever deferring or blocking a publish.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DomainConflict {
    /// The requested range is empty, or not fully inside the domain's aperture.
    OutsideAperture,
    /// The requested range overlaps a platform-reserved [`DomainBlocked`] span.
    Blocked,
    /// The requested `Present` range overlaps another view's currently installed span.
    InstalledOverlap(VmViewId),
    /// The identity or effect-epoch counter space is exhausted.
    IdentityExhausted,
    /// The named family or view is not registered.
    NotFound,
    /// The requested range's custody is already claimed by something other than what the
    /// operation requires (a hole, another view's span, an in-flight transition, or a mix of
    /// several), or a supplied token no longer matches the range's live generation.
    Occupied,
    /// The view's admission word is not [`AdmissionState::Open`]: a lease was refused, or
    /// [`GuestVaDomain::begin_drain`] was called again while a drain is already in flight.
    Draining,
    /// The view exists but has no currently installed `Present` span (its [`ViewOverlay`] is not
    /// [`ViewOverlay::Active`]).
    NotInstalled,
}

/// A [`VmView`]'s run/access admission word: [`AdmissionState`], a generation counter, and a live
/// lease count, packed into one [`AtomicU64`] (bits 0-1 = state, bits 2-33 = generation, bits
/// 34-63 = lease count) so a future switcher can compare-and-block on it as a single word.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdmissionState {
    /// New leases are admitted.
    Open,
    /// A drain is in flight: no new lease is admitted; already-held leases are unaffected.
    Draining,
    /// The view is permanently closed to new leases.
    Closed,
}

const ADMISSION_MAX_COUNT: u32 = (1u32 << 30) - 1;

fn pack_admission(state: AdmissionState, generation: u32, count: u32) -> u64 {
    let state_bits: u64 = match state {
        AdmissionState::Open => 0,
        AdmissionState::Draining => 1,
        AdmissionState::Closed => 2,
    };
    state_bits | (u64::from(generation) << 2) | (u64::from(count) << 34)
}

fn unpack_admission(word: u64) -> (AdmissionState, u32, u32) {
    let state = match word & 0b11 {
        0 => AdmissionState::Open,
        1 => AdmissionState::Draining,
        _ => AdmissionState::Closed,
    };
    let generation = ((word >> 2) & 0xFFFF_FFFF) as u32;
    let count = (word >> 34) as u32;
    (state, generation, count)
}

/// Origin of one permanently-blocked custody span in a [`GuestVaDomain`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockOrigin {
    /// Declared at domain construction time (e.g. a platform's reserved pages).
    ConstructionStatic,
    /// A platform trampoline/stub region.
    Trampoline,
    /// A hard floor imposed by the HVF backend's IPA layout.
    HvfFloorLimit,
    /// Discovered dynamically: the host refused to reserve this range for a reason attributable
    /// to another, uncontrolled owner (e.g. a Darwin `KERN_NO_SPACE`-shaped failure), so it is
    /// permanently excluded without ever re-probing the host for it again.
    ForeignHost,
}

/// Custody state of one guest-virtual-address range inside a [`GuestVaDomain`]'s aperture.
///
/// This is the per-range "component" state the guest-owned-aperture-provider-operations model
/// tracks, distinct from `ViewOverlay` (per-view lifecycle). `Installing`/`Retiring` are
/// transient overlay values a range holds only while a caller-supplied platform closure for that
/// operation is in flight, outside the domain lock -- see the provider-operation methods below.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Custody {
    /// No view has ever claimed this range.
    Unclaimed,
    /// Domain-owned, unmapped: reserved from the host but not backing any view.
    Hole {
        /// The custody generation stamped when this hole was created.
        generation: HoleGenerationId,
    },
    /// Backing a live, installed `Present` span of `view`.
    Present {
        /// The custody generation stamped when this span was installed.
        generation: HoleGenerationId,
        /// The view this span backs.
        view: VmViewId,
    },
    /// Permanently excluded; no view may ever claim this range.
    DomainBlocked(BlockOrigin),
    /// A claim/install platform callback is in flight for this range.
    Installing {
        /// The generation this range will resume under (a fresh one on success, the same one on
        /// rollback), authenticating racing callers against a stale token.
        generation: HoleGenerationId,
    },
    /// A retire platform callback is in flight for this range.
    Retiring {
        /// The generation this range was retiring from.
        generation: HoleGenerationId,
        /// The view whose span is being retired.
        view: VmViewId,
    },
    /// Logical-only custody claimed by one or more views (never installed; mirrors
    /// `SpanKind::Reserved`), counted as occupied for placement and conflicts exactly like
    /// `Present` for admission -- domain-wide, not just inside one view's private topology.
    Reserved {
        /// Every view that currently holds a logical reservation over this range.
        views: Vec<VmViewId>,
    },
}

/// An opaque, generation-authenticated capability minted by [`GuestVaDomain::claim_hole`] or
/// [`GuestVaDomain::retire_to_owned_hole`], consumed by exactly one of
/// [`GuestVaDomain::install_into_owned_hole`] or [`GuestVaDomain::release_hole`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HoleToken {
    range: Range<usize>,
    generation: HoleGenerationId,
    /// The family whose per-family maps this token's range lives in -- an install attempted from
    /// a different family's view is refused rather than silently mutating the wrong family's
    /// bookkeeping.
    family: FamilyId,
}

impl HoleToken {
    /// The guest-virtual-address range this token authenticates custody over.
    #[must_use]
    pub fn range(&self) -> Range<usize> {
        self.range.clone()
    }
}

/// Outcome of a caller-supplied host-reservation closure passed to [`GuestVaDomain::claim_hole`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClaimHostError {
    /// The host refused this range for a reason attributable to another, uncontrolled owner.
    /// The range is permanently marked [`Custody::DomainBlocked`] and never re-probed.
    ForeignHost,
    /// Any other recoverable failure: the range rolls back to [`Custody::Unclaimed`].
    Other,
}

/// Per-fork-family bookkeeping, kept in the registry independent of live [`VmView`] membership.
///
/// This record has zero members exactly while every survivor count below is also zero: a family
/// with no live views but an outstanding poison, quarantine, lease, ticket, or reservation
/// survivor is deliberately kept around rather than reaped, so that state outlives membership.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FamilyRecord {
    /// The family this one was registered from via [`GuestVaDomain::register_family_from`], if
    /// any -- `None` for a family registered via the plain [`GuestVaDomain::register_family`]
    /// (a genuinely new, unrelated lineage root). This is the sole lineage link a fork child's
    /// family carries back to its parent's: see [`GuestVaDomain::custody_at_via_lineage`], which
    /// walks this chain to resolve custody a freshly-forked child's own (still-empty) family map
    /// cannot answer on its own.
    pub parent: Option<FamilyId>,
    /// Whether this family has replaced its fork-inherited image with one of its own (an
    /// `execve`), after which nothing it maps is inherited from any ancestor any more. Consulted
    /// only by [`GuestVaDomain::family_has_live_inheriting_descendant_of`]; the lineage link
    /// itself, and every fault-path predicate built on it, is unaffected.
    pub exec_severed: bool,
    /// Count of [`VmView`]s currently registered to this family.
    pub members: usize,
    /// Count of live [`GuestRunLease`]/[`ViewAccessLease`] guards outstanding for views of this
    /// family, maintained by [`GuestVaDomain::acquire_run_lease`]/
    /// [`GuestVaDomain::acquire_access_lease`] and their `Drop` impls.
    pub lease_survivors: usize,
    /// Count of outstanding scheduler-ticket survivors (reserved for the dependent
    /// transaction-protocol row; never incremented here).
    pub ticket_survivors: usize,
    /// Whether [`GuestVaDomain::mark_poison`] has been called for this family.
    pub poisoned: bool,
    /// Whether [`GuestVaDomain::mark_quarantine`] has been called for this family.
    pub quarantined: bool,
    /// Count of outstanding logical `Reserved` custody survivors (reserved for the dependent
    /// transaction-protocol row; never incremented here).
    pub reservation_survivors: usize,
}

/// The blast radius a [`PoisonObligation`] was recorded against: one fork family, or (reserved
/// for a future HVF-provider-wide terminal condition) every family the process has ever
/// registered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TerminalScope {
    /// Only the one family named by [`PoisonObligation::family`] was poisoned.
    FamilyScoped,
    /// Every family in the domain was poisoned (see [`GuestVaDomain::mark_process_global_terminal`]).
    HvfProviderGlobal,
}

/// What a future repair pass can still do with the range a [`PoisonObligation`] was recorded
/// against.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ObligationRollback {
    /// A [`HoleToken`] for the obligation's range was never consumed (the session was dropped
    /// after claiming it but before installing or releasing it) -- the range can still be handed
    /// back to [`Custody::Unclaimed`] via [`GuestVaDomain::release_hole`].
    Recoverable {
        /// The unconsumed token.
        token: HoleToken,
    },
    /// No token survives (either none was ever produced, e.g. a bare `replace_present`/
    /// `install_into_owned_hole` panicked, or one already was consumed): nothing but the poison
    /// itself remains as evidence of the range's last known state.
    Terminal,
}

/// A durable record of exactly what a [`MemoryEffectSession`](crate::mm::session::MemoryEffectSession)
/// was doing to a [`GuestVaDomain`] when it poisoned its family, captured at poison time so a
/// future repair/diagnostic pass has more to act on than "this family is poisoned".
///
/// Deliberately not [`Clone`]: an obligation is a one-time capture of a specific mid-flight
/// moment, not a value meant to be copied around and potentially mutated in two places.
pub struct PoisonObligation {
    /// The view whose session recorded this obligation.
    pub view: VmViewId,
    /// The family that was poisoned as a result.
    pub family: FamilyId,
    /// The task/process that owned the session.
    pub owner: (ProcessInstanceId, TaskInstanceId),
    /// A snapshot of the view's identity/lifecycle state taken before the effect that triggered
    /// this obligation was attempted.
    pub pre_op_snapshot: VmViewSnapshot,
    /// A snapshot taken at obligation-capture time (after the effect), if the view was still
    /// registered then.
    pub post_op_snapshot: Option<VmViewSnapshot>,
    /// The address range the in-flight effect was operating over.
    pub touched_range: Range<usize>,
    /// Every custody fragment recorded over `touched_range` at capture time -- naturally
    /// captures a live `Installing`/`Retiring` transient marker left behind by a mid-flight
    /// panic, since this is queried after the poison but before anything else runs.
    pub touched_custody: Vec<(Range<usize>, Custody)>,
    /// The view's admission word, decomposed, at capture time.
    pub admission_snapshot: Option<(AdmissionState, u32, u32)>,
    /// This obligation's own identity.
    pub failure: FailureId,
    /// The blast radius this obligation's poison was recorded against.
    pub scope: TerminalScope,
    /// What a future repair pass can still do with `touched_range`.
    pub rollback: ObligationRollback,
}

/// One logical view of guest memory belonging to one fork family.
struct VmView {
    family: FamilyId,
    owner: (ProcessInstanceId, TaskInstanceId),
    overlay: ViewOverlay,
    topology: RangeMap<usize, SpanKind>,
    /// Run/access admission word (see [`AdmissionState`]). An [`Arc`] so a live lease guard can
    /// touch it on [`Drop`] with no domain lock held.
    admission: Arc<AtomicU64>,
}

/// A snapshot of one [`VmView`]'s identity and lifecycle state, returned by
/// [`GuestVaDomain::query_view`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VmViewSnapshot {
    /// This view's identity.
    pub id: VmViewId,
    /// The fork family this view belongs to.
    pub family: FamilyId,
    /// The process/task instance that owns this view.
    pub owner: (ProcessInstanceId, TaskInstanceId),
    /// This view's current lifecycle state.
    pub overlay: ViewOverlay,
}

/// One fork family's own installed set and custody map, kept structurally disjoint from every
/// other family's -- an unrelated family's identical-address `Present` claim is thus invisible to
/// this family's [`RangeMap::overlapping`] checks rather than clobbering its record.
struct FamilyMaps {
    installed: RangeMap<usize, VmViewId>,
    custody: RangeMap<usize, Custody>,
    /// The oldest [`Custody::Present`] value this family ever held at each address it has since
    /// retired via [`GuestVaDomain::retire_to_owned_hole`] while at least one other, currently
    /// live family's lineage passed through this one (see
    /// [`GuestVaDomain::family_has_live_descendant`]). Populated only there, and consulted only by
    /// [`GuestVaDomain::custody_at_via_lineage`] -- never by this family's own
    /// [`GuestVaDomain::custody_lookup`]-based operations (placement, `claim_hole`,
    /// `publish_present`, `replace_present`, `retire_to_owned_hole` itself), so a live ancestor's
    /// own subsequent claim/install/retire traffic at the same address is never blocked, deferred,
    /// or even observably slowed by a descendant's outstanding, unresolved inheritance there.
    ///
    /// An entry, once set, is never overwritten (the first retirement recorded for a given address
    /// wins) and never proactively reaped -- the same "cheap, process-lifetime metadata" discipline
    /// this module already applies to [`Inner::obligations`]/[`Inner::family_obligation_index`],
    /// bounded by genuine fork and munmap activity rather than a new leak class. Known scope limit:
    /// if the *same* address is retired more than once while *different* live descendant families
    /// each need a *different* one of those generations, every one of them lineage-resolves to the
    /// oldest recorded generation instead of their own -- never to an unrelated family's content,
    /// so this is a content-confusion risk bounded to one family's own real history, not a
    /// disclosure risk.
    retired_lineage_snapshot: RangeMap<usize, Custody>,
}

impl FamilyMaps {
    fn new() -> Self {
        Self {
            installed: RangeMap::new(),
            custody: RangeMap::new(),
            retired_lineage_snapshot: RangeMap::new(),
        }
    }
}

struct Inner {
    families: HashMap<FamilyId, FamilyRecord>,
    views: HashMap<VmViewId, VmView>,
    /// Permanently-blocked spans that apply identically to every family: construction-time
    /// platform reservations and dynamically-discovered [`BlockOrigin::ForeignHost`] spans. The
    /// only state that is genuinely global rather than per-family.
    domain_blocked: RangeMap<usize, BlockOrigin>,
    per_family: HashMap<FamilyId, FamilyMaps>,
    /// Every [`PoisonObligation`] ever captured, by its own identity. Never reaped: an obligation
    /// documents a poison that itself is never auto-cleared (see [`FamilyRecord::poisoned`]).
    obligations: HashMap<FailureId, PoisonObligation>,
    /// Index from family to every obligation recorded against it, in capture order.
    family_obligation_index: HashMap<FamilyId, Vec<FailureId>>,
}

/// The process-global domain of guest virtual addresses.
///
/// See the module documentation for the model this implements. A domain is created once (see
/// [`crate::platform::page_mgmt::PageManagementProvider::guest_va_domain`]) and lives for the
/// life of the process.
pub struct GuestVaDomain {
    id: MemoryDomainId,
    aperture: Range<usize>,
    blocked: Vec<DomainBlocked>,
    inner: Mutex<Inner>,
    /// Count of [`Self::confirm_present_or_reconcile`]/[`Self::confirm_retired_or_reconcile`]
    /// calls that could not make a real effect's mirror authoritative even after a bounded
    /// self-heal retry -- see those methods' docs. Zero across a run means the domain's custody
    /// never silently diverged from reality.
    untracked_present_events: AtomicU64,
}

impl GuestVaDomain {
    /// Creates a new domain over `aperture`, with `blocked` spans inside it that no view may
    /// ever claim.
    ///
    /// # Panics
    ///
    /// Panics if the process has somehow already minted `u64::MAX` [`MemoryDomainId`]s. In
    /// practice this domain is created exactly once per process.
    #[must_use]
    pub fn new(aperture: Range<usize>, blocked: Vec<DomainBlocked>) -> Self {
        let mut domain_blocked = RangeMap::new();
        for b in &blocked {
            domain_blocked.insert(b.0.clone(), BlockOrigin::ConstructionStatic);
        }
        Self {
            id: MemoryDomainId::next().expect("memory domain identity space exhausted"),
            aperture,
            blocked,
            inner: Mutex::new(Inner {
                families: HashMap::new(),
                views: HashMap::new(),
                domain_blocked,
                per_family: HashMap::new(),
                obligations: HashMap::new(),
                family_obligation_index: HashMap::new(),
            }),
            untracked_present_events: AtomicU64::new(0),
        }
    }

    /// This domain's own identity.
    #[must_use]
    pub fn id(&self) -> MemoryDomainId {
        self.id
    }

    /// The full aperture this domain governs.
    #[must_use]
    pub fn aperture(&self) -> Range<usize> {
        self.aperture.clone()
    }

    /// The platform-blocked spans inside [`Self::aperture`] that no view may claim.
    #[must_use]
    pub fn blocked(&self) -> &[DomainBlocked] {
        &self.blocked
    }

    fn validate_range(&self, range: &Range<usize>) -> Result<(), DomainConflict> {
        if range.start >= range.end {
            return Err(DomainConflict::OutsideAperture);
        }
        if range.start < self.aperture.start || range.end > self.aperture.end {
            return Err(DomainConflict::OutsideAperture);
        }
        if self.blocked.iter().any(|b| overlaps(&b.0, range)) {
            return Err(DomainConflict::Blocked);
        }
        Ok(())
    }

    /// Registers a new fork family, returning its identity.
    ///
    /// # Errors
    ///
    /// Returns [`DomainConflict::IdentityExhausted`] if the family identity counter space is
    /// exhausted.
    pub fn register_family(&self) -> Result<FamilyId, DomainConflict> {
        let id = FamilyId::next().ok_or(DomainConflict::IdentityExhausted)?;
        let mut inner = self.inner.lock();
        inner.families.insert(id, FamilyRecord::default());
        inner.per_family.insert(id, FamilyMaps::new());
        Ok(id)
    }

    /// Registers a new fork family exactly like [`Self::register_family`], additionally recording
    /// `parent` as its [`FamilyRecord::parent`] lineage link -- the entry point a fork call site
    /// uses in place of the plain [`Self::register_family`] so a freshly-forked child's family is
    /// never a wholly disconnected identity: [`Self::custody_at_via_lineage`] can walk back to
    /// `parent` (and beyond, transitively) to find the real backing content the child's own,
    /// still-empty family map has never published.
    ///
    /// # Errors
    ///
    /// Returns [`DomainConflict::NotFound`] if `parent` is not itself a registered family, or
    /// [`DomainConflict::IdentityExhausted`] if the family identity counter space is exhausted.
    pub fn register_family_from(&self, parent: FamilyId) -> Result<FamilyId, DomainConflict> {
        let mut inner = self.inner.lock();
        if !inner.families.contains_key(&parent) {
            return Err(DomainConflict::NotFound);
        }
        let id = FamilyId::next().ok_or(DomainConflict::IdentityExhausted)?;
        inner.families.insert(
            id,
            FamilyRecord {
                parent: Some(parent),
                ..FamilyRecord::default()
            },
        );
        inner.per_family.insert(id, FamilyMaps::new());
        Ok(id)
    }

    /// Returns the family `family` was registered from via [`Self::register_family_from`], or
    /// `None` if it has no recorded parent (including if `family` itself is not registered).
    #[must_use]
    pub fn family_parent(&self, family: FamilyId) -> Option<FamilyId> {
        self.inner.lock().families.get(&family).and_then(|r| r.parent)
    }

    /// Registers a new, empty [`VmView`] under `family`, owned by `owner`.
    ///
    /// # Errors
    ///
    /// Returns [`DomainConflict::NotFound`] if `family` is not registered, or
    /// [`DomainConflict::IdentityExhausted`] if the view identity counter space is exhausted.
    pub fn register_view(
        &self,
        family: FamilyId,
        owner: (ProcessInstanceId, TaskInstanceId),
    ) -> Result<VmViewId, DomainConflict> {
        let mut inner = self.inner.lock();
        let record = inner
            .families
            .get_mut(&family)
            .ok_or(DomainConflict::NotFound)?;
        let id = VmViewId::next().ok_or(DomainConflict::IdentityExhausted)?;
        record.members += 1;
        inner.views.insert(
            id,
            VmView {
                family,
                owner,
                overlay: ViewOverlay::Installing,
                topology: RangeMap::new(),
                admission: Arc::new(AtomicU64::new(pack_admission(AdmissionState::Open, 0, 0))),
            },
        );
        Ok(id)
    }

    /// Flips a freshly-[`register_view`](Self::register_view)ed view straight from
    /// [`ViewOverlay::Installing`] to [`ViewOverlay::Active`], without requiring it to have
    /// published any real `Present` span first (unlike [`Self::publish_present`]/
    /// [`Self::install_into_owned_hole`], the only other transitions out of `Installing`).
    ///
    /// For a caller that pins a view to a [`crate::mm::session::MemoryEffectSession`] before real
    /// per-view topology exists for it (`MemoryEffectSession::open` requires `Active`).
    /// A no-op if `view` is already past `Installing`.
    ///
    /// # Errors
    ///
    /// Returns [`DomainConflict::NotFound`] if `view` is not registered.
    pub fn activate_view(&self, view: VmViewId) -> Result<(), DomainConflict> {
        let mut inner = self.inner.lock();
        let entry = inner.views.get_mut(&view).ok_or(DomainConflict::NotFound)?;
        if entry.overlay == ViewOverlay::Installing {
            entry.overlay = ViewOverlay::Active;
        }
        Ok(())
    }

    /// Publishes `range` as a [`SpanKind::Present`] span of `view`, installing it into the
    /// domain's pairwise-disjoint installed set.
    ///
    /// Never defers or blocks: a collision against another view's installed span is refused
    /// immediately as [`DomainConflict::InstalledOverlap`].
    ///
    /// Also stamps `range` as [`Custody::Present`] under a freshly-minted generation, keeping
    /// [`Self::custody_at`]/[`Self::custody_fragments`] in sync with the domain's installed set
    /// and the view's own topology for this range, exactly as the [`Self::claim_hole`]/
    /// [`Self::install_into_owned_hole`] pair already does for a hole-authenticated install.
    /// This one-shot entry point never requires a pre-existing [`Custody::Hole`] the way that
    /// pair does, so it overwrites whatever custody `range` previously carried (bar a
    /// permanently-blocked span, already refused above via [`DomainConflict::Blocked`]) --
    /// callers that need the hole-authenticated protocol's stricter preconditions use that pair
    /// instead.
    ///
    /// # Errors
    ///
    /// See [`DomainConflict`].
    pub fn publish_present(
        &self,
        view: VmViewId,
        range: Range<usize>,
    ) -> Result<MutationId, DomainConflict> {
        self.validate_range(&range)?;
        let mut inner = self.inner.lock();
        let family = inner.views.get(&view).ok_or(DomainConflict::NotFound)?.family;
        if let Some((_, other)) = inner
            .per_family
            .get(&family)
            .expect("a registered view's family always has a FamilyMaps entry")
            .installed
            .overlapping(range.clone())
            .find(|(_, owner)| **owner != view)
        {
            return Err(DomainConflict::InstalledOverlap(*other));
        }
        let mutation = MutationId::next().ok_or(DomainConflict::IdentityExhausted)?;
        let _epoch = EffectEpoch::next().ok_or(DomainConflict::IdentityExhausted)?;
        let generation = HoleGenerationId::next().ok_or(DomainConflict::IdentityExhausted)?;
        let view_entry = inner
            .views
            .get_mut(&view)
            .expect("presence checked above under the same critical section");
        view_entry.topology.insert(range.clone(), SpanKind::Present);
        if view_entry.overlay == ViewOverlay::Installing {
            view_entry.overlay = ViewOverlay::Active;
        }
        let maps = inner
            .per_family
            .get_mut(&family)
            .expect("a registered view's family always has a FamilyMaps entry");
        maps.installed.insert(range.clone(), view);
        maps.custody.insert(range, Custody::Present { generation, view });
        Ok(mutation)
    }

    /// Publishes `range` as a [`SpanKind::Reserved`] span of `view`: purely logical custody that
    /// is never checked against, or entered into, the domain's installed set. Unrelated views may
    /// claim identical guest addresses this way.
    ///
    /// # Errors
    ///
    /// See [`DomainConflict`].
    pub fn publish_reserved(
        &self,
        view: VmViewId,
        range: Range<usize>,
    ) -> Result<MutationId, DomainConflict> {
        self.validate_range(&range)?;
        let mut inner = self.inner.lock();
        let view_entry = inner.views.get_mut(&view).ok_or(DomainConflict::NotFound)?;
        let family = view_entry.family;
        let mutation = MutationId::next().ok_or(DomainConflict::IdentityExhausted)?;
        let _epoch = EffectEpoch::next().ok_or(DomainConflict::IdentityExhausted)?;
        view_entry.topology.insert(range.clone(), SpanKind::Reserved);
        match Self::custody_lookup(&inner, family, &range) {
            Some(Custody::Reserved { views: mut existing }) => {
                if !existing.contains(&view) {
                    existing.push(view);
                }
                if let Some(maps) = inner.per_family.get_mut(&family) {
                    maps.custody.insert(range, Custody::Reserved { views: existing });
                }
            }
            Some(Custody::Unclaimed) | None => {
                if let Some(maps) = inner.per_family.get_mut(&family) {
                    maps.custody
                        .insert(range, Custody::Reserved { views: alloc::vec![view] });
                }
            }
            _ => {
                // Already domain-owned by something else (a hole, an installed present span, a
                // permanent block, or mid-transition): `Reserved` is logical-only custody and
                // never overrides or conflicts with that -- the view's own topology above already
                // recorded the reservation.
            }
        }
        Ok(mutation)
    }

    /// Returns a single uniform [`Custody`] value covering the whole of `range`, or `None` if the
    /// range is unrecorded-and-nonuniform (a mix of recorded entries and implicit gaps) or spans
    /// more than one recorded entry -- callers treat `None` conservatively, never as a specific
    /// state.
    /// Resolves `range`'s custody within `family`'s own map first, falling through to the
    /// genuinely-global `domain_blocked` map only when `family`'s map has no entry there -- the
    /// two are guaranteed disjoint (a range only ever enters `domain_blocked`, never a family map,
    /// once it is permanently blocked), so no merge logic beyond "check one, then the other" is
    /// needed.
    fn custody_lookup(inner: &Inner, family: FamilyId, range: &Range<usize>) -> Option<Custody> {
        if let Some(maps) = inner.per_family.get(&family) {
            let mut entries = maps.custody.overlapping(range.clone());
            if let Some((r, c)) = entries.next() {
                return if r.start <= range.start && r.end >= range.end && entries.next().is_none()
                {
                    Some(c.clone())
                } else {
                    None
                };
            }
        }
        let mut entries = inner.domain_blocked.overlapping(range.clone());
        match entries.next() {
            None => Some(Custody::Unclaimed),
            Some((r, origin)) => {
                if r.start <= range.start && r.end >= range.end && entries.next().is_none() {
                    Some(Custody::DomainBlocked(*origin))
                } else {
                    None
                }
            }
        }
    }

    /// Returns the [`Custody`] state recorded at `addr` within `view`'s own family, or
    /// [`Custody::Unclaimed`] if `view` is not registered or none is recorded there.
    #[must_use]
    pub fn custody_at(&self, view: VmViewId, addr: usize) -> Custody {
        let inner = self.inner.lock();
        let Some(family) = inner.views.get(&view).map(|v| v.family) else {
            return Custody::Unclaimed;
        };
        if let Some(c) = inner
            .per_family
            .get(&family)
            .and_then(|maps| maps.custody.get(&addr).cloned())
        {
            return c;
        }
        inner
            .domain_blocked
            .get(&addr)
            .copied()
            .map(Custody::DomainBlocked)
            .unwrap_or(Custody::Unclaimed)
    }

    /// Returns every recorded [`Custody`] fragment overlapping `range` within `view`'s own family,
    /// plus every genuinely-global `domain_blocked` fragment there, in address order, each clamped
    /// to `range` itself.
    ///
    /// A gap between two returned fragments -- or before the first one, or after the last one --
    /// is implicitly [`Custody::Unclaimed`]; this never synthesizes those entries explicitly, so
    /// an empty return means the whole of `range` is unclaimed (or `view` is not registered).
    /// Callers that need to classify an address-ordered sequence against actor state (munmap's
    /// hole-as-no-op rule, mprotect/madvise's own-Present-only walk, fault classification) build on
    /// this directly.
    #[must_use]
    pub fn custody_fragments(&self, view: VmViewId, range: Range<usize>) -> Vec<(Range<usize>, Custody)> {
        if range.start >= range.end {
            return Vec::new();
        }
        let inner = self.inner.lock();
        let Some(family) = inner.views.get(&view).map(|v| v.family) else {
            return Vec::new();
        };
        let mut fragments: Vec<(Range<usize>, Custody)> = Vec::new();
        if let Some(maps) = inner.per_family.get(&family) {
            fragments.extend(
                maps.custody
                    .overlapping(range.clone())
                    .map(|(r, c)| (r.start.max(range.start)..r.end.min(range.end), c.clone())),
            );
        }
        fragments.extend(
            inner
                .domain_blocked
                .overlapping(range.clone())
                .map(|(r, origin)| {
                    (
                        r.start.max(range.start)..r.end.min(range.end),
                        Custody::DomainBlocked(*origin),
                    )
                }),
        );
        fragments.sort_by_key(|(r, _)| r.start);
        fragments
    }

    /// Returns the [`Custody`] recorded at `addr`, resolved like [`Self::custody_at`] but walking
    /// up the family-lineage chain ([`FamilyRecord::parent`], set by
    /// [`Self::register_family_from`]) when `view`'s own family has nothing recorded there.
    ///
    /// [`Self::custody_at`]/[`Self::custody_fragments`] are strictly per-family by design (see
    /// [`FamilyMaps`]'s own doc comment) -- correct for an ordinary same-family query, but unable
    /// to ever find anything for a freshly-forked child, whose own family map is empty until the
    /// child itself publishes into it. This is the cross-fork-boundary counterpart: it checks
    /// `view`'s own family first (so an already-published entry in the child's own map, e.g. a
    /// span it materialized after a COW split, always wins), then each ancestor family in turn,
    /// stopping at the first non-[`Custody::Unclaimed`] entry -- which, for a
    /// [`Custody::Present`]/[`Custody::Retiring`] hit, directly names the `view` that holds the
    /// real backing content (a fault handler's exact "which view do I alias/copy from" answer).
    /// An explicit [`Custody::Unclaimed`] entry (see [`Self::claim_hole`]'s `ClaimHostError::Other`
    /// rollback) is treated the same as no entry at all -- both continue the walk upward.
    ///
    /// Lineage cannot cycle (a family can only be registered from an already-registered parent, so
    /// parent identities always precede their children's), so this always terminates; falls back
    /// to the genuinely-global `domain_blocked` map, exactly like [`Self::custody_at`], once the
    /// chain is exhausted. Returns [`Custody::Unclaimed`] if `view` is not registered.
    #[must_use]
    pub fn custody_at_via_lineage(&self, view: VmViewId, addr: usize) -> Custody {
        let inner = self.inner.lock();
        let Some(mut family) = inner.views.get(&view).map(|v| v.family) else {
            return Custody::Unclaimed;
        };
        loop {
            let maps = inner.per_family.get(&family);
            // Checked ahead of this hop's own live `custody`: a family's later, real retirement of
            // this exact address (via `retire_to_owned_hole`) must never retroactively invalidate
            // -- nor silently redirect to whatever unrelated content that family may have since
            // installed there instead -- what a live, not-yet-diverged descendant already inherited
            // via lineage at the moment it forked. See `retired_lineage_snapshot`'s own doc comment.
            if let Some(snapshot) = maps.and_then(|m| m.retired_lineage_snapshot.get(&addr).cloned())
            {
                return snapshot;
            }
            let found = maps.and_then(|m| m.custody.get(&addr).cloned());
            if let Some(custody) = found {
                if !matches!(custody, Custody::Unclaimed) {
                    return custody;
                }
            }
            match inner.families.get(&family).and_then(|r| r.parent) {
                Some(parent) => family = parent,
                None => break,
            }
        }
        inner
            .domain_blocked
            .get(&addr)
            .copied()
            .map(Custody::DomainBlocked)
            .unwrap_or(Custody::Unclaimed)
    }

    /// The range form of [`Self::custody_at_via_lineage`]: every recorded fragment of `range`,
    /// in address order, resolved through `view`'s own family first and then each ancestor
    /// family in turn for whatever the nearer families leave unrecorded (a
    /// [`FamilyMaps::retired_lineage_snapshot`] entry outranks the same family's live custody,
    /// an explicit [`Custody::Unclaimed`] entry counts as unrecorded, exactly as there). The
    /// flag says whether the fragment came from an ancestor family, i.e. is held by `view`
    /// only through fork lineage. Gaps between fragments are unrecorded everywhere; a
    /// [`Custody::DomainBlocked`] fragment is reported only where the whole chain has nothing.
    #[must_use]
    pub fn custody_fragments_via_lineage(
        &self,
        view: VmViewId,
        range: Range<usize>,
    ) -> Vec<(Range<usize>, Custody, bool)> {
        if range.start >= range.end {
            return Vec::new();
        }
        let inner = self.inner.lock();
        let Some(mut family) = inner.views.get(&view).map(|v| v.family) else {
            return Vec::new();
        };
        let mut resolved: Vec<(Range<usize>, Custody, bool)> = Vec::new();
        let mut gaps: Vec<Range<usize>> = alloc::vec![range.clone()];
        let mut inherited = false;
        loop {
            let mut next_gaps: Vec<Range<usize>> = Vec::new();
            for gap in gaps {
                let mut found: Vec<(Range<usize>, Custody)> = Vec::new();
                if let Some(maps) = inner.per_family.get(&family) {
                    let snapshots: Vec<(Range<usize>, Custody)> = maps
                        .retired_lineage_snapshot
                        .overlapping(gap.clone())
                        .map(|(r, c)| (r.start.max(gap.start)..r.end.min(gap.end), c.clone()))
                        .collect();
                    for (r, c) in maps.custody.overlapping(gap.clone()) {
                        if matches!(c, Custody::Unclaimed) {
                            continue;
                        }
                        let mut pieces = alloc::vec![r.start.max(gap.start)..r.end.min(gap.end)];
                        for (snapshot, _) in &snapshots {
                            let mut next = Vec::new();
                            for piece in pieces {
                                if piece.start < snapshot.start {
                                    next.push(piece.start..piece.end.min(snapshot.start));
                                }
                                if snapshot.end < piece.end {
                                    next.push(piece.start.max(snapshot.end)..piece.end);
                                }
                            }
                            pieces = next;
                        }
                        found.extend(pieces.into_iter().map(|piece| (piece, c.clone())));
                    }
                    found.extend(snapshots);
                }
                found.sort_by_key(|(r, _)| r.start);
                let mut cursor = gap.start;
                for (r, c) in found {
                    if cursor < r.start {
                        next_gaps.push(cursor..r.start);
                    }
                    cursor = cursor.max(r.end);
                    resolved.push((r, c, inherited));
                }
                if cursor < gap.end {
                    next_gaps.push(cursor..gap.end);
                }
            }
            if next_gaps.is_empty() {
                gaps = next_gaps;
                break;
            }
            match inner.families.get(&family).and_then(|r| r.parent) {
                Some(parent) => {
                    family = parent;
                    gaps = next_gaps;
                    inherited = true;
                }
                None => {
                    gaps = next_gaps;
                    break;
                }
            }
        }
        for gap in gaps {
            resolved.extend(inner.domain_blocked.overlapping(gap.clone()).map(|(r, origin)| {
                (
                    r.start.max(gap.start)..r.end.min(gap.end),
                    Custody::DomainBlocked(*origin),
                    false,
                )
            }));
        }
        resolved.sort_by_key(|(r, _, _)| r.start);
        resolved
    }

    /// Whether any OTHER, currently-live family (`record.members > 0`) has `ancestor` anywhere in
    /// its own [`FamilyRecord::parent`] chain -- i.e., whether `ancestor` has at least one live
    /// descendant that [`Self::custody_at_via_lineage`] could still walk back to. Used only by
    /// [`Self::retire_to_owned_hole`] to decide whether a retirement needs to leave behind a
    /// [`FamilyMaps::retired_lineage_snapshot`] entry; a family with no live descendant at all
    /// costs nothing beyond the `families.len() <= 1` fast-out below.
    ///
    /// `O(families x fork depth)`, matching this module's existing [`Self::foreign_family_present`]
    /// precedent for a cross-family scan -- bounded by genuine fork activity, not the guest's
    /// per-instruction fault rate, since this only ever runs from the munmap-frequency
    /// [`Self::retire_to_owned_hole`], never from a fault-handling path.
    fn family_has_live_descendant(inner: &Inner, ancestor: FamilyId) -> bool {
        if inner.families.len() <= 1 {
            return false;
        }
        for (&candidate, record) in &inner.families {
            if candidate == ancestor || record.members == 0 {
                continue;
            }
            let mut walk = record.parent;
            while let Some(p) = walk {
                if p == ancestor {
                    return true;
                }
                walk = inner.families.get(&p).and_then(|r| r.parent);
            }
        }
        false
    }

    /// Public, read-only sibling of [`Self::family_has_live_descendant`]: whether `view`'s own
    /// family currently has any other, live descendant family. Unlike [`Self::retire_to_owned_hole`]
    /// this never mutates the domain or takes a lineage snapshot -- it exists so a caller below the
    /// domain layer (a platform's own physical unmap) can learn, *before* it tears down a host
    /// resource, whether some live-but-undiverged descendant might still need it aliased in later.
    /// `view` naming a family the domain no longer has registered (already gone) answers `false`,
    /// matching the conservative default of not deferring anything for it.
    pub fn family_has_live_descendant_of(&self, view: VmViewId) -> bool {
        let inner = self.inner.lock();
        match inner.views.get(&view) {
            Some(entry) => Self::family_has_live_descendant(&inner, entry.family),
            None => false,
        }
    }

    /// The [`FamilyId`] `view` is registered under, if it still is. A caller that needs to keep
    /// asking a family-scoped question about `view` across a span of time that outlives `view`
    /// itself in [`Inner::views`] (e.g. a release-on-exit retry loop, which must keep re-checking
    /// a since-[`Self::unregister_view`]-ed candidate on every later retry) captures this once,
    /// up front, and queries by [`FamilyId`] from then on via
    /// [`Self::live_descendant_views_of_family`] instead of repeating this lookup.
    #[must_use]
    pub fn family_of_view(&self, view: VmViewId) -> Option<FamilyId> {
        let inner = self.inner.lock();
        inner.views.get(&view).map(|entry| entry.family)
    }

    /// Every live [`VmViewId`] belonging to a family that currently descends from `ancestor` --
    /// the same family-parent-chain walk [`Self::family_has_live_descendant`] already performs,
    /// generalized to return the actual live view ids of every such descendant family instead of
    /// stopping at the first hit. `ancestor` need not itself still be registered in
    /// [`Inner::views`] (see [`Self::family_of_view`]): only the [`FamilyId`] value is used, to
    /// match against other live families' own [`FamilyRecord::parent`] chains, so a caller may
    /// resolve it once, before `ancestor`'s own view is unregistered, and query repeatedly after.
    ///
    /// `O(families x fork depth)`, matching [`Self::family_has_live_descendant`]'s own precedent
    /// -- intended for the same kind of rare, teardown-time caller (an address-space release
    /// retry loop), never a fault-handling path.
    #[must_use]
    pub fn live_descendant_views_of_family(&self, ancestor: FamilyId) -> Vec<VmViewId> {
        let inner = self.inner.lock();
        if inner.families.len() <= 1 {
            return Vec::new();
        }
        let mut result = Vec::new();
        for (&candidate, record) in &inner.families {
            if candidate == ancestor || record.members == 0 {
                continue;
            }
            let mut walk = record.parent;
            let mut is_descendant = false;
            while let Some(p) = walk {
                if p == ancestor {
                    is_descendant = true;
                    break;
                }
                walk = inner.families.get(&p).and_then(|r| r.parent);
            }
            if is_descendant {
                result.extend(
                    inner
                        .views
                        .iter()
                        .filter(|(_, entry)| entry.family == candidate)
                        .map(|(&id, _)| id),
                );
            }
        }
        result
    }

    /// Marks `view`'s family as having `execve`d: see [`FamilyRecord::exec_severed`]. A no-op
    /// for an unregistered view.
    pub fn mark_family_exec(&self, view: VmViewId) {
        let mut inner = self.inner.lock();
        let Some(family) = inner.views.get(&view).map(|v| v.family) else {
            return;
        };
        if let Some(record) = inner.families.get_mut(&family) {
            record.exec_severed = true;
        }
    }

    /// Like [`Self::family_has_live_descendant_of`], but counts only a live descendant that
    /// still inherits `view`'s family's own pages by lineage: one that has not itself
    /// [`FamilyRecord::exec_severed`]. A descendant that has exec'd runs its own image. An
    /// exec'd family in the MIDDLE of the chain does not sever what lies below it: a grandchild
    /// forked before that middle family exec'd inherits the pre-exec image, i.e. this family's
    /// pages, and [`Self::custody_at_via_lineage`] walks straight through the middle family to
    /// find them -- so the platform's physical retention (`keep_mirror_for_descendant`) and the
    /// logical `VmArea` retention gated on this must keep them too (observed live: a
    /// pre-exec grandchild's host-side write to such a page found it already retired,
    /// `install_cow_read_alias` answering `RangeUnmapped`, once the walk stopped at the severed
    /// middle family). `false` for an unregistered view.
    pub fn family_has_live_inheriting_descendant_of(&self, view: VmViewId) -> bool {
        let inner = self.inner.lock();
        let Some(ancestor) = inner.views.get(&view).map(|v| v.family) else {
            return false;
        };
        Self::family_has_live_inheriting_descendant_inner(&inner, ancestor)
    }

    /// [`Self::family_has_live_inheriting_descendant_of`] keyed by the [`FamilyId`] itself, for a
    /// caller that captured it before the view was unregistered (see [`Self::family_of_view`]) --
    /// a platform's deferred address-space release deciding whether the fork-COW state it kept
    /// for that family's descendants can still be resolved by any of them.
    #[must_use]
    pub fn family_has_live_inheriting_descendant(&self, ancestor: FamilyId) -> bool {
        let inner = self.inner.lock();
        Self::family_has_live_inheriting_descendant_inner(&inner, ancestor)
    }

    fn family_has_live_inheriting_descendant_inner(inner: &Inner, ancestor: FamilyId) -> bool {
        for (&candidate, record) in &inner.families {
            if candidate == ancestor || record.members == 0 || record.exec_severed {
                continue;
            }
            let mut walk = record.parent;
            while let Some(parent) = walk {
                if parent == ancestor {
                    return true;
                }
                walk = inner.families.get(&parent).and_then(|r| r.parent);
            }
        }
        false
    }

    /// Records `custody` as `family`'s [`FamilyMaps::retired_lineage_snapshot`] for every part of
    /// `range` not already covered by an earlier snapshot there -- an existing snapshot fragment is
    /// never overwritten (see that field's own doc comment on why the oldest recorded generation
    /// must win), so this only ever fills the gaps.
    fn capture_lineage_snapshot(
        inner: &mut Inner,
        family: FamilyId,
        range: Range<usize>,
        custody: Custody,
    ) {
        let Some(maps) = inner.per_family.get_mut(&family) else {
            return;
        };
        let mut cursor = range.start;
        let mut gaps: Vec<Range<usize>> = Vec::new();
        let mut covered: Vec<Range<usize>> = maps
            .retired_lineage_snapshot
            .overlapping(range.clone())
            .map(|(r, _)| r.start.max(range.start)..r.end.min(range.end))
            .collect();
        covered.sort_by_key(|r| r.start);
        for fragment in covered {
            if cursor < fragment.start {
                gaps.push(cursor..fragment.start);
            }
            cursor = cursor.max(fragment.end);
        }
        if cursor < range.end {
            gaps.push(cursor..range.end);
        }
        for gap in gaps {
            maps.retired_lineage_snapshot.insert(gap, custody.clone());
        }
    }

    /// The authoritative entry point behind a real mapping-family effect's mirror into this
    /// domain: [`Self::publish_present`] with one bounded self-heal retry, instead of the
    /// caller silently tolerating any [`DomainConflict`] forever.
    ///
    /// On [`DomainConflict::InstalledOverlap`] -- the one conflict category a stale fragment left
    /// behind by an earlier, un-mirrored effect can actually cause -- every fragment of `range`
    /// that is `Present` for some *other* view within the same family is retired back to a hole
    /// via [`Self::retire_to_owned_hole`] (a purely in-domain reconciliation of stale
    /// bookkeeping, `host_reset` is a no-op: no real host mapping is touched), and
    /// [`Self::publish_present`] is retried exactly once.
    ///
    /// Any conflict that survives the retry (or was never `InstalledOverlap` to begin with, e.g.
    /// [`DomainConflict::NotFound`] from a genuine teardown race) is recorded via
    /// [`Self::untracked_present_events`] and logged at `error!`, then returned -- this never
    /// panics and never invents a mapping; a caller mirroring a real effect that already
    /// succeeded still simply logs and moves on, exactly as before.
    ///
    /// # Errors
    ///
    /// See [`DomainConflict`].
    pub fn confirm_present_or_reconcile(
        &self,
        view: VmViewId,
        range: Range<usize>,
    ) -> Result<MutationId, DomainConflict> {
        let first = self.publish_present(view, range.clone());
        let Err(DomainConflict::InstalledOverlap(_)) = first else {
            if let Err(error) = first {
                self.record_untracked_present_event("confirm_present_or_reconcile", view, &range, error);
            }
            return first;
        };
        for (fragment, custody) in self.custody_fragments(view, range.clone()) {
            if let Custody::Present { view: stale, .. } = custody {
                if stale != view {
                    let _ = self.retire_to_owned_hole(stale, fragment, |_| Ok(()));
                }
            }
        }
        let retried = self.publish_present(view, range.clone());
        if let Err(error) = retried {
            self.record_untracked_present_event("confirm_present_or_reconcile", view, &range, error);
        }
        retried
    }

    /// The retirement twin of [`Self::confirm_present_or_reconcile`]: reconciles every fragment of
    /// `range` that is genuinely still `Present` for `view` itself, retiring it via
    /// [`Self::retire_to_owned_hole`] (`host_reset` a no-op) with one bounded self-heal retry
    /// against a benign race (another caller having already retired the fragment between the
    /// initial [`Self::custody_fragments`] read and this call).
    ///
    /// A fragment that is not `view`'s own `Present` span (already retired, or never mirrored) is
    /// left untouched -- there is nothing stale to reconcile there. Any fragment still `Present`
    /// for `view` after the retry is recorded via [`Self::untracked_present_events`] and logged at
    /// `error!`; this never affects the caller's real unmap.
    pub fn confirm_retired_or_reconcile(&self, view: VmViewId, range: Range<usize>) {
        for (fragment, custody) in self.custody_fragments(view, range.clone()) {
            if !matches!(&custody, Custody::Present { view: v, .. } if *v == view) {
                continue;
            }
            if self
                .retire_to_owned_hole(view, fragment.clone(), |_| Ok(()))
                .is_ok()
            {
                continue;
            }
            let still_present =
                matches!(self.custody_at(view, fragment.start), Custody::Present { view: v, .. } if v == view);
            if !still_present {
                continue;
            }
            if let Err(error) = self.retire_to_owned_hole(view, fragment.clone(), |_| Ok(())) {
                self.record_untracked_present_event(
                    "confirm_retired_or_reconcile",
                    view,
                    &fragment,
                    error,
                );
            }
        }
    }

    fn record_untracked_present_event(
        &self,
        site: &'static str,
        view: VmViewId,
        range: &Range<usize>,
        error: DomainConflict,
    ) {
        self.untracked_present_events.fetch_add(1, Ordering::Relaxed);
        litebox_util_log::error!(
            site = site, view:? = view, start:? = range.start, end:? = range.end, error:? = error;
            "domain custody could not be made authoritative for a real memory effect even after a bounded self-heal retry -- untracked-but-legitimate range"
        );
    }

    /// Total count of unrecoverable conflicts recorded by [`Self::confirm_present_or_reconcile`]/
    /// [`Self::confirm_retired_or_reconcile`] since this domain was created. Zero across a run
    /// means every real mapping-family effect that path mirrored was successfully made
    /// authoritative in the domain (after at most one self-heal retry).
    #[must_use]
    pub fn untracked_present_events(&self) -> u64 {
        self.untracked_present_events.load(Ordering::Relaxed)
    }

    /// Resolves a real placement for a fresh, non-`FIXED_ADDR` allocation of `len` bytes inside
    /// `view`'s own family, combining the real `Vmem` topology with this domain's own
    /// family-scoped custody so a family-only reservation (e.g. a logical `Reserved` span, or a
    /// domain hole) that the real `Vmem` has no notion of can never be silently double-claimed.
    ///
    /// `search` is invoked with the domain lock released -- it is the caller's own real
    /// free-VA-range search (mirroring [`Self::claim_hole`]'s "run for real, then re-lock to
    /// validate" shape), called with the current hint and returning one candidate start address,
    /// or `None` when the real address space itself has no candidate left. On a family-level
    /// conflict at a returned candidate, the search is retried with a hint advanced past the
    /// conflicting span, bounded by a small retry count.
    ///
    /// Never publishes anything -- this is a pure placement query, symmetric with `Vmem`'s own
    /// unhinted search; callers still call [`Self::publish_present`]/[`Self::claim_hole`]
    /// afterward to actually claim the returned range.
    ///
    /// # Errors
    ///
    /// Returns [`DomainConflict::NotFound`] if `view` is not registered, or
    /// [`DomainConflict::Occupied`] if `search` returns `None` or the retry bound is exhausted
    /// before a family-unclaimed candidate is found.
    pub fn place(
        &self,
        view: VmViewId,
        len: usize,
        hint: Option<usize>,
        mut search: impl FnMut(Option<usize>) -> Option<usize>,
    ) -> Result<Range<usize>, DomainConflict> {
        const MAX_ATTEMPTS: usize = 8;
        let family = {
            let inner = self.inner.lock();
            inner.views.get(&view).ok_or(DomainConflict::NotFound)?.family
        };
        let mut current_hint = hint;
        for _ in 0..MAX_ATTEMPTS {
            let Some(start) = search(current_hint) else {
                return Err(DomainConflict::Occupied);
            };
            let candidate = start..start + len;
            let inner = self.inner.lock();
            if matches!(
                Self::custody_lookup(&inner, family, &candidate),
                Some(Custody::Unclaimed)
            ) {
                return Ok(candidate);
            }
            // Occupied (by this family) or ambiguous (`None`, a mix of recorded entries and
            // gaps): steer the next `search` call away from every conflicting fragment this
            // family or the genuinely-global blocked map has recorded overlapping `candidate`.
            //
            // `search` (`Vmem::find_unmapped_area`/`get_unmmaped_area`, the only real caller)
            // is a TOP-DOWN allocator: a non-`None` hint is a *ceiling* ("stay at or below
            // this"), not a floor -- it biases the search toward the highest gap whose start is
            // <= the hint, exactly the semantic V8's own descending-hint CodeRange retries rely
            // on. Advancing the hint *upward* past the conflict's far end (as a bottom-up
            // allocator's retry would) does not exclude the conflict from a ceiling-bounded
            // search at all: the new ceiling still sits at or above the conflicting fragment, so
            // the very next top-down search can re-derive the exact same highest-gap candidate
            // (or another one that still overlaps the same fragment), and a family with any
            // sizeable contiguous custody span can exhaust every one of `MAX_ATTEMPTS` bouncing
            // within that one span instead of ever reaching genuinely `Unclaimed` territory
            // below it -- observed live as a multi-hundred-Hz burst of `create_pages` calls
            // during real npm startup, `domain.place` declining as `Occupied` on nearly every
            // call for the whole burst (a real, if partial, contributor to a since-separately-
            // tracked total stall that follows; this fix measurably raises `place`'s own success
            // rate but does not by itself eliminate that stall).
            //
            // The correct advancement for this ceiling-biased search lowers the ceiling to just
            // below the *lowest* start among the fragments that overlapped `candidate`, minus
            // `len` so a full `len`-byte candidate anchored at the new ceiling cannot itself
            // reach back up into the conflict -- guaranteeing each of the remaining attempts
            // probes strictly lower, previously-unexamined territory instead of the same span.
            let conflict_start = inner
                .per_family
                .get(&family)
                .into_iter()
                .flat_map(|maps| maps.custody.overlapping(candidate.clone()).map(|(r, _)| r.start))
                .chain(
                    inner
                        .domain_blocked
                        .overlapping(candidate.clone())
                        .map(|(r, _)| r.start),
                )
                .min()
                .unwrap_or(candidate.start);
            drop(inner);
            let next_ceiling = conflict_start.saturating_sub(len);
            if next_ceiling >= start {
                // No real progress would result (e.g. `len == 0` is unreachable in practice, but
                // never spin in place regardless) -- fail closed rather than risk a same-spot
                // repeat.
                return Err(DomainConflict::Occupied);
            }
            current_hint = Some(next_ceiling);
        }
        Err(DomainConflict::Occupied)
    }

    /// Claims `range` as a domain-owned hole: a guest-virtual-address span reserved from the host
    /// but not yet backing any view. `host_reserve` runs with the domain lock released -- it is
    /// the caller's actual host reservation syscall (e.g. a `PROT_NONE` placeholder mapping).
    ///
    /// On [`ClaimHostError::ForeignHost`], `range` is permanently marked
    /// [`Custody::DomainBlocked`] so a caller's placement search never re-probes it; the search
    /// itself should simply continue elsewhere. On [`ClaimHostError::Other`], `range` rolls back
    /// to [`Custody::Unclaimed`] and may be retried.
    ///
    /// # Errors
    ///
    /// See [`DomainConflict`].
    pub fn claim_hole(
        &self,
        view: VmViewId,
        range: Range<usize>,
        host_reserve: impl FnOnce(Range<usize>) -> Result<(), ClaimHostError>,
    ) -> Result<HoleToken, DomainConflict> {
        self.validate_range(&range)?;
        let generation = HoleGenerationId::next().ok_or(DomainConflict::IdentityExhausted)?;
        let family = {
            let mut inner = self.inner.lock();
            let family = inner.views.get(&view).ok_or(DomainConflict::NotFound)?.family;
            match Self::custody_lookup(&inner, family, &range) {
                Some(Custody::Unclaimed) => {}
                Some(Custody::DomainBlocked(_)) => return Err(DomainConflict::Blocked),
                _ => return Err(DomainConflict::Occupied),
            }
            inner
                .per_family
                .get_mut(&family)
                .expect("a registered view's family always has a FamilyMaps entry")
                .custody
                .insert(range.clone(), Custody::Installing { generation });
            family
        };
        match host_reserve(range.clone()) {
            Ok(()) => {
                let mut inner = self.inner.lock();
                if let Some(maps) = inner.per_family.get_mut(&family) {
                    maps.custody.insert(range.clone(), Custody::Hole { generation });
                }
                Ok(HoleToken { range, generation, family })
            }
            Err(ClaimHostError::ForeignHost) => {
                let mut inner = self.inner.lock();
                if let Some(maps) = inner.per_family.get_mut(&family) {
                    maps.custody.remove(range.clone());
                }
                inner
                    .domain_blocked
                    .insert(range, BlockOrigin::ForeignHost);
                Err(DomainConflict::Blocked)
            }
            Err(ClaimHostError::Other) => {
                let mut inner = self.inner.lock();
                if let Some(maps) = inner.per_family.get_mut(&family) {
                    maps.custody.insert(range, Custody::Unclaimed);
                }
                Err(DomainConflict::Occupied)
            }
        }
    }

    /// Installs `view`'s `Present` span over the hole authenticated by `token`, consuming it.
    /// `install` runs with the domain lock released -- the caller's actual host mapping syscall.
    ///
    /// A stale token (the range has since moved past the generation it names) is rejected as
    /// [`DomainConflict::NotFound`] rather than silently mutating a range the caller no longer
    /// owns. On `install` failure, the range rolls back to [`Custody::Hole`] under its original
    /// generation -- a domain hole is never destroyed by a failed install.
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
        let range = token.range.clone();
        let (mutation, fresh_gen) = {
            let mut inner = self.inner.lock();
            let view_family = inner.views.get(&view).ok_or(DomainConflict::NotFound)?.family;
            if view_family != token.family {
                return Err(DomainConflict::NotFound);
            }
            match Self::custody_lookup(&inner, token.family, &range) {
                Some(Custody::Hole { generation }) if generation == token.generation => {}
                _ => return Err(DomainConflict::NotFound),
            }
            if let Some((_, other)) = inner
                .per_family
                .get(&token.family)
                .expect("a registered view's family always has a FamilyMaps entry")
                .installed
                .overlapping(range.clone())
                .find(|(_, owner)| **owner != view)
            {
                return Err(DomainConflict::InstalledOverlap(*other));
            }
            let mutation = MutationId::next().ok_or(DomainConflict::IdentityExhausted)?;
            let fresh_gen = HoleGenerationId::next().ok_or(DomainConflict::IdentityExhausted)?;
            inner
                .per_family
                .get_mut(&token.family)
                .expect("a registered view's family always has a FamilyMaps entry")
                .custody
                .insert(range.clone(), Custody::Installing { generation: token.generation });
            (mutation, fresh_gen)
        };
        match install(range.clone()) {
            Ok(()) => {
                let mut inner = self.inner.lock();
                if let Some(maps) = inner.per_family.get_mut(&token.family) {
                    maps.installed.insert(range.clone(), view);
                    maps.custody
                        .insert(range.clone(), Custody::Present { generation: fresh_gen, view });
                }
                if let Some(view_entry) = inner.views.get_mut(&view) {
                    view_entry.topology.insert(range, SpanKind::Present);
                    if view_entry.overlay == ViewOverlay::Installing {
                        view_entry.overlay = ViewOverlay::Active;
                    }
                }
                Ok(mutation)
            }
            Err(()) => {
                let mut inner = self.inner.lock();
                if let Some(maps) = inner.per_family.get_mut(&token.family) {
                    maps.custody
                        .insert(range, Custody::Hole { generation: token.generation });
                }
                Err(DomainConflict::Occupied)
            }
        }
    }

    /// Re-mutates `view`'s own already-installed `Present` span at `range` in place (e.g.
    /// re-`mmap` with new protection at the same address). Only legal when `range` is currently
    /// `Present` for `view` itself; refuses with [`DomainConflict::Occupied`] if any other view
    /// is `Present`/`Reserved` there -- this is never a synchronous switch of ownership.
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
        self.validate_range(&range)?;
        // `fresh_gen` -- the successor state this operation will commit on success -- is minted
        // here, in the locked pre-effect section, alongside the `Installing` marker itself: any
        // identity-exhaustion failure surfaces before `replace` ever runs, so the post-effect
        // commit below is a plain insert at the exact range `Installing` already claimed, never a
        // fallible step that could strand a successfully-replaced host mapping behind an error.
        let (mutation, old_gen, fresh_gen, family) = {
            let mut inner = self.inner.lock();
            let family = inner.views.get(&view).ok_or(DomainConflict::NotFound)?.family;
            if let Some((_, other)) = inner
                .per_family
                .get(&family)
                .expect("a registered view's family always has a FamilyMaps entry")
                .installed
                .overlapping(range.clone())
                .find(|(_, owner)| **owner != view)
            {
                return Err(DomainConflict::InstalledOverlap(*other));
            }
            let old_gen = match Self::custody_lookup(&inner, family, &range) {
                Some(Custody::Present { generation, view: v }) if v == view => generation,
                _ => return Err(DomainConflict::Occupied),
            };
            let mutation = MutationId::next().ok_or(DomainConflict::IdentityExhausted)?;
            let fresh_gen = HoleGenerationId::next().ok_or(DomainConflict::IdentityExhausted)?;
            inner
                .per_family
                .get_mut(&family)
                .expect("a registered view's family always has a FamilyMaps entry")
                .custody
                .insert(range.clone(), Custody::Installing { generation: old_gen });
            (mutation, old_gen, fresh_gen, family)
        };
        match replace(range.clone()) {
            Ok(()) => {
                let mut inner = self.inner.lock();
                if let Some(maps) = inner.per_family.get_mut(&family) {
                    maps.custody
                        .insert(range.clone(), Custody::Present { generation: fresh_gen, view });
                }
                if let Some(view_entry) = inner.views.get_mut(&view) {
                    view_entry.topology.insert(range, SpanKind::Present);
                }
                Ok(mutation)
            }
            Err(()) => {
                let mut inner = self.inner.lock();
                if let Some(maps) = inner.per_family.get_mut(&family) {
                    maps.custody
                        .insert(range, Custody::Present { generation: old_gen, view });
                }
                Err(DomainConflict::Occupied)
            }
        }
    }

    /// Retires `view`'s `Present` span at `range` back to a domain-owned hole (the `munmap`
    /// path). `host_reset` runs with the domain lock released -- the caller's actual host
    /// unmap/re-arm syscall. Unlike [`Self::release_hole`], the range is never returned to
    /// [`Custody::Unclaimed`] here: a domain hole is never destroyed by `munmap`.
    ///
    /// On success, if [`Self::family_has_live_descendant`] finds some other, currently live family
    /// descended from `view`'s own, the pre-retirement `Custody::Present { generation: old_gen,
    /// view }` this range just held is preserved in that family's own
    /// [`FamilyMaps::retired_lineage_snapshot`] before this family's own live `custody` moves on to
    /// `Hole` -- this family's own subsequent placement/claim/install/retire traffic at `range`
    /// (including reusing it for a brand new mapping right away) is entirely unaffected, since that
    /// traffic only ever consults the live `custody` map, never the snapshot; only a *descendant*
    /// resolving `range` via [`Self::custody_at_via_lineage`] ever sees it.
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
        self.validate_range(&range)?;
        let (old_gen, fresh_gen, family) = {
            let mut inner = self.inner.lock();
            let family = inner.views.get(&view).ok_or(DomainConflict::NotFound)?.family;
            let old_gen = match Self::custody_lookup(&inner, family, &range) {
                Some(Custody::Present { generation, view: v }) if v == view => generation,
                _ => return Err(DomainConflict::Occupied),
            };
            let fresh_gen = HoleGenerationId::next().ok_or(DomainConflict::IdentityExhausted)?;
            if let Some(maps) = inner.per_family.get_mut(&family) {
                maps.custody
                    .insert(range.clone(), Custody::Retiring { generation: old_gen, view });
            }
            (old_gen, fresh_gen, family)
        };
        match host_reset(range.clone()) {
            Ok(()) => {
                let mut inner = self.inner.lock();
                if Self::family_has_live_descendant(&inner, family) {
                    Self::capture_lineage_snapshot(
                        &mut inner,
                        family,
                        range.clone(),
                        Custody::Present { generation: old_gen, view },
                    );
                }
                if let Some(maps) = inner.per_family.get_mut(&family) {
                    maps.installed.remove(range.clone());
                    maps.custody
                        .insert(range.clone(), Custody::Hole { generation: fresh_gen });
                }
                if let Some(view_entry) = inner.views.get_mut(&view) {
                    view_entry.topology.remove(range.clone());
                }
                Ok(HoleToken { range, generation: fresh_gen, family })
            }
            Err(()) => {
                let mut inner = self.inner.lock();
                if let Some(maps) = inner.per_family.get_mut(&family) {
                    maps.custody
                        .insert(range, Custody::Present { generation: old_gen, view });
                }
                Err(DomainConflict::Occupied)
            }
        }
    }

    /// Releases a domain-owned hole back to [`Custody::Unclaimed`], consuming `token`.
    /// `host_release` runs with the domain lock released -- the caller's actual host-release
    /// syscall. Used for genuine rollback/cleanup; ordinary `munmap` uses
    /// [`Self::retire_to_owned_hole`] instead, which never reaches `Unclaimed`.
    ///
    /// # Errors
    ///
    /// See [`DomainConflict`].
    pub fn release_hole(
        &self,
        token: HoleToken,
        host_release: impl FnOnce(Range<usize>) -> Result<(), ()>,
    ) -> Result<(), DomainConflict> {
        let range = token.range.clone();
        {
            let mut inner = self.inner.lock();
            match Self::custody_lookup(&inner, token.family, &range) {
                Some(Custody::Hole { generation }) if generation == token.generation => {}
                _ => return Err(DomainConflict::NotFound),
            }
            if let Some(maps) = inner.per_family.get_mut(&token.family) {
                maps.custody
                    .insert(range.clone(), Custody::Installing { generation: token.generation });
            }
        }
        match host_release(range.clone()) {
            Ok(()) => {
                let mut inner = self.inner.lock();
                if let Some(maps) = inner.per_family.get_mut(&token.family) {
                    maps.custody.remove(range);
                }
                Ok(())
            }
            Err(()) => {
                let mut inner = self.inner.lock();
                if let Some(maps) = inner.per_family.get_mut(&token.family) {
                    maps.custody
                        .insert(range, Custody::Hole { generation: token.generation });
                }
                Err(DomainConflict::Occupied)
            }
        }
    }

    /// Removes every `Present` span `view` currently has in the domain's installed set, freeing
    /// those addresses for another view to install, and marks `view` as [`ViewOverlay::Retiring`].
    ///
    /// The view's identity and logical topology are unaffected; use [`Self::unregister_view`] to
    /// remove those.
    ///
    /// # Errors
    ///
    /// Returns [`DomainConflict::NotFound`] if `view` is not registered.
    pub fn retire_view(&self, view: VmViewId) -> Result<(), DomainConflict> {
        let mut inner = self.inner.lock();
        let family = inner.views.get(&view).ok_or(DomainConflict::NotFound)?.family;
        if let Some(maps) = inner.per_family.get_mut(&family) {
            let owned: Vec<Range<usize>> = maps
                .installed
                .iter()
                .filter(|(_, owner)| **owner == view)
                .map(|(r, _)| r.clone())
                .collect();
            for r in owned {
                maps.installed.remove(r);
            }
        }
        inner
            .views
            .get_mut(&view)
            .expect("presence checked above under the same critical section")
            .overlay = ViewOverlay::Retiring;
        Ok(())
    }

    /// Marks `family` poisoned. The family record survives regardless of member count once
    /// poisoned; see [`FamilyRecord`].
    ///
    /// # Errors
    ///
    /// Returns [`DomainConflict::NotFound`] if `family` is not registered.
    pub fn mark_poison(&self, family: FamilyId) -> Result<(), DomainConflict> {
        let mut inner = self.inner.lock();
        let record = inner
            .families
            .get_mut(&family)
            .ok_or(DomainConflict::NotFound)?;
        record.poisoned = true;
        for view in inner.views.values_mut().filter(|v| v.family == family) {
            view.overlay = ViewOverlay::Poisoned;
        }
        Ok(())
    }

    /// Marks `family` quarantined. The family record survives regardless of member count once
    /// quarantined; see [`FamilyRecord`].
    ///
    /// # Errors
    ///
    /// Returns [`DomainConflict::NotFound`] if `family` is not registered.
    pub fn mark_quarantine(&self, family: FamilyId) -> Result<(), DomainConflict> {
        let mut inner = self.inner.lock();
        let record = inner
            .families
            .get_mut(&family)
            .ok_or(DomainConflict::NotFound)?;
        record.quarantined = true;
        for view in inner.views.values_mut().filter(|v| v.family == family) {
            view.overlay = ViewOverlay::Quarantined;
        }
        Ok(())
    }

    /// Marks `family` poisoned exactly like [`Self::mark_poison`], additionally storing
    /// `obligation` (whose own [`PoisonObligation::failure`] identity is returned) so a future
    /// repair/diagnostic pass has a durable record of what was in flight at poison time.
    ///
    /// # Errors
    ///
    /// Returns [`DomainConflict::NotFound`] if `family` is not registered.
    pub fn mark_poison_with_obligation(
        &self,
        obligation: PoisonObligation,
    ) -> Result<FailureId, DomainConflict> {
        let family = obligation.family;
        let failure = obligation.failure;
        let mut inner = self.inner.lock();
        let record = inner
            .families
            .get_mut(&family)
            .ok_or(DomainConflict::NotFound)?;
        record.poisoned = true;
        for view in inner.views.values_mut().filter(|v| v.family == family) {
            view.overlay = ViewOverlay::Poisoned;
        }
        inner
            .family_obligation_index
            .entry(family)
            .or_default()
            .push(failure);
        inner.obligations.insert(failure, obligation);
        Ok(failure)
    }

    /// Marks every registered family in the domain poisoned, storing `obligation` the same way as
    /// [`Self::mark_poison_with_obligation`] but scoped [`TerminalScope::HvfProviderGlobal`].
    ///
    /// Reserved for a future process-wide HVF-provider terminal condition; nothing in this tree
    /// calls it yet.
    pub fn mark_process_global_terminal(&self, obligation: PoisonObligation) -> FailureId {
        let failure = obligation.failure;
        let mut inner = self.inner.lock();
        for record in inner.families.values_mut() {
            record.poisoned = true;
        }
        for view in inner.views.values_mut() {
            view.overlay = ViewOverlay::Poisoned;
        }
        let families: Vec<FamilyId> = inner.families.keys().copied().collect();
        for family in families {
            inner
                .family_obligation_index
                .entry(family)
                .or_default()
                .push(failure);
        }
        inner.obligations.insert(failure, obligation);
        failure
    }

    /// Reads the [`PoisonObligation`] recorded under `id`, if any, via `read` (never handed out
    /// by value/reference beyond the call since [`PoisonObligation`] is deliberately not
    /// [`Clone`]).
    pub fn query_obligation<R>(
        &self,
        id: FailureId,
        read: impl FnOnce(&PoisonObligation) -> R,
    ) -> Option<R> {
        let inner = self.inner.lock();
        inner.obligations.get(&id).map(read)
    }

    /// Reads every [`PoisonObligation`] recorded against `family`, in capture order, via `read`.
    pub fn family_obligations<R>(
        &self,
        family: FamilyId,
        read: impl Fn(&PoisonObligation) -> R,
    ) -> Vec<R> {
        let inner = self.inner.lock();
        inner
            .family_obligation_index
            .get(&family)
            .into_iter()
            .flat_map(|ids| ids.iter())
            .filter_map(|id| inner.obligations.get(id).map(&read))
            .collect()
    }

    /// Removes `view` entirely: any installed spans it still holds are freed, its logical
    /// topology is dropped, and its owning family's member count is decremented. The family
    /// record itself is never removed here -- see [`FamilyRecord`].
    ///
    /// # Errors
    ///
    /// Returns [`DomainConflict::NotFound`] if `view` is not registered.
    pub fn unregister_view(&self, view: VmViewId) -> Result<(), DomainConflict> {
        let mut inner = self.inner.lock();
        let entry = inner.views.remove(&view).ok_or(DomainConflict::NotFound)?;
        if let Some(maps) = inner.per_family.get_mut(&entry.family) {
            let owned: Vec<Range<usize>> = maps
                .installed
                .iter()
                .filter(|(_, owner)| **owner == view)
                .map(|(r, _)| r.clone())
                .collect();
            for r in owned {
                maps.installed.remove(r);
            }
        }
        if let Some(record) = inner.families.get_mut(&entry.family) {
            record.members = record.members.saturating_sub(1);
        }
        Ok(())
    }

    /// Returns whether any OTHER, currently-live fork family holds genuine `Present`/`Retiring`
    /// custody anywhere in `range` -- the cross-family primitive [`Self::custody_fragments`]/
    /// [`Self::custody_at`] structurally cannot provide, since both resolve the caller's own
    /// family first and only ever consult that family's own maps (see the module's
    /// family-scoping, [`FamilyMaps`]).
    ///
    /// Resolves `view`'s own family first, returning `false` (matching [`Self::custody_fragments`]'s
    /// existing conservative behavior) if `view` is not registered. A family whose member count
    /// has dropped to zero is excluded even if stale custody fragments remain in its map --
    /// neither [`Self::retire_view`] nor [`Self::unregister_view`] clears a family's `custody`
    /// map, only its `installed` set, so a fully-exited family can otherwise leave behind a
    /// `Present`/`Retiring` fragment that no longer belongs to any live process; only a
    /// genuinely live foreign family's fragment counts as a hit here. A zero-length `range` is
    /// never a hit.
    ///
    /// Purely additive and read-only: takes the same short critical section as every other query
    /// method here, never a provider callback, and changes no state.
    #[must_use]
    pub fn foreign_family_present(&self, view: VmViewId, range: Range<usize>) -> bool {
        if range.start >= range.end {
            return false;
        }
        let inner = self.inner.lock();
        let Some(self_family) = inner.views.get(&view).map(|v| v.family) else {
            return false;
        };
        for (family, maps) in &inner.per_family {
            if *family == self_family {
                continue;
            }
            let live = inner.families.get(family).is_some_and(|record| record.members > 0);
            if !live {
                continue;
            }
            if maps
                .custody
                .overlapping(range.clone())
                .any(|(_, c)| matches!(c, Custody::Present { .. } | Custody::Retiring { .. }))
            {
                return true;
            }
        }
        false
    }

    /// The fragment form of [`Self::foreign_family_present`]: every sub-range of `range` over
    /// which some OTHER, currently-live family holds `Present`/`Retiring` custody, clamped to
    /// `range`, merged across families and adjacent fragments, in address order. Empty when
    /// `view` is not registered or nothing foreign is held there.
    #[must_use]
    pub fn foreign_family_present_fragments(
        &self,
        view: VmViewId,
        range: Range<usize>,
    ) -> Vec<Range<usize>> {
        if range.start >= range.end {
            return Vec::new();
        }
        let inner = self.inner.lock();
        let Some(self_family) = inner.views.get(&view).map(|v| v.family) else {
            return Vec::new();
        };
        let mut held: Vec<Range<usize>> = Vec::new();
        for (family, maps) in &inner.per_family {
            if *family == self_family
                || !inner.families.get(family).is_some_and(|record| record.members > 0)
            {
                continue;
            }
            held.extend(
                maps.custody
                    .overlapping(range.clone())
                    .filter(|(_, c)| matches!(c, Custody::Present { .. } | Custody::Retiring { .. }))
                    .map(|(r, _)| r.start.max(range.start)..r.end.min(range.end)),
            );
        }
        held.sort_by_key(|r| r.start);
        let mut merged: Vec<Range<usize>> = Vec::new();
        for r in held {
            match merged.last_mut() {
                Some(last) if r.start <= last.end => last.end = last.end.max(r.end),
                _ => merged.push(r),
            }
        }
        merged
    }

    /// Returns the view currently installed at `addr` within `view`'s own family, if any.
    #[must_use]
    pub fn lookup_installed_at(&self, view: VmViewId, addr: usize) -> Option<VmViewId> {
        let inner = self.inner.lock();
        let family = inner.views.get(&view)?.family;
        inner.per_family.get(&family)?.installed.get(&addr).copied()
    }

    /// Returns a snapshot of `view`'s identity and lifecycle state.
    #[must_use]
    pub fn query_view(&self, view: VmViewId) -> Option<VmViewSnapshot> {
        let inner = self.inner.lock();
        inner.views.get(&view).map(|v| VmViewSnapshot {
            id: view,
            family: v.family,
            owner: v.owner,
            overlay: v.overlay,
        })
    }

    /// Returns a copy of `family`'s current [`FamilyRecord`], if it has been registered.
    #[must_use]
    pub fn query_family(&self, family: FamilyId) -> Option<FamilyRecord> {
        self.inner.lock().families.get(&family).copied()
    }

    /// Atomically marks `view`'s admission word [`AdmissionState::Draining`], refusing any new
    /// [`Self::acquire_run_lease`]/[`Self::acquire_access_lease`] from this point on. Does not
    /// wait for `view`'s outstanding lease count to reach zero -- that admission/drain orchestration
    /// is the dependent transaction-protocol row's job; this is the data-model primitive alone.
    ///
    /// Returns the drain's fresh generation.
    ///
    /// # Errors
    ///
    /// Returns [`DomainConflict::NotFound`] if `view` is not registered, or
    /// [`DomainConflict::Draining`] if the view's admission word is already not
    /// [`AdmissionState::Open`].
    pub fn begin_drain(&self, view: VmViewId) -> Result<u32, DomainConflict> {
        let inner = self.inner.lock();
        let entry = inner.views.get(&view).ok_or(DomainConflict::NotFound)?;
        loop {
            let word = entry.admission.load(Ordering::Acquire);
            let (state, generation, count) = unpack_admission(word);
            if state != AdmissionState::Open {
                return Err(DomainConflict::Draining);
            }
            let new_generation = generation.checked_add(1).ok_or(DomainConflict::IdentityExhausted)?;
            let new_word = pack_admission(AdmissionState::Draining, new_generation, count);
            if entry
                .admission
                .compare_exchange_weak(word, new_word, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return Ok(new_generation);
            }
        }
    }

    /// Reads `view`'s current `(state, generation, live lease count)` admission snapshot, for a
    /// future switcher to poll or park on. Returns `None` if `view` is not registered.
    #[must_use]
    pub fn admission_snapshot(&self, view: VmViewId) -> Option<(AdmissionState, u32, u32)> {
        let inner = self.inner.lock();
        let entry = inner.views.get(&view)?;
        Some(unpack_admission(entry.admission.load(Ordering::Acquire)))
    }

    fn acquire_lease(&self, view: VmViewId) -> Result<ViewLease<'_>, DomainConflict> {
        let mut inner = self.inner.lock();
        let entry = inner.views.get(&view).ok_or(DomainConflict::NotFound)?;
        if entry.overlay != ViewOverlay::Active {
            return Err(DomainConflict::NotInstalled);
        }
        let admission = entry.admission.clone();
        loop {
            let word = admission.load(Ordering::Acquire);
            let (state, generation, count) = unpack_admission(word);
            if state != AdmissionState::Open {
                return Err(DomainConflict::Draining);
            }
            if count > ADMISSION_MAX_COUNT {
                return Err(DomainConflict::IdentityExhausted);
            }
            let new_word = pack_admission(state, generation, count + 1);
            if admission
                .compare_exchange_weak(word, new_word, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                break;
            }
        }
        let family = entry.family;
        let record = inner
            .families
            .get_mut(&family)
            .expect("view's family must be registered while the view itself is");
        record.lease_survivors += 1;
        Ok(ViewLease { domain: self, view, admission })
    }

    /// Acquires a run lease on `view`: proof that `view` is currently installed and open to
    /// admission, held for the lifetime of the returned guard. Refused, never blocked, if `view`
    /// is not installed or its admission word is not [`AdmissionState::Open`].
    ///
    /// # Errors
    ///
    /// See [`DomainConflict`].
    pub fn acquire_run_lease(&self, view: VmViewId) -> Result<GuestRunLease<'_>, DomainConflict> {
        self.acquire_lease(view).map(GuestRunLease)
    }

    /// Acquires an access lease on `view`, identical in admission semantics to
    /// [`Self::acquire_run_lease`] but distinct in kind for a future scheduler's own bookkeeping.
    ///
    /// # Errors
    ///
    /// See [`DomainConflict`].
    pub fn acquire_access_lease(&self, view: VmViewId) -> Result<ViewAccessLease<'_>, DomainConflict> {
        self.acquire_lease(view).map(ViewAccessLease)
    }
}

struct ViewLease<'a> {
    domain: &'a GuestVaDomain,
    view: VmViewId,
    admission: Arc<AtomicU64>,
}

impl Drop for ViewLease<'_> {
    fn drop(&mut self) {
        loop {
            let word = self.admission.load(Ordering::Acquire);
            let (state, generation, count) = unpack_admission(word);
            let new_word = pack_admission(state, generation, count.saturating_sub(1));
            if self
                .admission
                .compare_exchange_weak(word, new_word, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                break;
            }
        }
        let mut inner = self.domain.inner.lock();
        if let Some(entry) = inner.views.get(&self.view) {
            let family = entry.family;
            if let Some(record) = inner.families.get_mut(&family) {
                record.lease_survivors = record.lease_survivors.saturating_sub(1);
            }
        }
    }
}

/// A held run-admission guard on a [`VmView`], returned by [`GuestVaDomain::acquire_run_lease`].
/// Dropping it releases the lease: decrements the view's live admission-word lease count with no
/// domain lock held, then decrements the owning family's [`FamilyRecord::lease_survivors`] under a
/// short, independent critical section.
#[must_use]
pub struct GuestRunLease<'a>(#[allow(dead_code)] ViewLease<'a>);

/// A held access-admission guard on a [`VmView`], returned by
/// [`GuestVaDomain::acquire_access_lease`]. See [`GuestRunLease`] for `Drop` semantics.
#[must_use]
pub struct ViewAccessLease<'a>(#[allow(dead_code)] ViewLease<'a>);
