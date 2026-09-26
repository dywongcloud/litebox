// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Checked, nonzero, never-reused identity types for memory, lifecycle, scheduler, backing and
//! failure authorities.
//!
//! Every identity here is minted from an independent monotonic counter via a checked
//! `fetch_update`, never from a pointer, PID/TID, wrapping counter, `Arc` count or content
//! equality. Allocation is fallible: counter exhaustion returns `None` rather than panicking,
//! reusing a value, or wrapping, so a caller can fail closed (publish no task/effect) instead of
//! minting a colliding identity.

use core::num::NonZeroU64;
use core::sync::atomic::{AtomicU64, Ordering};

macro_rules! checked_id {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        pub struct $name(NonZeroU64);

        impl $name {
            /// Allocates the next never-reused identity, or `None` if the counter space for
            /// this identity kind is exhausted.
            pub fn next() -> Option<Self> {
                static NEXT: AtomicU64 = AtomicU64::new(1);
                let raw = NEXT
                    .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                        value.checked_add(1)
                    })
                    .ok()?;
                Some(Self(NonZeroU64::new(raw)?))
            }

            /// Returns the raw value of this identity.
            #[must_use]
            pub fn get(self) -> NonZeroU64 {
                self.0
            }
        }
    };
}

checked_id! {
    /// Identity of one guest-memory domain (the process-global `GuestVaDomain`'s own scope, or a
    /// future scoped variant).
    MemoryDomainId
}
checked_id! {
    /// Identity of one fork family (a lineage of processes sharing a common ancestor's memory
    /// custody chain).
    FamilyId
}
checked_id! {
    /// Identity of one logical `VmView`.
    VmViewId
}
checked_id! {
    /// Identity of one logical guest `mm_struct`-equivalent.
    LogicalMmId
}
checked_id! {
    /// Identity of one process instance, never reused even across the same PID being reused.
    ProcessInstanceId
}
checked_id! {
    /// Identity of one task (thread) instance, never reused even across the same TID being
    /// reused.
    TaskInstanceId
}
checked_id! {
    /// Identity of one exec transition.
    ExecId
}
checked_id! {
    /// Identity of one view-switch handoff.
    HandoffId
}
checked_id! {
    /// Identity of one memory mutation.
    MutationId
}
checked_id! {
    /// Identity of one effect-session epoch.
    EffectEpoch
}
checked_id! {
    /// Identity of one private-backing generation.
    BackingGenerationId
}
checked_id! {
    /// Identity of one recorded failure.
    FailureId
}
checked_id! {
    /// Identity of one scheduler ticket.
    SchedulerTicketId
}
checked_id! {
    /// Identity of one active memory session.
    MemorySessionId
}
checked_id! {
    /// Identity of one guest-owned-aperture custody generation, stamped on `Hole`/`Present` and
    /// used to authenticate provider-operation tokens against a stale/already-mutated range.
    HoleGenerationId
}
