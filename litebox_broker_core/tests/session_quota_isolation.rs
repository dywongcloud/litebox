// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Per-session object reference quotas isolate sessions from one another.
//!
//! Regression coverage for the broker-wide reference budget being drainable by
//! a single session. `BrokerCore` is a process singleton, so a broker core may
//! be constructed only once per process and this property needs its own test
//! binary rather than a helper inside the crate's unit-test core.

use litebox_broker_core::{
    BrokerCore, BrokerCoreLimits, BrokerError, BrokerSession, CallerCredential, ObjectRights,
    PolicyEngine, event,
};
use litebox_broker_protocol::ObjectHandle;

/// Broker-wide room for four references, but only two per session.
const MAX_REFERENCES: usize = 4;
const MAX_REFERENCES_PER_SESSION: usize = 2;
const MAX_TOTAL_PIPE_CAPACITY: usize = 64;
const MAX_PIPE_CAPACITY_PER_SESSION: usize = 64;

#[test]
fn one_session_cannot_exhaust_the_reference_budget_of_another() {
    let broker = BrokerCore::new_with_limits(
        PolicyEngine::with_unauthenticated_rights(ObjectRights::all()),
        BrokerCoreLimits::new(
            MAX_REFERENCES,
            MAX_TOTAL_PIPE_CAPACITY,
            MAX_REFERENCES_PER_SESSION,
            MAX_PIPE_CAPACITY_PER_SESSION,
        ),
    )
    .unwrap();

    let greedy = broker
        .create_session(CallerCredential::Unauthenticated)
        .unwrap();
    let victim = broker
        .create_session(CallerCredential::Unauthenticated)
        .unwrap();

    let mut greedy_handles = alloc_up_to_quota(&greedy);
    assert_eq!(greedy_handles.len(), MAX_REFERENCES_PER_SESSION);

    // The greedy session is capped on its own account while the broker-wide
    // ceiling still has room, so it cannot pin the shared budget.
    assert_eq!(
        event::create(&greedy, 0),
        Err(BrokerError::ResourceExhausted)
    );

    // The other session is unaffected and reaches its own full quota.
    let victim_handles = alloc_up_to_quota(&victim);
    assert_eq!(victim_handles.len(), MAX_REFERENCES_PER_SESSION);

    // Both sessions together are still bounded by the broker-wide ceiling.
    assert_eq!(
        event::create(&victim, 0),
        Err(BrokerError::ResourceExhausted)
    );

    // Closing a reference returns quota to the session that owned it.
    let released = greedy_handles.pop().unwrap();
    assert_eq!(greedy.close_object_reference(released), Ok(()));
    let reused = event::create(&greedy, 0).expect("closing a reference must return session quota");
    assert_eq!(greedy.close_object_reference(reused), Ok(()));

    // Dropping a session returns every reference it still held.
    drop(victim);
    let revived = broker
        .create_session(CallerCredential::Unauthenticated)
        .unwrap();
    assert_eq!(
        alloc_up_to_quota(&revived).len(),
        MAX_REFERENCES_PER_SESSION,
        "session teardown must return the whole quota it held"
    );
}

/// Creates event references until the session's own quota rejects the next one.
fn alloc_up_to_quota(session: &BrokerSession) -> Vec<ObjectHandle> {
    let mut handles = Vec::new();
    while let Ok(handle) = event::create(session, 0) {
        handles.push(handle);
        assert!(
            handles.len() <= MAX_REFERENCES_PER_SESSION,
            "session exceeded its per-session reference quota"
        );
    }
    handles
}
