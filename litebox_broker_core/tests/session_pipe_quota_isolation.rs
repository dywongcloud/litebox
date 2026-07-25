// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Per-session pipe capacity quotas isolate sessions from one another.
//!
//! Regression coverage for the broker-wide pipe capacity budget being drainable
//! by a single session, and for the reservation released on every rejection
//! path. `BrokerCore` is a process singleton, so this needs its own test binary.

use litebox_broker_core::{
    BrokerCore, BrokerCoreLimits, BrokerError, CallerCredential, ObjectRights, PolicyEngine, pipe,
};

/// Broker-wide room for two full-size pipes, but only one per session.
const PIPE_CAPACITY: u64 = 4;
const ATOMIC_WRITE_SIZE: u64 = 2;
const MAX_REFERENCES: usize = 16;
const MAX_REFERENCES_PER_SESSION: usize = 16;
const MAX_TOTAL_PIPE_CAPACITY: usize = 8;
const MAX_PIPE_CAPACITY_PER_SESSION: usize = 4;

#[test]
fn one_session_cannot_exhaust_the_pipe_capacity_budget_of_another() {
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

    let (greedy_reader, greedy_writer) =
        pipe::create(&greedy, PIPE_CAPACITY, ATOMIC_WRITE_SIZE).unwrap();

    // The greedy session is capped on its own account while the broker-wide
    // ceiling still has room for another full-size pipe.
    assert_eq!(
        pipe::create(&greedy, PIPE_CAPACITY, ATOMIC_WRITE_SIZE),
        Err(BrokerError::ResourceExhausted)
    );

    // The other session still reaches its own full quota.
    let (victim_reader, victim_writer) =
        pipe::create(&victim, PIPE_CAPACITY, ATOMIC_WRITE_SIZE).unwrap();

    // A rejection on the per-session quota must not leak capacity: closing both
    // endpoints returns the whole reservation and lets the session retry.
    assert_eq!(greedy.close_object_reference(greedy_reader), Ok(()));
    assert_eq!(greedy.close_object_reference(greedy_writer), Ok(()));
    let (retry_reader, retry_writer) = pipe::create(&greedy, PIPE_CAPACITY, ATOMIC_WRITE_SIZE)
        .expect("closing both endpoints must return the session pipe quota");

    // With both sessions at quota the broker-wide ceiling is reached, so a
    // third session with a fully unused quota is refused by the ceiling.
    let third = broker
        .create_session(CallerCredential::Unauthenticated)
        .unwrap();
    assert_eq!(
        pipe::create(&third, PIPE_CAPACITY, ATOMIC_WRITE_SIZE),
        Err(BrokerError::ResourceExhausted)
    );

    // A rejection on the broker-wide ceiling must not leak the session-tier
    // charge either: once room is freed, the same session succeeds.
    assert_eq!(victim.close_object_reference(victim_reader), Ok(()));
    assert_eq!(victim.close_object_reference(victim_writer), Ok(()));
    let (third_reader, third_writer) = pipe::create(&third, PIPE_CAPACITY, ATOMIC_WRITE_SIZE)
        .expect("a ceiling rejection must not charge the session quota");

    // Dropping a session returns the capacity its live pipes still held.
    drop(third);
    assert_eq!(greedy.close_object_reference(retry_reader), Ok(()));
    assert_eq!(greedy.close_object_reference(retry_writer), Ok(()));
    let (final_reader, final_writer) = pipe::create(&greedy, PIPE_CAPACITY, ATOMIC_WRITE_SIZE)
        .expect("session teardown must return the capacity it held");
    assert_eq!(greedy.close_object_reference(final_reader), Ok(()));
    assert_eq!(greedy.close_object_reference(final_writer), Ok(()));

    // Handles from the dropped session are gone with it.
    assert_eq!(
        victim.close_object_reference(third_reader),
        Err(BrokerError::UnknownObject)
    );
    assert_eq!(
        victim.close_object_reference(third_writer),
        Err(BrokerError::UnknownObject)
    );
}
