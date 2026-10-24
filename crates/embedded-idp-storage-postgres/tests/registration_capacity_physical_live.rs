//! Physical capacity and admission-boundary acceptance for registration email.
//!
//! These cases stay ignored by default. They require a fresh isolated
//! PostgreSQL fixture and are intended to run serially.

#![allow(dead_code, unused_imports)]

mod registration_capacity_support;
mod registration_email_support;
mod registration_transport_support;

use registration_capacity_support::{
    assert_attached, facts, finish, fixture, marker, unknown_p, Facts,
};
use registration_transport_support::{database, Cut, Relay};
use serde_json::json;
use std::{sync::mpsc, thread, time::Duration};

#[test]
#[ignore = "requires fresh loopback sut_idp3_test with explicit confirmation"]
fn p_commit_not_forwarded_rolls_back_then_same_key_recovers() {
    let f = fixture();
    let (operation, input, before) = unknown_p(&f, true);

    let first = f
        .store()
        .register(&input)
        .expect("registration after rolled-back P");
    let attached = assert_attached(&f, operation, before);
    assert_eq!(attached.fence, 1);

    let replay = f.store().register(&input).expect("same-key replay");
    assert_eq!(
        first.verification_context.expose_secret(),
        replay.verification_context.expose_secret(),
        "same operation must return the same verification token"
    );
    let after_replay = facts(&f, operation);
    assert_eq!(after_replay, attached);

    let no_extra_charge = after_replay.charges == attached.charges
        && after_replay.start_charges == attached.start_charges;
    let no_duplicate = after_replay == attached;
    assert!(no_extra_charge);
    assert!(no_duplicate);
    marker(
        &f,
        2,
        json!({
            "recovery": true,
            "no_extra_charge": no_extra_charge,
            "no_duplicate": no_duplicate,
            "phase": after_replay.phase,
            "fence": after_replay.fence,
            "reserved_rows": after_replay.reserved,
            "lease": after_replay.lease,
            "contexts": after_replay.contexts,
            "intents": after_replay.intents,
            "events": after_replay.events,
            "charges": after_replay.charges,
            "start_charges": after_replay.start_charges,
            "weighted_rows": after_replay.weight,
            "sends": after_replay.sends,
        }),
    );
    finish(f);
}

#[test]
#[ignore = "requires fresh loopback sut_idp3_test with explicit confirmation"]
fn p_commit_ack_blackhole_preserves_reservation_and_recovers() {
    let f = fixture();
    let (operation, input, reserved) = unknown_p(&f, false);
    assert_eq!(
        (
            reserved.phase,
            reserved.fence,
            reserved.reserved,
            reserved.contexts,
            reserved.intents,
            reserved.events,
            reserved.charges,
        ),
        (1, 1, 2, 0, 0, 0, 1),
    );

    let first = f
        .store()
        .register(&input)
        .expect("registration recovery from reservation");
    let attached = assert_attached(&f, operation, reserved);
    assert_eq!(attached.fence, 1);
    assert_eq!(attached.reserved, 2);
    assert_eq!(attached.charges, 1);

    let replay = f.store().register(&input).expect("same-key replay");
    assert_eq!(
        first.verification_context.expose_secret(),
        replay.verification_context.expose_secret(),
        "same operation must return the same verification token"
    );
    let after_replay = facts(&f, operation);
    assert_eq!(after_replay, attached);

    let no_extra_charge = after_replay.charges == attached.charges
        && after_replay.start_charges == attached.start_charges;
    let no_duplicate = after_replay == attached;
    assert!(no_extra_charge);
    assert!(no_duplicate);
    marker(
        &f,
        3,
        json!({
            "recovery": true,
            "no_extra_charge": no_extra_charge,
            "no_duplicate": no_duplicate,
            "phase_before": reserved.phase,
            "phase_after": after_replay.phase,
            "fence": after_replay.fence,
            "reserved_rows": after_replay.reserved,
            "lease": after_replay.lease,
            "contexts": after_replay.contexts,
            "intents": after_replay.intents,
            "events": after_replay.events,
            "charges_before": reserved.charges,
            "charges": after_replay.charges,
            "start_charges": after_replay.start_charges,
            "weighted_rows": after_replay.weight,
            "sends": after_replay.sends,
        }),
    );
    finish(f);
}

#[test]
#[ignore = "requires fresh loopback sut_idp3_test with explicit confirmation"]
fn p_and_attach_boundaries_are_calibrated_before_faults() {
    let f = fixture();
    let operation = uuid::Uuid::now_v7();
    let input = registration_capacity_support::prepared(&f, operation);
    let baseline = facts(&f, operation);
    let mut relay = Relay::new(database(), Cut::BeginGate);
    let store = registration_transport_support::relay_store(&f, &relay);
    let work = input.clone();
    let (send, receive) = mpsc::channel();

    // The first two matching BEGIN frames are the early read and P. The
    // third is A, where the test-only gate holds the main transaction.
    relay.arm_after(2);
    let call = thread::spawn(move || {
        let _ = send.send(store.register(&work));
    });
    assert!(relay.wait_for_hits(1), "A BEGIN did not reach the gate");
    assert!(!relay.gate_released());

    let phase_before = facts(&f, operation);
    assert_eq!(
        (
            phase_before.phase,
            phase_before.fence,
            phase_before.reserved,
            phase_before.contexts,
            phase_before.intents,
            phase_before.events,
            phase_before.charges,
        ),
        (1, 1, 2, 0, 0, 0, 1),
    );
    assert_eq!(phase_before.accounts, baseline.accounts);
    assert_eq!(phase_before.members, baseline.members);

    relay.release_gate();
    let accepted = receive
        .recv_timeout(Duration::from_secs(3))
        .expect("registration after gate release")
        .expect("registration accepted after gate release");
    assert!(call.join().is_ok());
    assert!(relay.gate_released());

    let attached = assert_attached(&f, operation, baseline);
    assert_eq!(attached.phase, 2);
    assert_eq!(attached.fence, 1);
    assert_eq!(attached.charges, 1);
    let replay = f.store().register(&input).expect("same-key replay");
    assert_eq!(
        accepted.verification_context.expose_secret(),
        replay.verification_context.expose_secret(),
        "same operation must return the same verification token"
    );
    let after_replay = facts(&f, operation);
    assert_eq!(after_replay, attached);

    marker(
        &f,
        4,
        json!({
            "calibrated": true,
            "phase_before": phase_before.phase,
            "phase_after": after_replay.phase,
            "fence": after_replay.fence,
            "reserved_rows": phase_before.reserved,
            "charges": after_replay.charges,
            "gate_released": relay.gate_released(),
            "recovery": true,
            "no_extra_charge": true,
            "no_duplicate": true,
        }),
    );
    relay.close();
    finish(f);
}
