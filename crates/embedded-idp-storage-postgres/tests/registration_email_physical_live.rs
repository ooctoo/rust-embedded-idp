//! Physical PostgreSQL deadline acceptance for the IDP registration store.
//!
//! Every test is ignored by default and requires the isolated fixture selected
//! by `registration_email_support::Fixture`.

#![allow(dead_code, unused_imports)]

mod registration_email_support;
mod registration_transport_support;

use embedded_idp_core::access::{
    RegistrationEmailCommand, RegistrationEmailError, RegistrationEmailOperationKind,
    RegistrationEmailService, RegistrationEmailVerification,
};
use embedded_idp_core::SecretString;
use registration_email_support::Fixture;
use registration_transport_support::{
    counts, database, finish_call, install_runtime_and_resume, only_context, print_marker,
    relay_store, verify_facts, Counts, Cut, Relay, VerifyFacts, IDENTITY_DEADLINE,
    READONLY_DEADLINE,
};
use uuid::Uuid;

fn run_readonly_blackhole(stage: u8, cut: Cut) {
    let fixture = Fixture::new();
    install_runtime_and_resume(&fixture);
    let mut relay = Relay::new(database(), cut);
    let store = relay_store(&fixture, &relay);
    let before = counts(&fixture);
    let hit_eof_before = relay.hit_peer_eof();
    relay.arm_after(0);
    let operation = Uuid::now_v7();
    let evidence = finish_call(&mut relay, hit_eof_before, READONLY_DEADLINE, move || {
        RegistrationEmailService::is_replay(
            &store,
            RegistrationEmailOperationKind::Register,
            operation,
        )
        .is_err()
    });
    let recovered = if evidence.relay_open {
        let recovery_store = relay_store(&fixture, &relay);
        RegistrationEmailService::is_replay(
            &recovery_store,
            RegistrationEmailOperationKind::Register,
            Uuid::now_v7(),
        ) == Ok(false)
    } else {
        false
    };
    relay.close();
    let after = counts(&fixture);
    print_marker(stage, &evidence, recovered, after, before == after);
    assert!(evidence.hit);
    assert_eq!(evidence.result, Some(true));
    assert!(evidence.elapsed_ms <= READONLY_DEADLINE.as_millis());
    assert!(evidence.physical_eof);
    assert!(evidence.thread_joined);
    assert!(recovered);
    assert_eq!(
        after,
        Counts {
            contexts: 0,
            attached: 0,
            intents: 0
        }
    );
    assert_eq!(before, after);
}

#[test]
#[ignore = "requires fresh loopback sut_idp3_test with explicit confirmation"]
fn begin_blackhole_returns_within_readonly_budget_and_recovers() {
    run_readonly_blackhole(0, Cut::Begin);
}

#[test]
#[ignore = "requires fresh loopback sut_idp3_test with explicit confirmation"]
fn query_blackhole_returns_within_readonly_budget_and_recovers() {
    run_readonly_blackhole(1, Cut::Query);
}

#[test]
#[ignore = "requires fresh loopback sut_idp3_test with explicit confirmation"]
fn commit_blackhole_keeps_authoritative_mutation_and_replays() {
    let fixture = Fixture::new();
    install_runtime_and_resume(&fixture);
    let mut relay = Relay::new(database(), Cut::Commit);
    let store = relay_store(&fixture, &relay);
    let operation = Uuid::now_v7();
    let prepared = fixture.prepared(
        operation,
        "physical-commit@example.test",
        "NewPassword123",
        None,
    );
    let before = counts(&fixture);
    let hit_eof_before = relay.hit_peer_eof();
    // Direct register has one reservation COMMIT followed by the admission
    // COMMIT.  Skip the former and blackhole only the latter.
    relay.arm_after(1);
    let evidence = finish_call(&mut relay, hit_eof_before, IDENTITY_DEADLINE, move || {
        store.register(&prepared).is_err()
    });
    let after_fault = counts(&fixture);
    let context = only_context(&fixture);
    let replay = fixture.prepared(
        operation,
        "physical-commit@example.test",
        "NewPassword123",
        None,
    );
    let replay_result = if evidence.relay_open {
        let recovery_store = relay_store(&fixture, &relay);
        Some(recovery_store.register(&replay))
    } else {
        None
    };
    let replay_context = replay_result
        .as_ref()
        .and_then(|result| result.as_ref().ok())
        .map(|accepted| fixture.context_id(&accepted.verification_context));
    relay.close();
    let after_replay = counts(&fixture);
    let recovered = replay_context == Some(context);
    let replay_no_extra = replay_result.is_some() && after_fault == after_replay;
    print_marker(2, &evidence, recovered, after_replay, replay_no_extra);
    assert_eq!(
        before,
        Counts {
            contexts: 0,
            attached: 0,
            intents: 0
        }
    );
    assert!(evidence.hit);
    assert_eq!(evidence.result, Some(true));
    assert!(evidence.elapsed_ms <= IDENTITY_DEADLINE.as_millis());
    assert!(evidence.physical_eof);
    assert!(evidence.thread_joined);
    assert_eq!(
        after_fault,
        Counts {
            contexts: 1,
            attached: 1,
            intents: 1
        }
    );
    assert!(recovered);
    assert!(replay_no_extra);
}

#[test]
#[ignore = "requires fresh loopback sut_idp3_test with explicit confirmation"]
fn verify_commit_blackhole_keeps_activation_and_replays_verified() {
    let fixture = Fixture::new();
    install_runtime_and_resume(&fixture);
    let email = "physical-verify@example.test";
    let register_operation = Uuid::now_v7();
    let setup_store = fixture.store();
    let accepted = RegistrationEmailService::register_command(
        &setup_store,
        RegistrationEmailCommand {
            operation: register_operation,
            email: SecretString::new(email),
            password: SecretString::new("NewPassword123"),
            display_name: None,
        },
    )
    .expect("healthy registration");
    let token = accepted.verification_context.expose_secret().to_string();
    let context = fixture.context_id_str(&token);
    let claim = RegistrationEmailService::claim_preparation(&setup_store)
        .expect("preparation claim")
        .expect("preparation should be available");
    assert_eq!(claim.context_id, context);
    assert_eq!(
        RegistrationEmailService::prepare_claimed(&setup_store, &claim)
            .expect("prepare registration"),
        embedded_idp_core::access::RegistrationEmailPreparation::Prepared
    );
    let payload = registration_email_support::delivery(&fixture, context, 1);
    let code = payload.code.expose_secret().to_string();
    drop(setup_store);

    let verify_operation = Uuid::now_v7();
    let before = counts(&fixture);
    let before_facts = verify_facts(&fixture, email, context, verify_operation);
    let mut relay = Relay::new(database(), Cut::Commit);
    let store = relay_store(&fixture, &relay);
    let hit_eof_before = relay.hit_peer_eof();
    // verify has a reservation transaction COMMIT before its final identity
    // transaction COMMIT, so skip the reservation and blackhole the latter.
    relay.arm_after(1);
    let verify_token = token.clone();
    let verify_code = code.clone();
    let evidence = finish_call(&mut relay, hit_eof_before, IDENTITY_DEADLINE, move || {
        matches!(
            store.verify(verify_operation, &verify_token, &verify_code),
            Err(RegistrationEmailError::Store(_)) | Err(RegistrationEmailError::Unavailable)
        )
    });
    let after_fault = counts(&fixture);
    let after_fault_facts = verify_facts(&fixture, email, context, verify_operation);
    let replay_result = if evidence.relay_open {
        let recovery_store = relay_store(&fixture, &relay);
        Some(recovery_store.verify(verify_operation, &token, &code))
    } else {
        None
    };
    relay.close();
    let replay_verified = replay_result == Some(Ok(RegistrationEmailVerification::Verified));
    let after_replay = counts(&fixture);
    let after_replay_facts = verify_facts(&fixture, email, context, verify_operation);
    let replay_no_extra = replay_result.is_some()
        && after_fault == after_replay
        && after_fault_facts == after_replay_facts;
    let recovered = replay_verified
        && after_replay_facts
            == VerifyFacts {
                accounts: 1,
                active_accounts: 1,
                memberships: 1,
                active_memberships: 1,
                consumed_codes: 1,
                completed_contexts: 1,
                verify_attached: 1,
            };
    print_marker(3, &evidence, recovered, after_replay, replay_no_extra);
    assert_eq!(
        before,
        Counts {
            contexts: 1,
            attached: 1,
            intents: 1
        }
    );
    assert_eq!(
        before_facts,
        VerifyFacts {
            accounts: 0,
            active_accounts: 0,
            memberships: 0,
            active_memberships: 0,
            consumed_codes: 0,
            completed_contexts: 0,
            verify_attached: 0,
        }
    );
    assert!(evidence.hit);
    assert_eq!(evidence.result, Some(true));
    assert!(evidence.elapsed_ms <= IDENTITY_DEADLINE.as_millis());
    assert!(evidence.physical_eof);
    assert!(evidence.thread_joined);
    assert_eq!(
        after_fault,
        Counts {
            contexts: 1,
            attached: 2,
            intents: 1
        }
    );
    assert!(recovered);
    assert!(replay_no_extra);
}
