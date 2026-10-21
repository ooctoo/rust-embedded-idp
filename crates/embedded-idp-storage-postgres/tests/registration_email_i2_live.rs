//! Isolated I2 runtime tests. Never discover credentials or connect to an existing database.
#![allow(dead_code, unused_imports)]
mod registration_email_support;
use embedded_idp_core::{
    access::{
        RegistrationEmailCommand, RegistrationEmailDeliveryResult, RegistrationEmailOperationKind,
        RegistrationEmailPreparation, RegistrationEmailService,
    },
    SecretString,
};
use registration_email_support::Fixture;
use uuid::Uuid;

fn install(f: &Fixture) {
    let plan = f
        .adapter
        .registration_email_runtime_migration_plan(&f.scope)
        .expect("runtime plan");
    f.adapter
        .apply_registration_email_runtime(&plan, &f.scope)
        .expect("runtime apply");
}
fn command(operation: Uuid, email: &str) -> RegistrationEmailCommand {
    RegistrationEmailCommand {
        operation,
        email: SecretString::new(email),
        password: SecretString::new("NewPassword123"),
        display_name: None,
    }
}
fn setup() -> Fixture {
    let f = Fixture::new();
    install(&f);
    RegistrationEmailService::resume_registration(&f.store()).unwrap();
    f
}

#[test]
#[ignore = "requires fresh loopback sut_idp3_test with explicit confirmation"]
fn install_is_explicit_paused_and_rejects_repeat_and_drift() {
    let f = Fixture::new();
    assert!(
        !RegistrationEmailService::runtime_facts(&f.store())
            .unwrap()
            .store_ready
    );
    let plan = f
        .adapter
        .registration_email_runtime_migration_plan(&f.scope)
        .unwrap();
    let mut changed = plan.clone();
    changed.fingerprint = "0".repeat(64);
    assert!(f
        .adapter
        .apply_registration_email_runtime(&changed, &f.scope)
        .is_err());
    assert!(
        !RegistrationEmailService::runtime_facts(&f.store())
            .unwrap()
            .store_ready
    );
    f.adapter
        .apply_registration_email_runtime(&plan, &f.scope)
        .unwrap();
    assert!(f
        .adapter
        .apply_registration_email_runtime(&plan, &f.scope)
        .is_err());
    let facts = RegistrationEmailService::runtime_facts(&f.store()).unwrap();
    assert!(facts.store_ready);
    assert!(!facts.accepting);
    assert!(RegistrationEmailService::register_command(
        &f.store(),
        command(Uuid::now_v7(), "paused@example.test")
    )
    .is_err());
    assert_eq!(f.count("registration_email_contexts"), 0);
    RegistrationEmailService::resume_registration(&f.store()).unwrap();
    assert!(
        RegistrationEmailService::runtime_facts(&f.store())
            .unwrap()
            .accepting
    );
}

#[test]
#[ignore = "requires fresh loopback sut_idp3_test with explicit confirmation"]
fn replay_survives_restart_and_pause_but_changed_body_conflicts() {
    let f = setup();
    let op = Uuid::now_v7();
    let store = f.store();
    let first =
        RegistrationEmailService::register_command(&store, command(op, "replay@example.test"))
            .unwrap();
    RegistrationEmailService::pause_registration(&store).unwrap();
    let reopened = f.store();
    assert!(
        !RegistrationEmailService::runtime_facts(&reopened)
            .unwrap()
            .accepting
    );
    assert!(RegistrationEmailService::is_replay(
        &reopened,
        RegistrationEmailOperationKind::Register,
        op
    )
    .unwrap());
    // Original-key recovery must remain available when every KDF slot is busy.
    let budget = reopened.password_work_budget();
    let kdf_holds: Vec<_> = (0..4).map(|_| budget.try_login().unwrap()).collect();
    let replay =
        RegistrationEmailService::register_command(&reopened, command(op, "replay@example.test"))
            .unwrap();
    assert_eq!(
        first.verification_context.expose_secret(),
        replay.verification_context.expose_secret()
    );
    assert_eq!(first.accepted_at_unix_secs, replay.accepted_at_unix_secs);
    assert!(RegistrationEmailService::register_command(
        &reopened,
        command(op, "different@example.test")
    )
    .is_err());
    assert!(RegistrationEmailService::register_command(
        &reopened,
        command(Uuid::now_v7(), "new@example.test")
    )
    .is_err());
    assert_eq!(f.count("registration_email_contexts"), 1);
    drop(kdf_holds);
}

#[test]
#[ignore = "requires fresh loopback sut_idp3_test with explicit confirmation"]
fn preparation_is_fenced_and_delivery_message_taken_once() {
    let f = setup();
    let store = f.store();
    let accepted = RegistrationEmailService::register_command(
        &store,
        command(Uuid::now_v7(), "one@example.test"),
    )
    .unwrap();
    let context = f.context_id(&accepted.verification_context);
    let claim = RegistrationEmailService::claim_preparation(&store)
        .unwrap()
        .unwrap();
    assert_eq!(claim.context_id, context);
    assert!(RegistrationEmailService::claim_preparation(&store)
        .unwrap()
        .is_none());
    let mut forged = claim.clone();
    forged.claim_token = Uuid::now_v7();
    assert!(RegistrationEmailService::prepare_claimed(&store, &forged).is_err());
    assert_eq!(f.count("registration_email_codes"), 0);
    assert_eq!(
        RegistrationEmailService::prepare_claimed(&store, &claim).unwrap(),
        RegistrationEmailPreparation::Prepared
    );
    assert_eq!(
        RegistrationEmailService::prepare_claimed(&store, &claim).unwrap(),
        RegistrationEmailPreparation::Prepared
    );
    assert_eq!(f.count("registration_email_codes"), 1);
    let effect = RegistrationEmailService::next_delivery(&store)
        .unwrap()
        .unwrap();
    let delivery = RegistrationEmailService::claim_delivery(&store, effect)
        .unwrap()
        .unwrap();
    let mut forged = delivery.clone();
    forged.claim_token = Uuid::now_v7();
    assert!(RegistrationEmailService::delivery_message(&store, &forged).is_err());
    let message = RegistrationEmailService::delivery_message(&store, &delivery)
        .unwrap()
        .unwrap();
    assert_eq!(message.email.expose_secret(), "one@example.test");
    assert_eq!(message.code.expose_secret().len(), 6);
    assert!(RegistrationEmailService::delivery_message(&store, &delivery).is_err());
    RegistrationEmailService::finish_delivery(
        &store,
        &delivery,
        RegistrationEmailDeliveryResult::Sent,
    )
    .unwrap();
    assert!(RegistrationEmailService::next_delivery(&store)
        .unwrap()
        .is_none());
}

#[test]
#[ignore = "requires fresh loopback sut_idp3_test with explicit confirmation"]
fn unknown_delivery_survives_restart_and_requires_evidence_then_resume() {
    let f = setup();
    let store = f.store();
    RegistrationEmailService::register_command(
        &store,
        command(Uuid::now_v7(), "unknown@example.test"),
    )
    .unwrap();
    let claim = RegistrationEmailService::claim_preparation(&store)
        .unwrap()
        .unwrap();
    RegistrationEmailService::prepare_claimed(&store, &claim).unwrap();
    let effect = RegistrationEmailService::next_delivery(&store)
        .unwrap()
        .unwrap();
    let delivery = RegistrationEmailService::claim_delivery(&store, effect)
        .unwrap()
        .unwrap();
    assert!(
        RegistrationEmailService::delivery_message(&store, &delivery)
            .unwrap()
            .is_some()
    );
    RegistrationEmailService::finish_delivery(
        &store,
        &delivery,
        RegistrationEmailDeliveryResult::Unknown,
    )
    .unwrap();
    let reopened = f.store();
    let facts = RegistrationEmailService::runtime_facts(&reopened).unwrap();
    assert!(!facts.accepting);
    assert_eq!(facts.unresolved_delivery, 1);
    assert!(RegistrationEmailService::resume_registration(&reopened).is_err());
    RegistrationEmailService::confirm_delivery_stopped(&reopened, &delivery).unwrap();
    assert!(
        !RegistrationEmailService::runtime_facts(&reopened)
            .unwrap()
            .accepting
    );
    RegistrationEmailService::resume_registration(&reopened).unwrap();
    assert!(
        RegistrationEmailService::runtime_facts(&reopened)
            .unwrap()
            .accepting
    );
}

#[test]
#[ignore = "requires fresh loopback sut_idp3_test with explicit confirmation"]
fn expired_preparation_is_terminal_and_maintenance_pauses() {
    let f = setup();
    let store = f.store();
    RegistrationEmailService::register_command(
        &store,
        command(Uuid::now_v7(), "expired@example.test"),
    )
    .unwrap();
    let mut claim = RegistrationEmailService::claim_preparation(&store)
        .unwrap()
        .unwrap();
    let at = f.now();
    f.adapter.connect().unwrap().execute(&format!("update {}.registration_email_intents set lease_until=$3,created_at=$3::bigint-31 where context_id=$1 and seq=$2",f.schema),&[&claim.context_id,&claim.sequence,&(at-1)]).unwrap();
    claim.lease_until = at - 1;
    assert!(RegistrationEmailService::prepare_claimed(&store, &claim).is_err());
    assert_eq!(
        RegistrationEmailService::runtime_facts(&store)
            .unwrap()
            .overdue_processing,
        1
    );
    RegistrationEmailService::maintain_runtime(&store).unwrap();
    assert!(
        !RegistrationEmailService::runtime_facts(&store)
            .unwrap()
            .accepting
    );
    assert!(RegistrationEmailService::claim_preparation(&store)
        .unwrap()
        .is_none());
    assert_eq!(f.count("registration_email_codes"), 0);
    RegistrationEmailService::resume_registration(&store).unwrap();
    assert!(
        RegistrationEmailService::runtime_facts(&store)
            .unwrap()
            .accepting
    );
}

#[test]
#[ignore = "requires fresh loopback sut_idp3_test with explicit confirmation"]
fn competing_preparation_claims_have_one_winner() {
    use std::sync::{Arc, Barrier};
    let f = Arc::new(setup());
    let store = f.store();
    RegistrationEmailService::register_command(
        &store,
        command(Uuid::now_v7(), "race@example.test"),
    )
    .unwrap();
    let barrier = Arc::new(Barrier::new(3));
    let mut threads = Vec::new();
    for _ in 0..2 {
        let f = Arc::clone(&f);
        let barrier = Arc::clone(&barrier);
        threads.push(std::thread::spawn(move || {
            let store = f.store();
            barrier.wait();
            RegistrationEmailService::claim_preparation(&store).unwrap()
        }));
    }
    barrier.wait();
    let claims: Vec<_> = threads
        .into_iter()
        .filter_map(|t| t.join().unwrap())
        .collect();
    assert_eq!(claims.len(), 1);
    assert_eq!(
        RegistrationEmailService::prepare_claimed(&store, &claims[0]).unwrap(),
        RegistrationEmailPreparation::Prepared
    );
    assert_eq!(f.count("registration_email_codes"), 1);
}

#[test]
#[ignore = "requires fresh loopback sut_idp3_test with explicit confirmation"]
fn superseded_before_dispatch_never_releases_message() {
    let f = setup();
    let store = f.store();
    let accepted = RegistrationEmailService::register_command(
        &store,
        command(Uuid::now_v7(), "superseded@example.test"),
    )
    .unwrap();
    let context = f.context_id(&accepted.verification_context);
    let claim = RegistrationEmailService::claim_preparation(&store)
        .unwrap()
        .unwrap();
    RegistrationEmailService::prepare_claimed(&store, &claim).unwrap();
    let effect = RegistrationEmailService::next_delivery(&store)
        .unwrap()
        .unwrap();
    let delivery = RegistrationEmailService::claim_delivery(&store, effect)
        .unwrap()
        .unwrap();
    f.adapter
        .connect()
        .unwrap()
        .execute(
            &format!(
                "update {}.registration_email_contexts set accepted_seq=accepted_seq+1 where id=$1",
                f.schema
            ),
            &[&context],
        )
        .unwrap();
    assert!(
        RegistrationEmailService::delivery_message(&store, &delivery)
            .unwrap()
            .is_none()
    );
    assert!(RegistrationEmailService::delivery_message(&store, &delivery).is_err());
    let row=f.adapter.connect().unwrap().query_one(&format!("select status,octet_length(payload_cipher),stop_confirmed from {}.registration_email_deliveries where id=$1",f.schema),&[&effect]).unwrap();
    assert_eq!(row.get::<_, String>(0), "expired");
    assert_eq!(row.get::<_, i32>(1), 0);
    assert!(row.get::<_, bool>(2));
    assert_eq!(f.count("registration_email_codes"), 1);
}

#[test]
#[ignore = "requires fresh loopback sut_idp3_test with explicit confirmation"]
fn unknown_outcome_and_pause_roll_back_with_audit_failure() {
    let f = setup();
    let store = f.store();
    RegistrationEmailService::register_command(
        &store,
        command(Uuid::now_v7(), "audit@example.test"),
    )
    .unwrap();
    let claim = RegistrationEmailService::claim_preparation(&store)
        .unwrap()
        .unwrap();
    RegistrationEmailService::prepare_claimed(&store, &claim).unwrap();
    let effect = RegistrationEmailService::next_delivery(&store)
        .unwrap()
        .unwrap();
    let delivery = RegistrationEmailService::claim_delivery(&store, effect)
        .unwrap()
        .unwrap();
    RegistrationEmailService::delivery_message(&store, &delivery)
        .unwrap()
        .unwrap();
    f.install_event_failure();
    assert!(RegistrationEmailService::finish_delivery(
        &store,
        &delivery,
        RegistrationEmailDeliveryResult::Unknown
    )
    .is_err());
    let row = f
        .adapter
        .connect()
        .unwrap()
        .query_one(
            &format!(
                "select status from {}.registration_email_deliveries where id=$1",
                f.schema
            ),
            &[&effect],
        )
        .unwrap();
    assert_eq!(row.get::<_, String>(0), "claimed");
    assert!(
        RegistrationEmailService::runtime_facts(&store)
            .unwrap()
            .accepting
    );
    f.drop_event_failure();
    RegistrationEmailService::finish_delivery(
        &store,
        &delivery,
        RegistrationEmailDeliveryResult::Unknown,
    )
    .unwrap();
    assert!(
        !RegistrationEmailService::runtime_facts(&store)
            .unwrap()
            .accepting
    );
}

#[test]
#[ignore = "requires fresh loopback sut_idp3_test with explicit confirmation"]
fn disabled_mode_tenant_zero_registration_and_verification() {
    use embedded_idp_core::access::RegistrationEmailVerification;
    let f = Fixture::with_disabled_mode();
    assert_eq!(f.scope.tenant, "0");
    install(&f);
    let store = f.store();
    assert!(
        !RegistrationEmailService::runtime_facts(&store)
            .unwrap()
            .accepting
    );
    RegistrationEmailService::resume_registration(&store).unwrap();
    let accepted = RegistrationEmailService::register_command(
        &store,
        command(Uuid::now_v7(), "disabled@example.test"),
    )
    .unwrap();
    let claim = RegistrationEmailService::claim_preparation(&store)
        .unwrap()
        .unwrap();
    assert_eq!(
        RegistrationEmailService::prepare_claimed(&store, &claim).unwrap(),
        RegistrationEmailPreparation::Prepared
    );
    let effect = RegistrationEmailService::next_delivery(&store)
        .unwrap()
        .unwrap();
    let delivery = RegistrationEmailService::claim_delivery(&store, effect)
        .unwrap()
        .unwrap();
    let message = RegistrationEmailService::delivery_message(&store, &delivery)
        .unwrap()
        .unwrap();
    assert_eq!(message.email.expose_secret(), "disabled@example.test");
    assert!(RegistrationEmailService::delivery_message(&store, &delivery).is_err());
    RegistrationEmailService::finish_delivery(
        &store,
        &delivery,
        RegistrationEmailDeliveryResult::Sent,
    )
    .unwrap();
    let result = RegistrationEmailService::verify_command(
        &store,
        Uuid::now_v7(),
        accepted.verification_context.expose_secret(),
        message.code.expose_secret(),
    )
    .unwrap();
    assert_eq!(result, RegistrationEmailVerification::Verified);
    let mut c = f.adapter.connect().unwrap();
    let row=c.query_one(&format!("select a.status,a.registration_tenant_id,m.tenant_id,m.status from {}.accounts a join {}.access_memberships m on m.account_id=a.id where a.email=$1",f.schema,f.schema),&[&"disabled@example.test"]).unwrap();
    assert_eq!(row.get::<_, String>(0), "active");
    assert_eq!(row.get::<_, String>(1), "0");
    assert_eq!(row.get::<_, String>(2), "0");
    assert_eq!(row.get::<_, String>(3), "active");
    let count:i64=c.query_one(&format!("select count(*) from {}.access_memberships m join {}.accounts a on a.id=m.account_id where a.email=$1 and m.tenant_id<>'0'",f.schema,f.schema),&[&"disabled@example.test"]).unwrap().get(0);
    assert_eq!(count, 0);
}
