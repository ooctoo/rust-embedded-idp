use super::registration_email_support::*;
use embedded_idp_core::access::RegistrationEmailPolicy;
use embedded_idp_core::SecretString;
use embedded_idp_storage_postgres::{
    PostgresRegistrationEmailStore, PostgresStorageAdapter, RegistrationEmailDeliveryResult,
    RegistrationEmailPreparation,
};
use std::{
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};
use uuid::Uuid;

fn ready(fixture: &Fixture, email: &str) -> (SecretString, Uuid, DeliveryPayload) {
    let accepted = fixture
        .store()
        .register(&fixture.prepared(Uuid::now_v7(), email, "RecoveryPassword123", None))
        .expect("registration");
    let token = accepted.verification_context;
    let context = fixture.context_id(&token);
    assert_eq!(
        fixture.store().prepare(context, 1),
        Ok(RegistrationEmailPreparation::Prepared)
    );
    (token, context, delivery(fixture, context, 1))
}

#[test]
#[ignore = "requires fresh loopback sut_idp3_test with explicit confirmation"]
fn expired_reservation_is_cancelled_then_same_key_retry_reuses_capacity() {
    let fixture = Fixture::new();
    let operation = Uuid::now_v7();
    let prepared = fixture.prepared(operation, "lease@example.test", "LeasePassword123", None);
    let now = fixture.now();
    fixture
        .adapter
        .connect()
        .unwrap()
        .execute(
            &format!(
                "insert into {}.registration_email_operations(authority,product,kind,operation_id,request_digest,phase,reserved_rows,lease_until,fence,retain_until) values($1,$2,'register',$3,$4,'reserved',2,$5,1,$6)",
                fixture.schema
            ),
            &[&AUTHORITY, &PRODUCT, &operation, &prepared.request().as_slice(), &(now - 1), &(now + 1000)],
        )
        .unwrap();
    fixture.store().maintain(1).expect("maintenance");
    assert_eq!(
        operation_phase(&fixture, operation, "register"),
        "cancelled"
    );
    fixture
        .store()
        .register(&prepared)
        .expect("same-key retry after expired reservation");
    assert_eq!(operation_phase(&fixture, operation, "register"), "attached");
    assert_eq!(fixture.count("registration_email_contexts"), 1);
    assert_eq!(capacity_history_lengths(&fixture), (0, 0));
}

#[test]
#[ignore = "requires fresh loopback sut_idp3_test with explicit confirmation"]
fn private_context_lock_returns_without_waiting_for_a_second_authority_operation() {
    let fixture = Fixture::new();
    let accepted = fixture
        .store()
        .register(&fixture.prepared(
            Uuid::now_v7(),
            "private-lock@example.test",
            "PrivateLockPassword123",
            None,
        ))
        .expect("registration");
    let context = fixture.context_id(&accepted.verification_context);
    let mut client = fixture.adapter.connect().unwrap();
    let mut tx = client.transaction().unwrap();
    tx.query_one(
        &format!(
            "select id from {}.registration_email_contexts where id=$1 for update",
            fixture.schema
        ),
        &[&context],
    )
    .unwrap();
    let (sender, receiver) = mpsc::channel();
    let started = Instant::now();
    let other = FixtureHandle::from(&fixture);
    thread::spawn(move || {
        sender.send(other.store().prepare(context, 1)).unwrap();
    });
    let result = receiver
        .recv_timeout(Duration::from_secs(3))
        .expect("private context lock must be bounded");
    assert!(started.elapsed() < Duration::from_secs(3));
    assert!(result.is_err());
    drop(tx);
    drop(client);
}

#[test]
#[ignore = "requires fresh loopback sut_idp3_test with explicit confirmation"]
fn private_account_lock_returns_without_waiting_for_activation() {
    let fixture = Fixture::with_existing_account();
    let accepted = fixture
        .store()
        .register(&fixture.prepared(
            Uuid::now_v7(),
            EXISTING_EMAIL,
            "AccountLockPassword123",
            None,
        ))
        .expect("registration");
    let token = accepted.verification_context;
    let context = fixture.context_id(&token);
    fixture.store().prepare(context, 1).expect("preparation");
    let code = delivery(&fixture, context, 1).code;
    let account: Uuid = fixture
        .adapter
        .connect()
        .unwrap()
        .query_one(
            &format!("select id from {}.accounts where email=$1", fixture.schema),
            &[&EXISTING_EMAIL],
        )
        .unwrap()
        .get(0);
    let mut client = fixture.adapter.connect().unwrap();
    let mut tx = client.transaction().unwrap();
    tx.query_one(
        &format!(
            "select id from {}.accounts where id=$1 for update",
            fixture.schema
        ),
        &[&account],
    )
    .unwrap();
    let (sender, receiver) = mpsc::channel();
    let started = Instant::now();
    let other = FixtureHandle::from(&fixture);
    thread::spawn(move || {
        sender
            .send(
                other
                    .store()
                    .verify(Uuid::now_v7(), token.expose_secret(), code.expose_secret()),
            )
            .unwrap();
    });
    let result = receiver
        .recv_timeout(Duration::from_secs(3))
        .expect("private account lock must be bounded");
    assert!(started.elapsed() < Duration::from_secs(3));
    assert!(result.is_err());
    drop(tx);
    drop(client);
}

#[test]
#[ignore = "requires fresh loopback sut_idp3_test with explicit confirmation"]
fn unknown_smtp_delivery_occupies_one_slot_until_stop_confirmation() {
    let fixture = Fixture::new();
    let (_, _, first_payload) = ready(&fixture, "smtp-one@example.test");
    let mut first_claim = claim(&fixture, first_payload.effect_id);
    fixture.expire_delivery_claim(&mut first_claim);
    fixture.store().maintain(1).expect("maintenance");
    let (_, _, second_payload) = ready(&fixture, "smtp-two@example.test");
    let second_claim = claim(&fixture, second_payload.effect_id);
    let (_, _, third_payload) = ready(&fixture, "smtp-three@example.test");
    assert!(fixture
        .store()
        .claim_delivery(third_payload.effect_id)
        .unwrap()
        .is_none());
    fixture
        .store()
        .confirm_delivery_stopped(&first_claim)
        .expect("stop unknown delivery");
    fixture
        .store()
        .finish_delivery(&second_claim, RegistrationEmailDeliveryResult::Sent)
        .expect("finish second delivery");
    assert!(fixture
        .store()
        .claim_delivery(third_payload.effect_id)
        .unwrap()
        .is_some());
}

struct FixtureHandle {
    adapter: PostgresStorageAdapter,
    scope: embedded_idp_core::access::RegistrationEmailScope,
    crypto: std::sync::Arc<embedded_idp_security::RingRegistrationEmailCrypto>,
}

impl From<&Fixture> for FixtureHandle {
    fn from(fixture: &Fixture) -> Self {
        Self {
            adapter: fixture.adapter.clone(),
            scope: fixture.scope.clone(),
            crypto: fixture.crypto.clone(),
        }
    }
}

impl FixtureHandle {
    fn store(
        &self,
    ) -> PostgresRegistrationEmailStore<embedded_idp_security::RingRegistrationEmailCrypto> {
        PostgresRegistrationEmailStore::new(
            self.adapter.clone(),
            self.scope.clone(),
            RegistrationEmailPolicy::default(),
            self.crypto.clone(),
        )
        .expect("registration store")
    }
}
