use super::registration_email_support::*;
use embedded_idp_core::access::{
    PreparedRegistrationEmail, RegistrationEmailPolicy, RegistrationEmailScope,
};
use embedded_idp_core::SecretString;
use embedded_idp_security::RingRegistrationEmailCrypto;
use embedded_idp_storage_postgres::{PostgresRegistrationEmailStore, RegistrationEmailPreparation};
use uuid::Uuid;

fn capped_store(
    fixture: &Fixture,
    scope: RegistrationEmailScope,
) -> PostgresRegistrationEmailStore<RingRegistrationEmailCrypto> {
    let mut policy = RegistrationEmailPolicy::default();
    policy.product_subject_bucket_cap = 1;
    PostgresRegistrationEmailStore::new(
        fixture.adapter.clone(),
        scope,
        policy,
        fixture.crypto.clone(),
    )
    .expect("registration store")
}

fn prepare_for_scope(
    fixture: &Fixture,
    scope: &RegistrationEmailScope,
    operation: Uuid,
    email: &str,
) -> PreparedRegistrationEmail {
    PreparedRegistrationEmail::prepare(
        scope,
        fixture.crypto.as_ref(),
        operation,
        email,
        &SecretString::new("BoundaryPassword123"),
        None,
    )
    .expect("prepared registration")
}

fn bucket_count(fixture: &Fixture, product: &str) -> i64 {
    fixture
        .adapter
        .connect()
        .expect("fixture connection")
        .query_one(
            &format!(
                "select count(*) from {}.registration_email_buckets where authority=$1 and product=$2",
                fixture.schema
            ),
            &[&AUTHORITY, &product],
        )
        .expect("bucket count")
        .get(0)
}

fn delivery_state(fixture: &Fixture, effect: Uuid) -> (String, bool, i64) {
    let row = fixture
        .adapter
        .connect()
        .expect("fixture connection")
        .query_one(
            &format!(
                "select status,stop_confirmed,octet_length(payload_cipher)::bigint from {}.registration_email_deliveries where id=$1",
                fixture.schema
            ),
            &[&effect],
        )
        .expect("delivery state");
    (row.get(0), row.get(1), row.get(2))
}

fn delivery_lease(fixture: &Fixture, effect: Uuid) -> Option<i64> {
    fixture
        .adapter
        .connect()
        .expect("fixture connection")
        .query_one(
            &format!(
                "select lease_until from {}.registration_email_deliveries where id=$1",
                fixture.schema
            ),
            &[&effect],
        )
        .expect("delivery lease")
        .get(0)
}

fn event_kind_and_reason(fixture: &Fixture, operation: Uuid) -> (String, String) {
    let row = fixture
        .adapter
        .connect()
        .expect("fixture connection")
        .query_one(
            &format!(
                "select kind,reason from {}.registration_email_events where operation_id=$1 order by created_at desc,id desc limit 1",
                fixture.schema
            ),
            &[&operation],
        )
        .expect("delivery event");
    (row.get(0), row.get(1))
}

fn password_cipher_len(fixture: &Fixture, context: Uuid) -> i64 {
    fixture
        .adapter
        .connect()
        .expect("fixture connection")
        .query_one(
            &format!(
                "select octet_length(password_cipher)::bigint from {}.registration_email_contexts where id=$1",
                fixture.schema
            ),
            &[&context],
        )
        .expect("candidate material")
        .get(0)
}

fn context_exists(fixture: &Fixture, context: Uuid) -> bool {
    fixture
        .adapter
        .connect()
        .expect("fixture connection")
        .query_one(
            &format!(
                "select exists(select 1 from {}.registration_email_contexts where id=$1)",
                fixture.schema
            ),
            &[&context],
        )
        .expect("context existence")
        .get(0)
}

fn set_operation_retention(fixture: &Fixture, operation: Uuid, retain_until: i64) {
    fixture
        .adapter
        .connect()
        .expect("fixture connection")
        .execute(
            &format!(
                "update {}.registration_email_operations set retain_until=$2 where authority=$3 and product=$4 and kind='register' and operation_id=$1",
                fixture.schema
            ),
            &[&operation, &retain_until, &AUTHORITY, &PRODUCT],
        )
        .expect("operation retention");
}

fn expired_prepared_context(fixture: &Fixture, email: &str, operation: Uuid) -> Uuid {
    let accepted = fixture
        .store()
        .register(&fixture.prepared(operation, email, "BoundaryPassword123", None))
        .expect("registration");
    let context = fixture.context_id(&accepted.verification_context);
    assert_eq!(
        fixture.store().prepare(context, 1),
        Ok(RegistrationEmailPreparation::Prepared)
    );
    context
}

#[path = "cases_storage_boundaries/delivery_claim.rs"]
mod delivery_claim;
#[path = "cases_storage_boundaries/maintenance.rs"]
mod maintenance;
#[path = "cases_storage_boundaries/product_cap.rs"]
mod product_cap;
#[path = "cases_storage_boundaries/registration_closed.rs"]
mod registration_closed;
