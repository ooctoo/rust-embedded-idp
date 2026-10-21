use super::registration_email_support::*;
use embedded_idp_storage_postgres::RegistrationEmailPreparation;
use std::sync::{Arc, Barrier};
use std::thread;
use uuid::Uuid;

#[test]
#[ignore = "requires fresh loopback sut_idp3_test with explicit confirmation"]
fn processing_advisory_slots_bound_cross_instance_preparation() {
    let fixture = Arc::new(Fixture::new());
    let mut contexts = Vec::new();
    for index in 0..5 {
        let email = format!("processing-slot-{index}@example.test");
        let accepted = fixture
            .store()
            .register(&fixture.prepared(Uuid::now_v7(), &email, "ProcessingSlotPassword123", None))
            .expect("registration");
        contexts.push(fixture.context_id(&accepted.verification_context));
    }
    fixture
        .adapter
        .connect()
        .expect("fixture connection")
        .batch_execute(&format!(
            "create function {}.sleep_registration_code() returns trigger language plpgsql as $$ begin perform pg_sleep(2); return new; end $$; create trigger sleep_registration_code before insert on {}.registration_email_codes for each row execute function {}.sleep_registration_code()",
            fixture.schema, fixture.schema, fixture.schema
        ))
        .expect("processing slot trigger");
    let barrier = Arc::new(Barrier::new(contexts.len()));
    let mut handles = Vec::new();
    for context in contexts {
        let fixture = Arc::clone(&fixture);
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            barrier.wait();
            fixture.store().prepare(context, 1)
        }));
    }
    let results: Vec<_> = handles
        .into_iter()
        .map(|handle| handle.join().expect("preparation worker"))
        .collect();
    fixture
        .adapter
        .connect()
        .expect("fixture connection")
        .batch_execute(&format!(
            "drop trigger sleep_registration_code on {}.registration_email_codes; drop function {}.sleep_registration_code()",
            fixture.schema, fixture.schema
        ))
        .expect("drop processing slot trigger");
    assert_eq!(
        results
            .iter()
            .filter(|result| **result == Ok(RegistrationEmailPreparation::Prepared))
            .count(),
        4
    );
    assert_eq!(results.iter().filter(|result| result.is_err()).count(), 1);
}
