use super::fixture::Fixture;
use uuid::Uuid;

pub fn wrong_counts(fixture: &Fixture, context: Uuid) -> (i32, i64, i64) {
    let row = fixture
        .adapter
        .connect()
        .expect("fixture connection")
        .query_one(
            &format!(
                "select c.wrong_count, cardinality(s.wrongs)::bigint, cardinality(b.wrongs)::bigint from {}.registration_email_contexts c join {}.registration_email_subjects s on s.authority=c.authority and s.subject=c.subject join {}.registration_email_buckets b on b.authority=c.authority and b.product=c.product and b.subject=c.subject where c.id=$1",
                fixture.schema, fixture.schema, fixture.schema
            ),
            &[&context],
        )
        .expect("wrong counters");
    (row.get(0), row.get(1), row.get(2))
}

pub fn send_history_lengths(fixture: &Fixture) -> (i32, i32) {
    let row = fixture
        .adapter
        .connect()
        .expect("fixture connection")
        .query_one(
            &format!(
                "select coalesce((select cardinality(sends) from {}.registration_email_subjects where authority=$1),0), coalesce((select cardinality(sends) from {}.registration_email_buckets where authority=$1 and product=$2),0)",
                fixture.schema, fixture.schema
            ),
            &[&super::fixture::AUTHORITY, &super::fixture::PRODUCT],
        )
        .expect("send history");
    (row.get(0), row.get(1))
}

pub fn capacity_history_lengths(fixture: &Fixture) -> (i32, i32) {
    let row = fixture
        .adapter
        .connect()
        .expect("fixture connection")
        .query_one(
            &format!(
                "select cardinality(all_times), cardinality(start_times) from {}.registration_email_capacity where authority=$1",
                fixture.schema
            ),
            &[&super::fixture::AUTHORITY],
        )
        .expect("capacity history");
    (row.get(0), row.get(1))
}

pub fn context_row(fixture: &Fixture, context: Uuid) -> (bool, i64, Option<i64>, bool) {
    let row = fixture
        .adapter
        .connect()
        .expect("fixture connection")
        .query_one(
            &format!(
                "select deliverable,accepted_seq,current_seq,prepared from {}.registration_email_contexts where id=$1",
                fixture.schema
            ),
            &[&context],
        )
        .expect("context row");
    (row.get(0), row.get(1), row.get(2), row.get(3))
}

pub fn status_for_email(fixture: &Fixture, email: &str) -> Option<(Uuid, String)> {
    fixture
        .adapter
        .connect()
        .expect("fixture connection")
        .query_opt(
            &format!(
                "select id,status from {}.accounts where email=$1",
                fixture.schema
            ),
            &[&email],
        )
        .expect("account row")
        .map(|row| (row.get(0), row.get(1)))
}

pub fn operation_phase(fixture: &Fixture, operation: Uuid, kind: &str) -> String {
    fixture
        .adapter
        .connect()
        .expect("fixture connection")
        .query_one(
            &format!(
                "select phase from {}.registration_email_operations where authority=$1 and product=$2 and kind=$3 and operation_id=$4",
                fixture.schema
            ),
            &[&super::fixture::AUTHORITY, &super::fixture::PRODUCT, &kind, &operation],
        )
        .expect("operation row")
        .get(0)
}

pub fn intent_status(fixture: &Fixture, context: Uuid, sequence: i64) -> String {
    fixture
        .adapter
        .connect()
        .expect("fixture connection")
        .query_one(
            &format!(
                "select status from {}.registration_email_intents where context_id=$1 and seq=$2",
                fixture.schema
            ),
            &[&context, &sequence],
        )
        .expect("intent row")
        .get(0)
}
