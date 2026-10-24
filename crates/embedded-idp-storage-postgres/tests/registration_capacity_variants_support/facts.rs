use crate::{
    registration_capacity_support::Facts, registration_capacity_variants_support::VariantKind,
    registration_email_support::Fixture,
};
use serde_json::json;
use std::thread;
use uuid::Uuid;

pub fn variant_facts(fixture: &Fixture, kind: VariantKind, operation: Uuid) -> Facts {
    let sql = format!(
        "SELECT
        coalesce((select case phase when 'reserved' then 1 when 'attached' then 2 when 'cancelled' then 3 end from {s}.registration_email_operations where operation_id=$1 and authority=$2 and product=$3 and kind=$4),0),
        coalesce((select fence from {s}.registration_email_operations where operation_id=$1 and authority=$2 and product=$3 and kind=$4),0),
        coalesce((select lease_until from {s}.registration_email_operations where operation_id=$1 and authority=$2 and product=$3 and kind=$4),0),
        coalesce((select reserved_rows from {s}.registration_email_operations where operation_id=$1 and authority=$2 and product=$3 and kind=$4),0),
        (select count(*) from {s}.registration_email_contexts),
        (select count(*) from {s}.registration_email_intents),
        (select count(*) from {s}.registration_email_events where operation_id=$1 and authority=$2 and product=$3 and kind=$4),
        (select cardinality(all_times)::bigint from {s}.registration_email_capacity),
        (select cardinality(start_times)::bigint from {s}.registration_email_capacity),
        (select count(*) from {s}.registration_email_contexts)+(select coalesce(sum(case when phase='attached' then 1 else reserved_rows end),0)::bigint from {s}.registration_email_operations where kind<>'verify'),
        (select coalesce(sum(cardinality(sends)),0)::bigint from {s}.registration_email_subjects),
        (select count(*) from {s}.accounts),(select count(*) from {s}.access_memberships)",
        s = fixture.schema
    );
    let row = fixture
        .adapter
        .connect()
        .expect("variant facts connection")
        .query_one(
            &sql,
            &[
                &operation,
                &fixture.scope.authority,
                &fixture.scope.product,
                &kind.name(),
            ],
        )
        .expect("variant facts query");
    Facts {
        phase: row.get(0),
        fence: row.get(1),
        lease: row.get(2),
        reserved: row.get(3),
        contexts: row.get(4),
        intents: row.get(5),
        events: row.get(6),
        charges: row.get(7),
        start_charges: row.get(8),
        weight: row.get(9),
        sends: row.get(10),
        accounts: row.get(11),
        members: row.get(12),
    }
}

pub fn operation_rows(fixture: &Fixture, kind: VariantKind, operation: Uuid) -> i64 {
    fixture
        .adapter
        .connect()
        .expect("operation row connection")
        .query_one(
            &format!(
                "select count(*) from {}.registration_email_operations where authority=$1 and product=$2 and kind=$3 and operation_id=$4",
                fixture.schema
            ),
            &[&fixture.scope.authority, &fixture.scope.product, &kind.name(), &operation],
        )
        .expect("operation row query")
        .get(0)
}

pub fn event_rows(fixture: &Fixture, kind: VariantKind, operation: Uuid) -> i64 {
    fixture
        .adapter
        .connect()
        .expect("event row connection")
        .query_one(
            &format!(
                "select count(*) from {}.registration_email_events where authority=$1 and product=$2 and kind=$3 and operation_id=$4",
                fixture.schema
            ),
            &[&fixture.scope.authority, &fixture.scope.product, &kind.name(), &operation],
        )
        .expect("event row query")
        .get(0)
}

pub fn emit_marker(
    fixture: &Fixture,
    kind: VariantKind,
    before_forward: bool,
    evidence: &super::FaultEvidence,
    after: Facts,
    baseline: Facts,
    replay_no_extra: bool,
) {
    let during = evidence.during;
    eprintln!(
        "SUT_IDP_CAPACITY_VARIANT {}",
        json!({
            "fixture": fixture.schema.trim_start_matches("reg_email_foundation_i1_"),
            "test": thread::current().name().unwrap_or("unnamed"),
            "kind": kind.number(),
            "before_forward": before_forward,
            "backend_pid": evidence.pid,
            "server_state": evidence.server_state,
            "forwarded": evidence.forwarded,
            "elapsed_ms": evidence.elapsed_ms,
            "physical_eof": evidence.physical_eof,
            "thread_joined": evidence.thread_joined,
            "backend_gone": evidence.backend_gone,
            "phase_during": during.phase,
            "fence_during": during.fence,
            "reserved_rows_during": during.reserved,
            "all_charge_delta": during.charges - baseline.charges,
            "start_charge_delta": during.start_charges - baseline.start_charges,
            "contexts_delta": during.contexts - baseline.contexts,
            "intents_delta": during.intents - baseline.intents,
            "events_during": during.events - baseline.events,
            "accounts_unchanged": during.accounts == baseline.accounts && after.accounts == baseline.accounts,
            "phase_after": after.phase,
            "fence_after": after.fence,
            "receipt_rows": 1,
            "charges_after_delta": after.charges - baseline.charges,
            "starts_after_delta": after.start_charges - baseline.start_charges,
            "replay_no_extra": replay_no_extra,
            "business_result": kind.business_result(),
        })
    );
}
