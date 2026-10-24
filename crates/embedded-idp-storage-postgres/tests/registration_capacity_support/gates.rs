use crate::registration_email_support::Fixture;
use embedded_idp_storage_postgres::PgPooledConnection;
use std::time::{Duration, Instant};

const WAIT_GATE_SQL: &str = r#"
    select a.pid
    from pg_stat_activity a
    where a.backend_type = 'client backend'
      and a.application_name in (
            'registration-email-foundation-live',
            'registration-email-physical-live'
      )
      and a.wait_event_type = 'Lock'
      and a.wait_event = 'advisory'
      and strpos(a.query,$2)>0
      and $1 = any(pg_blocking_pids(a.pid))
      and exists (
            select 1
            from pg_locks l
            where l.pid = a.pid
              and l.locktype = 'relation'
              and l.relation = to_regclass($3)
              and l.granted
      )
    limit 1
"#;

const WAIT_BLOCKER_SQL: &str = r#"
    select a.pid
    from pg_stat_activity a
    where a.backend_type = 'client backend'
      and a.application_name in (
            'registration-email-foundation-live',
            'registration-email-physical-live'
      )
      and a.wait_event_type = 'Lock'
      and strpos(a.query,$2)>0
      and a.query like '%for update%'
      and $1 = any(pg_blocking_pids(a.pid))
      and exists (
            select 1
            from pg_locks l
            where l.pid = $1
              and l.locktype = 'relation'
              and l.relation = to_regclass($3)
              and l.granted
      )
    limit 1
"#;

pub fn install_gate(fixture: &Fixture, phase: &str, key: i64) {
    let phase = match phase {
        "attached" | "cancelled" => phase,
        _ => panic!("unsupported registration capacity gate phase"),
    };
    assert!(
        fixture.schema.starts_with("reg_email_foundation_i1_"),
        "capacity gate requires a fresh owning fixture"
    );
    let mut client = fixture.adapter.connect().expect("capacity gate connection");
    client
        .batch_execute(&format!(
            "create function {schema}.registration_capacity_gate() returns trigger language plpgsql as $$ begin if old.phase='reserved' and new.phase='{phase}' then perform pg_advisory_xact_lock({key}); end if; return new; end $$; create trigger registration_capacity_gate before update on {schema}.registration_email_operations for each row execute function {schema}.registration_capacity_gate()",
            schema = fixture.schema,
            phase = phase,
            key = key,
        ))
        .expect("capacity gate trigger");
}

pub fn hold_gate(fixture: &Fixture, key: i64) -> PgPooledConnection {
    let mut client = fixture.adapter.connect().expect("capacity gate holder");
    client
        .query_one("select pg_advisory_lock($1)", &[&key])
        .expect("capacity gate lock");
    client
}

pub fn wait_gate(fixture: &Fixture, holder: i32, deadline: Instant) -> i32 {
    let relation = format!("{}.registration_email_operations", fixture.schema);
    let query_marker = format!("{}.registration_email_operations", fixture.schema);
    loop {
        assert!(
            Instant::now() < deadline,
            "registration operation advisory gate was not reached"
        );
        let mut observer = fixture.adapter.connect().expect("capacity gate observer");
        if let Some(row) = observer
            .query_opt(WAIT_GATE_SQL, &[&holder, &query_marker, &relation])
            .expect("capacity gate observation")
        {
            return row.get(0);
        }
        drop(observer);
        std::thread::sleep(Duration::from_millis(5));
    }
}

pub fn wait_blocker(fixture: &Fixture, holder: i32, deadline: Instant) -> i32 {
    let relation = format!("{}.registration_email_runtime_state", fixture.schema);
    let query_marker = format!("{}.registration_email_runtime_state", fixture.schema);
    loop {
        assert!(
            Instant::now() < deadline,
            "maintenance runtime lock blocker was not reached"
        );
        let mut observer = fixture.adapter.connect().expect("runtime lock observer");
        if let Some(row) = observer
            .query_opt(WAIT_BLOCKER_SQL, &[&holder, &query_marker, &relation])
            .expect("runtime lock observation")
        {
            return row.get(0);
        }
        drop(observer);
        std::thread::sleep(Duration::from_millis(5));
    }
}
