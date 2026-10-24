mod gates;
use crate::{registration_email_support::Fixture, registration_transport_support::*};
use embedded_idp_core::access::{PreparedRegistrationEmail, RegistrationEmailPolicy};
use embedded_idp_storage_postgres::PgPooledConnection;
pub use gates::{hold_gate, install_gate, wait_blocker, wait_gate};
use serde_json::{json, Value};
use std::{
    sync::{mpsc, Arc},
    thread,
    time::{Duration, Instant},
};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Facts {
    pub phase: i32,
    pub fence: i64,
    pub lease: i64,
    pub reserved: i64,
    pub contexts: i64,
    pub intents: i64,
    pub events: i64,
    pub charges: i64,
    pub start_charges: i64,
    pub weight: i64,
    pub sends: i64,
    pub accounts: i64,
    pub members: i64,
}

pub fn facts(f: &Fixture, operation: Uuid) -> Facts {
    let sql = format!("SELECT
        coalesce((select case phase when 'reserved' then 1 when 'attached' then 2 when 'cancelled' then 3 end from {s}.registration_email_operations where operation_id=$1 and authority=$2 and product=$3 and kind='register'),0),
        coalesce((select fence from {s}.registration_email_operations where operation_id=$1 and authority=$2 and product=$3 and kind='register'),0),
        coalesce((select lease_until from {s}.registration_email_operations where operation_id=$1 and authority=$2 and product=$3 and kind='register'),0),
        coalesce((select reserved_rows from {s}.registration_email_operations where operation_id=$1 and authority=$2 and product=$3 and kind='register'),0),
        (select count(*) from {s}.registration_email_contexts),
        (select count(*) from {s}.registration_email_intents),
        (select count(*) from {s}.registration_email_events where operation_id=$1 and authority=$2 and product=$3 and kind='register'),
        (select cardinality(all_times)::bigint from {s}.registration_email_capacity),
        (select cardinality(start_times)::bigint from {s}.registration_email_capacity),
        (select count(*) from {s}.registration_email_contexts)+(select coalesce(sum(case when phase='attached' then 1 else reserved_rows end),0)::bigint from {s}.registration_email_operations where kind<>'verify'),
        (select coalesce(sum(cardinality(sends)),0)::bigint from {s}.registration_email_subjects),
        (select count(*) from {s}.accounts),(select count(*) from {s}.access_memberships)",s=f.schema);
    let r = f
        .adapter
        .connect()
        .unwrap()
        .query_one(&sql, &[&operation, &f.scope.authority, &f.scope.product])
        .unwrap();
    Facts {
        phase: r.get(0),
        fence: r.get(1),
        lease: r.get(2),
        reserved: r.get(3),
        contexts: r.get(4),
        intents: r.get(5),
        events: r.get(6),
        charges: r.get(7),
        start_charges: r.get(8),
        weight: r.get(9),
        sends: r.get(10),
        accounts: r.get(11),
        members: r.get(12),
    }
}

pub fn fixture() -> Fixture {
    let f = Fixture::new();
    install_runtime_and_resume(&f);
    f
}

pub fn marker(f: &Fixture, stage: u8, value: Value) {
    eprintln!(
        "SUT_IDP_CAPACITY {}",
        json!({
            "fixture":f.schema.trim_start_matches("reg_email_foundation_i1_"),
            "test":thread::current().name().unwrap_or("unnamed"),"stage":stage,"facts":value
        })
    );
}

pub fn assert_attached(f: &Fixture, operation: Uuid, baseline: Facts) -> Facts {
    let v = facts(f, operation);
    assert_eq!(
        (
            v.phase,
            v.contexts,
            v.intents,
            v.events,
            v.charges,
            v.start_charges,
            v.weight,
            v.sends
        ),
        (2, 1, 1, 1, 1, 1, 2, 1)
    );
    assert_eq!(
        (v.accounts, v.members),
        (baseline.accounts, baseline.members)
    );
    assert_eq!(f.count("registration_email_operations"), 1);
    assert_eq!(f.count("registration_email_codes"), 0);
    assert_eq!(f.count("registration_email_deliveries"), 0);
    v
}

pub fn prepared(f: &Fixture, operation: Uuid) -> Arc<PreparedRegistrationEmail> {
    Arc::new(f.prepared(
        operation,
        "p-capacity@example.test",
        "CapacityPassword123",
        None,
    ))
}

pub fn wait_until(f: &Fixture, at: i64) {
    let limit = Instant::now() + Duration::from_secs(35);
    while f.now() < at {
        assert!(Instant::now() < limit, "natural reservation lease deadline");
        thread::sleep(Duration::from_millis(20));
    }
}

pub fn near_expiry(f: &Fixture, lease: i64) {
    // The default 30s lease is not changed or synthetically shifted.
    // Enter A while valid, leaving <1s for the test advisory gate.
    let limit = Instant::now() + Duration::from_secs(35);
    loop {
        let at: f64 = f
            .adapter
            .connect()
            .unwrap()
            .query_one(
                "select extract(epoch from clock_timestamp())::double precision",
                &[],
            )
            .unwrap()
            .get(0);
        if at >= lease as f64 - 0.5 {
            assert!(at < lease as f64, "A must start before natural expiry");
            return;
        }
        assert!(Instant::now() < limit, "natural reservation lease");
        thread::sleep(Duration::from_millis(10));
    }
}

/// P is the first COMMIT: an empty early-operation read drops/rolls back.
pub fn unknown_p(
    f: &Fixture,
    before_forward: bool,
) -> (Uuid, Arc<PreparedRegistrationEmail>, Facts) {
    thread::scope(|scope| {
        let operation = Uuid::now_v7();
        let input = prepared(f, operation);
        let baseline = facts(f, operation);
        let cut = if before_forward {
            Cut::CommitBeforeForward
        } else {
            Cut::Commit
        };
        let mut relay = Relay::new(database(), cut);
        let store = relay_store(f, &relay);
        let work = input.clone();
        let (send, recv) = mpsc::channel();
        relay.arm_after(0);
        let started = Instant::now();
        let call = scope.spawn(move || {
            let _ = send.send(store.register(&work).is_err());
        });
        assert!(relay.wait_for_hits(1));
        let limit = Instant::now() + Duration::from_secs(2);
        let (pid, state) = loop {
            let r=f.adapter.connect().unwrap().query_opt("select pid,case state when 'idle in transaction' then 1 when 'idle' then 2 else 0 end from pg_stat_activity where application_name='registration-email-physical-live' and (($1 and state='idle in transaction') or (not $1 and state='idle' and query='COMMIT')) order by pid desc limit 1",&[&before_forward]).unwrap();
            if let Some(r) = r {
                break (r.get::<_, i32>(0), r.get::<_, i32>(1));
            }
            assert!(Instant::now() < limit, "selected P server state");
            thread::sleep(Duration::from_millis(5));
        };
        let during = facts(f, operation);
        let policy_lease = RegistrationEmailPolicy::default().capacity_reservation_lease_secs;
        let remaining = if before_forward {
            0
        } else {
            during.lease - f.now()
        };
        assert_eq!(policy_lease, 30);
        if !before_forward {
            assert!((28..=30).contains(&remaining));
        }
        if before_forward {
            assert_eq!(during, baseline);
        } else {
            assert_eq!(
                (
                    during.phase,
                    during.fence,
                    during.reserved,
                    during.contexts,
                    during.intents,
                    during.events,
                    during.charges,
                    during.start_charges,
                    during.weight
                ),
                (1, 1, 2, 0, 0, 0, 1, 1, 2)
            );
        }
        assert!(recv.recv_timeout(IDENTITY_DEADLINE).unwrap());
        let elapsed = started.elapsed().as_millis();
        assert!(relay.wait_for_hit_peer_eof(1));
        assert!(call.join().is_ok());
        assert!((9500..11000).contains(&elapsed));
        let forwarded = relay.selected_commit_forwarded();
        assert_eq!(forwarded, usize::from(!before_forward));
        // Observe real server exit before teardown, independently from client EOF.
        let limit = Instant::now() + Duration::from_secs(2);
        loop {
            let n: i64 = f
                .adapter
                .connect()
                .unwrap()
                .query_one(
                    "select count(*) from pg_stat_activity where pid=$1",
                    &[&pid],
                )
                .unwrap()
                .get(0);
            if n == 0 {
                break;
            }
            assert!(Instant::now() < limit, "P backend must end before recovery");
            thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(facts(f, operation), during);
        marker(
            f,
            if before_forward { 0 } else { 1 },
            json!({"backend_pid":pid,"server_state":state,"selected_commit_forwarded":forwarded,"elapsed_ms":elapsed,"physical_eof":true,"thread_joined":true,"backend_gone":true,"phase":during.phase,"fence":during.fence,"reserved_rows":during.reserved,"charges":during.charges,"start_charges":during.start_charges,"weighted_rows":during.weight,"contexts":during.contexts,"intents":during.intents,"events":during.events,"policy_lease_secs":policy_lease,"lease_remaining_secs":remaining}),
        );
        relay.close();
        (operation, input, during)
    })
}

pub fn finish(f: Fixture) {
    let adapter = f.adapter.clone();
    let schema = f.schema.clone();
    drop(f);
    let count: i64 = adapter
        .connect()
        .unwrap()
        .query_one(
            "select count(*) from pg_namespace where nspname=$1",
            &[&schema],
        )
        .unwrap()
        .get(0);
    assert_eq!(count, 0, "strict owning schema cleanup");
}
