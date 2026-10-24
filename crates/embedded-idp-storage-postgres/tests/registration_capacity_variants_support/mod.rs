mod facts;
use crate::{
    registration_capacity_support::{fixture, Facts},
    registration_email_support::Fixture,
    registration_transport_support::{
        database, relay_store, Cut, RegistrationStore, Relay, IDENTITY_DEADLINE,
    },
};
use embedded_idp_core::access::{RegistrationEmailError, RegistrationEmailVerification};
use facts::{emit_marker, event_rows, operation_rows, variant_facts};
use std::{
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};
use uuid::Uuid;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum VariantKind {
    Resend,
    Verify,
}

impl VariantKind {
    pub fn number(self) -> i64 {
        match self {
            Self::Resend => 1,
            Self::Verify => 2,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Resend => "resend",
            Self::Verify => "verify",
        }
    }

    pub fn start_delta(self) -> i64 {
        match self {
            Self::Resend => 1,
            Self::Verify => 0,
        }
    }

    pub fn business_result(self) -> i64 {
        match self {
            Self::Resend => 1,
            Self::Verify => 2,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BusinessResult {
    Accepted,
    Unavailable,
}

pub struct VariantSetup {
    pub fixture: Fixture,
    pub operation: Uuid,
    pub token: String,
    pub baseline: Facts,
}

pub struct FaultEvidence {
    pub during: Facts,
    pub pid: i32,
    pub server_state: i32,
    pub elapsed_ms: u128,
    pub physical_eof: bool,
    pub thread_joined: bool,
    pub backend_gone: bool,
    pub forwarded: i64,
}

pub fn setup(kind: VariantKind) -> VariantSetup {
    let fixture = fixture();
    let registration = Uuid::now_v7();
    let prepared = fixture.prepared(
        registration,
        "capacity-variant@example.test",
        "CapacityVariantPassword123",
        None,
    );
    let accepted = fixture
        .store()
        .register(&prepared)
        .expect("valid unprepared context");
    let operation = Uuid::now_v7();
    let baseline = variant_facts(&fixture, kind, operation);
    assert_eq!(baseline.phase, 0);
    assert_eq!(baseline.contexts, 1);
    assert_eq!(baseline.intents, 1);
    assert_eq!(baseline.accounts, 1);
    assert_eq!(baseline.members, 1);
    VariantSetup {
        fixture,
        operation,
        token: accepted.verification_context.expose_secret().to_string(),
        baseline,
    }
}

pub fn invoke(
    store: &RegistrationStore,
    kind: VariantKind,
    operation: Uuid,
    token: &str,
) -> Result<BusinessResult, RegistrationEmailError> {
    match kind {
        VariantKind::Resend => store
            .resend(operation, token)
            .map(|_| BusinessResult::Accepted),
        VariantKind::Verify => {
            store
                .verify(operation, token, "987654")
                .map(|result| match result {
                    RegistrationEmailVerification::Unavailable => BusinessResult::Unavailable,
                    RegistrationEmailVerification::Verified => BusinessResult::Accepted,
                })
        }
    }
}

pub fn wait_selected_backend(fixture: &Fixture, before_forward: bool) -> (i32, i32) {
    let limit = Instant::now() + Duration::from_secs(2);
    loop {
        let row = fixture
            .adapter
            .connect()
            .expect("selected backend connection")
            .query_opt(
                "select pid,case state when 'idle in transaction' then 1 when 'idle' then 2 else 0 end from pg_stat_activity where application_name='registration-email-physical-live' and (($1 and state='idle in transaction') or (not $1 and state='idle' and query='COMMIT')) order by pid desc limit 1",
                &[&before_forward],
            )
            .expect("selected backend query");
        if let Some(row) = row {
            return (row.get(0), row.get(1));
        }
        assert!(Instant::now() < limit, "selected P server state");
        thread::sleep(Duration::from_millis(5));
    }
}

pub fn wait_backend_gone(fixture: &Fixture, pid: i32) -> bool {
    let limit = Instant::now() + Duration::from_secs(2);
    loop {
        let count: i64 = fixture
            .adapter
            .connect()
            .expect("backend disappearance connection")
            .query_one(
                "select count(*) from pg_stat_activity where pid=$1",
                &[&pid],
            )
            .expect("backend disappearance query")
            .get(0);
        if count == 0 {
            return true;
        }
        assert!(Instant::now() < limit, "P backend must end before recovery");
        thread::sleep(Duration::from_millis(10));
    }
}

pub fn run(kind: VariantKind, before_forward: bool) {
    let setup = setup(kind);
    let VariantSetup {
        fixture,
        operation,
        token,
        baseline,
    } = setup;
    let cut = if before_forward {
        Cut::CommitBeforeForward
    } else {
        Cut::Commit
    };
    let mut relay = Relay::new(database(), cut);
    let store = relay_store(&fixture, &relay);
    let token_for_call = token.clone();
    let (send, receive) = mpsc::channel();
    relay.arm_after(0);
    let started = Instant::now();

    let evidence = thread::scope(|scope| {
        let call = scope.spawn(move || {
            let result = invoke(&store, kind, operation, &token_for_call);
            let _ = send.send(result);
        });
        assert!(relay.wait_for_hits(1), "variant P did not reach relay");
        let (pid, server_state) = wait_selected_backend(&fixture, before_forward);
        let during = variant_facts(&fixture, kind, operation);
        assert_eq!(during.phase, if before_forward { 0 } else { 1 });
        assert_eq!(during.fence, if before_forward { 0 } else { 1 });
        assert_eq!(during.reserved, if before_forward { 0 } else { 1 });
        assert_eq!(
            during.charges - baseline.charges,
            i64::from(!before_forward)
        );
        assert_eq!(
            during.start_charges - baseline.start_charges,
            if before_forward {
                0
            } else {
                kind.start_delta()
            },
        );
        assert_eq!(during.contexts - baseline.contexts, 0);
        assert_eq!(during.intents - baseline.intents, 0);
        assert_eq!(during.events - baseline.events, 0);
        assert_eq!(during.accounts, baseline.accounts);
        assert_eq!(during.members, baseline.members);
        assert_eq!(
            operation_rows(&fixture, kind, operation),
            i64::from(!before_forward)
        );
        assert_eq!(event_rows(&fixture, kind, operation), 0);

        let result = receive
            .recv_timeout(IDENTITY_DEADLINE)
            .expect("variant call result");
        assert!(result.is_err(), "blackholed COMMIT must return an error");
        let elapsed_ms = started.elapsed().as_millis();
        assert!((9_500..11_000).contains(&elapsed_ms));
        let physical_eof = relay.wait_for_hit_peer_eof(1);
        assert!(physical_eof);
        let thread_joined = call.join().is_ok();
        assert!(thread_joined);
        let backend_gone = wait_backend_gone(&fixture, pid);
        assert!(backend_gone);
        let forwarded = relay.selected_commit_forwarded() as i64;
        assert_eq!(forwarded, i64::from(!before_forward));
        FaultEvidence {
            during,
            pid,
            server_state,
            elapsed_ms,
            physical_eof,
            thread_joined,
            backend_gone,
            forwarded,
        }
    });
    relay.close();

    let first =
        invoke(&fixture.store(), kind, operation, &token).expect("healthy original-key recovery");
    assert_eq!(
        first,
        if kind == VariantKind::Resend {
            BusinessResult::Accepted
        } else {
            BusinessResult::Unavailable
        }
    );
    let after = variant_facts(&fixture, kind, operation);
    assert_eq!(after.phase, 2);
    assert_eq!(after.fence, 1);
    assert_eq!(operation_rows(&fixture, kind, operation), 1);
    assert_eq!(event_rows(&fixture, kind, operation), 1);
    assert_eq!(after.contexts, baseline.contexts);
    assert_eq!(after.intents, baseline.intents);
    assert_eq!(after.accounts, baseline.accounts);
    assert_eq!(after.members, baseline.members);
    assert_eq!(after.charges - baseline.charges, 1);
    assert_eq!(
        after.start_charges - baseline.start_charges,
        kind.start_delta()
    );

    let replay = invoke(&fixture.store(), kind, operation, &token).expect("healthy replay");
    assert_eq!(replay, first);
    let replay_facts = variant_facts(&fixture, kind, operation);
    let replay_no_extra = replay_facts == after
        && operation_rows(&fixture, kind, operation) == 1
        && event_rows(&fixture, kind, operation) == 1;
    assert!(replay_no_extra);
    emit_marker(
        &fixture,
        kind,
        before_forward,
        &evidence,
        replay_facts,
        baseline,
        replay_no_extra,
    );
    crate::registration_capacity_support::finish(fixture);
}
