//! Real P reservations and production attach/reaper calls over unchanged leases.
#![allow(dead_code, unused_imports)]
mod registration_capacity_support;
mod registration_email_support;
mod registration_transport_support;

use embedded_idp_core::access::RegistrationEmailError;
use registration_capacity_support::*;
use registration_transport_support::{database, relay_store, Cut, Relay};
use serde_json::json;
use std::{
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

#[test]
#[ignore = "requires explicitly confirmed fresh isolated PostgreSQL"]
fn attach_holds_reservation_across_expiry_and_reaper_cannot_cancel() {
    let f = fixture();
    let (op, input, p) = unknown_p(&f, false);
    let key = 912401_i64;
    install_gate(&f, "attached", key);
    let store = f.store();
    let maintenance = f.store();
    thread::scope(|scope| {
        near_expiry(&f, p.lease);
        let mut owner = hold_gate(&f, key);
        let started = Instant::now();
        let deadline = started + Duration::from_millis(900);
        let holder: i32 = owner
            .query_one("select pg_backend_pid()", &[])
            .unwrap()
            .get(0);
        let work = input.clone();
        let (send, recv) = mpsc::channel();
        let attach = scope.spawn(move || {
            let _ = send.send(store.register(&work));
        });
        let attach_pid = wait_gate(&f, holder, deadline);
        wait_until(&f, p.lease);
        let (send, maintained) = mpsc::channel();
        let reaper = scope.spawn(move || {
            let _ = send.send(maintenance.maintain(1));
        });
        let reaper_pid = wait_blocker(&f, attach_pid, deadline);
        let during = facts(&f, op);
        assert_eq!(
            (
                during.phase,
                during.fence,
                during.weight,
                during.contexts,
                during.intents
            ),
            (1, 1, 2, 0, 0)
        );
        owner
            .query_one("select pg_advisory_unlock($1)", &[&key])
            .unwrap();
        drop(owner);
        let gate_elapsed = started.elapsed().as_millis();
        assert!(
            gate_elapsed < 900,
            "gate must stay below original 1s lock timeout"
        );
        let accepted = recv.recv_timeout(Duration::from_secs(3)).unwrap().unwrap();
        assert!(maintained
            .recv_timeout(Duration::from_secs(3))
            .unwrap()
            .is_ok());
        assert!(attach.join().is_ok() && reaper.join().is_ok());
        let after = assert_attached(&f, op, p);
        assert_eq!(
            after.fence, 1,
            "reaper must not cancel attached reservation"
        );
        assert_eq!(
            f.store()
                .register(&input)
                .unwrap()
                .verification_context
                .expose_secret(),
            accepted.verification_context.expose_secret()
        );
        assert_eq!(facts(&f, op), after);
        marker(
            &f,
            5,
            json!({"attach_pid":attach_pid,"reaper_pid":reaper_pid,"gate_elapsed_ms":gate_elapsed,"blocking_edge":true,"natural_lease_expired":true,"phase_during":during.phase,"weight_during":during.weight,"phase_after":after.phase,"fence_after":after.fence,"charges":after.charges,"contexts":after.contexts,"intents":after.intents,"no_early_release":true,"same_key_no_extra":true}),
        );
    });
    finish(f);
}

#[test]
#[ignore = "requires explicitly confirmed fresh isolated PostgreSQL"]
fn reaper_cancels_expired_p_and_old_attach_fence_is_rejected() {
    let f = fixture();
    let (op, input, p) = unknown_p(&f, false);
    let key = 912402_i64;
    install_gate(&f, "cancelled", key);
    let maintenance = f.store();
    thread::scope(|scope| {
        let mut relay = Relay::new(database(), Cut::BeginGate);
        let store = relay_store(&f, &relay);
        let work = input.clone();
        let (send, recv) = mpsc::channel();
        near_expiry(&f, p.lease);
        // Store construction has an inspection transaction; arm afterwards.
        relay.arm_after(2);
        let attach = scope.spawn(move || {
            let _ = send.send(matches!(
                store.register(&work),
                Err(RegistrationEmailError::Unavailable)
            ));
        });
        assert!(relay.wait_for_hits(1));
        assert_eq!((facts(&f, op).phase, facts(&f, op).fence), (1, 1));
        wait_until(&f, p.lease);
        let mut owner = hold_gate(&f, key);
        let started = Instant::now();
        let deadline = started + Duration::from_millis(900);
        let holder: i32 = owner
            .query_one("select pg_backend_pid()", &[])
            .unwrap()
            .get(0);
        let (send, maintained) = mpsc::channel();
        let reaper = scope.spawn(move || {
            let _ = send.send(maintenance.maintain(1));
        });
        let reaper_pid = wait_gate(&f, holder, deadline);
        assert_eq!(
            facts(&f, op).phase,
            1,
            "cancellation is uncommitted while gated"
        );
        owner
            .query_one("select pg_advisory_unlock($1)", &[&key])
            .unwrap();
        drop(owner);
        let gate_elapsed = started.elapsed().as_millis();
        assert!(
            gate_elapsed < 900,
            "gate must stay below original 1s lock timeout"
        );
        assert!(maintained
            .recv_timeout(Duration::from_secs(3))
            .unwrap()
            .is_ok());
        assert!(reaper.join().is_ok());
        let cancelled = facts(&f, op);
        assert_eq!(
            (
                cancelled.phase,
                cancelled.fence,
                cancelled.reserved,
                cancelled.weight,
                cancelled.contexts,
                cancelled.intents,
                cancelled.charges
            ),
            (3, 2, 1, 1, 0, 0, 1)
        );
        relay.release_gate();
        assert!(
            recv.recv_timeout(Duration::from_secs(3)).unwrap(),
            "old fence must fail instead of attach"
        );
        assert!(attach.join().is_ok());
        relay.close();
        assert_eq!(
            facts(&f, op),
            cancelled,
            "rejected old holder must commit no partial effect"
        );
        // Two independent connections explicitly recover the same original key.
        let stores = [f.store(), f.store()];
        let workers: Vec<_> = stores
            .into_iter()
            .map(|store| {
                let input = input.clone();
                scope.spawn(move || store.register(&input))
            })
            .collect();
        let accepted: Vec<_> = workers
            .into_iter()
            .map(|w| w.join().unwrap().unwrap())
            .collect();
        assert_eq!(
            accepted[0].verification_context.expose_secret(),
            accepted[1].verification_context.expose_secret()
        );
        let after = assert_attached(&f, op, p);
        assert_eq!(after.fence, 3);
        marker(
            &f,
            6,
            json!({"reaper_pid":reaper_pid,"gate_elapsed_ms":gate_elapsed,"natural_lease_expired":true,"phase_cancelled":cancelled.phase,"fence_cancelled":cancelled.fence,"weight_cancelled":cancelled.weight,"old_fence_rejected":true,"phase_after":after.phase,"fence_after":after.fence,"charges":after.charges,"contexts":after.contexts,"intents":after.intents,"concurrent_recovery":2,"same_key_no_extra":true}),
        );
    });
    finish(f);
}
