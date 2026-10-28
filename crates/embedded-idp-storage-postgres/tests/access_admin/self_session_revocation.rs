use super::*;
use base64ct::{Base64UrlUnpadded, Encoding};
use embedded_idp_core::access::{
    AccessActor, AccessError, CoreSelfSessionRevocationService, SecurityReceiptQuery,
    SelfSessionRevocationService, SelfSessionRevokeCommand,
};
use embedded_idp_core::SecretString;
use embedded_idp_security::{AccountSecurityKeySet, RingAccountSecurityCrypto};

const AUTHORITY: &str = "phase-one-test";

fn install(db: &Db) {
    let foundation = db
        .adapter
        .plan_security_foundation(db.mode, AUTHORITY)
        .unwrap();
    db.adapter.apply_security_foundation(&foundation).unwrap();
    let runtime = db
        .adapter
        .plan_security_runtime(db.mode, AUTHORITY)
        .unwrap();
    db.adapter.apply_security_runtime(&runtime).unwrap();
}

fn key_set(id: &str, start: u8) -> AccountSecurityKeySet {
    AccountSecurityKeySet::new(
        id.to_owned(),
        [start; 32],
        [start + 1; 32],
        [start + 2; 32],
        [start + 3; 32],
    )
}

fn crypto(current: (&str, u8), previous: Option<(&str, u8)>) -> RingAccountSecurityCrypto {
    RingAccountSecurityCrypto::new(
        AUTHORITY.into(),
        [200; 32],
        key_set(current.0, current.1),
        previous.map(|(id, start)| key_set(id, start)),
    )
    .unwrap()
}

fn service(
    db: &Db,
    crypt: RingAccountSecurityCrypto,
) -> CoreSelfSessionRevocationService<
    PostgresAccessStore,
    FixedClock,
    RingAccountSecurityCrypto,
    UuidIds,
> {
    CoreSelfSessionRevocationService::new(db.mode, db.store(), FixedClock, crypt, UuidIds)
}

fn actor(db: &Db, session: Uuid) -> AccessActor {
    AccessActor {
        tenant_id: "0".into(),
        subject_id: db.actor.to_string(),
        session_id: session.to_string(),
    }
}

fn secret(byte: u8) -> SecretString {
    SecretString::new(Base64UrlUnpadded::encode_string(&[byte; 32]))
}

fn command(
    tenant: &str,
    target: Uuid,
    operation: Uuid,
    secret: SecretString,
) -> SelfSessionRevokeCommand {
    SelfSessionRevokeCommand {
        target_tenant_id: tenant.to_owned(),
        target_session_id: target.to_string(),
        operation_id: operation,
        receipt_secret: secret,
    }
}

fn add_actor_tenant_memberships(db: &Db) {
    if db.mode == TenancyMode::Enabled {
        let mut client = db.adapter.connect().unwrap();
        for tenant in ["t1", "t2"] {
            client
                .execute(
                    &format!("insert into {}.access_memberships(tenant_id,account_id,status,joined_at_epoch) values($1,$2,'active',$3)", db.schema()),
                    &[&tenant, &db.actor, &(NOW as i64)],
                )
                .unwrap();
        }
    }
}

fn insert_session(
    db: &Db,
    tenant: &str,
    session: Uuid,
    subject: Uuid,
    purpose: &str,
    status: &str,
    expires: i64,
) {
    let s = db.schema();
    db.adapter
        .connect()
        .unwrap()
        .execute(
            &format!("insert into {s}.auth_sessions(purpose,tenant_id,id,account_id,client_id,status,created_at_epoch,expires_at_epoch,refresh_token_version,authenticated_at_epoch) values($1,$2,$3,$4,'live-admin-client',$5,900,$6,1,900)"),
            &[&purpose, &tenant, &session, &subject, &status, &expires],
        )
        .unwrap();
}

fn insert_auth_artifacts(db: &Db, tenant: &str, session: Uuid, subject: Uuid, seed: u8) {
    let s = db.schema();
    let mut client = db.adapter.connect().unwrap();
    client.execute(&format!("insert into {s}.refresh_tokens(tenant_id,id,session_id,token_digest,token_version,issued_at_epoch,expires_at_epoch) values($1,$2,$3,$4,1,900,1900)"), &[&tenant, &Uuid::now_v7(), &session, &&[seed; 32][..]]).unwrap();
    client.execute(&format!("insert into {s}.authorization_codes(tenant_id,code_digest,account_id,source_session_id,login_entry,client_id,redirect_uri,scope,created_at_epoch,expires_at_epoch) values($1,$2,$3,$4,'self-revoke-test','live-admin-client','https://example.test/callback','openid',900,1200)"), &[&tenant, &&[seed + 1; 32][..], &subject, &session]).unwrap();
    client.execute(&format!("insert into {s}.auth_tenant_selections(id,ticket_digest,account_id,client_id,login_entry,purpose,authenticated_at_epoch,expires_at_epoch,source_tenant_id,source_session_id) values($1,$2,$3,'live-admin-client','self-revoke-test','tenant_selection',900,1200,$4,$5)"), &[&Uuid::now_v7(), &&[seed + 2; 32][..], &subject, &tenant, &session]).unwrap();
}

fn session_status(db: &Db, tenant: &str, session: Uuid) -> String {
    db.adapter
        .connect()
        .unwrap()
        .query_one(
            &format!(
                "select status from {}.auth_sessions where tenant_id=$1 and id=$2",
                db.schema()
            ),
            &[&tenant, &session],
        )
        .unwrap()
        .get(0)
}

fn receipt_count(db: &Db, operation: Uuid) -> i64 {
    db.adapter
        .connect()
        .unwrap()
        .query_one(
            &format!("select count(*) from {}.security_receipts where purpose='session_revoke' and operation_id=$1", db.schema()),
            &[&operation],
        )
        .unwrap()
        .get(0)
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn self_session_revoke_is_owner_and_composite_tenant_scoped_in_both_modes() {
    for mode in [TenancyMode::Disabled, TenancyMode::Enabled] {
        let db = Db::new(mode);
        install(&db);
        add_actor_tenant_memberships(&db);
        let tenant = db.target();
        let target = Uuid::now_v7();
        insert_session(&db, tenant, target, db.actor, "business", "active", 2_000);
        insert_auth_artifacts(&db, tenant, target, db.actor, 31);
        let other_tenant_session = if mode == TenancyMode::Enabled {
            // Same UUID in a different tenant proves all writes use the full key.
            insert_session(&db, "t2", target, db.actor, "business", "active", 2_000);
            insert_auth_artifacts(&db, "t2", target, db.actor, 41);
            Some("t2")
        } else {
            None
        };

        let crypt = crypto(("current", 10), None);
        let service = service(&db, crypt);
        let secret_value = secret(51);
        let operation = Uuid::now_v7();
        service
            .revoke_session(
                actor(&db, db.actor_session),
                command(tenant, target, operation, secret_value.clone()),
            )
            .unwrap();

        assert_eq!(session_status(&db, tenant, target), "revoked");
        let mut c = db.adapter.connect().unwrap();
        let target_artifacts = c.query_one(
            &format!("select r.revocation_reason,(select count(*) from {s}.authorization_codes x where x.tenant_id=$1 and x.source_session_id=$2),(select revoked_at_epoch is not null from {s}.auth_tenant_selections x where x.source_tenant_id=$1 and x.source_session_id=$2) from {s}.refresh_tokens r where r.tenant_id=$1 and r.session_id=$2", s=db.schema()),
            &[&tenant, &target],
        ).unwrap();
        assert_eq!(target_artifacts.get::<_, String>(0), "administrative");
        assert_eq!(target_artifacts.get::<_, i64>(1), 0);
        assert!(target_artifacts.get::<_, bool>(2));
        if let Some(other_tenant) = other_tenant_session {
            assert_eq!(session_status(&db, other_tenant, target), "active");
            let other_refresh: Option<i64> = c.query_one(&format!("select revoked_at_epoch from {s}.refresh_tokens where tenant_id=$1 and session_id=$2", s=db.schema()), &[&other_tenant, &target]).unwrap().get(0);
            assert!(other_refresh.is_none());
            assert_eq!(c.query_one(&format!("select count(*) from {s}.authorization_codes where tenant_id=$1 and source_session_id=$2", s=db.schema()), &[&other_tenant, &target]).unwrap().get::<_, i64>(0), 1);
            let other_selection: Option<i64> = c.query_one(&format!("select revoked_at_epoch from {s}.auth_tenant_selections where source_tenant_id=$1 and source_session_id=$2", s=db.schema()), &[&other_tenant, &target]).unwrap().get(0);
            assert!(other_selection.is_none());
        }
        assert_eq!(session_status(&db, tenant, db.member_session), "active");
        assert_eq!(receipt_count(&db, operation), 1);

        let before_events: i64 = c
            .query_one(
                &format!(
                    "select count(*) from {s}.security_events where kind='session_revoked'",
                    s = db.schema()
                ),
                &[],
            )
            .unwrap()
            .get(0);
        let cross_subject = service.revoke_session(
            actor(&db, db.actor_session),
            command(tenant, db.member_session, Uuid::now_v7(), secret(52)),
        );
        assert_eq!(cross_subject, Err(AccessError::NotFound("session")));
        assert_eq!(session_status(&db, tenant, db.member_session), "active");
        assert_eq!(
            c.query_one(
                &format!(
                    "select count(*) from {s}.security_events where kind='session_revoked'",
                    s = db.schema()
                ),
                &[]
            )
            .unwrap()
            .get::<_, i64>(0),
            before_events
        );
    }
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn self_session_revoke_current_session_keeps_anonymous_receipt_confirmation() {
    for mode in [TenancyMode::Disabled, TenancyMode::Enabled] {
        let db = Db::new(mode);
        install(&db);
        let service = service(&db, crypto(("current", 10), None));
        let receipt_secret = secret(61);
        let operation = Uuid::now_v7();
        service
            .revoke_session(
                actor(&db, db.actor_session),
                command("0", db.actor_session, operation, receipt_secret.clone()),
            )
            .unwrap();
        assert_eq!(session_status(&db, "0", db.actor_session), "revoked");
        assert!(service
            .session_revocation_result(SecurityReceiptQuery {
                operation_id: operation,
                receipt_secret: receipt_secret.clone(),
            })
            .unwrap());
        assert!(!service
            .session_revocation_result(SecurityReceiptQuery {
                operation_id: operation,
                receipt_secret: secret(62),
            })
            .unwrap());
        assert!(!service
            .session_revocation_result(SecurityReceiptQuery {
                operation_id: Uuid::now_v7(),
                receipt_secret,
            })
            .unwrap());
        // An invalidated actor cannot use write replay, even with the receipt secret.
        assert_eq!(
            service.revoke_session(
                actor(&db, db.actor_session),
                command("0", db.actor_session, operation, secret(61)),
            ),
            Err(AccessError::Forbidden)
        );
    }
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn self_session_revoke_accepts_expired_or_revoked_owned_targets_but_not_inactive_actors() {
    for mode in [TenancyMode::Disabled, TenancyMode::Enabled] {
        let db = Db::new(mode);
        install(&db);
        add_actor_tenant_memberships(&db);
        let tenant = db.target();
        let expired = Uuid::now_v7();
        let already_revoked = Uuid::now_v7();
        let pending = Uuid::now_v7();
        insert_session(&db, tenant, pending, db.actor, "business", "pending", 2_000);
        insert_session(&db, tenant, expired, db.actor, "business", "expired", 999);
        insert_session(
            &db,
            tenant,
            already_revoked,
            db.actor,
            "business",
            "revoked",
            2_000,
        );
        let service = service(&db, crypto(("current", 10), None));
        for target in [pending, expired, already_revoked] {
            service
                .revoke_session(
                    actor(&db, db.actor_session),
                    command(tenant, target, Uuid::now_v7(), secret(131)),
                )
                .unwrap();
            assert_eq!(session_status(&db, tenant, target), "revoked");
        }

        let target = Uuid::now_v7();
        insert_session(&db, tenant, target, db.actor, "business", "active", 2_000);
        let mut c = db.adapter.connect().unwrap();
        c.execute(
            &format!(
                "update {}.auth_sessions set scope='openid' where tenant_id='0' and id=$1",
                db.schema()
            ),
            &[&db.actor_session],
        )
        .unwrap();
        let delegated_operation = Uuid::now_v7();
        assert_eq!(
            service.revoke_session(
                actor(&db, db.actor_session),
                command(tenant, target, delegated_operation, secret(133))
            ),
            Err(AccessError::Forbidden)
        );
        assert_eq!(session_status(&db, tenant, target), "active");
        assert_eq!(receipt_count(&db, delegated_operation), 0);
        c.execute(
            &format!(
                "update {}.auth_sessions set scope=null where tenant_id='0' and id=$1",
                db.schema()
            ),
            &[&db.actor_session],
        )
        .unwrap();
        db.adapter
            .connect()
            .unwrap()
            .execute(
                &format!(
                    "update {}.auth_sessions set status='revoked' where tenant_id='0' and id=$1",
                    db.schema()
                ),
                &[&db.actor_session],
            )
            .unwrap();
        let operation = Uuid::now_v7();
        assert_eq!(
            service.revoke_session(
                actor(&db, db.actor_session),
                command(tenant, target, operation, secret(132)),
            ),
            Err(AccessError::Forbidden)
        );
        assert_eq!(session_status(&db, tenant, target), "active");
        assert_eq!(receipt_count(&db, operation), 0);
    }
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn self_session_revoke_replay_checks_secret_command_and_stored_key_id() {
    let db = Db::new(TenancyMode::Enabled);
    install(&db);
    add_actor_tenant_memberships(&db);
    let first = Uuid::now_v7();
    let second = Uuid::now_v7();
    insert_session(&db, "t1", first, db.actor, "business", "active", 2_000);
    insert_session(&db, "t2", second, db.actor, "business", "active", 2_000);
    let old_crypto = crypto(("old", 10), None);
    let old_service = service(&db, old_crypto);
    let receipt_secret = secret(71);
    let operation = Uuid::now_v7();
    let same = command("t1", first, operation, receipt_secret.clone());
    old_service
        .revoke_session(actor(&db, db.actor_session), same.clone())
        .unwrap();

    let rotated = crypto(("new", 30), Some(("old", 10)));
    let rotated_service = service(&db, rotated);
    rotated_service
        .revoke_session(actor(&db, db.actor_session), same)
        .unwrap();
    assert_eq!(receipt_count(&db, operation), 1);
    assert_eq!(db.adapter.connect().unwrap().query_one(&format!("select count(*) from {}.security_events where kind='session_revoked' and operation_id=$1", db.schema()), &[&operation]).unwrap().get::<_, i64>(0), 1);
    assert_eq!(
        rotated_service.revoke_session(
            actor(&db, db.actor_session),
            command("t2", second, operation, receipt_secret.clone()),
        ),
        Err(AccessError::Conflict("security.operation_conflict"))
    );
    assert_eq!(
        rotated_service.revoke_session(
            actor(&db, db.actor_session),
            command("t1", first, operation, secret(72)),
        ),
        Err(AccessError::Conflict("security.operation_conflict"))
    );
    assert!(rotated_service
        .session_revocation_result(SecurityReceiptQuery {
            operation_id: operation,
            receipt_secret: receipt_secret.clone(),
        })
        .unwrap());

    let without_old = service(&db, crypto(("new", 30), None));
    assert!(without_old
        .session_revocation_result(SecurityReceiptQuery {
            operation_id: operation,
            receipt_secret,
        })
        .is_err());
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn self_session_revoke_concurrent_same_operation_records_one_event() {
    let db = Db::new(TenancyMode::Disabled);
    install(&db);
    let target = Uuid::now_v7();
    insert_session(&db, "0", target, db.actor, "business", "active", 2_000);
    let operation = Uuid::now_v7();
    let receipt_secret = secret(81);
    let barrier = Arc::new(Barrier::new(2));
    let handles: Vec<_> = (0..2)
        .map(|_| {
            let store = db.store();
            let crypt = crypto(("current", 10), None);
            let barrier = barrier.clone();
            let actor = actor(&db, db.actor_session);
            let command = command("0", target, operation, receipt_secret.clone());
            thread::spawn(move || {
                let svc = CoreSelfSessionRevocationService::new(
                    TenancyMode::Disabled,
                    store,
                    FixedClock,
                    crypt,
                    UuidIds,
                );
                barrier.wait();
                svc.revoke_session(actor, command)
            })
        })
        .collect();
    for handle in handles {
        handle.join().unwrap().unwrap();
    }
    let s = db.schema();
    let row = db.adapter.connect().unwrap().query_one(
        &format!("select (select count(*) from {s}.security_receipts where purpose='session_revoke' and operation_id=$1),(select count(*) from {s}.security_events where kind='session_revoked' and operation_id=$1),(select status='revoked' from {s}.auth_sessions where tenant_id='0' and id=$2)"),
        &[&operation, &target],
    ).unwrap();
    assert_eq!(row.get::<_, i64>(0), 1);
    assert_eq!(row.get::<_, i64>(1), 1);
    assert!(row.get::<_, bool>(2));
}

#[derive(Clone, Copy)]
struct FixedEventId(Uuid);
impl IdGenerator for FixedEventId {
    fn next_id(&self, _: &str) -> String {
        self.0.to_string()
    }
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn self_session_revoke_event_collision_rolls_back_all_mutations() {
    let db = Db::new(TenancyMode::Disabled);
    install(&db);
    let target = Uuid::now_v7();
    insert_session(&db, "0", target, db.actor, "business", "active", 2_000);
    insert_auth_artifacts(&db, "0", target, db.actor, 91);
    let collision = Uuid::now_v7();
    let operation = Uuid::now_v7();
    let mut c = db.adapter.connect().unwrap();
    c.execute(
        &format!("insert into {}.security_events(id,kind,outcome,account_id,operation_id,occurred_at_epoch) values($1,'session_revoked','accepted',$2,$3,1000)", db.schema()),
        &[&collision, &db.actor, &Uuid::now_v7()],
    )
    .unwrap();
    let svc = CoreSelfSessionRevocationService::new(
        db.mode,
        db.store(),
        FixedClock,
        crypto(("current", 10), None),
        FixedEventId(collision),
    );
    assert!(svc
        .revoke_session(
            actor(&db, db.actor_session),
            command("0", target, operation, secret(92)),
        )
        .is_err());
    assert_eq!(session_status(&db, "0", target), "active");
    assert_eq!(receipt_count(&db, operation), 0);
    let row = c.query_one(
        &format!("select (select count(*) from {s}.refresh_tokens where tenant_id='0' and session_id=$1 and revoked_at_epoch is null),(select count(*) from {s}.authorization_codes where tenant_id='0' and source_session_id=$1),(select revoked_at_epoch is null from {s}.auth_tenant_selections where source_tenant_id='0' and source_session_id=$1)", s=db.schema()),
        &[&target],
    ).unwrap();
    assert_eq!(row.get::<_, i64>(0), 1);
    assert_eq!(row.get::<_, i64>(1), 1);
    assert!(row.get::<_, bool>(2));
}

fn seed_scan_delivery(
    db: &Db,
    tenant: &str,
    source: Uuid,
    child: Uuid,
    grant: Uuid,
    state: &str,
    seed: u8,
    device: Uuid,
    binding: Uuid,
) {
    let s = db.schema();
    let mut c = db.adapter.connect().unwrap();
    c.execute(&format!("insert into {s}.auth_sessions(purpose,tenant_id,id,account_id,client_id,device_id,status,created_at_epoch,expires_at_epoch,refresh_token_version,authenticated_at_epoch) values('business',$1,$2,$3,'live-admin-client',$4,$5,900,2000,1,900)"), &[&tenant, &child, &db.actor, &device, &if state == "recoverable" { "pending" } else { "active" }]).unwrap();
    c.execute(&format!("insert into {s}.refresh_tokens(tenant_id,id,session_id,token_digest,token_version,issued_at_epoch,expires_at_epoch) values($1,$2,$3,$4,1,900,1900)"), &[&tenant, &Uuid::now_v7(), &child, &&[seed; 32][..]]).unwrap();
    c.execute(&format!("insert into {s}.scan_login_grants(tenant_id,host_scope,entry_id,id,mode,target_client_id,state,version,code_digest,source_account_id,source_session_id,source_client_id,source_authenticated_at_epoch,presentation_key_id,presentation_nonce,presentation_ciphertext,delivery_secret_hash,created_at_epoch,expires_at_epoch,code_expires_at_epoch) values($1,'self-revoke','entry',$2,'device_display','live-admin-client','issued',1,$3,$4,$5,'live-admin-client',900,'presentation',decode(repeat('01',12),'hex'),decode(repeat('02',24),'hex'),$6,900,1900,1900)"), &[&tenant, &grant, &&[seed + 1; 32][..], &db.actor, &source, &&[seed + 2; 32][..]]).unwrap();
    let acknowledged = state == "acknowledged";
    c.execute(&format!("insert into {s}.scan_login_deliveries(tenant_id,grant_id,issuance_operation_id,session_id,state,binding_id,binding_version,result_key_id,result_nonce,result_ciphertext,receipt_nonce_hash,recover_until_epoch,created_at_epoch,release_authorized_at_epoch,acknowledged_at_epoch) values($1,$2,$3,$4,$5,$6,1,'result',decode(repeat('03',12),'hex'),decode(repeat('04',24),'hex'),$7,1800,900,$8,$9)"), &[&tenant, &grant, &Uuid::now_v7().to_string(), &child, &state, &binding, &&[seed + 3; 32][..], &if acknowledged { Some(1_100_i64) } else { None }, &if acknowledged { Some(1_100_i64) } else { None }]).unwrap();
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn self_session_revoke_retires_recoverable_scan_children_but_preserves_acknowledged_sessions() {
    for mode in [TenancyMode::Disabled, TenancyMode::Enabled] {
        let db = Db::new(mode);
        install(&db);
        add_actor_tenant_memberships(&db);
        let tenant = db.target();
        let source = Uuid::now_v7();
        insert_session(&db, tenant, source, db.actor, "business", "active", 2_000);

        let device = Uuid::now_v7();
        let key_id = "s".repeat(43);
        let binding = Uuid::now_v7();
        let s = db.schema();
        let mut c = db.adapter.connect().unwrap();
        let mut tx = c.transaction().unwrap();
        tx.execute(&format!("insert into {s}.devices(tenant_id,id,client_id,device_name,proof_key_id,status,registered_at_epoch) values($1,$2,'live-admin-client','scan fixture',$3,'active',900)"), &[&tenant, &device, &key_id]).unwrap();
        tx.execute(&format!("insert into {s}.device_proof_keys(tenant_id,key_id,device_id,algorithm,public_jwk,version,status,registered_at_epoch) values($1,$2,$3,'ed25519','synthetic',1,'active',900)"), &[&tenant, &key_id, &device]).unwrap();
        tx.execute(&format!("insert into {s}.account_device_bindings(tenant_id,id,account_id,device_id,status,bound_at_epoch) values($1,$2,$3,$4,'active',900)"), &[&tenant, &binding, &db.actor, &device]).unwrap();
        tx.commit().unwrap();
        let recoverable_child = Uuid::now_v7();
        let acknowledged_child = Uuid::now_v7();
        let recoverable_grant = Uuid::now_v7();
        let acknowledged_grant = Uuid::now_v7();
        seed_scan_delivery(
            &db,
            tenant,
            source,
            recoverable_child,
            recoverable_grant,
            "recoverable",
            101,
            device,
            binding,
        );
        seed_scan_delivery(
            &db,
            tenant,
            source,
            acknowledged_child,
            acknowledged_grant,
            "acknowledged",
            111,
            device,
            binding,
        );

        service(&db, crypto(("current", 10), None))
            .revoke_session(
                actor(&db, db.actor_session),
                command(tenant, source, Uuid::now_v7(), secret(121)),
            )
            .unwrap();
        assert_eq!(session_status(&db, tenant, source), "revoked");
        assert_eq!(session_status(&db, tenant, recoverable_child), "revoked");
        assert_eq!(session_status(&db, tenant, acknowledged_child), "active");
        let rows = c.query(
            &format!("select g.id,g.state,g.presentation_ciphertext is null,g.delivery_secret_hash is null,d.state,d.result_ciphertext is null,d.receipt_nonce_hash is null from {s}.scan_login_grants g join {s}.scan_login_deliveries d on d.tenant_id=g.tenant_id and d.grant_id=g.id where g.id=any($1) order by g.id"),
            &[&vec![recoverable_grant, acknowledged_grant]],
        ).unwrap();
        assert_eq!(rows.len(), 2);
        let mut observed = std::collections::HashMap::new();
        for row in rows {
            let id: Uuid = row.get(0);
            observed.insert(
                id,
                (
                    row.get::<_, String>(1),
                    row.get::<_, bool>(2),
                    row.get::<_, bool>(3),
                    row.get::<_, String>(4),
                    row.get::<_, bool>(5),
                    row.get::<_, bool>(6),
                ),
            );
        }
        assert_eq!(
            observed.get(&recoverable_grant),
            Some(&(
                "invalidated".into(),
                true,
                true,
                "revoked".into(),
                true,
                true
            ))
        );
        assert_eq!(
            observed.get(&acknowledged_grant),
            Some(&(
                "invalidated".into(),
                true,
                true,
                "acknowledged".into(),
                true,
                true
            ))
        );
        let child_refresh: Option<String> = c.query_one(&format!("select revocation_reason from {s}.refresh_tokens where tenant_id=$1 and session_id=$2"), &[&tenant, &recoverable_child]).unwrap().get(0);
        assert_eq!(child_refresh.as_deref(), Some("administrative"));
        // Acknowledgement protects an independent child from source revocation,
        // but never prevents its owner explicitly revoking that child itself.
        service(&db, crypto(("current", 10), None))
            .revoke_session(
                actor(&db, db.actor_session),
                command(tenant, acknowledged_child, Uuid::now_v7(), secret(122)),
            )
            .unwrap();
        assert_eq!(session_status(&db, tenant, acknowledged_child), "revoked");
        assert_eq!(c.query_one(&format!("select state from {s}.scan_login_deliveries where tenant_id=$1 and session_id=$2"), &[&tenant,&acknowledged_child]).unwrap().get::<_,String>(0), "revoked");
    }
}
