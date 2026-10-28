use super::*;
use base64ct::{Base64UrlUnpadded, Encoding};
use embedded_idp_core::{
    access::{
        AccountSecurityService, AdminSetAccountPassword, CoreAccountSecurityService,
        CoreSelfPasswordChangeService, SecurityReceiptQuery, SelfPasswordChangeCommand,
        SelfPasswordChangeService,
    },
    AuthConfig, PasswordWorkBudget, SecretString,
};
use embedded_idp_security::{AccountSecurityKeySet, RingAccountSecurityCrypto};

pub(super) const AUTHORITY: &str = "phase-one-test";
pub(super) const OLD_PASSWORD: &str = "Current-fixture-123";
pub(super) const NEW_PASSWORD: &str = "Changed-fixture-456";

pub(super) fn install(db: &Db) {
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

pub(super) fn crypto() -> RingAccountSecurityCrypto {
    RingAccountSecurityCrypto::new(AUTHORITY.into(), [200; 32], key_set("current", 10), None)
        .unwrap()
}

pub(super) fn config() -> AuthConfig {
    AuthConfig {
        allow_local_registration: false,
        access_token_ttl_secs: 60,
        refresh_token_ttl_secs: 600,
        session_ttl_secs: 1200,
        verification_code_ttl_secs: 300,
        password_min_length: 8,
        password_max_length: 128,
    }
}

pub(super) fn service(
    db: &Db,
) -> CoreSelfPasswordChangeService<
    PostgresAccessStore,
    FixedClock,
    RingAccountSecurityCrypto,
    UuidIds,
> {
    CoreSelfPasswordChangeService::new(
        db.mode,
        db.store(),
        FixedClock,
        crypto(),
        UuidIds,
        config(),
        PasswordWorkBudget::default(),
    )
    .unwrap()
}

pub(super) fn actor(db: &Db, session: Uuid) -> AccessActor {
    AccessActor {
        tenant_id: "0".into(),
        subject_id: db.actor.to_string(),
        session_id: session.to_string(),
    }
}

fn secret(byte: u8) -> SecretString {
    SecretString::new(Base64UrlUnpadded::encode_string(&[byte; 32]))
}

pub(super) fn command(
    operation: Uuid,
    receipt_byte: u8,
    new_password: &str,
) -> SelfPasswordChangeCommand {
    SelfPasswordChangeCommand {
        current_password: SecretString::new(OLD_PASSWORD),
        new_password: SecretString::new(new_password),
        operation_id: operation,
        receipt_secret: secret(receipt_byte),
    }
}

pub(super) fn set_password(db: &Db, account: Uuid, password: &str) {
    let admin = CoreAccountSecurityService::new(db.service(), config()).unwrap();
    admin
        .set_account_password(
            db.context(db.actor_session.to_string()),
            AdminSetAccountPassword {
                account_id: account.to_string(),
                new_password: SecretString::new(password),
            },
        )
        .unwrap();
    db.adapter
        .connect()
        .unwrap()
        .execute(
            &format!(
                "update {}.auth_sessions set status='active' where tenant_id='0' and id=$1",
                db.schema()
            ),
            &[&db.actor_session],
        )
        .unwrap();
}

pub(super) fn add_actor_memberships(db: &Db) {
    if db.mode == TenancyMode::Enabled {
        let mut c = db.adapter.connect().unwrap();
        for tenant in ["t1", "t2"] {
            c.execute(
                &format!("insert into {}.access_memberships(tenant_id,account_id,status,joined_at_epoch) values($1,$2,'active',$3)", db.schema()),
                &[&tenant, &db.actor, &(NOW as i64)],
            )
            .unwrap();
        }
    }
}

fn insert_session(db: &Db, tenant: &str, session: Uuid, purpose: &str, account: Uuid) {
    db.adapter
        .connect()
        .unwrap()
        .execute(
            &format!("insert into {}.auth_sessions(purpose,tenant_id,id,account_id,client_id,status,created_at_epoch,expires_at_epoch,refresh_token_version,authenticated_at_epoch) values($1,$2,$3,$4,'live-admin-client','active',900,2000,1,900)", db.schema()),
            &[&purpose, &tenant, &session, &account],
        )
        .unwrap();
}

fn insert_session_artifacts(db: &Db, tenant: &str, session: Uuid, account: Uuid, seed: u8) {
    let mut c = db.adapter.connect().unwrap();
    let s = db.schema();
    c.execute(
        &format!("insert into {s}.refresh_tokens(tenant_id,id,session_id,token_digest,token_version,issued_at_epoch,expires_at_epoch) values($1,$2,$3,$4,1,900,1900)"),
        &[&tenant, &Uuid::now_v7(), &session, &&[seed; 32][..]],
    )
    .unwrap();
    c.execute(
        &format!("insert into {s}.authorization_codes(tenant_id,code_digest,account_id,source_session_id,login_entry,client_id,redirect_uri,scope,created_at_epoch,expires_at_epoch) values($1,$2,$3,$4,'password-change-test','live-admin-client','https://example.test/callback','openid',900,1200)"),
        &[&tenant, &&[seed + 1; 32][..], &account, &session],
    )
    .unwrap();
    c.execute(
        &format!("insert into {s}.auth_tenant_selections(id,ticket_digest,account_id,client_id,login_entry,purpose,authenticated_at_epoch,expires_at_epoch,source_tenant_id,source_session_id) values($1,$2,$3,'live-admin-client','password-change-test','tenant_selection',900,1200,$4,$5)"),
        &[&Uuid::now_v7(), &&[seed + 2; 32][..], &account, &tenant, &session],
    )
    .unwrap();
    c.execute(
        &format!("insert into {s}.email_verification_codes(tenant_id,id,account_id,email,code,issued_at_epoch,expires_at_epoch) values($1,$2,$3,'actor@example.test','synthetic-code',900,1200)"),
        &[&tenant, &Uuid::now_v7(), &account],
    )
    .unwrap();
}

fn real_actor_password(db: &Db) -> String {
    db.adapter
        .connect()
        .unwrap()
        .query_one(
            &format!(
                "select password_hash from {}.accounts where id=$1",
                db.schema()
            ),
            &[&db.actor],
        )
        .unwrap()
        .get(0)
}

fn session_artifact_counts(db: &Db, account: Uuid) -> Vec<i64> {
    let s = db.schema();
    let row = db.adapter.connect().unwrap().query_one(
        &format!("select (select count(*) from {s}.auth_sessions where account_id=$1 and status<>'revoked'),(select count(*) from {s}.refresh_tokens f join {s}.auth_sessions x on x.tenant_id=f.tenant_id and x.id=f.session_id where x.account_id=$1 and f.revoked_at_epoch is null),(select count(*) from {s}.authorization_codes where account_id=$1),(select count(*) from {s}.auth_tenant_selections where account_id=$1 and revoked_at_epoch is null),(select count(*) from {s}.email_verification_codes where account_id=$1)"), &[&account]).unwrap();
    (0..5).map(|index| row.get(index)).collect()
}

fn seed_scan_fixtures(db: &Db, tenant: &str) -> (Vec<Uuid>, Vec<Uuid>, Uuid, Uuid, Uuid, Uuid) {
    let s = db.schema();
    let device = Uuid::now_v7();
    let key_id = "p".repeat(43);
    let binding = Uuid::now_v7();
    let mut c = db.adapter.connect().unwrap();
    {
        // devices.proof_key_id has a deferred FK; insert both sides in the same
        // transaction and let commit validate the complete synthetic key pair.
        let mut tx = c.transaction().unwrap();
        tx.execute(&format!("insert into {s}.devices(tenant_id,id,client_id,device_name,proof_key_id,status,registered_at_epoch) values($1,$2,'live-admin-client','password-change fixture',$3,'active',900)"), &[&tenant, &device, &key_id]).unwrap();
        tx.execute(&format!("insert into {s}.device_proof_keys(tenant_id,key_id,device_id,algorithm,public_jwk,version,status,registered_at_epoch) values($1,$2,$3,'ed25519','synthetic',1,'active',900)"), &[&tenant, &key_id, &device]).unwrap();
        tx.execute(&format!("insert into {s}.account_device_bindings(tenant_id,id,account_id,device_id,status,bound_at_epoch) values($1,$2,$3,$4,'active',900)"), &[&tenant, &binding, &db.actor, &device]).unwrap();
        tx.commit().unwrap();
    }
    let states = [
        "waiting_user",
        "waiting_device",
        "awaiting_approval",
        "approved",
        "issued",
        "denied",
        "cancelled",
        "expired",
        "invalidated",
    ];
    let grants = states.iter().map(|_| Uuid::now_v7()).collect::<Vec<_>>();
    let mut delivery_grants = Vec::new();
    let mut delivery_sessions = Vec::new();
    for (index, state) in states.iter().enumerate() {
        let grant = grants[index];
        let source_session = Uuid::now_v7();
        insert_session(db, tenant, source_session, "business", db.actor);
        let seed = index as u8 + 31;
        c.execute(&format!("insert into {s}.scan_login_grants(tenant_id,host_scope,entry_id,id,mode,target_client_id,state,version,code_digest,source_account_id,source_session_id,source_client_id,source_authenticated_at_epoch,presentation_key_id,presentation_nonce,presentation_ciphertext,delivery_secret_hash,created_at_epoch,expires_at_epoch,code_expires_at_epoch) values($1,'password-change-host','entry',$2,'device_display','live-admin-client',$3,2,$4,$5,$6,'live-admin-client',900,'presentation',decode(repeat('01',12),'hex'),decode(repeat('02',24),'hex'),$7,900,1900,1800)"), &[&tenant, &grant, state, &&[seed; 32][..], &db.actor, &source_session, &&[seed + 1; 32][..]]).unwrap();
        if index < 3 {
            let child = Uuid::now_v7();
            insert_session(db, tenant, child, "business", db.actor);
            let delivery_state = ["recoverable", "acknowledged", "revoked"][index];
            let acknowledged = delivery_state == "acknowledged";
            let revoked = delivery_state == "revoked";
            c.execute(&format!("insert into {s}.scan_login_deliveries(tenant_id,grant_id,issuance_operation_id,session_id,state,binding_id,binding_version,result_key_id,result_nonce,result_ciphertext,receipt_nonce_hash,recover_until_epoch,created_at_epoch,release_authorized_at_epoch,acknowledged_at_epoch,revoked_at_epoch,reason) values($1,$2,$3,$4,$5,$6,4,'result',decode(repeat('03',12),'hex'),decode(repeat('04',24),'hex'),$7,1800,900,$8,$9,$10,$11)"), &[&tenant, &grant, &format!("delivery-{index}"), &child, &delivery_state, &binding, &&[seed + 2; 32][..], &Some(1_000_i64), &if acknowledged { Some(1_100_i64) } else { None }, &if revoked { Some(1_200_i64) } else { None }, &if revoked { Some("fixture-revoked") } else { None }]).unwrap();
            delivery_grants.push(grant);
            delivery_sessions.push(child);
        }
    }
    let operation_grant = grants[4];
    c.execute(&format!("insert into {s}.scan_login_operations(tenant_id,host_scope,entry_id,actor_id,action,operation_id,fingerprint,grant_id,created_at_epoch) values($1,'password-change-host','entry','actor','create','operation',decode(repeat('05',32),'hex'),$2,900)"), &[&tenant, &operation_grant]).unwrap();
    c.execute(&format!("insert into {s}.scan_login_origin_closures(tenant_id,host_scope,entry_id,device_id,origin_action,origin_operation_id,delivery_secret_hash,grant_id,closed_by_key_id,closed_at_epoch) values($1,'password-change-host','entry',$2,'create','origin-operation',decode(repeat('06',32),'hex'),$3,'closed-key',900)"), &[&tenant, &device, &operation_grant]).unwrap();
    let other_device = Uuid::now_v7();
    let other_key = "o".repeat(43);
    let other_binding = Uuid::now_v7();
    {
        let mut tx = c.transaction().unwrap();
        tx.execute(&format!("insert into {s}.devices(tenant_id,id,client_id,device_name,proof_key_id,status,registered_at_epoch) values($1,$2,'live-admin-client','unrelated fixture',$3,'active',900)"), &[&tenant, &other_device, &other_key]).unwrap();
        tx.execute(&format!("insert into {s}.device_proof_keys(tenant_id,key_id,device_id,algorithm,public_jwk,version,status,registered_at_epoch) values($1,$2,$3,'ed25519','synthetic',1,'active',900)"), &[&tenant, &other_key, &other_device]).unwrap();
        tx.execute(&format!("insert into {s}.account_device_bindings(tenant_id,id,account_id,device_id,status,bound_at_epoch) values($1,$2,$3,$4,'active',900)"), &[&tenant, &other_binding, &db.member, &other_device]).unwrap();
        tx.commit().unwrap();
    }
    let other_grant = Uuid::now_v7();
    let other_delivery_session = Uuid::now_v7();
    insert_session(db, tenant, other_delivery_session, "business", db.member);
    c.execute(&format!("insert into {s}.scan_login_grants(tenant_id,host_scope,entry_id,id,mode,target_client_id,state,version,code_digest,source_account_id,source_session_id,source_client_id,source_authenticated_at_epoch,presentation_key_id,presentation_nonce,presentation_ciphertext,delivery_secret_hash,created_at_epoch,expires_at_epoch,code_expires_at_epoch) values($1,'password-change-host','unrelated',$2,'device_display','live-admin-client','issued',7,decode(repeat('71',32),'hex'),$3,$4,'live-admin-client',900,'keep-key',decode(repeat('07',12),'hex'),decode(repeat('08',24),'hex'),decode(repeat('09',32),'hex'),900,1900,1800)"), &[&tenant, &other_grant, &db.member, &db.member_session]).unwrap();
    c.execute(&format!("insert into {s}.scan_login_deliveries(tenant_id,grant_id,issuance_operation_id,session_id,state,binding_id,binding_version,result_key_id,result_nonce,result_ciphertext,receipt_nonce_hash,recover_until_epoch,created_at_epoch) values($1,$2,'unrelated-delivery',$3,'recoverable',$4,1,'keep-result',decode(repeat('0a',12),'hex'),decode(repeat('0b',24),'hex'),decode(repeat('0c',32),'hex'),1800,900)"), &[&tenant, &other_grant, &other_delivery_session, &other_binding]).unwrap();
    (
        grants,
        delivery_grants,
        operation_grant,
        device,
        other_grant,
        other_delivery_session,
    )
}

fn seed_recovery_fixtures(db: &Db) -> (Vec<Uuid>, [u8; 32], Uuid) {
    let s = db.schema();
    let mut c = db.adapter.connect().unwrap();
    let budget_digest = [71_u8; 32];
    c.execute(&format!("insert into {s}.password_recovery_budgets(subject_digest,window_start_epoch,start_count,failure_count,expires_at_epoch) values($1,900,2,3,4500)"), &[&&budget_digest[..]]).unwrap();
    let pending = Uuid::now_v7();
    let sending = Uuid::now_v7();
    let accepted = Uuid::now_v7();
    let flows = vec![pending, sending, accepted];
    for (index, flow) in flows.iter().enumerate() {
        let seed = index as u8 + 80;
        let state = if index == 2 { "consumed" } else { "pending" };
        c.execute(&format!("insert into {s}.password_recovery_flows(id,subject_digest,account_id,snapshot_credential_version,handle_key_id,handle_digest,code_key_id,code_digest,created_at_epoch,expires_at_epoch,retained_until_epoch,state,failed_attempts) values($1,$2,$3,1,'current',$4,'current',$4,900,1800,87300,$5,0)"), &[flow, &&[seed; 32][..], &db.actor, &&[seed + 1; 32][..], &state]).unwrap();
        c.execute(&format!("insert into {s}.password_recovery_start_receipts(operation_id,flow_id,request_key_id,request_digest,envelope_key_id,ciphertext,created_at_epoch,expires_at_epoch) values($1,$2,'current',$3,'current',$4,900,1800)"), &[&Uuid::now_v7(), flow, &&[seed + 2; 32][..], &&[seed + 3; 28][..]]).unwrap();
        if index == 0 {
            c.execute(&format!("insert into {s}.security_email_outbox(id,flow_id,envelope_key_id,ciphertext,state,created_at_epoch,expires_at_epoch,next_attempt_at_epoch,attempts) values($1,$2,'current',$3,'pending',900,1800,900,0)"), &[&Uuid::now_v7(), flow, &&[seed + 4; 28][..]]).unwrap();
        } else if index == 1 {
            c.execute(&format!("insert into {s}.security_email_outbox(id,flow_id,envelope_key_id,ciphertext,state,created_at_epoch,expires_at_epoch,next_attempt_at_epoch,attempts,lease_token,lease_until_epoch) values($1,$2,'current',$3,'sending',900,1800,900,1,$4,950)"), &[&Uuid::now_v7(), flow, &&[seed + 4; 28][..], &Uuid::now_v7()]).unwrap();
        } else {
            c.execute(&format!("insert into {s}.security_email_outbox(id,flow_id,envelope_key_id,ciphertext,state,created_at_epoch,expires_at_epoch,next_attempt_at_epoch,attempts,last_outcome) values($1,$2,null,null,'accepted',900,1800,900,1,'accepted')"), &[&Uuid::now_v7(), flow]).unwrap();
        }
    }
    let other_flow = Uuid::now_v7();
    c.execute(&format!("insert into {s}.password_recovery_flows(id,subject_digest,account_id,snapshot_credential_version,handle_key_id,handle_digest,code_key_id,code_digest,created_at_epoch,expires_at_epoch,retained_until_epoch,state,failed_attempts) values($1,$2,$3,1,'current',$4,'current',$4,900,1800,87300,'pending',0)"), &[&other_flow, &&[91_u8; 32][..], &db.member, &&[92_u8; 32][..]]).unwrap();
    c.execute(&format!("insert into {s}.security_email_outbox(id,flow_id,envelope_key_id,ciphertext,state,created_at_epoch,expires_at_epoch,next_attempt_at_epoch,attempts) values($1,$2,'current',$3,'pending',900,1800,900,0)"), &[&Uuid::now_v7(), &other_flow, &&[93_u8; 28][..]]).unwrap();
    c.execute(&format!("insert into {s}.password_recovery_start_receipts(operation_id,flow_id,request_key_id,request_digest,envelope_key_id,ciphertext,created_at_epoch,expires_at_epoch) values($1,$2,'current',$3,'current',$4,900,1800)"), &[&Uuid::now_v7(), &other_flow, &&[94_u8; 32][..], &&[95_u8; 28][..]]).unwrap();
    (flows, budget_digest, other_flow)
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn self_password_change_retires_all_account_credentials_and_recovery_state_in_both_modes() {
    for mode in [TenancyMode::Disabled, TenancyMode::Enabled] {
        let db = Db::new(mode);
        install(&db);
        add_actor_memberships(&db);
        set_password(&db, db.actor, OLD_PASSWORD);
        let s = db.schema();
        let mut tenants = if mode == TenancyMode::Enabled {
            vec!["t1", "t2"]
        } else {
            vec!["0"]
        };
        tenants.sort_unstable();
        insert_session_artifacts(&db, "0", db.actor_session, db.actor, 10);
        for (index, tenant) in tenants.iter().enumerate() {
            for (purpose_index, purpose) in ["business", "management"].iter().enumerate() {
                let session = Uuid::now_v7();
                insert_session(&db, tenant, session, purpose, db.actor);
                insert_session_artifacts(
                    &db,
                    tenant,
                    session,
                    db.actor,
                    20 + (index * 4 + purpose_index) as u8 * 4,
                );
            }
        }
        let (grants, delivery_grants, operation_grant, device, other_grant, other_delivery_session) =
            seed_scan_fixtures(&db, db.target());
        let (flows, budget_digest, other_flow) = seed_recovery_fixtures(&db);
        let version_before: i64 = db
            .adapter
            .connect()
            .unwrap()
            .query_one(
                &format!("select security_credential_version from {s}.accounts where id=$1"),
                &[&db.actor],
            )
            .unwrap()
            .get(0);
        let password_before = real_actor_password(&db);
        let operation = Uuid::now_v7();
        let receipt_secret = secret(111);
        service(&db)
            .change_password(
                actor(&db, db.actor_session),
                SelfPasswordChangeCommand {
                    current_password: SecretString::new(OLD_PASSWORD),
                    new_password: SecretString::new(NEW_PASSWORD),
                    operation_id: operation,
                    receipt_secret: receipt_secret.clone(),
                },
            )
            .unwrap();

        let after_hash = real_actor_password(&db);
        assert_ne!(after_hash, password_before);
        assert!(after_hash.starts_with("$argon2id$"));
        let version_after: i64 = db
            .adapter
            .connect()
            .unwrap()
            .query_one(
                &format!("select security_credential_version from {s}.accounts where id=$1"),
                &[&db.actor],
            )
            .unwrap()
            .get(0);
        assert_eq!(
            version_after,
            version_before + 1,
            "the schema trigger advances the version once"
        );
        assert_eq!(session_artifact_counts(&db, db.actor), vec![0, 0, 0, 0, 0]);
        assert!(
            session_artifact_counts(&db, db.member)[0] > 0,
            "another account remains active"
        );
        assert_eq!(
            db.adapter
                .connect()
                .unwrap()
                .query_one(
                    &format!("select status from {s}.auth_sessions where tenant_id=$1 and id=$2"),
                    &[&db.target(), &db.member_session]
                )
                .unwrap()
                .get::<_, String>(0),
            "active"
        );

        let mut c = db.adapter.connect().unwrap();
        for (index, grant) in grants.iter().enumerate() {
            let row = c.query_one(&format!("select state,version,presentation_key_id is null,presentation_nonce is null,presentation_ciphertext is null,delivery_secret_hash is null from {s}.scan_login_grants where id=$1"), &[grant]).unwrap();
            assert_eq!(
                row.get::<_, i64>(1),
                3,
                "every source grant version increments once"
            );
            for column in [2, 3, 4, 5] {
                assert!(row.get::<_, bool>(column));
            }
            let expected_state = if index < 5 {
                "invalidated"
            } else {
                ["denied", "cancelled", "expired", "invalidated"][index - 5]
            };
            assert_eq!(row.get::<_, String>(0), expected_state);
        }
        assert_eq!(delivery_grants.len(), 3);
        for grant in delivery_grants {
            let row = c.query_one(&format!("select state,result_key_id is null,result_nonce is null,result_ciphertext is null,receipt_nonce_hash is null from {s}.scan_login_deliveries where tenant_id=$1 and grant_id=$2"), &[&db.target(), &grant]).unwrap();
            assert_eq!(row.get::<_, String>(0), "revoked");
            for column in [1, 2, 3, 4] {
                assert!(row.get::<_, bool>(column));
            }
        }
        assert_eq!(
            c.query_one(
                &format!("select count(*) from {s}.scan_login_operations where grant_id=$1"),
                &[&operation_grant]
            )
            .unwrap()
            .get::<_, i64>(0),
            1
        );
        assert_eq!(c.query_one(&format!("select count(*) from {s}.scan_login_origin_closures where grant_id=$1 and device_id=$2"), &[&operation_grant, &device]).unwrap().get::<_, i64>(0), 1);
        let other_grant_row = c.query_one(&format!("select state,version,presentation_key_id is not null,presentation_nonce is not null,presentation_ciphertext is not null,delivery_secret_hash is not null from {s}.scan_login_grants where id=$1"), &[&other_grant]).unwrap();
        assert_eq!(other_grant_row.get::<_, String>(0), "issued");
        assert_eq!(other_grant_row.get::<_, i64>(1), 7);
        for column in [2, 3, 4, 5] {
            assert!(other_grant_row.get::<_, bool>(column));
        }
        let other_delivery = c.query_one(&format!("select state,result_key_id is not null,result_nonce is not null,result_ciphertext is not null,receipt_nonce_hash is not null from {s}.scan_login_deliveries where session_id=$1"), &[&other_delivery_session]).unwrap();
        assert_eq!(other_delivery.get::<_, String>(0), "recoverable");
        for column in [1, 2, 3, 4] {
            assert!(other_delivery.get::<_, bool>(column));
        }
        assert_eq!(
            c.query_one(
                &format!("select status from {s}.auth_sessions where tenant_id=$1 and id=$2"),
                &[&db.target(), &other_delivery_session]
            )
            .unwrap()
            .get::<_, String>(0),
            "active"
        );

        let flow_rows = c
            .query(
                &format!(
                    "select id,state from {s}.password_recovery_flows where id=any($1) order by id"
                ),
                &[&flows],
            )
            .unwrap();
        assert_eq!(flow_rows.len(), flows.len());
        for row in flow_rows {
            let id: Uuid = row.get(0);
            let original = flows.iter().position(|flow| *flow == id).unwrap();
            assert_eq!(
                row.get::<_, String>(1),
                if original == 2 {
                    "consumed"
                } else {
                    "invalidated"
                }
            );
        }
        assert_eq!(c.query_one(&format!("select count(*) from {s}.password_recovery_start_receipts r join {s}.password_recovery_flows f on f.id=r.flow_id where f.account_id=$1"), &[&db.actor]).unwrap().get::<_, i64>(0), 0);
        assert_eq!(c.query_one(&format!("select count(*) from {s}.password_recovery_start_receipts r join {s}.password_recovery_flows f on f.id=r.flow_id where f.id=$1"), &[&other_flow]).unwrap().get::<_, i64>(0), 1);
        let outbox = c.query(&format!("select f.id,o.state,o.envelope_key_id is null,o.ciphertext is null,o.lease_token is null,o.lease_until_epoch is null,o.last_outcome from {s}.security_email_outbox o join {s}.password_recovery_flows f on f.id=o.flow_id where f.account_id=$1"), &[&db.actor]).unwrap();
        assert_eq!(outbox.len(), 3);
        for row in outbox {
            let id: Uuid = row.get(0);
            let index = flows.iter().position(|flow| *flow == id).unwrap();
            let state: String = row.get(1);
            if index < 2 {
                assert_eq!(state, "cancelled");
                assert!(
                    row.get::<_, bool>(2)
                        && row.get::<_, bool>(3)
                        && row.get::<_, bool>(4)
                        && row.get::<_, bool>(5)
                );
                assert_eq!(
                    row.get::<_, String>(6),
                    if index == 0 { "not_started" } else { "unknown" }
                );
            } else {
                assert_eq!(state, "accepted");
                assert!(row.get::<_, bool>(2) && row.get::<_, bool>(3));
                assert_eq!(row.get::<_, String>(6), "accepted");
            }
        }
        let budget = c.query_one(&format!("select window_start_epoch,start_count,failure_count,expires_at_epoch from {s}.password_recovery_budgets where subject_digest=$1"), &[&&budget_digest[..]]).unwrap();
        assert_eq!(budget.get::<_, i64>(0), 900);
        assert_eq!(budget.get::<_, i32>(1), 2);
        assert_eq!(budget.get::<_, i32>(2), 3);
        assert_eq!(budget.get::<_, i64>(3), 4500);
        assert_eq!(c.query_one(&format!("select count(*) from {s}.security_receipts where purpose='password_change' and operation_id=$1"), &[&operation]).unwrap().get::<_, i64>(0), 1);
        assert_eq!(c.query_one(&format!("select count(*) from {s}.security_events where kind='password_changed' and operation_id=$1"), &[&operation]).unwrap().get::<_, i64>(0), 1);
        assert!(service(&db)
            .password_change_result(SecurityReceiptQuery {
                operation_id: operation,
                receipt_secret: receipt_secret.clone()
            })
            .unwrap());
        assert!(!service(&db)
            .password_change_result(SecurityReceiptQuery {
                operation_id: operation,
                receipt_secret: secret(112)
            })
            .unwrap());
        let other_outbox = c.query_one(&format!("select state,ciphertext is not null from {s}.security_email_outbox where flow_id=$1"), &[&other_flow]).unwrap();
        assert_eq!(other_outbox.get::<_, String>(0), "pending");
        assert!(other_outbox.get::<_, bool>(1));
    }
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
fn self_password_change_concurrent_updates_commit_once() {
    let db = Db::new(TenancyMode::Disabled);
    install(&db);
    set_password(&db, db.actor, OLD_PASSWORD);
    let before_version: i64 = db
        .adapter
        .connect()
        .unwrap()
        .query_one(
            &format!(
                "select security_credential_version from {}.accounts where id=$1",
                db.schema()
            ),
            &[&db.actor],
        )
        .unwrap()
        .get(0);
    let barrier = Arc::new(Barrier::new(2));
    let handles: Vec<_> = (0..2)
        .map(|index| {
            let store = db.store();
            let barrier = barrier.clone();
            let actor = actor(&db, db.actor_session);
            let cmd = command(
                Uuid::now_v7(),
                120 + index as u8,
                if index == 0 {
                    "Concurrent-fixture-101"
                } else {
                    "Concurrent-fixture-202"
                },
            );
            thread::spawn(move || {
                let service = CoreSelfPasswordChangeService::new(
                    TenancyMode::Disabled,
                    store,
                    FixedClock,
                    crypto(),
                    UuidIds,
                    config(),
                    PasswordWorkBudget::default(),
                )
                .unwrap();
                barrier.wait();
                service.change_password(actor, cmd)
            })
        })
        .collect();
    let results = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(results.iter().filter(|result| result.is_err()).count(), 1);
    let s = db.schema();
    let row = db.adapter.connect().unwrap().query_one(
        &format!("select (select security_credential_version from {s}.accounts where id=$1),(select count(*) from {s}.security_receipts where purpose='password_change'),(select count(*) from {s}.security_events where kind='password_changed')"),
        &[&db.actor],
    ).unwrap();
    assert_eq!(row.get::<_, i64>(0), before_version + 1);
    assert_eq!(row.get::<_, i64>(1), 1);
    assert_eq!(row.get::<_, i64>(2), 1);
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn self_password_change_event_collision_rolls_back_credentials_and_receipt() {
    let db = Db::new(TenancyMode::Disabled);
    install(&db);
    set_password(&db, db.actor, OLD_PASSWORD);
    let target = Uuid::now_v7();
    insert_session(&db, "0", target, "business", db.actor);
    insert_session_artifacts(&db, "0", target, db.actor, 155);
    let before_hash = real_actor_password(&db);
    let before_version: i64 = db
        .adapter
        .connect()
        .unwrap()
        .query_one(
            &format!(
                "select security_credential_version from {}.accounts where id=$1",
                db.schema()
            ),
            &[&db.actor],
        )
        .unwrap()
        .get(0);
    let before_artifacts = session_artifact_counts(&db, db.actor);
    let collision = Uuid::now_v7();
    let operation = Uuid::now_v7();
    db.adapter.connect().unwrap().execute(
        &format!("insert into {}.security_events(id,kind,outcome,account_id,operation_id,occurred_at_epoch) values($1,'password_changed','accepted',$2,$3,1000)", db.schema()),
        &[&collision, &db.actor, &Uuid::now_v7()],
    ).unwrap();
    let service = CoreSelfPasswordChangeService::new(
        db.mode,
        db.store(),
        FixedClock,
        crypto(),
        FixedEventId(collision),
        config(),
        PasswordWorkBudget::default(),
    )
    .unwrap();
    assert!(service
        .change_password(
            actor(&db, db.actor_session),
            command(operation, 156, NEW_PASSWORD),
        )
        .is_err());
    assert_eq!(real_actor_password(&db), before_hash);
    assert_eq!(session_artifact_counts(&db, db.actor), before_artifacts);
    let mut c = db.adapter.connect().unwrap();
    assert_eq!(
        c.query_one(
            &format!(
                "select security_credential_version from {}.accounts where id=$1",
                db.schema()
            ),
            &[&db.actor]
        )
        .unwrap()
        .get::<_, i64>(0),
        before_version
    );
    assert_eq!(c.query_one(&format!("select count(*) from {}.security_receipts where purpose='password_change' and operation_id=$1", db.schema()), &[&operation]).unwrap().get::<_, i64>(0), 0);
}
