use super::devices::{device, send};
use super::*;
use axum::{http::StatusCode, Extension, Router};
use embedded_idp_axum::{account_admin_router, account_security_admin_router};
use embedded_idp_core::{AuthConfig, ClientSecretVerifier, PhcClientSecretCodec};
use serde_json::{json, Value};
fn config() -> AuthConfig {
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
) -> CoreAccountSecurityService<PostgresAccessStore, FixedClock, UuidIds> {
    CoreAccountSecurityService::new(db.service(), config()).unwrap()
}
fn app(db: &Db, context: Option<AccessAdminContext>) -> Router {
    let router = account_admin_router(db.mode, Arc::new(db.service()))
        .merge(account_security_admin_router(Arc::new(service(db))));
    Router::new().nest(
        "/idp",
        if let Some(c) = context {
            router.layer(Extension(c))
        } else {
            router
        },
    )
}
fn create_body(db: &Db, email: &str) -> Value {
    json!({"tenant_id":db.target(),"email":email,"password":"Create-fixture-123","display_name":"Created user"})
}
fn status(db: &Db, id: Uuid) -> (String, String) {
    let r = db
        .adapter
        .connect()
        .unwrap()
        .query_one(
            &format!(
                "select status,password_hash from {}.accounts where id=$1",
                db.schema()
            ),
            &[&id],
        )
        .unwrap();
    (r.get(0), r.get(1))
}
fn credentials(db: &Db, id: Uuid) -> Vec<i64> {
    let r=db.adapter.connect().unwrap().query_one(&format!("select (select count(*) from {s}.auth_sessions where account_id=$1 and status<>'revoked'),(select count(*) from {s}.refresh_tokens f join {s}.auth_sessions x on x.tenant_id=f.tenant_id and x.id=f.session_id where x.account_id=$1 and f.revoked_at_epoch is null),(select count(*) from {s}.authorization_codes where account_id=$1),(select count(*) from {s}.auth_tenant_selections where account_id=$1 and revoked_at_epoch is null),(select count(*) from {s}.email_verification_codes where account_id=$1),(select count(*) from {s}.account_device_bindings where account_id=$1 and status='active')",s=db.schema()),&[&id]).unwrap();
    (0..6).map(|i| r.get(i)).collect()
}
#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn account_security_create_is_atomic_requires_a_tenant_and_never_returns_passwords() {
    for mode in [TenancyMode::Disabled, TenancyMode::Enabled] {
        let db = Db::new(mode);
        let s = db.schema();
        let router = app(&db, Some(db.context(db.actor_session.to_string())));
        let body = create_body(&db, "created-security@example.test");
        assert_eq!(
            send(
                &app(&db, None),
                "POST",
                "/admin/platform/accounts",
                None,
                &body.to_string()
            )
            .0,
            StatusCode::UNAUTHORIZED
        );
        let mut missing = body.clone();
        missing.as_object_mut().unwrap().remove("tenant_id");
        assert_eq!(
            send(
                &router,
                "POST",
                "/admin/platform/accounts",
                None,
                &missing.to_string()
            )
            .0,
            StatusCode::UNPROCESSABLE_ENTITY
        );
        let mut invalid = body.clone();
        invalid["password"] = json!("weak");
        assert_eq!(
            send(
                &router,
                "POST",
                "/admin/platform/accounts",
                None,
                &invalid.to_string()
            )
            .0,
            StatusCode::BAD_REQUEST
        );
        invalid = body.clone();
        invalid["tenant_id"] = json!(if mode == TenancyMode::Enabled {
            "0"
        } else {
            "t1"
        });
        assert_eq!(
            send(
                &router,
                "POST",
                "/admin/platform/accounts",
                None,
                &invalid.to_string()
            )
            .0,
            StatusCode::BAD_REQUEST
        );
        if mode == TenancyMode::Enabled {
            db.adapter.connect().unwrap().execute(&format!("update {s}.access_permissions set enabled=false where resource_type='idp.platform' and action='users.bind'"),&[]).unwrap();
            assert_eq!(
                send(
                    &router,
                    "POST",
                    "/admin/platform/accounts",
                    None,
                    &body.to_string()
                )
                .0,
                StatusCode::FORBIDDEN
            );
            db.adapter.connect().unwrap().execute(&format!("update {s}.access_permissions set enabled=true where resource_type='idp.platform' and action='users.bind'"),&[]).unwrap();
        }
        db.adapter
            .connect()
            .unwrap()
            .execute(
                &format!("update {s}.access_tenants set allow_registration=false where id=$1"),
                &[&db.target()],
            )
            .unwrap();
        db.adapter.connect().unwrap().batch_execute(&format!("create function {s}.security_audit_fail() returns trigger language plpgsql as $$ begin raise exception 'audit failure'; end $$; create trigger security_audit_fail before insert on {s}.access_audit_events for each row execute function {s}.security_audit_fail()" )).unwrap();
        assert_eq!(
            send(
                &router,
                "POST",
                "/admin/platform/accounts",
                None,
                &body.to_string()
            )
            .0,
            StatusCode::INTERNAL_SERVER_ERROR
        );
        let count: i64 = db
            .adapter
            .connect()
            .unwrap()
            .query_one(
                &format!(
                    "select count(*) from {s}.accounts where email='created-security@example.test'"
                ),
                &[],
            )
            .unwrap()
            .get(0);
        assert_eq!(count, 0);
        db.adapter
            .connect()
            .unwrap()
            .batch_execute(&format!(
                "drop trigger security_audit_fail on {s}.access_audit_events"
            ))
            .unwrap();
        let created = send(
            &router,
            "POST",
            "/admin/platform/accounts",
            None,
            &body.to_string(),
        );
        assert_eq!(created.0, StatusCode::OK, "{created:?}");
        let id = Uuid::parse_str(created.1["account"]["account_id"].as_str().unwrap()).unwrap();
        assert_eq!(created.1["account"]["membership"]["tenant_id"], db.target());
        assert_eq!(created.1["account"]["status"], "active");
        assert!(!created.1.to_string().contains("Create-fixture-123"));
        assert!(!created.1.to_string().contains("password_hash"));
        assert!(PhcClientSecretCodec
            .verify_client_secret("Create-fixture-123", &status(&db, id).1)
            .unwrap());
        assert_eq!(
            send(
                &router,
                "POST",
                "/admin/platform/accounts",
                None,
                &body.to_string()
            )
            .0,
            StatusCode::CONFLICT
        );
        let r=db.adapter.connect().unwrap().query_one(&format!("select (select count(*) from {s}.access_memberships where account_id=$1),(select count(*) from {s}.access_role_bindings where account_id=$1),(select count(*) from {s}.auth_sessions where account_id=$1)"),&[&id]).unwrap();
        assert_eq!(r.get::<_, i64>(0), 1);
        assert_eq!(r.get::<_, i64>(1), 0);
        assert_eq!(r.get::<_, i64>(2), 0);
        let status_path = format!("/admin/platform/accounts/{id}/status");
        db.adapter
            .connect()
            .unwrap()
            .execute(
                &format!("update {s}.accounts set status='pending_verification' where id=$1"),
                &[&id],
            )
            .unwrap();
        assert_eq!(
            send(
                &router,
                "POST",
                &status_path,
                None,
                r#"{"status":"active","expected_status":"pending_verification"}"#
            )
            .0,
            StatusCode::OK
        );
        assert_eq!(
            send(
                &router,
                "POST",
                &status_path,
                None,
                r#"{"status":"disabled","expected_status":"active"}"#
            )
            .0,
            StatusCode::OK
        );
        assert_eq!(
            send(
                &router,
                "POST",
                &status_path,
                None,
                r#"{"status":"active","expected_status":"disabled"}"#
            )
            .0,
            StatusCode::OK
        );
        db.adapter
            .connect()
            .unwrap()
            .execute(
                &format!("update {s}.accounts set status='closed' where id=$1"),
                &[&id],
            )
            .unwrap();
        assert_eq!(
            send(
                &router,
                "POST",
                &status_path,
                None,
                r#"{"status":"active","expected_status":"closed"}"#
            )
            .0,
            StatusCode::CONFLICT
        );
        assert_eq!(
            send(
                &router,
                "POST",
                &format!("/admin/platform/accounts/{id}/password"),
                None,
                r#"{"new_password":"Closed-fixture-123"}"#
            )
            .0,
            StatusCode::CONFLICT
        );
        let audit=db.adapter.connect().unwrap().query(&format!("select row_to_json(a)::text from {s}.access_audit_events a where operation like 'account.%'"),&[]).unwrap();
        assert_eq!(audit.len(), 4);
        for r in audit {
            let text: String = r.get(0);
            assert!(!text.contains("Create-fixture"));
            assert!(!text.contains("$argon2"));
        }
    }
}
#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn account_security_reset_retires_every_tenant_credential_and_rolls_back_on_failure() {
    let db = Db::new(TenancyMode::Enabled);
    let s = db.schema();
    let router = app(&db, Some(db.context(db.actor_session.to_string())));
    device(&db, "t1", Uuid::now_v7(), db.member, 110);
    device(&db, "t2", Uuid::now_v7(), db.member, 111);
    let owner_session = device(&db, "t1", Uuid::now_v7(), db.owner, 112);
    let mut c = db.adapter.connect().unwrap();
    c.execute(&format!("insert into {s}.auth_tenant_selections(id,ticket_digest,account_id,client_id,login_entry,purpose,authenticated_at_epoch,expires_at_epoch) values($1,$2,$3,'live-admin-client','password','tenant_selection',1000,1100)"),&[&Uuid::now_v7(),&vec![113u8;32],&db.member]).unwrap();
    c.execute(&format!("insert into {s}.email_verification_codes(tenant_id,id,account_id,email,code,issued_at_epoch,expires_at_epoch) values('t1',$1,$2,'member@example.test','fixture',1000,1100)"),&[&Uuid::now_v7(),&db.member]).unwrap();
    drop(c);
    let path = format!("/admin/platform/accounts/{}/password", db.member);
    let body = r#"{"new_password":" New-fixture-123 "}"#;
    let before = credentials(&db, db.member);
    let before_identity = status(&db, db.member);
    let tenant_context = AccessAdminContext {
        actor: AccessActor {
            tenant_id: "t1".into(),
            subject_id: db.owner.to_string(),
            session_id: owner_session.to_string(),
        },
        authentication_source: "test".into(),
        request_id: "denied".into(),
    };
    assert_eq!(
        send(&app(&db, Some(tenant_context)), "POST", &path, None, body).0,
        StatusCode::FORBIDDEN
    );
    db.adapter.connect().unwrap().batch_execute(&format!("create function {s}.reset_fail() returns trigger language plpgsql as $$ begin raise exception 'refresh cleanup failure'; end $$; create trigger reset_fail before update on {s}.refresh_tokens for each row execute function {s}.reset_fail()" )).unwrap();
    assert_eq!(
        send(&router, "POST", &path, None, body).0,
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert_eq!(credentials(&db, db.member), before);
    assert_eq!(status(&db, db.member), before_identity);
    db.adapter.connect().unwrap().batch_execute(&format!("drop trigger reset_fail on {s}.refresh_tokens; create trigger reset_fail before insert on {s}.access_audit_events for each row execute function {s}.reset_fail()" )).unwrap();
    assert_eq!(
        send(&router, "POST", &path, None, body).0,
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert_eq!(credentials(&db, db.member), before);
    assert_eq!(status(&db, db.member), before_identity);
    db.adapter
        .connect()
        .unwrap()
        .batch_execute(&format!(
            "drop trigger reset_fail on {s}.access_audit_events"
        ))
        .unwrap();
    let result = send(&router, "POST", &path, None, body);
    assert_eq!(result.0, StatusCode::OK);
    assert_eq!(credentials(&db, db.member), vec![0, 0, 0, 0, 0, 2]);
    assert_eq!(status(&db, db.member).0, "active");
    assert!(PhcClientSecretCodec
        .verify_client_secret(" New-fixture-123 ", &status(&db, db.member).1)
        .unwrap());
    assert!(!PhcClientSecretCodec
        .verify_client_secret("New-fixture-123", &status(&db, db.member).1)
        .unwrap());
    assert!(credentials(&db, db.owner)[0] > 0);
    for id in [db.actor, db.owner] {
        assert_eq!(
            send(
                &router,
                "POST",
                &format!("/admin/platform/accounts/{id}/status"),
                None,
                r#"{"status":"disabled","expected_status":"active"}"#
            )
            .0,
            StatusCode::CONFLICT
        );
        assert_eq!(status(&db, id).0, "active");
        assert!(credentials(&db, id)[0] > 0);
    }
    device(&db, "t1", Uuid::now_v7(), db.member, 114);
    device(&db, "t2", Uuid::now_v7(), db.member, 115);
    let status_path = format!("/admin/platform/accounts/{}/status", db.member);
    assert_eq!(
        send(
            &router,
            "POST",
            &status_path,
            None,
            r#"{"status":"disabled","expected_status":"active"}"#
        )
        .0,
        StatusCode::OK
    );
    assert_eq!(credentials(&db, db.member), vec![0, 0, 0, 0, 0, 4]);
    assert_eq!(
        send(
            &router,
            "POST",
            &status_path,
            None,
            r#"{"status":"active","expected_status":"active"}"#
        )
        .0,
        StatusCode::CONFLICT
    );
    assert_eq!(
        send(
            &router,
            "POST",
            &status_path,
            None,
            r#"{"status":"active","expected_status":"disabled"}"#
        )
        .0,
        StatusCode::OK
    );
    assert_eq!(credentials(&db, db.member), vec![0, 0, 0, 0, 0, 4]);
    db.adapter.connect().unwrap().execute(&format!("update {s}.access_permissions set enabled=false where resource_type='idp.platform' and action='users.security'"),&[]).unwrap();
    assert_eq!(
        send(&router, "POST", &path, None, body).0,
        StatusCode::FORBIDDEN
    );
    db.adapter.connect().unwrap().execute(&format!("update {s}.access_permissions set enabled=true where resource_type='idp.platform' and action='users.security'"),&[]).unwrap();
    assert_eq!(
        send(
            &router,
            "POST",
            &format!("/admin/platform/accounts/{}/password", db.actor),
            None,
            body
        )
        .0,
        StatusCode::OK
    );
    assert_eq!(
        send(&router, "GET", "/admin/platform/accounts", None, "").0,
        StatusCode::FORBIDDEN
    );
}
#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn concurrent_platform_account_disables_cannot_remove_the_last_effective_admin() {
    let db = Db::new(TenancyMode::Disabled);
    let s = db.schema();
    let second = db.member;
    let mut c = db.adapter.connect().unwrap();
    c.execute(&format!("insert into {s}.access_role_bindings(id,tenant_id,account_id,role_id,resource_type,created_at_epoch,created_by) select $1,'0',$2,id,'idp.platform',1000,$3 from {s}.access_roles where tenant_id='0' and kind='system_admin'"),&[&Uuid::now_v7(),&second,&db.actor]).unwrap();
    drop(c);
    let first = app(&db, Some(db.context(db.actor_session.to_string())));
    let second_router = app(
        &db,
        Some(AccessAdminContext {
            actor: AccessActor {
                tenant_id: "0".into(),
                subject_id: second.to_string(),
                session_id: db.member_session.to_string(),
            },
            authentication_source: "test".into(),
            request_id: "concurrent-disable".into(),
        }),
    );
    let barrier = Arc::new(Barrier::new(2));
    let joins: Vec<_> = [(first, second), (second_router, db.actor)]
        .into_iter()
        .map(|(router, id)| {
            let barrier = barrier.clone();
            thread::spawn(move || {
                barrier.wait();
                send(
                    &router,
                    "POST",
                    &format!("/admin/platform/accounts/{id}/status"),
                    None,
                    r#"{"status":"disabled","expected_status":"active"}"#,
                )
                .0
            })
        })
        .collect();
    let codes: Vec<_> = joins.into_iter().map(|j| j.join().unwrap()).collect();
    assert_eq!(codes.iter().filter(|s| **s == StatusCode::OK).count(), 1);
    assert_eq!(
        codes
            .iter()
            .filter(|s| **s == StatusCode::FORBIDDEN)
            .count(),
        1
    );
    let active: i64 = db
        .adapter
        .connect()
        .unwrap()
        .query_one(
            &format!("select count(*) from {s}.accounts where id=any($1) and status='active'"),
            &[&vec![db.actor, second]],
        )
        .unwrap()
        .get(0);
    assert_eq!(active, 1);
}
