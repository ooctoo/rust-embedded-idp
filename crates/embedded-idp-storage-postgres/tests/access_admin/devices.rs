use super::*;
use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
    Extension, Router,
};
use embedded_idp_axum::tenant_device_admin_router;
use embedded_idp_core::{DeviceStatus, SessionStatus};
use serde_json::Value;
use tower::ServiceExt;

// Synthetic trusted management-session fixture, including device authority checks.
pub(super) fn device(db: &Db, tenant: &str, id: Uuid, subject: Uuid, seed: u8) -> Uuid {
    let s = db.schema();
    let session = Uuid::now_v7();
    let mut c = db.adapter.connect().unwrap();
    let mut tx = c.transaction().unwrap();
    let key = char::from(b'a' + seed).to_string().repeat(43);
    tx.execute(&format!("insert into {s}.devices(tenant_id,id,client_id,device_name,proof_key_id,status,registered_at_epoch) values($1,$2,'live-admin-client','Fixture device',$3,'active',1000)"),&[&tenant,&id,&key]).unwrap();
    tx.execute(&format!("insert into {s}.device_proof_keys(tenant_id,key_id,device_id,algorithm,public_jwk,version,status,registered_at_epoch) values($1,$2,$3,'ed25519','synthetic-management-fixture',1,'active',1000)"),&[&tenant,&key,&id]).unwrap();
    tx.execute(&format!("insert into {s}.account_device_bindings(tenant_id,id,account_id,device_id,status,bound_at_epoch) values($1,$2,$3,$4,'active',1000)"),&[&tenant,&Uuid::now_v7(),&subject,&id]).unwrap();
    tx.execute(&format!("insert into {s}.auth_sessions(purpose,tenant_id,id,account_id,client_id,device_id,status,created_at_epoch,expires_at_epoch,refresh_token_version,authenticated_at_epoch) values('management',$1,$2,$3,'live-admin-client',$4,'active',1000,2000,1,1000)"),&[&tenant,&session,&subject,&id]).unwrap();
    tx.execute(&format!("insert into {s}.refresh_tokens(tenant_id,id,session_id,token_digest,token_version,issued_at_epoch,expires_at_epoch) values($1,$2,$3,$4,1,1000,2000)"),&[&tenant,&Uuid::now_v7(),&session,&vec![seed;32]]).unwrap();
    tx.execute(&format!("insert into {s}.authorization_codes(tenant_id,code_digest,account_id,source_session_id,login_entry,client_id,redirect_uri,scope,created_at_epoch,expires_at_epoch) values($1,$2,$3,$4,'admin-device-test','live-admin-client','https://example.test/callback','openid',1000,1100)"),&[&tenant,&vec![seed;32],&subject,&session]).unwrap();
    tx.execute(&format!("insert into {s}.auth_tenant_selections(id,ticket_digest,account_id,client_id,login_entry,purpose,authenticated_at_epoch,expires_at_epoch,source_tenant_id,source_session_id) values($1,$2,$3,'live-admin-client','admin-device-test','tenant_selection',1000,1100,$4,$5)"),&[&Uuid::now_v7(),&vec![seed;32],&subject,&tenant,&session]).unwrap();
    tx.execute(&format!("insert into {s}.device_nonces(tenant_id,id,device_id,purpose,challenge_digest,issued_at_epoch,expires_at_epoch) values($1,$2,$3,'heartbeat',$4,1000,1100)"),&[&tenant,&Uuid::now_v7(),&id,&vec![seed;32]]).unwrap();
    tx.commit().unwrap();
    session
}
fn app(db: &Db, context: Option<AccessAdminContext>) -> Router {
    let router = tenant_device_admin_router(db.mode, Arc::new(db.service()));
    let router = if let Some(context) = context {
        router.layer(Extension(context))
    } else {
        router
    };
    Router::new().nest("/idp", router)
}
pub(super) fn send(
    app: &Router,
    method: &str,
    path: &str,
    tenant: Option<&str>,
    body: &str,
) -> (StatusCode, Value) {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let mut builder = Request::builder()
                .method(method)
                .uri(format!("/idp{path}"))
                .header("content-type", "application/json");
            if let Some(tenant) = tenant {
                builder = builder.header("x-embedded-idp-tenant-id", tenant);
            }
            let response = app
                .clone()
                .oneshot(builder.body(Body::from(body.to_owned())).unwrap())
                .await
                .unwrap();
            assert_eq!(response.headers()["cache-control"], "no-store");
            let status = response.status();
            let bytes = to_bytes(response.into_body(), 65536).await.unwrap();
            (
                status,
                serde_json::from_slice(&bytes).unwrap_or(Value::Null),
            )
        })
}
fn mutate(
    db: &Db,
    id: Uuid,
    status: DeviceStatus,
    expected_status: DeviceStatus,
) -> Result<AccessAuditEvent, AccessError> {
    db.service().execute(
        db.context(db.actor_session.to_string()),
        db.command(AccessAdminMutation::SetDeviceStatus {
            device_id: id.to_string(),
            status,
            expected_status,
        }),
    )
}
fn snapshot(db: &Db, tenant: &str, id: Uuid) -> (String, i64, i64, i64, i64, i64, i64) {
    let s = db.schema();
    let row=db.adapter.connect().unwrap().query_one(&format!("select d.status,(select count(*) from {s}.auth_sessions x where x.tenant_id=d.tenant_id and x.device_id=d.id and x.status='active'),(select count(*) from {s}.refresh_tokens f join {s}.auth_sessions x on x.tenant_id=f.tenant_id and x.id=f.session_id where x.tenant_id=d.tenant_id and x.device_id=d.id and f.revoked_at_epoch is null),(select count(*) from {s}.device_nonces n where n.tenant_id=d.tenant_id and n.device_id=d.id),(select count(*) from {s}.device_proof_keys k where k.tenant_id=d.tenant_id and k.device_id=d.id and k.status='active'),(select count(*) from {s}.account_device_bindings b where b.tenant_id=d.tenant_id and b.device_id=d.id and b.status='active'),(select count(*) from {s}.authorization_codes c join {s}.auth_sessions x on x.tenant_id=c.tenant_id and x.id=c.source_session_id where x.tenant_id=d.tenant_id and x.device_id=d.id) from {s}.devices d where d.tenant_id=$1 and d.id=$2"),&[&tenant,&id]).unwrap();
    (
        row.get(0),
        row.get(1),
        row.get(2),
        row.get(3),
        row.get(4),
        row.get(5),
        row.get(6),
    )
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn device_admin_http_is_scoped_and_disable_revoke_cleanup_is_atomic_in_both_modes() {
    for mode in [TenancyMode::Disabled, TenancyMode::Enabled] {
        let db = Db::new(mode);
        let tenant = db.target();
        let id = Uuid::from_u128(1);
        let other = Uuid::from_u128(2);
        let session = device(&db, tenant, id, db.member, 1);
        // An administrative device action must affect every account on this
        // device, unlike the separate self-service unbind operation.
        let shared_session = Uuid::now_v7();
        let schema = db.schema();
        let mut c = db.adapter.connect().unwrap();
        c.execute(&format!("insert into {schema}.account_device_bindings(tenant_id,id,account_id,device_id,status,bound_at_epoch) values($1,$2,$3,$4,'active',1000)"),&[&tenant,&Uuid::now_v7(),&db.owner,&id]).unwrap();
        c.execute(&format!("insert into {schema}.auth_sessions(tenant_id,id,account_id,client_id,device_id,status,created_at_epoch,expires_at_epoch,refresh_token_version,authenticated_at_epoch) values($1,$2,$3,'live-admin-client',$4,'active',1000,2000,1,1000)"),&[&tenant,&shared_session,&db.owner,&id]).unwrap();
        c.execute(&format!("insert into {schema}.refresh_tokens(tenant_id,id,session_id,token_digest,token_version,issued_at_epoch,expires_at_epoch) values($1,$2,$3,$4,1,1000,2000)"),&[&tenant,&Uuid::now_v7(),&shared_session,&vec![9u8;32]]).unwrap();
        drop(c);
        device(&db, tenant, other, db.member, 2);
        if mode == TenancyMode::Enabled {
            device(&db, "t2", id, db.member, 3);
        }
        let router = app(&db, Some(db.context(db.actor_session.to_string())));
        assert_eq!(
            send(&app(&db, None), "GET", "/admin/devices", Some(tenant), "").0,
            StatusCode::UNAUTHORIZED
        );
        if mode == TenancyMode::Enabled {
            assert_eq!(
                send(&router, "GET", "/admin/devices", None, "").0,
                StatusCode::BAD_REQUEST
            );
        }
        let listed = send(&router, "GET", "/admin/devices?limit=1", Some(tenant), "");
        assert_eq!(listed.0, StatusCode::OK);
        assert_eq!(listed.1["items"][0]["device_id"], other.to_string());
        assert!(listed.1["items"][0].get("public_jwk").is_none());
        let cursor = listed.1["next_cursor"].as_str().unwrap();
        let last = send(
            &router,
            "GET",
            &format!("/admin/devices?cursor={cursor}"),
            Some(tenant),
            "",
        );
        assert_eq!(last.1["items"].as_array().unwrap().len(), 1);
        assert_eq!(last.1["has_more"], false);
        if mode == TenancyMode::Enabled {
            assert_eq!(
                send(
                    &router,
                    "GET",
                    &format!("/admin/devices?cursor={cursor}"),
                    Some("t2"),
                    ""
                )
                .0,
                StatusCode::BAD_REQUEST
            );
        }
        let mut denied = db.context(db.member_session.to_string());
        denied.actor.tenant_id = tenant.into();
        denied.actor.subject_id = db.member.to_string();
        assert_eq!(
            send(
                &app(&db, Some(denied)),
                "GET",
                "/admin/devices",
                Some(tenant),
                ""
            )
            .0,
            StatusCode::FORBIDDEN
        );
        let s = db.schema();
        let initial = snapshot(&db, tenant, id);
        db.adapter.connect().unwrap().batch_execute(&format!("create function {s}.fail_device_audit() returns trigger language plpgsql as $$ begin raise exception 'injected audit failure'; end $$; create trigger fail_device_audit before insert on {s}.access_audit_events for each row execute function {s}.fail_device_audit();")).unwrap();
        let path = format!("/admin/devices/{id}/revoke");
        assert_eq!(
            send(
                &router,
                "POST",
                &path,
                Some(tenant),
                r#"{"expected_status":"active"}"#
            )
            .0,
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(snapshot(&db, tenant, id), initial);
        db.adapter
            .connect()
            .unwrap()
            .batch_execute(&format!(
                "drop trigger fail_device_audit on {s}.access_audit_events"
            ))
            .unwrap();
        let result = send(
            &router,
            "POST",
            &format!("/admin/devices/{id}/disable"),
            Some(tenant),
            r#"{"expected_status":"active"}"#,
        );
        assert_eq!(result.0, StatusCode::OK);
        assert!(result.1["audit_id"].is_string());
        assert_eq!(
            snapshot(&db, tenant, id),
            ("disabled".into(), 0, 0, 0, 1, 2, 0)
        );
        assert_eq!(
            snapshot(&db, tenant, other),
            ("active".into(), 1, 1, 1, 1, 1, 1)
        );
        if mode == TenancyMode::Enabled {
            assert_eq!(snapshot(&db, "t2", id), ("active".into(), 1, 1, 1, 1, 1, 1));
        }
        let row=db.adapter.connect().unwrap().query_one(&format!("select revoked_at_epoch is not null from {s}.auth_tenant_selections where source_tenant_id=$1 and source_session_id=$2"),&[&tenant,&session]).unwrap();
        assert!(row.get::<_, bool>(0));
        assert_eq!(
            send(
                &router,
                "POST",
                &path,
                Some(tenant),
                r#"{"expected_status":"active"}"#
            )
            .0,
            StatusCode::CONFLICT
        );
        assert_eq!(
            send(
                &router,
                "POST",
                &path,
                Some(tenant),
                r#"{"expected_status":"disabled"}"#
            )
            .0,
            StatusCode::OK
        );
        assert_eq!(
            snapshot(&db, tenant, id),
            ("revoked".into(), 0, 0, 0, 0, 0, 0)
        );
        assert_eq!(
            send(
                &router,
                "POST",
                &format!("/admin/devices/{id}/disable"),
                Some(tenant),
                r#"{"expected_status":"revoked"}"#
            )
            .0,
            StatusCode::CONFLICT
        );
        let audit = db
            .adapter
            .connect()
            .unwrap()
            .query(
                &format!(
                    "select operation,change_json::text from {s}.access_audit_events order by id"
                ),
                &[],
            )
            .unwrap();
        assert_eq!(audit.len(), 2);
        assert_eq!(audit[1].get::<_, String>(0), "device.revoke");
        assert!(!audit[1]
            .get::<_, String>(1)
            .contains("synthetic-management-fixture"));
    }
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn device_admin_rechecks_tenant_grants_and_actor_device_authority() {
    let db = Db::new(TenancyMode::Enabled);
    let id = Uuid::now_v7();
    let session = device(&db, "t1", id, db.owner, 4);
    let mut context = db.context(session.to_string());
    context.actor.tenant_id = "t1".into();
    context.actor.subject_id = db.owner.to_string();
    let router = app(&db, Some(context.clone()));
    assert_eq!(
        send(&router, "GET", "/admin/devices", None, "").0,
        StatusCode::OK
    );
    assert_eq!(
        send(&router, "GET", "/admin/devices", Some("t2"), "").0,
        StatusCode::FORBIDDEN
    );
    let s = db.schema();
    db.adapter.connect().unwrap().batch_execute(&format!("update {s}.access_permissions set enabled=false where resource_type='idp.tenant' and action='devices.manage'")).unwrap();
    assert_eq!(
        send(&router, "GET", "/admin/devices", None, "").0,
        StatusCode::FORBIDDEN
    );
    db.adapter.connect().unwrap().batch_execute(&format!("update {s}.access_permissions set enabled=true where resource_type='idp.tenant' and action='devices.manage'")).unwrap();
    let mut c = db.adapter.connect().unwrap();
    for sql in [format!("update {s}.device_proof_keys set status='retired',retired_at_epoch=1000 where tenant_id='t1'"),format!("update {s}.account_device_bindings set status='suspended' where tenant_id='t1'")] {
        c.batch_execute(&sql).unwrap();
        assert_eq!(db.service().get_device(context.clone(),"t1".into(),id.to_string()),Err(AccessError::Forbidden));
        assert_eq!(db.service().execute(context.clone(),db.command(AccessAdminMutation::SetDeviceStatus{device_id:id.to_string(),status:DeviceStatus::Disabled,expected_status:DeviceStatus::Active})),Err(AccessError::Forbidden));
        c.batch_execute(&format!("update {s}.device_proof_keys set status='active',retired_at_epoch=null where tenant_id='t1'; update {s}.account_device_bindings set status='active' where tenant_id='t1'")).unwrap();
    }
    mutate(&db, id, DeviceStatus::Disabled, DeviceStatus::Active).unwrap();
    assert_eq!(
        db.service()
            .get_device(context, "t1".into(), id.to_string()),
        Err(AccessError::Forbidden)
    );
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn device_revocation_serializes_with_waiting_authentication() {
    use std::sync::mpsc;
    struct GateClock {
        locked: mpsc::SyncSender<()>,
        release: Arc<Barrier>,
    }
    impl Clock for GateClock {
        fn now(&self) -> SystemTime {
            self.locked.send(()).unwrap();
            self.release.wait();
            FixedClock.now()
        }
    }
    let db = Db::new(TenancyMode::Enabled);
    let id = Uuid::now_v7();
    let session = device(&db, "t1", id, db.member, 5);
    let (locked, ready) = mpsc::sync_channel(1);
    let release = Arc::new(Barrier::new(2));
    let svc = CoreAccessAdminService::new(
        db.mode,
        catalog(),
        db.store(),
        GateClock {
            locked,
            release: release.clone(),
        },
        UuidIds,
    );
    let context = db.context(db.actor_session.to_string());
    let command = db.command(AccessAdminMutation::SetDeviceStatus {
        device_id: id.to_string(),
        status: DeviceStatus::Revoked,
        expected_status: DeviceStatus::Active,
    });
    let revocation = thread::spawn(move || svc.execute(context, command));
    ready.recv_timeout(Duration::from_secs(5)).unwrap();
    let store = db.store();
    let session = session.to_string();
    let (done, received) = mpsc::channel();
    let reader = thread::spawn(move || {
        let result: Result<SessionStatus, TenantAuthError> =
            store.auth_transaction(TenancyMode::Enabled, |tx| {
                tx.lock_tenants(&["t1".into()])?;
                Ok(tx.session("t1", &session)?.unwrap().status)
            });
        done.send(result).unwrap();
    });
    assert!(matches!(
        received.recv_timeout(Duration::from_millis(100)),
        Err(mpsc::RecvTimeoutError::Timeout)
    ));
    release.wait();
    revocation.join().unwrap().unwrap();
    assert_eq!(
        received
            .recv_timeout(Duration::from_secs(5))
            .unwrap()
            .unwrap(),
        SessionStatus::Revoked
    );
    reader.join().unwrap();
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn device_filters_preserve_active_bindings_tenant_scope_and_pagination_in_both_modes() {
    for mode in [TenancyMode::Disabled, TenancyMode::Enabled] {
        let db = Db::new(mode);
        let t = db.target();
        let s = db.schema();
        let mut c = db.adapter.connect().unwrap();
        c.execute(&format!("insert into {s}.oidc_clients(client_id,client_name,redirect_uris_json,client_type,pkce_required,created_at_epoch) values('other-client','Other','[]','public_desktop',true,1000)"), &[]).unwrap();
        // 1/2 match all predicates; 3-8 each differ in one predicate.
        for (id, client, status, time, binding) in [
            (1, "live-admin-client", "active", 1000_i64, "active"),
            (2, "live-admin-client", "active", 1000, "active"),
            (3, "live-admin-client", "active", 1000, "unbound"),
            (4, "live-admin-client", "active", 1000, "suspended"),
            (5, "live-admin-client", "disabled", 1000, "active"),
            (6, "other-client", "active", 1000, "active"),
            (7, "live-admin-client", "active", 999, "active"),
            (8, "live-admin-client", "active", 1001, "active"),
            (9, "live-admin-client", "pending", 1000, ""),
            (10, "live-admin-client", "revoked", 1000, ""),
        ] {
            let id = Uuid::from_u128(id);
            c.execute(&format!("insert into {s}.devices(tenant_id,id,client_id,device_name,status,registered_at_epoch) values($1,$2,$3,'Filter fixture',$4,$5)"), &[&t,&id,&client,&status,&time]).unwrap();
            if !binding.is_empty() {
                c.execute(&format!("insert into {s}.account_device_bindings(tenant_id,id,account_id,device_id,status,bound_at_epoch) values($1,$2,$3,$4,$5,1000)"), &[&t,&Uuid::now_v7(),&db.member,&id,&binding]).unwrap();
            }
        }
        // Shared devices and historical bindings must not duplicate list rows.
        for (subject, status) in [
            (db.owner, "active"),
            (db.member, "unbound"),
            (db.member, "unbound"),
        ] {
            c.execute(&format!("insert into {s}.account_device_bindings(tenant_id,id,account_id,device_id,status,bound_at_epoch) values($1,$2,$3,$4,$5,1000)"), &[&t,&Uuid::now_v7(),&subject,&Uuid::from_u128(1),&status]).unwrap();
        }
        if mode == TenancyMode::Enabled {
            // An active binding to the same ID in another tenant cannot rescue
            // a suspended/unbound/absent binding in the selected tenant.
            for id in [3, 4, 9] {
                c.execute(&format!("insert into {s}.devices(tenant_id,id,client_id,device_name,status,registered_at_epoch) values('t2',$1,'live-admin-client','Other tenant','active',1000)"), &[&Uuid::from_u128(id)]).unwrap();
                c.execute(&format!("insert into {s}.account_device_bindings(tenant_id,id,account_id,device_id,status,bound_at_epoch) values('t2',$1,$2,$3,'active',1000)"), &[&Uuid::now_v7(),&db.member,&Uuid::from_u128(id)]).unwrap();
            }
        }
        drop(c);
        let router = app(&db, Some(db.context(db.actor_session.to_string())));
        let query = format!("account_id={}&client_id=live-admin-client&status=active&registered_after_unix_secs=1000&registered_before_unix_secs=1000", db.member);
        let result = send(
            &router,
            "GET",
            &format!("/admin/devices?limit=1&{query}"),
            Some(t),
            "",
        );
        assert_eq!(result.0, StatusCode::OK, "{}", result.1);
        assert_eq!(result.1["items"].as_array().unwrap().len(), 1);
        assert_eq!(
            result.1["items"][0]["device_id"],
            Uuid::from_u128(2).to_string()
        );
        let cursor = result.1["next_cursor"].as_str().unwrap();
        let next = send(
            &router,
            "GET",
            &format!("/admin/devices?limit=1&{query}&cursor={cursor}"),
            Some(t),
            "",
        );
        assert_eq!(next.0, StatusCode::OK);
        assert_eq!(next.1["items"].as_array().unwrap().len(), 1);
        assert_eq!(
            next.1["items"][0]["device_id"],
            Uuid::from_u128(1).to_string()
        );
        assert_eq!(next.1["has_more"], false);
        assert_eq!(next.1["next_cursor"], Value::Null);
        for part in query.split('&') {
            let changed = query
                .split('&')
                .filter(|p| *p != part)
                .collect::<Vec<_>>()
                .join("&");
            assert_eq!(
                send(
                    &router,
                    "GET",
                    &format!("/admin/devices?{changed}&cursor={cursor}"),
                    Some(t),
                    ""
                )
                .0,
                StatusCode::BAD_REQUEST
            );
        }
        if mode == TenancyMode::Enabled {
            assert_eq!(
                send(
                    &router,
                    "GET",
                    &format!("/admin/devices?{query}&cursor={cursor}"),
                    Some("t2"),
                    ""
                )
                .0,
                StatusCode::BAD_REQUEST
            );
        }
        let all = send(&router, "GET", "/admin/devices", Some(t), "");
        assert_eq!(all.1["items"].as_array().unwrap().len(), 10);
        assert!(all.1["items"]
            .as_array()
            .unwrap()
            .iter()
            .all(|r| r["tenant_id"] == t));
        for (filter, expected) in [
            (format!("account_id={}", db.member), 6),
            (format!("account_id={}", db.owner), 1),
            ("account_id=not-a-uuid".into(), 0),
            ("client_id=missing".into(), 0),
            ("client_id=other-client".into(), 1),
            ("status=disabled".into(), 1),
            ("status=pending".into(), 1),
            ("status=revoked".into(), 1),
            ("registered_before_unix_secs=999".into(), 1),
            ("registered_after_unix_secs=1001".into(), 1),
        ] {
            let result = send(
                &router,
                "GET",
                &format!("/admin/devices?{filter}"),
                Some(t),
                "",
            );
            assert_eq!(result.0, StatusCode::OK, "{filter}");
            assert_eq!(
                result.1["items"].as_array().unwrap().len(),
                expected,
                "{filter}"
            );
        }
        for invalid in [
            "account_id=",
            "status=unknown",
            "status=active&status=disabled",
            "registered_after_unix_secs=-1",
            "registered_before_unix_secs=18446744073709551615",
            "registered_after_unix_secs=1001&registered_before_unix_secs=1000",
            "registered_after_unix_secs=1.5",
            "limit=201",
            "limit=0",
            "unknown=value",
            "cursor=broken",
        ] {
            assert_eq!(
                send(
                    &router,
                    "GET",
                    &format!("/admin/devices?{invalid}"),
                    Some(t),
                    ""
                )
                .0,
                StatusCode::BAD_REQUEST,
                "{invalid}"
            );
        }
        // Every filtered page still checks the actor's current authority.
        let mut c = db.adapter.connect().unwrap();
        c.execute(
            &format!("update {s}.auth_sessions set status='revoked' where tenant_id='0' and id=$1"),
            &[&db.actor_session],
        )
        .unwrap();
        assert_eq!(
            send(
                &router,
                "GET",
                &format!("/admin/devices?{query}&cursor={cursor}"),
                Some(t),
                ""
            )
            .0,
            StatusCode::FORBIDDEN
        );
    }
}
