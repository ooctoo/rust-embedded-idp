use super::devices::{device, send};
use super::*;
use axum::{http::StatusCode, Extension, Router};
use embedded_idp_axum::tenant_session_admin_router;
use embedded_idp_core::SessionStatus;

fn app(db: &Db, context: Option<AccessAdminContext>) -> Router {
    let router = tenant_session_admin_router(db.mode, Arc::new(db.service()));
    let router = if let Some(c) = context {
        router.layer(Extension(c))
    } else {
        router
    };
    Router::new().nest("/idp", router)
}
fn state(db: &Db, tenant: &str, session: Uuid) -> (String, i64, i64, i64) {
    let s = db.schema();
    let row=db.adapter.connect().unwrap().query_one(&format!("select x.status,(select count(*) from {s}.refresh_tokens f where f.tenant_id=x.tenant_id and f.session_id=x.id and f.revoked_at_epoch is null),(select count(*) from {s}.authorization_codes c where c.tenant_id=x.tenant_id and c.source_session_id=x.id),(select count(*) from {s}.auth_tenant_selections p where p.source_tenant_id=x.tenant_id and p.source_session_id=x.id and p.revoked_at_epoch is null) from {s}.auth_sessions x where x.tenant_id=$1 and x.id=$2"),&[&tenant,&session]).unwrap();
    (row.get(0), row.get(1), row.get(2), row.get(3))
}
#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn session_admin_http_filters_paginates_and_revokes_atomically_in_both_modes() {
    for mode in [TenancyMode::Disabled, TenancyMode::Enabled] {
        let db = Db::new(mode);
        let tenant = db.target();
        let device_id = Uuid::now_v7();
        let first = device(&db, tenant, device_id, db.member, 10);
        let second = device(&db, tenant, Uuid::now_v7(), db.member, 11);
        let other = device(&db, tenant, Uuid::now_v7(), db.owner, 12);
        let s = db.schema();
        if mode == TenancyMode::Enabled {
            let mut c = db.adapter.connect().unwrap();
            c.execute(&format!("insert into {s}.auth_sessions(tenant_id,id,account_id,client_id,status,created_at_epoch,expires_at_epoch,refresh_token_version,authenticated_at_epoch) select 't2',id,account_id,client_id,status,created_at_epoch,expires_at_epoch,refresh_token_version,authenticated_at_epoch from {s}.auth_sessions where tenant_id='t1' and id=$1"),&[&first]).unwrap();
            c.execute(&format!("insert into {s}.refresh_tokens(tenant_id,id,session_id,token_digest,token_version,issued_at_epoch,expires_at_epoch) values('t2',$1,$2,$3,1,1000,2000)"),&[&Uuid::now_v7(),&first,&vec![19u8;32]]).unwrap();
        }
        let router = app(&db, Some(db.context(db.actor_session.to_string())));
        assert_eq!(
            send(&app(&db, None), "GET", "/admin/sessions", Some(tenant), "").0,
            StatusCode::UNAUTHORIZED
        );
        let prefix = format!("/admin/sessions?account_id={}&limit=1", db.member);
        let page = send(&router, "GET", &prefix, Some(tenant), "");
        assert_eq!(page.0, StatusCode::OK);
        assert_eq!(page.1["has_more"], true);
        let cursor = page.1["next_cursor"].as_str().unwrap();
        let next = send(
            &router,
            "GET",
            &format!(
                "/admin/sessions?account_id={}&limit=200&cursor={cursor}",
                db.member
            ),
            Some(tenant),
            "",
        );
        assert_eq!(next.1["items"].as_array().unwrap().len(), 2);
        assert_eq!(
            send(
                &router,
                "GET",
                &format!("/admin/sessions?cursor={cursor}"),
                Some(tenant),
                ""
            )
            .0,
            StatusCode::BAD_REQUEST
        );
        if mode == TenancyMode::Enabled {
            assert_eq!(
                send(
                    &router,
                    "GET",
                    &format!("{prefix}&cursor={cursor}"),
                    Some("t2"),
                    ""
                )
                .0,
                StatusCode::BAD_REQUEST
            );
        }
        let filter=format!("/admin/sessions?account_id={}&device_id={device_id}&client_id=live-admin-client&status=active&created_after_unix_secs=999&created_before_unix_secs=1000",db.member);
        let filtered = send(&router, "GET", &filter, Some(tenant), "");
        assert_eq!(filtered.0, StatusCode::OK);
        assert_eq!(filtered.1["items"].as_array().unwrap().len(), 1);
        assert_eq!(filtered.1["items"][0]["session_id"], first.to_string());
        assert!(filtered.1["items"][0]
            .get("refresh_token_version")
            .is_none());
        for filter in [
            "created_after_unix_secs=1001",
            "client_id=other",
            "status=revoked",
            "account_id=unknown",
        ] {
            assert_eq!(
                send(
                    &router,
                    "GET",
                    &format!("/admin/sessions?{filter}"),
                    Some(tenant),
                    ""
                )
                .1["items"]
                    .as_array()
                    .unwrap()
                    .len(),
                0
            );
        }
        for query in [
            "limit=0",
            "status=bad",
            "created_after_unix_secs=1001&created_before_unix_secs=1000",
            "tenant_id=t2",
        ] {
            assert_eq!(
                send(
                    &router,
                    "GET",
                    &format!("/admin/sessions?{query}"),
                    Some(tenant),
                    ""
                )
                .0,
                StatusCode::BAD_REQUEST
            );
        }
        let path = format!("/admin/sessions/{first}/revoke");
        assert_eq!(
            send(
                &router,
                "POST",
                &path,
                Some(tenant),
                r#"{"revoked_at_unix_secs":1}"#
            )
            .0,
            StatusCode::UNPROCESSABLE_ENTITY
        );
        db.adapter.connect().unwrap().batch_execute(&format!("create function {s}.fail_session_audit() returns trigger language plpgsql as $$ begin raise exception 'injected audit failure'; end $$; create trigger fail_session_audit before insert on {s}.access_audit_events for each row execute function {s}.fail_session_audit();")).unwrap();
        assert_eq!(
            send(&router, "POST", &path, Some(tenant), "{}").0,
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(state(&db, tenant, first), ("active".into(), 1, 1, 1));
        db.adapter
            .connect()
            .unwrap()
            .batch_execute(&format!(
                "drop trigger fail_session_audit on {s}.access_audit_events"
            ))
            .unwrap();
        assert_eq!(
            send(&router, "POST", &path, Some(tenant), "{}").0,
            StatusCode::OK
        );
        assert_eq!(state(&db, tenant, first), ("revoked".into(), 0, 0, 0));
        assert_eq!(state(&db, tenant, second), ("active".into(), 1, 1, 1));
        assert_eq!(
            send(&router, "POST", &path, Some(tenant), "{}").0,
            StatusCode::OK
        );
        let path = format!("/admin/accounts/{}/sessions/revoke", db.member);
        let all = send(&router, "POST", &path, Some(tenant), "{}");
        assert_eq!(all.0, StatusCode::OK);
        assert_eq!(all.1["revoked_session_count"], 2);
        assert_eq!(state(&db, tenant, second), ("revoked".into(), 0, 0, 0));
        assert_eq!(state(&db, tenant, other), ("active".into(), 1, 1, 1));
        assert_eq!(
            send(&router, "POST", &path, Some(tenant), "{}").1["revoked_session_count"],
            0
        );
        if mode == TenancyMode::Enabled {
            assert_eq!(state(&db, "t2", first), ("active".into(), 1, 0, 0));
        }
        let row=db.adapter.connect().unwrap().query_one(&format!("select d.status,b.status,(select count(*) from {s}.device_nonces where tenant_id=d.tenant_id and device_id=d.id) from {s}.devices d join {s}.account_device_bindings b on b.tenant_id=d.tenant_id and b.device_id=d.id where d.tenant_id=$1 and d.id=$2"),&[&tenant,&device_id]).unwrap();
        assert_eq!(row.get::<_, String>(0), "active");
        assert_eq!(row.get::<_, String>(1), "active");
        assert_eq!(row.get::<_, i64>(2), 1);
        assert_eq!(
            send(
                &router,
                "GET",
                &format!("/admin/sessions/{first}"),
                Some(tenant),
                ""
            )
            .1["status"],
            "revoked"
        );
    }
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn session_admin_requires_current_same_tenant_authority_and_rolls_back_bulk_cleanup() {
    let db = Db::new(TenancyMode::Enabled);
    let owner_session = device(&db, "t1", Uuid::now_v7(), db.owner, 13);
    let target_session = device(&db, "t1", Uuid::now_v7(), db.member, 14);
    let mut context = db.context(owner_session.to_string());
    context.actor.tenant_id = "t1".into();
    context.actor.subject_id = db.owner.to_string();
    let router = app(&db, Some(context.clone()));
    assert_eq!(
        send(&router, "GET", "/admin/sessions", None, "").0,
        StatusCode::OK
    );
    assert_eq!(
        send(&router, "GET", "/admin/sessions", Some("t2"), "").0,
        StatusCode::FORBIDDEN
    );
    let s = db.schema();
    let path = format!("/admin/accounts/{}/sessions/revoke", db.member);
    db.adapter.connect().unwrap().batch_execute(&format!("update {s}.access_permissions set enabled=false where resource_type='idp.tenant' and action='sessions.manage'")).unwrap();
    assert_eq!(
        send(&router, "POST", &path, None, "{}").0,
        StatusCode::FORBIDDEN
    );
    db.adapter.connect().unwrap().batch_execute(&format!("update {s}.access_permissions set enabled=true where resource_type='idp.tenant' and action='sessions.manage'; create function {s}.fail_session_refresh() returns trigger language plpgsql as $$ begin raise exception 'injected refresh failure'; end $$; create trigger fail_session_refresh after update on {s}.refresh_tokens for each row execute function {s}.fail_session_refresh();")).unwrap();
    assert_eq!(
        send(&router, "POST", &path, None, "{}").0,
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert_eq!(state(&db, "t1", target_session), ("active".into(), 1, 1, 1));
    assert_eq!(state(&db, "t1", db.member_session).0, "active");
    db.adapter
        .connect()
        .unwrap()
        .batch_execute(&format!(
            "drop trigger fail_session_refresh on {s}.refresh_tokens"
        ))
        .unwrap();
    let self_path = format!("/admin/sessions/{owner_session}/revoke");
    assert_eq!(
        send(&router, "POST", &self_path, None, "{}").0,
        StatusCode::OK
    );
    assert_eq!(
        send(&router, "GET", "/admin/sessions", None, "").0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        db.service()
            .get_session(context, "t1".into(), target_session.to_string()),
        Err(AccessError::Forbidden)
    );
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn concurrent_bulk_session_revocations_count_once_and_revoke_all_families() {
    let db = Db::new(TenancyMode::Enabled);
    let session = device(&db, "t1", Uuid::now_v7(), db.member, 15);
    let barrier = Arc::new(Barrier::new(3));
    let mut threads = vec![];
    for _ in 0..2 {
        let service = db.service();
        let context = db.context(db.actor_session.to_string());
        let command = db.command(AccessAdminMutation::RevokeSubjectSessions {
            subject_id: db.member.to_string(),
        });
        let barrier = barrier.clone();
        threads.push(thread::spawn(move || {
            barrier.wait();
            service.execute(context, command).unwrap()
        }));
    }
    barrier.wait();
    let mut counts: Vec<_> = threads
        .into_iter()
        .map(|t| match t.join().unwrap().change {
            AccessChange::SubjectSessionsRevoked {
                active_session_count,
                ..
            } => active_session_count,
            _ => panic!(),
        })
        .collect();
    counts.sort();
    assert_eq!(counts, vec![0, 2]);
    assert_eq!(state(&db, "t1", session), ("revoked".into(), 0, 0, 0));
    assert_eq!(
        db.service()
            .get_session(
                db.context(db.actor_session.to_string()),
                "t1".into(),
                session.to_string()
            )
            .unwrap()
            .status,
        SessionStatus::Revoked
    );
}
