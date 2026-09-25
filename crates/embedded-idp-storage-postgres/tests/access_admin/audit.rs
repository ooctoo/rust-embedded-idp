use super::devices::{device, send};
use super::*;
use axum::{http::StatusCode, Extension, Router};
use embedded_idp_axum::audit_admin_router;
use serde_json::{json, Value};
fn app(db: &Db, context: Option<AccessAdminContext>) -> Router {
    let router = audit_admin_router(db.mode, Arc::new(db.service()));
    Router::new().nest(
        "/idp",
        if let Some(c) = context {
            router.layer(Extension(c))
        } else {
            router
        },
    )
}
fn seed_events(db: &Db) -> Vec<String> {
    (0..3)
        .map(|i| {
            db.service()
                .execute(
                    db.context(db.actor_session.to_string()),
                    db.command(AccessAdminMutation::CreateRole {
                        key: format!("reader-{i}"),
                        name: format!("Reader {i}"),
                    }),
                )
                .unwrap()
                .id
        })
        .collect()
}
fn get(router: &Router, path: &str, tenant: Option<&str>) -> (StatusCode, Value) {
    send(router, "GET", path, tenant, "")
}
#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn audit_http_pages_metadata_with_bound_filters_and_reads_immutable_scoped_details() {
    for mode in [TenancyMode::Disabled, TenancyMode::Enabled] {
        let db = Db::new(mode);
        let ids = seed_events(&db);
        let t = db.target();
        let s = db.schema();
        let router = app(&db, Some(db.context(db.actor_session.to_string())));
        let mut c = db.adapter.connect().unwrap();
        for (i, id) in ids.iter().enumerate() {
            c.execute(
                &format!("update {s}.access_audit_events set occurred_at_epoch=$1 where id=$2"),
                &[
                    &(if i == 0 { 9i64 } else { 10i64 }),
                    &Uuid::parse_str(id).unwrap(),
                ],
            )
            .unwrap();
        }
        let base = "/admin/access/audit-events";
        let filter=format!("operation=role.create&actor_id={}&occurred_after_unix_secs=9&occurred_before_unix_secs=10",db.actor);
        let first = get(&router, &format!("{base}?{filter}&limit=1"), Some(t));
        assert_eq!(first.0, StatusCode::OK);
        assert_eq!(first.1["items"].as_array().unwrap().len(), 1);
        assert_eq!(first.1["items"][0]["audit_id"], ids[0]);
        assert!(first.1["items"][0].get("change").is_none());
        assert_eq!(first.1["items"][0]["actor_id"], db.actor.to_string());
        assert_eq!(first.1["items"][0]["target_domain"], t);
        let cursor = first.1["next_cursor"].as_str().unwrap();
        let second = get(
            &router,
            &format!("{base}?{filter}&limit=1&cursor={cursor}"),
            Some(t),
        );
        assert_eq!(second.0, StatusCode::OK);
        assert_eq!(second.1["items"][0]["audit_id"], ids[1]);
        let next = second.1["next_cursor"].as_str().unwrap();
        let third = get(
            &router,
            &format!("{base}?{filter}&limit=1&cursor={next}"),
            Some(t),
        );
        assert_eq!(third.1["items"][0]["audit_id"], ids[2]);
        assert_eq!(third.1["has_more"], false);
        assert!(third.1["next_cursor"].is_null());
        for part in filter.split('&') {
            let changed = filter
                .split('&')
                .filter(|p| *p != part)
                .collect::<Vec<_>>()
                .join("&");
            assert_eq!(
                get(
                    &router,
                    &format!("{base}?{changed}&cursor={cursor}"),
                    Some(t)
                )
                .0,
                StatusCode::BAD_REQUEST
            );
        }
        let detail_path = format!("{base}/{}", ids[0]);
        let detail = get(&router, &detail_path, Some(t));
        assert_eq!(detail.0, StatusCode::OK);
        assert_eq!(detail.1["change"]["kind"], "role");
        assert!(detail.1["change"]["before"].is_null());
        assert_eq!(detail.1["change"]["after"]["name"], "Reader 0");
        c.execute(
            &format!(
                "update {s}.access_roles set name='Renamed' where tenant_id=$1 and key='reader-0'"
            ),
            &[&t],
        )
        .unwrap();
        assert_eq!(
            get(&router, &detail_path, Some(t)).1["change"]["after"]["name"],
            "Reader 0"
        );
        for bad in [
            "not-a-uuid".to_string(),
            Uuid::now_v7().to_string(),
            Uuid::parse_str(&ids[0]).unwrap().simple().to_string(),
        ] {
            assert_eq!(
                get(&router, &format!("{base}/{bad}"), Some(t)).0,
                StatusCode::NOT_FOUND
            );
        }
        if mode == TenancyMode::Enabled {
            assert_eq!(
                get(&router, &detail_path, Some("t2")).0,
                StatusCode::NOT_FOUND
            );
            assert_eq!(
                get(
                    &router,
                    &format!("{base}?{filter}&cursor={cursor}"),
                    Some("t2")
                )
                .0,
                StatusCode::BAD_REQUEST
            );
            assert_eq!(
                get(
                    &router,
                    &format!("/admin/platform/audit-events?{filter}&cursor={cursor}"),
                    None
                )
                .0,
                StatusCode::BAD_REQUEST
            );
            assert_eq!(
                get(&router, "/admin/platform/audit-events", None).1["items"],
                json!([])
            );
        }
        // Historical offline bootstrap has no actor session. It is visible only in domain 0.
        let bootstrap = Uuid::now_v7();
        c.execute(&format!("insert into {s}.access_audit_events(id,occurred_at_epoch,actor_id,actor_domain,actor_session_id,authentication_source,target_domain,operation,request_id,change_json) values($1,1,$2,'0',null,'offline_bootstrap','0','access.bootstrap','bootstrap-fixture','{{\"kind\":\"bootstrap\",\"before\":null,\"after\":{{\"tenant_id\":\"0\"}}}}'::jsonb)"),&[&bootstrap,&db.actor]).unwrap();
        let boot = get(
            &router,
            &format!("/admin/platform/audit-events/{bootstrap}"),
            None,
        );
        assert_eq!(boot.0, StatusCode::OK);
        assert!(boot.1["actor_session_id"].is_null());
        assert_eq!(boot.1["authentication_source"], "offline_bootstrap");
        assert_eq!(boot.1["change"]["kind"], "bootstrap");
        let items = get(
            &router,
            "/admin/platform/audit-events?operation=access.bootstrap",
            None,
        );
        assert_eq!(items.1["items"].as_array().unwrap().len(), 1);
        if mode == TenancyMode::Enabled {
            assert_eq!(
                get(&router, &format!("{base}/{bootstrap}"), Some(t)).0,
                StatusCode::NOT_FOUND
            );
        }
        let count = c
            .query_one(
                &format!("select count(*) from {s}.access_audit_events"),
                &[],
            )
            .unwrap()
            .get::<_, i64>(0);
        assert_eq!(count, 4);
    }
}
#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn audit_http_requires_separate_live_audit_authority_and_rejects_invalid_queries() {
    for mode in [TenancyMode::Disabled, TenancyMode::Enabled] {
        let db = Db::new(mode);
        let ids = seed_events(&db);
        let t = db.target();
        let s = db.schema();
        let base = "/admin/access/audit-events";
        let detail = format!("{base}/{}", ids[0]);
        let router = app(&db, Some(db.context(db.actor_session.to_string())));
        for path in [base, &detail] {
            assert_eq!(
                get(&app(&db, None), path, Some(t)).0,
                StatusCode::UNAUTHORIZED
            );
        }
        for query in [
            "limit=0",
            "limit=201",
            "cursor=bad",
            "actor_id=a&actor_id=b",
            "operation=BAD",
            "occurred_after_unix_secs=11&occurred_before_unix_secs=10",
            "occurred_after_unix_secs=18446744073709551615",
            "tenant_id=t2",
        ] {
            assert_eq!(
                get(&router, &format!("{base}?{query}"), Some(t)).0,
                StatusCode::BAD_REQUEST,
                "{query}"
            );
        }
        assert_eq!(
            get(&router, "/admin/platform/audit-events", Some("t1")).0,
            StatusCode::BAD_REQUEST
        );
        let mut c = db.adapter.connect().unwrap();
        // access.manage is not an alternative to audit.read and is not required for reads.
        c.batch_execute(&format!("update {s}.access_permissions set enabled=false where resource_type='idp.platform' and action='access.manage'")).unwrap();
        assert_eq!(get(&router, base, Some(t)).0, StatusCode::OK);
        assert_eq!(get(&router, &detail, Some(t)).0, StatusCode::OK);
        c.batch_execute(&format!("update {s}.access_permissions set enabled=true where resource_type='idp.platform' and action='access.manage'; update {s}.access_permissions set enabled=false where resource_type='idp.platform' and action='audit.read'")).unwrap();
        assert_eq!(get(&router, base, Some(t)).0, StatusCode::FORBIDDEN);
        assert_eq!(get(&router, &detail, Some(t)).0, StatusCode::FORBIDDEN);
        assert_eq!(
            get(&router, "/admin/platform/audit-events", None).0,
            StatusCode::FORBIDDEN
        );
        c.batch_execute(&format!("update {s}.access_permissions set enabled=true where resource_type='idp.platform' and action='audit.read'")).unwrap();
        if mode == TenancyMode::Enabled {
            let session = device(&db, t, Uuid::now_v7(), db.owner, 1);
            let mut context = db.context(session.to_string());
            context.actor.tenant_id = t.into();
            context.actor.subject_id = db.owner.to_string();
            let tenant = app(&db, Some(context));
            assert_eq!(get(&tenant, base, None).0, StatusCode::OK);
            assert_eq!(get(&tenant, base, Some("t2")).0, StatusCode::FORBIDDEN);
            assert_eq!(
                get(&tenant, "/admin/platform/audit-events", None).0,
                StatusCode::FORBIDDEN
            );
            c.batch_execute(&format!("update {s}.access_permissions set enabled=false where resource_type='idp.tenant' and action='access.read'")).unwrap();
            assert_eq!(get(&tenant, &detail, None).0, StatusCode::OK);
            c.batch_execute(&format!("update {s}.access_permissions set enabled=false where resource_type='idp.tenant' and action='audit.read'")).unwrap();
            assert_eq!(get(&tenant, base, None).0, StatusCode::FORBIDDEN);
            assert_eq!(get(&tenant, &detail, None).0, StatusCode::FORBIDDEN);
            c.batch_execute(&format!("update {s}.access_permissions set enabled=true where resource_type='idp.tenant'; update {s}.auth_sessions set status='revoked' where id='{session}'")).unwrap();
            assert_eq!(get(&tenant, base, None).0, StatusCode::FORBIDDEN);
            assert_eq!(get(&router, base, None).0, StatusCode::BAD_REQUEST);
            assert_eq!(get(&router, base, Some("0")).0, StatusCode::BAD_REQUEST);
        }
        c.batch_execute(&format!(
            "update {s}.auth_sessions set status='revoked' where tenant_id='0'"
        ))
        .unwrap();
        assert_eq!(get(&router, base, Some(t)).0, StatusCode::FORBIDDEN);
        assert_eq!(get(&router, &detail, Some(t)).0, StatusCode::FORBIDDEN);
    }
}
