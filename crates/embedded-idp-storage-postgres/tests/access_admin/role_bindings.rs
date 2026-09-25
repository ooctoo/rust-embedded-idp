use super::devices::{device, send};
use super::*;
use axum::{http::StatusCode, Extension, Router};
use embedded_idp_axum::role_binding_admin_router;
use serde_json::{json, Value};
fn app(db: &Db, context: Option<AccessAdminContext>) -> Router {
    let r = role_binding_admin_router(db.mode, Arc::new(db.service()));
    Router::new().nest(
        "/idp",
        if let Some(c) = context {
            r.layer(Extension(c))
        } else {
            r
        },
    )
}
fn role(db: &Db) -> String {
    let id = event_role_id(
        db.service()
            .execute(
                db.context(db.actor_session.to_string()),
                db.command(AccessAdminMutation::CreateRole {
                    key: "reader".into(),
                    name: "Reader".into(),
                }),
            )
            .unwrap(),
    );
    db.service()
        .execute(
            db.context(db.actor_session.to_string()),
            db.command(AccessAdminMutation::ReplaceRolePermissions {
                role_id: id.clone(),
                permissions: vec![PermissionKey {
                    resource_type: "report".into(),
                    action: "read".into(),
                }],
                expected_version: 1,
            }),
        )
        .unwrap();
    id
}
fn path(subject: Uuid) -> String {
    format!("/admin/access/subjects/{subject}/role-bindings")
}
fn body(role: &str, resource: Option<&str>) -> String {
    json!({"role_id":role,"resource_type":"report","scope":resource.map_or(json!({"kind":"type"}),|id|json!({"kind":"instance","resource_id":id}))}).to_string()
}
fn grant(
    router: &Router,
    tenant: &str,
    subject: Uuid,
    role: &str,
    resource: Option<&str>,
) -> String {
    let r = send(
        router,
        "POST",
        &path(subject),
        Some(tenant),
        &body(role, resource),
    );
    assert_eq!(r.0, StatusCode::CREATED, "{}", r.1);
    assert!(r.1["audit_id"].is_string());
    assert_eq!(
        r.1["binding"]["scope"]["kind"],
        if resource.is_some() {
            "instance"
        } else {
            "type"
        }
    );
    r.1["binding"]["binding_id"].as_str().unwrap().to_owned()
}
fn revoke(router: &Router, tenant: &str, id: &str) -> (StatusCode, Value) {
    send(
        router,
        "DELETE",
        &format!("/admin/access/role-bindings/{id}"),
        Some(tenant),
        "",
    )
}
fn decision(db: &Db, tenant: &str, resource: Option<&str>) -> AccessDecision {
    CoreAccessService::new(db.mode, catalog(), db.store())
        .check(AccessQuery {
            tenant_id: tenant.into(),
            subject_id: db.member.to_string(),
            resource_type: "report".into(),
            action: "read".into(),
            resource_id: resource.map(str::to_owned),
        })
        .unwrap()
}
#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn binding_http_grants_and_revokes_exact_resources_with_atomic_audit_in_both_modes() {
    for mode in [TenancyMode::Disabled, TenancyMode::Enabled] {
        let db = Db::new(mode);
        let t = db.target();
        let s = db.schema();
        let role = role(&db);
        let router = app(&db, Some(db.context(db.actor_session.to_string())));
        let first = grant(&router, t, db.member, &role, Some("report-1"));
        assert_eq!(decision(&db, t, Some("report-1")), AccessDecision::Allow);
        assert_eq!(decision(&db, t, Some("report-2")), AccessDecision::Deny);
        assert_eq!(decision(&db, t, None), AccessDecision::Deny);
        assert_eq!(
            send(
                &router,
                "POST",
                &path(db.member),
                Some(t),
                &body(&role, Some("report-1"))
            )
            .0,
            StatusCode::CONFLICT
        );
        let second = grant(&router, t, db.member, &role, Some("report-2"));
        if mode == TenancyMode::Enabled {
            assert_eq!(decision(&db, "t2", Some("report-1")), AccessDecision::Deny);
            assert_eq!(revoke(&router, "t2", &first).0, StatusCode::NOT_FOUND);
        }
        let r = revoke(&router, t, &first);
        assert_eq!(r.0, StatusCode::OK);
        assert_eq!(r.1["binding"], Value::Null);
        assert_eq!(decision(&db, t, Some("report-1")), AccessDecision::Deny);
        assert_eq!(decision(&db, t, Some("report-2")), AccessDecision::Allow);
        assert_eq!(revoke(&router, t, &first).0, StatusCode::NOT_FOUND);
        let all = grant(&router, t, db.member, &role, None);
        assert_eq!(decision(&db, t, None), AccessDecision::Allow);
        assert_eq!(decision(&db, t, Some("report-3")), AccessDecision::Allow);
        assert_eq!(
            send(
                &router,
                "POST",
                &path(db.member),
                Some(t),
                &body(&role, None)
            )
            .0,
            StatusCode::CONFLICT
        );
        assert_eq!(revoke(&router, t, &all).0, StatusCode::OK);
        assert_eq!(decision(&db, t, Some("report-3")), AccessDecision::Deny);
        assert_eq!(decision(&db, t, Some("report-2")), AccessDecision::Allow);
        let mut c = db.adapter.connect().unwrap();
        c.batch_execute(&format!("create function {s}.fail_binding_http_audit() returns trigger language plpgsql as $$ begin raise exception 'injected audit failure'; end $$; create trigger fail_binding_http_audit before insert on {s}.access_audit_events for each row execute function {s}.fail_binding_http_audit()" )).unwrap();
        assert_eq!(
            send(
                &router,
                "POST",
                &path(db.member),
                Some(t),
                &body(&role, None)
            )
            .0,
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(decision(&db, t, Some("report-3")), AccessDecision::Deny);
        assert_eq!(
            revoke(&router, t, &second).0,
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(decision(&db, t, Some("report-2")), AccessDecision::Allow);
        assert_eq!(
            send(&router, "GET", &path(db.member), Some(t), "").1["items"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        c.batch_execute(&format!(
            "drop trigger fail_binding_http_audit on {s}.access_audit_events"
        ))
        .unwrap();
        assert_eq!(revoke(&router, t, &second).0, StatusCode::OK);
        assert_eq!(decision(&db, t, Some("report-2")), AccessDecision::Deny);
    }
}
#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn binding_http_queries_and_mutations_enforce_identity_scope_and_protected_roles() {
    for mode in [TenancyMode::Disabled, TenancyMode::Enabled] {
        let db = Db::new(mode);
        let t = db.target();
        let s = db.schema();
        let role = role(&db);
        let router = app(&db, Some(db.context(db.actor_session.to_string())));
        let subject_path = path(db.member);
        let first = grant(&router, t, db.member, &role, Some("report-1"));
        let second = grant(&router, t, db.member, &role, Some("report-2"));
        assert_eq!(
            send(&app(&db, None), "GET", &subject_path, Some(t), "").0,
            StatusCode::UNAUTHORIZED
        );
        if mode == TenancyMode::Enabled {
            assert_eq!(
                send(&router, "GET", &subject_path, None, "").0,
                StatusCode::BAD_REQUEST
            );
        }
        let page = send(
            &router,
            "GET",
            &format!("{subject_path}?limit=1"),
            Some(t),
            "",
        );
        assert_eq!(page.0, StatusCode::OK);
        assert_eq!(page.1["items"][0]["binding_id"], first);
        let cursor = page.1["next_cursor"].as_str().unwrap();
        let next_path = format!("{subject_path}?cursor={cursor}");
        let next = send(&router, "GET", &next_path, Some(t), "");
        assert_eq!(next.1["items"][0]["binding_id"], second);
        assert_eq!(next.1["has_more"], false);
        assert_eq!(
            send(
                &router,
                "GET",
                &format!("{}?cursor={cursor}", path(db.owner)),
                Some(t),
                ""
            )
            .0,
            StatusCode::BAD_REQUEST
        );
        if mode == TenancyMode::Enabled {
            assert_eq!(
                send(&router, "GET", &next_path, Some("t2"), "").0,
                StatusCode::BAD_REQUEST
            );
        }
        for invalid in ["limit=0", "limit=201", "cursor=broken", "unknown=1"] {
            assert_eq!(
                send(
                    &router,
                    "GET",
                    &format!("{subject_path}?{invalid}"),
                    Some(t),
                    ""
                )
                .0,
                StatusCode::BAD_REQUEST
            );
        }
        assert_eq!(
            send(&router, "GET", &path(Uuid::now_v7()), Some(t), "").0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            send(
                &router,
                "GET",
                "/admin/access/subjects/missing/role-bindings",
                Some(t),
                ""
            )
            .0,
            StatusCode::NOT_FOUND
        );
        for invalid in [Some(""), Some("*"), Some("bad/id")] {
            assert_eq!(
                send(
                    &router,
                    "POST",
                    &subject_path,
                    Some(t),
                    &body(&role, invalid)
                )
                .0,
                StatusCode::BAD_REQUEST
            );
        }
        assert_eq!(
            send(
                &router,
                "POST",
                &path(Uuid::now_v7()),
                Some(t),
                &body(&role, None)
            )
            .0,
            StatusCode::NOT_FOUND
        );
        let mut c = db.adapter.connect().unwrap();
        let protected=c.query_one(&format!("select b.id,b.account_id,b.role_id,b.resource_type from {s}.access_role_bindings b join {s}.access_roles r on r.tenant_id=b.tenant_id and r.id=b.role_id where b.tenant_id=$1 and r.kind<>'business'"),&[&t]).unwrap();
        let protected_id = protected.get::<_, Uuid>(0).to_string();
        let protected_subject = protected.get::<_, Uuid>(1);
        assert!(
            send(&router, "GET", &path(protected_subject), Some(t), "").1["items"]
                .as_array()
                .unwrap()
                .iter()
                .any(|b| b["binding_id"] == protected_id)
        );
        assert_eq!(revoke(&router, t, &protected_id).0, StatusCode::FORBIDDEN);
        let b=json!({"role_id":protected.get::<_,Uuid>(2).to_string(),"resource_type":protected.get::<_,String>(3),"scope":{"kind":"type"}}).to_string();
        assert_eq!(
            send(&router, "POST", &subject_path, Some(t), &b).0,
            StatusCode::FORBIDDEN
        );
        c.execute(&format!("update {s}.access_memberships set status='suspended' where tenant_id=$1 and account_id=$2"),&[&t,&db.member]).unwrap();
        assert_eq!(
            send(&router, "GET", &subject_path, Some(t), "").1["items"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
        assert_eq!(decision(&db, t, Some("report-1")), AccessDecision::Deny);
        assert_eq!(
            send(&router, "POST", &subject_path, Some(t), &body(&role, None)).0,
            StatusCode::FORBIDDEN
        );
        c.execute(&format!("update {s}.access_memberships set status='active' where tenant_id=$1 and account_id=$2"),&[&t,&db.member]).unwrap();
        c.execute(
            &format!("update {s}.access_roles set status='disabled' where tenant_id=$1 and id=$2"),
            &[&t, &Uuid::parse_str(&role).unwrap()],
        )
        .unwrap();
        assert_eq!(
            send(&router, "GET", &subject_path, Some(t), "").1["items"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
        assert_eq!(decision(&db, t, Some("report-1")), AccessDecision::Deny);
        assert_eq!(
            send(&router, "POST", &subject_path, Some(t), &body(&role, None)).0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(revoke(&router, t, &second).0, StatusCode::OK);
        c.execute(
            &format!("update {s}.access_roles set status='active' where tenant_id=$1 and id=$2"),
            &[&t, &Uuid::parse_str(&role).unwrap()],
        )
        .unwrap();
        if mode == TenancyMode::Enabled {
            assert_eq!(
                send(&router, "GET", &path(db.actor), Some(t), "").0,
                StatusCode::NOT_FOUND
            );
            let owner_session = device(&db, t, Uuid::now_v7(), db.owner, 1);
            let mut owner = db.context(owner_session.to_string());
            owner.actor.tenant_id = t.into();
            owner.actor.subject_id = db.owner.to_string();
            let owner_app = app(&db, Some(owner));
            assert_eq!(
                send(&owner_app, "GET", &subject_path, None, "").0,
                StatusCode::OK
            );
            assert_eq!(
                send(&owner_app, "GET", &subject_path, Some("t2"), "").0,
                StatusCode::FORBIDDEN
            );
            c.batch_execute(&format!("update {s}.access_permissions set enabled=false where resource_type='idp.tenant' and action='grants.manage'")).unwrap();
            assert_eq!(
                send(&owner_app, "POST", &subject_path, None, &body(&role, None)).0,
                StatusCode::FORBIDDEN
            );
            assert_eq!(
                send(&owner_app, "GET", &subject_path, None, "").0,
                StatusCode::OK
            );
            c.batch_execute(&format!("update {s}.access_permissions set enabled=true where resource_type='idp.tenant' and action='grants.manage'; update {s}.access_permissions set enabled=false where resource_type='idp.tenant' and action='access.read'")).unwrap();
            assert_eq!(
                send(&owner_app, "GET", &subject_path, None, "").0,
                StatusCode::FORBIDDEN
            );
        }
        c.batch_execute(&format!(
            "update {s}.auth_sessions set status='revoked' where tenant_id='0'"
        ))
        .unwrap();
        assert_eq!(
            send(&router, "GET", &next_path, Some(t), "").0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(revoke(&router, t, &first).0, StatusCode::FORBIDDEN);
    }
}
