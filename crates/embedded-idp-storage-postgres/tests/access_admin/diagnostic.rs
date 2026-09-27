use super::devices::{device, send};
use super::*;
use axum::{http::StatusCode, Extension, Router};
use embedded_idp_axum::access_diagnostic_router;
use serde_json::{json, Value};

fn app(db: &Db, context: Option<AccessAdminContext>) -> Router {
    let router = access_diagnostic_router(db.mode, Arc::new(db.service()));
    Router::new().nest(
        "/idp",
        if let Some(c) = context {
            router.layer(Extension(c))
        } else {
            router
        },
    )
}
fn body(db: &Db, resource: Option<&str>) -> Value {
    json!({"subject_id":db.member.to_string(),"resource_type":"report","action":"read","resource_id":resource})
}
fn check(router: &Router, tenant: Option<&str>, body: &Value) -> (StatusCode, Value) {
    send(
        router,
        "POST",
        "/admin/access/check",
        tenant,
        &body.to_string(),
    )
}
fn grants(db: &Db) -> String {
    let service = db.service();
    let context = db.context(db.actor_session.to_string());
    let role = event_role_id(
        service
            .execute(
                context.clone(),
                db.command(AccessAdminMutation::CreateRole {
                    business_id: "f_01".into(),
                    key: "reader".into(),
                    name: "Reader".into(),
                }),
            )
            .unwrap(),
    );
    service
        .execute(
            context.clone(),
            db.command(AccessAdminMutation::ReplaceRolePermissions {
                business_id: "f_01".into(),
                role_id: role.clone(),
                permissions: vec![PermissionKey {
                    business_id: "f_01".into(),
                    resource_type: "report".into(),
                    action: "read".into(),
                }],
                expected_version: 1,
            }),
        )
        .unwrap();
    service
        .execute(
            context,
            db.command(AccessAdminMutation::GrantRole {
                business_id: "f_01".into(),
                subject_id: db.member.to_string(),
                role_id: role.clone(),
                scope: RoleBindingScope::Resource {
                    resource_type: "report".into(),
                    scope: ResourceScope::Instance("r1".into()),
                },
            }),
        )
        .unwrap();
    role
}
#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn diagnostic_http_matches_host_decisions_and_audits_caller_target_and_result() {
    for mode in [TenancyMode::Disabled, TenancyMode::Enabled] {
        let db = Db::new(mode);
        let role = grants(&db);
        let context = db.context(db.actor_session.to_string());
        let router = app(&db, Some(context.clone()));
        let host = CoreAccessService::new(mode, catalog(), db.store());
        let mut c = db.adapter.connect().unwrap();
        let s = db.schema();
        for (resource, expected) in [(Some("r1"), "allow"), (Some("r2"), "deny"), (None, "deny")] {
            let result = check(&router, Some(db.target()), &body(&db, resource));
            assert_eq!(result.0, StatusCode::OK);
            assert_eq!(result.1["decision"], expected);
            assert_eq!(result.1["tenant_id"], db.target());
            assert_eq!(result.1["subject_id"], db.member.to_string());
            let decision = host
                .check(AccessQuery {
                    business_id: "f_01".into(),
                    tenant_id: db.target().into(),
                    subject_id: db.member.to_string(),
                    resource_type: "report".into(),
                    action: "read".into(),
                    resource_id: resource.map(str::to_owned),
                })
                .unwrap();
            assert_eq!(decision == AccessDecision::Allow, expected == "allow");
            let audit_id = Uuid::parse_str(result.1["audit_id"].as_str().unwrap()).unwrap();
            let audit=c.query_one(&format!("select actor_id,actor_domain,target_domain,operation,request_id,occurred_at_epoch,change_json::text from {s}.access_audit_events where id=$1"),&[&audit_id]).unwrap();
            assert_eq!(audit.get::<_, Uuid>(0), db.actor);
            assert_eq!(audit.get::<_, String>(1), "0");
            assert_eq!(audit.get::<_, String>(2), db.target());
            assert_eq!(audit.get::<_, String>(3), "access.check");
            assert_eq!(audit.get::<_, String>(4), context.request_id);
            assert_eq!(audit.get::<_, i64>(5), NOW as i64);
            let data: Value = serde_json::from_str(&audit.get::<_, String>(6)).unwrap();
            assert_eq!(
                data,
                json!({"kind":"access.check","tenant_id":db.target(),"subject_id":db.member.to_string(),"resource_type":"report","action":"read","resource_id":resource,"decision":expected})
            );
        }
        let mut unknown = body(&db, Some("r1"));
        unknown["action"] = json!("unknown");
        assert_eq!(
            check(&router, Some(db.target()), &unknown).1["decision"],
            "deny"
        );
        for sql in [
            format!("update {s}.access_permissions set enabled=false where resource_type='report' and action='read'"),
            format!("update {s}.access_roles set status='disabled' where id='{role}'"),
            format!("update {s}.access_memberships set status='suspended' where tenant_id='{}' and account_id='{}'",db.target(),db.member),
            format!("update {s}.accounts set status='disabled' where id='{}'",db.member),
        ] {
            c.batch_execute(&sql).unwrap();
            assert_eq!(check(&router,Some(db.target()),&body(&db,Some("r1"))).1["decision"],"deny");
            c.batch_execute(&format!("update {s}.access_permissions set enabled=true where resource_type='report'; update {s}.access_roles set status='active' where id='{role}'; update {s}.access_memberships set status='active' where tenant_id='{}' and account_id='{}'; update {s}.accounts set status='active' where id='{}'",db.target(),db.member,db.member)).unwrap();
        }
        let count: i64 = c
            .query_one(
                &format!("select count(*) from {s}.access_audit_events"),
                &[],
            )
            .unwrap()
            .get(0);
        c.batch_execute(&format!("create function {s}.fail_diagnostic_audit() returns trigger language plpgsql as $$ begin raise exception 'injected audit failure'; end $$; create trigger fail_diagnostic_audit before insert on {s}.access_audit_events for each row execute function {s}.fail_diagnostic_audit()" )).unwrap();
        for resource in [Some("r1"), Some("r2")] {
            let result = check(&router, Some(db.target()), &body(&db, resource));
            assert_eq!(result.0, StatusCode::INTERNAL_SERVER_ERROR);
            assert!(result.1.get("decision").is_none());
        }
        assert_eq!(
            c.query_one(
                &format!("select count(*) from {s}.access_audit_events"),
                &[]
            )
            .unwrap()
            .get::<_, i64>(0),
            count
        );
        c.batch_execute(&format!(
            "drop trigger fail_diagnostic_audit on {s}.access_audit_events"
        ))
        .unwrap();
        assert_eq!(
            check(&router, Some(db.target()), &body(&db, Some("r1"))).1["decision"],
            "allow"
        );
    }
}
#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn diagnostic_http_enforces_management_scope_and_live_authority() {
    for mode in [TenancyMode::Disabled, TenancyMode::Enabled] {
        let db = Db::new(mode);
        let router = app(&db, Some(db.context(db.actor_session.to_string())));
        let request = body(&db, Some("r1"));
        assert_eq!(
            check(&app(&db, None), Some(db.target()), &request).0,
            StatusCode::UNAUTHORIZED
        );
        for (key, value) in [
            ("tenant_id", json!("t2")),
            ("actor_id", json!(db.actor.to_string())),
            ("decision", json!("allow")),
        ] {
            let mut invalid = request.clone();
            invalid[key] = value;
            assert_eq!(
                check(&router, Some(db.target()), &invalid).0,
                StatusCode::UNPROCESSABLE_ENTITY
            );
        }
        for resource in ["", "*", "r/1"] {
            assert_eq!(
                check(&router, Some(db.target()), &body(&db, Some(resource))).0,
                StatusCode::BAD_REQUEST
            );
        }
        let mut absent = request.clone();
        absent["subject_id"] = json!(Uuid::now_v7().to_string());
        assert_eq!(
            check(&router, Some(db.target()), &absent).0,
            StatusCode::NOT_FOUND
        );
        let mut c = db.adapter.connect().unwrap();
        let s = db.schema();
        if mode == TenancyMode::Enabled {
            assert_eq!(check(&router, None, &request).0, StatusCode::BAD_REQUEST);
            assert_eq!(
                check(&router, Some("0"), &request).0,
                StatusCode::BAD_REQUEST
            );
            let session = device(&db, db.target(), Uuid::now_v7(), db.owner, 1);
            let mut context = db.context(session.to_string());
            context.actor.tenant_id = db.target().into();
            context.actor.subject_id = db.owner.to_string();
            let tenant = app(&db, Some(context));
            assert_eq!(check(&tenant, None, &request).0, StatusCode::OK);
            assert_eq!(
                check(&tenant, Some("t2"), &request).0,
                StatusCode::FORBIDDEN
            );
            let mut outside = request.clone();
            outside["subject_id"] = json!(db.actor.to_string());
            assert_eq!(check(&tenant, None, &outside).0, StatusCode::NOT_FOUND);
            c.batch_execute(&format!("update {s}.access_permissions set enabled=false where resource_type='idp.tenant' and action='access.read'")).unwrap();
            assert_eq!(check(&tenant, None, &request).0, StatusCode::FORBIDDEN);
            c.batch_execute(&format!("update {s}.access_permissions set enabled=true where resource_type='idp.tenant' and action='access.read'; update {s}.auth_sessions set status='revoked' where id='{session}'")).unwrap();
            assert_eq!(check(&tenant, None, &request).0, StatusCode::FORBIDDEN);
            // Platform authority permits diagnosis, never supplies the target's grant.
            assert_eq!(check(&router, Some("t2"), &request).1["decision"], "deny");
        } else {
            assert_eq!(check(&router, None, &request).0, StatusCode::OK);
            assert_eq!(
                check(&router, Some("t2"), &request).0,
                StatusCode::BAD_REQUEST
            );
        }
        let before: i64 = c
            .query_one(
                &format!("select count(*) from {s}.access_audit_events"),
                &[],
            )
            .unwrap()
            .get(0);
        c.batch_execute(&format!("update {s}.access_permissions set enabled=false where resource_type='idp.platform' and action='access.manage'")).unwrap();
        assert_eq!(
            check(&router, Some(db.target()), &request).0,
            StatusCode::FORBIDDEN
        );
        c.batch_execute(&format!("update {s}.access_permissions set enabled=true where resource_type='idp.platform' and action='access.manage'; update {s}.auth_sessions set status='revoked' where tenant_id='0'")).unwrap();
        assert_eq!(
            check(&router, Some(db.target()), &request).0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            c.query_one(
                &format!("select count(*) from {s}.access_audit_events"),
                &[]
            )
            .unwrap()
            .get::<_, i64>(0),
            before
        );
    }
}
