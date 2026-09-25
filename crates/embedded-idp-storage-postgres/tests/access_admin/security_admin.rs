use super::devices::{device, send};
use super::*;
use axum::{http::StatusCode, Extension, Router};
use embedded_idp_axum::{permission_admin_router, security_admin_router};
use serde_json::{json, Value};

fn app(db: &Db, context: Option<AccessAdminContext>) -> Router {
    let service = Arc::new(db.service());
    let router = security_admin_router(db.mode, service.clone())
        .merge(permission_admin_router(db.mode, service));
    Router::new().nest(
        "/idp",
        if let Some(c) = context {
            router.layer(Extension(c))
        } else {
            router
        },
    )
}
fn write(
    router: &Router,
    method: &str,
    platform: bool,
    subject: Uuid,
    tenant: Option<&str>,
) -> (StatusCode, Value) {
    send(
        router,
        method,
        &format!(
            "/admin/{}/security-admins/{subject}",
            if platform { "platform" } else { "access" }
        ),
        tenant,
        "",
    )
}
fn allowed(db: &Db, tenant: &str, subject: Uuid) -> bool {
    CoreAccessService::new(db.mode, catalog(), db.store())
        .check(AccessQuery {
            tenant_id: tenant.into(),
            subject_id: subject.to_string(),
            resource_type: if tenant == "0" {
                "idp.platform"
            } else {
                "idp.tenant"
            }
            .into(),
            action: if tenant == "0" {
                "access.manage"
            } else {
                "access.read"
            }
            .into(),
            resource_id: None,
        })
        .unwrap()
        == AccessDecision::Allow
}
#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn security_admin_http_lifecycle_is_fixed_role_audited_and_preserves_last_admin() {
    for mode in [TenancyMode::Disabled, TenancyMode::Enabled] {
        let db = Db::new(mode);
        let t = db.target();
        let s = db.schema();
        let context = db.context(db.actor_session.to_string());
        let router = app(&db, Some(context.clone()));
        assert_eq!(
            write(&app(&db, None), "POST", false, db.member, Some(t)).0,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            write(&router, "POST", false, Uuid::now_v7(), Some(t)).0,
            StatusCode::NOT_FOUND
        );
        let mut c = db.adapter.connect().unwrap();
        c.batch_execute(&format!("create function {s}.fail_appointment_audit() returns trigger language plpgsql as $$ begin raise exception 'injected audit failure'; end $$; create trigger fail_appointment_audit before insert on {s}.access_audit_events for each row execute function {s}.fail_appointment_audit()" )).unwrap();
        assert_eq!(
            write(&router, "POST", false, db.member, Some(t)).0,
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert!(!allowed(&db, t, db.member));
        c.batch_execute(&format!(
            "drop trigger fail_appointment_audit on {s}.access_audit_events"
        ))
        .unwrap();
        let appointed = write(&router, "POST", false, db.member, Some(t));
        assert_eq!(appointed.0, StatusCode::CREATED);
        assert_eq!(appointed.1["binding"]["tenant_id"], t);
        assert_eq!(appointed.1["binding"]["subject_id"], db.member.to_string());
        assert_eq!(
            appointed.1["binding"]["resource_type"],
            if mode == TenancyMode::Enabled {
                "idp.tenant"
            } else {
                "idp.platform"
            }
        );
        assert_eq!(appointed.1["binding"]["scope"], json!({"kind":"type"}));
        assert!(allowed(&db, t, db.member));
        assert_eq!(
            write(&router, "POST", false, db.member, Some(t)).0,
            StatusCode::CONFLICT
        );
        let audit=c.query_one(&format!("select actor_id,actor_domain,target_domain,operation,request_id,change_json::text from {s}.access_audit_events where id=$1"),&[&Uuid::parse_str(appointed.1["audit_id"].as_str().unwrap()).unwrap()]).unwrap();
        assert_eq!(audit.get::<_, Uuid>(0), db.actor);
        assert_eq!(audit.get::<_, String>(1), "0");
        assert_eq!(audit.get::<_, String>(2), t);
        assert_eq!(audit.get::<_, String>(3), "security_admin.set");
        assert_eq!(audit.get::<_, String>(4), context.request_id);
        let change: Value = serde_json::from_str(&audit.get::<_, String>(5)).unwrap();
        assert!(change["before"].is_null());
        assert_eq!(change["after"]["subject_id"], db.member.to_string());
        let mut member_context = db.context(db.member_session.to_string());
        member_context.actor.subject_id = db.member.to_string();
        member_context.actor.tenant_id = t.into();
        let member_app = app(&db, Some(member_context));
        assert_eq!(
            send(&member_app, "GET", "/admin/access/permissions", None, "").0,
            StatusCode::OK
        );
        if mode == TenancyMode::Enabled {
            // Even an appointed tenant administrator cannot appoint protected roles.
            assert_eq!(
                write(&member_app, "DELETE", false, db.owner, None).0,
                StatusCode::FORBIDDEN
            );
            assert_eq!(
                write(&member_app, "POST", true, db.owner, None).0,
                StatusCode::FORBIDDEN
            );
            assert_eq!(
                write(&member_app, "POST", false, db.member, Some("t2")).0,
                StatusCode::FORBIDDEN
            );
        }
        c.batch_execute(&format!("create trigger fail_appointment_audit before insert on {s}.access_audit_events for each row execute function {s}.fail_appointment_audit()")).unwrap();
        assert_eq!(
            write(&router, "DELETE", false, db.member, Some(t)).0,
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert!(allowed(&db, t, db.member));
        c.batch_execute(&format!(
            "drop trigger fail_appointment_audit on {s}.access_audit_events"
        ))
        .unwrap();
        let revoked = write(&router, "DELETE", false, db.member, Some(t));
        assert_eq!(revoked.0, StatusCode::OK);
        assert!(revoked.1["binding"].is_null());
        assert!(!allowed(&db, t, db.member));
        assert_eq!(
            send(&member_app, "GET", "/admin/access/permissions", None, "").0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            write(&router, "DELETE", false, db.member, Some(t)).0,
            StatusCode::CONFLICT
        );
        let last = if mode == TenancyMode::Enabled {
            db.owner
        } else {
            db.actor
        };
        assert_eq!(
            write(&router, "DELETE", false, last, Some(t)).0,
            StatusCode::CONFLICT
        );
        assert!(allowed(&db, t, last));
        assert_eq!(c.query_one(&format!("select count(*) from {s}.access_audit_events where operation='security_admin.set'"),&[]).unwrap().get::<_,i64>(0),2);
        // Disabled/suspended targets cannot acquire an administrator role.
        c.batch_execute(&format!("update {s}.access_memberships set status='suspended' where tenant_id='{t}' and account_id='{}'",db.member)).unwrap();
        assert_eq!(
            write(&router, "POST", false, db.member, Some(t)).0,
            StatusCode::FORBIDDEN
        );
        c.batch_execute(&format!("update {s}.access_memberships set status='active' where tenant_id='{t}' and account_id='{}'; update {s}.accounts set status='disabled' where id='{}'",db.member,db.member)).unwrap();
        assert_eq!(
            write(&router, "POST", false, db.member, Some(t)).0,
            StatusCode::FORBIDDEN
        );
    }
}
#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn platform_appointments_require_existing_domain_membership_and_current_platform_grants() {
    for mode in [TenancyMode::Disabled, TenancyMode::Enabled] {
        let db = Db::new(mode);
        let s = db.schema();
        let mut c = db.adapter.connect().unwrap();
        let router = app(&db, Some(db.context(db.actor_session.to_string())));
        assert_eq!(
            write(&router, "POST", true, db.member, Some("t1")).0,
            StatusCode::BAD_REQUEST
        );
        if mode == TenancyMode::Enabled {
            assert_eq!(
                write(&router, "POST", false, db.member, None).0,
                StatusCode::BAD_REQUEST
            );
            assert_eq!(
                write(&router, "POST", false, db.member, Some("0")).0,
                StatusCode::BAD_REQUEST
            );
            assert_eq!(
                write(&router, "POST", true, db.member, None).0,
                StatusCode::NOT_FOUND
            );
            // Fixture-only privileged membership; the appointment API never creates it.
            c.execute(&format!("insert into {s}.access_memberships(tenant_id,account_id,status,joined_at_epoch) values('0',$1,'active',1000)"),&[&db.member]).unwrap();
        }
        let appointed = write(&router, "POST", true, db.member, None);
        assert_eq!(appointed.0, StatusCode::CREATED);
        assert_eq!(appointed.1["binding"]["resource_type"], "idp.platform");
        assert_eq!(appointed.1["binding"]["tenant_id"], "0");
        let session = device(&db, "0", Uuid::now_v7(), db.member, 4);
        let mut member_context = db.context(session.to_string());
        member_context.actor.subject_id = db.member.to_string();
        let member_app = app(&db, Some(member_context));
        assert_eq!(
            write(&router, "DELETE", true, db.actor, None).0,
            StatusCode::OK
        );
        // A still-active session loses management authority immediately after removal.
        assert_eq!(
            write(&router, "POST", true, db.actor, None).0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            write(&member_app, "DELETE", true, db.member, None).0,
            StatusCode::CONFLICT
        );
        assert!(allowed(&db, "0", db.member));
        assert_eq!(
            write(&member_app, "POST", true, db.actor, None).0,
            StatusCode::CREATED
        );
        c.batch_execute(&format!("update {s}.access_permissions set enabled=false where resource_type='idp.platform' and action='access.manage'")).unwrap();
        assert_eq!(
            write(&member_app, "DELETE", true, db.actor, None).0,
            StatusCode::FORBIDDEN
        );
        c.batch_execute(&format!("update {s}.access_permissions set enabled=true where resource_type='idp.platform' and action='access.manage'; update {s}.auth_sessions set status='revoked' where id='{session}'")).unwrap();
        assert_eq!(
            write(&member_app, "DELETE", true, db.actor, None).0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            write(&router, "DELETE", true, db.member, None).0,
            StatusCode::OK
        );
        assert!(!allowed(&db, "0", db.member));
        assert!(allowed(&db, "0", db.actor));
    }
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn security_admin_snapshot_reads_exact_domain_and_requires_live_platform_authority() {
    for mode in [TenancyMode::Enabled, TenancyMode::Disabled] {
        let db = Db::new(mode);
        let target = db.target();
        let router = app(&db, Some(db.context(db.actor_session.to_string())));
        assert_eq!(
            write(&app(&db, None), "GET", false, db.member, Some(target)).0,
            StatusCode::UNAUTHORIZED
        );
        let before = write(&router, "GET", false, db.member, Some(target));
        assert_eq!(before.0, StatusCode::OK);
        assert_eq!(before.1["tenant_id"], target);
        assert_eq!(before.1["account"]["account_id"], db.member.to_string());
        assert_eq!(before.1["account"]["membership"]["tenant_id"], target);
        assert!(before.1["binding"].is_null());
        assert!(!before.1.to_string().contains("password_hash"));
        assert_eq!(
            write(&router, "POST", false, db.member, Some(target)).0,
            StatusCode::CREATED
        );
        let after = write(&router, "GET", false, db.member, Some(target));
        assert_eq!(after.1["binding"]["role_id"], after.1["role"]["role_id"]);
        assert_eq!(after.1["binding"]["scope"], json!({"kind":"type"}));
        assert_eq!(
            write(&router, "DELETE", false, db.member, Some(target)).0,
            StatusCode::OK
        );
        assert!(write(&router, "GET", false, db.member, Some(target)).1["binding"].is_null());
        let platform = write(&router, "GET", true, db.member, None);
        assert_eq!(platform.0, StatusCode::OK);
        assert_eq!(platform.1["role"]["kind"], "system_admin");
        if mode == TenancyMode::Enabled {
            assert!(platform.1["account"]["membership"].is_null());
        }
        let mut member = db.context(db.member_session.to_string());
        member.actor.tenant_id = target.into();
        member.actor.subject_id = db.member.to_string();
        assert_eq!(
            write(
                &app(&db, Some(member)),
                "GET",
                false,
                db.member,
                Some(target)
            )
            .0,
            StatusCode::FORBIDDEN
        );
        db.adapter.connect().unwrap().batch_execute(&format!("update {}.access_permissions set enabled=false where resource_type='idp.platform' and action='access.manage'", db.schema())).unwrap();
        assert_eq!(
            write(&router, "GET", true, db.member, None).0,
            StatusCode::FORBIDDEN
        );
    }
}
