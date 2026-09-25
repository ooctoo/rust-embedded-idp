use super::devices::{device, send};
use super::*;
use axum::{http::StatusCode, Extension, Router};
use embedded_idp_axum::permission_admin_router;
use serde_json::{json, Value};

fn app(db: &Db, context: Option<AccessAdminContext>) -> Router {
    let r = permission_admin_router(db.mode, Arc::new(db.service()));
    Router::new().nest(
        "/idp",
        if let Some(c) = context {
            r.layer(Extension(c))
        } else {
            r
        },
    )
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn directory_http_crud_is_scoped_versioned_and_audited() {
    for mode in [TenancyMode::Disabled, TenancyMode::Enabled] {
        let db = Db::new(mode);
        let tenant = db.target();
        let router = app(&db, Some(db.context(db.actor_session.to_string())));
        let path = "/admin/access/permissions/invoice/read";
        assert_eq!(
            send(
                &app(&db, None),
                "GET",
                "/admin/access/permissions",
                Some(tenant),
                ""
            )
            .0,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            send(
                &router,
                "GET",
                "/admin/access/permissions",
                Some(tenant),
                ""
            )
            .0,
            StatusCode::OK
        );
        let created = send(
            &router,
            "POST",
            "/admin/access/permissions",
            Some(tenant),
            &json!({
                "resource_type":"invoice", "action":"read", "description":"Read tenant invoices"
            })
            .to_string(),
        );
        assert_eq!(created.0, StatusCode::OK);
        assert_eq!(created.1["changes"][0]["after"]["tenant_id"], tenant);
        assert_eq!(
            send(&router, "GET", path, Some(tenant), "").1["description"],
            "Read tenant invoices"
        );
        assert_eq!(
            send(
                &router,
                "POST",
                "/admin/access/permissions",
                Some(tenant),
                r#"{"resource_type":"idp.custom","action":"read","description":"Forbidden"}"#
            )
            .0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            send(
                &router,
                "PATCH",
                path,
                Some(tenant),
                r#"{"description":"Updated","expected_version":9}"#
            )
            .0,
            StatusCode::CONFLICT
        );
        assert_eq!(
            send(
                &router,
                "PATCH",
                path,
                Some(tenant),
                r#"{"description":"Updated","expected_version":1}"#
            )
            .1["changes"][0]["after"]["version"],
            2
        );
        assert_eq!(
            send(
                &router,
                "POST",
                "/admin/access/permissions/invoice/read/enabled",
                Some(tenant),
                r#"{"enabled":false,"expected_enabled":true}"#
            )
            .1["changes"][0]["after"]["enabled"],
            false
        );
        assert_eq!(
            send(
                &router,
                "DELETE",
                path,
                Some(tenant),
                r#"{"expected_version":3}"#
            )
            .1["changes"][0]["after"]["archived"],
            true
        );
        assert_eq!(
            send(
                &router,
                "POST",
                "/admin/access/permissions",
                Some(tenant),
                &json!({
                    "resource_type":"invoice", "action":"read", "description":"Reuse"
                })
                .to_string()
            )
            .0,
            StatusCode::CONFLICT
        );
        assert_eq!(
            send(&router, "GET", path, Some(tenant), "").1["archived"],
            true
        );
        if mode == TenancyMode::Enabled {
            let other = send(
                &router,
                "POST",
                "/admin/access/permissions",
                Some("t2"),
                &json!({
                    "resource_type":"invoice", "action":"read", "description":"Other tenant"
                })
                .to_string(),
            );
            assert_eq!(other.0, StatusCode::OK);
            assert_eq!(
                send(&router, "GET", path, Some("t2"), "").1["description"],
                "Other tenant"
            );
            assert_eq!(
                send(&router, "GET", path, Some(tenant), "").1["archived"],
                true
            );
            let platform = send(&router, "GET", "/admin/platform/permissions", None, "");
            assert_eq!(platform.0, StatusCode::OK);
            assert!(platform.1["items"]
                .as_array()
                .unwrap()
                .iter()
                .all(|p| p["category"] == Value::String("platform".into())));
            let session = device(&db, tenant, Uuid::now_v7(), db.owner, 3);
            let mut owner = db.context(session.to_string());
            owner.actor.tenant_id = tenant.into();
            owner.actor.subject_id = db.owner.to_string();
            let owner_app = app(&db, Some(owner));
            assert_eq!(
                send(
                    &owner_app,
                    "POST",
                    "/admin/access/permissions",
                    None,
                    r#"{"resource_type":"receipt","action":"read","description":"Own tenant"}"#
                )
                .0,
                StatusCode::OK
            );
            assert_eq!(
                send(
                    &owner_app,
                    "POST",
                    "/admin/access/permissions",
                    Some("t2"),
                    r#"{"resource_type":"receipt","action":"read","description":"Other tenant"}"#
                )
                .0,
                StatusCode::FORBIDDEN
            );
        }
    }
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn directory_write_rolls_back_if_audit_fails() {
    let db = Db::new(TenancyMode::Disabled);
    let router = app(&db, Some(db.context(db.actor_session.to_string())));
    let s = db.schema();
    let mut c = db.adapter.connect().unwrap();
    c.batch_execute(&format!("create function {s}.fail_permission_audit() returns trigger language plpgsql as $$ begin raise exception 'injected audit failure'; end $$; create trigger fail_permission_audit before insert on {s}.access_audit_events for each row execute function {s}.fail_permission_audit()")).unwrap();
    assert_eq!(
        send(
            &router,
            "POST",
            "/admin/access/permissions",
            Some("0"),
            r#"{"resource_type":"invoice","action":"read","description":"Read"}"#
        )
        .0,
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert_eq!(c.query_one(&format!("select count(*) from {s}.access_permissions where tenant_id='0' and resource_type='invoice'"),&[]).unwrap().get::<_,i64>(0), 0);
}
