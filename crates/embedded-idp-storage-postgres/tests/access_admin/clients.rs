use super::devices::send;
use super::*;
use axum::{http::StatusCode, Extension, Router};
use embedded_idp_axum::client_admin_router;
use embedded_idp_core::{ClientSecretVerifier, OidcClientType, PhcClientSecretCodec, SecretString};
use serde_json::{json, Value};

fn service(
    db: &Db,
) -> CoreClientAdminService<PostgresAccessStore, FixedClock, UuidIds, PhcClientSecretCodec> {
    CoreClientAdminService::new(db.service(), PhcClientSecretCodec)
}
fn app(db: &Db, context: Option<AccessAdminContext>) -> Router {
    let router = client_admin_router(Arc::new(service(db)));
    Router::new().nest(
        "/idp",
        if let Some(c) = context {
            router.layer(Extension(c))
        } else {
            router
        },
    )
}
fn body(id: &str) -> Value {
    json!({"client_id":id,"client_name":"Web","redirect_uris":["https://example.test/callback"],"client_type":"confidential_web","pkce_required":false,"client_secret":"fixture-client-secret "})
}
fn stored(db: &Db, id: &str) -> (String, Option<String>) {
    let r = db
        .adapter
        .connect()
        .unwrap()
        .query_one(
            &format!(
                "select client_name,client_secret_hash from {}.oidc_clients where client_id=$1",
                db.schema()
            ),
            &[&id],
        )
        .unwrap();
    (r.get(0), r.get(1))
}
#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn client_admin_http_in_both_modes_filters_and_commits_only_secret_free_audits() {
    for mode in [TenancyMode::Disabled, TenancyMode::Enabled] {
        let db = Db::new(mode);
        let s = db.schema();
        let router = app(&db, Some(db.context(db.actor_session.to_string())));
        assert_eq!(
            send(&app(&db, None), "GET", "/admin/clients", None, "").0,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            send(&router, "GET", "/admin/clients", Some("t1"), "").0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            send(&router, "GET", "/admin/clients?tenant_id=t1", None, "").0,
            StatusCode::BAD_REQUEST
        );
        for id in ["Z-web", "a-web"] {
            let result = send(
                &router,
                "POST",
                "/admin/clients/upsert",
                None,
                &body(id).to_string(),
            );
            assert_eq!(result.0, StatusCode::OK, "{result:?}");
            assert_eq!(result.1["client"]["client_secret_configured"], true);
            assert!(!result.1.to_string().contains("fixture-client-secret"));
            assert!(result.1["client"].get("client_secret_hash").is_none());
        }
        let (_, hash) = stored(&db, "Z-web");
        assert!(PhcClientSecretCodec
            .verify_client_secret("fixture-client-secret ", hash.as_deref().unwrap())
            .unwrap());
        assert!(!PhcClientSecretCodec
            .verify_client_secret("fixture-client-secret", hash.as_deref().unwrap())
            .unwrap());
        let page = send(
            &router,
            "GET",
            "/admin/clients?client_type=confidential_web&pkce_required=false&limit=1",
            None,
            "",
        );
        assert_eq!(page.0, StatusCode::OK);
        assert_eq!(page.1["items"][0]["client_id"], "a-web");
        let cursor = page.1["next_cursor"].as_str().unwrap();
        let next = send(
            &router,
            "GET",
            &format!(
                "/admin/clients?client_type=confidential_web&pkce_required=false&cursor={cursor}"
            ),
            None,
            "",
        );
        assert_eq!(next.0, StatusCode::OK);
        assert_eq!(next.1["items"][0]["client_id"], "Z-web");
        assert_eq!(next.1["has_more"], false);
        assert_eq!(
            send(
                &router,
                "GET",
                &format!("/admin/clients?cursor={cursor}"),
                None,
                ""
            )
            .0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            send(&router, "GET", "/admin/clients/missing", None, "").0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            send(&router, "GET", "/admin/clients/Z-web", Some("0"), "").0,
            StatusCode::OK
        );
        let mut edit = body("Z-web");
        edit.as_object_mut().unwrap().remove("client_secret");
        edit["client_name"] = json!("Preserved");
        assert_eq!(
            send(
                &router,
                "POST",
                "/admin/clients/upsert",
                None,
                &edit.to_string()
            )
            .0,
            StatusCode::OK
        );
        assert_eq!(stored(&db, "Z-web"), ("Preserved".into(), hash.clone()));
        db.adapter.connect().unwrap().batch_execute(&format!("create function {s}.client_fail_audit() returns trigger language plpgsql as $$ begin raise exception 'audit blocked'; end $$; create trigger client_fail_audit before insert on {s}.access_audit_events for each row execute function {s}.client_fail_audit()" )).unwrap();
        edit["client_name"] = json!("Must roll back");
        edit["client_secret"] = json!("replacement-fixture");
        assert_eq!(
            send(
                &router,
                "POST",
                "/admin/clients/upsert",
                None,
                &edit.to_string()
            )
            .0,
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(stored(&db, "Z-web"), ("Preserved".into(), hash.clone()));
        assert_eq!(
            send(
                &router,
                "POST",
                "/admin/clients/upsert",
                None,
                &body("new-fails").to_string()
            )
            .0,
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(
            send(&router, "GET", "/admin/clients/new-fails", None, "").0,
            StatusCode::NOT_FOUND
        );
        db.adapter
            .connect()
            .unwrap()
            .batch_execute(&format!(
                "drop trigger client_fail_audit on {s}.access_audit_events"
            ))
            .unwrap();
        assert_eq!(
            send(
                &router,
                "POST",
                "/admin/clients/upsert",
                None,
                &edit.to_string()
            )
            .0,
            StatusCode::OK
        );
        let rotated = stored(&db, "Z-web").1.unwrap();
        assert_ne!(Some(rotated.clone()), hash);
        assert!(PhcClientSecretCodec
            .verify_client_secret("replacement-fixture", &rotated)
            .unwrap());
        edit["client_type"] = json!("public_desktop");
        edit["pkce_required"] = json!(true);
        edit["redirect_uris"] = json!(["http://127.0.0.1:49152/callback"]);
        assert_eq!(
            send(
                &router,
                "POST",
                "/admin/clients/upsert",
                None,
                &edit.to_string()
            )
            .0,
            StatusCode::BAD_REQUEST
        );
        edit.as_object_mut().unwrap().remove("client_secret");
        assert_eq!(
            send(
                &router,
                "POST",
                "/admin/clients/upsert",
                None,
                &edit.to_string()
            )
            .0,
            StatusCode::OK
        );
        assert!(stored(&db, "Z-web").1.is_none());
        for (field, value) in [
            ("client_secret_hash", json!("override")),
            ("actor_id", json!("override")),
            ("login_policy", json!("choose")),
        ] {
            let mut invalid = edit.clone();
            invalid[field] = value;
            assert_eq!(
                send(
                    &router,
                    "POST",
                    "/admin/clients/upsert",
                    None,
                    &invalid.to_string()
                )
                .0,
                StatusCode::UNPROCESSABLE_ENTITY
            );
        }
        let audit=db.adapter.connect().unwrap().query(&format!("select row_to_json(a)::text from {s}.access_audit_events a where operation='client.upsert'"),&[]).unwrap();
        assert_eq!(audit.len(), 5);
        for r in audit {
            let text: String = r.get(0);
            assert!(!text.contains("fixture-client-secret"));
            assert!(!text.contains("replacement-fixture"));
            assert!(!text.contains("$argon2"));
            assert!(text.contains("client_secret_configured"));
        }
    }
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn client_admin_rejects_tenant_actors_and_observes_platform_permission_and_session_revocation() {
    let db = Db::new(TenancyMode::Enabled);
    let s = db.schema();
    let tenant_context = AccessAdminContext {
        actor: AccessActor {
            tenant_id: "t1".into(),
            subject_id: db.member.to_string(),
            session_id: db.member_session.to_string(),
        },
        authentication_source: "test".into(),
        request_id: "client-denied".into(),
    };
    let tenant = app(&db, Some(tenant_context.clone()));
    assert_eq!(
        send(&tenant, "GET", "/admin/clients", None, "").0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        send(
            &tenant,
            "POST",
            "/admin/clients/upsert",
            Some("0"),
            &body("forbidden").to_string()
        )
        .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        service(&db).get_client(tenant_context, "live-admin-client".into()),
        Err(AccessError::Forbidden)
    );
    let platform = app(&db, Some(db.context(db.actor_session.to_string())));
    db.adapter.connect().unwrap().execute(&format!("update {s}.access_permissions set enabled=false where resource_type='idp.platform' and action='clients.manage'"),&[]).unwrap();
    assert_eq!(
        send(&platform, "GET", "/admin/clients", None, "").0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        send(
            &platform,
            "POST",
            "/admin/clients/upsert",
            None,
            &body("forbidden").to_string()
        )
        .0,
        StatusCode::FORBIDDEN
    );
    db.adapter.connect().unwrap().execute(&format!("update {s}.access_permissions set enabled=true where resource_type='idp.platform' and action='clients.manage'"),&[]).unwrap();
    assert_eq!(
        send(&platform, "GET", "/admin/clients", None, "").0,
        StatusCode::OK
    );
    db.adapter
        .connect()
        .unwrap()
        .execute(
            &format!("update {s}.auth_sessions set status='revoked' where tenant_id='0' and id=$1"),
            &[&db.actor_session],
        )
        .unwrap();
    assert_eq!(
        send(
            &platform,
            "POST",
            "/admin/clients/upsert",
            None,
            &body("forbidden").to_string()
        )
        .0,
        StatusCode::FORBIDDEN
    );
    let count: i64 = db
        .adapter
        .connect()
        .unwrap()
        .query_one(
            &format!("select count(*) from {s}.oidc_clients where client_id='forbidden'"),
            &[],
        )
        .unwrap()
        .get(0);
    assert_eq!(count, 0);
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn concurrent_client_updates_preserve_the_current_secret_and_audit_each_commit() {
    let db = Db::new(TenancyMode::Enabled);
    let command = AdminUpsertClient {
        client_id: "concurrent".into(),
        client_name: "Original".into(),
        redirect_uris: vec!["https://example.test/callback".into()],
        client_type: OidcClientType::ConfidentialWeb,
        pkce_required: true,
        client_secret: Some(SecretString::new("first-fixture")),
    };
    service(&db)
        .upsert_client(db.context(db.actor_session.to_string()), command.clone())
        .unwrap();
    let barrier = Arc::new(Barrier::new(2));
    let joins: Vec<_> = [true, false]
        .into_iter()
        .map(|rotate| {
            let service = service(&db);
            let context = db.context(db.actor_session.to_string());
            let mut command = command.clone();
            let barrier = barrier.clone();
            command.client_name = if rotate { "Rotated" } else { "Metadata" }.into();
            command.client_secret = rotate.then(|| SecretString::new("second-fixture"));
            thread::spawn(move || {
                barrier.wait();
                service.upsert_client(context, command).unwrap()
            })
        })
        .collect();
    for j in joins {
        j.join().unwrap();
    }
    let hash = stored(&db, "concurrent").1.unwrap();
    assert!(PhcClientSecretCodec
        .verify_client_secret("second-fixture", &hash)
        .unwrap());
    let count: i64 = db
        .adapter
        .connect()
        .unwrap()
        .query_one(
            &format!(
                "select count(*) from {}.access_audit_events where operation='client.upsert'",
                db.schema()
            ),
            &[],
        )
        .unwrap()
        .get(0);
    assert_eq!(count, 3);
}
