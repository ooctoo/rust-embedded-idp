use super::devices::send;
use super::*;
use axum::{http::StatusCode, Extension, Router};
use base64ct::{Base64UrlUnpadded, Encoding};
use embedded_idp_axum::{
    account_admin_router, audit_admin_router, client_admin_router, permission_admin_router,
    role_admin_router, role_binding_admin_router, tenant_device_admin_router,
    tenant_management_admin_router, tenant_session_admin_router,
};
use embedded_idp_core::{access::CoreClientAdminService, PhcClientSecretCodec};
use uuid::Uuid;

fn app(db: &Db) -> Router {
    let clients = CoreClientAdminService::new(db.service(), PhcClientSecretCodec);
    let routes = Router::new()
        .merge(account_admin_router(db.mode, Arc::new(db.service())))
        .merge(client_admin_router(Arc::new(clients)))
        .merge(permission_admin_router(db.mode, Arc::new(db.service())))
        .merge(role_admin_router(db.mode, Arc::new(db.service())))
        .merge(role_binding_admin_router(db.mode, Arc::new(db.service())))
        .merge(tenant_device_admin_router(db.mode, Arc::new(db.service())))
        .merge(tenant_management_admin_router(
            db.mode,
            Arc::new(db.service()),
            Arc::new(super::account_security::service(db)),
        ))
        .merge(tenant_session_admin_router(db.mode, Arc::new(db.service())))
        .merge(audit_admin_router(db.mode, Arc::new(db.service())))
        .layer(Extension(db.context(db.actor_session.to_string())));
    Router::new().nest("/idp", routes)
}

fn ids(page: &serde_json::Value, field: &str) -> Vec<String> {
    page["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item[field].as_str().unwrap().to_owned())
        .collect()
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn admin_lists_are_newest_first_and_cursor_pages_keep_tied_timestamps() {
    let db = Db::new(TenancyMode::Enabled);
    let s = db.schema();
    let tenant = db.target();
    let account_new = Uuid::from_u128(1);
    let account_old = Uuid::from_u128(2);
    let role_new = Uuid::from_u128(3);
    let role_old = Uuid::from_u128(4);
    let binding_new = Uuid::from_u128(5);
    let binding_old = Uuid::from_u128(6);
    let session_new = Uuid::from_u128(7);
    let session_old = Uuid::from_u128(8);
    let device_new = Uuid::from_u128(9);
    let device_old = Uuid::from_u128(10);
    let audit_new = Uuid::from_u128(11);
    let audit_old = Uuid::from_u128(12);
    let mut c = db.adapter.connect().unwrap();
    let mut tx = c.transaction().unwrap();
    tx.execute(&format!("insert into {s}.accounts(id,registration_tenant_id,email,password_hash,status,created_at_epoch) values($1,'t1','order-new@example.test','fixture','active',200),($2,'t1','order-old@example.test','fixture','active',100)"), &[&account_new, &account_old]).unwrap();
    tx.execute(&format!("insert into {s}.access_memberships(tenant_id,account_id,status,joined_at_epoch) values('t1',$1,'active',100),('t1',$2,'active',200)"), &[&account_new, &account_old]).unwrap();
    tx.execute(&format!("insert into {s}.oidc_clients(client_id,client_name,redirect_uris_json,client_type,pkce_required,created_at_epoch) values('a-order','Order','[]','confidential_web',true,200),('z-order','Order','[]','confidential_web',true,100),('order-device-client','Order','[]','public_desktop',true,100)"), &[]).unwrap();
    tx.execute(
        &format!("update {s}.access_roles set created_at_epoch=0 where tenant_id='t1'"),
        &[],
    )
    .unwrap();
    tx.execute(&format!("insert into {s}.access_roles(tenant_id,id,key,name,status,kind,created_at_epoch) values('t1',$1,'z-order','Order','active','business',200),('t1',$2,'a-order','Order','active','business',100)"), &[&role_new, &role_old]).unwrap();
    tx.execute(&format!("insert into {s}.access_role_bindings(id,tenant_id,account_id,role_id,resource_type,created_at_epoch,created_by) values($1,'t1',$3,$4,'order-new',200,$3),($2,'t1',$3,$4,'order-old',100,$3)"), &[&binding_new, &binding_old, &account_new, &role_new]).unwrap();
    tx.execute(&format!("insert into {s}.auth_sessions(purpose,tenant_id,id,account_id,client_id,status,created_at_epoch,expires_at_epoch,refresh_token_version,authenticated_at_epoch) values('management','t1',$1,$3,'z-order','active',200,1000,1,200),('management','t1',$2,$3,'z-order','active',100,1000,1,100)"), &[&session_new, &session_old, &account_new]).unwrap();
    tx.execute(&format!("insert into {s}.devices(tenant_id,id,client_id,device_name,status,registered_at_epoch) values('t1',$1,'order-device-client','Order','active',200),('t1',$2,'order-device-client','Order','active',100)"), &[&device_new, &device_old]).unwrap();
    tx.execute(&format!("insert into {s}.access_tenants(id,kind,name,status,allow_registration,created_at_epoch) values('a-order','tenant','Order','active',false,200),('z-order','tenant','Order','active',false,100)"), &[]).unwrap();
    tx.execute(&format!("insert into {s}.access_permissions(tenant_id,resource_type,action,category,description,enabled,created_at_epoch) values('t1','order','z','business','Order',true,200),('t1','order','y','business','Order',true,200),('t1','order','a','business','Order',true,100),('t1','order','legacy','business','Order',true,null)"), &[]).unwrap();
    for (id, time) in [(audit_new, 200_i64), (audit_old, 100)] {
        tx.execute(&format!("insert into {s}.access_audit_events(id,occurred_at_epoch,actor_id,actor_domain,actor_session_id,authentication_source,target_domain,operation,request_id,change_json) values($1,$2,$3,'0',$4,'live_test','t1','order.list',$5,'{{\"kind\":\"order\",\"before\":null,\"after\":null}}'::jsonb)"), &[&id, &time, &db.actor, &db.actor_session, &id.to_string()]).unwrap();
    }
    tx.commit().unwrap();
    let router = app(&db);

    let account_global = send(
        &router,
        "GET",
        "/admin/platform/accounts?email=order-&limit=1",
        None,
        "",
    );
    assert_eq!(
        ids(&account_global.1, "account_id"),
        vec![account_new.to_string()]
    );
    let account_global_next = send(
        &router,
        "GET",
        &format!(
            "/admin/platform/accounts?email=order-&cursor={}",
            account_global.1["next_cursor"].as_str().unwrap()
        ),
        None,
        "",
    );
    assert_eq!(
        ids(&account_global_next.1, "account_id"),
        vec![account_old.to_string()]
    );
    let members = send(
        &router,
        "GET",
        "/admin/accounts?email=order-&limit=1",
        Some(tenant),
        "",
    );
    assert_eq!(ids(&members.1, "account_id"), vec![account_old.to_string()]);
    let members_next = send(
        &router,
        "GET",
        &format!(
            "/admin/accounts?email=order-&cursor={}",
            members.1["next_cursor"].as_str().unwrap()
        ),
        Some(tenant),
        "",
    );
    assert_eq!(
        ids(&members_next.1, "account_id"),
        vec![account_new.to_string()]
    );
    let clients = send(
        &router,
        "GET",
        "/admin/clients?client_type=confidential_web&limit=1",
        None,
        "",
    );
    assert_eq!(ids(&clients.1, "client_id"), vec!["a-order"]);
    let clients_next = send(
        &router,
        "GET",
        &format!(
            "/admin/clients?client_type=confidential_web&cursor={}",
            clients.1["next_cursor"].as_str().unwrap()
        ),
        None,
        "",
    );
    assert_eq!(ids(&clients_next.1, "client_id"), vec!["z-order"]);
    let sessions = send(
        &router,
        "GET",
        &format!("/admin/sessions?account_id={account_new}&limit=1"),
        Some(tenant),
        "",
    );
    assert_eq!(
        ids(&sessions.1, "session_id"),
        vec![session_new.to_string()]
    );
    let sessions_next = send(
        &router,
        "GET",
        &format!(
            "/admin/sessions?account_id={account_new}&cursor={}",
            sessions.1["next_cursor"].as_str().unwrap()
        ),
        Some(tenant),
        "",
    );
    assert_eq!(
        ids(&sessions_next.1, "session_id"),
        vec![session_old.to_string()]
    );
    let devices = send(
        &router,
        "GET",
        "/admin/devices?client_id=order-device-client&limit=1",
        Some(tenant),
        "",
    );
    assert_eq!(ids(&devices.1, "device_id"), vec![device_new.to_string()]);
    let devices_next = send(
        &router,
        "GET",
        &format!(
            "/admin/devices?client_id=order-device-client&cursor={}",
            devices.1["next_cursor"].as_str().unwrap()
        ),
        Some(tenant),
        "",
    );
    assert_eq!(
        ids(&devices_next.1, "device_id"),
        vec![device_old.to_string()]
    );
    let tenants = send(
        &router,
        "GET",
        "/admin/tenants?name=Order&limit=1",
        None,
        "",
    );
    assert_eq!(ids(&tenants.1, "tenant_id"), vec!["a-order"]);
    let tenants_next = send(
        &router,
        "GET",
        &format!(
            "/admin/tenants?name=Order&cursor={}",
            tenants.1["next_cursor"].as_str().unwrap()
        ),
        None,
        "",
    );
    assert_eq!(ids(&tenants_next.1, "tenant_id"), vec!["z-order"]);
    let roles = send(
        &router,
        "GET",
        "/admin/access/roles?limit=1",
        Some(tenant),
        "",
    );
    assert_eq!(ids(&roles.1, "role_id"), vec![role_new.to_string()]);
    let roles_next = send(
        &router,
        "GET",
        &format!(
            "/admin/access/roles?limit=1&cursor={}",
            roles.1["next_cursor"].as_str().unwrap()
        ),
        Some(tenant),
        "",
    );
    assert_eq!(ids(&roles_next.1, "role_id"), vec![role_old.to_string()]);
    let bindings = send(
        &router,
        "GET",
        &format!("/admin/access/subjects/{account_new}/role-bindings?limit=1"),
        Some(tenant),
        "",
    );
    assert_eq!(
        ids(&bindings.1, "binding_id"),
        vec![binding_new.to_string()]
    );
    let bindings_next = send(
        &router,
        "GET",
        &format!(
            "/admin/access/subjects/{account_new}/role-bindings?cursor={}",
            bindings.1["next_cursor"].as_str().unwrap()
        ),
        Some(tenant),
        "",
    );
    assert_eq!(
        ids(&bindings_next.1, "binding_id"),
        vec![binding_old.to_string()]
    );
    let permissions = send(
        &router,
        "GET",
        "/admin/access/permissions?resource_type=order&limit=1",
        Some(tenant),
        "",
    );
    assert_eq!(ids(&permissions.1, "action"), vec!["z"]);
    let permissions_tied = send(
        &router,
        "GET",
        &format!(
            "/admin/access/permissions?resource_type=order&limit=1&cursor={}",
            permissions.1["next_cursor"].as_str().unwrap()
        ),
        Some(tenant),
        "",
    );
    assert_eq!(ids(&permissions_tied.1, "action"), vec!["y"]);
    let permissions_old = send(
        &router,
        "GET",
        &format!(
            "/admin/access/permissions?resource_type=order&limit=2&cursor={}",
            permissions_tied.1["next_cursor"].as_str().unwrap()
        ),
        Some(tenant),
        "",
    );
    assert_eq!(ids(&permissions_old.1, "action"), vec!["a", "legacy"]);
    let audits = send(
        &router,
        "GET",
        "/admin/access/audit-events?operation=order.list&limit=1",
        Some(tenant),
        "",
    );
    assert_eq!(ids(&audits.1, "audit_id"), vec![audit_new.to_string()]);
    let audits_next = send(
        &router,
        "GET",
        &format!(
            "/admin/access/audit-events?operation=order.list&cursor={}",
            audits.1["next_cursor"].as_str().unwrap()
        ),
        Some(tenant),
        "",
    );
    assert_eq!(ids(&audits_next.1, "audit_id"), vec![audit_old.to_string()]);

    // Every query must reverse the complete keyset, not merely the current page.
    for (path, scope, field) in [
        (
            "/admin/platform/accounts?email=order-".to_owned(),
            None,
            "account_id",
        ),
        (
            "/admin/accounts?email=order-".to_owned(),
            Some(tenant),
            "account_id",
        ),
        (
            "/admin/clients?client_type=confidential_web".to_owned(),
            None,
            "client_id",
        ),
        (
            format!("/admin/sessions?account_id={account_new}"),
            Some(tenant),
            "session_id",
        ),
        (
            "/admin/devices?client_id=order-device-client".to_owned(),
            Some(tenant),
            "device_id",
        ),
        ("/admin/tenants?name=Order".to_owned(), None, "tenant_id"),
        ("/admin/access/roles".to_owned(), Some(tenant), "role_id"),
        (
            format!("/admin/access/subjects/{account_new}/role-bindings"),
            Some(tenant),
            "binding_id",
        ),
        (
            "/admin/access/permissions?resource_type=order".to_owned(),
            Some(tenant),
            "action",
        ),
        (
            "/admin/access/audit-events?operation=order.list".to_owned(),
            Some(tenant),
            "audit_id",
        ),
    ] {
        let separator = if path.contains('?') { "&" } else { "?" };
        let default = send(&router, "GET", &path, scope, "");
        assert_eq!(default.0, StatusCode::OK, "{path}");
        let descending = ids(&default.1, field);
        assert!(descending.len() > 1, "{path}");
        let explicit = send(
            &router,
            "GET",
            &format!("{path}{separator}sort_order=desc"),
            scope,
            "",
        );
        assert_eq!(explicit, default, "{path}");
        assert_eq!(
            send(
                &router,
                "GET",
                &format!("{path}{separator}sort_order=sideways"),
                scope,
                ""
            )
            .0,
            StatusCode::BAD_REQUEST,
            "{path}"
        );

        let first = send(
            &router,
            "GET",
            &format!("{path}{separator}limit=1"),
            scope,
            "",
        );
        let raw = first.1["next_cursor"].as_str().unwrap();
        assert_eq!(
            send(
                &router,
                "GET",
                &format!("{path}{separator}sort_order=asc&cursor={raw}"),
                scope,
                ""
            )
            .0,
            StatusCode::BAD_REQUEST,
            "{path}"
        );
        let mut legacy: serde_json::Value =
            serde_json::from_slice(&Base64UrlUnpadded::decode_vec(raw).unwrap()).unwrap();
        assert_eq!(legacy["sort_order"], "desc");
        legacy.as_object_mut().unwrap().remove("sort_order");
        let legacy = Base64UrlUnpadded::encode_string(&serde_json::to_vec(&legacy).unwrap());
        let next = send(
            &router,
            "GET",
            &format!("{path}{separator}limit=1&cursor={legacy}"),
            scope,
            "",
        );
        assert_eq!(next.0, StatusCode::OK, "{path}");
        assert_eq!(ids(&next.1, field), descending[1..2], "{path}");

        let mut cursor: Option<String> = None;
        for (index, expected) in descending.iter().rev().enumerate() {
            let suffix = cursor
                .as_ref()
                .map_or(String::new(), |c| format!("&cursor={c}"));
            let page = send(
                &router,
                "GET",
                &format!("{path}{separator}sort_order=asc&limit=1{suffix}"),
                scope,
                "",
            );
            assert_eq!(page.0, StatusCode::OK, "{path}");
            assert_eq!(ids(&page.1, field), vec![expected.clone()], "{path}");
            assert_eq!(page.1["has_more"], index + 1 < descending.len(), "{path}");
            cursor = page.1["next_cursor"].as_str().map(str::to_owned);
            if let Some(raw) = &cursor {
                assert_eq!(
                    send(
                        &router,
                        "GET",
                        &format!("{path}{separator}cursor={raw}"),
                        scope,
                        ""
                    )
                    .0,
                    StatusCode::BAD_REQUEST,
                    "{path}"
                );
            }
        }
        assert!(cursor.is_none(), "{path}");
    }
}
