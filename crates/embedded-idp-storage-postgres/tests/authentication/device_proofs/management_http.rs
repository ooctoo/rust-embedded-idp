use super::*;
use axum::{
    body::{to_bytes, Body},
    http::{HeaderMap, Request, StatusCode},
    Extension, Router,
};
use embedded_idp_axum::{
    tenant_device_auth_router, tenant_device_router, TenantDeviceAuthHttpConfig,
    TenantDeviceHttpConfig,
};
use serde_json::{json, Value};
use tower::ServiceExt;

struct Admission(String);
impl TenantDeviceAdmission for Admission {
    fn authorize(
        &self,
        tenant: &str,
        client: &str,
        _: &str,
        _: DeviceAdmissionAction,
        _: &TrustedDeviceAdmission,
    ) -> Result<(), AccessError> {
        if tenant == self.0 && client == "web" {
            Ok(())
        } else {
            Err(AccessError::Forbidden)
        }
    }
}
fn app(db: &Db, tenant: &str, admitted: &str) -> Router {
    let service: Arc<dyn TenantDeviceService> =
        Arc::new(CoreTenantDeviceAuthenticationService::new(
            auth(
                db,
                LoginTenantPolicy::Fixed {
                    tenant_id: tenant.into(),
                },
                "device-http",
                false,
                false,
            ),
            proofs(db),
        ));
    Router::new().nest(
        "/api",
        tenant_device_router(
            service.clone(),
            Arc::new(Admission(admitted.into())),
            TenantDeviceHttpConfig::new("test-api", "/api/devices/heartbeat").unwrap(),
        )
        .layer(Extension(TrustedDeviceAdmission {
            registration_scope: "test_scope".into(),
            valid_until: SystemTime::now() + Duration::from_secs(3600),
        }))
        .merge(tenant_device_auth_router(
            service,
            TenantDeviceAuthHttpConfig::new(
                "test-api",
                "/api/auth/login",
                "/api/auth/tenant-selection/complete",
                "/api/auth/refresh",
            )
            .unwrap(),
        )),
    )
}
fn send(
    app: &Router,
    method: &str,
    path: &str,
    body: &str,
    headers: &HeaderMap,
) -> (StatusCode, Value) {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let mut request = Request::builder()
                .method(method)
                .uri(format!("/api{path}"))
                .header("content-type", "application/json")
                .body(Body::from(body.to_owned()))
                .unwrap();
            request.headers_mut().extend(headers.clone());
            let response = app.clone().oneshot(request).await.unwrap();
            assert_eq!(response.headers()["cache-control"], "no-store");
            let status = response.status();
            let bytes = to_bytes(response.into_body(), 65536).await.unwrap();
            (
                status,
                serde_json::from_slice(&bytes).unwrap_or(Value::Null),
            )
        })
}
fn bearer(raw: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert("authorization", format!("Bearer {raw}").parse().unwrap());
    headers
}
fn challenge(app: &Router, tenant: &str, device: &str, purpose: &str) -> String {
    let (status, body) = send(
        app,
        "POST",
        "/devices/proof/challenges",
        &json!({"tenant_id":tenant,"device_id":device,"purpose":purpose}).to_string(),
        &HeaderMap::new(),
    );
    assert_eq!(status, StatusCode::OK);
    body["challenge"].as_str().unwrap().into()
}
fn heartbeat_headers(
    app: &Router,
    key: &TenantProofKey,
    pair: &Ed25519KeyPair,
    body: &str,
    access: &str,
) -> HeaderMap {
    let nonce = challenge(
        app,
        &key.tenant_id,
        &key.device_id,
        TENANT_DEVICE_HEARTBEAT_PURPOSE,
    );
    let binding = DeviceRequestBinding::new(
        &key.tenant_id,
        DeviceProofProfile::new("EMBEDDED-IDP-DEVICE-REQUEST-V2").unwrap(),
        "test-api",
        CanonicalHttpMethod::Post,
        "/api/devices/heartbeat",
        digest(&SHA256, body.as_bytes())
            .as_ref()
            .try_into()
            .unwrap(),
    )
    .unwrap();
    let mut proof = DeviceProofPresentation {
        device_id: key.device_id.clone(),
        key_id: key.key_id.clone(),
        challenge: nonce,
        signature: Base64UrlUnpadded::encode_string(&[0; 64]),
        signed_at: TestClock.now(),
    };
    proof.signature = Base64UrlUnpadded::encode_string(
        pair.sign(&build_request_proof_bytes(&binding, &proof).unwrap())
            .as_ref(),
    );
    let mut headers = bearer(access);
    for (name, value) in [
        ("x-device-id", proof.device_id),
        ("x-device-key-id", proof.key_id),
        ("x-device-challenge", proof.challenge),
        ("x-device-signature", proof.signature),
        ("x-device-signed-at", "100".into()),
    ] {
        headers.insert(name, value.parse().unwrap());
    }
    headers
}
#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn http_device_lifecycle_and_heartbeat_use_real_proofs_in_both_modes() {
    for (mode, tenant) in [(TenancyMode::Disabled, "0"), (TenancyMode::Enabled, "t1")] {
        let db = Db::new(mode);
        prepare(&db);
        let app = app(&db, tenant, tenant);
        let (jwk, kid, pair) = material(111);
        let supplied_device_id = Uuid::now_v7().to_string();
        let registration_request_id = Uuid::now_v7().to_string();
        let provision_body = json!({"tenant_id":tenant,"device_id":supplied_device_id,"registration_request_id":registration_request_id,"device_name":"Laptop","public_jwk":serde_json::from_str::<Value>(&jwk).unwrap()}).to_string();
        let (status, device) = send(
            &app,
            "POST",
            "/devices/provision",
            &provision_body,
            &HeaderMap::new(),
        );
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(device["status"], "pending");
        assert!(device["completed_at_unix_secs"].is_null());
        assert_eq!(
            send(
                &app,
                "POST",
                "/devices/provision",
                &provision_body,
                &HeaderMap::new()
            ),
            (StatusCode::CREATED, device.clone())
        );
        let device = device["device_id"].as_str().unwrap();
        assert_eq!(device, supplied_device_id);
        let lookup = json!({"tenant_id":tenant,"device_id":device,"registration_request_id":registration_request_id}).to_string();
        assert_eq!(
            send(
                &app,
                "POST",
                "/devices/registration-result",
                &lookup,
                &HeaderMap::new()
            )
            .0,
            StatusCode::OK
        );
        let nonce = challenge(&app, tenant, device, DEVICE_REGISTRATION_PURPOSE);
        let sig = Base64UrlUnpadded::encode_string(
            pair.sign(
                &build_device_registration_proof_bytes(tenant, device, &kid, &nonce).unwrap(),
            )
            .as_ref(),
        );
        let body=json!({"tenant_id":tenant,"device_id":device,"public_jwk":serde_json::from_str::<Value>(&jwk).unwrap(),"challenge":nonce,"signature":sig}).to_string();
        assert_eq!(
            send(&app, "POST", "/devices/complete", &body, &HeaderMap::new()).0,
            StatusCode::OK
        );
        let (status, result) = send(
            &app,
            "POST",
            "/devices/registration-result",
            &lookup,
            &HeaderMap::new(),
        );
        assert_eq!(status, StatusCode::OK);
        assert_eq!(result["status"], "active");
        assert!(result["completed_at_unix_secs"].is_number());
        assert!(
            !send(&app, "POST", "/devices/complete", &body, &HeaderMap::new())
                .0
                .is_success()
        );
        assert_eq!(count(&db, "account_device_bindings"), 0);
        let key = TenantProofKey {
            tenant_id: tenant.into(),
            device_id: device.into(),
            key_id: kid,
            public_jwk: jwk,
            version: 1,
            status: embedded_idp_core::DeviceProofKeyStatus::Active,
        };
        let login = json!({"email":"new@example.test","password":"Test-password-123"}).to_string();
        let signed = super::http::signed(
            &app,
            &key,
            &pair,
            TENANT_DEVICE_LOGIN_PURPOSE,
            "/api/auth/login",
            &login,
            tenant_password_proof_context("web", "device-http", &password()),
        );
        let (status, login) = send(&app, "POST", "/auth/login", &login, &signed);
        assert_eq!(status, StatusCode::OK);
        let access = login["tokens"]["access_token"].as_str().unwrap();
        let headers = bearer(access);
        let listed = send(&app, "GET", "/devices", "", &headers);
        assert_eq!(listed.0, StatusCode::OK);
        assert_eq!(listed.1["items"].as_array().unwrap().len(), 1);
        assert_eq!(
            send(&app, "GET", &format!("/devices/{device}"), "", &headers).1["device_name"],
            "Laptop"
        );
        let body = json!({"device_id":device}).to_string();
        let heartbeat = heartbeat_headers(&app, &key, &pair, &body, access);
        assert_eq!(
            send(
                &app,
                "POST",
                "/devices/heartbeat",
                &format!("{body} "),
                &heartbeat
            )
            .0,
            StatusCode::UNAUTHORIZED
        );
        let nonce = SecretString::new(heartbeat["x-device-challenge"].to_str().unwrap());
        assert!(nonce_unused(&db, &nonce));
        assert_eq!(
            send(
                &app,
                "POST",
                "/devices/heartbeat?extra=1",
                &body,
                &heartbeat
            )
            .0,
            StatusCode::BAD_REQUEST
        );
        let s = db.schema();
        db.adapter.connect().unwrap().batch_execute(&format!("create function {s}.reject_heartbeat() returns trigger language plpgsql as $$ begin raise exception 'synthetic failure'; end $$;create trigger reject_heartbeat before update of last_seen_at_epoch on {s}.devices for each row execute function {s}.reject_heartbeat()")).unwrap();
        assert_eq!(
            send(&app, "POST", "/devices/heartbeat", &body, &heartbeat).0,
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert!(nonce_unused(&db, &nonce));
        db.adapter
            .connect()
            .unwrap()
            .batch_execute(&format!("drop trigger reject_heartbeat on {s}.devices"))
            .unwrap();
        assert_eq!(
            send(&app, "POST", "/devices/heartbeat", &body, &heartbeat).0,
            StatusCode::OK
        );
        assert!(!nonce_unused(&db, &nonce));
        assert_eq!(
            send(&app, "POST", "/devices/heartbeat", &body, &heartbeat).0,
            StatusCode::UNAUTHORIZED
        );
        let (new_jwk, new_kid, new_pair) = material(112);
        let nonce = challenge(&app, tenant, device, DEVICE_KEY_ROTATION_PURPOSE);
        let bytes =
            build_device_key_rotation_proof_bytes(tenant, device, &key.key_id, &new_kid, 2, &nonce)
                .unwrap();
        let mut rotate = json!({"device_id":device,"expected_key_id":key.key_id,"expected_key_version":1,"proposed_public_jwk":serde_json::from_str::<Value>(&new_jwk).unwrap(),"challenge":nonce,"current_key_signature":Base64UrlUnpadded::encode_string(pair.sign(&bytes).as_ref()),"proposed_key_signature":Base64UrlUnpadded::encode_string(&[0;64])});
        assert_eq!(
            send(
                &app,
                "POST",
                "/devices/rotate-key",
                &rotate.to_string(),
                &headers
            )
            .0,
            StatusCode::UNAUTHORIZED
        );
        rotate["proposed_key_signature"] = json!(Base64UrlUnpadded::encode_string(
            new_pair.sign(&bytes).as_ref()
        ));
        assert_eq!(
            send(
                &app,
                "POST",
                "/devices/rotate-key",
                &rotate.to_string(),
                &headers
            )
            .1["version"],
            2
        );
        let new_key = TenantProofKey {
            key_id: new_kid,
            public_jwk: new_jwk,
            version: 2,
            ..key.clone()
        };
        let previous_metadata = send(
            &app,
            "GET",
            &format!("/devices/{device}/keys/{}", key.key_id),
            "",
            &headers,
        );
        assert_eq!(previous_metadata.0, StatusCode::OK);
        assert_eq!(previous_metadata.1["status"], "retired");
        assert!(previous_metadata.1.get("public_jwk").is_none());
        let proposed_metadata = send(
            &app,
            "GET",
            &format!("/devices/{device}/keys/{}", new_key.key_id),
            "",
            &headers,
        );
        assert_eq!(proposed_metadata.0, StatusCode::OK);
        assert_eq!(proposed_metadata.1["status"], "active");
        assert_eq!(proposed_metadata.1["version"], 2);
        assert_eq!(
            send(
                &app,
                "GET",
                &format!("/devices/{device}/keys/missing"),
                "",
                &headers
            )
            .0,
            StatusCode::NOT_FOUND
        );
        let old = heartbeat_headers(&app, &key, &pair, &body, access);
        assert_eq!(
            send(&app, "POST", "/devices/heartbeat", &body, &old).0,
            StatusCode::UNAUTHORIZED
        );
        let new = heartbeat_headers(&app, &new_key, &new_pair, &body, access);
        assert_eq!(
            send(&app, "POST", "/devices/heartbeat", &body, &new).0,
            StatusCode::OK
        );
    }
}

fn login_device(
    db: &Db,
    tenant: &str,
    key: &TenantProofKey,
    pair: &Ed25519KeyPair,
    command: TenantPasswordLogin,
) -> TenantLoginSession {
    let service = auth(
        db,
        LoginTenantPolicy::Fixed {
            tenant_id: tenant.into(),
        },
        "device-http",
        false,
        false,
    );
    let proof = authentication_proof(
        db,
        key,
        pair,
        TENANT_DEVICE_LOGIN_PURPOSE,
        tenant_password_proof_context("web", "device-http", &command),
    );
    password_session(
        service
            .login_with_proof(command, proof, &proofs(db))
            .unwrap(),
    )
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn http_device_unbind_rolls_back_and_revokes_only_own_device_sessions_in_both_modes() {
    for (mode, tenant) in [(TenancyMode::Disabled, "0"), (TenancyMode::Enabled, "t1")] {
        let db = Db::new(mode);
        prepare(&db);
        let app = app(&db, tenant, tenant);
        let devices = proofs(&db);
        let (command, pair) = registration(&db, tenant, 113);
        let key = devices.complete_registration(command).unwrap();
        let first = login_device(&db, tenant, &key, &pair, password());
        let second = login_device(&db, tenant, &key, &pair, password());
        let service = auth(
            &db,
            LoginTenantPolicy::Fixed {
                tenant_id: tenant.into(),
            },
            "device-http",
            false,
            false,
        );
        let other_device = password_session(service.login(password()).unwrap());
        let mut registration = register(tenant);
        registration.email = "other@example.test".into();
        db.service().register_account(registration).unwrap();
        let mut verification = verify(tenant);
        verification.email = "other@example.test".into();
        db.service().verify_email(verification).unwrap();
        let mut other_password = password();
        other_password.email = "other@example.test".into();
        let unrelated = password_session(service.login(other_password.clone()).unwrap());
        let unrelated_headers = bearer(unrelated.tokens.access_token.expose_secret());
        assert_eq!(
            send(&app, "GET", "/devices", "", &unrelated_headers).1["items"]
                .as_array()
                .unwrap()
                .len(),
            0
        );
        assert_eq!(
            send(
                &app,
                "GET",
                &format!("/devices/{}", key.device_id),
                "",
                &unrelated_headers
            )
            .0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            send(
                &app,
                "POST",
                "/devices/unbind",
                &json!({"device_id":key.device_id,"binding_id":Uuid::nil().to_string(),"expected_version":1,"operation_id":Uuid::now_v7().to_string()}).to_string(),
                &unrelated_headers
            )
            .0,
            StatusCode::FORBIDDEN
        );
        let other_user = login_device(&db, tenant, &key, &pair, other_password);
        let other_tenant = if mode == TenancyMode::Enabled {
            Some(actor(&db, "t2"))
        } else {
            None
        };
        let headers = bearer(first.tokens.access_token.expose_secret());
        let detail = send(
            &app,
            "GET",
            &format!("/devices/{}", key.device_id),
            "",
            &headers,
        )
        .1;
        let operation_id = Uuid::now_v7().to_string();
        let body = json!({"device_id":key.device_id,"binding_id":detail["binding_id"],"expected_version":detail["binding_version"],"operation_id":operation_id}).to_string();
        let s = db.schema();
        db.adapter.connect().unwrap().batch_execute(&format!("create function {s}.fail_unbind() returns trigger language plpgsql as $$ begin raise exception 'injected unbind failure'; end $$; create trigger fail_unbind after update on {s}.account_device_bindings for each row execute function {s}.fail_unbind();")).unwrap();
        assert_eq!(
            send(&app, "POST", "/devices/unbind", &body, &headers).0,
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert!(service
            .authenticate(first.tokens.access_token.clone())
            .is_ok());
        let row = db
            .adapter
            .connect()
            .unwrap()
            .query_one(
                &format!(
                    "select count(*) from {s}.refresh_tokens where revoked_at_epoch is not null"
                ),
                &[],
            )
            .unwrap();
        assert_eq!(row.get::<_, i64>(0), 0);
        db.adapter
            .connect()
            .unwrap()
            .batch_execute(&format!(
                "drop trigger fail_unbind on {s}.account_device_bindings"
            ))
            .unwrap();
        let unbound = send(&app, "POST", "/devices/unbind", &body, &headers);
        assert_eq!(unbound.0, StatusCode::OK);
        assert_eq!(unbound.1["result_status"], "unbound");
        assert_eq!(unbound.1["operation_id"], operation_id);
        assert_eq!(
            send(
                &app,
                "GET",
                &format!("/devices/operations/{operation_id}"),
                "",
                &bearer(other_user.tokens.access_token.expose_secret())
            )
            .0,
            StatusCode::NOT_FOUND
        );
        for session in [&first, &second] {
            assert!(service
                .authenticate(session.tokens.access_token.clone())
                .is_err());
            let proof = authentication_proof(
                &db,
                &key,
                &pair,
                embedded_idp_core::REFRESH_PURPOSE,
                tenant_refresh_proof_context("web", "device-http", &session.tokens.refresh_token),
            );
            assert!(service
                .rotate_refresh_with_proof(
                    embedded_idp_core::RotateProofBoundRefreshCommand {
                        refresh_token: session.tokens.refresh_token.clone(),
                        proof: proof.proof,
                        binding: proof.binding
                    },
                    &devices
                )
                .is_err());
            let row = db.adapter.connect().unwrap().query_one(&format!("select status,(select bool_and(revocation_reason='client_revocation') from {s}.refresh_tokens f where f.tenant_id=a.tenant_id and f.session_id=a.id) from {s}.auth_sessions a where tenant_id=$1 and id=$2"), &[&tenant,&Uuid::parse_str(&session.session.id).unwrap()]).unwrap();
            assert_eq!(row.get::<_, String>(0), "revoked");
            assert!(row.get::<_, bool>(1));
        }
        assert!(service
            .authenticate(other_device.tokens.access_token.clone())
            .is_ok());
        assert!(service.authenticate(other_user.tokens.access_token).is_ok());
        if let Some(actor) = other_tenant {
            assert!(devices
                .list_subject_devices(actor, AccessPageRequest::default())
                .is_ok());
        }
        let remaining = send(
            &app,
            "GET",
            "/devices",
            "",
            &bearer(other_device.tokens.access_token.expose_secret()),
        );
        assert_eq!(remaining.1["items"].as_array().unwrap().len(), 0);
        let renewed = login_device(&db, tenant, &key, &pair, password());
        let renewed_headers = bearer(renewed.tokens.access_token.expose_secret());
        let repeated = send(&app, "POST", "/devices/unbind", &body, &renewed_headers);
        assert_eq!(repeated.0, StatusCode::OK);
        assert_eq!(repeated.1["audit_id"], unbound.1["audit_id"]);
        let found = send(
            &app,
            "GET",
            &format!("/devices/operations/{operation_id}"),
            "",
            &renewed_headers,
        );
        assert_eq!(found.0, StatusCode::OK);
        assert_eq!(found.1["audit_id"], unbound.1["audit_id"]);
        let changed_intent = json!({"device_id":key.device_id,"binding_id":Uuid::now_v7().to_string(),"expected_version":1,"operation_id":operation_id}).to_string();
        assert_eq!(
            send(
                &app,
                "POST",
                "/devices/unbind",
                &changed_intent,
                &renewed_headers
            )
            .0,
            StatusCode::CONFLICT
        );
        let receipt_count: i64 = db
            .adapter
            .connect()
            .unwrap()
            .query_one(
                &format!(
                    "select count(*) from {s}.access_audit_events where device_operation_id=$1"
                ),
                &[&Uuid::parse_str(&operation_id).unwrap()],
            )
            .unwrap()
            .get(0);
        assert_eq!(receipt_count, 1);
        let renewed_detail = send(
            &app,
            "GET",
            &format!("/devices/{}", key.device_id),
            "",
            &renewed_headers,
        )
        .1;
        assert_ne!(renewed_detail["binding_id"], detail["binding_id"]);
        assert!(service.authenticate(renewed.tokens.access_token).is_ok());
        assert!(service.authenticate(first.tokens.access_token).is_err());
    }
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn http_device_queries_enforce_actor_client_tenant_cursor_and_admission() {
    let db = Db::new(TenancyMode::Enabled);
    let account = prepare(&db);
    let app = app(&db, "t1", "t1");
    let devices = proofs(&db);
    let mut ids = vec![];
    let mut token = None;
    for seed in [114, 115, 116] {
        let (command, pair) = registration(&db, "t1", seed);
        let key = devices.complete_registration(command).unwrap();
        let issued = login_device(&db, "t1", &key, &pair, password())
            .tokens
            .access_token;
        if token.is_none() {
            token = Some(issued);
        }
        ids.push(key.device_id);
    }
    ids.sort();
    let headers = bearer(token.as_ref().unwrap().expose_secret());
    let first = send(&app, "GET", "/devices?limit=1", "", &headers);
    assert_eq!(first.0, StatusCode::OK);
    assert_eq!(first.1["items"][0]["device_id"], ids[0]);
    assert_eq!(first.1["has_more"], true);
    let cursor = first.1["next_cursor"].as_str().unwrap();
    let second = send(
        &app,
        "GET",
        &format!("/devices?limit=2&cursor={cursor}"),
        "",
        &headers,
    );
    assert_eq!(second.1["items"].as_array().unwrap().len(), 2);
    assert_eq!(second.1["items"][0]["device_id"], ids[1]);
    assert_eq!(second.1["has_more"], false);
    for field in ["tenant_id", "subject_id", "client_id", "after"] {
        let mut changed: Value =
            serde_json::from_slice(&Base64UrlUnpadded::decode_vec(cursor).unwrap()).unwrap();
        changed[field] = json!("wrong");
        let altered = Base64UrlUnpadded::encode_string(&serde_json::to_vec(&changed).unwrap());
        assert_eq!(
            send(
                &app,
                "GET",
                &format!("/devices?cursor={altered}"),
                "",
                &headers
            )
            .0,
            StatusCode::BAD_REQUEST
        );
    }
    for path in [
        "/devices?limit=0",
        "/devices?limit=201",
        "/devices?subject_id=other",
        "/devices?tenant_id=t2",
        "/devices?cursor=bad",
    ] {
        assert_eq!(
            send(&app, "GET", path, "", &headers).0,
            StatusCode::BAD_REQUEST
        );
    }
    assert_eq!(
        send(&app, "GET", "/devices", "", &HeaderMap::new()).0,
        StatusCode::UNAUTHORIZED
    );
    let mut wrong = headers.clone();
    wrong.insert("x-embedded-idp-tenant-id", "t2".parse().unwrap());
    assert_eq!(
        send(&app, "GET", "/devices", "", &wrong).0,
        StatusCode::UNAUTHORIZED
    );
    let outsider = actor(&db, "t2");
    assert!(devices
        .get_subject_device(outsider.clone(), &ids[0])
        .is_err());
    assert!(devices
        .unbind_subject_device(
            outsider,
            &ids[0],
            &Uuid::nil().to_string(),
            1,
            &Uuid::now_v7().to_string()
        )
        .is_err());
    let schema = db.schema();
    db.adapter.connect().unwrap().batch_execute(&format!("insert into {schema}.oidc_clients(client_id,client_name,redirect_uris_json,client_type,pkce_required,created_at_epoch) values('other','Other','[]','public_desktop',true,100)")).unwrap();
    let other_device = Uuid::now_v7();
    db.adapter
        .connect()
        .unwrap()
        .execute(
            &format!(
                "insert into {schema}.devices(tenant_id,id,client_id,device_name,status,registered_at_epoch) values('t1',$1,'other','Other','pending',100)"
            ),
            &[&other_device],
        )
        .unwrap();
    db.adapter.connect().unwrap().execute(&format!("insert into {schema}.account_device_bindings(tenant_id,id,account_id,device_id,status,bound_at_epoch) values('t1',$1,$2,$3,'active',100)"),&[&Uuid::now_v7(),&Uuid::parse_str(&account).unwrap(),&other_device]).unwrap();
    assert_eq!(
        send(&app, "GET", "/devices", "", &headers).1["items"]
            .as_array()
            .unwrap()
            .len(),
        3
    );
    assert_eq!(
        send(
            &app,
            "GET",
            &format!("/devices/{other_device}"),
            "",
            &headers
        )
        .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        send(
            &app,
            "POST",
            "/devices/unbind",
            &json!({"device_id":other_device.to_string(),"binding_id":Uuid::nil().to_string(),"expected_version":1,"operation_id":Uuid::now_v7().to_string()})
                .to_string(),
            &headers
        )
        .0,
        StatusCode::FORBIDDEN
    );
    let denied = super::management_http::app(&db, "t1", "t2");
    let before = count(&db, "devices");
    for (router, tenant) in [(&denied, "t1"), (&app, "t2")] {
        assert!(!send(
            router,
            "POST",
            "/devices/provision",
            &json!({"tenant_id":tenant,"device_id":Uuid::now_v7().to_string(),"registration_request_id":Uuid::now_v7().to_string(),"device_name":"denied","public_jwk":serde_json::from_str::<Value>(&material(112).0).unwrap()}).to_string(),
            &HeaderMap::new()
        )
        .0
        .is_success());
    }
    assert_eq!(count(&db, "devices"), before);
    // Direct Core calls must recheck expired/revoked state, not trust a cached actor.
    let service = auth(
        &db,
        LoginTenantPolicy::Fixed {
            tenant_id: "t1".into(),
        },
        "device-http",
        false,
        false,
    );
    let stale = service.authenticate(token.unwrap()).unwrap();
    let session_id = Uuid::parse_str(&stale.session_id).unwrap();
    db.adapter.connect().unwrap().execute(&format!("update {schema}.auth_sessions set authenticated_at_epoch=99,created_at_epoch=99,expires_at_epoch=100 where tenant_id='t1' and id=$1"),&[&session_id]).unwrap();
    assert_eq!(
        devices.list_subject_devices(stale.clone(), AccessPageRequest::default()),
        Err(TenantAuthError::InvalidSession)
    );
    assert_eq!(
        devices.get_subject_device(stale.clone(), &ids[0]),
        Err(TenantAuthError::InvalidSession)
    );
    assert_eq!(
        devices.unbind_subject_device(
            stale.clone(),
            &ids[0],
            &Uuid::nil().to_string(),
            1,
            &Uuid::now_v7().to_string()
        ),
        Err(TenantAuthError::InvalidSession)
    );
    db.adapter.connect().unwrap().execute(&format!("update {schema}.auth_sessions set authenticated_at_epoch=100,created_at_epoch=100,expires_at_epoch=700 where tenant_id='t1' and id=$1"),&[&session_id]).unwrap();
    db.adapter
        .connect()
        .unwrap()
        .execute(
            &format!(
                "update {schema}.devices set status='disabled' where tenant_id='t1' and id=$1"
            ),
            &[&Uuid::parse_str(&ids[0]).unwrap()],
        )
        .unwrap();
    assert_eq!(
        devices.list_subject_devices(stale.clone(), AccessPageRequest::default()),
        Err(TenantAuthError::InvalidSession)
    );
    db.adapter
        .connect()
        .unwrap()
        .execute(
            &format!("update {schema}.devices set status='active' where tenant_id='t1' and id=$1"),
            &[&Uuid::parse_str(&ids[0]).unwrap()],
        )
        .unwrap();
    db.adapter
        .connect()
        .unwrap()
        .execute(
            &format!(
                "update {}.auth_sessions set status='revoked' where tenant_id='t1' and id=$1",
                db.schema()
            ),
            &[&Uuid::parse_str(&stale.session_id).unwrap()],
        )
        .unwrap();
    assert!(devices
        .list_subject_devices(stale.clone(), AccessPageRequest::default())
        .is_err());
    assert!(devices
        .unbind_subject_device(
            stale,
            &ids[0],
            &Uuid::nil().to_string(),
            1,
            &Uuid::now_v7().to_string()
        )
        .is_err());
}
