use super::*;
use axum::{
    http::{HeaderMap, StatusCode},
    Router,
};
use embedded_idp_axum::{tenant_device_auth_router, TenantDeviceAuthHttpConfig};
use serde_json::{json, Value};
use tower::ServiceExt;

const LOGIN: &str = "/api/auth/login";
const SELECT: &str = "/api/auth/tenant-selection/complete";
const REFRESH: &str = "/api/auth/refresh";
fn router(db: &Db, policy: LoginTenantPolicy, required: bool, fail: bool) -> Router {
    let service = CoreTenantDeviceAuthenticationService::new(
        auth(db, policy, "http", required, fail),
        proofs(db),
    );
    Router::new().nest(
        "/api",
        tenant_device_auth_router(
            Arc::new(service),
            TenantDeviceAuthHttpConfig::new("test-api", LOGIN, SELECT, REFRESH).unwrap(),
        ),
    )
}
fn fixed(tenant: &str) -> LoginTenantPolicy {
    LoginTenantPolicy::Fixed {
        tenant_id: tenant.into(),
    }
}
fn login_body() -> String {
    json!({"email":"new@example.test","password":"Test-password-123"}).to_string()
}
pub(super) fn signed(
    router: &Router,
    key: &TenantProofKey,
    pair: &Ed25519KeyPair,
    purpose: &str,
    path: &str,
    body: &str,
    context: [u8; 32],
) -> HeaderMap {
    let (status, challenge) = request(
        router,
        "/api/devices/proof/challenges",
        &json!({"tenant_id":key.tenant_id,"device_id":key.device_id,"purpose":purpose}).to_string(),
        &HeaderMap::new(),
    );
    assert_eq!(status, StatusCode::OK);
    let binding = DeviceRequestBinding::new(
        &key.tenant_id,
        DeviceProofProfile::new(TENANT_DEVICE_AUTH_PROFILE).unwrap(),
        "test-api",
        CanonicalHttpMethod::Post,
        path,
        digest(&SHA256, body.as_bytes())
            .as_ref()
            .try_into()
            .unwrap(),
    )
    .unwrap();
    let mut proof = DeviceProofPresentation {
        device_id: key.device_id.clone(),
        key_id: key.key_id.clone(),
        challenge: challenge["challenge"].as_str().unwrap().into(),
        signature: Base64UrlUnpadded::encode_string(&[0; 64]),
        signed_at: TestClock.now(),
    };
    proof.signature = Base64UrlUnpadded::encode_string(
        pair.sign(&build_tenant_authentication_proof_bytes(&binding, &proof, &context).unwrap())
            .as_ref(),
    );
    let mut headers = HeaderMap::new();
    for (name, value) in [
        ("x-device-id", proof.device_id),
        ("x-device-key-id", proof.key_id),
        ("x-device-challenge", proof.challenge),
        ("x-device-signature", proof.signature),
        ("x-device-signed-at", "100".into()),
    ] {
        headers.insert(name, value.parse().unwrap());
    }
    if path == REFRESH {
        headers.insert("x-embedded-idp-tenant-id", key.tenant_id.parse().unwrap());
    }
    headers
}
fn unused(db: &Db, headers: &HeaderMap) -> bool {
    nonce_unused(
        db,
        &SecretString::new(headers["x-device-challenge"].to_str().unwrap()),
    )
}
#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn http_device_login_and_refresh_preserve_raw_bytes_tenant_and_committed_reuse() {
    for (mode, tenant) in [(TenancyMode::Disabled, "0"), (TenancyMode::Enabled, "t1")] {
        let db = Db::new(mode);
        prepare(&db);
        let (reg, pair) = registration(&db, tenant, 91);
        let key = proofs(&db).complete_registration(reg).unwrap();
        let app = router(&db, fixed(tenant), true, false);
        {
            let body = login_body();
            assert_eq!(
                request(&app, LOGIN, &body, &HeaderMap::new()).0,
                StatusCode::FORBIDDEN
            );
            let headers = signed(
                &app,
                &key,
                &pair,
                TENANT_DEVICE_LOGIN_PURPOSE,
                LOGIN,
                &body,
                tenant_password_proof_context("web", "http", &password()),
            );
            assert_eq!(
                request(&app, &format!("{LOGIN}?extra=1"), &body, &headers).0,
                StatusCode::BAD_REQUEST
            );
            assert!(unused(&db, &headers));
            assert_eq!(
                request(&app, LOGIN, &format!("{body}\n"), &headers).0,
                StatusCode::UNAUTHORIZED
            );
            assert!(unused(&db, &headers));
            let mut duplicated = headers.clone();
            duplicated.append("x-device-id", key.device_id.parse().unwrap());
            assert_eq!(
                request(&app, LOGIN, &body, &duplicated).0,
                StatusCode::UNAUTHORIZED
            );
            assert!(unused(&db, &headers));
            let (status, login) = request(&app, LOGIN, &body, &headers);
            assert_eq!(status, StatusCode::OK);
            assert_eq!(login["session"]["tenant_id"], tenant);
            assert!(!unused(&db, &headers));
            assert_eq!(
                request(&app, LOGIN, &body, &headers).0,
                StatusCode::UNAUTHORIZED
            );
            let raw = SecretString::new(login["tokens"]["refresh_token"].as_str().unwrap());
            let body = json!({"refresh_token":raw.expose_secret()}).to_string();
            let optional = router(&db, fixed(tenant), false, false);
            assert_eq!(
                request(&optional, REFRESH, &body, &HeaderMap::new()).0,
                StatusCode::FORBIDDEN
            );
            let proof = signed(
                &app,
                &key,
                &pair,
                embedded_idp_core::REFRESH_PURPOSE,
                REFRESH,
                &body,
                tenant_refresh_proof_context("web", "http", &raw),
            );
            let mut changed = proof.clone();
            changed.insert(
                "x-embedded-idp-tenant-id",
                if tenant == "0" { "t1" } else { "t2" }.parse().unwrap(),
            );
            assert_eq!(
                request(&app, REFRESH, &body, &changed).0,
                StatusCode::UNAUTHORIZED
            );
            assert!(unused(&db, &proof));
            let (status, rotated) = request(&app, REFRESH, &body, &proof);
            assert_eq!(status, StatusCode::OK);
            assert!(auth(&db, fixed(tenant), "http", true, false)
                .authenticate(SecretString::new(
                    rotated["tokens"]["access_token"].as_str().unwrap()
                ))
                .is_ok());
            assert_eq!(
                request(&app, REFRESH, &body, &proof).0,
                StatusCode::UNAUTHORIZED
            );
            let fresh = signed(
                &app,
                &key,
                &pair,
                embedded_idp_core::REFRESH_PURPOSE,
                REFRESH,
                &body,
                tenant_refresh_proof_context("web", "http", &raw),
            );
            let (status, error) = request(&app, REFRESH, &body, &fresh);
            assert_eq!(status, StatusCode::UNAUTHORIZED);
            assert_eq!(error["code"], "refresh_token_reuse_detected");
            assert!(!unused(&db, &fresh));
            assert!(auth(&db, fixed(tenant), "http", true, false)
                .authenticate(SecretString::new(
                    rotated["tokens"]["access_token"].as_str().unwrap()
                ))
                .is_err());
            let before = count(&db, "device_nonces");
            assert_eq!(request(&app,"/api/devices/proof/challenges",&json!({"tenant_id":tenant,"device_id":Uuid::now_v7().to_string(),"purpose":"refresh"}).to_string(),&HeaderMap::new()).0,StatusCode::OK);
            assert_eq!(count(&db, "device_nonces"), before);
        }
    }
}
#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn http_device_selection_binds_ticket_and_signed_target_tenant() {
    let db = Db::new(TenancyMode::Enabled);
    prepare(&db);
    let (reg, pair) = registration(&db, "t1", 92);
    let key = proofs(&db).complete_registration(reg).unwrap();
    let app = router(
        &db,
        LoginTenantPolicy::ChooseAfterAuthentication,
        true,
        false,
    );
    {
        let (_, login) = request(&app, LOGIN, &login_body(), &HeaderMap::new());
        let ticket = SecretString::new(login["selection_ticket"].as_str().unwrap());
        assert!(login.get("tokens").is_none());
        let body = json!({"tenant_id":"t1"}).to_string();
        let mut headers = signed(
            &app,
            &key,
            &pair,
            TENANT_DEVICE_SELECTION_PURPOSE,
            SELECT,
            &body,
            tenant_selection_proof_context("web", "http", &ticket),
        );
        headers.insert(
            "authorization",
            format!("TenantSelection {}", ticket.expose_secret())
                .parse()
                .unwrap(),
        );
        let (_, other) = request(&app, LOGIN, &login_body(), &HeaderMap::new());
        let mut swapped = headers.clone();
        swapped.insert(
            "authorization",
            format!(
                "TenantSelection {}",
                other["selection_ticket"].as_str().unwrap()
            )
            .parse()
            .unwrap(),
        );
        assert_eq!(
            request(&app, SELECT, &body, &swapped).0,
            StatusCode::UNAUTHORIZED
        );
        assert!(unused(&db, &headers));
        assert!(request(&app, SELECT, r#"{"tenant_id":"t2"}"#, &headers)
            .0
            .is_client_error());
        assert!(unused(&db, &headers));
        let (status, result) = request(&app, SELECT, &body, &headers);
        assert_eq!(status, StatusCode::OK);
        assert_eq!(result["session"]["tenant_id"], "t1");
        assert_eq!(
            request(&app, SELECT, &body, &headers).0,
            StatusCode::UNAUTHORIZED
        );
    }
}
#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn http_device_login_and_refresh_failures_roll_back_and_bearer_refresh_still_works() {
    let db = Db::new(TenancyMode::Disabled);
    prepare(&db);
    let (reg, pair) = registration(&db, "0", 93);
    let key = proofs(&db).complete_registration(reg).unwrap();
    let app = router(&db, fixed("0"), true, false);
    let failing = router(&db, fixed("0"), true, true);
    {
        let body = login_body();
        let headers = signed(
            &app,
            &key,
            &pair,
            TENANT_DEVICE_LOGIN_PURPOSE,
            LOGIN,
            &body,
            tenant_password_proof_context("web", "http", &password()),
        );
        assert_eq!(
            request(&failing, LOGIN, &body, &headers).0,
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert!(unused(&db, &headers));
        assert_eq!(count(&db, "auth_sessions"), 0);
        assert_eq!(count(&db, "account_device_bindings"), 0);
        let (_, login) = request(&app, LOGIN, &body, &headers);
        let raw = SecretString::new(login["tokens"]["refresh_token"].as_str().unwrap());
        let body = json!({"refresh_token":raw.expose_secret()}).to_string();
        let proof = signed(
            &app,
            &key,
            &pair,
            embedded_idp_core::REFRESH_PURPOSE,
            REFRESH,
            &body,
            tenant_refresh_proof_context("web", "http", &raw),
        );
        let s = db.schema();
        db.adapter.connect().unwrap().batch_execute(&format!("create function {s}.reject_http_refresh() returns trigger language plpgsql as $$ begin raise exception 'synthetic failure';end $$;create trigger reject_http_refresh after insert on {s}.refresh_tokens for each row execute function {s}.reject_http_refresh()" )).unwrap();
        assert_eq!(
            request(&app, REFRESH, &body, &proof).0,
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert!(unused(&db, &proof));
        assert_eq!(count(&db, "refresh_tokens"), 1);
        db.adapter
            .connect()
            .unwrap()
            .batch_execute(&format!(
                "drop trigger reject_http_refresh on {s}.refresh_tokens"
            ))
            .unwrap();
        assert_eq!(request(&app, REFRESH, &body, &proof).0, StatusCode::OK);
        let optional = router(&db, fixed("0"), false, false);
        let (status, login) = request(&optional, LOGIN, &login_body(), &HeaderMap::new());
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            request(
                &optional,
                REFRESH,
                &json!({"refresh_token":login["tokens"]["refresh_token"]}).to_string(),
                &HeaderMap::new()
            )
            .0,
            StatusCode::OK
        );
        assert_eq!(
            request(&optional, REFRESH, &"x".repeat(20_000), &HeaderMap::new()).0,
            StatusCode::PAYLOAD_TOO_LARGE
        );
    }
}

async fn execute_request(
    router: &Router,
    path: &str,
    body: &str,
    headers: &HeaderMap,
) -> (StatusCode, Value) {
    let mut request = axum::http::Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/json");
    for (k, v) in headers {
        request = request.header(k, v)
    }
    let response = router
        .clone()
        .oneshot(
            request
                .body(axum::body::Body::from(body.to_owned()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert_eq!(response.headers()["pragma"], "no-cache");
    let bytes = axum::body::to_bytes(response.into_body(), 65536)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

fn request(router: &Router, path: &str, body: &str, headers: &HeaderMap) -> (StatusCode, Value) {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(execute_request(router, path, body, headers))
}
