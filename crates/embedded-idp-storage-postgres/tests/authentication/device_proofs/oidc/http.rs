use super::*;
use axum::{
    body::{to_bytes, Body},
    http::{header, HeaderMap, Request, StatusCode},
    Router,
};
use embedded_idp_axum::{
    tenant_device_auth_router, tenant_oidc_authorization_router, TenantDeviceAuthHttpConfig,
    TenantOidcHttpConfig,
};
use serde_json::Value;
use tower::ServiceExt;

const HTTP_CALLBACK: &str = "http://127.0.0.1:49152/callback";
const TOKEN: &str = "/api/oidc/token";
const STATE: &str = "state &code=injected+#";
fn app(db: &Db, tenant: &str, fail: bool) -> Router {
    Router::new().nest(
        "/api",
        tenant_oidc_authorization_router(
            Arc::new(CoreTenantOidcAuthorizationService::new(
                oidc(db, tenant, fail),
                proofs(db),
            )),
            TenantOidcHttpConfig::new("test-api", TOKEN).unwrap(),
        )
        .merge(tenant_device_auth_router(
            Arc::new(CoreTenantDeviceAuthenticationService::new(
                entry(db, tenant),
                proofs(db),
            )),
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
fn setup_http(db: &Db, tenant: &str) -> TenantLoginSession {
    let initial = setup(db, tenant);
    db.adapter
        .connect()
        .unwrap()
        .execute(
            &format!(
                "update {}.oidc_clients set redirect_uris_json=$1 where client_id='web'",
                db.schema()
            ),
            &[&format!("[\"{HTTP_CALLBACK}\"]")],
        )
        .unwrap();
    initial
}
fn form(code: &SecretString, client: bool) -> String {
    let mut text = format!("grant_type=authorization_code&code={}&redirect_uri=http%3A%2F%2F127.0.0.1%3A49152%2Fcallback&code_verifier={VERIFIER}", code.expose_secret());
    if client {
        text.push_str("&client_id=web");
    }
    text
}
fn bearer(token: &SecretString) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::AUTHORIZATION,
        format!("Bearer {}", token.expose_secret()).parse().unwrap(),
    );
    headers
}
fn authorize_path() -> String {
    let state: String = STATE.bytes().map(|b| format!("%{b:02X}")).collect();
    format!("/api/oidc/authorize?response_type=code&client_id=web&redirect_uri=http%3A%2F%2F127.0.0.1%3A49152%2Fcallback&scope=openid&state={state}&nonce=nonce&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256")
}
fn send(
    app: &Router,
    method: &str,
    path: &str,
    body: &str,
    headers: &HeaderMap,
) -> (StatusCode, HeaderMap, Value) {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let mut request = Request::builder()
                .method(method)
                .uri(path)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(body.to_owned()))
                .unwrap();
            request.headers_mut().extend(headers.clone());
            let response = app.clone().oneshot(request).await.unwrap();
            assert_eq!(response.headers()["cache-control"], "no-store");
            assert_eq!(response.headers()["pragma"], "no-cache");
            let status = response.status();
            let headers = response.headers().clone();
            let bytes = to_bytes(response.into_body(), 65536).await.unwrap();
            (
                status,
                headers,
                serde_json::from_slice(&bytes).unwrap_or(Value::Null),
            )
        })
}
fn grant(app: &Router, token: &SecretString) -> SecretString {
    let (status, headers, _) = send(app, "GET", &authorize_path(), "", &bearer(token));
    assert_eq!(status, StatusCode::TEMPORARY_REDIRECT);
    let location = headers[header::LOCATION].to_str().unwrap();
    assert!(location.starts_with("http://127.0.0.1:49152/callback?code="));
    // State must be one encoded value, never a second code parameter or fragment.
    assert!(location.ends_with("&state=state+%26code%3Dinjected%2B%23"));
    let code = location
        .split("?code=")
        .nth(1)
        .unwrap()
        .split('&')
        .next()
        .unwrap();
    SecretString::new(code)
}
#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn http_oidc_authorize_and_exchange_validate_identity_client_pkce_and_single_use() {
    for (mode, tenant) in [(TenancyMode::Disabled, "0"), (TenancyMode::Enabled, "t1")] {
        let db = Db::new(mode);
        let initial = setup_http(&db, tenant);
        let app = app(&db, tenant, false);
        let path = authorize_path();
        let mut headers = bearer(&initial.tokens.access_token);
        assert_eq!(
            send(&app, "GET", &path, "", &HeaderMap::new()).0,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            send(&app, "GET", &format!("{path}&tenant_id=t2"), "", &headers).0,
            StatusCode::BAD_REQUEST
        );
        let bad_redirect = path.replace(
            "http%3A%2F%2F127.0.0.1%3A49152%2Fcallback",
            "https%3A%2F%2Fevil.example",
        );
        let denied = send(&app, "GET", &bad_redirect, "", &headers);
        assert_eq!(denied.0, StatusCode::BAD_REQUEST);
        assert!(!denied.1.contains_key(header::LOCATION));
        headers.insert("x-embedded-idp-tenant-id", "t2".parse().unwrap());
        assert_eq!(
            send(&app, "GET", &path, "", &headers).0,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(count(&db, "authorization_codes"), 0);
        let code = grant(&app, &initial.tokens.access_token);
        let body = form(&code, true);
        let bad = body.replace(VERIFIER, &"x".repeat(43));
        assert_eq!(
            send(&app, "POST", TOKEN, &bad, &HeaderMap::new()).2["error"],
            "invalid_grant"
        );
        assert!(unused(&db, &code));
        let (status, _, issued) = send(&app, "POST", TOKEN, &body, &HeaderMap::new());
        assert_eq!(status, StatusCode::OK);
        assert_eq!(issued["tenant_id"], tenant);
        assert_eq!(issued["scope"], "openid");
        assert_eq!(issued["token_type"], "Bearer");
        assert!(issued["expires_in"].as_u64().unwrap() > 0);
        assert!(entry(&db, tenant)
            .authenticate(SecretString::new(issued["access_token"].as_str().unwrap()))
            .is_ok());
        let id: Value = serde_json::from_slice(
            &Base64UrlUnpadded::decode_vec(
                issued["id_token"]
                    .as_str()
                    .unwrap()
                    .split('.')
                    .nth(1)
                    .unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(id["tenant_id"], tenant);
        assert_eq!(id["nonce"], "nonce");
        assert_eq!(
            send(&app, "POST", TOKEN, &body, &HeaderMap::new()).2["error"],
            "invalid_grant"
        );
        assert!(!unused(&db, &code));
        let code = grant(&app, &initial.tokens.access_token);
        // Authenticate the confidential client using the same parser as resource endpoints.
        db.adapter.connect().unwrap().execute(&format!("update {}.oidc_clients set client_type='confidential_web',client_secret_hash='synthetic-secret-hash' where client_id='web'",db.schema()),&[]).unwrap();
        let body = form(&code, false);
        let mut basic = HeaderMap::new();
        basic.insert(
            header::AUTHORIZATION,
            format!("Basic {}", base64ct::Base64::encode_string(b"web:wrong"))
                .parse()
                .unwrap(),
        );
        let denied = send(&app, "POST", TOKEN, &body, &basic);
        assert_eq!(denied.0, StatusCode::UNAUTHORIZED);
        assert_eq!(denied.2["error"], "invalid_client");
        assert!(denied.1.contains_key(header::WWW_AUTHENTICATE));
        assert!(unused(&db, &code));
        basic.insert(
            header::AUTHORIZATION,
            format!(
                "Basic {}",
                base64ct::Base64::encode_string(b"web:synthetic-client-secret")
            )
            .parse()
            .unwrap(),
        );
        assert_eq!(
            send(&app, "POST", TOKEN, &form(&code, true), &basic).0,
            StatusCode::UNAUTHORIZED
        );
        assert!(unused(&db, &code));
        assert_eq!(send(&app, "POST", TOKEN, &body, &basic).0, StatusCode::OK);
        let pending = grant(&app, &initial.tokens.access_token);
        oidc(&db, tenant, false)
            .logout(TenantTokenRequest {
                client_id: "web".into(),
                client_secret: Some(SecretString::new("synthetic-client-secret")),
                token: initial.tokens.refresh_token.clone(),
                token_type_hint: Some(TenantTokenType::Refresh),
            })
            .unwrap();
        assert_eq!(
            send(
                &app,
                "GET",
                &path,
                "",
                &bearer(&initial.tokens.access_token)
            )
            .0,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            send(&app, "POST", TOKEN, &form(&pending, false), &basic).2["error"],
            "invalid_grant"
        );
        assert!(unused(&db, &pending));
    }
}
#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn http_oidc_device_exchange_binds_raw_form_tenant_and_rolls_back_failures() {
    for (mode, tenant) in [(TenancyMode::Disabled, "0"), (TenancyMode::Enabled, "t1")] {
        let db = Db::new(mode);
        setup_http(&db, tenant);
        let (reg, pair) = registration(&db, tenant, 97);
        let key = proofs(&db).complete_registration(reg).unwrap();
        let proof = authentication_proof(
            &db,
            &key,
            &pair,
            TENANT_DEVICE_LOGIN_PURPOSE,
            tenant_password_proof_context("web", "oidc", &password()),
        );
        let initial = password_session(
            entry(&db, tenant)
                .login_with_proof(password(), proof, &proofs(&db))
                .unwrap(),
        );
        let app = app(&db, tenant, false);
        let code = grant(&app, &initial.tokens.access_token);
        let body = form(&code, true);
        let mut cmd = exchange(code.clone());
        cmd.redirect_uri = HTTP_CALLBACK.into();
        let mut signed = super::super::http::signed(
            &app,
            &key,
            &pair,
            TENANT_OIDC_EXCHANGE_PURPOSE,
            TOKEN,
            &body,
            tenant_code_proof_context("oidc", &cmd),
        );
        signed.insert("x-embedded-idp-tenant-id", tenant.parse().unwrap());
        let nonce = SecretString::new(signed["x-device-challenge"].to_str().unwrap());
        assert_eq!(
            send(&app, "POST", TOKEN, &body, &HeaderMap::new()).2["error"],
            "invalid_grant"
        );
        assert_eq!(
            send(&app, "POST", &format!("{TOKEN}?extra=1"), &body, &signed).0,
            StatusCode::BAD_REQUEST
        );
        // Equivalent decoded form with different bytes must fail the signature.
        assert_eq!(
            send(
                &app,
                "POST",
                TOKEN,
                &body.replace("client_id=web", "client_id=%77eb"),
                &signed
            )
            .2["error"],
            "invalid_grant"
        );
        let mut wrong = signed.clone();
        wrong.insert("x-embedded-idp-tenant-id", "t2".parse().unwrap());
        assert_eq!(
            send(&app, "POST", TOKEN, &body, &wrong).2["error"],
            "invalid_grant"
        );
        let mut duplicate = signed.clone();
        duplicate.append("x-device-id", key.device_id.parse().unwrap());
        assert_eq!(
            send(&app, "POST", TOKEN, &body, &duplicate).0,
            StatusCode::BAD_REQUEST
        );
        assert!(unused(&db, &code));
        assert!(nonce_unused(&db, &nonce));
        let before = count(&db, "auth_sessions");
        let failing = self::app(&db, tenant, true);
        assert_eq!(
            send(&failing, "POST", TOKEN, &body, &signed).0,
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert!(unused(&db, &code));
        assert!(nonce_unused(&db, &nonce));
        assert_eq!(count(&db, "auth_sessions"), before);
        let s = db.schema();
        db.adapter.connect().unwrap().batch_execute(&format!("create function {s}.fail_http_oidc() returns trigger language plpgsql as $$ begin raise exception 'synthetic failure'; end $$;create trigger fail_http_oidc after insert on {s}.refresh_tokens for each row execute function {s}.fail_http_oidc()" )).unwrap();
        assert_eq!(
            send(&app, "POST", TOKEN, &body, &signed).0,
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert!(unused(&db, &code));
        assert!(nonce_unused(&db, &nonce));
        assert_eq!(count(&db, "auth_sessions"), before);
        db.adapter
            .connect()
            .unwrap()
            .batch_execute(&format!(
                "drop trigger fail_http_oidc on {s}.refresh_tokens"
            ))
            .unwrap();
        assert_eq!(send(&app, "POST", TOKEN, &body, &signed).0, StatusCode::OK);
        assert!(!unused(&db, &code));
        assert!(!nonce_unused(&db, &nonce));
        assert_eq!(count(&db, "auth_sessions"), before + 1);
        assert_eq!(
            send(&app, "POST", TOKEN, &body, &signed).2["error"],
            "invalid_grant"
        );
    }
}
