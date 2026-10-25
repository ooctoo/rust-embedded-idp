#![cfg(feature = "openapi")]
use axum::{
    body::{to_bytes, Body},
    http::Request,
};
use embedded_idp_axum::{openapi::business_document, tenant_auth_router};
use embedded_idp_core::{access::*, SecretString};
use serde_json::{json, Value};
use std::{collections::BTreeSet, sync::Arc};
use tower::ServiceExt;

#[test]
fn generated_contract_is_current_and_references_resolve() {
    let document = business_document();
    let rendered = format!("{}\n", document.to_pretty_json().unwrap());
    assert_eq!(
        rendered,
        include_str!("../../../docs/api/business-openapi.json"),
        "regenerate using export_openapi"
    );
    let value = serde_json::to_value(document).unwrap();
    assert_eq!(value["openapi"], "3.1.0");
    let mut ids = BTreeSet::new();
    let inventory = include_str!("../../../docs/api/route-inventory.md");
    for (path, item) in value["paths"].as_object().unwrap() {
        assert!(inventory.contains(path), "inventory missing {path}");
        for (_, op) in item.as_object().unwrap() {
            assert!(ids.insert(op["operationId"].as_str().unwrap()));
        }
    }
    assert_eq!(ids.len(), 17);
    fn refs(v: &Value, root: &Value) {
        match v {
            Value::Object(map) => {
                if let Some(r) = map.get("$ref") {
                    let p = r.as_str().unwrap().strip_prefix('#').unwrap();
                    assert!(root.pointer(p).is_some(), "{p}");
                }
                for child in map.values() {
                    refs(child, root);
                }
            }
            Value::Array(a) => {
                for child in a {
                    refs(child, root);
                }
            }
            _ => {}
        }
    }
    refs(&value, &value);
    assert!(
        value["components"]["schemas"]["BrowserTokens"]["properties"]
            .get("refresh_token")
            .is_none()
    );
}

#[test]
fn shared_oidc_contract_is_current_complete_and_separate_from_business_entries() {
    use embedded_idp_axum::openapi::shared_oidc_document;
    let document = shared_oidc_document();
    let rendered = format!("{}\n", document.to_pretty_json().unwrap());
    assert_eq!(
        rendered,
        include_str!("../../../docs/api/shared-oidc-openapi.json"),
        "regenerate using export_shared_oidc"
    );
    let value = serde_json::to_value(document).unwrap();
    let expected = BTreeSet::from([
        ("/.well-known/openid-configuration", "get"),
        ("/oidc/jwks", "get"),
        ("/oidc/authorize", "get"),
        ("/oidc/token", "post"),
        ("/oidc/userinfo", "get"),
        ("/oidc/introspect", "post"),
        ("/oidc/revoke", "post"),
    ]);
    let actual = value["paths"]
        .as_object()
        .unwrap()
        .iter()
        .flat_map(|(p, item)| {
            item.as_object()
                .unwrap()
                .keys()
                .map(|m| (p.as_str(), m.as_str()))
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(actual, expected);
    assert!(value["paths"].get("/auth/logout").is_none());
    let authorize = &value["paths"]["/oidc/authorize"]["get"];
    let params = authorize["parameters"].as_array().unwrap();
    assert!(params
        .iter()
        .any(|p| p["name"] == "code_challenge" && p["required"] == true));
    let method = params
        .iter()
        .find(|p| p["name"] == "code_challenge_method")
        .unwrap();
    assert_eq!(method["schema"]["enum"], json!(["S256"]));
    let token_schema = &value["paths"]["/oidc/token"]["post"]["requestBody"]["content"]
        ["application/x-www-form-urlencoded"]["schema"];
    assert_eq!(
        token_schema["properties"]["grant_type"]["enum"],
        json!(["authorization_code"])
    );
    assert!(token_schema["properties"].get("proof").is_none());
    assert_eq!(
        value["components"]["schemas"]["Discovery"]["properties"]
            ["code_challenge_methods_supported"]["items"]["enum"],
        json!(["S256"])
    );
    assert!(value["components"]["schemas"]["Discovery"]["properties"]
        .get("device_provision_endpoint")
        .is_none());

    // Keep route declaration drift visible for the exact shared protocol
    // routers; the ordinary 17-operation document remains a separate catalog.
    let authorization = include_str!("../src/tenant_oidc_authorization.rs");
    let resource = include_str!("../src/tenant_oidc_resource.rs");
    let auth_routes = authorization
        .split("\npub fn tenant_oidc_authorization_router")
        .nth(1)
        .unwrap()
        .split("#[derive")
        .next()
        .unwrap();
    let resource_routes = resource
        .split("\npub fn tenant_oidc_protocol_resource_router")
        .nth(1)
        .unwrap()
        .split("/// Ordinary logout")
        .next()
        .unwrap();
    let mut declared = BTreeSet::new();
    for source in [auth_routes, resource_routes] {
        for route in source.split(".route(").skip(1) {
            let mut parts = route.splitn(3, '"');
            assert!(parts.next().unwrap().trim().is_empty());
            let path = parts.next().unwrap();
            let method = parts
                .next()
                .unwrap()
                .trim_start()
                .strip_prefix(',')
                .unwrap()
                .trim_start();
            let method = if method.starts_with("get(") {
                "get"
            } else if method.starts_with("post(") {
                "post"
            } else {
                panic!("unexpected method: {method}")
            };
            declared.insert((path, method));
        }
    }
    let protocol = expected
        .iter()
        .copied()
        .filter(|(p, _)| p.starts_with("/oidc/") && *p != "/oidc/jwks")
        .collect::<BTreeSet<_>>();
    assert_eq!(declared, protocol);
    let host = include_str!("../../embedded-idp-app/src/bootstrap.rs");
    assert!(host.contains("\"/.well-known/openid-configuration\""));
    assert!(host.contains("\"/oidc/jwks\""));
    assert!(host.contains("if !oidc_entries.is_empty()"));
    for metadata in [
        r#""response_types_supported":["code"]"#,
        r#""grant_types_supported":["authorization_code"]"#,
        r#""code_challenge_methods_supported":["S256"]"#,
        r#""scopes_supported":["openid","profile","email"]"#,
        r#""token_endpoint_auth_methods_supported":["none","client_secret_basic","client_secret_post"]"#,
    ] {
        assert!(host.contains(metadata), "host discovery drift: {metadata}");
    }
    assert!(host.contains(
        r#""kty":k.key_type,"alg":k.algorithm,"use":k.public_key_use,"n":k.modulus,"e":k.exponent"#
    ));
    assert!(host.contains("public, max-age=300"));
}
struct Auth(bool);
impl TenantAuthenticationService for Auth {
    fn login_capabilities(&self) -> TenantLoginCapabilities {
        TenantLoginCapabilities {
            mode: TenancyMode::Enabled,
            policy: if self.0 {
                LoginTenantPolicy::ChooseAfterAuthentication
            } else {
                LoginTenantPolicy::Fixed {
                    tenant_id: "t1".into(),
                }
            },
        }
    }
    fn login(&self, _: TenantPasswordLogin) -> Result<TenantLoginOutcome, TenantAuthError> {
        Err(TenantAuthError::InvalidCredentials)
    }
    fn list_tenants(
        &self,
        _: SecretString,
        _: AccessPageRequest,
    ) -> Result<AccessPage<SubjectTenant>, TenantAuthError> {
        Err(TenantAuthError::InvalidSelection)
    }
    fn select_tenant(
        &self,
        _: SecretString,
        _: String,
    ) -> Result<TenantLoginSession, TenantAuthError> {
        Err(TenantAuthError::InvalidSelection)
    }
    fn authenticate(&self, _: SecretString) -> Result<AccessActor, TenantAuthError> {
        Err(TenantAuthError::InvalidSession)
    }
    fn begin_switch(&self, _: SecretString) -> Result<TenantSelectionTicket, TenantAuthError> {
        Err(TenantAuthError::InvalidSelection)
    }
}
#[tokio::test]
async fn actual_http_capability_error_and_conditional_mount_match_contract() {
    let doc = serde_json::to_value(business_document()).unwrap();
    for choose in [false, true] {
        let router = tenant_auth_router(Arc::new(Auth(choose)));
        for (method, path, body, status) in [
            ("GET", "/auth/access/capabilities", "", 200),
            (
                "POST",
                "/auth/login",
                r#"{"email":"fixture@example.test","password":"fixture"}"#,
                401,
            ),
            (
                "GET",
                "/auth/tenant-selection/tenants",
                "",
                if choose { 401 } else { 404 },
            ),
        ] {
            let response = router
                .clone()
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri(path)
                        .header("content-type", "application/json")
                        .body(Body::from(body))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status().as_u16(), status);
            if status == 404 {
                continue;
            }
            assert_eq!(response.headers()["cache-control"], "no-store");
            assert_eq!(response.headers()["content-type"], "application/json");
            assert!(doc["paths"][path][method.to_lowercase()]["responses"]
                .get(status.to_string())
                .is_some());
            let value: Value =
                serde_json::from_slice(&to_bytes(response.into_body(), 16384).await.unwrap())
                    .unwrap();
            if status == 200 {
                let properties = doc["components"]["schemas"]["Capabilities"]["properties"]
                    .as_object()
                    .unwrap();
                for (key, field) in value.as_object().unwrap() {
                    assert!(properties.contains_key(key));
                    match properties[key]["type"].as_str().unwrap() {
                        "boolean" => assert!(field.is_boolean()),
                        "integer" => assert!(field.is_u64()),
                        "string" => assert!(field.is_string()),
                        other => panic!("unexpected capability type {other}"),
                    }
                }
                for required in doc["components"]["schemas"]["Capabilities"]["required"]
                    .as_array()
                    .unwrap()
                {
                    assert!(value.get(required.as_str().unwrap()).is_some());
                }
                assert_eq!(value["tenancy_enabled"], true);
                assert_eq!(value["max_page_limit"], 200);
                assert_eq!(
                    value.get("fixed_tenant_id").cloned(),
                    if choose { None } else { Some(json!("t1")) }
                );
            } else {
                assert_eq!(
                    value
                        .as_object()
                        .unwrap()
                        .keys()
                        .cloned()
                        .collect::<BTreeSet<_>>(),
                    BTreeSet::from(["code".into(), "message".into()])
                );
            }
        }
    }
}

#[test]
fn profiles_keep_module_roots_and_apply_conditional_surfaces() {
    use embedded_idp_axum::openapi::business_profile;
    let fixed =
        serde_json::to_value(business_profile("/entry-a", false, false, false, "a")).unwrap();
    assert_eq!(fixed["servers"][0]["url"], "/entry-a");
    assert_eq!(fixed["paths"].as_object().unwrap().len(), 6);
    assert!(fixed["paths"].get("/auth/refresh").is_some());
    let choose =
        serde_json::to_value(business_profile("/entry-b", true, true, false, "entry_b")).unwrap();
    assert_eq!(choose["paths"].as_object().unwrap().len(), 14);
    assert_eq!(
        choose["components"]["securitySchemes"]["RefreshCookie"]["name"],
        "entry_b"
    );
    let registered =
        serde_json::to_value(business_profile("/entry-c", false, true, true, "entry_c")).unwrap();
    assert_eq!(registered["paths"].as_object().unwrap().len(), 14);
    assert!(registered["paths"].get("/auth/register").is_some());
    assert!(registered["paths"]
        .get("/auth/tenant-selection/complete")
        .is_none());
    assert!(registered["paths"]
        .get("/auth/browser/tenant-selection/complete")
        .is_some());
}
struct Lifecycle;
impl TenantRefreshService for Lifecycle {
    fn refresh_ordinary(&self, _: SecretString) -> Result<TenantRefreshOutcome, TenantAuthError> {
        Ok(TenantRefreshOutcome::ReuseDetected {
            tenant_id: "t1".into(),
            session_id: "s1".into(),
        })
    }
}
impl TenantLogoutService for Lifecycle {
    fn logout_session(&self, c: TenantTokenRequest) -> Result<(), TenantAuthError> {
        if c.client_id == "ok" {
            Ok(())
        } else {
            Err(TenantAuthError::InvalidClient)
        }
    }
}
#[tokio::test]
async fn new_lifecycle_routes_match_error_schemas_and_form_contract() {
    let router = embedded_idp_axum::tenant_refresh_router(Arc::new(Lifecycle))
        .merge(embedded_idp_axum::tenant_logout_router(Arc::new(Lifecycle)));
    let doc = serde_json::to_value(business_document()).unwrap();
    for (path, mime, body, status, schema) in [
        (
            "/auth/refresh",
            "application/json",
            r#"{"refresh_token":"fixture"}"#,
            401,
            "Error",
        ),
        (
            "/auth/logout",
            "application/x-www-form-urlencoded",
            "refresh_token=fixture&client_id=bad",
            401,
            "OAuthError",
        ),
        (
            "/auth/logout",
            "application/x-www-form-urlencoded",
            "refresh_token=fixture&client_id=ok",
            200,
            "",
        ),
    ] {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(path)
                    .header("content-type", mime)
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status().as_u16(), status);
        assert_eq!(response.headers()["cache-control"], "no-store");
        assert!(doc["paths"][path]["post"]["requestBody"]["content"]
            .get(mime)
            .is_some());
        let bytes = to_bytes(response.into_body(), 16384).await.unwrap();
        if schema.is_empty() {
            assert!(bytes.is_empty());
            continue;
        }
        let actual: Value = serde_json::from_slice(&bytes).unwrap();
        let props = doc["components"]["schemas"][schema]["properties"]
            .as_object()
            .unwrap();
        assert_eq!(
            actual.as_object().unwrap().keys().collect::<Vec<_>>(),
            props.keys().collect::<Vec<_>>()
        );
        assert!(actual.as_object().unwrap().values().all(Value::is_string));
    }
}

#[test]
fn ordinary_route_declarations_and_contract_catalog_do_not_drift() {
    // Supplemental literal coverage only: conditional routing and wire behavior
    // are exercised above and in browser/host tests. This intentionally handles
    // just these ordinary routers, not arbitrary Rust syntax or legacy APIs.
    let logout = include_str!("../src/tenant_oidc_resource.rs");
    let narrow_logout = logout
        .split("pub fn tenant_logout_router")
        .nth(1)
        .unwrap()
        .split("#[derive")
        .next()
        .unwrap();
    let sources = [
        include_str!("../src/tenant_auth.rs"),
        include_str!("../src/tenant_refresh.rs"),
        include_str!("../src/tenant_registration.rs"),
        include_str!("../src/tenant_self.rs"),
        include_str!("../src/browser_session.rs"),
        narrow_logout,
    ];
    let mut declared = BTreeSet::new();
    for source in sources {
        for route in source.split(".route(").skip(1) {
            let mut parts = route.splitn(3, '"');
            let expression = parts.next().unwrap().trim();
            assert!(
                expression.is_empty() || expression == "&format!(",
                "unexpected route path expression: {expression}"
            );
            let literal = parts.next().expect("ordinary route literal");
            let path = literal.replace("{root}", "/auth/browser");
            let tail = parts.next().expect("route method").trim_start();
            let tail = if expression == "&format!(" {
                tail.strip_prefix(')')
                    .expect("format closing delimiter")
                    .trim_start()
            } else {
                tail
            };
            let method_call = tail
                .strip_prefix(',')
                .expect("route method separator")
                .trim_start();
            let method = if method_call.starts_with("get(") {
                "get"
            } else if method_call.starts_with("post(") {
                "post"
            } else {
                panic!("unexpected route method syntax: {method_call}")
            };
            declared.insert((path, method.to_owned()));
        }
    }
    let doc = serde_json::to_value(business_document()).unwrap();
    let documented = doc["paths"]
        .as_object()
        .unwrap()
        .iter()
        .flat_map(|(path, item)| {
            item.as_object()
                .unwrap()
                .keys()
                .map(|method| (path.clone(), method.clone()))
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        declared, documented,
        "ordinary route method/path declaration or contract coverage changed"
    );
}

// Deliberately limited to the schema forms emitted by this contract (not a
// general JSON Schema validator). Reject unknown keywords so new constraints
// cannot silently escape the wire checks.
fn matches_schema(value: &Value, schema: &Value, doc: &Value) -> bool {
    if let Some(reference) = schema["$ref"].as_str() {
        return matches_schema(
            value,
            doc.pointer(reference.strip_prefix('#').unwrap()).unwrap(),
            doc,
        );
    }
    if let Some(variants) = schema["oneOf"].as_array() {
        return variants
            .iter()
            .filter(|s| matches_schema(value, s, doc))
            .count()
            == 1;
    }
    if let Some(variants) = schema["anyOf"].as_array() {
        return variants.iter().any(|s| matches_schema(value, s, doc));
    }
    for key in schema.as_object().unwrap().keys() {
        assert!(
            [
                "type",
                "properties",
                "required",
                "additionalProperties",
                "items",
                "enum",
                "format",
                "minimum",
                "maximum",
                "description",
                "default"
            ]
            .contains(&key.as_str()),
            "unchecked schema constraint {key}: {schema}"
        );
    }
    if let Some(allowed) = schema["enum"].as_array() {
        if !allowed.contains(value) {
            return false;
        }
    }
    let types = schema["type"]
        .as_array()
        .cloned()
        .unwrap_or_else(|| vec![schema["type"].clone()]);
    if !types.iter().any(|t| match t.as_str().unwrap() {
        "null" => value.is_null(),
        "string" => value.is_string(),
        "boolean" => value.is_boolean(),
        "integer" => value.is_i64() || value.is_u64(),
        "object" => value.is_object(),
        "array" => value.is_array(),
        other => panic!("unchecked type {other}"),
    }) {
        return false;
    }
    if value.is_null() {
        return true;
    }
    if let Some(number) = value.as_f64() {
        if schema["minimum"].as_f64().is_some_and(|n| number < n)
            || schema["maximum"].as_f64().is_some_and(|n| number > n)
        {
            return false;
        }
    }
    if let Some(object) = value.as_object() {
        if schema["required"].as_array().is_some_and(|keys| {
            keys.iter()
                .any(|k| !object.contains_key(k.as_str().unwrap()))
        }) {
            return false;
        }
        let props = schema["properties"].as_object().unwrap();
        // These HTTP projections are intentionally exact even for response
        // structs without serde deny_unknown_fields.
        return object.iter().all(|(key, value)| {
            props
                .get(key)
                .is_some_and(|s| matches_schema(value, s, doc))
        });
    }
    if let Some(items) = value.as_array() {
        return items
            .iter()
            .all(|v| matches_schema(v, &schema["items"], doc));
    }
    true
}

async fn check_wire(router: axum::Router, request: Request<Body>, expected: u16) -> Value {
    let doc = serde_json::to_value(business_document()).unwrap();
    let path = request.uri().path().to_owned();
    let method = request.method().as_str().to_lowercase();
    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status().as_u16(), expected, "{method} {path}");
    assert_eq!(response.headers()["cache-control"], "no-store");
    let contract = &doc["paths"][&path][&method]["responses"][expected.to_string()];
    assert!(
        !contract.is_null(),
        "undocumented status {expected} on {path}"
    );
    let mime = response
        .headers()
        .get("content-type")
        .map(|v| v.to_str().unwrap().split(';').next().unwrap().to_owned());
    let bytes = to_bytes(response.into_body(), 65536).await.unwrap();
    if bytes.is_empty() {
        assert!(
            contract.get("content").is_none(),
            "documented body absent on {path}"
        );
        return Value::Null;
    }
    let mime = mime.expect("response body content type");
    let schema = &contract["content"][&mime]["schema"];
    assert!(
        !schema.is_null(),
        "undocumented media type {mime} on {path}/{expected}"
    );
    let value = if mime == "application/json" {
        serde_json::from_slice(&bytes).unwrap()
    } else {
        json!(std::str::from_utf8(&bytes).unwrap())
    };
    assert!(
        matches_schema(&value, schema, &doc),
        "{path}: {value} does not match {schema}"
    );
    value
}

async fn check_shared_wire(
    router: axum::Router,
    request: Request<Body>,
    doc: &Value,
    expected: u16,
) -> Value {
    let path = request.uri().path().to_owned();
    let method = request.method().as_str().to_lowercase();
    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status().as_u16(), expected, "{method} {path}");
    assert_eq!(response.headers()["cache-control"], "no-store");
    let contract = &doc["paths"][&path][&method]["responses"][expected.to_string()];
    assert!(!contract.is_null(), "undocumented {expected} on {path}");
    let mime = response
        .headers()
        .get("content-type")
        .map(|v| v.to_str().unwrap().split(';').next().unwrap().to_owned());
    let bytes = to_bytes(response.into_body(), 65536).await.unwrap();
    if bytes.is_empty() {
        assert!(
            contract.get("content").is_none(),
            "unexpected empty body contract on {path}"
        );
        return Value::Null;
    }
    let mime = mime.expect("response body content type");
    let schema = &contract["content"][&mime]["schema"];
    assert!(
        !schema.is_null(),
        "undocumented media type {mime} for {path}"
    );
    let actual = if mime == "application/json" {
        serde_json::from_slice(&bytes).unwrap()
    } else {
        json!(std::str::from_utf8(&bytes).unwrap())
    };
    assert!(
        matches_schema(&actual, schema, doc),
        "{path}: {actual} does not match {schema}"
    );
    actual
}

struct SharedOidc;
impl TenantOidcAuthorizationService for SharedOidc {
    fn authenticate(&self, access: SecretString) -> Result<AccessActor, TenantAuthError> {
        if access.expose_secret() == "good" {
            Ok(AccessActor {
                tenant_id: "t1".into(),
                subject_id: "u1".into(),
                session_id: "s1".into(),
            })
        } else {
            Err(TenantAuthError::InvalidSession)
        }
    }
    fn authorize(
        &self,
        _: AccessActor,
        request: TenantAuthorizationRequest,
    ) -> Result<TenantAuthorizationResult, TenantAuthError> {
        Ok(TenantAuthorizationResult {
            code: SecretString::new("authorization-code"),
            tenant_id: "t1".into(),
            redirect_uri: request.redirect_uri,
            state: request.state,
            expires_at: std::time::SystemTime::now() + std::time::Duration::from_secs(60),
        })
    }
    fn exchange(
        &self,
        command: TenantCodeExchange,
        _: Option<TenantAuthenticationProof>,
    ) -> Result<TenantCodeExchangeResult, TenantAuthError> {
        if command.code_verifier.is_none() {
            return Err(TenantAuthError::InvalidAuthorization);
        }
        Ok(TenantCodeExchangeResult {
            login: successful_session(),
            id_token: Some(SecretString::new("id-fixture")),
            scope: "openid profile email".into(),
        })
    }
}
impl TenantOidcResourceService for SharedOidc {
    fn user_info(&self, access: SecretString) -> Result<TenantUserInfo, TenantAuthError> {
        if access.expose_secret() != "good" {
            return Err(TenantAuthError::InvalidSession);
        }
        Ok(TenantUserInfo {
            tenant_id: "t1".into(),
            subject_account_id: "u1".into(),
            client_id: "c1".into(),
            email: Some("user@example.test".into()),
            display_name: Some("Fixture User".into()),
        })
    }
    fn introspect_token(
        &self,
        request: TenantTokenRequest,
    ) -> Result<Option<TenantTokenInfo>, TenantAuthError> {
        if request.token.expose_secret() == "inactive" {
            return Ok(None);
        }
        let now = std::time::SystemTime::now();
        Ok(Some(TenantTokenInfo {
            tenant_id: "t1".into(),
            subject_account_id: "u1".into(),
            session_id: "s1".into(),
            client_id: "c1".into(),
            scope: Some("openid profile email".into()),
            token_type: TenantTokenType::Access,
            issued_at: now - std::time::Duration::from_secs(1),
            expires_at: now + std::time::Duration::from_secs(60),
        }))
    }
    fn revoke_token(&self, _: TenantTokenRequest) -> Result<(), TenantAuthError> {
        Ok(())
    }
    fn logout(&self, _: TenantTokenRequest) -> Result<(), TenantAuthError> {
        Err(TenantAuthError::InvalidClient)
    }
}

#[tokio::test]
async fn shared_oidc_wire_responses_match_contract() {
    use embedded_idp_axum::{
        tenant_oidc_authorization_router, tenant_oidc_protocol_resource_router,
        TenantOidcHttpConfig,
    };
    let service = Arc::new(SharedOidc);
    let authorization: Arc<dyn TenantOidcAuthorizationService> = service.clone();
    let resources: Arc<dyn TenantOidcResourceService> = service;
    let router = tenant_oidc_authorization_router(
        authorization,
        TenantOidcHttpConfig::new("audience", "/oidc/token").unwrap(),
    )
    .merge(tenant_oidc_protocol_resource_router(resources));
    let doc = serde_json::to_value(embedded_idp_axum::openapi::shared_oidc_document()).unwrap();

    let authorize = Request::get("/oidc/authorize?response_type=code&client_id=c1&redirect_uri=https%3A%2F%2Fclient.test%2Fcb&state=st&code_challenge=challenge&code_challenge_method=S256")
        .header("authorization", "Bearer good").body(Body::empty()).unwrap();
    let redirected = router.clone().oneshot(authorize).await.unwrap();
    assert_eq!(redirected.status().as_u16(), 307);
    assert_eq!(redirected.headers()["cache-control"], "no-store");
    assert!(redirected.headers()["location"]
        .to_str()
        .unwrap()
        .contains("code=authorization-code"));
    assert_eq!(
        doc["paths"]["/oidc/authorize"]["get"]["responses"]
            .get("307")
            .is_some(),
        true
    );
    assert!(
        doc["paths"]["/oidc/jwks"]["get"]["responses"]["200"]["headers"]
            .get("ETag")
            .is_some()
    );

    for (body, status, client_auth) in [
        (
            "grant_type=authorization_code&code=c&redirect_uri=https%3A%2F%2Fclient.test%2Fcb&client_id=c1&code_verifier=verifier",
            200,
            None,
        ),
        (
            "grant_type=refresh_token&code=c&redirect_uri=https%3A%2F%2Fclient.test%2Fcb&client_id=c1",
            400,
            None,
        ),
        (
            "grant_type=authorization_code&code=c&redirect_uri=https%3A%2F%2Fclient.test%2Fcb",
            401,
            Some("Basic eA=="),
        ),
    ] {
        let mut request = Request::post("/oidc/token")
            .header("content-type", "application/x-www-form-urlencoded");
        if let Some(value) = client_auth {
            request = request.header("authorization", value);
        }
        check_shared_wire(
            router.clone(),
            request.body(Body::from(body)).unwrap(),
            &doc,
            status,
        )
        .await;
    }
    check_shared_wire(
        router.clone(),
        Request::post("/oidc/token")
            .header("content-type", "text/plain")
            .body(Body::from("grant_type=authorization_code"))
            .unwrap(),
        &doc,
        415,
    )
    .await;
    check_shared_wire(
        router.clone(),
        Request::post("/oidc/token")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from("grant_type=authorization_code&code=c&redirect_uri=https%3A%2F%2Fclient.test%2Fcb&client_id=c1"))
            .unwrap(),
        &doc,
        400,
    )
    .await;
    check_shared_wire(
        router.clone(),
        Request::post("/oidc/token")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from("x".repeat(16_385)))
            .unwrap(),
        &doc,
        413,
    )
    .await;
    let oversized_authorize = format!(
        "/oidc/authorize?response_type=code&client_id=c1&redirect_uri=https%3A%2F%2Fclient.test%2Fcb&code_challenge={}&code_challenge_method=S256",
        "a".repeat(16_300)
    );
    check_shared_wire(
        router.clone(),
        Request::get(oversized_authorize)
            .header("authorization", "Bearer good")
            .body(Body::empty())
            .unwrap(),
        &doc,
        414,
    )
    .await;
    check_shared_wire(
        router.clone(),
        Request::get("/oidc/userinfo")
            .header("authorization", "Bearer good")
            .body(Body::empty())
            .unwrap(),
        &doc,
        200,
    )
    .await;
    check_shared_wire(
        router.clone(),
        Request::get("/oidc/userinfo").body(Body::empty()).unwrap(),
        &doc,
        401,
    )
    .await;
    for (token, expected) in [("active", 200), ("inactive", 200)] {
        check_shared_wire(
            router.clone(),
            Request::post("/oidc/introspect")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(format!("token={token}&client_id=c1")))
                .unwrap(),
            &doc,
            expected,
        )
        .await;
    }
    for (mime, body, status) in [
        ("text/plain", "token=x", 415),
        (
            "application/x-www-form-urlencoded",
            "token=x&unknown=y&client_id=c1",
            422,
        ),
    ] {
        check_shared_wire(
            router.clone(),
            Request::post("/oidc/introspect")
                .header("content-type", mime)
                .body(Body::from(body.to_owned()))
                .unwrap(),
            &doc,
            status,
        )
        .await;
    }
    check_shared_wire(
        router.clone(),
        Request::post("/oidc/introspect")
            .header("content-type", "application/x-www-form-urlencoded")
            .header("x-embedded-idp-tenant-id", "t2")
            .body(Body::from("token=x&client_id=c1"))
            .unwrap(),
        &doc,
        400,
    )
    .await;
    check_shared_wire(
        router.clone(),
        Request::post("/oidc/introspect")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(
                "token=active&token_type_hint=unknown&client_id=c1",
            ))
            .unwrap(),
        &doc,
        200,
    )
    .await;
    check_shared_wire(
        router.clone(),
        Request::post("/oidc/introspect")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from("x".repeat(16_385)))
            .unwrap(),
        &doc,
        413,
    )
    .await;
    let revoked = check_shared_wire(
        router,
        Request::post("/oidc/revoke")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from("token=t&client_id=c1"))
            .unwrap(),
        &doc,
        200,
    )
    .await;
    assert!(revoked.is_null());
}

struct Successful;
fn successful_session() -> TenantLoginSession {
    use embedded_idp_core::{AccessTokenPurpose, IssuedTokenBundle, SessionStatus};
    use std::time::{Duration, SystemTime};
    let now = SystemTime::now();
    TenantLoginSession {
        session: TenantSession {
            purpose: AccessTokenPurpose::Business,
            tenant_id: "t1".into(),
            id: "s1".into(),
            account_id: "u1".into(),
            client_id: "c1".into(),
            device_id: None,
            scope: None,
            authenticated_at: now,
            status: SessionStatus::Active,
            created_at: now,
            expires_at: now + Duration::from_secs(300),
            refresh_token_version: 1,
        },
        tokens: IssuedTokenBundle {
            access_token: SecretString::new("access-fixture"),
            refresh_token: SecretString::new("refresh-fixture"),
            access_expires_at: now + Duration::from_secs(60),
            refresh_expires_at: now + Duration::from_secs(300),
            refresh_token_version: 1,
        },
    }
}
fn successful_ticket() -> TenantSelectionTicket {
    let now = std::time::SystemTime::now();
    TenantSelectionTicket {
        ticket: SecretString::new("ticket-fixture"),
        issued_at: now,
        expires_at: now + std::time::Duration::from_secs(60),
    }
}
impl TenantAuthenticationService for Successful {
    fn login_capabilities(&self) -> TenantLoginCapabilities {
        Auth(true).login_capabilities()
    }
    fn login(&self, command: TenantPasswordLogin) -> Result<TenantLoginOutcome, TenantAuthError> {
        Ok(if command.email == "choose@example.test" {
            TenantLoginOutcome::SelectionRequired(successful_ticket())
        } else {
            TenantLoginOutcome::Authenticated(successful_session())
        })
    }
    fn authenticate(&self, _: SecretString) -> Result<AccessActor, TenantAuthError> {
        Ok(AccessActor {
            tenant_id: "t1".into(),
            subject_id: "u1".into(),
            session_id: "s1".into(),
        })
    }
    fn select_tenant(
        &self,
        _: SecretString,
        _: String,
    ) -> Result<TenantLoginSession, TenantAuthError> {
        Ok(successful_session())
    }
    fn begin_switch(&self, _: SecretString) -> Result<TenantSelectionTicket, TenantAuthError> {
        Ok(successful_ticket())
    }
    fn list_tenants(
        &self,
        _: SecretString,
        _: AccessPageRequest,
    ) -> Result<AccessPage<SubjectTenant>, TenantAuthError> {
        Ok(AccessPage {
            items: vec![SubjectTenant {
                tenant: Tenant {
                    id: "t1".into(),
                    name: "Tenant".into(),
                    status: TenantStatus::Active,
                    allow_registration: true,
                },
                membership: TenantMembership {
                    tenant_id: "t1".into(),
                    subject_id: "u1".into(),
                    status: MembershipStatus::Active,
                    joined_at: std::time::SystemTime::now(),
                    version: 1,
                },
            }],
            next_cursor: Some(AccessCursor {
                version: 2,
                scope: AccessListScope::SubjectTenants {
                    subject_id: "u1".into(),
                },
                after: vec!["t1".into()],
                sort_order: None,
            }),
            has_more: true,
        })
    }
}
impl TenantRefreshService for Successful {
    fn refresh_ordinary(&self, _: SecretString) -> Result<TenantRefreshOutcome, TenantAuthError> {
        let result = successful_session();
        Ok(TenantRefreshOutcome::Rotated {
            session: result.session,
            tokens: embedded_idp_core::ProofBoundTokenResult {
                access_token: embedded_idp_core::IssuedAccessToken {
                    token: result.tokens.access_token,
                    expires_at: result.tokens.access_expires_at,
                },
                refresh_token: result.tokens.refresh_token,
                refresh_expires_at: result.tokens.refresh_expires_at,
                refresh_token_version: 1,
            },
        })
    }
}
impl BrowserSessionService for Successful {
    fn browser_purpose(&self) -> embedded_idp_core::AccessTokenPurpose {
        embedded_idp_core::AccessTokenPurpose::Business
    }
    fn browser_login(&self, c: TenantPasswordLogin) -> Result<TenantLoginOutcome, TenantAuthError> {
        self.login(c)
    }
    fn browser_select(
        &self,
        t: SecretString,
        id: String,
    ) -> Result<TenantLoginSession, TenantAuthError> {
        self.select_tenant(t, id)
    }
    fn browser_refresh(
        &self,
        t: SecretString,
        _: Option<BrowserSessionIdentity>,
    ) -> Result<TenantRefreshOutcome, TenantAuthError> {
        self.refresh_ordinary(t)
    }
    fn browser_logout(
        &self,
        _: SecretString,
        _: Option<BrowserSessionIdentity>,
    ) -> Result<(), TenantAuthError> {
        Ok(())
    }
}
impl AccessQueryService for Successful {
    fn list_subject_roles(
        &self,
        _: &str,
        _: &str,
        _: &str,
        _: AccessPageRequest,
    ) -> Result<AccessPage<Role>, AccessError> {
        Ok(AccessPage {
            items: vec![Role {
                tenant_id: "t1".into(),
                business_id: "f_01".into(),
                id: "r1".into(),
                key: "reader".into(),
                name: "Reader".into(),
                version: 1,
                status: RoleStatus::Active,
                kind: RoleKind::Business,
                created_at: std::time::SystemTime::now(),
            }],
            next_cursor: None,
            has_more: false,
        })
    }
    fn list_role_permissions(
        &self,
        _: &str,
        _: &str,
        _: &str,
        _: AccessPageRequest,
    ) -> Result<AccessPage<PermissionDefinition>, AccessError> {
        unreachable!()
    }
    fn list_subject_tenants(
        &self,
        _: &str,
        _: &LoginTenantPolicy,
        _: AccessPageRequest,
    ) -> Result<AccessPage<SubjectTenant>, AccessError> {
        unreachable!()
    }
}
impl TenantRegistrationService for Successful {
    fn tenancy_mode(&self) -> TenancyMode {
        TenancyMode::Enabled
    }
    fn register_account(
        &self,
        c: RegisterTenantAccountCommand,
    ) -> Result<TenantRegistrationResult, TenantRegistrationError> {
        Ok(TenantRegistrationResult {
            tenant_id: c.tenant_id,
            account_id: "u1".into(),
            email: c.email,
            verification_code: SecretString::new("fixture"),
            verification_expires_at: std::time::SystemTime::now(),
        })
    }
    fn verify_email(
        &self,
        c: VerifyTenantEmailCommand,
    ) -> Result<TenantEmailVerificationResult, TenantRegistrationError> {
        Ok(TenantEmailVerificationResult {
            tenant_id: c.tenant_id,
            account_id: "u1".into(),
        })
    }
    fn resend_verification(
        &self,
        _: ResendTenantVerificationCommand,
    ) -> Result<Option<TenantRegistrationResult>, TenantRegistrationError> {
        Ok(None)
    }
}
impl embedded_idp_email::VerificationEmailService for Successful {
    fn send_verification_email(
        &self,
        _: embedded_idp_email::VerificationEmailRequest,
    ) -> Result<(), embedded_idp_email::EmailSendError> {
        Ok(())
    }
}
fn complete_router() -> axum::Router {
    use embedded_idp_axum::*;
    let service = Arc::new(Successful);
    tenant_auth_router(service.clone())
        .merge(tenant_refresh_router(service.clone()))
        .merge(tenant_logout_router(Arc::new(Lifecycle)))
        .merge(tenant_self_router(service.clone(), service.clone()))
        .merge(
            tenant_registration_router(
                service.clone(),
                LoginTenantPolicy::Fixed {
                    tenant_id: "t1".into(),
                },
                service.clone(),
            )
            .unwrap(),
        )
        .merge(
            browser_session_router(
                service,
                BrowserSessionHttpConfig::new(
                    "https://entry.test",
                    "entry_refresh",
                    "/auth/browser",
                    embedded_idp_core::AccessTokenPurpose::Business,
                )
                .unwrap(),
            )
            .unwrap(),
        )
}
#[tokio::test]
async fn every_operation_success_matches_recursive_wire_schema() {
    let router = complete_router();
    let identity = r#"{"expected_session":{"tenant_id":"t1","account_id":"u1","session_id":"s1","client_id":"c1"}}"#;
    for (method, path, body, status) in [
        (
            "POST",
            "/auth/login",
            r#"{"email":"x@example.test","password":"fixture"}"#,
            200,
        ),
        (
            "POST",
            "/auth/login",
            r#"{"email":"choose@example.test","password":"fixture"}"#,
            200,
        ),
        ("GET", "/auth/access/capabilities", "", 200),
        ("GET", "/auth/session", "", 200),
        (
            "POST",
            "/auth/refresh",
            r#"{"refresh_token":"fixture"}"#,
            200,
        ),
        (
            "POST",
            "/auth/logout",
            "refresh_token=fixture&client_id=ok",
            200,
        ),
        ("GET", "/auth/tenant-selection/tenants", "", 200),
        ("POST", "/auth/me/tenant-selection", "", 200),
        (
            "POST",
            "/auth/tenant-selection/complete",
            r#"{"tenant_id":"t1"}"#,
            200,
        ),
        ("GET", "/auth/me/roles?business_id=f_01", "", 200),
        (
            "POST",
            "/auth/browser/login",
            r#"{"email":"x@example.test","password":"fixture"}"#,
            200,
        ),
        (
            "POST",
            "/auth/browser/login",
            r#"{"email":"choose@example.test","password":"fixture"}"#,
            200,
        ),
        (
            "POST",
            "/auth/browser/tenant-selection/complete",
            r#"{"tenant_id":"t1"}"#,
            200,
        ),
        ("POST", "/auth/browser/restore", "{}", 200),
        ("POST", "/auth/browser/refresh", identity, 200),
        ("POST", "/auth/browser/logout", "{}", 204),
        (
            "POST",
            "/auth/register",
            r#"{"tenant_id":"t1","email":"x@example.test","password":"fixture"}"#,
            202,
        ),
        (
            "POST",
            "/auth/verify-email",
            r#"{"tenant_id":"t1","email":"x@example.test","verification_code":"fixture"}"#,
            200,
        ),
        (
            "POST",
            "/auth/resend-verification",
            r#"{"tenant_id":"t1","email":"x@example.test"}"#,
            202,
        ),
    ] {
        let mut request = Request::builder().method(method).uri(path).header(
            "content-type",
            if path == "/auth/logout" {
                "application/x-www-form-urlencoded"
            } else {
                "application/json"
            },
        );
        if path != "/auth/logout" {
            request = request.header(
                "authorization",
                if path.contains("/tenant-selection/") {
                    "TenantSelection fixture"
                } else {
                    "Bearer fixture"
                },
            );
        }
        if path.contains("/browser/") {
            request = request
                .header("origin", "https://entry.test")
                .header("x-embedded-idp-browser", "1")
                .header("cookie", "entry_refresh=fixture");
        }
        check_wire(
            router.clone(),
            request.body(Body::from(body)).unwrap(),
            status,
        )
        .await;
    }
}
#[tokio::test]
async fn extractor_failures_have_documented_status_and_media() {
    let router = complete_router();
    for path in ["/auth/me/roles", "/auth/tenant-selection/tenants?limit=bad"] {
        check_wire(
            router.clone(),
            Request::get(path).body(Body::empty()).unwrap(),
            400,
        )
        .await;
    }
    for (path, mime, body, status) in [
        ("/auth/refresh", "text/plain", "{}".to_owned(), 415),
        ("/auth/refresh", "application/json", "x".repeat(16385), 413),
        ("/auth/refresh", "application/json", "{}".to_owned(), 422),
        ("/auth/login", "application/json", "{".to_owned(), 400),
        (
            "/auth/logout",
            "application/x-www-form-urlencoded",
            "unknown=x".to_owned(),
            422,
        ),
        (
            "/auth/browser/refresh",
            "application/json",
            "{}".to_owned(),
            400,
        ),
    ] {
        check_wire(
            router.clone(),
            Request::post(path)
                .header("content-type", mime)
                .header("origin", "https://entry.test")
                .header("x-embedded-idp-browser", "1")
                .body(Body::from(body))
                .unwrap(),
            status,
        )
        .await;
    }
    check_wire(
        router,
        Request::post("/auth/browser/login")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"email":"x@example.test","password":"fixture"}"#,
            ))
            .unwrap(),
        403,
    )
    .await;
}

#[tokio::test]
async fn every_profile_operation_matches_actual_conditional_router() {
    use embedded_idp_axum::*;
    let catalog = serde_json::to_value(business_document()).unwrap();
    for choose in [false, true] {
        for browser in [false, true] {
            for registration in [false, true] {
                if choose && registration {
                    continue;
                } // rejected host configuration
                let service = Arc::new(Successful);
                let auth = Arc::new(Auth(choose));
                let mut router = tenant_auth_router(auth.clone())
                    .merge(tenant_refresh_router(service.clone()))
                    .merge(tenant_logout_router(Arc::new(Lifecycle)))
                    .merge(tenant_self_router(auth, service.clone()));
                if browser {
                    router = router.merge(
                        browser_session_router(
                            service.clone(),
                            BrowserSessionHttpConfig::new(
                                "https://entry.test",
                                "entry_refresh",
                                "/auth/browser",
                                embedded_idp_core::AccessTokenPurpose::Business,
                            )
                            .unwrap(),
                        )
                        .unwrap(),
                    );
                }
                if registration {
                    router = router.merge(
                        tenant_registration_router(
                            service.clone(),
                            LoginTenantPolicy::Fixed {
                                tenant_id: "t1".into(),
                            },
                            service,
                        )
                        .unwrap(),
                    );
                }
                let profile = serde_json::to_value(openapi::business_profile(
                    "/entry",
                    choose,
                    browser,
                    registration,
                    "entry_refresh",
                ))
                .unwrap();
                let router = axum::Router::new().nest("/entry", router);
                for (path, item) in catalog["paths"].as_object().unwrap() {
                    let method = item
                        .as_object()
                        .unwrap()
                        .keys()
                        .next()
                        .unwrap()
                        .to_uppercase();
                    let response = router
                        .clone()
                        .oneshot(
                            Request::builder()
                                .method(method.as_str())
                                .uri(format!("/entry{path}"))
                                .header("content-type", "application/json")
                                .body(Body::from("{}"))
                                .unwrap(),
                        )
                        .await
                        .unwrap();
                    assert_eq!(
                        response.status().as_u16() != 404,
                        profile["paths"].get(path).is_some(),
                        "choose={choose} browser={browser} registration={registration}: {path}"
                    );
                }
            }
        }
    }
}

#[tokio::test]
async fn security_combinations_and_challenges_are_preserved() {
    let doc = serde_json::to_value(business_document()).unwrap();
    assert_eq!(
        doc["paths"]["/auth/logout"]["post"]["security"],
        json!([{"Basic":[]},{}])
    );
    assert_eq!(
        doc["paths"]["/auth/browser/refresh"]["post"]["security"],
        json!([{"Origin":[],"BrowserHeader":[],"RefreshCookie":[]}])
    );
    assert_eq!(
        doc["paths"]["/auth/browser/tenant-selection/complete"]["post"]["security"],
        json!([{"Origin":[],"BrowserHeader":[],"TenantSelection":[]}])
    );
    let router = complete_router();
    for (origin, marker) in [
        (None, Some("1")),
        (Some("https://entry.test"), None),
        (Some("https://other.test"), Some("1")),
    ] {
        let mut request =
            Request::post("/auth/browser/login").header("content-type", "application/json");
        if let Some(origin) = origin {
            request = request.header("origin", origin);
        }
        if let Some(marker) = marker {
            request = request.header("x-embedded-idp-browser", marker);
        }
        check_wire(
            router.clone(),
            request
                .body(Body::from(
                    r#"{"email":"x@example.test","password":"fixture"}"#,
                ))
                .unwrap(),
            403,
        )
        .await;
    }
    let response = router
        .oneshot(
            Request::post("/auth/logout")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from("refresh_token=fixture&client_id=bad"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 401);
    assert_eq!(
        response.headers()["www-authenticate"],
        "Basic realm=\"idp\""
    );
    assert!(
        doc["paths"]["/auth/logout"]["post"]["responses"]["401"]["headers"]
            .get("WWW-Authenticate")
            .is_some()
    );
}
