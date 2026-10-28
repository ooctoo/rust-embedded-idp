#![cfg(feature = "openapi")]
use axum::{
    body::{to_bytes, Body},
    http::Request,
    Router,
};
use embedded_idp_axum::{
    openapi::{
        business_document, business_profile, business_profile_with_account_security,
        business_profile_with_recovery,
    },
    tenant_auth_router,
};
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
    for path in ["/auth/login", "/auth/browser/login", "/auth/register"] {
        assert_eq!(
            value["paths"][path]["post"]["responses"]["503"]["content"]["application/json"]
                ["schema"]["$ref"],
            "#/components/schemas/Error",
            "conditional password work capacity response missing for {path}"
        );
    }
    let mut ids = BTreeSet::new();
    let inventory = include_str!("../../../docs/api/route-inventory.md");
    for (path, item) in value["paths"].as_object().unwrap() {
        assert!(inventory.contains(path), "inventory missing {path}");
        for (_, op) in item.as_object().unwrap() {
            assert!(ids.insert(op["operationId"].as_str().unwrap()));
        }
    }
    assert_eq!(ids.len(), 33);
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
fn password_change_contract_is_conditional_and_matches_http_error_boundary() {
    let value = serde_json::to_value(business_document()).unwrap();
    let paths = [
        (
            "/auth/security/password",
            "businessSelfPasswordChange",
            "SelfPasswordChange",
        ),
        (
            "/auth/security/password/result",
            "businessSelfPasswordChangeResult",
            "SelfPasswordChangeResult",
        ),
        (
            "/auth/browser/security/password",
            "browserSelfPasswordChange",
            "BrowserSelfPasswordChange",
        ),
        (
            "/auth/browser/security/password/result",
            "browserSelfPasswordChangeResult",
            "SelfPasswordChangeResult",
        ),
    ];
    for (path, id, request_schema) in paths {
        let operation = &value["paths"][path]["post"];
        assert_eq!(operation["operationId"], id);
        assert_eq!(
            operation["requestBody"]["content"]["application/json"]["schema"]["$ref"],
            format!("#/components/schemas/{request_schema}")
        );
        assert_eq!(
            operation["responses"]["200"]["content"]["application/json"]["schema"]["$ref"],
            "#/components/schemas/SelfPasswordChangeCompleted"
        );
        for code in ["400", "401", "403", "409", "413", "500", "503"] {
            assert_eq!(
                operation["responses"][code]["content"]["application/json"]["schema"]["$ref"],
                "#/components/schemas/Error",
                "{path} {code}"
            );
            assert_eq!(
                operation["responses"][code]["headers"]["Cache-Control"]["schema"]["enum"][0],
                "no-store"
            );
        }
        for code in ["415", "422"] {
            assert!(
                operation["responses"].get(code).is_none(),
                "{path} must normalize JSON rejection to 400"
            );
        }
        if path.contains("/browser/") {
            for response in operation["responses"].as_object().unwrap().values() {
                assert!(response["headers"].get("Set-Cookie").is_none());
            }
        }
        assert!(operation["description"]
            .as_str()
            .unwrap()
            .contains("none sets or clears cookies"));
    }
    let command = &value["components"]["schemas"]["SelfPasswordChange"];
    assert_eq!(command["additionalProperties"], false);
    assert_eq!(
        command["required"],
        json!([
            "current_password",
            "new_password",
            "operation_id",
            "receipt_secret"
        ])
    );
    assert_eq!(
        command["properties"]["operation_id"]["description"],
        "Canonical lowercase non-nil UUID."
    );
    assert_eq!(command["properties"]["receipt_secret"]["minLength"], 43);
    assert_eq!(command["properties"]["receipt_secret"]["maxLength"], 43);
    let browser_command = &value["components"]["schemas"]["BrowserSelfPasswordChange"];
    assert_eq!(
        browser_command["properties"]["expected"]["$ref"],
        "#/components/schemas/SelfSessionIdentity"
    );
    let result = &value["components"]["schemas"]["SelfPasswordChangeResult"];
    assert_eq!(
        result["required"],
        json!(["operation_id", "receipt_secret"])
    );
    assert!(result["properties"].get("current_password").is_none());
    assert!(result["properties"].get("new_password").is_none());

    let legacy = serde_json::to_value(business_profile("/", false, true, false, "cookie")).unwrap();
    assert!(legacy["paths"].get("/auth/security/password").is_none());
    let security_without_browser = serde_json::to_value(business_profile_with_account_security(
        "/", false, false, false, true, "cookie",
    ))
    .unwrap();
    assert!(security_without_browser["paths"]
        .get("/auth/security/password")
        .is_some());
    assert!(security_without_browser["paths"]
        .get("/auth/security/password/result")
        .is_some());
    assert!(security_without_browser["paths"]
        .get("/auth/browser/security/password")
        .is_none());
    let security_with_browser = serde_json::to_value(business_profile_with_account_security(
        "/", false, true, false, true, "cookie",
    ))
    .unwrap();
    assert!(security_with_browser["paths"]
        .get("/auth/browser/security/password")
        .is_some());
    assert!(security_with_browser["paths"]
        .get("/auth/browser/security/password/result")
        .is_some());
}

#[test]
fn self_session_contract_matches_http_routes_and_exact_projections() {
    let document = business_document();
    let value = serde_json::to_value(document).unwrap();
    let business = &value["paths"]["/auth/security/sessions"]["get"];
    assert_eq!(business["operationId"], "businessSelfSessions");
    assert_eq!(business["security"], json!([{"Bearer":[]} ]));
    assert_eq!(
        business["parameters"]
            .as_array()
            .unwrap()
            .iter()
            .map(|parameter| parameter["name"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["limit", "cursor"]
    );
    assert_eq!(business["parameters"][0]["schema"]["minimum"], 1);
    assert_eq!(business["parameters"][0]["schema"]["maximum"], 50);
    assert_eq!(business["parameters"][1]["schema"]["maxLength"], 1024);
    assert!(business["description"]
        .as_str()
        .unwrap()
        .contains("scope=null"));
    assert!(business["description"]
        .as_str()
        .unwrap()
        .contains("including delegated scope-bearing sessions"));

    let browser = &value["paths"]["/auth/browser/security/sessions"]["post"];
    assert_eq!(browser["operationId"], "browserSelfSessions");
    assert_eq!(
        browser["security"],
        json!([{"Origin":[],"BrowserHeader":[],"RefreshCookie":[]}])
    );
    assert_eq!(
        browser["requestBody"]["content"]["application/json"]["schema"]["$ref"],
        "#/components/schemas/SelfSessionRead"
    );
    assert_eq!(
        value["components"]["schemas"]["SelfSessionRead"]["required"],
        json!(["expected"])
    );
    assert_eq!(
        value["components"]["schemas"]["SelfSessionRead"]["additionalProperties"],
        false
    );
    assert_eq!(
        value["components"]["schemas"]["SelfSessionRead"]["properties"]["limit"]["maximum"],
        50
    );
    assert_eq!(
        value["components"]["schemas"]["SelfSessionRead"]["properties"]["cursor"]["maxLength"],
        1024
    );

    let item = &value["components"]["schemas"]["SelfSession"];
    let item_fields = item["properties"]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    assert_eq!(
        item_fields,
        BTreeSet::from([
            "tenant_id",
            "session_id",
            "client_id",
            "purpose",
            "device_id",
            "created_at",
            "expires_at",
            "status",
            "current"
        ])
    );
    assert_eq!(item["required"].as_array().unwrap().len(), 9);
    assert_eq!(
        item["properties"]["device_id"]["type"],
        json!(["string", "null"])
    );
    for timestamp in ["created_at", "expires_at"] {
        assert_eq!(item["properties"][timestamp]["type"], "integer");
        assert_eq!(item["properties"][timestamp]["minimum"], 0);
    }
    assert_eq!(
        value["components"]["schemas"]["SelfSessionPurpose"]["enum"],
        json!(["business", "management"])
    );
    assert_eq!(
        value["components"]["schemas"]["SelfSessionStatus"]["enum"],
        json!(["active", "expired"])
    );
    assert!(value["components"]["schemas"]["SelfSession"]
        .get("scope")
        .is_none());
    assert!(value["components"]["schemas"]["SelfSession"]
        .get("refresh_token")
        .is_none());

    for operation in [business, browser] {
        assert_eq!(
            operation["responses"]["200"]["content"]["application/json"]["schema"]["$ref"],
            "#/components/schemas/SelfSessionPage"
        );
        for response in operation["responses"].as_object().unwrap().values() {
            assert_eq!(
                response["headers"]["Cache-Control"]["schema"]["enum"][0],
                "no-store"
            );
        }
    }
    assert_eq!(
        browser["responses"]["413"]["content"]["text/plain"]["schema"]["type"],
        "string"
    );
    assert!(browser["responses"]["200"]["headers"]
        .get("Set-Cookie")
        .is_none());
    assert!(value["paths"]
        .get("/admin/auth/security/sessions")
        .is_none());
    assert!(value["paths"]
        .get("/admin/auth/browser/security/sessions")
        .is_none());

    let bearer_source = include_str!("../src/self_sessions.rs");
    assert!(bearer_source.contains("/auth/security/sessions"));
    assert!(bearer_source.contains("/admin/auth/security/sessions"));
    let browser_source = include_str!("../src/browser_session/self_sessions.rs");
    assert!(browser_source.contains("/security/sessions"));
    assert!(browser_source.contains("authenticate_self_security_browser"));
    assert!(browser_source.contains("DefaultBodyLimit::max(AUTH_DEVICE_BODY_LIMIT_BYTES)"));
    let inventory = include_str!("../../../docs/api/route-inventory.md");
    let dedicated = include_str!("../../../docs/api/self-session-contract.md");
    for route in [
        "/auth/security/sessions",
        "/auth/browser/security/sessions",
        "/admin/auth/security/sessions",
        "/admin/auth/browser/security/sessions",
    ] {
        assert!(
            dedicated.contains(route),
            "dedicated contract missing {route}"
        );
    }
    assert!(inventory.contains("/admin/auth/security/sessions"));
    assert!(inventory.contains("/admin/auth/browser/security/sessions"));
}

#[test]
fn self_session_revocation_contract_projects_capability_results_and_no_cookie_mutation() {
    let value = serde_json::to_value(business_document()).unwrap();
    for (path, id, schema, security) in [
        (
            "/auth/security/sessions/revoke",
            "businessRevokeSelfSession",
            "SelfSessionRevoke",
            json!([{"Bearer":[]} ]),
        ),
        (
            "/auth/security/sessions/revoke/result",
            "businessSelfSessionRevokeResult",
            "SelfSessionRevokeResult",
            json!([]),
        ),
        (
            "/auth/browser/security/sessions/revoke",
            "browserRevokeSelfSession",
            "BrowserSelfSessionRevoke",
            json!([{"Origin":[],"BrowserHeader":[],"RefreshCookie":[]} ]),
        ),
        (
            "/auth/browser/security/sessions/revoke/result",
            "browserSelfSessionRevokeResult",
            "SelfSessionRevokeResult",
            json!([{"Origin":[],"BrowserHeader":[]} ]),
        ),
    ] {
        let op = &value["paths"][path]["post"];
        assert_eq!(op["operationId"], id);
        assert_eq!(op["security"], security);
        assert_eq!(op["requestBody"]["required"], true);
        assert_eq!(
            op["requestBody"]["content"]["application/json"]["schema"]["$ref"],
            format!("#/components/schemas/{schema}")
        );
        assert_eq!(
            op["responses"]["200"]["content"]["application/json"]["schema"]["$ref"],
            "#/components/schemas/SelfSessionRevokeCompleted"
        );
        assert_eq!(
            op["responses"]["200"]["headers"]["Cache-Control"]["schema"]["enum"][0],
            "no-store"
        );
        assert!(op["responses"]["200"]["headers"]
            .get("Set-Cookie")
            .is_none());
    }
    assert_eq!(
        value["components"]["schemas"]["SelfSessionRevokeResult"]["additionalProperties"],
        false
    );
    assert_eq!(
        value["components"]["schemas"]["SelfSessionRevokeResult"]["required"],
        json!(["operation_id", "receipt_secret"])
    );
    assert!(value["paths"]
        .get("/admin/auth/security/sessions/revoke")
        .is_none());
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
    let token = &value["paths"]["/oidc/token"]["post"];
    for path in ["/oidc/token", "/oidc/introspect", "/oidc/revoke"] {
        let operation = &value["paths"][path]["post"];
        assert_eq!(
            operation["responses"]["503"]["content"]["application/json"]["schema"]["$ref"],
            "#/components/schemas/OAuthError",
            "conditional password work capacity response missing for {path}"
        );
        assert!(operation["responses"]["503"]["description"]
            .as_str()
            .unwrap()
            .contains("Password work budget"));
        assert!(operation["responses"]["503"]["headers"]
            .get("WWW-Authenticate")
            .is_none());
        assert_eq!(
            operation["responses"]["503"]["headers"]["Cache-Control"]["schema"]["enum"][0],
            "no-store"
        );
    }
    assert!(token["description"]
        .as_str()
        .unwrap()
        .contains("Device-bound authorization codes require matching proof"));
    assert_eq!(token["parameters"].as_array().unwrap().len(), 5);
    assert!(token["parameters"]
        .as_array()
        .unwrap()
        .iter()
        .all(|p| p["in"] == "header" && p["required"] == false));

    // Keep route declaration drift visible for the exact shared protocol
    // routers; the ordinary 17-operation document remains a separate catalog.
    let authorization = include_str!("../src/tenant_oidc_authorization.rs");
    let resource = include_str!("../src/tenant_oidc_resource.rs");
    // Both public constructors delegate to this single router; delimit the
    // source extractor at the private shared builder so route declarations
    // cannot disappear from drift coverage when composition is refactored.
    let auth_routes = authorization
        .split("\nfn oidc_router(state: OidcState)")
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

#[test]
fn scan_contract_is_separate_complete_resolvable_and_route_aligned() {
    use embedded_idp_axum::openapi::{scan_document, scan_profile};
    let document = scan_document();
    let value = serde_json::to_value(&document).unwrap();
    let rendered = format!("{}\n", document.to_pretty_json().unwrap());
    assert_eq!(
        rendered,
        include_str!("../../../docs/api/scan-openapi.json"),
        "regenerate using export_scan_openapi"
    );
    assert_eq!(value["openapi"], "3.1.0");
    let browser = BTreeSet::from([
        "/auth/browser/device-scan/context",
        "/auth/browser/device-scan/phone-codes",
        "/auth/browser/device-scan/attach",
        "/auth/browser/device-scan/inspect",
        "/auth/browser/device-scan/approve",
        "/auth/browser/device-scan/deny",
        "/auth/browser/device-scan/cancel",
        "/auth/browser/device-scan/status",
    ]);
    let device = BTreeSet::from([
        "/auth/device-scan/create",
        "/auth/device-scan/claim",
        "/auth/device-scan/status",
        "/auth/device-scan/lookup",
        "/auth/device-scan/cancel",
        "/auth/device-scan/exchange",
        "/auth/device-scan/recover",
        "/auth/device-scan/acknowledge",
        "/auth/device-scan/abort",
        "/auth/device-scan/close-origin",
    ]);
    let source = include_str!("../src/device_scan_login.rs");
    let inventory = include_str!("../../../docs/api/route-inventory.md");
    for path in &browser {
        let suffix = path.strip_prefix("/auth/browser/device-scan").unwrap();
        assert!(
            source.contains(&format!(".route(\"{suffix}\", post(")),
            "browser router drift: {path}"
        );
        assert!(inventory.contains(suffix), "route inventory missing {path}");
    }
    for path in &device {
        let suffix = path.strip_prefix("/auth/device-scan").unwrap();
        assert!(
            source.contains(&format!(".route(\"{suffix}\", post(")),
            "device router drift: {path}"
        );
        assert!(inventory.contains(suffix), "route inventory missing {path}");
    }
    let mut actual_browser = BTreeSet::new();
    let mut actual_device = BTreeSet::new();
    for (path, item) in value["paths"].as_object().unwrap() {
        let op = &item["post"];
        match op["x-scan-side"].as_str().unwrap() {
            "browser" => {
                actual_browser.insert(path.as_str());
            }
            "device" => {
                actual_device.insert(path.as_str());
            }
            side => panic!("unexpected scan side {side}"),
        }
        assert_eq!(
            op["requestBody"]["content"]["application/json"]["schema"]["$ref"]
                .as_str()
                .is_some(),
            true
        );
    }
    assert_eq!(actual_browser, browser);
    assert_eq!(actual_device, device);
    assert_eq!(actual_browser.len(), 8);
    assert_eq!(actual_device.len(), 10);
    let schemas = value["components"]["schemas"].as_object().unwrap();
    for name in [
        "ExpectedSession",
        "PhoneCodesRequest",
        "AttachRequest",
        "GrantRequest",
        "ReadGrantRequest",
        "ApprovalRequest",
        "CreateRequest",
        "ClaimRequest",
        "OperationAccessRequest",
        "ReadAccessRequest",
        "CloseOriginRequest",
        "RecoverRequest",
        "AcknowledgeRequest",
        "AbortRequest",
    ] {
        let schema = &schemas[name];
        let properties = schema["properties"].as_object().unwrap();
        let required = schema["required"].as_array().unwrap();
        assert_eq!(
            properties.len(),
            required.len(),
            "required DTO drift: {name}"
        );
        assert_eq!(
            schema["additionalProperties"], false,
            "DTO must stay strict: {name}"
        );
    }
    for name in ["BrowserOnly", "LookupRequest"] {
        let schema = &schemas[name];
        assert_eq!(
            schema["required"].as_array().map_or(0, Vec::len) + 1,
            schema["properties"].as_object().unwrap().len()
        );
    }
    assert_eq!(
        schemas["BrowserOnly"]["properties"]["expected_session"]["oneOf"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        schemas["LookupRequest"]["properties"]["origin_action"]["oneOf"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    for (schema, fields) in [
        (
            "CreateRequest",
            [
                "operation_id",
                "entry_id",
                "tenant_id",
                "delivery_secret_hash",
            ]
            .as_slice(),
        ),
        (
            "ClaimRequest",
            [
                "operation_id",
                "entry_id",
                "tenant_id",
                "scan_code",
                "delivery_secret_hash",
            ]
            .as_slice(),
        ),
        (
            "LookupRequest",
            [
                "origin_action",
                "origin_operation_id",
                "entry_id",
                "tenant_id",
                "delivery_secret",
            ]
            .as_slice(),
        ),
        (
            "RecoverRequest",
            [
                "issuance_operation_id",
                "grant_id",
                "delivery_secret",
                "tenant_id",
            ]
            .as_slice(),
        ),
        (
            "AcknowledgeRequest",
            [
                "operation_id",
                "issuance_operation_id",
                "grant_id",
                "delivery_secret",
                "receipt_nonce",
                "tenant_id",
            ]
            .as_slice(),
        ),
        (
            "AbortRequest",
            [
                "operation_id",
                "issuance_operation_id",
                "grant_id",
                "delivery_secret",
                "tenant_id",
            ]
            .as_slice(),
        ),
        (
            "CloseOriginRequest",
            [
                "entry_id",
                "tenant_id",
                "origin_action",
                "origin_operation_id",
                "delivery_secret",
            ]
            .as_slice(),
        ),
    ] {
        let actual = schemas[schema]["properties"]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        assert_eq!(
            actual,
            fields.iter().copied().collect(),
            "DTO/schema drift: {schema}"
        );
    }
    for (path, fragments) in [
        (
            "/create",
            &["same operation_id", "delivery_secret_hash"][..],
        ),
        ("/claim", &["same operation_id", "delivery secret"][..]),
        (
            "/lookup",
            &["404 is nonterminal", "retain the original"][..],
        ),
        (
            "/exchange",
            &[
                "fixed issuance_operation_id",
                "exchange_already_started",
                "progress-only",
            ][..],
        ),
        (
            "/recover",
            &["original issuance_operation_id", "progress-only"][..],
        ),
        (
            "/acknowledge",
            &["progress only", "delivery_state=acknowledged"][..],
        ),
        (
            "/abort",
            &["409 already_acknowledged", "Abort is not logout"][..],
        ),
        (
            "/close-origin",
            &["already_activated", "does not revoke or log out"][..],
        ),
    ] {
        let path = format!("/auth/device-scan{path}");
        let description = value["paths"][&path]["post"]["description"]
            .as_str()
            .unwrap();
        for fragment in fragments {
            assert!(description.contains(fragment), "{path} missing {fragment}");
        }
    }

    fn walk_refs(
        value: &Value,
        root: &Value,
        graph: &mut Vec<(String, String)>,
        from: Option<&str>,
    ) {
        match value {
            Value::Object(map) => {
                if let Some(target) = map.get("$ref").and_then(Value::as_str) {
                    let pointer = target.strip_prefix('#').expect("local reference");
                    assert!(
                        root.pointer(pointer).is_some(),
                        "unresolved reference {target}"
                    );
                    if let Some(prefix) = "#/components/schemas/".strip_prefix('#') {
                        if let Some(to) = pointer.strip_prefix(prefix) {
                            if let Some(from) = from {
                                graph.push((from.to_string(), to.to_string()));
                            }
                        }
                    }
                }
                for child in map.values() {
                    walk_refs(child, root, graph, from);
                }
            }
            Value::Array(items) => {
                for child in items {
                    walk_refs(child, root, graph, from);
                }
            }
            _ => {}
        }
    }
    let schemas = value["components"]["schemas"].as_object().unwrap();
    let mut graph = Vec::new();
    for (name, schema) in schemas {
        walk_refs(schema, &value, &mut graph, Some(name));
    }
    fn visit(
        node: &str,
        graph: &[(String, String)],
        active: &mut BTreeSet<String>,
        done: &mut BTreeSet<String>,
    ) {
        assert!(
            active.insert(node.to_string()),
            "schema reference cycle at {node}"
        );
        if done.insert(node.to_string()) {
            for (_, target) in graph.iter().filter(|(source, _)| source == node) {
                visit(target, graph, active, done);
            }
        }
        active.remove(node);
    }
    let mut done = BTreeSet::new();
    for name in schemas.keys() {
        visit(name, &graph, &mut BTreeSet::new(), &mut done);
    }

    assert_eq!(
        value["components"]["schemas"]["ScanProgress"]["required"]
            .as_array()
            .unwrap()
            .len(),
        14
    );
    assert_eq!(
        value["components"]["schemas"]["DeliveryResponse"]["oneOf"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        value["components"]["schemas"]["ScanConfirmation"]["properties"]["source"]["properties"]
            ["display_name"]["type"],
        "string"
    );
    assert_eq!(
        value["components"]["schemas"]["ScanConfirmation"]["properties"]["target"]["properties"]
            ["context_label"]["type"],
        json!(["string", "null"])
    );
    assert_eq!(
        value["components"]["schemas"]["ScanProgress"]["properties"]["approved_until_unix_secs"]
            ["type"],
        json!(["integer", "null"])
    );
    assert_eq!(
        value["components"]["schemas"]["ScanProgress"]["properties"]["delivery_state"]["enum"],
        json!(["recoverable", "acknowledged", "revoked", null])
    );
    assert!(
        value["paths"]["/auth/device-scan/exchange"]["post"]["description"]
            .as_str()
            .unwrap()
            .contains("Pending until acknowledge")
    );
    assert!(
        value["paths"]["/auth/device-scan/acknowledge"]["post"]["description"]
            .as_str()
            .unwrap()
            .contains("activates")
    );
    assert!(
        value["paths"]["/auth/browser/device-scan/phone-codes"]["post"]["responses"]
            .get("201")
            .is_some()
    );
    assert!(
        value["paths"]["/auth/device-scan/create"]["post"]["responses"]
            .get("201")
            .is_some()
    );
    assert!(
        value["paths"]["/auth/browser/device-scan/context"]["post"]["responses"]
            .get("413")
            .is_none()
    );
    assert!(
        value["paths"]["/auth/browser/device-scan/context"]["post"]["responses"]
            .get("415")
            .is_none()
    );
    assert!(
        value["paths"]["/auth/device-scan/status"]["post"]["responses"]
            .get("413")
            .is_some()
    );
    assert!(
        value["paths"]["/auth/device-scan/status"]["post"]["responses"]
            .get("415")
            .is_some()
    );
    assert_eq!(
        value["paths"]["/auth/browser/device-scan/context"]["post"]["security"][0]["BrowserCookie"],
        json!([])
    );
    assert_eq!(
        value["paths"]["/auth/device-scan/status"]["post"]["security"][0]["DeviceSignature"],
        json!([])
    );
    let profile = serde_json::to_value(scan_profile("/browser/prefix", "/device/prefix")).unwrap();
    assert!(profile["paths"].get("/browser/prefix/context").is_some());
    assert!(profile["paths"].get("/device/prefix/create").is_some());
    assert_eq!(profile["servers"][0]["url"], "/");
    assert!(profile["paths"]["/browser/prefix/context"]["post"]
        .get("x-scan-side")
        .is_none());
    for (path, item) in value["paths"].as_object().unwrap() {
        let side = item["post"]["x-scan-side"].as_str().unwrap();
        let responses = item["post"]["responses"].as_object().unwrap();
        assert_eq!(
            responses.contains_key("413"),
            side == "device",
            "413 drift at {path}"
        );
        assert_eq!(
            responses.contains_key("415"),
            side == "device",
            "415 drift at {path}"
        );
        assert_eq!(item["post"]["security"].as_array().unwrap().len(), 1);
        assert!(
            item["post"]["security"][0].is_object(),
            "invalid security requirement at {path}"
        );
        let header_names = item["post"]["parameters"]
            .as_array()
            .unwrap()
            .iter()
            .map(|parameter| parameter["name"].as_str().unwrap())
            .collect::<BTreeSet<_>>();
        if side == "browser" {
            assert!(header_names.contains("Origin"));
            assert!(header_names.contains("x-embedded-idp-browser"));
        } else {
            assert_eq!(header_names.len(), 5);
            for name in [
                "x-device-id",
                "x-device-key-id",
                "x-device-challenge",
                "x-device-signature",
                "x-device-signed-at",
            ] {
                assert!(
                    header_names.contains(name),
                    "missing device proof header {name}"
                );
            }
        }
    }

    // Compare representative public projection code to the schema field set;
    // the adjacent device_scan_login unit tests exercise these same projections
    // through actual Axum responses, including no-store and body/path proof binding.
    for field in [
        "grant_id",
        "approved_until_unix_secs",
        "delivery_state",
        "issuance_operation_id",
        "recover_until_unix_secs",
        "next_action",
    ] {
        assert!(
            source.contains(&format!("\"{field}\"")),
            "wire projection field missing: {field}"
        );
        assert!(
            value["components"]["schemas"]["ScanProgress"]["properties"]
                .get(field)
                .is_some(),
            "schema field missing: {field}"
        );
    }
    assert!(source.contains("\"receipt_nonce\""));
    assert!(
        value["components"]["schemas"]["DeliveryBundle"]["properties"]
            .get("receipt_nonce")
            .is_some()
    );
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
    assert_eq!(fixed["paths"].as_object().unwrap().len(), 7);
    assert!(fixed["paths"].get("/auth/refresh").is_some());
    let choose =
        serde_json::to_value(business_profile("/entry-b", true, true, false, "entry_b")).unwrap();
    assert_eq!(choose["paths"].as_object().unwrap().len(), 16);
    assert_eq!(
        choose["components"]["securitySchemes"]["RefreshCookie"]["name"],
        "entry_b"
    );
    let registered =
        serde_json::to_value(business_profile("/entry-c", false, true, true, "entry_c")).unwrap();
    assert_eq!(registered["paths"].as_object().unwrap().len(), 16);
    assert!(registered["paths"].get("/auth/register").is_some());
    assert!(registered["paths"]
        .get("/auth/tenant-selection/complete")
        .is_none());
    assert!(registered["paths"]
        .get("/auth/browser/tenant-selection/complete")
        .is_some());
    let secured = serde_json::to_value(
        embedded_idp_axum::openapi::business_profile_with_account_security(
            "/entry-d", false, true, false, true, "entry_d",
        ),
    )
    .unwrap();
    assert!(secured["paths"]
        .get("/auth/security/sessions/revoke")
        .is_some());
    assert!(secured["paths"]
        .get("/auth/browser/security/sessions/revoke")
        .is_some());
}

#[test]
fn password_recovery_contract_is_conditional_strict_and_anonymous() {
    let document = serde_json::to_value(business_document()).unwrap();
    let paths = [
        "/auth/password-recovery/start",
        "/auth/password-recovery/complete",
        "/auth/password-recovery/result",
        "/auth/browser/password-recovery/start",
        "/auth/browser/password-recovery/complete",
        "/auth/browser/password-recovery/result",
    ];
    let inventory = include_str!("../../../docs/api/route-inventory.md");
    for path in paths {
        assert!(inventory.contains(path), "inventory missing {path}");
        let operation = &document["paths"][path]["post"];
        assert!(operation["parameters"].is_null(), "query params at {path}");
        assert_eq!(
            operation["responses"]["200"]["headers"]["Cache-Control"]["schema"]["enum"],
            json!(["no-store"])
        );
        assert!(operation["responses"]["200"]["headers"]
            .get("Set-Cookie")
            .is_none());
        assert_eq!(
            operation["responses"]["400"]["content"]["application/json"]["schema"]["$ref"],
            "#/components/schemas/Error"
        );
        assert_eq!(
            operation["responses"]["408"]["content"]["application/json"]["schema"]["$ref"],
            "#/components/schemas/Error"
        );
        assert_eq!(
            operation["responses"]["413"]["content"]["application/json"]["schema"]["$ref"],
            "#/components/schemas/Error"
        );
        assert_eq!(
            operation["responses"]["429"]["content"]["application/json"]["schema"]["$ref"],
            "#/components/schemas/Error"
        );
        let unavailable_schema =
            &operation["responses"]["503"]["content"]["application/json"]["schema"];
        assert_eq!(
            unavailable_schema["oneOf"],
            json!([
                {"$ref":"#/components/schemas/Error"},
                {"$ref":"#/components/schemas/AnonymousWorkUnavailable"}
            ])
        );
        assert!(matches_schema(
            &json!({"error":{"code":"temporarily_unavailable"}}),
            unavailable_schema,
            &document
        ));
        assert!(matches_schema(
            &json!({"code":"temporarily_unavailable","message":"unavailable"}),
            unavailable_schema,
            &document
        ));
        let body = operation["requestBody"]["content"]["application/json"]["schema"]["$ref"]
            .as_str()
            .unwrap();
        let schema = document
            .pointer(&format!("{}", body.strip_prefix('#').unwrap()))
            .unwrap();
        assert_eq!(schema["additionalProperties"], false);
        if path.contains("/browser/") {
            assert_eq!(
                operation["security"],
                json!([{"Origin":[],"BrowserHeader":[]}])
            );
            assert_eq!(
                operation["responses"]["403"]["content"]["application/json"]["schema"]["$ref"],
                "#/components/schemas/Error"
            );
        } else {
            assert_eq!(operation["security"], json!([]));
        }
    }
    assert_eq!(
        document["components"]["schemas"]["PasswordRecoveryStart"]["required"],
        json!(["email", "operation_id", "receipt_secret"])
    );
    assert_eq!(
        document["components"]["schemas"]["PasswordRecoveryComplete"]["required"],
        json!([
            "handle",
            "code",
            "new_password",
            "operation_id",
            "receipt_secret"
        ])
    );
    assert_eq!(
        document["components"]["schemas"]["PasswordRecoveryResult"]["required"],
        json!(["operation_id", "receipt_secret"])
    );
    let start_schema = &document["components"]["schemas"]["PasswordRecoveryStart"];
    assert_eq!(start_schema["properties"]["email"]["format"], "email");
    assert_eq!(start_schema["properties"]["email"]["maxLength"], 254);
    assert!(start_schema["properties"]["operation_id"]["description"]
        .as_str()
        .unwrap()
        .contains("all-zero UUID is rejected"));
    assert_eq!(
        document["components"]["schemas"]["PasswordRecoveryComplete"]["properties"]["code"]
            ["pattern"],
        "^[0-9]{6}$"
    );

    let profile = |account_security, recovery_email, browser| {
        serde_json::to_value(business_profile_with_recovery(
            "/host-prefix",
            false,
            browser,
            false,
            account_security,
            recovery_email,
            "host_cookie",
        ))
        .unwrap()
    };
    let old_profile = serde_json::to_value(business_profile_with_account_security(
        "/legacy",
        false,
        true,
        false,
        true,
        "legacy_cookie",
    ))
    .unwrap();
    assert!(old_profile["paths"]
        .get("/auth/password-recovery/start")
        .is_none());
    let disabled = profile(false, true, true);
    let no_email = profile(true, false, true);
    let email_no_browser = profile(true, true, false);
    let all = profile(true, true, true);
    for path in paths {
        assert!(disabled["paths"].get(path).is_none());
        assert!(no_email["paths"].get(path).is_none());
    }
    for path in &paths[..3] {
        assert!(email_no_browser["paths"].get(*path).is_some());
        assert!(all["paths"].get(*path).is_some());
    }
    for path in &paths[3..] {
        assert!(email_no_browser["paths"].get(*path).is_none());
        assert!(all["paths"].get(*path).is_some());
    }
    assert_eq!(all["servers"][0]["url"], "/host-prefix");
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
    let self_sessions = include_str!("../src/self_sessions.rs");
    assert!(self_sessions.contains("/auth/security/sessions"));
    assert!(self_sessions.contains("/admin/auth/security/sessions"));
    declared.insert(("/auth/security/sessions".to_owned(), "get".to_owned()));
    let browser_self_sessions = include_str!("../src/browser_session/self_sessions.rs");
    assert!(browser_self_sessions.contains("/security/sessions"));
    declared.insert((
        "/auth/browser/security/sessions".to_owned(),
        "post".to_owned(),
    ));
    for path in [
        "/auth/security/sessions/revoke",
        "/auth/security/sessions/revoke/result",
    ] {
        declared.insert((path.to_owned(), "post".to_owned()));
    }
    for path in [
        "/auth/browser/security/sessions/revoke",
        "/auth/browser/security/sessions/revoke/result",
    ] {
        declared.insert((path.to_owned(), "post".to_owned()));
    }
    let self_password_change = include_str!("../src/self_password_change.rs");
    assert!(self_password_change.contains("/auth/security/password"));
    for path in ["/auth/security/password", "/auth/security/password/result"] {
        declared.insert((path.to_owned(), "post".to_owned()));
    }
    let browser_self_password_change =
        include_str!("../src/browser_session/self_password_change.rs");
    assert!(browser_self_password_change.contains("/security/password"));
    for path in [
        "/auth/browser/security/password",
        "/auth/browser/security/password/result",
    ] {
        declared.insert((path.to_owned(), "post".to_owned()));
    }
    let password_recovery = include_str!("../src/password_recovery.rs");
    assert!(password_recovery.contains("/auth/password-recovery"));
    assert!(password_recovery.contains("/admin/auth/password-recovery"));
    for path in [
        "/auth/password-recovery/start",
        "/auth/password-recovery/complete",
        "/auth/password-recovery/result",
        "/auth/browser/password-recovery/start",
        "/auth/browser/password-recovery/complete",
        "/auth/browser/password-recovery/result",
    ] {
        declared.insert((path.to_owned(), "post".to_owned()));
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

#[test]
fn device_contract_export_is_stable_and_profiles_are_conditional() {
    use embedded_idp_axum::openapi::{device_document, device_profile};
    let generated = serde_json::to_value(device_document()).unwrap();
    let checked_in: Value =
        serde_json::from_str(include_str!("../../../docs/api/device-openapi.json")).unwrap();
    assert_eq!(
        generated, checked_in,
        "regenerate using export_device_openapi"
    );
    let paths = generated["paths"].as_object().unwrap();
    assert_eq!(paths.len(), 14);
    for required in [
        "/auth/login",
        "/auth/refresh",
        "/devices/proof/challenges",
        "/devices/provision",
        "/devices/registration-result",
        "/devices/complete",
        "/devices/rotate-key",
        "/devices",
        "/devices/{device_id}",
        "/devices/{device_id}/keys/{key_id}",
        "/devices/unbind",
        "/devices/operations/{operation_id}",
        "/devices/heartbeat",
        "/auth/tenant-selection/complete",
    ] {
        assert!(paths.contains_key(required), "missing {required}");
    }
    assert!(generated["paths"]
        .as_object()
        .unwrap()
        .values()
        .all(|item| !item.to_string().contains("scan")));
    let rotate = &generated["paths"]["/devices/rotate-key"]["post"];
    assert_eq!(rotate["security"], json!([{"Bearer":[]}]));
    let rotation_description = rotate["description"].as_str().unwrap();
    for contract in [
        "signatures from both the current and proposed keys",
        "DEVICE-KEY-ROTATION-V2",
        "compare-and-swap",
        "one-time",
        "no idempotency key or receipt",
        "current device pointer",
        "same active binding",
        "does not prove its nonce was persisted",
    ] {
        assert!(
            rotation_description.contains(contract),
            "rotation contract missing {contract}"
        );
    }
    let rotate_body = &generated["components"]["schemas"]["Rotate"];
    for required in [
        "device_id",
        "expected_key_id",
        "expected_key_version",
        "proposed_public_jwk",
        "challenge",
        "current_key_signature",
        "proposed_key_signature",
    ] {
        assert!(
            rotate_body["required"]
                .as_array()
                .unwrap()
                .contains(&json!(required)),
            "rotation request omits {required}"
        );
    }
    assert_eq!(
        rotate_body["properties"]["proposed_public_jwk"]["required"],
        json!(["kty", "crv", "x", "kid"])
    );
    assert_eq!(
        rotate["responses"]["200"]["content"]["application/json"]["schema"]["$ref"],
        "#/components/schemas/DeviceKey"
    );
    assert!(
        rotate["responses"].get("409").is_some(),
        "stale expected key version must have a conflict response"
    );
    let challenge = &generated["paths"]["/devices/proof/challenges"]["post"]["description"];
    assert!(challenge
        .as_str()
        .unwrap()
        .contains("does not prove it was stored"));
    let fixed = serde_json::to_value(device_profile("/entry-a", false)).unwrap();
    let choose = serde_json::to_value(device_profile("/entry-b", true)).unwrap();
    assert_eq!(fixed["servers"][0]["url"], "/entry-a");
    assert!(fixed["paths"]
        .get("/auth/tenant-selection/complete")
        .is_none());
    assert!(choose["paths"]
        .get("/auth/tenant-selection/complete")
        .is_some());
    assert_eq!(choose["servers"][0]["url"], "/entry-b");
    assert_eq!(
        generated["paths"]["/devices/{device_id}"]["get"]["parameters"][0]["name"],
        "device_id"
    );
    assert_eq!(
        generated["paths"]["/devices"]["get"]["parameters"][0]["schema"]["maximum"],
        200
    );
    let provision = &generated["paths"]["/devices/provision"]["post"];
    assert_eq!(provision["security"], json!([{"DeviceAdmission":[]} ]));
    assert!(provision["description"]
        .as_str()
        .unwrap()
        .contains("original registration_request_id and identical"));
    let registration_result = &generated["paths"]["/devices/registration-result"]["post"];
    for behavior in [
        "every call",
        "stable registration scope",
        "not part of this server-side grant scope",
    ] {
        assert!(registration_result["description"]
            .as_str()
            .unwrap()
            .contains(behavior));
    }
    let heartbeat = &generated["paths"]["/devices/heartbeat"]["post"]["description"];
    for binding in [
        "original raw JSON bytes",
        "externally visible path",
        "audience",
    ] {
        assert!(heartbeat.as_str().unwrap().contains(binding));
    }
    assert_eq!(
        generated["components"]["securitySchemes"]["DeviceAdmission"]["name"],
        "x-embedded-idp-device-admission"
    );
    let complete = &generated["paths"]["/devices/complete"]["post"]["description"];
    assert!(complete.as_str().unwrap().contains("not idempotent"));
    assert!(complete
        .as_str()
        .unwrap()
        .contains("query registration-result"));
    assert!(!complete.as_str().unwrap().contains("raw JSON bytes"));
    let challenge = &generated["paths"]["/devices/proof/challenges"]["post"]["description"];
    assert!(challenge
        .as_str()
        .unwrap()
        .contains("does not prove it was stored"));
    assert_eq!(
        generated["components"]["schemas"]["Registration"]["properties"]["proof_key_id"]["type"],
        json!(["string", "null"])
    );
    assert_eq!(
        generated["components"]["schemas"]["Registration"]["properties"]["key_version"]["type"],
        json!(["integer", "null"])
    );
    let heartbeat = &generated["paths"]["/devices/heartbeat"]["post"];
    for scheme in [
        "Bearer",
        "DeviceId",
        "DeviceKeyId",
        "DeviceChallenge",
        "DeviceSignature",
        "DeviceSignedAt",
    ] {
        assert!(heartbeat["security"][0].get(scheme).is_some());
    }
    assert_eq!(
        generated["paths"]["/devices/provision"]["post"]["responses"]["503"]["content"]
            ["application/json"]["schema"]["$ref"],
        "#/components/schemas/DeviceAdmissionBusy"
    );
    assert_eq!(
        generated["paths"]["/devices/provision"]["post"]["responses"]["401"]["content"]
            ["application/json"]["schema"]["oneOf"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    let jwk = &generated["components"]["schemas"]["Provision"]["properties"]["public_jwk"];
    assert_eq!(jwk["required"], json!(["kty", "crv", "x", "kid"]));
    assert_eq!(jwk["properties"]["kty"]["enum"], json!(["OKP"]));
    assert_eq!(jwk["properties"]["crv"]["enum"], json!(["Ed25519"]));
    assert!(jwk["description"]
        .as_str()
        .unwrap()
        .contains("SHA-256 thumbprint"));
    let device_auth = generated["paths"]["/auth/login"]["post"]["description"]
        .as_str()
        .unwrap();
    for header in [
        "x-embedded-idp-tenant-id",
        "x-device-id",
        "x-device-key-id",
        "x-device-challenge",
        "x-device-signature",
        "x-device-signed-at",
    ] {
        assert!(
            device_auth.contains(header),
            "missing proof header description: {header}"
        );
    }
}

#[tokio::test]
async fn device_auth_reuses_resolvable_wire_schemas() {
    let document = serde_json::to_value(embedded_idp_axum::openapi::device_document()).unwrap();
    fn references(value: &Value, document: &Value, stack: &mut BTreeSet<String>) {
        match value {
            Value::Object(map) => {
                if let Some(reference) = map.get("$ref").and_then(Value::as_str) {
                    assert!(
                        stack.insert(reference.into()),
                        "cyclic schema reference: {reference}"
                    );
                    references(
                        document
                            .pointer(reference.strip_prefix('#').unwrap())
                            .expect("unresolved reference"),
                        document,
                        stack,
                    );
                    stack.remove(reference);
                }
                for (key, item) in map {
                    if key != "$ref" {
                        references(item, document, stack);
                    }
                }
            }
            Value::Array(items) => {
                for item in items {
                    references(item, document, stack);
                }
            }
            _ => {}
        }
    }
    references(&document, &document, &mut BTreeSet::new());
    // Device and ordinary authentication share the same session/token serializer.
    let response = complete_router()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/login")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"email":"x@example.test","password":"fixture"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let value: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 65536).await.unwrap()).unwrap();
    assert!(matches_schema(
        &value,
        &document["components"]["schemas"]["DeviceAuthResult"],
        &document
    ));
    assert!(matches_schema(
        &json!({"error":"device_admission_required","message":"valid device admission is required"}),
        &document["components"]["schemas"]["DeviceAdmissionRequired"],
        &document
    ));
    assert!(matches_schema(
        &json!({"error":"device_admission_busy"}),
        &document["components"]["schemas"]["DeviceAdmissionBusy"],
        &document
    ));
}

#[test]
fn device_route_source_and_contract_paths_stay_aligned() {
    let auth = include_str!("../src/tenant_device_auth.rs");
    let devices = include_str!("../src/tenant_devices.rs");
    let document = serde_json::to_value(embedded_idp_axum::openapi::device_document()).unwrap();
    let mut declared = std::collections::BTreeSet::new();
    for (source, prefix) in [(auth, ""), (devices, "")] {
        for line in source.lines() {
            let Some((_, rest)) = line.split_once(".route(\"") else {
                continue;
            };
            let Some((path, _)) = rest.split_once('\"') else {
                continue;
            };
            let method = if line.contains("get(") {
                "get"
            } else if line.contains("post(") {
                "post"
            } else {
                continue;
            };
            let canonical = path
                .replace(":device_id", "{device_id}")
                .replace(":key_id", "{key_id}")
                .replace(":operation_id", "{operation_id}");
            declared.insert((format!("{prefix}{canonical}"), method.to_string()));
        }
    }
    let mut contracted = std::collections::BTreeSet::new();
    for (path, item) in document["paths"].as_object().unwrap() {
        for method in item.as_object().unwrap().keys() {
            contracted.insert((path.clone(), method.clone()));
        }
    }
    assert_eq!(declared, contracted);
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
                "minLength",
                "maxLength",
                "pattern",
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
    if let Some(text) = value.as_str() {
        let length = text.chars().count();
        if schema["minLength"]
            .as_u64()
            .is_some_and(|n| length < n as usize)
            || schema["maxLength"]
                .as_u64()
                .is_some_and(|n| length > n as usize)
        {
            return false;
        }
        if let Some(pattern) = schema["pattern"].as_str() {
            let valid = match pattern {
                "^[A-Za-z0-9_-]{64}$" => {
                    length == 64
                        && text
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
                }
                "^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$" => {
                    length == 43
                        && text.len() == 43
                        && text[..42]
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
                        && text.as_bytes()[42].is_ascii_alphanumeric()
                        && b"AEIMQUYcgkosw048".contains(&text.as_bytes()[42])
                }
                "^[0-9]{6}$" => length == 6 && text.bytes().all(|b| b.is_ascii_digit()),
                "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$" => {
                    length == 36
                        && text != "00000000-0000-0000-0000-000000000000"
                        && text.bytes().enumerate().all(|(index, byte)| match index {
                            8 | 13 | 18 | 23 => byte == b'-',
                            _ => byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase(),
                        })
                }
                other => panic!("unchecked schema pattern {other}"),
            };
            if !valid {
                return false;
            }
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
    if path.contains("password-recovery") {
        assert!(response.headers().get("set-cookie").is_none());
    }
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
impl SelfSessionService for Successful {
    fn list_sessions(
        &self,
        _: AccessActor,
        _: SelfSessionPageRequest,
    ) -> Result<SelfSessionPage, AccessError> {
        Ok(SelfSessionPage {
            items: vec![],
            next_cursor: None,
        })
    }
}
impl RecoveryStartService for Successful {
    fn start_recovery(&self, _: RecoveryStartCommand) -> Result<RecoveryStartResult, AccessError> {
        Ok(RecoveryStartResult {
            handle: SecretString::new("a".repeat(64)),
            expires_at: std::time::UNIX_EPOCH + std::time::Duration::from_secs(1234),
        })
    }
}
impl RecoveryCompletionService for Successful {
    fn complete_recovery(&self, _: RecoveryCompleteCommand) -> Result<(), RecoveryCompleteError> {
        Ok(())
    }
    fn recovery_completion_result(&self, _: SecurityReceiptQuery) -> Result<bool, AccessError> {
        Ok(false)
    }
}
impl SelfSecurityBrowserIdentityService for Successful {
    fn self_security_browser_purpose(&self) -> embedded_idp_core::AccessTokenPurpose {
        embedded_idp_core::AccessTokenPurpose::Business
    }
    fn self_security_browser_lifetime_secs(&self) -> Option<u64> {
        None
    }
    fn authenticate_self_security_browser(
        &self,
        _: SecretString,
        _: BrowserSessionIdentity,
    ) -> Result<AccessActor, TenantAuthError> {
        self.authenticate(SecretString::new("fixture"))
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
        .merge(password_recovery_router(service.clone(), service.clone()))
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
        .merge(browser_password_recovery_router(
            service.clone(),
            service.clone(),
            BrowserSessionHttpConfig::new(
                "https://entry.test",
                "entry_refresh",
                "/auth/browser",
                embedded_idp_core::AccessTokenPurpose::Business,
            )
            .unwrap(),
        ))
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
        (
            "POST",
            "/auth/password-recovery/start",
            r#"{"email":"x@example.test","operation_id":"00000000-0000-0000-0000-000000000001","receipt_secret":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}"#,
            200,
        ),
        (
            "POST",
            "/auth/password-recovery/complete",
            r#"{"handle":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","code":"123456","new_password":"new-fixture-password","operation_id":"00000000-0000-0000-0000-000000000001","receipt_secret":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}"#,
            200,
        ),
        (
            "POST",
            "/auth/password-recovery/result",
            r#"{"operation_id":"00000000-0000-0000-0000-000000000001","receipt_secret":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}"#,
            200,
        ),
        (
            "POST",
            "/auth/browser/password-recovery/start",
            r#"{"email":"x@example.test","operation_id":"00000000-0000-0000-0000-000000000001","receipt_secret":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}"#,
            200,
        ),
        (
            "POST",
            "/auth/browser/password-recovery/complete",
            r#"{"handle":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","code":"123456","new_password":"new-fixture-password","operation_id":"00000000-0000-0000-0000-000000000001","receipt_secret":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}"#,
            200,
        ),
        (
            "POST",
            "/auth/browser/password-recovery/result",
            r#"{"operation_id":"00000000-0000-0000-0000-000000000001","receipt_secret":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}"#,
            200,
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
        if path != "/auth/logout" && !path.contains("password-recovery") {
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
                .header("x-embedded-idp-browser", "1");
            if !path.contains("password-recovery") {
                request = request.header("cookie", "entry_refresh=fixture");
            }
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
                    .merge(tenant_self_router(auth.clone(), service.clone()))
                    .merge(self_session_router(auth, service.clone()));
                if browser {
                    router = router
                        .merge(
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
                        )
                        .merge(
                            browser_self_session_router(
                                service.clone(),
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
async fn recovery_profile_paths_match_business_and_browser_router_mounts() {
    use embedded_idp_axum::*;
    for account_security in [false, true] {
        for recovery_email in [false, true] {
            for browser in [false, true] {
                let service = Arc::new(Successful);
                let mut router = Router::new();
                if account_security && recovery_email {
                    router =
                        router.merge(password_recovery_router(service.clone(), service.clone()));
                    if browser {
                        router = router.merge(browser_password_recovery_router(
                            service.clone(),
                            service.clone(),
                            BrowserSessionHttpConfig::new(
                                "https://entry.test",
                                "entry_refresh",
                                "/auth/browser",
                                embedded_idp_core::AccessTokenPurpose::Business,
                            )
                            .unwrap(),
                        ));
                    }
                }
                let profile = serde_json::to_value(business_profile_with_recovery(
                    "/entry",
                    false,
                    browser,
                    false,
                    account_security,
                    recovery_email,
                    "entry_refresh",
                ))
                .unwrap();
                let router = Router::new().nest("/entry", router);
                for suffix in ["start", "complete", "result"] {
                    for browser_path in [false, true] {
                        let path = if browser_path {
                            format!("/auth/browser/password-recovery/{suffix}")
                        } else {
                            format!("/auth/password-recovery/{suffix}")
                        };
                        let expected =
                            account_security && recovery_email && (!browser_path || browser);
                        assert_eq!(
                            profile["paths"].get(&path).is_some(),
                            expected,
                            "profile recovery path {path}"
                        );
                        let response = router
                            .clone()
                            .oneshot(
                                Request::get(format!("/entry{path}"))
                                    .body(Body::empty())
                                    .unwrap(),
                            )
                            .await
                            .unwrap();
                        assert_eq!(
                            response.status() != 404,
                            expected,
                            "router recovery path {path}; account_security={account_security} recovery_email={recovery_email} browser={browser}"
                        );
                    }
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
