//! Ordinary business HTTP contract. Local projections deliberately keep Core free of HTTP schemas.
//! This is a conditional module-root catalog, not a claim that every path is mounted by every host.
#![allow(dead_code)]
use serde::Serialize;
use serde_json::{json, Value};
use utoipa::{OpenApi, ToSchema};

macro_rules! dto {
    ($name:ident { $($field:ident : $ty:ty),* $(,)? }) => {
        #[derive(Serialize, ToSchema)]
        #[serde(deny_unknown_fields)]
        struct $name { $($field: $ty),* }
    };
}
#[derive(Serialize, ToSchema)]
enum AuthenticatedStatus {
    #[serde(rename = "authenticated")]
    Authenticated,
}
#[derive(Serialize, ToSchema)]
enum SelectionStatus {
    #[serde(rename = "tenant_selection_required")]
    SelectionRequired,
}
dto!(Login {
    email: String,
    password: String
});
dto!(Refresh {
    refresh_token: String
});
dto!(Select { tenant_id: String });
dto!(Logout { refresh_token: String, client_id: Option<String>, client_secret: Option<String> });
dto!(Identity {
    tenant_id: String,
    account_id: String,
    session_id: String,
    client_id: String
});
dto!(Session {
    tenant_id: String,
    account_id: String,
    session_id: String,
    client_id: String,
    expires_at_unix_secs: u64
});
dto!(Actor {
    tenant_id: String,
    account_id: String,
    session_id: String
});
dto!(Tokens {
    access_token: String,
    refresh_token: String,
    access_expires_at_unix_secs: u64,
    refresh_expires_at_unix_secs: u64
});
dto!(BrowserTokens {
    access_token: String,
    access_expires_at_unix_secs: u64,
    refresh_expires_at_unix_secs: u64
});
dto!(Authenticated {
    status: AuthenticatedStatus,
    session: Session,
    tokens: Tokens
});
dto!(BrowserAuthenticated {
    status: AuthenticatedStatus,
    session: Session,
    tokens: BrowserTokens
});
dto!(SelectionRequired {
    status: SelectionStatus,
    selection_ticket: String,
    expires_in: u64
});
dto!(BrowserSession { expected_session: Option<Identity> });
dto!(BrowserRefresh {
    expected_session: Identity
});
dto!(Error {
    code: String,
    message: String
});
dto!(OAuthError { error: String });
dto!(Register { tenant_id: String, email: String, password: String, display_name: Option<String> });
dto!(Verify {
    tenant_id: String,
    email: String,
    verification_code: String
});
dto!(Resend {
    tenant_id: String,
    email: String
});
dto!(Registered {
    tenant_id: String,
    account_id: String,
    account_status: String,
    verification_channel: String,
    verification_expires_at_unix_secs: u64,
    delivery_status: String
});
dto!(Verified {
    tenant_id: String,
    account_id: String,
    account_status: String
});
dto!(Resent { status: String });
dto!(Tenant {
    tenant_id: String,
    name: String,
    status: String,
    membership_status: String
});
dto!(Role {
    tenant_id: String,
    business_id: String,
    role_id: String,
    key: String,
    name: String,
    version: u64,
    status: String,
    kind: String
});
#[derive(Serialize, ToSchema)]
struct Tenants {
    tenants: Vec<Tenant>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(nullable = false)]
    next_cursor: Option<String>,
    has_more: bool,
}
#[derive(Serialize, ToSchema)]
struct Roles {
    items: Vec<Role>,
    #[schema(required = true)]
    next_cursor: Option<String>,
    has_more: bool,
}
#[derive(Serialize, ToSchema)]
struct Capabilities {
    tenancy_enabled: bool,
    login_tenant_policy: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(nullable = false)]
    fixed_tenant_id: Option<String>,
    page_limit: u32,
    max_page_limit: u32,
}
#[derive(OpenApi)]
#[openapi(components(schemas(
    AuthenticatedStatus,
    SelectionStatus,
    Login,
    Refresh,
    Select,
    Logout,
    Identity,
    Session,
    Actor,
    Tokens,
    BrowserTokens,
    Authenticated,
    BrowserAuthenticated,
    SelectionRequired,
    BrowserSession,
    BrowserRefresh,
    Error,
    OAuthError,
    Register,
    Verify,
    Resend,
    Registered,
    Verified,
    Resent,
    Tenant,
    Role,
    Tenants,
    Roles,
    Capabilities
)))]
struct Contract;
fn reference(name: &str) -> Value {
    json!({"$ref":format!("#/components/schemas/{name}")})
}
fn response(name: &str) -> Value {
    json!({"description":"Success", "content":{"application/json":{"schema":reference(name)}}})
}

/// OpenAPI 3.1.0 produced by utoipa. Servers use a host-selected mount prefix.
pub fn business_document() -> utoipa::openapi::OpenApi {
    let mut doc = Contract::openapi();
    doc.info.title = "Ordinary business entry HTTP contract".into();
    doc.info.version = env!("CARGO_PKG_VERSION").into();
    doc.info.description = Some("A02A module-root conditional catalog. Each entry binds client_id, login_entry_id, tenant policy and Business purpose. No device, scan or OIDC routes. Cookie name/path, origin, token lifetime and mount prefix belong to the host profile. JSON/form bodies are limited to 16384 bytes; all responses use Cache-Control: no-store. Secrets never belong in query parameters. Fixed and Choose are mutually exclusive; registration requires Fixed plus explicit enablement and email service.".into());
    let mut paths = serde_json::Map::new();
    for (path, method, id, body, success, auth, condition) in [
        (
            "/auth/login",
            "post",
            "businessLogin",
            "Login",
            "Authenticated",
            "",
            "always",
        ),
        (
            "/auth/access/capabilities",
            "get",
            "businessCapabilities",
            "",
            "Capabilities",
            "",
            "always",
        ),
        (
            "/auth/session",
            "get",
            "businessSession",
            "",
            "Actor",
            "Bearer",
            "always",
        ),
        (
            "/auth/refresh",
            "post",
            "businessRefresh",
            "Refresh",
            "Authenticated",
            "",
            "always",
        ),
        (
            "/auth/logout",
            "post",
            "businessLogout",
            "Logout",
            "",
            "Client",
            "always",
        ),
        (
            "/auth/tenant-selection/tenants",
            "get",
            "businessTenants",
            "",
            "Tenants",
            "TenantSelection",
            "enabled_choose",
        ),
        (
            "/auth/me/tenant-selection",
            "post",
            "businessSwitch",
            "",
            "SelectionRequired",
            "Bearer",
            "enabled_choose",
        ),
        (
            "/auth/tenant-selection/complete",
            "post",
            "businessSelect",
            "Select",
            "Authenticated",
            "TenantSelection",
            "enabled_choose",
        ),
        (
            "/auth/me/roles",
            "get",
            "businessRoles",
            "",
            "Roles",
            "Bearer",
            "always",
        ),
        (
            "/auth/browser/login",
            "post",
            "browserLogin",
            "Login",
            "BrowserAuthenticated",
            "Browser",
            "browser",
        ),
        (
            "/auth/browser/tenant-selection/complete",
            "post",
            "browserSelect",
            "Select",
            "BrowserAuthenticated",
            "BrowserSelection",
            "browser",
        ),
        (
            "/auth/browser/restore",
            "post",
            "browserRestore",
            "BrowserSession",
            "BrowserAuthenticated",
            "BrowserCookie",
            "browser",
        ),
        (
            "/auth/browser/refresh",
            "post",
            "browserRefresh",
            "BrowserRefresh",
            "BrowserAuthenticated",
            "BrowserCookie",
            "browser",
        ),
        (
            "/auth/browser/logout",
            "post",
            "browserLogout",
            "BrowserSession",
            "",
            "BrowserOptionalCookie",
            "browser",
        ),
        (
            "/auth/register",
            "post",
            "businessRegister",
            "Register",
            "Registered",
            "",
            "registration_fixed",
        ),
        (
            "/auth/verify-email",
            "post",
            "businessVerify",
            "Verify",
            "Verified",
            "",
            "registration_fixed",
        ),
        (
            "/auth/resend-verification",
            "post",
            "businessResend",
            "Resend",
            "Resent",
            "",
            "registration_fixed",
        ),
    ] {
        let mut op =
            json!({"operationId":id,"x-mount-condition":condition,"responses":{},"security":[]});
        let status = if id == "browserLogout" {
            "204"
        } else if id == "businessRegister" || id == "businessResend" {
            "202"
        } else {
            "200"
        };
        op["responses"][status] = if success.is_empty() {
            json!({"description":"Success; empty body"})
        } else {
            response(success)
        };
        if id == "businessLogin" || id == "browserLogin" {
            op["responses"][status]["content"]["application/json"]["schema"] =
                json!({"oneOf":[reference(success),reference("SelectionRequired")]});
        }
        for code in ["400", "401", "403", "409", "500"] {
            op["responses"][code] = json!({"description":"Service or boundary rejection", "content":{"application/json":{"schema": if id=="businessLogout" {json!({"oneOf":[reference("Error"),reference("OAuthError")]})} else {reference("Error")}}}});
        }
        if !body.is_empty() {
            let mime = if id == "businessLogout" {
                "application/x-www-form-urlencoded"
            } else {
                "application/json"
            };
            op["requestBody"] =
                json!({"required":true,"content":{mime:{"schema":reference(body)}}});
            for code in ["400", "413", "415", "422"] {
                op["responses"][code]["description"] = json!(
                    "Extractor rejection; may be text/plain. 400 can also be a JSON domain error."
                );
                op["responses"][code]["content"]["text/plain"]["schema"] = json!({"type":"string"});
            }
        }
        if id == "businessRefresh" {
            // raw_json has intentionally different boundaries from Axum Json:
            // overflow is our JSON error; unsupported content type has no body.
            op["responses"]["413"] = json!({"description":"Request body exceeds 16384 bytes", "content":{"application/json":{"schema":reference("Error")}}});
            op["responses"]["415"] = json!({"description":"Unsupported media type; empty body"});
        }
        if id == "businessRoles" || id == "businessTenants" {
            op["responses"]["400"]["content"]["text/plain"]["schema"] = json!({"type":"string"});
            op["responses"]["400"]["description"] =
                json!("Query extractor rejection is text/plain; domain rejection is JSON");
        }
        op["security"] = match auth {
            "" => json!([]),
            "Client" => json!([{"Basic":[]},{}]),
            "Browser" | "BrowserOptionalCookie" => json!([{"Origin":[],"BrowserHeader":[]}]),
            "BrowserSelection" => json!([{"Origin":[],"BrowserHeader":[],"TenantSelection":[]}]),
            "BrowserCookie" => json!([{"Origin":[],"BrowserHeader":[],"RefreshCookie":[]}]),
            name => json!([{name:[]}]),
        };
        let mut notes = "Access/tickets are entry/client/purpose scoped. Optional tenant header must agree with the authenticated context.".to_string();
        if path.contains("/browser/") {
            notes = "Exact configured Origin AND x-embedded-idp-browser: 1 required; Sec-Fetch-Site, when supplied, must be same-origin. Tenant header forbidden. Refresh cookie is HttpOnly, Secure in HTTPS, SameSite=Strict, entry-specific name/path. Only access token appears in JSON. Browser selection route is present even for Fixed but selection is rejected by policy. Restore rotates; refresh requires expected_session. Logout without cookie is idempotent 204 in normal mode. Development restricted browser mode disables restore/refresh and requires expected_session even for cookie-less logout.".into();
        }
        if id == "businessLogout" {
            notes = "Public client: form client_id. Confidential backend: Basic OR form client_id/client_secret; never both, never query credentials. Empty 200 on success. Credential determines tenant; tenant header forbidden. Invalid client emits WWW-Authenticate: Basic; invalid token emits Bearer.".into();
        }
        if id == "businessRefresh" {
            notes = "Refresh credential selects tenant and is bound to this entry/client/Business purpose. Tenant and device-proof headers forbidden; proof-bound sessions cannot downgrade. Reuse revocation is committed before 401 refresh_token_reuse_detected. Successful rotation returns status, session and tokens.".into();
        }
        if id == "businessLogin" {
            notes = "Tenant header forbidden: the entry owns tenant policy. Fixed returns authenticated; Choose returns tenant_selection_required.".into();
        }
        if id == "businessTenants" {
            notes = "TenantSelection ticket selects the subject. Tenant header is not used to select or restrict the returned tenant list; the ticket and entry policy own scope.".into();
        }
        if id == "businessSelect" || id == "businessSwitch" {
            notes.push_str(" New JSON hosts with restricted private-HTTP browser isolation reject browser tickets on token completion. Short persisted source sessions cannot switch into a longer-lived token session; reauthenticate and select through the browser channel. Full-session and LegacyReference behavior is unchanged.");
        }
        op["description"] = json!(notes);
        if id == "businessRoles" || id == "businessTenants" {
            op["parameters"] = json!([{"name":"limit","in":"query","required":false,"schema":{"type":"integer","minimum":1,"maximum":200}},{"name":"cursor","in":"query","required":false,"schema":{"type":"string"},"description":"Opaque scoped cursor. Tenant list bound to subject; roles bound to tenant/business/subject."}]);
            if id == "businessRoles" {
                op["parameters"].as_array_mut().unwrap().push(json!({"name":"business_id","in":"query","required":true,"schema":{"type":"string"}}));
            }
        }
        for (status, r) in op["responses"].as_object_mut().unwrap() {
            if id == "businessLogout" && status == "401" {
                r["headers"]["WWW-Authenticate"] = json!({"description":"On OAuth 401 invalid_client: Basic realm=\"idp\"; invalid_token: Bearer error=\"invalid_token\".","schema":{"type":"string"}});
            }
            r["headers"]["Cache-Control"] = json!({"schema":{"type":"string","enum":["no-store"]}});
            if path.contains("/browser/") {
                r["headers"]["Set-Cookie"] = json!({"description":"When rotating/clearing refresh credential; host profile defines exact cookie name/path.","schema":{"type":"string"}});
            }
        }
        paths.insert(path.into(), json!({method:op}));
    }
    doc.paths = serde_json::from_value(json!(paths)).unwrap();
    let schemes = json!({
        "Bearer":{"type":"http","scheme":"bearer"},
        "Basic":{"type":"http","scheme":"basic"},
        "TenantSelection":{"type":"apiKey","in":"header","name":"Authorization","description":"TenantSelection <opaque ticket>, not Bearer"},
        "Origin":{"type":"apiKey","in":"header","name":"Origin"},
        "BrowserHeader":{"type":"apiKey","in":"header","name":"x-embedded-idp-browser","description":"Exactly 1"},
        "RefreshCookie":{"type":"apiKey","in":"cookie","name":"HOST_PROFILE_COOKIE","description":"Placeholder: host must substitute its entry-specific cookie_name; no global cookie name."}
    });
    doc.components.as_mut().unwrap().security_schemes = serde_json::from_value(schemes).unwrap();
    doc.servers = Some(vec![utoipa::openapi::Server::new("/")]);
    doc
}

/// Select a validated host entry profile. `mount_prefix` and `cookie_name` must
/// come from the host's validated configuration, not from an HTTP request.
/// The host remains responsible for rejecting registration + Choose.
pub fn business_profile(
    mount_prefix: &str,
    choose: bool,
    browser: bool,
    registration: bool,
    cookie_name: &str,
) -> utoipa::openapi::OpenApi {
    let mut value = serde_json::to_value(business_document()).unwrap();
    let paths = value["paths"].as_object_mut().unwrap();
    paths.retain(|_, item| {
        item.as_object().unwrap().values().all(|op| {
            match op["x-mount-condition"].as_str().unwrap() {
                "enabled_choose" => choose,
                "browser" => browser,
                "registration_fixed" => registration && !choose,
                _ => true,
            }
        })
    });
    value["servers"] = json!([{"url": if mount_prefix.is_empty() {"/"} else {mount_prefix}}]);
    value["components"]["securitySchemes"]["RefreshCookie"]["name"] = json!(cookie_name);
    serde_json::from_value(value).unwrap()
}

/// Shared OIDC endpoints used by v2 business entries. Kept separate from the
/// ordinary business-entry catalog because these paths are mounted once for
/// the host when at least one v2 entry enables OIDC.
pub fn shared_oidc_document() -> utoipa::openapi::OpenApi {
    let schema = |name: &str| json!({"$ref":format!("#/components/schemas/{name}")});
    let json_response = |description: &str, schema: Value| json!({"description":description,"content":{"application/json":{"schema":schema}}});
    let error = json!({"type":"object","required":["error"],"properties":{"error":{"type":"string"}},"additionalProperties":false});
    let mut paths = serde_json::Map::new();
    paths.insert("/.well-known/openid-configuration".into(), json!({"get":{
        "operationId":"sharedOidcDiscovery",
        "description":"Mounted once when at least one v2 business entry enables OIDC. Advertises authorization_code, S256, openid/profile/email scopes, RS256, and none/basic/post token authentication. This shared v2 metadata does not advertise device endpoints.",
        "responses":{"200":json_response("OIDC provider metadata",schema("Discovery"))},"security":[]
    }}));
    paths.insert("/oidc/jwks".into(), json!({"get":{
        "operationId":"sharedOidcJwks","description":"RS256 public signing keys. Host response uses ETag and Cache-Control: public, max-age=300.",
        "responses":{"200":{
          "description":"JSON Web Key Set",
          "content":{"application/json":{"schema":schema("Jwks")}},
          "headers":{"ETag":{"schema":{"type":"string"}},"Cache-Control":{"schema":{"type":"string","enum":["public, max-age=300"]}}}
        }},"security":[]
    }}));
    paths.insert("/oidc/authorize".into(), json!({"get":{
        "operationId":"sharedOidcAuthorize","description":"Requires one Bearer access token. New v2 business composition requires a non-empty code_challenge and code_challenge_method=S256; `plain` is rejected. Successful authorization redirects with 307. Device-bound authorization codes are not supported by this shared business entry.",
        "parameters":[
          {"name":"response_type","in":"query","required":true,"schema":{"type":"string","enum":["code"]}},
          {"name":"client_id","in":"query","required":true,"schema":{"type":"string"}},
          {"name":"redirect_uri","in":"query","required":true,"schema":{"type":"string"}},
          {"name":"scope","in":"query","required":false,"schema":{"type":"string"}},
          {"name":"state","in":"query","required":false,"schema":{"type":"string"}},
          {"name":"nonce","in":"query","required":false,"schema":{"type":"string"}},
          {"name":"code_challenge","in":"query","required":true,"schema":{"type":"string","minLength":1}},
          {"name":"code_challenge_method","in":"query","required":true,"schema":{"type":"string","enum":["S256"]}}
        ],
        "responses":{"307":{"description":"Redirect to the registered client redirect_uri with code and optional state","headers":{"Location":{"schema":{"type":"string"}},"Cache-Control":{"schema":{"type":"string","enum":["no-store"]}}}},"400":json_response("OAuth protocol error",schema("OAuthError")),"401":json_response("Bearer authentication failed",schema("OAuthError")),"414":json_response("Authorization query exceeds 16384 bytes",schema("OAuthError")),"500":json_response("Server error",schema("OAuthError"))},"security":[{"Bearer":[]}]
    }}));
    paths.insert("/oidc/token".into(), json!({"post":{
        "operationId":"sharedOidcToken","description":"Authorization-code exchange only. Supports Basic or form client authentication. Device proof is not accepted or required for this shared business endpoint.",
        "requestBody":{"required":true,"content":{"application/x-www-form-urlencoded":{"schema":{"type":"object","required":["grant_type","code","redirect_uri","code_verifier"],"properties":{"grant_type":{"type":"string","enum":["authorization_code"]},"code":{"type":"string"},"redirect_uri":{"type":"string"},"client_id":{"type":"string"},"client_secret":{"type":"string"},"code_verifier":{"type":"string","minLength":1}},"additionalProperties":false,"description":"Every authorization code is created with S256 PKCE; code_verifier is required. No device proof fields are part of this contract."}}}},
        "responses":{"200":json_response("Issued token response",schema("TokenResponse")),"400":json_response("OAuth grant or form error",schema("OAuthError")),"401":json_response("Client authentication error",schema("OAuthError")),"413":json_response("Request body exceeds 16384 bytes",schema("OAuthError")),"415":json_response("Unsupported form media type",schema("OAuthError")),"500":json_response("Server error",schema("OAuthError"))},"security":[{"Basic":[]},{}]
    }}));
    paths.insert("/oidc/userinfo".into(), json!({"get":{
        "operationId":"sharedOidcUserinfo","responses":{"200":json_response("Authenticated user claims",schema("UserInfo")),"401":json_response("Bearer authentication failed",schema("OAuthError")),"403":json_response("Insufficient authorization",schema("OAuthError")),"500":json_response("Server error",schema("Error"))},"security":[{"Bearer":[]}]
    }}));
    for (path, id, desc) in [
        (
            "/oidc/introspect",
            "sharedOidcIntrospect",
            "Confidential clients only. Introspect a token using Basic or form client authentication.",
        ),
        (
            "/oidc/revoke",
            "sharedOidcRevoke",
            "Revoke only this client's current token family. Public clients supply client_id; confidential clients authenticate using Basic or form credentials.",
        ),
    ] {
        let success = if id.ends_with("Revoke") {
            json!({"description":"Token revoked or already inactive; empty response"})
        } else {
            json_response("Token activity", schema("Introspection"))
        };
        paths.insert(path.into(), json!({"post":{
            "operationId":id,"description":desc,
            "requestBody":{"required":true,"content":{"application/x-www-form-urlencoded":{"schema":{"type":"object","required":["token"],"properties":{"token":{"type":"string"},"token_type_hint":{"type":"string","description":"Unknown values are ignored."},"client_id":{"type":"string"},"client_secret":{"type":"string"}},"additionalProperties":false}}}},
            "responses":{"200":success,"400":{"description":"OAuth error or form extraction failure","content":{"application/json":{"schema":schema("OAuthError")},"text/plain":{"schema":{"type":"string"}}}},"401":json_response("Client authentication error",schema("OAuthError")),"413":{"description":"Form body exceeds 16384 bytes","content":{"text/plain":{"schema":{"type":"string"}}}},"415":{"description":"Unsupported form media type","content":{"text/plain":{"schema":{"type":"string"}}}},"422":{"description":"Form field extraction failed","content":{"text/plain":{"schema":{"type":"string"}}}},"500":json_response("Server error",schema("Error"))},"security":[{"Basic":[]},{}]
        }}));
    }
    let value = json!({
      "openapi":"3.1.0","info":{"title":"Shared v2 business OIDC contract","version":env!("CARGO_PKG_VERSION"),"description":"Host-shared OIDC surface, conditionally mounted when at least one v2 business entry enables OIDC. Does not include /auth/logout."},
      "servers":[{"url":"/"}],"paths":paths,
      "components":{"securitySchemes":{"Bearer":{"type":"http","scheme":"bearer"},"Basic":{"type":"http","scheme":"basic"}},"schemas":{
        "Error":error,"OAuthError":{"type":"object","required":["error"],"properties":{"error":{"type":"string"}},"additionalProperties":false},
        "Discovery":{"type":"object","required":["issuer","authorization_endpoint","token_endpoint","jwks_uri","userinfo_endpoint","introspection_endpoint","revocation_endpoint","response_types_supported","grant_types_supported","subject_types_supported","id_token_signing_alg_values_supported","code_challenge_methods_supported","scopes_supported","token_endpoint_auth_methods_supported"],"properties":{"issuer":{"type":"string"},"authorization_endpoint":{"type":"string"},"token_endpoint":{"type":"string"},"jwks_uri":{"type":"string"},"userinfo_endpoint":{"type":"string"},"introspection_endpoint":{"type":"string"},"revocation_endpoint":{"type":"string"},"response_types_supported":{"type":"array","items":{"type":"string","enum":["code"]}},"grant_types_supported":{"type":"array","items":{"type":"string","enum":["authorization_code"]}},"subject_types_supported":{"type":"array","items":{"type":"string","enum":["public"]}},"id_token_signing_alg_values_supported":{"type":"array","items":{"type":"string","enum":["RS256"]}},"code_challenge_methods_supported":{"type":"array","items":{"type":"string","enum":["S256"]}},"scopes_supported":{"type":"array","items":{"type":"string","enum":["openid","profile","email"]}},"token_endpoint_auth_methods_supported":{"type":"array","items":{"type":"string","enum":["none","client_secret_basic","client_secret_post"]}}},"additionalProperties":false},
        "Jwks":{"type":"object","required":["keys"],"properties":{"keys":{"type":"array","items":{"type":"object","required":["kid","kty","alg","use","n","e"],"properties":{"kid":{"type":"string"},"kty":{"type":"string","enum":["RSA"]},"alg":{"type":"string","enum":["RS256"]},"use":{"type":"string","enum":["sig"]},"n":{"type":"string"},"e":{"type":"string"}},"additionalProperties":false}}},"additionalProperties":false},
        "TokenResponse":{"type":"object","required":["access_token","refresh_token","refresh_token_version","token_type","scope","tenant_id","subject_account_id","session_id","expires_in"],"properties":{"access_token":{"type":"string"},"refresh_token":{"type":"string"},"refresh_token_version":{"type":"integer"},"token_type":{"type":"string","enum":["Bearer"]},"id_token":{"type":"string"},"scope":{"type":"string"},"tenant_id":{"type":"string"},"subject_account_id":{"type":"string"},"session_id":{"type":"string"},"expires_in":{"type":"integer"}},"additionalProperties":false},
        "UserInfo":{"type":"object","required":["sub","tenant_id","client_id"],"properties":{"sub":{"type":"string"},"tenant_id":{"type":"string"},"client_id":{"type":"string"},"email":{"type":"string"},"name":{"type":"string"}},"additionalProperties":false},
        "Introspection":{"oneOf":[{"type":"object","required":["active"],"properties":{"active":{"type":"boolean","enum":[false]}},"additionalProperties":false},{"type":"object","required":["active","tenant_id","sub","client_id","session_id","token_type","iat","exp"],"properties":{"active":{"type":"boolean","enum":[true]},"tenant_id":{"type":"string"},"sub":{"type":"string"},"client_id":{"type":"string"},"session_id":{"type":"string"},"token_type":{"type":"string","enum":["access_token","refresh_token"]},"iat":{"type":"integer"},"exp":{"type":"integer"},"scope":{"type":"string"}},"additionalProperties":false}]}
      }}
    });
    serde_json::from_value(value).unwrap()
}
