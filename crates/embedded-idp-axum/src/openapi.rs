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
    let mut doc_value = serde_json::to_value(Contract::openapi()).unwrap();
    doc_value["components"]["schemas"]["SelfSessionPurpose"] = json!({
        "type":"string","enum":["business","management"]
    });
    doc_value["components"]["schemas"]["SelfSessionStatus"] = json!({
        "type":"string","enum":["active","expired"]
    });
    doc_value["components"]["schemas"]["SelfSessionIdentity"] = json!({
        "type":"object","additionalProperties":false,
        "required":["tenant_id","account_id","session_id","client_id"],
        "properties":{"tenant_id":{"type":"string"},"account_id":{"type":"string"},"session_id":{"type":"string"},"client_id":{"type":"string"}}
    });
    doc_value["components"]["schemas"]["SelfSession"] = json!({
        "type":"object","additionalProperties":false,
        "required":["tenant_id","session_id","client_id","purpose","device_id","created_at","expires_at","status","current"],
        "properties":{
            "tenant_id":{"type":"string"},"session_id":{"type":"string"},"client_id":{"type":"string"},
            "purpose":{"$ref":"#/components/schemas/SelfSessionPurpose"},"device_id":{"type":["string","null"]},
            "created_at":{"type":"integer","format":"int64","minimum":0},"expires_at":{"type":"integer","format":"int64","minimum":0},
            "status":{"$ref":"#/components/schemas/SelfSessionStatus"},"current":{"type":"boolean"}
        }
    });
    doc_value["components"]["schemas"]["SelfSessionPage"] = json!({
        "type":"object","additionalProperties":false,"required":["items","next_cursor"],
        "properties":{"items":{"type":"array","items":{"$ref":"#/components/schemas/SelfSession"}},"next_cursor":{"type":["string","null"]}}
    });
    doc_value["components"]["schemas"]["SelfSessionRead"] = json!({
        "type":"object","additionalProperties":false,"required":["expected"],
        "properties":{
            "expected":{"$ref":"#/components/schemas/SelfSessionIdentity"},
            "limit":{"type":"integer","minimum":1,"maximum":50},
            "cursor":{"type":"string","maxLength":1024}
        }
    });
    doc_value["components"]["schemas"]["SelfSessionRevoke"] = json!({
        "type":"object","additionalProperties":false,
        "required":["target_tenant_id","target_session_id","operation_id","receipt_secret"],
        "properties":{"target_tenant_id":{"type":"string"},"target_session_id":{"type":"string","format":"uuid","description":"Canonical non-nil UUID."},"operation_id":{"type":"string","format":"uuid","pattern":"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$","description":"Canonical lowercase non-nil UUID."},"receipt_secret":{"type":"string","minLength":43,"maxLength":43,"pattern":"^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$","description":"Canonical unpadded base64url encoding of 32 random bytes."}}
    });
    doc_value["components"]["schemas"]["BrowserSelfSessionRevoke"] = json!({
        "type":"object","additionalProperties":false,
        "required":["target_tenant_id","target_session_id","operation_id","receipt_secret","expected"],
        "properties":{"target_tenant_id":{"type":"string"},"target_session_id":{"type":"string","format":"uuid","description":"Canonical non-nil UUID."},"operation_id":{"type":"string","format":"uuid","pattern":"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$","description":"Canonical lowercase non-nil UUID."},"receipt_secret":{"type":"string","minLength":43,"maxLength":43,"pattern":"^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$","description":"Canonical unpadded base64url encoding of 32 random bytes."},"expected":{"$ref":"#/components/schemas/SelfSessionIdentity"}}
    });
    doc_value["components"]["schemas"]["SelfSessionRevokeResult"] = json!({
        "type":"object","additionalProperties":false,"required":["operation_id","receipt_secret"],
        "properties":{"operation_id":{"type":"string","format":"uuid","pattern":"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$","description":"Canonical lowercase non-nil UUID."},"receipt_secret":{"type":"string","minLength":43,"maxLength":43,"pattern":"^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$","description":"Canonical unpadded base64url encoding of 32 random bytes."}}
    });
    doc_value["components"]["schemas"]["SelfSessionRevokeCompleted"] = json!({
        "type":"object","additionalProperties":false,"required":["completed"],"properties":{"completed":{"type":"boolean"}}
    });
    let operation_id = json!({"type":"string","format":"uuid","pattern":"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$","description":"Canonical lowercase non-nil UUID."});
    let receipt_secret = json!({"type":"string","minLength":43,"maxLength":43,"pattern":"^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$","description":"Canonical unpadded base64url encoding of 32 random bytes."});
    let password =
        json!({"type":"string","minLength":1,"description":"Password is not trimmed or returned."});
    doc_value["components"]["schemas"]["SelfPasswordChange"] = json!({
        "type":"object","additionalProperties":false,
        "required":["current_password","new_password","operation_id","receipt_secret"],
        "properties":{"current_password":password.clone(),"new_password":password.clone(),"operation_id":operation_id.clone(),"receipt_secret":receipt_secret.clone()}
    });
    doc_value["components"]["schemas"]["BrowserSelfPasswordChange"] = json!({
        "type":"object","additionalProperties":false,
        "required":["current_password","new_password","operation_id","receipt_secret","expected"],
        "properties":{"current_password":password.clone(),"new_password":password,"operation_id":operation_id.clone(),"receipt_secret":receipt_secret.clone(),"expected":{"$ref":"#/components/schemas/SelfSessionIdentity"}}
    });
    doc_value["components"]["schemas"]["SelfPasswordChangeResult"] = json!({
        "type":"object","additionalProperties":false,"required":["operation_id","receipt_secret"],
        "properties":{"operation_id":operation_id,"receipt_secret":receipt_secret}
    });
    doc_value["components"]["schemas"]["SelfPasswordChangeCompleted"] = json!({
        "type":"object","additionalProperties":false,"required":["completed"],"properties":{"completed":{"type":"boolean"}}
    });
    let recovery_operation_id = json!({"type":"string","format":"uuid","pattern":"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$","description":"Canonical lowercase non-nil UUID; the all-zero UUID is rejected."});
    let recovery_receipt_secret = json!({"type":"string","minLength":43,"maxLength":43,"pattern":"^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$","description":"Canonical unpadded base64url encoding of 32 random bytes."});
    doc_value["components"]["schemas"]["PasswordRecoveryStart"] = json!({
        "type":"object","additionalProperties":false,"required":["email","operation_id","receipt_secret"],
        "properties":{"email":{"type":"string","format":"email","maxLength":254},"operation_id":recovery_operation_id,"receipt_secret":recovery_receipt_secret}
    });
    doc_value["components"]["schemas"]["PasswordRecoveryComplete"] = json!({
        "type":"object","additionalProperties":false,"required":["handle","code","new_password","operation_id","receipt_secret"],
        "properties":{"handle":{"type":"string","minLength":64,"maxLength":64,"pattern":"^[A-Za-z0-9_-]{64}$"},"code":{"type":"string","minLength":6,"maxLength":6,"pattern":"^[0-9]{6}$"},"new_password":{"type":"string","minLength":1,"description":"Validated by the configured account password policy; never returned."},"operation_id":recovery_operation_id,"receipt_secret":recovery_receipt_secret}
    });
    doc_value["components"]["schemas"]["PasswordRecoveryResult"] = json!({
        "type":"object","additionalProperties":false,"required":["operation_id","receipt_secret"],
        "properties":{"operation_id":recovery_operation_id,"receipt_secret":recovery_receipt_secret}
    });
    doc_value["components"]["schemas"]["PasswordRecoveryStarted"] = json!({
        "type":"object","additionalProperties":false,"required":["handle","expires_at_unix_secs"],
        "properties":{"handle":{"type":"string","minLength":64,"maxLength":64,"pattern":"^[A-Za-z0-9_-]{64}$"},"expires_at_unix_secs":{"type":"integer","format":"int64","minimum":0}}
    });
    doc_value["components"]["schemas"]["PasswordRecoveryCompleted"] = json!({
        "type":"object","additionalProperties":false,"required":["completed"],"properties":{"completed":{"type":"boolean"}}
    });
    doc_value["components"]["schemas"]["AnonymousWorkUnavailable"] = json!({
        "type":"object","additionalProperties":false,"required":["error"],
        "properties":{"error":{"type":"object","additionalProperties":false,"required":["code"],"properties":{"code":{"type":"string","enum":["temporarily_unavailable"]}}}}
    });
    let mut doc: utoipa::openapi::OpenApi = serde_json::from_value(doc_value).unwrap();
    doc.info.title = "Ordinary business entry HTTP contract".into();
    doc.info.version = env!("CARGO_PKG_VERSION").into();
    doc.info.description = Some("A02A module-root conditional catalog. Each entry binds client_id, login_entry_id, tenant policy and Business purpose. No device, scan or OIDC routes. Cookie name/path, origin, token lifetime and mount prefix belong to the host profile. JSON/form bodies are limited to 16384 bytes; all responses use Cache-Control: no-store. Secrets never belong in query parameters. Fixed and Choose are mutually exclusive; registration requires Fixed plus explicit enablement and email service. Password recovery is account-wide and appears only when account security and recovery email are both enabled.".into());
    let mut paths = serde_json::Map::new();
    for (path, method, id, body, success, auth, condition) in [
        (
            "/auth/security/sessions",
            "get",
            "businessSelfSessions",
            "",
            "SelfSessionPage",
            "Bearer",
            "always",
        ),
        (
            "/auth/browser/security/sessions",
            "post",
            "browserSelfSessions",
            "SelfSessionRead",
            "SelfSessionPage",
            "BrowserCookie",
            "browser",
        ),
        (
            "/auth/security/sessions/revoke",
            "post",
            "businessRevokeSelfSession",
            "SelfSessionRevoke",
            "SelfSessionRevokeCompleted",
            "Bearer",
            "account_security",
        ),
        (
            "/auth/security/sessions/revoke/result",
            "post",
            "businessSelfSessionRevokeResult",
            "SelfSessionRevokeResult",
            "SelfSessionRevokeCompleted",
            "",
            "account_security",
        ),
        (
            "/auth/browser/security/sessions/revoke",
            "post",
            "browserRevokeSelfSession",
            "BrowserSelfSessionRevoke",
            "SelfSessionRevokeCompleted",
            "BrowserRevoke",
            "account_security_browser",
        ),
        (
            "/auth/browser/security/sessions/revoke/result",
            "post",
            "browserSelfSessionRevokeResult",
            "SelfSessionRevokeResult",
            "SelfSessionRevokeCompleted",
            "BrowserOrigin",
            "account_security_browser",
        ),
        (
            "/auth/security/password",
            "post",
            "businessSelfPasswordChange",
            "SelfPasswordChange",
            "SelfPasswordChangeCompleted",
            "Bearer",
            "account_security",
        ),
        (
            "/auth/security/password/result",
            "post",
            "businessSelfPasswordChangeResult",
            "SelfPasswordChangeResult",
            "SelfPasswordChangeCompleted",
            "",
            "account_security",
        ),
        (
            "/auth/browser/security/password",
            "post",
            "browserSelfPasswordChange",
            "BrowserSelfPasswordChange",
            "SelfPasswordChangeCompleted",
            "BrowserRevoke",
            "account_security_browser",
        ),
        (
            "/auth/browser/security/password/result",
            "post",
            "browserSelfPasswordChangeResult",
            "SelfPasswordChangeResult",
            "SelfPasswordChangeCompleted",
            "BrowserOrigin",
            "account_security_browser",
        ),
        (
            "/auth/password-recovery/start",
            "post",
            "businessPasswordRecoveryStart",
            "PasswordRecoveryStart",
            "PasswordRecoveryStarted",
            "",
            "recovery_email",
        ),
        (
            "/auth/password-recovery/complete",
            "post",
            "businessPasswordRecoveryComplete",
            "PasswordRecoveryComplete",
            "PasswordRecoveryCompleted",
            "",
            "recovery_email",
        ),
        (
            "/auth/password-recovery/result",
            "post",
            "businessPasswordRecoveryResult",
            "PasswordRecoveryResult",
            "PasswordRecoveryCompleted",
            "",
            "recovery_email",
        ),
        (
            "/auth/browser/password-recovery/start",
            "post",
            "browserPasswordRecoveryStart",
            "PasswordRecoveryStart",
            "PasswordRecoveryStarted",
            "BrowserOrigin",
            "recovery_email_browser",
        ),
        (
            "/auth/browser/password-recovery/complete",
            "post",
            "browserPasswordRecoveryComplete",
            "PasswordRecoveryComplete",
            "PasswordRecoveryCompleted",
            "BrowserOrigin",
            "recovery_email_browser",
        ),
        (
            "/auth/browser/password-recovery/result",
            "post",
            "browserPasswordRecoveryResult",
            "PasswordRecoveryResult",
            "PasswordRecoveryCompleted",
            "BrowserOrigin",
            "recovery_email_browser",
        ),
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
        if matches!(id, "businessLogin" | "browserLogin" | "businessRegister") {
            op["responses"]["503"] = json!({"description":"Password work budget is at capacity","content":{"application/json":{"schema":reference("Error")}}});
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
        if id.contains("PasswordRecovery") {
            op["responses"] = json!({
                "200":response(success),
                "400":{"description":"Invalid strict JSON or recovery command","content":{"application/json":{"schema":reference("Error")}}},
                "408":{"description":"Request body read timed out","content":{"application/json":{"schema":reference("Error")}}},
                "413":{"description":"Request body exceeds 16384 bytes","content":{"application/json":{"schema":reference("Error")}}},
                "429":{"description":"Source, global, or recovery account budget exhausted","content":{"application/json":{"schema":reference("Error")}}},
                "503":{"description":"Security operation unavailable; the local anonymous-work semaphore retains its legacy nested response","content":{"application/json":{"schema":{"oneOf":[reference("Error"),reference("AnonymousWorkUnavailable")]}}}}
            });
            op["responses"]["400"]["description"] = if id.ends_with("Complete") {
                json!(
                    "invalid_request for malformed JSON/command; invalid_recovery for invalid or unavailable recovery credentials"
                )
            } else {
                json!("invalid_request for malformed JSON or command")
            };
            op["responses"]["408"]["description"] =
                json!("request_timeout; body read exceeded 5 seconds");
            op["responses"]["413"]["description"] =
                json!("request_too_large; body exceeded 16384 bytes");
            op["responses"]["503"]["description"] = json!(
                "security_unavailable for recovery capacity, crypto, or storage; temporarily_unavailable for local or outer anonymous-work admission rejection (the local legacy response is nested)"
            );
            op["responses"]["429"]["description"] = if id.ends_with("Start") {
                json!("rate_limited by source/global admission or start account budget")
            } else {
                json!("rate_limited by source/global admission")
            };
            if id.ends_with("Start") || id.ends_with("Complete") {
                op["responses"]["409"] = json!({"description":"The operation ID is already bound to a different command","content":{"application/json":{"schema":reference("Error")}}});
            }
            if path.contains("/browser/") {
                op["responses"]["403"] = json!({"description":"Browser Origin/header/tenant guard rejected the request","content":{"application/json":{"schema":reference("Error")}}});
                op["security"] = json!([{"Origin":[],"BrowserHeader":[]}]);
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
        if id == "businessSelfSessions" {
            op["parameters"] = json!([
                {"name":"limit","in":"query","required":false,"schema":{"type":"integer","minimum":1,"maximum":50}},
                {"name":"cursor","in":"query","required":false,"schema":{"type":"string","maxLength":1024,"description":"Opaque base64url JSON cursor, bound to the authenticated subject."}}
            ]);
            op["responses"]["400"]["description"] =
                json!("Invalid limit/cursor or query extractor rejection");
            op["responses"]["400"]["content"]["text/plain"]["schema"] = json!({"type":"string"});
        }
        if id == "browserSelfSessions" {
            op["responses"]["413"] = json!({"description":"Request body exceeds 16384 bytes","content":{"text/plain":{"schema":{"type":"string"}}}});
            op["responses"]["415"] = json!({"description":"Unsupported media type","content":{"text/plain":{"schema":{"type":"string"}}}});
            op["responses"]["422"] = json!({"description":"Invalid JSON/body extraction","content":{"text/plain":{"schema":{"type":"string"}}}});
        }
        if matches!(
            id,
            "businessRevokeSelfSession"
                | "browserRevokeSelfSession"
                | "businessSelfSessionRevokeResult"
                | "browserSelfSessionRevokeResult"
        ) {
            op["responses"]["200"] = response("SelfSessionRevokeCompleted");
            op["responses"]["404"] = json!({"description":"Target session was not found","content":{"application/json":{"schema":reference("Error")}}});
            op["responses"]["409"] = json!({"description":"Operation conflicts with an existing request","content":{"application/json":{"schema":reference("Error")}}});
            op["responses"]["503"] = json!({"description":"Security storage, crypto or receipt capacity unavailable","content":{"application/json":{"schema":reference("Error")}}});
            op["description"] = json!(
                "Revocation requires an authenticated current actor. Its receipt result is capability-based: lookup needs no bearer token or cookie, and the receipt secret permits querying across entry points. No response sets or clears cookies."
            );
            if id.starts_with("browser") {
                op["responses"]["403"] = json!({"description":"Origin or browser boundary rejected","content":{"application/json":{"schema":reference("Error")}}});
                op["description"] = json!(
                    "Requires exact configured Origin and browser header, with same-origin Fetch-Site when present. Revocation also requires the configured HttpOnly cookie and expected identity. Result lookup requires no cookie or expected selector. No response sets or clears cookies."
                );
            }
        }
        if id.contains("SelfPasswordChange") {
            op["responses"]["200"] = response("SelfPasswordChangeCompleted");
            op["responses"]["400"] = json!({"description":"Invalid JSON, content type, fields or password policy","content":{"application/json":{"schema":reference("Error")}}});
            op["responses"]["401"] = json!({"description":"Invalid session or current password","content":{"application/json":{"schema":reference("Error")}}});
            op["responses"]["403"] = json!({"description":"Browser origin or request boundary rejected","content":{"application/json":{"schema":reference("Error")}}});
            op["responses"]["409"] = json!({"description":"Credential snapshot or operation conflict","content":{"application/json":{"schema":reference("Error")}}});
            op["responses"]["413"] = json!({"description":"Request body exceeds 16384 bytes","content":{"application/json":{"schema":reference("Error")}}});
            op["responses"]["500"] = json!({"description":"Unexpected service projection failure","content":{"application/json":{"schema":reference("Error")}}});
            op["responses"]["503"] = json!({"description":"Password work, security storage, crypto or receipt capacity unavailable","content":{"application/json":{"schema":reference("Error")}}});
            op["responses"].as_object_mut().unwrap().remove("415");
            op["responses"].as_object_mut().unwrap().remove("422");
        }
        op["security"] = match auth {
            "" => json!([]),
            "Client" => json!([{"Basic":[]},{}]),
            "Browser" | "BrowserOptionalCookie" | "BrowserOrigin" => {
                json!([{"Origin":[],"BrowserHeader":[]}])
            }
            "BrowserRevoke" => json!([{"Origin":[],"BrowserHeader":[],"RefreshCookie":[]}]),
            "BrowserSelection" => json!([{"Origin":[],"BrowserHeader":[],"TenantSelection":[]}]),
            "BrowserCookie" => json!([{"Origin":[],"BrowserHeader":[],"RefreshCookie":[]}]),
            name => json!([{name:[]}]),
        };
        let mut notes = "Access/tickets are entry/client/purpose scoped. Optional tenant header must agree with the authenticated context.".to_string();
        if path.contains("/browser/") {
            notes = "Exact configured Origin AND x-embedded-idp-browser: 1 required; Sec-Fetch-Site, when supplied, must be same-origin. Tenant header forbidden. Refresh cookie is HttpOnly, Secure in HTTPS, SameSite=Strict, entry-specific name/path. Only access token appears in JSON. Browser selection route is present even for Fixed but selection is rejected by policy. Restore rotates; refresh requires expected_session. Logout without cookie is idempotent 204 in normal mode. Development restricted browser mode disables restore/refresh and requires expected_session even for cookie-less logout.".into();
        }
        if id == "businessSelfSessions" {
            notes = "Requires exactly one Bearer Authorization header. An optional x-embedded-idp-tenant-id must match the authenticated tenant; x-embedded-idp-business-id is rejected. The authenticated actor must be a current first-party session with scope=null; OAuth-derived scope-bearing sessions cannot authorize global self-security reads. Lists all of the same account's database-active sessions across tenants, including delegated scope-bearing sessions. Expired-by-time sessions are projected as status=expired; revoked/pending records are omitted. Cursor is base64url JSON version=1 with subject_id, tenant_id and canonical UUID session_id, at most 1024 encoded bytes. Query accepts only limit and cursor. Response contains no scope, refresh-token data or account email.".to_string();
        }
        if id == "browserSelfSessions" {
            notes = "Requires the exact configured Origin and x-embedded-idp-browser: 1; when present, Sec-Fetch-Site must be same-origin. Tenant and business selection headers are forbidden. The configured HttpOnly refresh cookie is read only; this route does not refresh or expose credentials. Strict JSON requires expected {tenant_id,account_id,session_id,client_id}; optional limit is 1..50 and cursor is at most 1024 encoded bytes. The host must bind identity purpose and restricted-session lifetime exactly to BrowserSessionHttpConfig. The current actor must be a first-party scope=null session; same-account delegated sessions remain listable. Request body limit is 16384 bytes. Response fields match SelfSessionPage and all responses are no-store.".to_string();
        }
        if id == "businessRevokeSelfSession" {
            notes = "Requires exactly one Bearer Authorization header. An optional tenant header must match the authenticated actor; the business selector header is rejected. Request is strict JSON with target tenant/session, canonical non-nil operation UUID and receipt secret. All responses are no-store and none sets or clears a cookie.".into();
        }
        if id == "businessSelfSessionRevokeResult" {
            notes = "Capability result lookup: no bearer authentication is performed. Body contains only canonical non-nil operation UUID and receipt secret; tenant and business selector headers are rejected. A matching secret may query the same operation through another entry. All responses are no-store.".into();
        }
        if id == "browserRevokeSelfSession" {
            notes = "Requires exact configured Origin and x-embedded-idp-browser: 1; Sec-Fetch-Site, when present, must be same-origin. Requires the configured HttpOnly cookie and strict expected {tenant_id,account_id,session_id,client_id}. Business selector is rejected. All responses are no-store; none sets or clears a cookie.".into();
        }
        if id == "browserSelfSessionRevokeResult" {
            notes = "Capability result lookup: no cookie or expected identity is required and no authentication service is called. Exact configured Origin and x-embedded-idp-browser: 1 are required; Sec-Fetch-Site, when present, must be same-origin. Body contains only canonical non-nil operation UUID and receipt secret. All responses are no-store and none sets or clears a cookie.".into();
        }
        if id.contains("SelfPasswordChange") {
            notes = if id.ends_with("Result") {
                "Capability result lookup: no bearer authentication, cookie or expected identity is required; it reports only whether the operation completed. Browser results still require the configured Origin and browser header. Request is strict JSON; body is limited to 16384 bytes. All responses are no-store and none sets or clears cookies.".into()
            } else if id.starts_with("browser") {
                "Requires exact configured Origin and x-embedded-idp-browser: 1; Sec-Fetch-Site, when present, must be same-origin. Requires the configured HttpOnly cookie and strict expected {tenant_id,account_id,session_id,client_id}. Body includes current_password and new_password, neither is trimmed or returned. Request is strict JSON; body is limited to 16384 bytes. All responses are no-store and none sets or clears cookies.".into()
            } else {
                "Requires exactly one Bearer Authorization header. Optional tenant hint must match the authenticated actor; business selector is rejected. Strict JSON includes current_password and new_password, neither is trimmed or returned. Request body is limited to 16384 bytes. All responses are no-store and none sets or clears cookies.".into()
            };
        }
        if id.contains("PasswordRecovery") {
            notes = "Anonymous account-wide recovery; it is not tenant- or entry-scoped. Strict JSON rejects unknown fields and query parameters; tenant and business selector headers are rejected. Bearer tokens and refresh cookies do not authenticate this operation, and no response sets or clears cookies. Bodies are limited to 16384 bytes and read within 5 seconds. Start has one deliberately uniform result for known, unknown, and ineligible email addresses: success means the request was recorded, not that email was sent or an account exists. Start uses the shared account budget as an abuse limit, not as authenticated identity. Outer host admission may read the start body and consume this budget before the browser Origin guard runs. A result with completed=false is not proof that a command did not commit.".into();
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
        if id == "businessSelfSessions" {
            op["parameters"] = json!([
                {"name":"limit","in":"query","required":false,"schema":{"type":"integer","minimum":1,"maximum":50}},
                {"name":"cursor","in":"query","required":false,"schema":{"type":"string","maxLength":1024,"description":"Opaque base64url JSON cursor, bound to the authenticated subject."}}
            ]);
        }
        for (status, r) in op["responses"].as_object_mut().unwrap() {
            if id == "businessLogout" && status == "401" {
                r["headers"]["WWW-Authenticate"] = json!({"description":"On OAuth 401 invalid_client: Basic realm=\"idp\"; invalid_token: Bearer error=\"invalid_token\".","schema":{"type":"string"}});
            }
            r["headers"]["Cache-Control"] = json!({"schema":{"type":"string","enum":["no-store"]}});
            if path.contains("/browser/")
                && id != "browserSelfSessions"
                && !id.contains("RevokeSelfSession")
                && !id.contains("RevokeResult")
                && !id.contains("SelfPasswordChange")
                && !id.contains("PasswordRecovery")
            {
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
    business_profile_with_account_security(
        mount_prefix,
        choose,
        browser,
        registration,
        false,
        cookie_name,
    )
}

/// Profile variant for hosts that explicitly enable account-security routes.
pub fn business_profile_with_account_security(
    mount_prefix: &str,
    choose: bool,
    browser: bool,
    registration: bool,
    account_security: bool,
    cookie_name: &str,
) -> utoipa::openapi::OpenApi {
    business_profile_with_recovery(
        mount_prefix,
        choose,
        browser,
        registration,
        account_security,
        false,
        cookie_name,
    )
}

/// Profile variant for hosts that explicitly enable account security and
/// recovery email. Recovery routes require both switches.
pub fn business_profile_with_recovery(
    mount_prefix: &str,
    choose: bool,
    browser: bool,
    registration: bool,
    account_security: bool,
    recovery_email: bool,
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
                "account_security" => account_security,
                "account_security_browser" => account_security && browser,
                "recovery_email" => account_security && recovery_email,
                "recovery_email_browser" => account_security && recovery_email && browser,
                _ => true,
            }
        })
    });
    value["servers"] = json!([{"url": if mount_prefix.is_empty() {"/"} else {mount_prefix}}]);
    value["components"]["securitySchemes"]["RefreshCookie"]["name"] = json!(cookie_name);
    serde_json::from_value(value).unwrap()
}

/// Tenant device surface, intentionally separate from the ordinary entry
/// catalog. Device auth replaces the ordinary login/refresh routes when
/// mounted; callers must not merge both routers for the same entry.
pub fn device_document() -> utoipa::openapi::OpenApi {
    let error = json!({"type":"object","required":["code","message"],"properties":{"code":{"type":"string"},"message":{"type":"string"}},"additionalProperties":false});
    let obj = |fields: &[(&str, Value)]| {
        let mut props = serde_json::Map::new();
        for (name, schema) in fields {
            props.insert((*name).into(), schema.clone());
        }
        json!({"type":"object","properties":props,"required":props.keys().collect::<Vec<_>>(),"additionalProperties":false})
    };
    let string = json!({"type":"string"});
    let integer = json!({"type":"integer","minimum":0});
    let boolean = json!({"type":"boolean"});
    let jwk = json!({"type":"object","description":"Ed25519 public JWK. kid must equal the base64url SHA-256 thumbprint of the canonical RFC 7638 members crv, kty and x; private or unknown fields are rejected.","required":["kty","crv","x","kid"],"properties":{"kty":{"type":"string","enum":["OKP"]},"crv":{"type":"string","enum":["Ed25519"]},"x":{"type":"string","pattern":"^[A-Za-z0-9_-]{43}$"},"kid":{"type":"string","pattern":"^[A-Za-z0-9_-]{43}$"}},"additionalProperties":false});
    let schemas = json!({
      "Error":error,
      "DeviceAdmissionRequired":{"type":"object","required":["error","message"],"properties":{"error":{"type":"string","enum":["device_admission_required"]},"message":{"type":"string"}},"additionalProperties":false},
      "DeviceAdmissionBusy":{"type":"object","required":["error"],"properties":{"error":{"type":"string","enum":["device_admission_busy"]}},"additionalProperties":false},
      "DeviceAuthResult":{"oneOf":[reference("Authenticated"),reference("SelectionRequired")]},
      "ChallengeRequest":obj(&[("tenant_id",string.clone()),("device_id",string.clone()),("purpose",string.clone())]),
      "Provision":obj(&[("tenant_id",string.clone()),("device_id",string.clone()),("registration_request_id",string.clone()),("device_name",string.clone()),("public_jwk",jwk.clone())]),
      "RegistrationResultRequest":obj(&[("tenant_id",string.clone()),("device_id",string.clone()),("registration_request_id",string.clone())]),
      "Complete":obj(&[("tenant_id",string.clone()),("device_id",string.clone()),("public_jwk",jwk.clone()),("challenge",string.clone()),("signature",string.clone())]),
      "Rotate":obj(&[("device_id",string.clone()),("expected_key_id",string.clone()),("expected_key_version",integer.clone()),("proposed_public_jwk",jwk.clone()),("challenge",string.clone()),("current_key_signature",string.clone()),("proposed_key_signature",string.clone())]),
      "Unbind":obj(&[("device_id",string.clone()),("binding_id",string.clone()),("expected_version",integer.clone()),("operation_id",string.clone())]),
      "DeviceBody":obj(&[("device_id",string.clone())]),
      "Device":obj(&[("tenant_id",string.clone()),("device_id",string.clone()),("client_id",string.clone()),("proof_key_id",json!({"type":["string","null"]})),("status",string.clone()),("version",integer.clone()),("key_version",json!({"type":["integer","null"]}))]),
      "Registration":obj(&[("tenant_id",string.clone()),("device_id",string.clone()),("client_id",string.clone()),("proof_key_id",json!({"type":["string","null"]})),("status",string.clone()),("version",integer.clone()),("key_version",json!({"type":["integer","null"]})),("expected_key_id",string.clone()),("created_at_unix_secs",integer.clone()),("expires_at_unix_secs",integer.clone()),("completed_at_unix_secs",json!({"type":["integer","null"]}))]),
      "DeviceKey":obj(&[("tenant_id",string.clone()),("device_id",string.clone()),("key_id",string.clone()),("version",integer.clone())]),
      "KeyMetadata":obj(&[("tenant_id",string.clone()),("device_id",string.clone()),("key_id",string.clone()),("algorithm",string.clone()),("version",integer.clone()),("status",string.clone()),("registered_at_unix_secs",integer.clone()),("retired_at_unix_secs",json!({"type":["integer","null"]}))]),
      "SubjectDevice":obj(&[("tenant_id",string.clone()),("device_id",string.clone()),("client_id",string.clone()),("proof_key_id",string.clone()),("status",string.clone()),("version",integer.clone()),("key_version",integer.clone()),("binding_id",string.clone()),("binding_version",integer.clone()),("device_name",string.clone()),("registered_at_unix_secs",integer.clone()),("last_seen_at_unix_secs",json!({"type":["integer","null"]})),("binding_status",string.clone())]),
      "OperationReceipt":obj(&[("operation_id",string.clone()),("audit_id",string.clone()),("device_id",string.clone()),("binding_id",string.clone()),("operation",string.clone()),("occurred_at_unix_secs",integer.clone()),("result_version",integer.clone()),("result_status",string.clone())]),
      "DevicePage":obj(&[("items",json!({"type":"array","items":reference("SubjectDevice")})),("has_more",boolean.clone()),("next_cursor",json!({"type":["string","null"]}))]),
      "Heartbeat":obj(&[("tenant_id",string.clone()),("device_id",string.clone()),("observed_at_unix_secs",integer.clone())])
    });
    let mut paths = serde_json::Map::new();
    let mut add = |path: &str,
                   method: &str,
                   id: &str,
                   request: Option<&str>,
                   response_schema: &str,
                   status: &str,
                   security: Value,
                   condition: &str,
                   note: &str| {
        let mut op = json!({"operationId":id,"x-mount-condition":condition,"description":note,"responses":{status:{"description":"Success","content":{"application/json":{"schema":reference(response_schema)}}},"400":{"description":"Invalid request","content":{"application/json":{"schema":reference("Error")}}},"401":{"description":"Authentication/admission rejected","content":{"application/json":{"schema":reference("Error")}}},"403":{"description":"Forbidden","content":{"application/json":{"schema":reference("Error")}}},"409":{"description":"Conflict","content":{"application/json":{"schema":reference("Error")}}}},"security":security});
        if path == "/devices/provision" || path == "/devices/registration-result" {
            op["responses"]["401"]["description"] =
                json!("Core error or host admission grant missing/invalid");
            op["responses"]["401"]["content"]["application/json"]["schema"] =
                json!({"oneOf":[reference("Error"),reference("DeviceAdmissionRequired")]});
            op["responses"]["503"] = json!({"description":"Admission verification is at concurrency capacity","content":{"application/json":{"schema":reference("DeviceAdmissionBusy")}}});
        }
        if let Some(name) = request {
            op["requestBody"] =
                json!({"required":true,"content":{"application/json":{"schema":reference(name)}}});
        }
        let mut parameters = Vec::new();
        for part in path.split('/') {
            if let Some(name) = part.strip_prefix('{').and_then(|v| v.strip_suffix('}')) {
                parameters.push(
                    json!({"name":name,"in":"path","required":true,"schema":{"type":"string"}}),
                );
            }
        }
        if path == "/devices" && method == "get" {
            parameters.push(json!({"name":"limit","in":"query","required":false,"schema":{"type":"integer","minimum":1,"maximum":200}}));
            parameters.push(json!({"name":"cursor","in":"query","required":false,"schema":{"type":"string","maxLength":2048}}));
        }
        if !parameters.is_empty() {
            op["parameters"] = json!(parameters);
        }
        op["responses"]["413"] = json!({"description":"Body exceeds 16384 bytes"});
        op["responses"]["415"] = json!({"description":"Unsupported media type"});
        op["responses"]["500"] = json!({"description":"Service failure","content":{"application/json":{"schema":reference("Error")}}});
        for r in op["responses"].as_object_mut().unwrap().values_mut() {
            r["headers"]["Cache-Control"] = json!({"schema":{"type":"string","enum":["no-store"]}});
        }
        let mut item = serde_json::Map::new();
        item.insert(method.into(), op);
        if let Some(previous) = paths.get_mut(path).and_then(Value::as_object_mut) {
            previous.extend(item);
        } else {
            paths.insert(path.into(), Value::Object(item));
        }
    };
    let heartbeat_proof_note = "Bearer subject authentication and all five device proof headers are required: x-device-id, x-device-key-id, x-device-challenge, x-device-signature, and x-device-signed-at. The host-bound EMBEDDED-IDP-DEVICE-REQUEST-V2 profile verifies signature over original raw JSON bytes, HTTP method, externally visible path (including host prefix), audience and tenant; query strings are rejected and JSON reserialization is not used. An optional x-embedded-idp-tenant-id must match the authenticated tenant.";
    let device_auth_note = "Device-enabled v2 entry: this route replaces ordinary login/refresh for that entry. Device proof is optional or required by the configured entry policy; when present it binds the original raw JSON bytes, method, external path and audience using EMBEDDED-IDP-DEVICE-AUTH-V2. Include x-embedded-idp-tenant-id with all five proof headers: x-device-id, x-device-key-id, x-device-challenge, x-device-signature, and x-device-signed-at. Without proof, do not send the tenant assertion header.";
    let post = "post";
    add(
        "/auth/login",
        post,
        "deviceLogin",
        Some("Login"),
        "DeviceAuthResult",
        "200",
        json!([]),
        "always",
        device_auth_note,
    );
    add(
        "/auth/refresh",
        post,
        "deviceRefresh",
        Some("Refresh"),
        "Authenticated",
        "200",
        json!([]),
        "always",
        device_auth_note,
    );
    add(
        "/devices/proof/challenges",
        post,
        "deviceProofChallenge",
        Some("ChallengeRequest"),
        "Challenge",
        "200",
        json!([]),
        "always",
        "Issues a tenant/device/purpose challenge; HTTP 200 only returns a generated challenge and does not prove it was stored or that registration can complete. Registration challenge purpose is device_registration; only a successful complete followed by registration-result confirms completion.",
    );
    add(
        "/auth/tenant-selection/complete",
        post,
        "deviceTenantSelectionComplete",
        Some("Select"),
        "DeviceAuthResult",
        "200",
        json!([{"TenantSelection":[]}]),
        "enabled_choose",
        device_auth_note,
    );
    add(
        "/devices/provision",
        post,
        "deviceProvision",
        Some("Provision"),
        "Registration",
        "201",
        json!([{"DeviceAdmission":[]}]),
        "always",
        "Requires a host-validated short-lived admission grant bound by the host to tenant, client and device; each call is reauthorized. Provision is idempotent only when retried with the original registration_request_id and identical tenant/device/name/public JWK under the same registration scope. Reusing the id with changed fields conflicts. No query credential; the grant is carried in x-embedded-idp-device-admission.",
    );
    add(
        "/devices/registration-result",
        post,
        "deviceRegistrationResult",
        Some("RegistrationResultRequest"),
        "Registration",
        "200",
        json!([{"DeviceAdmission":[]}]),
        "always",
        "Requires a fresh host-validated short-lived admission grant on every call, bound to the same tenant, client and device. The grant's stable registration scope and registration_request_id select the record; a changed scope cannot read it. No query credential; the grant is carried in x-embedded-idp-device-admission. Entry identity is not part of this server-side grant scope.",
    );
    add(
        "/devices/complete",
        post,
        "deviceComplete",
        Some("Complete"),
        "DeviceKey",
        "200",
        json!([]),
        "always",
        "Completes device registration using the public JWK and challenge/signature fields in this JSON body. The registration signature is verified by the device service; HTTP device-proof headers and admission grant are not used by this route. Completion is not idempotent: the one-time challenge and registration are consumed atomically. After an unknown response, query registration-result; do not replay the old signature. A challenge response alone does not prove that its challenge was stored or that completion is possible.",
    );
    add(
        "/devices/rotate-key",
        post,
        "deviceRotateKey",
        Some("Rotate"),
        "DeviceKey",
        "200",
        json!([{"Bearer":[]}]),
        "always",
        "Requires the current authenticated subject and an active device binding, plus Ed25519 signatures from both the current and proposed keys over the same DEVICE-KEY-ROTATION-V2 bytes. expected_key_id and expected_key_version are compare-and-swap preconditions; the service verifies the one-time device_key_rotation challenge, retires the old key, activates the new key, and appends audit atomically. This operation has no idempotency key or receipt; retrying the old challenge/signatures fails. After an unknown response, read the current device pointer and both relevant key metadata under the same active binding. A challenge response does not prove its nonce was persisted.",
    );
    add(
        "/devices",
        "get",
        "deviceList",
        None,
        "DevicePage",
        "200",
        json!([{"Bearer":[]}]),
        "always",
        "Lists only devices bound to the authenticated subject, tenant and client. limit/cursor are query parameters; cursor is scoped.",
    );
    add(
        "/devices/{device_id}",
        "get",
        "deviceDetail",
        None,
        "SubjectDevice",
        "200",
        json!([{"Bearer":[]}]),
        "always",
        "Authenticated subject, tenant and client scope.",
    );
    add(
        "/devices/{device_id}/keys/{key_id}",
        "get",
        "deviceKeyMetadata",
        None,
        "KeyMetadata",
        "200",
        json!([{"Bearer":[]}]),
        "always",
        "Authenticated subject, tenant and client scope.",
    );
    add(
        "/devices/unbind",
        post,
        "deviceUnbind",
        Some("Unbind"),
        "OperationReceipt",
        "200",
        json!([{"Bearer":[]}]),
        "always",
        "Authenticated subject; expected binding version and operation id provide concurrency/idempotency controls.",
    );
    add(
        "/devices/operations/{operation_id}",
        "get",
        "deviceOperationResult",
        None,
        "OperationReceipt",
        "200",
        json!([{"Bearer":[]}]),
        "always",
        "Returns only an operation visible to authenticated subject, tenant and client.",
    );
    add(
        "/devices/heartbeat",
        post,
        "deviceHeartbeat",
        Some("DeviceBody"),
        "Heartbeat",
        "200",
        json!([{"Bearer":[],"DeviceId":[],"DeviceKeyId":[],"DeviceChallenge":[],"DeviceSignature":[],"DeviceSignedAt":[]}]),
        "always",
        heartbeat_proof_note,
    );
    let mut doc = Contract::openapi();
    doc.info.title = "Tenant device-enabled entry HTTP contract".into();
    doc.info.version = env!("CARGO_PKG_VERSION").into();
    doc.info.description=Some("B2 device entry profile. Includes device-auth login/refresh/challenge/conditional selection and all tenant self-service device routes. It replaces ordinary login/refresh routes for the same entry. No scan endpoints. Admission is host-trusted and restricted to provision and registration-result. Registration recovery uses the original request id and fresh admission authorization; complete is a one-time write and must be resolved by reading registration-result. The B2 grant binds tenant/client/device, not entry identity; entry_id isolation is local to SDK state.".into());
    let mut components = serde_json::to_value(&doc.components.as_ref().unwrap().schemas)
        .unwrap()
        .as_object()
        .unwrap()
        .clone();
    components.extend(schemas.as_object().unwrap().clone());
    components.insert(
        "Challenge".into(),
        obj(&[
            ("challenge", string.clone()),
            ("expires_at_unix_secs", integer),
        ]),
    );
    doc.components.as_mut().unwrap().schemas =
        serde_json::from_value(Value::Object(components)).unwrap();
    doc.paths = serde_json::from_value(Value::Object(paths)).unwrap();
    doc.servers = Some(vec![utoipa::openapi::Server::new("/")]);
    let schemes = json!({"Bearer":{"type":"http","scheme":"bearer"},"TenantSelection":{"type":"apiKey","in":"header","name":"Authorization","description":"TenantSelection <opaque ticket>"},"DeviceAdmission":{"type":"apiKey","in":"header","name":"x-embedded-idp-device-admission","description":"Host-issued, short-lived grant token; secret must not appear in URL"},"DeviceId":{"type":"apiKey","in":"header","name":"x-device-id"},"DeviceKeyId":{"type":"apiKey","in":"header","name":"x-device-key-id"},"DeviceChallenge":{"type":"apiKey","in":"header","name":"x-device-challenge"},"DeviceSignature":{"type":"apiKey","in":"header","name":"x-device-signature"},"DeviceSignedAt":{"type":"apiKey","in":"header","name":"x-device-signed-at","description":"Canonical unsigned Unix seconds"}});
    doc.components.as_mut().unwrap().security_schemes = serde_json::from_value(schemes).unwrap();
    doc
}

/// Filter conditional Choose paths and set the host mount prefix.
pub fn device_profile(mount_prefix: &str, choose: bool) -> utoipa::openapi::OpenApi {
    let mut value = serde_json::to_value(device_document()).unwrap();
    value["paths"].as_object_mut().unwrap().retain(|_, item| {
        item.as_object()
            .unwrap()
            .values()
            .all(|op| op["x-mount-condition"] != "enabled_choose")
            || choose
    });
    value["servers"] = json!([{"url":if mount_prefix.is_empty(){"/"}else{mount_prefix}}]);
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
        "operationId":"sharedOidcAuthorize","description":"Requires one Bearer access token. New v2 business composition requires a non-empty code_challenge and code_challenge_method=S256; `plain` is rejected. Successful authorization redirects with 307. This shared endpoint may issue a device-bound code when the selected client is configured with a device profile; its device proof is checked at token exchange.",
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
        "operationId":"sharedOidcToken","description":"Authorization-code exchange only. Supports Basic or form client authentication. The five x-device-* proof headers are optional for clients without a device profile and are accepted only for a host-configured device-enabled client. All five must be present together. Device-bound authorization codes require matching proof; ordinary authorization codes reject supplied proof. Proof binds the original encoded form bytes, POST method, externally visible /oidc/token path, configured audience and tenant.",
        "parameters":[{"name":"x-device-id","in":"header","required":false,"schema":{"type":"string"}},{"name":"x-device-key-id","in":"header","required":false,"schema":{"type":"string"}},{"name":"x-device-challenge","in":"header","required":false,"schema":{"type":"string"}},{"name":"x-device-signature","in":"header","required":false,"schema":{"type":"string"}},{"name":"x-device-signed-at","in":"header","required":false,"schema":{"type":"string","pattern":"^(0|[1-9][0-9]*)$"}}],
        "requestBody":{"required":true,"content":{"application/x-www-form-urlencoded":{"schema":{"type":"object","required":["grant_type","code","redirect_uri","code_verifier"],"properties":{"grant_type":{"type":"string","enum":["authorization_code"]},"code":{"type":"string"},"redirect_uri":{"type":"string"},"client_id":{"type":"string"},"client_secret":{"type":"string"},"code_verifier":{"type":"string","minLength":1}},"additionalProperties":false,"description":"Every authorization code is created with S256 PKCE; code_verifier is required. Proof uses optional HTTP headers, not form fields."}}}},
        "responses":{"200":json_response("Issued token response",schema("TokenResponse")),"400":json_response("OAuth grant or form error",schema("OAuthError")),"401":json_response("Client authentication error",schema("OAuthError")),"413":json_response("Request body exceeds 16384 bytes",schema("OAuthError")),"415":json_response("Unsupported form media type",schema("OAuthError")),"500":json_response("Server error",schema("OAuthError")),"503":{"description":"Password work budget is at capacity","headers":{"Cache-Control":{"schema":{"type":"string","enum":["no-store"]}}},"content":{"application/json":{"schema":schema("OAuthError")}}}},"security":[{"Basic":[]},{}]
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
            "responses":{"200":success,"400":{"description":"OAuth error or form extraction failure","content":{"application/json":{"schema":schema("OAuthError")},"text/plain":{"schema":{"type":"string"}}}},"401":json_response("Client authentication error",schema("OAuthError")),"413":{"description":"Form body exceeds 16384 bytes","content":{"text/plain":{"schema":{"type":"string"}}}},"415":{"description":"Unsupported form media type","content":{"text/plain":{"schema":{"type":"string"}}}},"422":{"description":"Form field extraction failed","content":{"text/plain":{"schema":{"type":"string"}}}},"500":json_response("Server error",schema("Error")),"503":{"description":"Password work budget is at capacity","headers":{"Cache-Control":{"schema":{"type":"string","enum":["no-store"]}}},"content":{"application/json":{"schema":schema("OAuthError")}}}},"security":[{"Basic":[]},{}]
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

/// The scan wire contract is separate from both business-entry and device-auth
/// catalogs. DTO and response fields mirror device_scan_login.rs projections.
pub fn scan_document() -> utoipa::openapi::OpenApi {
    let string = json!({"type":"string"});
    let secret_hash = json!({"type":"string","pattern":"^[A-Za-z0-9_-]{43}$","description":"Unpadded base64url encoding of exactly 32 bytes."});
    let integer = json!({"type":"integer","minimum":0});
    let nullable_string = json!({"type":["string","null"]});
    let nullable_integer = json!({"type":["integer","null"],"minimum":0});
    let scan_state = json!({"type":"string","enum":["waiting_user","waiting_device","awaiting_approval","approved","issued","denied","cancelled","expired","invalidated"]});
    let delivery_state =
        json!({"type":["string","null"],"enum":["recoverable","acknowledged","revoked",null]});
    let next_action = json!({"type":"string","enum":["use_local_session","persist_then_acknowledge","restart","exchange","wait_for_phone_scan","wait_for_device_scan","confirm_on_phone"]});
    let obj = |fields: &[(&str, Value)], optional: &[&str]| {
        let mut properties = serde_json::Map::new();
        for (name, schema) in fields {
            properties.insert((*name).into(), schema.clone());
        }
        let required = properties
            .keys()
            .filter(|key| !optional.contains(&key.as_str()))
            .cloned()
            .collect::<Vec<_>>();
        json!({"type":"object","properties":properties,"required":required,"additionalProperties":false})
    };
    let expected = obj(
        &[
            ("tenant_id", string.clone()),
            ("account_id", string.clone()),
            ("session_id", string.clone()),
            ("client_id", string.clone()),
        ],
        &[],
    );
    let mut schemas = serde_json::Map::new();
    schemas.insert("ExpectedSession".into(), expected.clone());
    schemas.insert(
        "BrowserOnly".into(),
        obj(
            &[(
                "expected_session",
                json!({"oneOf":[reference("ExpectedSession"),{"type":"null"}]}),
            )],
            &["expected_session"],
        ),
    );
    schemas.insert(
        "PhoneCodesRequest".into(),
        obj(
            &[
                ("operation_id", string.clone()),
                ("entry_id", string.clone()),
                ("expected_session", reference("ExpectedSession")),
            ],
            &[],
        ),
    );
    schemas.insert(
        "AttachRequest".into(),
        obj(
            &[
                ("operation_id", string.clone()),
                ("display_code", string.clone()),
                ("expected_session", reference("ExpectedSession")),
            ],
            &[],
        ),
    );
    schemas.insert(
        "GrantRequest".into(),
        obj(
            &[
                ("operation_id", string.clone()),
                ("grant_id", string.clone()),
                ("expected_session", reference("ExpectedSession")),
            ],
            &[],
        ),
    );
    schemas.insert(
        "ReadGrantRequest".into(),
        obj(
            &[
                ("grant_id", string.clone()),
                ("expected_session", reference("ExpectedSession")),
            ],
            &[],
        ),
    );
    schemas.insert(
        "ApprovalRequest".into(),
        obj(
            &[
                ("operation_id", string.clone()),
                ("grant_id", string.clone()),
                ("confirmation_revision", string.clone()),
                ("expected_session", reference("ExpectedSession")),
            ],
            &[],
        ),
    );
    schemas.insert(
        "CreateRequest".into(),
        obj(
            &[
                ("operation_id", string.clone()),
                ("entry_id", string.clone()),
                ("tenant_id", string.clone()),
                ("delivery_secret_hash", secret_hash.clone()),
            ],
            &[],
        ),
    );
    schemas.insert(
        "ClaimRequest".into(),
        obj(
            &[
                ("operation_id", string.clone()),
                ("entry_id", string.clone()),
                ("tenant_id", string.clone()),
                ("scan_code", string.clone()),
                ("delivery_secret_hash", secret_hash),
            ],
            &[],
        ),
    );
    schemas.insert(
        "OperationAccessRequest".into(),
        obj(
            &[
                ("operation_id", string.clone()),
                ("grant_id", string.clone()),
                ("delivery_secret", string.clone()),
                ("tenant_id", string.clone()),
            ],
            &[],
        ),
    );
    schemas.insert(
        "ReadAccessRequest".into(),
        obj(
            &[
                ("grant_id", string.clone()),
                ("delivery_secret", string.clone()),
                ("tenant_id", string.clone()),
            ],
            &[],
        ),
    );
    let origin_action = json!({"type":"string","enum":["create","claim"]});
    schemas.insert(
        "LookupRequest".into(),
        obj(
            &[
                (
                    "origin_action",
                    json!({"oneOf":[origin_action.clone(),{"type":"null"}]}),
                ),
                ("origin_operation_id", string.clone()),
                ("entry_id", string.clone()),
                ("tenant_id", string.clone()),
                ("delivery_secret", string.clone()),
            ],
            &["origin_action"],
        ),
    );
    schemas.insert(
        "CloseOriginRequest".into(),
        obj(
            &[
                ("entry_id", string.clone()),
                ("tenant_id", string.clone()),
                ("origin_action", origin_action.clone()),
                ("origin_operation_id", string.clone()),
                ("delivery_secret", string.clone()),
            ],
            &[],
        ),
    );
    schemas.insert(
        "RecoverRequest".into(),
        obj(
            &[
                ("issuance_operation_id", string.clone()),
                ("grant_id", string.clone()),
                ("delivery_secret", string.clone()),
                ("tenant_id", string.clone()),
            ],
            &[],
        ),
    );
    schemas.insert(
        "AcknowledgeRequest".into(),
        obj(
            &[
                ("operation_id", string.clone()),
                ("issuance_operation_id", string.clone()),
                ("grant_id", string.clone()),
                ("delivery_secret", string.clone()),
                ("receipt_nonce", string.clone()),
                ("tenant_id", string.clone()),
            ],
            &[],
        ),
    );
    schemas.insert(
        "AbortRequest".into(),
        obj(
            &[
                ("operation_id", string.clone()),
                ("issuance_operation_id", string.clone()),
                ("grant_id", string.clone()),
                ("delivery_secret", string.clone()),
                ("tenant_id", string.clone()),
            ],
            &[],
        ),
    );
    schemas.insert("ScanEntry".into(), obj(&[("entry_id",string.clone()),("target_client_id",string.clone()),("modes",json!({"type":"array","minItems":1,"uniqueItems":true,"items":{"type":"string","enum":["device_display","phone_display"]}}))], &[]));
    schemas.insert(
        "BrowserContext".into(),
        obj(
            &[
                ("tenant_id", string.clone()),
                ("account_id", string.clone()),
                ("session_id", string.clone()),
                ("client_id", string.clone()),
                ("entry", reference("ScanEntry")),
            ],
            &[],
        ),
    );
    schemas.insert(
        "ScanProgress".into(),
        obj(
            &[
                ("grant_id", string.clone()),
                (
                    "mode",
                    json!({"type":"string","enum":["device_display","phone_display"]}),
                ),
                ("state", scan_state),
                ("version", integer.clone()),
                ("server_time_unix_secs", integer.clone()),
                ("expires_at_unix_secs", integer.clone()),
                ("code_expires_at_unix_secs", integer.clone()),
                ("approved_until_unix_secs", nullable_integer.clone()),
                ("expires_in", integer.clone()),
                ("poll_after_ms", integer.clone()),
                ("delivery_state", delivery_state),
                ("issuance_operation_id", nullable_string.clone()),
                ("recover_until_unix_secs", nullable_integer.clone()),
                ("next_action", next_action),
            ],
            &[],
        ),
    );
    schemas.insert(
        "PhoneCodesResponse".into(),
        obj(
            &[
                ("progress", reference("ScanProgress")),
                ("scan_code", string.clone()),
                ("code_expires_at_unix_secs", integer.clone()),
            ],
            &[],
        ),
    );
    schemas.insert(
        "ScanConfirmation".into(),
        obj(
            &[
                ("progress", reference("ScanProgress")),
                (
                    "source",
                    obj(
                        &[
                            ("account_id", string.clone()),
                            ("session_id", string.clone()),
                            ("client_id", string.clone()),
                            ("display_name", string.clone()),
                        ],
                        &[],
                    ),
                ),
                (
                    "target",
                    obj(
                        &[
                            ("device_id", string.clone()),
                            ("display_name", string.clone()),
                            ("identification", string.clone()),
                            ("context_label", nullable_string.clone()),
                            ("revision", string.clone()),
                        ],
                        &[],
                    ),
                ),
                ("confirmation_revision", string.clone()),
            ],
            &[],
        ),
    );
    schemas.insert(
        "CreateResponse".into(),
        obj(
            &[
                ("progress", reference("ScanProgress")),
                ("display_code", string.clone()),
                ("verification_uri", string.clone()),
            ],
            &[],
        ),
    );
    schemas.insert(
        "LookupResponse".into(),
        obj(
            &[
                ("progress", reference("ScanProgress")),
                ("origin_operation_id", string.clone()),
                ("display_code", nullable_string.clone()),
            ],
            &[],
        ),
    );
    schemas.insert(
        "CloseOriginResponse".into(),
        obj(
            &[
                ("origin_action", origin_action.clone()),
                ("origin_operation_id", string.clone()),
                (
                    "outcome",
                    json!({"type":"string","enum":["closed","already_activated"]}),
                ),
                ("closed_at_unix_secs", nullable_integer.clone()),
                (
                    "progress",
                    json!({"oneOf":[reference("ScanProgress"),{"type":"null"}]}),
                ),
            ],
            &[],
        ),
    );
    schemas.insert(
        "DeliveryProgress".into(),
        obj(&[("progress", reference("ScanProgress"))], &[]),
    );
    schemas.insert(
        "DeliveryBundle".into(),
        obj(
            &[
                ("progress", reference("ScanProgress")),
                ("receipt_nonce", string.clone()),
                (
                    "session",
                    obj(
                        &[
                            ("tenant_id", string.clone()),
                            ("account_id", string.clone()),
                            ("session_id", string.clone()),
                            ("client_id", string.clone()),
                            ("expires_at_unix_secs", integer.clone()),
                        ],
                        &[],
                    ),
                ),
                (
                    "tokens",
                    obj(
                        &[
                            ("access_token", string.clone()),
                            ("refresh_token", string.clone()),
                            ("access_expires_at_unix_secs", integer.clone()),
                            ("refresh_expires_at_unix_secs", integer.clone()),
                        ],
                        &[],
                    ),
                ),
            ],
            &[],
        ),
    );
    schemas.insert("DeliveryResponse".into(), json!({"oneOf":[reference("DeliveryProgress"),reference("DeliveryBundle")],"description":"Exchange/recover may return progress while delivery is pending, or a token bundle that remains Pending until acknowledge succeeds."}));
    schemas.insert(
        "ScanError".into(),
        obj(
            &[
                ("error", string.clone()),
                ("message", string.clone()),
                ("request_id", nullable_string.clone()),
                ("retryable", json!({"type":"boolean"})),
                ("terminal", json!({"type":"boolean"})),
            ],
            &[],
        ),
    );
    schemas.insert(
        "ExchangeAlreadyStarted".into(),
        obj(
            &[
                (
                    "error",
                    json!({"type":"string","enum":["exchange_already_started"]}),
                ),
                ("message", string.clone()),
                ("request_id", nullable_string),
                ("retryable", json!({"type":"boolean"})),
                ("issuance_operation_id", string.clone()),
            ],
            &[],
        ),
    );
    let mut paths = serde_json::Map::new();
    let browser = [
        (
            "/context",
            "scanBrowserContext",
            "BrowserOnly",
            "BrowserContext",
            "Returns the authenticated source identity and configured scan entry.",
        ),
        (
            "/phone-codes",
            "scanBrowserPhoneCodes",
            "PhoneCodesRequest",
            "PhoneCodesResponse",
            "Issues a phone-display scan code.",
        ),
        (
            "/attach",
            "scanBrowserAttach",
            "AttachRequest",
            "ScanConfirmation",
            "Attaches the source session to a device display code.",
        ),
        (
            "/inspect",
            "scanBrowserInspect",
            "ReadGrantRequest",
            "ScanConfirmation",
            "Returns confirmation details for the source session.",
        ),
        (
            "/approve",
            "scanBrowserApprove",
            "ApprovalRequest",
            "ScanProgress",
            "Records approval; this does not activate the target session.",
        ),
        (
            "/deny",
            "scanBrowserDeny",
            "GrantRequest",
            "ScanProgress",
            "Denies the pending source grant.",
        ),
        (
            "/cancel",
            "scanBrowserCancel",
            "GrantRequest",
            "ScanProgress",
            "Cancels the pending source grant.",
        ),
        (
            "/status",
            "scanBrowserStatus",
            "ReadGrantRequest",
            "ScanProgress",
            "Returns source-scoped progress.",
        ),
    ];
    let device = [
        (
            "/create",
            "scanDeviceCreate",
            "CreateRequest",
            "CreateResponse",
            "Creates a device-display origin. For an unknown response, retry with the exact same operation_id, entry_id, tenant_id and delivery_secret_hash; persist the original operation_id and delivery secret so lookup can recover the result.",
        ),
        (
            "/claim",
            "scanDeviceClaim",
            "ClaimRequest",
            "ScanProgress",
            "Claims a phone-display code. For an unknown response, retry with the exact same operation_id and request values, then retain the original operation_id and delivery secret for lookup/recovery.",
        ),
        (
            "/status",
            "scanDeviceStatus",
            "ReadAccessRequest",
            "ScanProgress",
            "Returns delivery progress.",
        ),
        (
            "/lookup",
            "scanDeviceLookup",
            "LookupRequest",
            "LookupResponse",
            "Looks up an origin; origin_action is optional for compatibility. A scan_not_found 404 is nonterminal: retain the original create/claim action, operation_id and delivery secret, and retry lookup; do not create a replacement origin solely because of this response.",
        ),
        (
            "/cancel",
            "scanDeviceCancel",
            "OperationAccessRequest",
            "ScanProgress",
            "Cancels a device-side grant.",
        ),
        (
            "/exchange",
            "scanDeviceExchange",
            "OperationAccessRequest",
            "DeliveryResponse",
            "Starts delivery using the operation_id as the fixed issuance_operation_id. On exchange_already_started, use the returned existing issuance_operation_id. Delivery may be progress-only or a token bundle; the bundle remains Pending until acknowledge succeeds.",
        ),
        (
            "/recover",
            "scanDeviceRecover",
            "RecoverRequest",
            "DeliveryResponse",
            "Recovers delivery using the original issuance_operation_id; it does not issue a second session. The response may be progress-only (including after acknowledgement) or the same pending bundle.",
        ),
        (
            "/acknowledge",
            "scanDeviceAcknowledge",
            "AcknowledgeRequest",
            "ScanProgress",
            "Acknowledges receipt and activates the pending target session. The response contains progress only, never the bundle; delivery_state=acknowledged confirms activation. After an unknown response, recover/query status before deciding whether to retry, and expose the locally persisted session only after confirmation.",
        ),
        (
            "/abort",
            "scanDeviceAbort",
            "AbortRequest",
            "ScanProgress",
            "Aborts a pending delivery. HTTP 409 already_acknowledged means acknowledgement won the race and the target session is already active; preserve the bundle/session and recover or query status. Abort is not logout.",
        ),
        (
            "/close-origin",
            "scanDeviceCloseOrigin",
            "CloseOriginRequest",
            "CloseOriginResponse",
            "Closes an origin or reports that it was already activated. already_activated means delivery was acknowledged and the target session is active; close-origin does not revoke or log out that session.",
        ),
    ];
    let api_ref = |name: &str| reference(name);
    for (side, operations) in [
        ("browser", browser.as_slice()),
        ("device", device.as_slice()),
    ] {
        for (path, id, request, success, description) in operations {
            let mut parameters = Vec::new();
            if side == "browser" {
                parameters.push(json!({"name":"Origin","in":"header","required":true,"schema":{"type":"string"},"description":"Must exactly match configured browser origin; duplicate values rejected."}));
                parameters.push(json!({"name":"x-embedded-idp-browser","in":"header","required":true,"schema":{"type":"string","enum":["1"]}}));
                parameters.push(json!({"name":"Sec-Fetch-Site","in":"header","required":false,"schema":{"type":"string","enum":["same-origin"]},"description":"If supplied, exactly same-origin; duplicate values rejected."}));
            } else {
                for (name, note, schema) in [
                    (
                        "x-device-id",
                        "Device identifier; non-empty visible ASCII, at most 128 bytes.",
                        json!({"type":"string","minLength":1,"maxLength":128,"pattern":"^[!-~]+$"}),
                    ),
                    (
                        "x-device-key-id",
                        "Registered 32-byte Ed25519 key thumbprint, unpadded base64url.",
                        json!({"type":"string","pattern":"^[A-Za-z0-9_-]{43}$"}),
                    ),
                    (
                        "x-device-challenge",
                        "32-byte proof challenge, unpadded base64url.",
                        json!({"type":"string","pattern":"^[A-Za-z0-9_-]{43}$"}),
                    ),
                    (
                        "x-device-signature",
                        "64-byte Ed25519 signature, unpadded base64url.",
                        json!({"type":"string","pattern":"^[A-Za-z0-9_-]{86}$"}),
                    ),
                    (
                        "x-device-signed-at",
                        "Canonical unsigned Unix seconds; no sign or leading zero except 0.",
                        json!({"type":"string","minLength":1,"maxLength":20,"pattern":"^(0|[1-9][0-9]*)$"}),
                    ),
                ] {
                    parameters.push(json!({"name":name,"in":"header","required":true,"schema":schema,"description":note}));
                }
            }
            let proof = if side == "device" {
                " Proof profile is EMBEDDED-IDP-DEVICE-SCAN-V2. The signed bytes bind the proof fields (challenge, device id, key id, signed-at) to exact raw body bytes, POST method, externally prefixed path, tenant and configured audience, then append scan-context-sha256 as unpadded base64url. This is SHA-256 of the domain separator EMBEDDED-IDP-SCAN-CONTEXT-V1 plus length-prefixed canonical purpose_str, trusted target_client_id and entry_id. These trusted route-context values are not taken from request headers or body. Duplicate proof headers, query parameters and changed body are rejected. TrustedScanHostContext must also be injected by the host."
            } else {
                " Browser guard requires configured exact Origin and x-embedded-idp-browser: 1, rejects tenant header, and accepts Sec-Fetch-Site only when absent or exactly same-origin. Cookie name/origin are host-profile values; expected_session is checked against the authenticated browser identity."
            };
            let error_schema = if *id == "scanDeviceExchange" {
                json!({"oneOf":[api_ref("ScanError"),api_ref("ExchangeAlreadyStarted")]})
            } else {
                api_ref("ScanError")
            };
            let success_status = if *id == "scanBrowserPhoneCodes" || *id == "scanDeviceCreate" {
                "201"
            } else {
                "200"
            };
            let security = if side == "browser" {
                json!([{"BrowserOrigin":[],"BrowserHeader":[],"BrowserCookie":[]}])
            } else {
                json!([{"DeviceId":[],"DeviceKeyId":[],"DeviceChallenge":[],"DeviceSignature":[],"DeviceSignedAt":[]}])
            };
            let mut op = json!({"operationId":id,"description":format!("{} POST JSON; body limit 16384 bytes; strict DTO rejects unknown members and duplicate JSON keys. All responses use Cache-Control: no-store.{}",description,proof),"x-scan-side":side,"parameters":parameters,"requestBody":{"required":true,"content":{"application/json":{"schema":api_ref(request)}}},"responses":{success_status:{"description":description,"content":{"application/json":{"schema":api_ref(success)}}},"400":{"description":"Invalid request or proof mismatch","content":{"application/json":{"schema":api_ref("ScanError")}}},"401":{"description":"Invalid or expired browser session","content":{"application/json":{"schema":api_ref("ScanError")}}},"403":{"description":"Boundary, admission, host-context or proof rejected","content":{"application/json":{"schema":api_ref("ScanError")}}},"404":{"description":"Scan not found","content":{"application/json":{"schema":api_ref("ScanError")}}},"409":{"description":"Conflict; exchange may return exchange_already_started","content":{"application/json":{"schema":error_schema}}},"410":{"description":"Expired or closed scan/delivery","content":{"application/json":{"schema":api_ref("ScanError")}}},"429":{"description":"Scan rate limit exceeded","content":{"application/json":{"schema":api_ref("ScanError")}}},"503":{"description":"Storage or host configuration unavailable","content":{"application/json":{"schema":api_ref("ScanError")}}}},"security":security});
            if side == "device" {
                op["responses"]["413"] = json!({"description":"JSON body exceeds 16384 bytes","content":{"application/json":{"schema":api_ref("ScanError")}}});
                op["responses"]["415"] = json!({"description":"Unsupported JSON media type","content":{"application/json":{"schema":api_ref("ScanError")}}});
            }
            if side == "browser" {
                let responses = op["responses"].as_object_mut().unwrap();
                responses.remove("413");
                responses.remove("415");
            }
            for response in op["responses"].as_object_mut().unwrap().values_mut() {
                response["headers"]["Cache-Control"] =
                    json!({"schema":{"type":"string","enum":["no-store"]}});
            }
            let root = if side == "browser" {
                "/auth/browser/device-scan"
            } else {
                "/auth/device-scan"
            };
            let full_path = format!("{root}/{}", path.trim_start_matches('/'));
            paths
                .entry(full_path)
                .or_insert_with(|| json!({}))
                .as_object_mut()
                .unwrap()
                .insert("post".into(), op);
        }
    }
    let value = json!({"openapi":"3.1.0","info":{"title":"Device scan login HTTP contract","version":env!("CARGO_PKG_VERSION"),"description":"Independent 18-operation scan contract. Browser (8) and device (10) routers are mounted separately with host-selected prefixes. Scan modes are configured per entry; UI assets are not part of this JSON API contract."},"servers":[{"url":"/"}],"paths":paths,"components":{"securitySchemes":{"BrowserOrigin":{"type":"apiKey","in":"header","name":"Origin","description":"Exact configured origin; host-specific."},"BrowserHeader":{"type":"apiKey","in":"header","name":"x-embedded-idp-browser","description":"Exactly 1."},"BrowserCookie":{"type":"apiKey","in":"cookie","name":"HOST_CONFIGURED_COOKIE","description":"Placeholder only: substitute the entry-specific BrowserSessionHttpConfig cookie_name; no global cookie name."},"DeviceId":{"type":"apiKey","in":"header","name":"x-device-id"},"DeviceKeyId":{"type":"apiKey","in":"header","name":"x-device-key-id"},"DeviceChallenge":{"type":"apiKey","in":"header","name":"x-device-challenge"},"DeviceSignature":{"type":"apiKey","in":"header","name":"x-device-signature"},"DeviceSignedAt":{"type":"apiKey","in":"header","name":"x-device-signed-at"}},"schemas":schemas}});
    serde_json::from_value(value).unwrap()
}

/// Applies the two independently validated router prefixes without joining the
/// browser and device route families into a single router/profile.
pub fn scan_profile(browser_prefix: &str, device_prefix: &str) -> utoipa::openapi::OpenApi {
    let mut value = serde_json::to_value(scan_document()).unwrap();
    let previous_paths = std::mem::take(value["paths"].as_object_mut().unwrap());
    let mut paths = serde_json::Map::new();
    for (path, mut item) in previous_paths {
        let side = item["post"]["x-scan-side"].as_str().unwrap();
        let (module_root, prefix) = if side == "browser" {
            ("/auth/browser/device-scan", browser_prefix)
        } else {
            ("/auth/device-scan", device_prefix)
        };
        item["post"].as_object_mut().unwrap().remove("x-scan-side");
        let suffix = path.strip_prefix(module_root).unwrap();
        let prefix = prefix.trim_end_matches('/');
        let path = if prefix.is_empty() {
            suffix.to_string()
        } else {
            format!("{prefix}{suffix}")
        };
        paths.insert(path, item);
    }
    value["paths"] = Value::Object(paths);
    value["servers"] = json!([{"url":"/"}]);
    serde_json::from_value(value).unwrap()
}
