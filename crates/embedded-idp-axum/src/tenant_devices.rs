use crate::{
    http_support::{bearer_token, unix_time_secs},
    proof_http::*,
    tenant_auth::{call, map_tenant_auth_error, no_store, tenant_error, tenant_header_matches},
    tenant_device_auth::raw_json,
};
use axum::{
    extract::{DefaultBodyLimit, OriginalUri, Path, Query, Request, State},
    http::{header, HeaderMap, StatusCode},
    middleware,
    response::{IntoResponse, Response},
    routing::{get, post},
    Extension, Json, Router,
};
use base64ct::{Base64UrlUnpadded, Encoding};
use embedded_idp_core::{
    access::*, AccountDeviceBindingStatus, CanonicalHttpMethod, DeviceProofProfile,
    DeviceProofPurpose, DeviceStatus, SecretString,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, value::RawValue, Value};
use std::sync::Arc;

#[derive(Clone)]
pub struct TenantDeviceHttpConfig {
    heartbeat: ProtectedRouteConfig,
}
impl TenantDeviceHttpConfig {
    pub fn new(audience: &str, heartbeat_path: &str) -> Result<Self, ProofHttpError> {
        Ok(Self {
            heartbeat: ProtectedRouteConfig::new(
                DeviceProofProfile::new("EMBEDDED-IDP-DEVICE-REQUEST-V2")
                    .map_err(|_| ProofHttpError::ProofInvalid)?,
                audience,
                CanonicalHttpMethod::Post,
                heartbeat_path,
            )?,
        })
    }
}
#[derive(Clone)]
struct DeviceState {
    service: Arc<dyn TenantDeviceService>,
    admission: Arc<dyn TenantDeviceAdmission>,
    config: TenantDeviceHttpConfig,
}
/// Self-service device routes. Merge once with tenant_device_auth_router, which
/// owns the shared challenge endpoint. No default provisioning admission policy.
pub fn tenant_device_router(
    service: Arc<dyn TenantDeviceService>,
    admission: Arc<dyn TenantDeviceAdmission>,
    config: TenantDeviceHttpConfig,
) -> Router {
    Router::new()
        .route("/devices/provision", post(provision))
        .route("/devices/registration-result", post(registration_result))
        .route("/devices/complete", post(complete))
        .route("/devices/rotate-key", post(rotate))
        .route("/devices", get(list))
        .route("/devices/:device_id", get(detail))
        .route("/devices/:device_id/keys/:key_id", get(key_metadata))
        .route("/devices/unbind", post(unbind))
        .route("/devices/operations/:operation_id", get(operation_result))
        .route("/devices/heartbeat", post(heartbeat))
        .with_state(DeviceState {
            service,
            admission,
            config,
        })
        .layer(DefaultBodyLimit::max(AUTH_DEVICE_BODY_LIMIT_BYTES))
        .layer(middleware::from_fn(no_store))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProvisionBody {
    tenant_id: String,
    device_id: String,
    registration_request_id: String,
    device_name: String,
    public_jwk: Box<RawValue>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RegistrationResultBody {
    tenant_id: String,
    device_id: String,
    registration_request_id: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CompleteBody {
    tenant_id: String,
    device_id: String,
    public_jwk: Box<RawValue>,
    challenge: String,
    signature: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RotateBody {
    device_id: String,
    expected_key_id: String,
    expected_key_version: u64,
    proposed_public_jwk: Box<RawValue>,
    challenge: String,
    current_key_signature: String,
    proposed_key_signature: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeviceBody {
    device_id: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UnbindBody {
    device_id: String,
    binding_id: String,
    expected_version: u64,
    operation_id: String,
}
fn operation_receipt_json(r: DeviceOperationReceipt) -> Value {
    json!({"operation_id":r.operation_id,"audit_id":r.audit_id,"device_id":r.device_id,
        "binding_id":r.binding_id,"operation":r.operation,"occurred_at_unix_secs":unix_time_secs(r.occurred_at),
        "result_version":r.result_version,"result_status":r.result_status})
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PageQuery {
    limit: Option<u32>,
    cursor: Option<String>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeviceCursor {
    version: u8,
    tenant_id: String,
    subject_id: String,
    client_id: String,
    after: String,
}
pub(super) fn device_json(d: TenantProofDevice) -> Value {
    json!({"tenant_id":d.tenant_id,"device_id":d.id,"client_id":d.client_id,"proof_key_id":d.proof_key_id,"status":match d.status {DeviceStatus::Pending=>"pending",DeviceStatus::Active=>"active",DeviceStatus::Disabled=>"disabled",DeviceStatus::Revoked=>"revoked"},"version":d.version,"key_version":d.key_version})
}
fn registration_json(r: DeviceRegistrationResult) -> Value {
    let mut value = device_json(r.device);
    value["expected_key_id"] = json!(r.expected_key_id);
    value["created_at_unix_secs"] = json!(unix_time_secs(r.created_at));
    value["expires_at_unix_secs"] = json!(unix_time_secs(r.expires_at));
    value["completed_at_unix_secs"] = json!(r.completed_at.map(unix_time_secs));
    value
}
fn subject_device_json(r: TenantSubjectDevice) -> Value {
    let mut body = device_json(r.device);
    body["binding_id"] = json!(r.binding_id);
    body["binding_version"] = json!(r.binding_version);
    body["device_name"] = json!(r.name);
    body["registered_at_unix_secs"] = json!(unix_time_secs(r.registered_at));
    body["last_seen_at_unix_secs"] = json!(r.last_seen_at.map(unix_time_secs));
    body["binding_status"] = json!(match r.binding_status {
        AccountDeviceBindingStatus::Active => "active",
        AccountDeviceBindingStatus::Suspended => "suspended",
        AccountDeviceBindingStatus::Unbound => "unbound",
    });
    body
}
fn key_json(k: TenantProofKey) -> Response {
    Json(json!({"tenant_id":k.tenant_id,"device_id":k.device_id,"key_id":k.key_id,"version":k.version})).into_response()
}
pub(super) fn key_metadata_json(k: DeviceKeyMetadata) -> Value {
    json!({"tenant_id":k.tenant_id,"device_id":k.device_id,"key_id":k.key_id,"algorithm":k.algorithm,
        "version":k.version,"status":match k.status {embedded_idp_core::DeviceProofKeyStatus::Active=>"active",embedded_idp_core::DeviceProofKeyStatus::Retired=>"retired"},
        "registered_at_unix_secs":unix_time_secs(k.registered_at),"retired_at_unix_secs":k.retired_at.map(unix_time_secs)})
}
async fn key_metadata(
    State(state): State<DeviceState>,
    headers: HeaderMap,
    Path((device, key)): Path<(String, String)>,
) -> Response {
    let actor = match actor(&state, &headers).await {
        Ok(actor) => actor,
        Err(response) => return response,
    };
    match call(move || state.service.key_metadata(actor, device, key)).await {
        Ok(metadata) => Json(key_metadata_json(metadata)).into_response(),
        Err(error) => device_error(error),
    }
}
async fn actor(state: &DeviceState, headers: &HeaderMap) -> Result<AccessActor, Response> {
    if headers.get_all(header::AUTHORIZATION).iter().count() != 1 {
        return Err(map_tenant_auth_error(TenantAuthError::InvalidSession));
    }
    let raw = bearer_token(headers)
        .filter(|s| s.len() <= 16384)
        .map(SecretString::new)
        .ok_or_else(|| map_tenant_auth_error(TenantAuthError::InvalidSession))?;
    let service = state.service.clone();
    let actor = call(move || service.authenticate(raw))
        .await
        .map_err(map_tenant_auth_error)?;
    if !tenant_header_matches(headers, &actor.tenant_id) {
        return Err(map_tenant_auth_error(TenantAuthError::InvalidSession));
    }
    Ok(actor)
}
async fn provision(
    State(state): State<DeviceState>,
    trusted: Option<Extension<TrustedDeviceAdmission>>,
    headers: HeaderMap,
    Json(body): Json<ProvisionBody>,
) -> Response {
    if !tenant_header_matches(&headers, &body.tenant_id) {
        return bad_request();
    }
    let Some(Extension(trusted)) = trusted else {
        return tenant_error(
            StatusCode::UNAUTHORIZED,
            "device_admission_required",
            "device admission is required",
        );
    };
    match call(move || {
        state.service.provision(
            ProvisionTenantDevice {
                tenant_id: body.tenant_id,
                device_id: body.device_id,
                registration_request_id: body.registration_request_id,
                device_name: body.device_name,
                public_jwk: body.public_jwk.get().into(),
            },
            &trusted,
            state.admission.as_ref(),
        )
    })
    .await
    {
        Ok(result) => (StatusCode::CREATED, Json(registration_json(result))).into_response(),
        Err(e) => device_error(e),
    }
}
async fn registration_result(
    State(state): State<DeviceState>,
    trusted: Option<Extension<TrustedDeviceAdmission>>,
    headers: HeaderMap,
    Json(body): Json<RegistrationResultBody>,
) -> Response {
    if !tenant_header_matches(&headers, &body.tenant_id) {
        return bad_request();
    }
    let Some(Extension(trusted)) = trusted else {
        return tenant_error(
            StatusCode::UNAUTHORIZED,
            "device_admission_required",
            "device admission is required",
        );
    };
    match call(move || {
        state.service.registration_result(
            DeviceRegistrationLookup {
                tenant_id: body.tenant_id,
                device_id: body.device_id,
                registration_request_id: body.registration_request_id,
            },
            &trusted,
            state.admission.as_ref(),
        )
    })
    .await
    {
        Ok(result) => Json(registration_json(result)).into_response(),
        Err(e) => device_error(e),
    }
}
async fn complete(
    State(state): State<DeviceState>,
    headers: HeaderMap,
    Json(body): Json<CompleteBody>,
) -> Response {
    if !tenant_header_matches(&headers, &body.tenant_id) {
        return bad_request();
    }
    match call(move || {
        state.service.complete(CompleteTenantDeviceRegistration {
            tenant_id: body.tenant_id,
            device_id: body.device_id,
            public_jwk: body.public_jwk.get().into(),
            challenge: SecretString::new(body.challenge),
            signature: SecretString::new(body.signature),
        })
    })
    .await
    {
        Ok(key) => key_json(key),
        Err(e) => device_error(e),
    }
}
async fn rotate(
    State(state): State<DeviceState>,
    headers: HeaderMap,
    Json(body): Json<RotateBody>,
) -> Response {
    let actor = match actor(&state, &headers).await {
        Ok(a) => a,
        Err(r) => return r,
    };
    match call(move || {
        state.service.rotate(RotateTenantDeviceKey {
            actor,
            device_id: body.device_id,
            expected_key_id: body.expected_key_id,
            expected_key_version: body.expected_key_version,
            proposed_public_jwk: body.proposed_public_jwk.get().into(),
            challenge: SecretString::new(body.challenge),
            current_key_signature: SecretString::new(body.current_key_signature),
            proposed_key_signature: SecretString::new(body.proposed_key_signature),
        })
    })
    .await
    {
        Ok(k) => key_json(k),
        Err(e) => device_error(e),
    }
}
async fn list(
    State(state): State<DeviceState>,
    headers: HeaderMap,
    Query(query): Query<PageQuery>,
) -> Response {
    let actor = match actor(&state, &headers).await {
        Ok(a) => a,
        Err(r) => return r,
    };
    let cursor = match query.cursor {
        None => None,
        Some(raw) => {
            if raw.len() > 2048 {
                return bad_request();
            }
            let cursor = Base64UrlUnpadded::decode_vec(&raw)
                .ok()
                .and_then(|b| serde_json::from_slice::<DeviceCursor>(&b).ok());
            let Some(c) = cursor else {
                return bad_request();
            };
            Some(AccessCursor {
                version: c.version,
                scope: AccessListScope::SubjectDevices {
                    tenant_id: c.tenant_id,
                    subject_id: c.subject_id,
                    client_id: c.client_id,
                },
                after: vec![c.after],
                sort_order: None,
            })
        }
    };
    match call(move || {
        state.service.devices(
            actor,
            AccessPageRequest {
                limit: query.limit.unwrap_or(50),
                cursor,
                sort_order: None,
            },
        )
    })
    .await
    {
        Ok(page) => {
            let next = match page.next_cursor {
                None => None,
                Some(c) => {
                    let AccessListScope::SubjectDevices {
                        tenant_id,
                        subject_id,
                        client_id,
                    } = c.scope
                    else {
                        return device_error(AccessError::InvalidStoreResponse.into());
                    };
                    if c.after.len() != 1 {
                        return device_error(AccessError::InvalidStoreResponse.into());
                    }
                    let bytes = serde_json::to_vec(&DeviceCursor {
                        version: c.version,
                        tenant_id,
                        subject_id,
                        client_id,
                        after: c.after[0].clone(),
                    })
                    .unwrap();
                    Some(Base64UrlUnpadded::encode_string(&bytes))
                }
            };
            Json(json!({"items":page.items.into_iter().map(subject_device_json).collect::<Vec<_>>(),"has_more":page.has_more,"next_cursor":next})).into_response()
        }
        Err(e) => device_error(e),
    }
}
async fn detail(
    State(state): State<DeviceState>,
    Path(device): Path<String>,
    headers: HeaderMap,
) -> Response {
    let actor = match actor(&state, &headers).await {
        Ok(a) => a,
        Err(r) => return r,
    };
    match call(move || state.service.device(actor, device)).await {
        Ok(d) => Json(subject_device_json(d)).into_response(),
        Err(e) => device_error(e),
    }
}
async fn unbind(
    State(state): State<DeviceState>,
    headers: HeaderMap,
    Json(body): Json<UnbindBody>,
) -> Response {
    let actor = match actor(&state, &headers).await {
        Ok(a) => a,
        Err(r) => return r,
    };
    match call(move || {
        state.service.unbind(
            actor,
            body.device_id,
            body.binding_id,
            body.expected_version,
            body.operation_id,
        )
    })
    .await
    {
        Ok(receipt) => Json(operation_receipt_json(receipt)).into_response(),
        Err(e) => device_error(e),
    }
}
async fn operation_result(
    State(state): State<DeviceState>,
    headers: HeaderMap,
    Path(operation_id): Path<String>,
) -> Response {
    let actor = match actor(&state, &headers).await {
        Ok(actor) => actor,
        Err(response) => return response,
    };
    match call(move || state.service.operation_result(actor, operation_id)).await {
        Ok(receipt) => Json(operation_receipt_json(receipt)).into_response(),
        Err(error) => device_error(error),
    }
}
async fn heartbeat(
    State(state): State<DeviceState>,
    OriginalUri(uri): OriginalUri,
    request: Request,
) -> Response {
    let (body, headers, method, digest) = match raw_json::<DeviceBody>(request).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let actor = match actor(&state, &headers).await {
        Ok(a) => a,
        Err(r) => return r,
    };
    let proof = match parse_device_proof_headers(&headers) {
        Ok(p) if p.device_id == body.device_id => p,
        _ => return device_error(TenantAuthError::DeviceProofRequired),
    };
    let binding =
        match state
            .config
            .heartbeat
            .binding_for_request(&actor.tenant_id, &method, &uri, digest)
        {
            Ok(b) => b,
            Err(_) => return bad_request(),
        };
    match call(move||state.service.heartbeat(VerifyTenantDeviceRequest{actor,expected_purpose:DeviceProofPurpose::new(TENANT_DEVICE_HEARTBEAT_PURPOSE).unwrap(),proof,binding})).await {
        Ok(v)=>Json(json!({"tenant_id":v.tenant_id,"device_id":v.device_id,"observed_at_unix_secs":unix_time_secs(v.verified_at)})).into_response(),Err(e)=>device_error(e),
    }
}
fn bad_request() -> Response {
    tenant_error(
        StatusCode::BAD_REQUEST,
        "invalid_request",
        "request is invalid",
    )
}
fn device_error(e: TenantAuthError) -> Response {
    if matches!(
        e,
        TenantAuthError::Access(AccessError::Conflict("device_binding_version"))
    ) {
        return tenant_error(
            StatusCode::CONFLICT,
            "device_binding_conflict",
            "device binding has changed",
        );
    }
    if matches!(
        e,
        TenantAuthError::Access(AccessError::Conflict("device_operation_conflict"))
    ) {
        return tenant_error(
            StatusCode::CONFLICT,
            "device_operation_conflict",
            "device operation ID has different content",
        );
    }
    if matches!(
        e,
        TenantAuthError::Access(AccessError::Conflict("device_key_changed"))
    ) {
        return tenant_error(
            StatusCode::CONFLICT,
            "device_key_changed",
            "current device key has changed",
        );
    }
    if matches!(
        e,
        TenantAuthError::Access(AccessError::NotFound("device_operation"))
    ) {
        return tenant_error(
            StatusCode::NOT_FOUND,
            "device_operation_not_found",
            "device operation was not found",
        );
    }
    if matches!(
        e,
        TenantAuthError::Access(AccessError::NotFound("device_key"))
    ) {
        return tenant_error(
            StatusCode::NOT_FOUND,
            "device_key_not_found",
            "device key was not found",
        );
    }
    if matches!(
        e,
        TenantAuthError::Access(AccessError::Conflict(
            "device_registration" | "device_key" | "access.unique"
        ))
    ) {
        tenant_error(
            StatusCode::CONFLICT,
            "device_registration_conflict",
            "device registration conflicts with an existing identity",
        )
    } else if matches!(
        e,
        TenantAuthError::Access(AccessError::NotFound("device_registration"))
    ) {
        tenant_error(
            StatusCode::NOT_FOUND,
            "device_registration_not_found",
            "device registration was not found",
        )
    } else if matches!(e, TenantAuthError::Access(AccessError::Forbidden)) {
        tenant_error(
            StatusCode::FORBIDDEN,
            "device_forbidden",
            "device action is not allowed",
        )
    } else {
        map_tenant_auth_error(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_inputs_reject_identity_override_and_cursor_scope_changes() {
        assert!(
            serde_json::from_str::<DeviceBody>(r#"{"device_id":"d","subject_id":"other"}"#)
                .is_err()
        );
        assert!(
            serde_json::from_str::<DeviceBody>(r#"{"device_id":"a","device_id":"b"}"#).is_err()
        );
        assert!(serde_json::from_str::<ProvisionBody>(r#"{"device_name":"Laptop"}"#).is_err());
        let scope = AccessListScope::SubjectDevices {
            tenant_id: "t1".into(),
            subject_id: "u1".into(),
            client_id: "web".into(),
        };
        let page = AccessPageRequest {
            limit: 1,
            cursor: Some(AccessCursor {
                version: 1,
                scope: scope.clone(),
                after: vec!["d1".into()],
                sort_order: None,
            }),
            sort_order: None,
        };
        assert!(page.validate(&scope).is_ok());
        for other in [
            AccessListScope::SubjectDevices {
                tenant_id: "t2".into(),
                subject_id: "u1".into(),
                client_id: "web".into(),
            },
            AccessListScope::SubjectDevices {
                tenant_id: "t1".into(),
                subject_id: "u2".into(),
                client_id: "web".into(),
            },
            AccessListScope::SubjectDevices {
                tenant_id: "t1".into(),
                subject_id: "u1".into(),
                client_id: "other".into(),
            },
        ] {
            assert_eq!(page.validate(&other), Err(AccessError::InvalidCursor));
        }
        assert!(TenantDeviceHttpConfig::new("test-api", "/api/devices/heartbeat?x=1").is_err());
    }
}
