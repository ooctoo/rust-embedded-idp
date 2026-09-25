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
    Json, Router,
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
        .route("/devices/complete", post(complete))
        .route("/devices/rotate-key", post(rotate))
        .route("/devices", get(list))
        .route("/devices/:device_id", get(detail))
        .route("/devices/unbind", post(unbind))
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
    device_name: String,
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
    json!({"tenant_id":d.tenant_id,"device_id":d.id,"client_id":d.client_id,"proof_key_id":d.proof_key_id,"status":match d.status {DeviceStatus::Pending=>"pending",DeviceStatus::Active=>"active",DeviceStatus::Disabled=>"disabled",DeviceStatus::Revoked=>"revoked"}})
}
fn subject_device_json(r: TenantSubjectDevice) -> Value {
    let mut body = device_json(r.device);
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
    headers: HeaderMap,
    Json(body): Json<ProvisionBody>,
) -> Response {
    if !tenant_header_matches(&headers, &body.tenant_id) {
        return bad_request();
    }
    match call(move || {
        state
            .service
            .provision(body.tenant_id, body.device_name, state.admission.as_ref())
    })
    .await
    {
        Ok(device) => (StatusCode::CREATED, Json(device_json(device))).into_response(),
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
            })
        }
    };
    match call(move || {
        state.service.devices(
            actor,
            AccessPageRequest {
                limit: query.limit.unwrap_or(50),
                cursor,
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
    Json(body): Json<DeviceBody>,
) -> Response {
    let actor = match actor(&state, &headers).await {
        Ok(a) => a,
        Err(r) => return r,
    };
    match call(move || state.service.unbind(actor, body.device_id)).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => device_error(e),
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
    if matches!(e, TenantAuthError::Access(AccessError::Forbidden)) {
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
            }),
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
