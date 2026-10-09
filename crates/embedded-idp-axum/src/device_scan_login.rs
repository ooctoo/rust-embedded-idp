//! Thin HTTP transport for the generic, host-admitted device scan login service.
use std::{collections::HashSet, sync::Arc};

use axum::{
    body::to_bytes,
    extract::{rejection::JsonRejection, DefaultBodyLimit, Extension, OriginalUri, Request, State},
    http::{header, HeaderMap, StatusCode, Uri},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use base64ct::Encoding;
use embedded_idp_core::{access::*, CanonicalHttpMethod, DeviceProofProfile, SecretString};
use serde::{
    de::{DeserializeSeed, MapAccess, SeqAccess, Visitor},
    Deserialize,
};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::{
    browser_session::{credential, BrowserSessionHttpConfig},
    http_support::unix_time_secs,
    proof_http::{parse_device_proof_headers, ProtectedRouteConfig, AUTH_DEVICE_BODY_LIMIT_BYTES},
    tenant_auth::{call, no_store},
};

#[derive(Clone)]
pub struct ScanDeviceHttpConfig {
    routes: [ProtectedRouteConfig; 10],
    verification_uri: String,
}
impl ScanDeviceHttpConfig {
    /// `external_prefix` is the literal, externally mounted device-scan root.
    pub fn new(
        audience: &str,
        external_prefix: &str,
        verification_uri: &str,
    ) -> Result<Self, crate::ProofHttpError> {
        Self::new_with_transport_policy(
            audience,
            external_prefix,
            verification_uri,
            &crate::HttpTransportPolicy::Default,
        )
    }
    pub fn new_with_transport_policy(
        audience: &str,
        external_prefix: &str,
        verification_uri: &str,
        policy: &crate::HttpTransportPolicy,
    ) -> Result<Self, crate::ProofHttpError> {
        let verification: Uri = verification_uri
            .parse()
            .map_err(|_| crate::ProofHttpError::ProofInvalid)?;
        if verification_uri.contains('#') || policy.restricted(&verification).is_err() {
            return Err(crate::ProofHttpError::ProofInvalid);
        }
        let profile = DeviceProofProfile::new(SCAN_LOGIN_PROOF_PROFILE)
            .map_err(|_| crate::ProofHttpError::ProofInvalid)?;
        let route = |suffix: &str| {
            ProtectedRouteConfig::new(
                profile.clone(),
                audience,
                CanonicalHttpMethod::Post,
                format!("{external_prefix}/{suffix}"),
            )
        };
        Ok(Self {
            routes: [
                route("create")?,
                route("claim")?,
                route("status")?,
                route("lookup")?,
                route("cancel")?,
                route("exchange")?,
                route("recover")?,
                route("acknowledge")?,
                route("abort")?,
                route("close-origin")?,
            ],
            verification_uri: verification_uri.into(),
        })
    }
    fn route(&self, action: ScanLoginAction) -> &ProtectedRouteConfig {
        &self.routes[match action {
            ScanLoginAction::Create => 0,
            ScanLoginAction::Claim => 1,
            ScanLoginAction::Status => 2,
            ScanLoginAction::Lookup => 3,
            ScanLoginAction::Cancel => 4,
            ScanLoginAction::Exchange => 5,
            ScanLoginAction::Recover => 6,
            ScanLoginAction::Acknowledge => 7,
            ScanLoginAction::Abort => 8,
            ScanLoginAction::CloseOrigin => 9,
        }]
    }
    pub fn verification_uri(&self) -> &str {
        &self.verification_uri
    }
}

#[derive(Clone)]
struct BrowserState {
    service: Arc<dyn TenantDeviceScanLoginService>,
    identity: Arc<dyn BrowserSessionIdentityService>,
    config: BrowserSessionHttpConfig,
}
#[derive(Clone)]
struct DeviceState {
    service: Arc<dyn TenantDeviceScanLoginService>,
    config: ScanDeviceHttpConfig,
}

/// Validates identity-service restriction at host startup.
pub fn try_scan_browser_router(
    service: Arc<dyn TenantDeviceScanLoginService>,
    identity: Arc<dyn BrowserSessionIdentityService>,
    config: BrowserSessionHttpConfig,
) -> Result<Router, &'static str> {
    if identity.browser_session_lifetime_secs() != config.development_ttl_secs() {
        return Err("browser identity service lifetime mismatch");
    }
    if config.purpose() != embedded_idp_core::AccessTokenPurpose::Business {
        return Err("scan browser requires business purpose");
    }
    Ok(scan_browser_router(service, identity, config))
}
pub fn scan_browser_router(
    service: Arc<dyn TenantDeviceScanLoginService>,
    identity: Arc<dyn BrowserSessionIdentityService>,
    config: BrowserSessionHttpConfig,
) -> Router {
    let state = BrowserState {
        service,
        identity,
        config,
    };
    Router::new()
        .route("/context", post(context))
        .route("/phone-codes", post(issue_phone))
        .route("/attach", post(attach))
        .route("/inspect", post(inspect))
        .route("/approve", post(approve))
        .route("/deny", post(deny))
        .route("/cancel", post(cancel_source))
        .route("/status", post(source_status))
        .with_state(state.clone())
        .layer(DefaultBodyLimit::max(AUTH_DEVICE_BODY_LIMIT_BYTES))
        .route_layer(middleware::from_fn_with_state(state, browser_guard))
        .layer(middleware::from_fn(no_store))
}
pub fn scan_device_router(
    service: Arc<dyn TenantDeviceScanLoginService>,
    config: ScanDeviceHttpConfig,
) -> Router {
    let state = DeviceState { service, config };
    Router::new()
        .route("/create", post(create))
        .route("/claim", post(claim))
        .route("/status", post(device_status))
        .route("/lookup", post(lookup))
        .route("/cancel", post(cancel_device))
        .route("/exchange", post(exchange))
        .route("/recover", post(recover))
        .route("/acknowledge", post(acknowledge))
        .route("/abort", post(abort))
        .route("/close-origin", post(close_origin))
        .with_state(state)
        .layer(DefaultBodyLimit::max(AUTH_DEVICE_BODY_LIMIT_BYTES))
        .layer(middleware::from_fn(no_store))
}

fn exactly(h: &HeaderMap, key: &str, expected: &str) -> bool {
    let mut it = h.get_all(key).iter();
    it.next().is_some_and(|v| v == expected) && it.next().is_none()
}
async fn browser_guard(State(s): State<BrowserState>, request: Request, next: Next) -> Response {
    if s.identity.browser_session_lifetime_secs() != s.config.development_ttl_secs() {
        return err(
            StatusCode::SERVICE_UNAVAILABLE,
            "browser_session_configuration_mismatch",
        );
    }
    let h = request.headers();
    if s.config.purpose() != embedded_idp_core::AccessTokenPurpose::Business
        || !exactly(h, "origin", s.config.origin())
        || !exactly(h, "x-embedded-idp-browser", "1")
        || h.contains_key("sec-fetch-site") && !exactly(h, "sec-fetch-site", "same-origin")
        || h.contains_key("x-embedded-idp-tenant-id")
    {
        return err(StatusCode::FORBIDDEN, "browser_origin_rejected");
    }
    next.run(request).await
}
fn err(status: StatusCode, code: &'static str) -> Response {
    (
        status,
        Json(json!({"error":code,"message":"device scan request rejected","request_id":null,"retryable": status == StatusCode::SERVICE_UNAVAILABLE,"terminal": code == "origin_operation_closed"})),
    )
        .into_response()
}
fn scan_err(e: ScanLoginError) -> Response {
    let (s, c) = match e {
        ScanLoginError::InvalidRequest => (StatusCode::BAD_REQUEST, "invalid_request"),
        ScanLoginError::NotFound => (StatusCode::NOT_FOUND, "scan_not_found"),
        ScanLoginError::SourceClientNotAllowed => (StatusCode::FORBIDDEN, "source_client_not_allowed"),
        ScanLoginError::AdmissionDenied => (StatusCode::FORBIDDEN, "scan_admission_denied"),
        ScanLoginError::ModeDisabled => (StatusCode::FORBIDDEN, "scan_mode_disabled"),
        ScanLoginError::Expired => (StatusCode::GONE, "scan_expired"),
        ScanLoginError::DeliveryExpired => (StatusCode::GONE, "delivery_expired"),
        ScanLoginError::AlreadyClaimed => (StatusCode::CONFLICT, "scan_already_claimed"),
        ScanLoginError::ConfirmationChanged => (StatusCode::CONFLICT, "confirmation_changed"),
        ScanLoginError::NotApproved => (StatusCode::CONFLICT, "scan_not_approved"),
        ScanLoginError::OperationConflict => (StatusCode::CONFLICT, "operation_conflict"),
        ScanLoginError::OriginOperationClosed => (StatusCode::GONE, "origin_operation_closed"),
        ScanLoginError::ExchangeAlreadyStarted(operation_id) => return (StatusCode::CONFLICT, Json(json!({"error":"exchange_already_started","message":"device scan request rejected","request_id":null,"retryable":false,"issuance_operation_id":operation_id}))).into_response(),
        ScanLoginError::AlreadyIssued => (StatusCode::CONFLICT, "scan_already_issued"),
        ScanLoginError::AlreadyAcknowledged => (StatusCode::CONFLICT, "already_acknowledged"),
        ScanLoginError::Cancelled => (StatusCode::GONE, "scan_cancelled"),
        ScanLoginError::Denied => (StatusCode::GONE, "scan_denied"),
        ScanLoginError::Invalidated => (StatusCode::GONE, "scan_invalidated"),
        ScanLoginError::DeliveryRevoked => (StatusCode::GONE, "delivery_revoked"),
        ScanLoginError::RateLimited => (StatusCode::TOO_MANY_REQUESTS, "scan_rate_limited"),
        ScanLoginError::ResultUnavailable => (StatusCode::SERVICE_UNAVAILABLE, "scan_result_unavailable"),
        ScanLoginError::Auth(TenantAuthError::Access(AccessError::InvalidInput("browser_session_changed"))) => (StatusCode::CONFLICT, "browser_session_changed"),
        ScanLoginError::Auth(TenantAuthError::DeviceProofRequired | TenantAuthError::DeviceProof(_)) => (StatusCode::FORBIDDEN, "device_proof_invalid"),
        ScanLoginError::Auth(TenantAuthError::Store(_) | TenantAuthError::Access(AccessError::Store(_))) => (StatusCode::SERVICE_UNAVAILABLE, "scan_storage_unavailable"),
        ScanLoginError::Auth(TenantAuthError::Token(_) | TenantAuthError::Security(_)) => (StatusCode::SERVICE_UNAVAILABLE, "scan_result_unavailable"),
        ScanLoginError::Auth(_) => (StatusCode::UNAUTHORIZED, "invalid_source_session"),
        ScanLoginError::AdmissionUnavailable => (StatusCode::SERVICE_UNAVAILABLE, "scan_admission_unavailable"),
        ScanLoginError::Store(_) => (StatusCode::SERVICE_UNAVAILABLE, "scan_storage_unavailable"),
    };
    err(s, c)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Expected {
    tenant_id: String,
    account_id: String,
    session_id: String,
    client_id: String,
}
impl From<Expected> for BrowserSessionIdentity {
    fn from(x: Expected) -> Self {
        Self {
            tenant_id: x.tenant_id,
            account_id: x.account_id,
            session_id: x.session_id,
            client_id: x.client_id,
        }
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BrowserOnly {
    expected_session: Option<Expected>,
}
async fn source(
    state: &BrowserState,
    headers: &HeaderMap,
    expected: Option<Expected>,
    host: TrustedScanHostContext,
) -> Result<ScanSourceCall, Response> {
    let restricted = state.config.development_ttl_secs().is_some();
    if restricted && expected.is_none() {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "browser_expected_session_required",
        ));
    }
    let cookie = credential(headers, state.config.cookie_name())
        .map_err(|_| err(StatusCode::BAD_REQUEST, "invalid_request"))?
        .ok_or_else(|| {
            err(
                StatusCode::UNAUTHORIZED,
                if restricted {
                    "browser_session_expired"
                } else {
                    "browser_session_invalid"
                },
            )
        })?;
    let identity = state.identity.clone();
    let session = call(move || identity.authenticate_browser(cookie, expected.map(Into::into)))
        .await
        .map_err(|error| {
            if restricted
                && matches!(
                    error,
                    TenantAuthError::InvalidSession | TenantAuthError::InvalidRefresh
                )
            {
                err(StatusCode::UNAUTHORIZED, "browser_session_expired")
            } else {
                scan_err(ScanLoginError::Auth(error))
            }
        })?;
    Ok(ScanSourceCall {
        source: session,
        host,
    })
}
fn host(
    value: Option<Extension<TrustedScanHostContext>>,
) -> Result<TrustedScanHostContext, Response> {
    value
        .map(|value| value.0)
        .ok_or_else(|| err(StatusCode::FORBIDDEN, "scan_host_context_required"))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Phone {
    operation_id: String,
    entry_id: String,
    expected_session: Expected,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Attach {
    operation_id: String,
    display_code: String,
    expected_session: Expected,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Grant {
    operation_id: String,
    grant_id: String,
    expected_session: Expected,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadGrant {
    grant_id: String,
    expected_session: Expected,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Approval {
    operation_id: String,
    grant_id: String,
    confirmation_revision: String,
    expected_session: Expected,
}
async fn context(
    State(s): State<BrowserState>,
    headers: HeaderMap,
    h: Option<Extension<TrustedScanHostContext>>,
    body: Result<Json<BrowserOnly>, JsonRejection>,
) -> Response {
    let b = match body {
        Ok(Json(b)) => b,
        Err(_) => return err(StatusCode::BAD_REQUEST, "invalid_request"),
    };
    let h = match host(h) {
        Ok(value) => value,
        Err(response) => return response,
    };
    match source(&s,&headers,b.expected_session,h).await { Ok(x)=>Json(json!({"tenant_id":x.source.tenant_id(),"account_id":x.source.account_id(),"session_id":x.source.session_id(),"client_id":x.source.client_id(),"entry":entry(&s.service.entry_config())})).into_response(),Err(r)=>r }
}
async fn issue_phone(
    State(s): State<BrowserState>,
    headers: HeaderMap,
    h: Option<Extension<TrustedScanHostContext>>,
    body: Result<Json<Phone>, JsonRejection>,
) -> Response {
    let b = match body {
        Ok(Json(b)) => b,
        Err(_) => return err(StatusCode::BAD_REQUEST, "invalid_request"),
    };
    let h = match host(h) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let x = match source(&s, &headers, Some(b.expected_session), h).await {
        Ok(x) => x,
        Err(r) => return r,
    };
    match call(move||s.service.issue_phone(IssuePhoneScan{operation_id:b.operation_id,entry_id:b.entry_id},x)).await {Ok(v)=>(StatusCode::CREATED,Json(json!({"progress":progress(&v.progress),"scan_code":v.scan_code.into_exposed(),"code_expires_at_unix_secs":unix_time_secs(v.code_expires_at)}))).into_response(),Err(e)=>scan_err(e)}
}
async fn attach(
    State(s): State<BrowserState>,
    headers: HeaderMap,
    h: Option<Extension<TrustedScanHostContext>>,
    body: Result<Json<Attach>, JsonRejection>,
) -> Response {
    let b = match body {
        Ok(Json(b)) => b,
        Err(_) => return err(StatusCode::BAD_REQUEST, "invalid_request"),
    };
    let h = match host(h) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let x = match source(&s, &headers, Some(b.expected_session), h).await {
        Ok(x) => x,
        Err(r) => return r,
    };
    match call(move || {
        s.service.attach_source(
            AttachScanSource {
                operation_id: b.operation_id,
                display_code: SecretString::new(b.display_code),
            },
            x,
        )
    })
    .await
    {
        Ok(v) => Json(confirmation(v)).into_response(),
        Err(e) => scan_err(e),
    }
}
async fn inspect(
    State(s): State<BrowserState>,
    headers: HeaderMap,
    h: Option<Extension<TrustedScanHostContext>>,
    body: Result<Json<ReadGrant>, JsonRejection>,
) -> Response {
    let b = match body {
        Ok(Json(b)) => b,
        Err(_) => return err(StatusCode::BAD_REQUEST, "invalid_request"),
    };
    let h = match host(h) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let x = match source(&s, &headers, Some(b.expected_session), h).await {
        Ok(x) => x,
        Err(r) => return r,
    };
    match call(move || s.service.inspect(b.grant_id, x)).await {
        Ok(v) => Json(confirmation(v)).into_response(),
        Err(e) => scan_err(e),
    }
}
async fn approve(
    State(s): State<BrowserState>,
    headers: HeaderMap,
    h: Option<Extension<TrustedScanHostContext>>,
    body: Result<Json<Approval>, JsonRejection>,
) -> Response {
    let b = match body {
        Ok(Json(b)) => b,
        Err(_) => return err(StatusCode::BAD_REQUEST, "invalid_request"),
    };
    let h = match host(h) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let x = match source(&s, &headers, Some(b.expected_session), h).await {
        Ok(x) => x,
        Err(r) => return r,
    };
    match call(move || {
        s.service.approve(
            ApproveScan {
                action: SourceGrantAction {
                    operation_id: b.operation_id,
                    grant_id: b.grant_id,
                },
                confirmation_revision: b.confirmation_revision,
            },
            x,
        )
    })
    .await
    {
        Ok(v) => Json(progress(&v)).into_response(),
        Err(e) => scan_err(e),
    }
}
async fn deny(
    State(s): State<BrowserState>,
    headers: HeaderMap,
    h: Option<Extension<TrustedScanHostContext>>,
    body: Result<Json<Grant>, JsonRejection>,
) -> Response {
    let b = match body {
        Ok(Json(b)) => b,
        Err(_) => return err(StatusCode::BAD_REQUEST, "invalid_request"),
    };
    let h = match host(h) {
        Ok(value) => value,
        Err(response) => return response,
    };
    source_action(s, headers, h, b, false).await
}
async fn cancel_source(
    State(s): State<BrowserState>,
    headers: HeaderMap,
    h: Option<Extension<TrustedScanHostContext>>,
    body: Result<Json<Grant>, JsonRejection>,
) -> Response {
    let b = match body {
        Ok(Json(b)) => b,
        Err(_) => return err(StatusCode::BAD_REQUEST, "invalid_request"),
    };
    let h = match host(h) {
        Ok(value) => value,
        Err(response) => return response,
    };
    source_action(s, headers, h, b, true).await
}
async fn source_action(
    s: BrowserState,
    headers: HeaderMap,
    h: TrustedScanHostContext,
    b: Grant,
    cancel: bool,
) -> Response {
    let x = match source(&s, &headers, Some(b.expected_session), h).await {
        Ok(x) => x,
        Err(r) => return r,
    };
    let a = SourceGrantAction {
        operation_id: b.operation_id,
        grant_id: b.grant_id,
    };
    let result = call(move || {
        if cancel {
            s.service.cancel_source(a, x)
        } else {
            s.service.deny(a, x)
        }
    })
    .await;
    match result {
        Ok(v) => Json(progress(&v)).into_response(),
        Err(e) => scan_err(e),
    }
}
async fn source_status(
    State(s): State<BrowserState>,
    headers: HeaderMap,
    h: Option<Extension<TrustedScanHostContext>>,
    body: Result<Json<ReadGrant>, JsonRejection>,
) -> Response {
    let b = match body {
        Ok(Json(b)) => b,
        Err(_) => return err(StatusCode::BAD_REQUEST, "invalid_request"),
    };
    let h = match host(h) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let x = match source(&s, &headers, Some(b.expected_session), h).await {
        Ok(x) => x,
        Err(r) => return r,
    };
    match call(move || s.service.source_status(b.grant_id, x)).await {
        Ok(v) => Json(progress(&v)).into_response(),
        Err(e) => scan_err(e),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Create {
    operation_id: String,
    entry_id: String,
    tenant_id: String,
    delivery_secret_hash: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Claim {
    operation_id: String,
    entry_id: String,
    tenant_id: String,
    scan_code: String,
    delivery_secret_hash: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OpAccess {
    operation_id: String,
    grant_id: String,
    delivery_secret: String,
    tenant_id: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadAccess {
    grant_id: String,
    delivery_secret: String,
    tenant_id: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Lookup {
    origin_action: Option<OriginAction>,
    origin_operation_id: String,
    entry_id: String,
    tenant_id: String,
    delivery_secret: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum OriginAction {
    Create,
    Claim,
}
impl From<OriginAction> for ScanOriginAction {
    fn from(value: OriginAction) -> Self {
        match value {
            OriginAction::Create => Self::Create,
            OriginAction::Claim => Self::Claim,
        }
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CloseOrigin {
    entry_id: String,
    tenant_id: String,
    origin_action: OriginAction,
    origin_operation_id: String,
    delivery_secret: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Recover {
    issuance_operation_id: String,
    grant_id: String,
    delivery_secret: String,
    tenant_id: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Ack {
    operation_id: String,
    issuance_operation_id: String,
    grant_id: String,
    delivery_secret: String,
    receipt_nonce: String,
    tenant_id: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Abort {
    operation_id: String,
    issuance_operation_id: String,
    grant_id: String,
    delivery_secret: String,
    tenant_id: String,
}
trait DeviceTenant {
    fn tenant_id(&self) -> &str;
}
macro_rules! device_tenant { ($($kind:ty),+ $(,)?) => { $(impl DeviceTenant for $kind { fn tenant_id(&self) -> &str { &self.tenant_id } })+ }; }
device_tenant!(
    Create,
    Claim,
    OpAccess,
    ReadAccess,
    Lookup,
    CloseOrigin,
    Recover,
    Ack,
    Abort
);
fn digest(x: String) -> Result<[u8; 32], Response> {
    let bytes = base64ct::Base64UrlUnpadded::decode_vec(&x)
        .map_err(|_| err(StatusCode::BAD_REQUEST, "invalid_request"))?;
    bytes
        .try_into()
        .map_err(|_| err(StatusCode::BAD_REQUEST, "invalid_request"))
}
fn access(grant_id: String, delivery_secret: String) -> DeviceGrantAccess {
    DeviceGrantAccess {
        grant_id,
        delivery_secret: SecretString::new(delivery_secret),
    }
}
struct NoDuplicate;
impl<'de> DeserializeSeed<'de> for NoDuplicate {
    type Value = ();
    fn deserialize<D: serde::Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        deserializer.deserialize_any(NoDuplicate)
    }
}
impl<'de> Visitor<'de> for NoDuplicate {
    type Value = ();
    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a JSON value without duplicate members")
    }
    fn visit_bool<E: serde::de::Error>(self, _: bool) -> Result<(), E> {
        Ok(())
    }
    fn visit_i64<E: serde::de::Error>(self, _: i64) -> Result<(), E> {
        Ok(())
    }
    fn visit_u64<E: serde::de::Error>(self, _: u64) -> Result<(), E> {
        Ok(())
    }
    fn visit_f64<E: serde::de::Error>(self, _: f64) -> Result<(), E> {
        Ok(())
    }
    fn visit_str<E: serde::de::Error>(self, _: &str) -> Result<(), E> {
        Ok(())
    }
    fn visit_string<E: serde::de::Error>(self, _: String) -> Result<(), E> {
        Ok(())
    }
    fn visit_none<E: serde::de::Error>(self) -> Result<(), E> {
        Ok(())
    }
    fn visit_unit<E: serde::de::Error>(self) -> Result<(), E> {
        Ok(())
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut values: A) -> Result<(), A::Error> {
        while values.next_element_seed(NoDuplicate)?.is_some() {}
        Ok(())
    }
    fn visit_map<A: MapAccess<'de>>(self, mut values: A) -> Result<(), A::Error> {
        let mut keys = HashSet::new();
        while let Some(key) = values.next_key::<String>()? {
            if !keys.insert(key) {
                return Err(serde::de::Error::custom("duplicate JSON member"));
            }
            values.next_value_seed(NoDuplicate)?;
        }
        Ok(())
    }
}
fn reject_duplicate_members(bytes: &[u8]) -> Result<(), ()> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    NoDuplicate.deserialize(&mut deserializer).map_err(|_| ())?;
    deserializer.end().map_err(|_| ())
}
async fn device_call<T: for<'de> Deserialize<'de> + DeviceTenant>(
    state: &DeviceState,
    action: ScanLoginAction,
    uri: Uri,
    request: Request,
) -> Result<(T, ScanDeviceCall), Response> {
    let (parts, body) = request.into_parts();
    let content_type = parts
        .headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .unwrap_or("")
        .trim();
    if content_type != "application/json"
        && !(content_type.starts_with("application/") && content_type.ends_with("+json"))
    {
        return Err(err(StatusCode::UNSUPPORTED_MEDIA_TYPE, "invalid_request"));
    }
    let bytes = to_bytes(body, AUTH_DEVICE_BODY_LIMIT_BYTES)
        .await
        .map_err(|_| err(StatusCode::PAYLOAD_TOO_LARGE, "request_body_too_large"))?;
    reject_duplicate_members(&bytes)
        .map_err(|_| err(StatusCode::BAD_REQUEST, "invalid_request"))?;
    let value: T = serde_json::from_slice(&bytes)
        .map_err(|_| err(StatusCode::BAD_REQUEST, "invalid_request"))?;
    let tenant = serde_json::from_slice::<serde_json::Value>(&bytes)
        .ok()
        .and_then(|v| {
            v.get("tenant_id")
                .and_then(|x| x.as_str())
                .map(str::to_owned)
        })
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, "invalid_request"))?;
    if value.tenant_id() != tenant {
        return Err(err(StatusCode::BAD_REQUEST, "invalid_request"));
    }
    let binding = state
        .config
        .route(action)
        .binding_for_request(&tenant, &parts.method, &uri, Sha256::digest(&bytes).into())
        .map_err(|_| err(StatusCode::BAD_REQUEST, "device_proof_invalid"))?;
    let proof = parse_device_proof_headers(&parts.headers)
        .map_err(|_| err(StatusCode::FORBIDDEN, "device_proof_invalid"))?;
    let host = parts
        .extensions
        .get::<TrustedScanHostContext>()
        .cloned()
        .ok_or_else(|| err(StatusCode::FORBIDDEN, "scan_host_context_required"))?;
    let entry = state.service.entry_config().entry_id;
    Ok((
        value,
        ScanDeviceCall {
            entry_id: entry,
            proof,
            binding,
            host,
        },
    ))
}
async fn create(
    State(s): State<DeviceState>,
    OriginalUri(uri): OriginalUri,
    request: Request,
) -> Response {
    let verification_uri = s.config.verification_uri().to_owned();
    let (b, x) = match device_call::<Create>(&s, ScanLoginAction::Create, uri, request).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let hash = match digest(b.delivery_secret_hash) {
        Ok(v) => v,
        Err(r) => return r,
    };
    match call(move||s.service.create_device(CreateDeviceScan{operation_id:b.operation_id,entry_id:b.entry_id,tenant_id:b.tenant_id,delivery_secret_hash:hash},x)).await{Ok(v)=>(StatusCode::CREATED,Json(json!({"progress":progress(&v.progress),"display_code":v.display_code.into_exposed(),"verification_uri":verification_uri}))).into_response(),Err(e)=>scan_err(e)}
}
async fn claim(
    State(s): State<DeviceState>,
    OriginalUri(uri): OriginalUri,
    request: Request,
) -> Response {
    let (b, x) = match device_call::<Claim>(&s, ScanLoginAction::Claim, uri, request).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let hash = match digest(b.delivery_secret_hash) {
        Ok(v) => v,
        Err(r) => return r,
    };
    match call(move || {
        s.service.claim_target(
            ClaimScanTarget {
                operation_id: b.operation_id,
                entry_id: b.entry_id,
                tenant_id: b.tenant_id,
                scan_code: SecretString::new(b.scan_code),
                delivery_secret_hash: hash,
            },
            x,
        )
    })
    .await
    {
        Ok(v) => Json(progress(&v)).into_response(),
        Err(e) => scan_err(e),
    }
}
async fn device_status(
    State(s): State<DeviceState>,
    OriginalUri(uri): OriginalUri,
    request: Request,
) -> Response {
    let (b, x) = match device_call::<ReadAccess>(&s, ScanLoginAction::Status, uri, request).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    match call(move || {
        s.service
            .device_status(access(b.grant_id, b.delivery_secret), x)
    })
    .await
    {
        Ok(v) => Json(progress(&v)).into_response(),
        Err(e) => scan_err(e),
    }
}
async fn cancel_device(
    State(s): State<DeviceState>,
    OriginalUri(uri): OriginalUri,
    request: Request,
) -> Response {
    let (b, x) = match device_call::<OpAccess>(&s, ScanLoginAction::Cancel, uri, request).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    match call(move || {
        s.service.cancel_device(
            CancelDeviceScan {
                operation_id: b.operation_id,
                access: access(b.grant_id, b.delivery_secret),
            },
            x,
        )
    })
    .await
    {
        Ok(v) => Json(progress(&v)).into_response(),
        Err(e) => scan_err(e),
    }
}
async fn lookup(
    State(s): State<DeviceState>,
    OriginalUri(uri): OriginalUri,
    request: Request,
) -> Response {
    let (b, x) = match device_call::<Lookup>(&s, ScanLoginAction::Lookup, uri, request).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    match call(move||s.service.lookup_device(LookupDeviceScan{origin_action:b.origin_action.map(Into::into),origin_operation_id:b.origin_operation_id,entry_id:b.entry_id,tenant_id:b.tenant_id,delivery_secret:SecretString::new(b.delivery_secret)},x)).await{Ok(v)=>Json(json!({"progress":progress(&v.progress),"origin_operation_id":v.origin_operation_id,"display_code":v.display_code.map(SecretString::into_exposed)})).into_response(),Err(e)=>scan_err(e)}
}
async fn close_origin(
    State(s): State<DeviceState>,
    OriginalUri(uri): OriginalUri,
    request: Request,
) -> Response {
    let (b, x) =
        match device_call::<CloseOrigin>(&s, ScanLoginAction::CloseOrigin, uri, request).await {
            Ok(v) => v,
            Err(r) => return r,
        };
    match call(move || {
        s.service.close_origin(
            embedded_idp_core::access::CloseScanOrigin {
                entry_id: b.entry_id,
                tenant_id: b.tenant_id,
                origin_action: b.origin_action.into(),
                origin_operation_id: b.origin_operation_id,
                delivery_secret: SecretString::new(b.delivery_secret),
            },
            x,
        )
    })
    .await
    {
        Ok(v) => Json(close_origin_result(v)).into_response(),
        Err(e) => scan_err(e),
    }
}
async fn exchange(
    State(s): State<DeviceState>,
    OriginalUri(uri): OriginalUri,
    request: Request,
) -> Response {
    let (b, x) = match device_call::<OpAccess>(&s, ScanLoginAction::Exchange, uri, request).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    match call(move || {
        s.service.exchange(
            ExchangeScan {
                operation_id: b.operation_id,
                access: access(b.grant_id, b.delivery_secret),
            },
            x,
        )
    })
    .await
    {
        Ok(v) => delivery(v),
        Err(e) => scan_err(e),
    }
}
async fn recover(
    State(s): State<DeviceState>,
    OriginalUri(uri): OriginalUri,
    request: Request,
) -> Response {
    let (b, x) = match device_call::<Recover>(&s, ScanLoginAction::Recover, uri, request).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    match call(move || {
        s.service.recover(
            RecoverScan {
                issuance_operation_id: b.issuance_operation_id,
                access: access(b.grant_id, b.delivery_secret),
            },
            x,
        )
    })
    .await
    {
        Ok(v) => delivery(v),
        Err(e) => scan_err(e),
    }
}
async fn acknowledge(
    State(s): State<DeviceState>,
    OriginalUri(uri): OriginalUri,
    request: Request,
) -> Response {
    let (b, x) = match device_call::<Ack>(&s, ScanLoginAction::Acknowledge, uri, request).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    match call(move || {
        s.service.acknowledge(
            AcknowledgeScan {
                operation_id: b.operation_id,
                issuance_operation_id: b.issuance_operation_id,
                access: access(b.grant_id, b.delivery_secret),
                receipt_nonce: SecretString::new(b.receipt_nonce),
            },
            x,
        )
    })
    .await
    {
        Ok(v) => Json(progress(&v)).into_response(),
        Err(e) => scan_err(e),
    }
}
async fn abort(
    State(s): State<DeviceState>,
    OriginalUri(uri): OriginalUri,
    request: Request,
) -> Response {
    let (b, x) = match device_call::<Abort>(&s, ScanLoginAction::Abort, uri, request).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    match call(move || {
        s.service.abort_delivery(
            AbortScanDelivery {
                operation_id: b.operation_id,
                issuance_operation_id: b.issuance_operation_id,
                access: access(b.grant_id, b.delivery_secret),
            },
            x,
        )
    })
    .await
    {
        Ok(v) => Json(progress(&v)).into_response(),
        Err(e) => scan_err(e),
    }
}
fn entry(x: &ScanLoginEntryConfig) -> serde_json::Value {
    json!({"entry_id":x.entry_id,"target_client_id":x.target_client_id,"modes":x.modes.iter().map(|m|match m{ScanLoginMode::DeviceDisplay=>"device_display",ScanLoginMode::PhoneDisplay=>"phone_display"}).collect::<Vec<_>>()})
}
fn close_origin_result(x: ScanOriginCloseResult) -> serde_json::Value {
    json!({
        "origin_action": x.origin_action.as_str(),
        "origin_operation_id": x.origin_operation_id,
        "outcome": match x.outcome { ScanOriginCloseOutcome::Closed => "closed", ScanOriginCloseOutcome::AlreadyActivated => "already_activated" },
        "closed_at_unix_secs": x.closed_at.map(unix_time_secs),
        "progress": x.progress.as_ref().map(progress),
    })
}
fn progress(x: &ScanProgress) -> serde_json::Value {
    let expires_in = x
        .expires_at
        .duration_since(x.server_time)
        .unwrap_or_default()
        .as_secs();
    json!({"grant_id":x.grant_id,"mode":match x.mode {ScanLoginMode::DeviceDisplay=>"device_display",ScanLoginMode::PhoneDisplay=>"phone_display"},"state":x.state.as_str(),"version":x.version,"server_time_unix_secs":unix_time_secs(x.server_time),"expires_at_unix_secs":unix_time_secs(x.expires_at),"code_expires_at_unix_secs":unix_time_secs(x.code_expires_at),"approved_until_unix_secs":x.approved_until.map(unix_time_secs),"expires_in":expires_in,"poll_after_ms":x.poll_after_ms,"delivery_state":x.delivery_state.map(|x|x.as_str()),"issuance_operation_id":x.issuance_operation_id,"recover_until_unix_secs":x.recover_until.map(unix_time_secs),"next_action":x.next_action})
}
fn confirmation(x: ScanConfirmation) -> serde_json::Value {
    json!({"progress":progress(&x.progress),"source":{"account_id":x.source.account_id,"session_id":x.source.session_id,"client_id":x.source.client_id,"display_name":x.source_display_name},"target":{"device_id":x.target.device_id,"display_name":x.presentation.display_name,"identification":x.presentation.identification,"context_label":x.presentation.context_label,"revision":x.presentation.revision},"confirmation_revision":x.confirmation_revision})
}
fn delivery(x: ScanDeliveryResult) -> Response {
    match x { ScanDeliveryResult::Progress(x)=>Json(json!({"progress":progress(&x)})).into_response(),ScanDeliveryResult::Bundle{progress: p,session,receipt_nonce}=>Json(json!({"progress":progress(&p),"receipt_nonce":receipt_nonce.into_exposed(),"session":{"tenant_id":session.session.tenant_id,"account_id":session.session.account_id,"session_id":session.session.id,"client_id":session.session.client_id,"expires_at_unix_secs":unix_time_secs(session.session.expires_at)},"tokens":{"access_token":session.tokens.access_token.into_exposed(),"refresh_token":session.tokens.refresh_token.into_exposed(),"access_expires_at_unix_secs":unix_time_secs(session.tokens.access_expires_at),"refresh_expires_at_unix_secs":unix_time_secs(session.tokens.refresh_expires_at)}})).into_response()}
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use embedded_idp_core::{DeviceProofPresentation, DeviceRequestBinding};
    use std::{
        sync::Mutex,
        time::{Duration, SystemTime},
    };
    use tower::ServiceExt;

    #[derive(Default)]
    struct ScanStub {
        device: Mutex<Option<(DeviceRequestBinding, DeviceProofPresentation)>>,
        closed_origin: Mutex<Option<embedded_idp_core::access::CloseScanOrigin>>,
    }
    macro_rules! stub { ($($name:ident($($arg:ident:$ty:ty),*) -> $ret:ty;)*) => { $(fn $name(&self,$($arg:$ty),*) -> $ret { let _ = ($($arg,)*); unreachable!("route guard must stop before service") })* }; }
    impl TenantDeviceScanLoginService for ScanStub {
        stub! {
            create_device(c:CreateDeviceScan, actor:ScanDeviceCall) -> Result<CreatedDeviceScan,ScanLoginError>;
            issue_phone(c:IssuePhoneScan, actor:ScanSourceCall) -> Result<IssuedPhoneScan,ScanLoginError>;
            attach_source(c:AttachScanSource, actor:ScanSourceCall) -> Result<ScanConfirmation,ScanLoginError>;
            claim_target(c:ClaimScanTarget, actor:ScanDeviceCall) -> Result<ScanProgress,ScanLoginError>;
            inspect(grant_id:String, actor:ScanSourceCall) -> Result<ScanConfirmation,ScanLoginError>;
            approve(c:ApproveScan, actor:ScanSourceCall) -> Result<ScanProgress,ScanLoginError>;
            deny(c:SourceGrantAction, actor:ScanSourceCall) -> Result<ScanProgress,ScanLoginError>;
            cancel_source(c:SourceGrantAction, actor:ScanSourceCall) -> Result<ScanProgress,ScanLoginError>;
            cancel_device(c:CancelDeviceScan, actor:ScanDeviceCall) -> Result<ScanProgress,ScanLoginError>;
            source_status(grant_id:String, actor:ScanSourceCall) -> Result<ScanProgress,ScanLoginError>;
            lookup_device(c:LookupDeviceScan, actor:ScanDeviceCall) -> Result<DeviceScanLookup,ScanLoginError>;
            exchange(c:ExchangeScan, actor:ScanDeviceCall) -> Result<ScanDeliveryResult,ScanLoginError>;
            recover(c:RecoverScan, actor:ScanDeviceCall) -> Result<ScanDeliveryResult,ScanLoginError>;
            acknowledge(c:AcknowledgeScan, actor:ScanDeviceCall) -> Result<ScanProgress,ScanLoginError>;
            abort_delivery(c:AbortScanDelivery, actor:ScanDeviceCall) -> Result<ScanProgress,ScanLoginError>;
            compensate(host:TrustedScanHostContext, grant_id:String, issuance_operation_id:String, operation_id:String) -> Result<ScanProgress,ScanLoginError>;
            cleanup(host:TrustedScanHostContext, limit:u32) -> Result<u32,ScanLoginError>;
        }
        fn close_origin(
            &self,
            c: embedded_idp_core::access::CloseScanOrigin,
            actor: ScanDeviceCall,
        ) -> Result<ScanOriginCloseResult, ScanLoginError> {
            *self.device.lock().unwrap() = Some((actor.binding, actor.proof));
            *self.closed_origin.lock().unwrap() = Some(c.clone());
            Ok(ScanOriginCloseResult {
                origin_action: c.origin_action,
                origin_operation_id: c.origin_operation_id,
                outcome: ScanOriginCloseOutcome::Closed,
                closed_at: Some(SystemTime::UNIX_EPOCH),
                progress: None,
            })
        }
        fn entry_config(&self) -> ScanLoginEntryConfig {
            ScanLoginEntryConfig {
                entry_id: "terminal-login".into(),
                target_client_id: "terminal".into(),
                allowed_source_client_ids: vec!["phone".into()],
                host_scope: "host".into(),
                tenant_policy: LoginTenantPolicy::Fixed {
                    tenant_id: "tenant-a".into(),
                },
                modes: vec![ScanLoginMode::DeviceDisplay, ScanLoginMode::PhoneDisplay],
                target_scope: None,
                limits: ScanLoginLimits::default(),
            }
        }
        fn device_status(
            &self,
            _: DeviceGrantAccess,
            actor: ScanDeviceCall,
        ) -> Result<ScanProgress, ScanLoginError> {
            *self.device.lock().unwrap() = Some((actor.binding, actor.proof));
            Ok(test_progress())
        }
    }
    struct IdentityStub;
    impl BrowserSessionIdentityService for IdentityStub {
        fn authenticate_browser(
            &self,
            _: SecretString,
            _: Option<BrowserSessionIdentity>,
        ) -> Result<AuthenticatedBrowserSession, TenantAuthError> {
            unreachable!()
        }
    }
    fn browser() -> Router {
        scan_browser_router(
            Arc::new(ScanStub::default()),
            Arc::new(IdentityStub),
            BrowserSessionHttpConfig::new(
                "https://example.test",
                "business",
                "/auth/browser",
                embedded_idp_core::AccessTokenPurpose::Business,
            )
            .unwrap(),
        )
    }
    fn request(origin: &str) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/context")
            .header("origin", origin)
            .header("x-embedded-idp-browser", "1")
            .header("content-type", "application/json")
            .body(Body::from("{}"))
            .unwrap()
    }
    #[tokio::test]
    async fn browser_rejects_wrong_origin_before_cookie_or_service() {
        assert_eq!(
            browser()
                .oneshot(request("https://evil.test"))
                .await
                .unwrap()
                .status(),
            StatusCode::FORBIDDEN
        );
    }
    #[tokio::test]
    async fn browser_rejects_missing_trusted_host_context() {
        let response = browser()
            .oneshot(request("https://example.test"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    }
    #[tokio::test]
    async fn browser_rejects_management_cookie_configuration() {
        let router = scan_browser_router(
            Arc::new(ScanStub::default()),
            Arc::new(IdentityStub),
            BrowserSessionHttpConfig::new(
                "https://example.test",
                "management",
                "/admin/auth/browser",
                embedded_idp_core::AccessTokenPurpose::Management,
            )
            .unwrap(),
        );
        assert_eq!(
            router
                .oneshot(request("https://example.test"))
                .await
                .unwrap()
                .status(),
            StatusCode::FORBIDDEN
        );
    }
    struct ChangedIdentity;
    impl BrowserSessionIdentityService for ChangedIdentity {
        fn authenticate_browser(
            &self,
            _: SecretString,
            _: Option<BrowserSessionIdentity>,
        ) -> Result<AuthenticatedBrowserSession, TenantAuthError> {
            Err(TenantAuthError::Access(AccessError::InvalidInput(
                "browser_session_changed",
            )))
        }
    }
    #[tokio::test]
    async fn browser_read_routes_need_no_operation_and_report_changed_identity() {
        let app = scan_browser_router(
            Arc::new(ScanStub::default()),
            Arc::new(ChangedIdentity),
            BrowserSessionHttpConfig::new(
                "https://example.test",
                "business",
                "/auth/browser",
                embedded_idp_core::AccessTokenPurpose::Business,
            )
            .unwrap(),
        )
        .layer(Extension(TrustedScanHostContext::new(
            "host".into(),
            SystemTime::now() + Duration::from_secs(5),
        )));
        for path in ["/inspect", "/status"] {
            let response=app.clone().oneshot(Request::builder().method("POST").uri(path)
                .header("origin","https://example.test").header("x-embedded-idp-browser","1")
                .header("content-type","application/json").header("cookie","business=synthetic")
                .body(Body::from(r#"{"grant_id":"22222222-2222-4222-8222-222222222222","expected_session":{"tenant_id":"tenant-a","account_id":"44444444-4444-4444-8444-444444444444","session_id":"55555555-5555-4555-8555-555555555555","client_id":"phone"}}"#)).unwrap()).await.unwrap();
            assert_eq!(response.status(), StatusCode::CONFLICT);
            let bytes = to_bytes(response.into_body(), 4096).await.unwrap();
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()["error"],
                "browser_session_changed"
            );
        }
    }
    #[test]
    fn identity_store_failure_is_retryable_unavailability() {
        assert_eq!(
            scan_err(ScanLoginError::Auth(TenantAuthError::Store(
                embedded_idp_core::StoreError::Backend("synthetic outage".into())
            )))
            .status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }
    #[test]
    fn private_verification_uri_uses_the_same_transport_gate() {
        let policy = crate::HttpTransportPolicy::DevelopmentPrivateNetworkHttp;
        let result = ScanDeviceHttpConfig::new_with_transport_policy(
            "device",
            "/auth/device-scan",
            "http://192.168.31.159/scan",
            &policy,
        );
        assert_eq!(
            result.is_ok(),
            cfg!(all(
                feature = "development-private-network-http",
                debug_assertions
            ))
        );
        for uri in [
            "http://public.example/scan",
            "http://8.8.8.8/scan",
            "http://192.168.31.159/scan#fragment",
            "http://user@192.168.31.159/scan",
        ] {
            assert!(ScanDeviceHttpConfig::new_with_transport_policy(
                "device",
                "/auth/device-scan",
                uri,
                &policy
            )
            .is_err());
        }
    }

    #[cfg(all(feature = "development-private-network-http", debug_assertions))]
    #[tokio::test]
    async fn private_context_requires_restricted_identity_and_page_assertion() {
        struct RestrictedIdentity;
        impl BrowserSessionIdentityService for RestrictedIdentity {
            fn browser_session_lifetime_secs(&self) -> Option<u64> {
                Some(900)
            }
            fn authenticate_browser(
                &self,
                _: SecretString,
                expected: Option<BrowserSessionIdentity>,
            ) -> Result<AuthenticatedBrowserSession, TenantAuthError> {
                assert!(expected.is_some());
                Err(TenantAuthError::InvalidRefresh)
            }
        }
        let config = BrowserSessionHttpConfig::new_with_transport_policy(
            "http://192.168.31.159",
            "business",
            "/auth/browser",
            embedded_idp_core::AccessTokenPurpose::Business,
            &crate::HttpTransportPolicy::DevelopmentPrivateNetworkHttp,
        )
        .unwrap();
        assert!(try_scan_browser_router(
            Arc::new(ScanStub::default()),
            Arc::new(IdentityStub),
            config.clone()
        )
        .is_err());
        let app = try_scan_browser_router(
            Arc::new(ScanStub::default()),
            Arc::new(RestrictedIdentity),
            config,
        )
        .unwrap()
        .layer(Extension(TrustedScanHostContext::new(
            "host".into(),
            SystemTime::now() + Duration::from_secs(5),
        )));
        for (body, status, code) in [
            (
                "{}",
                StatusCode::BAD_REQUEST,
                "browser_expected_session_required",
            ),
            (
                r#"{"expected_session":{"tenant_id":"tenant-a","account_id":"account-a","session_id":"session-a","client_id":"phone"}}"#,
                StatusCode::UNAUTHORIZED,
                "browser_session_expired",
            ),
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::post("/context")
                        .header("origin", "http://192.168.31.159")
                        .header("content-type", "application/json")
                        .header("x-embedded-idp-browser", "1")
                        .header("cookie", "business=synthetic")
                        .body(Body::from(body))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), status);
            let bytes = to_bytes(response.into_body(), 4096).await.unwrap();
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()["error"],
                code
            );
        }
    }
    #[test]
    fn rejects_unsafe_verification_uri() {
        for uri in [
            "http://example.test/verify",
            "https://user@example.test/verify",
            "https://example.test/verify#fragment",
        ] {
            assert!(
                ScanDeviceHttpConfig::new("audience", "/auth/device-scan", uri).is_err(),
                "{uri}"
            );
        }
    }
    fn test_progress() -> ScanProgress {
        let now = SystemTime::now();
        ScanProgress {
            grant_id: "22222222-2222-4222-8222-222222222222".into(),
            mode: ScanLoginMode::DeviceDisplay,
            state: ScanGrantState::Approved,
            version: 1,
            server_time: now,
            expires_at: now + Duration::from_secs(60),
            code_expires_at: now + Duration::from_secs(60),
            approved_until: None,
            poll_after_ms: 2000,
            delivery_state: None,
            issuance_operation_id: None,
            recover_until: None,
            next_action: "exchange".into(),
        }
    }
    fn device_headers(request: axum::http::request::Builder) -> axum::http::request::Builder {
        request
            .header("x-device-id", "88888888-8888-4888-8888-888888888888")
            .header(
                "x-device-key-id",
                base64ct::Base64UrlUnpadded::encode_string(&[1; 32]),
            )
            .header(
                "x-device-challenge",
                base64ct::Base64UrlUnpadded::encode_string(&[2; 32]),
            )
            .header(
                "x-device-signature",
                base64ct::Base64UrlUnpadded::encode_string(&[3; 64]),
            )
            .header("x-device-signed-at", "1700000000")
    }
    fn device_router(stub: Arc<ScanStub>) -> Router {
        Router::new()
            .nest(
                "/outer/auth/device-scan",
                scan_device_router(
                    stub,
                    ScanDeviceHttpConfig::new(
                        "audience",
                        "/outer/auth/device-scan",
                        "https://example.test/verify",
                    )
                    .unwrap(),
                ),
            )
            .layer(Extension(TrustedScanHostContext::new(
                "host".into(),
                SystemTime::now() + Duration::from_secs(60),
            )))
    }
    #[tokio::test]
    async fn device_status_binds_exact_nested_path_and_body() {
        let stub = Arc::new(ScanStub::default());
        let body = r#"{"grant_id":"22222222-2222-4222-8222-222222222222","delivery_secret":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","tenant_id":"tenant-a"}"#;
        let response = device_router(stub.clone())
            .oneshot(
                device_headers(
                    Request::builder()
                        .method("POST")
                        .uri("/outer/auth/device-scan/status"),
                )
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        let (binding, proof) = stub.device.lock().unwrap().take().unwrap();
        assert_eq!(binding.external_path, "/outer/auth/device-scan/status");
        let expected_digest: [u8; 32] = Sha256::digest(body.as_bytes()).into();
        assert_eq!(binding.body_sha256, expected_digest);
        assert_eq!(binding.tenant_id, "tenant-a");
        assert_eq!(proof.device_id, "88888888-8888-4888-8888-888888888888");
    }
    #[tokio::test]
    async fn close_origin_uses_device_proof_and_returns_terminal_outcome() {
        let stub = Arc::new(ScanStub::default());
        let body = r#"{"entry_id":"terminal-login","tenant_id":"tenant-a","origin_action":"create","origin_operation_id":"33333333-3333-4333-8333-333333333333","delivery_secret":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#;
        let response = device_router(stub.clone())
            .oneshot(
                device_headers(
                    Request::builder()
                        .method("POST")
                        .uri("/outer/auth/device-scan/close-origin"),
                )
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = to_bytes(response.into_body(), 4096).await.unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value["outcome"], "closed");
        assert_eq!(value["origin_action"], "create");
        let closed = stub.closed_origin.lock().unwrap().take().unwrap();
        assert_eq!(closed.origin_action, ScanOriginAction::Create);
        assert_eq!(
            closed.origin_operation_id,
            "33333333-3333-4333-8333-333333333333"
        );
        let (binding, _) = stub.device.lock().unwrap().take().unwrap();
        assert_eq!(
            binding.external_path,
            "/outer/auth/device-scan/close-origin"
        );
        let expected_digest: [u8; 32] = Sha256::digest(body.as_bytes()).into();
        assert_eq!(binding.body_sha256, expected_digest);
    }
    #[test]
    fn closed_origin_is_a_gone_terminal_error() {
        let response = scan_err(ScanLoginError::OriginOperationClosed);
        assert_eq!(response.status(), StatusCode::GONE);
    }
    #[tokio::test]
    async fn origin_close_error_marks_only_the_closed_origin_terminal() {
        for (error, code, terminal) in [
            (ScanLoginError::NotFound, "scan_not_found", false),
            (
                ScanLoginError::OriginOperationClosed,
                "origin_operation_closed",
                true,
            ),
        ] {
            let response = scan_err(error);
            let bytes = to_bytes(response.into_body(), 4096).await.unwrap();
            let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(body["error"], code);
            assert_eq!(body["terminal"], terminal);
            assert_eq!(body["retryable"], false);
        }
    }
    #[tokio::test]
    async fn device_rejects_content_unknown_duplicate_and_oversize_before_service() {
        let stub = Arc::new(ScanStub::default());
        let router = device_router(stub.clone());
        let base = r#"{"grant_id":"22222222-2222-4222-8222-222222222222","delivery_secret":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","tenant_id":"tenant-a"}"#;
        let unknown = format!(r#"{{"unknown":1,{}}}"#, &base[1..]);
        let duplicate = base.replacen(
            "\"tenant_id\":\"tenant-a\"",
            "\"tenant_id\":\"tenant-a\",\"tenant_id\":\"tenant-b\"",
            1,
        );
        for (content, body) in [
            ("text/plain", base.to_owned()),
            ("application/json", unknown),
            ("application/json", duplicate),
            (
                "application/json",
                "x".repeat(AUTH_DEVICE_BODY_LIMIT_BYTES + 1),
            ),
        ] {
            let response = router
                .clone()
                .oneshot(
                    device_headers(
                        Request::builder()
                            .method("POST")
                            .uri("/outer/auth/device-scan/status"),
                    )
                    .header("content-type", content)
                    .body(Body::from(body))
                    .unwrap(),
                )
                .await
                .unwrap();
            assert_ne!(response.status(), StatusCode::OK, "content type {content}");
        }
        assert!(stub.device.lock().unwrap().is_none());
    }
}
