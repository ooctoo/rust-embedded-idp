use crate::{
    http_support::unix_time_secs,
    tenant_admin::{error, target, ManagementSortOrder},
    tenant_auth::{call, no_store},
    tenant_devices::{device_json, key_metadata_json},
};
use axum::{
    extract::{DefaultBodyLimit, Path, Query, State},
    http::HeaderMap,
    middleware,
    response::{IntoResponse, Response},
    routing::{get, post},
    Extension, Json, Router,
};
use base64ct::{Base64UrlUnpadded, Encoding};
use embedded_idp_core::{access::*, DeviceStatus};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};

#[derive(Clone)]
struct AdminState {
    mode: TenancyMode,
    service: Arc<dyn TenantDeviceAdminService>,
}
/// Management-only routes. Host middleware MUST authenticate the management
/// audience/purpose and inject AccessAdminContext; body/header values cannot do so.
pub fn tenant_device_admin_router(
    mode: TenancyMode,
    service: Arc<dyn TenantDeviceAdminService>,
) -> Router {
    Router::new()
        .route("/admin/devices", get(list))
        .route("/admin/devices/:device_id", get(detail))
        .route("/admin/devices/:device_id/keys/:key_id", get(key_metadata))
        .route("/admin/devices/:device_id/enable", post(enable))
        .route("/admin/devices/:device_id/disable", post(disable))
        .route("/admin/devices/:device_id/revoke", post(revoke))
        .route(
            "/admin/devices/:device_id/operations/:operation_id",
            get(operation_result),
        )
        .route("/admin/devices/:device_id/bindings", get(binding_list))
        .route(
            "/admin/devices/:device_id/bindings/:binding_id",
            get(binding_detail),
        )
        .route(
            "/admin/devices/:device_id/bindings/:binding_id/unbind",
            post(unbind_binding),
        )
        .with_state(AdminState { mode, service })
        .layer(DefaultBodyLimit::max(16384))
        .layer(middleware::from_fn(no_store))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PageQuery {
    limit: Option<u32>,
    cursor: Option<String>,
    #[serde(default)]
    sort_order: ManagementSortOrder,
    account_id: Option<String>,
    client_id: Option<String>,
    status: Option<ExpectedStatus>,
    registered_after_unix_secs: Option<u64>,
    registered_before_unix_secs: Option<u64>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Cursor {
    version: u8,
    tenant_id: String,
    filter: Filter,
    after: Vec<String>,
    #[serde(default)]
    sort_order: ManagementSortOrder,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum ExpectedStatus {
    Pending,
    Active,
    Disabled,
    Revoked,
}
impl From<ExpectedStatus> for DeviceStatus {
    fn from(value: ExpectedStatus) -> Self {
        match value {
            ExpectedStatus::Pending => Self::Pending,
            ExpectedStatus::Active => Self::Active,
            ExpectedStatus::Disabled => Self::Disabled,
            ExpectedStatus::Revoked => Self::Revoked,
        }
    }
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Filter {
    account_id: Option<String>,
    client_id: Option<String>,
    status: Option<ExpectedStatus>,
    registered_after_unix_secs: Option<u64>,
    registered_before_unix_secs: Option<u64>,
}
impl Filter {
    fn core(&self) -> Result<AdminDeviceFilter, AccessError> {
        fn time(value: Option<u64>) -> Result<Option<SystemTime>, AccessError> {
            value
                .map(|v| {
                    SystemTime::UNIX_EPOCH
                        .checked_add(Duration::from_secs(v))
                        .ok_or(AccessError::InvalidInput("registered_time"))
                })
                .transpose()
        }
        Ok(AdminDeviceFilter {
            account_id: self.account_id.clone(),
            client_id: self.client_id.clone(),
            status: self.status.clone().map(Into::into),
            registered_after: time(self.registered_after_unix_secs)?,
            registered_before: time(self.registered_before_unix_secs)?,
        })
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChangeBody {
    expected_version: u64,
    operation_id: String,
    reason: String,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum BindingStatus {
    Active,
    Suspended,
    Unbound,
}
impl BindingStatus {
    fn core(&self) -> embedded_idp_core::AccountDeviceBindingStatus {
        match self {
            Self::Active => embedded_idp_core::AccountDeviceBindingStatus::Active,
            Self::Suspended => embedded_idp_core::AccountDeviceBindingStatus::Suspended,
            Self::Unbound => embedded_idp_core::AccountDeviceBindingStatus::Unbound,
        }
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BindingPageQuery {
    limit: Option<u32>,
    cursor: Option<String>,
    status: Option<BindingStatus>,
    #[serde(default)]
    sort_order: ManagementSortOrder,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BindingCursor {
    version: u8,
    tenant_id: String,
    device_id: String,
    status: Option<BindingStatus>,
    after: Vec<String>,
    sort_order: ManagementSortOrder,
}
fn record_json(record: AccessDeviceRecord) -> Value {
    let mut value = device_json(record.device);
    value["device_name"] = json!(record.name);
    value["registered_at_unix_secs"] = json!(unix_time_secs(record.registered_at));
    value["last_seen_at_unix_secs"] = json!(record.last_seen_at.map(unix_time_secs));
    value
}
fn binding_json(r: AccessDeviceBindingRecord) -> Value {
    json!({"tenant_id":r.tenant_id,"binding_id":r.id,"device_id":r.device_id,"account_id":r.account_id,
        "status":match r.status {embedded_idp_core::AccountDeviceBindingStatus::Active=>"active",embedded_idp_core::AccountDeviceBindingStatus::Suspended=>"suspended",embedded_idp_core::AccountDeviceBindingStatus::Unbound=>"unbound"},
        "version":r.version,"bound_at_unix_secs":unix_time_secs(r.bound_at),
        "unbound_at_unix_secs":r.unbound_at.map(unix_time_secs),
        "last_authenticated_at_unix_secs":r.last_authenticated_at.map(unix_time_secs)})
}
fn receipt_json(r: DeviceOperationReceipt) -> Value {
    json!({"operation_id":r.operation_id,"audit_id":r.audit_id,"device_id":r.device_id,
        "binding_id":r.binding_id,"operation":r.operation,"occurred_at_unix_secs":unix_time_secs(r.occurred_at),
        "result_version":r.result_version,"result_status":r.result_status})
}
async fn operation_result(
    State(state): State<AdminState>,
    context: Option<Extension<AccessAdminContext>>,
    headers: HeaderMap,
    Path((device, operation_id)): Path<(String, String)>,
) -> Response {
    let (context, tenant) = match target(state.mode, context, &headers) {
        Ok(v) => v,
        Err(e) => return e,
    };
    match call(move || {
        state
            .service
            .device_operation_result(context, tenant, device, operation_id)
    })
    .await
    {
        Ok(receipt) => Json(receipt_json(receipt)).into_response(),
        Err(e) => error(e),
    }
}
async fn key_metadata(
    State(state): State<AdminState>,
    context: Option<Extension<AccessAdminContext>>,
    headers: HeaderMap,
    Path((device, key)): Path<(String, String)>,
) -> Response {
    let (context, tenant) = match target(state.mode, context, &headers) {
        Ok(v) => v,
        Err(e) => return e,
    };
    match call(move || {
        state
            .service
            .get_device_key_metadata(context, tenant, device, key)
    })
    .await
    {
        Ok(metadata) => Json(key_metadata_json(metadata)).into_response(),
        Err(cause) => error(cause),
    }
}
async fn binding_list(
    State(state): State<AdminState>,
    context: Option<Extension<AccessAdminContext>>,
    headers: HeaderMap,
    Path(device): Path<String>,
    Query(query): Query<BindingPageQuery>,
) -> Response {
    let (context, tenant) = match target(state.mode, context, &headers) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let cursor = match query.cursor {
        None => None,
        Some(raw) => {
            if raw.len() > 4096 {
                return error(AccessError::InvalidCursor);
            }
            let Some(c) = Base64UrlUnpadded::decode_vec(&raw)
                .ok()
                .and_then(|bytes| serde_json::from_slice::<BindingCursor>(&bytes).ok())
            else {
                return error(AccessError::InvalidCursor);
            };
            Some(AccessCursor {
                version: c.version,
                scope: AccessListScope::AdminDeviceBindings {
                    tenant_id: c.tenant_id,
                    device_id: c.device_id,
                    status: c.status.map(|s| s.core()),
                },
                after: c.after,
                sort_order: Some(c.sort_order.core()),
            })
        }
    };
    match call(move || {
        state.service.list_device_bindings(
            context,
            tenant,
            device,
            query.status.map(|s| s.core()),
            AccessPageRequest {
                limit: query.limit.unwrap_or(50),
                cursor,
                sort_order: Some(query.sort_order.core()),
            },
        )
    })
    .await
    {
        Ok(page) => {
            let next = match page.next_cursor {
                None => None,
                Some(c) => {
                    let AccessListScope::AdminDeviceBindings {
                        tenant_id,
                        device_id,
                        status,
                    } = c.scope
                    else {
                        return error(AccessError::InvalidStoreResponse);
                    };
                    if c.after.len() != 2 {
                        return error(AccessError::InvalidStoreResponse);
                    }
                    Some(Base64UrlUnpadded::encode_string(
                        &serde_json::to_vec(&BindingCursor {
                            version: c.version,
                            tenant_id,
                            device_id,
                            status: status.map(|s| match s {
                                embedded_idp_core::AccountDeviceBindingStatus::Active => {
                                    BindingStatus::Active
                                }
                                embedded_idp_core::AccountDeviceBindingStatus::Suspended => {
                                    BindingStatus::Suspended
                                }
                                embedded_idp_core::AccountDeviceBindingStatus::Unbound => {
                                    BindingStatus::Unbound
                                }
                            }),
                            after: c.after,
                            sort_order: ManagementSortOrder::from_core(
                                c.sort_order.unwrap_or(AccessSortOrder::Desc),
                            ),
                        })
                        .unwrap(),
                    ))
                }
            };
            Json(json!({"items":page.items.into_iter().map(binding_json).collect::<Vec<_>>(),"has_more":page.has_more,"next_cursor":next})).into_response()
        }
        Err(e) => error(e),
    }
}
async fn binding_detail(
    State(state): State<AdminState>,
    context: Option<Extension<AccessAdminContext>>,
    headers: HeaderMap,
    Path((device, binding)): Path<(String, String)>,
) -> Response {
    let (context, tenant) = match target(state.mode, context, &headers) {
        Ok(v) => v,
        Err(e) => return e,
    };
    match call(move || {
        state
            .service
            .get_device_binding(context, tenant, device, binding)
    })
    .await
    {
        Ok(row) => Json(binding_json(row)).into_response(),
        Err(e) => error(e),
    }
}
async fn unbind_binding(
    State(state): State<AdminState>,
    context: Option<Extension<AccessAdminContext>>,
    headers: HeaderMap,
    Path((device, binding)): Path<(String, String)>,
    Json(body): Json<ChangeBody>,
) -> Response {
    let operation_id = body.operation_id.clone();
    let (context, tenant) = match target(state.mode, context, &headers) {
        Ok(v) => v,
        Err(e) => return e,
    };
    match call(move || {
        state.service.unbind_device_binding(
            context,
            tenant,
            device,
            binding,
            body.expected_version,
            body.operation_id,
            body.reason,
        )
    })
    .await
    {
        Ok(event) => match event.device_receipt(&operation_id) {
            Some(receipt) => Json(receipt_json(receipt)).into_response(),
            None => error(AccessError::InvalidStoreResponse),
        },
        Err(e) => error(e),
    }
}
async fn list(
    State(state): State<AdminState>,
    context: Option<Extension<AccessAdminContext>>,
    headers: HeaderMap,
    Query(query): Query<PageQuery>,
) -> Response {
    let (context, tenant) = match target(state.mode, context, &headers) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let filter = Filter {
        account_id: query.account_id,
        client_id: query.client_id,
        status: query.status,
        registered_after_unix_secs: query.registered_after_unix_secs,
        registered_before_unix_secs: query.registered_before_unix_secs,
    };
    let core_filter = match filter.core() {
        Ok(v) => v,
        Err(e) => return error(e),
    };
    let cursor = match query.cursor {
        None => None,
        Some(raw) => {
            if raw.len() > 4096 {
                return error(AccessError::InvalidCursor);
            }
            let Some(c) = Base64UrlUnpadded::decode_vec(&raw)
                .ok()
                .and_then(|bytes| serde_json::from_slice::<Cursor>(&bytes).ok())
            else {
                return error(AccessError::InvalidCursor);
            };
            let stored = match c.filter.core() {
                Ok(v) => v,
                Err(_) => return error(AccessError::InvalidCursor),
            };
            Some(AccessCursor {
                version: c.version,
                scope: AccessListScope::AdminDevices {
                    tenant_id: c.tenant_id,
                    filter: stored,
                },
                after: c.after,
                sort_order: Some(c.sort_order.core()),
            })
        }
    };
    match call(move || {
        state.service.list_devices(
            context,
            tenant,
            core_filter,
            AccessPageRequest {
                limit: query.limit.unwrap_or(50),
                cursor,
                sort_order: Some(query.sort_order.core()),
            },
        )
    })
    .await
    {
        Ok(page) => {
            let next = match page.next_cursor {
                None => None,
                Some(c) => {
                    let AccessListScope::AdminDevices { tenant_id, .. } = c.scope else {
                        return error(AccessError::InvalidStoreResponse);
                    };
                    if c.after.len() != 2 {
                        return error(AccessError::InvalidStoreResponse);
                    }
                    Some(Base64UrlUnpadded::encode_string(
                        &serde_json::to_vec(&Cursor {
                            version: c.version,
                            tenant_id,
                            filter,
                            after: c.after,
                            sort_order: ManagementSortOrder::from_core(
                                c.sort_order.unwrap_or(AccessSortOrder::Desc),
                            ),
                        })
                        .unwrap(),
                    ))
                }
            };
            Json(json!({"items":page.items.into_iter().map(record_json).collect::<Vec<_>>(),"has_more":page.has_more,"next_cursor":next})).into_response()
        }
        Err(e) => error(e),
    }
}
async fn detail(
    State(state): State<AdminState>,
    context: Option<Extension<AccessAdminContext>>,
    headers: HeaderMap,
    Path(device): Path<String>,
) -> Response {
    let (context, tenant) = match target(state.mode, context, &headers) {
        Ok(v) => v,
        Err(e) => return e,
    };
    match call(move || state.service.get_device(context, tenant, device)).await {
        Ok(row) => Json(record_json(row)).into_response(),
        Err(e) => error(e),
    }
}
async fn disable(
    State(state): State<AdminState>,
    context: Option<Extension<AccessAdminContext>>,
    headers: HeaderMap,
    Path(device): Path<String>,
    Json(body): Json<ChangeBody>,
) -> Response {
    change(
        state,
        context,
        headers,
        device,
        body,
        DeviceStatus::Disabled,
    )
    .await
}
async fn enable(
    State(state): State<AdminState>,
    context: Option<Extension<AccessAdminContext>>,
    headers: HeaderMap,
    Path(device): Path<String>,
    Json(body): Json<ChangeBody>,
) -> Response {
    change(state, context, headers, device, body, DeviceStatus::Active).await
}
async fn revoke(
    State(state): State<AdminState>,
    context: Option<Extension<AccessAdminContext>>,
    headers: HeaderMap,
    Path(device): Path<String>,
    Json(body): Json<ChangeBody>,
) -> Response {
    change(state, context, headers, device, body, DeviceStatus::Revoked).await
}
async fn change(
    state: AdminState,
    context: Option<Extension<AccessAdminContext>>,
    headers: HeaderMap,
    device: String,
    body: ChangeBody,
    status: DeviceStatus,
) -> Response {
    let operation_id = body.operation_id.clone();
    let (context, tenant) = match target(state.mode, context, &headers) {
        Ok(v) => v,
        Err(e) => return e,
    };
    match call(move || {
        state.service.execute(
            context,
            AccessAdminCommand {
                tenant_id: tenant,
                mutation: AccessAdminMutation::SetDeviceStatus {
                    device_id: device,
                    status,
                    expected_version: body.expected_version,
                    operation_id: body.operation_id,
                    reason: body.reason,
                },
            },
        )
    })
    .await
    {
        Ok(event) => match event.device_receipt(&operation_id) {
            Some(receipt) => Json(receipt_json(receipt)).into_response(),
            None => error(AccessError::InvalidStoreResponse),
        },
        Err(e) => error(e),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;
    #[test]
    fn management_target_is_explicit_and_never_replaces_actor() {
        let context = AccessAdminContext {
            actor: AccessActor {
                tenant_id: "0".into(),
                subject_id: "admin".into(),
                session_id: "session".into(),
            },
            authentication_source: "host-management".into(),
            request_id: "req".into(),
        };
        let mut headers = HeaderMap::new();
        assert_eq!(
            target(TenancyMode::Enabled, None, &headers)
                .unwrap_err()
                .status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            target(
                TenancyMode::Enabled,
                Some(Extension(context.clone())),
                &headers
            )
            .unwrap_err()
            .status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            target(
                TenancyMode::Disabled,
                Some(Extension(context.clone())),
                &headers
            )
            .unwrap()
            .1,
            "0"
        );
        headers.insert("x-embedded-idp-tenant-id", "t1".parse().unwrap());
        let (actor, tenant) = target(
            TenancyMode::Enabled,
            Some(Extension(context.clone())),
            &headers,
        )
        .unwrap();
        assert_eq!(actor.actor.tenant_id, "0");
        assert_eq!(tenant, "t1");
        assert!(target(
            TenancyMode::Disabled,
            Some(Extension(context.clone())),
            &headers
        )
        .is_err());
        let mut tenant_context = context.clone();
        tenant_context.actor.tenant_id = "t2".into();
        assert_eq!(
            target(
                TenancyMode::Enabled,
                Some(Extension(tenant_context)),
                &headers
            )
            .unwrap_err()
            .status(),
            StatusCode::FORBIDDEN
        );
        headers.append("x-embedded-idp-tenant-id", "t1".parse().unwrap());
        assert!(target(TenancyMode::Enabled, Some(Extension(context)), &headers).is_err());
        assert!(serde_json::from_str::<ChangeBody>(
            r#"{"expected_status":"active","actor_id":"admin"}"#
        )
        .is_err());
        assert!(serde_json::from_str::<ChangeBody>(
            r#"{"expected_status":"active","expected_status":"revoked"}"#
        )
        .is_err());
    }
}
