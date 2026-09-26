use crate::{
    http_support::unix_time_secs,
    tenant_admin::{error, target},
    tenant_auth::{call, no_store},
    tenant_devices::device_json,
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
        .route("/admin/devices/:device_id/disable", post(disable))
        .route("/admin/devices/:device_id/revoke", post(revoke))
        .with_state(AdminState { mode, service })
        .layer(DefaultBodyLimit::max(16384))
        .layer(middleware::from_fn(no_store))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PageQuery {
    limit: Option<u32>,
    cursor: Option<String>,
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
    expected_status: ExpectedStatus,
}
fn record_json(record: AccessDeviceRecord) -> Value {
    let mut value = device_json(record.device);
    value["device_name"] = json!(record.name);
    value["registered_at_unix_secs"] = json!(unix_time_secs(record.registered_at));
    value["last_seen_at_unix_secs"] = json!(record.last_seen_at.map(unix_time_secs));
    value
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
                    expected_status: body.expected_status.into(),
                },
            },
        )
    })
    .await
    {
        Ok(event) => match event.change {
            AccessChange::Device { after, .. } => {
                Json(json!({"device":record_json(after),"audit_id":event.id})).into_response()
            }
            _ => error(AccessError::InvalidStoreResponse),
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
