use crate::{
    http_support::unix_time_secs,
    tenant_admin::{error, platform_context, target},
    tenant_auth::{call, no_store},
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
use embedded_idp_core::access::*;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};
#[derive(Clone)]
struct AdminState {
    mode: TenancyMode,
    service: Arc<dyn AccountAdminService>,
}
/// Trusted management context only. Shared credential writes are not member changes.
pub fn account_admin_router(mode: TenancyMode, service: Arc<dyn AccountAdminService>) -> Router {
    let mut router = Router::new()
        .route("/admin/accounts", get(list))
        .route("/admin/accounts/:account_id", get(detail))
        .route("/admin/platform/accounts", get(platform_list))
        .route("/admin/platform/accounts/:account_id", get(platform_detail));
    if mode == TenancyMode::Enabled {
        router = router
            .route("/admin/members/:account_id/status", post(set_status))
            .route("/admin/members/:account_id/bind", post(bind));
    }
    router
        .with_state(AdminState { mode, service })
        .layer(DefaultBodyLimit::max(16384))
        .layer(middleware::from_fn(no_store))
}
#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Status {
    PendingVerification,
    Active,
    Disabled,
    Closed,
}
impl Status {
    pub(super) fn core(self) -> AccountIdentityStatus {
        match self {
            Self::PendingVerification => AccountIdentityStatus::PendingVerification,
            Self::Active => AccountIdentityStatus::Active,
            Self::Disabled => AccountIdentityStatus::Disabled,
            Self::Closed => AccountIdentityStatus::Closed,
        }
    }
}
#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum MemberStatus {
    Active,
    Suspended,
    Removed,
}
impl MemberStatus {
    fn core(self) -> MembershipStatus {
        match self {
            Self::Active => MembershipStatus::Active,
            Self::Suspended => MembershipStatus::Suspended,
            Self::Removed => MembershipStatus::Removed,
        }
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Filter {
    status: Option<Status>,
    membership_status: Option<MemberStatus>,
    email: Option<String>,
    created_after_unix_secs: Option<u64>,
    created_before_unix_secs: Option<u64>,
}
impl Filter {
    fn core(&self) -> Result<AdminAccountFilter, AccessError> {
        fn time(value: Option<u64>) -> Result<Option<SystemTime>, AccessError> {
            value
                .map(|v| {
                    SystemTime::UNIX_EPOCH
                        .checked_add(Duration::from_secs(v))
                        .ok_or(AccessError::InvalidInput("created_time"))
                })
                .transpose()
        }
        Ok(AdminAccountFilter {
            status: self.status.map(Status::core),
            membership_status: self.membership_status.map(MemberStatus::core),
            email: self.email.clone(),
            created_after: time(self.created_after_unix_secs)?,
            created_before: time(self.created_before_unix_secs)?,
        })
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PageQuery {
    limit: Option<u32>,
    cursor: Option<String>,
    status: Option<Status>,
    membership_status: Option<MemberStatus>,
    email: Option<String>,
    created_after_unix_secs: Option<u64>,
    created_before_unix_secs: Option<u64>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Cursor {
    version: u8,
    tenant_id: Option<String>,
    filter: Filter,
    after: Vec<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SetStatus {
    status: MemberStatus,
    expected_version: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EmptyBody {}
fn member(m: TenantMembership) -> Value {
    json!({"tenant_id":m.tenant_id,"account_id":m.subject_id,"status":match m.status{MembershipStatus::Active=>"active",MembershipStatus::Suspended=>"suspended",MembershipStatus::Removed=>"removed"},"version":m.version,"joined_at_unix_secs":unix_time_secs(m.joined_at)})
}
pub(super) fn account(r: AccessAccountRecord) -> Value {
    json!({"account_id":r.account_id,"email":r.email,"display_name":r.display_name,"status":match r.status{AccountIdentityStatus::PendingVerification=>"pending_verification",AccountIdentityStatus::Active=>"active",AccountIdentityStatus::Disabled=>"disabled",AccountIdentityStatus::Closed=>"closed"},"created_at_unix_secs":unix_time_secs(r.created_at),"membership":r.membership.map(member)})
}
fn scope(
    mode: TenancyMode,
    context: Option<Extension<AccessAdminContext>>,
    headers: &HeaderMap,
    platform: bool,
) -> Result<(AccessAdminContext, Option<String>), Response> {
    if platform {
        platform_context(context, headers).map(|c| (c, None))
    } else {
        target(mode, context, headers).map(|(c, t)| (c, Some(t)))
    }
}
async fn list(
    State(state): State<AdminState>,
    context: Option<Extension<AccessAdminContext>>,
    headers: HeaderMap,
    Query(query): Query<PageQuery>,
) -> Response {
    list_scoped(state, context, headers, query, false).await
}
async fn platform_list(
    State(state): State<AdminState>,
    context: Option<Extension<AccessAdminContext>>,
    headers: HeaderMap,
    Query(query): Query<PageQuery>,
) -> Response {
    list_scoped(state, context, headers, query, true).await
}
async fn list_scoped(
    state: AdminState,
    context: Option<Extension<AccessAdminContext>>,
    headers: HeaderMap,
    query: PageQuery,
    platform: bool,
) -> Response {
    let (context, tenant) = match scope(state.mode, context, &headers, platform) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let filter = Filter {
        status: query.status,
        membership_status: query.membership_status,
        email: query.email,
        created_after_unix_secs: query.created_after_unix_secs,
        created_before_unix_secs: query.created_before_unix_secs,
    };
    let core_filter = match filter.core() {
        Ok(f) => f,
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
                .and_then(|b| serde_json::from_slice::<Cursor>(&b).ok())
            else {
                return error(AccessError::InvalidCursor);
            };
            let stored = match c.filter.core() {
                Ok(f) => f,
                Err(_) => return error(AccessError::InvalidCursor),
            };
            Some(AccessCursor {
                version: c.version,
                scope: AccessListScope::AdminAccounts {
                    tenant_id: c.tenant_id,
                    filter: stored,
                },
                after: c.after,
            })
        }
    };
    match call(move || {
        state.service.list_accounts(
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
                    let AccessListScope::AdminAccounts { tenant_id, .. } = c.scope else {
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
            Json(json!({"items":page.items.into_iter().map(account).collect::<Vec<_>>(),"has_more":page.has_more,"next_cursor":next})).into_response()
        }
        Err(e) => error(e),
    }
}
async fn detail(
    State(state): State<AdminState>,
    context: Option<Extension<AccessAdminContext>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    detail_scoped(state, context, headers, id, false).await
}
async fn platform_detail(
    State(state): State<AdminState>,
    context: Option<Extension<AccessAdminContext>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    detail_scoped(state, context, headers, id, true).await
}
async fn detail_scoped(
    state: AdminState,
    context: Option<Extension<AccessAdminContext>>,
    headers: HeaderMap,
    id: String,
    platform: bool,
) -> Response {
    let (context, tenant) = match scope(state.mode, context, &headers, platform) {
        Ok(v) => v,
        Err(e) => return e,
    };
    match call(move || state.service.get_account(context, tenant, id)).await {
        Ok(r) => Json(account(r)).into_response(),
        Err(e) => error(e),
    }
}
async fn set_status(
    State(state): State<AdminState>,
    context: Option<Extension<AccessAdminContext>>,
    headers: HeaderMap,
    Path(subject_id): Path<String>,
    Json(body): Json<SetStatus>,
) -> Response {
    change(
        state,
        context,
        headers,
        AccessAdminMutation::SetMemberStatus {
            subject_id,
            status: body.status.core(),
            expected_version: body.expected_version,
        },
    )
    .await
}
async fn bind(
    State(state): State<AdminState>,
    context: Option<Extension<AccessAdminContext>>,
    headers: HeaderMap,
    Path(subject_id): Path<String>,
    Json(_): Json<EmptyBody>,
) -> Response {
    change(
        state,
        context,
        headers,
        AccessAdminMutation::BindMember { subject_id },
    )
    .await
}
async fn change(
    state: AdminState,
    context: Option<Extension<AccessAdminContext>>,
    headers: HeaderMap,
    mutation: AccessAdminMutation,
) -> Response {
    let (context, tenant_id) = match target(state.mode, context, &headers) {
        Ok(v) => v,
        Err(e) => return e,
    };
    match call(move || {
        state.service.execute(
            context,
            AccessAdminCommand {
                tenant_id,
                mutation,
            },
        )
    })
    .await
    {
        Ok(event) => match event.change {
            AccessChange::Membership { after, .. } => {
                Json(json!({"membership":member(after),"audit_id":event.id})).into_response()
            }
            _ => error(AccessError::InvalidStoreResponse),
        },
        Err(e) => error(e),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn membership_requests_cannot_change_shared_credentials_or_identity_status() {
        assert!(serde_json::from_str::<SetStatus>(
            r#"{"status":"active","expected_version":1,"password":"override"}"#
        )
        .is_err());
        assert!(
            serde_json::from_str::<SetStatus>(r#"{"status":"disabled","expected_version":1}"#)
                .is_err()
        );
        assert!(serde_json::from_str::<EmptyBody>(r#"{"tenant_id":"other"}"#).is_err());
        let f = Filter {
            status: None,
            membership_status: None,
            email: None,
            created_after_unix_secs: Some(u64::MAX),
            created_before_unix_secs: None,
        };
        assert!(f.core().and_then(|f| f.validate(None)).is_err());
    }
}
