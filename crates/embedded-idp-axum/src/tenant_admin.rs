use crate::tenant_auth::tenant_error;
use axum::{
    http::{HeaderMap, StatusCode},
    response::Response,
    Extension,
};
use embedded_idp_core::access::*;

pub(super) fn target(
    mode: TenancyMode,
    context: Option<Extension<AccessAdminContext>>,
    headers: &HeaderMap,
) -> Result<(AccessAdminContext, String), Response> {
    let Some(Extension(context)) = context else {
        return Err(tenant_error(
            StatusCode::UNAUTHORIZED,
            "management_authentication_required",
            "management authentication is required",
        ));
    };
    let mut values = headers.get_all("x-embedded-idp-tenant-id").iter();
    let requested = values
        .next()
        .map(|v| v.to_str())
        .transpose()
        .map_err(|_| error(AccessError::InvalidInput("tenant_header")))?;
    if values.next().is_some() {
        return Err(error(AccessError::InvalidInput("tenant_header")));
    }
    let actor = &context.actor.tenant_id;
    let tenant = match (mode, actor.as_str(), requested) {
        (TenancyMode::Enabled, "0", None) => {
            return Err(error(AccessError::InvalidInput("target_tenant_required")))
        }
        (_, _, Some(t)) => t,
        _ => actor.as_str(),
    };
    mode.validate_business_tenant(tenant).map_err(error)?;
    if actor != "0" && actor != tenant {
        return Err(error(AccessError::Forbidden));
    }
    let tenant = tenant.to_owned();
    Ok((context, tenant))
}
pub(super) fn error(error: AccessError) -> Response {
    let (status, code, message) = match error {
        AccessError::Forbidden => (
            StatusCode::FORBIDDEN,
            "management_forbidden",
            "management action is not allowed",
        ),
        AccessError::NotFound(_) => (
            StatusCode::NOT_FOUND,
            "not_found",
            "resource or tenant was not found",
        ),
        AccessError::Conflict(_) => (
            StatusCode::CONFLICT,
            "conflict",
            "state changed or action conflicts with current state",
        ),
        AccessError::InvalidInput(_) | AccessError::InvalidCursor | AccessError::ModeMismatch => (
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "request is invalid",
        ),
        AccessError::FeatureDisabled => (
            StatusCode::FORBIDDEN,
            "feature_disabled",
            "feature is disabled",
        ),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "the request could not be completed",
        ),
    };
    tenant_error(status, code, message)
}

pub(super) fn platform_context(
    context: Option<Extension<AccessAdminContext>>,
    headers: &HeaderMap,
) -> Result<AccessAdminContext, Response> {
    let Some(Extension(context)) = context else {
        return Err(tenant_error(
            StatusCode::UNAUTHORIZED,
            "management_authentication_required",
            "management authentication is required",
        ));
    };
    // Platform operations never accept a selected business tenant.
    let mut values = headers.get_all("x-embedded-idp-tenant-id").iter();
    if values.next().is_some_and(|v| v != "0") || values.next().is_some() {
        return Err(error(AccessError::InvalidInput("tenant_header")));
    }
    Ok(context)
}
