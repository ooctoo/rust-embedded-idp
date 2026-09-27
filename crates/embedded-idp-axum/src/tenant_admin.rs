use crate::tenant_auth::tenant_error;
use axum::{
    http::{HeaderMap, StatusCode},
    response::Response,
    Extension,
};
use embedded_idp_core::access::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(super) enum ManagementSortOrder {
    Asc,
    #[default]
    Desc,
}
impl ManagementSortOrder {
    pub(super) fn core(self) -> AccessSortOrder {
        match self {
            Self::Asc => AccessSortOrder::Asc,
            Self::Desc => AccessSortOrder::Desc,
        }
    }
    pub(super) fn from_core(value: AccessSortOrder) -> Self {
        match value {
            AccessSortOrder::Asc => Self::Asc,
            AccessSortOrder::Desc => Self::Desc,
        }
    }
}

pub(super) fn target(
    mode: TenancyMode,
    context: Option<Extension<AccessAdminContext>>,
    headers: &HeaderMap,
) -> Result<(AccessAdminContext, String), Response> {
    reject_business_header(headers)?;
    target_inner(mode, context, headers)
}

pub(super) fn business_id(headers: &HeaderMap, allow_idp: bool) -> Result<String, Response> {
    let mut values = headers.get_all("x-embedded-idp-business-id").iter();
    let value = values
        .next()
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| error(AccessError::InvalidInput("business_header")))?;
    if values.next().is_some() {
        return Err(error(AccessError::InvalidInput("business_header")));
    }
    if allow_idp {
        validate_access_business_id(value)
    } else {
        validate_business_id(value)
    }
    .map_err(error)?;
    Ok(value.to_owned())
}

pub(super) fn optional_business_id(
    headers: &HeaderMap,
    allow_idp: bool,
) -> Result<Option<String>, Response> {
    if !headers.contains_key("x-embedded-idp-business-id") {
        return Ok(None);
    }
    business_id(headers, allow_idp).map(Some)
}

pub(super) fn optional_business_target(
    mode: TenancyMode,
    context: Option<Extension<AccessAdminContext>>,
    headers: &HeaderMap,
    allow_idp: bool,
) -> Result<(AccessAdminContext, String, Option<String>), Response> {
    let (context, tenant) = target_inner(mode, context, headers)?;
    Ok((context, tenant, optional_business_id(headers, allow_idp)?))
}

pub(super) fn business_target(
    mode: TenancyMode,
    context: Option<Extension<AccessAdminContext>>,
    headers: &HeaderMap,
    allow_idp: bool,
) -> Result<(AccessAdminContext, String, String), Response> {
    let (context, tenant) = target_inner(mode, context, headers)?;
    Ok((context, tenant, business_id(headers, allow_idp)?))
}

fn reject_business_header(headers: &HeaderMap) -> Result<(), Response> {
    if headers.contains_key("x-embedded-idp-business-id") {
        return Err(error(AccessError::InvalidInput(
            "unexpected_business_header",
        )));
    }
    Ok(())
}

fn target_inner(
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
    reject_business_header(headers)?;
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

#[cfg(test)]
mod tests {
    use super::ManagementSortOrder;

    #[test]
    fn business_selection_is_explicit_and_management_namespace_is_protected() {
        use super::*;
        use axum::http::HeaderValue;
        let mut headers = HeaderMap::new();
        assert!(business_id(&headers, false).is_err());
        for invalid in ["", "IDP", "idp.other", "a/b", "*"] {
            headers.insert(
                "x-embedded-idp-business-id",
                HeaderValue::from_str(invalid).unwrap(),
            );
            assert!(business_id(&headers, true).is_err());
        }
        headers.insert(
            "x-embedded-idp-business-id",
            HeaderValue::from_static("f_01"),
        );
        assert_eq!(business_id(&headers, false).unwrap(), "f_01");
        assert!(reject_business_header(&headers).is_err());
        headers.append(
            "x-embedded-idp-business-id",
            HeaderValue::from_static("f_02"),
        );
        assert!(business_id(&headers, false).is_err());
        headers.remove("x-embedded-idp-business-id");
        headers.insert(
            "x-embedded-idp-business-id",
            HeaderValue::from_static("idp"),
        );
        assert_eq!(business_id(&headers, true).unwrap(), "idp");
        assert!(business_id(&headers, false).is_err());
    }

    #[derive(Default, serde::Deserialize)]
    #[serde(default)]
    struct Query {
        sort_order: ManagementSortOrder,
    }

    #[test]
    fn management_sort_order_wire_values() {
        assert_eq!(
            serde_json::from_str::<Query>(r#"{}"#).unwrap().sort_order,
            ManagementSortOrder::Desc
        );
        assert_eq!(
            serde_json::from_str::<Query>(r#"{"sort_order":"asc"}"#)
                .unwrap()
                .sort_order,
            ManagementSortOrder::Asc
        );
        assert_eq!(
            serde_json::from_str::<Query>(r#"{"sort_order":"desc"}"#)
                .unwrap()
                .sort_order,
            ManagementSortOrder::Desc
        );
        assert!(serde_json::from_str::<Query>(r#"{"sort_order":"sideways"}"#).is_err());
    }
}
