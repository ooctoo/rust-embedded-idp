use super::*;
use crate::self_password_change::{change_error, json_rejection};
use crate::self_session_revocation::{
    auth_error, completed, invalid_request, parse_operation_id, revocation_auth_error,
};
use axum::extract::rejection::JsonRejection;
use embedded_idp_core::access::{BrowserSessionIdentity, SelfPasswordChangeService};

#[derive(Clone)]
struct StateData {
    identity: Arc<dyn SelfSecurityBrowserIdentityService>,
    service: Arc<dyn SelfPasswordChangeService>,
    config: BrowserSessionHttpConfig,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Expected {
    tenant_id: String,
    account_id: String,
    session_id: String,
    client_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChangeBody {
    current_password: String,
    new_password: String,
    operation_id: String,
    receipt_secret: String,
    expected: Expected,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResultBody {
    operation_id: String,
    receipt_secret: String,
}

pub fn browser_self_password_change_router(
    identity: Arc<dyn SelfSecurityBrowserIdentityService>,
    service: Arc<dyn SelfPasswordChangeService>,
    config: BrowserSessionHttpConfig,
) -> Result<Router, &'static str> {
    if identity.self_security_browser_purpose() != config.purpose
        || identity.self_security_browser_lifetime_secs() != config.development_ttl_secs
    {
        return Err("self security browser configuration mismatch");
    }
    let root = route_root(config.purpose);
    let state = StateData {
        identity,
        service,
        config,
    };
    Ok(Router::new()
        .route(&format!("{root}/security/password"), post(change))
        .route(&format!("{root}/security/password/result"), post(result))
        .with_state(state.clone())
        .layer(DefaultBodyLimit::max(AUTH_DEVICE_BODY_LIMIT_BYTES))
        .route_layer(middleware::from_fn_with_state(state, guard))
        .layer(middleware::from_fn(no_store)))
}

async fn guard(State(state): State<StateData>, request: Request, next: Next) -> Response {
    if !browser_headers_valid(request.headers(), &state.config) {
        return tenant_error(
            StatusCode::FORBIDDEN,
            "browser_origin_rejected",
            "browser request rejected",
        );
    }
    next.run(request).await
}

async fn change(
    State(state): State<StateData>,
    headers: HeaderMap,
    body: Result<Json<ChangeBody>, JsonRejection>,
) -> Response {
    let Json(body) = match body {
        Ok(body) => body,
        Err(error) => return json_rejection(error),
    };
    if headers.contains_key("x-embedded-idp-business-id") {
        return invalid_request();
    }
    let cookie = match credential(&headers, &state.config.cookie_name) {
        Ok(Some(cookie)) => cookie,
        Ok(None) | Err(_) => return auth_error(),
    };
    let Some(operation_id) = parse_operation_id(&body.operation_id) else {
        return invalid_request();
    };
    let expected = BrowserSessionIdentity {
        tenant_id: body.expected.tenant_id,
        account_id: body.expected.account_id,
        session_id: body.expected.session_id,
        client_id: body.expected.client_id,
    };
    let actor = call(move || {
        state
            .identity
            .authenticate_self_security_browser(cookie, expected)
    })
    .await;
    let actor = match actor {
        Ok(actor) => actor,
        Err(error) => return revocation_auth_error(error),
    };
    let command = SelfPasswordChangeCommand {
        current_password: SecretString::new(body.current_password),
        new_password: SecretString::new(body.new_password),
        operation_id,
        receipt_secret: SecretString::new(body.receipt_secret),
    };
    match call(move || state.service.change_password(actor, command)).await {
        Ok(()) => completed(true),
        Err(error) => change_error(error),
    }
}

async fn result(
    State(state): State<StateData>,
    headers: HeaderMap,
    body: Result<Json<ResultBody>, JsonRejection>,
) -> Response {
    if headers.contains_key("x-embedded-idp-business-id") {
        return invalid_request();
    }
    let Json(body) = match body {
        Ok(body) => body,
        Err(error) => return json_rejection(error),
    };
    let Some(operation_id) = parse_operation_id(&body.operation_id) else {
        return invalid_request();
    };
    let query = SecurityReceiptQuery {
        operation_id,
        receipt_secret: SecretString::new(body.receipt_secret),
    };
    match call(move || state.service.password_change_result(query)).await {
        Ok(value) => completed(value),
        Err(error) => change_error(error),
    }
}

#[cfg(test)]
#[path = "self_password_change_tests.rs"]
mod tests;
