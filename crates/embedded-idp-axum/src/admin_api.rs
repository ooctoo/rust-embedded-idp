use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use embedded_idp_core::{
    Account, AccountStatus, ActivateAccountCommand, AuthSession, CreateAccountCommand,
    DeviceStatus, DisableAccountCommand, DisableDeviceCommand, GetAccountCommand, GetClientCommand,
    GetDeviceCommand, GetSessionCommand, ListAccountsCommand, ListClientsCommand,
    ListDevicesCommand, ListSessionsCommand, OidcClientType, PageRequest,
    RevokeAccountSessionsCommand, RevokeDeviceCommand, RevokeSessionCommand, SessionStatus,
    SetAccountPasswordCommand, UnbindDeviceFromAccountCommand, UpsertClientCommand,
};

use crate::admin_dto::{
    AccountHttpResponse, AccountListHttpResponse, AccountManagementHttpRequest,
    AccountsQueryHttpRequest, AdminDeviceListHttpResponse, ClientHttpResponse,
    ClientListHttpResponse, ClientsQueryHttpRequest, CreateAccountHttpRequest,
    DevicesAdminQueryHttpRequest, PageHttpResponse, RevokeAccountSessionsHttpRequest,
    SessionHttpResponse, SessionListHttpResponse, SessionManagementHttpRequest,
    SessionsQueryHttpRequest, SetAccountPasswordHttpRequest, UnbindAnyDeviceHttpRequest,
    UpsertClientHttpRequest,
};
use crate::admin_paging::{
    account_next_cursor, device_next_cursor, page_response, parse_cursor, session_next_cursor,
};
use crate::dto::{DeviceDetailHttpResponse, DeviceManagementHttpRequest, ErrorHttpResponse};
use crate::http_paths::{
    ADMIN_ACCOUNTS_PATH, ADMIN_ACCOUNT_ACTIVATE_PATH, ADMIN_ACCOUNT_DETAIL_PATH_TEMPLATE,
    ADMIN_ACCOUNT_DISABLE_PATH, ADMIN_ACCOUNT_REVOKE_SESSIONS_PATH,
    ADMIN_ACCOUNT_SET_PASSWORD_PATH, ADMIN_CLIENTS_PATH, ADMIN_CLIENT_DETAIL_PATH_TEMPLATE,
    ADMIN_CLIENT_UPSERT_PATH, ADMIN_DEVICES_PATH, ADMIN_DEVICE_DETAIL_PATH_TEMPLATE,
    ADMIN_DEVICE_DISABLE_PATH, ADMIN_DEVICE_REVOKE_PATH, ADMIN_DEVICE_UNBIND_PATH,
    ADMIN_SESSIONS_PATH, ADMIN_SESSION_DETAIL_PATH_TEMPLATE, ADMIN_SESSION_REVOKE_PATH,
};
use crate::http_support::{map_service_error, run_service_call, unix_time};
use crate::{binding_response, device_response, EmbeddedIdpHttpState};

pub(crate) fn routes() -> Router<EmbeddedIdpHttpState> {
    Router::new()
        .route(ADMIN_ACCOUNTS_PATH, get(list_accounts).post(create_account))
        .route(ADMIN_ACCOUNT_DETAIL_PATH_TEMPLATE, get(get_account))
        .route(ADMIN_ACCOUNT_ACTIVATE_PATH, post(activate_account))
        .route(ADMIN_ACCOUNT_DISABLE_PATH, post(disable_account))
        .route(ADMIN_ACCOUNT_SET_PASSWORD_PATH, post(set_account_password))
        .route(
            ADMIN_ACCOUNT_REVOKE_SESSIONS_PATH,
            post(revoke_account_sessions),
        )
        .route(ADMIN_SESSIONS_PATH, get(list_sessions))
        .route(ADMIN_SESSION_DETAIL_PATH_TEMPLATE, get(get_session))
        .route(ADMIN_SESSION_REVOKE_PATH, post(revoke_session))
        .route(ADMIN_CLIENTS_PATH, get(list_clients))
        .route(ADMIN_CLIENT_DETAIL_PATH_TEMPLATE, get(get_client))
        .route(ADMIN_CLIENT_UPSERT_PATH, post(upsert_client))
        .route(ADMIN_DEVICES_PATH, get(list_devices))
        .route(ADMIN_DEVICE_DETAIL_PATH_TEMPLATE, get(get_device))
        .route(ADMIN_DEVICE_UNBIND_PATH, post(unbind_device))
        .route(ADMIN_DEVICE_DISABLE_PATH, post(disable_device))
        .route(ADMIN_DEVICE_REVOKE_PATH, post(revoke_device))
}

async fn create_account(
    State(state): State<EmbeddedIdpHttpState>,
    Json(request): Json<CreateAccountHttpRequest>,
) -> Response {
    let admin_service = state.admin_service.clone();
    match run_service_call(move || {
        admin_service.create_account(CreateAccountCommand {
            email: request.email,
            password: request.password,
            display_name: request.display_name,
        })
    })
    .await
    {
        Ok(result) => (StatusCode::CREATED, Json(account_response(result.account))).into_response(),
        Err(error) => map_service_error(error),
    }
}

async fn list_accounts(
    State(state): State<EmbeddedIdpHttpState>,
    Query(request): Query<AccountsQueryHttpRequest>,
) -> Response {
    let status = match request
        .status
        .as_deref()
        .map(parse_account_status)
        .transpose()
    {
        Ok(status) => status,
        Err(response) => return response,
    };
    let cursor = match request.cursor.as_deref().map(parse_cursor).transpose() {
        Ok(cursor) => cursor,
        Err(response) => return response,
    };

    let admin_service = state.admin_service.clone();
    match run_service_call(move || {
        admin_service.list_accounts(ListAccountsCommand {
            status,
            email: request.email,
            created_after: request.created_after_unix_secs.map(unix_time),
            created_before: request.created_before_unix_secs.map(unix_time),
            cursor,
            page: page_request(request.limit, request.offset),
        })
    })
    .await
    {
        Ok(result) => {
            let next_cursor = account_next_cursor(&result.accounts, &result.page);
            (
                StatusCode::OK,
                Json(AccountListHttpResponse {
                    accounts: result.accounts.into_iter().map(account_response).collect(),
                    page: page_response(result.page, next_cursor),
                }),
            )
                .into_response()
        }
        Err(error) => map_service_error(error),
    }
}

async fn get_account(
    State(state): State<EmbeddedIdpHttpState>,
    Path(account_id): Path<String>,
) -> Response {
    let admin_service = state.admin_service.clone();
    match run_service_call(move || admin_service.get_account(GetAccountCommand { account_id }))
        .await
    {
        Ok(result) => (StatusCode::OK, Json(account_response(result.account))).into_response(),
        Err(error) => map_service_error(error),
    }
}

async fn activate_account(
    State(state): State<EmbeddedIdpHttpState>,
    Json(request): Json<AccountManagementHttpRequest>,
) -> Response {
    let admin_service = state.admin_service.clone();
    match run_service_call(move || {
        admin_service.activate_account(ActivateAccountCommand {
            account_id: request.account_id,
        })
    })
    .await
    {
        Ok(result) => (StatusCode::OK, Json(account_response(result.account))).into_response(),
        Err(error) => map_service_error(error),
    }
}

async fn disable_account(
    State(state): State<EmbeddedIdpHttpState>,
    Json(request): Json<AccountManagementHttpRequest>,
) -> Response {
    let admin_service = state.admin_service.clone();
    match run_service_call(move || {
        admin_service.disable_account(DisableAccountCommand {
            account_id: request.account_id,
        })
    })
    .await
    {
        Ok(result) => (StatusCode::OK, Json(account_response(result.account))).into_response(),
        Err(error) => map_service_error(error),
    }
}

async fn set_account_password(
    State(state): State<EmbeddedIdpHttpState>,
    Json(request): Json<SetAccountPasswordHttpRequest>,
) -> Response {
    let admin_service = state.admin_service.clone();
    match run_service_call(move || {
        admin_service.set_account_password(SetAccountPasswordCommand {
            account_id: request.account_id,
            new_password: request.new_password,
        })
    })
    .await
    {
        Ok(result) => (StatusCode::OK, Json(account_response(result.account))).into_response(),
        Err(error) => map_service_error(error),
    }
}

async fn revoke_account_sessions(
    State(state): State<EmbeddedIdpHttpState>,
    Json(request): Json<RevokeAccountSessionsHttpRequest>,
) -> Response {
    let admin_service = state.admin_service.clone();
    let revoked_at = state.clock.now();
    match run_service_call(move || {
        admin_service.revoke_account_sessions(RevokeAccountSessionsCommand {
            account_id: request.account_id,
            revoked_at,
        })
    })
    .await
    {
        Ok(result) => {
            let returned = result.sessions.len() as u32;
            (
                StatusCode::OK,
                Json(SessionListHttpResponse {
                    sessions: result.sessions.into_iter().map(session_response).collect(),
                    page: PageHttpResponse {
                        limit: returned,
                        offset: 0,
                        returned,
                        total: u64::from(returned),
                        has_more: false,
                        next_cursor: None,
                    },
                }),
            )
                .into_response()
        }
        Err(error) => map_service_error(error),
    }
}

async fn list_sessions(
    State(state): State<EmbeddedIdpHttpState>,
    Query(request): Query<SessionsQueryHttpRequest>,
) -> Response {
    let status = match request
        .status
        .as_deref()
        .map(parse_session_status)
        .transpose()
    {
        Ok(status) => status,
        Err(response) => return response,
    };
    let cursor = match request.cursor.as_deref().map(parse_cursor).transpose() {
        Ok(cursor) => cursor,
        Err(response) => return response,
    };

    let admin_service = state.admin_service.clone();
    match run_service_call(move || {
        admin_service.list_sessions(ListSessionsCommand {
            account_id: request.account_id,
            status,
            client_id: request.client_id,
            device_id: request.device_id,
            created_after: request.created_after_unix_secs.map(unix_time),
            created_before: request.created_before_unix_secs.map(unix_time),
            cursor,
            page: page_request(request.limit, request.offset),
        })
    })
    .await
    {
        Ok(result) => {
            let next_cursor = session_next_cursor(&result.sessions, &result.page);
            (
                StatusCode::OK,
                Json(SessionListHttpResponse {
                    sessions: result.sessions.into_iter().map(session_response).collect(),
                    page: page_response(result.page, next_cursor),
                }),
            )
                .into_response()
        }
        Err(error) => map_service_error(error),
    }
}

async fn get_session(
    State(state): State<EmbeddedIdpHttpState>,
    Path(session_id): Path<String>,
) -> Response {
    let admin_service = state.admin_service.clone();
    match run_service_call(move || admin_service.get_session(GetSessionCommand { session_id }))
        .await
    {
        Ok(result) => (StatusCode::OK, Json(session_response(result.session))).into_response(),
        Err(error) => map_service_error(error),
    }
}

async fn revoke_session(
    State(state): State<EmbeddedIdpHttpState>,
    Json(request): Json<SessionManagementHttpRequest>,
) -> Response {
    let admin_service = state.admin_service.clone();
    let revoked_at = state.clock.now();
    match run_service_call(move || {
        admin_service.revoke_session(RevokeSessionCommand {
            session_id: request.session_id,
            revoked_at,
        })
    })
    .await
    {
        Ok(result) => (StatusCode::OK, Json(session_response(result.session))).into_response(),
        Err(error) => map_service_error(error),
    }
}

async fn list_clients(
    State(state): State<EmbeddedIdpHttpState>,
    Query(request): Query<ClientsQueryHttpRequest>,
) -> Response {
    let client_type = match request
        .client_type
        .as_deref()
        .map(parse_client_type)
        .transpose()
    {
        Ok(client_type) => client_type,
        Err(response) => return response,
    };

    let admin_service = state.admin_service.clone();
    match run_service_call(move || {
        admin_service.list_clients(ListClientsCommand {
            client_type,
            pkce_required: request.pkce_required,
            page: page_request(request.limit, request.offset),
        })
    })
    .await
    {
        Ok(result) => (
            StatusCode::OK,
            Json(ClientListHttpResponse {
                clients: result.clients.into_iter().map(client_response).collect(),
                page: page_response(result.page, None),
            }),
        )
            .into_response(),
        Err(error) => map_service_error(error),
    }
}

async fn get_client(
    State(state): State<EmbeddedIdpHttpState>,
    Path(client_id): Path<String>,
) -> Response {
    let admin_service = state.admin_service.clone();
    match run_service_call(move || admin_service.get_client(GetClientCommand { client_id })).await {
        Ok(result) => (StatusCode::OK, Json(client_response(result.client))).into_response(),
        Err(error) => map_service_error(error),
    }
}

async fn upsert_client(
    State(state): State<EmbeddedIdpHttpState>,
    Json(request): Json<UpsertClientHttpRequest>,
) -> Response {
    let client_type = match parse_client_type(&request.client_type) {
        Ok(client_type) => client_type,
        Err(response) => return response,
    };

    let admin_service = state.admin_service.clone();
    match run_service_call(move || {
        admin_service.upsert_client(UpsertClientCommand {
            client_id: request.client_id,
            client_name: request.client_name,
            redirect_uris: request.redirect_uris,
            client_type,
            pkce_required: request.pkce_required,
            client_secret: request.client_secret,
        })
    })
    .await
    {
        Ok(result) => (StatusCode::OK, Json(client_response(result.client))).into_response(),
        Err(error) => map_service_error(error),
    }
}

async fn list_devices(
    State(state): State<EmbeddedIdpHttpState>,
    Query(request): Query<DevicesAdminQueryHttpRequest>,
) -> Response {
    let status = match request
        .status
        .as_deref()
        .map(parse_device_status)
        .transpose()
    {
        Ok(status) => status,
        Err(response) => return response,
    };
    let cursor = match request.cursor.as_deref().map(parse_cursor).transpose() {
        Ok(cursor) => cursor,
        Err(response) => return response,
    };

    let device_service = state.device_service.clone();
    match run_service_call(move || {
        device_service.list_devices(ListDevicesCommand {
            account_id: request.account_id,
            client_id: request.client_id,
            status,
            registered_after: request.registered_after_unix_secs.map(unix_time),
            registered_before: request.registered_before_unix_secs.map(unix_time),
            cursor,
            page: page_request(request.limit, request.offset),
        })
    })
    .await
    {
        Ok(result) => {
            let next_cursor = device_next_cursor(&result.devices, &result.page);
            (
                StatusCode::OK,
                Json(AdminDeviceListHttpResponse {
                    devices: result.devices.into_iter().map(device_response).collect(),
                    page: page_response(result.page, next_cursor),
                }),
            )
                .into_response()
        }
        Err(error) => map_service_error(error),
    }
}

async fn get_device(
    State(state): State<EmbeddedIdpHttpState>,
    Path(device_id): Path<String>,
) -> Response {
    let device_service = state.device_service.clone();
    match run_service_call(move || device_service.get_device(GetDeviceCommand { device_id })).await
    {
        Ok(result) => (
            StatusCode::OK,
            Json(DeviceDetailHttpResponse {
                device: device_response(result.device),
                bindings: result.bindings.into_iter().map(binding_response).collect(),
            }),
        )
            .into_response(),
        Err(error) => map_service_error(error),
    }
}

async fn unbind_device(
    State(state): State<EmbeddedIdpHttpState>,
    Json(request): Json<UnbindAnyDeviceHttpRequest>,
) -> Response {
    let device_service = state.device_service.clone();
    let unbound_at = state.clock.now();
    match run_service_call(move || {
        device_service.unbind_device_from_account(UnbindDeviceFromAccountCommand {
            account_id: request.account_id,
            device_id: request.device_id,
            unbound_at,
        })
    })
    .await
    {
        Ok(result) => (StatusCode::OK, Json(binding_response(result.binding))).into_response(),
        Err(error) => map_service_error(error),
    }
}

async fn disable_device(
    State(state): State<EmbeddedIdpHttpState>,
    Json(request): Json<DeviceManagementHttpRequest>,
) -> Response {
    let device_service = state.device_service.clone();
    match run_service_call(move || {
        device_service.disable_device(DisableDeviceCommand {
            device_id: request.device_id,
        })
    })
    .await
    {
        Ok(result) => (StatusCode::OK, Json(device_response(result.device))).into_response(),
        Err(error) => map_service_error(error),
    }
}

async fn revoke_device(
    State(state): State<EmbeddedIdpHttpState>,
    Json(request): Json<DeviceManagementHttpRequest>,
) -> Response {
    let device_service = state.device_service.clone();
    match run_service_call(move || {
        device_service.revoke_device(RevokeDeviceCommand {
            device_id: request.device_id,
        })
    })
    .await
    {
        Ok(result) => (StatusCode::OK, Json(device_response(result.device))).into_response(),
        Err(error) => map_service_error(error),
    }
}

fn account_response(account: Account) -> AccountHttpResponse {
    AccountHttpResponse {
        account_id: account.id,
        email: account.email,
        display_name: account.display_name,
        status: account_status(&account.status),
        created_at_unix_secs: account
            .created_at
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .map(|value| value.as_secs())
            .unwrap_or_default(),
    }
}

fn session_response(session: AuthSession) -> SessionHttpResponse {
    SessionHttpResponse {
        session_id: session.id,
        account_id: session.account_id,
        client_id: session.client_id,
        device_id: session.device_id,
        status: session_status(&session.status),
        created_at_unix_secs: session
            .created_at
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .map(|value| value.as_secs())
            .unwrap_or_default(),
        expires_at_unix_secs: session
            .expires_at
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .map(|value| value.as_secs())
            .unwrap_or_default(),
        refresh_token_version: session.refresh_token_version,
    }
}

fn client_response(client: embedded_idp_core::AdminClientRecord) -> ClientHttpResponse {
    ClientHttpResponse {
        client_id: client.client_id,
        client_name: client.client_name,
        redirect_uris: client.redirect_uris,
        client_type: client_type(&client.client_type),
        pkce_required: client.pkce_required,
        client_secret_configured: client.client_secret_configured,
    }
}

fn account_status(status: &AccountStatus) -> &'static str {
    match status {
        AccountStatus::PendingVerification => "pending_verification",
        AccountStatus::Active => "active",
        AccountStatus::Disabled => "disabled",
    }
}

fn session_status(status: &embedded_idp_core::SessionStatus) -> &'static str {
    match status {
        embedded_idp_core::SessionStatus::Pending => "pending",
        embedded_idp_core::SessionStatus::Active => "active",
        embedded_idp_core::SessionStatus::Revoked => "revoked",
        embedded_idp_core::SessionStatus::Expired => "expired",
    }
}

fn client_type(client_type: &OidcClientType) -> &'static str {
    match client_type {
        OidcClientType::PublicDesktop => "public_desktop",
        OidcClientType::ConfidentialWeb => "confidential_web",
    }
}

fn parse_client_type(value: &str) -> Result<OidcClientType, Response> {
    match value {
        "public_desktop" => Ok(OidcClientType::PublicDesktop),
        "confidential_web" => Ok(OidcClientType::ConfidentialWeb),
        _ => Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorHttpResponse {
                code: "invalid_contract",
                message: format!("unsupported client_type: {value}"),
            }),
        )
            .into_response()),
    }
}

fn parse_account_status(value: &str) -> Result<AccountStatus, Response> {
    match value {
        "pending_verification" => Ok(AccountStatus::PendingVerification),
        "active" => Ok(AccountStatus::Active),
        "disabled" => Ok(AccountStatus::Disabled),
        _ => Err(invalid_query_value_response("status", value)),
    }
}

fn parse_session_status(value: &str) -> Result<SessionStatus, Response> {
    match value {
        "pending" => Ok(SessionStatus::Pending),
        "active" => Ok(SessionStatus::Active),
        "revoked" => Ok(SessionStatus::Revoked),
        "expired" => Ok(SessionStatus::Expired),
        _ => Err(invalid_query_value_response("status", value)),
    }
}

fn parse_device_status(value: &str) -> Result<DeviceStatus, Response> {
    match value {
        "pending" => Ok(DeviceStatus::Pending),
        "active" => Ok(DeviceStatus::Active),
        "disabled" => Ok(DeviceStatus::Disabled),
        "revoked" => Ok(DeviceStatus::Revoked),
        _ => Err(invalid_query_value_response("status", value)),
    }
}

fn invalid_query_value_response(field: &str, value: &str) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(ErrorHttpResponse {
            code: "invalid_contract",
            message: format!("unsupported {field}: {value}"),
        }),
    )
        .into_response()
}

fn page_request(limit: Option<u32>, offset: Option<u64>) -> PageRequest {
    let mut page = PageRequest::default();
    if let Some(limit) = limit {
        page.limit = limit;
    }
    if let Some(offset) = offset {
        page.offset = offset;
    }
    page
}
