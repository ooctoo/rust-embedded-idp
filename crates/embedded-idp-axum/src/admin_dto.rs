use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub(crate) struct AccountManagementHttpRequest {
    pub(crate) account_id: String,
}

#[derive(Deserialize)]
pub(crate) struct CreateAccountHttpRequest {
    pub(crate) email: String,
    pub(crate) password: String,
    pub(crate) display_name: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct AccountsQueryHttpRequest {
    pub(crate) status: Option<String>,
    pub(crate) email: Option<String>,
    pub(crate) created_after_unix_secs: Option<u64>,
    pub(crate) created_before_unix_secs: Option<u64>,
    pub(crate) cursor: Option<String>,
    pub(crate) limit: Option<u32>,
    pub(crate) offset: Option<u64>,
}

#[derive(Deserialize)]
pub(crate) struct SetAccountPasswordHttpRequest {
    pub(crate) account_id: String,
    pub(crate) new_password: String,
}

#[derive(Deserialize)]
pub(crate) struct RevokeAccountSessionsHttpRequest {
    pub(crate) account_id: String,
    pub(crate) revoked_at_unix_secs: u64,
}

#[derive(Deserialize)]
pub(crate) struct SessionsQueryHttpRequest {
    pub(crate) account_id: Option<String>,
    pub(crate) status: Option<String>,
    pub(crate) client_id: Option<String>,
    pub(crate) device_id: Option<String>,
    pub(crate) created_after_unix_secs: Option<u64>,
    pub(crate) created_before_unix_secs: Option<u64>,
    pub(crate) cursor: Option<String>,
    pub(crate) limit: Option<u32>,
    pub(crate) offset: Option<u64>,
}

#[derive(Deserialize)]
pub(crate) struct ClientsQueryHttpRequest {
    pub(crate) client_type: Option<String>,
    pub(crate) pkce_required: Option<bool>,
    pub(crate) limit: Option<u32>,
    pub(crate) offset: Option<u64>,
}

#[derive(Deserialize)]
pub(crate) struct DevicesAdminQueryHttpRequest {
    pub(crate) account_id: Option<String>,
    pub(crate) client_id: Option<String>,
    pub(crate) status: Option<String>,
    pub(crate) registered_after_unix_secs: Option<u64>,
    pub(crate) registered_before_unix_secs: Option<u64>,
    pub(crate) cursor: Option<String>,
    pub(crate) limit: Option<u32>,
    pub(crate) offset: Option<u64>,
}

#[derive(Deserialize)]
pub(crate) struct SessionManagementHttpRequest {
    pub(crate) session_id: String,
    pub(crate) revoked_at_unix_secs: u64,
}

#[derive(Deserialize)]
pub(crate) struct UpsertClientHttpRequest {
    pub(crate) client_id: String,
    pub(crate) client_name: String,
    pub(crate) redirect_uris: Vec<String>,
    pub(crate) client_type: String,
    pub(crate) pkce_required: bool,
    pub(crate) client_secret: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct UnbindAnyDeviceHttpRequest {
    pub(crate) account_id: String,
    pub(crate) device_id: String,
    pub(crate) unbound_at_unix_secs: u64,
}

#[derive(Serialize)]
pub(crate) struct AccountHttpResponse {
    pub(crate) account_id: String,
    pub(crate) email: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) display_name: Option<String>,
    pub(crate) status: &'static str,
    pub(crate) created_at_unix_secs: u64,
}

#[derive(Serialize)]
pub(crate) struct AccountListHttpResponse {
    pub(crate) accounts: Vec<AccountHttpResponse>,
    pub(crate) page: PageHttpResponse,
}

#[derive(Serialize)]
pub(crate) struct SessionHttpResponse {
    pub(crate) session_id: String,
    pub(crate) account_id: String,
    pub(crate) client_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) device_id: Option<String>,
    pub(crate) status: &'static str,
    pub(crate) created_at_unix_secs: u64,
    pub(crate) expires_at_unix_secs: u64,
    pub(crate) refresh_token_version: u64,
}

#[derive(Serialize)]
pub(crate) struct SessionListHttpResponse {
    pub(crate) sessions: Vec<SessionHttpResponse>,
    pub(crate) page: PageHttpResponse,
}

#[derive(Serialize)]
pub(crate) struct ClientHttpResponse {
    pub(crate) client_id: String,
    pub(crate) client_name: String,
    pub(crate) redirect_uris: Vec<String>,
    pub(crate) client_type: &'static str,
    pub(crate) pkce_required: bool,
    pub(crate) client_secret_configured: bool,
}

#[derive(Serialize)]
pub(crate) struct ClientListHttpResponse {
    pub(crate) clients: Vec<ClientHttpResponse>,
    pub(crate) page: PageHttpResponse,
}

#[derive(Serialize)]
pub(crate) struct AdminDeviceListHttpResponse {
    pub(crate) devices: Vec<crate::dto::DeviceHttpResponse>,
    pub(crate) page: PageHttpResponse,
}

#[derive(Serialize)]
pub(crate) struct PageHttpResponse {
    pub(crate) limit: u32,
    pub(crate) offset: u64,
    pub(crate) returned: u32,
    pub(crate) total: u64,
    pub(crate) has_more: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) next_cursor: Option<String>,
}
