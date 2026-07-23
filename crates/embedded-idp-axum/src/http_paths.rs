use embedded_idp_core::{OIDC_API_PREFIX, OIDC_DISCOVERY_PATH};

pub const AUTH_API_PREFIX: &str = "/auth";
pub const AUTH_REGISTER_PATH: &str = "/auth/register";
pub const AUTH_VERIFY_EMAIL_PATH: &str = "/auth/verify-email";
pub const AUTH_RESEND_VERIFICATION_PATH: &str = "/auth/resend-verification";
pub const AUTH_LOGIN_PATH: &str = "/auth/login";
pub const AUTH_REFRESH_PATH: &str = "/auth/refresh";
pub const AUTH_LOGOUT_PATH: &str = "/auth/logout";

pub const DEVICE_API_PREFIX: &str = "/devices";
pub const DEVICE_PROVISION_PATH: &str = "/devices/provision";
pub const DEVICE_COMPLETE_PATH: &str = "/devices/complete";
pub const DEVICE_BIND_PATH: &str = "/devices/bind";
pub const DEVICE_DETAIL_PATH_TEMPLATE: &str = "/devices/:device_id";
pub const DEVICE_UNBIND_PATH: &str = "/devices/unbind";
pub const DEVICE_DISABLE_PATH: &str = "/devices/disable";
pub const DEVICE_REVOKE_PATH: &str = "/devices/revoke";
pub const DEVICE_HEARTBEAT_PATH: &str = "/devices/heartbeat";

pub const ADMIN_API_PREFIX: &str = "/admin";
pub const ADMIN_ACCOUNTS_PATH: &str = "/admin/accounts";
pub const ADMIN_ACCOUNT_DETAIL_PATH_TEMPLATE: &str = "/admin/accounts/:account_id";
pub const ADMIN_ACCOUNT_ACTIVATE_PATH: &str = "/admin/accounts/activate";
pub const ADMIN_ACCOUNT_DISABLE_PATH: &str = "/admin/accounts/disable";
pub const ADMIN_ACCOUNT_SET_PASSWORD_PATH: &str = "/admin/accounts/set-password";
pub const ADMIN_ACCOUNT_REVOKE_SESSIONS_PATH: &str = "/admin/accounts/revoke-sessions";
pub const ADMIN_SESSIONS_PATH: &str = "/admin/sessions";
pub const ADMIN_SESSION_DETAIL_PATH_TEMPLATE: &str = "/admin/sessions/:session_id";
pub const ADMIN_SESSION_REVOKE_PATH: &str = "/admin/sessions/revoke";
pub const ADMIN_CLIENTS_PATH: &str = "/admin/clients";
pub const ADMIN_CLIENT_DETAIL_PATH_TEMPLATE: &str = "/admin/clients/:client_id";
pub const ADMIN_CLIENT_UPSERT_PATH: &str = "/admin/clients/upsert";
pub const ADMIN_DEVICES_PATH: &str = "/admin/devices";
pub const ADMIN_DEVICE_DETAIL_PATH_TEMPLATE: &str = "/admin/devices/:device_id";
pub const ADMIN_DEVICE_UNBIND_PATH: &str = "/admin/devices/unbind";
pub const ADMIN_DEVICE_DISABLE_PATH: &str = "/admin/devices/disable";
pub const ADMIN_DEVICE_REVOKE_PATH: &str = "/admin/devices/revoke";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteMountPlan {
    pub external_base_path: String,
    pub auth_prefix: &'static str,
    pub device_prefix: &'static str,
    pub admin_prefix: &'static str,
    pub oidc_prefix: &'static str,
    pub discovery_path: &'static str,
}

impl RouteMountPlan {
    pub fn new(external_base_path: impl Into<String>) -> Self {
        Self {
            external_base_path: normalize_external_base_path(external_base_path.into()),
            auth_prefix: AUTH_API_PREFIX,
            device_prefix: DEVICE_API_PREFIX,
            admin_prefix: ADMIN_API_PREFIX,
            oidc_prefix: OIDC_API_PREFIX,
            discovery_path: OIDC_DISCOVERY_PATH,
        }
    }

    pub fn default_mounts() -> Self {
        Self::new("")
    }

    pub fn external_auth_prefix(&self) -> String {
        self.external_path(self.auth_prefix)
    }

    pub fn external_auth_register_path(&self) -> String {
        self.external_path(AUTH_REGISTER_PATH)
    }

    pub fn external_auth_login_path(&self) -> String {
        self.external_path(AUTH_LOGIN_PATH)
    }

    pub fn external_auth_verify_email_path(&self) -> String {
        self.external_path(AUTH_VERIFY_EMAIL_PATH)
    }

    pub fn external_auth_resend_verification_path(&self) -> String {
        self.external_path(AUTH_RESEND_VERIFICATION_PATH)
    }

    pub fn external_oidc_authorize_path(&self) -> String {
        self.external_path("/oidc/authorize")
    }

    pub fn external_oidc_token_path(&self) -> String {
        self.external_path("/oidc/token")
    }

    pub fn external_oidc_jwks_path(&self) -> String {
        self.external_path("/oidc/jwks.json")
    }

    pub fn external_oidc_revoke_path(&self) -> String {
        self.external_path("/oidc/revoke")
    }

    pub fn external_oidc_userinfo_path(&self) -> String {
        self.external_path("/oidc/userinfo")
    }

    pub fn external_oidc_introspect_path(&self) -> String {
        self.external_path("/oidc/introspect")
    }

    pub fn external_discovery_path(&self) -> String {
        self.external_path(self.discovery_path)
    }

    pub fn external_device_provision_path(&self) -> String {
        self.external_path(DEVICE_PROVISION_PATH)
    }

    pub fn external_device_complete_path(&self) -> String {
        self.external_path(DEVICE_COMPLETE_PATH)
    }

    pub fn external_device_bind_path(&self) -> String {
        self.external_path(DEVICE_BIND_PATH)
    }

    pub fn external_devices_path(&self) -> String {
        self.external_path(self.device_prefix)
    }

    pub fn external_device_detail_path_template(&self) -> String {
        self.external_path(DEVICE_DETAIL_PATH_TEMPLATE)
    }

    pub fn external_device_unbind_path(&self) -> String {
        self.external_path(DEVICE_UNBIND_PATH)
    }

    pub fn external_device_disable_path(&self) -> String {
        self.external_path(DEVICE_DISABLE_PATH)
    }

    pub fn external_device_revoke_path(&self) -> String {
        self.external_path(DEVICE_REVOKE_PATH)
    }

    pub fn external_device_heartbeat_path(&self) -> String {
        self.external_path(DEVICE_HEARTBEAT_PATH)
    }

    fn external_path(&self, relative_path: &str) -> String {
        format!("{}{}", self.external_base_path, relative_path)
    }
}

fn normalize_external_base_path(base_path: String) -> String {
    let trimmed = base_path.trim();
    if trimmed.is_empty() || trimmed == "/" {
        return String::new();
    }

    let without_trailing = trimmed.trim_end_matches('/');
    if without_trailing.starts_with('/') {
        without_trailing.to_string()
    } else {
        format!("/{without_trailing}")
    }
}

#[cfg(test)]
mod tests {
    use super::RouteMountPlan;

    #[test]
    fn default_mounts_keep_root_relative_external_paths() {
        let plan = RouteMountPlan::default_mounts();

        assert_eq!(plan.external_base_path, "");
        assert_eq!(plan.external_auth_prefix(), "/auth");
        assert_eq!(plan.external_oidc_authorize_path(), "/oidc/authorize");
        assert_eq!(
            plan.external_discovery_path(),
            "/.well-known/openid-configuration"
        );
    }

    #[test]
    fn external_base_path_is_normalized_and_applied() {
        let plan = RouteMountPlan::new("api/v1/");

        assert_eq!(plan.external_base_path, "/api/v1");
        assert_eq!(plan.external_auth_prefix(), "/api/v1/auth");
        assert_eq!(plan.external_oidc_token_path(), "/api/v1/oidc/token");
        assert_eq!(
            plan.external_discovery_path(),
            "/api/v1/.well-known/openid-configuration"
        );
    }
}
