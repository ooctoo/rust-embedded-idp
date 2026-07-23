pub const OIDC_API_PREFIX: &str = "/oidc";
pub const OIDC_DISCOVERY_PATH: &str = "/.well-known/openid-configuration";
pub const OIDC_AUTHORIZE_PATH: &str = "/oidc/authorize";
pub const OIDC_TOKEN_PATH: &str = "/oidc/token";
pub const OIDC_JWKS_PATH: &str = "/oidc/jwks.json";
pub const OIDC_REVOKE_PATH: &str = "/oidc/revoke";
pub const OIDC_USERINFO_PATH: &str = "/oidc/userinfo";
pub const OIDC_INTROSPECT_PATH: &str = "/oidc/introspect";

#[cfg(test)]
mod tests {
    use super::{
        OIDC_API_PREFIX, OIDC_AUTHORIZE_PATH, OIDC_DISCOVERY_PATH, OIDC_INTROSPECT_PATH,
        OIDC_JWKS_PATH, OIDC_REVOKE_PATH, OIDC_TOKEN_PATH, OIDC_USERINFO_PATH,
    };

    #[test]
    fn exported_paths_match_module_contract() {
        assert_eq!(OIDC_API_PREFIX, "/oidc");
        assert_eq!(OIDC_DISCOVERY_PATH, "/.well-known/openid-configuration");
        assert_eq!(OIDC_AUTHORIZE_PATH, "/oidc/authorize");
        assert_eq!(OIDC_TOKEN_PATH, "/oidc/token");
        assert_eq!(OIDC_JWKS_PATH, "/oidc/jwks.json");
        assert_eq!(OIDC_REVOKE_PATH, "/oidc/revoke");
        assert_eq!(OIDC_USERINFO_PATH, "/oidc/userinfo");
        assert_eq!(OIDC_INTROSPECT_PATH, "/oidc/introspect");
    }
}
