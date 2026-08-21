use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub(crate) struct RegisterAccountHttpRequest {
    pub(crate) email: String,
    pub(crate) password: String,
    pub(crate) display_name: Option<String>,
    pub(crate) client_id: String,
    pub(crate) device_id: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct VerifyEmailHttpRequest {
    pub(crate) email: String,
    pub(crate) verification_code: String,
    pub(crate) client_id: String,
    pub(crate) device_id: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct ResendVerificationCodeHttpRequest {
    pub(crate) email: String,
}

#[derive(Deserialize)]
pub(crate) struct LoginHttpRequest {
    pub(crate) email: String,
    pub(crate) password: String,
    pub(crate) client_id: String,
    pub(crate) device_id: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RefreshHttpRequest {
    pub(crate) refresh_token: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LogoutHttpRequest {
    pub(crate) refresh_token: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProvisionDeviceHttpRequest {
    pub(crate) client_id: String,
    pub(crate) device_name: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LegacyCompleteDeviceRegistrationHttpRequest {
    pub(crate) device_id: String,
    pub(crate) proof_key_id: String,
    pub(crate) proof_challenge: String,
    pub(crate) proof_signature: String,
    pub(crate) proof_signed_at_unix_secs: u64,
    pub(crate) completed_at_unix_secs: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct IssueDeviceProofChallengeHttpRequest {
    pub(crate) device_id: String,
    pub(crate) purpose: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CompleteDeviceKeyRegistrationHttpRequest {
    pub(crate) device_id: String,
    pub(crate) public_jwk: Box<serde_json::value::RawValue>,
    pub(crate) challenge: String,
    pub(crate) signature: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RotateDeviceProofKeyHttpRequest {
    pub(crate) device_id: String,
    pub(crate) new_public_jwk: Box<serde_json::value::RawValue>,
    pub(crate) challenge: String,
    pub(crate) current_key_signature: String,
    pub(crate) new_key_signature: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BindDeviceHttpRequest {
    pub(crate) device_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct UnbindDeviceHttpRequest {
    pub(crate) device_id: String,
}

#[derive(Deserialize)]
pub(crate) struct DeviceManagementHttpRequest {
    pub(crate) device_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DeviceHeartbeatHttpRequest {
    pub(crate) device_id: String,
}

#[derive(Deserialize)]
pub(crate) struct AuthorizeHttpRequest {
    pub(crate) response_type: String,
    pub(crate) client_id: String,
    pub(crate) redirect_uri: String,
    pub(crate) scope: Option<String>,
    pub(crate) state: Option<String>,
    pub(crate) code_challenge: Option<String>,
    pub(crate) code_challenge_method: Option<String>,
    pub(crate) nonce: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct TokenHttpRequest {
    pub(crate) grant_type: String,
    pub(crate) code: String,
    pub(crate) redirect_uri: String,
    pub(crate) client_id: String,
    pub(crate) client_secret: Option<String>,
    pub(crate) code_verifier: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RevokeTokenHttpRequest {
    pub(crate) token: String,
    pub(crate) token_type_hint: Option<String>,
    pub(crate) client_id: String,
    pub(crate) client_secret: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct IntrospectTokenHttpRequest {
    pub(crate) token: String,
    pub(crate) token_type_hint: Option<String>,
    pub(crate) client_id: String,
    pub(crate) client_secret: Option<String>,
}

#[derive(Serialize)]
pub(crate) struct AuthHttpResponse {
    pub(crate) account_id: String,
    pub(crate) session_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) device_id: Option<String>,
    pub(crate) access_token: String,
    pub(crate) refresh_token: String,
    pub(crate) refresh_token_version: u64,
}

#[derive(Serialize)]
pub(crate) struct DeviceProofChallengeHttpResponse {
    pub(crate) challenge: String,
    pub(crate) expires_at_unix_secs: u64,
}

#[derive(Serialize)]
pub(crate) struct DeviceKeyHttpResponse {
    pub(crate) device_id: String,
    pub(crate) key_id: String,
    pub(crate) key_version: u64,
    pub(crate) key_status: &'static str,
}

#[derive(Serialize)]
pub(crate) struct PendingVerificationHttpResponse {
    pub(crate) account_id: String,
    pub(crate) account_status: &'static str,
    pub(crate) verification_channel: &'static str,
    pub(crate) verification_expires_at_unix_secs: u64,
    pub(crate) delivery_status: &'static str,
}

#[derive(Serialize)]
pub(crate) struct DeviceHttpResponse {
    pub(crate) device_id: String,
    pub(crate) client_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) proof_key_id: Option<String>,
    pub(crate) status: &'static str,
}

#[derive(Serialize)]
pub(crate) struct DeviceBindingHttpResponse {
    pub(crate) binding_id: String,
    pub(crate) account_id: String,
    pub(crate) device_id: String,
    pub(crate) status: &'static str,
}

#[derive(Serialize)]
pub(crate) struct ProvisionDeviceHttpResponse {
    pub(crate) device: DeviceHttpResponse,
    pub(crate) challenge: String,
    pub(crate) expires_at_unix_secs: u64,
}

#[derive(Serialize)]
pub(crate) struct SecureProvisionDeviceHttpResponse {
    pub(crate) device: DeviceHttpResponse,
}

#[derive(Serialize)]
pub(crate) struct DeviceDetailHttpResponse {
    pub(crate) device: DeviceHttpResponse,
    pub(crate) bindings: Vec<DeviceBindingHttpResponse>,
}

#[derive(Serialize)]
pub(crate) struct DeviceListHttpResponse {
    pub(crate) devices: Vec<DeviceHttpResponse>,
}

#[derive(Serialize)]
pub(crate) struct DiscoveryHttpResponse {
    pub(crate) issuer: String,
    pub(crate) authorization_endpoint: String,
    pub(crate) jwks_uri: String,
    pub(crate) revocation_endpoint: String,
    pub(crate) userinfo_endpoint: String,
    pub(crate) introspection_endpoint: String,
    pub(crate) registration_endpoint: String,
    pub(crate) email_verification_endpoint: String,
    pub(crate) resend_verification_endpoint: String,
    pub(crate) login_endpoint: String,
    pub(crate) token_endpoint: String,
    pub(crate) device_provision_endpoint: String,
    pub(crate) device_completion_endpoint: String,
    pub(crate) device_binding_endpoint: String,
    pub(crate) devices_endpoint: String,
    pub(crate) device_detail_path_template: String,
    pub(crate) device_unbind_endpoint: String,
    pub(crate) device_heartbeat_endpoint: String,
    pub(crate) response_types_supported: [&'static str; 1],
    pub(crate) grant_types_supported: [&'static str; 1],
    pub(crate) code_challenge_methods_supported: [&'static str; 2],
}

#[derive(Serialize)]
pub(crate) struct OidcTokenHttpResponse {
    pub(crate) access_token: String,
    pub(crate) refresh_token: String,
    pub(crate) refresh_token_version: u64,
    pub(crate) token_type: &'static str,
    pub(crate) id_token: Option<String>,
    pub(crate) scope: Option<String>,
    pub(crate) subject_account_id: String,
}

#[derive(Serialize)]
pub(crate) struct UserInfoHttpResponse {
    pub(crate) sub: String,
    pub(crate) email: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) name: Option<String>,
}

#[derive(Serialize)]
pub(crate) struct IntrospectionHttpResponse {
    pub(crate) active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) sub: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) client_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) token_type: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) sid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) exp: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) iat: Option<u64>,
}

#[derive(Serialize)]
pub(crate) struct JwksHttpResponse {
    pub(crate) keys: Vec<JwkHttpResponse>,
}

#[derive(Serialize)]
pub(crate) struct JwkHttpResponse {
    pub(crate) kid: String,
    pub(crate) kty: String,
    pub(crate) alg: String,
    #[serde(rename = "use")]
    pub(crate) public_key_use: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) crv: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) n: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) e: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) x: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) y: Option<String>,
}

#[derive(Serialize)]
pub(crate) struct ErrorHttpResponse {
    pub(crate) code: &'static str,
    pub(crate) message: String,
}
