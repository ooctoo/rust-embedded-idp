//! Reference-host enrollment grants. A private, pre-approved grant binds an
//! opaque credential to one tenant/client/device; it is not a device approval API.
use crate::composition_config::{read_limited, valid_id, Unique};
use axum::{
    extract::{OriginalUri, Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use embedded_idp_core::{
    access::*, ClientSecretVerifier, PasswordWorkBudget, PhcClientSecretCodec,
};
use serde::Deserialize;
use std::{
    collections::BTreeMap,
    path::Path,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const HEADER: &str = "x-embedded-idp-device-admission";
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Grant {
    grant_id: String,
    tenant_id: String,
    client_id: String,
    device_id: String,
    credential_hash: String,
    issued_at_unix_secs: u64,
    expires_at_unix_secs: u64,
}
pub(crate) struct FileAdmission {
    grants: BTreeMap<String, Grant>,
    password_work: PasswordWorkBudget,
}
impl FileAdmission {
    pub fn load(provider: &str, path: &str) -> Result<Self, String> {
        let path = Path::new(path);
        let metadata = std::fs::metadata(path).map_err(|_| "cannot inspect admission grants")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err("admission grants must be owner-only".into());
            }
        }
        let bytes = read_limited(path, 65536, "admission grants")?;
        let unique: Unique =
            serde_json::from_slice(&bytes).map_err(|_| "invalid admission grants structure")?;
        let grants: Vec<Grant> =
            serde_json::from_value(unique.0).map_err(|_| "invalid admission grant fields")?;
        if grants.is_empty() || grants.len() > 128 {
            return Err("admission grants count must be 1..128".into());
        }
        let mut result = BTreeMap::new();
        for grant in grants {
            if grant.grant_id.contains('.') || !valid_id(&grant.grant_id) || grant.grant_id.len() > 48
                || !valid_id(&grant.tenant_id) || !valid_id(&grant.client_id)
                || !canonical_uuid(&grant.device_id)
                || grant.expires_at_unix_secs <= grant.issued_at_unix_secs
                || grant.expires_at_unix_secs - grant.issued_at_unix_secs > 3600
                || UNIX_EPOCH.checked_add(Duration::from_secs(grant.expires_at_unix_secs)).is_none()
                // Only the existing codec's bounded default parameters are accepted.
                || !grant.credential_hash.starts_with("$argon2id$v=19$m=19456,t=2,p=1$")
                || grant.credential_hash.len() > 256
            {
                return Err("invalid admission grant constraints".into());
            }
            PhcClientSecretCodec
                .verify_client_secret("validation-only", &grant.credential_hash)
                .map_err(|_| "invalid admission credential hash")?;
            let scope = format!("{provider}.{}", grant.grant_id);
            if result.insert(scope, grant).is_some() {
                return Err("duplicate admission grant".into());
            }
        }
        Ok(Self {
            grants: result,
            password_work: PasswordWorkBudget::default(),
        })
    }
    pub fn with_password_work_budget(mut self, budget: PasswordWorkBudget) -> Self {
        self.password_work = budget;
        self
    }
    fn authenticate(
        &self,
        provider: &str,
        client: &str,
        value: &str,
        now: SystemTime,
    ) -> Option<TrustedDeviceAdmission> {
        let (id, secret) = value.split_once('.')?;
        if secret.len() < 32
            || secret.len() > 256
            || !secret.is_ascii()
            || secret.bytes().any(|b| b.is_ascii_whitespace())
        {
            return None;
        }
        let scope = format!("{provider}.{id}");
        let grant = self.grants.get(&scope)?;
        let expires = UNIX_EPOCH.checked_add(Duration::from_secs(grant.expires_at_unix_secs))?;
        let issued = UNIX_EPOCH.checked_add(Duration::from_secs(grant.issued_at_unix_secs))?;
        if grant.client_id != client || now < issued || now >= expires {
            return None;
        }
        if !PhcClientSecretCodec
            .verify_client_secret(secret, &grant.credential_hash)
            .ok()?
        {
            return None;
        }
        Some(TrustedDeviceAdmission {
            registration_scope: scope,
            valid_until: expires.min(now.checked_add(Duration::from_secs(300))?),
        })
    }
}
fn canonical_uuid(s: &str) -> bool {
    s.len() == 36
        && s.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
            }
        })
}
impl TenantDeviceAdmission for FileAdmission {
    fn authorize(
        &self,
        tenant: &str,
        client: &str,
        device: &str,
        _: DeviceAdmissionAction,
        context: &TrustedDeviceAdmission,
    ) -> Result<(), AccessError> {
        let grant = self
            .grants
            .get(&context.registration_scope)
            .ok_or(AccessError::Forbidden)?;
        let now = SystemTime::now();
        let expiry = UNIX_EPOCH + Duration::from_secs(grant.expires_at_unix_secs);
        if grant.tenant_id != tenant
            || grant.client_id != client
            || grant.device_id != device
            || now < UNIX_EPOCH + Duration::from_secs(grant.issued_at_unix_secs)
            || now >= expiry
            || now >= context.valid_until
            || context.valid_until > expiry
        {
            return Err(AccessError::Forbidden);
        }
        Ok(())
    }
}
#[derive(Clone)]
pub(crate) struct AdmissionHttp {
    pub provider: Arc<FileAdmission>,
    pub provider_id: String,
    pub client: String,
    pub provision_path: String,
    pub result_path: String,
}
pub(crate) async fn inject(
    State(state): State<AdmissionHttp>,
    mut request: Request,
    next: Next,
) -> Response {
    let path = request
        .extensions()
        .get::<OriginalUri>()
        .map(|u| u.0.path())
        .unwrap_or(request.uri().path());
    if path != state.provision_path && path != state.result_path {
        return next.run(request).await;
    }
    request.extensions_mut().remove::<TrustedDeviceAdmission>();
    let mut values = request.headers().get_all(HEADER).iter();
    let credential = values
        .next()
        .and_then(|v| v.to_str().ok())
        .filter(|v| v.len() <= 320)
        .map(str::to_owned);
    if values.next().is_some() {
        return denied();
    }
    let Some(credential) = credential else {
        return denied();
    };
    let Ok(permit) = state.provider.password_work.try_login() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            [("cache-control", "no-store")],
            Json(serde_json::json!({"error":"device_admission_busy"})),
        )
            .into_response();
    };
    let result = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        state.provider.authenticate(
            &state.provider_id,
            &state.client,
            &credential,
            SystemTime::now(),
        )
    })
    .await;
    match result {
        Ok(Some(context)) => {
            request.extensions_mut().insert(context);
            next.run(request).await
        }
        _ => denied(),
    }
}
fn denied() -> Response {
    (StatusCode::UNAUTHORIZED, [("cache-control", "no-store")], Json(serde_json::json!({"error":"device_admission_required","message":"valid device admission is required"}))).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, routing::post, Router};
    use embedded_idp_core::{ClientSecretHasher, IdGenerator, UuidV7IdGenerator};
    use tower::ServiceExt;
    fn fixture() -> (FileAdmission, String, String) {
        let id = UuidV7IdGenerator.next_id("grant");
        let path = std::env::temp_dir().join(format!("b2-admission-{id}.json"));
        let secret = "synthetic-admission-credential-32-bytes".to_string();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let grants = serde_json::json!([{"grant_id":"one","tenant_id":"t1","client_id":"client-one","device_id":"00000000-0000-0000-0000-000000000001","credential_hash":PhcClientSecretCodec.hash_client_secret(&secret).unwrap(),"issued_at_unix_secs":now-1,"expires_at_unix_secs":now+600}]);
        std::fs::write(&path, serde_json::to_vec(&grants).unwrap()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let provider = FileAdmission::load("enrollment", path.to_str().unwrap()).unwrap();
        std::fs::remove_file(path).unwrap();
        (
            provider,
            format!("one.{secret}"),
            "00000000-0000-0000-0000-000000000001".into(),
        )
    }
    #[test]
    #[cfg(unix)]
    fn grant_files_reject_ambiguous_scope_unbounded_hash_and_lifetime() {
        use std::os::unix::fs::PermissionsExt;
        let path = std::env::temp_dir().join(format!(
            "b2-invalid-{}.json",
            UuidV7IdGenerator.next_id("file")
        ));
        let valid = serde_json::json!({"grant_id":"one","tenant_id":"0","client_id":"one","device_id":"00000000-0000-0000-0000-000000000001","credential_hash":PhcClientSecretCodec.hash_client_secret("synthetic-secret-with-more-than-32-bytes").unwrap(),"issued_at_unix_secs":1,"expires_at_unix_secs":3601});
        fs_write_private(&path, &serde_json::json!([valid.clone()]));
        assert!(FileAdmission::load("enrollment", path.to_str().unwrap()).is_ok());
        for (field, value) in [
            ("grant_id", serde_json::json!("one.two")),
            ("device_id", serde_json::json!("noncanonical")),
            ("expires_at_unix_secs", serde_json::json!(3602)),
            ("expires_at_unix_secs", serde_json::json!(1)),
            (
                "credential_hash",
                serde_json::json!("$argon2id$v=19$m=999999,t=2,p=1$bad$bad"),
            ),
        ] {
            let mut invalid = valid.clone();
            invalid[field] = value;
            fs_write_private(&path, &serde_json::json!([invalid]));
            assert!(
                FileAdmission::load("enrollment", path.to_str().unwrap()).is_err(),
                "{field}"
            );
        }
        fs_write_private(&path, &serde_json::json!([valid.clone(), valid.clone()]));
        assert!(FileAdmission::load("enrollment", path.to_str().unwrap()).is_err());
        fs_write_private(&path, &serde_json::json!([valid]));
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(FileAdmission::load("enrollment", path.to_str().unwrap()).is_err());
        std::fs::remove_file(path).unwrap();
        fn fs_write_private(path: &Path, value: &serde_json::Value) {
            std::fs::write(path, serde_json::to_vec(value).unwrap()).unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
    }
    #[test]
    fn grants_bind_identity_and_fixed_deadlines() {
        let (provider, credential, device) = fixture();
        let now = SystemTime::now();
        let context = provider
            .authenticate("enrollment", "client-one", &credential, now)
            .unwrap();
        assert!(context.valid_until <= now + Duration::from_secs(300));
        for (tenant, client, id) in [
            ("t1", "client-one", device.as_str()),
            ("t2", "client-one", device.as_str()),
            ("t1", "client-two", device.as_str()),
            ("t1", "client-one", "00000000-0000-0000-0000-000000000002"),
        ] {
            assert_eq!(
                provider
                    .authorize(
                        tenant,
                        client,
                        id,
                        DeviceAdmissionAction::ReadResult,
                        &context
                    )
                    .is_ok(),
                tenant == "t1" && client == "client-one" && id == device
            );
        }
        assert!(provider
            .authenticate("other", "client-one", &credential, now)
            .is_none());
        assert!(provider
            .authenticate("enrollment", "client-two", &credential, now)
            .is_none());
        assert!(provider
            .authenticate(
                "enrollment",
                "client-one",
                &credential,
                now + Duration::from_secs(601)
            )
            .is_none());
        let mut expired = context.clone();
        expired.valid_until = now - Duration::from_secs(1);
        assert!(provider
            .authorize(
                "t1",
                "client-one",
                &device,
                DeviceAdmissionAction::Provision,
                &expired
            )
            .is_err());
        let mut forged = context;
        forged.registration_scope = "caller-supplied".into();
        assert!(provider
            .authorize(
                "t1",
                "client-one",
                &device,
                DeviceAdmissionAction::ReadResult,
                &forged
            )
            .is_err());
    }
    #[tokio::test]
    async fn middleware_rejects_duplicate_credentials_and_injects_only_after_authentication() {
        let (provider, credential, _) = fixture();
        let budget = provider.password_work.clone();
        let route = Router::new()
            .route(
                "/devices/provision",
                post(
                    |context: Option<axum::Extension<TrustedDeviceAdmission>>| async move {
                        assert_eq!(context.unwrap().0.registration_scope, "enrollment.one");
                        StatusCode::CREATED
                    },
                ),
            )
            .layer(axum::middleware::from_fn_with_state(
                AdmissionHttp {
                    provider: Arc::new(provider),
                    provider_id: "enrollment".into(),
                    client: "client-one".into(),
                    provision_path: "/entry/devices/provision".into(),
                    result_path: "/entry/devices/registration-result".into(),
                },
                inject,
            ));
        let router = Router::new().nest("/entry", route);
        for (headers, expected) in [
            (vec![], 401),
            (vec![credential.as_str()], 201),
            (vec![credential.as_str(), credential.as_str()], 401),
            (vec!["one.invalid"], 401),
        ] {
            let mut builder = axum::http::Request::builder()
                .method("POST")
                .uri("/entry/devices/provision");
            for value in headers {
                builder = builder.header(HEADER, value);
            }
            let response = router
                .clone()
                .oneshot(builder.body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status().as_u16(), expected);
        }
        let permit: Vec<_> = (0..4).map(|_| budget.try_login().unwrap()).collect();
        let response = router
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/entry/devices/provision")
                    .header(HEADER, credential)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(response.headers()["cache-control"], "no-store");
        drop(permit);
    }
}
