//! Explicit reference-host scan configuration; Core owns the protocol/state machine.
use crate::composition_config::{read_limited, valid_id, AppConfig, EntryConfig};
use axum::{
    extract::{Request, State},
    middleware::Next,
    response::Response,
};
use embedded_idp_core::access::*;
use embedded_idp_security::{RingScanResultCipher, ScanResultKey, ScanResultKeyring};
use serde::Deserialize;
use std::{
    collections::BTreeSet,
    path::Path,
    time::{Duration, SystemTime},
};

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ScanConfig {
    pub admission_provider: String,
    pub presentation_provider: String,
    pub host_scope: String,
    pub modes: Vec<String>,
    pub audience: String,
    pub device_prefix: String,
    pub verification_uri: String,
    pub result_keyring: ResultKeyringConfig,
    pub cleanup: CleanupConfig,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ResultKeyringConfig {
    pub active_key_id: String,
    pub keys: Vec<ResultKeyReference>,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ResultKeyReference {
    pub key_id: String,
    pub key_file: String,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CleanupConfig {
    pub interval_secs: u64,
    pub batch_size: u32,
}
impl ScanConfig {
    pub fn entry(&self, entry: &EntryConfig) -> Result<ScanLoginEntryConfig, String> {
        let modes = self
            .modes
            .iter()
            .map(|mode| match mode.as_str() {
                "device_display" => Ok(ScanLoginMode::DeviceDisplay),
                "phone_display" => Ok(ScanLoginMode::PhoneDisplay),
                _ => Err("unsupported scan mode".to_string()),
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(ScanLoginEntryConfig {
            entry_id: entry.login_entry.clone(),
            target_client_id: entry.client_id.clone(),
            allowed_source_client_ids: vec![entry.client_id.clone()],
            host_scope: self.host_scope.clone(),
            tenant_policy: entry.policy.clone(),
            modes,
            target_scope: None,
            limits: ScanLoginLimits::default(),
        })
    }
    pub fn validate(&self, entry: &EntryConfig, config: &AppConfig) -> Result<(), String> {
        if entry.device.is_none() || entry.browser.is_none() || entry.require_device_proof {
            return Err("scan requires device and ordinary browser source configuration".into());
        }
        if self.admission_provider != "reference-identity-only"
            || self.presentation_provider != "registered-device"
        {
            return Err("unsupported scan admission/presentation provider".into());
        }
        self.entry(entry)?
            .validate(config.tenancy_mode)
            .map_err(|_| "invalid scan entry configuration")?;
        let origin = config
            .browser_origin
            .as_deref()
            .ok_or("scan requires browser origin")?;
        if self.device_prefix != format!("{}/auth/device-scan", entry.mount_prefix)
            || self.verification_uri
                != format!("{origin}{}/auth/browser/device-scan/ui", entry.mount_prefix)
        {
            return Err(
                "scan paths must match mounted routes and configured browser origin".into(),
            );
        }
        embedded_idp_axum::ScanDeviceHttpConfig::new_with_transport_policy(
            &self.audience,
            &self.device_prefix,
            &self.verification_uri,
            &config.transport_policy,
        )
        .map_err(|_| "invalid scan proof HTTP configuration")?;
        if !(1..=3600).contains(&self.cleanup.interval_secs)
            || !(1..=100).contains(&self.cleanup.batch_size)
        {
            return Err("invalid bounded scan cleanup configuration".into());
        }
        let keys = &self.result_keyring;
        let mut ids = BTreeSet::new();
        if !(1..=4).contains(&keys.keys.len())
            || !valid_id(&keys.active_key_id)
            || keys
                .keys
                .iter()
                .any(|k| !valid_id(&k.key_id) || !ids.insert(&k.key_id))
            || !ids.contains(&keys.active_key_id)
        {
            return Err("invalid scan result keyring references".into());
        }
        Ok(())
    }
    pub fn load_cipher(&self) -> Result<RingScanResultCipher, String> {
        let keys = self
            .result_keyring
            .keys
            .iter()
            .map(|key| {
                let path = Path::new(&key.key_file);
                let metadata =
                    std::fs::metadata(path).map_err(|_| "cannot inspect scan result key")?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    if metadata.permissions().mode() & 0o077 != 0 {
                        return Err("scan result key must be owner-only".to_string());
                    }
                }
                let bytes: [u8; 32] = read_limited(path, 32, "scan result key")?
                    .try_into()
                    .map_err(|_| "scan result key must contain exactly 32 raw bytes")?;
                Ok(ScanResultKey::new(&key.key_id, bytes))
            })
            .collect::<Result<Vec<_>, String>>()?;
        Ok(RingScanResultCipher::new(
            ScanResultKeyring::new(&self.result_keyring.active_key_id, keys)
                .map_err(|_| "invalid scan result keyring material")?,
        ))
    }
}
/// The configured scope is trusted host metadata, never request-supplied authority.
pub(crate) async fn host_context(
    State(scope): State<String>,
    mut request: Request,
    next: Next,
) -> Response {
    request.extensions_mut().insert(TrustedScanHostContext::new(
        scope,
        SystemTime::now() + Duration::from_secs(60),
    ));
    next.run(request).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use embedded_idp_core::{
        access::ScanResultCipher, IdGenerator, SecretString, UuidV7IdGenerator,
    };
    #[test]
    #[cfg(unix)]
    fn private_keyring_supports_overlap_and_rejects_ambiguous_or_missing_material() {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let dir =
            std::env::temp_dir().join(format!("b3-keys-{}", UuidV7IdGenerator.next_id("test")));
        std::fs::create_dir(&dir).unwrap();
        for (name, byte) in [("old", 1), ("new", 2)] {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(dir.join(name))
                .unwrap();
            file.write_all(&[byte; 32]).unwrap();
        }
        let mut config: ScanConfig = serde_json::from_value(serde_json::json!({"admission_provider":"reference-identity-only","presentation_provider":"registered-device","host_scope":"test","modes":["device_display"],"audience":"test","device_prefix":"/auth/device-scan","verification_uri":"http://localhost/auth/browser/device-scan/ui","result_keyring":{"active_key_id":"old","keys":[{"key_id":"old","key_file":dir.join("old")},{"key_id":"new","key_file":dir.join("new")}]},"cleanup":{"interval_secs":30,"batch_size":100}})).unwrap();
        let original = config.load_cipher().unwrap();
        let context = ScanResultContext {
            tenant_id: "0".into(),
            host_scope: "test".into(),
            entry_id: "entry".into(),
            grant_id: "11111111-1111-4111-8111-111111111111".into(),
            expires_at_unix_secs: 2000000000,
            payload: ScanResultPayload::DevicePresentation {
                device_id: "22222222-2222-4222-8222-222222222222".into(),
                origin_operation_id: "33333333-3333-4333-8333-333333333333".into(),
            },
        };
        let sealed = original
            .seal(&context, &SecretString::new("synthetic-payload"))
            .unwrap();
        config.result_keyring.active_key_id = "new".into();
        let rotated = config.load_cipher().unwrap();
        assert_eq!(
            rotated.open(&context, &sealed).unwrap().expose_secret(),
            "synthetic-payload"
        );
        let mut other_entry = context.clone();
        other_entry.entry_id = "other-entry".into();
        assert!(rotated.open(&other_entry, &sealed).is_err());
        let mut duplicate_material = config.clone();
        duplicate_material.result_keyring.keys[1].key_file =
            duplicate_material.result_keyring.keys[0].key_file.clone();
        assert!(duplicate_material.load_cipher().is_err());
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.join("new"), std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(config.load_cipher().is_err());
        std::fs::set_permissions(dir.join("new"), std::fs::Permissions::from_mode(0o600)).unwrap();
        config.result_keyring.keys.remove(0);
        assert!(config
            .load_cipher()
            .unwrap()
            .open(&context, &sealed)
            .is_err());
        config
            .result_keyring
            .keys
            .push(config.result_keyring.keys[0].clone());
        assert!(config.load_cipher().is_err());
        config.result_keyring.keys.pop();
        std::fs::write(dir.join("new"), [2; 31]).unwrap();
        assert!(config.load_cipher().is_err());
        std::fs::remove_file(dir.join("new")).unwrap();
        assert!(config.load_cipher().is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
