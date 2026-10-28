use embedded_idp_security::{AccountSecurityKeySet, RingAccountSecurityCrypto};
use serde::Deserialize;
use std::{fs::File, io::Read};

const SUBJECT_KEY_BYTES: usize = 32;
const KEY_SET_BYTES: usize = 128;

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AccountSecurityConfig {
    pub authority: String,
    #[serde(default)]
    pub recovery_email: bool,
    pub subject_key_file: String,
    pub current: SecurityKeyFile,
    #[serde(default)]
    pub previous: Option<SecurityKeyFile>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SecurityKeyFile {
    pub key_id: String,
    pub key_file: String,
}

impl AccountSecurityConfig {
    /// Validate only the non-secret configuration. Key material is read only
    /// when the online composition is built, never by the preparation CLI.
    pub(crate) fn validate(&self) -> Result<(), String> {
        if !valid_identifier(&self.authority, 128)
            || !valid_key_id(&self.current.key_id)
            || self
                .previous
                .as_ref()
                .is_some_and(|key| !valid_key_id(&key.key_id) || key.key_id == self.current.key_id)
            || self.subject_key_file.trim().is_empty()
            || self.current.key_file.trim().is_empty()
            || self
                .previous
                .as_ref()
                .is_some_and(|key| key.key_file.trim().is_empty())
        {
            return Err("invalid runtime.account_security configuration".into());
        }
        Ok(())
    }

    pub(crate) fn load_crypto(&self) -> Result<RingAccountSecurityCrypto, String> {
        self.validate()?;
        let subject = read_secret_file(&self.subject_key_file, SUBJECT_KEY_BYTES)?;
        let subject: [u8; SUBJECT_KEY_BYTES] = subject
            .try_into()
            .map_err(|_| "invalid account-security key material".to_string())?;
        let current = load_key_set(&self.current)?;
        let previous = self.previous.as_ref().map(load_key_set).transpose()?;
        RingAccountSecurityCrypto::new(self.authority.clone(), subject, current, previous)
            .map_err(|_| "invalid account-security key material".into())
    }
}

fn load_key_set(reference: &SecurityKeyFile) -> Result<AccountSecurityKeySet, String> {
    let bytes = read_secret_file(&reference.key_file, KEY_SET_BYTES)?;
    let secret = key_part(&bytes, 0)?;
    let command = key_part(&bytes, 32)?;
    let code = key_part(&bytes, 64)?;
    let envelope = key_part(&bytes, 96)?;
    Ok(AccountSecurityKeySet::new(
        reference.key_id.clone(),
        secret,
        command,
        code,
        envelope,
    ))
}

fn key_part(bytes: &[u8], offset: usize) -> Result<[u8; 32], String> {
    bytes
        .get(offset..offset + 32)
        .and_then(|part| part.try_into().ok())
        .ok_or_else(|| "invalid account-security key file".into())
}

fn read_secret_file(path: &str, exact_length: usize) -> Result<Vec<u8>, String> {
    let file = File::open(path).map_err(|_| "cannot open account-security key file")?;
    let metadata = file
        .metadata()
        .map_err(|_| "cannot inspect account-security key file")?;
    if !metadata.is_file() || metadata.len() != exact_length as u64 {
        return Err("invalid account-security key file".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err("account-security key files must be owner-only (chmod 600)".into());
        }
    }
    let mut bytes = Vec::with_capacity(exact_length + 1);
    file.take((exact_length + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| "cannot read account-security key file")?;
    if bytes.len() != exact_length {
        return Err("invalid account-security key file".into());
    }
    Ok(bytes)
}

fn valid_identifier(value: &str, max_len: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
}

fn valid_key_id(value: &str) -> bool {
    valid_identifier(value, 32)
}

#[cfg(test)]
mod tests {
    use super::*;
    use embedded_idp_core::{AccountSecurityCrypto, SecurityCryptoContext, SecurityDigestPurpose};
    use std::{
        fs,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
        time::{SystemTime, UNIX_EPOCH},
    };

    static TEMP_ID: AtomicU64 = AtomicU64::new(0);

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "idp-account-security-{}-{}-{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos(),
                TEMP_ID.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn file(&self, name: &str, bytes: &[u8]) -> String {
            let path = self.0.join(name);
            fs::write(&path, bytes).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            }
            path.to_string_lossy().into_owned()
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn fixture_config(dir: &TempDir) -> AccountSecurityConfig {
        fn key_material(start: u8) -> Vec<u8> {
            [start, start + 1, start + 2, start + 3]
                .into_iter()
                .flat_map(|byte| [byte; 32])
                .collect()
        }
        AccountSecurityConfig {
            authority: "idp.example.test".into(),
            recovery_email: false,
            subject_key_file: dir.file("subject.key", &[1; 32]),
            current: SecurityKeyFile {
                key_id: "current".into(),
                key_file: dir.file("current.key", &key_material(2)),
            },
            previous: Some(SecurityKeyFile {
                key_id: "previous".into(),
                key_file: dir.file("previous.key", &key_material(6)),
            }),
        }
    }

    #[test]
    fn loads_current_and_previous_key_sets_without_exposing_material() {
        let dir = TempDir::new();
        let config = fixture_config(&dir);
        let crypto = config.load_crypto().unwrap();
        assert_eq!(crypto.authority(), "idp.example.test");
        assert!(!format!("{crypto:?}").contains("[2"));
        let old = RingAccountSecurityCrypto::new(
            "idp.example.test".into(),
            [1; 32],
            AccountSecurityKeySet::new("previous".into(), [6; 32], [7; 32], [8; 32], [9; 32]),
            None,
        )
        .unwrap();
        let context = SecurityCryptoContext {
            reference_id: embedded_idp_core::access::Uuid::from_u128(1),
            related_id: None,
        };
        let digest = old
            .digest(SecurityDigestPurpose::ReceiptSecret, &context, b"synthetic")
            .unwrap();
        assert_eq!(digest.key_id, "previous");
        assert!(crypto
            .verify_digest(
                SecurityDigestPurpose::ReceiptSecret,
                &context,
                b"synthetic",
                &digest
            )
            .unwrap());
    }

    #[test]
    fn rejects_wrong_lengths_duplicate_material_and_missing_files() {
        let dir = TempDir::new();
        let mut config = fixture_config(&dir);
        config.subject_key_file = dir.file("short.key", &[1; 31]);
        assert!(config.load_crypto().is_err());
        config = fixture_config(&dir);
        config.current.key_file = dir.file("short-current.key", &[2; 127]);
        assert!(config.load_crypto().is_err());
        config = fixture_config(&dir);
        config.current.key_file = dir.file("duplicate.key", &{
            let mut bytes = Vec::new();
            bytes
                .extend_from_slice(&fs::read(&config.previous.as_ref().unwrap().key_file).unwrap());
            bytes
        });
        assert!(config.load_crypto().is_err());
        config = fixture_config(&dir);
        config.subject_key_file = dir.0.join("missing.key").to_string_lossy().into_owned();
        let error = config.load_crypto().unwrap_err();
        assert!(!error.contains(&config.subject_key_file));
    }

    #[test]
    fn static_validation_rejects_bad_ids_and_duplicate_rotation_id() {
        let dir = TempDir::new();
        let mut config = fixture_config(&dir);
        config.current.key_id = "bad/id".into();
        assert!(config.validate().is_err());
        config.current.key_id = "same".into();
        config.previous.as_mut().unwrap().key_id = "same".into();
        assert!(config.validate().is_err());
    }

    #[cfg(unix)]
    #[test]
    fn rejects_group_or_other_readable_secret_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new();
        let config = fixture_config(&dir);
        fs::set_permissions(&config.subject_key_file, fs::Permissions::from_mode(0o640)).unwrap();
        assert!(config.load_crypto().unwrap_err().contains("owner-only"));
    }

    #[test]
    fn config_shape_rejects_unknown_fields() {
        let parsed = serde_json::from_str::<AccountSecurityConfig>(
            r#"{"authority":"idp.test","subject_key_file":"subject","current":{"key_id":"current","key_file":"current"},"secret":"bad"}"#,
        );
        assert!(parsed.is_err());
        let parsed = serde_json::from_str::<SecurityKeyFile>(
            r#"{"key_id":"current","key_file":"key","extra":true}"#,
        );
        assert!(parsed.is_err());
    }
}
