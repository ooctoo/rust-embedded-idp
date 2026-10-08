use std::collections::{BTreeMap, BTreeSet};

use embedded_idp_core::{
    access::{
        EncryptedScanResult, ScanResultCipher, ScanResultCipherError, ScanResultContext,
        MAX_SCAN_RESULT_BYTES,
    },
    SecretString,
};
use ring::{
    aead::{self, Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM},
    rand::{SecureRandom, SystemRandom},
};

const NONCE_BYTES: usize = 12;

/// A named AES-256-GCM key used only for encrypted scan-login results.
///
/// The key bytes deliberately have no accessor and are redacted from `Debug`.
#[derive(Clone, PartialEq, Eq)]
pub struct ScanResultKey {
    key_id: String,
    bytes: [u8; 32],
}

impl ScanResultKey {
    pub fn new(key_id: impl Into<String>, bytes: [u8; 32]) -> Self {
        Self {
            key_id: key_id.into(),
            bytes,
        }
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }
}

impl std::fmt::Debug for ScanResultKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ScanResultKey")
            .field("key_id", &self.key_id)
            .field("bytes", &"[REDACTED]")
            .finish()
    }
}

/// Typed, process-local result encryption configuration.
///
/// `current_key_id` encrypts new results. All listed keys, including old keys,
/// can decrypt existing results until they are purged by the host.
#[derive(Clone, PartialEq, Eq)]
pub struct ScanResultKeyring {
    current_key_id: String,
    keys: BTreeMap<String, [u8; 32]>,
}

impl ScanResultKeyring {
    pub fn new(
        current_key_id: impl Into<String>,
        keys: impl IntoIterator<Item = ScanResultKey>,
    ) -> Result<Self, ScanResultCipherError> {
        let current_key_id = current_key_id.into();
        if !valid_key_id(&current_key_id) {
            return Err(ScanResultCipherError::InvalidKeyConfiguration);
        }

        let mut configured = BTreeMap::new();
        let mut distinct_material = BTreeSet::new();
        for key in keys {
            if !valid_key_id(&key.key_id)
                || configured.contains_key(&key.key_id)
                || !distinct_material.insert(key.bytes)
            {
                return Err(ScanResultCipherError::InvalidKeyConfiguration);
            }
            configured.insert(key.key_id, key.bytes);
        }
        if !configured.contains_key(&current_key_id) {
            return Err(ScanResultCipherError::InvalidKeyConfiguration);
        }

        Ok(Self {
            current_key_id,
            keys: configured,
        })
    }

    pub fn current_key_id(&self) -> &str {
        &self.current_key_id
    }
}

fn valid_key_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
}

impl std::fmt::Debug for ScanResultKeyring {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ScanResultKeyring")
            .field("current_key_id", &self.current_key_id)
            .field("key_ids", &self.keys.keys().collect::<Vec<_>>())
            .finish()
    }
}

/// `ring` AES-256-GCM implementation for bounded scan-login result payloads.
#[derive(Clone, Debug)]
pub struct RingScanResultCipher {
    keyring: ScanResultKeyring,
}

impl RingScanResultCipher {
    pub fn new(keyring: ScanResultKeyring) -> Self {
        Self { keyring }
    }

    fn aead_key(&self, key_id: &str) -> Result<LessSafeKey, ScanResultCipherError> {
        let bytes = self
            .keyring
            .keys
            .get(key_id)
            .ok_or(ScanResultCipherError::DecryptionFailed)?;
        let key = UnboundKey::new(&AES_256_GCM, bytes)
            .map_err(|_| ScanResultCipherError::EncryptionFailed)?;
        Ok(LessSafeKey::new(key))
    }
}

impl ScanResultCipher for RingScanResultCipher {
    fn seal(
        &self,
        context: &ScanResultContext,
        plaintext: &SecretString,
    ) -> Result<EncryptedScanResult, ScanResultCipherError> {
        let authenticated = context.authenticated_bytes()?;
        if plaintext.expose_secret().len() > MAX_SCAN_RESULT_BYTES {
            return Err(ScanResultCipherError::ResultTooLarge);
        }

        let mut nonce = [0_u8; NONCE_BYTES];
        SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| ScanResultCipherError::RandomFailure)?;
        let mut ciphertext = plaintext.expose_secret().as_bytes().to_vec();
        self.aead_key(&self.keyring.current_key_id)?
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(authenticated.as_slice()),
                &mut ciphertext,
            )
            .map_err(|_| ScanResultCipherError::EncryptionFailed)?;

        Ok(EncryptedScanResult {
            key_id: self.keyring.current_key_id.clone(),
            nonce,
            ciphertext,
        })
    }

    fn open(
        &self,
        context: &ScanResultContext,
        encrypted: &EncryptedScanResult,
    ) -> Result<SecretString, ScanResultCipherError> {
        let authenticated = context.authenticated_bytes()?;
        if encrypted.ciphertext.len() < aead::MAX_TAG_LEN
            || encrypted.ciphertext.len() > MAX_SCAN_RESULT_BYTES + aead::MAX_TAG_LEN
        {
            return Err(ScanResultCipherError::DecryptionFailed);
        }
        let key = self.aead_key(&encrypted.key_id)?;
        let mut plaintext = encrypted.ciphertext.clone();
        let plaintext = key
            .open_in_place(
                Nonce::assume_unique_for_key(encrypted.nonce),
                Aad::from(authenticated.as_slice()),
                &mut plaintext,
            )
            .map_err(|_| ScanResultCipherError::DecryptionFailed)?;
        let plaintext =
            std::str::from_utf8(plaintext).map_err(|_| ScanResultCipherError::DecryptionFailed)?;
        Ok(SecretString::new(plaintext))
    }
}
