use std::fmt;

use base64ct::{Base64UrlUnpadded, Encoding};
use embedded_idp_core::{
    access::Uuid, AccountSecurityCrypto, SecretString, SecurityCryptoContext, SecurityCryptoError,
    SecurityDigest, SecurityDigestPurpose, SecurityEnvelope, SecurityEnvelopePurpose,
};
use ring::{
    aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM},
    hmac,
    rand::{SecureRandom, SystemRandom},
};

const TOKEN_BYTES: usize = 32;
const NONCE_BYTES: usize = 12;
const TAG_BYTES: usize = 16;
const MAX_PAYLOAD_BYTES: usize = 16_384;
const MAX_ENVELOPE_BYTES: usize = NONCE_BYTES + MAX_PAYLOAD_BYTES + TAG_BYTES;
const CODE_SPACE: u64 = 1_000_000;
const CODE_BOUND: u64 = (u32::MAX as u64 + 1) / CODE_SPACE * CODE_SPACE;
const SUBJECT_DOMAIN: &[u8] = b"embedded-idp/account-security/subject/v1";
const DIGEST_DOMAIN: &[u8] = b"embedded-idp/account-security/digest/v1";
const ENVELOPE_DOMAIN: &[u8] = b"embedded-idp/account-security/envelope/v1";

/// One named key set. Material is never exposed and Debug is redacted.
#[derive(Clone)]
pub struct AccountSecurityKeySet {
    key_id: String,
    secret_key: [u8; 32],
    command_key: [u8; 32],
    code_key: [u8; 32],
    envelope_key: [u8; 32],
}

impl AccountSecurityKeySet {
    pub fn new(
        key_id: String,
        secret_key: [u8; 32],
        command_key: [u8; 32],
        code_key: [u8; 32],
        envelope_key: [u8; 32],
    ) -> Self {
        Self {
            key_id,
            secret_key,
            command_key,
            code_key,
            envelope_key,
        }
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }
}

impl fmt::Debug for AccountSecurityKeySet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AccountSecurityKeySet")
            .field("key_id", &self.key_id)
            .field("secret_key", &"<redacted>")
            .field("command_key", &"<redacted>")
            .field("code_key", &"<redacted>")
            .field("envelope_key", &"<redacted>")
            .finish()
    }
}

/// Ring-backed, authority-bound security crypto with one optional read-only
/// previous key set. New digests and envelopes always use `current`.
#[derive(Clone)]
pub struct RingAccountSecurityCrypto {
    authority: String,
    subject_key: [u8; 32],
    current: AccountSecurityKeySet,
    previous: Option<AccountSecurityKeySet>,
}

impl RingAccountSecurityCrypto {
    pub fn new(
        authority: String,
        subject_key: [u8; 32],
        current: AccountSecurityKeySet,
        previous: Option<AccountSecurityKeySet>,
    ) -> Result<Self, SecurityCryptoError> {
        if !valid_identifier(&authority, 128)
            || subject_key.iter().all(|byte| *byte == 0)
            || !valid_key_id(&current.key_id)
        {
            return Err(SecurityCryptoError::InvalidInput);
        }
        let mut material = vec![
            &subject_key,
            &current.secret_key,
            &current.command_key,
            &current.code_key,
            &current.envelope_key,
        ];
        if let Some(previous) = &previous {
            if !valid_key_id(&previous.key_id) || previous.key_id == current.key_id {
                return Err(SecurityCryptoError::InvalidInput);
            }
            material.extend([
                &previous.secret_key,
                &previous.command_key,
                &previous.code_key,
                &previous.envelope_key,
            ]);
        }
        if material.iter().any(|key| key.iter().all(|byte| *byte == 0))
            || material
                .iter()
                .enumerate()
                .any(|(i, key)| material[..i].contains(key))
        {
            return Err(SecurityCryptoError::InvalidInput);
        }
        Ok(Self {
            authority,
            subject_key,
            current,
            previous,
        })
    }

    fn key_set(&self, key_id: &str) -> Result<&AccountSecurityKeySet, SecurityCryptoError> {
        if self.current.key_id == key_id {
            return Ok(&self.current);
        }
        self.previous
            .as_ref()
            .filter(|key| key.key_id == key_id)
            .ok_or(SecurityCryptoError::UnknownKey)
    }

    fn digest_key(key: &[u8; 32], message: &[u8]) -> [u8; 32] {
        let key = hmac::Key::new(hmac::HMAC_SHA256, key);
        hmac::sign(&key, message)
            .as_ref()
            .try_into()
            .expect("HMAC-SHA256 output has fixed size")
    }

    fn digest_key_for(purpose: SecurityDigestPurpose, keys: &AccountSecurityKeySet) -> &[u8; 32] {
        match purpose {
            SecurityDigestPurpose::RecoveryHandle | SecurityDigestPurpose::ReceiptSecret => {
                &keys.secret_key
            }
            SecurityDigestPurpose::Command => &keys.command_key,
            SecurityDigestPurpose::RecoveryCode => &keys.code_key,
        }
    }

    fn digest_message(
        &self,
        key_id: &str,
        purpose: SecurityDigestPurpose,
        context: &SecurityCryptoContext,
        payload: &[u8],
    ) -> Result<Vec<u8>, SecurityCryptoError> {
        validate_context(context)?;
        if payload.len() > MAX_PAYLOAD_BYTES {
            return Err(SecurityCryptoError::InvalidInput);
        }
        let mut message = Vec::new();
        append_field(&mut message, DIGEST_DOMAIN)?;
        append_field(&mut message, self.authority.as_bytes())?;
        append_field(&mut message, key_id.as_bytes())?;
        append_field(&mut message, digest_purpose_name(purpose))?;
        append_field(&mut message, context.reference_id.as_bytes())?;
        append_related(&mut message, context.related_id)?;
        append_field(&mut message, payload)?;
        Ok(message)
    }

    fn envelope_aad(
        &self,
        key_id: &str,
        purpose: SecurityEnvelopePurpose,
        context: &SecurityCryptoContext,
    ) -> Result<Vec<u8>, SecurityCryptoError> {
        validate_context(context)?;
        let mut aad = Vec::new();
        append_field(&mut aad, ENVELOPE_DOMAIN)?;
        append_field(&mut aad, self.authority.as_bytes())?;
        append_field(&mut aad, key_id.as_bytes())?;
        append_field(&mut aad, envelope_purpose_name(purpose))?;
        append_field(&mut aad, context.reference_id.as_bytes())?;
        append_related(&mut aad, context.related_id)?;
        Ok(aad)
    }

    fn envelope_key(key: &[u8; 32]) -> Result<LessSafeKey, SecurityCryptoError> {
        UnboundKey::new(&AES_256_GCM, key)
            .map(LessSafeKey::new)
            .map_err(|_| SecurityCryptoError::Unavailable)
    }
}

impl fmt::Debug for RingAccountSecurityCrypto {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RingAccountSecurityCrypto")
            .field("authority", &self.authority)
            .field("subject_key", &"<redacted>")
            .field("current", &self.current)
            .field("previous", &self.previous)
            .finish()
    }
}

impl AccountSecurityCrypto for RingAccountSecurityCrypto {
    fn authority(&self) -> &str {
        &self.authority
    }

    fn random_token(&self) -> Result<SecretString, SecurityCryptoError> {
        let mut bytes = [0_u8; TOKEN_BYTES];
        SystemRandom::new()
            .fill(&mut bytes)
            .map_err(|_| SecurityCryptoError::Unavailable)?;
        Ok(SecretString::new(Base64UrlUnpadded::encode_string(&bytes)))
    }

    fn random_code(&self) -> Result<SecretString, SecurityCryptoError> {
        for _ in 0..8 {
            let mut bytes = [0_u8; 4];
            SystemRandom::new()
                .fill(&mut bytes)
                .map_err(|_| SecurityCryptoError::Unavailable)?;
            let value = u32::from_be_bytes(bytes) as u64;
            if value < CODE_BOUND {
                return Ok(SecretString::new(format!("{:06}", value % CODE_SPACE)));
            }
        }
        Err(SecurityCryptoError::Unavailable)
    }

    fn subject_digest(&self, email: &str) -> Result<[u8; 32], SecurityCryptoError> {
        let trimmed = email.trim_matches(' ');
        if !(1..=254).contains(&trimmed.len()) {
            return Err(SecurityCryptoError::InvalidInput);
        }
        let normalized = trimmed.to_ascii_lowercase();
        let mut message = Vec::new();
        append_field(&mut message, SUBJECT_DOMAIN)?;
        append_field(&mut message, self.authority.as_bytes())?;
        append_field(&mut message, normalized.as_bytes())?;
        Ok(Self::digest_key(&self.subject_key, &message))
    }

    fn digest(
        &self,
        purpose: SecurityDigestPurpose,
        context: &SecurityCryptoContext,
        payload: &[u8],
    ) -> Result<SecurityDigest, SecurityCryptoError> {
        let key_id = &self.current.key_id;
        let message = self.digest_message(key_id, purpose, context, payload)?;
        let bytes = Self::digest_key(Self::digest_key_for(purpose, &self.current), &message);
        Ok(SecurityDigest {
            key_id: key_id.clone(),
            bytes,
        })
    }

    fn verify_digest(
        &self,
        purpose: SecurityDigestPurpose,
        context: &SecurityCryptoContext,
        payload: &[u8],
        stored: &SecurityDigest,
    ) -> Result<bool, SecurityCryptoError> {
        let keys = self.key_set(&stored.key_id)?;
        let message = self.digest_message(&stored.key_id, purpose, context, payload)?;
        let key = hmac::Key::new(hmac::HMAC_SHA256, Self::digest_key_for(purpose, keys));
        Ok(hmac::verify(&key, &message, &stored.bytes).is_ok())
    }

    fn seal(
        &self,
        purpose: SecurityEnvelopePurpose,
        context: &SecurityCryptoContext,
        plaintext: &SecretString,
    ) -> Result<SecurityEnvelope, SecurityCryptoError> {
        let bytes = plaintext.expose_secret().as_bytes();
        if bytes.len() > MAX_PAYLOAD_BYTES {
            return Err(SecurityCryptoError::InvalidInput);
        }
        validate_context(context)?;
        let key_id = &self.current.key_id;
        let aad = self.envelope_aad(key_id, purpose, context)?;
        let mut nonce = [0_u8; NONCE_BYTES];
        SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| SecurityCryptoError::Unavailable)?;
        let mut ciphertext = bytes.to_vec();
        Self::envelope_key(&self.current.envelope_key)?
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(aad.as_slice()),
                &mut ciphertext,
            )
            .map_err(|_| SecurityCryptoError::Unavailable)?;
        let mut result = Vec::with_capacity(NONCE_BYTES + ciphertext.len());
        result.extend_from_slice(&nonce);
        result.extend_from_slice(&ciphertext);
        Ok(SecurityEnvelope {
            key_id: key_id.clone(),
            ciphertext: result,
        })
    }

    fn open(
        &self,
        purpose: SecurityEnvelopePurpose,
        context: &SecurityCryptoContext,
        envelope: &SecurityEnvelope,
    ) -> Result<SecretString, SecurityCryptoError> {
        if !(NONCE_BYTES + TAG_BYTES..=MAX_ENVELOPE_BYTES).contains(&envelope.ciphertext.len()) {
            return Err(SecurityCryptoError::InvalidCiphertext);
        }
        let keys = self.key_set(&envelope.key_id)?;
        let aad = self.envelope_aad(&envelope.key_id, purpose, context)?;
        let nonce: [u8; NONCE_BYTES] = envelope.ciphertext[..NONCE_BYTES]
            .try_into()
            .expect("ciphertext length checked");
        let mut plaintext = envelope.ciphertext[NONCE_BYTES..].to_vec();
        let opened = Self::envelope_key(&keys.envelope_key)?
            .open_in_place(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(aad.as_slice()),
                &mut plaintext,
            )
            .map_err(|_| SecurityCryptoError::InvalidCiphertext)?;
        let text =
            std::str::from_utf8(opened).map_err(|_| SecurityCryptoError::InvalidCiphertext)?;
        Ok(SecretString::new(text))
    }
}

fn valid_identifier(value: &str, max_len: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_len
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}

fn valid_key_id(value: &str) -> bool {
    valid_identifier(value, 32)
}

fn validate_context(context: &SecurityCryptoContext) -> Result<(), SecurityCryptoError> {
    if context.reference_id.is_nil() || context.related_id.is_some_and(|id| id.is_nil()) {
        Err(SecurityCryptoError::InvalidInput)
    } else {
        Ok(())
    }
}

fn digest_purpose_name(purpose: SecurityDigestPurpose) -> &'static [u8] {
    match purpose {
        SecurityDigestPurpose::RecoveryHandle => b"recovery_handle",
        SecurityDigestPurpose::ReceiptSecret => b"receipt_secret",
        SecurityDigestPurpose::Command => b"command",
        SecurityDigestPurpose::RecoveryCode => b"recovery_code",
    }
}

fn envelope_purpose_name(purpose: SecurityEnvelopePurpose) -> &'static [u8] {
    match purpose {
        SecurityEnvelopePurpose::RecoveryEmail => b"recovery_email",
        SecurityEnvelopePurpose::RecoveryStartReceipt => b"recovery_start_receipt",
    }
}

fn append_related(
    output: &mut Vec<u8>,
    related_id: Option<Uuid>,
) -> Result<(), SecurityCryptoError> {
    match related_id {
        Some(id) => {
            append_field(output, b"1")?;
            append_field(output, id.as_bytes())
        }
        None => append_field(output, b"0"),
    }
}

fn append_field(output: &mut Vec<u8>, field: &[u8]) -> Result<(), SecurityCryptoError> {
    let len = u32::try_from(field.len()).map_err(|_| SecurityCryptoError::InvalidInput)?;
    output.extend_from_slice(&len.to_be_bytes());
    output.extend_from_slice(field);
    Ok(())
}

#[cfg(test)]
#[path = "account_security_tests.rs"]
mod tests;
