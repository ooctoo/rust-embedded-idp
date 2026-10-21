use std::fmt;

use base64ct::{Base64UrlUnpadded, Encoding};
use embedded_idp_core::{
    access::{
        CanonicalRegistrationEmail, RegistrationEmailCrypto, RegistrationEmailError,
        RegistrationEmailOperationKind, RegistrationEmailScope, Uuid,
    },
    SecretString,
};
use rand_core::{OsRng, RngCore};
use ring::{
    aead::{self, Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM},
    hmac,
    rand::{SecureRandom, SystemRandom},
};
use sha2::{Digest, Sha256};

const NONCE_BYTES: usize = 12;
const SUBJECT_DOMAIN: &[u8] = b"embedded-idp/registration-email/subject/v1";
const CONTEXT_DOMAIN: &[u8] = b"embedded-idp/registration-email/context/v1";
const REQUEST_DOMAIN: &[u8] = b"embedded-idp/registration-email/request/v1";
const CODE_DOMAIN: &[u8] = b"embedded-idp/registration-email/code/v1";
const ENVELOPE_DOMAIN: &[u8] = b"embedded-idp/registration-email/envelope/v1";
const CODE_BOUND: u64 = (u32::MAX as u64 + 1) / 1_000_000 * 1_000_000;

/// Ring-backed cryptography for registration email state.
///
/// Each operation has independent key material. Key bytes are retained only in
/// this process and are never exposed through accessors or `Debug`.
#[derive(Clone)]
pub struct RingRegistrationEmailCrypto {
    subject_key: [u8; 32],
    context_key: [u8; 32],
    request_key: [u8; 32],
    code_key: [u8; 32],
    envelope_key: [u8; 32],
}

impl RingRegistrationEmailCrypto {
    pub fn new(
        subject_key: [u8; 32],
        context_key: [u8; 32],
        request_key: [u8; 32],
        code_key: [u8; 32],
        envelope_key: [u8; 32],
    ) -> Result<Self, RegistrationEmailError> {
        let keys = [
            &subject_key,
            &context_key,
            &request_key,
            &code_key,
            &envelope_key,
        ];
        if keys.iter().any(|key| key.iter().all(|byte| *byte == 0)) {
            return Err(RegistrationEmailError::InvalidInput("key_material"));
        }
        for (index, key) in keys.iter().enumerate() {
            if keys[..index].iter().any(|other| other == key) {
                return Err(RegistrationEmailError::InvalidInput("key_material"));
            }
        }
        Ok(Self {
            subject_key,
            context_key,
            request_key,
            code_key,
            envelope_key,
        })
    }

    fn digest(key: &[u8; 32], message: &[u8]) -> [u8; 32] {
        let key = hmac::Key::new(hmac::HMAC_SHA256, key);
        hmac::sign(&key, message)
            .as_ref()
            .try_into()
            .expect("HMAC-SHA256 has 32 bytes")
    }

    fn scoped_message(domain: &[u8], scope: &RegistrationEmailScope) -> Vec<u8> {
        let mut message = Vec::new();
        append_field(&mut message, domain);
        append_field(&mut message, scope.authority.as_bytes());
        append_field(&mut message, scope.product.as_bytes());
        append_field(&mut message, scope.tenant.as_bytes());
        append_field(&mut message, mode_bytes(scope));
        message
    }

    fn envelope_aad(scope: &RegistrationEmailScope, context: &Uuid, purpose: &str) -> Vec<u8> {
        let mut aad = Self::scoped_message(ENVELOPE_DOMAIN, scope);
        append_field(&mut aad, context.as_bytes());
        append_field(&mut aad, purpose.as_bytes());
        aad
    }

    fn envelope_key(&self) -> Result<LessSafeKey, RegistrationEmailError> {
        let key = UnboundKey::new(&AES_256_GCM, &self.envelope_key)
            .map_err(|_| RegistrationEmailError::Unavailable)?;
        Ok(LessSafeKey::new(key))
    }
}

impl fmt::Debug for RingRegistrationEmailCrypto {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RingRegistrationEmailCrypto")
            .field("subject_key", &"[REDACTED]")
            .field("context_key", &"[REDACTED]")
            .field("request_key", &"[REDACTED]")
            .field("code_key", &"[REDACTED]")
            .field("envelope_key", &"[REDACTED]")
            .finish()
    }
}

impl RegistrationEmailCrypto for RingRegistrationEmailCrypto {
    fn subject(
        &self,
        scope: &RegistrationEmailScope,
        email: &CanonicalRegistrationEmail,
    ) -> [u8; 32] {
        let mut message = Vec::new();
        append_field(&mut message, SUBJECT_DOMAIN);
        append_field(&mut message, scope.authority.as_bytes());
        append_field(&mut message, email.abuse_identity().as_bytes());
        Self::digest(&self.subject_key, &message)
    }

    fn random_seed(&self) -> Result<[u8; 32], RegistrationEmailError> {
        let mut seed = [0_u8; 32];
        OsRng
            .try_fill_bytes(&mut seed)
            .map_err(|_| RegistrationEmailError::Unavailable)?;
        Ok(seed)
    }

    fn context_token(&self, scope: &RegistrationEmailScope, seed: &[u8; 32]) -> SecretString {
        let mut message = Self::scoped_message(CONTEXT_DOMAIN, scope);
        append_field(&mut message, seed);
        SecretString::new(Base64UrlUnpadded::encode_string(&Self::digest(
            &self.context_key,
            &message,
        )))
    }

    fn context_digest(&self, token: &str) -> [u8; 32] {
        Sha256::digest(token.as_bytes()).into()
    }

    fn request_digest(
        &self,
        scope: &RegistrationEmailScope,
        kind: RegistrationEmailOperationKind,
        operation: &Uuid,
        payload: &[u8],
    ) -> [u8; 32] {
        let mut message = Self::scoped_message(REQUEST_DOMAIN, scope);
        append_field(&mut message, kind.as_str().as_bytes());
        append_field(&mut message, operation.as_bytes());
        append_field(&mut message, payload);
        Self::digest(&self.request_key, &message)
    }

    fn code_digest(&self, scope: &RegistrationEmailScope, context: &Uuid, code: &str) -> [u8; 32] {
        let mut message = Self::scoped_message(CODE_DOMAIN, scope);
        append_field(&mut message, context.as_bytes());
        append_field(&mut message, code.as_bytes());
        Self::digest(&self.code_key, &message)
    }

    fn digests_equal(&self, left: &[u8], right: &[u8]) -> bool {
        // ring performs the comparison; avoid a compiler-optimizable local byte loop.
        let key = hmac::Key::new(hmac::HMAC_SHA256, &self.code_key);
        let tag = hmac::sign(&key, left);
        hmac::verify(&key, right, tag.as_ref()).is_ok()
    }

    fn seal(
        &self,
        purpose: &str,
        scope: &RegistrationEmailScope,
        context: &Uuid,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, RegistrationEmailError> {
        let aad = Self::envelope_aad(scope, context, purpose);
        let mut nonce = [0_u8; NONCE_BYTES];
        SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| RegistrationEmailError::Unavailable)?;
        let mut ciphertext = plaintext.to_vec();
        self.envelope_key()?
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(aad.as_slice()),
                &mut ciphertext,
            )
            .map_err(|_| RegistrationEmailError::Unavailable)?;
        let mut result = Vec::with_capacity(NONCE_BYTES + ciphertext.len());
        result.extend_from_slice(&nonce);
        result.extend_from_slice(&ciphertext);
        Ok(result)
    }

    fn open(
        &self,
        purpose: &str,
        scope: &RegistrationEmailScope,
        context: &Uuid,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, RegistrationEmailError> {
        if ciphertext.len() < NONCE_BYTES + aead::MAX_TAG_LEN {
            return Err(RegistrationEmailError::Unavailable);
        }
        let nonce: [u8; NONCE_BYTES] = ciphertext[..NONCE_BYTES]
            .try_into()
            .expect("slice length is checked above");
        let aad = Self::envelope_aad(scope, context, purpose);
        let mut plaintext = ciphertext[NONCE_BYTES..].to_vec();
        let plaintext = self
            .envelope_key()?
            .open_in_place(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(aad.as_slice()),
                &mut plaintext,
            )
            .map_err(|_| RegistrationEmailError::Unavailable)?;
        Ok(plaintext.to_vec())
    }

    fn random_code(&self) -> Result<SecretString, RegistrationEmailError> {
        for _ in 0..8 {
            let mut bytes = [0_u8; 4];
            OsRng
                .try_fill_bytes(&mut bytes)
                .map_err(|_| RegistrationEmailError::Unavailable)?;
            let value = u32::from_be_bytes(bytes) as u64;
            if value < CODE_BOUND {
                return Ok(SecretString::new(format!("{:06}", value % 1_000_000)));
            }
        }
        Err(RegistrationEmailError::Unavailable)
    }
}

fn append_field(output: &mut Vec<u8>, field: &[u8]) {
    output.extend_from_slice(&(field.len() as u64).to_be_bytes());
    output.extend_from_slice(field);
}

fn mode_bytes(scope: &RegistrationEmailScope) -> &'static [u8] {
    match scope.mode {
        embedded_idp_core::access::TenancyMode::Disabled => b"disabled",
        embedded_idp_core::access::TenancyMode::Enabled => b"enabled",
    }
}

#[cfg(test)]
mod tests;
