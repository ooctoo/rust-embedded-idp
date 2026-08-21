use std::time::{Duration, SystemTime};

use crate::{
    build_request_proof_bytes, digest_device_challenge, next_refresh_token_version,
    AccessTokenIssuer, Account, AccountDeviceBinding, AccountDeviceBindingStatus, AccountStatus,
    AuthSession, Clock, DeviceProofChallengeRecord, DeviceProofKeyRecord, DeviceProofKeyStatus,
    DeviceProofPresentation, DevicePublicJwkParser, DeviceRecord, DeviceRequestBinding,
    DeviceSignatureVerifier, DeviceStatus, IdGenerator, IssuedAccessToken, RefreshTokenDigester,
    RefreshTokenGenerator, RefreshTokenRecord, RefreshTokenRevocationReason, SecretString,
    SecurityContractError, SessionStatus, StoreError, TokenError, REFRESH_PURPOSE,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RotateProofBoundRefreshCommand {
    pub refresh_token: SecretString,
    pub proof: DeviceProofPresentation,
    pub binding: DeviceRequestBinding,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofBoundTokenResult {
    pub access_token: IssuedAccessToken,
    pub refresh_token: SecretString,
    pub refresh_expires_at: SystemTime,
    pub refresh_token_version: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
// This result crosses the service boundary once per refresh request. Keeping
// the success data inline makes the committed outcome explicit and avoids
// shaping the public API around an allocation-only optimization.
#[allow(clippy::large_enum_variant)]
pub enum RotateProofBoundRefreshOutcome {
    Rotated {
        session: AuthSession,
        tokens: ProofBoundTokenResult,
    },
    ReuseDetected {
        session_id: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProofBoundRefreshError {
    InvalidToken,
    InvalidProof,
    ExpiredProof,
    ReplayedProof,
    DeviceKeyMismatch,
    DeviceMismatch,
    DeviceInactive,
    BindingInactive,
    SessionInactive,
    AccountInactive,
    Store(StoreError),
    Token(TokenError),
}

pub trait ProofBoundRefreshService: Send + Sync {
    fn rotate_proof_bound_refresh(
        &self,
        command: RotateProofBoundRefreshCommand,
    ) -> Result<RotateProofBoundRefreshOutcome, ProofBoundRefreshError>;
}

pub trait ProofBoundRefreshTransaction {
    fn lock_refresh_token(
        &mut self,
        digest: &[u8; 32],
    ) -> Result<Option<RefreshTokenRecord>, StoreError>;
    fn lock_session(&mut self, session_id: &str) -> Result<Option<AuthSession>, StoreError>;
    fn lock_account(&mut self, account_id: &str) -> Result<Option<Account>, StoreError>;
    fn lock_device(&mut self, device_id: &str) -> Result<Option<DeviceRecord>, StoreError>;
    fn lock_device_key(&mut self, key_id: &str)
        -> Result<Option<DeviceProofKeyRecord>, StoreError>;
    fn lock_active_binding(
        &mut self,
        account_id: &str,
        device_id: &str,
    ) -> Result<Option<AccountDeviceBinding>, StoreError>;
    fn lock_challenge(
        &mut self,
        digest: &[u8; 32],
    ) -> Result<Option<DeviceProofChallengeRecord>, StoreError>;
    fn consume_challenge_if_active(
        &mut self,
        digest: &[u8; 32],
        observed_at: SystemTime,
    ) -> Result<bool, StoreError>;
    fn update_session(&mut self, session: AuthSession) -> Result<AuthSession, StoreError>;
    fn revoke_refresh_token(
        &mut self,
        digest: &[u8; 32],
        reason: RefreshTokenRevocationReason,
        revoked_at: SystemTime,
    ) -> Result<(), StoreError>;
    fn insert_refresh_token(&mut self, token: RefreshTokenRecord) -> Result<(), StoreError>;
    fn revoke_refresh_family(
        &mut self,
        session_id: &str,
        reason: RefreshTokenRevocationReason,
        revoked_at: SystemTime,
    ) -> Result<(), StoreError>;
}

pub trait ProofBoundRefreshTransactionRunner {
    type Transaction<'a>: ProofBoundRefreshTransaction
    where
        Self: 'a;

    fn proof_bound_refresh_transaction<R>(
        &self,
        run: impl FnOnce(&mut Self::Transaction<'_>) -> Result<R, ProofBoundRefreshError>,
    ) -> Result<R, ProofBoundRefreshError>;
}

pub struct CoreProofBoundRefreshService<S, D, G, V, J, A, K, I> {
    store_runner: S,
    digester: D,
    generator: G,
    signature_verifier: V,
    jwk_parser: J,
    access_token_issuer: A,
    clock: K,
    id_generator: I,
    refresh_token_ttl_secs: u64,
    proof_clock_skew_secs: u64,
}

impl<S, D, G, V, J, A, K, I> CoreProofBoundRefreshService<S, D, G, V, J, A, K, I> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        store_runner: S,
        digester: D,
        generator: G,
        signature_verifier: V,
        jwk_parser: J,
        access_token_issuer: A,
        clock: K,
        id_generator: I,
        refresh_token_ttl_secs: u64,
        proof_clock_skew_secs: u64,
    ) -> Self {
        Self {
            store_runner,
            digester,
            generator,
            signature_verifier,
            jwk_parser,
            access_token_issuer,
            clock,
            id_generator,
            refresh_token_ttl_secs,
            proof_clock_skew_secs,
        }
    }
}

impl<S, D, G, V, J, A, K, I> ProofBoundRefreshService
    for CoreProofBoundRefreshService<S, D, G, V, J, A, K, I>
where
    S: ProofBoundRefreshTransactionRunner + Send + Sync,
    D: RefreshTokenDigester + Send + Sync,
    G: RefreshTokenGenerator + Send + Sync,
    V: DeviceSignatureVerifier + Send + Sync,
    J: DevicePublicJwkParser + Send + Sync,
    A: AccessTokenIssuer + Send + Sync,
    K: Clock + Send + Sync,
    I: IdGenerator + Send + Sync,
{
    fn rotate_proof_bound_refresh(
        &self,
        command: RotateProofBoundRefreshCommand,
    ) -> Result<RotateProofBoundRefreshOutcome, ProofBoundRefreshError> {
        command
            .proof
            .validate()
            .map_err(map_security_contract_error)?;
        let observed_at = self.clock.now();
        let token_digest = self
            .digester
            .digest_refresh_token(command.refresh_token.expose_secret())
            .map_err(ProofBoundRefreshError::Token)?;
        let challenge_digest = digest_device_challenge(&command.proof.challenge)
            .map_err(map_security_contract_error)?;

        self.store_runner.proof_bound_refresh_transaction(|tx| {
            let refresh = tx
                .lock_refresh_token(&token_digest)
                .map_err(ProofBoundRefreshError::Store)?
                .ok_or(ProofBoundRefreshError::InvalidToken)?;
            let mut session = tx
                .lock_session(&refresh.session_id)
                .map_err(ProofBoundRefreshError::Store)?
                .ok_or(ProofBoundRefreshError::InvalidToken)?;
            if session.status != SessionStatus::Active || session.expires_at <= observed_at {
                return Err(ProofBoundRefreshError::SessionInactive);
            }
            let account = tx
                .lock_account(&session.account_id)
                .map_err(ProofBoundRefreshError::Store)?
                .ok_or(ProofBoundRefreshError::InvalidToken)?;
            if account.status != AccountStatus::Active {
                return Err(ProofBoundRefreshError::AccountInactive);
            }

            verify_device_proof(
                tx,
                &command,
                &account,
                &challenge_digest,
                observed_at,
                self.proof_clock_skew_secs,
                &self.jwk_parser,
                &self.signature_verifier,
            )?;
            if session.device_id.as_deref() != Some(command.proof.device_id.as_str()) {
                return Err(ProofBoundRefreshError::DeviceMismatch);
            }

            let confirmed_reuse = refresh.revocation_reason
                == Some(RefreshTokenRevocationReason::Rotated)
                && refresh.token_version < session.refresh_token_version;
            if refresh.revoked_at.is_some() && !confirmed_reuse {
                return Err(ProofBoundRefreshError::InvalidToken);
            }
            if refresh.expires_at <= observed_at {
                return Err(ProofBoundRefreshError::InvalidToken);
            }

            if confirmed_reuse {
                consume_challenge(tx, &challenge_digest, observed_at)?;
                session.status = SessionStatus::Revoked;
                tx.update_session(session.clone())
                    .map_err(ProofBoundRefreshError::Store)?;
                tx.revoke_refresh_family(
                    &session.id,
                    RefreshTokenRevocationReason::ReuseDetected,
                    observed_at,
                )
                .map_err(ProofBoundRefreshError::Store)?;
                return Ok(RotateProofBoundRefreshOutcome::ReuseDetected {
                    session_id: session.id,
                });
            }

            if refresh.token_version != session.refresh_token_version {
                return Err(ProofBoundRefreshError::InvalidToken);
            }
            let next_version =
                next_refresh_token_version(session.refresh_token_version, refresh.token_version)
                    .map_err(ProofBoundRefreshError::Token)?;
            let next_raw = self
                .generator
                .generate_refresh_token()
                .map_err(ProofBoundRefreshError::Token)?;
            let next_digest = self
                .digester
                .digest_refresh_token(next_raw.expose_secret())
                .map_err(ProofBoundRefreshError::Token)?;
            let access_token = self
                .access_token_issuer
                .issue_access_token(
                    &session.id,
                    &session.account_id,
                    &session.client_id,
                    observed_at,
                )
                .map_err(ProofBoundRefreshError::Token)?;
            let requested_refresh_expiry = observed_at
                .checked_add(Duration::from_secs(self.refresh_token_ttl_secs))
                .ok_or_else(|| {
                    ProofBoundRefreshError::Token(TokenError::IssuerRejected(
                        "refresh expiry overflow".to_string(),
                    ))
                })?;
            let refresh_expires_at = std::cmp::min(requested_refresh_expiry, session.expires_at);

            consume_challenge(tx, &challenge_digest, observed_at)?;
            session.refresh_token_version = next_version;
            let session = tx
                .update_session(session)
                .map_err(ProofBoundRefreshError::Store)?;
            tx.revoke_refresh_token(
                &token_digest,
                RefreshTokenRevocationReason::Rotated,
                observed_at,
            )
            .map_err(ProofBoundRefreshError::Store)?;
            tx.insert_refresh_token(RefreshTokenRecord {
                id: self.id_generator.next_id("rtok"),
                session_id: session.id.clone(),
                token_digest: next_digest,
                token_version: next_version,
                issued_at: observed_at,
                expires_at: refresh_expires_at,
                revoked_at: None,
                revocation_reason: None,
            })
            .map_err(ProofBoundRefreshError::Store)?;

            Ok(RotateProofBoundRefreshOutcome::Rotated {
                session,
                tokens: ProofBoundTokenResult {
                    access_token,
                    refresh_token: next_raw,
                    refresh_expires_at,
                    refresh_token_version: next_version,
                },
            })
        })
    }
}

#[allow(clippy::too_many_arguments)]
fn verify_device_proof<T, J, V>(
    tx: &mut T,
    command: &RotateProofBoundRefreshCommand,
    account: &Account,
    challenge_digest: &[u8; 32],
    observed_at: SystemTime,
    proof_clock_skew_secs: u64,
    jwk_parser: &J,
    signature_verifier: &V,
) -> Result<(), ProofBoundRefreshError>
where
    T: ProofBoundRefreshTransaction,
    J: DevicePublicJwkParser,
    V: DeviceSignatureVerifier,
{
    let device = tx
        .lock_device(&command.proof.device_id)
        .map_err(ProofBoundRefreshError::Store)?
        .ok_or(ProofBoundRefreshError::InvalidProof)?;
    let key = tx
        .lock_device_key(&command.proof.key_id)
        .map_err(ProofBoundRefreshError::Store)?
        .ok_or(ProofBoundRefreshError::InvalidProof)?;
    if key.device_id != device.id {
        return Err(ProofBoundRefreshError::InvalidProof);
    }
    let binding = tx
        .lock_active_binding(&account.id, &device.id)
        .map_err(ProofBoundRefreshError::Store)?;
    let challenge = tx
        .lock_challenge(challenge_digest)
        .map_err(ProofBoundRefreshError::Store)?
        .ok_or(ProofBoundRefreshError::InvalidProof)?;
    if challenge.device_id != device.id || challenge.purpose.as_str() != REFRESH_PURPOSE {
        return Err(ProofBoundRefreshError::InvalidProof);
    }
    crate::validate_proof_freshness(command.proof.signed_at, observed_at, proof_clock_skew_secs)
        .map_err(|_| ProofBoundRefreshError::ExpiredProof)?;
    let public_key = jwk_parser
        .parse_ed25519_public_key(&key.public_jwk)
        .map_err(map_security_contract_error)?;
    let canonical = build_request_proof_bytes(&command.binding, &command.proof)
        .map_err(map_security_contract_error)?;
    let signature = command
        .proof
        .signature_bytes()
        .map_err(map_security_contract_error)?;
    signature_verifier
        .verify_ed25519(&public_key, &canonical, &signature)
        .map_err(map_security_contract_error)?;

    // Relationship and replay details are only safe to disclose after the
    // presented key has authenticated the device context.
    if device.status != DeviceStatus::Active {
        return Err(ProofBoundRefreshError::DeviceInactive);
    }
    if key.status != DeviceProofKeyStatus::Active
        || device.proof_key_id.as_deref() != Some(key.key_id.as_str())
    {
        return Err(ProofBoundRefreshError::DeviceKeyMismatch);
    }
    if binding
        .as_ref()
        .is_none_or(|binding| binding.status != AccountDeviceBindingStatus::Active)
    {
        return Err(ProofBoundRefreshError::BindingInactive);
    }
    if challenge.expires_at <= observed_at {
        return Err(ProofBoundRefreshError::ExpiredProof);
    }
    if challenge.consumed_at.is_some() {
        return Err(ProofBoundRefreshError::ReplayedProof);
    }
    Ok(())
}

fn consume_challenge<T: ProofBoundRefreshTransaction>(
    tx: &mut T,
    digest: &[u8; 32],
    observed_at: SystemTime,
) -> Result<(), ProofBoundRefreshError> {
    if !tx
        .consume_challenge_if_active(digest, observed_at)
        .map_err(ProofBoundRefreshError::Store)?
    {
        return Err(ProofBoundRefreshError::ReplayedProof);
    }
    Ok(())
}

fn map_security_contract_error(error: SecurityContractError) -> ProofBoundRefreshError {
    match error {
        SecurityContractError::InvalidSignedAt => ProofBoundRefreshError::ExpiredProof,
        _ => ProofBoundRefreshError::InvalidProof,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Mutex;
    use std::time::{Duration, UNIX_EPOCH};

    use base64ct::{Base64UrlUnpadded, Encoding};

    use super::*;
    use crate::{
        CanonicalHttpMethod, DeviceProofAlgorithm, DeviceProofProfile, DeviceProofPurpose,
    };

    #[derive(Clone)]
    struct TestState {
        accounts: HashMap<String, Account>,
        sessions: HashMap<String, AuthSession>,
        devices: HashMap<String, DeviceRecord>,
        keys: HashMap<String, DeviceProofKeyRecord>,
        bindings: HashMap<(String, String), AccountDeviceBinding>,
        challenges: HashMap<[u8; 32], DeviceProofChallengeRecord>,
        refresh_tokens: HashMap<[u8; 32], RefreshTokenRecord>,
    }

    struct TestRunner {
        state: Mutex<TestState>,
    }

    struct TestTx<'a> {
        state: &'a mut TestState,
    }

    impl ProofBoundRefreshTransactionRunner for TestRunner {
        type Transaction<'a> = TestTx<'a>;

        fn proof_bound_refresh_transaction<R>(
            &self,
            run: impl FnOnce(&mut Self::Transaction<'_>) -> Result<R, ProofBoundRefreshError>,
        ) -> Result<R, ProofBoundRefreshError> {
            let mut guard = self.state.lock().unwrap();
            let mut working = guard.clone();
            let result = run(&mut TestTx {
                state: &mut working,
            });
            if result.is_ok() {
                *guard = working;
            }
            result
        }
    }

    impl ProofBoundRefreshTransaction for TestTx<'_> {
        fn lock_refresh_token(
            &mut self,
            digest: &[u8; 32],
        ) -> Result<Option<RefreshTokenRecord>, StoreError> {
            Ok(self.state.refresh_tokens.get(digest).cloned())
        }

        fn lock_session(&mut self, session_id: &str) -> Result<Option<AuthSession>, StoreError> {
            Ok(self.state.sessions.get(session_id).cloned())
        }

        fn lock_account(&mut self, account_id: &str) -> Result<Option<Account>, StoreError> {
            Ok(self.state.accounts.get(account_id).cloned())
        }

        fn lock_device(&mut self, device_id: &str) -> Result<Option<DeviceRecord>, StoreError> {
            Ok(self.state.devices.get(device_id).cloned())
        }

        fn lock_device_key(
            &mut self,
            key_id: &str,
        ) -> Result<Option<DeviceProofKeyRecord>, StoreError> {
            Ok(self.state.keys.get(key_id).cloned())
        }

        fn lock_active_binding(
            &mut self,
            account_id: &str,
            device_id: &str,
        ) -> Result<Option<AccountDeviceBinding>, StoreError> {
            Ok(self
                .state
                .bindings
                .get(&(account_id.to_string(), device_id.to_string()))
                .cloned())
        }

        fn lock_challenge(
            &mut self,
            digest: &[u8; 32],
        ) -> Result<Option<DeviceProofChallengeRecord>, StoreError> {
            Ok(self.state.challenges.get(digest).cloned())
        }

        fn consume_challenge_if_active(
            &mut self,
            digest: &[u8; 32],
            observed_at: SystemTime,
        ) -> Result<bool, StoreError> {
            let Some(challenge) = self.state.challenges.get_mut(digest) else {
                return Ok(false);
            };
            if challenge.consumed_at.is_some() || challenge.expires_at <= observed_at {
                return Ok(false);
            }
            challenge.consumed_at = Some(observed_at);
            Ok(true)
        }

        fn update_session(&mut self, session: AuthSession) -> Result<AuthSession, StoreError> {
            self.state
                .sessions
                .insert(session.id.clone(), session.clone());
            Ok(session)
        }

        fn revoke_refresh_token(
            &mut self,
            digest: &[u8; 32],
            reason: RefreshTokenRevocationReason,
            revoked_at: SystemTime,
        ) -> Result<(), StoreError> {
            let token = self.state.refresh_tokens.get_mut(digest).unwrap();
            token.revoked_at = Some(revoked_at);
            token.revocation_reason = Some(reason);
            Ok(())
        }

        fn insert_refresh_token(&mut self, token: RefreshTokenRecord) -> Result<(), StoreError> {
            self.state.refresh_tokens.insert(token.token_digest, token);
            Ok(())
        }

        fn revoke_refresh_family(
            &mut self,
            session_id: &str,
            reason: RefreshTokenRevocationReason,
            revoked_at: SystemTime,
        ) -> Result<(), StoreError> {
            for token in self.state.refresh_tokens.values_mut() {
                if token.session_id == session_id && token.revoked_at.is_none() {
                    token.revoked_at = Some(revoked_at);
                    token.revocation_reason = Some(reason);
                }
            }
            Ok(())
        }
    }

    struct TestClock;
    impl Clock for TestClock {
        fn now(&self) -> SystemTime {
            UNIX_EPOCH + Duration::from_secs(1_700_000_000)
        }
    }

    struct TestDigester;
    impl RefreshTokenDigester for TestDigester {
        fn digest_refresh_token(&self, raw_token: &str) -> Result<[u8; 32], TokenError> {
            Ok(crate::digest_refresh_token(raw_token))
        }
    }

    struct TestGenerator;
    impl RefreshTokenGenerator for TestGenerator {
        fn generate_refresh_token(&self) -> Result<SecretString, TokenError> {
            Ok(SecretString::new(Base64UrlUnpadded::encode_string(
                &[8_u8; 32],
            )))
        }
    }

    struct TestVerifier {
        accepts: bool,
    }
    impl DeviceSignatureVerifier for TestVerifier {
        fn verify_ed25519(
            &self,
            _public_key: &[u8; 32],
            _message: &[u8],
            _signature: &[u8; 64],
        ) -> Result<(), SecurityContractError> {
            self.accepts
                .then_some(())
                .ok_or(SecurityContractError::InvalidSignature)
        }
    }

    struct TestJwkParser;
    impl DevicePublicJwkParser for TestJwkParser {
        fn parse_ed25519_public_key(
            &self,
            _canonical_public_jwk: &str,
        ) -> Result<[u8; 32], SecurityContractError> {
            Ok([7_u8; 32])
        }
    }

    struct TestAccessIssuer;
    impl AccessTokenIssuer for TestAccessIssuer {
        fn issue_access_token(
            &self,
            _session_id: &str,
            _account_id: &str,
            _client_id: &str,
            issued_at: SystemTime,
        ) -> Result<IssuedAccessToken, TokenError> {
            Ok(IssuedAccessToken {
                token: SecretString::new("signed-access-token"),
                expires_at: issued_at + Duration::from_secs(900),
            })
        }
    }

    struct TestIds;
    impl IdGenerator for TestIds {
        fn next_id(&self, prefix: &str) -> String {
            format!("{prefix}-next")
        }
    }

    type Service = CoreProofBoundRefreshService<
        TestRunner,
        TestDigester,
        TestGenerator,
        TestVerifier,
        TestJwkParser,
        TestAccessIssuer,
        TestClock,
        TestIds,
    >;

    fn service(accepts_signature: bool, reused: bool) -> Service {
        let now = TestClock.now();
        let old_raw = raw_token(4);
        let old_digest = crate::digest_refresh_token(&old_raw);
        let challenge = raw_token(2);
        let challenge_digest = digest_device_challenge(&challenge).unwrap();
        let key_id = raw_token(1);
        let mut refresh_tokens = HashMap::new();
        refresh_tokens.insert(
            old_digest,
            RefreshTokenRecord {
                id: "rtok-old".to_string(),
                session_id: "session-1".to_string(),
                token_digest: old_digest,
                token_version: 0,
                issued_at: now - Duration::from_secs(60),
                expires_at: now + Duration::from_secs(3_600),
                revoked_at: reused.then_some(now - Duration::from_secs(1)),
                revocation_reason: reused.then_some(RefreshTokenRevocationReason::Rotated),
            },
        );
        if reused {
            let active_digest = crate::digest_refresh_token(&raw_token(5));
            refresh_tokens.insert(
                active_digest,
                RefreshTokenRecord {
                    id: "rtok-active".to_string(),
                    session_id: "session-1".to_string(),
                    token_digest: active_digest,
                    token_version: 1,
                    issued_at: now,
                    expires_at: now + Duration::from_secs(3_600),
                    revoked_at: None,
                    revocation_reason: None,
                },
            );
        }
        let state = TestState {
            accounts: HashMap::from([(
                "account-1".to_string(),
                Account {
                    id: "account-1".to_string(),
                    email: "user@example.com".to_string(),
                    password_hash: "hash".to_string(),
                    display_name: None,
                    status: AccountStatus::Active,
                    created_at: now,
                },
            )]),
            sessions: HashMap::from([(
                "session-1".to_string(),
                AuthSession {
                    id: "session-1".to_string(),
                    account_id: "account-1".to_string(),
                    client_id: "desktop-app".to_string(),
                    device_id: Some("device-1".to_string()),
                    status: SessionStatus::Active,
                    created_at: now,
                    expires_at: now + Duration::from_secs(7_200),
                    refresh_token_version: u64::from(reused),
                },
            )]),
            devices: HashMap::from([(
                "device-1".to_string(),
                DeviceRecord {
                    id: "device-1".to_string(),
                    client_id: "desktop-app".to_string(),
                    device_name: "Laptop".to_string(),
                    proof_key_id: Some(key_id.clone()),
                    status: DeviceStatus::Active,
                    registered_at: now,
                    last_seen_at: Some(now),
                },
            )]),
            keys: HashMap::from([(
                key_id.clone(),
                DeviceProofKeyRecord {
                    key_id,
                    device_id: "device-1".to_string(),
                    algorithm: DeviceProofAlgorithm::Ed25519,
                    public_jwk: "validated-jwk".to_string(),
                    version: 1,
                    status: DeviceProofKeyStatus::Active,
                    registered_at: now,
                    retired_at: None,
                },
            )]),
            bindings: HashMap::from([(
                ("account-1".to_string(), "device-1".to_string()),
                AccountDeviceBinding {
                    id: "binding-1".to_string(),
                    account_id: "account-1".to_string(),
                    device_id: "device-1".to_string(),
                    status: AccountDeviceBindingStatus::Active,
                    bound_at: now,
                    unbound_at: None,
                    last_authenticated_at: Some(now),
                },
            )]),
            challenges: HashMap::from([(
                challenge_digest,
                DeviceProofChallengeRecord {
                    id: "challenge-1".to_string(),
                    device_id: "device-1".to_string(),
                    purpose: DeviceProofPurpose::new(REFRESH_PURPOSE).unwrap(),
                    challenge_digest,
                    issued_at: now - Duration::from_secs(5),
                    expires_at: now + Duration::from_secs(60),
                    consumed_at: None,
                },
            )]),
            refresh_tokens,
        };
        CoreProofBoundRefreshService::new(
            TestRunner {
                state: Mutex::new(state),
            },
            TestDigester,
            TestGenerator,
            TestVerifier {
                accepts: accepts_signature,
            },
            TestJwkParser,
            TestAccessIssuer,
            TestClock,
            TestIds,
            3_600,
            30,
        )
    }

    fn command() -> RotateProofBoundRefreshCommand {
        RotateProofBoundRefreshCommand {
            refresh_token: SecretString::new(raw_token(4)),
            proof: DeviceProofPresentation {
                device_id: "device-1".to_string(),
                key_id: raw_token(1),
                challenge: raw_token(2),
                signature: Base64UrlUnpadded::encode_string(&[3_u8; 64]),
                signed_at: TestClock.now(),
            },
            binding: DeviceRequestBinding::new(
                DeviceProofProfile::new("SUT-DEVICE-PROOF-V1").unwrap(),
                "sut-api",
                CanonicalHttpMethod::Post,
                "/api/auth/refresh",
                [0_u8; 32],
            )
            .unwrap(),
        }
    }

    fn raw_token(byte: u8) -> String {
        Base64UrlUnpadded::encode_string(&[byte; 32])
    }

    #[test]
    fn successful_refresh_rotates_digest_and_consumes_challenge_atomically() {
        let service = service(true, false);
        let outcome = service.rotate_proof_bound_refresh(command()).unwrap();

        let RotateProofBoundRefreshOutcome::Rotated { session, tokens } = outcome else {
            panic!("expected rotation");
        };
        assert_eq!(session.refresh_token_version, 1);
        assert_eq!(tokens.refresh_token_version, 1);
        let state = service.store_runner.state.lock().unwrap();
        assert_eq!(
            state
                .refresh_tokens
                .get(&crate::digest_refresh_token(&raw_token(4)))
                .unwrap()
                .revocation_reason,
            Some(RefreshTokenRevocationReason::Rotated)
        );
        assert!(state
            .refresh_tokens
            .contains_key(&crate::digest_refresh_token(
                tokens.refresh_token.expose_secret()
            )));
        assert!(state
            .challenges
            .values()
            .all(|challenge| challenge.consumed_at.is_some()));
    }

    #[test]
    fn confirmed_reuse_commits_family_revocation() {
        let service = service(true, true);
        let outcome = service.rotate_proof_bound_refresh(command()).unwrap();

        assert_eq!(
            outcome,
            RotateProofBoundRefreshOutcome::ReuseDetected {
                session_id: "session-1".to_string()
            }
        );
        let state = service.store_runner.state.lock().unwrap();
        assert_eq!(state.sessions["session-1"].status, SessionStatus::Revoked);
        assert!(state
            .refresh_tokens
            .values()
            .all(|token| token.revoked_at.is_some()));
        assert!(state
            .refresh_tokens
            .values()
            .filter(|token| token.token_version == 1)
            .all(|token| token.revocation_reason
                == Some(RefreshTokenRevocationReason::ReuseDetected)));
    }

    #[test]
    fn invalid_proof_cannot_turn_old_token_into_family_revocation() {
        let service = service(false, true);
        assert_eq!(
            service.rotate_proof_bound_refresh(command()),
            Err(ProofBoundRefreshError::InvalidProof)
        );

        let state = service.store_runner.state.lock().unwrap();
        assert_eq!(state.sessions["session-1"].status, SessionStatus::Active);
        assert!(state
            .refresh_tokens
            .values()
            .any(|token| token.token_version == 1 && token.revoked_at.is_none()));
        assert!(state
            .challenges
            .values()
            .all(|challenge| challenge.consumed_at.is_none()));
    }

    #[test]
    fn invalid_signature_cannot_enumerate_device_binding_or_replay_state() {
        let service = service(false, false);
        {
            let mut state = service.store_runner.state.lock().unwrap();
            state.devices.get_mut("device-1").unwrap().status = DeviceStatus::Disabled;
            state
                .bindings
                .get_mut(&("account-1".to_string(), "device-1".to_string()))
                .unwrap()
                .status = AccountDeviceBindingStatus::Suspended;
            state.challenges.values_mut().next().unwrap().consumed_at = Some(TestClock.now());
        }

        assert_eq!(
            service.rotate_proof_bound_refresh(command()),
            Err(ProofBoundRefreshError::InvalidProof)
        );
    }

    #[test]
    fn active_key_must_match_the_device_current_key_pointer() {
        let service = service(true, false);
        service
            .store_runner
            .state
            .lock()
            .unwrap()
            .devices
            .get_mut("device-1")
            .unwrap()
            .proof_key_id = Some(raw_token(9));

        assert_eq!(
            service.rotate_proof_bound_refresh(command()),
            Err(ProofBoundRefreshError::DeviceKeyMismatch)
        );
    }
}
