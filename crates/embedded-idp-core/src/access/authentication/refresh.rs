use super::*;
use crate::{
    next_refresh_token_version, DeviceChallengeGenerator, DeviceProofPurpose,
    DevicePublicJwkValidator, DeviceRequestVerificationError, DeviceSignatureVerifier,
    ProofBoundTokenResult, RefreshTokenRevocationReason, RotateProofBoundRefreshCommand,
    ScopedAccessTokenIssuer, REFRESH_PURPOSE,
};

/// Digest-only persistence record. The raw credential exists only at the boundary.
#[derive(Clone, PartialEq, Eq)]
pub struct TenantRefreshRecord {
    pub tenant_id: String,
    pub id: String,
    pub session_id: String,
    pub token_digest: [u8; 32],
    pub token_version: u64,
    pub issued_at: SystemTime,
    pub expires_at: SystemTime,
    pub revoked_at: Option<SystemTime>,
    pub revocation_reason: Option<RefreshTokenRevocationReason>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum TenantRefreshOutcome {
    Rotated {
        session: TenantSession,
        tokens: ProofBoundTokenResult,
    },
    /// A successful transaction outcome: commit revocation before mapping to HTTP.
    ReuseDetected {
        tenant_id: String,
        session_id: String,
    },
}
pub trait TenantRefreshTransaction: TenantAuthTransaction {
    /// Non-locking routing hint only. Never authorizes rotation or reuse revocation.
    fn find_refresh(
        &mut self,
        digest: &[u8; 32],
    ) -> Result<Option<TenantRefreshRecord>, StoreError>;
    fn lock_refresh_session(
        &mut self,
        tenant: &str,
        session: &str,
    ) -> Result<Option<TenantSession>, StoreError>;
    fn lock_refresh_record(
        &mut self,
        tenant: &str,
        digest: &[u8; 32],
    ) -> Result<Option<TenantRefreshRecord>, StoreError>;
    /// Conditional version advance, old-token retirement and new digest insert in
    /// the surrounding transaction. Implementations do not commit independently.
    fn rotate_refresh_records(
        &mut self,
        session: &TenantSession,
        previous: &TenantRefreshRecord,
        next: &TenantRefreshRecord,
    ) -> Result<(), StoreError>;
    /// Revoke this exact tenant/session and all its refresh records, atomically.
    fn revoke_refresh_family(
        &mut self,
        session: &TenantSession,
        reason: RefreshTokenRevocationReason,
        now: SystemTime,
    ) -> Result<(), StoreError>;
}
impl<S, T, G, D, C, I> CoreTenantAuthenticationService<S, T, G, D, C, I>
where
    S: TenantAuthStore,
    for<'a> S::Transaction<'a>: TenantRefreshTransaction,
    T: TokenIssuer + AccessTokenValidator + ScopedAccessTokenIssuer,
    G: RefreshTokenGenerator,
    D: RefreshTokenDigester,
    C: Clock,
    I: IdGenerator,
{
    /// Bearer refresh only for sessions created without a device and entries that
    /// do not require proof. A device-bound session can never downgrade here.
    pub fn rotate_refresh(
        &self,
        refresh: SecretString,
    ) -> Result<TenantRefreshOutcome, TenantAuthError> {
        self.rotate_with_device_step(refresh, |_, session| {
            if self.entry.require_device_proof || session.device_id.is_some() {
                return Err(TenantAuthError::DeviceProofRequired);
            }
            Ok(())
        })
    }
    fn rotate_with_device_step(
        &self,
        raw: SecretString,
        verify: impl FnOnce(&mut S::Transaction<'_>, &TenantSession) -> Result<(), TenantAuthError>,
    ) -> Result<TenantRefreshOutcome, TenantAuthError> {
        let digest = self
            .digester
            .digest_refresh_token(raw.expose_secret())
            .map_err(|_| TenantAuthError::InvalidRefresh)?;
        self.store.auth_transaction(self.mode, |tx| {
            let hint = tx
                .find_refresh(&digest)?
                .ok_or(TenantAuthError::InvalidRefresh)?;
            self.validate_login_tenant(&hint.tenant_id)
                .map_err(|_| TenantAuthError::InvalidRefresh)?;
            // State is locked by auth_transaction. Never lock a token/session
            // before its tenant and account: management revocation uses this order.
            tx.lock_tenants(&[hint.tenant_id.clone()])?;
            let session_hint = tx
                .session(&hint.tenant_id, &hint.session_id)?
                .ok_or(TenantAuthError::InvalidRefresh)?;
            let account = tx
                .lock_account(&session_hint.account_id)?
                .ok_or(TenantAuthError::InvalidRefresh)?;
            let session = tx
                .lock_refresh_session(&hint.tenant_id, &hint.session_id)?
                .ok_or(TenantAuthError::InvalidRefresh)?;
            let refresh = tx
                .lock_refresh_record(&hint.tenant_id, &digest)?
                .ok_or(TenantAuthError::InvalidRefresh)?;
            if !account.active
                || account.id != session.account_id
                || session.account_id != session_hint.account_id
                || session.tenant_id != hint.tenant_id
                || session.id != hint.session_id
                || refresh.tenant_id != session.tenant_id
                || refresh.session_id != session.id
                || refresh.id != hint.id
                || refresh.token_digest != digest
                || session.client_id != self.entry.client_id
                || !tx.client_exists(&self.entry.client_id)?
            {
                return Err(TenantAuthError::InvalidRefresh);
            }
            self.require_session_identity(
                tx,
                &session,
                &session.tenant_id,
                &session.id,
                &account.id,
                self.clock.now(),
            )?;
            verify(tx, &session)?;
            // Proof verification may wait for locks. Recheck all credential times
            // afterwards; errors roll back any nonce consumption by that step.
            let now = self.clock.now();
            if session.created_at > now
                || session.expires_at <= now
                || refresh.issued_at < session.created_at
                || refresh.issued_at > now
                || refresh.expires_at <= now
                || refresh.expires_at > session.expires_at
                || refresh.token_version == 0
                || refresh.revoked_at.is_some() != refresh.revocation_reason.is_some()
                || refresh
                    .revoked_at
                    .is_some_and(|t| t < refresh.issued_at || t > now)
            {
                return Err(TenantAuthError::InvalidRefresh);
            }
            let reuse = refresh.revoked_at.is_some()
                && refresh.revocation_reason == Some(RefreshTokenRevocationReason::Rotated)
                && refresh.token_version < session.refresh_token_version;
            if reuse {
                tx.revoke_refresh_family(
                    &session,
                    RefreshTokenRevocationReason::ReuseDetected,
                    now,
                )?;
                return Ok(TenantRefreshOutcome::ReuseDetected {
                    tenant_id: session.tenant_id,
                    session_id: session.id,
                });
            }
            if refresh.revoked_at.is_some()
                || refresh.token_version != session.refresh_token_version
            {
                return Err(TenantAuthError::InvalidRefresh);
            }
            let version =
                next_refresh_token_version(session.refresh_token_version, refresh.token_version)?;
            let next_raw = self.generator.generate_refresh_token()?;
            let next_digest = self
                .digester
                .digest_refresh_token(next_raw.expose_secret())?;
            let access = match &session.scope {
                Some(scope) => self.tokens.issue_scoped_access_token(
                    &session.tenant_id,
                    &session.id,
                    &account.id,
                    &session.client_id,
                    now,
                    scope,
                )?,
                None => self.tokens.issue_access_token(
                    &session.tenant_id,
                    &session.id,
                    &account.id,
                    &session.client_id,
                    now,
                )?,
            };
            let expiry = now
                .checked_add(Duration::from_secs(self.config.refresh_token_ttl_secs))
                .ok_or(AccessError::InvalidInput("refresh_expiry"))?
                .min(session.expires_at);
            self.validate_issued_access(&access.token, &session)?;
            if access.token.expose_secret().is_empty()
                || access.expires_at <= now
                || access.expires_at > expiry
                || next_digest == digest
            {
                return Err(TokenError::IssuerRejected(
                    "invalid tenant refresh token bundle".into(),
                )
                .into());
            }
            let next = TenantRefreshRecord {
                tenant_id: session.tenant_id.clone(),
                id: self.ids.next_id("rtok"),
                session_id: session.id.clone(),
                token_digest: next_digest,
                token_version: version,
                issued_at: now,
                expires_at: expiry,
                revoked_at: None,
                revocation_reason: None,
            };
            tx.rotate_refresh_records(&session, &refresh, &next)?;
            Ok(TenantRefreshOutcome::Rotated {
                session: TenantSession {
                    refresh_token_version: version,
                    ..session
                },
                tokens: ProofBoundTokenResult {
                    access_token: access,
                    refresh_token: next_raw,
                    refresh_expires_at: expiry,
                    refresh_token_version: version,
                },
            })
        })
    }
}
impl<S, T, G, D, C, I> CoreTenantAuthenticationService<S, T, G, D, C, I>
where
    S: TenantAuthStore,
    for<'a> S::Transaction<'a>: TenantRefreshTransaction + TenantDeviceProofTransaction,
    T: TokenIssuer + AccessTokenValidator + ScopedAccessTokenIssuer,
    G: RefreshTokenGenerator,
    D: RefreshTokenDigester,
    C: Clock,
    I: IdGenerator,
{
    pub fn rotate_refresh_with_proof<J, V, N, K, Z>(
        &self,
        command: RotateProofBoundRefreshCommand,
        devices: &CoreTenantDeviceProofService<S, J, V, N, K, Z>,
    ) -> Result<TenantRefreshOutcome, TenantAuthError>
    where
        J: DevicePublicJwkValidator,
        V: DeviceSignatureVerifier,
        N: DeviceChallengeGenerator,
        K: Clock,
        Z: IdGenerator,
    {
        if !devices.matches_login_entry(self.mode, &self.entry.client_id) {
            return Err(AccessError::InvalidInput("device_refresh_configuration").into());
        }
        let context = tenant_refresh_proof_context(
            &self.entry.client_id,
            &self.entry.login_entry,
            &command.refresh_token,
        );
        self.rotate_with_device_step(command.refresh_token, |tx, session| {
            if session.device_id.as_deref() != Some(command.proof.device_id.as_str()) {
                return Err(TenantAuthError::DeviceProof(
                    DeviceRequestVerificationError::InvalidProof,
                ));
            }
            devices.verify_in_transaction(
                tx,
                &session.tenant_id,
                &session.account_id,
                &DeviceProofPurpose::new(REFRESH_PURPOSE).map_err(TenantAuthError::Security)?,
                &command.proof,
                &command.binding,
                Some(&context),
                false,
            )?;
            Ok(())
        })
    }
}
