use super::super::*;
use super::*;
use crate::*;
use base64ct::{Base64UrlUnpadded, Encoding};
use sha2::{Digest, Sha256};
use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

pub struct CoreTenantDeviceScanLoginService<A, P> {
    auth: A,
    devices: P,
    config: ScanLoginEntryConfig,
    admission: Arc<dyn ScanLoginAdmission>,
    presentation: Arc<dyn ScanTargetPresentationProvider>,
    cipher: Arc<dyn ScanResultCipher>,
}

impl<S, T, G, D, C, I, J, V, N, K, Z>
    CoreTenantDeviceScanLoginService<
        CoreTenantAuthenticationService<S, T, G, D, C, I>,
        CoreTenantDeviceProofService<S, J, V, N, K, Z>,
    >
where
    S: TenantScanLoginStore,
    for<'a> S::Transaction<'a>: TenantScanLoginTransaction,
    T: TokenIssuer + AccessTokenValidator + ScopedAccessTokenIssuer + Send + Sync,
    G: RefreshTokenGenerator + Send + Sync,
    D: RefreshTokenDigester + Send + Sync,
    C: Clock + Send + Sync,
    I: IdGenerator + Send + Sync,
    J: DevicePublicJwkValidator + Send + Sync,
    V: DeviceSignatureVerifier + Send + Sync,
    N: DeviceChallengeGenerator + Send + Sync,
    K: Clock + Send + Sync,
    Z: IdGenerator + Send + Sync,
{
    pub fn new(
        config: ScanLoginEntryConfig,
        auth: CoreTenantAuthenticationService<S, T, G, D, C, I>,
        devices: CoreTenantDeviceProofService<S, J, V, N, K, Z>,
        admission: Arc<dyn ScanLoginAdmission>,
        presentation: Arc<dyn ScanTargetPresentationProvider>,
        cipher: Arc<dyn ScanResultCipher>,
    ) -> Result<Self, ScanLoginError> {
        config
            .validate(auth.mode)
            .map_err(|_| ScanLoginError::InvalidRequest)?;
        if auth.entry.client_id != config.target_client_id
            || auth.entry.login_entry != config.entry_id
            || !auth.entry.require_device_proof
            || !devices.matches_login_entry(auth.mode, &config.target_client_id)
        {
            return Err(ScanLoginError::InvalidRequest);
        }
        Ok(Self {
            auth,
            devices,
            config,
            admission,
            presentation,
            cipher,
        })
    }
    fn now(&self) -> SystemTime {
        self.auth.clock.now()
    }
    fn id(&self, kind: &str) -> Result<String, ScanLoginError> {
        let id = self.auth.ids.next_id(kind);
        valid_uuid(&id)?;
        Ok(id)
    }
    fn secret(&self) -> Result<SecretString, ScanLoginError> {
        let s = self
            .auth
            .generator
            .generate_refresh_token()
            .map_err(TenantAuthError::from)?;
        decode_secret(&s)?;
        Ok(s)
    }
    fn host(&self, host: &TrustedScanHostContext) -> Result<(), ScanLoginError> {
        if host.scope() != self.config.host_scope || host.valid_until() <= self.now() {
            return Err(ScanLoginError::AdmissionDenied);
        }
        Ok(())
    }
    fn admit(
        &self,
        g: &ScanGrantRecord,
        stage: ScanAdmissionStage,
        op: Option<&str>,
        host: &TrustedScanHostContext,
        fingerprint: [u8; 32],
    ) -> Result<ScanAdmissionDecision, ScanLoginError> {
        self.host(host)?;
        let request = ScanAdmissionRequest {
            stage,
            host_scope: g.host_scope.clone(),
            entry_id: g.entry_id.clone(),
            tenant_id: g.tenant_id.clone(),
            mode: g.mode,
            source: g.source.clone(),
            target: g.target.clone(),
            grant_id: Some(g.id.clone()),
            operation_id: op.map(str::to_owned),
            request_fingerprint: fingerprint,
        };
        match self.admission.authorize(&request, host)? {
            d @ ScanAdmissionDecision::Allow { valid_until, .. }
                if valid_until > self.now()
                    && valid_until <= host.valid_until()
                    && valid_until
                        <= self.now()
                            + Duration::from_secs(self.config.limits.admission_ttl_secs as u64) =>
            {
                Ok(d)
            }
            ScanAdmissionDecision::Deny { .. } => Err(ScanLoginError::AdmissionDenied),
            _ => Err(ScanLoginError::AdmissionUnavailable),
        }
    }
    fn permit(&self, decision: &ScanAdmissionDecision) -> Result<(), ScanLoginError> {
        if let ScanAdmissionDecision::Allow { valid_until, .. } = decision {
            if *valid_until > self.now() {
                return Ok(());
            }
        }
        Err(ScanLoginError::AdmissionUnavailable)
    }
    fn source(
        &self,
        tx: &mut impl TenantScanLoginTransaction,
        tenant: &str,
        source: &ScanSourceReference,
    ) -> Result<TenantSession, ScanLoginError> {
        tx.lock_tenants(&[tenant.into()])?;
        let account = tx
            .lock_account(&source.account_id)?
            .ok_or(TenantAuthError::InvalidSession)?;
        let session = tx
            .lock_refresh_session(tenant, &source.session_id)?
            .ok_or(TenantAuthError::InvalidSession)?;
        self.source_current(tx, tenant, source, &account, &session)?;
        Ok(session)
    }
    fn source_current(
        &self,
        tx: &mut impl TenantScanLoginTransaction,
        tenant: &str,
        source: &ScanSourceReference,
        account: &TenantLoginIdentity,
        session: &TenantSession,
    ) -> Result<(), ScanLoginError> {
        let now = self.now();
        if !account.active
            || account.id != source.account_id
            || session.account_id != source.account_id
            || session.id != source.session_id
            || session.tenant_id != tenant
            || session.client_id != source.client_id
            || session.purpose != AccessTokenPurpose::Business
            || session.status != SessionStatus::Active
            || session.device_id.is_some()
            || session.created_at > now
            || session.expires_at <= now
            || session.authenticated_at != source.authenticated_at
            || !tx.client_exists(&source.client_id)?
            || !self
                .config
                .allowed_source_client_ids
                .contains(&source.client_id)
            || !tx
                .tenant(tenant)?
                .is_some_and(|t| t.status == TenantStatus::Active)
            || !tx
                .membership(tenant, &source.account_id)?
                .is_some_and(|m| m.status == MembershipStatus::Active)
        {
            return Err(TenantAuthError::InvalidSession.into());
        }
        Ok(())
    }
    fn target_account(
        &self,
        tx: &mut impl TenantScanLoginTransaction,
        g: &ScanGrantRecord,
    ) -> Result<(), ScanLoginError> {
        tx.lock_tenants(&[g.tenant_id.clone()])?;
        if let Some(source) = &g.source {
            let a = tx
                .lock_account(&source.account_id)?
                .ok_or(TenantAuthError::InvalidSession)?;
            if !a.active
                || !tx
                    .membership(&g.tenant_id, &source.account_id)?
                    .is_some_and(|m| m.status == MembershipStatus::Active)
            {
                return Err(TenantAuthError::InvalidSession.into());
            }
        }
        if !tx
            .tenant(&g.tenant_id)?
            .is_some_and(|t| t.status == TenantStatus::Active)
            || !tx.client_exists(&self.config.target_client_id)?
        {
            return Err(TenantAuthError::InvalidSession.into());
        }
        Ok(())
    }
    fn source_call(&self, actor: &ScanSourceCall) -> Result<ScanSourceReference, ScanLoginError> {
        self.host(&actor.host)?;
        if actor.source.expires_at() <= self.now()
            || !self
                .config
                .allowed_source_client_ids
                .iter()
                .any(|s| s == actor.source.client_id())
        {
            return Err(ScanLoginError::SourceClientNotAllowed);
        }
        self.config
            .tenant_policy
            .validate_selection(self.auth.mode, actor.source.tenant_id())
            .map_err(TenantAuthError::from)?;
        Ok(ScanSourceReference {
            account_id: actor.source.account_id().into(),
            session_id: actor.source.session_id().into(),
            client_id: actor.source.client_id().into(),
            authenticated_at: actor.source.authenticated_at(),
        })
    }
    fn prove(
        &self,
        tx: &mut impl TenantScanLoginTransaction,
        actor: &ScanDeviceCall,
        account: Option<&str>,
        action: ScanLoginAction,
    ) -> Result<(ScanTargetReference, bool), ScanLoginError> {
        self.prove_at(tx, actor, account, action, true)
    }
    fn prove_at(
        &self,
        tx: &mut impl TenantScanLoginTransaction,
        actor: &ScanDeviceCall,
        account: Option<&str>,
        action: ScanLoginAction,
        consume: bool,
    ) -> Result<(ScanTargetReference, bool), ScanLoginError> {
        self.host(&actor.host)?;
        if actor.entry_id != self.config.entry_id {
            return Err(ScanLoginError::InvalidRequest);
        }
        self.config
            .tenant_policy
            .validate_selection(self.auth.mode, &actor.binding.tenant_id)
            .map_err(TenantAuthError::from)?;
        tx.lock_tenants(&[actor.binding.tenant_id.clone()])?;
        if !tx.client_exists(&self.config.target_client_id)?
            || !tx
                .tenant(&actor.binding.tenant_id)?
                .is_some_and(|t| t.status == TenantStatus::Active)
        {
            return Err(TenantAuthError::InvalidSession.into());
        }
        let (verified, needs) = self.devices.verify_scan_in_transaction(
            tx,
            &actor.binding.tenant_id,
            account,
            action,
            &self.config.entry_id,
            &actor.proof,
            &actor.binding,
            consume,
        )?;
        Ok((
            ScanTargetReference {
                device_id: verified.device_id,
                key_id: verified.key_id,
                device_version: verified.device_version,
                key_version: verified.key_version,
            },
            needs,
        ))
    }
    // Called only after a verified device proof has locked the device. Final
    // original submissions and close_origin therefore share a serialization point.
    fn origin_open(
        &self,
        tx: &mut impl TenantScanLoginTransaction,
        tenant: &str,
        entry: &str,
        device: &str,
        action: ScanOriginAction,
        operation: &str,
        secret_hash: &[u8; 32],
    ) -> Result<(), ScanLoginError> {
        if let Some(closed) = tx.find_scan_origin_closure(
            tenant,
            &self.config.host_scope,
            entry,
            device,
            action,
            operation,
        )? {
            return Err(if &closed.delivery_secret_hash == secret_hash {
                ScanLoginError::OriginOperationClosed
            } else {
                ScanLoginError::OperationConflict
            });
        }
        Ok(())
    }
    fn close_original(
        &self,
        c: CloseScanOrigin,
        actor: ScanDeviceCall,
    ) -> Result<ScanOriginCloseResult, ScanLoginError> {
        valid_uuid(&c.origin_operation_id)?;
        if c.entry_id != self.config.entry_id || c.tenant_id != actor.binding.tenant_id {
            return Err(ScanLoginError::InvalidRequest);
        }
        let secret_hash: [u8; 32] = Sha256::digest(decode_secret(&c.delivery_secret)?).into();
        // A grant may gain a source account or delivery between preparation and
        // locking. Roll back and prepare again instead of acquiring identity locks
        // after the device/grant locks (the shared login lock order).
        for _ in 0..3 {
            let hint = self.auth.store.scan_transaction(self.auth.mode, |tx| {
                let (target, _) =
                    self.prove_at(tx, &actor, None, ScanLoginAction::CloseOrigin, false)?;
                if let Some(closed) = tx.find_scan_origin_closure(
                    &c.tenant_id,
                    &self.config.host_scope,
                    &c.entry_id,
                    &target.device_id,
                    c.origin_action,
                    &c.origin_operation_id,
                )? {
                    if closed.delivery_secret_hash != secret_hash {
                        return Err(ScanLoginError::NotFound);
                    }
                    return Ok(None);
                }
                let op = tx.find_scan_operation(
                    &c.tenant_id,
                    &self.config.host_scope,
                    &c.entry_id,
                    &target.device_id,
                    c.origin_action.as_str(),
                    &c.origin_operation_id,
                )?;
                match op {
                    Some(op) => {
                        let g = tx
                            .find_scan_grant(
                                &c.tenant_id,
                                &self.config.host_scope,
                                &c.entry_id,
                                &op.grant_id,
                            )?
                            .ok_or(ScanLoginError::NotFound)?;
                        if g.target.as_ref().map(|t| &t.device_id) != Some(&target.device_id)
                            || g.delivery_secret_hash != Some(secret_hash)
                        {
                            return Err(ScanLoginError::NotFound);
                        }
                        let d = tx.find_scan_delivery(&c.tenant_id, &g.id)?;
                        Ok(Some((g, d)))
                    }
                    None => Ok(None),
                }
            })?;
            let result = self.auth.store.scan_transaction(self.auth.mode, |tx| {
                tx.lock_tenants(&[c.tenant_id.clone()])?;
                let session = if let Some((g, d)) = &hint {
                    if let Some(source) = &g.source {
                        // Cancellation is allowed after logout or business suspension.
                        // These are ordering locks, not new-login admission checks.
                        tx.lock_account(&source.account_id)?;
                    }
                    match d {
                        Some(d) => Some(
                            tx.lock_refresh_session(&c.tenant_id, &d.session_id)?
                                .ok_or(ScanLoginError::NotFound)?,
                        ),
                        None => None,
                    }
                } else {
                    None
                };
                let (target, _) = self.prove(tx, &actor, None, ScanLoginAction::CloseOrigin)?;
                if let Some(closed) = tx.find_scan_origin_closure(
                    &c.tenant_id,
                    &self.config.host_scope,
                    &c.entry_id,
                    &target.device_id,
                    c.origin_action,
                    &c.origin_operation_id,
                )? {
                    if closed.delivery_secret_hash != secret_hash {
                        return Err(ScanLoginError::NotFound);
                    }
                    return Ok(ScanOriginCloseResult {
                        origin_action: c.origin_action,
                        origin_operation_id: c.origin_operation_id.clone(),
                        outcome: ScanOriginCloseOutcome::Closed,
                        closed_at: Some(closed.closed_at),
                        progress: None,
                    });
                }
                let op = tx.find_scan_operation(
                    &c.tenant_id,
                    &self.config.host_scope,
                    &c.entry_id,
                    &target.device_id,
                    c.origin_action.as_str(),
                    &c.origin_operation_id,
                )?;
                let (grant_id, progress) = match op {
                    Some(op) => {
                        let (prepared, _) =
                            hint.as_ref().ok_or(ScanLoginError::OperationConflict)?;
                        if op.grant_id != prepared.id {
                            return Err(ScanLoginError::OperationConflict);
                        }
                        let mut g = tx
                            .lock_scan_grant(&c.tenant_id, &op.grant_id)?
                            .ok_or(ScanLoginError::NotFound)?;
                        if g.source != prepared.source {
                            return Err(ScanLoginError::OperationConflict);
                        }
                        if g.host_scope != self.config.host_scope
                            || g.entry_id != c.entry_id
                            || g.target_client_id != self.config.target_client_id
                            || g.target.as_ref().map(|t| &t.device_id) != Some(&target.device_id)
                            || g.delivery_secret_hash != Some(secret_hash)
                        {
                            return Err(ScanLoginError::NotFound);
                        }
                        let mut d = tx.lock_scan_delivery(&c.tenant_id, &g.id)?;
                        if let Some(d) = &mut d {
                            let session =
                                session.as_ref().ok_or(ScanLoginError::OperationConflict)?;
                            if d.session_id != session.id {
                                return Err(ScanLoginError::OperationConflict);
                            }
                            if session.tenant_id != g.tenant_id
                                || g.source.as_ref().map(|s| &s.account_id)
                                    != Some(&session.account_id)
                                || session.device_id.as_deref() != Some(target.device_id.as_str())
                                || session.client_id != g.target_client_id
                                || session.purpose != AccessTokenPurpose::Business
                            {
                                return Err(ScanLoginError::NotFound);
                            }
                            if d.state == ScanDeliveryState::Acknowledged {
                                return Ok(ScanOriginCloseResult {
                                    origin_action: c.origin_action,
                                    origin_operation_id: c.origin_operation_id.clone(),
                                    outcome: ScanOriginCloseOutcome::AlreadyActivated,
                                    closed_at: None,
                                    progress: Some(self.progress(&g, Some(d))),
                                });
                            }
                            self.revoke_delivery(tx, &g, d, "origin_closed")?;
                        } else if g.state == ScanGrantState::Issued {
                            return Err(ScanLoginError::ResultUnavailable);
                        } else if matches!(
                            g.state,
                            ScanGrantState::WaitingUser
                                | ScanGrantState::WaitingDevice
                                | ScanGrantState::AwaitingApproval
                                | ScanGrantState::Approved
                        ) {
                            g.state = ScanGrantState::Cancelled;
                            g.presentation = None;
                            self.update(tx, &mut g)?;
                        }
                        tx.append_scan_audit(&ScanAuditEvent {
                            id: self.id("scan-audit")?,
                            tenant_id: g.tenant_id.clone(),
                            host_scope: g.host_scope.clone(),
                            grant_id: g.id.clone(),
                            actor_kind: "device".into(),
                            actor_id: Some(target.device_id.clone()),
                            operation: "close_origin".into(),
                            operation_id: c.origin_operation_id.clone(),
                            session_id: d.as_ref().map(|d| d.session_id.clone()),
                            decision_id: None,
                            occurred_at: self.now(),
                        })?;
                        (Some(g.id.clone()), Some(self.progress(&g, d.as_ref())))
                    }
                    None => {
                        if hint.is_some() {
                            return Err(ScanLoginError::OperationConflict);
                        }
                        (None, None)
                    }
                };
                // Match the durable Unix-second precision so Rust and HTTP
                // retries return exactly the original closing timestamp.
                let closed_at = UNIX_EPOCH + Duration::from_secs(epoch(self.now())?);
                tx.insert_scan_origin_closure(&ScanOriginClosure {
                    tenant_id: c.tenant_id.clone(),
                    host_scope: self.config.host_scope.clone(),
                    entry_id: c.entry_id.clone(),
                    device_id: target.device_id,
                    origin_action: c.origin_action,
                    origin_operation_id: c.origin_operation_id.clone(),
                    delivery_secret_hash: secret_hash,
                    grant_id,
                    closed_by_key_id: target.key_id,
                    closed_at,
                })?;
                Ok(ScanOriginCloseResult {
                    origin_action: c.origin_action,
                    origin_operation_id: c.origin_operation_id.clone(),
                    outcome: ScanOriginCloseOutcome::Closed,
                    closed_at: Some(closed_at),
                    progress,
                })
            });
            match result {
                Err(ScanLoginError::OperationConflict) => continue,
                other => return other,
            }
        }
        Err(ScanLoginError::OperationConflict)
    }
    fn hint(&self, tenant: &str, id: &str) -> Result<ScanGrantRecord, ScanLoginError> {
        valid_uuid(id)?;
        self.auth.store.scan_transaction(self.auth.mode, |tx| {
            tx.find_scan_grant(tenant, &self.config.host_scope, &self.config.entry_id, id)?
                .ok_or(ScanLoginError::NotFound)
        })
    }
    fn locked(
        &self,
        tx: &mut impl TenantScanLoginTransaction,
        hint: &ScanGrantRecord,
    ) -> Result<ScanGrantRecord, ScanLoginError> {
        let g = tx
            .lock_scan_grant(&hint.tenant_id, &hint.id)?
            .ok_or(ScanLoginError::NotFound)?;
        if g.host_scope != self.config.host_scope
            || g.entry_id != self.config.entry_id
            || g.target_client_id != self.config.target_client_id
        {
            return Err(ScanLoginError::NotFound);
        }
        if g.version != hint.version {
            return Err(ScanLoginError::OperationConflict);
        }
        Ok(g)
    }
    fn live(&self, g: &ScanGrantRecord) -> Result<(), ScanLoginError> {
        if !self.config.modes.contains(&g.mode) {
            return Err(ScanLoginError::ModeDisabled);
        }
        if matches!(
            g.state,
            ScanGrantState::WaitingUser
                | ScanGrantState::WaitingDevice
                | ScanGrantState::AwaitingApproval
                | ScanGrantState::Approved
        ) && (g.expires_at <= self.now()
            || (g.state == ScanGrantState::Approved
                && g.approved_until.is_some_and(|u| u <= self.now()))
            || (g.state == ScanGrantState::WaitingDevice && g.code_expires_at <= self.now()))
        {
            return Err(ScanLoginError::Expired);
        }
        match g.state {
            ScanGrantState::Denied => Err(ScanLoginError::Denied),
            ScanGrantState::Cancelled => Err(ScanLoginError::Cancelled),
            ScanGrantState::Expired => Err(ScanLoginError::Expired),
            ScanGrantState::Invalidated => Err(ScanLoginError::Invalidated),
            _ => Ok(()),
        }
    }
    fn owner(
        &self,
        g: &ScanGrantRecord,
        source: &ScanSourceReference,
    ) -> Result<(), ScanLoginError> {
        if g.source.as_ref() != Some(source) {
            return Err(ScanLoginError::NotFound);
        }
        Ok(())
    }
    fn device_owner(
        &self,
        g: &ScanGrantRecord,
        access: &DeviceGrantAccess,
        target: &ScanTargetReference,
    ) -> Result<(), ScanLoginError> {
        if g.target.as_ref() != Some(target)
            || g.delivery_secret_hash
                != Some(Sha256::digest(decode_secret(&access.delivery_secret)?).into())
        {
            return Err(ScanLoginError::NotFound);
        }
        Ok(())
    }
    fn operation(
        &self,
        tx: &mut impl TenantScanLoginTransaction,
        g: &ScanGrantRecord,
        actor: &str,
        action: &str,
        op: &str,
        fp: [u8; 32],
    ) -> Result<bool, ScanLoginError> {
        valid_uuid(op)?;
        if let Some(old) =
            tx.find_scan_operation(&g.tenant_id, &g.host_scope, &g.entry_id, actor, action, op)?
        {
            if old.fingerprint != fp || old.grant_id != g.id {
                return Err(ScanLoginError::OperationConflict);
            }
            Ok(true)
        } else {
            Ok(false)
        }
    }
    fn record(
        &self,
        tx: &mut impl TenantScanLoginTransaction,
        g: &ScanGrantRecord,
        actor: &str,
        kind: &str,
        action: &str,
        op: &str,
        fp: [u8; 32],
        decision: Option<&ScanAdmissionDecision>,
        session: Option<&str>,
    ) -> Result<(), ScanLoginError> {
        tx.insert_scan_operation(&ScanOperationRecord {
            tenant_id: g.tenant_id.clone(),
            host_scope: g.host_scope.clone(),
            entry_id: g.entry_id.clone(),
            actor_id: actor.into(),
            action: action.into(),
            operation_id: op.into(),
            fingerprint: fp,
            grant_id: g.id.clone(),
            created_at: self.now(),
        })?;
        tx.append_scan_audit(&ScanAuditEvent {
            id: self.id("scan-audit")?,
            tenant_id: g.tenant_id.clone(),
            host_scope: g.host_scope.clone(),
            grant_id: g.id.clone(),
            actor_kind: kind.into(),
            actor_id: if kind == "host" {
                None
            } else {
                Some(actor.into())
            },
            operation: action.into(),
            operation_id: op.into(),
            session_id: session.map(str::to_owned),
            decision_id: decision.and_then(|d| match d {
                ScanAdmissionDecision::Allow { decision_id, .. } => Some(decision_id.clone()),
                _ => None,
            }),
            occurred_at: self.now(),
        })?;
        Ok(())
    }
    fn update(
        &self,
        tx: &mut impl TenantScanLoginTransaction,
        g: &mut ScanGrantRecord,
    ) -> Result<(), ScanLoginError> {
        let old = g.version;
        g.version = g
            .version
            .checked_add(1)
            .ok_or(ScanLoginError::InvalidRequest)?;
        tx.update_scan_grant(g, old)?;
        Ok(())
    }
    fn progress(&self, g: &ScanGrantRecord, d: Option<&ScanDeliveryRecord>) -> ScanProgress {
        let state = if matches!(
            g.state,
            ScanGrantState::WaitingUser
                | ScanGrantState::WaitingDevice
                | ScanGrantState::AwaitingApproval
                | ScanGrantState::Approved
        ) && (g.expires_at <= self.now()
            || (g.state == ScanGrantState::Approved
                && g.approved_until.is_some_and(|u| u <= self.now()))
            || (g.state == ScanGrantState::WaitingDevice && g.code_expires_at <= self.now()))
        {
            ScanGrantState::Expired
        } else {
            g.state
        };
        let next = match (state, d.map(|d| d.state)) {
            (ScanGrantState::Issued, Some(ScanDeliveryState::Acknowledged)) => "use_local_session",
            (ScanGrantState::Issued, Some(ScanDeliveryState::Recoverable))
                if d.is_some_and(|d| d.recover_until > self.now()) =>
            {
                "persist_then_acknowledge"
            }
            (ScanGrantState::Issued, _) => "restart",
            (ScanGrantState::Approved, _) => "exchange",
            (ScanGrantState::WaitingUser, _) => "wait_for_phone_scan",
            (ScanGrantState::WaitingDevice, _) => "wait_for_device_scan",
            (ScanGrantState::AwaitingApproval, _) => "confirm_on_phone",
            _ => "restart",
        };
        ScanProgress {
            grant_id: g.id.clone(),
            mode: g.mode,
            state,
            version: g.version,
            server_time: self.now(),
            expires_at: g.expires_at,
            code_expires_at: g.code_expires_at,
            approved_until: g.approved_until,
            poll_after_ms: if matches!(
                state,
                ScanGrantState::WaitingUser
                    | ScanGrantState::WaitingDevice
                    | ScanGrantState::AwaitingApproval
                    | ScanGrantState::Approved
            ) {
                self.config.limits.poll_after_ms
            } else {
                0
            },
            delivery_state: d.map(|d| d.state),
            issuance_operation_id: d.map(|d| d.issuance_operation_id.clone()),
            recover_until: d.map(|d| d.recover_until),
            next_action: next.into(),
        }
    }
    fn code_context(
        &self,
        g: &ScanGrantRecord,
        op: &str,
    ) -> Result<ScanResultContext, ScanLoginError> {
        Ok(ScanResultContext {
            tenant_id: g.tenant_id.clone(),
            host_scope: g.host_scope.clone(),
            entry_id: g.entry_id.clone(),
            grant_id: g.id.clone(),
            expires_at_unix_secs: epoch(g.code_expires_at)?,
            payload: match g.mode {
                ScanLoginMode::DeviceDisplay => ScanResultPayload::DevicePresentation {
                    device_id: g
                        .target
                        .as_ref()
                        .ok_or(ScanLoginError::InvalidRequest)?
                        .device_id
                        .clone(),
                    origin_operation_id: op.into(),
                },
                ScanLoginMode::PhoneDisplay => ScanResultPayload::PhonePresentation {
                    source_session_id: g
                        .source
                        .as_ref()
                        .ok_or(ScanLoginError::InvalidRequest)?
                        .session_id
                        .clone(),
                    origin_operation_id: op.into(),
                },
            },
        })
    }
    fn bundle_context(
        &self,
        g: &ScanGrantRecord,
        d: &ScanDeliveryRecord,
    ) -> Result<ScanResultContext, ScanLoginError> {
        Ok(ScanResultContext {
            tenant_id: g.tenant_id.clone(),
            host_scope: g.host_scope.clone(),
            entry_id: g.entry_id.clone(),
            grant_id: g.id.clone(),
            expires_at_unix_secs: epoch(d.recover_until)?,
            payload: ScanResultPayload::SessionBundle {
                device_id: g
                    .target
                    .as_ref()
                    .ok_or(ScanLoginError::InvalidRequest)?
                    .device_id
                    .clone(),
                session_id: d.session_id.clone(),
                issuance_operation_id: d.issuance_operation_id.clone(),
            },
        })
    }
    fn presentation(
        &self,
        g: &ScanGrantRecord,
        host: &TrustedScanHostContext,
    ) -> Result<(ScanTargetPresentation, String), ScanLoginError> {
        let r = ScanAdmissionRequest {
            stage: ScanAdmissionStage::InspectConfirmation,
            host_scope: g.host_scope.clone(),
            entry_id: g.entry_id.clone(),
            tenant_id: g.tenant_id.clone(),
            mode: g.mode,
            source: g.source.clone(),
            target: g.target.clone(),
            grant_id: Some(g.id.clone()),
            operation_id: None,
            request_fingerprint: [0; 32],
        };
        let p = self.presentation.describe(&r, host)?;
        if p.display_name.is_empty()
            || p.identification.is_empty()
            || [&p.display_name, &p.identification]
                .iter()
                .any(|s| s.chars().count() > 128 || s.chars().any(char::is_control))
            || p.context_label
                .as_ref()
                .is_some_and(|s| s.chars().count() > 128 || s.chars().any(char::is_control))
            || p.revision.is_empty()
            || p.revision.len() > 128
        {
            return Err(ScanLoginError::InvalidRequest);
        }
        let source = g.source.as_ref().ok_or(ScanLoginError::NotFound)?;
        let target = g.target.as_ref().ok_or(ScanLoginError::NotFound)?;
        let hash = fingerprint(&[
            &g.id,
            &g.version.to_string(),
            &source.account_id,
            &source.session_id,
            &target.device_id,
            &target.key_id,
            &target.device_version.to_string(),
            &target.key_version.to_string(),
            &p.display_name,
            &p.identification,
            p.context_label.as_deref().unwrap_or(""),
            &p.revision,
        ]);
        Ok((p, Base64UrlUnpadded::encode_string(&hash)))
    }
    fn target_snapshot(
        &self,
        tx: &mut impl TenantScanLoginTransaction,
        g: &ScanGrantRecord,
    ) -> Result<(), ScanLoginError> {
        let t = g.target.as_ref().ok_or(ScanLoginError::NotFound)?;
        let d = tx
            .lock_proof_device(&g.tenant_id, &t.device_id)?
            .ok_or(ScanLoginError::Invalidated)?;
        let k = tx
            .lock_proof_key(&g.tenant_id, &t.device_id, &t.key_id)?
            .ok_or(ScanLoginError::Invalidated)?;
        if d.status != DeviceStatus::Active
            || d.client_id != g.target_client_id
            || d.version != t.device_version
            || d.proof_key_id.as_deref() != Some(&t.key_id)
            || k.status != DeviceProofKeyStatus::Active
            || k.version != t.key_version
        {
            return Err(ScanLoginError::Invalidated);
        }
        if let Some(source) = &g.source {
            if tx
                .lock_proof_binding(&g.tenant_id, &source.account_id, &t.device_id)?
                .is_some_and(|b| b.status != AccountDeviceBindingStatus::Active)
            {
                return Err(ScanLoginError::Invalidated);
            }
        }
        Ok(())
    }
    fn finish_source(
        &self,
        c: SourceGrantAction,
        actor: ScanSourceCall,
        deny: bool,
    ) -> Result<ScanProgress, ScanLoginError> {
        valid_uuid(&c.operation_id)?;
        let source = self.source_call(&actor)?;
        let hint = self.hint(actor.source.tenant_id(), &c.grant_id)?;
        self.owner(&hint, &source)?;
        let action = if deny { "deny" } else { "cancel_source" };
        let fp = fingerprint(&[&c.grant_id, action]);
        self.auth.store.scan_transaction(self.auth.mode, |tx| {
            self.source(tx, &hint.tenant_id, &source)?;
            let mut g = self.locked(tx, &hint)?;
            if self.operation(tx, &g, &source.session_id, action, &c.operation_id, fp)? {
                return Ok(self.progress(&g, None));
            }
            if g.state == ScanGrantState::Issued {
                return Err(ScanLoginError::AlreadyIssued);
            }
            if matches!(
                g.state,
                ScanGrantState::Denied
                    | ScanGrantState::Cancelled
                    | ScanGrantState::Expired
                    | ScanGrantState::Invalidated
            ) {
                return Ok(self.progress(&g, None));
            }
            g.state = if deny {
                ScanGrantState::Denied
            } else {
                ScanGrantState::Cancelled
            };
            g.presentation = None;
            self.update(tx, &mut g)?;
            self.record(
                tx,
                &g,
                &source.session_id,
                "person",
                action,
                &c.operation_id,
                fp,
                None,
                Some(&source.session_id),
            )?;
            Ok(self.progress(&g, None))
        })
    }
    fn read_device(
        &self,
        c: DeviceGrantAccess,
        actor: ScanDeviceCall,
        action: ScanLoginAction,
    ) -> Result<ScanProgress, ScanLoginError> {
        let hint = self.hint(&actor.binding.tenant_id, &c.grant_id)?;
        self.auth.store.scan_transaction(self.auth.mode, |tx| {
            self.target_account(tx, &hint)?;
            let (target, _) = self.prove(tx, &actor, None, action)?;
            self.device_owner(&hint, &c, &target)?;
            let g = self.locked(tx, &hint)?;
            Ok(self.progress(&g, tx.lock_scan_delivery(&g.tenant_id, &g.id)?.as_ref()))
        })
    }
    fn load_delivery(
        &self,
        tx: &mut impl TenantScanLoginTransaction,
        hint: &ScanGrantRecord,
        access: &DeviceGrantAccess,
        actor: &ScanDeviceCall,
        action: ScanLoginAction,
        verify: Option<bool>,
    ) -> Result<(ScanGrantRecord, ScanDeliveryRecord, TenantSession), ScanLoginError> {
        self.target_account(tx, hint)?;
        let dh = tx
            .find_scan_delivery(&hint.tenant_id, &hint.id)?
            .ok_or(ScanLoginError::NotApproved)?;
        let session = tx
            .lock_refresh_session(&hint.tenant_id, &dh.session_id)?
            .ok_or(ScanLoginError::NotFound)?;
        let target = match verify {
            Some(consume) => {
                self.prove_at(
                    tx,
                    actor,
                    hint.source.as_ref().map(|s| s.account_id.as_str()),
                    action,
                    consume,
                )?
                .0
            }
            None => {
                self.host(&actor.host)?;
                self.target_snapshot(tx, hint)?;
                hint.target.clone().ok_or(ScanLoginError::NotFound)?
            }
        };
        self.device_owner(hint, access, &target)?;
        let g = self.locked(tx, hint)?;
        let d = tx
            .lock_scan_delivery(&g.tenant_id, &g.id)?
            .ok_or(ScanLoginError::NotFound)?;
        if d.session_id != session.id
            || dh.session_id != d.session_id
            || session.tenant_id != g.tenant_id
            || session.account_id
                != g.source
                    .as_ref()
                    .ok_or(ScanLoginError::NotFound)?
                    .account_id
            || session.device_id.as_deref() != Some(target.device_id.as_str())
            || session.client_id != g.target_client_id
            || session.purpose != AccessTokenPurpose::Business
        {
            return Err(ScanLoginError::NotFound);
        }
        if d.state == ScanDeliveryState::Recoverable {
            let b = tx
                .scan_binding_snapshot(&g.tenant_id, &session.account_id, &target.device_id)?
                .ok_or(ScanLoginError::Invalidated)?;
            if b.id != d.binding_id
                || b.version != d.binding_version
                || b.status != AccountDeviceBindingStatus::Active
                || session.status != SessionStatus::Pending
            {
                return Err(ScanLoginError::Invalidated);
            }
        }
        Ok((g, d, session))
    }
    fn issue_and_release(
        &self,
        c: ExchangeScan,
        actor: ScanDeviceCall,
    ) -> Result<ScanDeliveryResult, ScanLoginError> {
        valid_uuid(&c.operation_id)?;
        let hint = self.hint(&actor.binding.tenant_id, &c.access.grant_id)?;
        if hint.state == ScanGrantState::Issued {
            return self.release(
                RecoverScan {
                    issuance_operation_id: c.operation_id,
                    access: c.access,
                },
                actor,
                ScanLoginAction::Exchange,
            );
        }
        self.auth.store.scan_transaction(self.auth.mode, |tx| {
            let source = hint.source.as_ref().ok_or(ScanLoginError::NotApproved)?;
            self.source(tx, &hint.tenant_id, source)?;
            let (target, _) = self.prove_at(
                tx,
                &actor,
                Some(&source.account_id),
                ScanLoginAction::Exchange,
                false,
            )?;
            self.device_owner(&hint, &c.access, &target)?;
            self.live(&hint)?;
            if hint.state != ScanGrantState::Approved
                || hint.approved_until.is_none_or(|until| until <= self.now())
            {
                return Err(ScanLoginError::NotApproved);
            }
            Ok(())
        })?;
        let fp = fingerprint(&[&c.access.grant_id]);
        let permit = self.admit(
            &hint,
            ScanAdmissionStage::Exchange,
            Some(&c.operation_id),
            &actor.host,
            fp,
        )?;
        let issued = self.auth.store.scan_transaction(self.auth.mode, |tx| {
            let source = hint.source.as_ref().ok_or(ScanLoginError::NotApproved)?;
            let source_session = self.source(tx, &hint.tenant_id, source)?;
            let (target, needs) = self.prove(
                tx,
                &actor,
                Some(&source.account_id),
                ScanLoginAction::Exchange,
            )?;
            self.device_owner(&hint, &c.access, &target)?;
            let mut g = tx
                .lock_scan_grant(&hint.tenant_id, &hint.id)?
                .ok_or(ScanLoginError::NotFound)?;
            if g.state == ScanGrantState::Issued {
                let d = tx
                    .lock_scan_delivery(&g.tenant_id, &g.id)?
                    .ok_or(ScanLoginError::NotFound)?;
                if d.issuance_operation_id != c.operation_id {
                    return Err(ScanLoginError::ExchangeAlreadyStarted(
                        d.issuance_operation_id,
                    ));
                }
                return Ok(g);
            }
            if g.version != hint.version {
                return Err(ScanLoginError::OperationConflict);
            }
            self.permit(&permit)?;
            self.live(&g)?;
            if source_session.expires_at <= self.now()
                || g.state != ScanGrantState::Approved
                || g.approved_until.is_none_or(|u| u <= self.now())
            {
                return Err(ScanLoginError::NotApproved);
            }
            let session_id = self.id("scan-session")?;
            if needs {
                tx.insert_login_binding(
                    &TenantProofBinding {
                        tenant_id: g.tenant_id.clone(),
                        account_id: source.account_id.clone(),
                        device_id: target.device_id.clone(),
                        status: AccountDeviceBindingStatus::Active,
                    },
                    &self.id("binding")?,
                    self.now(),
                    &session_id,
                    &self.id("audit")?,
                    &c.operation_id,
                )?;
            }
            let b = tx
                .scan_binding_snapshot(&g.tenant_id, &source.account_id, &target.device_id)?
                .ok_or(ScanLoginError::Invalidated)?;
            if b.status != AccountDeviceBindingStatus::Active {
                return Err(ScanLoginError::Invalidated);
            }
            let session = self.auth.issue_pending_scan_session(
                tx,
                &g.tenant_id,
                &source.account_id,
                &target.device_id,
                self.config.target_scope.clone(),
                source.authenticated_at,
                session_id.clone(),
            )?;
            let receipt = self.secret()?;
            let recover_until = (self.now()
                + Duration::from_secs(self.config.limits.recovery_ttl_secs as u64))
            .min(
                session
                    .tokens
                    .access_expires_at
                    .checked_sub(Duration::from_secs(1))
                    .ok_or(ScanLoginError::InvalidRequest)?,
            );
            if recover_until <= self.now() {
                return Err(ScanLoginError::ResultUnavailable);
            }
            let mut d = ScanDeliveryRecord {
                tenant_id: g.tenant_id.clone(),
                grant_id: g.id.clone(),
                issuance_operation_id: c.operation_id.clone(),
                session_id: session_id.clone(),
                state: ScanDeliveryState::Recoverable,
                binding_id: b.id,
                binding_version: b.version,
                result: None,
                receipt_nonce_hash: Some(Sha256::digest(decode_secret(&receipt)?).into()),
                recover_until,
                created_at: self.now(),
                release_authorized_at: None,
                acknowledged_at: None,
                revoked_at: None,
                reason: None,
            };
            let payload = encode_bundle(&session.tokens, &receipt)?;
            d.result = Some(
                self.cipher
                    .seal(&self.bundle_context(&g, &d)?, &payload)
                    .map_err(|_| ScanLoginError::ResultUnavailable)?,
            );
            g.state = ScanGrantState::Issued;
            g.presentation = None;
            self.update(tx, &mut g)?;
            tx.insert_scan_delivery(&d)?;
            self.record(
                tx,
                &g,
                &target.device_id,
                "device",
                "exchange",
                &c.operation_id,
                fp,
                Some(&permit),
                Some(&session_id),
            )?;
            Ok(g)
        })?;
        // The proof was consumed by the successful issue transaction. Only this
        // in-process continuation may release using its verified request capability.
        self.release_inner(
            RecoverScan {
                issuance_operation_id: c.operation_id,
                access: c.access,
            },
            actor,
            ScanLoginAction::Exchange,
            issued,
            false,
        )
    }
    fn release(
        &self,
        c: RecoverScan,
        actor: ScanDeviceCall,
        action: ScanLoginAction,
    ) -> Result<ScanDeliveryResult, ScanLoginError> {
        valid_uuid(&c.issuance_operation_id)?;
        let hint = self.hint(&actor.binding.tenant_id, &c.access.grant_id)?;
        self.release_inner(c, actor, action, hint, true)
    }
    fn release_inner(
        &self,
        c: RecoverScan,
        actor: ScanDeviceCall,
        action: ScanLoginAction,
        hint: ScanGrantRecord,
        verify: bool,
    ) -> Result<ScanDeliveryResult, ScanLoginError> {
        let (_, prepared, _) = self.auth.store.scan_transaction(self.auth.mode, |tx| {
            self.load_delivery(
                tx,
                &hint,
                &c.access,
                &actor,
                action,
                if verify { Some(false) } else { None },
            )
        })?;
        if prepared.issuance_operation_id != c.issuance_operation_id {
            return Err(ScanLoginError::ExchangeAlreadyStarted(
                prepared.issuance_operation_id,
            ));
        }
        if prepared.state == ScanDeliveryState::Acknowledged {
            return self.auth.store.scan_transaction(self.auth.mode, |tx| {
                let (g, d, _) = self.load_delivery(
                    tx,
                    &hint,
                    &c.access,
                    &actor,
                    action,
                    if verify { Some(true) } else { None },
                )?;
                Ok(ScanDeliveryResult::Progress(self.progress(&g, Some(&d))))
            });
        }
        if prepared.state == ScanDeliveryState::Revoked {
            return Err(ScanLoginError::DeliveryRevoked);
        }
        if !self.config.modes.contains(&hint.mode) {
            self.compensate_result(
                actor.host.clone(),
                hint.id.clone(),
                c.issuance_operation_id.clone(),
                self.id("compensation")?,
            )?;
            return Err(ScanLoginError::ModeDisabled);
        }
        let fp = fingerprint(&[&hint.id, &c.issuance_operation_id]);
        let permit = match self.admit(
            &hint,
            ScanAdmissionStage::ReleaseResult,
            Some(&c.issuance_operation_id),
            &actor.host,
            fp,
        ) {
            Ok(p) => p,
            Err(e @ ScanLoginError::AdmissionDenied) | Err(e @ ScanLoginError::ModeDisabled) => {
                self.compensate_result(
                    actor.host.clone(),
                    hint.id.clone(),
                    c.issuance_operation_id.clone(),
                    self.id("compensation")?,
                )?;
                return Err(e);
            }
            Err(e) => return Err(e),
        };
        self.auth.store.scan_transaction(self.auth.mode, |tx| {
            let (g, mut d, session) = self.load_delivery(
                tx,
                &hint,
                &c.access,
                &actor,
                action,
                if verify { Some(true) } else { None },
            )?;
            self.permit(&permit)?;
            if d.state == ScanDeliveryState::Acknowledged {
                return Ok(Ok(ScanDeliveryResult::Progress(
                    self.progress(&g, Some(&d)),
                )));
            }
            if d.state == ScanDeliveryState::Revoked {
                return Ok(Err(ScanLoginError::DeliveryRevoked));
            }
            if d.recover_until <= self.now() {
                self.revoke_delivery(tx, &g, &mut d, "expired")?;
                return Ok(Err(ScanLoginError::DeliveryExpired));
            }
            let plaintext = self
                .cipher
                .open(
                    &self.bundle_context(&g, &d)?,
                    d.result.as_ref().ok_or(ScanLoginError::ResultUnavailable)?,
                )
                .map_err(|_| ScanLoginError::ResultUnavailable)?;
            let (tokens, receipt) = decode_bundle(&plaintext)?;
            if tokens.access_expires_at <= self.now()
                || tokens.refresh_expires_at > session.expires_at
                || tokens.refresh_token_version != session.refresh_token_version
            {
                return Err(ScanLoginError::ResultUnavailable);
            }
            if d.release_authorized_at.is_none() {
                d.release_authorized_at = Some(self.now());
                tx.update_scan_delivery(&d, ScanDeliveryState::Recoverable)?;
                tx.append_scan_audit(&ScanAuditEvent {
                    id: self.id("scan-audit")?,
                    tenant_id: g.tenant_id.clone(),
                    host_scope: g.host_scope.clone(),
                    grant_id: g.id.clone(),
                    actor_kind: "device".into(),
                    actor_id: g.target.as_ref().map(|t| t.device_id.clone()),
                    operation: "release".into(),
                    operation_id: c.issuance_operation_id.clone(),
                    session_id: Some(d.session_id.clone()),
                    decision_id: match &permit {
                        ScanAdmissionDecision::Allow { decision_id, .. } => {
                            Some(decision_id.clone())
                        }
                        _ => None,
                    },
                    occurred_at: self.now(),
                })?;
            }
            Ok(Ok(ScanDeliveryResult::Bundle {
                progress: self.progress(&g, Some(&d)),
                session: TenantLoginSession { session, tokens },
                receipt_nonce: receipt,
            }))
        })?
    }
    fn activate(
        &self,
        c: AcknowledgeScan,
        actor: ScanDeviceCall,
    ) -> Result<ScanProgress, ScanLoginError> {
        valid_uuid(&c.operation_id)?;
        valid_uuid(&c.issuance_operation_id)?;
        let hint = self.hint(&actor.binding.tenant_id, &c.access.grant_id)?;
        let (_, d, _) = self.auth.store.scan_transaction(self.auth.mode, |tx| {
            self.load_delivery(
                tx,
                &hint,
                &c.access,
                &actor,
                ScanLoginAction::Acknowledge,
                Some(false),
            )
        })?;
        if d.issuance_operation_id != c.issuance_operation_id {
            return Err(ScanLoginError::NotFound);
        }
        let receipt_hash: [u8; 32] = Sha256::digest(decode_secret(&c.receipt_nonce)?).into();
        let fp = fingerprint(&[
            &c.access.grant_id,
            &c.issuance_operation_id,
            &Base64UrlUnpadded::encode_string(&receipt_hash),
        ]);
        let permit = if d.state == ScanDeliveryState::Acknowledged {
            None
        } else {
            match self.admit(
                &hint,
                ScanAdmissionStage::ActivateSession,
                Some(&c.issuance_operation_id),
                &actor.host,
                fp,
            ) {
                Ok(p) => Some(p),
                Err(e @ ScanLoginError::AdmissionDenied)
                | Err(e @ ScanLoginError::ModeDisabled) => {
                    self.compensate_result(
                        actor.host.clone(),
                        hint.id.clone(),
                        c.issuance_operation_id.clone(),
                        self.id("compensation")?,
                    )?;
                    return Err(e);
                }
                Err(e) => return Err(e),
            }
        };
        self.auth.store.scan_transaction(self.auth.mode, |tx| {
            let (g, mut d, _) = self.load_delivery(
                tx,
                &hint,
                &c.access,
                &actor,
                ScanLoginAction::Acknowledge,
                Some(true),
            )?;
            let device = &g.target.as_ref().ok_or(ScanLoginError::NotFound)?.device_id;
            if self.operation(tx, &g, device, "acknowledge", &c.operation_id, fp)? {
                return Ok(Ok(self.progress(&g, Some(&d))));
            }
            if d.state == ScanDeliveryState::Acknowledged {
                return Ok(Ok(self.progress(&g, Some(&d))));
            }
            if d.state == ScanDeliveryState::Revoked {
                return Ok(Err(ScanLoginError::DeliveryRevoked));
            }
            if d.recover_until <= self.now() {
                self.revoke_delivery(tx, &g, &mut d, "expired")?;
                return Ok(Err(ScanLoginError::DeliveryExpired));
            }
            self.permit(
                permit
                    .as_ref()
                    .ok_or(ScanLoginError::AdmissionUnavailable)?,
            )?;
            if d.release_authorized_at.is_none() || d.receipt_nonce_hash != Some(receipt_hash) {
                return Err(ScanLoginError::NotFound);
            }
            tx.activate_scan_session(&g.tenant_id, &d.session_id)?;
            d.state = ScanDeliveryState::Acknowledged;
            d.acknowledged_at = Some(self.now());
            d.result = None;
            d.receipt_nonce_hash = None;
            tx.update_scan_delivery(&d, ScanDeliveryState::Recoverable)?;
            self.record(
                tx,
                &g,
                device,
                "device",
                "acknowledge",
                &c.operation_id,
                fp,
                permit.as_ref(),
                Some(&d.session_id),
            )?;
            Ok(Ok(self.progress(&g, Some(&d))))
        })?
    }
    fn revoke_delivery(
        &self,
        tx: &mut impl TenantScanLoginTransaction,
        g: &ScanGrantRecord,
        d: &mut ScanDeliveryRecord,
        reason: &str,
    ) -> Result<(), ScanLoginError> {
        if d.state == ScanDeliveryState::Acknowledged {
            return Err(ScanLoginError::AlreadyAcknowledged);
        }
        if d.state == ScanDeliveryState::Revoked {
            return Ok(());
        }
        tx.revoke_scan_session(&g.tenant_id, &d.session_id, self.now())?;
        d.state = ScanDeliveryState::Revoked;
        d.result = None;
        d.receipt_nonce_hash = None;
        d.revoked_at = Some(self.now());
        d.reason = Some(reason.into());
        tx.update_scan_delivery(d, ScanDeliveryState::Recoverable)?;
        Ok(())
    }
    fn abort(
        &self,
        c: AbortScanDelivery,
        actor: ScanDeviceCall,
    ) -> Result<ScanProgress, ScanLoginError> {
        valid_uuid(&c.operation_id)?;
        valid_uuid(&c.issuance_operation_id)?;
        let hint = self.hint(&actor.binding.tenant_id, &c.access.grant_id)?;
        let fp = fingerprint(&[&c.access.grant_id, &c.issuance_operation_id]);
        self.auth.store.scan_transaction(self.auth.mode, |tx| {
            let (g, mut d, _) = self.load_delivery(
                tx,
                &hint,
                &c.access,
                &actor,
                ScanLoginAction::Abort,
                Some(true),
            )?;
            if d.issuance_operation_id != c.issuance_operation_id {
                return Err(ScanLoginError::NotFound);
            }
            let device = &g.target.as_ref().ok_or(ScanLoginError::NotFound)?.device_id;
            if self.operation(tx, &g, device, "abort", &c.operation_id, fp)? {
                return Ok(self.progress(&g, Some(&d)));
            }
            self.revoke_delivery(tx, &g, &mut d, "aborted")?;
            self.record(
                tx,
                &g,
                device,
                "device",
                "abort",
                &c.operation_id,
                fp,
                None,
                Some(&d.session_id),
            )?;
            Ok(self.progress(&g, Some(&d)))
        })
    }
    fn compensate_result(
        &self,
        host: TrustedScanHostContext,
        grant_id: String,
        issuance: String,
        op: String,
    ) -> Result<ScanProgress, ScanLoginError> {
        self.host(&host)?;
        valid_uuid(&grant_id)?;
        valid_uuid(&issuance)?;
        valid_uuid(&op)?;
        let tenant = self.auth.store.scan_transaction(self.auth.mode, |tx| {
            tx.scan_grant_tenant(&self.config.host_scope, &self.config.entry_id, &grant_id)?
                .ok_or(ScanLoginError::NotFound)
        })?;
        let hint = self.hint(&tenant, &grant_id)?;
        self.auth.store.scan_transaction(self.auth.mode, |tx| {
            tx.lock_tenants(&[tenant.clone()])?;
            if let Some(source) = &hint.source {
                tx.lock_account(&source.account_id)?;
            }
            let dh = tx
                .find_scan_delivery(&tenant, &grant_id)?
                .ok_or(ScanLoginError::NotFound)?;
            tx.lock_refresh_session(&tenant, &dh.session_id)?;
            let g = self.locked(tx, &hint)?;
            let mut d = tx
                .lock_scan_delivery(&tenant, &grant_id)?
                .ok_or(ScanLoginError::NotFound)?;
            if d.issuance_operation_id != issuance {
                return Err(ScanLoginError::NotFound);
            }
            let fp = fingerprint(&[&grant_id, &issuance]);
            if self.operation(tx, &g, &grant_id, "compensate", &op, fp)? {
                return Ok(self.progress(&g, Some(&d)));
            }
            self.revoke_delivery(tx, &g, &mut d, "host_denied")?;
            self.record(
                tx,
                &g,
                &grant_id,
                "host",
                "compensate",
                &op,
                fp,
                None,
                Some(&d.session_id),
            )?;
            Ok(self.progress(&g, Some(&d)))
        })
    }
    fn cleanup_results(
        &self,
        host: TrustedScanHostContext,
        limit: u32,
    ) -> Result<u32, ScanLoginError> {
        self.host(&host)?;
        if limit == 0 || limit > 100 {
            return Err(ScanLoginError::InvalidRequest);
        }
        let hints = self.auth.store.scan_transaction(self.auth.mode, |tx| {
            Ok(tx.expired_scan_deliveries(
                &self.config.host_scope,
                &self.config.entry_id,
                self.now(),
                limit,
            )?)
        })?;
        let mut count = 0;
        for hint in hints {
            let changed = self.auth.store.scan_transaction(self.auth.mode, |tx| {
                tx.lock_tenants(&[hint.tenant_id.clone()])?;
                if let Some(s) = &hint.source {
                    tx.lock_account(&s.account_id)?;
                }
                if let Some(d) = tx.find_scan_delivery(&hint.tenant_id, &hint.id)? {
                    tx.lock_refresh_session(&hint.tenant_id, &d.session_id)?;
                }
                let mut g = tx
                    .lock_scan_grant(&hint.tenant_id, &hint.id)?
                    .ok_or(ScanLoginError::NotFound)?;
                let mut d = tx.lock_scan_delivery(&g.tenant_id, &g.id)?;
                let changed = if let Some(d) = d.as_mut() {
                    if d.state == ScanDeliveryState::Recoverable && d.recover_until <= self.now() {
                        self.revoke_delivery(tx, &g, d, "expired")?;
                        true
                    } else {
                        false
                    }
                } else if g.state != ScanGrantState::Issued
                    && (g.expires_at <= self.now()
                        || (g.state == ScanGrantState::Approved
                            && g.approved_until.is_some_and(|u| u <= self.now()))
                        || (g.state == ScanGrantState::WaitingDevice
                            && g.code_expires_at <= self.now()))
                    && matches!(
                        g.state,
                        ScanGrantState::WaitingUser
                            | ScanGrantState::WaitingDevice
                            | ScanGrantState::AwaitingApproval
                            | ScanGrantState::Approved
                    )
                {
                    g.state = ScanGrantState::Expired;
                    g.presentation = None;
                    self.update(tx, &mut g)?;
                    true
                } else {
                    false
                };
                if changed {
                    tx.append_scan_audit(&ScanAuditEvent {
                        id: self.id("scan-audit")?,
                        tenant_id: g.tenant_id.clone(),
                        host_scope: g.host_scope.clone(),
                        grant_id: g.id.clone(),
                        actor_kind: "system".into(),
                        actor_id: None,
                        operation: "expired".into(),
                        operation_id: self.id("cleanup")?,
                        session_id: d.map(|d| d.session_id),
                        decision_id: None,
                        occurred_at: self.now(),
                    })?;
                }
                Ok(changed)
            })?;
            if changed {
                count += 1;
            }
        }
        Ok(count)
    }
}

fn valid_uuid(s: &str) -> Result<(), ScanLoginError> {
    if uuid::Uuid::parse_str(s).is_ok_and(|u| !u.is_nil() && u.hyphenated().to_string() == s) {
        Ok(())
    } else {
        Err(ScanLoginError::InvalidRequest)
    }
}
fn decode_secret(s: &SecretString) -> Result<[u8; 32], ScanLoginError> {
    let raw = s.expose_secret();
    if raw.len() != 43 {
        return Err(ScanLoginError::InvalidRequest);
    }
    let bytes: [u8; 32] = Base64UrlUnpadded::decode_vec(raw)
        .map_err(|_| ScanLoginError::InvalidRequest)?
        .try_into()
        .map_err(|_| ScanLoginError::InvalidRequest)?;
    if Base64UrlUnpadded::encode_string(&bytes) != raw {
        return Err(ScanLoginError::InvalidRequest);
    }
    Ok(bytes)
}
fn fingerprint(parts: &[&str]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"EMBEDDED-IDP-SCAN-OPERATION-V1\n");
    for p in parts {
        h.update((p.len() as u64).to_be_bytes());
        h.update(p.as_bytes());
    }
    h.finalize().into()
}
fn epoch(t: SystemTime) -> Result<u64, ScanLoginError> {
    t.duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| ScanLoginError::InvalidRequest)
}
fn encode_bundle(
    tokens: &IssuedTokenBundle,
    receipt: &SecretString,
) -> Result<SecretString, ScanLoginError> {
    let mut s = "EMBEDDED-IDP-SCAN-BUNDLE-V1\n".to_owned();
    for p in [
        tokens.access_token.expose_secret(),
        tokens.refresh_token.expose_secret(),
        receipt.expose_secret(),
        &epoch(tokens.access_expires_at)?.to_string(),
        &epoch(tokens.refresh_expires_at)?.to_string(),
        &tokens.refresh_token_version.to_string(),
    ] {
        s.push_str(&format!("{}:", p.len()));
        s.push_str(p);
    }
    Ok(SecretString::new(s))
}
fn decode_bundle(
    plaintext: &SecretString,
) -> Result<(IssuedTokenBundle, SecretString), ScanLoginError> {
    let mut rest = plaintext
        .expose_secret()
        .strip_prefix("EMBEDDED-IDP-SCAN-BUNDLE-V1\n")
        .ok_or(ScanLoginError::ResultUnavailable)?;
    let mut parts = Vec::new();
    for _ in 0..6 {
        let (len, r) = rest
            .split_once(':')
            .ok_or(ScanLoginError::ResultUnavailable)?;
        let n: usize = len.parse().map_err(|_| ScanLoginError::ResultUnavailable)?;
        let value = r.get(..n).ok_or(ScanLoginError::ResultUnavailable)?;
        rest = r.get(n..).ok_or(ScanLoginError::ResultUnavailable)?;
        parts.push(value);
    }
    if !rest.is_empty() {
        return Err(ScanLoginError::ResultUnavailable);
    }
    let time = |s: &str| -> Result<SystemTime, ScanLoginError> {
        UNIX_EPOCH
            .checked_add(Duration::from_secs(
                s.parse().map_err(|_| ScanLoginError::ResultUnavailable)?,
            ))
            .ok_or(ScanLoginError::ResultUnavailable)
    };
    Ok((
        IssuedTokenBundle {
            access_token: SecretString::new(parts[0]),
            refresh_token: SecretString::new(parts[1]),
            access_expires_at: time(parts[3])?,
            refresh_expires_at: time(parts[4])?,
            refresh_token_version: parts[5]
                .parse()
                .map_err(|_| ScanLoginError::ResultUnavailable)?,
        },
        SecretString::new(parts[2]),
    ))
}

impl<S, T, G, D, C, I, J, V, N, K, Z> TenantDeviceScanLoginService
    for CoreTenantDeviceScanLoginService<
        CoreTenantAuthenticationService<S, T, G, D, C, I>,
        CoreTenantDeviceProofService<S, J, V, N, K, Z>,
    >
where
    S: TenantScanLoginStore,
    for<'a> S::Transaction<'a>: TenantScanLoginTransaction,
    T: TokenIssuer + AccessTokenValidator + ScopedAccessTokenIssuer + Send + Sync,
    G: RefreshTokenGenerator + Send + Sync,
    D: RefreshTokenDigester + Send + Sync,
    C: Clock + Send + Sync,
    I: IdGenerator + Send + Sync,
    J: DevicePublicJwkValidator + Send + Sync,
    V: DeviceSignatureVerifier + Send + Sync,
    N: DeviceChallengeGenerator + Send + Sync,
    K: Clock + Send + Sync,
    Z: IdGenerator + Send + Sync,
{
    fn entry_config(&self) -> ScanLoginEntryConfig {
        self.config.clone()
    }
    fn create_device(
        &self,
        c: CreateDeviceScan,
        actor: ScanDeviceCall,
    ) -> Result<CreatedDeviceScan, ScanLoginError> {
        valid_uuid(&c.operation_id)?;
        if c.entry_id != self.config.entry_id
            || c.tenant_id != actor.binding.tenant_id
            || !self.config.modes.contains(&ScanLoginMode::DeviceDisplay)
        {
            return Err(ScanLoginError::ModeDisabled);
        }
        let fp = fingerprint(&[
            &c.entry_id,
            &c.tenant_id,
            &Base64UrlUnpadded::encode_string(&c.delivery_secret_hash),
        ]);
        let g = self.auth.store.scan_transaction(self.auth.mode, |tx| {
            let (target, _) = self.prove_at(tx, &actor, None, ScanLoginAction::Create, false)?;
            self.origin_open(
                tx,
                &c.tenant_id,
                &c.entry_id,
                &target.device_id,
                ScanOriginAction::Create,
                &c.operation_id,
                &c.delivery_secret_hash,
            )?;
            if let Some(op) = tx.find_scan_operation(
                &c.tenant_id,
                &self.config.host_scope,
                &c.entry_id,
                &target.device_id,
                "create",
                &c.operation_id,
            )? {
                if op.fingerprint != fp {
                    return Err(ScanLoginError::OperationConflict);
                }
                return tx
                    .find_scan_grant(
                        &c.tenant_id,
                        &self.config.host_scope,
                        &c.entry_id,
                        &op.grant_id,
                    )?
                    .ok_or(ScanLoginError::NotFound);
            }
            Ok(ScanGrantRecord {
                tenant_id: c.tenant_id.clone(),
                host_scope: self.config.host_scope.clone(),
                entry_id: c.entry_id.clone(),
                id: self.id("scan-grant")?,
                mode: ScanLoginMode::DeviceDisplay,
                target_client_id: self.config.target_client_id.clone(),
                state: ScanGrantState::WaitingUser,
                version: 1,
                source: None,
                target: Some(target),
                code_digest: [0; 32],
                presentation: None,
                delivery_secret_hash: Some(c.delivery_secret_hash),
                confirmation_revision: None,
                created_at: self.now(),
                expires_at: self.now()
                    + Duration::from_secs(self.config.limits.grant_ttl_secs as u64),
                code_expires_at: self.now()
                    + Duration::from_secs(self.config.limits.grant_ttl_secs as u64),
                approved_until: None,
            })
        })?;
        let permit = self.admit(
            &g,
            ScanAdmissionStage::CreateDevice,
            Some(&c.operation_id),
            &actor.host,
            fp,
        )?;
        self.auth.store.scan_transaction(self.auth.mode, |tx| {
            let (target, _) = self.prove(tx, &actor, None, ScanLoginAction::Create)?;
            self.origin_open(
                tx,
                &c.tenant_id,
                &c.entry_id,
                &target.device_id,
                ScanOriginAction::Create,
                &c.operation_id,
                &c.delivery_secret_hash,
            )?;
            self.permit(&permit)?;
            if let Some(op) = tx.find_scan_operation(
                &c.tenant_id,
                &g.host_scope,
                &g.entry_id,
                &target.device_id,
                "create",
                &c.operation_id,
            )? {
                if op.fingerprint != fp {
                    return Err(ScanLoginError::OperationConflict);
                }
                let old = tx
                    .lock_scan_grant(&c.tenant_id, &op.grant_id)?
                    .ok_or(ScanLoginError::NotFound)?;
                self.live(&old)?;
                let code = self
                    .cipher
                    .open(
                        &self.code_context(&old, &c.operation_id)?,
                        old.presentation
                            .as_ref()
                            .ok_or(ScanLoginError::AlreadyClaimed)?,
                    )
                    .map_err(|_| ScanLoginError::ResultUnavailable)?;
                return Ok(CreatedDeviceScan {
                    progress: self.progress(&old, None),
                    display_code: code,
                });
            }
            if g.target.as_ref() != Some(&target) {
                return Err(ScanLoginError::Invalidated);
            }
            if tx.pending_scan_count(
                &g.tenant_id,
                &g.host_scope,
                &g.entry_id,
                None,
                Some(&target.device_id),
                self.now(),
            )? >= 1
            {
                return Err(ScanLoginError::RateLimited);
            }
            let mut g = g;
            let code = SecretString::new(format!("D1.{}", self.secret()?.expose_secret()));
            g.code_digest = Sha256::digest(code.expose_secret().as_bytes()).into();
            g.presentation = Some(
                self.cipher
                    .seal(&self.code_context(&g, &c.operation_id)?, &code)
                    .map_err(|_| ScanLoginError::ResultUnavailable)?,
            );
            tx.insert_scan_grant(&g)?;
            self.record(
                tx,
                &g,
                &target.device_id,
                "device",
                "create",
                &c.operation_id,
                fp,
                Some(&permit),
                None,
            )?;
            Ok(CreatedDeviceScan {
                progress: self.progress(&g, None),
                display_code: code,
            })
        })
    }
    fn issue_phone(
        &self,
        c: IssuePhoneScan,
        actor: ScanSourceCall,
    ) -> Result<IssuedPhoneScan, ScanLoginError> {
        valid_uuid(&c.operation_id)?;
        let source = self.source_call(&actor)?;
        if c.entry_id != self.config.entry_id
            || !self.config.modes.contains(&ScanLoginMode::PhoneDisplay)
        {
            return Err(ScanLoginError::ModeDisabled);
        }
        let fp = fingerprint(&[&c.entry_id, &source.session_id]);
        let tenant = actor.source.tenant_id();
        let g = self.auth.store.scan_transaction(self.auth.mode, |tx| {
            self.source(tx, tenant, &source)?;
            if let Some(op) = tx.find_scan_operation(
                tenant,
                &self.config.host_scope,
                &c.entry_id,
                &source.session_id,
                "issue_phone",
                &c.operation_id,
            )? {
                if op.fingerprint != fp {
                    return Err(ScanLoginError::OperationConflict);
                }
                return tx
                    .find_scan_grant(tenant, &self.config.host_scope, &c.entry_id, &op.grant_id)?
                    .ok_or(ScanLoginError::NotFound);
            }
            Ok(ScanGrantRecord {
                tenant_id: tenant.into(),
                host_scope: self.config.host_scope.clone(),
                entry_id: c.entry_id.clone(),
                id: self.id("scan-grant")?,
                mode: ScanLoginMode::PhoneDisplay,
                target_client_id: self.config.target_client_id.clone(),
                state: ScanGrantState::WaitingDevice,
                version: 1,
                source: Some(source.clone()),
                target: None,
                code_digest: [0; 32],
                presentation: None,
                delivery_secret_hash: None,
                confirmation_revision: None,
                created_at: self.now(),
                expires_at: self.now()
                    + Duration::from_secs(self.config.limits.grant_ttl_secs as u64),
                code_expires_at: self.now()
                    + Duration::from_secs(self.config.limits.phone_code_ttl_secs as u64),
                approved_until: None,
            })
        })?;
        let permit = self.admit(
            &g,
            ScanAdmissionStage::IssuePhoneCode,
            Some(&c.operation_id),
            &actor.host,
            fp,
        )?;
        self.auth.store.scan_transaction(self.auth.mode, |tx| {
            self.source(tx, tenant, &source)?;
            self.permit(&permit)?;
            if let Some(op) = tx.find_scan_operation(
                tenant,
                &g.host_scope,
                &g.entry_id,
                &source.session_id,
                "issue_phone",
                &c.operation_id,
            )? {
                if op.fingerprint != fp {
                    return Err(ScanLoginError::OperationConflict);
                }
                let old = tx
                    .lock_scan_grant(tenant, &op.grant_id)?
                    .ok_or(ScanLoginError::NotFound)?;
                self.live(&old)?;
                if old.code_expires_at <= self.now() {
                    return Err(ScanLoginError::Expired);
                }
                let code = self
                    .cipher
                    .open(
                        &self.code_context(&old, &c.operation_id)?,
                        old.presentation
                            .as_ref()
                            .ok_or(ScanLoginError::AlreadyClaimed)?,
                    )
                    .map_err(|_| ScanLoginError::ResultUnavailable)?;
                return Ok(IssuedPhoneScan {
                    progress: self.progress(&old, None),
                    scan_code: code,
                    code_expires_at: old.code_expires_at,
                });
            }
            if tx.pending_scan_count(
                tenant,
                &g.host_scope,
                &g.entry_id,
                Some(&source.session_id),
                None,
                self.now(),
            )? >= 3
            {
                return Err(ScanLoginError::RateLimited);
            }
            let mut g = g;
            let raw = decode_secret(&self.secret()?)?;
            let code = SecretString::new(format!(
                "P1.{}",
                Base64UrlUnpadded::encode_string(&raw[..16])
            ));
            g.code_digest = Sha256::digest(code.expose_secret().as_bytes()).into();
            g.presentation = Some(
                self.cipher
                    .seal(&self.code_context(&g, &c.operation_id)?, &code)
                    .map_err(|_| ScanLoginError::ResultUnavailable)?,
            );
            tx.insert_scan_grant(&g)?;
            self.record(
                tx,
                &g,
                &source.session_id,
                "person",
                "issue_phone",
                &c.operation_id,
                fp,
                Some(&permit),
                Some(&source.session_id),
            )?;
            Ok(IssuedPhoneScan {
                progress: self.progress(&g, None),
                scan_code: code,
                code_expires_at: g.code_expires_at,
            })
        })
    }
    fn attach_source(
        &self,
        c: AttachScanSource,
        actor: ScanSourceCall,
    ) -> Result<ScanConfirmation, ScanLoginError> {
        valid_uuid(&c.operation_id)?;
        valid_code(&c.display_code, "D1.", 32)?;
        let source = self.source_call(&actor)?;
        let digest = Sha256::digest(c.display_code.expose_secret().as_bytes()).into();
        let mut hint = self.auth.store.scan_transaction(self.auth.mode, |tx| {
            self.source(tx, actor.source.tenant_id(), &source)?;
            let g = tx
                .find_scan_code(
                    Some(actor.source.tenant_id()),
                    &self.config.host_scope,
                    &self.config.entry_id,
                    &digest,
                )?
                .ok_or(ScanLoginError::NotFound)?;
            self.target_snapshot(tx, &g)?;
            Ok(g)
        })?;
        let original = hint.clone();
        if hint.source.is_some() && hint.source.as_ref() != Some(&source) {
            return Err(ScanLoginError::AlreadyClaimed);
        }
        hint.source = Some(source.clone());
        let fp = fingerprint(&[c.display_code.expose_secret(), &source.session_id]);
        let permit = self.admit(
            &hint,
            ScanAdmissionStage::AttachSource,
            Some(&c.operation_id),
            &actor.host,
            fp,
        )?;
        self.auth
            .store
            .scan_transaction(self.auth.mode, |tx| {
                self.source(tx, &original.tenant_id, &source)?;
                self.target_snapshot(tx, &original)?;
                let mut g = self.locked(tx, &original)?;
                self.permit(&permit)?;
                self.live(&g)?;
                if self.operation(tx, &g, &source.session_id, "attach", &c.operation_id, fp)? {
                    return Ok(g.id);
                }
                if g.mode != ScanLoginMode::DeviceDisplay
                    || g.state != ScanGrantState::WaitingUser
                    || g.code_expires_at <= self.now()
                {
                    return Err(ScanLoginError::AlreadyClaimed);
                }
                g.source = Some(source.clone());
                g.state = ScanGrantState::AwaitingApproval;
                g.presentation = None;
                self.update(tx, &mut g)?;
                self.record(
                    tx,
                    &g,
                    &source.session_id,
                    "person",
                    "attach",
                    &c.operation_id,
                    fp,
                    Some(&permit),
                    Some(&source.session_id),
                )?;
                Ok(g.id)
            })
            .and_then(|id| self.inspect(id, actor))
    }
    fn claim_target(
        &self,
        c: ClaimScanTarget,
        actor: ScanDeviceCall,
    ) -> Result<ScanProgress, ScanLoginError> {
        valid_uuid(&c.operation_id)?;
        valid_code(&c.scan_code, "P1.", 16)?;
        if c.entry_id != self.config.entry_id || c.tenant_id != actor.binding.tenant_id {
            return Err(ScanLoginError::InvalidRequest);
        }
        self.auth.store.scan_transaction(self.auth.mode, |tx| {
            let (target, _) = self.prove_at(tx, &actor, None, ScanLoginAction::Claim, false)?;
            self.origin_open(
                tx,
                &c.tenant_id,
                &c.entry_id,
                &target.device_id,
                ScanOriginAction::Claim,
                &c.operation_id,
                &c.delivery_secret_hash,
            )
        })?;
        let digest = Sha256::digest(c.scan_code.expose_secret().as_bytes()).into();
        let (hint, target) = self.auth.store.scan_transaction(self.auth.mode, |tx| {
            let g = tx
                .find_scan_code(
                    Some(&c.tenant_id),
                    &self.config.host_scope,
                    &c.entry_id,
                    &digest,
                )?
                .ok_or(ScanLoginError::NotFound)?;
            self.source(
                tx,
                &c.tenant_id,
                g.source.as_ref().ok_or(ScanLoginError::NotFound)?,
            )?;
            let (target, _) = self.prove_at(
                tx,
                &actor,
                g.source.as_ref().map(|s| s.account_id.as_str()),
                ScanLoginAction::Claim,
                false,
            )?;
            Ok((g, target))
        })?;
        let mut candidate = hint.clone();
        candidate.target = Some(target.clone());
        let fp = fingerprint(&[
            c.scan_code.expose_secret(),
            &target.device_id,
            &Base64UrlUnpadded::encode_string(&c.delivery_secret_hash),
        ]);
        let permit = self.admit(
            &candidate,
            ScanAdmissionStage::ClaimTarget,
            Some(&c.operation_id),
            &actor.host,
            fp,
        )?;
        self.auth.store.scan_transaction(self.auth.mode, |tx| {
            self.source(
                tx,
                &hint.tenant_id,
                hint.source.as_ref().ok_or(ScanLoginError::NotFound)?,
            )?;
            let (t, _) = self.prove(
                tx,
                &actor,
                hint.source.as_ref().map(|s| s.account_id.as_str()),
                ScanLoginAction::Claim,
            )?;
            self.origin_open(
                tx,
                &c.tenant_id,
                &c.entry_id,
                &t.device_id,
                ScanOriginAction::Claim,
                &c.operation_id,
                &c.delivery_secret_hash,
            )?;
            let mut g = self.locked(tx, &hint)?;
            self.permit(&permit)?;
            self.live(&g)?;
            if self.operation(tx, &g, &t.device_id, "claim", &c.operation_id, fp)? {
                return Ok(self.progress(&g, tx.lock_scan_delivery(&g.tenant_id, &g.id)?.as_ref()));
            }
            if g.mode != ScanLoginMode::PhoneDisplay
                || g.state != ScanGrantState::WaitingDevice
                || g.target.is_some()
            {
                return Err(ScanLoginError::AlreadyClaimed);
            }
            if g.code_expires_at <= self.now() {
                return Err(ScanLoginError::Expired);
            }
            if t != target {
                return Err(ScanLoginError::Invalidated);
            }
            if tx.pending_scan_count(
                &g.tenant_id,
                &g.host_scope,
                &g.entry_id,
                None,
                Some(&t.device_id),
                self.now(),
            )? >= 1
            {
                return Err(ScanLoginError::RateLimited);
            }
            g.target = Some(t.clone());
            g.delivery_secret_hash = Some(c.delivery_secret_hash);
            g.presentation = None;
            g.state = ScanGrantState::AwaitingApproval;
            self.update(tx, &mut g)?;
            self.record(
                tx,
                &g,
                &t.device_id,
                "device",
                "claim",
                &c.operation_id,
                fp,
                Some(&permit),
                None,
            )?;
            Ok(self.progress(&g, None))
        })
    }
    fn inspect(
        &self,
        grant_id: String,
        actor: ScanSourceCall,
    ) -> Result<ScanConfirmation, ScanLoginError> {
        let source = self.source_call(&actor)?;
        let hint = self.hint(actor.source.tenant_id(), &grant_id)?;
        self.owner(&hint, &source)?;
        let permit = self.admit(
            &hint,
            ScanAdmissionStage::InspectConfirmation,
            None,
            &actor.host,
            [0; 32],
        )?;
        let (p, rev) = self.presentation(&hint, &actor.host)?;
        self.auth.store.scan_transaction(self.auth.mode, |tx| {
            self.source(tx, &hint.tenant_id, &source)?;
            self.target_snapshot(tx, &hint)?;
            let g = self.locked(tx, &hint)?;
            self.permit(&permit)?;
            self.live(&g)?;
            Ok(ScanConfirmation {
                progress: self.progress(&g, tx.lock_scan_delivery(&g.tenant_id, &g.id)?.as_ref()),
                source,
                source_display_name: tx.scan_account_label(&actor.source.account_id())?,
                target: g.target.clone().ok_or(ScanLoginError::NotFound)?,
                presentation: p,
                confirmation_revision: rev,
            })
        })
    }
    fn approve(
        &self,
        c: ApproveScan,
        actor: ScanSourceCall,
    ) -> Result<ScanProgress, ScanLoginError> {
        valid_uuid(&c.action.operation_id)?;
        let source = self.source_call(&actor)?;
        let hint = self.hint(actor.source.tenant_id(), &c.action.grant_id)?;
        self.owner(&hint, &source)?;
        let fp = fingerprint(&[&c.action.grant_id, &c.confirmation_revision]);
        let permit = self.admit(
            &hint,
            ScanAdmissionStage::Approve,
            Some(&c.action.operation_id),
            &actor.host,
            fp,
        )?;
        let (_, revision) = self.presentation(&hint, &actor.host)?;
        self.auth.store.scan_transaction(self.auth.mode, |tx| {
            self.source(tx, &hint.tenant_id, &source)?;
            self.target_snapshot(tx, &hint)?;
            let mut g = self.locked(tx, &hint)?;
            self.permit(&permit)?;
            self.live(&g)?;
            if self.operation(
                tx,
                &g,
                &source.session_id,
                "approve",
                &c.action.operation_id,
                fp,
            )? {
                return Ok(self.progress(&g, tx.lock_scan_delivery(&g.tenant_id, &g.id)?.as_ref()));
            }
            if g.state != ScanGrantState::AwaitingApproval {
                return Err(ScanLoginError::NotApproved);
            }
            if c.confirmation_revision != revision {
                return Err(ScanLoginError::ConfirmationChanged);
            }
            g.state = ScanGrantState::Approved;
            g.confirmation_revision = Some(revision);
            g.approved_until = Some(
                (self.now() + Duration::from_secs(self.config.limits.approval_ttl_secs as u64))
                    .min(g.expires_at),
            );
            self.update(tx, &mut g)?;
            self.record(
                tx,
                &g,
                &source.session_id,
                "person",
                "approve",
                &c.action.operation_id,
                fp,
                Some(&permit),
                Some(&source.session_id),
            )?;
            Ok(self.progress(&g, None))
        })
    }
    fn deny(
        &self,
        c: SourceGrantAction,
        actor: ScanSourceCall,
    ) -> Result<ScanProgress, ScanLoginError> {
        self.finish_source(c, actor, true)
    }
    fn cancel_source(
        &self,
        c: SourceGrantAction,
        actor: ScanSourceCall,
    ) -> Result<ScanProgress, ScanLoginError> {
        self.finish_source(c, actor, false)
    }
    fn cancel_device(
        &self,
        c: CancelDeviceScan,
        actor: ScanDeviceCall,
    ) -> Result<ScanProgress, ScanLoginError> {
        valid_uuid(&c.operation_id)?;
        let hint = self.hint(&actor.binding.tenant_id, &c.access.grant_id)?;
        let fp = fingerprint(&[&c.access.grant_id]);
        self.auth.store.scan_transaction(self.auth.mode, |tx| {
            self.target_account(tx, &hint)?;
            let (target, _) = self.prove(tx, &actor, None, ScanLoginAction::Cancel)?;
            self.device_owner(&hint, &c.access, &target)?;
            let mut g = self.locked(tx, &hint)?;
            if self.operation(tx, &g, &target.device_id, "cancel", &c.operation_id, fp)? {
                return Ok(self.progress(&g, None));
            }
            if g.state == ScanGrantState::Issued {
                return Err(ScanLoginError::AlreadyIssued);
            }
            if matches!(
                g.state,
                ScanGrantState::Denied
                    | ScanGrantState::Cancelled
                    | ScanGrantState::Expired
                    | ScanGrantState::Invalidated
            ) {
                return Ok(self.progress(&g, None));
            }
            g.state = ScanGrantState::Cancelled;
            g.presentation = None;
            self.update(tx, &mut g)?;
            self.record(
                tx,
                &g,
                &target.device_id,
                "device",
                "cancel",
                &c.operation_id,
                fp,
                None,
                None,
            )?;
            Ok(self.progress(&g, None))
        })
    }
    fn source_status(
        &self,
        grant_id: String,
        actor: ScanSourceCall,
    ) -> Result<ScanProgress, ScanLoginError> {
        let source = self.source_call(&actor)?;
        let hint = self.hint(actor.source.tenant_id(), &grant_id)?;
        self.owner(&hint, &source)?;
        self.auth.store.scan_transaction(self.auth.mode, |tx| {
            self.source(tx, &hint.tenant_id, &source)?;
            let g = self.locked(tx, &hint)?;
            let d = tx.lock_scan_delivery(&g.tenant_id, &g.id)?;
            Ok(self.progress(&g, d.as_ref()))
        })
    }
    fn device_status(
        &self,
        c: DeviceGrantAccess,
        actor: ScanDeviceCall,
    ) -> Result<ScanProgress, ScanLoginError> {
        self.read_device(c, actor, ScanLoginAction::Status)
    }
    fn close_origin(
        &self,
        c: CloseScanOrigin,
        actor: ScanDeviceCall,
    ) -> Result<ScanOriginCloseResult, ScanLoginError> {
        self.close_original(c, actor)
    }
    fn lookup_device(
        &self,
        c: LookupDeviceScan,
        actor: ScanDeviceCall,
    ) -> Result<DeviceScanLookup, ScanLoginError> {
        valid_uuid(&c.origin_operation_id)?;
        if c.entry_id != self.config.entry_id || c.tenant_id != actor.binding.tenant_id {
            return Err(ScanLoginError::InvalidRequest);
        }
        self.auth.store.scan_transaction(self.auth.mode, |tx| {
            let (target, _) = self.prove(tx, &actor, None, ScanLoginAction::Lookup)?;
            let secret_hash: [u8; 32] = Sha256::digest(decode_secret(&c.delivery_secret)?).into();
            let actions: &[ScanOriginAction] = match c.origin_action {
                Some(ScanOriginAction::Create) => &[ScanOriginAction::Create],
                Some(ScanOriginAction::Claim) => &[ScanOriginAction::Claim],
                None => &[ScanOriginAction::Create, ScanOriginAction::Claim],
            };
            let mut found = None;
            let mut closed = false;
            for action in actions {
                if let Some(record) = tx.find_scan_origin_closure(
                    &c.tenant_id,
                    &self.config.host_scope,
                    &c.entry_id,
                    &target.device_id,
                    *action,
                    &c.origin_operation_id,
                )? {
                    if record.delivery_secret_hash != secret_hash {
                        return Err(ScanLoginError::NotFound);
                    }
                    if closed || found.is_some() {
                        return Err(ScanLoginError::OperationConflict);
                    }
                    closed = true;
                    // A known closed operation also retains its historical operation row.
                    continue;
                }
                if let Some(op) = tx.find_scan_operation(
                    &c.tenant_id,
                    &self.config.host_scope,
                    &c.entry_id,
                    &target.device_id,
                    action.as_str(),
                    &c.origin_operation_id,
                )? {
                    if closed || found.is_some() {
                        return Err(ScanLoginError::OperationConflict);
                    }
                    found = Some(op);
                }
            }
            if closed {
                // Without the action, a closed create cannot rule out a claim
                // with the same ID that has not yet committed (and vice versa).
                return Err(if c.origin_action.is_some() {
                    ScanLoginError::OriginOperationClosed
                } else {
                    ScanLoginError::OperationConflict
                });
            }
            let op = found.ok_or(ScanLoginError::NotFound)?;
            let g = tx
                .lock_scan_grant(&c.tenant_id, &op.grant_id)?
                .ok_or(ScanLoginError::NotFound)?;
            self.device_owner(
                &g,
                &DeviceGrantAccess {
                    grant_id: g.id.clone(),
                    delivery_secret: c.delivery_secret,
                },
                &target,
            )?;
            let display_code = if op.action == "create"
                && g.state == ScanGrantState::WaitingUser
                && g.code_expires_at > self.now()
            {
                Some(
                    self.cipher
                        .open(
                            &self.code_context(&g, &op.operation_id)?,
                            g.presentation
                                .as_ref()
                                .ok_or(ScanLoginError::ResultUnavailable)?,
                        )
                        .map_err(|_| ScanLoginError::ResultUnavailable)?,
                )
            } else {
                None
            };
            let d = tx.lock_scan_delivery(&g.tenant_id, &g.id)?;
            Ok(DeviceScanLookup {
                progress: self.progress(&g, d.as_ref()),
                origin_operation_id: op.operation_id,
                display_code,
            })
        })
    }
    fn exchange(
        &self,
        c: ExchangeScan,
        actor: ScanDeviceCall,
    ) -> Result<ScanDeliveryResult, ScanLoginError> {
        self.issue_and_release(c, actor)
    }
    fn recover(
        &self,
        c: RecoverScan,
        actor: ScanDeviceCall,
    ) -> Result<ScanDeliveryResult, ScanLoginError> {
        self.release(c, actor, ScanLoginAction::Recover)
    }
    fn acknowledge(
        &self,
        c: AcknowledgeScan,
        actor: ScanDeviceCall,
    ) -> Result<ScanProgress, ScanLoginError> {
        self.activate(c, actor)
    }
    fn abort_delivery(
        &self,
        c: AbortScanDelivery,
        actor: ScanDeviceCall,
    ) -> Result<ScanProgress, ScanLoginError> {
        self.abort(c, actor)
    }
    fn compensate(
        &self,
        host: TrustedScanHostContext,
        grant_id: String,
        issuance_operation_id: String,
        operation_id: String,
    ) -> Result<ScanProgress, ScanLoginError> {
        self.compensate_result(host, grant_id, issuance_operation_id, operation_id)
    }
    fn cleanup(&self, host: TrustedScanHostContext, limit: u32) -> Result<u32, ScanLoginError> {
        self.cleanup_results(host, limit)
    }
}

fn valid_code(code: &SecretString, prefix: &str, size: usize) -> Result<(), ScanLoginError> {
    let raw = code
        .expose_secret()
        .strip_prefix(prefix)
        .ok_or(ScanLoginError::InvalidRequest)?;
    let decoded = Base64UrlUnpadded::decode_vec(raw).map_err(|_| ScanLoginError::InvalidRequest)?;
    if decoded.len() != size || Base64UrlUnpadded::encode_string(&decoded) != raw {
        return Err(ScanLoginError::InvalidRequest);
    }
    Ok(())
}
