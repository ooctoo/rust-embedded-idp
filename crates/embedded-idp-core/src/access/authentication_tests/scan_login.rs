use super::*;

// The scanner flow uses the same clone-on-entry semantics as the authentication
// test store. A ScanLoginError never publishes a partially issued session.
impl TenantScanLoginStore for S {
    fn scan_transaction<R>(
        &self,
        _: TenancyMode,
        run: impl FnOnce(&mut Self::Transaction<'_>) -> Result<R, ScanLoginError>,
    ) -> Result<R, ScanLoginError> {
        let mut data = self.0.lock().unwrap();
        let mut tx = T {
            d: data.clone(),
            _s: self,
        };
        let result = run(&mut tx);
        if result.is_ok() {
            *data = tx.d;
        }
        result
    }
}

impl TenantScanLoginTransaction for T<'_> {
    fn find_scan_grant(
        &mut self,
        tenant: &str,
        scope: &str,
        entry: &str,
        id: &str,
    ) -> Result<Option<ScanGrantRecord>, StoreError> {
        Ok(self
            .d
            .scan_grants
            .iter()
            .find(|g| {
                g.tenant_id == tenant && g.host_scope == scope && g.entry_id == entry && g.id == id
            })
            .cloned())
    }
    fn find_scan_code(
        &mut self,
        tenant: Option<&str>,
        scope: &str,
        entry: &str,
        digest: &[u8; 32],
    ) -> Result<Option<ScanGrantRecord>, StoreError> {
        Ok(self
            .d
            .scan_grants
            .iter()
            .find(|g| {
                tenant.is_none_or(|t| g.tenant_id == t)
                    && g.host_scope == scope
                    && g.entry_id == entry
                    && &g.code_digest == digest
            })
            .cloned())
    }
    fn lock_scan_grant(
        &mut self,
        tenant: &str,
        id: &str,
    ) -> Result<Option<ScanGrantRecord>, StoreError> {
        Ok(self
            .d
            .scan_grants
            .iter()
            .find(|g| g.tenant_id == tenant && g.id == id)
            .cloned())
    }
    fn insert_scan_grant(&mut self, grant: &ScanGrantRecord) -> Result<(), StoreError> {
        if self.d.scan_grants.iter().any(|g| {
            g.id == grant.id
                || (g.tenant_id == grant.tenant_id
                    && g.host_scope == grant.host_scope
                    && g.entry_id == grant.entry_id
                    && g.code_digest == grant.code_digest)
        }) {
            return Err(StoreError::Conflict("scan.grant.unique"));
        }
        self.d.scan_grants.push(grant.clone());
        Ok(())
    }
    fn update_scan_grant(
        &mut self,
        grant: &ScanGrantRecord,
        expected: u64,
    ) -> Result<(), StoreError> {
        let current = self
            .d
            .scan_grants
            .iter_mut()
            .find(|g| g.tenant_id == grant.tenant_id && g.id == grant.id)
            .ok_or(StoreError::NotFound("scan.grant"))?;
        if current.version != expected {
            return Err(StoreError::Conflict("scan.grant.version"));
        }
        *current = grant.clone();
        Ok(())
    }
    fn find_scan_operation(
        &mut self,
        tenant: &str,
        scope: &str,
        entry: &str,
        actor: &str,
        action: &str,
        id: &str,
    ) -> Result<Option<ScanOperationRecord>, StoreError> {
        Ok(self
            .d
            .scan_operations
            .iter()
            .find(|o| {
                o.tenant_id == tenant
                    && o.host_scope == scope
                    && o.entry_id == entry
                    && o.actor_id == actor
                    && o.action == action
                    && o.operation_id == id
            })
            .cloned())
    }
    fn insert_scan_operation(&mut self, record: &ScanOperationRecord) -> Result<(), StoreError> {
        if self.d.scan_operations.iter().any(|o| {
            o.tenant_id == record.tenant_id
                && o.host_scope == record.host_scope
                && o.entry_id == record.entry_id
                && o.actor_id == record.actor_id
                && o.action == record.action
                && o.operation_id == record.operation_id
        }) {
            return Err(StoreError::Conflict("scan.operation.unique"));
        }
        self.d.scan_operations.push(record.clone());
        Ok(())
    }
    fn lock_scan_delivery(
        &mut self,
        tenant: &str,
        grant: &str,
    ) -> Result<Option<ScanDeliveryRecord>, StoreError> {
        Ok(self
            .d
            .scan_deliveries
            .iter()
            .find(|d| d.tenant_id == tenant && d.grant_id == grant)
            .cloned())
    }
    fn find_scan_delivery(
        &mut self,
        tenant: &str,
        grant: &str,
    ) -> Result<Option<ScanDeliveryRecord>, StoreError> {
        Ok(self
            .d
            .scan_deliveries
            .iter()
            .find(|d| d.tenant_id == tenant && d.grant_id == grant)
            .cloned())
    }
    fn scan_grant_tenant(
        &mut self,
        scope: &str,
        entry: &str,
        id: &str,
    ) -> Result<Option<String>, StoreError> {
        Ok(self
            .d
            .scan_grants
            .iter()
            .find(|g| g.host_scope == scope && g.entry_id == entry && g.id == id)
            .map(|g| g.tenant_id.clone()))
    }
    fn insert_scan_delivery(&mut self, record: &ScanDeliveryRecord) -> Result<(), StoreError> {
        if self.d.scan_deliveries.iter().any(|d| {
            d.tenant_id == record.tenant_id
                && (d.grant_id == record.grant_id || d.session_id == record.session_id)
        }) {
            return Err(StoreError::Conflict("scan.delivery.unique"));
        }
        self.d.scan_deliveries.push(record.clone());
        Ok(())
    }
    fn update_scan_delivery(
        &mut self,
        record: &ScanDeliveryRecord,
        expected: ScanDeliveryState,
    ) -> Result<(), StoreError> {
        let current = self
            .d
            .scan_deliveries
            .iter_mut()
            .find(|d| d.tenant_id == record.tenant_id && d.grant_id == record.grant_id)
            .ok_or(StoreError::NotFound("scan.delivery"))?;
        if current.state != expected {
            return Err(StoreError::Conflict("scan.delivery.state"));
        }
        *current = record.clone();
        Ok(())
    }
    fn scan_binding_snapshot(
        &mut self,
        tenant: &str,
        account: &str,
        device: &str,
    ) -> Result<Option<ScanBindingSnapshot>, StoreError> {
        Ok(self
            .d
            .proof_bindings
            .iter()
            .find(|b| b.tenant_id == tenant && b.account_id == account && b.device_id == device)
            .map(|b| ScanBindingSnapshot {
                id: format!("binding-{}", b.device_id),
                version: 1,
                status: b.status.clone(),
            }))
    }
    fn scan_account_label(&mut self, account: &str) -> Result<String, StoreError> {
        Ok(account.into())
    }
    fn activate_scan_session(&mut self, tenant: &str, session: &str) -> Result<(), StoreError> {
        let value = self
            .d
            .sessions
            .iter_mut()
            .find(|s| s.tenant_id == tenant && s.id == session)
            .ok_or(StoreError::NotFound("session"))?;
        if value.status != SessionStatus::Pending {
            return Err(StoreError::Conflict("scan.session.activate"));
        }
        value.status = SessionStatus::Active;
        Ok(())
    }
    fn revoke_scan_session(
        &mut self,
        tenant: &str,
        session: &str,
        now: SystemTime,
    ) -> Result<(), StoreError> {
        if let Some(value) = self
            .d
            .sessions
            .iter_mut()
            .find(|s| s.tenant_id == tenant && s.id == session)
        {
            value.status = SessionStatus::Revoked;
        }
        for refresh in &mut self.d.refreshes {
            if refresh.tenant_id == tenant && refresh.session_id == session {
                refresh.revoked_at = Some(now);
                refresh.revocation_reason = Some(RefreshTokenRevocationReason::ClientRevocation);
            }
        }
        Ok(())
    }
    fn expired_scan_deliveries(
        &mut self,
        scope: &str,
        entry: &str,
        now: SystemTime,
        limit: u32,
    ) -> Result<Vec<ScanGrantRecord>, StoreError> {
        Ok(self
            .d
            .scan_grants
            .iter()
            .filter(|g| {
                g.host_scope == scope
                    && g.entry_id == entry
                    && (g.expires_at <= now
                        || (g.state == ScanGrantState::WaitingDevice && g.code_expires_at <= now)
                        || (g.state == ScanGrantState::Approved
                            && g.approved_until.is_some_and(|until| until <= now))
                        || self.d.scan_deliveries.iter().any(|d| {
                            d.grant_id == g.id
                                && d.state == ScanDeliveryState::Recoverable
                                && d.recover_until <= now
                        }))
            })
            .take(limit as usize)
            .cloned()
            .collect())
    }
    fn append_scan_audit(&mut self, event: &ScanAuditEvent) -> Result<(), StoreError> {
        if self.d.fail_scan_audit {
            return Err(StoreError::Backend("scan audit".into()));
        }
        self.d.scan_audits.push(event.clone());
        Ok(())
    }
    fn pending_scan_count(
        &mut self,
        tenant: &str,
        scope: &str,
        entry: &str,
        source: Option<&str>,
        device: Option<&str>,
        now: SystemTime,
    ) -> Result<u64, StoreError> {
        Ok(self
            .d
            .scan_grants
            .iter()
            .filter(|g| {
                g.tenant_id == tenant
                    && g.host_scope == scope
                    && g.entry_id == entry
                    && g.expires_at > now
                    && (matches!(
                        g.state,
                        ScanGrantState::WaitingUser
                            | ScanGrantState::WaitingDevice
                            | ScanGrantState::AwaitingApproval
                            | ScanGrantState::Approved
                    ) || (g.state == ScanGrantState::Issued
                        && self.d.scan_deliveries.iter().any(|delivery| {
                            delivery.grant_id == g.id
                                && delivery.state == ScanDeliveryState::Recoverable
                                && delivery.recover_until > now
                        })))
                    && source.is_none_or(|session| {
                        g.source
                            .as_ref()
                            .is_some_and(|source| source.session_id == session)
                    })
                    && device.is_none_or(|d| g.target.as_ref().is_some_and(|t| t.device_id == d))
            })
            .count() as u64)
    }
}

#[test]
fn scan_store_rolls_back_audit_failure_and_enforces_compare_and_swap() {
    let store = seed();
    let now = C.now();
    let grant = ScanGrantRecord {
        tenant_id: "t1".into(),
        host_scope: "host".into(),
        entry_id: "terminal".into(),
        id: "018f0000-0000-7000-8000-000000000001".into(),
        mode: ScanLoginMode::DeviceDisplay,
        target_client_id: "web".into(),
        state: ScanGrantState::WaitingUser,
        version: 1,
        source: None,
        target: None,
        code_digest: [1; 32],
        presentation: None,
        delivery_secret_hash: None,
        confirmation_revision: None,
        created_at: now,
        expires_at: now + Duration::from_secs(60),
        code_expires_at: now + Duration::from_secs(60),
        approved_until: None,
    };
    store
        .scan_transaction(TenancyMode::Enabled, |tx| {
            tx.insert_scan_grant(&grant)?;
            Ok::<_, ScanLoginError>(())
        })
        .unwrap();
    let mut changed = grant.clone();
    changed.state = ScanGrantState::Cancelled;
    changed.version = 2;
    store
        .scan_transaction(TenancyMode::Enabled, |tx| {
            tx.update_scan_grant(&changed, 0)?;
            Ok::<_, ScanLoginError>(())
        })
        .unwrap_err();
    assert_eq!(
        store.0.lock().unwrap().scan_grants[0].state,
        ScanGrantState::WaitingUser
    );
    store.0.lock().unwrap().fail_scan_audit = true;
    let result = store.scan_transaction(TenancyMode::Enabled, |tx| {
        tx.insert_scan_operation(&ScanOperationRecord {
            tenant_id: "t1".into(),
            host_scope: "host".into(),
            entry_id: "terminal".into(),
            actor_id: "device".into(),
            action: "create".into(),
            operation_id: "018f0000-0000-7000-8000-000000000002".into(),
            fingerprint: [2; 32],
            grant_id: grant.id.clone(),
            created_at: now,
        })?;
        tx.append_scan_audit(&ScanAuditEvent {
            id: "018f0000-0000-7000-8000-000000000003".into(),
            tenant_id: "t1".into(),
            host_scope: "host".into(),
            grant_id: grant.id.clone(),
            actor_kind: "device".into(),
            actor_id: Some("device".into()),
            operation: "create".into(),
            operation_id: "018f0000-0000-7000-8000-000000000002".into(),
            session_id: None,
            decision_id: None,
            occurred_at: now,
        })?;
        Ok::<_, ScanLoginError>(())
    });
    assert!(matches!(result, Err(ScanLoginError::Store(_))));
    assert!(store.0.lock().unwrap().scan_operations.is_empty());
}

#[test]
fn scan_store_keeps_one_delivery_and_pending_session_is_not_activated_by_recovery() {
    let store = seed();
    let now = C.now();
    let grant = ScanGrantRecord {
        tenant_id: "t1".into(),
        host_scope: "host".into(),
        entry_id: "terminal".into(),
        id: "018f0000-0000-7000-8000-000000000011".into(),
        mode: ScanLoginMode::PhoneDisplay,
        target_client_id: "web".into(),
        state: ScanGrantState::Issued,
        version: 3,
        source: None,
        target: None,
        code_digest: [3; 32],
        presentation: None,
        delivery_secret_hash: Some([4; 32]),
        confirmation_revision: None,
        created_at: now,
        expires_at: now + Duration::from_secs(60),
        code_expires_at: now + Duration::from_secs(60),
        approved_until: None,
    };
    let pending = TenantSession {
        tenant_id: "t1".into(),
        id: "018f0000-0000-7000-8000-000000000012".into(),
        account_id: "a".into(),
        client_id: "web".into(),
        device_id: None,
        purpose: AccessTokenPurpose::Business,
        scope: None,
        authenticated_at: now,
        status: SessionStatus::Pending,
        created_at: now,
        expires_at: now + Duration::from_secs(60),
        refresh_token_version: 1,
    };
    store
        .scan_transaction(TenancyMode::Enabled, |tx| {
            tx.insert_scan_grant(&grant)?;
            tx.insert_session(
                &pending,
                "018f0000-0000-7000-8000-000000000013",
                &[9; 32],
                now + Duration::from_secs(60),
            )?;
            tx.insert_scan_delivery(&ScanDeliveryRecord {
                tenant_id: "t1".into(),
                grant_id: grant.id.clone(),
                issuance_operation_id: "018f0000-0000-7000-8000-000000000014".into(),
                session_id: pending.id.clone(),
                state: ScanDeliveryState::Recoverable,
                binding_id: "binding".into(),
                binding_version: 1,
                result: None,
                receipt_nonce_hash: Some([8; 32]),
                recover_until: now + Duration::from_secs(30),
                created_at: now,
                release_authorized_at: None,
                acknowledged_at: None,
                revoked_at: None,
                reason: None,
            })?;
            Ok::<_, ScanLoginError>(())
        })
        .unwrap();
    let snapshot = store.0.lock().unwrap().clone();
    assert_eq!(snapshot.sessions[0].status, SessionStatus::Pending);
    assert_eq!(snapshot.scan_deliveries.len(), 1);
    let duplicate = store.scan_transaction(TenancyMode::Enabled, |tx| {
        tx.insert_scan_delivery(&snapshot.scan_deliveries[0])
            .map_err(ScanLoginError::from)
    });
    assert!(matches!(
        duplicate,
        Err(ScanLoginError::Store(StoreError::Conflict(_)))
    ));
    store
        .scan_transaction(TenancyMode::Enabled, |tx| {
            tx.activate_scan_session("t1", &pending.id)?;
            Ok::<_, ScanLoginError>(())
        })
        .unwrap();
    assert_eq!(
        store.0.lock().unwrap().sessions[0].status,
        SessionStatus::Active
    );
}

// These tests exercise the coordinator rather than merely its store adapter.
// The cryptography adapter deliberately accepts the fixed test signature; the
// production proof and result-cipher implementations have their own tests.
use super::device_proofs::{Challenges, Crypto};
use base64ct::{Base64UrlUnpadded, Encoding};
use sha2::{Digest, Sha256};

#[derive(Clone, Copy)]
struct ScanIds;
impl IdGenerator for ScanIds {
    fn next_id(&self, _: &str) -> String {
        static NEXT: AtomicUsize = AtomicUsize::new(100);
        format!(
            "00000000-0000-4000-8000-{:012x}",
            NEXT.fetch_add(1, Ordering::Relaxed)
        )
    }
}

#[derive(Clone, Copy)]
struct ScanTokens;
impl RefreshTokenGenerator for ScanTokens {
    fn generate_refresh_token(&self) -> Result<SecretString, TokenError> {
        static NEXT: AtomicUsize = AtomicUsize::new(1);
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&(NEXT.fetch_add(1, Ordering::Relaxed) as u64).to_be_bytes());
        Ok(SecretString::new(Base64UrlUnpadded::encode_string(&bytes)))
    }
}

#[derive(Clone, Copy)]
struct PlaintextScanCipher;
impl ScanResultCipher for PlaintextScanCipher {
    fn seal(
        &self,
        _: &ScanResultContext,
        plaintext: &SecretString,
    ) -> Result<EncryptedScanResult, ScanResultCipherError> {
        Ok(EncryptedScanResult {
            key_id: "test".into(),
            nonce: [0; 12],
            ciphertext: plaintext.expose_secret().as_bytes().to_vec(),
        })
    }

    fn open(
        &self,
        _: &ScanResultContext,
        encrypted: &EncryptedScanResult,
    ) -> Result<SecretString, ScanResultCipherError> {
        String::from_utf8(encrypted.ciphertext.clone())
            .map(SecretString::new)
            .map_err(|_| ScanResultCipherError::DecryptionFailed)
    }
}

#[derive(Default)]
struct TestAdmission {
    deny_stage: Mutex<Option<ScanAdmissionStage>>,
}
impl TestAdmission {
    fn deny(&self, stage: ScanAdmissionStage) {
        *self.deny_stage.lock().unwrap() = Some(stage);
    }
}
impl ScanLoginAdmission for TestAdmission {
    fn authorize(
        &self,
        request: &ScanAdmissionRequest,
        _: &TrustedScanHostContext,
    ) -> Result<ScanAdmissionDecision, ScanLoginError> {
        if *self.deny_stage.lock().unwrap() == Some(request.stage) {
            return Ok(ScanAdmissionDecision::Deny {
                reason: "test denial".into(),
            });
        }
        Ok(ScanAdmissionDecision::Allow {
            decision_id: "test-decision".into(),
            policy_revision: "r1".into(),
            valid_until: C.now() + Duration::from_secs(4),
        })
    }
}

struct TestPresentation;
impl ScanTargetPresentationProvider for TestPresentation {
    fn describe(
        &self,
        _: &ScanAdmissionRequest,
        _: &TrustedScanHostContext,
    ) -> Result<ScanTargetPresentation, ScanLoginError> {
        Ok(ScanTargetPresentation {
            display_name: "Line 1 workstation".into(),
            identification: "workstation-1".into(),
            context_label: Some("Line 1".into()),
            revision: "presentation-r1".into(),
        })
    }
}

type ScanAuth = CoreTenantAuthenticationService<S, Tok, ScanTokens, Dg, C, ScanIds>;
type ScanProof = CoreTenantDeviceProofService<S, Crypto, Crypto, Challenges, C, ScanIds>;
type ScanService = CoreTenantDeviceScanLoginService<ScanAuth, ScanProof>;

const DEVICE_ID: &str = "11111111-1111-4111-8111-111111111111";

fn op(value: u32) -> String {
    format!("00000000-0000-4000-8000-{:012x}", value)
}

fn scan_secret(value: u8) -> SecretString {
    SecretString::new(Base64UrlUnpadded::encode_string(&[value; 32]))
}

fn scan_config() -> ScanLoginEntryConfig {
    ScanLoginEntryConfig {
        entry_id: "login".into(),
        target_client_id: "web".into(),
        allowed_source_client_ids: vec!["web".into()],
        host_scope: "host".into(),
        tenant_policy: LoginTenantPolicy::Fixed {
            tenant_id: "t1".into(),
        },
        modes: vec![ScanLoginMode::DeviceDisplay, ScanLoginMode::PhoneDisplay],
        target_scope: None,
        limits: ScanLoginLimits::default(),
    }
}

fn scan_auth(store: S, require_device_proof: bool) -> ScanAuth {
    CoreTenantAuthenticationService::new(
        TenancyMode::Enabled,
        AuthConfig {
            allow_local_registration: true,
            access_token_ttl_secs: 60,
            refresh_token_ttl_secs: 120,
            session_ttl_secs: 120,
            verification_code_ttl_secs: 60,
            password_min_length: 8,
            password_max_length: 128,
        },
        TenantLoginEntry {
            client_id: "web".into(),
            login_entry: "login".into(),
            policy: LoginTenantPolicy::Fixed {
                tenant_id: "t1".into(),
            },
            require_device_proof,
        },
        store.clone(),
        Tok,
        ScanTokens,
        Dg,
        C,
        ScanIds,
    )
    .unwrap()
}

fn scan_proof(store: S) -> ScanProof {
    CoreTenantDeviceProofService::new(
        TenancyMode::Enabled,
        TenantDeviceProofConfig {
            client_id: "web".into(),
            allowed_purposes: [
                ScanLoginAction::Create,
                ScanLoginAction::Claim,
                ScanLoginAction::Status,
                ScanLoginAction::Lookup,
                ScanLoginAction::Cancel,
                ScanLoginAction::Exchange,
                ScanLoginAction::Recover,
                ScanLoginAction::Acknowledge,
                ScanLoginAction::Abort,
            ]
            .into_iter()
            .map(ScanLoginAction::purpose)
            .collect(),
            challenge_ttl_secs: 60,
            clock_skew_secs: 30,
        },
        store.clone(),
        Crypto,
        Crypto,
        Challenges,
        C,
        ScanIds,
    )
    .unwrap()
}

fn host() -> TrustedScanHostContext {
    TrustedScanHostContext::new("host".into(), C.now() + Duration::from_secs(5))
}

fn device_call(proof_service: &ScanProof, action: ScanLoginAction) -> ScanDeviceCall {
    let challenge = proof_service
        .issue_challenge("t1", DEVICE_ID, action.purpose())
        .unwrap();
    let key_id = Base64UrlUnpadded::encode_string(&[1; 32]);
    ScanDeviceCall {
        entry_id: "login".into(),
        proof: DeviceProofPresentation {
            device_id: DEVICE_ID.into(),
            key_id,
            challenge: challenge.challenge.into_exposed(),
            signature: Base64UrlUnpadded::encode_string(&[3; 64]),
            signed_at: C.now(),
        },
        binding: DeviceRequestBinding::new(
            "t1",
            DeviceProofProfile::new(SCAN_LOGIN_PROOF_PROFILE).unwrap(),
            "api",
            CanonicalHttpMethod::Post,
            "/auth/device-scan",
            [0; 32],
        )
        .unwrap(),
        host: host(),
    }
}

fn setup() -> (
    S,
    ScanService,
    ScanProof,
    ScanAuth,
    Arc<TestAdmission>,
    SecretString,
) {
    let store = seed();
    let key_id = Base64UrlUnpadded::encode_string(&[1; 32]);
    {
        let mut data = store.0.lock().unwrap();
        data.proof_devices.push(TenantProofDevice {
            tenant_id: "t1".into(),
            id: DEVICE_ID.into(),
            client_id: "web".into(),
            proof_key_id: Some(key_id.clone()),
            status: DeviceStatus::Active,
            version: 1,
            key_version: None,
        });
        data.proof_keys.push(TenantProofKey {
            tenant_id: "t1".into(),
            device_id: DEVICE_ID.into(),
            key_id,
            public_jwk: "test".into(),
            version: 1,
            status: DeviceProofKeyStatus::Active,
        });
    }
    let source_auth = scan_auth(store.clone(), false);
    let TenantLoginOutcome::Authenticated(login) = source_auth.login(login()).unwrap() else {
        panic!("fixed tenant returns a session")
    };
    let source_cookie = login.tokens.refresh_token.clone();
    let admission = Arc::new(TestAdmission::default());
    let service = ScanService::new(
        scan_config(),
        scan_auth(store.clone(), true),
        scan_proof(store.clone()),
        admission.clone(),
        Arc::new(TestPresentation),
        Arc::new(PlaintextScanCipher),
    )
    .unwrap();
    (
        store.clone(),
        service,
        scan_proof(store),
        source_auth,
        admission,
        source_cookie,
    )
}

fn source_call(source_auth: &ScanAuth, cookie: SecretString) -> ScanSourceCall {
    ScanSourceCall {
        source: source_auth.authenticate_browser(cookie, None).unwrap(),
        host: host(),
    }
}

fn delivery_secret_hash(secret: &SecretString) -> [u8; 32] {
    Sha256::digest(
        Base64UrlUnpadded::decode_vec(secret.expose_secret())
            .expect("test secret is a canonical base64url value"),
    )
    .into()
}

#[test]
fn scan_device_display_flow_recovers_pending_bundle_then_acknowledges() {
    let (store, service, proofs, source_auth, _, source_cookie) = setup();
    let delivery_secret = scan_secret(7);
    let created = service
        .create_device(
            CreateDeviceScan {
                operation_id: op(1),
                entry_id: "login".into(),
                tenant_id: "t1".into(),
                delivery_secret_hash: delivery_secret_hash(&delivery_secret),
            },
            device_call(&proofs, ScanLoginAction::Create),
        )
        .unwrap();
    let repeated_create = service
        .create_device(
            CreateDeviceScan {
                operation_id: op(1),
                entry_id: "login".into(),
                tenant_id: "t1".into(),
                delivery_secret_hash: delivery_secret_hash(&delivery_secret),
            },
            device_call(&proofs, ScanLoginAction::Create),
        )
        .unwrap();
    assert_eq!(repeated_create.progress.grant_id, created.progress.grant_id);
    assert_eq!(
        repeated_create.display_code.expose_secret(),
        created.display_code.expose_secret()
    );
    let confirmation = service
        .attach_source(
            AttachScanSource {
                operation_id: op(2),
                display_code: created.display_code,
            },
            source_call(&source_auth, source_cookie.clone()),
        )
        .unwrap();
    let approved = service
        .approve(
            ApproveScan {
                action: SourceGrantAction {
                    operation_id: op(3),
                    grant_id: confirmation.progress.grant_id.clone(),
                },
                confirmation_revision: confirmation.confirmation_revision,
            },
            source_call(&source_auth, source_cookie.clone()),
        )
        .unwrap();
    assert_eq!(approved.state, ScanGrantState::Approved);

    let access = DeviceGrantAccess {
        grant_id: confirmation.progress.grant_id,
        delivery_secret,
    };
    assert_eq!(
        service.device_status(
            DeviceGrantAccess {
                grant_id: access.grant_id.clone(),
                delivery_secret: scan_secret(99),
            },
            device_call(&proofs, ScanLoginAction::Status),
        ),
        Err(ScanLoginError::NotFound)
    );
    let ScanDeliveryResult::Bundle {
        session,
        receipt_nonce,
        ..
    } = service
        .exchange(
            ExchangeScan {
                operation_id: op(4),
                access: access.clone(),
            },
            device_call(&proofs, ScanLoginAction::Exchange),
        )
        .unwrap()
    else {
        panic!("new exchange releases the encrypted bundle")
    };
    assert_eq!(session.session.status, SessionStatus::Pending);
    let ScanDeliveryResult::Bundle {
        session: replayed, ..
    } = service
        .exchange(
            ExchangeScan {
                operation_id: op(4),
                access: access.clone(),
            },
            device_call(&proofs, ScanLoginAction::Exchange),
        )
        .unwrap()
    else {
        panic!("same exchange operation releases the original pending session")
    };
    assert_eq!(replayed.session.id, session.session.id);
    source_auth.browser_logout(source_cookie, None).unwrap();
    let ScanDeliveryResult::Bundle {
        session: recovered, ..
    } = service
        .recover(
            RecoverScan {
                issuance_operation_id: op(4),
                access: access.clone(),
            },
            device_call(&proofs, ScanLoginAction::Recover),
        )
        .unwrap()
    else {
        panic!("unacknowledged delivery is recoverable")
    };
    assert_eq!(recovered.session.id, session.session.id);
    assert_eq!(
        service.acknowledge(
            AcknowledgeScan {
                operation_id: op(5),
                issuance_operation_id: op(4),
                access: access.clone(),
                receipt_nonce: scan_secret(12),
            },
            device_call(&proofs, ScanLoginAction::Acknowledge),
        ),
        Err(ScanLoginError::NotFound)
    );
    let acknowledged = service
        .acknowledge(
            AcknowledgeScan {
                operation_id: op(5),
                issuance_operation_id: op(4),
                access: access.clone(),
                receipt_nonce: receipt_nonce.clone(),
            },
            device_call(&proofs, ScanLoginAction::Acknowledge),
        )
        .unwrap();
    assert_eq!(
        acknowledged.delivery_state,
        Some(ScanDeliveryState::Acknowledged)
    );
    let data = store.0.lock().unwrap();
    assert_eq!(data.sessions.len(), 2);
    assert_eq!(data.sessions[1].status, SessionStatus::Active);
    assert!(data.scan_deliveries[0].result.is_none());
    assert!(data.scan_deliveries[0].receipt_nonce_hash.is_none());
    let audit_count = data.scan_audits.len();
    drop(data);
    let retry = service
        .acknowledge(
            AcknowledgeScan {
                operation_id: op(5),
                issuance_operation_id: op(4),
                access,
                receipt_nonce,
            },
            device_call(&proofs, ScanLoginAction::Acknowledge),
        )
        .unwrap();
    assert_eq!(retry.delivery_state, Some(ScanDeliveryState::Acknowledged));
    assert_eq!(store.0.lock().unwrap().scan_audits.len(), audit_count);
}

#[test]
fn scan_phone_display_requires_source_before_issue_but_not_after_issue() {
    let (store, service, proofs, source_auth, _, source_cookie) = setup();
    let issued = service
        .issue_phone(
            IssuePhoneScan {
                operation_id: op(21),
                entry_id: "login".into(),
            },
            source_call(&source_auth, source_cookie.clone()),
        )
        .unwrap();
    let delivery_secret = scan_secret(8);
    let claim = service
        .claim_target(
            ClaimScanTarget {
                operation_id: op(22),
                entry_id: "login".into(),
                tenant_id: "t1".into(),
                scan_code: issued.scan_code,
                delivery_secret_hash: delivery_secret_hash(&delivery_secret),
            },
            device_call(&proofs, ScanLoginAction::Claim),
        )
        .unwrap();
    let confirmation = service
        .inspect(
            claim.grant_id.clone(),
            source_call(&source_auth, source_cookie.clone()),
        )
        .unwrap();
    service
        .approve(
            ApproveScan {
                action: SourceGrantAction {
                    operation_id: op(23),
                    grant_id: claim.grant_id.clone(),
                },
                confirmation_revision: confirmation.confirmation_revision,
            },
            source_call(&source_auth, source_cookie.clone()),
        )
        .unwrap();
    let access = DeviceGrantAccess {
        grant_id: claim.grant_id,
        delivery_secret,
    };

    source_auth
        .browser_logout(source_cookie.clone(), None)
        .unwrap();
    assert!(matches!(
        service.exchange(
            ExchangeScan {
                operation_id: op(24),
                access: access.clone(),
            },
            device_call(&proofs, ScanLoginAction::Exchange),
        ),
        Err(ScanLoginError::Auth(TenantAuthError::InvalidSession))
    ));
    assert!(store.0.lock().unwrap().scan_deliveries.is_empty());
}

#[test]
fn scan_cancel_before_issue_prevents_session_creation() {
    let (store, service, proofs, source_auth, _, source_cookie) = setup();
    let delivery_secret = scan_secret(13);
    let created = service
        .create_device(
            CreateDeviceScan {
                operation_id: op(26),
                entry_id: "login".into(),
                tenant_id: "t1".into(),
                delivery_secret_hash: delivery_secret_hash(&delivery_secret),
            },
            device_call(&proofs, ScanLoginAction::Create),
        )
        .unwrap();
    let confirmation = service
        .attach_source(
            AttachScanSource {
                operation_id: op(27),
                display_code: created.display_code,
            },
            source_call(&source_auth, source_cookie.clone()),
        )
        .unwrap();
    let cancelled = service
        .cancel_source(
            SourceGrantAction {
                operation_id: op(28),
                grant_id: confirmation.progress.grant_id.clone(),
            },
            source_call(&source_auth, source_cookie),
        )
        .unwrap();
    assert_eq!(cancelled.state, ScanGrantState::Cancelled);
    assert_eq!(
        service.exchange(
            ExchangeScan {
                operation_id: op(29),
                access: DeviceGrantAccess {
                    grant_id: confirmation.progress.grant_id,
                    delivery_secret,
                },
            },
            device_call(&proofs, ScanLoginAction::Exchange),
        ),
        Err(ScanLoginError::Cancelled)
    );
    let data = store.0.lock().unwrap();
    assert_eq!(data.sessions.len(), 1);
    assert!(data.scan_deliveries.is_empty());
}

fn issued_device_bundle() -> (
    S,
    ScanService,
    ScanProof,
    Arc<TestAdmission>,
    DeviceGrantAccess,
    SecretString,
) {
    let (store, service, proofs, source_auth, admission, source_cookie) = setup();
    let delivery_secret = scan_secret(61);
    let created = service
        .create_device(
            CreateDeviceScan {
                operation_id: op(51),
                entry_id: "login".into(),
                tenant_id: "t1".into(),
                delivery_secret_hash: delivery_secret_hash(&delivery_secret),
            },
            device_call(&proofs, ScanLoginAction::Create),
        )
        .unwrap();
    let confirmation = service
        .attach_source(
            AttachScanSource {
                operation_id: op(52),
                display_code: created.display_code,
            },
            source_call(&source_auth, source_cookie.clone()),
        )
        .unwrap();
    service
        .approve(
            ApproveScan {
                action: SourceGrantAction {
                    operation_id: op(53),
                    grant_id: confirmation.progress.grant_id.clone(),
                },
                confirmation_revision: confirmation.confirmation_revision,
            },
            source_call(&source_auth, source_cookie),
        )
        .unwrap();
    let access = DeviceGrantAccess {
        grant_id: confirmation.progress.grant_id,
        delivery_secret,
    };
    let ScanDeliveryResult::Bundle { receipt_nonce, .. } = service
        .exchange(
            ExchangeScan {
                operation_id: op(54),
                access: access.clone(),
            },
            device_call(&proofs, ScanLoginAction::Exchange),
        )
        .unwrap()
    else {
        panic!("fixture issues a pending delivery")
    };
    (store, service, proofs, admission, access, receipt_nonce)
}

#[test]
fn scan_expired_recovery_and_activation_denial_revoke_only_pending_delivery() {
    let (store, service, proofs, _, access, receipt_nonce) = issued_device_bundle();
    store.0.lock().unwrap().scan_deliveries[0].recover_until = C.now();
    assert_eq!(
        service.acknowledge(
            AcknowledgeScan {
                operation_id: op(55),
                issuance_operation_id: op(54),
                access: access.clone(),
                receipt_nonce,
            },
            device_call(&proofs, ScanLoginAction::Acknowledge),
        ),
        Err(ScanLoginError::DeliveryExpired)
    );
    let data = store.0.lock().unwrap();
    assert_eq!(data.sessions[0].status, SessionStatus::Active);
    assert_eq!(data.sessions[1].status, SessionStatus::Revoked);
    assert_eq!(data.scan_deliveries[0].state, ScanDeliveryState::Revoked);
    assert!(data.scan_deliveries[0].result.is_none());
    assert_eq!(data.proof_bindings.len(), 1);
    assert_eq!(
        data.proof_bindings[0].status,
        AccountDeviceBindingStatus::Active
    );
    drop(data);

    let (store, service, proofs, admission, access, receipt_nonce) = issued_device_bundle();
    admission.deny(ScanAdmissionStage::ActivateSession);
    assert_eq!(
        service.acknowledge(
            AcknowledgeScan {
                operation_id: op(56),
                issuance_operation_id: op(54),
                access,
                receipt_nonce,
            },
            device_call(&proofs, ScanLoginAction::Acknowledge),
        ),
        Err(ScanLoginError::AdmissionDenied)
    );
    let data = store.0.lock().unwrap();
    assert_eq!(data.sessions[0].status, SessionStatus::Active);
    assert_eq!(data.sessions[1].status, SessionStatus::Revoked);
    assert_eq!(data.scan_deliveries[0].state, ScanDeliveryState::Revoked);
    assert!(data.scan_deliveries[0].result.is_none());
    assert_eq!(data.proof_bindings.len(), 1);
    assert_eq!(
        data.proof_bindings[0].status,
        AccountDeviceBindingStatus::Active
    );
}

#[test]
fn scan_cleanup_expires_phone_code_and_approval_before_grant_deadline() {
    let (store, service, _, source_auth, _, source_cookie) = setup();
    let phone = service
        .issue_phone(
            IssuePhoneScan {
                operation_id: op(71),
                entry_id: "login".into(),
            },
            source_call(&source_auth, source_cookie.clone()),
        )
        .unwrap();
    {
        let mut data = store.0.lock().unwrap();
        assert!(data.scan_grants[0].expires_at > C.now());
        data.scan_grants[0].code_expires_at = C.now();
    }
    assert_eq!(service.cleanup(host(), 10), Ok(1));
    {
        let data = store.0.lock().unwrap();
        assert_eq!(data.scan_grants[0].id, phone.progress.grant_id);
        assert_eq!(data.scan_grants[0].state, ScanGrantState::Expired);
        assert!(data.scan_grants[0].presentation.is_none());
    }

    let approval = service
        .issue_phone(
            IssuePhoneScan {
                operation_id: op(72),
                entry_id: "login".into(),
            },
            source_call(&source_auth, source_cookie),
        )
        .unwrap();
    {
        let mut data = store.0.lock().unwrap();
        let grant = data
            .scan_grants
            .iter_mut()
            .find(|grant| grant.id == approval.progress.grant_id)
            .unwrap();
        grant.state = ScanGrantState::Approved;
        grant.approved_until = Some(C.now());
        assert!(grant.expires_at > C.now());
    }
    assert_eq!(service.cleanup(host(), 10), Ok(1));
    let data = store.0.lock().unwrap();
    let grant = data
        .scan_grants
        .iter()
        .find(|grant| grant.id == approval.progress.grant_id)
        .unwrap();
    assert_eq!(grant.state, ScanGrantState::Expired);
    assert!(grant.presentation.is_none());
}

#[test]
fn scan_release_denial_revokes_pending_session_and_audit_failure_rolls_back() {
    let (store, service, proofs, source_auth, admission, source_cookie) = setup();
    let delivery_secret = scan_secret(9);
    let created = service
        .create_device(
            CreateDeviceScan {
                operation_id: op(31),
                entry_id: "login".into(),
                tenant_id: "t1".into(),
                delivery_secret_hash: delivery_secret_hash(&delivery_secret),
            },
            device_call(&proofs, ScanLoginAction::Create),
        )
        .unwrap();
    let confirmation = service
        .attach_source(
            AttachScanSource {
                operation_id: op(32),
                display_code: created.display_code,
            },
            source_call(&source_auth, source_cookie.clone()),
        )
        .unwrap();
    service
        .approve(
            ApproveScan {
                action: SourceGrantAction {
                    operation_id: op(33),
                    grant_id: confirmation.progress.grant_id.clone(),
                },
                confirmation_revision: confirmation.confirmation_revision,
            },
            source_call(&source_auth, source_cookie.clone()),
        )
        .unwrap();
    admission.deny(ScanAdmissionStage::ReleaseResult);
    let access = DeviceGrantAccess {
        grant_id: confirmation.progress.grant_id,
        delivery_secret,
    };
    assert_eq!(
        service.exchange(
            ExchangeScan {
                operation_id: op(34),
                access: access.clone(),
            },
            device_call(&proofs, ScanLoginAction::Exchange),
        ),
        Err(ScanLoginError::AdmissionDenied)
    );
    let data = store.0.lock().unwrap();
    assert_eq!(data.sessions.len(), 2);
    assert_eq!(data.sessions[1].status, SessionStatus::Revoked);
    assert_eq!(data.scan_deliveries[0].state, ScanDeliveryState::Revoked);
    drop(data);
    assert_eq!(
        service.cancel_source(
            SourceGrantAction {
                operation_id: op(35),
                grant_id: access.grant_id,
            },
            source_call(&source_auth, source_cookie),
        ),
        Err(ScanLoginError::AlreadyIssued)
    );

    let (store, service, proofs, source_auth, _, source_cookie) = setup();
    let delivery_secret = scan_secret(10);
    let created = service
        .create_device(
            CreateDeviceScan {
                operation_id: op(41),
                entry_id: "login".into(),
                tenant_id: "t1".into(),
                delivery_secret_hash: delivery_secret_hash(&delivery_secret),
            },
            device_call(&proofs, ScanLoginAction::Create),
        )
        .unwrap();
    let confirmation = service
        .attach_source(
            AttachScanSource {
                operation_id: op(42),
                display_code: created.display_code,
            },
            source_call(&source_auth, source_cookie.clone()),
        )
        .unwrap();
    service
        .approve(
            ApproveScan {
                action: SourceGrantAction {
                    operation_id: op(43),
                    grant_id: confirmation.progress.grant_id.clone(),
                },
                confirmation_revision: confirmation.confirmation_revision,
            },
            source_call(&source_auth, source_cookie),
        )
        .unwrap();
    store.0.lock().unwrap().fail_scan_audit = true;
    assert!(matches!(
        service.exchange(
            ExchangeScan {
                operation_id: op(44),
                access: DeviceGrantAccess {
                    grant_id: confirmation.progress.grant_id,
                    delivery_secret
                }
            },
            device_call(&proofs, ScanLoginAction::Exchange)
        ),
        Err(ScanLoginError::Store(_))
    ));
    let data = store.0.lock().unwrap();
    assert_eq!(data.sessions.len(), 1);
    assert!(data.scan_deliveries.is_empty());
    assert_eq!(data.scan_grants[0].state, ScanGrantState::Approved);
}
