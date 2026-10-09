mod browser;
mod management;
use super::*;
use crate::{digest_refresh_token, service::password::hash_password, *};
use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[derive(Clone)]
struct D {
    accounts: BTreeMap<String, TenantLoginIdentity>,
    tenants: BTreeMap<String, Tenant>,
    members: Vec<TenantMembership>,
    clients: Vec<String>,
    sessions: Vec<TenantSession>,
    refreshes: Vec<TenantRefreshRecord>,
    authorizations: Vec<TenantAuthorizationCode>,
    selections: Vec<TenantSelectionRecord>,
    fail_insert: bool,
    confidential_client: bool,
    proof_devices: Vec<TenantProofDevice>,
    registrations: Vec<TenantDeviceRegistration>,
    proof_keys: Vec<TenantProofKey>,
    proof_bindings: Vec<TenantProofBinding>,
    proof_challenges: Vec<TenantProofChallenge>,
    fail_consume: bool,
    scan_grants: Vec<ScanGrantRecord>,
    scan_operations: Vec<ScanOperationRecord>,
    scan_origin_closures: Vec<ScanOriginClosure>,
    scan_deliveries: Vec<ScanDeliveryRecord>,
    scan_audits: Vec<ScanAuditEvent>,
    fail_scan_audit: bool,
}
#[derive(Clone)]
struct S(Arc<Mutex<D>>);
struct T<'a> {
    d: D,
    _s: &'a S,
}
#[derive(Clone, Copy)]
struct C;
impl Clock for C {
    fn now(&self) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(1000)
    }
}
#[derive(Clone, Copy)]
struct I;
impl IdGenerator for I {
    fn next_id(&self, p: &str) -> String {
        static NEXT: AtomicUsize = AtomicUsize::new(1);
        format!("{p}-{}", NEXT.fetch_add(1, Ordering::Relaxed))
    }
}
#[derive(Clone, Copy)]
struct G;
impl RefreshTokenGenerator for G {
    fn generate_refresh_token(&self) -> Result<SecretString, TokenError> {
        Ok(SecretString::new(I.next_id("selection-token")))
    }
}
#[derive(Clone, Copy)]
struct Dg;
impl RefreshTokenDigester for Dg {
    fn digest_refresh_token(&self, s: &str) -> Result<[u8; 32], TokenError> {
        Ok(digest_refresh_token(s))
    }
}
#[derive(Clone, Copy)]
struct Tok;
impl TokenIssuer for Tok {
    fn issue_session_tokens(
        &self,
        t: &str,
        s: &str,
        a: &str,
        c: &str,
        _: u64,
        n: SystemTime,
    ) -> Result<IssuedTokenBundle, TokenError> {
        Ok(IssuedTokenBundle {
            access_token: SecretString::new(format!("{t}/{s}/{a}/{c}")),
            refresh_token: SecretString::new(format!("refresh-{s}")),
            access_expires_at: n + Duration::from_secs(60),
            refresh_expires_at: n + Duration::from_secs(120),
            refresh_token_version: 1,
        })
    }
}
impl AccessTokenIssuer for Tok {
    fn issue_access_token(
        &self,
        t: &str,
        s: &str,
        a: &str,
        c: &str,
        n: SystemTime,
    ) -> Result<IssuedAccessToken, TokenError> {
        Ok(IssuedAccessToken {
            token: SecretString::new(format!("{t}/{s}/{a}/{c}")),
            expires_at: n + Duration::from_secs(60),
        })
    }
}
impl ScopedAccessTokenIssuer for Tok {
    fn issue_scoped_access_token(
        &self,
        t: &str,
        s: &str,
        a: &str,
        c: &str,
        n: SystemTime,
        scope: &str,
    ) -> Result<IssuedAccessToken, TokenError> {
        Ok(IssuedAccessToken {
            token: SecretString::new(format!("{t}/{s}/{a}/{c}/{scope}")),
            expires_at: n + Duration::from_secs(60),
        })
    }
}
impl TenantRefreshTransaction for T<'_> {
    fn find_refresh(
        &mut self,
        digest: &[u8; 32],
    ) -> Result<Option<TenantRefreshRecord>, StoreError> {
        Ok(self
            .d
            .refreshes
            .iter()
            .find(|r| &r.token_digest == digest)
            .cloned())
    }
    fn lock_refresh_session(
        &mut self,
        tenant: &str,
        id: &str,
    ) -> Result<Option<TenantSession>, StoreError> {
        self.session(tenant, id)
    }
    fn lock_refresh_record(
        &mut self,
        tenant: &str,
        digest: &[u8; 32],
    ) -> Result<Option<TenantRefreshRecord>, StoreError> {
        Ok(self
            .d
            .refreshes
            .iter()
            .find(|r| r.tenant_id == tenant && &r.token_digest == digest)
            .cloned())
    }
    fn rotate_refresh_records(
        &mut self,
        session: &TenantSession,
        previous: &TenantRefreshRecord,
        next: &TenantRefreshRecord,
    ) -> Result<(), StoreError> {
        self.d
            .sessions
            .iter_mut()
            .find(|s| s.tenant_id == session.tenant_id && s.id == session.id)
            .unwrap()
            .refresh_token_version = next.token_version;
        let old = self
            .d
            .refreshes
            .iter_mut()
            .find(|r| r.tenant_id == previous.tenant_id && r.id == previous.id)
            .unwrap();
        old.revoked_at = Some(next.issued_at);
        old.revocation_reason = Some(RefreshTokenRevocationReason::Rotated);
        self.d.refreshes.push(next.clone());
        if self.d.fail_insert {
            return Err(StoreError::Backend("refresh insert".into()));
        }
        Ok(())
    }
    fn revoke_refresh_family(
        &mut self,
        session: &TenantSession,
        reason: RefreshTokenRevocationReason,
        now: SystemTime,
    ) -> Result<(), StoreError> {
        self.d
            .sessions
            .iter_mut()
            .find(|s| s.tenant_id == session.tenant_id && s.id == session.id)
            .unwrap()
            .status = SessionStatus::Revoked;
        for r in &mut self.d.refreshes {
            if r.tenant_id == session.tenant_id && r.session_id == session.id {
                r.revoked_at = Some(now);
                r.revocation_reason = Some(reason);
            }
        }
        if self.d.fail_insert {
            return Err(StoreError::Backend("family revoke".into()));
        }
        Ok(())
    }
}
impl AccessTokenValidator for Tok {
    fn validate_access_token(
        &self,
        raw: &str,
        n: SystemTime,
    ) -> Result<Option<ValidatedAccessToken>, TokenError> {
        let p: Vec<_> = raw.split('/').collect();
        if p.len() != 4 && p.len() != 5 {
            return Ok(None);
        };
        Ok(Some(ValidatedAccessToken {
            purpose: crate::AccessTokenPurpose::Business,
            tenant_id: p[0].into(),
            session_id: p[1].into(),
            subject_account_id: p[2].into(),
            client_id: p[3].into(),
            token: SecretString::new(raw),
            scope: p.get(4).map(|s| s.to_string()),
            issued_at: n,
            expires_at: n + Duration::from_secs(30),
        }))
    }
}
fn svc_mode_with_proof(
    mode: TenancyMode,
    policy: LoginTenantPolicy,
    s: S,
    require_device_proof: bool,
) -> CoreTenantAuthenticationService<S, Tok, G, Dg, C, I> {
    CoreTenantAuthenticationService::new(
        mode,
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
            policy,
            require_device_proof,
        },
        s,
        Tok,
        G,
        Dg,
        C,
        I,
    )
    .unwrap()
}
fn svc_mode(
    mode: TenancyMode,
    policy: LoginTenantPolicy,
    s: S,
) -> CoreTenantAuthenticationService<S, Tok, G, Dg, C, I> {
    svc_mode_with_proof(mode, policy, s, false)
}
fn svc(policy: LoginTenantPolicy, s: S) -> CoreTenantAuthenticationService<S, Tok, G, Dg, C, I> {
    svc_mode(TenancyMode::Enabled, policy, s)
}
fn svc_proof(
    policy: LoginTenantPolicy,
    s: S,
) -> CoreTenantAuthenticationService<S, Tok, G, Dg, C, I> {
    svc_mode_with_proof(TenancyMode::Enabled, policy, s, true)
}
fn seed() -> S {
    let mut a = BTreeMap::new();
    a.insert(
        "a".into(),
        TenantLoginIdentity {
            id: "a".into(),
            password_hash: SecretString::new(hash_password("password1").unwrap()),
            active: true,
        },
    );
    let tenants = ["0", "t1", "t2"]
        .into_iter()
        .map(|id| {
            (
                id.into(),
                Tenant {
                    id: id.into(),
                    name: id.into(),
                    status: TenantStatus::Active,
                    allow_registration: true,
                },
            )
        })
        .collect();
    let members = vec![m("t1", "a"), m("t2", "a")];
    S(Arc::new(Mutex::new(D {
        accounts: a,
        tenants,
        members,
        clients: vec!["web".into()],
        sessions: vec![],
        refreshes: vec![],
        authorizations: vec![],
        selections: vec![],
        fail_insert: false,
        confidential_client: false,
        proof_devices: vec![],
        registrations: vec![],
        proof_keys: vec![],
        proof_bindings: vec![],
        proof_challenges: vec![],
        fail_consume: false,
        scan_grants: vec![],
        scan_operations: vec![],
        scan_origin_closures: vec![],
        scan_deliveries: vec![],
        scan_audits: vec![],
        fail_scan_audit: false,
    })))
}

mod scan_login;
fn m(t: &str, a: &str) -> TenantMembership {
    TenantMembership {
        tenant_id: t.into(),
        subject_id: a.into(),
        status: MembershipStatus::Active,
        joined_at: UNIX_EPOCH,
        version: 1,
    }
}
fn login() -> TenantPasswordLogin {
    TenantPasswordLogin {
        email: "a@example.com".into(),
        password: SecretString::new("password1"),
    }
}
impl TenantAuthStore for S {
    type Transaction<'a> = T<'a>;
    fn auth_transaction<R>(
        &self,
        _mode: TenancyMode,
        f: impl FnOnce(&mut T<'_>) -> Result<R, TenantAuthError>,
    ) -> Result<R, TenantAuthError> {
        let mut data = self.0.lock().unwrap();
        let mut t = T {
            d: data.clone(),
            _s: self,
        };
        let r = f(&mut t);
        if r.is_ok() {
            *data = t.d
        }
        r
    }
}
impl TenantAuthTransaction for T<'_> {
    fn lock_tenants(&mut self, _: &[String]) -> Result<(), StoreError> {
        Ok(())
    }
    fn lock_account_by_email(
        &mut self,
        _: &str,
    ) -> Result<Option<TenantLoginIdentity>, StoreError> {
        Ok(self.d.accounts.get("a").cloned())
    }
    fn lock_account(&mut self, id: &str) -> Result<Option<TenantLoginIdentity>, StoreError> {
        Ok(self.d.accounts.get(id).cloned())
    }
    fn client_exists(&mut self, id: &str) -> Result<bool, StoreError> {
        Ok(self.d.clients.iter().any(|x| x == id))
    }
    fn tenant(&mut self, id: &str) -> Result<Option<Tenant>, StoreError> {
        Ok(self.d.tenants.get(id).cloned())
    }
    fn membership(&mut self, t: &str, a: &str) -> Result<Option<TenantMembership>, StoreError> {
        Ok(self
            .d
            .members
            .iter()
            .find(|m| m.tenant_id == t && m.subject_id == a)
            .cloned())
    }
    fn find_selection(
        &mut self,
        d: &[u8; 32],
    ) -> Result<Option<TenantSelectionRecord>, StoreError> {
        Ok(self
            .d
            .selections
            .iter()
            .find(|x| &x.ticket_digest == d)
            .cloned())
    }
    fn lock_selection(
        &mut self,
        d: &[u8; 32],
    ) -> Result<Option<TenantSelectionRecord>, StoreError> {
        self.find_selection(d)
    }
    fn insert_selection(&mut self, r: &TenantSelectionRecord) -> Result<(), StoreError> {
        self.d.selections.push(r.clone());
        Ok(())
    }
    fn consume_selection(&mut self, id: &str, n: SystemTime) -> Result<(), StoreError> {
        self.d
            .selections
            .iter_mut()
            .find(|x| x.id == id)
            .ok_or(StoreError::NotFound("selection"))
            .map(|x| x.consumed_at = Some(n))
    }
    fn list_tenants(
        &mut self,
        a: &str,
        _: &AccessPageRequest,
    ) -> Result<Vec<SubjectTenant>, StoreError> {
        Ok(self
            .d
            .members
            .iter()
            .filter(|m| {
                m.subject_id == a && m.status != MembershipStatus::Removed && m.tenant_id != "0"
            })
            .filter_map(|m| {
                self.d
                    .tenants
                    .get(&m.tenant_id)
                    .cloned()
                    .map(|t| SubjectTenant {
                        tenant: t,
                        membership: m.clone(),
                    })
            })
            .collect())
    }
    fn session_device(
        &mut self,
        tenant: &str,
        account: &str,
        device: &str,
    ) -> Result<Option<TenantSessionDevice>, StoreError> {
        Ok((|| {
            let d = self
                .d
                .proof_devices
                .iter()
                .find(|d| d.tenant_id == tenant && d.id == device)?;
            let k = self.d.proof_keys.iter().find(|k| {
                k.tenant_id == tenant
                    && k.device_id == device
                    && Some(&k.key_id) == d.proof_key_id.as_ref()
            })?;
            let b = self.d.proof_bindings.iter().find(|b| {
                b.tenant_id == tenant
                    && b.account_id == account
                    && b.device_id == device
                    && b.status != AccountDeviceBindingStatus::Unbound
            })?;
            Some(TenantSessionDevice {
                device: d.clone(),
                key: k.clone(),
                binding: b.clone(),
            })
        })())
    }
    fn session(&mut self, t: &str, id: &str) -> Result<Option<TenantSession>, StoreError> {
        Ok(self
            .d
            .sessions
            .iter()
            .find(|s| s.tenant_id == t && s.id == id)
            .cloned())
    }
    fn insert_session(
        &mut self,
        s: &TenantSession,
        id: &str,
        digest: &[u8; 32],
        expiry: SystemTime,
    ) -> Result<(), StoreError> {
        self.d.sessions.push(s.clone());
        self.d.refreshes.push(TenantRefreshRecord {
            tenant_id: s.tenant_id.clone(),
            id: id.into(),
            session_id: s.id.clone(),
            token_digest: *digest,
            token_version: 1,
            issued_at: s.created_at,
            expires_at: expiry,
            revoked_at: None,
            revocation_reason: None,
        });
        if self.d.fail_insert {
            return Err(StoreError::Backend("session".into()));
        }
        Ok(())
    }
}

#[test]
fn bearer_refresh_rotates_in_both_modes_and_reuse_revokes_only_its_family() {
    for (mode, tenant) in [(TenancyMode::Disabled, "0"), (TenancyMode::Enabled, "t1")] {
        let s = seed();
        if mode == TenancyMode::Disabled {
            s.0.lock().unwrap().members.push(m("0", "a"));
        }
        let auth = svc_mode(
            mode,
            LoginTenantPolicy::Fixed {
                tenant_id: tenant.into(),
            },
            s.clone(),
        );
        let TenantLoginOutcome::Authenticated(first) = auth.login(login()).unwrap() else {
            panic!()
        };
        let TenantLoginOutcome::Authenticated(other) = auth.login(login()).unwrap() else {
            panic!()
        };
        let TenantRefreshOutcome::Rotated { session, tokens } = auth
            .rotate_refresh(first.tokens.refresh_token.clone())
            .unwrap()
        else {
            panic!()
        };
        assert_eq!(session.refresh_token_version, 2);
        assert_eq!(tokens.refresh_expires_at, first.session.expires_at);
        assert!(auth.authenticate(tokens.access_token.token).is_ok());
        assert_eq!(
            auth.rotate_refresh(first.tokens.refresh_token),
            Ok(TenantRefreshOutcome::ReuseDetected {
                tenant_id: tenant.into(),
                session_id: session.id
            })
        );
        assert!(auth.authenticate(first.tokens.access_token).is_err());
        assert!(auth.authenticate(other.tokens.access_token).is_ok());
        assert!(auth.rotate_refresh(tokens.refresh_token).is_err());
    }
}

#[test]
fn fixed_login_requires_membership_and_issues_session() {
    let s = seed();
    let x = svc(
        LoginTenantPolicy::Fixed {
            tenant_id: "t1".into(),
        },
        s.clone(),
    );
    assert!(matches!(
        x.login(login()),
        Ok(TenantLoginOutcome::Authenticated(_))
    ));
    assert_eq!(s.0.lock().unwrap().sessions.len(), 1);
    let y = svc_mode(
        TenancyMode::Disabled,
        LoginTenantPolicy::Fixed {
            tenant_id: "0".into(),
        },
        s,
    );
    assert_eq!(y.login(login()), Err(TenantAuthError::InvalidCredentials));
}
#[test]
fn choose_login_creates_only_ticket_then_selects_and_authenticates() {
    let s = seed();
    let x = svc(LoginTenantPolicy::ChooseAfterAuthentication, s.clone());
    let ticket = match x.login(login()).unwrap() {
        TenantLoginOutcome::SelectionRequired(t) => t,
        _ => panic!(),
    };
    assert!(s.0.lock().unwrap().sessions.is_empty());
    let listed = x
        .list_tenants(ticket.ticket.clone(), AccessPageRequest::default())
        .unwrap();
    assert_eq!(listed.items.len(), 2);
    let out = x.select_tenant(ticket.ticket, "t2".into()).unwrap();
    assert_eq!(out.session.tenant_id, "t2");
    let actor = x.authenticate(out.tokens.access_token).unwrap();
    assert_eq!(actor.tenant_id, "t2");
}
#[test]
fn unknown_ticket_is_rejected() {
    let s = seed();
    let x = svc(LoginTenantPolicy::ChooseAfterAuthentication, s);
    assert_eq!(
        x.list_tenants(SecretString::new("bad"), AccessPageRequest::default()),
        Err(TenantAuthError::InvalidSelection)
    );
}

#[test]
fn selection_record_metadata_and_membership_are_rechecked() {
    let s = seed();
    let x = svc(LoginTenantPolicy::ChooseAfterAuthentication, s.clone());
    let ticket = match x.login(login()).unwrap() {
        TenantLoginOutcome::SelectionRequired(t) => t,
        _ => panic!(),
    };
    let original = s.0.lock().unwrap().selections[0].clone();
    for field in ["client", "entry", "purpose"] {
        let mut changed = original.clone();
        match field {
            "client" => changed.client_id = "other".into(),
            "entry" => changed.login_entry = "other".into(),
            _ => changed.purpose = "other".into(),
        }
        s.0.lock().unwrap().selections[0] = changed;
        assert_eq!(
            x.select_tenant(ticket.ticket.clone(), "t1".into()),
            Err(TenantAuthError::InvalidSelection),
            "{field}"
        );
    }
    s.0.lock().unwrap().selections[0] = original;
    let ticket = match x.login(login()).unwrap() {
        TenantLoginOutcome::SelectionRequired(t) => t,
        _ => panic!(),
    };
    s.0.lock()
        .unwrap()
        .members
        .iter_mut()
        .find(|m| m.tenant_id == "t1")
        .unwrap()
        .status = MembershipStatus::Suspended;
    assert_eq!(
        x.select_tenant(ticket.ticket, "t1".into()),
        Err(TenantAuthError::InvalidSelection)
    );
}

#[test]
fn consumed_expired_and_revoked_tickets_fail() {
    let s = seed();
    let x = svc(LoginTenantPolicy::ChooseAfterAuthentication, s.clone());
    let ticket = match x.login(login()).unwrap() {
        TenantLoginOutcome::SelectionRequired(t) => t,
        _ => panic!(),
    };
    let original = s.0.lock().unwrap().selections[0].clone();
    for state in ["consumed", "revoked", "expired", "future"] {
        let mut changed = original.clone();
        match state {
            "consumed" => changed.consumed_at = Some(C.now()),
            "revoked" => changed.revoked_at = Some(C.now()),
            "expired" => changed.expires_at = C.now(),
            _ => changed.authenticated_at = C.now() + Duration::from_secs(1),
        }
        s.0.lock().unwrap().selections[0] = changed;
        assert_eq!(
            x.list_tenants(ticket.ticket.clone(), AccessPageRequest::default()),
            Err(TenantAuthError::InvalidSelection),
            "{state}"
        );
        assert_eq!(
            x.select_tenant(ticket.ticket.clone(), "t1".into()),
            Err(TenantAuthError::InvalidSelection),
            "{state}"
        );
    }
}

#[test]
fn session_insert_failure_rolls_back_and_fixed_policy_rejects_switch() {
    let s = seed();
    s.0.lock().unwrap().fail_insert = true;
    let x = svc(LoginTenantPolicy::ChooseAfterAuthentication, s.clone());
    let ticket = match x.login(login()).unwrap() {
        TenantLoginOutcome::SelectionRequired(t) => t,
        _ => panic!(),
    };
    assert!(matches!(
        x.select_tenant(ticket.ticket.clone(), "t1".into()),
        Err(TenantAuthError::Store(StoreError::Backend(_)))
    ));
    {
        let mut data = s.0.lock().unwrap();
        assert!(data.sessions.is_empty());
        assert!(data.selections[0].consumed_at.is_none());
        data.fail_insert = false;
    }
    assert!(x.select_tenant(ticket.ticket, "t1".into()).is_ok());
    let fixed = svc(
        LoginTenantPolicy::Fixed {
            tenant_id: "t1".into(),
        },
        s,
    );
    assert_eq!(
        fixed.begin_switch(SecretString::new("x")),
        Err(TenantAuthError::InvalidSelection)
    );
}

#[test]
fn device_proof_requirement_fails_closed_for_session_issuance() {
    let s = seed();
    let fixed = svc_proof(
        LoginTenantPolicy::Fixed {
            tenant_id: "t1".into(),
        },
        s.clone(),
    );
    assert_eq!(
        fixed.login(login()),
        Err(TenantAuthError::DeviceProofRequired)
    );
    let choose = svc_proof(LoginTenantPolicy::ChooseAfterAuthentication, s);
    let ticket = match choose.login(login()).unwrap() {
        TenantLoginOutcome::SelectionRequired(t) => t,
        _ => panic!(),
    };
    assert_eq!(
        choose.select_tenant(ticket.ticket, "t1".into()),
        Err(TenantAuthError::DeviceProofRequired)
    );
}

#[test]
fn switch_ticket_rechecks_source_session_and_cursor_scope() {
    let s = seed();
    let x = svc(LoginTenantPolicy::ChooseAfterAuthentication, s.clone());
    let TenantLoginOutcome::SelectionRequired(ticket) = x.login(login()).unwrap() else {
        panic!()
    };
    let session = x.select_tenant(ticket.ticket, "t1".into()).unwrap();
    let switch = x.begin_switch(session.tokens.access_token).unwrap();
    let page = AccessPageRequest {
        limit: 1,
        cursor: Some(AccessCursor {
            version: 1,
            scope: AccessListScope::SubjectTenants {
                subject_id: "other".into(),
            },
            after: vec!["t1".into()],
            sort_order: None,
        }),
        sort_order: None,
    };
    assert_eq!(
        x.list_tenants(switch.ticket.clone(), page),
        Err(TenantAuthError::Access(AccessError::InvalidCursor))
    );
    s.0.lock().unwrap().sessions[0].status = SessionStatus::Revoked;
    assert_eq!(
        x.list_tenants(switch.ticket.clone(), AccessPageRequest::default()),
        Err(TenantAuthError::InvalidSelection)
    );
    assert_eq!(
        x.select_tenant(switch.ticket, "t2".into()),
        Err(TenantAuthError::InvalidSelection)
    );
    assert_eq!(s.0.lock().unwrap().sessions.len(), 1);
}

pub(super) mod device_proofs {
    use super::*;
    use base64ct::{Base64UrlUnpadded, Encoding};

    impl TenantDeviceProofTransaction for T<'_> {
        fn key_metadata(
            &mut self,
            _: &str,
            _: &str,
            _: &str,
        ) -> Result<Option<DeviceKeyMetadata>, StoreError> {
            Ok(None)
        }
        fn registration_for_device(
            &mut self,
            tenant: &str,
            device: &str,
        ) -> Result<Option<TenantDeviceRegistration>, StoreError> {
            Ok(self
                .d
                .registrations
                .iter()
                .find(|r| r.tenant_id == tenant && r.device_id == device)
                .cloned())
        }
        fn lock_proof_device(
            &mut self,
            tenant: &str,
            device: &str,
        ) -> Result<Option<TenantProofDevice>, StoreError> {
            Ok(self
                .d
                .proof_devices
                .iter()
                .find(|d| d.tenant_id == tenant && d.id == device)
                .cloned())
        }
        fn lock_proof_key(
            &mut self,
            tenant: &str,
            device: &str,
            key: &str,
        ) -> Result<Option<TenantProofKey>, StoreError> {
            Ok(self
                .d
                .proof_keys
                .iter()
                .find(|k| k.tenant_id == tenant && k.device_id == device && k.key_id == key)
                .cloned())
        }
        fn lock_proof_binding(
            &mut self,
            tenant: &str,
            account: &str,
            device: &str,
        ) -> Result<Option<TenantProofBinding>, StoreError> {
            Ok(self
                .d
                .proof_bindings
                .iter()
                .find(|b| {
                    b.tenant_id == tenant
                        && b.account_id == account
                        && b.device_id == device
                        && b.status != AccountDeviceBindingStatus::Unbound
                })
                .cloned())
        }
        fn lock_proof_challenge(
            &mut self,
            tenant: &str,
            digest: &[u8; 32],
        ) -> Result<Option<TenantProofChallenge>, StoreError> {
            Ok(self
                .d
                .proof_challenges
                .iter()
                .find(|c| c.tenant_id == tenant && &c.challenge_digest == digest)
                .cloned())
        }
        fn insert_proof_challenge(&mut self, c: &TenantProofChallenge) -> Result<(), StoreError> {
            self.d.proof_challenges.push(c.clone());
            Ok(())
        }
        fn consume_proof_challenge(
            &mut self,
            tenant: &str,
            digest: &[u8; 32],
            now: SystemTime,
        ) -> Result<bool, StoreError> {
            let c = self
                .d
                .proof_challenges
                .iter_mut()
                .find(|c| c.tenant_id == tenant && &c.challenge_digest == digest)
                .unwrap();
            if c.consumed_at.is_some() || c.expires_at <= now {
                return Ok(false);
            }
            c.consumed_at = Some(now);
            if self.d.fail_consume {
                return Err(StoreError::Backend("injected consume failure".into()));
            }
            Ok(true)
        }
    }
    impl TenantDeviceLoginTransaction for T<'_> {
        fn insert_login_binding(
            &mut self,
            binding: &TenantProofBinding,
            _: &str,
            _: SystemTime,
            _: &str,
            _: &str,
            _: &str,
        ) -> Result<(), StoreError> {
            self.d.proof_bindings.push(binding.clone());
            Ok(())
        }
    }
    pub(super) struct Crypto;
    impl DevicePublicJwkValidator for Crypto {
        fn validate_ed25519_public_jwk(
            &self,
            jwk: &str,
        ) -> Result<ValidatedDevicePublicJwk, SecurityContractError> {
            let bytes = if jwk == "new" { [2; 32] } else { [1; 32] };
            Ok(ValidatedDevicePublicJwk {
                key_id: Base64UrlUnpadded::encode_string(&bytes),
                public_key: bytes,
                canonical_public_jwk: jwk.into(),
            })
        }
    }
    impl DeviceSignatureVerifier for Crypto {
        fn verify_ed25519(
            &self,
            _: &[u8; 32],
            _: &[u8],
            signature: &[u8; 64],
        ) -> Result<(), SecurityContractError> {
            if signature == &[3; 64] {
                Ok(())
            } else {
                Err(SecurityContractError::InvalidSignature)
            }
        }
    }
    pub(super) struct Challenges;
    impl DeviceChallengeGenerator for Challenges {
        fn generate_device_challenge(&self) -> Result<SecretString, SecurityContractError> {
            static NEXT: AtomicUsize = AtomicUsize::new(1);
            let mut bytes = [0; 32];
            bytes[..8]
                .copy_from_slice(&(NEXT.fetch_add(1, Ordering::Relaxed) as u64).to_be_bytes());
            Ok(SecretString::new(Base64UrlUnpadded::encode_string(&bytes)))
        }
    }
    type ProofService = CoreTenantDeviceProofService<S, Crypto, Crypto, Challenges, C, I>;
    fn fixture() -> (S, ProofService, VerifyTenantDeviceRequest) {
        let s = seed();
        let auth = svc(
            LoginTenantPolicy::Fixed {
                tenant_id: "t1".into(),
            },
            s.clone(),
        );
        let TenantLoginOutcome::Authenticated(login) = auth.login(login()).unwrap() else {
            panic!()
        };
        let actor = auth.authenticate(login.tokens.access_token).unwrap();
        let key = Base64UrlUnpadded::encode_string(&[1; 32]);
        {
            let mut data = s.0.lock().unwrap();
            data.proof_devices.push(TenantProofDevice {
                tenant_id: "t1".into(),
                id: "d1".into(),
                client_id: "web".into(),
                proof_key_id: Some(key.clone()),
                status: DeviceStatus::Active,
                version: 1,
                key_version: None,
            });
            data.proof_keys.push(TenantProofKey {
                tenant_id: "t1".into(),
                device_id: "d1".into(),
                key_id: key.clone(),
                public_jwk: "test".into(),
                version: 1,
                status: DeviceProofKeyStatus::Active,
            });
            data.proof_bindings.push(TenantProofBinding {
                tenant_id: "t1".into(),
                account_id: "a".into(),
                device_id: "d1".into(),
                status: AccountDeviceBindingStatus::Active,
            });
        }
        let purpose = DeviceProofPurpose::new("report_read").unwrap();
        let service = CoreTenantDeviceProofService::new(
            TenancyMode::Enabled,
            TenantDeviceProofConfig {
                client_id: "web".into(),
                allowed_purposes: vec![
                    purpose.clone(),
                    DeviceProofPurpose::new(CLIENT_SYNC_TRANSPORT_PURPOSE).unwrap(),
                ],
                challenge_ttl_secs: 60,
                clock_skew_secs: 30,
            },
            s.clone(),
            Crypto,
            Crypto,
            Challenges,
            C,
            I,
        )
        .unwrap();
        let nonce = service
            .issue_challenge("t1", "d1", purpose.clone())
            .unwrap();
        let command = VerifyTenantDeviceRequest {
            actor,
            expected_purpose: purpose,
            proof: DeviceProofPresentation {
                device_id: "d1".into(),
                key_id: key,
                challenge: nonce.challenge.into_exposed(),
                signature: Base64UrlUnpadded::encode_string(&[3; 64]),
                signed_at: C.now(),
            },
            binding: DeviceRequestBinding::new(
                "t1",
                DeviceProofProfile::new("EMBEDDED-IDP-DEVICE-REQUEST-V2").unwrap(),
                "api",
                CanonicalHttpMethod::Get,
                "/reports",
                [0; 32],
            )
            .unwrap(),
        };
        (s, service, command)
    }
    #[test]
    fn tenant_proof_checks_current_state_before_consuming_nonce() {
        let (s, service, command) = fixture();
        let initial = s.0.lock().unwrap().clone();
        for case in 0..14 {
            let mut changed = initial.clone();
            match case {
                0 => changed.accounts.get_mut("a").unwrap().active = false,
                1 => changed.tenants.get_mut("t1").unwrap().status = TenantStatus::Suspended,
                2 => changed.members[0].status = MembershipStatus::Removed,
                3 => changed.sessions[0].status = SessionStatus::Revoked,
                4 => changed.sessions[0].expires_at = C.now(),
                5 => changed.proof_devices[0].status = DeviceStatus::Disabled,
                6 => changed.proof_keys[0].status = DeviceProofKeyStatus::Retired,
                7 => changed.proof_bindings[0].status = AccountDeviceBindingStatus::Suspended,
                8 => {
                    changed.proof_challenges[0].purpose = DeviceProofPurpose::new("other").unwrap()
                }
                9 => changed.proof_challenges[0].expires_at = C.now(),
                10 => changed.proof_challenges[0].issued_at = C.now() + Duration::from_secs(1),
                11 => changed.proof_devices[0].client_id = "other".into(),
                12 => changed.proof_devices[0].proof_key_id = Some("other".into()),
                _ => changed.sessions[0].device_id = Some("other".into()),
            }
            *s.0.lock().unwrap() = changed;
            assert!(
                service.verify_request(command.clone()).is_err(),
                "case {case}"
            );
            assert!(s.0.lock().unwrap().proof_challenges[0]
                .consumed_at
                .is_none());
        }
        *s.0.lock().unwrap() = initial;
        let result = service.verify_request(command.clone()).unwrap();
        assert_eq!(
            (result.tenant_id.as_str(), result.account_id.as_str()),
            ("t1", "a")
        );
        assert_eq!(
            service.verify_request(command),
            Err(TenantAuthError::DeviceProof(
                DeviceRequestVerificationError::ReplayedProof
            ))
        );
    }
    #[test]
    fn device_transport_needs_no_person_and_consumes_only_valid_proof() {
        let (store, service, request) = fixture();
        {
            let mut data = store.0.lock().unwrap();
            data.accounts.clear();
            data.members.clear();
            data.sessions.clear();
            data.proof_bindings.clear();
        }
        let purpose = DeviceProofPurpose::new(CLIENT_SYNC_TRANSPORT_PURPOSE).unwrap();
        let nonce = service.issue_challenge("t1", "d1", purpose).unwrap();
        let mut proof = request.proof;
        proof.challenge = nonce.challenge.into_exposed();
        let binding = request.binding;
        let original = store.0.lock().unwrap().clone();
        for case in 0..9 {
            let mut changed = original.clone();
            let mut request_binding = binding.clone();
            match case {
                0 => changed.tenants.get_mut("t1").unwrap().status = TenantStatus::Suspended,
                1 => changed.clients.clear(),
                2 => changed.proof_devices[0].status = DeviceStatus::Disabled,
                3 => changed.proof_keys[0].status = DeviceProofKeyStatus::Retired,
                4 => changed.proof_challenges[1].expires_at = C.now(),
                5 => {
                    changed.proof_challenges[1].purpose = DeviceProofPurpose::new("other").unwrap()
                }
                6 => request_binding.tenant_id = "t2".into(),
                7 => changed.proof_devices[0].proof_key_id = Some("other".into()),
                _ => changed.proof_devices[0].client_id = "other".into(),
            }
            *store.0.lock().unwrap() = changed;
            assert!(
                service
                    .verify_device_transport_request(proof.clone(), request_binding)
                    .is_err(),
                "case {case}"
            );
            assert!(store.0.lock().unwrap().proof_challenges[1]
                .consumed_at
                .is_none());
        }
        *store.0.lock().unwrap() = original;
        let verified = service
            .verify_device_transport_request(proof.clone(), binding.clone())
            .unwrap();
        assert_eq!(
            (
                verified.tenant_id.as_str(),
                verified.client_id.as_str(),
                verified.device_id.as_str()
            ),
            ("t1", "web", "d1")
        );
        assert_eq!((verified.device_version, verified.key_version), (1, 1));
        assert_eq!(
            service.verify_device_transport_request(proof, binding),
            Err(TenantAuthError::DeviceProof(
                DeviceRequestVerificationError::ReplayedProof
            ))
        );
    }
    #[test]
    fn invalid_signature_tenant_or_write_failure_preserves_nonce() {
        let (s, service, command) = fixture();
        let mut bad = command.clone();
        bad.binding.tenant_id = "t2".into();
        assert!(service.verify_request(bad).is_err());
        let mut bad = command.clone();
        bad.proof.signature = Base64UrlUnpadded::encode_string(&[4; 64]);
        assert!(service.verify_request(bad).is_err());
        s.0.lock().unwrap().fail_consume = true;
        assert!(matches!(
            service.verify_request(command.clone()),
            Err(TenantAuthError::Store(_))
        ));
        assert!(s.0.lock().unwrap().proof_challenges[0]
            .consumed_at
            .is_none());
        s.0.lock().unwrap().fail_consume = false;
        assert!(service.verify_request(command).is_ok());
    }
    #[test]
    fn unknown_or_ineligible_device_gets_no_stored_nonce() {
        let (s, service, command) = fixture();
        for (tenant, device) in [("t1", "missing"), ("t2", "d1")] {
            assert_eq!(
                service
                    .issue_challenge(tenant, device, command.expected_purpose.clone())
                    .unwrap()
                    .expires_at,
                C.now() + Duration::from_secs(60)
            );
        }
        s.0.lock().unwrap().proof_devices[0].status = DeviceStatus::Disabled;
        service
            .issue_challenge("t1", "d1", command.expected_purpose)
            .unwrap();
        assert_eq!(s.0.lock().unwrap().proof_challenges.len(), 1);
    }
    impl TenantDeviceLifecycleTransaction for T<'_> {
        fn append_rotation_audit(
            &mut self,
            _: &AccessActor,
            _: &TenantProofDevice,
            _: &TenantProofKey,
            _: &TenantProofKey,
            _: SystemTime,
            _: &str,
            _: &str,
        ) -> Result<(), StoreError> {
            Ok(())
        }
        fn registration(
            &mut self,
            tenant: &str,
            client: &str,
            scope: &str,
            request_id: &str,
        ) -> Result<Option<TenantDeviceRegistration>, StoreError> {
            Ok(self
                .d
                .registrations
                .iter()
                .find(|r| {
                    r.tenant_id == tenant
                        && r.client_id == client
                        && r.registration_scope == scope
                        && r.registration_request_id == request_id
                })
                .cloned())
        }
        fn insert_registration(&mut self, r: &TenantDeviceRegistration) -> Result<(), StoreError> {
            if self.d.registrations.iter().any(|x| {
                x.expected_key_id == r.expected_key_id
                    || x.tenant_id == r.tenant_id && x.device_id == r.device_id
            }) || self
                .d
                .proof_keys
                .iter()
                .any(|k| k.key_id == r.expected_key_id)
            {
                return Err(StoreError::Conflict("device_key"));
            }
            self.d.registrations.push(r.clone());
            Ok(())
        }
        fn complete_registration_record(
            &mut self,
            tenant: &str,
            device: &str,
            now: SystemTime,
        ) -> Result<(), StoreError> {
            let r = self
                .d
                .registrations
                .iter_mut()
                .find(|r| {
                    r.tenant_id == tenant && r.device_id == device && r.completed_at.is_none()
                })
                .ok_or(StoreError::Conflict("device_registration"))?;
            r.completed_at = Some(now);
            Ok(())
        }
        fn insert_pending_device(
            &mut self,
            d: &TenantProofDevice,
            _: &str,
            _: SystemTime,
        ) -> Result<(), StoreError> {
            self.d.proof_devices.push(d.clone());
            Ok(())
        }
        fn activate_device_key(
            &mut self,
            key: &TenantProofKey,
            old: Option<&str>,
            _: SystemTime,
        ) -> Result<(), StoreError> {
            if let Some(old) = old {
                self.d
                    .proof_keys
                    .iter_mut()
                    .find(|k| {
                        k.tenant_id == key.tenant_id
                            && k.device_id == key.device_id
                            && k.key_id == old
                    })
                    .unwrap()
                    .status = DeviceProofKeyStatus::Retired;
            }
            self.d.proof_keys.push(key.clone());
            let device = self
                .d
                .proof_devices
                .iter_mut()
                .find(|d| d.tenant_id == key.tenant_id && d.id == key.device_id)
                .unwrap();
            device.status = DeviceStatus::Active;
            device.proof_key_id = Some(key.key_id.clone());
            device.key_version = Some(key.version);
            device.version += 1;
            if self.d.fail_insert {
                return Err(StoreError::Backend("injected key write failure".into()));
            }
            Ok(())
        }
    }
    struct Admission(bool);
    impl TenantDeviceAdmission for Admission {
        fn authorize(
            &self,
            _: &str,
            _: &str,
            _: &str,
            _: DeviceAdmissionAction,
            _: &TrustedDeviceAdmission,
        ) -> Result<(), AccessError> {
            if self.0 {
                Ok(())
            } else {
                Err(AccessError::Forbidden)
            }
        }
    }
    fn trusted() -> TrustedDeviceAdmission {
        TrustedDeviceAdmission {
            registration_scope: "test_scope".into(),
            valid_until: C.now() + Duration::from_secs(3600),
        }
    }
    fn provision(tenant: &str) -> ProvisionTenantDevice {
        ProvisionTenantDevice {
            tenant_id: tenant.into(),
            device_id: uuid::Uuid::from_u128(42).to_string(),
            registration_request_id: uuid::Uuid::from_u128(43).to_string(),
            device_name: "Laptop".into(),
            public_jwk: "test".into(),
        }
    }
    fn lifecycle(mode: TenancyMode, s: S) -> ProofService {
        CoreTenantDeviceProofService::new(
            mode,
            TenantDeviceProofConfig {
                client_id: "web".into(),
                allowed_purposes: vec![
                    DeviceProofPurpose::new(DEVICE_REGISTRATION_PURPOSE).unwrap(),
                    DeviceProofPurpose::new(DEVICE_KEY_ROTATION_PURPOSE).unwrap(),
                    DeviceProofPurpose::new(TENANT_DEVICE_LOGIN_PURPOSE).unwrap(),
                    DeviceProofPurpose::new(TENANT_DEVICE_SELECTION_PURPOSE).unwrap(),
                    DeviceProofPurpose::new(REFRESH_PURPOSE).unwrap(),
                ],
                challenge_ttl_secs: 60,
                clock_skew_secs: 30,
            },
            s,
            Crypto,
            Crypto,
            Challenges,
            C,
            I,
        )
        .unwrap()
    }
    #[test]
    fn device_registration_requires_admission_and_commits_activation_with_nonce() {
        for (mode, tenant) in [(TenancyMode::Disabled, "0"), (TenancyMode::Enabled, "t1")] {
            let s = seed();
            let service = lifecycle(mode, s.clone());
            assert_eq!(
                service.provision_device(provision(tenant), &trusted(), &Admission(false)),
                Err(TenantAuthError::Access(AccessError::Forbidden))
            );
            assert!(s.0.lock().unwrap().proof_devices.is_empty());
            let mut short_admission = trusted();
            short_admission.valid_until = C.now() + Duration::from_millis(500);
            assert_eq!(
                service.provision_device(provision(tenant), &short_admission, &Admission(true)),
                Err(TenantAuthError::Access(AccessError::Forbidden))
            );
            assert!(s.0.lock().unwrap().proof_devices.is_empty());
            let device = service
                .provision_device(provision(tenant), &trusted(), &Admission(true))
                .unwrap();
            assert_eq!(device.device.status, DeviceStatus::Pending);
            assert_eq!(
                service
                    .provision_device(provision(tenant), &trusted(), &Admission(true))
                    .unwrap(),
                device
            );
            let mut changed = provision(tenant);
            changed.device_name = "Different".into();
            assert_eq!(
                service.provision_device(changed, &trusted(), &Admission(true)),
                Err(TenantAuthError::Access(AccessError::Conflict(
                    "device_registration"
                )))
            );
            let lookup = DeviceRegistrationLookup {
                tenant_id: tenant.into(),
                device_id: device.device.id.clone(),
                registration_request_id: provision(tenant).registration_request_id,
            };
            assert_eq!(
                service
                    .registration_result(lookup.clone(), &trusted(), &Admission(true))
                    .unwrap(),
                device
            );
            let mut different_scope = trusted();
            different_scope.registration_scope = "other".into();
            assert_eq!(
                service.registration_result(lookup.clone(), &different_scope, &Admission(true)),
                Err(TenantAuthError::Access(AccessError::NotFound(
                    "device_registration"
                )))
            );
            assert_eq!(s.0.lock().unwrap().proof_devices.len(), 1);
            s.0.lock().unwrap().registrations[0].expires_at = C.now();
            service
                .issue_challenge(
                    tenant,
                    &device.device.id,
                    DeviceProofPurpose::new(DEVICE_REGISTRATION_PURPOSE).unwrap(),
                )
                .unwrap();
            assert!(s.0.lock().unwrap().proof_challenges.is_empty());
            s.0.lock().unwrap().registrations[0].expires_at = C.now() + Duration::from_secs(3600);
            assert!(s.0.lock().unwrap().proof_challenges.is_empty());
            let challenge = service
                .issue_challenge(
                    tenant,
                    &device.device.id,
                    DeviceProofPurpose::new(DEVICE_REGISTRATION_PURPOSE).unwrap(),
                )
                .unwrap();
            let command = CompleteTenantDeviceRegistration {
                tenant_id: tenant.into(),
                device_id: device.device.id,
                public_jwk: "test".into(),
                challenge: challenge.challenge,
                signature: SecretString::new(Base64UrlUnpadded::encode_string(&[3; 64])),
            };
            let mut wrong_key = command.clone();
            wrong_key.public_jwk = "new".into();
            assert!(service.complete_registration(wrong_key).is_err());
            assert!(s.0.lock().unwrap().proof_challenges[0]
                .consumed_at
                .is_none());
            s.0.lock().unwrap().fail_insert = true;
            assert!(service.complete_registration(command.clone()).is_err());
            {
                let data = s.0.lock().unwrap();
                assert_eq!(data.proof_devices[0].status, DeviceStatus::Pending);
                assert!(data.proof_keys.is_empty());
                assert!(data.proof_challenges[0].consumed_at.is_none());
            }
            s.0.lock().unwrap().fail_insert = false;
            let key = service.complete_registration(command.clone()).unwrap();
            assert_eq!(key.version, 1);
            let result = service
                .registration_result(lookup, &trusted(), &Admission(true))
                .unwrap();
            assert_eq!(result.device.version, 2);
            assert_eq!(result.completed_at, Some(C.now()));
            assert!(service.complete_registration(command).is_err());
            let data = s.0.lock().unwrap();
            assert_eq!(data.proof_devices[0].status, DeviceStatus::Active);
            assert_eq!(
                data.proof_devices[0].proof_key_id.as_ref(),
                Some(&key.key_id)
            );
            assert!(data.proof_challenges[0].consumed_at.is_some());
        }
    }
    #[test]
    fn key_rotation_requires_both_signatures_and_rolls_back_retirement_on_failure() {
        let (s, _, request) = fixture();
        let service = lifecycle(TenancyMode::Enabled, s.clone());
        let nonce = service
            .issue_challenge(
                "t1",
                "d1",
                DeviceProofPurpose::new(DEVICE_KEY_ROTATION_PURPOSE).unwrap(),
            )
            .unwrap();
        let current_key_id = s.0.lock().unwrap().proof_keys[0].key_id.clone();
        let command = RotateTenantDeviceKey {
            actor: request.actor,
            device_id: "d1".into(),
            expected_key_id: current_key_id,
            expected_key_version: 1,
            proposed_public_jwk: "new".into(),
            challenge: nonce.challenge,
            current_key_signature: SecretString::new(Base64UrlUnpadded::encode_string(&[3; 64])),
            proposed_key_signature: SecretString::new(Base64UrlUnpadded::encode_string(&[3; 64])),
        };
        for old in [false, true] {
            let mut bad = command.clone();
            let signature = SecretString::new(Base64UrlUnpadded::encode_string(&[4; 64]));
            if old {
                bad.current_key_signature = signature
            } else {
                bad.proposed_key_signature = signature
            }
            assert!(service.rotate_key(bad).is_err());
        }
        s.0.lock().unwrap().fail_insert = true;
        assert!(service.rotate_key(command.clone()).is_err());
        {
            let data = s.0.lock().unwrap();
            assert_eq!(data.proof_keys.len(), 1);
            assert_eq!(data.proof_keys[0].status, DeviceProofKeyStatus::Active);
            assert!(data
                .proof_challenges
                .iter()
                .all(|c| c.consumed_at.is_none()));
        }
        s.0.lock().unwrap().fail_insert = false;
        let key = service.rotate_key(command.clone()).unwrap();
        assert_eq!(key.version, 2);
        assert!(service.rotate_key(command).is_err());
        let data = s.0.lock().unwrap();
        assert_eq!(data.proof_keys[0].status, DeviceProofKeyStatus::Retired);
        assert_eq!(
            data.proof_devices[0].proof_key_id.as_ref(),
            Some(&key.key_id)
        );
    }
    fn login_proof(service: &ProofService, purpose: &str) -> TenantAuthenticationProof {
        let nonce = service
            .issue_challenge("t1", "d1", DeviceProofPurpose::new(purpose).unwrap())
            .unwrap();
        TenantAuthenticationProof {
            proof: DeviceProofPresentation {
                device_id: "d1".into(),
                key_id: Base64UrlUnpadded::encode_string(&[1; 32]),
                challenge: nonce.challenge.into_exposed(),
                signature: Base64UrlUnpadded::encode_string(&[3; 64]),
                signed_at: C.now(),
            },
            binding: DeviceRequestBinding::new(
                "t1",
                DeviceProofProfile::new(TENANT_DEVICE_AUTH_PROFILE).unwrap(),
                "api",
                CanonicalHttpMethod::Post,
                "/auth/login",
                [0; 32],
            )
            .unwrap(),
        }
    }
    fn login_devices() -> (S, ProofService) {
        let (s, _, _) = fixture();
        {
            let mut data = s.0.lock().unwrap();
            data.sessions.clear();
            data.refreshes.clear();
            data.proof_bindings.clear();
            data.proof_challenges.clear();
        }
        let devices = lifecycle(TenancyMode::Enabled, s.clone());
        (s, devices)
    }
    #[test]
    fn proven_login_checks_authority_and_rolls_back_binding_nonce_and_session_together() {
        let (s, devices) = login_devices();
        let auth = svc_proof(
            LoginTenantPolicy::Fixed {
                tenant_id: "t1".into(),
            },
            s.clone(),
        );
        let proof = login_proof(&devices, TENANT_DEVICE_LOGIN_PURPOSE);
        let initial = s.0.lock().unwrap().clone();
        for case in 0..9 {
            let mut changed = initial.clone();
            match case {
                0 => changed.accounts.get_mut("a").unwrap().active = false,
                1 => changed.members[0].status = MembershipStatus::Suspended,
                2 => changed.tenants.get_mut("t1").unwrap().status = TenantStatus::Suspended,
                3 => changed.proof_devices[0].status = DeviceStatus::Revoked,
                4 => changed.proof_keys[0].status = DeviceProofKeyStatus::Retired,
                5 => changed.proof_challenges[0].expires_at = C.now(),
                6 => changed.fail_insert = true,
                7 => changed.fail_consume = true,
                _ => changed.proof_bindings.push(TenantProofBinding {
                    tenant_id: "t1".into(),
                    account_id: "a".into(),
                    device_id: "d1".into(),
                    status: AccountDeviceBindingStatus::Suspended,
                }),
            }
            *s.0.lock().unwrap() = changed;
            assert!(
                auth.login_with_proof(login(), proof.clone(), &devices)
                    .is_err(),
                "case {case}"
            );
            let data = s.0.lock().unwrap();
            assert!(data.sessions.is_empty());
            assert!(data.proof_challenges[0].consumed_at.is_none());
            assert_eq!(data.proof_bindings.len(), if case == 8 { 1 } else { 0 });
        }
        *s.0.lock().unwrap() = initial;
        let TenantLoginOutcome::Authenticated(session) = auth
            .login_with_proof(login(), proof.clone(), &devices)
            .unwrap()
        else {
            panic!()
        };
        assert_eq!(session.session.device_id.as_deref(), Some("d1"));
        assert!(auth
            .authenticate(session.tokens.access_token.clone())
            .is_ok());
        assert!(auth.login_with_proof(login(), proof, &devices).is_err());
        s.0.lock().unwrap().proof_bindings[0].status = AccountDeviceBindingStatus::Suspended;
        assert!(auth.authenticate(session.tokens.access_token).is_err());
    }
    #[test]
    fn device_authentication_uses_the_current_session_and_rejects_device_less_tokens() {
        let (s, devices) = login_devices();
        let auth = svc_proof(
            LoginTenantPolicy::Fixed {
                tenant_id: "t1".into(),
            },
            s.clone(),
        );
        let TenantLoginOutcome::Authenticated(proven_login) = auth
            .login_with_proof(
                login(),
                login_proof(&devices, TENANT_DEVICE_LOGIN_PURPOSE),
                &devices,
            )
            .unwrap()
        else {
            panic!()
        };
        let token = proven_login.tokens.access_token.clone();
        let service = CoreTenantDeviceAuthenticationService::new(auth, devices);
        assert_eq!(
            service.authenticate_device(token.clone()).unwrap(),
            AuthenticatedDeviceSession {
                tenant_id: "t1".into(),
                subject_id: "a".into(),
                session_id: proven_login.session.id,
                device_id: "d1".into(),
                session_expires_at: proven_login.session.expires_at,
            }
        );
        let valid = s.0.lock().unwrap().clone();
        for case in 0..8 {
            let mut changed = valid.clone();
            match case {
                0 => changed.accounts.get_mut("a").unwrap().active = false,
                1 => changed.members[0].status = MembershipStatus::Suspended,
                2 => changed.sessions[0].status = SessionStatus::Revoked,
                3 => changed.proof_devices[0].status = DeviceStatus::Disabled,
                4 => changed.proof_keys[0].status = DeviceProofKeyStatus::Retired,
                5 => changed.proof_bindings[0].status = AccountDeviceBindingStatus::Unbound,
                6 => changed.sessions[0].expires_at = C.now(),
                _ => changed.tenants.get_mut("t1").unwrap().status = TenantStatus::Suspended,
            }
            *s.0.lock().unwrap() = changed;
            assert!(
                service.authenticate_device(token.clone()).is_err(),
                "case {case}"
            );
        }
        *s.0.lock().unwrap() = valid;
        assert!(service.authenticate_device(token).is_ok());

        let browser = CoreTenantDeviceAuthenticationService::new(
            svc(
                LoginTenantPolicy::Fixed {
                    tenant_id: "t1".into(),
                },
                s.clone(),
            ),
            lifecycle(TenancyMode::Enabled, s),
        );
        let TenantLoginOutcome::Authenticated(login) = browser.login(login()).unwrap() else {
            panic!()
        };
        assert!(browser
            .authenticate(login.tokens.access_token.clone())
            .is_ok());
        assert_eq!(
            browser.authenticate_device(login.tokens.access_token),
            Err(TenantAuthError::DeviceProofRequired)
        );
    }
    #[test]
    fn proven_selection_consumes_ticket_and_nonce_only_with_committed_session() {
        let (s, devices) = login_devices();
        let auth = svc_proof(LoginTenantPolicy::ChooseAfterAuthentication, s.clone());
        let TenantLoginOutcome::SelectionRequired(ticket) = auth.login(login()).unwrap() else {
            panic!()
        };
        let proof = login_proof(&devices, TENANT_DEVICE_SELECTION_PURPOSE);
        assert!(auth
            .select_tenant_with_proof(ticket.ticket.clone(), "t2".into(), proof.clone(), &devices)
            .is_err());
        s.0.lock().unwrap().fail_insert = true;
        assert!(auth
            .select_tenant_with_proof(ticket.ticket.clone(), "t1".into(), proof.clone(), &devices)
            .is_err());
        {
            let mut data = s.0.lock().unwrap();
            assert!(data.selections[0].consumed_at.is_none());
            assert!(data.proof_challenges[0].consumed_at.is_none());
            assert!(data.proof_bindings.is_empty());
            data.fail_insert = false;
        }
        let session = auth
            .select_tenant_with_proof(ticket.ticket, "t1".into(), proof, &devices)
            .unwrap();
        let switch = auth.begin_switch(session.tokens.access_token).unwrap();
        s.0.lock().unwrap().proof_devices[0].status = DeviceStatus::Disabled;
        assert!(auth
            .list_tenants(switch.ticket, AccessPageRequest::default())
            .is_err());
    }
    fn refresh_command(
        devices: &ProofService,
        raw: SecretString,
    ) -> RotateProofBoundRefreshCommand {
        let proof = login_proof(devices, REFRESH_PURPOSE);
        RotateProofBoundRefreshCommand {
            refresh_token: raw,
            proof: proof.proof,
            binding: proof.binding,
        }
    }
    #[test]
    fn tenant_refresh_rejects_invalid_authority_and_rolls_back_rotation_writes() {
        let (s, devices) = login_devices();
        let auth = svc_proof(
            LoginTenantPolicy::Fixed {
                tenant_id: "t1".into(),
            },
            s.clone(),
        );
        let TenantLoginOutcome::Authenticated(session) = auth
            .login_with_proof(
                login(),
                login_proof(&devices, TENANT_DEVICE_LOGIN_PURPOSE),
                &devices,
            )
            .unwrap()
        else {
            panic!()
        };
        let command = refresh_command(&devices, session.tokens.refresh_token.clone());
        assert_eq!(
            auth.rotate_refresh(session.tokens.refresh_token),
            Err(TenantAuthError::DeviceProofRequired)
        );
        let initial = s.0.lock().unwrap().clone();
        for case in 0..13 {
            let mut changed = initial.clone();
            match case {
                0 => changed.accounts.get_mut("a").unwrap().active = false,
                1 => changed.tenants.get_mut("t1").unwrap().status = TenantStatus::Suspended,
                2 => changed.members[0].status = MembershipStatus::Removed,
                3 => changed.sessions[0].status = SessionStatus::Revoked,
                4 => changed.refreshes[0].expires_at = C.now(),
                5 => changed.refreshes[0].issued_at = C.now() + Duration::from_secs(1),
                6 => changed.refreshes[0].token_version = 2,
                7 => {
                    changed.refreshes[0].revoked_at = Some(C.now());
                    changed.refreshes[0].revocation_reason =
                        Some(RefreshTokenRevocationReason::Administrative);
                }
                8 => changed.proof_bindings[0].status = AccountDeviceBindingStatus::Suspended,
                9 => changed.proof_keys[0].status = DeviceProofKeyStatus::Retired,
                10 => changed.fail_insert = true,
                11 => changed.fail_consume = true,
                _ => {
                    changed.sessions[0].expires_at = C.now() + Duration::from_secs(30);
                    changed.refreshes[0].expires_at = changed.sessions[0].expires_at;
                }
            }
            let expected = changed.clone();
            *s.0.lock().unwrap() = changed;
            assert!(
                auth.rotate_refresh_with_proof(command.clone(), &devices)
                    .is_err(),
                "case {case}"
            );
            let data = s.0.lock().unwrap();
            assert!(data.refreshes == expected.refreshes, "case {case}");
            assert_eq!(data.sessions, expected.sessions);
            assert!(data.proof_challenges == expected.proof_challenges);
        }
        *s.0.lock().unwrap() = initial;
        assert!(matches!(
            auth.rotate_refresh_with_proof(command, &devices),
            Ok(TenantRefreshOutcome::Rotated { .. })
        ));
    }
    #[test]
    fn proof_replay_is_not_refresh_reuse_and_reuse_revocation_must_commit() {
        let (s, devices) = login_devices();
        let auth = svc_proof(
            LoginTenantPolicy::Fixed {
                tenant_id: "t1".into(),
            },
            s.clone(),
        );
        let TenantLoginOutcome::Authenticated(session) = auth
            .login_with_proof(
                login(),
                login_proof(&devices, TENANT_DEVICE_LOGIN_PURPOSE),
                &devices,
            )
            .unwrap()
        else {
            panic!()
        };
        let command = refresh_command(&devices, session.tokens.refresh_token.clone());
        let TenantRefreshOutcome::Rotated { tokens, .. } = auth
            .rotate_refresh_with_proof(command.clone(), &devices)
            .unwrap()
        else {
            panic!()
        };
        assert!(auth.rotate_refresh_with_proof(command, &devices).is_err());
        assert!(auth.authenticate(tokens.access_token.token.clone()).is_ok());
        let reuse = refresh_command(&devices, session.tokens.refresh_token);
        let initial = s.0.lock().unwrap().clone();
        let mut bad = reuse.clone();
        bad.proof.signature = Base64UrlUnpadded::encode_string(&[4; 64]);
        assert!(auth
            .rotate_refresh_with_proof(bad.clone(), &devices)
            .is_err());
        {
            let mut data = s.0.lock().unwrap();
            data.proof_devices[0].status = DeviceStatus::Disabled;
            data.proof_bindings[0].status = AccountDeviceBindingStatus::Suspended;
            data.proof_challenges.last_mut().unwrap().consumed_at = Some(C.now());
        }
        assert_eq!(
            auth.rotate_refresh_with_proof(bad, &devices),
            Err(TenantAuthError::DeviceProof(
                DeviceRequestVerificationError::InvalidProof
            ))
        );
        *s.0.lock().unwrap() = initial.clone();
        s.0.lock().unwrap().fail_insert = true;
        assert!(auth
            .rotate_refresh_with_proof(reuse.clone(), &devices)
            .is_err());
        {
            let mut data = s.0.lock().unwrap();
            assert!(data.refreshes == initial.refreshes);
            assert_eq!(data.sessions, initial.sessions);
            assert!(data.proof_challenges == initial.proof_challenges);
            data.fail_insert = false;
        }
        assert!(matches!(
            auth.rotate_refresh_with_proof(reuse, &devices),
            Ok(TenantRefreshOutcome::ReuseDetected { .. })
        ));
        assert!(auth.authenticate(tokens.access_token.token).is_err());
        assert!(s
            .0
            .lock()
            .unwrap()
            .refreshes
            .iter()
            .all(|r| r.revocation_reason == Some(RefreshTokenRevocationReason::ReuseDetected)));
    }
    #[test]
    fn refresh_rechecks_expiry_after_device_work_before_committing_nonce() {
        struct AfterDeviceClock(AtomicUsize);
        impl Clock for AfterDeviceClock {
            fn now(&self) -> SystemTime {
                if self.0.fetch_add(1, Ordering::SeqCst) == 0 {
                    C.now()
                } else {
                    C.now() + Duration::from_secs(600)
                }
            }
        }
        let (s, devices) = login_devices();
        let policy = LoginTenantPolicy::Fixed {
            tenant_id: "t1".into(),
        };
        let login_auth = svc_proof(policy.clone(), s.clone());
        let TenantLoginOutcome::Authenticated(session) = login_auth
            .login_with_proof(
                login(),
                login_proof(&devices, TENANT_DEVICE_LOGIN_PURPOSE),
                &devices,
            )
            .unwrap()
        else {
            panic!()
        };
        let command = refresh_command(&devices, session.tokens.refresh_token);
        let auth = CoreTenantAuthenticationService::new(
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
                policy,
                require_device_proof: true,
            },
            s.clone(),
            Tok,
            G,
            Dg,
            AfterDeviceClock(AtomicUsize::new(0)),
            I,
        )
        .unwrap();
        let initial = s.0.lock().unwrap().clone();
        assert_eq!(
            auth.rotate_refresh_with_proof(command, &devices),
            Err(TenantAuthError::InvalidRefresh)
        );
        let data = s.0.lock().unwrap();
        assert!(data.refreshes == initial.refreshes);
        assert_eq!(data.sessions, initial.sessions);
        assert!(data.proof_challenges == initial.proof_challenges);
    }
}

mod oidc;
