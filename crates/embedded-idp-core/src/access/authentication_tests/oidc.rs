use super::*;
impl IdTokenIssuer for Tok {
    fn issue_id_token(&self, claims: &IdTokenClaims) -> Result<SecretString, TokenError> {
        Ok(SecretString::new(format!(
            "id/{}/{}",
            claims.tenant_id, claims.subject_account_id
        )))
    }
}
impl TenantOidcTransaction for T<'_> {
    fn oidc_client(&mut self, client: &str) -> Result<Option<OidcClient>, StoreError> {
        Ok(self
            .d
            .clients
            .iter()
            .any(|c| c == client)
            .then(|| OidcClient {
                client_id: client.into(),
                client_name: "test".into(),
                redirect_uris: vec![if self.d.confidential_client {
                    "https://client.test/callback".into()
                } else {
                    "testapp://callback".into()
                }],
                client_type: if self.d.confidential_client {
                    OidcClientType::ConfidentialWeb
                } else {
                    OidcClientType::PublicDesktop
                },
                pkce_required: true,
                client_secret_hash: self.d.confidential_client.then(|| "synthetic-hash".into()),
            }))
    }
    fn insert_authorization(&mut self, code: &TenantAuthorizationCode) -> Result<(), StoreError> {
        self.d.authorizations.push(code.clone());
        Ok(())
    }
    fn find_authorization(
        &mut self,
        digest: &[u8; 32],
    ) -> Result<Option<TenantAuthorizationCode>, StoreError> {
        Ok(self
            .d
            .authorizations
            .iter()
            .find(|c| &c.code_digest == digest)
            .cloned())
    }
    fn lock_authorization(
        &mut self,
        tenant: &str,
        digest: &[u8; 32],
    ) -> Result<Option<TenantAuthorizationCode>, StoreError> {
        Ok(self
            .find_authorization(digest)?
            .filter(|c| c.tenant_id == tenant))
    }
    fn consume_authorization(
        &mut self,
        tenant: &str,
        digest: &[u8; 32],
        now: SystemTime,
    ) -> Result<(), StoreError> {
        let code = self
            .d
            .authorizations
            .iter_mut()
            .find(|c| {
                c.tenant_id == tenant
                    && &c.code_digest == digest
                    && c.consumed_at.is_none()
                    && c.expires_at > now
            })
            .ok_or(StoreError::Conflict("code"))?;
        code.consumed_at = Some(now);
        Ok(())
    }
}
struct Secrets;
impl ClientSecretVerifier for Secrets {
    fn verify_client_secret(&self, raw: &str, stored: &str) -> Result<bool, ClientSecretError> {
        Ok(raw == "synthetic-secret" && stored == "synthetic-hash")
    }
}
#[test]
fn tenant_code_keeps_scope_and_source_and_rolls_back_failed_issuance() {
    let s = seed();
    let auth = svc(LoginTenantPolicy::ChooseAfterAuthentication, s.clone());
    let TenantLoginOutcome::SelectionRequired(ticket) = auth.login(login()).unwrap() else {
        panic!()
    };
    let initial = auth.select_tenant(ticket.ticket, "t1".into()).unwrap();
    let actor = AccessActor {
        tenant_id: "t1".into(),
        subject_id: "a".into(),
        session_id: initial.session.id.clone(),
    };
    let oidc = CoreTenantOidcService::new(
        svc(LoginTenantPolicy::ChooseAfterAuthentication, s.clone()),
        "https://idp.example.test".into(),
        OidcConfig {
            authorization_code_ttl_secs: 60,
            require_pkce_for_public_clients: true,
        },
        "openid profile".into(),
        Secrets,
    )
    .unwrap();
    let request = TenantAuthorizationRequest {
        response_type: "code".into(),
        client_id: "web".into(),
        redirect_uri: "testapp://callback".into(),
        scope: "openid".into(),
        state: None,
        nonce: Some("nonce".into()),
        code_challenge: Some("a".repeat(43)),
        code_challenge_method: Some(PkceChallengeMethod::Plain),
    };
    let grant = oidc.authorize(actor, request.clone()).unwrap();
    let cmd = TenantCodeExchange {
        grant_type: "authorization_code".into(),
        client_id: "web".into(),
        code: grant.code,
        redirect_uri: request.redirect_uri.clone(),
        client_secret: None,
        code_verifier: Some(SecretString::new("a".repeat(43))),
    };
    let mut bad = cmd.clone();
    bad.code_verifier = Some(SecretString::new(" a".repeat(43)));
    assert!(oidc.exchange(bad).is_err());
    s.0.lock().unwrap().fail_insert = true;
    assert!(oidc.exchange(cmd.clone()).is_err());
    {
        let d = s.0.lock().unwrap();
        assert_eq!(d.sessions.len(), 1);
        assert!(d.authorizations[0].consumed_at.is_none());
    }
    s.0.lock().unwrap().fail_insert = false;
    let exchanged = oidc.exchange(cmd.clone()).unwrap();
    assert!(exchanged.id_token.is_some());
    assert!(oidc.exchange(cmd).is_err());
    let actor = auth
        .authenticate(exchanged.login.tokens.access_token)
        .unwrap();
    assert!(oidc
        .authorize(
            actor,
            TenantAuthorizationRequest {
                scope: "profile".into(),
                ..request
            }
        )
        .is_err());
    let TenantRefreshOutcome::Rotated { session, tokens } = auth
        .rotate_refresh(exchanged.login.tokens.refresh_token)
        .unwrap()
    else {
        panic!()
    };
    assert_eq!(session.scope.as_deref(), Some("openid"));
    assert!(auth.authenticate(tokens.access_token.token.clone()).is_ok());
    let ticket = auth.begin_switch(tokens.access_token.token).unwrap();
    let selected = auth.select_tenant(ticket.ticket, "t2".into()).unwrap();
    assert_eq!(selected.session.scope.as_deref(), Some("openid"));
    assert!(auth.authenticate(selected.tokens.access_token).is_ok());
}

#[test]
fn confidential_code_exchange_budget_rejection_preserves_code_and_session_state() {
    use crate::{BudgetedClientSecretCodec, PasswordWorkBudget};

    let s = seed();
    s.0.lock().unwrap().confidential_client = true;
    let policy = LoginTenantPolicy::Fixed {
        tenant_id: "t1".into(),
    };
    let auth = svc(policy.clone(), s.clone());
    let TenantLoginOutcome::Authenticated(initial) = auth.login(login()).unwrap() else {
        panic!()
    };
    let budget = PasswordWorkBudget::default();
    let oidc = CoreTenantOidcService::new(
        svc(policy, s.clone()),
        "https://idp.example.test".into(),
        OidcConfig {
            authorization_code_ttl_secs: 60,
            require_pkce_for_public_clients: true,
        },
        "openid profile".into(),
        BudgetedClientSecretCodec::new(Secrets, budget.clone()),
    )
    .unwrap();
    let actor = AccessActor {
        tenant_id: "t1".into(),
        subject_id: "a".into(),
        session_id: initial.session.id,
    };
    let request = TenantAuthorizationRequest {
        response_type: "code".into(),
        client_id: "web".into(),
        redirect_uri: "https://client.test/callback".into(),
        scope: "openid".into(),
        state: None,
        nonce: None,
        code_challenge: Some("a".repeat(43)),
        code_challenge_method: Some(PkceChallengeMethod::Plain),
    };
    let grant = oidc.authorize(actor, request.clone()).unwrap();
    let command = TenantCodeExchange {
        grant_type: "authorization_code".into(),
        client_id: "web".into(),
        code: grant.code.clone(),
        redirect_uri: request.redirect_uri,
        client_secret: Some(SecretString::new("synthetic-secret")),
        code_verifier: Some(SecretString::new("a".repeat(43))),
    };
    let permits: Vec<_> = (0..4).map(|_| budget.try_login().unwrap()).collect();
    assert!(matches!(
        oidc.exchange(command.clone()),
        Err(TenantAuthError::Store(StoreError::Backend(message)))
            if message == "password.work_unavailable"
    ));
    {
        let data = s.0.lock().unwrap();
        assert_eq!(data.sessions.len(), 1);
        assert_eq!(data.authorizations.len(), 1);
        assert!(data.authorizations[0].consumed_at.is_none());
    }

    drop(permits);
    assert!(oidc.exchange(command).unwrap().id_token.is_some());
    let data = s.0.lock().unwrap();
    assert_eq!(data.sessions.len(), 2);
    assert!(data.authorizations[0].consumed_at.is_some());
}

impl TenantOidcResourceTransaction for T<'_> {
    fn user_profile(
        &mut self,
        _: &str,
        account: &str,
    ) -> Result<Option<TenantUserProfile>, StoreError> {
        if self.d.fail_insert {
            return Err(StoreError::Backend("profile unavailable".into()));
        }
        Ok(Some(TenantUserProfile {
            subject_account_id: account.into(),
            email: "a@example.com".into(),
            display_name: Some("Account A".into()),
        }))
    }
}
fn resource_request(token: SecretString) -> TenantTokenRequest {
    TenantTokenRequest {
        client_id: "web".into(),
        client_secret: Some(SecretString::new("synthetic-secret")),
        token,
        token_type_hint: None,
    }
}
#[test]
fn resource_introspection_authenticates_inactive_tokens_and_logout_is_scoped_atomic() {
    let s = seed();
    let auth = svc(
        LoginTenantPolicy::Fixed {
            tenant_id: "t1".into(),
        },
        s.clone(),
    );
    let TenantLoginOutcome::Authenticated(initial) = auth.login(login()).unwrap() else {
        panic!()
    };
    let oidc = CoreTenantOidcService::new(
        svc(
            LoginTenantPolicy::Fixed {
                tenant_id: "t1".into(),
            },
            s.clone(),
        ),
        "https://idp.example.test".into(),
        OidcConfig {
            authorization_code_ttl_secs: 60,
            require_pkce_for_public_clients: true,
        },
        "openid profile email".into(),
        Secrets,
    )
    .unwrap();
    assert_eq!(
        oidc.introspect_token(resource_request(SecretString::new("invalid"))),
        Err(TenantAuthError::InvalidClient)
    );
    s.0.lock().unwrap().confidential_client = true;
    let mut wrong = resource_request(SecretString::new("invalid"));
    wrong.client_secret = None;
    assert_eq!(
        oidc.introspect_token(wrong),
        Err(TenantAuthError::InvalidClient)
    );
    assert_eq!(
        oidc.introspect_token(resource_request(SecretString::new("invalid")))
            .unwrap(),
        None
    );
    let info = oidc
        .introspect_token(resource_request(initial.tokens.refresh_token.clone()))
        .unwrap()
        .unwrap();
    assert_eq!(info.tenant_id, "t1");
    assert_eq!(info.token_type, TenantTokenType::Refresh);
    let TenantRefreshOutcome::Rotated { tokens, .. } = auth
        .rotate_refresh(initial.tokens.refresh_token.clone())
        .unwrap()
    else {
        panic!()
    };
    for invalid_client in [true, false] {
        let mut request = resource_request(tokens.refresh_token.clone());
        if invalid_client {
            request.client_id = "other".into();
        } else {
            request.client_secret = None;
        }
        assert_eq!(
            oidc.logout_session(request),
            Err(TenantAuthError::InvalidClient)
        );
        assert!(auth.authenticate(tokens.access_token.token.clone()).is_ok());
    }
    // A retired token cannot be used to log out a live family without proof.
    oidc.logout_session(resource_request(initial.tokens.refresh_token))
        .unwrap();
    assert!(auth.authenticate(tokens.access_token.token.clone()).is_ok());
    s.0.lock().unwrap().fail_insert = true;
    assert!(oidc
        .revoke_token(resource_request(tokens.access_token.token.clone()))
        .is_err());
    assert!(auth.authenticate(tokens.access_token.token.clone()).is_ok());
    s.0.lock().unwrap().fail_insert = false;
    oidc.logout_session(resource_request(tokens.refresh_token.clone()))
        .unwrap();
    assert_eq!(
        oidc.introspect_token(resource_request(tokens.access_token.token))
            .unwrap(),
        None
    );
    oidc.logout_session(resource_request(tokens.refresh_token))
        .unwrap();
    assert!(s
        .0
        .lock()
        .unwrap()
        .refreshes
        .iter()
        .all(|r| r.revocation_reason == Some(RefreshTokenRevocationReason::Logout)));
}

#[test]
fn confidential_resource_budget_rejection_does_not_revoke_session_or_refresh_family() {
    use crate::{BudgetedClientSecretCodec, PasswordWorkBudget};

    let s = seed();
    s.0.lock().unwrap().confidential_client = true;
    let auth = svc(
        LoginTenantPolicy::Fixed {
            tenant_id: "t1".into(),
        },
        s.clone(),
    );
    let TenantLoginOutcome::Authenticated(initial) = auth.login(login()).unwrap() else {
        panic!()
    };
    let budget = PasswordWorkBudget::default();
    let oidc = CoreTenantOidcService::new(
        svc(
            LoginTenantPolicy::Fixed {
                tenant_id: "t1".into(),
            },
            s.clone(),
        ),
        "https://idp.example.test".into(),
        OidcConfig {
            authorization_code_ttl_secs: 60,
            require_pkce_for_public_clients: true,
        },
        "openid profile email".into(),
        BudgetedClientSecretCodec::new(Secrets, budget.clone()),
    )
    .unwrap();
    let command = resource_request(initial.tokens.access_token.clone());
    let permits: Vec<_> = (0..4).map(|_| budget.try_login().unwrap()).collect();
    assert!(matches!(
        oidc.revoke_token(command.clone()),
        Err(TenantAuthError::Store(StoreError::Backend(message)))
            if message == "password.work_unavailable"
    ));
    {
        let data = s.0.lock().unwrap();
        assert_eq!(data.sessions[0].status, SessionStatus::Active);
        assert!(data
            .refreshes
            .iter()
            .all(|record| record.revoked_at.is_none()));
    }

    drop(permits);
    oidc.revoke_token(command).unwrap();
    let data = s.0.lock().unwrap();
    assert_eq!(data.sessions[0].status, SessionStatus::Revoked);
    assert!(data
        .refreshes
        .iter()
        .all(|record| record.revoked_at.is_some()));
}
#[test]
fn userinfo_rechecks_identity_and_releases_only_scope_authorized_claims() {
    let s = seed();
    let auth = svc(
        LoginTenantPolicy::Fixed {
            tenant_id: "t1".into(),
        },
        s.clone(),
    );
    let TenantLoginOutcome::Authenticated(initial) = auth.login(login()).unwrap() else {
        panic!()
    };
    let oidc = CoreTenantOidcService::new(
        svc(
            LoginTenantPolicy::Fixed {
                tenant_id: "t1".into(),
            },
            s.clone(),
        ),
        "https://idp.example.test".into(),
        OidcConfig {
            authorization_code_ttl_secs: 60,
            require_pkce_for_public_clients: true,
        },
        "openid profile email".into(),
        Secrets,
    )
    .unwrap();
    for (scope, email, name) in [
        ("openid", false, false),
        ("openid email", true, false),
        ("openid profile", false, true),
    ] {
        let raw = Tok
            .issue_scoped_access_token("t1", &initial.session.id, "a", "web", C.now(), scope)
            .unwrap()
            .token;
        let info = oidc.user_info(raw).unwrap();
        assert_eq!(info.email.is_some(), email);
        assert_eq!(info.display_name.is_some(), name);
        assert_eq!(info.tenant_id, "t1");
    }
    assert!(matches!(
        oidc.user_info(initial.tokens.access_token),
        Err(TenantAuthError::Access(AccessError::Forbidden))
    ));
    let raw = Tok
        .issue_scoped_access_token("t1", &initial.session.id, "a", "web", C.now(), "openid")
        .unwrap()
        .token;
    s.0.lock().unwrap().fail_insert = true;
    assert!(matches!(
        oidc.user_info(raw.clone()),
        Err(TenantAuthError::Store(_))
    ));
    s.0.lock().unwrap().fail_insert = false;
    s.0.lock().unwrap().members[0].status = MembershipStatus::Suspended;
    assert!(oidc.user_info(raw).is_err());
}

#[test]
fn ordinary_oidc_enforces_s256_and_rechecks_short_source_before_consuming_code() {
    use base64ct::{Base64UrlUnpadded, Encoding};
    use sha2::{Digest, Sha256};
    let s = seed();
    let policy = LoginTenantPolicy::ChooseAfterAuthentication;
    let auth = svc(policy.clone(), s.clone());
    let TenantLoginOutcome::SelectionRequired(ticket) = auth.login(login()).unwrap() else {
        panic!()
    };
    let initial = auth.select_tenant(ticket.ticket, "t1".into()).unwrap();
    let actor = auth
        .authenticate(initial.tokens.access_token.clone())
        .unwrap();
    let make = || {
        CoreTenantOidcService::new(
            svc(policy.clone(), s.clone())
                .with_restricted_browser_isolation(120)
                .unwrap(),
            "https://idp.example.test".into(),
            OidcConfig {
                authorization_code_ttl_secs: 60,
                require_pkce_for_public_clients: true,
            },
            "openid profile".into(),
            Secrets,
        )
        .unwrap()
    };
    let verifier = "a".repeat(43);
    let request = TenantAuthorizationRequest {
        response_type: "code".into(),
        client_id: "web".into(),
        redirect_uri: "testapp://callback".into(),
        scope: "openid".into(),
        state: None,
        nonce: None,
        code_challenge: Some(verifier.clone()),
        code_challenge_method: Some(PkceChallengeMethod::Plain),
    };
    let old_code = make().authorize(actor.clone(), request.clone()).unwrap();
    let strict = make().with_required_s256_pkce();
    assert!(strict.authorize(actor.clone(), request.clone()).is_err());
    let command = |code| TenantCodeExchange {
        grant_type: "authorization_code".into(),
        client_id: "web".into(),
        code,
        redirect_uri: "testapp://callback".into(),
        client_secret: None,
        code_verifier: Some(SecretString::new(verifier.clone())),
    };
    assert!(strict.exchange(command(old_code.code)).is_err());
    assert!(s.0.lock().unwrap().authorizations[0].consumed_at.is_none());
    let request = TenantAuthorizationRequest {
        code_challenge: Some(Base64UrlUnpadded::encode_string(&Sha256::digest(
            verifier.as_bytes(),
        ))),
        code_challenge_method: Some(PkceChallengeMethod::S256),
        ..request
    };
    let code = strict.authorize(actor.clone(), request.clone()).unwrap();
    let proof = TenantAuthenticationProof {
        proof: DeviceProofPresentation {
            device_id: "d1".into(),
            key_id: Base64UrlUnpadded::encode_string(&[1; 32]),
            challenge: Base64UrlUnpadded::encode_string(&[2; 32]),
            signature: Base64UrlUnpadded::encode_string(&[3; 64]),
            signed_at: C.now(),
        },
        binding: DeviceRequestBinding::new(
            "t1",
            DeviceProofProfile::new(TENANT_DEVICE_AUTH_PROFILE).unwrap(),
            "api",
            CanonicalHttpMethod::Post,
            "/oidc/token",
            [0; 32],
        )
        .unwrap(),
    };
    assert!(matches!(
        TenantOidcAuthorizationService::exchange(&strict, command(code.code.clone()), Some(proof)),
        Err(TenantAuthError::DeviceProofRequired)
    ));
    assert!(s
        .0
        .lock()
        .unwrap()
        .authorizations
        .iter()
        .all(|c| c.consumed_at.is_none()));
    // Simulate a pre-existing short session when the ordinary lifetime is raised.
    {
        let mut d = s.0.lock().unwrap();
        let source = d
            .sessions
            .iter_mut()
            .find(|s| s.id == actor.session_id)
            .unwrap();
        source.expires_at = source.created_at + Duration::from_secs(60);
    }
    assert!(strict.authorize(actor, request).is_err());
    assert!(strict.exchange(command(code.code)).is_err());
    assert!(s
        .0
        .lock()
        .unwrap()
        .authorizations
        .iter()
        .all(|c| c.consumed_at.is_none()));
}
