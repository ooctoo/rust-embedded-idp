use super::*;

fn identity(session: &TenantSession) -> BrowserSessionIdentity {
    BrowserSessionIdentity {
        tenant_id: session.tenant_id.clone(),
        account_id: session.account_id.clone(),
        session_id: session.id.clone(),
        client_id: session.client_id.clone(),
    }
}

#[test]
fn browser_identity_reads_the_current_business_session_without_mutating_state() {
    let s = seed();
    let auth = svc(
        LoginTenantPolicy::Fixed {
            tenant_id: "t1".into(),
        },
        s.clone(),
    );
    let TenantLoginOutcome::Authenticated(login) = auth.browser_login(login()).unwrap() else {
        panic!()
    };
    let before = s.0.lock().unwrap().clone();

    for _ in 0..2 {
        let current = auth
            .authenticate_browser(
                login.tokens.refresh_token.clone(),
                Some(identity(&login.session)),
            )
            .unwrap();
        assert_eq!(current.tenant_id(), "t1");
        assert_eq!(current.account_id(), "a");
        assert_eq!(current.session_id(), login.session.id);
        assert_eq!(current.client_id(), "web");
        assert_eq!(current.authenticated_at(), login.session.authenticated_at);
        assert_eq!(
            current.expires_at(),
            login
                .session
                .expires_at
                .min(login.tokens.refresh_expires_at)
        );
    }

    let after = s.0.lock().unwrap();
    assert_eq!(after.sessions, before.sessions);
    assert_eq!(after.refreshes.len(), before.refreshes.len());
    assert_eq!(
        after.refreshes[0].token_digest,
        before.refreshes[0].token_digest
    );
    assert_eq!(
        after.refreshes[0].token_version,
        before.refreshes[0].token_version
    );
    assert_eq!(
        after.refreshes[0].revoked_at,
        before.refreshes[0].revoked_at
    );
}

#[test]
fn browser_identity_rejects_stale_expected_identity_without_mutating_state() {
    let s = seed();
    let auth = svc(
        LoginTenantPolicy::Fixed {
            tenant_id: "t1".into(),
        },
        s.clone(),
    );
    let TenantLoginOutcome::Authenticated(login) = auth.browser_login(login()).unwrap() else {
        panic!()
    };
    let mut expected = identity(&login.session);
    expected.account_id = "other".into();

    assert_eq!(
        auth.authenticate_browser(login.tokens.refresh_token, Some(expected)),
        Err(TenantAuthError::Access(AccessError::InvalidInput(
            "browser_session_changed"
        )))
    );
    let state = s.0.lock().unwrap();
    assert_eq!(state.sessions[0].refresh_token_version, 1);
    assert!(state.refreshes[0].revoked_at.is_none());
}

#[test]
fn browser_identity_rejects_rotated_refresh_without_reuse_revocation() {
    let s = seed();
    let auth = svc(
        LoginTenantPolicy::Fixed {
            tenant_id: "t1".into(),
        },
        s.clone(),
    );
    let TenantLoginOutcome::Authenticated(login) = auth.browser_login(login()).unwrap() else {
        panic!()
    };
    let TenantRefreshOutcome::Rotated { session, .. } = auth
        .browser_refresh(
            login.tokens.refresh_token.clone(),
            Some(identity(&login.session)),
        )
        .unwrap()
    else {
        panic!()
    };

    assert_eq!(
        auth.authenticate_browser(login.tokens.refresh_token, Some(identity(&session))),
        Err(TenantAuthError::InvalidRefresh)
    );
    let state = s.0.lock().unwrap();
    assert_eq!(state.sessions[0].status, SessionStatus::Active);
    assert_eq!(state.sessions[0].refresh_token_version, 2);
    assert_eq!(state.refreshes.len(), 2);
    assert!(state.refreshes[1].revoked_at.is_none());
}

#[test]
fn browser_identity_rejects_logout_and_invalid_current_identity_state() {
    for state in [
        "logout",
        "pending",
        "management",
        "device",
        "account",
        "tenant",
        "membership",
    ] {
        let s = seed();
        let auth = svc(
            LoginTenantPolicy::Fixed {
                tenant_id: "t1".into(),
            },
            s.clone(),
        );
        let TenantLoginOutcome::Authenticated(login) = auth.browser_login(login()).unwrap() else {
            panic!()
        };
        match state {
            "logout" => auth
                .browser_logout(
                    login.tokens.refresh_token.clone(),
                    Some(identity(&login.session)),
                )
                .unwrap(),
            "pending" => s.0.lock().unwrap().sessions[0].status = SessionStatus::Pending,
            "management" => {
                s.0.lock().unwrap().sessions[0].purpose = AccessTokenPurpose::Management
            }
            "device" => s.0.lock().unwrap().sessions[0].device_id = Some("d1".into()),
            "account" => s.0.lock().unwrap().accounts.get_mut("a").unwrap().active = false,
            "tenant" => {
                s.0.lock().unwrap().tenants.get_mut("t1").unwrap().status = TenantStatus::Suspended
            }
            "membership" => {
                s.0.lock()
                    .unwrap()
                    .members
                    .iter_mut()
                    .find(|member| member.tenant_id == "t1" && member.subject_id == "a")
                    .unwrap()
                    .status = MembershipStatus::Suspended;
            }
            _ => unreachable!(),
        }
        assert!(
            auth.authenticate_browser(login.tokens.refresh_token, Some(identity(&login.session)))
                .is_err(),
            "case {state}"
        );
    }
}

#[test]
fn browser_identity_rejects_invalid_credential_times_and_client_without_mutation() {
    for case in [
        "refresh_expired",
        "refresh_issued_future",
        "refresh_version",
        "session_expired",
        "session_client",
        "unknown",
    ] {
        let s = seed();
        let auth = svc(
            LoginTenantPolicy::Fixed {
                tenant_id: "t1".into(),
            },
            s.clone(),
        );
        let TenantLoginOutcome::Authenticated(login) = auth.browser_login(login()).unwrap() else {
            panic!()
        };
        let before_version = s.0.lock().unwrap().sessions[0].refresh_token_version;
        match case {
            "refresh_expired" => s.0.lock().unwrap().refreshes[0].expires_at = C.now(),
            "refresh_issued_future" => {
                s.0.lock().unwrap().refreshes[0].issued_at = C.now() + Duration::from_secs(1)
            }
            "refresh_version" => s.0.lock().unwrap().refreshes[0].token_version = 2,
            "session_expired" => s.0.lock().unwrap().sessions[0].expires_at = C.now(),
            "session_client" => s.0.lock().unwrap().sessions[0].client_id = "other".into(),
            "unknown" => {}
            _ => unreachable!(),
        }
        let cookie = if case == "unknown" {
            SecretString::new("unknown-refresh")
        } else {
            login.tokens.refresh_token
        };
        assert!(
            auth.authenticate_browser(cookie, Some(identity(&login.session)))
                .is_err(),
            "case {case}"
        );
        let after = s.0.lock().unwrap();
        assert_eq!(after.sessions[0].refresh_token_version, before_version);
        assert_eq!(after.refreshes.len(), 1);
        assert!(after.refreshes[0].revoked_at.is_none());
        assert!(after.refreshes[0].revocation_reason.is_none());
    }
}

#[derive(Clone, Copy)]
struct InvalidRefreshDigest;

impl RefreshTokenDigester for InvalidRefreshDigest {
    fn digest_refresh_token(&self, _: &str) -> Result<[u8; 32], TokenError> {
        Err(TokenError::InvalidRefreshTokenEncoding)
    }
}

#[test]
fn browser_identity_rejects_malformed_refresh_digest_without_mutation() {
    let s = seed();
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
            policy: LoginTenantPolicy::Fixed {
                tenant_id: "t1".into(),
            },
            require_device_proof: false,
        },
        s.clone(),
        Tok,
        G,
        InvalidRefreshDigest,
        C,
        I,
    )
    .unwrap();
    assert_eq!(
        auth.authenticate_browser(SecretString::new("malformed"), None),
        Err(TenantAuthError::InvalidRefresh)
    );
    let state = s.0.lock().unwrap();
    assert!(state.sessions.is_empty());
    assert!(state.refreshes.is_empty());
}

#[test]
fn browser_identity_rejects_proof_required_entry() {
    let auth = svc_proof(
        LoginTenantPolicy::Fixed {
            tenant_id: "t1".into(),
        },
        seed(),
    );
    assert!(auth
        .authenticate_browser(SecretString::new("any-refresh"), None)
        .is_err());
}

#[test]
fn browser_refresh_rotates_and_rejects_stale_identity_without_state_change() {
    let s = seed();
    let auth = svc(
        LoginTenantPolicy::Fixed {
            tenant_id: "t1".into(),
        },
        s.clone(),
    );
    let TenantLoginOutcome::Authenticated(login) = auth.browser_login(login()).unwrap() else {
        panic!()
    };
    let mut stale = identity(&login.session);
    stale.tenant_id = "t2".into();
    assert_eq!(
        auth.browser_refresh(login.tokens.refresh_token.clone(), Some(stale)),
        Err(TenantAuthError::Access(AccessError::InvalidInput(
            "browser_session_changed"
        )))
    );
    {
        let state = s.0.lock().unwrap();
        assert_eq!(state.sessions[0].refresh_token_version, 1);
        assert!(state.refreshes[0].revoked_at.is_none());
    }
    let TenantRefreshOutcome::Rotated { session, tokens } = auth
        .browser_refresh(login.tokens.refresh_token, Some(identity(&login.session)))
        .unwrap()
    else {
        panic!()
    };
    assert_eq!(session.refresh_token_version, 2);
    assert!(auth
        .browser_refresh(tokens.refresh_token, Some(identity(&session)))
        .is_ok());
}

#[test]
fn browser_refresh_rejects_expired_or_revoked_credentials() {
    let s = seed();
    let auth = svc(
        LoginTenantPolicy::Fixed {
            tenant_id: "t1".into(),
        },
        s.clone(),
    );
    let TenantLoginOutcome::Authenticated(login) = auth.browser_login(login()).unwrap() else {
        panic!()
    };
    s.0.lock().unwrap().refreshes[0].expires_at = C.now();
    assert!(auth
        .browser_refresh(
            login.tokens.refresh_token.clone(),
            Some(identity(&login.session))
        )
        .is_err());
    s.0.lock().unwrap().refreshes[0].expires_at = C.now() + Duration::from_secs(60);
    auth.browser_logout(
        login.tokens.refresh_token.clone(),
        Some(identity(&login.session)),
    )
    .unwrap();
    assert!(auth
        .browser_refresh(login.tokens.refresh_token, Some(identity(&login.session)))
        .is_err());
}

#[test]
fn browser_refresh_rechecks_current_tenant_membership_and_device_state() {
    for state in ["membership", "tenant", "device"] {
        let s = seed();
        let auth = svc(
            LoginTenantPolicy::Fixed {
                tenant_id: "t1".into(),
            },
            s.clone(),
        );
        let TenantLoginOutcome::Authenticated(login) = auth.browser_login(login()).unwrap() else {
            panic!()
        };
        match state {
            "membership" => {
                s.0.lock()
                    .unwrap()
                    .members
                    .iter_mut()
                    .find(|member| member.tenant_id == "t1" && member.subject_id == "a")
                    .unwrap()
                    .status = MembershipStatus::Removed;
            }
            "tenant" => {
                s.0.lock().unwrap().tenants.get_mut("t1").unwrap().status = TenantStatus::Suspended;
            }
            "device" => {
                s.0.lock().unwrap().sessions[0].device_id = Some("device-1".into());
            }
            _ => unreachable!(),
        }
        assert!(auth
            .browser_refresh(login.tokens.refresh_token, Some(identity(&login.session)))
            .is_err());
        let state = s.0.lock().unwrap();
        assert_eq!(state.sessions[0].refresh_token_version, 1);
        assert!(state.refreshes[0].revoked_at.is_none());
    }
}

#[test]
fn browser_logout_uses_refresh_credential_and_is_idempotent() {
    let s = seed();
    let auth = svc(
        LoginTenantPolicy::Fixed {
            tenant_id: "t1".into(),
        },
        s.clone(),
    );
    let TenantLoginOutcome::Authenticated(login) = auth.browser_login(login()).unwrap() else {
        panic!()
    };
    auth.browser_logout(
        login.tokens.refresh_token.clone(),
        Some(identity(&login.session)),
    )
    .unwrap();
    assert_eq!(
        s.0.lock().unwrap().sessions[0].status,
        SessionStatus::Revoked
    );
    auth.browser_logout(
        login.tokens.refresh_token.clone(),
        Some(identity(&login.session)),
    )
    .unwrap();
    assert!(auth
        .browser_refresh(login.tokens.refresh_token, Some(identity(&login.session)))
        .is_err());
}

#[test]
fn browser_logout_rejects_stale_identity_and_old_rotated_tokens_without_revoking_current_session() {
    let s = seed();
    let auth = svc(
        LoginTenantPolicy::Fixed {
            tenant_id: "t1".into(),
        },
        s.clone(),
    );
    let TenantLoginOutcome::Authenticated(login) = auth.browser_login(login()).unwrap() else {
        panic!()
    };
    let mut stale = identity(&login.session);
    stale.account_id = "other".into();
    assert_eq!(
        auth.browser_logout(login.tokens.refresh_token.clone(), Some(stale)),
        Err(TenantAuthError::Access(AccessError::InvalidInput(
            "browser_session_changed"
        )))
    );
    assert_eq!(
        s.0.lock().unwrap().sessions[0].status,
        SessionStatus::Active
    );
    let TenantRefreshOutcome::Rotated {
        session,
        tokens: current,
    } = auth
        .browser_refresh(
            login.tokens.refresh_token.clone(),
            Some(identity(&login.session)),
        )
        .unwrap()
    else {
        panic!()
    };
    auth.browser_logout(login.tokens.refresh_token, None)
        .unwrap();
    assert!(auth
        .browser_refresh(current.refresh_token, Some(identity(&session)))
        .is_ok());
}

#[test]
fn browser_logout_propagates_store_failures_without_claiming_success() {
    let s = seed();
    let auth = svc(
        LoginTenantPolicy::Fixed {
            tenant_id: "t1".into(),
        },
        s.clone(),
    );
    let TenantLoginOutcome::Authenticated(login) = auth.browser_login(login()).unwrap() else {
        panic!()
    };
    s.0.lock().unwrap().fail_insert = true;
    assert!(matches!(
        auth.browser_logout(
            login.tokens.refresh_token.clone(),
            Some(identity(&login.session))
        ),
        Err(TenantAuthError::Store(StoreError::Backend(_)))
    ));
    s.0.lock().unwrap().fail_insert = false;
    assert!(auth
        .browser_refresh(login.tokens.refresh_token, Some(identity(&login.session)))
        .is_ok());
}

#[test]
fn browser_sessions_keep_management_and_business_purposes_separate() {
    let s = seed();
    s.0.lock().unwrap().members.push(m("0", "a"));
    let business = svc_mode(
        TenancyMode::Disabled,
        LoginTenantPolicy::Fixed {
            tenant_id: "0".into(),
        },
        s.clone(),
    );
    let management = management::management(
        TenancyMode::Disabled,
        LoginTenantPolicy::Fixed {
            tenant_id: "0".into(),
        },
        s,
    );
    let TenantLoginOutcome::Authenticated(business_login) =
        business.browser_login(login()).unwrap()
    else {
        panic!()
    };
    let TenantLoginOutcome::Authenticated(management_login) =
        management.browser_login(login()).unwrap()
    else {
        panic!()
    };
    assert_eq!(business.browser_purpose(), AccessTokenPurpose::Business);
    assert_eq!(management.browser_purpose(), AccessTokenPurpose::Management);
    assert!(management
        .browser_refresh(
            business_login.tokens.refresh_token,
            Some(identity(&business_login.session))
        )
        .is_err());
    assert!(business
        .browser_refresh(
            management_login.tokens.refresh_token,
            Some(identity(&management_login.session))
        )
        .is_err());
}

#[test]
fn browser_sessions_reject_device_proof_entries() {
    let auth = svc_proof(
        LoginTenantPolicy::Fixed {
            tenant_id: "t1".into(),
        },
        seed(),
    );
    assert_eq!(
        auth.browser_login(login()),
        Err(TenantAuthError::DeviceProofRequired)
    );
}

fn long_browser_service(
    store: S,
    policy: LoginTenantPolicy,
) -> CoreTenantAuthenticationService<S, Tok, G, Dg, C, I> {
    CoreTenantAuthenticationService::new(
        TenancyMode::Enabled,
        AuthConfig {
            allow_local_registration: true,
            access_token_ttl_secs: 60,
            refresh_token_ttl_secs: 86400,
            session_ttl_secs: 86400,
            verification_code_ttl_secs: 60,
            password_min_length: 8,
            password_max_length: 128,
        },
        TenantLoginEntry {
            client_id: "web".into(),
            login_entry: "login".into(),
            policy,
            require_device_proof: false,
        },
        store,
        Tok,
        G,
        Dg,
        C,
        I,
    )
    .unwrap()
}

#[test]
fn restricted_browser_issuance_is_persisted_bounded_and_cannot_refresh() {
    let store = seed();
    let policy = LoginTenantPolicy::Fixed {
        tenant_id: "t1".into(),
    };
    let auth = long_browser_service(store.clone(), policy.clone())
        .into_restricted_browser(120)
        .unwrap();
    assert_eq!(
        BrowserSessionService::browser_session_lifetime_secs(&auth),
        Some(120)
    );
    assert_eq!(
        BrowserSessionIdentityService::browser_session_lifetime_secs(&auth),
        Some(120)
    );
    let TenantLoginOutcome::Authenticated(session) = auth.browser_login(login()).unwrap() else {
        panic!()
    };
    assert_eq!(
        session.session.expires_at,
        C.now() + Duration::from_secs(120)
    );
    assert_eq!(
        store.0.lock().unwrap().sessions[0].expires_at,
        session.session.expires_at
    );
    assert_eq!(
        store.0.lock().unwrap().refreshes[0].expires_at,
        session.tokens.refresh_expires_at
    );
    assert_eq!(
        auth.browser_refresh(
            session.tokens.refresh_token.clone(),
            Some(identity(&session.session))
        ),
        Err(AccessError::InvalidInput("browser_refresh_disabled").into())
    );
    assert_eq!(
        auth.browser_logout(session.tokens.refresh_token.clone(), None),
        Err(AccessError::InvalidInput("browser_expected_session_required").into())
    );
    assert_eq!(
        auth.authenticate_browser(session.tokens.refresh_token.clone(), None),
        Err(AccessError::InvalidInput("browser_expected_session_required").into())
    );
    let mut wrong = identity(&session.session);
    wrong.account_id = "other".into();
    assert_eq!(
        auth.authenticate_browser(session.tokens.refresh_token.clone(), Some(wrong.clone())),
        Err(AccessError::InvalidInput("browser_session_changed").into())
    );
    assert_eq!(
        auth.browser_logout(session.tokens.refresh_token.clone(), Some(wrong)),
        Err(AccessError::InvalidInput("browser_session_changed").into())
    );
    assert!(store.0.lock().unwrap().refreshes[0].revoked_at.is_none());
    assert!(auth
        .authenticate_browser(
            session.tokens.refresh_token.clone(),
            Some(identity(&session.session))
        )
        .is_ok());
    auth.browser_logout(
        session.tokens.refresh_token,
        Some(identity(&session.session)),
    )
    .unwrap();
    assert!(store.0.lock().unwrap().refreshes[0].revoked_at.is_some());

    // A separately composed ordinary service retains its configured duration.
    let ordinary = long_browser_service(store.clone(), policy);
    let TenantLoginOutcome::Authenticated(session) = ordinary.browser_login(login()).unwrap()
    else {
        panic!()
    };
    assert_eq!(
        session.session.expires_at,
        C.now() + Duration::from_secs(86400)
    );
    assert_eq!(
        BrowserSessionService::browser_session_lifetime_secs(&ordinary),
        None
    );
}

#[test]
fn restricted_browser_rejects_overlong_issuer_atomically_including_selection() {
    for selection in [false, true] {
        let store = seed();
        let policy = if selection {
            LoginTenantPolicy::ChooseAfterAuthentication
        } else {
            LoginTenantPolicy::Fixed {
                tenant_id: "t1".into(),
            }
        };
        let auth = long_browser_service(store.clone(), policy)
            .into_restricted_browser(60)
            .unwrap();
        let result = if selection {
            let TenantLoginOutcome::SelectionRequired(ticket) =
                auth.browser_login(login()).unwrap()
            else {
                panic!()
            };
            auth.browser_select(ticket.ticket, "t1".into())
                .map(TenantLoginOutcome::Authenticated)
        } else {
            auth.browser_login(login())
        };
        assert!(matches!(result, Err(TenantAuthError::Token(_))));
        let state = store.0.lock().unwrap();
        assert!(state.sessions.is_empty());
        assert!(state.refreshes.is_empty());
        assert!(state
            .selections
            .iter()
            .all(|ticket| ticket.consumed_at.is_none()));
    }
    for seconds in [0, 59, 3601, u64::MAX] {
        assert!(long_browser_service(
            seed(),
            LoginTenantPolicy::Fixed {
                tenant_id: "t1".into()
            }
        )
        .into_restricted_browser(seconds)
        .is_err());
    }
}

#[test]
fn restricted_browser_rejects_existing_long_lived_cookie_for_scan_identity() {
    let store = seed();
    let policy = LoginTenantPolicy::Fixed {
        tenant_id: "t1".into(),
    };
    let ordinary = long_browser_service(store.clone(), policy.clone());
    let TenantLoginOutcome::Authenticated(session) = ordinary.browser_login(login()).unwrap()
    else {
        panic!()
    };
    let restricted = long_browser_service(store.clone(), policy)
        .into_restricted_browser(120)
        .unwrap();
    assert_eq!(
        restricted.authenticate_browser(
            session.tokens.refresh_token.clone(),
            Some(identity(&session.session))
        ),
        Err(TenantAuthError::InvalidSession)
    );
    assert!(ordinary
        .authenticate_browser(
            session.tokens.refresh_token,
            Some(identity(&session.session))
        )
        .is_ok());
    assert_eq!(
        store.0.lock().unwrap().sessions[0].status,
        SessionStatus::Active
    );
}

#[test]
fn restricted_browser_selection_and_management_remain_purpose_bound() {
    let store = seed();
    let restricted =
        long_browser_service(store.clone(), LoginTenantPolicy::ChooseAfterAuthentication)
            .into_restricted_browser(120)
            .unwrap();
    let TenantLoginOutcome::SelectionRequired(ticket) = restricted.browser_login(login()).unwrap()
    else {
        panic!()
    };
    let selected = restricted
        .browser_select(ticket.ticket, "t1".into())
        .unwrap();
    assert_eq!(
        selected.session.expires_at,
        C.now() + Duration::from_secs(120)
    );
    store.0.lock().unwrap().members.push(m("0", "a"));
    let admin = management::management(
        TenancyMode::Enabled,
        LoginTenantPolicy::Fixed {
            tenant_id: "0".into(),
        },
        store.clone(),
    )
    .into_restricted_browser(120)
    .unwrap();
    let TenantLoginOutcome::Authenticated(session) = admin.browser_login(login()).unwrap() else {
        panic!()
    };
    assert_eq!(admin.browser_purpose(), AccessTokenPurpose::Management);
    assert_eq!(session.session.purpose, AccessTokenPurpose::Management);
    assert_eq!(
        admin.authenticate_browser(
            session.tokens.refresh_token.clone(),
            Some(identity(&session.session))
        ),
        Err(TenantAuthError::InvalidSession)
    );
    assert_eq!(
        admin.browser_refresh(
            session.tokens.refresh_token.clone(),
            Some(identity(&session.session))
        ),
        Err(AccessError::InvalidInput("browser_refresh_disabled").into())
    );
    admin
        .browser_logout(
            session.tokens.refresh_token,
            Some(identity(&session.session)),
        )
        .unwrap();
}

#[test]
fn restricted_browser_rejects_overlong_signed_claim_even_with_short_bundle_metadata() {
    struct LongClaims;
    impl TokenIssuer for LongClaims {
        fn issue_session_tokens(
            &self,
            t: &str,
            s: &str,
            a: &str,
            c: &str,
            v: u64,
            n: SystemTime,
        ) -> Result<IssuedTokenBundle, TokenError> {
            Tok.issue_session_tokens(t, s, a, c, v, n)
        }
    }
    impl AccessTokenIssuer for LongClaims {
        fn issue_access_token(
            &self,
            t: &str,
            s: &str,
            a: &str,
            c: &str,
            n: SystemTime,
        ) -> Result<IssuedAccessToken, TokenError> {
            Tok.issue_access_token(t, s, a, c, n)
        }
    }
    impl ScopedAccessTokenIssuer for LongClaims {
        fn issue_scoped_access_token(
            &self,
            t: &str,
            s: &str,
            a: &str,
            c: &str,
            n: SystemTime,
            scope: &str,
        ) -> Result<IssuedAccessToken, TokenError> {
            Tok.issue_scoped_access_token(t, s, a, c, n, scope)
        }
    }
    impl AccessTokenValidator for LongClaims {
        fn validate_access_token(
            &self,
            raw: &str,
            now: SystemTime,
        ) -> Result<Option<ValidatedAccessToken>, TokenError> {
            Ok(Tok.validate_access_token(raw, now)?.map(|mut claims| {
                claims.expires_at = now + Duration::from_secs(3600);
                claims
            }))
        }
    }
    let store = seed();
    let restricted = CoreTenantAuthenticationService::new(
        TenancyMode::Enabled,
        AuthConfig {
            allow_local_registration: true,
            access_token_ttl_secs: 60,
            refresh_token_ttl_secs: 86400,
            session_ttl_secs: 86400,
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
            require_device_proof: false,
        },
        store.clone(),
        LongClaims,
        G,
        Dg,
        C,
        I,
    )
    .unwrap()
    .into_restricted_browser(120)
    .unwrap();
    assert_eq!(
        restricted.browser_login(login()),
        Err(TenantAuthError::InvalidSession)
    );
    let state = store.0.lock().unwrap();
    assert!(state.sessions.is_empty());
    assert!(state.refreshes.is_empty());
}
