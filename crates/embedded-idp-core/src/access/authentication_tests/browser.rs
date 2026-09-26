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
