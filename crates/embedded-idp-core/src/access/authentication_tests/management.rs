use super::*;

struct ManagementTokens;
impl AccessTokenIssuer for ManagementTokens {
    fn issue_access_token(
        &self,
        t: &str,
        s: &str,
        a: &str,
        c: &str,
        n: SystemTime,
    ) -> Result<IssuedAccessToken, TokenError> {
        let mut token = Tok.issue_access_token(t, s, a, c, n)?;
        token.token = SecretString::new(format!("management:{}", token.token.expose_secret()));
        Ok(token)
    }
}
impl ScopedAccessTokenIssuer for ManagementTokens {
    fn issue_scoped_access_token(
        &self,
        t: &str,
        s: &str,
        a: &str,
        c: &str,
        n: SystemTime,
        _: &str,
    ) -> Result<IssuedAccessToken, TokenError> {
        self.issue_access_token(t, s, a, c, n)
    }
}
impl TokenIssuer for ManagementTokens {
    fn issue_session_tokens(
        &self,
        t: &str,
        s: &str,
        a: &str,
        c: &str,
        v: u64,
        n: SystemTime,
    ) -> Result<IssuedTokenBundle, TokenError> {
        let mut tokens = Tok.issue_session_tokens(t, s, a, c, v, n)?;
        tokens.access_token = self.issue_access_token(t, s, a, c, n)?.token;
        Ok(tokens)
    }
}
impl AccessTokenValidator for ManagementTokens {
    fn validate_access_token(
        &self,
        token: &str,
        n: SystemTime,
    ) -> Result<Option<ValidatedAccessToken>, TokenError> {
        let Some(raw) = token.strip_prefix("management:") else {
            return Ok(None);
        };
        Ok(Tok.validate_access_token(raw, n)?.map(|mut t| {
            t.purpose = AccessTokenPurpose::Management;
            t.token = SecretString::new(token);
            t
        }))
    }
}
fn management(
    mode: TenancyMode,
    policy: LoginTenantPolicy,
    s: S,
) -> CoreManagementAuthenticationService<S, ManagementTokens, G, Dg, C, I> {
    CoreManagementAuthenticationService::new(
        mode,
        AuthConfig {
            access_token_ttl_secs: 60,
            refresh_token_ttl_secs: 120,
            session_ttl_secs: 120,
            allow_local_registration: true,
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
        s,
        ManagementTokens,
        G,
        Dg,
        C,
        I,
    )
    .unwrap()
}

#[test]
fn management_sessions_refresh_and_logout_are_separate_from_business_in_both_modes() {
    for mode in [TenancyMode::Disabled, TenancyMode::Enabled] {
        let s = seed();
        s.0.lock().unwrap().members.push(m("0", "a"));
        let fixed = LoginTenantPolicy::Fixed {
            tenant_id: "0".into(),
        };
        let admin = management(mode, fixed.clone(), s.clone());
        let TenantLoginOutcome::Authenticated(session) = admin.login(login()).unwrap() else {
            panic!()
        };
        assert_eq!(session.session.purpose, AccessTokenPurpose::Management);
        let context = admin
            .authenticate(session.tokens.access_token.clone(), "request".into())
            .unwrap();
        assert_eq!(context.actor.tenant_id, "0");
        assert_eq!(context.authentication_source, "management_access");
        assert!(admin
            .authenticate(session.tokens.access_token.clone(), "".into())
            .is_err());
        if mode == TenancyMode::Disabled {
            let business = svc_mode(mode, fixed, s.clone());
            let TenantLoginOutcome::Authenticated(b) = business.login(login()).unwrap() else {
                panic!()
            };
            assert!(admin
                .authenticate(b.tokens.access_token, "request".into())
                .is_err());
            assert!(admin.rotate_refresh(b.tokens.refresh_token).is_err());
            assert!(business
                .authenticate(session.tokens.access_token.clone())
                .is_err());
            assert!(business
                .rotate_refresh(session.tokens.refresh_token.clone())
                .is_err());
            // Even a correctly signed management credential must refer to a management session.
            s.0.lock()
                .unwrap()
                .sessions
                .iter_mut()
                .find(|x| x.id == session.session.id)
                .unwrap()
                .purpose = AccessTokenPurpose::Business;
            assert!(admin
                .authenticate(session.tokens.access_token.clone(), "request".into())
                .is_err());
            assert!(admin
                .rotate_refresh(session.tokens.refresh_token.clone())
                .is_err());
            s.0.lock()
                .unwrap()
                .sessions
                .iter_mut()
                .find(|x| x.id == session.session.id)
                .unwrap()
                .purpose = AccessTokenPurpose::Management;
        }
        let TenantRefreshOutcome::Rotated { tokens, .. } =
            admin.rotate_refresh(session.tokens.refresh_token).unwrap()
        else {
            panic!()
        };
        admin.logout(tokens.access_token.token.clone()).unwrap();
        assert!(admin
            .authenticate(tokens.access_token.token, "request".into())
            .is_err());
        assert!(admin.rotate_refresh(tokens.refresh_token).is_err());
    }
}

#[test]
fn management_selection_cannot_exchange_business_tickets_or_enter_platform_domain() {
    let s = seed();
    let admin = management(
        TenancyMode::Enabled,
        LoginTenantPolicy::ChooseAfterAuthentication,
        s.clone(),
    );
    let business = svc(LoginTenantPolicy::ChooseAfterAuthentication, s.clone());
    let TenantLoginOutcome::SelectionRequired(a) = admin.login(login()).unwrap() else {
        panic!()
    };
    let TenantLoginOutcome::SelectionRequired(b) = business.login(login()).unwrap() else {
        panic!()
    };
    assert!(admin.select_tenant(b.ticket, "t1".into()).is_err());
    assert!(business
        .select_tenant(a.ticket.clone(), "t1".into())
        .is_err());
    assert!(admin.select_tenant(a.ticket.clone(), "0".into()).is_err());
    let page = admin
        .list_tenants(a.ticket.clone(), AccessPageRequest::default())
        .unwrap();
    assert!(page.items.iter().all(|t| t.tenant.id != "0"));
    let session = admin.select_tenant(a.ticket, "t1".into()).unwrap();
    assert_eq!(session.session.purpose, AccessTokenPurpose::Management);
    let switch = admin
        .begin_switch(session.tokens.access_token.clone())
        .unwrap();
    let next = admin.select_tenant(switch.ticket, "t2".into()).unwrap();
    assert_eq!(next.session.purpose, AccessTokenPurpose::Management);
    s.0.lock()
        .unwrap()
        .members
        .iter_mut()
        .find(|m| m.tenant_id == "t2")
        .unwrap()
        .status = MembershipStatus::Suspended;
    assert!(admin
        .authenticate(next.tokens.access_token, "request".into())
        .is_err());
    assert!(admin.rotate_refresh(next.tokens.refresh_token).is_err());
    s.0.lock().unwrap().fail_insert = true;
    let count = s.0.lock().unwrap().sessions.len();
    let fixed = management(
        TenancyMode::Enabled,
        LoginTenantPolicy::Fixed {
            tenant_id: "t1".into(),
        },
        s.clone(),
    );
    assert!(fixed.login(login()).is_err());
    assert_eq!(s.0.lock().unwrap().sessions.len(), count);
}
