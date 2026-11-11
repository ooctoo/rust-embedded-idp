use super::*;
use std::sync::atomic::AtomicU64;

#[derive(Clone)]
struct MovingClock(Arc<AtomicU64>);
impl Clock for MovingClock {
    fn now(&self) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(self.0.load(Ordering::SeqCst))
    }
}
fn configured(
    store: S,
    clock: MovingClock,
    ttl: u64,
    mode: TenancyMode,
    tenant: &str,
) -> CoreTenantAuthenticationService<S, Tok, G, Dg, MovingClock, I> {
    CoreTenantAuthenticationService::new(
        mode,
        AuthConfig {
            access_token_ttl_secs: ttl,
            refresh_token_ttl_secs: 3600,
            session_ttl_secs: 3600,
            allow_local_registration: true,
            verification_code_ttl_secs: 60,
            password_min_length: 8,
            password_max_length: 128,
        },
        TenantLoginEntry {
            client_id: "web".into(),
            login_entry: "login".into(),
            policy: LoginTenantPolicy::Fixed {
                tenant_id: tenant.into(),
            },
            require_device_proof: false,
        },
        store,
        Tok,
        G,
        Dg,
        clock,
        I,
    )
    .unwrap()
}

#[test]
fn host_lifetime_applies_to_login_and_refresh_in_both_modes() {
    for (mode, tenant) in [(TenancyMode::Disabled, "0"), (TenancyMode::Enabled, "t1")] {
        for ttl in [300, 1800] {
            let store = seed();
            if mode == TenancyMode::Disabled {
                store.0.lock().unwrap().members.push(m("0", "a"));
            }
            let clock = MovingClock(Arc::new(AtomicU64::new(1000)));
            let auth = configured(store, clock.clone(), ttl, mode, tenant);
            let TenantLoginOutcome::Authenticated(first) = auth.login(login()).unwrap() else {
                panic!()
            };
            assert_eq!(
                first.tokens.access_expires_at,
                clock.now() + Duration::from_secs(ttl)
            );
            clock.0.store(1010, Ordering::SeqCst);
            let TenantRefreshOutcome::Rotated { session, tokens } =
                auth.rotate_refresh(first.tokens.refresh_token).unwrap()
            else {
                panic!()
            };
            assert_eq!(session.expires_at, first.session.expires_at);
            assert_eq!(
                tokens.access_token.expires_at,
                clock.now() + Duration::from_secs(ttl)
            );
            let claims = Tok
                .validate_access_token(tokens.access_token.token.expose_secret(), clock.now())
                .unwrap()
                .unwrap();
            assert_eq!(claims.expires_at, tokens.access_token.expires_at);
            assert_eq!(claims.issued_at, clock.now());
        }
    }
}

#[test]
fn existing_session_refresh_caps_configured_lifetime_at_absolute_deadline() {
    for remaining in [901, 900, 120, 1] {
        for scope in [None, Some("openid")] {
            let store = seed();
            let clock = MovingClock(Arc::new(AtomicU64::new(1000)));
            let original = configured(
                store.clone(),
                clock.clone(),
                300,
                TenancyMode::Enabled,
                "t1",
            );
            let TenantLoginOutcome::Authenticated(first) = original.login(login()).unwrap() else {
                panic!()
            };
            // Restore a persisted session/refresh near its absolute deadline, then
            // assemble the new host policy against that same state.
            {
                let mut data = store.0.lock().unwrap();
                data.sessions[0].scope = scope.map(str::to_owned);
                data.refreshes[0].expires_at = first.session.expires_at;
            }
            let auth = configured(
                store.clone(),
                clock.clone(),
                900,
                TenancyMode::Enabled,
                "t1",
            );
            clock.0.store(4600 - remaining, Ordering::SeqCst);
            let TenantRefreshOutcome::Rotated { session, tokens } = auth
                .rotate_refresh(first.tokens.refresh_token.clone())
                .unwrap()
            else {
                panic!()
            };
            assert_eq!(
                tokens.access_token.expires_at,
                clock.now() + Duration::from_secs(remaining.min(900))
            );
            assert_eq!(session.expires_at, first.session.expires_at);
            assert_eq!(session.refresh_token_version, 2);
            let claims = Tok
                .validate_access_token(tokens.access_token.token.expose_secret(), clock.now())
                .unwrap()
                .unwrap();
            assert_eq!(claims.scope.as_deref(), scope);
            assert_eq!(claims.expires_at, tokens.access_token.expires_at);
            assert!(auth.authenticate(tokens.access_token.token).is_ok());
            let before = store.0.lock().unwrap().clone();
            clock.0.store(4600, Ordering::SeqCst);
            assert!(auth.rotate_refresh(tokens.refresh_token).is_err());
            let after = store.0.lock().unwrap();
            assert_eq!(after.sessions, before.sessions);
            assert!(after.refreshes == before.refreshes);
        }
    }
}

#[test]
fn default_issuer_methods_reject_overlong_output_without_rewriting_metadata() {
    struct Legacy;
    impl AccessTokenIssuer for Legacy {
        fn issue_access_token(
            &self,
            t: &str,
            s: &str,
            a: &str,
            c: &str,
            now: SystemTime,
        ) -> Result<IssuedAccessToken, TokenError> {
            Tok.issue_access_token(t, s, a, c, now)
        }
    }
    assert!(Legacy
        .issue_access_token_with_expiry(
            "t1",
            "s",
            "a",
            "web",
            C.now(),
            C.now() + Duration::from_secs(59)
        )
        .is_err());
    assert_eq!(
        Legacy
            .issue_access_token_with_expiry(
                "t1",
                "s",
                "a",
                "web",
                C.now(),
                C.now() + Duration::from_secs(60)
            )
            .unwrap()
            .expires_at,
        C.now() + Duration::from_secs(60)
    );
}

struct FaultyTokens {
    fault: Arc<AtomicU64>,
    clock: MovingClock,
}
impl TokenIssuer for FaultyTokens {
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
impl AccessTokenIssuer for FaultyTokens {
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
    fn issue_access_token_with_expiry(
        &self,
        t: &str,
        s: &str,
        a: &str,
        c: &str,
        n: SystemTime,
        expiry: SystemTime,
    ) -> Result<IssuedAccessToken, TokenError> {
        let mut result = Tok.issue_access_token_with_expiry(t, s, a, c, n, expiry)?;
        match self.fault.load(Ordering::SeqCst) {
            1 => result.expires_at -= Duration::from_secs(1),
            2 => self.clock.0.store(
                expiry.duration_since(UNIX_EPOCH).unwrap().as_secs(),
                Ordering::SeqCst,
            ),
            3 => {
                result.token =
                    test_access_token(t, s, a, c, n, expiry + Duration::from_secs(1), None)
            }
            4 => {
                result.token =
                    test_access_token(t, s, a, c, n, expiry - Duration::from_secs(1), None);
                result.expires_at = expiry - Duration::from_millis(100);
            }
            _ => {}
        }
        Ok(result)
    }
}
impl ScopedAccessTokenIssuer for FaultyTokens {
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
impl AccessTokenValidator for FaultyTokens {
    fn validate_access_token(
        &self,
        raw: &str,
        now: SystemTime,
    ) -> Result<Option<ValidatedAccessToken>, TokenError> {
        let token = Tok.validate_access_token(raw, now)?;
        if self.fault.load(Ordering::SeqCst) == 4 {
            self.clock.0.store(
                token
                    .as_ref()
                    .unwrap()
                    .expires_at
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                Ordering::SeqCst,
            );
        }
        Ok(token)
    }
}

#[test]
fn refresh_rejects_mismatched_expiry_and_signing_that_outlives_the_window_atomically() {
    for fault in [1, 2, 3, 4] {
        let store = seed();
        let clock = MovingClock(Arc::new(AtomicU64::new(1000)));
        let fault_switch = Arc::new(AtomicU64::new(0));
        let auth = CoreTenantAuthenticationService::new(
            TenancyMode::Enabled,
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
                policy: LoginTenantPolicy::Fixed {
                    tenant_id: "t1".into(),
                },
                require_device_proof: false,
            },
            store.clone(),
            FaultyTokens {
                fault: fault_switch.clone(),
                clock: clock.clone(),
            },
            G,
            Dg,
            clock,
            I,
        )
        .unwrap();
        let TenantLoginOutcome::Authenticated(first) = auth.login(login()).unwrap() else {
            panic!()
        };
        let before = store.0.lock().unwrap().clone();
        fault_switch.store(fault, Ordering::SeqCst);
        assert!(
            auth.rotate_refresh(first.tokens.refresh_token).is_err(),
            "fault {fault}"
        );
        let after = store.0.lock().unwrap();
        assert_eq!(after.sessions, before.sessions);
        assert!(after.refreshes == before.refreshes);
    }
}
