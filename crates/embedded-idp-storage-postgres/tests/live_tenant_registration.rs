//! Opt-in real PostgreSQL checks, confined to a fresh owned schema per case.
use embedded_idp_core::access::*;
use embedded_idp_core::{
    Account, AccountStatus, AuthConfig, Clock, SecretString, UuidV7IdGenerator,
    VerificationCodeGenerator,
};
use embedded_idp_storage_postgres::*;
use std::{
    env,
    sync::{Arc, Barrier},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;

#[derive(Clone, Copy)]
struct TestClock;
impl Clock for TestClock {
    fn now(&self) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(100)
    }
}
struct Codes;
impl VerificationCodeGenerator for Codes {
    fn generate_code(&self) -> String {
        "123456".into()
    }
}
type Service =
    CoreTenantRegistrationService<PostgresAccessStore, TestClock, UuidV7IdGenerator, Codes>;
struct Db {
    adapter: PostgresStorageAdapter,
    mode: TenancyMode,
}
impl Db {
    fn new(mode: TenancyMode) -> Self {
        let adapter = PostgresStorageAdapter::new(PgStorageConfig {
            connection: PgConnectionConfig {
                connection_uri: env::var("EMBEDDED_IDP_TEST_PG_CONNECTION_URI")
                    .expect("explicit test connection required"),
                schema_name: format!("idp_registration_it_{}", Uuid::now_v7().simple()),
                tls_mode: PgTlsMode::Disable,
                tls_ca_cert_path: None,
            },
            pool: DbPoolConfig {
                application_name: "idp-registration-test".into(),
                max_connections: 4,
                connect_timeout_secs: 3,
            },
        })
        .unwrap();
        adapter
            .initialize_access_schema(mode, &PermissionCatalog::new(vec![]).unwrap())
            .unwrap();
        CoreAccessBootstrapService::new(mode, adapter.clone(), TestClock, UuidV7IdGenerator)
            .initialize(
                Account {
                    id: Uuid::now_v7().to_string(),
                    email: "bootstrap@example.test".into(),
                    password_hash: "test-only-unused-hash".into(),
                    display_name: None,
                    status: AccountStatus::Active,
                    created_at: UNIX_EPOCH,
                },
                "registration-test".into(),
            )
            .unwrap();
        let db = Self { adapter, mode };
        if mode == TenancyMode::Enabled {
            db.adapter.connect().unwrap().batch_execute(&format!("insert into {}.access_tenants(id,kind,name,status,allow_registration,created_at_epoch) values ('t1','tenant','T1','active',true,1),('t2','tenant','T2','active',true,1)", db.schema())).unwrap();
        }
        db
    }
    fn schema(&self) -> &str {
        self.adapter.schema_name()
    }
    fn store(&self) -> PostgresAccessStore {
        PostgresAccessStore::new(self.adapter.clone(), self.mode).unwrap()
    }
    fn service(&self) -> Service {
        CoreTenantRegistrationService::new(
            self.mode,
            AuthConfig {
                allow_local_registration: true,
                access_token_ttl_secs: 60,
                refresh_token_ttl_secs: 600,
                session_ttl_secs: 600,
                verification_code_ttl_secs: 60,
                password_min_length: 8,
                password_max_length: 128,
            },
            self.store(),
            TestClock,
            UuidV7IdGenerator,
            Codes,
        )
        .unwrap()
    }
    fn state(&self, id: &str) -> (String, Option<i64>) {
        let row = self.adapter.connect().unwrap().query_one(&format!("select a.status,v.consumed_at_epoch from {}.accounts a join {}.email_verification_codes v on v.account_id=a.id and v.tenant_id=a.registration_tenant_id where a.id=$1",self.schema(),self.schema()), &[&Uuid::parse_str(id).unwrap()]).unwrap();
        (row.get(0), row.get(1))
    }
}
impl Drop for Db {
    fn drop(&mut self) {
        assert!(self.schema().starts_with("idp_registration_it_"));
        if let Ok(mut c) = self.adapter.connect() {
            let _ = c.batch_execute(&format!("drop schema {} cascade", self.schema()));
        }
    }
}
fn register(tenant: &str) -> RegisterTenantAccountCommand {
    RegisterTenantAccountCommand {
        tenant_id: tenant.into(),
        email: "new@example.test".into(),
        password: SecretString::new("Test-password-123"),
        display_name: Some("New user".into()),
    }
}
fn verify(tenant: &str) -> VerifyTenantEmailCommand {
    VerifyTenantEmailCommand {
        tenant_id: tenant.into(),
        email: "new@example.test".into(),
        verification_code: SecretString::new("123456"),
    }
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn registration_verification_round_trip_both_modes_without_sessions() {
    for mode in [TenancyMode::Disabled, TenancyMode::Enabled] {
        let db = Db::new(mode);
        let service = db.service();
        let tenant = if mode == TenancyMode::Enabled {
            "t1"
        } else {
            "0"
        };
        let registered = service.register_account(register(tenant)).unwrap();
        let id = Uuid::parse_str(&registered.account_id).unwrap();
        assert_eq!(
            db.state(&registered.account_id),
            ("pending_verification".into(), None)
        );
        let mut c = db.adapter.connect().unwrap();
        let s = db.schema();
        let row=c.query_one(&format!("select a.password_hash,a.registration_tenant_id,m.status from {s}.accounts a join {s}.access_memberships m on m.account_id=a.id where a.id=$1"), &[&id]).unwrap();
        assert!(row.get::<_, String>(0).starts_with("$argon2id$"));
        assert_eq!(row.get::<_, String>(1), tenant);
        assert_eq!(row.get::<_, String>(2), "active");
        assert!(service.register_account(register(tenant)).is_err());
        if mode == TenancyMode::Enabled {
            assert!(service.register_account(register("t2")).is_err());
            assert!(service.verify_email(verify("t2")).is_err());
            assert_eq!(
                c.query_one(
                    &format!("select count(*) from {s}.access_memberships where account_id=$1"),
                    &[&id]
                )
                .unwrap()
                .get::<_, i64>(0),
                1
            );
        }
        assert_eq!(
            service.verify_email(verify(tenant)).unwrap().account_id,
            registered.account_id
        );
        assert_eq!(
            db.state(&registered.account_id),
            ("active".into(), Some(100))
        );
        assert!(service.verify_email(verify(tenant)).is_err());
        for table in [
            "auth_sessions",
            "refresh_tokens",
            "devices",
            "authorization_codes",
            "auth_tenant_selections",
        ] {
            assert_eq!(
                c.query_one(&format!("select count(*) from {s}.{table}"), &[])
                    .unwrap()
                    .get::<_, i64>(0),
                0
            );
        }
    }
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn verification_state_expiry_and_write_failure_cannot_activate_identity() {
    let db = Db::new(TenancyMode::Enabled);
    let service = db.service();
    let r = service.register_account(register("t1")).unwrap();
    let s = db.schema();
    let mut c = db.adapter.connect().unwrap();
    for (disable, restore) in [
        (format!("update {s}.access_tenants set status='suspended' where id='t1'"),format!("update {s}.access_tenants set status='active' where id='t1'")),
        (format!("update {s}.access_memberships set status='suspended' where tenant_id='t1'"),format!("update {s}.access_memberships set status='active' where tenant_id='t1'")),
        (format!("update {s}.email_verification_codes set issued_at_epoch=99,expires_at_epoch=100"),format!("update {s}.email_verification_codes set issued_at_epoch=100,expires_at_epoch=160")),
        (format!("update {s}.accounts set status='disabled' where email='new@example.test'"),format!("update {s}.accounts set status='pending_verification' where email='new@example.test'")),
        (format!("update {s}.accounts set status='closed' where email='new@example.test'"),format!("update {s}.accounts set status='pending_verification' where email='new@example.test'")),
    ] {
        c.batch_execute(&disable).unwrap(); assert!(service.verify_email(verify("t1")).is_err()); assert_eq!(db.state(&r.account_id).1,None); c.batch_execute(&restore).unwrap();
    }
    // Failure consuming the code must roll back the preceding account activation.
    c.batch_execute(&format!("create function {s}.reject_activation() returns trigger language plpgsql as $$ begin if new.consumed_at_epoch is not null then raise exception 'test activation failure'; end if; return new; end $$; create trigger reject_activation before update on {s}.email_verification_codes for each row execute function {s}.reject_activation()" )).unwrap();
    assert!(service.verify_email(verify("t1")).is_err());
    assert_eq!(
        db.state(&r.account_id),
        ("pending_verification".into(), None)
    );
    c.batch_execute(&format!(
        "drop trigger reject_activation on {s}.email_verification_codes"
    ))
    .unwrap();
    // Closing registration must block new accounts, but not verification already issued.
    c.batch_execute(&format!(
        "update {s}.access_tenants set allow_registration=false where id='t1'"
    ))
    .unwrap();
    let mut other = register("t1");
    other.email = "other@example.test".into();
    assert!(service.register_account(other).is_err());
    service.verify_email(verify("t1")).unwrap();
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn concurrent_verification_consumes_code_once_and_transaction_errors_rollback() {
    let db = Db::new(TenancyMode::Enabled);
    let r = db.service().register_account(register("t1")).unwrap();
    // Exercise callback rollback after both persistence writes have succeeded.
    let store = db.store();
    let result: Result<(), TenantRegistrationError> = store.verification_transaction("t1", |tx| {
        let state = tx.load_verification("new@example.test", "123456")?.unwrap();
        tx.activate_verified_account(
            &state.verification.account_id,
            &state.verification.id,
            TestClock.now(),
        )?;
        Err(TenantRegistrationError::InvalidVerificationCode)
    });
    assert!(result.is_err());
    assert_eq!(
        db.state(&r.account_id),
        ("pending_verification".into(), None)
    );
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _: Result<(), TenantRegistrationError> = store.verification_transaction("t1", |tx| {
            let state = tx.load_verification("new@example.test", "123456")?.unwrap();
            tx.activate_verified_account(
                &state.verification.account_id,
                &state.verification.id,
                TestClock.now(),
            )?;
            panic!("test transaction unwind");
        });
    }));
    assert!(panic.is_err());
    assert_eq!(
        db.state(&r.account_id),
        ("pending_verification".into(), None)
    );
    let id = Uuid::parse_str(&r.account_id).unwrap();
    let s = db.schema();
    let mut c = db.adapter.connect().unwrap();
    c.execute(&format!("insert into {s}.access_memberships(tenant_id,account_id,status,joined_at_epoch) values ('t2',$1,'active',100)"), &[&id]).unwrap();
    c.execute(&format!("insert into {s}.email_verification_codes(tenant_id,id,account_id,email,code,issued_at_epoch,expires_at_epoch) values ('t2',$1,$2,'new@example.test','123456',100,160)"), &[&Uuid::now_v7(),&id]).unwrap();
    let barrier = Arc::new(Barrier::new(2));
    assert!(db.service().verify_email(verify("t2")).is_err());
    let services = [db.service(), db.service()];
    let handles: Vec<_> = services
        .into_iter()
        .map(|service| {
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                service.verify_email(verify("t1"))
            })
        })
        .collect();
    let successes = handles
        .into_iter()
        .map(|h| h.join().unwrap().is_ok())
        .filter(|ok| *ok)
        .count();
    assert_eq!(successes, 1);
    assert_eq!(db.state(&r.account_id).0, "active");
    assert_eq!(c.query_one(&format!("select count(*) from {s}.email_verification_codes where account_id=$1 and consumed_at_epoch is not null"), &[&id]).unwrap().get::<_,i64>(0),1);
}

mod authentication {
    mod device_proofs;
    mod management;
    mod registration_http;
    use super::*;
    use base64ct::{Base64, Encoding};
    use embedded_idp_core::{
        AccessTokenValidator, IssuedTokenBundle, RefreshTokenDigester, TokenError, TokenIssuer,
        ValidatedAccessToken,
    };
    use embedded_idp_security::{
        ProductionJwtConfig, Rs256JwtService, RsaSigningKeyConfig, SecureRefreshTokenGenerator,
        Sha256RefreshTokenDigester,
    };

    struct SignedTokens {
        jwt: Rs256JwtService,
        fail_issue: bool,
    }
    impl TokenIssuer for SignedTokens {
        fn issue_session_tokens(
            &self,
            tenant: &str,
            session: &str,
            account: &str,
            client: &str,
            version: u64,
            now: SystemTime,
        ) -> Result<IssuedTokenBundle, TokenError> {
            if self.fail_issue {
                return Err(TokenError::IssuerRejected("test issuance failure".into()));
            }
            self.jwt
                .issue_session_tokens(tenant, session, account, client, version, now)
        }
    }
    impl embedded_idp_core::AccessTokenIssuer for SignedTokens {
        fn issue_access_token(
            &self,
            tenant: &str,
            session: &str,
            account: &str,
            client: &str,
            now: SystemTime,
        ) -> Result<embedded_idp_core::IssuedAccessToken, TokenError> {
            if self.fail_issue {
                return Err(TokenError::IssuerRejected(
                    "test access issuance failure".into(),
                ));
            }
            self.jwt
                .issue_access_token(tenant, session, account, client, now)
        }
    }
    impl embedded_idp_core::ScopedAccessTokenIssuer for SignedTokens {
        fn issue_scoped_access_token(
            &self,
            t: &str,
            s: &str,
            a: &str,
            c: &str,
            n: SystemTime,
            scope: &str,
        ) -> Result<embedded_idp_core::IssuedAccessToken, TokenError> {
            self.jwt.issue_scoped_access_token(t, s, a, c, n, scope)
        }
    }
    impl embedded_idp_core::IdTokenIssuer for SignedTokens {
        fn issue_id_token(
            &self,
            claims: &embedded_idp_core::IdTokenClaims,
        ) -> Result<SecretString, TokenError> {
            if self.fail_issue {
                return Err(TokenError::IssuerRejected(
                    "test ID issuance failure".into(),
                ));
            }
            self.jwt.issue_id_token(claims)
        }
    }
    impl AccessTokenValidator for SignedTokens {
        fn validate_access_token(
            &self,
            token: &str,
            now: SystemTime,
        ) -> Result<Option<ValidatedAccessToken>, TokenError> {
            self.jwt.validate_access_token(token, now)
        }
    }
    type Auth = CoreTenantAuthenticationService<
        PostgresAccessStore,
        SignedTokens,
        SecureRefreshTokenGenerator,
        Sha256RefreshTokenDigester,
        TestClock,
        UuidV7IdGenerator,
    >;
    fn auth(
        db: &Db,
        policy: LoginTenantPolicy,
        entry: &str,
        proof: bool,
        fail_issue: bool,
    ) -> Auth {
        let key = RsaSigningKeyConfig::from_private_key_der(
            Base64::decode_vec(
                include_str!("../../embedded-idp-security/tests/fixtures/rsa_3072_key_1.pk8.b64")
                    .trim(),
            )
            .unwrap(),
        )
        .unwrap();
        let jwt = Rs256JwtService::new(
            ProductionJwtConfig {
                issuer: "https://idp.example.test".into(),
                audience: "test-api".into(),
                scope: "openid".into(),
                access_token_ttl_secs: 60,
                refresh_token_ttl_secs: 600,
                clock_skew_secs: 0,
            },
            key,
            vec![],
        )
        .unwrap();
        CoreTenantAuthenticationService::new(
            db.mode,
            AuthConfig {
                allow_local_registration: true,
                access_token_ttl_secs: 60,
                refresh_token_ttl_secs: 600,
                session_ttl_secs: 600,
                verification_code_ttl_secs: 60,
                password_min_length: 8,
                password_max_length: 128,
            },
            TenantLoginEntry {
                client_id: "web".into(),
                login_entry: entry.into(),
                policy,
                require_device_proof: proof,
            },
            db.store(),
            SignedTokens { jwt, fail_issue },
            SecureRefreshTokenGenerator,
            Sha256RefreshTokenDigester,
            TestClock,
            UuidV7IdGenerator,
        )
        .unwrap()
    }
    fn password() -> TenantPasswordLogin {
        TenantPasswordLogin {
            email: "new@example.test".into(),
            password: SecretString::new("Test-password-123"),
        }
    }
    fn prepare(db: &Db) -> String {
        let tenant = if db.mode == TenancyMode::Enabled {
            "t1"
        } else {
            "0"
        };
        let r = db.service().register_account(register(tenant)).unwrap();
        db.service().verify_email(verify(tenant)).unwrap();
        let s = db.schema();
        let mut c = db.adapter.connect().unwrap();
        c.batch_execute(&format!("insert into {s}.oidc_clients(client_id,client_name,redirect_uris_json,client_type,pkce_required,created_at_epoch) values ('web','Web','[\"https://example.test/callback\"]','public_desktop',true,1)")).unwrap();
        if db.mode == TenancyMode::Enabled {
            c.execute(&format!("insert into {s}.access_memberships(tenant_id,account_id,status,joined_at_epoch) values ('t2',$1,'active',100),('0',$1,'active',100)"), &[&Uuid::parse_str(&r.account_id).unwrap()]).unwrap();
        }
        r.account_id
    }
    fn ticket(service: &Auth) -> TenantSelectionTicket {
        match service.login(password()).unwrap() {
            TenantLoginOutcome::SelectionRequired(t) => t,
            other => panic!("expected ticket, got {other:?}"),
        }
    }
    fn count(db: &Db, table: &str) -> i64 {
        db.adapter
            .connect()
            .unwrap()
            .query_one(
                &format!("select count(*) from {}.{table}", db.schema()),
                &[],
            )
            .unwrap()
            .get(0)
    }

    #[test]
    #[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
    fn fixed_login_creates_bound_session_and_rechecks_current_state_in_both_modes() {
        for mode in [TenancyMode::Disabled, TenancyMode::Enabled] {
            let db = Db::new(mode);
            let account = prepare(&db);
            let tenant = if mode == TenancyMode::Enabled {
                "t1"
            } else {
                "0"
            };
            let svc = auth(
                &db,
                LoginTenantPolicy::Fixed {
                    tenant_id: tenant.into(),
                },
                "fixed",
                false,
                false,
            );
            let TenantLoginOutcome::Authenticated(result) = svc.login(password()).unwrap() else {
                panic!("fixed must create session")
            };
            let actor = svc
                .authenticate(result.tokens.access_token.clone())
                .unwrap();
            assert_eq!(actor.tenant_id, tenant);
            assert_eq!(actor.subject_id, account);
            assert_eq!(actor.session_id, result.session.id);
            assert_eq!(count(&db, "auth_tenant_selections"), 0);
            assert_eq!(count(&db, "auth_sessions"), 1);
            let digest = Sha256RefreshTokenDigester
                .digest_refresh_token(result.tokens.refresh_token.expose_secret())
                .unwrap();
            let s = db.schema();
            let mut c = db.adapter.connect().unwrap();
            let row=c.query_one(&format!("select r.tenant_id,r.token_digest,r.token_version,s.account_id from {s}.refresh_tokens r join {s}.auth_sessions s on s.tenant_id=r.tenant_id and s.id=r.session_id"), &[]).unwrap();
            assert_eq!(row.get::<_, String>(0), tenant);
            assert_eq!(row.get::<_, Vec<u8>>(1), digest);
            assert_eq!(row.get::<_, i64>(2), 1);
            assert_eq!(row.get::<_, Uuid>(3).to_string(), account);
            let mut wrong = password();
            wrong.password = SecretString::new("Wrong-password1");
            assert_eq!(
                svc.login(wrong).unwrap_err(),
                TenantAuthError::InvalidCredentials
            );
            assert!(svc
                .begin_switch(result.tokens.access_token.clone())
                .is_err());
            assert!(svc
                .select_tenant(SecretString::new("not-ticket"), tenant.into())
                .is_err());
            c.execute(&format!("update {s}.access_memberships set status='suspended' where tenant_id=$1 and account_id=$2"), &[&tenant,&Uuid::parse_str(&account).unwrap()]).unwrap();
            assert!(svc
                .authenticate(result.tokens.access_token.clone())
                .is_err());
            assert_eq!(
                svc.login(password()).unwrap_err(),
                TenantAuthError::InvalidCredentials
            );
            c.execute(&format!("update {s}.access_memberships set status='active' where tenant_id=$1 and account_id=$2"), &[&tenant,&Uuid::parse_str(&account).unwrap()]).unwrap();
            let required = auth(
                &db,
                LoginTenantPolicy::Fixed {
                    tenant_id: tenant.into(),
                },
                "fixed",
                true,
                false,
            );
            assert_eq!(
                required.login(password()).unwrap_err(),
                TenantAuthError::DeviceProofRequired
            );
            assert!(required.authenticate(result.tokens.access_token).is_err());
        }
    }

    #[test]
    #[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
    fn choose_lists_only_joined_tenants_and_switch_requires_live_source() {
        let db = Db::new(TenancyMode::Enabled);
        let account = prepare(&db);
        let svc = auth(
            &db,
            LoginTenantPolicy::ChooseAfterAuthentication,
            "choose",
            false,
            false,
        );
        let pending = ticket(&svc);
        assert_eq!(count(&db, "auth_sessions"), 0);
        assert_eq!(count(&db, "refresh_tokens"), 0);
        assert!(!format!("{pending:?}").contains(pending.ticket.expose_secret()));
        assert!(svc.authenticate(pending.ticket.clone()).is_err());
        let digest = Sha256RefreshTokenDigester
            .digest_refresh_token(pending.ticket.expose_secret())
            .unwrap();
        let row=db.adapter.connect().unwrap().query_one(&format!("select ticket_digest,client_id,login_entry,purpose from {}.auth_tenant_selections",db.schema()),&[]).unwrap();
        assert_eq!(row.get::<_, Vec<u8>>(0), digest);
        assert_eq!(row.get::<_, String>(1), "web");
        assert_eq!(row.get::<_, String>(2), "choose");
        assert_eq!(row.get::<_, String>(3), "tenant_selection");
        let first = svc
            .list_tenants(
                pending.ticket.clone(),
                AccessPageRequest {
                    sort_order: None,
                    limit: 1,
                    cursor: None,
                },
            )
            .unwrap();
        assert_eq!(first.items[0].tenant.id, "t1");
        assert!(first.has_more);
        let second = svc
            .list_tenants(
                pending.ticket.clone(),
                AccessPageRequest {
                    sort_order: None,
                    limit: 1,
                    cursor: first.next_cursor,
                },
            )
            .unwrap();
        assert_eq!(second.items[0].tenant.id, "t2");
        assert!(!second.has_more);
        let other = auth(
            &db,
            LoginTenantPolicy::ChooseAfterAuthentication,
            "other-entry",
            false,
            false,
        );
        assert!(other
            .list_tenants(pending.ticket.clone(), AccessPageRequest::default())
            .is_err());
        assert!(svc
            .select_tenant(pending.ticket.clone(), "0".into())
            .is_err());
        let session = svc
            .select_tenant(pending.ticket.clone(), "t1".into())
            .unwrap();
        assert_eq!(
            svc.authenticate(session.tokens.access_token.clone())
                .unwrap()
                .subject_id,
            account
        );
        assert!(svc
            .list_tenants(pending.ticket, AccessPageRequest::default())
            .is_err());
        let switching = svc
            .begin_switch(session.tokens.access_token.clone())
            .unwrap();
        let switched = svc.select_tenant(switching.ticket, "t2".into()).unwrap();
        assert_eq!(switched.session.tenant_id, "t2");
        assert_eq!(
            svc.authenticate(session.tokens.access_token.clone())
                .unwrap()
                .tenant_id,
            "t1"
        );
        assert_eq!(
            svc.authenticate(switched.tokens.access_token)
                .unwrap()
                .tenant_id,
            "t2"
        );
        let revoked = svc.begin_switch(session.tokens.access_token).unwrap();
        db.adapter
            .connect()
            .unwrap()
            .execute(
                &format!(
                    "update {}.auth_sessions set status='revoked' where tenant_id='t1' and id=$1",
                    db.schema()
                ),
                &[&Uuid::parse_str(&session.session.id).unwrap()],
            )
            .unwrap();
        assert!(svc.select_tenant(revoked.ticket, "t2".into()).is_err());
    }

    #[test]
    #[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
    fn selection_rollback_and_concurrent_different_tenants_allow_one_session() {
        let db = Db::new(TenancyMode::Enabled);
        prepare(&db);
        let svc = auth(
            &db,
            LoginTenantPolicy::ChooseAfterAuthentication,
            "choose",
            false,
            false,
        );
        let pending = ticket(&svc);
        let fails = auth(
            &db,
            LoginTenantPolicy::ChooseAfterAuthentication,
            "choose",
            false,
            true,
        );
        assert!(fails
            .select_tenant(pending.ticket.clone(), "t1".into())
            .is_err());
        assert_eq!(count(&db, "auth_sessions"), 0);
        svc.list_tenants(pending.ticket.clone(), AccessPageRequest::default())
            .unwrap();
        let s = db.schema();
        let mut c = db.adapter.connect().unwrap();
        c.batch_execute(&format!("create function {s}.reject_refresh() returns trigger language plpgsql as $$ begin raise exception 'test refresh failure'; end $$; create trigger reject_refresh before insert on {s}.refresh_tokens for each row execute function {s}.reject_refresh()" )).unwrap();
        assert!(svc
            .select_tenant(pending.ticket.clone(), "t1".into())
            .is_err());
        assert_eq!(count(&db, "auth_sessions"), 0);
        assert_eq!(count(&db, "refresh_tokens"), 0);
        svc.list_tenants(pending.ticket.clone(), AccessPageRequest::default())
            .unwrap();
        c.batch_execute(&format!(
            "drop trigger reject_refresh on {s}.refresh_tokens"
        ))
        .unwrap();
        drop(c);
        let barrier = Arc::new(Barrier::new(2));
        let service = Arc::new(svc);
        let handles: Vec<_> = ["t1", "t2"]
            .into_iter()
            .map(|tenant| {
                let svc = service.clone();
                let raw = pending.ticket.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    svc.select_tenant(raw, tenant.into())
                })
            })
            .collect();
        assert_eq!(
            handles
                .into_iter()
                .map(|h| h.join().unwrap().is_ok())
                .filter(|ok| *ok)
                .count(),
            1
        );
        assert_eq!(count(&db, "auth_sessions"), 1);
        assert_eq!(count(&db, "refresh_tokens"), 1);
    }

    async fn http(
        app: &axum::Router,
        method: &str,
        path: &str,
        body: Option<serde_json::Value>,
        bearer: Option<&str>,
        tenant: Option<&str>,
    ) -> (axum::http::StatusCode, serde_json::Value) {
        use tower::ServiceExt;
        let mut request = axum::http::Request::builder().method(method).uri(path);
        if let Some(raw) = bearer {
            let scheme = if path.starts_with("/auth/tenant-selection/") {
                "TenantSelection"
            } else {
                "Bearer"
            };
            request = request.header("authorization", format!("{scheme} {raw}"));
        }
        if let Some(tenant) = tenant {
            request = request.header("X-Embedded-Idp-Tenant-Id", tenant);
        }
        let body = if let Some(body) = body {
            request = request.header("content-type", "application/json");
            axum::body::Body::from(body.to_string())
        } else {
            axum::body::Body::empty()
        };
        let response = app
            .clone()
            .oneshot(request.body(body).unwrap())
            .await
            .unwrap();
        assert_eq!(response.headers()["cache-control"], "no-store");
        assert_eq!(response.headers()["pragma"], "no-cache");
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 65536)
            .await
            .unwrap();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
        )
    }

    #[test]
    #[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
    fn http_login_selection_authentication_and_switch_use_real_postgres_and_rs256() {
        use axum::http::StatusCode;
        use serde_json::json;
        let db = Db::new(TenancyMode::Enabled);
        let account = prepare(&db);
        let router = embedded_idp_axum::tenant_auth_router(Arc::new(auth(
            &db,
            LoginTenantPolicy::ChooseAfterAuthentication,
            "browser",
            false,
            false,
        )));
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let (status,caps)=http(&router,"GET","/auth/access/capabilities",None,None,None).await;
            assert_eq!(status,StatusCode::OK);assert_eq!(caps["tenancy_enabled"],true);
            let (status,_)=http(&router,"POST","/auth/login",Some(json!({"email":"new@example.test","password":"Test-password-123","client_id":"override"})),None,None).await;
            assert_eq!(status,StatusCode::UNPROCESSABLE_ENTITY);
            let (status,login)=http(&router,"POST","/auth/login",Some(json!({"email":"new@example.test","password":"Test-password-123"})),None,None).await;
            assert_eq!(status,StatusCode::OK);assert_eq!(login["status"],"tenant_selection_required");assert!(login.get("tokens").is_none());assert!((1..=300).contains(&login["expires_in"].as_u64().unwrap()));
            let ticket=login["selection_ticket"].as_str().unwrap();
            assert_eq!(http(&router,"GET","/auth/session",None,Some(ticket),None).await.0,StatusCode::UNAUTHORIZED);
            let (status,page)=http(&router,"GET","/auth/tenant-selection/tenants?limit=1",None,Some(ticket),None).await;
            assert_eq!(status,StatusCode::OK);assert_eq!(page["tenants"][0]["tenant_id"],"t1");
            let cursor=page["next_cursor"].as_str().unwrap();
            let (_,page2)=http(&router,"GET",&format!("/auth/tenant-selection/tenants?limit=1&cursor={cursor}"),None,Some(ticket),None).await;
            assert_eq!(page2["tenants"][0]["tenant_id"],"t2");assert_eq!(page2["has_more"],false);
            let (status,selected)=http(&router,"POST","/auth/tenant-selection/complete",Some(json!({"tenant_id":"t2"})),Some(ticket),Some("t2")).await;
            assert_eq!(status,StatusCode::OK);assert_eq!(selected["session"]["tenant_id"],"t2");
            let access=selected["tokens"]["access_token"].as_str().unwrap();
            assert_eq!(http(&router,"GET","/auth/tenant-selection/tenants",None,Some(access),None).await.0,StatusCode::UNAUTHORIZED);
            let (status,actor)=http(&router,"GET","/auth/session",None,Some(access),Some("t2")).await;
            assert_eq!(status,StatusCode::OK);assert_eq!(actor["account_id"],account);assert_eq!(actor["tenant_id"],"t2");
            assert!(http(&router,"GET","/auth/session",None,Some(access),Some("t1")).await.0.is_client_error());
            assert_eq!(http(&router,"POST","/auth/me/tenant-selection",None,Some(access),Some("t1")).await.0,StatusCode::UNAUTHORIZED);
            let (status,switch)=http(&router,"POST","/auth/me/tenant-selection",None,Some(access),None).await;
            assert_eq!(status,StatusCode::OK);
            let (status,other)=http(&router,"POST","/auth/tenant-selection/complete",Some(json!({"tenant_id":"t1"})),switch["selection_ticket"].as_str(),None).await;
            assert_eq!(status,StatusCode::OK);assert_eq!(other["session"]["tenant_id"],"t1");
            assert_eq!(http(&router,"GET","/auth/session",None,Some(access),None).await.0,StatusCode::OK);
        });
        assert_eq!(count(&db, "auth_sessions"), 2);
        let disabled = Db::new(TenancyMode::Disabled);
        prepare(&disabled);
        let router = embedded_idp_axum::tenant_auth_router(Arc::new(auth(
            &disabled,
            LoginTenantPolicy::Fixed {
                tenant_id: "0".into(),
            },
            "fixed",
            false,
            false,
        )));
        runtime.block_on(async {
            assert_eq!(
                http(
                    &router,
                    "GET",
                    "/auth/access/capabilities",
                    None,
                    None,
                    None
                )
                .await
                .1["tenancy_enabled"],
                false
            );
            assert_eq!(
                http(
                    &router,
                    "GET",
                    "/auth/tenant-selection/tenants",
                    None,
                    None,
                    None
                )
                .await
                .0,
                StatusCode::NOT_FOUND
            );
            assert_eq!(
                http(
                    &router,
                    "POST",
                    "/auth/me/tenant-selection",
                    None,
                    None,
                    None
                )
                .await
                .0,
                StatusCode::NOT_FOUND
            );
            let (status, result) = http(
                &router,
                "POST",
                "/auth/login",
                Some(json!({"email":"new@example.test","password":"Test-password-123"})),
                None,
                None,
            )
            .await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(result["session"]["tenant_id"], "0");
        });
        let mismatch: Result<(), TenantAuthError> = disabled
            .store()
            .auth_transaction(TenancyMode::Enabled, |_| {
                panic!("mode mismatch must fail before callback")
            });
        assert!(matches!(
            mismatch,
            Err(TenantAuthError::Access(AccessError::ModeMismatch))
        ));
    }
}
