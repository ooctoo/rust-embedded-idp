use super::*;
use embedded_idp_core::{ClientSecretError, ClientSecretVerifier, OidcConfig, PkceChallengeMethod};

// Test adapter for the host-owned secret verification port; synthetic values only.
struct Secrets;
impl ClientSecretVerifier for Secrets {
    fn verify_client_secret(&self, raw: &str, stored: &str) -> Result<bool, ClientSecretError> {
        Ok(raw == "synthetic-client-secret" && stored == "synthetic-secret-hash")
    }
}
type Oidc = CoreTenantOidcService<
    PostgresAccessStore,
    SignedTokens,
    SecureRefreshTokenGenerator,
    Sha256RefreshTokenDigester,
    TestClock,
    UuidV7IdGenerator,
    Secrets,
>;
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CALLBACK: &str = "testapp://callback";
fn entry(db: &Db, tenant: &str) -> Auth {
    auth(
        db,
        LoginTenantPolicy::Fixed {
            tenant_id: tenant.into(),
        },
        "oidc",
        false,
        false,
    )
}
fn oidc(db: &Db, tenant: &str, fail: bool) -> Oidc {
    CoreTenantOidcService::new(
        auth(
            db,
            LoginTenantPolicy::Fixed {
                tenant_id: tenant.into(),
            },
            "oidc",
            false,
            fail,
        ),
        "https://idp.example.test".into(),
        OidcConfig {
            authorization_code_ttl_secs: 60,
            require_pkce_for_public_clients: true,
        },
        "openid".into(),
        Secrets,
    )
    .unwrap()
}
fn request(scope: &str) -> TenantAuthorizationRequest {
    TenantAuthorizationRequest {
        response_type: "code".into(),
        client_id: "web".into(),
        redirect_uri: CALLBACK.into(),
        scope: scope.into(),
        state: Some("state".into()),
        nonce: Some("nonce".into()),
        code_challenge: Some("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".into()),
        code_challenge_method: Some(PkceChallengeMethod::S256),
    }
}
fn exchange(code: SecretString) -> TenantCodeExchange {
    TenantCodeExchange {
        grant_type: "authorization_code".into(),
        client_id: "web".into(),
        code,
        redirect_uri: CALLBACK.into(),
        client_secret: None,
        code_verifier: Some(SecretString::new(VERIFIER)),
    }
}
fn setup(db: &Db, tenant: &str) -> TenantLoginSession {
    prepare(db);
    db.adapter.connect().unwrap().execute(&format!("update {}.oidc_clients set redirect_uris_json=$1,pkce_required=true where client_id='web'",db.schema()),&[&format!("[\"{CALLBACK}\"]")]).unwrap();
    password_session(entry(db, tenant).login(password()).unwrap())
}
fn actor(session: &TenantSession) -> AccessActor {
    AccessActor {
        tenant_id: session.tenant_id.clone(),
        subject_id: session.account_id.clone(),
        session_id: session.id.clone(),
    }
}
fn unused(db: &Db, code: &SecretString) -> bool {
    let digest = Sha256RefreshTokenDigester
        .digest_refresh_token(code.expose_secret())
        .unwrap();
    db.adapter
        .connect()
        .unwrap()
        .query_one(
            &format!(
                "select consumed_at_epoch is null from {}.authorization_codes where code_digest=$1",
                db.schema()
            ),
            &[&&digest[..]],
        )
        .unwrap()
        .get(0)
}
#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn tenant_oidc_exchange_is_single_use_and_keeps_scope_on_refresh_and_switch() {
    for (mode, tenant) in [(TenancyMode::Disabled, "0"), (TenancyMode::Enabled, "t1")] {
        let db = Db::new(mode);
        let mut initial = setup(&db, tenant);
        initial.session.authenticated_at = UNIX_EPOCH + Duration::from_secs(80);
        db.adapter
            .connect()
            .unwrap()
            .execute(
                &format!(
                    "update {}.auth_sessions set authenticated_at_epoch=80 where id=$1",
                    db.schema()
                ),
                &[&Uuid::parse_str(&initial.session.id).unwrap()],
            )
            .unwrap();
        let svc = oidc(&db, tenant, false);
        let result = svc
            .authorize(actor(&initial.session), request("openid"))
            .unwrap();
        assert_eq!(result.state.as_deref(), Some("state"));
        assert_eq!(result.tenant_id, tenant);
        let code = exchange(result.code.clone());
        let svc = Arc::new(svc);
        let barrier = Arc::new(Barrier::new(2));
        let handles: Vec<_> = (0..2)
            .map(|_| {
                let svc = svc.clone();
                let barrier = barrier.clone();
                let code = code.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    svc.exchange(code)
                })
            })
            .collect();
        let mut winners: Vec<_> = handles
            .into_iter()
            .filter_map(|h| h.join().unwrap().ok())
            .collect();
        assert_eq!(winners.len(), 1);
        let issued = winners.pop().unwrap();
        assert!(!unused(&db, &result.code));
        assert_eq!(count(&db, "auth_sessions"), 2);
        assert_eq!(
            issued.login.session.authenticated_at,
            initial.session.authenticated_at
        );
        assert_eq!(issued.login.session.scope.as_deref(), Some("openid"));
        let payload: serde_json::Value = serde_json::from_slice(
            &Base64UrlUnpadded::decode_vec(
                issued
                    .id_token
                    .unwrap()
                    .expose_secret()
                    .split('.')
                    .nth(1)
                    .unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(payload["nonce"], "nonce");
        assert_eq!(payload["aud"], "web");
        assert_eq!(payload["tenant_id"], tenant);
        assert_eq!(payload["auth_time"], 80);
        assert!(entry(&db, tenant)
            .authenticate(issued.login.tokens.access_token)
            .is_ok());
        // Empty OAuth scope is deliberately narrower than the host's default openid.
        let code = svc.authorize(actor(&initial.session), request("")).unwrap();
        let narrow = svc.exchange(exchange(code.code)).unwrap();
        assert!(narrow.id_token.is_none());
        assert!(svc
            .authorize(actor(&narrow.login.session), request("openid"))
            .is_err());
        let TenantRefreshOutcome::Rotated { session, tokens } = entry(&db, tenant)
            .rotate_refresh(narrow.login.tokens.refresh_token)
            .unwrap()
        else {
            panic!()
        };
        assert_eq!(session.scope.as_deref(), Some(""));
        assert!(entry(&db, tenant)
            .authenticate(tokens.access_token.token.clone())
            .is_ok());
        if mode == TenancyMode::Enabled {
            let choose = auth(
                &db,
                LoginTenantPolicy::ChooseAfterAuthentication,
                "oidc",
                false,
                false,
            );
            let ticket = choose.begin_switch(tokens.access_token.token).unwrap();
            let switched = choose.select_tenant(ticket.ticket, "t2".into()).unwrap();
            assert_eq!(switched.session.scope.as_deref(), Some(""));
            assert_eq!(
                switched.session.authenticated_at,
                initial.session.authenticated_at
            );
            assert!(choose.authenticate(switched.tokens.access_token).is_ok());
        }
    }
}
#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn tenant_oidc_rechecks_pkce_client_source_and_tenant_before_consuming_code() {
    let db = Db::new(TenancyMode::Enabled);
    let initial = setup(&db, "t1");
    let svc = oidc(&db, "t1", false);
    for req in [
        TenantAuthorizationRequest {
            scope: "admin".into(),
            ..request("openid")
        },
        TenantAuthorizationRequest {
            redirect_uri: "https://attacker.test".into(),
            ..request("openid")
        },
        TenantAuthorizationRequest {
            code_challenge: None,
            code_challenge_method: None,
            ..request("openid")
        },
    ] {
        assert!(svc.authorize(actor(&initial.session), req).is_err());
    }
    let mut forged = actor(&initial.session);
    forged.tenant_id = "t2".into();
    assert!(svc.authorize(forged, request("openid")).is_err());
    let grant = svc
        .authorize(actor(&initial.session), request("openid"))
        .unwrap();
    let cmd = exchange(grant.code.clone());
    for bad in [
        TenantCodeExchange {
            code_verifier: None,
            ..cmd.clone()
        },
        TenantCodeExchange {
            code_verifier: Some(SecretString::new("x".repeat(43))),
            ..cmd.clone()
        },
        TenantCodeExchange {
            client_id: "other".into(),
            ..cmd.clone()
        },
        TenantCodeExchange {
            redirect_uri: "testapp://other".into(),
            ..cmd.clone()
        },
    ] {
        assert!(svc.exchange(bad).is_err());
        assert!(unused(&db, &grant.code));
    }
    assert!(oidc(&db, "t2", false).exchange(cmd.clone()).is_err());
    let mut c = db.adapter.connect().unwrap();
    let s = db.schema();
    c.batch_execute(&format!(
        "update {s}.authorization_codes set created_at_epoch=99,expires_at_epoch=100"
    ))
    .unwrap();
    assert!(svc.exchange(cmd.clone()).is_err());
    assert!(unused(&db, &grant.code));
    c.batch_execute(&format!(
        "update {s}.authorization_codes set created_at_epoch=100,expires_at_epoch=160"
    ))
    .unwrap();
    c.execute(&format!("update {s}.access_memberships set status='suspended' where tenant_id='t1' and account_id=$1"),&[&Uuid::parse_str(&initial.session.account_id).unwrap()]).unwrap();
    assert!(svc.exchange(cmd.clone()).is_err());
    assert!(unused(&db, &grant.code));
    c.execute(&format!("update {s}.access_memberships set status='active' where tenant_id='t1' and account_id=$1"),&[&Uuid::parse_str(&initial.session.account_id).unwrap()]).unwrap();
    c.execute(
        &format!("update {s}.auth_sessions set status='revoked' where id=$1"),
        &[&Uuid::parse_str(&initial.session.id).unwrap()],
    )
    .unwrap();
    assert!(svc.exchange(cmd).is_err());
    assert!(unused(&db, &grant.code));
}
#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn tenant_oidc_confidential_client_secret_is_required() {
    let db = Db::new(TenancyMode::Disabled);
    let initial = setup(&db, "0");
    db.adapter.connect().unwrap().execute(&format!("update {}.oidc_clients set client_type='confidential_web',redirect_uris_json='[\"https://client.example.test/callback\"]',client_secret_hash='synthetic-secret-hash' where client_id='web'",db.schema()),&[]).unwrap();
    let svc = oidc(&db, "0", false);
    let mut req = request("openid");
    req.redirect_uri = "https://client.example.test/callback".into();
    let grant = svc.authorize(actor(&initial.session), req).unwrap();
    let mut cmd = exchange(grant.code.clone());
    cmd.redirect_uri = "https://client.example.test/callback".into();
    for secret in [None, Some("wrong"), Some(" synthetic-client-secret")] {
        cmd.client_secret = secret.map(SecretString::new);
        assert!(svc.exchange(cmd.clone()).is_err());
        assert!(unused(&db, &grant.code));
    }
    cmd.client_secret = Some(SecretString::new("synthetic-client-secret"));
    assert!(svc.exchange(cmd).is_ok());
}
#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn tenant_oidc_proof_and_code_roll_back_on_signing_and_database_failures() {
    for (mode, tenant) in [(TenancyMode::Disabled, "0"), (TenancyMode::Enabled, "t1")] {
        let db = Db::new(mode);
        setup(&db, tenant);
        let devices = proofs(&db);
        let (registration, pair) = registration(&db, tenant, 73);
        let key = devices.complete_registration(registration).unwrap();
        let proof = authentication_proof(
            &db,
            &key,
            &pair,
            TENANT_DEVICE_LOGIN_PURPOSE,
            tenant_password_proof_context("web", "oidc", &password()),
        );
        let initial = password_session(
            entry(&db, tenant)
                .login_with_proof(password(), proof, &devices)
                .unwrap(),
        );
        let svc = oidc(&db, tenant, false);
        let grant = svc
            .authorize(actor(&initial.session), request("openid"))
            .unwrap();
        let cmd = exchange(grant.code.clone());
        let proof = authentication_proof(
            &db,
            &key,
            &pair,
            TENANT_OIDC_EXCHANGE_PURPOSE,
            tenant_code_proof_context("oidc", &cmd),
        );
        assert_eq!(
            svc.exchange(cmd.clone()),
            Err(TenantAuthError::DeviceProofRequired)
        );
        let before = count(&db, "auth_sessions");
        assert!(oidc(&db, tenant, true)
            .exchange_with_proof(cmd.clone(), proof.clone(), &devices)
            .is_err());
        assert!(unused(&db, &grant.code));
        assert!(nonce_unused(
            &db,
            &SecretString::new(proof.proof.challenge.clone())
        ));
        assert_eq!(count(&db, "auth_sessions"), before);
        let s = db.schema();
        db.adapter.connect().unwrap().batch_execute(&format!("create function {s}.fail_oidc_insert() returns trigger language plpgsql as $$ begin raise exception 'synthetic failure'; end $$;create trigger fail_oidc_insert after insert on {s}.refresh_tokens for each row execute function {s}.fail_oidc_insert()" )).unwrap();
        assert!(svc
            .exchange_with_proof(cmd.clone(), proof.clone(), &devices)
            .is_err());
        assert!(unused(&db, &grant.code));
        assert!(nonce_unused(
            &db,
            &SecretString::new(proof.proof.challenge.clone())
        ));
        assert_eq!(count(&db, "auth_sessions"), before);
        db.adapter
            .connect()
            .unwrap()
            .batch_execute(&format!(
                "drop trigger fail_oidc_insert on {s}.refresh_tokens"
            ))
            .unwrap();
        let mut tampered = cmd.clone();
        tampered.code_verifier = Some(SecretString::new("x".repeat(43)));
        assert!(svc
            .exchange_with_proof(tampered, proof.clone(), &devices)
            .is_err());
        let mut tampered = cmd.clone();
        tampered.client_secret = Some(SecretString::new("changed-signed-credential"));
        assert!(svc
            .exchange_with_proof(tampered, proof.clone(), &devices)
            .is_err());
        let mut bad_proof = proof.clone();
        bad_proof.proof.signature = Base64UrlUnpadded::encode_string(&[0; 64]);
        assert!(svc
            .exchange_with_proof(cmd.clone(), bad_proof, &devices)
            .is_err());
        db.adapter
            .connect()
            .unwrap()
            .execute(
                &format!("update {s}.devices set status='revoked' where tenant_id=$1 and id=$2"),
                &[&tenant, &Uuid::parse_str(&key.device_id).unwrap()],
            )
            .unwrap();
        assert!(svc
            .exchange_with_proof(cmd.clone(), proof.clone(), &devices)
            .is_err());
        assert!(unused(&db, &grant.code));
        assert!(nonce_unused(
            &db,
            &SecretString::new(proof.proof.challenge.clone())
        ));
        db.adapter
            .connect()
            .unwrap()
            .execute(
                &format!("update {s}.devices set status='active' where tenant_id=$1 and id=$2"),
                &[&tenant, &Uuid::parse_str(&key.device_id).unwrap()],
            )
            .unwrap();
        let issued = svc
            .exchange_with_proof(cmd.clone(), proof.clone(), &devices)
            .unwrap();
        assert_eq!(issued.login.session.device_id, Some(key.device_id));
        assert!(!nonce_unused(
            &db,
            &SecretString::new(proof.proof.challenge.clone())
        ));
        assert!(!unused(&db, &grant.code));
        assert!(svc.exchange_with_proof(cmd, proof, &devices).is_err());
        assert_eq!(count(&db, "auth_sessions"), before + 1);
    }
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn device_revocation_committed_while_oidc_exchange_waits_prevents_issuance() {
    for (mode, tenant) in [(TenancyMode::Disabled, "0"), (TenancyMode::Enabled, "t1")] {
        let db = Db::new(mode);
        setup(&db, tenant);
        let devices = proofs(&db);
        let (registration, pair) = registration(&db, tenant, 74);
        let key = devices.complete_registration(registration).unwrap();
        let login_proof = authentication_proof(
            &db,
            &key,
            &pair,
            TENANT_DEVICE_LOGIN_PURPOSE,
            tenant_password_proof_context("web", "oidc", &password()),
        );
        let initial = password_session(
            entry(&db, tenant)
                .login_with_proof(password(), login_proof, &devices)
                .unwrap(),
        );
        let grant = oidc(&db, tenant, false)
            .authorize(actor(&initial.session), request("openid"))
            .unwrap();
        let exchange = exchange(grant.code.clone());
        let proof = authentication_proof(
            &db,
            &key,
            &pair,
            TENANT_OIDC_EXCHANGE_PURPOSE,
            tenant_code_proof_context("oidc", &exchange),
        );
        let nonce = SecretString::new(proof.proof.challenge.clone());
        let before = count(&db, "auth_sessions");
        let s = db.schema();
        let mut connection = db.adapter.connect().unwrap();
        let mut tx = connection.transaction().unwrap();
        tx.query_one(
            &format!("select singleton from {s}.access_state where singleton for update"),
            &[],
        )
        .unwrap();
        let svc = oidc(&db, tenant, false);
        let worker = std::thread::spawn(move || svc.exchange_with_proof(exchange, proof, &devices));
        wait_for_auth_state_lock(&db);
        tx.execute(
            &format!("update {s}.devices set status='revoked' where tenant_id=$1 and id=$2"),
            &[&tenant, &Uuid::parse_str(&key.device_id).unwrap()],
        )
        .unwrap();
        tx.commit().unwrap();
        assert!(worker.join().unwrap().is_err());
        assert!(unused(&db, &grant.code));
        assert!(nonce_unused(&db, &nonce));
        assert_eq!(count(&db, "auth_sessions"), before);
    }
}

mod resource;

mod http;
