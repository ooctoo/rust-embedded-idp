use super::*;
use embedded_idp_core::{RotateProofBoundRefreshCommand, REFRESH_PURPOSE};

fn service(db: &Db, tenant: &str, fail: bool) -> Auth {
    auth(
        db,
        LoginTenantPolicy::Fixed {
            tenant_id: tenant.into(),
        },
        "refresh-test",
        true,
        fail,
    )
}
fn prepared(
    db: &Db,
    tenant: &str,
    seed: u8,
) -> (TenantProofKey, Ed25519KeyPair, TenantLoginSession) {
    let devices = proofs(db);
    let (command, pair) = registration(db, tenant, seed);
    let key = devices.complete_registration(command).unwrap();
    let proof = authentication_proof(
        db,
        &key,
        &pair,
        TENANT_DEVICE_LOGIN_PURPOSE,
        tenant_password_proof_context("web", "refresh-test", &password()),
    );
    let session = password_session(
        service(db, tenant, false)
            .login_with_proof(password(), proof, &devices)
            .unwrap(),
    );
    (key, pair, session)
}
fn command(
    db: &Db,
    key: &TenantProofKey,
    pair: &Ed25519KeyPair,
    raw: SecretString,
) -> RotateProofBoundRefreshCommand {
    let context = tenant_refresh_proof_context("web", "refresh-test", &raw);
    let proof = authentication_proof(db, key, pair, REFRESH_PURPOSE, context);
    RotateProofBoundRefreshCommand {
        refresh_token: raw,
        proof: proof.proof,
        binding: proof.binding,
    }
}
fn state(db: &Db, session: &TenantSession) -> (String, i64) {
    let row=db.adapter.connect().unwrap().query_one(&format!("select status,refresh_token_version from {}.auth_sessions where tenant_id=$1 and id=$2",db.schema()),&[&session.tenant_id,&Uuid::parse_str(&session.id).unwrap()]).unwrap();
    (row.get(0), row.get(1))
}
fn assert_unused(db: &Db, command: &RotateProofBoundRefreshCommand) {
    assert!(nonce_unused(
        db,
        &SecretString::new(command.proof.challenge.clone())
    ));
}
#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn tenant_bearer_refresh_rotates_and_commits_scoped_reuse_in_both_modes() {
    for (mode, tenant) in [(TenancyMode::Disabled, "0"), (TenancyMode::Enabled, "t1")] {
        let db = Db::new(mode);
        prepare(&db);
        let svc = auth(
            &db,
            LoginTenantPolicy::Fixed {
                tenant_id: tenant.into(),
            },
            "bearer",
            false,
            false,
        );
        let first = password_session(svc.login(password()).unwrap());
        let other = password_session(svc.login(password()).unwrap());
        let TenantRefreshOutcome::Rotated { session, tokens } = svc
            .rotate_refresh(first.tokens.refresh_token.clone())
            .unwrap()
        else {
            panic!()
        };
        assert_eq!(session.refresh_token_version, 2);
        assert_eq!(tokens.refresh_expires_at, first.session.expires_at);
        assert!(svc.authenticate(tokens.access_token.token.clone()).is_ok());
        assert_eq!(
            svc.rotate_refresh(first.tokens.refresh_token),
            Ok(TenantRefreshOutcome::ReuseDetected {
                tenant_id: tenant.into(),
                session_id: first.session.id.clone()
            })
        );
        assert_eq!(state(&db, &session), ("revoked".into(), 2));
        assert!(svc.authenticate(tokens.access_token.token).is_err());
        assert!(svc.rotate_refresh(tokens.refresh_token).is_err());
        assert!(svc.authenticate(other.tokens.access_token).is_ok());
        let row=db.adapter.connect().unwrap().query_one(&format!("select count(*) from {}.refresh_tokens where tenant_id=$1 and session_id=$2 and revocation_reason='reuse_detected'",db.schema()),&[&tenant,&Uuid::parse_str(&first.session.id).unwrap()]).unwrap();
        assert_eq!(row.get::<_, i64>(0), 2);
    }
}
#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn tenant_proof_refresh_rotation_and_reuse_write_failures_roll_back_all_state_in_both_modes() {
    for (mode, tenant) in [(TenancyMode::Disabled, "0"), (TenancyMode::Enabled, "t1")] {
        let db = Db::new(mode);
        prepare(&db);
        let (key, pair, initial) = prepared(&db, tenant, 41);
        let svc = service(&db, tenant, false);
        let devices = proofs(&db);
        let cmd = command(&db, &key, &pair, initial.tokens.refresh_token.clone());
        assert_eq!(
            svc.rotate_refresh(initial.tokens.refresh_token.clone()),
            Err(TenantAuthError::DeviceProofRequired)
        );
        assert!(service(&db, tenant, true)
            .rotate_refresh_with_proof(cmd.clone(), &devices)
            .is_err());
        assert_unused(&db, &cmd);
        assert_eq!(state(&db, &initial.session), ("active".into(), 1));
        let s = db.schema();
        db.adapter.connect().unwrap().batch_execute(&format!("create function {s}.fail_refresh_insert() returns trigger language plpgsql as $$ begin raise exception 'injected refresh insert failure'; end $$; create trigger fail_refresh_insert after insert on {s}.refresh_tokens for each row execute function {s}.fail_refresh_insert();")).unwrap();
        assert!(svc
            .rotate_refresh_with_proof(cmd.clone(), &devices)
            .is_err());
        assert_unused(&db, &cmd);
        assert_eq!(state(&db, &initial.session), ("active".into(), 1));
        assert_eq!(count(&db, "refresh_tokens"), 1);
        db.adapter
            .connect()
            .unwrap()
            .batch_execute(&format!(
                "drop trigger fail_refresh_insert on {s}.refresh_tokens"
            ))
            .unwrap();
        let TenantRefreshOutcome::Rotated { session, tokens } = svc
            .rotate_refresh_with_proof(cmd.clone(), &devices)
            .unwrap()
        else {
            panic!()
        };
        assert_eq!(session.refresh_token_version, 2);
        assert_eq!(tokens.refresh_expires_at, initial.session.expires_at);
        assert!(svc.authenticate(tokens.access_token.token.clone()).is_ok());
        // Replaying the same nonce is rejected; only a fresh valid proof confirms reuse.
        assert!(svc.rotate_refresh_with_proof(cmd, &devices).is_err());
        assert_eq!(state(&db, &session), ("active".into(), 2));
        let reuse = command(&db, &key, &pair, initial.tokens.refresh_token);
        let mut invalid = reuse.clone();
        invalid.proof.signature = Base64UrlUnpadded::encode_string(&[0; 64]);
        assert!(svc.rotate_refresh_with_proof(invalid, &devices).is_err());
        assert_unused(&db, &reuse);
        db.adapter.connect().unwrap().batch_execute(&format!("create function {s}.fail_reuse() returns trigger language plpgsql as $$ begin if NEW.revocation_reason='reuse_detected' then raise exception 'injected family failure'; end if; return NEW; end $$; create trigger fail_reuse after update on {s}.refresh_tokens for each row execute function {s}.fail_reuse();")).unwrap();
        assert!(svc
            .rotate_refresh_with_proof(reuse.clone(), &devices)
            .is_err());
        assert_unused(&db, &reuse);
        assert_eq!(state(&db, &session), ("active".into(), 2));
        assert!(svc.authenticate(tokens.access_token.token.clone()).is_ok());
        db.adapter
            .connect()
            .unwrap()
            .batch_execute(&format!("drop trigger fail_reuse on {s}.refresh_tokens"))
            .unwrap();
        assert_eq!(
            svc.rotate_refresh_with_proof(reuse, &devices),
            Ok(TenantRefreshOutcome::ReuseDetected {
                tenant_id: tenant.into(),
                session_id: session.id.clone()
            })
        );
        assert_eq!(state(&db, &session), ("revoked".into(), 2));
        assert!(svc.authenticate(tokens.access_token.token).is_err());
        let later = command(&db, &key, &pair, tokens.refresh_token);
        assert!(svc
            .rotate_refresh_with_proof(later.clone(), &devices)
            .is_err());
        assert_unused(&db, &later);
    }
}
#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn revoked_device_cannot_refresh_a_proof_bound_session_in_both_modes() {
    for (mode, tenant) in [(TenancyMode::Disabled, "0"), (TenancyMode::Enabled, "t1")] {
        let db = Db::new(mode);
        prepare(&db);
        let (key, pair, initial) = prepared(&db, tenant, 45);
        let refresh = command(&db, &key, &pair, initial.tokens.refresh_token);
        let s = db.schema();
        let mut connection = db.adapter.connect().unwrap();
        let mut tx = connection.transaction().unwrap();
        tx.query_one(
            &format!("select singleton from {s}.access_state where singleton for update"),
            &[],
        )
        .unwrap();
        let svc = service(&db, tenant, false);
        let devices = proofs(&db);
        let attempt = refresh.clone();
        let worker = std::thread::spawn(move || svc.rotate_refresh_with_proof(attempt, &devices));
        wait_for_auth_state_lock(&db);
        tx.execute(
            &format!("update {s}.devices set status='revoked' where tenant_id=$1 and id=$2"),
            &[&tenant, &Uuid::parse_str(&key.device_id).unwrap()],
        )
        .unwrap();
        // Keep the session/token live to prove the device check independently denies refresh.
        tx.commit().unwrap();
        assert!(worker.join().unwrap().is_err());
        assert_unused(&db, &refresh);
        assert_eq!(state(&db, &initial.session), ("active".into(), 1));
        assert_eq!(count(&db, "refresh_tokens"), 1);
    }
}
#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn tenant_refresh_cannot_transplant_credentials_devices_or_revoke_another_tenant() {
    let db = Db::new(TenancyMode::Enabled);
    prepare(&db);
    let (key, pair, first) = prepared(&db, "t1", 42);
    let (key2, pair2, other) = prepared(&db, "t2", 43);
    let devices = proofs(&db);
    let svc = service(&db, "t1", false);
    // A second legitimate session on the same device must not borrow this signature.
    let login = authentication_proof(
        &db,
        &key,
        &pair,
        TENANT_DEVICE_LOGIN_PURPOSE,
        tenant_password_proof_context("web", "refresh-test", &password()),
    );
    let second = password_session(svc.login_with_proof(password(), login, &devices).unwrap());
    let original = command(&db, &key, &pair, first.tokens.refresh_token.clone());
    let mut swapped = original.clone();
    swapped.refresh_token = second.tokens.refresh_token;
    assert!(svc.rotate_refresh_with_proof(swapped, &devices).is_err());
    assert_unused(&db, &original);
    assert!(service(&db, "t2", false)
        .rotate_refresh_with_proof(original.clone(), &devices)
        .is_err());
    assert_unused(&db, &original);
    let TenantRefreshOutcome::Rotated { session, .. } =
        svc.rotate_refresh_with_proof(original, &devices).unwrap()
    else {
        panic!()
    };
    // A real t2 device signature over a real old t1 token still cannot revoke t1.
    let cross = command(&db, &key2, &pair2, first.tokens.refresh_token.clone());
    assert!(svc
        .rotate_refresh_with_proof(cross.clone(), &devices)
        .is_err());
    assert_unused(&db, &cross);
    assert_eq!(state(&db, &session), ("active".into(), 2));
    let reuse = command(&db, &key, &pair, first.tokens.refresh_token);
    assert!(matches!(
        svc.rotate_refresh_with_proof(reuse, &devices),
        Ok(TenantRefreshOutcome::ReuseDetected { .. })
    ));
    assert_eq!(state(&db, &other.session), ("active".into(), 1));
    assert!(service(&db, "t2", false)
        .authenticate(other.tokens.access_token)
        .is_ok());
    assert!(svc.authenticate(second.tokens.access_token).is_ok());
}
#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn concurrent_refresh_distinguishes_nonce_replay_from_fresh_proven_reuse() {
    let db = Db::new(TenancyMode::Enabled);
    prepare(&db);
    let (key, pair, initial) = prepared(&db, "t1", 44);
    let cmd = command(&db, &key, &pair, initial.tokens.refresh_token);
    let run = |commands: Vec<RotateProofBoundRefreshCommand>| {
        let gate = Arc::new(Barrier::new(2));
        std::thread::scope(|scope| {
            let handles: Vec<_> = commands
                .into_iter()
                .map(|cmd| {
                    let gate = gate.clone();
                    let svc = service(&db, "t1", false);
                    let devices = proofs(&db);
                    scope.spawn(move || {
                        gate.wait();
                        svc.rotate_refresh_with_proof(cmd, &devices)
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|h| h.join().unwrap())
                .collect::<Vec<_>>()
        })
    };
    let results = run(vec![cmd.clone(), cmd]);
    assert_eq!(
        results
            .iter()
            .filter(|r| matches!(r, Ok(TenantRefreshOutcome::Rotated { .. })))
            .count(),
        1
    );
    assert_eq!(results.iter().filter(|r| r.is_err()).count(), 1);
    assert_eq!(state(&db, &initial.session), ("active".into(), 2));
    let raw = results
        .into_iter()
        .find_map(|r| match r {
            Ok(TenantRefreshOutcome::Rotated { tokens, .. }) => Some(tokens.refresh_token),
            _ => None,
        })
        .unwrap();
    let results = run(vec![
        command(&db, &key, &pair, raw.clone()),
        command(&db, &key, &pair, raw),
    ]);
    assert_eq!(
        results
            .iter()
            .filter(|r| matches!(r, Ok(TenantRefreshOutcome::Rotated { .. })))
            .count(),
        1
    );
    assert_eq!(
        results
            .iter()
            .filter(|r| matches!(r, Ok(TenantRefreshOutcome::ReuseDetected { .. })))
            .count(),
        1
    );
    assert_eq!(state(&db, &initial.session), ("revoked".into(), 3));
}
#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn member_revocation_committed_while_refresh_waits_prevents_issuance() {
    let db = Db::new(TenancyMode::Enabled);
    let account = prepare(&db);
    let (key, pair, initial) = prepared(&db, "t1", 45);
    let cmd = command(&db, &key, &pair, initial.tokens.refresh_token);
    let mut connection = db.adapter.connect().unwrap();
    let mut block = connection.transaction().unwrap();
    let s = db.schema();
    block
        .query_one(
            &format!("select id from {s}.access_tenants where id='t1' for update"),
            &[],
        )
        .unwrap();
    block.execute(&format!("update {s}.access_memberships set status='suspended' where tenant_id='t1' and account_id=$1"),&[&Uuid::parse_str(&account).unwrap()]).unwrap();
    std::thread::scope(|scope| {
        let svc = service(&db, "t1", false);
        let devices = proofs(&db);
        let request = cmd.clone();
        let handle = scope.spawn(move || svc.rotate_refresh_with_proof(request, &devices));
        let mut observer = db.adapter.connect().unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            let waiting:bool=observer.query_one("select exists(select 1 from pg_stat_activity where application_name='idp-registration-test' and wait_event_type='Lock' and query like $1)",&[&format!("%{s}.access_tenants%")]).unwrap().get(0);
            if waiting {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "refresh did not reach the domain lock"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        block.commit().unwrap();
        assert!(handle.join().unwrap().is_err());
    });
    assert_unused(&db, &cmd);
    assert_eq!(state(&db, &initial.session), ("active".into(), 1));
    assert_eq!(count(&db, "refresh_tokens"), 1);
}
