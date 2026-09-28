use super::*;
use base64ct::{Base64UrlUnpadded, Encoding};
use embedded_idp_core::{
    build_device_key_rotation_proof_bytes, build_device_registration_proof_bytes,
    build_request_proof_bytes, CanonicalHttpMethod, DeviceProofKeyStatus, DeviceProofPresentation,
    DeviceProofProfile, DeviceProofPurpose, DeviceRequestBinding, DEVICE_KEY_ROTATION_PURPOSE,
    DEVICE_REGISTRATION_PURPOSE,
};
use embedded_idp_security::{
    Ed25519PublicJwkParser, RingEd25519Verifier, SecureDeviceChallengeGenerator,
};
use ring::{
    digest::{digest, SHA256},
    signature::{Ed25519KeyPair, KeyPair},
};

type Proofs = CoreTenantDeviceProofService<
    PostgresAccessStore,
    Ed25519PublicJwkParser,
    RingEd25519Verifier,
    SecureDeviceChallengeGenerator,
    TestClock,
    UuidV7IdGenerator,
>;
fn proofs(db: &Db) -> Proofs {
    CoreTenantDeviceProofService::new(
        db.mode,
        TenantDeviceProofConfig {
            client_id: "web".into(),
            allowed_purposes: [
                "report_read",
                DEVICE_REGISTRATION_PURPOSE,
                DEVICE_KEY_ROTATION_PURPOSE,
                TENANT_DEVICE_LOGIN_PURPOSE,
                TENANT_DEVICE_SELECTION_PURPOSE,
                embedded_idp_core::REFRESH_PURPOSE,
                TENANT_OIDC_EXCHANGE_PURPOSE,
                TENANT_DEVICE_HEARTBEAT_PURPOSE,
            ]
            .into_iter()
            .map(|p| DeviceProofPurpose::new(p).unwrap())
            .collect(),
            challenge_ttl_secs: 60,
            clock_skew_secs: 30,
        },
        db.store(),
        Ed25519PublicJwkParser,
        RingEd25519Verifier,
        SecureDeviceChallengeGenerator,
        TestClock,
        UuidV7IdGenerator,
    )
    .unwrap()
}
fn device(db: &Db, tenant: &str, account: &str, id: Uuid) -> (String, String, Ed25519KeyPair) {
    // Public synthetic test seed; a new logical device/key in each tenant.
    let seed = if tenant == "t2" { [8; 32] } else { [7; 32] };
    let pair = Ed25519KeyPair::from_seed_unchecked(&seed).unwrap();
    let x = Base64UrlUnpadded::encode_string(pair.public_key().as_ref());
    let thumb = format!(r#"{{"crv":"Ed25519","kty":"OKP","x":"{x}"}}"#);
    let kid = Base64UrlUnpadded::encode_string(digest(&SHA256, thumb.as_bytes()).as_ref());
    let jwk = serde_json::json!({"kty":"OKP","crv":"Ed25519","x":x,"kid":kid}).to_string();
    let account = Uuid::parse_str(account).unwrap();
    let s = db.schema();
    let mut conn = db.adapter.connect().unwrap();
    let mut tx = conn.transaction().unwrap();
    tx.execute(&format!("insert into {s}.devices(tenant_id,id,client_id,device_name,proof_key_id,status,registered_at_epoch) values($1,$2,'web','Test',$3,'active',100)"),&[&tenant,&id,&kid]).unwrap();
    tx.execute(&format!("insert into {s}.device_proof_keys(tenant_id,key_id,device_id,algorithm,public_jwk,version,status,registered_at_epoch) values($1,$2,$3,'ed25519',$4,1,'active',100)"),&[&tenant,&kid,&id,&jwk]).unwrap();
    tx.execute(&format!("insert into {s}.account_device_bindings(tenant_id,id,account_id,device_id,status,bound_at_epoch) values($1,$2,$3,$4,'active',100)"),&[&tenant,&Uuid::now_v7(),&account,&id]).unwrap();
    tx.commit().unwrap();
    (id.to_string(), kid, pair)
}
fn command(
    db: &Db,
    actor: AccessActor,
    device: &str,
    kid: &str,
    key: &Ed25519KeyPair,
) -> VerifyTenantDeviceRequest {
    let purpose = DeviceProofPurpose::new("report_read").unwrap();
    let nonce = proofs(db)
        .issue_challenge(&actor.tenant_id, device, purpose.clone())
        .unwrap();
    let binding = DeviceRequestBinding::new(
        &actor.tenant_id,
        DeviceProofProfile::new("EMBEDDED-IDP-DEVICE-REQUEST-V2").unwrap(),
        "test-api",
        CanonicalHttpMethod::Get,
        "/api/reports",
        [0; 32],
    )
    .unwrap();
    let mut proof = DeviceProofPresentation {
        device_id: device.into(),
        key_id: kid.into(),
        challenge: nonce.challenge.into_exposed(),
        signature: Base64UrlUnpadded::encode_string(&[0; 64]),
        signed_at: TestClock.now(),
    };
    proof.signature = Base64UrlUnpadded::encode_string(
        key.sign(&build_request_proof_bytes(&binding, &proof).unwrap())
            .as_ref(),
    );
    VerifyTenantDeviceRequest {
        actor,
        expected_purpose: purpose,
        proof,
        binding,
    }
}
fn actor(db: &Db, tenant: &str) -> AccessActor {
    let svc = auth(
        db,
        LoginTenantPolicy::Fixed {
            tenant_id: tenant.into(),
        },
        "device-test",
        false,
        false,
    );
    let TenantLoginOutcome::Authenticated(out) = svc.login(password()).unwrap() else {
        panic!()
    };
    svc.authenticate(out.tokens.access_token).unwrap()
}
fn unused(db: &Db, command: &VerifyTenantDeviceRequest) -> bool {
    let digest = embedded_idp_core::digest_device_challenge(&command.proof.challenge).unwrap();
    db.adapter
        .connect()
        .unwrap()
        .query_one(
            &format!(
                "select consumed_at_epoch is null from {}.device_nonces where challenge_digest=$1",
                db.schema()
            ),
            &[&&digest[..]],
        )
        .unwrap()
        .get(0)
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn tenant_proofs_verify_real_ed25519_once_in_both_modes() {
    for mode in [TenancyMode::Disabled, TenancyMode::Enabled] {
        let db = Db::new(mode);
        let account = prepare(&db);
        let tenant = if mode == TenancyMode::Enabled {
            "t1"
        } else {
            "0"
        };
        let (device, kid, key) = device(&db, tenant, &account, Uuid::now_v7());
        let cmd = command(&db, actor(&db, tenant), &device, &kid, &key);
        let result = proofs(&db).verify_request(cmd.clone()).unwrap();
        assert_eq!(result.tenant_id, tenant);
        assert_eq!(result.account_id, account);
        assert!(!unused(&db, &cmd));
        assert!(proofs(&db).verify_request(cmd).is_err());
    }
}
#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn tenant_proofs_reject_cross_tenant_and_revoked_members_without_nonce_consumption() {
    let db = Db::new(TenancyMode::Enabled);
    let account = prepare(&db);
    let (d1, k1, key1) = device(&db, "t1", &account, Uuid::now_v7());
    // Deliberately collide the local ID across tenants to exercise composite scope.
    let (d2, k2, key2) = device(&db, "t2", &account, Uuid::parse_str(&d1).unwrap());
    let c1 = command(&db, actor(&db, "t1"), &d1, &k1, &key1);
    let c2 = command(&db, actor(&db, "t2"), &d2, &k2, &key2);
    let mut swapped = c1.clone();
    swapped.actor = c2.actor.clone();
    swapped.binding.tenant_id = "t2".into();
    assert!(proofs(&db).verify_request(swapped).is_err());
    let mut swapped = c2.clone();
    swapped.proof.challenge = c1.proof.challenge.clone();
    swapped.proof.signature = Base64UrlUnpadded::encode_string(
        key2.sign(&build_request_proof_bytes(&swapped.binding, &swapped.proof).unwrap())
            .as_ref(),
    );
    assert!(proofs(&db).verify_request(swapped).is_err());
    let mut tampered = c1.clone();
    tampered.proof.signature = Base64UrlUnpadded::encode_string(&[9; 64]);
    assert!(proofs(&db).verify_request(tampered).is_err());
    assert!(unused(&db, &c1));
    assert!(unused(&db, &c2));
    db.adapter.connect().unwrap().execute(&format!("update {}.access_memberships set status='suspended' where tenant_id='t1' and account_id=$1",db.schema()),&[&Uuid::parse_str(&account).unwrap()]).unwrap();
    assert!(proofs(&db).verify_request(c1.clone()).is_err());
    assert!(unused(&db, &c1));
    assert!(proofs(&db).verify_request(c2).is_ok());
}
#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn tenant_proof_consume_failure_rolls_back_and_concurrent_replay_has_one_winner() {
    let db = Db::new(TenancyMode::Enabled);
    let account = prepare(&db);
    let (d, k, key) = device(&db, "t1", &account, Uuid::now_v7());
    let cmd = command(&db, actor(&db, "t1"), &d, &k, &key);
    let s = db.schema();
    db.adapter.connect().unwrap().batch_execute(&format!("create function {s}.fail_nonce() returns trigger language plpgsql as $$ begin raise exception 'injected test failure'; end $$; create trigger fail_nonce after update on {s}.device_nonces for each row execute function {s}.fail_nonce();")).unwrap();
    assert!(matches!(
        proofs(&db).verify_request(cmd.clone()),
        Err(TenantAuthError::Store(_))
    ));
    assert!(unused(&db, &cmd));
    db.adapter
        .connect()
        .unwrap()
        .batch_execute(&format!("drop trigger fail_nonce on {s}.device_nonces"))
        .unwrap();
    let barrier = Arc::new(Barrier::new(2));
    let results = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..2)
            .map(|_| {
                let gate = barrier.clone();
                let request = cmd.clone();
                let service = proofs(&db);
                scope.spawn(move || {
                    gate.wait();
                    service.verify_request(request).is_ok()
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().unwrap())
            .filter(|ok| *ok)
            .count()
    });
    assert_eq!(results, 1);
    assert!(!unused(&db, &cmd));
}

struct AdmitTenant<'a>(&'a str);
impl TenantDeviceAdmission for AdmitTenant<'_> {
    fn authorize(
        &self,
        tenant: &str,
        client: &str,
        _: &str,
        _: DeviceAdmissionAction,
        _: &TrustedDeviceAdmission,
    ) -> Result<(), AccessError> {
        if tenant == self.0 && client == "web" {
            Ok(())
        } else {
            Err(AccessError::Forbidden)
        }
    }
}
fn trusted() -> TrustedDeviceAdmission {
    TrustedDeviceAdmission {
        registration_scope: "test_scope".into(),
        valid_until: SystemTime::now() + Duration::from_secs(3600),
    }
}
fn provision(
    tenant: &str,
    device_id: Uuid,
    request_id: Uuid,
    jwk: String,
) -> ProvisionTenantDevice {
    ProvisionTenantDevice {
        tenant_id: tenant.into(),
        device_id: device_id.to_string(),
        registration_request_id: request_id.to_string(),
        device_name: "Laptop".into(),
        public_jwk: jwk,
    }
}
fn material(seed: u8) -> (String, String, Ed25519KeyPair) {
    let pair = Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).unwrap();
    let x = Base64UrlUnpadded::encode_string(pair.public_key().as_ref());
    let thumb = format!(r#"{{"crv":"Ed25519","kty":"OKP","x":"{x}"}}"#);
    let kid = Base64UrlUnpadded::encode_string(digest(&SHA256, thumb.as_bytes()).as_ref());
    let jwk = serde_json::json!({"kty":"OKP","crv":"Ed25519","x":x,"kid":kid}).to_string();
    (jwk, kid, pair)
}
fn registration(
    db: &Db,
    tenant: &str,
    seed: u8,
) -> (CompleteTenantDeviceRegistration, Ed25519KeyPair) {
    let svc = proofs(db);
    let (jwk, kid, pair) = material(seed);
    let pending = svc
        .provision_device(
            provision(tenant, Uuid::now_v7(), Uuid::now_v7(), jwk.clone()),
            &trusted(),
            &AdmitTenant(tenant),
        )
        .unwrap();
    let challenge = svc
        .issue_challenge(
            tenant,
            &pending.device.id,
            DeviceProofPurpose::new(DEVICE_REGISTRATION_PURPOSE).unwrap(),
        )
        .unwrap();
    let bytes = build_device_registration_proof_bytes(
        tenant,
        &pending.device.id,
        &kid,
        challenge.challenge.expose_secret(),
    )
    .unwrap();
    (
        CompleteTenantDeviceRegistration {
            tenant_id: tenant.into(),
            device_id: pending.device.id,
            public_jwk: jwk,
            challenge: challenge.challenge,
            signature: SecretString::new(Base64UrlUnpadded::encode_string(
                pair.sign(&bytes).as_ref(),
            )),
        },
        pair,
    )
}
fn rotation(
    db: &Db,
    actor: AccessActor,
    current: &TenantProofKey,
    old: &Ed25519KeyPair,
    seed: u8,
) -> (RotateTenantDeviceKey, Ed25519KeyPair) {
    let (jwk, kid, new) = material(seed);
    let nonce = proofs(db)
        .issue_challenge(
            &actor.tenant_id,
            &current.device_id,
            DeviceProofPurpose::new(DEVICE_KEY_ROTATION_PURPOSE).unwrap(),
        )
        .unwrap();
    let bytes = build_device_key_rotation_proof_bytes(
        &actor.tenant_id,
        &current.device_id,
        &current.key_id,
        &kid,
        current.version + 1,
        nonce.challenge.expose_secret(),
    )
    .unwrap();
    (
        RotateTenantDeviceKey {
            actor,
            device_id: current.device_id.clone(),
            expected_key_id: current.key_id.clone(),
            expected_key_version: current.version,
            proposed_public_jwk: jwk,
            challenge: nonce.challenge,
            current_key_signature: SecretString::new(Base64UrlUnpadded::encode_string(
                old.sign(&bytes).as_ref(),
            )),
            proposed_key_signature: SecretString::new(Base64UrlUnpadded::encode_string(
                new.sign(&bytes).as_ref(),
            )),
        },
        new,
    )
}
fn nonce_unused(db: &Db, challenge: &SecretString) -> bool {
    let d = embedded_idp_core::digest_device_challenge(challenge.expose_secret()).unwrap();
    db.adapter
        .connect()
        .unwrap()
        .query_one(
            &format!(
                "select consumed_at_epoch is null from {}.device_nonces where challenge_digest=$1",
                db.schema()
            ),
            &[&&d[..]],
        )
        .unwrap()
        .get(0)
}

fn wait_for_auth_state_lock(db: &Db) {
    let mut observer = db.adapter.connect().unwrap();
    let schema = db.schema();
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        let waiting: bool = observer.query_one(
            "select exists(select 1 from pg_stat_activity where application_name='idp-registration-test' and wait_event_type='Lock' and query like $1)",
            &[&format!("%{schema}.access_state%")],
        ).unwrap().get(0);
        if waiting {
            return;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "authentication did not reach the state lock"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}
#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn provision_and_registration_enforce_admission_and_activate_atomically_in_both_modes() {
    for (mode, tenant) in [(TenancyMode::Disabled, "0"), (TenancyMode::Enabled, "t1")] {
        let db = Db::new(mode);
        prepare(&db);
        let service = proofs(&db);
        assert!(matches!(
            service.provision_device(
                provision(tenant, Uuid::now_v7(), Uuid::now_v7(), material(21).0),
                &trusted(),
                &AdmitTenant("other")
            ),
            Err(TenantAuthError::Access(AccessError::Forbidden))
        ));
        assert_eq!(count(&db, "devices"), 0);
        let (cmd, _) = registration(&db, tenant, 21);
        assert!(matches!(
            service.provision_device(
                provision(tenant, Uuid::now_v7(), Uuid::now_v7(), material(21).0),
                &trusted(),
                &AdmitTenant(tenant),
            ),
            Err(TenantAuthError::Access(AccessError::Conflict("device_key")))
        ));
        assert_eq!(count(&db, "devices"), 1);
        let s = db.schema();
        let mut bad = cmd.clone();
        bad.signature = SecretString::new(Base64UrlUnpadded::encode_string(&[0; 64]));
        assert!(service.complete_registration(bad).is_err());
        assert!(nonce_unused(&db, &cmd.challenge));
        db.adapter.connect().unwrap().batch_execute(&format!("create function {s}.fail_activation() returns trigger language plpgsql as $$ begin raise exception 'injected activation failure'; end $$; create trigger fail_activation after update on {s}.devices for each row execute function {s}.fail_activation();")).unwrap();
        assert!(service.complete_registration(cmd.clone()).is_err());
        assert!(nonce_unused(&db, &cmd.challenge));
        assert_eq!(count(&db, "device_proof_keys"), 0);
        db.adapter
            .connect()
            .unwrap()
            .batch_execute(&format!("drop trigger fail_activation on {s}.devices"))
            .unwrap();
        let key = service.complete_registration(cmd.clone()).unwrap();
        assert_eq!(key.tenant_id, tenant);
        assert_eq!(key.version, 1);
        assert!(!nonce_unused(&db, &cmd.challenge));
        assert!(service.complete_registration(cmd.clone()).is_err());
        let row = db
            .adapter
            .connect()
            .unwrap()
            .query_one(
                &format!(
                    "select status,proof_key_id from {s}.devices where tenant_id=$1 and id=$2"
                ),
                &[&tenant, &Uuid::parse_str(&cmd.device_id).unwrap()],
            )
            .unwrap();
        assert_eq!(row.get::<_, String>(0), "active");
        assert_eq!(row.get::<_, String>(1), key.key_id);
        assert_eq!(count(&db, "account_device_bindings"), 0);
        assert_eq!(count(&db, "auth_sessions"), 0);
    }
}
#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn rotation_verifies_both_keys_preserves_old_authority_on_failure_and_retires_on_success() {
    let db = Db::new(TenancyMode::Enabled);
    let account = prepare(&db);
    let svc = proofs(&db);
    let (registration, old) = registration(&db, "t1", 22);
    let current = svc.complete_registration(registration).unwrap();
    let login = auth(
        &db,
        LoginTenantPolicy::Fixed {
            tenant_id: "t1".into(),
        },
        "proof-login",
        true,
        false,
    );
    let proof = authentication_proof(
        &db,
        &current,
        &old,
        TENANT_DEVICE_LOGIN_PURPOSE,
        tenant_password_proof_context("web", "proof-login", &password()),
    );
    let TenantLoginOutcome::Authenticated(session) =
        login.login_with_proof(password(), proof, &svc).unwrap()
    else {
        panic!()
    };
    let actor = login.authenticate(session.tokens.access_token).unwrap();
    assert_eq!(actor.subject_id, account);
    let old_request = command(
        &db,
        actor.clone(),
        &current.device_id,
        &current.key_id,
        &old,
    );
    let (cmd, new) = rotation(&db, actor.clone(), &current, &old, 23);
    let mut stale_expected = cmd.clone();
    stale_expected.expected_key_version = 99;
    assert!(matches!(
        svc.rotate_key(stale_expected),
        Err(TenantAuthError::Access(AccessError::Conflict(
            "device_key_changed"
        )))
    ));
    assert!(nonce_unused(&db, &cmd.challenge));
    for bad_old in [false, true] {
        let mut bad = cmd.clone();
        let sig = SecretString::new(Base64UrlUnpadded::encode_string(&[0; 64]));
        if bad_old {
            bad.current_key_signature = sig
        } else {
            bad.proposed_key_signature = sig
        }
        assert!(svc.rotate_key(bad).is_err());
        assert!(nonce_unused(&db, &cmd.challenge));
    }
    let mut wrong_tenant = cmd.clone();
    wrong_tenant.actor.tenant_id = "t2".into();
    assert!(svc.rotate_key(wrong_tenant).is_err());
    assert!(nonce_unused(&db, &cmd.challenge));
    let s = db.schema();
    db.adapter.connect().unwrap().batch_execute(&format!("create function {s}.fail_rotation() returns trigger language plpgsql as $$ begin raise exception 'injected rotation failure'; end $$; create trigger fail_rotation after insert on {s}.device_proof_keys for each row execute function {s}.fail_rotation();")).unwrap();
    assert!(svc.rotate_key(cmd.clone()).is_err());
    assert!(nonce_unused(&db, &cmd.challenge));
    assert_eq!(count(&db, "device_proof_keys"), 1);
    // A failed rotation must leave the old key fully usable.
    assert!(svc.verify_request(old_request).is_ok());
    db.adapter
        .connect()
        .unwrap()
        .batch_execute(&format!(
            "drop trigger fail_rotation on {s}.device_proof_keys"
        ))
        .unwrap();
    db.adapter.connect().unwrap().batch_execute(&format!("create function {s}.fail_rotation_audit() returns trigger language plpgsql as $$ begin raise exception 'injected rotation audit failure'; end $$; create trigger fail_rotation_audit before insert on {s}.access_audit_events for each row execute function {s}.fail_rotation_audit();")).unwrap();
    assert!(svc.rotate_key(cmd.clone()).is_err());
    assert!(nonce_unused(&db, &cmd.challenge));
    assert_eq!(count(&db, "device_proof_keys"), 1);
    db.adapter
        .connect()
        .unwrap()
        .batch_execute(&format!(
            "drop trigger fail_rotation_audit on {s}.access_audit_events"
        ))
        .unwrap();
    let stale = command(
        &db,
        actor.clone(),
        &current.device_id,
        &current.key_id,
        &old,
    );
    let next = svc.rotate_key(cmd.clone()).unwrap();
    assert_eq!(next.version, 2);
    let rotation_audit: i64 = db.adapter.connect().unwrap().query_one(&format!("select count(*) from {s}.access_audit_events where operation='device.key.rotate' and actor_id=$1 and actor_session_id=$2 and authentication_source='device_session'"), &[&Uuid::parse_str(&actor.subject_id).unwrap(),&Uuid::parse_str(&actor.session_id).unwrap()]).unwrap().get(0);
    assert_eq!(rotation_audit, 1);
    assert!(!nonce_unused(&db, &cmd.challenge));
    assert!(svc.verify_request(stale.clone()).is_err());
    assert!(unused(&db, &stale));
    assert!(svc
        .verify_request(command(
            &db,
            actor.clone(),
            &next.device_id,
            &next.key_id,
            &new
        ))
        .is_ok());
    assert!(svc.rotate_key(cmd).is_err());
    assert_eq!(
        db.adapter
            .connect()
            .unwrap()
            .query_one(
                &format!("select status from {s}.device_proof_keys where key_id=$1"),
                &[&current.key_id]
            )
            .unwrap()
            .get::<_, String>(0),
        "retired"
    );
    let (second_rotation, newest_pair) = rotation(&db, actor.clone(), &next, &new, 25);
    let newest = svc.rotate_key(second_rotation).unwrap();
    assert_eq!(newest.version, 3);
    assert_eq!(
        svc.subject_device_key_metadata(actor.clone(), &next.device_id, &next.key_id)
            .unwrap()
            .status,
        DeviceProofKeyStatus::Retired
    );
    assert_eq!(
        svc.subject_device_key_metadata(actor.clone(), &newest.device_id, &newest.key_id)
            .unwrap()
            .status,
        DeviceProofKeyStatus::Active
    );
    assert!(svc
        .verify_request(command(
            &db,
            actor,
            &newest.device_id,
            &newest.key_id,
            &newest_pair
        ))
        .is_ok());
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn concurrent_rotations_install_only_one_key_and_audit_once_in_both_modes() {
    for (mode, tenant) in [(TenancyMode::Disabled, "0"), (TenancyMode::Enabled, "t1")] {
        let db = Db::new(mode);
        prepare(&db);
        let svc = proofs(&db);
        let (registration, old_pair) = registration(&db, tenant, 42);
        let current = svc.complete_registration(registration).unwrap();
        let login = auth(
            &db,
            LoginTenantPolicy::Fixed {
                tenant_id: tenant.into(),
            },
            "proof-login",
            true,
            false,
        );
        let proof = authentication_proof(
            &db,
            &current,
            &old_pair,
            TENANT_DEVICE_LOGIN_PURPOSE,
            tenant_password_proof_context("web", "proof-login", &password()),
        );
        let session = password_session(login.login_with_proof(password(), proof, &svc).unwrap());
        let actor = login.authenticate(session.tokens.access_token).unwrap();
        let first = rotation(&db, actor.clone(), &current, &old_pair, 43).0;
        let second = rotation(&db, actor, &current, &old_pair, 44).0;
        let gate = Arc::new(Barrier::new(2));
        let outcomes = std::thread::scope(|scope| {
            let handles: Vec<_> = [first.clone(), second.clone()]
                .into_iter()
                .map(|request| {
                    let gate = gate.clone();
                    let service = proofs(&db);
                    scope.spawn(move || {
                        gate.wait();
                        service.rotate_key(request)
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|handle| handle.join().unwrap())
                .collect::<Vec<_>>()
        });
        assert_eq!(outcomes.iter().filter(|result| result.is_ok()).count(), 1);
        assert!(outcomes.iter().any(|result| matches!(
            result,
            Err(TenantAuthError::Access(AccessError::Conflict(
                "device_key_changed"
            )))
        )));
        let s = db.schema();
        let row = db.adapter.connect().unwrap().query_one(&format!("select (select count(*) from {s}.device_proof_keys where tenant_id=$1 and device_id=$2 and status='active'),(select count(*) from {s}.access_audit_events where operation='device.key.rotate'),(select version from {s}.devices where tenant_id=$1 and id=$2)"), &[&tenant,&Uuid::parse_str(&current.device_id).unwrap()]).unwrap();
        assert_eq!(row.get::<_, i64>(0), 1);
        assert_eq!(row.get::<_, i64>(1), 1);
        assert_eq!(row.get::<_, i64>(2), 3);
        assert_ne!(
            nonce_unused(&db, &first.challenge),
            nonce_unused(&db, &second.challenge)
        );
    }
}
#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn concurrent_completion_has_one_winner_and_global_key_reuse_is_rejected_at_provision() {
    let db = Db::new(TenancyMode::Enabled);
    prepare(&db);
    let (cmd, _) = registration(&db, "t1", 24);
    let gate = Arc::new(Barrier::new(2));
    let wins = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..2)
            .map(|_| {
                let g = gate.clone();
                let request = cmd.clone();
                let service = proofs(&db);
                scope.spawn(move || {
                    g.wait();
                    service.complete_registration(request).is_ok()
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().unwrap())
            .filter(|ok| *ok)
            .count()
    });
    assert_eq!(wins, 1);
    assert_eq!(count(&db, "device_proof_keys"), 1);
    // Key reservation rejects the same key before a second logical device is created.
    assert!(matches!(
        proofs(&db).provision_device(
            provision("t2", Uuid::now_v7(), Uuid::now_v7(), material(24).0),
            &trusted(),
            &AdmitTenant("t2"),
        ),
        Err(TenantAuthError::Access(AccessError::Conflict("device_key")))
    ));
    assert_eq!(count(&db, "devices"), 1);
    assert_eq!(count(&db, "device_proof_keys"), 1);
}

fn authentication_proof(
    db: &Db,
    key: &TenantProofKey,
    pair: &Ed25519KeyPair,
    purpose: &str,
    context: [u8; 32],
) -> TenantAuthenticationProof {
    let challenge = proofs(db)
        .issue_challenge(
            &key.tenant_id,
            &key.device_id,
            DeviceProofPurpose::new(purpose).unwrap(),
        )
        .unwrap();
    // Trusted route/body metadata, as a host HTTP adapter would reconstruct it.
    let binding = DeviceRequestBinding::new(
        &key.tenant_id,
        DeviceProofProfile::new(TENANT_DEVICE_AUTH_PROFILE).unwrap(),
        "test-api",
        CanonicalHttpMethod::Post,
        if purpose == TENANT_DEVICE_LOGIN_PURPOSE {
            "/auth/login"
        } else if purpose == TENANT_OIDC_EXCHANGE_PURPOSE {
            "/oidc/token"
        } else if purpose == embedded_idp_core::REFRESH_PURPOSE {
            "/auth/refresh"
        } else {
            "/auth/tenant-selection/complete"
        },
        digest(&SHA256, b"synthetic request body")
            .as_ref()
            .try_into()
            .unwrap(),
    )
    .unwrap();
    let mut proof = DeviceProofPresentation {
        device_id: key.device_id.clone(),
        key_id: key.key_id.clone(),
        challenge: challenge.challenge.into_exposed(),
        signature: Base64UrlUnpadded::encode_string(&[0; 64]),
        signed_at: TestClock.now(),
    };
    proof.signature = Base64UrlUnpadded::encode_string(
        pair.sign(&build_tenant_authentication_proof_bytes(&binding, &proof, &context).unwrap())
            .as_ref(),
    );
    TenantAuthenticationProof { proof, binding }
}
fn password_session(outcome: TenantLoginOutcome) -> TenantLoginSession {
    let TenantLoginOutcome::Authenticated(session) = outcome else {
        panic!("expected a device session")
    };
    session
}
#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn proof_login_binds_and_issues_atomically_in_both_modes_and_rechecks_device_authority() {
    for (mode, tenant) in [(TenancyMode::Disabled, "0"), (TenancyMode::Enabled, "t1")] {
        let db = Db::new(mode);
        prepare(&db);
        let devices = proofs(&db);
        let (registration, pair) = registration(&db, tenant, 31);
        let key = devices.complete_registration(registration).unwrap();
        let policy = LoginTenantPolicy::Fixed {
            tenant_id: tenant.into(),
        };
        let service = auth(&db, policy.clone(), "proof-login", true, false);
        assert_eq!(
            service.login(password()),
            Err(TenantAuthError::DeviceProofRequired)
        );
        let context = tenant_password_proof_context("web", "proof-login", &password());
        let proof = authentication_proof(&db, &key, &pair, TENANT_DEVICE_LOGIN_PURPOSE, context);
        let nonce = SecretString::new(proof.proof.challenge.clone());
        let mut bad = proof.clone();
        bad.binding.external_path = "/wrong".into();
        assert!(service.login_with_proof(password(), bad, &devices).is_err());
        let mut bad = proof.clone();
        bad.proof.signature = Base64UrlUnpadded::encode_string(&[0; 64]);
        assert!(service.login_with_proof(password(), bad, &devices).is_err());
        let mut wrong = password();
        wrong.password = SecretString::new("wrong-password");
        assert!(service
            .login_with_proof(wrong, proof.clone(), &devices)
            .is_err());
        let other_entry = auth(&db, policy.clone(), "other-entry", true, false);
        assert!(other_entry
            .login_with_proof(password(), proof.clone(), &devices)
            .is_err());
        let failed_issuer = auth(&db, policy, "proof-login", true, true);
        assert!(failed_issuer
            .login_with_proof(password(), proof.clone(), &devices)
            .is_err());
        assert!(nonce_unused(&db, &nonce));
        assert_eq!(count(&db, "account_device_bindings"), 0);
        let s = db.schema();
        db.adapter.connect().unwrap().batch_execute(&format!("create function {s}.fail_binding_audit() returns trigger language plpgsql as $$ begin if new.operation='device.binding.create' then raise exception 'injected binding audit failure'; end if; return new; end $$; create trigger fail_binding_audit before insert on {s}.access_audit_events for each row execute function {s}.fail_binding_audit();")).unwrap();
        assert!(service
            .login_with_proof(password(), proof.clone(), &devices)
            .is_err());
        assert!(nonce_unused(&db, &nonce));
        assert_eq!(count(&db, "account_device_bindings"), 0);
        assert_eq!(count(&db, "auth_sessions"), 0);
        db.adapter
            .connect()
            .unwrap()
            .batch_execute(&format!(
                "drop trigger fail_binding_audit on {s}.access_audit_events"
            ))
            .unwrap();
        db.adapter.connect().unwrap().batch_execute(&format!("create function {s}.fail_device_login() returns trigger language plpgsql as $$ begin raise exception 'injected refresh write failure'; end $$; create trigger fail_device_login after insert on {s}.refresh_tokens for each row execute function {s}.fail_device_login();")).unwrap();
        assert!(service
            .login_with_proof(password(), proof.clone(), &devices)
            .is_err());
        assert!(nonce_unused(&db, &nonce));
        assert_eq!(count(&db, "account_device_bindings"), 0);
        assert_eq!(count(&db, "auth_sessions"), 0);
        assert_eq!(count(&db, "refresh_tokens"), 0);
        db.adapter
            .connect()
            .unwrap()
            .batch_execute(&format!(
                "drop trigger fail_device_login on {s}.refresh_tokens"
            ))
            .unwrap();
        let session = password_session(
            service
                .login_with_proof(password(), proof.clone(), &devices)
                .unwrap(),
        );
        assert_eq!(session.session.tenant_id, tenant);
        assert_eq!(
            session.session.device_id.as_deref(),
            Some(key.device_id.as_str())
        );
        assert!(service
            .authenticate(session.tokens.access_token.clone())
            .is_ok());
        assert_eq!(count(&db, "account_device_bindings"), 1);
        assert_eq!(count(&db, "refresh_tokens"), 1);
        let binding_audit = db.adapter.connect().unwrap().query_one(&format!("select actor_id,actor_session_id,authentication_source,change_json::text from {s}.access_audit_events where operation='device.binding.create'"), &[]).unwrap();
        assert_eq!(
            binding_audit.get::<_, Uuid>(0).to_string(),
            session.session.account_id
        );
        assert_eq!(
            binding_audit.get::<_, Uuid>(1).to_string(),
            session.session.id
        );
        assert_eq!(binding_audit.get::<_, String>(2), "device_session");
        let audit_change: String = binding_audit.get(3);
        assert!(!audit_change.contains("public_jwk"));
        assert!(!audit_change.contains("signature"));
        assert!(!nonce_unused(&db, &nonce));
        assert!(service
            .login_with_proof(password(), proof, &devices)
            .is_err());
        db.adapter
            .connect()
            .unwrap()
            .execute(
                &format!("update {s}.devices set status='disabled' where tenant_id=$1"),
                &[&tenant],
            )
            .unwrap();
        assert!(service
            .authenticate(session.tokens.access_token.clone())
            .is_err());
        db.adapter
            .connect()
            .unwrap()
            .execute(
                &format!("update {s}.devices set status='active' where tenant_id=$1"),
                &[&tenant],
            )
            .unwrap();
        db.adapter
            .connect()
            .unwrap()
            .execute(
                &format!(
                    "update {s}.account_device_bindings set status='suspended' where tenant_id=$1"
                ),
                &[&tenant],
            )
            .unwrap();
        assert!(service.authenticate(session.tokens.access_token).is_err());
        let fresh = authentication_proof(&db, &key, &pair, TENANT_DEVICE_LOGIN_PURPOSE, context);
        assert!(service
            .login_with_proof(password(), fresh.clone(), &devices)
            .is_err());
        assert!(nonce_unused(&db, &SecretString::new(fresh.proof.challenge)));
    }
}
#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn revoked_device_cannot_complete_proof_login_in_both_modes() {
    for (mode, tenant) in [(TenancyMode::Disabled, "0"), (TenancyMode::Enabled, "t1")] {
        let db = Db::new(mode);
        prepare(&db);
        let devices = proofs(&db);
        let (registration, pair) = registration(&db, tenant, 43);
        let key = devices.complete_registration(registration).unwrap();
        let login = auth(
            &db,
            LoginTenantPolicy::Fixed {
                tenant_id: tenant.into(),
            },
            "proof-login",
            true,
            false,
        );
        let proof = authentication_proof(
            &db,
            &key,
            &pair,
            TENANT_DEVICE_LOGIN_PURPOSE,
            tenant_password_proof_context("web", "proof-login", &password()),
        );
        let nonce = SecretString::new(proof.proof.challenge.clone());
        let s = db.schema();
        let mut connection = db.adapter.connect().unwrap();
        let mut tx = connection.transaction().unwrap();
        tx.query_one(
            &format!("select singleton from {s}.access_state where singleton for update"),
            &[],
        )
        .unwrap();
        let worker =
            std::thread::spawn(move || login.login_with_proof(password(), proof, &devices));
        wait_for_auth_state_lock(&db);
        tx.execute(
            &format!("update {s}.devices set status='revoked' where tenant_id=$1 and id=$2"),
            &[&tenant, &Uuid::parse_str(&key.device_id).unwrap()],
        )
        .unwrap();
        tx.execute(
            &format!("update {s}.device_proof_keys set status='retired',retired_at_epoch=100 where tenant_id=$1 and key_id=$2"),
            &[&tenant, &key.key_id],
        )
        .unwrap();
        tx.commit().unwrap();
        assert!(worker.join().unwrap().is_err());
        assert!(nonce_unused(&db, &nonce));
        assert_eq!(count(&db, "auth_sessions"), 0);
        assert_eq!(count(&db, "refresh_tokens"), 0);
        assert_eq!(count(&db, "account_device_bindings"), 0);
    }
}
#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn proof_selection_signs_exact_ticket_and_switch_requires_live_source_and_target_device() {
    let db = Db::new(TenancyMode::Enabled);
    prepare(&db);
    let devices = proofs(&db);
    let (registration1, pair1) = registration(&db, "t1", 32);
    let key1 = devices.complete_registration(registration1).unwrap();
    let (registration2, pair2) = registration(&db, "t2", 33);
    let key2 = devices.complete_registration(registration2).unwrap();
    let service = auth(
        &db,
        LoginTenantPolicy::ChooseAfterAuthentication,
        "proof-choose",
        true,
        false,
    );
    let TenantLoginOutcome::SelectionRequired(first) = service.login(password()).unwrap() else {
        panic!()
    };
    let TenantLoginOutcome::SelectionRequired(second) = service.login(password()).unwrap() else {
        panic!()
    };
    let context = tenant_selection_proof_context("web", "proof-choose", &first.ticket);
    let proof = authentication_proof(&db, &key1, &pair1, TENANT_DEVICE_SELECTION_PURPOSE, context);
    // Even another live ticket for the same account cannot borrow this proof.
    assert!(service
        .select_tenant_with_proof(second.ticket, "t1".into(), proof.clone(), &devices)
        .is_err());
    assert!(service
        .select_tenant_with_proof(first.ticket.clone(), "t2".into(), proof.clone(), &devices)
        .is_err());
    assert!(nonce_unused(
        &db,
        &SecretString::new(proof.proof.challenge.clone())
    ));
    assert_eq!(count(&db, "auth_sessions"), 0);
    let failed_issuer = auth(
        &db,
        LoginTenantPolicy::ChooseAfterAuthentication,
        "proof-choose",
        true,
        true,
    );
    assert!(failed_issuer
        .select_tenant_with_proof(first.ticket.clone(), "t1".into(), proof.clone(), &devices)
        .is_err());
    assert!(nonce_unused(
        &db,
        &SecretString::new(proof.proof.challenge.clone())
    ));
    assert_eq!(count(&db, "account_device_bindings"), 0);
    assert_eq!(count(&db, "auth_sessions"), 0);
    let session1 = service
        .select_tenant_with_proof(first.ticket, "t1".into(), proof, &devices)
        .unwrap();
    let switch = service
        .begin_switch(session1.tokens.access_token.clone())
        .unwrap();
    let context = tenant_selection_proof_context("web", "proof-choose", &switch.ticket);
    let target = authentication_proof(&db, &key2, &pair2, TENANT_DEVICE_SELECTION_PURPOSE, context);
    let s = db.schema();
    db.adapter
        .connect()
        .unwrap()
        .batch_execute(&format!(
            "update {s}.account_device_bindings set status='suspended' where tenant_id='t1'"
        ))
        .unwrap();
    assert!(service
        .select_tenant_with_proof(switch.ticket.clone(), "t2".into(), target.clone(), &devices)
        .is_err());
    assert!(nonce_unused(
        &db,
        &SecretString::new(target.proof.challenge.clone())
    ));
    db.adapter
        .connect()
        .unwrap()
        .batch_execute(&format!(
            "update {s}.account_device_bindings set status='active' where tenant_id='t1'"
        ))
        .unwrap();
    let session2 = service
        .select_tenant_with_proof(switch.ticket, "t2".into(), target, &devices)
        .unwrap();
    assert_eq!(
        session2.session.device_id.as_deref(),
        Some(key2.device_id.as_str())
    );
    assert!(service.authenticate(session1.tokens.access_token).is_ok());
    assert!(service.authenticate(session2.tokens.access_token).is_ok());
    assert_eq!(count(&db, "account_device_bindings"), 2);
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn source_unbind_committed_while_tenant_switch_waits_prevents_issuance() {
    let db = Db::new(TenancyMode::Enabled);
    prepare(&db);
    let devices = proofs(&db);
    let (first, first_pair) = registration(&db, "t1", 35);
    let first = devices.complete_registration(first).unwrap();
    let (second, second_pair) = registration(&db, "t2", 36);
    let second = devices.complete_registration(second).unwrap();
    let service = auth(
        &db,
        LoginTenantPolicy::ChooseAfterAuthentication,
        "proof-choose",
        true,
        false,
    );
    let TenantLoginOutcome::SelectionRequired(initial) = service.login(password()).unwrap() else {
        panic!()
    };
    let source_proof = authentication_proof(
        &db,
        &first,
        &first_pair,
        TENANT_DEVICE_SELECTION_PURPOSE,
        tenant_selection_proof_context("web", "proof-choose", &initial.ticket),
    );
    let source = service
        .select_tenant_with_proof(initial.ticket, "t1".into(), source_proof, &devices)
        .unwrap();
    let switch = service.begin_switch(source.tokens.access_token).unwrap();
    let target_proof = authentication_proof(
        &db,
        &second,
        &second_pair,
        TENANT_DEVICE_SELECTION_PURPOSE,
        tenant_selection_proof_context("web", "proof-choose", &switch.ticket),
    );
    let nonce = SecretString::new(target_proof.proof.challenge.clone());
    let before = count(&db, "auth_sessions");
    let s = db.schema();
    let mut connection = db.adapter.connect().unwrap();
    let mut tx = connection.transaction().unwrap();
    tx.query_one(
        &format!("select singleton from {s}.access_state where singleton for update"),
        &[],
    )
    .unwrap();
    let worker = std::thread::spawn(move || {
        service.select_tenant_with_proof(switch.ticket, "t2".into(), target_proof, &devices)
    });
    wait_for_auth_state_lock(&db);
    tx.execute(
        &format!("update {s}.account_device_bindings set status='unbound',unbound_at_epoch=100,version=version+1 where tenant_id='t1' and device_id=$1"),
        &[&Uuid::parse_str(&first.device_id).unwrap()],
    ).unwrap();
    tx.commit().unwrap();
    assert!(worker.join().unwrap().is_err());
    assert!(nonce_unused(&db, &nonce));
    assert_eq!(count(&db, "auth_sessions"), before);
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn concurrent_proven_login_consumes_one_nonce_and_creates_one_binding_session_and_refresh() {
    let db = Db::new(TenancyMode::Enabled);
    prepare(&db);
    let devices = proofs(&db);
    let (registration, pair) = registration(&db, "t1", 34);
    let key = devices.complete_registration(registration).unwrap();
    let proof = authentication_proof(
        &db,
        &key,
        &pair,
        TENANT_DEVICE_LOGIN_PURPOSE,
        tenant_password_proof_context("web", "proof-login", &password()),
    );
    let gate = Arc::new(Barrier::new(2));
    let wins = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..2)
            .map(|_| {
                let gate = gate.clone();
                let proof = proof.clone();
                let devices = proofs(&db);
                let service = auth(
                    &db,
                    LoginTenantPolicy::Fixed {
                        tenant_id: "t1".into(),
                    },
                    "proof-login",
                    true,
                    false,
                );
                scope.spawn(move || {
                    gate.wait();
                    service
                        .login_with_proof(password(), proof, &devices)
                        .is_ok()
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().unwrap())
            .filter(|ok| *ok)
            .count()
    });
    assert_eq!(wins, 1);
    for table in ["account_device_bindings", "auth_sessions", "refresh_tokens"] {
        assert_eq!(count(&db, table), 1);
    }
}

mod refresh;

mod oidc;

mod http;

mod management_http;
