//! Opt-in PostgreSQL coverage for the generic scan-login state machine.
use super::*;
use embedded_idp_core::{
    access::*, DeviceProofProfile, DeviceRequestBinding, SecretString, SessionStatus,
};
use embedded_idp_security::{RingScanResultCipher, ScanResultKey, ScanResultKeyring};
use ring::digest::{digest, SHA256};
use std::{sync::Arc, time::Duration};

struct Allow;
impl ScanLoginAdmission for Allow {
    fn authorize(
        &self,
        _: &ScanAdmissionRequest,
        _: &TrustedScanHostContext,
    ) -> Result<ScanAdmissionDecision, ScanLoginError> {
        Ok(ScanAdmissionDecision::Allow {
            decision_id: "test".into(),
            policy_revision: "test".into(),
            valid_until: TestClock.now() + Duration::from_secs(5),
        })
    }
}
struct Presentation;
impl ScanTargetPresentationProvider for Presentation {
    fn describe(
        &self,
        _: &ScanAdmissionRequest,
        _: &TrustedScanHostContext,
    ) -> Result<ScanTargetPresentation, ScanLoginError> {
        Ok(ScanTargetPresentation {
            display_name: "Test terminal".into(),
            identification: "terminal-1".into(),
            context_label: None,
            revision: "1".into(),
        })
    }
}
fn entry() -> ScanLoginEntryConfig {
    ScanLoginEntryConfig {
        entry_id: "terminal".into(),
        target_client_id: "web".into(),
        allowed_source_client_ids: vec!["web".into()],
        host_scope: "test-host".into(),
        tenant_policy: LoginTenantPolicy::Fixed {
            tenant_id: "t1".into(),
        },
        modes: vec![ScanLoginMode::DeviceDisplay, ScanLoginMode::PhoneDisplay],
        target_scope: None,
        limits: ScanLoginLimits::default(),
    }
}
fn host() -> TrustedScanHostContext {
    TrustedScanHostContext::new("test-host".into(), TestClock.now() + Duration::from_secs(5))
}
fn cipher() -> Arc<dyn ScanResultCipher> {
    Arc::new(RingScanResultCipher::new(
        ScanResultKeyring::new("test", [ScanResultKey::new("test", [9; 32])]).unwrap(),
    ))
}
fn service(db: &Db) -> CoreTenantDeviceScanLoginService<Auth, Proofs> {
    CoreTenantDeviceScanLoginService::new(
        entry(),
        auth(
            db,
            LoginTenantPolicy::Fixed {
                tenant_id: "t1".into(),
            },
            "terminal",
            true,
            false,
        ),
        proofs(db),
        Arc::new(Allow),
        Arc::new(Presentation),
        cipher(),
    )
    .unwrap()
}
fn device_call(
    db: &Db,
    action: ScanLoginAction,
    operation: &str,
    device: &str,
    kid: &str,
    key: &ring::signature::Ed25519KeyPair,
) -> ScanDeviceCall {
    let challenge = proofs(db)
        .issue_challenge("t1", device, action.purpose())
        .unwrap();
    let binding = DeviceRequestBinding::new(
        "t1",
        DeviceProofProfile::new(SCAN_LOGIN_PROOF_PROFILE).unwrap(),
        "test-api",
        embedded_idp_core::CanonicalHttpMethod::Post,
        "/scan",
        [7; 32],
    )
    .unwrap();
    let mut proof = DeviceProofPresentation {
        device_id: device.into(),
        key_id: kid.into(),
        challenge: challenge.challenge.into_exposed(),
        signature: base64ct::Base64UrlUnpadded::encode_string(&[0; 64]),
        signed_at: TestClock.now(),
    };
    proof.signature = base64ct::Base64UrlUnpadded::encode_string(
        key.sign(
            &build_scan_login_proof_bytes(&binding, &proof, action, "web", "terminal").unwrap(),
        )
        .as_ref(),
    );
    let _ = operation;
    ScanDeviceCall {
        entry_id: "terminal".into(),
        proof,
        binding,
        host: host(),
    }
}
fn source(db: &Db) -> ScanSourceCall {
    let browser = auth(
        db,
        LoginTenantPolicy::Fixed {
            tenant_id: "t1".into(),
        },
        "phone",
        false,
        false,
    );
    let TenantLoginOutcome::Authenticated(login) = browser.login(password()).unwrap() else {
        panic!()
    };
    ScanSourceCall {
        source: browser
            .authenticate_browser(login.tokens.refresh_token, None)
            .unwrap(),
        host: host(),
    }
}
fn approved_device_display(
    db: &Db,
    svc: &CoreTenantDeviceScanLoginService<Auth, Proofs>,
    device_id: &str,
    kid: &str,
    key: &ring::signature::Ed25519KeyPair,
) -> DeviceGrantAccess {
    let secret_bytes = [6_u8; 32];
    let secret = SecretString::new(Base64UrlUnpadded::encode_string(&secret_bytes));
    let secret_hash: [u8; 32] = digest(&SHA256, &secret_bytes).as_ref().try_into().unwrap();
    let created = svc
        .create_device(
            CreateDeviceScan {
                operation_id: "11111111-1111-4111-8111-111111111111".into(),
                entry_id: "terminal".into(),
                tenant_id: "t1".into(),
                delivery_secret_hash: secret_hash,
            },
            device_call(db, ScanLoginAction::Create, "", device_id, kid, key),
        )
        .unwrap();
    let phone = source(db);
    let confirmation = svc
        .attach_source(
            AttachScanSource {
                operation_id: "33333333-3333-4333-8333-333333333333".into(),
                display_code: created.display_code,
            },
            phone.clone(),
        )
        .unwrap();
    svc.approve(
        ApproveScan {
            action: SourceGrantAction {
                operation_id: "44444444-4444-4444-8444-444444444444".into(),
                grant_id: confirmation.progress.grant_id.clone(),
            },
            confirmation_revision: confirmation.confirmation_revision,
        },
        phone,
    )
    .unwrap();
    DeviceGrantAccess {
        grant_id: confirmation.progress.grant_id,
        delivery_secret: secret,
    }
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn scan_login_device_display_round_trip_persists_one_delivery_and_activates_on_ack() {
    let db = Db::new(TenancyMode::Enabled);
    let account = prepare(&db);
    let (device, kid, key) = device(&db, "t1", &account, Uuid::now_v7());
    // Exercise first personnel/device binding, including its transaction rollback.
    db.adapter.connect().unwrap().execute(
        &format!("delete from {}.account_device_bindings where tenant_id='t1' and account_id=$1 and device_id=$2",db.schema()),
        &[&Uuid::parse_str(&account).unwrap(),&Uuid::parse_str(&device).unwrap()],
    ).unwrap();
    let svc = service(&db);
    let secret_bytes = [4_u8; 32];
    let secret = SecretString::new(Base64UrlUnpadded::encode_string(&secret_bytes));
    let digest: [u8; 32] = digest(&SHA256, &secret_bytes).as_ref().try_into().unwrap();
    let created = svc
        .create_device(
            CreateDeviceScan {
                operation_id: "11111111-1111-4111-8111-111111111111".into(),
                entry_id: "terminal".into(),
                tenant_id: "t1".into(),
                delivery_secret_hash: digest,
            },
            device_call(&db, ScanLoginAction::Create, "", &device, &kid, &key),
        )
        .unwrap();
    let phone = source(&db);
    let confirmation = svc
        .attach_source(
            AttachScanSource {
                operation_id: "33333333-3333-4333-8333-333333333333".into(),
                display_code: created.display_code,
            },
            phone.clone(),
        )
        .unwrap();
    svc.approve(
        ApproveScan {
            action: SourceGrantAction {
                operation_id: "44444444-4444-4444-8444-444444444444".into(),
                grant_id: confirmation.progress.grant_id.clone(),
            },
            confirmation_revision: confirmation.confirmation_revision,
        },
        phone,
    )
    .unwrap();
    let access = DeviceGrantAccess {
        grant_id: confirmation.progress.grant_id,
        delivery_secret: secret,
    };
    let issued = svc
        .exchange(
            ExchangeScan {
                operation_id: "55555555-5555-4555-8555-555555555555".into(),
                access: access.clone(),
            },
            device_call(&db, ScanLoginAction::Exchange, "", &device, &kid, &key),
        )
        .unwrap();
    let ScanDeliveryResult::Bundle {
        progress,
        session,
        receipt_nonce,
    } = issued
    else {
        panic!()
    };
    assert_eq!(progress.state, ScanGrantState::Issued);
    assert_eq!(session.session.status, SessionStatus::Pending);
    let recovered = svc
        .recover(
            RecoverScan {
                issuance_operation_id: progress.issuance_operation_id.clone().unwrap(),
                access: access.clone(),
            },
            device_call(&db, ScanLoginAction::Recover, "", &device, &kid, &key),
        )
        .unwrap();
    let ScanDeliveryResult::Bundle { session: again, .. } = recovered else {
        panic!()
    };
    assert_eq!(session.session.id, again.session.id);
    let active = svc
        .acknowledge(
            AcknowledgeScan {
                operation_id: "66666666-6666-4666-8666-666666666666".into(),
                issuance_operation_id: progress.issuance_operation_id.unwrap(),
                access,
                receipt_nonce,
            },
            device_call(&db, ScanLoginAction::Acknowledge, "", &device, &kid, &key),
        )
        .unwrap();
    assert_eq!(active.delivery_state, Some(ScanDeliveryState::Acknowledged));
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn scan_login_phone_display_claims_the_proven_target_before_confirmation() {
    let db = Db::new(TenancyMode::Enabled);
    let account = prepare(&db);
    let (device, kid, key) = device(&db, "t1", &account, Uuid::now_v7());
    let svc = service(&db);
    let phone = source(&db);
    let issued = svc
        .issue_phone(
            IssuePhoneScan {
                operation_id: "77777777-7777-4777-8777-777777777777".into(),
                entry_id: "terminal".into(),
            },
            phone.clone(),
        )
        .unwrap();
    assert_eq!(issued.progress.mode, ScanLoginMode::PhoneDisplay);
    let secret_bytes = [5_u8; 32];
    let secret = SecretString::new(Base64UrlUnpadded::encode_string(&secret_bytes));
    let hash: [u8; 32] = digest(&SHA256, &secret_bytes).as_ref().try_into().unwrap();
    let claimed = svc
        .claim_target(
            ClaimScanTarget {
                operation_id: "88888888-8888-4888-8888-888888888888".into(),
                entry_id: "terminal".into(),
                tenant_id: "t1".into(),
                scan_code: issued.scan_code,
                delivery_secret_hash: hash,
            },
            device_call(&db, ScanLoginAction::Claim, "", &device, &kid, &key),
        )
        .unwrap();
    let confirmation = svc
        .inspect(claimed.grant_id.clone(), phone.clone())
        .unwrap();
    assert_eq!(confirmation.target.device_id, device);
    svc.approve(
        ApproveScan {
            action: SourceGrantAction {
                operation_id: "99999999-9999-4999-8999-999999999999".into(),
                grant_id: claimed.grant_id.clone(),
            },
            confirmation_revision: confirmation.confirmation_revision,
        },
        phone,
    )
    .unwrap();
    let result = svc
        .exchange(
            ExchangeScan {
                operation_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".into(),
                access: DeviceGrantAccess {
                    grant_id: claimed.grant_id,
                    delivery_secret: secret,
                },
            },
            device_call(&db, ScanLoginAction::Exchange, "", &device, &kid, &key),
        )
        .unwrap();
    assert!(matches!(result, ScanDeliveryResult::Bundle { .. }));
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn concurrent_different_exchange_operations_create_one_delivery_and_original_recovers() {
    let db = Db::new(TenancyMode::Enabled);
    let account = prepare(&db);
    let (device, kid, key) = device(&db, "t1", &account, Uuid::now_v7());
    let svc = Arc::new(service(&db));
    let access = approved_device_display(&db, &svc, &device, &kid, &key);
    let barrier = Arc::new(std::sync::Barrier::new(2));
    let outcomes = std::thread::scope(|scope| {
        [
            "55555555-5555-4555-8555-555555555555",
            "66666666-6666-4666-8666-666666666666",
        ]
        .map(|op| {
            let svc = svc.clone();
            let gate = barrier.clone();
            let call = device_call(&db, ScanLoginAction::Exchange, op, &device, &kid, &key);
            let access = access.clone();
            scope.spawn(move || {
                gate.wait();
                svc.exchange(
                    ExchangeScan {
                        operation_id: op.into(),
                        access,
                    },
                    call,
                )
            })
        })
        .map(|h| h.join().unwrap())
    });
    let bundles = outcomes
        .iter()
        .filter(|r| matches!(r, Ok(ScanDeliveryResult::Bundle { .. })))
        .count();
    assert_eq!(bundles, 1);
    let original = outcomes
        .iter()
        .find_map(|r| match r {
            Ok(ScanDeliveryResult::Bundle { progress, .. }) => {
                progress.issuance_operation_id.clone()
            }
            Err(ScanLoginError::ExchangeAlreadyStarted(id)) => Some(id.clone()),
            Err(ScanLoginError::OperationConflict) => None,
            _ => None,
        })
        .expect("original issuance");
    let recovered = svc
        .recover(
            RecoverScan {
                issuance_operation_id: original,
                access,
            },
            device_call(&db, ScanLoginAction::Recover, "", &device, &kid, &key),
        )
        .unwrap();
    assert!(matches!(recovered, ScanDeliveryResult::Bundle { .. }));
    let mut c = db.adapter.connect().unwrap();
    let s = db.schema();
    assert_eq!(
        c.query_one(
            &format!("select count(*) from {s}.scan_login_deliveries"),
            &[]
        )
        .unwrap()
        .get::<_, i64>(0),
        1
    );
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn audit_write_failure_rolls_back_exchange_and_same_operation_can_retry() {
    let db = Db::new(TenancyMode::Enabled);
    let account = prepare(&db);
    let (device, kid, key) = device(&db, "t1", &account, Uuid::now_v7());
    // Exercise first personnel/device binding, including its transaction rollback.
    db.adapter.connect().unwrap().execute(
        &format!("delete from {}.account_device_bindings where tenant_id='t1' and account_id=$1 and device_id=$2",db.schema()),
        &[&Uuid::parse_str(&account).unwrap(),&Uuid::parse_str(&device).unwrap()],
    ).unwrap();
    let svc = service(&db);
    let access = approved_device_display(&db, &svc, &device, &kid, &key);
    let s = db.schema().to_owned();
    let mut c = db.adapter.connect().unwrap();
    let before = ["auth_sessions", "refresh_tokens", "account_device_bindings"].map(|table| {
        c.query_one(&format!("select count(*) from {s}.{table}"), &[])
            .unwrap()
            .get::<_, i64>(0)
    });
    c.batch_execute(&format!("create function {s}.reject_scan_audit() returns trigger language plpgsql as $$ begin raise exception 'scan audit fail'; end $$; create trigger reject_scan_audit before insert on {s}.scan_login_audit_events for each row execute function {s}.reject_scan_audit()" )).unwrap();
    let op = "77777777-7777-4777-8777-777777777777";
    assert!(svc
        .exchange(
            ExchangeScan {
                operation_id: op.into(),
                access: access.clone()
            },
            device_call(&db, ScanLoginAction::Exchange, "", &device, &kid, &key)
        )
        .is_err());
    assert_eq!(
        c.query_one(
            &format!("select count(*) from {s}.scan_login_deliveries"),
            &[]
        )
        .unwrap()
        .get::<_, i64>(0),
        0
    );
    let after = ["auth_sessions", "refresh_tokens", "account_device_bindings"].map(|table| {
        c.query_one(&format!("select count(*) from {s}.{table}"), &[])
            .unwrap()
            .get::<_, i64>(0)
    });
    assert_eq!(after, before);
    assert_eq!(
        c.query_one(
            &format!("select state from {s}.scan_login_grants where id=$1"),
            &[&Uuid::parse_str(&access.grant_id).unwrap()]
        )
        .unwrap()
        .get::<_, String>(0),
        "approved"
    );
    c.batch_execute(&format!(
        "drop trigger reject_scan_audit on {s}.scan_login_audit_events"
    ))
    .unwrap();
    let retry = svc
        .exchange(
            ExchangeScan {
                operation_id: op.into(),
                access,
            },
            device_call(&db, ScanLoginAction::Exchange, "", &device, &kid, &key),
        )
        .unwrap();
    assert!(matches!(retry, ScanDeliveryResult::Bundle { .. }));
}
