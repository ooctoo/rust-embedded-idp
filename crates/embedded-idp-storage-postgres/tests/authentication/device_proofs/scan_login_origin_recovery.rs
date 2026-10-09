use super::*;

fn scan_secret(byte: u8) -> (SecretString, [u8; 32]) {
    let bytes = [byte; 32];
    let hash: [u8; 32] = digest(&SHA256, &bytes).as_ref().try_into().unwrap();
    (
        SecretString::new(Base64UrlUnpadded::encode_string(&bytes)),
        hash,
    )
}

fn close(
    db: &Db,
    svc: &CoreTenantDeviceScanLoginService<Auth, Proofs>,
    device: &str,
    kid: &str,
    key: &ring::signature::Ed25519KeyPair,
    action: ScanOriginAction,
    operation_id: &str,
    secret: SecretString,
) -> Result<ScanOriginCloseResult, ScanLoginError> {
    svc.close_origin(
        CloseScanOrigin {
            entry_id: "terminal".into(),
            tenant_id: "t1".into(),
            origin_action: action,
            origin_operation_id: operation_id.into(),
            delivery_secret: secret,
        },
        device_call(
            db,
            ScanLoginAction::CloseOrigin,
            operation_id,
            device,
            kid,
            key,
        ),
    )
}

fn assert_revoked_delivery(db: &Db, session_id: &str) {
    let row = db
        .adapter
        .connect()
        .unwrap()
        .query_one(
            &format!(
                "select s.status, r.revocation_reason, d.result_ciphertext is null, d.receipt_nonce_hash is null \
                 from {}.auth_sessions s \
                 join {}.refresh_tokens r on r.tenant_id=s.tenant_id and r.session_id=s.id \
                 join {}.scan_login_deliveries d on d.tenant_id=s.tenant_id and d.session_id=s.id \
                 where s.id=$1",
                db.schema(),
                db.schema(),
                db.schema(),
            ),
            &[&Uuid::parse_str(session_id).unwrap()],
        )
        .unwrap();
    assert_eq!(row.get::<_, String>(0), "revoked");
    assert_eq!(row.get::<_, String>(1), "client_revocation");
    assert!(row.get::<_, bool>(2));
    assert!(row.get::<_, bool>(3));
    let schema = db.schema();
    let untouched = db.adapter.connect().unwrap().query_one(
        &format!("select           (select count(*) from {schema}.auth_sessions where device_id is null)>0,           not exists(select 1 from {schema}.auth_sessions where device_id is null and status<>'active'),           (select count(*) from {schema}.auth_sessions where device_id is not null)=1,           (select count(*) from {schema}.account_device_bindings)=1,           not exists(select 1 from {schema}.account_device_bindings where status<>'active'),           (select count(*) from {schema}.scan_login_deliveries)=1"), &[],
    ).unwrap();
    for column in 0..6 {
        assert!(untouched.get::<_, bool>(column));
    }
}

struct Deny(ScanAdmissionStage);
impl ScanLoginAdmission for Deny {
    fn authorize(
        &self,
        request: &ScanAdmissionRequest,
        _: &TrustedScanHostContext,
    ) -> Result<ScanAdmissionDecision, ScanLoginError> {
        if request.stage == self.0 {
            Ok(ScanAdmissionDecision::Deny {
                reason: "test denial".into(),
            })
        } else {
            Allow.authorize(request, &host())
        }
    }
}

fn denied_service(
    db: &Db,
    stage: ScanAdmissionStage,
) -> CoreTenantDeviceScanLoginService<Auth, Proofs> {
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
        Arc::new(Deny(stage)),
        Arc::new(Presentation),
        cipher(),
    )
    .unwrap()
}

struct GateAdmission {
    stage: ScanAdmissionStage,
    entered: std::sync::mpsc::Sender<()>,
    release: std::sync::Mutex<std::sync::mpsc::Receiver<()>>,
}
impl ScanLoginAdmission for GateAdmission {
    fn authorize(
        &self,
        request: &ScanAdmissionRequest,
        _: &TrustedScanHostContext,
    ) -> Result<ScanAdmissionDecision, ScanLoginError> {
        if request.stage == self.stage {
            self.entered.send(()).unwrap();
            self.release
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_secs(10))
                .unwrap();
        }
        Ok(ScanAdmissionDecision::Allow {
            decision_id: "test".into(),
            policy_revision: "test".into(),
            valid_until: TestClock.now() + Duration::from_secs(5),
        })
    }
}

fn gated_service(
    db: &Db,
    admission: Arc<GateAdmission>,
) -> CoreTenantDeviceScanLoginService<Auth, Proofs> {
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
        admission,
        Arc::new(Presentation),
        cipher(),
    )
    .unwrap()
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn close_commits_before_a_blocked_create_finalization_and_the_late_create_is_rejected() {
    let db = Db::new(TenancyMode::Enabled);
    let account = prepare(&db);
    let (device_id, kid, key) = device(&db, "t1", &account, Uuid::now_v7());
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let svc = Arc::new(gated_service(
        &db,
        Arc::new(GateAdmission {
            stage: ScanAdmissionStage::CreateDevice,
            entered: entered_tx,
            release: std::sync::Mutex::new(release_rx),
        }),
    ));
    let (secret, hash) = scan_secret(31);
    let create_call = device_call(&db, ScanLoginAction::Create, "", &device_id, &kid, &key);
    let outcome = std::thread::scope(|scope| {
        let create_svc = svc.clone();
        let create = scope.spawn(move || {
            create_svc.create_device(
                CreateDeviceScan {
                    operation_id: "31313131-3131-4131-8131-313131313131".into(),
                    entry_id: "terminal".into(),
                    tenant_id: "t1".into(),
                    delivery_secret_hash: hash,
                },
                create_call,
            )
        });
        entered_rx.recv_timeout(Duration::from_secs(10)).unwrap();
        assert_eq!(
            close(
                &db,
                &svc,
                &device_id,
                &kid,
                &key,
                ScanOriginAction::Create,
                "31313131-3131-4131-8131-313131313131",
                secret
            ),
            Ok(ScanOriginCloseResult {
                origin_action: ScanOriginAction::Create,
                origin_operation_id: "31313131-3131-4131-8131-313131313131".into(),
                outcome: ScanOriginCloseOutcome::Closed,
                closed_at: Some(TestClock.now()),
                progress: None,
            })
        );
        release_tx.send(()).unwrap();
        create.join().unwrap()
    });
    assert_eq!(outcome, Err(ScanLoginError::OriginOperationClosed));
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn cleanup_and_host_compensation_revoke_recoverable_delivery() {
    let db = Db::new(TenancyMode::Enabled);
    let account = prepare(&db);
    let (device_id, kid, key) = device(&db, "t1", &account, Uuid::now_v7());
    let svc = service(&db);
    let access = approved_device_display(&db, &svc, &device_id, &kid, &key);
    let ScanDeliveryResult::Bundle {
        progress: _,
        session,
        ..
    } = svc
        .exchange(
            ExchangeScan {
                operation_id: "32323232-3232-4232-8232-323232323232".into(),
                access: access.clone(),
            },
            device_call(&db, ScanLoginAction::Exchange, "", &device_id, &kid, &key),
        )
        .unwrap()
    else {
        panic!()
    };
    db.adapter
        .connect()
        .unwrap()
        .execute(
            &format!(
                "update {}.scan_login_deliveries set recover_until_epoch=100",
                db.schema()
            ),
            &[],
        )
        .unwrap();
    assert_eq!(svc.cleanup(host(), 10), Ok(1));
    assert_revoked_delivery(&db, &session.session.id);

    let db = Db::new(TenancyMode::Enabled);
    let account = prepare(&db);
    let (device, kid, key) = device(&db, "t1", &account, Uuid::now_v7());
    let svc = service(&db);
    let access = approved_device_display(&db, &svc, &device, &kid, &key);
    let ScanDeliveryResult::Bundle {
        progress, session, ..
    } = svc
        .exchange(
            ExchangeScan {
                operation_id: "33333333-3333-4333-8333-333333333334".into(),
                access: access.clone(),
            },
            device_call(&db, ScanLoginAction::Exchange, "", &device, &kid, &key),
        )
        .unwrap()
    else {
        panic!()
    };
    svc.compensate(
        host(),
        access.grant_id,
        progress.issuance_operation_id.unwrap(),
        "34343434-3434-4434-8434-343434343434".into(),
    )
    .unwrap();
    assert_revoked_delivery(&db, &session.session.id);
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn close_commits_before_a_blocked_claim_finalization() {
    let db = Db::new(TenancyMode::Enabled);
    let account = prepare(&db);
    let (device, kid, key) = device(&db, "t1", &account, Uuid::now_v7());
    let phone = source(&db);
    let allow = service(&db);
    let issued = allow
        .issue_phone(
            IssuePhoneScan {
                operation_id: "35353535-3535-4535-8535-353535353535".into(),
                entry_id: "terminal".into(),
            },
            phone,
        )
        .unwrap();
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let svc = Arc::new(gated_service(
        &db,
        Arc::new(GateAdmission {
            stage: ScanAdmissionStage::ClaimTarget,
            entered: entered_tx,
            release: std::sync::Mutex::new(release_rx),
        }),
    ));
    let (secret, hash) = scan_secret(35);
    let call = device_call(&db, ScanLoginAction::Claim, "", &device, &kid, &key);
    let outcome = std::thread::scope(|scope| {
        let create_svc = svc.clone();
        let claim = scope.spawn(move || {
            create_svc.claim_target(
                ClaimScanTarget {
                    operation_id: "36363636-3636-4636-8636-363636363636".into(),
                    entry_id: "terminal".into(),
                    tenant_id: "t1".into(),
                    scan_code: issued.scan_code,
                    delivery_secret_hash: hash,
                },
                call,
            )
        });
        entered_rx.recv_timeout(Duration::from_secs(10)).unwrap();
        close(
            &db,
            &svc,
            &device,
            &kid,
            &key,
            ScanOriginAction::Claim,
            "36363636-3636-4636-8636-363636363636",
            secret,
        )
        .unwrap();
        release_tx.send(()).unwrap();
        claim.join().unwrap()
    });
    assert_eq!(outcome, Err(ScanLoginError::OriginOperationClosed));
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn acknowledge_and_close_race_leaves_one_terminal_delivery() {
    let db = Db::new(TenancyMode::Enabled);
    let account = prepare(&db);
    let (device, kid, key) = device(&db, "t1", &account, Uuid::now_v7());
    let svc = Arc::new(service(&db));
    let access = approved_device_display(&db, &svc, &device, &kid, &key);
    let ScanDeliveryResult::Bundle {
        progress,
        session,
        receipt_nonce,
    } = svc
        .exchange(
            ExchangeScan {
                operation_id: "37373737-3737-4737-8737-373737373737".into(),
                access: access.clone(),
            },
            device_call(&db, ScanLoginAction::Exchange, "", &device, &kid, &key),
        )
        .unwrap()
    else {
        panic!()
    };
    let gate = Arc::new(std::sync::Barrier::new(2));
    let issuance = progress.issuance_operation_id.unwrap();
    let (ack, close_result) = std::thread::scope(|scope| {
        let a = svc.clone();
        let g = gate.clone();
        let access_a = access.clone();
        let ack_call = device_call(&db, ScanLoginAction::Acknowledge, "", &device, &kid, &key);
        let h1 = scope.spawn(move || {
            g.wait();
            a.acknowledge(
                AcknowledgeScan {
                    operation_id: "38383838-3838-4838-8838-383838383838".into(),
                    issuance_operation_id: issuance,
                    access: access_a,
                    receipt_nonce,
                },
                ack_call,
            )
        });
        let c = svc.clone();
        let close_call = device_call(&db, ScanLoginAction::CloseOrigin, "", &device, &kid, &key);
        let h2 = scope.spawn(move || {
            gate.wait();
            c.close_origin(
                CloseScanOrigin {
                    entry_id: "terminal".into(),
                    tenant_id: "t1".into(),
                    origin_action: ScanOriginAction::Create,
                    origin_operation_id: "11111111-1111-4111-8111-111111111111".into(),
                    delivery_secret: access.delivery_secret,
                },
                close_call,
            )
        });
        (h1.join().unwrap(), h2.join().unwrap())
    });
    let status = db
        .adapter
        .connect()
        .unwrap()
        .query_one(
            &format!(
                "select status from {}.auth_sessions where id=$1",
                db.schema()
            ),
            &[&Uuid::parse_str(&session.session.id).unwrap()],
        )
        .unwrap()
        .get::<_, String>(0);
    if status == "active" {
        assert!(ack.is_ok());
        assert!(matches!(
            close_result,
            Ok(ScanOriginCloseResult {
                outcome: ScanOriginCloseOutcome::AlreadyActivated,
                ..
            })
        ));
    } else {
        assert_eq!(status, "revoked");
        assert_eq!(ack, Err(ScanLoginError::DeliveryRevoked));
        assert_revoked_delivery(&db, &session.session.id);
        assert!(matches!(
            close_result,
            Ok(ScanOriginCloseResult {
                outcome: ScanOriginCloseOutcome::Closed,
                ..
            })
        ));
    }
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn denied_release_and_activation_revoke_only_the_pending_delivery_in_sql() {
    let db = Db::new(TenancyMode::Enabled);
    let account = prepare(&db);
    let (device_id, kid, key) = device(&db, "t1", &account, Uuid::now_v7());
    let allow = service(&db);
    let access = approved_device_display(&db, &allow, &device_id, &kid, &key);
    let denied_release = denied_service(&db, ScanAdmissionStage::ReleaseResult);
    assert_eq!(
        denied_release.exchange(
            ExchangeScan {
                operation_id: "20202020-2020-4020-8020-202020202020".into(),
                access: access.clone(),
            },
            device_call(&db, ScanLoginAction::Exchange, "", &device_id, &kid, &key),
        ),
        Err(ScanLoginError::AdmissionDenied)
    );
    let session = db
        .adapter
        .connect()
        .unwrap()
        .query_one(
            &format!(
                "select session_id from {}.scan_login_deliveries",
                db.schema()
            ),
            &[],
        )
        .unwrap()
        .get::<_, Uuid>(0)
        .to_string();
    assert_revoked_delivery(&db, &session);

    let db = Db::new(TenancyMode::Enabled);
    let account = prepare(&db);
    let (device, kid, key) = device(&db, "t1", &account, Uuid::now_v7());
    let allow = service(&db);
    let access = approved_device_display(&db, &allow, &device, &kid, &key);
    let ScanDeliveryResult::Bundle {
        progress,
        session,
        receipt_nonce,
    } = allow
        .exchange(
            ExchangeScan {
                operation_id: "21212121-2121-4121-8121-212121212121".into(),
                access: access.clone(),
            },
            device_call(&db, ScanLoginAction::Exchange, "", &device, &kid, &key),
        )
        .unwrap()
    else {
        panic!()
    };
    let denied_activation = denied_service(&db, ScanAdmissionStage::ActivateSession);
    assert_eq!(
        denied_activation.acknowledge(
            AcknowledgeScan {
                operation_id: "22222222-2222-4222-8222-222222222222".into(),
                issuance_operation_id: progress.issuance_operation_id.unwrap(),
                access,
                receipt_nonce,
            },
            device_call(&db, ScanLoginAction::Acknowledge, "", &device, &kid, &key),
        ),
        Err(ScanLoginError::AdmissionDenied)
    );
    assert_revoked_delivery(&db, &session.session.id);
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn close_pending_rolls_back_tombstone_when_audit_insert_fails_and_unknown_closure_is_terminal() {
    let db = Db::new(TenancyMode::Enabled);
    let account = prepare(&db);
    let (device, kid, key) = device(&db, "t1", &account, Uuid::now_v7());
    let svc = service(&db);
    let access = approved_device_display(&db, &svc, &device, &kid, &key);
    let ScanDeliveryResult::Bundle { session, .. } = svc
        .exchange(
            ExchangeScan {
                operation_id: "23232323-2323-4323-8323-232323232323".into(),
                access: access.clone(),
            },
            device_call(&db, ScanLoginAction::Exchange, "", &device, &kid, &key),
        )
        .unwrap()
    else {
        panic!()
    };
    let schema = db.schema();
    let mut connection = db.adapter.connect().unwrap();
    connection.batch_execute(&format!(
        "create function {schema}.reject_close_audit() returns trigger language plpgsql as $$ begin raise exception 'close audit fail'; end $$; \
         create trigger reject_close_audit before insert on {schema}.scan_login_audit_events for each row execute function {schema}.reject_close_audit()"
    )).unwrap();
    assert!(matches!(
        close(
            &db,
            &svc,
            &device,
            &kid,
            &key,
            ScanOriginAction::Create,
            "11111111-1111-4111-8111-111111111111",
            access.delivery_secret.clone()
        ),
        Err(ScanLoginError::Store(_))
    ));
    assert_eq!(
        connection
            .query_one(
                &format!("select count(*) from {schema}.scan_login_origin_closures"),
                &[]
            )
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    assert_eq!(
        connection
            .query_one(
                &format!("select status from {schema}.auth_sessions where id=$1"),
                &[&Uuid::parse_str(&session.session.id).unwrap()]
            )
            .unwrap()
            .get::<_, String>(0),
        "pending"
    );
    let restored = connection.query_one(
        &format!("select r.revoked_at_epoch is null, d.state='recoverable',             d.result_ciphertext is not null, d.receipt_nonce_hash is not null             from {schema}.refresh_tokens r join {schema}.scan_login_deliveries d             on r.tenant_id=d.tenant_id and r.session_id=d.session_id where r.session_id=$1"),
        &[&Uuid::parse_str(&session.session.id).unwrap()],
    ).unwrap();
    for column in 0..4 {
        assert!(restored.get::<_, bool>(column));
    }
    connection
        .batch_execute(&format!(
            "drop trigger reject_close_audit on {schema}.scan_login_audit_events"
        ))
        .unwrap();

    let (secret, _) = scan_secret(24);
    let operation = "24242424-2424-4424-8424-242424242424";
    close(
        &db,
        &svc,
        &device,
        &kid,
        &key,
        ScanOriginAction::Claim,
        operation,
        secret.clone(),
    )
    .unwrap();
    assert_eq!(
        svc.lookup_device(
            LookupDeviceScan {
                origin_action: Some(ScanOriginAction::Claim),
                origin_operation_id: operation.into(),
                entry_id: "terminal".into(),
                tenant_id: "t1".into(),
                delivery_secret: secret
            },
            device_call(&db, ScanLoginAction::Lookup, "", &device, &kid, &key),
        ),
        Err(ScanLoginError::OriginOperationClosed)
    );
}
