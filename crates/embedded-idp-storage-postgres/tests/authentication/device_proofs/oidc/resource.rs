use super::*;
fn confidential(db: &Db) {
    db.adapter.connect().unwrap().execute(&format!("update {}.oidc_clients set client_type='confidential_web',redirect_uris_json='[\"https://client.example.test/callback\"]',client_secret_hash='synthetic-secret-hash' where client_id='web'",db.schema()),&[]).unwrap();
}
fn token_request(token: SecretString) -> TenantTokenRequest {
    TenantTokenRequest {
        client_id: "web".into(),
        client_secret: Some(SecretString::new("synthetic-client-secret")),
        token,
        token_type_hint: None,
    }
}
#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn resource_queries_recheck_tenant_membership_session_and_current_refresh_version() {
    for (mode, tenant) in [(TenancyMode::Disabled, "0"), (TenancyMode::Enabled, "t1")] {
        let db = Db::new(mode);
        let initial = setup(&db, tenant);
        let svc = oidc(&db, tenant, false);
        assert_eq!(
            svc.introspect_token(token_request(SecretString::new("invalid"))),
            Err(TenantAuthError::InvalidClient)
        );
        confidential(&db);
        let mut bad = token_request(SecretString::new("invalid"));
        bad.client_secret = None;
        assert_eq!(
            svc.introspect_token(bad),
            Err(TenantAuthError::InvalidClient)
        );
        assert_eq!(
            svc.introspect_token(token_request(SecretString::new("invalid")))
                .unwrap(),
            None
        );
        let info = svc.user_info(initial.tokens.access_token.clone()).unwrap();
        assert_eq!(info.subject_account_id, initial.session.account_id);
        assert_eq!(info.tenant_id, tenant);
        assert!(info.email.is_none());
        assert!(info.display_name.is_none());
        for (raw, hint, kind) in [
            (
                initial.tokens.access_token.clone(),
                TenantTokenType::Refresh,
                TenantTokenType::Access,
            ),
            (
                initial.tokens.refresh_token.clone(),
                TenantTokenType::Access,
                TenantTokenType::Refresh,
            ),
        ] {
            let mut cmd = token_request(raw);
            cmd.token_type_hint = Some(hint);
            let info = svc.introspect_token(cmd).unwrap().unwrap();
            assert_eq!(info.tenant_id, tenant);
            assert_eq!(info.token_type, kind);
            assert_eq!(info.session_id, initial.session.id);
        }
        if mode == TenancyMode::Enabled {
            let other = oidc(&db, "t2", false);
            assert!(other
                .user_info(initial.tokens.access_token.clone())
                .is_err());
            assert_eq!(
                other
                    .introspect_token(token_request(initial.tokens.refresh_token.clone()))
                    .unwrap(),
                None
            );
            other
                .revoke_token(token_request(initial.tokens.access_token.clone()))
                .unwrap();
            assert!(svc.user_info(initial.tokens.access_token.clone()).is_ok());
        }
        let TenantRefreshOutcome::Rotated { tokens, .. } = entry(&db, tenant)
            .rotate_refresh(initial.tokens.refresh_token.clone())
            .unwrap()
        else {
            panic!()
        };
        assert_eq!(
            svc.introspect_token(token_request(initial.tokens.refresh_token.clone()))
                .unwrap(),
            None
        );
        svc.logout(token_request(initial.tokens.refresh_token))
            .unwrap();
        assert!(svc
            .introspect_token(token_request(tokens.refresh_token.clone()))
            .unwrap()
            .is_some());
        let s = db.schema();
        db.adapter.connect().unwrap().execute(&format!("update {s}.access_memberships set status='suspended' where tenant_id=$1 and account_id=$2"),&[&tenant,&Uuid::parse_str(&initial.session.account_id).unwrap()]).unwrap();
        assert!(svc.user_info(tokens.access_token.token.clone()).is_err());
        assert_eq!(
            svc.introspect_token(token_request(tokens.refresh_token.clone()))
                .unwrap(),
            None
        );
        db.adapter.connect().unwrap().execute(&format!("update {s}.access_memberships set status='active' where tenant_id=$1 and account_id=$2"),&[&tenant,&Uuid::parse_str(&initial.session.account_id).unwrap()]).unwrap();
        db.adapter
            .connect()
            .unwrap()
            .execute(
                &format!("update {s}.auth_sessions set created_at_epoch=99,authenticated_at_epoch=99,expires_at_epoch=100 where id=$1"),
                &[&Uuid::parse_str(&initial.session.id).unwrap()],
            )
            .unwrap();
        assert_eq!(
            svc.introspect_token(token_request(tokens.access_token.token))
                .unwrap(),
            None
        );
        assert_eq!(
            svc.introspect_token(token_request(tokens.refresh_token))
                .unwrap(),
            None
        );
    }
}
#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn resource_logout_is_atomic_idempotent_and_invalidates_source_grants_only() {
    for (mode, tenant) in [(TenancyMode::Disabled, "0"), (TenancyMode::Enabled, "t1")] {
        let db = Db::new(mode);
        let initial = setup(&db, tenant);
        let other = password_session(entry(&db, tenant).login(password()).unwrap());
        let svc = oidc(&db, tenant, false);
        confidential(&db);
        let mut authorization = request("openid");
        authorization.redirect_uri = "https://client.example.test/callback".into();
        let code = svc
            .authorize(actor(&initial.session), authorization)
            .unwrap();
        let ticket = if mode == TenancyMode::Enabled {
            Some(
                auth(
                    &db,
                    LoginTenantPolicy::ChooseAfterAuthentication,
                    "oidc",
                    false,
                    false,
                )
                .begin_switch(initial.tokens.access_token.clone())
                .unwrap(),
            )
        } else {
            None
        };
        let remote = if mode == TenancyMode::Enabled {
            Some(password_session(
                entry(&db, "t2").login(password()).unwrap(),
            ))
        } else {
            None
        };
        confidential(&db);
        let s = db.schema();
        db.adapter.connect().unwrap().batch_execute(&format!("create function {s}.fail_resource_revoke() returns trigger language plpgsql as $$ begin raise exception 'synthetic revoke failure'; end $$;create trigger fail_resource_revoke after update on {s}.refresh_tokens for each row execute function {s}.fail_resource_revoke()" )).unwrap();
        assert!(svc
            .logout(token_request(initial.tokens.refresh_token.clone()))
            .is_err());
        assert!(svc.user_info(initial.tokens.access_token.clone()).is_ok());
        assert!(svc
            .introspect_token(token_request(initial.tokens.refresh_token.clone()))
            .unwrap()
            .is_some());
        db.adapter
            .connect()
            .unwrap()
            .batch_execute(&format!(
                "drop trigger fail_resource_revoke on {s}.refresh_tokens"
            ))
            .unwrap();
        let svc = Arc::new(svc);
        let barrier = Arc::new(Barrier::new(2));
        let handles: Vec<_> = (0..2)
            .map(|_| {
                let svc = svc.clone();
                let barrier = barrier.clone();
                let token = initial.tokens.refresh_token.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    svc.logout(token_request(token))
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap().unwrap()
        }
        assert!(svc.user_info(initial.tokens.access_token).is_err());
        assert!(svc.user_info(other.tokens.access_token.clone()).is_ok());
        if let Some(remote) = remote {
            assert!(entry(&db, "t2")
                .authenticate(remote.tokens.access_token)
                .is_ok())
        }
        let mut exchange = exchange(code.code);
        exchange.redirect_uri = "https://client.example.test/callback".into();
        exchange.client_secret = Some(SecretString::new("synthetic-client-secret"));
        assert_eq!(svc.exchange(exchange), Err(TenantAuthError::InvalidSession));
        if let Some(ticket) = ticket {
            assert!(auth(
                &db,
                LoginTenantPolicy::ChooseAfterAuthentication,
                "oidc",
                false,
                false
            )
            .select_tenant(ticket.ticket, "t2".into())
            .is_err())
        }
        let rows=db.adapter.connect().unwrap().query(&format!("select revocation_reason from {s}.refresh_tokens where tenant_id=$1 and session_id=$2"),&[&tenant,&Uuid::parse_str(&initial.session.id).unwrap()]).unwrap();
        assert!(rows.iter().all(|r| r.get::<_, String>(0) == "logout"));
        svc.revoke_token(token_request(other.tokens.access_token.clone()))
            .unwrap();
        assert!(svc.user_info(other.tokens.access_token).is_err());
        let reason: String = db
            .adapter
            .connect()
            .unwrap()
            .query_one(
                &format!("select revocation_reason from {s}.refresh_tokens where session_id=$1"),
                &[&Uuid::parse_str(&other.session.id).unwrap()],
            )
            .unwrap()
            .get(0);
        assert_eq!(reason, "client_revocation");
    }
}
#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn resource_device_sessions_require_live_device_authority_and_current_token_for_logout() {
    let db = Db::new(TenancyMode::Enabled);
    setup(&db, "t1");
    let devices = proofs(&db);
    let (reg, pair) = registration(&db, "t1", 81);
    let key = devices.complete_registration(reg).unwrap();
    let proof = authentication_proof(
        &db,
        &key,
        &pair,
        TENANT_DEVICE_LOGIN_PURPOSE,
        tenant_password_proof_context("web", "oidc", &password()),
    );
    let login = password_session(
        entry(&db, "t1")
            .login_with_proof(password(), proof, &devices)
            .unwrap(),
    );
    confidential(&db);
    let svc = oidc(&db, "t1", false);
    assert!(svc.user_info(login.tokens.access_token.clone()).is_ok());
    assert!(svc
        .introspect_token(token_request(login.tokens.refresh_token.clone()))
        .unwrap()
        .is_some());
    let s = db.schema();
    db.adapter
        .connect()
        .unwrap()
        .execute(
            &format!("update {s}.devices set status='revoked' where tenant_id='t1' and id=$1"),
            &[&Uuid::parse_str(&key.device_id).unwrap()],
        )
        .unwrap();
    assert!(svc.user_info(login.tokens.access_token.clone()).is_err());
    assert_eq!(
        svc.introspect_token(token_request(login.tokens.refresh_token.clone()))
            .unwrap(),
        None
    );
    db.adapter
        .connect()
        .unwrap()
        .execute(
            &format!("update {s}.devices set status='active' where tenant_id='t1' and id=$1"),
            &[&Uuid::parse_str(&key.device_id).unwrap()],
        )
        .unwrap();
    // Logout removes credentials; it does not issue credentials or consume a nonce.
    svc.logout(token_request(login.tokens.refresh_token))
        .unwrap();
    assert!(svc.user_info(login.tokens.access_token).is_err());
}
async fn http_request(
    router: &axum::Router,
    path: &str,
    body: Option<String>,
    authorization: Option<String>,
    tenant: Option<&str>,
) -> (axum::http::StatusCode, serde_json::Value) {
    use tower::ServiceExt;
    let mut request = axum::http::Request::builder()
        .method(if body.is_some() { "POST" } else { "GET" })
        .uri(path);
    if let Some(auth) = authorization {
        request = request.header("authorization", auth)
    }
    if let Some(tenant) = tenant {
        request = request.header("x-embedded-idp-tenant-id", tenant)
    }
    let body = match body {
        Some(body) => {
            request = request.header("content-type", "application/x-www-form-urlencoded");
            axum::body::Body::from(body)
        }
        None => axum::body::Body::empty(),
    };
    let response = router
        .clone()
        .oneshot(request.body(body).unwrap())
        .await
        .unwrap();
    let status = response.status();
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert_eq!(response.headers()["pragma"], "no-cache");
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
fn resource_http_uses_real_tokens_checks_clients_and_hides_inactive_identity() {
    use axum::http::StatusCode;
    let db = Db::new(TenancyMode::Enabled);
    let initial = setup(&db, "t1");
    confidential(&db);
    let router = embedded_idp_axum::tenant_oidc_resource_router(Arc::new(oidc(&db, "t1", false)));
    let basic = format!(
        "Basic {}",
        Base64::encode_string(b"web:synthetic-client-secret")
    );
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let access = initial.tokens.access_token.expose_secret();
        let refresh = initial.tokens.refresh_token.expose_secret();
        let bearer = format!("Bearer {access}");
        let (status, info) =
            http_request(&router, "/oidc/userinfo", None, Some(bearer.clone()), None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(info["tenant_id"], "t1");
        assert!(info.get("email").is_none());
        assert_eq!(
            http_request(
                &router,
                "/oidc/userinfo",
                None,
                Some(bearer.clone()),
                Some("t2")
            )
            .await
            .0,
            StatusCode::UNAUTHORIZED
        );
        let (status, info) = http_request(
            &router,
            "/oidc/introspect",
            Some(format!("token={access}&token_type_hint=refresh_token")),
            Some(basic.clone()),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(info["active"], true);
        assert_eq!(info["tenant_id"], "t1");
        assert_eq!(info["token_type"], "access_token");
        assert_eq!(
            http_request(
                &router,
                "/oidc/introspect",
                Some("token=invalid&client_id=web".into()),
                None,
                None
            )
            .await
            .0,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            http_request(
                &router,
                "/oidc/introspect",
                Some("token=invalid".into()),
                Some(basic.clone()),
                None
            )
            .await
            .1,
            serde_json::json!({"active":false})
        );
        for invalid in [
            "token=invalid&tenant_id=t2",
            "token=invalid&token=other",
            "token=invalid&client_id=web",
        ] {
            assert!(http_request(
                &router,
                "/oidc/revoke",
                Some(invalid.into()),
                Some(basic.clone()),
                None
            )
            .await
            .0
            .is_client_error());
        }
        assert_eq!(
            http_request(
                &router,
                "/oidc/revoke",
                Some(format!("token={refresh}")),
                Some(basic.clone()),
                Some("t2")
            )
            .await
            .0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            http_request(&router, "/oidc/userinfo", None, Some(bearer.clone()), None)
                .await
                .0,
            StatusCode::OK
        );
        let body =
            format!("refresh_token={refresh}&client_id=web&client_secret=synthetic-client-secret");
        for _ in 0..2 {
            assert_eq!(
                http_request(&router, "/auth/logout", Some(body.clone()), None, None)
                    .await
                    .0,
                StatusCode::OK
            );
        }
        assert_eq!(
            http_request(&router, "/oidc/userinfo", None, Some(bearer), None)
                .await
                .0,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            http_request(
                &router,
                "/oidc/introspect",
                Some(format!("token={refresh}")),
                Some(basic.clone()),
                None
            )
            .await
            .1,
            serde_json::json!({"active":false})
        );
        assert_eq!(
            http_request(
                &router,
                "/oidc/revoke",
                Some("token=invalid".into()),
                Some(basic),
                None
            )
            .await
            .0,
            StatusCode::OK
        );
    });
}
