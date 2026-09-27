use super::*;
use embedded_idp_core::AccessTokenPurpose;
mod http;

type Management = CoreManagementAuthenticationService<
    PostgresAccessStore,
    Rs256JwtService,
    SecureRefreshTokenGenerator,
    Sha256RefreshTokenDigester,
    TestClock,
    UuidV7IdGenerator,
>;

fn management(db: &Db, policy: LoginTenantPolicy) -> Management {
    let key = RsaSigningKeyConfig::from_private_key_der(
        Base64::decode_vec(
            include_str!("../../../embedded-idp-security/tests/fixtures/rsa_3072_key_1.pk8.b64")
                .trim(),
        )
        .unwrap(),
    )
    .unwrap();
    let tokens = Rs256JwtService::new_management(
        ProductionJwtConfig {
            issuer: "https://idp.example.test".into(),
            audience: "management-api".into(),
            scope: "management".into(),
            access_token_ttl_secs: 60,
            refresh_token_ttl_secs: 600,
            clock_skew_secs: 0,
        },
        key,
        vec![],
    )
    .unwrap();
    CoreManagementAuthenticationService::new(
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
            login_entry: "management".into(),
            policy,
            require_device_proof: false,
        },
        db.store(),
        tokens,
        SecureRefreshTokenGenerator,
        Sha256RefreshTokenDigester,
        TestClock,
        UuidV7IdGenerator,
    )
    .unwrap()
}
fn logged_in(service: &Management) -> TenantLoginSession {
    let TenantLoginOutcome::Authenticated(session) = service.login(password()).unwrap() else {
        panic!()
    };
    session
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn management_login_enforces_persisted_purpose_live_authority_refresh_and_logout_in_both_modes() {
    for mode in [TenancyMode::Disabled, TenancyMode::Enabled] {
        let db = Db::new(mode);
        let account = Uuid::parse_str(&prepare(&db)).unwrap();
        let admin = management(
            &db,
            LoginTenantPolicy::Fixed {
                tenant_id: "0".into(),
            },
        );
        let session = logged_in(&admin);
        let token = session.tokens.access_token.clone();
        let context = admin
            .authenticate(token.clone(), "management-test".into())
            .unwrap();
        assert_eq!(context.actor.subject_id, account.to_string());
        assert_eq!(session.session.purpose, AccessTokenPurpose::Management);
        let s = db.schema();
        let mut c = db.adapter.connect().unwrap();
        let id = Uuid::parse_str(&session.session.id).unwrap();
        assert_eq!(
            c.query_one(
                &format!("select purpose from {s}.auth_sessions where id=$1"),
                &[&id]
            )
            .unwrap()
            .get::<_, String>(0),
            "management"
        );
        let admin_service = CoreAccessAdminService::new(
            mode,
            PermissionCatalog::new(vec![]).unwrap(),
            db.store(),
            TestClock,
            UuidV7IdGenerator,
        );
        let target = if mode == TenancyMode::Enabled {
            "t1"
        } else {
            "0"
        };
        let roles = || {
            admin_service.list_roles(
                context.clone(),
                target.into(),
                Some("idp".into()),
                AccessPageRequest::default(),
            )
        };
        // Authentication alone is not an administrator appointment.
        assert_eq!(roles(), Err(AccessError::Forbidden));
        c.execute(&format!("insert into {s}.access_role_bindings(id,tenant_id,business_id,account_id,role_id,scope_kind,resource_type,created_at_epoch,created_by) select $1,'0','idp',$2,role_id,'type',resource_type,100,created_by from {s}.access_role_bindings where tenant_id='0' limit 1"), &[&Uuid::now_v7(), &account]).unwrap();
        assert!(roles().is_ok());
        c.execute(
            &format!("update {s}.auth_sessions set purpose='business' where id=$1"),
            &[&id],
        )
        .unwrap();
        assert!(admin.authenticate(token.clone(), "test".into()).is_err());
        assert!(admin
            .rotate_refresh(session.tokens.refresh_token.clone())
            .is_err());
        assert_eq!(roles(), Err(AccessError::Forbidden));
        c.execute(
            &format!("update {s}.auth_sessions set purpose='management' where id=$1"),
            &[&id],
        )
        .unwrap();
        let ordinary = auth(
            &db,
            LoginTenantPolicy::Fixed {
                tenant_id: target.into(),
            },
            "business",
            false,
            false,
        );
        let TenantLoginOutcome::Authenticated(business) = ordinary.login(password()).unwrap()
        else {
            panic!()
        };
        assert!(admin
            .authenticate(business.tokens.access_token.clone(), "test".into())
            .is_err());
        assert!(admin
            .rotate_refresh(business.tokens.refresh_token.clone())
            .is_err());
        assert!(ordinary.authenticate(token.clone()).is_err());
        assert!(ordinary
            .rotate_refresh(session.tokens.refresh_token.clone())
            .is_err());
        // Wrong-purpose refresh attempts neither rotate nor revoke their target.
        assert!(ordinary
            .authenticate(business.tokens.access_token.clone())
            .is_ok());
        let TenantRefreshOutcome::Rotated { tokens, .. } = admin
            .rotate_refresh(session.tokens.refresh_token.clone())
            .unwrap()
        else {
            panic!()
        };
        assert!(admin
            .authenticate(tokens.access_token.token.clone(), "rotated".into())
            .is_ok());
        assert!(matches!(
            admin.rotate_refresh(session.tokens.refresh_token).unwrap(),
            TenantRefreshOutcome::ReuseDetected { .. }
        ));
        assert!(admin.authenticate(token, "reused".into()).is_err());
        assert!(ordinary.authenticate(business.tokens.access_token).is_ok());
        let fresh = logged_in(&admin);
        admin.logout(fresh.tokens.access_token.clone()).unwrap();
        assert!(admin
            .authenticate(fresh.tokens.access_token, "logout".into())
            .is_err());
        assert!(admin.rotate_refresh(fresh.tokens.refresh_token).is_err());
        let live = logged_in(&admin);
        c.execute(&format!("update {s}.access_memberships set status='suspended' where tenant_id='0' and account_id=$1"), &[&account]).unwrap();
        assert!(admin
            .authenticate(live.tokens.access_token, "suspended".into())
            .is_err());
        assert!(admin.rotate_refresh(live.tokens.refresh_token).is_err());
        assert!(admin.login(password()).is_err());
    }
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn management_selection_is_separate_and_session_creation_is_atomic() {
    let db = Db::new(TenancyMode::Enabled);
    prepare(&db);
    let admin = management(&db, LoginTenantPolicy::ChooseAfterAuthentication);
    let ordinary = auth(
        &db,
        LoginTenantPolicy::ChooseAfterAuthentication,
        "management",
        false,
        false,
    );
    let TenantLoginOutcome::SelectionRequired(a) = admin.login(password()).unwrap() else {
        panic!()
    };
    let b = ticket(&ordinary);
    assert!(admin.select_tenant(b.ticket.clone(), "t1".into()).is_err());
    assert!(ordinary
        .select_tenant(a.ticket.clone(), "t1".into())
        .is_err());
    assert!(admin.select_tenant(a.ticket.clone(), "0".into()).is_err());
    assert_eq!(
        admin
            .list_tenants(a.ticket.clone(), AccessPageRequest::default())
            .unwrap()
            .items
            .len(),
        2
    );
    let s = db.schema();
    let mut c = db.adapter.connect().unwrap();
    c.batch_execute(&format!("create function {s}.fail_management_session() returns trigger language plpgsql as $$ begin raise exception 'test session failure'; end $$; create trigger test_session_failure before insert on {s}.refresh_tokens for each row execute function {s}.fail_management_session()")).unwrap();
    assert!(admin.select_tenant(a.ticket.clone(), "t1".into()).is_err());
    assert_eq!(count(&db, "auth_sessions"), 0);
    c.batch_execute(&format!(
        "drop trigger test_session_failure on {s}.refresh_tokens"
    ))
    .unwrap();
    let selected = admin.select_tenant(a.ticket, "t1".into()).unwrap();
    assert_eq!(selected.session.purpose, AccessTokenPurpose::Management);
    assert!(ordinary.select_tenant(b.ticket, "t1".into()).is_ok());
    let switch = admin.begin_switch(selected.tokens.access_token).unwrap();
    let next = admin.select_tenant(switch.ticket, "t2".into()).unwrap();
    assert_eq!(next.session.tenant_id, "t2");
    assert_eq!(next.session.purpose, AccessTokenPurpose::Management);
    assert!(admin
        .authenticate(next.tokens.access_token, "switched".into())
        .is_ok());
}
