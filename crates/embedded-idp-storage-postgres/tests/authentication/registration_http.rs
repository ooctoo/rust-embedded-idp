use super::*;
use axum::{
    body::{to_bytes, Body},
    http::{HeaderMap, Request, StatusCode},
    Router,
};
use embedded_idp_axum::{tenant_auth_router, tenant_registration_router};
use embedded_idp_email::{EmailSendError, VerificationEmailRequest, VerificationEmailService};
use serde_json::{json, Value};
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Mutex,
};
use tower::ServiceExt;

struct SequenceCodes;
impl VerificationCodeGenerator for SequenceCodes {
    fn generate_code(&self) -> String {
        static NEXT: AtomicU64 = AtomicU64::new(200000);
        NEXT.fetch_add(1, Ordering::SeqCst).to_string()
    }
}
struct Mailbox {
    adapter: PostgresStorageAdapter,
    messages: Mutex<Vec<VerificationEmailRequest>>,
    fail: AtomicBool,
}
impl Mailbox {
    fn new(db: &Db) -> Arc<Self> {
        Arc::new(Self {
            adapter: db.adapter.clone(),
            messages: Mutex::new(vec![]),
            fail: AtomicBool::new(false),
        })
    }
    fn len(&self) -> usize {
        self.messages.lock().unwrap().len()
    }
    fn latest(&self) -> VerificationEmailRequest {
        self.messages.lock().unwrap().last().unwrap().clone()
    }
}
impl VerificationEmailService for Mailbox {
    fn send_verification_email(
        &self,
        request: VerificationEmailRequest,
    ) -> Result<(), EmailSendError> {
        // A separate connection must already see the committed registration/code.
        let exists:bool=self.adapter.connect().unwrap().query_one(&format!("select exists(select 1 from {}.email_verification_codes where email=$1 and code=$2)",self.adapter.schema_name()),&[&request.email,&request.code]).unwrap().get(0);
        assert!(exists, "delivery preceded commit");
        self.messages.lock().unwrap().push(request);
        if self.fail.load(Ordering::SeqCst) {
            Err(EmailSendError::new(
                "synthetic provider detail must stay private",
            ))
        } else {
            Ok(())
        }
    }
}
fn policy(mode: TenancyMode, tenant: &str) -> LoginTenantPolicy {
    if mode == TenancyMode::Enabled {
        LoginTenantPolicy::ChooseAfterAuthentication
    } else {
        LoginTenantPolicy::Fixed {
            tenant_id: tenant.into(),
        }
    }
}
fn app(db: &Db, policy: LoginTenantPolicy, mailbox: Arc<Mailbox>) -> Router {
    let service = CoreTenantRegistrationService::new(
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
        db.store(),
        TestClock,
        UuidV7IdGenerator,
        SequenceCodes,
    )
    .unwrap();
    Router::new().nest(
        "/api",
        tenant_registration_router(Arc::new(service), policy.clone(), mailbox)
            .unwrap()
            .merge(tenant_auth_router(Arc::new(auth(
                db,
                policy,
                "registration-http",
                false,
                false,
            )))),
    )
}
fn send(app: &Router, path: &str, body: Value) -> (StatusCode, Value) {
    send_headers(app, path, body, HeaderMap::new())
}
fn send_headers(app: &Router, path: &str, body: Value, headers: HeaderMap) -> (StatusCode, Value) {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let mut request = Request::builder()
                .method("POST")
                .uri(format!("/api{path}"))
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap();
            request.headers_mut().extend(headers);
            let response = app.clone().oneshot(request).await.unwrap();
            assert_eq!(response.headers()["cache-control"], "no-store");
            assert_eq!(response.headers()["pragma"], "no-cache");
            let status = response.status();
            let bytes = to_bytes(response.into_body(), 65536).await.unwrap();
            (status, serde_json::from_slice(&bytes).unwrap())
        })
}
fn register_body(tenant: &str) -> Value {
    json!({"tenant_id":tenant,"email":"new@example.test","password":"Test-password-123","display_name":"New"})
}
fn resend_body(tenant: &str) -> Value {
    json!({"tenant_id":tenant,"email":"new@example.test"})
}
fn verify_body(tenant: &str, code: &str) -> Value {
    json!({"tenant_id":tenant,"email":"new@example.test","verification_code":code})
}
const ACCEPTED: &str = "verification_requested";
fn active_codes(db: &Db) -> i64 {
    db.adapter
        .connect()
        .unwrap()
        .query_one(
            &format!(
                "select count(*) from {}.email_verification_codes where consumed_at_epoch is null",
                db.schema()
            ),
            &[],
        )
        .unwrap()
        .get(0)
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn http_registration_resend_verify_and_login_complete_in_both_modes() {
    for (mode, tenant) in [(TenancyMode::Disabled, "0"), (TenancyMode::Enabled, "t1")] {
        let db = Db::new(mode);
        db.adapter.connect().unwrap().batch_execute(&format!("insert into {}.oidc_clients(client_id,client_name,redirect_uris_json,client_type,pkce_required,created_at_epoch) values ('web','Web','[\"testapp://callback\"]','public_desktop',true,1)",db.schema())).unwrap();
        let mail = Mailbox::new(&db);
        mail.fail.store(true, Ordering::SeqCst);
        let app = app(&db, policy(mode, tenant), mail.clone());
        let (status, created) = send(&app, "/auth/register", register_body(tenant));
        assert_eq!(status, StatusCode::ACCEPTED);
        assert_eq!(created["tenant_id"], tenant);
        assert_eq!(created["delivery_status"], "failed");
        assert_eq!(created["account_status"], "pending_verification");
        let original = mail.latest();
        assert!(!created.to_string().contains(&original.code));
        assert!(!created.to_string().contains("synthetic provider"));
        assert!(created.get("password").is_none() && created.get("tokens").is_none());
        assert_eq!(count(&db, "auth_sessions"), 0);
        assert_eq!(
            send(&app, "/auth/register", register_body(tenant)).0,
            StatusCode::CONFLICT
        );
        assert_eq!(mail.len(), 1);
        assert!(!send(
            &app,
            "/auth/login",
            json!({"email":"new@example.test","password":"Test-password-123"})
        )
        .0
        .is_success());
        mail.fail.store(false, Ordering::SeqCst);
        let (status, result) = send(&app, "/auth/resend-verification", resend_body(tenant));
        assert_eq!(status, StatusCode::ACCEPTED);
        assert_eq!(result, json!({"status":ACCEPTED}));
        let replacement = mail.latest();
        assert_ne!(original.code, replacement.code);
        assert_eq!(active_codes(&db), 1);
        assert_eq!(
            send(
                &app,
                "/auth/verify-email",
                verify_body(tenant, &original.code)
            )
            .0,
            StatusCode::UNAUTHORIZED
        );
        if mode == TenancyMode::Enabled {
            assert_eq!(
                send(&app, "/auth/register", register_body("t2")).0,
                StatusCode::CONFLICT
            );
            assert_eq!(
                send(
                    &app,
                    "/auth/verify-email",
                    verify_body("t2", &replacement.code)
                )
                .0,
                StatusCode::UNAUTHORIZED
            );
            let account = Uuid::parse_str(created["account_id"].as_str().unwrap()).unwrap();
            let members: i64 = db
                .adapter
                .connect()
                .unwrap()
                .query_one(
                    &format!(
                        "select count(*) from {}.access_memberships where account_id=$1",
                        db.schema()
                    ),
                    &[&account],
                )
                .unwrap()
                .get(0);
            assert_eq!(members, 1);
        }
        let (status, verified) = send(
            &app,
            "/auth/verify-email",
            verify_body(tenant, &replacement.code),
        );
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            verified,
            json!({"tenant_id":tenant,"account_id":created["account_id"],"account_status":"active"})
        );
        assert_eq!(count(&db, "auth_sessions"), 0);
        assert_eq!(count(&db, "refresh_tokens"), 0);
        assert_eq!(count(&db, "devices"), 0);
        assert_eq!(
            send(
                &app,
                "/auth/verify-email",
                verify_body(tenant, &replacement.code)
            )
            .0,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            send(&app, "/auth/resend-verification", resend_body(tenant)).1,
            result
        );
        assert_eq!(mail.len(), 2);
        let (status, mut login) = send(
            &app,
            "/auth/login",
            json!({"email":"new@example.test","password":"Test-password-123"}),
        );
        assert_eq!(status, StatusCode::OK);
        if mode == TenancyMode::Enabled {
            assert_eq!(login["status"], "tenant_selection_required");
            let mut headers = HeaderMap::new();
            headers.insert(
                "authorization",
                format!(
                    "TenantSelection {}",
                    login["selection_ticket"].as_str().unwrap()
                )
                .parse()
                .unwrap(),
            );
            let selected = send_headers(
                &app,
                "/auth/tenant-selection/complete",
                json!({"tenant_id":tenant}),
                headers,
            );
            assert_eq!(selected.0, StatusCode::OK);
            login = selected.1;
        }
        assert_eq!(login["session"]["tenant_id"], tenant);
        assert_eq!(login["session"]["account_id"], created["account_id"]);
        assert_eq!(count(&db, "auth_sessions"), 1);
    }
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn http_resend_hides_ineligible_accounts_and_preserves_registration_tenant() {
    let db = Db::new(TenancyMode::Enabled);
    let mail = Mailbox::new(&db);
    let app = app(
        &db,
        LoginTenantPolicy::ChooseAfterAuthentication,
        mail.clone(),
    );
    let created = send(&app, "/auth/register", register_body("t1")).1;
    let id = Uuid::parse_str(created["account_id"].as_str().unwrap()).unwrap();
    let s = db.schema();
    db.adapter.connect().unwrap().execute(&format!("insert into {s}.access_memberships(tenant_id,account_id,status,joined_at_epoch) values ('t2',$1,'active',100)"),&[&id]).unwrap();
    for body in [
        resend_body("t2"),
        resend_body("missing-tenant"),
        json!({"tenant_id":"t1","email":"absent@example.test"}),
    ] {
        assert_eq!(
            send(&app, "/auth/resend-verification", body),
            (StatusCode::ACCEPTED, json!({"status":ACCEPTED}))
        );
    }
    for (disable,restore) in [
        (format!("update {s}.access_tenants set status='suspended' where id='t1'"),format!("update {s}.access_tenants set status='active' where id='t1'")),
        (format!("update {s}.access_memberships set status='suspended' where tenant_id='t1'"),format!("update {s}.access_memberships set status='active' where tenant_id='t1'")),
        (format!("update {s}.accounts set status='active' where email='new@example.test'"),format!("update {s}.accounts set status='pending_verification' where email='new@example.test'")),
        (format!("update {s}.accounts set status='disabled' where email='new@example.test'"),format!("update {s}.accounts set status='pending_verification' where email='new@example.test'")),
        (format!("update {s}.accounts set status='closed' where email='new@example.test'"),format!("update {s}.accounts set status='pending_verification' where email='new@example.test'")),
    ] {
        let mut conn=db.adapter.connect().unwrap();conn.batch_execute(&disable).unwrap();
        assert_eq!(send(&app,"/auth/resend-verification",resend_body("t1")),(StatusCode::ACCEPTED,json!({"status":ACCEPTED})));
        conn.batch_execute(&restore).unwrap();
    }
    assert_eq!(mail.len(), 1);
    assert_eq!(active_codes(&db), 1);
    db.adapter
        .connect()
        .unwrap()
        .batch_execute(&format!(
            "update {s}.access_tenants set allow_registration=false where id='t1'"
        ))
        .unwrap();
    assert_eq!(
        send(&app, "/auth/resend-verification", resend_body("t1")).0,
        StatusCode::ACCEPTED
    );
    assert_eq!(mail.len(), 2);
    assert_eq!(
        send(
            &app,
            "/auth/verify-email",
            verify_body("t1", &mail.latest().code)
        )
        .0,
        StatusCode::OK
    );
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn http_registration_and_resend_failures_rollback_and_concurrent_resends_leave_one_code() {
    let db = Db::new(TenancyMode::Enabled);
    let mail = Mailbox::new(&db);
    let app = app(
        &db,
        LoginTenantPolicy::Fixed {
            tenant_id: "t1".into(),
        },
        mail.clone(),
    );
    let s = db.schema();
    let trigger=format!("create trigger reject_mail_insert before insert on {s}.email_verification_codes for each row execute function {s}.reject_mail_insert()");
    db.adapter.connect().unwrap().batch_execute(&format!("create function {s}.reject_mail_insert() returns trigger language plpgsql as $$ begin raise exception 'synthetic failure'; end $$;{trigger}")).unwrap();
    let accounts = count(&db, "accounts");
    let members = count(&db, "access_memberships");
    assert_eq!(
        send(&app, "/auth/register", register_body("t1")).0,
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert_eq!(count(&db, "accounts"), accounts);
    assert_eq!(count(&db, "access_memberships"), members);
    assert_eq!(mail.len(), 0);
    db.adapter
        .connect()
        .unwrap()
        .batch_execute(&format!(
            "drop trigger reject_mail_insert on {s}.email_verification_codes"
        ))
        .unwrap();
    assert_eq!(
        send(&app, "/auth/register", register_body("t1")).0,
        StatusCode::ACCEPTED
    );
    let original = mail.latest();
    db.adapter
        .connect()
        .unwrap()
        .batch_execute(&trigger)
        .unwrap();
    assert_eq!(
        send(&app, "/auth/resend-verification", resend_body("t1")).0,
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert_eq!(mail.len(), 1);
    assert_eq!(active_codes(&db), 1);
    assert_eq!(count(&db, "email_verification_codes"), 1);
    db.adapter
        .connect()
        .unwrap()
        .batch_execute(&format!(
            "drop trigger reject_mail_insert on {s}.email_verification_codes"
        ))
        .unwrap();
    let barrier = Arc::new(Barrier::new(2));
    let handles: Vec<_> = (0..2)
        .map(|_| {
            let app = app.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                send(&app, "/auth/resend-verification", resend_body("t1"))
            })
        })
        .collect();
    for handle in handles {
        assert_eq!(handle.join().unwrap().0, StatusCode::ACCEPTED);
    }
    assert_eq!(active_codes(&db), 1);
    assert_eq!(count(&db, "email_verification_codes"), 3);
    assert_eq!(mail.len(), 3);
    assert_eq!(
        send(
            &app,
            "/auth/verify-email",
            verify_body("t1", &original.code)
        )
        .0,
        StatusCode::UNAUTHORIZED
    );
    let current: String = db
        .adapter
        .connect()
        .unwrap()
        .query_one(
            &format!(
                "select code from {s}.email_verification_codes where consumed_at_epoch is null"
            ),
            &[],
        )
        .unwrap()
        .get(0);
    assert_eq!(
        send(&app, "/auth/verify-email", verify_body("t1", &current)).0,
        StatusCode::OK
    );
}
