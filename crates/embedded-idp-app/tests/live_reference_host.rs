//! Runs the actual reference binary. Opt-in PostgreSQL, disposable schemas only.
use base64ct::{Base64, Encoding};
use embedded_idp_core::{
    access::*, AuthConfig, IdGenerator, SecretString, SystemClock, UuidV7IdGenerator,
};
use embedded_idp_storage_postgres::*;
use serde_json::{json, Value};
use std::{
    env, fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::PathBuf,
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};
struct Db {
    adapter: PostgresStorageAdapter,
    uri: String,
    mode: TenancyMode,
    dir: PathBuf,
}
impl Db {
    fn new(mode: TenancyMode) -> Self {
        let uri = env::var("EMBEDDED_IDP_TEST_PG_CONNECTION_URI")
            .expect("explicit test database required");
        let id = UuidV7IdGenerator.next_id("schema").replace('-', "");
        let dir = env::temp_dir().join(format!("idp-runtime-{id}"));
        fs::create_dir(&dir).unwrap();
        let key = Base64::decode_vec(
            include_str!("../../embedded-idp-security/tests/fixtures/rsa_3072_key_1.pk8.b64")
                .trim(),
        )
        .unwrap();
        let path = dir.join("key.der");
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .unwrap();
        file.write_all(&key).unwrap();
        let adapter = PostgresStorageAdapter::new(PgStorageConfig {
            connection: PgConnectionConfig {
                connection_uri: uri.clone(),
                schema_name: format!("idp_runtime_it_{id}"),
                tls_mode: PgTlsMode::Disable,
                tls_ca_cert_path: None,
            },
            pool: DbPoolConfig {
                application_name: "idp-runtime-test".into(),
                max_connections: 2,
                connect_timeout_secs: 3,
            },
        })
        .unwrap();
        adapter
            .initialize_access_schema(mode, &PermissionCatalog::new(vec![]).unwrap())
            .unwrap();
        Self {
            adapter,
            uri,
            mode,
            dir,
        }
    }
    fn bootstrap(&self) {
        CoreAccessBootstrapService::new(
            self.mode,
            self.adapter.clone(),
            SystemClock,
            UuidV7IdGenerator,
        )
        .initialize_administrator(
            &AuthConfig {
                allow_local_registration: true,
                access_token_ttl_secs: 900,
                refresh_token_ttl_secs: 86400,
                session_ttl_secs: 604800,
                verification_code_ttl_secs: 900,
                password_min_length: 8,
                password_max_length: 128,
            },
            BootstrapAdministrator {
                email: "admin@example.test".into(),
                display_name: None,
                password: SecretString::new("Runtime-Admin123"),
                request_id: "runtime-test".into(),
            },
        )
        .unwrap();
    }
    fn command(&self, port: u16) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_embedded-idp-app"));
        for (key, _) in env::vars().filter(|(key, _)| key.starts_with("EMBEDDED_IDP_")) {
            cmd.env_remove(key);
        }
        cmd.env(
            "EMBEDDED_IDP_APP_TENANCY_MODE",
            if self.mode == TenancyMode::Enabled {
                "enabled"
            } else {
                "disabled"
            },
        )
        .env("EMBEDDED_IDP_APP_PG_URI", &self.uri)
        .env("EMBEDDED_IDP_APP_PG_SCHEMA", self.adapter.schema_name())
        .env("EMBEDDED_IDP_APP_PG_TLS_MODE", "disable")
        .env("EMBEDDED_IDP_APP_BIND_ADDR", format!("127.0.0.1:{port}"))
        .env(
            "EMBEDDED_IDP_APP_SIGNING_KEY_FILE",
            self.dir.join("key.der"),
        )
        .env("EMBEDDED_IDP_APP_ADMIN_API_KEY", "ignored-legacy-key")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
        cmd
    }
    fn start(&self) -> Host {
        self.start_with(&[])
    }
    fn start_with(&self, settings: &[(&str, &str)]) -> Host {
        let port = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let mut host = Host {
            child: self
                .command(port)
                .envs(settings.iter().copied())
                .spawn()
                .unwrap(),
            port,
        };
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            assert!(
                host.child.try_wait().unwrap().is_none(),
                "reference host exited before readiness"
            );
            if let Ok(mut stream) = TcpStream::connect(("127.0.0.1", port)) {
                stream
                    .write_all(
                        b"GET /readyz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
                    )
                    .unwrap();
                let mut reply = String::new();
                stream.read_to_string(&mut reply).unwrap();
                if reply.starts_with("HTTP/1.1 200") {
                    break;
                }
            }
            assert!(
                Instant::now() < deadline,
                "reference host readiness timed out"
            );
            thread::sleep(Duration::from_millis(50));
        }
        host
    }
    fn start_with_scan_login(&self) -> Host {
        let port = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let origin = format!("http://127.0.0.1:{port}");
        let mut host = Host {
            child: self
                .command(port)
                .env("EMBEDDED_IDP_APP_BROWSER_ORIGIN", &origin)
                .env("EMBEDDED_IDP_APP_SCAN_LOGIN_ENABLED", "true")
                .env(
                    "EMBEDDED_IDP_APP_SCAN_LOGIN_ENTRY_ID",
                    "reference-device-scan",
                )
                .env(
                    "EMBEDDED_IDP_APP_SCAN_LOGIN_ALLOWED_SOURCE_CLIENT_IDS",
                    "desktop-app",
                )
                .env("EMBEDDED_IDP_APP_SCAN_LOGIN_MODES", "device_display")
                .env(
                    "EMBEDDED_IDP_APP_SCAN_LOGIN_VERIFICATION_URI",
                    format!("{origin}/auth/browser/device-scan/ui"),
                )
                .env("EMBEDDED_IDP_APP_SCAN_LOGIN_RESULT_KEY_ID", "test-key")
                .env(
                    "EMBEDDED_IDP_APP_SCAN_LOGIN_RESULT_KEY_BASE64URL",
                    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                )
                .spawn()
                .unwrap(),
            port,
        };
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            assert!(
                host.child.try_wait().unwrap().is_none(),
                "scan reference host exited before readiness"
            );
            if let Ok(mut stream) = TcpStream::connect(("127.0.0.1", port)) {
                stream
                    .write_all(
                        b"GET /readyz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
                    )
                    .unwrap();
                let mut reply = String::new();
                stream.read_to_string(&mut reply).unwrap();
                if reply.starts_with("HTTP/1.1 200") {
                    break;
                }
            }
            assert!(
                Instant::now() < deadline,
                "scan reference host readiness timed out"
            );
            thread::sleep(Duration::from_millis(50));
        }
        host
    }
}
impl Drop for Db {
    fn drop(&mut self) {
        assert!(self.adapter.schema_name().starts_with("idp_runtime_it_"));
        if let Ok(mut c) = self.adapter.connect() {
            let _ = c.batch_execute(&format!(
                "drop schema {} cascade",
                self.adapter.schema_name()
            ));
        }
        let _ = fs::remove_dir_all(&self.dir);
    }
}
struct Host {
    child: Child,
    port: u16,
}
impl Drop for Host {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
impl Host {
    fn raw(
        &self,
        method: &str,
        path: &str,
        token: Option<&str>,
        tenant: Option<&str>,
        body: Option<Value>,
    ) -> (u16, String) {
        let scoped = [
            "/api/admin/access/roles",
            "/api/admin/access/permissions",
            "/api/admin/access/check",
            "/api/admin/access/business-admin",
            "/api/admin/access/subjects",
            "/api/admin/access/role-bindings",
        ]
        .iter()
        .any(|prefix| path.starts_with(prefix));
        self.raw_business(
            method,
            path,
            token,
            tenant,
            body,
            scoped.then_some("runtime"),
        )
    }
    fn raw_business(
        &self,
        method: &str,
        path: &str,
        token: Option<&str>,
        tenant: Option<&str>,
        body: Option<Value>,
        business: Option<&str>,
    ) -> (u16, String) {
        let mut stream = TcpStream::connect(("127.0.0.1", self.port)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let body = body.map(|b| b.to_string()).unwrap_or_default();
        let mut request=format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nx-embedded-idp-admin-key: ignored-legacy-key\r\nx-embedded-idp-account-id: forged-subject\r\nContent-Length: {}\r\n",body.len());
        if !body.is_empty() {
            request.push_str("Content-Type: application/json\r\n");
        }
        if let Some(token) = token {
            let scheme = if path.starts_with("/auth/tenant-selection/") {
                "TenantSelection"
            } else {
                "Bearer"
            };
            request.push_str(&format!("Authorization: {scheme} {token}\r\n"));
        }
        if let Some(tenant) = tenant {
            request.push_str(&format!("x-embedded-idp-tenant-id: {tenant}\r\n"));
        }
        if let Some(business) = business {
            request.push_str(&format!("x-embedded-idp-business-id: {business}\r\n"));
        }
        request.push_str("\r\n");
        request.push_str(&body);
        stream.write_all(request.as_bytes()).unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        let (headers, body) = response.split_once("\r\n\r\n").unwrap();
        (
            headers.split_whitespace().nth(1).unwrap().parse().unwrap(),
            body.into(),
        )
    }
    fn json(
        &self,
        method: &str,
        path: &str,
        token: Option<&str>,
        tenant: Option<&str>,
        body: Option<Value>,
        expected: u16,
    ) -> Value {
        let (status, body) = self.raw(method, path, token, tenant, body);
        assert_eq!(status, expected, "{method} {path}: {body}");
        serde_json::from_str(&body).unwrap_or(Value::Null)
    }
}
fn token(v: &Value) -> &str {
    v["tokens"]["access_token"].as_str().unwrap()
}
fn login(host: &Host, management: bool, email: &str, password: &str) -> Value {
    host.json(
        "POST",
        if management {
            "/api/admin/auth/login"
        } else {
            "/auth/login"
        },
        None,
        None,
        Some(json!({"email":email,"password":password})),
        200,
    )
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn reference_host_runs_management_and_business_flows_in_both_modes() {
    for mode in [TenancyMode::Disabled, TenancyMode::Enabled] {
        let db = Db::new(mode);
        db.bootstrap();
        let host = db.start();
        let cap = host.json("GET", "/api/admin/auth/capabilities", None, None, None, 200);
        assert_eq!(cap["tenancy_enabled"], mode == TenancyMode::Enabled);
        assert_eq!(cap["fixed_tenant_id"], "0");
        let (status, html) = host.raw("GET", "/", None, None, None);
        assert_eq!(status, 200);
        assert!(html.contains("身份管理控制台"));
        let asset = html
            .split("src=\"")
            .nth(1)
            .unwrap()
            .split('"')
            .next()
            .unwrap();
        assert_eq!(host.raw("GET", asset, None, None, None).0, 200);
        let jwks = host.json("GET", "/oidc/jwks", None, None, None, 200);
        assert_eq!(jwks["keys"][0]["alg"], "RS256");
        assert!(jwks["keys"][0].get("d").is_none());
        host.json("GET", "/api/admin/access/roles", None, None, None, 401);
        let admin = login(&host, true, "admin@example.test", "Runtime-Admin123");
        let bearer = token(&admin);
        host.json("GET", "/auth/session", Some(bearer), None, None, 401);
        let tenant = if mode == TenancyMode::Enabled {
            "runtime-a"
        } else {
            "0"
        };
        let target = (mode == TenancyMode::Enabled).then_some(tenant);
        let subject = if mode == TenancyMode::Enabled {
            let created=host.json("POST","/api/admin/tenants",Some(bearer),None,Some(json!({"tenant_id":tenant,"name":"Runtime tenant","allow_registration":true,"administrator":{"kind":"new","email":"member@example.test","password":"Runtime-Member123"}})),201);
            assert_eq!(created["tenant"]["tenant_id"], tenant);
            let members = host.json(
                "GET",
                "/api/admin/accounts",
                Some(bearer),
                target,
                None,
                200,
            );
            members["items"][0]["account_id"]
                .as_str()
                .unwrap()
                .to_owned()
        } else {
            host.json("GET", "/api/admin/tenants", Some(bearer), None, None, 404);
            let created=host.json("POST","/api/admin/platform/accounts",Some(bearer),None,Some(json!({"tenant_id":"0","email":"member@example.test","password":"Runtime-Member123"})),200);
            created["account"]["account_id"]
                .as_str()
                .unwrap()
                .to_owned()
        };
        host.json(
            "POST",
            "/api/admin/access/roles",
            Some(bearer),
            target,
            Some(json!({"key":"reviewer","name":"Reviewer"})),
            201,
        );
        // End-to-end business-admin behavior uses the same authenticated HTTP boundary.
        let request_business =
            |business: &str, method: &str, path: &str, body: Option<Value>, expected| {
                let (status, body) =
                    host.raw_business(method, path, Some(bearer), target, body, Some(business));
                assert_eq!(status, expected, "{method} {path}: {body}");
                serde_json::from_str::<Value>(&body).unwrap()
            };
        for business in ["runtime", "other"] {
            request_business(
                business,
                "POST",
                "/api/admin/access/permissions",
                Some(json!({"resource_type":"report","action":"read","description":"Read"})),
                200,
            );
        }
        let created = request_business(
            "runtime",
            "POST",
            "/api/admin/access/business-admin",
            Some(json!({"name":"Runtime administrator"})),
            201,
        );
        assert_eq!(created["role"]["kind"], "business_admin");
        assert_eq!(created["role"]["key"], "business_admin");
        assert_eq!(created["role"]["business_id"], "runtime");
        assert_eq!(created["role"]["permissions"], json!([]));
        let role_id = created["role"]["role_id"].as_str().unwrap();
        request_business(
            "runtime",
            "POST",
            "/api/admin/access/business-admin",
            Some(json!({})),
            409,
        );
        request_business(
            "other",
            "GET",
            &format!("/api/admin/access/roles/{role_id}"),
            None,
            404,
        );
        let binding = request_business(
            "runtime",
            "POST",
            &format!("/api/admin/access/subjects/{subject}/role-bindings"),
            Some(json!({"role_id":role_id,"scope":{"kind":"business"}})),
            201,
        );
        assert!(binding["binding"].get("resource_type").is_none());
        request_business(
            "runtime",
            "DELETE",
            &format!("/api/admin/access/roles/{role_id}"),
            Some(json!({"expected_version":created["role"]["version"]})),
            409,
        );
        let check = json!({"subject_id":subject,"resource_type":"report","action":"read","resource_id":"any-instance"});
        assert_eq!(
            request_business(
                "runtime",
                "POST",
                "/api/admin/access/check",
                Some(check.clone()),
                200
            )["decision"],
            "allow"
        );
        assert_eq!(
            request_business(
                "other",
                "POST",
                "/api/admin/access/check",
                Some(check.clone()),
                200
            )["decision"],
            "deny"
        );
        request_business(
            "runtime",
            "POST",
            "/api/admin/access/permissions",
            Some(
                json!({"resource_type":"new_resource","action":"write","description":"Added later"}),
            ),
            200,
        );
        assert_eq!(
            request_business(
                "runtime",
                "POST",
                "/api/admin/access/check",
                Some(json!({"subject_id":subject,"resource_type":"new_resource","action":"write"})),
                200
            )["decision"],
            "allow"
        );
        request_business(
            "runtime",
            "POST",
            "/api/admin/access/permissions/report/read/enabled",
            Some(json!({"enabled":false,"expected_enabled":true})),
            200,
        );
        assert_eq!(
            request_business(
                "runtime",
                "POST",
                "/api/admin/access/check",
                Some(check),
                200
            )["decision"],
            "deny"
        );
        request_business(
            "runtime",
            "DELETE",
            &format!(
                "/api/admin/access/role-bindings/{}",
                binding["binding"]["binding_id"].as_str().unwrap()
            ),
            None,
            200,
        );
        assert_eq!(
            request_business(
                "runtime",
                "POST",
                "/api/admin/access/check",
                Some(json!({"subject_id":subject,"resource_type":"new_resource","action":"write"})),
                200
            )["decision"],
            "deny"
        );
        request_business(
            "runtime",
            "DELETE",
            &format!("/api/admin/access/roles/{role_id}"),
            Some(json!({"expected_version":created["role"]["version"]})),
            200,
        );
        let appointment = format!("/api/admin/access/security-admins/{subject}");
        if mode == TenancyMode::Disabled {
            host.json("POST", &appointment, Some(bearer), target, None, 201);
        }
        assert!(
            !host.json("GET", &appointment, Some(bearer), target, None, 200)["binding"].is_null()
        );
        let business = login(&host, false, "member@example.test", "Runtime-Member123");
        let business = if mode == TenancyMode::Enabled {
            assert_eq!(business["status"], "tenant_selection_required");
            let selection = business["selection_ticket"].as_str().unwrap();
            let list = host.json(
                "GET",
                "/auth/tenant-selection/tenants",
                Some(selection),
                None,
                None,
                200,
            );
            assert_eq!(list["tenants"].as_array().unwrap().len(), 1);
            host.json(
                "POST",
                "/auth/tenant-selection/complete",
                Some(selection),
                None,
                Some(json!({"tenant_id":tenant})),
                200,
            )
        } else {
            business
        };
        host.json(
            "GET",
            "/api/admin/access/roles",
            Some(token(&business)),
            target,
            None,
            401,
        );
        host.json(
            "GET",
            "/oidc/userinfo",
            Some(token(&business)),
            None,
            None,
            200,
        );
        host.json(
            "POST",
            "/devices/provision",
            None,
            None,
            Some(json!({"tenant_id":tenant,"device_id":UuidV7IdGenerator.next_id("device"),"registration_request_id":UuidV7IdGenerator.next_id("registration"),"device_name":"Not admitted","public_jwk":{}})),
            401,
        );
        // Create a second tenant admin before revoking the initial administrator.
        if mode == TenancyMode::Enabled {
            let second=host.json("POST","/api/admin/platform/accounts",Some(bearer),None,Some(json!({"tenant_id":tenant,"email":"second@example.test","password":"Runtime-Second123"})),200);
            let id = second["account"]["account_id"].as_str().unwrap();
            host.json(
                "POST",
                &format!("/api/admin/access/security-admins/{id}"),
                Some(bearer),
                target,
                None,
                201,
            );
        }
        host.json("DELETE", &appointment, Some(bearer), target, None, 200);
        assert!(
            host.json("GET", &appointment, Some(bearer), target, None, 200)["binding"].is_null()
        );
        let rotated = host.json(
            "POST",
            "/api/admin/auth/refresh",
            None,
            None,
            Some(json!({"refresh_token":admin["tokens"]["refresh_token"]})),
            200,
        );
        let rotated_token = token(&rotated);
        host.json(
            "POST",
            "/api/admin/auth/logout",
            Some(rotated_token),
            None,
            None,
            204,
        );
        host.json(
            "GET",
            "/api/admin/auth/session",
            Some(rotated_token),
            None,
            None,
            401,
        );
        // Restart preserves existing client configuration instead of resetting it from env.
        drop(host);
        db.adapter.connect().unwrap().execute(&format!("update {}.oidc_clients set client_name='Admin edited' where client_id='desktop-app'",db.adapter.schema_name()),&[]).unwrap();
        let host = db.start();
        assert_eq!(
            db.adapter
                .connect()
                .unwrap()
                .query_one(
                    &format!(
                        "select client_name from {}.oidc_clients where client_id='desktop-app'",
                        db.adapter.schema_name()
                    ),
                    &[]
                )
                .unwrap()
                .get::<_, String>(0),
            "Admin edited"
        );
        host.json("GET", "/readyz", None, None, None, 200);
        drop(host);
        if mode == TenancyMode::Enabled {
            let fixed = db.start_with(&[
                ("EMBEDDED_IDP_APP_LOGIN_POLICY", "fixed"),
                ("EMBEDDED_IDP_APP_LOGIN_TENANT_ID", tenant),
                ("EMBEDDED_IDP_APP_MANAGEMENT_TENANT_ID", tenant),
            ]);
            let tenant_admin = login(&fixed, true, "second@example.test", "Runtime-Second123");
            assert_eq!(tenant_admin["session"]["tenant_id"], tenant);
            fixed.json(
                "GET",
                "/api/admin/access/roles",
                Some(token(&tenant_admin)),
                None,
                None,
                200,
            );
            fixed.json(
                "GET",
                "/api/admin/tenants",
                Some(token(&tenant_admin)),
                None,
                None,
                403,
            );
            assert_eq!(
                login(&fixed, false, "member@example.test", "Runtime-Member123")["session"]
                    ["tenant_id"],
                tenant
            );
            drop(fixed);
            let choose = db.start_with(&[("EMBEDDED_IDP_APP_MANAGEMENT_LOGIN_POLICY", "choose")]);
            let selection = login(&choose, true, "second@example.test", "Runtime-Second123");
            assert_eq!(selection["status"], "tenant_selection_required");
        }
    }
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn reference_host_refuses_uninitialized_or_wrong_mode_without_mutating_schema() {
    let db = Db::new(TenancyMode::Enabled);
    assert!(!db.command(0).status().unwrap().success());
    db.bootstrap();
    assert!(!db
        .command(0)
        .env("EMBEDDED_IDP_APP_TENANCY_MODE", "disabled")
        .status()
        .unwrap()
        .success());
    assert_eq!(
        db.adapter
            .connect()
            .unwrap()
            .query_one(
                &format!(
                    "select count(*) from {}.oidc_clients",
                    db.adapter.schema_name()
                ),
                &[]
            )
            .unwrap()
            .get::<_, i64>(0),
        0
    );
}

fn seed_active_device_for_scan_challenges(db: &Db) -> String {
    let device_id = "88888888-8888-4888-8888-888888888888";
    let key_id = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let schema = db.adapter.schema_name();
    let mut client = db.adapter.connect().unwrap();
    client
        .batch_execute(&format!(
            "begin;
             insert into {schema}.devices(tenant_id,id,client_id,device_name,proof_key_id,status,version,registered_at_epoch)
             values('0','{device_id}','desktop-app','scan proof test','{key_id}','active',1,1);
             insert into {schema}.device_proof_keys(tenant_id,key_id,device_id,algorithm,public_jwk,version,status,registered_at_epoch)
             values('0','{key_id}','{device_id}','ed25519','{{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"}}',1,'active',1);
             commit;"
        ))
        .unwrap();
    device_id.into()
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn reference_scan_login_enables_all_device_proof_challenge_purposes() {
    let db = Db::new(TenancyMode::Disabled);
    db.bootstrap();
    let host = db.start_with_scan_login();
    let device_id = seed_active_device_for_scan_challenges(&db);
    for action in [
        ScanLoginAction::Create,
        ScanLoginAction::Claim,
        ScanLoginAction::Status,
        ScanLoginAction::Lookup,
        ScanLoginAction::Cancel,
        ScanLoginAction::Exchange,
        ScanLoginAction::Recover,
        ScanLoginAction::Acknowledge,
        ScanLoginAction::Abort,
        ScanLoginAction::CloseOrigin,
    ] {
        let body = host.json(
            "POST",
            "/devices/proof/challenges",
            None,
            Some("0"),
            Some(
                json!({"tenant_id":"0","device_id":device_id,"purpose":action.purpose().as_str()}),
            ),
            200,
        );
        assert!(body["challenge"].as_str().is_some());
    }
}

/// Uses the real HTTP server and database; Cookie handling is explicit so the
/// test can also submit stale/wrong-purpose credentials deliberately.
impl Host {
    fn browser(
        &self,
        path: &str,
        cookie: Option<&str>,
        ticket: Option<&str>,
        body: Value,
    ) -> (u16, Option<String>, Value) {
        self.browser_with_origin(
            path,
            cookie,
            ticket,
            body,
            &format!("http://127.0.0.1:{}", self.port),
        )
    }
    fn browser_with_origin(
        &self,
        path: &str,
        cookie: Option<&str>,
        ticket: Option<&str>,
        body: Value,
        origin: &str,
    ) -> (u16, Option<String>, Value) {
        let body = body.to_string();
        let mut request = format!("POST {path} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nOrigin: {origin}\r\nX-Embedded-Idp-Browser: 1\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n", self.port, body.len());
        if let Some(cookie) = cookie {
            request.push_str(&format!("Cookie: {cookie}\r\n"));
        }
        if let Some(ticket) = ticket {
            request.push_str(&format!("Authorization: TenantSelection {ticket}\r\n"));
        }
        request.push_str("\r\n");
        request.push_str(&body);
        let mut stream = TcpStream::connect(("127.0.0.1", self.port)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream.write_all(request.as_bytes()).unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        let (headers, body) = response.split_once("\r\n\r\n").unwrap();
        let status = headers.split_whitespace().nth(1).unwrap().parse().unwrap();
        let cookie = headers.lines().find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("set-cookie")
                .then(|| value.trim().to_owned())
        });
        (
            status,
            cookie,
            serde_json::from_str(body).unwrap_or(Value::Null),
        )
    }
}
fn cookie_pair(cookie: &str) -> &str {
    cookie.split(';').next().unwrap()
}
fn browser_identity(session: &Value) -> Value {
    json!({"tenant_id":session["tenant_id"], "account_id":session["account_id"],
        "session_id":session["session_id"], "client_id":session["client_id"]})
}
#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn browser_cookie_restore_logout_and_purpose_isolation_in_both_modes() {
    for mode in [TenancyMode::Disabled, TenancyMode::Enabled] {
        let db = Db::new(mode);
        db.bootstrap();
        let host = db.start();
        let management_root = "/api/admin/auth/browser";
        let (status, management_cookie, admin) = host.browser(
            &format!("{management_root}/login"),
            None,
            None,
            json!({"email":"admin@example.test","password":"Runtime-Admin123"}),
        );
        assert_eq!(status, 200);
        assert!(admin["tokens"].get("refresh_token").is_none());
        let management_cookie = management_cookie.unwrap();
        assert!(
            management_cookie.contains("HttpOnly") && management_cookie.contains("SameSite=Strict")
        );
        let tenant = if mode == TenancyMode::Enabled {
            "browser-a"
        } else {
            "0"
        };
        if mode == TenancyMode::Enabled {
            host.json("POST", "/api/admin/tenants", Some(token(&admin)), None,
                Some(json!({"tenant_id":tenant,"name":"Browser tenant","allow_registration":true,
                    "administrator":{"kind":"new","email":"browser@example.test","password":"Browser-Member123"}})), 201);
        } else {
            host.json("POST", "/api/admin/platform/accounts", Some(token(&admin)), None,
                Some(json!({"tenant_id":"0","email":"browser@example.test","password":"Browser-Member123"})), 200);
        }
        let (status, cookie, result) = host.browser(
            "/auth/browser/login",
            None,
            None,
            json!({"email":"browser@example.test","password":"Browser-Member123"}),
        );
        assert_eq!(status, 200);
        let (cookie, result) = if mode == TenancyMode::Enabled {
            assert!(cookie.is_none());
            assert_eq!(result["status"], "tenant_selection_required");
            let (status, cookie, result) = host.browser(
                "/auth/browser/tenant-selection/complete",
                None,
                result["selection_ticket"].as_str(),
                json!({"tenant_id":tenant}),
            );
            assert_eq!(status, 200);
            (cookie.unwrap(), result)
        } else {
            (cookie.unwrap(), result)
        };
        assert_eq!(result["session"]["tenant_id"], tenant);
        assert!(result["tokens"].get("refresh_token").is_none());
        let identity = browser_identity(&result["session"]);
        let mut wrong = identity.clone();
        wrong["tenant_id"] = json!("wrong-tenant");
        let (status, changed_cookie, result) = host.browser(
            "/auth/browser/refresh",
            Some(cookie_pair(&cookie)),
            None,
            json!({"expected_session":wrong}),
        );
        assert_eq!(status, 409);
        assert!(changed_cookie.is_none());
        assert_eq!(result["code"], "browser_session_changed");
        let (status, next, restored) = host.browser(
            "/auth/browser/restore",
            Some(cookie_pair(&cookie)),
            None,
            json!({"expected_session":identity}),
        );
        assert_eq!(status, 200);
        let next = next.unwrap();
        assert_ne!(cookie_pair(&cookie), cookie_pair(&next));
        assert!(restored["tokens"].get("refresh_token").is_none());
        // Renaming a business cookie cannot upgrade its signed/stored purpose.
        let forged = format!(
            "{}={}",
            cookie_pair(&management_cookie).split_once('=').unwrap().0,
            cookie_pair(&next).split_once('=').unwrap().1
        );
        assert_eq!(
            host.browser(
                &format!("{management_root}/restore"),
                Some(&forged),
                None,
                json!({})
            )
            .0,
            401
        );
        // No access token is supplied to logout, including before local restoration.
        let (status, cleared, _) = host.browser(
            "/auth/browser/logout",
            Some(cookie_pair(&next)),
            None,
            json!({}),
        );
        assert_eq!(status, 204);
        assert!(cleared.unwrap().contains("Max-Age=0"));
        assert_eq!(
            host.browser(
                "/auth/browser/restore",
                Some(cookie_pair(&next)),
                None,
                json!({})
            )
            .0,
            401
        );
        assert_eq!(
            host.browser(
                "/auth/browser/logout",
                Some(cookie_pair(&next)),
                None,
                json!({})
            )
            .0,
            204
        );
        // Business logout has no effect on the separate management session.
        let (status, next_admin, _) = host.browser(
            &format!("{management_root}/restore"),
            Some(cookie_pair(&management_cookie)),
            None,
            json!({}),
        );
        assert_eq!(status, 200);
        let next_admin = next_admin.unwrap();
        // Reusing the old management credential revokes its family, including the new token.
        assert_eq!(
            host.browser(
                &format!("{management_root}/restore"),
                Some(cookie_pair(&management_cookie)),
                None,
                json!({})
            )
            .0,
            401
        );
        assert_eq!(
            host.browser(
                &format!("{management_root}/restore"),
                Some(cookie_pair(&next_admin)),
                None,
                json!({})
            )
            .0,
            401
        );
    }
}

/// Exercises the actual feature-enabled reference binary with a private external
/// Origin and a disposable PostgreSQL schema. The TCP socket is loopback: this
/// is HTTP/server acceptance, not evidence of browser insecure-context support.
#[cfg(all(feature = "development-private-network-http", debug_assertions))]
#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn private_http_development_bounds_browser_sessions_and_rejects_stale_identity() {
    const ORIGIN: &str = "http://192.168.31.159:8080";
    const TTL: i64 = 120;
    let db = Db::new(TenancyMode::Disabled);
    db.bootstrap();
    let host = db.start_with(&[
        ("EMBEDDED_IDP_APP_BROWSER_ORIGIN", ORIGIN),
        (
            "EMBEDDED_IDP_APP_HTTP_TRANSPORT_POLICY",
            "development-private-network-http",
        ),
        ("EMBEDDED_IDP_APP_DEVELOPMENT_SESSION_TTL_SECS", "120"),
        ("EMBEDDED_IDP_APP_SCAN_LOGIN_ENABLED", "true"),
        (
            "EMBEDDED_IDP_APP_SCAN_LOGIN_ENTRY_ID",
            "reference-device-scan",
        ),
        (
            "EMBEDDED_IDP_APP_SCAN_LOGIN_ALLOWED_SOURCE_CLIENT_IDS",
            "desktop-app",
        ),
        (
            "EMBEDDED_IDP_APP_SCAN_LOGIN_MODES",
            "device_display,phone_display",
        ),
        (
            "EMBEDDED_IDP_APP_SCAN_LOGIN_VERIFICATION_URI",
            "http://192.168.31.159:8080/auth/browser/device-scan/ui",
        ),
        ("EMBEDDED_IDP_APP_SCAN_LOGIN_RESULT_KEY_ID", "test-key"),
        (
            "EMBEDDED_IDP_APP_SCAN_LOGIN_RESULT_KEY_BASE64URL",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ),
    ]);
    let browser = |path: &str, cookie: Option<&str>, body: Value| {
        host.browser_with_origin(path, cookie, None, body, ORIGIN)
    };
    let credentials = json!({"email":"admin@example.test","password":"Runtime-Admin123"});
    let (status, changed, _) = host.browser_with_origin(
        "/api/admin/auth/browser/login",
        None,
        None,
        credentials.clone(),
        "http://192.168.31.160:8080",
    );
    assert_eq!(status, 403);
    assert!(changed.is_none());

    let (status, cookie, admin) = browser("/api/admin/auth/browser/login", None, credentials);
    assert_eq!(status, 200, "{admin}");
    let cookie = cookie.unwrap();
    assert!(cookie.contains("HttpOnly") && cookie.contains("SameSite=Strict"));
    assert!(cookie.contains("Path=/api/admin/auth/browser"));
    assert!(!cookie.contains("; Secure"));
    assert!(admin["tokens"].get("refresh_token").is_none());
    let admin_id = admin["session"]["session_id"].as_str().unwrap();
    let lifetime = |session_id: &str| -> (i64, i64, i64) {
        let row = db.adapter.connect().unwrap().query_one(
            &format!("select s.expires_at_epoch-s.created_at_epoch, r.expires_at_epoch-r.issued_at_epoch, s.refresh_token_version, r.revoked_at_epoch, s.status from {}.auth_sessions s join {}.refresh_tokens r on r.tenant_id=s.tenant_id and r.session_id=s.id and r.token_version=s.refresh_token_version where s.id::text=$1", db.adapter.schema_name(), db.adapter.schema_name()),
            &[&session_id],
        ).unwrap();
        assert!(
            row.get::<_, Option<i64>>(3).is_none(),
            "refresh token was revoked"
        );
        assert_eq!(row.get::<_, String>(4), "active");
        (row.get(0), row.get(1), row.get(2))
    };
    let before = lifetime(admin_id);
    assert!(
        before.0 > 0 && before.0 <= TTL,
        "actual database session lifetime: {before:?}"
    );
    assert!(
        before.1 > 0 && before.1 <= TTL,
        "actual database refresh lifetime: {before:?}"
    );
    assert!(
        admin["tokens"]["access_expires_at_unix_secs"]
            .as_u64()
            .unwrap()
            <= admin["session"]["expires_at_unix_secs"].as_u64().unwrap()
    );
    for (action, code) in [
        ("restore", "browser_restore_disabled"),
        ("refresh", "browser_refresh_disabled"),
    ] {
        let (status, replacement, result) = browser(
            &format!("/api/admin/auth/browser/{action}"),
            Some(cookie_pair(&cookie)),
            json!({"expected_session":browser_identity(&admin["session"])}),
        );
        assert_eq!(status, 403, "{result}");
        assert_eq!(result["code"], code);
        assert!(replacement.is_none());
        assert_eq!(
            lifetime(admin_id),
            before,
            "disabled action must not rotate or revoke"
        );
    }
    // Ordinary token login retains the independently configured long lifetime.
    let ordinary = login(&host, true, "admin@example.test", "Runtime-Admin123");
    let ordinary_id = ordinary["session"]["session_id"].as_str().unwrap();
    assert!(lifetime(ordinary_id).0 > TTL);
    assert!(lifetime(ordinary_id).1 > TTL);

    for name in ["alice", "bob"] {
        host.json("POST", "/api/admin/platform/accounts", Some(token(&admin)), None,
            Some(json!({"tenant_id":"0","email":format!("{name}@example.test"),"password":"Browser-Member123"})), 200);
    }
    let mut sessions = vec![];
    for name in ["alice", "bob"] {
        let (status, cookie, value) = browser(
            "/auth/browser/login",
            None,
            json!({"email":format!("{name}@example.test"),"password":"Browser-Member123"}),
        );
        assert_eq!(status, 200, "{value}");
        let id = value["session"]["session_id"].as_str().unwrap();
        assert!(lifetime(id).0 <= TTL);
        sessions.push((cookie.unwrap(), value));
    }
    let alice_identity = browser_identity(&sessions[0].1["session"]);
    let bob_identity = browser_identity(&sessions[1].1["session"]);
    let bob_cookie = cookie_pair(&sessions[1].0);
    let bob_id = sessions[1].1["session"]["session_id"].as_str().unwrap();
    let bob_before = lifetime(bob_id);
    // Simulate an old tab whose page still shows Alice, but whose browser Cookie
    // was replaced when another tab signed in as Bob.
    for path in ["/auth/browser/logout", "/auth/browser/device-scan/context"] {
        let (status, replacement, value) = browser(
            path,
            Some(bob_cookie),
            json!({"expected_session":alice_identity}),
        );
        assert_eq!(status, 409, "{path}: {value}");
        let error_field = if path.ends_with("/context") {
            "error"
        } else {
            "code"
        };
        assert_eq!(value[error_field], "browser_session_changed");
        assert!(replacement.is_none());
        assert_eq!(lifetime(bob_id), bob_before);
        let (status, replacement, value) = browser(path, Some(bob_cookie), json!({}));
        assert_eq!(status, 400, "{path}: {value}");
        assert_eq!(value[error_field], "browser_expected_session_required");
        assert!(replacement.is_none());
    }
    let (status, replacement, context) = browser(
        "/auth/browser/device-scan/context",
        Some(bob_cookie),
        json!({"expected_session":bob_identity}),
    );
    assert_eq!(status, 200, "{context}");
    assert_eq!(context["account_id"], bob_identity["account_id"]);
    assert!(replacement.is_none());
    let (status, _, phone) = browser(
        "/auth/browser/device-scan/phone-codes",
        Some(bob_cookie),
        json!({"expected_session":bob_identity,"entry_id":"reference-device-scan","operation_id":UuidV7IdGenerator.next_id("operation")}),
    );
    assert_eq!(status, 201, "{phone}");

    for path in ["/", "/auth/browser/device-scan/ui"] {
        let (status, html) = host.raw("GET", path, None, None, None);
        assert_eq!(status, 200);
        assert!(html.contains("idp-browser-config"));
        assert!(html.contains("development_login"));
        assert!(html.contains("session_ttl_secs"));
    }
    // Expire the persisted browser session without waiting for wall-clock TTL;
    // its still-unexpired presented token must not authorize the scan context.
    db.adapter.connect().unwrap().execute(
        &format!("update {}.auth_sessions set created_at_epoch=created_at_epoch-300, authenticated_at_epoch=authenticated_at_epoch-300, expires_at_epoch=floor(extract(epoch from clock_timestamp()))::bigint-1 where id::text=$1", db.adapter.schema_name()),
        &[&bob_id],
    ).unwrap();
    let (status, _, expired) = browser(
        "/auth/browser/device-scan/context",
        Some(bob_cookie),
        json!({"expected_session":bob_identity}),
    );
    assert_eq!(status, 401, "{expired}");
    assert_eq!(expired["error"], "browser_session_expired");
}

// Explicit-v1 exercises only a pre-provisioned management client. The fixture
// owns its schema and sentinel; the binary must not seed or repair either.
impl Db {
    fn seed_management_client(&self) {
        self.adapter.connect().unwrap().execute(
            &format!("insert into {}.oidc_clients(client_id,client_name,redirect_uris_json,client_type,pkce_required,created_at_epoch) values ('management-test','Management test','[\"http://127.0.0.1/callback\"]','public_desktop',true,1)", self.adapter.schema_name()),
            &[],
        ).unwrap();
    }

    fn sentinel(&self) {
        self.adapter.connect().unwrap().batch_execute(&format!(
            "create table {}.host_sentinel (value text not null); insert into {}.host_sentinel values ('untouched')",
            self.adapter.schema_name(), self.adapter.schema_name()
        )).unwrap();
    }

    // Snapshot every table and its rows as well as the schema's object names.
    // This includes identity, client and audit tables, even when empty.
    fn snapshot(&self) -> Vec<(String, Vec<String>)> {
        let mut conn = self.adapter.connect().unwrap();
        let names: Vec<String> = conn.query(
            "select tablename from pg_catalog.pg_tables where schemaname = $1 order by tablename",
            &[&self.adapter.schema_name()],
        ).unwrap().into_iter().map(|row| row.get(0)).collect();
        names
            .into_iter()
            .map(|name| {
                let quoted = name.replace('"', "\"\"");
                let rows = conn
                    .query(
                        &format!(
                            "select row_to_json(t)::text from {}.\"{}\" t order by 1",
                            self.adapter.schema_name(),
                            quoted
                        ),
                        &[],
                    )
                    .unwrap()
                    .into_iter()
                    .map(|row| row.get(0))
                    .collect();
                (name, rows)
            })
            .collect()
    }

    fn explicit_command(&self, port: u16, mode: TenancyMode, mount: &str, ui: &str) -> Command {
        let config = json!({
            "version": 1,
            "runtime": {
                "tenancy_mode": if mode == TenancyMode::Enabled { "enabled" } else { "disabled" },
                "bind_addr": format!("127.0.0.1:{port}"),
                "issuer": format!("http://127.0.0.1:{port}"),
                "signing_key_file": "key.der",
                "postgres": { "connection": {
                    "uri_ref": {"env": "IDP_TEST_DATABASE_URI"},
                    "schema_name": self.adapter.schema_name(), "tls_mode": "disable"
                } },
                "http": {"browser_origin": format!("http://127.0.0.1:{port}")}
            },
            "management": {
                "login_entry": "management-test-entry", "client_id": "management-test",
                "tenant_policy": {"kind": "fixed", "tenant_id": "0"},
                "mount_prefix": mount, "browser": {"cookie_name": "idp_management_test"},
                "ui": if ui.is_empty() { Value::Null } else { json!({"base_path": ui}) }
            },
            "business_entries": []
        });
        self.explicit_command_from_config(config)
    }

    fn explicit_command_from_config(&self, config: Value) -> Command {
        let path = self.dir.join("explicit.json");
        fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_embedded-idp-app"));
        for (key, _) in env::vars().filter(|(key, _)| {
            key.starts_with("EMBEDDED_IDP_APP_") || key == "EMBEDDED_IDP_COMMON_ENV_FILE"
        }) {
            cmd.env_remove(key);
        }
        cmd.arg("--config")
            .arg(path)
            .env("IDP_TEST_DATABASE_URI", &self.uri)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        cmd
    }

    fn optional_command(
        &self,
        port: u16,
        browser: Option<Option<Value>>,
        ui: Option<Option<Value>>,
        http: bool,
    ) -> Command {
        let _ = self.explicit_command(port, self.mode, "/identity", "/console");
        let path = self.dir.join("explicit.json");
        let mut config: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        let management = config["management"].as_object_mut().unwrap();
        for (name, value) in [("browser", browser), ("ui", ui)] {
            match value {
                Some(Some(value)) => {
                    management.insert(name.into(), value);
                }
                Some(None) => {
                    management.insert(name.into(), Value::Null);
                }
                None => {
                    management.remove(name);
                }
            }
        }
        if !http {
            config["runtime"].as_object_mut().unwrap().remove("http");
        }
        self.explicit_command_from_config(config)
    }

    fn start_command(&self, port: u16, command: &mut Command) -> Host {
        let mut host = Host {
            child: command.spawn().unwrap(),
            port,
        };
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            assert!(
                host.child.try_wait().unwrap().is_none(),
                "explicit host exited before readiness"
            );
            if TcpStream::connect(("127.0.0.1", port)).is_ok()
                && host.raw("GET", "/readyz", None, None, None).0 == 200
            {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "explicit host readiness timed out"
            );
            thread::sleep(Duration::from_millis(50));
        }
        host
    }

    fn start_explicit(&self, mount: &str, ui: &str) -> Host {
        let port = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        self.start_explicit_at(port, mount, ui)
    }

    fn start_explicit_at(&self, port: u16, mount: &str, ui: &str) -> Host {
        let mut host = Host {
            child: self
                .explicit_command(port, self.mode, mount, ui)
                .spawn()
                .unwrap(),
            port,
        };
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            assert!(
                host.child.try_wait().unwrap().is_none(),
                "explicit host exited before readiness"
            );
            if TcpStream::connect(("127.0.0.1", port)).is_ok()
                && host.raw("GET", "/readyz", None, None, None).0 == 200
            {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "explicit host readiness timed out"
            );
            thread::sleep(Duration::from_millis(50));
        }
        host
    }

    fn explicit_rejected(&self, mode: TenancyMode) {
        let port = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let mut child = self
            .explicit_command(port, mode, "/identity", "/console")
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                assert!(
                    !status.success(),
                    "invalid explicit host unexpectedly succeeded"
                );
                break;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("invalid explicit host did not exit");
            }
            thread::sleep(Duration::from_millis(50));
        }
    }
}

impl Host {
    fn token_lifecycle(&self, auth: &str, clients_path: &str) {
        let admin = self.json(
            "POST",
            &format!("{auth}/login"),
            None,
            None,
            Some(json!({"email":"admin@example.test","password":"Runtime-Admin123"})),
            200,
        );
        assert_eq!(
            self.raw(
                "GET",
                &format!("{auth}/session"),
                Some(token(&admin)),
                None,
                None
            )
            .0,
            200
        );
        assert_eq!(self.raw("GET", clients_path, None, None, None).0, 401);
        let clients = self.json("GET", clients_path, Some(token(&admin)), None, None, 200);
        assert_eq!(clients["items"].as_array().unwrap().len(), 1);
        assert_eq!(clients["items"][0]["client_id"], "management-test");
        // Rotate and revoke the token session without replaying its old refresh
        // token until after logout (replay itself revokes the family).
        let independent = self.json(
            "POST",
            &format!("{auth}/login"),
            None,
            None,
            Some(json!({"email":"admin@example.test","password":"Runtime-Admin123"})),
            200,
        );
        let rotated = self.json(
            "POST",
            &format!("{auth}/refresh"),
            None,
            None,
            Some(json!({"refresh_token":admin["tokens"]["refresh_token"]})),
            200,
        );
        self.json("GET", clients_path, Some(token(&rotated)), None, None, 200);
        self.json(
            "POST",
            &format!("{auth}/logout"),
            Some(token(&rotated)),
            None,
            None,
            204,
        );
        for access in [token(&admin), token(&rotated)] {
            assert_eq!(
                self.raw("GET", clients_path, Some(access), None, None).0,
                401
            );
        }
        // Check the last valid refresh first, before replaying the rotated token.
        for refresh in [
            &rotated["tokens"]["refresh_token"],
            &admin["tokens"]["refresh_token"],
        ] {
            assert_eq!(
                self.raw(
                    "POST",
                    &format!("{auth}/refresh"),
                    None,
                    None,
                    Some(json!({"refresh_token":refresh}))
                )
                .0,
                401
            );
        }
        self.json(
            "GET",
            clients_path,
            Some(token(&independent)),
            None,
            None,
            200,
        );
    }

    fn browser_lifecycle(&self, auth: &str, clients_path: &str, mount: &str) {
        let independent = self.json(
            "POST",
            &format!("{auth}/login"),
            None,
            None,
            Some(json!({"email":"admin@example.test","password":"Runtime-Admin123"})),
            200,
        );
        let browser = format!("{auth}/browser");
        let (status, cookie, session) = self.browser(
            &format!("{browser}/login"),
            None,
            None,
            json!({"email":"admin@example.test","password":"Runtime-Admin123"}),
        );
        assert_eq!(status, 200);
        let cookie = cookie.unwrap();
        let cookie_path = format!("Path={mount}/admin/auth/browser");
        assert!(cookie.split(';').any(|part| part.trim() == cookie_path));
        self.json("GET", clients_path, Some(token(&session)), None, None, 200);
        let (status, refreshed, rotated_browser) = self.browser(
            &format!("{browser}/refresh"),
            Some(cookie_pair(&cookie)),
            None,
            json!({"expected_session":browser_identity(&session["session"])}),
        );
        assert_eq!(status, 200);
        let refreshed = refreshed.unwrap();
        self.json(
            "GET",
            clients_path,
            Some(token(&rotated_browser)),
            None,
            None,
            200,
        );
        let (status, cleared, _) = self.browser(
            &format!("{browser}/logout"),
            Some(cookie_pair(&refreshed)),
            None,
            json!({"expected_session":browser_identity(&rotated_browser["session"])}),
        );
        assert_eq!(status, 204);
        let cleared = cleared.unwrap();
        assert_eq!(
            cookie_pair(&cleared).split_once('=').unwrap().0,
            cookie_pair(&refreshed).split_once('=').unwrap().0
        );
        assert!(cleared.split(';').any(|part| part.trim() == cookie_path));
        assert!(cleared
            .split(';')
            .any(|part| part.trim().eq_ignore_ascii_case("Max-Age=0")));
        for action in ["restore", "refresh"] {
            assert_eq!(
                self.browser(
                    &format!("{browser}/{action}"),
                    Some(cookie_pair(&refreshed)),
                    None,
                    json!({"expected_session":browser_identity(&rotated_browser["session"])})
                )
                .0,
                401
            );
        }
        for access in [token(&session), token(&rotated_browser)] {
            assert_eq!(
                self.raw("GET", clients_path, Some(access), None, None).0,
                401
            );
        }
        self.json(
            "GET",
            clients_path,
            Some(token(&independent)),
            None,
            None,
            200,
        );
    }
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn explicit_management_only_is_read_only_at_startup_in_both_modes_and_mounts() {
    for mode in [TenancyMode::Disabled, TenancyMode::Enabled] {
        for (mount, ui) in [
            ("", "/console"),
            ("/api", "/console"),
            ("/identity", "/console"),
        ] {
            let db = Db::new(mode);
            db.bootstrap();
            db.seed_management_client();
            db.sentinel();
            let before = db.snapshot();
            let host = db.start_explicit(mount, ui);
            assert_eq!(
                db.snapshot(),
                before,
                "startup and readiness must not write"
            );
            assert_eq!(host.raw("GET", "/readyz", None, None, None).0, 200);
            assert_eq!(db.snapshot(), before, "readyz must not write");
            let (status, html) = host.raw("GET", "/console/", None, None, None);
            assert_eq!(status, 200);
            assert_eq!(html.matches("name=\"idp-api-base\"").count(), 1);
            assert_eq!(html.matches("name=\"idp-browser-config\"").count(), 1);
            let api_base = if mount.is_empty() { "/" } else { mount };
            assert!(html.contains(&format!("name=\"idp-api-base\" content=\"{api_base}\"")));
            for (method, path) in [
                ("POST", "/auth/login"),
                ("POST", "/auth/register"),
                ("POST", "/devices/provision"),
                ("POST", "/devices/proof/challenges"),
                ("POST", "/auth/device-scan"),
                ("GET", "/oidc/jwks"),
                ("GET", "/.well-known/openid-configuration"),
            ] {
                assert_eq!(
                    host.raw(method, path, None, None, None).0,
                    404,
                    "{method} {path}"
                );
            }
            let auth = format!("{mount}/admin/auth");
            let clients = format!("{mount}/admin/clients");
            host.token_lifecycle(&auth, &clients);
            host.browser_lifecycle(&auth, &clients, mount);
        }
    }
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn explicit_optional_management_surfaces_respect_mount_and_authorization() {
    // Read an actual compiled asset URL from the same HTML embedded by the host.
    let html = include_str!("../../../web/dist/management/index.html");
    let asset = html
        .split("/assets/")
        .nth(1)
        .expect("management asset missing")
        .split('"')
        .next()
        .unwrap();
    let asset_path = format!("/console/assets/{asset}");
    let root_asset_path = format!("/assets/{asset}");
    for mode in [TenancyMode::Disabled, TenancyMode::Enabled] {
        let db = Db::new(mode);
        db.bootstrap();
        db.seed_management_client();
        db.sentinel();
        for (browser, ui, http, has_browser) in [
            (
                Some(Some(json!({"cookie_name":"idp_management_test"}))),
                None,
                true,
                true,
            ),
            (None, None, false, false),
            (Some(None), Some(None), false, false),
        ] {
            let port = TcpListener::bind("127.0.0.1:0")
                .unwrap()
                .local_addr()
                .unwrap()
                .port();
            let before = db.snapshot();
            let mut command = db.optional_command(port, browser, ui, http);
            let host = db.start_command(port, &mut command);
            assert_eq!(db.snapshot(), before, "startup must be read-only");
            for path in [
                "/",
                "/console/",
                asset_path.as_str(),
                root_asset_path.as_str(),
                "/api/admin/clients",
            ] {
                assert_eq!(host.raw("GET", path, None, None, None).0, 404, "{path}");
            }
            let auth = "/identity/admin/auth";
            let clients = "/identity/admin/clients";
            host.token_lifecycle(auth, clients);
            if has_browser {
                host.browser_lifecycle(auth, clients, "/identity");
            } else {
                for action in ["login", "refresh", "restore", "logout"] {
                    assert_eq!(
                        host.browser(&format!("{auth}/browser/{action}"), None, None, json!({}))
                            .0,
                        404
                    );
                }
            }
        }
    }
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn explicit_management_and_legacy_business_credentials_are_isolated_with_same_issuer_and_key() {
    const ISSUER: &str = "https://idp.example.test";
    let db = Db::new(TenancyMode::Disabled);
    db.bootstrap();
    let legacy = db.start_with(&[("EMBEDDED_IDP_APP_ISSUER", ISSUER)]);
    let business = login(&legacy, false, "admin@example.test", "Runtime-Admin123");
    let (status, cookie, browser_session) = legacy.browser(
        "/auth/browser/login",
        None,
        None,
        json!({"email":"admin@example.test","password":"Runtime-Admin123"}),
    );
    assert_eq!(status, 200);
    let business_cookie = cookie.unwrap();
    legacy.json(
        "GET",
        "/auth/session",
        Some(token(&business)),
        None,
        None,
        200,
    );
    drop(legacy);

    db.seed_management_client();
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let _ = db.explicit_command(port, db.mode, "/identity", "/console");
    let path = db.dir.join("explicit.json");
    let mut config: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    config["runtime"]["issuer"] = json!(ISSUER);
    let mut command = db.explicit_command_from_config(config);
    let management = db.start_command(port, &mut command);
    for path in ["/identity/admin/auth/session", "/identity/admin/clients"] {
        assert_eq!(
            management
                .raw("GET", path, Some(token(&business)), None, None)
                .0,
            401
        );
    }
    assert_eq!(
        management
            .raw(
                "POST",
                "/identity/admin/auth/refresh",
                None,
                None,
                Some(json!({"refresh_token":business["tokens"]["refresh_token"]}))
            )
            .0,
        401
    );
    // Rename the transport cookie so rejection cannot be explained by a missing cookie.
    let value = cookie_pair(&business_cookie).split_once('=').unwrap().1;
    let renamed = format!("idp_management_test={value}");
    for action in ["restore", "refresh"] {
        assert_eq!(
            management
                .browser(
                    &format!("/identity/admin/auth/browser/{action}"),
                    Some(&renamed),
                    None,
                    json!({"expected_session":browser_identity(&browser_session["session"])})
                )
                .0,
            401
        );
    }
    let admin = management.json(
        "POST",
        "/identity/admin/auth/login",
        None,
        None,
        Some(json!({"email":"admin@example.test","password":"Runtime-Admin123"})),
        200,
    );
    let rotated = management.json(
        "POST",
        "/identity/admin/auth/refresh",
        None,
        None,
        Some(json!({"refresh_token":admin["tokens"]["refresh_token"]})),
        200,
    );
    management.json(
        "GET",
        "/identity/admin/clients",
        Some(token(&rotated)),
        None,
        None,
        200,
    );
    let (status, management_cookie, management_browser) = management.browser(
        "/identity/admin/auth/browser/login",
        None,
        None,
        json!({"email":"admin@example.test","password":"Runtime-Admin123"}),
    );
    assert_eq!(status, 200);
    let (status, management_cookie, _) = management.browser(
        "/identity/admin/auth/browser/refresh",
        Some(cookie_pair(&management_cookie.unwrap())),
        None,
        json!({"expected_session":browser_identity(&management_browser["session"])}),
    );
    assert_eq!(status, 200);
    let management_cookie = management_cookie.unwrap();
    drop(management);

    let legacy = db.start_with(&[("EMBEDDED_IDP_APP_ISSUER", ISSUER)]);
    assert_eq!(
        legacy
            .raw("GET", "/auth/session", Some(token(&rotated)), None, None)
            .0,
        401
    );
    assert_eq!(
        legacy
            .raw(
                "POST",
                "/auth/refresh",
                None,
                None,
                Some(json!({"refresh_token":rotated["tokens"]["refresh_token"]}))
            )
            .0,
        401
    );
    // Match the restarted legacy host's actual cookie name, retaining the
    // management credential value so the test reaches the purpose/client checks.
    let value = cookie_pair(&management_cookie).split_once('=').unwrap().1;
    let renamed = format!("idp_{}_business={value}", legacy.port);
    for action in ["restore", "refresh"] {
        assert_eq!(
            legacy
                .browser(
                    &format!("/auth/browser/{action}"),
                    Some(&renamed),
                    None,
                    json!({"expected_session":browser_identity(&management_browser["session"])})
                )
                .0,
            401
        );
    }
    legacy.json(
        "GET",
        "/auth/session",
        Some(token(&business)),
        None,
        None,
        200,
    );
    legacy.json(
        "POST",
        "/auth/refresh",
        None,
        None,
        Some(json!({"refresh_token":business["tokens"]["refresh_token"]})),
        200,
    );
    drop(legacy);

    // Wrong-purpose requests must not consume or revoke valid management
    // credentials: the same values still refresh/restore at their own entry.
    let management = db.start_command(port, &mut command);
    management.json(
        "POST",
        "/identity/admin/auth/refresh",
        None,
        None,
        Some(json!({"refresh_token":rotated["tokens"]["refresh_token"]})),
        200,
    );
    let (status, _, _) = management.browser(
        "/identity/admin/auth/browser/restore",
        Some(cookie_pair(&management_cookie)),
        None,
        json!({"expected_session":browser_identity(&management_browser["session"])}),
    );
    assert_eq!(status, 200);
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn legacy_restart_does_not_overwrite_existing_client() {
    for mode in [TenancyMode::Disabled, TenancyMode::Enabled] {
        let db = Db::new(mode);
        db.bootstrap();
        let host = db.start();
        drop(host);
        let mut conn = db.adapter.connect().unwrap();
        let sql = format!(
            "update {}.oidc_clients set redirect_uris_json=$1 where client_id='desktop-app'",
            db.adapter.schema_name()
        );
        let edited = r#"["http://127.0.0.1/edited"]"#;
        assert_eq!(conn.execute(&sql, &[&edited]).unwrap(), 1);
        drop(conn);
        let host = db.start();
        let row = db
            .adapter
            .connect()
            .unwrap()
            .query_one(
                &format!(
                    "select redirect_uris_json from {}.oidc_clients where client_id='desktop-app'",
                    db.adapter.schema_name()
                ),
                &[],
            )
            .unwrap();
        assert_eq!(row.get::<_, String>(0), edited);
        drop(host);
    }
}

/// Private Origin is checked by the server over a loopback socket; this does
/// not establish browser support for an insecure private-network context.
#[cfg(all(feature = "development-private-network-http", debug_assertions))]
#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn explicit_private_http_keeps_token_lifetime_and_bounds_browser() {
    const ORIGIN: &str = "http://192.168.31.159:8080";
    const TTL: i64 = 120;
    let db = Db::new(TenancyMode::Disabled);
    db.bootstrap();
    db.seed_management_client();
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let _ = db.explicit_command(port, db.mode, "/identity", "/console");
    let path = db.dir.join("explicit.json");
    let mut config: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    config["management"].as_object_mut().unwrap().remove("ui");
    config["runtime"]["http"] = json!({"browser_origin":ORIGIN,
        "transport_policy":"development-private-network-http", "development_session_ttl_secs":TTL});
    let mut command = db.explicit_command_from_config(config);
    let host = db.start_command(port, &mut command);
    let browser = |action: &str, cookie: Option<&str>, body: Value| {
        host.browser_with_origin(
            &format!("/identity/admin/auth/browser/{action}"),
            cookie,
            None,
            body,
            ORIGIN,
        )
    };
    let (status, cookie, session) = browser(
        "login",
        None,
        json!({"email":"admin@example.test","password":"Runtime-Admin123"}),
    );
    assert_eq!(status, 200, "{session}");
    let cookie = cookie.unwrap();
    let browser_id = session["session"]["session_id"].as_str().unwrap();
    let lifetime = |session_id: &str| -> (i64, i64, i64) {
        let row = db.adapter.connect().unwrap().query_one(
            &format!("select s.expires_at_epoch-s.created_at_epoch, r.expires_at_epoch-r.issued_at_epoch, s.refresh_token_version, r.revoked_at_epoch, s.status from {}.auth_sessions s join {}.refresh_tokens r on r.tenant_id=s.tenant_id and r.session_id=s.id and r.token_version=s.refresh_token_version where s.id::text=$1", db.adapter.schema_name(), db.adapter.schema_name()),
            &[&session_id]).unwrap();
        assert!(row.get::<_, Option<i64>>(3).is_none());
        assert_eq!(row.get::<_, String>(4), "active");
        (row.get(0), row.get(1), row.get(2))
    };
    let before = lifetime(browser_id);
    assert!(before.0 > 0 && before.0 <= TTL, "{before:?}");
    assert!(before.1 > 0 && before.1 <= TTL, "{before:?}");
    let identity = browser_identity(&session["session"]);
    for (action, code) in [
        ("restore", "browser_restore_disabled"),
        ("refresh", "browser_refresh_disabled"),
    ] {
        let (status, replacement, result) = browser(
            action,
            Some(cookie_pair(&cookie)),
            json!({"expected_session":identity}),
        );
        assert_eq!(status, 403, "{result}");
        assert_eq!(result["code"], code);
        assert!(replacement.is_none());
        assert_eq!(lifetime(browser_id), before);
    }
    let ordinary = host.json(
        "POST",
        "/identity/admin/auth/login",
        None,
        None,
        Some(json!({"email":"admin@example.test","password":"Runtime-Admin123"})),
        200,
    );
    let ordinary_lifetime = lifetime(ordinary["session"]["session_id"].as_str().unwrap());
    assert!(
        ordinary_lifetime.0 > TTL && ordinary_lifetime.1 > TTL,
        "{ordinary_lifetime:?}"
    );
    let rotated = host.json(
        "POST",
        "/identity/admin/auth/refresh",
        None,
        None,
        Some(json!({"refresh_token":ordinary["tokens"]["refresh_token"]})),
        200,
    );
    host.json(
        "GET",
        "/identity/admin/clients",
        Some(token(&rotated)),
        None,
        None,
        200,
    );
    let (status, cleared, _) = browser(
        "logout",
        Some(cookie_pair(&cookie)),
        json!({"expected_session":identity}),
    );
    assert_eq!(status, 204);
    assert!(cleared.unwrap().to_ascii_lowercase().contains("max-age=0"));
    assert_eq!(
        host.raw(
            "GET",
            "/identity/admin/clients",
            Some(token(&session)),
            None,
            None
        )
        .0,
        401
    );
    host.json(
        "GET",
        "/identity/admin/clients",
        Some(token(&rotated)),
        None,
        None,
        200,
    );
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn explicit_ui_without_browser_fails_without_writes() {
    let db = Db::new(TenancyMode::Disabled);
    db.bootstrap();
    db.seed_management_client();
    db.sentinel();
    let before = db.snapshot();
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let mut command = db.optional_command(
        port,
        None,
        Some(Some(json!({"base_path":"/console"}))),
        false,
    );
    let mut child = command.spawn().unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(!status.success(), "UI without browser unexpectedly started");
            break;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("invalid explicit host did not exit");
        }
        thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(db.snapshot(), before);
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn explicit_management_only_rejects_missing_dependencies_without_writes() {
    let db = Db::new(TenancyMode::Enabled);
    db.sentinel();
    db.seed_management_client();
    let before = db.snapshot();
    db.explicit_rejected(TenancyMode::Enabled); // no administrator
    assert_eq!(db.snapshot(), before);
    db.bootstrap();
    let before = db.snapshot();
    db.explicit_rejected(TenancyMode::Disabled); // schema mode mismatch
    assert_eq!(db.snapshot(), before);
    db.adapter
        .connect()
        .unwrap()
        .execute(
            &format!(
                "delete from {}.oidc_clients where client_id='management-test'",
                db.adapter.schema_name()
            ),
            &[],
        )
        .unwrap();
    let before = db.snapshot();
    db.explicit_rejected(TenancyMode::Enabled); // missing management client
    assert_eq!(db.snapshot(), before);
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn explicit_management_restart_preserves_credentials_and_existing_client() {
    let db = Db::new(TenancyMode::Enabled);
    db.bootstrap();
    db.seed_management_client();
    db.sentinel();
    let host = db.start_explicit("/identity", "/console");
    let port = host.port;
    let admin = host.json(
        "POST",
        "/identity/admin/auth/login",
        None,
        None,
        Some(json!({"email":"admin@example.test","password":"Runtime-Admin123"})),
        200,
    );
    let (status, cookie, browser_session) = host.browser(
        "/identity/admin/auth/browser/login",
        None,
        None,
        json!({"email":"admin@example.test","password":"Runtime-Admin123"}),
    );
    assert_eq!(status, 200);
    let cookie = cookie.unwrap();
    let browser_id = browser_session["session"]["session_id"].as_str().unwrap();
    db.adapter.connect().unwrap().execute(&format!(
        "update {}.oidc_clients set redirect_uris_json='[\"http://127.0.0.1/edited\"]' where client_id='management-test'",
        db.adapter.schema_name()), &[]).unwrap();
    let before = db.snapshot();
    drop(host);
    let host = db.start_explicit_at(port, "/identity", "/console");
    assert_eq!(
        db.snapshot(),
        before,
        "restart must not seed, modify client or extend TTL"
    );
    assert_eq!(
        host.raw(
            "GET",
            "/identity/admin/auth/session",
            Some(token(&admin)),
            None,
            None
        )
        .0,
        200
    );
    let (status, _, _) = host.browser(
        "/identity/admin/auth/browser/restore",
        Some(cookie_pair(&cookie)),
        None,
        json!({"expected_session":browser_identity(&browser_session["session"])}),
    );
    assert_eq!(status, 200);
    let expiry: i64 = db
        .adapter
        .connect()
        .unwrap()
        .query_one(
            &format!(
                "select expires_at_epoch from {}.auth_sessions where id::text=$1",
                db.adapter.schema_name()
            ),
            &[&browser_id],
        )
        .unwrap()
        .get(0);
    let original = before
        .iter()
        .find(|(name, _)| name == "auth_sessions")
        .unwrap()
        .1
        .iter()
        .map(|row| serde_json::from_str::<Value>(row).unwrap())
        .find(|row| row["id"] == browser_id)
        .unwrap();
    assert_eq!(Some(expiry), original["expires_at_epoch"].as_i64());
    let clients = host.json(
        "GET",
        "/identity/admin/clients",
        Some(token(&admin)),
        None,
        None,
        200,
    );
    assert_eq!(
        clients["items"][0]["redirect_uris"][0],
        "http://127.0.0.1/edited"
    );
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn explicit_management_probe_missing_client_and_no_ui() {
    let db = Db::new(TenancyMode::Disabled);
    db.bootstrap();
    db.seed_management_client();
    db.sentinel();
    let before = db.snapshot();
    let host = db.start_explicit("/identity", "");
    assert_eq!(db.snapshot(), before);
    assert_eq!(host.raw("GET", "/", None, None, None).0, 404);
    assert_eq!(host.raw("GET", "/console/", None, None, None).0, 404);
    db.adapter
        .connect()
        .unwrap()
        .execute(
            &format!(
                "delete from {}.oidc_clients where client_id='management-test'",
                db.adapter.schema_name()
            ),
            &[],
        )
        .unwrap();
    let missing = db.snapshot();
    assert_eq!(host.raw("GET", "/readyz", None, None, None).0, 200);
    assert_eq!(db.snapshot(), missing);
    assert_ne!(
        host.raw(
            "POST",
            "/identity/admin/auth/login",
            None,
            None,
            Some(json!({"email":"admin@example.test","password":"Runtime-Admin123"}))
        )
        .0,
        200
    );
    drop(host);
    let before = db.snapshot();
    db.explicit_rejected(TenancyMode::Disabled);
    assert_eq!(db.snapshot(), before);
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn explicit_management_rejects_invalid_key_and_client_without_writes() {
    let db = Db::new(TenancyMode::Disabled);
    db.bootstrap();
    db.seed_management_client();
    db.sentinel();
    let key = fs::read(db.dir.join("key.der")).unwrap();
    fs::write(db.dir.join("key.der"), b"invalid fixture key").unwrap();
    let before = db.snapshot();
    db.explicit_rejected(TenancyMode::Disabled);
    assert_eq!(db.snapshot(), before);
    fs::write(db.dir.join("key.der"), key).unwrap();
    db.adapter
        .connect()
        .unwrap()
        .execute(
            &format!(
                "update {}.oidc_clients set pkce_required=false where client_id='management-test'",
                db.adapter.schema_name()
            ),
            &[],
        )
        .unwrap();
    let before = db.snapshot();
    db.explicit_rejected(TenancyMode::Disabled);
    assert_eq!(db.snapshot(), before);
}
