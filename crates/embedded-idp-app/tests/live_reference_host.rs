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
    fn terminate_gracefully(&mut self) {
        let pid = self.child.id().to_string();
        let status = Command::new("kill")
            .args(["-TERM", &pid])
            .status()
            .expect("send SIGTERM to reference host");
        assert!(status.success(), "kill -TERM {pid} failed: {status}");
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            if let Some(status) = self.child.try_wait().expect("wait for reference host") {
                assert!(
                    status.success(),
                    "reference host exited unsuccessfully: {status}"
                );
                return;
            }
            assert!(
                Instant::now() < deadline,
                "reference host did not exit within 15 seconds after SIGTERM"
            );
            thread::sleep(Duration::from_millis(50));
        }
    }

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
        let mut request = format!(
            "{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nx-embedded-idp-admin-key: ignored-legacy-key\r\nx-embedded-idp-account-id: forged-subject\r\nContent-Length: {}\r\n",
            body.len()
        );
        if !body.is_empty() {
            request.push_str("Content-Type: application/json\r\n");
        }
        if let Some(token) = token {
            let scheme = if path.contains("/auth/tenant-selection/") {
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
        let mut request = format!(
            "POST {path} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nOrigin: {origin}\r\nX-Embedded-Idp-Browser: 1\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n",
            self.port,
            body.len()
        );
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
        let deadline = Instant::now() + Duration::from_secs(60);
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
        let deadline = Instant::now() + Duration::from_secs(60);
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

// Raw bytes are required to exercise repeated JSON keys and HTTP headers.
fn n1_request(
    port: u16,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> (u16, Value) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut request = format!(
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n",
        body.len()
    );
    for (name, value) in headers {
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    request.push_str("\r\n");
    request.push_str(body);
    stream.write_all(request.as_bytes()).unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    let (headers, body) = response.split_once("\r\n\r\n").unwrap();
    (
        headers.split_whitespace().nth(1).unwrap().parse().unwrap(),
        serde_json::from_str(body).unwrap_or(Value::Null),
    )
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn n1_reference_lookup_and_authentication_boundaries_in_both_modes() {
    for mode in [TenancyMode::Enabled, TenancyMode::Disabled] {
        let db = Db::new(mode);
        db.bootstrap();
        let host = db.start();
        let admin = login(&host, true, "admin@example.test", "Runtime-Admin123");
        let bearer = token(&admin);
        for id in [".", "..", "...", ".a", "a..", "-", "lookup", "upsert"] {
            let missing = host.json(
                "GET",
                &format!("/api/admin/clients/-/lookup?client_id={id}"),
                Some(bearer),
                None,
                None,
                200,
            );
            assert_eq!(missing["client_id"], id);
            assert!(missing["client"].is_null());
            let result = host.json("POST", "/api/admin/clients/upsert", Some(bearer), None, Some(json!({"client_id":id,"client_name":"N1 client","redirect_uris":["http://127.0.0.1/callback"],"client_type":"public_desktop","pkce_required":true})), 200);
            assert_eq!(result["client"]["client_id"], id);
            let found = host.json(
                "GET",
                &format!("/api/admin/clients/-/lookup?client_id={id}"),
                Some(bearer),
                None,
                None,
                200,
            );
            assert_eq!(found["client"]["client_id"], id);
            assert!(found["client"].get("client_secret").is_none());
            assert!(found["client"].get("client_secret_hash").is_none());
        }
        for query in [
            "client_id=.&client_id=.",
            "client_id=.&client_id=..",
            "client_id=.&unknown=x",
            "client_id=%252e",
            "client_id=%",
            "client_id=",
        ] {
            assert_eq!(
                host.raw(
                    "GET",
                    &format!("/api/admin/clients/-/lookup?{query}"),
                    Some(bearer),
                    None,
                    None
                )
                .0,
                400,
                "{query}"
            );
        }
        assert_eq!(
            host.json(
                "GET",
                "/api/admin/clients/-/lookup?client_id=%2E",
                Some(bearer),
                None,
                None,
                200
            )["client_id"],
            "."
        );
        for id in ["-", "lookup"] {
            assert_eq!(
                host.raw(
                    "GET",
                    &format!("/api/admin/clients/{id}"),
                    Some(bearer),
                    None,
                    None
                )
                .0,
                200
            );
        }
        assert_eq!(
            host.raw("GET", "/api/admin/clients/upsert", Some(bearer), None, None)
                .0,
            405
        );
        let lookup = "/api/admin/clients/-/lookup?client_id=.";
        assert_eq!(host.raw("GET", lookup, None, None, None).0, 401);
        assert_eq!(
            host.raw("GET", lookup, Some(bearer), Some("0"), None).0,
            200
        );
        assert_eq!(
            host.raw("GET", lookup, Some(bearer), Some("other"), None).0,
            400
        );
        assert_eq!(
            host.raw_business("GET", lookup, Some(bearer), None, None, Some("runtime"))
                .0,
            400
        );
        let authorization = format!("Bearer {bearer}");
        assert_eq!(
            n1_request(
                host.port,
                "GET",
                lookup,
                &[
                    ("Authorization", &authorization),
                    ("x-embedded-idp-tenant-id", "0"),
                    ("x-embedded-idp-tenant-id", "0")
                ],
                ""
            )
            .0,
            400
        );
        assert_eq!(
            n1_request(
                host.port,
                "GET",
                lookup,
                &[
                    ("Cookie", "idp_management=fake"),
                    ("x-embedded-idp-subject", "admin")
                ],
                ""
            )
            .0,
            401
        );
        let business = if mode == TenancyMode::Enabled {
            host.json("POST", "/api/admin/tenants", Some(bearer), None, Some(json!({"tenant_id":"business-test","name":"Business","allow_registration":false,"administrator":{"kind":"new","email":"n1-member@example.test","password":"Runtime-Member123"}})), 201);
            login(&host, false, "n1-member@example.test", "Runtime-Member123")
        } else {
            login(&host, false, "admin@example.test", "Runtime-Admin123")
        };
        if mode == TenancyMode::Disabled {
            assert!(business["tokens"]["access_token"].is_string());
            assert_eq!(
                host.raw("GET", lookup, Some(token(&business)), None, None)
                    .0,
                401
            );
        } else {
            assert_eq!(business["status"], "tenant_selection_required");
            let selection = business["selection_ticket"].as_str().unwrap();
            let ticket = format!("TenantSelection {selection}");
            assert_eq!(
                n1_request(host.port, "GET", lookup, &[("Authorization", &ticket)], "").0,
                401
            );
            let selected = host.json(
                "POST",
                "/auth/tenant-selection/complete",
                Some(selection),
                None,
                Some(json!({"tenant_id":"business-test"})),
                200,
            );
            assert_eq!(
                host.raw("GET", lookup, Some(token(&selected)), None, None)
                    .0,
                401
            );
        }
        if mode == TenancyMode::Disabled {
            assert_eq!(host.raw("PATCH", "/api/admin/tenants", Some(bearer), None, Some(json!({"tenant_id":".","name":"X","status":"active","allow_registration":false,"expected_version":1}))).0, 404);
        }
    }
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn n1_reference_tenant_body_path_and_concurrent_version_share_transaction() {
    let db = Db::new(TenancyMode::Enabled);
    db.bootstrap();
    let host = db.start();
    let admin = login(&host, true, "admin@example.test", "Runtime-Admin123");
    let bearer = token(&admin);
    for (id, email) in [
        (".", "dot@example.test"),
        ("..", "dots@example.test"),
        ("ordinary", "ordinary@example.test"),
    ] {
        host.json("POST", "/api/admin/tenants", Some(bearer), None, Some(json!({"tenant_id":id,"name":"Before","allow_registration":false,"administrator":{"kind":"new","email":email,"password":"Runtime-Member123"}})), 201);
    }
    let auth = format!("Bearer {bearer}");
    let original = r#"{"tenant_id":".","name":"Changed","status":"active","allow_registration":false,"expected_version":1}"#;
    let audit_count = || -> i64 {
        db.adapter
            .connect()
            .unwrap()
            .query_one(
                &format!(
                    "select count(*) from {}.access_audit_events where operation='tenant.update'",
                    db.adapter.schema_name()
                ),
                &[],
            )
            .unwrap()
            .get(0)
    };
    let tenant_host = db.start_with(&[("EMBEDDED_IDP_APP_MANAGEMENT_TENANT_ID", "ordinary")]);
    let tenant_admin = login(
        &tenant_host,
        true,
        "ordinary@example.test",
        "Runtime-Member123",
    );
    assert_eq!(tenant_admin["session"]["tenant_id"], "ordinary");
    let tenant_bearer = token(&tenant_admin);
    let state_before = host.json(
        "GET",
        "/api/admin/tenants/ordinary",
        Some(bearer),
        None,
        None,
        200,
    );
    let audit_before = audit_count();
    for target in [None, Some("0")] {
        assert_eq!(
            tenant_host
                .raw(
                    "GET",
                    "/api/admin/clients/-/lookup?client_id=.",
                    Some(tenant_bearer),
                    target,
                    None
                )
                .0,
            403
        );
        assert_eq!(tenant_host.raw("PATCH", "/api/admin/tenants", Some(tenant_bearer), target, Some(json!({"tenant_id":"ordinary","name":"Forbidden","status":"active","allow_registration":false,"expected_version":1}))).0, 403);
    }
    assert_eq!(
        host.json(
            "GET",
            "/api/admin/tenants/ordinary",
            Some(bearer),
            None,
            None,
            200
        ),
        state_before
    );
    assert_eq!(audit_count(), audit_before);
    drop(tenant_host);
    assert_eq!(
        n1_request(host.port, "PATCH", "/api/admin/tenants", &[], original).0,
        401
    );
    assert_eq!(
        n1_request(
            host.port,
            "PATCH",
            "/api/admin/tenants",
            &[("Authorization", &auth), ("x-embedded-idp-tenant-id", "0")],
            original
        )
        .0,
        200
    );
    let before = audit_count();
    assert_eq!(
        n1_request(
            host.port,
            "PATCH",
            "/api/admin/tenants",
            &[
                ("Authorization", &auth),
                ("x-embedded-idp-tenant-id", "other")
            ],
            original
        )
        .0,
        400
    );
    assert_eq!(
        n1_request(
            host.port,
            "PATCH",
            "/api/admin/tenants",
            &[
                ("Authorization", &auth),
                ("x-embedded-idp-tenant-id", "0"),
                ("x-embedded-idp-tenant-id", "0")
            ],
            original
        )
        .0,
        400
    );
    assert_eq!(
        n1_request(
            host.port,
            "PATCH",
            "/api/admin/tenants",
            &[
                ("Authorization", &auth),
                ("x-embedded-idp-business-id", "runtime")
            ],
            original
        )
        .0,
        400
    );
    for (path, body) in [
        ("/api/admin/tenants?tenant_id=other", original),
        (
            "/api/admin/tenants",
            r#"{"tenant_id":".","tenant_id":"..","name":"Changed","status":"active","allow_registration":false,"expected_version":1}"#,
        ),
        (
            "/api/admin/tenants",
            r#"{"tenant_id":".","name":"Changed","status":"active","allow_registration":false,"expected_version":1,"actor_id":"admin"}"#,
        ),
        ("/api/admin/tenants/ordinary", original),
        (
            "/api/admin/tenants",
            r#"{"name":"Changed","status":"active","allow_registration":false,"expected_version":1}"#,
        ),
        (
            "/api/admin/tenants",
            r#"{"tenant_id":"%2e","name":"Changed","status":"active","allow_registration":false,"expected_version":1}"#,
        ),
        (
            "/api/admin/tenants",
            r#"{"tenant_id":"0","name":"Changed","status":"active","allow_registration":false,"expected_version":1}"#,
        ),
    ] {
        let status = n1_request(host.port, "PATCH", path, &[("Authorization", &auth)], body).0;
        assert!((400..500).contains(&status), "{path}: {status}");
    }
    assert_eq!(audit_count(), before);
    let result = host.json("PATCH", "/api/admin/tenants", Some(bearer), None, Some(json!({"tenant_id":"..","name":"Changed","status":"suspended","allow_registration":false,"expected_version":1})), 200);
    assert_eq!(result["tenant"]["tenant_id"], "..");
    assert_eq!(result["tenant"]["version"], 2);
    assert!(result["audit_id"].is_string());
    let reread = host.json(
        "GET",
        "/api/admin/tenants?tenant_id=..&limit=2",
        Some(bearer),
        None,
        None,
        200,
    );
    assert_eq!(reread["items"][0]["name"], "Changed");
    assert_eq!(reread["items"][0]["status"], "suspended");
    assert_eq!(audit_count(), before + 1);
    let concurrent_before = audit_count();
    let port = host.port;
    let barrier = std::sync::Barrier::new(2);
    let (a, b) = thread::scope(|scope| {
        let a = scope.spawn(|| { barrier.wait(); n1_request(port, "PATCH", "/api/admin/tenants", &[("Authorization", &auth)], r#"{"tenant_id":"ordinary","name":"Collection","status":"active","allow_registration":false,"expected_version":1}"#).0 });
        let b = scope.spawn(|| { barrier.wait(); n1_request(port, "PATCH", "/api/admin/tenants/ordinary", &[("Authorization", &auth)], r#"{"name":"Path","status":"active","allow_registration":false,"expected_version":1}"#).0 });
        (a.join().unwrap(), b.join().unwrap())
    });
    assert!((a == 200 && b == 409) || (a == 409 && b == 200), "{a}, {b}");
    let final_tenant = host.json(
        "GET",
        "/api/admin/tenants/ordinary",
        Some(bearer),
        None,
        None,
        200,
    );
    assert_eq!(final_tenant["version"], 2);
    assert_eq!(
        final_tenant["name"],
        if a == 200 { "Collection" } else { "Path" }
    );
    assert_eq!(audit_count(), concurrent_before + 1);
    let schema = db.adapter.schema_name();
    db.adapter.connect().unwrap().batch_execute(&format!(
        "create function {schema}.n1_reject_tenant_audit() returns trigger language plpgsql as $$ begin if new.operation = 'tenant.update' then raise exception 'n1 audit fault' using errcode = 'P0001'; end if; return new; end $$; create trigger n1_reject_tenant_audit before insert on {schema}.access_audit_events for each row execute function {schema}.n1_reject_tenant_audit()"
    )).unwrap();
    let failing_update = json!({"tenant_id":"ordinary","name":"Injected failure","status":"active","allow_registration":false,"expected_version":2});
    assert_eq!(
        host.raw(
            "PATCH",
            "/api/admin/tenants",
            Some(bearer),
            None,
            Some(failing_update.clone())
        )
        .0,
        500
    );
    assert_eq!(
        host.json(
            "GET",
            "/api/admin/tenants/ordinary",
            Some(bearer),
            None,
            None,
            200
        ),
        final_tenant
    );
    assert_eq!(audit_count(), concurrent_before + 1);
    db.adapter.connect().unwrap().batch_execute(&format!(
        "drop trigger n1_reject_tenant_audit on {schema}.access_audit_events; drop function {schema}.n1_reject_tenant_audit()"
    )).unwrap();
    let recovered = host.json(
        "PATCH",
        "/api/admin/tenants",
        Some(bearer),
        None,
        Some(failing_update),
        200,
    );
    assert_eq!(recovered["tenant"]["version"], 3);
    assert_eq!(recovered["tenant"]["name"], "Injected failure");
    assert_eq!(audit_count(), concurrent_before + 2);
    assert_eq!(host.raw("PATCH", "/api/admin/tenants", Some(bearer), None, Some(json!({"tenant_id":"ordinary","name":"stale","status":"active","allow_registration":false,"expected_version":1}))).0, 409);
    assert_eq!(audit_count(), concurrent_before + 2);
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn a01_preparation_cli_then_read_only_p4_login_and_restricted_p5() {
    for mode in [TenancyMode::Disabled, TenancyMode::Enabled] {
        let db = Db::new(mode);
        db.bootstrap();
        db.sentinel();
        let before = db.snapshot();
        db.explicit_rejected(mode); // P4 must not seed a missing management client.
        assert_eq!(db.snapshot(), before);
        let config = db.dir.join("explicit.json");
        let definition = db.dir.join("management.json");
        let original =
            json!({"client_name":"Management test","redirect_uris":["http://127.0.0.1/callback"]});
        fs::write(&definition, serde_json::to_vec(&original).unwrap()).unwrap();
        let prepare = |audit: bool| {
            let mut command = Command::new(env!("CARGO_BIN_EXE_embedded-idp-app"));
            for (key, _) in env::vars().filter(|(k, _)| {
                k.starts_with("EMBEDDED_IDP_APP_") || k == "EMBEDDED_IDP_COMMON_ENV_FILE"
            }) {
                command.env_remove(key);
            }
            command
                .env("IDP_TEST_DATABASE_URI", &db.uri)
                .arg(if audit {
                    "prepare-management-client-audit"
                } else {
                    "prepare-management-client"
                })
                .arg("--config")
                .arg(&config);
            if !audit {
                command.arg("--definition").arg(&definition);
            }
            command.output().unwrap()
        };
        assert_eq!(prepare(false).status.code(), Some(4)); // no implicit audit DDL
        assert_eq!(db.snapshot(), before);
        assert!(prepare(true).status.success());
        let created = prepare(false);
        assert!(created.status.success());
        assert_eq!(String::from_utf8_lossy(&created.stdout).trim(), "Created");
        let prepared = db.snapshot();
        let matched = prepare(false);
        assert!(matched.status.success());
        assert_eq!(
            String::from_utf8_lossy(&matched.stdout).trim(),
            "AlreadyMatches"
        );
        assert_eq!(db.snapshot(), prepared);
        fs::write(
            &definition,
            serde_json::to_vec(
                &json!({"client_name":"Different","redirect_uris":["http://127.0.0.1/callback"]}),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(prepare(false).status.code(), Some(3));
        assert_eq!(db.snapshot(), prepared);
        let host = db.start_explicit("/identity", "/console");
        assert_eq!(
            db.snapshot(),
            prepared,
            "P4 startup must not modify identity/audit records"
        );
        let admin = host.json(
            "POST",
            "/identity/admin/auth/login",
            None,
            None,
            Some(json!({"email":"admin@example.test","password":"Runtime-Admin123"})),
            200,
        );
        assert_eq!(
            host.raw(
                "POST",
                "/identity/admin/clients/upsert",
                None,
                None,
                Some(json!({}))
            )
            .0,
            401
        );
        host.json("POST", "/identity/admin/clients/upsert", Some(token(&admin)), None, Some(json!({"client_id":"a01-business","client_name":"Prepared business","redirect_uris":["http://127.0.0.1/business-callback"],"client_type":"public_desktop","pkce_required":true})), 200);
        host.json(
            "GET",
            "/identity/admin/clients/-/lookup?client_id=a01-business",
            Some(token(&admin)),
            None,
            None,
            200,
        );
        if mode == TenancyMode::Enabled {
            host.json("POST", "/identity/admin/tenants", Some(token(&admin)), None, Some(json!({"tenant_id":"a01-business","name":"Prepared tenant","allow_registration":false,"administrator":{"kind":"new","email":"a01-member@example.test","password":"Runtime-Member123"}})), 201);
        }
        assert_eq!(
            host.raw("POST", "/auth/register", None, None, Some(json!({})))
                .0,
            404
        );
    }
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn a02_ordinary_entries_are_isolated_read_only_and_preserve_sessions_on_reorder() {
    for mode in [TenancyMode::Disabled, TenancyMode::Enabled] {
        let db = Db::new(mode);
        db.bootstrap();
        db.seed_management_client();
        let setup = db.start_explicit("/identity", "/console");
        let admin = setup.json(
            "POST",
            "/identity/admin/auth/login",
            None,
            None,
            Some(json!({"email":"admin@example.test","password":"Runtime-Admin123"})),
            200,
        );
        for client in ["ordinary-one", "ordinary-two"] {
            setup.json("POST", "/identity/admin/clients/upsert", Some(token(&admin)), None,
                Some(json!({"client_id":client,"client_name":client,"redirect_uris":["http://127.0.0.1/callback"],"client_type":"public_desktop","pkce_required":true})), 200);
        }
        let (tenant, email, password) = if mode == TenancyMode::Enabled {
            setup.json("POST", "/identity/admin/tenants", Some(token(&admin)), None,
                Some(json!({"tenant_id":"ordinary-domain","name":"Ordinary","allow_registration":false,"administrator":{"kind":"new","email":"ordinary@example.test","password":"Runtime-Member123"}})), 201);
            (
                "ordinary-domain",
                "ordinary@example.test",
                "Runtime-Member123",
            )
        } else {
            ("0", "admin@example.test", "Runtime-Admin123")
        };
        drop(setup);
        let port = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let _ = db.explicit_command(port, mode, "/identity", "/console");
        let mut config: Value =
            serde_json::from_slice(&fs::read(db.dir.join("explicit.json")).unwrap()).unwrap();
        config["business_entries"] = json!([
            {"login_entry":"ordinary-one","client_id":"ordinary-one","tenant_policy":{"kind":"fixed","tenant_id":tenant},"mount_prefix":"/one","browser":{"cookie_name":"ordinary_one"}},
            {"login_entry":"ordinary-two","client_id":"ordinary-two","tenant_policy":{"kind":"fixed","tenant_id":tenant},"mount_prefix":"/two","browser":{"cookie_name":"ordinary_two"}}
        ]);
        // A missing configured reference must fail before any identity write.
        let before = db.snapshot();
        let mut invalid = config.clone();
        invalid["business_entries"][0]["client_id"] = "missing-client".into();
        assert!(!db
            .explicit_command_from_config(invalid)
            .status()
            .unwrap()
            .success());
        assert_eq!(db.snapshot(), before);
        let host = db.start_command(port, &mut db.explicit_command_from_config(config.clone()));
        assert_eq!(
            db.snapshot(),
            before,
            "ordinary startup never seeds or repairs"
        );
        let credentials = json!({"email":email,"password":password});
        let one = host.json(
            "POST",
            "/one/auth/login",
            None,
            None,
            Some(credentials.clone()),
            200,
        );
        let two = host.json(
            "POST",
            "/two/auth/login",
            None,
            None,
            Some(credentials.clone()),
            200,
        );
        for (path, access) in [
            ("/two/auth/session", token(&one)),
            ("/one/auth/session", token(&two)),
            ("/identity/admin/auth/session", token(&one)),
        ] {
            assert_eq!(host.raw("GET", path, Some(access), None, None).0, 401);
        }
        host.json(
            "GET",
            "/one/auth/me/roles?business_id=runtime",
            Some(token(&one)),
            None,
            None,
            200,
        );
        assert_eq!(
            host.raw("GET", "/one/auth/me/roles", Some(token(&one)), None, None)
                .0,
            400
        );
        assert_eq!(
            host.raw(
                "POST",
                "/two/auth/refresh",
                None,
                None,
                Some(json!({"refresh_token":one["tokens"]["refresh_token"]}))
            )
            .0,
            401
        );
        let rotated = host.json(
            "POST",
            "/one/auth/refresh",
            None,
            None,
            Some(json!({"refresh_token":one["tokens"]["refresh_token"]})),
            200,
        );
        let (status, cookie, browser) =
            host.browser("/one/auth/browser/login", None, None, credentials.clone());
        assert_eq!(status, 200);
        let cookie = cookie.unwrap();
        assert!(cookie.starts_with("ordinary_one="));
        assert!(cookie.contains("Path=/one/auth/browser"));
        assert!(cookie.contains("HttpOnly"));
        assert!(browser["tokens"].get("refresh_token").is_none());
        let expected = json!({"expected_session":browser_identity(&browser["session"])});
        assert_eq!(
            host.browser(
                "/two/auth/browser/restore",
                Some(cookie_pair(&cookie)),
                None,
                expected.clone()
            )
            .0,
            401
        );
        let (status, restored_cookie, restored) = host.browser(
            "/one/auth/browser/restore",
            Some(cookie_pair(&cookie)),
            None,
            expected,
        );
        assert_eq!(status, 200);
        // Restore rotates refresh credentials just like refresh; retain the new cookie.
        let cookie = restored_cookie.unwrap();
        let expected = json!({"expected_session":browser_identity(&restored["session"])});
        for (method, path) in [
            ("POST", "/one/auth/register"),
            ("POST", "/one/devices/proof/challenges"),
            ("GET", "/one/oidc/userinfo"),
            ("POST", "/one/auth/device-scan"),
            ("GET", "/.well-known/openid-configuration"),
            ("GET", "/oidc/jwks"),
        ] {
            assert_eq!(host.raw(method, path, None, None, None).0, 404, "{path}");
        }
        drop(host);
        config["business_entries"].as_array_mut().unwrap().reverse();
        let before_restart = db.snapshot();
        let host = db.start_command(port, &mut db.explicit_command_from_config(config));
        assert_eq!(db.snapshot(), before_restart);
        host.json(
            "GET",
            "/one/auth/session",
            Some(token(&rotated)),
            None,
            None,
            200,
        );
        let (status, restored_cookie, restored) = host.browser(
            "/one/auth/browser/restore",
            Some(cookie_pair(&cookie)),
            None,
            expected,
        );
        assert_eq!(status, 200);
        // Restore rotates refresh credentials just like refresh; retain the new cookie.
        let cookie = restored_cookie.unwrap();
        let expected = json!({"expected_session":browser_identity(&restored["session"])});
        let (status, refreshed_cookie, refreshed) = host.browser(
            "/one/auth/browser/refresh",
            Some(cookie_pair(&cookie)),
            None,
            expected,
        );
        assert_eq!(status, 200);
        let refreshed_cookie = refreshed_cookie.unwrap();
        assert_eq!(
            host.browser(
                "/one/auth/browser/logout",
                Some(cookie_pair(&refreshed_cookie)),
                None,
                json!({"expected_session":browser_identity(&refreshed["session"])})
            )
            .0,
            204
        );
        // Reuse detection must commit its revocation, while the other entry survives.
        assert_eq!(
            host.raw(
                "POST",
                "/one/auth/refresh",
                None,
                None,
                Some(json!({"refresh_token":one["tokens"]["refresh_token"]}))
            )
            .0,
            401
        );
        assert_eq!(
            host.raw(
                "GET",
                "/one/auth/session",
                Some(token(&rotated)),
                None,
                None
            )
            .0,
            401
        );
        host.json(
            "GET",
            "/two/auth/session",
            Some(token(&two)),
            None,
            None,
            200,
        );
    }
}

impl Host {
    fn ordinary_logout_form(&self, path: &str, form: &str, basic: Option<&str>) -> u16 {
        let mut request = format!(
            "POST {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n",
            form.len()
        );
        if let Some(credentials) = basic {
            request.push_str(&format!(
                "Authorization: Basic {}\r\n",
                Base64::encode_string(credentials.as_bytes())
            ));
        }
        request.push_str("\r\n");
        request.push_str(form);
        let mut stream = TcpStream::connect(("127.0.0.1", self.port)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream.write_all(request.as_bytes()).unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        response.split_whitespace().nth(1).unwrap().parse().unwrap()
    }

    fn oidc_form(&self, path: &str, form: &str, authorization: Option<&str>) -> (u16, String) {
        let mut request = format!(
            "POST {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n",
            form.len()
        );
        if let Some(authorization) = authorization {
            request.push_str(&format!("Authorization: {authorization}\r\n"));
        }
        request.push_str("\r\n");
        request.push_str(form);
        let mut stream = TcpStream::connect(("127.0.0.1", self.port)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream.write_all(request.as_bytes()).unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        let (headers, body) = response.split_once("\r\n\r\n").unwrap();
        (
            headers.split_whitespace().nth(1).unwrap().parse().unwrap(),
            body.into(),
        )
    }

    fn oidc_authorize(&self, query: &str, bearer: &str) -> (u16, String) {
        let mut stream = TcpStream::connect(("127.0.0.1", self.port)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        write!(stream, "GET /oidc/authorize?{query} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nAuthorization: Bearer {bearer}\r\n\r\n").unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        let status = response.split_whitespace().nth(1).unwrap().parse().unwrap();
        (status, response)
    }
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn a02b_shared_oidc_dispatch_is_client_and_session_bound() {
    let db = Db::new(TenancyMode::Disabled);
    db.bootstrap();
    db.seed_management_client();
    let setup = db.start_explicit("/identity", "/console");
    let admin = setup.json(
        "POST",
        "/identity/admin/auth/login",
        None,
        None,
        Some(json!({"email":"admin@example.test","password":"Runtime-Admin123"})),
        200,
    );
    for client in ["oidc-one", "oidc-two", "oidc-off"] {
        setup.json("POST", "/identity/admin/clients/upsert", Some(token(&admin)), None,
            Some(json!({"client_id":client,"client_name":client,"redirect_uris":["http://127.0.0.1/callback"],"client_type":"public_desktop","pkce_required":true})), 200);
    }
    drop(setup);

    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let _ = db.explicit_command(port, db.mode, "/identity", "/console");
    let mut config: Value =
        serde_json::from_slice(&fs::read(db.dir.join("explicit.json")).unwrap()).unwrap();
    config["version"] = json!(2);
    config["business_entries"] = json!([
        {"login_entry":"oidc-one","client_id":"oidc-one","tenant_policy":{"kind":"fixed","tenant_id":"0"},"mount_prefix":"/one","oidc":{"enabled":true}},
        {"login_entry":"oidc-two","client_id":"oidc-two","tenant_policy":{"kind":"fixed","tenant_id":"0"},"mount_prefix":"/two","oidc":{"enabled":true}},
        {"login_entry":"oidc-off","client_id":"oidc-off","tenant_policy":{"kind":"fixed","tenant_id":"0"},"mount_prefix":"/off"}
    ]);
    let mut host = db.start_command(port, &mut db.explicit_command_from_config(config.clone()));
    assert_eq!(
        host.raw("GET", "/.well-known/openid-configuration", None, None, None)
            .0,
        200
    );
    let metadata = host.json(
        "GET",
        "/.well-known/openid-configuration",
        None,
        None,
        None,
        200,
    );
    assert_eq!(metadata["issuer"], config["runtime"]["issuer"]);
    assert_eq!(
        metadata["grant_types_supported"],
        json!(["authorization_code"])
    );
    assert_eq!(
        metadata["code_challenge_methods_supported"],
        json!(["S256"])
    );
    for name in [
        "authorization_endpoint",
        "token_endpoint",
        "userinfo_endpoint",
        "introspection_endpoint",
        "revocation_endpoint",
        "jwks_uri",
    ] {
        assert!(metadata[name].as_str().unwrap().starts_with(&format!(
            "{}/oidc/",
            config["runtime"]["issuer"]
                .as_str()
                .unwrap()
                .trim_end_matches('/')
        )));
    }
    assert!(metadata.get("device_authorization_endpoint").is_none());
    let jwks = host.json("GET", "/oidc/jwks", None, None, None, 200);
    assert_eq!(jwks["keys"].as_array().unwrap().len(), 1);
    assert_eq!(jwks["keys"][0]["alg"], "RS256");
    assert_eq!(jwks["keys"][0]["kty"], "RSA");
    assert!(jwks["keys"][0].get("d").is_none());
    assert_eq!(host.raw("GET", "/oidc/jwks", None, None, None).0, 200);
    for path in [
        "/off/oidc/authorize",
        "/off/oidc/token",
        "/off/oidc/userinfo",
    ] {
        assert_eq!(host.raw("GET", path, None, None, None).0, 404, "{path}");
    }
    // OIDC is shared at the issuer root and adds no ordinary root logout alias.
    assert_eq!(host.raw("POST", "/auth/logout", None, None, None).0, 404);
    assert_eq!(
        host.raw("GET", "/one/oidc/userinfo", None, None, None).0,
        404
    );

    let one = host.json(
        "POST",
        "/one/auth/login",
        None,
        None,
        Some(json!({"email":"admin@example.test","password":"Runtime-Admin123"})),
        200,
    );
    let two = host.json(
        "POST",
        "/two/auth/login",
        None,
        None,
        Some(json!({"email":"admin@example.test","password":"Runtime-Admin123"})),
        200,
    );
    let off = host.json(
        "POST",
        "/off/auth/login",
        None,
        None,
        Some(json!({"email":"admin@example.test","password":"Runtime-Admin123"})),
        200,
    );
    assert_eq!(
        host.raw("GET", "/oidc/userinfo", Some(token(&off)), None, None)
            .0,
        401
    );
    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    let query = |client: &str, redirect: &str, code_challenge: &str| {
        format!(
            "response_type=code&client_id={client}&redirect_uri={redirect}&scope=openid%20profile%20email&state=state123&code_challenge={code_challenge}&code_challenge_method=S256"
        )
    };
    assert_eq!(
        host.oidc_authorize(
            &query(
                "unknown-client",
                "http%3A%2F%2F127.0.0.1%2Fcallback",
                challenge
            ),
            token(&one)
        )
        .0,
        400
    );
    assert_eq!(
        host.oidc_authorize(
            &query("oidc-one", "http%3A%2F%2F127.0.0.1%2Fwrong", challenge),
            token(&one)
        )
        .0,
        400
    );
    assert_eq!(
        host.oidc_authorize(
            &query("oidc-off", "http%3A%2F%2F127.0.0.1%2Fcallback", challenge),
            token(&off)
        )
        .0,
        401
    );
    assert_eq!(
        host.oidc_authorize(
            &query("oidc-one", "http%3A%2F%2F127.0.0.1%2Fcallback", challenge),
            token(&two)
        )
        .0,
        401,
        "a business actor from another client cannot authorize this client"
    );
    // Management-purpose bearer and forged subject headers are not accepted as actors.
    assert_eq!(
        host.oidc_authorize(
            &query("oidc-one", "http%3A%2F%2F127.0.0.1%2Fcallback", challenge),
            token(&admin)
        )
        .0,
        401
    );
    assert_eq!(
        host.oidc_authorize(
            &query("oidc-one", "http%3A%2F%2F127.0.0.1%2Fcallback", challenge),
            "eyJhbGciOiJub25lIn0.eyJzdWIiOiJmb3JnZWQifQ."
        )
        .0,
        401
    );

    let (status, raw) = host.oidc_authorize(
        &query("oidc-one", "http%3A%2F%2F127.0.0.1%2Fcallback", challenge),
        token(&one),
    );
    assert_eq!(status, 307, "{raw}");
    let location = raw
        .lines()
        .find_map(|line| {
            line.strip_prefix("location: ")
                .or_else(|| line.strip_prefix("Location: "))
        })
        .unwrap();
    let redirect = location
        .split_once("\r")
        .map_or(location, |(value, _)| value);
    let code = redirect
        .split("code=")
        .nth(1)
        .unwrap()
        .split('&')
        .next()
        .unwrap();
    let exchange = |client: &str, code: &str, redirect: &str, verifier: &str| {
        format!(
            "grant_type=authorization_code&client_id={client}&code={code}&redirect_uri={redirect}&code_verifier={verifier}"
        )
    };
    let wrong_redirect = host.oidc_form(
        "/oidc/token",
        &exchange("oidc-one", code, "http%3A%2F%2F127.0.0.1%2Fwrong", verifier),
        None,
    );
    assert_eq!(wrong_redirect.0, 400, "{}", wrong_redirect.1);
    let wrong_pkce = host.oidc_form(
        "/oidc/token",
        &exchange(
            "oidc-one",
            code,
            "http%3A%2F%2F127.0.0.1%2Fcallback",
            "wrong-verifier",
        ),
        None,
    );
    assert_eq!(wrong_pkce.0, 400, "{}", wrong_pkce.1);
    let cross_client = host.oidc_form(
        "/oidc/token",
        &exchange(
            "oidc-two",
            code,
            "http%3A%2F%2F127.0.0.1%2Fcallback",
            verifier,
        ),
        None,
    );
    assert_eq!(cross_client.0, 400, "{}", cross_client.1);
    let (status, body) = host.oidc_form(
        "/oidc/token",
        &exchange(
            "oidc-one",
            code,
            "http%3A%2F%2F127.0.0.1%2Fcallback",
            verifier,
        ),
        None,
    );
    assert_eq!(status, 200, "{body}");
    let tokens: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(tokens["token_type"], "Bearer");
    let userinfo = host.raw(
        "GET",
        "/oidc/userinfo",
        tokens["access_token"].as_str(),
        None,
        None,
    );
    assert_eq!(userinfo.0, 200, "{}", userinfo.1);
    assert!(userinfo.1.contains("oidc-one"));
    assert_eq!(
        host.oidc_form(
            "/oidc/token",
            &exchange(
                "oidc-one",
                code,
                "http%3A%2F%2F127.0.0.1%2Fcallback",
                verifier,
            ),
            None
        )
        .0,
        400,
        "authorization code must be single-use"
    );

    // Reordering preserves dispatch by client identity; removing one enabled entry removes it from
    // the active protocol registry without claiming global session revocation.
    drop(host);
    config["business_entries"].as_array_mut().unwrap().reverse();
    host = db.start_command(port, &mut db.explicit_command_from_config(config.clone()));
    assert_eq!(
        host.raw("GET", "/one/auth/session", Some(token(&one)), None, None)
            .0,
        200
    );
    assert_eq!(
        host.raw(
            "GET",
            "/oidc/userinfo",
            tokens["access_token"].as_str(),
            None,
            None
        )
        .0,
        200
    );
    drop(host);
    config["business_entries"][2]["oidc"]["enabled"] = json!(false);
    host = db.start_command(port, &mut db.explicit_command_from_config(config.clone()));
    let now_disabled = host.raw(
        "GET",
        "/oidc/userinfo",
        tokens["access_token"].as_str(),
        None,
        None,
    );
    assert_eq!(
        now_disabled.0, 401,
        "disabled entry is no longer in OIDC dispatch registry"
    );
    host.json(
        "GET",
        "/one/auth/session",
        Some(token(&one)),
        None,
        None,
        200,
    );
    drop(host);
    for entry in config["business_entries"].as_array_mut().unwrap() {
        entry["oidc"] = json!({"enabled":false});
    }
    host = db.start_command(port, &mut db.explicit_command_from_config(config));
    for path in [
        "/.well-known/openid-configuration",
        "/oidc/jwks",
        "/oidc/userinfo",
    ] {
        assert_eq!(host.raw("GET", path, None, None, None).0, 404);
    }
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn a02b_confidential_oidc_clients_authenticate_and_isolate_resource_operations() {
    let db = Db::new(TenancyMode::Enabled);
    db.bootstrap();
    db.seed_management_client();
    let setup = db.start_explicit("/identity", "/console");
    let admin = setup.json(
        "POST",
        "/identity/admin/auth/login",
        None,
        None,
        Some(json!({"email":"admin@example.test","password":"Runtime-Admin123"})),
        200,
    );
    for (client, secret) in [
        ("confidential-one", "Synthetic-One-Secret"),
        ("confidential-two", "Synthetic-Two-Secret"),
    ] {
        setup.json(
            "POST",
            "/identity/admin/clients/upsert",
            Some(token(&admin)),
            None,
            Some(json!({"client_id":client,"client_name":client,"redirect_uris":["http://127.0.0.1/callback"],"client_type":"confidential_web","pkce_required":true,"client_secret":secret})),
            200,
        );
    }
    setup.json(
        "POST",
        "/identity/admin/tenants",
        Some(token(&admin)),
        None,
        Some(json!({"tenant_id":"confidential-domain","name":"Confidential domain","allow_registration":false,"administrator":{"kind":"new","email":"confidential@example.test","password":"Runtime-Member123"}})),
        201,
    );
    drop(setup);

    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let _ = db.explicit_command(port, db.mode, "/identity", "/console");
    let mut config: Value =
        serde_json::from_slice(&fs::read(db.dir.join("explicit.json")).unwrap()).unwrap();
    config["version"] = json!(2);
    config["business_entries"] = json!([
        {"login_entry":"confidential-one","client_id":"confidential-one","tenant_policy":{"kind":"choose"},"mount_prefix":"/one","oidc":{"enabled":true}},
        {"login_entry":"confidential-two","client_id":"confidential-two","tenant_policy":{"kind":"fixed","tenant_id":"confidential-domain"},"mount_prefix":"/two","oidc":{"enabled":true}}
    ]);
    let host = db.start_command(port, &mut db.explicit_command_from_config(config));
    let one = host.json(
        "POST",
        "/one/auth/login",
        None,
        None,
        Some(json!({"email":"confidential@example.test","password":"Runtime-Member123"})),
        200,
    );
    assert_eq!(one["status"], "tenant_selection_required");
    let one = host.json(
        "POST",
        "/one/auth/tenant-selection/complete",
        one["selection_ticket"].as_str(),
        None,
        Some(json!({"tenant_id":"confidential-domain"})),
        200,
    );
    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let (status, raw) = host.oidc_authorize(
        "response_type=code&client_id=confidential-one&redirect_uri=http%3A%2F%2F127.0.0.1%2Fcallback&scope=openid%20profile%20email&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256",
        token(&one),
    );
    assert_eq!(status, 307, "{raw}");
    let location = raw
        .lines()
        .find_map(|line| {
            line.strip_prefix("location: ")
                .or_else(|| line.strip_prefix("Location: "))
        })
        .unwrap();
    let code = location
        .split("code=")
        .nth(1)
        .unwrap()
        .split('&')
        .next()
        .unwrap();
    let token_form = format!(
        "grant_type=authorization_code&code={code}&redirect_uri=http%3A%2F%2F127.0.0.1%2Fcallback&code_verifier={verifier}"
    );
    let basic = |client: &str, secret: &str| {
        format!(
            "Basic {}",
            Base64::encode_string(format!("{client}:{secret}").as_bytes())
        )
    };
    let wrong_secret = host.oidc_form(
        "/oidc/token",
        &token_form,
        Some(&basic("confidential-one", "wrong-secret")),
    );
    assert_eq!(wrong_secret.0, 401, "{}", wrong_secret.1);
    let exchanged = host.oidc_form(
        "/oidc/token",
        &token_form,
        Some(&basic("confidential-one", "Synthetic-One-Secret")),
    );
    assert_eq!(exchanged.0, 200, "{}", exchanged.1);
    let tokens: Value = serde_json::from_str(&exchanged.1).unwrap();
    let access = tokens["access_token"].as_str().unwrap();
    let introspection = |credential: String| {
        host.oidc_form(
            "/oidc/introspect",
            &format!("token={access}&token_type_hint=access_token"),
            Some(&credential),
        )
    };
    let first_info = introspection(basic("confidential-one", "Synthetic-One-Secret"));
    assert_eq!(first_info.0, 200, "{}", first_info.1);
    assert!(serde_json::from_str::<Value>(&first_info.1).unwrap()["active"] == true);
    let wrong_secret_info = introspection(basic("confidential-one", "wrong-secret"));
    assert_eq!(wrong_secret_info.0, 401, "{}", wrong_secret_info.1);
    let cross_client_info = introspection(basic("confidential-two", "Synthetic-Two-Secret"));
    assert_eq!(cross_client_info.0, 200, "{}", cross_client_info.1);
    assert_eq!(
        serde_json::from_str::<Value>(&cross_client_info.1).unwrap()["active"],
        false
    );

    let cross_client_revoke = host.oidc_form(
        "/oidc/revoke",
        &format!("token={access}&token_type_hint=access_token"),
        Some(&basic("confidential-two", "Synthetic-Two-Secret")),
    );
    assert_eq!(cross_client_revoke.0, 200, "{}", cross_client_revoke.1);
    assert_eq!(
        host.raw("GET", "/oidc/userinfo", Some(access), None, None)
            .0,
        200,
        "cross-client revocation is a no-op for another client's token"
    );
    let revoke = host.oidc_form(
        "/oidc/revoke",
        &format!("token={access}&token_type_hint=access_token"),
        Some(&basic("confidential-one", "Synthetic-One-Secret")),
    );
    assert_eq!(revoke.0, 200, "{}", revoke.1);
    assert_eq!(
        host.raw("GET", "/oidc/userinfo", Some(access), None, None)
            .0,
        401
    );
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn a02b_b2_device_admission_is_bound_to_entry_and_registration_identity() {
    use embedded_idp_core::ClientSecretHasher;
    use std::time::{SystemTime, UNIX_EPOCH};

    let db = Db::new(TenancyMode::Disabled);
    db.bootstrap();
    db.seed_management_client();
    let setup = db.start_explicit("/identity", "/console");
    let admin = setup.json(
        "POST",
        "/identity/admin/auth/login",
        None,
        None,
        Some(json!({"email":"admin@example.test","password":"Runtime-Admin123"})),
        200,
    );
    for client in ["device-one", "device-two"] {
        setup.json(
            "POST",
            "/identity/admin/clients/upsert",
            Some(token(&admin)),
            None,
            Some(json!({"client_id":client,"client_name":client,"redirect_uris":["http://127.0.0.1/callback"],"client_type":"public_desktop","pkce_required":true})),
            200,
        );
    }
    drop(setup);

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let secret_one = "device-admission-secret-one-with-more-than-32-bytes";
    let secret_two = "device-admission-secret-two-with-more-than-32-bytes";
    let secret_expired = "expired-admission-secret-with-more-than-32-bytes";
    let grant_file = db.dir.join("grants.json");
    let grants = json!([
        {"grant_id":"grant-one","tenant_id":"0","client_id":"device-one","device_id":"11111111-1111-4111-8111-111111111111","credential_hash":embedded_idp_core::PhcClientSecretCodec.hash_client_secret(secret_one).unwrap(),"issued_at_unix_secs":now-1,"expires_at_unix_secs":now+300},
        {"grant_id":"grant-two","tenant_id":"0","client_id":"device-two","device_id":"22222222-2222-4222-8222-222222222222","credential_hash":embedded_idp_core::PhcClientSecretCodec.hash_client_secret(secret_two).unwrap(),"issued_at_unix_secs":now-1,"expires_at_unix_secs":now+300},
        {"grant_id":"grant-expired","tenant_id":"0","client_id":"device-one","device_id":"33333333-3333-4333-8333-333333333333","credential_hash":embedded_idp_core::PhcClientSecretCodec.hash_client_secret(secret_expired).unwrap(),"issued_at_unix_secs":now-10,"expires_at_unix_secs":now-1}
    ]);
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&grant_file)
        .unwrap();
    file.write_all(&serde_json::to_vec(&grants).unwrap())
        .unwrap();

    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let _ = db.explicit_command(port, db.mode, "/identity", "/console");
    let mut config: Value =
        serde_json::from_slice(&fs::read(db.dir.join("explicit.json")).unwrap()).unwrap();
    config["version"] = json!(2);
    config["runtime"]["device_admission_providers"] =
        json!([{"id":"enrollment","grants_file":"grants.json"}]);
    let entry = |client: &str, prefix: &str| {
        json!({
            "login_entry":client,"client_id":client,"tenant_policy":{"kind":"fixed","tenant_id":"0"},"mount_prefix":prefix,
            "device":{"admission_provider":"enrollment","profile_provider":"ed25519-v2","audience":format!("{client}-audience"),
                "paths":{"login":format!("{prefix}/auth/login"),"selection":format!("{prefix}/auth/tenant-selection/complete"),"refresh":format!("{prefix}/auth/refresh"),"heartbeat":format!("{prefix}/devices/heartbeat"),"oidc_token":"/oidc/token"}}
        })
    };
    config["business_entries"] = json!([entry("device-one", "/one"), entry("device-two", "/two")]);
    // Keep optional proof mode explicit for this admission isolation test.
    config["business_entries"][0]["require_device_proof"] = json!(false);
    config["business_entries"][1]["require_device_proof"] = json!(false);
    let host = db.start_command(port, &mut db.explicit_command_from_config(config));

    let send = |path: &str, admission: &[&str], body: Value| {
        let body = body.to_string();
        let mut request = format!("POST {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n", body.len());
        for value in admission {
            request.push_str(&format!("x-embedded-idp-device-admission: {value}\r\n"));
        }
        request.push_str("\r\n");
        request.push_str(&body);
        let mut stream = TcpStream::connect(("127.0.0.1", host.port)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream.write_all(request.as_bytes()).unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        let (headers, body) = response.split_once("\r\n\r\n").unwrap();
        (
            headers
                .split_whitespace()
                .nth(1)
                .unwrap()
                .parse::<u16>()
                .unwrap(),
            serde_json::from_str::<Value>(body).unwrap_or(Value::Null),
        )
    };
    let admission_key = B2DeviceKey::test_key([0x19; 32]);
    let body_one = json!({"tenant_id":"0","device_id":"11111111-1111-4111-8111-111111111111","registration_request_id":"33333333-3333-4333-8333-333333333333","device_name":"One","public_jwk":serde_json::from_str::<Value>(&admission_key.public_jwk).unwrap()});
    let admission_one = format!("grant-one.{secret_one}");
    let admission_two = format!("grant-two.{secret_two}");
    let expired_admission = format!("grant-expired.{secret_expired}");
    assert_eq!(send("/one/devices/provision", &[], body_one.clone()).0, 401);
    assert_eq!(
        send(
            "/one/devices/provision",
            &[&admission_two],
            body_one.clone()
        )
        .0,
        401,
        "admission credentials are client scoped"
    );
    assert_eq!(
        send(
            "/one/devices/provision",
            &[&format!(
                "grant-one.wrong-secret-long-enough-for-validation"
            )],
            body_one.clone()
        )
        .0,
        401
    );
    assert_eq!(
        send(
            "/one/devices/provision",
            &[&expired_admission],
            body_one.clone()
        )
        .0,
        401,
        "expired grants cannot provision"
    );
    assert_eq!(
        send(
            "/one/devices/provision",
            &[&admission_one, &admission_one],
            body_one.clone()
        )
        .0,
        401,
        "duplicate admission headers are rejected"
    );
    let mut wrong_device = body_one.clone();
    wrong_device["device_id"] = json!("99999999-9999-4999-8999-999999999999");
    assert_eq!(
        send("/one/devices/provision", &[&admission_one], wrong_device).0,
        403,
        "body device cannot widen the grant scope"
    );
    let (status, registration) = send(
        "/one/devices/provision",
        &[&admission_one],
        body_one.clone(),
    );
    assert_eq!(status, 201, "{registration}");
    assert_eq!(registration["client_id"], "device-one");
    assert_eq!(registration["device_id"], body_one["device_id"]);
    let result_body = json!({"tenant_id":"0","device_id":body_one["device_id"],"registration_request_id":body_one["registration_request_id"]});
    assert_eq!(
        send("/one/devices/registration-result", &[], result_body.clone()).0,
        401
    );
    assert_eq!(
        send(
            "/one/devices/registration-result",
            &[&admission_two],
            result_body.clone()
        )
        .0,
        401
    );
    assert_eq!(
        send(
            "/one/devices/registration-result",
            &[&admission_one],
            result_body.clone()
        )
        .0,
        200
    );
    let mut altered_result = result_body.clone();
    altered_result["device_id"] = json!("99999999-9999-4999-8999-999999999999");
    assert_eq!(
        send(
            "/one/devices/registration-result",
            &[&admission_one],
            altered_result
        )
        .0,
        403
    );
    let admission_key_two = B2DeviceKey::test_key([0x77; 32]);
    let body_two = json!({"tenant_id":"0","device_id":"22222222-2222-4222-8222-222222222222","registration_request_id":"44444444-4444-4444-8444-444444444444","device_name":"Two","public_jwk":serde_json::from_str::<Value>(&admission_key_two.public_jwk).unwrap()});
    assert_eq!(
        send(
            "/two/devices/provision",
            &[&admission_one],
            body_two.clone()
        )
        .0,
        401
    );
    let (status, registration_two) = send("/two/devices/provision", &[&admission_two], body_two);
    assert_eq!(status, 201, "{registration_two}");
    host.json(
        "POST",
        "/one/auth/login",
        None,
        None,
        Some(json!({"email":"admin@example.test","password":"Runtime-Admin123"})),
        200,
    );
}

fn b2_request(
    host: &Host,
    method: &str,
    path: &str,
    content_type: &str,
    headers: &[(String, String)],
    body: &str,
) -> (u16, String) {
    let mut request = format!(
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n",
        body.len()
    );
    for (name, value) in headers {
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    request.push_str("\r\n");
    request.push_str(body);
    let mut stream = TcpStream::connect(("127.0.0.1", host.port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stream.write_all(request.as_bytes()).unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    let (head, body) = response.split_once("\r\n\r\n").unwrap();
    (
        head.split_whitespace().nth(1).unwrap().parse().unwrap(),
        body.to_owned(),
    )
}

struct B2DeviceKey {
    key: ring::signature::Ed25519KeyPair,
    public_jwk: String,
    key_id: String,
}
impl B2DeviceKey {
    fn test_key(seed: [u8; 32]) -> Self {
        use base64ct::{Base64UrlUnpadded, Encoding};
        use ring::signature::{Ed25519KeyPair, KeyPair};
        let key = Ed25519KeyPair::from_seed_unchecked(&seed).unwrap();
        let x = Base64UrlUnpadded::encode_string(key.public_key().as_ref());
        let thumbprint_input = format!(r#"{{"crv":"Ed25519","kty":"OKP","x":"{x}"}}"#);
        let key_id = Base64UrlUnpadded::encode_string(
            ring::digest::digest(&ring::digest::SHA256, thumbprint_input.as_bytes()).as_ref(),
        );
        Self {
            key,
            public_jwk: json!({"kty":"OKP","crv":"Ed25519","x":x,"kid":key_id}).to_string(),
            key_id,
        }
    }
}

fn b2_proof_headers(
    key: &B2DeviceKey,
    device_id: &str,
    challenge: &str,
    tenant: &str,
    profile: &str,
    audience: &str,
    path: &str,
    body: &str,
    credential_context: Option<[u8; 32]>,
) -> Vec<(String, String)> {
    use base64ct::{Base64UrlUnpadded, Encoding};
    use embedded_idp_core::{
        access::build_tenant_authentication_proof_bytes, build_request_proof_bytes,
        CanonicalHttpMethod, DeviceProofPresentation, DeviceProofProfile, DeviceRequestBinding,
    };
    use std::time::{SystemTime, UNIX_EPOCH};
    let signed_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let presentation = DeviceProofPresentation {
        device_id: device_id.to_owned(),
        key_id: key.key_id.clone(),
        challenge: challenge.to_owned(),
        signature: Base64UrlUnpadded::encode_string(&[0_u8; 64]),
        signed_at: UNIX_EPOCH + Duration::from_secs(signed_at),
    };
    let binding = DeviceRequestBinding::new(
        tenant,
        DeviceProofProfile::new(profile).unwrap(),
        audience,
        CanonicalHttpMethod::Post,
        path,
        ring::digest::digest(&ring::digest::SHA256, body.as_bytes())
            .as_ref()
            .try_into()
            .unwrap(),
    )
    .unwrap();
    let canonical = match credential_context {
        Some(context) => build_tenant_authentication_proof_bytes(&binding, &presentation, &context),
        None => build_request_proof_bytes(&binding, &presentation),
    }
    .unwrap();
    let signature = Base64UrlUnpadded::encode_string(key.key.sign(&canonical).as_ref());
    vec![
        ("x-embedded-idp-tenant-id".into(), tenant.into()),
        ("x-device-id".into(), device_id.into()),
        ("x-device-key-id".into(), key.key_id.clone()),
        ("x-device-challenge".into(), challenge.into()),
        ("x-device-signature".into(), signature),
        ("x-device-signed-at".into(), signed_at.to_string()),
    ]
}

fn b3_write_private(path: &std::path::Path, bytes: &[u8]) {
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
}

fn b3_entry(client: &str, prefix: &str, host_scope: &str, origin: &str) -> Value {
    let key = |id: &str| json!({"key_id":id,"key_file":format!("{id}.key")});
    json!({
        "login_entry":client,
        "client_id":client,
        "tenant_policy":{"kind":"fixed","tenant_id":"0"},
        "mount_prefix":prefix,
        "require_device_proof":false,
        "browser":{"cookie_name":format!("{client}_browser")},
        "device":{"admission_provider":"enrollment","profile_provider":"ed25519-v2","audience":format!("{client}-device"),"paths":{"login":format!("{prefix}/auth/login"),"selection":format!("{prefix}/auth/tenant-selection/complete"),"refresh":format!("{prefix}/auth/refresh"),"heartbeat":format!("{prefix}/devices/heartbeat"),"oidc_token":"/oidc/token"}},
        "scan":{"admission_provider":"reference-identity-only","presentation_provider":"registered-device","host_scope":host_scope,"modes":["device_display","phone_display"],"audience":format!("{client}-scan"),"device_prefix":format!("{prefix}/auth/device-scan"),"verification_uri":format!("{origin}{prefix}/auth/browser/device-scan/ui"),"result_keyring":{"active_key_id":format!("{client}-active"),"keys":[key(&format!("{client}-active")),key(&format!("{client}-old"))]},"cleanup":{"interval_secs":3600,"batch_size":10}}
    })
}

fn b3_register_device(
    host: &Host,
    prefix: &str,
    device_id: &str,
    client: &str,
    admission: &str,
    key: &B2DeviceKey,
) {
    let body = json!({"tenant_id":"0","device_id":device_id,"registration_request_id":UuidV7IdGenerator.next_id("registration"),"device_name":client,"public_jwk":serde_json::from_str::<Value>(&key.public_jwk).unwrap()}).to_string();
    let headers = vec![("x-embedded-idp-device-admission".into(), admission.into())];
    let (status, response) = b2_request(
        host,
        "POST",
        &format!("{prefix}/devices/provision"),
        "application/json",
        &headers,
        &body,
    );
    assert_eq!(status, 201, "{response}");
    let challenge = host.json("POST", &format!("{prefix}/devices/proof/challenges"), None, Some("0"), Some(json!({"tenant_id":"0","device_id":device_id,"purpose":embedded_idp_core::DEVICE_REGISTRATION_PURPOSE})), 200)["challenge"].as_str().unwrap().to_owned();
    let signed = embedded_idp_core::build_device_registration_proof_bytes(
        "0",
        device_id,
        &key.key_id,
        &challenge,
    )
    .unwrap();
    use base64ct::{Base64UrlUnpadded, Encoding};
    let signature = Base64UrlUnpadded::encode_string(key.key.sign(&signed).as_ref());
    let body = json!({"tenant_id":"0","device_id":device_id,"public_jwk":serde_json::from_str::<Value>(&key.public_jwk).unwrap(),"challenge":challenge,"signature":signature}).to_string();
    let (status, response) = b2_request(
        host,
        "POST",
        &format!("{prefix}/devices/complete"),
        "application/json",
        &[("x-embedded-idp-tenant-id".into(), "0".into())],
        &body,
    );
    assert_eq!(status, 200, "{response}");
}

fn b3_scan_proof(
    host: &Host,
    prefix: &str,
    device_id: &str,
    key: &B2DeviceKey,
    audience: &str,
    action: ScanLoginAction,
    target_client_id: &str,
    entry_id: &str,
    path: &str,
    body: &str,
) -> Vec<(String, String)> {
    use embedded_idp_core::{
        CanonicalHttpMethod, DeviceProofPresentation, DeviceProofProfile, DeviceRequestBinding,
    };
    let challenge = host.json(
        "POST",
        &format!("{prefix}/devices/proof/challenges"),
        None,
        Some("0"),
        Some(json!({"tenant_id":"0","device_id":device_id,"purpose":action.purpose().as_str()})),
        200,
    )["challenge"]
        .as_str()
        .unwrap()
        .to_owned();
    let signed_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut proof = DeviceProofPresentation {
        device_id: device_id.into(),
        key_id: key.key_id.clone(),
        challenge: challenge.clone(),
        signature: base64ct::Base64UrlUnpadded::encode_string(&[0; 64]),
        signed_at: std::time::UNIX_EPOCH + Duration::from_secs(signed_at),
    };
    let binding = DeviceRequestBinding::new(
        "0",
        DeviceProofProfile::new(SCAN_LOGIN_PROOF_PROFILE).unwrap(),
        audience,
        CanonicalHttpMethod::Post,
        path,
        ring::digest::digest(&ring::digest::SHA256, body.as_bytes())
            .as_ref()
            .try_into()
            .unwrap(),
    )
    .unwrap();
    let canonical =
        build_scan_login_proof_bytes(&binding, &proof, action, target_client_id, entry_id).unwrap();
    proof.signature = base64ct::Base64UrlUnpadded::encode_string(key.key.sign(&canonical).as_ref());
    vec![
        ("x-embedded-idp-tenant-id".into(), "0".into()),
        ("x-device-id".into(), device_id.into()),
        ("x-device-key-id".into(), key.key_id.clone()),
        ("x-device-challenge".into(), challenge),
        ("x-device-signature".into(), proof.signature),
        ("x-device-signed-at".into(), signed_at.to_string()),
    ]
}

fn b3_scan_post(
    host: &Host,
    path: &str,
    headers: &[(String, String)],
    body: &str,
) -> (u16, String) {
    b2_request(host, "POST", path, "application/json", headers, body)
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn a02b_b3_scan_entries_isolate_proofs_sources_and_recover_pending_delivery() {
    b3_scan_fixture("scan");
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI and built embedded Web bundle"]
fn a04a_device_self_client_reads_and_recovers_unbind_against_reference_host() {
    b3_scan_fixture("self-service");
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI and built embedded Web bundle"]
fn a04b_registration_client_recovers_provision_and_complete_against_reference_host() {
    b3_scan_fixture("registration");
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI and built embedded Web bundle"]
fn a04c_rotation_client_dual_signs_and_recovers_against_reference_host() {
    b3_scan_fixture("rotation");
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI and built embedded Web bundle"]
fn a04d_scan_client_both_modes_recover_delivery_and_close_origin() {
    b3_scan_fixture("scan-client");
}

fn b3_scan_fixture(client_check: &str) {
    use embedded_idp_core::ClientSecretHasher;

    let db = Db::new(TenancyMode::Disabled);
    db.bootstrap();
    db.seed_management_client();
    let setup = db.start_explicit("/identity", "/console");
    let admin = setup.json(
        "POST",
        "/identity/admin/auth/login",
        None,
        None,
        Some(json!({"email":"admin@example.test","password":"Runtime-Admin123"})),
        200,
    );
    for client in ["scan-one", "scan-two"] {
        setup.json("POST", "/identity/admin/clients/upsert", Some(token(&admin)), None, Some(json!({"client_id":client,"client_name":client,"redirect_uris":["http://127.0.0.1/callback"],"client_type":"public_desktop","pkce_required":true})), 200);
    }
    drop(setup);

    let keys = [
        B2DeviceKey::test_key([0x41; 32]),
        B2DeviceKey::test_key([0x42; 32]),
    ];
    let devices = [
        "41414141-4141-4141-8141-414141414141",
        "42424242-4242-4242-8242-424242424242",
    ];
    let admission_secret = "b3-device-admission-secret-with-over-32-bytes";
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let grants = json!([
        {"grant_id":"scan-grant-one","tenant_id":"0","client_id":"scan-one","device_id":devices[0],"credential_hash":embedded_idp_core::PhcClientSecretCodec.hash_client_secret(admission_secret).unwrap(),"issued_at_unix_secs":now-1,"expires_at_unix_secs":now+300},
        {"grant_id":"scan-grant-two","tenant_id":"0","client_id":"scan-two","device_id":devices[1],"credential_hash":embedded_idp_core::PhcClientSecretCodec.hash_client_secret(admission_secret).unwrap(),"issued_at_unix_secs":now-1,"expires_at_unix_secs":now+300}
    ]);
    b3_write_private(
        &db.dir.join("b3-grants.json"),
        &serde_json::to_vec(&grants).unwrap(),
    );
    for (id, value) in [
        ("scan-one-active", 0x11),
        ("scan-one-old", 0x12),
        ("scan-two-active", 0x21),
        ("scan-two-old", 0x22),
    ] {
        b3_write_private(&db.dir.join(format!("{id}.key")), &[value; 32]);
    }

    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let _ = db.explicit_command(port, db.mode, "/identity", "/console");
    let mut config: Value =
        serde_json::from_slice(&fs::read(db.dir.join("explicit.json")).unwrap()).unwrap();
    config["version"] = json!(2);
    config["runtime"]["device_admission_providers"] =
        json!([{"id":"enrollment","grants_file":"b3-grants.json"}]);
    let origin = format!("http://127.0.0.1:{port}");
    config["business_entries"] = json!([
        b3_entry("scan-one", "/one", "b3-host-scope-one", &origin),
        b3_entry("scan-two", "/two", "b3-host-scope-two", &origin)
    ]);

    // Missing result material must fail before the host mutates database state.
    let before = db.snapshot();
    let mut missing_key = config.clone();
    missing_key["business_entries"][0]["scan"]["result_keyring"]["keys"][0]["key_file"] =
        json!("missing.key");
    let mut command = db.explicit_command_from_config(missing_key);
    assert!(!command.status().unwrap().success());
    assert_eq!(
        db.snapshot(),
        before,
        "key loading failure must precede database side effects"
    );

    let mut command = db.explicit_command_from_config(config.clone());
    let mut host = db.start_command(port, &mut command);
    for prefix in ["/one", "/two"] {
        let page_path = format!("{prefix}/auth/browser/device-scan/ui");
        let (status, page) = host.raw("GET", &page_path, None, None, None);
        assert_eq!(status, 200, "{page_path}: {page}");
        assert!(page.contains(&format!("import \"{page_path}/assets/scan-code.js\"")));

        let asset_path = format!("{page_path}/assets/scan-code.js");
        let (status, asset) = host.raw("GET", &asset_path, None, None, None);
        assert_eq!(status, 200, "{asset_path}: {asset}");
        assert!(!asset.is_empty(), "{asset_path} returned an empty asset");
    }
    if client_check == "registration" {
        let output = Command::new("node")
            .arg("../../web/embedded/registration-live-check.mjs")
            .env("IDP_A04B_BASE", format!("{origin}/one"))
            .env("IDP_A04B_DEVICE", devices[0])
            .env(
                "IDP_A04B_ADMISSION",
                format!("scan-grant-one.{admission_secret}"),
            )
            .env("IDP_A04B_EXPIRES", (now + 300).to_string())
            .output()
            .expect("run built JS registration client");
        assert!(
            output.status.success(),
            "A04-B JS registration failed: {}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        host.terminate_gracefully();
        return;
    }
    b3_register_device(
        &host,
        "/one",
        devices[0],
        "scan-one",
        &format!("scan-grant-one.{admission_secret}"),
        &keys[0],
    );
    b3_register_device(
        &host,
        "/two",
        devices[1],
        "scan-two",
        &format!("scan-grant-two.{admission_secret}"),
        &keys[1],
    );

    if client_check == "scan-client" {
        let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../web/embedded/scan-live-check.mjs");
        let output = Command::new("node")
            .arg(script)
            .env("IDP_A04D_BASE", format!("http://127.0.0.1:{port}/one"))
            .output()
            .expect("run actual scan JS client");
        assert!(
            output.status.success(),
            "A04-D JS scan failed: {}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        host.terminate_gracefully();
        return;
    }

    let (status, cookie_one, browser_one) = host.browser(
        "/one/auth/browser/login",
        None,
        None,
        json!({"email":"admin@example.test","password":"Runtime-Admin123"}),
    );
    assert_eq!(status, 200, "{browser_one}");
    let cookie_one = cookie_one.unwrap();
    let identity_one = browser_identity(&browser_one["session"]);
    let (status, cookie_two, browser_two) = host.browser(
        "/two/auth/browser/login",
        None,
        None,
        json!({"email":"admin@example.test","password":"Runtime-Admin123"}),
    );
    assert_eq!(status, 200, "{browser_two}");
    let cookie_two = cookie_two.unwrap();
    let identity_two = browser_identity(&browser_two["session"]);

    // A source cookie from entry one cannot authenticate entry two. Entry one's
    // own context still succeeds with the same cookie/session pair.
    let (status, _, _) = host.browser(
        "/two/auth/browser/device-scan/context",
        Some(cookie_pair(&cookie_one)),
        None,
        json!({"expected_session":identity_one}),
    );
    assert_eq!(status, 401);
    let (status, _, context_one) = host.browser(
        "/one/auth/browser/device-scan/context",
        Some(cookie_pair(&cookie_one)),
        None,
        json!({"expected_session":identity_one}),
    );
    assert_eq!(status, 200, "{context_one}");
    let (status, _, context_two) = host.browser(
        "/two/auth/browser/device-scan/context",
        Some(cookie_pair(&cookie_two)),
        None,
        json!({"expected_session":identity_two}),
    );
    assert_eq!(status, 200, "{context_two}");
    let (status, _, phone) = host.browser("/two/auth/browser/device-scan/phone-codes", Some(cookie_pair(&cookie_two)), None, json!({"operation_id":UuidV7IdGenerator.next_id("phone-code"),"entry_id":context_two["entry"]["entry_id"],"expected_session":identity_two}));
    assert_eq!(status, 201, "{phone}");
    assert_eq!(phone["progress"]["mode"], "phone_display");

    let delivery_secret = base64ct::Base64UrlUnpadded::encode_string(&[0x55; 32]);
    let delivery_hash = base64ct::Base64UrlUnpadded::encode_string(
        ring::digest::digest(&ring::digest::SHA256, &[0x55; 32]).as_ref(),
    );
    let create_path = "/one/auth/device-scan/create";
    let create_body = json!({"operation_id":UuidV7IdGenerator.next_id("scan-create"),"entry_id":"scan-one","tenant_id":"0","delivery_secret_hash":delivery_hash}).to_string();
    let create_proof = b3_scan_proof(
        &host,
        "/one",
        devices[0],
        &keys[0],
        "scan-one-scan",
        ScanLoginAction::Create,
        "scan-one",
        "scan-one",
        create_path,
        &create_body,
    );

    // Wrong external route and body scope reject without consuming the nonce;
    // the exact signed request succeeds immediately afterward.
    let wrong_entry = json!({"operation_id":UuidV7IdGenerator.next_id("scan-create-cross-entry"),"entry_id":"scan-two","tenant_id":"0","delivery_secret_hash":delivery_hash}).to_string();
    let (status, _) = b3_scan_post(
        &host,
        "/two/auth/device-scan/create",
        &create_proof,
        &wrong_entry,
    );
    assert!(status >= 400, "cross-entry proof unexpectedly succeeded");
    let wrong_scope = json!({"operation_id":UuidV7IdGenerator.next_id("scan-create-wrong"),"entry_id":"scan-one","tenant_id":"wrong-tenant","delivery_secret_hash":delivery_hash}).to_string();
    let wrong_scope_headers = create_proof.clone();
    let (status, _) = b3_scan_post(&host, create_path, &wrong_scope_headers, &wrong_scope);
    assert!(status >= 400, "wrong-tenant proof unexpectedly succeeded");
    let (status, response) = b3_scan_post(&host, create_path, &create_proof, &create_body);
    assert_eq!(status, 201, "{response}");
    let created: Value = serde_json::from_str(&response).unwrap();
    let grant_id = created["progress"]["grant_id"].as_str().unwrap().to_owned();
    let display_code = created["display_code"].as_str().unwrap().to_owned();

    let (status, _, attached) = host.browser("/one/auth/browser/device-scan/attach", Some(cookie_pair(&cookie_one)), None, json!({"operation_id":UuidV7IdGenerator.next_id("scan-attach"),"display_code":display_code,"expected_session":identity_one}));
    assert_eq!(status, 200, "{attached}");
    assert_eq!(attached["progress"]["grant_id"], grant_id);
    let (status, _, approved) = host.browser("/one/auth/browser/device-scan/approve", Some(cookie_pair(&cookie_one)), None, json!({"operation_id":UuidV7IdGenerator.next_id("scan-approve"),"grant_id":grant_id,"confirmation_revision":attached["confirmation_revision"],"expected_session":identity_one}));
    assert_eq!(status, 200, "{approved}");

    let exchange_path = "/one/auth/device-scan/exchange";
    let issuance_operation_id = UuidV7IdGenerator.next_id("scan-exchange");
    let exchange_body = json!({"operation_id":issuance_operation_id,"grant_id":grant_id,"delivery_secret":delivery_secret,"tenant_id":"0"}).to_string();
    let exchange_proof = b3_scan_proof(
        &host,
        "/one",
        devices[0],
        &keys[0],
        "scan-one-scan",
        ScanLoginAction::Exchange,
        "scan-one",
        "scan-one",
        exchange_path,
        &exchange_body,
    );
    let (status, response) = b3_scan_post(&host, exchange_path, &exchange_proof, &exchange_body);
    assert_eq!(status, 200, "{response}");
    let pending: Value = serde_json::from_str(&response).unwrap();
    let access = pending["tokens"]["access_token"].as_str().unwrap();
    assert_eq!(
        host.raw("GET", "/one/auth/session", Some(access), None, None)
            .0,
        401,
        "unacknowledged delivery is not an active session"
    );

    // Restart with the old key active. The pending result was encrypted with
    // the previous active key and must still be recoverable from the ring.
    drop(host);
    config["business_entries"][0]["scan"]["result_keyring"]["active_key_id"] =
        json!("scan-one-old");
    let mut command = db.explicit_command_from_config(config);
    command.stderr(Stdio::inherit());
    let mut host = db.start_command(port, &mut command);
    let recover_path = "/one/auth/device-scan/recover";
    let recover_body = json!({"issuance_operation_id":issuance_operation_id,"grant_id":grant_id,"delivery_secret":delivery_secret,"tenant_id":"0"}).to_string();
    let recover_proof = b3_scan_proof(
        &host,
        "/one",
        devices[0],
        &keys[0],
        "scan-one-scan",
        ScanLoginAction::Recover,
        "scan-one",
        "scan-one",
        recover_path,
        &recover_body,
    );
    let (status, response) = b3_scan_post(&host, recover_path, &recover_proof, &recover_body);
    assert_eq!(status, 200, "{response}");
    let recovered: Value = serde_json::from_str(&response).unwrap();
    assert_eq!(
        recovered["session"]["session_id"],
        pending["session"]["session_id"]
    );
    assert_eq!(
        recovered["tokens"]["access_token"],
        pending["tokens"]["access_token"]
    );
    assert_eq!(recovered["receipt_nonce"], pending["receipt_nonce"]);

    let ack_path = "/one/auth/device-scan/acknowledge";
    let ack_body = json!({"operation_id":UuidV7IdGenerator.next_id("scan-ack"),"issuance_operation_id":issuance_operation_id,"grant_id":grant_id,"delivery_secret":delivery_secret,"receipt_nonce":recovered["receipt_nonce"],"tenant_id":"0"}).to_string();
    let ack_proof = b3_scan_proof(
        &host,
        "/one",
        devices[0],
        &keys[0],
        "scan-one-scan",
        ScanLoginAction::Acknowledge,
        "scan-one",
        "scan-one",
        ack_path,
        &ack_body,
    );
    let (status, response) = b3_scan_post(&host, ack_path, &ack_proof, &ack_body);
    assert_eq!(status, 200, "{response}");
    assert_eq!(
        host.raw("GET", "/one/auth/session", Some(access), None, None)
            .0,
        200
    );
    if client_check == "self-service" || client_check == "rotation" {
        let script =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(if client_check == "rotation" {
                "../../web/embedded/rotation-live-check.mjs"
            } else {
                "../../web/embedded/device-live-check.mjs"
            });
        let output = Command::new("node")
            .arg(script)
            .env("IDP_A04_BASE", format!("http://127.0.0.1:{port}/one"))
            .output()
            .expect("run local device client check with Node");
        assert!(
            output.status.success(),
            "device client check failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    host.terminate_gracefully();
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn a02b_b2_device_proofs_bind_registration_auth_refresh_and_shared_oidc_exchange() {
    use base64ct::{Base64UrlUnpadded, Encoding};
    use embedded_idp_core::{
        access::{
            tenant_code_proof_context, tenant_password_proof_context, tenant_refresh_proof_context,
            *,
        },
        build_device_registration_proof_bytes, ClientSecretHasher, SecretString,
        DEVICE_REGISTRATION_PURPOSE, REFRESH_PURPOSE,
    };
    use std::time::{SystemTime, UNIX_EPOCH};

    let db = Db::new(TenancyMode::Disabled);
    db.bootstrap();
    db.seed_management_client();
    let setup = db.start_explicit("/identity", "/console");
    let admin = setup.json(
        "POST",
        "/identity/admin/auth/login",
        None,
        None,
        Some(json!({"email":"admin@example.test","password":"Runtime-Admin123"})),
        200,
    );
    for client in ["proof-one", "proof-two"] {
        setup.json(
            "POST",
            "/identity/admin/clients/upsert",
            Some(token(&admin)),
            None,
            Some(json!({"client_id":client,"client_name":client,"redirect_uris":["http://127.0.0.1/callback"],"client_type":"public_desktop","pkce_required":true})),
            200,
        );
    }
    drop(setup);

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let admission_secret = "proof-admission-secret-has-at-least-thirty-two-bytes";
    let device_ids = [
        "51515151-5151-4151-8151-515151515151",
        "62626262-6262-4262-8262-626262626262",
    ];
    let keys = [
        B2DeviceKey::test_key([0x31; 32]),
        B2DeviceKey::test_key([0x62; 32]),
    ];
    let grants = json!([
        {"grant_id":"proof-grant-one","tenant_id":"0","client_id":"proof-one","device_id":device_ids[0],"credential_hash":embedded_idp_core::PhcClientSecretCodec.hash_client_secret(admission_secret).unwrap(),"issued_at_unix_secs":now-1,"expires_at_unix_secs":now+300},
        {"grant_id":"proof-grant-two","tenant_id":"0","client_id":"proof-two","device_id":device_ids[1],"credential_hash":embedded_idp_core::PhcClientSecretCodec.hash_client_secret(admission_secret).unwrap(),"issued_at_unix_secs":now-1,"expires_at_unix_secs":now+300}
    ]);
    use std::os::unix::fs::OpenOptionsExt;
    let grant_path = db.dir.join("proof-grants.json");
    let mut grants_file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&grant_path)
        .unwrap();
    grants_file
        .write_all(&serde_json::to_vec(&grants).unwrap())
        .unwrap();

    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let _ = db.explicit_command(port, db.mode, "/identity", "/console");
    let mut config: Value =
        serde_json::from_slice(&fs::read(db.dir.join("explicit.json")).unwrap()).unwrap();
    config["version"] = json!(2);
    config["runtime"]["device_admission_providers"] =
        json!([{"id":"enrollment","grants_file":"proof-grants.json"}]);
    config["business_entries"] = json!([
        {"login_entry":"proof-one","client_id":"proof-one","tenant_policy":{"kind":"fixed","tenant_id":"0"},"mount_prefix":"/one","require_device_proof":true,"device":{"admission_provider":"enrollment","profile_provider":"ed25519-v2","audience":"device-one","paths":{"login":"/one/auth/login","selection":"/one/auth/tenant-selection/complete","refresh":"/one/auth/refresh","heartbeat":"/one/devices/heartbeat","oidc_token":"/oidc/token"}},"oidc":{"enabled":true}},
        {"login_entry":"proof-two","client_id":"proof-two","tenant_policy":{"kind":"fixed","tenant_id":"0"},"mount_prefix":"/two","require_device_proof":true,"device":{"admission_provider":"enrollment","profile_provider":"ed25519-v2","audience":"device-two","paths":{"login":"/two/auth/login","selection":"/two/auth/tenant-selection/complete","refresh":"/two/auth/refresh","heartbeat":"/two/devices/heartbeat","oidc_token":"/oidc/token"}},"oidc":{"enabled":true}}
    ]);
    let host = db.start_command(port, &mut db.explicit_command_from_config(config));

    for index in 0..2 {
        let client = if index == 0 { "proof-one" } else { "proof-two" };
        let prefix = if index == 0 { "/one" } else { "/two" };
        let body = json!({"tenant_id":"0","device_id":device_ids[index],"registration_request_id":format!("71717171-7171-4171-8171-71717171717{index}"),"device_name":client,"public_jwk":serde_json::from_str::<Value>(&keys[index].public_jwk).unwrap()}).to_string();
        let admission = vec![(
            "x-embedded-idp-device-admission".into(),
            format!(
                "proof-grant-{}.{admission_secret}",
                if index == 0 { "one" } else { "two" }
            ),
        )];
        let (status, response) = b2_request(
            &host,
            "POST",
            &format!("{prefix}/devices/provision"),
            "application/json",
            &admission,
            &body,
        );
        assert_eq!(status, 201, "{response}");
        assert_eq!(
            serde_json::from_str::<Value>(&response).unwrap()["client_id"],
            client
        );
        let challenge_body = json!({"tenant_id":"0","device_id":device_ids[index],"purpose":DEVICE_REGISTRATION_PURPOSE});
        let challenge_response = host.json(
            "POST",
            &format!("{prefix}/devices/proof/challenges"),
            None,
            Some("0"),
            Some(challenge_body),
            200,
        );
        let challenge = challenge_response["challenge"].as_str().unwrap();
        let registration_bytes = build_device_registration_proof_bytes(
            "0",
            device_ids[index],
            &keys[index].key_id,
            challenge,
        )
        .unwrap();
        let signature =
            Base64UrlUnpadded::encode_string(keys[index].key.sign(&registration_bytes).as_ref());
        let complete = json!({"tenant_id":"0","device_id":device_ids[index],"public_jwk":serde_json::from_str::<Value>(&keys[index].public_jwk).unwrap(),"challenge":challenge,"signature":signature}).to_string();
        let headers = vec![("x-embedded-idp-tenant-id".into(), "0".into())];
        let (status, response) = b2_request(
            &host,
            "POST",
            &format!("{prefix}/devices/complete"),
            "application/json",
            &headers,
            &complete,
        );
        assert_eq!(status, 200, "{response}");
        assert_eq!(
            serde_json::from_str::<Value>(&response).unwrap()["key_id"],
            keys[index].key_id
        );
    }

    let key = &keys[0];
    let device_id = device_ids[0];
    let login_body =
        json!({"email":"admin@example.test","password":"Runtime-Admin123"}).to_string();
    assert_eq!(
        host.raw(
            "POST",
            "/one/auth/login",
            None,
            None,
            Some(serde_json::from_str(&login_body).unwrap())
        )
        .0,
        403,
        "required-proof entries reject password-only login"
    );
    let issue_login_challenge = |device: &str, path: &str| {
        host.json(
            "POST",
            path,
            None,
            Some("0"),
            Some(json!({"tenant_id":"0","device_id":device,"purpose":"tenant_login"})),
            200,
        )["challenge"]
            .as_str()
            .unwrap()
            .to_owned()
    };
    let password_command = TenantPasswordLogin {
        email: "admin@example.test".into(),
        password: SecretString::new("Runtime-Admin123"),
    };
    let context = tenant_password_proof_context("proof-one", "proof-one", &password_command);
    let login_challenge = issue_login_challenge(device_id, "/one/devices/proof/challenges");
    // Negative proofs use the same still-unconsumed nonce; the valid request
    // succeeds afterwards, proving rejection did not consume it.
    let bad_audience = b2_proof_headers(
        key,
        device_id,
        &login_challenge,
        "0",
        "EMBEDDED-IDP-DEVICE-AUTH-V2",
        "device-two",
        "/one/auth/login",
        &login_body,
        Some(context),
    );
    assert_eq!(
        b2_request(
            &host,
            "POST",
            "/one/auth/login",
            "application/json",
            &bad_audience,
            &login_body
        )
        .0,
        401
    );
    let bad_path = b2_proof_headers(
        key,
        device_id,
        &login_challenge,
        "0",
        "EMBEDDED-IDP-DEVICE-AUTH-V2",
        "device-one",
        "/one/auth/refresh",
        &login_body,
        Some(context),
    );
    assert_eq!(
        b2_request(
            &host,
            "POST",
            "/one/auth/login",
            "application/json",
            &bad_path,
            &login_body
        )
        .0,
        401
    );
    let bad_body_proof = b2_proof_headers(
        key,
        device_id,
        &login_challenge,
        "0",
        "EMBEDDED-IDP-DEVICE-AUTH-V2",
        "device-one",
        "/one/auth/login",
        &login_body,
        Some(context),
    );
    let changed_login = format!(" {login_body}");
    assert_eq!(
        b2_request(
            &host,
            "POST",
            "/one/auth/login",
            "application/json",
            &bad_body_proof,
            &changed_login
        )
        .0,
        401
    );
    let proof_headers = b2_proof_headers(
        key,
        device_id,
        &login_challenge,
        "0",
        "EMBEDDED-IDP-DEVICE-AUTH-V2",
        "device-one",
        "/one/auth/login",
        &login_body,
        Some(context),
    );
    let (status, response) = b2_request(
        &host,
        "POST",
        "/one/auth/login",
        "application/json",
        &proof_headers,
        &login_body,
    );
    assert_eq!(status, 200, "valid nonce remained unconsumed: {response}");
    let login: Value = serde_json::from_str(&response).unwrap();
    let old_refresh = login["tokens"]["refresh_token"]
        .as_str()
        .unwrap()
        .to_owned();

    // The second entry has its own audience and key and completes a real proof login.
    let second_key = &keys[1];
    let second_device = device_ids[1];
    let second_challenge = issue_login_challenge(second_device, "/two/devices/proof/challenges");
    let second_context = tenant_password_proof_context("proof-two", "proof-two", &password_command);
    let second_proof = b2_proof_headers(
        second_key,
        second_device,
        &second_challenge,
        "0",
        "EMBEDDED-IDP-DEVICE-AUTH-V2",
        "device-two",
        "/two/auth/login",
        &login_body,
        Some(second_context),
    );
    let (status, response) = b2_request(
        &host,
        "POST",
        "/two/auth/login",
        "application/json",
        &second_proof,
        &login_body,
    );
    assert_eq!(status, 200, "{response}");

    let refresh_body = json!({"refresh_token":old_refresh}).to_string();
    let refresh_challenge = host.json(
        "POST",
        "/one/devices/proof/challenges",
        None,
        Some("0"),
        Some(json!({"tenant_id":"0","device_id":device_id,"purpose":REFRESH_PURPOSE})),
        200,
    )["challenge"]
        .as_str()
        .unwrap()
        .to_owned();
    let refresh_context =
        tenant_refresh_proof_context("proof-one", "proof-one", &SecretString::new(&old_refresh));
    let refresh_headers = b2_proof_headers(
        key,
        device_id,
        &refresh_challenge,
        "0",
        "EMBEDDED-IDP-DEVICE-AUTH-V2",
        "device-one",
        "/one/auth/refresh",
        &refresh_body,
        Some(refresh_context),
    );
    let (status, response) = b2_request(
        &host,
        "POST",
        "/one/auth/refresh",
        "application/json",
        &refresh_headers,
        &refresh_body,
    );
    assert_eq!(status, 200, "{response}");
    let refreshed: Value = serde_json::from_str(&response).unwrap();
    assert_ne!(refreshed["tokens"]["refresh_token"], old_refresh);
    assert_eq!(
        host.raw(
            "POST",
            "/one/auth/refresh",
            None,
            None,
            Some(json!({"refresh_token":refreshed["tokens"]["refresh_token"]}))
        )
        .0,
        403,
        "device refresh cannot downgrade to an unproven request"
    );

    let heartbeat_body = json!({"device_id":device_id}).to_string();
    let heartbeat_challenge = host.json(
        "POST",
        "/one/devices/proof/challenges",
        None,
        Some("0"),
        Some(json!({"tenant_id":"0","device_id":device_id,"purpose":"heartbeat"})),
        200,
    )["challenge"]
        .as_str()
        .unwrap()
        .to_owned();
    let mut heartbeat_proof = b2_proof_headers(
        key,
        device_id,
        &heartbeat_challenge,
        "0",
        "EMBEDDED-IDP-DEVICE-REQUEST-V2",
        "device-one",
        "/one/devices/heartbeat",
        &heartbeat_body,
        None,
    );
    heartbeat_proof.push((
        "authorization".into(),
        format!("Bearer {}", token(&refreshed)),
    ));
    assert_eq!(
        b2_request(
            &host,
            "POST",
            "/one/devices/heartbeat",
            "application/json",
            &heartbeat_proof,
            &heartbeat_body
        )
        .0,
        200,
        "heartbeat uses request-v2 and its configured audience/path"
    );
    assert_eq!(
        b2_request(
            &host,
            "POST",
            "/one/devices/heartbeat",
            "application/json",
            &heartbeat_proof,
            &heartbeat_body
        )
        .0,
        401,
        "heartbeat nonce cannot be replayed"
    );
    let wrong_heartbeat_challenge = host.json(
        "POST",
        "/one/devices/proof/challenges",
        None,
        Some("0"),
        Some(json!({"tenant_id":"0","device_id":device_id,"purpose":"heartbeat"})),
        200,
    )["challenge"]
        .as_str()
        .unwrap()
        .to_owned();
    let mut wrong_heartbeat_path = b2_proof_headers(
        key,
        device_id,
        &wrong_heartbeat_challenge,
        "0",
        "EMBEDDED-IDP-DEVICE-REQUEST-V2",
        "device-one",
        "/one/auth/login",
        &heartbeat_body,
        None,
    );
    wrong_heartbeat_path.push((
        "authorization".into(),
        format!("Bearer {}", token(&refreshed)),
    ));
    assert_eq!(
        b2_request(
            &host,
            "POST",
            "/one/devices/heartbeat",
            "application/json",
            &wrong_heartbeat_path,
            &heartbeat_body
        )
        .0,
        401,
        "heartbeat rejects a proof signed for another route"
    );

    // The common issuer chooses the proof profile from client_id and verifies the raw form bytes.
    let access = token(&login);
    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = Base64UrlUnpadded::encode_string(
        ring::digest::digest(&ring::digest::SHA256, verifier.as_bytes()).as_ref(),
    );
    let query = format!("response_type=code&client_id=proof-one&redirect_uri=http%3A%2F%2F127.0.0.1%2Fcallback&scope=openid%20profile%20email&state=b2state&code_challenge={challenge}&code_challenge_method=S256");
    let (status, raw) = host.oidc_authorize(&query, access);
    assert_eq!(status, 307, "{raw}");
    let location = raw
        .lines()
        .find_map(|line| {
            line.strip_prefix("location: ")
                .or_else(|| line.strip_prefix("Location: "))
                .map(str::trim)
        })
        .unwrap();
    let code = location
        .split("code=")
        .nth(1)
        .unwrap()
        .split('&')
        .next()
        .unwrap();
    let form = format!("grant_type=authorization_code&client_id=proof-one&code={code}&redirect_uri=http%3A%2F%2F127.0.0.1%2Fcallback&code_verifier={verifier}");
    let issue_oidc_challenge = || {
        host.json(
            "POST",
            "/one/devices/proof/challenges",
            None,
            Some("0"),
            Some(json!({"tenant_id":"0","device_id":device_id,"purpose":"authorization_code"})),
            200,
        )["challenge"]
            .as_str()
            .unwrap()
            .to_owned()
    };
    let oidc_challenge = issue_oidc_challenge();
    let command = TenantCodeExchange {
        grant_type: "authorization_code".into(),
        client_id: "proof-one".into(),
        code: SecretString::new(code),
        redirect_uri: "http://127.0.0.1/callback".into(),
        client_secret: None,
        code_verifier: Some(SecretString::new(verifier)),
    };
    let oidc_context = tenant_code_proof_context("proof-one", &command);
    let oidc_headers = b2_proof_headers(
        key,
        device_id,
        &oidc_challenge,
        "0",
        "EMBEDDED-IDP-DEVICE-AUTH-V2",
        "device-one",
        "/oidc/token",
        &form,
        Some(oidc_context),
    );
    let wrong_audience = b2_proof_headers(
        key,
        device_id,
        &oidc_challenge,
        "0",
        "EMBEDDED-IDP-DEVICE-AUTH-V2",
        "device-two",
        "/oidc/token",
        &form,
        Some(oidc_context),
    );
    assert_ne!(
        b2_request(
            &host,
            "POST",
            "/oidc/token",
            "application/x-www-form-urlencoded",
            &wrong_audience,
            &form
        )
        .0,
        200
    );
    let wrong_path = b2_proof_headers(
        key,
        device_id,
        &oidc_challenge,
        "0",
        "EMBEDDED-IDP-DEVICE-AUTH-V2",
        "device-one",
        "/one/auth/refresh",
        &form,
        Some(oidc_context),
    );
    assert_ne!(
        b2_request(
            &host,
            "POST",
            "/oidc/token",
            "application/x-www-form-urlencoded",
            &wrong_path,
            &form
        )
        .0,
        200
    );
    let changed_form = form.split('&').rev().collect::<Vec<_>>().join("&");
    let changed_body_proof = b2_proof_headers(
        key,
        device_id,
        &oidc_challenge,
        "0",
        "EMBEDDED-IDP-DEVICE-AUTH-V2",
        "device-one",
        "/oidc/token",
        &form,
        Some(oidc_context),
    );
    assert_ne!(
        b2_request(
            &host,
            "POST",
            "/oidc/token",
            "application/x-www-form-urlencoded",
            &changed_body_proof,
            &changed_form
        )
        .0,
        200
    );
    let wrong_client_form = form.replace("client_id=proof-one", "client_id=proof-two");
    let wrong_client_proof = b2_proof_headers(
        key,
        device_id,
        &oidc_challenge,
        "0",
        "EMBEDDED-IDP-DEVICE-AUTH-V2",
        "device-one",
        "/oidc/token",
        &form,
        Some(oidc_context),
    );
    assert_ne!(
        b2_request(
            &host,
            "POST",
            "/oidc/token",
            "application/x-www-form-urlencoded",
            &wrong_client_proof,
            &wrong_client_form
        )
        .0,
        200
    );
    let (status, response) = b2_request(
        &host,
        "POST",
        "/oidc/token",
        "application/x-www-form-urlencoded",
        &oidc_headers,
        &form,
    );
    assert_eq!(status, 200, "{response}");
    let exchanged: Value = serde_json::from_str(&response).unwrap();
    assert_eq!(exchanged["token_type"], "Bearer");
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn a02_choose_confidential_and_opt_in_registration() {
    let db = Db::new(TenancyMode::Enabled);
    db.bootstrap();
    db.seed_management_client();
    let setup = db.start_explicit("/identity", "/console");
    let admin = setup.json(
        "POST",
        "/identity/admin/auth/login",
        None,
        None,
        Some(json!({"email":"admin@example.test","password":"Runtime-Admin123"})),
        200,
    );
    for client in ["choose-one", "choose-two", "fixed-registration"] {
        setup.json("POST", "/identity/admin/clients/upsert", Some(token(&admin)), None, Some(json!({"client_id":client,"client_name":client,"redirect_uris":["http://127.0.0.1/callback"],"client_type":"public_desktop","pkce_required":true})), 200);
    }
    setup.json("POST", "/identity/admin/clients/upsert", Some(token(&admin)), None, Some(json!({"client_id":"backend","client_name":"Backend","redirect_uris":["http://127.0.0.1/callback"],"client_type":"confidential_web","pkce_required":true,"client_secret":"Synthetic-Backend-Secret"})), 200);
    setup.json("POST", "/identity/admin/tenants", Some(token(&admin)), None, Some(json!({"tenant_id":"domain-a","name":"A","allow_registration":true,"administrator":{"kind":"new","email":"choose@example.test","password":"Runtime-Member123"}})), 201);
    let members = setup.json(
        "GET",
        "/identity/admin/accounts",
        Some(token(&admin)),
        Some("domain-a"),
        None,
        200,
    );
    let subject = members["items"][0]["account_id"].as_str().unwrap();
    setup.json("POST", "/identity/admin/tenants", Some(token(&admin)), None, Some(json!({"tenant_id":"domain-b","name":"B","allow_registration":true,"administrator":{"kind":"existing","subject_id":subject}})), 201);
    drop(setup);
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let _ = db.explicit_command(port, TenancyMode::Enabled, "/identity", "/console");
    let mut config: Value =
        serde_json::from_slice(&fs::read(db.dir.join("explicit.json")).unwrap()).unwrap();
    config["runtime"]["email"] = json!({"mode":"log"});
    config["business_entries"] = json!([
        {"login_entry":"choose-one","client_id":"choose-one","tenant_policy":{"kind":"choose"},"mount_prefix":"/choose-one","browser":{"cookie_name":"choose_one"}},
        {"login_entry":"choose-two","client_id":"choose-two","tenant_policy":{"kind":"choose"},"mount_prefix":"/choose-two"},
        {"login_entry":"backend","client_id":"backend","tenant_policy":{"kind":"fixed","tenant_id":"domain-a"},"mount_prefix":"/backend","browser":{"cookie_name":"backend_browser"}},
        {"login_entry":"registration","client_id":"fixed-registration","tenant_policy":{"kind":"fixed","tenant_id":"domain-a"},"mount_prefix":"/registration","registration_enabled":true}
    ]);
    let host = db.start_command(port, &mut db.explicit_command_from_config(config));
    let credentials = json!({"email":"choose@example.test","password":"Runtime-Member123"});
    let choice = host.json(
        "POST",
        "/choose-one/auth/login",
        None,
        None,
        Some(credentials.clone()),
        200,
    );
    assert_eq!(choice["status"], "tenant_selection_required");
    let ticket = choice["selection_ticket"].as_str().unwrap();
    assert_eq!(
        host.raw(
            "POST",
            "/choose-two/auth/tenant-selection/complete",
            Some(ticket),
            None,
            Some(json!({"tenant_id":"domain-a"}))
        )
        .0,
        401
    );
    let tenants = host.json(
        "GET",
        "/choose-one/auth/tenant-selection/tenants",
        Some(ticket),
        None,
        None,
        200,
    );
    assert_eq!(tenants["tenants"].as_array().unwrap().len(), 2);
    let selected = host.json(
        "POST",
        "/choose-one/auth/tenant-selection/complete",
        Some(ticket),
        None,
        Some(json!({"tenant_id":"domain-a"})),
        200,
    );
    assert_eq!(selected["session"]["tenant_id"], "domain-a");
    let switch = host.json(
        "POST",
        "/choose-one/auth/me/tenant-selection",
        Some(token(&selected)),
        None,
        None,
        200,
    );
    let switched = host.json(
        "POST",
        "/choose-one/auth/tenant-selection/complete",
        switch["selection_ticket"].as_str(),
        None,
        Some(json!({"tenant_id":"domain-b"})),
        200,
    );
    assert_eq!(switched["session"]["tenant_id"], "domain-b");
    let (status, _, browser_choice) = host.browser(
        "/choose-one/auth/browser/login",
        None,
        None,
        credentials.clone(),
    );
    assert_eq!(status, 200);
    let (status, cookie, browser_selected) = host.browser(
        "/choose-one/auth/browser/tenant-selection/complete",
        None,
        browser_choice["selection_ticket"].as_str(),
        json!({"tenant_id":"domain-a"}),
    );
    assert_eq!(status, 200);
    assert!(cookie.unwrap().contains("Path=/choose-one/auth/browser"));
    assert_eq!(browser_selected["session"]["tenant_id"], "domain-a");
    // Confidential credentials stay in the server caller; browser lifecycle needs none.
    let (status, cookie, browser) = host.browser(
        "/backend/auth/browser/login",
        None,
        None,
        credentials.clone(),
    );
    assert_eq!(status, 200);
    let cookie = cookie.unwrap();
    assert_eq!(
        host.browser(
            "/backend/auth/browser/logout",
            Some(cookie_pair(&cookie)),
            None,
            json!({"expected_session":browser_identity(&browser["session"])})
        )
        .0,
        204
    );
    for basic in [false, true] {
        let backend = host.json(
            "POST",
            "/backend/auth/login",
            None,
            None,
            Some(credentials.clone()),
            200,
        );
        let refresh = backend["tokens"]["refresh_token"].as_str().unwrap();
        let form = format!("refresh_token={refresh}&client_id=backend");
        assert_eq!(
            host.ordinary_logout_form("/backend/auth/logout", &form, None),
            401
        );
        assert_eq!(
            host.ordinary_logout_form(
                "/backend/auth/logout",
                &format!("{form}&client_secret=wrong"),
                None
            ),
            401
        );
        assert_eq!(
            host.raw(
                "GET",
                "/backend/auth/session",
                Some(token(&backend)),
                None,
                None
            )
            .0,
            200
        );
        let status = if basic {
            host.ordinary_logout_form(
                "/backend/auth/logout",
                &format!("refresh_token={refresh}"),
                Some("backend:Synthetic-Backend-Secret"),
            )
        } else {
            host.ordinary_logout_form(
                "/backend/auth/logout",
                &format!("{form}&client_secret=Synthetic-Backend-Secret"),
                None,
            )
        };
        assert_eq!(status, 200);
        assert_eq!(
            host.raw(
                "GET",
                "/backend/auth/session",
                Some(token(&backend)),
                None,
                None
            )
            .0,
            401
        );
    }
    let registration = json!({"tenant_id":"domain-a","email":"registered@example.test","password":"Registration-Test123"});
    assert_eq!(
        host.raw(
            "POST",
            "/choose-one/auth/register",
            None,
            None,
            Some(registration.clone())
        )
        .0,
        404
    );
    let mut wrong = registration.clone();
    wrong["tenant_id"] = "domain-b".into();
    assert_eq!(
        host.raw(
            "POST",
            "/registration/auth/register",
            None,
            None,
            Some(wrong)
        )
        .0,
        400
    );
    let registered = host.json(
        "POST",
        "/registration/auth/register",
        None,
        None,
        Some(registration),
        202,
    );
    assert_eq!(registered["account_status"], "pending_verification");
    assert!(registered.get("verification_code").is_none());
}

#[cfg(all(feature = "development-private-network-http", debug_assertions))]
#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn a02_private_http_business_lifetimes_are_per_entry_and_token_sessions_stay_full() {
    const ORIGIN: &str = "http://192.168.31.159:8080";
    let db = Db::new(TenancyMode::Disabled);
    db.bootstrap();
    db.seed_management_client();
    for client in ["lifetime-one", "lifetime-two"] {
        db.adapter.connect().unwrap().execute(&format!("insert into {}.oidc_clients(client_id,client_name,redirect_uris_json,client_type,pkce_required,created_at_epoch) values ($1,$1,'[\"http://127.0.0.1/callback\"]','public_desktop',true,1)",db.adapter.schema_name()), &[&client]).unwrap();
    }
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let _ = db.explicit_command(port, db.mode, "/identity", "/console");
    let mut config: Value =
        serde_json::from_slice(&fs::read(db.dir.join("explicit.json")).unwrap()).unwrap();
    config["management"].as_object_mut().unwrap().remove("ui");
    config["runtime"]["http"] = json!({"browser_origin":ORIGIN,"transport_policy":"development-private-network-http","development_session_ttl_secs":600});
    config["business_entries"] = json!([
        {"login_entry":"lifetime-one","client_id":"lifetime-one","tenant_policy":{"kind":"fixed","tenant_id":"0"},"mount_prefix":"/one","browser":{"cookie_name":"one","development_session_ttl_secs":120}},
        {"login_entry":"lifetime-two","client_id":"lifetime-two","tenant_policy":{"kind":"fixed","tenant_id":"0"},"mount_prefix":"/two","browser":{"cookie_name":"two","development_session_ttl_secs":240}}
    ]);
    let host = db.start_command(port, &mut db.explicit_command_from_config(config));
    let lifetime = |session: &Value| -> (i64, i64) {
        let id = session["session"]["session_id"].as_str().unwrap();
        let row = db.adapter.connect().unwrap().query_one(&format!("select s.expires_at_epoch-s.created_at_epoch,r.expires_at_epoch-r.issued_at_epoch from {}.auth_sessions s join {}.refresh_tokens r on r.tenant_id=s.tenant_id and r.session_id=s.id and r.token_version=s.refresh_token_version where s.id::text=$1",db.adapter.schema_name(),db.adapter.schema_name()), &[&id]).unwrap();
        (row.get(0), row.get(1))
    };
    for (prefix, ttl) in [("/one", 120i64), ("/two", 240), ("/identity/admin", 600)] {
        let credentials = json!({"email":"admin@example.test","password":"Runtime-Admin123"});
        let (status, cookie, session) = host.browser_with_origin(
            &format!("{prefix}/auth/browser/login"),
            None,
            None,
            credentials.clone(),
            ORIGIN,
        );
        assert_eq!(status, 200, "{session}");
        let (session_ttl, refresh_ttl) = lifetime(&session);
        assert!(
            session_ttl >= ttl - 1 && session_ttl <= ttl,
            "{prefix}: {session_ttl}"
        );
        assert!(
            refresh_ttl >= ttl - 1 && refresh_ttl <= ttl,
            "{prefix}: {refresh_ttl}"
        );
        let access_expiry = session["tokens"]["access_expires_at_unix_secs"]
            .as_i64()
            .unwrap();
        let session_expiry = session["session"]["expires_at_unix_secs"].as_i64().unwrap();
        assert!(access_expiry < session_expiry);
        let cookie = cookie.unwrap();
        assert_eq!(
            host.browser_with_origin(
                &format!("{prefix}/auth/browser/refresh"),
                Some(cookie_pair(&cookie)),
                None,
                json!({"expected_session":browser_identity(&session["session"])}),
                ORIGIN
            )
            .0,
            403
        );
        let ordinary = host.json(
            "POST",
            &format!("{prefix}/auth/login"),
            None,
            None,
            Some(credentials),
            200,
        );
        let (session_ttl, refresh_ttl) = lifetime(&ordinary);
        assert!(
            session_ttl > 600 && refresh_ttl > 600,
            "ordinary token lifetime must remain independent"
        );
    }
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn a02_refresh_concurrency_logout_and_failure_are_atomic_and_entry_isolated() {
    let db = Db::new(TenancyMode::Disabled);
    db.bootstrap();
    db.seed_management_client();
    for client in ["race-one", "race-two"] {
        db.adapter.connect().unwrap().execute(&format!("insert into {}.oidc_clients(client_id,client_name,redirect_uris_json,client_type,pkce_required,created_at_epoch) values ($1,$1,'[\"http://127.0.0.1/callback\"]','public_desktop',true,1)",db.adapter.schema_name()), &[&client]).unwrap();
    }
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let _ = db.explicit_command(port, db.mode, "/identity", "/console");
    let mut config: Value =
        serde_json::from_slice(&fs::read(db.dir.join("explicit.json")).unwrap()).unwrap();
    config["business_entries"] = json!([
        {"login_entry":"race-one","client_id":"race-one","tenant_policy":{"kind":"fixed","tenant_id":"0"},"mount_prefix":"/one"},
        {"login_entry":"race-two","client_id":"race-two","tenant_policy":{"kind":"fixed","tenant_id":"0"},"mount_prefix":"/two"}
    ]);
    let host = db.start_command(port, &mut db.explicit_command_from_config(config));
    let login_at = |prefix: &str| {
        host.json(
            "POST",
            &format!("{prefix}/auth/login"),
            None,
            None,
            Some(json!({"email":"admin@example.test","password":"Runtime-Admin123"})),
            200,
        )
    };
    let refresh = |session: &Value| {
        host.raw(
            "POST",
            "/one/auth/refresh",
            None,
            None,
            Some(json!({"refresh_token":session["tokens"]["refresh_token"]})),
        )
    };
    let other = login_at("/two");
    let raced = login_at("/one");
    let barrier = std::sync::Barrier::new(2);
    let (first, second) = thread::scope(|scope| {
        let first = scope.spawn(|| {
            barrier.wait();
            refresh(&raced)
        });
        let second = scope.spawn(|| {
            barrier.wait();
            refresh(&raced)
        });
        (first.join().unwrap(), second.join().unwrap())
    });
    assert!(
        (first.0 == 200 && second.0 == 401) || (first.0 == 401 && second.0 == 200),
        "exactly one rotation succeeds: {first:?}, {second:?}"
    );
    let winner: Value =
        serde_json::from_str(if first.0 == 200 { &first.1 } else { &second.1 }).unwrap();
    // The losing replay's 401 must COMMIT family revocation, not roll it back.
    assert_eq!(
        host.raw("GET", "/one/auth/session", Some(token(&winner)), None, None)
            .0,
        401
    );
    assert_eq!(refresh(&winner).0, 401);

    // Logout deliberately accepts only the current refresh credential. Exercise
    // the race and both serial orders without granting stale tokens revocation.
    for ordering in [0, 1, 2] {
        let session = login_at("/one");
        let form = format!(
            "client_id=race-one&refresh_token={}",
            session["tokens"]["refresh_token"].as_str().unwrap()
        );
        let barrier = std::sync::Barrier::new(2);
        let (rotated, logged_out) = if ordering == 0 {
            thread::scope(|scope| {
                let rotate = scope.spawn(|| {
                    barrier.wait();
                    refresh(&session)
                });
                let logout = scope.spawn(|| {
                    barrier.wait();
                    host.ordinary_logout_form("/one/auth/logout", &form, None)
                });
                (rotate.join().unwrap(), logout.join().unwrap())
            })
        } else if ordering == 1 {
            (
                refresh(&session),
                host.ordinary_logout_form("/one/auth/logout", &form, None),
            )
        } else {
            let logged_out = host.ordinary_logout_form("/one/auth/logout", &form, None);
            (refresh(&session), logged_out)
        };
        assert_eq!(logged_out, 200);
        assert!(rotated.0 == 200 || rotated.0 == 401, "{rotated:?}");
        if ordering == 1 {
            assert_eq!(rotated.0, 200);
        }
        if ordering == 2 {
            assert_eq!(rotated.0, 401);
        }
        if rotated.0 == 200 {
            // Refresh won: logout with its now-stale predecessor is a no-op.
            // The current credential still logs out exactly this session.
            let rotated: Value = serde_json::from_str(&rotated.1).unwrap();
            host.json(
                "GET",
                "/one/auth/session",
                Some(token(&rotated)),
                None,
                None,
                200,
            );
            let current_form = format!(
                "client_id=race-one&refresh_token={}",
                rotated["tokens"]["refresh_token"].as_str().unwrap()
            );
            assert_eq!(
                host.ordinary_logout_form("/one/auth/logout", &current_form, None),
                200
            );
            assert_eq!(refresh(&rotated).0, 401);
        }
        assert_eq!(
            host.raw(
                "GET",
                "/one/auth/session",
                Some(token(&session)),
                None,
                None
            )
            .0,
            401
        );
    }

    // Fail the final INSERT after the session version and old refresh row were
    // updated. All three changes must roll back together, and retry must work.
    let session = login_at("/one");
    let id = session["session"]["session_id"].as_str().unwrap();
    let schema = db.adapter.schema_name();
    let snapshot = || -> Vec<String> {
        db.adapter.connect().unwrap().query(&format!(
            "select row_to_json(s)::text as row from {schema}.auth_sessions s where id::text=$1 union all select row_to_json(r)::text from {schema}.refresh_tokens r where session_id::text=$1 order by row"
        ), &[&id]).unwrap().into_iter().map(|r| r.get(0)).collect()
    };
    let before = snapshot();
    db.adapter.connect().unwrap().batch_execute(&format!(
        "create function {schema}.a02_fail_refresh_insert() returns trigger language plpgsql as $$ begin raise exception 'a02 rotation fault' using errcode = 'P0001'; end $$; create trigger a02_fail_refresh_insert before insert on {schema}.refresh_tokens for each row execute function {schema}.a02_fail_refresh_insert()"
    )).unwrap();
    assert_eq!(refresh(&session).0, 500);
    assert_eq!(
        snapshot(),
        before,
        "failed rotation must not consume the old credential or increment its version"
    );
    db.adapter.connect().unwrap().batch_execute(&format!(
        "drop trigger a02_fail_refresh_insert on {schema}.refresh_tokens; drop function {schema}.a02_fail_refresh_insert()"
    )).unwrap();
    assert_eq!(refresh(&session).0, 200);
    host.json(
        "GET",
        "/two/auth/session",
        Some(token(&other)),
        None,
        None,
        200,
    );
    host.json(
        "POST",
        "/two/auth/refresh",
        None,
        None,
        Some(json!({"refresh_token":other["tokens"]["refresh_token"]})),
        200,
    );
}

#[cfg(all(feature = "development-private-network-http", debug_assertions))]
#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn a02_restricted_choose_cannot_escape_browser_lifetime_through_token_routes() {
    const ORIGIN: &str = "http://192.168.31.159:8080";
    let db = Db::new(TenancyMode::Enabled);
    db.bootstrap();
    db.seed_management_client();
    let setup = db.start_explicit("/identity", "/console");
    let admin = setup.json(
        "POST",
        "/identity/admin/auth/login",
        None,
        None,
        Some(json!({"email":"admin@example.test","password":"Runtime-Admin123"})),
        200,
    );
    setup.json("POST", "/identity/admin/clients/upsert", Some(token(&admin)), None,
        Some(json!({"client_id":"restricted-choose","client_name":"Restricted choose","redirect_uris":["http://127.0.0.1/callback"],"client_type":"public_desktop","pkce_required":true})), 200);
    setup.json("POST", "/identity/admin/tenants", Some(token(&admin)), None,
        Some(json!({"tenant_id":"domain-a","name":"A","allow_registration":false,"administrator":{"kind":"new","email":"choose@example.test","password":"Runtime-Member123"}})), 201);
    let members = setup.json(
        "GET",
        "/identity/admin/accounts",
        Some(token(&admin)),
        Some("domain-a"),
        None,
        200,
    );
    let subject = members["items"][0]["account_id"].as_str().unwrap();
    setup.json("POST", "/identity/admin/tenants", Some(token(&admin)), None,
        Some(json!({"tenant_id":"domain-b","name":"B","allow_registration":false,"administrator":{"kind":"existing","subject_id":subject}})), 201);
    drop(setup);
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let _ = db.explicit_command(port, db.mode, "/identity", "/console");
    let mut config: Value =
        serde_json::from_slice(&fs::read(db.dir.join("explicit.json")).unwrap()).unwrap();
    config["management"].as_object_mut().unwrap().remove("ui");
    config["runtime"]["http"] = json!({"browser_origin":ORIGIN,"transport_policy":"development-private-network-http","development_session_ttl_secs":600});
    config["business_entries"] = json!([
        {"login_entry":"restricted-choose","client_id":"restricted-choose","tenant_policy":{"kind":"choose"},"mount_prefix":"/choose","browser":{"cookie_name":"restricted_choose","development_session_ttl_secs":120}}
    ]);
    let host = db.start_command(port, &mut db.explicit_command_from_config(config));
    let credentials = json!({"email":"choose@example.test","password":"Runtime-Member123"});
    let (status, _, browser_choice) = host.browser_with_origin(
        "/choose/auth/browser/login",
        None,
        None,
        credentials.clone(),
        ORIGIN,
    );
    assert_eq!(status, 200, "{browser_choice}");
    let restricted_ticket = browser_choice["selection_ticket"].as_str().unwrap();
    assert_eq!(
        host.raw(
            "POST",
            "/choose/auth/tenant-selection/complete",
            Some(restricted_ticket),
            None,
            Some(json!({"tenant_id":"domain-a"}))
        )
        .0,
        401
    );
    let tenants = host.json(
        "GET",
        "/choose/auth/tenant-selection/tenants",
        Some(restricted_ticket),
        None,
        None,
        200,
    );
    assert_eq!(tenants["tenants"].as_array().unwrap().len(), 2);
    let (status, cookie, restricted) = host.browser_with_origin(
        "/choose/auth/browser/tenant-selection/complete",
        None,
        Some(restricted_ticket),
        json!({"tenant_id":"domain-a"}),
        ORIGIN,
    );
    assert_eq!(
        status, 200,
        "rejected token completion must not consume browser ticket: {restricted}"
    );
    assert!(cookie.unwrap().contains("Path=/choose/auth/browser"));
    let lifetimes = |session: &Value| -> (i64, i64) {
        let id = session["session"]["session_id"].as_str().unwrap();
        let row = db.adapter.connect().unwrap().query_one(&format!("select s.expires_at_epoch-s.created_at_epoch,r.expires_at_epoch-r.issued_at_epoch from {}.auth_sessions s join {}.refresh_tokens r on r.tenant_id=s.tenant_id and r.session_id=s.id and r.token_version=s.refresh_token_version where s.id::text=$1",db.adapter.schema_name(),db.adapter.schema_name()), &[&id]).unwrap();
        (row.get(0), row.get(1))
    };
    let (session_ttl, refresh_ttl) = lifetimes(&restricted);
    assert!((119..=120).contains(&session_ttl), "{session_ttl}");
    assert!((119..=120).contains(&refresh_ttl), "{refresh_ttl}");
    assert_eq!(
        host.raw(
            "POST",
            "/choose/auth/me/tenant-selection",
            Some(token(&restricted)),
            None,
            None
        )
        .0,
        401
    );
    // Ordinary login and switching retain their full existing lifetime.
    let choice = host.json(
        "POST",
        "/choose/auth/login",
        None,
        None,
        Some(credentials),
        200,
    );
    let normal = host.json(
        "POST",
        "/choose/auth/tenant-selection/complete",
        choice["selection_ticket"].as_str(),
        None,
        Some(json!({"tenant_id":"domain-a"})),
        200,
    );
    let (session_ttl, refresh_ttl) = lifetimes(&normal);
    assert!(session_ttl > 600 && refresh_ttl > 600);
    let switch = host.json(
        "POST",
        "/choose/auth/me/tenant-selection",
        Some(token(&normal)),
        None,
        None,
        200,
    );
    let switched = host.json(
        "POST",
        "/choose/auth/tenant-selection/complete",
        switch["selection_ticket"].as_str(),
        None,
        Some(json!({"tenant_id":"domain-b"})),
        200,
    );
    assert_eq!(switched["session"]["tenant_id"], "domain-b");
    let (session_ttl, refresh_ttl) = lifetimes(&switched);
    assert!(session_ttl > 600 && refresh_ttl > 600);
}

#[cfg(all(feature = "development-private-network-http", debug_assertions))]
#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn a02b_private_browser_cannot_upgrade_through_oidc() {
    const ORIGIN: &str = "http://192.168.31.159:8080";
    let db = Db::new(TenancyMode::Disabled);
    db.bootstrap();
    db.seed_management_client();
    let setup = db.start_explicit("/identity", "/console");
    let admin = setup.json(
        "POST",
        "/identity/admin/auth/login",
        None,
        None,
        Some(json!({"email":"admin@example.test","password":"Runtime-Admin123"})),
        200,
    );
    setup.json("POST", "/identity/admin/clients/upsert", Some(token(&admin)), None,
        Some(json!({"client_id":"short-oidc","client_name":"Short OIDC","redirect_uris":["http://127.0.0.1/callback"],"client_type":"public_desktop","pkce_required":true})),200);
    drop(setup);
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let _ = db.explicit_command(port, db.mode, "/identity", "/console");
    let mut config: Value =
        serde_json::from_slice(&fs::read(db.dir.join("explicit.json")).unwrap()).unwrap();
    config["version"] = json!(2);
    config["management"].as_object_mut().unwrap().remove("ui");
    config["runtime"]["http"] = json!({"browser_origin":ORIGIN,"transport_policy":"development-private-network-http","development_session_ttl_secs":600});
    config["business_entries"] = json!([{"login_entry":"short-oidc","client_id":"short-oidc","tenant_policy":{"kind":"fixed","tenant_id":"0"},"mount_prefix":"/one","oidc":{"enabled":true},"browser":{"cookie_name":"short_oidc","development_session_ttl_secs":120}}]);
    let host = db.start_command(port, &mut db.explicit_command_from_config(config));
    let credentials = json!({"email":"admin@example.test","password":"Runtime-Admin123"});
    let (status, _, browser) = host.browser_with_origin(
        "/one/auth/browser/login",
        None,
        None,
        credentials.clone(),
        ORIGIN,
    );
    assert_eq!(status, 200);
    let query = "response_type=code&client_id=short-oidc&redirect_uri=http%3A%2F%2F127.0.0.1%2Fcallback&scope=openid&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256";
    assert_eq!(host.oidc_authorize(query, token(&browser)).0, 401);
    let normal = host.json(
        "POST",
        "/one/auth/login",
        None,
        None,
        Some(credentials),
        200,
    );
    assert_eq!(host.oidc_authorize(query, token(&normal)).0, 307);
    assert_eq!(
        host.oidc_authorize(
            &query.replace("method=S256", "method=plain"),
            token(&normal)
        )
        .0,
        400
    );
}
