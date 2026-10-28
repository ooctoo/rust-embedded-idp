use super::*;
use base64ct::{Base64UrlUnpadded, Encoding};

const AUTHORITY: &str = "phase-one-host-test";
const EMAIL: &str = "admin@example.test";
const PASSWORD_0: &str = "Runtime-Admin123";
const PASSWORD_1: &str = "Password-change-1";
const PASSWORD_2: &str = "Password-change-2";
const PASSWORD_3: &str = "Password-change-3";
const PASSWORD_4: &str = "Password-change-4";

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn cli(path: &std::path::Path, subcommand: &str, args: &[&str], db: &Db) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_embedded-idp-app"));
    for (key, _) in env::vars().filter(|(key, _)| key.starts_with("EMBEDDED_IDP_APP_")) {
        command.env_remove(key);
    }
    command
        .arg(subcommand)
        .arg("--config")
        .arg(path)
        .args(args)
        .env("IDP_TEST_DATABASE_URI", &db.uri)
        .output()
        .unwrap()
}

fn install_security(config_path: &std::path::Path, db: &Db) {
    for extension in ["foundation", "runtime"] {
        let plan = cli(
            config_path,
            "security-plan",
            &["--extension", extension],
            db,
        );
        assert!(
            plan.status.success(),
            "{}",
            String::from_utf8_lossy(&plan.stderr)
        );
        let plan: Value = serde_json::from_slice(&plan.stdout).unwrap();
        let apply = cli(
            config_path,
            "security-apply",
            &[
                "--extension",
                extension,
                "--fingerprint",
                plan["fingerprint"].as_str().unwrap(),
            ],
            db,
        );
        assert!(
            apply.status.success(),
            "{}",
            String::from_utf8_lossy(&apply.stderr)
        );
        let check = cli(
            config_path,
            "security-check",
            &["--extension", extension],
            db,
        );
        assert!(
            check.status.success(),
            "{}",
            String::from_utf8_lossy(&check.stderr)
        );
    }
}

fn raw_headers(
    host: &Host,
    method: &str,
    path: &str,
    headers: &[(&str, String)],
    body: &Value,
) -> (u16, String, Value) {
    let body = body.to_string();
    let mut request = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n",
        host.port,
        body.len()
    );
    for (name, value) in headers {
        request.push_str(&format!("{name}: {value}\r\n"));
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
    let status = headers.split_whitespace().nth(1).unwrap().parse().unwrap();
    (
        status,
        headers.to_owned(),
        serde_json::from_str(body).unwrap_or(Value::Null),
    )
}

fn bearer_headers(token: &str) -> [(&'static str, String); 1] {
    [("Authorization", format!("Bearer {token}"))]
}

fn browser_headers(host: &Host, cookie: Option<&str>) -> Vec<(&'static str, String)> {
    let mut headers = vec![
        ("Origin", format!("http://127.0.0.1:{}", host.port)),
        ("X-Embedded-Idp-Browser", "1".into()),
    ];
    if let Some(cookie) = cookie {
        headers.push(("Cookie", cookie.to_owned()));
    }
    headers
}

fn secret(byte: u8) -> String {
    Base64UrlUnpadded::encode_string(&[byte; 32])
}

fn change_body(current: &str, new: &str, operation: Uuid, receipt_secret: &str) -> Value {
    json!({
        "current_password":current,
        "new_password":new,
        "operation_id":operation.to_string(),
        "receipt_secret":receipt_secret
    })
}

fn browser_change_body(
    current: &str,
    new: &str,
    operation: Uuid,
    receipt_secret: &str,
    session: &Value,
) -> Value {
    let mut body = change_body(current, new, operation, receipt_secret);
    body["expected"] = browser_identity(session);
    body
}

fn result_body(operation: Uuid, receipt_secret: &str) -> Value {
    json!({
        "operation_id":operation.to_string(),
        "receipt_secret":receipt_secret
    })
}

fn assert_headers_are_safe(headers: &str) {
    let lower = headers.to_ascii_lowercase();
    assert!(lower.contains("cache-control: no-store"), "{headers}");
    assert!(!lower.contains("set-cookie:"), "{headers}");
}

fn account_snapshot(db: &Db, account_id: &str) -> (String, i64, i64, i64, i64) {
    let mut c = db.adapter.connect().unwrap();
    let row = c
        .query_one(
            &format!(
                "select a.password_hash,a.security_credential_version,(select count(*) from {}.auth_sessions s where s.account_id=a.id and s.status<>'revoked'),(select count(*) from {}.security_receipts r where r.purpose='password_change' and r.account_id=a.id),(select count(*) from {}.security_events e where e.kind='password_changed' and e.account_id=a.id) from {}.accounts a where a.id=$1",
                db.adapter.schema_name(),
                db.adapter.schema_name(),
                db.adapter.schema_name(),
                db.adapter.schema_name()
            ),
            &[&Uuid::parse_str(account_id).unwrap()],
        )
        .unwrap();
    (row.get(0), row.get(1), row.get(2), row.get(3), row.get(4))
}

fn change_with_bearer(
    host: &Host,
    path: &str,
    token: &str,
    current: &str,
    new: &str,
    operation: Uuid,
    receipt_secret: &str,
) -> (u16, String, Value) {
    raw_headers(
        host,
        "POST",
        path,
        &bearer_headers(token),
        &change_body(current, new, operation, receipt_secret),
    )
}

fn change_with_browser(
    host: &Host,
    path: &str,
    cookie: &str,
    current: &str,
    new: &str,
    operation: Uuid,
    receipt_secret: &str,
    session: &Value,
) -> (u16, String, Value) {
    let headers = browser_headers(host, Some(cookie_pair(cookie)));
    raw_headers(
        host,
        "POST",
        path,
        &headers,
        &browser_change_body(current, new, operation, receipt_secret, session),
    )
}

fn browser_result(
    host: &Host,
    path: &str,
    cookie: Option<&str>,
    operation: Uuid,
    receipt_secret: &str,
) -> (u16, String, Value) {
    let headers = browser_headers(host, cookie);
    raw_headers(
        host,
        "POST",
        path,
        &headers,
        &result_body(operation, receipt_secret),
    )
}

fn login_bearer(host: &Host, path: &str, password: &str) -> Value {
    host.json(
        "POST",
        path,
        None,
        None,
        Some(json!({"email":EMAIL,"password":password})),
        200,
    )
}

fn login_browser(host: &Host, path: &str, password: &str) -> (String, Value) {
    let (status, cookie, value) =
        host.browser(path, None, None, json!({"email":EMAIL,"password":password}));
    assert_eq!(status, 200, "{path}: {value}");
    (cookie.unwrap(), value)
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn s03_a5_password_change_http_works_for_management_and_business_entries_in_both_modes() {
    for mode in [TenancyMode::Disabled, TenancyMode::Enabled] {
        let db = Db::new(mode);
        db.bootstrap();
        db.seed_management_client();

        let setup_port = free_port();
        let setup = db.start_command(
            setup_port,
            &mut db.explicit_command(setup_port, mode, "/identity", "/console"),
        );
        let admin = setup.json(
            "POST",
            "/identity/admin/auth/login",
            None,
            None,
            Some(json!({"email":EMAIL,"password":PASSWORD_0})),
            200,
        );
        for client in ["password-one", "password-two"] {
            setup.json(
                "POST",
                "/identity/admin/clients/upsert",
                Some(token(&admin)),
                None,
                Some(json!({
                    "client_id":client,
                    "client_name":client,
                    "redirect_uris":["http://127.0.0.1/callback"],
                    "client_type":"public_desktop",
                    "pkce_required":true
                })),
                200,
            );
        }
        let business_tenant = if mode == TenancyMode::Enabled {
            setup.json(
                "POST",
                "/identity/admin/tenants",
                Some(token(&admin)),
                None,
                Some(json!({
                    "tenant_id":"password-change-domain",
                    "name":"Password change test",
                    "allow_registration":false,
                    "administrator":{"kind":"existing","subject_id":admin["session"]["account_id"]}
                })),
                201,
            );
            "password-change-domain"
        } else {
            "0"
        };
        drop(setup);

        b3_write_private(&db.dir.join("account-subject.key"), &[201; 32]);
        let mut keyset = Vec::with_capacity(128);
        for byte in 21..25 {
            keyset.extend_from_slice(&[byte; 32]);
        }
        b3_write_private(&db.dir.join("account-current.keys"), &keyset);

        let port = free_port();
        let _ = db.explicit_command(port, mode, "/identity", "/console");
        let config_path = db.dir.join("explicit.json");
        let mut config: Value = serde_json::from_slice(&fs::read(&config_path).unwrap()).unwrap();
        // This lifecycle test logs the same synthetic account into several
        // entries repeatedly. Keep admission enabled with an explicit test
        // quota; default rate-limit behavior has its own S01 regression tests.
        config["runtime"]["abuse"] = json!({"account":{"period_ms":10,"burst":100}});
        config["runtime"]["account_security"] = json!({
            "authority":AUTHORITY,
            "subject_key_file":"account-subject.key",
            "current":{"key_id":"current","key_file":"account-current.keys"}
        });
        config["business_entries"] = json!([
            {"login_entry":"password-one","client_id":"password-one","tenant_policy":{"kind":"fixed","tenant_id":business_tenant},"mount_prefix":"/one","browser":{"cookie_name":"password_one"}},
            {"login_entry":"password-two","client_id":"password-two","tenant_policy":{"kind":"fixed","tenant_id":business_tenant},"mount_prefix":"/two","browser":{"cookie_name":"password_two"}}
        ]);
        fs::write(&config_path, serde_json::to_vec(&config).unwrap()).unwrap();
        install_security(&config_path, &db);
        let host = db.start_command(port, &mut db.explicit_command_from_config(config.clone()));

        // Capture old Bearer tokens and browser sessions for all three entry roots.
        let management_old = login_bearer(&host, "/identity/admin/auth/login", PASSWORD_0);
        let one_old = login_bearer(&host, "/one/auth/login", PASSWORD_0);
        let two_old = login_bearer(&host, "/two/auth/login", PASSWORD_0);
        let (management_cookie_old, management_browser_old) =
            login_browser(&host, "/identity/admin/auth/browser/login", PASSWORD_0);
        let (one_cookie_old, one_browser_old) =
            login_browser(&host, "/one/auth/browser/login", PASSWORD_0);
        let (two_cookie_old, two_browser_old) =
            login_browser(&host, "/two/auth/browser/login", PASSWORD_0);

        // A valid entry-one token is rejected at entry two before changing credentials.
        let cross = change_with_bearer(
            &host,
            "/two/auth/security/password",
            token(&one_old),
            PASSWORD_0,
            PASSWORD_1,
            Uuid::now_v7(),
            &secret(31),
        );
        assert_eq!(cross.0, 401, "{}", cross.2);
        assert_eq!(
            host.raw(
                "GET",
                "/one/auth/security/sessions",
                Some(token(&one_old)),
                None,
                None
            )
            .0,
            200
        );

        let snapshot_before_bad_password = account_snapshot(
            &db,
            management_old["session"]["account_id"].as_str().unwrap(),
        );
        let bad = change_with_bearer(
            &host,
            "/identity/admin/auth/security/password",
            token(&management_old),
            "Incorrect-current-456",
            PASSWORD_1,
            Uuid::now_v7(),
            &secret(32),
        );
        assert_eq!(bad.0, 401, "{}", bad.2);
        assert_eq!(bad.2["code"], "invalid_credentials");
        assert_headers_are_safe(&bad.1);
        assert_eq!(
            account_snapshot(
                &db,
                management_old["session"]["account_id"].as_str().unwrap()
            ),
            snapshot_before_bad_password
        );

        let management_operation = Uuid::now_v7();
        let management_secret = secret(33);
        let changed = change_with_bearer(
            &host,
            "/identity/admin/auth/security/password",
            token(&management_old),
            PASSWORD_0,
            PASSWORD_1,
            management_operation,
            &management_secret,
        );
        assert_eq!(changed.0, 200, "{}", changed.2);
        assert_eq!(changed.2["completed"], true);
        assert_headers_are_safe(&changed.1);
        let (result_status, result_headers, result) = raw_headers(
            &host,
            "POST",
            "/two/auth/security/password/result",
            &[],
            &result_body(management_operation, &management_secret),
        );
        assert_eq!(result_status, 200, "{result}");
        assert_eq!(result["completed"], true);
        assert_headers_are_safe(&result_headers);

        for (path, token) in [
            (
                "/identity/admin/auth/security/sessions",
                token(&management_old),
            ),
            ("/one/auth/security/sessions", token(&one_old)),
            ("/two/auth/security/sessions", token(&two_old)),
        ] {
            assert_eq!(
                host.raw("GET", path, Some(token), None, None).0,
                401,
                "{path}"
            );
        }
        for (path, cookie, session) in [
            (
                "/identity/admin/auth/browser/restore",
                &management_cookie_old,
                &management_browser_old,
            ),
            (
                "/one/auth/browser/restore",
                &one_cookie_old,
                &one_browser_old,
            ),
            (
                "/two/auth/browser/restore",
                &two_cookie_old,
                &two_browser_old,
            ),
        ] {
            assert_eq!(
                host.browser(
                    path,
                    Some(cookie_pair(cookie)),
                    None,
                    json!({"expected_session":browser_identity(&session["session"])})
                )
                .0,
                401,
                "{path}"
            );
        }

        // The new password logs in at management and both ordinary entries.
        let _ = login_bearer(&host, "/identity/admin/auth/login", PASSWORD_1);
        let one_p1 = login_bearer(&host, "/one/auth/login", PASSWORD_1);
        let two_p1 = login_bearer(&host, "/two/auth/login", PASSWORD_1);
        let _ = login_browser(&host, "/identity/admin/auth/browser/login", PASSWORD_1);
        let (one_cookie_p1, one_browser_p1) =
            login_browser(&host, "/one/auth/browser/login", PASSWORD_1);
        let (_two_cookie_p1, _two_browser_p1) =
            login_browser(&host, "/two/auth/browser/login", PASSWORD_1);
        assert!(!token(&one_p1).is_empty());
        assert!(!token(&two_p1).is_empty());

        // A browser receipt query that carries the stale cookie emits no cookie
        // mutation; a newly authenticated same-entry cookie remains usable.
        let (one_cookie_fresh, one_browser_fresh) =
            login_browser(&host, "/one/auth/browser/login", PASSWORD_1);
        let (status, headers, result) = browser_result(
            &host,
            "/one/auth/browser/security/password/result",
            Some(cookie_pair(&one_cookie_old)),
            management_operation,
            &management_secret,
        );
        assert_eq!(status, 200, "{result}");
        assert_eq!(result["completed"], true);
        assert_headers_are_safe(&headers);
        assert_eq!(
            host.browser(
                "/one/auth/browser/restore",
                Some(cookie_pair(&one_cookie_fresh)),
                None,
                json!({"expected_session":browser_identity(&one_browser_fresh["session"])})
            )
            .0,
            200
        );

        let one_operation = Uuid::now_v7();
        let one_secret = secret(34);
        let changed = change_with_browser(
            &host,
            "/one/auth/browser/security/password",
            &one_cookie_p1,
            PASSWORD_1,
            PASSWORD_2,
            one_operation,
            &one_secret,
            &one_browser_p1["session"],
        );
        assert_eq!(changed.0, 200, "{}", changed.2);
        assert_eq!(changed.2["completed"], true);
        assert_headers_are_safe(&changed.1);
        assert_eq!(
            host.browser(
                "/one/auth/browser/restore",
                Some(cookie_pair(&one_cookie_fresh)),
                None,
                json!({"expected_session":browser_identity(&one_browser_fresh["session"])})
            )
            .0,
            401
        );
        let (one_cookie_p2, one_browser_p2) =
            login_browser(&host, "/one/auth/browser/login", PASSWORD_2);
        let (status, headers, result) = browser_result(
            &host,
            "/one/auth/browser/security/password/result",
            Some(cookie_pair(&one_cookie_p1)),
            one_operation,
            &one_secret,
        );
        assert_eq!(status, 200, "{result}");
        assert_eq!(result["completed"], true);
        assert_headers_are_safe(&headers);
        assert_eq!(
            host.browser(
                "/one/auth/browser/restore",
                Some(cookie_pair(&one_cookie_p2)),
                None,
                json!({"expected_session":browser_identity(&one_browser_p2["session"])})
            )
            .0,
            200
        );

        // The other ordinary entry can also reauthenticate and change via Bearer.
        let two_p2 = login_bearer(&host, "/two/auth/login", PASSWORD_2);
        let two_operation = Uuid::now_v7();
        let two_secret = secret(35);
        let changed = change_with_bearer(
            &host,
            "/two/auth/security/password",
            token(&two_p2),
            PASSWORD_2,
            PASSWORD_3,
            two_operation,
            &two_secret,
        );
        assert_eq!(changed.0, 200, "{}", changed.2);
        assert_eq!(changed.2["completed"], true);
        assert_headers_are_safe(&changed.1);
        let (status, headers, result) = raw_headers(
            &host,
            "POST",
            "/identity/admin/auth/security/password/result",
            &[],
            &result_body(two_operation, &two_secret),
        );
        assert_eq!(status, 200, "{result}");
        assert_eq!(result["completed"], true);
        assert_headers_are_safe(&headers);

        // Management browser is the fourth independent route family.
        let (management_cookie_p3, management_browser_p3) =
            login_browser(&host, "/identity/admin/auth/browser/login", PASSWORD_3);
        let management_browser_operation = Uuid::now_v7();
        let management_browser_secret = secret(36);
        let changed = change_with_browser(
            &host,
            "/identity/admin/auth/browser/security/password",
            &management_cookie_p3,
            PASSWORD_3,
            PASSWORD_4,
            management_browser_operation,
            &management_browser_secret,
            &management_browser_p3["session"],
        );
        assert_eq!(changed.0, 200, "{}", changed.2);
        assert_eq!(changed.2["completed"], true);
        assert_headers_are_safe(&changed.1);
        let (status, headers, result) = browser_result(
            &host,
            "/identity/admin/auth/browser/security/password/result",
            Some(cookie_pair(&management_cookie_p3)),
            management_browser_operation,
            &management_browser_secret,
        );
        assert_eq!(status, 200, "{result}");
        assert_eq!(result["completed"], true);
        assert_headers_are_safe(&headers);

        // Final password works for management and each business entry.
        login_bearer(&host, "/identity/admin/auth/login", PASSWORD_4);
        login_bearer(&host, "/one/auth/login", PASSWORD_4);
        login_bearer(&host, "/two/auth/login", PASSWORD_4);
        login_browser(&host, "/identity/admin/auth/browser/login", PASSWORD_4);
        login_browser(&host, "/one/auth/browser/login", PASSWORD_4);
        login_browser(&host, "/two/auth/browser/login", PASSWORD_4);

        let no_security_port = free_port();
        let mut no_security = config.clone();
        no_security["runtime"]
            .as_object_mut()
            .unwrap()
            .remove("account_security");
        no_security["runtime"]["bind_addr"] = json!(format!("127.0.0.1:{no_security_port}"));
        no_security["runtime"]["issuer"] = json!(format!("http://127.0.0.1:{no_security_port}"));
        no_security["runtime"]["http"]["browser_origin"] =
            json!(format!("http://127.0.0.1:{no_security_port}"));
        let unconfigured = db.start_command(
            no_security_port,
            &mut db.explicit_command_from_config(no_security),
        );
        assert_eq!(
            unconfigured
                .raw(
                    "POST",
                    "/one/auth/security/password",
                    None,
                    None,
                    Some(change_body(
                        PASSWORD_4,
                        "Noop-password-55",
                        Uuid::now_v7(),
                        &secret(37)
                    ))
                )
                .0,
            404
        );
        drop(unconfigured);
    }
}
