use super::*;
use base64ct::{Base64UrlUnpadded, Encoding};

fn command(
    path: &std::path::Path,
    subcommand: &str,
    args: &[&str],
    db: &Db,
) -> std::process::Output {
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

fn security_headers_request(
    host: &Host,
    method: &str,
    path: &str,
    extra: &[(&str, &str)],
    body: &Value,
) -> (u16, String, String) {
    let body = body.to_string();
    let mut request = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n",
        host.port,
        body.len()
    );
    for (name, value) in extra {
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
    (status, headers.to_owned(), body.to_owned())
}

fn revoke_body(session: &Value, operation: Uuid, secret: &[u8; 32]) -> Value {
    json!({
        "target_tenant_id":session["tenant_id"].as_str().unwrap(),
        "target_session_id":session["session_id"].as_str().unwrap(),
        "operation_id":operation.to_string(),
        "receipt_secret":Base64UrlUnpadded::encode_string(secret)
    })
}

fn receipt_body(operation: Uuid, secret: &[u8; 32]) -> Value {
    json!({
        "operation_id":operation.to_string(),
        "receipt_secret":Base64UrlUnpadded::encode_string(secret)
    })
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn s03_a3_explicit_security_migration_and_revocation_routes_work_across_entries() {
    for mode in [TenancyMode::Disabled, TenancyMode::Enabled] {
        let db = Db::new(mode);
        db.bootstrap();
        db.seed_management_client();

        let port = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let setup = db.start_command(
            port,
            &mut db.explicit_command(port, mode, "/identity", "/console"),
        );
        let admin = setup.json(
            "POST",
            "/identity/admin/auth/login",
            None,
            None,
            Some(json!({"email":"admin@example.test","password":"Runtime-Admin123"})),
            200,
        );
        for client in ["security-one", "security-two"] {
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
            setup.json("POST", "/identity/admin/tenants", Some(token(&admin)), None,
                Some(json!({"tenant_id":"security-domain","name":"Security test","allow_registration":false,
                    "administrator":{"kind":"existing","subject_id":admin["session"]["account_id"]}})), 201);
            "security-domain"
        } else {
            "0"
        };
        drop(setup);

        b3_write_private(&db.dir.join("account-subject.key"), &[201; 32]);
        let mut keyset = Vec::with_capacity(128);
        keyset.extend_from_slice(&[21; 32]);
        keyset.extend_from_slice(&[22; 32]);
        keyset.extend_from_slice(&[23; 32]);
        keyset.extend_from_slice(&[24; 32]);
        b3_write_private(&db.dir.join("account-current.keys"), &keyset);

        let port = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let _ = db.explicit_command(port, mode, "/identity", "/console");
        let mut config: Value =
            serde_json::from_slice(&fs::read(db.dir.join("explicit.json")).unwrap()).unwrap();
        config["runtime"]["account_security"] = json!({
            "authority":"phase-one-host-test",
            "subject_key_file":"account-subject.key",
            "current":{"key_id":"current","key_file":"account-current.keys"}
        });
        config["business_entries"] = json!([
            {"login_entry":"security-one","client_id":"security-one","tenant_policy":{"kind":"fixed","tenant_id":business_tenant},"mount_prefix":"/one","browser":{"cookie_name":"security_one"}},
            {"login_entry":"security-two","client_id":"security-two","tenant_policy":{"kind":"fixed","tenant_id":business_tenant},"mount_prefix":"/two","browser":{"cookie_name":"security_two"}}
        ]);
        let config_path = db.dir.join("explicit.json");
        fs::write(&config_path, serde_json::to_vec(&config).unwrap()).unwrap();

        // An enabled host refuses to start before either extension is prepared.
        // Its reference clients already exist, so unchanged snapshot proves no
        // startup migration/repair or additional identity writes occurred.
        let before = db.snapshot();
        let failed = db
            .explicit_command_from_config(config.clone())
            .status()
            .unwrap();
        assert!(!failed.success(), "runtime extension must be explicit");
        assert_eq!(db.snapshot(), before);
        let mut c = db.adapter.connect().unwrap();
        assert!(!c
            .query_one(
                "select to_regclass($1) is not null",
                &[&format!(
                    "{}.security_runtime_state",
                    db.adapter.schema_name()
                )]
            )
            .unwrap()
            .get::<_, bool>(0));

        drop(c); // Release the small fixture pool before later snapshots.

        let plan_args = ["--extension", "foundation"];
        let planned = command(&config_path, "security-plan", &plan_args, &db);
        assert!(
            planned.status.success(),
            "{}",
            String::from_utf8_lossy(&planned.stderr)
        );
        let plan: Value = serde_json::from_slice(&planned.stdout).unwrap();
        assert_eq!(plan["extension"], "foundation");
        assert_eq!(plan["authority"], "phase-one-host-test");
        assert_eq!(db.snapshot(), before, "plan is read-only");
        let wrong = if plan["fingerprint"] == "0".repeat(64) {
            "1".repeat(64)
        } else {
            "0".repeat(64)
        };
        let wrong = command(
            &config_path,
            "security-apply",
            &["--extension", "foundation", "--fingerprint", &wrong],
            &db,
        );
        assert_eq!(wrong.status.code(), Some(3));
        assert_eq!(db.snapshot(), before, "wrong fingerprint has no effect");
        let applied = command(
            &config_path,
            "security-apply",
            &[
                "--extension",
                "foundation",
                "--fingerprint",
                plan["fingerprint"].as_str().unwrap(),
            ],
            &db,
        );
        assert!(
            applied.status.success(),
            "{}",
            String::from_utf8_lossy(&applied.stderr)
        );
        assert!(command(
            &config_path,
            "security-check",
            &["--extension", "foundation"],
            &db
        )
        .status
        .success());

        let plan = command(
            &config_path,
            "security-plan",
            &["--extension", "runtime"],
            &db,
        );
        assert!(
            plan.status.success(),
            "{}",
            String::from_utf8_lossy(&plan.stderr)
        );
        let plan: Value = serde_json::from_slice(&plan.stdout).unwrap();
        let applied = command(
            &config_path,
            "security-apply",
            &[
                "--extension",
                "runtime",
                "--fingerprint",
                plan["fingerprint"].as_str().unwrap(),
            ],
            &db,
        );
        assert!(
            applied.status.success(),
            "{}",
            String::from_utf8_lossy(&applied.stderr)
        );
        assert!(command(
            &config_path,
            "security-check",
            &["--extension", "runtime"],
            &db
        )
        .status
        .success());

        let mut wrong_authority = config.clone();
        wrong_authority["runtime"]["account_security"]["authority"] =
            json!("different-host-authority");
        let wrong_authority_path = db.dir.join("wrong-authority.json");
        fs::write(
            &wrong_authority_path,
            serde_json::to_vec(&wrong_authority).unwrap(),
        )
        .unwrap();
        let before_invalid_configs = db.snapshot();
        assert!(!command(
            &wrong_authority_path,
            "security-check",
            &["--extension", "runtime"],
            &db
        )
        .status
        .success());
        assert_eq!(
            command(
                &wrong_authority_path,
                "security-apply",
                &[
                    "--extension",
                    "runtime",
                    "--fingerprint",
                    plan["fingerprint"].as_str().unwrap(),
                ],
                &db
            )
            .status
            .code(),
            Some(4)
        );
        assert!(!db
            .explicit_command_from_config(wrong_authority)
            .status()
            .unwrap()
            .success());
        assert_eq!(db.snapshot(), before_invalid_configs);
        // Startup helper writes explicit.json; restore the original CLI input.
        fs::write(&config_path, serde_json::to_vec(&config).unwrap()).unwrap();
        assert!(command(
            &config_path,
            "security-check",
            &["--extension", "runtime"],
            &db
        )
        .status
        .success());

        let mut missing_key = config.clone();
        missing_key["runtime"]["account_security"]["subject_key_file"] =
            json!("missing-subject.key");
        assert!(!db
            .explicit_command_from_config(missing_key)
            .status()
            .unwrap()
            .success());
        assert_eq!(db.snapshot(), before_invalid_configs);

        let mut no_security = config.clone();
        no_security["runtime"]
            .as_object_mut()
            .unwrap()
            .remove("account_security");
        let no_security_port = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        no_security["runtime"]["bind_addr"] = json!(format!("127.0.0.1:{no_security_port}"));
        no_security["runtime"]["issuer"] = json!(format!("http://127.0.0.1:{no_security_port}"));
        no_security["runtime"]["http"]["browser_origin"] =
            json!(format!("http://127.0.0.1:{no_security_port}"));
        let no_security_host = db.start_command(
            no_security_port,
            &mut db.explicit_command_from_config(no_security),
        );
        assert_eq!(
            no_security_host
                .raw(
                    "POST",
                    "/one/auth/security/sessions/revoke",
                    None,
                    None,
                    Some(json!({})),
                )
                .0,
            404
        );
        drop(no_security_host);

        let host = db.start_command(port, &mut db.explicit_command_from_config(config));
        let root = format!("http://127.0.0.1:{}", host.port);
        let management_path = "/identity/admin/auth";
        let management = host.json(
            "POST",
            &format!("{management_path}/login"),
            None,
            None,
            Some(json!({"email":"admin@example.test","password":"Runtime-Admin123"})),
            200,
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

        let bearer_operation = Uuid::now_v7();
        let bearer_secret = [31; 32];
        let bearer_path = "/one/auth/security/sessions/revoke";
        let cross_entry = host.raw(
            "POST",
            "/two/auth/security/sessions/revoke",
            Some(token(&one)),
            None,
            Some(revoke_body(&two["session"], Uuid::now_v7(), &[32; 32])),
        );
        assert_eq!(
            cross_entry.0, 401,
            "a valid token from another entry is not accepted"
        );
        let (status, bearer_headers, missing) = security_headers_request(
            &host,
            "POST",
            bearer_path,
            &[("Authorization", &format!("Bearer {}", token(&one)))],
            &revoke_body(&one["session"], bearer_operation, &bearer_secret),
        );
        assert_eq!(status, 200, "{missing}");
        assert!(missing.contains("\"completed\":true"));
        assert!(bearer_headers
            .to_ascii_lowercase()
            .contains("cache-control: no-store"));
        assert!(!bearer_headers.to_ascii_lowercase().contains("set-cookie:"));
        let (_, result_headers, result) = security_headers_request(
            &host,
            "POST",
            "/two/auth/security/sessions/revoke/result",
            &[],
            &receipt_body(bearer_operation, &bearer_secret),
        );
        assert!(result.contains("\"completed\":true"));
        assert!(result_headers
            .to_ascii_lowercase()
            .contains("cache-control: no-store"));
        assert!(!result_headers.to_ascii_lowercase().contains("set-cookie:"));
        let (status, wrong_headers, wrong_secret) = security_headers_request(
            &host,
            "POST",
            "/one/auth/security/sessions/revoke/result",
            &[],
            &receipt_body(bearer_operation, &[99; 32]),
        );
        assert_eq!(status, 200);
        assert!(wrong_secret.contains("\"completed\":false"));
        assert!(wrong_headers
            .to_ascii_lowercase()
            .contains("cache-control: no-store"));
        assert!(!wrong_headers.to_ascii_lowercase().contains("set-cookie:"));
        assert_eq!(
            host.raw(
                "GET",
                "/one/auth/security/sessions",
                Some(token(&one)),
                None,
                None
            )
            .0,
            401,
            "a revoked bearer session cannot resume authenticated use"
        );

        // The second browser session is deliberately fresh. Revoking the first
        // returns no cookie mutation, so a late response cannot clear this login.
        let (status, old_cookie, old_browser) = host.browser(
            "/one/auth/browser/login",
            None,
            None,
            json!({"email":"admin@example.test","password":"Runtime-Admin123"}),
        );
        assert_eq!(status, 200);
        let old_cookie = old_cookie.unwrap();
        let (status, fresh_cookie, fresh_browser) = host.browser(
            "/one/auth/browser/login",
            None,
            None,
            json!({"email":"admin@example.test","password":"Runtime-Admin123"}),
        );
        assert_eq!(status, 200);
        let fresh_cookie = fresh_cookie.unwrap();
        let browser_operation = Uuid::now_v7();
        let browser_secret = [41; 32];
        let mut browser_body =
            revoke_body(&old_browser["session"], browser_operation, &browser_secret);
        browser_body["expected"] = browser_identity(&old_browser["session"]);
        let (status, browser_revoke_headers, revoked) = security_headers_request(
            &host,
            "POST",
            "/one/auth/browser/security/sessions/revoke",
            &[
                ("Cookie", &cookie_pair(&old_cookie)),
                ("Origin", &root),
                ("X-Embedded-Idp-Browser", "1"),
            ],
            &browser_body,
        );
        assert_eq!(status, 200, "{revoked}");
        assert!(browser_revoke_headers
            .to_ascii_lowercase()
            .contains("cache-control: no-store"));
        assert!(!browser_revoke_headers
            .to_ascii_lowercase()
            .contains("set-cookie:"));
        let receipt = receipt_body(browser_operation, &browser_secret);
        let (status, changed, result) = host.browser(
            "/one/auth/browser/security/sessions/revoke/result",
            None,
            None,
            receipt,
        );
        assert_eq!(status, 200, "{result}");
        assert!(changed.is_none());
        assert_eq!(result["completed"], true);
        let (status, browser_result_headers, _) = security_headers_request(
            &host,
            "POST",
            "/one/auth/browser/security/sessions/revoke/result",
            &[("Origin", &root), ("X-Embedded-Idp-Browser", "1")],
            &receipt_body(browser_operation, &browser_secret),
        );
        assert_eq!(status, 200);
        assert!(browser_result_headers
            .to_ascii_lowercase()
            .contains("cache-control: no-store"));
        assert!(!browser_result_headers
            .to_ascii_lowercase()
            .contains("set-cookie:"));
        assert_eq!(
            host.browser(
                "/one/auth/browser/restore",
                Some(cookie_pair(&old_cookie)),
                None,
                json!({"expected_session":browser_identity(&old_browser["session"])}),
            )
            .0,
            401
        );
        assert_eq!(
            host.browser(
                "/one/auth/browser/restore",
                Some(cookie_pair(&fresh_cookie)),
                None,
                json!({"expected_session":browser_identity(&fresh_browser["session"])}),
            )
            .0,
            200,
            "revoking an old session cannot clear a fresh same-entry login cookie"
        );

        let mgmt_operation = Uuid::now_v7();
        let mgmt_secret = [51; 32];
        let management_body = revoke_body(&management["session"], mgmt_operation, &mgmt_secret);
        let (status, headers, response) = security_headers_request(
            &host,
            "POST",
            "/identity/admin/auth/security/sessions/revoke",
            &[("Authorization", &format!("Bearer {}", token(&management)))],
            &management_body,
        );
        assert_eq!(status, 200, "{response}");
        assert!(headers
            .to_ascii_lowercase()
            .contains("cache-control: no-store"));
        assert!(!headers.to_ascii_lowercase().contains("set-cookie:"));
        let (_, _, result) = security_headers_request(
            &host,
            "POST",
            "/identity/admin/auth/security/sessions/revoke/result",
            &[],
            &receipt_body(mgmt_operation, &mgmt_secret),
        );
        assert!(result.contains("\"completed\":true"));

        let disabled_write = host.raw(
            "POST",
            "/auth/security/sessions/revoke",
            None,
            None,
            Some(json!({"operation_id":Uuid::now_v7().to_string(),"receipt_secret":Base64UrlUnpadded::encode_string(&[61;32]),"target_tenant_id":"0","target_session_id":two["session"]["session_id"]})),
        );
        assert_eq!(disabled_write.0, 404);

        let mut c = db.adapter.connect().unwrap();
        let saved_authority: String = c
            .query_one(
                &format!(
                    "select authority from {}.security_runtime_state where singleton",
                    db.adapter.schema_name()
                ),
                &[],
            )
            .unwrap()
            .get(0);
        c.execute(
            &format!("update {}.security_runtime_state set authority='drifted-authority' where singleton", db.adapter.schema_name()),
            &[],
        ).unwrap();
        let tampered_state = db.snapshot();
        assert_eq!(host.raw("GET", "/readyz", None, None, None).0, 503);
        let unavailable = security_headers_request(
            &host,
            "POST",
            "/one/auth/security/sessions/revoke/result",
            &[],
            &receipt_body(bearer_operation, &bearer_secret),
        );
        assert_eq!(unavailable.0, 503);
        assert!(unavailable.2.contains("security_unavailable"));
        assert_eq!(
            db.snapshot(),
            tampered_state,
            "readiness drift check performs no repair"
        );
        c.execute(
            &format!(
                "update {}.security_runtime_state set authority=$1 where singleton",
                db.adapter.schema_name()
            ),
            &[&saved_authority],
        )
        .unwrap();
        assert_eq!(host.raw("GET", "/readyz", None, None, None).0, 200);
    }
}
