//! Configuration failures must remain offline and must never fall back to legacy startup.
use std::{env, fs, process::Command};

#[test]
fn unsupported_business_fails_before_loading_secrets_or_keys() {
    let dir = env::temp_dir().join(format!("m102-cli-support-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join("unsupported.json");
    let mut config = serde_json::json!({
        "version":1,
        "runtime": {
            "tenancy_mode":"enabled", "bind_addr":"127.0.0.1:0",
            "issuer":"https://idp.example.test", "signing_key_file":"missing-key.der",
            "postgres":{"connection": {
                "uri_ref":{"env":"IDP_M102_MISSING_DATABASE"},
                "schema_name":"idp_test", "tls_mode":"require"
            }},
            "email":{"mode":"smtp","smtp":{
                "username":"fixture", "password_ref":{"env":"IDP_M102_MISSING_SMTP"}
            }}
        },
        "management": {
            "login_entry":"management", "client_id":"management",
            "tenant_policy":{"kind":"fixed","tenant_id":"0"},
            "mount_prefix":"/identity"
        },
        "business_entries":[{
            "login_entry":"product", "client_id":"product",
            "tenant_policy":{"kind":"fixed","tenant_id":"tenant-a"},
            "mount_prefix":"/product"
        }]
    });
    for expected in [
        "business entries are not supported by this build",
        "missing secret",
    ] {
        fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_embedded-idp-app"))
            .env_clear()
            .arg("--config")
            .arg(&path)
            .output()
            .unwrap();
        assert!(!output.status.success());
        let message = String::from_utf8_lossy(&output.stderr);
        assert!(message.contains(expected), "{message}");
        assert!(!message.contains("missing-key"));
        assert!(!message.contains("postgres://"));
        config["business_entries"] = serde_json::json!([]);
    }
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn explicit_cli_rejects_ambiguous_inputs_without_fallback_or_secret_output() {
    let dir = env::temp_dir().join(format!("m102-cli-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join("invalid.json");
    fs::write(
        &path,
        br#"{"version":1,"credential":"synthetic-secret-marker",broken}"#,
    )
    .unwrap();
    let path = path.to_str().unwrap();
    for (args, expected) in [
        (vec!["--config"], "requires one file path"),
        (vec!["--config", ""], "requires one file path"),
        (
            vec!["--config", path, "--config", path],
            "exactly one file path",
        ),
        (
            vec!["--config", path],
            "invalid JSON configuration structure",
        ),
        (vec!["bootstrap-admin", "--config", path], "usage:"),
        (vec!["--help", "extra"], "unknown command"),
    ] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_embedded-idp-app"));
        for (key, _) in env::vars_os() {
            if key.to_string_lossy().starts_with("EMBEDDED_IDP_APP_") {
                command.env_remove(key);
            }
        }
        let output = command
            .args(args)
            .env(
                "EMBEDDED_IDP_APP_PG_URI",
                "postgres://synthetic-secret-marker@127.0.0.1:1/unreachable",
            )
            .output()
            .unwrap();
        assert!(!output.status.success());
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(text.contains(expected), "{text}");
        assert!(
            !text.contains("synthetic-secret-marker"),
            "secret was echoed"
        );
        assert!(!text.contains("postgres://"));
    }
    fs::remove_dir_all(dir).unwrap();
}
