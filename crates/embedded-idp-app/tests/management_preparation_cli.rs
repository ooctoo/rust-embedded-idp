//! Real CLI rejection paths remain offline, bounded and secret-free.
use serde_json::json;
use std::{
    fs,
    process::{Command, Output},
    time::{Duration, Instant},
};
fn run(args: &[&str]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_embedded-idp-app"))
        .env_clear()
        .env(
            "A01_DB",
            "postgres://synthetic-sensitive-value@127.0.0.1:1/unreachable",
        )
        .args(args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if child.try_wait().unwrap().is_some() {
            break;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("CLI did not exit within bounded deadline");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let output = child.wait_with_output().unwrap();
    for value in [&output.stdout, &output.stderr] {
        assert!(!String::from_utf8_lossy(value).contains("synthetic-sensitive-value"));
    }
    output
}
#[test]
fn preparation_cli_rejects_special_oversized_and_invalid_definitions_before_database_access() {
    let dir = std::env::temp_dir().join(format!("a01-cli-{}", std::process::id()));
    fs::create_dir(&dir).unwrap();
    let config = dir.join("config.json");
    let definition = dir.join("definition.json");
    fs::write(&config,serde_json::to_vec(&json!({"version":1,"runtime":{"tenancy_mode":"enabled","bind_addr":"127.0.0.1:0","issuer":"https://idp.example.test","signing_key_file":"unavailable.der","postgres":{"connection":{"uri_ref":{"env":"A01_DB"},"schema_name":"idp_test","tls_mode":"disable"}},"email":{"mode":"smtp","smtp":{"username":"fixture","password_ref":{"env":"UNAVAILABLE_SMTP"}}}},"management":{"login_entry":"management","client_id":"management","tenant_policy":{"kind":"fixed","tenant_id":"0"},"mount_prefix":"/identity"},"business_entries":[{"login_entry":"product","client_id":"product","tenant_policy":{"kind":"choose"},"mount_prefix":"/product"}]})).unwrap()).unwrap();
    let args = [
        "prepare-management-client",
        "--config",
        config.to_str().unwrap(),
        "--definition",
        definition.to_str().unwrap(),
    ];
    for bytes in [
        br#"{"client_name":"a","client_name":"b","redirect_uris":[]}"#.to_vec(),
        br#"{"client_name":"a","redirect_uris":[],"client_secret":"synthetic-sensitive-value"}"#
            .to_vec(),
        vec![b' '; 65537],
    ] {
        fs::write(&definition, bytes).unwrap();
        let output = run(&args);
        assert_eq!(output.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&output.stderr).contains("client definition"));
    }
    fs::write(
        &definition,
        br#"{"client_name":"Management","redirect_uris":["http://127.0.0.1/callback"]}"#,
    )
    .unwrap();
    let unavailable = run(&args);
    assert_eq!(unavailable.status.code(), Some(4));
    assert!(String::from_utf8_lossy(&unavailable.stderr).contains("failed or outcome unknown"));
    fs::remove_file(&definition).unwrap();
    #[cfg(unix)]
    {
        assert!(Command::new("mkfifo")
            .arg(&definition)
            .status()
            .unwrap()
            .success());
        let output = run(&args);
        assert_eq!(output.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&output.stderr).contains("regular file"));
        fs::remove_file(&definition).unwrap();
    }
    assert_eq!(
        run(&[
            "prepare-management-client-audit",
            "--config",
            config.to_str().unwrap(),
            "--definition",
            "synthetic-sensitive-value"
        ])
        .status
        .code(),
        Some(2)
    );
    fs::remove_dir_all(dir).unwrap();
}
