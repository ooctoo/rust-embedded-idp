use crate::config::{auth_config_from_env, postgres_config_from_env};
use embedded_idp_core::access::{
    AccessBootstrapResult, AccessError, BootstrapAdministrator, CoreAccessBootstrapService,
    TenancyMode,
};
use embedded_idp_core::{IdGenerator, SecretString, SystemClock, UuidV7IdGenerator};
use embedded_idp_storage_postgres::PostgresStorageAdapter;
use std::{
    env,
    io::{self, IsTerminal, Read},
};

pub(crate) const USAGE:&str="usage: embedded-idp-app bootstrap-admin --email <email> --password-stdin [--display-name <name>]\nRequires explicit EMBEDDED_IDP_APP_TENANCY_MODE, EMBEDDED_IDP_APP_PG_URI and EMBEDDED_IDP_APP_PG_SCHEMA. Prepare the fresh Access schema first. Supply a single UTF-8 password line through a pipe or private input file, never a command argument.";
struct Options {
    email: String,
    display_name: Option<String>,
}
fn parse(args: Vec<String>) -> Result<Options, String> {
    let mut email = None;
    let mut name = None;
    let mut stdin = false;
    let mut args = args.into_iter();
    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--email" if email.is_none() => email = Some(args.next().ok_or(USAGE)?),
            "--display-name" if name.is_none() => name = Some(args.next().ok_or(USAGE)?),
            "--password-stdin" if !stdin => stdin = true,
            _ => return Err(USAGE.into()),
        }
    }
    if !stdin {
        return Err(USAGE.into());
    }
    Ok(Options {
        email: email.ok_or(USAGE)?,
        display_name: name,
    })
}
fn password(input: impl Read) -> Result<SecretString, String> {
    // A bounded one-line secret avoids unbounded stdin buffering; do not trim password spaces.
    let mut value = String::new();
    input
        .take(16385)
        .read_to_string(&mut value)
        .map_err(|_| "cannot read UTF-8 password input")?;
    if value.len() > 16384 {
        return Err("password input exceeds 16 KiB".into());
    }
    if value.ends_with('\n') {
        value.pop();
        if value.ends_with('\r') {
            value.pop();
        }
    }
    if value.is_empty() || value.chars().any(char::is_control) {
        return Err("password input must contain exactly one nonempty line".into());
    }
    Ok(SecretString::new(value))
}
pub(crate) fn run(args: Vec<String>) -> Result<(), String> {
    if args == ["--help"] {
        println!("{USAGE}");
        return Ok(());
    }
    let options = parse(args)?;
    let mode = match env::var("EMBEDDED_IDP_APP_TENANCY_MODE").as_deref() {
        Ok("enabled") => TenancyMode::Enabled,
        Ok("disabled") => TenancyMode::Disabled,
        _ => {
            return Err(
                "explicit EMBEDDED_IDP_APP_TENANCY_MODE=disabled|enabled is required".into(),
            )
        }
    };
    for key in ["EMBEDDED_IDP_APP_PG_URI", "EMBEDDED_IDP_APP_PG_SCHEMA"] {
        if env::var(key).map_or(true, |v| v.trim().is_empty()) {
            return Err(format!("explicit {key} is required"));
        }
    }
    let config = auth_config_from_env()?;
    let postgres = postgres_config_from_env()?;
    if io::stdin().is_terminal() {
        return Err(
            "refusing echoed terminal password input; use a pipe or private input file".into(),
        );
    }
    let password = password(io::stdin().lock())?;
    let adapter =
        PostgresStorageAdapter::new(postgres).map_err(|_| "invalid database configuration")?;
    let ids = UuidV7IdGenerator;
    let result=CoreAccessBootstrapService::new(mode,adapter,SystemClock,ids).initialize_administrator(&config,BootstrapAdministrator {
        email:options.email,display_name:options.display_name,password,request_id:UuidV7IdGenerator.next_id("request"),
    }).map_err(|error|match error {
        AccessError::InvalidInput(field)=>format!("invalid administrator input: {field}"),
        AccessError::Conflict(reason)=>format!("administrator bootstrap refused: {reason}"),
        _=>"administrator bootstrap failed; verify prepared Access schema, mode, database access and bootstrap state".into(),
    })?;
    match result {
        AccessBootstrapResult::Initialized => println!("administrator bootstrap initialized"),
        AccessBootstrapResult::AlreadyInitialized => {
            println!("administrator bootstrap already initialized; no credentials changed")
        }
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bootstrap_options_are_explicit_and_never_echo_rejected_values() {
        for args in [
            vec![],
            vec!["--email", "admin@example.test"],
            vec!["--email", "a@example.test", "--password", "must-not-echo"],
            vec![
                "--email",
                "a@example.test",
                "--email",
                "b@example.test",
                "--password-stdin",
            ],
            vec![
                "--email",
                "a@example.test",
                "--password-stdin",
                "--password-stdin",
            ],
        ] {
            let error = parse(args.into_iter().map(str::to_owned).collect())
                .err()
                .unwrap();
            assert!(!error.contains("must-not-echo"));
        }
        let result = parse(
            [
                "--email",
                "admin@example.test",
                "--password-stdin",
                "--display-name",
                "Initial Admin",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        )
        .unwrap();
        assert_eq!(result.email, "admin@example.test");
        assert_eq!(result.display_name.as_deref(), Some("Initial Admin"));
    }
    #[test]
    fn bootstrap_password_input_is_bounded_single_line_and_preserves_spaces() {
        for line in [" Example123 ", " Example123 \n", " Example123 \r\n"] {
            assert_eq!(
                password(line.as_bytes()).unwrap().expose_secret(),
                " Example123 "
            );
        }
        for raw in [
            b"".as_slice(),
            b"\n",
            b"Example123\nother",
            b"Example123\0",
            &[255],
        ] {
            assert!(password(raw).is_err());
        }
        assert!(password(vec![b'a'; 16385].as_slice()).is_err());
        assert!(
            !format!("{:?}", password(b"Example123".as_slice()).unwrap()).contains("Example123")
        );
    }
}
