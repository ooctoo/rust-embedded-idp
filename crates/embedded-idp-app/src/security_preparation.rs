use crate::composition_config::AppConfig;
use embedded_idp_storage_postgres::PostgresStorageAdapter;
use serde_json::json;
use std::path::Path;

pub(crate) const USAGE: &str = "security-plan|security-apply|security-check --config <path> --extension foundation|runtime\nsecurity-apply additionally requires --fingerprint <64 lowercase hex>";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Extension {
    Foundation,
    Runtime,
}

impl Extension {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "foundation" => Ok(Self::Foundation),
            "runtime" => Ok(Self::Runtime),
            _ => Err(USAGE.into()),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Foundation => "foundation",
            Self::Runtime => "runtime",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Action {
    Plan,
    Apply,
    Check,
}

struct Options {
    config: String,
    extension: Extension,
    fingerprint: Option<String>,
}

fn parse_options(action: Action, args: Vec<String>) -> Result<Options, String> {
    let mut config = None;
    let mut extension = None;
    let mut fingerprint = None;
    let mut args = args.into_iter();
    while let Some(flag) = args.next() {
        let target = match flag.as_str() {
            "--config" if config.is_none() => &mut config,
            "--extension" if extension.is_none() => &mut extension,
            "--fingerprint" if action == Action::Apply && fingerprint.is_none() => &mut fingerprint,
            _ => return Err(USAGE.into()),
        };
        *target = Some(
            args.next()
                .filter(|value| !value.is_empty() && !value.starts_with("--"))
                .ok_or_else(|| USAGE.to_string())?,
        );
    }
    let config = config.ok_or_else(|| USAGE.to_string())?;
    let extension = Extension::parse(&extension.ok_or_else(|| USAGE.to_string())?)?;
    if action == Action::Apply {
        let fingerprint = fingerprint.ok_or_else(|| USAGE.to_string())?;
        if !valid_fingerprint(&fingerprint) {
            return Err("invalid fingerprint".into());
        }
        Ok(Options {
            config,
            extension,
            fingerprint: Some(fingerprint),
        })
    } else if fingerprint.is_some() {
        Err(USAGE.into())
    } else {
        Ok(Options {
            config,
            extension,
            fingerprint: None,
        })
    }
}

fn valid_fingerprint(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(crate) fn run(command: &str, args: Vec<String>) -> Result<(), (i32, String)> {
    let action = match command {
        "security-plan" => Action::Plan,
        "security-apply" => Action::Apply,
        "security-check" => Action::Check,
        _ => return Err((2, USAGE.into())),
    };
    if args == ["--help"] {
        println!("{USAGE}");
        return Ok(());
    }
    let options = parse_options(action, args).map_err(|error| (2, error))?;
    let config = AppConfig::for_preparation(Path::new(&options.config)).map_err(|_| {
        (
            2,
            "invalid or unavailable host configuration for security migration".into(),
        )
    })?;
    let security = config.account_security.as_ref().ok_or((
        2,
        "runtime.account_security is required for security migration".into(),
    ))?;
    security
        .validate()
        .map_err(|_| (2, "invalid runtime.account_security configuration".into()))?;
    let adapter = PostgresStorageAdapter::new(config.postgres)
        .map_err(|_| (2, "invalid Postgres configuration".into()))?;

    match (action, options.extension) {
        (Action::Plan, Extension::Foundation) => {
            let plan = adapter
                .plan_security_foundation(config.tenancy_mode, &security.authority)
                .map_err(|_| (4, "security foundation plan failed".into()))?;
            print_plan(
                Extension::Foundation,
                &plan.schema_name,
                plan.mode,
                &plan.authority,
                &plan.fingerprint,
            );
        }
        (Action::Plan, Extension::Runtime) => {
            let plan = adapter
                .plan_security_runtime(config.tenancy_mode, &security.authority)
                .map_err(|_| (4, "security runtime plan failed".into()))?;
            print_plan(
                Extension::Runtime,
                &plan.schema_name,
                plan.mode,
                &plan.authority,
                &plan.fingerprint,
            );
        }
        (Action::Apply, Extension::Foundation) => {
            let plan = adapter
                .plan_security_foundation(config.tenancy_mode, &security.authority)
                .map_err(|_| (4, "security foundation plan failed".into()))?;
            apply_fingerprint(options.fingerprint.as_deref(), &plan.fingerprint)?;
            adapter.apply_security_foundation(&plan).map_err(|_| {
                (
                    4,
                    "security foundation apply failed or outcome unknown".into(),
                )
            })?;
            println!("{{\"extension\":\"foundation\",\"ready\":true}}");
        }
        (Action::Apply, Extension::Runtime) => {
            let plan = adapter
                .plan_security_runtime(config.tenancy_mode, &security.authority)
                .map_err(|_| (4, "security runtime plan failed".into()))?;
            apply_fingerprint(options.fingerprint.as_deref(), &plan.fingerprint)?;
            adapter
                .apply_security_runtime(&plan)
                .map_err(|_| (4, "security runtime apply failed or outcome unknown".into()))?;
            println!("{{\"extension\":\"runtime\",\"ready\":true}}");
        }
        (Action::Check, Extension::Foundation) => {
            adapter
                .check_security_foundation(config.tenancy_mode, &security.authority)
                .map_err(|_| (4, "security foundation check failed".into()))?;
            println!("{{\"extension\":\"foundation\",\"ready\":true}}");
        }
        (Action::Check, Extension::Runtime) => {
            adapter
                .check_security_runtime(config.tenancy_mode, &security.authority)
                .map_err(|_| (4, "security runtime check failed".into()))?;
            println!("{{\"extension\":\"runtime\",\"ready\":true}}");
        }
    }
    Ok(())
}

fn apply_fingerprint(expected: Option<&str>, actual: &str) -> Result<(), (i32, String)> {
    if expected == Some(actual) {
        Ok(())
    } else {
        Err((
            3,
            "security migration plan fingerprint does not match".into(),
        ))
    }
}

fn print_plan(
    extension: Extension,
    schema_name: &str,
    mode: embedded_idp_core::access::TenancyMode,
    authority: &str,
    fingerprint: &str,
) {
    println!(
        "{}",
        json!({
            "extension": extension.as_str(),
            "schema_name": schema_name,
            "mode": mode_name(mode),
            "authority": authority,
            "fingerprint": fingerprint,
        })
    );
}

fn mode_name(mode: embedded_idp_core::access::TenancyMode) -> &'static str {
    match mode {
        embedded_idp_core::access::TenancyMode::Disabled => "disabled",
        embedded_idp_core::access::TenancyMode::Enabled => "enabled",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_grammar_rejects_missing_duplicate_unknown_and_wrong_flags() {
        for args in [
            vec![],
            vec!["--config", "cfg"],
            vec![
                "--config",
                "cfg",
                "--extension",
                "runtime",
                "--config",
                "other",
            ],
            vec!["--config", "cfg", "--extension", "future"],
            vec![
                "--config",
                "cfg",
                "--extension",
                "runtime",
                "--fingerprint",
                &"a".repeat(64),
            ],
            vec!["--config", "--extension", "runtime"],
        ] {
            assert!(
                parse_options(Action::Plan, args.into_iter().map(str::to_owned).collect()).is_err()
            );
        }
        assert!(parse_options(
            Action::Check,
            [
                "--config",
                "cfg",
                "--extension",
                "runtime",
                "--fingerprint",
                &"a".repeat(64)
            ]
            .map(str::to_owned)
            .to_vec()
        )
        .is_err());
        assert!(parse_options(
            Action::Apply,
            ["--config", "cfg", "--extension", "runtime"]
                .map(str::to_owned)
                .to_vec()
        )
        .is_err());
    }

    #[test]
    fn fingerprint_requires_exact_lowercase_sha256_hex() {
        assert!(valid_fingerprint(&"a1".repeat(32)));
        for value in [
            "",
            &"A".repeat(64),
            &"g".repeat(64),
            &"a".repeat(63),
            &"a".repeat(65),
        ] {
            assert!(!valid_fingerprint(value));
        }
        assert!(apply_fingerprint(Some(&"b".repeat(64)), &"a".repeat(64)).is_err());
        assert!(apply_fingerprint(Some(&"a".repeat(64)), &"a".repeat(64)).is_ok());
    }
}
