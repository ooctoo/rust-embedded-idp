use crate::composition_config::AppConfig;
use embedded_idp_core::{access::*, IdGenerator, SystemClock, UuidV7IdGenerator};
use embedded_idp_storage_postgres::PostgresStorageAdapter;
use serde::Deserialize;
use std::path::Path;

pub(crate) const USAGE: &str = "prepare-management-client --config <path> --definition <path>\nprepare-management-client-audit --config <path> (explicit additive schema preparation)";
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Definition {
    client_name: String,
    redirect_uris: Vec<String>,
}
fn options(args: Vec<String>, audit: bool) -> Result<(String, Option<String>), String> {
    let mut args = args.into_iter();
    let (mut config, mut definition) = (None, None);
    while let Some(flag) = args.next() {
        let target = match flag.as_str() {
            "--config" if config.is_none() => &mut config,
            "--definition" if !audit && definition.is_none() => &mut definition,
            _ => return Err(USAGE.into()),
        };
        *target = Some(
            args.next()
                .filter(|s| !s.is_empty() && !s.starts_with("--"))
                .ok_or(USAGE)?,
        );
    }
    if !audit && definition.is_none() {
        return Err(USAGE.into());
    }
    Ok((config.ok_or(USAGE)?, definition))
}
fn definition(path: &Path) -> Result<Definition, String> {
    let bytes = crate::composition_config::read_limited(path, 65536, "client definition")?;
    serde_json::from_slice(&bytes).map_err(|_| "invalid client definition structure".into())
}
pub(crate) fn run(args: Vec<String>, audit: bool) -> Result<(), (i32, String)> {
    if args == ["--help"] {
        println!("{USAGE}");
        return Ok(());
    }
    let (path, definition_path) = options(args, audit).map_err(|e| (2, e))?;
    let config = AppConfig::for_preparation(Path::new(&path)).map_err(|e| (2, e))?;
    let input = definition_path
        .map(|path| definition(Path::new(&path)))
        .transpose()
        .map_err(|e| (2, e))?;
    let adapter = PostgresStorageAdapter::new(config.postgres)
        .map_err(|_| (2, "invalid database configuration".into()))?;
    if audit {
        adapter
            .prepare_management_client_audit_schema(config.tenancy_mode)
            .map_err(|_| {
                (
                    4,
                    "audit schema preparation failed; verify schema/mode and database access"
                        .into(),
                )
            })?;
        println!("management client preparation audit schema ready");
        return Ok(());
    }
    let input = input.ok_or((2, USAGE.into()))?;
    let result = CoreManagementClientPreparationService::new(config.tenancy_mode, adapter, SystemClock, UuidV7IdGenerator)
        .prepare(PrepareManagementClient { client_id: config.management.client_id, client_name: input.client_name, redirect_uris: input.redirect_uris, request_id: UuidV7IdGenerator.next_id("request") })
        .map_err(|e| match e { AccessError::InvalidInput(_) => (2, "invalid management client definition".into()), _ => (4, "management client preparation failed or outcome unknown; verify schema, mode, administrator and audit preparation; retry the identical definition".into()) })?;
    match result {
        ManagementClientPreparationResult::Created => println!("Created"),
        ManagementClientPreparationResult::AlreadyMatches => println!("AlreadyMatches"),
        ManagementClientPreparationResult::Conflict => {
            return Err((
                3,
                "Conflict: existing client differs; no changes made".into(),
            ))
        }
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_ambiguous_options_and_definition_fields() {
        for args in [
            vec![],
            vec!["--config", "a"],
            vec!["--config", "a", "--config", "b"],
            vec!["--config", "--definition", "a"],
        ] {
            assert!(options(args.into_iter().map(String::from).collect(), false).is_err());
        }
        for json in [
            r#"{"client_name":"a","client_name":"b","redirect_uris":[]}"#,
            r#"{"client_name":"a","redirect_uris":[],"client_id":"override"}"#,
            r#"{"client_name":"a","redirect_uris":[],"client_secret":"secret"}"#,
        ] {
            assert!(serde_json::from_str::<Definition>(json).is_err());
        }
        assert!(options(vec!["--config".into(), "a".into()], true).is_ok());
    }
}
