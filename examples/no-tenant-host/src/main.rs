mod config;
mod reports;

use std::{error::Error, fs, sync::Arc};

use axum::{routing::get, Json, Router};
use config::Config;
use embedded_idp_axum::{
    tenant_device_auth_router, tenant_oidc_resource_router, tenant_self_router,
    TenantDeviceAuthHttpConfig,
};
use embedded_idp_core::{access::*, *};
use embedded_idp_security::*;
use embedded_idp_storage_postgres::{PostgresAccessStore, PostgresStorageAdapter};
use reports::{ReportState, ReportStore};
use serde_json::json;

const BUSINESS_AUDIENCE: &str = "embedded-idp-business";

fn signing_key(path: &str) -> Result<RsaSigningKeyConfig, String> {
    let metadata = fs::metadata(path).map_err(|_| "signing key is missing")?;
    if !metadata.is_file() || metadata.len() > 65_536 {
        return Err("invalid signing key file".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err("signing key must be owner-only (chmod 600)".into());
        }
    }
    RsaSigningKeyConfig::from_private_key_der(
        fs::read(path).map_err(|_| "cannot read signing key")?,
    )
    .map_err(|_| "invalid RSA PKCS#8 signing key".into())
}

fn build_app(config: &Config, business: ReportStore) -> Result<Router, String> {
    let adapter = PostgresStorageAdapter::new(config.idp.clone())
        .map_err(|_| "invalid IdP database configuration")?;
    let store = PostgresAccessStore::new(adapter, config.mode)
        .map_err(|error| format!("IdP is not ready: {error:?}"))?;
    let catalog = PermissionCatalog::new(vec![]).map_err(|_| "invalid permission catalog")?;
    store
        .check_readiness(&catalog)
        .map_err(|_| "IdP is not ready; prepare the schema and administrator")?;
    business.ready()?;
    let key = signing_key(&config.signing_key_file)?;
    let tokens = || {
        Rs256JwtService::new(
            ProductionJwtConfig {
                issuer: config.issuer.clone(),
                audience: BUSINESS_AUDIENCE.into(),
                scope: "openid profile email".into(),
                access_token_ttl_secs: config.auth.access_token_ttl_secs,
                refresh_token_ttl_secs: config.auth.refresh_token_ttl_secs,
                clock_skew_secs: 0,
            },
            key.clone(),
            vec![],
        )
        .map_err(|_| "invalid business token configuration".to_string())
    };
    let auth = || {
        CoreTenantAuthenticationService::new(
            config.mode,
            config.auth.clone(),
            TenantLoginEntry {
                client_id: config.client_id.clone(),
                login_entry: "business".into(),
                policy: config.login_policy.clone(),
                require_device_proof: false,
            },
            store.clone(),
            tokens()?,
            SecureRefreshTokenGenerator,
            Sha256RefreshTokenDigester,
            SystemClock,
            UuidV7IdGenerator,
        )
        .map_err(|_| "invalid business login configuration".to_string())
    };
    let proofs = CoreTenantDeviceProofService::new(
        config.mode,
        TenantDeviceProofConfig {
            client_id: config.client_id.clone(),
            allowed_purposes: [
                TENANT_DEVICE_LOGIN_PURPOSE,
                TENANT_DEVICE_SELECTION_PURPOSE,
                REFRESH_PURPOSE,
            ]
            .into_iter()
            .map(|purpose| DeviceProofPurpose::new(purpose).expect("known purpose"))
            .collect(),
            challenge_ttl_secs: config.proof_ttl_secs,
            clock_skew_secs: config.proof_skew_secs,
        },
        store.clone(),
        Ed25519PublicJwkParser,
        RingEd25519Verifier,
        SecureDeviceChallengeGenerator,
        SystemClock,
        UuidV7IdGenerator,
    )
    .map_err(|_| "invalid device proof configuration")?;
    let authentication = Arc::new(CoreTenantDeviceAuthenticationService::new(auth()?, proofs));
    let access = Arc::new(CoreAccessService::new(config.mode, catalog, store.clone()));
    let oidc = CoreTenantOidcService::new(
        auth()?,
        config.issuer.clone(),
        config.oidc.clone(),
        "openid profile email".into(),
        PhcClientSecretCodec,
    )
    .map_err(|_| "invalid OIDC resource configuration")?;
    let auth_http = TenantDeviceAuthHttpConfig::new(
        BUSINESS_AUDIENCE,
        "/auth/login",
        "/auth/tenant-selection/complete",
        "/auth/refresh",
    )
    .map_err(|_| "invalid auth route configuration")?;

    Ok(Router::new()
        .route("/", get(reports::index))
        .route("/assets/:name", get(reports::asset))
        .route("/healthz", get(|| async { Json(json!({"status":"ok"})) }))
        .merge(tenant_device_auth_router(authentication.clone(), auth_http))
        .merge(tenant_oidc_resource_router(Arc::new(oidc)))
        .merge(tenant_self_router(authentication.clone(), access.clone()))
        .merge(reports::router(ReportState {
            authentication,
            authorization: access,
            store: business,
        })))
}

fn main() -> Result<(), Box<dyn Error>> {
    let config = Config::from_env()?;
    let business = ReportStore::new(config.business_uri.clone(), config.business_schema.clone());
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("db-init") if args.next().is_none() => {
            let adapter = PostgresStorageAdapter::new(config.idp.clone())
                .map_err(|_| "invalid IdP database configuration")?;
            let catalog =
                PermissionCatalog::new(vec![]).map_err(|_| "invalid permission catalog")?;
            let facts = adapter
                .initialize_access_schema(config.mode, &catalog)
                .map_err(|error| format!("IdP schema initialization failed: {error:?}"))?;
            business.init()?;
            business.ready()?;
            println!(
                "prepared IdP schema {} ({}) and business schema {}; administrator bootstrap complete: {}",
                config.idp.connection.schema_name,
                facts.version,
                config.business_schema,
                facts.bootstrap_completed
            );
        }
        Some("seed-report") => {
            let id = args.next().ok_or("missing report ID")?;
            let title = args.next().ok_or("missing report title")?;
            if args.next().is_some() {
                return Err("too many seed-report arguments".into());
            }
            business.seed("0", &id, &title)?;
            println!("seeded report {id}");
        }
        Some("serve") if args.next().is_none() => {
            let app = build_app(&config, business)?;
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            runtime.block_on(async move {
                let listener = tokio::net::TcpListener::bind(config.bind_addr).await?;
                println!(
                    "no-tenant host listening on http://{}",
                    listener.local_addr()?
                );
                println!(
                    "tenancy mode: {:?}; IdP schema: {}; business schema: {}",
                    config.mode, config.idp.connection.schema_name, config.business_schema
                );
                axum::serve(listener, app).await?;
                Ok::<_, Box<dyn Error>>(())
            })?;
        }
        _ => return Err("use serve | db-init | seed-report <report-id> <title>".into()),
    }
    Ok(())
}
