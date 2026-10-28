mod config;
mod fixtures;
mod reports;
use axum::{
    extract::Path,
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use config::Config;
use embedded_idp_axum::*;
use embedded_idp_core::{access::*, *};
use embedded_idp_security::*;
use embedded_idp_storage_postgres::PostgresAccessStore;
use serde_json::json;
use std::{fs, sync::Arc};

pub(crate) type BusinessAuth = CoreTenantAuthenticationService<
    PostgresAccessStore,
    Rs256JwtService,
    SecureRefreshTokenGenerator,
    Sha256RefreshTokenDigester,
    SystemClock,
    UuidV7IdGenerator,
>;
pub(crate) type ManagementAuth = CoreManagementAuthenticationService<
    PostgresAccessStore,
    Rs256JwtService,
    SecureRefreshTokenGenerator,
    Sha256RefreshTokenDigester,
    SystemClock,
    UuidV7IdGenerator,
>;
pub(crate) fn load_key(config: &Config) -> Result<RsaSigningKeyConfig, String> {
    let meta =
        fs::metadata(&config.signing_key_file).map_err(|_| "signing key missing; run key-init")?;
    if !meta.is_file() || meta.len() > 65536 {
        return Err("invalid key file".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o077 != 0 {
            return Err("signing key must be owner-only".into());
        }
    }
    RsaSigningKeyConfig::from_private_key_der(
        fs::read(&config.signing_key_file).map_err(|_| "cannot read key")?,
    )
    .map_err(|_| "invalid RSA PKCS8 key".into())
}
fn tokens(
    config: &Config,
    key: &RsaSigningKeyConfig,
    entry: &str,
    management: bool,
) -> Result<Rs256JwtService, String> {
    let jwt = ProductionJwtConfig {
        issuer: config.issuer.clone(),
        audience: format!("tenant-host-{entry}"),
        scope: "openid profile email".into(),
        access_token_ttl_secs: 900,
        refresh_token_ttl_secs: 86400,
        clock_skew_secs: 0,
    };
    (if management {
        Rs256JwtService::new_management(jwt, key.clone(), vec![])
    } else {
        Rs256JwtService::new(jwt, key.clone(), vec![])
    })
    .map_err(|_| "invalid token configuration".into())
}
fn business_auth(
    config: &Config,
    store: &PostgresAccessStore,
    key: &RsaSigningKeyConfig,
    entry: &str,
) -> Result<BusinessAuth, String> {
    let policy = if entry == "fixed" {
        LoginTenantPolicy::Fixed {
            tenant_id: "tenant-a".into(),
        }
    } else {
        LoginTenantPolicy::ChooseAfterAuthentication
    };
    CoreTenantAuthenticationService::new(
        TenancyMode::Enabled,
        config.auth(),
        TenantLoginEntry {
            client_id: format!("tenant-host-{entry}"),
            login_entry: format!("a05-{entry}"),
            policy,
            require_device_proof: false,
        },
        store.clone(),
        tokens(config, key, entry, false)?,
        SecureRefreshTokenGenerator,
        Sha256RefreshTokenDigester,
        SystemClock,
        UuidV7IdGenerator,
    )
    .map_err(|_| "invalid business entry".into())
}
pub(crate) fn management_auth(
    config: &Config,
    store: &PostgresAccessStore,
    key: &RsaSigningKeyConfig,
) -> Result<ManagementAuth, String> {
    CoreManagementAuthenticationService::new(
        TenancyMode::Enabled,
        config.auth(),
        TenantLoginEntry {
            client_id: "tenant-host-management".into(),
            login_entry: "a05-management".into(),
            policy: LoginTenantPolicy::Fixed {
                tenant_id: "0".into(),
            },
            require_device_proof: false,
        },
        store.clone(),
        tokens(config, key, "management", true)?,
        SecureRefreshTokenGenerator,
        Sha256RefreshTokenDigester,
        SystemClock,
        UuidV7IdGenerator,
    )
    .map_err(|_| "invalid management entry".into())
}
fn build_app(config: &Config) -> Result<Router, String> {
    let password_work = embedded_idp_core::PasswordWorkBudget::default();
    fixtures::verify_marker(config)?;
    let store = config.store()?;
    let catalog = PermissionCatalog::new(vec![]).map_err(|_| "invalid catalog")?;
    store
        .check_readiness(&catalog)
        .map_err(|_| "IdP not prepared; bootstrap administrator first")?;
    store
        .auth_transaction(TenancyMode::Enabled, |tx| {
            for id in [
                "tenant-host-fixed",
                "tenant-host-choose",
                "tenant-host-management",
            ] {
                if !tx.client_exists(id)? {
                    return Err(TenantAuthError::InvalidSession);
                }
            }
            for id in ["tenant-a", "tenant-b"] {
                if tx.tenant(id)?.is_none() {
                    return Err(TenantAuthError::InvalidSession);
                }
            }
            Ok(())
        })
        .map_err(|_| "prepare clients and tenant fixtures before serve")?;
    let key = load_key(config)?;
    let business =
        reports::ReportStore::new(config.business_uri.clone(), config.business_schema.clone());
    business.ready()?;
    let access = Arc::new(CoreAccessService::new(
        TenancyMode::Enabled,
        catalog.clone(),
        store.clone(),
    ));
    let mut secret = [0u8; 32];
    ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut secret)
        .map_err(|_| "secure random unavailable")?;
    let cursor_key = Arc::new(ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &secret));
    let management = config.management_enabled;
    let mut app = Router::new()
        .route("/", get(index))
        .route("/assets/:name", get(asset))
        .route("/healthz", get(|| async { Json(json!({"status":"ok"})) }))
        .route(
            "/example-config",
            get(move || async move {
                (
                    [(header::CACHE_CONTROL, "no-store")],
                    Json(json!({"management_enabled":management,"business_id":"reports"})),
                )
            }),
        );
    for entry in ["fixed", "choose"] {
        let auth = Arc::new(
            business_auth(config, &store, &key, entry)?
                .with_password_work_budget(password_work.clone()),
        );
        let logout = CoreTenantOidcService::new(
            business_auth(config, &store, &key, entry)?
                .with_password_work_budget(password_work.clone()),
            config.issuer.clone(),
            OidcConfig {
                authorization_code_ttl_secs: 300,
                require_pkce_for_public_clients: true,
            },
            "openid profile email".into(),
            BudgetedClientSecretCodec::new(PhcClientSecretCodec, password_work.clone()),
        )
        .map_err(|_| "invalid logout service")?;
        let http = BrowserSessionHttpConfig::new(
            &config.browser_origin,
            &format!("a05_{}_{entry}", config.bind_addr.port()),
            &format!("/{entry}/auth/browser"),
            AccessTokenPurpose::Business,
        )
        .map_err(str::to_owned)?;
        let routes = Router::new()
            .route("/", get(index))
            .merge(tenant_auth_router(auth.clone()))
            .merge(tenant_refresh_router(auth.clone()))
            .merge(tenant_logout_router(Arc::new(logout)))
            .merge(tenant_self_router(auth.clone(), access.clone()))
            .merge(browser_session_router(auth.clone(), http)?)
            .merge(reports::router(reports::ReportState {
                business_id: "reports".into(),
                entry_id: entry.into(),
                authentication: auth,
                authorization: access.clone(),
                store: business.clone(),
                cursor_key: cursor_key.clone(),
            }));
        app = app.nest(&format!("/{entry}"), routes);
    }
    if config.management_enabled {
        let auth = Arc::new(
            management_auth(config, &store, &key)?.with_password_work_budget(password_work.clone()),
        );
        let admin = Arc::new(CoreAccessAdminService::new(
            TenancyMode::Enabled,
            catalog,
            store,
            SystemClock,
            UuidV7IdGenerator,
        ));
        let http = BrowserSessionHttpConfig::new(
            &config.browser_origin,
            &format!("a05_{}_management", config.bind_addr.port()),
            "/control/admin/auth/browser",
            AccessTokenPurpose::Management,
        )
        .map_err(str::to_owned)?;
        app = app.route("/management", get(index)).nest(
            "/control",
            management_router(
                auth.clone(),
                permission_admin_router(TenancyMode::Enabled, admin),
            )
            .merge(browser_session_router(auth, http)?),
        );
    }
    let abuse = Arc::new(
        InMemoryAbuseAdmission::new_random(AdmissionPolicy::default())
            .map_err(|e| e.to_string())?,
    );
    Ok(with_abuse_admission(
        with_anonymous_login_budget(app, AnonymousLoginBudget::default()),
        abuse,
    ))
}
async fn index() -> Response {
    static_file("index.html", "text/html; charset=utf-8").await
}
async fn asset(Path(name): Path<String>) -> Response {
    if name.is_empty()
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
    {
        return StatusCode::NOT_FOUND.into_response();
    }
    let kind = if name.ends_with(".js") {
        "text/javascript; charset=utf-8"
    } else if name.ends_with(".css") {
        "text/css; charset=utf-8"
    } else {
        return StatusCode::NOT_FOUND.into_response();
    };
    static_file(&format!("assets/{name}"), kind).await
}
async fn static_file(name: &str, kind: &'static str) -> Response {
    match tokio::fs::read(format!("{}/dist/{name}", env!("CARGO_MANIFEST_DIR"))).await {
        Ok(bytes) => (
            [
                (header::CONTENT_TYPE, kind),
                (header::CACHE_CONTROL, "no-store"),
            ],
            bytes,
        )
            .into_response(),
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::from_env()?;
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("serve") if args.len()==1 => {
            let app=build_app(&config)?;
            tokio::runtime::Builder::new_multi_thread().enable_all().build()?.block_on(async move {
                let listener=tokio::net::TcpListener::bind(config.bind_addr).await?;
                println!("A05 tenant host listening on {}",listener.local_addr()?);
                axum::serve(listener,app.into_make_service_with_connect_info::<std::net::SocketAddr>()).await
            })?;
        },
        Some(action)=>fixtures::run(&config,action,&args[1..])?,
        None=>return Err("use serve | db-init | bootstrap-admin <email> | prepare-clients | seed-fixtures <admin-email>".into()),
    }
    Ok(())
}
