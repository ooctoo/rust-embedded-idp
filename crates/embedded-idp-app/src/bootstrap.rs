use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::Request;
use axum::http::{header::HeaderName, HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use embedded_idp_axum::{
    admin_router, client_authenticated_router, public_router, subject_router, token_router,
    AuthenticatedSubject, EmbeddedIdpHttpState, RouteMountPlan,
};
use embedded_idp_core::{
    ClientSecretHasher, CoreAdminService, CoreAuthService, CoreDeviceService,
    CoreOidcResourceService, CoreOidcService, JwksDocument, NumericVerificationCodeGenerator,
    PhcClientSecretCodec, StaticOidcMetadataService, SystemClock,
};
use embedded_idp_email::{DefaultVerificationEmailService, VerificationEmailConfig};
use embedded_idp_storage_postgres::PostgresStorageAdapter;
use postgres::Client;
use serde_json::json;

use crate::admin_ui::admin_console_router;
use crate::config::{EmbeddedIdpAppConfig, SeedClientConfig, SeedConfidentialClientConfig};
use crate::dev_security::{
    DevAccessTokenValidator, DevDeviceProofVerifier, DevIdGenerator, DevIdTokenIssuer,
    DevTokenIssuer,
};
use crate::email_sender::AppEmailSenderProvider;

pub fn build_app(config: &EmbeddedIdpAppConfig) -> Result<Router, String> {
    let adapter = PostgresStorageAdapter::new(config.postgres.clone())
        .map_err(|error| format!("postgres adapter init failed: {error:?}"))?;
    adapter
        .apply_migrations()
        .map_err(|error| format!("apply migrations failed: {error:?}"))?;

    seed_public_client(&adapter, &config.public_client)?;
    if let Some(confidential_client) = &config.confidential_client {
        seed_confidential_client(&adapter, confidential_client)?;
    }

    let token_issuer = DevTokenIssuer::new(
        config.embedded_idp.auth.access_token_ttl_secs,
        config.embedded_idp.auth.refresh_token_ttl_secs,
    );
    let client_secret_codec = PhcClientSecretCodec;
    let id_generator = DevIdGenerator::default();
    let auth_service = Arc::new(CoreAuthService::new(
        config.embedded_idp.auth.clone(),
        adapter.clone(),
        token_issuer.clone(),
        SystemClock,
        id_generator.clone(),
        NumericVerificationCodeGenerator,
    ));
    let admin_service = Arc::new(CoreAdminService::new(
        config.embedded_idp.auth.clone(),
        adapter.clone(),
        client_secret_codec,
    ));
    let device_service = Arc::new(CoreDeviceService::new(
        config.embedded_idp.device.clone(),
        adapter.clone(),
        DevDeviceProofVerifier,
        id_generator.clone(),
    ));
    let oidc_service = Arc::new(CoreOidcService::new(
        config.embedded_idp.issuer.clone(),
        config.embedded_idp.auth.clone(),
        config.embedded_idp.oidc.clone(),
        adapter.clone(),
        token_issuer,
        DevIdTokenIssuer,
        client_secret_codec,
        SystemClock,
        id_generator,
    ));
    let oidc_resource_service = Arc::new(CoreOidcResourceService::new(
        adapter,
        DevAccessTokenValidator,
        client_secret_codec,
    ));
    let state = EmbeddedIdpHttpState {
        issuer: config.embedded_idp.issuer.clone(),
        route_mount_plan: RouteMountPlan::default_mounts(),
        admin_service,
        auth_service,
        verification_email_service: Arc::new(DefaultVerificationEmailService::new(
            AppEmailSenderProvider::new(config.email_delivery.clone()),
            VerificationEmailConfig {
                from_email: config.email_delivery.from_email.clone(),
                from_name: config.email_delivery.from_name.clone(),
                subject: config.email_delivery.subject.clone(),
            },
        )),
        device_service,
        oidc_authorization_service: oidc_service.clone(),
        oidc_metadata_service: Arc::new(StaticOidcMetadataService::new(JwksDocument {
            keys: Vec::new(),
        })),
        token_management_service: oidc_service,
        user_info_service: oidc_resource_service.clone(),
        token_introspection_service: oidc_resource_service,
    };

    let subject_header = config.dev_subject_header.clone();
    let mut app = Router::new()
        .route(
            "/healthz",
            get(|| async { Json(json!({ "status": "ok" })) }),
        )
        .merge(admin_console_router(&config.admin_ui_base_path))
        .merge(public_router(state.clone()))
        .merge(token_router(state.clone()))
        .merge(client_authenticated_router(state.clone()))
        .merge(
            subject_router(state.clone()).route_layer(middleware::from_fn(move |request, next| {
                require_subject_header(subject_header.clone(), request, next)
            })),
        );

    if let Some(admin_api_key) = config.admin_api_key.clone() {
        app = app.merge(Router::new().nest(
            "/api",
            admin_router(state).route_layer(middleware::from_fn(move |request, next| {
                require_admin_api_key(admin_api_key.clone(), request, next)
            })),
        ));
    }

    Ok(app)
}

fn seed_public_client(
    adapter: &PostgresStorageAdapter,
    client: &SeedClientConfig,
) -> Result<(), String> {
    let mut connection = adapter
        .connect()
        .map_err(|error| format!("postgres connect failed: {error:?}"))?;
    upsert_client(
        &mut connection,
        adapter.schema_name(),
        &client.client_id,
        &client.client_name,
        &client.redirect_uri,
        "public_desktop",
        true,
        None,
    )
}

fn seed_confidential_client(
    adapter: &PostgresStorageAdapter,
    client: &SeedConfidentialClientConfig,
) -> Result<(), String> {
    let mut connection = adapter
        .connect()
        .map_err(|error| format!("postgres connect failed: {error:?}"))?;
    upsert_client(
        &mut connection,
        adapter.schema_name(),
        &client.client_id,
        &client.client_name,
        &client.redirect_uri,
        "confidential_web",
        false,
        Some(
            PhcClientSecretCodec
                .hash_client_secret(&client.client_secret)
                .map_err(|error| format!("hash confidential client secret failed: {error:?}"))?,
        ),
    )
}

#[allow(clippy::too_many_arguments)]
fn upsert_client(
    connection: &mut Client,
    schema_name: &str,
    client_id: &str,
    client_name: &str,
    redirect_uri: &str,
    client_type: &str,
    pkce_required: bool,
    client_secret_hash: Option<String>,
) -> Result<(), String> {
    let sql = format!(
        "insert into {schema_name}.oidc_clients \
         (client_id, client_name, redirect_uris_json, client_type, pkce_required, client_secret_hash, created_at_epoch) \
         values ($1, $2, $3, $4, $5, $6, $7) \
         on conflict (client_id) do update set \
         client_name = excluded.client_name, \
         redirect_uris_json = excluded.redirect_uris_json, \
         client_type = excluded.client_type, \
         pkce_required = excluded.pkce_required, \
         client_secret_hash = excluded.client_secret_hash"
    );
    let redirect_uris = serde_json::to_string(&vec![redirect_uri])
        .map_err(|error| format!("serialize redirect uri failed: {error}"))?;
    let created_at_epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_secs() as i64)
        .map_err(|error| format!("system time error: {error}"))?;

    connection
        .execute(
            &sql,
            &[
                &client_id,
                &client_name,
                &redirect_uris,
                &client_type,
                &pkce_required,
                &client_secret_hash,
                &created_at_epoch,
            ],
        )
        .map_err(|error| format!("seed oidc client failed: {error}"))?;
    Ok(())
}

async fn require_subject_header(header_name: String, mut request: Request, next: Next) -> Response {
    let Ok(header_name) = header_name.parse::<HeaderName>() else {
        return unauthorized("invalid_subject_header_name");
    };
    let Some(value) = request.headers().get(&header_name) else {
        return unauthorized("missing_authenticated_subject");
    };
    let Ok(account_id) = value.to_str() else {
        return unauthorized("invalid_authenticated_subject");
    };
    let account_id = account_id.to_string();

    request
        .extensions_mut()
        .insert(AuthenticatedSubject::new(account_id));
    next.run(request).await
}

async fn require_admin_api_key(admin_api_key: String, request: Request, next: Next) -> Response {
    let expected = HeaderValue::from_str(&admin_api_key).map_err(|_| ()).ok();
    let provided = request.headers().get("x-embedded-idp-admin-key");

    if expected.as_ref() != provided {
        return unauthorized("admin_api_key_required");
    }

    next.run(request).await
}

fn unauthorized(code: &'static str) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(json!({
            "code": code,
            "message": "request rejected by embedded-idp-app host middleware",
        })),
    )
        .into_response()
}
