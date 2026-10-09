use crate::admin_ui::admin_console_router;
use crate::config::{EmbeddedIdpAppConfig, SeedClientConfig, SeedConfidentialClientConfig};
use crate::email_sender::AppEmailSenderProvider;
use crate::scan_ui::scan_reference_ui_router;
use axum::{http::StatusCode, routing::get, Extension, Json, Router};
use embedded_idp_axum::*;
use embedded_idp_core::{access::*, *};
use embedded_idp_email::{DefaultVerificationEmailService, VerificationEmailConfig};
use embedded_idp_security::*;
use embedded_idp_storage_postgres::{PostgresAccessStore, PostgresStorageAdapter};
use postgres::Client;
use serde_json::json;
use std::io::Read;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const BUSINESS_AUDIENCE: &str = "embedded-idp-business";
const MANAGEMENT_CLIENT: &str = "idp-management";

/// Reference-host policy: provisioning is opt-in, restricted by the configured
/// login policy and live tenant checks. Production hosts inject their own admission.
struct DeviceAdmission(bool);
impl TenantDeviceAdmission for DeviceAdmission {
    fn authorize(
        &self,
        _: &str,
        _: &str,
        _: &str,
        _: DeviceAdmissionAction,
        trusted: &TrustedDeviceAdmission,
    ) -> Result<(), AccessError> {
        if self.0 && trusted.registration_scope == "reference_dev" {
            Ok(())
        } else {
            Err(AccessError::Forbidden)
        }
    }
}

/// Reference-only admission intentionally has no business facts. Production
/// hosts must inject their own policy through the Core trait.
struct IdentityOnlyScanAdmission;
impl ScanLoginAdmission for IdentityOnlyScanAdmission {
    fn authorize(
        &self,
        _: &ScanAdmissionRequest,
        context: &TrustedScanHostContext,
    ) -> Result<ScanAdmissionDecision, ScanLoginError> {
        Ok(ScanAdmissionDecision::Allow {
            decision_id: "reference-identity-only".into(),
            policy_revision: "reference-v1".into(),
            valid_until: std::cmp::min(
                context.valid_until(),
                SystemTime::now() + Duration::from_secs(5),
            ),
        })
    }
}

/// A reference host has no terminal business table. It only exposes a stable
/// representation derived from the registered device identity.
struct RegisteredDevicePresentation;
impl ScanTargetPresentationProvider for RegisteredDevicePresentation {
    fn describe(
        &self,
        request: &ScanAdmissionRequest,
        _: &TrustedScanHostContext,
    ) -> Result<ScanTargetPresentation, ScanLoginError> {
        let target = request
            .target
            .as_ref()
            .ok_or(ScanLoginError::InvalidRequest)?;
        Ok(ScanTargetPresentation {
            display_name: format!("Registered device {}", target.device_id),
            identification: target.device_id.clone(),
            context_label: Some("Reference host (no business terminal data)".into()),
            revision: format!(
                "device-{}-key-{}",
                target.device_version, target.key_version
            ),
        })
    }
}

pub struct AppComposition {
    pub router: Router,
    pub scan_cleanup: Option<Arc<dyn TenantDeviceScanLoginService>>,
}
fn signing_key(path: &str) -> Result<RsaSigningKeyConfig, String> {
    let file = std::fs::File::open(path).map_err(|_| {
        "cannot open signing key; prepare EMBEDDED_IDP_APP_SIGNING_KEY_FILE (RSA PKCS#8 DER)"
    })?;
    let metadata = file.metadata().map_err(|_| "cannot inspect signing key")?;
    if !metadata.is_file() || metadata.len() > 65536 {
        return Err("invalid signing key file".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err("signing key must be readable only by its owner (chmod 600)".into());
        }
    }
    let mut bytes = Vec::new();
    file.take(65537)
        .read_to_end(&mut bytes)
        .map_err(|_| "cannot read signing key")?;
    if bytes.len() > 65536 {
        return Err("signing key file is too large".into());
    }
    RsaSigningKeyConfig::from_private_key_der(bytes)
        .map_err(|_| "invalid RSA signing key; require PKCS#8 DER and at least 3072 bits".into())
}

#[cfg(test)]
#[allow(dead_code)] // Shared by integration-test hosts that include this module.
pub fn build_app(config: &EmbeddedIdpAppConfig) -> Result<Router, String> {
    Ok(build_app_with_scan_cleanup(config)?.router)
}

pub fn build_app_with_scan_cleanup(
    config: &EmbeddedIdpAppConfig,
) -> Result<AppComposition, String> {
    let key = signing_key(&config.signing_key_file)?;
    let jwt_config = |management: bool| ProductionJwtConfig {
        issuer: config.embedded_idp.issuer.clone(),
        audience: if management {
            "embedded-idp-management"
        } else {
            BUSINESS_AUDIENCE
        }
        .into(),
        scope: if management {
            "management"
        } else {
            "openid profile email"
        }
        .into(),
        access_token_ttl_secs: config.embedded_idp.auth.access_token_ttl_secs,
        refresh_token_ttl_secs: config.embedded_idp.auth.refresh_token_ttl_secs,
        clock_skew_secs: 0,
    };
    let tokens = || {
        Rs256JwtService::new(jwt_config(false), key.clone(), vec![])
            .map_err(|_| "invalid business token configuration".to_string())
    };
    let management_tokens = Rs256JwtService::new_management(jwt_config(true), key.clone(), vec![])
        .map_err(|_| "invalid management token configuration")?;
    let metadata = tokens()?;
    let jwks = metadata
        .jwks_document()
        .map_err(|_| "cannot publish public signing key")?;
    let jwks = json!({"keys": jwks.keys.into_iter().map(|k| json!({"kid":k.key_id,"kty":k.key_type,"alg":k.algorithm,"use":k.public_key_use,"n":k.modulus,"e":k.exponent})).collect::<Vec<_>>()});
    let etag = metadata.jwks_etag().expect("RS256 metadata has ETag");
    let mode = config.tenancy_mode;
    let adapter = PostgresStorageAdapter::new(config.postgres.clone())
        .map_err(|_| "invalid database configuration")?;
    // Online startup never creates, migrates or repairs identity data.
    let store = PostgresAccessStore::new(adapter.clone(), mode).map_err(|_| "database is not ready: prepare Access schema and bootstrap an administrator in the selected mode")?;
    let catalog = PermissionCatalog::new(vec![]).map_err(|_| "invalid host permission catalog")?;
    store
        .check_readiness(&catalog)
        .map_err(|_| "database readiness check failed")?;
    if config.public_client.client_id == MANAGEMENT_CLIENT
        || config.confidential_client.as_ref().is_some_and(|c| {
            c.client_id == MANAGEMENT_CLIENT || c.client_id == config.public_client.client_id
        })
    {
        return Err("seeded client IDs must be distinct; idp-management is reserved".into());
    }
    seed_public_client(&adapter, &config.public_client)?;
    seed_public_client(
        &adapter,
        &SeedClientConfig {
            client_id: MANAGEMENT_CLIENT.into(),
            client_name: "IdP management console".into(),
            redirect_uri: "http://127.0.0.1/management-callback".into(),
        },
    )?;
    if let Some(c) = &config.confidential_client {
        seed_confidential_client(&adapter, c)?;
    }
    let admin = || {
        CoreAccessAdminService::new(
            mode,
            catalog.clone(),
            store.clone(),
            SystemClock,
            UuidV7IdGenerator,
        )
    };
    let access_admin = Arc::new(admin());
    let accounts = Arc::new(
        CoreAccountSecurityService::new(admin(), config.embedded_idp.auth.clone())
            .map_err(|_| "invalid account security configuration")?,
    );
    let admin_routes = role_admin_router(mode, access_admin.clone())
        .merge(role_binding_admin_router(mode, access_admin.clone()))
        .merge(account_admin_router(mode, access_admin.clone()))
        .merge(account_security_admin_router(accounts.clone()))
        .merge(tenant_management_admin_router(
            mode,
            access_admin.clone(),
            accounts,
        ))
        .merge(security_admin_router(mode, access_admin.clone()))
        .merge(permission_admin_router(mode, access_admin.clone()))
        .merge(access_diagnostic_router(mode, access_admin.clone()))
        .merge(audit_admin_router(mode, access_admin.clone()))
        .merge(tenant_device_admin_router(mode, access_admin.clone()))
        .merge(tenant_session_admin_router(mode, access_admin))
        .merge(client_admin_router(Arc::new(CoreClientAdminService::new(
            admin(),
            PhcClientSecretCodec,
        ))));
    let management = CoreManagementAuthenticationService::new(
        mode,
        config.embedded_idp.auth.clone(),
        TenantLoginEntry {
            client_id: MANAGEMENT_CLIENT.into(),
            login_entry: "management".into(),
            policy: config.management_policy.clone(),
            require_device_proof: false,
        },
        store.clone(),
        management_tokens,
        SecureRefreshTokenGenerator,
        Sha256RefreshTokenDigester,
        SystemClock,
        UuidV7IdGenerator,
    )
    .map_err(|_| "invalid management login configuration")?;
    let auth = || {
        CoreTenantAuthenticationService::new(
            mode,
            config.embedded_idp.auth.clone(),
            TenantLoginEntry {
                client_id: config.public_client.client_id.clone(),
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
    let proofs = || {
        let mut allowed_purposes = [
            DEVICE_REGISTRATION_PURPOSE,
            DEVICE_KEY_ROTATION_PURPOSE,
            TENANT_DEVICE_LOGIN_PURPOSE,
            TENANT_DEVICE_SELECTION_PURPOSE,
            REFRESH_PURPOSE,
            TENANT_OIDC_EXCHANGE_PURPOSE,
            TENANT_DEVICE_HEARTBEAT_PURPOSE,
        ]
        .into_iter()
        .map(|purpose| DeviceProofPurpose::new(purpose).expect("known purpose"))
        .collect::<Vec<_>>();
        if config.scan_login.is_some() {
            allowed_purposes.extend(
                [
                    ScanLoginAction::Create,
                    ScanLoginAction::Claim,
                    ScanLoginAction::Status,
                    ScanLoginAction::Lookup,
                    ScanLoginAction::Cancel,
                    ScanLoginAction::Exchange,
                    ScanLoginAction::Recover,
                    ScanLoginAction::Acknowledge,
                    ScanLoginAction::Abort,
                    ScanLoginAction::CloseOrigin,
                ]
                .into_iter()
                .map(ScanLoginAction::purpose),
            );
        }
        CoreTenantDeviceProofService::new(
            mode,
            TenantDeviceProofConfig {
                client_id: config.public_client.client_id.clone(),
                allowed_purposes,
                challenge_ttl_secs: config.embedded_idp.device.nonce_ttl_secs,
                clock_skew_secs: config.embedded_idp.device.proof_clock_skew_secs,
            },
            store.clone(),
            Ed25519PublicJwkParser,
            RingEd25519Verifier,
            SecureDeviceChallengeGenerator,
            SystemClock,
            UuidV7IdGenerator,
        )
        .map_err(|_| "invalid device proof configuration")
    };
    let devices = Arc::new(CoreTenantDeviceAuthenticationService::new(
        auth()?,
        proofs()?,
    ));
    let oidc = || {
        CoreTenantOidcService::new(
            auth()?,
            config.embedded_idp.issuer.clone(),
            config.embedded_idp.oidc.clone(),
            "openid profile email".into(),
            PhcClientSecretCodec,
        )
        .map_err(|_| "invalid OIDC configuration".to_string())
    };
    let registration = CoreTenantRegistrationService::new(
        mode,
        config.embedded_idp.auth.clone(),
        store.clone(),
        SystemClock,
        UuidV7IdGenerator,
        NumericVerificationCodeGenerator,
    )
    .map_err(|_| "invalid registration configuration")?;
    let email = Arc::new(DefaultVerificationEmailService::new(
        AppEmailSenderProvider::new(config.email_delivery.clone()),
        VerificationEmailConfig {
            from_email: config.email_delivery.from_email.clone(),
            from_name: config.email_delivery.from_name.clone(),
            subject: config.email_delivery.subject.clone(),
        },
    ));
    let management = Arc::new(management);
    let cookie_prefix = format!("idp_{}", config.bind_addr.port());
    let browser_business = browser_session_router(
        Arc::new(auth()?),
        BrowserSessionHttpConfig::new(
            &config.browser_origin,
            &format!("{cookie_prefix}_business"),
            "/auth/browser",
            AccessTokenPurpose::Business,
        )?,
    )?;
    let browser_management = browser_session_router(
        management.clone(),
        BrowserSessionHttpConfig::new(
            &config.browser_origin,
            &format!("{cookie_prefix}_management"),
            "/api/admin/auth/browser",
            AccessTokenPurpose::Management,
        )?,
    )?;
    let scan_service: Option<Arc<dyn TenantDeviceScanLoginService>> = match &config.scan_login {
        None => None,
        Some(scan) => {
            let scan_auth = CoreTenantAuthenticationService::new(
                mode,
                config.embedded_idp.auth.clone(),
                TenantLoginEntry {
                    client_id: config.public_client.client_id.clone(),
                    login_entry: scan.entry.entry_id.clone(),
                    policy: scan.entry.tenant_policy.clone(),
                    require_device_proof: true,
                },
                store.clone(),
                tokens()?,
                SecureRefreshTokenGenerator,
                Sha256RefreshTokenDigester,
                SystemClock,
                UuidV7IdGenerator,
            )
            .map_err(|_| "invalid reference scan-login target authentication")?;
            let cipher = RingScanResultCipher::new(
                ScanResultKeyring::new(
                    scan.result_key_id.clone(),
                    [ScanResultKey::new(
                        scan.result_key_id.clone(),
                        scan.result_key,
                    )],
                )
                .map_err(|_| "invalid reference scan-login result key configuration")?,
            );
            Some(Arc::new(
                CoreTenantDeviceScanLoginService::new(
                    scan.entry.clone(),
                    scan_auth,
                    proofs()?,
                    Arc::new(IdentityOnlyScanAdmission),
                    Arc::new(RegisteredDevicePresentation),
                    Arc::new(cipher),
                )
                .map_err(|_| "invalid reference scan-login service configuration")?,
            ))
        }
    };
    let mut device_routes = tenant_device_router(
        devices.clone(),
        Arc::new(DeviceAdmission(config.allow_device_provisioning)),
        TenantDeviceHttpConfig::new(BUSINESS_AUDIENCE, "/devices/heartbeat")
            .map_err(|_| "invalid device routes")?,
    );
    if config.allow_device_provisioning {
        device_routes = device_routes.layer(Extension(TrustedDeviceAdmission {
            registration_scope: "reference_dev".into(),
            valid_until: SystemTime::now() + Duration::from_secs(365 * 24 * 60 * 60),
        }));
    }
    let public = tenant_device_auth_router(
        devices.clone(),
        TenantDeviceAuthHttpConfig::new(
            BUSINESS_AUDIENCE,
            "/auth/login",
            "/auth/tenant-selection/complete",
            "/auth/refresh",
        )
        .map_err(|_| "invalid auth routes")?,
    )
    .merge(device_routes)
    .merge(
        tenant_registration_router(Arc::new(registration), config.login_policy.clone(), email)
            .map_err(|_| "invalid registration routes")?,
    )
    .merge(tenant_oidc_authorization_router(
        Arc::new(CoreTenantOidcAuthorizationService::new(oidc()?, proofs()?)),
        TenantOidcHttpConfig::new(BUSINESS_AUDIENCE, "/oidc/token")
            .map_err(|_| "invalid OIDC routes")?,
    ))
    .merge(tenant_oidc_resource_router(Arc::new(oidc()?)));
    let public = public.merge(tenant_self_router(
        Arc::new(auth()?),
        Arc::new(CoreAccessService::new(mode, catalog.clone(), store.clone())),
    ));
    let public = if let Some(service) = scan_service.clone() {
        let host = TrustedScanHostContext::new(
            "reference-host".into(),
            SystemTime::now() + Duration::from_secs(365 * 24 * 60 * 60),
        );
        let browser = scan_browser_router(
            service.clone(),
            Arc::new(auth()?),
            BrowserSessionHttpConfig::new(
                &config.browser_origin,
                &format!("{cookie_prefix}_business"),
                "/auth/browser",
                AccessTokenPurpose::Business,
            )?,
        )
        .layer(Extension(host.clone()));
        let device = scan_device_router(
            service,
            ScanDeviceHttpConfig::new(
                BUSINESS_AUDIENCE,
                "/auth/device-scan",
                &config
                    .scan_login
                    .as_ref()
                    .expect("scan service requires scan config")
                    .verification_uri,
            )
            .map_err(|_| "invalid reference scan-login device routes")?,
        )
        .layer(Extension(host));
        public
            .nest("/auth/browser/device-scan", browser)
            .nest("/auth/browser/device-scan/ui", scan_reference_ui_router())
            .nest("/auth/device-scan", device)
    } else {
        public
    };
    let issuer = config.embedded_idp.issuer.trim_end_matches('/');
    let discovery = json!({"issuer":config.embedded_idp.issuer,"authorization_endpoint":format!("{issuer}/oidc/authorize"),"token_endpoint":format!("{issuer}/oidc/token"),"jwks_uri":format!("{issuer}/oidc/jwks"),"userinfo_endpoint":format!("{issuer}/oidc/userinfo"),"introspection_endpoint":format!("{issuer}/oidc/introspect"),"revocation_endpoint":format!("{issuer}/oidc/revoke"),"response_types_supported":["code"],"grant_types_supported":["authorization_code"],"subject_types_supported":["public"],"id_token_signing_alg_values_supported":["RS256"],"code_challenge_methods_supported":["S256"],"scopes_supported":["openid","profile","email"],"token_endpoint_auth_methods_supported":["none","client_secret_basic","client_secret_post"]});
    Ok(AppComposition {
        router: Router::new()
            .route("/healthz", get(|| async { Json(json!({"status":"ok"})) }))
            .route(
                "/readyz",
                get(move || {
                    let store = store.clone();
                    let catalog = catalog.clone();
                    async move {
                        match tokio::task::spawn_blocking(move || store.check_readiness(&catalog))
                            .await
                        {
                            Ok(Ok(())) => (StatusCode::OK, Json(json!({"status":"ready"}))),
                            _ => (
                                StatusCode::SERVICE_UNAVAILABLE,
                                Json(json!({"status":"not_ready"})),
                            ),
                        }
                    }
                }),
            )
            .route(
                "/.well-known/openid-configuration",
                get(move || {
                    let data = discovery.clone();
                    async move { Json(data) }
                }),
            )
            .route(
                "/oidc/jwks",
                get(move || {
                    let data = jwks.clone();
                    let etag = etag.clone();
                    async move {
                        (
                            [
                                ("etag", etag),
                                ("cache-control", "public, max-age=300".into()),
                            ],
                            Json(data),
                        )
                    }
                }),
            )
            .merge(admin_console_router(&config.admin_ui_base_path))
            .nest(
                "/api",
                management_router(management, admin_routes).merge(browser_management),
            )
            .merge(public)
            .merge(browser_business),
        scan_cleanup: scan_service,
    })
}
fn seed_public_client(
    adapter: &PostgresStorageAdapter,
    client: &SeedClientConfig,
) -> Result<(), String> {
    let mut connection = adapter
        .connect()
        .map_err(|error| format!("postgres connect failed: {error:?}"))?;
    insert_client_if_missing(
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
    insert_client_if_missing(
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
fn insert_client_if_missing(
    connection: &mut Client,
    schema_name: &str,
    client_id: &str,
    client_name: &str,
    redirect_uri: &str,
    client_type: &str,
    pkce_required: bool,
    client_secret_hash: Option<String>,
) -> Result<(), String> {
    OidcClient {
        client_id: client_id.into(),
        client_name: client_name.into(),
        redirect_uris: vec![redirect_uri.into()],
        client_type: if client_type == "public_desktop" {
            OidcClientType::PublicDesktop
        } else {
            OidcClientType::ConfidentialWeb
        },
        pkce_required,
        client_secret_hash: client_secret_hash.clone(),
    }
    .validate()
    .map_err(|_| "invalid seeded client configuration")?;
    let sql = format!(
        "insert into {schema_name}.oidc_clients \
         (client_id, client_name, redirect_uris_json, client_type, pkce_required, client_secret_hash, created_at_epoch) \
         values ($1, $2, $3, $4, $5, $6, $7) \
         on conflict (client_id) do nothing"
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
