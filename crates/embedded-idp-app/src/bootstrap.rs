use crate::admin_ui::{admin_console_router, try_admin_console_router};
use crate::composition_config::AppConfig;
use crate::config::{SeedClientConfig, SeedConfidentialClientConfig};
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
    pub scan_cleanup: Vec<crate::scan_cleanup::ScanCleanupJob>,
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

pub fn build_composition(config: &AppConfig) -> Result<AppComposition, String> {
    config.validate_for_startup()?;
    let mut admission_providers = std::collections::BTreeMap::new();
    for provider in &config.device_admission_providers {
        admission_providers.insert(
            provider.id.clone(),
            Arc::new(crate::device_admission::FileAdmission::load(
                &provider.id,
                &provider.grants_file,
            )?),
        );
    }
    let mut scan_ciphers = std::collections::BTreeMap::new();
    for entry in &config.business_entries {
        if let Some(scan) = &entry.scan {
            scan_ciphers.insert(entry.login_entry.clone(), Arc::new(scan.load_cipher()?));
        }
    }
    let management_http = config
        .management
        .browser
        .as_ref()
        .map(|_| config.browser_http_config(&config.management, AccessTokenPurpose::Management))
        .transpose()?;
    let browser_lifetime = management_http
        .as_ref()
        .and_then(|http| http.client_config().session_ttl_secs);
    let reference_business_http = if config.reference_business.is_some() {
        Some(
            config.browser_http_config(
                config
                    .business_entries
                    .first()
                    .ok_or("missing reference business entry")?,
                AccessTokenPurpose::Business,
            )?,
        )
    } else {
        None
    };
    let key = signing_key(&config.signing_key_file)?;
    let jwt_config = |management: bool, browser: bool| ProductionJwtConfig {
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
        access_token_ttl_secs: if browser {
            browser_lifetime.map_or(config.embedded_idp.auth.access_token_ttl_secs, |ttl| {
                config.embedded_idp.auth.access_token_ttl_secs.min(ttl - 1)
            })
        } else {
            config.embedded_idp.auth.access_token_ttl_secs
        },
        refresh_token_ttl_secs: if browser {
            browser_lifetime.map_or(config.embedded_idp.auth.refresh_token_ttl_secs, |ttl| {
                config.embedded_idp.auth.refresh_token_ttl_secs.min(ttl)
            })
        } else {
            config.embedded_idp.auth.refresh_token_ttl_secs
        },
        clock_skew_secs: 0,
    };
    let tokens = |browser: bool| {
        Rs256JwtService::new(jwt_config(false, browser), key.clone(), vec![])
            .map_err(|_| "invalid business token configuration".to_string())
    };
    // Preserve legacy token/key validation before any reference client seed.
    let business_metadata = if config.reference_business.is_some()
        || config.business_entries.iter().any(|e| e.oidc_enabled)
    {
        let metadata = tokens(false)?;
        let jwks = metadata
            .jwks_document()
            .map_err(|_| "cannot publish public signing key")?;
        let jwks = json!({"keys": jwks.keys.into_iter().map(|k| json!({"kid":k.key_id,"kty":k.key_type,"alg":k.algorithm,"use":k.public_key_use,"n":k.modulus,"e":k.exponent})).collect::<Vec<_>>()});
        Some((jwks, metadata.jwks_etag().expect("RS256 metadata has ETag")))
    } else {
        None
    };
    let mode = config.tenancy_mode;
    let adapter = PostgresStorageAdapter::new(config.postgres.clone())
        .map_err(|_| "invalid database configuration")?;
    // Online startup never creates, migrates or repairs identity data.
    let store = PostgresAccessStore::new(adapter.clone(), mode).map_err(|_| "database is not ready: prepare Access schema and bootstrap an administrator in the selected mode")?;
    let catalog = PermissionCatalog::new(vec![]).map_err(|_| "invalid host permission catalog")?;
    store
        .check_readiness(&catalog)
        .map_err(|_| "database readiness check failed")?;
    if let Some(reference) = &config.reference_business {
        if reference.public_client.client_id == MANAGEMENT_CLIENT
            || reference.confidential_client.as_ref().is_some_and(|c| {
                c.client_id == MANAGEMENT_CLIENT || c.client_id == reference.public_client.client_id
            })
        {
            return Err("seeded client IDs must be distinct; idp-management is reserved".into());
        }
        seed_public_client(&adapter, &reference.public_client)?;
        seed_public_client(
            &adapter,
            &SeedClientConfig {
                client_id: MANAGEMENT_CLIENT.into(),
                client_name: "IdP management console".into(),
                redirect_uri: "http://127.0.0.1/management-callback".into(),
            },
        )?;
        if let Some(c) = &reference.confidential_client {
            seed_confidential_client(&adapter, c)?;
        }
    } else {
        check_entry_references(config, &store)?;
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
    let management_auth = |browser: bool| {
        let auth = CoreManagementAuthenticationService::new(
            mode,
            config.embedded_idp.auth.clone(),
            TenantLoginEntry {
                client_id: config.management.client_id.clone(),
                login_entry: config.management.login_entry.clone(),
                policy: config.management.policy.clone(),
                require_device_proof: config.management.require_device_proof,
            },
            store.clone(),
            Rs256JwtService::new_management(jwt_config(true, browser), key.clone(), vec![])
                .map_err(|_| "invalid management token configuration")?,
            SecureRefreshTokenGenerator,
            Sha256RefreshTokenDigester,
            SystemClock,
            UuidV7IdGenerator,
        )
        .map_err(|_| "invalid management login configuration")?;
        match browser_lifetime.filter(|_| config.reference_business.is_none()) {
            Some(ttl) => auth
                .with_restricted_browser_isolation(ttl)
                .map_err(|_| "invalid management browser isolation"),
            None => Ok(auth),
        }
    };
    let management = Arc::new(management_auth(false)?);
    let mut management_routes = management_router(management.clone(), admin_routes);
    if let Some(http) = &management_http {
        let browser_management_service: Arc<dyn BrowserSessionService> = match browser_lifetime {
            Some(ttl) => Arc::new(
                management_auth(true)?
                    .into_restricted_browser(ttl)
                    .map_err(|_| "invalid management browser lifetime")?,
            ),
            None => management,
        };
        management_routes = management_routes.merge(browser_session_router(
            browser_management_service,
            http.clone(),
        )?);
    }
    let mut router = health_router(store.clone(), catalog.clone());
    router = if config.management.mount_prefix.is_empty() {
        router.merge(management_routes)
    } else {
        router.nest(&config.management.mount_prefix, management_routes)
    };
    if let Some(base_path) = &config.management.ui_base_path {
        let browser_config = management_http
            .as_ref()
            .ok_or("management UI requires browser configuration")?
            .client_config();
        let api_base = if config.management.mount_prefix.is_empty() {
            "/"
        } else {
            &config.management.mount_prefix
        };
        let ui = if config.reference_business.is_some() {
            admin_console_router(base_path, browser_config)
        } else {
            try_admin_console_router(base_path, api_base, browser_config)?
        };
        router = router.merge(ui);
    }
    let Some(reference) = &config.reference_business else {
        let mut scan_cleanup = Vec::new();
        let mut oidc_entries = std::collections::BTreeMap::new();
        let mut oidc_profiles = std::collections::BTreeMap::new();
        for entry in &config.business_entries {
            let (routes, oidc, cleanup) = ordinary_business_routes(
                config,
                entry,
                &store,
                &catalog,
                &key,
                &admission_providers,
                &scan_ciphers,
            )?;
            if let Some(job) = cleanup {
                scan_cleanup.push(job);
            }
            if let Some(oidc) = oidc {
                oidc_entries.insert(entry.client_id.clone(), oidc);
                let (audience, path) = entry
                    .device
                    .as_ref()
                    .map(|d| (d.audience.as_str(), d.paths.oidc_token.as_str()))
                    .unwrap_or((BUSINESS_AUDIENCE, "/oidc/token"));
                oidc_profiles.insert(
                    entry.client_id.clone(),
                    TenantOidcHttpConfig::new(audience, path)
                        .map_err(|_| "invalid OIDC device profile")?,
                );
            }
            router = if entry.mount_prefix.is_empty() {
                router.merge(routes)
            } else {
                router.nest(&entry.mount_prefix, routes)
            };
        }
        if !oidc_entries.is_empty() {
            let dispatcher = Arc::new(crate::oidc_dispatch::OidcDispatch {
                entries: oidc_entries,
                tokens: tokens(false)?,
            });
            let (jwks, etag) = business_metadata.ok_or("missing OIDC metadata")?;
            router = router
                .merge(tenant_oidc_authorization_router_with_profiles(
                    dispatcher.clone(),
                    oidc_profiles,
                ))
                .merge(tenant_oidc_protocol_resource_router(dispatcher))
                .merge(oidc_metadata_router(config, jwks, etag));
        }
        return Ok(AppComposition {
            router,
            scan_cleanup,
        });
    };
    // The old reference business composition remains opt-in through its legacy input.
    let entry = config
        .business_entries
        .first()
        .ok_or("missing reference business entry")?;
    let business_http = reference_business_http.ok_or("missing reference browser configuration")?;
    let (jwks, etag) = business_metadata.ok_or("missing reference token metadata")?;
    let auth = |browser: bool| {
        CoreTenantAuthenticationService::new(
            mode,
            config.embedded_idp.auth.clone(),
            TenantLoginEntry {
                client_id: reference.public_client.client_id.clone(),
                login_entry: entry.login_entry.clone(),
                policy: entry.policy.clone(),
                require_device_proof: false,
            },
            store.clone(),
            tokens(browser)?,
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
        if reference.scan_login.is_some() {
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
                client_id: reference.public_client.client_id.clone(),
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
        auth(false)?,
        proofs()?,
    ));
    let oidc = || {
        CoreTenantOidcService::new(
            auth(false)?,
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
    let email_config = config
        .email_delivery
        .as_ref()
        .ok_or("missing reference email configuration")?;
    let email = Arc::new(DefaultVerificationEmailService::new(
        AppEmailSenderProvider::new(email_config.clone()),
        VerificationEmailConfig {
            from_email: email_config.from_email.clone(),
            from_name: email_config.from_name.clone(),
            subject: email_config.subject.clone(),
        },
    ));
    let browser_business_service: Arc<dyn BrowserSessionService> = match browser_lifetime {
        Some(ttl) => Arc::new(
            auth(true)?
                .into_restricted_browser(ttl)
                .map_err(|_| "invalid browser lifetime")?,
        ),
        None => Arc::new(auth(false)?),
    };
    let browser_identity: Arc<dyn BrowserSessionIdentityService> = match browser_lifetime {
        Some(ttl) => Arc::new(
            auth(true)?
                .into_restricted_browser(ttl)
                .map_err(|_| "invalid browser lifetime")?,
        ),
        None => Arc::new(auth(false)?),
    };
    let browser_business = browser_session_router(browser_business_service, business_http.clone())?;
    let scan_service: Option<Arc<dyn TenantDeviceScanLoginService>> = match &reference.scan_login {
        None => None,
        Some(scan) => {
            let scan_auth = CoreTenantAuthenticationService::new(
                mode,
                config.embedded_idp.auth.clone(),
                TenantLoginEntry {
                    client_id: reference.public_client.client_id.clone(),
                    login_entry: scan.entry.entry_id.clone(),
                    policy: scan.entry.tenant_policy.clone(),
                    require_device_proof: true,
                },
                store.clone(),
                tokens(false)?,
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
        Arc::new(DeviceAdmission(reference.allow_device_provisioning)),
        TenantDeviceHttpConfig::new(BUSINESS_AUDIENCE, "/devices/heartbeat")
            .map_err(|_| "invalid device routes")?,
    );
    if reference.allow_device_provisioning {
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
        tenant_registration_router(Arc::new(registration), entry.policy.clone(), email)
            .map_err(|_| "invalid registration routes")?,
    )
    .merge(tenant_oidc_authorization_router(
        Arc::new(CoreTenantOidcAuthorizationService::new(oidc()?, proofs()?)),
        TenantOidcHttpConfig::new(BUSINESS_AUDIENCE, "/oidc/token")
            .map_err(|_| "invalid OIDC routes")?,
    ))
    .merge(tenant_oidc_resource_router(Arc::new(oidc()?)));
    let public = public.merge(tenant_self_router(
        Arc::new(auth(false)?),
        Arc::new(CoreAccessService::new(mode, catalog.clone(), store.clone())),
    ));
    let public = if let Some(service) = scan_service.clone() {
        let host = TrustedScanHostContext::new(
            "reference-host".into(),
            SystemTime::now() + Duration::from_secs(365 * 24 * 60 * 60),
        );
        let browser =
            try_scan_browser_router(service.clone(), browser_identity, business_http.clone())?
                .layer(Extension(host.clone()));
        let device = scan_device_router(
            service,
            ScanDeviceHttpConfig::new_with_transport_policy(
                BUSINESS_AUDIENCE,
                "/auth/device-scan",
                &reference
                    .scan_login
                    .as_ref()
                    .expect("scan service requires scan config")
                    .verification_uri,
                &config.transport_policy,
            )
            .map_err(|_| "invalid reference scan-login device routes")?,
        )
        .layer(Extension(host));
        public
            .nest("/auth/browser/device-scan", browser)
            .nest(
                "/auth/browser/device-scan/ui",
                scan_reference_ui_router(business_http.client_config()),
            )
            .nest("/auth/device-scan", device)
    } else {
        public
    };
    Ok(AppComposition {
        router: router
            .merge(oidc_metadata_router(config, jwks, etag))
            .merge(public)
            .merge(browser_business),
        scan_cleanup: scan_service
            .into_iter()
            .map(|service| crate::scan_cleanup::ScanCleanupJob {
                service,
                host_scope: "reference-host".into(),
                interval_secs: 30,
                batch_size: 100,
            })
            .collect(),
    })
}

fn oidc_metadata_router(config: &AppConfig, jwks: serde_json::Value, etag: String) -> Router {
    let issuer = config.embedded_idp.issuer.trim_end_matches('/');
    let discovery = json!({"issuer":config.embedded_idp.issuer,"authorization_endpoint":format!("{issuer}/oidc/authorize"),"token_endpoint":format!("{issuer}/oidc/token"),"jwks_uri":format!("{issuer}/oidc/jwks"),"userinfo_endpoint":format!("{issuer}/oidc/userinfo"),"introspection_endpoint":format!("{issuer}/oidc/introspect"),"revocation_endpoint":format!("{issuer}/oidc/revoke"),"response_types_supported":["code"],"grant_types_supported":["authorization_code"],"subject_types_supported":["public"],"id_token_signing_alg_values_supported":["RS256"],"code_challenge_methods_supported":["S256"],"scopes_supported":["openid","profile","email"],"token_endpoint_auth_methods_supported":["none","client_secret_basic","client_secret_post"]});
    Router::new()
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
}

fn ordinary_business_routes(
    config: &AppConfig,
    entry: &crate::composition_config::EntryConfig,
    store: &PostgresAccessStore,
    catalog: &PermissionCatalog,
    key: &RsaSigningKeyConfig,
    admission_providers: &std::collections::BTreeMap<
        String,
        Arc<crate::device_admission::FileAdmission>,
    >,
    scan_ciphers: &std::collections::BTreeMap<String, Arc<RingScanResultCipher>>,
) -> Result<
    (
        Router,
        Option<crate::oidc_dispatch::OidcEntry>,
        Option<crate::scan_cleanup::ScanCleanupJob>,
    ),
    String,
> {
    let browser_http = entry
        .browser
        .as_ref()
        .map(|_| config.browser_http_config(entry, AccessTokenPurpose::Business))
        .transpose()?;
    let browser_ttl = browser_http
        .as_ref()
        .and_then(|http| http.client_config().session_ttl_secs);
    let auth_for = |browser: bool, require_device_proof: bool| {
        let ttl = if browser { browser_ttl } else { None };
        let tokens = Rs256JwtService::new(
            ProductionJwtConfig {
                issuer: config.embedded_idp.issuer.clone(),
                audience: BUSINESS_AUDIENCE.into(),
                scope: "openid profile email".into(),
                access_token_ttl_secs: ttl
                    .map_or(config.embedded_idp.auth.access_token_ttl_secs, |ttl| {
                        config.embedded_idp.auth.access_token_ttl_secs.min(ttl - 1)
                    }),
                refresh_token_ttl_secs: ttl
                    .map_or(config.embedded_idp.auth.refresh_token_ttl_secs, |ttl| {
                        config.embedded_idp.auth.refresh_token_ttl_secs.min(ttl)
                    }),
                clock_skew_secs: 0,
            },
            key.clone(),
            vec![],
        )
        .map_err(|_| "invalid business token configuration")?;
        let auth = CoreTenantAuthenticationService::new(
            config.tenancy_mode,
            config.embedded_idp.auth.clone(),
            TenantLoginEntry {
                client_id: entry.client_id.clone(),
                login_entry: entry.login_entry.clone(),
                policy: entry.policy.clone(),
                require_device_proof,
            },
            store.clone(),
            tokens,
            SecureRefreshTokenGenerator,
            Sha256RefreshTokenDigester,
            SystemClock,
            UuidV7IdGenerator,
        )
        .map_err(|_| "invalid business login configuration".to_string())?;
        match browser_ttl {
            Some(ttl) => auth
                .with_restricted_browser_isolation(ttl)
                .map_err(|_| "invalid business browser isolation".to_string()),
            None => Ok(auth),
        }
    };
    let auth = |browser| auth_for(browser, entry.require_device_proof);
    let proofs = || {
        let mut purposes = vec![
            DEVICE_REGISTRATION_PURPOSE,
            DEVICE_KEY_ROTATION_PURPOSE,
            TENANT_DEVICE_LOGIN_PURPOSE,
            TENANT_DEVICE_SELECTION_PURPOSE,
            REFRESH_PURPOSE,
            TENANT_DEVICE_HEARTBEAT_PURPOSE,
        ];
        if entry.oidc_enabled {
            purposes.push(TENANT_OIDC_EXCHANGE_PURPOSE);
        }
        let mut allowed_purposes = purposes
            .into_iter()
            .map(|p| DeviceProofPurpose::new(p).expect("known purpose"))
            .collect::<Vec<_>>();
        if entry.scan.is_some() {
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
            config.tenancy_mode,
            TenantDeviceProofConfig {
                client_id: entry.client_id.clone(),
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
        .map_err(|_| "invalid entry device proof configuration")
    };
    let service = Arc::new(auth(false)?);
    let logout = CoreTenantOidcService::new(
        auth(false)?,
        config.embedded_idp.issuer.clone(),
        config.embedded_idp.oidc.clone(),
        "openid profile email".into(),
        PhcClientSecretCodec,
    )
    .map_err(|_| "invalid business logout configuration")?;
    let oidc = if entry.oidc_enabled {
        let protocol = || {
            CoreTenantOidcService::new(
                auth(false)?,
                config.embedded_idp.issuer.clone(),
                config.embedded_idp.oidc.clone(),
                "openid profile email".into(),
                PhcClientSecretCodec,
            )
            .map(|s| s.with_required_s256_pkce())
            .map_err(|_| "invalid business OIDC configuration".to_string())
        };
        let authorization: Arc<dyn TenantOidcAuthorizationService> = if entry.device.is_some() {
            Arc::new(CoreTenantOidcAuthorizationService::new(
                protocol()?,
                proofs()?,
            ))
        } else {
            Arc::new(protocol()?)
        };
        Some(crate::oidc_dispatch::OidcEntry {
            authorization,
            resource: Arc::new(protocol()?),
        })
    } else {
        None
    };
    let mut routes = if let Some(device) = &entry.device {
        let devices = Arc::new(CoreTenantDeviceAuthenticationService::new(
            auth(false)?,
            proofs()?,
        ));
        let admission = admission_providers
            .get(&device.admission_provider)
            .ok_or("missing device admission provider")?
            .clone();
        let device_routes = tenant_device_router(
            devices.clone(),
            admission.clone(),
            TenantDeviceHttpConfig::new(&device.audience, &device.paths.heartbeat)
                .map_err(|_| "invalid device routes")?,
        )
        .layer(axum::middleware::from_fn_with_state(
            crate::device_admission::AdmissionHttp {
                provider: admission,
                provider_id: device.admission_provider.clone(),
                client: entry.client_id.clone(),
                provision_path: format!("{}/devices/provision", entry.mount_prefix),
                result_path: format!("{}/devices/registration-result", entry.mount_prefix),
            },
            crate::device_admission::inject,
        ));
        tenant_device_auth_router(
            devices,
            TenantDeviceAuthHttpConfig::new(
                &device.audience,
                &device.paths.login,
                &device.paths.selection,
                &device.paths.refresh,
            )
            .map_err(|_| "invalid device auth routes")?,
        )
        .merge(device_routes)
    } else {
        tenant_auth_router(service.clone()).merge(tenant_refresh_router(service.clone()))
    };
    routes = routes
        .merge(tenant_logout_router(Arc::new(logout)))
        .merge(tenant_self_router(
            service,
            Arc::new(CoreAccessService::new(
                config.tenancy_mode,
                catalog.clone(),
                store.clone(),
            )),
        ));
    let mut cleanup = None;
    if let Some(scan) = &entry.scan {
        let service: Arc<dyn TenantDeviceScanLoginService> = Arc::new(
            CoreTenantDeviceScanLoginService::new(
                scan.entry(entry)?,
                auth_for(false, true)?,
                proofs()?,
                Arc::new(IdentityOnlyScanAdmission),
                Arc::new(RegisteredDevicePresentation),
                scan_ciphers
                    .get(&entry.login_entry)
                    .ok_or("missing scan result cipher")?
                    .clone(),
            )
            .map_err(|_| "invalid entry scan service configuration")?,
        );
        let identity: Arc<dyn BrowserSessionIdentityService> = match browser_ttl {
            Some(ttl) => Arc::new(
                auth(true)?
                    .into_restricted_browser(ttl)
                    .map_err(|_| "invalid scan browser lifetime")?,
            ),
            None => Arc::new(auth(false)?),
        };
        let http = browser_http
            .as_ref()
            .ok_or("scan requires browser configuration")?;
        let browser = try_scan_browser_router(service.clone(), identity, http.clone())?.layer(
            axum::middleware::from_fn_with_state(
                scan.host_scope.clone(),
                crate::scan_composition::host_context,
            ),
        );
        let device = scan_device_router(
            service.clone(),
            ScanDeviceHttpConfig::new_with_transport_policy(
                &scan.audience,
                &scan.device_prefix,
                &scan.verification_uri,
                &config.transport_policy,
            )
            .map_err(|_| "invalid scan device routes")?,
        )
        .layer(axum::middleware::from_fn_with_state(
            scan.host_scope.clone(),
            crate::scan_composition::host_context,
        ));
        routes = routes
            .nest("/auth/browser/device-scan", browser)
            .nest(
                "/auth/browser/device-scan/ui",
                crate::scan_ui::scan_reference_ui_router_for_entry(
                    http.client_config(),
                    &entry.mount_prefix,
                ),
            )
            .nest("/auth/device-scan", device);
        cleanup = Some(crate::scan_cleanup::ScanCleanupJob {
            service,
            host_scope: scan.host_scope.clone(),
            interval_secs: scan.cleanup.interval_secs,
            batch_size: scan.cleanup.batch_size,
        });
    }
    if let Some(http) = browser_http {
        let browser_service: Arc<dyn BrowserSessionService> = match browser_ttl {
            Some(ttl) => Arc::new(
                auth(true)?
                    .into_restricted_browser(ttl)
                    .map_err(|_| "invalid browser lifetime")?,
            ),
            None => Arc::new(auth(false)?),
        };
        routes = routes.merge(browser_session_router(browser_service, http)?);
    }
    if entry.registration_enabled {
        let mut registration_config = config.embedded_idp.auth.clone();
        registration_config.allow_local_registration = true;
        let registration = CoreTenantRegistrationService::new(
            config.tenancy_mode,
            registration_config,
            store.clone(),
            SystemClock,
            UuidV7IdGenerator,
            NumericVerificationCodeGenerator,
        )
        .map_err(|_| "invalid registration configuration")?;
        let email_config = config
            .email_delivery
            .as_ref()
            .ok_or("registration requires runtime.email")?;
        let email = Arc::new(DefaultVerificationEmailService::new(
            AppEmailSenderProvider::new(email_config.clone()),
            VerificationEmailConfig {
                from_email: email_config.from_email.clone(),
                from_name: email_config.from_name.clone(),
                subject: email_config.subject.clone(),
            },
        ));
        routes = routes.merge(
            tenant_registration_router(Arc::new(registration), entry.policy.clone(), email)
                .map_err(|_| "invalid registration routes")?,
        );
    }
    Ok((routes, oidc, cleanup))
}

fn health_router(store: PostgresAccessStore, catalog: PermissionCatalog) -> Router {
    Router::new()
        .route("/healthz", get(|| async { Json(json!({"status":"ok"})) }))
        .route(
            "/readyz",
            get(move || {
                let store = store.clone();
                let catalog = catalog.clone();
                async move {
                    match tokio::task::spawn_blocking(move || store.check_readiness(&catalog)).await
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
}

fn check_entry_references(config: &AppConfig, store: &PostgresAccessStore) -> Result<(), String> {
    let entries = std::iter::once(&config.management).chain(config.business_entries.iter());
    let entries = entries.collect::<Vec<_>>();
    let tenants = entries
        .iter()
        .filter_map(|entry| match &entry.policy {
            LoginTenantPolicy::Fixed { tenant_id } => Some(tenant_id.clone()),
            LoginTenantPolicy::ChooseAfterAuthentication => None,
        })
        .collect::<Vec<_>>();
    store.auth_transaction(config.tenancy_mode, |tx| {
        tx.lock_tenants(&tenants)?;
        for tenant in &tenants {
            if tx.tenant(tenant)?.is_none() {
                return Err(AccessError::InvalidInput("entry.tenant_missing").into());
            }
        }
        let mut clients = entries.iter().map(|entry| entry.client_id.as_str()).collect::<Vec<_>>();
        clients.sort_unstable();
        clients.dedup();
        for client_id in clients {
            let client = tx.oidc_client(client_id)?
                .ok_or(AccessError::InvalidInput("entry.client_missing"))?;
            client.validate().map_err(|_| AccessError::InvalidInput("entry.client_invalid"))?;
            if client_id == config.management.client_id && (client.client_type != OidcClientType::PublicDesktop || client.client_secret_hash.is_some()) {
                return Err(AccessError::InvalidInput("management.client_configuration").into());
            }
        }
        Ok(())
    }).map_err(|_| "entry reference validation failed; prepare the configured tenants and clients explicitly".into())
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
