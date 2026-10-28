use crate::account_security_config::AccountSecurityConfig;
use crate::config::{
    EmailDeliveryConfig, EmailDeliveryMode, EmbeddedIdpAppConfig, ReferenceScanLoginConfig,
    SeedClientConfig, SeedConfidentialClientConfig, SmtpEmailDeliveryConfig, SmtpTlsMode,
};
use embedded_idp_axum::{BrowserSessionHttpConfig, HttpTransportPolicy};
use embedded_idp_core::{
    access::{LoginTenantPolicy, TenancyMode},
    AccessTokenPurpose, AuthConfig, DeviceConfig, EmbeddedIdpConfig, OidcConfig,
};
use embedded_idp_storage_postgres::{DbPoolConfig, PgConnectionConfig, PgStorageConfig, PgTlsMode};
use serde::{
    de::{self, IntoDeserializer, MapAccess, SeqAccess, Visitor},
    Deserialize,
};
use std::{
    collections::BTreeSet,
    env, fs,
    io::Read,
    net::SocketAddr,
    path::{Path, PathBuf},
};

#[derive(Clone)]
pub(crate) struct BrowserConfig {
    pub cookie_name: String,
    pub development_session_ttl_secs: Option<u64>,
}
#[derive(Clone)]
pub(crate) struct EntryConfig {
    pub login_entry: String,
    pub client_id: String,
    pub policy: LoginTenantPolicy,
    pub require_device_proof: bool,
    pub mount_prefix: String,
    pub browser: Option<BrowserConfig>,
    pub ui_base_path: Option<String>,
    pub registration_enabled: bool,
    pub oidc_enabled: bool,
    pub device: Option<DeviceEntryConfig>,
    pub scan: Option<crate::scan_composition::ScanConfig>,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DeviceEntryConfig {
    pub admission_provider: String,
    pub profile_provider: String,
    pub audience: String,
    pub paths: DevicePaths,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DevicePaths {
    pub login: String,
    pub selection: String,
    pub refresh: String,
    pub heartbeat: String,
    pub oidc_token: String,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AdmissionProviderReference {
    pub id: String,
    pub grants_file: String,
}
#[derive(Clone)]
pub(crate) struct ReferenceBusinessConfig {
    pub public_client: SeedClientConfig,
    pub confidential_client: Option<SeedConfidentialClientConfig>,
    pub allow_device_provisioning: bool,
    pub scan_login: Option<ReferenceScanLoginConfig>,
}
#[derive(Clone)]
pub(crate) struct AppConfig {
    pub abuse: embedded_idp_core::AdmissionPolicy,
    pub bind_addr: SocketAddr,
    pub browser_origin: Option<String>,
    pub transport_policy: HttpTransportPolicy,
    pub development_session_ttl_secs: u64,
    pub embedded_idp: EmbeddedIdpConfig,
    pub postgres: PgStorageConfig,
    pub email_delivery: Option<EmailDeliveryConfig>,
    pub account_security: Option<AccountSecurityConfig>,
    pub tenancy_mode: TenancyMode,
    pub signing_key_file: String,
    pub management: EntryConfig,
    pub business_entries: Vec<EntryConfig>,
    pub reference_business: Option<ReferenceBusinessConfig>,
    pub device_admission_providers: Vec<AdmissionProviderReference>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    version: u64,
    runtime: Runtime,
    management: Management,
    business_entries: Vec<Business>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Runtime {
    #[serde(default)]
    abuse: crate::abuse_config::AbuseConfig,
    #[serde(default)]
    device_admission_providers: Vec<AdmissionProviderReference>,
    tenancy_mode: String,
    bind_addr: String,
    issuer: String,
    signing_key_file: String,
    postgres: Postgres,
    #[serde(default)]
    http: Http,
    #[serde(default)]
    auth: Auth,
    #[serde(default)]
    email: Option<Email>,
    #[serde(default)]
    account_security: Option<AccountSecurityConfig>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Postgres {
    connection: Connection,
    #[serde(default)]
    pool: Pool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Connection {
    uri_ref: SecretRef,
    schema_name: String,
    tls_mode: String,
    #[serde(default)]
    tls_ca_cert_path: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SecretRef {
    #[serde(default)]
    env: Option<String>,
    #[serde(default)]
    file: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Pool {
    #[serde(default = "app_name")]
    application_name: String,
    #[serde(default = "ten")]
    max_connections: u32,
    #[serde(default = "five")]
    connect_timeout_secs: u64,
}
impl Default for Pool {
    fn default() -> Self {
        Self {
            application_name: app_name(),
            max_connections: ten(),
            connect_timeout_secs: five(),
        }
    }
}
fn app_name() -> String {
    "embedded-idp-app".into()
}
fn ten() -> u32 {
    10
}
fn five() -> u64 {
    5
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Http {
    #[serde(default)]
    browser_origin: Option<String>,
    #[serde(default = "default_transport")]
    transport_policy: String,
    #[serde(default = "nine_hundred")]
    development_session_ttl_secs: u64,
}
impl Default for Http {
    fn default() -> Self {
        Self {
            browser_origin: None,
            transport_policy: default_transport(),
            development_session_ttl_secs: nine_hundred(),
        }
    }
}
fn default_transport() -> String {
    "default".into()
}
fn nine_hundred() -> u64 {
    900
}
fn day() -> u64 {
    86400
}
fn week() -> u64 {
    604800
}
fn eight() -> usize {
    8
}
fn one_twenty_eight() -> usize {
    128
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Auth {
    #[serde(default = "nine_hundred")]
    access_token_ttl_secs: u64,
    #[serde(default = "day")]
    refresh_token_ttl_secs: u64,
    #[serde(default = "week")]
    session_ttl_secs: u64,
    #[serde(default = "nine_hundred")]
    verification_code_ttl_secs: u64,
    #[serde(default = "eight")]
    password_min_length: usize,
    #[serde(default = "one_twenty_eight")]
    password_max_length: usize,
}
impl Default for Auth {
    fn default() -> Self {
        Self {
            access_token_ttl_secs: 900,
            refresh_token_ttl_secs: 86400,
            session_ttl_secs: 604800,
            verification_code_ttl_secs: 900,
            password_min_length: 8,
            password_max_length: 128,
        }
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Management {
    login_entry: String,
    client_id: String,
    tenant_policy: Policy,
    mount_prefix: String,
    #[serde(default)]
    browser: Option<Browser>,
    #[serde(default)]
    ui: Option<Ui>,
    #[serde(default)]
    require_device_proof: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Business {
    login_entry: String,
    client_id: String,
    tenant_policy: Policy,
    mount_prefix: String,
    #[serde(default)]
    browser: Option<Browser>,
    #[serde(default)]
    require_device_proof: bool,
    #[serde(default)]
    registration_enabled: bool,
    #[serde(default)]
    oidc: Option<OidcProtocol>,
    #[serde(default)]
    device: Option<DeviceEntryConfig>,
    #[serde(default)]
    scan: Option<crate::scan_composition::ScanConfig>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OidcProtocol {
    enabled: bool,
}
#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Policy {
    Fixed { tenant_id: String },
    Choose,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Browser {
    cookie_name: String,
    #[serde(default)]
    development_session_ttl_secs: Option<u64>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Ui {
    base_path: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Email {
    mode: String,
    #[serde(default)]
    sendmail_command: Option<String>,
    #[serde(default)]
    smtp: Option<Smtp>,
    #[serde(default)]
    from_email: Option<String>,
    #[serde(default)]
    from_name: Option<String>,
    #[serde(default)]
    subject: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Smtp {
    #[serde(default)]
    host: Option<String>,
    #[serde(default)]
    port: Option<u16>,
    #[serde(default)]
    tls_mode: Option<String>,
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    password_ref: Option<SecretRef>,
}

// A recursive visitor catches duplicate keys even where serde Option normally accepts repeated null.
pub(crate) struct Unique(pub(crate) serde_json::Value);
impl<'de> Deserialize<'de> for Unique {
    fn deserialize<D: de::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_any(UniqueVisitor)
    }
}
struct UniqueVisitor;
impl<'de> Visitor<'de> for UniqueVisitor {
    type Value = Unique;
    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("JSON value")
    }
    fn visit_bool<E: de::Error>(self, v: bool) -> Result<Unique, E> {
        Ok(Unique(v.into()))
    }
    fn visit_i64<E: de::Error>(self, v: i64) -> Result<Unique, E> {
        Ok(Unique(v.into()))
    }
    fn visit_u64<E: de::Error>(self, v: u64) -> Result<Unique, E> {
        Ok(Unique(v.into()))
    }
    fn visit_f64<E: de::Error>(self, v: f64) -> Result<Unique, E> {
        serde_json::Number::from_f64(v)
            .map(|n| Unique(n.into()))
            .ok_or_else(|| E::custom("invalid number"))
    }
    fn visit_str<E: de::Error>(self, v: &str) -> Result<Unique, E> {
        Ok(Unique(v.into()))
    }
    fn visit_string<E: de::Error>(self, v: String) -> Result<Unique, E> {
        Ok(Unique(v.into()))
    }
    fn visit_unit<E: de::Error>(self) -> Result<Unique, E> {
        Ok(Unique(serde_json::Value::Null))
    }
    fn visit_none<E: de::Error>(self) -> Result<Unique, E> {
        self.visit_unit()
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<Unique, A::Error> {
        let mut v = Vec::new();
        while let Some(x) = a.next_element::<Unique>()? {
            v.push(x.0)
        }
        Ok(Unique(v.into()))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut a: A) -> Result<Unique, A::Error> {
        let mut m = serde_json::Map::new();
        while let Some(k) = a.next_key::<String>()? {
            if m.contains_key(&k) {
                return Err(de::Error::custom("duplicate key"));
            }
            let v = a.next_value::<Unique>()?;
            m.insert(k, v.0);
        }
        Ok(Unique(m.into()))
    }
}

impl AppConfig {
    pub(crate) fn from_legacy(c: &EmbeddedIdpAppConfig) -> Self {
        let port = c.bind_addr.port();
        Self {
            abuse: embedded_idp_core::AdmissionPolicy::default(),
            bind_addr: c.bind_addr,
            browser_origin: Some(c.browser_origin.clone()),
            transport_policy: c.transport_policy.clone(),
            development_session_ttl_secs: c.development_session_ttl_secs,
            embedded_idp: c.embedded_idp.clone(),
            postgres: c.postgres.clone(),
            email_delivery: Some(c.email_delivery.clone()),
            account_security: None,
            tenancy_mode: c.tenancy_mode,
            signing_key_file: c.signing_key_file.clone(),
            management: EntryConfig {
                login_entry: "management".into(),
                client_id: "idp-management".into(),
                policy: c.management_policy.clone(),
                require_device_proof: false,
                mount_prefix: "/api".into(),
                browser: Some(BrowserConfig {
                    cookie_name: format!("idp_{port}_management"),
                    development_session_ttl_secs: None,
                }),
                ui_base_path: Some(c.admin_ui_base_path.clone()),
                registration_enabled: false,
                oidc_enabled: false,
                device: None,
                scan: None,
            },
            business_entries: vec![EntryConfig {
                login_entry: "business".into(),
                client_id: c.public_client.client_id.clone(),
                policy: c.login_policy.clone(),
                require_device_proof: false,
                mount_prefix: String::new(),
                browser: Some(BrowserConfig {
                    cookie_name: format!("idp_{port}_business"),
                    development_session_ttl_secs: None,
                }),
                ui_base_path: None,
                registration_enabled: c.embedded_idp.auth.allow_local_registration,
                oidc_enabled: false,
                device: None,
                scan: None,
            }],
            device_admission_providers: vec![],
            reference_business: Some(ReferenceBusinessConfig {
                public_client: c.public_client.clone(),
                confidential_client: c.confidential_client.clone(),
                allow_device_provisioning: c.allow_device_provisioning,
                scan_login: c.scan_login.clone(),
            }),
        }
    }
    pub(crate) fn from_file(path: &Path) -> Result<Self, String> {
        Self::load_file(path, true)
    }
    pub(crate) fn for_preparation(path: &Path) -> Result<Self, String> {
        Self::load_file(path, false)
    }
    fn load_file(path: &Path, for_startup: bool) -> Result<Self, String> {
        let names: BTreeSet<String> = env::vars_os()
            .filter_map(|(key, _)| key.into_string().ok())
            .collect();
        Self::from_file_with_lookup(
            path,
            &names,
            for_startup,
            for_startup,
            &|name| match env::var(name) {
                Ok(value) => Ok(Some(value)),
                Err(env::VarError::NotPresent) => Ok(None),
                Err(env::VarError::NotUnicode(_)) => Err("invalid secret encoding".into()),
            },
        )
    }
    #[cfg(test)]
    fn from_file_with_env(
        path: &Path,
        envs: &std::collections::HashMap<String, String>,
    ) -> Result<Self, String> {
        let names = envs.keys().cloned().collect();
        Self::from_file_with_lookup(path, &names, false, true, &|name| {
            Ok(envs.get(name).cloned())
        })
    }
    fn from_file_with_lookup(
        path: &Path,
        names: &BTreeSet<String>,
        for_startup: bool,
        resolve_email: bool,
        lookup: &impl Fn(&str) -> Result<Option<String>, String>,
    ) -> Result<Self, String> {
        let bytes = read_limited(path, 1024 * 1024, "configuration")?;
        let unique: Unique = serde_json::from_slice(&bytes)
            .map_err(|_| "invalid JSON configuration structure".to_string())?;
        reject_nulls(&unique.0, None)?;
        if unique.0["version"] == 1
            && unique.0["runtime"]
                .get("device_admission_providers")
                .is_some()
        {
            return Err("device providers require version 2".into());
        }
        let d: Document = serde_path_to_error::deserialize(unique.0.into_deserializer())
            .map_err(|e| format!("invalid JSON configuration field: {}", e.path()))?;
        if !matches!(d.version, 1 | 2) {
            return Err("unsupported configuration version".into());
        }
        let mut refs = vec![(
            &d.runtime.postgres.connection.uri_ref,
            "EMBEDDED_IDP_APP_PG_URI",
        )];
        if let Some(s) = d
            .runtime
            .email
            .as_ref()
            .and_then(|e| e.smtp.as_ref())
            .and_then(|s| s.password_ref.as_ref())
        {
            refs.push((s, "EMBEDDED_IDP_APP_EMAIL_SMTP_PASSWORD"))
        }
        let mut allowed = BTreeSet::new();
        for (r, expected) in &refs {
            r.validate()?;
            if let Some(name) = &r.env {
                if name.starts_with("EMBEDDED_IDP_APP_") {
                    if name != *expected {
                        return Err("unsupported legacy secret reference".into());
                    }
                    allowed.insert(name.clone());
                }
            }
        }
        for k in names {
            if (k.starts_with("EMBEDDED_IDP_APP_") || k == "EMBEDDED_IDP_COMMON_ENV_FILE")
                && !allowed.contains(k)
            {
                return Err(format!("configuration source conflict: {k}"));
            }
        }
        let mode = match d.runtime.tenancy_mode.as_str() {
            "enabled" => TenancyMode::Enabled,
            "disabled" => TenancyMode::Disabled,
            _ => return Err("invalid runtime.tenancy_mode".into()),
        };
        let bind_addr = d
            .runtime
            .bind_addr
            .parse()
            .map_err(|_| "invalid runtime.bind_addr")?;
        let transport_policy = match d.runtime.http.transport_policy.as_str() {
            "default" => HttpTransportPolicy::Default,
            "development-private-network-http" => {
                HttpTransportPolicy::DevelopmentPrivateNetworkHttp
            }
            _ => return Err("invalid runtime.http.transport_policy".into()),
        };
        transport_policy.validate().map_err(str::to_owned)?;
        if let Some(origin) = &d.runtime.http.browser_origin {
            validate_origin(origin, transport_policy)?;
        }
        if !(60..=3600).contains(&d.runtime.http.development_session_ttl_secs) {
            return Err("invalid runtime.http.development_session_ttl_secs".into());
        }
        let a = d.runtime.auth;
        let embedded_idp = EmbeddedIdpConfig {
            issuer: d.runtime.issuer,
            auth: AuthConfig {
                allow_local_registration: false,
                access_token_ttl_secs: a.access_token_ttl_secs,
                refresh_token_ttl_secs: a.refresh_token_ttl_secs,
                session_ttl_secs: a.session_ttl_secs,
                verification_code_ttl_secs: a.verification_code_ttl_secs,
                password_min_length: a.password_min_length,
                password_max_length: a.password_max_length,
            },
            device: DeviceConfig {
                nonce_ttl_secs: 300,
                proof_clock_skew_secs: 30,
                heartbeat_grace_period_secs: 60,
            },
            oidc: OidcConfig {
                authorization_code_ttl_secs: 300,
                require_pkce_for_public_clients: true,
            },
        };
        embedded_idp
            .validate()
            .map_err(|_| "invalid runtime.auth or issuer")?;
        let management = EntryConfig {
            login_entry: d.management.login_entry,
            client_id: d.management.client_id,
            policy: policy(d.management.tenant_policy, mode, true)?,
            require_device_proof: d.management.require_device_proof,
            mount_prefix: d.management.mount_prefix,
            browser: d.management.browser.map(|b| BrowserConfig {
                cookie_name: b.cookie_name,
                development_session_ttl_secs: b.development_session_ttl_secs,
            }),
            ui_base_path: d.management.ui.map(|x| x.base_path),
            registration_enabled: false,
            oidc_enabled: false,
            device: None,
            scan: None,
        };
        if d.version == 1
            && (d
                .business_entries
                .iter()
                .any(|b| b.oidc.is_some() || b.device.is_some() || b.scan.is_some())
                || !d.runtime.device_admission_providers.is_empty())
        {
            return Err("protocol configuration requires version 2".into());
        }
        let mut business_entries = Vec::new();
        for b in d.business_entries {
            business_entries.push(EntryConfig {
                login_entry: b.login_entry,
                client_id: b.client_id,
                policy: policy(b.tenant_policy, mode, false)?,
                require_device_proof: b.require_device_proof,
                mount_prefix: b.mount_prefix,
                browser: b.browser.map(|x| BrowserConfig {
                    cookie_name: x.cookie_name,
                    development_session_ttl_secs: x.development_session_ttl_secs,
                }),
                ui_base_path: None,
                registration_enabled: b.registration_enabled,
                oidc_enabled: b.oidc.is_some_and(|o| o.enabled),
                device: b.device,
                scan: b.scan,
            })
        }
        let absolute = if path.is_absolute() {
            path.to_path_buf()
        } else {
            env::current_dir()
                .map_err(|_| "cannot resolve configuration directory")?
                .join(path)
        };
        let base = absolute
            .parent()
            .ok_or("cannot resolve configuration directory")?;
        let tls_mode = match d.runtime.postgres.connection.tls_mode.as_str() {
            "disable" => PgTlsMode::Disable,
            "prefer" => PgTlsMode::Prefer,
            "require" => PgTlsMode::Require,
            _ => return Err("invalid runtime.postgres.connection.tls_mode".into()),
        };
        let mut c = Self {
            abuse: d.runtime.abuse.policy()?,
            bind_addr,
            browser_origin: d.runtime.http.browser_origin,
            transport_policy,
            development_session_ttl_secs: d.runtime.http.development_session_ttl_secs,
            embedded_idp,
            postgres: PgStorageConfig {
                connection: PgConnectionConfig {
                    connection_uri: String::new(),
                    schema_name: d.runtime.postgres.connection.schema_name,
                    tls_mode,
                    tls_ca_cert_path: d
                        .runtime
                        .postgres
                        .connection
                        .tls_ca_cert_path
                        .map(|p| resolve_path(base, &p))
                        .transpose()?,
                },
                pool: DbPoolConfig {
                    application_name: d.runtime.postgres.pool.application_name,
                    max_connections: d.runtime.postgres.pool.max_connections,
                    connect_timeout_secs: d.runtime.postgres.pool.connect_timeout_secs,
                },
            },
            email_delivery: None,
            account_security: d
                .runtime
                .account_security
                .map(|mut security| {
                    security.subject_key_file = resolve_path(base, &security.subject_key_file)?;
                    security.current.key_file = resolve_path(base, &security.current.key_file)?;
                    if let Some(previous) = &mut security.previous {
                        previous.key_file = resolve_path(base, &previous.key_file)?;
                    }
                    security.validate()?;
                    Ok::<_, String>(security)
                })
                .transpose()?,
            tenancy_mode: mode,
            signing_key_file: resolve_path(base, &d.runtime.signing_key_file)?,
            management,
            business_entries,
            reference_business: None,
            device_admission_providers: d
                .runtime
                .device_admission_providers
                .into_iter()
                .map(|mut p| {
                    p.grants_file = resolve_path(base, &p.grants_file)?;
                    Ok(p)
                })
                .collect::<Result<Vec<_>, String>>()?,
        };
        for entry in &mut c.business_entries {
            if let Some(scan) = &mut entry.scan {
                for key in &mut scan.result_keyring.keys {
                    key.key_file = resolve_path(base, &key.key_file)?;
                }
            }
        }
        c.validate_static(d.runtime.email.as_ref())?;
        c.postgres.connection.connection_uri = "postgres://placeholder".into();
        c.postgres
            .validate()
            .map_err(|_| "invalid runtime.postgres".to_string())?;
        if for_startup {
            c.validate_for_startup()?;
        }
        c.postgres.connection.connection_uri = d
            .runtime
            .postgres
            .connection
            .uri_ref
            .resolve(base, lookup)?;
        if resolve_email {
            c.email_delivery = d
                .runtime
                .email
                .map(|email| email.normalize(base, lookup))
                .transpose()?;
        }
        c.postgres
            .validate()
            .map_err(|_| "invalid runtime.postgres".to_string())?;
        Ok(c)
    }
    pub(crate) fn browser_http_config(
        &self,
        entry: &EntryConfig,
        purpose: AccessTokenPurpose,
    ) -> Result<BrowserSessionHttpConfig, String> {
        let b = entry.browser.as_ref().ok_or("browser is not configured")?;
        let suffix = match purpose {
            AccessTokenPurpose::Business => "/auth/browser",
            AccessTokenPurpose::Management => "/admin/auth/browser",
        };
        let config = BrowserSessionHttpConfig::new_with_transport_policy(
            self.browser_origin
                .as_deref()
                .ok_or("browser origin is required")?,
            &b.cookie_name,
            &format!("{}{suffix}", entry.mount_prefix),
            purpose,
            &self.transport_policy,
        )
        .map_err(str::to_owned)?;
        if config.client_config().session_ttl_secs.is_some() {
            config
                .with_development_session_ttl_secs(
                    b.development_session_ttl_secs
                        .unwrap_or(self.development_session_ttl_secs),
                )
                .map_err(str::to_owned)
        } else if b.development_session_ttl_secs.is_some() {
            Err("browser.development_session_ttl_secs requires development-login transport".into())
        } else {
            Ok(config)
        }
    }
    pub(crate) fn validate_for_startup(&self) -> Result<(), String> {
        self.abuse.validate().map_err(|e| e.to_string())?;
        if let Some(security) = &self.account_security {
            security.validate()?;
        }
        Ok(()) // All supported protocol combinations are checked before secret resolution.
    }
    fn validate_static(&mut self, email: Option<&Email>) -> Result<(), String> {
        if let Some(e) = email {
            e.validate()?;
        }
        if self
            .account_security
            .as_ref()
            .is_some_and(|s| s.recovery_email)
            && !email.is_some_and(|email| email.mode == "smtp")
        {
            return Err(
                "runtime.account_security.recovery_email requires runtime.email.mode=smtp".into(),
            );
        }
        if self
            .business_entries
            .iter()
            .filter(|e| e.scan.is_some())
            .count()
            > 16
        {
            return Err("at most 16 scan entries are supported".into());
        }
        for entry in &self.business_entries {
            if let Some(scan) = &entry.scan {
                scan.validate(entry, self)?;
            }
        }
        let mut providers = BTreeSet::new();
        for provider in &self.device_admission_providers {
            if !valid_id(&provider.id) || provider.id.len() > 48 || !providers.insert(&provider.id)
            {
                return Err("invalid or duplicate device admission provider".into());
            }
        }
        let mut ids = BTreeSet::new();
        let mut clients = BTreeSet::new();
        let mut cookies = BTreeSet::new();
        let mut paths: Vec<(String, String)> = Vec::new();
        if self.business_entries.iter().any(|e| e.oidc_enabled) {
            paths.push(("shared OIDC".into(), "/oidc".into()));
            paths.push(("discovery".into(), "/.well-known".into()));
        }
        let mut cookie_paths: Vec<String> = Vec::new();
        for (management, e) in std::iter::once((true, &self.management))
            .chain(self.business_entries.iter().map(|e| (false, e)))
        {
            if !valid_id(&e.login_entry) || !valid_id(&e.client_id) {
                return Err(if !valid_id(&e.login_entry) {
                    "invalid login_entry"
                } else {
                    "invalid client_id"
                }
                .into());
            }
            if !ids.insert(&e.login_entry) {
                return Err("duplicate login_entry".into());
            }
            if !clients.insert(&e.client_id) {
                return Err("duplicate client_id".into());
            }
            if management && e.require_device_proof {
                return Err("management_device_proof_unsupported".into());
            }
            if e.require_device_proof && e.device.is_none() {
                return Err("business device proof requires device configuration".into());
            }
            if e.require_device_proof && e.browser.is_some() {
                return Err("required device proof cannot use browser sessions".into());
            }
            if let Some(device) = &e.device {
                if !providers.contains(&device.admission_provider)
                    || device.profile_provider != "ed25519-v2"
                {
                    return Err("missing or unsupported device admission/profile provider".into());
                }
                for (actual, suffix) in [
                    (&device.paths.login, "/auth/login"),
                    (&device.paths.selection, "/auth/tenant-selection/complete"),
                    (&device.paths.refresh, "/auth/refresh"),
                    (&device.paths.heartbeat, "/devices/heartbeat"),
                ] {
                    if actual != &format!("{}{suffix}", e.mount_prefix) {
                        return Err("device external path must match mounted route".into());
                    }
                }
                if device.paths.oidc_token != "/oidc/token" {
                    return Err("device OIDC path must be /oidc/token".into());
                }
                embedded_idp_axum::TenantDeviceAuthHttpConfig::new(
                    &device.audience,
                    &device.paths.login,
                    &device.paths.selection,
                    &device.paths.refresh,
                )
                .map_err(|_| "invalid device proof profile")?;
                let family = format!("{}/devices", e.mount_prefix);
                for (owner, path) in &paths {
                    if overlaps(&family, path) {
                        return Err(format!(
                            "route conflict between {owner} and {}",
                            e.login_entry
                        ));
                    }
                }
                paths.push((e.login_entry.clone(), family));
            }
            if e.registration_enabled && !matches!(e.policy, LoginTenantPolicy::Fixed { .. }) {
                return Err("registration requires a fixed tenant policy".into());
            }
            if e.registration_enabled && email.is_none() {
                return Err("registration requires runtime.email".into());
            }
            if !valid_mount(&e.mount_prefix) {
                return Err("invalid mount_prefix".into());
            }
            let family = format!(
                "{}{}",
                e.mount_prefix,
                if management { "/admin" } else { "/auth" }
            );
            for (owner, p) in &paths {
                if overlaps(&family, p) {
                    return Err(format!(
                        "route conflict between {} and {}",
                        owner, e.login_entry
                    ));
                }
            }
            paths.push((e.login_entry.clone(), family));
            if let Some(b) = &e.browser {
                if !cookies.insert(&b.cookie_name) {
                    return Err("duplicate cookie name".into());
                }
                let p = format!(
                    "{}{}",
                    e.mount_prefix,
                    if management {
                        "/admin/auth/browser"
                    } else {
                        "/auth/browser"
                    }
                );
                if cookie_paths.iter().any(|x| overlaps(x, &p)) {
                    return Err("overlapping cookie paths".into());
                }
                cookie_paths.push(p);
                self.browser_http_config(
                    e,
                    if management {
                        AccessTokenPurpose::Management
                    } else {
                        AccessTokenPurpose::Business
                    },
                )?;
            }
        }
        if self.management.ui_base_path.is_some() && self.management.browser.is_none() {
            return Err("management UI requires browser".into());
        }
        if let Some(ui) = &mut self.management.ui_base_path {
            *ui = normalize_ui(ui)?;
            let home = ui.clone();
            let assets = if ui == "/" {
                "/assets".to_string()
            } else {
                format!("{ui}/assets")
            };
            for (_, p) in &paths {
                if overlaps(&assets, p)
                    || home == *p
                    || home
                        .strip_prefix(p)
                        .is_some_and(|suffix| suffix.starts_with('/'))
                {
                    return Err("UI and route conflict".into());
                }
            }
            if ["/healthz", "/readyz"]
                .iter()
                .any(|p| *p == home || overlaps(&assets, p))
            {
                return Err("UI and health route conflict".into());
            }
        }
        Ok(())
    }
}
impl SecretRef {
    fn validate(&self) -> Result<(), String> {
        match (&self.env, &self.file) {
            (Some(n), None) if valid_env_name(n) => Ok(()),
            (None, Some(p)) if !p.is_empty() => Ok(()),
            _ => Err("invalid secret reference".into()),
        }
    }
    fn resolve(
        &self,
        base: &Path,
        lookup: &impl Fn(&str) -> Result<Option<String>, String>,
    ) -> Result<String, String> {
        let v = if let Some(n) = &self.env {
            lookup(n)?.ok_or("missing secret")?
        } else {
            let p = base.join(self.file.as_ref().ok_or("missing secret reference")?);
            String::from_utf8(read_limited(&p, 65536, "secret")?)
                .map_err(|_| "invalid secret encoding")?
        };
        if v.is_empty() {
            return Err("empty secret".into());
        }
        Ok(v)
    }
}
pub(crate) fn read_limited(path: &Path, limit: u64, label: &str) -> Result<Vec<u8>, String> {
    if !fs::metadata(path)
        .map_err(|_| format!("cannot read {label}"))?
        .is_file()
    {
        return Err(format!("{label} must be a regular file"));
    }
    let f = fs::File::open(path).map_err(|_| format!("cannot read {label}"))?;
    if !f
        .metadata()
        .map_err(|_| format!("cannot read {label}"))?
        .is_file()
    {
        return Err(format!("{label} must be a regular file"));
    }
    let mut b = Vec::new();
    f.take(limit + 1)
        .read_to_end(&mut b)
        .map_err(|_| format!("cannot read {label}"))?;
    if b.len() as u64 > limit {
        return Err(format!("{label} too large"));
    }
    Ok(b)
}
fn valid_env_name(n: &str) -> bool {
    let mut b = n.bytes();
    matches!(b.next(),Some(x) if x.is_ascii_alphabetic()||x==b'_')
        && b.all(|x| x.is_ascii_alphanumeric() || x == b'_')
}
pub(crate) fn valid_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|x| x.is_ascii_alphanumeric() || b"_.-".contains(&x))
}
fn policy(p: Policy, mode: TenancyMode, management: bool) -> Result<LoginTenantPolicy, String> {
    let p = match p {
        Policy::Fixed { tenant_id } => {
            if !valid_id(&tenant_id) {
                return Err("invalid tenant_id".into());
            }
            LoginTenantPolicy::Fixed { tenant_id }
        }
        Policy::Choose => LoginTenantPolicy::ChooseAfterAuthentication,
    };
    if !(management
        && p == LoginTenantPolicy::Fixed {
            tenant_id: "0".into(),
        })
    {
        p.validate(mode).map_err(|_| "invalid tenant policy")?;
    }
    Ok(p)
}
fn valid_mount(s: &str) -> bool {
    s.is_empty()
        || s.starts_with('/')
            && s != "/"
            && s.split('/').skip(1).all(|x| {
                !x.is_empty()
                    && x != "."
                    && x != ".."
                    && x.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
            })
}
fn overlaps(a: &str, b: &str) -> bool {
    a == b
        || a.strip_prefix(b).is_some_and(|x| x.starts_with('/'))
        || b.strip_prefix(a).is_some_and(|x| x.starts_with('/'))
}
fn normalize_ui(s: &str) -> Result<String, String> {
    let s = s.trim();
    if s == "/" {
        return Ok("/".into());
    }
    let s = s.trim_end_matches('/');
    if !valid_mount(s)
        || s.is_empty()
        || [
            "api",
            "auth",
            "devices",
            "oidc",
            "assets",
            ".well-known",
            "healthz",
            "readyz",
        ]
        .contains(&s.split('/').nth(1).unwrap_or(""))
    {
        return Err("invalid UI base path".into());
    }
    Ok(s.into())
}
fn resolve_path(base: &Path, value: &str) -> Result<String, String> {
    if value.trim().is_empty() {
        return Err("invalid file path".into());
    }
    let p = Path::new(value);
    let p: PathBuf = if p.is_absolute() {
        p.into()
    } else {
        base.join(p)
    };
    p.to_str()
        .map(str::to_owned)
        .ok_or_else(|| "invalid file path encoding".into())
}
// Check an explicitly supplied origin even when there is no browser transport.
// BrowserSessionHttpConfig performs the same transport checks when it is enabled.
fn validate_origin(origin: &str, policy: HttpTransportPolicy) -> Result<(), String> {
    let uri: axum::http::Uri = origin.parse().map_err(|_| "invalid browser origin")?;
    let scheme = uri.scheme_str().ok_or("invalid browser origin")?;
    let authority = uri.authority().ok_or("invalid browser origin")?;
    let host = uri
        .host()
        .filter(|host| !host.is_empty())
        .ok_or("invalid browser origin")?;
    if origin != format!("{scheme}://{authority}") || authority.as_str().contains('@') {
        return Err("invalid browser origin".into());
    }
    match scheme {
        "https" => Ok(()),
        "http" if matches!(host, "localhost" | "127.0.0.1" | "[::1]") => Ok(()),
        "http" if policy == HttpTransportPolicy::DevelopmentPrivateNetworkHttp => {
            let ip: std::net::Ipv4Addr = host.parse().map_err(|_| "invalid browser origin")?;
            if ip.is_private() && ip.to_string() == host {
                Ok(())
            } else {
                Err("invalid browser origin".into())
            }
        }
        _ => Err("invalid browser origin".into()),
    }
}
impl Email {
    fn normalize(
        self,
        base: &Path,
        lookup: &impl Fn(&str) -> Result<Option<String>, String>,
    ) -> Result<EmailDeliveryConfig, String> {
        let mode = match self.mode.as_str() {
            "log" => EmailDeliveryMode::Log,
            "sendmail" => EmailDeliveryMode::Sendmail,
            "smtp" => EmailDeliveryMode::Smtp,
            _ => return Err("invalid runtime.email.mode".into()),
        };
        let smtp = self.smtp.unwrap_or(Smtp {
            host: None,
            port: None,
            tls_mode: None,
            username: None,
            password_ref: None,
        });
        let tls_mode = match smtp.tls_mode.as_deref().unwrap_or("starttls") {
            "starttls" => SmtpTlsMode::StartTls,
            "implicit_tls" => SmtpTlsMode::ImplicitTls,
            "plain" => SmtpTlsMode::Plain,
            _ => return Err("invalid runtime.email.smtp".into()),
        };
        Ok(EmailDeliveryConfig {
            mode,
            sendmail_command: resolve_path(
                base,
                self.sendmail_command
                    .as_deref()
                    .unwrap_or("/usr/sbin/sendmail"),
            )?,
            smtp: SmtpEmailDeliveryConfig {
                host: smtp.host.unwrap_or_else(|| "localhost".into()),
                port: smtp.port.unwrap_or(587),
                tls_mode,
                username: smtp.username,
                password: smtp
                    .password_ref
                    .map(|r| r.resolve(base, lookup))
                    .transpose()?,
            },
            from_email: self
                .from_email
                .unwrap_or_else(|| "embedded-idp@localhost.localdomain".into()),
            from_name: self.from_name,
            subject: self
                .subject
                .unwrap_or_else(|| "Your embedded IDP verification code".into()),
        })
    }
    fn validate(&self) -> Result<(), String> {
        if !["log", "sendmail", "smtp"].contains(&self.mode.as_str()) {
            return Err("invalid runtime.email.mode".into());
        }
        if self
            .sendmail_command
            .as_ref()
            .is_some_and(|s| s.trim().is_empty())
            || self
                .from_email
                .as_ref()
                .is_some_and(|s| s.trim().is_empty())
            || self.from_name.as_ref().is_some_and(|s| s.trim().is_empty())
            || self.subject.as_ref().is_some_and(|s| s.trim().is_empty())
        {
            return Err("invalid runtime.email".into());
        }
        if let Some(s) = &self.smtp {
            if s.host.as_ref().is_some_and(|x| x.trim().is_empty())
                || s.port == Some(0)
                || s.username.as_ref().is_some_and(|x| x.is_empty())
                || s.tls_mode
                    .as_ref()
                    .is_some_and(|x| !["starttls", "implicit_tls", "plain"].contains(&x.as_str()))
                || s.username.is_some() != s.password_ref.is_some()
            {
                return Err("invalid runtime.email.smtp".into());
            }
        }
        Ok(())
    }
}

fn reject_nulls(v: &serde_json::Value, key: Option<&str>) -> Result<(), String> {
    match v {
        serde_json::Value::Null if !matches!(key, Some("browser" | "ui")) => {
            Err("null is not allowed in configuration field".into())
        }
        serde_json::Value::Object(map) => {
            for (k, v) in map {
                reject_nulls(v, Some(k))?;
            }
            Ok(())
        }
        serde_json::Value::Array(values) => {
            for v in values {
                reject_nulls(v, None)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    fn doc() -> serde_json::Value {
        serde_json::json!({"version":1,"runtime":{"tenancy_mode":"enabled","bind_addr":"127.0.0.1:9100","issuer":"https://idp.example.test","signing_key_file":"signing.der","postgres":{"connection":{"uri_ref":{"env":"DB_URI"},"schema_name":"embedded_idp","tls_mode":"require"}},"http":{"browser_origin":"https://idp.example.test"}},"management":{"login_entry":"management","client_id":"manager","tenant_policy":{"kind":"fixed","tenant_id":"0"},"mount_prefix":"/api","browser":{"cookie_name":"management"},"ui":{"base_path":"/"}},"business_entries":[]})
    }
    fn parse(v: &serde_json::Value, envs: &HashMap<String, String>) -> Result<AppConfig, String> {
        let file = std::env::temp_dir().join(format!(
            "m1-02-{}-{:?}.json",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::write(&file, serde_json::to_vec(v).unwrap()).unwrap();
        let r = AppConfig::from_file_with_env(&file, envs);
        std::fs::remove_file(file).unwrap();
        r
    }
    fn envs() -> HashMap<String, String> {
        HashMap::from([("DB_URI".into(), "postgres://localhost/db".into())])
    }
    #[test]
    fn preparation_skips_unrelated_secrets_and_startup_capability_gate() {
        let mut value = doc();
        value["runtime"]["account_security"] = serde_json::json!({"authority":"idp.example.test","subject_key_file":"absent-subject.key","current":{"key_id":"current","key_file":"absent-current.key"},"recovery_email":true});
        value["runtime"]["email"] = serde_json::json!({"mode":"smtp","smtp":{"username":"user","password_ref":{"env":"UNAVAILABLE_SMTP"}}});
        value["business_entries"] = serde_json::json!([{"login_entry":"product","client_id":"product-client","tenant_policy":{"kind":"choose"},"mount_prefix":"/product"}]);
        let path = std::env::temp_dir().join(format!("a01-prep-{}.json", std::process::id()));
        std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        let lookup = |key: &str| {
            assert_eq!(
                key, "DB_URI",
                "preparation must not resolve unrelated secrets"
            );
            Ok(Some("postgres://localhost/db".into()))
        };
        let config =
            AppConfig::from_file_with_lookup(&path, &BTreeSet::new(), false, false, &lookup)
                .unwrap();
        assert!(config.email_delivery.is_none());
        assert!(config.validate_for_startup().is_ok());
        value["runtime"]["email"]["smtp"]["port"] = serde_json::json!(0);
        std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(
            AppConfig::from_file_with_lookup(&path, &BTreeSet::new(), false, false, &lookup)
                .is_err()
        );
        std::fs::remove_file(path).unwrap();
    }
    #[test]
    fn management_and_legacy_conflicts() {
        let c = parse(&doc(), &envs()).ok().unwrap();
        assert!(c.business_entries.is_empty());
        assert!(c.validate_for_startup().is_ok());
        assert!(!c.embedded_idp.auth.allow_local_registration);
        let mut e = envs();
        e.insert("EMBEDDED_IDP_APP_BIND_ADDR".into(), "".into());
        assert!(parse(&doc(), &e).err().unwrap().contains("conflict"));
    }
    #[test]
    fn optional_browser_ui_and_origin_contract() {
        let mut token_only = doc();
        token_only["management"]
            .as_object_mut()
            .unwrap()
            .remove("browser");
        token_only["management"]
            .as_object_mut()
            .unwrap()
            .remove("ui");
        token_only["runtime"]
            .as_object_mut()
            .unwrap()
            .remove("http");
        let config = parse(&token_only, &envs()).ok().unwrap();
        assert!(config.browser_origin.is_none());
        assert!(config.management.browser.is_none());
        assert!(config.management.ui_base_path.is_none());
        let mut browser = token_only.clone();
        browser["management"]["browser"] = serde_json::json!({"cookie_name":"manager"});
        assert!(parse(&browser, &envs()).is_err());
        browser["runtime"]["http"] =
            serde_json::json!({"browser_origin":"https://idp.example.test"});
        assert!(parse(&browser, &envs()).is_ok());
        browser["management"]["ui"] = serde_json::json!({"base_path":"/"});
        assert!(parse(&browser, &envs()).is_ok());
        let mut invalid = token_only.clone();
        invalid["management"]["ui"] = serde_json::json!({"base_path":"/"});
        assert!(parse(&invalid, &envs()).is_err());
        invalid = token_only.clone();
        invalid["runtime"]["http"] = serde_json::Value::Null;
        assert!(parse(&invalid, &envs()).is_err());
        for origin in [
            "https://example.test/",
            "https://user@example.test",
            "http://example.test",
            "https://example.test/path",
            "null",
        ] {
            invalid = token_only.clone();
            invalid["runtime"]["http"] = serde_json::json!({"browser_origin":origin});
            assert!(parse(&invalid, &envs()).is_err(), "{origin}");
        }
        invalid = token_only;
        invalid["business_entries"] = serde_json::json!([{"login_entry":"product","client_id":"product","tenant_policy":{"kind":"choose"},"mount_prefix":"/product","browser":{"cookie_name":"product"}}]);
        assert!(parse(&invalid, &envs()).err().unwrap().contains("origin"));
        invalid["runtime"]["http"] =
            serde_json::json!({"browser_origin":"https://idp.example.test"});
        assert!(parse(&invalid, &envs()).is_ok());
    }
    #[test]
    fn unsupported_startup_does_not_resolve_secrets() {
        use std::cell::Cell;
        let path = env::temp_dir().join(format!(
            "m1-02-startup-{}-{:?}.json",
            std::process::id(),
            std::thread::current().id()
        ));
        let mut d = doc();
        d["business_entries"] = serde_json::json!([{"login_entry":"product","client_id":"product","tenant_policy":{"kind":"choose"},"mount_prefix":"/product","require_device_proof":true}]);
        fs::write(&path, serde_json::to_vec(&d).unwrap()).unwrap();
        let calls = Cell::new(0);
        let lookup = |_: &str| {
            calls.set(calls.get() + 1);
            Ok(None)
        };
        let err = AppConfig::from_file_with_lookup(&path, &BTreeSet::new(), true, true, &lookup)
            .err()
            .unwrap();
        assert!(err.contains("requires device configuration"));
        assert_eq!(calls.get(), 0);
        d["business_entries"][0]["require_device_proof"] = false.into();
        d["management"]["mount_prefix"] = "/invalid+".into();
        fs::write(&path, serde_json::to_vec(&d).unwrap()).unwrap();
        assert!(
            AppConfig::from_file_with_lookup(&path, &BTreeSet::new(), true, true, &lookup)
                .err()
                .unwrap()
                .contains("mount")
        );
        assert_eq!(calls.get(), 0);
        fs::remove_file(path).unwrap();
    }
    #[test]
    fn email_configuration_is_normalized_and_secrets_retained() {
        let path = env::temp_dir().join(format!(
            "m1-02-mail-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        fs::create_dir_all(&path).unwrap();
        let config_path = path.join("config.json");
        let mut d = doc();
        for (mode, expected) in [
            ("log", EmailDeliveryMode::Log),
            ("sendmail", EmailDeliveryMode::Sendmail),
            ("smtp", EmailDeliveryMode::Smtp),
        ] {
            d["runtime"]["email"] =
                serde_json::json!({"mode":mode, "sendmail_command":"bin/sendmail"});
            fs::write(&config_path, serde_json::to_vec(&d).unwrap()).unwrap();
            let email = AppConfig::from_file_with_env(&config_path, &envs())
                .ok()
                .unwrap()
                .email_delivery
                .unwrap();
            assert_eq!(email.mode, expected);
            assert_eq!(
                email.sendmail_command,
                path.join("bin/sendmail").to_str().unwrap()
            );
            assert_eq!(email.smtp.host, "localhost");
            assert_eq!(email.smtp.port, 587);
            assert_eq!(email.smtp.tls_mode, SmtpTlsMode::StartTls);
            assert_eq!(email.from_email, "embedded-idp@localhost.localdomain");
            assert_eq!(email.subject, "Your embedded IDP verification code");
        }
        let mut env = envs();
        env.insert("SMTP_PASSWORD".into(), "synthetic-secret".into());
        d["runtime"]["email"] = serde_json::json!({"mode":"smtp", "smtp":{"username":"user", "password_ref":{"env":"SMTP_PASSWORD"}}});
        fs::write(&config_path, serde_json::to_vec(&d).unwrap()).unwrap();
        let c = AppConfig::from_file_with_env(&config_path, &env)
            .ok()
            .unwrap();
        assert_eq!(
            c.email_delivery.unwrap().smtp.password.as_deref(),
            Some("synthetic-secret")
        );
        fs::write(path.join("password"), "file-secret").unwrap();
        d["runtime"]["email"]["smtp"]["password_ref"] = serde_json::json!({"file":"password"});
        fs::write(&config_path, serde_json::to_vec(&d).unwrap()).unwrap();
        let c = AppConfig::from_file_with_env(&config_path, &envs())
            .ok()
            .unwrap();
        assert_eq!(
            c.email_delivery.unwrap().smtp.password.as_deref(),
            Some("file-secret")
        );
        fs::write(path.join("password"), "").unwrap();
        assert!(AppConfig::from_file_with_env(&config_path, &envs())
            .err()
            .unwrap()
            .contains("empty secret"));
        fs::remove_dir_all(path).unwrap();
        assert!(parse(&doc(), &envs())
            .ok()
            .unwrap()
            .email_delivery
            .is_none());
    }
    #[test]
    fn device_v2_requires_providers_exact_paths_and_safe_combinations() {
        let mut v = doc();
        v["version"] = 2.into();
        v["runtime"]["device_admission_providers"] =
            serde_json::json!([{"id":"grants","grants_file":"grants.json"}]);
        v["business_entries"] = serde_json::json!([{"login_entry":"one","client_id":"one","tenant_policy":{"kind":"choose"},"mount_prefix":"/one","require_device_proof":true,"device":{"admission_provider":"grants","profile_provider":"ed25519-v2","audience":"one-api","paths":{"login":"/one/auth/login","selection":"/one/auth/tenant-selection/complete","refresh":"/one/auth/refresh","heartbeat":"/one/devices/heartbeat","oidc_token":"/oidc/token"}}}]);
        assert!(parse(&v, &envs()).is_ok());
        for (key, value) in [
            ("admission_provider", "missing"),
            ("profile_provider", "untrusted"),
        ] {
            let mut bad = v.clone();
            bad["business_entries"][0]["device"][key] = value.into();
            assert!(parse(&bad, &envs()).err().unwrap().contains("provider"));
        }
        for path in ["login", "selection", "refresh", "heartbeat", "oidc_token"] {
            let mut bad = v.clone();
            bad["business_entries"][0]["device"]["paths"][path] = "/unbound".into();
            assert!(parse(&bad, &envs()).is_err());
        }
        let mut bad = v.clone();
        bad["business_entries"][0]["browser"] = serde_json::json!({"cookie_name":"device"});
        assert!(parse(&bad, &envs()).err().unwrap().contains("browser"));
        bad["business_entries"][0]["require_device_proof"] = false.into();
        assert!(parse(&bad, &envs()).is_ok());
        bad = v.clone();
        bad["version"] = 1.into();
        assert!(parse(&bad, &envs()).err().unwrap().contains("version 2"));
        bad = v.clone();
        bad["business_entries"].as_array_mut().unwrap().push(serde_json::json!({"login_entry":"two","client_id":"two","tenant_policy":{"kind":"choose"},"mount_prefix":"/one/devices"}));
        assert!(parse(&bad, &envs()).err().unwrap().contains("conflict"));
        bad = v;
        bad["business_entries"][0]["scan"] = serde_json::json!({});
        assert!(parse(&bad, &envs()).is_err());
    }
    #[test]
    fn scan_v2_requires_explicit_dependencies_paths_keys_and_bounded_cleanup() {
        let mut v = doc();
        v["version"] = 2.into();
        v["runtime"]["device_admission_providers"] =
            serde_json::json!([{"id":"grants","grants_file":"grants.json"}]);
        v["business_entries"] = serde_json::json!([{"login_entry":"one","client_id":"one","tenant_policy":{"kind":"choose"},"mount_prefix":"/one","browser":{"cookie_name":"one"},"device":{"admission_provider":"grants","profile_provider":"ed25519-v2","audience":"one-api","paths":{"login":"/one/auth/login","selection":"/one/auth/tenant-selection/complete","refresh":"/one/auth/refresh","heartbeat":"/one/devices/heartbeat","oidc_token":"/oidc/token"}},"scan":{"admission_provider":"reference-identity-only","presentation_provider":"registered-device","host_scope":"one-host","modes":["device_display","phone_display"],"audience":"one-scan","device_prefix":"/one/auth/device-scan","verification_uri":"https://idp.example.test/one/auth/browser/device-scan/ui","result_keyring":{"active_key_id":"new","keys":[{"key_id":"new","key_file":"new.key"},{"key_id":"old","key_file":"old.key"}]},"cleanup":{"interval_secs":30,"batch_size":100}}}]);
        let parsed = parse(&v, &envs()).unwrap();
        let entry = &parsed.business_entries[0];
        let scan = entry.scan.as_ref().unwrap();
        let core = scan.entry(entry).unwrap();
        assert_eq!(core.entry_id, entry.login_entry);
        assert_eq!(
            core.allowed_source_client_ids,
            vec![entry.client_id.clone()]
        );
        assert!(std::path::Path::new(&scan.result_keyring.keys[0].key_file).is_absolute());
        for path in [
            "admission_provider",
            "presentation_provider",
            "device_prefix",
            "verification_uri",
        ] {
            let mut bad = v.clone();
            bad["business_entries"][0]["scan"][path] = "unsupported".into();
            assert!(parse(&bad, &envs()).is_err(), "{path}");
        }
        for (path, value) in [
            ("/version", serde_json::json!(1)),
            (
                "/business_entries/0/require_device_proof",
                serde_json::json!(true),
            ),
            ("/business_entries/0/scan/modes", serde_json::json!([])),
            (
                "/business_entries/0/scan/modes",
                serde_json::json!(["device_display", "device_display"]),
            ),
            (
                "/business_entries/0/scan/cleanup/interval_secs",
                serde_json::json!(0),
            ),
            (
                "/business_entries/0/scan/cleanup/batch_size",
                serde_json::json!(101),
            ),
            (
                "/business_entries/0/scan/result_keyring/active_key_id",
                serde_json::json!("missing"),
            ),
            (
                "/business_entries/0/scan/result_keyring/keys/1/key_id",
                serde_json::json!("new"),
            ),
        ] {
            let mut bad = v.clone();
            if path.ends_with("require_device_proof") {
                bad["business_entries"][0]["require_device_proof"] = value;
            } else {
                *bad.pointer_mut(path).unwrap() = value;
            }
            assert!(parse(&bad, &envs()).is_err(), "{path}");
        }
        for dependency in ["browser", "device"] {
            let mut bad = v.clone();
            bad["business_entries"][0]
                .as_object_mut()
                .unwrap()
                .remove(dependency);
            assert!(parse(&bad, &envs()).is_err());
        }
    }
    #[test]
    fn oidc_v2_is_explicit_and_reserves_shared_routes() {
        let mut v = doc();
        v["business_entries"] = serde_json::json!([{"login_entry":"one","client_id":"one","tenant_policy":{"kind":"choose"},"mount_prefix":"/one","oidc":{"enabled":true}}]);
        assert!(parse(&v, &envs()).err().unwrap().contains("version 2"));
        v["version"] = 2.into();
        assert!(parse(&v, &envs()).unwrap().business_entries[0].oidc_enabled);
        for field in ["device", "scan"] {
            v["business_entries"][0][field] = serde_json::json!({"enabled":true});
            assert!(parse(&v, &envs()).is_err());
            v["business_entries"][0]
                .as_object_mut()
                .unwrap()
                .remove(field);
        }
        for path in ["/oidc", "/.well-known", "/oidc/token"] {
            v["business_entries"][0]["mount_prefix"] = path.into();
            assert!(parse(&v, &envs()).err().unwrap().contains("conflict"));
        }
        v["business_entries"][0]["mount_prefix"] = "/one".into();
        v["business_entries"][0]["oidc"] = serde_json::json!({"enabled":false});
        assert!(!parse(&v, &envs()).unwrap().business_entries[0].oidc_enabled);
        v["business_entries"][0]["oidc"] = serde_json::json!({"enabled":true,"device":true});
        assert!(parse(&v, &envs()).is_err());
    }
    #[test]
    fn ordinary_business_is_supported_at_startup() {
        let mut v = doc();
        v["business_entries"] = serde_json::json!([{"login_entry":"product","client_id":"product-client","tenant_policy":{"kind":"fixed","tenant_id":"a"},"mount_prefix":"/product"}]);
        let c = parse(&v, &envs()).ok().unwrap();
        assert!(c.validate_for_startup().is_ok());
    }
    #[test]
    fn registration_requires_fixed_policy_and_email_and_full_browser_rejects_dev_ttl() {
        let mut v = doc();
        v["business_entries"] = serde_json::json!([{"login_entry":"registration","client_id":"registration","tenant_policy":{"kind":"fixed","tenant_id":"a"},"mount_prefix":"/registration","registration_enabled":true}]);
        assert!(parse(&v, &envs()).err().unwrap().contains("email"));
        v["runtime"]["email"] = serde_json::json!({"mode":"log"});
        assert!(parse(&v, &envs()).is_ok());
        v["business_entries"][0]["tenant_policy"] = serde_json::json!({"kind":"choose"});
        assert!(parse(&v, &envs()).err().unwrap().contains("fixed"));
        v["business_entries"][0]["registration_enabled"] = false.into();
        v["business_entries"][0]["browser"] =
            serde_json::json!({"cookie_name":"business","development_session_ttl_secs":120});
        assert!(parse(&v, &envs()).err().unwrap().contains("development"));
    }
    #[cfg(all(feature = "development-private-network-http", debug_assertions))]
    #[test]
    fn ordinary_registration_and_independent_browser_lifetimes() {
        let mut v = doc();
        v["business_entries"] = serde_json::json!([
            {"login_entry":"one","client_id":"one","tenant_policy":{"kind":"fixed","tenant_id":"a"},"mount_prefix":"/one","browser":{"cookie_name":"one","development_session_ttl_secs":120}},
            {"login_entry":"two","client_id":"two","tenant_policy":{"kind":"choose"},"mount_prefix":"/two","browser":{"cookie_name":"two","development_session_ttl_secs":240}}
        ]);
        // Full browser sessions must not silently ignore a development TTL.
        assert!(parse(&v, &envs()).err().unwrap().contains("development"));
        v["runtime"]["http"]["transport_policy"] = "development-private-network-http".into();
        v["runtime"]["http"]["browser_origin"] = "http://192.168.1.10:9100".into();
        let c = parse(&v, &envs()).ok().unwrap();
        let configs = c
            .business_entries
            .iter()
            .map(|entry| {
                c.browser_http_config(entry, AccessTokenPurpose::Business)
                    .unwrap()
                    .client_config()
            })
            .collect::<Vec<_>>();
        assert_eq!(configs[0].session_ttl_secs, Some(120));
        assert_eq!(configs[1].session_ttl_secs, Some(240));
        assert_eq!(
            c.browser_http_config(&c.management, AccessTokenPurpose::Management)
                .unwrap()
                .client_config()
                .session_ttl_secs,
            Some(900)
        );
        v["business_entries"].as_array_mut().unwrap().reverse();
        let reordered = parse(&v, &envs()).ok().unwrap();
        assert_eq!(reordered.business_entries[1].login_entry, "one");
        assert_eq!(reordered.business_entries[1].mount_prefix, "/one");
        v["business_entries"][1]["registration_enabled"] = true.into();
        assert!(parse(&v, &envs()).err().unwrap().contains("email"));
        v["runtime"]["email"] = serde_json::json!({"mode":"log"});
        assert!(parse(&v, &envs()).is_ok());
        v["business_entries"][0]["registration_enabled"] = true.into();
        assert!(parse(&v, &envs()).err().unwrap().contains("fixed"));
        v["business_entries"][0]["registration_enabled"] = false.into();
        v["business_entries"][0]["browser"]["development_session_ttl_secs"] = 59.into();
        assert!(parse(&v, &envs()).is_err());
    }
    #[test]
    fn rejects_policy_paths_cookie_and_secrets() {
        for p in ["/a+1", "/a//b", "/a/../b", "/a/", "/产品"] {
            let mut v = doc();
            v["management"]["mount_prefix"] = p.into();
            assert!(parse(&v, &envs()).is_err(), "{p}");
        }
        let mut v = doc();
        v["business_entries"] = serde_json::json!([{"login_entry":"other","client_id":"other","tenant_policy":{"kind":"fixed","tenant_id":"0"},"mount_prefix":"/other"}]);
        assert!(parse(&v, &envs()).is_err());
        let mut v = doc();
        v["runtime"]["postgres"]["connection"]["uri_ref"] =
            serde_json::json!({"env":"MISSING_SECRET"});
        let err = parse(&v, &envs()).err().unwrap();
        assert!(!err.contains("postgres://"));
    }
    #[test]
    fn policy_matrix_and_entry_collisions() {
        for (mode, purpose, tenant, expected) in [
            (TenancyMode::Enabled, true, "0", true),
            (TenancyMode::Enabled, false, "0", false),
            (TenancyMode::Enabled, true, "tenant-a", true),
            (TenancyMode::Enabled, false, "tenant-a", true),
            (TenancyMode::Disabled, true, "0", true),
            (TenancyMode::Disabled, false, "0", true),
            (TenancyMode::Disabled, true, "tenant-a", false),
            (TenancyMode::Disabled, false, "tenant-a", false),
        ] {
            assert_eq!(
                policy(
                    Policy::Fixed {
                        tenant_id: tenant.into()
                    },
                    mode,
                    purpose
                )
                .is_ok(),
                expected
            );
        }
        for (mode, expected) in [(TenancyMode::Enabled, true), (TenancyMode::Disabled, false)] {
            for management in [true, false] {
                assert_eq!(policy(Policy::Choose, mode, management).is_ok(), expected);
            }
        }
        for (entry, client, mount, cookie) in [
            ("management", "other", "/other", "other"),
            ("other", "manager", "/other", "other"),
            ("other", "other", "/other", "management"),
            ("other", "other", "/api/admin/auth/browser", "other"),
        ] {
            let mut v = doc();
            v["business_entries"] = serde_json::json!([{"login_entry":entry,"client_id":client,"tenant_policy":{"kind":"choose"},"mount_prefix":mount,"browser":{"cookie_name":cookie}}]);
            assert!(parse(&v, &envs()).is_err());
        }
    }
    #[test]
    fn conflict_precedes_secret_read() {
        let mut v = doc();
        v["runtime"]["postgres"]["connection"]["uri_ref"] =
            serde_json::json!({"file":"missing-secret-file"});
        let mut e = envs();
        e.insert("EMBEDDED_IDP_APP_BIND_ADDR".into(), "".into());
        assert!(parse(&v, &e).err().unwrap().contains("conflict"));
        let mut v = doc();
        v["runtime"]["postgres"]["connection"]["uri_ref"] =
            serde_json::json!({"env":"EMBEDDED_IDP_APP_PG_URI"});
        let e = HashMap::from([(
            "EMBEDDED_IDP_APP_PG_URI".into(),
            "postgres://localhost/db".into(),
        )]);
        assert!(parse(&v, &e).is_ok());
    }
    #[test]
    fn secret_lookup_is_lazy_and_limited_to_references() {
        let path = env::temp_dir().join(format!(
            "m1-02-lookup-{}-{:?}.json",
            std::process::id(),
            std::thread::current().id()
        ));
        let calls = std::cell::RefCell::new(Vec::new());
        let lookup = |name: &str| {
            calls.borrow_mut().push(name.to_owned());
            Ok(Some("postgres://localhost/db".to_string()))
        };
        let mut names =
            BTreeSet::from(["DB_URI".to_string(), "EMBEDDED_IDP_APP_UNKNOWN".to_string()]);
        fs::write(&path, serde_json::to_vec(&doc()).unwrap()).unwrap();
        assert!(AppConfig::from_file_with_lookup(&path, &names, false, true, &lookup).is_err());
        assert!(calls.borrow().is_empty());
        names.remove("EMBEDDED_IDP_APP_UNKNOWN");
        let mut bad = doc();
        bad["management"]["mount_prefix"] = "/bad+path".into();
        fs::write(&path, serde_json::to_vec(&bad).unwrap()).unwrap();
        assert!(AppConfig::from_file_with_lookup(&path, &names, false, true, &lookup).is_err());
        assert!(calls.borrow().is_empty());
        fs::write(&path, serde_json::to_vec(&doc()).unwrap()).unwrap();
        assert!(AppConfig::from_file_with_lookup(&path, &names, false, true, &lookup).is_ok());
        assert_eq!(&*calls.borrow(), &["DB_URI".to_string()]);
        fs::remove_file(path).unwrap();
    }
    #[test]
    fn structural_errors_report_path_without_value() {
        let mut v = doc();
        v["runtime"]["postgres"]["connection"]["schema_name"] = serde_json::json!(12345);
        let e = parse(&v, &envs()).err().unwrap();
        assert!(e.contains("runtime.postgres.connection.schema_name"), "{e}");
        assert!(!e.contains("12345"));
        for v in [
            serde_json::json!(null),
            serde_json::json!("1"),
            serde_json::json!(3),
        ] {
            let mut d = doc();
            d["version"] = v;
            assert!(parse(&d, &envs()).is_err());
        }
        let mut d = doc();
        d["management"]["require_device_proof"] = true.into();
        assert_eq!(
            parse(&d, &envs()).err().unwrap(),
            "management_device_proof_unsupported"
        );
        let mut d = doc();
        d["runtime"]["bogus_secret_value"] = serde_json::json!("supersecret");
        let e = parse(&d, &envs()).err().unwrap();
        assert!(!e.contains("supersecret"));
    }
    #[test]
    fn ui_and_paths_are_checked() {
        for path in ["//", "/healthz", "/readyz", "/assets"] {
            let mut d = doc();
            d["management"]["ui"]["base_path"] = path.into();
            assert!(parse(&d, &envs()).is_err(), "{path}");
        }
        let mut d = doc();
        d["business_entries"] = serde_json::json!([{"login_entry":"product","client_id":"product","tenant_policy":{"kind":"choose"},"mount_prefix":"/assets"}]);
        assert!(parse(&d, &envs()).is_err());
        let mut d = doc();
        d["management"]["mount_prefix"] = "".into();
        let c = parse(&d, &envs()).ok().unwrap();
        assert!(Path::new(&c.signing_key_file).is_absolute());
    }
    #[test]
    fn recovery_email_is_opt_in_and_requires_smtp_before_secret_resolution() {
        let mut value = doc();
        value["runtime"]["account_security"] = serde_json::json!({
            "authority":"idp.example.test", "subject_key_file":"absent-subject.key",
            "current":{"key_id":"current","key_file":"absent-current.key"}
        });
        assert!(
            !parse(&value, &envs())
                .unwrap()
                .account_security
                .unwrap()
                .recovery_email
        );
        value["runtime"]["account_security"]["recovery_email"] = serde_json::json!(true);
        assert!(parse(&value, &envs())
            .err()
            .unwrap()
            .contains("requires runtime.email.mode=smtp"));
        for mode in ["log", "sendmail"] {
            value["runtime"]["email"] = serde_json::json!({"mode":mode});
            assert!(parse(&value, &envs())
                .err()
                .unwrap()
                .contains("requires runtime.email.mode=smtp"));
        }
        value["runtime"]["email"] = serde_json::json!({"mode":"smtp"});
        assert!(
            parse(&value, &envs())
                .unwrap()
                .account_security
                .unwrap()
                .recovery_email
        );
        value["runtime"]["account_security"]["recovery_email"] = serde_json::json!("true");
        assert!(parse(&value, &envs()).is_err());
    }
    #[test]
    fn account_security_paths_are_resolved_without_reading_key_files() {
        let mut value = doc();
        value["runtime"]["account_security"] = serde_json::json!({
            "authority": "idp.example.test",
            "subject_key_file": "security/subject.key",
            "current": {"key_id": "current", "key_file": "security/current.key"},
            "previous": {"key_id": "previous", "key_file": "security/previous.key"}
        });
        let config = parse(&value, &envs()).unwrap();
        let security = config.account_security.unwrap();
        assert!(Path::new(&security.subject_key_file).is_absolute());
        assert!(security.subject_key_file.ends_with("security/subject.key"));
        assert!(Path::new(&security.current.key_file).is_absolute());
        assert!(security.current.key_file.ends_with("security/current.key"));
        let previous = security.previous.unwrap();
        assert!(Path::new(&previous.key_file).is_absolute());
        assert!(previous.key_file.ends_with("security/previous.key"));

        let mut unknown = value;
        unknown["runtime"]["account_security"]["raw_subject_key"] = "not-accepted".into();
        assert!(parse(&unknown, &envs()).is_err());
    }
    #[test]
    fn file_secret_and_legacy_source_rules() {
        let dir = env::temp_dir().join(format!(
            "m1-02-secret-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        fs::create_dir_all(&dir).unwrap();
        let config = dir.join("config.json");
        let secret = dir.join("uri");
        let mut d = doc();
        d["runtime"]["postgres"]["connection"]["uri_ref"] = serde_json::json!({"file":"uri"});
        fs::write(&config, serde_json::to_vec(&d).unwrap()).unwrap();
        for bytes in [vec![], vec![0xff], vec![b'x'; 65537]] {
            fs::write(&secret, bytes).unwrap();
            assert!(AppConfig::from_file_with_env(&config, &HashMap::new()).is_err());
        }
        fs::write(&secret, b"postgres://localhost/db").unwrap();
        let c = AppConfig::from_file_with_env(&config, &HashMap::new())
            .ok()
            .unwrap();
        assert_eq!(
            c.postgres.connection.connection_uri,
            "postgres://localhost/db"
        );
        d["runtime"]["postgres"]["connection"]["uri_ref"] =
            serde_json::json!({"file":"uri","env":"DB_URI"});
        fs::write(&config, serde_json::to_vec(&d).unwrap()).unwrap();
        assert!(AppConfig::from_file_with_env(&config, &envs()).is_err());
        assert!(read_limited(&dir, 65536, "secret").is_err());
        fs::remove_dir_all(dir).unwrap();
        let mut e = envs();
        e.insert("EMBEDDED_IDP_APP_UNKNOWN".into(), "".into());
        assert!(parse(&doc(), &e).err().unwrap().contains("conflict"));
    }
    #[cfg(unix)]
    #[test]
    fn special_file_is_rejected_before_open() {
        let path = env::temp_dir().join(format!(
            "m1-02-fifo-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        assert!(std::process::Command::new("mkfifo")
            .arg(&path)
            .status()
            .unwrap()
            .success());
        assert!(read_limited(&path, 64, "secret")
            .unwrap_err()
            .contains("regular file"));
        fs::remove_file(path).unwrap();
    }
    #[test]
    fn legacy_mapping_preserves_existing_browser_contract() {
        use crate::config::{EmailDeliveryMode, SmtpEmailDeliveryConfig, SmtpTlsMode};
        let c = parse(&doc(), &envs()).ok().unwrap();
        let old = EmbeddedIdpAppConfig {
            bind_addr: c.bind_addr,
            browser_origin: c.browser_origin.clone().unwrap(),
            transport_policy: c.transport_policy.clone(),
            development_session_ttl_secs: c.development_session_ttl_secs,
            embedded_idp: c.embedded_idp.clone(),
            admin_ui_base_path: "/console".into(),
            postgres: c.postgres.clone(),
            email_delivery: EmailDeliveryConfig {
                mode: EmailDeliveryMode::Log,
                sendmail_command: "sendmail".into(),
                smtp: SmtpEmailDeliveryConfig {
                    host: "localhost".into(),
                    port: 587,
                    tls_mode: SmtpTlsMode::StartTls,
                    username: None,
                    password: None,
                },
                from_email: "test@example.test".into(),
                from_name: None,
                subject: "code".into(),
            },
            public_client: SeedClientConfig {
                client_id: "client".into(),
                client_name: "client".into(),
                redirect_uri: "http://localhost/cb".into(),
            },
            confidential_client: None,
            tenancy_mode: TenancyMode::Enabled,
            login_policy: LoginTenantPolicy::ChooseAfterAuthentication,
            management_policy: LoginTenantPolicy::Fixed {
                tenant_id: "0".into(),
            },
            signing_key_file: "key".into(),
            allow_device_provisioning: true,
            scan_login: None,
        };
        let mapped = AppConfig::from_legacy(&old);
        assert_eq!(mapped.email_delivery.as_ref(), Some(&old.email_delivery));
        assert_eq!(mapped.embedded_idp, old.embedded_idp);
        assert_eq!(mapped.postgres, old.postgres);
        assert_eq!(mapped.management.policy, old.management_policy);
        assert_eq!(mapped.business_entries[0].policy, old.login_policy);
        assert_eq!(
            mapped.business_entries[0].client_id,
            old.public_client.client_id
        );
        assert_eq!(mapped.management.ui_base_path.as_deref(), Some("/console"));
        for (entry, purpose) in [
            (&mapped.management, AccessTokenPurpose::Management),
            (&mapped.business_entries[0], AccessTokenPurpose::Business),
        ] {
            assert_eq!(
                format!("{:?}", mapped.browser_http_config(entry, purpose).unwrap()),
                format!("{:?}", old.browser_http_config(purpose).unwrap())
            );
        }
    }
    #[test]
    fn rejects_duplicate_null_and_unknown() {
        for s in [r#"{"a":null,"a":null}"#, r#"{"a":{"b":1,"b":2}}"#] {
            assert!(serde_json::from_str::<Unique>(s).is_err())
        }
        let mut v = doc();
        v["runtime"]["auth"] = serde_json::Value::Null;
        assert!(parse(&v, &envs()).is_err());
        let mut v = doc();
        v["runtime"]["device"] = serde_json::json!({});
        assert!(parse(&v, &envs()).is_err());
    }
}
