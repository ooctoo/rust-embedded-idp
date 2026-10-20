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
    pub bind_addr: SocketAddr,
    pub browser_origin: Option<String>,
    pub transport_policy: HttpTransportPolicy,
    pub development_session_ttl_secs: u64,
    pub embedded_idp: EmbeddedIdpConfig,
    pub postgres: PgStorageConfig,
    pub email_delivery: Option<EmailDeliveryConfig>,
    pub tenancy_mode: TenancyMode,
    pub signing_key_file: String,
    pub management: EntryConfig,
    pub business_entries: Vec<EntryConfig>,
    pub reference_business: Option<ReferenceBusinessConfig>,
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
struct Unique(serde_json::Value);
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
            bind_addr: c.bind_addr,
            browser_origin: Some(c.browser_origin.clone()),
            transport_policy: c.transport_policy.clone(),
            development_session_ttl_secs: c.development_session_ttl_secs,
            embedded_idp: c.embedded_idp.clone(),
            postgres: c.postgres.clone(),
            email_delivery: Some(c.email_delivery.clone()),
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
                }),
                ui_base_path: Some(c.admin_ui_base_path.clone()),
                registration_enabled: false,
            },
            business_entries: vec![EntryConfig {
                login_entry: "business".into(),
                client_id: c.public_client.client_id.clone(),
                policy: c.login_policy.clone(),
                require_device_proof: false,
                mount_prefix: String::new(),
                browser: Some(BrowserConfig {
                    cookie_name: format!("idp_{port}_business"),
                }),
                ui_base_path: None,
                registration_enabled: c.embedded_idp.auth.allow_local_registration,
            }],
            reference_business: Some(ReferenceBusinessConfig {
                public_client: c.public_client.clone(),
                confidential_client: c.confidential_client.clone(),
                allow_device_provisioning: c.allow_device_provisioning,
                scan_login: c.scan_login.clone(),
            }),
        }
    }
    pub(crate) fn from_file(path: &Path) -> Result<Self, String> {
        let names: BTreeSet<String> = env::vars_os()
            .filter_map(|(key, _)| key.into_string().ok())
            .collect();
        Self::from_file_with_lookup(path, &names, true, &|name| match env::var(name) {
            Ok(value) => Ok(Some(value)),
            Err(env::VarError::NotPresent) => Ok(None),
            Err(env::VarError::NotUnicode(_)) => Err("invalid secret encoding".into()),
        })
    }
    #[cfg(test)]
    fn from_file_with_env(
        path: &Path,
        envs: &std::collections::HashMap<String, String>,
    ) -> Result<Self, String> {
        let names = envs.keys().cloned().collect();
        Self::from_file_with_lookup(path, &names, false, &|name| Ok(envs.get(name).cloned()))
    }
    fn from_file_with_lookup(
        path: &Path,
        names: &BTreeSet<String>,
        for_startup: bool,
        lookup: &impl Fn(&str) -> Result<Option<String>, String>,
    ) -> Result<Self, String> {
        let bytes = read_limited(path, 1024 * 1024, "configuration")?;
        let unique: Unique = serde_json::from_slice(&bytes)
            .map_err(|_| "invalid JSON configuration structure".to_string())?;
        reject_nulls(&unique.0, None)?;
        let d: Document = serde_path_to_error::deserialize(unique.0.into_deserializer())
            .map_err(|e| format!("invalid JSON configuration field: {}", e.path()))?;
        if d.version != 1 {
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
            }),
            ui_base_path: d.management.ui.map(|x| x.base_path),
            registration_enabled: false,
        };
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
                }),
                ui_base_path: None,
                registration_enabled: b.registration_enabled,
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
            tenancy_mode: mode,
            signing_key_file: resolve_path(base, &d.runtime.signing_key_file)?,
            management,
            business_entries,
            reference_business: None,
        };
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
        c.email_delivery = d
            .runtime
            .email
            .map(|email| email.normalize(base, lookup))
            .transpose()?;
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
                .with_development_session_ttl_secs(self.development_session_ttl_secs)
                .map_err(str::to_owned)
        } else {
            Ok(config)
        }
    }
    pub(crate) fn validate_for_startup(&self) -> Result<(), String> {
        if self.reference_business.is_none() && !self.business_entries.is_empty() {
            return Err("business entries are not supported by this build".into());
        }
        Ok(())
    }
    fn validate_static(&mut self, email: Option<&Email>) -> Result<(), String> {
        if let Some(e) = email {
            e.validate()?;
        }
        let mut ids = BTreeSet::new();
        let mut clients = BTreeSet::new();
        let mut cookies = BTreeSet::new();
        let mut paths: Vec<(String, String)> = Vec::new();
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
            if e.require_device_proof {
                return Err(if management {
                    "management_device_proof_unsupported"
                } else {
                    "business device proof is not supported by this build"
                }
                .into());
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
fn read_limited(path: &Path, limit: u64, label: &str) -> Result<Vec<u8>, String> {
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
fn valid_id(s: &str) -> bool {
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
        d["business_entries"] = serde_json::json!([{"login_entry":"product","client_id":"product","tenant_policy":{"kind":"choose"},"mount_prefix":"/product"}]);
        fs::write(&path, serde_json::to_vec(&d).unwrap()).unwrap();
        let calls = Cell::new(0);
        let lookup = |_: &str| {
            calls.set(calls.get() + 1);
            Ok(None)
        };
        let err = AppConfig::from_file_with_lookup(&path, &BTreeSet::new(), true, &lookup)
            .err()
            .unwrap();
        assert!(err.contains("not supported"));
        assert_eq!(calls.get(), 0);
        d["management"]["mount_prefix"] = "/invalid+".into();
        fs::write(&path, serde_json::to_vec(&d).unwrap()).unwrap();
        assert!(
            AppConfig::from_file_with_lookup(&path, &BTreeSet::new(), true, &lookup)
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
    fn nonempty_business_is_valid_but_build_rejects_startup() {
        let mut v = doc();
        v["business_entries"] = serde_json::json!([{"login_entry":"product","client_id":"product-client","tenant_policy":{"kind":"fixed","tenant_id":"a"},"mount_prefix":"/product"}]);
        let c = parse(&v, &envs()).ok().unwrap();
        assert!(c.validate_for_startup().is_err());
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
        assert!(AppConfig::from_file_with_lookup(&path, &names, false, &lookup).is_err());
        assert!(calls.borrow().is_empty());
        names.remove("EMBEDDED_IDP_APP_UNKNOWN");
        let mut bad = doc();
        bad["management"]["mount_prefix"] = "/bad+path".into();
        fs::write(&path, serde_json::to_vec(&bad).unwrap()).unwrap();
        assert!(AppConfig::from_file_with_lookup(&path, &names, false, &lookup).is_err());
        assert!(calls.borrow().is_empty());
        fs::write(&path, serde_json::to_vec(&doc()).unwrap()).unwrap();
        assert!(AppConfig::from_file_with_lookup(&path, &names, false, &lookup).is_ok());
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
            serde_json::json!(2),
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
