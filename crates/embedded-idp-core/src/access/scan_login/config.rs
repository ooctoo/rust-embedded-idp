use std::collections::HashSet;

use super::super::{query::validate_id, AccessError, LoginTenantPolicy, TenancyMode};
use crate::normalize_oauth_scope;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ScanLoginMode {
    DeviceDisplay,
    PhoneDisplay,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanLoginLimits {
    pub grant_ttl_secs: u32,
    pub phone_code_ttl_secs: u32,
    pub approval_ttl_secs: u32,
    pub recovery_ttl_secs: u32,
    pub poll_after_ms: u32,
    pub admission_ttl_secs: u32,
}

impl Default for ScanLoginLimits {
    fn default() -> Self {
        Self {
            grant_ttl_secs: 180,
            phone_code_ttl_secs: 60,
            approval_ttl_secs: 60,
            recovery_ttl_secs: 120,
            poll_after_ms: 2000,
            admission_ttl_secs: 5,
        }
    }
}

impl ScanLoginLimits {
    pub fn validate(&self) -> Result<(), AccessError> {
        for (value, max, field) in [
            (self.grant_ttl_secs, 600, "scan_grant_ttl"),
            (self.phone_code_ttl_secs, 120, "scan_phone_code_ttl"),
            (self.approval_ttl_secs, 600, "scan_approval_ttl"),
            (self.recovery_ttl_secs, 300, "scan_recovery_ttl"),
            (self.admission_ttl_secs, 5, "scan_admission_ttl"),
            (self.poll_after_ms, 30_000, "scan_poll_interval"),
        ] {
            if value == 0 || value > max {
                return Err(AccessError::InvalidInput(field));
            }
        }
        if self.phone_code_ttl_secs > self.grant_ttl_secs
            || self.approval_ttl_secs > self.grant_ttl_secs
        {
            return Err(AccessError::InvalidInput("scan_grant_deadlines"));
        }
        Ok(())
    }
}

/// Host configuration only. The module never reads process environment or
/// accepts a source->target relationship from an HTTP request.
/// Verification URI and audience belong to the HTTP adapter's trusted config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanLoginEntryConfig {
    pub entry_id: String,
    pub target_client_id: String,
    pub allowed_source_client_ids: Vec<String>,
    pub host_scope: String,
    pub tenant_policy: LoginTenantPolicy,
    pub modes: Vec<ScanLoginMode>,
    pub target_scope: Option<String>,
    pub limits: ScanLoginLimits,
}

impl ScanLoginEntryConfig {
    pub fn validate(&self, tenancy: TenancyMode) -> Result<(), AccessError> {
        validate_id(&self.entry_id, 128, "scan_entry_id")?;
        validate_id(&self.target_client_id, 128, "scan_target_client_id")?;
        validate_id(&self.host_scope, 128, "scan_host_scope")?;
        self.tenant_policy.validate(tenancy)?;
        self.limits.validate()?;
        if self.allowed_source_client_ids.is_empty() || self.modes.is_empty() {
            return Err(AccessError::InvalidInput("scan_entry_disabled"));
        }
        let mut clients = HashSet::new();
        for client in &self.allowed_source_client_ids {
            validate_id(client, 128, "scan_source_client_id")?;
            if !clients.insert(client) {
                return Err(AccessError::InvalidInput("scan_duplicate_source_client"));
            }
        }
        if self.modes.iter().collect::<HashSet<_>>().len() != self.modes.len() {
            return Err(AccessError::InvalidInput("scan_duplicate_mode"));
        }
        if let Some(scope) = &self.target_scope {
            if scope.is_empty()
                || scope.len() > 1024
                || normalize_oauth_scope(scope)
                    .map_err(|_| AccessError::InvalidInput("scan_target_scope"))?
                    != *scope
            {
                return Err(AccessError::InvalidInput("scan_target_scope"));
            }
        }
        Ok(())
    }

    /// Configuration admission only. Session purpose, active membership, client
    /// existence, target proof and host business policy require service checks.
    pub fn authorize_source(
        &self,
        tenancy: TenancyMode,
        tenant_id: &str,
        source_client_id: &str,
        mode: ScanLoginMode,
    ) -> Result<(), AccessError> {
        self.validate(tenancy)?;
        self.tenant_policy.validate_selection(tenancy, tenant_id)?;
        if !self.modes.contains(&mode)
            || !self
                .allowed_source_client_ids
                .iter()
                .any(|allowed| allowed == source_client_id)
        {
            return Err(AccessError::Forbidden);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry() -> ScanLoginEntryConfig {
        ScanLoginEntryConfig {
            entry_id: "terminal-login".into(),
            target_client_id: "terminal".into(),
            allowed_source_client_ids: vec!["phone".into()],
            host_scope: "host-a".into(),
            tenant_policy: LoginTenantPolicy::Fixed {
                tenant_id: "t1".into(),
            },
            modes: vec![ScanLoginMode::DeviceDisplay, ScanLoginMode::PhoneDisplay],
            target_scope: Some("read write".into()),
            limits: ScanLoginLimits::default(),
        }
    }

    #[test]
    fn scan_client_relationship_is_explicit_directional_and_tenant_bound() {
        let mut config = entry();
        assert!(config
            .authorize_source(
                TenancyMode::Enabled,
                "t1",
                "phone",
                ScanLoginMode::DeviceDisplay
            )
            .is_ok());
        for (tenant, client) in [("t2", "phone"), ("t1", "terminal"), ("t1", "Phone")] {
            assert!(config
                .authorize_source(
                    TenancyMode::Enabled,
                    tenant,
                    client,
                    ScanLoginMode::DeviceDisplay
                )
                .is_err());
        }
        config.allowed_source_client_ids.push("terminal".into());
        assert!(config
            .authorize_source(
                TenancyMode::Enabled,
                "t1",
                "terminal",
                ScanLoginMode::PhoneDisplay
            )
            .is_ok());
        config.modes = vec![ScanLoginMode::DeviceDisplay];
        assert!(config
            .authorize_source(
                TenancyMode::Enabled,
                "t1",
                "phone",
                ScanLoginMode::PhoneDisplay
            )
            .is_err());
    }

    #[test]
    fn scan_entry_rejects_ambiguous_or_unbounded_configuration() {
        for field in [
            "sources",
            "duplicate_sources",
            "modes",
            "duplicate_modes",
            "scope",
            "ttl",
            "deadline",
            "tenant",
        ] {
            let mut config = entry();
            match field {
                "sources" => config.allowed_source_client_ids.clear(),
                "duplicate_sources" => config.allowed_source_client_ids.push("phone".into()),
                "modes" => config.modes.clear(),
                "duplicate_modes" => config.modes.push(ScanLoginMode::DeviceDisplay),
                "scope" => config.target_scope = Some("read  write".into()),
                "ttl" => config.limits.recovery_ttl_secs = 301,
                "deadline" => config.limits.grant_ttl_secs = 10,
                "tenant" => {
                    config.tenant_policy = LoginTenantPolicy::Fixed {
                        tenant_id: "0".into(),
                    }
                }
                _ => unreachable!(),
            }
            assert!(config.validate(TenancyMode::Enabled).is_err(), "{field}");
        }
        let mut config = entry();
        config.tenant_policy = LoginTenantPolicy::Fixed {
            tenant_id: "0".into(),
        };
        assert!(config
            .authorize_source(
                TenancyMode::Disabled,
                "0",
                "phone",
                ScanLoginMode::DeviceDisplay
            )
            .is_ok());
        config.tenant_policy = LoginTenantPolicy::ChooseAfterAuthentication;
        assert!(config.validate(TenancyMode::Disabled).is_err());
        assert!(config
            .authorize_source(
                TenancyMode::Enabled,
                "t2",
                "phone",
                ScanLoginMode::DeviceDisplay
            )
            .is_ok());
        assert!(config
            .authorize_source(
                TenancyMode::Enabled,
                "0",
                "phone",
                ScanLoginMode::DeviceDisplay
            )
            .is_err());
    }
}
