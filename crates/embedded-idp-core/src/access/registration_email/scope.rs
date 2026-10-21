use super::super::TenancyMode;

use super::RegistrationEmailError;

/// Trusted server-side binding for one registration namespace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistrationEmailScope {
    pub authority: String,
    pub product: String,
    pub tenant: String,
    pub mode: TenancyMode,
}

impl RegistrationEmailScope {
    /// Construct a scope after validating its service-bound identifiers and
    /// the tenant against the configured tenancy mode.
    pub fn new(
        authority: impl Into<String>,
        product: impl Into<String>,
        tenant: impl Into<String>,
        mode: TenancyMode,
    ) -> Result<Self, RegistrationEmailError> {
        let scope = Self {
            authority: authority.into(),
            product: product.into(),
            tenant: tenant.into(),
            mode,
        };
        validate_scope_component(&scope.authority, "authority")?;
        validate_scope_component(&scope.product, "product")?;
        mode.validate_business_tenant(&scope.tenant)
            .map_err(|_| RegistrationEmailError::InvalidInput("tenant"))?;
        Ok(scope)
    }
}

fn validate_scope_component(
    value: &str,
    field: &'static str,
) -> Result<(), RegistrationEmailError> {
    if value.is_empty()
        || value.len() > 128
        || !value.as_bytes()[0].is_ascii_lowercase()
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"_.-".contains(&byte)
        })
    {
        return Err(RegistrationEmailError::InvalidInput(field));
    }
    Ok(())
}
