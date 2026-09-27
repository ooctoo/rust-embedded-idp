use std::{fmt, str::FromStr};

use super::AccessError;

pub const MAX_ACCESS_DESCRIPTION_BYTES: usize = 1024;
pub const MAX_ACCESS_BATCH_SIZE: usize = 100;
pub const IDP_BUSINESS_ID: &str = "idp";

pub(crate) fn validate_id(value: &str, max: usize, field: &'static str) -> Result<(), AccessError> {
    if value.is_empty()
        || value.len() > max
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
    {
        return Err(AccessError::InvalidInput(field));
    }
    Ok(())
}

pub(crate) fn validate_name(value: &str, field: &'static str) -> Result<(), AccessError> {
    validate_id(value, 64, field)?;
    if !value.as_bytes()[0].is_ascii_lowercase() || value.bytes().any(|b| b.is_ascii_uppercase()) {
        return Err(AccessError::InvalidInput(field));
    }
    Ok(())
}

/// Validates a host business namespace. `idp` and `idp.*` are reserved for
/// management records and cannot be selected by a host business operation.
pub fn validate_business_id(value: &str) -> Result<(), AccessError> {
    validate_name(value, "business_id")?;
    if value == IDP_BUSINESS_ID || value.starts_with("idp.") {
        return Err(AccessError::InvalidInput("business_id"));
    }
    Ok(())
}

/// Validates an authorization namespace, including the fixed IDP namespace.
pub fn validate_access_business_id(value: &str) -> Result<(), AccessError> {
    if value == IDP_BUSINESS_ID {
        Ok(())
    } else {
        validate_business_id(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct PermissionKey {
    pub business_id: String,
    pub resource_type: String,
    pub action: String,
}

impl PermissionKey {
    pub fn validate(&self) -> Result<(), AccessError> {
        validate_access_business_id(&self.business_id)?;
        validate_name(&self.resource_type, "resource_type")?;
        validate_name(&self.action, "action")
    }
}

/// A lookup description, never a credential. A missing ID asks for type-wide access.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessQuery {
    pub tenant_id: String,
    pub business_id: String,
    pub subject_id: crate::AccountId,
    pub resource_type: String,
    pub action: String,
    pub resource_id: Option<String>,
}

impl AccessQuery {
    pub fn validate(&self) -> Result<(), AccessError> {
        validate_id(&self.tenant_id, 128, "tenant_id")?;
        validate_access_business_id(&self.business_id)?;
        validate_id(&self.subject_id, 128, "subject_id")?;
        self.permission().validate()?;
        if let Some(id) = &self.resource_id {
            validate_id(id, 256, "resource_id")?;
        }
        Ok(())
    }

    pub fn permission(&self) -> PermissionKey {
        PermissionKey {
            business_id: self.business_id.clone(),
            resource_type: self.resource_type.clone(),
            action: self.action.clone(),
        }
    }
}

impl FromStr for AccessQuery {
    type Err = AccessError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.len() > MAX_ACCESS_DESCRIPTION_BYTES {
            return Err(AccessError::InvalidInput("description_length"));
        }
        let mut parts = value.split("::");
        let (tenant_id, business_id, subject_id) = parts
            .next()
            .and_then(|s| {
                let mut parts = s.split('/');
                Some((parts.next()?, parts.next()?, parts.next()?))
                    .filter(|_| parts.next().is_none())
            })
            .ok_or(AccessError::InvalidInput("subject_scope"))?;
        let resource_type = parts
            .next()
            .ok_or(AccessError::InvalidInput("resource_type"))?;
        let action = parts.next().ok_or(AccessError::InvalidInput("action"))?;
        let resource_id = parts.next().filter(|id| !id.is_empty()).map(str::to_owned);
        if parts.next().is_some() {
            return Err(AccessError::InvalidInput("description_segments"));
        }
        let query = Self {
            tenant_id: tenant_id.to_owned(),
            business_id: business_id.to_owned(),
            subject_id: subject_id.to_owned(),
            resource_type: resource_type.to_owned(),
            action: action.to_owned(),
            resource_id,
        };
        query.validate()?;
        Ok(query)
    }
}

impl fmt::Display for AccessQuery {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}/{}/{}::{}::{}",
            self.tenant_id, self.business_id, self.subject_id, self.resource_type, self.action
        )?;
        if let Some(id) = &self.resource_id {
            write!(f, "::{id}")?;
        }
        Ok(())
    }
}

/// Every item must have the same tenant and subject. Results retain input order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchAccessQuery {
    pub queries: Vec<AccessQuery>,
}

impl BatchAccessQuery {
    pub fn validate(&self) -> Result<(), AccessError> {
        if self.queries.is_empty() || self.queries.len() > MAX_ACCESS_BATCH_SIZE {
            return Err(AccessError::InvalidInput("batch_size"));
        }
        let first = &self.queries[0];
        for query in &self.queries {
            query.validate()?;
            if query.tenant_id != first.tenant_id
                || query.business_id != first.business_id
                || query.subject_id != first.subject_id
            {
                return Err(AccessError::InvalidInput("batch_subject_scope"));
            }
        }
        Ok(())
    }
}

/// Explicit scope on assignment prevents omitted IDs accidentally granting all resources.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResourceScope {
    Type,
    Instance(String),
}

/// A role is either assigned to its whole business or to a resource type/instance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoleBindingScope {
    Business,
    Resource {
        resource_type: String,
        scope: ResourceScope,
    },
}

impl RoleBindingScope {
    pub fn validate(&self) -> Result<(), AccessError> {
        match self {
            Self::Business => Ok(()),
            Self::Resource {
                resource_type,
                scope,
            } => {
                validate_name(resource_type, "resource_type")?;
                scope.validate()
            }
        }
    }
}

impl ResourceScope {
    pub fn validate(&self) -> Result<(), AccessError> {
        match self {
            Self::Type => Ok(()),
            Self::Instance(id) => validate_id(id, 256, "resource_id"),
        }
    }

    pub fn covers(&self, resource_id: Option<&str>) -> bool {
        match self {
            Self::Type => true,
            Self::Instance(id) => resource_id == Some(id.as_str()),
        }
    }
}
