use super::*;
use crate::service::{
    contracts::is_valid_email,
    password::{hash_password, validate_registration_password},
};
use crate::{AuthConfig, ConfigValidationError, SecretString};
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminCreateAccount {
    pub tenant_id: String,
    pub email: String,
    pub password: SecretString,
    pub display_name: Option<String>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminSetAccountStatus {
    pub account_id: String,
    pub status: AccountIdentityStatus,
    pub expected_status: AccountIdentityStatus,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminSetAccountPassword {
    pub account_id: String,
    pub new_password: SecretString,
}
/// Exactly one initial administrator source; secrets never enter AccessChange/audit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InitialTenantAdministrator {
    Existing {
        subject_id: String,
    },
    New {
        email: String,
        password: SecretString,
        display_name: Option<String>,
    },
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminCreateTenant {
    pub tenant_id: String,
    pub name: String,
    pub allow_registration: bool,
    pub administrator: InitialTenantAdministrator,
}
pub trait TenantCreationService: Send + Sync {
    fn create_tenant(
        &self,
        context: AccessAdminContext,
        command: AdminCreateTenant,
    ) -> Result<AccessAuditEvent, AccessError>;
}

pub trait AccountSecurityService: Send + Sync {
    fn create_account(
        &self,
        context: AccessAdminContext,
        command: AdminCreateAccount,
    ) -> Result<AccessAuditEvent, AccessError>;
    fn set_account_status(
        &self,
        context: AccessAdminContext,
        command: AdminSetAccountStatus,
    ) -> Result<AccessAuditEvent, AccessError>;
    fn set_account_password(
        &self,
        context: AccessAdminContext,
        command: AdminSetAccountPassword,
    ) -> Result<AccessAuditEvent, AccessError>;
}
pub struct CoreAccountSecurityService<S, C, I> {
    admin: CoreAccessAdminService<S, C, I>,
    config: AuthConfig,
}
impl<S, C, I> CoreAccountSecurityService<S, C, I> {
    pub fn new(
        admin: CoreAccessAdminService<S, C, I>,
        config: AuthConfig,
    ) -> Result<Self, ConfigValidationError> {
        config.validate()?;
        Ok(Self { admin, config })
    }
}
impl<S: AccessAdminStore, C: Clock + Send + Sync, I: IdGenerator + Send + Sync>
    AccountSecurityService for CoreAccountSecurityService<S, C, I>
{
    fn create_account(
        &self,
        context: AccessAdminContext,
        command: AdminCreateAccount,
    ) -> Result<AccessAuditEvent, AccessError> {
        self.admin
            .mode
            .validate_business_tenant(&command.tenant_id)?;
        validate_account_profile(&command.email, &command.display_name)?;
        self.password(&command.password)?;
        let account_id = self.admin.new_id("acct")?;
        self.admin.store.admin_transaction(|tx| {
            self.authorize(tx, &context, Some(&account_id))?;
            if self.admin.mode == TenancyMode::Enabled {
                let permission = super::super::service::admin_permission_query(
                    self.admin.mode,
                    &context.actor,
                    &command.tenant_id,
                    AccessAdminOperation::BindUser,
                )?;
                if !tx.check_permission(&permission)? {
                    return Err(AccessError::Forbidden);
                }
            }
            let tenant = tx
                .tenant(&command.tenant_id)?
                .ok_or(AccessError::NotFound("tenant"))?;
            if tenant.id != command.tenant_id {
                return Err(AccessError::InvalidStoreResponse);
            }
            if tenant.status != TenantStatus::Active {
                return Err(AccessError::Forbidden);
            }
            let hash = SecretString::new(hash_password(command.password.expose_secret())?);
            let now = self.admin.clock.now();
            if !tx.actor_is_active(&context.actor, now)? {
                return Err(AccessError::Forbidden);
            }
            let record = AccessAccountRecord {
                account_id: account_id.clone(),
                email: command.email,
                display_name: command.display_name,
                status: AccountIdentityStatus::Active,
                created_at: now,
                membership: Some(TenantMembership {
                    tenant_id: command.tenant_id.clone(),
                    subject_id: account_id,
                    status: MembershipStatus::Active,
                    joined_at: now,
                    version: 1,
                }),
            };
            tx.insert_admin_account(&record, &hash)?;
            let event = AccessAuditEvent {
                id: self.admin.new_id("audit")?,
                occurred_at: now,
                context,
                tenant_id: command.tenant_id,
                target_business_id: None,
                operation: "account.create",
                change: AccessChange::AccountCreated { after: record },
            };
            tx.append_audit(&event)?;
            Ok(event)
        })
    }
    fn set_account_status(
        &self,
        context: AccessAdminContext,
        command: AdminSetAccountStatus,
    ) -> Result<AccessAuditEvent, AccessError> {
        validate_id(&command.account_id, 128, "account_id")?;
        if !matches!(
            command.status,
            AccountIdentityStatus::Active | AccountIdentityStatus::Disabled
        ) {
            return Err(AccessError::InvalidInput("account_status"));
        }
        self.admin.store.admin_transaction(|tx| {
            self.authorize(tx, &context, Some(&command.account_id))?;
            let before = self.account(tx, &command.account_id)?;
            if before.status != command.expected_status {
                return Err(AccessError::Conflict("account_status"));
            }
            if before.status == AccountIdentityStatus::Closed {
                return Err(AccessError::Conflict("account_closed"));
            }
            if command.status == AccountIdentityStatus::Active
                && !tx.has_non_removed_membership(&command.account_id)?
            {
                return Err(AccessError::Conflict("last_membership"));
            }
            let now = self.admin.clock.now();
            let mut after = before.clone();
            after.status = command.status;
            tx.update_account_security(&before, command.status, None, now)?;
            if before.status == AccountIdentityStatus::Active
                && command.status == AccountIdentityStatus::Disabled
            {
                self.protect_administrators(tx, &command.account_id)?;
            }
            self.audit(tx, context, before, after, false, now)
        })
    }
    fn set_account_password(
        &self,
        context: AccessAdminContext,
        command: AdminSetAccountPassword,
    ) -> Result<AccessAuditEvent, AccessError> {
        validate_id(&command.account_id, 128, "account_id")?;
        self.password(&command.new_password)?;
        self.admin.store.admin_transaction(|tx| {
            self.authorize(tx, &context, Some(&command.account_id))?;
            let before = self.account(tx, &command.account_id)?;
            if before.status == AccountIdentityStatus::Closed {
                return Err(AccessError::Conflict("account_closed"));
            }
            // ponytail: rare security writes hold the deployment lock while hashing;
            // split preparation only after measuring contention and preserving rechecks.
            let hash = SecretString::new(hash_password(command.new_password.expose_secret())?);
            let now = self.admin.clock.now();
            if !tx.actor_is_active(&context.actor, now)? {
                return Err(AccessError::Forbidden);
            }
            tx.update_account_security(&before, before.status, Some(&hash), now)?;
            self.audit(tx, context, before.clone(), before, true, now)
        })
    }
}
impl<S: AccessAdminStore, C: Clock, I: IdGenerator> CoreAccountSecurityService<S, C, I> {
    fn password(&self, password: &SecretString) -> Result<(), AccessError> {
        validate_registration_password(&self.config, password.expose_secret())
            .map_err(|_| AccessError::InvalidInput("password"))
    }
    fn authorize(
        &self,
        tx: &mut impl AccessAdminTransaction,
        context: &AccessAdminContext,
        subject: Option<&str>,
    ) -> Result<(), AccessError> {
        self.admin
            .authorize_management(
                tx,
                context,
                SYSTEM_TENANT_ID,
                AccessAdminOperation::ManageAccountSecurity,
                true,
                subject,
            )
            .map(|_| ())
    }
    fn account(
        &self,
        tx: &mut impl AccessAdminTransaction,
        id: &str,
    ) -> Result<AccessAccountRecord, AccessError> {
        let record = tx
            .admin_account(None, id)?
            .ok_or(AccessError::NotFound("account"))?;
        if record.account_id != id || record.membership.is_some() {
            return Err(AccessError::InvalidStoreResponse);
        }
        Ok(record)
    }
    fn protect_administrators(
        &self,
        tx: &mut impl AccessAdminTransaction,
        subject: &str,
    ) -> Result<(), AccessError> {
        let mut after: Option<String> = None;
        loop {
            // Bound memory even when one identity belongs to many tenants. Reuse
            // the same effective-admin predicate as role/member mutations.
            let tenants = tx.account_admin_tenants(subject, after.as_deref(), 100)?;
            if tenants.len() > 100 {
                return Err(AccessError::InvalidStoreResponse);
            }
            let full = tenants.len() == 100;
            for tenant in tenants {
                validate_id(&tenant, 128, "tenant_id")?;
                if after.as_ref().is_some_and(|a| a >= &tenant) {
                    return Err(AccessError::InvalidStoreResponse);
                }
                if !tx.has_effective_security_admin(&tenant, security_kind(&tenant))? {
                    return Err(AccessError::Conflict("last_security_admin"));
                }
                after = Some(tenant);
            }
            if !full {
                return Ok(());
            }
        }
    }
    fn audit(
        &self,
        tx: &mut impl AccessAdminTransaction,
        context: AccessAdminContext,
        before: AccessAccountRecord,
        after: AccessAccountRecord,
        password_changed: bool,
        now: SystemTime,
    ) -> Result<AccessAuditEvent, AccessError> {
        let event = AccessAuditEvent {
            id: self.admin.new_id("audit")?,
            occurred_at: now,
            context,
            tenant_id: SYSTEM_TENANT_ID.into(),
            target_business_id: None,
            operation: if password_changed {
                "account.password"
            } else {
                "account.status"
            },
            change: AccessChange::AccountSecurity {
                before,
                after,
                password_changed,
            },
        };
        tx.append_audit(&event)?;
        Ok(event)
    }
}

fn validate_account_profile(email: &str, display_name: &Option<String>) -> Result<(), AccessError> {
    if !is_valid_email(email) || email.len() > 254 || email.chars().any(char::is_control) {
        return Err(AccessError::InvalidInput("email"));
    }
    if display_name
        .as_ref()
        .is_some_and(|s| s.trim().is_empty() || s.len() > 256 || s.chars().any(char::is_control))
    {
        return Err(AccessError::InvalidInput("display_name"));
    }
    Ok(())
}

impl<S: AccessAdminStore, C: Clock + Send + Sync, I: IdGenerator + Send + Sync>
    TenantCreationService for CoreAccountSecurityService<S, C, I>
{
    fn create_tenant(
        &self,
        context: AccessAdminContext,
        command: AdminCreateTenant,
    ) -> Result<AccessAuditEvent, AccessError> {
        if self.admin.mode != TenancyMode::Enabled {
            return Err(AccessError::Forbidden);
        }
        self.admin
            .mode
            .validate_business_tenant(&command.tenant_id)?;
        let (subject_id, new_account) = match command.administrator {
            InitialTenantAdministrator::Existing { subject_id } => (subject_id, None),
            InitialTenantAdministrator::New {
                email,
                password,
                display_name,
            } => {
                validate_account_profile(&email, &display_name)?;
                self.password(&password)?;
                (
                    self.admin.new_id("acct")?,
                    Some((email, password, display_name)),
                )
            }
        };
        let admin_command = AccessAdminCommand {
            tenant_id: command.tenant_id.clone(),
            mutation: AccessAdminMutation::CreateTenant {
                name: command.name,
                allow_registration: command.allow_registration,
                administrator_subject_id: subject_id.clone(),
            },
        };
        admin_command.mutation.validate()?;
        let Some((email, password, display_name)) = new_account else {
            return self.admin.execute(context, admin_command);
        };
        self.admin.store.admin_transaction(|tx| {
            // Account creation additionally requires platform users.security.
            // The exclusive state lock covers the not-yet-existing tenant and account.
            self.authorize(tx, &context, Some(&subject_id))?;
            for operation in [
                AccessAdminOperation::ManageTenants,
                AccessAdminOperation::BindUser,
                AccessAdminOperation::ManageSecurityAdmins,
            ] {
                let query = super::super::service::admin_permission_query(
                    self.admin.mode,
                    &context.actor,
                    &command.tenant_id,
                    operation,
                )?;
                if !tx.check_permission(&query)? {
                    return Err(AccessError::Forbidden);
                }
            }
            // ponytail: infrequent administrator creation hashes under the existing
            // exclusive security-write lock; move preparation only if contention is measured.
            let hash = SecretString::new(hash_password(password.expose_secret())?);
            let now = self.admin.clock.now();
            if !tx.actor_is_active(&context.actor, now)? {
                return Err(AccessError::Forbidden);
            }
            let change = self
                .admin
                .prepare_tenant_creation(tx, &admin_command, now)?;
            let AccessChange::TenantCreated {
                record,
                administrator,
                permission_definitions,
                role,
                binding,
            } = &change
            else {
                return Err(AccessError::InvalidStoreResponse);
            };
            let account = AccessAccountRecord {
                account_id: subject_id.clone(),
                email,
                display_name,
                status: AccountIdentityStatus::Active,
                created_at: now,
                membership: Some(administrator.clone()),
            };
            tx.insert_admin_tenant(record, now)?;
            tx.insert_admin_account(&account, &hash)?;
            tx.apply_change(
                &AccessChange::Catalog {
                    changes: permission_definitions
                        .iter()
                        .cloned()
                        .map(|after| AccessPermissionChange {
                            before: None,
                            after,
                        })
                        .collect(),
                },
                now,
            )?;
            tx.apply_change(
                &AccessChange::Role {
                    before: None,
                    after: Some(role.clone()),
                },
                now,
            )?;
            tx.apply_change(
                &AccessChange::Binding {
                    before: None,
                    after: Some(binding.clone()),
                },
                now,
            )?;
            if !tx
                .has_effective_security_admin(&command.tenant_id, RoleKind::TenantSecurityAdmin)?
            {
                return Err(AccessError::Conflict("last_security_admin"));
            }
            tx.append_audit(&AccessAuditEvent {
                id: self.admin.new_id("audit")?,
                occurred_at: now,
                context: context.clone(),
                tenant_id: command.tenant_id.clone(),
                target_business_id: None,
                operation: "account.create",
                change: AccessChange::AccountCreated { after: account },
            })?;
            let event = AccessAuditEvent {
                id: self.admin.new_id("audit")?,
                occurred_at: now,
                context,
                tenant_id: command.tenant_id,
                target_business_id: None,
                operation: "tenant.create",
                change,
            };
            tx.append_audit(&event)?;
            Ok(event)
        })
    }
}
