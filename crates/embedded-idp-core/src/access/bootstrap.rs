use super::{query::validate_id, AccessError, TenancyMode};
use crate::service::{
    contracts::is_valid_email,
    password::{hash_password, validate_registration_password},
};
use crate::{Account, AccountStatus, Clock, IdGenerator, StoreError};
use crate::{AuthConfig, SecretString};

/// Explicit offline input; Debug redacts the password through SecretString.
#[derive(Debug)]
pub struct BootstrapAdministrator {
    pub email: String,
    pub display_name: Option<String>,
    pub password: SecretString,
    pub request_id: String,
}

/// Offline host input: the host validates the identity and supplies a securely
/// hashed credential. This operation is never exposed as a public registration route.
/// Fields are private so storage only receives a validated, complete plan.
pub struct AccessBootstrap {
    mode: TenancyMode,
    account: Account,
    role_id: String,
    binding_id: String,
    audit_id: String,
    request_id: String,
}
impl AccessBootstrap {
    pub fn mode(&self) -> TenancyMode {
        self.mode
    }
    pub fn account(&self) -> &Account {
        &self.account
    }
    pub fn role_id(&self) -> &str {
        &self.role_id
    }
    pub fn binding_id(&self) -> &str {
        &self.binding_id
    }
    pub fn audit_id(&self) -> &str {
        &self.audit_id
    }
    pub fn request_id(&self) -> &str {
        &self.request_id
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessBootstrapResult {
    Initialized,
    AlreadyInitialized,
}

pub trait AccessBootstrapStore: Send + Sync {
    /// Exclusive state lock; atomically create account + domain 0 membership,
    /// protected platform role and type-wide binding, audit, and completion marker.
    /// A repeated call verifies the effective administrator invariant, without
    /// changing any account, credential, role, permission state or audit record.
    /// Refuse incomplete/pre-populated bootstrap state, never silently adopt it.
    fn bootstrap_access(&self, plan: &AccessBootstrap)
        -> Result<AccessBootstrapResult, StoreError>;
}

pub struct CoreAccessBootstrapService<S, C, I> {
    mode: TenancyMode,
    store: S,
    clock: C,
    ids: I,
}
impl<S, C, I> CoreAccessBootstrapService<S, C, I>
where
    S: AccessBootstrapStore,
    C: Clock,
    I: IdGenerator,
{
    pub fn new(mode: TenancyMode, store: S, clock: C, ids: I) -> Self {
        Self {
            mode,
            store,
            clock,
            ids,
        }
    }
    pub fn initialize(
        &self,
        mut account: Account,
        request_id: String,
    ) -> Result<AccessBootstrapResult, AccessError> {
        validate_id(&account.id, 128, "subject_id")?;
        validate_id(&request_id, 128, "request_id")?;
        if account.status != AccountStatus::Active
            || account.email.trim().is_empty()
            || account.password_hash.trim().is_empty()
        {
            return Err(AccessError::InvalidInput("bootstrap_account"));
        }
        account.created_at = self.clock.now();
        let plan = AccessBootstrap {
            mode: self.mode,
            account,
            role_id: self.ids.next_id("role"),
            binding_id: self.ids.next_id("binding"),
            audit_id: self.ids.next_id("audit"),
            request_id,
        };
        for id in [&plan.role_id, &plan.binding_id, &plan.audit_id] {
            validate_id(id, 128, "generated_id")?;
        }
        self.store.bootstrap_access(&plan).map_err(Into::into)
    }

    /// Reuses registration password rules and hashing before the atomic offline bootstrap.
    /// This is not public registration, and does not depend on allow_local_registration.
    pub fn initialize_administrator(
        &self,
        config: &AuthConfig,
        input: BootstrapAdministrator,
    ) -> Result<AccessBootstrapResult, AccessError> {
        config
            .validate()
            .map_err(|_| AccessError::InvalidInput("auth_config"))?;
        validate_id(&input.request_id, 128, "request_id")?;
        if !is_valid_email(&input.email)
            || input.email.len() > 254
            || input.email.chars().any(char::is_control)
        {
            return Err(AccessError::InvalidInput("email"));
        }
        if input.display_name.as_ref().is_some_and(|name| {
            name.trim().is_empty() || name.len() > 256 || name.chars().any(char::is_control)
        }) {
            return Err(AccessError::InvalidInput("display_name"));
        }
        validate_registration_password(config, input.password.expose_secret())
            .map_err(|_| AccessError::InvalidInput("password"))?;
        let password_hash = hash_password(input.password.expose_secret())?;
        self.initialize(
            Account {
                id: self.ids.next_id("acct"),
                email: input.email,
                password_hash,
                display_name: input.display_name,
                status: AccountStatus::Active,
                created_at: std::time::SystemTime::UNIX_EPOCH,
            },
            input.request_id,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        sync::{Arc, Mutex},
        time::{Duration, SystemTime, UNIX_EPOCH},
    };
    struct FixedClock;
    impl Clock for FixedClock {
        fn now(&self) -> SystemTime {
            UNIX_EPOCH + Duration::from_secs(100)
        }
    }
    struct Ids;
    impl IdGenerator for Ids {
        fn next_id(&self, prefix: &str) -> String {
            format!("{prefix}-id")
        }
    }
    struct Store(Arc<Mutex<Option<AccessBootstrap>>>);
    impl AccessBootstrapStore for Store {
        fn bootstrap_access(
            &self,
            plan: &AccessBootstrap,
        ) -> Result<AccessBootstrapResult, StoreError> {
            *self.0.lock().unwrap() = Some(AccessBootstrap {
                mode: plan.mode,
                account: plan.account.clone(),
                role_id: plan.role_id.clone(),
                binding_id: plan.binding_id.clone(),
                audit_id: plan.audit_id.clone(),
                request_id: plan.request_id.clone(),
            });
            Ok(AccessBootstrapResult::Initialized)
        }
    }
    #[test]
    fn bootstrap_validates_before_storage_and_uses_server_time() {
        let saved = Arc::new(Mutex::new(None));
        let service = CoreAccessBootstrapService::new(
            TenancyMode::Enabled,
            Store(saved.clone()),
            FixedClock,
            Ids,
        );
        let mut account = Account {
            id: "admin-id".into(),
            email: "admin@example.test".into(),
            password_hash: "fixture-only-hash".into(),
            display_name: None,
            status: AccountStatus::Disabled,
            created_at: UNIX_EPOCH,
        };
        assert_eq!(
            service.initialize(account.clone(), "request".into()),
            Err(AccessError::InvalidInput("bootstrap_account"))
        );
        assert!(saved.lock().unwrap().is_none());
        account.status = AccountStatus::Active;
        let mut missing = account.clone();
        missing.password_hash.clear();
        assert_eq!(
            service.initialize(missing, "request".into()),
            Err(AccessError::InvalidInput("bootstrap_account"))
        );
        assert_eq!(
            service.initialize(account, "request".into()),
            Ok(AccessBootstrapResult::Initialized)
        );
        let lock = saved.lock().unwrap();
        let plan = lock.as_ref().unwrap();
        assert_eq!(plan.mode(), TenancyMode::Enabled);
        assert_eq!(plan.account().created_at, FixedClock.now());
        assert_eq!(plan.role_id(), "role-id");
        assert_eq!(plan.binding_id(), "binding-id");
        assert_eq!(plan.audit_id(), "audit-id");
        assert_eq!(plan.request_id(), "request");
    }
    #[test]
    fn explicit_administrator_validates_and_hashes_password_before_bootstrap() {
        let saved = Arc::new(Mutex::new(None));
        let service = CoreAccessBootstrapService::new(
            TenancyMode::Enabled,
            Store(saved.clone()),
            FixedClock,
            Ids,
        );
        let config = AuthConfig {
            allow_local_registration: false,
            access_token_ttl_secs: 900,
            refresh_token_ttl_secs: 86400,
            session_ttl_secs: 604800,
            verification_code_ttl_secs: 900,
            password_min_length: 8,
            password_max_length: 128,
        };
        let input = || BootstrapAdministrator {
            email: "admin@example.test".into(),
            display_name: Some("Administrator".into()),
            password: SecretString::new("FixtureAdmin123"),
            request_id: "offline-request".into(),
        };
        for invalid in [
            BootstrapAdministrator {
                email: "invalid".into(),
                ..input()
            },
            BootstrapAdministrator {
                password: SecretString::new("short"),
                ..input()
            },
            BootstrapAdministrator {
                display_name: Some("\n".into()),
                ..input()
            },
        ] {
            assert!(matches!(
                service.initialize_administrator(&config, invalid),
                Err(AccessError::InvalidInput(_))
            ));
            assert!(saved.lock().unwrap().is_none());
        }
        assert!(!format!("{:?}", input()).contains("FixtureAdmin123"));
        assert_eq!(
            service.initialize_administrator(&config, input()),
            Ok(AccessBootstrapResult::Initialized)
        );
        let guard = saved.lock().unwrap();
        let account = guard.as_ref().unwrap().account();
        assert_eq!(account.email, "admin@example.test");
        assert_eq!(account.status, AccountStatus::Active);
        assert_eq!(account.created_at, FixedClock.now());
        assert!(account.password_hash.starts_with("$argon2id$"));
        assert_eq!(
            crate::service::password::verify_password(&account.password_hash, "FixtureAdmin123"),
            Ok(true)
        );
    }
}
