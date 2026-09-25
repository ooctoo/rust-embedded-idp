use super::*;
use crate::{
    Account, AccountStatus, AuthConfig, Clock, EmailVerificationCode, IdGenerator, SecretString,
    StoreError, VerificationCodeGenerator,
};
use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const NOW: u64 = 1_000;

#[derive(Clone)]
struct Memory {
    inner: Arc<Mutex<Data>>,
    clock: TestClock,
}
#[derive(Clone)]
struct Data {
    mode: TenancyMode,
    tenants: BTreeMap<String, Tenant>,
    accounts: Vec<Account>,
    registration_tenants: BTreeMap<String, String>,
    memberships: Vec<TenantMembership>,
    verifications: Vec<EmailVerificationCode>,
    fail_create: bool,
    fail_activate: bool,
}
struct Tx {
    data: Data,
    tenant_id: String,
    clock: TestClock,
}
#[derive(Clone)]
struct TestClock(Arc<AtomicU64>);
#[derive(Clone, Copy)]
struct TestIds;
#[derive(Clone, Copy)]
struct TestCodes;

impl Clock for TestClock {
    fn now(&self) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(self.0.load(Ordering::SeqCst))
    }
}
impl IdGenerator for TestIds {
    fn next_id(&self, prefix: &str) -> String {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        format!("{prefix}-{}", NEXT.fetch_add(1, Ordering::SeqCst))
    }
}
impl VerificationCodeGenerator for TestCodes {
    fn generate_code(&self) -> String {
        "123456".into()
    }
}

fn config() -> AuthConfig {
    AuthConfig {
        allow_local_registration: true,
        access_token_ttl_secs: 900,
        refresh_token_ttl_secs: 86_400,
        session_ttl_secs: 604_800,
        verification_code_ttl_secs: 300,
        password_min_length: 8,
        password_max_length: 128,
    }
}
fn memory(mode: TenancyMode) -> Memory {
    let mut tenants = BTreeMap::new();
    tenants.insert(
        "0".into(),
        Tenant {
            id: "0".into(),
            name: "system".into(),
            status: TenantStatus::Active,
            allow_registration: true,
        },
    );
    if mode == TenancyMode::Enabled {
        tenants.insert(
            "t1".into(),
            Tenant {
                id: "t1".into(),
                name: "Tenant 1".into(),
                status: TenantStatus::Active,
                allow_registration: true,
            },
        );
        tenants.insert(
            "t2".into(),
            Tenant {
                id: "t2".into(),
                name: "Tenant 2".into(),
                status: TenantStatus::Active,
                allow_registration: true,
            },
        );
    }
    Memory {
        inner: Arc::new(Mutex::new(Data {
            mode,
            tenants,
            accounts: vec![],
            registration_tenants: BTreeMap::new(),
            memberships: vec![],
            verifications: vec![],
            fail_create: false,
            fail_activate: false,
        })),
        clock: TestClock(Arc::new(AtomicU64::new(NOW))),
    }
}
fn service(
    memory: Memory,
    mode: TenancyMode,
) -> CoreTenantRegistrationService<Memory, TestClock, TestIds, TestCodes> {
    let clock = memory.clock.clone();
    CoreTenantRegistrationService::new(mode, config(), memory, clock, TestIds, TestCodes).unwrap()
}
fn register_command(tenant_id: &str, email: &str, password: &str) -> RegisterTenantAccountCommand {
    RegisterTenantAccountCommand {
        tenant_id: tenant_id.into(),
        email: email.into(),
        password: SecretString::new(password),
        display_name: Some("Test user".into()),
    }
}
impl TenantRegistrationStore for Memory {
    fn create_registered_account(
        &self,
        registration: &TenantRegistration,
    ) -> Result<(), StoreError> {
        let mut data = self.inner.lock().unwrap().clone();
        let tenant = data
            .tenants
            .get(registration.registration_tenant_id())
            .ok_or(StoreError::NotFound("tenant"))?;
        if data.mode != TenancyMode::Enabled && registration.registration_tenant_id() != "0" {
            return Err(StoreError::Conflict("mode"));
        }
        if tenant.status != TenantStatus::Active || !tenant.allow_registration {
            return Err(StoreError::Conflict("registration_disabled"));
        }
        if data
            .accounts
            .iter()
            .any(|account| account.email == registration.account().email)
        {
            return Err(StoreError::Conflict("account.email"));
        }
        if data.fail_create {
            return Err(StoreError::Backend("create".into()));
        }
        data.accounts.push(registration.account().clone());
        data.registration_tenants.insert(
            registration.account().id.clone(),
            registration.registration_tenant_id().into(),
        );
        data.memberships.push(registration.membership().clone());
        data.verifications.push(registration.verification().clone());
        *self.inner.lock().unwrap() = data;
        Ok(())
    }
}
impl TenantEmailVerificationStore for Memory {
    type Transaction<'a> = Tx;
    fn verification_transaction<T, F>(
        &self,
        tenant_id: &str,
        operation: F,
    ) -> Result<T, TenantRegistrationError>
    where
        F: FnOnce(&mut Tx) -> Result<T, TenantRegistrationError>,
    {
        let mut guard = self.inner.lock().unwrap();
        let mut tx = Tx {
            data: guard.clone(),
            tenant_id: tenant_id.into(),
            clock: self.clock.clone(),
        };
        let result = operation(&mut tx);
        if result.is_ok() {
            *guard = tx.data;
        }
        result
    }
}
impl TenantEmailVerificationTransaction for Tx {
    fn load_verification_account(
        &mut self,
        email: &str,
    ) -> Result<Option<TenantVerificationAccount>, StoreError> {
        self.clock.0.fetch_add(1, Ordering::SeqCst);
        let Some(account) = self.data.accounts.iter().find(|a| a.email == email) else {
            return Ok(None);
        };
        let Some(tenant) = self.data.tenants.get(&self.tenant_id).cloned() else {
            return Ok(None);
        };
        let Some(membership) = self
            .data
            .memberships
            .iter()
            .find(|m| m.tenant_id == self.tenant_id && m.subject_id == account.id)
            .cloned()
        else {
            return Ok(None);
        };
        Ok(Some(TenantVerificationAccount {
            account_id: account.id.clone(),
            email: account.email.clone(),
            registration_tenant_id: self.data.registration_tenants[&account.id].clone(),
            tenant,
            membership,
            pending_verification: account.status == AccountStatus::PendingVerification,
        }))
    }
    fn replace_verification(&mut self, code: &EmailVerificationCode) -> Result<(), StoreError> {
        for previous in self
            .data
            .verifications
            .iter_mut()
            .filter(|v| v.account_id == code.account_id && v.consumed_at.is_none())
        {
            previous.consumed_at = Some(code.issued_at);
        }
        if self.data.fail_create {
            return Err(StoreError::Backend("replace".into()));
        }
        self.data.verifications.push(code.clone());
        Ok(())
    }
    fn load_verification(
        &mut self,
        email: &str,
        code: &str,
    ) -> Result<Option<TenantEmailVerificationState>, StoreError> {
        // Simulates a lock wait: the service must read its clock only after this returns.
        self.clock.0.fetch_add(1, Ordering::SeqCst);
        let verification = self
            .data
            .verifications
            .iter()
            .find(|v| v.email == email && v.code == code)
            .cloned();
        let Some(verification) = verification else {
            return Ok(None);
        };
        let Some(account) = self
            .data
            .accounts
            .iter()
            .find(|a| a.id == verification.account_id)
        else {
            return Ok(None);
        };
        let Some(registration_tenant_id) = self.data.registration_tenants.get(&account.id).cloned()
        else {
            return Ok(None);
        };
        let Some(membership) = self
            .data
            .memberships
            .iter()
            .find(|m| m.tenant_id == self.tenant_id && m.subject_id == account.id)
            .cloned()
        else {
            return Ok(None);
        };
        let Some(tenant) = self.data.tenants.get(&self.tenant_id).cloned() else {
            return Ok(None);
        };
        Ok(Some(TenantEmailVerificationState {
            registration_tenant_id,
            tenant,
            membership,
            account_pending_verification: account.status == AccountStatus::PendingVerification,
            verification,
        }))
    }
    fn activate_verified_account(
        &mut self,
        account_id: &str,
        verification_id: &str,
        now: SystemTime,
    ) -> Result<(), StoreError> {
        let account = self
            .data
            .accounts
            .iter_mut()
            .find(|a| a.id == account_id)
            .ok_or(StoreError::NotFound("account"))?;
        if account.status != AccountStatus::PendingVerification {
            return Err(StoreError::Conflict("account.status"));
        }
        let verification = self
            .data
            .verifications
            .iter_mut()
            .find(|v| v.id == verification_id)
            .ok_or(StoreError::NotFound("verification"))?;
        if verification.consumed_at.is_some() {
            return Err(StoreError::Conflict("verification.consumed"));
        }
        account.status = AccountStatus::Active;
        verification.consumed_at = Some(now);
        if self.data.fail_activate {
            return Err(StoreError::Backend("activate".into()));
        }
        Ok(())
    }
}

#[test]
fn registration_requires_real_tenant_in_enabled_and_only_zero_in_disabled() {
    for (mode, tenant, expected) in [
        (TenancyMode::Enabled, "0", false),
        (TenancyMode::Enabled, "t1", true),
        (TenancyMode::Disabled, "0", true),
        (TenancyMode::Disabled, "t1", false),
    ] {
        let db = memory(mode);
        if service(db.clone(), mode)
            .register_account(register_command(tenant, "user@example.com", "goodpass1"))
            .is_ok()
            != expected
        {
            panic!("unexpected registration result");
        }
    }
}

#[test]
fn registration_hashes_password_and_result_debug_redacts_secrets() {
    let db = memory(TenancyMode::Enabled);
    let result = service(db.clone(), TenancyMode::Enabled)
        .register_account(register_command("t1", "user@example.com", "goodpass1"))
        .unwrap();
    assert_eq!(result.verification_code.expose_secret(), "123456");
    assert!(!format!("{result:?}").contains("123456"));
    let data = db.inner.lock().unwrap();
    assert!(data.accounts[0].password_hash.starts_with("$argon2id$"));
    assert!(!data.accounts[0].password_hash.contains("goodpass1"));
    assert_eq!(data.memberships.len(), 1);
    assert_eq!(data.verifications.len(), 1);
}

#[test]
fn registration_rejects_password_config_and_duplicate_without_autobind() {
    let db = memory(TenancyMode::Enabled);
    let mut bad = config();
    bad.password_min_length = 0;
    assert!(CoreTenantRegistrationService::<Memory, _, _, _>::new(
        TenancyMode::Enabled,
        bad,
        db.clone(),
        db.clock.clone(),
        TestIds,
        TestCodes
    )
    .is_err());
    let svc = service(db.clone(), TenancyMode::Enabled);
    svc.register_account(register_command("t1", "user@example.com", "goodpass1"))
        .unwrap();
    assert!(matches!(
        svc.register_account(register_command("t2", "user@example.com", "goodpass1")),
        Err(TenantRegistrationError::Store(StoreError::Conflict(
            "account.email"
        )))
    ));
    assert_eq!(db.inner.lock().unwrap().memberships.len(), 1);
    assert!(matches!(
        svc.register_account(register_command("t1", "short", "bad")),
        Err(TenantRegistrationError::InvalidContract(_))
    ));
}

#[test]
fn verification_validates_tenant_state_code_and_returns_no_session() {
    let db = memory(TenancyMode::Enabled);
    let svc = service(db.clone(), TenancyMode::Enabled);
    let registered = svc
        .register_account(register_command("t1", "user@example.com", "goodpass1"))
        .unwrap();
    let verified = svc
        .verify_email(VerifyTenantEmailCommand {
            tenant_id: "t1".into(),
            email: "user@example.com".into(),
            verification_code: registered.verification_code.clone(),
        })
        .unwrap();
    assert_eq!(verified.tenant_id, "t1");
    assert_eq!(verified.account_id, registered.account_id);
    assert!(db.inner.lock().unwrap().accounts[0].status == AccountStatus::Active);
    assert!(matches!(
        svc.verify_email(VerifyTenantEmailCommand {
            tenant_id: "t1".into(),
            email: "user@example.com".into(),
            verification_code: registered.verification_code
        }),
        Err(TenantRegistrationError::InvalidVerificationCode)
    ));
}

#[test]
fn verification_stays_bound_to_original_registration_tenant() {
    let db = memory(TenancyMode::Enabled);
    let svc = service(db.clone(), TenancyMode::Enabled);
    let registered = svc
        .register_account(register_command("t1", "user@example.com", "goodpass1"))
        .unwrap();
    db.inner.lock().unwrap().memberships.push(TenantMembership {
        tenant_id: "t2".into(),
        subject_id: registered.account_id,
        status: MembershipStatus::Active,
        joined_at: UNIX_EPOCH + Duration::from_secs(NOW),
        version: 1,
    });
    assert!(matches!(
        svc.verify_email(VerifyTenantEmailCommand {
            tenant_id: "t2".into(),
            email: "user@example.com".into(),
            verification_code: registered.verification_code,
        }),
        Err(TenantRegistrationError::InvalidVerificationCode)
    ));
    assert_eq!(
        db.inner.lock().unwrap().accounts[0].status,
        AccountStatus::PendingVerification
    );
}

#[test]
fn verification_rejects_wrong_tenant_membership_status_code_and_time() {
    for scenario in 0..7 {
        let db = memory(TenancyMode::Enabled);
        let svc = service(db.clone(), TenancyMode::Enabled);
        let registered = svc
            .register_account(register_command(
                "t1",
                &format!("user{scenario}@example.com"),
                "goodpass1",
            ))
            .unwrap();
        if scenario == 1 {
            db.inner.lock().unwrap().memberships[0].status = MembershipStatus::Suspended;
        }
        if scenario == 2 {
            db.inner
                .lock()
                .unwrap()
                .tenants
                .get_mut("t1")
                .unwrap()
                .status = TenantStatus::Suspended;
        }
        if scenario == 3 {
            db.inner.lock().unwrap().verifications[0].code = "wrong".into();
        }
        if scenario == 4 {
            db.inner.lock().unwrap().verifications[0].issued_at =
                UNIX_EPOCH + Duration::from_secs(NOW + 10);
        }
        if scenario == 5 {
            db.inner.lock().unwrap().accounts[0].status = AccountStatus::Active;
        }
        if scenario == 6 {
            db.inner.lock().unwrap().verifications[0].expires_at =
                UNIX_EPOCH + Duration::from_secs(NOW);
        }
        let tenant = if scenario == 0 { "t2" } else { "t1" };
        let result = svc.verify_email(VerifyTenantEmailCommand {
            tenant_id: tenant.into(),
            email: format!("user{scenario}@example.com"),
            verification_code: registered.verification_code,
        });
        if scenario == 6 {
            assert!(matches!(
                result,
                Err(TenantRegistrationError::VerificationCodeExpired)
            ));
        } else {
            assert!(matches!(
                result,
                Err(TenantRegistrationError::InvalidVerificationCode)
            ));
        }
    }
}

#[test]
fn verification_failures_roll_back_account_and_code_activation() {
    for activate_failure in [false, true] {
        let db = memory(TenancyMode::Enabled);
        let svc = service(db.clone(), TenancyMode::Enabled);
        let registered = svc
            .register_account(register_command("t1", "user@example.com", "goodpass1"))
            .unwrap();
        db.inner.lock().unwrap().fail_activate = activate_failure;
        let result = svc.verify_email(VerifyTenantEmailCommand {
            tenant_id: "t1".into(),
            email: "user@example.com".into(),
            verification_code: registered.verification_code,
        });
        if activate_failure {
            assert!(matches!(
                result,
                Err(TenantRegistrationError::Store(StoreError::Backend(_)))
            ));
        } else {
            assert!(result.is_ok());
        }
        let data = db.inner.lock().unwrap();
        assert_eq!(
            data.accounts[0].status,
            if activate_failure {
                AccountStatus::PendingVerification
            } else {
                AccountStatus::Active
            }
        );
        assert_eq!(
            data.verifications[0].consumed_at.is_some(),
            !activate_failure
        );
    }
}

struct ChangingCodes(AtomicU64);
impl VerificationCodeGenerator for ChangingCodes {
    fn generate_code(&self) -> String {
        self.0.fetch_add(1, Ordering::SeqCst).to_string()
    }
}
fn resend_command(tenant: &str) -> ResendTenantVerificationCommand {
    ResendTenantVerificationCommand {
        tenant_id: tenant.into(),
        email: "user@example.com".into(),
    }
}
#[test]
fn resend_requires_original_tenant_pending_account_and_current_active_membership() {
    let db = memory(TenancyMode::Enabled);
    let registered = service(db.clone(), TenancyMode::Enabled)
        .register_account(register_command("t1", "user@example.com", "goodpass1"))
        .unwrap();
    let mut closed = config();
    closed.allow_local_registration = false;
    let svc = CoreTenantRegistrationService::new(
        TenancyMode::Enabled,
        closed,
        db.clone(),
        db.clock.clone(),
        TestIds,
        ChangingCodes(AtomicU64::new(200000)),
    )
    .unwrap();
    {
        let mut data = db.inner.lock().unwrap();
        data.tenants.get_mut("t1").unwrap().allow_registration = false;
        let mut member = data.memberships[0].clone();
        member.tenant_id = "t2".into();
        data.memberships.push(member);
    }
    assert_eq!(svc.resend_verification(resend_command("t2")).unwrap(), None);
    let mut absent = resend_command("t1");
    absent.email = "absent@example.com".into();
    assert_eq!(svc.resend_verification(absent).unwrap(), None);
    for status in [AccountStatus::Active, AccountStatus::Disabled] {
        db.inner.lock().unwrap().accounts[0].status = status;
        assert_eq!(svc.resend_verification(resend_command("t1")).unwrap(), None);
    }
    db.inner.lock().unwrap().accounts[0].status = AccountStatus::PendingVerification;
    db.inner.lock().unwrap().memberships[0].status = MembershipStatus::Suspended;
    assert_eq!(svc.resend_verification(resend_command("t1")).unwrap(), None);
    db.inner.lock().unwrap().memberships[0].status = MembershipStatus::Active;
    db.inner
        .lock()
        .unwrap()
        .tenants
        .get_mut("t1")
        .unwrap()
        .status = TenantStatus::Suspended;
    assert_eq!(svc.resend_verification(resend_command("t1")).unwrap(), None);
    db.inner
        .lock()
        .unwrap()
        .tenants
        .get_mut("t1")
        .unwrap()
        .status = TenantStatus::Active;
    let result = svc
        .resend_verification(resend_command("t1"))
        .unwrap()
        .unwrap();
    assert_eq!(result.account_id, registered.account_id);
    assert_eq!(result.verification_code.expose_secret(), "200000");
    assert_eq!(
        db.inner
            .lock()
            .unwrap()
            .verifications
            .iter()
            .filter(|v| v.consumed_at.is_none())
            .count(),
        1
    );
    assert!(svc
        .verify_email(VerifyTenantEmailCommand {
            tenant_id: "t1".into(),
            email: result.email.clone(),
            verification_code: registered.verification_code
        })
        .is_err());
    assert!(svc
        .verify_email(VerifyTenantEmailCommand {
            tenant_id: "t1".into(),
            email: result.email,
            verification_code: result.verification_code
        })
        .is_ok());
    assert_eq!(svc.resend_verification(resend_command("t1")).unwrap(), None);
}
#[test]
fn resend_reads_time_after_lock_and_rolls_back_retirement_when_insertion_fails() {
    let db = memory(TenancyMode::Disabled);
    let svc = CoreTenantRegistrationService::new(
        TenancyMode::Disabled,
        config(),
        db.clone(),
        db.clock.clone(),
        TestIds,
        ChangingCodes(AtomicU64::new(200000)),
    )
    .unwrap();
    let registered = svc
        .register_account(register_command("0", "user@example.com", "goodpass1"))
        .unwrap();
    db.inner.lock().unwrap().fail_create = true;
    assert!(svc.resend_verification(resend_command("0")).is_err());
    assert_eq!(db.inner.lock().unwrap().verifications.len(), 1);
    assert!(db.inner.lock().unwrap().verifications[0]
        .consumed_at
        .is_none());
    db.inner.lock().unwrap().fail_create = false;
    db.clock.0.store(NOW + 1000, Ordering::SeqCst);
    let result = svc
        .resend_verification(resend_command("0"))
        .unwrap()
        .unwrap();
    assert_eq!(
        result.verification_expires_at,
        UNIX_EPOCH + Duration::from_secs(NOW + 1001 + config().verification_code_ttl_secs)
    );
    assert_ne!(result.verification_code, registered.verification_code);
    assert!(svc.resend_verification(resend_command("t1")).is_err());
}
