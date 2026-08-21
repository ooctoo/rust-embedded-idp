use std::time::SystemTime;

use crate::{
    Account, AccountDeviceBinding, AuthSession, DeviceNonceRecord, DeviceProof, DeviceRecord,
    DeviceStatus, IssuedTokenBundle, PageMetadata, PageRequest, TimePageCursor, MAX_PAGE_LIMIT,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisterAccountCommand {
    pub email: String,
    pub password: String,
    pub display_name: Option<String>,
    pub client_id: String,
    pub device_id: Option<String>,
}

impl RegisterAccountCommand {
    pub fn validate(&self) -> Result<(), ContractValidationError> {
        if self.email.trim().is_empty() {
            return Err(ContractValidationError::MissingEmail);
        }

        if !is_valid_email(&self.email) {
            return Err(ContractValidationError::InvalidEmail);
        }

        if self.password.trim().is_empty() {
            return Err(ContractValidationError::MissingPassword);
        }

        if self.client_id.trim().is_empty() {
            return Err(ContractValidationError::MissingClientId);
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisterAccountResult {
    pub account: Account,
    pub verification: PendingEmailVerification,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingEmailVerification {
    pub account_id: String,
    pub email: String,
    pub code: String,
    pub expires_at: SystemTime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginCommand {
    pub email: String,
    pub password: String,
    pub client_id: String,
    pub device_id: Option<String>,
}

impl LoginCommand {
    pub fn validate(&self) -> Result<(), ContractValidationError> {
        if self.email.trim().is_empty() {
            return Err(ContractValidationError::MissingEmail);
        }

        if self.password.trim().is_empty() {
            return Err(ContractValidationError::MissingPassword);
        }

        if self.client_id.trim().is_empty() {
            return Err(ContractValidationError::MissingClientId);
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginResult {
    pub account: Account,
    pub session: AuthSession,
    pub tokens: IssuedTokenBundle,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyEmailCommand {
    pub email: String,
    pub verification_code: String,
    pub client_id: String,
    pub device_id: Option<String>,
}

impl VerifyEmailCommand {
    pub fn validate(&self) -> Result<(), ContractValidationError> {
        if self.email.trim().is_empty() {
            return Err(ContractValidationError::MissingEmail);
        }

        if self.verification_code.trim().is_empty() {
            return Err(ContractValidationError::MissingVerificationCode);
        }

        if self.client_id.trim().is_empty() {
            return Err(ContractValidationError::MissingClientId);
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyEmailResult {
    pub account: Account,
    pub session: AuthSession,
    pub tokens: IssuedTokenBundle,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResendVerificationCodeCommand {
    pub email: String,
}

impl ResendVerificationCodeCommand {
    pub fn validate(&self) -> Result<(), ContractValidationError> {
        if self.email.trim().is_empty() {
            return Err(ContractValidationError::MissingEmail);
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResendVerificationCodeResult {
    pub account: Account,
    pub verification: PendingEmailVerification,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RotateRefreshTokenCommand {
    pub refresh_token: String,
}

impl RotateRefreshTokenCommand {
    pub fn validate(&self) -> Result<(), ContractValidationError> {
        if self.refresh_token.trim().is_empty() {
            return Err(ContractValidationError::MissingToken);
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RotateRefreshTokenResult {
    pub session: AuthSession,
    pub tokens: IssuedTokenBundle,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogoutSessionCommand {
    pub refresh_token: String,
}

impl LogoutSessionCommand {
    pub fn validate(&self) -> Result<(), ContractValidationError> {
        if self.refresh_token.trim().is_empty() {
            return Err(ContractValidationError::MissingToken);
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogoutSessionResult {
    pub session: AuthSession,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvisionDeviceCommand {
    pub client_id: String,
    pub device_name: String,
    pub requested_at: SystemTime,
}

impl ProvisionDeviceCommand {
    pub fn validate(&self) -> Result<(), ContractValidationError> {
        if self.client_id.trim().is_empty() {
            return Err(ContractValidationError::MissingClientId);
        }

        if self.device_name.trim().is_empty() {
            return Err(ContractValidationError::MissingDeviceName);
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvisionDeviceResult {
    pub device: DeviceRecord,
    pub nonce: DeviceNonceRecord,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompleteDeviceRegistrationCommand {
    pub device_id: String,
    pub proof: DeviceProof,
    pub completed_at: SystemTime,
}

impl CompleteDeviceRegistrationCommand {
    pub fn validate(&self) -> Result<(), ContractValidationError> {
        if self.device_id.trim().is_empty() {
            return Err(ContractValidationError::MissingDeviceId);
        }

        self.proof
            .validate()
            .map_err(ContractValidationError::InvalidDeviceProof)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompleteDeviceRegistrationResult {
    pub device: DeviceRecord,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindDeviceToAccountCommand {
    pub account_id: String,
    pub device_id: String,
    pub bound_at: SystemTime,
}

impl BindDeviceToAccountCommand {
    pub fn validate(&self) -> Result<(), ContractValidationError> {
        if self.account_id.trim().is_empty() {
            return Err(ContractValidationError::MissingAccountId);
        }

        if self.device_id.trim().is_empty() {
            return Err(ContractValidationError::MissingDeviceId);
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindDeviceToAccountResult {
    pub binding: AccountDeviceBinding,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetDeviceCommand {
    pub device_id: String,
}

impl GetDeviceCommand {
    pub fn validate(&self) -> Result<(), ContractValidationError> {
        if self.device_id.trim().is_empty() {
            return Err(ContractValidationError::MissingDeviceId);
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetDeviceResult {
    pub device: DeviceRecord,
    pub bindings: Vec<AccountDeviceBinding>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ListDevicesCommand {
    pub account_id: Option<String>,
    pub client_id: Option<String>,
    pub status: Option<DeviceStatus>,
    pub registered_after: Option<SystemTime>,
    pub registered_before: Option<SystemTime>,
    pub cursor: Option<TimePageCursor>,
    pub page: PageRequest,
}

impl ListDevicesCommand {
    pub fn validate(&self) -> Result<(), ContractValidationError> {
        if self
            .account_id
            .as_deref()
            .is_some_and(|account_id| account_id.trim().is_empty())
        {
            return Err(ContractValidationError::MissingAccountId);
        }

        if self
            .client_id
            .as_deref()
            .is_some_and(|client_id| client_id.trim().is_empty())
        {
            return Err(ContractValidationError::MissingClientId);
        }

        validate_cursor(&self.cursor, &self.page)?;
        validate_page_request(&self.page)?;
        validate_time_range(self.registered_after, self.registered_before)?;

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListDevicesResult {
    pub devices: Vec<DeviceRecord>,
    pub page: PageMetadata,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnbindDeviceFromAccountCommand {
    pub account_id: String,
    pub device_id: String,
    pub unbound_at: SystemTime,
}

impl UnbindDeviceFromAccountCommand {
    pub fn validate(&self) -> Result<(), ContractValidationError> {
        if self.account_id.trim().is_empty() {
            return Err(ContractValidationError::MissingAccountId);
        }

        if self.device_id.trim().is_empty() {
            return Err(ContractValidationError::MissingDeviceId);
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnbindDeviceFromAccountResult {
    pub binding: AccountDeviceBinding,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisableDeviceCommand {
    pub device_id: String,
}

impl DisableDeviceCommand {
    pub fn validate(&self) -> Result<(), ContractValidationError> {
        if self.device_id.trim().is_empty() {
            return Err(ContractValidationError::MissingDeviceId);
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisableDeviceResult {
    pub device: DeviceRecord,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevokeDeviceCommand {
    pub device_id: String,
}

impl RevokeDeviceCommand {
    pub fn validate(&self) -> Result<(), ContractValidationError> {
        if self.device_id.trim().is_empty() {
            return Err(ContractValidationError::MissingDeviceId);
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevokeDeviceResult {
    pub device: DeviceRecord,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceHeartbeatCommand {
    pub device_id: String,
    pub observed_at: SystemTime,
}

impl DeviceHeartbeatCommand {
    pub fn validate(&self) -> Result<(), ContractValidationError> {
        if self.device_id.trim().is_empty() {
            return Err(ContractValidationError::MissingDeviceId);
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceHeartbeatResult {
    pub device: DeviceRecord,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContractValidationError {
    MissingEmail,
    MissingPassword,
    MissingVerificationCode,
    PasswordTooShort { min_length: usize },
    PasswordTooLong { max_length: usize },
    InvalidEmail,
    PasswordRequiresLetter,
    PasswordRequiresNumber,
    MissingClientId,
    MissingResponseType,
    MissingRedirectUri,
    MissingGrantType,
    MissingAuthorizationCode,
    MissingToken,
    MissingSubjectAccountId,
    MissingSessionId,
    MissingAccountId,
    MissingDeviceId,
    MissingDeviceName,
    MissingCursorId,
    CursorWithOffsetUnsupported,
    InvalidPageLimit { max_limit: u32 },
    InvalidTimeRange,
    InvalidDeviceProof(crate::DeviceProofError),
}

fn validate_page_request(page: &PageRequest) -> Result<(), ContractValidationError> {
    if page.limit == 0 || page.limit > MAX_PAGE_LIMIT {
        return Err(ContractValidationError::InvalidPageLimit {
            max_limit: MAX_PAGE_LIMIT,
        });
    }

    Ok(())
}

fn is_valid_email(value: &str) -> bool {
    let email = value.trim();
    let Some((local, domain)) = email.split_once('@') else {
        return false;
    };
    !local.is_empty()
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && !domain.contains("..")
}

fn validate_time_range(
    after: Option<SystemTime>,
    before: Option<SystemTime>,
) -> Result<(), ContractValidationError> {
    if matches!((after, before), (Some(after), Some(before)) if after > before) {
        return Err(ContractValidationError::InvalidTimeRange);
    }

    Ok(())
}

fn validate_cursor(
    cursor: &Option<TimePageCursor>,
    page: &PageRequest,
) -> Result<(), ContractValidationError> {
    let Some(cursor) = cursor else {
        return Ok(());
    };

    if cursor.entity_id.trim().is_empty() {
        return Err(ContractValidationError::MissingCursorId);
    }

    if page.offset != 0 {
        return Err(ContractValidationError::CursorWithOffsetUnsupported);
    }

    Ok(())
}

pub trait AuthService: Send + Sync {
    fn register_account(
        &self,
        command: RegisterAccountCommand,
    ) -> Result<RegisterAccountResult, super::ServiceError>;

    fn login(&self, command: LoginCommand) -> Result<LoginResult, super::ServiceError>;

    fn verify_email(
        &self,
        command: VerifyEmailCommand,
    ) -> Result<VerifyEmailResult, super::ServiceError>;

    fn resend_verification_code(
        &self,
        command: ResendVerificationCodeCommand,
    ) -> Result<ResendVerificationCodeResult, super::ServiceError>;

    fn rotate_refresh_token(
        &self,
        command: RotateRefreshTokenCommand,
    ) -> Result<RotateRefreshTokenResult, super::ServiceError>;

    fn logout(
        &self,
        command: LogoutSessionCommand,
    ) -> Result<LogoutSessionResult, super::ServiceError>;
}

pub trait DeviceService: Send + Sync {
    fn provision_device(
        &self,
        command: ProvisionDeviceCommand,
    ) -> Result<ProvisionDeviceResult, super::ServiceError>;

    fn complete_device_registration(
        &self,
        command: CompleteDeviceRegistrationCommand,
    ) -> Result<CompleteDeviceRegistrationResult, super::ServiceError>;

    fn bind_device_to_account(
        &self,
        command: BindDeviceToAccountCommand,
    ) -> Result<BindDeviceToAccountResult, super::ServiceError>;

    fn get_device(&self, command: GetDeviceCommand)
        -> Result<GetDeviceResult, super::ServiceError>;

    fn list_devices(
        &self,
        command: ListDevicesCommand,
    ) -> Result<ListDevicesResult, super::ServiceError>;

    fn unbind_device_from_account(
        &self,
        command: UnbindDeviceFromAccountCommand,
    ) -> Result<UnbindDeviceFromAccountResult, super::ServiceError>;

    fn disable_device(
        &self,
        command: DisableDeviceCommand,
    ) -> Result<DisableDeviceResult, super::ServiceError>;

    fn revoke_device(
        &self,
        command: RevokeDeviceCommand,
    ) -> Result<RevokeDeviceResult, super::ServiceError>;

    fn heartbeat(
        &self,
        command: DeviceHeartbeatCommand,
    ) -> Result<DeviceHeartbeatResult, super::ServiceError>;
}

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use crate::{DeviceProof, TimePageCursor};

    use super::{
        BindDeviceToAccountCommand, CompleteDeviceRegistrationCommand, ContractValidationError,
        DeviceHeartbeatCommand, DisableDeviceCommand, GetDeviceCommand, ListDevicesCommand,
        LoginCommand, LogoutSessionCommand, ProvisionDeviceCommand, RegisterAccountCommand,
        ResendVerificationCodeCommand, RevokeDeviceCommand, RotateRefreshTokenCommand,
        UnbindDeviceFromAccountCommand, VerifyEmailCommand,
    };

    #[test]
    fn register_account_command_accepts_required_fields() {
        let command = RegisterAccountCommand {
            email: "user@example.com".to_string(),
            password: "password-1".to_string(),
            display_name: Some("Demo User".to_string()),
            client_id: "desktop-app".to_string(),
            device_id: Some("device-1".to_string()),
        };

        assert_eq!(command.validate(), Ok(()));
    }

    #[test]
    fn register_account_command_rejects_invalid_email() {
        let command = RegisterAccountCommand {
            email: "stu".to_string(),
            password: "password-1".to_string(),
            display_name: None,
            client_id: "desktop-app".to_string(),
            device_id: None,
        };

        assert_eq!(
            command.validate(),
            Err(ContractValidationError::InvalidEmail)
        );
    }

    #[test]
    fn login_command_rejects_missing_password() {
        let command = LoginCommand {
            email: "user@example.com".to_string(),
            password: String::new(),
            client_id: "desktop-app".to_string(),
            device_id: Some("device-1".to_string()),
        };

        assert_eq!(
            command.validate(),
            Err(ContractValidationError::MissingPassword)
        );
    }

    #[test]
    fn verify_email_command_requires_code_and_client() {
        let command = VerifyEmailCommand {
            email: "user@example.com".to_string(),
            verification_code: String::new(),
            client_id: String::new(),
            device_id: None,
        };

        assert_eq!(
            command.validate(),
            Err(ContractValidationError::MissingVerificationCode)
        );
    }

    #[test]
    fn resend_verification_code_requires_email() {
        let command = ResendVerificationCodeCommand {
            email: String::new(),
        };

        assert_eq!(
            command.validate(),
            Err(ContractValidationError::MissingEmail)
        );
    }

    #[test]
    fn rotate_and_device_commands_enforce_identifier_presence() {
        let rotate = RotateRefreshTokenCommand {
            refresh_token: String::new(),
        };
        let heartbeat = DeviceHeartbeatCommand {
            device_id: String::new(),
            observed_at: SystemTime::UNIX_EPOCH,
        };
        let logout = LogoutSessionCommand {
            refresh_token: String::new(),
        };
        assert_eq!(
            rotate.validate(),
            Err(ContractValidationError::MissingToken)
        );
        assert_eq!(
            heartbeat.validate(),
            Err(ContractValidationError::MissingDeviceId)
        );
        assert_eq!(
            logout.validate(),
            Err(ContractValidationError::MissingToken)
        );
    }

    #[test]
    fn device_provision_complete_and_bind_require_identifiers() {
        let provision = ProvisionDeviceCommand {
            client_id: String::new(),
            device_name: String::new(),
            requested_at: SystemTime::UNIX_EPOCH,
        };
        let complete = CompleteDeviceRegistrationCommand {
            device_id: String::new(),
            proof: DeviceProof {
                key_id: "key-1".to_string(),
                challenge: "nonce-1".to_string(),
                signature: "sig".to_string(),
                signed_at: SystemTime::UNIX_EPOCH,
            },
            completed_at: SystemTime::UNIX_EPOCH,
        };
        let bind = BindDeviceToAccountCommand {
            account_id: String::new(),
            device_id: String::new(),
            bound_at: SystemTime::UNIX_EPOCH,
        };
        let get_device = GetDeviceCommand {
            device_id: String::new(),
        };
        let list_devices = ListDevicesCommand {
            account_id: Some(String::new()),
            ..Default::default()
        };
        let unbind = UnbindDeviceFromAccountCommand {
            account_id: String::new(),
            device_id: String::new(),
            unbound_at: SystemTime::UNIX_EPOCH,
        };
        let disable = DisableDeviceCommand {
            device_id: String::new(),
        };
        let revoke = RevokeDeviceCommand {
            device_id: String::new(),
        };

        assert_eq!(
            provision.validate(),
            Err(ContractValidationError::MissingClientId)
        );
        assert_eq!(
            complete.validate(),
            Err(ContractValidationError::MissingDeviceId)
        );
        assert_eq!(
            bind.validate(),
            Err(ContractValidationError::MissingAccountId)
        );
        assert_eq!(
            get_device.validate(),
            Err(ContractValidationError::MissingDeviceId)
        );
        assert_eq!(
            list_devices.validate(),
            Err(ContractValidationError::MissingAccountId)
        );
        assert_eq!(
            ListDevicesCommand {
                page: crate::PageRequest {
                    limit: 0,
                    offset: 0,
                },
                ..Default::default()
            }
            .validate(),
            Err(ContractValidationError::InvalidPageLimit {
                max_limit: crate::MAX_PAGE_LIMIT,
            })
        );
        assert_eq!(
            ListDevicesCommand {
                cursor: Some(TimePageCursor {
                    sort_time: SystemTime::UNIX_EPOCH,
                    entity_id: "dev-1".to_string(),
                }),
                page: crate::PageRequest {
                    limit: 10,
                    offset: 1,
                },
                ..Default::default()
            }
            .validate(),
            Err(ContractValidationError::CursorWithOffsetUnsupported)
        );
        assert_eq!(
            unbind.validate(),
            Err(ContractValidationError::MissingAccountId)
        );
        assert_eq!(
            disable.validate(),
            Err(ContractValidationError::MissingDeviceId)
        );
        assert_eq!(
            revoke.validate(),
            Err(ContractValidationError::MissingDeviceId)
        );
    }
}
