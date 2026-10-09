use super::super::*;
use super::{EncryptedScanResult, ScanLoginMode};
use crate::{DeviceProofPresentation, DeviceRequestBinding, SecretString, StoreError};
use std::time::SystemTime;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanGrantState {
    WaitingUser,
    WaitingDevice,
    AwaitingApproval,
    Approved,
    Issued,
    Denied,
    Cancelled,
    Expired,
    Invalidated,
}
impl ScanGrantState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WaitingUser => "waiting_user",
            Self::WaitingDevice => "waiting_device",
            Self::AwaitingApproval => "awaiting_approval",
            Self::Approved => "approved",
            Self::Issued => "issued",
            Self::Denied => "denied",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
            Self::Invalidated => "invalidated",
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanDeliveryState {
    Recoverable,
    Acknowledged,
    Revoked,
}
impl ScanDeliveryState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Recoverable => "recoverable",
            Self::Acknowledged => "acknowledged",
            Self::Revoked => "revoked",
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanSourceReference {
    pub account_id: String,
    pub session_id: String,
    pub client_id: String,
    pub authenticated_at: SystemTime,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanTargetReference {
    pub device_id: String,
    pub key_id: String,
    pub device_version: u64,
    pub key_version: u64,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanGrantRecord {
    pub tenant_id: String,
    pub host_scope: String,
    pub entry_id: String,
    pub id: String,
    pub mode: ScanLoginMode,
    pub target_client_id: String,
    pub state: ScanGrantState,
    pub version: u64,
    pub source: Option<ScanSourceReference>,
    pub target: Option<ScanTargetReference>,
    pub code_digest: [u8; 32],
    pub presentation: Option<EncryptedScanResult>,
    pub delivery_secret_hash: Option<[u8; 32]>,
    pub confirmation_revision: Option<String>,
    pub created_at: SystemTime,
    pub expires_at: SystemTime,
    pub code_expires_at: SystemTime,
    pub approved_until: Option<SystemTime>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanOperationRecord {
    pub tenant_id: String,
    pub host_scope: String,
    pub entry_id: String,
    pub actor_id: String,
    pub action: String,
    pub operation_id: String,
    pub fingerprint: [u8; 32],
    pub grant_id: String,
    pub created_at: SystemTime,
}
/// Original native operations that can be stopped before their result is known.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanOriginAction {
    Create,
    Claim,
}
impl ScanOriginAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Claim => "claim",
        }
    }
}
/// Durable denial of the scoped original operation. Cleanup must retain this
/// record (or an equivalent denial index), even after its grant is archived.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanOriginClosure {
    pub tenant_id: String,
    pub host_scope: String,
    pub entry_id: String,
    pub device_id: String,
    pub origin_action: ScanOriginAction,
    pub origin_operation_id: String,
    pub delivery_secret_hash: [u8; 32],
    pub grant_id: Option<String>,
    pub closed_by_key_id: String,
    pub closed_at: SystemTime,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanDeliveryRecord {
    pub tenant_id: String,
    pub grant_id: String,
    pub issuance_operation_id: String,
    pub session_id: String,
    pub state: ScanDeliveryState,
    pub binding_id: String,
    pub binding_version: u64,
    pub result: Option<EncryptedScanResult>,
    pub receipt_nonce_hash: Option<[u8; 32]>,
    pub recover_until: SystemTime,
    pub created_at: SystemTime,
    pub release_authorized_at: Option<SystemTime>,
    pub acknowledged_at: Option<SystemTime>,
    pub revoked_at: Option<SystemTime>,
    pub reason: Option<String>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanBindingSnapshot {
    pub id: String,
    pub version: u64,
    pub status: crate::AccountDeviceBindingStatus,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanAuditEvent {
    pub id: String,
    pub tenant_id: String,
    pub host_scope: String,
    pub grant_id: String,
    pub actor_kind: String,
    pub actor_id: Option<String>,
    pub operation: String,
    pub operation_id: String,
    pub session_id: Option<String>,
    pub decision_id: Option<String>,
    pub occurred_at: SystemTime,
}

/// Same identity transaction and lock ordering as login/refresh. No method commits.
pub trait TenantScanLoginTransaction:
    TenantDeviceLoginTransaction + TenantRefreshTransaction
{
    fn find_scan_grant(
        &mut self,
        tenant: &str,
        scope: &str,
        entry: &str,
        id: &str,
    ) -> Result<Option<ScanGrantRecord>, StoreError>;
    fn find_scan_code(
        &mut self,
        tenant: Option<&str>,
        scope: &str,
        entry: &str,
        digest: &[u8; 32],
    ) -> Result<Option<ScanGrantRecord>, StoreError>;
    fn lock_scan_grant(
        &mut self,
        tenant: &str,
        id: &str,
    ) -> Result<Option<ScanGrantRecord>, StoreError>;
    fn insert_scan_grant(&mut self, grant: &ScanGrantRecord) -> Result<(), StoreError>;
    fn update_scan_grant(
        &mut self,
        grant: &ScanGrantRecord,
        expected_version: u64,
    ) -> Result<(), StoreError>;
    fn find_scan_operation(
        &mut self,
        tenant: &str,
        scope: &str,
        entry: &str,
        actor: &str,
        action: &str,
        id: &str,
    ) -> Result<Option<ScanOperationRecord>, StoreError>;
    fn insert_scan_operation(&mut self, record: &ScanOperationRecord) -> Result<(), StoreError>;
    fn find_scan_origin_closure(
        &mut self,
        tenant: &str,
        scope: &str,
        entry: &str,
        device: &str,
        action: ScanOriginAction,
        operation_id: &str,
    ) -> Result<Option<ScanOriginClosure>, StoreError>;
    fn insert_scan_origin_closure(&mut self, closure: &ScanOriginClosure)
        -> Result<(), StoreError>;

    fn lock_scan_delivery(
        &mut self,
        tenant: &str,
        grant: &str,
    ) -> Result<Option<ScanDeliveryRecord>, StoreError>;
    fn find_scan_delivery(
        &mut self,
        tenant: &str,
        grant: &str,
    ) -> Result<Option<ScanDeliveryRecord>, StoreError>;
    fn scan_grant_tenant(
        &mut self,
        scope: &str,
        entry: &str,
        id: &str,
    ) -> Result<Option<String>, StoreError>;
    fn insert_scan_delivery(&mut self, record: &ScanDeliveryRecord) -> Result<(), StoreError>;
    fn update_scan_delivery(
        &mut self,
        record: &ScanDeliveryRecord,
        expected: ScanDeliveryState,
    ) -> Result<(), StoreError>;
    fn scan_binding_snapshot(
        &mut self,
        tenant: &str,
        account: &str,
        device: &str,
    ) -> Result<Option<ScanBindingSnapshot>, StoreError>;
    fn scan_account_label(&mut self, account: &str) -> Result<String, StoreError>;
    fn activate_scan_session(&mut self, tenant: &str, session: &str) -> Result<(), StoreError>;
    fn revoke_scan_session(
        &mut self,
        tenant: &str,
        session: &str,
        now: SystemTime,
    ) -> Result<(), StoreError>;
    fn expired_scan_deliveries(
        &mut self,
        scope: &str,
        entry: &str,
        now: SystemTime,
        limit: u32,
    ) -> Result<Vec<ScanGrantRecord>, StoreError>;
    fn append_scan_audit(&mut self, event: &ScanAuditEvent) -> Result<(), StoreError>;
    fn pending_scan_count(
        &mut self,
        tenant: &str,
        scope: &str,
        entry: &str,
        source: Option<&str>,
        device: Option<&str>,
        now: SystemTime,
    ) -> Result<u64, StoreError>;
}

pub trait TenantScanLoginStore: TenantAuthStore {
    fn scan_transaction<R>(
        &self,
        mode: TenancyMode,
        run: impl FnOnce(&mut Self::Transaction<'_>) -> Result<R, ScanLoginError>,
    ) -> Result<R, ScanLoginError>;
}

#[derive(Debug, Clone)]
pub struct TrustedScanHostContext {
    scope: String,
    valid_until: SystemTime,
}
impl TrustedScanHostContext {
    pub fn new(scope: String, valid_until: SystemTime) -> Self {
        Self { scope, valid_until }
    }
    pub fn scope(&self) -> &str {
        &self.scope
    }
    pub fn valid_until(&self) -> SystemTime {
        self.valid_until
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanAdmissionStage {
    CreateDevice,
    IssuePhoneCode,
    AttachSource,
    ClaimTarget,
    InspectConfirmation,
    Approve,
    Exchange,
    ReleaseResult,
    ActivateSession,
}
#[derive(Debug, Clone)]
pub struct ScanAdmissionRequest {
    pub stage: ScanAdmissionStage,
    pub host_scope: String,
    pub entry_id: String,
    pub tenant_id: String,
    pub mode: ScanLoginMode,
    pub source: Option<ScanSourceReference>,
    pub target: Option<ScanTargetReference>,
    pub grant_id: Option<String>,
    pub operation_id: Option<String>,
    pub request_fingerprint: [u8; 32],
}
#[derive(Debug, Clone)]
pub enum ScanAdmissionDecision {
    Allow {
        decision_id: String,
        policy_revision: String,
        valid_until: SystemTime,
    },
    Deny {
        reason: String,
    },
}
pub trait ScanLoginAdmission: Send + Sync {
    fn authorize(
        &self,
        request: &ScanAdmissionRequest,
        context: &TrustedScanHostContext,
    ) -> Result<ScanAdmissionDecision, ScanLoginError>;
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanTargetPresentation {
    pub display_name: String,
    pub identification: String,
    pub context_label: Option<String>,
    pub revision: String,
}
pub trait ScanTargetPresentationProvider: Send + Sync {
    fn describe(
        &self,
        request: &ScanAdmissionRequest,
        context: &TrustedScanHostContext,
    ) -> Result<ScanTargetPresentation, ScanLoginError>;
}

#[derive(Debug, Clone)]
pub struct ScanDeviceCall {
    pub entry_id: String,
    pub proof: DeviceProofPresentation,
    pub binding: DeviceRequestBinding,
    pub host: TrustedScanHostContext,
}
#[derive(Debug, Clone)]
pub struct ScanSourceCall {
    pub source: AuthenticatedBrowserSession,
    pub host: TrustedScanHostContext,
}
#[derive(Debug, Clone)]
pub struct CreateDeviceScan {
    pub operation_id: String,
    pub entry_id: String,
    pub tenant_id: String,
    pub delivery_secret_hash: [u8; 32],
}
#[derive(Debug, Clone)]
pub struct IssuePhoneScan {
    pub operation_id: String,
    pub entry_id: String,
}
#[derive(Debug, Clone)]
pub struct AttachScanSource {
    pub operation_id: String,
    pub display_code: SecretString,
}
#[derive(Debug, Clone)]
pub struct ClaimScanTarget {
    pub operation_id: String,
    pub entry_id: String,
    pub tenant_id: String,
    pub scan_code: SecretString,
    pub delivery_secret_hash: [u8; 32],
}
#[derive(Debug, Clone)]
pub struct SourceGrantAction {
    pub operation_id: String,
    pub grant_id: String,
}
#[derive(Debug, Clone)]
pub struct ApproveScan {
    pub action: SourceGrantAction,
    pub confirmation_revision: String,
}
#[derive(Debug, Clone)]
pub struct DeviceGrantAccess {
    pub grant_id: String,
    pub delivery_secret: SecretString,
}
#[derive(Debug, Clone)]
pub struct ExchangeScan {
    pub operation_id: String,
    pub access: DeviceGrantAccess,
}
#[derive(Debug, Clone)]
pub struct RecoverScan {
    pub issuance_operation_id: String,
    pub access: DeviceGrantAccess,
}
#[derive(Debug, Clone)]
pub struct AcknowledgeScan {
    pub operation_id: String,
    pub issuance_operation_id: String,
    pub access: DeviceGrantAccess,
    pub receipt_nonce: SecretString,
}
#[derive(Debug, Clone)]
pub struct CancelDeviceScan {
    pub operation_id: String,
    pub access: DeviceGrantAccess,
}
#[derive(Debug, Clone)]
pub struct AbortScanDelivery {
    pub operation_id: String,
    pub issuance_operation_id: String,
    pub access: DeviceGrantAccess,
}
/// Close the original operation with a fresh device proof and its persisted
/// delivery secret. No phone code or live source session is required.
#[derive(Debug, Clone)]
pub struct CloseScanOrigin {
    pub entry_id: String,
    pub tenant_id: String,
    pub origin_action: ScanOriginAction,
    pub origin_operation_id: String,
    pub delivery_secret: SecretString,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanOriginCloseOutcome {
    Closed,
    AlreadyActivated,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanOriginCloseResult {
    pub origin_action: ScanOriginAction,
    pub origin_operation_id: String,
    pub outcome: ScanOriginCloseOutcome,
    pub closed_at: Option<SystemTime>,
    pub progress: Option<ScanProgress>,
}
#[derive(Debug, Clone)]
pub struct LookupDeviceScan {
    /// Specify the original action to confirm closure. None supports legacy
    /// committed-result lookup but cannot conclusively identify a closed action.
    pub origin_action: Option<ScanOriginAction>,
    pub origin_operation_id: String,
    pub entry_id: String,
    pub tenant_id: String,
    pub delivery_secret: SecretString,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanLoginError {
    InvalidRequest,
    NotFound,
    SourceClientNotAllowed,
    AdmissionDenied,
    AdmissionUnavailable,
    ModeDisabled,
    AlreadyClaimed,
    ConfirmationChanged,
    NotApproved,
    OperationConflict,
    OriginOperationClosed,
    ExchangeAlreadyStarted(String),
    AlreadyIssued,
    Expired,
    Cancelled,
    Denied,
    Invalidated,
    AlreadyAcknowledged,
    DeliveryExpired,
    DeliveryRevoked,
    RateLimited,
    ResultUnavailable,
    Auth(TenantAuthError),
    Store(StoreError),
}
impl From<TenantAuthError> for ScanLoginError {
    fn from(e: TenantAuthError) -> Self {
        Self::Auth(e)
    }
}
impl From<StoreError> for ScanLoginError {
    fn from(e: StoreError) -> Self {
        Self::Store(e)
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanProgress {
    pub grant_id: String,
    pub mode: ScanLoginMode,
    pub state: ScanGrantState,
    pub version: u64,
    pub server_time: SystemTime,
    pub expires_at: SystemTime,
    pub code_expires_at: SystemTime,
    pub approved_until: Option<SystemTime>,
    pub poll_after_ms: u32,
    pub delivery_state: Option<ScanDeliveryState>,
    pub issuance_operation_id: Option<String>,
    pub recover_until: Option<SystemTime>,
    pub next_action: String,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanConfirmation {
    pub progress: ScanProgress,
    pub source: ScanSourceReference,
    pub source_display_name: String,
    pub target: ScanTargetReference,
    pub presentation: ScanTargetPresentation,
    pub confirmation_revision: String,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreatedDeviceScan {
    pub progress: ScanProgress,
    pub display_code: SecretString,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuedPhoneScan {
    pub progress: ScanProgress,
    pub scan_code: SecretString,
    pub code_expires_at: SystemTime,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceScanLookup {
    pub progress: ScanProgress,
    pub origin_operation_id: String,
    pub display_code: Option<SecretString>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanDeliveryResult {
    Bundle {
        progress: ScanProgress,
        session: TenantLoginSession,
        receipt_nonce: SecretString,
    },
    Progress(ScanProgress),
}

pub trait TenantDeviceScanLoginService: Send + Sync {
    fn close_origin(
        &self,
        c: CloseScanOrigin,
        actor: ScanDeviceCall,
    ) -> Result<ScanOriginCloseResult, ScanLoginError>;
    fn entry_config(&self) -> super::ScanLoginEntryConfig;
    fn create_device(
        &self,
        c: CreateDeviceScan,
        actor: ScanDeviceCall,
    ) -> Result<CreatedDeviceScan, ScanLoginError>;
    fn issue_phone(
        &self,
        c: IssuePhoneScan,
        actor: ScanSourceCall,
    ) -> Result<IssuedPhoneScan, ScanLoginError>;
    fn attach_source(
        &self,
        c: AttachScanSource,
        actor: ScanSourceCall,
    ) -> Result<ScanConfirmation, ScanLoginError>;
    fn claim_target(
        &self,
        c: ClaimScanTarget,
        actor: ScanDeviceCall,
    ) -> Result<ScanProgress, ScanLoginError>;
    fn inspect(
        &self,
        grant_id: String,
        actor: ScanSourceCall,
    ) -> Result<ScanConfirmation, ScanLoginError>;
    fn approve(
        &self,
        c: ApproveScan,
        actor: ScanSourceCall,
    ) -> Result<ScanProgress, ScanLoginError>;
    fn deny(
        &self,
        c: SourceGrantAction,
        actor: ScanSourceCall,
    ) -> Result<ScanProgress, ScanLoginError>;
    fn cancel_source(
        &self,
        c: SourceGrantAction,
        actor: ScanSourceCall,
    ) -> Result<ScanProgress, ScanLoginError>;
    fn cancel_device(
        &self,
        c: CancelDeviceScan,
        actor: ScanDeviceCall,
    ) -> Result<ScanProgress, ScanLoginError>;
    fn source_status(
        &self,
        grant_id: String,
        actor: ScanSourceCall,
    ) -> Result<ScanProgress, ScanLoginError>;
    fn device_status(
        &self,
        c: DeviceGrantAccess,
        actor: ScanDeviceCall,
    ) -> Result<ScanProgress, ScanLoginError>;
    fn lookup_device(
        &self,
        c: LookupDeviceScan,
        actor: ScanDeviceCall,
    ) -> Result<DeviceScanLookup, ScanLoginError>;
    fn exchange(
        &self,
        c: ExchangeScan,
        actor: ScanDeviceCall,
    ) -> Result<ScanDeliveryResult, ScanLoginError>;
    fn recover(
        &self,
        c: RecoverScan,
        actor: ScanDeviceCall,
    ) -> Result<ScanDeliveryResult, ScanLoginError>;
    fn acknowledge(
        &self,
        c: AcknowledgeScan,
        actor: ScanDeviceCall,
    ) -> Result<ScanProgress, ScanLoginError>;
    fn abort_delivery(
        &self,
        c: AbortScanDelivery,
        actor: ScanDeviceCall,
    ) -> Result<ScanProgress, ScanLoginError>;
    fn compensate(
        &self,
        host: TrustedScanHostContext,
        grant_id: String,
        issuance_operation_id: String,
        operation_id: String,
    ) -> Result<ScanProgress, ScanLoginError>;
    fn cleanup(&self, host: TrustedScanHostContext, limit: u32) -> Result<u32, ScanLoginError>;
}
