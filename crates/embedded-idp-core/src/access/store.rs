use super::{
    AccessPageRequest, AccessQuery, PermissionDefinition, Role, SubjectTenant, TenantRegistration,
};
use crate::StoreError;

/// A trusted infrastructure port, separate from the legacy StoreTransaction.
///
/// Every check must use current account, tenant, membership, role and permission
/// state in one snapshot. Match RoleBinding::grants; missing/inactive rows deny.
/// No cross-request allow cache. Postgres implementations must execute a batch
/// in ONE round trip, without materializing every role or resource of the user.
pub trait AccessReadStore: Send + Sync {
    /// Return exactly one result per query in input order (including duplicates).
    fn check_active_grants(&self, queries: &[AccessQuery]) -> Result<Vec<bool>, StoreError>;

    /// Explicit tenant filters, distinct role IDs, bytewise ID order, limit + 1.
    /// Role state is returned for display; a disabled role is not an active grant.
    fn list_subject_roles(
        &self,
        tenant_id: &str,
        subject_id: &str,
        page: &AccessPageRequest,
    ) -> Result<Vec<Role>, StoreError>;

    /// Explicit tenant + role filter; bytewise (resource_type, action) order.
    /// Include disabled definitions for display, never for a grant decision.
    fn list_role_permissions(
        &self,
        tenant_id: &str,
        role_id: &str,
        page: &AccessPageRequest,
    ) -> Result<Vec<PermissionDefinition>, StoreError>;

    /// Only this subject's non-removed REAL tenant memberships, tenant ID order.
    /// Used after trusted authentication with ChooseAfterAuthentication policy.
    fn list_subject_tenants(
        &self,
        subject_id: &str,
        page: &AccessPageRequest,
    ) -> Result<Vec<SubjectTenant>, StoreError>;
}

/// Atomic persistence used by CoreTenantRegistrationService.
/// Recheck that the tenant is active and accepts registration, then atomically
/// insert the account (with registration_tenant_id), initial membership and
/// tenant-bound verification record. A duplicate identity MUST NOT auto-bind it
/// to another tenant. Any failure rolls back all three writes. No tokens issued.
/// No implementation is wired to the legacy public registration flow yet.
pub trait TenantRegistrationStore: Send + Sync {
    fn create_registered_account(
        &self,
        registration: &TenantRegistration,
    ) -> Result<(), StoreError>;
}
