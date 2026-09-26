use super::*;
use crate::access::{
    service::{finish_page, time_page_key},
    AccessListScope, AccessPage, AccessPageRequest,
};
use crate::{AdminClientRecord, ClientSecretHasher, OidcClient, OidcClientType, SecretString};

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AdminClientFilter {
    pub client_type: Option<OidcClientType>,
    pub pkce_required: Option<bool>,
}
impl AdminClientFilter {
    pub fn matches(&self, client: &AdminClientRecord) -> bool {
        self.client_type.is_none_or(|v| v == client.client_type)
            && self.pkce_required.is_none_or(|v| v == client.pkce_required)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminUpsertClient {
    pub client_id: String,
    pub client_name: String,
    pub redirect_uris: Vec<String>,
    pub client_type: OidcClientType,
    pub pkce_required: bool,
    /// None preserves an existing confidential secret. Public clients reject secrets.
    pub client_secret: Option<SecretString>,
}
impl AdminUpsertClient {
    fn validate(&self) -> Result<(), AccessError> {
        validate_id(&self.client_id, 128, "client_id")?;
        if self.client_name.trim().is_empty()
            || self.client_name.len() > 256
            || self.client_name.chars().any(char::is_control)
        {
            return Err(AccessError::InvalidInput("client_name"));
        }
        if self.redirect_uris.len() > 32
            || self
                .redirect_uris
                .iter()
                .any(|u| u.len() > 2048 || u.chars().any(char::is_control))
        {
            return Err(AccessError::InvalidInput("redirect_uris"));
        }
        if let Some(secret) = &self.client_secret {
            if self.client_type == OidcClientType::PublicDesktop
                || secret.expose_secret().trim().is_empty()
                || secret.expose_secret().len() > 4096
            {
                return Err(AccessError::InvalidInput("client_secret"));
            }
        }
        // Reuse client-type, PKCE and redirect rules before invoking a hasher.
        self.client(Some("validation-only".into()))
            .validate()
            .map_err(|_| AccessError::InvalidInput("client_config"))
    }
    fn client(&self, secret: Option<String>) -> OidcClient {
        OidcClient {
            client_id: self.client_id.clone(),
            client_name: self.client_name.clone(),
            redirect_uris: self.redirect_uris.clone(),
            client_type: self.client_type,
            pkce_required: self.pkce_required,
            client_secret_hash: if self.client_type == OidcClientType::PublicDesktop {
                None
            } else {
                secret
            },
        }
    }
}

/// Deployment-level clients; no caller-selected tenant or login policy.
pub trait ClientAdminService: Send + Sync {
    fn list_clients(
        &self,
        context: AccessAdminContext,
        filter: AdminClientFilter,
        page: AccessPageRequest,
    ) -> Result<AccessPage<AdminClientRecord>, AccessError>;
    fn get_client(
        &self,
        context: AccessAdminContext,
        client_id: String,
    ) -> Result<AdminClientRecord, AccessError>;
    fn upsert_client(
        &self,
        context: AccessAdminContext,
        command: AdminUpsertClient,
    ) -> Result<AccessAuditEvent, AccessError>;
}
pub struct CoreClientAdminService<S, C, I, H> {
    admin: CoreAccessAdminService<S, C, I>,
    hasher: H,
}
impl<S, C, I, H> CoreClientAdminService<S, C, I, H> {
    pub fn new(admin: CoreAccessAdminService<S, C, I>, hasher: H) -> Self {
        Self { admin, hasher }
    }
}
impl<
        S: AccessAdminStore,
        C: Clock + Send + Sync,
        I: IdGenerator + Send + Sync,
        H: ClientSecretHasher + Send + Sync,
    > ClientAdminService for CoreClientAdminService<S, C, I, H>
{
    fn list_clients(
        &self,
        context: AccessAdminContext,
        filter: AdminClientFilter,
        page: AccessPageRequest,
    ) -> Result<AccessPage<AdminClientRecord>, AccessError> {
        let scope = AccessListScope::AdminClients {
            filter: filter.clone(),
        };
        page.validate(&scope)?;
        self.admin.store.admin_transaction(|tx| {
            self.admin.authorize_management_read(
                tx,
                &context,
                SYSTEM_TENANT_ID,
                AccessAdminOperation::ManageClients,
            )?;
            let rows = tx.admin_clients(&filter, &page)?;
            if rows.iter().any(|c| !filter.matches(c)) {
                return Err(AccessError::InvalidStoreResponse);
            }
            finish_page(rows, page, scope, |c| {
                time_page_key(
                    c.created_at.unwrap_or(SystemTime::UNIX_EPOCH),
                    c.client_id.clone(),
                )
            })
        })
    }
    fn get_client(
        &self,
        context: AccessAdminContext,
        client_id: String,
    ) -> Result<AdminClientRecord, AccessError> {
        validate_id(&client_id, 128, "client_id")?;
        self.admin.store.admin_transaction(|tx| {
            self.admin.authorize_management_read(
                tx,
                &context,
                SYSTEM_TENANT_ID,
                AccessAdminOperation::ManageClients,
            )?;
            let c = tx
                .admin_client(&client_id)?
                .ok_or(AccessError::NotFound("client"))?;
            if c.client_id != client_id {
                return Err(AccessError::InvalidStoreResponse);
            }
            Ok(client_metadata(c))
        })
    }
    fn upsert_client(
        &self,
        context: AccessAdminContext,
        command: AdminUpsertClient,
    ) -> Result<AccessAuditEvent, AccessError> {
        command.validate()?;
        self.admin.store.admin_transaction(|tx| {
            self.admin.authorize_management(
                tx,
                &context,
                SYSTEM_TENANT_ID,
                AccessAdminOperation::ManageClients,
                true,
                None,
            )?;
            let before = tx.admin_client(&command.client_id)?;
            if before
                .as_ref()
                .is_some_and(|c| c.client_id != command.client_id)
            {
                return Err(AccessError::InvalidStoreResponse);
            }
            // ponytail: hashing holds the platform write lock; prepare hashes before
            // locking only if measured management traffic warrants a two-stage path.
            let secret = match &command.client_secret {
                Some(raw) => Some(
                    self.hasher
                        .hash_client_secret(raw.expose_secret())
                        // Provider error text can contain secret material.
                        .map_err(|_| {
                            AccessError::Store(StoreError::Backend(
                                "client secret hashing failed".into(),
                            ))
                        })?,
                ),
                None => before.as_ref().and_then(|c| c.client_secret_hash.clone()),
            };
            let after = command.client(secret);
            after
                .validate()
                .map_err(|_| AccessError::InvalidInput("client_config"))?;
            let secret_changed = before.as_ref().and_then(|c| c.client_secret_hash.as_ref())
                != after.client_secret_hash.as_ref();
            let now = self.admin.clock.now();
            // Hashing may take time. Never commit on authority that expired meanwhile.
            if !tx.actor_is_active(&context.actor, now)? {
                return Err(AccessError::Forbidden);
            }
            tx.upsert_admin_client(&after, now)?;
            let event = AccessAuditEvent {
                id: self.admin.new_id("audit")?,
                occurred_at: now,
                context,
                tenant_id: SYSTEM_TENANT_ID.into(),
                operation: "client.upsert",
                change: AccessChange::Client {
                    before: before.map(client_metadata),
                    after: client_metadata(after),
                    secret_changed,
                },
            };
            tx.append_audit(&event)?;
            Ok(event)
        })
    }
}
pub fn client_metadata(client: OidcClient) -> AdminClientRecord {
    AdminClientRecord {
        client_id: client.client_id,
        client_name: client.client_name,
        redirect_uris: client.redirect_uris,
        client_type: client.client_type,
        pkce_required: client.pkce_required,
        client_secret_configured: client
            .client_secret_hash
            .is_some_and(|s| !s.trim().is_empty()),
        created_at: None,
    }
}
