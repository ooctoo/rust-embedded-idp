//! Optional offline management-client preparation, separate from online administration.
use super::{query::validate_id, AccessError, AdminUpsertClient, TenancyMode};
use crate::{Clock, IdGenerator, OidcClient, OidcClientType, StoreError};
use std::time::SystemTime;

#[derive(Debug, Clone)]
pub struct PrepareManagementClient {
    pub client_id: String,
    pub client_name: String,
    pub redirect_uris: Vec<String>,
    pub request_id: String,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagementClientPreparationResult {
    Created,
    AlreadyMatches,
    Conflict,
}

pub struct ManagementClientPreparation {
    mode: TenancyMode,
    client: OidcClient,
    request_id: String,
    audit_id: String,
    occurred_at: SystemTime,
}
impl ManagementClientPreparation {
    pub fn mode(&self) -> TenancyMode {
        self.mode
    }
    pub fn client(&self) -> &OidcClient {
        &self.client
    }
    pub fn request_id(&self) -> &str {
        &self.request_id
    }
    pub fn audit_id(&self) -> &str {
        &self.audit_id
    }
    pub fn occurred_at(&self) -> SystemTime {
        self.occurred_at
    }
    /// Versioned SHA-256 over length-framed canonical fields (redirect set sorted).
    pub fn configuration_digest(&self) -> String {
        use sha2::{Digest, Sha256};
        let mut digest = Sha256::new();
        for field in std::iter::once("management-client-v1")
            .chain([
                self.client.client_id.as_str(),
                self.client.client_name.as_str(),
                "public_desktop",
                "pkce=true",
                "secret=absent",
            ])
            .chain(self.client.redirect_uris.iter().map(String::as_str))
        {
            digest.update((field.len() as u64).to_be_bytes());
            digest.update(field.as_bytes());
        }
        format!("sha256-v1:{:x}", digest.finalize())
    }
    /// Ordering and duplicate redirects are immaterial; no URI normalization.
    pub fn matches(&self, current: &OidcClient) -> bool {
        let mut current = current.clone();
        current.redirect_uris.sort();
        current.redirect_uris.dedup();
        current == self.client
    }
}
/// Implementations must atomically check preparation prerequisites, create only
/// if absent, and audit only creation. Never overwrite a conflicting client.
pub trait ManagementClientPreparationStore: Send + Sync {
    fn prepare_management_client(
        &self,
        plan: &ManagementClientPreparation,
    ) -> Result<ManagementClientPreparationResult, StoreError>;
}
pub trait ManagementClientPreparationService: Send + Sync {
    fn prepare(
        &self,
        input: PrepareManagementClient,
    ) -> Result<ManagementClientPreparationResult, AccessError>;
}
pub struct CoreManagementClientPreparationService<S, C, I> {
    mode: TenancyMode,
    store: S,
    clock: C,
    ids: I,
}
impl<S: ManagementClientPreparationStore, C: Clock, I: IdGenerator>
    CoreManagementClientPreparationService<S, C, I>
{
    pub fn new(mode: TenancyMode, store: S, clock: C, ids: I) -> Self {
        Self {
            mode,
            store,
            clock,
            ids,
        }
    }
    pub fn prepare(
        &self,
        input: PrepareManagementClient,
    ) -> Result<ManagementClientPreparationResult, AccessError> {
        validate_id(&input.request_id, 128, "request_id")?;
        let command = AdminUpsertClient {
            client_id: input.client_id,
            client_name: input.client_name,
            redirect_uris: input.redirect_uris,
            client_type: OidcClientType::PublicDesktop,
            pkce_required: true,
            client_secret: None,
        };
        command.validate()?;
        let mut client = OidcClient {
            client_id: command.client_id,
            client_name: command.client_name,
            redirect_uris: command.redirect_uris,
            client_type: command.client_type,
            pkce_required: true,
            client_secret_hash: None,
        };
        client.redirect_uris.sort();
        client.redirect_uris.dedup();
        let audit_id = self.ids.next_id("audit");
        validate_id(&audit_id, 128, "generated_id")?;
        self.store
            .prepare_management_client(&ManagementClientPreparation {
                mode: self.mode,
                client,
                request_id: input.request_id,
                audit_id,
                occurred_at: self.clock.now(),
            })
            .map_err(Into::into)
    }
}
impl<S: ManagementClientPreparationStore, C: Clock + Send + Sync, I: IdGenerator + Send + Sync>
    ManagementClientPreparationService for CoreManagementClientPreparationService<S, C, I>
{
    fn prepare(
        &self,
        input: PrepareManagementClient,
    ) -> Result<ManagementClientPreparationResult, AccessError> {
        Self::prepare(self, input)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    struct FixtureClock;
    impl Clock for FixtureClock {
        fn now(&self) -> SystemTime {
            SystemTime::UNIX_EPOCH
        }
    }
    struct Ids;
    impl IdGenerator for Ids {
        fn next_id(&self, _: &str) -> String {
            "audit-id".into()
        }
    }
    #[derive(Default)]
    struct UnknownCommitStore(Mutex<Option<OidcClient>>);
    impl ManagementClientPreparationStore for UnknownCommitStore {
        fn prepare_management_client(
            &self,
            p: &ManagementClientPreparation,
        ) -> Result<ManagementClientPreparationResult, StoreError> {
            let mut state = self.0.lock().unwrap();
            if let Some(c) = state.as_ref() {
                return Ok(if p.matches(c) {
                    ManagementClientPreparationResult::AlreadyMatches
                } else {
                    ManagementClientPreparationResult::Conflict
                });
            }
            *state = Some(p.client().clone());
            Err(StoreError::Backend("simulated commit reply lost".into()))
        }
    }
    fn input() -> PrepareManagementClient {
        PrepareManagementClient {
            client_id: "management".into(),
            client_name: "Management".into(),
            redirect_uris: vec!["http://127.0.0.1:4200/callback".into()],
            request_id: "request".into(),
        }
    }
    #[test]
    fn validation_and_unknown_commit_rerun_never_overwrite() {
        let service = CoreManagementClientPreparationService::new(
            TenancyMode::Enabled,
            UnknownCommitStore::default(),
            FixtureClock,
            Ids,
        );
        for bad in [
            PrepareManagementClient {
                client_name: "".into(),
                ..input()
            },
            PrepareManagementClient {
                redirect_uris: vec!["javascript:alert(1)".into()],
                ..input()
            },
            PrepareManagementClient {
                request_id: "\n".into(),
                ..input()
            },
        ] {
            assert!(matches!(
                service.prepare(bad),
                Err(AccessError::InvalidInput(_))
            ));
        }
        assert!(service.store.0.lock().unwrap().is_none());
        assert!(matches!(
            service.prepare(input()),
            Err(AccessError::Store(_))
        ));
        let mut duplicate = input();
        duplicate
            .redirect_uris
            .push(duplicate.redirect_uris[0].clone());
        assert_eq!(
            service.prepare(duplicate),
            Ok(ManagementClientPreparationResult::AlreadyMatches)
        );
        assert_eq!(
            service.prepare(PrepareManagementClient {
                client_name: "changed".into(),
                ..input()
            }),
            Ok(ManagementClientPreparationResult::Conflict)
        );
        // An online edit after an unknown commit must not be repaired by rerun.
        service
            .store
            .0
            .lock()
            .unwrap()
            .as_mut()
            .unwrap()
            .client_name = "Online edit".into();
        assert_eq!(
            service.prepare(input()),
            Ok(ManagementClientPreparationResult::Conflict)
        );
        assert_eq!(
            service
                .store
                .0
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .client_name,
            "Online edit"
        );
    }
}
