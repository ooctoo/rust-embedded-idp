mod transport;
pub use transport::{
    Error as PgError, Executor as PgExecutor, Transaction as PgTransaction,
    TransactionBuilder as PgTransactionBuilder,
};
mod registration_email_runtime_migration;
pub use registration_email_runtime_migration::*;
mod registration_email;
mod registration_email_migration;
pub use registration_email::*;
pub use registration_email_migration::*;
mod security_foundation;
pub use security_foundation::*;
mod security_runtime;
pub use security_runtime::*;
mod access;
mod adapter;
mod config;
mod migration;
mod sql;
mod transaction;

pub use access::{
    AccessSchemaFacts, PostgresAccessAdminTransaction, PostgresAccessStore,
    PostgresRecoveryCompletionTransaction, PostgresRecoveryStartTransaction,
    PostgresSecurityOutboxTransaction, PostgresSelfPasswordChangeReadTransaction,
    PostgresSelfPasswordChangeWriteTransaction, PostgresSelfSessionMutationTransaction,
    PostgresSelfSessionReadTransaction, PostgresTenantAuthTransaction,
    PostgresTenantEmailVerificationTransaction, ACCESS_SCHEMA_VERSION,
};
pub use adapter::{PgPooledConnection, PostgresStorageAdapter};
pub use config::{
    DbPoolConfig, PgConnectionConfig, PgStorageConfig, PgStorageConfigError, PgTlsMode,
};
pub use migration::{
    MigrationPlan, SchemaHealthFacts, SecurityCutoverPlan, MAXIMUM_ONLINE_SCHEMA_VERSION,
    MINIMUM_ONLINE_SCHEMA_VERSION, PRODUCTION_SECURITY_CUTOVER_ID,
};
pub use transaction::PostgresStoreTransaction;
