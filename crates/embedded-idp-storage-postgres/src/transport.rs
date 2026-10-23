//! Shared owned PostgreSQL transport. Domain SQL and transaction semantics stay
//! with their stores; no mutation is retried here.
macro_rules! queries {
    () => {
        pub fn query(
            &mut self,
            sql: &str,
            params: &[&(dyn tokio_postgres::types::ToSql + Sync)],
        ) -> Result<Vec<tokio_postgres::Row>, super::Error> {
            self.run(self.native().query(sql, params))
        }
        pub fn query_one(
            &mut self,
            sql: &str,
            params: &[&(dyn tokio_postgres::types::ToSql + Sync)],
        ) -> Result<tokio_postgres::Row, super::Error> {
            self.run(self.native().query_one(sql, params))
        }
        pub fn query_opt(
            &mut self,
            sql: &str,
            params: &[&(dyn tokio_postgres::types::ToSql + Sync)],
        ) -> Result<Option<tokio_postgres::Row>, super::Error> {
            self.run(self.native().query_opt(sql, params))
        }
        pub fn execute(
            &mut self,
            sql: &str,
            params: &[&(dyn tokio_postgres::types::ToSql + Sync)],
        ) -> Result<u64, super::Error> {
            self.run(self.native().execute(sql, params))
        }
        pub fn batch_execute(&mut self, sql: &str) -> Result<(), super::Error> {
            self.run(self.native().batch_execute(sql))
        }
    };
}
mod error;
mod executor;
mod runtime;
mod session;
#[cfg(test)]
mod tests;
mod transaction;
use crate::{PgStorageConfig, PgTlsMode};
pub use error::Error;
pub use executor::Executor;
use runtime::{blocking, DriverRuntime};
use rustls::{
    pki_types::{pem::PemObject, CertificateDer},
    ClientConfig, RootCertStore,
};
pub use session::Client;
use std::{sync::Arc, time::Duration};
use tokio::{
    sync::Semaphore,
    task::JoinSet,
    time::{timeout_at, Instant},
};
use tokio_postgres::{
    config::{Host, SslMode},
    Config,
};
use tokio_postgres_rustls::MakeRustlsConnect;
pub use transaction::{Transaction, TransactionBuilder};

#[derive(Clone)]
pub(crate) struct Transport {
    config: Config,
    tls: MakeRustlsConnect,
    slots: Arc<Semaphore>,
    runtime: Arc<DriverRuntime>,
}
impl Transport {
    pub(crate) fn new(settings: &PgStorageConfig) -> Result<Self, Error> {
        let mut config: Config = settings
            .connection
            .connection_uri
            .parse()
            .map_err(|_| Error::Closed)?;
        // libc DNS is not cancellable. Trusted hostaddr preserves the DNS TLS
        // name without invoking it inside a physical database budget.
        if config.get_hosts().is_empty()
            || (!config.get_hostaddrs().is_empty()
                && config.get_hostaddrs().len() != config.get_hosts().len())
            || (config.get_hostaddrs().is_empty()
                && config
                    .get_hosts()
                    .iter()
                    .any(|h| !matches!(h,Host::Tcp(h) if h.parse::<std::net::IpAddr>().is_ok())))
        {
            return Err(Error::Closed);
        }
        config.application_name(&settings.pool.application_name);
        config.connect_timeout(Duration::from_secs(settings.pool.connect_timeout_secs));
        config.ssl_mode(match settings.connection.tls_mode {
            PgTlsMode::Disable => SslMode::Disable,
            PgTlsMode::Prefer => SslMode::Prefer,
            PgTlsMode::Require => SslMode::Require,
        });
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        if settings.connection.tls_mode != PgTlsMode::Disable {
            if let Some(path) = &settings.connection.tls_ca_cert_path {
                let pem = std::fs::read(path).map_err(|_| Error::Closed)?;
                let mut count = 0;
                for cert in CertificateDer::pem_slice_iter(&pem) {
                    roots
                        .add(cert.map_err(|_| Error::Closed)?)
                        .map_err(|_| Error::Closed)?;
                    count += 1;
                }
                if count == 0 {
                    return Err(Error::Closed);
                }
            }
        }
        let tls =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .map_err(|_| Error::Closed)?
                .with_root_certificates(roots)
                .with_no_client_auth();
        Ok(Self {
            config,
            tls: MakeRustlsConnect::new(tls),
            slots: Arc::new(Semaphore::new(settings.pool.max_connections as usize)),
            runtime: Arc::new(DriverRuntime::new()?),
        })
    }
    pub(crate) fn connect(&self, budget: Duration) -> Result<Client, Error> {
        self.connect_inner(budget, false)
    }
    pub(crate) fn connect_registration(&self, budget: Duration) -> Result<Client, Error> {
        self.connect_inner(budget, true)
    }
    fn connect_inner(&self, budget: Duration, registration: bool) -> Result<Client, Error> {
        let deadline = Instant::now() + budget;
        let mut config = self.config.clone();
        // Enforce limits at startup too: BEGIN acknowledgement may be lost
        // before the store gets to execute SET LOCAL.
        // transaction_timeout is a registration-profile PG17+ requirement. The
        // general adapter keeps older PG compatibility, with the same client
        // physical deadline plus statement/idle limits available since PG9.6.
        let transaction = if registration {
            format!(" -c transaction_timeout={}", budget.as_millis())
        } else {
            String::new()
        };
        let limits = format!("{transaction} -c statement_timeout={} -c lock_timeout=1000 -c idle_in_transaction_session_timeout={}", budget.as_millis(), budget.as_millis());
        // Generic Host options may already impose stricter readiness limits.
        // Preserve their authority; the physical driver deadline is independent
        // and cannot be extended by any server GUC. The registration profile
        // retains its frozen startup policy and therefore applies limits last.
        let options = if registration {
            format!("{} {limits}", config.get_options().unwrap_or(""))
        } else {
            format!("{limits} {}", config.get_options().unwrap_or(""))
        };
        config.options(&options);
        let (slot, client, drivers) = blocking(|| {
            self.runtime.get().block_on(async {
                let slot = timeout_at(deadline, self.slots.clone().acquire_owned())
                    .await
                    .map_err(|_| Error::Closed)?
                    .map_err(|_| Error::Closed)?;
                let (client, connection) = timeout_at(deadline, config.connect(self.tls.clone()))
                    .await
                    .map_err(|_| Error::Closed)?
                    .map_err(Error::Database)?;
                let mut drivers = JoinSet::new();
                // The shared driver runtime keeps this timer alive even while the
                // caller is idle or its outer async wait has been cancelled.
                drivers.spawn(async move {
                    timeout_at(deadline, connection)
                        .await
                        .map_err(|_| Error::Closed)?
                        .map_err(Error::Database)
                });
                Ok::<_, Error>((slot, client, drivers))
            })
        })?;
        Ok(Client::new(
            self.runtime.clone(),
            client,
            drivers,
            slot,
            deadline,
        ))
    }
}
