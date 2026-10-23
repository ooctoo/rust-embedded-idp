//! Private synchronous bridge over an owned, cancellable PostgreSQL driver.
//! Domain SQL remains in the registration store; no mutation is retried here.
mod session;
#[cfg(test)]
mod tests;
use crate::{PgStorageConfig, PgTlsMode};
use rustls::{
    pki_types::{pem::PemObject, CertificateDer},
    ClientConfig, RootCertStore,
};
pub(crate) use session::{Client, Error, Transaction};
use std::{sync::Arc, time::Duration};
use tokio::{
    runtime::Builder,
    sync::Semaphore,
    task::JoinSet,
    time::{timeout_at, Instant},
};
use tokio_postgres::{
    config::{Host, SslMode},
    Config,
};
use tokio_postgres_rustls::MakeRustlsConnect;

#[derive(Clone)]
pub(crate) struct Transport {
    config: Config,
    tls: MakeRustlsConnect,
    slots: Arc<Semaphore>,
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
        })
    }
    pub(crate) fn connect(&self, budget: Duration) -> Result<Client, Error> {
        let deadline = Instant::now() + budget;
        let runtime = Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| Error::Closed)?;
        let mut config = self.config.clone();
        // Enforce limits at startup too: BEGIN acknowledgement may be lost
        // before the store gets to execute SET LOCAL.
        let options=format!("{} -c transaction_timeout={} -c statement_timeout={} -c lock_timeout=1000 -c idle_in_transaction_session_timeout={}",config.get_options().unwrap_or(""),budget.as_millis(),budget.as_millis(),budget.as_millis());
        config.options(&options);
        let (slot, client, drivers) = runtime.block_on(async {
            let slot = timeout_at(deadline, self.slots.clone().acquire_owned())
                .await
                .map_err(|_| Error::Closed)?
                .map_err(|_| Error::Closed)?;
            let (client, connection) = timeout_at(deadline, config.connect(self.tls.clone()))
                .await
                .map_err(|_| Error::Closed)?
                .map_err(Error::Database)?;
            let mut drivers = JoinSet::new();
            drivers.spawn(connection);
            Ok::<_, Error>((slot, client, drivers))
        })?;
        Ok(Client::new(runtime, client, drivers, slot, deadline))
    }
}
