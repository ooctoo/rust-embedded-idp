use super::*;
use crate::{DbPoolConfig, PgConnectionConfig};
use std::time::Instant as WallInstant;
fn settings() -> PgStorageConfig {
    PgStorageConfig {
        connection: PgConnectionConfig {
            connection_uri: "postgres://fixture@127.0.0.1:1/sut_idp3_test?sslmode=disable".into(),
            schema_name: "fixture".into(),
            tls_mode: PgTlsMode::Disable,
            tls_ca_cert_path: None,
        },
        pool: DbPoolConfig {
            application_name: "fixture".into(),
            max_connections: 1,
            connect_timeout_secs: 1,
        },
    }
}
#[test]
fn exhausted_registration_capacity_is_bounded_and_shared_by_clones() {
    let transport = Transport::new(&settings()).unwrap();
    let _held = transport.slots.clone().try_acquire_owned().unwrap();
    let start = WallInstant::now();
    assert!(transport
        .clone()
        .connect(Duration::from_millis(80))
        .is_err());
    assert!(
        start.elapsed() >= Duration::from_millis(70)
            && start.elapsed() < Duration::from_millis(300)
    );
}
#[test]
fn tls_mode_is_explicit_and_missing_explicit_ca_fails_closed() {
    let mut settings = settings();
    settings.connection.tls_mode = PgTlsMode::Require;
    let transport = Transport::new(&settings).unwrap();
    assert_eq!(transport.config.get_ssl_mode(), SslMode::Require);
    settings.connection.tls_ca_cert_path = Some("/private/tmp/idp-timeout-missing-ca.pem".into());
    assert!(Transport::new(&settings).is_err());
}
#[test]
fn dns_requires_literal_hostaddr_and_keeps_certificate_name() {
    let mut settings = settings();
    settings.connection.connection_uri =
        "postgres://fixture@db.example.invalid:5432/sut_idp3_test".into();
    assert!(Transport::new(&settings).is_err());
    settings
        .connection
        .connection_uri
        .push_str("?hostaddr=192.0.2.8");
    let transport = Transport::new(&settings).unwrap();
    assert_eq!(
        transport.config.get_hosts(),
        &[Host::Tcp("db.example.invalid".into())]
    );
    assert_eq!(
        transport.config.get_hostaddrs(),
        &["192.0.2.8".parse::<std::net::IpAddr>().unwrap()]
    );
}

#[test]
fn adapter_clones_share_one_registration_capacity() {
    let adapter = crate::PostgresStorageAdapter::new(settings()).unwrap();
    let first = adapter.registration_transport().unwrap();
    let second = adapter.clone().registration_transport().unwrap();
    assert!(Arc::ptr_eq(&first.slots, &second.slots));
}
