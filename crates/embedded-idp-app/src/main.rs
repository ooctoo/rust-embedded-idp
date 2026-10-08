use std::error::Error;

mod admin_ui;
mod administrator_init;
mod bootstrap;
mod config;
mod email_sender;
mod scan_ui;

use tokio::net::TcpListener;
use tokio::runtime::Builder;

use crate::bootstrap::build_app_with_scan_cleanup;
use crate::config::EmbeddedIdpAppConfig;

const SCAN_CLEANUP_INTERVAL_SECS: u64 = 30;
const SCAN_CLEANUP_BATCH_SIZE: u32 = 100;

fn main() -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args().skip(1);
    if let Some(command) = args.next() {
        return match command.as_str() {
            "bootstrap-admin" => administrator_init::run(args.collect()).map_err(Into::into),
            "--help" if args.next().is_none() => {
                println!(
                    "Run with no arguments to start the reference host.\n{}",
                    administrator_init::USAGE
                );
                Ok(())
            }
            _ => Err("unknown command; use --help".into()),
        };
    }
    let config = EmbeddedIdpAppConfig::from_env()?;
    let composition = build_app_with_scan_cleanup(&config)?;
    let app = composition.router;
    let scan_cleanup = composition.scan_cleanup;
    let runtime = Builder::new_multi_thread().enable_all().build()?;

    runtime.block_on(async move {
        if let Some(service) = scan_cleanup {
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(std::time::Duration::from_secs(
                    SCAN_CLEANUP_INTERVAL_SECS,
                ));
                loop {
                    interval.tick().await;
                    let service = service.clone();
                    let host = embedded_idp_core::access::TrustedScanHostContext::new(
                        "reference-host".into(),
                        std::time::SystemTime::now() + std::time::Duration::from_secs(60),
                    );
                    if !matches!(
                        tokio::task::spawn_blocking(move || {
                            service.cleanup(host, SCAN_CLEANUP_BATCH_SIZE)
                        })
                        .await,
                        Ok(Ok(_))
                    ) {
                        eprintln!("scan-login cleanup failed; retrying at the next interval");
                    }
                }
            });
        }
        let listener = TcpListener::bind(config.bind_addr).await?;

        println!(
            "embedded-idp-app listening on http://{}",
            listener.local_addr()?
        );
        println!(
            "oidc discovery: {}/.well-known/openid-configuration",
            config.embedded_idp.issuer
        );
        println!(
            "public client: {} -> {}",
            config.public_client.client_id, config.public_client.redirect_uri
        );
        println!(
            "admin console: {}{}",
            config.embedded_idp.issuer, config.admin_ui_base_path
        );
        println!("management authentication: /api/admin/auth/login");
        println!("tenancy mode: {:?}", config.tenancy_mode);

        axum::serve(listener, app).await?;
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::{SCAN_CLEANUP_BATCH_SIZE, SCAN_CLEANUP_INTERVAL_SECS};

    #[test]
    fn reference_scan_cleanup_is_bounded_and_not_request_driven() {
        assert_eq!(SCAN_CLEANUP_INTERVAL_SECS, 30);
        assert_eq!(SCAN_CLEANUP_BATCH_SIZE, 100);
    }
}
