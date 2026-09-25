use std::error::Error;

mod admin_ui;
mod administrator_init;
mod bootstrap;
mod config;
mod email_sender;

use tokio::net::TcpListener;
use tokio::runtime::Builder;

use crate::bootstrap::build_app;
use crate::config::EmbeddedIdpAppConfig;

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
    let app = build_app(&config)?;
    let runtime = Builder::new_multi_thread().enable_all().build()?;

    runtime.block_on(async move {
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
