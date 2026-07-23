use std::error::Error;

mod admin_ui;
mod bootstrap;
mod config;
mod dev_security;
mod email_sender;

use tokio::net::TcpListener;
use tokio::runtime::Builder;

use crate::bootstrap::build_app;
use crate::config::EmbeddedIdpAppConfig;

fn main() -> Result<(), Box<dyn Error>> {
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
        println!("subject header: {}", config.dev_subject_header);
        println!(
            "admin console: {}{}",
            config.embedded_idp.issuer, config.admin_ui_base_path
        );
        if config.admin_api_key.is_some() {
            println!("admin routes enabled with header: x-embedded-idp-admin-key");
        } else {
            println!("admin routes disabled; set EMBEDDED_IDP_APP_ADMIN_API_KEY to enable");
        }

        axum::serve(listener, app).await?;
        Ok(())
    })
}
