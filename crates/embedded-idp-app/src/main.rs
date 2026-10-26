use std::{
    error::Error,
    future::{Future, IntoFuture},
};

mod admin_ui;
mod administrator_init;
mod bootstrap;
mod composition_config;
mod config;
mod device_admission;
mod email_sender;
mod management_client_preparation;
mod oidc_dispatch;
mod scan_cleanup;
mod scan_composition;
mod scan_ui;

use std::time::Duration;
use tokio::runtime::Builder;
use tokio::{net::TcpListener, sync::watch};

use crate::bootstrap::build_composition;
use crate::composition_config::AppConfig;
use crate::config::EmbeddedIdpAppConfig;

const HTTP_DRAIN_TIMEOUT: Duration = Duration::from_secs(10);
const CLEANUP_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);
const RUNTIME_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

fn main() -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args().skip(1);
    let config = if let Some(command) = args.next() {
        match command.as_str() {
            "prepare-management-client" | "prepare-management-client-audit" => {
                if let Err((code, message)) =
                    management_client_preparation::run(args.collect(), command.ends_with("-audit"))
                {
                    eprintln!("{message}");
                    std::process::exit(code);
                }
                return Ok(());
            }
            "bootstrap-admin" => {
                return administrator_init::run(args.collect()).map_err(Into::into)
            }
            "--config" => {
                let path = args
                    .next()
                    .filter(|value| !value.is_empty())
                    .ok_or("--config requires one file path")?;
                if args.next().is_some() {
                    return Err("--config accepts exactly one file path".into());
                }
                AppConfig::from_file(std::path::Path::new(&path))?
            }
            "--help" if args.next().is_none() => {
                println!(
                    "Run with no arguments to start the reference host using legacy environment configuration.\nUse --config <path> for explicit JSON v1/v2 host configuration. SIGINT and SIGTERM trigger bounded HTTP and cleanup shutdown.\n{}",
                    format!("{}\n{}", administrator_init::USAGE, management_client_preparation::USAGE)
                );
                return Ok(());
            }
            _ => return Err("unknown command; use --help".into()),
        }
    } else {
        AppConfig::from_legacy(&EmbeddedIdpAppConfig::from_env()?)
    };
    let composition = build_composition(&config)?;
    let app = composition.router;
    // Keep the synchronous Postgres pool alive until outside the Tokio runtime.
    // Its last connection drop drives an internal runtime to close the connection.
    let services_until_runtime_stops = app.clone();
    let scan_cleanup = composition.scan_cleanup;
    let runtime = Builder::new_multi_thread().enable_all().build()?;

    let result = runtime.block_on(async move {
        let listener = TcpListener::bind(config.bind_addr).await?;
        let (stop_tx, stop_rx) = watch::channel(false);
        let cleanup = if scan_cleanup.is_empty() {
            None
        } else {
            Some(scan_cleanup::spawn(scan_cleanup, stop_rx.clone()))
        };

        println!(
            "embedded-idp-app listening on http://{}",
            listener.local_addr()?
        );
        if let Some(reference) = &config.reference_business {
            println!(
                "oidc discovery: {}/.well-known/openid-configuration",
                config.embedded_idp.issuer
            );
            println!(
                "public client: {} -> {}",
                reference.public_client.client_id, reference.public_client.redirect_uri
            );
        }
        if let Some(path) = &config.management.ui_base_path {
            println!("admin console: {}{}", config.embedded_idp.issuer, path);
        }
        println!(
            "management authentication: {}/admin/auth/login",
            config.management.mount_prefix
        );
        println!("tenancy mode: {:?}", config.tenancy_mode);

        let signal_stop = stop_tx.clone();
        let shutdown = async move {
            shutdown_signal().await;
            let _ = signal_stop.send(true);
        };
        let serving = axum::serve(listener, app)
            .with_graceful_shutdown(shutdown)
            .into_future();
        let server_stop = stop_tx.clone();
        let server_drain = drain_http(
            serving,
            stop_rx.clone(),
            server_stop,
            HTTP_DRAIN_TIMEOUT,
        );
        let cleanup_drain = async move {
            if let Some(mut task) = cleanup {
                let mut stopped = stop_rx;
                if !*stopped.borrow() {
                    let _ = stopped.changed().await;
                }
                match tokio::time::timeout(CLEANUP_DRAIN_TIMEOUT, &mut task).await {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => eprintln!("scan-login cleanup task failed: {error}"),
                    Err(_) => {
                        eprintln!("scan-login cleanup drain exceeded 5 seconds; in-flight database outcome is unknown")
                    }
                }
            }
        };
        let (server_result, ()) = tokio::join!(server_drain, cleanup_drain);
        server_result?;
        Ok::<(), std::io::Error>(())
    });
    runtime.shutdown_timeout(RUNTIME_SHUTDOWN_TIMEOUT);
    drop(services_until_runtime_stops);
    result?;
    Ok(())
}

async fn drain_http<F>(
    serving: F,
    mut stop: watch::Receiver<bool>,
    stop_tx: watch::Sender<bool>,
    timeout: Duration,
) -> Result<(), std::io::Error>
where
    F: Future<Output = Result<(), std::io::Error>>,
{
    match bounded_http_drain(serving, &mut stop, timeout).await {
        Ok(Ok(())) => {
            let _ = stop_tx.send(true);
            Ok(())
        }
        Ok(Err(error)) => {
            let _ = stop_tx.send(true);
            Err(error)
        }
        Err(_) => {
            eprintln!(
                "HTTP drain exceeded {} seconds; active requests may be interrupted",
                timeout.as_secs()
            );
            let _ = stop_tx.send(true);
            Ok(())
        }
    }
}

async fn bounded_http_drain<F>(
    serving: F,
    stop: &mut watch::Receiver<bool>,
    timeout: Duration,
) -> Result<Result<(), std::io::Error>, ()>
where
    F: Future<Output = Result<(), std::io::Error>>,
{
    tokio::pin!(serving);
    loop {
        if *stop.borrow() {
            return tokio::time::timeout(timeout, &mut serving)
                .await
                .map_err(|_| ());
        }
        tokio::select! {
            result = &mut serving => return Ok(result),
            changed = stop.changed() => {
                if changed.is_err() || *stop.borrow() {
                    return tokio::time::timeout(timeout, &mut serving)
                        .await
                        .map_err(|_| ());
                }
            }
        }
    }
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut terminate = match signal(SignalKind::terminate()) {
            Ok(signal) => signal,
            Err(error) => {
                eprintln!("could not register SIGTERM handler: {error}");
                let _ = tokio::signal::ctrl_c().await;
                return;
            }
        };
        tokio::select! {
            result = tokio::signal::ctrl_c() => {
                if let Err(error) = result {
                    eprintln!("could not receive SIGINT: {error}");
                }
            }
            _ = terminate.recv() => {}
        }
    }
    #[cfg(not(unix))]
    if let Err(error) = tokio::signal::ctrl_c().await {
        eprintln!("could not receive shutdown signal: {error}");
    }
}

#[cfg(test)]
mod tests {
    use super::{bounded_http_drain, drain_http};
    use std::time::Duration;
    use tokio::sync::watch;

    #[tokio::test]
    async fn http_drain_deadline_starts_only_after_stop_signal() {
        let (stop_tx, mut stop_rx) = watch::channel(false);
        let serving = std::future::pending::<Result<(), std::io::Error>>();
        let task = tokio::spawn(async move {
            bounded_http_drain(serving, &mut stop_rx, Duration::from_millis(20)).await
        });
        tokio::time::sleep(Duration::from_millis(40)).await;
        assert!(
            !task.is_finished(),
            "the running server must not time out early"
        );
        stop_tx.send(true).unwrap();
        assert!(
            task.await.unwrap().is_err(),
            "stop begins the bounded drain"
        );
    }

    #[tokio::test]
    async fn http_drain_ignores_false_watch_updates_and_honors_initial_stop() {
        let (stop_tx, mut stop_rx) = watch::channel(false);
        let task = tokio::spawn(async move {
            bounded_http_drain(
                std::future::pending::<Result<(), std::io::Error>>(),
                &mut stop_rx,
                Duration::from_millis(20),
            )
            .await
        });
        stop_tx.send(false).unwrap();
        tokio::time::sleep(Duration::from_millis(35)).await;
        assert!(
            !task.is_finished(),
            "a false update must not end the server"
        );
        stop_tx.send(true).unwrap();
        assert!(task.await.unwrap().is_err());

        let (_stop_tx, mut stop_rx) = watch::channel(true);
        assert!(bounded_http_drain(
            std::future::pending::<Result<(), std::io::Error>>(),
            &mut stop_rx,
            Duration::from_millis(20),
        )
        .await
        .is_err());
    }

    #[tokio::test]
    async fn normal_http_completion_stops_cleanup_waiters() {
        let (stop_tx, mut cleanup_waiter) = watch::channel(false);
        drain_http(
            async { Ok(()) },
            stop_tx.subscribe(),
            stop_tx.clone(),
            Duration::from_millis(20),
        )
        .await
        .unwrap();
        cleanup_waiter.changed().await.unwrap();
        assert!(*cleanup_waiter.borrow());
    }
}
