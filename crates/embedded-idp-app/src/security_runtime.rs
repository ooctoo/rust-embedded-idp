use std::{
    sync::Arc,
    time::{Duration, Instant, SystemTime},
};

use embedded_idp_core::access::{
    SecurityCleanupResult, SecurityMailClaim, SecurityMailCompletion, SecurityMailOutcome,
    SecurityOutboxService,
};
use embedded_idp_email::{
    SecurityEmail, SecurityEmailDeliveryOutcome, SecurityEmailDeliveryService, SecurityEmailPurpose,
};
use tokio::{
    sync::watch,
    task::JoinHandle,
    time::{sleep, timeout},
};

use crate::security_email::ProcessSecurityEmailSender;

const SENDERS: usize = 4;
const POLL_INTERVAL: Duration = Duration::from_secs(1);
const SEND_DEADLINE: Duration = Duration::from_secs(15);
const LEASE_DURATION: Duration = Duration::from_secs(30);
const LOOP_DRAIN: Duration = Duration::from_secs(35);

#[derive(Clone)]
pub(crate) struct SecurityRuntimeJob {
    pub service: Arc<dyn SecurityOutboxService>,
    pub sender: Option<Arc<ProcessSecurityEmailSender>>,
}

pub(crate) struct SecurityRuntimeHandle {
    loops: Vec<JoinHandle<()>>,
    sender: Option<Arc<ProcessSecurityEmailSender>>,
}

impl SecurityRuntimeHandle {
    /// The caller must set the shared stop watch to `true` before shutdown.
    pub async fn shutdown(mut self) {
        eprintln!("security runtime stopping");
        let sender_shutdown = self.sender.take().map(|sender| {
            tokio::spawn(async move {
                sender.shutdown().await;
            })
        });

        drain_loops(self.loops, LOOP_DRAIN).await;

        if let Some(task) = sender_shutdown {
            let _ = task.await;
        }
    }
}

async fn drain_loops(mut loops: Vec<JoinHandle<()>>, limit: Duration) -> bool {
    let drained = timeout(limit, async {
        while let Some(task) = loops.first_mut() {
            let result = task.await;
            if let Err(error) = result {
                if error.is_panic() {
                    eprintln!("security runtime loop failed");
                }
            }
            loops.remove(0);
        }
    })
    .await
    .is_ok();

    if drained {
        return true;
    }

    for task in &loops {
        task.abort();
    }
    for task in loops {
        if let Err(error) = task.await {
            if error.is_panic() {
                eprintln!("security runtime loop failed");
            }
        }
    }
    eprintln!("security runtime database outcome unknown");
    false
}

pub(crate) fn spawn(job: SecurityRuntimeJob, stop: watch::Receiver<bool>) -> SecurityRuntimeHandle {
    let delivery = job
        .sender
        .as_ref()
        .map(|sender| Arc::clone(sender) as Arc<dyn SecurityEmailDeliveryService>);
    SecurityRuntimeHandle {
        loops: spawn_loops(job.service, delivery, stop, POLL_INTERVAL),
        sender: job.sender,
    }
}

fn spawn_loops(
    service: Arc<dyn SecurityOutboxService>,
    delivery: Option<Arc<dyn SecurityEmailDeliveryService>>,
    stop: watch::Receiver<bool>,
    interval: Duration,
) -> Vec<JoinHandle<()>> {
    let mut tasks = Vec::with_capacity(1 + delivery.as_ref().map_or(0, |_| SENDERS));
    if let Some(delivery) = delivery {
        for _ in 0..SENDERS {
            tasks.push(tokio::spawn(send_loop(
                Arc::clone(&service),
                Arc::clone(&delivery),
                stop.clone(),
                interval,
            )));
        }
    }
    tasks.push(tokio::spawn(cleanup_loop(service, stop, interval)));
    tasks
}

async fn send_loop(
    service: Arc<dyn SecurityOutboxService>,
    delivery: Arc<dyn SecurityEmailDeliveryService>,
    mut stop: watch::Receiver<bool>,
    interval: Duration,
) {
    loop {
        if stopped(&stop) {
            return;
        }

        let claim_service = Arc::clone(&service);
        let claim = match tokio::task::spawn_blocking(move || claim_service.claim()).await {
            Ok(Ok(claim)) => claim,
            Ok(Err(_)) | Err(_) => {
                eprintln!("security outbox claim failed");
                None
            }
        };

        if let Some(claim) = claim {
            if stopped(&stop) {
                finish(&service, claim, SecurityMailOutcome::NotStarted).await;
            } else {
                let deadline = send_deadline(&claim, SystemTime::now(), Instant::now());
                if let Some(deadline) = deadline {
                    let body = format!(
                        "Your password recovery code is: {}\n\nIf you did not request this, please ignore this message.",
                        claim.code.expose_secret()
                    );
                    let email = SecurityEmail {
                        purpose: SecurityEmailPurpose::PasswordRecovery,
                        recipient: claim.recipient.expose_secret().to_owned(),
                        text_body: body,
                    };
                    let outcome = delivery.send(email, deadline).await;
                    finish(&service, claim, map_outcome(outcome)).await;
                } else {
                    finish(&service, claim, SecurityMailOutcome::NotStarted).await;
                }
            }
        }

        if !wait_interval(&mut stop, interval).await {
            return;
        }
    }
}

async fn finish(
    service: &Arc<dyn SecurityOutboxService>,
    claim: SecurityMailClaim,
    outcome: SecurityMailOutcome,
) {
    let completion = SecurityMailCompletion {
        outbox_id: claim.outbox_id,
        lease_token: claim.lease_token,
        outcome,
    };
    let finish_service = Arc::clone(service);
    match tokio::task::spawn_blocking(move || finish_service.finish(completion)).await {
        Ok(Ok(_)) => {}
        Ok(Err(_)) | Err(_) => eprintln!("security outbox finish failed"),
    }
}

async fn cleanup_loop(
    service: Arc<dyn SecurityOutboxService>,
    mut stop: watch::Receiver<bool>,
    interval: Duration,
) {
    loop {
        if stopped(&stop) {
            return;
        }
        let cleanup_service = Arc::clone(&service);
        match tokio::task::spawn_blocking(move || cleanup_service.cleanup()).await {
            Ok(Ok(SecurityCleanupResult { .. })) => {}
            Ok(Err(_)) | Err(_) => eprintln!("security outbox cleanup failed"),
        }
        if !wait_interval(&mut stop, interval).await {
            return;
        }
    }
}

fn map_outcome(outcome: SecurityEmailDeliveryOutcome) -> SecurityMailOutcome {
    match outcome {
        SecurityEmailDeliveryOutcome::Accepted => SecurityMailOutcome::Accepted,
        SecurityEmailDeliveryOutcome::Rejected => SecurityMailOutcome::Rejected,
        SecurityEmailDeliveryOutcome::NotStarted => SecurityMailOutcome::NotStarted,
        SecurityEmailDeliveryOutcome::Unknown => SecurityMailOutcome::Unknown,
    }
}

fn send_deadline(
    claim: &SecurityMailClaim,
    wall_now: SystemTime,
    instant_now: Instant,
) -> Option<Instant> {
    let inferred_created = claim.lease_until.checked_sub(LEASE_DURATION)?;
    if wall_now < inferred_created {
        return None;
    }
    let latest = claim.lease_until.min(claim.expires_at);
    let remaining = latest.duration_since(wall_now).ok()?;
    if remaining.is_zero() {
        return None;
    }
    instant_now.checked_add(remaining.min(SEND_DEADLINE))
}

fn stopped(stop: &watch::Receiver<bool>) -> bool {
    *stop.borrow() || stop.has_changed().is_err()
}

async fn wait_interval(stop: &mut watch::Receiver<bool>, interval: Duration) -> bool {
    if stopped(stop) {
        return false;
    }
    tokio::select! {
        _ = sleep(interval) => !stopped(stop),
        changed = stop.changed() => changed.is_ok() && !*stop.borrow(),
    }
}

#[cfg(test)]
#[path = "security_runtime_tests.rs"]
mod tests;
