use super::*;

use embedded_idp_email::{
    RegistrationEmailDeliveryRequest, RegistrationEmailDeliveryService,
    RegistrationEmailSendOutcome,
};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant as StdInstant};
use tokio::sync::Notify;

struct BlockingMailer {
    started: Arc<Notify>,
    release: Mutex<mpsc::Receiver<()>>,
}

impl BlockingMailer {
    fn new() -> (Arc<Self>, mpsc::Sender<()>, Arc<Notify>) {
        let (release_tx, release_rx) = mpsc::channel();
        let started = Arc::new(Notify::new());
        (
            Arc::new(Self {
                started: started.clone(),
                release: Mutex::new(release_rx),
            }),
            release_tx,
            started,
        )
    }
}

impl RegistrationEmailDeliveryService for BlockingMailer {
    fn send_registration_email(
        &self,
        _: RegistrationEmailDeliveryRequest,
        _: StdInstant,
    ) -> RegistrationEmailSendOutcome {
        self.started.notify_one();
        let _ = self.release.lock().unwrap().recv();
        RegistrationEmailSendOutcome::Sent
    }
}

struct BlockingUnknownMailer {
    started: Arc<Notify>,
    release: Mutex<mpsc::Receiver<()>>,
}

impl BlockingUnknownMailer {
    fn new() -> (Arc<Self>, mpsc::Sender<()>, Arc<Notify>) {
        let (release_tx, release_rx) = mpsc::channel();
        let started = Arc::new(Notify::new());
        (
            Arc::new(Self {
                started: started.clone(),
                release: Mutex::new(release_rx),
            }),
            release_tx,
            started,
        )
    }
}

impl RegistrationEmailDeliveryService for BlockingUnknownMailer {
    fn send_registration_email(
        &self,
        _: RegistrationEmailDeliveryRequest,
        _: StdInstant,
    ) -> RegistrationEmailSendOutcome {
        self.started.notify_one();
        let _ = self.release.lock().unwrap().recv();
        RegistrationEmailSendOutcome::Unknown
    }
}

async fn wait_for_storage_drain(runtime: &RegistrationEmailRuntime) {
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if runtime.unresolved_storage() == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("storage call ended");
}

#[tokio::test]
async fn shutdown_waits_for_a_legitimate_request_to_finish_before_draining() {
    let service = Arc::new(FakeService::new());
    let runtime = runtime(service);
    let workers = runtime.start().await.unwrap();
    let permit = runtime
        .try_request(RegistrationEmailOperationKind::Register, false)
        .unwrap();
    let started = Arc::new(Notify::new());
    let (release_tx, release_rx) = mpsc::channel();
    let started_for_call = started.clone();
    let request = tokio::spawn(registration_call(permit, move || {
        started_for_call.notify_one();
        release_rx.recv().unwrap();
        Ok::<_, RegistrationEmailError>(())
    }));
    tokio::time::timeout(Duration::from_secs(1), started.notified())
        .await
        .expect("request call started");

    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(20)).await;
        let _ = release_tx.send(());
    });
    let shutdown = tokio::time::timeout(
        Duration::from_secs(1),
        workers.shutdown(Duration::from_millis(200)),
    )
    .await
    .expect("bounded shutdown");
    assert!(shutdown.drained);
    assert_eq!(shutdown.unresolved_processing, 0);
    assert_eq!(shutdown.unresolved_delivery, 0);
    assert_eq!(shutdown.unresolved_storage, 0);
    assert_eq!(shutdown.unresolved_requests, 0);
    assert!(!shutdown.failed);
    assert!(request.await.unwrap().is_ok());
}

#[tokio::test]
async fn short_shutdown_reports_blocked_facts_and_closes_admission() {
    let service = Arc::new(FakeService::new());
    let runtime = runtime(service.clone());
    let workers = runtime.start().await.unwrap();
    let (release_tx, entered) = service.block_facts();
    tokio::time::timeout(Duration::from_secs(1), entered.notified())
        .await
        .expect("facts call started");

    workers.begin_shutdown(Duration::from_millis(50));
    assert!(runtime
        .try_request(RegistrationEmailOperationKind::Register, false)
        .is_err());
    assert!(runtime.try_probe().is_err());
    let shutdown = tokio::time::timeout(
        Duration::from_secs(1),
        workers.shutdown(Duration::from_secs(1)),
    )
    .await
    .expect("bounded shutdown");
    assert!(!shutdown.drained);
    assert_eq!(shutdown.unresolved_storage, 1);
    assert_eq!(shutdown.unresolved_requests, 0);
    assert!(shutdown.failed);
    assert_eq!(service.pause_calls(), 0);

    release_tx.send(()).unwrap();
    wait_for_storage_drain(&runtime).await;
}

#[tokio::test]
async fn short_shutdown_reports_blocked_maintenance_without_post_stop_pause() {
    let service = Arc::new(FakeService::new());
    let (release_tx, entered) = service.block_maintenance();
    let runtime = runtime(service.clone());
    let workers = runtime.start().await.unwrap();
    tokio::time::timeout(Duration::from_secs(1), entered.notified())
        .await
        .expect("maintenance call started");

    workers.begin_shutdown(Duration::from_millis(50));
    let shutdown = tokio::time::timeout(
        Duration::from_secs(1),
        workers.shutdown(Duration::from_secs(1)),
    )
    .await
    .expect("bounded shutdown");
    assert!(!shutdown.drained);
    assert_eq!(shutdown.unresolved_storage, 1);
    assert_eq!(shutdown.unresolved_requests, 0);
    assert!(shutdown.failed);
    assert_eq!(service.pause_calls(), 0);

    release_tx.send(()).unwrap();
    wait_for_storage_drain(&runtime).await;
    assert_eq!(service.pause_calls(), 0);
}

#[tokio::test]
async fn short_shutdown_keeps_claim_storage_and_processing_physical_until_release() {
    let service = Arc::new(FakeService::new());
    let (release_tx, entered) = service.block_claim();
    let runtime = runtime(service.clone());
    let workers = runtime.start().await.unwrap();
    tokio::time::timeout(Duration::from_secs(1), entered.notified())
        .await
        .expect("claim call started");
    assert_eq!(runtime.processing.available_permits(), 3);

    workers.begin_shutdown(Duration::from_millis(50));
    let shutdown = tokio::time::timeout(
        Duration::from_secs(1),
        workers.shutdown(Duration::from_secs(1)),
    )
    .await
    .expect("bounded shutdown");
    assert!(!shutdown.drained);
    assert_eq!(shutdown.unresolved_storage, 1);
    assert_eq!(shutdown.unresolved_processing, 1);
    assert_eq!(shutdown.unresolved_delivery, 0);
    assert_eq!(shutdown.unresolved_requests, 0);
    assert!(shutdown.failed);

    release_tx.send(()).unwrap();
    wait_for_storage_drain(&runtime).await;
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if runtime.processing.available_permits() == 4 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("processing permit released");
}

#[tokio::test]
async fn short_shutdown_does_not_start_a_second_pause_after_deadline() {
    let service = Arc::new(FakeService::new());
    let runtime = runtime(service.clone());
    let workers = runtime.start().await.unwrap();
    let (release_tx, entered) = service.block_pause();
    service.set_facts(Err(RegistrationEmailError::Unavailable));
    tokio::time::timeout(Duration::from_secs(1), entered.notified())
        .await
        .expect("pause call started");

    workers.begin_shutdown(Duration::from_millis(50));
    let shutdown = tokio::time::timeout(
        Duration::from_secs(1),
        workers.shutdown(Duration::from_secs(1)),
    )
    .await
    .expect("bounded shutdown");
    assert!(!shutdown.drained);
    assert_eq!(shutdown.unresolved_storage, 1);
    assert_eq!(shutdown.unresolved_requests, 0);
    assert!(shutdown.failed);
    assert_eq!(service.pause_calls(), 1);

    release_tx.send(()).unwrap();
    wait_for_storage_drain(&runtime).await;
    assert_eq!(service.pause_calls(), 1);
}

#[tokio::test]
async fn shutdown_finishes_a_preparation_claim_returned_after_stop() {
    let service = Arc::new(FakeService::new());
    service.set_preparation_claim(RegistrationEmailPreparationClaim {
        context_id: Uuid::from_u128(11),
        sequence: 1,
        claim_token: Uuid::from_u128(12),
        lease_until: 1_713_894_300,
    });
    let (release_tx, entered) = service.block_claim();
    let runtime = runtime(service.clone());
    let workers = runtime.start().await.unwrap();
    tokio::time::timeout(Duration::from_secs(1), entered.notified())
        .await
        .expect("preparation claim started");

    workers.begin_shutdown(Duration::from_secs(2));
    release_tx.send(()).unwrap();
    let shutdown = tokio::time::timeout(
        Duration::from_secs(2),
        workers.shutdown(Duration::from_secs(2)),
    )
    .await
    .expect("bounded shutdown");
    assert!(shutdown.drained);
    assert!(!shutdown.failed);
    assert_eq!(shutdown.unresolved_processing, 0);
    assert_eq!(shutdown.unresolved_delivery, 0);
    assert_eq!(shutdown.unresolved_storage, 0);
    assert_eq!(shutdown.unresolved_requests, 0);
    assert_eq!(service.preparation_claim_calls(), 1);
    assert_eq!(service.prepare_calls(), 1);
    assert_eq!(service.pause_calls(), 0);
    assert_eq!(runtime.processing.available_permits(), 4);
    assert!(!runtime.worker_running());
}

#[tokio::test]
async fn shutdown_finishes_a_delivery_claim_returned_after_stop() {
    let service = Arc::new(FakeService::with_delivery());
    let (release_tx, entered) = service.block_delivery_claim();
    let runtime = runtime(service.clone());
    let workers = runtime.start().await.unwrap();
    tokio::time::timeout(Duration::from_secs(1), entered.notified())
        .await
        .expect("delivery claim started");

    workers.begin_shutdown(Duration::from_secs(2));
    release_tx.send(()).unwrap();
    let shutdown = tokio::time::timeout(
        Duration::from_secs(2),
        workers.shutdown(Duration::from_secs(2)),
    )
    .await
    .expect("bounded shutdown");
    assert!(shutdown.drained);
    assert!(!shutdown.failed);
    assert_eq!(shutdown.unresolved_processing, 0);
    assert_eq!(shutdown.unresolved_delivery, 0);
    assert_eq!(shutdown.unresolved_storage, 0);
    assert_eq!(shutdown.unresolved_requests, 0);
    assert_eq!(service.preparation_claim_calls(), 1);
    assert_eq!(service.delivery_claim_calls(), 1);
    assert_eq!(
        service.results(),
        vec![RegistrationEmailDeliveryResult::Sent]
    );
    assert_eq!(runtime.delivery.available_permits(), 2);
    assert!(!runtime.worker_running());
}

async fn terminal_preparation_result_does_not_pause(result: RegistrationEmailPreparation) {
    let service = Arc::new(FakeService::new());
    service.set_preparation_result(Ok(result));
    service.set_preparation_claim(RegistrationEmailPreparationClaim {
        context_id: Uuid::from_u128(21),
        sequence: 1,
        claim_token: Uuid::from_u128(22),
        lease_until: 1_713_894_300,
    });
    let (release_tx, entered) = service.block_claim();
    let runtime = runtime(service.clone());
    let workers = runtime.start().await.unwrap();
    tokio::time::timeout(Duration::from_secs(1), entered.notified())
        .await
        .expect("preparation claim started");

    workers.begin_shutdown(Duration::from_secs(2));
    release_tx.send(()).unwrap();
    let shutdown = tokio::time::timeout(
        Duration::from_secs(2),
        workers.shutdown(Duration::from_secs(2)),
    )
    .await
    .expect("bounded shutdown");
    assert!(shutdown.drained);
    assert!(!shutdown.failed);
    assert_eq!(shutdown.unresolved_processing, 0);
    assert_eq!(shutdown.unresolved_delivery, 0);
    assert_eq!(shutdown.unresolved_storage, 0);
    assert_eq!(shutdown.unresolved_requests, 0);
    assert_eq!(service.preparation_claim_calls(), 1);
    assert_eq!(service.prepare_calls(), 1);
    assert_eq!(service.pause_calls(), 0);
    assert_eq!(runtime.processing.available_permits(), 4);
}

#[tokio::test]
async fn suppressed_preparation_does_not_pause_worker() {
    terminal_preparation_result_does_not_pause(RegistrationEmailPreparation::Suppressed).await;
}

#[tokio::test]
async fn superseded_preparation_does_not_pause_worker() {
    terminal_preparation_result_does_not_pause(RegistrationEmailPreparation::Superseded).await;
}

#[tokio::test]
async fn unknown_delivery_during_shutdown_latches_failure_without_pause_write() {
    let service = Arc::new(FakeService::with_delivery());
    let (mailer, release_tx, started) = BlockingUnknownMailer::new();
    let runtime =
        RegistrationEmailRuntime::new(service.clone(), mailer, service.budget.clone()).unwrap();
    let workers = runtime.start().await.unwrap();
    tokio::time::timeout(Duration::from_secs(1), started.notified())
        .await
        .expect("mail call started");

    workers.begin_shutdown(Duration::from_secs(2));
    release_tx.send(()).unwrap();
    let shutdown = tokio::time::timeout(
        Duration::from_secs(2),
        workers.shutdown(Duration::from_secs(2)),
    )
    .await
    .expect("bounded shutdown");
    assert!(shutdown.drained);
    assert!(shutdown.failed);
    assert_eq!(shutdown.unresolved_processing, 0);
    assert_eq!(shutdown.unresolved_delivery, 0);
    assert_eq!(shutdown.unresolved_storage, 0);
    assert_eq!(shutdown.unresolved_requests, 0);
    assert_eq!(service.pause_calls(), 0);
    assert!(!service.is_paused());
    assert!(!runtime.worker_running());
}

#[tokio::test]
async fn preparation_error_during_shutdown_latches_failure_without_pause_write() {
    let service = Arc::new(FakeService::new());
    service.set_preparation_result(Err(RegistrationEmailError::Unavailable));
    service.set_preparation_claim(RegistrationEmailPreparationClaim {
        context_id: Uuid::from_u128(31),
        sequence: 1,
        claim_token: Uuid::from_u128(32),
        lease_until: 1_713_894_300,
    });
    let (release_tx, entered) = service.block_claim();
    let runtime = runtime(service.clone());
    let workers = runtime.start().await.unwrap();
    tokio::time::timeout(Duration::from_secs(1), entered.notified())
        .await
        .expect("preparation claim started");

    workers.begin_shutdown(Duration::from_secs(2));
    release_tx.send(()).unwrap();
    let shutdown = tokio::time::timeout(
        Duration::from_secs(2),
        workers.shutdown(Duration::from_secs(2)),
    )
    .await
    .expect("bounded shutdown");
    assert!(shutdown.drained);
    assert!(shutdown.failed);
    assert_eq!(shutdown.unresolved_processing, 0);
    assert_eq!(shutdown.unresolved_delivery, 0);
    assert_eq!(shutdown.unresolved_storage, 0);
    assert_eq!(shutdown.unresolved_requests, 0);
    assert_eq!(service.pause_calls(), 0);
    assert!(!service.is_paused());
    assert!(!runtime.worker_running());
}

#[tokio::test]
async fn worker_shutdown_drains_when_no_physical_work_is_claimed() {
    let service = Arc::new(FakeService::new());
    let runtime = runtime(service);
    let workers = runtime.start().await.unwrap();
    let shutdown = tokio::time::timeout(
        Duration::from_secs(1),
        workers.shutdown(Duration::from_secs(1)),
    )
    .await
    .expect("bounded shutdown");
    assert!(shutdown.drained);
    assert_eq!(shutdown.unresolved_processing, 0);
    assert_eq!(shutdown.unresolved_delivery, 0);
    assert_eq!(shutdown.unresolved_storage, 0);
    assert_eq!(shutdown.unresolved_requests, 0);
    assert!(!shutdown.failed);
}

#[tokio::test]
async fn blocking_mail_finishes_unknown_and_quarantines_the_worker() {
    let service = Arc::new(FakeService::with_delivery());
    let (mailer, release_tx, mail_started) = BlockingMailer::new();
    let runtime =
        RegistrationEmailRuntime::new(service.clone(), mailer, service.budget.clone()).unwrap();
    let workers = runtime.start().await.unwrap();

    tokio::time::timeout(Duration::from_secs(1), mail_started.notified())
        .await
        .expect("mail call started");
    let unknown = service.unknown_signal();
    tokio::time::timeout(Duration::from_secs(1), unknown.notified())
        .await
        .expect("unknown delivery recorded");
    let paused = service.paused_signal();
    tokio::time::timeout(Duration::from_secs(1), paused.notified())
        .await
        .expect("runtime paused");
    assert_eq!(
        service.results(),
        vec![RegistrationEmailDeliveryResult::Unknown]
    );
    assert!(service.is_paused());
    assert!(!runtime.worker_running());

    release_tx.send(()).unwrap();
    let stopped = service.stopped_signal();
    tokio::time::timeout(Duration::from_secs(1), stopped.notified())
        .await
        .expect("blocking mail stopped");
    let shutdown = workers.shutdown(Duration::from_secs(1)).await;
    assert!(shutdown.drained);
}
