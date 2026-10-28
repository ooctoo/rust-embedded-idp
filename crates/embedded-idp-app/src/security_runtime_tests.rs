use super::*;
use embedded_idp_core::{access::AccessError, SecretString};
use std::{
    future::Future,
    sync::{
        atomic::{AtomicUsize, Ordering},
        mpsc as std_mpsc, Mutex,
    },
    time::SystemTime,
};
use tokio::sync::{oneshot, Notify};

struct FakeOutbox {
    claim: Mutex<Option<SecurityMailClaim>>,
    claims: AtomicUsize,
    finishes: Mutex<Vec<SecurityMailOutcome>>,
    cleanup_count: AtomicUsize,
    cleanup_seen: Notify,
    finish_seen: Notify,
    fail_finish: bool,
}

impl FakeOutbox {
    fn new(claim: Option<SecurityMailClaim>, fail_finish: bool) -> Self {
        Self {
            claim: Mutex::new(claim),
            claims: AtomicUsize::new(0),
            finishes: Mutex::new(Vec::new()),
            cleanup_count: AtomicUsize::new(0),
            cleanup_seen: Notify::new(),
            finish_seen: Notify::new(),
            fail_finish,
        }
    }
}

impl SecurityOutboxService for FakeOutbox {
    fn claim(&self) -> Result<Option<SecurityMailClaim>, AccessError> {
        self.claims.fetch_add(1, Ordering::SeqCst);
        Ok(self.claim.lock().unwrap().take())
    }

    fn finish(&self, completion: SecurityMailCompletion) -> Result<bool, AccessError> {
        self.finishes.lock().unwrap().push(completion.outcome);
        self.finish_seen.notify_one();
        if self.fail_finish {
            Err(AccessError::InvalidStoreResponse)
        } else {
            Ok(true)
        }
    }

    fn cleanup(&self) -> Result<SecurityCleanupResult, AccessError> {
        self.cleanup_count.fetch_add(1, Ordering::SeqCst);
        self.cleanup_seen.notify_one();
        Ok(SecurityCleanupResult { processed: 0 })
    }
}

struct BlockingClaimOutbox {
    claim: Mutex<Option<SecurityMailClaim>>,
    entered: Mutex<Option<std_mpsc::Sender<()>>>,
    release: Mutex<std_mpsc::Receiver<()>>,
    finishes: Mutex<Vec<SecurityMailOutcome>>,
}

impl SecurityOutboxService for BlockingClaimOutbox {
    fn claim(&self) -> Result<Option<SecurityMailClaim>, AccessError> {
        let claim = self.claim.lock().unwrap().take();
        if claim.is_some() {
            let _ = self.entered.lock().unwrap().take().unwrap().send(());
            self.release.lock().unwrap().recv().unwrap();
        }
        Ok(claim)
    }

    fn finish(&self, completion: SecurityMailCompletion) -> Result<bool, AccessError> {
        self.finishes.lock().unwrap().push(completion.outcome);
        Ok(true)
    }

    fn cleanup(&self) -> Result<SecurityCleanupResult, AccessError> {
        Ok(SecurityCleanupResult { processed: 0 })
    }
}

struct WaitingDelivery {
    entered: tokio::sync::mpsc::UnboundedSender<SecurityEmail>,
    release: Mutex<Option<oneshot::Receiver<SecurityEmailDeliveryOutcome>>>,
    calls: AtomicUsize,
}

impl SecurityEmailDeliveryService for WaitingDelivery {
    fn send<'a>(
        &'a self,
        email: SecurityEmail,
        _deadline: Instant,
    ) -> std::pin::Pin<Box<dyn Future<Output = SecurityEmailDeliveryOutcome> + Send + 'a>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let _ = self.entered.send(email);
        let receiver = self.release.lock().unwrap().take();
        Box::pin(async move {
            receiver
                .expect("one send expected")
                .await
                .unwrap_or(SecurityEmailDeliveryOutcome::Unknown)
        })
    }
}

fn claim() -> SecurityMailClaim {
    let now = SystemTime::now();
    SecurityMailClaim {
        outbox_id: "00000000-0000-0000-0000-000000000001".parse().unwrap(),
        flow_id: "00000000-0000-0000-0000-000000000002".parse().unwrap(),
        lease_token: "00000000-0000-0000-0000-000000000003".parse().unwrap(),
        lease_until: now + LEASE_DURATION,
        expires_at: now + Duration::from_secs(900),
        recipient: SecretString::new("person@example.test"),
        code: SecretString::new("code-secret"),
    }
}

#[test]
fn deadline_is_capped_by_lease_expiry_and_send_limit() {
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1000);
    let instant = Instant::now();
    let mut item = claim();
    item.lease_until = now + Duration::from_secs(30);
    item.expires_at = now + Duration::from_secs(10);

    assert_eq!(
        send_deadline(&item, now, instant),
        Some(instant + Duration::from_secs(10))
    );

    item.expires_at = now + Duration::from_secs(100);
    assert_eq!(
        send_deadline(&item, now, instant),
        Some(instant + SEND_DEADLINE)
    );
    assert_eq!(send_deadline(&item, item.lease_until, instant), None);
    assert_eq!(
        send_deadline(&item, now - Duration::from_secs(1), instant),
        None
    );
}

#[tokio::test]
async fn no_sender_runs_cleanup_only_and_sender_configuration_is_four_loops() {
    let service = Arc::new(FakeOutbox::new(None, false));
    let (stop_tx, stop_rx) = watch::channel(false);
    let cleanup_wait = service.cleanup_seen.notified();
    let tasks = spawn_loops(service.clone(), None, stop_rx, Duration::from_secs(30));
    assert_eq!(tasks.len(), 1);
    cleanup_wait.await;
    stop_tx.send(true).unwrap();
    for task in tasks {
        task.await.unwrap();
    }
    assert_eq!(service.cleanup_count.load(Ordering::SeqCst), 1);
    assert_eq!(service.claims.load(Ordering::SeqCst), 0);

    let (stop_tx, stop_rx) = watch::channel(true);
    let (entered, _entered_rx) = tokio::sync::mpsc::unbounded_channel();
    let delivery = Arc::new(WaitingDelivery {
        entered,
        release: Mutex::new(None),
        calls: AtomicUsize::new(0),
    });
    let tasks = spawn_loops(service, Some(delivery), stop_rx, Duration::ZERO);
    assert_eq!(tasks.len(), 1 + SENDERS);
    stop_tx.send(true).unwrap();
    for task in tasks {
        task.await.unwrap();
    }
}

#[tokio::test]
async fn stop_during_physical_send_waits_and_records_single_outcome() {
    let service = Arc::new(FakeOutbox::new(Some(claim()), false));
    let (entered_tx, mut entered_rx) = tokio::sync::mpsc::unbounded_channel();
    let (release_tx, release_rx) = oneshot::channel();
    let delivery = Arc::new(WaitingDelivery {
        entered: entered_tx,
        release: Mutex::new(Some(release_rx)),
        calls: AtomicUsize::new(0),
    });
    let (stop_tx, stop_rx) = watch::channel(false);
    let tasks = spawn_loops(
        service.clone(),
        Some(delivery.clone()),
        stop_rx,
        Duration::from_secs(30),
    );
    let email = timeout(Duration::from_secs(2), entered_rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(email.text_body.contains("code-secret"));
    assert_eq!(email.recipient, "person@example.test");

    stop_tx.send(true).unwrap();
    let mut drainer = tokio::spawn(async move {
        for task in tasks {
            let _ = task.await;
        }
    });
    assert!(timeout(Duration::from_millis(20), &mut drainer)
        .await
        .is_err());

    release_tx
        .send(SecurityEmailDeliveryOutcome::Accepted)
        .unwrap();
    drainer.await.unwrap();
    assert_eq!(delivery.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        *service.finishes.lock().unwrap(),
        [SecurityMailOutcome::Accepted]
    );
}

#[tokio::test]
async fn stop_after_claim_finishes_as_not_started_without_sending() {
    let (entered_tx, entered_rx) = std_mpsc::channel();
    let (release_tx, release_rx) = std_mpsc::channel();
    let service = Arc::new(BlockingClaimOutbox {
        claim: Mutex::new(Some(claim())),
        entered: Mutex::new(Some(entered_tx)),
        release: Mutex::new(release_rx),
        finishes: Mutex::new(Vec::new()),
    });
    let (delivery_entered_tx, _delivery_entered_rx) = tokio::sync::mpsc::unbounded_channel();
    let delivery = Arc::new(WaitingDelivery {
        entered: delivery_entered_tx,
        release: Mutex::new(None),
        calls: AtomicUsize::new(0),
    });
    let (stop_tx, stop_rx) = watch::channel(false);
    let tasks = spawn_loops(
        service.clone(),
        Some(delivery.clone()),
        stop_rx,
        Duration::from_secs(30),
    );

    tokio::task::spawn_blocking(move || entered_rx.recv().unwrap())
        .await
        .unwrap();
    stop_tx.send(true).unwrap();
    release_tx.send(()).unwrap();
    for task in tasks {
        task.await.unwrap();
    }

    assert_eq!(delivery.calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        *service.finishes.lock().unwrap(),
        [SecurityMailOutcome::NotStarted]
    );
}

#[tokio::test]
async fn failed_finish_does_not_retry_the_physical_send() {
    let service = Arc::new(FakeOutbox::new(Some(claim()), true));
    let (entered_tx, mut entered_rx) = tokio::sync::mpsc::unbounded_channel();
    let delivery = Arc::new(WaitingDelivery {
        entered: entered_tx,
        release: Mutex::new(None),
        calls: AtomicUsize::new(0),
    });
    // Immediate delivery helper for this case.
    struct ImmediateDelivery(Arc<WaitingDelivery>);
    impl SecurityEmailDeliveryService for ImmediateDelivery {
        fn send<'a>(
            &'a self,
            email: SecurityEmail,
            deadline: Instant,
        ) -> std::pin::Pin<Box<dyn Future<Output = SecurityEmailDeliveryOutcome> + Send + 'a>>
        {
            self.0.calls.fetch_add(1, Ordering::SeqCst);
            let _ = self.0.entered.send(email);
            Box::pin(async move {
                let _ = deadline;
                SecurityEmailDeliveryOutcome::Unknown
            })
        }
    }
    let immediate: Arc<dyn SecurityEmailDeliveryService> =
        Arc::new(ImmediateDelivery(delivery.clone()));
    let (stop_tx, stop_rx) = watch::channel(false);
    let tasks = spawn_loops(
        service.clone(),
        Some(immediate),
        stop_rx,
        Duration::from_secs(30),
    );
    timeout(Duration::from_secs(2), entered_rx.recv())
        .await
        .unwrap()
        .unwrap();
    timeout(Duration::from_secs(2), service.finish_seen.notified())
        .await
        .unwrap();
    stop_tx.send(true).unwrap();
    for task in tasks {
        task.await.unwrap();
    }
    assert_eq!(delivery.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        *service.finishes.lock().unwrap(),
        [SecurityMailOutcome::Unknown]
    );
    assert!(service.claims.load(Ordering::SeqCst) <= SENDERS);
}

#[tokio::test]
async fn bounded_drain_reaps_prior_completed_and_blocked_handles_once() {
    let completed = tokio::spawn(async {});
    let (started_tx, started_rx) = oneshot::channel();
    let blocked = tokio::spawn(async move {
        let _ = started_tx.send(());
        std::future::pending::<()>().await;
    });
    started_rx.await.unwrap();

    assert!(!drain_loops(vec![completed, blocked], Duration::from_millis(20)).await);
}
