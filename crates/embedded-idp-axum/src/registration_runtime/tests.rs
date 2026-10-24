use super::*;

use embedded_idp_core::access::*;
use embedded_idp_core::{PasswordWorkBudget, SecretString};
use embedded_idp_email::{
    RegistrationEmailDeliveryRequest, RegistrationEmailDeliveryService,
    RegistrationEmailSendOutcome,
};
use std::sync::{
    atomic::{AtomicUsize, Ordering as AtomicOrdering},
    mpsc, Arc, Mutex,
};
use std::time::{Duration, Instant as StdInstant};
use tokio::sync::Notify;

mod control;
mod fault;
mod shutdown;

#[derive(Clone)]
struct FakeService {
    scope: RegistrationEmailScope,
    policy: RegistrationEmailPolicy,
    budget: PasswordWorkBudget,
    facts: Arc<Mutex<Result<RegistrationEmailRuntimeFacts, RegistrationEmailError>>>,
    facts_block: Arc<Mutex<Option<BlockingGate>>>,
    maintenance_block: Arc<Mutex<Option<BlockingGate>>>,
    claim_block: Arc<Mutex<Option<BlockingGate>>>,
    delivery_claim_block: Arc<Mutex<Option<BlockingGate>>>,
    pause_block: Arc<Mutex<Option<BlockingGate>>>,
    resume_block: Arc<Mutex<Option<BlockingGate>>>,
    pause_calls: Arc<AtomicUsize>,
    resume_calls: Arc<AtomicUsize>,
    preparation_claim: Arc<Mutex<Option<RegistrationEmailPreparationClaim>>>,
    preparation_claim_calls: Arc<AtomicUsize>,
    prepare_calls: Arc<AtomicUsize>,
    preparation_result: Arc<Mutex<Result<RegistrationEmailPreparation, RegistrationEmailError>>>,
    delivery_claim_calls: Arc<AtomicUsize>,
    state: Arc<Mutex<FakeState>>,
}

struct BlockingGate {
    entered: Arc<Notify>,
    release: mpsc::Receiver<()>,
}

fn install_block(slot: &Arc<Mutex<Option<BlockingGate>>>) -> (mpsc::Sender<()>, Arc<Notify>) {
    let (release_tx, release_rx) = mpsc::channel();
    let entered = Arc::new(Notify::new());
    *slot.lock().unwrap() = Some(BlockingGate {
        entered: entered.clone(),
        release: release_rx,
    });
    (release_tx, entered)
}

fn wait_for_block(slot: &Arc<Mutex<Option<BlockingGate>>>) {
    let Some(gate) = slot.lock().unwrap().take() else {
        return;
    };
    gate.entered.notify_one();
    let _ = gate.release.recv();
}

struct FakeState {
    next_delivery: Option<Uuid>,
    message_available: bool,
    results: Vec<RegistrationEmailDeliveryResult>,
    paused: bool,
    unknown: Arc<Notify>,
    paused_signal: Arc<Notify>,
    stopped: Arc<Notify>,
}

impl FakeService {
    fn new() -> Self {
        Self::with_facts(Ok(RegistrationEmailRuntimeFacts {
            store_ready: true,
            accepting: true,
            overdue_processing: 0,
            unresolved_delivery: 0,
        }))
    }

    fn with_facts(facts: Result<RegistrationEmailRuntimeFacts, RegistrationEmailError>) -> Self {
        Self {
            scope: RegistrationEmailScope::new(
                "sut",
                "registration",
                "tenant-a",
                TenancyMode::Enabled,
            )
            .unwrap(),
            policy: RegistrationEmailPolicy::default(),
            budget: PasswordWorkBudget::default(),
            facts: Arc::new(Mutex::new(facts)),
            facts_block: Arc::new(Mutex::new(None)),
            maintenance_block: Arc::new(Mutex::new(None)),
            claim_block: Arc::new(Mutex::new(None)),
            delivery_claim_block: Arc::new(Mutex::new(None)),
            pause_block: Arc::new(Mutex::new(None)),
            resume_block: Arc::new(Mutex::new(None)),
            pause_calls: Arc::new(AtomicUsize::new(0)),
            resume_calls: Arc::new(AtomicUsize::new(0)),
            preparation_claim: Arc::new(Mutex::new(None)),
            preparation_claim_calls: Arc::new(AtomicUsize::new(0)),
            prepare_calls: Arc::new(AtomicUsize::new(0)),
            preparation_result: Arc::new(Mutex::new(Ok(RegistrationEmailPreparation::Prepared))),
            delivery_claim_calls: Arc::new(AtomicUsize::new(0)),
            state: Arc::new(Mutex::new(FakeState {
                next_delivery: None,
                message_available: false,
                results: Vec::new(),
                paused: false,
                unknown: Arc::new(Notify::new()),
                paused_signal: Arc::new(Notify::new()),
                stopped: Arc::new(Notify::new()),
            })),
        }
    }

    fn with_delivery() -> Self {
        let service = Self::new();
        let mut state = service.state.lock().unwrap();
        state.next_delivery = Some(Uuid::from_u128(1));
        state.message_available = true;
        drop(state);
        service
    }

    fn unknown_signal(&self) -> Arc<Notify> {
        self.state.lock().unwrap().unknown.clone()
    }

    fn paused_signal(&self) -> Arc<Notify> {
        self.state.lock().unwrap().paused_signal.clone()
    }

    fn stopped_signal(&self) -> Arc<Notify> {
        self.state.lock().unwrap().stopped.clone()
    }

    fn results(&self) -> Vec<RegistrationEmailDeliveryResult> {
        self.state.lock().unwrap().results.clone()
    }

    fn is_paused(&self) -> bool {
        self.state.lock().unwrap().paused
    }

    fn block_facts(&self) -> (mpsc::Sender<()>, Arc<Notify>) {
        install_block(&self.facts_block)
    }

    fn block_maintenance(&self) -> (mpsc::Sender<()>, Arc<Notify>) {
        install_block(&self.maintenance_block)
    }

    fn block_claim(&self) -> (mpsc::Sender<()>, Arc<Notify>) {
        install_block(&self.claim_block)
    }

    fn block_delivery_claim(&self) -> (mpsc::Sender<()>, Arc<Notify>) {
        install_block(&self.delivery_claim_block)
    }

    fn block_pause(&self) -> (mpsc::Sender<()>, Arc<Notify>) {
        install_block(&self.pause_block)
    }

    fn set_facts(&self, facts: Result<RegistrationEmailRuntimeFacts, RegistrationEmailError>) {
        *self.facts.lock().unwrap() = facts;
    }

    fn set_preparation_claim(&self, claim: RegistrationEmailPreparationClaim) {
        *self.preparation_claim.lock().unwrap() = Some(claim);
    }

    fn set_preparation_result(
        &self,
        result: Result<RegistrationEmailPreparation, RegistrationEmailError>,
    ) {
        *self.preparation_result.lock().unwrap() = result;
    }

    fn preparation_claim_calls(&self) -> usize {
        self.preparation_claim_calls.load(AtomicOrdering::Acquire)
    }

    fn prepare_calls(&self) -> usize {
        self.prepare_calls.load(AtomicOrdering::Acquire)
    }

    fn delivery_claim_calls(&self) -> usize {
        self.delivery_claim_calls.load(AtomicOrdering::Acquire)
    }

    fn pause_calls(&self) -> usize {
        self.pause_calls.load(AtomicOrdering::Acquire)
    }
}

impl RegistrationEmailService for FakeService {
    fn scope(&self) -> &RegistrationEmailScope {
        &self.scope
    }

    fn policy(&self) -> &RegistrationEmailPolicy {
        &self.policy
    }

    fn password_work_budget(&self) -> PasswordWorkBudget {
        self.budget.clone()
    }

    fn runtime_facts(&self) -> Result<RegistrationEmailRuntimeFacts, RegistrationEmailError> {
        wait_for_block(&self.facts_block);
        self.facts.lock().unwrap().clone()
    }

    fn is_replay(
        &self,
        _: RegistrationEmailOperationKind,
        _: Uuid,
    ) -> Result<bool, RegistrationEmailError> {
        Ok(false)
    }

    fn register_command(
        &self,
        _: RegistrationEmailCommand,
    ) -> Result<RegistrationEmailAccepted, RegistrationEmailError> {
        Ok(RegistrationEmailAccepted {
            verification_context: SecretString::new(format!("{}A", "A".repeat(42))),
            accepted_at_unix_secs: 1_713_894_200,
            context_lifetime_secs: 900,
            resend_after_secs: 60,
        })
    }

    fn resend_command(&self, _: Uuid, _: &str) -> Result<(), RegistrationEmailError> {
        Ok(())
    }

    fn verify_command(
        &self,
        _: Uuid,
        _: &str,
        _: &str,
    ) -> Result<RegistrationEmailVerification, RegistrationEmailError> {
        Ok(RegistrationEmailVerification::Unavailable)
    }

    fn claim_preparation(
        &self,
    ) -> Result<Option<RegistrationEmailPreparationClaim>, RegistrationEmailError> {
        self.preparation_claim_calls
            .fetch_add(1, AtomicOrdering::AcqRel);
        wait_for_block(&self.claim_block);
        Ok(self.preparation_claim.lock().unwrap().take())
    }

    fn prepare_claimed(
        &self,
        _: &RegistrationEmailPreparationClaim,
    ) -> Result<RegistrationEmailPreparation, RegistrationEmailError> {
        self.prepare_calls.fetch_add(1, AtomicOrdering::AcqRel);
        self.preparation_result.lock().unwrap().clone()
    }

    fn next_delivery(&self) -> Result<Option<Uuid>, RegistrationEmailError> {
        Ok(self.state.lock().unwrap().next_delivery.take())
    }

    fn claim_delivery(
        &self,
        effect_id: Uuid,
    ) -> Result<Option<RegistrationEmailDeliveryClaim>, RegistrationEmailError> {
        self.delivery_claim_calls
            .fetch_add(1, AtomicOrdering::AcqRel);
        wait_for_block(&self.delivery_claim_block);
        Ok(Some(RegistrationEmailDeliveryClaim {
            effect_id,
            context_id: Uuid::from_u128(2),
            sequence: 1,
            claim_token: Uuid::from_u128(3),
            lease_until: 1_713_894_300,
        }))
    }

    fn delivery_message(
        &self,
        _: &RegistrationEmailDeliveryClaim,
    ) -> Result<Option<RegistrationEmailMessage>, RegistrationEmailError> {
        let mut state = self.state.lock().unwrap();
        if !state.message_available {
            return Ok(None);
        }
        state.message_available = false;
        Ok(Some(RegistrationEmailMessage {
            email: SecretString::new("member@example.test"),
            code: SecretString::new("123456"),
            expires_at_unix_secs: 4_000_000_000,
            lease_remaining_millis: 500,
        }))
    }

    fn finish_delivery(
        &self,
        _: &RegistrationEmailDeliveryClaim,
        result: RegistrationEmailDeliveryResult,
    ) -> Result<(), RegistrationEmailError> {
        let signal = {
            let mut state = self.state.lock().unwrap();
            state.results.push(result);
            state.unknown.clone()
        };
        if result == RegistrationEmailDeliveryResult::Unknown {
            signal.notify_one();
        }
        Ok(())
    }

    fn confirm_delivery_stopped(
        &self,
        _: &RegistrationEmailDeliveryClaim,
    ) -> Result<(), RegistrationEmailError> {
        self.stopped_signal().notify_one();
        Ok(())
    }

    fn pause_registration(&self) -> Result<(), RegistrationEmailError> {
        self.pause_calls.fetch_add(1, AtomicOrdering::AcqRel);
        wait_for_block(&self.pause_block);
        let signal = {
            let mut state = self.state.lock().unwrap();
            state.paused = true;
            state.paused_signal.clone()
        };
        signal.notify_one();
        Ok(())
    }

    fn resume_registration(&self) -> Result<(), RegistrationEmailError> {
        self.resume_calls.fetch_add(1, AtomicOrdering::AcqRel);
        wait_for_block(&self.resume_block);
        self.state.lock().unwrap().paused = false;
        Ok(())
    }

    fn maintain_runtime(&self) -> Result<(), RegistrationEmailError> {
        wait_for_block(&self.maintenance_block);
        Ok(())
    }
}

struct ImmediateMailer;

impl RegistrationEmailDeliveryService for ImmediateMailer {
    fn send_registration_email(
        &self,
        _: RegistrationEmailDeliveryRequest,
        _: StdInstant,
    ) -> RegistrationEmailSendOutcome {
        RegistrationEmailSendOutcome::Sent
    }
}

fn runtime(service: Arc<FakeService>) -> Arc<RegistrationEmailRuntime> {
    RegistrationEmailRuntime::new(
        service.clone(),
        Arc::new(ImmediateMailer),
        service.budget.clone(),
    )
    .unwrap()
}

#[test]
fn rejects_a_password_budget_that_is_not_shared_with_the_service() {
    let service = Arc::new(FakeService::new());
    let result = RegistrationEmailRuntime::new(
        service,
        Arc::new(ImmediateMailer),
        PasswordWorkBudget::default(),
    );
    assert!(matches!(
        result,
        Err(RegistrationEmailError::InvalidInput("runtime_composition"))
    ));
}

#[tokio::test]
async fn readiness_is_closed_until_the_worker_starts_and_after_shutdown() {
    let service = Arc::new(FakeService::new());
    let runtime = runtime(service);
    assert!(!runtime.worker_running());

    let workers = runtime.start().await.unwrap();
    assert!(runtime.worker_running());
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
    assert!(!runtime.worker_running());
    assert!(runtime
        .try_request(RegistrationEmailOperationKind::Register, false)
        .is_err());
}

#[tokio::test]
async fn startup_rejects_unavailable_store_and_failed_facts() {
    let not_ready = Arc::new(FakeService::with_facts(Ok(RegistrationEmailRuntimeFacts {
        store_ready: false,
        accepting: true,
        overdue_processing: 0,
        unresolved_delivery: 0,
    })));
    let not_ready_runtime = runtime(not_ready);
    assert!(matches!(
        not_ready_runtime.start().await,
        Err(RegistrationEmailError::Unavailable)
    ));
    assert!(!not_ready_runtime.worker_running());

    let facts_failed = Arc::new(FakeService::with_facts(Err(
        RegistrationEmailError::Unavailable,
    )));
    let failed_runtime = runtime(facts_failed);
    assert!(matches!(
        failed_runtime.start().await,
        Err(RegistrationEmailError::Unavailable)
    ));
    assert!(!failed_runtime.worker_running());
}

#[tokio::test]
async fn cancellation_keeps_the_physical_request_permit_until_blocking_work_ends() {
    let service = Arc::new(FakeService::new());
    let runtime = runtime(service);
    let mut permits = (0..44)
        .map(|_| {
            runtime
                .try_request(RegistrationEmailOperationKind::Register, false)
                .unwrap()
        })
        .collect::<Vec<_>>();
    let physical = permits.pop().unwrap();
    let started = Arc::new(Notify::new());
    let done = Arc::new(Notify::new());
    let (release_tx, release_rx) = mpsc::channel();
    let started_for_call = started.clone();
    let done_for_call = done.clone();

    let task = tokio::spawn(registration_call(physical, move || {
        started_for_call.notify_one();
        release_rx.recv().unwrap();
        done_for_call.notify_one();
        Ok::<_, RegistrationEmailError>(())
    }));
    tokio::time::timeout(Duration::from_secs(1), started.notified())
        .await
        .expect("blocking operation started");
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert!(runtime
        .try_request(RegistrationEmailOperationKind::Register, false)
        .is_err());

    release_tx.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(1), done.notified())
        .await
        .expect("blocking operation ended");
    drop(permits);
    let mut released = None;
    for _ in 0..100 {
        if let Ok(permit) = runtime.try_request(RegistrationEmailOperationKind::Register, false) {
            released = Some(permit);
            break;
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    assert!(released.is_some());
}
