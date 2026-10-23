mod delivery;
#[cfg(test)]
mod tests;
mod workers;
use embedded_idp_core::access::*;
use embedded_idp_core::PasswordWorkBudget;
use embedded_idp_email::RegistrationEmailDeliveryService;
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc, Mutex,
};
use tokio::{
    sync::{Notify, OwnedSemaphorePermit, Semaphore},
    task::JoinHandle,
    time::{Duration, Instant},
};

#[derive(Clone)]
pub struct RegistrationEmailRequestPermit {
    _hold: Arc<OwnedSemaphorePermit>,
}
/// One runtime per trusted Host composition; no hidden mailbox, credentials or source limiter.
pub struct RegistrationEmailRuntime {
    service: Arc<dyn RegistrationEmailService>,
    login_http: crate::AnonymousLoginBudget,
    mail: Arc<dyn RegistrationEmailDeliveryService>,
    started: AtomicBool,
    running: AtomicBool,
    failed: AtomicBool,
    stopping: AtomicBool,
    stop: Notify,
    admission: Mutex<()>,
    storage_calls: Arc<AtomicUsize>,
    shutdown_deadline: Mutex<Option<Instant>>,
    start: Arc<Semaphore>,
    verify: Arc<Semaphore>,
    replay: Arc<Semaphore>,
    probe: Arc<Semaphore>,
    processing: Arc<Semaphore>,
    delivery: Arc<Semaphore>,
}
pub struct RegistrationEmailWorkers {
    runtime: Arc<RegistrationEmailRuntime>,
    task: Option<JoinHandle<()>>,
}
#[derive(Debug, Clone, Copy)]
pub struct RegistrationEmailShutdown {
    pub drained: bool,
    pub unresolved_processing: usize,
    pub unresolved_delivery: usize,
    pub unresolved_storage: usize,
    pub unresolved_requests: usize,
    pub failed: bool,
}

struct StorageCallGuard(Arc<AtomicUsize>);
impl Drop for StorageCallGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}
impl RegistrationEmailRuntime {
    /// The same budget must be injected into ALL adjacent login services by the Host.
    pub fn new(
        service: Arc<dyn RegistrationEmailService>,
        mail: Arc<dyn RegistrationEmailDeliveryService>,
        login_budget: PasswordWorkBudget,
    ) -> Result<Arc<Self>, RegistrationEmailError> {
        if !service.password_work_budget().same_budget(&login_budget)
            || service.policy() != &RegistrationEmailPolicy::default()
        {
            return Err(RegistrationEmailError::InvalidInput("runtime_composition"));
        }
        Ok(Arc::new(Self {
            service,
            mail,
            login_http: crate::AnonymousLoginBudget::default(),
            started: AtomicBool::new(false),
            running: AtomicBool::new(false),
            failed: AtomicBool::new(false),
            stopping: AtomicBool::new(false),
            stop: Notify::new(),
            admission: Mutex::new(()),
            storage_calls: Arc::new(AtomicUsize::new(0)),
            shutdown_deadline: Mutex::new(None),
            start: Arc::new(Semaphore::new(44)),
            verify: Arc::new(Semaphore::new(8)),
            replay: Arc::new(Semaphore::new(4)),
            probe: Arc::new(Semaphore::new(4)),
            processing: Arc::new(Semaphore::new(4)),
            delivery: Arc::new(Semaphore::new(2)),
        }))
    }
    pub fn login_http_budget(&self) -> crate::AnonymousLoginBudget {
        self.login_http.clone()
    }
    pub fn service(&self) -> Arc<dyn RegistrationEmailService> {
        self.service.clone()
    }
    pub fn worker_running(&self) -> bool {
        self.running.load(Ordering::Acquire)
            && !self.failed.load(Ordering::Acquire)
            && !self.stopping.load(Ordering::Acquire)
    }
    pub fn try_probe(&self) -> Result<RegistrationEmailRequestPermit, RegistrationEmailError> {
        let _admission = self
            .admission
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if self.stopping.load(Ordering::Acquire) {
            return Err(RegistrationEmailError::Unavailable);
        }
        permit(&self.probe)
    }
    pub fn try_request(
        &self,
        kind: RegistrationEmailOperationKind,
        replay: bool,
    ) -> Result<RegistrationEmailRequestPermit, RegistrationEmailError> {
        let _admission = self
            .admission
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if self.stopping.load(Ordering::Acquire) {
            return Err(RegistrationEmailError::Unavailable);
        }
        permit(if replay {
            &self.replay
        } else if kind == RegistrationEmailOperationKind::Verify {
            &self.verify
        } else {
            &self.start
        })
    }
    fn shutdown_expired(&self) -> bool {
        self.shutdown_deadline
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .is_some_and(|deadline| Instant::now() >= deadline)
    }
    fn shutdown_deadline(&self) -> Option<Instant> {
        *self
            .shutdown_deadline
            .lock()
            .unwrap_or_else(|error| error.into_inner())
    }
    fn begin_shutdown(&self, grace: Duration) {
        let _admission = self
            .admission
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        self.stopping.store(true, Ordering::Release);
        let candidate = Instant::now() + grace;
        let mut deadline = self
            .shutdown_deadline
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if deadline.map_or(true, |existing| candidate < existing) {
            *deadline = Some(candidate);
        }
        drop(deadline);
        self.stop.notify_waiters();
    }
    fn unresolved_requests(&self) -> usize {
        44 - self.start.available_permits()
            + (8 - self.verify.available_permits())
            + (4 - self.replay.available_permits())
            + (4 - self.probe.available_permits())
    }
    fn unresolved_storage(&self) -> usize {
        self.storage_calls.load(Ordering::Acquire)
    }
    fn drained_counts(&self) -> bool {
        self.unresolved_processing() == 0
            && self.unresolved_delivery() == 0
            && self.unresolved_storage() == 0
            && self.unresolved_requests() == 0
    }
    fn unresolved_processing(&self) -> usize {
        4 - self.processing.available_permits()
    }
    fn unresolved_delivery(&self) -> usize {
        2 - self.delivery.available_permits()
    }
    async fn wait_for_drain(&self, deadline: Instant) {
        while !self.drained_counts() {
            let now = Instant::now();
            if now >= deadline {
                break;
            }
            tokio::time::sleep((deadline - now).min(Duration::from_millis(5))).await;
        }
    }
    pub(super) async fn storage_call<T: Send + 'static>(
        &self,
        f: impl FnOnce() -> Result<T, RegistrationEmailError> + Send + 'static,
    ) -> Result<T, RegistrationEmailError> {
        if self.shutdown_expired() {
            return Err(RegistrationEmailError::Unavailable);
        }
        let tracker = self.storage_calls.clone();
        tracker.fetch_add(1, Ordering::AcqRel);
        let guard = StorageCallGuard(tracker);
        tokio::task::spawn_blocking(move || {
            let _guard = guard;
            f()
        })
        .await
        .map_err(|_| RegistrationEmailError::Unavailable)?
    }
    pub async fn start(
        self: &Arc<Self>,
    ) -> Result<RegistrationEmailWorkers, RegistrationEmailError> {
        if self.stopping.load(Ordering::Acquire) || self.started.swap(true, Ordering::AcqRel) {
            return Err(RegistrationEmailError::Unavailable);
        }
        let service = self.service.clone();
        let ready = self.storage_call(move || service.runtime_facts()).await;
        if !matches!(
            ready,
            Ok(RegistrationEmailRuntimeFacts {
                store_ready: true,
                ..
            })
        ) {
            self.started.store(false, Ordering::Release);
            return Err(RegistrationEmailError::Unavailable);
        }
        let this = self.clone();
        let (loaded, ready) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            let _state = WorkerStateGuard(this.clone());
            this.running.store(true, Ordering::Release);
            let _ = loaded.send(());
            this.run_workers().await
        });
        let workers = RegistrationEmailWorkers {
            runtime: self.clone(),
            task: Some(task),
        };
        ready
            .await
            .map_err(|_| RegistrationEmailError::Unavailable)?;
        Ok(workers)
    }
    /// Trusted operator only. This never appears in the anonymous router.
    pub async fn resume_after_operator_check(&self) -> Result<(), RegistrationEmailError> {
        if !self.running.load(Ordering::Acquire) || self.stopping.load(Ordering::Acquire) {
            return Err(RegistrationEmailError::Unavailable);
        }
        let s = self.service.clone();
        self.storage_call(move || s.resume_registration()).await?;
        self.failed.store(false, Ordering::Release);
        Ok(())
    }
    async fn pause(&self) {
        self.failed.store(true, Ordering::Release);
        if self.stopping.load(Ordering::Acquire) {
            return;
        }
        let s = self.service.clone();
        let _ = self.storage_call(move || s.pause_registration()).await;
    }
}
fn permit(s: &Arc<Semaphore>) -> Result<RegistrationEmailRequestPermit, RegistrationEmailError> {
    s.clone()
        .try_acquire_owned()
        .map(|p| RegistrationEmailRequestPermit { _hold: Arc::new(p) })
        .map_err(|_| RegistrationEmailError::Unavailable)
}
pub(crate) async fn registration_call<T: Send + 'static>(
    permit: RegistrationEmailRequestPermit,
    f: impl FnOnce() -> Result<T, RegistrationEmailError> + Send + 'static,
) -> Result<T, RegistrationEmailError> {
    tokio::task::spawn_blocking(move || {
        let _physical = permit;
        f()
    })
    .await
    .map_err(|_| RegistrationEmailError::Unavailable)?
}
pub(crate) async fn anonymous_response_delay(start: Instant) {
    use embedded_idp_core::access::registration_response_jitter_millis;
    tokio::time::sleep_until(
        start + Duration::from_millis(750 + registration_response_jitter_millis()),
    )
    .await;
}

// A task panic or cancellation must revoke the in-memory capability too.
struct WorkerStateGuard(Arc<RegistrationEmailRuntime>);
impl Drop for WorkerStateGuard {
    fn drop(&mut self) {
        self.0.running.store(false, Ordering::Release);
        if !self.0.stopping.load(Ordering::Acquire) {
            self.0.failed.store(true, Ordering::Release);
        }
    }
}
