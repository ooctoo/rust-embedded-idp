mod delivery;
#[cfg(test)]
mod tests;
mod workers;
use embedded_idp_core::access::*;
use embedded_idp_core::PasswordWorkBudget;
use embedded_idp_email::RegistrationEmailDeliveryService;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
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
        permit(&self.probe)
    }
    pub fn try_request(
        &self,
        kind: RegistrationEmailOperationKind,
        replay: bool,
    ) -> Result<RegistrationEmailRequestPermit, RegistrationEmailError> {
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
    pub async fn start(
        self: &Arc<Self>,
    ) -> Result<RegistrationEmailWorkers, RegistrationEmailError> {
        if self.stopping.load(Ordering::Acquire) || self.started.swap(true, Ordering::AcqRel) {
            return Err(RegistrationEmailError::Unavailable);
        }
        let service = self.service.clone();
        let ready = tokio::task::spawn_blocking(move || service.runtime_facts())
            .await
            .map_err(|_| RegistrationEmailError::Unavailable);
        if !matches!(
            ready,
            Ok(Ok(RegistrationEmailRuntimeFacts {
                store_ready: true,
                ..
            }))
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
        tokio::task::spawn_blocking(move || s.resume_registration())
            .await
            .map_err(|_| RegistrationEmailError::Unavailable)??;
        self.failed.store(false, Ordering::Release);
        Ok(())
    }
    async fn pause(&self) {
        self.failed.store(true, Ordering::Release);
        let s = self.service.clone();
        let _ = tokio::task::spawn_blocking(move || s.pause_registration()).await;
    }
}
impl RegistrationEmailWorkers {
    pub async fn shutdown(mut self, grace: Duration) -> RegistrationEmailShutdown {
        self.runtime.stopping.store(true, Ordering::Release);
        self.runtime.stop.notify_waiters();
        let mut task = self.task.take().expect("worker task");
        let drained = matches!(tokio::time::timeout(grace, &mut task).await, Ok(Ok(())));
        if !drained {
            self.runtime.failed.store(true, Ordering::Release);
            task.abort();
            self.runtime.pause().await;
        }
        self.runtime.running.store(false, Ordering::Release);
        RegistrationEmailShutdown {
            drained,
            unresolved_processing: 4 - self.runtime.processing.available_permits(),
            unresolved_delivery: 2 - self.runtime.delivery.available_permits(),
        }
    }
}
impl Drop for RegistrationEmailWorkers {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            self.runtime.stopping.store(true, Ordering::Release);
            self.runtime.failed.store(true, Ordering::Release);
            self.runtime.running.store(false, Ordering::Release);
            self.runtime.stop.notify_waiters();
            task.abort();
        }
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
        self.0.failed.store(true, Ordering::Release);
    }
}
