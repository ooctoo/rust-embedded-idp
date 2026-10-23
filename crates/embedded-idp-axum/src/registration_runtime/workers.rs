use super::*;
use tokio::task::JoinSet;
impl RegistrationEmailRuntime {
    pub(super) async fn run_workers(self: Arc<Self>) {
        let mut jobs = JoinSet::new();
        let mut next_maintenance = Instant::now();
        loop {
            while let Some(done) = jobs.try_join_next() {
                if !matches!(done, Ok(true)) {
                    self.pause().await;
                }
            }
            if self.stopping.load(Ordering::Acquire) {
                break;
            }
            let s = self.service.clone();
            let facts = self.storage_call(move || s.runtime_facts()).await;
            if self.stopping.load(Ordering::Acquire) {
                break;
            }
            let accepting = matches!(&facts, Ok(f) if f.store_ready && f.accepting && f.overdue_processing == 0 && f.unresolved_delivery == 0);
            match facts {
                Ok(f)
                    if f.store_ready && f.overdue_processing == 0 && f.unresolved_delivery == 0 => {
                }
                _ => {
                    self.pause().await;
                }
            }
            if Instant::now() >= next_maintenance {
                if self.stopping.load(Ordering::Acquire) {
                    break;
                }
                let s = self.service.clone();
                let maintenance = self.storage_call(move || s.maintain_runtime()).await;
                if self.stopping.load(Ordering::Acquire) {
                    break;
                }
                if !matches!(maintenance, Ok(())) {
                    self.pause().await;
                }
                next_maintenance = Instant::now() + Duration::from_secs(1);
            }
            if self.stopping.load(Ordering::Acquire) {
                break;
            }
            if !accepting || self.failed.load(Ordering::Acquire) {
                tokio::select! {_=self.stop.notified()=>{},_=tokio::time::sleep(Duration::from_millis(100))=>{}}
                continue;
            }
            // Claim and physical execution each have finite local and shared-store ceilings.
            for _ in 0..4 {
                if self.stopping.load(Ordering::Acquire) {
                    break;
                }
                let Ok(p) = self.processing.clone().try_acquire_owned() else {
                    break;
                };
                let p = Arc::new(p);
                let s = self.service.clone();
                let held = p.clone();
                let claim = self
                    .storage_call(move || {
                        let _hold = held;
                        s.claim_preparation()
                    })
                    .await;
                match claim {
                    Ok(Some(claim)) => {
                        let this = self.clone();
                        let s = self.service.clone();
                        jobs.spawn(async move {
                            this.storage_call(move || {
                                let _hold = p;
                                s.prepare_claimed(&claim)
                            })
                            .await
                            .is_ok()
                        });
                    }
                    Ok(None) => break,
                    _ => {
                        self.pause().await;
                        break;
                    }
                }
            }
            if self.stopping.load(Ordering::Acquire) {
                break;
            }
            for _ in 0..2 {
                if self.stopping.load(Ordering::Acquire) {
                    break;
                }
                let Ok(p) = self.delivery.clone().try_acquire_owned() else {
                    break;
                };
                let p = Arc::new(p);
                let s = self.service.clone();
                let held = p.clone();
                let claim = self
                    .storage_call(move || {
                        let _hold = held;
                        match s.next_delivery()? {
                            Some(id) => s.claim_delivery(id),
                            None => Ok(None),
                        }
                    })
                    .await;
                match claim {
                    Ok(Some(claim)) => {
                        let this = self.clone();
                        jobs.spawn(async move { this.deliver(claim, p).await });
                    }
                    Ok(None) => break,
                    _ => {
                        self.pause().await;
                        break;
                    }
                }
            }
            if self.stopping.load(Ordering::Acquire) {
                break;
            }
            tokio::select! {_=self.stop.notified()=>{},_=tokio::time::sleep(Duration::from_millis(100))=>{}}
        }
        // Closing admission is immediate; in-flight effects retain their physical permits.
        while let Some(done) = jobs.join_next().await {
            if !matches!(done, Ok(true)) {
                self.pause().await;
            }
        }
        self.running.store(false, Ordering::Release);
    }
}

impl RegistrationEmailWorkers {
    pub fn begin_shutdown(&self, grace: Duration) {
        self.runtime.begin_shutdown(grace);
    }
    pub async fn shutdown(mut self, grace: Duration) -> RegistrationEmailShutdown {
        self.begin_shutdown(grace);
        let runtime = self.runtime.clone();
        let mut task_joined = false;
        {
            let task = self.task.as_mut().expect("worker task");
            let task_result = match runtime.shutdown_deadline() {
                Some(deadline) => tokio::time::timeout_at(deadline, &mut *task).await,
                None => unreachable!("shutdown deadline must be set before waiting"),
            };
            match task_result {
                Ok(Ok(())) => task_joined = true,
                Ok(Err(_)) | Err(_) => {
                    runtime.failed.store(true, Ordering::Release);
                    if !task.is_finished() {
                        task.abort();
                    }
                    let _ = task.await;
                }
            }
        }
        if !task_joined {
            runtime.failed.store(true, Ordering::Release);
        }
        if task_joined {
            if let Some(deadline) = runtime.shutdown_deadline() {
                runtime.wait_for_drain(deadline).await;
            }
        }
        runtime.running.store(false, Ordering::Release);
        let unresolved_processing = runtime.unresolved_processing();
        let unresolved_delivery = runtime.unresolved_delivery();
        let unresolved_storage = runtime.unresolved_storage();
        let unresolved_requests = runtime.unresolved_requests();
        let failed = runtime.failed.load(Ordering::Acquire);
        self.task.take();
        RegistrationEmailShutdown {
            drained: task_joined
                && unresolved_processing == 0
                && unresolved_delivery == 0
                && unresolved_storage == 0
                && unresolved_requests == 0,
            unresolved_processing,
            unresolved_delivery,
            unresolved_storage,
            unresolved_requests,
            failed,
        }
    }
}

impl Drop for RegistrationEmailWorkers {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            self.runtime.begin_shutdown(Duration::ZERO);
            self.runtime.failed.store(true, Ordering::Release);
            self.runtime.running.store(false, Ordering::Release);
            task.abort();
        }
    }
}
