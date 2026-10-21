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
            let facts = tokio::task::spawn_blocking(move || s.runtime_facts()).await;
            let accepting = matches!(&facts,Ok(Ok(f)) if f.store_ready && f.accepting && f.overdue_processing==0 && f.unresolved_delivery==0);
            match facts {
                Ok(Ok(f))
                    if f.store_ready && f.overdue_processing == 0 && f.unresolved_delivery == 0 => {
                }
                _ => {
                    self.pause().await;
                }
            }
            if Instant::now() >= next_maintenance {
                let s = self.service.clone();
                if !matches!(
                    tokio::task::spawn_blocking(move || s.maintain_runtime()).await,
                    Ok(Ok(()))
                ) {
                    self.pause().await;
                }
                next_maintenance = Instant::now() + Duration::from_secs(1);
            }
            if !accepting || self.failed.load(Ordering::Acquire) {
                tokio::select! {_=self.stop.notified()=>{},_=tokio::time::sleep(Duration::from_millis(100))=>{}}
                continue;
            }
            // Claim and physical execution each have finite local and shared-store ceilings.
            for _ in 0..4 {
                let Ok(p) = self.processing.clone().try_acquire_owned() else {
                    break;
                };
                let p = Arc::new(p);
                let s = self.service.clone();
                let held = p.clone();
                let claim = tokio::task::spawn_blocking(move || {
                    let _hold = held;
                    s.claim_preparation()
                })
                .await;
                match claim {
                    Ok(Ok(Some(claim))) => {
                        let s = self.service.clone();
                        jobs.spawn(async move {
                            tokio::task::spawn_blocking(move || {
                                let _hold = p;
                                s.prepare_claimed(&claim)
                            })
                            .await
                            .is_ok_and(|r| r.is_ok())
                        });
                    }
                    Ok(Ok(None)) => break,
                    _ => {
                        self.pause().await;
                        break;
                    }
                }
            }
            for _ in 0..2 {
                let Ok(p) = self.delivery.clone().try_acquire_owned() else {
                    break;
                };
                let p = Arc::new(p);
                let s = self.service.clone();
                let held = p.clone();
                let claim = tokio::task::spawn_blocking(move || {
                    let _hold = held;
                    match s.next_delivery()? {
                        Some(id) => s.claim_delivery(id),
                        None => Ok(None),
                    }
                })
                .await;
                match claim {
                    Ok(Ok(Some(claim))) => {
                        let this = self.clone();
                        jobs.spawn(async move { this.deliver(claim, p).await });
                    }
                    Ok(Ok(None)) => break,
                    _ => {
                        self.pause().await;
                        break;
                    }
                }
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
