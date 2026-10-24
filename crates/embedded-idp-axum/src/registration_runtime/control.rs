use super::*;

impl RegistrationEmailRuntime {
    pub(super) fn mark_failed(&self) {
        let _admission = self.admission.lock().unwrap_or_else(|e| e.into_inner());
        self.failure_revision.fetch_add(1, Ordering::AcqRel);
        self.failed.store(true, Ordering::Release);
    }

    /// Trusted operator only. This never appears in the anonymous router.
    pub async fn resume_after_operator_check(&self) -> Result<(), RegistrationEmailError> {
        let (physical, revision) = {
            let _admission = self.admission.lock().unwrap_or_else(|e| e.into_inner());
            if !self.running.load(Ordering::Acquire) || self.stopping.load(Ordering::Acquire) {
                return Err(RegistrationEmailError::Unavailable);
            }
            (
                permit(&self.probe)?,
                self.failure_revision.load(Ordering::Acquire),
            )
        };
        // The existing four probe slots bound both control waiters and physical
        // calls. Serialize pause/resume effects until their actual closure ends;
        // cancellation must not release this lock or its admission early.
        let control = self.control.clone().lock_owned().await;
        {
            let _admission = self.admission.lock().unwrap_or_else(|e| e.into_inner());
            if !self.can_finish_resume(revision) {
                return Err(RegistrationEmailError::Unavailable);
            }
        }
        let service = self.service.clone();
        self.storage_call(move || {
            let _physical = (physical, control);
            service.resume_registration()
        })
        .await?;
        let _admission = self.admission.lock().unwrap_or_else(|e| e.into_inner());
        if !self.can_finish_resume(revision) {
            // A pre-stop effect may already have committed. Do not undo it or
            // retry: the stopped/failed runtime remains closed to new work.
            return Err(RegistrationEmailError::Unavailable);
        }
        self.failed.store(false, Ordering::Release);
        Ok(())
    }

    fn can_finish_resume(&self, revision: usize) -> bool {
        self.running.load(Ordering::Acquire)
            && !self.stopping.load(Ordering::Acquire)
            && self.failure_revision.load(Ordering::Acquire) == revision
    }

    pub(super) async fn pause(&self) {
        self.mark_failed();
        if self.stopping.load(Ordering::Acquire) {
            return;
        }
        let control = self.control.clone().lock_owned().await;
        if self.stopping.load(Ordering::Acquire) {
            return;
        }
        let service = self.service.clone();
        let _ = self
            .storage_call(move || {
                let _control = control;
                service.pause_registration()
            })
            .await;
    }
}
