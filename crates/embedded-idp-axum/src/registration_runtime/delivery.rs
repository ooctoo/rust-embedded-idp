use super::*;
use embedded_idp_email::{RegistrationEmailDeliveryRequest, RegistrationEmailSendOutcome};
use std::time::UNIX_EPOCH;
impl RegistrationEmailRuntime {
    pub(super) async fn deliver(
        self: Arc<Self>,
        claim: RegistrationEmailDeliveryClaim,
        physical: Arc<OwnedSemaphorePermit>,
    ) -> bool {
        let message_started = std::time::Instant::now();
        let s = self.service.clone();
        let c = claim.clone();
        let hold = physical.clone();
        let message = tokio::task::spawn_blocking(move || {
            let _hold = hold;
            s.delivery_message(&c)
        })
        .await;
        let message = match message {
            Ok(Ok(Some(m))) => m,
            Ok(Ok(None)) => return true,
            _ => {
                self.finish_unknown(&claim, true).await;
                return false;
            }
        };
        let deadline =
            message_started + Duration::from_millis(message.lease_remaining_millis.min(15000));
        if deadline <= std::time::Instant::now() || self.stopping.load(Ordering::Acquire) {
            self.finish_unknown(&claim, true).await;
            return true;
        }
        let request = RegistrationEmailDeliveryRequest {
            email: message.email.expose_secret().to_owned(),
            code: message.code.expose_secret().to_owned(),
            expires_at: UNIX_EPOCH
                + Duration::from_secs(message.expires_at_unix_secs.max(0) as u64),
        };
        let mail = self.mail.clone();
        let mut send = tokio::task::spawn_blocking(move || {
            let _physical = physical;
            mail.send_registration_email(request, deadline)
        });
        match tokio::time::timeout_at(Instant::from_std(deadline), &mut send).await {
            Ok(result) => {
                let outcome = match result {
                    Ok(RegistrationEmailSendOutcome::Sent) => RegistrationEmailDeliveryResult::Sent,
                    Ok(RegistrationEmailSendOutcome::Rejected) => {
                        RegistrationEmailDeliveryResult::Failed
                    }
                    _ => RegistrationEmailDeliveryResult::Unknown,
                };
                let s = self.service.clone();
                let c = claim.clone();
                let done =
                    tokio::task::spawn_blocking(move || s.finish_delivery(&c, outcome)).await;
                if outcome == RegistrationEmailDeliveryResult::Unknown
                    || !matches!(done, Ok(Ok(())))
                {
                    self.finish_unknown(&claim, true).await;
                    return false;
                }
                true
            }
            Err(_) => {
                self.finish_unknown(&claim, false).await;
                self.pause().await;
                // No release/re-dispatch merely because a lease or async wait ended.
                let _ = send.await;
                let s = self.service.clone();
                let c = claim.clone();
                let _ = tokio::task::spawn_blocking(move || s.confirm_delivery_stopped(&c)).await;
                false
            }
        }
    }
    async fn finish_unknown(&self, claim: &RegistrationEmailDeliveryClaim, stopped: bool) {
        let s = self.service.clone();
        let c = claim.clone();
        let _ = tokio::task::spawn_blocking(move || {
            s.finish_delivery(&c, RegistrationEmailDeliveryResult::Unknown)
        })
        .await;
        if stopped {
            let s = self.service.clone();
            let c = claim.clone();
            let _ = tokio::task::spawn_blocking(move || s.confirm_delivery_stopped(&c)).await;
        }
    }
}
