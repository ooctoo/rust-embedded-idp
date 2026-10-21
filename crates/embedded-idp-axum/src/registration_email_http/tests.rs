use super::*;

use crate::{RegistrationEmailRuntime, RegistrationEmailWorkers};
use axum::body::to_bytes;
use axum::body::Body;
use axum::http::{header, HeaderMap, HeaderValue, Request, StatusCode};
use axum::response::Response;
use axum::Router;
use embedded_idp_core::access::*;
use embedded_idp_core::{PasswordWorkBudget, SecretString};
use embedded_idp_email::{
    RegistrationEmailDeliveryRequest, RegistrationEmailDeliveryService,
    RegistrationEmailSendOutcome,
};
use serde_json::Value;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant as StdInstant};
use tower::ServiceExt;

fn profile_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.append(
        REGISTRATION_EMAIL_PROFILE_HEADER,
        HeaderValue::from_static(REGISTRATION_EMAIL_PROFILE),
    );
    headers
}

fn context() -> String {
    format!("{}A", "A".repeat(42))
}

#[derive(Clone)]
struct FakeService {
    scope: RegistrationEmailScope,
    policy: RegistrationEmailPolicy,
    budget: PasswordWorkBudget,
    calls: Arc<Mutex<usize>>,
    facts: RegistrationEmailRuntimeFacts,
    replay: bool,
    verify: RegistrationEmailVerification,
}

impl FakeService {
    fn new() -> Self {
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
            calls: Arc::new(Mutex::new(0)),
            facts: RegistrationEmailRuntimeFacts {
                store_ready: true,
                accepting: true,
                overdue_processing: 0,
                unresolved_delivery: 0,
            },
            replay: false,
            verify: RegistrationEmailVerification::Unavailable,
        }
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
        Ok(self.facts.clone())
    }
    fn is_replay(
        &self,
        _: RegistrationEmailOperationKind,
        _: Uuid,
    ) -> Result<bool, RegistrationEmailError> {
        Ok(self.replay)
    }
    fn register_command(
        &self,
        command: RegistrationEmailCommand,
    ) -> Result<RegistrationEmailAccepted, RegistrationEmailError> {
        *self.calls.lock().unwrap() += 1;
        assert_eq!(command.email.expose_secret(), "member@example.test");
        assert_eq!(command.password.expose_secret(), "Correct-Horse-7");
        Ok(RegistrationEmailAccepted {
            verification_context: SecretString::new(context()),
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
        Ok(self.verify)
    }
    fn claim_preparation(
        &self,
    ) -> Result<Option<RegistrationEmailPreparationClaim>, RegistrationEmailError> {
        Ok(None)
    }
    fn prepare_claimed(
        &self,
        _: &RegistrationEmailPreparationClaim,
    ) -> Result<RegistrationEmailPreparation, RegistrationEmailError> {
        Ok(RegistrationEmailPreparation::Prepared)
    }
    fn next_delivery(&self) -> Result<Option<Uuid>, RegistrationEmailError> {
        Ok(None)
    }
    fn claim_delivery(
        &self,
        _: Uuid,
    ) -> Result<Option<RegistrationEmailDeliveryClaim>, RegistrationEmailError> {
        Ok(None)
    }
    fn delivery_message(
        &self,
        _: &RegistrationEmailDeliveryClaim,
    ) -> Result<Option<RegistrationEmailMessage>, RegistrationEmailError> {
        Ok(None)
    }
    fn finish_delivery(
        &self,
        _: &RegistrationEmailDeliveryClaim,
        _: RegistrationEmailDeliveryResult,
    ) -> Result<(), RegistrationEmailError> {
        Ok(())
    }
    fn confirm_delivery_stopped(
        &self,
        _: &RegistrationEmailDeliveryClaim,
    ) -> Result<(), RegistrationEmailError> {
        Ok(())
    }
    fn pause_registration(&self) -> Result<(), RegistrationEmailError> {
        Ok(())
    }
    fn resume_registration(&self) -> Result<(), RegistrationEmailError> {
        Ok(())
    }
    fn maintain_runtime(&self) -> Result<(), RegistrationEmailError> {
        Ok(())
    }
}

struct NoopMailer;

impl RegistrationEmailDeliveryService for NoopMailer {
    fn send_registration_email(
        &self,
        _: RegistrationEmailDeliveryRequest,
        _: StdInstant,
    ) -> RegistrationEmailSendOutcome {
        RegistrationEmailSendOutcome::Sent
    }
}

async fn app() -> (Router, RegistrationEmailWorkers, Arc<FakeService>) {
    let service = Arc::new(FakeService::new());
    let (router, workers) = app_for_service(service.clone(), true).await;
    (router, workers.expect("started worker"), service)
}

async fn app_for_service(
    service: Arc<FakeService>,
    start: bool,
) -> (Router, Option<RegistrationEmailWorkers>) {
    let runtime = RegistrationEmailRuntime::new(
        service.clone(),
        Arc::new(NoopMailer),
        service.budget.clone(),
    )
    .unwrap();
    let workers = if start {
        Some(runtime.start().await.unwrap())
    } else {
        None
    };
    let router =
        registration_email_router(runtime, RegistrationEmailHttpConfig::default()).unwrap();
    (router, workers)
}

fn request(path: &str, body: &str) -> Request<Body> {
    Request::post(path)
        .header(header::CONTENT_TYPE, "application/json")
        .header(
            REGISTRATION_EMAIL_PROFILE_HEADER,
            REGISTRATION_EMAIL_PROFILE,
        )
        .body(Body::from(body.to_owned()))
        .unwrap()
}

async fn json(response: Response) -> Value {
    serde_json::from_slice(
        &to_bytes(response.into_body(), MAX_BODY_BYTES)
            .await
            .unwrap(),
    )
    .unwrap()
}

mod route_tests;
mod validation_tests;
