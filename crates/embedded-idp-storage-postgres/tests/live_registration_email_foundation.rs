//! Live PostgreSQL coverage for the IDP-owned registration-email foundation.
//!
//! Every test requires the explicitly confirmed fresh loopback instance and
//! owns a random schema which is dropped by the fixture.

mod registration_email_support;

#[path = "registration_email_support/cases_admission.rs"]
mod cases_admission;
#[path = "registration_email_support/cases_capacity.rs"]
mod cases_capacity;
#[path = "registration_email_support/cases_recovery.rs"]
mod cases_recovery;
#[path = "registration_email_support/cases_recovery_concurrency.rs"]
mod cases_recovery_concurrency;
#[path = "registration_email_support/cases_verification.rs"]
mod cases_verification;
#[path = "registration_email_support/cases_verification_activation.rs"]
mod cases_verification_activation;
#[path = "registration_email_support/cases_verification_failure.rs"]
mod cases_verification_failure;

#[path = "registration_email_support/cases_process.rs"]
mod cases_process;
#[path = "registration_email_support/cases_storage_boundaries.rs"]
mod cases_storage_boundaries;
