//! Physical P-boundary acceptance for resend and verify registration operations.
//!
//! These cases stay ignored by default. They require a fresh isolated
//! PostgreSQL fixture and are intended to run serially.

#![allow(dead_code, unused_imports)]

mod registration_capacity_support;
mod registration_capacity_variants_support;
mod registration_email_support;
mod registration_transport_support;

use registration_capacity_variants_support::{run, VariantKind};

#[test]
#[ignore = "requires fresh loopback sut_idp3_test with explicit confirmation"]
fn resend_p_commit_not_forwarded_recovers() {
    run(VariantKind::Resend, true);
}

#[test]
#[ignore = "requires fresh loopback sut_idp3_test with explicit confirmation"]
fn resend_p_commit_ack_blackhole_recovers() {
    run(VariantKind::Resend, false);
}

#[test]
#[ignore = "requires fresh loopback sut_idp3_test with explicit confirmation"]
fn verify_p_commit_not_forwarded_recovers() {
    run(VariantKind::Verify, true);
}

#[test]
#[ignore = "requires fresh loopback sut_idp3_test with explicit confirmation"]
fn verify_p_commit_ack_blackhole_recovers() {
    run(VariantKind::Verify, false);
}
