use uuid::Timestamp;

use crate::{access::TenancyMode, SecretString, StoreError};

use super::{
    check_registration_operation_freshness, classify_registration_email_code_state,
    failure_block_until, prepare_registration_password, rolling_allowed, rolling_history,
    trim_rolling_history, CanonicalRegistrationEmail, RegistrationEmailCodeState,
    RegistrationEmailError, RegistrationEmailPolicy, RegistrationEmailScope, Uuid,
};

#[test]
fn scope_accepts_disabled_business_tenant_and_rejects_enabled_zero() {
    let scope = RegistrationEmailScope::new("sut", "online", "0", TenancyMode::Disabled)
        .expect("disabled tenant is valid");
    assert_eq!(scope.tenant, "0");
    assert!(matches!(
        RegistrationEmailScope::new("sut", "online", "0", TenancyMode::Enabled),
        Err(RegistrationEmailError::InvalidInput("tenant"))
    ));
    assert!(matches!(
        RegistrationEmailScope::new("bad scope", "online", "0", TenancyMode::Disabled),
        Err(RegistrationEmailError::InvalidInput("authority"))
    ));
}

#[test]
fn canonical_email_trims_outer_spaces_and_lowercases_only_domain() {
    let email = CanonicalRegistrationEmail::parse("  Alice.Tag+test@EXAMPLE.COM  ")
        .expect("valid canonical email");
    assert_eq!(email.identity(), "Alice.Tag+test@example.com");
    assert_eq!(email.abuse_identity(), "alice.tag+test@example.com");
    assert_eq!(
        format!("{email:?}"),
        "CanonicalRegistrationEmail(<redacted>)"
    );
    assert_eq!(format!("{email}"), "<redacted>");
}

#[test]
fn canonical_email_rejects_dot_atom_and_dns_boundaries() {
    for invalid in [
        "alice..tag@example.com",
        ".alice@example.com",
        "alice.@example.com",
        "alice example@example.com",
        "alice@example..com",
        "alice@-example.com",
        "alice@example-.com",
        "alice@example_com",
        "alice@example.com@other.com",
        "alice@例子.test",
    ] {
        assert!(
            CanonicalRegistrationEmail::parse(invalid).is_err(),
            "{invalid}"
        );
    }
}

#[test]
fn canonical_email_enforces_local_and_total_limits() {
    let local = "a".repeat(65);
    assert!(CanonicalRegistrationEmail::parse(&format!("{local}@example.com")).is_err());
    let domain = "a".repeat(246);
    assert!(CanonicalRegistrationEmail::parse(&format!("a@{domain}")).is_err());
    assert!(CanonicalRegistrationEmail::parse("a\tb@example.com").is_err());
}

#[test]
fn operation_kind_strings_and_password_hash_are_stable_contracts() {
    use super::RegistrationEmailOperationKind::{Register, Resend, Verify};
    assert_eq!(Register.as_str(), "register");
    assert_eq!(Resend.as_str(), "resend");
    assert_eq!(Verify.as_str(), "verify");

    let hash = prepare_registration_password(&SecretString::new("valid-password1"))
        .expect("password is accepted");
    assert!(hash.expose_secret().starts_with("$argon2id$"));
    for invalid in ["short1", "allletters", "12345678"] {
        assert!(prepare_registration_password(&SecretString::new(invalid)).is_err());
    }
    let too_long = "a1".repeat(65);
    assert!(prepare_registration_password(&SecretString::new(too_long)).is_err());
}

#[test]
fn policy_defaults_validate_and_bounds_reject_unsafe_changes() {
    let policy = RegistrationEmailPolicy::default();
    assert_eq!(policy.revision, 2);
    assert_eq!(policy.context_lifetime_secs, 900);
    assert_eq!(policy.context_wrong_limit, 5);
    assert_eq!(policy.product_email_send_limit_30m, 5);
    assert_eq!(policy.authority_email_wrong_limit, 30);
    assert!(policy.validate().is_ok());

    let mut invalid = policy.clone();
    invalid.db_transaction_deadline_secs = invalid.capacity_reservation_lease_secs;
    assert!(invalid.validate().is_err());
    invalid = policy;
    invalid.revision = 1;
    assert!(invalid.validate().is_err());

    let mut invalid = RegistrationEmailPolicy::default();
    invalid.processing_queue_max_age_secs = 31;
    assert!(invalid.validate().is_err());
    invalid = RegistrationEmailPolicy::default();
    invalid.authority_new_operation_start_ceiling = 0;
    assert!(invalid.validate().is_err());
    invalid = RegistrationEmailPolicy::default();
    invalid.durable_context_receipts_verify_reserve = 7_799;
    assert!(invalid.validate().is_err());
    invalid = RegistrationEmailPolicy::default();
    invalid.code_digits = 7;
    assert!(invalid.validate().is_err());
}

#[test]
fn rolling_window_uses_strict_lower_boundary_and_fixed_failure_anchor() {
    let mut history = vec![90, 91, 100, 101, 110];
    assert_eq!(rolling_history(&history, 110, 20), vec![91, 100, 101, 110]);
    assert!(rolling_allowed(&history, 110, 20, 5));
    assert!(!rolling_allowed(&history, 110, 20, 4));
    trim_rolling_history(&mut history, 110, 20);
    assert_eq!(history, vec![91, 100, 101, 110]);
    assert_eq!(failure_block_until(110, 900), Some(1_010));
    assert_eq!(failure_block_until(110, 0), None);
}

#[test]
fn non_ready_code_states_never_charge_email_error_budget() {
    let states = [
        RegistrationEmailCodeState::Unready,
        RegistrationEmailCodeState::Suppressed,
        RegistrationEmailCodeState::Expired,
        RegistrationEmailCodeState::Consumed,
        RegistrationEmailCodeState::Exhausted,
    ];
    assert!(states.iter().all(|state| !state.counts_email_error()));
    assert!(RegistrationEmailCodeState::Ready.counts_email_error());
    assert_eq!(
        classify_registration_email_code_state(false, true, false, 10, 20, Some(20), false, 0, 5),
        RegistrationEmailCodeState::Unready
    );
    assert_eq!(
        classify_registration_email_code_state(true, true, true, 10, 20, Some(20), false, 0, 5),
        RegistrationEmailCodeState::Suppressed
    );
    assert_eq!(
        classify_registration_email_code_state(true, true, false, 10, 20, Some(20), false, 4, 5),
        RegistrationEmailCodeState::Ready
    );
    assert_eq!(
        classify_registration_email_code_state(true, true, false, 10, 20, Some(20), false, 5, 5),
        RegistrationEmailCodeState::Exhausted
    );
}

fn operation_at(seconds: u64) -> Uuid {
    Uuid::new_v7(Timestamp::from_unix_time(seconds, 0, 0, 0))
}

#[test]
fn operation_freshness_rejects_non_v7_stale_and_future_ids() {
    assert_eq!(
        check_registration_operation_freshness(&Uuid::nil(), 1_700_000_000),
        Err(RegistrationEmailError::InvalidInput("operation_id"))
    );
    assert_eq!(
        check_registration_operation_freshness(&operation_at(1_700_000_000), 1_700_000_901),
        Err(RegistrationEmailError::RequestExpired)
    );
    assert_eq!(
        check_registration_operation_freshness(&operation_at(1_700_000_031), 1_700_000_000),
        Err(RegistrationEmailError::RequestExpired)
    );
    assert!(
        check_registration_operation_freshness(&operation_at(1_700_000_000), 1_700_000_900).is_ok()
    );
}

#[test]
fn registration_error_keeps_store_failure_typed() {
    let error = RegistrationEmailError::from(StoreError::Conflict("registration.operation"));
    assert!(matches!(
        error,
        RegistrationEmailError::Store(StoreError::Conflict(_))
    ));
}
