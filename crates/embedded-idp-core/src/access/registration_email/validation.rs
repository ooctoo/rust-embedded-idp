use super::rolling::retained_rows;
use super::{RegistrationEmailError, RegistrationEmailPolicy};

pub(super) fn validate_bounds(
    policy: &RegistrationEmailPolicy,
) -> Result<(), RegistrationEmailError> {
    // Revision 2 is intentionally bounded. A smaller isolated fixture is
    // valid, but deployment configuration cannot silently widen the
    // retention, guessing, or capacity envelope.
    for (value, maximum, field) in [
        (
            policy.authority_email_send_gap_secs,
            86_400,
            "authority_send_gap",
        ),
        (
            policy.product_email_send_gap_secs,
            86_400,
            "product_send_gap",
        ),
        (
            policy.product_email_send_window_30m_secs,
            1_800,
            "product_send_window_30m",
        ),
        (
            policy.product_email_send_window_24h_secs,
            86_400,
            "product_send_window_24h",
        ),
        (
            policy.authority_email_send_window_24h_secs,
            86_400,
            "authority_send_window",
        ),
        (policy.context_lifetime_secs, 900, "context_lifetime"),
        (
            policy.product_email_wrong_window_secs,
            900,
            "product_wrong_window",
        ),
        (
            policy.authority_email_wrong_window_secs,
            900,
            "authority_wrong_window",
        ),
        (
            policy.authority_new_operation_window_secs,
            60,
            "operation_window",
        ),
        (
            policy.capacity_reservation_lease_secs,
            30,
            "reservation_lease",
        ),
        (
            policy.db_transaction_deadline_secs,
            10,
            "transaction_deadline",
        ),
        (policy.processing_queue_max_age_secs, 30, "queue_max_age"),
        (policy.processing_lease_secs, 15, "processing_lease"),
        (policy.smtp_lease_secs, 15, "smtp_lease"),
        (policy.maintenance_sweep_max_secs, 600, "maintenance_sweep"),
        (policy.operation_id_max_age_secs, 900, "operation_max_age"),
        (
            policy.operation_id_future_skew_secs,
            30,
            "operation_future_skew",
        ),
        (policy.attempt_replay_grace_secs, 30, "attempt_replay_grace"),
        (policy.bucket_retention_extra_secs, 900, "bucket_retention"),
    ] {
        if value > maximum {
            return Err(RegistrationEmailError::InvalidInput(field));
        }
    }
    for (value, maximum, field) in [
        (
            policy.product_email_send_limit_30m as u64,
            5,
            "product_send_limit_30m",
        ),
        (
            policy.product_email_send_limit_24h as u64,
            10,
            "product_send_limit_24h",
        ),
        (
            policy.authority_email_send_limit_24h as u64,
            20,
            "authority_send_limit",
        ),
        (policy.context_wrong_limit as u64, 5, "context_wrong_limit"),
        (
            policy.product_email_wrong_limit as u64,
            20,
            "product_wrong_limit",
        ),
        (
            policy.authority_email_wrong_limit as u64,
            30,
            "authority_wrong_limit",
        ),
        (
            policy.context_count_per_product_email as u64,
            3,
            "context_count",
        ),
        (
            policy.context_slots_per_authority_email as u64,
            10,
            "context_slots",
        ),
        (policy.code_distinct_draw_limit as u64, 8, "code_draw_limit"),
        (
            policy.authority_new_operation_limit as u64,
            300,
            "operation_limit",
        ),
        (
            policy.authority_new_operation_start_ceiling as u64,
            200,
            "operation_start_ceiling",
        ),
        (policy.durable_context_receipts_cap, 40_000, "receipt_cap"),
        (
            policy.durable_context_receipts_verify_reserve,
            8_000,
            "verify_reserve",
        ),
        (
            policy.authority_subject_bucket_cap,
            20_000,
            "authority_bucket_cap",
        ),
        (
            policy.product_subject_bucket_cap,
            40_000,
            "product_bucket_cap",
        ),
        (
            policy.processing_concurrency as u64,
            4,
            "processing_concurrency",
        ),
        (policy.smtp_concurrency as u64, 2, "smtp_concurrency"),
        (
            policy.anonymous_security_event_retention_days as u64,
            7,
            "event_retention",
        ),
    ] {
        if value > maximum {
            return Err(RegistrationEmailError::InvalidInput(field));
        }
    }
    if policy.product_email_send_window_30m_secs >= policy.product_email_send_window_24h_secs
        || policy.context_slots_per_authority_email < policy.context_count_per_product_email
        || policy.durable_context_receipts_verify_reserve >= policy.durable_context_receipts_cap
        || policy.authority_new_operation_start_ceiling > policy.authority_new_operation_limit
        || policy.db_transaction_deadline_secs >= policy.capacity_reservation_lease_secs
        || policy.smtp_concurrency > policy.processing_concurrency
        || policy.operation_id_future_skew_secs > policy.operation_id_max_age_secs
        || policy.code_digits != 6
        || policy.product_email_send_limit_30m > policy.product_email_send_limit_24h
        || policy.product_email_send_limit_24h > policy.authority_email_send_limit_24h
        || policy.context_wrong_limit > policy.product_email_wrong_limit
        || policy.product_email_wrong_limit > policy.authority_email_wrong_limit
        || policy.product_email_send_gap_secs < policy.authority_email_send_gap_secs
    {
        return Err(RegistrationEmailError::InvalidInput("policy_bounds"));
    }

    let retention_secs = policy
        .operation_id_max_age_secs
        .checked_add(policy.operation_id_future_skew_secs)
        .and_then(|value| value.checked_add(policy.attempt_replay_grace_secs))
        .and_then(|value| value.checked_add(policy.maintenance_sweep_max_secs))
        .ok_or(RegistrationEmailError::InvalidInput("retention"))?;
    let start_rows = retained_rows(
        policy.authority_new_operation_start_ceiling,
        policy.authority_new_operation_window_secs,
        retention_secs,
        2,
    )
    .ok_or(RegistrationEmailError::InvalidInput("start_capacity"))?;
    let verify_rows = retained_rows(
        policy.authority_new_operation_limit,
        policy.authority_new_operation_window_secs,
        retention_secs,
        1,
    )
    .ok_or(RegistrationEmailError::InvalidInput("verify_capacity"))?;
    let start_capacity = policy
        .durable_context_receipts_cap
        .checked_sub(policy.durable_context_receipts_verify_reserve)
        .ok_or(RegistrationEmailError::InvalidInput("receipt_reserve"))?;
    if start_rows > u128::from(start_capacity)
        || verify_rows > u128::from(policy.durable_context_receipts_verify_reserve)
    {
        return Err(RegistrationEmailError::InvalidInput("receipt_capacity"));
    }
    Ok(())
}
