/// The registration-email policy revision owned by the IDP core.

pub const REGISTRATION_EMAIL_POLICY_REVISION: u16 = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistrationEmailPolicy {
    pub revision: u16,
    pub authority_email_send_gap_secs: i64,
    pub product_email_send_gap_secs: i64,
    pub product_email_send_limit_30m: u32,
    pub product_email_send_window_30m_secs: i64,
    pub product_email_send_limit_24h: u32,
    pub product_email_send_window_24h_secs: i64,
    pub authority_email_send_limit_24h: u32,
    pub authority_email_send_window_24h_secs: i64,
    pub context_lifetime_secs: i64,
    pub context_wrong_limit: u32,
    pub product_email_wrong_limit: u32,
    pub product_email_wrong_window_secs: i64,
    pub authority_email_wrong_limit: u32,
    pub authority_email_wrong_window_secs: i64,
    pub context_count_per_product_email: u32,
    pub context_slots_per_authority_email: u32,
    pub code_digits: u8,
    pub code_distinct_draw_limit: u8,
    pub authority_new_operation_limit: u32,
    pub authority_new_operation_window_secs: i64,
    pub authority_new_operation_start_ceiling: u32,
    pub durable_context_receipts_cap: u64,
    pub durable_context_receipts_verify_reserve: u64,
    pub authority_subject_bucket_cap: u64,
    pub product_subject_bucket_cap: u64,
    pub capacity_reservation_lease_secs: i64,
    pub db_transaction_deadline_secs: i64,
    pub processing_concurrency: u32,
    pub smtp_concurrency: u32,
    pub processing_queue_max_age_secs: i64,
    pub processing_lease_secs: i64,
    pub smtp_lease_secs: i64,
    pub maintenance_sweep_max_secs: i64,
    pub operation_id_max_age_secs: i64,
    pub operation_id_future_skew_secs: i64,
    pub attempt_replay_grace_secs: i64,
    pub bucket_retention_extra_secs: i64,
    pub anonymous_security_event_retention_days: u32,
}

impl Default for RegistrationEmailPolicy {
    fn default() -> Self {
        Self {
            revision: REGISTRATION_EMAIL_POLICY_REVISION,
            authority_email_send_gap_secs: 30,
            product_email_send_gap_secs: 60,
            product_email_send_limit_30m: 5,
            product_email_send_window_30m_secs: 1_800,
            product_email_send_limit_24h: 10,
            product_email_send_window_24h_secs: 86_400,
            authority_email_send_limit_24h: 20,
            authority_email_send_window_24h_secs: 86_400,
            context_lifetime_secs: 900,
            context_wrong_limit: 5,
            product_email_wrong_limit: 20,
            product_email_wrong_window_secs: 900,
            authority_email_wrong_limit: 30,
            authority_email_wrong_window_secs: 900,
            context_count_per_product_email: 3,
            context_slots_per_authority_email: 10,
            code_digits: 6,
            code_distinct_draw_limit: 8,
            authority_new_operation_limit: 300,
            authority_new_operation_window_secs: 60,
            authority_new_operation_start_ceiling: 200,
            durable_context_receipts_cap: 40_000,
            durable_context_receipts_verify_reserve: 8_000,
            authority_subject_bucket_cap: 20_000,
            product_subject_bucket_cap: 40_000,
            capacity_reservation_lease_secs: 30,
            db_transaction_deadline_secs: 10,
            processing_concurrency: 4,
            smtp_concurrency: 2,
            processing_queue_max_age_secs: 30,
            processing_lease_secs: 15,
            smtp_lease_secs: 15,
            maintenance_sweep_max_secs: 600,
            operation_id_max_age_secs: 900,
            operation_id_future_skew_secs: 30,
            attempt_replay_grace_secs: 30,
            bucket_retention_extra_secs: 900,
            anonymous_security_event_retention_days: 7,
        }
    }
}

impl RegistrationEmailPolicy {
    pub const REVISION: u16 = REGISTRATION_EMAIL_POLICY_REVISION;

    pub fn validate(&self) -> Result<(), super::RegistrationEmailError> {
        if self.revision != Self::REVISION {
            return Err(super::RegistrationEmailError::InvalidInput("revision"));
        }
        for (value, field) in [
            (self.authority_email_send_gap_secs, "authority_send_gap"),
            (self.product_email_send_gap_secs, "product_send_gap"),
            (
                self.product_email_send_window_30m_secs,
                "product_send_window_30m",
            ),
            (
                self.product_email_send_window_24h_secs,
                "product_send_window_24h",
            ),
            (
                self.authority_email_send_window_24h_secs,
                "authority_send_window",
            ),
            (self.context_lifetime_secs, "context_lifetime"),
            (self.product_email_wrong_window_secs, "product_wrong_window"),
            (
                self.authority_email_wrong_window_secs,
                "authority_wrong_window",
            ),
            (self.authority_new_operation_window_secs, "operation_window"),
            (self.capacity_reservation_lease_secs, "reservation_lease"),
            (self.db_transaction_deadline_secs, "transaction_deadline"),
            (self.processing_queue_max_age_secs, "queue_max_age"),
            (self.processing_lease_secs, "processing_lease"),
            (self.smtp_lease_secs, "smtp_lease"),
            (self.maintenance_sweep_max_secs, "maintenance_sweep"),
            (self.operation_id_max_age_secs, "operation_max_age"),
            (self.operation_id_future_skew_secs, "operation_future_skew"),
            (self.attempt_replay_grace_secs, "attempt_replay_grace"),
            (self.bucket_retention_extra_secs, "bucket_retention"),
        ] {
            if value <= 0 {
                return Err(super::RegistrationEmailError::InvalidInput(field));
            }
        }
        for (value, field) in [
            (
                self.product_email_send_limit_30m as u64,
                "product_send_limit_30m",
            ),
            (
                self.product_email_send_limit_24h as u64,
                "product_send_limit_24h",
            ),
            (
                self.authority_email_send_limit_24h as u64,
                "authority_send_limit",
            ),
            (self.context_wrong_limit as u64, "context_wrong_limit"),
            (self.product_email_wrong_limit as u64, "product_wrong_limit"),
            (
                self.authority_email_wrong_limit as u64,
                "authority_wrong_limit",
            ),
            (self.context_count_per_product_email as u64, "context_count"),
            (
                self.context_slots_per_authority_email as u64,
                "context_slots",
            ),
            (self.code_distinct_draw_limit as u64, "code_draw_limit"),
            (self.authority_new_operation_limit as u64, "operation_limit"),
            (
                self.authority_new_operation_start_ceiling as u64,
                "operation_start_ceiling",
            ),
            (self.durable_context_receipts_cap, "receipt_cap"),
            (
                self.durable_context_receipts_verify_reserve,
                "verify_reserve",
            ),
            (self.authority_subject_bucket_cap, "authority_bucket_cap"),
            (self.product_subject_bucket_cap, "product_bucket_cap"),
            (self.processing_concurrency as u64, "processing_concurrency"),
            (self.smtp_concurrency as u64, "smtp_concurrency"),
            (
                self.anonymous_security_event_retention_days as u64,
                "event_retention",
            ),
        ] {
            if value == 0 {
                return Err(super::RegistrationEmailError::InvalidInput(field));
            }
        }

        super::validation::validate_bounds(self)
    }
}
