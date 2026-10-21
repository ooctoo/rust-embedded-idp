#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistrationEmailCodeState {
    Ready,
    Unready,
    Suppressed,
    Expired,
    Consumed,
    Exhausted,
}

impl RegistrationEmailCodeState {
    pub fn is_ready(self) -> bool {
        self == Self::Ready
    }

    /// Only an actually usable current code can consume the shared email
    /// wrong-code budget. Suppressed and unavailable states are free of that
    /// budget, while their source/operation budgets remain independent.
    pub fn counts_email_error(self) -> bool {
        self == Self::Ready
    }
}

/// Classify the persisted state before comparing any supplied code.
pub fn classify_registration_email_code_state(
    context_exists: bool,
    current_code_exists: bool,
    suppressed: bool,
    now: i64,
    context_expires_at: i64,
    code_expires_at: Option<i64>,
    consumed: bool,
    wrong_count: u32,
    wrong_limit: u32,
) -> RegistrationEmailCodeState {
    if !context_exists || !current_code_exists || code_expires_at.is_none() {
        return RegistrationEmailCodeState::Unready;
    }
    if suppressed {
        return RegistrationEmailCodeState::Suppressed;
    }
    if now >= context_expires_at || now >= code_expires_at.expect("checked above") {
        return RegistrationEmailCodeState::Expired;
    }
    if consumed {
        return RegistrationEmailCodeState::Consumed;
    }
    if wrong_limit == 0 || wrong_count >= wrong_limit {
        return RegistrationEmailCodeState::Exhausted;
    }
    RegistrationEmailCodeState::Ready
}
