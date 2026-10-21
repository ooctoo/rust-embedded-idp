use super::{RegistrationEmailError, Uuid};

pub const REGISTRATION_OPERATION_MAX_AGE_SECS: i64 = 900;
pub const REGISTRATION_OPERATION_FUTURE_SKEW_SECS: i64 = 30;

/// Accept only UUIDv7 operation identifiers within the fixed revision-2 age
/// window. The timestamp is read from the UUID, never from client input.
pub fn check_registration_operation_freshness(
    operation: &Uuid,
    now: i64,
) -> Result<(), RegistrationEmailError> {
    if now < 0 || operation.get_version_num() != 7 {
        return Err(RegistrationEmailError::InvalidInput("operation_id"));
    }
    let timestamp = operation
        .get_timestamp()
        .ok_or(RegistrationEmailError::InvalidInput("operation_id"))?;
    let (seconds, nanos) = timestamp.to_unix();
    let operation_ms = i128::from(seconds)
        .checked_mul(1_000)
        .and_then(|value| value.checked_add(i128::from(nanos / 1_000_000)))
        .ok_or(RegistrationEmailError::InvalidInput("operation_id"))?;
    let now_ms = i128::from(now)
        .checked_mul(1_000)
        .ok_or(RegistrationEmailError::InvalidInput("now"))?;
    let age_ms = now_ms - operation_ms;
    if age_ms > i128::from(REGISTRATION_OPERATION_MAX_AGE_SECS) * 1_000
        || age_ms < -(i128::from(REGISTRATION_OPERATION_FUTURE_SKEW_SECS) * 1_000)
    {
        return Err(RegistrationEmailError::RequestExpired);
    }
    Ok(())
}
