/// Return a bounded copy using the policy's half-open rolling-window rule.
pub fn rolling_history(history: &[i64], now: i64, window_secs: i64) -> Vec<i64> {
    if window_secs <= 0 {
        return Vec::new();
    }
    let cutoff = now.saturating_sub(window_secs);
    history
        .iter()
        .copied()
        .filter(|timestamp| *timestamp > cutoff && *timestamp <= now)
        .collect()
}

pub fn trim_rolling_history(history: &mut Vec<i64>, now: i64, window_secs: i64) {
    *history = rolling_history(history, now, window_secs);
}

/// A request is admitted while the bounded history contains fewer than limit
/// events. A timestamp exactly at `now - window_secs` is outside the window.
pub fn rolling_allowed(history: &[i64], now: i64, window_secs: i64, limit: usize) -> bool {
    limit > 0 && rolling_history(history, now, window_secs).len() < limit
}

/// Anchor a failure block at the event that reached the limit. Later rejected
/// requests must keep this same anchor instead of extending it.
pub fn failure_block_until(failed_at: i64, window_secs: i64) -> Option<i64> {
    (window_secs > 0).then(|| failed_at.checked_add(window_secs))?
}

pub fn fixed_block_until(failed_at: i64, window_secs: i64) -> Option<i64> {
    failure_block_until(failed_at, window_secs)
}

pub(super) fn retained_rows(
    rate: u32,
    window_secs: i64,
    retention_secs: i64,
    rows_per_operation: u32,
) -> Option<u128> {
    let numerator = u128::from(rate)
        .checked_mul(u128::try_from(retention_secs).ok()?)
        .and_then(|value| value.checked_mul(u128::from(rows_per_operation)))?;
    let denominator = u128::try_from(window_secs).ok()?;
    Some((numerator + denominator - 1) / denominator)
}
