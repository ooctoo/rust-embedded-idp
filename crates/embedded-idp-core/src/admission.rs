//! Host-injected admission budgets. These decisions never establish identity.
use std::{fmt, time::Duration};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdmissionQuota {
    pub replenish_every: Duration,
    pub burst: u32,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdmissionPolicy {
    pub global: AdmissionQuota,
    pub source: AdmissionQuota,
    pub account: AdmissionQuota,
    pub max_keys: usize,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AdmissionConfigError(pub &'static str);
impl fmt::Display for AdmissionConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for AdmissionConfigError {}
impl AdmissionPolicy {
    pub fn validate(&self) -> Result<(), AdmissionConfigError> {
        if !(1..=65536).contains(&self.max_keys) {
            return Err(AdmissionConfigError("invalid admission key capacity"));
        }
        for q in [&self.global, &self.source, &self.account] {
            if !(1..=1000).contains(&q.burst)
                || q.replenish_every < Duration::from_millis(1)
                || q.replenish_every > Duration::from_secs(3600)
                || q.replenish_every
                    .checked_mul(q.burst)
                    .is_none_or(|d| d > Duration::from_secs(86400))
            {
                return Err(AdmissionConfigError("invalid admission quota"));
            }
        }
        Ok(())
    }
}
impl Default for AdmissionPolicy {
    fn default() -> Self {
        Self {
            global: AdmissionQuota {
                replenish_every: Duration::from_millis(10),
                burst: 200,
            },
            source: AdmissionQuota {
                replenish_every: Duration::from_millis(200),
                burst: 60,
            },
            account: AdmissionQuota {
                replenish_every: Duration::from_secs(2),
                burst: 10,
            },
            max_keys: 16384,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdmissionRejection {
    RateLimited,
    Unavailable,
}
/// Trusted host port: source admission precedes body parsing/account admission.
/// Each method is atomic; the two HTTP stages are not one atomic transaction.
/// Earlier charges are not refunded on a later rejection or cancelled request.
pub trait AbuseAdmission: Send + Sync {
    fn admit_source(&self, source: &[u8]) -> Result<(), AdmissionRejection>;
    fn admit_account(&self, account: &str) -> Result<(), AdmissionRejection>;
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn policy_rejects_unbounded_or_zero_budgets() {
        let base = AdmissionPolicy::default();
        assert!(base.validate().is_ok());
        for max_keys in [0, 65537] {
            assert!(AdmissionPolicy {
                max_keys,
                ..base.clone()
            }
            .validate()
            .is_err());
        }
        for (period, burst) in [
            (Duration::ZERO, 1),
            (Duration::from_secs(1), 0),
            (Duration::from_secs(3600), 1000),
        ] {
            let mut p = base.clone();
            p.account = AdmissionQuota {
                replenish_every: period,
                burst,
            };
            assert!(p.validate().is_err());
        }
    }
}
