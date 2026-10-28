//! Bounded in-memory abuse admission budgets for a single host process.
use std::{collections::HashMap, num::NonZeroU32, sync::Mutex, time::Duration};

use embedded_idp_core::{
    AbuseAdmission, AdmissionConfigError, AdmissionPolicy, AdmissionQuota, AdmissionRejection,
};
use governor::{
    clock::{Clock, MonotonicClock, Reference},
    middleware::NoOpMiddleware,
    state::{InMemoryState, NotKeyed},
    Quota, RateLimiter,
};
use ring::{
    hmac,
    rand::{SecureRandom, SystemRandom},
};

type DirectLimiter<C> =
    RateLimiter<NotKeyed, InMemoryState, C, NoOpMiddleware<<C as Clock>::Instant>>;

struct Bucket<C: Clock> {
    limiter: DirectLimiter<C>,
    last_allowed: C::Instant,
    retain_for: Duration,
}

struct AdmissionState<C: Clock> {
    global: DirectLimiter<C>,
    keyed: HashMap<[u8; 32], Bucket<C>>,
}

/// A bounded, process-local source and account admission adapter.
///
/// Keys are stored only as domain-separated HMAC digests. This adapter does
/// not share budgets across processes.
pub struct InMemoryAbuseAdmission<C: Clock = MonotonicClock> {
    policy: AdmissionPolicy,
    key: [u8; 32],
    clock: C,
    state: Mutex<AdmissionState<C>>,
}

impl InMemoryAbuseAdmission<MonotonicClock> {
    pub fn new(policy: AdmissionPolicy, key: [u8; 32]) -> Result<Self, AdmissionConfigError> {
        Self::with_clock(policy, key, MonotonicClock)
    }

    pub fn new_random(policy: AdmissionPolicy) -> Result<Self, AdmissionConfigError> {
        let mut key = [0_u8; 32];
        SystemRandom::new()
            .fill(&mut key)
            .map_err(|_| AdmissionConfigError("admission key generation failed"))?;
        Self::new(policy, key)
    }
}

impl<C: Clock + Clone> InMemoryAbuseAdmission<C> {
    fn with_clock(
        policy: AdmissionPolicy,
        key: [u8; 32],
        clock: C,
    ) -> Result<Self, AdmissionConfigError> {
        policy.validate()?;
        if key.iter().all(|byte| *byte == 0) {
            return Err(AdmissionConfigError("invalid admission key"));
        }
        let global = direct_limiter(&policy.global, clock.clone());
        Ok(Self {
            policy,
            key,
            clock,
            state: Mutex::new(AdmissionState {
                global,
                keyed: HashMap::new(),
            }),
        })
    }

    fn admit_key(
        &self,
        domain: &[u8],
        input: &[u8],
        quota: &AdmissionQuota,
    ) -> Result<(), AdmissionRejection> {
        let digest = digest_key(&self.key, domain, input);
        let mut state = self
            .state
            .lock()
            .map_err(|_| AdmissionRejection::Unavailable)?;
        self.admit_key_locked(&mut state, digest, quota)
    }

    fn admit_key_locked(
        &self,
        state: &mut AdmissionState<C>,
        digest: [u8; 32],
        quota: &AdmissionQuota,
    ) -> Result<(), AdmissionRejection> {
        let now = self.clock.now();
        if !state.keyed.contains_key(&digest) {
            self.clean_expired(&mut state.keyed, now);
            if state.keyed.len() >= self.policy.max_keys {
                return Err(AdmissionRejection::Unavailable);
            }
            state.keyed.insert(
                digest,
                Bucket {
                    limiter: direct_limiter(quota, self.clock.clone()),
                    last_allowed: now,
                    retain_for: retention(quota),
                },
            );
        }
        let bucket = state
            .keyed
            .get_mut(&digest)
            .expect("bucket inserted or found");
        if bucket.limiter.check().is_err() {
            return Err(AdmissionRejection::RateLimited);
        }
        bucket.last_allowed = now;
        bucket.retain_for = retention(quota);
        Ok(())
    }

    fn clean_expired(&self, keyed: &mut HashMap<[u8; 32], Bucket<C>>, now: C::Instant) {
        keyed
            .retain(|_, bucket| now.duration_since(bucket.last_allowed) < bucket.retain_for.into());
    }
}

impl<C: Clock + Clone + Send + Sync> AbuseAdmission for InMemoryAbuseAdmission<C> {
    fn admit_source(&self, source: &[u8]) -> Result<(), AdmissionRejection> {
        if !(1..=256).contains(&source.len()) {
            return Err(AdmissionRejection::Unavailable);
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| AdmissionRejection::Unavailable)?;
        if state.global.check().is_err() {
            return Err(AdmissionRejection::RateLimited);
        }
        let digest = digest_key(&self.key, b"source\0", source);
        self.admit_key_locked(&mut state, digest, &self.policy.source)
    }

    fn admit_account(&self, account: &str) -> Result<(), AdmissionRejection> {
        if account.is_empty() || account.len() > 16_384 {
            return Err(AdmissionRejection::Unavailable);
        }
        let normalized = account.trim_matches(' ').to_ascii_lowercase();
        if normalized.is_empty() {
            return Err(AdmissionRejection::Unavailable);
        }
        self.admit_key(b"account\0", normalized.as_bytes(), &self.policy.account)
    }
}

fn direct_limiter<C: Clock>(quota: &AdmissionQuota, clock: C) -> DirectLimiter<C> {
    let burst = NonZeroU32::new(quota.burst).expect("validated non-zero burst");
    RateLimiter::direct_with_clock(
        Quota::with_period(quota.replenish_every)
            .expect("validated non-zero quota period")
            .allow_burst(burst),
        clock,
    )
}

fn retention(quota: &AdmissionQuota) -> Duration {
    quota
        .replenish_every
        .checked_mul(quota.burst)
        .expect("validated retention duration")
}

fn digest_key(key: &[u8; 32], domain: &[u8], input: &[u8]) -> [u8; 32] {
    let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, key);
    let mut message = Vec::with_capacity(domain.len() + input.len());
    message.extend_from_slice(domain);
    message.extend_from_slice(input);
    hmac::sign(&hmac_key, &message)
        .as_ref()
        .try_into()
        .expect("HMAC-SHA256 has 32 bytes")
}

#[cfg(test)]
mod tests {
    use super::*;
    use governor::clock::FakeRelativeClock;

    fn policy(source: u32, account: u32, max_keys: usize) -> AdmissionPolicy {
        let q = |burst| AdmissionQuota {
            replenish_every: Duration::from_secs(1),
            burst,
        };
        AdmissionPolicy {
            global: q(100),
            source: q(source),
            account: q(account),
            max_keys,
        }
    }

    fn fixture(
        policy: AdmissionPolicy,
        clock: FakeRelativeClock,
    ) -> InMemoryAbuseAdmission<FakeRelativeClock> {
        InMemoryAbuseAdmission::with_clock(policy, [7; 32], clock).unwrap()
    }

    #[test]
    fn source_and_account_budgets_are_independent_and_account_is_normalized() {
        let clock = FakeRelativeClock::default();
        let admission = fixture(policy(2, 1, 8), clock.clone());
        assert!(admission.admit_source(b"ip").is_ok());
        assert!(admission.admit_source(b"ip").is_ok());
        assert_eq!(
            admission.admit_source(b"ip"),
            Err(AdmissionRejection::RateLimited)
        );
        assert!(admission.admit_account(" Alice@example.test ").is_ok());
        assert_eq!(
            admission.admit_account("alice@EXAMPLE.TEST"),
            Err(AdmissionRejection::RateLimited)
        );
        clock.advance(Duration::from_secs(1));
        assert!(admission.admit_source(b"ip").is_ok());
    }

    #[test]
    fn capacity_is_shared_and_only_fully_replenished_buckets_are_removed() {
        let clock = FakeRelativeClock::default();
        let admission = fixture(policy(1, 1, 1), clock.clone());
        admission.admit_source(b"one").unwrap();
        assert_eq!(
            admission.admit_account("two"),
            Err(AdmissionRejection::Unavailable)
        );
        clock.advance(Duration::from_millis(999));
        assert_eq!(
            admission.admit_account("two"),
            Err(AdmissionRejection::Unavailable)
        );
        clock.advance(Duration::from_millis(1));
        assert!(admission.admit_account("two").is_ok());
    }

    #[test]
    fn denial_does_not_extend_bucket_retention_or_refund_global_budget() {
        let clock = FakeRelativeClock::default();
        let mut p = policy(1, 1, 1);
        p.global.burst = 2;
        let admission = fixture(p, clock.clone());
        admission.admit_source(b"one").unwrap();
        assert_eq!(
            admission.admit_source(b"one"),
            Err(AdmissionRejection::RateLimited)
        );
        assert_eq!(
            admission.admit_source(b"two"),
            Err(AdmissionRejection::RateLimited)
        );
        clock.advance(Duration::from_secs(1));
        assert!(admission.admit_source(b"two").is_ok());
    }

    #[test]
    fn concurrent_calls_cannot_exceed_the_source_burst() {
        let admission =
            std::sync::Arc::new(fixture(policy(10, 1, 32), FakeRelativeClock::default()));
        let workers: Vec<_> = (0..32)
            .map(|_| {
                let admission = admission.clone();
                std::thread::spawn(move || admission.admit_source(b"shared-source").is_ok())
            })
            .collect();
        let allowed = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .filter(|allowed| *allowed)
            .count();
        assert_eq!(allowed, 10);
    }

    #[test]
    fn invalid_configuration_and_inputs_fail_closed_without_debugging_values() {
        assert!(InMemoryAbuseAdmission::new(policy(1, 1, 1), [0; 32]).is_err());
        let admission = fixture(policy(1, 1, 4), FakeRelativeClock::default());
        assert_eq!(
            admission.admit_source(b""),
            Err(AdmissionRejection::Unavailable)
        );
        assert_eq!(
            admission.admit_account("  "),
            Err(AdmissionRejection::Unavailable)
        );
        let debug = format!("{:?}", AdmissionRejection::Unavailable);
        assert!(!debug.contains("alice"));
    }
    #[test]
    fn poisoned_adapter_fails_closed_for_both_stages() {
        let adapter = InMemoryAbuseAdmission::new(AdmissionPolicy::default(), [7; 32]).unwrap();
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = adapter.state.lock().unwrap();
            panic!("synthetic adapter failure");
        }));
        assert_eq!(
            adapter.admit_source(b"source"),
            Err(AdmissionRejection::Unavailable)
        );
        assert_eq!(
            adapter.admit_account("person@example.test"),
            Err(AdmissionRejection::Unavailable)
        );
    }
}
