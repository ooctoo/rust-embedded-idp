use crate::PasswordWorkBudget;
use argon2::{
    password_hash::{
        Error as PasswordHashError, PasswordHash, PasswordHasher, PasswordVerifier, SaltString,
    },
    Argon2,
};
use rand_core::OsRng;

const WORK_UNAVAILABLE: &str = "password.work_unavailable";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientSecretError {
    VerifierRejected(String),
    HasherRejected(String),
}

impl ClientSecretError {
    /// Returns true only for the fixed shared-password-budget saturation marker.
    pub fn is_work_unavailable(&self) -> bool {
        matches!(
            self,
            Self::VerifierRejected(message) | Self::HasherRejected(message)
                if message == WORK_UNAVAILABLE
        )
    }
}

pub trait ClientSecretVerifier {
    fn verify_client_secret(
        &self,
        provided_secret: &str,
        stored_secret_hash: &str,
    ) -> Result<bool, ClientSecretError>;
}

pub trait ClientSecretHasher {
    fn hash_client_secret(&self, raw_secret: &str) -> Result<String, ClientSecretError>;
}

/// Applies the host's shared password-work budget to synchronous client-secret
/// hashing and verification without changing the underlying codec.
pub struct BudgetedClientSecretCodec<V> {
    inner: V,
    budget: PasswordWorkBudget,
}

impl<V> BudgetedClientSecretCodec<V> {
    pub fn new(inner: V, budget: PasswordWorkBudget) -> Self {
        Self { inner, budget }
    }
}

impl<V: ClientSecretVerifier> ClientSecretVerifier for BudgetedClientSecretCodec<V> {
    fn verify_client_secret(
        &self,
        provided_secret: &str,
        stored_secret_hash: &str,
    ) -> Result<bool, ClientSecretError> {
        let permit = self
            .budget
            .try_login()
            .map_err(|_| ClientSecretError::VerifierRejected(WORK_UNAVAILABLE.into()))?;
        let result = self
            .inner
            .verify_client_secret(provided_secret, stored_secret_hash);
        drop(permit);
        result
    }
}

impl<V: ClientSecretHasher> ClientSecretHasher for BudgetedClientSecretCodec<V> {
    fn hash_client_secret(&self, raw_secret: &str) -> Result<String, ClientSecretError> {
        let permit = self
            .budget
            .try_login()
            .map_err(|_| ClientSecretError::HasherRejected(WORK_UNAVAILABLE.into()))?;
        let result = self.inner.hash_client_secret(raw_secret);
        drop(permit);
        result
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct PhcClientSecretCodec;

impl ClientSecretHasher for PhcClientSecretCodec {
    fn hash_client_secret(&self, raw_secret: &str) -> Result<String, ClientSecretError> {
        let salt = SaltString::generate(&mut OsRng);
        Argon2::default()
            .hash_password(raw_secret.as_bytes(), &salt)
            .map(|hash| hash.to_string())
            .map_err(|error| ClientSecretError::HasherRejected(error.to_string()))
    }
}

impl ClientSecretVerifier for PhcClientSecretCodec {
    fn verify_client_secret(
        &self,
        provided_secret: &str,
        stored_secret_hash: &str,
    ) -> Result<bool, ClientSecretError> {
        let parsed_hash = PasswordHash::new(stored_secret_hash)
            .map_err(|error| ClientSecretError::VerifierRejected(error.to_string()))?;

        match Argon2::default().verify_password(provided_secret.as_bytes(), &parsed_hash) {
            Ok(()) => Ok(true),
            Err(PasswordHashError::Password) => Ok(false),
            Err(error) => Err(ClientSecretError::VerifierRejected(error.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        BudgetedClientSecretCodec, ClientSecretError, ClientSecretHasher, ClientSecretVerifier,
        PhcClientSecretCodec,
    };
    use crate::PasswordWorkBudget;
    use std::{
        sync::{Arc, Condvar, Mutex},
        thread,
        time::{Duration, Instant},
    };

    #[derive(Default)]
    struct Gate {
        entered: Mutex<usize>,
        entered_changed: Condvar,
        released: Mutex<bool>,
        released_changed: Condvar,
    }

    impl Gate {
        fn block(&self) -> bool {
            *self.entered.lock().unwrap() += 1;
            self.entered_changed.notify_all();
            let mut released = self.released.lock().unwrap();
            while !*released {
                let remaining = deadline_remaining();
                if remaining.is_zero() {
                    return false;
                }
                let (next, timeout) = self
                    .released_changed
                    .wait_timeout(released, remaining)
                    .unwrap();
                released = next;
                if timeout.timed_out() && !*released {
                    return false;
                }
            }
            true
        }
        fn wait_for(&self, count: usize) -> bool {
            let mut entered = self.entered.lock().unwrap();
            while *entered < count {
                let remaining = deadline_remaining();
                if remaining.is_zero() {
                    return false;
                }
                let (next, timeout) = self
                    .entered_changed
                    .wait_timeout(entered, remaining)
                    .unwrap();
                entered = next;
                if timeout.timed_out() && *entered < count {
                    return false;
                }
            }
            true
        }
        fn release(&self) {
            *self.released.lock().unwrap() = true;
            self.released_changed.notify_all();
        }
    }

    fn deadline_remaining() -> Duration {
        TEST_DEADLINE.with(|deadline| deadline.saturating_duration_since(Instant::now()))
    }

    thread_local! {
        static TEST_DEADLINE: Instant = Instant::now() + Duration::from_secs(5);
    }

    struct BlockingCodec(Arc<Gate>);
    impl ClientSecretHasher for BlockingCodec {
        fn hash_client_secret(&self, _: &str) -> Result<String, ClientSecretError> {
            if self.0.block() {
                Ok("hash".into())
            } else {
                Err(ClientSecretError::HasherRejected(
                    "test gate timed out".into(),
                ))
            }
        }
    }
    impl ClientSecretVerifier for BlockingCodec {
        fn verify_client_secret(&self, _: &str, _: &str) -> Result<bool, ClientSecretError> {
            if self.0.block() {
                Ok(true)
            } else {
                Err(ClientSecretError::VerifierRejected(
                    "test gate timed out".into(),
                ))
            }
        }
    }

    #[test]
    fn phc_client_secret_codec_round_trips() {
        let codec = PhcClientSecretCodec;
        let secret_hash = codec
            .hash_client_secret("top-secret")
            .expect("hash client secret");

        assert!(secret_hash.starts_with("$argon2id$"));
        assert_eq!(
            codec.verify_client_secret("top-secret", &secret_hash),
            Ok(true)
        );
    }

    #[test]
    fn phc_client_secret_codec_rejects_wrong_secret() {
        let codec = PhcClientSecretCodec;
        let secret_hash = codec
            .hash_client_secret("top-secret")
            .expect("hash client secret");

        assert_eq!(
            codec.verify_client_secret("wrong-secret", &secret_hash),
            Ok(false)
        );
    }

    #[test]
    fn budget_is_shared_by_hash_and_verify_and_held_until_work_returns() {
        let budget = PasswordWorkBudget::default();
        let gate = Arc::new(Gate::default());
        let codec = Arc::new(BudgetedClientSecretCodec::new(
            BlockingCodec(gate.clone()),
            budget.clone(),
        ));
        let workers: Vec<_> = (0..4)
            .map(|index| {
                let codec = codec.clone();
                thread::spawn(move || {
                    if index < 2 {
                        codec.hash_client_secret("secret").map(|_| ())
                    } else {
                        codec.verify_client_secret("secret", "hash").map(|_| ())
                    }
                })
            })
            .collect();
        let all_entered = gate.wait_for(4);
        if !all_entered {
            gate.release();
            for worker in workers {
                let _ = worker.join();
            }
            panic!("client-secret work did not enter the blocking codec in time");
        }
        let verify = codec.verify_client_secret("extra", "hash");
        let hash = codec.hash_client_secret("extra");
        assert!(matches!(
            verify,
            Err(ClientSecretError::VerifierRejected(message)) if message == "password.work_unavailable"
        ));
        assert!(matches!(
            hash,
            Err(ClientSecretError::HasherRejected(message)) if message == "password.work_unavailable"
        ));
        assert_eq!(*gate.entered.lock().unwrap(), 4);
        gate.release();
        for worker in workers {
            worker.join().unwrap().unwrap();
        }
        assert!(codec.hash_client_secret("after release").is_ok());
    }

    #[test]
    fn work_unavailable_helper_matches_only_the_fixed_marker() {
        assert!(
            ClientSecretError::VerifierRejected("password.work_unavailable".into())
                .is_work_unavailable()
        );
        assert!(
            ClientSecretError::HasherRejected("password.work_unavailable".into())
                .is_work_unavailable()
        );
        assert!(!ClientSecretError::VerifierRejected(
            "internal password.work_unavailable detail".into()
        )
        .is_work_unavailable());
        assert!(!ClientSecretError::HasherRejected("invalid secret".into()).is_work_unavailable());
    }
}
