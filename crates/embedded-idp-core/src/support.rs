use std::time::SystemTime;

use rand_core::{OsRng, RngCore};
use uuid::Uuid;

pub trait Clock {
    fn now(&self) -> SystemTime;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }
}

pub trait IdGenerator {
    fn next_id(&self, prefix: &str) -> String;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct UuidV7IdGenerator;

impl IdGenerator for UuidV7IdGenerator {
    fn next_id(&self, _prefix: &str) -> String {
        Uuid::now_v7().to_string()
    }
}

pub trait VerificationCodeGenerator {
    fn generate_code(&self) -> String;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct NumericVerificationCodeGenerator;

impl VerificationCodeGenerator for NumericVerificationCodeGenerator {
    fn generate_code(&self) -> String {
        let mut bytes = [0_u8; 4];
        OsRng.fill_bytes(&mut bytes);
        let value = u32::from_le_bytes(bytes) % 1_000_000;
        format!("{value:06}")
    }
}

#[cfg(test)]
mod tests {
    use super::{
        IdGenerator, NumericVerificationCodeGenerator, UuidV7IdGenerator, VerificationCodeGenerator,
    };

    #[test]
    fn uuid_v7_generator_emits_parseable_v7_ids() {
        let generator = UuidV7IdGenerator;
        let id = generator.next_id("acct");
        let parsed = uuid::Uuid::parse_str(&id).expect("generated id should parse as uuid");

        assert_eq!(parsed.get_version_num(), 7);
    }

    #[test]
    fn numeric_verification_code_generator_emits_six_digits() {
        let generator = NumericVerificationCodeGenerator;
        let code = generator.generate_code();

        assert_eq!(code.len(), 6);
        assert!(code.chars().all(|ch| ch.is_ascii_digit()));
    }
}
