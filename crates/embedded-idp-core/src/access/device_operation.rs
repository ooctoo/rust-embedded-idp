use super::AccessError;
use sha2::{Digest, Sha256};
use std::time::SystemTime;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceOperationReceipt {
    pub operation_id: String,
    pub audit_id: String,
    pub device_id: String,
    pub binding_id: Option<String>,
    pub operation: &'static str,
    pub occurred_at: SystemTime,
    pub result_version: u64,
    pub result_status: String,
}

pub fn validate_device_operation_id(id: &str) -> Result<(), AccessError> {
    if uuid::Uuid::parse_str(id).map_or(true, |parsed| parsed.to_string() != id) {
        return Err(AccessError::InvalidInput("operation_id"));
    }
    Ok(())
}

/// V1 digest of one intent, independent of the transport request and clock.
pub fn device_command_digest(
    kind: &str,
    tenant: &str,
    device: &str,
    binding: Option<&str>,
    account: Option<&str>,
    expected_version: u64,
    reason: &str,
) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"embedded-idp-device-operation-v1");
    for field in [
        kind,
        tenant,
        device,
        binding.unwrap_or(""),
        account.unwrap_or(""),
        reason,
    ] {
        hash.update((field.len() as u32).to_be_bytes());
        hash.update(field.as_bytes());
    }
    hash.update(expected_version.to_be_bytes());
    hash.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operation_digest_is_stable_and_unambiguous() {
        let first = device_command_digest(
            "device.binding.unbind",
            "t",
            "ab",
            Some("c"),
            Some("u"),
            7,
            "lost",
        );
        assert_eq!(
            hex(&first),
            "3fa9ff32f086fde3ccf759d0d4cc97cdd76887a262a83a31811af5b749373d86"
        );
        assert_ne!(
            first,
            device_command_digest(
                "device.binding.unbind",
                "t",
                "a",
                Some("bc"),
                Some("u"),
                7,
                "lost"
            )
        );
        assert_ne!(
            first,
            device_command_digest(
                "device.binding.unbind",
                "t",
                "ab",
                Some("c"),
                Some("u"),
                8,
                "lost"
            )
        );
    }
    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}
