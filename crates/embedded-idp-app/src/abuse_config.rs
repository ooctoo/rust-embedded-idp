use embedded_idp_core::{AdmissionPolicy, AdmissionQuota};
use serde::Deserialize;
use std::time::Duration;

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct AbuseConfig {
    global: Option<QuotaConfig>,
    source: Option<QuotaConfig>,
    account: Option<QuotaConfig>,
    max_keys: Option<usize>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct QuotaConfig {
    period_ms: u64,
    burst: u32,
}
impl AbuseConfig {
    pub(crate) fn policy(self) -> Result<AdmissionPolicy, String> {
        let mut policy = AdmissionPolicy::default();
        for (value, target) in [
            (self.global, &mut policy.global),
            (self.source, &mut policy.source),
            (self.account, &mut policy.account),
        ] {
            if let Some(value) = value {
                *target = AdmissionQuota {
                    replenish_every: Duration::from_millis(value.period_ms),
                    burst: value.burst,
                };
            }
        }
        if let Some(max) = self.max_keys {
            policy.max_keys = max;
        }
        policy.validate().map_err(|e| e.to_string())?;
        Ok(policy)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn defaults_and_explicit_quotas_are_validated_without_disabling_admission() {
        assert_eq!(
            serde_json::from_str::<AbuseConfig>("{}")
                .unwrap()
                .policy()
                .unwrap(),
            AdmissionPolicy::default()
        );
        assert!(
            serde_json::from_str::<AbuseConfig>(r#"{"account":{"period_ms":0,"burst":3}}"#)
                .unwrap()
                .policy()
                .is_err()
        );
        assert!(serde_json::from_str::<AbuseConfig>(r#"{"enabled":false}"#).is_err());
        assert!(serde_json::from_str::<AbuseConfig>(
            r#"{"source":{"period_ms":1000,"burst":10,"trust_proxy":true}}"#
        )
        .is_err());
        let p = serde_json::from_str::<AbuseConfig>(
            r#"{"source":{"period_ms":1000,"burst":10},"max_keys":32}"#,
        )
        .unwrap()
        .policy()
        .unwrap();
        assert_eq!(p.source.burst, 10);
        assert_eq!(p.max_keys, 32);
    }
}
