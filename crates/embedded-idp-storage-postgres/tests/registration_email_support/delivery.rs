use super::fixture::Fixture;
use embedded_idp_core::access::RegistrationEmailCrypto;
use embedded_idp_core::SecretString;
use embedded_idp_storage_postgres::RegistrationEmailDeliveryClaim;
use uuid::Uuid;

pub struct DeliveryPayload {
    pub effect_id: Uuid,
    pub code: SecretString,
    pub expires_at: i64,
}

pub fn delivery(fixture: &Fixture, context: Uuid, sequence: i64) -> DeliveryPayload {
    let row = fixture
        .adapter
        .connect()
        .expect("fixture connection")
        .query_one(
            &format!(
                "select id,payload_cipher from {}.registration_email_deliveries where context_id=$1 and seq=$2",
                fixture.schema
            ),
            &[&context, &sequence],
        )
        .expect("delivery row");
    let effect_id: Uuid = row.get("id");
    let ciphertext: Vec<u8> = row.get("payload_cipher");
    let plaintext = fixture
        .crypto
        .open("delivery", &fixture.scope, &context, &ciphertext)
        .expect("delivery payload");
    let mut rest = plaintext.as_slice();
    let _email = take_string(&mut rest);
    let code = take_string(&mut rest);
    let expires_at = take_string(&mut rest)
        .parse::<i64>()
        .expect("delivery expiry");
    assert!(rest.is_empty());
    DeliveryPayload {
        effect_id,
        code: SecretString::new(code),
        expires_at,
    }
}

pub fn claim(fixture: &Fixture, effect_id: Uuid) -> RegistrationEmailDeliveryClaim {
    fixture
        .store()
        .claim_delivery(effect_id)
        .expect("delivery claim")
        .expect("delivery should be claimable")
}

fn take_string(rest: &mut &[u8]) -> String {
    assert!(rest.len() >= 4);
    let length = u32::from_be_bytes(rest[..4].try_into().expect("length")) as usize;
    assert!(length <= 1024 && rest.len() >= 4 + length);
    let value = String::from_utf8(rest[4..4 + length].to_vec()).expect("UTF-8 payload");
    *rest = &rest[4 + length..];
    value
}
