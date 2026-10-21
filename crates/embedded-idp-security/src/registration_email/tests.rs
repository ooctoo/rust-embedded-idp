use embedded_idp_core::access::{
    CanonicalRegistrationEmail, RegistrationEmailCrypto, RegistrationEmailError,
    RegistrationEmailOperationKind, RegistrationEmailScope, TenancyMode, Uuid,
};

use super::RingRegistrationEmailCrypto;

fn crypto() -> RingRegistrationEmailCrypto {
    RingRegistrationEmailCrypto::new([1; 32], [2; 32], [3; 32], [4; 32], [5; 32]).unwrap()
}

fn scope(product: &str) -> RegistrationEmailScope {
    RegistrationEmailScope::new("authority", product, "0", TenancyMode::Disabled).unwrap()
}

fn email(value: &str) -> CanonicalRegistrationEmail {
    CanonicalRegistrationEmail::parse(value).unwrap()
}

#[test]
fn constructor_rejects_zero_and_reused_key_material() {
    assert!(matches!(
        RingRegistrationEmailCrypto::new([0; 32], [2; 32], [3; 32], [4; 32], [5; 32]),
        Err(RegistrationEmailError::InvalidInput("key_material"))
    ));
    assert!(matches!(
        RingRegistrationEmailCrypto::new([1; 32], [1; 32], [3; 32], [4; 32], [5; 32]),
        Err(RegistrationEmailError::InvalidInput("key_material"))
    ));
}

#[test]
fn subject_uses_abuse_identity_and_aggregates_across_products() {
    let crypto = crypto();
    let first = crypto.subject(&scope("sut"), &email("User@Example.COM"));
    let second = crypto.subject(&scope("other"), &email("user@example.com"));
    assert_eq!(first, second);

    let other_authority =
        RegistrationEmailScope::new("other-authority", "sut", "0", TenancyMode::Disabled).unwrap();
    assert_ne!(
        first,
        crypto.subject(&other_authority, &email("user@example.com"))
    );
}

#[test]
fn context_request_and_code_domains_are_isolated() {
    let crypto = crypto();
    let first_scope = scope("sut");
    let second_scope = scope("other");
    let seed = [9; 32];
    let first_context = crypto.context_token(&first_scope, &seed);
    let second_context = crypto.context_token(&second_scope, &seed);
    assert_eq!(first_context.expose_secret().len(), 43);
    assert_ne!(first_context, second_context);

    let operation = Uuid::from_u128(7);
    let request = crypto.request_digest(
        &first_scope,
        RegistrationEmailOperationKind::Register,
        &operation,
        b"payload",
    );
    let resend = crypto.request_digest(
        &first_scope,
        RegistrationEmailOperationKind::Resend,
        &operation,
        b"payload",
    );
    assert_ne!(request, resend);

    let first_code = crypto.code_digest(&first_scope, &operation, "123456");
    let second_code = crypto.code_digest(&first_scope, &Uuid::from_u128(8), "123456");
    assert_ne!(first_code, second_code);
    assert!(crypto.digests_equal(&first_code, &first_code));
    assert!(!crypto.digests_equal(&first_code, &first_code[..31]));
}

#[test]
fn key_material_isolated_per_operation() {
    let original = crypto();
    let scope = scope("sut");
    let email = email("user@example.com");
    let context = Uuid::from_u128(21);
    let operation = Uuid::from_u128(22);
    let seed = [9; 32];

    let subject_key =
        RingRegistrationEmailCrypto::new([9; 32], [2; 32], [3; 32], [4; 32], [5; 32]).unwrap();
    assert_ne!(
        original.subject(&scope, &email),
        subject_key.subject(&scope, &email)
    );

    let context_key =
        RingRegistrationEmailCrypto::new([1; 32], [9; 32], [3; 32], [4; 32], [5; 32]).unwrap();
    assert_ne!(
        original.context_token(&scope, &seed),
        context_key.context_token(&scope, &seed)
    );

    let request_key =
        RingRegistrationEmailCrypto::new([1; 32], [2; 32], [9; 32], [4; 32], [5; 32]).unwrap();
    assert_ne!(
        original.request_digest(
            &scope,
            RegistrationEmailOperationKind::Register,
            &operation,
            b"payload"
        ),
        request_key.request_digest(
            &scope,
            RegistrationEmailOperationKind::Register,
            &operation,
            b"payload"
        )
    );

    let code_key =
        RingRegistrationEmailCrypto::new([1; 32], [2; 32], [3; 32], [9; 32], [5; 32]).unwrap();
    assert_ne!(
        original.code_digest(&scope, &context, "123456"),
        code_key.code_digest(&scope, &context, "123456")
    );

    let envelope_key =
        RingRegistrationEmailCrypto::new([1; 32], [2; 32], [3; 32], [4; 32], [9; 32]).unwrap();
    let ciphertext = original.seal("test", &scope, &context, b"secret").unwrap();
    assert_eq!(
        envelope_key.open("test", &scope, &context, &ciphertext),
        Err(RegistrationEmailError::Unavailable)
    );
}

#[test]
fn envelope_binds_scope_purpose_context_and_authentication() {
    let crypto = crypto();
    let current_scope = scope("sut");
    let other_scope = scope("other");
    let context = Uuid::from_u128(11);
    let ciphertext = crypto
        .seal("candidate-password", &current_scope, &context, b"plaintext")
        .unwrap();
    assert!(ciphertext.len() > 12 + 16);
    assert_eq!(
        crypto
            .open("candidate-password", &current_scope, &context, &ciphertext,)
            .unwrap(),
        b"plaintext"
    );

    for (purpose, scope, context) in [
        ("other-purpose", &current_scope, context),
        ("candidate-password", &other_scope, context),
        ("candidate-password", &current_scope, Uuid::from_u128(12)),
    ] {
        assert_eq!(
            crypto.open(purpose, scope, &context, &ciphertext),
            Err(RegistrationEmailError::Unavailable)
        );
    }

    let mut tampered = ciphertext.clone();
    *tampered.last_mut().unwrap() ^= 1;
    assert_eq!(
        crypto.open("candidate-password", &current_scope, &context, &tampered),
        Err(RegistrationEmailError::Unavailable)
    );
    for length in [0, 12, 12 + 15] {
        assert_eq!(
            crypto.open(
                "candidate-password",
                &current_scope,
                &context,
                &ciphertext[..length]
            ),
            Err(RegistrationEmailError::Unavailable)
        );
    }
}

#[test]
fn random_values_are_canonical_and_secret_debug_is_redacted() {
    let crypto = crypto();
    let seed = crypto.random_seed().unwrap();
    assert_ne!(seed, [0; 32]);
    let code = crypto.random_code().unwrap();
    assert_eq!(code.expose_secret().len(), 6);
    assert!(code
        .expose_secret()
        .bytes()
        .all(|byte| byte.is_ascii_digit()));
    assert_eq!(format!("{code:?}"), "<redacted>");

    let debug = format!("{:?}", crypto);
    assert!(debug.contains("[REDACTED]"));
    assert!(!debug.contains("010101010101"));
    assert!(!debug.contains("020202020202"));
    assert!(!debug.contains("030303030303"));
    assert!(!debug.contains("040404040404"));
    assert!(!debug.contains("050505050505"));
}

#[test]
fn prepared_candidate_is_core_hashed_bound_and_redacted() {
    use embedded_idp_core::{
        access::{decode_registration_candidate, PreparedRegistrationEmail},
        SecretString,
    };
    let crypto = crypto();
    let scope = scope("sut");
    let op = Uuid::now_v7();
    let prepared = PreparedRegistrationEmail::prepare(
        &scope,
        &crypto,
        op,
        " Alice@EXAMPLE.COM ",
        &SecretString::new("CandidatePass123"),
        Some("Alice"),
    )
    .unwrap();
    let repeated = PreparedRegistrationEmail::prepare(
        &scope,
        &crypto,
        op,
        "Alice@example.com",
        &SecretString::new("CandidatePass123"),
        Some("Alice"),
    )
    .unwrap();
    assert_eq!(prepared.request(), repeated.request());
    assert_ne!(prepared.context(), repeated.context());
    let candidate = crypto
        .open(
            "candidate",
            &scope,
            &prepared.context(),
            prepared.password_cipher(),
        )
        .unwrap();
    let (hash, name) = decode_registration_candidate(&candidate).unwrap();
    assert!(hash.expose_secret().starts_with("$argon2id$"));
    assert_eq!(name.as_deref(), Some("Alice"));
    assert!(!String::from_utf8_lossy(&candidate).contains("CandidatePass123"));
    assert_eq!(
        format!("{prepared:?}"),
        "PreparedRegistrationEmail(<redacted>)"
    );
    assert!(crypto
        .open(
            "email",
            &scope,
            &prepared.context(),
            prepared.password_cipher()
        )
        .is_err());
}
#[test]
fn malformed_candidates_and_untrusted_names_are_rejected() {
    use embedded_idp_core::{
        access::{decode_registration_candidate, PreparedRegistrationEmail},
        SecretString,
    };
    for data in [vec![], vec![0, 0, 0, 5], vec![255; 16]] {
        assert!(decode_registration_candidate(&data).is_err());
    }
    let mut malformed = Vec::new();
    for field in ["plain-hash", "Alice"] {
        malformed.extend_from_slice(&(field.len() as u32).to_be_bytes());
        malformed.extend_from_slice(field.as_bytes());
    }
    assert!(decode_registration_candidate(&malformed).is_err());
    for name in ["".to_owned(), "x".repeat(129), "a\nb".to_owned()] {
        assert!(PreparedRegistrationEmail::prepare(
            &scope("sut"),
            &crypto(),
            Uuid::now_v7(),
            "a@example.test",
            &SecretString::new("CandidatePass123"),
            Some(&name)
        )
        .is_err());
    }
}
