use super::*;
use base64ct::Encoding;
use ring::aead::{Aad, Nonce};

fn key_set(id: &str, start: u8) -> AccountSecurityKeySet {
    AccountSecurityKeySet::new(
        id.to_owned(),
        [start; 32],
        [start + 1; 32],
        [start + 2; 32],
        [start + 3; 32],
    )
}

fn crypto() -> RingAccountSecurityCrypto {
    RingAccountSecurityCrypto::new(
        "auth.example".into(),
        [200; 32],
        key_set("current", 10),
        None,
    )
    .unwrap()
}

fn context() -> SecurityCryptoContext {
    SecurityCryptoContext {
        reference_id: Uuid::from_u128(1),
        related_id: Some(Uuid::from_u128(2)),
    }
}

#[test]
fn validates_authority_key_ids_and_independent_nonzero_material() {
    for authority in ["", "contains space", "a/b", "ümlaut", &"a".repeat(129)] {
        assert!(RingAccountSecurityCrypto::new(
            authority.into(),
            [200; 32],
            key_set("current", 10),
            None
        )
        .is_err());
    }
    for key_id in ["", "bad/id", &"x".repeat(33)] {
        assert!(RingAccountSecurityCrypto::new(
            "auth.example".into(),
            [200; 32],
            key_set(key_id, 10),
            None
        )
        .is_err());
    }
    assert!(
        RingAccountSecurityCrypto::new("auth".into(), [0; 32], key_set("current", 10), None)
            .is_err()
    );
    assert!(
        RingAccountSecurityCrypto::new("auth".into(), [10; 32], key_set("current", 10), None)
            .is_err()
    );

    let duplicate =
        AccountSecurityKeySet::new("current".into(), [10; 32], [11; 32], [11; 32], [13; 32]);
    assert!(RingAccountSecurityCrypto::new("auth".into(), [200; 32], duplicate, None).is_err());
    assert!(RingAccountSecurityCrypto::new(
        "auth".into(),
        [200; 32],
        key_set("same", 10),
        Some(key_set("same", 20))
    )
    .is_err());
    assert!(RingAccountSecurityCrypto::new(
        "auth".into(),
        [200; 32],
        key_set("current", 10),
        Some(key_set("previous", 10))
    )
    .is_err());
    assert!(RingAccountSecurityCrypto::new(
        "auth".into(),
        [200; 32],
        AccountSecurityKeySet::new("current".into(), [0; 32], [1; 32], [2; 32], [3; 32]),
        None
    )
    .is_err());
}

#[test]
fn subject_digest_trims_ascii_spaces_and_lowercases_ascii_only() {
    let crypto = crypto();
    assert_eq!(
        crypto.subject_digest(" Alice@EXAMPLE.test ").unwrap(),
        crypto.subject_digest("alice@example.test").unwrap()
    );
    let padded_254 = format!("{}a@b{}", " ".repeat(125), " ".repeat(126));
    assert_eq!(padded_254.len(), 254);
    assert_eq!(
        crypto.subject_digest(&padded_254).unwrap(),
        crypto.subject_digest("a@b").unwrap()
    );
    assert!(crypto.subject_digest("").is_err());
    assert!(crypto.subject_digest("   ").is_err());
    assert!(crypto.subject_digest(&"a".repeat(255)).is_err());
    assert_ne!(
        crypto.subject_digest(" É@example.test ").unwrap(),
        crypto.subject_digest(" é@example.test ").unwrap()
    );
    assert_ne!(
        crypto.subject_digest("alice@example.test").unwrap(),
        RingAccountSecurityCrypto::new(
            "other.authority".into(),
            [200; 32],
            key_set("current", 10),
            None
        )
        .unwrap()
        .subject_digest("alice@example.test")
        .unwrap()
    );
}

#[test]
fn digest_purposes_context_authority_and_key_ids_are_bound() {
    let crypto = crypto();
    let ctx = context();
    let purposes = [
        SecurityDigestPurpose::RecoveryHandle,
        SecurityDigestPurpose::ReceiptSecret,
        SecurityDigestPurpose::Command,
        SecurityDigestPurpose::RecoveryCode,
    ];
    let digests: Vec<_> = purposes
        .iter()
        .map(|purpose| crypto.digest(*purpose, &ctx, b"payload").unwrap())
        .collect();
    assert!(digests.iter().all(|digest| digest.key_id == "current"));
    for i in 0..digests.len() {
        for j in 0..i {
            assert_ne!(digests[i].bytes, digests[j].bytes);
        }
    }
    assert!(crypto
        .verify_digest(purposes[0], &ctx, b"payload", &digests[0])
        .unwrap());
    assert!(!crypto
        .verify_digest(purposes[0], &ctx, b"different", &digests[0])
        .unwrap());
    assert!(!crypto
        .verify_digest(purposes[1], &ctx, b"payload", &digests[0])
        .unwrap());

    let mut other = ctx;
    other.reference_id = Uuid::from_u128(3);
    assert!(!crypto
        .verify_digest(purposes[0], &other, b"payload", &digests[0])
        .unwrap());
    other = ctx;
    other.related_id = Some(Uuid::from_u128(99));
    assert!(!crypto
        .verify_digest(purposes[0], &other, b"payload", &digests[0])
        .unwrap());
    other.related_id = None;
    assert!(!crypto
        .verify_digest(purposes[0], &other, b"payload", &digests[0])
        .unwrap());

    let other_authority = RingAccountSecurityCrypto::new(
        "other.authority".into(),
        [200; 32],
        key_set("current", 10),
        None,
    )
    .unwrap();
    assert!(!other_authority
        .verify_digest(purposes[0], &ctx, b"payload", &digests[0])
        .unwrap());
    let mut unknown = digests[0].clone();
    unknown.key_id = "removed".into();
    assert_eq!(
        crypto.verify_digest(purposes[0], &ctx, b"payload", &unknown),
        Err(SecurityCryptoError::UnknownKey)
    );
    let rotated = RingAccountSecurityCrypto::new(
        "auth.example".into(),
        [200; 32],
        key_set("current", 10),
        Some(key_set("previous", 30)),
    )
    .unwrap();
    let mut known_but_wrong_key = digests[0].clone();
    known_but_wrong_key.key_id = "previous".into();
    assert!(!rotated
        .verify_digest(purposes[0], &ctx, b"payload", &known_but_wrong_key)
        .unwrap());
}

#[test]
fn digest_inputs_and_context_are_bounded_and_non_nil() {
    let crypto = crypto();
    let mut nil = context();
    nil.reference_id = Uuid::nil();
    assert_eq!(
        crypto
            .digest(SecurityDigestPurpose::Command, &nil, b"x")
            .unwrap_err(),
        SecurityCryptoError::InvalidInput
    );
    let mut nil = context();
    nil.related_id = Some(Uuid::nil());
    assert_eq!(
        crypto
            .digest(SecurityDigestPurpose::Command, &nil, b"x")
            .unwrap_err(),
        SecurityCryptoError::InvalidInput
    );
    assert_eq!(
        crypto
            .digest(
                SecurityDigestPurpose::Command,
                &context(),
                &vec![0; MAX_PAYLOAD_BYTES + 1]
            )
            .unwrap_err(),
        SecurityCryptoError::InvalidInput
    );
    assert!(crypto
        .digest(
            SecurityDigestPurpose::Command,
            &context(),
            &vec![0; MAX_PAYLOAD_BYTES]
        )
        .is_ok());
}

#[test]
fn previous_key_reads_exactly_and_current_key_writes() {
    let old =
        RingAccountSecurityCrypto::new("auth.example".into(), [200; 32], key_set("old", 10), None)
            .unwrap();
    let old_digest = old
        .digest(SecurityDigestPurpose::ReceiptSecret, &context(), b"receipt")
        .unwrap();
    let old_envelope = old
        .seal(
            SecurityEnvelopePurpose::RecoveryStartReceipt,
            &context(),
            &SecretString::new("receipt payload"),
        )
        .unwrap();
    let rotated = RingAccountSecurityCrypto::new(
        "auth.example".into(),
        [200; 32],
        key_set("new", 30),
        Some(key_set("old", 10)),
    )
    .unwrap();
    assert!(rotated
        .verify_digest(
            SecurityDigestPurpose::ReceiptSecret,
            &context(),
            b"receipt",
            &old_digest
        )
        .unwrap());
    assert_eq!(
        rotated
            .open(
                SecurityEnvelopePurpose::RecoveryStartReceipt,
                &context(),
                &old_envelope
            )
            .unwrap()
            .expose_secret(),
        "receipt payload"
    );
    assert_eq!(
        rotated.subject_digest(" User@Example.test ").unwrap(),
        old.subject_digest("user@example.test").unwrap(),
        "subject budget digest remains stable across keyset rotation"
    );
    assert_eq!(
        rotated
            .digest(SecurityDigestPurpose::ReceiptSecret, &context(), b"new")
            .unwrap()
            .key_id,
        "new"
    );
    let no_previous =
        RingAccountSecurityCrypto::new("auth.example".into(), [200; 32], key_set("new", 30), None)
            .unwrap();
    assert_eq!(
        no_previous.verify_digest(
            SecurityDigestPurpose::ReceiptSecret,
            &context(),
            b"receipt",
            &old_digest
        ),
        Err(SecurityCryptoError::UnknownKey)
    );
    assert_eq!(
        no_previous.open(
            SecurityEnvelopePurpose::RecoveryStartReceipt,
            &context(),
            &old_envelope
        ),
        Err(SecurityCryptoError::UnknownKey)
    );
}

#[test]
fn envelopes_bind_authority_purpose_and_context_and_reject_tampering() {
    let crypto = crypto();
    let plaintext = SecretString::new("encrypted recovery mail payload");
    let first = crypto
        .seal(
            SecurityEnvelopePurpose::RecoveryEmail,
            &context(),
            &plaintext,
        )
        .unwrap();
    let second = crypto
        .seal(
            SecurityEnvelopePurpose::RecoveryEmail,
            &context(),
            &plaintext,
        )
        .unwrap();
    assert_eq!(first.key_id, "current");
    assert_eq!(
        first.ciphertext.len(),
        NONCE_BYTES + plaintext.expose_secret().len() + TAG_BYTES
    );
    assert_ne!(
        &first.ciphertext[..NONCE_BYTES],
        &second.ciphertext[..NONCE_BYTES]
    );
    assert_eq!(
        crypto
            .open(SecurityEnvelopePurpose::RecoveryEmail, &context(), &first)
            .unwrap()
            .expose_secret(),
        plaintext.expose_secret()
    );
    assert_eq!(
        crypto.open(
            SecurityEnvelopePurpose::RecoveryStartReceipt,
            &context(),
            &first
        ),
        Err(SecurityCryptoError::InvalidCiphertext)
    );
    let mut other = context();
    other.reference_id = Uuid::from_u128(77);
    assert_eq!(
        crypto.open(SecurityEnvelopePurpose::RecoveryEmail, &other, &first),
        Err(SecurityCryptoError::InvalidCiphertext)
    );
    let mut nil = context();
    nil.reference_id = Uuid::nil();
    assert_eq!(
        crypto
            .open(SecurityEnvelopePurpose::RecoveryEmail, &nil, &first)
            .unwrap_err(),
        SecurityCryptoError::InvalidInput
    );
    assert_eq!(
        crypto
            .seal(
                SecurityEnvelopePurpose::RecoveryEmail,
                &nil,
                &SecretString::new("payload"),
            )
            .unwrap_err(),
        SecurityCryptoError::InvalidInput
    );
    other = context();
    other.related_id = Some(Uuid::from_u128(99));
    assert_eq!(
        crypto.open(SecurityEnvelopePurpose::RecoveryEmail, &other, &first),
        Err(SecurityCryptoError::InvalidCiphertext)
    );
    other.related_id = None;
    assert_eq!(
        crypto.open(SecurityEnvelopePurpose::RecoveryEmail, &other, &first),
        Err(SecurityCryptoError::InvalidCiphertext)
    );
    let other_authority =
        RingAccountSecurityCrypto::new("different".into(), [200; 32], key_set("current", 10), None)
            .unwrap();
    assert_eq!(
        other_authority.open(SecurityEnvelopePurpose::RecoveryEmail, &context(), &first),
        Err(SecurityCryptoError::InvalidCiphertext)
    );
    let rotated = RingAccountSecurityCrypto::new(
        "auth.example".into(),
        [200; 32],
        key_set("current", 10),
        Some(key_set("previous", 30)),
    )
    .unwrap();
    let mut known_but_wrong_key = first.clone();
    known_but_wrong_key.key_id = "previous".into();
    assert_eq!(
        rotated.open(
            SecurityEnvelopePurpose::RecoveryEmail,
            &context(),
            &known_but_wrong_key
        ),
        Err(SecurityCryptoError::InvalidCiphertext)
    );
    let mut tampered = first.clone();
    *tampered.ciphertext.last_mut().unwrap() ^= 1;
    assert_eq!(
        crypto.open(
            SecurityEnvelopePurpose::RecoveryEmail,
            &context(),
            &tampered
        ),
        Err(SecurityCryptoError::InvalidCiphertext)
    );
    for len in [0, NONCE_BYTES + TAG_BYTES - 1, MAX_ENVELOPE_BYTES + 1] {
        let bad = SecurityEnvelope {
            key_id: "current".into(),
            ciphertext: vec![0; len],
        };
        assert_eq!(
            crypto.open(SecurityEnvelopePurpose::RecoveryEmail, &context(), &bad),
            Err(SecurityCryptoError::InvalidCiphertext)
        );
    }
    let empty = crypto
        .seal(
            SecurityEnvelopePurpose::RecoveryEmail,
            &context(),
            &SecretString::new(""),
        )
        .unwrap();
    assert_eq!(empty.ciphertext.len(), NONCE_BYTES + TAG_BYTES);
    assert_eq!(
        crypto
            .open(SecurityEnvelopePurpose::RecoveryEmail, &context(), &empty)
            .unwrap()
            .expose_secret(),
        ""
    );
    let maximum = crypto
        .seal(
            SecurityEnvelopePurpose::RecoveryEmail,
            &context(),
            &SecretString::new("x".repeat(MAX_PAYLOAD_BYTES)),
        )
        .unwrap();
    assert_eq!(maximum.ciphertext.len(), MAX_ENVELOPE_BYTES);
    assert_eq!(
        crypto
            .open(SecurityEnvelopePurpose::RecoveryEmail, &context(), &maximum)
            .unwrap()
            .expose_secret()
            .len(),
        MAX_PAYLOAD_BYTES
    );
    assert_eq!(
        crypto
            .seal(
                SecurityEnvelopePurpose::RecoveryEmail,
                &context(),
                &SecretString::new("x".repeat(MAX_PAYLOAD_BYTES + 1))
            )
            .unwrap_err(),
        SecurityCryptoError::InvalidInput
    );
}

#[test]
fn authenticated_non_utf8_plaintext_is_rejected() {
    let crypto = crypto();
    let key_id = crypto.current.key_id.clone();
    let aad = crypto
        .envelope_aad(&key_id, SecurityEnvelopePurpose::RecoveryEmail, &context())
        .unwrap();
    let nonce = [9; NONCE_BYTES];
    let mut ciphertext = vec![0xff];
    RingAccountSecurityCrypto::envelope_key(&crypto.current.envelope_key)
        .unwrap()
        .seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(aad.as_slice()),
            &mut ciphertext,
        )
        .unwrap();
    let mut bytes = nonce.to_vec();
    bytes.extend_from_slice(&ciphertext);
    assert_eq!(
        crypto.open(
            SecurityEnvelopePurpose::RecoveryEmail,
            &context(),
            &SecurityEnvelope {
                key_id,
                ciphertext: bytes
            }
        ),
        Err(SecurityCryptoError::InvalidCiphertext)
    );
}

#[test]
fn random_token_and_code_have_required_formats_and_debug_is_redacted() {
    let crypto = crypto();
    for _ in 0..32 {
        let token = crypto.random_token().unwrap();
        assert_eq!(token.expose_secret().len(), 43);
        assert!(!token.expose_secret().contains('='));
        assert_eq!(
            Base64UrlUnpadded::decode_vec(token.expose_secret())
                .unwrap()
                .len(),
            32
        );
        let code = crypto.random_code().unwrap();
        assert_eq!(code.expose_secret().len(), 6);
        assert!(code.expose_secret().bytes().all(|b| b.is_ascii_digit()));
    }
    let digest = crypto
        .digest(SecurityDigestPurpose::Command, &context(), b"digest secret")
        .unwrap();
    let envelope = crypto
        .seal(
            SecurityEnvelopePurpose::RecoveryEmail,
            &context(),
            &SecretString::new("envelope secret"),
        )
        .unwrap();
    let debug = format!(
        "{:?} {:?} {:?} {:?} {:?}",
        crypto,
        crypto.current,
        digest,
        envelope,
        SecretString::new("plaintext")
    );
    for secret in [
        "10, 10",
        "200, 200",
        "digest secret",
        "envelope secret",
        "plaintext",
    ] {
        assert!(!debug.contains(secret));
    }
    assert!(debug.contains("auth.example"));
    assert!(debug.contains("current"));
    assert!(format!("{:?}", envelope).contains("ciphertext_length"));
}
