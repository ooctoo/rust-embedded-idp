use base64ct::{Base64UrlUnpadded, Encoding};
use embedded_idp_core::{
    access::{
        build_scan_login_proof_bytes, scan_login_proof_context, EncryptedScanResult,
        ScanLoginAction, ScanResultCipher, ScanResultCipherError, ScanResultContext,
        ScanResultPayload, MAX_SCAN_RESULT_BYTES, SCAN_LOGIN_PROOF_PROFILE,
    },
    CanonicalHttpMethod, DeviceProofPresentation, DeviceProofProfile, DeviceRequestBinding,
    DeviceSignatureVerifier, SecretString,
};
use embedded_idp_security::{
    RingEd25519Verifier, RingScanResultCipher, ScanResultKey, ScanResultKeyring,
};
use ring::signature::KeyPair;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::time::{Duration, UNIX_EPOCH};

const GRANT_ID: &str = "22222222-2222-4222-8222-222222222222";
const DEVICE_ID: &str = "88888888-8888-4888-8888-888888888888";
const SESSION_ID: &str = "77777777-7777-4777-8777-777777777777";
const OPERATION_ID: &str = "66666666-6666-4666-8666-666666666666";

fn context() -> ScanResultContext {
    ScanResultContext {
        tenant_id: "tenant-a".into(),
        host_scope: "host-a".into(),
        entry_id: "terminal-login".into(),
        grant_id: GRANT_ID.into(),
        expires_at_unix_secs: 1_700_000_120,
        payload: ScanResultPayload::SessionBundle {
            device_id: DEVICE_ID.into(),
            session_id: SESSION_ID.into(),
            issuance_operation_id: OPERATION_ID.into(),
        },
    }
}

fn cipher() -> RingScanResultCipher {
    RingScanResultCipher::new(
        ScanResultKeyring::new("current", [ScanResultKey::new("current", [7; 32])]).unwrap(),
    )
}

#[test]
fn result_round_trip_uses_fresh_nonces() {
    let cipher = cipher();
    let context = context();
    let plaintext = SecretString::new("{\"access_token\":\"secret\"}");

    let first = cipher.seal(&context, &plaintext).unwrap();
    let second = cipher.seal(&context, &plaintext).unwrap();

    assert_eq!(first.key_id, "current");
    assert_ne!(first.nonce, second.nonce);
    assert_eq!(cipher.open(&context, &first).unwrap(), plaintext);
    assert_eq!(cipher.open(&context, &second).unwrap(), plaintext);
}

#[test]
fn result_authenticates_context_payload_and_ciphertext() {
    let cipher = cipher();
    let original = context();
    let encrypted = cipher
        .seal(&original, &SecretString::new("payload"))
        .unwrap();

    let mut variants = Vec::new();
    let mut changed = original.clone();
    changed.tenant_id = "tenant-b".into();
    variants.push(changed);
    let mut changed = original.clone();
    changed.host_scope = "host-b".into();
    variants.push(changed);
    let mut changed = original.clone();
    changed.entry_id = "another-entry".into();
    variants.push(changed);
    let mut changed = original.clone();
    changed.grant_id = "33333333-3333-4333-8333-333333333333".into();
    variants.push(changed);
    let mut changed = original.clone();
    changed.expires_at_unix_secs += 1;
    variants.push(changed);
    let mut changed = original.clone();
    changed.payload = ScanResultPayload::DevicePresentation {
        device_id: DEVICE_ID.into(),
        origin_operation_id: OPERATION_ID.into(),
    };
    variants.push(changed);
    let mut changed = original.clone();
    changed.payload = ScanResultPayload::PhonePresentation {
        source_session_id: SESSION_ID.into(),
        origin_operation_id: OPERATION_ID.into(),
    };
    variants.push(changed);
    let mut changed = original.clone();
    changed.payload = ScanResultPayload::SessionBundle {
        device_id: "99999999-9999-4999-8999-999999999999".into(),
        session_id: SESSION_ID.into(),
        issuance_operation_id: OPERATION_ID.into(),
    };
    variants.push(changed);
    let mut changed = original.clone();
    changed.payload = ScanResultPayload::SessionBundle {
        device_id: DEVICE_ID.into(),
        session_id: "99999999-9999-4999-8999-999999999999".into(),
        issuance_operation_id: OPERATION_ID.into(),
    };
    variants.push(changed);
    let mut changed = original.clone();
    changed.payload = ScanResultPayload::SessionBundle {
        device_id: DEVICE_ID.into(),
        session_id: SESSION_ID.into(),
        issuance_operation_id: "99999999-9999-4999-8999-999999999999".into(),
    };
    variants.push(changed);

    for changed in variants {
        assert_eq!(
            cipher.open(&changed, &encrypted),
            Err(ScanResultCipherError::DecryptionFailed)
        );
    }

    let mut tampered = encrypted.clone();
    tampered.ciphertext[0] ^= 1;
    assert_eq!(
        cipher.open(&original, &tampered),
        Err(ScanResultCipherError::DecryptionFailed)
    );
    let mut tampered = encrypted.clone();
    tampered.nonce[0] ^= 1;
    assert_eq!(
        cipher.open(&original, &tampered),
        Err(ScanResultCipherError::DecryptionFailed)
    );
    let mut unknown_key = encrypted;
    unknown_key.key_id = "missing".into();
    assert_eq!(
        cipher.open(&original, &unknown_key),
        Err(ScanResultCipherError::DecryptionFailed)
    );
}

#[test]
fn rotated_keyring_keeps_old_results_readable() {
    let old = RingScanResultCipher::new(
        ScanResultKeyring::new("old", [ScanResultKey::new("old", [3; 32])]).unwrap(),
    );
    let context = context();
    let encrypted = old.seal(&context, &SecretString::new("previous")).unwrap();
    let rotated = RingScanResultCipher::new(
        ScanResultKeyring::new(
            "current",
            [
                ScanResultKey::new("current", [7; 32]),
                ScanResultKey::new("old", [3; 32]),
            ],
        )
        .unwrap(),
    );

    assert_eq!(
        rotated.open(&context, &encrypted).unwrap(),
        SecretString::new("previous")
    );
}

#[test]
fn rejects_oversized_results_and_invalid_keyrings_without_exposing_key_bytes() {
    let context = context();
    let cipher = cipher();
    assert_eq!(
        cipher.seal(
            &context,
            &SecretString::new("a".repeat(MAX_SCAN_RESULT_BYTES + 1))
        ),
        Err(ScanResultCipherError::ResultTooLarge)
    );
    assert_eq!(
        ScanResultKeyring::new("", [ScanResultKey::new("current", [1; 32])]),
        Err(ScanResultCipherError::InvalidKeyConfiguration)
    );
    assert_eq!(
        ScanResultKeyring::new("missing", [ScanResultKey::new("current", [1; 32])]),
        Err(ScanResultCipherError::InvalidKeyConfiguration)
    );
    assert_eq!(
        ScanResultKeyring::new(
            "current",
            [
                ScanResultKey::new("current", [1; 32]),
                ScanResultKey::new("other", [1; 32]),
            ],
        ),
        Err(ScanResultCipherError::InvalidKeyConfiguration)
    );
    assert_eq!(
        ScanResultKeyring::new(
            "current",
            [
                ScanResultKey::new("current", [1; 32]),
                ScanResultKey::new("current", [2; 32]),
            ],
        ),
        Err(ScanResultCipherError::InvalidKeyConfiguration)
    );
    assert_eq!(
        ScanResultKeyring::new("current", [ScanResultKey::new("", [1; 32])]),
        Err(ScanResultCipherError::InvalidKeyConfiguration)
    );
    for invalid_key_id in ["current key", "current\nkey", "密钥", &"a".repeat(129)] {
        assert_eq!(
            ScanResultKeyring::new(invalid_key_id, [ScanResultKey::new("current", [1; 32])],),
            Err(ScanResultCipherError::InvalidKeyConfiguration)
        );
        assert_eq!(
            ScanResultKeyring::new("current", [ScanResultKey::new(invalid_key_id, [1; 32])],),
            Err(ScanResultCipherError::InvalidKeyConfiguration)
        );
    }

    let key = ScanResultKey::new("current", [42; 32]);
    let keyring = ScanResultKeyring::new("current", [key.clone()]).unwrap();
    assert!(!format!("{key:?}").contains("42"));
    assert!(!format!("{keyring:?}").contains("42"));
}

#[test]
fn rejects_malformed_ciphertexts_before_decryption() {
    let cipher = cipher();
    let context = context();
    for ciphertext in [Vec::new(), vec![0; 15], vec![0; MAX_SCAN_RESULT_BYTES + 17]] {
        assert_eq!(
            cipher.open(
                &context,
                &EncryptedScanResult {
                    key_id: "current".into(),
                    nonce: [0; 12],
                    ciphertext,
                },
            ),
            Err(ScanResultCipherError::DecryptionFailed)
        );
    }
}

#[test]
fn scan_login_proof_vectors_are_frozen_across_rust_and_host_implementations() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../docs/fixtures/device-scan-login-v1.json"
    ))
    .unwrap();
    let seed_text = fixture["test_seed_hex"].as_str().unwrap();
    let seed: Vec<u8> = (0..seed_text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&seed_text[index..index + 2], 16).unwrap())
        .collect();
    let private = ring::signature::Ed25519KeyPair::from_seed_unchecked(&seed).unwrap();
    let public_key: [u8; 32] =
        Base64UrlUnpadded::decode_vec(fixture["public_jwk"]["x"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
    assert_eq!(private.public_key().as_ref(), public_key);

    for vector in fixture["vectors"].as_array().unwrap() {
        let text = |name: &str| vector[name].as_str().unwrap();
        let action = scan_action(text("action"));
        assert_eq!(action.purpose_str(), text("purpose"), "{}", text("name"));
        assert_eq!(
            text("profile"),
            SCAN_LOGIN_PROOF_PROFILE,
            "{}",
            text("name")
        );
        let binding = DeviceRequestBinding::new(
            text("tenant_id"),
            DeviceProofProfile::new(text("profile")).unwrap(),
            text("audience"),
            CanonicalHttpMethod::Post,
            text("path"),
            Sha256::digest(text("body_utf8").as_bytes()).into(),
        )
        .unwrap();
        assert_eq!(
            Base64UrlUnpadded::encode_string(&binding.body_sha256),
            text("body_sha256"),
            "{}",
            text("name")
        );
        let proof = DeviceProofPresentation {
            device_id: text("device_id").into(),
            key_id: text("key_id").into(),
            challenge: text("challenge").into(),
            signature: text("signature").into(),
            signed_at: UNIX_EPOCH + Duration::from_secs(vector["signed_at"].as_u64().unwrap()),
        };
        let context =
            scan_login_proof_context(action, text("target_client_id"), text("entry_id")).unwrap();
        assert_eq!(
            Base64UrlUnpadded::encode_string(&context),
            text("context_sha256"),
            "{}",
            text("name")
        );
        let bytes = build_scan_login_proof_bytes(
            &binding,
            &proof,
            action,
            text("target_client_id"),
            text("entry_id"),
        )
        .unwrap();
        assert_eq!(bytes, text("canonical_utf8").as_bytes(), "{}", text("name"));
        assert_eq!(
            Base64UrlUnpadded::encode_string(&Sha256::digest(&bytes)),
            text("canonical_sha256"),
            "{}",
            text("name")
        );
        let signature: [u8; 64] = Base64UrlUnpadded::decode_vec(text("signature"))
            .unwrap()
            .try_into()
            .unwrap();
        RingEd25519Verifier
            .verify_ed25519(&public_key, &bytes, &signature)
            .unwrap();

        for changed in [
            build_scan_login_proof_bytes(
                &binding,
                &proof,
                alternate_action(action),
                text("target_client_id"),
                text("entry_id"),
            )
            .unwrap(),
            build_scan_login_proof_bytes(
                &binding,
                &proof,
                action,
                "other-client",
                text("entry_id"),
            )
            .unwrap(),
            build_scan_login_proof_bytes(
                &binding,
                &proof,
                action,
                text("target_client_id"),
                "other-entry",
            )
            .unwrap(),
        ] {
            assert_ne!(bytes, changed, "{}", text("name"));
            assert!(RingEd25519Verifier
                .verify_ed25519(&public_key, &changed, &signature)
                .is_err());
        }
    }
}

fn scan_action(action: &str) -> ScanLoginAction {
    match action {
        "create" => ScanLoginAction::Create,
        "claim" => ScanLoginAction::Claim,
        "status" => ScanLoginAction::Status,
        "lookup" => ScanLoginAction::Lookup,
        "cancel" => ScanLoginAction::Cancel,
        "exchange" => ScanLoginAction::Exchange,
        "recover" => ScanLoginAction::Recover,
        "acknowledge" => ScanLoginAction::Acknowledge,
        "abort" => ScanLoginAction::Abort,
        _ => panic!("unsupported fixture action"),
    }
}

fn alternate_action(action: ScanLoginAction) -> ScanLoginAction {
    if action == ScanLoginAction::Create {
        ScanLoginAction::Claim
    } else {
        ScanLoginAction::Create
    }
}
