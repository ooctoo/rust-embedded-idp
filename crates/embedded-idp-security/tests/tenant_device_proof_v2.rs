//! Cross-language frozen vectors generated from an explicitly public test seed.
use base64ct::{Base64UrlUnpadded, Encoding};
use embedded_idp_core::{access::*, SecretString};
use embedded_idp_core::{
    build_device_key_rotation_proof_bytes, build_device_registration_proof_bytes,
    build_request_proof_bytes, CanonicalHttpMethod, DeviceProofPresentation, DeviceProofProfile,
    DeviceRequestBinding, DeviceSignatureVerifier,
};
use embedded_idp_security::RingEd25519Verifier;
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::time::{Duration, UNIX_EPOCH};

#[test]
fn rust_and_node_share_tenant_bound_ed25519_vectors() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/tenant_device_proof_v2.json")).unwrap();
    let seed_text = fixture["test_seed_hex"].as_str().unwrap();
    let seed: Vec<u8> = (0..seed_text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&seed_text[i..i + 2], 16).unwrap())
        .collect();
    let key = Ed25519KeyPair::from_seed_unchecked(&seed).unwrap();
    let public_key: [u8; 32] = key.public_key().as_ref().try_into().unwrap();
    assert_eq!(
        Base64UrlUnpadded::encode_string(&public_key),
        fixture["public_key"]
    );
    for v in fixture["vectors"].as_array().unwrap() {
        let text = |name: &str| v[name].as_str().unwrap();
        let tenant = text("tenant_id");
        let bytes = match text("kind") {
            "registration" => build_device_registration_proof_bytes(
                tenant,
                text("device_id"),
                text("key_id"),
                text("challenge"),
            )
            .unwrap(),
            "rotation" => build_device_key_rotation_proof_bytes(
                tenant,
                text("device_id"),
                text("old_key_id"),
                text("key_id"),
                v["key_version"].as_u64().unwrap(),
                text("challenge"),
            )
            .unwrap(),
            "request" | "authentication" => {
                let binding = DeviceRequestBinding::new(
                    tenant,
                    DeviceProofProfile::new(text("profile")).unwrap(),
                    text("audience"),
                    match text("method") {
                        "GET" => CanonicalHttpMethod::Get,
                        "POST" => CanonicalHttpMethod::Post,
                        _ => panic!("unsupported fixture method"),
                    },
                    text("path"),
                    Sha256::digest(text("body_utf8").as_bytes()).into(),
                )
                .unwrap();
                let proof = DeviceProofPresentation {
                    device_id: text("device_id").into(),
                    key_id: text("key_id").into(),
                    challenge: text("challenge").into(),
                    signature: text("signature").into(),
                    signed_at: UNIX_EPOCH + Duration::from_secs(v["signed_at"].as_u64().unwrap()),
                };
                if text("kind") == "authentication" {
                    let context = if text("credential_kind") == "password" {
                        tenant_password_proof_context(
                            text("client_id"),
                            text("login_entry"),
                            &TenantPasswordLogin {
                                email: text("email").into(),
                                password: SecretString::new(text("password")),
                            },
                        )
                    } else if text("credential_kind") == "refresh" {
                        tenant_refresh_proof_context(
                            text("client_id"),
                            text("login_entry"),
                            &SecretString::new(text("refresh_token")),
                        )
                    } else if text("credential_kind") == "authorization_code" {
                        tenant_code_proof_context(
                            text("login_entry"),
                            &TenantCodeExchange {
                                grant_type: text("grant_type").into(),
                                client_id: text("client_id").into(),
                                code: SecretString::new(text("code")),
                                redirect_uri: text("redirect_uri").into(),
                                code_verifier: Some(SecretString::new(text("code_verifier"))),
                                client_secret: Some(SecretString::new(text("client_secret"))),
                            },
                        )
                    } else {
                        tenant_selection_proof_context(
                            text("client_id"),
                            text("login_entry"),
                            &SecretString::new(text("ticket")),
                        )
                    };
                    assert_eq!(
                        Base64UrlUnpadded::encode_string(&context),
                        text("credential_sha256")
                    );
                    build_tenant_authentication_proof_bytes(&binding, &proof, &context).unwrap()
                } else {
                    build_request_proof_bytes(&binding, &proof).unwrap()
                }
            }
            _ => panic!("unsupported fixture kind"),
        };
        assert_eq!(bytes, text("canonical_utf8").as_bytes(), "{}", text("name"));
        assert_eq!(
            Base64UrlUnpadded::encode_string(&Sha256::digest(&bytes)),
            text("sha256")
        );
        let signature: [u8; 64] = Base64UrlUnpadded::decode_vec(text("signature"))
            .unwrap()
            .try_into()
            .unwrap();
        assert_eq!(key.sign(&bytes).as_ref(), signature);
        RingEd25519Verifier
            .verify_ed25519(&public_key, &bytes, &signature)
            .unwrap();
        let canonical = String::from_utf8(bytes).unwrap();
        let tenant_line = format!("tenant-id:{tenant}\n");
        for changed in [
            canonical.replace(&tenant_line, "tenant-id:other-tenant\n"),
            canonical.replace(&tenant_line, ""),
            canonical
                .replace("-V2\n", "-V1\n")
                .replace(&tenant_line, ""),
            canonical.trim_end_matches('\n').to_owned(),
        ] {
            assert!(RingEd25519Verifier
                .verify_ed25519(&public_key, changed.as_bytes(), &signature)
                .is_err());
            // Also prove that an authentic old-format signature cannot pass the V2 verifier.
            let old_signature: [u8; 64] = key.sign(changed.as_bytes()).as_ref().try_into().unwrap();
            assert!(RingEd25519Verifier
                .verify_ed25519(&public_key, canonical.as_bytes(), &old_signature)
                .is_err());
        }
    }
}
