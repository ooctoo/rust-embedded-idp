use super::*;

#[test]
fn config_accepts_https_origin() {
    let config = RegistrationEmailHttpConfig::new(["https://console.example"], false);
    assert!(config.is_ok());
}

#[test]
fn config_rejects_http_origin_without_explicit_loopback_opt_in() {
    let config = RegistrationEmailHttpConfig::new(["http://127.0.0.1:9000"], false);
    assert_eq!(
        config,
        Err(RegistrationEmailError::InvalidInput("allowed_origin"))
    );
}

#[test]
fn config_accepts_loopback_http_when_enabled() {
    let config = RegistrationEmailHttpConfig::new(["http://127.0.0.1:9000"], true);
    assert!(config.is_ok());
}

#[test]
fn config_rejects_non_loopback_http() {
    let config = RegistrationEmailHttpConfig::new(["http://example.test"], true);
    assert_eq!(
        config,
        Err(RegistrationEmailError::InvalidInput("allowed_origin"))
    );
}

#[test]
fn config_rejects_origin_path_and_duplicates() {
    assert!(RegistrationEmailHttpConfig::new(["https://example.test/path"], false).is_err());
    assert!(RegistrationEmailHttpConfig::new(
        ["https://example.test", "https://example.test"],
        false
    )
    .is_err());
}

#[test]
fn profile_is_required_before_body_parse() {
    let config = RegistrationEmailHttpConfig::default();
    let error = validate_profile_and_origin(&HeaderMap::new(), &config).unwrap_err();
    assert_eq!(error.status(), StatusCode::BAD_REQUEST);
    assert_eq!(error.headers()[header::CACHE_CONTROL], "no-store");
}

#[test]
fn duplicate_profile_is_rejected() {
    let mut headers = profile_headers();
    headers.append(
        REGISTRATION_EMAIL_PROFILE_HEADER,
        HeaderValue::from_static(REGISTRATION_EMAIL_PROFILE),
    );
    let error =
        validate_profile_and_origin(&headers, &RegistrationEmailHttpConfig::default()).unwrap_err();
    assert_eq!(error.status(), StatusCode::BAD_REQUEST);
}

#[test]
fn duplicate_tenant_header_is_rejected_before_body() {
    let mut headers = profile_headers();
    headers.append(
        "x-embedded-idp-tenant",
        HeaderValue::from_static("tenant-a"),
    );
    headers.append(
        "x-embedded-idp-tenant",
        HeaderValue::from_static("tenant-a"),
    );
    let error = validate_tenant_header_shape(&headers).unwrap_err();
    assert_eq!(error.status(), StatusCode::FORBIDDEN);
}

#[test]
fn null_origin_is_forbidden() {
    let mut headers = profile_headers();
    headers.insert(header::ORIGIN, HeaderValue::from_static("null"));
    let config = RegistrationEmailHttpConfig::new(["https://console.example"], false).unwrap();
    let error = validate_profile_and_origin(&headers, &config).unwrap_err();
    assert_eq!(error.status(), StatusCode::FORBIDDEN);
}

#[test]
fn cross_site_origin_is_forbidden_without_cors_headers() {
    let mut headers = profile_headers();
    headers.insert(
        header::ORIGIN,
        HeaderValue::from_static("https://evil.example"),
    );
    let config = RegistrationEmailHttpConfig::new(["https://console.example"], false).unwrap();
    let error = validate_profile_and_origin(&headers, &config).unwrap_err();
    assert_eq!(error.status(), StatusCode::FORBIDDEN);
    assert!(!error.headers().contains_key("access-control-allow-origin"));
}

#[test]
fn only_application_json_is_accepted() {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    assert!(is_json_content_type(&headers));
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/vnd.api+json"),
    );
    assert!(!is_json_content_type(&headers));

    let mut duplicate = HeaderMap::new();
    duplicate.append(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    duplicate.append(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    assert!(!is_json_content_type(&duplicate));
}

#[test]
fn syntax_and_data_errors_have_distinct_statuses() {
    let syntax: Result<RegisterRequest, _> = parse_json(br"{");
    assert_eq!(syntax.unwrap_err().status(), StatusCode::BAD_REQUEST);
    let data: Result<RegisterRequest, _> = parse_json(
        br#"{"tenant_id":"tenant-a","email":"a@example.test","password":3,"client_operation_id":"018f0c0e-0000-7000-8000-000000000060"}"#,
    );
    assert_eq!(data.unwrap_err().status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[test]
fn unknown_and_duplicate_json_fields_are_rejected() {
    let unknown: Result<RegisterRequest, _> = parse_json(
        br#"{"tenant_id":"tenant-a","email":"a@example.test","password":"Correct-Horse-7","client_operation_id":"018f0c0e-0000-7000-8000-000000000060","actor":"unexpected"}"#,
    );
    assert_eq!(
        unknown.unwrap_err().status(),
        StatusCode::UNPROCESSABLE_ENTITY
    );
    let duplicate: Result<RegisterRequest, _> = parse_json(
        br#"{"tenant_id":"tenant-a","email":"a@example.test","password":"Correct-Horse-7","client_operation_id":"018f0c0e-0000-7000-8000-000000000060","tenant_id":"tenant-a"}"#,
    );
    assert_eq!(
        duplicate.unwrap_err().status(),
        StatusCode::UNPROCESSABLE_ENTITY
    );
    let null_display: Result<RegisterRequest, _> = parse_json(
        br#"{"tenant_id":"tenant-a","email":"a@example.test","password":"Correct-Horse-7","client_operation_id":"018f0c0e-0000-7000-8000-000000000060","display_name":null}"#,
    );
    assert_eq!(
        null_display.unwrap_err().status(),
        StatusCode::UNPROCESSABLE_ENTITY
    );
}

#[test]
fn operation_id_requires_lowercase_uuid_v7() {
    assert!(validate_operation_id("018f0c0e-0000-7000-8000-000000000060").is_ok());
    assert!(validate_operation_id("018f0c0e-0000-4000-8000-000000000060").is_err());
    assert!(validate_operation_id("018F0C0E-0000-7000-8000-000000000060").is_err());
}

#[test]
fn verification_context_requires_exact_unpadded_length() {
    assert!(validate_context(&context()).is_ok());
    assert!(validate_context(&format!("{}=", "A".repeat(42))).is_err());
    assert!(validate_context(&"A".repeat(42)).is_err());
}

#[test]
fn every_generated_32_byte_context_is_accepted_by_http() {
    use base64ct::{Base64UrlUnpadded, Encoding};
    for last in 0..=u8::MAX {
        let mut bytes = [0u8; 32];
        bytes[31] = last;
        let token = Base64UrlUnpadded::encode_string(&bytes);
        assert!(
            validate_context(&token).is_ok(),
            "canonical generated context rejected"
        );
        let response = accepted_response(RegistrationEmailAccepted {
            verification_context: SecretString::new(token),
            accepted_at_unix_secs: 1,
            context_lifetime_secs: 900,
            resend_after_secs: 60,
        });
        assert_eq!(response.status(), StatusCode::ACCEPTED);
    }
}

#[test]
fn all_noncanonical_context_tail_bits_are_rejected() {
    for tail in b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" {
        let token = format!("{}{}", "A".repeat(42), *tail as char);
        assert_eq!(
            validate_context(&token).is_ok(),
            b"AEIMQUYcgkosw048".contains(tail)
        );
    }
}
