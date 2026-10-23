use super::*;

pub(super) async fn transport_parts(
    request: Request,
    config: &RegistrationEmailHttpConfig,
) -> Result<(HeaderMap, Bytes), Response> {
    let (parts, body) = request.into_parts();
    if let Err(response) = validate_profile_and_origin(&parts.headers, config) {
        return Err(response);
    }
    if let Err(response) = validate_tenant_header_shape(&parts.headers) {
        return Err(response);
    }
    if !is_json_content_type(&parts.headers) {
        return Err(error_response(
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid_request",
        ));
    }
    if parts
        .headers
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok())
        .is_some_and(|length| length > MAX_BODY_BYTES)
    {
        return Err(error_response(
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid_request",
        ));
    }
    let body = to_bytes(body, MAX_BODY_BYTES)
        .await
        .map_err(|_| error_response(StatusCode::UNPROCESSABLE_ENTITY, "invalid_request"))?;
    Ok((parts.headers, body))
}

pub(super) fn validate_profile_and_origin(
    headers: &HeaderMap,
    config: &RegistrationEmailHttpConfig,
) -> Result<(), Response> {
    let mut profiles = headers.get_all(REGISTRATION_EMAIL_PROFILE_HEADER).iter();
    let Some(profile) = profiles.next() else {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "registration_profile_required",
        ));
    };
    if profiles.next().is_some() || profile.to_str().ok() != Some(REGISTRATION_EMAIL_PROFILE) {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "registration_profile_required",
        ));
    }

    let mut origins = headers.get_all(header::ORIGIN).iter();
    let Some(origin) = origins.next() else {
        return Ok(());
    };
    if origins.next().is_some() {
        return Err(error_response(StatusCode::FORBIDDEN, "invalid_request"));
    }
    let Ok(origin) = origin.to_str() else {
        return Err(error_response(StatusCode::FORBIDDEN, "invalid_request"));
    };
    if origin == "null"
        || !config
            .allowed_origins
            .iter()
            .any(|allowed| allowed == origin)
    {
        return Err(error_response(StatusCode::FORBIDDEN, "invalid_request"));
    }
    Ok(())
}

pub(super) fn validate_tenant_header(
    headers: &HeaderMap,
    service: &Arc<dyn RegistrationEmailService>,
) -> Result<(), Response> {
    let mut values = headers.get_all("x-embedded-idp-tenant").iter();
    let Some(value) = values.next() else {
        return Ok(());
    };
    let Ok(value) = value.to_str() else {
        return Err(error_response(StatusCode::FORBIDDEN, "invalid_request"));
    };
    if value != service.scope().tenant {
        return Err(error_response(StatusCode::BAD_REQUEST, "invalid_tenant"));
    }
    Ok(())
}

pub(super) fn validate_tenant_header_shape(headers: &HeaderMap) -> Result<(), Response> {
    let mut values = headers.get_all("x-embedded-idp-tenant").iter();
    let Some(value) = values.next() else {
        return Ok(());
    };
    if values.next().is_some() || value.to_str().is_err() {
        return Err(error_response(StatusCode::FORBIDDEN, "invalid_request"));
    }
    Ok(())
}

pub(super) fn parse_json<T: for<'de> Deserialize<'de>>(body: &[u8]) -> Result<T, Response> {
    serde_json::from_slice(body).map_err(|error| {
        let status = match error.classify() {
            serde_json::error::Category::Syntax | serde_json::error::Category::Eof => {
                StatusCode::BAD_REQUEST
            }
            serde_json::error::Category::Data | serde_json::error::Category::Io => {
                StatusCode::UNPROCESSABLE_ENTITY
            }
        };
        error_response(status, "invalid_request")
    })
}

pub(super) fn validate_register(
    request: &RegisterRequest,
    service: &Arc<dyn RegistrationEmailService>,
) -> Result<embedded_idp_core::access::Uuid, Response> {
    validate_operation_id(&request.client_operation_id)?;
    validate_len(&request.tenant_id, 1, 128)?;
    validate_len(request.email.expose_secret(), 0, 254)?;
    validate_len(request.password.expose_secret(), 8, 128)?;
    if let Some(display_name) = request.display_name.as_ref() {
        validate_len(display_name.expose_secret(), 1, 128)?;
    }
    validate_tenant(&request.tenant_id, service)?;
    parse_operation_id(&request.client_operation_id)
}

pub(super) fn validate_resend(
    request: &ResendRequest,
    service: &Arc<dyn RegistrationEmailService>,
) -> Result<embedded_idp_core::access::Uuid, Response> {
    validate_operation_id(&request.client_operation_id)?;
    validate_len(&request.tenant_id, 1, 128)?;
    validate_context(request.verification_context.expose_secret())?;
    validate_tenant(&request.tenant_id, service)?;
    parse_operation_id(&request.client_operation_id)
}

pub(super) fn validate_verify(
    request: &VerifyRequest,
    service: &Arc<dyn RegistrationEmailService>,
) -> Result<embedded_idp_core::access::Uuid, Response> {
    validate_operation_id(&request.client_operation_id)?;
    validate_len(&request.tenant_id, 1, 128)?;
    validate_context(request.verification_context.expose_secret())?;
    validate_len(request.verification_code.expose_secret(), 0, 64)?;
    validate_tenant(&request.tenant_id, service)?;
    parse_operation_id(&request.client_operation_id)
}

pub(super) fn validate_tenant(
    tenant: &str,
    service: &Arc<dyn RegistrationEmailService>,
) -> Result<(), Response> {
    if tenant != service.scope().tenant {
        return Err(error_response(StatusCode::BAD_REQUEST, "invalid_tenant"));
    }
    Ok(())
}

pub(super) fn validate_len(value: &str, min: usize, max: usize) -> Result<(), Response> {
    let len = value.chars().count();
    if len < min || len > max {
        return Err(error_response(
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid_request",
        ));
    }
    Ok(())
}

pub(super) fn validate_operation_id(value: &str) -> Result<(), Response> {
    let uuid = parse_uuid(value)
        .map_err(|_| error_response(StatusCode::UNPROCESSABLE_ENTITY, "invalid_request"))?;
    if uuid.get_version_num() != 7 || uuid.to_string() != value {
        return Err(error_response(
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid_request",
        ));
    }
    Ok(())
}

pub(super) fn parse_operation_id(value: &str) -> Result<embedded_idp_core::access::Uuid, Response> {
    parse_uuid(value)
        .map_err(|_| error_response(StatusCode::UNPROCESSABLE_ENTITY, "invalid_request"))
}

pub(super) fn parse_uuid(value: &str) -> Result<embedded_idp_core::access::Uuid, ()> {
    embedded_idp_core::access::Uuid::parse_str(value).map_err(|_| ())
}

pub(super) fn validate_context(value: &str) -> Result<(), Response> {
    let bytes = value.as_bytes();
    if bytes.len() != 43
        || !bytes[..42]
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        || !matches!(
            bytes[42],
            b'A' | b'E'
                | b'I'
                | b'M'
                | b'Q'
                | b'U'
                | b'Y'
                | b'c'
                | b'g'
                | b'k'
                | b'o'
                | b's'
                | b'w'
                | b'0'
                | b'4'
                | b'8'
        )
    {
        return Err(error_response(
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid_request",
        ));
    }
    Ok(())
}

pub(super) fn validate_origin(origin: &str) -> Result<(), ()> {
    if origin.is_empty() || origin.chars().any(|character| character.is_control()) {
        return Err(());
    }
    let uri: Uri = origin.parse().map_err(|_| ())?;
    let scheme = uri.scheme_str().ok_or(())?;
    let authority = uri.authority().ok_or(())?;
    if uri.query().is_some() || origin != format!("{scheme}://{authority}") {
        return Err(());
    }
    if authority.as_str().contains('@') || authority.host().is_empty() {
        return Err(());
    }
    if !matches!(scheme, "https" | "http") {
        return Err(());
    }
    if scheme == "http" && !is_loopback_host(authority.host()) {
        return Err(());
    }
    Ok(())
}

pub(super) fn is_loopback_host(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    let host = host.trim_matches(['[', ']']);
    IpAddr::from_str(host).is_ok_and(|address| address.is_loopback())
}

pub(super) fn is_json_content_type(headers: &HeaderMap) -> bool {
    let mut values = headers.get_all(header::CONTENT_TYPE).iter();
    let Some(value) = values.next() else {
        return false;
    };
    if values.next().is_some() {
        return false;
    }
    let Ok(value) = value.to_str() else {
        return false;
    };
    value
        .split(';')
        .next()
        .map(str::trim)
        .is_some_and(|value| value.eq_ignore_ascii_case("application/json"))
}
