use super::*;

pub(super) async fn register(
    State(state): State<RegistrationEmailHttpState>,
    request: Request,
) -> Response {
    let start = Instant::now();
    let (headers, body) = match transport_parts(request, &state.config).await {
        Ok(parts) => parts,
        Err(response) => return response,
    };
    let request: RegisterRequest = match parse_json(&body) {
        Ok(request) => request,
        Err(response) => return response,
    };
    let service = state.runtime.service();
    let operation = match validate_register(&request, &service) {
        Ok(operation) => operation,
        Err(response) => return response,
    };
    if let Err(response) = validate_tenant_header(&headers, &service) {
        return response;
    }

    let (service, replay, facts) = match inspect_runtime(
        &state.runtime,
        service,
        RegistrationEmailOperationKind::Register,
        operation,
    )
    .await
    {
        Ok(value) => value,
        Err(error) => return delayed_error(start, error).await,
    };
    if !facts.store_ready {
        return delayed_error(start, RegistrationEmailError::Unavailable).await;
    }
    if !replay
        && (!state.runtime.worker_running()
            || !facts.accepting
            || facts.overdue_processing != 0
            || facts.unresolved_delivery != 0)
    {
        return delayed_error(start, RegistrationEmailError::Unavailable).await;
    }
    let permit = match state
        .runtime
        .try_request(RegistrationEmailOperationKind::Register, replay)
    {
        Ok(permit) => permit,
        Err(error) => return delayed_error(start, error).await,
    };
    let hold = permit.clone();
    let command = RegistrationEmailCommand {
        operation,
        email: request.email,
        password: request.password,
        display_name: request.display_name,
    };
    let result = crate::registration_call(permit, move || service.register_command(command)).await;
    let response = match result {
        Ok(accepted) => accepted_response(accepted),
        Err(error) => error_response_for(error),
    };
    crate::anonymous_response_delay(start).await;
    drop(hold);
    response
}

pub(super) async fn resend(
    State(state): State<RegistrationEmailHttpState>,
    request: Request,
) -> Response {
    let start = Instant::now();
    let (headers, body) = match transport_parts(request, &state.config).await {
        Ok(parts) => parts,
        Err(response) => return response,
    };
    let request: ResendRequest = match parse_json(&body) {
        Ok(request) => request,
        Err(response) => return response,
    };
    let service = state.runtime.service();
    let operation = match validate_resend(&request, &service) {
        Ok(operation) => operation,
        Err(response) => return response,
    };
    if let Err(response) = validate_tenant_header(&headers, &service) {
        return response;
    }
    let (service, replay, facts) = match inspect_runtime(
        &state.runtime,
        service,
        RegistrationEmailOperationKind::Resend,
        operation,
    )
    .await
    {
        Ok(value) => value,
        Err(error) => return delayed_error(start, error).await,
    };
    if !facts.store_ready {
        return delayed_error(start, RegistrationEmailError::Unavailable).await;
    }
    if !replay
        && (!state.runtime.worker_running()
            || !facts.accepting
            || facts.overdue_processing != 0
            || facts.unresolved_delivery != 0)
    {
        return delayed_error(start, RegistrationEmailError::Unavailable).await;
    }
    let permit = match state
        .runtime
        .try_request(RegistrationEmailOperationKind::Resend, replay)
    {
        Ok(permit) => permit,
        Err(error) => return delayed_error(start, error).await,
    };
    let hold = permit.clone();
    let context = request.verification_context;
    let result = crate::registration_call(permit, move || {
        service.resend_command(operation, context.expose_secret())
    })
    .await;
    let response = match result {
        Ok(()) => accepted_resend_response(),
        Err(error) => error_response_for(error),
    };
    crate::anonymous_response_delay(start).await;
    drop(hold);
    response
}

pub(super) async fn verify(
    State(state): State<RegistrationEmailHttpState>,
    request: Request,
) -> Response {
    let start = Instant::now();
    let (headers, body) = match transport_parts(request, &state.config).await {
        Ok(parts) => parts,
        Err(response) => return response,
    };
    let request: VerifyRequest = match parse_json(&body) {
        Ok(request) => request,
        Err(response) => return response,
    };
    let service = state.runtime.service();
    let operation = match validate_verify(&request, &service) {
        Ok(operation) => operation,
        Err(response) => return response,
    };
    if let Err(response) = validate_tenant_header(&headers, &service) {
        return response;
    }
    let (service, replay, facts) = match inspect_runtime(
        &state.runtime,
        service,
        RegistrationEmailOperationKind::Verify,
        operation,
    )
    .await
    {
        Ok(value) => value,
        Err(error) => return delayed_error(start, error).await,
    };
    if !facts.store_ready {
        return delayed_error(start, RegistrationEmailError::Unavailable).await;
    }
    let permit = match state
        .runtime
        .try_request(RegistrationEmailOperationKind::Verify, replay)
    {
        Ok(permit) => permit,
        Err(error) => return delayed_error(start, error).await,
    };
    let hold = permit.clone();
    let context = request.verification_context;
    let code = request.verification_code;
    let result = crate::registration_call(permit, move || {
        service.verify_command(operation, context.expose_secret(), code.expose_secret())
    })
    .await;
    let response = match result {
        Ok(RegistrationEmailVerification::Verified) => with_no_store(
            (
                StatusCode::OK,
                Json(VerifySuccessResponse { status: "verified" }),
            )
                .into_response(),
        ),
        Ok(RegistrationEmailVerification::Unavailable) => {
            error_response(StatusCode::BAD_REQUEST, "verification_unavailable")
        }
        Err(error) => error_response_for(error),
    };
    crate::anonymous_response_delay(start).await;
    drop(hold);
    response
}

pub(super) async fn inspect_runtime(
    runtime: &Arc<crate::RegistrationEmailRuntime>,
    service: Arc<dyn RegistrationEmailService>,
    kind: RegistrationEmailOperationKind,
    operation: embedded_idp_core::access::Uuid,
) -> Result<
    (
        Arc<dyn RegistrationEmailService>,
        bool,
        embedded_idp_core::access::RegistrationEmailRuntimeFacts,
    ),
    RegistrationEmailError,
> {
    let permit = runtime.try_probe()?;
    let check_service = service.clone();
    crate::registration_call(permit, move || {
        let replay = check_service.is_replay(kind, operation)?;
        let facts = check_service.runtime_facts()?;
        Ok((check_service, replay, facts))
    })
    .await
}
