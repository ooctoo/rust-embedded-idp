use super::*;

#[tokio::test]
async fn accepted_response_has_only_frozen_public_fields_and_no_store() {
    let response = accepted_response(RegistrationEmailAccepted {
        verification_context: SecretString::new(context()),
        accepted_at_unix_secs: 1_713_894_200,
        context_lifetime_secs: ACCEPTED_CONTEXT_LIFETIME_SECS,
        resend_after_secs: ACCEPTED_RESEND_AFTER_SECS,
    });
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    let value: Value = serde_json::from_slice(
        &to_bytes(response.into_body(), MAX_BODY_BYTES)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(value["status"], "verification_requested");
    assert_eq!(value["verification_context"], context());
    assert_eq!(value["context_lifetime_secs"], 900);
    assert_eq!(value["resend_after_secs"], 60);
    assert_eq!(value.as_object().unwrap().len(), 5);
}

#[test]
fn errors_have_fixed_shape_and_remove_auth_headers() {
    let mut response = error_response(StatusCode::UNAUTHORIZED, "invalid_request");
    response
        .headers_mut()
        .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
    let response = with_no_store(response);
    assert!(!response.headers().contains_key(header::WWW_AUTHENTICATE));
    let body = response.into_body();
    let _ = body;
}

#[tokio::test]
async fn oneshot_register_projects_the_frozen_acceptance_shape() {
    let (app, workers, service) = app().await;
    let response = app
        .oneshot(request(
            REGISTER_PATH,
            r#"{"tenant_id":"tenant-a","email":"member@example.test","password":"Correct-Horse-7","client_operation_id":"018f0c0e-0000-7000-8000-000000000060"}"#,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    let value = json(response).await;
    assert_eq!(value["status"], "verification_requested");
    assert_eq!(value.as_object().unwrap().len(), 5);
    assert_eq!(*service.calls.lock().unwrap(), 1);
    workers.shutdown(Duration::from_secs(1)).await;
}

#[tokio::test]
async fn oneshot_profile_gate_wins_over_malformed_json() {
    let (app, workers, service) = app().await;
    let response = app
        .oneshot(
            Request::post(REGISTER_PATH)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from("{"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        json(response).await["error"]["code"],
        "registration_profile_required"
    );
    assert_eq!(*service.calls.lock().unwrap(), 0);
    workers.shutdown(Duration::from_secs(1)).await;
}

#[tokio::test]
async fn oneshot_unknown_field_is_422_and_does_not_enter_core() {
    let (app, workers, service) = app().await;
    let response = app
        .oneshot(request(
            REGISTER_PATH,
            r#"{"tenant_id":"tenant-a","email":"member@example.test","password":"Correct-Horse-7","client_operation_id":"018f0c0e-0000-7000-8000-000000000060","actor":"unexpected"}"#,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(json(response).await["error"]["code"], "invalid_request");
    assert_eq!(*service.calls.lock().unwrap(), 0);
    workers.shutdown(Duration::from_secs(1)).await;
}

#[tokio::test]
async fn oneshot_verify_unavailable_is_uniform_400_without_bearer_challenge() {
    let (app, workers, _) = app().await;
    let response = app
        .oneshot(request(
            VERIFY_PATH,
            &format!(
                r#"{{"tenant_id":"tenant-a","verification_context":"{}","verification_code":"000000","client_operation_id":"018f0c0e-0000-7000-8000-000000000060"}}"#,
                context()
            ),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(!response.headers().contains_key(header::WWW_AUTHENTICATE));
    assert_eq!(
        json(response).await["error"]["code"],
        "verification_unavailable"
    );
    workers.shutdown(Duration::from_secs(1)).await;
}

#[tokio::test]
async fn oneshot_method_errors_are_also_no_store() {
    let (app, workers, _) = app().await;
    let response = app
        .oneshot(Request::get(REGISTER_PATH).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert!(!response.headers().contains_key(header::SET_COOKIE));
    assert!(!response.headers().contains_key(header::LOCATION));
    assert!(!response.headers().contains_key(header::WWW_AUTHENTICATE));
    workers.shutdown(Duration::from_secs(1)).await;
}

#[tokio::test]
async fn oneshot_unknown_paths_are_also_no_store() {
    let (app, workers, _) = app().await;
    let response = app
        .oneshot(Request::get("/auth/unknown").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert!(!response.headers().contains_key(header::SET_COOKIE));
    assert!(!response.headers().contains_key(header::LOCATION));
    assert!(!response.headers().contains_key(header::WWW_AUTHENTICATE));
    workers.shutdown(Duration::from_secs(1)).await;
}

#[tokio::test]
async fn oneshot_new_registration_is_closed_without_worker() {
    let service = Arc::new(FakeService::new());
    let (app, workers) = app_for_service(service.clone(), false).await;
    let response = app
        .oneshot(request(
            REGISTER_PATH,
            r#"{"tenant_id":"tenant-a","email":"member@example.test","password":"Correct-Horse-7","client_operation_id":"018f0c0e-0000-7000-8000-000000000060"}"#,
        ))
        .await
        .unwrap();
    assert!(workers.is_none());
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        json(response).await["error"]["code"],
        "temporarily_unavailable"
    );
    assert_eq!(*service.calls.lock().unwrap(), 0);
}

#[tokio::test]
async fn oneshot_replay_does_not_activate_a_paused_runtime() {
    let mut fake = FakeService::new();
    fake.replay = true;
    fake.facts.accepting = false;
    fake.facts.overdue_processing = 1;
    fake.facts.unresolved_delivery = 1;
    let service = Arc::new(fake);
    let (app, workers) = app_for_service(service.clone(), false).await;
    let response = app
        .oneshot(request(
            REGISTER_PATH,
            r#"{"tenant_id":"tenant-a","email":"member@example.test","password":"Correct-Horse-7","client_operation_id":"018f0c0e-0000-7000-8000-000000000060"}"#,
        ))
        .await
        .unwrap();
    assert!(workers.is_none());
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    assert_eq!(*service.calls.lock().unwrap(), 1);
}

#[tokio::test]
async fn oneshot_oversized_body_is_rejected_before_core() {
    let (app, workers, service) = app().await;
    let response = app
        .oneshot(
            Request::post(REGISTER_PATH)
                .header(header::CONTENT_TYPE, "application/json")
                .header(
                    REGISTRATION_EMAIL_PROFILE_HEADER,
                    REGISTRATION_EMAIL_PROFILE,
                )
                .body(Body::from(vec![b'a'; MAX_BODY_BYTES + 1]))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(json(response).await["error"]["code"], "invalid_request");
    assert_eq!(*service.calls.lock().unwrap(), 0);
    workers.shutdown(Duration::from_secs(1)).await;
}
