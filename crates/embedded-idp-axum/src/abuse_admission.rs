use axum::{
    body::{to_bytes, Body},
    extract::{ConnectInfo, Request, State},
    http::{header, HeaderValue, Method, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    Json, Router,
};
use embedded_idp_core::{AbuseAdmission, AdmissionConfigError, AdmissionRejection};
use http_body_util::LengthLimitError;
use serde::Deserialize;
use std::{error::Error, net::SocketAddr, sync::Arc, time::Duration};

const ACCOUNT_BODY_LIMIT: usize = 16 * 1024;
const ACCOUNT_BODY_DEADLINE: Duration = Duration::from_secs(5);

/// A host-asserted source identity. Construct this only from trusted host state,
/// never from request headers or other client-controlled values.
#[derive(Clone)]
pub struct TrustedRequestSource(Vec<u8>);

impl TrustedRequestSource {
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, AdmissionConfigError> {
        if !(1..=256).contains(&bytes.len()) {
            return Err(AdmissionConfigError("invalid trusted request source"));
        }
        Ok(Self(bytes))
    }
}

/// Add host-injected source and account admission to a complete router.
pub fn with_abuse_admission(router: Router, admission: Arc<dyn AbuseAdmission>) -> Router {
    router.layer(middleware::from_fn_with_state(admission, admit))
}

async fn admit(
    State(admission): State<Arc<dyn AbuseAdmission>>,
    request: Request,
    next: Next,
) -> Response {
    if !is_write_method(request.method()) {
        return next.run(request).await;
    }

    let source = request
        .extensions()
        .get::<TrustedRequestSource>()
        .map(|source| source.0.clone())
        .or_else(|| {
            request
                .extensions()
                .get::<ConnectInfo<SocketAddr>>()
                .map(|info| socket_source(info.0))
        });
    let Some(source) = source else {
        return unavailable();
    };
    if let Err(rejection) = admission.admit_source(&source) {
        return rejection_response(rejection);
    }

    if !uses_account_budget(request.uri().path()) {
        return next.run(request).await;
    }

    let (parts, body) = request.into_parts();
    let bytes =
        match tokio::time::timeout(ACCOUNT_BODY_DEADLINE, to_bytes(body, ACCOUNT_BODY_LIMIT)).await
        {
            Err(_) => return body_error(StatusCode::REQUEST_TIMEOUT, "request_timeout"),
            Ok(Err(error)) if is_length_limit_error(&error) => {
                return body_error(StatusCode::PAYLOAD_TOO_LARGE, "request_too_large");
            }
            Ok(Err(_)) => return body_error(StatusCode::BAD_REQUEST, "invalid_request_body"),
            Ok(Ok(bytes)) => bytes,
        };

    if let Ok(credential) = serde_json::from_slice::<AccountCredential>(&bytes) {
        if let Err(rejection) = admission.admit_account(&credential.email) {
            return rejection_response(rejection);
        }
    }

    next.run(Request::from_parts(parts, Body::from(bytes)))
        .await
}

fn is_length_limit_error(error: &(dyn Error + 'static)) -> bool {
    let mut source = Some(error);
    while let Some(error) = source {
        if error.downcast_ref::<LengthLimitError>().is_some() {
            return true;
        }
        source = error.source();
    }
    false
}

fn is_write_method(method: &Method) -> bool {
    method == Method::POST
        || method == Method::PUT
        || method == Method::PATCH
        || method == Method::DELETE
}

fn uses_account_budget(path: &str) -> bool {
    let mut parts = path.rsplit('/').filter(|part| !part.is_empty());
    let last = parts.next().unwrap_or_default();
    match last {
        "login" | "register" | "verify-email" | "resend-verification" => true,
        "start" | "verify" => parts.next() == Some("password-recovery"),
        _ => false,
    }
}

fn socket_source(address: SocketAddr) -> Vec<u8> {
    match address.ip() {
        std::net::IpAddr::V4(ip) => {
            let mut source = Vec::with_capacity(5);
            source.push(4);
            source.extend_from_slice(&ip.octets());
            source
        }
        std::net::IpAddr::V6(ip) => {
            if let Some(ip) = ip.to_ipv4_mapped() {
                let mut source = Vec::with_capacity(5);
                source.push(4);
                source.extend_from_slice(&ip.octets());
                source
            } else {
                let mut source = Vec::with_capacity(17);
                source.push(6);
                source.extend_from_slice(&ip.octets());
                source
            }
        }
    }
}

#[derive(Deserialize)]
struct AccountCredential {
    email: String,
}

fn rejection_response(rejection: AdmissionRejection) -> Response {
    match rejection {
        AdmissionRejection::RateLimited => {
            let mut response = error_response(
                StatusCode::TOO_MANY_REQUESTS,
                "rate_limited",
                "request rate limit exceeded",
            );
            response
                .headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from_static("60"));
            response
        }
        AdmissionRejection::Unavailable => unavailable(),
    }
}

fn unavailable() -> Response {
    error_response(
        StatusCode::SERVICE_UNAVAILABLE,
        "temporarily_unavailable",
        "the request could not be completed",
    )
}

fn body_error(status: StatusCode, code: &'static str) -> Response {
    let message = match status {
        StatusCode::REQUEST_TIMEOUT => "request body read timed out",
        StatusCode::BAD_REQUEST => "request body could not be read",
        _ => "request body exceeds the configured limit",
    };
    error_response(status, code, message)
}

fn error_response(status: StatusCode, code: &'static str, message: &'static str) -> Response {
    let mut response = (
        status,
        Json(crate::dto::ErrorHttpResponse {
            code,
            message: message.into(),
        }),
    )
        .into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::{to_bytes, Bytes},
        routing::{get, post},
    };
    use http_body::{Body as HttpBody, Frame, SizeHint};
    use std::{
        io,
        pin::Pin,
        sync::Mutex,
        task::{Context, Poll},
    };
    use tower::ServiceExt;

    #[derive(Default)]
    struct FakeAdmission {
        sources: Mutex<Vec<Vec<u8>>>,
        accounts: Mutex<Vec<String>>,
        source_result: Mutex<Option<AdmissionRejection>>,
        account_result: Mutex<Option<AdmissionRejection>>,
    }

    impl AbuseAdmission for FakeAdmission {
        fn admit_source(&self, source: &[u8]) -> Result<(), AdmissionRejection> {
            self.sources.lock().unwrap().push(source.to_vec());
            match *self.source_result.lock().unwrap() {
                Some(rejection) => Err(rejection),
                None => Ok(()),
            }
        }

        fn admit_account(&self, account: &str) -> Result<(), AdmissionRejection> {
            self.accounts.lock().unwrap().push(account.to_owned());
            match *self.account_result.lock().unwrap() {
                Some(rejection) => Err(rejection),
                None => Ok(()),
            }
        }
    }

    fn app_with(admission: Arc<FakeAdmission>, router: Router) -> Router {
        with_abuse_admission(router, admission)
    }

    fn request(method: Method, uri: &str, body: impl Into<Body>) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(uri)
            .body(body.into())
            .unwrap()
    }

    fn with_peer(mut request: Request<Body>, peer: SocketAddr) -> Request<Body> {
        request.extensions_mut().insert(ConnectInfo(peer));
        request
    }

    fn with_trusted_source(mut request: Request<Body>, source: &[u8]) -> Request<Body> {
        request
            .extensions_mut()
            .insert(TrustedRequestSource::from_bytes(source.to_vec()).unwrap());
        request
    }

    struct PendingBody;

    impl HttpBody for PendingBody {
        type Data = Bytes;
        type Error = io::Error;

        fn poll_frame(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
            Poll::Pending
        }

        fn is_end_stream(&self) -> bool {
            false
        }

        fn size_hint(&self) -> SizeHint {
            SizeHint::default()
        }
    }

    struct ErrorBody;

    impl HttpBody for ErrorBody {
        type Data = Bytes;
        type Error = io::Error;

        fn poll_frame(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
            Poll::Ready(Some(Err(io::Error::other("synthetic body read failure"))))
        }

        fn is_end_stream(&self) -> bool {
            false
        }

        fn size_hint(&self) -> SizeHint {
            SizeHint::default()
        }
    }

    #[tokio::test]
    async fn source_uses_peer_ip_ignores_forwarded_headers_and_fails_closed_without_peer() {
        let admission = Arc::new(FakeAdmission::default());
        let app = app_with(
            admission.clone(),
            Router::new().route("/write", post(|| async { StatusCode::OK })),
        );
        let peer_a: SocketAddr = "192.0.2.10:41000".parse().unwrap();
        let peer_b: SocketAddr = "192.0.2.10:42000".parse().unwrap();
        for peer in [peer_a, peer_b] {
            let mut request = with_peer(request(Method::POST, "/write", Body::empty()), peer);
            request
                .headers_mut()
                .insert("x-forwarded-for", HeaderValue::from_static("203.0.113.99"));
            let response = app.clone().oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
        }
        let sources = admission.sources.lock().unwrap();
        assert_eq!(sources.len(), 2);
        assert_eq!(sources[0], vec![4, 192, 0, 2, 10]);
        assert_eq!(sources[0], sources[1]);
        drop(sources);

        let missing = app
            .clone()
            .oneshot(request(Method::POST, "/write", Body::empty()))
            .await
            .unwrap();
        assert_eq!(missing.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(admission.sources.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn trusted_source_extension_overrides_connect_info_without_header_parsing() {
        let admission = Arc::new(FakeAdmission::default());
        let app = app_with(
            admission.clone(),
            Router::new().route("/write", post(|| async { StatusCode::OK })),
        );
        let mut request = with_peer(
            request(Method::POST, "/write", Body::empty()),
            "192.0.2.1:1".parse().unwrap(),
        );
        request
            .headers_mut()
            .insert("x-forwarded-for", HeaderValue::from_static("203.0.113.4"));
        let request = with_trusted_source(request, b"trusted-proxy-client");
        assert_eq!(app.oneshot(request).await.unwrap().status(), StatusCode::OK);
        assert_eq!(
            admission.sources.lock().unwrap().as_slice(),
            &[b"trusted-proxy-client".to_vec()]
        );
        assert!(TrustedRequestSource::from_bytes(Vec::new()).is_err());
        assert!(TrustedRequestSource::from_bytes(vec![0; 257]).is_err());
    }

    #[tokio::test]
    async fn account_email_is_extracted_but_original_bytes_reach_handler() {
        let admission = Arc::new(FakeAdmission::default());
        let app = app_with(
            admission.clone(),
            Router::new().route(
                "/auth/register",
                post(|request: Request<Body>| async move {
                    let bytes = to_bytes(request.into_body(), usize::MAX).await.unwrap();
                    Response::new(Body::from(bytes))
                }),
            ),
        );
        let body = br#"{ "email" : "Person@example.test", "unknown": 1 }"#;
        let response = app
            .oneshot(with_peer(
                request(Method::POST, "/auth/register", Body::from(body.to_vec())),
                "192.0.2.4:80".parse().unwrap(),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            to_bytes(response.into_body(), usize::MAX).await.unwrap(),
            body.as_slice()
        );
        assert_eq!(
            admission.accounts.lock().unwrap().as_slice(),
            &["Person@example.test".to_owned()]
        );
    }

    #[tokio::test]
    async fn duplicate_email_is_forwarded_without_account_charge() {
        let admission = Arc::new(FakeAdmission::default());
        let app = app_with(
            admission.clone(),
            Router::new().route(
                "/auth/login",
                post(|request: Request<Body>| async move {
                    let bytes = to_bytes(request.into_body(), usize::MAX).await.unwrap();
                    Response::new(Body::from(bytes))
                }),
            ),
        );
        let body = br#"{"email":"one@example.test","email":"two@example.test"}"#;
        let response = app
            .oneshot(with_peer(
                request(Method::POST, "/auth/login", Body::from(body.to_vec())),
                "192.0.2.5:80".parse().unwrap(),
            ))
            .await
            .unwrap();
        assert_eq!(
            to_bytes(response.into_body(), usize::MAX).await.unwrap(),
            body.as_slice()
        );
        assert!(admission.accounts.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn other_write_routes_keep_large_bodies_and_reads_skip_admission() {
        let admission = Arc::new(FakeAdmission::default());
        let app = app_with(
            admission.clone(),
            Router::new()
                .route(
                    "/admin/permissions",
                    post(|request: Request<Body>| async move {
                        let bytes = to_bytes(request.into_body(), usize::MAX).await.unwrap();
                        Response::new(Body::from(bytes))
                    }),
                )
                .route("/read", get(|| async { StatusCode::OK })),
        );
        let body = vec![b'x'; ACCOUNT_BODY_LIMIT + 1];
        let write = app
            .clone()
            .oneshot(with_peer(
                request(Method::POST, "/admin/permissions", Body::from(body.clone())),
                "192.0.2.6:80".parse().unwrap(),
            ))
            .await
            .unwrap();
        assert_eq!(write.status(), StatusCode::OK);
        assert_eq!(
            to_bytes(write.into_body(), usize::MAX).await.unwrap().len(),
            body.len()
        );
        assert!(admission.accounts.lock().unwrap().is_empty());

        assert_eq!(
            app.oneshot(request(Method::GET, "/read", Body::empty()))
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        assert_eq!(admission.sources.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn account_rejection_and_source_failure_have_generic_no_store_contracts() {
        let admission = Arc::new(FakeAdmission::default());
        *admission.account_result.lock().unwrap() = Some(AdmissionRejection::RateLimited);
        let app = app_with(
            admission.clone(),
            Router::new().route("/auth/login", post(|| async { StatusCode::OK })),
        );
        let response = app
            .clone()
            .oneshot(with_peer(
                request(
                    Method::POST,
                    "/auth/login",
                    Body::from(r#"{"email":"secret@example.test"}"#),
                ),
                "192.0.2.7:80".parse().unwrap(),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(response.headers()[header::RETRY_AFTER], "60");
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        let bytes = to_bytes(response.into_body(), 4096).await.unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()["code"],
            "rate_limited"
        );
        assert!(!String::from_utf8_lossy(&bytes).contains("secret@example.test"));

        *admission.source_result.lock().unwrap() = Some(AdmissionRejection::Unavailable);
        let response = app
            .oneshot(with_peer(
                request(Method::POST, "/auth/login", Body::empty()),
                "192.0.2.8:80".parse().unwrap(),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        let bytes = to_bytes(response.into_body(), 4096).await.unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()["code"],
            "temporarily_unavailable"
        );
    }

    #[tokio::test]
    async fn account_body_over_limit_is_rejected_before_handler() {
        let admission = Arc::new(FakeAdmission::default());
        let handler_called = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let called = handler_called.clone();
        let app = app_with(
            admission.clone(),
            Router::new().route(
                "/auth/register",
                post(move || {
                    let called = called.clone();
                    async move {
                        called.store(true, std::sync::atomic::Ordering::SeqCst);
                        StatusCode::OK
                    }
                }),
            ),
        );
        let response = app
            .oneshot(with_peer(
                request(
                    Method::POST,
                    "/auth/register",
                    Body::from(vec![b'x'; ACCOUNT_BODY_LIMIT + 1]),
                ),
                "192.0.2.9:80".parse().unwrap(),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert!(!handler_called.load(std::sync::atomic::Ordering::SeqCst));
        assert!(admission.accounts.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn account_body_transport_error_is_bad_request_not_too_large() {
        let admission = Arc::new(FakeAdmission::default());
        let app = app_with(
            admission.clone(),
            Router::new().route("/auth/login", post(|| async { StatusCode::OK })),
        );
        let response = app
            .oneshot(with_peer(
                request(Method::POST, "/auth/login", Body::new(ErrorBody)),
                "192.0.2.11:80".parse().unwrap(),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        let bytes = to_bytes(response.into_body(), 4096).await.unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()["code"],
            "invalid_request_body"
        );
        assert!(admission.accounts.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn account_body_read_deadline_returns_408() {
        let admission = Arc::new(FakeAdmission::default());
        let app = app_with(
            admission.clone(),
            Router::new().route("/auth/login", post(|| async { StatusCode::OK })),
        );
        let response = tokio::time::timeout(
            Duration::from_secs(ACCOUNT_BODY_DEADLINE.as_secs() + 2),
            app.oneshot(with_peer(
                request(Method::POST, "/auth/login", Body::new(PendingBody)),
                "192.0.2.12:80".parse().unwrap(),
            )),
        )
        .await
        .expect("middleware body deadline")
        .unwrap();
        assert_eq!(response.status(), StatusCode::REQUEST_TIMEOUT);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        let bytes = to_bytes(response.into_body(), 4096).await.unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()["code"],
            "request_timeout"
        );
        assert!(admission.accounts.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn recovery_start_charges_email_before_browser_origin_guard_but_complete_and_result_only_charge_source(
    ) {
        let admission = Arc::new(FakeAdmission::default());
        let app = app_with(
            admission.clone(),
            Router::new()
                .route(
                    "/one/auth/password-recovery/start",
                    post(|| async { StatusCode::OK }),
                )
                .route(
                    "/identity/admin/auth/browser/password-recovery/start",
                    post(|request: Request<Body>| async move {
                        if request
                            .headers()
                            .get(header::ORIGIN)
                            .and_then(|value| value.to_str().ok())
                            == Some("https://wrong-origin.example")
                        {
                            StatusCode::FORBIDDEN
                        } else {
                            StatusCode::OK
                        }
                    }),
                )
                .route(
                    "/two/auth/password-recovery/complete",
                    post(|| async { StatusCode::OK }),
                )
                .route(
                    "/identity/admin/auth/password-recovery/result",
                    post(|| async { StatusCode::OK }),
                ),
        );
        let email = "Person@example.test";
        let email_body = Body::from(serde_json::json!({"email":email}).to_string());
        let start = app
            .clone()
            .oneshot(with_peer(
                request(
                    Method::POST,
                    "/one/auth/password-recovery/start",
                    email_body,
                ),
                "192.0.2.31:80".parse().unwrap(),
            ))
            .await
            .unwrap();
        assert_eq!(start.status(), StatusCode::OK);
        assert_eq!(
            admission.accounts.lock().unwrap().as_slice(),
            &[email.to_owned()]
        );

        let mut browser_request = request(
            Method::POST,
            "/identity/admin/auth/browser/password-recovery/start",
            Body::from(serde_json::json!({"email":email}).to_string()),
        );
        browser_request.headers_mut().insert(
            header::ORIGIN,
            HeaderValue::from_static("https://wrong-origin.example"),
        );
        let rejected_browser = app
            .clone()
            .oneshot(with_peer(browser_request, "192.0.2.31:80".parse().unwrap()))
            .await
            .unwrap();
        assert_eq!(rejected_browser.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            admission.accounts.lock().unwrap().as_slice(),
            &[email.to_owned(), email.to_owned()]
        );

        for path in [
            "/two/auth/password-recovery/complete",
            "/identity/admin/auth/password-recovery/result",
        ] {
            let response = app
                .clone()
                .oneshot(with_peer(
                    request(
                        Method::POST,
                        path,
                        Body::from(r#"{"operation_id":"synthetic","receipt_secret":"synthetic"}"#),
                    ),
                    "192.0.2.31:80".parse().unwrap(),
                ))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK, "{path}");
            assert_eq!(
                admission.accounts.lock().unwrap().as_slice(),
                &[email.to_owned(), email.to_owned()],
                "{path} does not consume an email-account budget"
            );
        }
        assert_eq!(admission.sources.lock().unwrap().len(), 4);
    }

    #[test]
    fn mapped_ipv6_and_ipv4_use_one_source_budget_key() {
        assert_eq!(
            socket_source("127.0.0.1:80".parse().unwrap()),
            socket_source("[::ffff:127.0.0.1]:9000".parse().unwrap())
        );
        assert_ne!(
            socket_source("[::1]:80".parse().unwrap()),
            socket_source("127.0.0.1:80".parse().unwrap())
        );
    }
}
