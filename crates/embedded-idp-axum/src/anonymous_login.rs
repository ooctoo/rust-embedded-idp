use axum::{
    extract::{Request, State},
    http::{header, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    Json, Router,
};
use serde_json::json;
use std::sync::Arc;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::Instant;

#[derive(Clone)]
pub struct AnonymousLoginBudget(Arc<Semaphore>);
impl Default for AnonymousLoginBudget {
    fn default() -> Self {
        Self(Arc::new(Semaphore::new(8)))
    }
}
tokio::task_local! {static LOGIN_HOLDS:Vec<Arc<OwnedSemaphorePermit>>;}
pub(crate) fn physical_holds() -> Vec<Arc<OwnedSemaphorePermit>> {
    LOGIN_HOLDS.try_with(Clone::clone).unwrap_or_default()
}
/// The trusted Host wraps its complete merged router with one shared budget.
/// Existing independent routers also get a local bound; nested permits are all
/// retained by the physical blocking call if the HTTP caller cancels.
pub fn with_anonymous_login_budget(router: Router, budget: AnonymousLoginBudget) -> Router {
    router.layer(middleware::from_fn_with_state(budget, admit))
}
pub(crate) async fn admit(
    State(budget): State<AnonymousLoginBudget>,
    request: Request,
    next: Next,
) -> Response {
    if request.method() != axum::http::Method::POST || !uses_anonymous_budget(request.uri().path())
    {
        return next.run(request).await;
    }
    let start = Instant::now();
    let Ok(permit) = budget.0.clone().try_acquire_owned() else {
        return reject();
    };
    let mut holds = physical_holds();
    holds.push(Arc::new(permit));
    LOGIN_HOLDS
        .scope(holds, async move {
            let mut response = next.run(request).await;
            if !response.status().is_success() {
                crate::anonymous_response_delay(start).await;
            }
            response
                .headers_mut()
                .insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
            response
        })
        .await
}
fn uses_anonymous_budget(path: &str) -> bool {
    [
        "/login",
        "/password-recovery/start",
        "/password-recovery/complete",
        "/password-recovery/result",
    ]
    .iter()
    .any(|suffix| path.ends_with(suffix))
}

#[cfg(test)]
mod path_tests {
    use super::uses_anonymous_budget;

    #[test]
    fn shared_budget_covers_each_recovery_post_path_under_host_prefixes() {
        for path in [
            "/auth/password-recovery/start",
            "/admin/auth/password-recovery/complete",
            "/mount/auth/browser/password-recovery/result",
        ] {
            assert!(uses_anonymous_budget(path), "{path}");
        }
        assert!(!uses_anonymous_budget("/auth/password-recovery/status"));
    }
}
fn reject() -> Response {
    let mut r = (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(json!({"error":{"code":"temporarily_unavailable"}})),
    )
        .into_response();
    r.headers_mut()
        .insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    r
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        extract::State,
        http::Request,
        routing::{get, post},
    };
    use std::sync::mpsc;
    use tokio::{sync::Notify, time::Duration};
    use tower::ServiceExt;

    #[derive(Default)]
    struct RequestGate {
        entered: Notify,
        release: Notify,
    }

    async fn gated_login(State(gate): State<Arc<RequestGate>>) -> StatusCode {
        gate.entered.notify_one();
        gate.release.notified().await;
        StatusCode::OK
    }

    #[tokio::test]
    async fn outer_budget_is_shared_across_prefixes_and_does_not_limit_reads() {
        let gate = Arc::new(RequestGate::default());
        let router = Router::new()
            .route("/one/login", post(gated_login))
            .route("/two/login", post(|| async { StatusCode::OK }))
            .route("/read", get(|| async { StatusCode::OK }))
            .with_state(gate.clone());
        let router =
            with_anonymous_login_budget(router, AnonymousLoginBudget(Arc::new(Semaphore::new(1))));

        let first_router = router.clone();
        let first = tokio::spawn(async move {
            first_router
                .oneshot(Request::post("/one/login").body(Body::empty()).unwrap())
                .await
                .unwrap()
        });
        tokio::time::timeout(Duration::from_secs(2), gate.entered.notified())
            .await
            .expect("first login entered");

        let saturated = tokio::time::timeout(
            Duration::from_secs(2),
            router
                .clone()
                .oneshot(Request::post("/two/login").body(Body::empty()).unwrap()),
        )
        .await
        .expect("saturated login returned")
        .unwrap();
        assert_eq!(saturated.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(saturated.headers()[header::CACHE_CONTROL], "no-store");

        let read = tokio::time::timeout(
            Duration::from_secs(2),
            router
                .clone()
                .oneshot(Request::get("/read").body(Body::empty()).unwrap()),
        )
        .await
        .expect("read returned")
        .unwrap();
        assert_eq!(read.status(), StatusCode::OK);

        gate.release.notify_one();
        assert_eq!(first.await.unwrap().status(), StatusCode::OK);
        let recovered = tokio::time::timeout(
            Duration::from_secs(2),
            router.oneshot(Request::post("/two/login").body(Body::empty()).unwrap()),
        )
        .await
        .expect("login recovered after release")
        .unwrap();
        assert_eq!(recovered.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn cancelled_http_call_keeps_budget_until_blocking_work_finishes() {
        let (release_tx, release_rx) = mpsc::channel();
        let release_rx = Arc::new(std::sync::Mutex::new(Some(release_rx)));
        let entered = Arc::new(Notify::new());
        let finished = Arc::new(Notify::new());
        let entered_call = entered.clone();
        let finished_call = finished.clone();
        let router = Router::new()
            .route(
                "/auth/password-recovery/start",
                post(move || {
                    let release_rx = release_rx.clone();
                    let entered = entered_call.clone();
                    let finished = finished_call.clone();
                    async move {
                        crate::tenant_auth::call(move || {
                            entered.notify_one();
                            if let Some(release_rx) = release_rx.lock().unwrap().take() {
                                release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
                                finished.notify_one();
                            }
                            Ok::<_, embedded_idp_core::StoreError>(())
                        })
                        .await
                        .unwrap();
                        StatusCode::OK
                    }
                }),
            )
            .route(
                "/admin/auth/browser/password-recovery/result",
                post(|| async { StatusCode::OK }),
            );
        let budget = AnonymousLoginBudget(Arc::new(Semaphore::new(1)));
        let router = with_anonymous_login_budget(router, budget.clone());

        let request_router = router.clone();
        let request = tokio::spawn(async move {
            request_router
                .oneshot(
                    Request::post("/auth/password-recovery/start")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
        });
        tokio::time::timeout(Duration::from_secs(2), entered.notified())
            .await
            .expect("blocking work entered");
        request.abort();
        assert!(request.await.unwrap_err().is_cancelled());

        let saturated = tokio::time::timeout(
            Duration::from_secs(2),
            router.clone().oneshot(
                Request::post("/admin/auth/browser/password-recovery/result")
                    .body(Body::empty())
                    .unwrap(),
            ),
        )
        .await
        .expect("saturated login returned")
        .unwrap();
        assert_eq!(saturated.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(saturated.headers()[header::CACHE_CONTROL], "no-store");

        let wait_finished = finished.notified();
        release_tx.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(2), wait_finished)
            .await
            .expect("blocking work finished");
        tokio::time::timeout(Duration::from_secs(2), async {
            while budget.0.available_permits() != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("physical permit released");

        let recovered = tokio::time::timeout(
            Duration::from_secs(2),
            router.oneshot(
                Request::post("/admin/auth/browser/password-recovery/result")
                    .body(Body::empty())
                    .unwrap(),
            ),
        )
        .await
        .expect("login recovered after physical work finished")
        .unwrap();
        assert_eq!(recovered.status(), StatusCode::OK);
    }
}
