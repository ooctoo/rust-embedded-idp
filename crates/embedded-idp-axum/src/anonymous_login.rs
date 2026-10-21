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
    if request.method() != axum::http::Method::POST || !request.uri().path().ends_with("/login") {
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
