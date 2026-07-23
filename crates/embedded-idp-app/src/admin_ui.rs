use axum::extract::State;
use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE};
use axum::http::{HeaderValue, StatusCode};
use axum::response::Redirect;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;

const ADMIN_CONSOLE_INDEX: &str = include_str!("../../../web/dist/index.html");
const ADMIN_CONSOLE_CSS: &str = include_str!("../../../web/dist/assets/admin-app.css");
const ADMIN_CONSOLE_JS: &str = include_str!("../../../web/dist/assets/admin-app.js");

#[derive(Clone)]
struct AdminUiState {
    static_prefix: String,
}

pub fn admin_console_router(base_path: &str) -> Router {
    let static_prefix = if base_path == "/" {
        "/static".to_string()
    } else {
        format!("{base_path}/static")
    };
    let state = AdminUiState {
        static_prefix: static_prefix.clone(),
    };
    let router = Router::new()
        .route(&format!("{static_prefix}/admin-app.css"), get(css))
        .route(&format!("{static_prefix}/admin-app.js"), get(js));

    if base_path == "/" {
        router.route("/", get(index))
    } else {
        let with_slash = format!("{base_path}/");
        let redirect_target = with_slash.clone();
        router
            .route(
                base_path,
                get(move || async move { Redirect::permanent(&redirect_target) }),
            )
            .route(&with_slash, get(index))
    }
    .with_state(state)
}

async fn index(State(state): State<AdminUiState>) -> Response {
    static_response(
        "text/html; charset=utf-8",
        ADMIN_CONSOLE_INDEX
            .replace(
                "./assets/admin-app.js",
                &format!("{}/admin-app.js", state.static_prefix),
            )
            .replace(
                "./assets/admin-app.css",
                &format!("{}/admin-app.css", state.static_prefix),
            ),
    )
}

async fn css() -> Response {
    static_response("text/css; charset=utf-8", ADMIN_CONSOLE_CSS.to_string())
}

async fn js() -> Response {
    static_response(
        "application/javascript; charset=utf-8",
        ADMIN_CONSOLE_JS.to_string(),
    )
}

fn static_response(content_type: &'static str, body: String) -> Response {
    let mut response = (StatusCode::OK, body).into_response();
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static(content_type));
    response.headers_mut().insert(
        CACHE_CONTROL,
        HeaderValue::from_static("no-store, max-age=0"),
    );
    response
}

#[cfg(test)]
mod tests {
    use axum::body::to_bytes;
    use axum::extract::State;
    use axum::http::header::CONTENT_TYPE;

    use super::{index, AdminUiState};

    #[tokio::test]
    async fn index_serves_built_html_shell() {
        let response = index(State(AdminUiState {
            static_prefix: "/static".to_string(),
        }))
        .await;

        assert_eq!(
            response
                .headers()
                .get(CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("text/html; charset=utf-8")
        );

        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body should collect");
        let html = String::from_utf8(body.to_vec()).expect("body should be utf-8");

        assert!(html.contains("Embedded IDP Admin"));
        assert!(html.contains("/static/admin-app.js"));
    }
}
