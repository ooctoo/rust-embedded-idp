use axum::extract::{Path as AxumPath, State};
use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE};
use axum::http::{HeaderValue, StatusCode};
use axum::response::Redirect;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use embedded_idp_axum::BrowserSessionClientConfig;

include!(concat!(env!("OUT_DIR"), "/management_assets.rs"));

#[derive(Clone)]
struct AdminUiState {
    asset_prefix: String,
    browser_config: BrowserSessionClientConfig,
}

pub fn admin_console_router(base_path: &str, browser_config: BrowserSessionClientConfig) -> Router {
    let asset_prefix = if base_path == "/" {
        "/assets".to_string()
    } else {
        format!("{base_path}/assets")
    };
    let state = AdminUiState {
        asset_prefix: asset_prefix.clone(),
        browser_config,
    };
    let assets_route = format!("{asset_prefix}/*path");
    let router = Router::new().route(&assets_route, get(asset));

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
    let html = asset_bytes("index.html").expect("management distribution must contain index.html");
    let html =
        String::from_utf8_lossy(html).replace("./assets/", &format!("{}/", state.asset_prefix));
    let html = html.replace(
        "</head>",
        &format!("{}</head>", browser_config_meta(&state.browser_config)),
    );
    static_response("text/html; charset=utf-8", html.into_bytes())
}

/// Only a server-derived, non-sensitive typed descriptor enters the HTML.
pub(crate) fn browser_config_meta(config: &BrowserSessionClientConfig) -> String {
    let value = serde_json::to_string(config)
        .expect("browser configuration serializes")
        .replace('&', "&amp;")
        .replace('"', "&quot;")
        .replace('<', "&lt;")
        .replace('>', "&gt;");
    format!("<meta name=\"idp-browser-config\" content=\"{value}\">")
}

async fn asset(AxumPath(path): AxumPath<String>) -> Response {
    if !valid_asset_path(&path) {
        return StatusCode::NOT_FOUND.into_response();
    }
    let Some(bytes) = asset_bytes(&format!("assets/{path}")) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    static_response(content_type(&path), bytes.to_vec())
}

fn asset_bytes(path: &str) -> Option<&'static [u8]> {
    MANAGEMENT_ASSETS
        .iter()
        .find_map(|(name, bytes)| (*name == path).then_some(*bytes))
}

fn valid_asset_path(path: &str) -> bool {
    !path.is_empty()
        && !path.starts_with('/')
        && !path.contains('\\')
        && path
            .split('/')
            .all(|segment| !segment.is_empty() && segment != "." && segment != "..")
}

fn content_type(path: &str) -> &'static str {
    match path.rsplit('.').next() {
        Some("css") => "text/css; charset=utf-8",
        Some("js") => "application/javascript; charset=utf-8",
        Some("json") => "application/json; charset=utf-8",
        Some("svg") => "image/svg+xml",
        Some("woff") => "font/woff",
        Some("woff2") => "font/woff2",
        Some("png") => "image/png",
        Some("jpg") | Some("jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        _ => "application/octet-stream",
    }
}

fn static_response(content_type: &'static str, body: Vec<u8>) -> Response {
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
    use axum::body::Body;
    use axum::extract::State;
    use axum::http::{header::CONTENT_TYPE, Request, StatusCode};
    use tower::ServiceExt;

    use super::{admin_console_router, index, valid_asset_path, AdminUiState, MANAGEMENT_ASSETS};

    fn full_config() -> embedded_idp_axum::BrowserSessionClientConfig {
        embedded_idp_axum::BrowserSessionHttpConfig::new(
            "http://localhost",
            "test",
            "/admin/auth/browser",
            embedded_idp_core::AccessTokenPurpose::Management,
        )
        .unwrap()
        .client_config()
    }

    #[tokio::test]
    async fn index_serves_management_html_with_hashed_assets() {
        let response = index(State(AdminUiState {
            asset_prefix: "/assets".to_string(),
            browser_config: full_config(),
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

        assert!(html.contains("身份管理控制台"));
        assert!(html.contains("/assets/index-"));
        assert!(html.contains(".js"));
        assert!(html.contains("/api"));
    }

    #[test]
    fn asset_paths_reject_traversal() {
        assert!(valid_asset_path("assets/index.js"));
        assert!(!valid_asset_path("../index.html"));
        assert!(!valid_asset_path("assets/../index.html"));
        assert!(!valid_asset_path("assets\\index.js"));
    }

    #[tokio::test]
    async fn router_serves_root_management_assets_and_rejects_unknown_paths() {
        let app = admin_console_router("/", full_config());
        let response = app
            .clone()
            .oneshot(Request::get("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let role_asset = MANAGEMENT_ASSETS
            .iter()
            .find(|(name, _)| name.starts_with("assets/roles-") && name.ends_with(".js"))
            .expect("role chunk")
            .0;
        let response = app
            .clone()
            .oneshot(
                Request::get(format!("/{role_asset}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let response = app
            .oneshot(Request::get("/assets/nope.js").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn router_preserves_nested_base_redirect_and_assets() {
        let app = admin_console_router("/admin", full_config());
        let response = app
            .clone()
            .oneshot(Request::get("/admin").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::PERMANENT_REDIRECT);
        assert_eq!(response.headers().get("location").unwrap(), "/admin/");

        let entry_asset = MANAGEMENT_ASSETS
            .iter()
            .find(|(name, _)| name.starts_with("assets/index-") && name.ends_with(".js"))
            .expect("entry chunk")
            .0;
        let response = app
            .oneshot(
                Request::get(format!("/admin/{entry_asset}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
}
