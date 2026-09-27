use std::{sync::Arc, time::Duration};

use axum::{
    extract::{Path, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use embedded_idp_core::{
    access::{
        AccessActor, AccessDecision, AccessError, AccessQuery, AuthorizationService,
        TenantAuthError, TenantAuthenticationService,
    },
    SecretString,
};
use postgres::{Client, NoTls};
use serde::Serialize;
use serde_json::json;

#[derive(Clone)]
pub struct ReportStore {
    uri: String,
    schema: String,
}

#[derive(Serialize)]
pub struct Report {
    tenant_id: String,
    report_id: String,
    title: String,
    body: String,
}

pub fn valid_report_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
}

impl ReportStore {
    pub fn new(uri: String, schema: String) -> Self {
        Self { uri, schema }
    }

    fn connect(&self) -> Result<Client, String> {
        let mut config: postgres::Config = self
            .uri
            .parse()
            .map_err(|_| "invalid business database URI")?;
        config.connect_timeout(Duration::from_secs(5));
        config
            .connect(NoTls)
            .map_err(|_| "business database unavailable".into())
    }

    pub fn init(&self) -> Result<(), String> {
        let mut client = self.connect()?;
        client.batch_execute(&format!(
            "create schema if not exists {}; \
             create table if not exists {}.reports ( \
               tenant_id text not null, report_id text not null, title text not null, body text not null, \
               primary key (tenant_id, report_id))",
            self.schema, self.schema
        )).map_err(|_| "could not initialize business report schema".to_string())
    }

    pub fn ready(&self) -> Result<(), String> {
        let mut client = self.connect()?;
        client
            .query(
                &format!(
                    "select tenant_id, report_id, title, body from {}.reports limit 0",
                    self.schema
                ),
                &[],
            )
            .map_err(|_| "business report table is missing or incompatible".to_string())?;
        Ok(())
    }

    pub fn seed(&self, tenant: &str, id: &str, title: &str) -> Result<(), String> {
        if !valid_report_id(id) || title.trim().is_empty() || title.len() > 200 {
            return Err("invalid report ID or title".into());
        }
        let mut client = self.connect()?;
        client.execute(&format!(
            "insert into {}.reports (tenant_id, report_id, title, body) values ($1,$2,$3,$4) \
             on conflict (tenant_id, report_id) do update set title=excluded.title, body=excluded.body",
            self.schema
        ), &[&tenant, &id, &title, &format!("Example report {id} in tenant {tenant}.")])
            .map_err(|_| "could not seed business report".to_string())?;
        Ok(())
    }

    fn get(&self, tenant: &str, id: &str) -> Result<Option<Report>, String> {
        let mut client = self.connect()?;
        client
            .query_opt(
                &format!(
                    "select title, body from {}.reports where tenant_id=$1 and report_id=$2",
                    self.schema
                ),
                &[&tenant, &id],
            )
            .map(|row| {
                row.map(|row| Report {
                    tenant_id: tenant.into(),
                    report_id: id.into(),
                    title: row.get(0),
                    body: row.get(1),
                })
            })
            .map_err(|_| "business report read failed".into())
    }
}

#[derive(Clone)]
pub struct ReportState {
    pub business_id: String,
    pub authentication: Arc<dyn TenantAuthenticationService>,
    pub authorization: Arc<dyn AuthorizationService>,
    pub store: ReportStore,
}

pub fn router(state: ReportState) -> Router {
    Router::new()
        .route("/api/reports/:id", get(read_report))
        .with_state(state)
}

fn bearer(headers: &HeaderMap) -> Option<String> {
    if headers.contains_key("x-embedded-idp-tenant-id")
        || headers.contains_key("x-embedded-idp-business-id")
    {
        return None;
    }
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let value = values.next()?.to_str().ok()?;
    if values.next().is_some() {
        return None;
    }
    let (scheme, token) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer")
        || token.is_empty()
        || token.len() > 16_384
        || token.contains(char::is_whitespace)
    {
        return None;
    }
    Some(token.into())
}

fn authorized(
    actor: &AccessActor,
    business_id: &str,
    id: &str,
    service: &dyn AuthorizationService,
) -> Result<bool, StatusCode> {
    service
        .check(AccessQuery {
            tenant_id: actor.tenant_id.clone(),
            business_id: business_id.into(),
            subject_id: actor.subject_id.clone(),
            resource_type: "report".into(),
            action: "read".into(),
            resource_id: Some(id.into()),
        })
        .map(|decision| decision == AccessDecision::Allow)
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)
}

fn authentication_status(error: TenantAuthError) -> StatusCode {
    match error {
        TenantAuthError::Store(_) | TenantAuthError::Access(AccessError::Store(_)) => {
            StatusCode::SERVICE_UNAVAILABLE
        }
        _ => StatusCode::UNAUTHORIZED,
    }
}

async fn read_report(
    State(state): State<ReportState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let result = if !valid_report_id(&id) {
        Err(StatusCode::BAD_REQUEST)
    } else if let Some(token) = bearer(&headers) {
        tokio::task::spawn_blocking(move || {
            let actor = state
                .authentication
                .authenticate(SecretString::new(token))
                .map_err(authentication_status)?;
            if !authorized(
                &actor,
                &state.business_id,
                &id,
                state.authorization.as_ref(),
            )? {
                return Err(StatusCode::FORBIDDEN);
            }
            state
                .store
                .get(&actor.tenant_id, &id)
                .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
                .ok_or(StatusCode::NOT_FOUND)
        })
        .await
        .unwrap_or(Err(StatusCode::SERVICE_UNAVAILABLE))
    } else {
        Err(StatusCode::UNAUTHORIZED)
    };
    let mut response = match result {
        Ok(report) => Json(json!(report)).into_response(),
        Err(code) => (
            code,
            Json(json!({"error": match code {
                StatusCode::BAD_REQUEST => "invalid_report_id",
                StatusCode::UNAUTHORIZED => "unauthorized",
                StatusCode::FORBIDDEN => "forbidden",
                StatusCode::NOT_FOUND => "not_found",
                _ => "unavailable",
            }})),
        )
            .into_response(),
    };
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

pub async fn index() -> Response {
    file("index.html", "text/html; charset=utf-8").await
}

pub async fn asset(Path(name): Path<String>) -> Response {
    if name.is_empty()
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
    {
        return StatusCode::NOT_FOUND.into_response();
    }
    let content_type = if name.ends_with(".js") {
        "text/javascript; charset=utf-8"
    } else if name.ends_with(".css") {
        "text/css; charset=utf-8"
    } else {
        return StatusCode::NOT_FOUND.into_response();
    };
    file(&format!("assets/{name}"), content_type).await
}

async fn file(name: &str, content_type: &'static str) -> Response {
    let path = format!("{}/dist/{name}", env!("CARGO_MANIFEST_DIR"));
    match tokio::fs::read(path).await {
        Ok(bytes) => ([(header::CONTENT_TYPE, content_type)], bytes).into_response(),
        Err(_)
            if name != "index.html"
                && tokio::fs::metadata(format!(
                    "{}/dist/index.html",
                    env!("CARGO_MANIFEST_DIR")
                ))
                .await
                .is_ok() =>
        {
            StatusCode::NOT_FOUND.into_response()
        }
        Err(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            "build the no-tenant-host Web app first",
        )
            .into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use embedded_idp_core::access::{AccessDecision, AccessError, BatchAccessQuery};
    use std::sync::Mutex;

    struct Spy(Mutex<Option<AccessQuery>>);
    impl AuthorizationService for Spy {
        fn check(&self, query: AccessQuery) -> Result<AccessDecision, AccessError> {
            *self.0.lock().unwrap() = Some(query);
            Ok(AccessDecision::Allow)
        }
        fn check_many(&self, _: BatchAccessQuery) -> Result<Vec<AccessDecision>, AccessError> {
            unreachable!()
        }
    }

    #[test]
    fn report_authorization_uses_authenticated_tenant_subject_and_exact_id() {
        let service = Spy(Mutex::new(None));
        let actor = AccessActor {
            tenant_id: "t1".into(),
            subject_id: "user1".into(),
            session_id: "session1".into(),
        };
        assert_eq!(authorized(&actor, "reports", "r001", &service), Ok(true));
        assert_eq!(
            *service.0.lock().unwrap(),
            Some(AccessQuery {
                tenant_id: "t1".into(),
                business_id: "reports".into(),
                subject_id: "user1".into(),
                resource_type: "report".into(),
                action: "read".into(),
                resource_id: Some("r001".into()),
            })
        );
        assert!(!valid_report_id("t1/r001"));
    }

    #[test]
    fn bearer_rejects_ambiguous_credentials_and_caller_tenant() {
        let mut headers = HeaderMap::new();
        headers.append(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer token"),
        );
        assert_eq!(bearer(&headers).as_deref(), Some("token"));
        headers.append(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer other"),
        );
        assert!(bearer(&headers).is_none());
        headers.remove(header::AUTHORIZATION);
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer token"),
        );
        headers.insert("x-embedded-idp-tenant-id", HeaderValue::from_static("t2"));
        assert!(bearer(&headers).is_none());
    }

    #[test]
    fn authentication_outage_is_not_reported_as_invalid_credentials() {
        assert_eq!(
            authentication_status(TenantAuthError::InvalidSession),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            authentication_status(TenantAuthError::Store(
                embedded_idp_core::StoreError::Backend("unavailable".into())
            )),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }
}
