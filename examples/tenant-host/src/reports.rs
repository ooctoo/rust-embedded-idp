use std::{sync::Arc, time::Duration};

use axum::{
    extract::{Path, Query, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use base64ct::{Base64UrlUnpadded, Encoding};
use embedded_idp_core::{
    access::{
        AccessActor, AccessDecision, AccessError, AccessQuery, AuthorizationService,
        BatchAccessQuery, TenantAuthError, TenantAuthenticationService,
    },
    SecretString,
};
use ring::hmac;
use serde::{Deserialize, Serialize};

const MAX_SCAN: usize = 40;
const MAX_PAGE: usize = 20;
const DEFAULT_PAGE: usize = 10;
const CURSOR_TTL_SECS: u64 = 15 * 60;
const MAX_CURSOR_BYTES: usize = 2048;

#[derive(Clone)]
pub struct ReportStore {
    uri: String,
    schema: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Report {
    pub tenant_id: String,
    pub report_id: String,
    pub title: String,
    pub body: String,
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

    fn connect(&self) -> Result<postgres::Client, String> {
        let mut config: postgres::Config = self
            .uri
            .parse()
            .map_err(|_| "invalid business database URI")?;
        config.connect_timeout(Duration::from_secs(5));
        config
            .connect(postgres::NoTls)
            .map_err(|_| "business database unavailable".into())
    }

    fn table(&self) -> String {
        format!("{}.reports", self.schema)
    }

    pub fn ready(&self) -> Result<(), String> {
        let mut client = self.connect()?;
        client
            .query(
                &format!(
                    "select tenant_id, report_id, title, body from {} limit 0",
                    self.table()
                ),
                &[],
            )
            .map_err(|_| "business report table is missing or incompatible".to_string())?;
        Ok(())
    }

    fn ids(&self, tenant: &str, prefix: &str, after: Option<&str>) -> Result<Vec<String>, String> {
        let mut client = self.connect()?;
        let query = format!(
            "select report_id from {} where tenant_id=$1 and left(report_id, length($2))=$2 \
             and ($3::text is null or report_id > $3) order by report_id asc limit $4",
            self.table()
        );
        client
            .query(
                &query,
                &[&tenant, &prefix, &after, &((MAX_SCAN + 1) as i64)],
            )
            .map(|rows| rows.into_iter().map(|row| row.get(0)).collect())
            .map_err(|_| "business report read failed".into())
    }

    fn get(&self, tenant: &str, id: &str) -> Result<Option<Report>, String> {
        let mut client = self.connect()?;
        client
            .query_opt(
                &format!(
                    "select title, body from {} where tenant_id=$1 and report_id=$2",
                    self.table()
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
    pub entry_id: String,
    pub authentication: Arc<dyn TenantAuthenticationService>,
    pub authorization: Arc<dyn AuthorizationService>,
    pub store: ReportStore,
    pub cursor_key: Arc<hmac::Key>,
}

pub fn router(state: ReportState) -> Router {
    Router::new()
        .route("/api/reports/:id", get(read_report))
        .route("/api/reports", get(list_reports))
        .with_state(state)
        .layer(middleware::from_fn(no_store))
}

async fn no_store(request: axum::extract::Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
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

fn auth_status(error: TenantAuthError) -> StatusCode {
    match error {
        TenantAuthError::Store(_) | TenantAuthError::Access(AccessError::Store(_)) => {
            StatusCode::SERVICE_UNAVAILABLE
        }
        _ => StatusCode::UNAUTHORIZED,
    }
}

async fn authenticate(state: &ReportState, headers: &HeaderMap) -> Result<AccessActor, StatusCode> {
    let token = bearer(headers).ok_or(StatusCode::UNAUTHORIZED)?;
    let service = state.authentication.clone();
    tokio::task::spawn_blocking(move || service.authenticate(SecretString::new(token)))
        .await
        .unwrap_or(Err(TenantAuthError::Store(
            embedded_idp_core::StoreError::Backend("authentication worker unavailable".into()),
        )))
        .map_err(auth_status)
}

fn allowed(actor: &AccessActor, state: &ReportState, id: &str) -> Result<bool, StatusCode> {
    state
        .authorization
        .check(AccessQuery {
            tenant_id: actor.tenant_id.clone(),
            business_id: state.business_id.clone(),
            subject_id: actor.subject_id.clone(),
            resource_type: "report".into(),
            action: "read".into(),
            resource_id: Some(id.into()),
        })
        .map(|decision| decision == AccessDecision::Allow)
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)
}

async fn read_report(
    State(state): State<ReportState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    if !valid_report_id(&id) {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let actor = match authenticate(&state, &headers).await {
        Ok(actor) => actor,
        Err(status) => return status.into_response(),
    };
    let check_actor = actor.clone();
    let check_state = state.clone();
    let check_id = id.clone();
    let decision =
        match tokio::task::spawn_blocking(move || allowed(&check_actor, &check_state, &check_id))
            .await
            .unwrap_or(Err(StatusCode::SERVICE_UNAVAILABLE))
        {
            Ok(value) => value,
            Err(status) => return status.into_response(),
        };
    if !decision {
        return StatusCode::FORBIDDEN.into_response();
    }
    let store = state.store.clone();
    let tenant = actor.tenant_id;
    let report = tokio::task::spawn_blocking(move || store.get(&tenant, &id))
        .await
        .unwrap_or(Err("report read failed".into()));
    match report {
        Ok(Some(value)) => Json(value).into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(_) => StatusCode::SERVICE_UNAVAILABLE.into_response(),
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ListQuery {
    limit: Option<usize>,
    cursor: Option<String>,
    prefix: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Cursor {
    version: u8,
    tenant_id: String,
    subject_id: String,
    session_id: String,
    business_id: String,
    entry_id: String,
    prefix: String,
    limit: usize,
    after: String,
    expires_at_unix_secs: u64,
}

fn now_secs() -> Result<u64, StatusCode> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)
}
fn valid_prefix(value: &str) -> bool {
    value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
}
fn encode_cursor(cursor: &Cursor, key: &hmac::Key) -> Result<String, StatusCode> {
    let payload = serde_json::to_vec(cursor).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let text = Base64UrlUnpadded::encode_string(&payload);
    let tag = hmac::sign(key, text.as_bytes());
    Ok(format!(
        "{text}.{}",
        Base64UrlUnpadded::encode_string(tag.as_ref())
    ))
}
fn decode_cursor(token: &str, key: &hmac::Key) -> Result<Cursor, StatusCode> {
    if token.is_empty() || token.len() > MAX_CURSOR_BYTES {
        return Err(StatusCode::BAD_REQUEST);
    }
    let (payload, signature) = token.split_once('.').ok_or(StatusCode::BAD_REQUEST)?;
    let sig = Base64UrlUnpadded::decode_vec(signature).map_err(|_| StatusCode::BAD_REQUEST)?;
    if Base64UrlUnpadded::encode_string(&sig) != signature {
        return Err(StatusCode::BAD_REQUEST);
    }
    let payload_bytes =
        Base64UrlUnpadded::decode_vec(payload).map_err(|_| StatusCode::BAD_REQUEST)?;
    if Base64UrlUnpadded::encode_string(&payload_bytes) != payload {
        return Err(StatusCode::BAD_REQUEST);
    }
    hmac::verify(key, payload.as_bytes(), &sig).map_err(|_| StatusCode::BAD_REQUEST)?;
    serde_json::from_slice(&payload_bytes).map_err(|_| StatusCode::BAD_REQUEST)
}
fn cursor_position(
    token: Option<&str>,
    key: &hmac::Key,
    tenant: &str,
    subject: &str,
    session: &str,
    business: &str,
    entry: &str,
    prefix: &str,
    limit: usize,
    now: u64,
) -> Result<Option<String>, StatusCode> {
    let Some(token) = token else { return Ok(None) };
    let cursor = decode_cursor(token, key)?;
    if cursor.version != 1
        || cursor.tenant_id != tenant
        || cursor.subject_id != subject
        || cursor.session_id != session
        || cursor.business_id != business
        || cursor.entry_id != entry
        || cursor.prefix != prefix
        || cursor.limit != limit
        || !valid_report_id(&cursor.after)
        || cursor.expires_at_unix_secs <= now
        || cursor.expires_at_unix_secs > now.saturating_add(CURSOR_TTL_SECS)
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    Ok(Some(cursor.after))
}

fn report_queries(tenant: &str, subject: &str, business: &str, ids: &[String]) -> BatchAccessQuery {
    BatchAccessQuery {
        queries: ids
            .iter()
            .map(|id| AccessQuery {
                tenant_id: tenant.into(),
                business_id: business.into(),
                subject_id: subject.into(),
                resource_type: "report".into(),
                action: "read".into(),
                resource_id: Some(id.clone()),
            })
            .collect(),
    }
}

struct PageSelection {
    ids: Vec<String>,
    last_checked: Option<String>,
    has_more: bool,
}
fn select_page(candidates: &[String], decisions: &[AccessDecision], limit: usize) -> PageSelection {
    let checked = candidates.len().min(MAX_SCAN);
    let mut ids = Vec::with_capacity(limit);
    let mut last_checked = None;
    let mut has_more = false;
    for (index, (id, decision)) in candidates
        .iter()
        .take(checked)
        .zip(decisions.iter())
        .enumerate()
    {
        last_checked = Some(id.clone());
        if *decision == AccessDecision::Allow {
            ids.push(id.clone());
        }
        if ids.len() == limit {
            has_more = index + 1 < candidates.len();
            break;
        }
    }
    if last_checked.is_some() && checked == MAX_SCAN && candidates.len() > MAX_SCAN {
        has_more = true;
    }
    PageSelection {
        ids,
        last_checked,
        has_more,
    }
}

#[derive(Serialize)]
struct ReportPage {
    items: Vec<Report>,
    has_more: bool,
    next_cursor: Option<String>,
}

async fn list_reports(
    State(state): State<ReportState>,
    headers: HeaderMap,
    Query(query): Query<ListQuery>,
) -> Response {
    let limit = query.limit.unwrap_or(DEFAULT_PAGE);
    let prefix = query.prefix.unwrap_or_default();
    if !(1..=MAX_PAGE).contains(&limit) || !valid_prefix(&prefix) {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let actor = match authenticate(&state, &headers).await {
        Ok(actor) => actor,
        Err(status) => return status.into_response(),
    };
    let now = match now_secs() {
        Ok(now) => now,
        Err(status) => return status.into_response(),
    };
    let after = match cursor_position(
        query.cursor.as_deref(),
        &state.cursor_key,
        &actor.tenant_id,
        &actor.subject_id,
        &actor.session_id,
        &state.business_id,
        &state.entry_id,
        &prefix,
        limit,
        now,
    ) {
        Ok(after) => after,
        Err(status) => return status.into_response(),
    };
    let store = state.store.clone();
    let tenant = actor.tenant_id.clone();
    let prefix_for_query = prefix.clone();
    let ids = tokio::task::spawn_blocking(move || {
        store.ids(&tenant, &prefix_for_query, after.as_deref())
    })
    .await
    .unwrap_or(Err("report list failed".into()));
    let ids = match ids {
        Ok(ids) => ids,
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };
    let checked = ids.len().min(MAX_SCAN);
    let batch = report_queries(
        &actor.tenant_id,
        &actor.subject_id,
        &state.business_id,
        &ids[..checked],
    );
    let service = state.authorization.clone();
    let decisions = match if checked == 0 {
        Ok(vec![])
    } else {
        tokio::task::spawn_blocking(move || service.check_many(batch))
            .await
            .unwrap_or(Err(AccessError::InvalidStoreResponse))
    } {
        Ok(decisions) if decisions.len() == checked => decisions,
        _ => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };
    let selection = select_page(&ids, &decisions, limit);
    let mut items = Vec::with_capacity(selection.ids.len());
    for id in &selection.ids {
        let store = state.store.clone();
        let tenant = actor.tenant_id.clone();
        let id = id.clone();
        let report = tokio::task::spawn_blocking(move || store.get(&tenant, &id))
            .await
            .unwrap_or(Err("report read failed".into()));
        match report {
            Ok(Some(report)) => items.push(report),
            Ok(None) => {}
            Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
        }
    }
    let has_more = selection.has_more;
    let last_checked = selection.last_checked;
    let next_cursor = if has_more {
        let Some(after) = last_checked else {
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        };
        let cursor = Cursor {
            version: 1,
            tenant_id: actor.tenant_id,
            subject_id: actor.subject_id,
            session_id: actor.session_id,
            business_id: state.business_id,
            entry_id: state.entry_id,
            prefix,
            limit,
            after,
            expires_at_unix_secs: now.saturating_add(CURSOR_TTL_SECS),
        };
        match encode_cursor(&cursor, &state.cursor_key) {
            Ok(value) => Some(value),
            Err(status) => return status.into_response(),
        }
    } else {
        None
    };
    Json(ReportPage {
        items,
        has_more,
        next_cursor,
    })
    .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> hmac::Key {
        hmac::Key::new(hmac::HMAC_SHA256, &[7; 32])
    }
    fn cursor() -> Cursor {
        Cursor {
            version: 1,
            tenant_id: "tenant-a".into(),
            subject_id: "user-a".into(),
            session_id: "session-a".into(),
            business_id: "reports".into(),
            entry_id: "choose".into(),
            prefix: "r".into(),
            limit: 5,
            after: "r009".into(),
            expires_at_unix_secs: 2_000,
        }
    }
    fn encoded(cursor: &Cursor, key: &hmac::Key) -> String {
        encode_cursor(cursor, key).unwrap()
    }

    #[test]
    fn cursor_binds_session_scope_filters_and_expiry() {
        let key = key();
        let current = cursor();
        let token = encoded(&current, &key);
        assert_eq!(decode_cursor(&token, &key).unwrap().after, "r009");
        assert_eq!(
            cursor_position(
                Some(&token),
                &key,
                "tenant-a",
                "user-a",
                "session-a",
                "reports",
                "choose",
                "r",
                5,
                1_900
            )
            .unwrap()
            .as_deref(),
            Some("r009")
        );
        assert_eq!(
            cursor_position(
                Some(&token),
                &key,
                "tenant-b",
                "user-a",
                "session-a",
                "reports",
                "choose",
                "r",
                5,
                1_900
            ),
            Err(StatusCode::BAD_REQUEST)
        );
        assert_eq!(
            cursor_position(
                Some(&token),
                &key,
                "tenant-a",
                "user-a",
                "session-b",
                "reports",
                "choose",
                "r",
                5,
                1_900
            ),
            Err(StatusCode::BAD_REQUEST)
        );
        assert_eq!(
            cursor_position(
                Some(&token),
                &key,
                "tenant-a",
                "user-a",
                "session-a",
                "reports",
                "fixed",
                "r",
                5,
                1_900
            ),
            Err(StatusCode::BAD_REQUEST)
        );
        assert_eq!(
            cursor_position(
                Some(&token),
                &key,
                "tenant-a",
                "user-a",
                "session-a",
                "reports",
                "choose",
                "x",
                5,
                1_900
            ),
            Err(StatusCode::BAD_REQUEST)
        );
        assert_eq!(
            cursor_position(
                Some(&token),
                &key,
                "tenant-a",
                "user-a",
                "session-a",
                "reports",
                "choose",
                "r",
                6,
                1_900
            ),
            Err(StatusCode::BAD_REQUEST)
        );
        assert_eq!(
            cursor_position(
                Some(&token),
                &key,
                "tenant-a",
                "user-a",
                "session-a",
                "reports",
                "choose",
                "r",
                5,
                2_000
            ),
            Err(StatusCode::BAD_REQUEST)
        );
        let mut changed = token.clone();
        changed.replace_range(0..1, if &token[0..1] == "A" { "B" } else { "A" });
        assert!(decode_cursor(&changed, &key).is_err());
        assert!(decode_cursor("not-a-cursor", &key).is_err());
    }

    #[test]
    fn list_authorization_uses_authenticated_scope_and_each_exact_resource() {
        let batch = report_queries(
            "tenant-a",
            "account-a",
            "reports",
            &["r001".into(), "r002".into()],
        );
        assert_eq!(batch.queries.len(), 2);
        for (query, id) in batch.queries.iter().zip(["r001", "r002"]) {
            assert_eq!(query.tenant_id, "tenant-a");
            assert_eq!(query.subject_id, "account-a");
            assert_eq!(query.business_id, "reports");
            assert_eq!(query.resource_type, "report");
            assert_eq!(query.action, "read");
            assert_eq!(query.resource_id.as_deref(), Some(id));
        }
    }

    #[test]
    fn denied_candidates_advance_the_cursor_and_empty_pages_can_continue() {
        let candidates: Vec<String> = (0..=MAX_SCAN).map(|n| format!("r{n:03}")).collect();
        let denied = vec![AccessDecision::Deny; MAX_SCAN];
        let page = select_page(&candidates, &denied, 5);
        assert!(page.ids.is_empty());
        assert_eq!(page.last_checked.as_deref(), Some("r039"));
        assert!(page.has_more);
        let end = select_page(&candidates[..MAX_SCAN], &denied, 5);
        assert!(end.ids.is_empty());
        assert!(!end.has_more);
    }

    #[test]
    fn page_selection_stops_at_requested_authorized_count() {
        let candidates: Vec<String> = (0..12).map(|n| format!("r{n:03}")).collect();
        let decisions: Vec<AccessDecision> = (0..12)
            .map(|n| {
                if n == 2 || n == 7 {
                    AccessDecision::Allow
                } else {
                    AccessDecision::Deny
                }
            })
            .collect();
        let page = select_page(&candidates, &decisions, 2);
        assert_eq!(page.ids, ["r002", "r007"]);
        assert_eq!(page.last_checked.as_deref(), Some("r007"));
        assert!(page.has_more);
    }
}
