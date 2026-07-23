use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use embedded_idp_core::{Account, AuthSession, DeviceRecord, PageMetadata, TimePageCursor};

use crate::admin_dto::PageHttpResponse;
use crate::dto::ErrorHttpResponse;

pub(crate) fn parse_cursor(value: &str) -> Result<TimePageCursor, Response> {
    let (sort_time_secs, entity_id) = value
        .split_once(':')
        .ok_or_else(|| invalid_cursor_response(value))?;
    let sort_time_secs = sort_time_secs
        .parse::<u64>()
        .map_err(|_| invalid_cursor_response(value))?;

    if entity_id.trim().is_empty() {
        return Err(invalid_cursor_response(value));
    }

    Ok(TimePageCursor {
        sort_time: UNIX_EPOCH + Duration::from_secs(sort_time_secs),
        entity_id: entity_id.to_string(),
    })
}

pub(crate) fn page_response(page: PageMetadata, next_cursor: Option<String>) -> PageHttpResponse {
    PageHttpResponse {
        limit: page.limit,
        offset: page.offset,
        returned: page.returned,
        total: page.total,
        has_more: page.has_more,
        next_cursor,
    }
}

pub(crate) fn account_next_cursor(accounts: &[Account], page: &PageMetadata) -> Option<String> {
    time_cursor(
        page,
        accounts
            .last()
            .map(|account| (account.created_at, account.id.as_str())),
    )
}

pub(crate) fn session_next_cursor(sessions: &[AuthSession], page: &PageMetadata) -> Option<String> {
    time_cursor(
        page,
        sessions
            .last()
            .map(|session| (session.created_at, session.id.as_str())),
    )
}

pub(crate) fn device_next_cursor(devices: &[DeviceRecord], page: &PageMetadata) -> Option<String> {
    time_cursor(
        page,
        devices
            .last()
            .map(|device| (device.registered_at, device.id.as_str())),
    )
}

fn time_cursor(page: &PageMetadata, value: Option<(SystemTime, &str)>) -> Option<String> {
    if !page.has_more {
        return None;
    }

    value.map(|(sort_time, entity_id)| encode_cursor(sort_time, entity_id))
}

fn encode_cursor(sort_time: SystemTime, entity_id: &str) -> String {
    format!("{}:{entity_id}", unix_secs(sort_time))
}

fn unix_secs(value: SystemTime) -> u64 {
    value
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}

fn invalid_cursor_response(value: &str) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(ErrorHttpResponse {
            code: "invalid_contract",
            message: format!("unsupported cursor: {value}"),
        }),
    )
        .into_response()
}
