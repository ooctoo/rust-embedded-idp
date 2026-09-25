use std::sync::Arc;

use axum::{
    extract::{Query, State},
    http::{header, HeaderMap, StatusCode},
    middleware,
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use base64ct::{Base64UrlUnpadded, Encoding};
use embedded_idp_core::{access::*, SecretString};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{
    http_support::bearer_token,
    role_admin::role_json,
    tenant_auth::{call, map_tenant_auth_error, no_store, tenant_error, tenant_header_matches},
};

#[derive(Clone)]
struct SelfState {
    authentication: Arc<dyn TenantAuthenticationService>,
    access: Arc<dyn AccessQueryService>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PageQuery {
    limit: Option<u32>,
    cursor: Option<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Cursor {
    version: u8,
    tenant_id: String,
    subject_id: String,
    after: String,
}

/// Public, session-scoped role list. The caller cannot choose a tenant or subject.
pub fn tenant_self_router(
    authentication: Arc<dyn TenantAuthenticationService>,
    access: Arc<dyn AccessQueryService>,
) -> Router {
    Router::new()
        .route("/auth/me/roles", get(roles))
        .with_state(SelfState {
            authentication,
            access,
        })
        .layer(middleware::from_fn(no_store))
}

async fn roles(
    State(state): State<SelfState>,
    headers: HeaderMap,
    Query(query): Query<PageQuery>,
) -> Response {
    if headers.get_all(header::AUTHORIZATION).iter().count() != 1 {
        return map_tenant_auth_error(TenantAuthError::InvalidSession);
    }
    let Some(token) = bearer_token(&headers)
        .filter(|token| token.len() <= 16384)
        .map(str::to_owned)
    else {
        return map_tenant_auth_error(TenantAuthError::InvalidSession);
    };
    let authentication = state.authentication;
    let actor = match call(move || authentication.authenticate(SecretString::new(token))).await {
        Ok(actor) if tenant_header_matches(&headers, &actor.tenant_id) => actor,
        Ok(_) => return map_tenant_auth_error(TenantAuthError::InvalidSession),
        Err(error) => return map_tenant_auth_error(error),
    };
    let cursor = match query.cursor {
        None => None,
        Some(raw) if raw.len() <= 2048 => {
            let Some(cursor) = Base64UrlUnpadded::decode_vec(&raw)
                .ok()
                .and_then(|bytes| serde_json::from_slice::<Cursor>(&bytes).ok())
            else {
                return invalid_cursor();
            };
            Some(AccessCursor {
                version: cursor.version,
                scope: AccessListScope::SubjectRoles {
                    tenant_id: cursor.tenant_id,
                    subject_id: cursor.subject_id,
                },
                after: vec![cursor.after],
            })
        }
        Some(_) => return invalid_cursor(),
    };
    let access = state.access;
    let tenant_id = actor.tenant_id;
    let subject_id = actor.subject_id;
    match call(move || {
        access.list_subject_roles(
            &tenant_id,
            &subject_id,
            AccessPageRequest {
                limit: query.limit.unwrap_or(embedded_idp_core::DEFAULT_PAGE_LIMIT),
                cursor,
            },
        )
    })
    .await
    {
        Ok(page) => {
            let next_cursor = match page.next_cursor {
                None => None,
                Some(cursor) => {
                    let (
                        AccessListScope::SubjectRoles {
                            tenant_id,
                            subject_id,
                        },
                        [after],
                    ) = (cursor.scope, cursor.after.as_slice())
                    else {
                        return internal_error();
                    };
                    let Ok(bytes) = serde_json::to_vec(&Cursor {
                        version: cursor.version,
                        tenant_id,
                        subject_id,
                        after: after.clone(),
                    }) else {
                        return internal_error();
                    };
                    Some(Base64UrlUnpadded::encode_string(&bytes))
                }
            };
            Json(
                json!({"items": page.items.into_iter().map(role_json).collect::<Vec<_>>(),
                "has_more": page.has_more, "next_cursor": next_cursor}),
            )
            .into_response()
        }
        Err(AccessError::InvalidCursor) => invalid_cursor(),
        Err(AccessError::InvalidInput(_)) => tenant_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "request is invalid",
        ),
        Err(_) => internal_error(),
    }
}

fn invalid_cursor() -> Response {
    tenant_error(
        StatusCode::BAD_REQUEST,
        "invalid_cursor",
        "request is invalid",
    )
}

fn internal_error() -> Response {
    tenant_error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "internal_error",
        "the request could not be completed",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use tower::ServiceExt;

    struct Authentication;
    impl TenantAuthenticationService for Authentication {
        fn login_capabilities(&self) -> TenantLoginCapabilities {
            TenantLoginCapabilities {
                mode: TenancyMode::Enabled,
                policy: LoginTenantPolicy::ChooseAfterAuthentication,
            }
        }
        fn login(&self, _: TenantPasswordLogin) -> Result<TenantLoginOutcome, TenantAuthError> {
            Err(TenantAuthError::InvalidCredentials)
        }
        fn list_tenants(
            &self,
            _: SecretString,
            _: AccessPageRequest,
        ) -> Result<AccessPage<SubjectTenant>, TenantAuthError> {
            Err(TenantAuthError::InvalidSelection)
        }
        fn select_tenant(
            &self,
            _: SecretString,
            _: String,
        ) -> Result<TenantLoginSession, TenantAuthError> {
            Err(TenantAuthError::InvalidSelection)
        }
        fn authenticate(&self, token: SecretString) -> Result<AccessActor, TenantAuthError> {
            if token.expose_secret() != "valid-token" {
                return Err(TenantAuthError::InvalidSession);
            }
            Ok(AccessActor {
                tenant_id: "t1".into(),
                subject_id: "u1".into(),
                session_id: "s1".into(),
            })
        }
        fn begin_switch(&self, _: SecretString) -> Result<TenantSelectionTicket, TenantAuthError> {
            Err(TenantAuthError::InvalidSelection)
        }
    }

    struct Access;
    impl AccessQueryService for Access {
        fn list_subject_roles(
            &self,
            tenant: &str,
            subject: &str,
            page: AccessPageRequest,
        ) -> Result<AccessPage<Role>, AccessError> {
            assert_eq!((tenant, subject), ("t1", "u1"));
            page.validate(&AccessListScope::SubjectRoles {
                tenant_id: tenant.into(),
                subject_id: subject.into(),
            })?;
            Ok(AccessPage {
                items: vec![Role {
                    id: "r1".into(),
                    tenant_id: tenant.into(),
                    key: "reader".into(),
                    name: "Reader".into(),
                    status: RoleStatus::Active,
                    kind: RoleKind::Business,
                    version: 1,
                }],
                has_more: true,
                next_cursor: Some(AccessCursor {
                    version: 1,
                    scope: AccessListScope::SubjectRoles {
                        tenant_id: tenant.into(),
                        subject_id: subject.into(),
                    },
                    after: vec!["r1".into()],
                }),
            })
        }
        fn list_role_permissions(
            &self,
            _: &str,
            _: &str,
            _: AccessPageRequest,
        ) -> Result<AccessPage<PermissionDefinition>, AccessError> {
            unreachable!()
        }
        fn list_subject_tenants(
            &self,
            _: &str,
            _: &LoginTenantPolicy,
            _: AccessPageRequest,
        ) -> Result<AccessPage<SubjectTenant>, AccessError> {
            unreachable!()
        }
    }

    async fn get(uri: &str, token: Option<&str>, tenant: Option<&str>) -> Response {
        let mut request = Request::builder().uri(uri);
        if let Some(token) = token {
            request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        if let Some(tenant) = tenant {
            request = request.header("x-embedded-idp-tenant-id", tenant);
        }
        tenant_self_router(Arc::new(Authentication), Arc::new(Access))
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn only_current_session_scope_can_read_roles() {
        assert_eq!(
            get("/auth/me/roles", None, None).await.status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            get("/auth/me/roles", Some("invalid"), None).await.status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            get("/auth/me/roles", Some("valid-token"), Some("t2"))
                .await
                .status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            get("/auth/me/roles?tenant_id=t2", Some("valid-token"), None)
                .await
                .status(),
            StatusCode::BAD_REQUEST
        );
        let response = get("/auth/me/roles", Some("valid-token"), Some("t1")).await;
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(body["items"][0]["role_id"], "r1");
        let cursor = body["next_cursor"].as_str().unwrap();
        let own = format!("/auth/me/roles?cursor={cursor}");
        assert_eq!(
            get(&own, Some("valid-token"), None).await.status(),
            StatusCode::OK
        );
        let foreign = Base64UrlUnpadded::encode_string(
            &serde_json::to_vec(&Cursor {
                version: 1,
                tenant_id: "t2".into(),
                subject_id: "u1".into(),
                after: "r1".into(),
            })
            .unwrap(),
        );
        let foreign = format!("/auth/me/roles?cursor={foreign}");
        assert_eq!(
            get(&foreign, Some("valid-token"), None).await.status(),
            StatusCode::BAD_REQUEST
        );
    }
}
