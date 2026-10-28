use super::*;
use embedded_idp_core::access::{
    AccessActor, AccessError, CoreSelfSessionService, SelfSessionCursor, SelfSessionPageRequest,
};
use embedded_idp_core::SessionStatus;

fn service(db: &Db) -> CoreSelfSessionService<PostgresAccessStore, FixedClock> {
    CoreSelfSessionService::new(db.mode, db.store(), FixedClock)
}

fn actor(tenant: &str, subject: Uuid, session: Uuid) -> AccessActor {
    AccessActor {
        tenant_id: tenant.to_owned(),
        subject_id: subject.to_string(),
        session_id: session.to_string(),
    }
}

fn insert_actor_memberships(db: &Db) {
    if db.mode == TenancyMode::Enabled {
        let mut client = db.adapter.connect().unwrap();
        for tenant in ["t1", "t2"] {
            client
                .execute(
                    &format!("insert into {}.access_memberships(tenant_id,account_id,status,joined_at_epoch) values($1,$2,'active',$3)", db.schema()),
                    &[&tenant, &db.actor, &(NOW as i64)],
                )
                .unwrap();
        }
    }
}

fn insert_session(
    db: &Db,
    tenant: &str,
    id: Uuid,
    account: Uuid,
    created: i64,
    expires: i64,
    scope: Option<&str>,
) {
    let mut client = db.adapter.connect().unwrap();
    client
        .execute(
            &format!("insert into {}.auth_sessions(purpose,tenant_id,id,account_id,client_id,status,created_at_epoch,expires_at_epoch,refresh_token_version,scope,authenticated_at_epoch) values('business',$1,$2,$3,'live-admin-client','active',$4,$5,1,$6,$4)", db.schema()),
            &[&tenant, &id, &account, &created, &expires, &scope],
        )
        .unwrap();
}

fn counts(db: &Db) -> (i64, i64) {
    let mut client = db.adapter.connect().unwrap();
    let row = client
        .query_one(
            &format!(
                "select (select count(*) from {}.auth_sessions where account_id=$1), (select count(*) from {}.refresh_tokens)",
                db.schema(),
                db.schema()
            ),
            &[&db.actor],
        )
        .unwrap();
    (row.get(0), row.get(1))
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn self_sessions_list_global_pages_and_projects_expiry_without_writes() {
    for mode in [TenancyMode::Disabled, TenancyMode::Enabled] {
        let db = Db::new(mode);
        insert_actor_memberships(&db);
        let tenants = if mode == TenancyMode::Enabled {
            ["0", "t1", "t2", "t2", "t1"]
        } else {
            ["0", "0", "0", "0", "0"]
        };
        let ids = [1_u128, 2, 3, 4, 5].map(Uuid::from_u128);
        for (index, id) in ids.iter().enumerate() {
            let (created, expires, scope) = match index {
                3 => (900, 999, None),
                4 => (900, 2_000, Some("openid profile")),
                _ => (900, 2_000, None),
            };
            insert_session(&db, tenants[index], *id, db.actor, created, expires, scope);
        }
        // A different subject has active sessions in the same tenants; none may leak.
        let other_id = Uuid::from_u128(99);
        insert_session(&db, db.target(), other_id, db.member, 900, 2_000, None);

        let before = counts(&db);
        let actor = actor("0", db.actor, db.actor_session);
        let service = service(&db);
        let mut cursor = None;
        let mut collected = Vec::new();
        loop {
            let page = service
                .list_sessions(
                    actor.clone(),
                    SelfSessionPageRequest {
                        limit: 2,
                        cursor: cursor.clone(),
                    },
                )
                .unwrap();
            assert!(page.items.len() <= 2);
            collected.extend(page.items);
            let Some(next) = page.next_cursor else { break };
            assert_eq!(next.subject_id, db.actor.to_string());
            cursor = Some(next);
        }

        assert_eq!(collected.len(), 6);
        assert!(collected
            .iter()
            .all(|item| item.session_id != other_id.to_string()));
        assert!(collected
            .iter()
            .any(|item| item.session_id == ids[4].to_string()));
        assert_eq!(
            collected
                .iter()
                .find(|item| item.session_id == ids[3].to_string())
                .unwrap()
                .status,
            SessionStatus::Expired
        );
        assert!(
            collected
                .iter()
                .find(|item| item.session_id == db.actor_session.to_string())
                .unwrap()
                .current
        );
        assert!(collected
            .iter()
            .filter(|item| item.current)
            .all(|item| item.session_id == db.actor_session.to_string()));
        let expected_tenants = if mode == TenancyMode::Enabled {
            vec!["0", "t1", "t2"]
        } else {
            vec!["0"]
        };
        let actual_tenants: Vec<_> = collected
            .iter()
            .map(|item| item.tenant_id.as_str())
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();
        assert_eq!(actual_tenants, expected_tenants);
        assert_eq!(
            counts(&db),
            before,
            "self-session reads must not mutate rows"
        );
    }
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn self_sessions_rejects_invalid_cursor_and_non_native_actor() {
    for mode in [TenancyMode::Disabled, TenancyMode::Enabled] {
        let db = Db::new(mode);
        let service = service(&db);
        let actor = actor("0", db.actor, db.actor_session);
        let bad_subject = SelfSessionCursor {
            subject_id: db.member.to_string(),
            tenant_id: "0".into(),
            session_id: Uuid::now_v7().to_string(),
        };
        assert_eq!(
            service.list_sessions(
                actor.clone(),
                SelfSessionPageRequest {
                    limit: 10,
                    cursor: Some(bad_subject),
                }
            ),
            Err(AccessError::InvalidCursor)
        );
        let malformed = SelfSessionCursor {
            subject_id: db.actor.to_string(),
            tenant_id: "0".into(),
            session_id: "not-a-canonical-uuid".into(),
        };
        assert_eq!(
            service.list_sessions(
                actor.clone(),
                SelfSessionPageRequest {
                    limit: 10,
                    cursor: Some(malformed),
                }
            ),
            Err(AccessError::InvalidCursor)
        );

        let mut client = db.adapter.connect().unwrap();
        let s = db.schema();
        client
            .execute(
                &format!(
                    "update {s}.auth_sessions set scope='openid' where tenant_id='0' and id=$1"
                ),
                &[&db.actor_session],
            )
            .unwrap();
        assert_eq!(
            service.list_sessions(
                actor.clone(),
                SelfSessionPageRequest {
                    limit: 10,
                    cursor: None
                }
            ),
            Err(AccessError::Forbidden)
        );
        client
            .execute(
                &format!("update {s}.auth_sessions set scope=null where tenant_id='0' and id=$1"),
                &[&db.actor_session],
            )
            .unwrap();
        client
            .execute(
                &format!(
                    "update {s}.auth_sessions set status='revoked' where tenant_id='0' and id=$1"
                ),
                &[&db.actor_session],
            )
            .unwrap();
        assert_eq!(
            service.list_sessions(
                actor.clone(),
                SelfSessionPageRequest {
                    limit: 10,
                    cursor: None
                }
            ),
            Err(AccessError::Forbidden)
        );
        client
            .execute(
                &format!(
                    "update {s}.auth_sessions set status='active' where tenant_id='0' and id=$1"
                ),
                &[&db.actor_session],
            )
            .unwrap();
        client
            .execute(
                &format!("update {s}.access_memberships set status='suspended' where tenant_id='0' and account_id=$1"),
                &[&db.actor],
            )
            .unwrap();
        assert_eq!(
            service.list_sessions(
                actor,
                SelfSessionPageRequest {
                    limit: 10,
                    cursor: None
                }
            ),
            Err(AccessError::Forbidden)
        );
    }
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn self_sessions_rejects_actor_with_retired_key_or_suspended_binding() {
    for mode in [TenancyMode::Disabled, TenancyMode::Enabled] {
        let db = Db::new(mode);
        insert_actor_memberships(&db);
        let tenant = db.target().to_owned();
        let device_id = Uuid::now_v7();
        let device_session = super::devices::device(&db, &tenant, device_id, db.actor, 12);
        let s = db.schema();
        let mut client = db.adapter.connect().unwrap();
        let key: String = client
            .query_one(
                &format!("select proof_key_id from {s}.devices where tenant_id=$1 and id=$2"),
                &[&tenant, &device_id],
            )
            .unwrap()
            .get(0);
        let binding: Uuid = client
            .query_one(
                &format!("select id from {s}.account_device_bindings where tenant_id=$1 and device_id=$2 and account_id=$3"),
                &[&tenant, &device_id, &db.actor],
            )
            .unwrap()
            .get(0);
        let device_actor = actor(&tenant, db.actor, device_session);
        let service = service(&db);

        client
            .execute(
                &format!("update {s}.device_proof_keys set status='retired',retired_at_epoch=1001 where tenant_id=$1 and key_id=$2"),
                &[&tenant, &key],
            )
            .unwrap();
        assert_eq!(
            service.list_sessions(
                device_actor.clone(),
                SelfSessionPageRequest {
                    limit: 10,
                    cursor: None
                }
            ),
            Err(AccessError::Forbidden)
        );
        client
            .execute(
                &format!("update {s}.device_proof_keys set status='active',retired_at_epoch=null where tenant_id=$1 and key_id=$2"),
                &[&tenant, &key],
            )
            .unwrap();
        client
            .execute(
                &format!("update {s}.account_device_bindings set status='suspended' where tenant_id=$1 and id=$2"),
                &[&tenant, &binding],
            )
            .unwrap();
        assert_eq!(
            service.list_sessions(
                device_actor,
                SelfSessionPageRequest {
                    limit: 10,
                    cursor: None
                }
            ),
            Err(AccessError::Forbidden)
        );
    }
}
