use super::*;
use std::sync::{Arc, Mutex};
use std::time::UNIX_EPOCH;

const SUBJECT: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const CURRENT_SESSION: &str = "00000000-0000-4000-8000-000000000001";
const NOW: u64 = 1_000;

#[derive(Clone)]
struct FixedClock;

impl Clock for FixedClock {
    fn now(&self) -> SystemTime {
        UNIX_EPOCH + std::time::Duration::from_secs(NOW)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AdapterResponse {
    WrongSubject,
    WrongOrder,
    TooMany,
    NonActive,
    InvalidTimestamp,
}

#[derive(Default)]
struct State {
    rows: Vec<TenantSession>,
    actor_active: bool,
    actor_scope: Option<String>,
    response: Option<AdapterResponse>,
    trace: Vec<&'static str>,
    transaction_count: usize,
}

#[derive(Clone, Default)]
struct MemoryStore(Arc<Mutex<State>>);

struct MemoryTransaction<'a> {
    state: &'a mut State,
}

impl SelfSessionReadTransaction for MemoryTransaction<'_> {
    fn actor_is_active(
        &mut self,
        actor: &AccessActor,
        _now: SystemTime,
    ) -> Result<bool, StoreError> {
        self.state.trace.push("actor");
        Ok(self.state.actor_active
            && self.state.actor_scope.is_none()
            && actor.subject_id == SUBJECT
            && actor.tenant_id == "tenant-a"
            && actor.session_id == CURRENT_SESSION)
    }

    fn sessions_for_subject(
        &mut self,
        subject: &str,
        after: Option<&SelfSessionCursor>,
        limit: u32,
    ) -> Result<Vec<TenantSession>, StoreError> {
        self.state.trace.push("sessions");
        let mut rows: Vec<_> = self
            .state
            .rows
            .iter()
            .filter(|row| row.account_id == subject)
            .filter(|row| {
                after.is_none_or(|cursor| {
                    (row.tenant_id.as_str(), row.id.as_str())
                        > (cursor.tenant_id.as_str(), cursor.session_id.as_str())
                })
            })
            .cloned()
            .collect();
        rows.sort_by(|left, right| (&left.tenant_id, &left.id).cmp(&(&right.tenant_id, &right.id)));

        let force_too_many = self.state.response == Some(AdapterResponse::TooMany);
        match self.state.response.take() {
            Some(AdapterResponse::WrongSubject) => {
                if let Some(row) = rows.first_mut() {
                    row.account_id = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb".into();
                }
            }
            Some(AdapterResponse::WrongOrder) => rows.reverse(),
            Some(AdapterResponse::TooMany) => {
                if let Some(row) = rows.first().cloned() {
                    rows = vec![row; limit as usize + 1];
                }
            }
            Some(AdapterResponse::NonActive) => {
                if let Some(row) = rows.first_mut() {
                    row.status = SessionStatus::Revoked;
                }
            }
            Some(AdapterResponse::InvalidTimestamp) => {
                if let Some(row) = rows.first_mut() {
                    row.authenticated_at = row.created_at + std::time::Duration::from_secs(1);
                }
            }
            None => {}
        }
        if force_too_many {
            Ok(rows)
        } else {
            Ok(rows.into_iter().take(limit as usize).collect())
        }
    }
}

impl SelfSessionReadStore for MemoryStore {
    type Transaction<'a> = MemoryTransaction<'a>;

    fn self_session_read<R>(
        &self,
        _mode: TenancyMode,
        _actor: &AccessActor,
        run: impl FnOnce(&mut Self::Transaction<'_>) -> Result<R, AccessError>,
    ) -> Result<R, AccessError> {
        let mut state = self.0.lock().unwrap();
        state.transaction_count += 1;
        let mut tx = MemoryTransaction { state: &mut state };
        run(&mut tx)
    }
}

fn actor() -> AccessActor {
    AccessActor {
        tenant_id: "tenant-a".into(),
        subject_id: SUBJECT.into(),
        session_id: CURRENT_SESSION.into(),
    }
}

fn session(tenant: &str, id: &str, expires: u64, scope: Option<&str>) -> TenantSession {
    let created = UNIX_EPOCH + std::time::Duration::from_secs(100);
    TenantSession {
        purpose: if scope.is_some() {
            AccessTokenPurpose::Business
        } else {
            AccessTokenPurpose::Management
        },
        tenant_id: tenant.into(),
        id: id.into(),
        account_id: SUBJECT.into(),
        client_id: "web-client".into(),
        device_id: None,
        scope: scope.map(str::to_owned),
        authenticated_at: UNIX_EPOCH + std::time::Duration::from_secs(90),
        status: SessionStatus::Active,
        created_at: created,
        expires_at: UNIX_EPOCH + std::time::Duration::from_secs(expires),
        refresh_token_version: 7,
    }
}

fn fixture() -> (MemoryStore, CoreSelfSessionService<MemoryStore, FixedClock>) {
    let store = MemoryStore::default();
    {
        let mut state = store.0.lock().unwrap();
        state.actor_active = true;
        state.rows = vec![
            session("tenant-a", CURRENT_SESSION, 3_000, None),
            session(
                "tenant-b",
                "00000000-0000-4000-8000-000000000002",
                3_000,
                Some("openid profile email"),
            ),
            session(
                "tenant-b",
                "00000000-0000-4000-8000-000000000003",
                500,
                None,
            ),
        ];
    }
    let service = CoreSelfSessionService::new(TenancyMode::Enabled, store.clone(), FixedClock);
    (store, service)
}

fn page(limit: u32, cursor: Option<SelfSessionCursor>) -> SelfSessionPageRequest {
    SelfSessionPageRequest { limit, cursor }
}

fn cursor(subject_id: &str, tenant_id: &str, session_id: &str) -> SelfSessionCursor {
    SelfSessionCursor {
        subject_id: subject_id.into(),
        tenant_id: tenant_id.into(),
        session_id: session_id.into(),
    }
}

#[test]
fn validates_limit_and_cursor_before_opening_store_transaction() {
    let (store, service) = fixture();
    for limit in [0, 51] {
        assert!(matches!(
            service.list_sessions(actor(), page(limit, None)),
            Err(AccessError::InvalidInput("limit"))
        ));
    }
    let invalid_cursors = [
        cursor(
            "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
            "tenant-a",
            CURRENT_SESSION,
        ),
        cursor(SUBJECT, "bad/tenant", CURRENT_SESSION),
        cursor(SUBJECT, "tenant-a", "00000000-0000-4000-8000-00000000000A"),
    ];
    for cursor in invalid_cursors {
        assert!(matches!(
            service.list_sessions(actor(), page(10, Some(cursor))),
            Err(AccessError::InvalidCursor)
        ));
    }
    let state = store.0.lock().unwrap();
    assert_eq!(state.transaction_count, 0);
    assert!(state.trace.is_empty());
}

#[test]
fn rejects_inactive_actor_before_querying_sessions() {
    let (store, service) = fixture();
    store.0.lock().unwrap().actor_active = false;

    assert!(matches!(
        service.list_sessions(actor(), page(10, None)),
        Err(AccessError::Forbidden)
    ));
    assert_eq!(store.0.lock().unwrap().trace, ["actor"]);
}

#[test]
fn pages_across_tenants_and_projects_current_expired_and_delegated_sessions() {
    let (store, service) = fixture();
    let first = service.list_sessions(actor(), page(2, None)).unwrap();
    assert_eq!(first.items.len(), 2);
    assert!(first.items[0].current);
    assert_eq!(first.items[0].status, SessionStatus::Active);
    assert!(!first.items[1].current);
    assert_eq!(first.items[1].purpose, AccessTokenPurpose::Business);
    assert_eq!(
        first.items[1].session_id,
        "00000000-0000-4000-8000-000000000002"
    );
    assert_eq!(
        first.next_cursor,
        Some(cursor(
            SUBJECT,
            "tenant-b",
            "00000000-0000-4000-8000-000000000002"
        ))
    );
    let second = service
        .list_sessions(actor(), page(2, first.next_cursor.clone()))
        .unwrap();
    assert_eq!(second.items.len(), 1);
    assert_eq!(second.items[0].status, SessionStatus::Expired);
    assert!(!second.items[0].current);
    assert!(second.next_cursor.is_none());
    assert_eq!(
        store.0.lock().unwrap().trace,
        ["actor", "sessions", "actor", "sessions"]
    );

    let debug = format!("{:?}", first.items[1]);
    assert!(!debug.contains("openid profile email"));
    assert!(!debug.contains("refresh_token_version"));
}

#[test]
fn scope_bearing_actor_cannot_read_but_own_delegated_sessions_are_listed() {
    let (store, service) = fixture();
    store.0.lock().unwrap().actor_scope = Some("openid profile email".into());
    assert!(matches!(
        service.list_sessions(actor(), page(10, None)),
        Err(AccessError::Forbidden)
    ));
    assert_eq!(store.0.lock().unwrap().trace, ["actor"]);

    store.0.lock().unwrap().actor_scope = None;
    let listing = service.list_sessions(actor(), page(10, None)).unwrap();
    assert!(listing
        .items
        .iter()
        .any(|item| item.session_id == "00000000-0000-4000-8000-000000000002"));
}

#[test]
fn rejects_malformed_adapter_rows() {
    for response in [
        AdapterResponse::WrongSubject,
        AdapterResponse::WrongOrder,
        AdapterResponse::TooMany,
        AdapterResponse::NonActive,
        AdapterResponse::InvalidTimestamp,
    ] {
        let (store, service) = fixture();
        store.0.lock().unwrap().response = Some(response);
        assert!(
            matches!(
                service.list_sessions(actor(), page(1, None)),
                Err(AccessError::InvalidStoreResponse)
            ),
            "adapter response {response:?} should be rejected"
        );
    }
}

#[test]
fn actor_time_is_sampled_after_the_runner_acquires_locks() {
    use std::sync::atomic::{AtomicBool, Ordering};
    struct LockedStore {
        inner: MemoryStore,
        locked: Arc<AtomicBool>,
    }
    impl SelfSessionReadStore for LockedStore {
        type Transaction<'a> = MemoryTransaction<'a>;
        fn self_session_read<R>(
            &self,
            mode: TenancyMode,
            actor: &AccessActor,
            run: impl FnOnce(&mut Self::Transaction<'_>) -> Result<R, AccessError>,
        ) -> Result<R, AccessError> {
            self.inner.self_session_read(mode, actor, |tx| {
                self.locked.store(true, Ordering::SeqCst);
                run(tx)
            })
        }
    }
    struct AfterLockClock(Arc<AtomicBool>);
    impl Clock for AfterLockClock {
        fn now(&self) -> SystemTime {
            assert!(
                self.0.load(Ordering::SeqCst),
                "clock read before actor locks"
            );
            FixedClock.now()
        }
    }
    let locked = Arc::new(AtomicBool::new(false));
    let inner = MemoryStore::default();
    inner.0.lock().unwrap().actor_active = true;
    let service = CoreSelfSessionService::new(
        TenancyMode::Enabled,
        LockedStore {
            inner,
            locked: locked.clone(),
        },
        AfterLockClock(locked),
    );
    assert!(service
        .list_sessions(
            actor(),
            SelfSessionPageRequest {
                limit: 1,
                cursor: None
            }
        )
        .unwrap()
        .items
        .is_empty());
}
