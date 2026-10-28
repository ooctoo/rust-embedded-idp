use super::self_password_change::{
    actor, add_actor_memberships, command, config, install, service, set_password, NEW_PASSWORD,
    OLD_PASSWORD,
};
use super::*;
use base64ct::{Base64, Encoding};
use embedded_idp_core::{SecretString, UuidV7IdGenerator};
use embedded_idp_security::{
    ProductionJwtConfig, Rs256JwtService, RsaSigningKeyConfig, SecureRefreshTokenGenerator,
    Sha256RefreshTokenDigester,
};
use std::sync::{mpsc, Mutex};

#[derive(Clone, Copy)]
enum PauseAt {
    Snapshot,
    AuthTransaction,
}
struct PausedAuthStore {
    inner: PostgresAccessStore,
    phase: PauseAt,
    reached: mpsc::SyncSender<()>,
    release: Mutex<mpsc::Receiver<()>>,
}
impl PausedAuthStore {
    fn pause(&self) {
        self.reached.send(()).unwrap();
        self.release
            .lock()
            .unwrap()
            .recv_timeout(Duration::from_secs(15))
            .expect("test barrier released");
    }
}
impl TenantAuthStore for PausedAuthStore {
    type Transaction<'a> = <PostgresAccessStore as TenantAuthStore>::Transaction<'a>;
    fn credential_snapshot_by_email(
        &self,
        mode: TenancyMode,
        email: &str,
    ) -> Result<Option<TenantLoginIdentity>, TenantAuthError> {
        let snapshot = self.inner.credential_snapshot_by_email(mode, email)?;
        if matches!(self.phase, PauseAt::Snapshot) {
            self.pause();
        }
        Ok(snapshot)
    }
    fn auth_transaction<R>(
        &self,
        mode: TenancyMode,
        run: impl FnOnce(&mut Self::Transaction<'_>) -> Result<R, TenantAuthError>,
    ) -> Result<R, TenantAuthError> {
        self.inner.auth_transaction(mode, |tx| {
            if matches!(self.phase, PauseAt::AuthTransaction) {
                self.pause();
            }
            run(tx)
        })
    }
}

fn tokens() -> Rs256JwtService {
    let key = RsaSigningKeyConfig::from_private_key_der(
        Base64::decode_vec(
            include_str!("../../../embedded-idp-security/tests/fixtures/rsa_3072_key_1.pk8.b64")
                .trim(),
        )
        .unwrap(),
    )
    .unwrap();
    Rs256JwtService::new(
        ProductionJwtConfig {
            issuer: "https://idp.example.test".into(),
            audience: "password-race".into(),
            scope: "openid".into(),
            access_token_ttl_secs: 60,
            refresh_token_ttl_secs: 600,
            clock_skew_secs: 0,
        },
        key,
        vec![],
    )
    .unwrap()
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn self_password_change_serializes_both_old_password_login_orders() {
    for mode in [TenancyMode::Disabled, TenancyMode::Enabled] {
        for phase in [PauseAt::AuthTransaction, PauseAt::Snapshot] {
            let db = Db::new(mode);
            install(&db);
            add_actor_memberships(&db);
            set_password(&db, db.actor, OLD_PASSWORD);
            // Admin fixture setup retires the actor session. Restore only this
            // synthetic actor so the tested operation starts authenticated.
            db.adapter
                .connect()
                .unwrap()
                .execute(
                    &format!(
                        "update {}.auth_sessions set status='active' where tenant_id='0' and id=$1",
                        db.schema()
                    ),
                    &[&db.actor_session],
                )
                .unwrap();
            let (reached_tx, reached_rx) = mpsc::sync_channel(1);
            let (release_tx, release_rx) = mpsc::sync_channel(1);
            let auth = CoreTenantAuthenticationService::new(
                mode,
                config(),
                TenantLoginEntry {
                    client_id: "live-admin-client".into(),
                    login_entry: "password-race".into(),
                    policy: LoginTenantPolicy::Fixed {
                        tenant_id: db.target().into(),
                    },
                    require_device_proof: false,
                },
                PausedAuthStore {
                    inner: db.store(),
                    phase,
                    reached: reached_tx,
                    release: Mutex::new(release_rx),
                },
                tokens(),
                SecureRefreshTokenGenerator,
                Sha256RefreshTokenDigester,
                FixedClock,
                UuidV7IdGenerator,
            )
            .unwrap();
            let login = thread::spawn(move || {
                auth.login(TenantPasswordLogin {
                    email: "actor@example.test".into(),
                    password: SecretString::new(OLD_PASSWORD),
                })
            });
            reached_rx
                .recv_timeout(Duration::from_secs(10))
                .expect("login reached deterministic barrier");
            let change = service(&db);
            let change_actor = actor(&db, db.actor_session);
            let operation = Uuid::now_v7();
            let change_thread = thread::spawn(move || {
                change.change_password(change_actor, command(operation, 121, NEW_PASSWORD))
            });
            if matches!(phase, PauseAt::AuthTransaction) {
                // Confirm the actual write has queued behind login's shared
                // state lock, rather than relying on an arbitrary sleep.
                let deadline = std::time::Instant::now() + Duration::from_secs(8);
                loop {
                    let pattern = format!("%{}.access_state%for update%", db.schema());
                    let waiting: bool = db.adapter.connect().unwrap().query_one(
                        "select exists(select 1 from pg_stat_activity where pid<>pg_backend_pid() and wait_event_type='Lock' and query like $1)",
                        &[&pattern],
                    ).unwrap().get(0);
                    if waiting {
                        break;
                    }
                    assert!(
                        std::time::Instant::now() < deadline,
                        "password write must wait for login state lock"
                    );
                    thread::sleep(Duration::from_millis(10));
                }
                release_tx.send(()).unwrap();
                let outcome = login.join().unwrap().expect("old login committed first");
                let TenantLoginOutcome::Authenticated(session) = outcome else {
                    panic!("fixed entry must issue session")
                };
                change_thread.join().unwrap().unwrap();
                let state: String = db
                    .adapter
                    .connect()
                    .unwrap()
                    .query_one(
                        &format!(
                            "select status from {}.auth_sessions where tenant_id=$1 and id=$2",
                            db.schema()
                        ),
                        &[&db.target(), &Uuid::parse_str(&session.session.id).unwrap()],
                    )
                    .unwrap()
                    .get(0);
                assert_eq!(state, "revoked");
            } else {
                change_thread.join().unwrap().unwrap();
                release_tx.send(()).unwrap();
                assert!(matches!(
                    login.join().unwrap(),
                    Err(TenantAuthError::InvalidCredentials)
                ));
            }
        }
    }
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn self_password_change_cas_rejects_snapshot_after_email_change() {
    for mode in [TenancyMode::Disabled, TenancyMode::Enabled] {
        let db = Db::new(mode);
        install(&db);
        set_password(&db, db.actor, OLD_PASSWORD);
        let store = db.store();
        let actor = actor(&db, db.actor_session);
        let snapshot = store
            .password_change_read(
                mode,
                super::self_password_change::AUTHORITY,
                Some(&actor),
                |tx| {
                    assert!(tx.actor_is_active(&actor, FixedClock.now())?);
                    Ok(tx.credential_snapshot(&actor)?.unwrap())
                },
            )
            .unwrap();
        db.adapter
            .connect()
            .unwrap()
            .execute(
                &format!(
                    "update {}.accounts set email='changed@example.test' where id=$1",
                    db.schema()
                ),
                &[&db.actor],
            )
            .unwrap();
        let result = store.password_change_write(
            mode,
            super::self_password_change::AUTHORITY,
            &actor,
            |tx| {
                assert!(tx.actor_is_active(&actor, FixedClock.now())?);
                tx.replace_password_and_retire(
                    &actor,
                    &snapshot,
                    &SecretString::new("must-not-be-stored"),
                    FixedClock.now(),
                )?;
                Ok(())
            },
        );
        assert!(matches!(
            result,
            Err(AccessError::Conflict("security.credentials_changed"))
        ));
        let row = db.adapter.connect().unwrap().query_one(
            &format!("select password_hash,security_credential_version,(select status from {}.auth_sessions where tenant_id='0' and id=$2) from {}.accounts where id=$1", db.schema(), db.schema()),
            &[&db.actor,&db.actor_session],
        ).unwrap();
        assert_eq!(
            row.get::<_, String>(0),
            snapshot.password_hash.expose_secret()
        );
        assert_eq!(row.get::<_, i64>(1), snapshot.credential_version as i64 + 1);
        assert_eq!(row.get::<_, String>(2), "active");
    }
}
