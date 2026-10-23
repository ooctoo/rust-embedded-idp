mod http;
mod smtp;

use crate::registration_email_support;
use embedded_idp_core::access::*;
use embedded_idp_core::PasswordWorkBudget;
use std::sync::mpsc::{self, Sender};
use std::thread::{self, JoinHandle};

pub use http::{
    post_json, post_without_profile, start_harness, worker_diagnostic_snapshot, HttpResponse,
};
pub use smtp::SmtpSink;

pub use super::registration_email_support::Fixture;

pub struct FixtureGuard(Option<Fixture>);

impl FixtureGuard {
    pub fn new(fixture: Fixture) -> Self {
        Self(Some(fixture))
    }

    pub fn get(&self) -> &Fixture {
        self.0.as_ref().expect("fixture guard")
    }
}

impl Drop for FixtureGuard {
    fn drop(&mut self) {
        if let Some(fixture) = self.0.take() {
            thread::spawn(move || drop(fixture))
                .join()
                .expect("fixture cleanup thread");
        }
    }
}

pub fn install_runtime(fixture: &Fixture) {
    let plan = fixture
        .adapter
        .registration_email_runtime_migration_plan(&fixture.scope)
        .expect("runtime migration plan");
    fixture
        .adapter
        .apply_registration_email_runtime(&plan, &fixture.scope)
        .expect("runtime migration apply");
}

pub fn auth_service(
    fixture: &Fixture,
    budget: PasswordWorkBudget,
) -> std::sync::Arc<dyn TenantAuthenticationService> {
    std::sync::Arc::new(
        registration_email_support::auth_service(fixture).with_password_work_budget(budget),
    )
}

pub fn seed_registration_states(fixture: &Fixture) {
    let mut client = fixture.adapter.connect().expect("fixture connection");
    let password_hash: String = client
        .query_one(
            &format!(
                "select password_hash from {}.accounts where email=$1",
                fixture.schema
            ),
            &[&super::registration_email_support::EXISTING_EMAIL],
        )
        .expect("existing password hash")
        .get(0);
    let mut transaction = client.transaction().expect("seed transaction");
    for (email, status) in [
        ("active@example.test", "active"),
        ("disabled@example.test", "disabled"),
    ] {
        let account_id = uuid::Uuid::now_v7();
        transaction
            .execute(
                &format!(
                    "insert into {}.accounts(id,registration_tenant_id,email,password_hash,display_name,status,created_at_epoch) values($1,$2,$3,$4,$5,'pending_verification',$6)",
                    fixture.schema
                ),
                &[
                    &account_id,
                    &super::registration_email_support::TENANT,
                    &email,
                    &password_hash,
                    &None::<String>,
                    &1_i64,
                ],
            )
            .expect("seed account");
        transaction
            .execute(
                &format!(
                    "insert into {}.access_memberships(tenant_id,account_id,status,version,joined_at_epoch) values($1,$2,'active',1,$3)",
                    fixture.schema
                ),
                &[&super::registration_email_support::TENANT, &account_id, &1_i64],
            )
            .expect("seed membership");
        transaction
            .execute(
                &format!(
                    "update {}.accounts set status=$2 where id=$1",
                    fixture.schema
                ),
                &[&account_id, &status],
            )
            .expect("activate seeded account");
    }
    transaction.commit().expect("seed transaction commit");
}

pub struct AccountLockGuard {
    release: Option<Sender<()>>,
    thread: Option<JoinHandle<()>>,
}

pub fn hold_account_lock(fixture: &Fixture, email: &str) -> AccountLockGuard {
    let adapter = fixture.adapter.clone();
    let schema = fixture.schema.clone();
    let email = email.to_owned();
    let (ready_send, ready_receive) = mpsc::sync_channel(1);
    let (release_send, release_receive) = mpsc::channel();
    let thread = thread::spawn(move || {
        let result = (|| -> Result<(), String> {
            let mut client = adapter.connect().map_err(|error| format!("{error:?}"))?;
            let mut transaction = client.transaction().map_err(|error| format!("{error:?}"))?;
            transaction
                .query_one(
                    &format!("select id from {schema}.accounts where email=$1 for update"),
                    &[&email],
                )
                .map_err(|error| format!("{error:?}"))?;
            ready_send.send(Ok(())).map_err(|error| error.to_string())?;
            release_receive.recv().map_err(|error| error.to_string())?;
            transaction
                .rollback()
                .map_err(|error| format!("{error:?}"))?;
            Ok(())
        })();
        if let Err(error) = result {
            let _ = ready_send.send(Err(error));
        }
    });
    match ready_receive.recv().expect("account lock thread") {
        Ok(()) => AccountLockGuard {
            release: Some(release_send),
            thread: Some(thread),
        },
        Err(error) => {
            let _ = release_send.send(());
            let _ = thread.join();
            panic!("account lock setup: {error}");
        }
    }
}

impl Drop for AccountLockGuard {
    fn drop(&mut self) {
        if let Some(release) = self.release.take() {
            let _ = release.send(());
        }
        if let Some(thread) = self.thread.take() {
            thread.join().expect("account lock thread");
        }
    }
}
