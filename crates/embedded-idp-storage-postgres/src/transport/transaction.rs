use super::{
    runtime::DriverRuntime,
    session::{drive, Drivers},
    Error,
};
use std::{future::Future, sync::atomic::AtomicBool};
use tokio::time::Instant;

/// All transaction semantics and rollback-on-drop remain native tokio-postgres.
pub struct Transaction<'a> {
    inner: Option<tokio_postgres::Transaction<'a>>,
    runtime: &'a DriverRuntime,
    drivers: &'a Drivers,
    failed: &'a AtomicBool,
    deadline: Instant,
}
impl Transaction<'_> {
    fn native(&self) -> &tokio_postgres::Transaction<'_> {
        self.inner.as_ref().unwrap()
    }
    fn run<T: Send>(
        &self,
        future: impl Future<Output = Result<T, tokio_postgres::Error>> + Send,
    ) -> Result<T, Error> {
        drive(
            self.runtime,
            self.drivers,
            self.failed,
            self.deadline,
            future,
        )
    }
    queries!();
    pub fn commit(mut self) -> Result<(), Error> {
        let tx = self.inner.take().unwrap();
        self.run(tx.commit())
    }
    pub fn rollback(mut self) -> Result<(), Error> {
        let tx = self.inner.take().unwrap();
        self.run(tx.rollback())
    }
}

pub struct TransactionBuilder<'a> {
    pub(super) inner: tokio_postgres::TransactionBuilder<'a>,
    pub(super) runtime: &'a DriverRuntime,
    pub(super) drivers: &'a Drivers,
    pub(super) failed: &'a AtomicBool,
    pub(super) deadline: Instant,
}
impl<'a> TransactionBuilder<'a> {
    pub fn isolation_level(mut self, level: tokio_postgres::IsolationLevel) -> Self {
        self.inner = self.inner.isolation_level(level);
        self
    }
    pub fn read_only(mut self, read_only: bool) -> Self {
        self.inner = self.inner.read_only(read_only);
        self
    }
    pub fn start(self) -> Result<Transaction<'a>, Error> {
        let inner = drive(
            self.runtime,
            self.drivers,
            self.failed,
            self.deadline,
            self.inner.start(),
        )?;
        Ok(Transaction {
            inner: Some(inner),
            runtime: self.runtime,
            drivers: self.drivers,
            failed: self.failed,
            deadline: self.deadline,
        })
    }
}
