use std::{
    cell::{Cell, RefCell},
    fmt,
    future::Future,
};
use tokio::{
    runtime::Runtime,
    sync::OwnedSemaphorePermit,
    task::JoinSet,
    time::{timeout_at, Instant},
};
use tokio_postgres::{types::ToSql, Row};
type Drivers = RefCell<JoinSet<Result<(), tokio_postgres::Error>>>;

pub(crate) enum Error {
    Database(tokio_postgres::Error),
    Closed,
}
impl Error {
    pub(crate) fn code(&self) -> Option<&tokio_postgres::error::SqlState> {
        match self {
            Self::Database(e) => e.code(),
            Self::Closed => None,
        }
    }
}
impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("registration database transport unavailable")
    }
}

pub(crate) struct Client {
    runtime: Runtime,
    client: tokio_postgres::Client,
    drivers: Drivers,
    failed: Cell<bool>,
    deadline: Instant,
    // Dropped only after Drop has joined the actual driver.
    _slot: OwnedSemaphorePermit,
}
impl Client {
    pub(crate) fn new(
        runtime: Runtime,
        client: tokio_postgres::Client,
        drivers: JoinSet<Result<(), tokio_postgres::Error>>,
        slot: OwnedSemaphorePermit,
        deadline: Instant,
    ) -> Self {
        Self {
            runtime,
            client,
            drivers: RefCell::new(drivers),
            failed: Cell::new(false),
            deadline,
            _slot: slot,
        }
    }
    pub(crate) fn transaction(&mut self) -> Result<Transaction<'_>, Error> {
        let inner = drive(
            &self.runtime,
            &self.drivers,
            &self.failed,
            self.deadline,
            self.client.transaction(),
        )?;
        Ok(Transaction {
            inner: Some(inner),
            runtime: &self.runtime,
            drivers: &self.drivers,
            failed: &self.failed,
            deadline: self.deadline,
        })
    }
    pub(crate) fn query_opt(
        &mut self,
        sql: &str,
        params: &[&(dyn ToSql + Sync)],
    ) -> Result<Option<Row>, Error> {
        drive(
            &self.runtime,
            &self.drivers,
            &self.failed,
            self.deadline,
            self.client.query_opt(sql, params),
        )
    }
}
impl Drop for Client {
    fn drop(&mut self) {
        self.runtime.block_on(self.drivers.borrow_mut().shutdown());
    }
}

/// Delegates transaction semantics, rollback-on-drop and COMMIT to the native
/// driver. The bridge adds only the one absolute transport deadline.
pub(crate) struct Transaction<'a> {
    inner: Option<tokio_postgres::Transaction<'a>>,
    runtime: &'a Runtime,
    drivers: &'a Drivers,
    failed: &'a Cell<bool>,
    deadline: Instant,
}
impl Transaction<'_> {
    fn run<T>(
        &self,
        future: impl Future<Output = Result<T, tokio_postgres::Error>>,
    ) -> Result<T, Error> {
        drive(
            self.runtime,
            self.drivers,
            self.failed,
            self.deadline,
            future,
        )
    }
    pub(crate) fn query(
        &mut self,
        sql: &str,
        params: &[&(dyn ToSql + Sync)],
    ) -> Result<Vec<Row>, Error> {
        self.run(self.inner.as_ref().unwrap().query(sql, params))
    }
    pub(crate) fn query_one(
        &mut self,
        sql: &str,
        params: &[&(dyn ToSql + Sync)],
    ) -> Result<Row, Error> {
        self.run(self.inner.as_ref().unwrap().query_one(sql, params))
    }
    pub(crate) fn query_opt(
        &mut self,
        sql: &str,
        params: &[&(dyn ToSql + Sync)],
    ) -> Result<Option<Row>, Error> {
        self.run(self.inner.as_ref().unwrap().query_opt(sql, params))
    }
    pub(crate) fn execute(
        &mut self,
        sql: &str,
        params: &[&(dyn ToSql + Sync)],
    ) -> Result<u64, Error> {
        self.run(self.inner.as_ref().unwrap().execute(sql, params))
    }
    pub(crate) fn batch_execute(&mut self, sql: &str) -> Result<(), Error> {
        self.run(self.inner.as_ref().unwrap().batch_execute(sql))
    }
    pub(crate) fn commit(mut self) -> Result<(), Error> {
        let tx = self.inner.take().unwrap();
        self.run(tx.commit())
    }
    pub(crate) fn rollback(mut self) -> Result<(), Error> {
        let tx = self.inner.take().unwrap();
        self.run(tx.rollback())
    }
}
fn drive<T>(
    runtime: &Runtime,
    drivers: &Drivers,
    failed: &Cell<bool>,
    deadline: Instant,
    future: impl Future<Output = Result<T, tokio_postgres::Error>>,
) -> Result<T, Error> {
    if failed.get() || Instant::now() >= deadline {
        failed.set(true);
        runtime.block_on(drivers.borrow_mut().shutdown());
        return Err(Error::Closed);
    }
    match runtime.block_on(async { timeout_at(deadline, future).await }) {
        Ok(result) => result.map_err(Error::Database),
        Err(_) => {
            failed.set(true);
            runtime.block_on(drivers.borrow_mut().shutdown());
            Err(Error::Closed)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    use std::time::Duration;
    #[test]
    fn expired_deadline_never_polls_database_work() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let drivers = RefCell::new(JoinSet::new());
        let failed = Cell::new(false);
        let result: Result<(), Error> = drive(
            &runtime,
            &drivers,
            &failed,
            Instant::now() - Duration::from_secs(1),
            async { panic!("expired database work was polled") },
        );
        assert!(matches!(result, Err(Error::Closed)));
        assert!(failed.get());
    }
    #[test]
    fn deadline_returns_only_after_driver_future_is_dropped() {
        struct Guard(Arc<AtomicUsize>);
        impl Drop for Guard {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let drivers = RefCell::new(JoinSet::new());
        let stopped = Arc::new(AtomicUsize::new(0));
        runtime.block_on(async {
            let guard = Guard(stopped.clone());
            drivers.borrow_mut().spawn(async move {
                let _guard = guard;
                std::future::pending::<()>().await;
                Ok(())
            });
            tokio::task::yield_now().await;
        });
        let result: Result<(), Error> = drive(
            &runtime,
            &drivers,
            &Cell::new(false),
            Instant::now() + Duration::from_millis(40),
            std::future::pending(),
        );
        assert!(matches!(result, Err(Error::Closed)));
        assert_eq!(stopped.load(Ordering::SeqCst), 1);
        assert!(drivers.borrow().is_empty());
    }
}
