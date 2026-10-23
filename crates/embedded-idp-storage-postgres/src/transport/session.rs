use super::{runtime::blocking, runtime::DriverRuntime, Error, Transaction, TransactionBuilder};
use std::{
    future::Future,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
};
use tokio::{
    sync::OwnedSemaphorePermit,
    task::JoinSet,
    time::{timeout_at, Instant},
};

pub(super) type Drivers = Mutex<JoinSet<Result<(), Error>>>;

/// One fresh, bounded connection. Capacity is shared by every adapter clone and
/// released only after its actual connection driver has ended.
pub struct Client {
    pub(super) runtime: Arc<DriverRuntime>,
    pub(super) client: tokio_postgres::Client,
    pub(super) drivers: Drivers,
    pub(super) failed: AtomicBool,
    pub(super) deadline: Instant,
    _slot: OwnedSemaphorePermit,
}
impl Client {
    pub(super) fn new(
        runtime: Arc<DriverRuntime>,
        client: tokio_postgres::Client,
        drivers: JoinSet<Result<(), Error>>,
        slot: OwnedSemaphorePermit,
        deadline: Instant,
    ) -> Self {
        Self {
            runtime,
            client,
            drivers: Mutex::new(drivers),
            failed: AtomicBool::new(false),
            deadline,
            _slot: slot,
        }
    }
    fn native(&self) -> &tokio_postgres::Client {
        &self.client
    }
    fn run<T: Send>(
        &self,
        future: impl Future<Output = Result<T, tokio_postgres::Error>> + Send,
    ) -> Result<T, Error> {
        drive(
            &self.runtime,
            &self.drivers,
            &self.failed,
            self.deadline,
            future,
        )
    }
    queries!();
    pub fn transaction(&mut self) -> Result<Transaction<'_>, Error> {
        self.build_transaction().start()
    }
    pub fn build_transaction(&mut self) -> TransactionBuilder<'_> {
        TransactionBuilder {
            inner: self.client.build_transaction(),
            runtime: &self.runtime,
            drivers: &self.drivers,
            failed: &self.failed,
            deadline: self.deadline,
        }
    }
}
impl Drop for Client {
    fn drop(&mut self) {
        blocking(|| {
            self.runtime
                .get()
                .block_on(self.drivers.lock().unwrap().shutdown())
        });
    }
}

pub(super) fn drive<T: Send>(
    runtime: &DriverRuntime,
    drivers: &Drivers,
    failed: &AtomicBool,
    deadline: Instant,
    future: impl Future<Output = Result<T, tokio_postgres::Error>> + Send,
) -> Result<T, Error> {
    blocking(|| {
        if failed.load(Ordering::Acquire) || Instant::now() >= deadline {
            failed.store(true, Ordering::Release);
            runtime.get().block_on(drivers.lock().unwrap().shutdown());
            return Err(Error::Closed);
        }
        match runtime
            .get()
            .block_on(async { timeout_at(deadline, future).await })
        {
            Ok(value) => value.map_err(Error::Database),
            Err(_) => {
                failed.store(true, Ordering::Release);
                runtime.get().block_on(drivers.lock().unwrap().shutdown());
                Err(Error::Closed)
            }
        }
    })
}

#[cfg(test)]
#[path = "session_tests.rs"]
mod tests;
