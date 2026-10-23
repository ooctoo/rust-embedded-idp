use super::Error;
use tokio::runtime::{Builder, Handle, Runtime, RuntimeFlavor};

/// Synchronous callers may own/drop a lease from either kind of Host runtime.
/// Keep the driver's runtime and its destruction outside an async executor.
pub(super) fn blocking<T: Send>(f: impl FnOnce() -> T + Send) -> T {
    match Handle::try_current().map(|h| h.runtime_flavor()) {
        Ok(RuntimeFlavor::MultiThread) => tokio::task::block_in_place(f),
        Ok(_) => std::thread::scope(|scope| match scope.spawn(f).join() {
            Ok(value) => value,
            Err(panic) => std::panic::resume_unwind(panic),
        }),
        Err(_) => f(),
    }
}

pub(super) struct DriverRuntime(Option<Runtime>);
impl DriverRuntime {
    pub(super) fn new() -> Result<Self, Error> {
        blocking(|| {
            Builder::new_multi_thread()
                .worker_threads(1)
                .enable_all()
                .build()
                .map(|runtime| Self(Some(runtime)))
                .map_err(|_| Error::Closed)
        })
    }
    pub(super) fn get(&self) -> &Runtime {
        self.0.as_ref().expect("owned driver runtime")
    }
}
impl Drop for DriverRuntime {
    fn drop(&mut self) {
        if let Some(runtime) = self.0.take() {
            blocking(move || drop(runtime));
        }
    }
}
