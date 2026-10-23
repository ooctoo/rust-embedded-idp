use super::*;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::time::Duration;
#[test]
fn expired_deadline_never_polls_database_work() {
    let runtime = DriverRuntime::new().unwrap();
    let drivers = Mutex::new(JoinSet::new());
    let failed = AtomicBool::new(false);
    let result: Result<(), Error> = drive(
        &runtime,
        &drivers,
        &failed,
        Instant::now() - Duration::from_secs(1),
        async { panic!("expired database work was polled") },
    );
    assert!(matches!(result, Err(Error::Closed)));
    assert!(failed.load(Ordering::Acquire));
}
#[test]
fn deadline_returns_only_after_driver_future_is_dropped() {
    struct Guard(Arc<AtomicUsize>);
    impl Drop for Guard {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    let runtime = DriverRuntime::new().unwrap();
    let drivers = Mutex::new(JoinSet::new());
    let stopped = Arc::new(AtomicUsize::new(0));
    runtime.get().block_on(async {
        let guard = Guard(stopped.clone());
        drivers.lock().unwrap().spawn(async move {
            let _guard = guard;
            std::future::pending::<()>().await;
            Ok(())
        });
        tokio::task::yield_now().await;
    });
    let result: Result<(), Error> = drive(
        &runtime,
        &drivers,
        &AtomicBool::new(false),
        Instant::now() + Duration::from_millis(40),
        std::future::pending(),
    );
    assert!(matches!(result, Err(Error::Closed)));
    assert_eq!(stopped.load(Ordering::SeqCst), 1);
    assert!(drivers.lock().unwrap().is_empty());
}
