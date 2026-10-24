use super::*;

async fn storage_ended(runtime: &RegistrationEmailRuntime) {
    tokio::time::timeout(Duration::from_secs(1), async {
        while runtime.unresolved_storage() != 0 {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("physical storage closure ended");
}

#[tokio::test]
async fn operator_resume_requires_running_admission_and_can_clear_checked_failure() {
    let service = Arc::new(FakeService::new());
    let runtime = runtime(service.clone());
    assert!(runtime.resume_after_operator_check().await.is_err());
    let workers = runtime.start().await.unwrap();
    runtime.pause().await;
    assert!(service.is_paused());
    assert!(!runtime.worker_running());
    runtime.resume_after_operator_check().await.unwrap();
    assert!(!service.is_paused());
    assert!(runtime.worker_running());
    workers.begin_shutdown(Duration::from_secs(1));
    assert!(runtime.resume_after_operator_check().await.is_err());
    let report = workers.shutdown(Duration::from_secs(1)).await;
    assert!(report.drained);
    assert!(!report.failed);
}

#[tokio::test]
async fn stopped_resume_keeps_failure_and_physical_admission_until_storage_ends() {
    let service = Arc::new(FakeService::new());
    let runtime = runtime(service.clone());
    let workers = runtime.start().await.unwrap();
    runtime.pause().await;
    let (release, entered) = install_block(&service.resume_block);
    let pending = {
        let runtime = runtime.clone();
        tokio::spawn(async move { runtime.resume_after_operator_check().await })
    };
    tokio::time::timeout(Duration::from_secs(1), entered.notified())
        .await
        .unwrap();
    let report = workers.shutdown(Duration::from_millis(30)).await;
    release.send(()).unwrap();
    let result = pending.await.unwrap();
    storage_ended(&runtime).await;
    assert!(!report.drained);
    assert!(report.failed);
    assert!(report.unresolved_storage >= 1);
    assert_eq!(report.unresolved_requests, 1);
    assert!(result.is_err());
    assert!(runtime.failed.load(Ordering::Acquire));
    assert!(!runtime.worker_running());
    assert_eq!(runtime.unresolved_requests(), 0);
    assert!(runtime.resume_after_operator_check().await.is_err());
}

#[tokio::test]
async fn cancelled_resume_holds_physical_permit_without_clearing_failure() {
    let service = Arc::new(FakeService::new());
    let runtime = runtime(service.clone());
    let workers = runtime.start().await.unwrap();
    runtime.pause().await;
    let (release, entered) = install_block(&service.resume_block);
    let pending = {
        let runtime = runtime.clone();
        tokio::spawn(async move { runtime.resume_after_operator_check().await })
    };
    tokio::time::timeout(Duration::from_secs(1), entered.notified())
        .await
        .unwrap();
    pending.abort();
    assert!(pending.await.unwrap_err().is_cancelled());
    let held = runtime.unresolved_requests();
    let storage = runtime.unresolved_storage();
    release.send(()).unwrap();
    storage_ended(&runtime).await;
    assert_eq!(held, 1);
    assert!(storage >= 1);
    assert_eq!(runtime.unresolved_requests(), 0);
    assert!(runtime.failed.load(Ordering::Acquire));
    let report = workers.shutdown(Duration::from_secs(1)).await;
    assert!(report.drained);
    assert!(report.failed);
}

#[tokio::test]
async fn older_resume_cannot_clear_a_new_failure_or_overwrite_its_pause() {
    let service = Arc::new(FakeService::new());
    let runtime = runtime(service.clone());
    let workers = runtime.start().await.unwrap();
    runtime.pause().await;
    let (release, entered) = install_block(&service.resume_block);
    let pending = {
        let runtime = runtime.clone();
        tokio::spawn(async move { runtime.resume_after_operator_check().await })
    };
    tokio::time::timeout(Duration::from_secs(1), entered.notified())
        .await
        .unwrap();
    let pause = runtime.pause();
    tokio::pin!(pause);
    // Poll the new fault through its synchronous latch before releasing the
    // older physical resume, regardless of blocking-pool scheduling order.
    std::future::poll_fn(|cx| {
        assert!(std::future::Future::poll(pause.as_mut(), cx).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
    release.send(()).unwrap();
    let (resumed, ()) = tokio::join!(pending, &mut pause);
    assert!(resumed.unwrap().is_err());
    assert!(runtime.failed.load(Ordering::Acquire));
    assert!(service.is_paused());
    assert!(!runtime.worker_running());
    let report = workers.shutdown(Duration::from_secs(1)).await;
    assert!(report.drained);
    assert!(report.failed);
}

#[tokio::test]
async fn queued_operator_resume_is_bounded_and_cannot_dispatch_after_stop() {
    let service = Arc::new(FakeService::new());
    let runtime = runtime(service.clone());
    let workers = runtime.start().await.unwrap();
    runtime.pause().await;
    let (release, entered) = install_block(&service.resume_block);
    let mut calls = Vec::new();
    for _ in 0..4 {
        let runtime = runtime.clone();
        calls.push(tokio::spawn(async move {
            runtime.resume_after_operator_check().await
        }));
    }
    tokio::time::timeout(Duration::from_secs(1), entered.notified())
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(1), async {
        while runtime.unresolved_requests() != 4 {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .unwrap();
    assert!(runtime.resume_after_operator_check().await.is_err());
    workers.begin_shutdown(Duration::from_secs(1));
    release.send(()).unwrap();
    for call in calls {
        assert!(call.await.unwrap().is_err());
    }
    assert_eq!(service.resume_calls.load(AtomicOrdering::Acquire), 1);
    assert_eq!(runtime.unresolved_requests(), 0);
    assert!(runtime.failed.load(Ordering::Acquire));
    let report = workers.shutdown(Duration::from_secs(1)).await;
    assert!(report.drained);
    assert!(report.failed);
}

#[tokio::test]
async fn queued_pause_does_not_add_a_write_after_stop() {
    let service = Arc::new(FakeService::new());
    let runtime = runtime(service.clone());
    let workers = runtime.start().await.unwrap();
    runtime.pause().await;
    let (release, entered) = install_block(&service.resume_block);
    let pending = {
        let runtime = runtime.clone();
        tokio::spawn(async move { runtime.resume_after_operator_check().await })
    };
    tokio::time::timeout(Duration::from_secs(1), entered.notified())
        .await
        .unwrap();
    let pause = runtime.pause();
    tokio::pin!(pause);
    std::future::poll_fn(|cx| {
        assert!(std::future::Future::poll(pause.as_mut(), cx).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
    workers.begin_shutdown(Duration::from_secs(1));
    release.send(()).unwrap();
    let (resumed, ()) = tokio::join!(pending, &mut pause);
    assert!(resumed.unwrap().is_err());
    assert_eq!(service.pause_calls(), 1);
    assert_eq!(service.resume_calls.load(AtomicOrdering::Acquire), 1);
    let report = workers.shutdown(Duration::from_secs(1)).await;
    assert!(report.drained);
    assert!(report.failed);
}
