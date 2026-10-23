use super::*;

#[tokio::test]
async fn shutdown_reports_aborted_outer_task_without_polling_it_twice() {
    let service = Arc::new(FakeService::new());
    let runtime = runtime(service.clone());
    let workers = runtime.start().await.unwrap();
    let (release_tx, entered) = service.block_facts();
    tokio::time::timeout(Duration::from_secs(1), entered.notified())
        .await
        .expect("facts call started");

    workers.task.as_ref().expect("worker task").abort();
    let shutdown = tokio::time::timeout(
        Duration::from_secs(1),
        workers.shutdown(Duration::from_secs(1)),
    )
    .await
    .expect("bounded shutdown");
    assert!(!shutdown.drained);
    assert!(shutdown.failed);
    assert_eq!(shutdown.unresolved_storage, 1);

    release_tx.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if runtime.unresolved_storage() == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("storage call ended");
    assert_eq!(runtime.unresolved_storage(), 0);
}
