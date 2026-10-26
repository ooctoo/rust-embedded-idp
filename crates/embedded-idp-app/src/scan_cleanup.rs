use embedded_idp_core::access::{TenantDeviceScanLoginService, TrustedScanHostContext};
use std::{
    future::Future,
    sync::Arc,
    time::{Duration, Instant, SystemTime},
};
use tokio::{sync::watch, task::JoinHandle};

pub(crate) struct ScanCleanupJob {
    pub service: Arc<dyn TenantDeviceScanLoginService>,
    pub host_scope: String,
    pub interval_secs: u64,
    pub batch_size: u32,
}

pub(crate) fn spawn(jobs: Vec<ScanCleanupJob>, stop: watch::Receiver<bool>) -> JoinHandle<()> {
    tokio::spawn(run_jobs(jobs, stop))
}

async fn run_jobs(jobs: Vec<ScanCleanupJob>, stop: watch::Receiver<bool>) {
    let intervals = jobs
        .iter()
        .map(|job| Duration::from_secs(job.interval_secs.max(1)))
        .collect();
    run_schedule(intervals, stop, move |index| {
        let job = &jobs[index];
        let service = job.service.clone();
        let scope = job.host_scope.clone();
        let batch_size = job.batch_size;
        async move {
            let host =
                TrustedScanHostContext::new(scope, SystemTime::now() + Duration::from_secs(60));
            matches!(
                tokio::task::spawn_blocking(move || service.cleanup(host, batch_size)).await,
                Ok(Ok(_))
            )
        }
    })
    .await;
}

async fn run_schedule<F, Fut>(
    intervals: Vec<Duration>,
    mut stop: watch::Receiver<bool>,
    mut run_one: F,
) where
    F: FnMut(usize) -> Fut,
    Fut: Future<Output = bool>,
{
    if intervals.is_empty() {
        return;
    }
    let mut deadlines: Vec<_> = intervals
        .iter()
        .map(|interval| Instant::now() + *interval)
        .collect();

    loop {
        if *stop.borrow() {
            return;
        }
        let next = *deadlines.iter().min().expect("non-empty cleanup jobs");
        tokio::select! {
            _ = tokio::time::sleep_until(next.into()) => {}
            changed = stop.changed() => {
                if changed.is_err() || *stop.borrow() {
                    return;
                }
            }
        }
        if *stop.borrow() {
            return;
        }

        let due = Instant::now();
        for index in 0..deadlines.len() {
            if *stop.borrow() {
                return;
            }
            if deadlines[index] > due {
                continue;
            }
            if !run_one(index).await {
                eprintln!("scan-login cleanup failed for job {index}; retrying next interval");
            }
            // Schedule from completion. Missed intervals are skipped, never replayed.
            deadlines[index] = Instant::now() + intervals[index];
        }
    }
}

#[cfg(test)]
mod tests {
    use super::run_schedule;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    };
    use tokio::sync::{oneshot, watch};

    #[tokio::test]
    async fn work_does_not_overlap_or_replay_missed_intervals() {
        let (stop_tx, stop_rx) = watch::channel(false);
        let active = Arc::new(AtomicUsize::new(0));
        let starts = Arc::new(AtomicUsize::new(0));
        let start_times = Arc::new(Mutex::new(Vec::new()));
        let first_started = Arc::new(tokio::sync::Notify::new());
        let active_for_run = active.clone();
        let starts_for_run = starts.clone();
        let start_times_for_run = start_times.clone();
        let first_started_for_run = first_started.clone();
        let stop_on_second = stop_tx.clone();
        let task = tokio::spawn(async move {
            run_schedule(
                vec![std::time::Duration::from_millis(10)],
                stop_rx,
                move |_| {
                    let active = active_for_run.clone();
                    let starts = starts_for_run.clone();
                    let start_times = start_times_for_run.clone();
                    let first_started = first_started_for_run.clone();
                    let stop = stop_on_second.clone();
                    async move {
                        assert_eq!(active.fetch_add(1, Ordering::SeqCst), 0);
                        let count = starts.fetch_add(1, Ordering::SeqCst) + 1;
                        start_times.lock().unwrap().push(std::time::Instant::now());
                        if count == 1 {
                            first_started.notify_one();
                        }
                        tokio::time::sleep(std::time::Duration::from_millis(40)).await;
                        active.fetch_sub(1, Ordering::SeqCst);
                        if count == 2 {
                            let _ = stop.send(true);
                        }
                        count != 1
                    }
                },
            )
            .await;
        });
        first_started.notified().await;
        task.await.unwrap();
        assert_eq!(starts.load(Ordering::SeqCst), 2);
        let times = start_times.lock().unwrap();
        assert!(times[1].duration_since(times[0]) >= std::time::Duration::from_millis(45));
    }

    #[tokio::test]
    async fn stop_waits_for_current_work_and_prevents_another_batch() {
        let (stop_tx, stop_rx) = watch::channel(false);
        let calls = Arc::new(AtomicUsize::new(0));
        let started = Arc::new(tokio::sync::Notify::new());
        let (release_tx, release_rx) = oneshot::channel::<()>();
        let release_rx = Arc::new(tokio::sync::Mutex::new(Some(release_rx)));
        let calls_for_run = calls.clone();
        let started_for_run = started.clone();
        let task = tokio::spawn(async move {
            run_schedule(
                vec![std::time::Duration::from_millis(1)],
                stop_rx,
                move |_| {
                    let calls = calls_for_run.clone();
                    let started = started_for_run.clone();
                    let release_rx = release_rx.clone();
                    async move {
                        calls.fetch_add(1, Ordering::SeqCst);
                        started.notify_one();
                        if let Some(receiver) = release_rx.lock().await.take() {
                            let _ = receiver.await;
                        }
                        true
                    }
                },
            )
            .await;
        });
        started.notified().await;
        stop_tx.send(true).unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        release_tx.send(()).unwrap();
        task.await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn multiple_jobs_make_progress_sequentially_without_overlap() {
        let (stop_tx, stop_rx) = watch::channel(false);
        let counts = Arc::new([AtomicUsize::new(0), AtomicUsize::new(0)]);
        let active = Arc::new(AtomicUsize::new(0));
        let order = Arc::new(Mutex::new(Vec::new()));
        let task = tokio::spawn({
            let counts = counts.clone();
            let active = active.clone();
            let order = order.clone();
            async move {
                run_schedule(
                    vec![
                        std::time::Duration::from_millis(5),
                        std::time::Duration::from_millis(5),
                    ],
                    stop_rx,
                    move |index| {
                        let counts = counts.clone();
                        let active = active.clone();
                        let order = order.clone();
                        let stop = stop_tx.clone();
                        async move {
                            assert_eq!(active.fetch_add(1, Ordering::SeqCst), 0);
                            order.lock().unwrap().push(index);
                            let count = counts[index].fetch_add(1, Ordering::SeqCst) + 1;
                            tokio::time::sleep(std::time::Duration::from_millis(15)).await;
                            active.fetch_sub(1, Ordering::SeqCst);
                            if count >= 2
                                && counts.iter().all(|count| count.load(Ordering::SeqCst) >= 2)
                            {
                                let _ = stop.send(true);
                            }
                            true
                        }
                    },
                )
                .await;
            }
        });
        tokio::time::timeout(std::time::Duration::from_millis(500), task)
            .await
            .expect("both cleanup jobs should keep making progress")
            .unwrap();
        assert!(counts.iter().all(|count| count.load(Ordering::SeqCst) >= 2));
        let order = order.lock().unwrap();
        assert!(order.contains(&0));
        assert!(order.contains(&1));
    }
}
