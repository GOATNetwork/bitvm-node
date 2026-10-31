//! In-memory wakeups. They only accelerate the workers, publisher and executor;
//! the database is the source of truth and every loop also polls.

use crate::event::AggregateRef;
use std::sync::Arc;
use tokio::sync::Notify;

#[derive(Clone, Debug)]
pub(crate) struct EngineWake {
    workers: Arc<Vec<Arc<Notify>>>,
    publisher: Arc<Notify>,
    executor: Arc<Notify>,
}

impl EngineWake {
    pub(crate) fn new(shard_count: usize) -> Self {
        Self {
            workers: Arc::new((0..shard_count.max(1)).map(|_| Arc::new(Notify::new())).collect()),
            publisher: Arc::new(Notify::new()),
            executor: Arc::new(Notify::new()),
        }
    }

    pub(crate) fn shard_count(&self) -> usize {
        self.workers.len()
    }

    pub(crate) fn worker_notify(&self, shard: usize) -> Arc<Notify> {
        self.workers[shard % self.workers.len()].clone()
    }

    pub(crate) fn worker_for(&self, aggregate: &AggregateRef) {
        self.workers[aggregate.shard(self.workers.len())].notify_one();
    }

    pub(crate) fn workers_all(&self) {
        for worker in self.workers.iter() {
            worker.notify_one();
        }
    }

    pub(crate) fn publisher_notify(&self) -> Arc<Notify> {
        self.publisher.clone()
    }

    pub(crate) fn publisher(&self) {
        self.publisher.notify_one();
    }

    pub(crate) fn executor_notify(&self) -> Arc<Notify> {
        self.executor.clone()
    }

    pub(crate) fn executor(&self) {
        self.executor.notify_one();
    }
}

/// Run `future` on a dedicated thread with `stack_bytes` of stack (0 runs it as
/// a tokio task). The returned handle resolves when the future finished.
pub(crate) fn spawn_on_thread<F>(
    name: String,
    stack_bytes: usize,
    future: F,
) -> tokio::task::JoinHandle<()>
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    if stack_bytes == 0 {
        return tokio::spawn(future);
    }
    let runtime = tokio::runtime::Handle::current();
    let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();
    std::thread::Builder::new()
        .name(name)
        .stack_size(stack_bytes)
        .spawn(move || {
            runtime.block_on(future);
            let _ = done_tx.send(());
        })
        .expect("spawn engine thread");
    tokio::spawn(async move {
        let _ = done_rx.await;
    })
}

pub(crate) fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(message) = payload.downcast_ref::<&'static str>() {
        (*message).to_owned()
    } else if let Some(message) = payload.downcast_ref::<String>() {
        message.clone()
    } else {
        "non-string panic payload".to_owned()
    }
}
