//! Proving backends, the GPU gate and shutdown draining shared by every proof task.
//!
//! In Fleet mode every builder shares one client of the replica's dedicated GPU server.
//! The server runs one proof at a time, so a FIFO gate serializes program setup and each
//! proving unit (prove, publish and database commit). Units are tracked so shutdown can
//! wait for the one in progress instead of abandoning a proof that is being committed.

use crate::fleet::{ProgramsFile, verify_program};
use anyhow::anyhow;
use proof_builder::{ProofBuilder, ProofRequest, ProverCallError};
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use zkm_cuda::ZKMGpuServer;
use zkm_sdk::provers::CudaProver;
use zkm_sdk::{HashableKey, ProverClient, ZKMProver};

/// Proving stopped because the worker is shutting down.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Cancelled;

impl std::fmt::Display for Cancelled {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("proving stopped for shutdown")
    }
}

impl std::error::Error for Cancelled {}

/// How a proving failure should be handled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Failure {
    /// The prover call failed although its guest executes and the prover stays healthy,
    /// for example on a transport error. The task is retried in place and the failure does
    /// not count as an attempt.
    Transient,
    /// The GPU server no longer reports ready. In Fleet mode the worker exits so Fleet
    /// restarts the replica together with its GPU server; the task stays pending.
    ProverUnavailable,
    /// The proof itself failed: the guest rejects its input, or the result is invalid.
    Fatal,
}

/// A proof that was generated, verified and published.
#[derive(Debug, Clone)]
pub(crate) struct Proved {
    pub cycles: u64,
    pub proving_time: f32,
    pub public_value_hex: String,
    pub proof_size: usize,
    pub zkm_version: String,
}

/// Why proving and publishing did not complete.
#[derive(Debug)]
pub(crate) enum ProveError {
    Prove(anyhow::Error, Failure),
    /// Writing the proof artifacts failed.
    Save(anyhow::Error),
}

enum Backend {
    Sdk,
    Fleet {
        client: Arc<ProverClient>,
        gpu_endpoint: String,
        http: reqwest::Client,
        programs: ProgramsFile,
    },
}

struct Inner {
    backend: Backend,
    gate: Option<Arc<Semaphore>>,
    units: TaskTracker,
    closing: CancellationToken,
    max_attempts: u32,
}

#[derive(Clone)]
pub(crate) struct ProverRuntime(Arc<Inner>);

const GPU_READY_PROBES: usize = 3;
const GPU_READY_INTERVAL: Duration = Duration::from_secs(2);

impl ProverRuntime {
    /// Each builder creates its own SDK client (`ZKM_PROVER`); proofs run concurrently.
    pub(crate) fn sdk(max_attempts: u32) -> Self {
        Self::with_backend(Backend::Sdk, None, max_attempts)
    }

    /// Every builder shares one client of the replica's loopback GPU server.
    pub(crate) async fn fleet(
        gpu_endpoint: String,
        programs: ProgramsFile,
        max_attempts: u32,
    ) -> anyhow::Result<Self> {
        let endpoint = gpu_endpoint.clone();
        let client = tokio::task::spawn_blocking(move || ProverClient {
            prover: Box::new(CudaProver::new(
                ZKMProver::new(),
                ZKMGpuServer::External { endpoint },
            )),
        })
        .await?;
        let http = reqwest::Client::builder().timeout(Duration::from_secs(3)).build()?;
        let backend = Backend::Fleet { client: Arc::new(client), gpu_endpoint, http, programs };
        Ok(Self::with_backend(backend, Some(Arc::new(Semaphore::new(1))), max_attempts))
    }

    fn with_backend(backend: Backend, gate: Option<Arc<Semaphore>>, max_attempts: u32) -> Self {
        Self(Arc::new(Inner {
            backend,
            gate,
            units: TaskTracker::new(),
            closing: CancellationToken::new(),
            max_attempts: max_attempts.max(1),
        }))
    }

    pub(crate) fn is_fleet(&self) -> bool {
        matches!(self.0.backend, Backend::Fleet { .. })
    }

    /// Consecutive non-retryable failures before an on-demand task is marked failed.
    pub(crate) fn max_attempts(&self) -> u32 {
        self.0.max_attempts
    }

    /// Sets a program up. In Fleet mode the setup runs on the GPU server under the gate
    /// and its verifying key must match the packaged program list.
    pub(crate) async fn builder<B, F>(&self, ctor: F) -> anyhow::Result<Arc<B>>
    where
        B: ProofBuilder + Send + Sync + 'static,
        F: FnOnce(Arc<ProverClient>) -> B + Send + 'static,
    {
        let shared = match &self.0.backend {
            Backend::Sdk => None,
            Backend::Fleet { client, .. } => Some(client.clone()),
        };
        let builder = self
            .run(blocking(move || ctor(shared.unwrap_or_else(|| Arc::new(ProverClient::new())))))
            .await??;
        if let Backend::Fleet { programs, .. } = &self.0.backend {
            verify_program(programs, &builder.pk().elf, &builder.vk().bytes32())?;
        }
        Ok(Arc::new(builder))
    }

    /// Runs one proving unit under the GPU gate. The unit is tracked for draining and keeps
    /// running if the calling task is dropped, so a started proof is always committed or
    /// abandoned as a whole.
    pub(crate) async fn run<T, F>(&self, unit: F) -> Result<T, Cancelled>
    where
        F: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        if self.0.closing.is_cancelled() {
            return Err(Cancelled);
        }
        let permit = match &self.0.gate {
            Some(gate) => Some(gate.clone().acquire_owned().await.map_err(|_| Cancelled)?),
            None => None,
        };
        if self.0.closing.is_cancelled() {
            return Err(Cancelled);
        }
        let handle = self.0.units.spawn(async move {
            let _permit = permit;
            unit.await
        });
        match handle.await {
            Ok(value) => Ok(value),
            Err(error) if error.is_panic() => std::panic::resume_unwind(error.into_panic()),
            Err(_) => Err(Cancelled),
        }
    }

    /// Proves and publishes `ctx` on a blocking thread. Call it inside [`Self::run`]: the
    /// gate is still held while a failure is classified, so the GPU probe cannot observe
    /// another task's proof.
    pub(crate) async fn prove_and_save<B>(
        &self,
        builder: Arc<B>,
        ctx: ProofRequest,
    ) -> Result<Proved, ProveError>
    where
        B: ProofBuilder + Send + Sync + 'static,
    {
        let attempt = blocking(move || {
            let (input, proof, cycles, proving_time) =
                builder.build_proof(&ctx).map_err(|error| (error, false))?;
            let zkm_version = proof.zkm_version.clone();
            let (public_value_hex, proof_size) =
                builder.save_proof(&ctx, &input, cycles, proof).map_err(|error| (error, true))?;
            Ok::<_, (anyhow::Error, bool)>(Proved {
                cycles,
                proving_time,
                public_value_hex,
                proof_size,
                zkm_version,
            })
        })
        .await;
        match attempt {
            Ok(Ok(proved)) => {
                fault_point("after-publish");
                Ok(proved)
            }
            Ok(Err((error, true))) => Err(ProveError::Save(error)),
            Ok(Err((error, false))) | Err(error) => {
                let failure = self.classify(&error).await;
                Err(ProveError::Prove(error, failure))
            }
        }
    }

    /// Classifies a proving failure; see [`classify_error`].
    pub(crate) async fn classify(&self, error: &anyhow::Error) -> Failure {
        match &self.0.backend {
            Backend::Sdk => classify_error(error, None).await,
            Backend::Fleet { gpu_endpoint, http, .. } => {
                classify_error(error, Some((http, gpu_endpoint))).await
            }
        }
    }

    /// Stops new proofs: queued units are cancelled and later ones are refused. A unit
    /// already holding the gate continues until it commits.
    pub(crate) fn begin_shutdown(&self) {
        self.0.closing.cancel();
        if let Some(gate) = &self.0.gate {
            gate.close();
        }
        self.0.units.close();
    }

    /// Waits for the unit in progress; returns `false` when `timeout` expires first.
    pub(crate) async fn drain(&self, timeout: Duration) -> bool {
        self.begin_shutdown();
        tokio::time::timeout(timeout, self.0.units.wait()).await.is_ok()
    }

    pub(crate) fn in_flight(&self) -> usize {
        self.0.units.len()
    }
}

/// Exits the process at a named point when `PROOF_BUILDER_FAULT` selects it, to test
/// recovery (for example a proof published but not yet committed). Only builds with the
/// `fault-injection` feature contain it.
fn fault_point(name: &str) {
    #[cfg(feature = "fault-injection")]
    if std::env::var("PROOF_BUILDER_FAULT").as_deref() == Ok(name) {
        tracing::warn!(fault = name, "injected fault: exiting");
        std::process::exit(86);
    }
    #[cfg(not(feature = "fault-injection"))]
    let _ = name;
}

/// Runs blocking proving work, reporting a panic as an error.
pub(crate) async fn blocking<T, F>(work: F) -> anyhow::Result<T>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(work).await.map_err(|error| {
        if error.is_panic() {
            let panic = error.into_panic();
            let message = panic
                .downcast_ref::<String>()
                .map(String::as_str)
                .or_else(|| panic.downcast_ref::<&str>().copied())
                .unwrap_or("unknown panic");
            anyhow!("proving panicked: {message}")
        } else {
            anyhow!("proving task was cancelled")
        }
    })
}

/// Executes a failed prover call's guest on the CPU; an error means the guest rejects
/// the input.
type GuestCheck = Box<dyn FnOnce() -> anyhow::Result<()> + Send>;

/// Classifies a proving failure; a failed prover call supplies its guest check.
async fn classify_error(error: &anyhow::Error, gpu: Option<(&reqwest::Client, &str)>) -> Failure {
    let guest_check = error
        .chain()
        .find_map(|cause| cause.downcast_ref::<ProverCallError>())
        .map(|call| Box::new(call.guest_check()) as GuestCheck);
    classify_with(error, gpu, guest_check).await
}

/// A GPU server (`gpu`) that no longer reports ready needs a restart, whatever failed.
/// Otherwise a failed prover call is told apart by executing its guest on the CPU: a guest
/// that executes means the prover or its transport failed, so the proof is retried in
/// place; a guest that rejects the input makes the failure fatal. Any other error is
/// transient when it comes from I/O or the network, and fatal otherwise.
async fn classify_with(
    error: &anyhow::Error,
    gpu: Option<(&reqwest::Client, &str)>,
    guest_check: Option<GuestCheck>,
) -> Failure {
    if let Some((http, endpoint)) = gpu
        && !gpu_ready_after_probes(http, endpoint).await
    {
        return Failure::ProverUnavailable;
    }
    if let Some(guest_check) = guest_check {
        return match blocking(guest_check).await {
            Ok(Ok(())) => Failure::Transient,
            Ok(Err(_)) | Err(_) => Failure::Fatal,
        };
    }
    if error.chain().any(|cause| cause.is::<reqwest::Error>() || cause.is::<std::io::Error>()) {
        Failure::Transient
    } else {
        Failure::Fatal
    }
}

/// Probes readiness a few times so a server that is finishing a request is not mistaken
/// for a dead one.
async fn gpu_ready_after_probes(http: &reqwest::Client, endpoint: &str) -> bool {
    for probe in 0..GPU_READY_PROBES {
        if gpu_ready(http, endpoint).await {
            return true;
        }
        if probe + 1 < GPU_READY_PROBES {
            tokio::time::sleep(GPU_READY_INTERVAL).await;
        }
    }
    false
}

/// The Fleet bridge's readiness probe of a Ziren GPU server.
async fn gpu_ready(http: &reqwest::Client, endpoint: &str) -> bool {
    let url = format!("{}/api.ProverService/Ready", endpoint.trim_end_matches('/'));
    let response =
        http.post(url).header("content-type", "application/protobuf").body(Vec::new()).send().await;
    match response {
        Ok(response) if response.status().is_success() => {
            response.bytes().await.is_ok_and(|body| body.as_ref() == [0x08, 0x01])
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn serial_runtime() -> ProverRuntime {
        ProverRuntime::with_backend(Backend::Sdk, Some(Arc::new(Semaphore::new(1))), 2)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn gate_runs_one_unit_at_a_time_in_fifo_order() {
        let runtime = serial_runtime();
        let active = Arc::new(AtomicUsize::new(0));
        let order = Arc::new(Mutex::new(Vec::new()));
        // Hold the gate so the next units queue in a known order.
        let (release, hold) = tokio::sync::oneshot::channel::<()>();
        let first = {
            let runtime = runtime.clone();
            tokio::spawn(async move { runtime.run(async move { hold.await.ok() }).await })
        };
        tokio::time::sleep(Duration::from_millis(50)).await;
        let mut queued = Vec::new();
        for index in 0..4 {
            let (runtime, active, order) = (runtime.clone(), active.clone(), order.clone());
            queued.push(tokio::spawn(async move {
                runtime
                    .run(async move {
                        assert_eq!(
                            active.fetch_add(1, Ordering::SeqCst),
                            0,
                            "one unit holds the gate"
                        );
                        order.lock().unwrap().push(index);
                        tokio::time::sleep(Duration::from_millis(10)).await;
                        active.fetch_sub(1, Ordering::SeqCst);
                    })
                    .await
            }));
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        release.send(()).unwrap();
        first.await.unwrap().unwrap();
        for unit in queued {
            unit.await.unwrap().unwrap();
        }
        assert_eq!(*order.lock().unwrap(), vec![0, 1, 2, 3]);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn shutdown_cancels_queued_units_and_drains_the_active_one() {
        let runtime = serial_runtime();
        let committed = Arc::new(AtomicUsize::new(0));
        let active = {
            let (runtime, committed) = (runtime.clone(), committed.clone());
            tokio::spawn(async move {
                runtime
                    .run(async move {
                        tokio::time::sleep(Duration::from_millis(200)).await;
                        committed.fetch_add(1, Ordering::SeqCst);
                    })
                    .await
            })
        };
        tokio::time::sleep(Duration::from_millis(50)).await;
        let queued = {
            let runtime = runtime.clone();
            tokio::spawn(async move { runtime.run(async {}).await })
        };
        tokio::time::sleep(Duration::from_millis(20)).await;
        // Dropping the caller does not abort a unit that holds the gate.
        active.abort();
        assert!(runtime.drain(Duration::from_secs(5)).await);
        assert_eq!(committed.load(Ordering::SeqCst), 1);
        assert_eq!(queued.await.unwrap(), Err(Cancelled));
        assert_eq!(runtime.run(async {}).await, Err(Cancelled));
        assert_eq!(runtime.in_flight(), 0);
    }

    #[tokio::test]
    async fn drain_reports_a_timeout() {
        let runtime = ProverRuntime::sdk(2);
        let blocked = {
            let runtime = runtime.clone();
            tokio::spawn(
                async move { runtime.run(tokio::time::sleep(Duration::from_secs(60))).await },
            )
        };
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(!runtime.drain(Duration::from_millis(50)).await);
        blocked.abort();
    }

    #[tokio::test]
    async fn blocking_reports_panics_as_errors() {
        let error = blocking(|| -> () { panic!("gpu server reset") }).await.unwrap_err();
        assert!(error.to_string().contains("gpu server reset"));
    }

    #[tokio::test]
    async fn sdk_classification_replays_failed_prover_calls() {
        let runtime = ProverRuntime::sdk(2);
        let io = anyhow::Error::new(std::io::Error::other("connection reset")).context("prove");
        assert_eq!(runtime.classify(&io).await, Failure::Transient);
        assert_eq!(runtime.classify(&anyhow!("verification failed")).await, Failure::Fatal);

        // A prover call whose guest executes failed in the prover or its transport.
        let rpc = anyhow!("CUDA RPC `prove_core_stateless` failed: connection reset");
        let executes: GuestCheck = Box::new(|| Ok(()));
        assert_eq!(classify_with(&rpc, None, Some(executes)).await, Failure::Transient);
        // A guest that rejects its input makes the same RPC error fatal.
        let rejects: GuestCheck = Box::new(|| Err(anyhow!("guest panicked")));
        assert_eq!(classify_with(&rpc, None, Some(rejects)).await, Failure::Fatal);
        let panics: GuestCheck = Box::new(|| panic!("executor panicked"));
        assert_eq!(classify_with(&rpc, None, Some(panics)).await, Failure::Fatal);
    }

    async fn ready_server(ready: bool) -> String {
        use axum::{Router, routing::post};
        let body: &'static [u8] = if ready { &[0x08, 0x01] } else { &[] };
        let app = Router::new()
            .route("/twirp/api.ProverService/Ready", post(move || async move { body }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        format!("http://{address}/twirp/")
    }

    #[tokio::test]
    async fn fleet_classification_probes_the_gpu_server_first() {
        let http = reqwest::Client::new();
        let rpc = anyhow!("CUDA RPC `compress` failed: operation timed out");
        let healthy = ready_server(true).await;
        let gpu = Some((&http, healthy.as_str()));
        // A transport failure on a healthy server is retried in place, not counted.
        let executes: GuestCheck = Box::new(|| Ok(()));
        assert_eq!(classify_with(&rpc, gpu, Some(executes)).await, Failure::Transient);
        let rejects: GuestCheck = Box::new(|| Err(anyhow!("guest panicked")));
        assert_eq!(classify_with(&rpc, gpu, Some(rejects)).await, Failure::Fatal);
        assert_eq!(classify_error(&anyhow!("verification failed"), gpu).await, Failure::Fatal);

        // An unready or vanished server needs a restart whatever the guest does.
        let unready = ready_server(false).await;
        let executes: GuestCheck = Box::new(|| Ok(()));
        let failure = classify_with(&rpc, Some((&http, &unready)), Some(executes)).await;
        assert_eq!(failure, Failure::ProverUnavailable);

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let gone = format!("http://{}/twirp/", listener.local_addr().unwrap());
        drop(listener);
        let failure = classify_error(&rpc, Some((&http, &gone))).await;
        assert_eq!(failure, Failure::ProverUnavailable);
    }
}
