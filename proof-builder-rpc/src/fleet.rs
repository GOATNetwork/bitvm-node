//! Integrated Fleet app worker mode.
//!
//! Fleet starts a dedicated Ziren GPU server for the GOAT app, then launches the proof
//! builder beside it with the variables below. The worker proves directly against the
//! loopback server and owns its storage root; Fleet manages lifecycle and resources.
//! A partial Fleet environment is an error: falling back to the SDK network prover is an
//! explicit operator choice made by running outside Fleet.

use anyhow::{Context, anyhow, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};

pub(crate) const ENV_WORKER_ROLE: &str = "FLEET_WORKER_ROLE";
pub(crate) const ENV_GPU_ENDPOINT: &str = "FLEET_GPU_ENDPOINT";
pub(crate) const ENV_STORAGE_ROOT: &str = "FLEET_APP_STORAGE_ROOT";
pub(crate) const ENV_APP_ID: &str = "FLEET_APP_ELF_ID";
pub(crate) const ENV_NAMESPACE: &str = "FLEET_APP_NAMESPACE";
pub(crate) const ENV_TENANT: &str = "FLEET_APP_TENANT";
pub(crate) const ENV_EXIT_WITH_PARENT: &str = "FLEET_EXIT_WITH_PARENT";
pub(crate) const ENV_PROGRAMS_FILE: &str = "PROOF_BUILDER_PROGRAMS_FILE";
const FLEET_MARKERS: [&str; 7] = [
    ENV_WORKER_ROLE,
    ENV_GPU_ENDPOINT,
    ENV_STORAGE_ROOT,
    ENV_APP_ID,
    ENV_NAMESPACE,
    ENV_TENANT,
    ENV_EXIT_WITH_PARENT,
];
const LOCK_FILE: &str = "proof-builder.lock";

/// The environment Fleet supplies to an integrated app worker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FleetEnv {
    pub gpu_endpoint: String,
    pub storage_root: PathBuf,
    /// The Fleet proof app id: the digest of the program bundle.
    pub app_id: String,
    pub namespace: String,
    pub tenant: String,
    pub exit_with_parent: bool,
    pub programs_file: PathBuf,
}

impl FleetEnv {
    /// Returns `None` only when no Fleet variable is set.
    pub(crate) fn from_lookup(
        lookup: impl Fn(&str) -> Option<String>,
    ) -> anyhow::Result<Option<Self>> {
        if FLEET_MARKERS.iter().all(|key| lookup(key).is_none()) {
            return Ok(None);
        }
        let required = |key: &str| {
            lookup(key)
                .filter(|value| !value.is_empty())
                .with_context(|| format!("{key} is required when Fleet launches the proof builder"))
        };
        if let Some(role) = lookup(ENV_WORKER_ROLE) {
            ensure!(role == "app", "{ENV_WORKER_ROLE} must be \"app\", got {role:?}");
        }
        let gpu_endpoint = required(ENV_GPU_ENDPOINT)?;
        ensure_loopback_http(&gpu_endpoint)?;
        let app_id = required(ENV_APP_ID)?.to_ascii_lowercase();
        ensure!(is_sha256_hex(&app_id), "{ENV_APP_ID} must be 64 hex digits, got {app_id:?}");
        Ok(Some(Self {
            gpu_endpoint,
            storage_root: PathBuf::from(required(ENV_STORAGE_ROOT)?),
            app_id,
            namespace: required(ENV_NAMESPACE)?,
            tenant: required(ENV_TENANT)?,
            exit_with_parent: lookup(ENV_EXIT_WITH_PARENT).as_deref() == Some("true"),
            programs_file: PathBuf::from(required(ENV_PROGRAMS_FILE)?),
        }))
    }
}

fn ensure_loopback_http(endpoint: &str) -> anyhow::Result<()> {
    let url = reqwest::Url::parse(endpoint)
        .with_context(|| format!("invalid {ENV_GPU_ENDPOINT} {endpoint:?}"))?;
    ensure!(
        url.scheme() == "http"
            && matches!(url.host_str(), Some("127.0.0.1" | "localhost" | "[::1]")),
        "{ENV_GPU_ENDPOINT} must be a loopback HTTP URL, got {endpoint:?}"
    );
    Ok(())
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// The guest programs of the GOAT proof bundle, sorted by name.
pub(crate) fn bundle_programs() -> [(&'static str, &'static [u8]); 5] {
    [
        ("commit-chain", commit_chain_proof::COMMIT_CHAIN),
        ("header-chain", header_chain_proof::HEADER_CHAIN),
        ("operator", operator_proof::OPERATOR),
        ("state-chain", state_chain_proof::STATE_CHAIN),
        ("watchtower", watchtower_proof::WATCHTOWER),
    ]
}

/// One `<name> <ELF SHA-256>` line per program, sorted by name.
pub(crate) fn bundle_manifest(elf_digests: &[(&str, String)]) -> String {
    let mut lines: Vec<_> =
        elf_digests.iter().map(|(name, digest)| format!("{name} {digest}\n")).collect();
    lines.sort();
    lines.concat()
}

/// The Fleet app id of a bundle: the SHA-256 of its manifest.
pub(crate) fn bundle_id(manifest: &str) -> String {
    sha256_hex(manifest.as_bytes())
}

/// The packaged description of the bundle, written by `--print-programs`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ProgramsFile {
    pub bundle_id: String,
    pub zkm_circuit_version: String,
    pub imm_wrap_vk: bool,
    pub programs: Vec<ProgramRecord>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ProgramRecord {
    pub name: String,
    pub elf_sha256: String,
    pub program_id: String,
    pub vk_hash: String,
}

impl ProgramsFile {
    pub(crate) fn load(path: &Path) -> anyhow::Result<Self> {
        let bytes =
            std::fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
        serde_json::from_slice(&bytes)
            .with_context(|| format!("invalid programs file {}", path.display()))
    }

    /// Requires the packaged list to describe exactly the embedded programs of `app_id`
    /// under this process's wrap mode.
    pub(crate) fn check_embedded(
        &self,
        app_id: &str,
        embedded: &[(&str, String)],
        imm_wrap_vk: bool,
    ) -> anyhow::Result<()> {
        let embedded_id = bundle_id(&bundle_manifest(embedded));
        ensure!(
            embedded_id == app_id,
            "embedded program bundle {embedded_id} differs from the Fleet app {app_id}"
        );
        ensure!(
            self.bundle_id == app_id,
            "programs file describes bundle {}, not {app_id}",
            self.bundle_id
        );
        ensure!(
            self.imm_wrap_vk == imm_wrap_vk,
            "programs file was built with ZKM_IMM_WRAP_VK={}, this worker runs with {imm_wrap_vk}",
            self.imm_wrap_vk
        );
        let mut packaged: Vec<_> =
            self.programs.iter().map(|p| (p.name.as_str(), p.elf_sha256.clone())).collect();
        let mut expected = embedded.to_vec();
        packaged.sort();
        expected.sort();
        ensure!(
            packaged == expected,
            "programs file ELF digests differ from the embedded programs"
        );
        Ok(())
    }
}

/// Requires a program set up on the GPU server to have the packaged verifying key.
pub(crate) fn verify_program(
    programs: &ProgramsFile,
    elf: &[u8],
    vk_hash: &str,
) -> anyhow::Result<()> {
    let digest = sha256_hex(elf);
    let record = programs
        .programs
        .iter()
        .find(|p| p.elf_sha256 == digest)
        .ok_or_else(|| anyhow!("program {digest} is not part of the packaged bundle"))?;
    ensure!(
        record.vk_hash == vk_hash,
        "{} verifying key {vk_hash} differs from the packaged {}",
        record.name,
        record.vk_hash
    );
    Ok(())
}

/// Exclusive ownership of a storage root for the life of the worker.
#[derive(Debug)]
pub(crate) struct StorageLock(#[allow(dead_code)] File);

pub(crate) fn lock_storage_root(root: &Path) -> anyhow::Result<StorageLock> {
    let path = root.join(LOCK_FILE);
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&path)
        .with_context(|| format!("failed to open {}", path.display()))?;
    file.try_lock()
        .map_err(|error| anyhow!("another proof builder owns {}: {error}", root.display()))?;
    Ok(StorageLock(file))
}

/// Requires the working directory and the sqlite database inside the storage root, so
/// relative proof paths, snapshots and task state are durable app storage.
pub(crate) fn check_storage_paths(
    root: &Path,
    cwd: &Path,
    database_url: &str,
) -> anyhow::Result<()> {
    let root = root
        .canonicalize()
        .with_context(|| format!("storage root {} is not accessible", root.display()))?;
    let cwd = cwd.canonicalize()?;
    ensure!(
        cwd.starts_with(&root),
        "working directory {} must be inside the storage root {}",
        cwd.display(),
        root.display()
    );
    let database = sqlite_file(database_url)?;
    let database = if database.is_absolute() { database } else { cwd.join(database) };
    let parent = database.parent().unwrap_or(Path::new("."));
    let parent = parent
        .canonicalize()
        .with_context(|| format!("database directory {} is not accessible", parent.display()))?;
    ensure!(
        parent.starts_with(&root),
        "database {} must be inside the storage root {}",
        database.display(),
        root.display()
    );
    Ok(())
}

pub(crate) fn sqlite_file(database_url: &str) -> anyhow::Result<PathBuf> {
    let rest = database_url
        .strip_prefix("sqlite://")
        .or_else(|| database_url.strip_prefix("sqlite:"))
        .with_context(|| {
            format!("Fleet mode requires a sqlite DATABASE_URL, got {database_url:?}")
        })?;
    let path = rest.split('?').next().unwrap_or_default();
    ensure!(
        !path.is_empty() && !path.starts_with(":memory:"),
        "Fleet mode requires a file database"
    );
    Ok(PathBuf::from(path))
}

/// Ties the worker's life to its Fleet actor: an orphan must not keep the storage lock.
pub(crate) fn exit_with_parent() -> anyhow::Result<()> {
    #[cfg(target_os = "linux")]
    unsafe {
        let parent = libc::getppid();
        ensure!(parent > 1, "Fleet worker has no live parent");
        if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM) != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        ensure!(libc::getppid() == parent, "Fleet parent exited during startup");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    const APP_ID: &str = "aa000000000000000000000000000000000000000000000000000000000000bb";

    fn lookup(vars: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let vars: HashMap<String, String> =
            vars.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        move |key| vars.get(key).cloned()
    }

    fn complete() -> Vec<(&'static str, &'static str)> {
        vec![
            (ENV_WORKER_ROLE, "app"),
            (ENV_GPU_ENDPOINT, "http://127.0.0.1:30100/twirp/"),
            (ENV_STORAGE_ROOT, "/srv/zkm-fleet/apps/goat"),
            (ENV_APP_ID, APP_ID),
            (ENV_NAMESPACE, "zkm"),
            (ENV_TENANT, "goat"),
            (ENV_EXIT_WITH_PARENT, "true"),
            (ENV_PROGRAMS_FILE, "/opt/zkm-fleet/apps/goat/programs.json"),
        ]
    }

    #[test]
    fn no_fleet_variable_means_sdk_mode() {
        assert_eq!(FleetEnv::from_lookup(lookup(&[(ENV_PROGRAMS_FILE, "x")])).unwrap(), None);
    }

    #[test]
    fn complete_environment_is_accepted() {
        let env = FleetEnv::from_lookup(lookup(&complete())).unwrap().unwrap();
        assert_eq!(env.app_id, APP_ID);
        assert!(env.exit_with_parent);
        assert_eq!(env.storage_root, PathBuf::from("/srv/zkm-fleet/apps/goat"));
    }

    #[test]
    fn partial_or_invalid_environment_is_rejected() {
        for missing in [
            ENV_GPU_ENDPOINT,
            ENV_STORAGE_ROOT,
            ENV_APP_ID,
            ENV_NAMESPACE,
            ENV_TENANT,
            ENV_PROGRAMS_FILE,
        ] {
            let vars: Vec<_> = complete().into_iter().filter(|(k, _)| *k != missing).collect();
            assert!(FleetEnv::from_lookup(lookup(&vars)).is_err(), "{missing} must be required");
        }
        // A single Fleet marker without the rest is not silently ignored.
        assert!(FleetEnv::from_lookup(lookup(&[(ENV_WORKER_ROLE, "app")])).is_err());
        for (key, value) in [
            (ENV_GPU_ENDPOINT, "http://10.0.0.5:30100/twirp/"),
            (ENV_GPU_ENDPOINT, "https://127.0.0.1:30100/twirp/"),
            (ENV_APP_ID, "abc"),
            (ENV_WORKER_ROLE, "batch"),
        ] {
            let mut vars = complete();
            vars.retain(|(k, _)| *k != key);
            vars.push((key, value));
            assert!(
                FleetEnv::from_lookup(lookup(&vars)).is_err(),
                "{key}={value} must be rejected"
            );
        }
    }

    fn digests() -> Vec<(&'static str, String)> {
        vec![("watchtower", "02".repeat(32)), ("commit-chain", "01".repeat(32))]
    }

    #[test]
    fn bundle_id_is_order_independent_and_tracks_every_program() {
        let manifest = bundle_manifest(&digests());
        assert_eq!(
            manifest,
            format!("commit-chain {}\nwatchtower {}\n", "01".repeat(32), "02".repeat(32))
        );
        let mut reversed = digests();
        reversed.reverse();
        assert_eq!(bundle_id(&bundle_manifest(&reversed)), bundle_id(&manifest));
        assert!(is_sha256_hex(&bundle_id(&manifest)));
        let mut changed = digests();
        changed[0].1 = "03".repeat(32);
        assert_ne!(bundle_id(&bundle_manifest(&changed)), bundle_id(&manifest));
    }

    #[test]
    fn programs_file_must_match_the_embedded_bundle() {
        let embedded = digests();
        let app_id = bundle_id(&bundle_manifest(&embedded));
        let file = ProgramsFile {
            bundle_id: app_id.clone(),
            zkm_circuit_version: "v2".to_string(),
            imm_wrap_vk: true,
            programs: embedded
                .iter()
                .map(|(name, digest)| ProgramRecord {
                    name: name.to_string(),
                    elf_sha256: digest.clone(),
                    program_id: "id".to_string(),
                    vk_hash: format!("0x{name}"),
                })
                .collect(),
        };
        file.check_embedded(&app_id, &embedded, true).unwrap();
        assert!(file.check_embedded(&app_id, &embedded, false).is_err(), "wrap mode must match");
        assert!(file.check_embedded(APP_ID, &embedded, true).is_err(), "app id must match");
        let mut other = embedded.clone();
        other[1].1 = "04".repeat(32);
        assert!(file.check_embedded(&app_id, &other, true).is_err());

        let elf = b"elf";
        let mut with_elf = file.clone();
        with_elf.programs[0].elf_sha256 = sha256_hex(elf);
        verify_program(&with_elf, elf, "0xwatchtower").unwrap();
        assert!(verify_program(&with_elf, elf, "0xother").is_err());
        assert!(verify_program(&with_elf, b"unknown", "0xwatchtower").is_err());
    }

    #[test]
    fn storage_root_lock_is_exclusive() {
        let root = tempfile::tempdir().unwrap();
        let lock = lock_storage_root(root.path()).unwrap();
        assert!(lock_storage_root(root.path()).is_err());
        drop(lock);
        lock_storage_root(root.path()).unwrap();
    }

    #[test]
    fn working_directory_and_database_must_be_inside_the_root() {
        let root = tempfile::tempdir().unwrap();
        let run = root.path().join("run");
        std::fs::create_dir(&run).unwrap();
        check_storage_paths(root.path(), &run, "sqlite:proof-builder.db?mode=rwc").unwrap();
        let absolute = format!("sqlite://{}/proof-builder.db", run.display());
        check_storage_paths(root.path(), &run, &absolute).unwrap();

        let outside = tempfile::tempdir().unwrap();
        assert!(check_storage_paths(root.path(), outside.path(), "sqlite:x.db").is_err());
        let elsewhere = format!("sqlite:{}/x.db", outside.path().display());
        assert!(check_storage_paths(root.path(), &run, &elsewhere).is_err());
        assert!(check_storage_paths(root.path(), &run, "sqlite:../../x.db").is_err());
        assert!(check_storage_paths(root.path(), &run, "sqlite::memory:").is_err());
        assert!(check_storage_paths(root.path(), &run, "postgres://db").is_err());
    }
}
