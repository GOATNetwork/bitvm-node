//! `--check-storage`: verifies that the proof builder's durable state lives inside its
//! storage root before a data migration or a Fleet enable.
//!
//! It checks the proof paths recorded in the database, the paths in the TOML config and
//! the state-chain `.args`/`.ctx` snapshots of batches that are not proven yet. Relative
//! paths resolve against the working directory, as they do at runtime.

use crate::config::ProofBuilderConfig;
use anyhow::Context;
use proof_builder::ProofBuilder;
use proof_builder::artifacts::{ManifestStatus, manifest_status};
use state_chain_proof::StateChainProofBuilder;
use std::path::{Path, PathBuf};
use store::ProofState;
use store::localdb::LocalDB;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Level {
    Ok,
    /// A proof written before atomic publication; it has no manifest.
    Legacy,
    Warning,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Finding {
    pub level: Level,
    pub message: String,
}

impl Finding {
    fn new(level: Level, message: impl Into<String>) -> Self {
        Self { level, message: message.into() }
    }
}

/// How a path must exist.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Need {
    /// The file must exist.
    File,
    /// The file may be created later; its directory must exist.
    Directory,
}

struct Checker {
    root: PathBuf,
    cwd: PathBuf,
    findings: Vec<Finding>,
}

impl Checker {
    fn resolve(&self, path: &str) -> PathBuf {
        let path = Path::new(path);
        if path.is_absolute() { path.to_path_buf() } else { self.cwd.join(path) }
    }

    /// Checks one path and returns its resolved location when it exists inside the root.
    /// Problems are reported at `level`.
    fn check(&mut self, label: &str, path: &str, need: Need, level: Level) -> Option<PathBuf> {
        let resolved = self.resolve(path);
        let located = match resolved.canonicalize() {
            Ok(file) => Some(file),
            Err(_) => {
                if need == Need::File {
                    self.findings
                        .push(Finding::new(level, format!("{label}: {path} does not exist")));
                    return None;
                }
                let parent = resolved.parent().unwrap_or(Path::new("."));
                match parent.canonicalize() {
                    Ok(dir) => resolved.file_name().map(|name| dir.join(name)),
                    Err(_) => {
                        self.findings.push(Finding::new(
                            level,
                            format!("{label}: directory of {path} does not exist"),
                        ));
                        return None;
                    }
                }
            }
        };
        let located = located?;
        if !located.starts_with(&self.root) {
            self.findings.push(Finding::new(
                level,
                format!(
                    "{label}: {path} resolves to {} outside {}",
                    located.display(),
                    self.root.display()
                ),
            ));
            return None;
        }
        Some(located)
    }

    fn check_proof(&mut self, label: &str, path: &str, proven: bool) {
        let need = if proven { Need::File } else { Need::Directory };
        let Some(located) = self.check(label, path, need, Level::Error) else { return };
        if !proven {
            return;
        }
        match manifest_status(&located) {
            Ok(ManifestStatus::Complete) => {
                self.findings.push(Finding::new(Level::Ok, format!("{label}: {path}")))
            }
            Ok(ManifestStatus::Missing) => self
                .findings
                .push(Finding::new(Level::Legacy, format!("{label}: {path} has no manifest"))),
            Ok(ManifestStatus::Mismatch(reason)) => {
                self.findings.push(Finding::new(Level::Error, format!("{label}: {reason}")))
            }
            Err(error) => {
                self.findings.push(Finding::new(Level::Error, format!("{label}: {error:#}")))
            }
        }
    }
}

/// Collects the string values of path-like keys from a snapshot.
fn snapshot_paths(value: &serde_json::Value, found: &mut Vec<(String, String)>) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, value) in map {
                match value {
                    serde_json::Value::String(path)
                        if matches!(key.as_str(), "input_proof" | "output_proof" | "blocks") =>
                    {
                        found.push((key.clone(), path.clone()));
                    }
                    _ => snapshot_paths(value, found),
                }
            }
        }
        serde_json::Value::Array(items) => {
            items.iter().for_each(|item| snapshot_paths(item, found))
        }
        _ => {}
    }
}

pub(crate) async fn check_storage(
    root: &Path,
    cfg: &ProofBuilderConfig,
    local_db: &LocalDB,
) -> anyhow::Result<Vec<Finding>> {
    let root = root
        .canonicalize()
        .with_context(|| format!("storage root {} is not accessible", root.display()))?;
    let cwd = std::env::current_dir()?.canonicalize()?;
    let mut checker = Checker { root, cwd, findings: Vec::new() };
    if !checker.cwd.starts_with(&checker.root) {
        checker.findings.push(Finding::new(
            Level::Error,
            format!("working directory {} is outside the storage root", checker.cwd.display()),
        ));
    }

    let mut storage = local_db.acquire().await?;
    for recorded in storage.list_recorded_proof_paths().await? {
        let label = format!("{} {}", recorded.source, recorded.task);
        let proven = recorded.proof_state == ProofState::Proven.to_i64();
        checker.check_proof(&label, &recorded.path_to_proof, proven);
    }

    let runtime_paths = [
        ("header_chain.block_headers", &cfg.header_chain.block_headers, Need::Directory),
        ("header_chain.input_proof", &cfg.header_chain.input_proof, Need::Directory),
        ("header_chain.output_proof", &cfg.header_chain.output_proof, Need::Directory),
        ("commit_chain.commit_info", &cfg.commit_chain.commit_info, Need::Directory),
        ("commit_chain.commits", &cfg.commit_chain.commits, Need::Directory),
        ("commit_chain.input_proof", &cfg.commit_chain.input_proof, Need::Directory),
        ("commit_chain.output_proof", &cfg.commit_chain.output_proof, Need::Directory),
        ("state_chain.blocks", &cfg.state_chain.blocks, Need::Directory),
        ("state_chain.input_proof", &cfg.state_chain.input_proof, Need::Directory),
        ("state_chain.output_proof", &cfg.state_chain.output_proof, Need::Directory),
        ("watchtower.output", &cfg.watchtower.output, Need::Directory),
        ("operator.output", &cfg.operator.output, Need::Directory),
    ];
    for (label, path, need) in runtime_paths {
        if checker.check(&format!("config {label}"), path, need, Level::Error).is_some() {
            checker.findings.push(Finding::new(Level::Ok, format!("config {label}: {path}")));
        }
    }
    // Operator and watchtower inputs are replaced by the database's proofs per task.
    let task_inputs = [
        ("watchtower.header_chain_input_proof", &cfg.watchtower.header_chain_input_proof),
        ("watchtower.commit_chain_input_proof", &cfg.watchtower.commit_chain_input_proof),
        ("watchtower.state_chain_input_proof", &cfg.watchtower.state_chain_input_proof),
        ("operator.header_chain_input_proof", &cfg.operator.header_chain_input_proof),
        ("operator.commit_chain_input_proof", &cfg.operator.commit_chain_input_proof),
        ("operator.state_chain_input_proof", &cfg.operator.state_chain_input_proof),
    ];
    for (label, path) in task_inputs {
        checker.check(&format!("config {label}"), path, Need::Directory, Level::Warning);
    }

    // The state-chain prover reads snapshots next to the latest proven proof.
    let latest = storage
        .find_latest_long_running_task_proof_by_name_and_state(
            StateChainProofBuilder::name(),
            ProofState::Proven.to_i64(),
        )
        .await?;
    let from = latest.as_ref().map_or(0, |task| task.block_end);
    let anchor =
        latest.and_then(|task| task.path_to_proof).unwrap_or(cfg.state_chain.input_proof.clone());
    let snapshot_dir = checker.resolve(&anchor).parent().map(Path::to_path_buf).unwrap_or_default();
    if let Ok(entries) = std::fs::read_dir(&snapshot_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            let is_snapshot =
                matches!(path.extension().and_then(|e| e.to_str()), Some("args" | "ctx"));
            let start =
                path.file_stem().and_then(|s| s.to_str()).and_then(|s| s.parse::<i64>().ok());
            let Some(start) = start.filter(|start| is_snapshot && *start >= from) else { continue };
            let label = format!("snapshot {}", path.display());
            let value = std::fs::read(&path).map_err(anyhow::Error::from).and_then(|bytes| {
                serde_json::from_slice::<serde_json::Value>(&bytes).map_err(Into::into)
            });
            let value = match value {
                Ok(value) => value,
                Err(error) => {
                    checker
                        .findings
                        .push(Finding::new(Level::Error, format!("{label}: {error:#}")));
                    continue;
                }
            };
            let mut paths = Vec::new();
            snapshot_paths(&value, &mut paths);
            for (key, snapshot_path) in paths {
                checker.check(
                    &format!("{label} {key} (batch {start})"),
                    &snapshot_path,
                    Need::Directory,
                    Level::Error,
                );
            }
        }
    }
    Ok(checker.findings)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_paths_reads_args_and_ctx_layouts() {
        let args = serde_json::json!({"input_proof": "../a.bin", "output_proof": "../b.bin", "blocks": "../s.blocks", "start": 1});
        let ctx = serde_json::json!({"StateChainProofRequest": {"input_proof": "../a.bin", "output_proof": "../b.bin", "blocks": [{"x": 1}]}});
        let mut found = Vec::new();
        snapshot_paths(&args, &mut found);
        snapshot_paths(&ctx, &mut found);
        found.sort();
        assert_eq!(
            found,
            vec![
                ("blocks".to_string(), "../s.blocks".to_string()),
                ("input_proof".to_string(), "../a.bin".to_string()),
                ("input_proof".to_string(), "../a.bin".to_string()),
                ("output_proof".to_string(), "../b.bin".to_string()),
                ("output_proof".to_string(), "../b.bin".to_string()),
            ]
        );
    }

    #[test]
    fn checker_flags_missing_outside_and_legacy_proofs() {
        let root = tempfile::tempdir().unwrap();
        let run = root.path().join("run");
        let data = root.path().join("circuits/data/header-chain");
        std::fs::create_dir_all(&run).unwrap();
        std::fs::create_dir_all(&data).unwrap();
        std::fs::write(data.join("legacy.bin"), b"p").unwrap();
        proof_builder::artifacts::publish_artifacts(
            data.join("new.bin"),
            b"p",
            &[(".vk_hash.bin", b"v")],
            "t",
        )
        .unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("x.bin"), b"p").unwrap();

        let mut checker = Checker {
            root: root.path().canonicalize().unwrap(),
            cwd: run.canonicalize().unwrap(),
            findings: Vec::new(),
        };
        checker.check_proof("legacy", "../circuits/data/header-chain/legacy.bin", true);
        checker.check_proof("new", "../circuits/data/header-chain/new.bin", true);
        checker.check_proof("missing", "../circuits/data/header-chain/gone.bin", true);
        checker.check_proof("pending", "../circuits/data/header-chain/next.bin", false);
        checker.check_proof("outside", &outside.path().join("x.bin").display().to_string(), true);
        checker.check_proof("no-dir", "../circuits/data/none/next.bin", false);
        let levels: Vec<_> = checker.findings.iter().map(|f| f.level).collect();
        assert_eq!(
            levels,
            vec![Level::Legacy, Level::Ok, Level::Error, Level::Error, Level::Error]
        );
        assert!(checker.findings[2].message.contains("missing"));
        assert!(checker.findings[3].message.contains("outside"));
        assert!(checker.findings[4].message.contains("no-dir"));

        // Task inputs replaced from the database at runtime only warn.
        checker.findings.clear();
        checker.check("task input", "/nonexistent/440-10.bin", Need::Directory, Level::Warning);
        assert_eq!(checker.findings.len(), 1);
        assert_eq!(checker.findings[0].level, Level::Warning);
    }
}
