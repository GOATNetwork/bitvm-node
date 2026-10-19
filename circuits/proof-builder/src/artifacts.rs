//! Crash-safe publication of proof artifacts.
//!
//! A proof is published as its main file plus sidecar files that share its path as a
//! prefix. Every file is written through a synced temporary file and an atomic rename;
//! the manifest is written last and names a complete set of files. Callers record a
//! proof in the database only after publication, so readers never see partial files.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

/// Suffix of the manifest that marks a complete publication.
pub const MANIFEST_SUFFIX: &str = ".manifest.json";
const MANIFEST_VERSION: u32 = 1;
const TMP_MARKER: &str = ".tmp-";

/// The files of one complete publication and their SHA-256 digests.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactManifest {
    pub version: u32,
    /// The task that produced the proof, for operators reading the directory.
    pub task: String,
    pub files: Vec<ManifestEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestEntry {
    /// The suffix appended to the proof path (empty for the proof file itself).
    pub suffix: String,
    pub sha256: String,
}

fn tmp_path(path: &Path) -> PathBuf {
    let mut name = path.file_name().map(|n| n.to_os_string()).unwrap_or_default();
    name.push(format!("{TMP_MARKER}{}", std::process::id()));
    path.with_file_name(name)
}

fn suffixed(path: &Path, suffix: &str) -> PathBuf {
    let mut joined = path.as_os_str().to_os_string();
    joined.push(suffix);
    PathBuf::from(joined)
}

fn parent_dir(path: &Path) -> &Path {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    }
}

fn sync_dir(dir: &Path) -> Result<()> {
    File::open(dir)
        .and_then(|d| d.sync_all())
        .with_context(|| format!("failed to sync directory {}", dir.display()))
}

fn write_synced(path: &Path, bytes: &[u8]) -> Result<()> {
    let tmp = tmp_path(path);
    let written = File::create(&tmp).and_then(|mut file| {
        file.write_all(bytes)?;
        file.sync_all()
    });
    if let Err(error) = written.and_then(|_| fs::rename(&tmp, path)) {
        let _ = fs::remove_file(&tmp);
        return Err(error).with_context(|| format!("failed to write {}", path.display()));
    }
    Ok(())
}

/// Atomically replaces `path` with `bytes` and syncs its directory.
pub fn atomic_write(path: impl AsRef<Path>, bytes: &[u8]) -> Result<()> {
    let path = path.as_ref();
    write_synced(path, bytes)?;
    sync_dir(parent_dir(path))
}

/// Publishes a proof file and its sidecars (`(suffix, bytes)` pairs appended to the
/// proof path). Any earlier manifest is removed first, sidecars are renamed into
/// place before the proof file, and the new manifest is written last.
pub fn publish_artifacts(
    proof_path: impl AsRef<Path>,
    proof: &[u8],
    sidecars: &[(&str, &[u8])],
    task: &str,
) -> Result<()> {
    let proof_path = proof_path.as_ref();
    let dir = parent_dir(proof_path);
    let manifest_path = suffixed(proof_path, MANIFEST_SUFFIX);
    match fs::remove_file(&manifest_path) {
        Ok(()) => sync_dir(dir)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to remove {}", manifest_path.display()));
        }
    }

    let mut files = Vec::with_capacity(sidecars.len() + 1);
    for (suffix, bytes) in sidecars {
        anyhow::ensure!(!suffix.is_empty() && *suffix != MANIFEST_SUFFIX, "invalid sidecar suffix");
        write_synced(&suffixed(proof_path, suffix), bytes)?;
        files.push(ManifestEntry {
            suffix: suffix.to_string(),
            sha256: hex::encode(Sha256::digest(bytes)),
        });
    }
    write_synced(proof_path, proof)?;
    files.push(ManifestEntry { suffix: String::new(), sha256: hex::encode(Sha256::digest(proof)) });
    sync_dir(dir)?;

    let manifest = ArtifactManifest { version: MANIFEST_VERSION, task: task.to_string(), files };
    write_synced(&manifest_path, &serde_json::to_vec_pretty(&manifest)?)?;
    sync_dir(dir)
}

/// Removes temporary files left in `dir` by interrupted writes of other processes.
pub fn remove_stale_tmp_files(dir: impl AsRef<Path>) -> Result<usize> {
    let own = format!("{TMP_MARKER}{}", std::process::id());
    let mut removed = 0;
    for entry in fs::read_dir(dir.as_ref())? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Some(index) = name.rfind(TMP_MARKER) else { continue };
        let pid = &name[index + TMP_MARKER.len()..];
        if pid.is_empty() || !pid.bytes().all(|b| b.is_ascii_digit()) || name.ends_with(&own) {
            continue;
        }
        if entry.file_type()?.is_file() {
            fs::remove_file(entry.path())?;
            removed += 1;
        }
    }
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Whether every file the manifest of `proof` names exists with its recorded digest.
    fn manifest_matches(proof: &Path) -> bool {
        let bytes = fs::read(suffixed(proof, MANIFEST_SUFFIX)).unwrap();
        let manifest: ArtifactManifest = serde_json::from_slice(&bytes).unwrap();
        manifest.files.iter().all(|entry| {
            fs::read(suffixed(proof, &entry.suffix))
                .is_ok_and(|content| hex::encode(Sha256::digest(&content)) == entry.sha256)
        })
    }

    #[test]
    fn publication_writes_manifest_last_and_verifies() {
        let dir = tempfile::tempdir().unwrap();
        let proof = dir.path().join("10-1.bin");
        publish_artifacts(
            &proof,
            b"proof",
            &[(".public_inputs.bin", b"pv"), (".vk_hash.bin", b"vk")],
            "header-chain 10",
        )
        .unwrap();
        assert_eq!(fs::read(&proof).unwrap(), b"proof");
        assert_eq!(fs::read(suffixed(&proof, ".public_inputs.bin")).unwrap(), b"pv");
        assert!(manifest_matches(&proof));
        let leftovers: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains(TMP_MARKER))
            .collect();
        assert!(leftovers.is_empty());

        fs::write(suffixed(&proof, ".vk_hash.bin"), b"other").unwrap();
        assert!(!manifest_matches(&proof));
    }

    #[test]
    fn republication_replaces_the_previous_set() {
        let dir = tempfile::tempdir().unwrap();
        let proof = dir.path().join("1.bin");
        publish_artifacts(&proof, b"old", &[(".public_inputs.bin", b"old")], "watchtower 1")
            .unwrap();
        publish_artifacts(&proof, b"new", &[(".public_inputs.bin", b"new")], "watchtower 1")
            .unwrap();
        assert_eq!(fs::read(&proof).unwrap(), b"new");
        assert!(manifest_matches(&proof));
    }

    #[test]
    fn interrupted_publication_has_no_manifest() {
        let dir = tempfile::tempdir().unwrap();
        let proof = dir.path().join("1.bin");
        // A legacy or interrupted proof file without a manifest.
        fs::write(&proof, b"partial").unwrap();
        assert!(!suffixed(&proof, MANIFEST_SUFFIX).exists());
        // An invalid sidecar fails before the proof file or manifest are replaced.
        assert!(publish_artifacts(&proof, b"proof", &[("", b"x")], "operator 1").is_err());
        assert_eq!(fs::read(&proof).unwrap(), b"partial");
        assert!(!suffixed(&proof, MANIFEST_SUFFIX).exists());
    }

    #[test]
    fn stale_tmp_files_of_other_processes_are_removed() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("1.bin.tmp-999999999"), b"x").unwrap();
        fs::write(dir.path().join(format!("2.bin{TMP_MARKER}{}", std::process::id())), b"x")
            .unwrap();
        fs::write(dir.path().join("3.bin"), b"x").unwrap();
        fs::write(dir.path().join("4.bin.tmp-notapid"), b"x").unwrap();
        assert_eq!(remove_stale_tmp_files(dir.path()).unwrap(), 1);
        assert!(!dir.path().join("1.bin.tmp-999999999").exists());
        assert!(dir.path().join("3.bin").exists());
        assert!(dir.path().join("4.bin.tmp-notapid").exists());
    }

    #[test]
    fn atomic_write_replaces_content() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("10.ctx");
        atomic_write(&path, b"a").unwrap();
        atomic_write(&path, b"b").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"b");
    }
}
