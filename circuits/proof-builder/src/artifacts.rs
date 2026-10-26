//! Crash-safe publication of proof artifacts.
//!
//! A proof is published as its main file plus sidecar files that share its path as a
//! prefix. Every file is written through a synced temporary file and an atomic rename.
//! Sidecars are published before the proof file. Callers record a proof in the database
//! only after all files and the directory have been synced.

use anyhow::{Context, Result};
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

const TMP_MARKER: &str = ".tmp-";

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
/// proof path). Sidecars are renamed into place before the proof file, then the
/// directory is synced.
pub fn publish_artifacts(
    proof_path: impl AsRef<Path>,
    proof: &[u8],
    sidecars: &[(&str, &[u8])],
) -> Result<()> {
    let proof_path = proof_path.as_ref();
    let dir = parent_dir(proof_path);
    for (suffix, bytes) in sidecars {
        anyhow::ensure!(!suffix.is_empty(), "invalid sidecar suffix");
        write_synced(&suffixed(proof_path, suffix), bytes)?;
    }
    write_synced(proof_path, proof)?;
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

    #[test]
    fn publication_writes_only_proof_and_sidecars() {
        let dir = tempfile::tempdir().unwrap();
        let proof = dir.path().join("10-1.bin");
        publish_artifacts(
            &proof,
            b"proof",
            &[(".public_inputs.bin", b"pv"), (".vk_hash.bin", b"vk")],
        )
        .unwrap();
        assert_eq!(fs::read(&proof).unwrap(), b"proof");
        assert_eq!(fs::read(suffixed(&proof, ".public_inputs.bin")).unwrap(), b"pv");
        assert_eq!(fs::read(suffixed(&proof, ".vk_hash.bin")).unwrap(), b"vk");
        let mut files: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        files.sort();
        assert_eq!(files, ["10-1.bin", "10-1.bin.public_inputs.bin", "10-1.bin.vk_hash.bin"]);
    }

    #[test]
    fn republication_replaces_the_previous_set() {
        let dir = tempfile::tempdir().unwrap();
        let proof = dir.path().join("1.bin");
        publish_artifacts(&proof, b"old", &[(".public_inputs.bin", b"old")]).unwrap();
        publish_artifacts(&proof, b"new", &[(".public_inputs.bin", b"new")]).unwrap();
        assert_eq!(fs::read(&proof).unwrap(), b"new");
        assert_eq!(fs::read(suffixed(&proof, ".public_inputs.bin")).unwrap(), b"new");
    }

    #[test]
    fn invalid_sidecar_does_not_replace_proof() {
        let dir = tempfile::tempdir().unwrap();
        let proof = dir.path().join("1.bin");
        fs::write(&proof, b"old").unwrap();
        assert!(publish_artifacts(&proof, b"proof", &[("", b"x")]).is_err());
        assert_eq!(fs::read(&proof).unwrap(), b"old");
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
