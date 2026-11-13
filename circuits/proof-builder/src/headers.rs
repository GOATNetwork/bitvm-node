//! The archive of proven Bitcoin headers.
//!
//! A header-chain proof covers every header from Genesis to its last block. The headers
//! are kept once, in [`HEADER_ARCHIVE`] next to the proofs, 80 bytes each and only ever
//! appended: a proof covering `n` headers reads the archive's first `n`, so readers need
//! no lock against the prover.

use anyhow::{Context, Result, bail, ensure};
use bincode::Options;
use borsh::{BorshDeserialize, BorshSerialize};
use header_chain::{BlockHeaderCircuitOutput, CircuitBlockHeader};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

pub const HEADER_ARCHIVE: &str = "headers.blocks";
const HEADER_SIZE: u64 = 80;

/// The archive next to `proof_path`.
pub fn header_archive_path(proof_path: impl AsRef<Path>) -> PathBuf {
    match proof_path.as_ref().parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir.join(HEADER_ARCHIVE),
        _ => PathBuf::from(HEADER_ARCHIVE),
    }
}

fn header_bytes(header: &CircuitBlockHeader) -> Result<Vec<u8>> {
    let mut bytes = Vec::with_capacity(HEADER_SIZE as usize);
    header.serialize(&mut bytes)?;
    ensure!(bytes.len() as u64 == HEADER_SIZE, "block headers must be 80 bytes each");
    Ok(bytes)
}

fn read_header(file: &mut File, index: u64) -> Result<CircuitBlockHeader> {
    let mut bytes = [0u8; HEADER_SIZE as usize];
    file.seek(SeekFrom::Start(index * HEADER_SIZE))?;
    file.read_exact(&mut bytes)?;
    Ok(CircuitBlockHeader::try_from_slice(&bytes)?)
}

/// Extend the archive to `headers[..end]`, the headers the proof being saved covers.
/// Headers already archived must be the same ones, and every appended header must
/// extend the one before it. A torn tail from an interrupted append is dropped first.
pub fn extend_header_archive(
    archive: impl AsRef<Path>,
    headers: &[CircuitBlockHeader],
    end: usize,
) -> Result<()> {
    let archive = archive.as_ref();
    let headers = headers.get(..end).context("block headers do not cover the proven batch")?;
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(archive)
        .with_context(|| format!("open {}", archive.display()))?;
    let len = file.metadata()?.len();
    let archived = len / HEADER_SIZE;
    if len % HEADER_SIZE != 0 {
        file.set_len(archived * HEADER_SIZE)?;
    }
    // The archive is a hash chain, so one shared header equal on both sides means the
    // whole shared prefix is.
    let shared = archived.min(end as u64);
    if shared > 0 && read_header(&mut file, shared - 1)? != headers[shared as usize - 1] {
        bail!(
            "{} holds another header at height {}; the proven chain changed",
            archive.display(),
            shared - 1
        );
    }
    if archived >= end as u64 {
        return Ok(());
    }
    let mut previous = match archived {
        0 => None,
        index => Some(read_header(&mut file, index - 1)?.compute_block_hash()),
    };
    file.seek(SeekFrom::Start(archived * HEADER_SIZE))?;
    let mut bytes = Vec::with_capacity((end - archived as usize) * HEADER_SIZE as usize);
    for header in &headers[archived as usize..] {
        if let Some(previous) = previous {
            ensure!(
                header.prev_block_hash == previous,
                "header at height {} does not extend the archived chain",
                archived as usize + bytes.len() / HEADER_SIZE as usize
            );
        }
        bytes.extend(header_bytes(header)?);
        previous = Some(header.compute_block_hash());
    }
    file.write_all(&bytes)?;
    file.sync_all().with_context(|| format!("sync {}", archive.display()))
}

fn decode_header_chain_output(public_values: &[u8]) -> Result<BlockHeaderCircuitOutput> {
    // The encoding the header-chain guest commits its output with.
    Ok(bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .deserialize(public_values)?)
}

/// The headers a header-chain proof covers, from Genesis to its last block. They come
/// from the archive next to the proof, or from the proof's own `.blocks` sidecar (the
/// Genesis seed), and the last one must be the proof's best block.
pub fn proven_headers(proof_path: &str) -> Result<Vec<CircuitBlockHeader>> {
    let public_values = fs::read(format!("{proof_path}.public_inputs.bin"))
        .with_context(|| format!("read {proof_path}.public_inputs.bin"))?;
    let chain_state = decode_header_chain_output(&public_values)
        .with_context(|| format!("decode the header-chain output of {proof_path}"))?
        .chain_state;
    let count = u64::from(chain_state.block_height.wrapping_add(1));
    ensure!(count > 0, "{proof_path} covers no header");
    let bytes = count * HEADER_SIZE;

    let archive = header_archive_path(proof_path);
    let source = match fs::metadata(&archive) {
        Ok(metadata) if metadata.len() >= bytes => archive,
        _ => PathBuf::from(format!("{proof_path}.blocks")),
    };
    let mut raw = Vec::with_capacity(bytes as usize);
    File::open(&source)
        .with_context(|| format!("open {}", source.display()))?
        .take(bytes)
        .read_to_end(&mut raw)?;
    ensure!(
        raw.len() as u64 == bytes,
        "{} holds {} headers, {proof_path} covers {count}",
        source.display(),
        raw.len() as u64 / HEADER_SIZE
    );
    let headers = raw
        .chunks_exact(HEADER_SIZE as usize)
        .map(CircuitBlockHeader::try_from_slice)
        .collect::<Result<Vec<_>, _>>()?;
    let last = headers.last().map(CircuitBlockHeader::compute_block_hash);
    ensure!(
        last == Some(chain_state.best_block_hash),
        "{} does not end at the best block of {proof_path}",
        source.display()
    );
    Ok(headers)
}

/// Delete the per-proof `.blocks` sidecars older proofs were published with, once per
/// process: only those the archive in `dir` covers (their last header is the archive's
/// at the same height), so nothing else ending in `.blocks` is touched. Sidecars of
/// Genesis batches (`0-*`) stay: they seed a fresh archive.
pub fn remove_superseded_sidecars(dir: impl AsRef<Path>) -> Result<usize> {
    static DONE: AtomicBool = AtomicBool::new(false);
    if DONE.swap(true, Ordering::SeqCst) {
        return Ok(0);
    }
    let dir = dir.as_ref();
    let mut archive = File::open(dir.join(HEADER_ARCHIVE))?;
    let archived = archive.metadata()?.len() / HEADER_SIZE;
    let mut removed = 0;
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if !name.ends_with(".bin.blocks") || name.starts_with("0-") || !entry.file_type()?.is_file()
        {
            continue;
        }
        let mut sidecar = File::open(entry.path())?;
        let len = sidecar.metadata()?.len();
        let count = len / HEADER_SIZE;
        if len == 0 || len % HEADER_SIZE != 0 || count > archived {
            continue;
        }
        let covered = read_header(&mut sidecar, count - 1)
            .and_then(|last| Ok(last == read_header(&mut archive, count - 1)?))
            .unwrap_or(false);
        if covered {
            fs::remove_file(entry.path())?;
            removed += 1;
        }
    }
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chain(len: usize) -> Vec<CircuitBlockHeader> {
        let genesis = bitcoin::constants::genesis_block(bitcoin::Network::Regtest).header;
        let mut headers: Vec<CircuitBlockHeader> = vec![genesis.into()];
        while headers.len() < len {
            let mut next = headers.last().unwrap().clone();
            next.prev_block_hash = next.compute_block_hash();
            next.nonce = next.nonce.wrapping_add(1);
            headers.push(next);
        }
        headers
    }

    #[test]
    fn the_archive_grows_by_batch_and_refuses_a_changed_or_broken_chain() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join(HEADER_ARCHIVE);
        let headers = chain(6);
        extend_header_archive(&archive, &headers, 4).unwrap();
        // A torn append and a repeated save are both harmless.
        let mut file = OpenOptions::new().append(true).open(&archive).unwrap();
        file.write_all(&[1, 2, 3]).unwrap();
        extend_header_archive(&archive, &headers, 4).unwrap();
        extend_header_archive(&archive, &headers, 5).unwrap();
        assert_eq!(fs::metadata(&archive).unwrap().len(), 5 * HEADER_SIZE);

        let mut changed = headers.clone();
        changed[4].nonce += 7;
        assert!(extend_header_archive(&archive, &changed, 5).is_err());
        let mut broken = headers.clone();
        broken[5].prev_block_hash = [9; 32];
        assert!(extend_header_archive(&archive, &broken, 6).is_err());
        assert_eq!(fs::metadata(&archive).unwrap().len(), 5 * HEADER_SIZE);
    }

    fn write_proof(dir: &Path, name: &str, headers: &[CircuitBlockHeader]) -> String {
        let mut chain_state = header_chain::ChainState::new();
        chain_state.block_height = headers.len() as u32 - 1;
        chain_state.best_block_hash = headers.last().unwrap().compute_block_hash();
        let output = BlockHeaderCircuitOutput {
            chain_state,
            self_program_id: [0; 32],
            program_history_hash: [0; 32],
            upgrade_checkpoint_hash: [0; 32],
        };
        let public_values =
            bincode::DefaultOptions::new().with_fixint_encoding().serialize(&output).unwrap();
        let proof = dir.join(name).to_str().unwrap().to_string();
        fs::write(format!("{proof}.public_inputs.bin"), public_values).unwrap();
        proof
    }

    #[test]
    fn a_proof_reads_its_own_prefix_of_the_archive_or_its_seed_sidecar() {
        let dir = tempfile::tempdir().unwrap();
        let headers = chain(5);
        let seed = write_proof(dir.path(), "0-2.bin", &headers[..2]);
        let mut sidecar = Vec::new();
        for header in &headers[..2] {
            sidecar.extend(header_bytes(header).unwrap());
        }
        fs::write(format!("{seed}.blocks"), sidecar).unwrap();
        // No archive yet: the seed's own sidecar.
        assert_eq!(proven_headers(&seed).unwrap(), headers[..2]);

        let later = write_proof(dir.path(), "3-1.bin", &headers[..4]);
        assert!(proven_headers(&later).is_err(), "neither archive nor sidecar covers it");
        extend_header_archive(header_archive_path(&later), &headers, 5).unwrap();
        assert_eq!(proven_headers(&later).unwrap(), headers[..4]);
        assert_eq!(proven_headers(&seed).unwrap(), headers[..2]);

        // An archive of another chain is refused, not served.
        let other = chain(4).into_iter().map(|mut h| {
            h.time += 1;
            h
        });
        let stranger = write_proof(dir.path(), "9-1.bin", &other.collect::<Vec<_>>());
        assert!(proven_headers(&stranger).is_err());
    }

    #[test]
    fn only_sidecars_the_archive_covers_are_removed() {
        let dir = tempfile::tempdir().unwrap();
        let headers = chain(4);
        extend_header_archive(dir.path().join(HEADER_ARCHIVE), &headers, 3).unwrap();
        let bytes = |headers: &[CircuitBlockHeader]| -> Vec<u8> {
            headers.iter().flat_map(|header| header_bytes(header).unwrap()).collect()
        };
        let other = chain(2).into_iter().map(|mut h| {
            h.time += 1;
            h
        });
        for (name, content) in [
            ("0-2.bin.blocks", bytes(&headers[..2])),
            ("2-1.bin.blocks", bytes(&headers[..3])),
            ("3-1.bin.blocks", bytes(&headers[..4])),
            ("5-1.bin.blocks", bytes(&other.collect::<Vec<_>>())),
            ("7-40.bin.blocks", b"[{\"state\":1}]".to_vec()),
            ("2-1.bin", b"proof".to_vec()),
        ] {
            fs::write(dir.path().join(name), content).unwrap();
        }
        assert_eq!(remove_superseded_sidecars(dir.path()).unwrap(), 1);
        let mut left: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        left.sort();
        assert_eq!(
            left,
            [
                "0-2.bin.blocks",
                "2-1.bin",
                "3-1.bin.blocks",
                "5-1.bin.blocks",
                "7-40.bin.blocks",
                HEADER_ARCHIVE
            ]
        );
    }
}
