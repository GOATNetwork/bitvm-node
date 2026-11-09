use std::path::{Path, PathBuf};

use bitcode::{Decode, Encode};
use bitcoin::Network;

const NUM_BLOCKS_REGTEST: u32 = 1;
const NUM_BLOCKS_TESTNET: u32 = 7;

pub fn num_blocks_per_network(network: Network, mainnet_num_blocks: u32) -> u32 {
    match network {
        Network::Bitcoin => mainnet_num_blocks,
        Network::Regtest => NUM_BLOCKS_REGTEST,
        _ => NUM_BLOCKS_TESTNET, // Testnet, Signet
    }
}

pub fn remove_script_and_control_block_from_witness(mut witness: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    witness.truncate(witness.len() - 2);

    witness
}

pub fn write_cache(file_path: &Path, data: &impl Encode) -> std::io::Result<()> {
    println!("Writing cache to {}...", file_path.display());
    if let Some(parent) = file_path.parent() {
        if !parent.exists() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let now = std::time::Instant::now();
    let encoded_data = bitcode::encode(data);
    let compressed_data = zstd::stream::encode_all(encoded_data.as_slice(), 5)?;
    let elapsed = now.elapsed();
    println!("Encoded cache to in {} ms", elapsed.as_millis());
    std::fs::write(file_path, compressed_data)
}

pub fn read_cache<T>(file_path: &Path) -> std::io::Result<T>
where
    T: for<'de> Decode<'de>,
{
    println!("Reading cache from {}...", file_path.display());
    let compressed_data = std::fs::read(file_path)?;
    let now = std::time::Instant::now();
    let encoded_data: Vec<u8> = zstd::stream::decode_all(compressed_data.as_slice())?;
    let decoded = bitcode::decode(&encoded_data).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("bitcode error: {}", e),
        )
    })?;
    let elapsed = now.elapsed();
    println!("Decoded cache in {} ms", elapsed.as_millis());

    Ok(decoded)
}

pub fn cleanup_cache_files(prefix: &str, cache_location: &Path, max_cache_files: u32) {
    let mut paths: Vec<PathBuf> = std::fs::read_dir(cache_location)
        .unwrap()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_name().to_str().unwrap_or("").starts_with(prefix))
        .map(|entry| entry.path())
        .collect();

    paths.sort_by_key(|path| {
        std::fs::metadata(path)
            .and_then(|m| m.modified())
            .unwrap_or_else(|_| std::time::SystemTime::now())
    });

    if paths.len() >= max_cache_files as usize {
        if let Some(oldest) = paths.first() {
            std::fs::remove_file(oldest).expect("Failed to delete the old cache file");
            println!("Old cache file deleted: {:?}", oldest);
        }
    }
}
