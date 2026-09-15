use core::time::Duration;
use cosmos_sdk_proto::cosmos::tx::v1beta1::Tx;
use prost::Message;
use sha2::{Digest, Sha256};
pub use tendermint_light_client_verifier::{
    ProdVerifier, Verdict, Verifier,
    options::Options,
    types::{Header, LightBlock},
};

use crate::proto::ExecutionPayload;

pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/goat.goat.v1.rs"));
    //include!(concat!(env!("OUT_DIR"), "/goat.goat.v1.serde.rs"));
}

fn merkle_leaf_hash(leaf: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x00]);
    h.update(leaf);
    h.finalize().into()
}

fn merkle_inner_node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x01]);
    h.update(left);
    h.update(right);
    h.finalize().into()
}

fn largest_power_of_two_less_than(n: usize) -> usize {
    let mut k = 1usize;
    while (k << 1) < n {
        k <<= 1;
    }
    k
}

fn compute_merkle_root(items: &[[u8; 32]]) -> [u8; 32] {
    match items.len() {
        0 => Sha256::digest([]).into(),
        1 => merkle_leaf_hash(&items[0]),
        n => {
            let k = largest_power_of_two_less_than(n);
            let left = compute_merkle_root(&items[..k]);
            let right = compute_merkle_root(&items[k..]);
            merkle_inner_node_hash(&left, &right)
        }
    }
}

fn merkle_root_from_base64_txns(txns_b64: &[Vec<u8>]) -> [u8; 32] {
    let tx_hashes: Vec<[u8; 32]> = txns_b64.iter().map(|s| Sha256::digest(s).into()).collect();
    compute_merkle_root(&tx_hashes)
}

pub fn verify_sequencer_commit(light_block: &LightBlock) {
    let vp = ProdVerifier::default();
    let untrusted = light_block.as_untrusted_state();
    for verdict in [vp.verify_validator_sets(&untrusted), vp.verify_commit(&untrusted)] {
        if !matches!(verdict, Verdict::Success) {
            panic!("invalid sequencer commit: {verdict:?}");
        }
    }
}

/// Verify
pub fn verify_sequencer_set(light_block_1: LightBlock, light_block_2: LightBlock) {
    println!("LightBlock1 number of validators: {}", light_block_1.validators.validators().len());
    println!("LightBlock2 number of validators: {}", light_block_2.validators.validators().len());

    assert_eq!(
        light_block_1.next_validators.hash(),
        light_block_1.as_trusted_state().next_validators_hash
    );
    let vp = ProdVerifier::default();
    let opt = Options {
        trust_threshold: Default::default(),
        trusting_period: Duration::from_secs(500),
        clock_drift: Default::default(),
    };
    let verify_time = light_block_2.time() + Duration::from_secs(20);
    let verdict = vp.verify_update_header(
        light_block_2.as_untrusted_state(),
        light_block_1.as_trusted_state(),
        &opt,
        verify_time.unwrap(),
    );
    match verdict {
        Verdict::Success => {
            println!("success");
        }
        v => panic!("expected success, got: {v:?}"),
    }
}

// we can not move it to cbft-rpc since it'll get non-std involved.
pub fn parse_cbft_tx_payload(tx_bytes: &[u8]) -> Option<ExecutionPayload> {
    let tx = Tx::decode(tx_bytes).unwrap();

    // check consistance of GOAT block hash
    if let Some(tx_body) = tx.body {
        let first_message = &tx_body.messages[0];
        // https://github.com/GOATNetwork/goat/blob/main/proto/goat/goat/v1/tx.proto#L25
        let type_url = first_message.type_url.as_str();
        assert_eq!(type_url, "/goat.goat.v1.MsgNewEthBlock");
        let payload = proto::MsgNewEthBlock::decode(&first_message.value[..]).unwrap();
        let payload = payload.payload.unwrap();
        return Some(payload);
    };
    None
}

pub fn check_el_block_from_payload(
    el_block_number: u64,
    el_block_hash: &[u8; 32],
    el_parent_block_hash: &[u8; 32],
    txs: &[Vec<u8>],
    actual_data_hash: &[u8; 32],
) {
    // The payload is what binds this EVM block to the chain we are extending, so
    // it must be present: a `Tx` encoded without a body decodes to `body: None`,
    // which used to skip all three assertions and leave only the merkle root.
    assert!(!txs.is_empty(), "cosmos block carries no txs");
    let payload = parse_cbft_tx_payload(&txs[0]).expect("missing MsgNewEthBlock payload");
    assert_eq!(payload.block_number, el_block_number);
    assert_eq!(payload.block_hash, el_block_hash);
    assert_eq!(payload.parent_hash, el_parent_block_hash);
    let computed_data_hash = merkle_root_from_base64_txns(txs);
    assert_eq!(*actual_data_hash, computed_data_hash);
}

#[cfg(test)]
mod tests {
    use super::*;

    pub const LB_1_JSON: &str = include_str!("../samples/light_block_5756784.json");
    pub const LB_2_JSON: &str = include_str!("../samples/light_block_5756785.json");

    pub const LB_1_JSON_TXNS: &str = include_str!("../samples/light_block_5756784.json.txns");
    pub const LB_2_JSON_TXNS: &str = include_str!("../samples/light_block_5756785.json.txns");
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as BASE64;

    #[test]
    pub fn test_verify_validator_set() {
        let light_block_1 = serde_json::from_str::<LightBlock>(LB_1_JSON).unwrap();
        let light_block_2 = serde_json::from_str::<LightBlock>(LB_2_JSON).unwrap();
        verify_sequencer_set(light_block_1, light_block_2.clone());
    }

    #[test]
    fn sequencer_commit_rejects_a_validator_hash_mismatch() {
        let mut light_block = serde_json::from_str::<LightBlock>(LB_1_JSON).unwrap();
        verify_sequencer_commit(&light_block);
        light_block.signed_header.header.validators_hash = tendermint::Hash::Sha256([0x42; 32]);
        assert!(std::panic::catch_unwind(|| verify_sequencer_commit(&light_block)).is_err());
    }

    #[test]
    pub fn test_verify_goat_block() {
        // https://explorer.goat.network/block/5756298
        // curl "http://127.0.0.1:26657/block?height=5756784" | jq .result.block.data
        let cosmos_txns: Vec<String> = serde_json::from_str(LB_1_JSON_TXNS).unwrap();
        let cosmos_txns =
            cosmos_txns.into_iter().map(|s| BASE64.decode(s).unwrap()).collect::<Vec<_>>();
        // loght block 5756784
        let light_block_1 = serde_json::from_str::<LightBlock>(LB_1_JSON).unwrap();

        check_el_block_from_payload(
            5756298,
            &hex::decode("f51b3d69d25631e34b91c0f043bd30deb00c25eb63b4d45a1433fbcb3e9c494a")
                .unwrap()
                .try_into()
                .unwrap(),
            &hex::decode("fa13fd897dd9d9dbbdbf8e5d8d77c3411ed7dbbe7e1288686eed2ffd8ec99a91")
                .unwrap()
                .try_into()
                .unwrap(),
            &cosmos_txns,
            light_block_1.signed_header.header.data_hash.unwrap().as_bytes().try_into().unwrap(),
        );

        //
        let light_block_2 = serde_json::from_str::<LightBlock>(LB_2_JSON).unwrap();
        // curl "http://127.0.0.1:26657/block?height=5756785" | jq .result.block.data
        // https://explorer.goat.network/block/5756299
        let cosmos_txns: Vec<String> = serde_json::from_str(LB_2_JSON_TXNS).unwrap();
        let cosmos_txns =
            cosmos_txns.into_iter().map(|s| BASE64.decode(s).unwrap()).collect::<Vec<_>>();
        check_el_block_from_payload(
            5756299,
            &hex::decode("56473094ffd5bc070446fdbaaf2b443b9beffb82dded0e053eb6b25c7d60be0b")
                .unwrap()
                .try_into()
                .unwrap(),
            &hex::decode("f51b3d69d25631e34b91c0f043bd30deb00c25eb63b4d45a1433fbcb3e9c494a")
                .unwrap()
                .try_into()
                .unwrap(),
            &cosmos_txns,
            light_block_2.signed_header.header.data_hash.unwrap().as_bytes().try_into().unwrap(),
        );
    }
}
