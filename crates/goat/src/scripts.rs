use bitcoin::{
    hashes::{ripemd160::Hash as Ripemd160, sha256::Hash as Sha256, Hash},
    Address, Amount, CompressedPublicKey, Network, PubkeyHash, PublicKey, ScriptBuf, TxOut,
    XOnlyPublicKey,
};
use bitvm::treepp::script;
use std::{str::FromStr, sync::LazyLock};

use crate::transactions::base::{DUST_AMOUNT, P2A_AMOUNT};

// TODO replace these public keys
pub static UNSPENDABLE_PUBLIC_KEY: LazyLock<PublicKey> = LazyLock::new(|| {
    PublicKey::from_str(
        "0405f818748aecbc8c67a4e61a03cee506888f49480cf343363b04908ed51e25b9615f244c38311983fb0f5b99e3fd52f255c5cc47a03ee2d85e78eaf6fa76bb9d"
    )
    .unwrap()
});
pub static UNSPENDABLE_TAPROOT_PUBLIC_KEY: LazyLock<XOnlyPublicKey> = LazyLock::new(|| {
    XOnlyPublicKey::from_str("50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0")
        .unwrap()
});

pub fn generate_burn_script() -> ScriptBuf {
    generate_pay_to_pubkey_script(&UNSPENDABLE_PUBLIC_KEY)
}

pub fn generate_burn_script_address(network: Network) -> Address {
    Address::p2wsh(&generate_burn_script(), network)
}

pub fn generate_burn_taproot_script() -> ScriptBuf {
    generate_pay_to_pubkey_taproot_script(&UNSPENDABLE_TAPROOT_PUBLIC_KEY)
}

pub fn generate_pay_to_pubkey_script(public_key: &PublicKey) -> ScriptBuf {
    script! {
        { *public_key }
        OP_CHECKSIG
    }
    .compile()
}

pub fn generate_pay_to_pubkey_hash_with_inscription_script(
    public_key_hash: &PubkeyHash,
    timestamp: u32,
    evm_address: &str,
) -> ScriptBuf {
    let inscription = [
        public_key_hash.as_byte_array().to_vec(),
        timestamp.to_be_bytes().to_vec(),
        evm_address.as_bytes().to_vec(),
    ]
    .concat();
    let inscription_hash = Ripemd160::hash(&Sha256::hash(&inscription).to_byte_array());
    script! {
        OP_FALSE
        OP_IF
        { inscription_hash.to_byte_array().to_vec() }
        OP_ENDIF
        OP_DUP
        OP_HASH160
        { public_key_hash.as_byte_array().to_vec() }
        OP_EQUALVERIFY
        OP_CHECKSIG
    }
    .compile()
}

pub fn generate_p2pkh_address(network: Network, public_key: &PublicKey) -> Address {
    Address::p2pkh(
        CompressedPublicKey::try_from(*public_key).expect("Could not compress public key"),
        network,
    )
}

pub fn generate_p2wpkh_address(network: Network, public_key: &PublicKey) -> Address {
    Address::p2wpkh(
        &CompressedPublicKey::try_from(*public_key).expect("Could not compress public key"),
        network,
    )
}

pub fn generate_pay_to_pubkey_script_address(network: Network, public_key: &PublicKey) -> Address {
    Address::p2wsh(&generate_pay_to_pubkey_script(public_key), network)
}

pub fn generate_pay_to_pubkey_hash_with_inscription_script_address(
    network: Network,
    public_key_hash: &PubkeyHash,
    timestamp: u32,
    evm_address: &str,
) -> Address {
    Address::p2wsh(
        &generate_pay_to_pubkey_hash_with_inscription_script(
            public_key_hash,
            timestamp,
            evm_address,
        ),
        network,
    )
}

pub fn generate_pay_to_pubkey_taproot_script(public_key: &XOnlyPublicKey) -> ScriptBuf {
    script! {
        { *public_key }
        OP_CHECKSIG
    }
    .compile()
}

pub fn generate_pay_to_pubkey_taproot_script_address(
    network: Network,
    public_key: &XOnlyPublicKey,
) -> Address {
    Address::p2wsh(&generate_pay_to_pubkey_taproot_script(public_key), network)
}

pub fn generate_timelock_script(public_key: &PublicKey, num_blocks_timelock: u32) -> ScriptBuf {
    script! {
      { num_blocks_timelock }
      OP_CSV
      OP_DROP
      { *public_key }
      OP_CHECKSIG
    }
    .compile()
}

pub fn generate_timelock_script_address(
    network: Network,
    public_key: &PublicKey,
    num_blocks_timelock: u32,
) -> Address {
    Address::p2wsh(
        &generate_timelock_script(public_key, num_blocks_timelock),
        network,
    )
}

pub fn generate_timelock_taproot_script(
    public_key: &XOnlyPublicKey,
    num_blocks_timelock: u32,
) -> ScriptBuf {
    script! {
      { num_blocks_timelock }
      OP_CSV
      OP_DROP
      { *public_key }
      OP_CHECKSIG
    }
    .compile()
}

pub fn generate_timelock_taproot_script_address(
    network: Network,
    public_key: &XOnlyPublicKey,
    num_blocks_timelock: u32,
) -> Address {
    Address::p2wsh(
        &generate_timelock_taproot_script(public_key, num_blocks_timelock),
        network,
    )
}

pub fn generate_opreturn_script(msg: Vec<u8>) -> ScriptBuf {
    assert!(msg.len() <= 80, "message must less than 80 bytes");
    script! {
        OP_RETURN
        {msg}
    }
    .compile()
}

pub fn p2a_amount() -> Amount {
    Amount::from_sat(P2A_AMOUNT)
}

pub fn p2a_script() -> ScriptBuf {
    ScriptBuf::from_bytes(hex::decode("51024e73").unwrap())
}

pub fn p2a_output() -> TxOut {
    TxOut {
        value: p2a_amount(),
        script_pubkey: p2a_script(),
    }
}

pub fn generate_data_commitment_outputs(data: &[u8]) -> Vec<TxOut> {
    let data_len = data.len();
    if data_len <= 80 {
        vec![TxOut {
            value: Amount::ZERO,
            script_pubkey: generate_opreturn_script(data.to_vec()),
        }]
    } else {
        let mut txouts = vec![];
        let mut data = data.to_vec();
        let opreturn_len = data_len - (data_len - 80).div_ceil(32) * 32;
        let opreturn_data = data.split_off(data_len - opreturn_len);
        for chunk in data.chunks(32) {
            txouts.push(TxOut {
                value: Amount::from_sat(DUST_AMOUNT),
                script_pubkey: script! {
                    OP_0
                    { chunk.to_vec() }
                }
                .compile(),
            });
        }
        txouts.push(TxOut {
            value: Amount::ZERO,
            script_pubkey: generate_opreturn_script(opreturn_data),
        });
        txouts
    }
}

pub fn is_valid_commitment_outputs(txouts: &[TxOut]) -> bool {
    if txouts.is_empty() {
        return false;
    }
    let last_txout = &txouts[txouts.len() - 1];
    if !last_txout.script_pubkey.is_op_return() {
        return false;
    }
    for txout in &txouts[..txouts.len() - 1] {
        if !txout.script_pubkey.is_p2wsh() {
            return false;
        }
    }
    true
}

pub fn extract_data_from_commitment_outputs(txouts: &[TxOut]) -> Vec<u8> {
    let mut data = vec![];
    for txout in txouts {
        let script = &txout.script_pubkey;
        let instructions = script
            .instructions_minimal()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        if let bitcoin::blockdata::script::Instruction::PushBytes(bytes) = &instructions[1] {
            data.extend_from_slice(bytes.as_bytes());
        }
        if script.is_op_return() {
            break;
        }
    }
    data
}

#[test]
fn test_commitment_outputs() {
    let data = b"Hello, this is a test message for commitment outputs. It should be split into multiple outputs as it exceeds opreturn size limit.";
    let outputs = generate_data_commitment_outputs(data);
    assert!(is_valid_commitment_outputs(&outputs));
    let extracted_data = extract_data_from_commitment_outputs(&outputs);
    assert_eq!(extracted_data, data.to_vec());
}
