use bitcoin::absolute::LockTime;
use bitcoin::blockdata::opcodes::all::*;
use bitcoin::blockdata::script::Builder;
use bitcoin::script::PushBytesBuf;
use bitcoin::transaction::Version;
use bitcoin::{Address, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};

/// Return script length L for a standard m-of-n multisig script with compressed pubkeys.
pub fn multisig_script_len(n: u32) -> u32 {
    // <m>(1) + n * (push(33)=1 + 33) + <n>(1) + OP_CHECKMULTISIG(1)
    1 + n * 34 + 1 + 1
}

/// Estimate vbytes for a P2WSH m-of-n input (SegWit v0), rounding up.
#[allow(clippy::manual_div_ceil)]
pub fn p2wsh_input_vbytes(m: u32, n: u32, siglen: u32) -> u32 {
    let l = multisig_script_len(n);
    // witness = 1(count) + 1(dummy) + m*(1+siglen) + (1 + L)
    let witness_bytes = 1 + 1 + m * (1 + siglen) + (1 + l);
    let weight = 4 * 41 + witness_bytes; // base 41 bytes
    (weight + 3) / 4 // ceil(weight/4)
}

/// Common siglen is ~73 incl. sighash byte.
pub fn estimate_tx_vbytes(
    inputs: &[(u32, u32)],           // list of (m, n) P2WSH inputs
    outputs: &[(&'static str, u32)], // ("p2wpkh"|"p2wsh"|"p2tr"|"p2pkh", count)
    siglen: u32,
) -> u32 {
    let mut v = 10; // overhead
    for &(m, n) in inputs {
        v += p2wsh_input_vbytes(m, n, siglen);
    }
    for &(ty, count) in outputs {
        let size = match ty {
            "p2wpkh" => 31,
            "p2wsh" => 43,
            "p2tr" => 43,
            "p2pkh" => 34,
            _ => panic!("unknown output type"),
        };
        v += size * count;
    }
    v
}

/// `create_fee_tx` create a fee payment tx for `sequencer_update_tx`.
///  
pub fn create_fee_tx(
    evm_address: &[u8; 20],
    input: &OutPoint,
    input_value: Amount,
    replennish_fee: Amount,
    destination: Address,
    change: Address,
    relayer_fee: Amount,
) -> Result<Transaction, Box<dyn std::error::Error>> {
    let script = Builder::new().push_opcode(OP_RETURN).push_slice(evm_address).into_script();

    let change_value = input_value - replennish_fee - relayer_fee;

    let txin = TxIn {
        previous_output: *input,
        script_sig: ScriptBuf::new(), // empty for P2WSH
        sequence: Sequence::MAX,
        witness: Witness::default(), // to be filled after signing
    };

    let txout_fee = TxOut { value: replennish_fee, script_pubkey: destination.script_pubkey() };

    // make TxOut with 0 satoshis
    let txout_op_return = TxOut { value: Amount::ZERO, script_pubkey: script };

    let txout_change = TxOut { value: change_value, script_pubkey: change.script_pubkey() };

    Ok(Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![txin],
        output: vec![txout_fee, txout_op_return, txout_change],
    })
}

pub fn create_sequencer_update_partial_tx(
    commitment: [u8; 32],
    update_connector: &Option<OutPoint>,
    replenish_fee_connector: &Option<OutPoint>,
    next_update_connector: Address,
    relayer_fee: Amount,
) -> Result<Transaction, Box<dyn std::error::Error>> {
    assert!(
        update_connector.is_some() || replenish_fee_connector.is_some(),
        "At least one of update_connector or replenish_fee_connector must be provided"
    );
    let txout_next_connector =
        TxOut { value: relayer_fee, script_pubkey: next_update_connector.script_pubkey() };

    println!("commitment: {commitment:?}");

    let commitment =
        PushBytesBuf::try_from(commitment.to_vec()).expect("commitment payload is pushable");
    let script = Builder::new().push_opcode(OP_RETURN).push_slice(commitment).into_script();

    // make TxOut with 0 satoshis
    let txout_op_return = TxOut { value: Amount::ZERO, script_pubkey: script };

    let mut input = Vec::new();
    if let Some(uc) = update_connector {
        let txin_connector = TxIn {
            previous_output: *uc,
            script_sig: ScriptBuf::new(), // empty for P2WSH
            sequence: Sequence::MAX,
            witness: Witness::default(), // to be filled after signing
        };
        input.push(txin_connector);
    }
    if let Some(rfc) = replenish_fee_connector {
        let txin_replenish_fee_connector = TxIn {
            previous_output: *rfc,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::default(), // to be filled after signing
        };
        input.push(txin_replenish_fee_connector);
    };

    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input,
        output: vec![txout_next_connector, txout_op_return],
    };
    Ok(tx)
}
