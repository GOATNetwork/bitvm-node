use alloy::primitives::Address as EvmAddress;
use bitcoin::consensus::encode::deserialize;
use bitcoin::{Transaction, Txid};
use client::goat_chain::GOATClient;
use serde::{Deserialize, Serialize};

use crate::utils::evm_swap_utils::IEscrowManager::{EscrowData, IEscrowManagerCalls};
use alloy::primitives::{B256, keccak256};
use alloy::rpc::types::trace::geth::{CallConfig, CallFrame, GethDebugTracingOptions};
use alloy::sol;
use alloy::sol_types::SolInterface;
use alloy::sol_types::SolValue;
#[cfg(test)]
use bitcoin::hashes::Hash;
#[cfg(test)]
use std::str::FromStr;
use tracing::warn;

sol! {
    interface IEscrowManager {
        event Initialize(address indexed offerer, address indexed claimer, bytes32 indexed escrowHash, address claimHandler, address refundHandler);
        event Claim(address indexed offerer, address indexed claimer, bytes32 indexed escrowHash, address claimHandler, bytes witnessResult); // for BitcoinNoncedOutputClaimHandler, Claim.witnessResult = payout_btc_txid
        event Refund(address indexed offerer, address indexed claimer, bytes32 indexed escrowHash, address refundHandler, bytes witnessResult);
        event ExecutionError(bytes32 indexed escrowHash, bytes error);
        #[derive(Debug)]
        struct EscrowData {
            //Account funding the escrow
            address offerer;
            //Account entitled to claim the funds from the escrow
            address claimer;

            //Amount of tokens in the escrow
            uint256 amount;
            //Token of the escrow
            address token;

            //Misc escrow data flags, currently defined: payIn, payOut, reputation.
            //It is recommended to randomize the other unused bits in the flags to act as a salt,
            // such that no 2 escrow data are the same, even if all the other data in them match.
            uint256 flags;

            //Address of the IClaimHandler deciding if this escrow is claimable
            // use BitcoinNoncedOutputClaimHandler for Goat -> Bitcoin swaps
            address claimHandler;
            //Data provided to the claim handler along with the witness to check claimability
            // for BitcoinNoncedOutputClaimHandler, this is the hash commitment of the claim data, see hash_claim_commitment
            bytes32 claimData;

            //Address of the IRefundHandler deciding if this escrow is refundable
            // use TimelockRefundHandler for Goat -> Bitcoin swaps
            address refundHandler;
            //Data provided to the refund handler along with the witness to check for refundability
            // for TimelockRefundHandler, this is the timestamp after which refund is possible
            bytes32 refundData;

            //Security deposit taken by the offerer if swap expires without claimer claiming (i.e. options premium)
            uint256 securityDeposit;
            //Claimer bounty that can be claimed by a 3rd party claimer if he were to claim this swap on behalf of claimer
            uint256 claimerBounty;
            //Deposit token of the swap used for securityDeposit and claimerBounty
            address depositToken;

            //ExecutionAction hash commitment to be executed on claim, left 0x0 if no execution should happen on claim
            bytes32 successActionCommitment;
        }
        function initialize(EscrowData calldata escrow, bytes calldata signature, uint256 timeout, bytes memory _extraData) external payable {}
        function claim(EscrowData calldata escrow, bytes calldata witness) external {}
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct ClaimData {
    pub txid: Txid,
    pub nonce: u64,
    pub output_amount: u64,
    pub output_script: Vec<u8>,
    pub confirmations: u32,
    pub btc_relay_contract: EvmAddress,
    pub witness: String,
}

pub fn hash_escrow_data(escrow: &EscrowData) -> B256 {
    let encoded = escrow.abi_encode();
    keccak256(&encoded)
}

pub fn hash_claim_commitment(claim_data: &ClaimData) -> B256 {
    // txoHash = keccak256(uint64 nonce || uint64 outputAmount || keccak256(bytes outputScript))
    // Commitment: C = abi.encodePacked(bytes32 txoHash, uint32 confirmations, address btcRelayContract)
    // Witness: W = C || StoredBlockHeader blockheader || uint32 vout || bytes transaction || uint32 position || bytes32[] merkleProof
    sol! {
        interface IClaimHandlerHelper {
            struct Txo {
                uint64 nonce;
                uint64 outputAmount;
                bytes32 outputScriptHash;
            }
            struct ClaimCommitment {
                bytes32 TxoHash;
                uint32 confirmations;
                address btcRelayContract;
            }
        }
    }
    let output_script_hash = keccak256(&claim_data.output_script);
    let txo = IClaimHandlerHelper::Txo {
        nonce: claim_data.nonce,
        outputAmount: claim_data.output_amount,
        outputScriptHash: output_script_hash,
    };
    let txo_hash = keccak256(txo.abi_encode_packed());
    let claim_commitment = IClaimHandlerHelper::ClaimCommitment {
        TxoHash: txo_hash,
        confirmations: claim_data.confirmations,
        btcRelayContract: claim_data.btc_relay_contract,
    };
    keccak256(claim_commitment.abi_encode_packed())
}

fn find_escrow_data(
    call: &CallFrame,
    swap_contract_address: &EvmAddress,
    escrow_hash: &[u8; 32],
) -> anyhow::Result<Option<EscrowData>> {
    if call.to == Some(*swap_contract_address)
        && let Ok(calldata) = IEscrowManagerCalls::abi_decode(&call.input)
        && let IEscrowManagerCalls::initialize(args) = calldata
    {
        let computed_hash = hash_escrow_data(&args.escrow);
        if &computed_hash.0 == escrow_hash {
            return Ok(Some(args.escrow));
        }
    }

    for sub_call in &call.calls {
        if let Some(escrow_data) = find_escrow_data(sub_call, swap_contract_address, escrow_hash)? {
            return Ok(Some(escrow_data));
        }
    }
    Ok(None)
}

pub async fn extract_escrow_data_from_tx(
    goat_client: &GOATClient,
    tx_hash: &str,
    swap_contract_address: &EvmAddress,
    escrow_hash: &[u8; 32],
) -> anyhow::Result<Option<EscrowData>> {
    let trace_opts = GethDebugTracingOptions::call_tracer(CallConfig::default());
    let trace_raw = goat_client.debug_trace_tx(tx_hash, Some(trace_opts)).await?;
    let call_trace = trace_raw.try_into_call_frame()?;
    if let Some(escrow_data) = find_escrow_data(&call_trace, swap_contract_address, escrow_hash)? {
        Ok(Some(escrow_data))
    } else {
        Ok(None)
    }
}

fn claim_data_from_witness(witness: &[u8]) -> anyhow::Result<ClaimData> {
    // txoHash = keccak256(uint64 nonce || uint64 outputAmount || keccak256(bytes outputScript))
    // Witness: W = bytes32 txoHash
    //  || uint32 confirmations
    //  || address btcRelayContract
    //  || StoredBlockHeader(160-bytes) blockheader
    //  || uint32 vout
    //  || bytes transaction (32-byte length prefix + data)
    //  || uint32 position || bytes32[] merkleProof
    // claimData.nonce = or(shl(24, locktimeSub500M), and(firstNSequence, 0x00FFFFFF))
    // claimData.output_amount = W.transaction.outputs[vout].value
    // claimData.output_script = W.transaction.outputs[vout].scriptPubKey

    let mut offset = 0;

    // 1. txoHash (32 bytes)
    if witness.len() < 32 {
        anyhow::bail!("witness too short for txoHash");
    }
    offset += 32;

    // 2. confirmations (4 bytes)
    if witness.len() < offset + 4 {
        anyhow::bail!("witness too short for confirmations");
    }
    let confirmations = u32::from_be_bytes(witness[offset..offset + 4].try_into()?);
    offset += 4;

    // 3. btcRelayContract (20 bytes)
    if witness.len() < offset + 20 {
        anyhow::bail!("witness too short for btcRelayContract");
    }
    let btc_relay_contract = EvmAddress::from_slice(&witness[offset..offset + 20]);
    offset += 20;

    // 4. StoredBlockHeader (160 bytes)
    if witness.len() < offset + 160 {
        anyhow::bail!("witness too short for blockheader");
    }
    offset += 160;

    // 5. vout (4 bytes)
    if witness.len() < offset + 4 {
        anyhow::bail!("witness too short for vout");
    }
    let vout = u32::from_be_bytes(witness[offset..offset + 4].try_into()?);
    offset += 4;

    // 6. transaction (32-byte length prefix + data)
    if witness.len() < offset + 32 {
        anyhow::bail!("witness too short for transaction length");
    }
    let tx_len = alloy::primitives::U256::from_be_slice(&witness[offset..offset + 32]);
    offset += 32;

    let tx_len_usize: usize =
        tx_len.try_into().map_err(|_| anyhow::anyhow!("tx length too large"))?;

    if witness.len() < offset + tx_len_usize {
        anyhow::bail!("witness too short for transaction data");
    }
    let tx_bytes = &witness[offset..offset + tx_len_usize];

    let tx: Transaction = deserialize(tx_bytes)?;

    if vout as usize >= tx.output.len() {
        anyhow::bail!("vout index out of bounds");
    }
    let output = &tx.output[vout as usize];

    if tx.input.is_empty() {
        anyhow::bail!("transaction has no inputs");
    }
    let first_input_sequence = tx.input[0].sequence.to_consensus_u32();

    let lock_time = tx.lock_time.to_consensus_u32();
    let lock_time_val = if lock_time >= 500_000_000 { lock_time - 500_000_000 } else { lock_time };

    let nonce = ((lock_time_val as u64) << 24) | ((first_input_sequence as u64) & 0x00ffffff);

    Ok(ClaimData {
        txid: tx.compute_txid(),
        nonce,
        output_amount: output.value.to_sat(),
        output_script: output.script_pubkey.to_bytes(),
        confirmations,
        btc_relay_contract,
        witness: hex::encode(witness),
    })
}

// for BitcoinNoncedOutputClaimHandler
fn find_claim_data(
    tx_hash: &str,
    call: &CallFrame,
    swap_contract_address: &EvmAddress,
    escrow_hash: &[u8; 32],
) -> anyhow::Result<Option<ClaimData>> {
    if call.to == Some(*swap_contract_address)
        && let Ok(calldata) = IEscrowManagerCalls::abi_decode(&call.input)
        && let IEscrowManagerCalls::claim(args) = calldata
    {
        let computed_hash = hash_escrow_data(&args.escrow);
        if &computed_hash.0 == escrow_hash {
            return match claim_data_from_witness(&args.witness) {
                Ok(claim_data) => Ok(Some(claim_data)),
                Err(e) => {
                    warn!("fail to decode claim data for tx: {tx_hash}, error:{e}");
                    Ok(None)
                }
            };
        }
    }

    for sub_call in &call.calls {
        if let Some(claim_data) =
            find_claim_data(tx_hash, sub_call, swap_contract_address, escrow_hash)?
        {
            return Ok(Some(claim_data));
        }
    }
    Ok(None)
}

pub async fn extract_claim_data_from_tx(
    goat_client: &GOATClient,
    tx_hash: &str,
    swap_contract_address: &EvmAddress,
    escrow_hash: &[u8; 32],
) -> anyhow::Result<Option<ClaimData>> {
    let trace_opts = GethDebugTracingOptions::call_tracer(CallConfig::default());
    let trace_raw = goat_client.debug_trace_tx(tx_hash, Some(trace_opts)).await?;
    let call_trace = trace_raw.try_into_call_frame()?;
    if let Some(claim_data) =
        find_claim_data(tx_hash, &call_trace, swap_contract_address, escrow_hash)?
    {
        Ok(Some(claim_data))
    } else {
        Ok(None)
    }
}

#[tokio::test]
async fn test_find_escrow_data() {
    unsafe {
        std::env::set_var(crate::env::ENV_GOAT_CHAIN_URL, "https://rpc.testnet3.goat.network");
    }
    let tx_hash = "0x6027024dc57b847120074efed67c3e31534988f70b6b1e5043b248e7740a295c";
    let goat_client = GOATClient::new(
        crate::env::goat_config_from_env().await,
        client::goat_chain::GoatNetwork::Test,
    );
    let swap_contract_address =
        EvmAddress::from_str("0xe510D5781C6C849284Fb25Dc20b1684cEC445C8B").unwrap();
    let escrow_hash: [u8; 32] =
        hex::decode("521a1d007f9fdf41b18ad6f1ccfeaf8fd67d0b04608ce3d8950526e55e4eca28")
            .unwrap()
            .try_into()
            .unwrap();
    let escrow_data =
        extract_escrow_data_from_tx(&goat_client, tx_hash, &swap_contract_address, &escrow_hash)
            .await
            .unwrap();
    assert!(escrow_data.is_some());
    let expected_claim_hash =
        B256::from_str("0xc69e4a62e0c904b341245656ba191790356d771bd4a7a00bed2780a5abad8c63")
            .unwrap();
    assert_eq!(escrow_data.unwrap().claimData, expected_claim_hash);
}

#[test]
fn test_hash_claim_commitment() {
    // example data from an actual swap on testnet:
    // goat initialize txid: 0x6027024dc57b847120074efed67c3e31534988f70b6b1e5043b248e7740a295c
    // goat claim txid: 0xc2b26508a28f349c7ee1e189914dc5815b77d1abaa5ce6a60449f69bd1e7e64a
    // btc payout txid: 033d4024aca7f6dda6b01e7f0a2bb0fdd15160cc9b2559b55c6f65962362d74e
    let claim_data = ClaimData {
        txid: Txid::from_slice(&[0_u8; 32]).unwrap(),
        nonce: 17872110975047329u64,
        output_amount: 9511u64,
        output_script: hex::decode(
            "5120a5d06cb76aaf6287b93a8ee73d9678e32b039354e6df4019bbd60087e347f5cc",
        )
        .unwrap(),
        confirmations: 2u32,
        btc_relay_contract: EvmAddress::from_str("0x3887B02217726bB36958Dd595e57293fB63D5082")
            .unwrap(),
        witness: "".to_string(),
    };
    let commitment_hash = hash_claim_commitment(&claim_data);

    let expected_hash =
        B256::from_str("0xc69e4a62e0c904b341245656ba191790356d771bd4a7a00bed2780a5abad8c63")
            .unwrap();
    assert_eq!(commitment_hash, expected_hash);
}

#[tokio::test]
async fn test_find_claim_data() {
    unsafe {
        std::env::set_var(crate::env::ENV_GOAT_CHAIN_URL, "https://rpc.testnet3.goat.network");
    }
    let tx_hash = "0xc2b26508a28f349c7ee1e189914dc5815b77d1abaa5ce6a60449f69bd1e7e64a";
    let goat_client = GOATClient::new(
        crate::env::goat_config_from_env().await,
        client::goat_chain::GoatNetwork::Test,
    );
    let swap_contract_address =
        EvmAddress::from_str("0xe510D5781C6C849284Fb25Dc20b1684cEC445C8B").unwrap();
    let escrow_hash: [u8; 32] =
        hex::decode("521a1d007f9fdf41b18ad6f1ccfeaf8fd67d0b04608ce3d8950526e55e4eca28")
            .unwrap()
            .try_into()
            .unwrap();
    let expected_claim_data = ClaimData {
        txid: Txid::from_str("033d4024aca7f6dda6b01e7f0a2bb0fdd15160cc9b2559b55c6f65962362d74e")
            .unwrap(),
        nonce: 17872110975047329u64,
        output_amount: 9511u64,
        output_script: hex::decode(
            "5120a5d06cb76aaf6287b93a8ee73d9678e32b039354e6df4019bbd60087e347f5cc",
        )
        .unwrap(),
        confirmations: 2u32,
        btc_relay_contract: EvmAddress::from_str("0x3887B02217726bB36958Dd595e57293fB63D5082")
            .unwrap(),
        witness: "8977831297fa2d7156898a8d26bb9e276a83cf907d739eb64ff98a0092e9250e000000023887b022\
        17726bb36958dd595e57293fb63d508200600020bfe2760399ccb567289b120361316911b13e937aa0f2742bb7\
        0b000000000000efaf19dc26fadb8b1cd69e76c6d1f51123f6d22407755f865b65b446cf863c3c5fbe3769f0ff\
        0f1ad88a60f10000000000000000000000000000000000000000000017b6e253602b5f4cc25000494e876937b2\
        636937bd246937bd2a6937bd2d6937bd306937bd6f6937bd8f6937bda66937bde76937bdf96937be07000000000\
        00000000000000000000000000000000000000000000000000000000000008902000000018c3db50ef29dbdddf9\
        628cd968667688cd37560ef5e64131efc3a1e4cf4e739c0100000000a1d60dfe022725000000000000225120a5d\
        06cb76aaf6287b93a8ee73d9678e32b039354e6df4019bbd60087e347f5ccf61a010000000000225120eb3e0c2d\
        d6b344c6efaa771306a29e864c65d536dfac8f89a87680285af7acad1afc4b5d000000060000000000000000000\
        000000000000000000000000000000000000000000003f7cfe6eed4929eea954c8e1358704c6dec19e2826f7223\
        ff7d0eff92c1addf20fd2b876e05846a100c38bd3c30619c66437abb97bc5fc21e2595fbb8a514f5341ebf1f8dd\
        26752879de5c581667aaf183b18c1b5a111f4a24061d2c44aea2fd1"
            .to_string(),
    };
    let claim_data =
        extract_claim_data_from_tx(&goat_client, tx_hash, &swap_contract_address, &escrow_hash)
            .await
            .unwrap();
    assert!(claim_data.is_some());
    assert_eq!(claim_data.unwrap(), expected_claim_data);
}
