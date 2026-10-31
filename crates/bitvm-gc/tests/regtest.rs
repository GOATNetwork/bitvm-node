use anyhow::{Context, Result, anyhow, bail, ensure};
use ark_bn254::{Bn254, Fr, G1Affine, G2Affine};
use ark_ec::AffineRepr;
use ark_groth16::Proof;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use bitcoin::hashes::{Hash, hash160};
use bitcoin::key::Keypair;
use bitcoin::secp256k1::{SECP256K1, SecretKey};
use bitcoin::{
    Address, Amount, EcdsaSighashType, Network, OutPoint, PublicKey, ScriptBuf, Sequence,
    Transaction, TxIn, TxOut, Txid, XOnlyPublicKey, absolute, transaction,
};
use bitcoin_script::script;
use bitvm_gc::babe_adapter::{
    BABE_M_CC, BabeProverState, CACSetupPackage, Seed, TxAssertWitness, assert_wots_message,
    build_assert_witness, build_setup_package, derive_finalized_indices, extract_gc_circuit_data,
    open_and_solder, recover_operator_proof_from_assert_witness, verify_setup,
};
use bitvm_gc::committee::{
    agg_and_push_pegin_confirm_sigs, committee_pre_sign, generate_nonce_from_seed, key_aggregation,
    nonce_aggregation, nonces_aggregation, push_committee_pre_signatures, sign_pegin_confirm,
    signature_aggregation, verify_graph_committee_pre_signatures, verify_nonce_signatures,
};
use bitvm_gc::keys::{CommitteeMasterKey, OperatorMasterKey};
use bitvm_gc::operator::{
    generate_bitvm_graph, operator_pre_sign, operator_sign_assert, operator_sign_challenge_ack,
    operator_sign_commit_pubin, operator_sign_kickoff, operator_sign_prekickoff_input_0,
    operator_sign_take1, operator_sign_take2, operator_sign_watchtower_challenge_init,
    operator_sign_watchtower_challenge_timeout, operator_sign_wrongly_challenged,
    verify_graph_operator_pre_signatures,
};
use bitvm_gc::timelocks::{
    connector_f_timelock_blocks, default_timelock_config, disprove_timelock_blocks,
    operator_ack_timelock_blocks, operator_commit_timelock_blocks, take1_timelock_blocks,
    take2_timelock_blocks, watchtower_challenge_timelock_blocks,
};
use bitvm_gc::types::{
    BitvmGcCircuitData, BitvmGcGraph, BitvmGcGraphParameters, BitvmGcInstanceParameters,
    PrekickoffParameters, UserInfo,
};
use bitvm_gc::verifier::{
    build_disprove_tx, build_pubin_disprove_txin, build_verifier_assert_tx, export_challenge_tx,
    validate_pubin_disprove,
};
use bitvm_gc::watchtower::{build_watchtower_challenge_tx, estimate_watchtower_challenge_vbytes};
use esplora_client::AsyncClient as EsploraClient;
use goat::assert_scripts::{INPUT_WIRE_NUM, Label, WireHash, label_hash};
use goat::connectors::base::TaprootConnector;
use goat::connectors::kickoff_connectors::{
    ForceSkipConnector, KickoffConnector, PrekickoffConnector,
};
use goat::scripts::{generate_opreturn_script, p2a_output};
use goat::transactions::base::{DUST_AMOUNT, Input};
use goat::transactions::pre_signed::PreSignedTransaction;
use goat::transactions::prekickoff::PrekickoffTransaction;
use goat::transactions::signing::populate_p2wsh_witness;
use reqwest::Client;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{Duration, Instant};
use tokio::time::sleep;
use uuid::Uuid;

const REGTEST_ESPLORA_URL: &str = "http://127.0.0.1:3002";
const REGTEST_RPC_URL: &str = "http://127.0.0.1:18443/wallet/alice";
const FIXTURE_VERSION: u32 = 1;
const FIXTURE_FILE: &str = "bitvm-gc-regtest-proof-gc-v1.bin";
const DEFAULT_FEE_SATS: u64 = 1_000;
const PREKICKOFF_AMOUNT_SATS: u64 = 500_000;
const PEGIN_AMOUNT_SATS: u64 = 100_000_000;
const PAYER_AMOUNT_SATS: u64 = 5_000_000;
const FEE_RATE_SAT_PER_VBYTE: u64 = 2;
const CONFIRM_TIMEOUT: Duration = Duration::from_secs(60);

static MOCK_FIXTURE: OnceLock<std::result::Result<MockProofGcFixture, String>> = OnceLock::new();

#[derive(Serialize, Deserialize)]
struct MockProofGcFixture {
    version: u32,
    setup_package: CACSetupPackage,
    opened: Vec<(usize, Seed)>,
    prover_state: BabeProverState,
    gc_data: BitvmGcCircuitData,
    proof_bytes: Vec<u8>,
}

struct TestKeys {
    user: Keypair,
    operator: Keypair,
    challenger: Keypair,
    committee: Vec<Keypair>,
    verifier: Keypair,
    watchtowers: Vec<Keypair>,
}

struct RegtestRpc {
    client: Client,
    url: String,
    user: String,
    password: String,
}

struct RegtestGraph {
    graph: BitvmGcGraph,
    keys: TestKeys,
    assert_witness: TxAssertWitness,
    challenge_labels: Vec<Label>,
    final_msg: Vec<u8>,
}

impl RegtestRpc {
    fn from_env() -> Result<Self> {
        Ok(Self {
            client: Client::builder().no_proxy().build().expect("build Bitcoin RPC client"),
            url: std::env::var("BITVM_E2E_BITCOIN_RPC_URL")
                .unwrap_or_else(|_| REGTEST_RPC_URL.to_string()),
            user: std::env::var("BITVM_E2E_BITCOIN_RPC_USER")
                .context("BITVM_E2E_BITCOIN_RPC_USER must be set for regtest E2E tests")?,
            password: std::env::var("BITVM_E2E_BITCOIN_RPC_PASSWORD")
                .context("BITVM_E2E_BITCOIN_RPC_PASSWORD must be set for regtest E2E tests")?,
        })
    }

    async fn call<T: DeserializeOwned>(&self, method: &str, params: Value) -> Result<T> {
        let response = self
            .client
            .post(&self.url)
            .basic_auth(&self.user, Some(&self.password))
            .json(&json!({
                "jsonrpc": "1.0",
                "id": "bitvm-gc-e2e",
                "method": method,
                "params": params,
            }))
            .send()
            .await
            .with_context(|| format!("call Bitcoin RPC method {method}"))?
            .error_for_status()
            .with_context(|| format!("Bitcoin RPC method {method} returned HTTP error"))?;
        let body: Value = response.json().await?;
        if !body["error"].is_null() {
            bail!("Bitcoin RPC method {method} failed: {}", body["error"]);
        }
        serde_json::from_value(body["result"].clone())
            .with_context(|| format!("decode Bitcoin RPC method {method} result"))
    }

    async fn send_to_address(&self, address: &Address, amount: Amount) -> Result<Txid> {
        let txid: String =
            self.call("sendtoaddress", json!([address.to_string(), amount.to_btc()])).await?;
        txid.parse().context("Bitcoin RPC returned invalid funding txid")
    }

    async fn prepare_wallet(&self) -> Result<()> {
        let passphrase = std::env::var("BITVM_E2E_WALLET_PASSPHRASE")
            .context("BITVM_E2E_WALLET_PASSPHRASE must be set for regtest E2E tests")?;
        if let Err(error) = self.call::<Value>("walletpassphrase", json!([passphrase, 3_600])).await
        {
            let message = error.to_string();
            if !message.contains("unencrypted wallet") && !message.contains("not encrypted") {
                return Err(error).context("unlock regtest wallet");
            }
        }

        let balance: f64 = self.call("getbalance", json!([])).await?;
        if balance >= 5.0 {
            return Ok(());
        }

        let mining_address: String = self.call("getnewaddress", json!([])).await?;
        let _: Vec<String> = self.call("generatetoaddress", json!([101, mining_address])).await?;
        Ok(())
    }

    async fn mine_blocks(&self, count: u32, address: &Address) -> Result<()> {
        if count == 0 {
            return Ok(());
        }
        let _: Vec<String> =
            self.call("generatetoaddress", json!([count, address.to_string()])).await?;
        Ok(())
    }
}

fn fixture_path() -> PathBuf {
    if let Some(path) = std::env::var_os("BITVM_E2E_FIXTURE_DIR") {
        return PathBuf::from(path).join(FIXTURE_FILE);
    }
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("bitvm-gc crate must be inside workspace/crates")
        .join("target/e2e-fixtures")
        .join(FIXTURE_FILE)
}

fn keypair(seed: &str) -> Result<Keypair> {
    let digest = Sha256::digest(seed.as_bytes());
    let secret_key = SecretKey::from_slice(&digest)?;
    Ok(Keypair::from_secret_key(SECP256K1, &secret_key))
}

fn test_keys() -> Result<TestKeys> {
    Ok(TestKeys {
        user: keypair("bitvm-gc-e2e-user")?,
        operator: keypair("bitvm-gc-e2e-operator")?,
        challenger: keypair("bitvm-gc-e2e-challenger")?,
        committee: vec![keypair("bitvm-gc-e2e-committee-0")?, keypair("bitvm-gc-e2e-committee-1")?],
        verifier: keypair("bitvm-gc-e2e-verifier")?,
        watchtowers: vec![
            keypair("bitvm-gc-e2e-watchtower-0")?,
            keypair("bitvm-gc-e2e-watchtower-1")?,
        ],
    })
}

fn generate_fixture() -> Result<MockProofGcFixture> {
    let keys = test_keys()?;
    let setup_package = build_setup_package(BABE_M_CC + 1)?;
    let finalized_indices = derive_finalized_indices(&setup_package, BABE_M_CC)?;
    let (opened, finalized, soldering) = open_and_solder(&setup_package, &finalized_indices)?;
    verify_setup(&setup_package, &opened, &finalized, &soldering)?;

    let epk = &setup_package.commits[finalized[0].index].epk;
    let h_msgs =
        finalized.iter().map(|item| setup_package.commits[item.index].h_msg).collect::<Vec<_>>();
    let gc_data =
        extract_gc_circuit_data(PublicKey::from(keys.verifier.public_key()), epk, &h_msgs)?;
    let prover_state =
        BabeProverState { package: setup_package.clone(), finalized, soldering, h_msgs };

    let proof = Proof::<Bn254> {
        a: G1Affine::generator(),
        b: G2Affine::generator(),
        c: G1Affine::generator(),
    };
    let mut proof_bytes = Vec::new();
    proof.serialize_compressed(&mut proof_bytes)?;

    Ok(MockProofGcFixture {
        version: FIXTURE_VERSION,
        setup_package,
        opened,
        prover_state,
        gc_data,
        proof_bytes,
    })
}

fn validate_fixture(fixture: &MockProofGcFixture) -> Result<()> {
    ensure!(fixture.version == FIXTURE_VERSION, "fixture version mismatch");
    verify_setup(
        &fixture.setup_package,
        &fixture.opened,
        &fixture.prover_state.finalized,
        &fixture.prover_state.soldering,
    )?;
    ensure!(
        fixture.prover_state.package == fixture.setup_package,
        "fixture prover state uses another setup package"
    );

    let first =
        fixture.prover_state.finalized.first().context("fixture has no finalized GC instance")?;
    let expected_gc = extract_gc_circuit_data(
        PublicKey::from(test_keys()?.verifier.public_key()),
        &fixture.setup_package.commits[first.index].epk,
        &fixture.prover_state.h_msgs,
    )?;
    ensure!(expected_gc == fixture.gc_data, "fixture GC data is inconsistent");
    let _: Proof<Bn254> = Proof::deserialize_compressed(fixture.proof_bytes.as_slice())?;
    Ok(())
}

fn load_or_generate_fixture() -> Result<MockProofGcFixture> {
    let path = fixture_path();
    if let Ok(bytes) = fs::read(&path)
        && let Ok(fixture) = bincode::deserialize::<MockProofGcFixture>(&bytes)
        && validate_fixture(&fixture).is_ok()
    {
        return Ok(fixture);
    }

    let fixture = generate_fixture()?;
    validate_fixture(&fixture)?;
    let parent = path.parent().context("fixture path has no parent")?;
    fs::create_dir_all(parent)?;
    fs::write(&path, bincode::serialize(&fixture)?)
        .with_context(|| format!("write fixture {}", path.display()))?;
    Ok(fixture)
}

fn fixture() -> Result<&'static MockProofGcFixture> {
    match MOCK_FIXTURE.get_or_init(|| load_or_generate_fixture().map_err(|error| error.to_string()))
    {
        Ok(fixture) => Ok(fixture),
        Err(error) => Err(anyhow!(error.clone())),
    }
}

fn mock_proof(fixture: &MockProofGcFixture) -> Result<Proof<Bn254>> {
    Proof::deserialize_compressed(fixture.proof_bytes.as_slice()).map_err(Into::into)
}

fn challenge_label(wire_index: usize, value: bool) -> Label {
    let mut hasher = Sha256::new();
    hasher.update(b"bitvm-gc-regtest-challenge-label");
    hasher.update(wire_index.to_le_bytes());
    hasher.update([u8::from(value)]);
    hasher.finalize()[..16].to_vec()
}

fn synthetic_challenge_data(
    verifier_pubkey: PublicKey,
    message: &[u8; 96],
) -> (BitvmGcCircuitData, Vec<Label>, Vec<u8>) {
    let true_labels =
        (0..INPUT_WIRE_NUM).map(|wire_index| challenge_label(wire_index, true)).collect::<Vec<_>>();
    let false_labels = (0..INPUT_WIRE_NUM)
        .map(|wire_index| challenge_label(wire_index, false))
        .collect::<Vec<_>>();
    let wire_hashes: [WireHash; INPUT_WIRE_NUM] = std::array::from_fn(|wire_index| WireHash {
        true_label_hash: label_hash(&true_labels[wire_index]),
        false_label_hash: label_hash(&false_labels[wire_index]),
    });
    let labels = (0..INPUT_WIRE_NUM)
        .map(|wire_index| {
            let bit = (message[wire_index / 8] >> (wire_index % 8)) & 1;
            if bit == 1 {
                true_labels[wire_index].clone()
            } else {
                false_labels[wire_index].clone()
            }
        })
        .collect();
    let final_msg = b"bitvm-gc-regtest-final-message".to_vec();
    (
        BitvmGcCircuitData {
            verifier_pubkey,
            final_msg_hashlocks: vec![label_hash(&final_msg)],
            wire_hashes,
        },
        labels,
        final_msg,
    )
}

fn node_script(pubkey: &PublicKey) -> ScriptBuf {
    script! {
        { *pubkey }
        OP_CHECKSIG
    }
    .compile()
}

fn node_address(network: Network, keypair: &Keypair) -> Address {
    Address::p2wsh(&node_script(&PublicKey::from(keypair.public_key())), network)
}

fn node_sign(tx: &mut Transaction, input_index: usize, input_value: Amount, keypair: &Keypair) {
    let pubkey = PublicKey::from(keypair.public_key());
    populate_p2wsh_witness(
        tx,
        input_index,
        EcdsaSighashType::All,
        &node_script(&pubkey),
        input_value,
        &vec![keypair],
    );
}

fn esplora_client() -> Result<EsploraClient> {
    let url =
        std::env::var("BITVM_E2E_ESPLORA_URL").unwrap_or_else(|_| REGTEST_ESPLORA_URL.to_string());
    let client = reqwest_0_11::Client::builder()
        .no_proxy()
        .build()
        .context("build regtest Esplora HTTP client")?;
    Ok(EsploraClient::from_client(url, client))
}

async fn wait_esplora_height(esplora: &EsploraClient, expected: u32) -> Result<()> {
    let started = Instant::now();
    loop {
        if esplora.get_height().await.is_ok_and(|height| height >= expected) {
            return Ok(());
        }
        if started.elapsed() >= CONFIRM_TIMEOUT {
            bail!("Esplora did not reach block height {expected} within {CONFIRM_TIMEOUT:?}");
        }
        sleep(Duration::from_millis(500)).await;
    }
}

async fn wait_tx_confirm(
    esplora: &EsploraClient,
    rpc: &RegtestRpc,
    mining_address: &Address,
    txid: Txid,
) -> Result<u32> {
    rpc.mine_blocks(1, mining_address).await?;
    let started = Instant::now();
    loop {
        if let Ok(status) = esplora.get_tx_status(&txid).await
            && let Some(height) = status.block_height
        {
            return Ok(height);
        }
        if started.elapsed() >= CONFIRM_TIMEOUT {
            bail!("transaction {txid} was not confirmed within {CONFIRM_TIMEOUT:?}");
        }
        sleep(Duration::from_millis(500)).await;
    }
}

async fn broadcast_and_confirm(
    esplora: &EsploraClient,
    rpc: &RegtestRpc,
    mining_address: &Address,
    label: &str,
    tx: &Transaction,
) -> Result<u32> {
    let txid = tx.compute_txid();
    println!("broadcasting {label}: {txid}");
    esplora.broadcast(tx).await.with_context(|| format!("broadcast {label} {txid}"))?;
    let height = wait_tx_confirm(esplora, rpc, mining_address, txid).await?;
    println!("{label} confirmed at height {height}: {txid}");
    Ok(height)
}

async fn fund_address(
    esplora: &EsploraClient,
    rpc: &RegtestRpc,
    mining_address: &Address,
    address: &Address,
    amount: Amount,
) -> Result<OutPoint> {
    let txid = rpc.send_to_address(address, amount).await?;
    wait_tx_confirm(esplora, rpc, mining_address, txid).await?;
    let tx = esplora
        .get_tx(&txid)
        .await?
        .with_context(|| format!("funding transaction {txid} is missing from Esplora"))?;
    let vout = tx
        .output
        .iter()
        .position(|output| output.script_pubkey == address.script_pubkey())
        .with_context(|| format!("funding transaction {txid} does not pay {address}"))?;
    Ok(OutPoint { txid, vout: vout.try_into()? })
}

async fn wait_timelock(
    esplora: &EsploraClient,
    rpc: &RegtestRpc,
    mining_address: &Address,
    start_height: u32,
    blocks: u32,
) -> Result<()> {
    let expected = start_height.saturating_add(blocks).saturating_add(1);
    let current = esplora.get_height().await?;
    rpc.mine_blocks(expected.saturating_sub(current), mining_address).await?;
    wait_esplora_height(esplora, expected).await
}

async fn add_payer_input(
    esplora: &EsploraClient,
    rpc: &RegtestRpc,
    mining_address: &Address,
    payer: &Keypair,
    mut tx: Transaction,
    committed_input_amount: Amount,
) -> Result<Transaction> {
    let payer_amount = Amount::from_sat(PAYER_AMOUNT_SATS);
    let payer_address = node_address(Network::Regtest, payer);
    let payer_outpoint =
        fund_address(esplora, rpc, mining_address, &payer_address, payer_amount).await?;
    tx.input.push(TxIn {
        previous_output: payer_outpoint,
        script_sig: ScriptBuf::new(),
        sequence: Sequence::MAX,
        witness: bitcoin::Witness::new(),
    });

    let output_amount: Amount = tx.output.iter().map(|output| output.value).sum();
    let total_input_amount = committed_input_amount + payer_amount;
    ensure!(
        total_input_amount >= output_amount + Amount::from_sat(DUST_AMOUNT),
        "payer input cannot cover transaction outputs and change"
    );
    tx.output.push(TxOut {
        value: total_input_amount - output_amount,
        script_pubkey: payer_address.script_pubkey(),
    });
    let payer_index = tx.input.len() - 1;
    node_sign(&mut tx, payer_index, payer_amount, payer);

    let fee =
        Amount::from_sat((tx.vsize() as u64 * FEE_RATE_SAT_PER_VBYTE).max(DEFAULT_FEE_SATS * 2));
    ensure!(
        total_input_amount >= output_amount + fee + Amount::from_sat(DUST_AMOUNT),
        "payer input cannot cover transaction outputs, fee, and change"
    );
    tx.output.last_mut().expect("change output was added").value =
        total_input_amount - output_amount - fee;
    tx.input[payer_index].witness.clear();
    node_sign(&mut tx, payer_index, payer_amount, payer);
    Ok(tx)
}

fn committee_pre_sign_graph(graph: &mut BitvmGcGraph, keys: &TestKeys) -> Result<()> {
    let watchtower_num = graph.parameters.watchtower_pubkeys.len();
    let verifier_num = graph.parameters.gc_data.len();
    let mut pub_nonces = Vec::with_capacity(keys.committee.len());
    let mut sec_nonces = Vec::with_capacity(keys.committee.len());

    for (index, keypair) in keys.committee.iter().enumerate() {
        let (member_pub_nonces, member_sec_nonces, nonce_signatures) = generate_nonce_from_seed(
            format!("bitvm-gc-regtest-committee-{index}"),
            graph.parameters.graph_nonce as usize,
            *keypair,
            watchtower_num,
            verifier_num,
        );
        ensure!(
            verify_nonce_signatures(
                &XOnlyPublicKey::from(PublicKey::from(keypair.public_key())),
                &member_pub_nonces,
                &nonce_signatures,
                watchtower_num,
                verifier_num,
            )?,
            "committee member {index} generated invalid nonce signatures"
        );
        pub_nonces.push(member_pub_nonces);
        sec_nonces.push(member_sec_nonces);
    }

    let agg_nonces = nonces_aggregation(&pub_nonces)?;
    let partial_signatures = keys
        .committee
        .iter()
        .zip(sec_nonces)
        .map(|(keypair, sec_nonce)| {
            committee_pre_sign(*keypair, sec_nonce, agg_nonces.clone(), graph)
        })
        .collect::<Result<Vec<_>>>()?;
    let signatures = signature_aggregation(&partial_signatures, &agg_nonces, graph)?;
    push_committee_pre_signatures(graph, &signatures)?;
    verify_graph_committee_pre_signatures(graph)
}

fn committee_sign_pegin(graph: &BitvmGcGraph, keys: &TestKeys) -> Result<Transaction> {
    let mut pub_nonces = Vec::with_capacity(keys.committee.len());
    let mut sec_nonces = Vec::with_capacity(keys.committee.len());
    for keypair in &keys.committee {
        let (sec_nonce, pub_nonce, _) = CommitteeMasterKey::new(*keypair)
            .nonce_for_instance_job_with_keypair(&graph.parameters.instance_parameters, *keypair)?;
        pub_nonces.push(pub_nonce);
        sec_nonces.push(sec_nonce);
    }
    let agg_nonce = nonce_aggregation(&pub_nonces);
    let partial_signatures = keys
        .committee
        .iter()
        .zip(sec_nonces)
        .map(|(keypair, sec_nonce)| {
            sign_pegin_confirm(graph, *keypair, sec_nonce, agg_nonce.clone())
        })
        .collect::<Result<Vec<_>>>()?;
    agg_and_push_pegin_confirm_sigs(graph, partial_signatures, &agg_nonce)
}

async fn build_regtest_graph_with_watchtowers(
    esplora: &EsploraClient,
    rpc: &RegtestRpc,
    watchtower_count: usize,
) -> Result<RegtestGraph> {
    rpc.prepare_wallet().await?;
    let fixture = fixture()?;
    let keys = test_keys()?;
    ensure!(
        (1..=keys.watchtowers.len()).contains(&watchtower_count),
        "watchtower count must be between 1 and {}",
        keys.watchtowers.len()
    );
    let network = Network::Regtest;
    let mining_address = node_address(network, &keys.challenger);
    let instance_id = Uuid::new_v4();
    let graph_id = Uuid::new_v4();
    let operator_master_key = OperatorMasterKey::new(keys.operator);
    let operator_pubkey = PublicKey::from(keys.operator.public_key());
    let operator_xonly = XOnlyPublicKey::from(operator_pubkey);
    let committee_pubkeys =
        keys.committee.iter().map(|key| PublicKey::from(key.public_key())).collect::<Vec<_>>();
    let committee_agg_pubkey = key_aggregation(&committee_pubkeys);
    let fee = Amount::from_sat(DEFAULT_FEE_SATS);
    let pegin_amount = Amount::from_sat(PEGIN_AMOUNT_SATS);
    let deposit_input_amount = pegin_amount + fee * 2;
    let user_address = node_address(network, &keys.user);
    let deposit_outpoint =
        fund_address(esplora, rpc, &mining_address, &user_address, deposit_input_amount).await?;

    let instance_parameters = BitvmGcInstanceParameters {
        network,
        instance_id,
        user_info: UserInfo {
            depositor_evm_address: [0x11; 20],
            txn_fees: [fee.to_sat(); 3],
            inputs: vec![Input { outpoint: deposit_outpoint, amount: deposit_input_amount }],
            user_xonly_pubkey: keys.user.x_only_public_key().0,
            user_change_address: user_address.clone(),
            user_refund_address: user_address,
        },
        pegin_amount,
        committee_pubkeys,
        committee_agg_pubkey,
    };

    let mut pegin_deposit = instance_parameters.build_pegin_tx()?.0;
    node_sign(pegin_deposit.tx_mut(), 0, deposit_input_amount, &keys.user);
    broadcast_and_confirm(esplora, rpc, &mining_address, "pegin-deposit", pegin_deposit.tx())
        .await?;

    let prekickoff_connector = PrekickoffConnector::new(network, &operator_xonly);
    let force_skip_connector = ForceSkipConnector::new(network, &operator_xonly);
    let kickoff_connector = KickoffConnector::new(network, &operator_xonly);
    let prekickoff_amount = Amount::from_sat(PREKICKOFF_AMOUNT_SATS);
    let prekickoff_outpoint = fund_address(
        esplora,
        rpc,
        &mining_address,
        &prekickoff_connector.generate_taproot_address(),
        prekickoff_amount,
    )
    .await?;
    let cur_prekickoff = PrekickoffTransaction::new_for_validation(
        &prekickoff_connector,
        &force_skip_connector,
        &kickoff_connector,
        &prekickoff_connector,
        Input { outpoint: prekickoff_outpoint, amount: prekickoff_amount },
        vec![],
        vec![],
        fee.to_sat(),
        watchtower_count,
        1,
    )
    .map_err(|error| anyhow!("build current pre-kickoff: {error}"))?;

    let (_, operator_assert_wots_pubkey) =
        operator_master_key.assert_wots_keypair_for_graph(graph_id);
    let (_, operator_commit_pubin_wots_pubkey) =
        operator_master_key.commit_pubin_wots_keypair_for_graph(graph_id);
    let proof = mock_proof(fixture)?;
    let (assert_secret_key, _) = operator_master_key.assert_wots_keypair_for_graph(graph_id);
    let assert_witness = build_assert_witness(&proof, &assert_secret_key, Fr::from(42_u64))?;
    let recovered = recover_operator_proof_from_assert_witness(&assert_witness)?;
    ensure!(recovered == proof, "mock proof did not round-trip through the assert witness");
    let assert_message = assert_wots_message(&assert_witness)?;
    let (gc_data, challenge_labels, final_msg) =
        synthetic_challenge_data(PublicKey::from(keys.verifier.public_key()), &assert_message);
    let watchtower_pubkeys = keys
        .watchtowers
        .iter()
        .take(watchtower_count)
        .map(|key| key.x_only_public_key().0)
        .collect();
    let watchtower_ack_hashlocks = (0..watchtower_count)
        .map(|index| {
            hash160::Hash::hash(&operator_master_key.preimage_for_graph(graph_id, index))
                .to_byte_array()
        })
        .collect();
    let parameters = BitvmGcGraphParameters {
        instance_parameters,
        prekickoff_parameters: PrekickoffParameters {
            cur_prekickoff_txn: cur_prekickoff,
            replenish_fee_inputs: vec![],
            replenish_fee_prev_outs: vec![],
            fee_amount: fee.to_sat(),
        },
        timelock_config: default_timelock_config(network),
        graph_id,
        graph_nonce: 0,
        challenge_amount: Amount::from_sat(20_000),
        operator_pubkey,
        operator_assert_wots_pubkey,
        operator_commit_pubin_wots_pubkey,
        operator_receive_address: node_address(network, &keys.operator),
        watchtower_pubkeys,
        watchtower_ack_hashlocks,
        pubin_disprove_constant: [0x81; 32],
        gc_data: vec![gc_data],
    };
    let mut graph = generate_bitvm_graph(parameters)?;

    let prekickoff = operator_sign_prekickoff_input_0(keys.operator, &mut graph)?;
    broadcast_and_confirm(esplora, rpc, &mining_address, "pre-kickoff", &prekickoff).await?;

    operator_pre_sign(keys.operator, &mut graph)?;
    verify_graph_operator_pre_signatures(&graph)?;
    committee_pre_sign_graph(&mut graph, &keys)?;

    let pegin_confirm = committee_sign_pegin(&graph, &keys)?;
    broadcast_and_confirm(esplora, rpc, &mining_address, "pegin-confirm", &pegin_confirm).await?;

    Ok(RegtestGraph { graph, keys, assert_witness, challenge_labels, final_msg })
}

async fn build_regtest_graph(esplora: &EsploraClient, rpc: &RegtestRpc) -> Result<RegtestGraph> {
    build_regtest_graph_with_watchtowers(esplora, rpc, 1).await
}

async fn enter_watchtower_phase(
    esplora: &EsploraClient,
    rpc: &RegtestRpc,
    mining_address: &Address,
    graph: &mut BitvmGcGraph,
    keys: &TestKeys,
) -> Result<u32> {
    let kickoff = operator_sign_kickoff(keys.operator, graph)?;
    broadcast_and_confirm(esplora, rpc, mining_address, "kickoff", &kickoff).await?;

    let (challenge, _) = export_challenge_tx(graph)?;
    let challenge = add_payer_input(
        esplora,
        rpc,
        mining_address,
        &keys.challenger,
        challenge,
        graph.challenge.prev_outs()[0].value,
    )
    .await?;
    broadcast_and_confirm(esplora, rpc, mining_address, "challenge", &challenge).await?;

    let watchtower_challenge_init = operator_sign_watchtower_challenge_init(keys.operator, graph)?;
    broadcast_and_confirm(
        esplora,
        rpc,
        mining_address,
        "watchtower-challenge-init",
        &watchtower_challenge_init,
    )
    .await
}

async fn build_watchtower_challenge(
    esplora: &EsploraClient,
    rpc: &RegtestRpc,
    mining_address: &Address,
    graph: &BitvmGcGraph,
    keys: &TestKeys,
    watchtower_index: usize,
) -> Result<Transaction> {
    let watchtower = keys
        .watchtowers
        .get(watchtower_index)
        .with_context(|| format!("missing watchtower key {watchtower_index}"))?;
    let payer_amount = Amount::from_sat(PAYER_AMOUNT_SATS);
    let payer_address = node_address(Network::Regtest, watchtower);
    let payer_outpoint =
        fund_address(esplora, rpc, mining_address, &payer_address, payer_amount).await?;
    let commitment = format!("watchtower-{watchtower_index}-challenge").into_bytes();
    let fee = Amount::from_sat(
        (estimate_watchtower_challenge_vbytes(commitment.len()) as u64 * FEE_RATE_SAT_PER_VBYTE)
            .max(DEFAULT_FEE_SATS),
    );
    let mut tx = build_watchtower_challenge_tx(
        graph,
        watchtower,
        watchtower_index,
        &commitment,
        vec![Input { outpoint: payer_outpoint, amount: payer_amount }],
        &payer_address,
        fee,
    )?;
    node_sign(&mut tx, 1, payer_amount, watchtower);
    Ok(tx)
}

async fn build_operator_ack(
    esplora: &EsploraClient,
    rpc: &RegtestRpc,
    mining_address: &Address,
    graph: &BitvmGcGraph,
    keys: &TestKeys,
    watchtower_index: usize,
) -> Result<Transaction> {
    let preimage = OperatorMasterKey::new(keys.operator)
        .preimage_for_graph(graph.parameters.graph_id, watchtower_index);
    let input = operator_sign_challenge_ack(graph, watchtower_index, &preimage)?;
    let input_amount = graph
        .watchtower_challenge_init
        .ack_connector_input(watchtower_index)
        .map_err(|error| anyhow!("get ACK connector input {watchtower_index}: {error}"))?
        .amount;
    add_payer_input(
        esplora,
        rpc,
        mining_address,
        &keys.operator,
        Transaction {
            version: transaction::Version(2),
            lock_time: absolute::LockTime::ZERO,
            input: vec![input],
            output: vec![p2a_output()],
        },
        input_amount,
    )
    .await
}

async fn build_operator_commit_pubin(
    esplora: &EsploraClient,
    rpc: &RegtestRpc,
    mining_address: &Address,
    graph: &BitvmGcGraph,
    keys: &TestKeys,
    pubin: &[u8; 96],
) -> Result<Transaction> {
    let operator_master_key = OperatorMasterKey::new(keys.operator);
    let (commit_pubin_secret_key, _) =
        operator_master_key.commit_pubin_wots_keypair_for_graph(graph.parameters.graph_id);
    let input = operator_sign_commit_pubin(graph, &commit_pubin_secret_key, pubin)?;
    let input_amount = graph
        .watchtower_challenge_init
        .connector_e_input()
        .map_err(|error| anyhow!("get connector-e input: {error}"))?
        .amount;
    add_payer_input(
        esplora,
        rpc,
        mining_address,
        &keys.operator,
        Transaction {
            version: transaction::Version(2),
            lock_time: absolute::LockTime::ZERO,
            input: vec![input],
            output: vec![TxOut {
                value: Amount::ZERO,
                script_pubkey: generate_opreturn_script(vec![]),
            }],
        },
        input_amount,
    )
    .await
}

fn build_operator_assert(
    graph: &mut BitvmGcGraph,
    keys: &TestKeys,
    assert_witness: &TxAssertWitness,
) -> Result<Transaction> {
    let operator_master_key = OperatorMasterKey::new(keys.operator);
    let (assert_secret_key, _) =
        operator_master_key.assert_wots_keypair_for_graph(graph.parameters.graph_id);
    let proof_message = assert_wots_message(assert_witness)?;
    operator_sign_assert(
        graph,
        &assert_secret_key,
        &proof_message,
        &assert_witness.pi2,
        &assert_witness.pi3,
    )
}

fn build_verifier_assert(
    graph: &BitvmGcGraph,
    operator_assert_input: TxIn,
    labels: Vec<Label>,
) -> Result<Transaction> {
    let labels: [Label; INPUT_WIRE_NUM] = labels.try_into().map_err(|labels: Vec<Label>| {
        anyhow!("challenge label count is {}; expected {INPUT_WIRE_NUM}", labels.len())
    })?;
    build_verifier_assert_tx(graph, operator_assert_input, 0, labels)
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires local regtest Bitcoin Core and Esplora"]
async fn regtest_take1_flow() -> Result<()> {
    let esplora = esplora_client()?;
    let rpc = RegtestRpc::from_env()?;
    let RegtestGraph { mut graph, keys, .. } = build_regtest_graph(&esplora, &rpc).await?;
    let mining_address = node_address(Network::Regtest, &keys.challenger);

    let kickoff = operator_sign_kickoff(keys.operator, &mut graph)?;
    let kickoff_height =
        broadcast_and_confirm(&esplora, &rpc, &mining_address, "kickoff", &kickoff).await?;
    wait_timelock(
        &esplora,
        &rpc,
        &mining_address,
        kickoff_height,
        take1_timelock_blocks(Network::Regtest, &graph.parameters.timelock_config),
    )
    .await?;

    let take1 = operator_sign_take1(keys.operator, &mut graph)?;
    broadcast_and_confirm(&esplora, &rpc, &mining_address, "take1", &take1).await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires local regtest Bitcoin Core and Esplora"]
async fn regtest_take2_flow() -> Result<()> {
    let esplora = esplora_client()?;
    let rpc = RegtestRpc::from_env()?;
    let RegtestGraph { mut graph, keys, assert_witness, .. } =
        build_regtest_graph(&esplora, &rpc).await?;
    let mining_address = node_address(Network::Regtest, &keys.challenger);

    let kickoff = operator_sign_kickoff(keys.operator, &mut graph)?;
    broadcast_and_confirm(&esplora, &rpc, &mining_address, "kickoff", &kickoff).await?;

    let (challenge, _) = export_challenge_tx(&graph)?;
    let challenge_input_amount = graph.challenge.prev_outs()[0].value;
    let challenge = add_payer_input(
        &esplora,
        &rpc,
        &mining_address,
        &keys.challenger,
        challenge,
        challenge_input_amount,
    )
    .await?;
    broadcast_and_confirm(&esplora, &rpc, &mining_address, "challenge", &challenge).await?;

    let watchtower_challenge_init =
        operator_sign_watchtower_challenge_init(keys.operator, &mut graph)?;
    let watchtower_height = broadcast_and_confirm(
        &esplora,
        &rpc,
        &mining_address,
        "watchtower-challenge-init",
        &watchtower_challenge_init,
    )
    .await?;

    let operator_master_key = OperatorMasterKey::new(keys.operator);
    let (commit_pubin_secret_key, _) =
        operator_master_key.commit_pubin_wots_keypair_for_graph(graph.parameters.graph_id);
    let pubin_commitment = assert_wots_message(&assert_witness)?;
    let commit_pubin_input =
        operator_sign_commit_pubin(&graph, &commit_pubin_secret_key, &pubin_commitment)?;
    let commit_pubin_amount = graph
        .watchtower_challenge_init
        .connector_e_input()
        .map_err(|error| anyhow!("get connector-e input: {error}"))?
        .amount;
    let commit_pubin = add_payer_input(
        &esplora,
        &rpc,
        &mining_address,
        &keys.operator,
        Transaction {
            version: transaction::Version(2),
            lock_time: absolute::LockTime::ZERO,
            input: vec![commit_pubin_input],
            output: vec![TxOut {
                value: Amount::ZERO,
                script_pubkey: generate_opreturn_script(vec![]),
            }],
        },
        commit_pubin_amount,
    )
    .await?;
    broadcast_and_confirm(&esplora, &rpc, &mining_address, "operator-commit-pubin", &commit_pubin)
        .await?;

    let (assert_secret_key, _) =
        operator_master_key.assert_wots_keypair_for_graph(graph.parameters.graph_id);
    let proof_message = assert_wots_message(&assert_witness)?;
    let operator_assert = operator_sign_assert(
        &mut graph,
        &assert_secret_key,
        &proof_message,
        &assert_witness.pi2,
        &assert_witness.pi3,
    )?;
    let assert_height =
        broadcast_and_confirm(&esplora, &rpc, &mining_address, "operator-assert", &operator_assert)
            .await?;

    wait_timelock(
        &esplora,
        &rpc,
        &mining_address,
        assert_height,
        take2_timelock_blocks(Network::Regtest, &graph.parameters.timelock_config),
    )
    .await?;
    wait_timelock(
        &esplora,
        &rpc,
        &mining_address,
        watchtower_height,
        connector_f_timelock_blocks(Network::Regtest, &graph.parameters.timelock_config),
    )
    .await?;

    let take2 = operator_sign_take2(keys.operator, &mut graph)?;
    broadcast_and_confirm(&esplora, &rpc, &mining_address, "take2", &take2).await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires local regtest Bitcoin Core and Esplora"]
async fn regtest_watchtower_ack_and_timeout_flow() -> Result<()> {
    let esplora = esplora_client()?;
    let rpc = RegtestRpc::from_env()?;
    let RegtestGraph { mut graph, keys, .. } =
        build_regtest_graph_with_watchtowers(&esplora, &rpc, 2).await?;
    let mining_address = node_address(Network::Regtest, &keys.challenger);
    let watchtower_init_height =
        enter_watchtower_phase(&esplora, &rpc, &mining_address, &mut graph, &keys).await?;

    let challenge =
        build_watchtower_challenge(&esplora, &rpc, &mining_address, &graph, &keys, 0).await?;
    broadcast_and_confirm(&esplora, &rpc, &mining_address, "watchtower-0-challenge", &challenge)
        .await?;
    let ack = build_operator_ack(&esplora, &rpc, &mining_address, &graph, &keys, 0).await?;
    broadcast_and_confirm(&esplora, &rpc, &mining_address, "operator-ack-0", &ack).await?;

    wait_timelock(
        &esplora,
        &rpc,
        &mining_address,
        watchtower_init_height,
        watchtower_challenge_timelock_blocks(Network::Regtest, &graph.parameters.timelock_config),
    )
    .await?;
    let timeout = operator_sign_watchtower_challenge_timeout(keys.operator, &mut graph, 1)?;
    broadcast_and_confirm(
        &esplora,
        &rpc,
        &mining_address,
        "watchtower-1-challenge-timeout",
        &timeout,
    )
    .await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires local regtest Bitcoin Core and Esplora"]
async fn regtest_operator_challenge_nack_flow() -> Result<()> {
    let esplora = esplora_client()?;
    let rpc = RegtestRpc::from_env()?;
    let RegtestGraph { mut graph, keys, .. } = build_regtest_graph(&esplora, &rpc).await?;
    let mining_address = node_address(Network::Regtest, &keys.challenger);
    let watchtower_init_height =
        enter_watchtower_phase(&esplora, &rpc, &mining_address, &mut graph, &keys).await?;

    let challenge =
        build_watchtower_challenge(&esplora, &rpc, &mining_address, &graph, &keys, 0).await?;
    broadcast_and_confirm(&esplora, &rpc, &mining_address, "watchtower-challenge", &challenge)
        .await?;
    wait_timelock(
        &esplora,
        &rpc,
        &mining_address,
        watchtower_init_height,
        operator_ack_timelock_blocks(Network::Regtest, &graph.parameters.timelock_config),
    )
    .await?;
    let nack = graph.operator_challenge_nacks[0].tx().clone();
    broadcast_and_confirm(&esplora, &rpc, &mining_address, "operator-challenge-nack", &nack)
        .await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires local regtest Bitcoin Core and Esplora"]
async fn regtest_operator_commit_timeout_flow() -> Result<()> {
    let esplora = esplora_client()?;
    let rpc = RegtestRpc::from_env()?;
    let RegtestGraph { mut graph, keys, .. } = build_regtest_graph(&esplora, &rpc).await?;
    let mining_address = node_address(Network::Regtest, &keys.challenger);
    let watchtower_init_height =
        enter_watchtower_phase(&esplora, &rpc, &mining_address, &mut graph, &keys).await?;

    wait_timelock(
        &esplora,
        &rpc,
        &mining_address,
        watchtower_init_height,
        operator_commit_timelock_blocks(Network::Regtest, &graph.parameters.timelock_config),
    )
    .await?;
    let timeout = graph.operator_commit_timeout.tx().clone();
    broadcast_and_confirm(&esplora, &rpc, &mining_address, "operator-commit-timeout", &timeout)
        .await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires local regtest Bitcoin Core and Esplora"]
async fn regtest_pubin_disprove_flow() -> Result<()> {
    let esplora = esplora_client()?;
    let rpc = RegtestRpc::from_env()?;
    let RegtestGraph { mut graph, keys, assert_witness, .. } =
        build_regtest_graph(&esplora, &rpc).await?;
    let mining_address = node_address(Network::Regtest, &keys.challenger);
    enter_watchtower_phase(&esplora, &rpc, &mining_address, &mut graph, &keys).await?;

    let mut inconsistent_pubin = [0_u8; 96];
    inconsistent_pubin[..32].fill(0x55);
    inconsistent_pubin[32..64].copy_from_slice(&graph.parameters.pubin_disprove_constant);
    let commit = build_operator_commit_pubin(
        &esplora,
        &rpc,
        &mining_address,
        &graph,
        &keys,
        &inconsistent_pubin,
    )
    .await?;
    broadcast_and_confirm(&esplora, &rpc, &mining_address, "operator-commit-pubin", &commit)
        .await?;

    let operator_assert = build_operator_assert(&mut graph, &keys, &assert_witness)?;
    broadcast_and_confirm(&esplora, &rpc, &mining_address, "operator-assert", &operator_assert)
        .await?;
    let (witness, _) =
        validate_pubin_disprove(&graph, &commit.input[0], &operator_assert.input[0], &[])?
            .context("inconsistent pubin was not disprovable")?;
    let input = build_pubin_disprove_txin(&graph, witness)?;
    let input_amount = graph
        .operator_assert
        .connector_d_input()
        .map_err(|error| anyhow!("get connector-d input: {error}"))?
        .amount;
    let pubin_disprove = add_payer_input(
        &esplora,
        &rpc,
        &mining_address,
        &keys.verifier,
        Transaction {
            version: transaction::Version(2),
            lock_time: absolute::LockTime::ZERO,
            input: vec![input],
            output: vec![p2a_output()],
        },
        input_amount,
    )
    .await?;
    broadcast_and_confirm(&esplora, &rpc, &mining_address, "pubin-disprove", &pubin_disprove)
        .await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires local regtest Bitcoin Core and Esplora"]
async fn regtest_verifier_disprove_flow() -> Result<()> {
    let esplora = esplora_client()?;
    let rpc = RegtestRpc::from_env()?;
    let RegtestGraph { mut graph, keys, assert_witness, challenge_labels, .. } =
        build_regtest_graph(&esplora, &rpc).await?;
    let mining_address = node_address(Network::Regtest, &keys.challenger);
    enter_watchtower_phase(&esplora, &rpc, &mining_address, &mut graph, &keys).await?;

    let pubin = assert_wots_message(&assert_witness)?;
    let commit =
        build_operator_commit_pubin(&esplora, &rpc, &mining_address, &graph, &keys, &pubin).await?;
    broadcast_and_confirm(&esplora, &rpc, &mining_address, "operator-commit-pubin", &commit)
        .await?;
    let operator_assert = build_operator_assert(&mut graph, &keys, &assert_witness)?;
    broadcast_and_confirm(&esplora, &rpc, &mining_address, "operator-assert", &operator_assert)
        .await?;

    let verifier_assert =
        build_verifier_assert(&graph, operator_assert.input[0].clone(), challenge_labels)?;
    let verifier_assert_height =
        broadcast_and_confirm(&esplora, &rpc, &mining_address, "verifier-assert", &verifier_assert)
            .await?;
    wait_timelock(
        &esplora,
        &rpc,
        &mining_address,
        verifier_assert_height,
        disprove_timelock_blocks(Network::Regtest, &graph.parameters.timelock_config),
    )
    .await?;
    let disprove = build_disprove_tx(&graph, 0, None)?;
    broadcast_and_confirm(&esplora, &rpc, &mining_address, "disprove", &disprove).await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires local regtest Bitcoin Core and Esplora"]
async fn regtest_wrongly_challenged_flow() -> Result<()> {
    let esplora = esplora_client()?;
    let rpc = RegtestRpc::from_env()?;
    let RegtestGraph { mut graph, keys, assert_witness, challenge_labels, final_msg } =
        build_regtest_graph(&esplora, &rpc).await?;
    let mining_address = node_address(Network::Regtest, &keys.challenger);
    enter_watchtower_phase(&esplora, &rpc, &mining_address, &mut graph, &keys).await?;

    let pubin = assert_wots_message(&assert_witness)?;
    let commit =
        build_operator_commit_pubin(&esplora, &rpc, &mining_address, &graph, &keys, &pubin).await?;
    broadcast_and_confirm(&esplora, &rpc, &mining_address, "operator-commit-pubin", &commit)
        .await?;
    let operator_assert = build_operator_assert(&mut graph, &keys, &assert_witness)?;
    broadcast_and_confirm(&esplora, &rpc, &mining_address, "operator-assert", &operator_assert)
        .await?;
    let verifier_assert =
        build_verifier_assert(&graph, operator_assert.input[0].clone(), challenge_labels)?;
    broadcast_and_confirm(&esplora, &rpc, &mining_address, "verifier-assert", &verifier_assert)
        .await?;

    let (input, input_amount) = operator_sign_wrongly_challenged(&graph, 0, &final_msg)?;
    let wrongly_challenged = add_payer_input(
        &esplora,
        &rpc,
        &mining_address,
        &keys.operator,
        Transaction {
            version: transaction::Version(2),
            lock_time: absolute::LockTime::ZERO,
            input: vec![input],
            output: vec![p2a_output()],
        },
        input_amount,
    )
    .await?;
    broadcast_and_confirm(
        &esplora,
        &rpc,
        &mining_address,
        "wrongly-challenged",
        &wrongly_challenged,
    )
    .await?;
    Ok(())
}
