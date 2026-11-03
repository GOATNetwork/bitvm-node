//! What both chains say about a graph: its stage and challenge branches.

use anyhow::{Result, anyhow, bail};
use bitcoin::{OutPoint, Script, Transaction, Txid};
use bitvm_lib::types::BitvmGcGraph;
use client::{btc_chain::BTCClient, goat_chain::GOATClient};
use goat::connectors::base::TaprootConnector;
use goat::connectors::connector_d::{
    CONNECTOR_D_N_OF_N_LEAF_INDEX, CONNECTOR_D_PUBIN_DISPROVE_LEAF_INDEX,
};
use goat::transactions::base::output_topology;
use goat::transactions::pre_signed::PreSignedTransaction;
use store::localdb::{GraphRuntimeUpdate, LocalDB};

use crate::aggregates::graph_scan::{ChallengeSubStatus, VerifierChallengeStatus};
use client::goat_chain::DisproveTxType;
use store::{GraphStatus, GraphStatusTransitionOutcome};
use tracing::warn;
use uuid::Uuid;

use super::btc::{outpoint_spent_confirmed, outpoint_spent_txid, tx_confirmed, tx_visible};
use super::graph_store::update_graph_status;

/// Re-derive the graph's stage from both chains and record it
/// (ChainReconcile); a stale stage is ignored with a warning.
pub(crate) async fn refresh_graph(
    local_db: &LocalDB,
    btc_client: &BTCClient,
    goat_client: &GOATClient,
    instance_id: Uuid,
    graph_id: Uuid,
    graph: &BitvmGcGraph,
) -> Result<()> {
    if graph.parameters.instance_parameters.instance_id != instance_id
        || graph.parameters.graph_id != graph_id
    {
        bail!(
            "refuse to refresh graph {instance_id}:{graph_id} with mismatched graph parameters {}:{}",
            graph.parameters.instance_parameters.instance_id,
            graph.parameters.graph_id
        );
    }

    let scan = scan_graph_chain_state(btc_client, goat_client, graph).await?;
    let outcome = update_graph_status(
        local_db,
        instance_id,
        graph_id,
        scan.status,
        Some(scan.sub_status.clone()),
    )
    .await?;
    match outcome {
        GraphStatusTransitionOutcome::Applied | GraphStatusTransitionOutcome::AlreadyCurrent => {
            if let Some(challenge_txid) = scan.challenge_txid {
                update_graph_challenge_txid_if_needed(local_db, graph_id, challenge_txid).await?;
            }
        }
        GraphStatusTransitionOutcome::Rejected { current } => warn!(
            "ignore stale chain scan for graph {instance_id}:{graph_id}: candidate={}, current={current}",
            scan.status
        ),
        GraphStatusTransitionOutcome::NotFound => {
            warn!("graph {instance_id}:{graph_id} disappeared while applying chain scan")
        }
    }
    Ok(())
}

#[derive(Clone, Debug)]
pub(crate) struct DetectedDisprove {
    pub(crate) disprove_type: DisproveTxType,
    pub(crate) index: usize,
    pub(crate) challenge_finish_txid: Txid,
}

/// What both chains say about a graph's transactions: the stage it reached
/// and, in a challenge, how far each branch got.
#[derive(Clone, Debug)]
pub(crate) struct GraphChainScan {
    pub(crate) status: GraphStatus,
    pub(crate) sub_status: ChallengeSubStatus,
    pub(crate) challenge_txid: Option<Txid>,
    pub(crate) disprove: Option<DetectedDisprove>,
}

#[cfg(test)]
impl GraphChainScan {
    pub(crate) fn for_test(status: GraphStatus) -> Self {
        Self {
            status,
            sub_status: ChallengeSubStatus::default(),
            challenge_txid: None,
            disprove: None,
        }
    }
}

fn initial_challenge_sub_status(watchtower_num: usize, verifier_num: usize) -> ChallengeSubStatus {
    let mut sub_status = ChallengeSubStatus::default();
    sub_status.watchtower_challenge_status.resize(watchtower_num, false);
    sub_status.verifier_challenge_status.resize(verifier_num, VerifierChallengeStatus::None);
    sub_status
}

fn connector_a_outpoint(graph: &BitvmGcGraph) -> Result<OutPoint> {
    graph
        .kickoff
        .connector_a_input()
        .map(|input| input.outpoint)
        .map_err(|e| anyhow!("failed to get connector-a input: {e}"))
}

fn connector_d_outpoint(graph: &BitvmGcGraph) -> Result<OutPoint> {
    graph
        .operator_assert
        .connector_d_input()
        .map(|input| input.outpoint)
        .map_err(|e| anyhow!("failed to get connector-d input: {e}"))
}

async fn update_graph_challenge_txid_if_needed(
    local_db: &LocalDB,
    graph_id: Uuid,
    challenge_txid: Txid,
) -> Result<()> {
    let mut storage_processor = local_db.acquire().await?;
    let Some(graph) = storage_processor.find_graph(&graph_id).await? else {
        warn!("graph: {graph_id} not found, skip updating challenge txid");
        return Ok(());
    };
    if graph.challenge_txid.as_ref().map(|txid| txid.0) != Some(challenge_txid) {
        storage_processor
            .update_graph_runtime(
                &GraphRuntimeUpdate::new(graph.instance_id, graph_id)
                    .with_challenge_txid(challenge_txid.into()),
            )
            .await?;
    }
    Ok(())
}

/// Read the actual confirmed spender, including its broadcast-time outputs.
/// Missing or inconsistent backend data must not become a terminal graph fact.
async fn confirmed_connector_spend(
    client: &BTCClient,
    outpoint: OutPoint,
) -> Result<Option<Transaction>> {
    let Some(txid) = outpoint_spent_confirmed(client, &outpoint.txid, outpoint.vout as u64).await?
    else {
        return Ok(None);
    };
    let tx = client
        .get_tx(&txid)
        .await?
        .ok_or_else(|| anyhow!("confirmed connector spender {txid} is unavailable"))?;
    anyhow::ensure!(
        tx.compute_txid() == txid,
        "connector spender transaction hash mismatch: {txid}"
    );
    anyhow::ensure!(
        tx.input.iter().any(|input| input.previous_output == outpoint),
        "transaction {txid} does not spend connector {outpoint}"
    );
    Ok(Some(tx))
}

/// SIGHASH_NONE commits to version, locktime and the input structure, while
/// allowing the broadcaster to choose outputs. Witnesses are not template data.
fn matches_presigned_inputs(actual: &Transaction, template: &Transaction) -> bool {
    actual.version == template.version
        && actual.lock_time == template.lock_time
        && actual.input.len() == template.input.len()
        && actual.input.iter().zip(&template.input).all(|(a, b)| {
            a.previous_output == b.previous_output
                && a.sequence == b.sequence
                && a.script_sig == b.script_sig
        })
}

fn classify_connector_spend(
    tx: &Transaction,
    candidates: &[(DisproveTxType, usize, &Transaction)],
    takes: &[Txid],
    connector_d: Option<(OutPoint, &Script, &Script)>,
) -> Result<Option<DetectedDisprove>> {
    let txid = tx.compute_txid();
    if takes.contains(&txid) {
        return Ok(None);
    }
    let disprove_leaf_matches = if let Some((connector, pubin_script, disprove_script)) =
        connector_d
    {
        let leaf = tx
            .input
            .iter()
            .find(|input| input.previous_output == connector)
            .and_then(|input| input.witness.taproot_leaf_script());
        if leaf.is_some_and(|leaf| {
            leaf.version == bitcoin::taproot::LeafVersion::TapScript && leaf.script == pubin_script
        }) {
            return Ok(Some(DetectedDisprove {
                disprove_type: DisproveTxType::PubinDisprove,
                index: 0,
                challenge_finish_txid: txid,
            }));
        }
        leaf.is_some_and(|leaf| {
            leaf.version == bitcoin::taproot::LeafVersion::TapScript
                && leaf.script == disprove_script
        })
    } else {
        true
    };
    for (kind, index, template) in candidates {
        if disprove_leaf_matches && matches_presigned_inputs(tx, template) {
            return Ok(Some(DetectedDisprove {
                disprove_type: *kind,
                index: *index,
                challenge_finish_txid: txid,
            }));
        }
    }
    bail!("unrecognized confirmed connector spender {txid}")
}

async fn detect_guardian_disprove(
    btc_client: &BTCClient,
    graph: &BitvmGcGraph,
) -> Result<Option<DetectedDisprove>> {
    let guardian = graph
        .kickoff
        .guardian_connector_input()
        .map_err(|error| anyhow!("failed to get guardian connector input: {error}"))?
        .outpoint;
    let Some(tx) = confirmed_connector_spend(btc_client, guardian).await? else {
        return Ok(None);
    };
    classify_connector_spend(
        &tx,
        &[
            (DisproveTxType::QuickChallenge, 0, graph.quick_challenge.tx()),
            (
                DisproveTxType::ChallengeIncompleteKickoff,
                0,
                graph.challenge_incomplete_kickoff.tx(),
            ),
        ],
        &[graph.take1.tx().compute_txid(), graph.take2.tx().compute_txid()],
        None,
    )
}

async fn detect_connector_d_disprove(
    btc_client: &BTCClient,
    graph: &BitvmGcGraph,
) -> Result<Option<DetectedDisprove>> {
    let connector = connector_d_outpoint(graph)?;
    let Some(tx) = confirmed_connector_spend(btc_client, connector).await? else {
        return Ok(None);
    };
    let candidates: Vec<_> = graph
        .disproves
        .iter()
        .enumerate()
        .map(|(index, template)| (DisproveTxType::Disprove, index, template.tx()))
        .collect();
    let pubin_script =
        graph.connector_d().generate_taproot_leaf_script(CONNECTOR_D_PUBIN_DISPROVE_LEAF_INDEX);
    let disprove_script =
        graph.connector_d().generate_taproot_leaf_script(CONNECTOR_D_N_OF_N_LEAF_INDEX);
    classify_connector_spend(
        &tx,
        &candidates,
        &[graph.take2.tx().compute_txid()],
        Some((connector, &pubin_script, &disprove_script)),
    )
}

async fn detect_watchtower_flow_disprove(
    btc_client: &BTCClient,
    graph: &BitvmGcGraph,
) -> Result<Option<DetectedDisprove>> {
    for (index, nack) in graph.operator_challenge_nacks.iter().enumerate() {
        let txid = nack.tx().compute_txid();
        if tx_confirmed(btc_client, &txid).await? {
            return Ok(Some(DetectedDisprove {
                disprove_type: DisproveTxType::OperatorChallengeNack,
                index,
                challenge_finish_txid: txid,
            }));
        }
    }

    let txid = graph.operator_commit_timeout.tx().compute_txid();
    if tx_confirmed(btc_client, &txid).await? {
        return Ok(Some(DetectedDisprove {
            disprove_type: DisproveTxType::OperatorCommitTimeout,
            index: 0,
            challenge_finish_txid: txid,
        }));
    }

    Ok(None)
}

pub(crate) async fn scan_graph_chain_state(
    btc_client: &BTCClient,
    goat_client: &GOATClient,
    graph: &BitvmGcGraph,
) -> Result<GraphChainScan> {
    let graph_id = graph.parameters.graph_id;
    let watchtower_num = graph.parameters.watchtower_pubkeys.len();
    let verifier_num = graph.verifier_asserts.len();
    let mut sub_status = initial_challenge_sub_status(watchtower_num, verifier_num);
    // Derive the candidate from the graph and both chains, rather than using
    // the locally persisted status as the scan start. The stored status is a
    // projection and can be stale after a restart or missed listener event.
    let mut current_status = if graph.committee_pre_signed() {
        GraphStatus::CommitteePresigned
    } else {
        GraphStatus::OperatorPresigned
    };

    let prekickoff_txid = graph.cur_prekickoff.tx().compute_txid();
    let kickoff_txid = graph.kickoff.tx().compute_txid();
    let take1_txid = graph.take1.tx().compute_txid();
    let take2_txid = graph.take2.tx().compute_txid();

    // GraphData is a Goat-chain fact and must be checked regardless of the
    // current local projection. A fully synced node may otherwise remain at
    // OperatorPresigned forever after a prior status regression.
    let graph_data_on_goat = goat_client.gateway_get_graph_data(&graph_id).await?;
    if graph_data_on_goat.operator_pubkey != [0u8; 32] {
        current_status = GraphStatus::OperatorDataPushed;
    }
    // Derive stages from confirmed chain progress, not local Obsoleted state.
    // Mempool transactions can be replaced and must not decide a terminal stage.
    if !tx_confirmed(btc_client, &prekickoff_txid).await? {
        return Ok(GraphChainScan {
            status: current_status,
            sub_status,
            challenge_txid: None,
            disprove: None,
        });
    }
    // check Kickoff/SkipKickoff. Only a confirmed spend decides: Skipped is
    // closed and never scanned again, so a Skip-Kickoff that is only in the
    // mempool must not hide the Kickoff that replaces it, and a mempool
    // Kickoff replaced by the Skip must not strand the graph at OperatorKickOff.
    let kickoff_connector_vout = output_topology::prekickoff::kickoff_connector() as u64;
    let kickoff_connector_spent =
        outpoint_spent_confirmed(btc_client, &prekickoff_txid, kickoff_connector_vout).await?;
    match kickoff_connector_spent {
        Some(spent_txid) if spent_txid != kickoff_txid => {
            return Ok(GraphChainScan {
                status: GraphStatus::Skipped,
                sub_status,
                challenge_txid: None,
                disprove: None,
            });
        }
        Some(_) => current_status = GraphStatus::OperatorKickOff,
        None => {
            return Ok(GraphChainScan {
                status: GraphStatus::PreKickoff,
                sub_status,
                challenge_txid: None,
                disprove: None,
            });
        }
    }

    let mut challenge_txid = None;
    if current_status == GraphStatus::OperatorKickOff
        && let Some(disprove) = detect_guardian_disprove(btc_client, graph).await?
    {
        sub_status.disprove_type = Some(disprove.disprove_type);
        sub_status.disprove_index = disprove.index as i32;
        return Ok(GraphChainScan {
            status: GraphStatus::Disprove,
            sub_status,
            challenge_txid,
            disprove: Some(disprove),
        });
    }
    if current_status == GraphStatus::OperatorKickOff {
        let connector_a = connector_a_outpoint(graph)?;
        if let Some(spent_txid) =
            outpoint_spent_confirmed(btc_client, &connector_a.txid, connector_a.vout as u64).await?
        {
            if spent_txid != take1_txid {
                current_status = GraphStatus::Challenge;
                challenge_txid = Some(spent_txid);
            } else {
                return Ok(GraphChainScan {
                    status: GraphStatus::OperatorTake1,
                    sub_status,
                    challenge_txid: None,
                    disprove: None,
                });
            }
        } else {
            return Ok(GraphChainScan {
                status: GraphStatus::OperatorKickOff,
                sub_status,
                challenge_txid: None,
                disprove: None,
            });
        }
    }

    if current_status == GraphStatus::Challenge {
        if let Some(disprove) = detect_guardian_disprove(btc_client, graph).await? {
            sub_status.disprove_type = Some(disprove.disprove_type);
            sub_status.disprove_index = disprove.index as i32;
            return Ok(GraphChainScan {
                status: GraphStatus::Disprove,
                sub_status,
                challenge_txid,
                disprove: Some(disprove),
            });
        }

        if let Some(disprove) = detect_watchtower_flow_disprove(btc_client, graph).await? {
            sub_status.disprove_type = Some(disprove.disprove_type);
            sub_status.disprove_index = disprove.index as i32;
            return Ok(GraphChainScan {
                status: GraphStatus::Disprove,
                sub_status,
                challenge_txid,
                disprove: Some(disprove),
            });
        }

        let watchtower_challenge_init_txid = graph.watchtower_challenge_init.tx().compute_txid();
        let watchtower_challenge_init_on_chain =
            tx_visible(btc_client, &watchtower_challenge_init_txid).await?;
        if watchtower_challenge_init_on_chain {
            for watchtower_index in 0..watchtower_num {
                let watchtower_vout =
                    output_topology::watchtower_challenge_init::watchtower_connector(
                        watchtower_index,
                    ) as u64;
                let spent = outpoint_spent_txid(
                    btc_client,
                    &watchtower_challenge_init_txid,
                    watchtower_vout,
                )
                .await?
                .is_some();
                if let Some(status) =
                    sub_status.watchtower_challenge_status.get_mut(watchtower_index)
                {
                    *status = spent;
                }
            }
        }
        if !watchtower_challenge_init_on_chain {
            return Ok(GraphChainScan {
                status: current_status,
                sub_status,
                challenge_txid,
                disprove: None,
            });
        }
        let operator_assert_txid = graph.operator_assert.tx().compute_txid();
        let operator_assert_on_chain = tx_visible(btc_client, &operator_assert_txid).await?;
        if !operator_assert_on_chain {
            return Ok(GraphChainScan {
                status: current_status,
                sub_status,
                challenge_txid,
                disprove: None,
            });
        }
        // TBD: add GraphStatus::Assert
    }

    if current_status == GraphStatus::Challenge {
        // TBD: add GraphStatus::Assert
        for verifier_index in 0..verifier_num {
            let verifier_assert_txid = graph.verifier_asserts[verifier_index].tx().compute_txid();
            if tx_visible(btc_client, &verifier_assert_txid).await? {
                sub_status.verifier_challenge_status[verifier_index] =
                    if outpoint_spent_confirmed(btc_client, &verifier_assert_txid, 0)
                        .await?
                        .is_some()
                    {
                        VerifierChallengeStatus::ProverAnswered
                    } else {
                        VerifierChallengeStatus::VerifierAsserted
                    };
            }
        }
        if let Some(disprove) = detect_connector_d_disprove(btc_client, graph).await? {
            if matches!(disprove.disprove_type, DisproveTxType::Disprove) {
                let status = sub_status
                    .verifier_challenge_status
                    .get_mut(disprove.index)
                    .ok_or_else(|| {
                        anyhow!(
                            "Disprove-X verifier index {} is outside graph branches",
                            disprove.index
                        )
                    })?;
                *status = VerifierChallengeStatus::Disproved;
            }
            sub_status.disprove_type = Some(disprove.disprove_type);
            sub_status.disprove_index = disprove.index as i32;
            return Ok(GraphChainScan {
                status: GraphStatus::Disprove,
                sub_status,
                challenge_txid,
                disprove: Some(disprove),
            });
        }
        if tx_confirmed(btc_client, &take2_txid).await? {
            return Ok(GraphChainScan {
                status: GraphStatus::OperatorTake2,
                sub_status,
                challenge_txid,
                disprove: None,
            });
        }
    }

    Ok(GraphChainScan { status: current_status, sub_status, challenge_txid, disprove: None })
}

#[cfg(test)]
mod disprove_tests {
    use super::*;
    use bitcoin::{Amount, ScriptBuf, TxIn, TxOut, Witness, hashes::Hash};

    fn outpoint(tag: u8) -> OutPoint {
        OutPoint { txid: Txid::from_byte_array([tag; 32]), vout: u32::from(tag) }
    }
    fn template(inputs: &[OutPoint]) -> Transaction {
        Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: inputs
                .iter()
                .map(|outpoint| TxIn { previous_output: *outpoint, ..Default::default() })
                .collect(),
            output: vec![],
        }
    }
    fn output(script: &[u8]) -> TxOut {
        TxOut {
            value: Amount::from_sat(330),
            script_pubkey: ScriptBuf::from_bytes(script.to_vec()),
        }
    }
    fn leaf_witness(script: &Script) -> Witness {
        // Classification fixtures; script execution is the confirming Bitcoin node's responsibility.
        Witness::from_slice(&[vec![1], script.as_bytes().to_vec(), vec![0xc0; 33]])
    }
    fn api_tx(tx: &Transaction, confirmed: bool) -> esplora_client::Tx {
        esplora_client::Tx {
            txid: tx.compute_txid(),
            version: tx.version.0,
            locktime: tx.lock_time.to_consensus_u32(),
            vin: tx
                .input
                .iter()
                .map(|input| esplora_client::Vin {
                    txid: input.previous_output.txid,
                    vout: input.previous_output.vout,
                    prevout: None,
                    scriptsig: input.script_sig.clone(),
                    witness: input.witness.to_vec(),
                    sequence: input.sequence.0,
                    is_coinbase: false,
                })
                .collect(),
            vout: tx
                .output
                .iter()
                .map(|o| esplora_client::Vout {
                    value: o.value.to_sat(),
                    scriptpubkey: o.script_pubkey.clone(),
                })
                .collect(),
            size: tx.total_size(),
            weight: tx.weight().to_wu(),
            fee: 0,
            status: esplora_client::TxStatus {
                confirmed,
                block_height: confirmed.then_some(10),
                block_hash: None,
                block_time: None,
            },
        }
    }
    fn spend_status(txid: Txid) -> esplora_client::OutputStatus {
        esplora_client::OutputStatus { spent: true, txid: Some(txid), vin: Some(0), status: None }
    }

    #[test]
    fn guardian_challenges_ignore_change_and_anchor_outputs_and_keep_actual_txid() {
        let guardian = outpoint(1);
        let quick = template(&[guardian, outpoint(2)]);
        let incomplete = template(&[guardian, outpoint(3)]);
        let candidates = [
            (DisproveTxType::QuickChallenge, 0, &quick),
            (DisproveTxType::ChallengeIncompleteKickoff, 0, &incomplete),
        ];
        for (kind, source) in [
            (DisproveTxType::QuickChallenge, &quick),
            (DisproveTxType::ChallengeIncompleteKickoff, &incomplete),
        ] {
            for outputs in
                [vec![output(&[0x51])], vec![output(&[0x51]), output(&[0x51, 0x02, 0x4e, 0x73])]]
            {
                let mut actual = source.clone();
                actual.output = outputs;
                assert_ne!(actual.compute_txid(), source.compute_txid());
                let result =
                    classify_connector_spend(&actual, &candidates, &[], None).unwrap().unwrap();
                assert_eq!(result.disprove_type, kind);
                assert_eq!(result.challenge_finish_txid, actual.compute_txid());
            }
        }
    }

    #[test]
    fn output_modified_disprove_x_keeps_verifier_index_and_requires_correct_d_leaf() {
        let d = outpoint(5);
        let pubin = ScriptBuf::from_bytes(vec![0x51]);
        let disprove = ScriptBuf::from_bytes(vec![0x52]);
        let templates: Vec<_> = (10..13).map(|tag| template(&[outpoint(tag), d])).collect();
        let candidates: Vec<_> =
            templates.iter().enumerate().map(|(i, t)| (DisproveTxType::Disprove, i, t)).collect();
        for (index, source) in templates.iter().enumerate() {
            let mut tx = source.clone();
            tx.output = vec![output(&[0x6a, 0x14]), output(&[0x51])];
            tx.input[1].witness = leaf_witness(&disprove);
            let result =
                classify_connector_spend(&tx, &candidates, &[], Some((d, &pubin, &disprove)))
                    .unwrap()
                    .unwrap();
            assert_eq!(result.disprove_type, DisproveTxType::Disprove);
            assert_eq!(result.index, index);
            assert_eq!(result.challenge_finish_txid, tx.compute_txid());
            tx.input[1].witness = Witness::default();
            assert!(
                classify_connector_spend(&tx, &candidates, &[], Some((d, &pubin, &disprove)))
                    .is_err()
            );
        }
    }

    #[test]
    fn pubin_disprove_is_identified_by_its_leaf_including_annex_and_fee_inputs() {
        let d = outpoint(5);
        let pubin = ScriptBuf::from_bytes(vec![0x51]);
        let disprove = ScriptBuf::from_bytes(vec![0x52]);
        let candidate = template(&[outpoint(10), d]);
        let candidates = [(DisproveTxType::Disprove, 0, &candidate)];
        let mut tx = candidate.clone();
        tx.input[1].witness = leaf_witness(&pubin);
        tx.input[1].witness.push([0x50, 0x01]);
        // Even if other inputs resemble a Disprove-X, the D leaf decides the path.
        let result = classify_connector_spend(&tx, &candidates, &[], Some((d, &pubin, &disprove)))
            .unwrap()
            .unwrap();
        assert_eq!(result.disprove_type, DisproveTxType::PubinDisprove);
        tx.input.insert(0, TxIn { previous_output: outpoint(99), ..Default::default() });
        assert_eq!(
            classify_connector_spend(&tx, &candidates, &[], Some((d, &pubin, &disprove)))
                .unwrap()
                .unwrap()
                .disprove_type,
            DisproveTxType::PubinDisprove
        );
        tx.input[2].witness = leaf_witness(Script::from_bytes(&[0x53]));
        assert!(
            classify_connector_spend(&tx, &candidates, &[], Some((d, &pubin, &disprove))).is_err()
        );
    }

    #[test]
    fn takes_are_excluded_and_unknown_or_changed_inputs_are_not_disproves() {
        let candidate = template(&[outpoint(1), outpoint(2)]);
        let candidates = [(DisproveTxType::QuickChallenge, 0, &candidate)];
        for tag in [3, 4] {
            let take = template(&[outpoint(1), outpoint(tag)]);
            assert!(
                classify_connector_spend(&take, &candidates, &[take.compute_txid()], None)
                    .unwrap()
                    .is_none()
            );
            assert!(classify_connector_spend(&take, &candidates, &[], None).is_err());
        }
        let mut changed = candidate.clone();
        changed.input[0].sequence = bitcoin::Sequence(10);
        assert!(classify_connector_spend(&changed, &candidates, &[], None).is_err());
        changed = candidate.clone();
        changed.input.swap(0, 1);
        assert!(classify_connector_spend(&changed, &candidates, &[], None).is_err());
    }

    #[tokio::test]
    async fn only_confirmed_actual_connector_spends_are_loaded() {
        let (btc, mock) = BTCClient::new_mock_client();
        let connector = outpoint(1);
        assert!(confirmed_connector_spend(&btc, connector).await.unwrap().is_none());
        let mut tx = template(&[connector, outpoint(2)]);
        tx.output.push(output(&[0x51]));
        mock.set_tx(tx.compute_txid(), api_tx(&tx, false));
        mock.set_output_status(
            connector.txid,
            connector.vout as u64,
            spend_status(tx.compute_txid()),
        );
        assert!(confirmed_connector_spend(&btc, connector).await.unwrap().is_none());
        mock.set_tx(tx.compute_txid(), api_tx(&tx, true));
        let actual = confirmed_connector_spend(&btc, connector).await.unwrap().unwrap();
        assert_eq!(actual, tx);
    }

    #[tokio::test]
    async fn unavailable_or_inconsistent_spender_data_returns_error_for_retry() {
        let (btc, mock) = BTCClient::new_mock_client();
        let connector = outpoint(1);
        let missing = Txid::from_byte_array([99; 32]);
        mock.set_output_status(connector.txid, connector.vout as u64, spend_status(missing));
        assert!(confirmed_connector_spend(&btc, connector).await.is_err());
        let tx = template(&[outpoint(2)]);
        mock.set_tx(missing, api_tx(&tx, true));
        assert!(
            confirmed_connector_spend(&btc, connector)
                .await
                .unwrap_err()
                .to_string()
                .contains("hash mismatch")
        );
        mock.set_tx(tx.compute_txid(), api_tx(&tx, true));
        mock.set_output_status(
            connector.txid,
            connector.vout as u64,
            spend_status(tx.compute_txid()),
        );
        assert!(
            confirmed_connector_spend(&btc, connector)
                .await
                .unwrap_err()
                .to_string()
                .contains("does not spend connector")
        );
    }
}
