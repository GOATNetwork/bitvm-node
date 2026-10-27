//! What both chains say about a graph: its stage and challenge branches.

use anyhow::{Result, anyhow, bail};
use bitcoin::{OutPoint, Txid};
use bitvm_lib::types::BitvmGcGraph;
use client::{btc_chain::BTCClient, goat_chain::GOATClient};
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

async fn detect_guardian_disprove(
    btc_client: &BTCClient,
    graph: &BitvmGcGraph,
) -> Result<Option<DetectedDisprove>> {
    let quick_challenge_txid = graph.quick_challenge.tx().compute_txid();
    if tx_confirmed(btc_client, &quick_challenge_txid).await? {
        return Ok(Some(DetectedDisprove {
            disprove_type: DisproveTxType::QuickChallenge,
            index: 0,
            challenge_finish_txid: quick_challenge_txid,
        }));
    }

    let challenge_incomplete_kickoff_txid = graph.challenge_incomplete_kickoff.tx().compute_txid();
    if tx_confirmed(btc_client, &challenge_incomplete_kickoff_txid).await? {
        return Ok(Some(DetectedDisprove {
            disprove_type: DisproveTxType::ChallengeIncompleteKickoff,
            index: 0,
            challenge_finish_txid: challenge_incomplete_kickoff_txid,
        }));
    }
    Ok(None)
}

async fn detect_connector_d_disprove(
    btc_client: &BTCClient,
    graph: &BitvmGcGraph,
) -> Result<Option<DetectedDisprove>> {
    let connector_d = connector_d_outpoint(graph)?;
    let Some(spent_txid) =
        outpoint_spent_confirmed(btc_client, &connector_d.txid, connector_d.vout as u64).await?
    else {
        return Ok(None);
    };

    if spent_txid == graph.take2.tx().compute_txid() {
        return Ok(None);
    }

    for (index, disprove) in graph.disproves.iter().enumerate() {
        if spent_txid == disprove.tx().compute_txid() {
            return Ok(Some(DetectedDisprove {
                disprove_type: DisproveTxType::Disprove,
                index,
                challenge_finish_txid: spent_txid,
            }));
        }
    }

    Ok(Some(DetectedDisprove {
        disprove_type: DisproveTxType::PubinDisprove,
        index: 0,
        challenge_finish_txid: spent_txid,
    }))
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
        let mut detected_disprove = None;
        for verifier_index in 0..verifier_num {
            let verifier_assert_txid = graph.verifier_asserts[verifier_index].tx().compute_txid();
            let disprove_txid = graph.disproves[verifier_index].tx().compute_txid();
            if tx_visible(btc_client, &verifier_assert_txid).await? {
                if let Some(spent_txid) =
                    outpoint_spent_confirmed(btc_client, &verifier_assert_txid, 0).await?
                {
                    if spent_txid == disprove_txid {
                        sub_status.verifier_challenge_status[verifier_index] =
                            VerifierChallengeStatus::Disproved;
                        sub_status.disprove_type = Some(DisproveTxType::Disprove);
                        sub_status.disprove_index = verifier_index as i32;
                        detected_disprove = Some(DetectedDisprove {
                            disprove_type: DisproveTxType::Disprove,
                            index: verifier_index,
                            challenge_finish_txid: spent_txid,
                        });
                        current_status = GraphStatus::Disprove;
                    } else {
                        sub_status.verifier_challenge_status[verifier_index] =
                            VerifierChallengeStatus::ProverAnswered;
                    }
                } else {
                    sub_status.verifier_challenge_status[verifier_index] =
                        VerifierChallengeStatus::VerifierAsserted;
                }
            }
        }
        if current_status == GraphStatus::Disprove {
            return Ok(GraphChainScan {
                status: current_status,
                sub_status,
                challenge_txid,
                disprove: detected_disprove,
            });
        }
        if let Some(disprove) = detect_connector_d_disprove(btc_client, graph).await? {
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
