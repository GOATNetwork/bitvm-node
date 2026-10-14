//! Graph definitions in the store: ingest, raw data, lookups and status
//! transitions.

use crate::env::*;
use crate::error::SpecialError;
use crate::rpc_service::current_time_secs;
use anyhow::{Result, bail};
use bitcoin::PublicKey;
use bitvm_lib::committee::*;
use bitvm_lib::operator::*;
use bitvm_lib::types::{BitvmGcGraph, SimplifiedBitvmGcGraph};
use goat::transactions::prekickoff::PrekickoffTransaction;
use indexmap::IndexMap;
use store::localdb::{GraphQuery, LocalDB, StorageProcessor};

use crate::aggregates::graph_scan::ChallengeSubStatus;
use bitvm_lib::transactions::base::BaseTransaction;
use store::{
    Graph, GraphRawData, GraphStatus, GraphStatusSource, GraphStatusTransitionOutcome,
    PeginGraphProcessData,
};
use tracing::error;
use uuid::Uuid;

use super::btc::node_p2wsh_address;
use super::rounds::GraphProcessDataMap;

// db operations
pub async fn get_current_prekickoff_tx(
    local_db: &LocalDB,
    operator_pubkey: &PublicKey,
) -> Result<Option<(u64, PrekickoffTransaction)>> {
    // return (latest_graph.nonce + 1 , latest_graph.next_prekickoff_tx)
    // return None if no graph yet
    let mut storage_processor = local_db.acquire().await?;
    let graphs = storage_processor
        .get_operator_graphs(
            GraphQuery::default()
                .with_operator_pubkey(operator_pubkey.to_string())
                .with_order("kickoff_index DESC".to_string())
                .with_limit(1),
        )
        .await?;

    if let Some(graph) = graphs.first()
        && let Some(simplified_graph) = load_validated_graph_definition(
            &mut storage_processor,
            graph.instance_id,
            graph.graph_id,
        )
        .await?
    {
        Ok(Some((
            (graph.kickoff_index + 1) as u64,
            BitvmGcGraph::from_simplified(&simplified_graph)?.next_prekickoff,
        )))
    } else {
        Ok(None)
    }
}

fn convert_graph(
    bitvm_graph: &BitvmGcGraph,
    current_time: i64,
    initial_status: GraphStatus,
    definition_hash: String,
) -> Graph {
    Graph {
        graph_id: bitvm_graph.parameters.graph_id,
        instance_id: bitvm_graph.parameters.instance_parameters.instance_id,
        kickoff_index: bitvm_graph.parameters.graph_nonce as i64,
        from_addr: "".to_string(),
        to_addr: "".to_string(),
        amount: bitvm_graph.parameters.instance_parameters.pegin_amount.to_sat() as i64,
        challenge_amount: bitvm_graph.parameters.challenge_amount.to_sat() as i64,
        status: initial_status.to_string(),
        sub_status: "".to_string(),
        operator_pubkey: bitvm_graph.parameters.operator_pubkey.to_string(),
        definition_hash,
        cur_prekickoff_txid: Some(bitvm_graph.cur_prekickoff.finalize().compute_txid().into()),
        next_prekickoff: Some(bitvm_graph.next_prekickoff.finalize().compute_txid().into()),
        force_skip_kickoff_txid: Some(
            bitvm_graph.force_skip_kickoff.finalize().compute_txid().into(),
        ),
        quick_challenge_txid: Some(bitvm_graph.quick_challenge.finalize().compute_txid().into()),
        challenge_incomplete_kickoff_txid: Some(
            bitvm_graph.challenge_incomplete_kickoff.finalize().compute_txid().into(),
        ),
        pegin_txid: Some(bitvm_graph.pegin.finalize().compute_txid().into()),
        kickoff_txid: Some(bitvm_graph.kickoff.finalize().compute_txid().into()),
        take1_txid: Some(bitvm_graph.take1.finalize().compute_txid().into()),
        challenge_txid: None,
        take2_txid: Some(bitvm_graph.take2.finalize().compute_txid().into()),
        watchtower_challenge_init_txid: Some(
            bitvm_graph.watchtower_challenge_init.finalize().compute_txid().into(),
        ),
        operator_assert_txid: Some(bitvm_graph.operator_assert.finalize().compute_txid().into()),
        verifier_assert_txids: bitvm_graph
            .verifier_asserts
            .iter()
            .map(|tx| tx.finalize().compute_txid().into())
            .collect(),
        disprove_txids: bitvm_graph
            .disproves
            .iter()
            .map(|tx| tx.finalize().compute_txid().into())
            .collect(),
        watchtower_challenge_timeout_txids: bitvm_graph
            .watchtower_challenge_timeouts
            .iter()
            .map(|tx| tx.finalize().compute_txid().into())
            .collect(),
        operator_challenge_nack_txids: bitvm_graph
            .operator_challenge_nacks
            .iter()
            .map(|tx| tx.finalize().compute_txid().into())
            .collect(),
        operator_commit_timeout_txid: Some(
            bitvm_graph.operator_commit_timeout.finalize().compute_txid().into(),
        ),
        init_withdraw_tx_hash: None,
        bridge_out_start_at: 0,
        status_updated_at: current_time,
        proceed_withdraw_height: 0,
        created_at: current_time,
        updated_at: current_time,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FinalizedGraphStoreOutcome {
    NewlyStored,
    DefinitionUpgraded,
    AlreadyFinalized,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GraphDefinitionIngestKind {
    OperatorPresigned,
    Finalized,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GraphDefinitionIngestOutcome {
    Inserted,
    FinalizedUpgrade,
    Replay,
    AlreadyFinalized,
}

/// Store a verified operator-pre-signed graph definition.
///
/// This path is intentionally unable to advance `GraphStatus`: receiving a
/// CreateGraph message is not evidence of committee finalization.
pub(crate) async fn store_operator_presigned_graph(
    local_db: &LocalDB,
    simple_graph: &SimplifiedBitvmGcGraph,
) -> Result<()> {
    if !simple_graph.operator_pre_signed() || simple_graph.committee_pre_signed() {
        bail!(SpecialError::InvalidGraph(format!(
            "graph {} is not an operator-pre-signed proposal",
            simple_graph.parameters.graph_id
        )));
    }

    // The definition path reads existing state before updating it. Reserve the
    // writer up front so another task cannot invalidate that read snapshot.
    let mut tx = local_db.start_immediate_transaction().await?;
    ingest_graph_definition(&mut tx, simple_graph, GraphDefinitionIngestKind::OperatorPresigned)
        .await?;
    tx.commit().await?;
    Ok(())
}

/// Store a verified finalized graph once without replacing a graph whose
/// finalized form is already known.
pub(crate) async fn store_finalized_graph_if_needed(
    local_db: &LocalDB,
    simple_graph: &SimplifiedBitvmGcGraph,
) -> Result<FinalizedGraphStoreOutcome> {
    let graph_id = simple_graph.parameters.graph_id;
    if !simple_graph.operator_pre_signed() || !simple_graph.committee_pre_signed() {
        bail!(SpecialError::InvalidGraph(format!("graph {graph_id} is not fully pre-signed")));
    }

    // The definition path reads existing state before updating it. Reserve the
    // writer up front so another task cannot invalidate that read snapshot.
    let mut tx = local_db.start_immediate_transaction().await?;
    let outcome =
        ingest_graph_definition(&mut tx, simple_graph, GraphDefinitionIngestKind::Finalized)
            .await?;
    tx.commit().await?;

    Ok(match outcome {
        GraphDefinitionIngestOutcome::Inserted => FinalizedGraphStoreOutcome::NewlyStored,
        GraphDefinitionIngestOutcome::FinalizedUpgrade => {
            FinalizedGraphStoreOutcome::DefinitionUpgraded
        }
        GraphDefinitionIngestOutcome::AlreadyFinalized => {
            FinalizedGraphStoreOutcome::AlreadyFinalized
        }
        GraphDefinitionIngestOutcome::Replay => {
            unreachable!("a finalized graph replay must be classified as already finalized")
        }
    })
}

async fn ingest_graph_definition(
    tx: &mut StorageProcessor<'_>,
    simple_graph: &SimplifiedBitvmGcGraph,
    kind: GraphDefinitionIngestKind,
) -> Result<GraphDefinitionIngestOutcome> {
    let bitvm_graph: BitvmGcGraph = BitvmGcGraph::from_simplified(simple_graph)?;
    let graph_id = simple_graph.parameters.graph_id;
    verify_graph_operator_pre_signatures(&bitvm_graph).map_err(|error| {
        SpecialError::InvalidGraph(format!(
            "graph {graph_id} has invalid operator pre-signatures: {error}"
        ))
    })?;
    if kind == GraphDefinitionIngestKind::Finalized {
        verify_graph_committee_pre_signatures(&bitvm_graph).map_err(|error| {
            SpecialError::InvalidGraph(format!(
                "graph {graph_id} has invalid committee pre-signatures: {error}"
            ))
        })?;
    }
    let current_time = current_time_secs();
    let definition_hash = hex::encode(simple_graph.parameters_hash()?);
    let existing_graph_row = tx.find_graph(&graph_id).await?;
    let existing_raw_data = tx.find_graph_raw_data(&graph_id).await?;
    let existing_graph = match (existing_graph_row.as_ref(), existing_raw_data) {
        (None, None) => None,
        (Some(_), None) => {
            bail!(SpecialError::InvalidGraph(format!(
                "graph {graph_id} has runtime data but no raw definition; explicit repair is required"
            )));
        }
        (None, Some(_)) => {
            bail!(SpecialError::InvalidGraph(format!(
                "graph {graph_id} has raw definition but no graph row; explicit repair is required"
            )));
        }
        (Some(existing_row), Some(existing_raw_data)) => {
            if existing_row.definition_hash.is_empty() {
                bail!(SpecialError::InvalidGraph(format!(
                    "graph {graph_id} is missing its stored definition hash; explicit repair is required"
                )));
            }
            if existing_row.definition_hash != definition_hash {
                bail!(SpecialError::InvalidGraph(format!(
                    "graph parameters changed for graph_id {graph_id}: existing={}, incoming={definition_hash}",
                    existing_row.definition_hash
                )));
            }

            let existing_graph = parse_graph_raw_data(existing_raw_data.raw_data, graph_id).await?;
            let existing_raw_hash = hex::encode(existing_graph.parameters_hash()?);
            if existing_raw_hash != existing_row.definition_hash {
                bail!(SpecialError::InvalidGraph(format!(
                    "graph {graph_id} definition hash does not match its stored raw definition"
                )));
            }
            let existing_full_graph = BitvmGcGraph::from_simplified(&existing_graph)?;
            verify_graph_operator_pre_signatures(&existing_full_graph).map_err(|error| {
                SpecialError::InvalidGraph(format!(
                    "stored graph {graph_id} has invalid operator pre-signatures: {error}"
                ))
            })?;
            if existing_full_graph.committee_pre_signed() {
                verify_graph_committee_pre_signatures(&existing_full_graph).map_err(|error| {
                    SpecialError::InvalidGraph(format!(
                        "stored graph {graph_id} has invalid committee pre-signatures: {error}"
                    ))
                })?;
            }
            Some(existing_graph)
        }
    };

    let existing_is_finalized =
        existing_graph.as_ref().is_some_and(SimplifiedBitvmGcGraph::committee_pre_signed);
    if existing_is_finalized {
        let existing_graph = existing_graph.as_ref().expect("checked above");
        if kind == GraphDefinitionIngestKind::Finalized && existing_graph != simple_graph {
            bail!(SpecialError::InvalidGraph(format!(
                "conflicting finalized graph for graph_id {graph_id}"
            )));
        }

        // An old CreateGraph replay is harmless once a verified finalized
        // graph is stored. Do not replace its raw signatures or runtime.
        if kind == GraphDefinitionIngestKind::Finalized {
            confirm_finalized_graph_definition(
                tx,
                bitvm_graph.parameters.instance_parameters.instance_id,
                graph_id,
            )
            .await?;
        }
        return Ok(GraphDefinitionIngestOutcome::AlreadyFinalized);
    }

    if kind == GraphDefinitionIngestKind::OperatorPresigned
        && let Some(existing_graph) = existing_graph.as_ref()
        && existing_graph != simple_graph
    {
        bail!(SpecialError::InvalidGraph(format!(
            "conflicting operator-pre-signed graph for graph_id {graph_id}"
        )));
    }
    if kind == GraphDefinitionIngestKind::Finalized
        && let Some(existing_graph) = existing_graph.as_ref()
        && existing_graph.operator_pre_sigs != simple_graph.operator_pre_sigs
    {
        bail!(SpecialError::InvalidGraph(format!(
            "finalized graph {graph_id} changes the stored operator pre-signatures"
        )));
    }

    if existing_graph.is_none() {
        // One definition per operator slot: a second graph for a taken slot is refused for
        // good, not retried on the unique index.
        let operator_pubkey = bitvm_graph.parameters.operator_pubkey.to_string();
        let graph_nonce = bitvm_graph.parameters.graph_nonce;
        if let Some(holder) =
            tx.find_graph_by_operator_slot(&operator_pubkey, graph_nonce as i64).await?
            && holder.graph_id != graph_id
        {
            bail!(SpecialError::InvalidGraph(format!(
                "slot {graph_nonce} of operator {operator_pubkey} is held by graph {}; graph {graph_id} is refused",
                holder.graph_id
            )));
        }
    }

    let mut graph = convert_graph(
        &bitvm_graph,
        current_time,
        // A graph row is always created at the operator-presigned baseline.
        // Only a verified finalized definition may advance it through the
        // dedicated Definition transition below.
        GraphStatus::OperatorPresigned,
        definition_hash.clone(),
    );

    if let Some(node_info) =
        tx.get_node_by_btc_pub_key(&bitvm_graph.parameters.operator_pubkey.to_string()).await?
    {
        graph.from_addr = node_info.goat_addr.clone();
        graph.to_addr =
            node_p2wsh_address(get_network(), &bitvm_graph.parameters.operator_pubkey).to_string();
    }

    tx.upsert_graph_definition(&graph).await?;

    let outcome = if existing_graph.is_none() {
        let raw_data = serialize_graph_raw_data(simple_graph, graph_id).await?;
        tx.upsert_graph_raw_data(
            bitvm_graph.parameters.instance_parameters.instance_id,
            GraphRawData { graph_id, raw_data, created_at: current_time, updated_at: current_time },
            &definition_hash,
        )
        .await?;
        if kind == GraphDefinitionIngestKind::Finalized {
            confirm_finalized_graph_definition(
                tx,
                bitvm_graph.parameters.instance_parameters.instance_id,
                graph_id,
            )
            .await?;
        }
        GraphDefinitionIngestOutcome::Inserted
    } else if kind == GraphDefinitionIngestKind::Finalized {
        let raw_data = serialize_graph_raw_data(simple_graph, graph_id).await?;
        tx.upsert_graph_raw_data(
            bitvm_graph.parameters.instance_parameters.instance_id,
            GraphRawData { graph_id, raw_data, created_at: current_time, updated_at: current_time },
            &definition_hash,
        )
        .await?;

        // Only a verified finalized definition can advance an existing locally
        // operator-pre-signed graph. A later chain-observed state is retained.
        confirm_finalized_graph_definition(
            tx,
            bitvm_graph.parameters.instance_parameters.instance_id,
            graph_id,
        )
        .await?;
        GraphDefinitionIngestOutcome::FinalizedUpgrade
    } else {
        GraphDefinitionIngestOutcome::Replay
    };

    Ok(outcome)
}

/// Confirm that a fully verified graph definition has reached the committee
/// pre-signing stage without allowing it to overwrite a later runtime state.
async fn confirm_finalized_graph_definition(
    tx: &mut StorageProcessor<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
) -> Result<()> {
    match tx
        .transition_graph_status(
            instance_id,
            graph_id,
            GraphStatus::CommitteePresigned,
            GraphStatusSource::Definition,
            None,
        )
        .await?
    {
        GraphStatusTransitionOutcome::Applied | GraphStatusTransitionOutcome::AlreadyCurrent => {
            Ok(())
        }
        GraphStatusTransitionOutcome::Rejected { current } => {
            tracing::debug!(
                "keep later graph status while storing finalized definition: graph={graph_id}, current={current}"
            );
            Ok(())
        }
        GraphStatusTransitionOutcome::NotFound => {
            bail!("graph {graph_id} disappeared while confirming its finalized definition")
        }
    }
}

/// Parse raw graph data JSON string to SimplifiedBitvmGcGraph using spawn_blocking
/// to handle large data and potential stack overflow issues
pub async fn parse_graph_raw_data(
    raw_data: String,
    graph_id: Uuid,
) -> Result<SimplifiedBitvmGcGraph> {
    let raw_data_len = raw_data.len();
    let raw_data_clone = raw_data.clone();
    let parse_result = tokio::task::spawn_blocking(move || {
        serde_json::from_str::<SimplifiedBitvmGcGraph>(&raw_data_clone)
    })
    .await;

    match parse_result {
        Ok(Ok(data)) => Ok(data),
        Ok(Err(e)) => {
            // Normal JSON parsing error
            error!("Failed to parse graph data for graph_id {graph_id}: {e}");
            error!("Raw data length: {raw_data_len} bytes");
            Err(e.into())
        }
        Err(join_err) => {
            // spawn_blocking task failed (thread panic or task cancelled)
            let msg = if join_err.is_panic() {
                format!("Thread panic while parsing graph data for graph_id {graph_id}")
            } else if join_err.is_cancelled() {
                format!("Task cancelled while parsing graph data for graph_id {graph_id}")
            } else {
                format!(
                    "Task join error while parsing graph data for graph_id {graph_id}: {join_err}"
                )
            };
            error!("{msg}");
            error!("Raw data length: {raw_data_len} bytes");
            Err(anyhow::anyhow!("{msg}"))
        }
    }
}

/// Serialize SimplifiedBitvmGcGraph to JSON string using spawn_blocking
/// to handle large data and potential stack overflow issues
pub async fn serialize_graph_raw_data(
    graph: &SimplifiedBitvmGcGraph,
    graph_id: Uuid,
) -> Result<String> {
    let graph_clone = graph.clone();
    let serialize_result =
        tokio::task::spawn_blocking(move || serde_json::to_string(&graph_clone)).await;

    match serialize_result {
        Ok(Ok(data)) => Ok(data),
        Ok(Err(e)) => {
            // Normal JSON serialization error
            error!("Failed to serialize graph data for graph_id {graph_id}: {e}");
            Err(e.into())
        }
        Err(join_err) => {
            // spawn_blocking task failed (thread panic or task cancelled)
            let msg = if join_err.is_panic() {
                format!("Thread panic while serializing graph data for graph_id {graph_id}")
            } else if join_err.is_cancelled() {
                format!("Task cancelled while serializing graph data for graph_id {graph_id}")
            } else {
                format!(
                    "Task join error while serializing graph data for graph_id {graph_id}: {join_err}",
                )
            };
            error!("{msg}");
            Err(anyhow::anyhow!("{graph_id}"))
        }
    }
}

/// Load a graph only after binding its runtime row, raw definition, canonical
/// parameters and pre-signatures together. Callers must use this instead of
/// parsing `graph_raw_data` directly.
pub(crate) async fn load_validated_graph_definition(
    storage_processor: &mut StorageProcessor<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
) -> Result<Option<SimplifiedBitvmGcGraph>> {
    let Some(graph_row) = storage_processor.find_graph(&graph_id).await? else {
        return Ok(None);
    };
    if graph_row.instance_id != instance_id {
        bail!(SpecialError::InvalidGraph(format!(
            "graph {graph_id} belongs to instance {}, not {instance_id}",
            graph_row.instance_id
        )));
    }
    if graph_row.definition_hash.is_empty() {
        bail!(SpecialError::InvalidGraph(format!(
            "graph {graph_id} is missing its definition hash; explicit repair is required"
        )));
    }

    let graph_raw_data = storage_processor
        .find_graph_raw_data(&graph_id)
        .await?
        .ok_or_else(|| {
            SpecialError::InvalidGraph(format!(
                "graph {graph_id} has a runtime row but no raw definition; explicit repair is required"
            ))
        })?;
    let simplified_graph = parse_graph_raw_data(graph_raw_data.raw_data, graph_id).await?;
    if simplified_graph.parameters.graph_id != graph_id
        || simplified_graph.parameters.instance_parameters.instance_id != instance_id
    {
        bail!(SpecialError::InvalidGraph(format!(
            "stored raw definition identifiers do not match graph {instance_id}:{graph_id}"
        )));
    }
    let definition_hash = hex::encode(simplified_graph.parameters_hash()?);
    if definition_hash != graph_row.definition_hash {
        bail!(SpecialError::InvalidGraph(format!(
            "stored raw definition hash does not match graph row for {instance_id}:{graph_id}"
        )));
    }

    let full_graph = BitvmGcGraph::from_simplified(&simplified_graph).map_err(|error| {
        SpecialError::InvalidGraph(format!(
            "stored raw definition cannot rebuild graph for {instance_id}:{graph_id}: {error}"
        ))
    })?;
    verify_graph_operator_pre_signatures(&full_graph).map_err(|error| {
        SpecialError::InvalidGraph(format!(
            "stored raw definition has invalid operator pre-signatures for {instance_id}:{graph_id}: {error}"
        ))
    })?;
    if full_graph.committee_pre_signed() {
        verify_graph_committee_pre_signatures(&full_graph).map_err(|error| {
            SpecialError::InvalidGraph(format!(
                "stored raw definition has invalid committee pre-signatures for {instance_id}:{graph_id}: {error}"
            ))
        })?;
    }

    Ok(Some(simplified_graph))
}

pub async fn get_graph(
    local_db: &LocalDB,
    instance_id: Uuid,
    graph_id: Uuid,
) -> Result<Option<SimplifiedBitvmGcGraph>> {
    let mut storage_processor = local_db.acquire().await?;
    load_validated_graph_definition(&mut storage_processor, instance_id, graph_id).await
}

pub async fn get_graph_by_instance_id_and_operator_pubkey(
    local_db: &LocalDB,
    instance_id: Uuid,
    operator_pubkey: &PublicKey,
) -> Result<Option<SimplifiedBitvmGcGraph>> {
    let mut storage_process = local_db.acquire().await?;
    if let Some(graph_id) = storage_process
        .get_graph_id_by_instance_id_and_operator_pubkey(&instance_id, &operator_pubkey.to_string())
        .await?
    {
        load_validated_graph_definition(&mut storage_process, instance_id, graph_id).await
    } else {
        Ok(None)
    }
}

pub async fn upsert_pegin_graph_process_data(
    storage_processor: &mut StorageProcessor<'_>,
    graph_id: Uuid,
    instance_id: Uuid,
    is_endorsed: bool,
    process_data_map: &GraphProcessDataMap,
) -> Result<()> {
    let current_time = current_time_secs();
    storage_processor
        .upsert_pegin_graph_process_data(&PeginGraphProcessData {
            graph_id,
            instance_id,
            is_endorsed,
            process_data: serde_json::to_string(process_data_map)?,
            updated_at: current_time,
            created_at: current_time,
        })
        .await?;
    Ok(())
}

pub async fn find_pegin_graph_process_data(
    storage_processor: &mut StorageProcessor<'_>,
    graph_id: Uuid,
) -> Result<(bool, GraphProcessDataMap)> {
    match storage_processor.find_pegin_graph_process_data(&graph_id).await? {
        Some(data) => Ok((data.is_endorsed, serde_json::from_str(&data.process_data)?)),
        None => Ok((false, IndexMap::new())),
    }
}

pub async fn update_graph_status(
    local_db: &LocalDB,
    instance_id: Uuid,
    graph_id: Uuid,
    new_status: GraphStatus,
    sub_status: Option<ChallengeSubStatus>,
) -> Result<GraphStatusTransitionOutcome> {
    let mut storage_processor = local_db.acquire().await?;
    storage_processor
        .transition_graph_status(
            instance_id,
            graph_id,
            new_status,
            GraphStatusSource::ChainReconcile,
            sub_status.map(|sub_status| serde_json::to_string(&sub_status)).transpose()?,
        )
        .await
}

/// Mark one graph obsolete and cancel its pending messages.
pub(crate) async fn obsolete_graph(
    storage_processor: &mut StorageProcessor<'_>,
    instance_id: Uuid,
    graph_id: Uuid,
) -> Result<bool> {
    let outcome = storage_processor
        .transition_graph_status(
            instance_id,
            graph_id,
            GraphStatus::Obsoleted,
            GraphStatusSource::ChainReconcile,
            None,
        )
        .await?;
    Ok(matches!(
        outcome,
        GraphStatusTransitionOutcome::Applied | GraphStatusTransitionOutcome::AlreadyCurrent
    ))
}

/// Mark every non-terminal graph for an already claimed instance as obsolete.
///
/// `retained_graph_id` is the graph which completed the withdrawal. The caller
/// must only use this after a terminal Gateway withdraw event confirms that
/// this graph completed the withdrawal.
pub(crate) async fn obsolete_instance_graphs_except(
    storage_processor: &mut StorageProcessor<'_>,
    instance_id: Uuid,
    retained_graph_id: Option<Uuid>,
) -> Result<Vec<Uuid>> {
    let graphs = storage_processor.get_graphs_by_instance_id(&instance_id).await?;
    let mut obsoleted_graph_ids = Vec::new();

    for graph in graphs {
        if Some(graph.graph_id) != retained_graph_id
            && obsolete_graph(storage_processor, instance_id, graph.graph_id).await?
        {
            obsoleted_graph_ids.push(graph.graph_id);
        }
    }

    Ok(obsoleted_graph_ids)
}

pub(crate) async fn pending_graph_belongs_to_operator(
    local_db: &LocalDB,
    instance_id: Uuid,
    graph_id: Uuid,
    operator_pubkey: &PublicKey,
) -> Result<bool> {
    let mut storage = local_db.acquire().await?;
    Ok(storage.find_pending_graph_init_by_graph_id(&graph_id).await?.is_some_and(|pending| {
        pending.instance_id == instance_id && pending.operator_pubkey == operator_pubkey.to_string()
    }))
}
