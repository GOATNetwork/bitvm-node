//! Fetch and serve graph definitions over `GetGraph`.
//!
//! Fetched definitions must match the requested identity and chain parameters.
//! Operator pre-signatures are verified, as are committee pre-signatures when
//! present. A graph posted on Goat requires committee pre-signatures.

use crate::middleware::get_graph::{GetGraphRequest, GetGraphResponse};
use crate::middleware::publisher::NetworkPublisher;
use crate::utils::{
    load_validated_graph_definition, parse_graph_raw_data, store_finalized_graph_if_needed,
    store_operator_presigned_graph, validate_graph_instance_parameters,
};
use anyhow::{Context, bail};
use bitvm_lib::operator::verify_graph_operator_pre_signatures;
use bitvm_lib::types::{BitvmGcGraph, SimplifiedBitvmGcGraph};
use client::btc_chain::BTCClient;
use client::goat_chain::GOATClient;
use libp2p::PeerId;
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use store::localdb::LocalDB;
use tracing::{info, warn};
use uuid::Uuid;

/// Which definition a fetch job wants.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum GraphLookup {
    /// By id; `finalized` asks for a copy with committee pre-signatures, so a
    /// stored operator-presigned copy does not satisfy it.
    Id {
        instance_id: Uuid,
        graph_id: Uuid,
        finalized: bool,
    },
    Slot {
        operator_pubkey: String,
        graph_nonce: u64,
    },
}

impl GraphLookup {
    pub fn request(&self) -> GetGraphRequest {
        match self {
            GraphLookup::Id { instance_id, graph_id, .. } => {
                GetGraphRequest::by_id(*instance_id, *graph_id)
            }
            GraphLookup::Slot { operator_pubkey, graph_nonce } => {
                GetGraphRequest::by_slot(operator_pubkey.clone(), *graph_nonce)
            }
        }
    }
}

/// Answer a request from the local store.
pub async fn serve_graph_request(
    local_db: &LocalDB,
    request: &GetGraphRequest,
) -> anyhow::Result<GetGraphResponse> {
    let mut storage = local_db.acquire().await?;
    let row = match (request.graph_id, &request.operator_pubkey, request.graph_nonce) {
        (Some(graph_id), _, _) => storage.find_graph(&graph_id).await?,
        (None, Some(operator_pubkey), Some(graph_nonce)) => {
            storage.find_graph_by_operator_slot(operator_pubkey, graph_nonce as i64).await?
        }
        _ => return Ok(GetGraphResponse::not_found()),
    };
    let Some(row) = row else {
        return Ok(GetGraphResponse::not_found());
    };
    if let Some(instance_id) = request.instance_id
        && row.instance_id != instance_id
    {
        return Ok(GetGraphResponse::not_found());
    }
    let Some(raw) = storage.find_graph_raw_data(&row.graph_id).await? else {
        return Ok(GetGraphResponse::not_found());
    };
    Ok(GetGraphResponse::found(row.instance_id, row.graph_id, raw.raw_data))
}

/// What a fetch stored.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FetchedGraph {
    pub instance_id: Uuid,
    pub graph_id: Uuid,
    pub operator_pubkey: String,
    pub graph_nonce: u64,
    pub finalized: bool,
}

/// Candidate peers in the order the spec prescribes: relayer / committee
/// first, the operator last.
pub fn fetch_candidates(operator_pubkey: Option<&str>) -> Vec<PeerId> {
    let now = std::time::Instant::now();
    let registry = crate::p2p_admission::peer_registry();
    let mut peers = registry.committee_peer_ids(now);
    if let Some(operator_pubkey) = operator_pubkey
        && let Ok(pubkey) = bitcoin::PublicKey::from_str(operator_pubkey)
    {
        let key = crate::p2p_admission::operator_key(&bitcoin::XOnlyPublicKey::from(pubkey));
        if let Some(peer) = registry.operator_peer_for(&key)
            && !peers.contains(&peer)
        {
            peers.push(peer);
        }
    }
    let local = crate::env::get_peer_id();
    peers.retain(|peer| peer.to_string() != local);
    peers
}

/// Ask the candidates one by one until a copy validates and is stored.
pub async fn fetch_and_store_graph(
    local_db: &LocalDB,
    btc_client: &BTCClient,
    goat_client: &GOATClient,
    publisher: &NetworkPublisher,
    lookup: &GraphLookup,
) -> anyhow::Result<Option<FetchedGraph>> {
    // Already present (another path stored it meanwhile).
    if let Some(found) = local_copy(local_db, lookup).await? {
        return Ok(Some(found));
    }
    let operator_pubkey = match lookup {
        GraphLookup::Slot { operator_pubkey, .. } => Some(operator_pubkey.as_str()),
        GraphLookup::Id { .. } => None,
    };
    let candidates = fetch_candidates(operator_pubkey);
    if candidates.is_empty() {
        bail!("no committee or operator peer known to ask for {lookup:?}");
    }
    let mut last_error = None;
    for peer in candidates {
        let response = match publisher.request_graph(peer, lookup.request()).await {
            Ok(response) => response,
            Err(error) => {
                warn!(event = "get_graph", outcome = "request_failed", %peer, error = %error, "GetGraph request failed");
                last_error = Some(error);
                continue;
            }
        };
        let (Some(instance_id), Some(graph_id), Some(raw)) =
            (response.instance_id, response.graph_id, response.graph)
        else {
            info!(event = "get_graph", outcome = "not_found", %peer, ?lookup, "peer has no copy");
            continue;
        };
        match validate_and_store(
            local_db,
            btc_client,
            goat_client,
            lookup,
            instance_id,
            graph_id,
            raw,
        )
        .await
        {
            Ok(found) => {
                info!(event = "get_graph", outcome = "stored", %peer, graph_id = %found.graph_id, finalized = found.finalized, "stored a pulled graph definition");
                return Ok(Some(found));
            }
            Err(error) => {
                warn!(event = "get_graph", outcome = "rejected", %peer, graph_id = %graph_id, error = %error, "rejected a pulled graph definition");
                last_error = Some(error);
            }
        }
    }
    match last_error {
        Some(error) => Err(error.context("no candidate served an acceptable definition")),
        None => Ok(None),
    }
}

async fn local_copy(
    local_db: &LocalDB,
    lookup: &GraphLookup,
) -> anyhow::Result<Option<FetchedGraph>> {
    let mut storage = local_db.acquire().await?;
    let row = match lookup {
        GraphLookup::Id { graph_id, .. } => storage.find_graph(graph_id).await?,
        GraphLookup::Slot { operator_pubkey, graph_nonce } => {
            storage.find_graph_by_operator_slot(operator_pubkey, *graph_nonce as i64).await?
        }
    };
    let Some(row) = row else { return Ok(None) };
    let Some(graph) =
        load_validated_graph_definition(&mut storage, row.instance_id, row.graph_id).await?
    else {
        return Ok(None);
    };
    let finalized = graph.committee_pre_signed();
    if matches!(lookup, GraphLookup::Id { finalized: true, .. }) && !finalized {
        // The stored copy is the operator's version; the finalized one is fetched.
        return Ok(None);
    }
    Ok(Some(FetchedGraph {
        instance_id: row.instance_id,
        graph_id: row.graph_id,
        operator_pubkey: row.operator_pubkey,
        graph_nonce: graph.parameters.graph_nonce,
        finalized,
    }))
}

#[allow(clippy::too_many_arguments)]
async fn validate_and_store(
    local_db: &LocalDB,
    btc_client: &BTCClient,
    goat_client: &GOATClient,
    lookup: &GraphLookup,
    instance_id: Uuid,
    graph_id: Uuid,
    raw: String,
) -> anyhow::Result<FetchedGraph> {
    let graph: SimplifiedBitvmGcGraph = parse_graph_raw_data(raw, graph_id).await?;
    if graph.parameters.graph_id != graph_id
        || graph.parameters.instance_parameters.instance_id != instance_id
    {
        bail!("response identifiers do not match the definition");
    }
    match lookup {
        GraphLookup::Id { instance_id: wanted_instance, graph_id: wanted_graph, finalized } => {
            if *wanted_instance != instance_id || *wanted_graph != graph_id {
                bail!("response names another graph than requested");
            }
            if *finalized && !graph.committee_pre_signed() {
                bail!("response lacks the committee pre-signatures the lookup asks for");
            }
        }
        GraphLookup::Slot { operator_pubkey, graph_nonce } => {
            if graph.parameters.operator_pubkey.to_string() != *operator_pubkey
                || graph.parameters.graph_nonce != *graph_nonce
            {
                bail!("response names another slot than requested");
            }
        }
    }
    if !graph.operator_pre_signed() {
        bail!("definition lacks operator pre-signatures");
    }
    let full_graph = BitvmGcGraph::from_simplified(&graph).context("rebuild pulled graph")?;
    verify_graph_operator_pre_signatures(&full_graph).context("operator pre-signatures")?;
    // Bind the instance parameters to both chains before trusting anything else.
    validate_graph_instance_parameters(
        btc_client,
        goat_client,
        &graph.parameters.instance_parameters,
    )
    .await
    .context("instance parameters")?;
    let posted = goat_client.gateway_get_graph_data(&graph_id).await?.operator_pubkey != [0u8; 32];
    let finalized = if graph.committee_pre_signed() {
        bitvm_lib::committee::verify_graph_committee_pre_signatures(&full_graph)
            .context("committee pre-signatures")?;
        true
    } else {
        if posted {
            bail!(
                "graph {graph_id} is posted on Goat; a copy without committee pre-signatures is not acceptable"
            );
        }
        false
    };
    if finalized {
        store_finalized_graph_if_needed(local_db, &graph).await?;
    } else {
        store_operator_presigned_graph(local_db, &graph).await?;
    }
    Ok(FetchedGraph {
        instance_id,
        graph_id,
        operator_pubkey: graph.parameters.operator_pubkey.to_string(),
        graph_nonce: graph.parameters.graph_nonce,
        finalized,
    })
}
