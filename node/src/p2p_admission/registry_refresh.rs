//! Background lookups that fill and refresh the peer registry from Goat and
//! the node table.

use anyhow::Result;
use client::goat_chain::GOATClient;
use libp2p::PeerId;
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use store::localdb::LocalDB;

use super::registry::{OperatorKey, PeerRegistry, REGISTRY_RPC_TIMEOUT, peer_registry};
use super::strikes::take_refused_peers;

/// Persisted registration kinds.
pub(super) const REGISTERED_KIND_COMMITTEE: &str = "Committee";
pub(super) const REGISTERED_KIND_OPERATOR: &str = "Operator";

/// Persist a change in a peer's confirmed registration. Best effort: the cache
/// stays authoritative for this session, the table only warms the next one.
async fn persist_registration_change(
    local_db: &LocalDB,
    peer: &PeerId,
    kind: &str,
    pubkey: Option<&OperatorKey>,
    change: Option<bool>,
) {
    let Some(registered) = change else {
        return;
    };
    let peer_id = peer.to_string();
    let pubkey = pubkey.map(hex::encode).unwrap_or_default();
    let result = async {
        let mut storage = local_db.acquire().await?;
        if registered {
            storage.upsert_p2p_registered_peer(&peer_id, kind, &pubkey).await
        } else {
            storage.delete_p2p_registered_peer(&peer_id, kind).await
        }
    }
    .await;
    if let Err(error) = result {
        tracing::debug!(
            event = "p2p_admission",
            outcome = "registration_persist_failed",
            peer_id = %peer_id,
            kind,
            error = %error,
            "failed to persist a confirmed registration; it will be rediscovered after a restart"
        );
    }
}

/// Revoke persisted operator registration after a key change.
pub async fn revoke_persisted_operator(local_db: &LocalDB, peer: &PeerId) {
    persist_registration_change(local_db, peer, REGISTERED_KIND_OPERATOR, None, Some(false)).await;
}

/// Restore confirmed peers; operator bindings must be signature-checked and match stored keys.
pub async fn seed_registry_from_store(
    local_db: &LocalDB,
    registry: &PeerRegistry,
    operator_bindings: &HashMap<PeerId, (OperatorKey, i64)>,
    now: Instant,
) -> Result<u64> {
    let persisted = local_db.acquire().await?.load_p2p_registered_peers().await?;
    let mut seeded = 0;
    for (peer_id, kind, confirmed_pubkey) in persisted {
        let Ok(peer) = PeerId::from_str(&peer_id) else {
            continue;
        };
        match kind.as_str() {
            REGISTERED_KIND_COMMITTEE => {
                registry.seed_verified_committee_peer(&peer, now);
                seeded += 1;
            }
            REGISTERED_KIND_OPERATOR => {
                if let Some((pubkey, issued_at)) = operator_bindings.get(&peer)
                    && hex::encode(pubkey) == confirmed_pubkey
                {
                    registry.seed_verified_operator(&peer, pubkey, *issued_at, now);
                    seeded += 1;
                }
            }
            _ => {}
        }
    }
    Ok(seeded)
}

fn spawn_committee_lookup(local_db: &LocalDB, goat_client: &Arc<GOATClient>, peer: PeerId) {
    let registry = peer_registry();
    let (local_db, goat_client) = (local_db.clone(), goat_client.clone());
    tokio::spawn(async move {
        let registered = match tokio::time::timeout(
            REGISTRY_RPC_TIMEOUT,
            goat_client.committee_mana_is_validate_peer_id(&peer.to_bytes()),
        )
        .await
        {
            Ok(Ok(registered)) => Some(registered),
            Ok(Err(error)) => {
                tracing::debug!(
                    event = "p2p_admission",
                    outcome = "committee_lookup_failed",
                    peer_id = %peer,
                    error = %error,
                    "failed to look up a peer in the committee registry"
                );
                None
            }
            Err(_) => None,
        };
        let change = registry.record_committee_peer(&peer, registered, Instant::now());
        persist_registration_change(&local_db, &peer, REGISTERED_KIND_COMMITTEE, None, change)
            .await;
    });
}

fn spawn_operator_stake_lookup(
    local_db: &LocalDB,
    goat_client: &Arc<GOATClient>,
    peer: PeerId,
    operator_key: OperatorKey,
) {
    use crate::utils::OperatorStakeStatus;

    let registry = peer_registry();
    // The stake is registered under the x-only key; the parity chosen here is
    // dropped again by the lookup.
    let Ok(xonly) = bitcoin::XOnlyPublicKey::from_slice(&operator_key) else {
        registry.record_operator_stake(&peer, &operator_key, Some(false), Instant::now());
        return;
    };
    let pubkey = bitcoin::PublicKey::new(xonly.public_key(bitcoin::secp256k1::Parity::Even));
    let (local_db, goat_client) = (local_db.clone(), goat_client.clone());
    tokio::spawn(async move {
        let staked = match tokio::time::timeout(
            REGISTRY_RPC_TIMEOUT,
            crate::utils::operator_stake_status(&goat_client, &pubkey),
        )
        .await
        {
            Ok(Ok(OperatorStakeStatus::Staked)) => Some(true),
            Ok(Ok(
                OperatorStakeStatus::NotRegistered | OperatorStakeStatus::Insufficient { .. },
            )) => Some(false),
            // Preserve the cached stake verdict on RPC failure.
            Ok(Err(error)) => {
                tracing::debug!(
                    event = "p2p_admission",
                    outcome = "operator_stake_lookup_failed",
                    peer_id = %peer,
                    error = %error,
                    "failed to confirm operator stake; leaving the binding unverified"
                );
                None
            }
            Err(_) => None,
        };
        let change = registry.record_operator_stake(&peer, &operator_key, staked, Instant::now());
        persist_registration_change(
            &local_db,
            &peer,
            REGISTERED_KIND_OPERATOR,
            Some(&operator_key),
            change,
        )
        .await;
    });
}

/// Look up a peer this node is connected to; see
/// [`PeerRegistry::plan_neighbour_lookup`].
pub fn refresh_neighbour_in_background(
    local_db: &LocalDB,
    goat_client: &Arc<GOATClient>,
    peer: PeerId,
) {
    if peer_registry().plan_neighbour_lookup(&peer, Instant::now()) {
        spawn_committee_lookup(local_db, goat_client, peer);
    }
}

/// Schedule due verifier-set and candidate committee lookups without waiting.
/// Durable messages do not trigger these lookups.
pub fn refresh_registry_in_background(
    local_db: &LocalDB,
    goat_client: &Arc<GOATClient>,
    peer: Option<PeerId>,
) {
    let registry = peer_registry();
    let plan = registry.plan_refresh(peer.as_ref(), Instant::now());
    if plan.verifier_set {
        let goat_client = goat_client.clone();
        tokio::spawn(async move {
            let fetched = match tokio::time::timeout(
                REGISTRY_RPC_TIMEOUT,
                goat_client.committee_mana_get_verifiers(),
            )
            .await
            {
                Ok(Ok(verifiers)) => Some(verifiers),
                Ok(Err(error)) => {
                    tracing::warn!(
                        event = "p2p_admission",
                        outcome = "verifier_set_refresh_failed",
                        error = %error,
                        "failed to refresh the registered verifier set; keeping the previous one"
                    );
                    None
                }
                Err(_) => {
                    tracing::warn!(
                        event = "p2p_admission",
                        outcome = "verifier_set_refresh_timeout",
                        "timed out refreshing the registered verifier set; keeping the previous one"
                    );
                    None
                }
            };
            registry.record_verifier_set(fetched, Instant::now());
        });
    }
    if let Some(peer) = peer.filter(|_| plan.committee_peer) {
        spawn_committee_lookup(local_db, goat_client, peer);
    }
}

/// Schedule refreshes for known registrations that are due.
pub fn refresh_due_registrations_in_background(local_db: &LocalDB, goat_client: &Arc<GOATClient>) {
    let registry = peer_registry();
    let now = Instant::now();
    refresh_registry_in_background(local_db, goat_client, None);
    for peer in registry.plan_due_committee_refreshes(now) {
        spawn_committee_lookup(local_db, goat_client, peer);
    }
    for peer in take_refused_peers() {
        if registry.plan_refused_peer_lookup(&peer, now) {
            spawn_committee_lookup(local_db, goat_client, peer);
        }
    }
    for (peer, operator_key) in registry.plan_due_operator_refreshes(now) {
        spawn_operator_stake_lookup(local_db, goat_client, peer, operator_key);
    }
}

/// Committee candidates the node table holds (self-declared by NodeInfo)
/// that the registry does not know as registered: looked up within the
/// candidate budget, so a member whose NodeInfo arrived while the budget was
/// spent, or before a restart, is classified by the maintenance tick instead
/// of by its first message.
const COMMITTEE_CANDIDATES_PER_TICK: u32 = 64;
const COMMITTEE_CANDIDATE_SCAN_INTERVAL: Duration = Duration::from_secs(60);
static COMMITTEE_CANDIDATES_SCANNED_AT: Mutex<Option<Instant>> = Mutex::new(None);

fn committee_candidate_scan_due(now: Instant) -> bool {
    let mut scanned_at =
        COMMITTEE_CANDIDATES_SCANNED_AT.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    if scanned_at
        .is_some_and(|at| now.saturating_duration_since(at) < COMMITTEE_CANDIDATE_SCAN_INTERVAL)
    {
        return false;
    }
    *scanned_at = Some(now);
    true
}

/// Look up the self-declared committee peers the registry has never
/// classified. Peers with a verdict, registered or not, are refreshed by their
/// own messages; the scan only covers announcements that arrived while the
/// discovery budget was spent or before a restart.
pub async fn revalidate_committee_candidates(local_db: &LocalDB, goat_client: &Arc<GOATClient>) {
    let registry = peer_registry();
    let now = Instant::now();
    if !committee_candidate_scan_due(now) {
        return;
    }
    let candidates = match local_db.acquire().await {
        Ok(mut storage) => {
            storage
                .find_nodes(
                    &store::localdb::NodeQuery::default()
                        .with_actor(bitvm_lib::actors::Actor::Committee.to_string())
                        .with_order("updated_at DESC".to_string())
                        .with_limit(COMMITTEE_CANDIDATES_PER_TICK),
                )
                .await
        }
        Err(error) => Err(error),
    };
    let candidates = match candidates {
        Ok((nodes, _)) => nodes,
        Err(error) => {
            tracing::debug!(event = "p2p_admission", outcome = "candidate_scan_failed", error = %error, "could not read committee candidates");
            return;
        }
    };
    for node in candidates {
        let Ok(peer) = PeerId::from_str(&node.peer_id) else { continue };
        if !registry.is_unclassified(&peer) {
            continue;
        }
        if registry.plan_candidate_lookup(&peer, now) {
            spawn_committee_lookup(local_db, goat_client, peer);
        }
    }
}

/// Confirm, off the event loop, that a proven operator binding belongs to a
/// sufficiently staked operator, and cache the verdict for classification.
pub fn refresh_operator_binding_in_background(
    local_db: &LocalDB,
    goat_client: &Arc<GOATClient>,
    peer: PeerId,
    operator_key: OperatorKey,
) {
    if !peer_registry().plan_operator_refresh(&peer, &operator_key, Instant::now()) {
        return;
    }
    spawn_operator_stake_lookup(local_db, goat_client, peer, operator_key);
}
