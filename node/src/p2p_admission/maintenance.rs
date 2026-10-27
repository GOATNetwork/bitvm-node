//! The admission maintenance pass: registry refreshes, drop and clock-skew
//! reports, bans that expired and stale node rows; and the persisted operator
//! bindings restored at boot.

use crate::clock::current_time_secs;
use crate::messages::{NODE_INFO_BINDING_MAX_FUTURE_SECS, NodeInfo, verify_node_info_binding};
use anyhow::Result;
use client::goat_chain::GOATClient;
use libp2p::PeerId;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use store::localdb::LocalDB;

/// A `node` row of an unregistered peer may be evicted to make room for a new
/// one once it has gone this long without a refresh: three missed heartbeats.
pub const NODE_TABLE_EVICTABLE_AFTER_SECS: i64 = 3 * crate::env::HEARTBEAT_INTERVAL_SECOND as i64;

/// Maximum unregistered node rows.
pub const NODE_TABLE_MAX_UNREGISTERED_ROWS: i64 = 4_096;

/// A `node` row of a peer that is not registered is deleted once it has not been
/// refreshed for this long; live nodes refresh theirs on every heartbeat.
const NODE_TABLE_STALE_SECS: i64 = 7 * 24 * 60 * 60;

const NODE_TABLE_PURGE_INTERVAL: Duration = Duration::from_secs(60 * 60);

/// Restore persisted operator bindings, re-verify signatures and refresh stake asynchronously.
pub async fn load_persisted_peer_bindings(
    local_db: &LocalDB,
    goat_client: &Arc<GOATClient>,
) -> Result<u64> {
    let bindings = local_db
        .acquire()
        .await?
        .load_p2p_peer_bindings(crate::p2p_admission::OPERATOR_BINDING_LOAD_LIMIT)
        .await?;
    let registry = crate::p2p_admission::peer_registry();
    let mut loaded = 0;
    let mut verified_bindings = std::collections::HashMap::new();
    for node in bindings {
        let node_info = NodeInfo {
            peer_id: node.peer_id.clone(),
            btc_pub_key: node.btc_pub_key.clone(),
            binding_sig: node.binding_sig.clone(),
            binding_issued_at: node.binding_issued_at,
            ..Default::default()
        };
        let Some(operator_key) = verify_node_info_binding(&node_info) else {
            continue;
        };
        if node.binding_issued_at > current_time_secs() + NODE_INFO_BINDING_MAX_FUTURE_SECS {
            continue;
        }
        if let Ok(peer_id) = PeerId::from_str(&node.peer_id) {
            let operator_key = crate::p2p_admission::operator_key(&operator_key);
            registry.observe_operator_binding(&peer_id, &operator_key, node.binding_issued_at);
            verified_bindings.insert(peer_id, (operator_key, node.binding_issued_at));
            loaded += 1;
        }
    }
    // Apply configured bindings only where no signed binding exists; stake still requires confirmation.
    for (peer_id, operator_key) in crate::env::get_p2p_trusted_operator_bindings() {
        match registry.trust_operator_binding(&peer_id, &operator_key) {
            Ok(()) => loaded += 1,
            Err(conflict) => tracing::warn!(
                event = "p2p_admission",
                outcome = "trusted_binding_ignored",
                peer_id = %peer_id,
                configured_key = %hex::encode(operator_key),
                conflict = ?conflict,
                env = crate::env::ENV_P2P_TRUSTED_OPERATOR_BINDINGS,
                "configured operator binding disagrees with one the operator signed; keeping \
                 the signed binding — update or remove the configured entry"
            ),
        }
    }
    // Peers confirmed on chain in an earlier session keep their class and are
    // re-validated as known members, outside the discovery budget.
    loaded += crate::p2p_admission::seed_registry_from_store(
        local_db,
        registry,
        &verified_bindings,
        Instant::now(),
    )
    .await?;
    // Everything loaded is due; the unconfirmed remainder is picked up by the
    // regular tick as lookup slots free up.
    crate::p2p_admission::refresh_due_registrations_in_background(local_db, goat_client);
    Ok(loaded)
}

/// A clock disagreement below this is not worth reporting.
const CLOCK_LEAD_REPORT_THRESHOLD: Duration = Duration::from_secs(60);

/// Warn about registered authors whose message numbering is ahead of the local clock.
fn report_clock_leads(leads: Vec<(PeerId, Duration)>) {
    let ahead: Vec<&(PeerId, Duration)> =
        leads.iter().filter(|(_, lead)| *lead >= CLOCK_LEAD_REPORT_THRESHOLD).collect();
    let max_lead = ahead.iter().map(|(_, lead)| *lead).max().unwrap_or_default();
    match ahead.as_slice() {
        [] => {}
        [(peer, lead)] => tracing::warn!(
            event = "p2p_admission",
            outcome = "author_clock_ahead",
            peer_id = %peer,
            lead_secs = lead.as_secs(),
            "a registered author's clock is ahead of this node's; past the tolerance its \
             messages are refused as coming from the future"
        ),
        several => tracing::error!(
            event = "p2p_admission",
            outcome = "local_clock_behind_suspected",
            authors = several.len(),
            max_lead_secs = max_lead.as_secs(),
            "several registered authors' clocks are ahead of this node's: check this node's \
             clock (NTP). Past the tolerance their messages are refused as coming from the future"
        ),
    }
}

/// Refresh registrations, summarize drops and purge stale node rows.
pub async fn run_p2p_admission_maintenance(local_db: &LocalDB, goat_client: &Arc<GOATClient>) {
    let now = Instant::now();
    crate::p2p_admission::refresh_due_registrations_in_background(local_db, goat_client);
    crate::p2p_admission::revalidate_committee_candidates(local_db, goat_client).await;
    crate::p2p_admission::log_drop_summary();
    // Expired bans only need forgetting: the gate compares against the clock.
    crate::p2p_admission::direct_peer_strikes().take_expired_bans(now);
    report_clock_leads(crate::p2p_admission::replay_guard().take_clock_leads());
    for (peer, rejected) in crate::p2p_admission::replay_guard().take_lockout_suspects() {
        tracing::warn!(
            event = "p2p_admission",
            outcome = "replay_lockout_suspected",
            peer_id = %peer,
            rejected,
            "a registered author keeps being refused as a replay; if it is not under \
             attack, its clock stepped back or another instance shares its key"
        );
    }

    if !crate::p2p_admission::node_table_purge_due(NODE_TABLE_PURGE_INTERVAL, now) {
        return;
    }
    let result = async {
        local_db
            .acquire()
            .await?
            .purge_stale_unregistered_nodes(
                current_time_secs() - NODE_TABLE_STALE_SECS,
                &crate::env::get_peer_id(),
            )
            .await
    }
    .await;
    match result {
        Ok(0) => {}
        Ok(purged) => tracing::info!(
            event = "p2p_admission",
            outcome = "stale_nodes_purged",
            purged,
            "removed node rows of unregistered peers that stopped announcing themselves"
        ),
        Err(error) => tracing::warn!(
            event = "p2p_admission",
            outcome = "maintenance_write_failed",
            error = %error,
            "failed to purge stale node rows; retried next tick"
        ),
    }
}
