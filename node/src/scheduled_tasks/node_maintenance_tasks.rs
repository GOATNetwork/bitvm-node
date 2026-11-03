use client::goat_chain::GOATClient;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};
use store::localdb::LocalDB;
use tracing::warn;

const BALANCE_BATCH: usize = 32;
static BALANCE_CURSOR: LazyLock<Mutex<Option<String>>> = LazyLock::new(|| Mutex::new(None));

pub(crate) async fn node_available_pbtc_update_monitor(
    local_db: &LocalDB,
    goat_client: &GOATClient,
) -> anyhow::Result<()> {
    let registry = crate::p2p_admission::peer_registry();
    let operators = registry.registered_operators(Instant::now());
    refresh_operator_batch(
        operators,
        &BALANCE_CURSOR,
        Duration::from_secs(5),
        |peer, pubkey| async move {
            let address = goat_client.stake_mana_pubkey_to_address(&pubkey).await?;
            anyhow::ensure!(address != [0; 20], "operator registration no longer exists");
            let balance = goat_client.peg_btc_balance(&address).await?;
            local_db
                .acquire()
                .await?
                .update_verified_operator_balance(
                    &peer.to_string(),
                    &hex::encode(pubkey),
                    &balance.to_string(),
                )
                .await
        },
    )
    .await
}

async fn refresh_operator_batch<F, Fut>(
    mut operators: Vec<(libp2p::PeerId, [u8; 32])>,
    cursor: &Mutex<Option<String>>,
    item_timeout: Duration,
    mut refresh: F,
) -> anyhow::Result<()>
where
    F: FnMut(libp2p::PeerId, [u8; 32]) -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<()>>,
{
    operators.sort_by_key(|(peer, _)| peer.to_string());
    let after = cursor.lock().unwrap_or_else(|e| e.into_inner()).clone();
    let start = after
        .as_ref()
        .and_then(|cursor| operators.iter().position(|(peer, _)| peer.to_string() > *cursor))
        .unwrap_or(0);
    let mut failures = 0;
    for offset in 0..operators.len().min(BALANCE_BATCH) {
        let (peer, pubkey) = operators[(start + offset) % operators.len()];
        // Advance before awaiting, so cancellation does not restart on the same slow operator.
        *cursor.lock().unwrap_or_else(|e| e.into_inner()) = Some(peer.to_string());
        let result = tokio::time::timeout(item_timeout, refresh(peer, pubkey)).await;
        if !matches!(result, Ok(Ok(()))) {
            failures += 1;
            warn!(event = "operator_balance", %peer, ?result, "operator balance refresh failed; continuing");
        }
    }
    anyhow::ensure!(failures == 0, "{failures} operator balance refreshes failed");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::PeerId;
    use std::collections::HashSet;

    #[tokio::test]
    async fn only_verified_bindings_are_visited_and_batches_rotate_after_timeout() {
        let registry = crate::p2p_admission::PeerRegistry::default();
        let now = Instant::now();
        let unverified = PeerId::random();
        registry.observe_operator_binding(&unverified, &[254; 32], 1);
        let mut expected = HashSet::new();
        for index in 0..40u8 {
            let peer = PeerId::random();
            let key = [index; 32];
            registry.observe_operator_binding(&peer, &key, 1);
            registry.record_operator_stake(&peer, &key, Some(true), now);
            expected.insert(peer);
        }
        let operators = registry.registered_operators(now);
        assert_eq!(operators.len(), 40);
        let cursor = Mutex::new(None);
        let mut visited = HashSet::new();
        assert!(
            refresh_operator_batch(
                operators.clone(),
                &cursor,
                Duration::from_millis(1),
                |peer, _| {
                    visited.insert(peer);
                    std::future::pending::<anyhow::Result<()>>()
                }
            )
            .await
            .is_err()
        );
        assert_eq!(visited.len(), BALANCE_BATCH);
        refresh_operator_batch(operators, &cursor, Duration::from_millis(1), |peer, _| {
            visited.insert(peer);
            std::future::ready(Ok(()))
        })
        .await
        .unwrap();
        assert_eq!(visited, expected);
        assert!(!visited.contains(&unverified));
    }

    #[tokio::test]
    async fn cancellation_advances_balance_cursor_before_slow_item() {
        let mut operators: Vec<_> = (0..3).map(|i| (PeerId::random(), [i; 32])).collect();
        operators.sort_by_key(|(peer, _)| peer.to_string());
        let cursor = Mutex::new(None);
        let result = tokio::time::timeout(
            Duration::from_millis(5),
            refresh_operator_batch(operators.clone(), &cursor, Duration::from_secs(60), |_, _| {
                std::future::pending::<anyhow::Result<()>>()
            }),
        )
        .await;
        assert!(result.is_err());
        assert_eq!(*cursor.lock().unwrap(), Some(operators[0].0.to_string()));
        let mut first = None;
        refresh_operator_batch(operators.clone(), &cursor, Duration::from_secs(1), |peer, _| {
            first.get_or_insert(peer);
            std::future::ready(Ok(()))
        })
        .await
        .unwrap();
        assert_eq!(first, Some(operators[1].0));
    }
}
