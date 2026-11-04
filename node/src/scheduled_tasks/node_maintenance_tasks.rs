use crate::p2p_admission::{OperatorKey, operator_key};
use client::goat_chain::GOATClient;
use std::str::FromStr;
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
    let mut operators = registry.registered_operators(Instant::now());
    // The local node never receives its own NodeInfo, so it is not in the registry.
    if crate::env::get_actor() == bitvm_lib::actors::Actor::Operator {
        let peer = libp2p::PeerId::from_str(&crate::env::get_peer_id())?;
        let key = crate::env::get_node_pubkey()?;
        if !operators.iter().any(|(known, _)| *known == peer) {
            operators.push((peer, operator_key(&key.inner.x_only_public_key().0)));
        }
    }
    refresh_operator_batch(
        operators,
        &BALANCE_CURSOR,
        crate::env::maintenance_item_timeout(0, 2),
        |peer, pubkey| async move {
            let Some(stored_key) = verified_row_key(local_db, &peer, &pubkey).await? else {
                return Ok(());
            };
            let address = goat_client.stake_mana_pubkey_to_address(&pubkey).await?;
            anyhow::ensure!(address != [0; 20], "operator registration no longer exists");
            let balance = goat_client.peg_btc_balance(&address).await?;
            local_db
                .acquire()
                .await?
                .update_verified_operator_balance(
                    &peer.to_string(),
                    &stored_key,
                    &balance.to_string(),
                )
                .await?;
            Ok(())
        },
    )
    .await
}

/// The node row keeps the key spelling its NodeInfo used. Return it only when it
/// names the verified binding's x-only key; `None` means no row yet.
async fn verified_row_key(
    local_db: &LocalDB,
    peer: &libp2p::PeerId,
    pubkey: &OperatorKey,
) -> anyhow::Result<Option<String>> {
    let Some(stored) = local_db.acquire().await?.get_node_btc_pub_key(&peer.to_string()).await?
    else {
        return Ok(None);
    };
    let stored_operator = bitcoin::PublicKey::from_str(&stored)
        .ok()
        .map(|key| operator_key(&key.inner.x_only_public_key().0));
    anyhow::ensure!(
        stored_operator.as_ref() == Some(pubkey),
        "node row key {stored} does not match the verified operator binding"
    );
    Ok(Some(stored))
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

    #[tokio::test]
    async fn balance_rows_match_real_key_spellings_of_the_verified_binding() {
        use bitcoin::secp256k1::{Keypair, SECP256K1, SecretKey};
        let dir = tempfile::tempdir().unwrap();
        let db = LocalDB::new_with_busy_timeout(
            &format!("sqlite:{}", dir.path().join("balance.db").display()),
            false,
            store::DEFAULT_BUSY_TIMEOUT,
        )
        .await;
        db.migrate().await;
        let keypair =
            Keypair::from_secret_key(SECP256K1, &SecretKey::from_slice(&[9; 32]).unwrap());
        let compressed = bitcoin::PublicKey::new(keypair.public_key());
        let binding = operator_key(&keypair.x_only_public_key().0);
        let mut uncompressed = compressed;
        uncompressed.compressed = false;
        let peer = PeerId::random();
        assert!(verified_row_key(&db, &peer, &binding).await.unwrap().is_none());
        for spelling in [
            compressed.to_string(),
            compressed.to_string().to_uppercase(),
            uncompressed.to_string(),
        ] {
            let row = store::Node {
                peer_id: peer.to_string(),
                btc_pub_key: spelling.clone(),
                ..Default::default()
            };
            db.acquire().await.unwrap().upsert_node(&row).await.unwrap();
            let stored = verified_row_key(&db, &peer, &binding).await.unwrap().unwrap();
            assert_eq!(stored, spelling);
            let mut storage = db.acquire().await.unwrap();
            assert!(
                storage
                    .update_verified_operator_balance(&peer.to_string(), &stored, "777")
                    .await
                    .unwrap(),
                "{spelling}"
            );
            assert_eq!(
                storage.find_nodes(&Default::default()).await.unwrap().0[0].available_peg_btc,
                "777"
            );
        }
        assert!(verified_row_key(&db, &peer, &[7; 32]).await.is_err());
    }
}
