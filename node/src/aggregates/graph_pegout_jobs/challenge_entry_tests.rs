use super::tests::{make_confirmed_ack_tx, make_txid};
use super::*;

#[tokio::test]
async fn kickoff_challenge_does_not_wait_for_spv_and_preserves_other_gates() {
    use bitcoin::OutPoint;
    use bitvm_lib::actors::Actor;
    use client::goat_chain::{GOATClient, WithdrawData};
    use client::http_client::async_client::HttpAsyncClient;
    use std::sync::{Arc, Mutex};

    let dir = tempfile::tempdir().unwrap();
    let db = LocalDB::new_with_busy_timeout(
        &format!("sqlite:{}", dir.path().join("challenge.db").display()),
        false,
        store::DEFAULT_BUSY_TIMEOUT,
    )
    .await;
    let (btc, btc_mock) = client::btc_chain::BTCClient::new_mock_client();
    let (goat, goat_mock) = GOATClient::new_mock_client();
    let deps = JobDeps {
        actor: Actor::Verifier,
        relayer: false,
        local_db: db,
        btc_client: Arc::new(btc),
        goat_client: Arc::new(goat),
        http_client: Arc::new(HttpAsyncClient::new(Some(0))),
        soldering_builder: None,
        metrics_state: crate::metrics_service::MetricsState::new(Arc::new(Mutex::new(
            libp2p_metrics::Registry::default(),
        ))),
        publisher: crate::middleware::publisher::channel().0,
    };
    let graph_id = Uuid::new_v4();
    let kickoff = make_txid(10);
    let take1 = make_txid(11);
    let connector = OutPoint { txid: kickoff, vout: 0 };
    let mut kickoff_tx = make_confirmed_ack_tx(kickoff, make_txid(99), 0);
    btc_mock.set_tx(kickoff, kickoff_tx.clone());
    let preflight = || kickoff_challenge_preflight(&deps, graph_id, kickoff, take1, connector);
    for spv in [Ok(0), Err("SPV unavailable".to_string())] {
        let unavailable = spv.is_err();
        goat_mock.set_spv_height(spv);
        // L2 settlement still waits for SPV or propagates its backend error.
        let settlement = spv_covered(&deps, &kickoff, "kickoff").await;
        if unavailable {
            assert!(settlement.is_err());
        } else {
            assert!(matches!(settlement.unwrap(), Some(Step::Retry { .. })));
        }
        for status in [
            WithdrawStatus::None,
            WithdrawStatus::Canceled,
            WithdrawStatus::Initialized,
            WithdrawStatus::Processing,
            WithdrawStatus::Complete,
            WithdrawStatus::Disproved,
        ] {
            goat_mock.set_withdraw_data(
                *graph_id.as_bytes(),
                Ok(WithdrawData {
                    status: status.clone(),
                    pegin_txid: [0; 32],
                    operator_address: [0; 20],
                    instance_id: [0; 16],
                    lock_amount: alloy::primitives::U256::ZERO,
                    btc_block_height_withdraw: alloy::primitives::U256::ZERO,
                }),
            );
            let result = preflight().await.unwrap();
            match status {
                WithdrawStatus::None | WithdrawStatus::Canceled => assert!(result.is_none()),
                WithdrawStatus::Initialized => {
                    assert!(matches!(result, Some(Step::Retry { .. })))
                }
                _ => assert!(matches!(result, Some(Step::Plan(_)))),
            }
        }
    }
    // An unconfirmed kickoff or pending connector spend must still wait.
    kickoff_tx.status.confirmed = false;
    btc_mock.set_tx(kickoff, kickoff_tx.clone());
    assert!(matches!(preflight().await.unwrap(), Some(Step::Retry { .. })));
    kickoff_tx.status.confirmed = true;
    btc_mock.set_tx(kickoff, kickoff_tx);
    let mut spender = make_confirmed_ack_tx(take1, kickoff, 0);
    spender.status.confirmed = false;
    btc_mock.set_tx(take1, spender.clone());
    btc_mock.set_output_status(
        kickoff,
        0,
        esplora_client::OutputStatus { spent: true, txid: Some(take1), vin: Some(0), status: None },
    );
    assert!(matches!(preflight().await.unwrap(), Some(Step::Retry { .. })));
    spender.status.confirmed = true;
    btc_mock.set_tx(take1, spender);
    assert!(matches!(preflight().await.unwrap(), Some(Step::Plan(_))));
}
