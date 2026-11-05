use super::tests::{make_confirmed_ack_tx, make_txid};
use super::*;

async fn settlement_deps(
    status: Option<WithdrawStatus>,
    transactions: Vec<esplora_client::Tx>,
) -> (JobDeps, tempfile::TempDir) {
    use std::sync::{Arc, Mutex};
    let dir = tempfile::tempdir().unwrap();
    let db = LocalDB::new_with_busy_timeout(
        &format!("sqlite:{}", dir.path().join("settlement.db").display()),
        false,
        store::DEFAULT_BUSY_TIMEOUT,
    )
    .await;
    db.migrate().await;
    let (btc, btc_mock) = client::btc_chain::BTCClient::new_mock_client();
    for tx in transactions {
        btc_mock.set_tx(tx.txid, tx);
    }
    let (goat, goat_mock) = client::goat_chain::GOATClient::new_mock_client();
    if let Some(status) = status {
        goat_mock.set_withdraw_data(
            *Uuid::nil().as_bytes(),
            Ok(client::goat_chain::WithdrawData {
                status,
                pegin_txid: [0; 32],
                operator_address: [0; 20],
                instance_id: [0; 16],
                lock_amount: Default::default(),
                btc_block_height_withdraw: Default::default(),
            }),
        );
    }
    let metrics_state = crate::metrics_service::MetricsState::new(Arc::new(Mutex::new(
        libp2p_metrics::Registry::default(),
    )));
    let (publisher, _receiver) = crate::middleware::publisher::channel();
    (
        JobDeps {
            actor: bitvm_lib::actors::Actor::Committee,
            relayer: true,
            local_db: db,
            btc_client: Arc::new(btc),
            goat_client: Arc::new(goat),
            http_client: Arc::new(client::http_client::async_client::HttpAsyncClient::new(None)),
            soldering_builder: None,
            metrics_state,
            publisher,
        },
        dir,
    )
}

async fn try_finish_disproved(deps: &JobDeps) -> Result<Step> {
    finish_disproved(
        deps,
        Uuid::nil(),
        make_txid(1),
        make_txid(2),
        DisproveTxType::QuickChallenge,
        0,
        make_txid(3),
    )
    .await
}

#[tokio::test]
async fn finish_disproved_all_non_disproved_states_reach_bitcoin_settlement() {
    for status in [
        WithdrawStatus::None,
        WithdrawStatus::Initialized,
        WithdrawStatus::Processing,
        WithdrawStatus::Canceled,
        WithdrawStatus::Complete,
    ] {
        let (deps, _dir) = settlement_deps(Some(status), vec![]).await;
        match try_finish_disproved(&deps).await.unwrap() {
            Step::Retry { reason, .. } => assert!(
                reason.contains("challenge finish tx") && reason.contains("not available"),
                "{reason}"
            ),
            Step::Plan(_) => {
                panic!("missing Bitcoin data must retry, not complete or abandon settlement")
            }
        }
    }
}

#[tokio::test]
async fn finish_disproved_already_applied_is_a_noop_and_non_relayer_does_not_query_goat() {
    let (deps, _dir) = settlement_deps(Some(WithdrawStatus::Disproved), vec![]).await;
    match try_finish_disproved(&deps).await.unwrap() {
        Step::Plan(plan) => assert_eq!(plan.note.as_deref(), Some("already disproved on Goat")),
        Step::Retry { .. } => panic!("already applied settlement should not retry"),
    }
    // The unconfigured mock would fail a GOAT lookup; the role gate must run first.
    let (mut deps, _dir) = settlement_deps(None, vec![]).await;
    deps.relayer = false;
    match try_finish_disproved(&deps).await.unwrap() {
        Step::Plan(plan) => assert_eq!(plan.note.as_deref(), Some("not a relayer")),
        Step::Retry { .. } => panic!("non-relayer should not schedule settlement"),
    }
}

#[tokio::test]
async fn finish_disproved_none_still_waits_for_spv_and_propagates_backend_errors() {
    let tx = make_confirmed_ack_tx(make_txid(3), make_txid(9), 0);
    let (deps, _dir) = settlement_deps(Some(WithdrawStatus::None), vec![tx]).await;
    match try_finish_disproved(&deps).await.unwrap() {
        Step::Retry { reason, .. } => {
            assert!(reason.contains("not available through GOAT SPV"), "{reason}")
        }
        Step::Plan(_) => panic!("SPV lag must not report a completed settlement"),
    }
    let (deps, _dir) = settlement_deps(None, vec![]).await;
    assert!(
        try_finish_disproved(&deps)
            .await
            .err()
            .expect("backend failure must propagate")
            .to_string()
            .contains("not find withdraw data")
    );
}

#[tokio::test]
async fn finish_disproved_none_preserves_take1_exclusion() {
    let take1 = make_confirmed_ack_tx(
        make_txid(2),
        make_txid(1),
        output_topology::kickoff::connector_a() as u32,
    );
    let (deps, _dir) = settlement_deps(Some(WithdrawStatus::None), vec![take1]).await;
    match try_finish_disproved(&deps).await.unwrap() {
        Step::Plan(plan) => assert!(plan.note.unwrap().contains("already settled by Take-1")),
        Step::Retry { .. } => panic!("Take-1 must not be settled as a disprove"),
    }
}
