use super::*;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn subgraph(replies: Vec<Value>) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        for reply in replies {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut bytes = Vec::new();
            loop {
                let mut buffer = [0; 4096];
                let count = stream.read(&mut buffer).await.unwrap();
                assert!(count > 0);
                bytes.extend_from_slice(&buffer[..count]);
                if let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                    let header = String::from_utf8_lossy(&bytes[..end]).to_lowercase();
                    let length: usize = header
                        .lines()
                        .find_map(|line| line.strip_prefix("content-length:"))
                        .unwrap()
                        .trim()
                        .parse()
                        .unwrap();
                    if bytes.len() >= end + 4 + length {
                        break;
                    }
                }
            }
            let body = reply.to_string();
            stream
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
        }
    });
    (url, task)
}

fn request(index: u128) -> Value {
    json!({"id":format!("0x{index:08x}"),"blockNumber":"12","transactionHash":"0xaa",
        "blockTimestamp":"1","instanceId":format!("0x{}",Uuid::from_u128(index+1).simple()),
        "depositorAddress":"0x01","peginAmountSats":"1000","txnFees":["1","2","3"],
        "userXonlyPubkey":"aa","userChangeAddress":"change","userRefundAddress":"refund"})
}
use uuid::Uuid;

#[tokio::test]
async fn history_window_commits_all_pages_or_keeps_its_original_cursor() {
    // Success, second-page RPC failure, late typed decode failure, Swap RPC failure.
    for case in 0..4 {
        let dir = tempfile::tempdir().unwrap();
        let db = LocalDB::new_with_busy_timeout(
            &format!("sqlite:{}", dir.path().join("pages.db").display()),
            false,
            store::DEFAULT_BUSY_TIMEOUT,
        )
        .await;
        db.migrate().await;
        let entity = if case == 3 { "claims" } else { "bridgeInRequests" };
        let first: Vec<_> = (0..100).map(request).collect();
        let last = match case {
            0 => json!({"data":{entity:[request(100)]}}),
            2 => json!({"data":{entity:[{"id":"0x00000064","blockNumber":"12"}]}}),
            _ => json!({"errors":[{"message":"second page unavailable"}]}),
        };
        let (url, server) = subgraph(vec![
            json!({"data":{"_meta":{"block":{"number":20}}}}),
            json!({"data":{entity:first}}),
            last,
        ])
        .await;
        let address = EvmAddress::from([1; 20]);
        let watch = WatchContract {
            contract_addr: address.to_string(),
            the_graph_url: url.clone(),
            gap: 10,
            from_height: 10,
            status: WatchContractStatus::Syncing.to_string(),
            updated_at: current_time_secs(),
            ..Default::default()
        };
        db.acquire().await.unwrap().upsert_watch_contract(&watch).await.unwrap();
        let config = if case == 3 {
            WatchEventConfig::Swap(SwapConfig {
                graph_config: TheGraphConfig {
                    address,
                    the_graph_url: url,
                    event_entities: vec![SwapEventEntity::Claims],
                },
                peg_btc_address: EvmAddress::from([2; 20]),
            })
        } else {
            WatchEventConfig::Gateway(TheGraphConfig {
                address,
                the_graph_url: url,
                event_entities: vec![GatewayEventEntity::BridgeInRequests],
            })
        };
        let (btc, _) = BTCClient::new_mock_client();
        let (goat, _) = GOATClient::new_mock_client();
        tokio::time::timeout(
            Duration::from_secs(5),
            fetch_history_events(
                Actor::Verifier,
                Arc::new(btc),
                Arc::new(goat),
                &db,
                &GraphQueryClient::new(),
                watch,
                config,
            ),
        )
        .await
        .unwrap()
        .unwrap();
        server.await.unwrap();
        let mut storage = db.acquire().await.unwrap();
        let stored = storage.find_watch_contract(&address.to_string()).await.unwrap().unwrap();
        let records = storage
            .get_goat_tx_record_by_processing_status("BridgeInRequest", "Pending")
            .await
            .unwrap();
        if case == 0 {
            assert_eq!(stored.from_height, 21);
            assert_eq!(stored.status, WatchContractStatus::Synced.to_string());
            assert_eq!(records.len(), 101);
        } else {
            assert_eq!(stored.from_height, 10);
            assert_eq!(stored.status, WatchContractStatus::Failed.to_string());
            assert!(records.is_empty(), "no partial page writes may commit");
        }
    }
}
