use super::*;
use graph_query::{
    BlockRange, EventEntity, GatewayEventEntity as G, QueryBuilder, SwapEventEntity as S,
};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn server(
    pages: Vec<(&'static str, Option<String>, Value)>,
) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        for (entity, after, response) in pages {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut bytes = Vec::new();
            let (header_end, content_len) = loop {
                let mut buffer = [0; 4096];
                let read = stream.read(&mut buffer).await.unwrap();
                assert!(read > 0);
                bytes.extend_from_slice(&buffer[..read]);
                if let Some(index) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                    let headers = String::from_utf8_lossy(&bytes[..index]).to_lowercase();
                    let len: usize = headers
                        .lines()
                        .find_map(|line| line.strip_prefix("content-length:"))
                        .unwrap()
                        .trim()
                        .parse()
                        .unwrap();
                    break (index + 4, len);
                }
            };
            while bytes.len() < header_end + content_len {
                let mut buffer = [0; 4096];
                let read = stream.read(&mut buffer).await.unwrap();
                assert!(read > 0);
                bytes.extend_from_slice(&buffer[..read]);
            }
            let request: Value =
                serde_json::from_slice(&bytes[header_end..header_end + content_len]).unwrap();
            let query = request["query"].as_str().unwrap();
            assert!(query.contains(&format!("{entity}(")), "{query}");
            for expected in [
                "first: 100",
                "orderBy: id",
                "orderDirection: asc",
                "blockNumber_gte: \"10\"",
                "blockNumber_lte: \"20\"",
            ] {
                assert!(query.contains(expected), "{query}");
            }
            if let Some(after) = after {
                assert!(query.contains(&format!("id_gt: {}", json!(after))), "{query}");
            } else {
                assert!(!query.contains("id_gt:"));
            }
            let body = response.to_string();
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
fn events(start: usize, count: usize) -> Vec<Value> {
    (start..start + count)
        .map(|i| json!({"id":format!("0x{i:08x}"),"blockNumber":if i%2 == 0 {"11"} else {"10"}}))
        .collect()
}
fn page(entity: &str, rows: Vec<Value>) -> Value {
    json!({"data":{entity:rows}})
}
fn id(i: usize) -> Option<String> {
    Some(format!("0x{i:08x}"))
}

#[tokio::test]
async fn gateway_entities_have_independent_cursors_and_restore_block_order() {
    let (url, task) = server(vec![
        ("bridgeInRequests", None, page("bridgeInRequests", events(0, 100))),
        ("bridgeInRequests", id(99), page("bridgeInRequests", events(100, 100))),
        ("bridgeInRequests", id(199), page("bridgeInRequests", events(200, 1))),
        ("initWithdraws", None, page("initWithdraws", events(0, 2))),
    ])
    .await;
    let result = GraphQueryClient::new()
        .get_events(&url, &[G::BridgeInRequests, G::InitWithdraws], 10, 20)
        .await
        .unwrap();
    task.await.unwrap();
    let rows = result["bridgeInRequests"].as_array().unwrap();
    assert_eq!(rows.len(), 201);
    assert_eq!(result["initWithdraws"].as_array().unwrap().len(), 2);
    assert!(rows.windows(2).all(|w|w[0]["blockNumber"].as_str().unwrap() <= w[1]["blockNumber"].as_str().unwrap()));
    let ids: std::collections::HashSet<_> =
        rows.iter().map(|row| row["id"].as_str().unwrap()).collect();
    assert_eq!(ids.len(), 201);
}

#[tokio::test]
async fn exact_full_swap_page_requires_an_empty_final_page() {
    let (url, task) = server(vec![
        ("initializes", None, page("initializes", vec![])),
        ("claims", None, page("claims", events(0, 100))),
        ("claims", id(99), page("claims", vec![])),
        ("refunds", None, page("refunds", events(0, 1))),
    ])
    .await;
    let result = GraphQueryClient::new()
        .get_events(&url, &[S::Initializes, S::Claims, S::Refunds], 10, 20)
        .await
        .unwrap();
    task.await.unwrap();
    assert_eq!(result["claims"].as_array().unwrap().len(), 100);
    assert_eq!(result["refunds"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn failed_or_non_advancing_later_pages_never_return_partial_events() {
    for response in [
        json!({"errors":[{"message":"indexer unavailable"}]}),
        page("bridgeInRequests", events(99, 1)),
        json!({"data":{}}),
        json!({"data":{"bridgeInRequests":null}}),
    ] {
        let (url, task) = server(vec![
            ("bridgeInRequests", None, page("bridgeInRequests", events(0, 100))),
            ("bridgeInRequests", id(99), response),
        ])
        .await;
        assert!(
            GraphQueryClient::new().get_events(&url, &[G::BridgeInRequests], 10, 20).await.is_err()
        );
        task.await.unwrap();
    }
}

#[tokio::test]
async fn malformed_rows_and_duplicate_ids_are_errors_not_empty_pages() {
    for rows in [
        vec![json!({"blockNumber":"10"})],
        vec![json!({"id":"","blockNumber":"10"})],
        vec![json!({"id":"1","blockNumber":"invalid"})],
        vec![json!({"id":"1","blockNumber":"21"})],
        vec![json!({"id":"1","blockNumber":"10"}), json!({"id":"1","blockNumber":"10"})],
        events(0, 101),
    ] {
        let (url, task) = server(vec![("claims", None, page("claims", rows))]).await;
        assert!(GraphQueryClient::new().get_events(&url, &[S::Claims], 10, 20).await.is_err());
        task.await.unwrap();
    }
}

#[test]
fn every_event_entity_supports_a_total_order_and_escaped_cursor() {
    fn check<E: EventEntity>(entities: &[E]) {
        for entity in entities {
            let name = entity.to_string();
            let cursor = "quote\"\nslash\\";
            let query = entity
                .add_event_query(QueryBuilder::new(), BlockRange::new(10, 20))
                .set_order_by(&name, "id", "asc")
                .set_pagination(&name, 100, None)
                .add_filter(&name, "id_gt", cursor)
                .build();
            assert!(query.contains(&format!("id_gt: {}", json!(cursor))));
            assert!(query.contains("first: 100"));
            assert!(query.contains("blockNumber_gte:"));
            assert!(query.contains("id "));
        }
    }
    check(&[
        G::InitWithdraws,
        G::CancelWithdraws,
        G::ProceedWithdraws,
        G::WithdrawHappyPaths,
        G::WithdrawUnhappyPaths,
        G::WithdrawDisproveds,
        G::BridgeInRequests,
        G::CommitteeResponses,
        G::BridgeIns,
        G::PostGraphDatas,
    ]);
    check(&[S::Initializes, S::Claims, S::Refunds]);
}
