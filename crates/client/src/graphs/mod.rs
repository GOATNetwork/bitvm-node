use crate::graphs::graph_query::get_meta_data_query;
use std::time::Duration;
use tokio::time::sleep;

const GRAPH_QUERY_RETRY_MAX_ATTEMPTS: usize = 3;
const GRAPH_QUERY_RETRY_BASE_DELAY_MS: u64 = 250;

pub mod graph_query;
#[derive(Clone)]
pub struct GraphQueryClient {
    client: reqwest::Client,
}

impl Default for GraphQueryClient {
    fn default() -> Self {
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(10))
            .pool_max_idle_per_host(0)
            .build()
            .expect("failed to create graph query client");
        Self { client }
    }
}

impl GraphQueryClient {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn execute_query(
        &self,
        subgraph_url: &str,
        query: &str,
    ) -> anyhow::Result<serde_json::Value> {
        let payload = serde_json::json!({
            "query": query
        });

        let mut last_err: Option<anyhow::Error> = None;
        for attempt in 1..=GRAPH_QUERY_RETRY_MAX_ATTEMPTS {
            let result = self
                .client
                .post(subgraph_url)
                .header(reqwest::header::CONNECTION, "close")
                .json(&payload)
                .send()
                .await;

            match result {
                Ok(resp) => {
                    let status = resp.status();
                    let body = resp.text().await.unwrap_or_else(|_| String::new());
                    if !status.is_success() {
                        let err = anyhow::format_err!(
                            "graph query failed, status: {}, body: {}",
                            status,
                            body
                        );
                        if attempt < GRAPH_QUERY_RETRY_MAX_ATTEMPTS {
                            let delay = GRAPH_QUERY_RETRY_BASE_DELAY_MS * attempt as u64;
                            sleep(Duration::from_millis(delay)).await;
                            last_err = Some(err);
                            continue;
                        }
                        return Err(err);
                    }

                    let response = serde_json::from_str::<serde_json::Value>(&body)
                        .map_err(|err| anyhow::format_err!("invalid graph json response: {err}"))?;

                    if let Some(errors) = response.get("errors") {
                        return Err(anyhow::format_err!("graph query returned errors: {errors}"));
                    }

                    return Ok(response["data"].clone());
                }
                Err(err) => {
                    let reqwest_err = anyhow::format_err!("graph request failed: {err:#}");
                    if attempt < GRAPH_QUERY_RETRY_MAX_ATTEMPTS {
                        let delay = GRAPH_QUERY_RETRY_BASE_DELAY_MS * attempt as u64;
                        sleep(Duration::from_millis(delay)).await;
                        last_err = Some(reqwest_err);
                        continue;
                    }
                    return Err(reqwest_err);
                }
            }
        }

        Err(last_err.unwrap_or_else(|| anyhow::format_err!("unknown graph query error")))
    }

    /// Fetch complete event sets before callers process or advance a block window.
    /// IDs give each entity a total order, including events in the same block.
    pub async fn get_events<E: graph_query::EventEntity>(
        &self,
        url: &str,
        entities: &[E],
        from: i64,
        to: i64,
    ) -> anyhow::Result<serde_json::Value> {
        use graph_query::{BlockRange, QueryBuilder};
        const PAGE_SIZE: usize = 100;
        anyhow::ensure!(from >= 0 && to >= from, "invalid event block range {from}..{to}");
        let mut result = serde_json::Map::new();
        for entity in entities {
            let name = entity.to_string();
            let mut cursor: Option<String> = None;
            let mut events = Vec::new();
            loop {
                let mut query = entity
                    .add_event_query(QueryBuilder::new(), BlockRange::new(from, to))
                    .set_order_by(&name, "id", "asc")
                    .set_pagination(&name, PAGE_SIZE, None);
                if let Some(after) = &cursor {
                    query = query.add_filter(&name, "id_gt", after);
                }
                let response = self.execute_query(url, &query.build()).await?;
                let page =
                    response.get(&name).and_then(|value| value.as_array()).ok_or_else(|| {
                        anyhow::anyhow!("subgraph response has no event array for {name}")
                    })?;
                anyhow::ensure!(
                    page.len() <= PAGE_SIZE,
                    "subgraph returned oversized page for {name}"
                );
                for event in page {
                    let id = event
                        .get("id")
                        .and_then(|value| value.as_str())
                        .filter(|id| !id.is_empty())
                        .ok_or_else(|| anyhow::anyhow!("invalid event ID in {name}"))?;
                    anyhow::ensure!(
                        cursor.as_ref().is_none_or(|after| id > after.as_str()),
                        "non-advancing or duplicate event ID in {name}: {id}"
                    );
                    let height = event
                        .get("blockNumber")
                        .and_then(|value| value.as_str())
                        .and_then(|height| height.parse::<i64>().ok())
                        .ok_or_else(|| {
                            anyhow::anyhow!("invalid event blockNumber in {name}: {id}")
                        })?;
                    anyhow::ensure!(
                        (from..=to).contains(&height),
                        "event outside requested range in {name}: {id}"
                    );
                    cursor = Some(id.to_string());
                    events.push((height, event.clone()));
                }
                if page.len() < PAGE_SIZE {
                    break;
                }
            }
            // Restore the original per-entity block order before existing handlers run.
            events.sort_by_key(|(height, _)| *height);
            result.insert(
                name,
                serde_json::Value::Array(events.into_iter().map(|(_, event)| event).collect()),
            );
        }
        Ok(serde_json::Value::Object(result))
    }

    pub async fn get_sync_block_height(&self, subgraph_url: &str) -> anyhow::Result<Option<i64>> {
        let query_res = self.execute_query(subgraph_url, &get_meta_data_query()).await?;
        Ok(query_res["_meta"]["block"]["number"].clone().as_i64())
    }
}

#[cfg(test)]
mod tests;
