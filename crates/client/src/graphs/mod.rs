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

    pub async fn get_sync_block_height(&self, subgraph_url: &str) -> anyhow::Result<Option<i64>> {
        let query_res = self.execute_query(subgraph_url, &get_meta_data_query()).await?;
        if query_res["_meta"]["hasIndexingErrors"].as_bool() == Some(true) {
            anyhow::bail!("subgraph reports indexing errors");
        }
        Ok(query_res["_meta"]["block"]["number"].clone().as_i64())
    }
}
