use crate::timeout_config::{DEFAULT_HTTP_CONNECT_TIMEOUT_SECS, get_http_request_timeout_secs};
use anyhow::anyhow;
use esplora_client::Error;
use reqwest::{Client, Response};
use std::time::Duration;

const DEFAULT_MAX_RETRIES: usize = 6;
const BASE_BACKOFF_MILLIS: Duration = Duration::from_millis(256);
const RETRYABLE_ERROR_CODES: [u16; 5] = [
    429, // TOO_MANY_REQUESTS
    500, // INTERNAL_SERVER_ERROR
    502, // BAD_GATEWAY (a proxy in front of the upstream)
    503, // SERVICE_UNAVAILABLE
    504, // GATEWAY_TIMEOUT
];

pub struct HttpAsyncClient {
    client: Client,
    max_retries: usize,
}

impl HttpAsyncClient {
    /// A client with a connect timeout and a whole-request timeout
    /// (`HTTP_REQUEST_TIMEOUT_SECS`), so a hung upstream fails the call instead
    /// of parking the caller forever.
    pub fn new(max_retries: Option<usize>) -> Self {
        let client = Client::builder()
            .connect_timeout(Duration::from_secs(DEFAULT_HTTP_CONNECT_TIMEOUT_SECS))
            .timeout(Duration::from_secs(get_http_request_timeout_secs()))
            .build()
            .unwrap_or_else(|err| {
                tracing::warn!(
                    "failed to build the HTTP client with timeouts: {err}; using the default client"
                );
                Client::new()
            });
        Self { client, max_retries: max_retries.unwrap_or(DEFAULT_MAX_RETRIES) }
    }

    pub async fn get_response_json<T: serde::de::DeserializeOwned>(
        &self,
        url: &str,
    ) -> anyhow::Result<T> {
        let response = self.get_with_retry(url).await?;
        if !response.status().is_success() {
            let status = response.status().as_u16();
            let message = response.text().await?;
            return Err(Error::HttpResponse { status, message }.into());
        }

        response.json::<T>().await.map_err(|e| anyhow!("failed to deserialize response:{e}"))
    }

    pub async fn get_opt_response_json<T: serde::de::DeserializeOwned>(
        &self,
        url: &str,
    ) -> anyhow::Result<Option<T>> {
        match self.get_response_json(url).await {
            Ok(res) => Ok(Some(res)),
            Err(e) => {
                if let Some(esplora_err) = e.downcast_ref::<Error>()
                    && let Error::HttpResponse { status: 404, .. } = esplora_err
                {
                    return Ok(None);
                }
                Err(e)
            }
        }
    }

    pub async fn post_response_json<T: serde::de::DeserializeOwned, B: serde::Serialize>(
        &self,
        url: &str,
        body: &B,
    ) -> anyhow::Result<T> {
        let response = self.post_with_retry(url, body).await?;
        if !response.status().is_success() {
            let status = response.status().as_u16();
            let message = response.text().await?;
            return Err(Error::HttpResponse { status, message }.into());
        }

        response.json::<T>().await.map_err(|e| anyhow!("failed to deserialize response:{e}"))
    }

    /// Posts JSON while rebuilding caller-supplied headers for every retry attempt.
    pub async fn post_response_json_with_dynamic_headers<
        T: serde::de::DeserializeOwned,
        B: serde::Serialize,
        F: Fn() -> anyhow::Result<Vec<(String, String)>>,
    >(
        &self,
        url: &str,
        body: &B,
        header_factory: F,
    ) -> anyhow::Result<T> {
        let response = self.post_with_retry_and_dynamic_headers(url, body, &header_factory).await?;
        if !response.status().is_success() {
            let status = response.status().as_u16();
            let message = response.text().await?;
            return Err(Error::HttpResponse { status, message }.into());
        }

        response.json::<T>().await.map_err(|e| anyhow!("failed to deserialize response:{e}"))
    }

    pub async fn post_opt_response_json<T: serde::de::DeserializeOwned, B: serde::Serialize>(
        &self,
        url: &str,
        body: &B,
    ) -> anyhow::Result<Option<T>> {
        match self.post_response_json(url, body).await {
            Ok(res) => Ok(Some(res)),
            Err(e) => {
                if let Some(esplora_err) = e.downcast_ref::<Error>()
                    && let Error::HttpResponse { status: 404, .. } = esplora_err
                {
                    return Ok(None);
                }
                Err(e)
            }
        }
    }

    async fn get_with_retry(&self, url: &str) -> anyhow::Result<Response> {
        let mut delay = BASE_BACKOFF_MILLIS;
        let mut attempts = 0;

        loop {
            match self.client.get(url).send().await? {
                resp if attempts < self.max_retries
                    && RETRYABLE_ERROR_CODES.contains(&resp.status().as_u16()) =>
                {
                    tokio::time::sleep(delay).await;
                    attempts += 1;
                    delay *= 2;
                }
                resp => return Ok(resp),
            }
        }
    }

    async fn post_with_retry<B: serde::Serialize>(
        &self,
        url: &str,
        body: &B,
    ) -> anyhow::Result<Response> {
        let mut delay = BASE_BACKOFF_MILLIS;
        let mut attempts = 0;

        loop {
            match self.client.post(url).json(body).send().await? {
                resp if attempts < self.max_retries
                    && RETRYABLE_ERROR_CODES.contains(&resp.status().as_u16()) =>
                {
                    tokio::time::sleep(delay).await;
                    attempts += 1;
                    delay *= 2;
                }
                resp => return Ok(resp),
            }
        }
    }

    /// Sends one JSON request and regenerates dynamic headers before each retry.
    async fn post_with_retry_and_dynamic_headers<
        B: serde::Serialize,
        F: Fn() -> anyhow::Result<Vec<(String, String)>>,
    >(
        &self,
        url: &str,
        body: &B,
        header_factory: &F,
    ) -> anyhow::Result<Response> {
        let mut delay = BASE_BACKOFF_MILLIS;
        let mut attempts = 0;

        loop {
            let mut request = self.client.post(url).json(body);
            for (name, value) in header_factory()? {
                request = request.header(name, value);
            }
            match request.send().await? {
                resp if attempts < self.max_retries
                    && RETRYABLE_ERROR_CODES.contains(&resp.status().as_u16()) =>
                {
                    tokio::time::sleep(delay).await;
                    attempts += 1;
                    delay *= 2;
                }
                resp => return Ok(resp),
            }
        }
    }
}
