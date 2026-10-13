//! Direct request-response protocol for fetching a graph definition.
//!
//! Responses use the request's stream and authenticated peer connection.
//! Definition validation is handled by the requester.

use async_trait::async_trait;
use futures::prelude::*;
use libp2p::request_response::{self, ProtocolSupport};
use libp2p::swarm::StreamProtocol;
use serde::{Deserialize, Serialize};
use std::io;
use std::time::Duration;
use uuid::Uuid;

pub type GetGraphBehaviour = request_response::Behaviour<GetGraphCodec>;

/// JSON on the stream, with limits large enough for a full graph definition.
#[derive(Clone, Debug, Default)]
pub struct GetGraphCodec;

#[async_trait]
impl request_response::Codec for GetGraphCodec {
    type Protocol = StreamProtocol;
    type Request = GetGraphRequest;
    type Response = GetGraphResponse;

    async fn read_request<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<GetGraphRequest>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut bytes = Vec::new();
        io.take(MAX_REQUEST_BYTES).read_to_end(&mut bytes).await?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    async fn read_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<GetGraphResponse>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut bytes = Vec::new();
        io.take(MAX_RESPONSE_BYTES).read_to_end(&mut bytes).await?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    async fn write_request<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        request: GetGraphRequest,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        io.write_all(&serde_json::to_vec(&request)?).await?;
        io.close().await
    }

    async fn write_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        response: GetGraphResponse,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        io.write_all(&serde_json::to_vec(&response)?).await?;
        io.close().await
    }
}

/// A definition is addressed by graph id or by operator slot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GetGraphRequest {
    pub instance_id: Option<Uuid>,
    pub graph_id: Option<Uuid>,
    pub operator_pubkey: Option<String>,
    pub graph_nonce: Option<u64>,
}

impl GetGraphRequest {
    pub fn by_id(instance_id: Uuid, graph_id: Uuid) -> Self {
        Self {
            instance_id: Some(instance_id),
            graph_id: Some(graph_id),
            operator_pubkey: None,
            graph_nonce: None,
        }
    }

    pub fn by_slot(operator_pubkey: String, graph_nonce: u64) -> Self {
        Self {
            instance_id: None,
            graph_id: None,
            operator_pubkey: Some(operator_pubkey),
            graph_nonce: Some(graph_nonce),
        }
    }
}

/// The stored raw definition (simplified graph JSON) when the peer has it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GetGraphResponse {
    pub instance_id: Option<Uuid>,
    pub graph_id: Option<Uuid>,
    pub graph: Option<String>,
}

impl GetGraphResponse {
    pub fn not_found() -> Self {
        Self::default()
    }

    pub fn found(instance_id: Uuid, graph_id: Uuid, graph: String) -> Self {
        Self { instance_id: Some(instance_id), graph_id: Some(graph_id), graph: Some(graph) }
    }
}

pub const GET_GRAPH_REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_REQUEST_BYTES: u64 = 64 * 1024;
const MAX_RESPONSE_BYTES: u64 = 64 * 1024 * 1024;

pub fn get_graph_protocol() -> StreamProtocol {
    let protocol = crate::env::get_proto_base();
    StreamProtocol::try_from_owned(format!("/{protocol}/get-graph/1"))
        .expect("valid get-graph protocol name")
}

/// Open `GetGraph` streams per connection. Each may hold one serialized
/// definition until the peer reads it, so this is a memory bound against a
/// peer that requests and never reads.
pub const GET_GRAPH_MAX_CONCURRENT_STREAMS: usize = 4;

pub fn new_get_graph_behaviour() -> GetGraphBehaviour {
    request_response::Behaviour::with_codec(
        GetGraphCodec,
        [(get_graph_protocol(), ProtocolSupport::Full)],
        request_response::Config::default()
            .with_request_timeout(GET_GRAPH_REQUEST_TIMEOUT)
            .with_max_concurrent_streams(GET_GRAPH_MAX_CONCURRENT_STREAMS),
    )
}
