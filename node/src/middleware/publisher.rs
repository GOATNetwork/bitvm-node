//! Bounded, acknowledged access to the swarm from tasks that do not own it:
//! gossip publishes and direct `GetGraph` requests.
use futures::future::BoxFuture;
use libp2p::request_response::{OutboundRequestId, ResponseChannel};
use libp2p::{
    PeerId, Swarm,
    gossipsub::{IdentTopic, MessageId},
};
use std::collections::HashMap;
use tokio::sync::{mpsc, oneshot};

use super::AllBehaviours;
use super::get_graph::{GET_GRAPH_REQUEST_TIMEOUT, GetGraphRequest, GetGraphResponse};

pub trait MessagePublisher: Send {
    fn publish_message(
        &mut self,
        topic: IdentTopic,
        data: Vec<u8>,
    ) -> BoxFuture<'_, anyhow::Result<MessageId>>;
}

impl MessagePublisher for Swarm<AllBehaviours> {
    fn publish_message(
        &mut self,
        topic: IdentTopic,
        data: Vec<u8>,
    ) -> BoxFuture<'_, anyhow::Result<MessageId>> {
        Box::pin(
            async move { self.behaviour_mut().gossipsub.publish(topic, data).map_err(Into::into) },
        )
    }
}

impl MessagePublisher for super::swarm::BitvmSwarmWrapper {
    fn publish_message(
        &mut self,
        topic: IdentTopic,
        data: Vec<u8>,
    ) -> BoxFuture<'_, anyhow::Result<MessageId>> {
        self.0.publish_message(topic, data)
    }
}

/// Replies the swarm loop still owes to `GetGraph` requesters.
pub type PendingGraphRequests =
    HashMap<OutboundRequestId, oneshot::Sender<anyhow::Result<GetGraphResponse>>>;

pub enum PublishCommand {
    Gossip {
        topic: IdentTopic,
        data: Vec<u8>,
        result: oneshot::Sender<anyhow::Result<MessageId>>,
    },
    GetGraph {
        peer: PeerId,
        request: GetGraphRequest,
        result: oneshot::Sender<anyhow::Result<GetGraphResponse>>,
    },
    /// The answer to an inbound `GetGraph`, produced off the network loop;
    /// only the swarm can use the response channel.
    GetGraphResponse {
        channel: ResponseChannel<GetGraphResponse>,
        response: GetGraphResponse,
    },
}

impl PublishCommand {
    pub fn execute(self, swarm: &mut Swarm<AllBehaviours>, pending: &mut PendingGraphRequests) {
        match self {
            PublishCommand::Gossip { topic, data, result } => {
                // A timed-out/cancelled caller must not leave a delayed broadcast behind.
                if !result.is_closed() {
                    let outcome = swarm.behaviour_mut().gossipsub.publish(topic, data);
                    let _ = result.send(outcome.map_err(Into::into));
                }
            }
            PublishCommand::GetGraph { peer, request, result } => {
                if result.is_closed() {
                    return;
                }
                let request_id = swarm.behaviour_mut().get_graph.send_request(&peer, request);
                pending.insert(request_id, result);
            }
            PublishCommand::GetGraphResponse { channel, response } => {
                // The requester may have given up meanwhile; nothing to do then.
                let _ = swarm.behaviour_mut().get_graph.send_response(channel, response);
            }
        }
    }
}

/// Maximum publish wait; cancellation closes the reply and skips queued commands.
const PUBLISH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

#[derive(Clone)]
pub struct NetworkPublisher(mpsc::Sender<PublishCommand>);

pub fn channel() -> (NetworkPublisher, mpsc::Receiver<PublishCommand>) {
    let (tx, rx) = mpsc::channel(8);
    (NetworkPublisher(tx), rx)
}

impl NetworkPublisher {
    /// Hand the swarm the answer to an inbound `GetGraph` request.
    pub async fn respond_graph(
        &self,
        channel: ResponseChannel<GetGraphResponse>,
        response: GetGraphResponse,
    ) -> anyhow::Result<()> {
        let send = self.0.send(PublishCommand::GetGraphResponse { channel, response });
        tokio::time::timeout(PUBLISH_TIMEOUT, send)
            .await
            .map_err(|_| {
                anyhow::anyhow!("network task did not take the GetGraph response in time")
            })?
            .map_err(|_| anyhow::anyhow!("network publisher stopped"))
    }

    /// Ask `peer` for a graph definition over the direct protocol.
    pub async fn request_graph(
        &self,
        peer: PeerId,
        request: GetGraphRequest,
    ) -> anyhow::Result<GetGraphResponse> {
        let (tx, rx) = oneshot::channel();
        let send = async {
            self.0
                .send(PublishCommand::GetGraph { peer, request, result: tx })
                .await
                .map_err(|_| anyhow::anyhow!("network publisher stopped"))?;
            rx.await.map_err(|_| anyhow::anyhow!("network publisher stopped before answering"))?
        };
        tokio::time::timeout(GET_GRAPH_REQUEST_TIMEOUT + PUBLISH_TIMEOUT, send)
            .await
            .map_err(|_| anyhow::anyhow!("GetGraph request to {peer} timed out"))?
    }
}

impl MessagePublisher for NetworkPublisher {
    fn publish_message(
        &mut self,
        topic: IdentTopic,
        data: Vec<u8>,
    ) -> BoxFuture<'_, anyhow::Result<MessageId>> {
        Box::pin(async move {
            let (tx, rx) = oneshot::channel();
            let publish = async {
                self.0
                    .send(PublishCommand::Gossip { topic, data, result: tx })
                    .await
                    .map_err(|_| anyhow::anyhow!("network publisher stopped"))?;
                rx.await
                    .map_err(|_| anyhow::anyhow!("network publisher stopped before publishing"))?
            };
            tokio::time::timeout(PUBLISH_TIMEOUT, publish)
                .await
                .map_err(|_| anyhow::anyhow!("network task did not take the publish in time"))?
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn publish_waits_for_actual_network_result_and_cancellation_closes_reply() {
        let (mut publisher, mut commands) = channel();
        let mut send = publisher.publish_message(IdentTopic::new("test"), vec![1]);
        let command = tokio::select! {
            result = &mut send => panic!("must wait for network: {result:?}"),
            command = commands.recv() => command.unwrap(),
        };
        let PublishCommand::Gossip { result, .. } = command else { panic!("gossip command") };
        result.send(Err(anyhow::anyhow!("not published"))).unwrap();
        assert!(send.await.unwrap_err().to_string().contains("not published"));

        let mut send = publisher.publish_message(IdentTopic::new("test"), vec![2]);
        let command = tokio::select! {
            _ = &mut send => panic!("must wait for network"),
            command = commands.recv() => command.unwrap(),
        };
        drop(send);
        let PublishCommand::Gossip { result, .. } = command else { panic!("gossip command") };
        assert!(result.is_closed());
    }
}
