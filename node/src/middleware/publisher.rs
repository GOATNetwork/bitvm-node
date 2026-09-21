//! Bounded, acknowledged access to the swarm from the business worker.
use futures::future::BoxFuture;
use libp2p::{
    Swarm,
    gossipsub::{IdentTopic, MessageId},
};
use tokio::sync::{mpsc, oneshot};

use super::AllBehaviours;

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

pub struct PublishCommand {
    topic: IdentTopic,
    data: Vec<u8>,
    result: oneshot::Sender<anyhow::Result<MessageId>>,
}

impl PublishCommand {
    pub fn execute(self, swarm: &mut Swarm<AllBehaviours>) {
        // A timed-out/cancelled caller must not leave a delayed broadcast behind.
        if !self.result.is_closed() {
            let result = swarm.behaviour_mut().gossipsub.publish(self.topic, self.data);
            let _ = self.result.send(result.map_err(Into::into));
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
                    .send(PublishCommand { topic, data, result: tx })
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
        command.result.send(Err(anyhow::anyhow!("not published"))).unwrap();
        assert!(send.await.unwrap_err().to_string().contains("not published"));

        let mut send = publisher.publish_message(IdentTopic::new("test"), vec![2]);
        let command = tokio::select! {
            _ = &mut send => panic!("must wait for network"),
            command = commands.recv() => command.unwrap(),
        };
        drop(send);
        assert!(command.result.is_closed());
    }
}
