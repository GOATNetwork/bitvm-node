//! ACK return channel: the aggregate worker hands ACKs to the network task
//! after its transaction committed. The channel is bounded; when it is full the
//! ACK is dropped and the sender's resend produces it again.

use tokio::sync::mpsc;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AckRequest {
    pub peer: String,
    pub delivery_id: String,
}

pub type AckReceiver = mpsc::Receiver<AckRequest>;

#[derive(Clone, Debug)]
pub struct AckSender(mpsc::Sender<AckRequest>);

impl AckSender {
    pub fn channel(capacity: usize) -> (Self, AckReceiver) {
        let (tx, rx) = mpsc::channel(capacity.max(1));
        (Self(tx), rx)
    }

    /// Returns false when the ACK was dropped because the channel is full or closed.
    pub fn try_send(&self, request: AckRequest) -> bool {
        self.0.try_send(request).is_ok()
    }
}
