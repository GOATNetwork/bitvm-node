use thiserror::Error;

#[derive(Debug, Error)]
pub enum SpecialError {
    #[error("Invalid Pegin Request: {0}")]
    InvalidPeginRequest(String),

    #[error("Invalid Pegin Data: {0}")]
    InvalidPeginData(String),

    #[error("Invalid Graph: {0}")]
    InvalidGraph(String),

    #[error("Invalid Committee: {0}")]
    InvalidCommittee(String),

    #[error("Insufficient Balance: {0}")]
    InsufficientBalance(String),
}

/// How a failed step is retried.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FailureClass {
    /// A business rejection: the input or the call is wrong, retrying cannot help.
    Permanent(String),
    /// The chain, the network or the database did not answer; retried without limit.
    Transient,
    /// Anything else, a bug or a state nobody foresaw; setup steps retry it a
    /// bounded number of times, peg-out steps keep retrying with an alert.
    Unknown,
}

pub fn classify_failure(error: &anyhow::Error) -> FailureClass {
    if let Some(reason) = permanent_rejection(error) {
        return FailureClass::Permanent(reason);
    }
    if is_transient(error) {
        return FailureClass::Transient;
    }
    FailureClass::Unknown
}

/// The message or call was rejected for good: a malformed or forged input, a
/// committee mismatch or a contract revert.
pub fn permanent_rejection(error: &anyhow::Error) -> Option<String> {
    for cause in error.chain() {
        if let Some(special) = cause.downcast_ref::<SpecialError>() {
            return match special {
                SpecialError::InvalidPeginRequest(message)
                | SpecialError::InvalidPeginData(message)
                | SpecialError::InvalidGraph(message)
                | SpecialError::InvalidCommittee(message) => Some(message.clone()),
                SpecialError::InsufficientBalance(_) => None,
            };
        }
        if let Some(message) = revert_message(cause) {
            return Some(format!("contract call reverted: {message}"));
        }
    }
    None
}

/// Whether the contract refused the call (an `execution reverted` answer from
/// a Goat node anywhere in the chain).
pub fn is_contract_revert(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| revert_message(cause).is_some())
}

fn revert_message(cause: &(dyn std::error::Error + 'static)) -> Option<String> {
    if cause.downcast_ref::<alloy::contract::Error>().is_none()
        && cause.downcast_ref::<alloy::transports::TransportError>().is_none()
    {
        return None;
    }
    let message = cause.to_string();
    (message.contains("execution reverted") || message.contains("revert")).then_some(message)
}

fn is_transient(error: &anyhow::Error) -> bool {
    store::is_storage_error(error)
        || error.chain().any(|cause| {
            cause.downcast_ref::<reqwest::Error>().is_some()
            || cause.downcast_ref::<esplora_client::Error>().is_some()
            || cause.downcast_ref::<std::io::Error>().is_some()
            || cause.downcast_ref::<tokio::time::error::Elapsed>().is_some()
            || cause.downcast_ref::<alloy::transports::TransportError>().is_some_and(transport_down)
            || cause.downcast_ref::<alloy::contract::Error>().is_some_and(|contract| {
                matches!(contract, alloy::contract::Error::TransportError(inner) if transport_down(inner))
            })
            || transient_message(&cause.to_string())
        })
}

fn transport_down(error: &alloy::transports::TransportError) -> bool {
    matches!(
        error,
        alloy::transports::RpcError::Transport(_) | alloy::transports::RpcError::NullResp
    )
}

/// Errors the clients wrap into plain strings: network and backend failures by
/// their usual wording.
fn transient_message(message: &str) -> bool {
    let message = message.to_ascii_lowercase();
    [
        "timed out",
        "timeout",
        "connection",
        "error sending request",
        "transport(",
        "temporarily",
        "database is locked",
        "database is busy",
        "dns error",
        "broken pipe",
        "reset by peer",
        "429 too many",
        "502 bad gateway",
        "503 service",
        "504 gateway",
    ]
    .iter()
    .any(|needle| message.contains(needle))
}
