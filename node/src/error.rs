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

    /// A backend has not caught up with a fact another source already proved
    /// (a transaction Goat names that esplora does not know yet). Retried.
    #[error("Backend Lag: {0}")]
    BackendLag(String),
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
                SpecialError::InsufficientBalance(_) | SpecialError::BackendLag(_) => None,
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
            matches!(cause.downcast_ref::<SpecialError>(), Some(SpecialError::BackendLag(_)))
            || cause.downcast_ref::<reqwest::Error>().is_some()
            || cause.downcast_ref::<esplora_client::Error>().is_some()
            || cause.downcast_ref::<std::io::Error>().is_some_and(is_transient_io)
            || cause.downcast_ref::<tokio::time::error::Elapsed>().is_some()
            || cause.downcast_ref::<alloy::transports::TransportError>().is_some_and(transport_down)
            || cause.downcast_ref::<alloy::contract::Error>().is_some_and(|contract| {
                matches!(contract, alloy::contract::Error::TransportError(inner) if transport_down(inner))
            })
            || transient_message(&cause.to_string())
        })
}

/// Network-shaped io errors pass; a missing file, a permission error or bad data
/// stays wrong on retry and must reach the give-up cap and its alert.
fn is_transient_io(error: &std::io::Error) -> bool {
    use std::io::ErrorKind::*;
    matches!(
        error.kind(),
        TimedOut
            | ConnectionRefused
            | ConnectionReset
            | ConnectionAborted
            | NotConnected
            | BrokenPipe
            | Interrupted
            | WouldBlock
            | UnexpectedEof
    )
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

/// Log an unwind payload without assuming it contains a string.
pub(crate) fn panic_message(payload: &(dyn std::any::Any + Send)) -> &str {
    if let Some(message) = payload.downcast_ref::<&str>() {
        message
    } else if let Some(message) = payload.downcast_ref::<String>() {
        message
    } else {
        "non-string panic payload"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Error, ErrorKind};

    #[test]
    fn only_network_io_errors_are_transient() {
        let wrapped = |kind| anyhow::Error::new(Error::from(kind)).context("read setup state");
        assert!(is_transient(&wrapped(ErrorKind::ConnectionReset)));
        assert!(is_transient(&wrapped(ErrorKind::TimedOut)));
        assert!(!is_transient(&wrapped(ErrorKind::NotFound)));
        assert!(!is_transient(&wrapped(ErrorKind::PermissionDenied)));
        assert!(!is_transient(&wrapped(ErrorKind::InvalidData)));
    }

    #[test]
    fn backend_lag_is_transient() {
        let error = anyhow::Error::new(SpecialError::BackendLag("tx not seen".to_string()))
            .context("validate graph");
        assert_eq!(classify_failure(&error), FailureClass::Transient);
    }
}
