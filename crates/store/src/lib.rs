pub mod engine;
pub mod localdb;
mod schema;
pub mod signing;
mod utils;

pub use engine::*;
pub use localdb::{DEFAULT_BUSY_TIMEOUT, create_local_db, create_local_db_with_busy_timeout};
pub use schema::*;
pub use signing::SigningAuthorization;

/// Whether a `sqlx` error sits anywhere in `error`'s chain: the database did
/// not answer, which callers retry rather than treat as a business failure.
pub fn is_storage_error(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| cause.downcast_ref::<sqlx::Error>().is_some())
}
