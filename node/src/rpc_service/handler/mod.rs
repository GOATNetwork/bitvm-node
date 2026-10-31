pub mod bitvm_handler;
#[cfg(feature = "rpc-debug-endpoints")]
pub mod debug_handler;
pub mod node_handler;
pub mod proof_handler;
pub mod swap_handler;

// Re-export all handler functions for better documentation visibility
pub use bitvm_handler::*;
#[cfg(feature = "rpc-debug-endpoints")]
pub use debug_handler::*;
pub use node_handler::*;
pub use proof_handler::*;
pub use swap_handler::*;
