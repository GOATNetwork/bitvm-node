//! Instance and Graph event handlers and their jobs.
//!
//! Business data stays in the instance and graph tables; the engine manages
//! pending events, jobs, outgoing messages and dependency waits.

pub mod instance;
pub mod instance_jobs;
pub mod instance_scan;

#[cfg(test)]
mod instance_tests;
