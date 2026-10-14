//! Instance and Graph event handlers and their jobs.
//!
//! Business data stays in the instance and graph tables; the engine manages
//! pending events, jobs, outgoing messages and dependency waits.

pub mod common;
pub mod graph;
pub mod graph_fetch;
pub mod graph_jobs;
pub mod graph_pegout;
pub mod graph_pegout_jobs;
pub mod graph_scan;
pub mod graph_setup;
pub mod instance;
pub mod instance_jobs;
pub mod instance_scan;
pub mod jobs;

#[cfg(test)]
mod graph_tests;
#[cfg(test)]
mod instance_tests;
