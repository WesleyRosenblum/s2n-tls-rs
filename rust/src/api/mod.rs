//! Public API for s2n-tls-rs
//!
//! This module provides the public API for the s2n-tls-rs library.

mod connection;
mod config;

pub use connection::{Connection, ConnectionStatus, BlockedStatus};
pub use crate::state::ConnectionMode;
pub use config::Config;
