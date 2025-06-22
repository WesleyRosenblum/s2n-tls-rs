//! Public API for s2n-tls-rs
//!
//! This module provides the public API for the s2n-tls-rs library. It includes
//! the main types and functions needed to use s2n-tls-rs in your application.
//!
//! ## Main Components
//!
//! - [`Config`]: Configuration for TLS connections
//! - [`Connection`]: TLS connection state and operations
//! - [`ConnectionMode`]: Client or server mode
//! - [`BlockedStatus`]: Status of blocked operations
//!
//! ## Usage
//!
//! The typical usage pattern is:
//!
//! 1. Initialize the library with [`init()`](crate::init)
//! 2. Create a [`Config`] with appropriate settings
//! 3. Create a [`Connection`] with the config
//! 4. Perform I/O operations using the connection
//! 5. Close the connection when done
//! 6. Clean up with [`cleanup()`](crate::cleanup)
//!
//! See the [crate-level documentation](crate) for examples.

mod connection;
mod config;

pub use connection::{Connection, ConnectionStatus, BlockedStatus};
pub use crate::state::ConnectionMode;
pub use config::Config;
