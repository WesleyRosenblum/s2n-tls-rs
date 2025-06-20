// Error module
// Contains error types for the library

use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("TLS protocol error: {0}")]
    Protocol(String),
    
    #[error("Crypto error: {0}")]
    Crypto(String),
    
    #[error("Configuration error: {0}")]
    Config(String),
    
    #[error("Internal error: {0}")]
    Internal(String),
}