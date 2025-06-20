// API unit tests

use s2n_tls_rs::{Config, Connection, ConnectionMode, init, cleanup};

#[test]
fn test_connection_client_server() {
    // Initialize the library
    assert!(init().is_ok());
    
    // Create a client connection
    let client = Connection::new_client().unwrap();
    assert_eq!(client.mode(), ConnectionMode::Client);
    
    // Create a server connection
    let server = Connection::new_server().unwrap();
    assert_eq!(server.mode(), ConnectionMode::Server);
    
    // Create a config
    let config = Config::new().unwrap();
    
    // Clean up
    assert!(cleanup().is_ok());
}

#[test]
fn test_config_creation() {
    // Initialize the library
    assert!(init().is_ok());
    
    // Create a config
    let config = Config::new().unwrap();
    
    // Clean up
    assert!(cleanup().is_ok());
}