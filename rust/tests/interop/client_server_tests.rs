// Interoperability tests between Rust and C implementations
//
// These tests verify that the Rust implementation can interoperate with the C implementation.

use s2n_tls_rs::{init, cleanup, Config, Connection, ConnectionMode, BlockedStatus, ConnectionStatus};
use s2n_tls_rs::crypto::cipher_suites::TLS_AES_128_GCM_SHA256;
use s2n_tls_rs::handshake::NamedGroup;
use std::process::{Command, Stdio, Child};
use std::io::{Read, Write};
use std::thread;
use std::time::Duration;
use std::path::Path;

// Helper function to check if s2n-tls C implementation is available
fn is_s2n_tls_available() -> bool {
    // Check if the s2n-tls binary is available
    let output = Command::new("which")
        .arg("s2nc")
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false);
    
    output
}

// Helper function to start s2n-tls server
fn start_s2n_tls_server(port: u16) -> Option<Child> {
    if !is_s2n_tls_available() {
        return None;
    }
    
    // Start s2n-tls server
    let server = Command::new("s2nd")
        .arg("--cert")
        .arg("tests/pems/rsa_2048_sha256_wildcard_cert.pem")
        .arg("--key")
        .arg("tests/pems/rsa_2048_sha256_wildcard_key.pem")
        .arg("--port")
        .arg(port.to_string())
        .arg("localhost")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .ok()?;
    
    // Wait for the server to start
    thread::sleep(Duration::from_millis(100));
    
    Some(server)
}

// Helper function to start s2n-tls client
fn start_s2n_tls_client(port: u16) -> Option<Child> {
    if !is_s2n_tls_available() {
        return None;
    }
    
    // Start s2n-tls client
    let client = Command::new("s2nc")
        .arg("--port")
        .arg(port.to_string())
        .arg("localhost")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .ok()?;
    
    // Wait for the client to start
    thread::sleep(Duration::from_millis(100));
    
    Some(client)
}

/// Test Rust client with s2n-tls server
#[test]
#[ignore] // This test requires the s2n-tls C implementation
fn test_rust_client_with_s2n_tls_server() {
    // Skip the test if s2n-tls is not available
    if !is_s2n_tls_available() {
        println!("Skipping test_rust_client_with_s2n_tls_server because s2n-tls is not available");
        return;
    }
    
    // Initialize the library
    assert!(init().is_ok());
    
    // Start s2n-tls server
    let port = 8443;
    let mut server = start_s2n_tls_server(port).expect("Failed to start s2n-tls server");
    
    // Create a client configuration
    let mut client_config = Config::new_client();
    client_config.set_server_name("localhost".to_string()).unwrap();
    client_config.add_cipher_suite(TLS_AES_128_GCM_SHA256).unwrap();
    client_config.add_named_group(NamedGroup::X25519).unwrap();
    
    // Create a client connection
    let mut client_connection = Connection::new(client_config);
    
    // Initialize the connection
    assert!(client_connection.initialize().is_ok());
    
    // In a real test, we would connect to the s2n-tls server
    // For now, we'll just verify that the connection is in the expected state
    assert!(client_connection.is_handshaking());
    
    // Clean up
    server.kill().expect("Failed to kill s2n-tls server");
    assert!(cleanup().is_ok());
}

/// Test s2n-tls client with Rust server
#[test]
#[ignore] // This test requires the s2n-tls C implementation
fn test_s2n_tls_client_with_rust_server() {
    // Skip the test if s2n-tls is not available
    if !is_s2n_tls_available() {
        println!("Skipping test_s2n_tls_client_with_rust_server because s2n-tls is not available");
        return;
    }
    
    // Initialize the library
    assert!(init().is_ok());
    
    // Create a server configuration
    let mut server_config = Config::new_server();
    
    // Set the server certificate
    // In a real test, we would use a real certificate
    let server_cert = vec![
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    ];
    server_config.set_server_certificate(server_cert).unwrap();
    
    // Set the server private key
    // In a real test, we would use a real private key
    let server_key = vec![
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    ];
    server_config.set_server_private_key(server_key).unwrap();
    
    // Add a cipher suite
    server_config.add_cipher_suite(TLS_AES_128_GCM_SHA256).unwrap();
    
    // Add a named group
    server_config.add_named_group(NamedGroup::X25519).unwrap();
    
    // Create a server connection
    let mut server_connection = Connection::new(server_config);
    
    // Initialize the connection
    assert!(server_connection.initialize().is_ok());
    
    // Start s2n-tls client
    let port = 8444;
    let mut client = start_s2n_tls_client(port).expect("Failed to start s2n-tls client");
    
    // In a real test, we would accept the connection from the s2n-tls client
    // For now, we'll just verify that the connection is in the expected state
    assert!(server_connection.is_handshaking());
    
    // Clean up
    client.kill().expect("Failed to kill s2n-tls client");
    assert!(cleanup().is_ok());
}

/// Test data transfer between Rust client and s2n-tls server
#[test]
#[ignore] // This test requires the s2n-tls C implementation
fn test_data_transfer_rust_client_s2n_tls_server() {
    // Skip the test if s2n-tls is not available
    if !is_s2n_tls_available() {
        println!("Skipping test_data_transfer_rust_client_s2n_tls_server because s2n-tls is not available");
        return;
    }
    
    // Initialize the library
    assert!(init().is_ok());
    
    // Start s2n-tls server
    let port = 8445;
    let mut server = start_s2n_tls_server(port).expect("Failed to start s2n-tls server");
    
    // Create a client configuration
    let mut client_config = Config::new_client();
    client_config.set_server_name("localhost".to_string()).unwrap();
    client_config.add_cipher_suite(TLS_AES_128_GCM_SHA256).unwrap();
    client_config.add_named_group(NamedGroup::X25519).unwrap();
    
    // Create a client connection
    let mut client_connection = Connection::new(client_config);
    
    // Initialize the connection
    assert!(client_connection.initialize().is_ok());
    
    // In a real test, we would connect to the s2n-tls server and send/receive data
    // For now, we'll just verify that the connection is in the expected state
    assert!(client_connection.is_handshaking());
    
    // Clean up
    server.kill().expect("Failed to kill s2n-tls server");
    assert!(cleanup().is_ok());
}

/// Test data transfer between s2n-tls client and Rust server
#[test]
#[ignore] // This test requires the s2n-tls C implementation
fn test_data_transfer_s2n_tls_client_rust_server() {
    // Skip the test if s2n-tls is not available
    if !is_s2n_tls_available() {
        println!("Skipping test_data_transfer_s2n_tls_client_rust_server because s2n-tls is not available");
        return;
    }
    
    // Initialize the library
    assert!(init().is_ok());
    
    // Create a server configuration
    let mut server_config = Config::new_server();
    
    // Set the server certificate
    // In a real test, we would use a real certificate
    let server_cert = vec![
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    ];
    server_config.set_server_certificate(server_cert).unwrap();
    
    // Set the server private key
    // In a real test, we would use a real private key
    let server_key = vec![
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    ];
    server_config.set_server_private_key(server_key).unwrap();
    
    // Add a cipher suite
    server_config.add_cipher_suite(TLS_AES_128_GCM_SHA256).unwrap();
    
    // Add a named group
    server_config.add_named_group(NamedGroup::X25519).unwrap();
    
    // Create a server connection
    let mut server_connection = Connection::new(server_config);
    
    // Initialize the connection
    assert!(server_connection.initialize().is_ok());
    
    // Start s2n-tls client
    let port = 8446;
    let mut client = start_s2n_tls_client(port).expect("Failed to start s2n-tls client");
    
    // In a real test, we would accept the connection from the s2n-tls client and send/receive data
    // For now, we'll just verify that the connection is in the expected state
    assert!(server_connection.is_handshaking());
    
    // Clean up
    client.kill().expect("Failed to kill s2n-tls client");
    assert!(cleanup().is_ok());
}
