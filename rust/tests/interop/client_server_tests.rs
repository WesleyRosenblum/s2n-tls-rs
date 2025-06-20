// Interoperability tests between Rust and C implementations

use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;
use s2n_tls_rs::{init, cleanup, Config, Connection};

// This test requires the s2n-tls C implementation to be built
#[test]
#[ignore] // Ignore by default as it requires external setup
fn test_rust_client_c_server() {
    // Initialize the library
    assert!(init().is_ok());
    
    // Start the s2n-tls C server in a separate process
    let server = Command::new("../bin/s2nd")
        .args(&["--cert", "../tests/pems/rsa_2048_sha256_wildcard_cert.pem",
                "--key", "../tests/pems/rsa_2048_sha256_wildcard_key.pem",
                "127.0.0.1", "8443"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("Failed to start s2n-tls C server");
    
    // Give the server time to start
    thread::sleep(Duration::from_secs(1));
    
    // Create a Rust client
    let mut config = Config::new().unwrap();
    config.set_verify_host_callback(|_| Ok(())).unwrap(); // Skip hostname verification for testing
    
    let mut client = Connection::new_client().unwrap();
    client.set_config(config).unwrap();
    
    // Connect to the server
    // Note: In a real test, we would use actual socket I/O
    // This is just a skeleton for the test structure
    
    // Clean up
    assert!(cleanup().is_ok());
    
    // Terminate the server
    server.kill().expect("Failed to kill server process");
}

#[test]
#[ignore] // Ignore by default as it requires external setup
fn test_c_client_rust_server() {
    // Initialize the library
    assert!(init().is_ok());
    
    // Start a Rust server
    // Note: In a real test, we would start a server in a separate thread
    // This is just a skeleton for the test structure
    
    // Run the s2n-tls C client
    let output = Command::new("../bin/s2nc")
        .args(&["--ca-file", "../tests/pems/rsa_2048_sha256_wildcard_cert.pem",
                "127.0.0.1", "8443"])
        .output()
        .expect("Failed to run s2n-tls C client");
    
    // Check the output
    // In a real test, we would verify successful connection
    
    // Clean up
    assert!(cleanup().is_ok());
}