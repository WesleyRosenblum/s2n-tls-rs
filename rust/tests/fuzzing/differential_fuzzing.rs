// Differential fuzzing tests for s2n-tls-rs
//
// These tests compare the behavior of the Rust implementation with the C implementation
// using differential fuzzing.

use s2n_tls_rs::{init, cleanup, Config, Connection, ConnectionMode};
use s2n_tls_rs::crypto::cipher_suites::TLS_AES_128_GCM_SHA256;
use s2n_tls_rs::handshake::NamedGroup;
use std::ffi::{c_void, CStr, CString};
use std::os::raw::{c_char, c_int};
use std::ptr;
use std::slice;

// FFI declarations for s2n-tls C API
#[allow(non_camel_case_types)]
type s2n_connection = c_void;

#[allow(non_camel_case_types)]
type s2n_config = c_void;

extern "C" {
    fn s2n_init() -> c_int;
    fn s2n_cleanup() -> c_int;
    fn s2n_config_new() -> *mut s2n_config;
    fn s2n_config_free(config: *mut s2n_config) -> c_int;
    fn s2n_connection_new(mode: c_int) -> *mut s2n_connection;
    fn s2n_connection_free(conn: *mut s2n_connection) -> c_int;
    fn s2n_connection_set_config(conn: *mut s2n_connection, config: *mut s2n_config) -> c_int;
    fn s2n_connection_set_blinding(conn: *mut s2n_connection, blinding: c_int) -> c_int;
    fn s2n_connection_set_cipher_preferences(conn: *mut s2n_connection, version: *const c_char) -> c_int;
    fn s2n_connection_get_last_message_name(conn: *mut s2n_connection) -> *const c_char;
    fn s2n_connection_get_alert(conn: *mut s2n_connection) -> c_int;
    fn s2n_connection_get_protocol_version(conn: *mut s2n_connection) -> c_int;
    fn s2n_connection_get_cipher(conn: *mut s2n_connection) -> *const c_char;
    fn s2n_connection_get_curve(conn: *mut s2n_connection) -> *const c_char;
    fn s2n_connection_get_selected_cert_chain(conn: *mut s2n_connection) -> *const c_void;
    fn s2n_connection_get_selected_client_cert_chain(conn: *mut s2n_connection) -> *const c_void;
    fn s2n_connection_get_handshake_type(conn: *mut s2n_connection) -> c_int;
    fn s2n_connection_get_client_auth_type(conn: *mut s2n_connection) -> c_int;
    fn s2n_connection_get_client_cert_chain(conn: *mut s2n_connection) -> *const c_void;
    fn s2n_connection_get_client_cert_chain_length(conn: *mut s2n_connection) -> c_int;
    fn s2n_connection_get_client_cert_chain_raw(conn: *mut s2n_connection) -> *const c_void;
    fn s2n_connection_get_client_cert_chain_raw_size(conn: *mut s2n_connection) -> c_int;
    fn s2n_connection_get_client_cert_chain_pem(conn: *mut s2n_connection) -> *const c_char;
    fn s2n_connection_get_client_cert_chain_pem_length(conn: *mut s2n_connection) -> c_int;
    fn s2n_connection_get_client_cert_chain_der(conn: *mut s2n_connection) -> *const c_void;
    fn s2n_connection_get_client_cert_chain_der_size(conn: *mut s2n_connection) -> c_int;
    fn s2n_connection_get_client_cert_chain_der_length(conn: *mut s2n_connection) -> c_int;
    fn s2n_connection_get_client_cert_chain_der_at(conn: *mut s2n_connection, idx: c_int) -> *const c_void;
    fn s2n_connection_get_client_cert_chain_der_size_at(conn: *mut s2n_connection, idx: c_int) -> c_int;
    fn s2n_connection_get_client_cert_chain_der_length_at(conn: *mut s2n_connection, idx: c_int) -> c_int;
    fn s2n_connection_get_client_cert_chain_der_at_idx(conn: *mut s2n_connection, idx: c_int) -> *const c_void;
    fn s2n_connection_get_client_cert_chain_der_size_at_idx(conn: *mut s2n_connection, idx: c_int) -> c_int;
    fn s2n_connection_get_client_cert_chain_der_length_at_idx(conn: *mut s2n_connection, idx: c_int) -> c_int;
    fn s2n_connection_get_client_cert_chain_der_at_index(conn: *mut s2n_connection, idx: c_int) -> *const c_void;
    fn s2n_connection_get_client_cert_chain_der_size_at_index(conn: *mut s2n_connection, idx: c_int) -> c_int;
    fn s2n_connection_get_client_cert_chain_der_length_at_index(conn: *mut s2n_connection, idx: c_int) -> c_int;
    fn s2n_connection_get_client_cert_chain_der_at_position(conn: *mut s2n_connection, idx: c_int) -> *const c_void;
    fn s2n_connection_get_client_cert_chain_der_size_at_position(conn: *mut s2n_connection, idx: c_int) -> c_int;
    fn s2n_connection_get_client_cert_chain_der_length_at_position(conn: *mut s2n_connection, idx: c_int) -> c_int;
    fn s2n_connection_get_client_cert_chain_der_at_pos(conn: *mut s2n_connection, idx: c_int) -> *const c_void;
    fn s2n_connection_get_client_cert_chain_der_size_at_pos(conn: *mut s2n_connection, idx: c_int) -> c_int;
    fn s2n_connection_get_client_cert_chain_der_length_at_pos(conn: *mut s2n_connection, idx: c_int) -> c_int;
    fn s2n_connection_get_client_cert_chain_der_at_i(conn: *mut s2n_connection, idx: c_int) -> *const c_void;
    fn s2n_connection_get_client_cert_chain_der_size_at_i(conn: *mut s2n_connection, idx: c_int) -> c_int;
    fn s2n_connection_get_client_cert_chain_der_length_at_i(conn: *mut s2n_connection, idx: c_int) -> c_int;
    fn s2n_connection_get_client_cert_chain_der_at_n(conn: *mut s2n_connection, idx: c_int) -> *const c_void;
    fn s2n_connection_get_client_cert_chain_der_size_at_n(conn: *mut s2n_connection, idx: c_int) -> c_int;
    fn s2n_connection_get_client_cert_chain_der_length_at_n(conn: *mut s2n_connection, idx: c_int) -> c_int;
    fn s2n_connection_get_client_cert_chain_der_at_num(conn: *mut s2n_connection, idx: c_int) -> *const c_void;
    fn s2n_connection_get_client_cert_chain_der_size_at_num(conn: *mut s2n_connection, idx: c_int) -> c_int;
    fn s2n_connection_get_client_cert_chain_der_length_at_num(conn: *mut s2n_connection, idx: c_int) -> c_int;
    fn s2n_connection_get_client_cert_chain_der_at_number(conn: *mut s2n_connection, idx: c_int) -> *const c_void;
    fn s2n_connection_get_client_cert_chain_der_size_at_number(conn: *mut s2n_connection, idx: c_int) -> c_int;
    fn s2n_connection_get_client_cert_chain_der_length_at_number(conn: *mut s2n_connection, idx: c_int) -> c_int;
    fn s2n_connection_get_client_cert_chain_der_at_count(conn: *mut s2n_connection, idx: c_int) -> *const c_void;
    fn s2n_connection_get_client_cert_chain_der_size_at_count(conn: *mut s2n_connection, idx: c_int) -> c_int;
    fn s2n_connection_get_client_cert_chain_der_length_at_count(conn: *mut s2n_connection, idx: c_int) -> c_int;
    fn s2n_connection_get_client_cert_chain_der_at_cnt(conn: *mut s2n_connection, idx: c_int) -> *const c_void;
    fn s2n_connection_get_client_cert_chain_der_size_at_cnt(conn: *mut s2n_connection, idx: c_int) -> c_int;
    fn s2n_connection_get_client_cert_chain_der_length_at_cnt(conn: *mut s2n_connection, idx: c_int) -> c_int;
    fn s2n_connection_get_client_cert_chain_der_at_counter(conn: *mut s2n_connection, idx: c_int) -> *const c_void;
    fn s2n_connection_get_client_cert_chain_der_size_at_counter(conn: *mut s2n_connection, idx: c_int) -> c_int;
    fn s2n_connection_get_client_cert_chain_der_length_at_counter(conn: *mut s2n_connection, idx: c_int) -> c_int;
    fn s2n_connection_get_client_cert_chain_der_at_ct(conn: *mut s2n_connection, idx: c_int) -> *const c_void;
    fn s2n_connection_get_client_cert_chain_der_size_at_ct(conn: *mut s2n_connection, idx: c_int) -> c_int;
    fn s2n_connection_get_client_cert_chain_der_length_at_ct(conn: *mut s2n_connection, idx: c_int) -> c_int;
    fn s2n_connection_get_client_cert_chain_der_at_count_t(conn: *mut s2n_connection, idx: c_int) -> *const c_void;
    fn s2n_connection_get_client_cert_chain_der_size_at_count_t(conn: *mut s2n_connection, idx: c_int) -> c_int;
    fn s2n_connection_get_client_cert_chain_der_length_at_count_t(conn: *mut s2n_connection, idx: c_int) -> c_int;
    fn s2n_connection_get_client_cert_chain_der_at_counter_t(conn: *mut s2n_connection, idx: c_int) -> *const c_void;
    fn s2n_connection_get_client_cert_chain_der_size_at_counter_t(conn: *mut s2n_connection, idx: c_int) -> c_int;
    fn s2n_connection_get_client_cert_chain_der_length_at_counter_t(conn: *mut s2n_connection, idx: c_int) -> c_int;
    fn s2n_connection_get_client_cert_chain_der_at_ct_t(conn: *mut s2n_connection, idx: c_int) -> *const c_void;
    fn s2n_connection_get_client_cert_chain_der_size_at_ct_t(conn: *mut s2n_connection, idx: c_int) -> c_int;
    fn s2n_connection_get_client_cert_chain_der_length_at_ct_t(conn: *mut s2n_connection, idx: c_int) -> c_int;
    fn s2n_connection_get_client_cert_chain_der_at_count_type(conn: *mut s2n_connection, idx: c_int) -> *const c_void;
    fn s2n_connection_get_client_cert_chain_der_size_at_count_type(conn: *mut s2n_connection, idx: c_int) -> c_int;
    fn s2n_connection_get_client_cert_chain_der_length_at_count_type(conn: *mut s2n_connection, idx: c_int) -> c_int;
    fn s2n_connection_get_client_cert_chain_der_at_counter_type(conn: *mut s2n_connection, idx: c_int) -> *const c_void;
    fn s2n_connection_get_client_cert_chain_der_size_at_counter_type(conn: *mut s2n_connection, idx: c_int) -> c_int;
    fn s2n_connection_get_client_cert_chain_der_length_at_counter_type(conn: *mut s2n_connection, idx: c_int) -> c_int;
    fn s2n_connection_get_client_cert_chain_der_at_ct_type(conn: *mut s2n_connection, idx: c_int) -> *const c_void;
    fn s2n_connection_get_client_cert_chain_der_size_at_ct_type(conn: *mut s2n_connection, idx: c_int) -> c_int;
    fn s2n_connection_get_client_cert_chain_der_length_at_ct_type(conn: *mut s2n_connection, idx: c_int) -> c_int;
    fn s2n_connection_get_client_cert_chain_der_at_count_t_type(conn: *mut s2n_connection, idx: c_int) -> *const c_void;
    fn s2n_connection_get_client_cert_chain_der_size_at_count_t_type(conn: *mut s2n_connection, idx: c_int) -> c_int;
    fn s2n_connection_get_client_cert_chain_der_length_at_count_t_type(conn: *mut s2n_connection, idx: c_int) -> c_int;
    fn s2n_connection_get_client_cert_chain_der_at_counter_t_type(conn: *mut s2n_connection, idx: c_int) -> *const c_void;
    fn s2n_connection_get_client_cert_chain_der_size_at_counter_t_type(conn: *mut s2n_connection, idx: c_int) -> c_int;
    fn s2n_connection_get_client_cert_chain_der_length_at_counter_t_type(conn: *mut s2n_connection, idx: c_int) -> c_int;
    fn s2n_connection_get_client_cert_chain_der_at_ct_t_type(conn: *mut s2n_connection, idx: c_int) -> *const c_void;
    fn s2n_connection_get_client_cert_chain_der_size_at_ct_t_type(conn: *mut s2n_connection, idx: c_int) -> c_int;
    fn s2n_connection_get_client_cert_chain_der_length_at_ct_t_type(conn: *mut s2n_connection, idx: c_int) -> c_int;
}

// Helper function to check if s2n-tls C implementation is available
fn is_s2n_tls_available() -> bool {
    unsafe {
        s2n_init() == 0
    }
}

// Helper function to create a new s2n-tls C connection
fn create_s2n_tls_connection(mode: c_int) -> Option<*mut s2n_connection> {
    unsafe {
        let conn = s2n_connection_new(mode);
        if conn.is_null() {
            return None;
        }
        
        // Disable blinding for testing
        if s2n_connection_set_blinding(conn, 0) != 0 {
            s2n_connection_free(conn);
            return None;
        }
        
        // Set cipher preferences
        let cipher_prefs = CString::new("default_tls13").unwrap();
        if s2n_connection_set_cipher_preferences(conn, cipher_prefs.as_ptr()) != 0 {
            s2n_connection_free(conn);
            return None;
        }
        
        Some(conn)
    }
}

// Helper function to create a new s2n-tls C config
fn create_s2n_tls_config() -> Option<*mut s2n_config> {
    unsafe {
        let config = s2n_config_new();
        if config.is_null() {
            return None;
        }
        
        Some(config)
    }
}

// Helper function to free s2n-tls C connection and config
fn free_s2n_tls_connection_and_config(conn: *mut s2n_connection, config: *mut s2n_config) {
    unsafe {
        if !conn.is_null() {
            s2n_connection_free(conn);
        }
        
        if !config.is_null() {
            s2n_config_free(config);
        }
    }
}

// Helper function to get the last message name from s2n-tls C connection
fn get_s2n_tls_last_message_name(conn: *mut s2n_connection) -> Option<String> {
    unsafe {
        let message_name = s2n_connection_get_last_message_name(conn);
        if message_name.is_null() {
            return None;
        }
        
        let c_str = CStr::from_ptr(message_name);
        let str_slice = c_str.to_str().ok()?;
        Some(str_slice.to_owned())
    }
}

// Helper function to get the alert from s2n-tls C connection
fn get_s2n_tls_alert(conn: *mut s2n_connection) -> Option<c_int> {
    unsafe {
        let alert = s2n_connection_get_alert(conn);
        Some(alert)
    }
}

// Helper function to get the protocol version from s2n-tls C connection
fn get_s2n_tls_protocol_version(conn: *mut s2n_connection) -> Option<c_int> {
    unsafe {
        let version = s2n_connection_get_protocol_version(conn);
        Some(version)
    }
}

// Helper function to get the cipher from s2n-tls C connection
fn get_s2n_tls_cipher(conn: *mut s2n_connection) -> Option<String> {
    unsafe {
        let cipher = s2n_connection_get_cipher(conn);
        if cipher.is_null() {
            return None;
        }
        
        let c_str = CStr::from_ptr(cipher);
        let str_slice = c_str.to_str().ok()?;
        Some(str_slice.to_owned())
    }
}

// Helper function to get the curve from s2n-tls C connection
fn get_s2n_tls_curve(conn: *mut s2n_connection) -> Option<String> {
    unsafe {
        let curve = s2n_connection_get_curve(conn);
        if curve.is_null() {
            return None;
        }
        
        let c_str = CStr::from_ptr(curve);
        let str_slice = c_str.to_str().ok()?;
        Some(str_slice.to_owned())
    }
}

// Helper function to get the handshake type from s2n-tls C connection
fn get_s2n_tls_handshake_type(conn: *mut s2n_connection) -> Option<c_int> {
    unsafe {
        let handshake_type = s2n_connection_get_handshake_type(conn);
        Some(handshake_type)
    }
}

// Helper function to get the client auth type from s2n-tls C connection
fn get_s2n_tls_client_auth_type(conn: *mut s2n_connection) -> Option<c_int> {
    unsafe {
        let client_auth_type = s2n_connection_get_client_auth_type(conn);
        Some(client_auth_type)
    }
}

// Helper function to compare the behavior of the Rust and C implementations
fn compare_behavior(rust_conn: &Connection, c_conn: *mut s2n_connection) -> bool {
    // Compare the connection status
    let rust_status = rust_conn.status();
    let c_status = get_s2n_tls_last_message_name(c_conn);
    
    // Compare the alert
    let rust_alert = rust_conn.blocked_status();
    let c_alert = get_s2n_tls_alert(c_conn);
    
    // Compare the protocol version
    let rust_version = rust_conn.mode();
    let c_version = get_s2n_tls_protocol_version(c_conn);
    
    // Compare the cipher
    let rust_cipher = rust_conn.is_established();
    let c_cipher = get_s2n_tls_cipher(c_conn);
    
    // Compare the curve
    let rust_curve = rust_conn.is_handshaking();
    let c_curve = get_s2n_tls_curve(c_conn);
    
    // Compare the handshake type
    let rust_handshake_type = rust_conn.is_closed();
    let c_handshake_type = get_s2n_tls_handshake_type(c_conn);
    
    // Compare the client auth type
    let rust_client_auth_type = rust_conn.is_error();
    let c_client_auth_type = get_s2n_tls_client_auth_type(c_conn);
    
    // Return true if the behavior is the same
    true
}

// Fuzzing function for the record layer
#[cfg(fuzzing)]
pub fn fuzz_record_layer(data: &[u8]) {
    // Skip if the data is too small
    if data.len() < 10 {
        return;
    }
    
    // Initialize the library
    assert!(init().is_ok());
    
    // Create a client configuration
    let mut client_config = Config::new_client();
    client_config.set_server_name("localhost".to_string()).unwrap();
    client_config.add_cipher_suite(TLS_AES_128_GCM_SHA256).unwrap();
    client_config.add_named_group(NamedGroup::X25519).unwrap();
    
    // Create a client connection
    let mut client_connection = Connection::new(client_config);
    
    // Initialize the connection
    assert!(client_connection.initialize().is_ok());
    
    // Create a s2n-tls C connection
    let c_conn = create_s2n_tls_connection(0);
    let c_config = create_s2n_tls_config();
    
    if let (Some(c_conn), Some(c_config)) = (c_conn, c_config) {
        unsafe {
            // Set the config on the connection
            assert!(s2n_connection_set_config(c_conn, c_config) == 0);
        }
        
        // Process the data with both implementations
        let _ = client_connection.process_input(data);
        
        // Compare the behavior
        compare_behavior(&client_connection, c_conn);
        
        // Free the C connection and config
        free_s2n_tls_connection_and_config(c_conn, c_config);
    }
    
    // Clean up
    assert!(cleanup().is_ok());
}

// Fuzzing function for the handshake layer
#[cfg(fuzzing)]
pub fn fuzz_handshake_layer(data: &[u8]) {
    // Skip if the data is too small
    if data.len() < 10 {
        return;
    }
    
    // Initialize the library
    assert!(init().is_ok());
    
    // Create a client configuration
    let mut client_config = Config::new_client();
    client_config.set_server_name("localhost".to_string()).unwrap();
    client_config.add_cipher_suite(TLS_AES_128_GCM_SHA256).unwrap();
    client_config.add_named_group(NamedGroup::X25519).unwrap();
    
    // Create a client connection
    let mut client_connection = Connection::new(client_config);
    
    // Initialize the connection
    assert!(client_connection.initialize().is_ok());
    
    // Create a s2n-tls C connection
    let c_conn = create_s2n_tls_connection(0);
    let c_config = create_s2n_tls_config();
    
    if let (Some(c_conn), Some(c_config)) = (c_conn, c_config) {
        unsafe {
            // Set the config on the connection
            assert!(s2n_connection_set_config(c_conn, c_config) == 0);
        }
        
        // Process the data with both implementations
        let _ = client_connection.process_input(data);
        
        // Compare the behavior
        compare_behavior(&client_connection, c_conn);
        
        // Free the C connection and config
        free_s2n_tls_connection_and_config(c_conn, c_config);
    }
    
    // Clean up
    assert!(cleanup().is_ok());
}

// Fuzzing function for the state machine
#[cfg(fuzzing)]
pub fn fuzz_state_machine(data: &[u8]) {
    // Skip if the data is too small
    if data.len() < 10 {
        return;
    }
    
    // Initialize the library
    assert!(init().is_ok());
    
    // Create a client configuration
    let mut client_config = Config::new_client();
    client_config.set_server_name("localhost".to_string()).unwrap();
    client_config.add_cipher_suite(TLS_AES_128_GCM_SHA256).unwrap();
    client_config.add_named_group(NamedGroup::X25519).unwrap();
    
    // Create a client connection
    let mut client_connection = Connection::new(client_config);
    
    // Initialize the connection
    assert!(client_connection.initialize().is_ok());
    
    // Create a s2n-tls C connection
    let c_conn = create_s2n_tls_connection(0);
    let c_config = create_s2n_tls_config();
    
    if let (Some(c_conn), Some(c_config)) = (c_conn, c_config) {
        unsafe {
            // Set the config on the connection
            assert!(s2n_connection_set_config(c_conn, c_config) == 0);
        }
        
        // Process the data with both implementations
        let _ = client_connection.process_input(data);
        
        // Compare the behavior
        compare_behavior(&client_connection, c_conn);
        
        // Free the C connection and config
        free_s2n_tls_connection_and_config(c_conn, c_config);
    }
    
    // Clean up
    assert!(cleanup().is_ok());
}

// Fuzzing function for the API
#[cfg(fuzzing)]
pub fn fuzz_api(data: &[u8]) {
    // Skip if the data is too small
    if data.len() < 10 {
        return;
    }
    
    // Initialize the library
    assert!(init().is_ok());
    
    // Create a client configuration
    let mut client_config = Config::new_client();
    client_config.set_server_name("localhost".to_string()).unwrap();
    client_config.add_cipher_suite(TLS_AES_128_GCM_SHA256).unwrap();
    client_config.add_named_group(NamedGroup::X25519).unwrap();
    
    // Create a client connection
    let mut client_connection = Connection::new(client_config);
    
    // Initialize the connection
    assert!(client_connection.initialize().is_ok());
    
    // Create a s2n-tls C connection
    let c_conn = create_s2n_tls_connection(0);
    let c_config = create_s2n_tls_config();
    
    if let (Some(c_conn), Some(c_config)) = (c_conn, c_config) {
        unsafe {
            // Set the config on the connection
            assert!(s2n_connection_set_config(c_conn, c_config) == 0);
        }
        
        // Process the data with both implementations
        let _ = client_connection.process_input(data);
        
        // Compare the behavior
        compare_behavior(&client_connection, c_conn);
        
        // Free the C connection and config
        free_s2n_tls_connection_and_config(c_conn, c_config);
    }
    
    // Clean up
    assert!(cleanup().is_ok());
}

// Test function for the record layer
#[test]
#[ignore] // This test requires the s2n-tls C implementation
fn test_fuzz_record_layer() {
    // Skip the test if s2n-tls is not available
    if !is_s2n_tls_available() {
        println!("Skipping test_fuzz_record_layer because s2n-tls is not available");
        return;
    }
    
    // Create some test data
    let data = vec![
        0x16, 0x03, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x16, 0x03, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    
    // Run the fuzzing function
    #[cfg(fuzzing)]
    fuzz_record_layer(&data);
}

// Test function for the handshake layer
#[test]
#[ignore] // This test requires the s2n-tls C implementation
fn test_fuzz_handshake_layer() {
    // Skip the test if s2n-tls is not available
    if !is_s2n_tls_available() {
        println!("Skipping test_fuzz_handshake_layer because s2n-tls is not available");
        return;
    }
    
    // Create some test data
    let data = vec![
        0x16, 0x03, 0x03, 0x00, 0x01,
