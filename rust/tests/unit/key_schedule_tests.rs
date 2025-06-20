// Key schedule unit tests

use s2n_tls_rs::{init, cleanup};
use s2n_tls_rs::crypto::{HashAlgorithm, cipher_suites::TLS_AES_128_GCM_SHA256};
use s2n_tls_rs::handshake::KeySchedule;
use s2n_tls_rs::handshake::key_schedule::labels;

#[test]
fn test_key_schedule_initialization() {
    // Initialize the library
    assert!(init().is_ok());
    
    // Create a key schedule
    let key_schedule = KeySchedule::new(HashAlgorithm::Sha256).unwrap();
    
    // Verify the key schedule
    assert_eq!(key_schedule.hash_algorithm, HashAlgorithm::Sha256);
    assert_eq!(key_schedule.early_secret.len(), 32); // SHA-256 output size
    assert!(key_schedule.handshake_secret.is_none());
    assert!(key_schedule.master_secret.is_none());
    
    // Clean up
    assert!(cleanup().is_ok());
}

#[test]
fn test_key_schedule_with_psk() {
    // Initialize the library
    assert!(init().is_ok());
    
    // Create a PSK
    let psk = vec![
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    ];
    
    // Create a key schedule with PSK
    let key_schedule = KeySchedule::new_with_psk(HashAlgorithm::Sha256, &psk).unwrap();
    
    // Verify the key schedule
    assert_eq!(key_schedule.hash_algorithm, HashAlgorithm::Sha256);
    assert_eq!(key_schedule.early_secret.len(), 32); // SHA-256 output size
    assert!(key_schedule.handshake_secret.is_none());
    assert!(key_schedule.master_secret.is_none());
    
    // Clean up
    assert!(cleanup().is_ok());
}

#[test]
fn test_derive_handshake_secret() {
    // Initialize the library
    assert!(init().is_ok());
    
    // Create a key schedule
    let mut key_schedule = KeySchedule::new(HashAlgorithm::Sha256).unwrap();
    
    // Create a shared secret
    let shared_secret = vec![
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    ];
    
    // Derive the handshake secret
    assert!(key_schedule.derive_handshake_secret(&shared_secret).is_ok());
    
    // Verify the handshake secret
    assert!(key_schedule.handshake_secret.is_some());
    assert_eq!(key_schedule.handshake_secret.as_ref().unwrap().len(), 32); // SHA-256 output size
    
    // Clean up
    assert!(cleanup().is_ok());
}

#[test]
fn test_derive_master_secret() {
    // Initialize the library
    assert!(init().is_ok());
    
    // Create a key schedule
    let mut key_schedule = KeySchedule::new(HashAlgorithm::Sha256).unwrap();
    
    // Create a shared secret
    let shared_secret = vec![
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    ];
    
    // Derive the handshake secret
    assert!(key_schedule.derive_handshake_secret(&shared_secret).is_ok());
    
    // Derive the master secret
    assert!(key_schedule.derive_master_secret().is_ok());
    
    // Verify the master secret
    assert!(key_schedule.master_secret.is_some());
    assert_eq!(key_schedule.master_secret.as_ref().unwrap().len(), 32); // SHA-256 output size
    
    // Clean up
    assert!(cleanup().is_ok());
}

#[test]
fn test_derive_traffic_secrets() {
    // Initialize the library
    assert!(init().is_ok());
    
    // Create a key schedule
    let mut key_schedule = KeySchedule::new(HashAlgorithm::Sha256).unwrap();
    
    // Create a shared secret
    let shared_secret = vec![
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    ];
    
    // Create a transcript hash
    let transcript_hash = vec![
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
        0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
        0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40,
    ];
    
    // Derive the handshake secret
    assert!(key_schedule.derive_handshake_secret(&shared_secret).is_ok());
    
    // Derive the client handshake traffic secret
    let client_handshake_traffic_secret = key_schedule.derive_client_handshake_traffic_secret(&transcript_hash).unwrap();
    assert_eq!(client_handshake_traffic_secret.len(), 32); // SHA-256 output size
    
    // Derive the server handshake traffic secret
    let server_handshake_traffic_secret = key_schedule.derive_server_handshake_traffic_secret(&transcript_hash).unwrap();
    assert_eq!(server_handshake_traffic_secret.len(), 32); // SHA-256 output size
    
    // Derive the master secret
    assert!(key_schedule.derive_master_secret().is_ok());
    
    // Derive the client application traffic secret
    let client_application_traffic_secret = key_schedule.derive_client_application_traffic_secret(&transcript_hash).unwrap();
    assert_eq!(client_application_traffic_secret.len(), 32); // SHA-256 output size
    
    // Derive the server application traffic secret
    let server_application_traffic_secret = key_schedule.derive_server_application_traffic_secret(&transcript_hash).unwrap();
    assert_eq!(server_application_traffic_secret.len(), 32); // SHA-256 output size
    
    // Derive the exporter master secret
    let exporter_master_secret = key_schedule.derive_exporter_master_secret(&transcript_hash).unwrap();
    assert_eq!(exporter_master_secret.len(), 32); // SHA-256 output size
    
    // Derive the resumption master secret
    let resumption_master_secret = key_schedule.derive_resumption_master_secret(&transcript_hash).unwrap();
    assert_eq!(resumption_master_secret.len(), 32); // SHA-256 output size
    
    // Clean up
    assert!(cleanup().is_ok());
}

#[test]
fn test_derive_traffic_keys() {
    // Initialize the library
    assert!(init().is_ok());
    
    // Create a key schedule
    let key_schedule = KeySchedule::new(HashAlgorithm::Sha256).unwrap();
    
    // Create a traffic secret
    let traffic_secret = vec![
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    ];
    
    // Derive traffic keys
    let traffic_keys = key_schedule.derive_traffic_keys(TLS_AES_128_GCM_SHA256, &traffic_secret).unwrap();
    
    // Verify the traffic keys
    assert_eq!(traffic_keys.key.len(), 16); // AES-128-GCM key size
    assert_eq!(traffic_keys.iv.len(), 12); // AEAD nonce size
    
    // Clean up
    assert!(cleanup().is_ok());
}

#[test]
fn test_derive_finished_key() {
    // Initialize the library
    assert!(init().is_ok());
    
    // Create a key schedule
    let key_schedule = KeySchedule::new(HashAlgorithm::Sha256).unwrap();
    
    // Create a traffic secret
    let traffic_secret = vec![
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    ];
    
    // Derive finished key
    let finished_key = key_schedule.derive_finished_key(&traffic_secret).unwrap();
    
    // Verify the finished key
    assert_eq!(finished_key.len(), 32); // SHA-256 output size
    
    // Clean up
    assert!(cleanup().is_ok());
}

#[test]
fn test_hkdf_expand_label() {
    // Initialize the library
    assert!(init().is_ok());
    
    // Create a secret
    let secret = vec![
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    ];
    
    // Create a context
    let context = vec![
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
        0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
    ];
    
    // Expand label
    let expanded = s2n_tls_rs::crypto::hkdf_expand_label(
        HashAlgorithm::Sha256,
        &secret,
        labels::KEY,
        &context,
        16,
    ).unwrap();
    
    // Verify the expanded label
    assert_eq!(expanded.len(), 16);
    
    // Clean up
    assert!(cleanup().is_ok());
}

#[test]
fn test_key_schedule_error_handling() {
    // Initialize the library
    assert!(init().is_ok());
    
    // Create a key schedule
    let key_schedule = KeySchedule::new(HashAlgorithm::Sha256).unwrap();
    
    // Create a transcript hash
    let transcript_hash = vec![
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
        0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
        0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40,
    ];
    
    // Attempt to derive the client handshake traffic secret without deriving the handshake secret
    assert!(key_schedule.derive_client_handshake_traffic_secret(&transcript_hash).is_err());
    
    // Attempt to derive the server handshake traffic secret without deriving the handshake secret
    assert!(key_schedule.derive_server_handshake_traffic_secret(&transcript_hash).is_err());
    
    // Attempt to derive the master secret without deriving the handshake secret
    assert!(key_schedule.derive_master_secret().is_err());
    
    // Attempt to derive the client application traffic secret without deriving the master secret
    assert!(key_schedule.derive_client_application_traffic_secret(&transcript_hash).is_err());
    
    // Attempt to derive the server application traffic secret without deriving the master secret
    assert!(key_schedule.derive_server_application_traffic_secret(&transcript_hash).is_err());
    
    // Attempt to derive the exporter master secret without deriving the master secret
    assert!(key_schedule.derive_exporter_master_secret(&transcript_hash).is_err());
    
    // Attempt to derive the resumption master secret without deriving the master secret
    assert!(key_schedule.derive_resumption_master_secret(&transcript_hash).is_err());
    
    // Clean up
    assert!(cleanup().is_ok());
}
