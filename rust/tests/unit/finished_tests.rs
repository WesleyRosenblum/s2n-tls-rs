// Finished message unit tests

use s2n_tls_rs::{init, cleanup};
use s2n_tls_rs::buffer::Buffer;
use s2n_tls_rs::crypto::HashAlgorithm;
use s2n_tls_rs::handshake::{
    Finished, HandshakeVerificationContext, TranscriptHashContext
};
use s2n_tls_rs::handshake::finished::{
    compute_verify_data, verify_finished_data
};

#[test]
fn test_finished_creation() {
    // Initialize the library
    assert!(init().is_ok());
    
    // Create a Finished message
    let verify_data = vec![
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    ];
    let finished = Finished::new(verify_data.clone());
    
    // Verify the Finished message
    assert_eq!(finished.verify_data, verify_data);
    
    // Clean up
    assert!(cleanup().is_ok());
}

#[test]
fn test_finished_encode_decode() {
    // Initialize the library
    assert!(init().is_ok());
    
    // Create a Finished message
    let verify_data = vec![
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    ];
    let finished = Finished::new(verify_data.clone());
    
    // Encode the Finished message
    let mut buffer = Buffer::new();
    assert!(finished.encode(&mut buffer).is_ok());
    
    // Decode the Finished message
    let mut offset = 0;
    let decoded = Finished::decode(&buffer, &mut offset).unwrap();
    
    // Verify the decoded Finished message
    assert_eq!(decoded.verify_data, verify_data);
    
    // Clean up
    assert!(cleanup().is_ok());
}

#[test]
fn test_compute_verify_data() {
    // Initialize the library
    assert!(init().is_ok());
    
    // Create a finished key
    let finished_key = vec![
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
    
    // Compute the verify data
    let verify_data = compute_verify_data(&finished_key, &transcript_hash).unwrap();
    
    // Verify the verify data
    assert_eq!(verify_data.len(), 32); // SHA-256 output size
    
    // Clean up
    assert!(cleanup().is_ok());
}

#[test]
fn test_verify_finished_data() {
    // Initialize the library
    assert!(init().is_ok());
    
    // Create a finished key
    let finished_key = vec![
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
    
    // Compute the verify data
    let verify_data = compute_verify_data(&finished_key, &transcript_hash).unwrap();
    
    // Verify the finished data
    assert!(verify_finished_data(&finished_key, &transcript_hash, &verify_data).is_ok());
    
    // Verify with incorrect data
    let incorrect_data = vec![0; 32];
    assert!(verify_finished_data(&finished_key, &transcript_hash, &incorrect_data).is_err());
    
    // Clean up
    assert!(cleanup().is_ok());
}

#[test]
fn test_transcript_hash_context() {
    // Initialize the library
    assert!(init().is_ok());
    
    // Create a transcript hash context
    let mut context = TranscriptHashContext::new(HashAlgorithm::Sha256);
    
    // Update the transcript hash
    let message1 = vec![
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    ];
    assert!(context.update(&message1).is_ok());
    
    let message2 = vec![
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    ];
    assert!(context.update(&message2).is_ok());
    
    // Get the hash
    let hash = context.get_hash().unwrap();
    
    // Verify the hash
    assert_eq!(hash.len(), 32); // SHA-256 output size
    
    // Clean up
    assert!(cleanup().is_ok());
}

#[test]
fn test_handshake_verification_context() {
    // Initialize the library
    assert!(init().is_ok());
    
    // Create a handshake verification context
    let mut context = HandshakeVerificationContext::new(HashAlgorithm::Sha256);
    
    // Set the client finished key
    let client_finished_key = vec![
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    ];
    context.set_client_finished_key(client_finished_key);
    
    // Set the server finished key
    let server_finished_key = vec![
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
        0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
        0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40,
    ];
    context.set_server_finished_key(server_finished_key);
    
    // Update the transcript hash
    let message = vec![
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    ];
    assert!(context.update_transcript(&message).is_ok());
    
    // Get the transcript hash
    let transcript_hash = context.get_transcript_hash().unwrap();
    assert_eq!(transcript_hash.len(), 32); // SHA-256 output size
    
    // Clean up
    assert!(cleanup().is_ok());
}

#[test]
fn test_create_verify_finished() {
    // Initialize the library
    assert!(init().is_ok());
    
    // Create a handshake verification context
    let mut context = HandshakeVerificationContext::new(HashAlgorithm::Sha256);
    
    // Set the client finished key
    let client_finished_key = vec![
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    ];
    context.set_client_finished_key(client_finished_key);
    
    // Set the server finished key
    let server_finished_key = vec![
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
        0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
        0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40,
    ];
    context.set_server_finished_key(server_finished_key);
    
    // Update the transcript hash
    let message = vec![
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    ];
    assert!(context.update_transcript(&message).is_ok());
    
    // Create a client Finished message
    let client_finished = context.create_client_finished().unwrap();
    
    // Verify the client Finished message
    assert!(context.verify_client_finished(&client_finished).is_ok());
    
    // Create a server Finished message
    let server_finished = context.create_server_finished().unwrap();
    
    // Verify the server Finished message
    assert!(context.verify_server_finished(&server_finished).is_ok());
    
    // Verify with incorrect Finished message
    let incorrect_finished = Finished::new(vec![0; 32]);
    assert!(context.verify_client_finished(&incorrect_finished).is_err());
    assert!(context.verify_server_finished(&incorrect_finished).is_err());
    
    // Clean up
    assert!(cleanup().is_ok());
}

#[test]
fn test_handshake_verification_error_handling() {
    // Initialize the library
    assert!(init().is_ok());
    
    // Create a handshake verification context
    let context = HandshakeVerificationContext::new(HashAlgorithm::Sha256);
    
    // Attempt to create a client Finished message without setting the client finished key
    assert!(context.create_client_finished().is_err());
    
    // Attempt to create a server Finished message without setting the server finished key
    assert!(context.create_server_finished().is_err());
    
    // Attempt to verify a client Finished message without setting the client finished key
    let finished = Finished::new(vec![0; 32]);
    assert!(context.verify_client_finished(&finished).is_err());
    
    // Attempt to verify a server Finished message without setting the server finished key
    assert!(context.verify_server_finished(&finished).is_err());
    
    // Clean up
    assert!(cleanup().is_ok());
}
