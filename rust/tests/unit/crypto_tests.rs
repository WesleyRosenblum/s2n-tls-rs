// Crypto module unit tests

use s2n_tls_rs::{init, cleanup};
use s2n_tls_rs::crypto::{
    self, AeadAlgorithm, HashAlgorithm, CipherSuite, TrafficKeys,
    cipher_suites::{TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256},
};

#[test]
fn test_aead_algorithm_properties() {
    // Initialize the library
    assert!(init().is_ok());
    
    // Test AES-128-GCM properties
    assert_eq!(AeadAlgorithm::Aes128Gcm.key_size(), 16);
    assert_eq!(AeadAlgorithm::Aes128Gcm.nonce_size(), 12);
    assert_eq!(AeadAlgorithm::Aes128Gcm.tag_size(), 16);
    
    // Test AES-256-GCM properties
    assert_eq!(AeadAlgorithm::Aes256Gcm.key_size(), 32);
    assert_eq!(AeadAlgorithm::Aes256Gcm.nonce_size(), 12);
    assert_eq!(AeadAlgorithm::Aes256Gcm.tag_size(), 16);
    
    // Test ChaCha20-Poly1305 properties
    assert_eq!(AeadAlgorithm::ChaCha20Poly1305.key_size(), 32);
    assert_eq!(AeadAlgorithm::ChaCha20Poly1305.nonce_size(), 12);
    assert_eq!(AeadAlgorithm::ChaCha20Poly1305.tag_size(), 16);
    
    // Clean up
    assert!(cleanup().is_ok());
}

#[test]
fn test_hash_algorithm_properties() {
    // Initialize the library
    assert!(init().is_ok());
    
    // Test SHA-256 properties
    assert_eq!(HashAlgorithm::Sha256.output_size(), 32);
    
    // Test SHA-384 properties
    assert_eq!(HashAlgorithm::Sha384.output_size(), 48);
    
    // Clean up
    assert!(cleanup().is_ok());
}

#[test]
fn test_cipher_suite_lookup() {
    // Initialize the library
    assert!(init().is_ok());
    
    // Test TLS_AES_128_GCM_SHA256
    let cipher_suite = crypto::cipher_suites::from_value(&[0x13, 0x01]).unwrap();
    assert_eq!(cipher_suite.aead, AeadAlgorithm::Aes128Gcm);
    assert_eq!(cipher_suite.hash, HashAlgorithm::Sha256);
    assert_eq!(cipher_suite.value, [0x13, 0x01]);
    
    // Test TLS_AES_256_GCM_SHA384
    let cipher_suite = crypto::cipher_suites::from_value(&[0x13, 0x02]).unwrap();
    assert_eq!(cipher_suite.aead, AeadAlgorithm::Aes256Gcm);
    assert_eq!(cipher_suite.hash, HashAlgorithm::Sha384);
    assert_eq!(cipher_suite.value, [0x13, 0x02]);
    
    // Test TLS_CHACHA20_POLY1305_SHA256
    let cipher_suite = crypto::cipher_suites::from_value(&[0x13, 0x03]).unwrap();
    assert_eq!(cipher_suite.aead, AeadAlgorithm::ChaCha20Poly1305);
    assert_eq!(cipher_suite.hash, HashAlgorithm::Sha256);
    assert_eq!(cipher_suite.value, [0x13, 0x03]);
    
    // Test unknown cipher suite
    assert!(crypto::cipher_suites::from_value(&[0x00, 0x00]).is_none());
    
    // Clean up
    assert!(cleanup().is_ok());
}

#[test]
fn test_random_bytes() {
    // Initialize the library
    assert!(init().is_ok());
    
    // Generate random bytes
    let random1 = crypto::random_bytes(32).unwrap();
    let random2 = crypto::random_bytes(32).unwrap();
    
    // Verify the length
    assert_eq!(random1.len(), 32);
    assert_eq!(random2.len(), 32);
    
    // Verify that the two random values are different
    assert_ne!(random1, random2);
    
    // Clean up
    assert!(cleanup().is_ok());
}

#[test]
fn test_aead_encrypt_decrypt() {
    // Initialize the library
    assert!(init().is_ok());
    
    // Test vectors
    let key = vec![0x3f, 0xce, 0x51, 0x60, 0x09, 0xc2, 0x17, 0x27, 0xd0, 0xf2, 0xe4, 0xe8, 0x6e, 0xe4, 0x03, 0xbc];
    let nonce = vec![0x5d, 0x31, 0x3e, 0xb2, 0x67, 0x12, 0x76, 0xee, 0x13, 0x00, 0x0b, 0x30];
    let aad = vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x16, 0x03, 0x03, 0x00, 0x10];
    let plaintext = vec![0x14, 0x00, 0x00, 0x20, 0xb0, 0x38, 0xd4, 0xd4, 0xab, 0x08, 0x33, 0xa2, 0x7c, 0x0a, 0x1b, 0xd4];
    
    // Test AES-128-GCM
    let ciphertext = crypto::aead_encrypt(
        AeadAlgorithm::Aes128Gcm,
        &key,
        &nonce,
        &aad,
        &plaintext,
    ).unwrap();
    
    let decrypted = crypto::aead_decrypt(
        AeadAlgorithm::Aes128Gcm,
        &key,
        &nonce,
        &aad,
        &ciphertext,
    ).unwrap();
    
    assert_eq!(decrypted, plaintext);
    
    // Test with invalid key size
    let invalid_key = vec![0x00; 8]; // Too short
    let result = crypto::aead_encrypt(
        AeadAlgorithm::Aes128Gcm,
        &invalid_key,
        &nonce,
        &aad,
        &plaintext,
    );
    assert!(result.is_err());
    
    // Test with invalid nonce size
    let invalid_nonce = vec![0x00; 8]; // Too short
    let result = crypto::aead_encrypt(
        AeadAlgorithm::Aes128Gcm,
        &key,
        &invalid_nonce,
        &aad,
        &plaintext,
    );
    assert!(result.is_err());
    
    // Clean up
    assert!(cleanup().is_ok());
}

#[test]
fn test_hash() {
    // Initialize the library
    assert!(init().is_ok());
    
    // Test data
    let data = b"hello world";
    
    // Test SHA-256
    let sha256 = crypto::hash(HashAlgorithm::Sha256, data).unwrap();
    assert_eq!(sha256.len(), 32);
    
    // Test SHA-384
    let sha384 = crypto::hash(HashAlgorithm::Sha384, data).unwrap();
    assert_eq!(sha384.len(), 48);
    
    // Clean up
    assert!(cleanup().is_ok());
}

#[test]
fn test_hmac() {
    // Initialize the library
    assert!(init().is_ok());
    
    // Test data
    let key = b"key";
    let data = b"The quick brown fox jumps over the lazy dog";
    
    // Test HMAC-SHA-256
    let hmac_sha256 = crypto::hmac(HashAlgorithm::Sha256, key, data).unwrap();
    assert_eq!(hmac_sha256.len(), 32);
    
    // Test HMAC-SHA-384
    let hmac_sha384 = crypto::hmac(HashAlgorithm::Sha384, key, data).unwrap();
    assert_eq!(hmac_sha384.len(), 48);
    
    // Clean up
    assert!(cleanup().is_ok());
}

#[test]
fn test_hkdf() {
    // Initialize the library
    assert!(init().is_ok());
    
    // Test data
    let ikm = b"input key material";
    let salt = b"salt";
    let info = b"info";
    
    // Test HKDF with SHA-256
    let prk = crypto::hkdf_extract(HashAlgorithm::Sha256, Some(salt), ikm).unwrap();
    assert_eq!(prk.len(), 32);
    
    let okm = crypto::hkdf_expand(HashAlgorithm::Sha256, &prk, info, 42).unwrap();
    assert_eq!(okm.len(), 42);
    
    // Test HKDF with SHA-384
    let prk = crypto::hkdf_extract(HashAlgorithm::Sha384, Some(salt), ikm).unwrap();
    assert_eq!(prk.len(), 48);
    
    let okm = crypto::hkdf_expand(HashAlgorithm::Sha384, &prk, info, 42).unwrap();
    assert_eq!(okm.len(), 42);
    
    // Clean up
    assert!(cleanup().is_ok());
}

#[test]
fn test_derive_traffic_keys() {
    // Initialize the library
    assert!(init().is_ok());
    
    // Test data
    let secret = vec![0; 32]; // All zeros for simplicity
    let purpose = b"test purpose";
    
    // Test with TLS_AES_128_GCM_SHA256
    let traffic_keys = crypto::derive_traffic_keys(
        TLS_AES_128_GCM_SHA256,
        &secret,
        purpose,
    ).unwrap();
    
    assert_eq!(traffic_keys.key.len(), 16); // AES-128-GCM key size
    assert_eq!(traffic_keys.iv.len(), 12);  // AEAD nonce size
    
    // Test with TLS_AES_256_GCM_SHA384
    let secret = vec![0; 48]; // SHA-384 output size
    let traffic_keys = crypto::derive_traffic_keys(
        TLS_AES_256_GCM_SHA384,
        &secret,
        purpose,
    ).unwrap();
    
    assert_eq!(traffic_keys.key.len(), 32); // AES-256-GCM key size
    assert_eq!(traffic_keys.iv.len(), 12);  // AEAD nonce size
    
    // Test with invalid secret size
    let secret = vec![0; 16]; // Too short for SHA-256
    let result = crypto::derive_traffic_keys(
        TLS_AES_128_GCM_SHA256,
        &secret,
        purpose,
    );
    assert!(result.is_err());
    
    // Clean up
    assert!(cleanup().is_ok());
}

#[test]
fn test_construct_nonce() {
    // Initialize the library
    assert!(init().is_ok());
    
    // Test data
    let iv = vec![0x5d, 0x31, 0x3e, 0xb2, 0x67, 0x12, 0x76, 0xee, 0x13, 0x00, 0x0b, 0x30];
    
    // Test with sequence number 0
    let nonce = crypto::construct_nonce(&iv, 0).unwrap();
    assert_eq!(nonce, iv);
    
    // Test with sequence number 1
    let nonce = crypto::construct_nonce(&iv, 1).unwrap();
    let expected = vec![0x5d, 0x31, 0x3e, 0xb2, 0x67, 0x12, 0x76, 0xee, 0x13, 0x00, 0x0b, 0x31];
    assert_eq!(nonce, expected);
    
    // Test with sequence number 0x0123456789ABCDEF
    let nonce = crypto::construct_nonce(&iv, 0x0123456789ABCDEF).unwrap();
    let expected = vec![0x5d, 0x31, 0x3e, 0xb2, 0x67, 0x12, 0x76, 0xee ^ 0x01, 0x13 ^ 0x23, 0x00 ^ 0x45, 0x0b ^ 0x67, 0x30 ^ 0xEF];
    assert_eq!(nonce, expected);
    
    // Test with invalid IV size
    let invalid_iv = vec![0x00; 8]; // Too short
    let result = crypto::construct_nonce(&invalid_iv, 0);
    assert!(result.is_err());
    
    // Clean up
    assert!(cleanup().is_ok());
}
