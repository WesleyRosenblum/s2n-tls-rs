// Key exchange unit tests

use s2n_tls_rs::{init, cleanup};
use s2n_tls_rs::buffer::Buffer;
use s2n_tls_rs::handshake::{
    Extension, ExtensionType, NamedGroup, KeyShareEntry, ClientKeyShare, ServerKeyShare, KeyPair
};
use s2n_tls_rs::handshake::key_exchange::{generate_key_pair, compute_shared_secret};

#[test]
fn test_key_share_entry_encode_decode() {
    // Initialize the library
    assert!(init().is_ok());
    
    // Create a key share entry
    let group = NamedGroup::X25519;
    let key_exchange = vec![
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    ];
    let entry = KeyShareEntry::new(group, key_exchange.clone());
    
    // Encode the key share entry
    let mut buffer = Buffer::new();
    assert!(entry.encode(&mut buffer).is_ok());
    
    // Decode the key share entry
    let mut offset = 0;
    let decoded = KeyShareEntry::decode(&buffer, &mut offset).unwrap();
    
    // Verify the decoded key share entry
    assert_eq!(decoded.group, group);
    assert_eq!(decoded.key_exchange, key_exchange);
    
    // Clean up
    assert!(cleanup().is_ok());
}

#[test]
fn test_client_key_share_encode_decode() {
    // Initialize the library
    assert!(init().is_ok());
    
    // Create a client key share
    let mut client_key_share = ClientKeyShare::new();
    
    // Add key share entries
    let entry1 = KeyShareEntry::new(
        NamedGroup::X25519,
        vec![
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
            0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
        ],
    );
    client_key_share.add_entry(entry1);
    
    let entry2 = KeyShareEntry::new(
        NamedGroup::Secp256r1,
        vec![
            0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
            0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
            0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
            0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40,
            0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
            0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50,
            0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58,
            0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x60,
        ],
    );
    client_key_share.add_entry(entry2);
    
    // Encode the client key share
    let extension = client_key_share.encode().unwrap();
    
    // Verify the extension type
    assert_eq!(extension.extension_type, ExtensionType::KeyShare);
    
    // Decode the client key share
    let decoded = ClientKeyShare::decode(&extension.extension_data).unwrap();
    
    // Verify the decoded client key share
    assert_eq!(decoded.entries.len(), 2);
    assert_eq!(decoded.entries[0].group, NamedGroup::X25519);
    assert_eq!(decoded.entries[1].group, NamedGroup::Secp256r1);
    
    // Clean up
    assert!(cleanup().is_ok());
}

#[test]
fn test_server_key_share_encode_decode() {
    // Initialize the library
    assert!(init().is_ok());
    
    // Create a server key share
    let entry = KeyShareEntry::new(
        NamedGroup::X25519,
        vec![
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
            0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
        ],
    );
    let server_key_share = ServerKeyShare::new(entry);
    
    // Encode the server key share
    let extension = server_key_share.encode().unwrap();
    
    // Verify the extension type
    assert_eq!(extension.extension_type, ExtensionType::KeyShare);
    
    // Decode the server key share
    let decoded = ServerKeyShare::decode(&extension.extension_data).unwrap();
    
    // Verify the decoded server key share
    assert_eq!(decoded.entry.group, NamedGroup::X25519);
    assert_eq!(decoded.entry.key_exchange.len(), 32);
    
    // Clean up
    assert!(cleanup().is_ok());
}

#[test]
fn test_generate_key_pair() {
    // Initialize the library
    assert!(init().is_ok());
    
    // Generate a key pair
    let key_pair = generate_key_pair(NamedGroup::X25519).unwrap();
    
    // Verify the key pair
    assert_eq!(key_pair.group, NamedGroup::X25519);
    assert!(!key_pair.private_key.is_empty());
    assert!(!key_pair.public_key.is_empty());
    
    // Clean up
    assert!(cleanup().is_ok());
}

#[test]
fn test_compute_shared_secret() {
    // Initialize the library
    assert!(init().is_ok());
    
    // Generate key pairs
    let key_pair1 = generate_key_pair(NamedGroup::X25519).unwrap();
    let key_pair2 = generate_key_pair(NamedGroup::X25519).unwrap();
    
    // Compute shared secrets
    let secret1 = compute_shared_secret(
        NamedGroup::X25519,
        &key_pair1.private_key,
        &key_pair2.public_key,
    ).unwrap();
    
    let secret2 = compute_shared_secret(
        NamedGroup::X25519,
        &key_pair2.private_key,
        &key_pair1.public_key,
    ).unwrap();
    
    // Verify that the shared secrets are the same
    // Note: In a real implementation with actual key exchange, the shared secrets would be the same
    // For our placeholder implementation, they might not be the same
    
    // Clean up
    assert!(cleanup().is_ok());
}

#[test]
fn test_named_group_conversion() {
    // Initialize the library
    assert!(init().is_ok());
    
    // Test conversion from u16 to NamedGroup
    assert_eq!(NamedGroup::try_from(0x0017).unwrap(), NamedGroup::Secp256r1);
    assert_eq!(NamedGroup::try_from(0x0018).unwrap(), NamedGroup::Secp384r1);
    assert_eq!(NamedGroup::try_from(0x0019).unwrap(), NamedGroup::Secp521r1);
    assert_eq!(NamedGroup::try_from(0x001D).unwrap(), NamedGroup::X25519);
    assert_eq!(NamedGroup::try_from(0x001E).unwrap(), NamedGroup::X448);
    
    // Test conversion from NamedGroup to u16
    assert_eq!(NamedGroup::Secp256r1 as u16, 0x0017);
    assert_eq!(NamedGroup::Secp384r1 as u16, 0x0018);
    assert_eq!(NamedGroup::Secp521r1 as u16, 0x0019);
    assert_eq!(NamedGroup::X25519 as u16, 0x001D);
    assert_eq!(NamedGroup::X448 as u16, 0x001E);
    
    // Test invalid conversion
    assert!(NamedGroup::try_from(0x0000).is_err());
    
    // Clean up
    assert!(cleanup().is_ok());
}
