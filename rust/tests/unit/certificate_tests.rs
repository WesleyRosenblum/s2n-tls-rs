// Certificate handling unit tests

use s2n_tls_rs::{init, cleanup};
use s2n_tls_rs::buffer::Buffer;
use s2n_tls_rs::handshake::{
    Certificate, CertificateEntry, CertificateVerificationContext, Extension, ExtensionType
};
use s2n_tls_rs::handshake::certificate::{verify_certificate_chain, verify_hostname};

#[test]
fn test_certificate_entry_creation() {
    // Initialize the library
    assert!(init().is_ok());
    
    // Create a certificate entry
    let cert_data = vec![
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    ];
    let mut entry = CertificateEntry::new(cert_data.clone());
    
    // Add an extension
    let extension = Extension::new(
        ExtensionType::ServerName,
        vec![0x00, 0x01, 0x02],
    );
    entry.add_extension(extension.clone());
    
    // Verify the certificate entry
    assert_eq!(entry.cert_data, cert_data);
    assert_eq!(entry.extensions.len(), 1);
    assert_eq!(entry.extensions[0], extension);
    
    // Clean up
    assert!(cleanup().is_ok());
}

#[test]
fn test_certificate_entry_encode_decode() {
    // Initialize the library
    assert!(init().is_ok());
    
    // Create a certificate entry
    let cert_data = vec![
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    ];
    let mut entry = CertificateEntry::new(cert_data.clone());
    
    // Add an extension
    let extension = Extension::new(
        ExtensionType::ServerName,
        vec![0x00, 0x01, 0x02],
    );
    entry.add_extension(extension);
    
    // Encode the certificate entry
    let mut buffer = Buffer::new();
    assert!(entry.encode(&mut buffer).is_ok());
    
    // Decode the certificate entry
    let mut offset = 0;
    let decoded = CertificateEntry::decode(&buffer, &mut offset).unwrap();
    
    // Verify the decoded certificate entry
    assert_eq!(decoded.cert_data, cert_data);
    assert_eq!(decoded.extensions.len(), 1);
    assert_eq!(decoded.extensions[0].extension_type, ExtensionType::ServerName);
    
    // Clean up
    assert!(cleanup().is_ok());
}

#[test]
fn test_certificate_creation() {
    // Initialize the library
    assert!(init().is_ok());
    
    // Create a certificate message
    let mut certificate = Certificate::new();
    
    // Set the certificate request context
    let context = vec![0x01, 0x02, 0x03];
    certificate.set_certificate_request_context(context.clone());
    
    // Add a certificate entry
    let cert_data = vec![
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    ];
    let entry = CertificateEntry::new(cert_data.clone());
    certificate.add_certificate_entry(entry);
    
    // Verify the certificate message
    assert_eq!(certificate.certificate_request_context, context);
    assert_eq!(certificate.certificate_list.len(), 1);
    assert_eq!(certificate.certificate_list[0].cert_data, cert_data);
    
    // Clean up
    assert!(cleanup().is_ok());
}

#[test]
fn test_certificate_encode_decode() {
    // Initialize the library
    assert!(init().is_ok());
    
    // Create a certificate message
    let mut certificate = Certificate::new();
    
    // Set the certificate request context
    let context = vec![0x01, 0x02, 0x03];
    certificate.set_certificate_request_context(context);
    
    // Add certificate entries
    let cert_data1 = vec![
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    ];
    let mut entry1 = CertificateEntry::new(cert_data1);
    entry1.add_extension(Extension::new(
        ExtensionType::ServerName,
        vec![0x00, 0x01, 0x02],
    ));
    certificate.add_certificate_entry(entry1);
    
    let cert_data2 = vec![
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    ];
    let entry2 = CertificateEntry::new(cert_data2);
    certificate.add_certificate_entry(entry2);
    
    // Encode the certificate message
    let mut buffer = Buffer::new();
    assert!(certificate.encode(&mut buffer).is_ok());
    
    // Decode the certificate message
    let mut offset = 0;
    let decoded = Certificate::decode(&buffer, &mut offset).unwrap();
    
    // Verify the decoded certificate message
    assert_eq!(decoded.certificate_request_context.len(), 3);
    assert_eq!(decoded.certificate_list.len(), 2);
    assert_eq!(decoded.certificate_list[0].extensions.len(), 1);
    assert_eq!(decoded.certificate_list[0].extensions[0].extension_type, ExtensionType::ServerName);
    
    // Clean up
    assert!(cleanup().is_ok());
}

#[test]
fn test_certificate_verification_context() {
    // Initialize the library
    assert!(init().is_ok());
    
    // Create a certificate verification context
    let mut context = CertificateVerificationContext::new();
    
    // Add a trusted CA certificate
    let ca_cert = vec![
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    ];
    context.add_trusted_ca(ca_cert.clone());
    
    // Set the server name
    context.set_server_name("example.com".to_string());
    
    // Enable OCSP stapling
    context.enable_ocsp_stapling();
    
    // Verify the certificate verification context
    assert_eq!(context.trusted_cas.len(), 1);
    assert_eq!(context.trusted_cas[0], ca_cert);
    assert_eq!(context.server_name, Some("example.com".to_string()));
    assert!(context.ocsp_stapling_enabled);
    
    // Clean up
    assert!(cleanup().is_ok());
}

#[test]
fn test_verify_certificate_chain() {
    // Initialize the library
    assert!(init().is_ok());
    
    // Create a certificate chain
    let cert_data1 = vec![
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    ];
    let entry1 = CertificateEntry::new(cert_data1);
    
    let cert_data2 = vec![
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    ];
    let entry2 = CertificateEntry::new(cert_data2);
    
    let cert_chain = vec![entry1, entry2];
    
    // Create a certificate verification context
    let mut context = CertificateVerificationContext::new();
    context.add_trusted_ca(vec![
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
        0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
    ]);
    context.set_server_name("example.com".to_string());
    
    // Verify the certificate chain
    // Note: This is a placeholder implementation, so it should always succeed
    assert!(verify_certificate_chain(&cert_chain, &context).is_ok());
    
    // Test with an empty certificate chain
    let empty_chain: Vec<CertificateEntry> = Vec::new();
    assert!(verify_certificate_chain(&empty_chain, &context).is_err());
    
    // Clean up
    assert!(cleanup().is_ok());
}

#[test]
fn test_verify_hostname() {
    // Initialize the library
    assert!(init().is_ok());
    
    // Create a certificate
    let cert_data = vec![
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    ];
    
    // Verify the hostname
    // Note: This is a placeholder implementation, so it should always succeed
    assert!(verify_hostname(&cert_data, "example.com").is_ok());
    
    // Clean up
    assert!(cleanup().is_ok());
}

#[test]
fn test_certificate_max_chain_length() {
    // Initialize the library
    assert!(init().is_ok());
    
    // Create a certificate message
    let mut certificate = Certificate::new();
    
    // Add the maximum number of certificate entries
    for i in 0..s2n_tls_rs::handshake::certificate::MAX_CERT_CHAIN_LEN {
        let cert_data = vec![i as u8; 16];
        let entry = CertificateEntry::new(cert_data);
        certificate.add_certificate_entry(entry);
    }
    
    // Encode the certificate message
    let mut buffer = Buffer::new();
    assert!(certificate.encode(&mut buffer).is_ok());
    
    // Decode the certificate message
    let mut offset = 0;
    let decoded = Certificate::decode(&buffer, &mut offset).unwrap();
    
    // Verify the decoded certificate message
    assert_eq!(decoded.certificate_list.len(), s2n_tls_rs::handshake::certificate::MAX_CERT_CHAIN_LEN);
    
    // Clean up
    assert!(cleanup().is_ok());
}
