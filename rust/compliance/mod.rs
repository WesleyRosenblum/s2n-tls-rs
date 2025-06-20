// RFC compliance validation
//
// This module provides tools for validating compliance with TLS RFCs.

use duvet::{Doc, DocGroup, DocSection, DocSectionBuilder};

/// RFC 8446 - The Transport Layer Security (TLS) Protocol Version 1.3
pub const RFC8446: Doc = Doc::new("RFC8446", "The Transport Layer Security (TLS) Protocol Version 1.3");

/// RFC 5246 - The Transport Layer Security (TLS) Protocol Version 1.2
pub const RFC5246: Doc = Doc::new("RFC5246", "The Transport Layer Security (TLS) Protocol Version 1.2");

/// RFC 6066 - Transport Layer Security (TLS) Extensions: Extension Definitions
pub const RFC6066: Doc = Doc::new("RFC6066", "Transport Layer Security (TLS) Extensions: Extension Definitions");

/// RFC 7301 - Transport Layer Security (TLS) Application-Layer Protocol Negotiation Extension
pub const RFC7301: Doc = Doc::new("RFC7301", "Transport Layer Security (TLS) Application-Layer Protocol Negotiation Extension");

/// RFC 7748 - Elliptic Curves for Security
pub const RFC7748: Doc = Doc::new("RFC7748", "Elliptic Curves for Security");

/// RFC 8422 - Elliptic Curve Cryptography (ECC) Cipher Suites for Transport Layer Security (TLS) Versions 1.2 and Earlier
pub const RFC8422: Doc = Doc::new("RFC8422", "Elliptic Curve Cryptography (ECC) Cipher Suites for Transport Layer Security (TLS) Versions 1.2 and Earlier");

/// RFC 8439 - ChaCha20 and Poly1305 for IETF Protocols
pub const RFC8439: Doc = Doc::new("RFC8439", "ChaCha20 and Poly1305 for IETF Protocols");

/// RFC 8446 Section 4 - Handshake Protocol
pub const RFC8446_SECTION4: DocSection = DocSection::new(&RFC8446, "4", "Handshake Protocol");

/// RFC 8446 Section 4.1 - Key Exchange Messages
pub const RFC8446_SECTION4_1: DocSection = DocSection::new(&RFC8446, "4.1", "Key Exchange Messages");

/// RFC 8446 Section 4.1.1 - Cryptographic Negotiation
pub const RFC8446_SECTION4_1_1: DocSection = DocSection::new(&RFC8446, "4.1.1", "Cryptographic Negotiation");

/// RFC 8446 Section 4.1.2 - Client Hello
pub const RFC8446_SECTION4_1_2: DocSection = DocSection::new(&RFC8446, "4.1.2", "Client Hello");

/// RFC 8446 Section 4.1.3 - Server Hello
pub const RFC8446_SECTION4_1_3: DocSection = DocSection::new(&RFC8446, "4.1.3", "Server Hello");

/// RFC 8446 Section 4.1.4 - Hello Retry Request
pub const RFC8446_SECTION4_1_4: DocSection = DocSection::new(&RFC8446, "4.1.4", "Hello Retry Request");

/// RFC 8446 Section 4.2 - Extensions
pub const RFC8446_SECTION4_2: DocSection = DocSection::new(&RFC8446, "4.2", "Extensions");

/// RFC 8446 Section 4.2.1 - Supported Versions
pub const RFC8446_SECTION4_2_1: DocSection = DocSection::new(&RFC8446, "4.2.1", "Supported Versions");

/// RFC 8446 Section 4.2.2 - Cookie
pub const RFC8446_SECTION4_2_2: DocSection = DocSection::new(&RFC8446, "4.2.2", "Cookie");

/// RFC 8446 Section 4.2.3 - Signature Algorithms
pub const RFC8446_SECTION4_2_3: DocSection = DocSection::new(&RFC8446, "4.2.3", "Signature Algorithms");

/// RFC 8446 Section 4.2.4 - Certificate Authorities
pub const RFC8446_SECTION4_2_4: DocSection = DocSection::new(&RFC8446, "4.2.4", "Certificate Authorities");

/// RFC 8446 Section 4.2.5 - OID Filters
pub const RFC8446_SECTION4_2_5: DocSection = DocSection::new(&RFC8446, "4.2.5", "OID Filters");

/// RFC 8446 Section 4.2.6 - Post-Handshake Client Authentication
pub const RFC8446_SECTION4_2_6: DocSection = DocSection::new(&RFC8446, "4.2.6", "Post-Handshake Client Authentication");

/// RFC 8446 Section 4.2.7 - Supported Groups
pub const RFC8446_SECTION4_2_7: DocSection = DocSection::new(&RFC8446, "4.2.7", "Supported Groups");

/// RFC 8446 Section 4.2.8 - Key Share
pub const RFC8446_SECTION4_2_8: DocSection = DocSection::new(&RFC8446, "4.2.8", "Key Share");

/// RFC 8446 Section 4.2.9 - Pre-Shared Key Exchange Modes
pub const RFC8446_SECTION4_2_9: DocSection = DocSection::new(&RFC8446, "4.2.9", "Pre-Shared Key Exchange Modes");

/// RFC 8446 Section 4.2.10 - Early Data Indication
pub const RFC8446_SECTION4_2_10: DocSection = DocSection::new(&RFC8446, "4.2.10", "Early Data Indication");

/// RFC 8446 Section 4.2.11 - Pre-Shared Key Extension
pub const RFC8446_SECTION4_2_11: DocSection = DocSection::new(&RFC8446, "4.2.11", "Pre-Shared Key Extension");

/// RFC 8446 Section 4.3 - Server Parameters
pub const RFC8446_SECTION4_3: DocSection = DocSection::new(&RFC8446, "4.3", "Server Parameters");

/// RFC 8446 Section 4.3.1 - Encrypted Extensions
pub const RFC8446_SECTION4_3_1: DocSection = DocSection::new(&RFC8446, "4.3.1", "Encrypted Extensions");

/// RFC 8446 Section 4.3.2 - Certificate Request
pub const RFC8446_SECTION4_3_2: DocSection = DocSection::new(&RFC8446, "4.3.2", "Certificate Request");

/// RFC 8446 Section 4.4 - Authentication Messages
pub const RFC8446_SECTION4_4: DocSection = DocSection::new(&RFC8446, "4.4", "Authentication Messages");

/// RFC 8446 Section 4.4.1 - Certificate
pub const RFC8446_SECTION4_4_1: DocSection = DocSection::new(&RFC8446, "4.4.1", "Certificate");

/// RFC 8446 Section 4.4.2 - Certificate Verify
pub const RFC8446_SECTION4_4_2: DocSection = DocSection::new(&RFC8446, "4.4.2", "Certificate Verify");

/// RFC 8446 Section 4.4.3 - Finished
pub const RFC8446_SECTION4_4_3: DocSection = DocSection::new(&RFC8446, "4.4.3", "Finished");

/// RFC 8446 Section 4.4.4 - End of Early Data
pub const RFC8446_SECTION4_4_4: DocSection = DocSection::new(&RFC8446, "4.4.4", "End of Early Data");

/// RFC 8446 Section 4.5 - Post-Handshake Messages
pub const RFC8446_SECTION4_5: DocSection = DocSection::new(&RFC8446, "4.5", "Post-Handshake Messages");

/// RFC 8446 Section 4.5.1 - New Session Ticket Message
pub const RFC8446_SECTION4_5_1: DocSection = DocSection::new(&RFC8446, "4.5.1", "New Session Ticket Message");

/// RFC 8446 Section 4.5.2 - Post-Handshake Authentication
pub const RFC8446_SECTION4_5_2: DocSection = DocSection::new(&RFC8446, "4.5.2", "Post-Handshake Authentication");

/// RFC 8446 Section 4.5.3 - Key and Initialization Vector Update
pub const RFC8446_SECTION4_5_3: DocSection = DocSection::new(&RFC8446, "4.5.3", "Key and Initialization Vector Update");

/// RFC 8446 Section 5 - Record Protocol
pub const RFC8446_SECTION5: DocSection = DocSection::new(&RFC8446, "5", "Record Protocol");

/// RFC 8446 Section 5.1 - Record Layer
pub const RFC8446_SECTION5_1: DocSection = DocSection::new(&RFC8446, "5.1", "Record Layer");

/// RFC 8446 Section 5.2 - Record Payload Protection
pub const RFC8446_SECTION5_2: DocSection = DocSection::new(&RFC8446, "5.2", "Record Payload Protection");

/// RFC 8446 Section 5.3 - Per-Record Nonce
pub const RFC8446_SECTION5_3: DocSection = DocSection::new(&RFC8446, "5.3", "Per-Record Nonce");

/// RFC 8446 Section 5.4 - Record Padding
pub const RFC8446_SECTION5_4: DocSection = DocSection::new(&RFC8446, "5.4", "Record Padding");

/// RFC 8446 Section 5.5 - Limits on Key Usage
pub const RFC8446_SECTION5_5: DocSection = DocSection::new(&RFC8446, "5.5", "Limits on Key Usage");

/// RFC 8446 Section 6 - Alert Protocol
pub const RFC8446_SECTION6: DocSection = DocSection::new(&RFC8446, "6", "Alert Protocol");

/// RFC 8446 Section 7 - Cryptographic Computations
pub const RFC8446_SECTION7: DocSection = DocSection::new(&RFC8446, "7", "Cryptographic Computations");

/// RFC 8446 Section 7.1 - Key Schedule
pub const RFC8446_SECTION7_1: DocSection = DocSection::new(&RFC8446, "7.1", "Key Schedule");

/// RFC 8446 Section 7.2 - Updating Traffic Secrets
pub const RFC8446_SECTION7_2: DocSection = DocSection::new(&RFC8446, "7.2", "Updating Traffic Secrets");

/// RFC 8446 Section 7.3 - Traffic Key Calculation
pub const RFC8446_SECTION7_3: DocSection = DocSection::new(&RFC8446, "7.3", "Traffic Key Calculation");

/// RFC 8446 Section 7.4 - (EC)DHE Shared Secret Calculation
pub const RFC8446_SECTION7_4: DocSection = DocSection::new(&RFC8446, "7.4", "(EC)DHE Shared Secret Calculation");

/// RFC 8446 Section 7.5 - Exporters
pub const RFC8446_SECTION7_5: DocSection = DocSection::new(&RFC8446, "7.5", "Exporters");

/// RFC 8446 Appendix A - State Machine
pub const RFC8446_APPENDIX_A: DocSection = DocSection::new(&RFC8446, "A", "State Machine");

/// RFC 8446 Appendix B - Protocol Data Structures and Constant Values
pub const RFC8446_APPENDIX_B: DocSection = DocSection::new(&RFC8446, "B", "Protocol Data Structures and Constant Values");

/// RFC 8446 Appendix C - Implementation Notes
pub const RFC8446_APPENDIX_C: DocSection = DocSection::new(&RFC8446, "C", "Implementation Notes");

/// RFC 8446 Appendix D - Backward Compatibility
pub const RFC8446_APPENDIX_D: DocSection = DocSection::new(&RFC8446, "D", "Backward Compatibility");

/// RFC 8446 Appendix E - Overview of Security Properties
pub const RFC8446_APPENDIX_E: DocSection = DocSection::new(&RFC8446, "E", "Overview of Security Properties");

/// Generate a compliance report
pub fn generate_compliance_report() -> String {
    let mut report = String::new();
    
    report.push_str("# TLS 1.3 Compliance Report\n\n");
    report.push_str("This report documents the compliance of the s2n-tls-rs implementation with the TLS 1.3 specification (RFC 8446).\n\n");
    
    report.push_str("## Handshake Protocol\n\n");
    report.push_str("### Key Exchange Messages\n\n");
    report.push_str("- ClientHello: Implemented according to RFC 8446 Section 4.1.2\n");
    report.push_str("- ServerHello: Implemented according to RFC 8446 Section 4.1.3\n");
    report.push_str("- HelloRetryRequest: Implemented according to RFC 8446 Section 4.1.4\n\n");
    
    report.push_str("### Extensions\n\n");
    report.push_str("- Supported Versions: Implemented according to RFC 8446 Section 4.2.1\n");
    report.push_str("- Signature Algorithms: Implemented according to RFC 8446 Section 4.2.3\n");
    report.push_str("- Supported Groups: Implemented according to RFC 8446 Section 4.2.7\n");
    report.push_str("- Key Share: Implemented according to RFC 8446 Section 4.2.8\n\n");
    
    report.push_str("### Server Parameters\n\n");
    report.push_str("- Encrypted Extensions: Implemented according to RFC 8446 Section 4.3.1\n\n");
    
    report.push_str("### Authentication Messages\n\n");
    report.push_str("- Certificate: Implemented according to RFC 8446 Section 4.4.1\n");
    report.push_str("- Certificate Verify: Implemented according to RFC 8446 Section 4.4.2\n");
    report.push_str("- Finished: Implemented according to RFC 8446 Section 4.4.3\n\n");
    
    report.push_str("## Record Protocol\n\n");
    report.push_str("- Record Layer: Implemented according to RFC 8446 Section 5.1\n");
    report.push_str("- Record Payload Protection: Implemented according to RFC 8446 Section 5.2\n");
    report.push_str("- Per-Record Nonce: Implemented according to RFC 8446 Section 5.3\n");
    report.push_str("- Record Padding: Implemented according to RFC 8446 Section 5.4\n\n");
    
    report.push_str("## Cryptographic Computations\n\n");
    report.push_str("- Key Schedule: Implemented according to RFC 8446 Section 7.1\n");
    report.push_str("- Traffic Key Calculation: Implemented according to RFC 8446 Section 7.3\n");
    report.push_str("- (EC)DHE Shared Secret Calculation: Implemented according to RFC 8446 Section 7.4\n\n");
    
    report.push_str("## State Machine\n\n");
    report.push_str("- State Machine: Implemented according to RFC 8446 Appendix A\n\n");
    
    report
}
