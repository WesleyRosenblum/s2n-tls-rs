//! TLS state machine implementation
//!
//! This module implements the TLS state machine as specified in RFC 8446.

use crate::buffer::Buffer;
use crate::crypto::{self, HashAlgorithm, CipherSuite, TrafficKeys};
use crate::error::{Error, ProtocolError, CryptoError};
use crate::handshake::{
    ClientHello, ServerHello, Certificate, CertificateEntry, CertificateVerificationContext,
    Finished, HandshakeVerificationContext, TranscriptHashContext, KeySchedule,
    NamedGroup, KeyShareEntry, ClientKeyShare, ServerKeyShare, KeyPair,
};
use crate::record::{Record, RecordType, ProtocolVersion, TLSPlaintext, TLSCiphertext};

/// TLS connection mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionMode {
    /// Client mode
    Client,
    /// Server mode
    Server,
}

/// TLS connection state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// Initial state
    Initial,
    /// ClientHello sent (client) or received (server)
    ClientHelloSent,
    /// ServerHello sent (server) or received (client)
    ServerHelloSent,
    /// Server Certificate sent (server) or received (client)
    ServerCertificateSent,
    /// Server CertificateVerify sent (server) or received (client)
    ServerCertificateVerifySent,
    /// Server Finished sent (server) or received (client)
    ServerFinishedSent,
    /// Client Certificate sent (client) or received (server)
    ClientCertificateSent,
    /// Client CertificateVerify sent (client) or received (server)
    ClientCertificateVerifySent,
    /// Client Finished sent (client) or received (server)
    ClientFinishedSent,
    /// Handshake completed
    HandshakeCompleted,
    /// Connection closed
    Closed,
    /// Error state
    Error,
}

/// TLS connection configuration
#[derive(Debug, Clone)]
pub struct ConnectionConfig {
    /// Connection mode
    pub mode: ConnectionMode,
    /// Server name
    pub server_name: Option<String>,
    /// Trusted CA certificates
    pub trusted_cas: Vec<Vec<u8>>,
    /// Client certificate
    pub client_certificate: Option<Vec<u8>>,
    /// Client private key
    pub client_private_key: Option<Vec<u8>>,
    /// Server certificate
    pub server_certificate: Option<Vec<u8>>,
    /// Server private key
    pub server_private_key: Option<Vec<u8>>,
    /// Supported cipher suites
    pub cipher_suites: Vec<CipherSuite>,
    /// Supported named groups
    pub named_groups: Vec<NamedGroup>,
    /// OCSP stapling enabled
    pub ocsp_stapling_enabled: bool,
}

impl ConnectionConfig {
    /// Create a new connection configuration
    pub fn new(mode: ConnectionMode) -> Self {
        Self {
            mode,
            server_name: None,
            trusted_cas: Vec::new(),
            client_certificate: None,
            client_private_key: None,
            server_certificate: None,
            server_private_key: None,
            cipher_suites: Vec::new(),
            named_groups: Vec::new(),
            ocsp_stapling_enabled: false,
        }
    }
    
    /// Set the server name
    pub fn set_server_name(&mut self, server_name: String) {
        self.server_name = Some(server_name);
    }
    
    /// Add a trusted CA certificate
    pub fn add_trusted_ca(&mut self, cert_data: Vec<u8>) {
        self.trusted_cas.push(cert_data);
    }
    
    /// Set the client certificate
    pub fn set_client_certificate(&mut self, cert_data: Vec<u8>) {
        self.client_certificate = Some(cert_data);
    }
    
    /// Set the client private key
    pub fn set_client_private_key(&mut self, key_data: Vec<u8>) {
        self.client_private_key = Some(key_data);
    }
    
    /// Set the server certificate
    pub fn set_server_certificate(&mut self, cert_data: Vec<u8>) {
        self.server_certificate = Some(cert_data);
    }
    
    /// Set the server private key
    pub fn set_server_private_key(&mut self, key_data: Vec<u8>) {
        self.server_private_key = Some(key_data);
    }
    
    /// Add a cipher suite
    pub fn add_cipher_suite(&mut self, cipher_suite: CipherSuite) {
        self.cipher_suites.push(cipher_suite);
    }
    
    /// Add a named group
    pub fn add_named_group(&mut self, named_group: NamedGroup) {
        self.named_groups.push(named_group);
    }
    
    /// Enable OCSP stapling
    pub fn enable_ocsp_stapling(&mut self) {
        self.ocsp_stapling_enabled = true;
    }
}

/// TLS connection
#[derive(Debug)]
pub struct Connection {
    /// Connection configuration
    pub config: ConnectionConfig,
    /// Connection state
    pub state: ConnectionState,
    /// Key schedule
    pub key_schedule: Option<KeySchedule>,
    /// Handshake verification context
    pub handshake_verification: Option<HandshakeVerificationContext>,
    /// Selected cipher suite
    pub cipher_suite: Option<CipherSuite>,
    /// Client random
    pub client_random: Option<[u8; 32]>,
    /// Server random
    pub server_random: Option<[u8; 32]>,
    /// Client key share
    pub client_key_share: Option<ClientKeyShare>,
    /// Server key share
    pub server_key_share: Option<ServerKeyShare>,
    /// Client handshake traffic keys
    pub client_handshake_traffic_keys: Option<TrafficKeys>,
    /// Server handshake traffic keys
    pub server_handshake_traffic_keys: Option<TrafficKeys>,
    /// Client application traffic keys
    pub client_application_traffic_keys: Option<TrafficKeys>,
    /// Server application traffic keys
    pub server_application_traffic_keys: Option<TrafficKeys>,
    /// Client sequence number
    pub client_sequence_number: u64,
    /// Server sequence number
    pub server_sequence_number: u64,
}

impl Connection {
    /// Create a new connection
    pub fn new(config: ConnectionConfig) -> Self {
        Self {
            config,
            state: ConnectionState::Initial,
            key_schedule: None,
            handshake_verification: None,
            cipher_suite: None,
            client_random: None,
            server_random: None,
            client_key_share: None,
            server_key_share: None,
            client_handshake_traffic_keys: None,
            server_handshake_traffic_keys: None,
            client_application_traffic_keys: None,
            server_application_traffic_keys: None,
            client_sequence_number: 0,
            server_sequence_number: 0,
        }
    }
    
    /// Initialize the connection
    pub fn initialize(&mut self) -> Result<(), Error> {
        // Create the handshake verification context
        self.handshake_verification = Some(HandshakeVerificationContext::new(HashAlgorithm::Sha256));
        
        // Initialize the state based on the connection mode
        match self.config.mode {
            ConnectionMode::Client => {
                // Client starts by sending a ClientHello
                self.state = ConnectionState::Initial;
            }
            ConnectionMode::Server => {
                // Server starts by waiting for a ClientHello
                self.state = ConnectionState::Initial;
            }
        }
        
        Ok(())
    }
    
    /// Process a record
    pub fn process_record(&mut self, record: &Record) -> Result<Vec<Record>, Error> {
        match self.state {
            ConnectionState::Initial => {
                // Initial state
                match self.config.mode {
                    ConnectionMode::Client => {
                        // Client sends a ClientHello
                        let client_hello = self.create_client_hello()?;
                        let mut buffer = Buffer::new();
                        client_hello.encode(&mut buffer)?;
                        
                        // Update the handshake verification context
                        if let Some(handshake_verification) = &mut self.handshake_verification {
                            handshake_verification.update_transcript(&buffer)?;
                        }
                        
                        // Create a record
                        let record = Record::new(
                            RecordType::Handshake,
                            ProtocolVersion::TLS_1_2,
                            buffer.into_vec(),
                        );
                        
                        // Update the state
                        self.state = ConnectionState::ClientHelloSent;
                        
                        Ok(vec![record])
                    }
                    ConnectionMode::Server => {
                        // Server expects a ClientHello
                        if record.record_type != RecordType::Handshake {
                            return Err(Error::protocol(ProtocolError::Other("Expected Handshake record".into())));
                        }
                        
                        // Parse the ClientHello
                        let mut offset = 0;
                        let client_hello = ClientHello::decode(&record.payload, &mut offset)?;
                        
                        // Update the handshake verification context
                        if let Some(handshake_verification) = &mut self.handshake_verification {
                            handshake_verification.update_transcript(&record.payload)?;
                        }
                        
                        // Process the ClientHello
                        self.process_client_hello(&client_hello)?;
                        
                        // Create a ServerHello
                        let server_hello = self.create_server_hello()?;
                        let mut buffer = Buffer::new();
                        server_hello.encode(&mut buffer)?;
                        
                        // Update the handshake verification context
                        if let Some(handshake_verification) = &mut self.handshake_verification {
                            handshake_verification.update_transcript(&buffer)?;
                        }
                        
                        // Create a record
                        let record = Record::new(
                            RecordType::Handshake,
                            ProtocolVersion::TLS_1_2,
                            buffer.into_vec(),
                        );
                        
                        // Update the state
                        self.state = ConnectionState::ServerHelloSent;
                        
                        Ok(vec![record])
                    }
                }
            }
            ConnectionState::ClientHelloSent => {
                // ClientHello sent
                match self.config.mode {
                    ConnectionMode::Client => {
                        // Client expects a ServerHello
                        if record.record_type != RecordType::Handshake {
                            return Err(Error::protocol(ProtocolError::Other("Expected Handshake record".into())));
                        }
                        
                        // Parse the ServerHello
                        let mut offset = 0;
                        let server_hello = ServerHello::decode(&record.payload, &mut offset)?;
                        
                        // Update the handshake verification context
                        if let Some(handshake_verification) = &mut self.handshake_verification {
                            handshake_verification.update_transcript(&record.payload)?;
                        }
                        
                        // Process the ServerHello
                        self.process_server_hello(&server_hello)?;
                        
                        // Update the state
                        self.state = ConnectionState::ServerHelloSent;
                        
                        Ok(Vec::new())
                    }
                    ConnectionMode::Server => {
                        // Server should not be in this state
                        Err(Error::protocol(ProtocolError::Other("Server in invalid state".into())))
                    }
                }
            }
            // Additional states would be implemented here
            _ => Err(Error::protocol(ProtocolError::Other("State not implemented".into()))),
        }
    }
    
    /// Create a ClientHello message
    fn create_client_hello(&mut self) -> Result<ClientHello, Error> {
        // Create a ClientHello message
        let mut client_hello = ClientHello::new();
        
        // Generate a random value
        client_hello.generate_random()?;
        self.client_random = Some(client_hello.random);
        
        // Generate a session ID for compatibility mode
        client_hello.generate_session_id()?;
        
        // Add cipher suites
        if self.config.cipher_suites.is_empty() {
            // Add default cipher suites
            client_hello.add_default_cipher_suites();
        } else {
            // Add configured cipher suites
            for cipher_suite in &self.config.cipher_suites {
                client_hello.add_cipher_suite(*cipher_suite);
            }
        }
        
        // Add the supported versions extension for TLS 1.3
        client_hello.add_supported_versions_extension();
        
        // Create a key share extension
        let mut client_key_share = ClientKeyShare::new();
        
        // Generate key pairs for each supported named group
        if self.config.named_groups.is_empty() {
            // Use X25519 as the default named group
            let key_pair = crate::handshake::key_exchange::generate_key_pair(NamedGroup::X25519)?;
            let entry = KeyShareEntry::new(NamedGroup::X25519, key_pair.public_key);
            client_key_share.add_entry(entry);
        } else {
            // Generate key pairs for each configured named group
            for named_group in &self.config.named_groups {
                let key_pair = crate::handshake::key_exchange::generate_key_pair(*named_group)?;
                let entry = KeyShareEntry::new(*named_group, key_pair.public_key);
                client_key_share.add_entry(entry);
            }
        }
        
        // Add the key share extension
        let key_share_extension = client_key_share.encode()?;
        client_hello.add_extension(key_share_extension);
        
        // Save the client key share
        self.client_key_share = Some(client_key_share);
        
        Ok(client_hello)
    }
    
    /// Process a ClientHello message
    fn process_client_hello(&mut self, client_hello: &ClientHello) -> Result<(), Error> {
        // Save the client random
        self.client_random = Some(client_hello.random);
        
        // Select a cipher suite
        let mut selected_cipher_suite = None;
        for cipher_suite in &client_hello.cipher_suites {
            if self.config.cipher_suites.contains(cipher_suite) {
                selected_cipher_suite = Some(*cipher_suite);
                break;
            }
        }
        
        if let Some(cipher_suite) = selected_cipher_suite {
            self.cipher_suite = Some(cipher_suite);
        } else {
            return Err(Error::protocol(ProtocolError::Other("No common cipher suite".into())));
        }
        
        // Process the key share extension
        for extension in &client_hello.extensions {
            if extension.extension_type == crate::handshake::ExtensionType::KeyShare {
                let client_key_share = ClientKeyShare::decode(&extension.extension_data)?;
                self.client_key_share = Some(client_key_share);
                break;
            }
        }
        
        Ok(())
    }
    
    /// Create a ServerHello message
    fn create_server_hello(&mut self) -> Result<ServerHello, Error> {
        // Create a ServerHello message
        let mut server_hello = ServerHello::new();
        
        // Generate a random value
        server_hello.generate_random()?;
        self.server_random = Some(server_hello.random);
        
        // Echo the session ID from the ClientHello
        if let Some(client_key_share) = &self.client_key_share {
            // In a real implementation, we would get this from the ClientHello
            server_hello.set_legacy_session_id_echo(Vec::new())?;
        }
        
        // Set the selected cipher suite
        if let Some(cipher_suite) = self.cipher_suite {
            server_hello.set_cipher_suite(cipher_suite);
        } else {
            return Err(Error::protocol(ProtocolError::Other("No cipher suite selected".into())));
        }
        
        // Add the supported versions extension for TLS 1.3
        server_hello.add_supported_versions_extension();
        
        // Create a key share extension
        if let Some(client_key_share) = &self.client_key_share {
            // Select a named group from the client key share
            if let Some(entry) = client_key_share.entries.first() {
                // Generate a key pair for the selected named group
                let key_pair = crate::handshake::key_exchange::generate_key_pair(entry.group)?;
                
                // Create a server key share
                let server_key_share = ServerKeyShare::new(
                    KeyShareEntry::new(entry.group, key_pair.public_key.clone()),
                );
                
                // Add the key share extension
                let key_share_extension = server_key_share.encode()?;
                server_hello.add_extension(key_share_extension);
                
                // Save the server key share
                self.server_key_share = Some(server_key_share);
                
                // Compute the shared secret
                if let Some(cipher_suite) = self.cipher_suite {
                    // Create the key schedule
                    let mut key_schedule = KeySchedule::new(cipher_suite.hash)?;
                    
                    // Compute the shared secret
                    let shared_secret = crate::handshake::key_exchange::compute_shared_secret(
                        entry.group,
                        &key_pair.private_key,
                        &entry.key_exchange,
                    )?;
                    
                    // Derive the handshake secret
                    key_schedule.derive_handshake_secret(&shared_secret)?;
                    
                    // Save the key schedule
                    self.key_schedule = Some(key_schedule);
                }
            } else {
                return Err(Error::protocol(ProtocolError::Other("No key share entry".into())));
            }
        } else {
            return Err(Error::protocol(ProtocolError::Other("No client key share".into())));
        }
        
        Ok(server_hello)
    }
    
    /// Process a ServerHello message
    fn process_server_hello(&mut self, server_hello: &ServerHello) -> Result<(), Error> {
        // Save the server random
        self.server_random = Some(server_hello.random);
        
        // Save the selected cipher suite
        self.cipher_suite = Some(server_hello.cipher_suite);
        
        // Process the key share extension
        for extension in &server_hello.extensions {
            if extension.extension_type == crate::handshake::ExtensionType::KeyShare {
                let server_key_share = ServerKeyShare::decode(&extension.extension_data)?;
                self.server_key_share = Some(server_key_share);
                break;
            }
        }
        
        // Compute the shared secret
        if let (Some(client_key_share), Some(server_key_share)) = (&self.client_key_share, &self.server_key_share) {
            // Find the client key share entry for the server's named group
            for entry in &client_key_share.entries {
                if entry.group == server_key_share.entry.group {
                    // In a real implementation, we would have saved the private key
                    // For now, we'll just use a placeholder
                    let private_key = vec![0; 32];
                    
                    // Compute the shared secret
                    let shared_secret = crate::handshake::key_exchange::compute_shared_secret(
                        entry.group,
                        &private_key,
                        &server_key_share.entry.key_exchange,
                    )?;
                    
                    // Create the key schedule
                    let mut key_schedule = KeySchedule::new(server_hello.cipher_suite.hash)?;
                    
                    // Derive the handshake secret
                    key_schedule.derive_handshake_secret(&shared_secret)?;
                    
                    // Save the key schedule
                    self.key_schedule = Some(key_schedule);
                    
                    break;
                }
            }
        }
        
        Ok(())
    }
}
