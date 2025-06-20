//! TLS 1.3 key schedule implementation
//!
//! This module implements the TLS 1.3 key schedule as specified in RFC 8446 section 7.1.

use crate::crypto::{self, HashAlgorithm, CipherSuite, TrafficKeys};
use crate::error::{Error, ProtocolError, CryptoError};

/// TLS 1.3 key derivation labels
pub mod labels {
    /// Label for deriving the early secret
    pub const EARLY_SECRET: &[u8] = b"tls13 early secret";
    /// Label for deriving the handshake secret
    pub const HANDSHAKE_SECRET: &[u8] = b"tls13 handshake secret";
    /// Label for deriving the master secret
    pub const MASTER_SECRET: &[u8] = b"tls13 master secret";
    /// Label for deriving the client handshake traffic secret
    pub const CLIENT_HANDSHAKE_TRAFFIC_SECRET: &[u8] = b"tls13 c hs traffic";
    /// Label for deriving the server handshake traffic secret
    pub const SERVER_HANDSHAKE_TRAFFIC_SECRET: &[u8] = b"tls13 s hs traffic";
    /// Label for deriving the client application traffic secret
    pub const CLIENT_APPLICATION_TRAFFIC_SECRET: &[u8] = b"tls13 c ap traffic";
    /// Label for deriving the server application traffic secret
    pub const SERVER_APPLICATION_TRAFFIC_SECRET: &[u8] = b"tls13 s ap traffic";
    /// Label for deriving the exporter master secret
    pub const EXPORTER_MASTER_SECRET: &[u8] = b"tls13 exp master";
    /// Label for deriving the resumption master secret
    pub const RESUMPTION_MASTER_SECRET: &[u8] = b"tls13 res master";
    /// Label for deriving finished keys
    pub const FINISHED: &[u8] = b"tls13 finished";
    /// Label for deriving key material
    pub const KEY: &[u8] = b"tls13 key";
    /// Label for deriving IV material
    pub const IV: &[u8] = b"tls13 iv";
}

/// TLS 1.3 key schedule
#[derive(Debug, Clone)]
pub struct KeySchedule {
    /// Hash algorithm used for key derivation
    pub hash_algorithm: HashAlgorithm,
    /// Early secret
    pub early_secret: Vec<u8>,
    /// Handshake secret
    pub handshake_secret: Option<Vec<u8>>,
    /// Master secret
    pub master_secret: Option<Vec<u8>>,
}

impl KeySchedule {
    /// Create a new key schedule
    pub fn new(hash_algorithm: HashAlgorithm) -> Result<Self, Error> {
        // Derive the early secret
        let early_secret = crypto::hkdf_extract(hash_algorithm, None, &[])?;
        
        Ok(Self {
            hash_algorithm,
            early_secret,
            handshake_secret: None,
            master_secret: None,
        })
    }
    
    /// Create a new key schedule from a PSK
    pub fn new_with_psk(hash_algorithm: HashAlgorithm, psk: &[u8]) -> Result<Self, Error> {
        // Derive the early secret
        let early_secret = crypto::hkdf_extract(hash_algorithm, None, psk)?;
        
        Ok(Self {
            hash_algorithm,
            early_secret,
            handshake_secret: None,
            master_secret: None,
        })
    }
    
    /// Derive the handshake secret
    pub fn derive_handshake_secret(&mut self, shared_secret: &[u8]) -> Result<(), Error> {
        // Derive the handshake secret
        let derived_secret = self.derive_secret(&self.early_secret, labels::HANDSHAKE_SECRET, &[])?;
        let handshake_secret = crypto::hkdf_extract(self.hash_algorithm, Some(&derived_secret), shared_secret)?;
        
        self.handshake_secret = Some(handshake_secret);
        
        Ok(())
    }
    
    /// Derive the master secret
    pub fn derive_master_secret(&mut self) -> Result<(), Error> {
        // Check if the handshake secret has been derived
        let handshake_secret = self.handshake_secret.as_ref().ok_or_else(|| {
            Error::protocol(ProtocolError::Other("Handshake secret not derived".into()))
        })?;
        
        // Derive the master secret
        let derived_secret = self.derive_secret(handshake_secret, labels::MASTER_SECRET, &[])?;
        let master_secret = crypto::hkdf_extract(self.hash_algorithm, Some(&derived_secret), &[])?;
        
        self.master_secret = Some(master_secret);
        
        Ok(())
    }
    
    /// Derive the client handshake traffic secret
    pub fn derive_client_handshake_traffic_secret(&self, transcript_hash: &[u8]) -> Result<Vec<u8>, Error> {
        // Check if the handshake secret has been derived
        let handshake_secret = self.handshake_secret.as_ref().ok_or_else(|| {
            Error::protocol(ProtocolError::Other("Handshake secret not derived".into()))
        })?;
        
        // Derive the client handshake traffic secret
        self.derive_secret(handshake_secret, labels::CLIENT_HANDSHAKE_TRAFFIC_SECRET, transcript_hash)
    }
    
    /// Derive the server handshake traffic secret
    pub fn derive_server_handshake_traffic_secret(&self, transcript_hash: &[u8]) -> Result<Vec<u8>, Error> {
        // Check if the handshake secret has been derived
        let handshake_secret = self.handshake_secret.as_ref().ok_or_else(|| {
            Error::protocol(ProtocolError::Other("Handshake secret not derived".into()))
        })?;
        
        // Derive the server handshake traffic secret
        self.derive_secret(handshake_secret, labels::SERVER_HANDSHAKE_TRAFFIC_SECRET, transcript_hash)
    }
    
    /// Derive the client application traffic secret
    pub fn derive_client_application_traffic_secret(&self, transcript_hash: &[u8]) -> Result<Vec<u8>, Error> {
        // Check if the master secret has been derived
        let master_secret = self.master_secret.as_ref().ok_or_else(|| {
            Error::protocol(ProtocolError::Other("Master secret not derived".into()))
        })?;
        
        // Derive the client application traffic secret
        self.derive_secret(master_secret, labels::CLIENT_APPLICATION_TRAFFIC_SECRET, transcript_hash)
    }
    
    /// Derive the server application traffic secret
    pub fn derive_server_application_traffic_secret(&self, transcript_hash: &[u8]) -> Result<Vec<u8>, Error> {
        // Check if the master secret has been derived
        let master_secret = self.master_secret.as_ref().ok_or_else(|| {
            Error::protocol(ProtocolError::Other("Master secret not derived".into()))
        })?;
        
        // Derive the server application traffic secret
        self.derive_secret(master_secret, labels::SERVER_APPLICATION_TRAFFIC_SECRET, transcript_hash)
    }
    
    /// Derive the exporter master secret
    pub fn derive_exporter_master_secret(&self, transcript_hash: &[u8]) -> Result<Vec<u8>, Error> {
        // Check if the master secret has been derived
        let master_secret = self.master_secret.as_ref().ok_or_else(|| {
            Error::protocol(ProtocolError::Other("Master secret not derived".into()))
        })?;
        
        // Derive the exporter master secret
        self.derive_secret(master_secret, labels::EXPORTER_MASTER_SECRET, transcript_hash)
    }
    
    /// Derive the resumption master secret
    pub fn derive_resumption_master_secret(&self, transcript_hash: &[u8]) -> Result<Vec<u8>, Error> {
        // Check if the master secret has been derived
        let master_secret = self.master_secret.as_ref().ok_or_else(|| {
            Error::protocol(ProtocolError::Other("Master secret not derived".into()))
        })?;
        
        // Derive the resumption master secret
        self.derive_secret(master_secret, labels::RESUMPTION_MASTER_SECRET, transcript_hash)
    }
    
    /// Derive traffic keys from a traffic secret
    pub fn derive_traffic_keys(&self, cipher_suite: CipherSuite, secret: &[u8]) -> Result<TrafficKeys, Error> {
        // Derive the key
        let key_len = cipher_suite.aead.key_size();
        let key = crypto::hkdf_expand_label(self.hash_algorithm, secret, labels::KEY, &[], key_len)?;
        
        // Derive the IV
        let iv_len = cipher_suite.aead.nonce_size();
        let iv = crypto::hkdf_expand_label(self.hash_algorithm, secret, labels::IV, &[], iv_len)?;
        
        Ok(TrafficKeys { key, iv })
    }
    
    /// Derive a finished key from a traffic secret
    pub fn derive_finished_key(&self, secret: &[u8]) -> Result<Vec<u8>, Error> {
        // Derive the finished key
        let hash_len = self.hash_algorithm.output_size();
        crypto::hkdf_expand_label(self.hash_algorithm, secret, labels::FINISHED, &[], hash_len)
    }
    
    /// Derive a secret using HKDF-Expand-Label
    fn derive_secret(&self, secret: &[u8], label: &[u8], context: &[u8]) -> Result<Vec<u8>, Error> {
        let hash_len = self.hash_algorithm.output_size();
        crypto::hkdf_expand_label(self.hash_algorithm, secret, label, context, hash_len)
    }
}

/// Extend the crypto module with HKDF-Expand-Label
impl crypto {
    /// HKDF-Expand-Label as defined in RFC 8446 section 7.1
    pub fn hkdf_expand_label(
        hash_algorithm: HashAlgorithm,
        secret: &[u8],
        label: &[u8],
        context: &[u8],
        length: usize,
    ) -> Result<Vec<u8>, Error> {
        // Construct the HkdfLabel
        let mut hkdf_label = Vec::with_capacity(2 + 1 + label.len() + 1 + context.len());
        
        // Length (2 bytes)
        hkdf_label.push((length >> 8) as u8);
        hkdf_label.push(length as u8);
        
        // Label length (1 byte)
        hkdf_label.push(label.len() as u8);
        
        // Label
        hkdf_label.extend_from_slice(label);
        
        // Context length (1 byte)
        hkdf_label.push(context.len() as u8);
        
        // Context
        hkdf_label.extend_from_slice(context);
        
        // Expand
        crypto::hkdf_expand(hash_algorithm, secret, &hkdf_label, length)
    }
}
