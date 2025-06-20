// Crypto module
// Contains cryptographic operations for the TLS implementation

use aws_lc_rs::aead::{Aead, AeadTag, Aes128Gcm, Aes256Gcm, ChaCha20Poly1305};
use aws_lc_rs::digest::{Digest, Sha256, Sha384};
use aws_lc_rs::hkdf::Hkdf;
use aws_lc_rs::hmac::{Hmac, Key as HmacKey};
use aws_lc_rs::rand::{SecureRandom, SystemRandom};

use std::convert::TryInto;

use crate::error::{CryptoError, Error};

/// Initialize the cryptographic library
pub fn init() -> Result<(), Error> {
    // aws-lc-rs doesn't require explicit initialization
    Ok(())
}

/// Clean up the cryptographic library
pub fn cleanup() -> Result<(), Error> {
    // aws-lc-rs doesn't require explicit cleanup
    Ok(())
}

/// TLS 1.3 AEAD algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AeadAlgorithm {
    /// AES-128-GCM
    Aes128Gcm,
    /// AES-256-GCM
    Aes256Gcm,
    /// ChaCha20-Poly1305
    ChaCha20Poly1305,
}

impl AeadAlgorithm {
    /// Get the key size for this algorithm in bytes
    pub fn key_size(&self) -> usize {
        match self {
            AeadAlgorithm::Aes128Gcm => 16,
            AeadAlgorithm::Aes256Gcm => 32,
            AeadAlgorithm::ChaCha20Poly1305 => 32,
        }
    }

    /// Get the nonce size for this algorithm in bytes
    pub fn nonce_size(&self) -> usize {
        // All TLS 1.3 AEAD algorithms use 12-byte nonces
        12
    }

    /// Get the tag size for this algorithm in bytes
    pub fn tag_size(&self) -> usize {
        // All TLS 1.3 AEAD algorithms use 16-byte authentication tags
        16
    }
}

/// TLS 1.3 hash algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    /// SHA-256
    Sha256,
    /// SHA-384
    Sha384,
}

impl HashAlgorithm {
    /// Get the output size for this algorithm in bytes
    pub fn output_size(&self) -> usize {
        match self {
            HashAlgorithm::Sha256 => 32,
            HashAlgorithm::Sha384 => 48,
        }
    }
}

/// TLS 1.3 cipher suite
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CipherSuite {
    /// AEAD algorithm
    pub aead: AeadAlgorithm,
    /// Hash algorithm
    pub hash: HashAlgorithm,
    /// Cipher suite value (2 bytes)
    pub value: [u8; 2],
}

/// TLS 1.3 cipher suites
pub mod cipher_suites {
    use super::{AeadAlgorithm, CipherSuite, HashAlgorithm};

    /// TLS_AES_128_GCM_SHA256 (0x1301)
    pub const TLS_AES_128_GCM_SHA256: CipherSuite = CipherSuite {
        aead: AeadAlgorithm::Aes128Gcm,
        hash: HashAlgorithm::Sha256,
        value: [0x13, 0x01],
    };

    /// TLS_AES_256_GCM_SHA384 (0x1302)
    pub const TLS_AES_256_GCM_SHA384: CipherSuite = CipherSuite {
        aead: AeadAlgorithm::Aes256Gcm,
        hash: HashAlgorithm::Sha384,
        value: [0x13, 0x02],
    };

    /// TLS_CHACHA20_POLY1305_SHA256 (0x1303)
    pub const TLS_CHACHA20_POLY1305_SHA256: CipherSuite = CipherSuite {
        aead: AeadAlgorithm::ChaCha20Poly1305,
        hash: HashAlgorithm::Sha256,
        value: [0x13, 0x03],
    };

    /// Get a cipher suite by value
    pub fn from_value(value: &[u8; 2]) -> Option<CipherSuite> {
        match *value {
            [0x13, 0x01] => Some(TLS_AES_128_GCM_SHA256),
            [0x13, 0x02] => Some(TLS_AES_256_GCM_SHA384),
            [0x13, 0x03] => Some(TLS_CHACHA20_POLY1305_SHA256),
            _ => None,
        }
    }
}

/// TLS 1.3 traffic keys
#[derive(Debug, Clone)]
pub struct TrafficKeys {
    /// Key for encryption/decryption
    pub key: Vec<u8>,
    /// IV for nonce construction
    pub iv: Vec<u8>,
}

/// Generate a random value of the specified length
pub fn random_bytes(len: usize) -> Result<Vec<u8>, Error> {
    let mut result = vec![0; len];
    let rng = SystemRandom::new();
    rng.fill(&mut result)
        .map_err(|_| Error::crypto(CryptoError::RandomGenerationFailed))?;
    Ok(result)
}

/// Encrypt data using AEAD
pub fn aead_encrypt(
    algorithm: AeadAlgorithm,
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, Error> {
    // Check key and nonce sizes
    if key.len() != algorithm.key_size() {
        return Err(Error::crypto(CryptoError::InvalidKeySize));
    }
    if nonce.len() != algorithm.nonce_size() {
        return Err(Error::crypto(CryptoError::InvalidNonceSize));
    }

    // Allocate space for ciphertext and tag
    let mut result = Vec::with_capacity(plaintext.len() + algorithm.tag_size());
    result.extend_from_slice(plaintext);
    result.resize(plaintext.len() + algorithm.tag_size(), 0);

    // Split the result into ciphertext and tag
    let (ciphertext, tag_bytes) = result.split_at_mut(plaintext.len());

    // Create the AEAD object and encrypt
    match algorithm {
        AeadAlgorithm::Aes128Gcm => {
            let aead = Aes128Gcm::new(key.try_into().map_err(|_| Error::crypto(CryptoError::InvalidKeySize))?);
            let tag = aead
                .seal_in_place_separate_tag(nonce, aad, ciphertext)
                .map_err(|_| Error::crypto(CryptoError::EncryptionFailed))?;
            tag_bytes.copy_from_slice(tag.as_ref());
        }
        AeadAlgorithm::Aes256Gcm => {
            let aead = Aes256Gcm::new(key.try_into().map_err(|_| Error::crypto(CryptoError::InvalidKeySize))?);
            let tag = aead
                .seal_in_place_separate_tag(nonce, aad, ciphertext)
                .map_err(|_| Error::crypto(CryptoError::EncryptionFailed))?;
            tag_bytes.copy_from_slice(tag.as_ref());
        }
        AeadAlgorithm::ChaCha20Poly1305 => {
            let aead = ChaCha20Poly1305::new(key.try_into().map_err(|_| Error::crypto(CryptoError::InvalidKeySize))?);
            let tag = aead
                .seal_in_place_separate_tag(nonce, aad, ciphertext)
                .map_err(|_| Error::crypto(CryptoError::EncryptionFailed))?;
            tag_bytes.copy_from_slice(tag.as_ref());
        }
    }

    Ok(result)
}

/// Decrypt data using AEAD
pub fn aead_decrypt(
    algorithm: AeadAlgorithm,
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    ciphertext_and_tag: &[u8],
) -> Result<Vec<u8>, Error> {
    // Check key and nonce sizes
    if key.len() != algorithm.key_size() {
        return Err(Error::crypto(CryptoError::InvalidKeySize));
    }
    if nonce.len() != algorithm.nonce_size() {
        return Err(Error::crypto(CryptoError::InvalidNonceSize));
    }

    // Check that the ciphertext is at least as long as the tag
    if ciphertext_and_tag.len() < algorithm.tag_size() {
        return Err(Error::crypto(CryptoError::DecryptionFailed));
    }

    // Split the input into ciphertext and tag
    let ciphertext_len = ciphertext_and_tag.len() - algorithm.tag_size();
    let (ciphertext, tag) = ciphertext_and_tag.split_at(ciphertext_len);

    // Create a mutable copy of the ciphertext
    let mut plaintext = ciphertext.to_vec();

    // Create the AEAD object and decrypt
    match algorithm {
        AeadAlgorithm::Aes128Gcm => {
            let aead = Aes128Gcm::new(key.try_into().map_err(|_| Error::crypto(CryptoError::InvalidKeySize))?);
            let tag = AeadTag::try_from(tag).map_err(|_| Error::crypto(CryptoError::DecryptionFailed))?;
            aead.open_in_place_with_tag(nonce, aad, &mut plaintext, &tag)
                .map_err(|_| Error::crypto(CryptoError::DecryptionFailed))?;
        }
        AeadAlgorithm::Aes256Gcm => {
            let aead = Aes256Gcm::new(key.try_into().map_err(|_| Error::crypto(CryptoError::InvalidKeySize))?);
            let tag = AeadTag::try_from(tag).map_err(|_| Error::crypto(CryptoError::DecryptionFailed))?;
            aead.open_in_place_with_tag(nonce, aad, &mut plaintext, &tag)
                .map_err(|_| Error::crypto(CryptoError::DecryptionFailed))?;
        }
        AeadAlgorithm::ChaCha20Poly1305 => {
            let aead = ChaCha20Poly1305::new(key.try_into().map_err(|_| Error::crypto(CryptoError::InvalidKeySize))?);
            let tag = AeadTag::try_from(tag).map_err(|_| Error::crypto(CryptoError::DecryptionFailed))?;
            aead.open_in_place_with_tag(nonce, aad, &mut plaintext, &tag)
                .map_err(|_| Error::crypto(CryptoError::DecryptionFailed))?;
        }
    }

    Ok(plaintext)
}

/// Compute a hash using the specified algorithm
pub fn hash(algorithm: HashAlgorithm, data: &[u8]) -> Result<Vec<u8>, Error> {
    match algorithm {
        HashAlgorithm::Sha256 => {
            let mut hasher = Sha256::new();
            hasher.update(data);
            Ok(hasher.finish().as_ref().to_vec())
        }
        HashAlgorithm::Sha384 => {
            let mut hasher = Sha384::new();
            hasher.update(data);
            Ok(hasher.finish().as_ref().to_vec())
        }
    }
}

/// Compute an HMAC using the specified hash algorithm
pub fn hmac(algorithm: HashAlgorithm, key: &[u8], data: &[u8]) -> Result<Vec<u8>, Error> {
    match algorithm {
        HashAlgorithm::Sha256 => {
            let hmac_key = HmacKey::new(Sha256::new(), key);
            let mut hmac = Hmac::new(&hmac_key);
            hmac.update(data);
            Ok(hmac.sign().as_ref().to_vec())
        }
        HashAlgorithm::Sha384 => {
            let hmac_key = HmacKey::new(Sha384::new(), key);
            let mut hmac = Hmac::new(&hmac_key);
            hmac.update(data);
            Ok(hmac.sign().as_ref().to_vec())
        }
    }
}

/// Perform HKDF extract operation
pub fn hkdf_extract(
    algorithm: HashAlgorithm,
    salt: Option<&[u8]>,
    ikm: &[u8],
) -> Result<Vec<u8>, Error> {
    match algorithm {
        HashAlgorithm::Sha256 => {
            let salt = salt.unwrap_or(&[]);
            let prk = Hkdf::<Sha256>::extract(Some(salt), ikm);
            Ok(prk.as_ref().to_vec())
        }
        HashAlgorithm::Sha384 => {
            let salt = salt.unwrap_or(&[]);
            let prk = Hkdf::<Sha384>::extract(Some(salt), ikm);
            Ok(prk.as_ref().to_vec())
        }
    }
}

/// Perform HKDF expand operation
pub fn hkdf_expand(
    algorithm: HashAlgorithm,
    prk: &[u8],
    info: &[u8],
    output_len: usize,
) -> Result<Vec<u8>, Error> {
    match algorithm {
        HashAlgorithm::Sha256 => {
            let mut output = vec![0; output_len];
            let hkdf = Hkdf::<Sha256>::from_prk(prk)
                .map_err(|_| Error::crypto(CryptoError::HkdfError))?;
            hkdf.expand(info, &mut output)
                .map_err(|_| Error::crypto(CryptoError::HkdfError))?;
            Ok(output)
        }
        HashAlgorithm::Sha384 => {
            let mut output = vec![0; output_len];
            let hkdf = Hkdf::<Sha384>::from_prk(prk)
                .map_err(|_| Error::crypto(CryptoError::HkdfError))?;
            hkdf.expand(info, &mut output)
                .map_err(|_| Error::crypto(CryptoError::HkdfError))?;
            Ok(output)
        }
    }
}

/// Derive TLS 1.3 traffic keys
pub fn derive_traffic_keys(
    cipher_suite: CipherSuite,
    secret: &[u8],
    purpose: &[u8],
) -> Result<TrafficKeys, Error> {
    let key_size = cipher_suite.aead.key_size();
    let iv_size = cipher_suite.aead.nonce_size();
    let hash_size = cipher_suite.hash.output_size();

    // Check that the secret has the correct length
    if secret.len() != hash_size {
        return Err(Error::crypto(CryptoError::InvalidSecretSize));
    }

    // Derive the key
    let key_info = [purpose, b"key"].concat();
    let key = hkdf_expand(cipher_suite.hash, secret, &key_info, key_size)?;

    // Derive the IV
    let iv_info = [purpose, b"iv"].concat();
    let iv = hkdf_expand(cipher_suite.hash, secret, &iv_info, iv_size)?;

    Ok(TrafficKeys { key, iv })
}

/// Construct a nonce for AEAD encryption/decryption
pub fn construct_nonce(iv: &[u8], sequence_number: u64) -> Result<Vec<u8>, Error> {
    if iv.len() != 12 {
        return Err(Error::crypto(CryptoError::InvalidNonceSize));
    }

    // XOR the sequence number with the IV
    let mut nonce = iv.to_vec();
    for i in 0..8 {
        nonce[4 + i] ^= ((sequence_number >> ((7 - i) * 8)) & 0xff) as u8;
    }

    Ok(nonce)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aead_encrypt_decrypt_aes_128_gcm() {
        // Test vectors from RFC 8448
        let key = hex::decode("3fce516009c21727d0f2e4e86ee403bc").unwrap();
        let nonce = hex::decode("5d313eb2671276ee13000b30").unwrap();
        let aad = hex::decode("00000000000000001603030010").unwrap();
        let plaintext = hex::decode("14000020b038d4d4ab0833a27c0a1bd4").unwrap();
        let expected_ciphertext = hex::decode("c6d9ff03cad0848e79fc734e7bc76bcf2912856e6a1c3fcaabf0ea5").unwrap();

        // Encrypt
        let ciphertext = aead_encrypt(
            AeadAlgorithm::Aes128Gcm,
            &key,
            &nonce,
            &aad,
            &plaintext,
        )
        .unwrap();
        assert_eq!(ciphertext, expected_ciphertext);

        // Decrypt
        let decrypted = aead_decrypt(
            AeadAlgorithm::Aes128Gcm,
            &key,
            &nonce,
            &aad,
            &ciphertext,
        )
        .unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_hash() {
        // Test vectors
        let data = b"hello world";
        let expected_sha256 = hex::decode("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9").unwrap();
        let expected_sha384 = hex::decode("fdbd8e75a67f29f701a4e040385e2e23986303ea10239211af907fcbb83578b3e417cb71ce646efd0819dd8c088de1bd").unwrap();

        // SHA-256
        let sha256 = hash(HashAlgorithm::Sha256, data).unwrap();
        assert_eq!(sha256, expected_sha256);

        // SHA-384
        let sha384 = hash(HashAlgorithm::Sha384, data).unwrap();
        assert_eq!(sha384, expected_sha384);
    }

    #[test]
    fn test_hmac() {
        // Test vectors
        let key = b"key";
        let data = b"The quick brown fox jumps over the lazy dog";
        let expected_sha256 = hex::decode("f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8").unwrap();
        let expected_sha384 = hex::decode("d7f4727e2c0b39ae0f1e40cc96f60242d5b7801841cea6fc592c5d3e1ae50700582a96cf35e1e554995fe4e03381c237").unwrap();

        // HMAC-SHA-256
        let hmac_sha256 = hmac(HashAlgorithm::Sha256, key, data).unwrap();
        assert_eq!(hmac_sha256, expected_sha256);

        // HMAC-SHA-384
        let hmac_sha384 = hmac(HashAlgorithm::Sha384, key, data).unwrap();
        assert_eq!(hmac_sha384, expected_sha384);
    }

    #[test]
    fn test_hkdf() {
        // Test vectors from RFC 5869
        let ikm = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let salt = hex::decode("000102030405060708090a0b0c").unwrap();
        let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();
        let expected_prk = hex::decode("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5").unwrap();
        let expected_okm = hex::decode("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865").unwrap();

        // Extract
        let prk = hkdf_extract(HashAlgorithm::Sha256, Some(&salt), &ikm).unwrap();
        assert_eq!(prk, expected_prk);

        // Expand
        let okm = hkdf_expand(HashAlgorithm::Sha256, &prk, &info, 42).unwrap();
        assert_eq!(okm, expected_okm);
    }

    #[test]
    fn test_nonce_construction() {
        let iv = hex::decode("5d313eb2671276ee13000b30").unwrap();
        let sequence_number = 0;
        let expected_nonce = hex::decode("5d313eb2671276ee13000b30").unwrap();

        let nonce = construct_nonce(&iv, sequence_number).unwrap();
        assert_eq!(nonce, expected_nonce);

        let sequence_number = 1;
        let expected_nonce = hex::decode("5d313eb2671276ee13000b31").unwrap();

        let nonce = construct_nonce(&iv, sequence_number).unwrap();
        assert_eq!(nonce, expected_nonce);
    }
}
