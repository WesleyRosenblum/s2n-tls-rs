//! Utility functions for the s2n-tls-rs library
//!
//! This module provides utility functions for the s2n-tls-rs library.

/// Convert a slice of bytes to a hexadecimal string
pub(crate) fn to_hex(bytes: &[u8]) -> String {
    bytes.iter()
        .map(|b| format!("{:02x}", b))
        .collect()
}

/// Convert a hexadecimal string to a vector of bytes
pub(crate) fn from_hex(hex: &str) -> Result<Vec<u8>, String> {
    if hex.len() % 2 != 0 {
        return Err("Hex string must have an even number of characters".to_string());
    }
    
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    
    for i in (0..hex.len()).step_by(2) {
        let byte_str = &hex[i..i + 2];
        let byte = u8::from_str_radix(byte_str, 16)
            .map_err(|e| format!("Invalid hex string: {}", e))?;
        bytes.push(byte);
    }
    
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_to_hex() {
        let bytes = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
        assert_eq!(to_hex(&bytes), "0123456789abcdef");
    }

    #[test]
    fn test_from_hex() {
        let hex = "0123456789abcdef";
        let bytes = from_hex(hex).unwrap();
        assert_eq!(bytes, [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]);
    }

    #[test]
    fn test_from_hex_invalid() {
        let hex = "0123456789abcdef0";
        assert!(from_hex(hex).is_err());
    }
}