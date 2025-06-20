// Buffer module property tests

use s2n_tls_rs::{init, cleanup};
use s2n_tls_rs::buffer::{Buffer, BufferView, BufferCursor};
use proptest::prelude::*;

/// Generate a valid buffer content
fn valid_buffer_content() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..1024) // Using a smaller max for test efficiency
}

proptest! {
    #[test]
    fn test_buffer_from_vec_roundtrip(data in valid_buffer_content()) {
        // Initialize the library
        assert!(init().is_ok());
        
        // Create a buffer from a vector
        let buffer = Buffer::from_vec(data.clone());
        
        // Convert back to a vector
        let result = buffer.into_vec();
        
        // Verify the roundtrip
        prop_assert_eq!(data, result);
        
        // Clean up
        assert!(cleanup().is_ok());
    }

    #[test]
    fn test_buffer_from_slice_roundtrip(data in valid_buffer_content()) {
        // Initialize the library
        assert!(init().is_ok());
        
        // Create a buffer from a slice
        let buffer = Buffer::from_slice(&data);
        
        // Convert to a vector
        let result = buffer.into_vec();
        
        // Verify the roundtrip
        prop_assert_eq!(data, result);
        
        // Clean up
        assert!(cleanup().is_ok());
    }

    #[test]
    fn test_buffer_write_read_u8(value: u8) {
        // Initialize the library
        assert!(init().is_ok());
        
        // Create a buffer and write a u8
        let mut buffer = Buffer::new();
        buffer.write_u8(value);
        
        // Read the u8 back
        let result = buffer.read_u8(0).unwrap();
        
        // Verify the roundtrip
        prop_assert_eq!(value, result);
        
        // Clean up
        assert!(cleanup().is_ok());
    }

    #[test]
    fn test_buffer_write_read_u16(value: u16) {
        // Initialize the library
        assert!(init().is_ok());
        
        // Create a buffer and write a u16
        let mut buffer = Buffer::new();
        buffer.write_u16(value);
        
        // Read the u16 back
        let result = buffer.read_u16(0).unwrap();
        
        // Verify the roundtrip
        prop_assert_eq!(value, result);
        
        // Clean up
        assert!(cleanup().is_ok());
    }

    #[test]
    fn test_buffer_write_read_u24(value in 0u32..0x1000000) {
        // Initialize the library
        assert!(init().is_ok());
        
        // Create a buffer and write a u24
        let mut buffer = Buffer::new();
        buffer.write_u24(value);
        
        // Read the u24 back
        let result = buffer.read_u24(0).unwrap();
        
        // Verify the roundtrip
        prop_assert_eq!(value, result);
        
        // Clean up
        assert!(cleanup().is_ok());
    }

    #[test]
    fn test_buffer_write_read_u32(value: u32) {
        // Initialize the library
        assert!(init().is_ok());
        
        // Create a buffer and write a u32
        let mut buffer = Buffer::new();
        buffer.write_u32(value);
        
        // Read the u32 back
        let result = buffer.read_u32(0).unwrap();
        
        // Verify the roundtrip
        prop_assert_eq!(value, result);
        
        // Clean up
        assert!(cleanup().is_ok());
    }

    #[test]
    fn test_buffer_view_read(data in valid_buffer_content()) {
        // Initialize the library
        assert!(init().is_ok());
        
        // Skip empty data
        if data.is_empty() {
            return Ok(());
        }
        
        // Create a buffer view
        let view = BufferView::new(&data);
        
        // Read a u8
        let u8_result = view.read_u8(0).unwrap();
        prop_assert_eq!(u8_result, data[0]);
        
        // Read a slice if possible
        if data.len() >= 3 {
            let slice_result = view.read_slice(0, 3).unwrap();
            prop_assert_eq!(slice_result, &data[0..3]);
        }
        
        // Clean up
        assert!(cleanup().is_ok());
    }

    #[test]
    fn test_buffer_cursor_read(data in valid_buffer_content()) {
        // Initialize the library
        assert!(init().is_ok());
        
        // Skip empty data
        if data.is_empty() {
            return Ok(());
        }
        
        // Create a buffer cursor
        let mut cursor = BufferCursor::new(&data);
        
        // Read a u8
        let u8_result = cursor.read_u8().unwrap();
        prop_assert_eq!(u8_result, data[0]);
        prop_assert_eq!(cursor.position(), 1);
        
        // Read a slice if possible
        cursor.set_position(0);
        if data.len() >= 3 {
            let slice_result = cursor.read_slice(3).unwrap();
            prop_assert_eq!(slice_result, &data[0..3]);
            prop_assert_eq!(cursor.position(), 3);
        }
        
        // Clean up
        assert!(cleanup().is_ok());
    }

    #[test]
    fn test_buffer_append(data1 in valid_buffer_content(), data2 in valid_buffer_content()) {
        // Initialize the library
        assert!(init().is_ok());
        
        // Create a buffer and append data
        let mut buffer = Buffer::from_vec(data1.clone());
        buffer.append(&data2);
        
        // Verify the result
        let mut expected = data1;
        expected.extend_from_slice(&data2);
        prop_assert_eq!(buffer.as_slice(), &expected[..]);
        
        // Clean up
        assert!(cleanup().is_ok());
    }

    #[test]
    fn test_buffer_resize(data in valid_buffer_content(), new_len in 0usize..1024, value: u8) {
        // Initialize the library
        assert!(init().is_ok());
        
        // Create a buffer and resize it
        let mut buffer = Buffer::from_vec(data.clone());
        buffer.resize(new_len, value);
        
        // Verify the result
        let mut expected = data;
        if new_len > expected.len() {
            expected.resize(new_len, value);
        } else {
            expected.truncate(new_len);
        }
        prop_assert_eq!(buffer.as_slice(), &expected[..]);
        
        // Clean up
        assert!(cleanup().is_ok());
    }
}
