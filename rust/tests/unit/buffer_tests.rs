// Buffer module unit tests

use s2n_tls_rs::{init, cleanup};
use s2n_tls_rs::buffer::{Buffer, BufferView, BufferCursor};

#[test]
fn test_buffer_creation() {
    // Initialize the library
    assert!(init().is_ok());
    
    // Test empty buffer
    let buffer = Buffer::new();
    assert_eq!(buffer.len(), 0);
    assert!(buffer.is_empty());
    
    // Test buffer with capacity
    let buffer = Buffer::with_capacity(10);
    assert_eq!(buffer.len(), 0);
    assert!(buffer.is_empty());
    assert!(buffer.capacity() >= 10);
    
    // Test buffer from vector
    let buffer = Buffer::from_vec(vec![1, 2, 3]);
    assert_eq!(buffer.len(), 3);
    assert!(!buffer.is_empty());
    assert_eq!(buffer.as_slice(), &[1, 2, 3]);
    
    // Test buffer from slice
    let buffer = Buffer::from_slice(&[4, 5, 6]);
    assert_eq!(buffer.len(), 3);
    assert!(!buffer.is_empty());
    assert_eq!(buffer.as_slice(), &[4, 5, 6]);
    
    // Clean up
    assert!(cleanup().is_ok());
}

#[test]
fn test_buffer_operations() {
    // Initialize the library
    assert!(init().is_ok());
    
    // Test push and append
    let mut buffer = Buffer::new();
    buffer.push(1);
    assert_eq!(buffer.len(), 1);
    assert_eq!(buffer.as_slice(), &[1]);
    
    buffer.append(&[2, 3, 4]);
    assert_eq!(buffer.len(), 4);
    assert_eq!(buffer.as_slice(), &[1, 2, 3, 4]);
    
    // Test clear
    buffer.clear();
    assert_eq!(buffer.len(), 0);
    assert!(buffer.is_empty());
    
    // Test resize
    buffer.resize(3, 5);
    assert_eq!(buffer.len(), 3);
    assert_eq!(buffer.as_slice(), &[5, 5, 5]);
    
    // Test reserve
    let capacity = buffer.capacity();
    buffer.reserve(100);
    assert!(buffer.capacity() >= capacity + 100);
    
    // Test into_vec
    let vec = buffer.into_vec();
    assert_eq!(vec, vec![5, 5, 5]);
    
    // Clean up
    assert!(cleanup().is_ok());
}

#[test]
fn test_buffer_write_read() {
    // Initialize the library
    assert!(init().is_ok());
    
    let mut buffer = Buffer::new();
    
    // Test write methods
    buffer.write_u8(0x01);
    buffer.write_u16(0x0203);
    buffer.write_u24(0x040506);
    buffer.write_u32(0x0708090A);
    
    assert_eq!(buffer.len(), 10);
    assert_eq!(buffer.as_slice(), &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A]);
    
    // Test read methods
    assert_eq!(buffer.read_u8(0).unwrap(), 0x01);
    assert_eq!(buffer.read_u16(1).unwrap(), 0x0203);
    assert_eq!(buffer.read_u24(3).unwrap(), 0x040506);
    assert_eq!(buffer.read_u32(6).unwrap(), 0x0708090A);
    
    // Test read_slice
    assert_eq!(buffer.read_slice(1, 3).unwrap(), &[0x02, 0x03, 0x04]);
    
    // Test read errors
    assert!(buffer.read_u8(10).is_err());
    assert!(buffer.read_u16(9).is_err());
    assert!(buffer.read_u24(8).is_err());
    assert!(buffer.read_u32(7).is_err());
    assert!(buffer.read_slice(8, 3).is_err());
    
    // Clean up
    assert!(cleanup().is_ok());
}

#[test]
fn test_buffer_parse() {
    // Initialize the library
    assert!(init().is_ok());
    
    // Create a test structure
    #[derive(Debug, PartialEq, zerocopy::AsBytes, zerocopy::FromBytes, zerocopy::Unaligned)]
    #[repr(C)]
    struct TestStruct {
        a: u8,
        b: u16,
        c: u32,
    }
    
    let mut buffer = Buffer::new();
    
    // Write raw bytes for the structure
    buffer.write_u8(0x01);           // a
    buffer.write_u16(0x0203);        // b (big-endian)
    buffer.write_u32(0x04050607);    // c (big-endian)
    
    // Parse the structure
    let test_struct = buffer.parse::<TestStruct>(0).unwrap();
    assert_eq!(test_struct.a, 0x01);
    
    // Note: The fields b and c will be in native endianness, not big-endian
    // This is because zerocopy doesn't handle endianness conversion
    
    // Test parse_and_advance
    let mut offset = 0;
    let test_struct = buffer.parse_and_advance::<TestStruct>(&mut offset).unwrap();
    assert_eq!(test_struct.a, 0x01);
    assert_eq!(offset, std::mem::size_of::<TestStruct>());
    
    // Test parse errors
    assert!(buffer.parse::<TestStruct>(1).is_err());
    
    // Clean up
    assert!(cleanup().is_ok());
}

#[test]
fn test_buffer_view() {
    // Initialize the library
    assert!(init().is_ok());
    
    // Create a buffer view from a slice
    let data = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A];
    let view = BufferView::new(&data);
    
    // Test basic properties
    assert_eq!(view.len(), 10);
    assert!(!view.is_empty());
    assert_eq!(view.as_slice(), &data);
    
    // Test read methods
    assert_eq!(view.read_u8(0).unwrap(), 0x01);
    assert_eq!(view.read_u16(1).unwrap(), 0x0203);
    assert_eq!(view.read_u24(3).unwrap(), 0x040506);
    assert_eq!(view.read_u32(6).unwrap(), 0x0708090A);
    
    // Test read_slice
    assert_eq!(view.read_slice(1, 3).unwrap(), &[0x02, 0x03, 0x04]);
    
    // Test read errors
    assert!(view.read_u8(10).is_err());
    assert!(view.read_u16(9).is_err());
    assert!(view.read_u24(8).is_err());
    assert!(view.read_u32(7).is_err());
    assert!(view.read_slice(8, 3).is_err());
    
    // Test parse methods
    #[derive(Debug, PartialEq, zerocopy::AsBytes, zerocopy::FromBytes, zerocopy::Unaligned)]
    #[repr(C)]
    struct TestStruct {
        a: u8,
        b: u8,
        c: u8,
    }
    
    let test_struct = view.parse::<TestStruct>(0).unwrap();
    assert_eq!(test_struct.a, 0x01);
    assert_eq!(test_struct.b, 0x02);
    assert_eq!(test_struct.c, 0x03);
    
    // Test parse_and_advance
    let mut offset = 0;
    let test_struct = view.parse_and_advance::<TestStruct>(&mut offset).unwrap();
    assert_eq!(test_struct.a, 0x01);
    assert_eq!(test_struct.b, 0x02);
    assert_eq!(test_struct.c, 0x03);
    assert_eq!(offset, std::mem::size_of::<TestStruct>());
    
    // Clean up
    assert!(cleanup().is_ok());
}

#[test]
fn test_buffer_cursor() {
    // Initialize the library
    assert!(init().is_ok());
    
    // Create a buffer cursor from a slice
    let data = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A];
    let mut cursor = BufferCursor::new(&data);
    
    // Test initial state
    assert_eq!(cursor.position(), 0);
    assert_eq!(cursor.remaining(), 10);
    assert!(!cursor.is_empty());
    
    // Test read methods
    assert_eq!(cursor.read_u8().unwrap(), 0x01);
    assert_eq!(cursor.position(), 1);
    assert_eq!(cursor.remaining(), 9);
    
    assert_eq!(cursor.read_u16().unwrap(), 0x0203);
    assert_eq!(cursor.position(), 3);
    assert_eq!(cursor.remaining(), 7);
    
    assert_eq!(cursor.read_u24().unwrap(), 0x040506);
    assert_eq!(cursor.position(), 6);
    assert_eq!(cursor.remaining(), 4);
    
    assert_eq!(cursor.read_u32().unwrap(), 0x0708090A);
    assert_eq!(cursor.position(), 10);
    assert_eq!(cursor.remaining(), 0);
    assert!(cursor.is_empty());
    
    // Test read errors when at end
    assert!(cursor.read_u8().is_err());
    
    // Test set_position
    cursor.set_position(0);
    assert_eq!(cursor.position(), 0);
    assert_eq!(cursor.remaining(), 10);
    assert!(!cursor.is_empty());
    
    // Test skip
    assert!(cursor.skip(5).is_ok());
    assert_eq!(cursor.position(), 5);
    assert_eq!(cursor.remaining(), 5);
    
    // Test read_slice
    assert_eq!(cursor.read_slice(3).unwrap(), &[0x06, 0x07, 0x08]);
    assert_eq!(cursor.position(), 8);
    assert_eq!(cursor.remaining(), 2);
    
    // Test parse
    cursor.set_position(0);
    #[derive(Debug, PartialEq, zerocopy::AsBytes, zerocopy::FromBytes, zerocopy::Unaligned)]
    #[repr(C)]
    struct TestStruct {
        a: u8,
        b: u8,
        c: u8,
    }
    
    let test_struct = cursor.parse::<TestStruct>().unwrap();
    assert_eq!(test_struct.a, 0x01);
    assert_eq!(test_struct.b, 0x02);
    assert_eq!(test_struct.c, 0x03);
    assert_eq!(cursor.position(), std::mem::size_of::<TestStruct>());
    
    // Clean up
    assert!(cleanup().is_ok());
}

#[test]
fn test_buffer_traits() {
    // Initialize the library
    assert!(init().is_ok());
    
    // Test Deref trait
    let buffer = Buffer::from_slice(&[1, 2, 3]);
    assert_eq!(buffer[0], 1);
    assert_eq!(buffer[1], 2);
    assert_eq!(buffer[2], 3);
    
    // Test DerefMut trait
    let mut buffer = Buffer::from_slice(&[1, 2, 3]);
    buffer[0] = 4;
    assert_eq!(buffer.as_slice(), &[4, 2, 3]);
    
    // Test AsRef trait
    let buffer = Buffer::from_slice(&[1, 2, 3]);
    let slice: &[u8] = buffer.as_ref();
    assert_eq!(slice, &[1, 2, 3]);
    
    // Test AsMut trait
    let mut buffer = Buffer::from_slice(&[1, 2, 3]);
    let slice: &mut [u8] = buffer.as_mut();
    slice[0] = 4;
    assert_eq!(buffer.as_slice(), &[4, 2, 3]);
    
    // Test From<Vec<u8>> trait
    let buffer = Buffer::from(vec![1, 2, 3]);
    assert_eq!(buffer.as_slice(), &[1, 2, 3]);
    
    // Test From<&[u8]> trait
    let buffer = Buffer::from(&[1, 2, 3][..]);
    assert_eq!(buffer.as_slice(), &[1, 2, 3]);
    
    // Test From<Buffer> for Vec<u8> trait
    let buffer = Buffer::from_slice(&[1, 2, 3]);
    let vec: Vec<u8> = buffer.into();
    assert_eq!(vec, vec![1, 2, 3]);
    
    // Test BufferView traits
    let view = BufferView::from(&[1, 2, 3][..]);
    assert_eq!(view[0], 1);
    assert_eq!(view[1], 2);
    assert_eq!(view[2], 3);
    
    let slice: &[u8] = view.as_ref();
    assert_eq!(slice, &[1, 2, 3]);
    
    // Clean up
    assert!(cleanup().is_ok());
}
