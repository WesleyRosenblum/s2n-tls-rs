// Buffer module snapshot tests

use insta::assert_debug_snapshot;
use s2n_tls_rs::{init, cleanup};
use s2n_tls_rs::buffer::{Buffer, BufferView, BufferCursor};

#[test]
fn test_buffer_snapshot() {
    // Initialize the library
    assert!(init().is_ok());
    
    // Create a buffer with fixed test data
    let mut buffer = Buffer::new();
    buffer.write_u8(0x01);
    buffer.write_u16(0x0203);
    buffer.write_u24(0x040506);
    buffer.write_u32(0x0708090A);
    
    // Create a snapshot of the buffer
    assert_debug_snapshot!("buffer_snapshot", buffer);
    
    // Clean up
    assert!(cleanup().is_ok());
}

#[test]
fn test_buffer_view_snapshot() {
    // Initialize the library
    assert!(init().is_ok());
    
    // Create a buffer view with fixed test data
    let data = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A];
    let view = BufferView::new(&data);
    
    // Create a snapshot of the buffer view
    assert_debug_snapshot!("buffer_view_snapshot", view);
    
    // Clean up
    assert!(cleanup().is_ok());
}

#[test]
fn test_buffer_cursor_snapshot() {
    // Initialize the library
    assert!(init().is_ok());
    
    // Create a buffer cursor with fixed test data
    let data = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A];
    let cursor = BufferCursor::new(&data);
    
    // Create a snapshot of the buffer cursor
    assert_debug_snapshot!("buffer_cursor_snapshot", cursor);
    
    // Clean up
    assert!(cleanup().is_ok());
}

#[test]
fn test_buffer_operations_snapshot() {
    // Initialize the library
    assert!(init().is_ok());
    
    // Create a buffer with fixed test data
    let mut buffer = Buffer::new();
    buffer.write_u8(0x01);
    buffer.write_u16(0x0203);
    buffer.write_u24(0x040506);
    buffer.write_u32(0x0708090A);
    
    // Read values from the buffer
    let u8_value = buffer.read_u8(0).unwrap();
    let u16_value = buffer.read_u16(1).unwrap();
    let u24_value = buffer.read_u24(3).unwrap();
    let u32_value = buffer.read_u32(6).unwrap();
    let slice = buffer.read_slice(1, 3).unwrap();
    
    // Create snapshots of the read values
    assert_debug_snapshot!("buffer_read_u8_snapshot", u8_value);
    assert_debug_snapshot!("buffer_read_u16_snapshot", u16_value);
    assert_debug_snapshot!("buffer_read_u24_snapshot", u24_value);
    assert_debug_snapshot!("buffer_read_u32_snapshot", u32_value);
    assert_debug_snapshot!("buffer_read_slice_snapshot", slice);
    
    // Clean up
    assert!(cleanup().is_ok());
}

#[test]
fn test_buffer_cursor_operations_snapshot() {
    // Initialize the library
    assert!(init().is_ok());
    
    // Create a buffer cursor with fixed test data
    let data = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A];
    let mut cursor = BufferCursor::new(&data);
    
    // Read values from the cursor
    let u8_value = cursor.read_u8().unwrap();
    let u16_value = cursor.read_u16().unwrap();
    let u24_value = cursor.read_u24().unwrap();
    let u32_value = cursor.read_u32().unwrap();
    
    // Create snapshots of the cursor state after each read
    assert_debug_snapshot!("buffer_cursor_after_read_u8_snapshot", cursor.position());
    
    // Reset cursor position
    cursor.set_position(0);
    
    // Read a slice from the cursor
    let slice = cursor.read_slice(5).unwrap();
    
    // Create a snapshot of the slice
    assert_debug_snapshot!("buffer_cursor_read_slice_snapshot", slice);
    
    // Clean up
    assert!(cleanup().is_ok());
}
