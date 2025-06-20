//! Buffer management module
//!
//! This module provides safe buffer abstractions and zero-copy parsing utilities.

use std::convert::{TryFrom, TryInto};
use std::fmt;
use std::ops::{Deref, DerefMut};
use zerocopy::{AsBytes, FromBytes, LayoutVerified, Unaligned};

use crate::error::{Error, InternalError, ProtocolError};

/// A buffer that owns its data
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Buffer {
    /// The underlying data
    data: Vec<u8>,
}

impl Buffer {
    /// Create a new empty buffer
    pub fn new() -> Self {
        Self { data: Vec::new() }
    }

    /// Create a new buffer with the given capacity
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            data: Vec::with_capacity(capacity),
        }
    }

    /// Create a new buffer from a vector
    pub fn from_vec(data: Vec<u8>) -> Self {
        Self { data }
    }

    /// Create a new buffer from a slice
    pub fn from_slice(data: &[u8]) -> Self {
        Self {
            data: data.to_vec(),
        }
    }

    /// Get the length of the buffer
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if the buffer is empty
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Get the capacity of the buffer
    pub fn capacity(&self) -> usize {
        self.data.capacity()
    }

    /// Get a reference to the underlying data
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    /// Get a mutable reference to the underlying data
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }

    /// Append data to the buffer
    pub fn append(&mut self, data: &[u8]) {
        self.data.extend_from_slice(data);
    }

    /// Append a single byte to the buffer
    pub fn push(&mut self, byte: u8) {
        self.data.push(byte);
    }

    /// Clear the buffer
    pub fn clear(&mut self) {
        self.data.clear();
    }

    /// Resize the buffer
    pub fn resize(&mut self, new_len: usize, value: u8) {
        self.data.resize(new_len, value);
    }

    /// Reserve capacity for at least `additional` more bytes
    pub fn reserve(&mut self, additional: usize) {
        self.data.reserve(additional);
    }

    /// Consume the buffer and return the underlying vector
    pub fn into_vec(self) -> Vec<u8> {
        self.data
    }

    /// Parse a fixed-size structure from the buffer
    pub fn parse<T: FromBytes + AsBytes + Unaligned>(&self, offset: usize) -> Result<&T, Error> {
        if offset + std::mem::size_of::<T>() > self.data.len() {
            return Err(Error::protocol(ProtocolError::Other(
                "Buffer too small for parsing".into(),
            )));
        }

        let layout = LayoutVerified::<_, T>::new_unaligned(&self.data[offset..])
            .ok_or_else(|| Error::internal(InternalError::Other("Layout verification failed".into())))?;

        Ok(layout.into_ref())
    }

    /// Parse a fixed-size structure from the buffer and advance the offset
    pub fn parse_and_advance<T: FromBytes + AsBytes + Unaligned>(
        &self,
        offset: &mut usize,
    ) -> Result<&T, Error> {
        let result = self.parse::<T>(*offset)?;
        *offset += std::mem::size_of::<T>();
        Ok(result)
    }

    /// Write a fixed-size structure to the buffer
    pub fn write<T: FromBytes + AsBytes + Unaligned>(&mut self, value: &T) {
        self.data.extend_from_slice(value.as_bytes());
    }

    /// Write a u8 to the buffer
    pub fn write_u8(&mut self, value: u8) {
        self.data.push(value);
    }

    /// Write a u16 to the buffer in big-endian format
    pub fn write_u16(&mut self, value: u16) {
        self.data.push((value >> 8) as u8);
        self.data.push(value as u8);
    }

    /// Write a u24 to the buffer in big-endian format
    pub fn write_u24(&mut self, value: u32) {
        self.data.push((value >> 16) as u8);
        self.data.push((value >> 8) as u8);
        self.data.push(value as u8);
    }

    /// Write a u32 to the buffer in big-endian format
    pub fn write_u32(&mut self, value: u32) {
        self.data.push((value >> 24) as u8);
        self.data.push((value >> 16) as u8);
        self.data.push((value >> 8) as u8);
        self.data.push(value as u8);
    }

    /// Read a u8 from the buffer at the given offset
    pub fn read_u8(&self, offset: usize) -> Result<u8, Error> {
        if offset >= self.data.len() {
            return Err(Error::protocol(ProtocolError::Other(
                "Buffer too small for reading u8".into(),
            )));
        }
        Ok(self.data[offset])
    }

    /// Read a u16 from the buffer at the given offset in big-endian format
    pub fn read_u16(&self, offset: usize) -> Result<u16, Error> {
        if offset + 2 > self.data.len() {
            return Err(Error::protocol(ProtocolError::Other(
                "Buffer too small for reading u16".into(),
            )));
        }
        Ok(((self.data[offset] as u16) << 8) | (self.data[offset + 1] as u16))
    }

    /// Read a u24 from the buffer at the given offset in big-endian format
    pub fn read_u24(&self, offset: usize) -> Result<u32, Error> {
        if offset + 3 > self.data.len() {
            return Err(Error::protocol(ProtocolError::Other(
                "Buffer too small for reading u24".into(),
            )));
        }
        Ok(((self.data[offset] as u32) << 16)
            | ((self.data[offset + 1] as u32) << 8)
            | (self.data[offset + 2] as u32))
    }

    /// Read a u32 from the buffer at the given offset in big-endian format
    pub fn read_u32(&self, offset: usize) -> Result<u32, Error> {
        if offset + 4 > self.data.len() {
            return Err(Error::protocol(ProtocolError::Other(
                "Buffer too small for reading u32".into(),
            )));
        }
        Ok(((self.data[offset] as u32) << 24)
            | ((self.data[offset + 1] as u32) << 16)
            | ((self.data[offset + 2] as u32) << 8)
            | (self.data[offset + 3] as u32))
    }

    /// Read a slice from the buffer at the given offset
    pub fn read_slice(&self, offset: usize, length: usize) -> Result<&[u8], Error> {
        if offset + length > self.data.len() {
            return Err(Error::protocol(ProtocolError::Other(
                "Buffer too small for reading slice".into(),
            )));
        }
        Ok(&self.data[offset..offset + length])
    }

    /// Read a slice from the buffer at the given offset and advance the offset
    pub fn read_slice_and_advance<'a>(
        &'a self,
        offset: &mut usize,
        length: usize,
    ) -> Result<&'a [u8], Error> {
        let result = self.read_slice(*offset, length)?;
        *offset += length;
        Ok(result)
    }
}

impl Default for Buffer {
    fn default() -> Self {
        Self::new()
    }
}

impl Deref for Buffer {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl DerefMut for Buffer {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.data
    }
}

impl AsRef<[u8]> for Buffer {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

impl AsMut<[u8]> for Buffer {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }
}

impl From<Vec<u8>> for Buffer {
    fn from(data: Vec<u8>) -> Self {
        Self { data }
    }
}

impl From<&[u8]> for Buffer {
    fn from(data: &[u8]) -> Self {
        Self {
            data: data.to_vec(),
        }
    }
}

impl From<Buffer> for Vec<u8> {
    fn from(buffer: Buffer) -> Self {
        buffer.data
    }
}

/// A buffer that references data owned by someone else
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BufferView<'a> {
    /// The underlying data
    data: &'a [u8],
}

impl<'a> BufferView<'a> {
    /// Create a new buffer view
    pub fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    /// Get the length of the buffer
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if the buffer is empty
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Get a reference to the underlying data
    pub fn as_slice(&self) -> &'a [u8] {
        self.data
    }

    /// Parse a fixed-size structure from the buffer
    pub fn parse<T: FromBytes + AsBytes + Unaligned>(&self, offset: usize) -> Result<&'a T, Error> {
        if offset + std::mem::size_of::<T>() > self.data.len() {
            return Err(Error::protocol(ProtocolError::Other(
                "Buffer too small for parsing".into(),
            )));
        }

        let layout = LayoutVerified::<_, T>::new_unaligned(&self.data[offset..])
            .ok_or_else(|| Error::internal(InternalError::Other("Layout verification failed".into())))?;

        Ok(layout.into_ref())
    }

    /// Parse a fixed-size structure from the buffer and advance the offset
    pub fn parse_and_advance<T: FromBytes + AsBytes + Unaligned>(
        &self,
        offset: &mut usize,
    ) -> Result<&'a T, Error> {
        let result = self.parse::<T>(*offset)?;
        *offset += std::mem::size_of::<T>();
        Ok(result)
    }

    /// Read a u8 from the buffer at the given offset
    pub fn read_u8(&self, offset: usize) -> Result<u8, Error> {
        if offset >= self.data.len() {
            return Err(Error::protocol(ProtocolError::Other(
                "Buffer too small for reading u8".into(),
            )));
        }
        Ok(self.data[offset])
    }

    /// Read a u16 from the buffer at the given offset in big-endian format
    pub fn read_u16(&self, offset: usize) -> Result<u16, Error> {
        if offset + 2 > self.data.len() {
            return Err(Error::protocol(ProtocolError::Other(
                "Buffer too small for reading u16".into(),
            )));
        }
        Ok(((self.data[offset] as u16) << 8) | (self.data[offset + 1] as u16))
    }

    /// Read a u24 from the buffer at the given offset in big-endian format
    pub fn read_u24(&self, offset: usize) -> Result<u32, Error> {
        if offset + 3 > self.data.len() {
            return Err(Error::protocol(ProtocolError::Other(
                "Buffer too small for reading u24".into(),
            )));
        }
        Ok(((self.data[offset] as u32) << 16)
            | ((self.data[offset + 1] as u32) << 8)
            | (self.data[offset + 2] as u32))
    }

    /// Read a u32 from the buffer at the given offset in big-endian format
    pub fn read_u32(&self, offset: usize) -> Result<u32, Error> {
        if offset + 4 > self.data.len() {
            return Err(Error::protocol(ProtocolError::Other(
                "Buffer too small for reading u32".into(),
            )));
        }
        Ok(((self.data[offset] as u32) << 24)
            | ((self.data[offset + 1] as u32) << 16)
            | ((self.data[offset + 2] as u32) << 8)
            | (self.data[offset + 3] as u32))
    }

    /// Read a slice from the buffer at the given offset
    pub fn read_slice(&self, offset: usize, length: usize) -> Result<&'a [u8], Error> {
        if offset + length > self.data.len() {
            return Err(Error::protocol(ProtocolError::Other(
                "Buffer too small for reading slice".into(),
            )));
        }
        Ok(&self.data[offset..offset + length])
    }

    /// Read a slice from the buffer at the given offset and advance the offset
    pub fn read_slice_and_advance<'b>(
        &'b self,
        offset: &mut usize,
        length: usize,
    ) -> Result<&'a [u8], Error> {
        let result = self.read_slice(*offset, length)?;
        *offset += length;
        Ok(result)
    }
}

impl<'a> Deref for BufferView<'a> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.data
    }
}

impl<'a> AsRef<[u8]> for BufferView<'a> {
    fn as_ref(&self) -> &[u8] {
        self.data
    }
}

impl<'a> From<&'a [u8]> for BufferView<'a> {
    fn from(data: &'a [u8]) -> Self {
        Self { data }
    }
}

/// A cursor for reading from a buffer
#[derive(Debug, Clone, Copy)]
pub struct BufferCursor<'a> {
    /// The buffer being read
    buffer: BufferView<'a>,
    /// The current position in the buffer
    position: usize,
}

impl<'a> BufferCursor<'a> {
    /// Create a new buffer cursor
    pub fn new(buffer: &'a [u8]) -> Self {
        Self {
            buffer: BufferView::new(buffer),
            position: 0,
        }
    }

    /// Get the current position
    pub fn position(&self) -> usize {
        self.position
    }

    /// Set the current position
    pub fn set_position(&mut self, position: usize) {
        self.position = position;
    }

    /// Get the remaining length
    pub fn remaining(&self) -> usize {
        self.buffer.len().saturating_sub(self.position)
    }

    /// Check if the cursor is at the end of the buffer
    pub fn is_empty(&self) -> bool {
        self.position >= self.buffer.len()
    }

    /// Skip a number of bytes
    pub fn skip(&mut self, count: usize) -> Result<(), Error> {
        if self.position + count > self.buffer.len() {
            return Err(Error::protocol(ProtocolError::Other(
                "Buffer too small for skipping".into(),
            )));
        }
        self.position += count;
        Ok(())
    }

    /// Read a u8 from the buffer
    pub fn read_u8(&mut self) -> Result<u8, Error> {
        let result = self.buffer.read_u8(self.position)?;
        self.position += 1;
        Ok(result)
    }

    /// Read a u16 from the buffer in big-endian format
    pub fn read_u16(&mut self) -> Result<u16, Error> {
        let result = self.buffer.read_u16(self.position)?;
        self.position += 2;
        Ok(result)
    }

    /// Read a u24 from the buffer in big-endian format
    pub fn read_u24(&mut self) -> Result<u32, Error> {
        let result = self.buffer.read_u24(self.position)?;
        self.position += 3;
        Ok(result)
    }

    /// Read a u32 from the buffer in big-endian format
    pub fn read_u32(&mut self) -> Result<u32, Error> {
        let result = self.buffer.read_u32(self.position)?;
        self.position += 4;
        Ok(result)
    }

    /// Read a slice from the buffer
    pub fn read_slice(&mut self, length: usize) -> Result<&'a [u8], Error> {
        let result = self.buffer.read_slice(self.position, length)?;
        self.position += length;
        Ok(result)
    }

    /// Parse a fixed-size structure from the buffer
    pub fn parse<T: FromBytes + AsBytes + Unaligned>(&mut self) -> Result<&'a T, Error> {
        let result = self.buffer.parse::<T>(self.position)?;
        self.position += std::mem::size_of::<T>();
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_buffer_basic() {
        let mut buffer = Buffer::new();
        assert_eq!(buffer.len(), 0);
        assert!(buffer.is_empty());

        buffer.push(1);
        buffer.push(2);
        buffer.push(3);
        assert_eq!(buffer.len(), 3);
        assert!(!buffer.is_empty());
        assert_eq!(buffer.as_slice(), &[1, 2, 3]);

        buffer.clear();
        assert_eq!(buffer.len(), 0);
        assert!(buffer.is_empty());
    }

    #[test]
    fn test_buffer_write_read() {
        let mut buffer = Buffer::new();
        buffer.write_u8(1);
        buffer.write_u16(0x0203);
        buffer.write_u24(0x040506);
        buffer.write_u32(0x0708090A);

        assert_eq!(buffer.len(), 10);
        assert_eq!(buffer.as_slice(), &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);

        assert_eq!(buffer.read_u8(0).unwrap(), 1);
        assert_eq!(buffer.read_u16(1).unwrap(), 0x0203);
        assert_eq!(buffer.read_u24(3).unwrap(), 0x040506);
        assert_eq!(buffer.read_u32(6).unwrap(), 0x0708090A);
    }

    #[test]
    fn test_buffer_view() {
        let data = [1, 2, 3, 4, 5];
        let view = BufferView::new(&data);
        assert_eq!(view.len(), 5);
        assert!(!view.is_empty());
        assert_eq!(view.as_slice(), &[1, 2, 3, 4, 5]);

        assert_eq!(view.read_u8(0).unwrap(), 1);
        assert_eq!(view.read_u16(1).unwrap(), 0x0203);
        assert_eq!(view.read_slice(2, 3).unwrap(), &[3, 4, 5]);
    }

    #[test]
    fn test_buffer_cursor() {
        let data = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let mut cursor = BufferCursor::new(&data);
        assert_eq!(cursor.position(), 0);
        assert_eq!(cursor.remaining(), 10);
        assert!(!cursor.is_empty());

        assert_eq!(cursor.read_u8().unwrap(), 1);
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
    }
}
