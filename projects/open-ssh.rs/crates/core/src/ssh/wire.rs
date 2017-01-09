//! SSH data types from RFC 4251 section 5.
//!
//! The writer and reader are deliberately small: every message this client
//! sends or accepts is built and parsed here instead of by a third-party
//! protocol crate.

use crate::errors::{Error, ErrorCode};

use super::Result;

/// Builds one SSH message payload, starting with its message number.
pub struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    /// Start a payload with its message number.
    pub fn new(message: u8) -> Self {
        Self { buf: vec![message] }
    }

    /// Start an empty buffer for blob-shaped data without a message number.
    pub fn empty() -> Self {
        Self { buf: Vec::new() }
    }

    /// Append one byte.
    pub fn byte(&mut self, value: u8) -> &mut Self {
        self.buf.push(value);
        self
    }

    /// Append a boolean, encoded as one byte.
    pub fn boolean(&mut self, value: bool) -> &mut Self {
        self.byte(u8::from(value))
    }

    /// Append a `uint32`.
    pub fn u32(&mut self, value: u32) -> &mut Self {
        self.buf.extend_from_slice(&value.to_be_bytes());
        self
    }

    /// Append raw bytes that are already encoded.
    pub fn raw(&mut self, value: &[u8]) -> &mut Self {
        self.buf.extend_from_slice(value);
        self
    }

    /// Append a length-prefixed byte string.
    pub fn string(&mut self, value: &[u8]) -> &mut Self {
        self.u32(value.len() as u32);
        self.buf.extend_from_slice(value);
        self
    }

    /// Append a name-list.
    pub fn name_list(&mut self, values: &[&str]) -> &mut Self {
        self.string(values.join(",").as_bytes())
    }

    /// Finish the payload.
    pub fn finish(self) -> Vec<u8> {
        self.buf
    }
}

/// Encode a big-endian magnitude as an `mpint` two's-complement value.
pub fn encode_mpint(magnitude: &[u8]) -> Vec<u8> {
    let start = magnitude.iter().position(|byte| *byte != 0).unwrap_or(magnitude.len());
    let significant = &magnitude[start..];
    let mut encoded = Vec::with_capacity(significant.len() + 1);
    if significant.first().is_some_and(|byte| byte & 0x80 != 0) {
        encoded.push(0);
    }
    encoded.extend_from_slice(significant);
    encoded
}

/// Reads one SSH payload.
pub struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    /// Wrap a received payload.
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(len).ok_or_else(truncated)?;
        if end > self.data.len() {
            return Err(truncated());
        }
        let slice = &self.data[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    /// Read one byte.
    pub fn byte(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    /// Read a boolean.
    pub fn boolean(&mut self) -> Result<bool> {
        Ok(self.byte()? != 0)
    }

    /// Read a `uint32`.
    pub fn u32(&mut self) -> Result<u32> {
        let bytes = self.take(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    /// Read a length-prefixed byte string.
    pub fn string(&mut self) -> Result<&'a [u8]> {
        let len = self.u32()? as usize;
        self.take(len)
    }

    /// Read a name-list.
    pub fn name_list(&mut self) -> Result<Vec<&'a str>> {
        let raw = self.string()?;
        if raw.is_empty() {
            return Ok(Vec::new());
        }
        let text = std::str::from_utf8(raw).map_err(|_| invalid("name-list is not valid UTF-8"))?;
        Ok(text.split(',').collect())
    }

    /// Whether every byte was consumed.
    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.pos >= self.data.len()
    }
}

fn truncated() -> Error {
    Error::new(ErrorCode::ProtocolError, "peer sent a truncated SSH message")
}

fn invalid(message: &str) -> Error {
    Error::new(ErrorCode::ProtocolError, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mpint_drops_leading_zeros_and_adds_a_sign_byte() {
        assert_eq!(encode_mpint(&[0, 0, 0x12, 0x34]), vec![0x12, 0x34]);
        assert_eq!(encode_mpint(&[0x80]), vec![0x00, 0x80]);
        assert_eq!(encode_mpint(&[0, 0, 0]), Vec::<u8>::new());
    }

    #[test]
    fn round_trips_every_type() {
        let mut writer = Writer::new(20);
        writer.u32(7).boolean(true).string(b"abc").name_list(&["a", "b"]);
        let payload = writer.finish();
        let mut reader = Reader::new(&payload);
        assert_eq!(reader.byte().expect("message"), 20);
        assert_eq!(reader.u32().expect("u32"), 7);
        assert!(reader.boolean().expect("bool"));
        assert_eq!(reader.string().expect("string"), b"abc");
        assert_eq!(reader.name_list().expect("names"), vec!["a", "b"]);
        assert!(reader.is_empty());
    }

    #[test]
    fn truncated_input_is_a_protocol_error() {
        let payload = [1u8, 0, 0];
        let mut reader = Reader::new(&payload);
        let error = reader.u32().expect_err("truncated u32 must fail");
        assert_eq!(error.code(), ErrorCode::ProtocolError);
    }
}
