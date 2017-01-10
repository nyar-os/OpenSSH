//! TCP transport, version exchange, and the SSH binary packet protocol.
//!
//! Only the packet framing is implemented here. Negotiation, key exchange,
//! authentication, and channels live in the sibling modules.

use std::{
    io::{ErrorKind, Read, Write},
    net::{TcpStream, ToSocketAddrs},
    time::{Duration, Instant},
};

use aes_gcm::{
    Aes256Gcm,
    aead::{AeadInOut, KeyInit, Nonce, Tag},
};

use crate::errors::{Error, ErrorCode};

use super::Result;

/// Client identification string. The product owns this name and never
/// impersonates another client implementation.
const CLIENT_VERSION: &str = "SSH-2.0-WAE_OpenSSH_0.0.0";

/// Upper bound for one SSH packet.
const MAX_PACKET: usize = 256 * 1024;

/// Upper bound for a version line, including CRLF.
const MAX_VERSION_LINE: usize = 1024;

/// One direction of `aes256-gcm@openssh.com`.
pub struct AesGcmState {
    cipher: Aes256Gcm,
    iv: [u8; 12],
}

impl AesGcmState {
    pub(crate) fn new(key: &[u8], iv: &[u8]) -> Result<Self> {
        if key.len() != 32 || iv.len() != 12 {
            return Err(Error::new(ErrorCode::ProtocolError, "derived key material has the wrong length"));
        }
        let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| Error::new(ErrorCode::Internal, "AES key rejected"))?;
        let mut state = [0u8; 12];
        state.copy_from_slice(iv);
        Ok(Self { cipher, iv: state })
    }

    fn encrypt(&mut self, aad: &[u8], buffer: &mut [u8]) -> Result<[u8; 16]> {
        let nonce = Nonce::<Aes256Gcm>::from(self.iv);
        let tag = self
            .cipher
            .encrypt_inout_detached(&nonce, aad, buffer.into())
            .map_err(|_| Error::new(ErrorCode::Internal, "AES-GCM encryption failed"))?;
        self.advance();
        Ok(tag.into())
    }

    fn decrypt(&mut self, aad: &[u8], buffer: &mut [u8], tag: &[u8; 16]) -> Result<()> {
        let nonce = Nonce::<Aes256Gcm>::from(self.iv);
        let tag = Tag::<Aes256Gcm>::from(*tag);
        self.cipher
            .decrypt_inout_detached(&nonce, aad, buffer.into(), &tag)
            .map_err(|_| Error::new(ErrorCode::ProtocolError, "packet authentication failed, so the peer or the wire is not trustworthy"))?;
        self.advance();
        Ok(())
    }

    fn advance(&mut self) {
        for slot in self.iv[4..].iter_mut().rev() {
            let (value, carry) = slot.overflowing_add(1);
            *slot = value;
            if !carry {
                break;
            }
        }
    }
}

/// A connected SSH transport before or after key exchange.
pub struct Transport {
    stream: TcpStream,
    deadline: Instant,
    inbound: Option<AesGcmState>,
    outbound: Option<AesGcmState>,
    client_version: String,
    server_version: String,
    session_id: Vec<u8>,
    client_kexinit: Vec<u8>,
    server_kexinit: Vec<u8>,
}

impl Transport {
    /// Wrap an already accepted connection for the loopback fixture.
    #[cfg(test)]
    pub(crate) fn accept(stream: TcpStream, timeout: Duration) -> Self {
        stream.set_nodelay(true).ok();
        Self {
            stream,
            deadline: Instant::now() + timeout,
            inbound: None,
            outbound: None,
            client_version: String::new(),
            server_version: String::new(),
            session_id: Vec::new(),
            client_kexinit: Vec::new(),
            server_kexinit: Vec::new(),
        }
    }

    /// Server side of the identification exchange, used by the loopback fixture.
    #[cfg(test)]
    pub(crate) fn exchange_versions_as_server(&mut self) -> Result<()> {
        let server = "SSH-2.0-WAE_Fixture_0.0.0\r\n";
        self.write_all(server.as_bytes())?;
        let line = self.read_line()?;
        if !line.starts_with("SSH-2.0-") && !line.starts_with("SSH-1.99-") {
            return Err(Error::new(ErrorCode::NegotiationFailed, "the client does not offer SSH protocol 2.0"));
        }
        self.server_version = server.trim_end_matches("\r\n").to_string();
        self.client_version = line;
        Ok(())
    }

    /// Open a TCP connection under one deadline.
    pub fn connect(host: &str, port: u16, timeout: Duration) -> Result<Self> {
        if host.is_empty() {
            return Err(Error::new(ErrorCode::InvalidArgument, "host must not be empty"));
        }
        if port == 0 {
            return Err(Error::new(ErrorCode::InvalidArgument, "port must not be zero"));
        }
        if timeout.is_zero() {
            return Err(Error::new(ErrorCode::InvalidArgument, "timeout must be greater than zero"));
        }
        let deadline = Instant::now() + timeout;
        let addresses = (host, port)
            .to_socket_addrs()
            .map_err(|error| Error::new(ErrorCode::ConnectFailed, format!("cannot resolve `{host}:{port}`: {error}")))?;
        let mut last_error = None;
        for address in addresses {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(timeout_error("TCP connect timed out"));
            }
            match TcpStream::connect_timeout(&address, remaining) {
                Ok(stream) => {
                    stream.set_nodelay(true).ok();
                    return Ok(Self {
                        stream,
                        deadline,
                        inbound: None,
                        outbound: None,
                        client_version: String::new(),
                        server_version: String::new(),
                        session_id: Vec::new(),
                        client_kexinit: Vec::new(),
                        server_kexinit: Vec::new(),
                    });
                }
                Err(error) if error.kind() == ErrorKind::TimedOut => {
                    return Err(timeout_error(format!("TCP connect to `{address}` timed out")));
                }
                Err(error) => last_error = Some(error),
            }
        }
        let detail = last_error.map(|error| error.to_string()).unwrap_or_else(|| "no address resolved".to_string());
        Err(Error::new(ErrorCode::ConnectFailed, format!("cannot connect to `{host}:{port}`: {detail}")))
    }

    /// Exchange identification strings and require SSH 2.0.
    pub fn exchange_versions(&mut self) -> Result<()> {
        let client = format!("{CLIENT_VERSION}\r\n");
        self.write_all(client.as_bytes())?;
        let mut skipped = 0usize;
        loop {
            let line = self.read_line()?;
            if let Some(rest) = line.strip_prefix("SSH-") {
                let Some((protocol, _software)) = rest.split_once('-')
                else {
                    return Err(Error::new(ErrorCode::ProtocolError, "peer sent a malformed identification string"));
                };
                if protocol != "2.0" && protocol != "1.99" {
                    return Err(Error::new(
                        ErrorCode::NegotiationFailed,
                        format!("peer only offers SSH protocol `{protocol}`, and this client requires `2.0`"),
                    ));
                }
                self.client_version = CLIENT_VERSION.to_string();
                self.server_version = line;
                return Ok(());
            }
            skipped += 1;
            if skipped > 50 {
                return Err(Error::new(ErrorCode::ProtocolError, "peer never sent an SSH identification string"));
            }
        }
    }

    /// Client identification without CRLF.
    pub fn client_version(&self) -> &str {
        &self.client_version
    }

    /// Server identification without CRLF.
    pub fn server_version(&self) -> &str {
        &self.server_version
    }

    /// Record the KEXINIT payloads that the exchange hash commits to.
    pub fn remember_kexinit(&mut self, client: Vec<u8>, server: Vec<u8>) {
        self.client_kexinit = client;
        self.server_kexinit = server;
    }

    /// The client KEXINIT payload.
    pub fn client_kexinit(&self) -> &[u8] {
        &self.client_kexinit
    }

    /// The server KEXINIT payload.
    pub fn server_kexinit(&self) -> &[u8] {
        &self.server_kexinit
    }

    /// Record the session identifier, fixed at the first key exchange.
    pub fn set_session_id(&mut self, session_id: Vec<u8>) {
        self.session_id = session_id;
    }

    /// Session identifier.
    pub fn session_id(&self) -> &[u8] {
        &self.session_id
    }

    /// Activate outbound encryption after sending `SSH_MSG_NEWKEYS`.
    pub fn install_outbound(&mut self, outbound: AesGcmState) {
        self.outbound = Some(outbound);
    }

    /// Activate inbound encryption after receiving `SSH_MSG_NEWKEYS`.
    pub fn install_inbound(&mut self, inbound: AesGcmState) {
        self.inbound = Some(inbound);
    }

    /// Send one SSH payload wrapped in the binary packet protocol.
    pub fn send(&mut self, payload: &[u8]) -> Result<()> {
        let block = if self.outbound.is_some() { 16 } else { 8 };
        let unpadded = 5 + payload.len();
        let mut padding_len = block - (unpadded % block);
        if padding_len < 4 {
            padding_len += block;
        }
        let packet_len = 1 + payload.len() + padding_len;
        let mut packet = Vec::with_capacity(packet_len);
        packet.push(padding_len as u8);
        packet.extend_from_slice(payload);
        packet.resize(packet_len, 0);
        let padding_start = 1 + payload.len();
        getrandom::fill(&mut packet[padding_start..])
            .map_err(|error| Error::new(ErrorCode::Internal, format!("cannot obtain random padding: {error}")))?;
        let length = (packet_len as u32).to_be_bytes();
        match self.outbound.as_mut() {
            Some(cipher) => {
                let tag = cipher.encrypt(&length, &mut packet)?;
                self.write_all(&length)?;
                self.write_all(&packet)?;
                self.write_all(&tag)?;
            }
            None => {
                self.write_all(&length)?;
                self.write_all(&packet)?;
            }
        }
        Ok(())
    }

    /// Receive one SSH payload.
    pub fn receive(&mut self) -> Result<Vec<u8>> {
        let mut length = [0u8; 4];
        self.read_exact(&mut length)?;
        let packet_len = u32::from_be_bytes(length) as usize;
        if !(5..=MAX_PACKET).contains(&packet_len) {
            return Err(Error::new(ErrorCode::ProtocolError, format!("peer announced an invalid packet length of {packet_len}")));
        }
        let mut buffer = vec![0u8; packet_len];
        self.read_exact(&mut buffer)?;
        if self.inbound.is_some() {
            let mut tag = [0u8; 16];
            self.read_exact(&mut tag)?;
            if let Some(cipher) = self.inbound.as_mut() {
                cipher.decrypt(&length, &mut buffer, &tag)?;
            }
        }
        let padding_len = buffer[0] as usize;
        if padding_len < 4 || padding_len + 1 > packet_len {
            return Err(Error::new(ErrorCode::ProtocolError, "peer announced an invalid padding length"));
        }
        let payload_end = packet_len - padding_len;
        Ok(buffer[1..payload_end].to_vec())
    }

    fn read_line(&mut self) -> Result<String> {
        let mut line = Vec::new();
        loop {
            let mut byte = [0u8; 1];
            self.read_exact(&mut byte)?;
            if byte[0] == b'\n' {
                if line.last() == Some(&b'\r') {
                    line.pop();
                }
                return String::from_utf8(line)
                    .map_err(|_| Error::new(ErrorCode::ProtocolError, "peer identification string is not valid UTF-8"));
            }
            line.push(byte[0]);
            if line.len() > MAX_VERSION_LINE {
                return Err(Error::new(ErrorCode::ProtocolError, "peer identification string is too long"));
            }
        }
    }

    fn remaining(&self) -> Result<Duration> {
        let remaining = self.deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(timeout_error("the connection deadline expired"));
        }
        Ok(remaining)
    }

    fn write_all(&mut self, bytes: &[u8]) -> Result<()> {
        let remaining = self.remaining()?;
        self.stream.set_write_timeout(Some(remaining)).ok();
        self.stream.write_all(bytes).map_err(map_write_error)
    }

    fn read_exact(&mut self, bytes: &mut [u8]) -> Result<()> {
        let remaining = self.remaining()?;
        self.stream.set_read_timeout(Some(remaining)).ok();
        self.stream.read_exact(bytes).map_err(map_read_error)
    }
}

fn timeout_error(message: impl Into<String>) -> Error {
    Error::new(ErrorCode::ConnectTimeout, message)
}

fn map_read_error(error: std::io::Error) -> Error {
    match error.kind() {
        ErrorKind::TimedOut | ErrorKind::WouldBlock => timeout_error(format!("timed out while reading from the peer: {error}")),
        ErrorKind::UnexpectedEof => Error::new(ErrorCode::ProtocolError, "the peer closed the connection unexpectedly"),
        _ => Error::new(ErrorCode::Io, format!("read failed: {error}")),
    }
}

fn map_write_error(error: std::io::Error) -> Error {
    match error.kind() {
        ErrorKind::TimedOut | ErrorKind::WouldBlock => timeout_error(format!("timed out while writing to the peer: {error}")),
        _ => Error::new(ErrorCode::Io, format!("write failed: {error}")),
    }
}
