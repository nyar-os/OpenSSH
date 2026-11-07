//! SFTP version 3 client running over an SSH session channel.
//!
//! Only the operations the `transfer` capability needs are implemented:
//! `open`, `read`, `write`, `close`, `stat`, `opendir`, and `readdir`.

use crate::errors::{Error, ErrorCode};

use super::{
    Result,
    channel::Channel,
    transport::Transport,
    wire::{Reader, Writer},
};

const MSG_INIT: u8 = 1;
const MSG_VERSION: u8 = 2;
const MSG_OPEN: u8 = 3;
const MSG_CLOSE: u8 = 4;
const MSG_READ: u8 = 5;
const MSG_WRITE: u8 = 6;
const MSG_OPENDIR: u8 = 11;
const MSG_READDIR: u8 = 12;
const MSG_STAT: u8 = 17;
const MSG_STATUS: u8 = 101;
const MSG_HANDLE: u8 = 102;
const MSG_DATA: u8 = 103;
const MSG_NAME: u8 = 104;

const STATUS_OK: u32 = 0;
const STATUS_EOF: u32 = 1;
const STATUS_NO_SUCH_FILE: u32 = 2;
const STATUS_PERMISSION_DENIED: u32 = 3;
const STATUS_CONNECTION_LOST: u32 = 7;

const FLAG_SIZE: u32 = 1;

const READ: u32 = 1;
const WRITE: u32 = 2;
const CREATE: u32 = 8;
const TRUNCATE: u32 = 16;

/// Largest data payload carried by one SFTP packet.
pub(crate) const CHUNK: usize = 16 * 1024;

/// One directory entry returned by `readdir`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RemoteEntry {
    /// Entry name, relative to the listed directory.
    pub name: String,
    /// Entry size in bytes. Zero for directories.
    pub size: u64,
    /// Whether the entry is a directory.
    pub is_dir: bool,
}

/// An open SFTP session.
pub(crate) struct SftpClient<'a> {
    transport: &'a mut Transport,
    channel: Channel,
    next_id: u32,
    inbound: Vec<u8>,
}

impl<'a> SftpClient<'a> {
    /// Open the `sftp` subsystem and complete the version exchange.
    pub(crate) fn open(transport: &'a mut Transport) -> Result<Self> {
        let mut channel = Channel::open(transport, ErrorCode::TransferFailed)?;
        channel.request_subsystem(transport, "sftp")?;
        let mut client = Self { transport, channel, next_id: 1, inbound: Vec::new() };
        let mut init = Writer::new(MSG_INIT);
        init.u32(3);
        client.write_packet(&init.finish())?;
        let packet = client.read_packet()?;
        let mut reader = Reader::new(&packet);
        if reader.byte()? != MSG_VERSION {
            return Err(protocol("expected `SSH_FXP_VERSION`"));
        }
        let version = reader.u32()?;
        if version != 3 {
            return Err(protocol(format!("the server selected SFTP version {version}, and this client implements version 3")));
        }
        Ok(client)
    }

    /// Remote file size, or `None` when the path does not exist.
    pub(crate) fn size(&mut self, path: &str) -> Result<Option<u64>> {
        let id = self.next_id();
        let mut request = Writer::new(MSG_STAT);
        request.u32(id).string(path.as_bytes());
        let packet = self.roundtrip(id, &request.finish())?;
        let mut reader = Reader::new(&packet);
        let response = reader.byte()?;
        let _ = reader.u32()?;
        match response {
            MSG_STATUS => {
                let (code, _message) = parse_status(&mut reader)?;
                if code == STATUS_NO_SUCH_FILE {
                    return Ok(None);
                }
                Err(status_error(code, path))
            }
            MSG_STATUS_ATTRS => {
                let flags = reader.u32()?;
                if flags & FLAG_SIZE == 0 {
                    return Err(protocol("the server returned attributes without a size"));
                }
                Ok(Some(reader.u64()?))
            }
            other => Err(protocol(format!("unexpected response {} to `stat`", other))),
        }
    }

    /// Create or truncate a remote file and return its handle.
    pub(crate) fn create(&mut self, path: &str, append: bool) -> Result<Vec<u8>> {
        let mut flags = WRITE | CREATE;
        if !append {
            flags |= TRUNCATE;
        }
        self.open_handle(path, flags)
    }

    /// Open an existing remote file for reading.
    pub(crate) fn open_read(&mut self, path: &str) -> Result<Vec<u8>> {
        self.open_handle(path, READ)
    }

    fn open_handle(&mut self, path: &str, flags: u32) -> Result<Vec<u8>> {
        let id = self.next_id();
        let mut request = Writer::new(MSG_OPEN);
        request.u32(id).string(path.as_bytes()).u32(flags);
        request.u32(0);
        let packet = self.roundtrip(id, &request.finish())?;
        let mut reader = Reader::new(&packet);
        let response = reader.byte()?;
        let _ = reader.u32()?;
        match response {
            MSG_HANDLE => Ok(reader.string()?.to_vec()),
            MSG_STATUS => {
                let (code, message) = parse_status(&mut reader)?;
                Err(status_error_with_message(code, path, &message))
            }
            other => Err(protocol(format!("unexpected response {} to `open`", other))),
        }
    }

    /// Write one chunk at an absolute offset.
    pub(crate) fn write_at(&mut self, handle: &[u8], offset: u64, data: &[u8]) -> Result<()> {
        let id = self.next_id();
        let mut request = Writer::new(MSG_WRITE);
        request.u32(id).string(handle).u64(offset).string(data);
        let packet = self.roundtrip(id, &request.finish())?;
        let mut reader = Reader::new(&packet);
        let response = reader.byte()?;
        let _ = reader.u32()?;
        if response != MSG_STATUS {
            return Err(protocol(format!("unexpected response {} to `write`", response)));
        }
        let (code, message) = parse_status(&mut reader)?;
        if code != STATUS_OK {
            return Err(status_error_with_message(code, "write", &message));
        }
        Ok(())
    }

    /// Read up to `limit` bytes at an absolute offset. `None` means end of file.
    pub(crate) fn read_at(&mut self, handle: &[u8], offset: u64, limit: usize) -> Result<Option<Vec<u8>>> {
        let id = self.next_id();
        let mut request = Writer::new(MSG_READ);
        request.u32(id).string(handle).u64(offset).u32(limit as u32);
        let packet = self.roundtrip(id, &request.finish())?;
        let mut reader = Reader::new(&packet);
        let response = reader.byte()?;
        let _ = reader.u32()?;
        match response {
            MSG_DATA => Ok(Some(reader.string()?.to_vec())),
            MSG_STATUS => {
                let (code, message) = parse_status(&mut reader)?;
                if code == STATUS_EOF {
                    return Ok(None);
                }
                Err(status_error_with_message(code, "read", &message))
            }
            other => Err(protocol(format!("unexpected response {} to `read`", other))),
        }
    }

    /// Close one handle. A close failure is reported but never hides an earlier one.
    pub(crate) fn close_handle(&mut self, handle: &[u8]) -> Result<()> {
        let id = self.next_id();
        let mut request = Writer::new(MSG_CLOSE);
        request.u32(id).string(handle);
        let packet = self.roundtrip(id, &request.finish())?;
        let mut reader = Reader::new(&packet);
        let response = reader.byte()?;
        let _ = reader.u32()?;
        if response != MSG_STATUS {
            return Err(protocol(format!("unexpected response {} to `close`", response)));
        }
        let (code, message) = parse_status(&mut reader)?;
        if code != STATUS_OK {
            return Err(status_error_with_message(code, "close", &message));
        }
        Ok(())
    }

    /// List one remote directory.
    pub(crate) fn list(&mut self, path: &str) -> Result<Vec<RemoteEntry>> {
        let id = self.next_id();
        let mut request = Writer::new(MSG_OPENDIR);
        request.u32(id).string(path.as_bytes());
        let packet = self.roundtrip(id, &request.finish())?;
        let mut reader = Reader::new(&packet);
        let response = reader.byte()?;
        let _ = reader.u32()?;
        let handle = match response {
            MSG_HANDLE => reader.string()?.to_vec(),
            MSG_STATUS => {
                let (code, message) = parse_status(&mut reader)?;
                return Err(status_error_with_message(code, path, &message));
            }
            other => return Err(protocol(format!("unexpected response {} to `opendir`", other))),
        };

        let mut entries = Vec::new();
        loop {
            let id = self.next_id();
            let mut request = Writer::new(MSG_READDIR);
            request.u32(id).string(&handle);
            let packet = match self.roundtrip(id, &request.finish()) {
                Ok(packet) => packet,
                Err(error) => {
                    let _ = self.close_handle(&handle);
                    return Err(error);
                }
            };
            let mut reader = Reader::new(&packet);
            let response = reader.byte()?;
            let _ = reader.u32()?;
            match response {
                MSG_NAME => {
                    let count = reader.u32()?;
                    for _ in 0..count {
                        let name = String::from_utf8_lossy(reader.string()?).into_owned();
                        let _longname = reader.string()?;
                        let (size, is_dir) = parse_attrs(&mut reader)?;
                        if name == "." || name == ".." {
                            continue;
                        }
                        entries.push(RemoteEntry { name, size, is_dir });
                    }
                }
                MSG_STATUS => {
                    let (code, message) = parse_status(&mut reader)?;
                    if code == STATUS_EOF {
                        break;
                    }
                    let _ = self.close_handle(&handle);
                    return Err(status_error_with_message(code, path, &message));
                }
                other => {
                    let _ = self.close_handle(&handle);
                    return Err(protocol(format!("unexpected response {} to `readdir`", other)));
                }
            }
        }
        self.close_handle(&handle)?;
        Ok(entries)
    }

    /// Close the SFTP channel.
    pub(crate) fn finish(mut self) -> Result<()> {
        self.channel.close(self.transport)
    }

    fn next_id(&mut self) -> u32 {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        id
    }

    fn roundtrip(&mut self, id: u32, request: &[u8]) -> Result<Vec<u8>> {
        self.write_packet(request)?;
        loop {
            let packet = self.read_packet()?;
            if packet.len() < 5 {
                return Err(protocol("an SFTP response is shorter than its id"));
            }
            let response_id = u32::from_be_bytes([packet[1], packet[2], packet[3], packet[4]]);
            if response_id == id {
                return Ok(packet);
            }
        }
    }

    fn write_packet(&mut self, payload: &[u8]) -> Result<()> {
        let mut framed = Vec::with_capacity(payload.len() + 4);
        framed.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        framed.extend_from_slice(payload);
        self.channel.send(self.transport, &framed)
    }

    fn read_packet(&mut self) -> Result<Vec<u8>> {
        loop {
            if self.inbound.len() >= 4 {
                let length = u32::from_be_bytes([self.inbound[0], self.inbound[1], self.inbound[2], self.inbound[3]]) as usize;
                if length == 0 || length > 256 * 1024 {
                    return Err(protocol("the server sent an unacceptable SFTP packet length"));
                }
                if self.inbound.len() >= 4 + length {
                    let rest = self.inbound.split_off(4 + length);
                    let mut packet = std::mem::replace(&mut self.inbound, rest);
                    packet.drain(..4);
                    return Ok(packet);
                }
            }
            match self.channel.receive(self.transport)? {
                Some(data) => self.inbound.extend_from_slice(&data),
                None => return Err(Error::new(ErrorCode::ConnectionLost, "the server closed the SFTP channel")),
            }
        }
    }
}

const MSG_STATUS_ATTRS: u8 = 105;

fn parse_status(reader: &mut Reader<'_>) -> Result<(u32, String)> {
    let code = reader.u32()?;
    let message = String::from_utf8_lossy(reader.string()?).into_owned();
    Ok((code, message))
}

fn parse_attrs(reader: &mut Reader<'_>) -> Result<(u64, bool)> {
    let flags = reader.u32()?;
    let mut size = 0;
    if flags & FLAG_SIZE != 0 {
        size = reader.u64()?;
    }
    if flags & 2 != 0 {
        let _ = reader.u32()?;
        let _ = reader.u32()?;
    }
    let mut is_dir = false;
    if flags & 4 != 0 {
        let permissions = reader.u32()?;
        is_dir = permissions & 0o170_000 == 0o040_000;
    }
    if flags & 8 != 0 {
        let _ = reader.u32()?;
        let _ = reader.u32()?;
    }
    Ok((size, is_dir))
}

fn status_error(code: u32, path: &str) -> Error {
    status_error_with_message(code, path, "")
}

fn status_error_with_message(code: u32, path: &str, message: &str) -> Error {
    match code {
        STATUS_NO_SUCH_FILE => Error::new(ErrorCode::RemoteNotFound, format!("the remote path `{path}` does not exist")),
        STATUS_PERMISSION_DENIED => Error::new(ErrorCode::PermissionDenied, format!("the server refused access to `{path}`")),
        STATUS_CONNECTION_LOST => Error::new(ErrorCode::ConnectionLost, "the SFTP session was lost"),
        _ if is_disk_full(message) => Error::new(ErrorCode::DiskFull, format!("the remote file system is out of space: {message}")),
        _ if message.is_empty() => Error::new(ErrorCode::TransferFailed, format!("the server rejected `{path}` with SFTP status {code}")),
        _ => Error::new(ErrorCode::TransferFailed, format!("the server rejected `{path}`: {message}")),
    }
}

fn is_disk_full(message: &str) -> bool {
    let message = message.to_ascii_lowercase();
    message.contains("no space") || message.contains("disk full") || message.contains("not enough space")
}

fn protocol(message: impl Into<String>) -> Error {
    Error::new(ErrorCode::ProtocolError, message.into())
}
