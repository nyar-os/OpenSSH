//! Session channel setup and one `exec` request.

use crate::errors::{Error, ErrorCode};

use super::wire::{Reader, Writer};
use super::transport::Transport;
use super::Result;

const MSG_DISCONNECT: u8 = 1;
const MSG_IGNORE: u8 = 2;
const MSG_UNIMPLEMENTED: u8 = 3;
const MSG_DEBUG: u8 = 4;
const MSG_GLOBAL_REQUEST: u8 = 80;
const MSG_REQUEST_SUCCESS: u8 = 81;
const MSG_REQUEST_FAILURE: u8 = 82;
const MSG_CHANNEL_OPEN: u8 = 90;
const MSG_CHANNEL_OPEN_CONFIRMATION: u8 = 91;
const MSG_CHANNEL_OPEN_FAILURE: u8 = 92;
const MSG_CHANNEL_WINDOW_ADJUST: u8 = 93;
const MSG_CHANNEL_DATA: u8 = 94;
const MSG_CHANNEL_EXTENDED_DATA: u8 = 95;
const MSG_CHANNEL_EOF: u8 = 96;
const MSG_CHANNEL_CLOSE: u8 = 97;
const MSG_CHANNEL_REQUEST: u8 = 98;
const MSG_CHANNEL_SUCCESS: u8 = 99;
const MSG_CHANNEL_FAILURE: u8 = 100;

/// Initial receive window offered to the server.
const WINDOW_SIZE: u32 = 2 * 1024 * 1024;
/// Largest payload the server may send in one channel packet.
const MAX_PACKET_SIZE: u32 = 32 * 1024;
/// Upper bound for captured stdout or stderr, so a runaway command cannot
/// exhaust memory.
const MAX_CAPTURE: usize = 8 * 1024 * 1024;

/// Result of one executed command.
pub struct ExecOutcome {
    /// Captured standard output.
    pub stdout: Vec<u8>,
    /// Captured standard error.
    pub stderr: Vec<u8>,
    /// Status reported by the server, when it sent one.
    pub exit_status: Option<u32>,
}

/// Open a session channel, run one command, and collect its output.
pub fn exec(transport: &mut Transport, command: &str) -> Result<ExecOutcome> {
    let local_channel = 0u32;
    let mut open = Writer::new(MSG_CHANNEL_OPEN);
    open.string(b"session").u32(local_channel).u32(WINDOW_SIZE).u32(MAX_PACKET_SIZE);
    transport.send(&open.finish())?;

    let remote_channel = loop {
        let payload = transport.receive()?;
        match payload[0] {
            MSG_CHANNEL_OPEN_CONFIRMATION => {
                let mut reader = Reader::new(&payload);
                let _ = reader.byte()?;
                let recipient = reader.u32()?;
                if recipient != local_channel {
                    return Err(Error::new(ErrorCode::ProtocolError, "server confirmed an unknown channel"));
                }
                break reader.u32()?;
            }
            MSG_CHANNEL_OPEN_FAILURE => {
                let mut reader = Reader::new(&payload);
                let _ = reader.byte()?;
                let _recipient = reader.u32()?;
                let reason = reader.u32()?;
                let description = reader.string().map(|bytes| String::from_utf8_lossy(bytes).into_owned()).unwrap_or_default();
                return Err(Error::new(
                    ErrorCode::ExecFailed,
                    format!("the server refused to open a session channel (reason {reason}): {description}"),
                ));
            }
            MSG_GLOBAL_REQUEST => reply_global_failure(transport, &payload)?,
            MSG_IGNORE | MSG_DEBUG | MSG_REQUEST_SUCCESS | MSG_REQUEST_FAILURE => continue,
            MSG_DISCONNECT => return Err(disconnect(&payload)),
            other => return Err(unexpected(other, "CHANNEL_OPEN_CONFIRMATION")),
        }
    };

    let mut request = Writer::new(MSG_CHANNEL_REQUEST);
    request.u32(remote_channel).string(b"exec").boolean(true).string(command.as_bytes());
    transport.send(&request.finish())?;

    let mut outcome = ExecOutcome { stdout: Vec::new(), stderr: Vec::new(), exit_status: None };
    let mut accepted = false;
    loop {
        let payload = transport.receive()?;
        match payload[0] {
            MSG_CHANNEL_SUCCESS => {
                let mut reader = Reader::new(&payload);
                let _ = reader.byte()?;
                let _ = reader.u32()?;
                accepted = true;
            }
            MSG_CHANNEL_FAILURE => {
                return Err(Error::new(ErrorCode::ExecFailed, "the server refused the exec request"));
            }
            MSG_CHANNEL_DATA => {
                let mut reader = Reader::new(&payload);
                let _ = reader.byte()?;
                let _ = reader.u32()?;
                let data = reader.string()?;
                push(&mut outcome.stdout, data)?;
                adjust_window(transport, remote_channel, data.len())?;
            }
            MSG_CHANNEL_EXTENDED_DATA => {
                let mut reader = Reader::new(&payload);
                let _ = reader.byte()?;
                let _ = reader.u32()?;
                let data_type = reader.u32()?;
                let data = reader.string()?;
                if data_type == 1 {
                    push(&mut outcome.stderr, data)?;
                }
                adjust_window(transport, remote_channel, data.len())?;
            }
            MSG_CHANNEL_EOF => {}
            MSG_CHANNEL_CLOSE => {
                let mut close = Writer::new(MSG_CHANNEL_CLOSE);
                close.u32(remote_channel);
                transport.send(&close.finish())?;
                break;
            }
            MSG_CHANNEL_REQUEST => {
                let (status, want_reply) = parse_channel_request(&payload)?;
                if let Some(status) = status {
                    outcome.exit_status = Some(status);
                }
                if want_reply {
                    let mut reply = Writer::new(MSG_CHANNEL_SUCCESS);
                    reply.u32(remote_channel);
                    transport.send(&reply.finish())?;
                }
            }
            MSG_CHANNEL_WINDOW_ADJUST => {}
            MSG_GLOBAL_REQUEST => reply_global_failure(transport, &payload)?,
            MSG_IGNORE | MSG_DEBUG | MSG_REQUEST_SUCCESS | MSG_REQUEST_FAILURE => {}
            MSG_DISCONNECT => return Err(disconnect(&payload)),
            other => {
                let mut reply = Writer::new(MSG_UNIMPLEMENTED);
                reply.u32(0);
                transport.send(&reply.finish())?;
                return Err(unexpected(other, "a session channel message"));
            }
        }
    }

    if !accepted {
        return Err(Error::new(ErrorCode::ExecFailed, "the server closed the channel before accepting the exec request"));
    }
    Ok(outcome)
}

fn push(target: &mut Vec<u8>, data: &[u8]) -> Result<()> {
    if target.len() + data.len() > MAX_CAPTURE {
        return Err(Error::new(
            ErrorCode::ExecFailed,
            format!("command output exceeded the {MAX_CAPTURE} byte capture limit"),
        ));
    }
    target.extend_from_slice(data);
    Ok(())
}

fn adjust_window(transport: &mut Transport, remote_channel: u32, consumed: usize) -> Result<()> {
    let mut adjust = Writer::new(MSG_CHANNEL_WINDOW_ADJUST);
    adjust.u32(remote_channel).u32(consumed as u32);
    transport.send(&adjust.finish())
}

fn parse_channel_request(payload: &[u8]) -> Result<(Option<u32>, bool)> {
    let mut reader = Reader::new(payload);
    let _ = reader.byte()?;
    let _recipient = reader.u32()?;
    let request = reader.string()?;
    let want_reply = reader.boolean()?;
    if request == b"exit-status" {
        return Ok((Some(reader.u32()?), want_reply));
    }
    Ok((None, want_reply))
}

fn reply_global_failure(transport: &mut Transport, payload: &[u8]) -> Result<()> {
    let mut reader = Reader::new(payload);
    let _ = reader.byte()?;
    let _request = reader.string()?;
    let want_reply = reader.boolean()?;
    if want_reply {
        transport.send(&Writer::new(MSG_REQUEST_FAILURE).finish())?;
    }
    Ok(())
}

fn disconnect(payload: &[u8]) -> Error {
    let mut reader = Reader::new(payload);
    let _ = reader.byte();
    let reason = reader.u32().unwrap_or(0);
    let description = reader.string().map(|bytes| String::from_utf8_lossy(bytes).into_owned()).unwrap_or_default();
    Error::new(ErrorCode::ExecFailed, format!("the server disconnected during exec (reason {reason}): {description}"))
}

fn unexpected(message: u8, expected: &str) -> Error {
    Error::new(ErrorCode::ProtocolError, format!("expected `{expected}` but the server sent SSH message {message}"))
}
