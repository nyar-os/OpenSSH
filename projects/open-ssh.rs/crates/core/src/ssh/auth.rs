//! User authentication for the `password` and `publickey` methods.

use crate::errors::{Error, ErrorCode};

use super::identity::{Ed25519Identity, ALGORITHM};
use super::wire::{Reader, Writer};
use super::transport::Transport;
use super::Result;

const MSG_DISCONNECT: u8 = 1;
const MSG_IGNORE: u8 = 2;
const MSG_DEBUG: u8 = 4;
const MSG_SERVICE_REQUEST: u8 = 5;
const MSG_SERVICE_ACCEPT: u8 = 6;
const MSG_USERAUTH_REQUEST: u8 = 50;
const MSG_USERAUTH_FAILURE: u8 = 51;
const MSG_USERAUTH_SUCCESS: u8 = 52;
const MSG_USERAUTH_BANNER: u8 = 53;
const MSG_USERAUTH_METHOD_SPECIFIC: u8 = 60;

const SERVICE: &str = "ssh-userauth";

/// How the client proves its identity.
pub enum AuthMethod {
    /// Password authentication.
    Password(String),
    /// Public key authentication with an ed25519 identity.
    PublicKey(Ed25519Identity),
}

impl AuthMethod {
    /// Name reported to the audit record.
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Password(_) => "password",
            Self::PublicKey(_) => "publickey",
        }
    }
}

/// Request the userauth service and authenticate once.
pub fn authenticate(transport: &mut Transport, user: &str, method: &AuthMethod) -> Result<()> {
    let mut request = Writer::new(MSG_SERVICE_REQUEST);
    request.string(SERVICE.as_bytes());
    transport.send(&request.finish())?;
    loop {
        let payload = transport.receive()?;
        match payload[0] {
            MSG_SERVICE_ACCEPT => break,
            MSG_IGNORE | MSG_DEBUG => continue,
            MSG_DISCONNECT => return Err(disconnect(&payload)),
            other => return Err(unexpected(other, "SERVICE_ACCEPT")),
        }
    }

    match method {
        AuthMethod::Password(password) => {
            let mut request = Writer::new(MSG_USERAUTH_REQUEST);
            request.string(user.as_bytes()).string(SERVICE.as_bytes()).string(b"password").boolean(false);
            request.string(password.as_bytes());
            transport.send(&request.finish())?;
        }
        AuthMethod::PublicKey(identity) => {
            let mut request = Writer::new(MSG_USERAUTH_REQUEST);
            request
                .string(user.as_bytes())
                .string(SERVICE.as_bytes())
                .string(b"publickey")
                .boolean(true)
                .string(ALGORITHM.as_bytes())
                .string(&identity.public_blob());
            let prefix = request.finish();
            let mut signed = Writer::empty();
            signed.string(transport.session_id()).raw(&prefix);
            let signature = identity.signature_blob(&signed.finish());
            let mut signature_field = Writer::empty();
            signature_field.string(&signature);
            let mut message = prefix;
            message.extend_from_slice(&signature_field.finish());
            transport.send(&message)?;
        }
    }

    loop {
        let payload = transport.receive()?;
        match payload[0] {
            MSG_USERAUTH_SUCCESS => return Ok(()),
            MSG_USERAUTH_FAILURE => return Err(auth_failure(&payload)),
            MSG_USERAUTH_BANNER => continue,
            MSG_USERAUTH_METHOD_SPECIFIC => {
                return Err(Error::new(
                    ErrorCode::AuthFailed,
                    "the server requires a password change or another method-specific step, which this client does not support",
                ));
            }
            MSG_IGNORE | MSG_DEBUG => continue,
            MSG_DISCONNECT => return Err(disconnect(&payload)),
            other => return Err(unexpected(other, "USERAUTH_SUCCESS or USERAUTH_FAILURE")),
        }
    }
}

fn auth_failure(payload: &[u8]) -> Error {
    let mut reader = Reader::new(payload);
    let _ = reader.byte();
    let methods = reader.name_list().map(|names| names.join(",")).unwrap_or_default();
    let partial = reader.boolean().unwrap_or(false);
    let suffix = if partial { " after partial success" } else { "" };
    Error::new(ErrorCode::AuthFailed, format!("the server rejected the credentials{suffix}, and it accepts: {methods}"))
}

fn disconnect(payload: &[u8]) -> Error {
    let mut reader = Reader::new(payload);
    let _ = reader.byte();
    let reason = reader.u32().unwrap_or(0);
    let description = reader.string().map(|bytes| String::from_utf8_lossy(bytes).into_owned()).unwrap_or_default();
    Error::new(ErrorCode::ProtocolError, format!("the server disconnected during authentication (reason {reason}): {description}"))
}

fn unexpected(message: u8, expected: &str) -> Error {
    Error::new(ErrorCode::ProtocolError, format!("expected `{expected}` but the server sent SSH message {message}"))
}
