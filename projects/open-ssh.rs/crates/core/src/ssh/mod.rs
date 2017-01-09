//! In-process SSH client providing the `exec` capability.
//!
//! Everything below the API surface is implemented in this crate: protocol
//! framing, negotiation, key exchange wiring, host key verification, user
//! authentication, and the session channel. Only cryptographic primitives
//! come from audited crates. No external `ssh`, `sftp`, or `scp` process is
//! ever started, and no library that owns the protocol is admitted.

mod auth;
mod channel;
mod identity;
mod kex;
mod transport;
mod wire;

use std::path::PathBuf;
use std::time::{Duration, Instant};

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::errors::{Error, ErrorCode};

type Result<T> = std::result::Result<T, Error>;

/// How the caller proves its identity for `exec`.
pub enum ExecAuth {
    /// Password authentication. The password is never written to audit.
    Password(String),
    /// Public key authentication with an OpenSSH ed25519 identity file.
    Identity(PathBuf),
}

impl ExecAuth {
    /// Name reported to the audit record.
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Password(_) => "password",
            Self::Identity(_) => "publickey",
        }
    }
}

impl std::fmt::Debug for ExecAuth {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Password(_) => formatter.write_str("ExecAuth::Password(<redacted>)"),
            Self::Identity(path) => formatter.debug_tuple("ExecAuth::Identity").field(path).finish(),
        }
    }
}

/// One `exec` call.
#[derive(Debug)]
pub struct ExecRequest {
    /// Transport adapter name. Only `ssh` carries a command channel.
    pub transport: String,
    /// Target host name or address.
    pub host: String,
    /// Target port.
    pub port: u16,
    /// Remote user name.
    pub user: String,
    /// The single command line to run.
    pub command: String,
    /// How to authenticate.
    pub auth: ExecAuth,
    /// Pinned `SHA256:` host key fingerprint.
    pub host_key_sha256: String,
    /// Deadline for connecting, authenticating, and running the command.
    pub timeout: Duration,
}

/// Result of one successful `exec` call.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecResult {
    /// Transport adapter that served the call.
    pub transport: &'static str,
    /// Truncated SHA-256 of the target host, safe for audit.
    pub host_hash: String,
    /// Target port.
    pub port: u16,
    /// Remote user name.
    pub user: String,
    /// Authentication method used.
    pub auth_method: &'static str,
    /// Remote exit status, when the server reported one.
    pub exit_code: Option<i32>,
    /// Captured standard output decoded as UTF-8 with replacement.
    pub stdout: String,
    /// Captured standard error decoded as UTF-8 with replacement.
    pub stderr: String,
    /// Exact captured stdout byte count.
    pub stdout_bytes: usize,
    /// Exact captured stderr byte count.
    pub stderr_bytes: usize,
    /// Wall-clock duration of the whole call.
    pub duration_ms: u64,
}

/// Run one command over the `ssh` transport.
pub fn execute(request: ExecRequest) -> Result<ExecResult> {
    validate(&request)?;
    let pin = normalize_pin(&request.host_key_sha256);
    let method = match &request.auth {
        ExecAuth::Password(password) => auth::AuthMethod::Password(password.clone()),
        ExecAuth::Identity(path) => {
            auth::AuthMethod::PublicKey(identity::Ed25519Identity::load(path)?)
        }
    };
    let started = Instant::now();

    let mut transport = transport::Transport::connect(&request.host, request.port, request.timeout)?;
    transport.exchange_versions()?;
    let handshake = kex::handshake(&mut transport)?;
    if pin != handshake.fingerprint {
        return Err(Error::new(
            ErrorCode::HostKeyMismatch,
            format!("the server host key is `{}` but the pinned fingerprint is `SHA256:{pin}`", handshake.fingerprint),
        ));
    }
    auth::authenticate(&mut transport, &request.user, &method)?;
    let outcome = channel::exec(&mut transport, &request.command)?;

    Ok(ExecResult {
        transport: "ssh",
        host_hash: host_hash(&request.host),
        port: request.port,
        user: request.user,
        auth_method: method.name(),
        exit_code: outcome.exit_status.map(|status| status as i32),
        stdout: String::from_utf8_lossy(&outcome.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&outcome.stderr).into_owned(),
        stdout_bytes: outcome.stdout.len(),
        stderr_bytes: outcome.stderr.len(),
        duration_ms: started.elapsed().as_millis() as u64,
    })
}

fn validate(request: &ExecRequest) -> Result<()> {
    match request.transport.as_str() {
        "ssh" => {}
        "rdp" => {
            return Err(Error::for_capability(
                ErrorCode::NotImplemented,
                crate::audit::capability_ids::EXEC,
                "RDP has no command channel. The protocol carries graphics, input, clipboard, and redirection channels only.",
            ));
        }
        other => {
            return Err(Error::new(ErrorCode::InvalidArgument, format!("unknown transport `{other}`")));
        }
    }
    if request.host.trim().is_empty() {
        return Err(Error::new(ErrorCode::InvalidArgument, "host must not be empty"));
    }
    if request.user.trim().is_empty() {
        return Err(Error::new(ErrorCode::InvalidArgument, "user must not be empty"));
    }
    if request.command.trim().is_empty() {
        return Err(Error::new(ErrorCode::InvalidArgument, "command must not be empty"));
    }
    if request.host_key_sha256.trim().is_empty() {
        return Err(Error::new(
            ErrorCode::HostKeyUnverified,
            "exec requires a pinned host key fingerprint, and this client never trusts an unknown key",
        ));
    }
    if request.timeout.is_zero() {
        return Err(Error::new(ErrorCode::InvalidArgument, "timeout must be greater than zero"));
    }
    Ok(())
}

/// Accept a pin with or without the `SHA256:` prefix.
fn normalize_pin(pin: &str) -> String {
    let trimmed = pin.trim();
    match trimmed.strip_prefix("SHA256:") {
        Some(rest) => rest.trim().to_string(),
        None => trimmed.to_string(),
    }
}

/// Truncated SHA-256 of the target host for audit records.
pub fn host_hash(host: &str) -> String {
    let digest = Sha256::digest(host.as_bytes());
    digest[..6].iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> ExecRequest {
        ExecRequest {
            transport: "ssh".to_string(),
            host: "example.invalid".to_string(),
            port: 22,
            user: "operator".to_string(),
            command: "uname -a".to_string(),
            auth: ExecAuth::Password("secret".to_string()),
            host_key_sha256: "SHA256:abc".to_string(),
            timeout: Duration::from_secs(1),
        }
    }

    #[test]
    fn rdp_is_refused_with_the_capability_code() {
        let mut request = request();
        request.transport = "rdp".to_string();
        let error = execute(request).expect_err("rdp has no command channel");
        assert_eq!(error.code(), ErrorCode::NotImplemented);
    }

    #[test]
    fn an_unknown_transport_is_an_argument_error() {
        let mut request = request();
        request.transport = "telnet".to_string();
        let error = execute(request).expect_err("unknown transport is refused");
        assert_eq!(error.code(), ErrorCode::InvalidArgument);
    }

    #[test]
    fn an_empty_host_key_pin_is_refused_before_connecting() {
        let mut request = request();
        request.host_key_sha256 = "   ".to_string();
        let error = execute(request).expect_err("an unpinned host key is refused");
        assert_eq!(error.code(), ErrorCode::HostKeyUnverified);
    }

    #[test]
    fn pins_accept_the_openssh_prefix() {
        assert_eq!(normalize_pin("SHA256:abc"), normalize_pin(" abc "));
    }

    #[test]
    fn host_hashes_are_short_and_stable() {
        let hash = host_hash("example.invalid");
        assert_eq!(hash.len(), 12);
        assert_eq!(hash, host_hash("example.invalid"));
    }
}
