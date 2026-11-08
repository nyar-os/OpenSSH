//! Connection probe backing the `connect` capability.
//!
//! A probe opens the transport, verifies the pinned host key, authenticates, and
//! closes the connection with a protocol-level disconnect. It proves the target,
//! the credentials, and the negotiated algorithm set without running a command
//! or opening a channel.

use std::time::{Duration, Instant};

use serde::Serialize;

use crate::errors::{Error, ErrorCode};

use super::{
    ExecAuth, Result,
    kex::{CIPHER, HOST_KEY_ALGORITHM, KEX_ALGORITHM, MAC},
    transport::Transport,
    wire::Writer,
};

use super::{connect_and_authenticate, host_hash};

/// Reason code meaning the client finished on its own.
const DISCONNECT_BY_APPLICATION: u32 = 11;

/// One `connect` call.
#[derive(Debug)]
pub struct ConnectRequest {
    /// Transport adapter name. Only `ssh` is implemented.
    pub transport: String,
    /// Target host name or address.
    pub host: String,
    /// Target port.
    pub port: u16,
    /// Remote user name.
    pub user: String,
    /// How to authenticate.
    pub auth: ExecAuth,
    /// Pinned `SHA256:` host key fingerprint.
    pub host_key_sha256: String,
    /// Deadline for connecting, authenticating, and disconnecting.
    pub timeout: Duration,
}

/// Result of one successful `connect` call.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectResult {
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
    /// Server identification string without the trailing CRLF.
    pub server_version: String,
    /// Verified `SHA256:` host key fingerprint.
    pub host_key_sha256: String,
    /// Key exchange algorithm this client admitted.
    pub kex_algorithm: &'static str,
    /// Host key algorithm this client admitted.
    pub host_key_algorithm: &'static str,
    /// Cipher this client admitted in both directions.
    pub cipher: &'static str,
    /// MAC identifier on the session.
    pub mac: &'static str,
    /// Wall-clock duration of the whole call.
    pub duration_ms: u64,
}

/// What one `connect` call would do, resolved without opening a connection.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectPreview {
    /// Transport adapter that would serve the call.
    pub transport: &'static str,
    /// Truncated SHA-256 of the target host, safe for audit.
    pub host_hash: String,
    /// Target port.
    pub port: u16,
    /// Remote user name.
    pub user: String,
    /// Authentication method that would be used.
    pub auth_method: &'static str,
    /// Pinned fingerprint in `SHA256:` notation.
    pub host_key_sha256: String,
    /// Deadline in milliseconds.
    pub timeout_ms: u64,
}

/// Resolve a `connect` request without connecting.
pub fn preview(request: &ConnectRequest) -> Result<ConnectPreview> {
    validate(request)?;
    Ok(ConnectPreview {
        transport: "ssh",
        host_hash: host_hash(&request.host),
        port: request.port,
        user: request.user.clone(),
        auth_method: request.auth.name(),
        host_key_sha256: format!("SHA256:{}", normalize_pin(&request.host_key_sha256)),
        timeout_ms: request.timeout.as_millis() as u64,
    })
}

/// Connect, verify the pinned host key, authenticate, then disconnect.
pub fn execute(request: ConnectRequest) -> Result<ConnectResult> {
    validate(&request)?;
    let started = Instant::now();
    let (mut transport, auth_method) =
        connect_and_authenticate(&request.host, request.port, &request.user, &request.auth, &request.host_key_sha256, request.timeout)?;
    let server_version = transport.server_version().to_string();
    disconnect(&mut transport)?;

    Ok(ConnectResult {
        transport: "ssh",
        host_hash: host_hash(&request.host),
        port: request.port,
        user: request.user,
        auth_method,
        server_version,
        host_key_sha256: format!("SHA256:{}", normalize_pin(&request.host_key_sha256)),
        kex_algorithm: KEX_ALGORITHM,
        host_key_algorithm: HOST_KEY_ALGORITHM,
        cipher: CIPHER,
        mac: MAC,
        duration_ms: started.elapsed().as_millis() as u64,
    })
}

/// Close the session with a protocol-level disconnect instead of a bare FIN.
fn disconnect(transport: &mut Transport) -> Result<()> {
    let mut writer = Writer::new(1);
    writer.u32(DISCONNECT_BY_APPLICATION).string(b"open-ssh connect probe complete").string(b"");
    transport.send(&writer.finish())
}

fn validate(request: &ConnectRequest) -> Result<()> {
    match request.transport.as_str() {
        "ssh" => {}
        "rdp" => {
            return Err(Error::for_capability(
                ErrorCode::NotImplemented,
                crate::audit::capability_ids::CONNECT,
                "RDP negotiation is not implemented in this round, so no RDP connection can be established.",
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
    if request.host_key_sha256.trim().is_empty() {
        return Err(Error::new(
            ErrorCode::HostKeyUnverified,
            "connect requires a pinned host key fingerprint, and this client never trusts an unknown key",
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

#[cfg(test)]
mod tests {
    use super::{super::fixture, *};

    fn request() -> ConnectRequest {
        ConnectRequest {
            transport: "ssh".to_string(),
            host: "example.invalid".to_string(),
            port: 22,
            user: "operator".to_string(),
            auth: ExecAuth::Password("secret".to_string()),
            host_key_sha256: "SHA256:abc".to_string(),
            timeout: Duration::from_secs(1),
        }
    }

    fn loopback_request(fixture: &fixture::Fixture) -> ConnectRequest {
        ConnectRequest {
            transport: "ssh".to_string(),
            host: fixture.addr.ip().to_string(),
            port: fixture.addr.port(),
            user: "operator".to_string(),
            auth: ExecAuth::Password("secret".to_string()),
            host_key_sha256: fixture.pin.clone(),
            timeout: Duration::from_secs(10),
        }
    }

    #[test]
    fn rdp_is_refused_with_the_capability_code() {
        let mut request = request();
        request.transport = "rdp".to_string();
        let error = execute(request).expect_err("rdp negotiation is not implemented");
        assert_eq!(error.code(), ErrorCode::NotImplemented);
        assert_eq!(error.capability(), Some(crate::audit::capability_ids::CONNECT));
    }

    #[test]
    fn an_unknown_transport_is_an_argument_error() {
        let mut request = request();
        request.transport = "telnet".to_string();
        assert_eq!(execute(request).expect_err("unknown transport").code(), ErrorCode::InvalidArgument);
    }

    #[test]
    fn an_empty_pin_is_refused_before_connecting() {
        let mut request = request();
        request.host_key_sha256 = "  ".to_string();
        assert_eq!(execute(request).expect_err("an unpinned host key is refused").code(), ErrorCode::HostKeyUnverified);
    }

    #[test]
    fn preview_resolves_without_connecting() {
        let preview = preview(&request()).expect("preview");
        assert_eq!(preview.transport, "ssh");
        assert_eq!(preview.port, 22);
        assert_eq!(preview.user, "operator");
        assert_eq!(preview.auth_method, "password");
        assert_eq!(preview.host_key_sha256, "SHA256:abc");
        assert_eq!(preview.timeout_ms, 1000);
        assert_eq!(preview.host_hash, host_hash("example.invalid"));
    }

    #[test]
    fn a_probe_authenticates_and_disconnects_over_loopback() {
        let fixture =
            fixture::Fixture::start_with(fixture::FixtureOptions { mode: fixture::FixtureMode::Probe, ..fixture::FixtureOptions::default() });
        let result = execute(loopback_request(&fixture)).expect("loopback probe");
        assert_eq!(result.transport, "ssh");
        assert_eq!(result.auth_method, "password");
        assert_eq!(result.server_version, "SSH-2.0-WAE_Fixture_0.0.0");
        assert_eq!(result.host_key_sha256, fixture.pin);
        assert_eq!(result.kex_algorithm, "curve25519-sha256");
        assert_eq!(result.host_key_algorithm, "ssh-ed25519");
        assert_eq!(result.cipher, "aes256-gcm@openssh.com");
        assert_eq!(result.mac, "hmac-sha2-256");
        assert_eq!(result.host_hash, host_hash(&fixture.addr.ip().to_string()));
        fixture.wait();
    }

    #[test]
    fn a_wrong_password_reports_auth_failed() {
        let fixture =
            fixture::Fixture::start_with(fixture::FixtureOptions { mode: fixture::FixtureMode::Probe, ..fixture::FixtureOptions::default() });
        let mut request = loopback_request(&fixture);
        request.auth = ExecAuth::Password("wrong".to_string());
        assert_eq!(execute(request).expect_err("wrong password").code(), ErrorCode::AuthFailed);
        fixture.wait();
    }

    #[test]
    fn a_mismatched_pin_reports_host_key_mismatch() {
        let fixture =
            fixture::Fixture::start_with(fixture::FixtureOptions { mode: fixture::FixtureMode::Probe, ..fixture::FixtureOptions::default() });
        let mut request = loopback_request(&fixture);
        request.host_key_sha256 = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string();
        assert_eq!(execute(request).expect_err("mismatched pin").code(), ErrorCode::HostKeyMismatch);
        fixture.wait();
    }

    #[test]
    fn a_closed_port_reports_connect_failed() {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind");
        let address = listener.local_addr().expect("address");
        drop(listener);
        let mut request = request();
        request.host = address.ip().to_string();
        request.port = address.port();
        request.timeout = Duration::from_secs(5);
        assert_eq!(execute(request).expect_err("closed port").code(), ErrorCode::ConnectFailed);
    }
}
