//! In-process SSH client providing the `exec` capability.
//!
//! Everything below the API surface is implemented in this crate: protocol
//! framing, negotiation, key exchange wiring, host key verification, user
//! authentication, and the session channel. Only cryptographic primitives
//! come from audited crates. No external `ssh`, `sftp`, or `scp` process is
//! ever started, and no library that owns the protocol is admitted.

mod auth;
mod channel;
#[cfg(test)]
mod fixture;
mod identity;
mod kex;
mod sftp;
mod transfer;
mod transport;
mod wire;

pub use transfer::{
    Progress, TransferDirection, TransferEntry, TransferPreview, TransferRequest, TransferResult, execute as transfer,
    execute_with as transfer_with, normalize_local_path, normalize_remote_path, preview as transfer_preview,
};

use std::{
    path::PathBuf,
    time::{Duration, Instant},
};

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

/// What one `exec` call would do, resolved without opening a connection.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecPreview {
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
    /// Byte length of the command that would be sent.
    pub command_bytes: usize,
    /// Pinned fingerprint in `SHA256:` notation.
    pub host_key_sha256: String,
    /// Deadline in milliseconds.
    pub timeout_ms: u64,
}

/// Resolve an `exec` request without connecting.
pub fn preview(request: &ExecRequest) -> Result<ExecPreview> {
    validate(request)?;
    Ok(ExecPreview {
        transport: "ssh",
        host_hash: host_hash(&request.host),
        port: request.port,
        user: request.user.clone(),
        auth_method: request.auth.name(),
        command_bytes: request.command.len(),
        host_key_sha256: format!("SHA256:{}", normalize_pin(&request.host_key_sha256)),
        timeout_ms: request.timeout.as_millis() as u64,
    })
}

/// Run one command over the `ssh` transport.
pub fn execute(request: ExecRequest) -> Result<ExecResult> {
    validate(&request)?;
    let started = Instant::now();
    let (mut transport, auth_method) =
        connect_and_authenticate(&request.host, request.port, &request.user, &request.auth, &request.host_key_sha256, request.timeout)?;
    let outcome = channel::exec(&mut transport, &request.command)?;

    Ok(ExecResult {
        transport: "ssh",
        host_hash: host_hash(&request.host),
        port: request.port,
        user: request.user,
        auth_method,
        exit_code: outcome.exit_status.map(|status| status as i32),
        stdout: String::from_utf8_lossy(&outcome.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&outcome.stderr).into_owned(),
        stdout_bytes: outcome.stdout.len(),
        stderr_bytes: outcome.stderr.len(),
        duration_ms: started.elapsed().as_millis() as u64,
    })
}

/// Connect, verify the pinned host key, and authenticate. Shared by `exec` and
/// `transfer` so both capabilities use one connection and authentication path.
fn connect_and_authenticate(
    host: &str,
    port: u16,
    user: &str,
    auth: &ExecAuth,
    host_key_sha256: &str,
    timeout: Duration,
) -> Result<(transport::Transport, &'static str)> {
    let pin = normalize_pin(host_key_sha256);
    let method = match auth {
        ExecAuth::Password(password) => auth::AuthMethod::Password(password.clone()),
        ExecAuth::Identity(path) => auth::AuthMethod::PublicKey(identity::Ed25519Identity::load(path)?),
    };
    let name = method.name();

    let mut transport = transport::Transport::connect(host, port, timeout)?;
    transport.exchange_versions()?;
    let handshake = kex::handshake(&mut transport)?;
    if handshake.fingerprint != format!("SHA256:{pin}") {
        return Err(Error::new(
            ErrorCode::HostKeyMismatch,
            format!("the server host key is `{}` but the pinned fingerprint is `SHA256:{pin}`", handshake.fingerprint),
        ));
    }
    auth::authenticate(&mut transport, user, &method)?;
    Ok((transport, name))
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
    fn preview_resolves_without_connecting() {
        let preview = preview(&request()).expect("preview");
        assert_eq!(preview.transport, "ssh");
        assert_eq!(preview.port, 22);
        assert_eq!(preview.user, "operator");
        assert_eq!(preview.auth_method, "password");
        assert_eq!(preview.host_key_sha256, "SHA256:abc");
        assert_eq!(preview.command_bytes, "uname -a".len());
        assert_eq!(preview.timeout_ms, 1000);
    }

    #[test]
    fn host_hashes_are_short_and_stable() {
        let hash = host_hash("example.invalid");
        assert_eq!(hash.len(), 12);
        assert_eq!(hash, host_hash("example.invalid"));
    }

    fn loopback_request(fixture: &fixture::Fixture, auth: ExecAuth) -> ExecRequest {
        ExecRequest {
            transport: "ssh".to_string(),
            host: fixture.addr.ip().to_string(),
            port: fixture.addr.port(),
            user: "operator".to_string(),
            command: "uname -a".to_string(),
            auth,
            host_key_sha256: fixture.pin.clone(),
            timeout: Duration::from_secs(10),
        }
    }

    #[test]
    fn exec_over_loopback_returns_output_and_the_remote_exit_status() {
        let fixture = fixture::Fixture::start(fixture::FixtureAuth::Password("secret"), ed25519_dalek::SigningKey::from_bytes(&[3u8; 32]));
        let result = execute(loopback_request(&fixture, ExecAuth::Password("secret".to_string()))).expect("loopback exec");
        assert_eq!(result.stdout, fixture.stdout);
        assert_eq!(result.stderr, fixture.stderr);
        assert_eq!(result.exit_code, Some(fixture.exit_status as i32));
        assert_eq!(result.stdout_bytes, fixture.stdout.len());
        assert_eq!(result.stderr_bytes, fixture.stderr.len());
        assert_eq!(result.auth_method, "password");
        assert_eq!(result.transport, "ssh");
        assert_eq!(result.host_hash, host_hash(&fixture.addr.ip().to_string()));
        fixture.wait();
    }

    #[test]
    fn exec_over_loopback_accepts_an_openssh_identity_file() {
        let key = ed25519_dalek::SigningKey::from_bytes(&[5u8; 32]);
        let fixture = fixture::Fixture::start(fixture::FixtureAuth::PublicKey, key.clone());
        let path = std::env::temp_dir().join(format!("wae-open-ssh-id-{}.key", std::process::id()));
        std::fs::write(&path, identity::document(&key, b"none", b"none", "loopback")).expect("write identity");
        let result = execute(loopback_request(&fixture, ExecAuth::Identity(path.clone()))).expect("loopback exec");
        assert_eq!(result.auth_method, "publickey");
        assert_eq!(result.exit_code, Some(fixture.exit_status as i32));
        assert_eq!(result.stdout, fixture.stdout);
        let _ = std::fs::remove_file(&path);
        fixture.wait();
    }

    #[test]
    fn a_mismatched_pin_fails_with_host_key_mismatch() {
        let fixture = fixture::Fixture::start(fixture::FixtureAuth::Password("secret"), ed25519_dalek::SigningKey::from_bytes(&[3u8; 32]));
        let mut request = loopback_request(&fixture, ExecAuth::Password("secret".to_string()));
        request.host_key_sha256 = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string();
        let error = execute(request).expect_err("a wrong pin must fail");
        assert_eq!(error.code(), ErrorCode::HostKeyMismatch);
        assert!(error.message().contains("SHA256:"));
        fixture.wait();
    }

    #[test]
    fn a_wrong_password_fails_with_auth_failed() {
        let fixture = fixture::Fixture::start(fixture::FixtureAuth::Password("secret"), ed25519_dalek::SigningKey::from_bytes(&[3u8; 32]));
        let error = execute(loopback_request(&fixture, ExecAuth::Password("wrong".to_string()))).expect_err("wrong password must fail");
        assert_eq!(error.code(), ErrorCode::AuthFailed);
        fixture.wait();
    }

    #[test]
    fn a_closed_port_fails_with_connect_failed() {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind");
        let address = listener.local_addr().expect("address");
        drop(listener);
        let request = ExecRequest {
            transport: "ssh".to_string(),
            host: address.ip().to_string(),
            port: address.port(),
            user: "operator".to_string(),
            command: "true".to_string(),
            auth: ExecAuth::Password("secret".to_string()),
            host_key_sha256: "SHA256:abc".to_string(),
            timeout: Duration::from_secs(5),
        };
        let error = execute(request).expect_err("a closed port must fail");
        assert_eq!(error.code(), ErrorCode::ConnectFailed);
    }

    fn sftp_fixture(options: fixture::FixtureOptions) -> fixture::Fixture {
        fixture::Fixture::start_with(fixture::FixtureOptions { mode: fixture::FixtureMode::Sftp, ..options })
    }

    fn temp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("wae-open-ssh-{}-{name}", std::process::id()))
    }

    fn transfer_request(fixture: &fixture::Fixture, direction: TransferDirection, local: Option<PathBuf>, remote: &str) -> TransferRequest {
        TransferRequest {
            transport: "ssh".to_string(),
            host: fixture.addr.ip().to_string(),
            port: fixture.addr.port(),
            user: "operator".to_string(),
            auth: ExecAuth::Password("secret".to_string()),
            host_key_sha256: fixture.pin.clone(),
            timeout: Duration::from_secs(10),
            direction,
            local_path: local,
            remote_path: remote.to_string(),
            resume: false,
        }
    }

    #[test]
    fn upload_writes_the_local_file_to_the_remote_path() {
        let fixture = sftp_fixture(fixture::FixtureOptions::default());
        let local = temp_path("upload.bin");
        let contents: Vec<u8> = (0..40_000u32).map(|index| (index % 251) as u8).collect();
        std::fs::write(&local, &contents).expect("write the local file");

        let mut progress = Vec::new();
        let result =
            transfer_with(transfer_request(&fixture, TransferDirection::Upload, Some(local.clone()), "/incoming/data.bin"), |update| {
                progress.push(update);
            })
            .expect("upload");

        assert_eq!(result.direction, "upload");
        assert_eq!(result.remote_path, "/incoming/data.bin");
        assert_eq!(result.bytes, contents.len() as u64);
        assert_eq!(result.resumed_from, 0);
        assert_eq!(result.auth_method, "password");
        assert!(progress.len() >= 2, "progress must be reported while bytes move");
        assert_eq!(progress.last().expect("last progress").transferred, contents.len() as u64);
        assert_eq!(fixture.file("/incoming/data.bin").as_deref(), Some(contents.as_slice()));
        let _ = std::fs::remove_file(&local);
        fixture.wait();
    }

    #[test]
    fn download_writes_the_remote_file_to_the_named_local_path() {
        let contents: Vec<u8> = (0..33_000u32).map(|index| (index % 241) as u8).collect();
        let fixture = sftp_fixture(fixture::FixtureOptions { files: vec![("/outgoing/report.bin", contents.clone())], ..Default::default() });
        let local = temp_path("download.bin");

        let result =
            transfer(transfer_request(&fixture, TransferDirection::Download, Some(local.clone()), "/outgoing/report.bin")).expect("download");

        assert_eq!(result.direction, "download");
        assert_eq!(result.bytes, contents.len() as u64);
        assert_eq!(result.resumed_from, 0);
        assert_eq!(std::fs::read(&local).expect("read the local file"), contents);
        let _ = std::fs::remove_file(&local);
        fixture.wait();
    }

    #[test]
    fn list_returns_sorted_directory_entries() {
        let fixture = sftp_fixture(fixture::FixtureOptions {
            files: vec![("/var/log/app.log", b"hello".to_vec()), ("/var/log/notes.txt", b"x".to_vec())],
            directories: vec!["/var/log/archive"],
            ..Default::default()
        });

        let result = transfer(transfer_request(&fixture, TransferDirection::List, None, "/var/log")).expect("list");

        let names: Vec<&str> = result.entries.iter().map(|entry| entry.name.as_str()).collect();
        assert_eq!(names, ["app.log", "archive", "notes.txt"]);
        assert_eq!(result.entries[0].size, 5);
        assert!(!result.entries[0].is_dir);
        assert!(result.entries[1].is_dir);
        assert_eq!(result.bytes, 0);
        assert_eq!(result.remote_path, "/var/log");
        fixture.wait();
    }

    #[test]
    fn paths_that_escape_or_are_empty_are_refused_before_connecting() {
        let request = || TransferRequest {
            transport: "ssh".to_string(),
            host: "127.0.0.1".to_string(),
            port: 1,
            user: "operator".to_string(),
            auth: ExecAuth::Password("secret".to_string()),
            host_key_sha256: "SHA256:abc".to_string(),
            timeout: Duration::from_secs(1),
            direction: TransferDirection::Upload,
            local_path: Some(PathBuf::from("payload.txt")),
            remote_path: "/safe/payload.txt".to_string(),
            resume: false,
        };

        let mut escaping_remote = request();
        escaping_remote.remote_path = "../../etc/passwd".to_string();
        assert_eq!(transfer(escaping_remote).expect_err("an escaping remote path is refused").code(), ErrorCode::PathRejected);

        let mut empty_remote = request();
        empty_remote.remote_path = "   ".to_string();
        assert_eq!(transfer(empty_remote).expect_err("an empty remote path is refused").code(), ErrorCode::PathRejected);

        let mut escaping_local = request();
        escaping_local.local_path = Some(PathBuf::from("../payload.txt"));
        assert_eq!(transfer(escaping_local).expect_err("an escaping local path is refused").code(), ErrorCode::PathRejected);

        let mut empty_local = request();
        empty_local.local_path = Some(PathBuf::new());
        assert_eq!(transfer(empty_local).expect_err("an empty local path is refused").code(), ErrorCode::PathRejected);
    }

    #[test]
    fn an_interrupted_upload_reports_connection_lost_and_resumes() {
        let fixture = sftp_fixture(fixture::FixtureOptions { connections: 2, drop_after_write: Some(1), ..Default::default() });
        let local = temp_path("resume.bin");
        let contents: Vec<u8> = (0..40_000u32).map(|index| (index % 251) as u8).collect();
        std::fs::write(&local, &contents).expect("write the local file");

        let first = transfer(transfer_request(&fixture, TransferDirection::Upload, Some(local.clone()), "/resume/data.bin"));
        let error = first.expect_err("the fixture drops the first connection");
        assert_eq!(error.code(), ErrorCode::ConnectionLost, "{}", error.message());

        let mut resume = transfer_request(&fixture, TransferDirection::Upload, Some(local.clone()), "/resume/data.bin");
        resume.resume = true;
        let result = transfer(resume).expect("resume the upload");

        assert!(result.resumed_from > 0, "the second attempt must continue from the partial file");
        assert_eq!(result.resumed_from + result.bytes, contents.len() as u64);
        assert_eq!(fixture.file("/resume/data.bin").as_deref(), Some(contents.as_slice()));
        let _ = std::fs::remove_file(&local);
        fixture.wait();
    }

    #[test]
    fn missing_remote_files_report_remote_not_found() {
        let fixture = sftp_fixture(fixture::FixtureOptions::default());
        let local = temp_path("missing.bin");
        let error = transfer(transfer_request(&fixture, TransferDirection::Download, Some(local), "/missing/file.bin"))
            .expect_err("a missing remote file must fail");
        assert_eq!(error.code(), ErrorCode::RemoteNotFound);
        fixture.wait();
    }

    #[test]
    fn denied_paths_report_permission_denied() {
        let fixture = sftp_fixture(fixture::FixtureOptions {
            files: vec![("/secret/key.bin", b"data".to_vec())],
            deny: vec!["/secret/key.bin"],
            ..Default::default()
        });
        let local = temp_path("denied.bin");
        let error = transfer(transfer_request(&fixture, TransferDirection::Download, Some(local), "/secret/key.bin"))
            .expect_err("a denied path must fail");
        assert_eq!(error.code(), ErrorCode::PermissionDenied);
        fixture.wait();
    }

    #[test]
    fn a_full_remote_file_system_reports_disk_full() {
        let fixture = sftp_fixture(fixture::FixtureOptions { disk_full: true, ..Default::default() });
        let local = temp_path("disk-full.bin");
        std::fs::write(&local, vec![3u8; 20_000]).expect("write the local file");
        let error = transfer(transfer_request(&fixture, TransferDirection::Upload, Some(local.clone()), "/incoming/full.bin"))
            .expect_err("a full remote file system must fail");
        assert_eq!(error.code(), ErrorCode::DiskFull);
        let _ = std::fs::remove_file(&local);
        fixture.wait();
    }

    #[test]
    fn preview_plans_an_upload_without_connecting() {
        let local = temp_path("preview.bin");
        std::fs::write(&local, vec![1u8; 1234]).expect("write the local file");
        let request = TransferRequest {
            transport: "ssh".to_string(),
            host: "127.0.0.1".to_string(),
            port: 1,
            user: "operator".to_string(),
            auth: ExecAuth::Password("secret".to_string()),
            host_key_sha256: "SHA256:abc".to_string(),
            timeout: Duration::from_secs(1),
            direction: TransferDirection::Upload,
            local_path: Some(local.clone()),
            remote_path: "/incoming/./preview.bin".to_string(),
            resume: false,
        };

        let preview = transfer_preview(&request).expect("preview");

        assert_eq!(preview.direction, "upload");
        assert_eq!(preview.remote_path, "/incoming/preview.bin");
        assert_eq!(preview.planned_bytes, Some(1234));
        assert!(!preview.resume);
        assert_eq!(preview.host_key_sha256, "SHA256:abc");
        let _ = std::fs::remove_file(&local);
    }
}
