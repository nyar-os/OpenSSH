//! Interop tests that run against a real OpenSSH server.
//!
//! The loopback fixture inside the crate proves the protocol branches, but it
//! speaks the same encoding as the client, so a symmetric mistake passes both
//! sides. These tests talk to a stock `sshd` instead, and they only run when an
//! operator points them at one.
//!
//! A target is described entirely by these environment variables:
//!
//! ```text
//! OPEN_SSH_INTEROP_HOST      host name or address of the server
//! OPEN_SSH_INTEROP_PORT      TCP port of the server
//! OPEN_SSH_INTEROP_USER      remote user name
//! OPEN_SSH_INTEROP_KEY       path to an unencrypted OpenSSH ed25519 identity
//! OPEN_SSH_INTEROP_PIN       pinned `SHA256:` host key fingerprint
//! OPEN_SSH_INTEROP_REQUIRED  set to `1` to fail instead of skipping
//! ```
//!
//! Without them the tests print one skip line and return, so an ordinary
//! `cargo test` stays offline. CI sets `OPEN_SSH_INTEROP_REQUIRED=1` so a
//! missing target fails the job rather than silently shrinking the suite.

use std::{
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use open_ssh_core::ssh::{ConnectRequest, ExecAuth, ExecRequest, ExecResult, TransferDirection, TransferRequest, connect, execute, transfer};

const HOST: &str = "OPEN_SSH_INTEROP_HOST";
const PORT: &str = "OPEN_SSH_INTEROP_PORT";
const USER: &str = "OPEN_SSH_INTEROP_USER";
const KEY: &str = "OPEN_SSH_INTEROP_KEY";
const PIN: &str = "OPEN_SSH_INTEROP_PIN";
const REQUIRED: &str = "OPEN_SSH_INTEROP_REQUIRED";

/// Deadline for a single call. A real handshake plus one command or one small
/// file needs far less, so this only bounds a hung target.
const TIMEOUT: Duration = Duration::from_secs(30);

/// Every variable a run needs.
const TARGET_VARIABLES: [&str; 5] = [HOST, PORT, USER, KEY, PIN];

struct Target {
    host: String,
    port: u16,
    user: String,
    identity: PathBuf,
    pin: String,
}

impl Target {
    fn auth(&self) -> ExecAuth {
        ExecAuth::Identity(self.identity.clone())
    }
}

/// Read one variable, treating blank values as unset.
fn read(name: &str) -> Option<String> {
    std::env::var(name).ok().map(|value| value.trim().to_string()).filter(|value| !value.is_empty())
}

/// Whether a missing target must fail the run.
fn required() -> bool {
    read(REQUIRED).as_deref() == Some("1")
}

/// Resolve the target, or skip the test when the operator supplied none.
fn target() -> Option<Target> {
    let missing: Vec<&str> = TARGET_VARIABLES.iter().copied().filter(|name| read(name).is_none()).collect();
    if !missing.is_empty() {
        let summary = missing.join(", ");
        if required() {
            panic!("a live OpenSSH target is required, and these variables are unset: {summary}");
        }
        eprintln!("skipping the real OpenSSH interop tests, and these variables are unset: {summary}");
        return None;
    }

    let host = read(HOST).expect("checked above");
    let user = read(USER).expect("checked above");
    let identity = PathBuf::from(read(KEY).expect("checked above"));
    let pin = read(PIN).expect("checked above");
    let raw_port = read(PORT).expect("checked above");
    let port = raw_port.parse::<u16>().unwrap_or_else(|_| panic!("{PORT} must be a port number, and `{raw_port}` is not"));

    assert!(identity.is_file(), "{KEY} must point at an existing identity file, and `{}` is not a file", identity.display());
    Some(Target { host, port, user, identity, pin })
}

/// Drop an optional `SHA256:` prefix so a pin can be compared either way.
fn bare_pin(pin: &str) -> &str {
    let trimmed = pin.trim();
    match trimmed.strip_prefix("SHA256:") {
        Some(rest) => rest.trim(),
        None => trimmed,
    }
}

/// A suffix unique to this process and this instant, for remote file names.
fn unique_suffix() -> String {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).map(|elapsed| elapsed.as_nanos()).unwrap_or_default();
    format!("{}-{nanos}", std::process::id())
}

/// Give one argument to a shell safely.
fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn exec_request(target: &Target, command: String) -> ExecRequest {
    ExecRequest {
        transport: "ssh".to_string(),
        host: target.host.clone(),
        port: target.port,
        user: target.user.clone(),
        command,
        auth: target.auth(),
        host_key_sha256: target.pin.clone(),
        timeout: TIMEOUT,
    }
}

fn run(target: &Target, command: String) -> ExecResult {
    execute(exec_request(target, command)).expect("the command must run over a real OpenSSH session")
}

fn transfer_request(target: &Target, direction: TransferDirection, local_path: Option<PathBuf>, remote_path: &str) -> TransferRequest {
    TransferRequest {
        transport: "ssh".to_string(),
        host: target.host.clone(),
        port: target.port,
        user: target.user.clone(),
        auth: target.auth(),
        host_key_sha256: target.pin.clone(),
        timeout: TIMEOUT,
        direction,
        local_path,
        remote_path: remote_path.to_string(),
        resume: false,
    }
}

fn remove_local(path: &Path) {
    let _ = std::fs::remove_file(path);
}

#[test]
fn connect_verifies_the_pinned_host_key() {
    let Some(target) = target()
    else {
        return;
    };

    let result = connect(ConnectRequest {
        transport: "ssh".to_string(),
        host: target.host.clone(),
        port: target.port,
        user: target.user.clone(),
        auth: target.auth(),
        host_key_sha256: target.pin.clone(),
        timeout: TIMEOUT,
    })
    .expect("a real server must accept a pinned connect");

    println!("connect: server `{}`, pin `{}`, {} ms", result.server_version, result.host_key_sha256, result.duration_ms);

    assert_eq!(result.transport, "ssh");
    assert_eq!(result.auth_method, "publickey");
    assert_eq!(result.port, target.port);
    assert_eq!(result.user, target.user);
    assert!(
        result.server_version.starts_with("SSH-2.0-"),
        "the server version `{}` is not an SSH identification string",
        result.server_version
    );
    assert_eq!(result.host_key_sha256, format!("SHA256:{}", bare_pin(&target.pin)), "the server host key must match the pinned fingerprint");
    assert_eq!(result.kex_algorithm, "curve25519-sha256");
    assert_eq!(result.host_key_algorithm, "ssh-ed25519");
}

#[test]
fn exec_passes_output_and_the_remote_exit_status_through() {
    let Some(target) = target()
    else {
        return;
    };

    let result = run(&target, "sh -c 'printf out; printf err >&2; exit 3'".to_string());

    println!(
        "exec: exit {:?}, stdout {:?} ({} bytes), stderr {:?} ({} bytes)",
        result.exit_code, result.stdout, result.stdout_bytes, result.stderr, result.stderr_bytes
    );

    assert_eq!(result.exit_code, Some(3), "the remote exit status must be reported as is, and stderr was `{}`", result.stderr);
    assert_eq!(result.stdout, "out");
    assert_eq!(result.stderr, "err");
    assert_eq!(result.stdout_bytes, 3);
    assert_eq!(result.stderr_bytes, 3);
    assert_eq!(result.auth_method, "publickey");
}

#[test]
fn transfer_round_trips_a_file_through_the_remote_home() {
    let Some(target) = target()
    else {
        return;
    };

    let home = run(&target, "printf %s \"$HOME\"".to_string());
    assert_eq!(home.exit_code, Some(0), "resolving the remote home failed: {}", home.stderr);
    let home = home.stdout.trim().to_string();
    assert!(home.starts_with('/'), "the remote home `{home}` is not an absolute path");

    let suffix = unique_suffix();
    let name = format!("open-ssh-interop-{suffix}.bin");
    let remote_path = format!("{home}/{name}");
    let upload = std::env::temp_dir().join(format!("open-ssh-interop-upload-{suffix}.bin"));
    let download = std::env::temp_dir().join(format!("open-ssh-interop-download-{suffix}.bin"));

    let contents: Vec<u8> = (0..48_000u32).map(|index| (index % 239) as u8).collect();
    std::fs::write(&upload, &contents).expect("write the local source file");

    let uploaded = transfer(transfer_request(&target, TransferDirection::Upload, Some(upload.clone()), &remote_path)).expect("upload");
    println!("transfer: uploaded {} bytes to `{}`", uploaded.bytes, uploaded.remote_path);
    assert_eq!(uploaded.direction, "upload");
    assert_eq!(uploaded.bytes, contents.len() as u64);
    assert_eq!(uploaded.resumed_from, 0);

    let listing = transfer(transfer_request(&target, TransferDirection::List, None, &home)).expect("list");
    let entry =
        listing.entries.iter().find(|entry| entry.name == name).unwrap_or_else(|| panic!("`{name}` is missing from the listing of `{home}`"));
    println!("transfer: listed `{}` at {} bytes", entry.name, entry.size);
    assert_eq!(entry.size, contents.len() as u64);
    assert!(!entry.is_dir);

    let downloaded = transfer(transfer_request(&target, TransferDirection::Download, Some(download.clone()), &remote_path)).expect("download");
    println!("transfer: downloaded {} bytes from `{}`", downloaded.bytes, downloaded.remote_path);
    assert_eq!(downloaded.direction, "download");
    assert_eq!(downloaded.bytes, contents.len() as u64);
    let round_tripped = std::fs::read(&download).expect("read the downloaded file");
    assert_eq!(round_tripped.len(), contents.len());
    assert_eq!(round_tripped, contents);

    let removed = run(&target, format!("rm -f -- {}", shell_quote(&remote_path)));
    assert_eq!(removed.exit_code, Some(0), "removing `{remote_path}` failed: {}", removed.stderr);

    remove_local(&upload);
    remove_local(&download);
}
