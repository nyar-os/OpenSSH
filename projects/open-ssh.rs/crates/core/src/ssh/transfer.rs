//! SFTP transfer orchestration for the `transfer` capability.
//!
//! Uploads, downloads, and directory listings share the connection and
//! authentication path used by `exec`. Paths are normalized before use, and
//! every failure keeps its own stable code.

use std::{
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Component, Path, PathBuf},
    time::{Duration, Instant},
};

use serde::Serialize;

use crate::{
    audit::capability_ids,
    errors::{Error, ErrorCode},
};

use super::{
    ExecAuth, Result, connect_and_authenticate, host_hash, normalize_pin,
    sftp::{CHUNK, SftpClient},
};

/// Which way bytes move.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum TransferDirection {
    /// Local file to remote path.
    Upload,
    /// Remote path to local file.
    Download,
    /// Remote directory to the caller.
    List,
}

impl TransferDirection {
    /// Stable identifier used in results and audit params.
    pub fn name(self) -> &'static str {
        match self {
            Self::Upload => "upload",
            Self::Download => "download",
            Self::List => "list",
        }
    }
}

/// One `transfer` request.
#[derive(Debug)]
pub struct TransferRequest {
    /// Transport adapter. Only `ssh` is available.
    pub transport: String,
    /// Target host name or address.
    pub host: String,
    /// Target port.
    pub port: u16,
    /// Remote user name.
    pub user: String,
    /// Authentication material.
    pub auth: ExecAuth,
    /// Required `SHA256:` host key fingerprint.
    pub host_key_sha256: String,
    /// Deadline in milliseconds.
    pub timeout: Duration,
    /// Direction of the transfer.
    pub direction: TransferDirection,
    /// Local file for upload and download. Ignored for listings.
    pub local_path: Option<PathBuf>,
    /// Remote file or directory.
    pub remote_path: String,
    /// Continue from the partially transferred data already on the other side.
    pub resume: bool,
}

/// One directory entry in a listing result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferEntry {
    /// Entry name relative to the listed directory.
    pub name: String,
    /// Entry size in bytes.
    pub size: u64,
    /// Whether the entry is a directory.
    pub is_dir: bool,
}

/// Result of one `transfer` call.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferResult {
    /// Transport adapter that served the call.
    pub transport: &'static str,
    /// Truncated SHA-256 of the target host, safe for audit.
    pub host_hash: String,
    /// Target port.
    pub port: u16,
    /// Remote user name.
    pub user: String,
    /// Authentication method that was used.
    pub auth_method: &'static str,
    /// `upload`, `download`, or `list`.
    pub direction: &'static str,
    /// Normalized remote path.
    pub remote_path: String,
    /// Local path as resolved, if the direction uses one.
    pub local_path: Option<String>,
    /// Bytes transferred by this call.
    pub bytes: u64,
    /// Offset this call resumed from.
    pub resumed_from: u64,
    /// Directory entries, empty for uploads and downloads.
    pub entries: Vec<TransferEntry>,
    /// Wall-clock duration of the whole call.
    pub duration_ms: u64,
}

/// What one `transfer` call would do, resolved without opening a connection.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferPreview {
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
    /// `upload`, `download`, or `list`.
    pub direction: &'static str,
    /// Normalized remote path.
    pub remote_path: String,
    /// Local path as resolved, if the direction uses one.
    pub local_path: Option<String>,
    /// Whether the call would resume.
    pub resume: bool,
    /// Local file size for uploads, `null` when only the server knows.
    pub planned_bytes: Option<u64>,
    /// Pinned fingerprint in `SHA256:` notation.
    pub host_key_sha256: String,
    /// Deadline in milliseconds.
    pub timeout_ms: u64,
}

/// Progress reported while bytes move.
#[derive(Debug, Clone, Copy)]
pub struct Progress {
    /// Bytes accounted for so far, including any resumed prefix.
    pub transferred: u64,
    /// Expected total, when it is known before the transfer starts.
    pub total: Option<u64>,
}

/// Resolve a transfer request without connecting.
pub fn preview(request: &TransferRequest) -> Result<TransferPreview> {
    let plan = plan(request)?;
    let planned_bytes = match request.direction {
        TransferDirection::Upload => Some(std::fs::metadata(&plan.local_path).map_err(|error| local_error(&plan.local_path, error))?.len()),
        TransferDirection::Download | TransferDirection::List => None,
    };
    Ok(TransferPreview {
        transport: "ssh",
        host_hash: host_hash(&request.host),
        port: request.port,
        user: request.user.clone(),
        auth_method: request.auth.name(),
        direction: request.direction.name(),
        remote_path: plan.remote_path,
        local_path: match request.direction {
            TransferDirection::List => None,
            _ => Some(plan.local_path.display().to_string()),
        },
        resume: request.resume,
        planned_bytes,
        host_key_sha256: format!("SHA256:{}", normalize_pin(&request.host_key_sha256)),
        timeout_ms: request.timeout.as_millis() as u64,
    })
}

/// Run one transfer.
pub fn execute(request: TransferRequest) -> Result<TransferResult> {
    execute_with(request, |_| {})
}

/// Run one transfer and report progress as it goes.
pub fn execute_with(request: TransferRequest, mut progress: impl FnMut(Progress)) -> Result<TransferResult> {
    let plan = plan(&request)?;
    let started = Instant::now();
    let (mut transport, auth_method) =
        connect_and_authenticate(&request.host, request.port, &request.user, &request.auth, &request.host_key_sha256, request.timeout)?;

    let mut client = SftpClient::open(&mut transport)?;
    let outcome = match request.direction {
        TransferDirection::Upload => upload(&mut client, &plan, request.resume, &mut progress)?,
        TransferDirection::Download => download(&mut client, &plan, request.resume, &mut progress)?,
        TransferDirection::List => list(&mut client, &plan)?,
    };
    client.finish()?;

    Ok(TransferResult {
        transport: "ssh",
        host_hash: host_hash(&request.host),
        port: request.port,
        user: request.user,
        auth_method,
        direction: request.direction.name(),
        remote_path: plan.remote_path,
        local_path: match request.direction {
            TransferDirection::List => None,
            _ => Some(plan.local_path.display().to_string()),
        },
        bytes: outcome.bytes,
        resumed_from: outcome.resumed_from,
        entries: outcome.entries,
        duration_ms: started.elapsed().as_millis() as u64,
    })
}

struct Plan {
    remote_path: String,
    local_path: PathBuf,
}

#[derive(Default)]
struct Outcome {
    bytes: u64,
    resumed_from: u64,
    entries: Vec<TransferEntry>,
}

fn plan(request: &TransferRequest) -> Result<Plan> {
    validate(request)?;
    let remote_path = normalize_remote_path(&request.remote_path)?;
    let local_path = match request.direction {
        TransferDirection::Upload | TransferDirection::Download => {
            let raw = request.local_path.as_ref().ok_or_else(|| Error::new(ErrorCode::PathRejected, "this direction requires a local path"))?;
            normalize_local_path(raw)?
        }
        TransferDirection::List => {
            if request.resume {
                return Err(Error::new(ErrorCode::InvalidArgument, "`list` moves no bytes, so `resume` does not apply"));
            }
            if request.local_path.is_some() {
                return Err(Error::new(ErrorCode::InvalidArgument, "`list` has no local file, so `local_path` does not apply"));
            }
            PathBuf::new()
        }
    };
    Ok(Plan { remote_path, local_path })
}

fn validate(request: &TransferRequest) -> Result<()> {
    if request.transport != "ssh" {
        return Err(Error::for_capability(
            ErrorCode::NotImplemented,
            capability_ids::TRANSFER,
            "RDP transfer uses drive redirection and is not implemented. Only the ssh transport is available.",
        ));
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
            "transfer requires a pinned host key fingerprint, and this client never trusts an unknown key",
        ));
    }
    if request.timeout.is_zero() {
        return Err(Error::new(ErrorCode::InvalidArgument, "timeout must be greater than zero"));
    }
    Ok(())
}

/// Reject empty paths, `..` components, and NUL bytes.
///
/// `..` is refused outright instead of being collapsed, so a caller cannot rely
/// on the client to rewrite an escaping path.
pub fn normalize_remote_path(raw: &str) -> Result<String> {
    if raw.trim().is_empty() {
        return Err(Error::new(ErrorCode::PathRejected, "the remote path must not be empty"));
    }
    if raw.contains('\0') {
        return Err(Error::new(ErrorCode::PathRejected, "the remote path must not contain NUL bytes"));
    }
    let absolute = raw.starts_with('/');
    let mut parts = Vec::new();
    for part in raw.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                return Err(Error::new(ErrorCode::PathRejected, format!("the remote path `{raw}` must not contain `..`")));
            }
            other => parts.push(other),
        }
    }
    if parts.is_empty() {
        return Err(Error::new(ErrorCode::PathRejected, format!("the remote path `{raw}` resolves to nothing")));
    }
    let mut normalized = String::new();
    if absolute {
        normalized.push('/');
    }
    normalized.push_str(&parts.join("/"));
    Ok(normalized)
}

/// Reject empty local paths and `..` components.
pub fn normalize_local_path(raw: &Path) -> Result<PathBuf> {
    if raw.as_os_str().is_empty() {
        return Err(Error::new(ErrorCode::PathRejected, "the local path must not be empty"));
    }
    let mut normalized = PathBuf::new();
    let mut named = false;
    for component in raw.components() {
        match component {
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir => normalized.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                return Err(Error::new(ErrorCode::PathRejected, format!("the local path `{}` must not contain `..`", raw.display())));
            }
            Component::Normal(value) => {
                named = true;
                normalized.push(value);
            }
        }
    }
    if !named {
        return Err(Error::new(ErrorCode::PathRejected, format!("the local path `{}` resolves to nothing", raw.display())));
    }
    Ok(normalized)
}

fn upload(client: &mut SftpClient<'_>, plan: &Plan, resume: bool, progress: &mut impl FnMut(Progress)) -> Result<Outcome> {
    let mut local = File::open(&plan.local_path).map_err(|error| local_error(&plan.local_path, error))?;
    let total = local.metadata().map_err(|error| local_error(&plan.local_path, error))?.len();
    let start = if resume { client.size(&plan.remote_path)?.unwrap_or(0) } else { 0 };
    if start > total {
        return Err(Error::new(
            ErrorCode::TransferFailed,
            format!(
                "the remote file `{}` is {start} bytes but the local source is only {total} bytes, so it cannot be resumed",
                plan.remote_path
            ),
        ));
    }

    let handle = client.create(&plan.remote_path, start > 0)?;
    if start > 0 {
        local.seek(SeekFrom::Start(start)).map_err(|error| local_error(&plan.local_path, error))?;
    }
    let mut offset = start;
    let mut buffer = vec![0u8; CHUNK];
    loop {
        let read = local.read(&mut buffer).map_err(|error| local_error(&plan.local_path, error))?;
        if read == 0 {
            break;
        }
        client.write_at(&handle, offset, &buffer[..read])?;
        offset += read as u64;
        progress(Progress { transferred: offset, total: Some(total) });
    }
    client.close_handle(&handle)?;
    Ok(Outcome { bytes: offset - start, resumed_from: start, entries: Vec::new() })
}

fn download(client: &mut SftpClient<'_>, plan: &Plan, resume: bool, progress: &mut impl FnMut(Progress)) -> Result<Outcome> {
    let total = client
        .size(&plan.remote_path)?
        .ok_or_else(|| Error::new(ErrorCode::RemoteNotFound, format!("the remote path `{}` does not exist", plan.remote_path)))?;
    let start = if resume { std::fs::metadata(&plan.local_path).map(|metadata| metadata.len()).unwrap_or(0) } else { 0 };
    if start > total {
        return Err(Error::new(
            ErrorCode::TransferFailed,
            format!("`{}` is {start} bytes but the remote file is only {total} bytes", plan.local_path.display()),
        ));
    }

    let mut local = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(!resume)
        .open(&plan.local_path)
        .map_err(|error| local_error(&plan.local_path, error))?;
    if start > 0 {
        local.seek(SeekFrom::Start(start)).map_err(|error| local_error(&plan.local_path, error))?;
    }

    let handle = client.open_read(&plan.remote_path)?;
    let mut offset = start;
    while offset < total {
        let limit = CHUNK.min((total - offset) as usize);
        let Some(chunk) = client.read_at(&handle, offset, limit)?
        else {
            break;
        };
        if chunk.is_empty() {
            break;
        }
        local.write_all(&chunk).map_err(|error| local_error(&plan.local_path, error))?;
        offset += chunk.len() as u64;
        progress(Progress { transferred: offset, total: Some(total) });
    }
    local.flush().map_err(|error| local_error(&plan.local_path, error))?;
    client.close_handle(&handle)?;
    Ok(Outcome { bytes: offset - start, resumed_from: start, entries: Vec::new() })
}

fn list(client: &mut SftpClient<'_>, plan: &Plan) -> Result<Outcome> {
    let mut entries: Vec<TransferEntry> = client
        .list(&plan.remote_path)?
        .into_iter()
        .map(|entry| TransferEntry { name: entry.name, size: entry.size, is_dir: entry.is_dir })
        .collect();
    entries.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(Outcome { bytes: 0, resumed_from: 0, entries })
}

fn local_error(path: &Path, error: std::io::Error) -> Error {
    if error.kind() == std::io::ErrorKind::StorageFull || error.raw_os_error() == Some(112) || error.raw_os_error() == Some(28) {
        return Error::new(ErrorCode::DiskFull, format!("`{}` could not be written: {error}", path.display()));
    }
    Error::new(ErrorCode::Io, format!("`{}` could not be used: {error}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_paths_reject_escapes_and_empty_values() {
        assert!(normalize_remote_path("").is_err());
        assert!(normalize_remote_path("   ").is_err());
        assert!(normalize_remote_path("a/../../b").is_err());
        assert!(normalize_remote_path("/../etc/passwd").is_err());
        assert_eq!(normalize_remote_path("/var//log/./app.log").expect("normalized"), "/var/log/app.log");
        assert_eq!(normalize_remote_path("relative/path").expect("normalized"), "relative/path");
    }

    #[test]
    fn local_paths_reject_escapes_and_empty_values() {
        assert!(normalize_local_path(Path::new("")).is_err());
        assert!(normalize_local_path(Path::new(".")).is_err());
        assert!(normalize_local_path(Path::new("a/../b")).is_err());
        assert_eq!(normalize_local_path(Path::new("./a/b.txt")).expect("normalized"), PathBuf::from("a/b.txt"));
    }
}
