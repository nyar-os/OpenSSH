//! Loopback SSH server used to verify the client end to end.
//!
//! This is test-only infrastructure. It implements just enough of the server
//! side of the same protocol to exercise the real socket path, key exchange,
//! both authentication methods, one `exec` channel, and the `sftp` subsystem
//! backed by an in-memory file system. It is never compiled into a released
//! build.

use std::{
    collections::{BTreeMap, BTreeSet},
    net::{SocketAddr, TcpListener, TcpStream},
    sync::{Arc, Mutex, MutexGuard, PoisonError},
    thread::{self, JoinHandle},
    time::Duration,
};

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::errors::{Error, ErrorCode};

use super::{
    Result,
    kex::{derive, exchange_hash, fingerprint_of},
    transport::{AesGcmState, Transport},
    wire::{Reader, Writer, encode_mpint},
};

const TIMEOUT: Duration = Duration::from_secs(10);
const WINDOW: u32 = 2 * 1024 * 1024;
const MAX_PACKET: u32 = 32 * 1024;

/// Fixed output the fixture returns for `exec`.
const STDOUT: &str = "hello from the fixture\n";
/// Fixed error output the fixture returns for `exec`.
const STDERR: &str = "warning from the fixture\n";
/// Fixed remote exit status the fixture returns for `exec`.
const EXIT_STATUS: u32 = 7;

const MSG_STATUS: u8 = 101;
const MSG_HANDLE: u8 = 102;
const MSG_DATA: u8 = 103;
const MSG_NAME: u8 = 104;
const MSG_STATUS_ATTRS: u8 = 105;

const STATUS_OK: u32 = 0;
const STATUS_EOF: u32 = 1;
const STATUS_NO_SUCH_FILE: u32 = 2;
const STATUS_PERMISSION_DENIED: u32 = 3;
const STATUS_FAILURE: u32 = 4;
const STATUS_OP_UNSUPPORTED: u32 = 8;

const ATTR_SIZE: u32 = 1;
const ATTR_PERMISSIONS: u32 = 4;

/// Authentication the fixture server accepts.
pub(crate) enum FixtureAuth {
    /// Accept this password.
    Password(&'static str),
    /// Accept the fixture's client key.
    PublicKey,
}

/// Which service the fixture serves after authentication.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FixtureMode {
    /// One `exec` channel with fixed output.
    Exec,
    /// The `sftp` subsystem over an in-memory file system.
    Sftp,
    /// Authenticate and then expect a client disconnect.
    Probe,
}

/// One loopback server configuration.
pub(crate) struct FixtureOptions {
    /// Accepted credentials.
    pub(crate) auth: FixtureAuth,
    /// Public key the fixture accepts in `PublicKey` mode.
    pub(crate) client_key: SigningKey,
    /// Service served after authentication.
    pub(crate) mode: FixtureMode,
    /// How many connections the listener accepts before it stops.
    pub(crate) connections: usize,
    /// Files seeded into the SFTP file system.
    pub(crate) files: Vec<(&'static str, Vec<u8>)>,
    /// Directories seeded into the SFTP file system.
    pub(crate) directories: Vec<&'static str>,
    /// Drop the first connection once this many bytes were written.
    pub(crate) drop_after_write: Option<u64>,
    /// Paths that answer with `SSH_FX_PERMISSION_DENIED`.
    pub(crate) deny: Vec<&'static str>,
    /// Answer every write with `SSH_FX_FAILURE` and a disk-full message.
    pub(crate) disk_full: bool,
}

impl Default for FixtureOptions {
    fn default() -> Self {
        Self {
            auth: FixtureAuth::Password("secret"),
            client_key: SigningKey::from_bytes(&[3u8; 32]),
            mode: FixtureMode::Exec,
            connections: 1,
            files: Vec::new(),
            directories: Vec::new(),
            drop_after_write: None,
            deny: Vec::new(),
            disk_full: false,
        }
    }
}

/// One loopback server and the material the client needs.
pub(crate) struct Fixture {
    /// Bound loopback address.
    pub(crate) addr: SocketAddr,
    /// Expected `SHA256:` host key fingerprint.
    pub(crate) pin: String,
    /// Output the fixture returns for `exec`.
    pub(crate) stdout: &'static str,
    /// Error output the fixture returns for `exec`.
    pub(crate) stderr: &'static str,
    /// Exit status the fixture returns for `exec`.
    pub(crate) exit_status: u32,
    files: Arc<Mutex<BTreeMap<String, Vec<u8>>>>,
    server: Mutex<Option<JoinHandle<()>>>,
}

impl Fixture {
    /// Serve one `exec` connection with password or public key authentication.
    pub(crate) fn start(auth: FixtureAuth, client_key: SigningKey) -> Self {
        Self::start_with(FixtureOptions { auth, client_key, ..FixtureOptions::default() })
    }

    /// Serve a configured set of connections.
    pub(crate) fn start_with(options: FixtureOptions) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind loopback");
        let addr = listener.local_addr().expect("local address");
        let host_key = SigningKey::from_bytes(&[9u8; 32]);
        let pin = fingerprint_of(&host_key_blob(&host_key));

        let files: Arc<Mutex<BTreeMap<String, Vec<u8>>>> =
            Arc::new(Mutex::new(options.files.iter().map(|(path, data)| (path.to_string(), data.clone())).collect()));
        let shared_files = Arc::clone(&files);
        let directories: BTreeSet<String> = options.directories.iter().map(|path| path.to_string()).collect();
        let connections = options.connections.max(1);

        let server = thread::spawn(move || {
            let mut state = SftpState { files: shared_files, directories, handles: BTreeMap::new(), next_handle: 1, written: 0 };
            for index in 0..connections {
                let Ok((stream, _)) = listener.accept()
                else {
                    return;
                };
                let _ = serve(stream, &host_key, &options, index, &mut state);
                state.handles.clear();
            }
        });

        Self { addr, pin, stdout: STDOUT, stderr: STDERR, exit_status: EXIT_STATUS, files, server: Mutex::new(Some(server)) }
    }

    /// Wait for the fixture thread to finish.
    pub(crate) fn wait(&self) {
        if let Some(handle) = self.server.lock().unwrap_or_else(PoisonError::into_inner).take() {
            let _ = handle.join();
        }
    }

    /// A file in the fixture file system, if the server created it.
    pub(crate) fn file(&self, path: &str) -> Option<Vec<u8>> {
        self.files.lock().unwrap_or_else(PoisonError::into_inner).get(path).cloned()
    }
}

fn serve(stream: TcpStream, host_key: &SigningKey, options: &FixtureOptions, index: usize, state: &mut SftpState) -> Result<()> {
    let mut transport = Transport::accept(stream, TIMEOUT);
    transport.exchange_versions_as_server()?;
    handshake(&mut transport, host_key)?;
    service_request(&mut transport)?;
    authenticate(&mut transport, &options.auth, &options.client_key)?;
    if options.mode == FixtureMode::Probe {
        return expect_disconnect(&mut transport);
    }
    let (client_channel, request) = open_channel(&mut transport)?;
    match (options.mode, request) {
        (FixtureMode::Exec, ChannelRequest::Exec) => run_exec(&mut transport, client_channel),
        (FixtureMode::Sftp, ChannelRequest::Subsystem(name)) if name == "sftp" => {
            serve_sftp(&mut transport, client_channel, options, index, state)
        }
        _ => Err(protocol("the fixture serves only the configured service")),
    }
}

/// Require the client to end the session with a disconnect instead of a bare FIN.
fn expect_disconnect(transport: &mut Transport) -> Result<()> {
    let message = transport.receive()?;
    let mut reader = Reader::new(&message);
    if reader.byte()? != 1 {
        return Err(protocol("the probe did not send `SSH_MSG_DISCONNECT`"));
    }
    if reader.u32()? != 11 {
        return Err(protocol("the probe did not disconnect by application"));
    }
    Ok(())
}

fn host_key_blob(key: &SigningKey) -> Vec<u8> {
    let mut writer = Writer::empty();
    writer.string(b"ssh-ed25519").string(&key.verifying_key().to_bytes());
    writer.finish()
}

fn kexinit() -> Vec<u8> {
    let mut writer = Writer::new(20);
    for byte in [7u8; 16] {
        writer.byte(byte);
    }
    writer
        .name_list(&["curve25519-sha256"])
        .name_list(&["ssh-ed25519"])
        .name_list(&["aes256-gcm@openssh.com"])
        .name_list(&["aes256-gcm@openssh.com"])
        .name_list(&["hmac-sha2-256"])
        .name_list(&["hmac-sha2-256"])
        .name_list(&["none"])
        .name_list(&["none"])
        .name_list(&[])
        .name_list(&[])
        .boolean(false)
        .u32(0);
    writer.finish()
}

fn handshake(transport: &mut Transport, host_key: &SigningKey) -> Result<()> {
    let server_kexinit = kexinit();
    transport.send(&server_kexinit)?;
    let client_kexinit = transport.receive()?;
    transport.remember_kexinit(client_kexinit, server_kexinit);

    let init = transport.receive()?;
    let mut reader = Reader::new(&init);
    if reader.byte()? != 30 {
        return Err(protocol("the client did not send `SSH_MSG_KEX_ECDH_INIT`"));
    }
    let client_public = reader.string()?.to_vec();
    let client_array: [u8; 32] = client_public.as_slice().try_into().map_err(|_| protocol("the client ephemeral key has the wrong length"))?;

    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).map_err(|error| Error::new(ErrorCode::Internal, error.to_string()))?;
    let secret = StaticSecret::from(seed);
    let server_public = PublicKey::from(&secret).to_bytes();
    let mut shared = secret.diffie_hellman(&PublicKey::from(client_array)).to_bytes();
    shared.reverse();
    let shared_mpint = encode_mpint(&shared);

    let host_blob = host_key_blob(host_key);
    let hash = exchange_hash(transport, &host_blob, &client_public, &server_public, &shared_mpint)?;
    transport.set_session_id(hash.clone());

    let signature = host_key.sign(&hash);
    let mut signature_blob = Writer::empty();
    signature_blob.string(b"ssh-ed25519").string(&signature.to_bytes());
    let mut reply = Writer::new(31);
    reply.string(&host_blob).string(&server_public).string(&signature_blob.finish());
    transport.send(&reply.finish())?;
    transport.send(&[21])?;

    let iv_client_to_server = derive(b'A', &shared_mpint, &hash, &hash, 12)?;
    let iv_server_to_client = derive(b'B', &shared_mpint, &hash, &hash, 12)?;
    let key_client_to_server = derive(b'C', &shared_mpint, &hash, &hash, 32)?;
    let key_server_to_client = derive(b'D', &shared_mpint, &hash, &hash, 32)?;
    transport.install_outbound(AesGcmState::new(&key_server_to_client, &iv_server_to_client)?);

    if transport.receive()? != [21] {
        return Err(protocol("the client did not send `SSH_MSG_NEWKEYS`"));
    }
    transport.install_inbound(AesGcmState::new(&key_client_to_server, &iv_client_to_server)?);
    Ok(())
}

fn service_request(transport: &mut Transport) -> Result<()> {
    let message = transport.receive()?;
    let mut reader = Reader::new(&message);
    if reader.byte()? != 5 {
        return Err(protocol("the client did not request a service"));
    }
    let service = reader.string()?;
    let mut reply = Writer::new(6);
    reply.string(service);
    transport.send(&reply.finish())
}

fn authenticate(transport: &mut Transport, auth: &FixtureAuth, client_key: &SigningKey) -> Result<()> {
    let message = transport.receive()?;
    let mut reader = Reader::new(&message);
    if reader.byte()? != 50 {
        return Err(protocol("the client did not start user authentication"));
    }
    let _user = reader.string()?;
    let _service = reader.string()?;
    let method = reader.string()?.to_vec();
    let accepted = match (auth, method.as_slice()) {
        (FixtureAuth::Password(expected), b"password") => {
            let _change = reader.boolean()?;
            reader.string()? == expected.as_bytes()
        }
        (FixtureAuth::PublicKey, b"publickey") => verify_publickey(transport, &message, &mut reader, client_key)?,
        _ => false,
    };
    if !accepted {
        let mut failure = Writer::new(51);
        failure.name_list(&["password", "publickey"]).boolean(false);
        transport.send(&failure.finish())?;
        return Err(Error::new(ErrorCode::AuthFailed, "fixture rejected the credentials"));
    }
    let success = Writer::new(52);
    transport.send(&success.finish())
}

fn verify_publickey(transport: &mut Transport, message: &[u8], reader: &mut Reader<'_>, client_key: &SigningKey) -> Result<bool> {
    let has_signature = reader.boolean()?;
    let algorithm = reader.string()?.to_vec();
    let blob = reader.string()?.to_vec();
    if !has_signature || algorithm != b"ssh-ed25519" {
        return Ok(false);
    }
    let signature = reader.string()?.to_vec();
    let mut blob_reader = Reader::new(&blob);
    blob_reader.string()?;
    let public: [u8; 32] = blob_reader.string()?.try_into().map_err(|_| protocol("the client public key has the wrong length"))?;
    if public != client_key.verifying_key().to_bytes() {
        return Ok(false);
    }
    let verifying = VerifyingKey::from_bytes(&public).map_err(|_| protocol("the client public key is not a valid ed25519 point"))?;
    let mut signature_reader = Reader::new(&signature);
    signature_reader.string()?;
    let bytes: [u8; 64] = signature_reader.string()?.try_into().map_err(|_| protocol("the client signature has the wrong length"))?;

    let prefix = &message[..message.len() - 4 - signature.len()];
    let session = transport.session_id();
    let mut signed = Vec::with_capacity(4 + session.len() + prefix.len());
    signed.extend_from_slice(&(session.len() as u32).to_be_bytes());
    signed.extend_from_slice(session);
    signed.extend_from_slice(prefix);
    Ok(verifying.verify_strict(&signed, &Signature::from_bytes(&bytes)).is_ok())
}

/// What the client asked the session channel to do.
enum ChannelRequest {
    /// Run one command.
    Exec,
    /// Start a named subsystem.
    Subsystem(String),
}

/// Accept one session channel and read its first request.
///
/// The returned channel id is the client's own channel, which the server uses
/// as the recipient of every message it sends back.
fn open_channel(transport: &mut Transport) -> Result<(u32, ChannelRequest)> {
    let message = transport.receive()?;
    let mut reader = Reader::new(&message);
    if reader.byte()? != 90 {
        return Err(protocol("the client did not open a channel"));
    }
    let _kind = reader.string()?;
    let client_channel = reader.u32()?;
    let mut confirmation = Writer::new(91);
    confirmation.u32(client_channel).u32(0).u32(WINDOW).u32(MAX_PACKET);
    transport.send(&confirmation.finish())?;

    let request = transport.receive()?;
    let mut reader = Reader::new(&request);
    if reader.byte()? != 98 {
        return Err(protocol("the client did not send a channel request"));
    }
    let recipient = reader.u32()?;
    let kind = reader.string()?.to_vec();
    let want_reply = reader.boolean()?;
    let parsed = match kind.as_slice() {
        b"exec" => {
            let _command = reader.string()?;
            ChannelRequest::Exec
        }
        b"subsystem" => ChannelRequest::Subsystem(String::from_utf8_lossy(reader.string()?).into_owned()),
        _ => return Err(protocol("the fixture does not serve this channel request")),
    };
    if want_reply {
        let mut success = Writer::new(99);
        success.u32(recipient);
        transport.send(&success.finish())?;
    }
    Ok((client_channel, parsed))
}

fn run_exec(transport: &mut Transport, channel: u32) -> Result<()> {
    let mut data = Writer::new(94);
    data.u32(channel).string(STDOUT.as_bytes());
    transport.send(&data.finish())?;

    let mut extended = Writer::new(95);
    extended.u32(channel).u32(1).string(STDERR.as_bytes());
    transport.send(&extended.finish())?;

    let mut status = Writer::new(98);
    status.u32(channel).string(b"exit-status").boolean(false).u32(EXIT_STATUS);
    transport.send(&status.finish())?;

    let mut eof = Writer::new(96);
    eof.u32(channel);
    transport.send(&eof.finish())?;

    let mut close = Writer::new(97);
    close.u32(channel);
    transport.send(&close.finish())?;
    drain(transport)
}

/// Read the client's remaining window updates and close, then stop.
fn drain(transport: &mut Transport) -> Result<()> {
    for _ in 0..16 {
        let message = transport.receive()?;
        if message.first() == Some(&97) {
            return Ok(());
        }
    }
    Ok(())
}

/// One open SFTP handle.
enum Handle {
    /// An open file, by normalized remote path.
    File { path: String },
    /// A directory listing that is served once.
    Directory { entries: Vec<(String, u64, bool)>, drained: bool },
}

/// Server-side state shared across connections of one fixture.
struct SftpState {
    files: Arc<Mutex<BTreeMap<String, Vec<u8>>>>,
    directories: BTreeSet<String>,
    handles: BTreeMap<Vec<u8>, Handle>,
    next_handle: u32,
    written: u64,
}

impl SftpState {
    fn files(&self) -> MutexGuard<'_, BTreeMap<String, Vec<u8>>> {
        self.files.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn allocate(&mut self, handle: Handle) -> Vec<u8> {
        let id = self.next_handle;
        self.next_handle = self.next_handle.wrapping_add(1);
        let bytes = id.to_be_bytes().to_vec();
        self.handles.insert(bytes.clone(), handle);
        bytes
    }
}

fn serve_sftp(transport: &mut Transport, channel: u32, options: &FixtureOptions, index: usize, state: &mut SftpState) -> Result<()> {
    state.written = 0;
    let mut inbound = Vec::new();
    while let Some(packet) = read_packet(transport, &mut inbound)? {
        if packet.len() < 5 {
            return Err(protocol("the client sent an SFTP request without an id"));
        }
        let kind = packet[0];
        let mut reader = Reader::new(&packet);
        let _ = reader.byte()?;
        if kind == 1 {
            let _version = reader.u32()?;
            let mut writer = Writer::new(2);
            writer.u32(3);
            send_packet(transport, channel, &writer.finish())?;
            continue;
        }
        let id = reader.u32()?;
        match kind {
            3 => {
                let path = String::from_utf8_lossy(reader.string()?).into_owned();
                let flags = reader.u32()?;
                if denied(options, &path) {
                    status(transport, channel, id, STATUS_PERMISSION_DENIED, "Permission denied")?;
                    continue;
                }
                let read = flags & 1 != 0;
                let write = flags & 2 != 0;
                let create = flags & 8 != 0;
                let truncate = flags & 16 != 0;
                let opened = {
                    let mut files = state.files();
                    let exists = files.contains_key(&path);
                    let refused = (read && !write && !exists) || (write && !exists && !create);
                    if !refused && write {
                        let entry = files.entry(path.clone()).or_default();
                        if truncate {
                            entry.clear();
                        }
                    }
                    !refused
                };
                if !opened {
                    status(transport, channel, id, STATUS_NO_SUCH_FILE, "No such file")?;
                    continue;
                }
                let handle = state.allocate(Handle::File { path });
                let mut writer = Writer::new(MSG_HANDLE);
                writer.u32(id).string(&handle);
                send_packet(transport, channel, &writer.finish())?;
            }
            4 => {
                let handle = reader.string()?.to_vec();
                state.handles.remove(&handle);
                status(transport, channel, id, STATUS_OK, "ok")?;
            }
            5 => {
                let handle = reader.string()?.to_vec();
                let offset = reader.u64()? as usize;
                let limit = reader.u32()? as usize;
                let path = match state.handles.get(&handle) {
                    Some(Handle::File { path }) => path.clone(),
                    _ => {
                        status(transport, channel, id, STATUS_FAILURE, "invalid handle")?;
                        continue;
                    }
                };
                if denied(options, &path) {
                    status(transport, channel, id, STATUS_PERMISSION_DENIED, "Permission denied")?;
                    continue;
                }
                let files = state.files();
                let Some(data) = files.get(&path)
                else {
                    status(transport, channel, id, STATUS_NO_SUCH_FILE, "No such file")?;
                    continue;
                };
                if offset >= data.len() {
                    status(transport, channel, id, STATUS_EOF, "EOF")?;
                    continue;
                }
                let end = offset.saturating_add(limit).min(data.len());
                let mut writer = Writer::new(MSG_DATA);
                writer.u32(id).string(&data[offset..end]);
                send_packet(transport, channel, &writer.finish())?;
            }
            6 => {
                let handle = reader.string()?.to_vec();
                let offset = reader.u64()?;
                let data = reader.string()?.to_vec();
                let path = match state.handles.get(&handle) {
                    Some(Handle::File { path }) => path.clone(),
                    _ => {
                        status(transport, channel, id, STATUS_FAILURE, "invalid handle")?;
                        continue;
                    }
                };
                if denied(options, &path) {
                    status(transport, channel, id, STATUS_PERMISSION_DENIED, "Permission denied")?;
                    continue;
                }
                if options.disk_full {
                    status(transport, channel, id, STATUS_FAILURE, "no space left on device")?;
                    continue;
                }
                {
                    let mut files = state.files();
                    let entry = files.entry(path).or_default();
                    write_at(entry, offset, &data);
                }
                state.written += data.len() as u64;
                status(transport, channel, id, STATUS_OK, "ok")?;
                if index == 0 && options.drop_after_write.is_some_and(|limit| state.written >= limit) {
                    return Err(protocol("the fixture dropped the connection on purpose"));
                }
            }
            11 => {
                let path = String::from_utf8_lossy(reader.string()?).into_owned();
                if denied(options, &path) {
                    status(transport, channel, id, STATUS_PERMISSION_DENIED, "Permission denied")?;
                    continue;
                }
                let entries = {
                    let files = state.files();
                    entries_of(&path, &files, &state.directories)
                };
                let Some(entries) = entries
                else {
                    status(transport, channel, id, STATUS_NO_SUCH_FILE, "No such file")?;
                    continue;
                };
                let handle = state.allocate(Handle::Directory { entries, drained: false });
                let mut writer = Writer::new(MSG_HANDLE);
                writer.u32(id).string(&handle);
                send_packet(transport, channel, &writer.finish())?;
            }
            12 => {
                let handle = reader.string()?.to_vec();
                let drained = match state.handles.get_mut(&handle) {
                    Some(Handle::Directory { drained, .. }) => {
                        let previous = *drained;
                        *drained = true;
                        previous
                    }
                    _ => {
                        status(transport, channel, id, STATUS_FAILURE, "invalid handle")?;
                        continue;
                    }
                };
                if drained {
                    status(transport, channel, id, STATUS_EOF, "EOF")?;
                    continue;
                }
                let entries = match state.handles.get(&handle) {
                    Some(Handle::Directory { entries, .. }) => entries.clone(),
                    _ => unreachable!("the handle was just checked"),
                };
                let mut writer = Writer::new(MSG_NAME);
                writer.u32(id).u32(entries.len() as u32);
                for (name, size, is_dir) in entries {
                    writer.string(name.as_bytes()).string(name.as_bytes());
                    write_attrs(&mut writer, size, is_dir);
                }
                send_packet(transport, channel, &writer.finish())?;
            }
            17 => {
                let path = String::from_utf8_lossy(reader.string()?).into_owned();
                if denied(options, &path) {
                    status(transport, channel, id, STATUS_PERMISSION_DENIED, "Permission denied")?;
                    continue;
                }
                let found = {
                    let files = state.files();
                    match files.get(&path) {
                        Some(data) => Some((data.len() as u64, false)),
                        None => entries_of(&path, &files, &state.directories).map(|_| (0, true)),
                    }
                };
                let Some((size, is_dir)) = found
                else {
                    status(transport, channel, id, STATUS_NO_SUCH_FILE, "No such file")?;
                    continue;
                };
                let mut writer = Writer::new(MSG_STATUS_ATTRS);
                writer.u32(id);
                write_attrs(&mut writer, size, is_dir);
                send_packet(transport, channel, &writer.finish())?;
            }
            _ => status(transport, channel, id, STATUS_OP_UNSUPPORTED, "operation unsupported")?,
        }
    }
    Ok(())
}

fn denied(options: &FixtureOptions, path: &str) -> bool {
    options.deny.contains(&path)
}

fn write_attrs(writer: &mut Writer, size: u64, is_dir: bool) {
    writer.u32(ATTR_SIZE | ATTR_PERMISSIONS).u64(size).u32(if is_dir { 0o040755 } else { 0o100644 });
}

fn write_at(target: &mut Vec<u8>, offset: u64, data: &[u8]) {
    let offset = offset as usize;
    let end = offset.saturating_add(data.len());
    if target.len() < end {
        target.resize(end, 0);
    }
    target[offset..end].copy_from_slice(data);
}

/// One directory's entries, or `None` when the directory does not exist.
fn entries_of(directory: &str, files: &BTreeMap<String, Vec<u8>>, directories: &BTreeSet<String>) -> Option<Vec<(String, u64, bool)>> {
    let base = directory.trim_end_matches('/');
    let prefix = if base.is_empty() { "/".to_string() } else { format!("{base}/") };
    let exists = base.is_empty()
        || directories.contains(base)
        || files.keys().any(|path| path.starts_with(&prefix))
        || directories.iter().any(|path| path.starts_with(&prefix));
    if !exists {
        return None;
    }
    let mut entries: BTreeMap<String, (u64, bool)> = BTreeMap::new();
    for (path, data) in files {
        if let Some(rest) = path.strip_prefix(&prefix)
            && !rest.is_empty()
        {
            let name = rest.split('/').next().unwrap_or(rest).to_string();
            let is_dir = rest.contains('/');
            entries.insert(name, (if is_dir { 0 } else { data.len() as u64 }, is_dir));
        }
    }
    for path in directories {
        if let Some(rest) = path.strip_prefix(&prefix)
            && !rest.is_empty()
        {
            entries.insert(rest.split('/').next().unwrap_or(rest).to_string(), (0, true));
        }
    }
    Some(entries.into_iter().map(|(name, (size, is_dir))| (name, size, is_dir)).collect())
}

/// Read one SFTP packet out of the channel data stream.
fn read_packet(transport: &mut Transport, inbound: &mut Vec<u8>) -> Result<Option<Vec<u8>>> {
    loop {
        if inbound.len() >= 4 {
            let length = u32::from_be_bytes([inbound[0], inbound[1], inbound[2], inbound[3]]) as usize;
            if length == 0 || length > 256 * 1024 {
                return Err(protocol("the client sent an unacceptable SFTP packet length"));
            }
            if inbound.len() >= 4 + length {
                let rest = inbound.split_off(4 + length);
                let mut packet = std::mem::replace(inbound, rest);
                packet.drain(..4);
                return Ok(Some(packet));
            }
        }
        let message = transport.receive()?;
        match message[0] {
            94 => {
                let mut reader = Reader::new(&message);
                let _ = reader.byte()?;
                let _ = reader.u32()?;
                inbound.extend_from_slice(reader.string()?);
            }
            97 => return Ok(None),
            96 | 93 => {}
            1 => return Err(protocol("the client disconnected")),
            _ => {}
        }
    }
}

/// Send one SFTP packet as channel data.
fn send_packet(transport: &mut Transport, channel: u32, payload: &[u8]) -> Result<()> {
    let mut framed = Vec::with_capacity(payload.len() + 4);
    framed.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    framed.extend_from_slice(payload);
    let mut data = Writer::new(94);
    data.u32(channel).string(&framed);
    transport.send(&data.finish())
}

fn status(transport: &mut Transport, channel: u32, id: u32, code: u32, message: &str) -> Result<()> {
    let mut writer = Writer::new(MSG_STATUS);
    writer.u32(id).u32(code).string(message.as_bytes()).string(b"");
    send_packet(transport, channel, &writer.finish())
}

fn protocol(message: &str) -> Error {
    Error::new(ErrorCode::ProtocolError, message.to_string())
}
