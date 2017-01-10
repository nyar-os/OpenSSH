//! Loopback SSH server used to verify the client end to end.
//!
//! This is test-only infrastructure. It implements just enough of the server
//! side of the same protocol to exercise the real socket path, key exchange,
//! both authentication methods, and one `exec` channel. It is never compiled
//! into a released build.

use std::{
    net::{SocketAddr, TcpListener, TcpStream},
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

/// Authentication the fixture server accepts.
pub(crate) enum FixtureAuth {
    Password(&'static str),
    PublicKey,
}

/// One loopback server configuration and the material the client needs.
pub(crate) struct Fixture {
    pub(crate) addr: SocketAddr,
    pub(crate) pin: String,
    pub(crate) stdout: &'static str,
    pub(crate) stderr: &'static str,
    pub(crate) exit_status: u32,
    server: JoinHandle<()>,
}

impl Fixture {
    /// Bind a loopback listener and serve exactly one connection.
    pub(crate) fn start(auth: FixtureAuth, client_key: SigningKey) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind loopback");
        let addr = listener.local_addr().expect("local address");
        let host_key = SigningKey::from_bytes(&[9u8; 32]);
        let stdout = "hello from the fixture\n";
        let stderr = "warning from the fixture\n";
        let exit_status = 7;
        let pin = fingerprint_of(&host_key_blob(&host_key));
        let server = thread::spawn(move || {
            if let Ok((stream, _)) = listener.accept() {
                let _ = serve(stream, &host_key, auth, &client_key, stdout, stderr, exit_status);
            }
        });
        Self { addr, pin, stdout, stderr, exit_status, server }
    }

    /// Wait for the fixture thread to finish.
    pub(crate) fn wait(self) {
        let _ = self.server.join();
    }
}

fn serve(
    stream: TcpStream,
    host_key: &SigningKey,
    auth: FixtureAuth,
    client_key: &SigningKey,
    stdout: &str,
    stderr: &str,
    exit_status: u32,
) -> Result<()> {
    let mut transport = Transport::accept(stream, TIMEOUT);
    transport.exchange_versions_as_server()?;
    handshake(&mut transport, host_key)?;
    service_request(&mut transport)?;
    authenticate(&mut transport, auth, client_key)?;
    let channel = open_channel(&mut transport)?;
    run_exec(&mut transport, channel, stdout, stderr, exit_status)?;
    drain(&mut transport)
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

fn authenticate(transport: &mut Transport, auth: FixtureAuth, client_key: &SigningKey) -> Result<()> {
    let message = transport.receive()?;
    let mut reader = Reader::new(&message);
    if reader.byte()? != 50 {
        return Err(protocol("the client did not start user authentication"));
    }
    let _user = reader.string()?;
    let _service = reader.string()?;
    let method = reader.string()?.to_vec();
    let accepted = match (&auth, method.as_slice()) {
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

fn open_channel(transport: &mut Transport) -> Result<u32> {
    let message = transport.receive()?;
    let mut reader = Reader::new(&message);
    if reader.byte()? != 90 {
        return Err(protocol("the client did not open a channel"));
    }
    let _kind = reader.string()?;
    let sender = reader.u32()?;
    let mut confirmation = Writer::new(91);
    confirmation.u32(sender).u32(0).u32(WINDOW).u32(MAX_PACKET);
    transport.send(&confirmation.finish())?;

    let request = transport.receive()?;
    let mut reader = Reader::new(&request);
    if reader.byte()? != 98 {
        return Err(protocol("the client did not send a channel request"));
    }
    let recipient = reader.u32()?;
    let kind = reader.string()?.to_vec();
    let want_reply = reader.boolean()?;
    if kind != b"exec" {
        return Err(protocol("the fixture only serves `exec`"));
    }
    if want_reply {
        let mut success = Writer::new(99);
        success.u32(recipient);
        transport.send(&success.finish())?;
    }
    Ok(recipient)
}

fn run_exec(transport: &mut Transport, channel: u32, stdout: &str, stderr: &str, exit_status: u32) -> Result<()> {
    let mut data = Writer::new(94);
    data.u32(channel).string(stdout.as_bytes());
    transport.send(&data.finish())?;

    let mut extended = Writer::new(95);
    extended.u32(channel).u32(1).string(stderr.as_bytes());
    transport.send(&extended.finish())?;

    let mut status = Writer::new(98);
    status.u32(channel).string(b"exit-status").boolean(false).u32(exit_status);
    transport.send(&status.finish())?;

    let mut eof = Writer::new(96);
    eof.u32(channel);
    transport.send(&eof.finish())?;

    let mut close = Writer::new(97);
    close.u32(channel);
    transport.send(&close.finish())
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

fn protocol(message: &str) -> Error {
    Error::new(ErrorCode::ProtocolError, message.to_string())
}
