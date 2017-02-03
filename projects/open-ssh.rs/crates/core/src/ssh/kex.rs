//! Key exchange for `curve25519-sha256` with an `ssh-ed25519` host key.
//!
//! RFC 4253 framing, RFC 8731 key exchange, and RFC 4253 section 7.2 key
//! derivation are implemented here. Curve arithmetic and signature primitives
//! come from audited crates.

use base64::Engine;
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::errors::{Error, ErrorCode};

use super::{
    Result,
    transport::{AesGcmState, Transport},
    wire::{Reader, Writer, encode_mpint},
};

/// Message numbers used during key exchange.
const MSG_DISCONNECT: u8 = 1;
const MSG_IGNORE: u8 = 2;
const MSG_DEBUG: u8 = 4;
const MSG_KEXINIT: u8 = 20;
const MSG_NEWKEYS: u8 = 21;
const MSG_KEX_ECDH_INIT: u8 = 30;
const MSG_KEX_ECDH_REPLY: u8 = 31;
const MSG_EXT_INFO: u8 = 7;

/// Admitted algorithm names. Every list has exactly one entry so negotiation
/// is a presence check instead of a preference guess.
pub(crate) const KEX_ALGORITHM: &str = "curve25519-sha256";
pub(crate) const HOST_KEY_ALGORITHM: &str = "ssh-ed25519";
pub(crate) const CIPHER: &str = "aes256-gcm@openssh.com";
pub(crate) const MAC: &str = "hmac-sha2-256";
const COMPRESSION: &str = "none";

/// Result of a completed first key exchange.
pub struct Handshake {
    /// `SHA256:` fingerprint of the host key blob.
    pub fingerprint: String,
}

/// Run the first key exchange and activate encryption in both directions.
pub fn handshake(transport: &mut Transport) -> Result<Handshake> {
    let client_kexinit = client_kexinit()?;
    transport.send(&client_kexinit)?;
    let server_kexinit = loop {
        let payload = transport.receive()?;
        match payload[0] {
            MSG_KEXINIT => break payload,
            MSG_IGNORE | MSG_DEBUG => continue,
            MSG_DISCONNECT => return Err(disconnected(&payload)),
            other => return Err(unexpected(other, "KEXINIT")),
        }
    };
    transport.remember_kexinit(client_kexinit, server_kexinit.clone());

    let offered = Offered::parse(&server_kexinit)?;
    offered.require()?;
    if offered.first_kex_packet_follows
        && (offered.first_kex.as_deref() != Some(KEX_ALGORITHM) || offered.first_host_key.as_deref() != Some(HOST_KEY_ALGORITHM))
    {
        // The server guessed a different algorithm, so its next packet is the
        // guess and must be discarded before the real exchange starts.
        let _ = transport.receive()?;
    }

    let secret = ephemeral_secret()?;
    let client_public = PublicKey::from(&secret);
    let mut init = Writer::new(MSG_KEX_ECDH_INIT);
    init.string(client_public.as_bytes());
    transport.send(&init.finish())?;

    let reply = loop {
        let payload = transport.receive()?;
        match payload[0] {
            MSG_KEX_ECDH_REPLY => break payload,
            MSG_IGNORE | MSG_DEBUG => continue,
            MSG_DISCONNECT => return Err(disconnected(&payload)),
            other => return Err(unexpected(other, "KEX_ECDH_REPLY")),
        }
    };
    let mut reader = Reader::new(&reply);
    let _ = reader.byte()?;
    let host_key = reader.string()?.to_vec();
    let server_public = reader.string()?;
    let signature = reader.string()?;
    if server_public.len() != 32 {
        return Err(Error::new(ErrorCode::ProtocolError, "server ephemeral public key has the wrong length"));
    }
    let mut server_public_bytes = [0u8; 32];
    server_public_bytes.copy_from_slice(server_public);

    let shared = secret.diffie_hellman(&PublicKey::from(server_public_bytes));
    let shared_mpint = shared_secret_mpint(&shared.to_bytes());

    let exchange_hash = exchange_hash(transport, &host_key, client_public.as_bytes(), &server_public_bytes, &shared_mpint)?;
    verify_signature(&host_key, signature, &exchange_hash)?;

    let session_id = exchange_hash.clone();
    transport.set_session_id(session_id.clone());
    let outbound_key = derive(b'C', &shared_mpint, &exchange_hash, &session_id, 32)?;
    let outbound_iv = derive(b'A', &shared_mpint, &exchange_hash, &session_id, 12)?;
    let inbound_key = derive(b'D', &shared_mpint, &exchange_hash, &session_id, 32)?;
    let inbound_iv = derive(b'B', &shared_mpint, &exchange_hash, &session_id, 12)?;

    transport.send(&Writer::new(MSG_NEWKEYS).finish())?;
    transport.install_outbound(AesGcmState::new(&outbound_key, &outbound_iv)?);
    loop {
        let payload = transport.receive()?;
        match payload[0] {
            MSG_NEWKEYS => break,
            MSG_EXT_INFO | MSG_IGNORE | MSG_DEBUG => continue,
            MSG_DISCONNECT => return Err(disconnected(&payload)),
            other => return Err(unexpected(other, "NEWKEYS")),
        }
    }
    transport.install_inbound(AesGcmState::new(&inbound_key, &inbound_iv)?);

    let fingerprint = fingerprint_of(&host_key);
    Ok(Handshake { fingerprint })
}

fn client_kexinit() -> Result<Vec<u8>> {
    let mut cookie = [0u8; 16];
    getrandom::fill(&mut cookie).map_err(|error| Error::new(ErrorCode::Internal, format!("cannot obtain a KEXINIT cookie: {error}")))?;
    let mut writer = Writer::new(MSG_KEXINIT);
    for byte in cookie {
        writer.byte(byte);
    }
    writer
        .name_list(&[KEX_ALGORITHM])
        .name_list(&[HOST_KEY_ALGORITHM])
        .name_list(&[CIPHER])
        .name_list(&[CIPHER])
        .name_list(&[MAC])
        .name_list(&[MAC])
        .name_list(&[COMPRESSION])
        .name_list(&[COMPRESSION])
        .name_list(&[])
        .name_list(&[])
        .boolean(false)
        .u32(0);
    Ok(writer.finish())
}

/// The subset of a peer KEXINIT this client needs.
struct Offered {
    kex: Vec<String>,
    host_key: Vec<String>,
    cipher_client_to_server: Vec<String>,
    cipher_server_to_client: Vec<String>,
    compression_client_to_server: Vec<String>,
    compression_server_to_client: Vec<String>,
    first_kex_packet_follows: bool,
    first_kex: Option<String>,
    first_host_key: Option<String>,
}

impl Offered {
    fn parse(payload: &[u8]) -> Result<Self> {
        let mut reader = Reader::new(payload);
        let _ = reader.byte()?;
        for _ in 0..16 {
            let _ = reader.byte()?;
        }
        let owned = |names: Vec<&str>| names.into_iter().map(str::to_string).collect::<Vec<_>>();
        let kex = owned(reader.name_list()?);
        let host_key = owned(reader.name_list()?);
        let cipher_client_to_server = owned(reader.name_list()?);
        let cipher_server_to_client = owned(reader.name_list()?);
        let _mac_client_to_server = reader.name_list()?;
        let _mac_server_to_client = reader.name_list()?;
        let compression_client_to_server = owned(reader.name_list()?);
        let compression_server_to_client = owned(reader.name_list()?);
        let _language_client_to_server = reader.name_list()?;
        let _language_server_to_client = reader.name_list()?;
        let first_kex_packet_follows = reader.boolean()?;
        let _reserved = reader.u32()?;
        Ok(Self {
            first_kex: kex.first().cloned(),
            first_host_key: host_key.first().cloned(),
            kex,
            host_key,
            cipher_client_to_server,
            cipher_server_to_client,
            compression_client_to_server,
            compression_server_to_client,
            first_kex_packet_follows,
        })
    }

    fn require(&self) -> Result<()> {
        require_list("key exchange", &self.kex, KEX_ALGORITHM)?;
        require_list("host key", &self.host_key, HOST_KEY_ALGORITHM)?;
        require_list("client to server cipher", &self.cipher_client_to_server, CIPHER)?;
        require_list("server to client cipher", &self.cipher_server_to_client, CIPHER)?;
        require_list("client to server compression", &self.compression_client_to_server, COMPRESSION)?;
        require_list("server to client compression", &self.compression_server_to_client, COMPRESSION)?;
        Ok(())
    }
}

fn require_list(category: &str, offered: &[String], required: &str) -> Result<()> {
    if offered.iter().any(|name| name == required) {
        return Ok(());
    }
    Err(Error::new(ErrorCode::NegotiationFailed, format!("the server offers no admitted {category} algorithm, so `{required}` cannot be used")))
}

fn ephemeral_secret() -> Result<StaticSecret> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|error| Error::new(ErrorCode::Internal, format!("cannot obtain an ephemeral key: {error}")))?;
    Ok(StaticSecret::from(bytes))
}

/// Encode the raw X25519 output as the SSH `mpint` `K`.
///
/// RFC 8731 section 3.1 reinterprets the 32 byte output as a fixed length
/// unsigned big endian integer before `mpint` encoding. Only the X25519
/// multiplication itself is little endian, so no byte order flip happens here.
pub(crate) fn shared_secret_mpint(raw: &[u8; 32]) -> Vec<u8> {
    encode_mpint(raw)
}

/// The inputs of `H = SHA256(V_C || V_S || I_C || I_S || K_S || e || f || K)`.
pub(crate) struct ExchangeHashInputs<'a> {
    pub(crate) client_version: &'a [u8],
    pub(crate) server_version: &'a [u8],
    pub(crate) client_kexinit: &'a [u8],
    pub(crate) server_kexinit: &'a [u8],
    pub(crate) host_key: &'a [u8],
    pub(crate) client_public: &'a [u8],
    pub(crate) server_public: &'a [u8],
    pub(crate) shared_mpint: &'a [u8],
}

pub(crate) fn exchange_hash(
    transport: &Transport,
    host_key: &[u8],
    client_public: &[u8],
    server_public: &[u8],
    shared_mpint: &[u8],
) -> Result<Vec<u8>> {
    Ok(exchange_hash_of(&ExchangeHashInputs {
        client_version: transport.client_version().as_bytes(),
        server_version: transport.server_version().as_bytes(),
        client_kexinit: transport.client_kexinit(),
        server_kexinit: transport.server_kexinit(),
        host_key,
        client_public,
        server_public,
        shared_mpint,
    }))
}

/// `H` from inputs that were separated from a live transport.
pub(crate) fn exchange_hash_of(inputs: &ExchangeHashInputs<'_>) -> Vec<u8> {
    let mut hasher = Sha256::new();
    put_string(&mut hasher, inputs.client_version);
    put_string(&mut hasher, inputs.server_version);
    put_string(&mut hasher, inputs.client_kexinit);
    put_string(&mut hasher, inputs.server_kexinit);
    put_string(&mut hasher, inputs.host_key);
    put_string(&mut hasher, inputs.client_public);
    put_string(&mut hasher, inputs.server_public);
    put_string(&mut hasher, inputs.shared_mpint);
    hasher.finalize().to_vec()
}

fn put_string(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u32).to_be_bytes());
    hasher.update(bytes);
}

fn verify_signature(host_key: &[u8], signature: &[u8], exchange_hash: &[u8]) -> Result<()> {
    let mut key_reader = Reader::new(host_key);
    let algorithm = key_reader.string()?;
    if algorithm != HOST_KEY_ALGORITHM.as_bytes() {
        return Err(Error::new(
            ErrorCode::NegotiationFailed,
            format!("the server host key uses `{}`, which this client does not admit", String::from_utf8_lossy(algorithm)),
        ));
    }
    let key_bytes = key_reader.string()?;
    let key_array: [u8; 32] =
        key_bytes.try_into().map_err(|_| Error::new(ErrorCode::ProtocolError, "the server host key has the wrong length"))?;
    let verifying = VerifyingKey::from_bytes(&key_array)
        .map_err(|_| Error::new(ErrorCode::ProtocolError, "the server host key is not a valid ed25519 point"))?;

    let mut signature_reader = Reader::new(signature);
    let signature_algorithm = signature_reader.string()?;
    if signature_algorithm != HOST_KEY_ALGORITHM.as_bytes() {
        return Err(Error::new(ErrorCode::NegotiationFailed, "the exchange hash is not signed with the negotiated host key algorithm"));
    }
    let signature_bytes = signature_reader.string()?;
    let signature_array: [u8; 64] =
        signature_bytes.try_into().map_err(|_| Error::new(ErrorCode::ProtocolError, "the exchange hash signature has the wrong length"))?;
    let signature = Signature::from_bytes(&signature_array);
    verifying
        .verify_strict(exchange_hash, &signature)
        .map_err(|_| Error::new(ErrorCode::ProtocolError, "the exchange hash signature does not verify against the host key"))
}

pub(crate) fn derive(letter: u8, shared_mpint: &[u8], exchange_hash: &[u8], session_id: &[u8], len: usize) -> Result<Vec<u8>> {
    if len > 32 {
        return Err(Error::new(ErrorCode::Internal, "key derivation beyond one SHA-256 block is not implemented"));
    }
    let mut hasher = Sha256::new();
    put_string(&mut hasher, shared_mpint);
    hasher.update(exchange_hash);
    hasher.update([letter]);
    hasher.update(session_id);
    let digest = hasher.finalize();
    Ok(digest[..len].to_vec())
}

/// `SHA256:` fingerprint of a host key blob, matching OpenSSH notation.
pub fn fingerprint_of(host_key: &[u8]) -> String {
    let digest = Sha256::digest(host_key);
    format!("SHA256:{}", base64::engine::general_purpose::STANDARD_NO_PAD.encode(digest))
}

fn disconnected(payload: &[u8]) -> Error {
    let mut reader = Reader::new(payload);
    let _ = reader.byte();
    let reason = reader.u32().unwrap_or(0);
    let description = reader.string().map(|bytes| String::from_utf8_lossy(bytes).into_owned()).unwrap_or_default();
    Error::new(ErrorCode::ProtocolError, format!("the server disconnected during key exchange (reason {reason}): {description}"))
}

fn unexpected(message: u8, expected: &str) -> Error {
    Error::new(ErrorCode::ProtocolError, format!("expected `{expected}` but the server sent SSH message {message}"))
}

#[cfg(test)]
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod trace {
    use std::time::Duration;

    use super::*;

    fn env(name: &str) -> Option<String> {
        std::env::var(name).ok().map(|value| value.trim().to_string()).filter(|value| !value.is_empty())
    }

    fn report(label: &str, bytes: &[u8]) {
        println!("{label} len={} hex={}", bytes.len(), hex(bytes));
    }

    fn expect_message(transport: &mut Transport, expected: u8, name: &str) -> Result<Vec<u8>> {
        loop {
            let payload = transport.receive()?;
            match payload[0] {
                value if value == expected => return Ok(payload),
                MSG_IGNORE | MSG_DEBUG => continue,
                MSG_DISCONNECT => return Err(disconnected(&payload)),
                other => return Err(unexpected(other, name)),
            }
        }
    }

    /// Dump the eight exchange hash inputs, `H`, and the signature verdict for
    /// one real server. Test-only: nothing here is compiled into a release.
    ///
    /// ```text
    /// OPEN_SSH_KEX_TRACE_HOST=... OPEN_SSH_KEX_TRACE_PORT=22 \
    /// OPEN_SSH_KEX_TRACE_PIN=SHA256:... \
    ///   cargo test -p open-ssh-core --lib ssh::kex::trace -- --ignored --nocapture
    /// ```
    #[test]
    #[ignore = "requires a reachable SSH server in the `OPEN_SSH_KEX_TRACE_*` variables"]
    fn dump_key_exchange_inputs() {
        let Some(host) = env("OPEN_SSH_KEX_TRACE_HOST")
        else {
            eprintln!("no `OPEN_SSH_KEX_TRACE_HOST` is set, so there is nothing to trace");
            return;
        };
        let port = env("OPEN_SSH_KEX_TRACE_PORT").map_or(22, |value| value.parse::<u16>().expect("`OPEN_SSH_KEX_TRACE_PORT` must be a port"));
        let pin = env("OPEN_SSH_KEX_TRACE_PIN");

        let mut transport = Transport::connect(&host, port, Duration::from_secs(30)).expect("connect");
        transport.exchange_versions().expect("version exchange");

        let client_kexinit = client_kexinit().expect("client KEXINIT");
        transport.send(&client_kexinit).expect("send KEXINIT");
        let server_kexinit = expect_message(&mut transport, MSG_KEXINIT, "KEXINIT").expect("receive KEXINIT");
        transport.remember_kexinit(client_kexinit, server_kexinit.clone());
        let offered = Offered::parse(&server_kexinit).expect("parse KEXINIT");
        offered.require().expect("negotiate");
        if offered.first_kex_packet_follows
            && (offered.first_kex.as_deref() != Some(KEX_ALGORITHM) || offered.first_host_key.as_deref() != Some(HOST_KEY_ALGORITHM))
        {
            let _ = transport.receive().expect("discard the guessed packet");
        }

        let secret = ephemeral_secret().expect("ephemeral secret");
        let client_public = PublicKey::from(&secret);
        let mut init = Writer::new(MSG_KEX_ECDH_INIT);
        init.string(client_public.as_bytes());
        transport.send(&init.finish()).expect("send KEX_ECDH_INIT");

        let reply = expect_message(&mut transport, MSG_KEX_ECDH_REPLY, "KEX_ECDH_REPLY").expect("receive KEX_ECDH_REPLY");
        let mut reader = Reader::new(&reply);
        let _ = reader.byte().expect("message number");
        let host_key = reader.string().expect("host key").to_vec();
        let server_public = reader.string().expect("server public key").to_vec();
        let signature = reader.string().expect("signature").to_vec();
        let server_public_bytes: [u8; 32] = server_public.as_slice().try_into().expect("32 byte server public key");

        let shared = secret.diffie_hellman(&PublicKey::from(server_public_bytes)).to_bytes();
        let shared_mpint = shared_secret_mpint(&shared);
        let hash = exchange_hash(&transport, &host_key, client_public.as_bytes(), &server_public_bytes, &shared_mpint).expect("exchange hash");

        println!("target host fingerprint {}", fingerprint_of(&host_key));
        if let Some(expected) = pin {
            assert_eq!(fingerprint_of(&host_key), expected, "the server does not present the pinned host key");
        }
        report("V_C", transport.client_version().as_bytes());
        report("V_S", transport.server_version().as_bytes());
        report("I_C", transport.client_kexinit());
        report("I_S", transport.server_kexinit());
        report("K_S", &host_key);
        report("e", client_public.as_bytes());
        report("f", &server_public);
        report("shared_raw", &shared);
        report("K", &shared_mpint);
        report("signature", &signature);
        report("H", &hash);
        match verify_signature(&host_key, &signature, &hash) {
            Ok(()) => println!("signature verification: OK"),
            Err(error) => println!("signature verification: FAILED ({}: {})", error.code(), error.message()),
        }
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey};

    use super::*;

    // Synthetic exchange material. None of it comes from a deployed server, and
    // `K` and `H` were derived independently from the RFC 4253 section 8
    // ordering, so the vector freezes the byte layout instead of agreeing with
    // our own encoder by construction.
    const V_C: &str = "SSH-2.0-ExampleClient_1.0";
    const V_S: &str = "SSH-2.0-ExampleServer_1.0";
    const I_C: &str = "1400112233445566778899aabbccddeeff00000000";
    const I_S: &str = "14ffeeddccbbaa9988776655443322110000000000";
    const K_S: &str = "0000000b7373682d65643235353139000000201111111111111111111111111111111111111111111111111111111111111111";
    const E: &str = "2222222222222222222222222222222222222222222222222222222222222222";
    const F: &str = "3333333333333333333333333333333333333333333333333333333333333333";
    // Two leading zero bytes followed by a byte below `0x80`, so both the
    // leading-zero strip and the missing sign byte are exercised.
    const SHARED_RAW: &str = "00007f0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d";
    const K: &str = "7f0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d";
    const H: &str = "0b246bda7fd24f66062df0619ba66c6091e448367b8e4ea89a14831705aa7d87";

    fn unhex(value: &str) -> Vec<u8> {
        assert!(value.len().is_multiple_of(2), "hex input must have an even length");
        (0..value.len()).step_by(2).map(|index| u8::from_str_radix(&value[index..index + 2], 16).expect("hex pair")).collect()
    }

    fn synthetic_exchange() -> Vec<u8> {
        let shared: [u8; 32] = unhex(SHARED_RAW).try_into().expect("the shared secret is 32 bytes");
        let shared_mpint = shared_secret_mpint(&shared);
        let host_key = unhex(K_S);
        let client_kexinit = unhex(I_C);
        let server_kexinit = unhex(I_S);
        let client_public = unhex(E);
        let server_public = unhex(F);
        exchange_hash_of(&ExchangeHashInputs {
            client_version: V_C.as_bytes(),
            server_version: V_S.as_bytes(),
            client_kexinit: &client_kexinit,
            server_kexinit: &server_kexinit,
            host_key: &host_key,
            client_public: &client_public,
            server_public: &server_public,
            shared_mpint: &shared_mpint,
        })
    }

    #[test]
    fn the_exchange_hash_follows_the_rfc_ordering() {
        let shared: [u8; 32] = unhex(SHARED_RAW).try_into().expect("the shared secret is 32 bytes");
        let shared_mpint = shared_secret_mpint(&shared);
        assert_eq!(hex(&shared_mpint), K, "`K` reinterprets the X25519 output as a big endian integer");

        let exchange = synthetic_exchange();
        assert_eq!(hex(&exchange), H, "the exchange hash must follow the RFC 4253 section 8 ordering");
    }

    #[test]
    fn a_host_signature_over_the_exchange_hash_verifies() {
        let exchange = synthetic_exchange();
        let key = SigningKey::from_bytes(&[42u8; 32]);
        let mut blob = Writer::empty();
        blob.string(HOST_KEY_ALGORITHM.as_bytes()).string(&key.verifying_key().to_bytes());
        let mut signature = Writer::empty();
        signature.string(HOST_KEY_ALGORITHM.as_bytes()).string(&key.sign(&exchange).to_bytes());

        verify_signature(&blob.finish(), &signature.finish(), &exchange).expect("the signature must cover the exchange hash");
    }
}
