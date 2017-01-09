//! `ssh-ed25519` identities in the OpenSSH private key format.
//!
//! Only unencrypted `openssh-key-v1` files are admitted. Encrypted identity
//! files and foreign formats are rejected with a stable code instead of being
//! silently ignored.

use std::path::Path;

use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};

use crate::errors::{Error, ErrorCode};

use super::wire::{Reader, Writer};
use super::Result;

/// Algorithm name used in key and signature blobs.
pub const ALGORITHM: &str = "ssh-ed25519";

const BEGIN: &str = "-----BEGIN OPENSSH PRIVATE KEY-----";
const END: &str = "-----END OPENSSH PRIVATE KEY-----";
const MAGIC: &[u8] = b"openssh-key-v1\0";

/// A loaded ed25519 identity able to sign the userauth request.
pub struct Ed25519Identity {
    signing: SigningKey,
}

impl std::fmt::Debug for Ed25519Identity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_tuple("Ed25519Identity").field(&self.public_bytes()).finish()
    }
}

impl Ed25519Identity {
    /// Load an unencrypted OpenSSH ed25519 private key.
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .map_err(|error| Error::new(ErrorCode::IdentityRejected, format!("cannot read identity `{}`: {error}", path.display())))?;
        Self::parse(&text)
    }

    /// Parse an unencrypted `openssh-key-v1` document.
    pub fn parse(text: &str) -> Result<Self> {
        let body = between_markers(text)?;
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(body.as_bytes())
            .map_err(|error| Error::new(ErrorCode::IdentityRejected, format!("identity is not valid base64: {error}")))?;
        if !decoded.starts_with(MAGIC) {
            return Err(Error::new(ErrorCode::IdentityRejected, "identity is not an `openssh-key-v1` file"));
        }
        let mut reader = Reader::new(&decoded[MAGIC.len()..]);
        let cipher = reader.string()?;
        let kdf = reader.string()?;
        let _kdf_options = reader.string()?;
        let key_count = reader.u32()?;
        if cipher != b"none" || kdf != b"none" {
            return Err(Error::new(
                ErrorCode::IdentityRejected,
                "encrypted identity files are not supported, so pass an unencrypted key or use password authentication",
            ));
        }
        if key_count != 1 {
            return Err(Error::new(ErrorCode::IdentityRejected, "identity file must contain exactly one key"));
        }
        let _public = reader.string()?;
        let private = reader.string()?;
        Self::parse_private(private)
    }

    fn parse_private(section: &[u8]) -> Result<Self> {
        let mut reader = Reader::new(section);
        let check_a = reader.u32()?;
        let check_b = reader.u32()?;
        if check_a != check_b {
            return Err(Error::new(ErrorCode::IdentityRejected, "identity file failed its own integrity check"));
        }
        let algorithm = reader.string()?;
        if algorithm != ALGORITHM.as_bytes() {
            return Err(Error::new(
                ErrorCode::IdentityRejected,
                format!("identity algorithm `{}` is not supported, so use an `ssh-ed25519` key", String::from_utf8_lossy(algorithm)),
            ));
        }
        let public = reader.string()?;
        let secret = reader.string()?;
        let _comment = reader.string()?;
        if public.len() != 32 || secret.len() != 64 {
            return Err(Error::new(ErrorCode::IdentityRejected, "identity file has an unexpected key length"));
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&secret[..32]);
        let signing = SigningKey::from_bytes(&seed);
        if signing.verifying_key().to_bytes() != public {
            return Err(Error::new(ErrorCode::IdentityRejected, "identity file contains a mismatched public and private key"));
        }
        Ok(Self { signing })
    }

    /// The 32-byte public key.
    pub fn public_bytes(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    /// The public key blob used in the userauth request.
    pub fn public_blob(&self) -> Vec<u8> {
        let mut writer = Writer::empty();
        writer.string(ALGORITHM.as_bytes()).string(&self.public_bytes());
        writer.finish()
    }

    /// Sign `data` and wrap the signature in an SSH signature blob.
    pub fn signature_blob(&self, data: &[u8]) -> Vec<u8> {
        let signature = self.signing.sign(data);
        let mut writer = Writer::empty();
        writer.string(ALGORITHM.as_bytes()).string(&signature.to_bytes());
        writer.finish()
    }
}

fn between_markers(text: &str) -> Result<String> {
    let start = text
        .find(BEGIN)
        .ok_or_else(|| Error::new(ErrorCode::IdentityRejected, "identity file has no OpenSSH private key header"))?;
    let rest = &text[start + BEGIN.len()..];
    let end = rest
        .find(END)
        .ok_or_else(|| Error::new(ErrorCode::IdentityRejected, "identity file has no OpenSSH private key footer"))?;
    Ok(rest[..end].chars().filter(|character| !character.is_whitespace()).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (String, [u8; 32]) {
        let (text, public) = fixture_with(b"none", b"none");
        (text, public)
    }

    fn fixture_with(cipher: &[u8], kdf: &[u8]) -> (String, [u8; 32]) {
        let seed = [7u8; 32];
        let signing = SigningKey::from_bytes(&seed);
        let public = signing.verifying_key().to_bytes();

        let mut public_blob = Writer::empty();
        public_blob.string(ALGORITHM.as_bytes()).string(&public);

        let mut secret = Vec::with_capacity(64);
        secret.extend_from_slice(&seed);
        secret.extend_from_slice(&public);

        let mut section = Writer::empty();
        section.u32(0x1234_5678).u32(0x1234_5678);
        section.string(ALGORITHM.as_bytes()).string(&public).string(&secret).string(b"fixture");
        let mut section = section.finish();
        let mut padding = 1u8;
        while section.len() % 8 != 0 {
            section.push(padding);
            padding += 1;
        }

        let mut document = Writer::empty();
        document.string(cipher).string(kdf).string(b"").u32(1);
        document.string(&public_blob.finish()).string(&section);
        let mut encoded = MAGIC.to_vec();
        encoded.extend_from_slice(&document.finish());
        let body = base64::engine::general_purpose::STANDARD.encode(encoded);
        (format!("{BEGIN}\n{body}\n{END}\n"), public)
    }

    #[test]
    fn parses_an_unencrypted_openssh_key() {
        let (text, public) = fixture();
        let identity = Ed25519Identity::parse(&text).expect("fixture parses");
        assert_eq!(identity.public_bytes(), public);

        let blob = identity.public_blob();
        let mut reader = Reader::new(&blob);
        assert_eq!(reader.string().expect("algorithm"), ALGORITHM.as_bytes());
        assert_eq!(reader.string().expect("public"), public);

        let signature = identity.signature_blob(b"payload");
        let mut reader = Reader::new(&signature);
        assert_eq!(reader.string().expect("algorithm"), ALGORITHM.as_bytes());
        assert_eq!(reader.string().expect("signature").len(), 64);
    }

    #[test]
    fn rejects_encrypted_keys() {
        let (text, _) = fixture_with(b"aes256-ctr", b"bcrypt");
        let error = Ed25519Identity::parse(&text).expect_err("encrypted key must be rejected");
        assert_eq!(error.code(), ErrorCode::IdentityRejected);
    }

    #[test]
    fn rejects_foreign_documents() {
        let error = Ed25519Identity::parse("-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----\n")
            .expect_err("foreign document must be rejected");
        assert_eq!(error.code(), ErrorCode::IdentityRejected);
    }
}
