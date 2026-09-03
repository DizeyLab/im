//! At-rest encryption for secrets, ported from izlek-core's `store/secret.rs`
//! (same product family, same author).
//!
//! The column holds ciphertext, and the key that opens it lives in a second
//! file (`im.key`, beside the database) that a database backup does not
//! automatically include.
//!
//! The envelope is `v1:` followed by base64 of a 24-byte XChaCha20-Poly1305
//! nonce and the sealed bytes it protects.

use std::io;
use std::path::Path;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as base64;
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use rand::Rng;

/// A key is 32 raw bytes; nothing here derives it from a password, because
/// there is no password to derive it from — it is the thing that protects
/// one.
pub const KEY_BYTES: usize = 32;
pub type Key = [u8; KEY_BYTES];

const PREFIX: &str = "v1:";
const NONCE_BYTES: usize = 24;

/// True for a value already in our envelope.
#[cfg(test)]
pub fn is_sealed(value: &str) -> bool {
    value.starts_with(PREFIX)
}

/// Encrypts `plaintext` under `key`, returning the envelope ready to store.
///
/// A fresh random nonce is drawn every call, so sealing the same secret twice
/// gives two different strings. XChaCha20-Poly1305's 24-byte nonce is wide
/// enough that "draw at random and never track reuse" is safe for the volume
/// of writes an SSO produces.
pub fn seal(key: &Key, plaintext: &[u8]) -> String {
    let cipher = XChaCha20Poly1305::new(key.into());
    let mut nonce_bytes = [0u8; NONCE_BYTES];
    rand::rng().fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .expect("XChaCha20-Poly1305 cannot fail to encrypt a plaintext this small");
    let mut payload = Vec::with_capacity(NONCE_BYTES + ciphertext.len());
    payload.extend_from_slice(&nonce_bytes);
    payload.extend_from_slice(&ciphertext);
    format!("{PREFIX}{}", base64.encode(payload))
}

/// Reverses [`seal`]. `None` covers every way this can fail to come back —
/// not our prefix, not valid base64, too short to hold a nonce, wrong key,
/// or a tampered/truncated ciphertext that fails the Poly1305 tag check.
pub fn open(key: &Key, sealed: &str) -> Option<Vec<u8>> {
    let body = sealed.strip_prefix(PREFIX)?;
    let payload = base64.decode(body).ok()?;
    if payload.len() < NONCE_BYTES {
        return None;
    }
    let (nonce_bytes, ciphertext) = payload.split_at(NONCE_BYTES);
    let cipher = XChaCha20Poly1305::new(key.into());
    let nonce = XNonce::from_slice(nonce_bytes);
    cipher.decrypt(nonce, ciphertext).ok()
}

/// Reads the key at `path`, generating and writing a fresh one (mode 0600,
/// where the platform has modes) if the file is not there yet.
///
/// Called once, at [`crate::store::Store::open`] — the key is loaded, not
/// re-read per query, so a corrupted key file is a boot-time failure, not a
/// per-request one.
pub fn load_or_create_key(path: &Path) -> io::Result<Key> {
    match std::fs::read(path) {
        Ok(bytes) => {
            let key: Key = bytes.try_into().map_err(|bytes: Vec<u8>| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "{} holds {} bytes, not the {KEY_BYTES} of a key",
                        path.display(),
                        bytes.len()
                    ),
                )
            })?;
            Ok(key)
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let mut key = [0u8; KEY_BYTES];
            rand::rng().fill_bytes(&mut key);
            std::fs::write(path, key)?;
            restrict(path)?;
            Ok(key)
        }
        Err(e) => Err(e),
    }
}

/// Best-effort 0600; platforms without modes simply skip the call.
#[cfg(unix)]
fn restrict(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn restrict(_path: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_roundtrip() {
        let key = [7u8; KEY_BYTES];
        let sealed = seal(&key, b"a totp secret");
        assert!(is_sealed(&sealed));
        assert_eq!(
            open(&key, &sealed).as_deref(),
            Some(b"a totp secret".as_slice())
        );
    }

    #[test]
    fn seal_is_randomized() {
        let key = [7u8; KEY_BYTES];
        assert_ne!(seal(&key, b"same"), seal(&key, b"same"));
    }

    #[test]
    fn open_rejects_garbage() {
        let key = [7u8; KEY_BYTES];
        assert_eq!(open(&key, "plaintext"), None);
        assert_eq!(open(&key, "v1:not-base64!!!"), None);
        assert_eq!(open(&key, "v1:c2hvcnQ"), None);
        let wrong = [8u8; KEY_BYTES];
        assert_eq!(open(&wrong, &seal(&key, b"x")), None);
    }

    #[test]
    fn key_file_is_stable_across_opens() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("im.key");
        let first = load_or_create_key(&path).unwrap();
        let second = load_or_create_key(&path).unwrap();
        assert_eq!(first, second, "a second open reuses the same key");
    }
}
