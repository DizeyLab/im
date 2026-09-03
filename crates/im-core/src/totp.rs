//! TOTP (RFC 6238): the second factor. HMAC-SHA1, 30-second steps, 6 digits,
//! one step of clock drift accepted in either direction.
//!
//! The secret is 160 bits; the database holds it sealed (`secret.rs`), the
//! setup page shows it base32-encoded, and authenticator apps take the
//! `otpauth://` URI from [`totp_uri`].

use crate::model::UserId;
use crate::secret;
use crate::store::{self, Result, Store, backend};
use data_encoding::BASE32_NOPAD;
use hmac::digest::KeyInit;
use hmac::{Hmac, Mac};
use sha1::Sha1;
use time::OffsetDateTime;

/// How long one step is, in seconds.
pub const STEP_SECONDS: u64 = 30;

/// A fresh 160-bit secret.
pub fn generate_secret() -> [u8; 20] {
    let mut secret = [0u8; 20];
    rand::Rng::fill_bytes(&mut rand::rng(), &mut secret);
    secret
}

/// The secret in the form authenticator apps and humans copy: base32, no
/// padding, grouped every four characters.
pub fn display_secret(secret: &[u8; 20]) -> String {
    let raw = BASE32_NOPAD.encode(secret);
    raw.as_bytes()
        .chunks(4)
        .map(|chunk| std::str::from_utf8(chunk).unwrap())
        .collect::<Vec<_>>()
        .join(" ")
}

/// The `otpauth://` URI a QR code carries.
pub fn totp_uri(issuer: &str, email: &str, secret: &[u8; 20]) -> String {
    let encoded = BASE32_NOPAD.encode(secret);
    format!(
        "otpauth://totp/{issuer}:{email}?secret={encoded}&issuer={issuer}&algorithm=SHA1&digits=6&period={STEP_SECONDS}"
    )
}

/// The 6-digit code for `secret` at instant `at`.
pub fn totp_code(secret: &[u8; 20], at: OffsetDateTime) -> String {
    code_at_step(secret, at.unix_timestamp() as u64 / STEP_SECONDS)
}

fn code_at_step(secret: &[u8; 20], step: u64) -> String {
    let mut mac =
        <Hmac<Sha1> as KeyInit>::new_from_slice(secret).expect("HMAC accepts keys of any length");
    mac.update(&step.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = (digest[19] & 0x0f) as usize;
    let binary = u32::from_be_bytes([
        digest[offset] & 0x7f,
        digest[offset + 1],
        digest[offset + 2],
        digest[offset + 3],
    ]);
    format!("{:06}", binary % 1_000_000)
}

/// Checks a user-typed code, accepting one step of drift either way. The
/// comparison runs over every candidate regardless of where the match is, so
/// the answer's timing does not narrow the search.
pub fn verify_totp(secret: &[u8; 20], code: &str, at: OffsetDateTime) -> bool {
    let step = at.unix_timestamp() as u64 / STEP_SECONDS;
    let mut found = false;
    for candidate in [step.wrapping_sub(1), step, step.wrapping_add(1)] {
        let expected = code_at_step(secret, candidate);
        found |=
            subtle::ConstantTimeEq::ct_eq(expected.as_bytes(), code.as_bytes()).unwrap_u8() == 1;
    }
    found
}

// ---------------------------------------------------------------------------
// Storage
// ---------------------------------------------------------------------------

/// Stores a freshly generated secret, sealed, unconfirmed until the user
/// proves their app agrees (`confirm_totp`).
pub async fn set_totp(store: &Store, user: &UserId, secret_bytes: &[u8; 20]) -> Result<()> {
    let sealed = secret::seal(store.key(), secret_bytes);
    store
        .conn
        .execute(
            "UPDATE users SET totp_secret = ?1, totp_confirmed = 0 WHERE id = ?2",
            turso::params![sealed, user.to_string()],
        )
        .await
        .map_err(backend)?;
    Ok(())
}

/// Marks the stored secret confirmed — called after one successful code.
pub async fn confirm_totp(store: &Store, user: &UserId) -> Result<()> {
    store
        .conn
        .execute(
            "UPDATE users SET totp_confirmed = 1 WHERE id = ?1",
            turso::params![user.to_string()],
        )
        .await
        .map_err(backend)?;
    Ok(())
}

/// The user's sealed secret, opened: `(secret, confirmed)`, or `None` when
/// TOTP was never set up. A sealed value that no longer opens (wrong key,
/// damaged ciphertext) reads as `None` — the user re-enrolls.
pub async fn totp_secret(store: &Store, user: &UserId) -> Result<Option<([u8; 20], bool)>> {
    let mut rows = store
        .conn
        .query(
            "SELECT totp_secret, totp_confirmed FROM users WHERE id = ?1",
            turso::params![user.to_string()],
        )
        .await
        .map_err(backend)?;
    let Some(row) = rows.next().await.map_err(backend)? else {
        return Ok(None);
    };
    let confirmed = store::int(&row, 1)? != 0;
    let Some(sealed) = store::opt_text(&row, 0)? else {
        return Ok(None);
    };
    let Some(bytes) = secret::open(store.key(), &sealed) else {
        return Ok(None);
    };
    let Ok(secret_bytes) = <[u8; 20]>::try_from(bytes.as_slice()) else {
        return Ok(None);
    };
    Ok(Some((secret_bytes, confirmed)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounts::{create_invite, create_user_from_invite};
    use std::path::Path;
    use time::macros::datetime;

    /// RFC 6238 Appendix B, SHA-1 test key "12345678901234567890".
    const RFC_KEY: &[u8; 20] = b"12345678901234567890";

    #[test]
    fn rfc6238_sha1_vectors() {
        // (unix time, expected 6-digit truncation of the 8-digit vector)
        let cases = [
            (59i64, "94287082"),
            (1111111109, "07081804"),
            (1111111111, "14050471"),
            (1234567890, "89005924"),
            (2000000000, "69279037"),
            (20000000000, "65353130"),
        ];
        for (at, expected8) in cases {
            let step = at as u64 / STEP_SECONDS;
            let got = code_at_step(RFC_KEY, step);
            let expected = &expected8[2..];
            assert_eq!(got, expected, "at {at}");
        }
    }

    #[test]
    fn verify_accepts_one_step_of_drift() {
        let at = datetime!(2026-09-03 12:00:00 UTC);
        let step = at.unix_timestamp() as u64 / STEP_SECONDS;
        for (delta, ok) in [(-1i64, true), (0, true), (1, true), (2, false), (-2, false)] {
            let code = code_at_step(RFC_KEY, (step as i64 + delta) as u64);
            assert_eq!(verify_totp(RFC_KEY, &code, at), ok, "delta {delta}");
        }
    }

    #[tokio::test]
    async fn store_roundtrip_and_confirm() {
        let store = Store::open(Path::new(":memory:")).await.unwrap();
        let invite = create_invite(&store, "ann@example.com", None, false)
            .await
            .unwrap();
        let user = create_user_from_invite(&store, invite.expose(), "Ann", "tDLr9!mZQ2xv")
            .await
            .unwrap();

        assert!(totp_secret(&store, &user.id).await.unwrap().is_none());
        let secret = generate_secret();
        set_totp(&store, &user.id, &secret).await.unwrap();
        let (stored, confirmed) = totp_secret(&store, &user.id).await.unwrap().unwrap();
        assert_eq!(stored, secret);
        assert!(!confirmed);
        confirm_totp(&store, &user.id).await.unwrap();
        let (_, confirmed) = totp_secret(&store, &user.id).await.unwrap().unwrap();
        assert!(confirmed);
    }
}
