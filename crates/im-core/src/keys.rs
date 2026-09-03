//! JWT signing keys: RSA-2048 pairs generated on first boot, sealed at rest,
//! published as a JWKS.
//!
//! The private half never leaves this module unsealed: the database holds the
//! XChaCha20-Poly1305 envelope of its PKCS#8 DER under `im.key`, and only
//! `active_signing_key` (signing) and `jwks` (the public half) cross the
//! boundary.
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey};
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use sha2::Digest;

use crate::accounts::hex;
use crate::secret;
use crate::store::{self, Result, Store, StoreError, backend};

/// The active signing key, generating and storing one on first boot.
///
/// `kid` is a fingerprint of the public half, so a key's id is stable across
/// restarts and a JWKS consumer can match header to key without guessing.
pub async fn active_signing_key(store: &Store) -> Result<(String, RsaPrivateKey)> {
    let conn = store.conn.lock().await;
    let mut rows = conn
        .query(
            "SELECT kid, private_der_enc FROM signing_keys WHERE active = 1 \
             ORDER BY created_at DESC LIMIT 1",
            (),
        )
        .await
        .map_err(backend)?;
    if let Some(row) = rows.next().await.map_err(backend)? {
        let kid = store::text(&row, 0)?;
        let sealed = store::text(&row, 1)?;
        let der = secret::open(store.key(), &sealed)
            .ok_or_else(|| StoreError::Corrupt("signing key does not open".into()))?;
        let key = RsaPrivateKey::from_pkcs8_der(&der)
            .map_err(|e| StoreError::Corrupt(format!("signing key: {e}")))?;
        return Ok((kid, key));
    }

    let mut rng = rand_core::OsRng;
    let key = RsaPrivateKey::new(&mut rng, 2048)
        .map_err(|e| StoreError::Backend(format!("key generation: {e}")))?;
    let public_der = key
        .to_public_key()
        .to_public_key_der()
        .map_err(|e| StoreError::Backend(format!("public der: {e}")))?
        .as_bytes()
        .to_vec();
    let private_der = key
        .to_pkcs8_der()
        .map_err(|e| StoreError::Backend(format!("private der: {e}")))?
        .as_bytes()
        .to_vec();
    let kid = kid_of(&public_der);
    conn.execute(
        "INSERT INTO signing_keys (kid, private_der_enc, public_der, created_at) \
             VALUES (?1, ?2, ?3, ?4)",
        turso::params![
            kid.clone(),
            secret::seal(store.key(), &private_der),
            public_der,
            store::stamp(store::now())?,
        ],
    )
    .await
    .map_err(backend)?;
    Ok((kid, key))
}

/// A key id: the first 16 hex of the public half's SHA-256.
fn kid_of(public_der: &[u8]) -> String {
    hex(&sha2::Sha256::digest(public_der))[..16].to_string()
}

/// Every active public key as a JWKS document.
pub async fn jwks(store: &Store) -> Result<serde_json::Value> {
    let conn = store.conn.lock().await;
    use base64::Engine;
    let mut rows = conn
        .query(
            "SELECT kid, public_der FROM signing_keys WHERE active = 1 ORDER BY created_at",
            (),
        )
        .await
        .map_err(backend)?;
    let mut keys = Vec::new();
    while let Some(row) = rows.next().await.map_err(backend)? {
        let kid = store::text(&row, 0)?;
        let der = row.get::<Vec<u8>>(1).map_err(backend)?;
        let public = RsaPublicKey::from_public_key_der(&der)
            .map_err(|e| StoreError::Corrupt(format!("public key {kid}: {e}")))?;
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        keys.push(serde_json::json!({
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": kid,
            "n": b64.encode(public.n().to_bytes_be()),
            "e": b64.encode(public.e().to_bytes_be()),
        }));
    }
    Ok(serde_json::json!({ "keys": keys }))
}

/// The public half of an active key, by id — what JWT verification looks up.
pub async fn public_key_by_kid(store: &Store, kid: &str) -> Result<Option<RsaPublicKey>> {
    let conn = store.conn.lock().await;
    let mut rows = conn
        .query(
            "SELECT public_der FROM signing_keys WHERE kid = ?1 AND active = 1",
            turso::params![kid],
        )
        .await
        .map_err(backend)?;
    let Some(row) = rows.next().await.map_err(backend)? else {
        return Ok(None);
    };
    let der = row.get::<Vec<u8>>(0).map_err(backend)?;
    RsaPublicKey::from_public_key_der(&der)
        .map(Some)
        .map_err(|e| StoreError::Corrupt(format!("public key {kid}: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn key_is_generated_once_and_reopened() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("im.db");
        let (kid, first) = {
            let store = Store::open(&path).await.unwrap();
            let (kid, key) = active_signing_key(&store).await.unwrap();
            // A second ask returns the same key rather than generating.
            let (kid2, _) = active_signing_key(&store).await.unwrap();
            assert_eq!(kid, kid2);
            (kid, key)
        };
        // A fresh store over the same database + im.key opens the same key.
        let store = Store::open(&path).await.unwrap();
        let (kid2, second) = active_signing_key(&store).await.unwrap();
        assert_eq!(kid, kid2);
        assert_eq!(first.to_public_key(), second.to_public_key());

        let doc = jwks(&store).await.unwrap();
        let keys = doc["keys"].as_array().unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0]["kid"].as_str().unwrap(), kid);
        assert_eq!(keys[0]["kty"], "RSA");
        assert_eq!(keys[0]["alg"], "RS256");
    }
}
