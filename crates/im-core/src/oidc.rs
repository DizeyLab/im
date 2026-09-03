//! The OIDC provider half: relying-party registration, authorization codes,
//! refresh tokens, and the hand-rolled RS256 JWT the endpoints mint.
//!
//! JWT is hand-rolled on purpose: both ends of the wire are ours, the format
//! is `base64url(header).base64url(payload).base64url(signature)` and nothing
//! more, and a third crate in the trust path buys nothing.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as b64url;
use rsa::RsaPrivateKey;
use rsa::signature::{SignatureEncoding, Signer};

use crate::accounts::{Token, digests_match, hash_token};
use crate::model::{AuthCode, ClientId, OidcClient, RefreshToken, UserId};
use crate::store::{self, Result, Store, StoreError, backend};

/// How long an authorization code lives, in seconds.
pub const CODE_SECONDS: i64 = 60;
/// How long an access/id token lives, in seconds.
pub const TOKEN_SECONDS: i64 = 15 * 60;
/// How long a refresh token lives.
pub const REFRESH_DAYS: i64 = 30;

#[derive(Debug, thiserror::Error)]
pub enum OidcError {
    #[error("database: {0}")]
    Backend(String),
    #[error("unknown client")]
    UnknownClient,
    #[error("bad client secret")]
    BadSecret,
}

impl From<StoreError> for OidcError {
    fn from(e: StoreError) -> Self {
        OidcError::Backend(e.to_string())
    }
}

/// Signs `claims` into a compact RS256 JWT under `kid`.
pub fn sign_jwt(claims: &serde_json::Value, kid: &str, key: &RsaPrivateKey) -> String {
    let header = serde_json::json!({ "alg": "RS256", "typ": "JWT", "kid": kid });
    let mut out = b64url.encode(header.to_string());
    out.push('.');
    out.push_str(&b64url.encode(claims.to_string()));
    let signing = rsa::pkcs1v15::SigningKey::<sha2_for_rsa::Sha256>::new(key.clone());
    let signature = signing.sign(out.as_bytes());
    out.push('.');
    out.push_str(&b64url.encode(signature.to_bytes()));
    out
}

// ---------------------------------------------------------------------------
// Clients
// ---------------------------------------------------------------------------

/// Registers a relying party, returning its id and the raw client secret —
/// shown exactly once; the row holds the digest.
pub async fn create_client(
    store: &Store,
    name: &str,
    redirect_uris: Vec<String>,
) -> Result<(ClientId, Token)> {
    let conn = store.conn.lock().await;
    let id = ClientId::mint();
    let secret = Token::mint();
    conn.execute(
        "INSERT INTO oidc_clients (client_id, name, secret_hash, redirect_uris, created_at) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
        turso::params![
            id.to_string(),
            name,
            secret.hash(),
            serde_json::to_string(&redirect_uris)
                .map_err(|e| StoreError::Corrupt(format!("redirect_uris: {e}")))?,
            store::stamp(store::now())?,
        ],
    )
    .await
    .map_err(backend)?;
    Ok((id, secret))
}

/// Looks a client up by its public id.
pub async fn client_by_id(store: &Store, client_id: &str) -> Result<Option<OidcClient>> {
    let conn = store.conn.lock().await;
    let mut rows = conn
        .query(
            "SELECT client_id, name, secret_hash, redirect_uris, created_at \
             FROM oidc_clients WHERE client_id = ?1",
            turso::params![client_id],
        )
        .await
        .map_err(backend)?;
    let Some(row) = rows.next().await.map_err(backend)? else {
        return Ok(None);
    };
    Ok(Some(read_client(&row)?))
}

fn read_client(row: &turso::Row) -> Result<OidcClient> {
    let uris_raw = store::text(row, 3)?;
    Ok(OidcClient {
        client_id: ClientId::from(store::text(row, 0)?),
        name: store::text(row, 1)?,
        secret_hash: store::text(row, 2)?,
        redirect_uris: serde_json::from_str(&uris_raw)
            .map_err(|e| StoreError::Corrupt(format!("redirect_uris {uris_raw:?}: {e}")))?,
        created_at: store::parse_stamp(&store::text(row, 4)?)?,
    })
}

/// Constant-time client-secret check.
pub fn verify_client_secret(client: &OidcClient, secret: &str) -> bool {
    digests_match(&client.secret_hash, &hash_token(secret))
}

// ---------------------------------------------------------------------------
// Authorization codes
// ---------------------------------------------------------------------------

/// Mints an authorization code for a completed login. Raw code returned; the
/// row holds the digest.
pub async fn create_auth_code(
    store: &Store,
    client_id: &ClientId,
    user: &UserId,
    redirect_uri: &str,
    nonce: Option<String>,
    challenge: &str,
    session_hash: &str,
) -> Result<Token> {
    let conn = store.conn.lock().await;
    let code = Token::mint();
    conn
        .execute(
            "INSERT INTO auth_codes \
             (code_hash, client_id, user_id, redirect_uri, nonce, code_challenge, session_hash, expires_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            turso::params![
                code.hash(),
                client_id.to_string(),
                user.to_string(),
                redirect_uri,
                nonce,
                challenge,
                session_hash,
                store::stamp(store::now() + time::Duration::seconds(CODE_SECONDS))?,
            ],
        )
        .await
        .map_err(backend)?;
    Ok(code)
}

/// Consumes a code: returns its row exactly once. The SELECT and the
/// `consumed_at` stamp run inside one immediate transaction, so two parallel
/// exchanges of the same code cannot both succeed.
pub async fn consume_auth_code(store: &Store, code: &str) -> Result<Option<AuthCode>> {
    let conn = store.conn.lock().await;
    let hash = hash_token(code);
    conn.execute("BEGIN IMMEDIATE", ()).await.map_err(backend)?;
    let outcome = async {
        let mut rows = conn
            .query(
                "SELECT client_id, user_id, redirect_uri, nonce, code_challenge, session_hash, \
                 expires_at, consumed_at FROM auth_codes WHERE code_hash = ?1",
                turso::params![hash.clone()],
            )
            .await
            .map_err(backend)?;
        let Some(row) = rows.next().await.map_err(backend)? else {
            return Ok(None);
        };
        if store::opt_text(&row, 7)?.is_some() {
            return Ok(None);
        }
        if store::parse_stamp(&store::text(&row, 6)?)? < store::now() {
            return Ok(None);
        }
        conn.execute(
            "UPDATE auth_codes SET consumed_at = ?1 WHERE code_hash = ?2",
            turso::params![store::stamp(store::now())?, hash],
        )
        .await
        .map_err(backend)?;
        Ok(Some(AuthCode {
            client_id: ClientId::from(store::text(&row, 0)?),
            user_id: UserId::from(store::text(&row, 1)?),
            redirect_uri: store::text(&row, 2)?,
            nonce: store::opt_text(&row, 3)?,
            code_challenge: store::text(&row, 4)?,
            session_hash: store::text(&row, 5)?,
            expires_at: store::parse_stamp(&store::text(&row, 6)?)?,
        }))
    }
    .await;
    match outcome {
        Ok(found) => {
            conn.execute("COMMIT", ()).await.map_err(backend)?;
            Ok(found)
        }
        Err(e) => {
            let _ = conn.execute("ROLLBACK", ()).await;
            Err(e)
        }
    }
}

// ---------------------------------------------------------------------------
// Refresh tokens
// ---------------------------------------------------------------------------

/// Issues a refresh token bound to the central session that minted it, so
/// revoking the session retires every token the apps are still holding.
pub async fn issue_refresh(
    store: &Store,
    user: &UserId,
    client_id: &ClientId,
    session_hash: &str,
) -> Result<Token> {
    let conn = store.conn.lock().await;
    let token = Token::mint();
    conn.execute(
        "INSERT INTO refresh_tokens \
             (token_hash, user_id, client_id, session_hash, expires_at) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
        turso::params![
            token.hash(),
            user.to_string(),
            client_id.to_string(),
            session_hash,
            store::stamp(store::now() + time::Duration::days(REFRESH_DAYS))?,
        ],
    )
    .await
    .map_err(backend)?;
    Ok(token)
}

/// Rotates a refresh token: the presented one is revoked, a fresh one is
/// minted against the same session, and the new raw token plus the old row
/// come back. `None` for unknown, expired, or revoked tokens — and for tokens
/// whose central session is gone, which is what makes SSO logout global.
pub async fn rotate_refresh(store: &Store, token: &str) -> Result<Option<(Token, RefreshToken)>> {
    let conn = store.conn.lock().await;
    let hash = hash_token(token);
    conn.execute("BEGIN IMMEDIATE", ()).await.map_err(backend)?;
    let outcome = async {
        let mut rows = conn
            .query(
                "SELECT user_id, client_id, session_hash, expires_at, revoked_at \
                 FROM refresh_tokens WHERE token_hash = ?1",
                turso::params![hash.clone()],
            )
            .await
            .map_err(backend)?;
        let Some(row) = rows.next().await.map_err(backend)? else {
            return Ok(None);
        };
        if store::opt_text(&row, 4)?.is_some() {
            return Ok(None);
        }
        if store::parse_stamp(&store::text(&row, 3)?)? < store::now() {
            return Ok(None);
        }
        let record = RefreshToken {
            user_id: UserId::from(store::text(&row, 0)?),
            client_id: ClientId::from(store::text(&row, 1)?),
            session_hash: store::text(&row, 2)?,
            expires_at: store::parse_stamp(&store::text(&row, 3)?)?,
        };
        // The session that minted this token must still be alive.
        let mut sessions = conn
            .query(
                "SELECT expires_at, revoked_at FROM sessions WHERE token_hash = ?1",
                turso::params![record.session_hash.clone()],
            )
            .await
            .map_err(backend)?;
        let Some(session) = sessions.next().await.map_err(backend)? else {
            return Ok(None);
        };
        if store::opt_text(&session, 1)?.is_some() {
            return Ok(None);
        }
        if store::parse_stamp(&store::text(&session, 0)?)? < store::now() {
            return Ok(None);
        }

        let now = store::stamp(store::now())?;
        conn.execute(
            "UPDATE refresh_tokens SET revoked_at = ?1 WHERE token_hash = ?2",
            turso::params![now.clone(), hash.clone()],
        )
        .await
        .map_err(backend)?;
        // Inlined from `issue_refresh`: the transaction already holds the
        // connection, and the helper locks for itself.
        let fresh = Token::mint();
        conn.execute(
            "INSERT INTO refresh_tokens \
                 (token_hash, user_id, client_id, session_hash, expires_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5)",
            turso::params![
                fresh.hash(),
                record.user_id.to_string(),
                record.client_id.to_string(),
                record.session_hash.clone(),
                store::stamp(store::now() + time::Duration::days(REFRESH_DAYS))?,
            ],
        )
        .await
        .map_err(backend)?;
        Ok(Some((fresh, record)))
    }
    .await;
    match outcome {
        Ok(found) => {
            conn.execute("COMMIT", ()).await.map_err(backend)?;
            Ok(found)
        }
        Err(e) => {
            let _ = conn.execute("ROLLBACK", ()).await;
            Err(e)
        }
    }
}

// ---------------------------------------------------------------------------
// Verification (the provider half: /userinfo and future introspection)
// ---------------------------------------------------------------------------

/// RFC 7636 S256: `base64url(sha256(verifier))` must equal the challenge the
/// `/authorize` call stored.
pub fn pkce_matches(challenge: &str, verifier: &str) -> bool {
    use sha2::Digest;
    let computed = b64url.encode(sha2::Sha256::digest(verifier.as_bytes()));
    crate::accounts::digests_match(challenge, &computed)
}

/// Verifies a compact JWT im minted: RS256 signature against the active key
/// named by `kid`, `aud` equal to `audience`, `exp` in the future. Returns
/// the claims on success, `None` for every way a token can fail — unknown
/// key, bad signature, wrong audience, expired — which all read the same to
/// the caller: this token does not authenticate anyone.
///
/// `iss` is the caller's to check: the issuer string is configuration the
/// core crate does not hold.
pub async fn verify_jwt(
    store: &Store,
    token: &str,
    audience: Option<&str>,
) -> Result<Option<serde_json::Value>> {
    use rsa::signature::Verifier;

    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Ok(None);
    }
    let Ok(header_bytes) = b64url.decode(parts[0]) else {
        return Ok(None);
    };
    let Ok(header) = serde_json::from_slice::<serde_json::Value>(&header_bytes) else {
        return Ok(None);
    };
    if header["alg"] != "RS256" {
        return Ok(None);
    }
    let Some(kid) = header["kid"].as_str() else {
        return Ok(None);
    };
    let Some(public) = crate::keys::public_key_by_kid(store, kid).await? else {
        return Ok(None);
    };
    let Ok(signature_bytes) = b64url.decode(parts[2]) else {
        return Ok(None);
    };
    let Ok(signature) = rsa::pkcs1v15::Signature::try_from(signature_bytes.as_slice()) else {
        return Ok(None);
    };
    let verifying = rsa::pkcs1v15::VerifyingKey::<sha2_for_rsa::Sha256>::new(public);
    if verifying
        .verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &signature)
        .is_err()
    {
        return Ok(None);
    }
    let Ok(claims_bytes) = b64url.decode(parts[1]) else {
        return Ok(None);
    };
    let Ok(claims) = serde_json::from_slice::<serde_json::Value>(&claims_bytes) else {
        return Ok(None);
    };
    if let Some(audience) = audience {
        if claims["aud"].as_str() != Some(audience) {
            return Ok(None);
        }
    }
    let Some(exp) = claims["exp"].as_i64() else {
        return Ok(None);
    };
    if exp <= store::now().unix_timestamp() {
        return Ok(None);
    }
    Ok(Some(claims))
}

// ---------------------------------------------------------------------------
// App sessions: the opaque, introspected session an app actually holds
// ---------------------------------------------------------------------------

/// How long an app session may live when nothing revokes it first.
pub const APP_SESSION_DAYS: i64 = 30;

/// Mints an opaque app session bound to the central session that authorized
/// it. The app stores only this token; every request it serves introspects
/// the token against im, so revocation is immediate rather than
/// token-TTL-bounded.
pub async fn issue_app_session(
    store: &Store,
    user: &UserId,
    client_id: &ClientId,
    session_hash: &str,
) -> Result<Token> {
    let conn = store.conn.lock().await;
    let token = Token::mint();
    let now = store::now();
    conn.execute(
        "INSERT INTO app_sessions \
             (token_hash, user_id, client_id, session_hash, created_at, expires_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        turso::params![
            token.hash(),
            user.to_string(),
            client_id.to_string(),
            session_hash,
            store::stamp(now)?,
            store::stamp(now + time::Duration::days(APP_SESSION_DAYS))?,
        ],
    )
    .await
    .map_err(backend)?;
    Ok(token)
}

/// RFC 7662's answer shape: who this token is, or inactive. Inactive covers
/// unknown, expired, revoked, a revoked central session, a disabled user, or
/// a token presented by a client it was never issued to.
pub async fn introspect_app_session(
    store: &Store,
    token: &str,
    client_id: &str,
) -> Result<Option<serde_json::Value>> {
    // Both rows are read under one short-held guard; the user lookup locks
    // for itself after it drops.
    let (user_id, expires) = {
        let conn = store.conn.lock().await;
        let mut rows = conn
            .query(
                "SELECT user_id, client_id, session_hash, expires_at, revoked_at \
                 FROM app_sessions WHERE token_hash = ?1",
                turso::params![hash_token(token)],
            )
            .await
            .map_err(backend)?;
        let Some(row) = rows.next().await.map_err(backend)? else {
            return Ok(None);
        };
        if store::opt_text(&row, 4)?.is_some() {
            return Ok(None);
        }
        let expires = store::parse_stamp(&store::text(&row, 3)?)?;
        if expires < store::now() {
            return Ok(None);
        }
        if store::text(&row, 1)? != client_id {
            return Ok(None);
        }
        // The central session must still be alive — this is what makes admin
        // revocation immediate.
        let session_hash = store::text(&row, 2)?;
        let mut sessions = conn
            .query(
                "SELECT expires_at, revoked_at FROM sessions WHERE token_hash = ?1",
                turso::params![session_hash],
            )
            .await
            .map_err(backend)?;
        let Some(session) = sessions.next().await.map_err(backend)? else {
            return Ok(None);
        };
        if store::opt_text(&session, 1)?.is_some() {
            return Ok(None);
        }
        if store::parse_stamp(&store::text(&session, 0)?)? < store::now() {
            return Ok(None);
        }
        (UserId::from(store::text(&row, 0)?), expires)
    };
    let Some(user) = crate::accounts::user_by_id(store, &user_id).await? else {
        return Ok(None);
    };
    if user.disabled {
        return Ok(None);
    }
    Ok(Some(serde_json::json!({
        "active": true,
        "sub": user.id.as_str(),
        "email": user.email,
        "name": user.name,
        "exp": expires.unix_timestamp(),
    })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounts::{create_invite, create_user_from_invite};
    use crate::sessions::create_session;
    use rsa::signature::Verifier;
    use std::path::Path;

    #[tokio::test]
    async fn app_session_introspection_and_instant_revoke() {
        let (store, client_id, user_id) = fixture().await;
        let session = create_session(&store, &user_id).await.unwrap();
        let app_token = issue_app_session(&store, &user_id, &client_id, &session.hash())
            .await
            .unwrap();

        let active = introspect_app_session(&store, app_token.expose(), client_id.as_str())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(active["active"], true);
        assert_eq!(active["sub"], user_id.as_str());

        // Another client cannot spend the token.
        assert!(
            introspect_app_session(&store, app_token.expose(), "someone-else")
                .await
                .unwrap()
                .is_none()
        );

        // Admin revokes the person: the very next introspection is inactive.
        crate::sessions::revoke_user_sessions(&store, &user_id)
            .await
            .unwrap();
        assert!(
            introspect_app_session(&store, app_token.expose(), client_id.as_str())
                .await
                .unwrap()
                .is_none(),
            "no ghost after admin revocation"
        );
    }

    async fn fixture() -> (Store, ClientId, UserId) {
        let store = Store::open(Path::new(":memory:")).await.unwrap();
        let (client_id, _secret) =
            create_client(&store, "demo", vec!["http://app/callback".into()])
                .await
                .unwrap();
        let invite = create_invite(&store, "ann@example.com", None, false)
            .await
            .unwrap();
        let user = create_user_from_invite(&store, invite.expose(), "Ann", "tDLr9!mZQ2xv")
            .await
            .unwrap();
        (store, client_id, user.id)
    }

    #[tokio::test]
    async fn jwt_structure_and_signature() {
        let store = Store::open(Path::new(":memory:")).await.unwrap();
        let (kid, key) = crate::keys::active_signing_key(&store).await.unwrap();
        let token = sign_jwt(
            &serde_json::json!({ "iss": "im", "sub": "u1", "exp": 1i64 }),
            &kid,
            &key,
        );
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3);
        let header: serde_json::Value =
            serde_json::from_slice(&b64url.decode(parts[0]).unwrap()).unwrap();
        assert_eq!(header["alg"], "RS256");
        assert_eq!(header["kid"].as_str().unwrap(), kid);
        let claims: serde_json::Value =
            serde_json::from_slice(&b64url.decode(parts[1]).unwrap()).unwrap();
        assert_eq!(claims["sub"], "u1");

        let verifying =
            rsa::pkcs1v15::VerifyingKey::<sha2_for_rsa::Sha256>::new(key.to_public_key());
        let signature =
            rsa::pkcs1v15::Signature::try_from(b64url.decode(parts[2]).unwrap().as_slice())
                .unwrap();
        verifying
            .verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &signature)
            .unwrap();
        // A tampered payload must not verify.
        let forged = format!("{}.{}", parts[0], b64url.encode(r#"{"sub":"mallory"}"#));
        assert!(verifying.verify(forged.as_bytes(), &signature).is_err());
    }

    #[tokio::test]
    async fn auth_code_is_single_use() {
        let (store, client_id, user_id) = fixture().await;
        let code = create_auth_code(
            &store,
            &client_id,
            &user_id,
            "http://app/callback",
            None,
            "challenge",
            "session-hash",
        )
        .await
        .unwrap();
        let first = consume_auth_code(&store, code.expose()).await.unwrap();
        assert!(first.is_some());
        assert_eq!(first.unwrap().code_challenge, "challenge");
        assert!(
            consume_auth_code(&store, code.expose())
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn refresh_rotates_and_dies_with_session() {
        let (store, client_id, user_id) = fixture().await;
        let session = create_session(&store, &user_id).await.unwrap();
        let token = issue_refresh(&store, &user_id, &client_id, &session.hash())
            .await
            .unwrap();

        let (fresh, old) = rotate_refresh(&store, token.expose())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(old.user_id, user_id);
        // The old token is spent.
        assert!(
            rotate_refresh(&store, token.expose())
                .await
                .unwrap()
                .is_none()
        );
        // The fresh one works.
        assert!(
            rotate_refresh(&store, fresh.expose())
                .await
                .unwrap()
                .is_some()
        );

        // Revoking the central session retires the refresh chain.
        let session2 = create_session(&store, &user_id).await.unwrap();
        let token2 = issue_refresh(&store, &user_id, &client_id, &session2.hash())
            .await
            .unwrap();
        crate::sessions::revoke_session(&store, session2.expose())
            .await
            .unwrap();
        assert!(
            rotate_refresh(&store, token2.expose())
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn client_secret_verifies_constant_time() {
        let (store, client_id, _) = fixture().await;
        let client = client_by_id(&store, &client_id.to_string())
            .await
            .unwrap()
            .unwrap();
        assert!(!verify_client_secret(&client, "wrong"));
        assert!(
            client
                .redirect_uris
                .contains(&"http://app/callback".to_string())
        );
    }
}
