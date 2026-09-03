//! Central sessions: the `im_session` cookie's server half.
//!
//! A session is what makes SSO single: once a browser holds one, every app's
//! `/authorize` round-trip is a silent redirect. Revoking a session also
//! revokes every refresh token bound to it — that is what "log me out
//! everywhere" means here.

use crate::accounts::{Token, hash_token};
use crate::model::{User, UserId};
use crate::store::{self, Result, Store, backend};

/// How long a central session lives.
pub const SESSION_DAYS: i64 = 30;

/// Creates a session for `user`, returning the raw cookie token. The row
/// holds only its digest.
pub async fn create_session(store: &Store, user: &UserId) -> Result<Token> {
    let token = Token::mint();
    let now = store::now();
    store
        .conn
        .execute(
            "INSERT INTO sessions (token_hash, user_id, created_at, expires_at) \
             VALUES (?1, ?2, ?3, ?4)",
            turso::params![
                token.hash(),
                user.to_string(),
                store::stamp(now)?,
                store::stamp(now + time::Duration::days(SESSION_DAYS))?,
            ],
        )
        .await
        .map_err(backend)?;
    Ok(token)
}

/// Resolves a raw cookie token to its user. `None` for unknown, expired,
/// revoked, or disabled — every one of them is "please log in again".
pub async fn resolve_session(store: &Store, token: &str) -> Result<Option<User>> {
    let mut rows = store
        .conn
        .query(
            "SELECT user_id, expires_at, revoked_at FROM sessions WHERE token_hash = ?1",
            turso::params![hash_token(token)],
        )
        .await
        .map_err(backend)?;
    let Some(row) = rows.next().await.map_err(backend)? else {
        return Ok(None);
    };
    if store::opt_text(&row, 2)?.is_some() {
        return Ok(None);
    }
    if store::parse_stamp(&store::text(&row, 1)?)? < store::now() {
        return Ok(None);
    }
    let user_id = UserId::from(store::text(&row, 0)?);
    match crate::accounts::user_by_id(store, &user_id).await? {
        Some(user) if !user.disabled => Ok(Some(user)),
        _ => Ok(None),
    }
}

/// Revokes a session and every refresh token bound to it.
pub async fn revoke_session(store: &Store, token: &str) -> Result<()> {
    let now = store::stamp(store::now())?;
    let hash = hash_token(token);
    store
        .conn
        .execute(
            "UPDATE sessions SET revoked_at = ?1 WHERE token_hash = ?2 AND revoked_at IS NULL",
            turso::params![now.clone(), hash.clone()],
        )
        .await
        .map_err(backend)?;
    store
        .conn
        .execute(
            "UPDATE refresh_tokens SET revoked_at = ?1 WHERE session_hash = ?2 AND revoked_at IS NULL",
            turso::params![now, hash],
        )
        .await
        .map_err(backend)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounts::{create_invite, create_user_from_invite};
    use std::path::Path;

    async fn fixture() -> (Store, UserId) {
        let store = Store::open(Path::new(":memory:")).await.unwrap();
        let invite = create_invite(&store, "ann@example.com", None)
            .await
            .unwrap();
        let user = create_user_from_invite(&store, invite.expose(), "Ann", "tDLr9!mZQ2xv")
            .await
            .unwrap();
        (store, user.id)
    }

    #[tokio::test]
    async fn session_roundtrip_and_revoke() {
        let (store, user_id) = fixture().await;
        let token = create_session(&store, &user_id).await.unwrap();
        let user = resolve_session(&store, token.expose())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(user.id, user_id);

        revoke_session(&store, token.expose()).await.unwrap();
        assert!(
            resolve_session(&store, token.expose())
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            resolve_session(&store, "not-a-token")
                .await
                .unwrap()
                .is_none()
        );
    }
}
