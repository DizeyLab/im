//! Central sessions: the `im_session` cookie's server half.
//!
//! A session is what makes SSO single: once a browser holds one, every app's
//! `/authorize` round-trip is a silent redirect. Revoking a session also
//! revokes every refresh token bound to it — that is what "log me out
//! everywhere" means here. Each session also remembers its browser (IP,
//! agent, last seen) so the sessions list can show every device separately.

use crate::accounts::{Token, hash_token};
use crate::model::{User, UserId};
use crate::store::{self, Result, Store, backend};

/// The default central-session lifetime. The panel's Settings section can
/// move it; the constant stays the fresh-database answer and the cookie's
/// Max-Age (which is set before the store is in hand).
pub const SESSION_DAYS: i64 = 30;

/// Creation-time facts about the client holding the session.
#[derive(Debug, Clone, Default)]
pub struct SessionMeta {
    pub ip: Option<String>,
    pub agent: Option<String>,
}

/// One live central session, as the sessions list shows it.
#[derive(Debug, Clone)]
pub struct SessionInfo {
    pub token_hash: String,
    pub created_at: time::OffsetDateTime,
    pub expires_at: time::OffsetDateTime,
    pub seen_at: Option<time::OffsetDateTime>,
    pub ip: Option<String>,
    pub agent: Option<String>,
}

/// Creates a session for `user`, returning the raw cookie token. The row
/// holds only its digest, plus what `meta` says about the browser — and the
/// first sighting is creation itself, so `seen_at` starts at `created_at`.
pub async fn create_session(store: &Store, user: &UserId, meta: &SessionMeta) -> Result<Token> {
    let token = Token::mint();
    let now = store::now();
    let days = crate::settings::policy(store).await?.session_days;
    let conn = store.conn.lock().await;
    conn.execute(
        "INSERT INTO sessions (token_hash, user_id, created_at, expires_at, ip, agent, seen_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?3)",
        turso::params![
            token.hash(),
            user.to_string(),
            store::stamp(now)?,
            store::stamp(now + time::Duration::days(days))?,
            meta.ip.clone(),
            meta.agent.clone(),
        ],
    )
    .await
    .map_err(backend)?;
    Ok(token)
}

/// Resolves a raw cookie token to its user. `None` for unknown, expired,
/// revoked, or disabled — every one of them is "please log in again".
pub async fn resolve_session(store: &Store, token: &str) -> Result<Option<User>> {
    // The session row is read under a short-held guard; the user lookup locks
    // for itself once the guard is dropped.
    let found = {
        let conn = store.conn.lock().await;
        let mut rows = conn
            .query(
                "SELECT user_id, expires_at, revoked_at FROM sessions WHERE token_hash = ?1",
                turso::params![hash_token(token)],
            )
            .await
            .map_err(backend)?;
        match rows.next().await.map_err(backend)? {
            Some(row)
                if store::opt_text(&row, 2)?.is_none()
                    && store::parse_stamp(&store::text(&row, 1)?)? >= store::now() =>
            {
                Some(UserId::from(store::text(&row, 0)?))
            }
            _ => None,
        }
    };
    let Some(user_id) = found else {
        return Ok(None);
    };
    match crate::accounts::user_by_id(store, &user_id).await? {
        Some(user) if !user.disabled => {
            // The sighting lands after the fact, guard long dropped: one
            // UPDATE per call, and the throttle keeps it near one write per
            // five minutes per session no matter how chatty the browser is.
            let now = store::now();
            let conn = store.conn.lock().await;
            conn.execute(
                "UPDATE sessions SET seen_at = ?1 WHERE token_hash = ?2 \
                     AND (seen_at IS NULL OR seen_at < ?3)",
                turso::params![
                    store::stamp(now)?,
                    hash_token(token),
                    store::stamp(now - time::Duration::minutes(5))?,
                ],
            )
            .await
            .map_err(backend)?;
            Ok(Some(user))
        }
        _ => Ok(None),
    }
}

/// Revokes a session and everything bound to it: refresh tokens and the
/// opaque app sessions introspection answers for.
pub async fn revoke_session(store: &Store, token: &str) -> Result<()> {
    let hash = hash_token(token);
    revoke_session_hash(store, &hash).await
}

/// The hash-level half of [`revoke_session`], shared with the admin's
/// revoke-everything below.
pub(crate) async fn revoke_session_hash(store: &Store, hash: &str) -> Result<()> {
    let conn = store.conn.lock().await;
    let now = store::stamp(store::now())?;
    conn.execute(
        "UPDATE sessions SET revoked_at = ?1 WHERE token_hash = ?2 AND revoked_at IS NULL",
        turso::params![now.clone(), hash],
    )
    .await
    .map_err(backend)?;
    conn.execute(
        "UPDATE refresh_tokens SET revoked_at = ?1 WHERE session_hash = ?2 AND revoked_at IS NULL",
        turso::params![now.clone(), hash],
    )
    .await
    .map_err(backend)?;
    conn.execute(
        "UPDATE app_sessions SET revoked_at = ?1 WHERE session_hash = ?2 AND revoked_at IS NULL",
        turso::params![now, hash],
    )
    .await
    .map_err(backend)?;
    Ok(())
}

/// Active (not revoked, not expired) sessions of `user`, newest first.
pub async fn list_sessions(store: &Store, user: &UserId) -> Result<Vec<SessionInfo>> {
    // Revocation filters in SQL; expiry is a stamp comparison, done beside
    // `resolve_session` in Rust where a corrupt stamp surfaces as an error.
    let now = store::now();
    let conn = store.conn.lock().await;
    let mut rows = conn
        .query(
            "SELECT token_hash, created_at, expires_at, seen_at, ip, agent FROM sessions \
                 WHERE user_id = ?1 AND revoked_at IS NULL ORDER BY created_at DESC",
            turso::params![user.to_string()],
        )
        .await
        .map_err(backend)?;
    let mut out = Vec::new();
    while let Some(row) = rows.next().await.map_err(backend)? {
        let expires_at = store::parse_stamp(&store::text(&row, 2)?)?;
        if expires_at < now {
            continue;
        }
        let seen_at = match store::opt_text(&row, 3)? {
            Some(raw) => Some(store::parse_stamp(&raw)?),
            None => None,
        };
        out.push(SessionInfo {
            token_hash: store::text(&row, 0)?,
            created_at: store::parse_stamp(&store::text(&row, 1)?)?,
            expires_at,
            seen_at,
            ip: store::opt_text(&row, 4)?,
            agent: store::opt_text(&row, 5)?,
        });
    }
    Ok(out)
}

/// Revokes `hash` only if it names a session of `user`; true when it did.
/// The cascade is [`revoke_session_hash`]'s, so a device gone from the list
/// takes its app tokens down with it.
pub async fn revoke_owned_session(store: &Store, user: &UserId, hash: &str) -> Result<bool> {
    // Ownership reads first: a hash naming someone else's session — or no
    // session at all — is a quiet false, never a revoke.
    let owned = {
        let conn = store.conn.lock().await;
        let mut rows = conn
            .query(
                "SELECT user_id FROM sessions WHERE token_hash = ?1 AND revoked_at IS NULL",
                turso::params![hash],
            )
            .await
            .map_err(backend)?;
        match rows.next().await.map_err(backend)? {
            Some(row) => store::text(&row, 0)? == user.as_str(),
            None => false,
        }
    };
    if !owned {
        return Ok(false);
    }
    revoke_session_hash(store, hash).await?;
    Ok(true)
}

/// The admin's "log this person out everywhere": every central session of
/// theirs dies, and the cascades above take every refresh token and every
/// live app session down with them. Introspection is per-request, so the
/// next call any app makes on their behalf comes back inactive — no ghost.
pub async fn revoke_user_sessions(store: &Store, user: &UserId) -> Result<u64> {
    // Read under a short guard; the per-session revokes and the final sweep
    // lock for themselves.
    let hashes = {
        let conn = store.conn.lock().await;
        let mut rows = conn
            .query(
                "SELECT token_hash FROM sessions WHERE user_id = ?1 AND revoked_at IS NULL",
                turso::params![user.to_string()],
            )
            .await
            .map_err(backend)?;
        let mut hashes = Vec::new();
        while let Some(row) = rows.next().await.map_err(backend)? {
            hashes.push(store::text(&row, 0)?);
        }
        hashes
    };
    let count = hashes.len() as u64;
    for hash in hashes {
        revoke_session_hash(store, &hash).await?;
    }
    // Sessions already revoked earlier still own live app sessions; sweep
    // those too so nothing outlives the person being signed out.
    let now = store::stamp(store::now())?;
    let conn = store.conn.lock().await;
    conn.execute(
        "UPDATE app_sessions SET revoked_at = ?1 WHERE user_id = ?2 AND revoked_at IS NULL",
        turso::params![now.clone(), user.to_string()],
    )
    .await
    .map_err(backend)?;
    conn.execute(
        "UPDATE refresh_tokens SET revoked_at = ?1 WHERE user_id = ?2 AND revoked_at IS NULL",
        turso::params![now, user.to_string()],
    )
    .await
    .map_err(backend)?;
    Ok(count)
}

/// A password change's revoke: every session dies except the one holding the
/// form — the browser that just proved the old password stays signed in, and
/// every other device (and every app token born of them) is out.
pub async fn revoke_user_sessions_except(
    store: &Store,
    user: &UserId,
    keep_token: &str,
) -> Result<u64> {
    let keep = hash_token(keep_token);
    let hashes = {
        let conn = store.conn.lock().await;
        let mut rows = conn
            .query(
                "SELECT token_hash FROM sessions \
                 WHERE user_id = ?1 AND revoked_at IS NULL AND token_hash != ?2",
                turso::params![user.to_string(), keep.clone()],
            )
            .await
            .map_err(backend)?;
        let mut hashes = Vec::new();
        while let Some(row) = rows.next().await.map_err(backend)? {
            hashes.push(store::text(&row, 0)?);
        }
        hashes
    };
    let count = hashes.len() as u64;
    for hash in &hashes {
        revoke_session_hash(store, hash).await?;
    }
    // The kept session is the only one allowed to keep its app sessions and
    // refresh tokens; everything else of this user's is swept.
    let now = store::stamp(store::now())?;
    let conn = store.conn.lock().await;
    conn.execute(
        "UPDATE app_sessions SET revoked_at = ?1 WHERE user_id = ?2 AND revoked_at IS NULL \
             AND session_hash != ?3",
        turso::params![now.clone(), user.to_string(), keep.clone()],
    )
    .await
    .map_err(backend)?;
    conn.execute(
        "UPDATE refresh_tokens SET revoked_at = ?1 WHERE user_id = ?2 AND revoked_at IS NULL \
             AND session_hash != ?3",
        turso::params![now, user.to_string(), keep],
    )
    .await
    .map_err(backend)?;
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounts::{create_invite, create_user_from_invite};
    use std::path::Path;

    async fn fixture() -> (Store, UserId) {
        let store = Store::open(Path::new(":memory:")).await.unwrap();
        let invite = create_invite(&store, "ann@example.com", None, false)
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
        let token = create_session(&store, &user_id, &SessionMeta::default())
            .await
            .unwrap();
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

    #[tokio::test]
    async fn revoke_except_keeps_the_asking_session() {
        let (store, user_id) = fixture().await;
        let mine = create_session(&store, &user_id, &SessionMeta::default())
            .await
            .unwrap();
        let other = create_session(&store, &user_id, &SessionMeta::default())
            .await
            .unwrap();

        let count = revoke_user_sessions_except(&store, &user_id, mine.expose())
            .await
            .unwrap();
        assert_eq!(count, 1);
        assert!(
            resolve_session(&store, mine.expose())
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            resolve_session(&store, other.expose())
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn list_shows_only_active_newest_first_with_facts() {
        let (store, user_id) = fixture().await;
        let plain = create_session(&store, &user_id, &SessionMeta::default())
            .await
            .unwrap();
        let meta = SessionMeta {
            ip: Some("203.0.113.7".to_string()),
            agent: Some("TestBrowser/1.0".to_string()),
        };
        let noted = create_session(&store, &user_id, &meta).await.unwrap();

        let listed = list_sessions(&store, &user_id).await.unwrap();
        assert_eq!(listed.len(), 2);
        // Newest first: the noted session was created second.
        assert_eq!(listed[0].token_hash, noted.hash());
        assert_eq!(listed[0].ip.as_deref(), Some("203.0.113.7"));
        assert_eq!(listed[0].agent.as_deref(), Some("TestBrowser/1.0"));
        assert_eq!(listed[0].seen_at, Some(listed[0].created_at));
        assert_eq!(listed[1].token_hash, plain.hash());
        assert!(listed[1].ip.is_none());
        assert!(listed[1].agent.is_none());
        assert!(listed[1].created_at <= listed[0].created_at);

        // A revoked session leaves the list; an expired one never shows.
        revoke_session(&store, plain.expose()).await.unwrap();
        let listed = list_sessions(&store, &user_id).await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].token_hash, noted.hash());

        let conn = store.conn.lock().await;
        conn.execute(
            "UPDATE sessions SET expires_at = ?1 WHERE token_hash = ?2",
            turso::params![
                store::stamp(store::now() - time::Duration::days(1)).unwrap(),
                noted.hash(),
            ],
        )
        .await
        .unwrap();
        drop(conn);
        assert!(list_sessions(&store, &user_id).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn revoke_owned_refuses_a_strangers_session() {
        let (store, user_id) = fixture().await;
        let invite = create_invite(&store, "bob@example.com", None, false)
            .await
            .unwrap();
        let stranger = create_user_from_invite(&store, invite.expose(), "Bob", "tDLr9!mZQ2xvQ")
            .await
            .unwrap();
        let mine = create_session(&store, &user_id, &SessionMeta::default())
            .await
            .unwrap();
        let theirs = create_session(&store, &stranger.id, &SessionMeta::default())
            .await
            .unwrap();

        // Someone else's hash is a quiet false, and their session survives it.
        assert!(!revoke_owned_session(&store, &user_id, &theirs.hash())
            .await
            .unwrap());
        assert!(
            resolve_session(&store, theirs.expose())
                .await
                .unwrap()
                .is_some()
        );
        assert!(!revoke_owned_session(&store, &user_id, "no-such-hash")
            .await
            .unwrap());

        assert!(revoke_owned_session(&store, &user_id, &mine.hash())
            .await
            .unwrap());
        assert!(
            resolve_session(&store, mine.expose())
                .await
                .unwrap()
                .is_none()
        );
        // Revoking twice is a quiet false the second time.
        assert!(!revoke_owned_session(&store, &user_id, &mine.hash())
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn resolve_touches_seen_at_past_the_throttle() {
        let (store, user_id) = fixture().await;
        let token = create_session(&store, &user_id, &SessionMeta::default())
            .await
            .unwrap();
        // Backdate the sighting past the throttle without sleeping.
        let conn = store.conn.lock().await;
        conn.execute(
            "UPDATE sessions SET seen_at = ?1 WHERE token_hash = ?2",
            turso::params![
                store::stamp(store::now() - time::Duration::minutes(10)).unwrap(),
                token.hash(),
            ],
        )
        .await
        .unwrap();
        drop(conn);

        let before = list_sessions(&store, &user_id).await.unwrap();
        assert_eq!(before.len(), 1);
        let stale = before[0].seen_at.unwrap();

        assert!(
            resolve_session(&store, token.expose())
                .await
                .unwrap()
                .is_some()
        );
        let after = list_sessions(&store, &user_id).await.unwrap();
        assert!(after[0].seen_at.unwrap() > stale);

        // A fresh sighting is inside the throttle: resolving again is a
        // no-op write, so seen_at stands still.
        let fresh = after[0].seen_at.unwrap();
        assert!(
            resolve_session(&store, token.expose())
                .await
                .unwrap()
                .is_some()
        );
        let again = list_sessions(&store, &user_id).await.unwrap();
        assert_eq!(again[0].seen_at, Some(fresh));
    }
}
