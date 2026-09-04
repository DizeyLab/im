//! The profile page's statistics: how often this identity has been used,
//! and what is holding it right now.
//!
//! Everything here derives from rows the system already keeps — a session
//! row per sign-in, an app-session row per app a sign-in was handed to. No
//! counters, nothing to drift: the page's numbers are the tables, read.

use crate::model::UserId;
use crate::store::{self, Result, Store, backend};

/// One person's counts, for the profile section of the signed-in landing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileStats {
    /// Every sign-in ever: one central-session row is written per login.
    pub sign_ins: u64,
    /// Sessions neither revoked nor expired — the devices that could act
    /// as this person right now.
    pub active_sessions: u64,
    /// Apps holding a live token for this person (distinct OIDC clients
    /// with an unrevoked, unexpired app session).
    pub connected_apps: u64,
}

/// Reads the three counts. One round-trip: the tables are small, and the
/// landing is the only reader.
pub async fn profile_stats(store: &Store, user: &UserId) -> Result<ProfileStats> {
    let conn = store.conn.lock().await;
    let id = user.to_string();
    let now = store::stamp(store::now())?;
    let mut rows = conn
        .query(
            "SELECT \
               (SELECT COUNT(*) FROM sessions WHERE user_id = ?1), \
               (SELECT COUNT(*) FROM sessions \
                 WHERE user_id = ?1 AND revoked_at IS NULL AND expires_at > ?2), \
               (SELECT COUNT(DISTINCT client_id) FROM app_sessions \
                 WHERE user_id = ?1 AND revoked_at IS NULL AND expires_at > ?2)",
            turso::params![id, now],
        )
        .await
        .map_err(backend)?;
    let row = rows
        .next()
        .await
        .map_err(backend)?
        .ok_or_else(|| backend("counts query returned no row"))?;
    Ok(ProfileStats {
        sign_ins: store::int(&row, 0)? as u64,
        active_sessions: store::int(&row, 1)? as u64,
        connected_apps: store::int(&row, 2)? as u64,
    })
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

    /// Stamps relative to now, so "expired" and "live" rows stay on their
    /// own sides of the comparison whatever the clock says at test time.
    fn stamp_in(hours: i64) -> String {
        store::stamp(store::now() + time::Duration::hours(hours)).unwrap()
    }

    #[tokio::test]
    async fn counts_reflect_the_tables() {
        let (store, user_id) = fixture().await;
        let id = user_id.to_string();
        {
            let conn = store.conn.lock().await;
            // Three sign-ins: one expired, one revoked, one live.
            for (hash, expires, revoked) in [
                ("h-expired", stamp_in(-1), None),
                ("h-revoked", stamp_in(24), Some(stamp_in(-1))),
                ("h-live", stamp_in(24), None),
            ] {
                conn.execute(
                    "INSERT INTO sessions (token_hash, user_id, created_at, expires_at, revoked_at) \
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    turso::params![hash, id.clone(), stamp_in(-24), expires, revoked],
                )
                .await
                .unwrap();
            }
            // A client the app sessions point at, then three app sessions:
            // two live for one client (counts once), one revoked for another.
            conn.execute(
                "INSERT INTO oidc_clients (client_id, name, secret_hash, redirect_uris, created_at) \
                 VALUES ('client-a', 'A', 'x', '[]', ?1)",
                turso::params![stamp_in(-24)],
            )
            .await
            .unwrap();
            conn.execute(
                "INSERT INTO oidc_clients (client_id, name, secret_hash, redirect_uris, created_at) \
                 VALUES ('client-b', 'B', 'x', '[]', ?1)",
                turso::params![stamp_in(-24)],
            )
            .await
            .unwrap();
            for (hash, client, expires, revoked) in [
                ("a1", "client-a", stamp_in(24), None),
                ("a2", "client-a", stamp_in(24), None),
                ("b1", "client-b", stamp_in(24), Some(stamp_in(-1))),
            ] {
                conn.execute(
                    "INSERT INTO app_sessions \
                     (token_hash, user_id, client_id, session_hash, created_at, expires_at, revoked_at) \
                     VALUES (?1, ?2, ?3, 'h-live', ?4, ?5, ?6)",
                    turso::params![hash, id.clone(), client, stamp_in(-24), expires, revoked],
                )
                .await
                .unwrap();
            }
        }
        let stats = profile_stats(&store, &user_id).await.unwrap();
        assert_eq!(
            stats,
            ProfileStats {
                sign_ins: 3,
                active_sessions: 1,
                connected_apps: 1,
            }
        );
    }

    #[tokio::test]
    async fn a_fresh_account_reads_zero() {
        let (store, user_id) = fixture().await;
        assert_eq!(
            profile_stats(&store, &user_id).await.unwrap(),
            ProfileStats {
                sign_ins: 0,
                active_sessions: 0,
                connected_apps: 0,
            }
        );
    }
}
