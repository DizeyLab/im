//! The turso store: connection, schema, and the conventions every module
//! queries through.

use std::path::Path;

use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use turso::{Builder, Connection, Row};

use crate::secret::{self, Key};

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("database: {0}")]
    Backend(String),
    #[error("corrupt row: {0}")]
    Corrupt(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T, E = StoreError> = std::result::Result<T, E>;

pub(crate) fn backend<E: std::fmt::Display>(e: E) -> StoreError {
    StoreError::Backend(e.to_string())
}

/// The schema, authoritative. Every table is `IF NOT EXISTS` so `migrate()`
/// is idempotent and safe to run on every boot.
pub const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE COLLATE NOCASE,
  name TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  totp_secret BLOB,
  totp_confirmed INTEGER NOT NULL DEFAULT 0,
  admin INTEGER NOT NULL DEFAULT 0,
  disabled INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS invites (
  token TEXT PRIMARY KEY,
  email TEXT NOT NULL,
  invited_by TEXT,
  admin INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  accepted_at TEXT
);
CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  revoked_at TEXT
);
CREATE TABLE IF NOT EXISTS oidc_clients (
  client_id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  secret_hash TEXT NOT NULL,
  redirect_uris TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS auth_codes (
  code_hash TEXT PRIMARY KEY,
  client_id TEXT NOT NULL REFERENCES oidc_clients(client_id),
  user_id TEXT NOT NULL REFERENCES users(id),
  redirect_uri TEXT NOT NULL,
  nonce TEXT,
  code_challenge TEXT NOT NULL,
  session_hash TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  consumed_at TEXT
);
CREATE TABLE IF NOT EXISTS refresh_tokens (
  token_hash TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  client_id TEXT NOT NULL REFERENCES oidc_clients(client_id),
  session_hash TEXT NOT NULL REFERENCES sessions(token_hash),
  expires_at TEXT NOT NULL,
  revoked_at TEXT
);
CREATE TABLE IF NOT EXISTS signing_keys (
  kid TEXT PRIMARY KEY,
  private_der_enc BLOB NOT NULL,
  public_der BLOB NOT NULL,
  created_at TEXT NOT NULL,
  active INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS app_sessions (
  token_hash TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  client_id TEXT NOT NULL REFERENCES oidc_clients(client_id),
  session_hash TEXT NOT NULL REFERENCES sessions(token_hash),
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  revoked_at TEXT
);
CREATE TABLE IF NOT EXISTS events (
  id TEXT PRIMARY KEY,
  at TEXT NOT NULL,
  kind TEXT NOT NULL,
  actor TEXT,
  detail TEXT
);
CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
";

/// One database handle with the at-rest key beside it. Turso is a
/// single-writer engine; one connection per store, like izlek-core.
pub struct Store {
    pub(crate) conn: Connection,
    pub(crate) key: Key,
}

impl Store {
    /// Opens (creating if needed) the database at `path` and runs the schema
    /// migration. `:memory:` gives a test store with a fresh throwaway key.
    pub async fn open(path: &Path) -> Result<Store> {
        let raw = path
            .to_str()
            .ok_or_else(|| StoreError::Corrupt("path is not utf-8".into()))?;
        let db = Builder::new_local(raw).build().await.map_err(backend)?;
        let conn = db.connect().map_err(backend)?;
        let store = Store {
            conn,
            key: load_key(path)?,
        };
        store.migrate().await?;
        Ok(store)
    }

    /// Applies the schema inside one immediate transaction; safe to re-run.
    pub async fn migrate(&self) -> Result<()> {
        self.conn
            .execute("BEGIN IMMEDIATE", ())
            .await
            .map_err(backend)?;
        if let Err(e) = self.conn.execute_batch(SCHEMA).await {
            let _ = self.conn.execute("ROLLBACK", ()).await;
            return Err(backend(e));
        }
        self.conn.execute("COMMIT", ()).await.map_err(backend)?;
        Ok(())
    }

    /// The at-rest encryption key for this database.
    pub(crate) fn key(&self) -> &Key {
        &self.key
    }

    /// Seals a small value for a cookie (the pending-login marker), so its
    /// contents are neither readable nor forgeable client-side.
    pub fn seal_value(&self, plaintext: &[u8]) -> String {
        secret::seal(&self.key, plaintext)
    }

    /// Reverses [`Store::seal_value`]; `None` for anything we did not seal.
    pub fn open_value(&self, sealed: &str) -> Option<Vec<u8>> {
        secret::open(&self.key, sealed)
    }
}

/// The key for `path`'s database. `:memory:` has no directory to anchor a
/// sibling file to, so it gets a key generated fresh in memory — every
/// in-memory store is its own, unrelated encryption domain.
fn load_key(path: &Path) -> Result<Key> {
    if path.as_os_str() == ":memory:" {
        let mut key = [0u8; secret::KEY_BYTES];
        rand::Rng::fill_bytes(&mut rand::rng(), &mut key);
        return Ok(key);
    }
    let dir = path
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    secret::load_or_create_key(&dir.join("im.key")).map_err(StoreError::Io)
}

pub(crate) fn now() -> OffsetDateTime {
    OffsetDateTime::now_utc()
}

pub(crate) fn stamp(at: OffsetDateTime) -> Result<String> {
    at.format(&Rfc3339)
        .map_err(|e| StoreError::Corrupt(format!("timestamp: {e}")))
}

pub(crate) fn parse_stamp(raw: &str) -> Result<OffsetDateTime> {
    OffsetDateTime::parse(raw, &Rfc3339)
        .map_err(|e| StoreError::Corrupt(format!("timestamp {raw:?}: {e}")))
}

pub(crate) fn text(row: &Row, idx: usize) -> Result<String> {
    row.get::<String>(idx).map_err(backend)
}

pub(crate) fn opt_text(row: &Row, idx: usize) -> Result<Option<String>> {
    row.get::<Option<String>>(idx).map_err(backend)
}
pub(crate) fn int(row: &Row, idx: usize) -> Result<i64> {
    row.get::<i64>(idx).map_err(backend)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn migrate_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("im.db");
        let store = Store::open(&path).await.unwrap();
        store.migrate().await.unwrap();
        store.migrate().await.unwrap();
        let mut rows = store
            .conn
            .query("SELECT name FROM sqlite_master WHERE type = 'table'", ())
            .await
            .unwrap();
        let mut tables = Vec::new();
        while let Some(row) = rows.next().await.unwrap() {
            tables.push(text(&row, 0).unwrap());
        }
        for expected in [
            "users",
            "invites",
            "sessions",
            "oidc_clients",
            "auth_codes",
            "refresh_tokens",
            "signing_keys",
        ] {
            assert!(tables.contains(&expected.to_string()), "missing {expected}");
        }
    }

    #[tokio::test]
    async fn key_file_lives_beside_database() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("im.db");
        let _store = Store::open(&path).await.unwrap();
        assert!(dir.path().join("im.key").exists());
    }
}
