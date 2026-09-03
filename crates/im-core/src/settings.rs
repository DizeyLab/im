//! Admin-managed settings in the database, sealed where they are secrets —
//! the same contract izlek-core's `store/secret.rs` keeps for SMTP. The TOML
//! config holds deployment facts (paths, listen, issuer); the settings table
//! holds what an admin rotates from the panel.

use crate::secret;
use crate::store::{self, Result, Store, backend};

/// The SMTP sender, as the panel sets it. `password` only ever comes back
/// opened; the row holds the sealed envelope.
#[derive(Debug, Clone, Default)]
pub struct Smtp {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub from: String,
    pub password: Option<String>,
}

impl Smtp {
    pub fn configured(&self) -> bool {
        !self.host.is_empty() && self.port > 0 && !self.from.is_empty()
    }
}

async fn get(store: &Store, key: &str) -> Result<Option<String>> {
    let mut rows = store
        .conn
        .query(
            "SELECT value FROM settings WHERE key = ?1",
            turso::params![key],
        )
        .await
        .map_err(backend)?;
    let Some(row) = rows.next().await.map_err(backend)? else {
        return Ok(None);
    };
    store::opt_text(&row, 0)
}

async fn set(store: &Store, key: &str, value: &str) -> Result<()> {
    store
        .conn
        .execute(
            "INSERT INTO settings (key, value) VALUES (?1, ?2) \
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            turso::params![key, value],
        )
        .await
        .map_err(backend)?;
    Ok(())
}

/// Reads the SMTP settings; a sealed password that no longer opens reads as
/// absent (wrong im.key, restored backup) — the same degradation izlek-core
/// chose.
pub async fn smtp(store: &Store) -> Result<Smtp> {
    let host = get(store, "smtp_host").await?.unwrap_or_default();
    let port = get(store, "smtp_port")
        .await?
        .and_then(|raw| raw.parse().ok())
        .unwrap_or(465);
    let username = get(store, "smtp_username").await?.unwrap_or_default();
    let from = get(store, "smtp_from").await?.unwrap_or_default();
    let password = get(store, "smtp_password")
        .await?
        .and_then(|sealed| secret::open(store.key(), &sealed))
        .and_then(|bytes| String::from_utf8(bytes).ok());
    Ok(Smtp {
        host,
        port,
        username,
        from,
        password,
    })
}

/// Writes the SMTP settings. `password: None` keeps the stored one — the
/// panel's password field is write-only, like izlek's.
pub async fn set_smtp(store: &Store, smtp: &Smtp, password: Option<&str>) -> Result<()> {
    if smtp.host.is_empty() {
        for key in [
            "smtp_host",
            "smtp_port",
            "smtp_username",
            "smtp_from",
            "smtp_password",
        ] {
            store
                .conn
                .execute("DELETE FROM settings WHERE key = ?1", turso::params![key])
                .await
                .map_err(backend)?;
        }
        return Ok(());
    }
    set(store, "smtp_host", &smtp.host).await?;
    set(store, "smtp_port", &smtp.port.to_string()).await?;
    set(store, "smtp_username", &smtp.username).await?;
    set(store, "smtp_from", &smtp.from).await?;
    if let Some(password) = password {
        if !password.is_empty() {
            set(
                store,
                "smtp_password",
                &secret::seal(store.key(), password.as_bytes()),
            )
            .await?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[tokio::test]
    async fn smtp_roundtrip_with_sealed_password() {
        let store = Store::open(Path::new(":memory:")).await.unwrap();
        assert!(!smtp(&store).await.unwrap().configured());

        let value = Smtp {
            host: "smtp.example.com".into(),
            port: 465,
            username: "im".into(),
            from: "im <auth@example.com>".into(),
            password: None,
        };
        set_smtp(&store, &value, Some("s3cret")).await.unwrap();
        let read = smtp(&store).await.unwrap();
        assert!(read.configured());
        assert_eq!(read.password.as_deref(), Some("s3cret"));

        // A write without a password keeps the stored one.
        set_smtp(&store, &value, None).await.unwrap();
        assert_eq!(
            smtp(&store).await.unwrap().password.as_deref(),
            Some("s3cret")
        );

        // An empty host clears the sender.
        set_smtp(&store, &Smtp::default(), None).await.unwrap();
        assert!(!smtp(&store).await.unwrap().configured());
    }

    #[tokio::test]
    async fn sealed_password_needs_the_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("im.db");
        {
            let store = Store::open(&path).await.unwrap();
            let value = Smtp {
                host: "smtp.example.com".into(),
                port: 465,
                username: String::new(),
                from: "a@b.c".into(),
                password: None,
            };
            set_smtp(&store, &value, Some("s3cret")).await.unwrap();
        }
        // A different key cannot open it.
        let sealed = {
            let store = Store::open(&path).await.unwrap();
            super::get(&store, "smtp_password").await.unwrap().unwrap()
        };
        assert!(secret::is_sealed(&sealed));
        let wrong_key = [9u8; 32];
        assert!(secret::open(&wrong_key, &sealed).is_none());
    }
}
