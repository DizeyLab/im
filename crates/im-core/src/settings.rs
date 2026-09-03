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
        .unwrap_or(587);
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

/// One probe of the sender, as izlek records it: when it ran, how long the
/// handshake took, and what the server said if it refused. `error: None` is
/// a pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SenderCheck {
    pub at: time::OffsetDateTime,
    pub took_ms: u64,
    pub error: Option<String>,
}

/// What the panel can claim about the sender right now. Saved settings wipe
/// the recorded check, so "Connected" can never outlive the settings it
/// proved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Standing {
    NotConfigured,
    Unchecked,
    Connected {
        at: time::OffsetDateTime,
        took_ms: u64,
    },
    Refused {
        at: time::OffsetDateTime,
        said: String,
    },
}

/// The sender's standing: settings plus the last probe, folded.
pub async fn standing(store: &Store) -> Result<Standing> {
    if !smtp(store).await?.configured() {
        return Ok(Standing::NotConfigured);
    }
    let Some(check) = last_check(store).await? else {
        return Ok(Standing::Unchecked);
    };
    Ok(match check.error {
        None => Standing::Connected {
            at: check.at,
            took_ms: check.took_ms,
        },
        Some(said) => Standing::Refused { at: check.at, said },
    })
}

/// Writes down what a probe saw. The error text is built from what the
/// server said, never from the credentials we sent — safe to store and show.
pub async fn record_check(store: &Store, check: &SenderCheck) -> Result<()> {
    set(
        store,
        "smtp_check_at",
        &check
            .at
            .format(&time::format_description::well_known::Rfc3339)
            .map_err(backend)?,
    )
    .await?;
    set(store, "smtp_check_ms", &check.took_ms.to_string()).await?;
    set(
        store,
        "smtp_check_error",
        check.error.as_deref().unwrap_or(""),
    )
    .await?;
    Ok(())
}

/// The last recorded probe, if any.
pub async fn last_check(store: &Store) -> Result<Option<SenderCheck>> {
    let Some(at) = get(store, "smtp_check_at").await? else {
        return Ok(None);
    };
    let at = time::OffsetDateTime::parse(&at, &time::format_description::well_known::Rfc3339)
        .map_err(backend)?;
    let took_ms = get(store, "smtp_check_ms")
        .await?
        .and_then(|raw| raw.parse().ok())
        .unwrap_or(0);
    let error = get(store, "smtp_check_error")
        .await?
        .filter(|said| !said.is_empty());
    Ok(Some(SenderCheck { at, took_ms, error }))
}

/// A saved sender cannot borrow the last probe's verdict: the check is
/// cleared on every settings write, like izlek's.
async fn clear_check(store: &Store) -> Result<()> {
    for key in ["smtp_check_at", "smtp_check_ms", "smtp_check_error"] {
        store
            .conn
            .execute("DELETE FROM settings WHERE key = ?1", turso::params![key])
            .await
            .map_err(backend)?;
    }
    Ok(())
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
            "smtp_check_at",
            "smtp_check_ms",
            "smtp_check_error",
        ] {
            store
                .conn
                .execute("DELETE FROM settings WHERE key = ?1", turso::params![key])
                .await
                .map_err(backend)?;
        }
        return Ok(());
    }
    // A saved sender cannot borrow the last probe's verdict.
    clear_check(store).await?;
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
        assert_eq!(smtp(&store).await.unwrap().port, 587);

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

    #[tokio::test]
    async fn check_records_and_a_save_wipes_it() {
        let store = Store::open(Path::new(":memory:")).await.unwrap();
        assert_eq!(standing(&store).await.unwrap(), Standing::NotConfigured);

        let value = Smtp {
            host: "smtp.example.com".into(),
            port: 587,
            username: "auth@example.com".into(),
            from: "im <auth@example.com>".into(),
            password: None,
        };
        set_smtp(&store, &value, Some("s3cret")).await.unwrap();
        assert_eq!(standing(&store).await.unwrap(), Standing::Unchecked);

        record_check(
            &store,
            &SenderCheck {
                at: time::OffsetDateTime::now_utc(),
                took_ms: 142,
                error: None,
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            standing(&store).await.unwrap(),
            Standing::Connected { took_ms: 142, .. }
        ));

        record_check(
            &store,
            &SenderCheck {
                at: time::OffsetDateTime::now_utc(),
                took_ms: 0,
                error: Some("the mail server did not answer in time".into()),
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            standing(&store).await.unwrap(),
            Standing::Refused { .. }
        ));

        // A new save cannot borrow the old probe's verdict.
        set_smtp(&store, &value, None).await.unwrap();
        assert_eq!(standing(&store).await.unwrap(), Standing::Unchecked);
        assert!(last_check(&store).await.unwrap().is_none());
    }
}
