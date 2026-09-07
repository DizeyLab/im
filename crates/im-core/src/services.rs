//! The family: the services every topbar shows as wordmarks and the
//! landing's services home. The list lives in the database and the admin
//! panel owns it — seeded once from the config's `[[services]]` on first
//! boot, edited from the landing (add, rename, reorder, remove), and served
//! to the sibling apps over `GET /family`, which each mirrors into its own
//! database.

use serde::Serialize;

use crate::store::{self, Result, Store, StoreError, backend};

/// One service of the family: the wordmark `key` ("in", "im", "iz" — or a
/// later sibling; the key rules are mechanical, not a fixed trio), the
/// human `name`, and the absolute base `url` without a trailing slash.
/// `position` is the stored order and never leaves this module — readers
/// get the list already ordered.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Service {
    pub key: String,
    pub name: String,
    pub url: String,
}

/// The form-level rules every stored row obeys: a key of lowercase ASCII
/// letters, digits, and dashes; a non-empty name; an absolute http(s) URL.
/// Returns the reason a value is refused — the panel shows it as its one
/// generic refusal, the exact words stay a store matter.
pub fn validate(key: &str, name: &str, url: &str) -> std::result::Result<(), String> {
    if key.is_empty()
        || !key
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Err(format!(
            "key {key:?} must be lowercase letters, digits, or dashes"
        ));
    }
    if name.trim().is_empty() {
        return Err("name must not be empty".to_string());
    }
    let trimmed = url.trim_end_matches('/');
    let Some(rest) = trimmed
        .strip_prefix("http://")
        .or_else(|| trimmed.strip_prefix("https://"))
    else {
        return Err(format!("url {url:?} must be an http(s) URL"));
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.is_empty() {
        return Err(format!("url {url:?} must name a host"));
    }
    if trimmed
        .chars()
        .any(|c| c.is_whitespace() || c.is_control())
    {
        return Err(format!(
            "url {url:?} must not carry spaces or control characters"
        ));
    }
    Ok(())
}

/// The one doorway every write passes: [`validate`], with the URL in its
/// stored form — no trailing slash.
fn checked(service: &Service) -> Result<String> {
    validate(&service.key, &service.name, &service.url).map_err(StoreError::Invalid)?;
    Ok(service.url.trim_end_matches('/').to_string())
}

/// Every service, in the stored order — the one order the trio, the landing
/// cards, and `/family` all render in.
pub async fn list(store: &Store) -> Result<Vec<Service>> {
    let conn = store.conn.lock().await;
    let mut rows = conn
        .query(
            "SELECT key, name, url FROM services ORDER BY position, key",
            (),
        )
        .await
        .map_err(backend)?;
    let mut services = Vec::new();
    while let Some(row) = rows.next().await.map_err(backend)? {
        services.push(Service {
            key: store::text(&row, 0)?,
            name: store::text(&row, 1)?,
            url: store::text(&row, 2)?,
        });
    }
    Ok(services)
}

/// Appends a service at the end of the family. A key already on the list is
/// refused — the add form is the only writer, and a silent overwrite would
/// surprise it.
pub async fn add(store: &Store, service: &Service) -> Result<()> {
    let url = checked(service)?;
    let conn = store.conn.lock().await;
    let mut rows = conn
        .query(
            "SELECT 1 FROM services WHERE key = ?1",
            turso::params![service.key.as_str()],
        )
        .await
        .map_err(backend)?;
    let taken = rows.next().await.map_err(backend)?.is_some();
    drop(rows);
    if taken {
        return Err(StoreError::Invalid(format!(
            "service key {:?} is already on the list",
            service.key
        )));
    }
    conn.execute(
        "INSERT INTO services (key, name, url, position) \
             VALUES (?1, ?2, ?3, (SELECT COALESCE(MAX(position), -1) + 1 FROM services))",
        turso::params![service.key.as_str(), service.name.trim(), url.as_str()],
    )
    .await
    .map_err(backend)?;
    Ok(())
}

/// Rewrites a service's name and address. The key travels in the form's
/// hidden field and is not editable; a key not on the list is refused, so a
/// form posted against a since-removed row cannot resurrect it.
pub async fn edit(store: &Store, key: &str, name: &str, url: &str) -> Result<()> {
    validate(key, name, url).map_err(StoreError::Invalid)?;
    let url = url.trim_end_matches('/');
    let conn = store.conn.lock().await;
    let updated = conn
        .execute(
            "UPDATE services SET name = ?2, url = ?3 WHERE key = ?1",
            turso::params![key, name.trim(), url],
        )
        .await
        .map_err(backend)?;
    if updated == 0 {
        return Err(StoreError::Invalid(format!("no service keyed {key:?}")));
    }
    Ok(())
}

/// Takes a service off the list and closes the gap: every later row slides
/// down one, so positions stay contiguous and the next add appends cleanly.
/// A key not on the list is a no-op — the panel only offers existing rows.
pub async fn remove(store: &Store, key: &str) -> Result<()> {
    let conn = store.conn.lock().await;
    let mut rows = conn
        .query(
            "SELECT position FROM services WHERE key = ?1",
            turso::params![key],
        )
        .await
        .map_err(backend)?;
    let Some(row) = rows.next().await.map_err(backend)? else {
        return Ok(());
    };
    let position = store::int(&row, 0)?;
    drop(rows);
    conn.execute(
        "DELETE FROM services WHERE key = ?1",
        turso::params![key],
    )
    .await
    .map_err(backend)?;
    conn.execute(
        "UPDATE services SET position = position - 1 WHERE position > ?1",
        turso::params![position],
    )
    .await
    .map_err(backend)?;
    Ok(())
}

/// Swaps a service one slot toward the front (`up`) or the back. An edge
/// row has no neighbor in that direction and the list is left alone.
pub async fn move_service(store: &Store, key: &str, up: bool) -> Result<()> {
    let conn = store.conn.lock().await;
    let mut rows = conn
        .query(
            "SELECT position FROM services WHERE key = ?1",
            turso::params![key],
        )
        .await
        .map_err(backend)?;
    let Some(row) = rows.next().await.map_err(backend)? else {
        return Ok(());
    };
    let position = store::int(&row, 0)?;
    drop(rows);
    let mut neighbor = if up {
        conn.query(
            "SELECT key, position FROM services WHERE position < ?1 \
                 ORDER BY position DESC LIMIT 1",
            turso::params![position],
        )
        .await
        .map_err(backend)?
    } else {
        conn.query(
            "SELECT key, position FROM services WHERE position > ?1 \
                 ORDER BY position ASC LIMIT 1",
            turso::params![position],
        )
        .await
        .map_err(backend)?
    };
    let Some(row) = neighbor.next().await.map_err(backend)? else {
        return Ok(());
    };
    let other_key = store::text(&row, 0)?;
    let other_position = store::int(&row, 1)?;
    drop(neighbor);
    conn.execute(
        "UPDATE services SET position = ?1 WHERE key = ?2",
        turso::params![other_position, key],
    )
    .await
    .map_err(backend)?;
    conn.execute(
        "UPDATE services SET position = ?1 WHERE key = ?2",
        turso::params![position, other_key],
    )
    .await
    .map_err(backend)?;
    Ok(())
}

/// The one-time seed: a database with no services yet takes the config's
/// list as the starting rows, in the order the file names them. After that
/// the panel owns the list and the same config is ignored — the `false`
/// return tells the boot it did nothing.
pub async fn seed_from(store: &Store, seed: &[Service]) -> Result<bool> {
    if !list(store).await?.is_empty() {
        return Ok(false);
    }
    let conn = store.conn.lock().await;
    for (position, service) in seed.iter().enumerate() {
        let url = checked(service)?;
        conn.execute(
            "INSERT OR IGNORE INTO services (key, name, url, position) \
                 VALUES (?1, ?2, ?3, ?4)",
            turso::params![
                service.key.as_str(),
                service.name.trim(),
                url.as_str(),
                position as i64
            ],
        )
        .await
        .map_err(backend)?;
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;
    use crate::store::StoreError;

    async fn store() -> Store {
        Store::open(Path::new(":memory:")).await.unwrap()
    }

    fn service(key: &str, name: &str, url: &str) -> Service {
        Service {
            key: key.to_string(),
            name: name.to_string(),
            url: url.to_string(),
        }
    }

    async fn keys(store: &Store) -> Vec<String> {
        list(store).await.unwrap().into_iter().map(|s| s.key).collect()
    }

    #[tokio::test]
    async fn the_seed_fills_an_empty_table_once_and_then_hands_over() {
        let store = store().await;
        let seed = vec![
            service("in", "Files", "http://127.0.0.1:7655/"),
            service("im", "Account", "http://127.0.0.1:7650"),
        ];
        assert!(seed_from(&store, &seed).await.unwrap());
        // A trailing slash in the file is not in the table: the stored form
        // is slash-free, everywhere.
        assert_eq!(list(&store).await.unwrap()[0].url, "http://127.0.0.1:7655");
        // The panel renamed the first entry; a re-boot with the same config
        // must not bring the old name back.
        edit(&store, "in", "Renamed", "http://127.0.0.1:7655")
            .await
            .unwrap();
        assert!(!seed_from(&store, &seed).await.unwrap());
        assert_eq!(list(&store).await.unwrap()[0].name, "Renamed");
    }

    #[tokio::test]
    async fn add_appends_edit_rewrites_and_a_taken_key_is_refused() {
        let store = store().await;
        seed_from(
            &store,
            &[service("im", "Account", "http://127.0.0.1:7650")],
        )
        .await
        .unwrap();
        add(&store, &service("in", "Files", "http://127.0.0.1:7655"))
            .await
            .unwrap();
        add(&store, &service("in", "Again", "http://elsewhere/"))
            .await
            .err()
            .unwrap_or_else(|| panic!("a taken key must be refused"));
        // The refused add changed nothing.
        assert_eq!(keys(&store).await, vec!["im".to_string(), "in".to_string()]);
        edit(&store, "in", "Dosyalar", "https://in.example")
            .await
            .unwrap();
        let services = list(&store).await.unwrap();
        assert_eq!(services[1].name, "Dosyalar");
        assert_eq!(services[1].url, "https://in.example");
        // A form posted against a since-removed key cannot resurrect it.
        remove(&store, "in").await.unwrap();
        assert!(matches!(
            edit(&store, "in", "Zombie", "https://in.example").await,
            Err(StoreError::Invalid(_))
        ));
        assert_eq!(keys(&store).await, vec!["im".to_string()]);
    }

    #[tokio::test]
    async fn moving_swaps_with_the_neighbor_and_edges_stay_put() {
        let store = store().await;
        seed_from(
            &store,
            &[
                service("in", "Files", "http://127.0.0.1:7655"),
                service("im", "Account", "http://127.0.0.1:7650"),
                service("iz", "Board", "http://127.0.0.1:7654"),
            ],
        )
        .await
        .unwrap();
        move_service(&store, "iz", true).await.unwrap();
        assert_eq!(
            keys(&store).await,
            vec!["in".to_string(), "iz".to_string(), "im".to_string()]
        );
        // The front edge has nothing above it; the list does not move.
        move_service(&store, "in", true).await.unwrap();
        assert_eq!(
            keys(&store).await,
            vec!["in".to_string(), "iz".to_string(), "im".to_string()]
        );
        move_service(&store, "in", false).await.unwrap();
        assert_eq!(
            keys(&store).await,
            vec!["iz".to_string(), "in".to_string(), "im".to_string()]
        );
    }

    #[tokio::test]
    async fn removing_closes_the_gap_so_the_next_add_appends_last() {
        let store = store().await;
        seed_from(
            &store,
            &[
                service("in", "Files", "http://127.0.0.1:7655"),
                service("im", "Account", "http://127.0.0.1:7650"),
                service("iz", "Board", "http://127.0.0.1:7654"),
            ],
        )
        .await
        .unwrap();
        remove(&store, "im").await.unwrap();
        remove(&store, "im").await.unwrap(); // already gone: a no-op
        add(&store, &service("wiki", "Wiki", "http://wiki")).await.unwrap();
        assert_eq!(
            keys(&store).await,
            vec!["in".to_string(), "iz".to_string(), "wiki".to_string()]
        );
    }

    #[tokio::test]
    async fn the_value_rules_refuse_garbage_before_the_database_sees_it() {
        assert!(validate("in", "Files", "http://in.example").is_ok());
        assert!(validate("In", "Files", "http://in.example").is_err(), "uppercase key");
        assert!(validate("in!", "Files", "http://in.example").is_err(), "punctuated key");
        assert!(validate("in", " ", "http://in.example").is_err(), "blank name");
        assert!(validate("in", "Files", "ftp://in.example").is_err(), "non-http url");
        assert!(validate("in", "Files", "http://").is_err(), "hostless url");
        assert!(validate("in", "Files", "http://in.example/path x").is_err(), "space in url");
        // A trailing slash is not garbage — it is normalized away.
        assert!(validate("in", "Files", "http://in.example/").is_ok());
    }
}
