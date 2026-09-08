//! The family: the services every topbar shows as wordmarks and the
//! landing's services home. The list lives in the database, seeded once from
//! the config's `[[services]]` on first boot and served to the sibling apps
//! over `GET /family`, which each mirrors into its own database.
//!
//! Names and order are the admin panel's. Addresses maintain themselves: an
//! app writes its own row through [`register`] — im from its `issuer` on
//! every boot, a sibling over `POST /family/register` — and a row an app
//! keeps is neither removed nor re-pointed from the panel, because the next
//! boot would undo it.

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
    /// The app that keeps this row — `SELF_OWNER` for im's own entry, a
    /// client id for a sibling that registered itself, `None` for a row the
    /// seed or the panel made. Never serialized: `/family`'s shape is the
    /// three public fields the siblings mirror, and nothing more.
    #[serde(skip)]
    pub owner: Option<String>,
}

/// The owner im writes on its own row, registered from `issuer` on every
/// boot — not a client id, because im is nobody's client.
pub const SELF_OWNER: &str = "im";

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
    if trimmed.chars().any(|c| c.is_whitespace() || c.is_control()) {
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
            "SELECT key, name, url, owner FROM services ORDER BY position, key",
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
            owner: store::opt_text(&row, 3)?,
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
/// A row an app keeps only takes its new name here: the address is the
/// app's own, rewritten on its every boot, so accepting one from the panel
/// would show an edit the next boot silently undoes.
pub async fn edit(store: &Store, key: &str, name: &str, url: &str) -> Result<()> {
    validate(key, name, url).map_err(StoreError::Invalid)?;
    let url = url.trim_end_matches('/');
    if let Some(row) = owned_row(store, key).await?
        && row.1.is_some()
        && row.0 != url
    {
        return Err(StoreError::Invalid(format!(
            "service {key:?} keeps its own address; its app re-registers it on every boot"
        )));
    }
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
/// A row an app keeps is not the panel's to take: it would come back on the
/// app's next boot.
pub async fn remove(store: &Store, key: &str) -> Result<()> {
    if let Some((_, Some(_))) = owned_row(store, key).await? {
        return Err(StoreError::Invalid(format!(
            "service {key:?} is kept by its app; it re-registers on every boot"
        )));
    }
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
    conn.execute("DELETE FROM services WHERE key = ?1", turso::params![key])
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

/// A row's stored `(url, owner)`, or `None` when no row carries the key.
async fn owned_row(store: &Store, key: &str) -> Result<Option<(String, Option<String>)>> {
    let conn = store.conn.lock().await;
    let mut rows = conn
        .query(
            "SELECT url, owner FROM services WHERE key = ?1",
            turso::params![key],
        )
        .await
        .map_err(backend)?;
    let Some(row) = rows.next().await.map_err(backend)? else {
        return Ok(None);
    };
    Ok(Some((store::text(&row, 0)?, store::opt_text(&row, 1)?)))
}

/// An app writing its own row: im from its `issuer` on every boot, a sibling
/// over `POST /family/register` with its client id as the `owner`. A key
/// nobody holds is appended (or claimed, keeping the name the seed or the
/// panel gave it); a key the caller already holds takes the new address
/// only — the name is the admin's after the first insert. A key another app
/// keeps is a conflict, never a takeover.
pub async fn register(
    store: &Store,
    key: &str,
    name: &str,
    url: &str,
    owner: &str,
) -> Result<Service> {
    validate(key, name, url).map_err(StoreError::Invalid)?;
    let url = url.trim_end_matches('/').to_string();
    match owned_row(store, key).await? {
        Some((_, Some(held))) if held != owner => {
            return Err(StoreError::Conflict(format!(
                "service key {key:?} belongs to another app"
            )));
        }
        Some(_) => {
            // Claiming an unowned row or refreshing our own: the address is
            // the app's to say, the name stays whatever is stored.
            let conn = store.conn.lock().await;
            conn.execute(
                "UPDATE services SET url = ?2, owner = ?3 WHERE key = ?1",
                turso::params![key, url.as_str(), owner],
            )
            .await
            .map_err(backend)?;
        }
        None => {
            let conn = store.conn.lock().await;
            conn.execute(
                "INSERT INTO services (key, name, url, position, owner) \
                     VALUES (?1, ?2, ?3, (SELECT COALESCE(MAX(position), -1) + 1 FROM services), ?4)",
                turso::params![key, name.trim(), url.as_str(), owner],
            )
            .await
            .map_err(backend)?;
        }
    }
    let row = list(store)
        .await?
        .into_iter()
        .find(|service| service.key == key)
        .ok_or_else(|| StoreError::Backend(format!("service {key:?} vanished after its write")))?;
    Ok(row)
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
            owner: None,
        }
    }

    async fn keys(store: &Store) -> Vec<String> {
        list(store)
            .await
            .unwrap()
            .into_iter()
            .map(|s| s.key)
            .collect()
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
        seed_from(&store, &[service("im", "Account", "http://127.0.0.1:7650")])
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
        add(&store, &service("wiki", "Wiki", "http://wiki"))
            .await
            .unwrap();
        assert_eq!(
            keys(&store).await,
            vec!["in".to_string(), "iz".to_string(), "wiki".to_string()]
        );
    }

    #[tokio::test]
    async fn the_value_rules_refuse_garbage_before_the_database_sees_it() {
        assert!(validate("in", "Files", "http://in.example").is_ok());
        assert!(
            validate("In", "Files", "http://in.example").is_err(),
            "uppercase key"
        );
        assert!(
            validate("in!", "Files", "http://in.example").is_err(),
            "punctuated key"
        );
        assert!(
            validate("in", " ", "http://in.example").is_err(),
            "blank name"
        );
        assert!(
            validate("in", "Files", "ftp://in.example").is_err(),
            "non-http url"
        );
        assert!(validate("in", "Files", "http://").is_err(), "hostless url");
        assert!(
            validate("in", "Files", "http://in.example/path x").is_err(),
            "space in url"
        );
        // A trailing slash is not garbage — it is normalized away.
        assert!(validate("in", "Files", "http://in.example/").is_ok());
    }

    #[tokio::test]
    async fn an_app_registers_itself_appending_then_claiming_then_refreshing() {
        let store = store().await;
        // Nothing on the list yet: the app's own row is appended.
        let row = register(
            &store,
            "im",
            "Account",
            "http://127.0.0.1:7650/",
            SELF_OWNER,
        )
        .await
        .unwrap();
        assert_eq!(
            row.url, "http://127.0.0.1:7650",
            "the slash is normalized off"
        );
        assert_eq!(row.owner.as_deref(), Some(SELF_OWNER));

        // A seeded row belongs to nobody; the app that names it claims it,
        // keeping the name the seed (or a later rename) gave it.
        add(&store, &service("in", "Dosyalar", "http://127.0.0.1:7655"))
            .await
            .unwrap();
        let row = register(&store, "in", "Files", "https://in.example", "in-client")
            .await
            .unwrap();
        assert_eq!(row.name, "Dosyalar", "the name stays the admin's");
        assert_eq!(row.url, "https://in.example");
        assert_eq!(row.owner.as_deref(), Some("in-client"));

        // The same app's next boot moves the address only.
        let row = register(&store, "in", "Whatever", "https://in.dizey.sh", "in-client")
            .await
            .unwrap();
        assert_eq!(row.name, "Dosyalar");
        assert_eq!(row.url, "https://in.dizey.sh");
        // And no row was duplicated by any of it.
        assert_eq!(keys(&store).await, vec!["im".to_string(), "in".to_string()]);
    }

    #[tokio::test]
    async fn a_key_another_app_keeps_is_a_conflict_and_the_row_is_untouched() {
        let store = store().await;
        register(&store, "in", "Files", "https://in.example", "in-client")
            .await
            .unwrap();
        assert!(matches!(
            register(&store, "in", "Files", "https://evil.example", "iz-client").await,
            Err(StoreError::Conflict(_))
        ));
        assert_eq!(list(&store).await.unwrap()[0].url, "https://in.example");
    }

    #[tokio::test]
    async fn the_panel_cannot_remove_an_owned_row_or_move_its_address() {
        let store = store().await;
        register(&store, "in", "Files", "https://in.example", "in-client")
            .await
            .unwrap();
        assert!(matches!(
            remove(&store, "in").await,
            Err(StoreError::Invalid(_))
        ));
        assert!(matches!(
            edit(&store, "in", "Dosyalar", "https://elsewhere.example").await,
            Err(StoreError::Invalid(_))
        ));
        // The name is still the admin's, and a name-only edit lands.
        edit(&store, "in", "Dosyalar", "https://in.example")
            .await
            .unwrap();
        let row = &list(&store).await.unwrap()[0];
        assert_eq!(row.name, "Dosyalar");
        assert_eq!(row.url, "https://in.example");
        // An unowned row is still the panel's to take.
        add(&store, &service("wiki", "Wiki", "http://wiki"))
            .await
            .unwrap();
        remove(&store, "wiki").await.unwrap();
        assert_eq!(keys(&store).await, vec!["in".to_string()]);
    }

    #[tokio::test]
    async fn the_family_json_never_carries_the_owner() {
        let store = store().await;
        register(&store, "im", "Account", "http://127.0.0.1:7650", SELF_OWNER)
            .await
            .unwrap();
        let json = serde_json::to_value(list(&store).await.unwrap()).unwrap();
        let row = &json.as_array().unwrap()[0];
        assert_eq!(
            row.as_object().unwrap().keys().collect::<Vec<_>>(),
            vec!["key", "name", "url"],
            "the sibling mirrors deserialize this shape: {json}"
        );
    }
}
