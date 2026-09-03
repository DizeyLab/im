//! The audit log: one row per thing that happened to identity — logins,
//! refusals, invites, enrolments, revocations. The admin panel's Logs
//! section reads it; nothing here is a hot path (introspection is
//! deliberately NOT logged — it runs per request and would drown the rest).

use crate::store::{self, Result, Store, backend};

#[derive(Debug, Clone)]
pub struct Event {
    pub id: String,
    pub at: time::OffsetDateTime,
    pub kind: String,
    pub actor: Option<String>,
    pub detail: Option<String>,
}

/// Appends an event. Never fails the caller's operation: a log that cannot
/// be written is printed, not propagated.
pub async fn log(store: &Store, kind: &str, actor: Option<&str>, detail: Option<&str>) {
    let conn = store.conn.lock().await;
    let outcome = conn
        .execute(
            "INSERT INTO events (id, at, kind, actor, detail) VALUES (?1, ?2, ?3, ?4, ?5)",
            turso::params![
                ulid::Ulid::new().to_string(),
                store::stamp(store::now()).expect("rfc3339 of now"),
                kind,
                actor,
                detail,
            ],
        )
        .await;
    if let Err(e) = outcome {
        eprintln!("im event  {kind} ({actor:?}): could not be logged: {e}");
    }
}

/// Newest-first page of the log for the admin panel.
pub async fn list(store: &Store, limit: i64) -> Result<Vec<Event>> {
    let conn = store.conn.lock().await;
    let mut rows = conn
        .query(
            "SELECT id, at, kind, actor, detail FROM events ORDER BY at DESC, id DESC LIMIT ?1",
            turso::params![limit],
        )
        .await
        .map_err(backend)?;
    let mut events = Vec::new();
    while let Some(row) = rows.next().await.map_err(backend)? {
        events.push(Event {
            id: store::text(&row, 0)?,
            at: store::parse_stamp(&store::text(&row, 1)?)?,
            kind: store::text(&row, 2)?,
            actor: store::opt_text(&row, 3)?,
            detail: store::opt_text(&row, 4)?,
        });
    }
    Ok(events)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[tokio::test]
    async fn log_and_list_newest_first() {
        let store = Store::open(Path::new(":memory:")).await.unwrap();
        log(&store, "login_ok", Some("ann@example.com"), None).await;
        log(
            &store,
            "login_fail",
            Some("bob@example.com"),
            Some("wrong password"),
        )
        .await;
        let events = list(&store, 10).await.unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].kind, "login_fail");
        assert_eq!(events[1].actor.as_deref(), Some("ann@example.com"));
    }
}
