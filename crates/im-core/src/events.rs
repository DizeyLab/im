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

/// Log read filters, izlek's `ActivityFilter` shape: every present field
/// narrows (AND), an absent one matches all.
#[derive(Debug, Default, Clone)]
pub struct EventFilter {
    pub kind: Option<String>,
    pub actor: Option<String>,
    /// Free text against detail, actor and kind — ASCII case-folded
    /// substring, no wildcards, like izlek's board search but in SQL (the
    /// fold must live in the predicate or the keyset pages lie).
    pub q: Option<String>,
    /// Half-open day range `[from, to)`; both ends UTC stamps.
    pub day: Option<(time::OffsetDateTime, time::OffsetDateTime)>,
}

/// A place in the log: the ordered pair, never a row count — rows arrive
/// while the admin reads, and an offset lies the moment one lands.
#[derive(Debug, Clone)]
pub struct EventCursor {
    pub at: time::OffsetDateTime,
    pub id: String,
}

/// The window asked for: the freshest rows, the rows older than a cursor,
/// or the rows newer than one (walking back toward the top).
#[derive(Debug)]
pub enum EventPage {
    Newest,
    Before(EventCursor),
    After(EventCursor),
}

/// Read direction: newest-first is the default; Oldest flips both the
/// ordering and which side of a cursor Before/After mean.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dir {
    Newest,
    Oldest,
}

fn filter_sql(filter: &EventFilter, params: &mut Vec<turso::Value>) -> String {
    let mut sql = String::new();
    if let Some(kind) = &filter.kind {
        sql += " AND kind = ?";
        params.push(kind.clone().into());
    }
    if let Some(actor) = &filter.actor {
        sql += " AND actor = ?";
        params.push(actor.clone().into());
    }
    if let Some((from, to)) = &filter.day {
        sql += " AND at >= ? AND at < ?";
        params.push(store::stamp(*from).expect("rfc3339 of range start").into());
        params.push(store::stamp(*to).expect("rfc3339 of range end").into());
    }
    if let Some(q) = &filter.q {
        sql += " AND (lower(coalesce(detail, '')) LIKE ? OR lower(coalesce(actor, '')) LIKE ? OR lower(kind) LIKE ?)";
        let needle = q.to_lowercase();
        params.push(format!("%{needle}%").into());
        params.push(format!("%{needle}%").into());
        params.push(format!("%{needle}%").into());
    }
    sql
}

/// One window of the log under the filters. The caller asks for one row more
/// than the page shows: the extra row is the "there is more" signal, trimmed
/// before render. `After` reads the newer side in mirrored order and flips it
/// back in memory, so the page always presents in `dir` order.
pub async fn list_filtered(
    store: &Store,
    limit: i64,
    page: &EventPage,
    dir: Dir,
    filter: &EventFilter,
) -> Result<Vec<Event>> {
    let oldest = dir == Dir::Oldest;
    let base = if oldest { "ASC" } else { "DESC" };
    let mut params: Vec<turso::Value> = Vec::new();
    let mut sql = "SELECT id, at, kind, actor, detail FROM events WHERE 1=1".to_string();
    sql += &filter_sql(filter, &mut params);
    let mut reversed = false;
    match page {
        EventPage::Newest => {}
        EventPage::Before(cursor) => {
            let cmp = if oldest { ">" } else { "<" };
            sql += &format!(" AND (at {cmp} ? OR (at = ? AND id {cmp} ?))");
            let at = store::stamp(cursor.at)?;
            params.push(at.clone().into());
            params.push(at.into());
            params.push(cursor.id.clone().into());
        }
        EventPage::After(cursor) => {
            let cmp = if oldest { "<" } else { ">" };
            sql += &format!(" AND (at {cmp} ? OR (at = ? AND id {cmp} ?))");
            let at = store::stamp(cursor.at)?;
            params.push(at.clone().into());
            params.push(at.into());
            params.push(cursor.id.clone().into());
            reversed = true;
        }
    }
    let order = if reversed {
        if oldest { "DESC" } else { "ASC" }
    } else {
        base
    };
    sql += &format!(" ORDER BY at {order}, id {order} LIMIT ?");
    params.push(limit.into());
    let conn = store.conn.lock().await;
    let mut rows = conn
        .query(&sql, turso::params_from_iter(params))
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
    if reversed {
        events.reverse();
    }
    Ok(events)
}

/// How many rows the filters admit at all.
pub async fn count_filtered(store: &Store, filter: &EventFilter) -> Result<u64> {
    let mut params: Vec<turso::Value> = Vec::new();
    let mut sql = "SELECT COUNT(*) FROM events WHERE 1=1".to_string();
    sql += &filter_sql(filter, &mut params);
    let conn = store.conn.lock().await;
    let mut rows = conn
        .query(&sql, turso::params_from_iter(params))
        .await
        .map_err(backend)?;
    let count = match rows.next().await.map_err(backend)? {
        Some(row) => store::int(&row, 0)? as u64,
        None => 0,
    };
    Ok(count)
}

/// How many matching rows sit on the newer side of the page's top row — the
/// "X–Y" half of the position note. No cursor means the page starts at the
/// very top: nothing precedes it.
pub async fn count_preceding(
    store: &Store,
    filter: &EventFilter,
    dir: Dir,
    cursor: Option<&EventCursor>,
) -> Result<u64> {
    let Some(cursor) = cursor else { return Ok(0) };
    let cmp = if dir == Dir::Oldest { "<" } else { ">" };
    let mut params: Vec<turso::Value> = Vec::new();
    let mut sql = "SELECT COUNT(*) FROM events WHERE 1=1".to_string();
    sql += &filter_sql(filter, &mut params);
    sql += &format!(" AND (at {cmp} ? OR (at = ? AND id {cmp} ?))");
    let at = store::stamp(cursor.at)?;
    params.push(at.clone().into());
    params.push(at.into());
    params.push(cursor.id.clone().into());
    let conn = store.conn.lock().await;
    let mut rows = conn
        .query(&sql, turso::params_from_iter(params))
        .await
        .map_err(backend)?;
    let count = match rows.next().await.map_err(backend)? {
        Some(row) => store::int(&row, 0)? as u64,
        None => 0,
    };
    Ok(count)
}

/// The kind and actor dropdowns list what the log actually contains — im's
/// kinds are free strings, so the vocabulary is read, not hardcoded.
pub async fn distinct_kinds(store: &Store) -> Result<Vec<String>> {
    let conn = store.conn.lock().await;
    let mut rows = conn
        .query("SELECT DISTINCT kind FROM events ORDER BY kind", ())
        .await
        .map_err(backend)?;
    let mut kinds = Vec::new();
    while let Some(row) = rows.next().await.map_err(backend)? {
        kinds.push(store::text(&row, 0)?);
    }
    Ok(kinds)
}

pub async fn distinct_actors(store: &Store) -> Result<Vec<String>> {
    let conn = store.conn.lock().await;
    let mut rows = conn
        .query(
            "SELECT DISTINCT actor FROM events WHERE actor IS NOT NULL ORDER BY actor",
            (),
        )
        .await
        .map_err(backend)?;
    let mut actors = Vec::new();
    while let Some(row) = rows.next().await.map_err(backend)? {
        actors.push(store::text(&row, 0)?);
    }
    Ok(actors)
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
        let events = list_filtered(
            &store,
            10,
            &EventPage::Newest,
            Dir::Newest,
            &EventFilter::default(),
        )
        .await
        .unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].kind, "login_fail");
        assert_eq!(events[1].actor.as_deref(), Some("ann@example.com"));
        // Search: substring hits detail, actor and kind; a miss admits nothing.
        for (q, want) in [("password", 1), ("ann@", 1), ("login", 2), ("zzz", 0)] {
            let hits = list_filtered(
                &store,
                10,
                &EventPage::Newest,
                Dir::Newest,
                &EventFilter {
                    q: Some(q.to_string()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
            assert_eq!(hits.len(), want, "search {q:?}");
        }
    }

    #[tokio::test]
    async fn filtered_paging_walks_the_log() {
        let store = Store::open(Path::new(":memory:")).await.unwrap();
        for i in 0..7 {
            let kind = if i % 2 == 0 { "login_ok" } else { "logout" };
            log(&store, kind, Some("ann@example.com"), None).await;
        }
        let filter = EventFilter::default();
        // First page of three: newest rows, plus the has-more signal row.
        let first = list_filtered(&store, 4, &EventPage::Newest, Dir::Newest, &filter)
            .await
            .unwrap();
        assert_eq!(first.len(), 4);
        let cursor = EventCursor {
            at: first[2].at,
            id: first[2].id.clone(),
        };
        let second = list_filtered(
            &store,
            4,
            &EventPage::Before(cursor.clone()),
            Dir::Newest,
            &filter,
        )
        .await
        .unwrap();
        assert_eq!(second.len(), 4);
        assert!(second.iter().all(|e| e.at <= cursor.at));
        assert!(!second.iter().any(|e| e.id == cursor.id));
        // Walking back up returns the same top rows.
        let up = list_filtered(&store, 4, &EventPage::After(cursor), Dir::Newest, &filter)
            .await
            .unwrap();
        assert_eq!(up.len(), 2);
        assert_eq!(up.first().unwrap().id, first.first().unwrap().id);
        // Filters narrow, counts agree, and the position note's input exists.
        let only_logins = EventFilter {
            kind: Some("login_ok".into()),
            ..Default::default()
        };
        assert_eq!(count_filtered(&store, &only_logins).await.unwrap(), 4);
        assert_eq!(count_filtered(&store, &filter).await.unwrap(), 7);
        assert_eq!(
            count_preceding(
                &store,
                &filter,
                Dir::Newest,
                Some(&EventCursor {
                    at: first[1].at,
                    id: first[1].id.clone(),
                })
            )
            .await
            .unwrap(),
            1
        );
        assert_eq!(
            distinct_kinds(&store).await.unwrap(),
            vec!["login_ok", "logout"]
        );
        assert_eq!(
            distinct_actors(&store).await.unwrap(),
            vec!["ann@example.com"]
        );
    }
}
