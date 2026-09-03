//! The live channel: one long-lived connection per open admin tab, carrying
//! the news that something changed — ported from iz's `live.rs`.
//!
//! What travels here is a bare tick and nothing else — never a row, never a
//! name. The client is told only *that* the panel moved, and re-fetches it
//! through the ordinary route, where the ordinary admin gate answers. The
//! route itself is admin-gated, and the whole panel behind it is admin-only,
//! so there is no per-topic filtering to get wrong.

use std::time::{Duration, Instant};

use futures_util::StreamExt;
use tokio::sync::broadcast::error::RecvError;
use topcoat::context::Cx;
use topcoat::router::content::sse::{Event, KeepAlive, Sse};
use topcoat::router::response::{IntoResponse, Response};
use topcoat::router::{StatusCode, route};

use crate::server;

/// How long one connection is held before the server ends it and the browser
/// opens another. The session is resolved once, at connect, and never again
/// for the life of the stream — the reconnect is what re-authenticates, so a
/// session revoked mid-stream goes quiet within one window rather than never.
const WINDOW: Duration = Duration::from_secs(50 * 60);

/// Tells a live stream that the process is going down.
///
/// Without this, stopping the server takes as long as its graceful shutdown
/// allows: the server stops accepting connections and then waits for
/// in-flight requests to finish, and an open live stream is an in-flight
/// request that intends to sit there for the whole window. Every open admin
/// tab is one. So the streams are told, and they end; the browser reconnects
/// when the server comes back, which is what it does after any dropped
/// connection.
#[derive(Clone)]
pub struct Shutdown(pub tokio::sync::watch::Receiver<bool>);

#[route(GET "/admin/live")]
async fn live(cx: &Cx) -> topcoat::Result<Response> {
    // Resolved once, here, and never again for the life of this connection.
    let Ok(_admin) = server::current_user(cx)
        .await
        .filter(|user| user.admin)
        .ok_or(())
    else {
        return (StatusCode::UNAUTHORIZED, "").into_response(cx);
    };
    let rx = server::app(cx).live.subscribe();
    let stopping = topcoat::context::try_app_context::<Shutdown>(cx).map(|s| s.0.clone());
    let deadline = Instant::now() + WINDOW;

    let events = futures_util::stream::unfold(
        (rx, deadline, stopping),
        |(mut rx, deadline, mut stopping)| async move {
            loop {
                // Already going down: end, so this connection is not one the
                // shutdown has to sit and wait out.
                if stopping.as_ref().is_some_and(|watch| *watch.borrow()) {
                    return None;
                }
                let left = deadline.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    return None;
                }
                // Three things end the wait: an announcement, the window
                // running out, and the server being told to stop. The third
                // is watched rather than polled, so SIGTERM is felt at once.
                let heard = tokio::time::timeout(left, async {
                    match stopping.as_mut() {
                        Some(watch) => tokio::select! {
                            _ = watch.changed() => None,
                            got = rx.recv() => Some(got),
                        },
                        None => Some(rx.recv().await),
                    }
                })
                .await;
                match heard {
                    // The window closed, or the server is stopping. Ending
                    // the stream is the point: the browser reconnects by
                    // itself and authenticates again.
                    Err(_) | Ok(None) => return None,
                    // The broadcaster is gone, which means the process is
                    // going with it.
                    Ok(Some(Err(RecvError::Closed))) => return None,
                    // This reader fell behind and announcements were dropped.
                    // Which ones is unknowable, so the tick says "re-read
                    // everything" — the client refetches the whole page, so
                    // a lagged tick and a plain tick are the same frame.
                    Ok(Some(Err(RecvError::Lagged(_)))) | Ok(Some(Ok(()))) => {}
                }
                return Some((
                    Ok::<_, std::convert::Infallible>(Event::new().data("{}")),
                    (rx, deadline, stopping),
                ));
            }
        },
    );

    Sse::new(events.boxed())
        .keep_alive(KeepAlive::new())
        .into_response(cx)
}
