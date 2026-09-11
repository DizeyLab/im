//! The live channel: one long-lived connection per open signed-in tab,
//! carrying the news that something changed — ported from iz's `live.rs`.
//!
//! What travels here is a bare tick — "the page moved, re-read it" — and one
//! addressed frame: a `revoked` event whose emptiness is the whole message,
//! sent only to the connection the eviction names. A revoked tab does not
//! re-read (its session would refuse it); it goes home. Everything else
//! stays nameless: the client re-fetches through the ordinary route, where
//! the ordinary gate answers.

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
pub(crate) const WINDOW: Duration = Duration::from_secs(50 * 60);

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

#[route(GET "/live")]
async fn live(cx: &Cx) -> topcoat::Result<Response> {
    // Resolved once, here, and never again for the life of this connection.
    // Both halves stay: the id and the session's token hash are the address
    // a `Revoked` announcement is checked against — the eviction news is
    // addressed, and this connection reads its own address off it.
    let Ok(user) = server::current_user(cx).await.ok_or(()) else {
        return (StatusCode::UNAUTHORIZED, "").into_response(cx);
    };
    let me = user.id.to_string();
    let mine = server::presented_session(cx)
        .as_deref()
        .map(im_core::accounts::hash_token);
    let rx = server::app(cx).live.subscribe();
    let stopping = topcoat::context::try_app_context::<Shutdown>(cx).map(|s| s.0.clone());
    let deadline = Instant::now() + WINDOW;

    let events = futures_util::stream::unfold(
        (rx, deadline, stopping, me, mine),
        |(mut rx, deadline, mut stopping, me, mine)| async move {
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
                    Ok(Some(Err(RecvError::Lagged(_))))
                    | Ok(Some(Ok(server::LiveEvent::Tick))) => break,
                    // One member's row changed. The frame names which one —
                    // im's own client still just re-fetches the page it is
                    // on, so the payload is forward-compatibility for a
                    // future page that can react to its own subject alone.
                    Ok(Some(Ok(server::LiveEvent::Profile(member)))) => {
                        return Some((
                            Ok::<_, std::convert::Infallible>(Event::new().data(
                                serde_json::json!({ "kind": "profile", "sub": member.sub })
                                    .to_string(),
                            )),
                            (rx, deadline, stopping, me, mine),
                        ));
                    }
                    // A sign-out in motion: every session of the named user,
                    // or the one named session. Addressed news — this
                    // connection answers only when it is the one evicted;
                    // anyone else's news is silence here.
                    Ok(Some(Ok(server::LiveEvent::Revoked {
                        user_id,
                        session_hash,
                    }))) => {
                        let evicted = session_hash
                            .as_deref()
                            .is_none_or(|hash| mine.as_deref() == Some(hash));
                        if user_id == me && evicted {
                            return Some((
                                Ok(Event::new().event("revoked").data("")),
                                (rx, deadline, stopping, me, mine),
                            ));
                        }
                    }
                }
            }
            Some((
                Ok::<_, std::convert::Infallible>(Event::new().data("{}")),
                (rx, deadline, stopping, me, mine),
            ))
        },
    );

    Sse::new(events.boxed())
        .keep_alive(KeepAlive::new())
        .into_response(cx)
}

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::pin::Pin;
    use std::sync::Arc;

    use futures_util::StreamExt as _;
    use im_core::accounts::{create_invite, create_user_from_invite, hash_token};
    use im_core::model::UserId;
    use im_core::sessions::{SessionMeta, create_session, resolve_session};
    use im_core::store::Store;
    use topcoat::cookie::RouterBuilderCookieExt as _;
    use topcoat::router::{
        Body, BodyDataStream, Router, RouterBuilderDiscoverExt as _, StatusCode, header, to_bytes,
    };

    use crate::config::Config;
    use crate::server::{self, SESSION_COOKIE};

    struct Setup {
        router: Router,
        store: Arc<Store>,
        admin_cookie: String,
        /// Ben's two sessions, by raw token — each opens its own `/live`
        /// connection through its cookie.
        ben_tokens: [String; 2],
        ben_id: UserId,
    }

    async fn setup() -> Setup {
        let store = Store::open(Path::new(":memory:")).await.unwrap();
        let admin_invite = create_invite(&store, "ada@example.com", None, true)
            .await
            .unwrap();
        let admin = create_user_from_invite(&store, admin_invite.expose(), "Ada", "tDLr9!mZQ2xv")
            .await
            .unwrap();
        let ben_invite = create_invite(&store, "ben@example.com", None, false)
            .await
            .unwrap();
        let ben = create_user_from_invite(&store, ben_invite.expose(), "Ben", "tDLr9!mZQ2xv")
            .await
            .unwrap();
        let admin_session = create_session(&store, &admin.id, &SessionMeta::default())
            .await
            .unwrap();
        let ben_a = create_session(&store, &ben.id, &SessionMeta::default())
            .await
            .unwrap();
        let ben_b = create_session(&store, &ben.id, &SessionMeta::default())
            .await
            .unwrap();
        let store = Arc::new(store);
        let app = server::App {
            store: store.clone(),
            config: Config {
                database: ":memory:".into(),
                listen: "127.0.0.1:7650".parse().unwrap(),
                issuer: "http://127.0.0.1:7650".into(),
                services: Vec::new(),
            },
            live: tokio::sync::broadcast::channel(64).0,
        };
        let router = Router::builder()
            .discover()
            .cookies()
            .app_context(app)
            .build();
        Setup {
            router,
            store,
            admin_cookie: format!("{SESSION_COOKIE}={}", admin_session.expose()),
            ben_tokens: [ben_a.expose().to_string(), ben_b.expose().to_string()],
            ben_id: ben.id,
        }
    }

    fn cookie(token: &str) -> String {
        format!("{SESSION_COOKIE}={token}")
    }

    /// A form post through the router, answered as (status, Location).
    async fn post_form(
        router: &Router,
        uri: &str,
        body: &str,
        cookie: Option<&str>,
    ) -> (StatusCode, Option<String>) {
        let mut builder = http::Request::builder()
            .method(http::Method::POST)
            .uri(uri)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
        if let Some(cookie) = cookie {
            builder = builder.header(header::COOKIE, cookie);
        }
        let response = router
            .handle(builder.body(Body::from(body.to_string())).unwrap())
            .await;
        let (parts, body) = response.into_parts();
        let location = parts
            .headers
            .get(header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let _ = to_bytes(body, usize::MAX).await.unwrap();
        (parts.status, location)
    }

    /// Opens `/live` as a signed-in tab would and pins the body's data
    /// stream. A single SSE frame may straddle two body frames, so callers
    /// accumulate text and match on substrings.
    async fn open_live(router: &Router, cookie: &str) -> Pin<Box<BodyDataStream>> {
        let response = router
            .handle(
                http::Request::builder()
                    .uri("/live")
                    .header(header::COOKIE, cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
        let (parts, body) = response.into_parts();
        assert_eq!(parts.status, StatusCode::OK);
        Box::pin(body.into_data_stream())
    }

    /// The next body frame off the stream, as text. Bounded, so a
    /// regression fails loudly instead of hanging the suite — under the
    /// single-threaded test runtime a plain park can miss the producer's
    /// wakeup entirely.
    async fn next_chunk(stream: &mut Pin<Box<BodyDataStream>>) -> String {
        let chunk = tokio::time::timeout(std::time::Duration::from_secs(10), stream.as_mut().next())
            .await
            .expect("a frame arrives in time")
            .expect("stream stays open")
            .expect("frames succeed");
        String::from_utf8_lossy(&chunk).into_owned()
    }

    /// Reads frames until `needle` appears, returning everything read.
    async fn read_until(stream: &mut Pin<Box<BodyDataStream>>, needle: &str) -> String {
        let mut wire = String::new();
        while !wire.contains(needle) {
            wire.push_str(&next_chunk(stream).await);
        }
        wire
    }

    /// The heart of the live logout: a revoke reaches the revoked session's
    /// own tab as an addressed `revoked` event, while a bystander's tab —
    /// on the same bus — hears only the tick the action logs. The
    /// bystander's read is the absence proof: frames arrive in send order,
    /// and the eviction news is sent before the tick, so a tick with no
    /// revoked frame before it means none was addressed here.
    #[tokio::test]
    async fn a_revoke_reaches_the_revoked_tab_and_not_a_bystanders() {
        let setup = setup().await;
        let mut ben = open_live(&setup.router, &cookie(&setup.ben_tokens[0])).await;
        let mut ada = open_live(&setup.router, &setup.admin_cookie).await;

        let (status, _) = post_form(
            &setup.router,
            "/admin/revoke",
            &format!("user={}", setup.ben_id),
            Some(&setup.admin_cookie),
        )
        .await;
        assert_eq!(status, StatusCode::SEE_OTHER);

        let wire = read_until(&mut ben, "event: revoked").await;
        assert!(wire.contains("event: revoked"), "{wire}");

        let wire = read_until(&mut ada, "data: {}").await;
        assert!(!wire.contains("event: revoked"), "{wire}");
    }

    /// A per-session revoke is aimed: the named session's tab hears its
    /// eviction, the same person's other tab hears only the tick.
    #[tokio::test]
    async fn a_session_revoke_spares_the_same_users_other_tab() {
        let setup = setup().await;
        let mut kept = open_live(&setup.router, &cookie(&setup.ben_tokens[0])).await;
        let mut killed = open_live(&setup.router, &cookie(&setup.ben_tokens[1])).await;

        let (status, _) = post_form(
            &setup.router,
            "/admin/session_revoke",
            &format!(
                "user={}&session={}",
                setup.ben_id,
                hash_token(&setup.ben_tokens[1])
            ),
            Some(&setup.admin_cookie),
        )
        .await;
        assert_eq!(status, StatusCode::SEE_OTHER);

        let wire = read_until(&mut killed, "event: revoked").await;
        assert!(wire.contains("event: revoked"), "{wire}");

        let wire = read_until(&mut kept, "data: {}").await;
        assert!(!wire.contains("event: revoked"), "{wire}");
    }

    /// The password change's courtesy: the browser that proved the old
    /// password keeps its tab — no revoked frame ever names its session —
    /// while every other session really dies.
    #[tokio::test]
    async fn a_password_change_keeps_the_asking_tab_signed_in() {
        let setup = setup().await;
        let mut asking = open_live(&setup.router, &cookie(&setup.ben_tokens[0])).await;

        let (status, location) = post_form(
            &setup.router,
            "/password",
            "current=tDLr9!mZQ2xv&password=n3w-Hard-Pass!9&password_confirm=n3w-Hard-Pass!9",
            Some(&cookie(&setup.ben_tokens[0])),
        )
        .await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        assert_eq!(location.as_deref(), Some("/?section=password&ok=password"));

        let wire = read_until(&mut asking, "data: {}").await;
        assert!(!wire.contains("event: revoked"), "{wire}");
        assert!(
            resolve_session(&setup.store, &setup.ben_tokens[0])
                .await
                .unwrap()
                .is_some(),
            "the asking session survives"
        );
        assert!(
            resolve_session(&setup.store, &setup.ben_tokens[1])
                .await
                .unwrap()
                .is_none(),
            "the other session dies"
        );
    }

    /// A disable is a sign-out too: the disabled account's tab hears the
    /// eviction on the spot. The roster half — the Profile frame carrying
    /// `disabled` — is asserted in directory.rs's stream test.
    #[tokio::test]
    async fn a_disable_reaches_the_disabled_tab() {
        let setup = setup().await;
        let mut ben = open_live(&setup.router, &cookie(&setup.ben_tokens[0])).await;

        let (status, _) = post_form(
            &setup.router,
            "/admin/disable",
            &format!("user={}", setup.ben_id),
            Some(&setup.admin_cookie),
        )
        .await;
        assert_eq!(status, StatusCode::SEE_OTHER);

        let wire = read_until(&mut ben, "event: revoked").await;
        assert!(wire.contains("event: revoked"), "{wire}");
    }

    /// A delete takes the person's sessions with them, and their tabs hear
    /// it like any other eviction.
    #[tokio::test]
    async fn a_delete_reaches_the_deleted_users_tab() {
        let setup = setup().await;
        let mut ben = open_live(&setup.router, &cookie(&setup.ben_tokens[0])).await;

        let (status, _) = post_form(
            &setup.router,
            "/admin/delete",
            &format!("user={}", setup.ben_id),
            Some(&setup.admin_cookie),
        )
        .await;
        assert_eq!(status, StatusCode::SEE_OTHER);

        let wire = read_until(&mut ben, "event: revoked").await;
        assert!(wire.contains("event: revoked"), "{wire}");
    }

    /// The live client's fallback probe: a bare status, no HTML — 204 when
    /// the session still stands, 401 when it does not.
    #[tokio::test]
    async fn the_me_probe_answers_a_bare_status() {
        let setup = setup().await;
        for (cookie, expected) in [
            (Some(setup.admin_cookie.as_str()), StatusCode::NO_CONTENT),
            (None, StatusCode::UNAUTHORIZED),
        ] {
            let mut builder = http::Request::builder().uri("/api/me");
            if let Some(cookie) = cookie {
                builder = builder.header(header::COOKIE, cookie);
            }
            let response = setup
                .router
                .handle(builder.body(Body::empty()).unwrap())
                .await;
            assert_eq!(response.into_parts().0.status, expected);
        }
    }
}
