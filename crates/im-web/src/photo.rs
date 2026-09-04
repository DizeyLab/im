//! Profile photo upload, removal and serving — the landing's profile card
//! is their only reader. Adapted from izlek-web's `photo.rs`; the refusal
//! answer is im's, though: a plain 303 whose query names the code, which the
//! landing reads back on render.

use std::collections::HashMap;
use std::sync::{Arc, LazyLock};

use im_core::photos;
use parking_lot::Mutex;
use time::OffsetDateTime;
use topcoat::context::{Cx, try_app_context};
use topcoat::router::content::multipart::Multipart;
use topcoat::router::request::headers as request_headers;
use topcoat::router::{HeaderMap, HeaderValue, StatusCode, header, path_param, route};

use crate::auth::{Redirect, see};
use crate::server;

path_param!(user_id);

/// The upload ceiling: big enough for any sane avatar, small enough that a
/// form post cannot park the connection. The router's body limit carries the
/// same number so an oversized body dies before it is even parsed.
pub const PHOTO_LIMIT_BYTES: u64 = 5 * 1024 * 1024;

/// What the first bytes say the image is. The browser's claimed mime never
/// reaches the store — only this.
fn sniff(bytes: &[u8]) -> Option<&'static str> {
    if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        Some("image/png")
    } else if bytes.starts_with(b"\xff\xd8\xff") {
        Some("image/jpeg")
    } else if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF98a") {
        Some("image/gif")
    } else if bytes.len() >= 12 && &bytes[..4] == b"RIFF" && &bytes[8..12] == b"WEBP" {
        Some("image/webp")
    } else if bytes.len() >= 12 && &bytes[4..8] == b"ftyp" && &bytes[8..12] == b"avif" {
        Some("image/avif")
    } else {
        None
    }
}

/// Sets the signed-in person's own photo. Nobody else's — the id comes from
/// the session, never from the form.
#[route(POST "/api/profile_photo")]
async fn upload(cx: &Cx, mut multipart: Multipart) -> Redirect {
    let Some(user) = server::current_user(cx).await else {
        return see("/login".to_string());
    };
    let store = server::app(cx).store.clone();
    loop {
        let mut field = match multipart.next_field().await {
            Ok(Some(field)) => field,
            _ => return see("/?error=no_file".to_string()),
        };
        if field.file_name().is_none() {
            continue;
        }
        let mut collected = Vec::new();
        loop {
            match field.chunk().await {
                Ok(Some(chunk)) => {
                    if (collected.len() + chunk.len()) as u64 > PHOTO_LIMIT_BYTES {
                        return see("/?error=photo_too_big".to_string());
                    }
                    collected.extend_from_slice(&chunk);
                }
                Ok(None) => break,
                Err(_) => return see("/?error=photo_too_big".to_string()),
            }
        }
        let Some(mime) = sniff(&collected) else {
            return see("/?error=not_an_image".to_string());
        };
        return match photos::set_photo(&store, &user.id, &collected, mime).await {
            Ok(()) => {
                // The bytes changed, so the URL the avatar renders has to
                // change with them — bump before the answer goes out.
                if let Some(stamps) = try_app_context::<PhotoStamps>(cx) {
                    stamps.bump(&user.id.to_string());
                }
                server::log_event(cx, "photo_saved", Some(&user.email), None).await;
                see("/?ok=photo_saved".to_string())
            }
            Err(_) => see("/?error=unavailable".to_string()),
        };
    }
}

/// Clears the signed-in person's own photo.
#[route(POST "/api/delete_profile_photo")]
async fn delete(cx: &Cx) -> Redirect {
    let Some(user) = server::current_user(cx).await else {
        return see("/login".to_string());
    };
    let store = server::app(cx).store.clone();
    match photos::clear_photo(&store, &user.id).await {
        Ok(()) => {
            server::log_event(cx, "photo_removed", Some(&user.email), None).await;
            see("/?ok=photo_removed".to_string())
        }
        Err(_) => see("/?error=unavailable".to_string()),
    }
}

/// Photo URL version stamps, in process memory. The `user` row carries no
/// photo-updated moment and a schema column for cache-busting is out of
/// proportion, so the stamp lives here: `upload` bumps it when the bytes
/// change, and the avatar render reads it back. A photo whose bytes this
/// process never saw change stamps at the process start, which is still a
/// URL no browser has fetched, so it is re-downloaded exactly once per
/// restart and cached from then on.
#[derive(Clone, Default)]
pub struct PhotoStamps(Arc<Mutex<HashMap<String, i64>>>);

/// Unix microseconds at first use: the stamp for every photo whose bytes
/// this process never saw change. Stable for the process's lifetime, and
/// later than any stamp an earlier process emitted, so no pre-restart URL
/// survives a restart.
static PROCESS_START: LazyLock<i64> =
    LazyLock::new(|| (OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000) as i64);

impl PhotoStamps {
    fn stamp(&self, user_id: &str) -> i64 {
        self.0
            .lock()
            .get(user_id)
            .copied()
            .unwrap_or(*PROCESS_START)
    }

    fn bump(&self, user_id: &str) {
        let now = (OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000) as i64;
        let mut stamps = self.0.lock();
        // A write always moves the URL: never emit a stamp this user has
        // already rendered with, even when two writes land inside the same
        // microsecond.
        let stamp = stamps.get(user_id).copied().unwrap_or(*PROCESS_START);
        stamps.insert(user_id.to_string(), now.max(stamp + 1));
    }
}

/// The stamp an avatar's photo URL carries. A router built without
/// `PhotoStamps` falls back to the process start, which is still a URL no
/// browser has fetched before.
pub fn photo_stamp(cx: &Cx, user_id: &str) -> i64 {
    match try_app_context::<PhotoStamps>(cx) {
        Some(stamps) => stamps.stamp(user_id),
        None => *PROCESS_START,
    }
}

/// A cheap, non-cryptographic hash — good enough for an `ETag` on bytes only
/// this server ever writes.
fn fnv1a(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for &b in bytes {
        hash ^= b as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

fn not_found() -> (StatusCode, HeaderMap, Vec<u8>) {
    (StatusCode::NOT_FOUND, HeaderMap::new(), Vec::new())
}

/// Serves one person's photo. Signed-in only — either through the session
/// cookie or as a registered OIDC app presenting HTTP Basic over
/// `client_id:client_secret` — and a missing photo reads exactly like a
/// missing person: the not-found, never a `403`.
///
/// Apps count as signed-in viewers because registration is the trust: im
/// hands the client secret out exactly once, keeps only its digest, and the
/// app presents it on every fetch. Unknown clients, wrong secrets, unknown
/// users and missing photos all answer the same not-found, so no failure
/// is distinguishable on the wire.
#[route(GET "/photo/{user_id}")]
async fn serve(cx: &Cx) -> topcoat::Result<(StatusCode, HeaderMap, Vec<u8>)> {
    if server::current_user(cx).await.is_none() && !valid_app(cx).await {
        return Ok(not_found());
    }
    let target = im_core::model::UserId::from(path_param::<UserId>(cx).to_string());
    let store = server::app(cx).store.clone();
    let Ok(Some((bytes, mime))) = photos::photo(&store, &target).await else {
        return Ok(not_found());
    };

    let etag = format!("\"{:x}\"", fnv1a(&bytes));
    let mut headers = HeaderMap::new();
    headers.insert(header::ETAG, HeaderValue::from_str(&etag).unwrap());
    // The stamp in the URL is the other half of this caching: `upload`
    // bumps it whenever the bytes change, so a year of `immutable` never
    // shows an old photo — a changed photo is a changed URL. `private`
    // because the route is session-gated.
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, max-age=31536000, immutable"),
    );

    let if_none_match = request_headers(cx)
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok());
    if if_none_match == Some(etag.as_str()) {
        return Ok((StatusCode::NOT_MODIFIED, headers, Vec::new()));
    }

    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(&mime)
            .unwrap_or(HeaderValue::from_static("application/octet-stream")),
    );
    Ok((StatusCode::OK, headers, bytes))
}

/// Whether this request carries a registered OIDC app's credentials: HTTP
/// Basic over `client_id:client_secret`, checked against the client
/// registry. Anything unparseable, unknown, or wrong is simply false — the
/// caller answers its one not-found and never says which.
async fn valid_app(cx: &Cx) -> bool {
    use base64::Engine as _;
    let Some(encoded) = request_headers(cx)
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Basic "))
    else {
        return false;
    };
    let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(encoded) else {
        return false;
    };
    let Ok(pair) = std::str::from_utf8(&decoded) else {
        return false;
    };
    let Some((client_id, secret)) = pair.split_once(':') else {
        return false;
    };
    let store = server::app(cx).store.clone();
    let Ok(Some(client)) = im_core::oidc::client_by_id(&store, client_id).await else {
        return false;
    };
    im_core::oidc::verify_client_secret(&client, secret)
}

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::sync::Arc;

    use im_core::accounts::{create_invite, create_user_from_invite};
    use im_core::model::UserId;
    use im_core::oidc::create_client;
    use im_core::photos::set_photo;
    use im_core::sessions::{SessionMeta, create_session};
    use im_core::store::Store;
    use topcoat::cookie::RouterBuilderCookieExt as _;
    use topcoat::router::{Body, HeaderMap, Router, RouterBuilderDiscoverExt as _, StatusCode};
    use topcoat::router::{header, to_bytes};
    use super::PhotoStamps;

    use crate::config::Config;
    use crate::server::{self, SESSION_COOKIE};

    const PHOTO: &[u8] = b"\x89PNG\r\n\x1a\nfake-photo-bytes";

    struct Setup {
        router: Router,
        user_id: UserId,
        plain_id: UserId,
        client_id: String,
        secret: String,
        session_cookie: String,
    }

    async fn setup() -> Setup {
        let store = Store::open(Path::new(":memory:")).await.unwrap();
        let (client_id, secret) = create_client(&store, "drive", vec!["http://app/callback".into()])
            .await
            .unwrap();
        let invite = create_invite(&store, "ann@example.com", None, false)
            .await
            .unwrap();
        let user = create_user_from_invite(&store, invite.expose(), "Ann", "tDLr9!mZQ2xv")
            .await
            .unwrap();
        set_photo(&store, &user.id, PHOTO, "image/png")
            .await
            .unwrap();
        let bare = create_invite(&store, "ben@example.com", None, false)
            .await
            .unwrap();
        let plain = create_user_from_invite(&store, bare.expose(), "Ben", "tDLr9!mZQ2xv")
            .await
            .unwrap();
        let session = create_session(&store, &user.id, &SessionMeta::default())
            .await
            .unwrap();
        let (live, _) = tokio::sync::broadcast::channel(64);
        let app = server::App {
            store: Arc::new(store),
            config: Config {
                database: ":memory:".into(),
                listen: "127.0.0.1:7650".parse().unwrap(),
                issuer: "http://127.0.0.1:7650".into(),
            },
            live,
        };
        let router = Router::builder()
            .discover()
            .cookies()
            .app_context(app)
            .app_context(PhotoStamps::default())
            .build();
        Setup {
            router,
            user_id: user.id,
            plain_id: plain.id,
            client_id: client_id.to_string(),
            secret: secret.expose().to_string(),
            session_cookie: format!("{SESSION_COOKIE}={}", session.expose()),
        }
    }

    fn basic(client_id: &str, secret: &str) -> String {
        use base64::Engine as _;
        format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(format!("{client_id}:{secret}"))
        )
    }

    async fn get(
        router: &Router,
        user_id: &str,
        auth: Option<String>,
        cookie: Option<&str>,
    ) -> (StatusCode, HeaderMap, Vec<u8>) {
        let mut builder = http::Request::builder().uri(format!("/photo/{user_id}"));
        if let Some(auth) = auth {
            builder = builder.header(header::AUTHORIZATION, auth);
        }
        if let Some(cookie) = cookie {
            builder = builder.header(header::COOKIE, cookie);
        }
        let response = router.handle(builder.body(Body::empty()).unwrap()).await;
        let (parts, body) = response.into_parts();
        let bytes = to_bytes(body, usize::MAX).await.unwrap().to_vec();
        (parts.status, parts.headers, bytes)
    }

    #[tokio::test]
    async fn app_credentials_serve_photo_bytes() {
        let setup = setup().await;
        let (status, headers, bytes) = get(
            &setup.router,
            setup.user_id.as_str(),
            Some(basic(&setup.client_id, &setup.secret)),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(bytes, PHOTO);
        assert_eq!(
            headers.get(header::CONTENT_TYPE).unwrap(),
            "image/png"
        );
    }

    #[tokio::test]
    async fn wrong_secret_is_not_found() {
        let setup = setup().await;
        let (status, _, bytes) = get(
            &setup.router,
            setup.user_id.as_str(),
            Some(basic(&setup.client_id, "wrong-secret")),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(bytes.is_empty());
    }

    #[tokio::test]
    async fn unknown_client_is_not_found() {
        let setup = setup().await;
        let (status, _, bytes) = get(
            &setup.router,
            setup.user_id.as_str(),
            Some(basic("no-such-client", &setup.secret)),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(bytes.is_empty());
    }

    #[tokio::test]
    async fn no_credentials_is_not_found() {
        let setup = setup().await;
        let (status, _, bytes) = get(&setup.router, setup.user_id.as_str(), None, None).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(bytes.is_empty());
    }

    #[tokio::test]
    async fn malformed_authorization_is_not_found() {
        let setup = setup().await;
        let (status, _, _) = get(
            &setup.router,
            setup.user_id.as_str(),
            Some("Basic !!!not-base64!!!".to_string()),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn app_credentials_unknown_user_is_not_found() {
        let setup = setup().await;
        let (status, _, bytes) = get(
            &setup.router,
            "no-such-user",
            Some(basic(&setup.client_id, &setup.secret)),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(bytes.is_empty());
    }

    #[tokio::test]
    async fn app_credentials_missing_photo_is_not_found() {
        let setup = setup().await;
        let (status, _, bytes) = get(
            &setup.router,
            setup.plain_id.as_str(),
            Some(basic(&setup.client_id, &setup.secret)),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(bytes.is_empty());
    }

    #[tokio::test]
    async fn session_still_serves_photo() {
        let setup = setup().await;
        let (status, _, bytes) = get(
            &setup.router,
            setup.user_id.as_str(),
            None,
            Some(&setup.session_cookie),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(bytes, PHOTO);
    }

    #[tokio::test]
    async fn session_takes_precedence_over_bad_app_credentials() {
        let setup = setup().await;
        let (status, _, bytes) = get(
            &setup.router,
            setup.user_id.as_str(),
            Some(basic(&setup.client_id, "wrong-secret")),
            Some(&setup.session_cookie),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(bytes, PHOTO);
    }
}
