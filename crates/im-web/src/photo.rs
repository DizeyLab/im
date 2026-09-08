//! Profile photo upload, removal and serving — the landing's profile card
//! is their only reader. Adapted from izlek-web's `photo.rs`; the refusal
//! answer is im's, though: a plain 303 whose query names the code, which the
//! landing reads back on render.

use im_core::photos;
use topcoat::context::Cx;
use topcoat::router::content::multipart::Multipart;
use topcoat::router::request::headers as request_headers;
use topcoat::router::request::uri;
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
                // The row is committed with its bumped version: announce the
                // changed face to every open tab and every app on the
                // directory stream before the answer goes out.
                server::notify_profile(cx, &user.id).await;
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
            // Committed: the face is gone, the version moved on either way.
            server::notify_profile(cx, &user.id).await;
            server::log_event(cx, "photo_removed", Some(&user.email), None).await;
            see("/?ok=photo_removed".to_string())
        }
        Err(_) => see("/?error=unavailable".to_string()),
    }
}

fn not_found() -> (StatusCode, HeaderMap, Vec<u8>) {
    (StatusCode::NOT_FOUND, HeaderMap::new(), Vec::new())
}

/// The response for served bytes: the version ETag — strong, one per photo
/// generation — the caller's cache policy, and the 304 when the caller's
/// copy is already this one.
fn bytes_response(
    cx: &Cx,
    bytes: Vec<u8>,
    content_type: &str,
    cache: &'static str,
    version: u64,
) -> (StatusCode, HeaderMap, Vec<u8>) {
    let etag = format!("\"p{version}\"");
    let mut headers = HeaderMap::new();
    headers.insert(header::ETAG, HeaderValue::from_str(&etag).unwrap());
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static(cache));
    let if_none_match = request_headers(cx)
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok());
    if if_none_match == Some(etag.as_str()) {
        return (StatusCode::NOT_MODIFIED, headers, Vec::new());
    }
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(content_type)
            .unwrap_or(HeaderValue::from_static("application/octet-stream")),
    );
    (StatusCode::OK, headers, bytes)
}

/// The default face, as an image: the name's first letter on a quiet tile —
/// the same answer im's own pages give a photoless profile (the initial span
/// in `layout::avatar`), rendered to SVG so an app's `<img>` can carry it.
/// The colors are fixed (mid tile, light letter) because the tile ships to
/// apps whose themes im does not know.
fn default_avatar(initial: &str) -> Vec<u8> {
    // The initial is one character off a name, but escape anyway: nothing
    // stops a name from starting with `&`, `<`, or `>`.
    let escaped = initial
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;");
    format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 96 96\">\
         <rect width=\"96\" height=\"96\" rx=\"6\" fill=\"#3a3f47\"/>\
         <text x=\"48\" y=\"48\" dy=\"0.35em\" text-anchor=\"middle\" \
         font-family=\"ui-monospace, monospace\" font-size=\"40\" \
         fill=\"#9aa1ab\">{escaped}</text></svg>"
    )
    .into_bytes()
}

/// The `v` pair of this request's query string, if it carried one. Matched
/// verbatim against the row's `photo_version`; a version needs no escaping,
/// so a plain split is the whole parse.
fn requested_version(cx: &Cx) -> Option<&str> {
    uri(cx)
        .query()?
        .split('&')
        .find_map(|pair| pair.strip_prefix("v="))
}

/// Serves one person's photo. Signed-in only — either through the session
/// cookie or as a registered OIDC app presenting HTTP Basic over
/// `client_id:client_secret`.
///
/// A person with no photo gets the default face — the name's first letter
/// on a quiet tile, the same face im's own pages render — so an app's
/// `<img>` shows a person, never a broken-image glyph. An unknown id gets
/// the same tile with a `?`, so an authenticated fetch still cannot tell a
/// missing person from a missing photo; only the missing credential reads
/// as the not-found.
///
/// Caching hangs off the row's `photo_version`, the same number the
/// directory answers with: a URL whose `?v=` names the current version
/// may cache for a year — a changed photo is a changed URL — while every
/// other spelling of the route, the bare `/photo/{sub}` an app fetches or
/// the photoless tile, answers `no-cache` and revalidates on the ETag.
/// The version comes from the store, not from process memory, so a
/// restart forgets nothing and every reader sees the same one.
#[route(GET "/photo/{user_id}")]
async fn serve(cx: &Cx) -> topcoat::Result<(StatusCode, HeaderMap, Vec<u8>)> {
    if server::current_user(cx).await.is_none() && !server::valid_app(cx).await {
        return Ok(not_found());
    }
    let target = im_core::model::UserId::from(path_param::<UserId>(cx).to_string());
    let store = server::app(cx).store.clone();
    let user = im_core::accounts::user_by_id(&store, &target)
        .await
        .ok()
        .flatten();
    let version = user.as_ref().map_or(0, |user| user.photo_version);
    if let Ok(Some((bytes, mime))) = photos::photo(&store, &target).await {
        // `private` because the route is session-gated.
        let cache = if requested_version(cx) == Some(version.to_string().as_str()) {
            "private, max-age=31536000, immutable"
        } else {
            "private, no-cache"
        };
        return Ok(bytes_response(cx, bytes, &mime, cache, version));
    }
    let initial = user
        .as_ref()
        .and_then(|user| user.name.chars().next())
        .unwrap_or('?')
        .to_uppercase()
        .to_string();
    Ok(bytes_response(
        cx,
        default_avatar(&initial),
        "image/svg+xml",
        "private, no-cache",
        version,
    ))
}

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::sync::Arc;

    use futures_util::StreamExt as _;
    use im_core::accounts::{create_invite, create_user_from_invite};
    use im_core::model::UserId;
    use im_core::oidc::create_client;
    use im_core::photos::set_photo;
    use im_core::sessions::{SessionMeta, create_session};
    use im_core::store::Store;
    use topcoat::cookie::RouterBuilderCookieExt as _;
    use topcoat::router::{
        Body, BodyDataStream, HeaderMap, Router, RouterBuilderDiscoverExt as _, StatusCode,
    };
    use topcoat::router::{header, to_bytes};

    use crate::config::Config;
    use crate::server::{self, SESSION_COOKIE};

    const PHOTO: &[u8] = b"\x89PNG\r\n\x1a\nfake-photo-bytes";

    struct Setup {
        router: Router,
        store: Arc<Store>,
        user_id: UserId,
        plain_id: UserId,
        client_id: String,
        secret: String,
        session_cookie: String,
    }

    async fn setup() -> Setup {
        let store = Store::open(Path::new(":memory:")).await.unwrap();
        let (client_id, secret) =
            create_client(&store, "drive", vec!["http://app/callback".into()])
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
        let store = Arc::new(store);
        let app = server::App {
            store: store.clone(),
            config: Config {
                database: ":memory:".into(),
                listen: "127.0.0.1:7650".parse().unwrap(),
                issuer: "http://127.0.0.1:7650".into(),
                services: Vec::new(),
            },
            live,
        };
        let router = Router::builder()
            .discover()
            .cookies()
            .app_context(app)
            .build();
        Setup {
            router,
            store,
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

    /// GETs `/photo/{id}` — the plain helper most tests use.
    async fn get(
        router: &Router,
        user_id: &str,
        auth: Option<String>,
        cookie: Option<&str>,
    ) -> (StatusCode, HeaderMap, Vec<u8>) {
        get_uri(router, &format!("/photo/{user_id}"), auth, cookie, None).await
    }

    /// GETs a photo URI — with or without the `?v=` pair — optionally
    /// carrying an app's Basic pair, a session cookie, and an
    /// `If-None-Match` for the revalidation dance.
    async fn get_uri(
        router: &Router,
        uri: &str,
        auth: Option<String>,
        cookie: Option<&str>,
        if_none_match: Option<&str>,
    ) -> (StatusCode, HeaderMap, Vec<u8>) {
        let mut builder = http::Request::builder().uri(uri);
        if let Some(auth) = auth {
            builder = builder.header(header::AUTHORIZATION, auth);
        }
        if let Some(cookie) = cookie {
            builder = builder.header(header::COOKIE, cookie);
        }
        if let Some(etag) = if_none_match {
            builder = builder.header(header::IF_NONE_MATCH, etag);
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
        assert_eq!(headers.get(header::CONTENT_TYPE).unwrap(), "image/png");
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
    async fn app_credentials_unknown_user_gets_the_unknown_avatar() {
        let setup = setup().await;
        let (status, headers, bytes) = get(
            &setup.router,
            "no-such-user",
            Some(basic(&setup.client_id, &setup.secret)),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(headers.get(header::CONTENT_TYPE).unwrap(), "image/svg+xml");
        let body = String::from_utf8(bytes).unwrap();
        assert!(body.contains(">?<"), "unknown user gets the ? tile: {body}");
    }

    #[tokio::test]
    async fn app_credentials_missing_photo_gets_the_initial_avatar() {
        let setup = setup().await;
        let (status, headers, bytes) = get(
            &setup.router,
            setup.plain_id.as_str(),
            Some(basic(&setup.client_id, &setup.secret)),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(headers.get(header::CONTENT_TYPE).unwrap(), "image/svg+xml");
        // The tile revalidates instead of caching immutably: a photo
        // uploaded later has to be able to replace it.
        assert_eq!(
            headers.get(header::CACHE_CONTROL).unwrap(),
            "private, no-cache"
        );
        let body = String::from_utf8(bytes).unwrap();
        assert!(
            body.contains(">B<"),
            "photoless Ben gets his initial: {body}"
        );
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

    #[tokio::test]
    async fn versioned_url_caches_immutably_on_the_version_etag() {
        let setup = setup().await;
        // Setup uploads once, so Ann's row sits at version 1.
        let uri = format!("/photo/{}?v=1", setup.user_id);
        let (status, headers, _) =
            get_uri(&setup.router, &uri, Some(basic(&setup.client_id, &setup.secret)), None, None)
                .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(headers.get(header::ETAG).unwrap(), "\"p1\"");
        assert_eq!(
            headers.get(header::CACHE_CONTROL).unwrap(),
            "private, max-age=31536000, immutable"
        );
    }

    #[tokio::test]
    async fn unversioned_url_must_revalidate() {
        let setup = setup().await;
        let (status, headers, _) = get(
            &setup.router,
            setup.user_id.as_str(),
            Some(basic(&setup.client_id, &setup.secret)),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(headers.get(header::ETAG).unwrap(), "\"p1\"");
        // The bare URL an app fetches cannot promise freshness: a year of
        // `immutable` would pin yesterday's face until the next restart
        // minted a new stamp.
        assert_eq!(
            headers.get(header::CACHE_CONTROL).unwrap(),
            "private, no-cache"
        );
    }

    #[tokio::test]
    async fn a_stale_version_asks_for_a_revalidation_too() {
        let setup = setup().await;
        let uri = format!("/photo/{}?v=0", setup.user_id);
        let (_, headers, _) =
            get_uri(&setup.router, &uri, Some(basic(&setup.client_id, &setup.secret)), None, None)
                .await;
        assert_eq!(
            headers.get(header::CACHE_CONTROL).unwrap(),
            "private, no-cache"
        );
    }

    #[tokio::test]
    async fn matching_if_none_match_answers_not_modified() {
        let setup = setup().await;
        let uri = format!("/photo/{}?v=1", setup.user_id);
        let (status, headers, bytes) = get_uri(
            &setup.router,
            &uri,
            Some(basic(&setup.client_id, &setup.secret)),
            None,
            Some("\"p1\""),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_MODIFIED);
        assert_eq!(headers.get(header::ETAG).unwrap(), "\"p1\"");
        assert!(bytes.is_empty());
        // A stale copy revalidates to the full answer, never a 304.
        let (status, _, _) = get_uri(
            &setup.router,
            &uri,
            Some(basic(&setup.client_id, &setup.secret)),
            None,
            Some("\"p0\""),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn a_new_upload_moves_the_version_and_the_etag() {
        let setup = setup().await;
        set_photo(
            &setup.store,
            &setup.user_id,
            b"\x89PNG\r\n\x1a\nother-bytes",
            "image/png",
        )
        .await
        .unwrap();
        // The old cached copy is stale on both spellings of the URL.
        let uri = format!("/photo/{}?v=1", setup.user_id);
        let (_, headers, _) =
            get_uri(&setup.router, &uri, Some(basic(&setup.client_id, &setup.secret)), None, None)
                .await;
        assert_eq!(
            headers.get(header::CACHE_CONTROL).unwrap(),
            "private, no-cache"
        );
        let uri = format!("/photo/{}?v=2", setup.user_id);
        let (status, headers, bytes) =
            get_uri(&setup.router, &uri, Some(basic(&setup.client_id, &setup.secret)), None, None)
                .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(headers.get(header::ETAG).unwrap(), "\"p2\"");
        assert_eq!(
            headers.get(header::CACHE_CONTROL).unwrap(),
            "private, max-age=31536000, immutable"
        );
        assert_eq!(bytes, b"\x89PNG\r\n\x1a\nother-bytes");
    }

    #[tokio::test]
    async fn the_photoless_tile_validates_on_the_version_etag() {
        let setup = setup().await;
        let (status, headers, _) = get(
            &setup.router,
            setup.plain_id.as_str(),
            Some(basic(&setup.client_id, &setup.secret)),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(headers.get(header::ETAG).unwrap(), "\"p0\"");
        let (status, _, bytes) = get_uri(
            &setup.router,
            &format!("/photo/{}", setup.plain_id),
            Some(basic(&setup.client_id, &setup.secret)),
            None,
            Some("\"p0\""),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_MODIFIED);
        assert!(bytes.is_empty());
    }

    /// POSTs a photo the way the avatar script's autosubmit does — a
    /// multipart form with one named file — through the router, with the
    /// session cookie carrying who it is for.
    async fn post_upload(
        router: &Router,
        cookie: &str,
        bytes: &[u8],
    ) -> (StatusCode, Option<String>) {
        const BOUNDARY: &str = "imwebtestboundary";
        let mut body = Vec::new();
        body.extend_from_slice(
            format!(
                "--{BOUNDARY}\r\n\
                 Content-Disposition: form-data; name=\"file\"; filename=\"face.png\"\r\n\
                 Content-Type: image/png\r\n\r\n"
            )
            .as_bytes(),
        );
        body.extend_from_slice(bytes);
        body.extend_from_slice(format!("\r\n--{BOUNDARY}--\r\n").as_bytes());
        let response = router
            .handle(
                http::Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/profile_photo")
                    .header(
                        header::CONTENT_TYPE,
                        format!("multipart/form-data; boundary={BOUNDARY}"),
                    )
                    .header(header::COOKIE, cookie)
                    .body(Body::from(body))
                    .unwrap(),
            )
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

    /// Opens `/directory/live` as an app would and pins the body's data
    /// stream. A single SSE frame may straddle two body frames, so
    /// callers accumulate text and match on substrings, never on chunk
    /// boundaries.
    async fn open_live_stream(
        router: &Router,
        authorization: &str,
    ) -> std::pin::Pin<Box<BodyDataStream>> {
        let response = router
            .handle(
                http::Request::builder()
                    .uri("/directory/live")
                    .header(header::AUTHORIZATION, authorization)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
        let (parts, body) = response.into_parts();
        assert_eq!(parts.status, StatusCode::OK);
        Box::pin(body.into_data_stream())
    }

    /// The next body frame off the stream, as text.
    async fn next_wire_chunk(stream: &mut std::pin::Pin<Box<BodyDataStream>>) -> String {
        let chunk = stream
            .as_mut()
            .next()
            .await
            .expect("stream stays open")
            .expect("frames succeed");
        String::from_utf8_lossy(&chunk).into_owned()
    }

    /// The whole emit path, end to end: a signed-in upload through the
    /// router, the committed row's new version on the live bus, and an
    /// `event: profile` frame off `/directory/live` carrying it.
    #[tokio::test]
    async fn a_photo_upload_through_the_router_emits_a_profile_frame() {
        let setup = setup().await;
        // Open the app stream first, the way a sibling sits on it, and
        // read through the opening reconnection hint.
        let mut stream =
            open_live_stream(&setup.router, &basic(&setup.client_id, &setup.secret)).await;
        let mut wire = String::new();
        while !wire.contains("retry: 5000") {
            wire.push_str(&next_wire_chunk(&mut stream).await);
        }

        // Setup's upload was version 1; this one must announce 2.
        let (status, location) = post_upload(&setup.router, &setup.session_cookie, PHOTO).await;
        assert_eq!(status, StatusCode::SEE_OTHER, "upload answers a 303");
        assert_eq!(location.as_deref(), Some("/?ok=photo_saved"));

        wire.clear();
        while !wire.contains("event: profile") {
            wire.push_str(&next_wire_chunk(&mut stream).await);
        }
        assert!(wire.contains(&format!("\"sub\":\"{}\"", setup.user_id)));
        assert!(
            wire.contains("\"photo_version\":2"),
            "the frame carries the bumped version: {wire}"
        );
    }

    /// Same path, the removal half: a delete announces too, and its frame
    /// moves the version forward even though the mime is gone.
    #[tokio::test]
    async fn a_photo_delete_through_the_router_emits_a_profile_frame() {
        let setup = setup().await;
        let mut stream =
            open_live_stream(&setup.router, &basic(&setup.client_id, &setup.secret)).await;
        let mut wire = String::new();
        while !wire.contains("retry: 5000") {
            wire.push_str(&next_wire_chunk(&mut stream).await);
        }

        let response = setup
            .router
            .handle(
                http::Request::builder()
                    .method(http::Method::POST)
                    .uri("/api/delete_profile_photo")
                    .header(header::COOKIE, &setup.session_cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
        let (parts, _) = response.into_parts();
        assert_eq!(parts.status, StatusCode::SEE_OTHER);

        wire.clear();
        while !wire.contains("event: profile") {
            wire.push_str(&next_wire_chunk(&mut stream).await);
        }
        assert!(
            wire.contains("\"photo_version\":2"),
            "the removal bumps and announces the version: {wire}"
        );
    }
}
