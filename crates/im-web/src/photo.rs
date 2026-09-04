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

/// Serves one person's photo. Signed-in only, and a missing photo reads
/// exactly like a missing person: the not-found, never a `403`.
#[route(GET "/photo/{user_id}")]
async fn serve(cx: &Cx) -> topcoat::Result<(StatusCode, HeaderMap, Vec<u8>)> {
    if server::current_user(cx).await.is_none() {
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
