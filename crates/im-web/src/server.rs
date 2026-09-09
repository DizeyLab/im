//! Shared request plumbing: the app context, the two cookies (`im_session`
//! for a completed login, `im_pending` for the ten minutes between password
//! and second factor), and the refusal codes a redirect carries back to the
//! page that posted the form.
//!
//! Every form post answers a plain 303 whose query names the refusal, and
//! the page reads it back on render. The soft-nav script replays posts over
//! fetch with `accept: text/html`, so the 303's target document is what
//! comes back — no refusal-carrying layer as in İzlek is needed.

use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex, PoisonError};
use std::time::{Duration, Instant};

use im_core::model::User;
use im_core::store::Store;
use topcoat::context::{Cx, try_app_context};
use topcoat::cookie::{Cookie, Cookies, cookie, cookies};

use crate::config::Config;

pub const SESSION_COOKIE: &str = "im_session";
pub const PENDING_COOKIE: &str = "im_pending";

/// The pending marker's lifetime: long enough to find the authenticator,
/// short enough to not be a session.
pub const PENDING_MINUTES: i64 = 10;

pub struct App {
    pub store: Arc<Store>,
    pub config: Config,
    /// The live channel: any mutation announces itself here, and every open
    /// tab re-reads what it is showing. A `Tick` says "re-fetch", nothing
    /// more — never a row, never a name. A `Profile` carries the full
    /// directory row of the one member whose row changed, for the app-facing
    /// `/directory/live` stream.
    pub live: tokio::sync::broadcast::Sender<LiveEvent>,
}

/// What travels the live channel. `Tick` is the panel's "something moved —
/// re-read"; `Profile` is the directory's own news: this member's row, as it
/// now stands, serialized exactly as `/directory` would have answered it.
#[derive(Clone, Debug)]
pub enum LiveEvent {
    Tick,
    Profile(crate::directory::DirectoryMember),
}

/// Announce that the panel's data moved. Sends are lossy on purpose: nobody
/// listening is not an error, and a lagging tab gets a resync tick.
pub fn note(cx: &Cx) {
    let _ = app(cx).live.send(LiveEvent::Tick);
}

/// Announce that one member's row changed. Re-reads the row — the callers
/// hold the pre-write copy — and broadcasts it as the member `/directory`
/// would answer. A row that no longer resolves (deleted) has no member to
/// announce; the next full pass is where a removal surfaces.
pub async fn notify_profile(cx: &Cx, user_id: &im_core::model::UserId) {
    let Ok(Some(user)) = im_core::accounts::user_by_id(&app(cx).store, user_id).await else {
        return;
    };
    let _ = app(cx).live.send(LiveEvent::Profile(
        crate::directory::DirectoryMember::of(&user),
    ));
}

/// Log the event, then tick the live channel — the two travel together so
/// the Logs page (and any watching panel) catches up without a reload.
pub async fn log_event(cx: &Cx, kind: &str, actor: Option<&str>, detail: Option<&str>) {
    im_core::events::log(&app(cx).store, kind, actor, detail).await;
    note(cx);
}

// ---------------------------------------------------------------------------
// The show-once shelf
// ---------------------------------------------------------------------------

/// How long a stashed secret waits for its one reader.
const SHOWN_TTL: Duration = Duration::from_secs(10 * 60);

/// Where a freshly minted client secret waits between its POST and the one
/// GET that shows it. The panel's write answers a 303 — the house idiom —
/// but the secret itself must never ride a URL or a log line, so the query
/// carries only a random claim ticket: the shelf holds the plaintext, the
/// page's read takes it out (`take_shown_secret`), and a replayed or
/// reloaded URL finds the shelf empty and renders no secret at all. A
/// restart drops the shelf — the admin mints another, as with the CLI.
static SHOWN_SECRETS: LazyLock<Mutex<HashMap<String, ((String, String), Instant)>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Parks a client's fresh pair on the shelf and returns the claim ticket
/// for its URL. The id travels too — it is the public half of the pair and
/// the one render shows it beside the secret.
pub fn stash_shown_secret(client_id: String, secret: String) -> String {
    let ticket = im_core::accounts::Token::mint().expose().to_string();
    let mut shelf = SHOWN_SECRETS.lock().unwrap_or_else(PoisonError::into_inner);
    shelf.retain(|_, (_, parked)| parked.elapsed() < SHOWN_TTL);
    shelf.insert(ticket.clone(), ((client_id, secret), Instant::now()));
    ticket
}

/// Takes a stashed pair out — exactly once; the second reader of the same
/// ticket gets nothing.
pub fn take_shown_secret(ticket: &str) -> Option<(String, String)> {
    SHOWN_SECRETS
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .remove(ticket)
        .map(|(pair, _)| pair)
}

pub fn app(cx: &Cx) -> &App {
    try_app_context::<App>(cx).expect("the router always carries the App")
}

/// The application cookie jar, with the attributes every im cookie wants.
fn app_cookies(cx: &Cx) -> impl Cookies {
    cookies(cx)
        .default_secure(app(cx).config.is_secure())
        .default_http_only(true)
        .default_same_site(topcoat::cookie::SameSite::Lax)
        .default_path("/")
}

/// The session cookie value this request presented, if it presented one.
pub fn presented_session(cx: &Cx) -> Option<String> {
    cookies(cx)
        .get(SESSION_COOKIE)
        .map(|c| c.value().to_string())
}

pub fn presented_pending(cx: &Cx) -> Option<String> {
    cookies(cx)
        .get(PENDING_COOKIE)
        .map(|c| c.value().to_string())
}

/// Writes the session cookie. `HttpOnly` so script cannot read it, `Secure`
/// (on https issuers) so it never crosses plain HTTP, `SameSite=Lax` so
/// another site's form cannot post with it — and so the top-level redirect
/// back from `/authorize` still carries it.
pub fn set_session_cookie(cx: &Cx, token: &str) {
    app_cookies(cx).add(cookie! {
        SESSION_COOKIE = token.to_owned();
        Path = "/";
        HttpOnly;
        SameSite = Lax;
        MaxAge = time::Duration::days(im_core::sessions::SESSION_DAYS)
    });
}

pub async fn set_pending_cookie(cx: &Cx, sealed: String) {
    let minutes = im_core::settings::pending_minutes(&app(cx).store)
        .await
        .unwrap_or(PENDING_MINUTES);
    app_cookies(cx).add(cookie! {
        PENDING_COOKIE = sealed;
        Path = "/";
        HttpOnly;
        SameSite = Lax;
        MaxAge = time::Duration::minutes(minutes)
    });
}

/// Removes the session cookie from this browser. The server-side revocation
/// is what actually ends the session; this only tidies the client.
pub fn clear_session_cookie(cx: &Cx) {
    app_cookies(cx).remove(Cookie::build((SESSION_COOKIE, "")).path("/").build());
}

pub fn clear_pending_cookie(cx: &Cx) {
    app_cookies(cx).remove(Cookie::build((PENDING_COOKIE, "")).path("/").build());
}

/// The person behind this request, resolved through the central session.
pub async fn current_user(cx: &Cx) -> Option<User> {
    let token = presented_session(cx)?;
    im_core::sessions::resolve_session(&app(cx).store, &token)
        .await
        .ok()
        .flatten()
}

// ---------------------------------------------------------------------------
// The pending marker: between password and TOTP
// ---------------------------------------------------------------------------

#[derive(Debug, serde::Serialize, serde::Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum PendingPurpose {
    /// Password verified, TOTP code still owed.
    Login,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct Pending {
    pub user: String,
    pub purpose: PendingPurpose,
    /// The `/authorize` URL the login is in the middle of, urlencoded as it
    /// arrived; `/` when there is none.
    pub back: String,
    pub exp: i64,
}

pub async fn mint_pending(
    cx: &Cx,
    user: &im_core::model::UserId,
    purpose: PendingPurpose,
    back: String,
) -> String {
    let minutes = im_core::settings::pending_minutes(&app(cx).store)
        .await
        .unwrap_or(PENDING_MINUTES);
    let pending = Pending {
        user: user.to_string(),
        purpose,
        back,
        exp: time::OffsetDateTime::now_utc().unix_timestamp() + minutes * 60,
    };
    let json = serde_json::to_string(&pending).expect("Pending is plain data");
    app(cx).store.seal_value(json.as_bytes())
}

/// Opens the pending cookie this request presented. `None` for absent,
/// forged, or expired — all three mean "start the login over".
pub fn opened_pending(cx: &Cx) -> Option<Pending> {
    let sealed = presented_pending(cx)?;
    let bytes = app(cx).store.open_value(&sealed)?;
    let pending: Pending = serde_json::from_slice(&bytes).ok()?;
    if pending.exp <= time::OffsetDateTime::now_utc().unix_timestamp() {
        return None;
    }
    Some(pending)
}

/// Whether this request carries a registered OIDC app's credentials: HTTP
/// Basic over `client_id:client_secret`, checked against the client
/// registry. Anything unparseable, unknown, or wrong is simply false — the
/// caller answers its one refusal and never says which.
pub async fn valid_app(cx: &Cx) -> bool {
    app_client(cx).await.is_some()
}

/// The same check, answering *which* app it is: the routes that write on a
/// caller's behalf (`/family/register`) need the client id the pair
/// authenticated, and the ones that only read do not.
pub async fn app_client(cx: &Cx) -> Option<String> {
    use base64::Engine as _;
    use topcoat::router::{header, request::headers as request_headers};
    let encoded = request_headers(cx)
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Basic "))?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .ok()?;
    let pair = std::str::from_utf8(&decoded).ok()?;
    let (client_id, secret) = pair.split_once(':')?;
    let store = app(cx).store.clone();
    let client = im_core::oidc::client_by_id(&store, client_id)
        .await
        .ok()??;
    im_core::oidc::verify_client_secret(&client, secret).then(|| client_id.to_string())
}
