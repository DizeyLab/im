//! Shared request plumbing: the app context, the two cookies (`im_session`
//! for a completed login, `im_pending` for the ten minutes between password
//! and second factor), and the refusal codes a redirect carries back to the
//! page that posted the form.
//!
//! im serves no client-side script, so there is no refusal-carrying layer as
//! in İzlek: every form post answers a plain 303 whose query names the
//! refusal, and the page reads it back on render.

use std::sync::Arc;

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
    /// The live channel's ticker: any mutation announces itself here, and
    /// every open admin tab re-reads what it is showing. Carries no data —
    /// a tick says "re-fetch", nothing more.
    pub live: tokio::sync::broadcast::Sender<()>,
}

/// Announce that the panel's data moved. Sends are lossy on purpose: nobody
/// listening is not an error, and a lagging tab gets a resync tick.
pub fn note(cx: &Cx) {
    let _ = app(cx).live.send(());
}

/// Log the event, then tick the live channel — the two travel together so
/// the Logs page (and any watching panel) catches up without a reload.
pub async fn log_event(cx: &Cx, kind: &str, actor: Option<&str>, detail: Option<&str>) {
    im_core::events::log(&app(cx).store, kind, actor, detail).await;
    note(cx);
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

pub fn set_pending_cookie(cx: &Cx, sealed: String) {
    app_cookies(cx).add(cookie! {
        PENDING_COOKIE = sealed;
        Path = "/";
        HttpOnly;
        SameSite = Lax;
        MaxAge = time::Duration::minutes(PENDING_MINUTES)
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
// The pending marker: between password and TOTP, between invite and enrolment
// ---------------------------------------------------------------------------

#[derive(Debug, serde::Serialize, serde::Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum PendingPurpose {
    /// Password verified, TOTP code still owed.
    Login,
    /// Account created, TOTP enrolment still owed.
    Enroll,
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

pub fn mint_pending(
    cx: &Cx,
    user: &im_core::model::UserId,
    purpose: PendingPurpose,
    back: String,
) -> String {
    let pending = Pending {
        user: user.to_string(),
        purpose,
        back,
        exp: time::OffsetDateTime::now_utc().unix_timestamp() + PENDING_MINUTES * 60,
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
