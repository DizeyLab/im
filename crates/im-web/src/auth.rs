//! The form handlers behind the pages. Every one answers a plain 303: the
//! page it lands on reads `?error=` / `?ok=` back on render — im serves no
//! client-side script, so there is no action value to answer with.

use im_core::accounts::{self, AccountError};
use im_core::model::UserId;
use serde::Deserialize;
use topcoat::Result;
use topcoat::context::Cx;
use topcoat::router::content::Form;
use topcoat::router::response::IntoResponse as _;
use topcoat::router::{HeaderName, StatusCode, header, route};

use crate::server::{self, PendingPurpose};

pub(crate) type Redirect = Result<(StatusCode, [(HeaderName, String); 1])>;

pub(crate) fn see(location: String) -> Redirect {
    Ok((StatusCode::SEE_OTHER, [(header::LOCATION, location)]))
}

/// Percent-encodes a value for a query pair. The `back` a login carries is
/// always a local `/authorize?...` URL, which is full of `?&=` of its own.
fn urlencode(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for byte in raw.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// A `back` worth honoring: a local absolute path, never `//elsewhere` —
/// and never a backslash, which browsers normalize like a slash, so
/// `/\evil.com` would ride the guard out to a foreign host. Anything
/// else — including a full URL — becomes the front door.
fn safe_back(raw: &str) -> &str {
    if raw.starts_with('/') && !raw.starts_with("//") && !raw.contains('\\') {
        raw
    } else {
        "/"
    }
}

/// Where a logout sends the browser. A local absolute path always
/// qualifies — the login `back` rule. An absolute URL qualifies when its
/// origin is exactly one of the family's stored services': the sibling app
/// that sent the browser here gets it handed back. A foreign origin — and
/// anything unparseable — is refused to the front door.
fn logout_target(raw: Option<&str>, services: &[im_core::services::Service]) -> String {
    let Some(raw) = raw else {
        return "/".to_string();
    };
    if raw.starts_with('/') && !raw.starts_with("//") && !raw.contains('\\') {
        // The backslash rule is [`safe_back`]'s: browsers normalize
        // `/\evil.com` into a foreign navigation.
        return raw.to_string();
    }
    if let Some(origin) = url_origin(raw)
        && services
            .iter()
            .any(|s| url_origin(&s.url).is_some_and(|known| known == origin))
    {
        return raw.to_string();
    }
    "/".to_string()
}

/// The `scheme://authority` of an absolute http(s) URL, lowercased — the
/// whole of what an origin match compares. `None` for anything else.
fn url_origin(raw: &str) -> Option<String> {
    let (scheme, rest) = raw.split_once("://")?;
    if !scheme.eq_ignore_ascii_case("http") && !scheme.eq_ignore_ascii_case("https") {
        return None;
    }
    let authority = rest.split(['/', '?', '#']).next()?;
    if authority.is_empty() {
        return None;
    }
    Some(format!(
        "{}://{}",
        scheme.to_ascii_lowercase(),
        authority.to_ascii_lowercase()
    ))
}

/// Creation-time facts for the session row: the address the browser came
/// through and the agent it claims to be. The accept loop discards the peer
/// address, so the proxy headers are the only source — the first
/// `x-forwarded-for` hop, else `x-real-ip`, else nothing known.
fn session_meta(cx: &Cx) -> im_core::sessions::SessionMeta {
    let headers = topcoat::router::request::headers(cx);
    let ip = headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .map(str::trim)
        .filter(|hop| !hop.is_empty())
        .map(str::to_string)
        .or_else(|| {
            headers
                .get("x-real-ip")
                .and_then(|value| value.to_str().ok())
                .map(str::trim)
                .filter(|ip| !ip.is_empty())
                .map(str::to_string)
        });
    let agent = headers
        .get("user-agent")
        .and_then(|value| value.to_str().ok())
        .map(|value| value.chars().take(255).collect::<String>());
    im_core::sessions::SessionMeta { ip, agent }
}

#[derive(Deserialize)]
pub struct LoginForm {
    email: String,
    password: String,
    #[serde(default)]
    back: Option<String>,
}

#[route(POST "/login")]
async fn login(cx: &Cx, Form(input): Form<LoginForm>) -> Redirect {
    let back = safe_back(input.back.as_deref().unwrap_or("/")).to_string();
    let store = &server::app(cx).store;
    // The door stops listening after the panel's per-hour allowance of
    // failures. The refusal says nothing about which step refused, as always.
    let key = input.email.trim().to_lowercase();
    if accounts::login_blocked(store, &key).await? {
        server::log_event(cx, "login_limited", Some(&key), None).await;
        return see(format!(
            "/login?error=rate_limited&back={}",
            urlencode(&back)
        ));
    }
    match accounts::verify_login(store, &input.email, &input.password).await {
        Ok(user) if user.totp_confirmed => {
            let sealed = server::mint_pending(cx, &user.id, PendingPurpose::Login, back).await;
            server::set_pending_cookie(cx, sealed).await;
            let _ = accounts::clear_login_failures(store, &key).await;
            see("/login/totp".to_string())
        }
        Ok(user) => {
            let _ = accounts::clear_login_failures(store, &key).await;
            let token =
                im_core::sessions::create_session(store, &user.id, &session_meta(cx)).await?;
            server::set_session_cookie(cx, token.expose());
            server::log_event(cx, "login_ok", Some(&user.email), None).await;
            see(back)
        }
        Err(_) => {
            // The failure is logged against the address tried, never the
            // password — and never whether the address exists.
            let _ = accounts::record_login_failure(store, &key).await;
            server::log_event(cx, "login_fail", Some(&input.email), None).await;
            see(format!("/login?error=bad_login&back={}", urlencode(&back)))
        }
    }
}

#[derive(Deserialize)]
pub struct TotpForm {
    code: String,
}

#[route(POST "/login/totp")]
async fn login_totp(cx: &Cx, Form(input): Form<TotpForm>) -> Redirect {
    let Some(pending) = server::opened_pending(cx) else {
        return see("/login".to_string());
    };
    if pending.purpose != PendingPurpose::Login {
        return see("/login".to_string());
    }
    let store = &server::app(cx).store;
    let user_id = UserId::from(pending.user.clone());
    let ok = match accounts::user_by_id(store, &user_id).await? {
        Some(user) => match im_core::totp::totp_secret(store, &user.id).await? {
            Some((secret, confirmed)) => {
                // `consume_totp`, not a bare verify: the accepted timestep
                // is burned atomically, so a code cannot mint a second
                // session inside its drift window.
                confirmed
                    && im_core::totp::consume_totp(
                        store,
                        &user.id,
                        &secret,
                        input.code.trim(),
                        time::OffsetDateTime::now_utc(),
                    )
                    .await?
            }
            None => false,
        },
        None => false,
    };
    // The second factor gets the same ceiling as the first, keyed on the
    // account, so an attacker past the password cannot grind codes either.
    let totp_key = format!("totp:{}", pending.user);
    if accounts::login_blocked(store, &totp_key).await? {
        server::log_event(cx, "login_limited", None, Some("2fa")).await;
        server::clear_pending_cookie(cx);
        return see("/login?error=rate_limited".to_string());
    }
    if !ok {
        let _ = accounts::record_login_failure(store, &totp_key).await;
        server::log_event(cx, "totp_fail", None, Some("login")).await;
        return see("/login/totp?error=bad_code".to_string());
    }
    let _ = accounts::clear_login_failures(store, &totp_key).await;
    let token = im_core::sessions::create_session(store, &user_id, &session_meta(cx)).await?;
    let email = accounts::user_by_id(store, &user_id)
        .await?
        .map(|u| u.email);
    server::log_event(cx, "login_ok", email.as_deref(), Some("2fa")).await;
    server::clear_pending_cookie(cx);
    server::set_session_cookie(cx, token.expose());
    see(pending.back)
}

#[derive(Deserialize)]
pub struct InviteForm {
    token: String,
    name: String,
    password: String,
    password_confirm: String,
}

#[route(POST "/invite")]
async fn invite(cx: &Cx, Form(input): Form<InviteForm>) -> Redirect {
    if input.password != input.password_confirm {
        return see(format!("/invite/{}?error=passwords_differ", input.token));
    }
    let store = &server::app(cx).store;
    let user = match accounts::create_user_from_invite(
        store,
        &input.token,
        input.name.trim(),
        &input.password,
    )
    .await
    {
        Ok(user) => user,
        Err(problem) => {
            let code = match problem {
                AccountError::InviteInvalid => "invite_invalid",
                AccountError::InviteExpired => "invite_expired",
                AccountError::InviteSpent => "invite_spent",
                AccountError::EmailTaken => "email_taken",
                AccountError::Password(im_core::accounts::PasswordProblem::TooShort) => {
                    "password_too_short"
                }
                AccountError::Password(im_core::accounts::PasswordProblem::LooksLikeYou) => {
                    "password_personal"
                }
                _ => {
                    return Err(topcoat::Error::from(std::io::Error::other(
                        problem.to_string(),
                    )));
                }
            };
            return see(format!("/invite/{}?error={code}", input.token));
        }
    };
    let token = im_core::sessions::create_session(store, &user.id, &session_meta(cx)).await?;
    server::log_event(cx, "invite_accepted", Some(&user.email), None).await;
    // A member exists from this moment on: the roster — and every app
    // mirroring it — learns the new row now, not on their next full list.
    server::notify_profile(cx, &user.id).await;
    server::set_session_cookie(cx, token.expose());
    see("/".to_string())
}

#[route(POST "/enroll")]
async fn enroll(cx: &Cx, Form(input): Form<TotpForm>) -> Redirect {
    let Some(user) = server::current_user(cx).await else {
        return see("/login".to_string());
    };
    if user.totp_confirmed {
        return see("/".to_string());
    }
    let store = &server::app(cx).store;
    let Some((secret, _)) = im_core::totp::totp_secret(store, &user.id).await? else {
        return see("/enroll".to_string());
    };
    // The proving code burns its timestep too — the same replay rule the
    // login enforces, applied at the moment TOTP turns on.
    if !im_core::totp::consume_totp(
        store,
        &user.id,
        &secret,
        input.code.trim(),
        time::OffsetDateTime::now_utc(),
    )
    .await?
    {
        return see("/enroll?error=bad_code".to_string());
    }
    im_core::totp::confirm_totp(store, &user.id).await?;
    let email = accounts::user_by_id(store, &user.id)
        .await?
        .map(|u| u.email);
    server::log_event(cx, "enrolled", email.as_deref(), None).await;
    see("/?ok=enrolled".to_string())
}

/// "Sign out everywhere": the central session dies, and with it every
/// refresh token any app is still holding — see `sessions::revoke_session`.
#[route(POST "/logout")]
async fn logout(cx: &Cx) -> Redirect {
    sign_out_everywhere(cx).await?;
    see("/".to_string())
}

/// The shared half of both logouts: the central session dies — with it
/// every refresh token and app session bound to it — and the cookie is
/// tidied. Where the browser goes next is each route's own business.
async fn sign_out_everywhere(cx: &Cx) -> Result<()> {
    if let Some(token) = server::presented_session(cx) {
        let user = im_core::sessions::resolve_session(&server::app(cx).store, &token)
            .await?
            .map(|u| (u.id, u.email));
        im_core::sessions::revoke_session(&server::app(cx).store, &token).await?;
        // The eviction news is addressed to the dying session's own
        // connection, so its tab leaves at once instead of at the next
        // full refetch.
        if let Some((id, _)) = &user {
            server::note_revoked(cx, id.as_str(), Some(&im_core::accounts::hash_token(&token)))
                .await;
        }
        server::log_event(
            cx,
            "logout",
            user.as_ref().map(|(_, email)| email.as_str()),
            None,
        )
        .await;
    }
    server::clear_session_cookie(cx);
    Ok(())
}

/// The RP-initiated exit: a sibling app has cleared its own cookie and
/// sent the browser here as a top-level navigation. `back` names the
/// return address, judged by [`logout_target`] — and the central session
/// dies whatever the answer is.
#[route(GET "/logout")]
async fn logout_return(cx: &Cx) -> Redirect {
    let query = topcoat::router::request::uri(cx)
        .query()
        .unwrap_or("")
        .to_string();
    let back = crate::pages::query_value(&query, "back");
    sign_out_everywhere(cx).await?;
    let services = im_core::services::list(&server::app(cx).store).await?;
    see(logout_target(back.as_deref(), &services))
}

/// The signed-in probe behind the live channel's error path: a tab whose
/// stream died asks here whether its session still stands, and the bare
/// status — no HTML, no redirect — is the whole answer. 204 signed in,
/// 401 not.
#[route(GET "/api/me")]
async fn me_probe(cx: &Cx) -> topcoat::Result<topcoat::router::response::Response> {
    if server::current_user(cx).await.is_some() {
        (StatusCode::NO_CONTENT, "").into_response(cx)
    } else {
        (StatusCode::UNAUTHORIZED, "").into_response(cx)
    }
}

#[derive(Deserialize)]
pub struct ForgotForm {
    email: String,
}

/// The self-serve reset ask. It answers every address the same — the mail
/// either exists or it doesn't, and the page never says which. Each ask
/// retires the address's previous live link: the newest mail is the only
/// door. The asks themselves carry the login limiter's per-hour ceiling,
/// keyed on the address, so a stranger cannot turn the form into a
/// mail-bomb — and a throttled ask still answers exactly like a sent one.
#[route(POST "/forgot")]
async fn forgot(cx: &Cx, Form(input): Form<ForgotForm>) -> Redirect {
    let store = &server::app(cx).store;
    let email = input.email.trim().to_string();
    let key = format!("forgot:{}", email.to_lowercase());
    if accounts::login_blocked(store, &key).await? {
        server::log_event(cx, "forgot_limited", Some(&email), None).await;
        return see("/forgot?ok=sent".to_string());
    }
    // Every ask spends from the same budget, account or not — the mails
    // are the thing being rationed, and existence is never the answer.
    let _ = accounts::record_login_failure(store, &key).await;
    if let Some(token) = accounts::create_reset(store, &email).await? {
        let issuer = server::app(cx).config.issuer.clone();
        // The mail follows the account's language; a missing account still
        // answers identically, in English.
        let lang = accounts::user_by_email(store, &email)
            .await?
            .map(|user| crate::i18n::Lang::from_code(&user.language))
            .unwrap_or(crate::i18n::Lang::En);
        if crate::mailer::send_reset(store, &issuer, &email, token.expose(), lang)
            .await
            .is_ok()
        {
            server::log_event(cx, "reset_sent", Some(&email), None).await;
        }
    }
    see("/forgot?ok=sent".to_string())
}

#[derive(Deserialize)]
pub struct ResetForm {
    token: String,
    password: String,
    password_confirm: String,
}

/// Redeems a reset link: new password in, every session out. A dead link is
/// sent back to the ask — the form it came from is gone with it.
#[route(POST "/reset")]
async fn reset(cx: &Cx, Form(input): Form<ResetForm>) -> Redirect {
    if input.password != input.password_confirm {
        return see(format!("/reset/{}?error=passwords_differ", input.token));
    }
    let store = &server::app(cx).store;
    match accounts::redeem_reset(store, &input.token, &input.password).await {
        Ok(user) => {
            // redeem_reset swept every session of theirs inside the core;
            // their tabs hear the eviction here.
            server::note_revoked(cx, user.id.as_str(), None).await;
            server::log_event(cx, "password_reset", Some(&user.email), None).await;
            see("/login?ok=reset".to_string())
        }
        Err(AccountError::Password(problem)) => {
            let code = match problem {
                im_core::accounts::PasswordProblem::TooShort => "password_too_short",
                im_core::accounts::PasswordProblem::LooksLikeYou => "password_personal",
                _ => "passwords_differ",
            };
            see(format!("/reset/{}?error={code}", input.token))
        }
        Err(AccountError::ResetInvalid) => see("/forgot?error=reset_invalid".to_string()),
        Err(e) => Err(topcoat::Error::from(std::io::Error::other(e.to_string()))),
    }
}

#[derive(Deserialize)]
struct EmailChangeForm {
    email: String,
}

/// The landing's address change: one ask, two mails — the old address must
/// agree to let the account go and the new one to take it on. Without a
/// sender configured the two links come back on the redirect once — the
/// crate's unmailed idiom, and the requester is the only person who needs
/// them.
#[route(POST "/email_change")]
async fn email_change(cx: &Cx, Form(input): Form<EmailChangeForm>) -> Redirect {
    let Some(me) = server::current_user(cx).await else {
        return see("/".to_string());
    };
    let store = &server::app(cx).store;
    let (old_token, new_token) =
        match accounts::request_email_change(store, &me.id, &input.email).await {
            Ok(pair) => pair,
            Err(AccountError::InvalidEmail) => {
                return see("/?section=password&error=bad_email".to_string());
            }
            Err(AccountError::SameEmail) => {
                return see("/?section=password&error=same_email".to_string());
            }
            Err(AccountError::EmailTaken) => {
                return see("/?section=password&error=email_taken".to_string());
            }
            Err(e) => return Err(topcoat::Error::from(std::io::Error::other(e.to_string()))),
        };
    let issuer = server::app(cx).config.issuer.clone();
    // Both mails follow the account's own language.
    let lang = crate::i18n::Lang::from_code(&me.language);
    let old_mailed = crate::mailer::send_email_change(
        store,
        &issuer,
        &me.email,
        old_token.expose(),
        lang,
        false,
    )
    .await
    .is_ok();
    let new_mailed = crate::mailer::send_email_change(
        store,
        &issuer,
        input.email.trim(),
        new_token.expose(),
        lang,
        true,
    )
    .await
    .is_ok();
    server::log_event(
        cx,
        "email_change_asked",
        Some(&me.email),
        Some(input.email.trim().to_lowercase()).as_deref(),
    )
    .await;
    if old_mailed && new_mailed {
        see("/?section=password&ok=email_change_asked".to_string())
    } else {
        let links = format!(
            "{issuer}/email/{} {issuer}/email/{}",
            old_token.expose(),
            new_token.expose()
        );
        see(format!(
            "/?section=password&ok=email_change_asked&links={}",
            crate::oidc::urlencode(&links)
        ))
    }
}

#[derive(Deserialize)]
struct EmailConfirmForm {
    token: String,
}

/// A confirmation link's POST — the click that counts. The first mailbox
/// to agree only marks its side; the second applies the change. Signed-out
/// viewers may confirm, because holding the mailbox is the proof; each
/// lands where their state says, a session on the landing and everyone
/// else at the front door.
#[route(POST "/email")]
async fn email_confirm(cx: &Cx, Form(input): Form<EmailConfirmForm>) -> Redirect {
    let store = &server::app(cx).store;
    match accounts::confirm_email_change(store, &input.token).await {
        Ok(accounts::EmailChangeConfirmed::Applied(user)) => {
            server::log_event(cx, "email_changed", Some(&user.email), None).await;
            // Both mailboxes agreed and the address is rewritten: the
            // roster's row moved with it.
            server::notify_profile(cx, &user.id).await;
            if server::current_user(cx).await.is_some() {
                see("/?section=profile&ok=email_changed".to_string())
            } else {
                see("/login?ok=email_changed".to_string())
            }
        }
        Ok(accounts::EmailChangeConfirmed::AwaitOther) => {
            if server::current_user(cx).await.is_some() {
                see("/?section=profile&ok=email_half_confirmed".to_string())
            } else {
                see("/login?ok=email_half_confirmed".to_string())
            }
        }
        Err(AccountError::EmailTaken) => see("/login?error=email_taken".to_string()),
        Err(AccountError::EmailChangeInvalid) => {
            see("/login?error=email_change_invalid".to_string())
        }
        Err(e) => Err(topcoat::Error::from(std::io::Error::other(e.to_string()))),
    }
}
#[derive(Deserialize)]
struct SessionRevokeForm {
    session: String,
}

/// Revokes one of the signer's own sessions. The current one signs this
/// browser out — the server row dies and the cookie is tidied; any other
/// just dies where it lives.
#[route(POST "/sessions/revoke")]
async fn revoke_session(cx: &Cx, Form(input): Form<SessionRevokeForm>) -> Redirect {
    let Some(user) = server::current_user(cx).await else {
        return see("/".to_string());
    };
    let store = &server::app(cx).store;
    if let Some(presented) = server::presented_session(cx)
        && im_core::accounts::hash_token(&presented) == input.session
    {
        im_core::sessions::revoke_session(store, &presented).await?;
        // The news is addressed to this very session; this tab hears its
        // own eviction and goes home like any other.
        server::note_revoked(cx, user.id.as_str(), Some(&input.session)).await;
        server::clear_session_cookie(cx);
        return see("/".to_string());
    }
    // The row's address, when it is still there, is the useful half of the
    // log line — which of their devices they just killed.
    let ip = im_core::sessions::list_sessions(store, &user.id)
        .await?
        .into_iter()
        .find(|s| s.token_hash == input.session)
        .and_then(|s| s.ip);
    if !im_core::sessions::revoke_owned_session(store, &user.id, &input.session).await? {
        return see("/?section=sessions&error=session_unknown".to_string());
    }
    server::note_revoked(cx, user.id.as_str(), Some(&input.session)).await;
    server::log_event(cx, "session_revoked", Some(&user.email), ip.as_deref()).await;
    see("/?section=sessions&ok=session_revoked".to_string())
}

#[derive(Deserialize)]
struct PreferencesForm {
    theme: Option<String>,
    ui: Option<String>,
    language: Option<String>,
    timezone: Option<String>,
}

/// The landing's preferences: three selects, validated against the option
/// lists. Absent or unknown refuses the whole save — nothing half-written —
/// and the landing reads the refusal back through `pages::error_text`.
#[route(POST "/preferences")]
async fn preferences(cx: &Cx, Form(input): Form<PreferencesForm>) -> Redirect {
    let Some(user) = server::current_user(cx).await else {
        return see("/".to_string());
    };
    let Some(theme) = input.theme.as_deref() else {
        return see("/?section=preferences&error=bad_theme".to_string());
    };
    if theme != "light" && theme != "dark" {
        return see("/?section=preferences&error=bad_theme".to_string());
    }
    let Some(ui) = input.ui.as_deref() else {
        return see("/?section=preferences&error=bad_ui".to_string());
    };
    if ui != "instrument" && ui != "ledger" {
        return see("/?section=preferences&error=bad_ui".to_string());
    }
    let Some(language) = input.language.as_deref() else {
        return see("/?section=preferences&error=bad_language".to_string());
    };
    if language != "en" && language != "tr" {
        return see("/?section=preferences&error=bad_language".to_string());
    }
    let Some(timezone) = input.timezone.as_deref() else {
        return see("/?section=preferences&error=bad_zone".to_string());
    };
    if !crate::pages::zone_options().contains(&timezone.to_string()) {
        return see("/?section=preferences&error=bad_zone".to_string());
    }
    let store = &server::app(cx).store;
    im_core::accounts::set_preferences(store, &user.id, theme, language, ui, timezone).await?;
    // The timezone rides the directory: registered siblings apply it live,
    // the way a name or photo change announces itself.
    server::notify_profile(cx, &user.id).await;
    server::log_event(cx, "preferences_saved", Some(&user.email), None).await;
    see("/?section=preferences&ok=preferences".to_string())
}

#[derive(Deserialize)]
struct PasswordForm {
    current: String,
    password: String,
    password_confirm: String,
}

/// The landing's password pane: the admin panel's account form without the
/// admin gate — same field names, same refusal codes, and the same courtesy
/// to the browser holding the form (every other session dies, this one
/// proved the old password and keeps its own).
#[route(POST "/password")]
async fn password(cx: &Cx, Form(input): Form<PasswordForm>) -> Redirect {
    let Some(me) = server::current_user(cx).await else {
        return see("/".to_string());
    };
    if input.password != input.password_confirm {
        return see("/?section=password&error=passwords_differ".to_string());
    }
    let store = &server::app(cx).store;
    match im_core::accounts::change_password(store, &me, &input.current, &input.password).await {
        Ok(()) => {}
        Err(im_core::accounts::AccountError::Password(problem)) => {
            use im_core::accounts::PasswordProblem::*;
            let code = match problem {
                TooShort => "password_too_short",
                LooksLikeYou => "password_personal",
                WrongCurrent => "password_wrong",
                IsCurrent => "password_same",
            };
            return see(format!("/?section=password&error={code}"));
        }
        Err(e) => return Err(topcoat::Error::from(std::io::Error::other(e.to_string()))),
    }
    if let Some(token) = server::presented_session(cx) {
        let revoked = im_core::sessions::revoke_user_sessions_except(store, &me.id, &token)
            .await?;
        // Each dead session's own tab hears its eviction; the asking
        // browser's hash is never among them, so this tab stays.
        for hash in &revoked {
            server::note_revoked(cx, me.id.as_str(), Some(hash)).await;
        }
    }
    server::log_event(cx, "password_changed", Some(&me.email), None).await;
    see("/?section=password&ok=password".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn back_rejects_scheme_relative_and_backslash_paths() {
        assert_eq!(safe_back("/dashboard"), "/dashboard");
        assert_eq!(safe_back("/authorize?client_id=x"), "/authorize?client_id=x");
        assert_eq!(safe_back("//evil.example/path"), "/");
        // Browsers normalize the backslash into a slash: `/\evil.example`
        // navigates off-host exactly like `//evil.example`.
        assert_eq!(safe_back("/\\evil.example"), "/");
        assert_eq!(safe_back("/settings\\..\\..\\evil"), "/");
        assert_eq!(safe_back("https://evil.example"), "/");
        assert_eq!(safe_back("relative"), "/");
    }

    #[test]
    fn logout_target_judges_local_paths_by_the_back_rule() {
        let services: Vec<im_core::services::Service> = Vec::new();
        assert_eq!(logout_target(None, &services), "/");
        assert_eq!(logout_target(Some("/settings"), &services), "/settings");
        assert_eq!(logout_target(Some("//evil.example"), &services), "/");
        assert_eq!(logout_target(Some("/\\evil.example"), &services), "/");
        assert_eq!(
            logout_target(Some("https://stranger.example/bye"), &services),
            "/"
        );
    }

    #[test]
    fn logout_target_hands_the_browser_to_a_known_family_service() {
        let sibling = im_core::services::Service {
            key: "in".into(),
            name: "in".into(),
            url: "https://in.example".into(),
            owner: None,
            client_id: None,
            storage_limit_bytes: None,
        };
        let services = vec![sibling];
        assert_eq!(
            logout_target(Some("https://in.example/goodbye"), &services),
            "https://in.example/goodbye"
        );
        // A look-alike origin is still a stranger.
        assert_eq!(
            logout_target(Some("https://in.example.evil/bye"), &services),
            "/"
        );
        // The local-path rule stands beside the origin rule.
        assert_eq!(logout_target(Some("/\\in.example"), &services), "/");
    }
}
