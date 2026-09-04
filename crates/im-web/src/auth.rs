//! The form handlers behind the pages. Every one answers a plain 303: the
//! page it lands on reads `?error=` / `?ok=` back on render — im serves no
//! client-side script, so there is no action value to answer with.

use im_core::accounts::{self, AccountError};
use im_core::model::UserId;
use serde::Deserialize;
use topcoat::Result;
use topcoat::context::Cx;
use topcoat::router::content::Form;
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

/// A `back` worth honoring: a local absolute path, never `//elsewhere`.
/// Anything else — including a full URL — becomes the front door.
fn safe_back(raw: &str) -> &str {
    if raw.starts_with('/') && !raw.starts_with("//") {
        raw
    } else {
        "/"
    }
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
            // An account without confirmed 2FA — everyone who migrated from
            // İzlek — enrols before any session exists: same bar as an
            // invited account.
            if im_core::totp::totp_secret(store, &user.id).await?.is_none() {
                let secret = im_core::totp::generate_secret();
                im_core::totp::set_totp(store, &user.id, &secret).await?;
            }
            let sealed = server::mint_pending(cx, &user.id, PendingPurpose::Enroll, back).await;
            server::set_pending_cookie(cx, sealed).await;
            let _ = accounts::clear_login_failures(store, &key).await;
            see("/enroll".to_string())
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
                confirmed
                    && im_core::totp::verify_totp(
                        &secret,
                        input.code.trim(),
                        time::OffsetDateTime::now_utc(),
                    )
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
    let token = im_core::sessions::create_session(store, &user_id).await?;
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
    // TOTP enrolment is not optional: the account exists from here, and the
    // enrolment page is the only way forward.
    let secret = im_core::totp::generate_secret();
    im_core::totp::set_totp(store, &user.id, &secret).await?;
    let sealed = server::mint_pending(cx, &user.id, PendingPurpose::Enroll, "/".to_string()).await;
    server::set_pending_cookie(cx, sealed).await;
    server::log_event(cx, "invite_accepted", Some(&user.email), None).await;
    see("/enroll".to_string())
}

#[route(POST "/enroll")]
async fn enroll(cx: &Cx, Form(input): Form<TotpForm>) -> Redirect {
    let Some(pending) = server::opened_pending(cx) else {
        return see("/login".to_string());
    };
    if pending.purpose != PendingPurpose::Enroll {
        return see("/login".to_string());
    }
    let store = &server::app(cx).store;
    let user_id = UserId::from(pending.user);
    let Some((secret, _)) = im_core::totp::totp_secret(store, &user_id).await? else {
        return see("/login?error=enroll_first".to_string());
    };
    if !im_core::totp::verify_totp(&secret, input.code.trim(), time::OffsetDateTime::now_utc()) {
        return see("/enroll?error=bad_code".to_string());
    }
    im_core::totp::confirm_totp(store, &user_id).await?;
    let token = im_core::sessions::create_session(store, &user_id).await?;
    let email = accounts::user_by_id(store, &user_id)
        .await?
        .map(|u| u.email);
    server::log_event(cx, "enrolled", email.as_deref(), None).await;
    server::clear_pending_cookie(cx);
    server::set_session_cookie(cx, token.expose());
    // A migrated user who was mid-`/authorize` continues to their app; a
    // fresh invite lands on the welcome banner.
    if pending.back == "/" {
        see("/?ok=enrolled".to_string())
    } else {
        see(pending.back)
    }
}

/// "Sign out everywhere": the central session dies, and with it every
/// refresh token any app is still holding — see `sessions::revoke_session`.
#[route(POST "/logout")]
async fn logout(cx: &Cx) -> Redirect {
    if let Some(token) = server::presented_session(cx) {
        let email = im_core::sessions::resolve_session(&server::app(cx).store, &token)
            .await?
            .map(|u| u.email);
        im_core::sessions::revoke_session(&server::app(cx).store, &token).await?;
        server::log_event(cx, "logout", email.as_deref(), None).await;
    }
    server::clear_session_cookie(cx);
    see("/".to_string())
}

#[derive(Deserialize)]
pub struct ForgotForm {
    email: String,
}

/// The self-serve reset ask. It answers every address the same — the mail
/// either exists or it doesn't, and the page never says which. Each ask
/// retires the address's previous live link: the newest mail is the only
/// door.
#[route(POST "/forgot")]
async fn forgot(cx: &Cx, Form(input): Form<ForgotForm>) -> Redirect {
    let store = &server::app(cx).store;
    let email = input.email.trim().to_string();
    if let Some(token) = accounts::create_reset(store, &email).await? {
        let issuer = server::app(cx).config.issuer.clone();
        if crate::mailer::send_reset(store, &issuer, &email, token.expose())
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
