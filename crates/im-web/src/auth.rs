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

type Redirect = Result<(StatusCode, [(HeaderName, String); 1])>;

fn see(location: String) -> Redirect {
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
    match accounts::verify_login(&server::app(cx).store, &input.email, &input.password).await {
        Ok(user) if user.totp_confirmed => {
            let sealed = server::mint_pending(cx, &user.id, PendingPurpose::Login, back);
            server::set_pending_cookie(cx, sealed);
            see("/login/totp".to_string())
        }
        Ok(user) => {
            // Accounts enrol TOTP at invite time, so this is the path for one
            // created before that rule — sign it in, enrolment comes next.
            let token = im_core::sessions::create_session(&server::app(cx).store, &user.id).await?;
            server::set_session_cookie(cx, token.expose());
            see(back)
        }
        Err(_) => see(format!("/login?error=bad_login&back={}", urlencode(&back))),
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
    if !ok {
        return see("/login/totp?error=bad_code".to_string());
    }
    let token = im_core::sessions::create_session(store, &user_id).await?;
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
    let sealed = server::mint_pending(cx, &user.id, PendingPurpose::Enroll, "/".to_string());
    server::set_pending_cookie(cx, sealed);
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
    server::clear_pending_cookie(cx);
    server::set_session_cookie(cx, token.expose());
    see("/?ok=enrolled".to_string())
}

/// "Sign out everywhere": the central session dies, and with it every
/// refresh token any app is still holding — see `sessions::revoke_session`.
#[route(POST "/logout")]
async fn logout(cx: &Cx) -> Redirect {
    if let Some(token) = server::presented_session(cx) {
        im_core::sessions::revoke_session(&server::app(cx).store, &token).await?;
    }
    server::clear_session_cookie(cx);
    see("/".to_string())
}
