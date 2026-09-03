//! The pages: sign-in, the second factor, invite acceptance, TOTP enrolment,
//! and the signed-in landing. Every page is server-rendered on every request;
//! a refused form post comes back as `?error=<code>` on the query and the
//! page reads it out.

use im_core::accounts::MIN_PASSWORD_CHARS;
use topcoat::Result;
use topcoat::context::Cx;
use topcoat::router::error::see_other;
use topcoat::router::response::{IntoResponse, Response};
use topcoat::router::{page, path_param, route};
use topcoat::view::view;

use crate::layout::{shell, wordmark};
use crate::server::{self, PendingPurpose};

path_param!(token);

/// What a refusal code reads as on the page. The code travels through the
/// URL; the sentence never does.
pub fn error_text(code: &str) -> &'static str {
    match code {
        "bad_login" => "Wrong email or password.",
        "bad_code" => "That code didn't match — try again.",
        "invite_invalid" => "This invite link is not valid.",
        "invite_expired" => "This invite has expired. Ask for a fresh one.",
        "invite_spent" => "This invite was already used.",
        "email_taken" => "An account with this address already exists.",
        "password_too_short" => "The password needs at least 10 characters.",
        "password_personal" => "The password can't contain your address or your name.",
        "passwords_differ" => "The two passwords don't match.",
        "enroll_first" => "Set up your second factor first.",
        "smtp_test" => "The test mail could not be sent.",
        _ => "Something went wrong. Try again.",
    }
}

/// The refusal this request carries back, if any. Values come percent-
/// decoded: `redirect_uri=http%3A%2F%2F…` must equal the registered URI.
pub fn query_value(query: &str, key: &str) -> Option<String> {
    query.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        (k == key).then(|| urldecode(v))
    })
}

/// Percent-decodes a query value (`+` is a space, form-style).
pub fn urldecode(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("");
                match u8::from_str_radix(hex, 16) {
                    Ok(byte) => {
                        out.push(byte);
                        i += 3;
                    }
                    Err(_) => {
                        out.push(b'%');
                        i += 1;
                    }
                }
            }
            byte => {
                out.push(byte);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn current_query(cx: &Cx) -> String {
    topcoat::router::request::uri(cx)
        .query()
        .unwrap_or("")
        .to_string()
}

/// The front door: the sign-in card, or the signed-in landing when the
/// browser already holds a session.
#[page("/")]
async fn landing(cx: &Cx) -> Result {
    match server::current_user(cx).await {
        Some(user) => signed_in(cx, &user).await,
        None => login_card(cx).await,
    }
}

/// `/login` is the same card with a `back` it must keep: the `/authorize`
/// call the browser was in the middle of.
#[page("/login")]
async fn login(cx: &Cx) -> Result {
    login_card(cx).await
}

async fn login_card(cx: &Cx) -> Result {
    let query = current_query(cx);
    let back = query_value(&query, "back").unwrap_or_else(|| "/".to_string());
    let error = query_value(&query, "error");
    let stage = view! {
        cx =>
        <main class="auth-stage">
            <div class="auth-column">
                (wordmark(cx).await?)
                <div class="auth-card">
                    <div class="auth-head">
                        <div class="auth-title">"Sign in"</div>
                        <div class="auth-sub">"One account for everything Dizey."</div>
                    </div>
                    if let Some(code) = error {
                        <div class="auth-problem">(error_text(&code))</div>
                    }
                    <form method="post" action="/login">
                        <input type="hidden" name="back" value=(back)>
                        <label class="auth-field">
                            <span class="auth-label">"Email"</span>
                            <input
                                class="auth-input auth-input-mono"
                                type="email"
                                name="email"
                                autocomplete="email"
                                required=""
                            >
                        </label>
                        <label class="auth-field">
                            <span class="auth-label">"Password"</span>
                            <input
                                class="auth-input auth-input-mono"
                                type="password"
                                name="password"
                                autocomplete="current-password"
                                required=""
                            >
                        </label>
                        <button class="auth-submit" type="submit">
                            <span class="auth-submit-text">"Sign in"</span>
                        </button>
                    </form>
                </div>
                <div class="auth-footer">"im · Dizey SSO"</div>
            </div>
        </main>
    };
    shell(cx, "Sign in · im", stage).await
}

/// The second factor. Reached only with a pending-login cookie; without one
/// the request starts over at the sign-in card.
#[route(GET "/login/totp")]
async fn totp(cx: &Cx) -> Result<Response> {
    match server::opened_pending(cx) {
        Some(pending) if pending.purpose == PendingPurpose::Login => {
            let query = current_query(cx);
            let error = query_value(&query, "error");
            let stage = view! {
                cx =>
                <main class="auth-stage">
                    <div class="auth-column">
                        (wordmark(cx).await?)
                        <div class="auth-card">
                            <div class="auth-head">
                                <div class="auth-title">"Two-factor code"</div>
                                <div class="auth-sub">"The 6-digit code from your authenticator."</div>
                            </div>
                            if let Some(code) = error {
                                <div class="auth-problem">(error_text(&code))</div>
                            }
                            <form method="post" action="/login/totp">
                                <label class="auth-field">
                                    <span class="auth-label">"Code"</span>
                                    <input
                                        class="auth-input auth-input-mono"
                                        type="text"
                                        name="code"
                                        inputmode="numeric"
                                        pattern="[0-9]{6}"
                                        autocomplete="one-time-code"
                                        required=""
                                    >
                                </label>
                                <button class="auth-submit" type="submit">
                                    <span class="auth-submit-text">"Verify"</span>
                                </button>
                            </form>
                        </div>
                        <div class="auth-footer">"im · Dizey SSO"</div>
                    </div>
                </main>
            };
            shell(cx, "Two-factor · im", stage).await?.into_response(cx)
        }
        _ => see_other("/login").into_response(cx),
    }
}

/// The invited member's first screen: name and password, address locked to
/// what the invite carries.
#[route(GET "/invite/{token}")]
async fn invite(cx: &Cx) -> Result<Response> {
    let token: &str = path_param::<Token>(cx);
    let invite = im_core::accounts::invite_by_token(&server::app(cx).store, token).await?;
    let query = current_query(cx);
    let error = query_value(&query, "error");

    let usable = matches!(
        &invite,
        Some(invite) if invite.accepted_at.is_none() && invite.expires_at > time::OffsetDateTime::now_utc()
    );
    let stage = if usable {
        let invite = invite.expect("usable implies Some");
        view! {
            cx =>
            <main class="auth-stage">
                <div class="auth-column">
                    (wordmark(cx).await?)
                    <div class="auth-card">
                        <div class="auth-head">
                            <div class="auth-title">"You're invited"</div>
                            <div class="auth-sub">"Pick a name and a password. Next step sets up two-factor sign-in."</div>
                        </div>
                        if let Some(code) = error {
                            <div class="auth-problem">(error_text(&code))</div>
                        }
                        <form method="post" action="/invite">
                            <input type="hidden" name="token" value=(token.to_string())>
                            <div class="auth-field">
                                <span class="auth-label">"Email"</span>
                                <div class="auth-locked">
                                    <span class="auth-locked-value">(invite.email)</span>
                                </div>
                            </div>
                            <label class="auth-field">
                                <span class="auth-label">"Your name"</span>
                                <input
                                    class="auth-input"
                                    type="text"
                                    name="name"
                                    autocomplete="name"
                                    required=""
                                >
                            </label>
                            <label class="auth-field">
                                <span class="auth-label">"Password"</span>
                                <input
                                    class="auth-input auth-input-mono"
                                    type="password"
                                    name="password"
                                    autocomplete="new-password"
                                    minlength=(MIN_PASSWORD_CHARS.to_string())
                                    required=""
                                >
                            </label>
                            <label class="auth-field">
                                <span class="auth-label">"Password again"</span>
                                <input
                                    class="auth-input auth-input-mono"
                                    type="password"
                                    name="password_confirm"
                                    autocomplete="new-password"
                                    minlength=(MIN_PASSWORD_CHARS.to_string())
                                    required=""
                                >
                            </label>
                            <button class="auth-submit" type="submit">
                                <span class="auth-submit-text">"Create account"</span>
                            </button>
                        </form>
                    </div>
                    <div class="auth-footer">"im · Dizey SSO"</div>
                </div>
            </main>
        }
    } else {
        let code = match &invite {
            None => "invite_invalid",
            Some(i) if i.accepted_at.is_some() => "invite_spent",
            _ => "invite_expired",
        };
        view! {
            cx =>
            <main class="auth-stage">
                <div class="auth-column">
                    (wordmark(cx).await?)
                    <div class="auth-card">
                        <div class="auth-head">
                            <div class="auth-title">"This link doesn't work"</div>
                        </div>
                        <div class="auth-problem">(error_text(code))</div>
                        <a class="auth-alt" href="/">"Back to sign in"</a>
                    </div>
                </div>
            </main>
        }
    };
    shell(cx, "You're invited · im", stage)
        .await?
        .into_response(cx)
}

/// TOTP enrolment: the QR, the manual key, and the first code that proves
/// the authenticator agrees. Reached with a pending-enroll cookie, set when
/// the account was created.
#[route(GET "/enroll")]
async fn enroll(cx: &Cx) -> Result<Response> {
    let Some(pending) = server::opened_pending(cx) else {
        return see_other("/login").into_response(cx);
    };
    if pending.purpose != PendingPurpose::Enroll {
        return see_other("/login").into_response(cx);
    }
    let user = im_core::accounts::user_by_id(
        &server::app(cx).store,
        &im_core::model::UserId::from(pending.user.clone()),
    )
    .await?
    .ok_or_else(|| topcoat::Error::from(std::io::Error::other("pending user is gone")))?;
    let Some((secret, _confirmed)) =
        im_core::totp::totp_secret(&server::app(cx).store, &user.id).await?
    else {
        return see_other("/login?error=enroll_first").into_response(cx);
    };

    let issuer = &server::app(cx).config.issuer;
    let uri = im_core::totp::totp_uri("im", &user.email, &secret);
    let qr = qrcode::QrCode::new(uri.as_bytes())
        .and_then(|code| {
            Ok::<_, qrcode::types::QrError>(
                code.render::<qrcode::render::svg::Color>()
                    .min_dimensions(200, 200)
                    .build(),
            )
        })
        .map_err(|e| topcoat::Error::from(std::io::Error::other(format!("qr: {e}"))))?;
    let manual = im_core::totp::display_secret(&secret);
    let _ = issuer;
    let query = current_query(cx);
    let error = query_value(&query, "error");

    let stage = view! {
        cx =>
        <main class="auth-stage">
            <div class="auth-column">
                (wordmark(cx).await?)
                <div class="auth-card">
                    <div class="auth-head">
                        <div class="auth-title">"Set up two-factor"</div>
                        <div class="auth-sub">"Scan with your authenticator, then type the 6-digit code it shows."</div>
                    </div>
                    if let Some(code) = error {
                        <div class="auth-problem">(error_text(&code))</div>
                    }
                    <div class="auth-qr">(topcoat::view::Unescaped::new_unchecked(qr))</div>
                    <div class="auth-secret">(manual)</div>
                    <form method="post" action="/enroll">
                        <label class="auth-field">
                            <span class="auth-label">"Code"</span>
                            <input
                                class="auth-input auth-input-mono"
                                type="text"
                                name="code"
                                inputmode="numeric"
                                pattern="[0-9]{6}"
                                autocomplete="one-time-code"
                                required=""
                            >
                        </label>
                        <button class="auth-submit" type="submit">
                            <span class="auth-submit-text">"Confirm and sign in"</span>
                        </button>
                    </form>
                </div>
                <div class="auth-footer">"im · Dizey SSO"</div>
            </div>
        </main>
    };
    shell(cx, "Two-factor setup · im", stage)
        .await?
        .into_response(cx)
}

/// The signed-in landing. im is an auth service, not an app: this page is
/// the proof of session, the way out, and nothing more.
async fn signed_in(cx: &Cx, user: &im_core::model::User) -> Result {
    let query = current_query(cx);
    let ok = query_value(&query, "ok");
    let stage = view! {
        cx =>
        <main class="auth-stage">
            <div class="auth-column">
                (wordmark(cx).await?)
                <div class="auth-card">
                    <div class="auth-head">
                        <div class="auth-title">(format!("Signed in as {}", user.name))</div>
                        <div class="auth-sub">(user.email.clone())</div>
                    </div>
                    if ok.as_deref() == Some("enrolled") {
                        <div class="auth-ok">"Two-factor sign-in is on. You're all set."</div>
                    }
                    <form method="post" action="/logout">
                        <button class="auth-submit" type="submit">
                            <span class="auth-submit-text">"Sign out everywhere"</span>
                        </button>
                    </form>
                    if user.admin {
                        <a class="auth-alt" href="/admin">"Admin panel"</a>
                    }
                </div>
                <div class="auth-footer">"im · Dizey SSO"</div>
            </div>
        </main>
    };
    shell(cx, "im", stage).await
}
