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

use crate::i18n::{Key, Lang, lang_of, t};
use crate::layout::{avatar, shell, wordmark};
use crate::server::{self, PendingPurpose};

path_param!(token);

/// What a refusal code reads as on the page. The code travels through the
/// URL; the sentence never does.
pub fn error_text(code: &str, lang: Lang) -> &'static str {
    match code {
        "bad_login" => t(lang, Key::ErrBadLogin),
        "bad_code" => t(lang, Key::ErrBadCode),
        "invite_invalid" => t(lang, Key::ErrInviteInvalid),
        "invite_expired" => t(lang, Key::ErrInviteExpired),
        "invite_spent" => t(lang, Key::ErrInviteSpent),
        "email_taken" => t(lang, Key::ErrEmailTaken),
        "password_too_short" => t(lang, Key::ErrPasswordTooShort),
        "password_personal" => t(lang, Key::ErrPasswordPersonal),
        "passwords_differ" => t(lang, Key::ErrPasswordsDiffer),
        "enroll_first" => t(lang, Key::ErrEnrollFirst),
        "smtp_test" => t(lang, Key::ErrSmtpTest),
        "password_wrong" => t(lang, Key::ErrPasswordWrong),
        "password_same" => t(lang, Key::ErrPasswordSame),
        "rate_limited" => t(lang, Key::ErrRateLimited),
        "photo_too_big" => t(lang, Key::ErrPhotoTooBig),
        "not_an_image" => t(lang, Key::ErrNotAnImage),
        "no_file" => t(lang, Key::ErrNoFile),
        "session_unknown" => t(lang, Key::ErrSessionUnknown),
        "bad_theme" => t(lang, Key::ErrBadTheme),
        "bad_ui" => t(lang, Key::ErrBadUi),
        "bad_language" => t(lang, Key::ErrBadLanguage),
        _ => t(lang, Key::ErrFallback),
    }
}

/// The good news, where a page carries an `ok` code in its URL.
pub fn ok_text(code: &str, lang: Lang) -> &'static str {
    match code {
        "reset" => t(lang, Key::OkReset),
        "enrolled" => t(lang, Key::OkEnrolled),
        "photo_saved" => t(lang, Key::OkPhotoSaved),
        "photo_removed" => t(lang, Key::OkPhotoRemoved),
        "session_revoked" => t(lang, Key::OkSessionRevoked),
        "preferences" => t(lang, Key::Saved),
        "password" => t(lang, Key::PasswordSaved),
        _ => t(lang, Key::OkDone),
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
    // No session to read a preference from — mirroring iz's auth pages.
    let lang = Lang::En;
    let query = current_query(cx);
    let back = query_value(&query, "back").unwrap_or_else(|| "/".to_string());
    let error = query_value(&query, "error");
    let ok = query_value(&query, "ok");
    let stage = view! {
        cx =>
        <main class="auth-stage">
            <div class="auth-column">
                (wordmark(cx).await?)
                <div class="auth-card">
                    <div class="auth-head">
                        <div class="auth-title">(t(lang, Key::SignInTitle))</div>
                        <div class="auth-sub">(t(lang, Key::SignInSub))</div>
                    </div>
                    if let Some(code) = ok {
                        <div class="auth-ok">(ok_text(&code, lang))</div>
                    }
                    if let Some(code) = error {
                        <div class="auth-problem">(error_text(&code, lang))</div>
                    }
                    <form method="post" action="/login">
                        <input type="hidden" name="back" value=(back)>
                        <label class="auth-field">
                            <span class="auth-label">(t(lang, Key::EmailLabel))</span>
                            <input
                                class="auth-input auth-input-mono"
                                type="email"
                                name="email"
                                autocomplete="email"
                                required=""
                            >
                        </label>
                        <label class="auth-field">
                            <span class="auth-label">(t(lang, Key::PasswordLabel))</span>
                            <input
                                class="auth-input auth-input-mono"
                                type="password"
                                name="password"
                                autocomplete="current-password"
                                required=""
                            >
                        </label>
                        <button class="auth-submit" type="submit">
                            <span class="auth-submit-text">(t(lang, Key::SignInButton))</span>
                        </button>
                    </form>
                    <a class="auth-alt" href="/forgot">(t(lang, Key::ForgotIt))</a>
                </div>
                <div class="auth-footer">(t(lang, Key::BrandFooter))</div>
            </div>
        </main>
    };
    shell(cx, t(lang, Key::TitleSignIn), None, stage).await
}

/// The second factor. Reached only with a pending-login cookie; without one
/// the request starts over at the sign-in card.
#[route(GET "/login/totp")]
async fn totp(cx: &Cx) -> Result<Response> {
    match server::opened_pending(cx) {
        Some(pending) if pending.purpose == PendingPurpose::Login => {
            let lang = Lang::En;
            let query = current_query(cx);
            let error = query_value(&query, "error");
            let stage = view! {
                cx =>
                <main class="auth-stage">
                    <div class="auth-column">
                        (wordmark(cx).await?)
                        <div class="auth-card">
                            <div class="auth-head">
                                <div class="auth-title">(t(lang, Key::TotpTitle))</div>
                                <div class="auth-sub">(t(lang, Key::TotpSub))</div>
                            </div>
                            if let Some(code) = error {
                                <div class="auth-problem">(error_text(&code, lang))</div>
                            }
                            <form method="post" action="/login/totp">
                                <label class="auth-field">
                                    <span class="auth-label">(t(lang, Key::CodeLabel))</span>
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
                                    <span class="auth-submit-text">(t(lang, Key::VerifyButton))</span>
                                </button>
                            </form>
                        </div>
                        <div class="auth-footer">(t(lang, Key::BrandFooter))</div>
                    </div>
                </main>
            };
            shell(cx, t(lang, Key::TitleTotp), None, stage)
                .await?
                .into_response(cx)
        }
        _ => see_other("/login").into_response(cx),
    }
}

/// The invited member's first screen: name and password, address locked to
/// what the invite carries.
#[route(GET "/invite/{token}")]
async fn invite(cx: &Cx) -> Result<Response> {
    let lang = Lang::En;
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
                            <div class="auth-title">(t(lang, Key::InviteTitle))</div>
                            <div class="auth-sub">(t(lang, Key::InviteSub))</div>
                        </div>
                        if let Some(code) = error {
                            <div class="auth-problem">(error_text(&code, lang))</div>
                        }
                        <form method="post" action="/invite">
                            <input type="hidden" name="token" value=(token.to_string())>
                            <div class="auth-field">
                                <span class="auth-label">(t(lang, Key::EmailLabel))</span>
                                <div class="auth-locked">
                                    <span class="auth-locked-value">(invite.email)</span>
                                </div>
                            </div>
                            <label class="auth-field">
                                <span class="auth-label">(t(lang, Key::YourNameLabel))</span>
                                <input
                                    class="auth-input"
                                    type="text"
                                    name="name"
                                    autocomplete="name"
                                    required=""
                                >
                            </label>
                            <label class="auth-field">
                                <span class="auth-label">(t(lang, Key::PasswordLabel))</span>
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
                                <span class="auth-label">(t(lang, Key::PasswordAgainLabel))</span>
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
                                <span class="auth-submit-text">(t(lang, Key::CreateAccountButton))</span>
                            </button>
                        </form>
                    </div>
                    <div class="auth-footer">(t(lang, Key::BrandFooter))</div>
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
                            <div class="auth-title">(t(lang, Key::InviteDeadTitle))</div>
                        </div>
                        <div class="auth-problem">(error_text(code, lang))</div>
                        <a class="auth-alt" href="/">(t(lang, Key::BackToSignIn))</a>
                    </div>
                </div>
            </main>
        }
    };
    shell(cx, t(lang, Key::TitleInvited), None, stage)
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
    let lang = Lang::En;
    let query = current_query(cx);
    let error = query_value(&query, "error");

    let stage = view! {
        cx =>
        <main class="auth-stage">
            <div class="auth-column">
                (wordmark(cx).await?)
                <div class="auth-card">
                    <div class="auth-head">
                        <div class="auth-title">(t(lang, Key::EnrollTitle))</div>
                        <div class="auth-sub">(t(lang, Key::EnrollSub))</div>
                    </div>
                    if let Some(code) = error {
                        <div class="auth-problem">(error_text(&code, lang))</div>
                    }
                    <div class="auth-qr">(topcoat::view::Unescaped::new_unchecked(qr))</div>
                    <div class="auth-secret">(manual)</div>
                    <form method="post" action="/enroll">
                        <label class="auth-field">
                            <span class="auth-label">(t(lang, Key::CodeLabel))</span>
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
                            <span class="auth-submit-text">(t(lang, Key::ConfirmAndSignIn))</span>
                        </button>
                    </form>
                </div>
                <div class="auth-footer">(t(lang, Key::BrandFooter))</div>
            </div>
        </main>
    };
    shell(cx, t(lang, Key::TitleEnroll), None, stage)
        .await?
        .into_response(cx)
}

/// The sessions card builds its rows as a string — one per live session —
/// so its interpolations never pass through `view!`'s escaping. The
/// discipline matches admin.rs's `escape`: everything user-controlled
/// (agent, address) crosses it before it reaches the markup.
fn escape(raw: &str) -> String {
    raw.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// What the agent string means to a person — "Chrome on Linux", not the raw
/// header. The full string stays one click away in the session's detail.
/// Substring matching in precedence order (Edge before Chrome before Safari:
/// each carries the later one's token too); shared with the admin panel.
/// Browser and system names are proper nouns and stay untranslated; only the
/// unknown-device fallback follows the viewer's language.
pub(crate) fn device_label(agent: Option<&str>, lang: Lang) -> String {
    let Some(agent) = agent.filter(|agent| !agent.is_empty()) else {
        return t(lang, Key::UnknownDevice).to_string();
    };
    let browser = if agent.contains("Edg/") {
        "Edge"
    } else if agent.contains("Firefox/") {
        "Firefox"
    } else if agent.contains("Chrome/") {
        "Chrome"
    } else if agent.contains("Safari/") {
        "Safari"
    } else {
        "Browser"
    };
    let system = if agent.contains("iPhone") {
        "iPhone"
    } else if agent.contains("iPad") {
        "iPad"
    } else if agent.contains("Android") {
        "Android"
    } else if agent.contains("Windows") {
        "Windows"
    } else if agent.contains("Mac OS X") {
        "macOS"
    } else if agent.contains("CrOS") {
        "ChromeOS"
    } else if agent.contains("Linux") {
        "Linux"
    } else {
        return browser.to_string();
    };
    format!("{browser} on {system}")
}

/// `2026-09-04 10:22`: the last-seen stamp. An unrenderable stamp falls back
/// to the day — a stamp that cannot print must still say something true.
fn stamp_min(when: time::OffsetDateTime) -> String {
    when.format(&time::macros::format_description!(
        "[year]-[month]-[day] [hour]:[minute]"
    ))
    .unwrap_or_else(|_| when.date().to_string())
}

/// The sessions card: one header row per live session — what a person
/// recognizes (device, address, the current one chipped) — with everything
/// else a click behind it. The item is a `<details>`, so the open state and
/// its modal styling (style/main.scss) work with no script at all; the full
/// agent string, the stamps and the revoke live in the detail. The current
/// session's button reads as the way out of this browser; every other names
/// what it does.
fn sessions_html(
    sessions: &[im_core::sessions::SessionInfo],
    current: Option<&str>,
    lang: Lang,
) -> String {
    let mut rows = String::new();
    for session in sessions {
        let mine = current == Some(session.token_hash.as_str());
        let seen = session.seen_at.unwrap_or(session.created_at);
        let chip = if mine {
            format!(
                r#" <span class="chip chip-connected">{}</span>"#,
                t(lang, Key::ThisSessionChip)
            )
        } else {
            String::new()
        };
        let ip = session
            .ip
            .as_deref()
            .map(escape)
            .unwrap_or_else(|| "—".to_string());
        rows.push_str(&format!(
            concat!(
                r#"<details class="session-item"><summary class="session-head">"#,
                r#"<span class="session-device">{}{}</span>"#,
                r#"<span class="session-ip mono">{}</span>"#,
                r#"</summary><div class="session-detail">"#,
                r#"<dl class="profile-fields">"#,
                r#"<div class="profile-field"><dt class="auth-label">{}</dt>"#,
                r#"<dd class="profile-value session-agent">{}</dd></div>"#,
                r#"<div class="profile-field"><dt class="auth-label">{}</dt>"#,
                r#"<dd class="profile-value mono">{}</dd></div>"#,
                r#"<div class="profile-field"><dt class="auth-label">{}</dt>"#,
                r#"<dd class="profile-value">{}</dd></div>"#,
                r#"<div class="profile-field"><dt class="auth-label">{}</dt>"#,
                r#"<dd class="profile-value">{}</dd></div>"#,
                r#"<div class="profile-field"><dt class="auth-label">{}</dt>"#,
                r#"<dd class="profile-value">{}</dd></div>"#,
                r#"</dl>"#,
                r#"<form method="post" action="/sessions/revoke">"#,
                r#"<input type="hidden" name="session" value="{}">"#,
                r#"<button class="admin-action" type="submit">{}</button></form>"#,
                r#"</div></details>"#
            ),
            escape(&device_label(session.agent.as_deref(), lang)),
            chip,
            ip,
            t(lang, Key::DeviceLabel),
            session
                .agent
                .as_deref()
                .filter(|agent| !agent.is_empty())
                .map(escape)
                .unwrap_or_else(|| t(lang, Key::UnknownDevice).to_string()),
            t(lang, Key::AddressLabel),
            ip,
            t(lang, Key::SignedInLabel),
            session.created_at.date(),
            t(lang, Key::LastSeenLabel),
            stamp_min(seen),
            t(lang, Key::ExpiresLabel),
            session.expires_at.date(),
            escape(&session.token_hash),
            if mine {
                t(lang, Key::SignOutButton)
            } else {
                t(lang, Key::RevokeButton)
            },
        ));
    }
    rows
}

/// The signed-in landing. im is an auth service, not an app: this page is
/// the proof of session, the person's profile — photo and the counts their
/// identity has earned — and the way out. izlek gives a profile its own
/// page under `/people`; im has exactly one signed-in screen, so the
/// profile is a section of it.
async fn signed_in(cx: &Cx, user: &im_core::model::User) -> Result {
    let lang = lang_of(Some(user));
    let query = current_query(cx);
    let ok = query_value(&query, "ok");
    let error = query_value(&query, "error");
    let stats = im_core::stats::profile_stats(&server::app(cx).store, &user.id).await?;
    let joined = user.created_at.date().to_string();
    let sessions = im_core::sessions::list_sessions(&server::app(cx).store, &user.id).await?;
    let current = server::presented_session(cx).map(|token| im_core::accounts::hash_token(&token));
    let sessions_html = sessions_html(&sessions, current.as_deref(), lang);
    let stage = view! {
        cx =>
        <main class="auth-stage">
            <div class="auth-column">
                (wordmark(cx).await?)
                <div class="auth-card">
                    <div class="profile-head">
                        if user.has_photo {
                            // The face is the whole control surface: it opens
                            // the viewer, and the viewer carries Change/Remove
                            // (avatar_script builds them for `data-own`). The
                            // picker input hides here, unreached until the
                            // viewer's Change label points at it by id.
                            <button
                                class="avatar-view"
                                type="button"
                                aria-label=(t(lang, Key::ViewPhotoAria))
                                data-own=""
                            >
                                (avatar(cx, user).await?)
                            </button>
                            <input
                                id="profile-photo-input"
                                class="profile-file-hidden"
                                type="file"
                                name="photo"
                                accept="image/png,image/jpeg,image/gif,image/webp,image/avif"
                                form="profile-photo-form"
                                data-autosubmit=""
                            >
                        } else {
                            // Without one, the face itself is the picker: the
                            // label wraps the hidden input, which autosubmits
                            // on change (avatar_script) — no buttons at all.
                            <label class="profile-avatar-upload">
                                (avatar(cx, user).await?)
                                <input
                                    class="profile-file-hidden"
                                    type="file"
                                    name="photo"
                                    accept="image/png,image/jpeg,image/gif,image/webp,image/avif"
                                    form="profile-photo-form"
                                    data-autosubmit=""
                                >
                            </label>
                        }
                        <div class="profile-heading">
                            <div class="auth-title">(user.name.clone())</div>
                            <div class="profile-marks">
                                if user.totp_confirmed {
                                    <span class="chip chip-connected">(t(lang, Key::TwoFaOn))</span>
                                } else {
                                    <span class="chip chip-muted">(t(lang, Key::TwoFaOff))</span>
                                }
                                if user.admin {
                                    <span class="chip chip-accent">(t(lang, Key::AdminChip))</span>
                                }
                            </div>
                        </div>
                    </div>
                    if let Some(code) = ok {
                        <div class="auth-ok">(ok_text(&code, lang))</div>
                    }
                    if let Some(code) = error {
                        <div class="auth-problem">(error_text(&code, lang))</div>
                    }
                    <dl class="profile-fields">
                        <div class="profile-field">
                            <dt class="auth-label">(t(lang, Key::EmailLabel))</dt>
                            <dd class="profile-value mono">(user.email.clone())</dd>
                        </div>
                        <div class="profile-field">
                            <dt class="auth-label">(t(lang, Key::MemberSinceLabel))</dt>
                            <dd class="profile-value">(joined)</dd>
                        </div>
                    </dl>
                    <a class="auth-alt" href=(format!("/people/{}", user.id))>(t(lang, Key::PublicProfileLink))</a>
                    // Both forms carry no visible chrome of their own: the
                    // picker input hides beside the face, the remove button
                    // lives in the viewer — all reaching here by `form=`.
                    <form
                        id="profile-photo-form"
                        method="post"
                        action="/api/profile_photo"
                        enctype="multipart/form-data"
                    ></form>
                    if user.has_photo {
                        <form
                            id="profile-photo-remove"
                            method="post"
                            action="/api/delete_profile_photo"
                        ></form>
                    }
                </div>
                <div class="auth-card">
                    <dl class="profile-stats">
                        <div class="profile-stat">
                            <dd class="profile-stat-value">(stats.sign_ins)</dd>
                            <dt class="auth-label">(t(lang, Key::StatSignIns))</dt>
                        </div>
                        <div class="profile-stat">
                            <dd class="profile-stat-value">(stats.active_sessions)</dd>
                            <dt class="auth-label">(t(lang, Key::StatActiveSessions))</dt>
                        </div>
                        <div class="profile-stat">
                            <dd class="profile-stat-value">(stats.connected_apps)</dd>
                            <dt class="auth-label">(t(lang, Key::StatConnectedApps))</dt>
                        </div>
                    </dl>
                </div>
                <div class="auth-card">
                    <div class="auth-title">(t(lang, Key::SessionsTitle))</div>
                    <div class="session-list">(topcoat::view::Unescaped::new_unchecked(sessions_html))</div>
                </div>
                <div class="auth-card" id="preferences">
                    <div class="auth-title">(t(lang, Key::PreferencesLabel))</div>
                    <form method="post" action="/preferences">
                        <label class="auth-field">
                            <span class="auth-label">(t(lang, Key::ThemeLabel))</span>
                            <select class="auth-input" name="theme">
                                <option value="light" selected=(user.theme == "light")>(t(lang, Key::LightOption))</option>
                                <option value="dark" selected=(user.theme == "dark")>(t(lang, Key::DarkOption))</option>
                            </select>
                        </label>
                        <label class="auth-field">
                            <span class="auth-label">(t(lang, Key::UiLabel))</span>
                            <select class="auth-input" name="ui">
                                <option value="instrument" selected=(user.ui == "instrument")>(t(lang, Key::InstrumentOption))</option>
                                <option value="ledger" selected=(user.ui == "ledger")>(t(lang, Key::LedgerOption))</option>
                            </select>
                        </label>
                        <label class="auth-field">
                            <span class="auth-label">(t(lang, Key::LanguageLabel))</span>
                            <select class="auth-input" name="language">
                                <option value="en" selected=(user.language == "en")>"English"</option>
                                <option value="tr" selected=(user.language == "tr")>"Türkçe"</option>
                            </select>
                        </label>
                        <button class="auth-submit" type="submit">
                            <span class="auth-submit-text">(t(lang, Key::SaveButton))</span>
                        </button>
                    </form>
                </div>
                <div class="auth-card" id="password">
                    <div class="auth-title">(t(lang, Key::ChangePassword))</div>
                    <form method="post" action="/password">
                        <label class="auth-field">
                            <span class="auth-label">(t(lang, Key::CurrentPasswordLabel))</span>
                            <input
                                class="auth-input auth-input-mono"
                                type="password"
                                name="current"
                                autocomplete="current-password"
                                required=""
                            >
                        </label>
                        <label class="auth-field">
                            <span class="auth-label">(t(lang, Key::NewPasswordLabel))</span>
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
                            <span class="auth-label">(t(lang, Key::NewPasswordAgainLabel))</span>
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
                            <span class="auth-submit-text">(t(lang, Key::ChangePassword))</span>
                        </button>
                    </form>
                    <div class="auth-sub">(t(lang, Key::AccountPasswordNote))</div>
                </div>
                <div class="auth-card">
                    <form method="post" action="/logout">
                        <button class="auth-submit" type="submit">
                            <span class="auth-submit-text">(t(lang, Key::SignOutEverywhere))</span>
                        </button>
                    </form>
                    if user.admin {
                        <a class="auth-alt" href="/admin">(t(lang, Key::AdminPanelLink))</a>
                    }
                </div>
                <div class="auth-footer">(t(lang, Key::BrandFooter))</div>
            </div>
        </main>
        (crate::layout::avatar_script(cx, lang).await?)
    };
    shell(cx, "im", Some(user), stage).await
}

/// "Forgot it?" — the self-serve reset ask. It answers the same whether the
/// address has an account: one quiet note, the same one for every address.
#[page("/forgot")]
async fn forgot(cx: &Cx) -> Result {
    let lang = Lang::En;
    let query = current_query(cx);
    let error = query_value(&query, "error");
    let sent = query_value(&query, "ok").as_deref() == Some("sent");
    let stage = view! {
        cx =>
        <main class="auth-stage">
            <div class="auth-column">
                (wordmark(cx).await?)
                <div class="auth-card">
                    <div class="auth-head">
                        <div class="auth-title">(t(lang, Key::ForgotTitle))</div>
                        <div class="auth-sub">(t(lang, Key::ForgotSub))</div>
                    </div>
                    if sent {
                        <div class="auth-ok">(t(lang, Key::ForgotSentNote))</div>
                    }
                    if let Some(code) = error {
                        <div class="auth-problem">(error_text(&code, lang))</div>
                    }
                    <form method="post" action="/forgot">
                        <label class="auth-field">
                            <span class="auth-label">(t(lang, Key::EmailLabel))</span>
                            <input
                                class="auth-input auth-input-mono"
                                type="email"
                                name="email"
                                autocomplete="email"
                                required=""
                            >
                        </label>
                        <button class="auth-submit" type="submit">
                            <span class="auth-submit-text">(t(lang, Key::SendLinkButton))</span>
                        </button>
                    </form>
                    <a class="auth-alt" href="/">(t(lang, Key::BackToSignInDash))</a>
                </div>
                <div class="auth-footer">(t(lang, Key::BrandFooter))</div>
            </div>
        </main>
    };
    shell(cx, t(lang, Key::TitleForgot), None, stage).await
}

/// The reset link's destination: a new password, twice. A dead link never
/// shows a working form — it goes back to the ask with the refusal named.
#[route(GET "/reset/{token}")]
async fn reset_page(cx: &Cx) -> Result<Response> {
    let lang = Lang::En;
    let token: &str = path_param::<Token>(cx);
    if !im_core::accounts::reset_link_valid(&server::app(cx).store, token).await? {
        return see_other("/forgot?error=reset_invalid").into_response(cx);
    }
    let query = current_query(cx);
    let error = query_value(&query, "error");
    let stage = view! {
        cx =>
        <main class="auth-stage">
            <div class="auth-column">
                (wordmark(cx).await?)
                <div class="auth-card">
                    <div class="auth-head">
                        <div class="auth-title">(t(lang, Key::ResetTitle))</div>
                        <div class="auth-sub">(t(lang, Key::ResetSub))</div>
                    </div>
                    if let Some(code) = error {
                        <div class="auth-problem">(error_text(&code, lang))</div>
                    }
                    <form method="post" action="/reset">
                        <input type="hidden" name="token" value=(token.to_string())>
                        <label class="auth-field">
                            <span class="auth-label">(t(lang, Key::NewPasswordLabel))</span>
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
                            <span class="auth-label">(t(lang, Key::NewPasswordAgainLabel))</span>
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
                            <span class="auth-submit-text">(t(lang, Key::ChangePassword))</span>
                        </button>
                    </form>
                </div>
                <div class="auth-footer">(t(lang, Key::BrandFooter))</div>
            </div>
        </main>
    };
    shell(cx, t(lang, Key::TitleReset), None, stage)
        .await?
        .into_response(cx)
}
