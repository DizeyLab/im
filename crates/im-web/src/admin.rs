//! The admin panel: users, mail, logs. One page, three sections, every
//! action a plain form post answering a 303 back to its section — the same
//! idiom as izlek-web's settings.rs/logs.rs, minus the client script.

use im_core::accounts;
use im_core::events;
use im_core::model::{User, UserId};
use im_core::settings::{self, Smtp};
use serde::Deserialize;
use topcoat::Result;
use topcoat::context::Cx;
use topcoat::cookie::Cookies;
use topcoat::router::content::Form;
use topcoat::router::response::{IntoResponse, Response};
use topcoat::router::{HeaderValue, StatusCode, header, route};
use topcoat::view::view;

use crate::i18n::{self, Key, lang_of, t};
use crate::layout::shell;
use crate::mailer;
use crate::pages::{error_text, query_value};
use crate::server::{self, App};

fn app(cx: &Cx) -> &App {
    server::app(cx)
}

/// The admin behind this request, or the redirect the request gets instead.
async fn require_admin(cx: &Cx) -> std::result::Result<User, Response> {
    match server::current_user(cx).await {
        Some(user) if user.admin => Ok(user),
        _ => Err((
            StatusCode::SEE_OTHER,
            [(header::LOCATION, HeaderValue::from_static("/"))],
        )
            .into_response(cx)
            .expect("a redirect can always be built")),
    }
}

/// Everything user-controlled crosses the panel escaped — a display name is
/// free text and the panel renders raw HTML.
fn escape(raw: &str) -> String {
    raw.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// One row action as a two-step disclosure — iz's `confirm-details` idiom:
/// the summary is the word ("Delete"), the opened panel says what it costs
/// and holds the button that actually does it. Works with no script at all;
/// the live script adds outside-click closing.
fn confirm_action(
    id: &str,
    action: &str,
    word: &str,
    extra_class: &str,
    title: &str,
    cost: &str,
    confirm: &str,
) -> String {
    format!(
        r#"<details class="admin-confirm"><summary class="admin-action{extra_class}">{word}</summary><div class="admin-confirm-pop"><div class="admin-confirm-title">{title}</div><div class="muted">{cost}</div><form method="post" action="{action}"><input type="hidden" name="user" value="{id}"><button class="admin-action{extra_class}" type="submit">{confirm}</button></form></div></details>"#
    )
}
/// The panel's live wiring moved into the shell: `layout::live_script` runs
/// on every signed-in page and morphs through `__imRefresh`. What stays here
/// is the one bit of behavior the no-script markup cannot do itself — an open
/// confirm disclosure closes on outside click and Escape.
const ADMIN_SCRIPT: &str = r#"<script>(function () {
  if (window.__imAdmin) { return; }
  window.__imAdmin = true;
  document.addEventListener('click', function (e) {
    document.querySelectorAll('.admin-confirm[open]').forEach(function (d) {
      if (!d.contains(e.target)) { d.removeAttribute('open'); }
    });
  }, true);
  document.addEventListener('keydown', function (e) {
    if (e.key !== 'Escape') { return; }
    document.querySelectorAll('.admin-confirm[open]').forEach(function (d) { d.removeAttribute('open'); });
  }, true);
})();</script>"#;

fn back(cx: &Cx, section: &str, extra: &str) -> Result<Response> {
    (
        StatusCode::SEE_OTHER,
        [(
            header::LOCATION,
            HeaderValue::from_str(&format!("/admin?section={section}{extra}"))
                .unwrap_or_else(|_| HeaderValue::from_static("/admin")),
        )],
    )
        .into_response(cx)
}

#[route(GET "/admin")]
async fn admin_page(cx: &Cx) -> Result<Response> {
    let me = match require_admin(cx).await {
        Ok(me) => me,
        Err(redirect) => return Ok(redirect),
    };
    let lang = lang_of(Some(&me));
    let query = topcoat::router::request::uri(cx)
        .query()
        .unwrap_or("")
        .to_string();
    let section = query_value(&query, "section").unwrap_or_else(|| "users".to_string());
    let error = query_value(&query, "error");
    let ok = query_value(&query, "ok");
    let why = query_value(&query, "why");
    let invited = query_value(&query, "invited");

    let nav = |current: &str| {
        [
            ("users", t(lang, Key::NavUsers)),
            ("mail", t(lang, Key::NavMail)),
            ("message", t(lang, Key::NavMessage)),
            ("settings", t(lang, Key::NavSettings)),
            ("logs", t(lang, Key::NavLogs)),
        ]
        .into_iter()
        .map(|(id, label)| {
            format!(
                r#"<a class="admin-nav{}" href="/admin?section={id}">{label}</a>"#,
                if id == current { " admin-nav-on" } else { "" }
            )
        })
        .collect::<String>()
    };

    let section_html = match section.as_str() {
        "mail" => mail_section(cx, lang).await?,
        "message" => message_section(cx, lang).await?,
        "settings" => settings_section(cx, lang).await?,
        "logs" => logs_section(cx, lang).await?,
        "users" => users_section(cx, &me, invited.as_deref(), lang).await?,
        _ => users_section(cx, &me, invited.as_deref(), lang).await?,
    };

    let banner = match (ok.as_deref(), error.as_deref()) {
        (Some(code), _) => Some(format!(
            r#"<div class="auth-ok">{}</div>"#,
            match code {
                "invited" => t(lang, Key::OkInvited),
                "revoked" => t(lang, Key::OkRevoked),
                "session_revoked" => t(lang, Key::OkSessionRevoked),
                "disabled" => t(lang, Key::OkDisabled),
                "enabled" => t(lang, Key::OkEnabled),
                "smtp" => t(lang, Key::OkSmtpSaved),
                "smtp_test" => t(lang, Key::OkSmtpTest),
                "message" => t(lang, Key::OkMessageSent),
                "uninvited" => t(lang, Key::OkUninvited),
                "deleted" => t(lang, Key::OkDeleted),
                "settings" => t(lang, Key::OkSettingsSaved),
                _ => t(lang, Key::OkDone),
            }
        )),
        (_, Some(code)) => Some(format!(
            r#"<div class="auth-problem">{}{}</div>"#,
            error_text(code, lang),
            why.as_deref()
                .map(|detail| format!("<div class=\"muted\">{}</div>", escape(detail)))
                .unwrap_or_default(),
        )),
        _ => None,
    };

    let stage = view! {
        cx =>
        <main class="admin-shell">
            <div class="admin-column">
                <div class="admin-bar">
                    // The brand is the way back to the landing, as in iz's
                    // topbar; the address stays a link too.
                    <a class="wordmark-text wordmark-home" href="/">"im"</a>
                    <nav class="admin-tabs">(topcoat::view::Unescaped::new_unchecked(nav(&section)))</nav>
                    <a class="auth-alt" href="/">(escape(&me.email))</a>
                </div>
                if let Some(banner) = banner {
                    (topcoat::view::Unescaped::new_unchecked(banner))
                }
                (topcoat::view::Unescaped::new_unchecked(section_html))
                (topcoat::view::Unescaped::new_unchecked(ADMIN_SCRIPT.to_string()))
            </div>
        </main>
    };
    shell(cx, t(lang, Key::TitleAdmin), Some(&me), stage)
        .await?
        .into_response(cx)
}

/// One person's live sessions as the disclosure under their row: a small
/// table with a per-session revoke, or the muted line when nothing is live.
/// The admin's own row gets one too — "you" still signs in from somewhere.
fn sessions_row(
    user: &User,
    sessions: &[im_core::sessions::SessionInfo],
    lang: i18n::Lang,
) -> String {
    let id = escape(&user.id.to_string());
    let body = if sessions.is_empty() {
        format!(
            r#"<div class="muted">{}</div>"#,
            t(lang, Key::AdminSessionsEmpty)
        )
    } else {
        let mut rows = String::new();
        for session in sessions {
            let seen_at = session.seen_at.unwrap_or(session.created_at);
            let seen = seen_at
                .format(&time::macros::format_description!(
                    "[year]-[month]-[day] [hour]:[minute]"
                ))
                .unwrap_or_else(|_| seen_at.date().to_string());
            rows.push_str(&format!(
                concat!(
                    r#"<tr><td title="{}">{}</td>"#,
                    r#"<td class="mono">{}</td>"#,
                    r#"<td class="muted">{}</td>"#,
                    r#"<td class="muted">{}</td>"#,
                    r#"<td class="actions">"#,
                    r#"<form method="post" action="/admin/session_revoke">"#,
                    r#"<input type="hidden" name="user" value="{id}">"#,
                    r#"<input type="hidden" name="session" value="{}">"#,
                    r#"<button class="admin-action" type="submit">{}</button>"#,
                    r#"</form></td></tr>"#
                ),
                // The cell reads as a device; the raw agent rides the title
                // for the admin who needs the whole string.
                session
                    .agent
                    .as_deref()
                    .filter(|agent| !agent.is_empty())
                    .map(escape)
                    .unwrap_or_default(),
                escape(&crate::pages::device_label(session.agent.as_deref(), lang)),
                session
                    .ip
                    .as_deref()
                    .map(escape)
                    .unwrap_or_else(|| "—".to_string()),
                session.created_at.date(),
                seen,
                escape(&session.token_hash),
                t(lang, Key::RevokeButton),
                id = id,
            ));
        }
        format!(
            concat!(
                r#"<table class="admin-table"><thead><tr>"#,
                r#"<th>{device}</th><th>{address}</th><th>{signed_in}</th><th>{last_seen}</th><th></th>"#,
                r#"</tr></thead><tbody>{rows}</tbody></table>"#
            ),
            device = t(lang, Key::DeviceLabel),
            address = t(lang, Key::AddressLabel),
            signed_in = t(lang, Key::SignedInLabel),
            last_seen = t(lang, Key::LastSeenLabel),
            rows = rows,
        )
    };
    format!(
        r#"<tr><td colspan="4"><details class="admin-sessions"><summary class="muted">{}</summary>{body}</details></td></tr>"#,
        i18n::sessions_summary(lang, sessions.len())
    )
}

async fn users_section(
    cx: &Cx,
    me: &User,
    invited: Option<&str>,
    lang: i18n::Lang,
) -> Result<String, topcoat::Error> {
    let users = accounts::list_users(&app(cx).store).await?;
    let pending = accounts::list_pending_invites(&app(cx).store).await?;
    let mut rows = String::new();
    for user in &users {
        let flags = [
            user.admin.then_some(t(lang, Key::FlagAdmin)),
            user.disabled.then_some(t(lang, Key::FlagDisabled)),
            (!user.totp_confirmed).then_some(t(lang, Key::FlagNo2fa)),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join(" · ");
        let actions = if user.id == me.id {
            // Never let the only admin lock themselves out by reflex.
            format!(r#"<span class="muted">{}</span>"#, t(lang, Key::YouWord))
        } else {
            let id = escape(&user.id.to_string());
            let email = escape(&user.email);
            // Every row action is a two-step disclosure — iz's
            // confirm-details idiom: the summary is the word, the panel holds
            // the button that actually does it. No script required; the live
            // script adds outside-click closing on top.
            let toggle = if user.disabled {
                confirm_action(
                    &id,
                    "/admin/enable",
                    t(lang, Key::EnableWord),
                    "",
                    &i18n::enable_title(lang, &email),
                    t(lang, Key::EnableCost),
                    t(lang, Key::ConfirmEnable),
                )
            } else {
                confirm_action(
                    &id,
                    "/admin/disable",
                    t(lang, Key::DisableWord),
                    "",
                    &i18n::disable_title(lang, &email),
                    t(lang, Key::DisableCost),
                    t(lang, Key::ConfirmDisable),
                )
            };
            let remove = confirm_action(
                &id,
                "/admin/delete",
                t(lang, Key::DeleteWord),
                " admin-danger",
                &i18n::delete_title(lang, &email),
                t(lang, Key::DeleteCost),
                t(lang, Key::ConfirmDelete),
            );
            format!(
                r#"{toggle}<form method="post" action="/admin/revoke"><input type="hidden" name="user" value="{id}"><button class="admin-action" type="submit">{sign_out}</button></form>{remove}"#,
                sign_out = t(lang, Key::SignOutEverywhere),
            )
        };
        rows.push_str(&format!(
            "<tr><td class=\"mono\">{}</td><td>{}</td><td class=\"muted\">{}</td><td class=\"actions\">{}</td></tr>",
            escape(&user.email),
            escape(&user.name),
            flags,
            actions
        ));
        let sessions = im_core::sessions::list_sessions(&app(cx).store, &user.id).await?;
        rows.push_str(&sessions_row(user, &sessions, lang));
    }
    // Invites still waiting on their person sit in the same table — "waiting"
    // instead of a name, and the one action an outstanding link understands:
    for row in &pending {
        let flags = [
            Some(t(lang, Key::FlagInvited)),
            row.admin.then_some(t(lang, Key::FlagAdmin)),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join(" · ");
        let expires = row
            .expires_at
            .format(&time::macros::format_description!("[year]-[month]-[day]"))
            .unwrap_or_default();
        rows.push_str(&format!(
            r#"<tr><td class="mono">{}</td><td class="muted">{}</td><td class="muted">{}</td><td class="actions"><form method="post" action="/admin/uninvite"><input type="hidden" name="invite" value="{}"><button class="admin-action" type="submit">{}</button></form></td></tr>"#,
            escape(&row.email),
            i18n::waiting_label(lang, &expires),
            flags,
            escape(&row.token_hash),
            t(lang, Key::InvalidateButton),
        ));
    }
    let invited_html = invited
        .map(|link| {
            format!(
                r#"<div class="auth-note">{}<br><span class="mono">{}</span></div>"#,
                t(lang, Key::InviteLinkNote),
                escape(link)
            )
        })
        .unwrap_or_default();
    Ok(format!(
        r#"<div class="admin-card">
  <div class="auth-title">{title}</div>
  {invited_html}
  <table class="admin-table">
    <thead><tr><th>{email}</th><th>{name}</th><th></th><th></th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
  <form method="post" action="/admin/invite" class="admin-invite">
    <input class="auth-input auth-input-mono" type="email" name="email" placeholder="person@example.com" required>
    <select class="auth-input admin-role" name="role">
      <option value="member">{member}</option>
      <option value="admin">{admin}</option>
    </select>
    <button class="auth-submit admin-invite-go" type="submit"><span class="auth-submit-text">{invite}</span></button>
  </form>
</div>"#,
        title = t(lang, Key::PeopleTitle),
        email = t(lang, Key::EmailCol),
        name = t(lang, Key::NameCol),
        member = t(lang, Key::RoleMember),
        admin = t(lang, Key::RoleAdmin),
        invite = t(lang, Key::InviteButton),
    ))
}

/// The knobs the code shipped with, now the panel's: invite and reset link
/// lifetimes, the sign-in session's days, the pending marker's minutes, and
/// the sign-in failure ceiling. Same form skin as Mail.
async fn settings_section(cx: &Cx, lang: i18n::Lang) -> Result<String, topcoat::Error> {
    let policy = settings::policy(&app(cx).store).await?;
    Ok(format!(
        r#"<div class="admin-card">
  <div class="auth-title">{title}</div>
  <div class="auth-sub">{sub}</div>
  <form method="post" action="/admin/settings" class="admin-form">
    <label class="auth-field"><span class="auth-label">{invite_days}</span>
      <input class="auth-input auth-input-mono" type="number" name="invite_days" min="1" value="{}"></label>
    <label class="auth-field"><span class="auth-label">{session_days}</span>
      <input class="auth-input auth-input-mono" type="number" name="session_days" min="1" value="{}"></label>
    <label class="auth-field"><span class="auth-label">{pending_minutes}</span>
      <input class="auth-input auth-input-mono" type="number" name="pending_minutes" min="1" value="{}"></label>
    <label class="auth-field"><span class="auth-label">{reset_minutes}</span>
      <input class="auth-input auth-input-mono" type="number" name="reset_minutes" min="1" value="{}"></label>
    <label class="auth-field"><span class="auth-label">{attempts}</span>
      <input class="auth-input auth-input-mono" type="number" name="login_attempts_per_hour" min="1" value="{}"></label>
    <button class="auth-submit admin-action-wide" type="submit"><span class="auth-submit-text">{save}</span></button>
  </form>
</div>"#,
        policy.invite_days,
        policy.session_days,
        policy.pending_minutes,
        policy.reset_minutes,
        policy.login_attempts_per_hour,
        title = t(lang, Key::SettingsTitle),
        sub = t(lang, Key::SettingsSub),
        invite_days = t(lang, Key::InviteDaysLabel),
        session_days = t(lang, Key::SessionDaysLabel),
        pending_minutes = t(lang, Key::PendingMinutesLabel),
        reset_minutes = t(lang, Key::ResetMinutesLabel),
        attempts = t(lang, Key::LoginAttemptsLabel),
        save = t(lang, Key::SaveButton),
    ))
}

#[derive(Deserialize)]
struct PolicyForm {
    invite_days: i64,
    session_days: i64,
    pending_minutes: i64,
    reset_minutes: i64,
    login_attempts_per_hour: i64,
}

#[route(POST "/admin/settings")]
async fn settings_save(cx: &Cx, Form(input): Form<PolicyForm>) -> Result<Response> {
    let me = match require_admin(cx).await {
        Ok(me) => me,
        Err(redirect) => return Ok(redirect),
    };
    let store = &app(cx).store;
    settings::set_policy(
        store,
        &settings::Policy {
            invite_days: input.invite_days,
            session_days: input.session_days,
            pending_minutes: input.pending_minutes,
            reset_minutes: input.reset_minutes,
            login_attempts_per_hour: input.login_attempts_per_hour,
        },
    )
    .await?;
    server::log_event(cx, "settings_updated", Some(&me.email), None).await;
    back(cx, "settings", "&ok=settings")
}

async fn mail_section(cx: &Cx, lang: i18n::Lang) -> Result<String, topcoat::Error> {
    let store = &app(cx).store;
    let smtp = settings::smtp(store).await?;
    let password_note = if smtp.password.is_some() {
        t(lang, Key::PasswordSetNote)
    } else {
        t(lang, Key::NoPasswordNote)
    };
    // The standing chip, izlek's idiom: one colored chip that says what the
    // last probe proved, with the server's own words under it on a refusal.
    // Saving settings wipes the record, so the chip can never claim
    // "connected" for settings that changed since.
    let stamp = |at: time::OffsetDateTime| {
        at.format(&time::macros::format_description!(
            "[year]-[month]-[day] [hour]:[minute] UTC"
        ))
        .unwrap_or_default()
    };
    let (chip_class, chip_text, lede) = match settings::standing(store).await? {
        settings::Standing::NotConfigured => (
            "chip chip-muted",
            t(lang, Key::ChipNotConfigured).to_string(),
            String::new(),
        ),
        settings::Standing::Unchecked => (
            "chip chip-muted",
            t(lang, Key::ChipUnchecked).to_string(),
            t(lang, Key::UncheckedNote).to_string(),
        ),
        settings::Standing::Connected { at, took_ms } => (
            "chip chip-connected",
            i18n::connected_chip(lang, took_ms),
            i18n::checked_note(lang, &stamp(at)),
        ),
        settings::Standing::Refused { at, said } => (
            "chip chip-refused",
            t(lang, Key::ChipRefused).to_string(),
            format!("{} — {}", stamp(at), escape(&said)),
        ),
    };
    let lede_html = if lede.is_empty() {
        String::new()
    } else {
        format!(r#"<div class="admin-standing">{lede}</div>"#)
    };
    Ok(format!(
        r#"<div class="admin-card">
  <div class="admin-card-head"><div class="auth-title">{title}</div><span class="{chip_class}">{chip_text}</span></div>
  <div class="auth-sub">{sub}</div>
  <form method="post" action="/admin/smtp" class="admin-form">
    <label class="auth-field"><span class="auth-label">{host}</span>
      <input class="auth-input auth-input-mono" type="text" name="host" value="{}" placeholder="smtp.example.com"></label>
    <label class="auth-field"><span class="auth-label">{port}</span>
      <input class="auth-input auth-input-mono" type="number" name="port" value="{}"></label>
    <label class="auth-field"><span class="auth-label">{username}</span>
      <input class="auth-input auth-input-mono" type="text" name="username" value="{}"></label>
    <label class="auth-field"><span class="auth-label">{password}</span>
      <input class="auth-input auth-input-mono" type="password" name="password" placeholder="{password_note}" autocomplete="off"></label>
    <label class="auth-field"><span class="auth-label">{from_name}</span>
      <input class="auth-input auth-input-mono" type="text" name="from_name" value="{}" placeholder="im"></label>
    <label class="auth-field"><span class="auth-label">{from_address}</span>
      <input class="auth-input auth-input-mono" type="text" name="from" value="{}" placeholder="auth@example.com"></label>
    <button class="auth-submit admin-action-wide" type="submit"><span class="auth-submit-text">{save}</span></button>
  </form>
  {lede_html}
  <div class="admin-pair">
    <form method="post" action="/admin/smtp_check"><button class="admin-action" type="submit">{check}</button></form>
    <form method="post" action="/admin/smtp_test"><button class="admin-action" type="submit">{test}</button></form>
  </div>
</div>"#,
        escape(&smtp.host),
        smtp.port,
        escape(&smtp.username),
        escape(&smtp.from_name),
        escape(&smtp.from),
        title = t(lang, Key::MailTitle),
        sub = i18n::mail_sub(lang),
        host = t(lang, Key::HostLabel),
        port = t(lang, Key::PortLabel),
        username = t(lang, Key::UsernameLabel),
        password = t(lang, Key::MailPasswordLabel),
        from_name = t(lang, Key::FromNameLabel),
        from_address = t(lang, Key::FromAddressLabel),
        save = t(lang, Key::SaveButton),
        check = t(lang, Key::CheckConnectionButton),
        test = t(lang, Key::SendTestMailButton),
    ))
}

/// The compose half of mail, its own tab like izlek's settings rail keeps
/// Message beside Outgoing: the sender's settings live one tab over, this
/// page is only "to whom, what, send".
async fn message_section(cx: &Cx, lang: i18n::Lang) -> Result<String, topcoat::Error> {
    let store = &app(cx).store;
    let users = accounts::list_users(store).await?;
    let mut options = format!(
        r#"<option value="everyone">{}</option>"#,
        t(lang, Key::EveryoneOption)
    );
    for person in &users {
        options.push_str(&format!(
            r#"<option value="{}">{} · {}</option>"#,
            escape(person.id.as_str()),
            escape(&person.name),
            escape(&person.email),
        ));
    }
    Ok(format!(
        r#"<div class="admin-card">
  <div class="admin-card-head"><div class="auth-title">{msg_title}</div></div>
  <form method="post" action="/admin/message" class="admin-form">
    <label class="auth-field"><span class="auth-label">{to_label}</span>
      <select class="auth-input" name="to">{options}</select></label>
    <label class="auth-field"><span class="auth-label">{subject_label}</span>
      <input class="auth-input" type="text" name="subject" required></label>
    <label class="auth-field"><span class="auth-label">{body_label}</span>
      <textarea class="auth-input" name="body" rows="5" required></textarea></label>
    <button class="auth-submit admin-action-wide" type="submit"><span class="auth-submit-text">{send}</span></button>
  </form>
</div>"#,
        msg_title = t(lang, Key::MessageTitle),
        to_label = t(lang, Key::MessageToLabel),
        subject_label = t(lang, Key::MessageSubjectLabel),
        body_label = t(lang, Key::MessageBodyLabel),
        send = t(lang, Key::SendMessageButton),
    ))
}

/// One page of the log: fifty rows, izlek's default. The log grows without
/// bound; the page does not.
const LOGS_LIMIT: i64 = 50;

/// The page size fitted to the browser's own viewport: the log-fit script
/// measures a real rendered row against the window and says how many rows
/// fit, through the `im_rows_logs` cookie — read clamped, so a stale or
/// tampered value cannot ask for an absurd window. `LOGS_LIMIT` when the
/// cookie is absent or unparsable. Ported from izlek's `resolve_limit`.
fn resolve_log_limit(cx: &Cx) -> i64 {
    topcoat::cookie::cookies(cx)
        .get("im_rows_logs")
        .and_then(|c| c.value().parse::<i64>().ok())
        .map(|rows| rows.clamp(5, 200))
        .unwrap_or(LOGS_LIMIT)
}

/// The cursor on the wire: `rfc3339~id`, percent-encoded into `before`/`after`.
fn cursor_q(cursor: &events::EventCursor) -> String {
    crate::oidc::urlencode(&format!("{}~{}", events_cursor_stamp(cursor), cursor.id))
}

fn events_cursor_stamp(cursor: &events::EventCursor) -> String {
    cursor
        .at
        .format(&time::macros::format_description!(
            "[year]-[month]-[day]T[hour]:[minute]:[second]Z"
        ))
        .unwrap_or_default()
}

fn parse_cursor(raw: Option<String>) -> Option<events::EventCursor> {
    let raw = raw?;
    let (at, id) = raw.split_once('~')?;
    let at =
        time::OffsetDateTime::parse(at, &time::format_description::well_known::Rfc3339).ok()?;
    if id.is_empty() {
        return None;
    }
    Some(events::EventCursor {
        at,
        id: id.to_string(),
    })
}

/// YYYY-MM-DD at the UTC midnight that opens the day; `to` is handed the
/// midnight that closes it. Backwards ranges swap, garbage opens the end.
fn parse_day(raw: Option<String>) -> Option<time::OffsetDateTime> {
    let raw = raw?;
    let date = time::Date::parse(
        &raw,
        &time::macros::format_description!("[year]-[month]-[day]"),
    )
    .ok()?;
    date.with_hms(0, 0, 0).ok().map(|dt| dt.assume_utc())
}

async fn logs_section(cx: &Cx, lang: i18n::Lang) -> Result<String, topcoat::Error> {
    let store = &app(cx).store;
    let query = topcoat::router::request::uri(cx)
        .query()
        .unwrap_or("")
        .to_string();
    let pick = |name: &str| query_value(&query, name).filter(|v| !v.is_empty());

    let from = parse_day(pick("from"));
    let to = parse_day(pick("to")).and_then(|d| d.checked_add(time::Duration::days(1)));
    let day = match (from, to) {
        (Some(a), Some(b)) if a > b => Some((b, a)),
        (Some(a), Some(b)) => Some((a, b)),
        (Some(a), None) => Some((a, time::Date::MAX.with_hms(0, 0, 0).unwrap().assume_utc())),
        (None, Some(b)) => Some((time::OffsetDateTime::UNIX_EPOCH, b)),
        (None, None) => None,
    };
    let filter = events::EventFilter {
        kind: pick("kind"),
        actor: pick("actor"),
        day,
        q: pick("q")
            .map(|raw| raw.trim().to_string())
            .filter(|s| !s.is_empty()),
    };
    let dir = if pick("dir").as_deref() == Some("oldest") {
        events::Dir::Oldest
    } else {
        events::Dir::Newest
    };
    let mut page = match (parse_cursor(pick("before")), parse_cursor(pick("after"))) {
        (Some(cursor), _) => events::EventPage::Before(cursor),
        (None, Some(cursor)) => events::EventPage::After(cursor),
        _ => events::EventPage::Newest,
    };
    let limit = resolve_log_limit(cx);
    let mut window = events::list_filtered(store, limit + 1, &page, dir, &filter).await?;
    // Ran off the top walking back: answer with the freshest page instead.
    if matches!(page, events::EventPage::After(_)) && window.is_empty() {
        page = events::EventPage::Newest;
        window = events::list_filtered(store, limit + 1, &page, dir, &filter).await?;
    }
    let has_more = window.len() as i64 > limit;
    window.truncate(limit as usize);

    let total = events::count_filtered(store, &filter).await?;
    let preceding = events::count_preceding(
        store,
        &filter,
        dir,
        window
            .first()
            .map(|e| events::EventCursor {
                at: e.at,
                id: e.id.clone(),
            })
            .as_ref(),
    )
    .await?;

    // A page turn re-appends every filter: turning never drops the narrowing.
    let mut suffix = String::new();
    if let Some(kind) = &filter.kind {
        suffix += &format!("&kind={}", crate::oidc::urlencode(kind));
    }
    if let Some(actor) = &filter.actor {
        suffix += &format!("&actor={}", crate::oidc::urlencode(actor));
    }
    if let Some(raw) = pick("from") {
        suffix += &format!("&from={}", crate::oidc::urlencode(&raw));
    }
    if let Some(raw) = pick("to") {
        suffix += &format!("&to={}", crate::oidc::urlencode(&raw));
    }
    if dir == events::Dir::Oldest {
        suffix += "&dir=oldest";
    }
    if let Some(q) = &filter.q {
        suffix += &format!("&q={}", crate::oidc::urlencode(q));
    }

    let kinds = events::distinct_kinds(store).await?;
    let actors = events::distinct_actors(store).await?;
    let mut kind_options = format!(r#"<option value="">{}</option>"#, t(lang, Key::AllOption));
    for kind in &kinds {
        kind_options.push_str(&format!(
            r#"<option value="{}"{}>{}</option>"#,
            escape(kind),
            if filter.kind.as_deref() == Some(kind) {
                " selected"
            } else {
                ""
            },
            escape(&i18n::kind_word(lang, kind)),
        ));
    }
    let mut actor_options = format!(r#"<option value="">{}</option>"#, t(lang, Key::AllOption));
    for actor in &actors {
        actor_options.push_str(&format!(
            r#"<option value="{}"{}>{}</option>"#,
            escape(actor),
            if filter.actor.as_deref() == Some(actor) {
                " selected"
            } else {
                ""
            },
            escape(actor),
        ));
    }

    let mut rows = String::new();
    for event in &window {
        rows.push_str(&format!(
            "<tr><td class=\"mono muted\">{}</td><td class=\"mono\">{}</td><td>{}</td><td class=\"muted\">{}</td></tr>",
            escape(&event.at.format(&time::macros::format_description!("[year]-[month]-[day] [hour]:[minute]:[second]")).unwrap_or_default()),
            escape(&i18n::kind_word(lang, &event.kind)),
            escape(event.actor.as_deref().unwrap_or("")),
            escape(event.detail.as_deref().unwrap_or("")),
        ));
    }

    let body = if window.is_empty() {
        format!(r#"<div class="muted">{}</div>"#, t(lang, Key::LogsEmpty))
    } else {
        format!(
            r#"<table class="admin-table log-list" data-rows="{limit}" data-section="logs">
    <thead><tr><th>{when}</th><th>{what}</th><th>{who}</th><th>{detail}</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>"#,
            when = t(lang, Key::WhenCol),
            what = t(lang, Key::WhatCol),
            who = t(lang, Key::WhoCol),
            detail = t(lang, Key::DetailCol),
        )
    };

    // izlek's link visibility: the freshest page shows only Older, a middle
    // page shows both, the last page hides Older.
    let mut foot = String::new();
    if !window.is_empty() {
        let newest = events::EventCursor {
            at: window.first().unwrap().at,
            id: window.first().unwrap().id.clone(),
        };
        let oldest = events::EventCursor {
            at: window.last().unwrap().at,
            id: window.last().unwrap().id.clone(),
        };
        let show_older = matches!(page, events::EventPage::After(_)) || has_more;
        let show_newer = matches!(page, events::EventPage::Before(_))
            || (matches!(page, events::EventPage::After(_)) && has_more);
        let mut links = String::new();
        if show_newer {
            links += &format!(
                r#"<a class="auth-alt" href="/admin?section=logs{suffix}&after={}">{}</a>"#,
                cursor_q(&newest),
                t(lang, Key::NewerLink),
            );
        }
        if show_older {
            links += &format!(
                r#"<a class="auth-alt" href="/admin?section=logs{suffix}&before={}">{}</a>"#,
                cursor_q(&oldest),
                t(lang, Key::OlderLink),
            );
        }
        foot = format!(
            r#"<div class="logs-foot"><span class="log-count">{}–{} / {}</span><div class="logs-links">{links}</div></div>"#,
            preceding + 1,
            preceding + window.len() as u64,
            total,
        );
    }

    Ok(format!(
        r#"<div class="admin-card">
  <div class="auth-title">{title}</div>
  <div class="auth-sub">{sub}</div>
  <form method="get" action="/admin" class="logs-filters">
    <input type="hidden" name="section" value="logs">
    <label class="auth-field"><span class="auth-label">{kind_label}</span>
      <select class="auth-input" name="kind" data-autosubmit>{kind_options}</select></label>
    <label class="auth-field"><span class="auth-label">{actor_label}</span>
      <select class="auth-input" name="actor" data-autosubmit>{actor_options}</select></label>
    <label class="auth-field"><span class="auth-label">{from_label}</span>
      <input class="auth-input" type="date" name="from" value="{from_value}" data-autosubmit></label>
    <label class="auth-field"><span class="auth-label">{to_label}</span>
      <input class="auth-input" type="date" name="to" value="{to_value}" data-autosubmit></label>
    <label class="auth-field"><span class="auth-label">{dir_label}</span>
      <select class="auth-input" name="dir" data-autosubmit>{dir_options}</select></label>
    <label class="auth-field logs-q"><span class="auth-label">{search_label}</span>
      <input class="auth-input" type="text" name="q" value="{q_value}"></label>
  </form>
  {body}
  {foot}
</div>"#,
        title = t(lang, Key::LogsTitle),
        sub = t(lang, Key::LogsSub),
        kind_label = t(lang, Key::KindLabel),
        actor_label = t(lang, Key::ActorLabel),
        from_label = t(lang, Key::FromLabel),
        to_label = t(lang, Key::ToLabel),
        dir_label = t(lang, Key::OrderLabel),
        search_label = t(lang, Key::SearchLabel),
        q_value = escape(filter.q.as_deref().unwrap_or("")),
        from_value = escape(&pick("from").unwrap_or_default()),
        to_value = escape(&pick("to").unwrap_or_default()),
        dir_options = format!(
            r#"<option value=""{}>{}</option><option value="oldest"{}>{}</option>"#,
            if dir == events::Dir::Newest {
                " selected"
            } else {
                ""
            },
            t(lang, Key::NewestFirst),
            if dir == events::Dir::Oldest {
                " selected"
            } else {
                ""
            },
            t(lang, Key::OldestFirst),
        ),
    ))
    .map(|card| card + LOG_FIT_SCRIPT)
}
/// Fits the log's page size to the browser's own viewport: measured against
/// the first rendered row, never against a guess at the row height. A fit
/// that would change the page size reloads once through a fresh
/// `im_rows_logs` cookie; the `sessionStorage` guard, keyed to the exact fit
/// computed, stops a borderline measurement from reloading forever. The
/// measure runs again once fonts settle — a row measured under the fallback
/// face is shorter than the row the webfont draws, and the first fit would
/// otherwise overflow by exactly that difference. A container too short to
/// measure (no rows yet) is left alone rather than guessed at. Ported from
/// izlek's `log_fit_script`.
const LOG_FIT_SCRIPT: &str = r#"<script>(function () {
  var waits = 0;
  function measure() {
    // Never measure while the document's fonts are still arriving — every
    // fresh document repaints the rows in the fallback face first, and a
    // fit confirmed under it is wrong by half. Defer until the set is done;
    // after forty waits the CDN is presumed dead and the fallback face is
    // the truth the page will keep.
    if (document.fonts && document.fonts.status === 'loading' && waits < 40) {
      waits++;
      setTimeout(measure, 300);
      return;
    }
    var list = document.querySelector('.log-list[data-rows]');
    if (!list) { return; }
    var current = parseInt(list.dataset.rows, 10);

    var row = list.querySelector('tbody tr');
    if (!row || !row.offsetHeight) { return; }
    var avail = window.innerHeight - list.getBoundingClientRect().top - 100;
    var fit = Math.min(200, Math.max(5, Math.floor(avail / row.offsetHeight)));
    if (fit === current) { lastFit = -1; window.sessionStorage.removeItem('imLogFitHops'); return; }
    // A fit is committed only when two measures in a row — geometry events
    // are at least the debounce apart — agree on it. The font swap flips
    // row heights once, so the transient value never confirms; the settled
    // one always does. The hop budget — not a per-value veto — stops the
    // loop if the geometry never settles: a vetoed value would otherwise
    // stay wrong for the whole session.
    if (fit !== lastFit) { lastFit = fit; setTimeout(measure, 350); return; }
    var hops = parseInt(window.sessionStorage.getItem('imLogFitHops') || '0', 10);
    if (hops >= 5) { return; }
    window.sessionStorage.setItem('imLogFitHops', String(hops + 1));
    document.cookie = 'im_rows_logs=' + fit + ';path=/';
    location.replace(location.href);
  }
  var lastFit = -1;
  // No event is the right moment to measure: `load` can precede the
  // webfont, and a face that arrives late redraws every row taller. So the
  // measurement is driven by the geometry itself — a ResizeObserver on the
  // first row re-measures whenever its height changes (font swap, layout
  // settle), a window resize re-measures for the new viewport, and the
  // debounce folds the burst into one. A wrong early value is corrected by
  // the next firing; the reload guard caps the round trips.
  var timer = null;
  function schedule() {
    if (timer) { clearTimeout(timer); }
    timer = setTimeout(function () { timer = null; measure(); }, 200);
  }
  var row = document.querySelector('.log-list[data-rows] tbody tr');
  if (row && window.ResizeObserver) { new ResizeObserver(schedule).observe(row); }
  window.addEventListener('resize', schedule);
  schedule();
})();</script>"#;

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct InviteForm {
    email: String,
    role: Option<String>,
}

#[route(POST "/admin/invite")]
async fn invite(cx: &Cx, Form(input): Form<InviteForm>) -> Result<Response> {
    let me = match require_admin(cx).await {
        Ok(me) => me,
        Err(redirect) => return Ok(redirect),
    };
    let store = &app(cx).store;
    let email = input.email.trim().to_string();
    let admin = input.role.as_deref() == Some("admin");
    let token = match accounts::create_invite(store, &email, Some(me.id.clone()), admin).await {
        Ok(token) => token,
        Err(accounts::AccountError::EmailTaken) => {
            return back(cx, "users", "&error=email_taken");
        }
        Err(e) => return Err(topcoat::Error::from(std::io::Error::other(e.to_string()))),
    };
    // Mailed when a sender is configured; shown once on the page otherwise.
    let mailed = mailer::send_invite(store, &app(cx).config.issuer, &email, token.expose())
        .await
        .is_ok();
    server::log_event(
        cx,
        "invite_created",
        Some(&me.email),
        Some(&format!(
            "for {email}{}",
            if admin { " (admin)" } else { "" }
        )),
    )
    .await;
    if mailed {
        back(cx, "users", "&ok=invited")
    } else {
        let link = format!("{}/invite/{}", app(cx).config.issuer, token.expose());
        back(
            cx,
            "users",
            &format!("&ok=invited&invited={}", crate::oidc::urlencode(&link)),
        )
    }
}

#[derive(Deserialize)]
struct InviteAction {
    invite: String,
}

/// Invalidates an outstanding invite: the link dies now, not at expiry.
#[route(POST "/admin/uninvite")]
async fn uninvite(cx: &Cx, Form(input): Form<InviteAction>) -> Result<Response> {
    let me = match require_admin(cx).await {
        Ok(me) => me,
        Err(redirect) => return Ok(redirect),
    };
    let store = &app(cx).store;
    let email = accounts::revoke_invite(store, &input.invite).await?;
    server::log_event(cx, "invite_revoked", Some(&me.email), email.as_deref()).await;
    back(cx, "users", "&ok=uninvited")
}

/// Deletes the account outright — user, sessions, app tokens. Disable is
/// the reversible door; this one is for "should not exist". The admin's own
/// row never carries the button, so there is no self-delete to guard here.
#[route(POST "/admin/delete")]
async fn delete(cx: &Cx, Form(input): Form<UserAction>) -> Result<Response> {
    let me = match require_admin(cx).await {
        Ok(me) => me,
        Err(redirect) => return Ok(redirect),
    };
    let store = &app(cx).store;
    let user_id = UserId::from(input.user);
    let email = accounts::user_by_id(store, &user_id)
        .await?
        .map(|u| u.email);
    accounts::delete_user(store, &user_id).await?;
    server::log_event(cx, "user_deleted", Some(&me.email), email.as_deref()).await;
    back(cx, "users", "&ok=deleted")
}

#[derive(Deserialize)]
struct UserAction {
    user: String,
}
#[route(POST "/admin/revoke")]
async fn revoke(cx: &Cx, Form(input): Form<UserAction>) -> Result<Response> {
    let me = match require_admin(cx).await {
        Ok(me) => me,
        Err(redirect) => return Ok(redirect),
    };
    let store = &app(cx).store;
    let user_id = UserId::from(input.user);
    let sessions = im_core::sessions::revoke_user_sessions(store, &user_id).await?;
    let email = accounts::user_by_id(store, &user_id)
        .await?
        .map(|u| u.email);
    server::log_event(
        cx,
        "sessions_revoked",
        Some(&me.email),
        Some(&format!(
            "{}: {sessions} session(s)",
            email.as_deref().unwrap_or("unknown")
        )),
    )
    .await;
    back(cx, "users", "&ok=revoked")
}

#[derive(Deserialize)]
struct SessionRevokeForm {
    user: String,
    session: String,
}

/// Revokes one session of one person — the per-row door beside the
/// sign-them-out-everywhere one above.
#[route(POST "/admin/session_revoke")]
async fn session_revoke(cx: &Cx, Form(input): Form<SessionRevokeForm>) -> Result<Response> {
    let me = match require_admin(cx).await {
        Ok(me) => me,
        Err(redirect) => return Ok(redirect),
    };
    let user_id = UserId::from(input.user.clone());
    if !im_core::sessions::revoke_owned_session(&app(cx).store, &user_id, &input.session).await? {
        return back(cx, "users", "&error=session_unknown");
    }
    server::log_event(cx, "session_revoked", Some(&me.email), Some(&input.user)).await;
    back(cx, "users", "&ok=session_revoked")
}

#[route(POST "/admin/disable")]
async fn disable(cx: &Cx, Form(input): Form<UserAction>) -> Result<Response> {
    set_disabled(cx, input, true).await
}

#[route(POST "/admin/enable")]
async fn enable(cx: &Cx, Form(input): Form<UserAction>) -> Result<Response> {
    set_disabled(cx, input, false).await
}

async fn set_disabled(cx: &Cx, input: UserAction, disabled: bool) -> Result<Response> {
    let me = match require_admin(cx).await {
        Ok(me) => me,
        Err(redirect) => return Ok(redirect),
    };
    let store = &app(cx).store;
    let user_id = UserId::from(input.user);
    accounts::set_disabled(store, &user_id, disabled).await?;
    if disabled {
        // A disabled account keeps no sessions either.
        im_core::sessions::revoke_user_sessions(store, &user_id).await?;
    }
    let email = accounts::user_by_id(store, &user_id)
        .await?
        .map(|u| u.email);
    server::log_event(
        cx,
        if disabled {
            "user_disabled"
        } else {
            "user_enabled"
        },
        Some(&me.email),
        email.as_deref(),
    )
    .await;
    back(
        cx,
        "users",
        if disabled {
            "&ok=disabled"
        } else {
            "&ok=enabled"
        },
    )
}

#[derive(Deserialize)]
struct SmtpForm {
    host: String,
    port: u16,
    username: String,
    password: Option<String>,
    #[serde(default)]
    from_name: String,
    from: String,
}

#[route(POST "/admin/smtp")]
async fn smtp_save(cx: &Cx, Form(input): Form<SmtpForm>) -> Result<Response> {
    let me = match require_admin(cx).await {
        Ok(me) => me,
        Err(redirect) => return Ok(redirect),
    };
    let store = &app(cx).store;
    let value = Smtp {
        host: input.host.trim().to_string(),
        port: input.port,
        username: input.username.trim().to_string(),
        from: input.from.trim().to_string(),
        from_name: input.from_name.trim().to_string(),
        password: None,
    };
    settings::set_smtp(store, &value, input.password.as_deref()).await?;
    server::log_event(cx, "smtp_updated", Some(&me.email), None).await;
    // The saved sender gets re-probed in the background — the standing line
    // on the Mail section catches up on the next view, like izlek's panel.
    tokio::spawn(probe(store_of(cx), app(cx).live.clone()));
    back(cx, "mail", "&ok=smtp")
}

#[route(POST "/admin/smtp_test")]
async fn smtp_test(cx: &Cx) -> Result<Response> {
    let me = match require_admin(cx).await {
        Ok(me) => me,
        Err(redirect) => return Ok(redirect),
    };
    if !settings::smtp(&app(cx).store).await?.configured() {
        return back(cx, "mail", "&error=sender_unset");
    }
    match mailer::send_test(&app(cx).store, &me.email, lang_of(Some(&me))).await {
        Ok(()) => {
            server::log_event(cx, "smtp_test_sent", Some(&me.email), None).await;
            back(cx, "mail", "&ok=smtp_test")
        }
        Err(e) => {
            server::log_event(
                cx,
                "smtp_test_failed",
                Some(&me.email),
                Some(&e.to_string()),
            )
            .await;
            back(
                cx,
                "mail",
                &format!(
                    "&error=smtp_test&why={}",
                    crate::oidc::urlencode(&e.to_string())
                ),
            )
        }
    }
}

#[derive(Deserialize)]
struct MessageForm {
    to: String,
    subject: String,
    body: String,
}

/// The composed notice, izlek's `send_message`: one person or everyone (the
/// admin excluded — they wrote it), the words verbatim through the
/// configured sender. A failure answers with the server's own words, like
/// the test mail does.
#[route(POST "/admin/message")]
async fn message(cx: &Cx, Form(input): Form<MessageForm>) -> Result<Response> {
    let me = match require_admin(cx).await {
        Ok(me) => me,
        Err(redirect) => return Ok(redirect),
    };
    let store = &app(cx).store;
    if !settings::smtp(store).await?.configured() {
        return back(cx, "message", "&error=sender_unset");
    }
    let subject = input.subject.trim();
    if subject.is_empty() {
        return back(cx, "message", "&error=empty_subject");
    }
    let body = input.body.trim();
    if body.is_empty() {
        return back(cx, "message", "&error=empty_body");
    }
    let users = accounts::list_users(store).await?;
    let recipients: Vec<String> = if input.to == "everyone" {
        users
            .into_iter()
            .filter(|person| person.id != me.id)
            .map(|person| person.email)
            .collect()
    } else {
        match users
            .into_iter()
            .find(|person| person.id.as_str() == input.to)
        {
            Some(person) => vec![person.email],
            None => return back(cx, "message", "&error=no_such_user"),
        }
    };
    if recipients.is_empty() {
        return back(cx, "message", "&error=no_such_user");
    }
    for recipient in &recipients {
        if let Err(e) = mailer::send_message(store, recipient, subject, body.to_string()).await {
            server::log_event(cx, "message_failed", Some(&me.email), Some(&e.to_string())).await;
            return back(
                cx,
                "message",
                &format!(
                    "&error=message&why={}",
                    crate::oidc::urlencode(&e.to_string())
                ),
            );
        }
    }
    server::log_event(cx, "message_sent", Some(&me.email), Some(subject)).await;
    back(cx, "message", "&ok=message")
}
/// Dials the mail server without sending, on an admin's say-so, and writes
/// down what it said. The result shows on the Mail section as the standing
/// line; the panel redirects straight back.
#[route(POST "/admin/smtp_check")]
async fn smtp_check(cx: &Cx) -> Result<Response> {
    let me = match require_admin(cx).await {
        Ok(me) => me,
        Err(redirect) => return Ok(redirect),
    };
    if !settings::smtp(&app(cx).store).await?.configured() {
        return back(cx, "mail", "&error=sender_unset");
    }
    probe(store_of(cx), app(cx).live.clone()).await;
    server::log_event(cx, "smtp_checked", Some(&me.email), None).await;
    back(cx, "mail", "")
}

fn store_of(cx: &Cx) -> std::sync::Arc<im_core::store::Store> {
    app(cx).store.clone()
}

/// Runs the probe and records whatever it saw. Shared by the check button
/// and the after-save probe: a saved sender is re-probed in the background,
/// so the standing line catches up on the next view without making the save
/// itself wait on a mail server.
async fn probe(
    store: std::sync::Arc<im_core::store::Store>,
    live: tokio::sync::broadcast::Sender<()>,
) {
    let check = match mailer::check(&store).await {
        Ok(took_ms) => settings::SenderCheck {
            at: time::OffsetDateTime::now_utc(),
            took_ms,
            error: None,
        },
        Err(problem) => settings::SenderCheck {
            at: time::OffsetDateTime::now_utc(),
            took_ms: 0,
            error: Some(problem.to_string()),
        },
    };
    if let Err(problem) = settings::record_check(&store, &check).await {
        eprintln!("im: failed to record the sender check: {problem}");
    }
    // The chip changed; watching tabs re-read it on the next tick.
    let _ = live.send(());
}
