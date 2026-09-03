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
use topcoat::router::content::Form;
use topcoat::router::response::{IntoResponse, Response};
use topcoat::router::{HeaderValue, StatusCode, header, route};
use topcoat::view::view;

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
/// The panel's live wiring, the client half of `live.rs`. One EventSource
/// per tab; a tick re-fetches the page and swaps the panel's body. iz's
/// lesson is honored in miniature: the swap must not throw away what someone
/// is doing, so a focused field suspends the refresh until the next tick,
/// and the morph is one innerHTML swap of the column — small DOM, no diffing
/// library needed.
///
/// The same script closes an open confirm disclosure on outside click and
/// Escape — the one bit of behavior the no-script markup cannot do itself.
const LIVE_SCRIPT: &str = r#"<script>(function () {
  if (window.__imLive) { return; }
  window.__imLive = true;
  var timer = null;
  function refresh() {
    timer = null;
    var active = document.activeElement;
    if (active && /^(INPUT|SELECT|TEXTAREA)$/.test(active.tagName)) { return; }
    fetch(location.href).then(function (r) { return r.text(); }).then(function (html) {
      var fresh = new DOMParser().parseFromString(html, 'text/html');
      var here = document.querySelector('.admin-column');
      var there = fresh.querySelector('.admin-column');
      if (here && there) { here.innerHTML = there.innerHTML; }
    }).catch(function () {});
  }
  var source = new EventSource('/admin/live');
  source.onmessage = function () {
    if (timer) { return; }
    timer = setTimeout(refresh, 200);
  };
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
    let query = topcoat::router::request::uri(cx)
        .query()
        .unwrap_or("")
        .to_string();
    let section = query_value(&query, "section").unwrap_or_else(|| "account".to_string());
    let error = query_value(&query, "error");
    let ok = query_value(&query, "ok");
    let why = query_value(&query, "why");
    let invited = query_value(&query, "invited");

    let nav = |current: &str| {
        [
            ("account", "Account"),
            ("users", "Users"),
            ("mail", "Mail"),
            ("settings", "Settings"),
            ("logs", "Logs"),
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
        "mail" => mail_section(cx).await?,
        "settings" => settings_section(cx).await?,
        "logs" => logs_section(cx).await?,
        "users" => users_section(cx, &me, invited.as_deref()).await?,
        _ => account_section(&me),
    };

    let banner = match (ok.as_deref(), error.as_deref()) {
        (Some(code), _) => Some(format!(
            r#"<div class="auth-ok">{}</div>"#,
            match code {
                "invited" => "Invite created.",
                "revoked" => "Sessions revoked — every device is signed out.",
                "disabled" => "Account disabled.",
                "enabled" => "Account enabled.",
                "smtp" => "Mail settings saved.",
                "smtp_test" => "Test mail sent.",
                "password" => "Password changed — every other device is signed out.",
                "uninvited" => "Invite invalidated — the link is dead.",
                "deleted" => "Account deleted.",
                "settings" => "Settings saved.",
                _ => "Done.",
            }
        )),
        (_, Some(code)) => Some(format!(
            r#"<div class="auth-problem">{}{}</div>"#,
            error_text(code),
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
                    <span class="wordmark-text">"im"</span>
                    <nav class="admin-tabs">(topcoat::view::Unescaped::new_unchecked(nav(&section)))</nav>
                    <a class="auth-alt" href="/">(escape(&me.email))</a>
                </div>
                if let Some(banner) = banner {
                    (topcoat::view::Unescaped::new_unchecked(banner))
                }
                (topcoat::view::Unescaped::new_unchecked(section_html))
                (topcoat::view::Unescaped::new_unchecked(LIVE_SCRIPT.to_string()))
            </div>
        </main>
    };
    shell(cx, "Admin · im", stage).await?.into_response(cx)
}
/// The self-service half of the panel: the account the panel is signed in
/// as. Izlek keeps this on the settings rail's first tab; so do we.
fn account_section(me: &User) -> String {
    let two_factor = if me.totp_confirmed {
        "two-factor is on"
    } else {
        "two-factor is NOT on — sign out and back in to set it up"
    };
    format!(
        r#"<div class="admin-card">
  <div class="auth-title">Account</div>
  <div class="auth-sub">Signed in as <span class="mono">{}</span> · {two_factor}.</div>
  <form method="post" action="/admin/password" class="admin-form">
    <label class="auth-field"><span class="auth-label">Current password</span>
      <input class="auth-input auth-input-mono" type="password" name="current" autocomplete="current-password" required></label>
    <label class="auth-field"><span class="auth-label">New password</span>
      <input class="auth-input auth-input-mono" type="password" name="password" autocomplete="new-password" minlength="10" required></label>
    <label class="auth-field"><span class="auth-label">New password, again</span>
      <input class="auth-input auth-input-mono" type="password" name="password_confirm" autocomplete="new-password" minlength="10" required></label>
    <button class="auth-submit admin-action-wide" type="submit"><span class="auth-submit-text">Change password</span></button>
  </form>
  <div class="auth-sub">Changing it signs every other device out — this one stays.</div>
</div>"#,
        escape(&me.email)
    )
}

async fn users_section(
    cx: &Cx,
    me: &User,
    invited: Option<&str>,
) -> Result<String, topcoat::Error> {
    let users = accounts::list_users(&app(cx).store).await?;
    let pending = accounts::list_pending_invites(&app(cx).store).await?;
    let mut rows = String::new();
    for user in &users {
        let flags = [
            user.admin.then_some("admin"),
            user.disabled.then_some("disabled"),
            (!user.totp_confirmed).then_some("no 2fa"),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join(" · ");
        let actions = if user.id == me.id {
            // Never let the only admin lock themselves out by reflex.
            r#"<span class="muted">you</span>"#.to_string()
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
                    "Enable",
                    "",
                    &format!("Enable {email}?"),
                    "They can sign in again.",
                    "Confirm enable",
                )
            } else {
                confirm_action(
                    &id,
                    "/admin/disable",
                    "Disable",
                    "",
                    &format!("Disable {email}?"),
                    "They cannot sign in, and every live session ends.",
                    "Confirm disable",
                )
            };
            let remove = confirm_action(
                &id,
                "/admin/delete",
                "Delete",
                " admin-danger",
                &format!("Delete {email}?"),
                "The account, its sessions and every app token go with it. The address can be invited again, as somebody new.",
                "Confirm delete",
            );
            format!(
                r#"{toggle}<form method="post" action="/admin/revoke"><input type="hidden" name="user" value="{id}"><button class="admin-action" type="submit">Sign out everywhere</button></form>{remove}"#
            )
        };
        rows.push_str(&format!(
            "<tr><td class=\"mono\">{}</td><td>{}</td><td class=\"muted\">{}</td><td class=\"actions\">{}</td></tr>",
            escape(&user.email),
            escape(&user.name),
            flags,
            actions
        ));
    }
    // Invites still waiting on their person sit in the same table — "waiting"
    // instead of a name, and the one action an outstanding link understands:
    for row in &pending {
        let flags = [Some("invited"), row.admin.then_some("admin")]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>()
            .join(" · ");
        let expires = row
            .expires_at
            .format(&time::macros::format_description!("[year]-[month]-[day]"))
            .unwrap_or_default();
        rows.push_str(&format!(
            r#"<tr><td class="mono">{}</td><td class="muted">waiting · until {}</td><td class="muted">{}</td><td class="actions"><form method="post" action="/admin/uninvite"><input type="hidden" name="invite" value="{}"><button class="admin-action" type="submit">Invalidate</button></form></td></tr>"#,
            escape(&row.email),
            expires,
            flags,
            escape(&row.token_hash),
        ));
    }
    let invited_html = invited
        .map(|link| {
            format!(
                r#"<div class="auth-note">The link exists once. It is shown once:<br><span class="mono">{}</span></div>"#,
                escape(link)
            )
        })
        .unwrap_or_default();
    Ok(format!(
        r#"<div class="admin-card">
  <div class="auth-title">People</div>
  {invited_html}
  <table class="admin-table">
    <thead><tr><th>Email</th><th>Name</th><th></th><th></th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
  <form method="post" action="/admin/invite" class="admin-invite">
    <input class="auth-input auth-input-mono" type="email" name="email" placeholder="person@example.com" required>
    <select class="auth-input admin-role" name="role">
      <option value="member">member</option>
      <option value="admin">admin</option>
    </select>
    <button class="auth-submit admin-invite-go" type="submit"><span class="auth-submit-text">Invite</span></button>
  </form>
</div>"#
    ))
}

/// The knobs the code shipped with, now the panel's: invite and reset link
/// lifetimes, the sign-in session's days, the pending marker's minutes, and
/// the sign-in failure ceiling. Same form skin as Mail.
async fn settings_section(cx: &Cx) -> Result<String, topcoat::Error> {
    let policy = settings::policy(&app(cx).store).await?;
    Ok(format!(
        r#"<div class="admin-card">
  <div class="auth-title">Settings</div>
  <div class="auth-sub">The rules identity lives by. They apply from the next invite, sign-in or link — nothing already minted is rewritten.</div>
  <form method="post" action="/admin/settings" class="admin-form">
    <label class="auth-field"><span class="auth-label">Invite link, days</span>
      <input class="auth-input auth-input-mono" type="number" name="invite_days" min="1" value="{}"></label>
    <label class="auth-field"><span class="auth-label">Sign-in session, days</span>
      <input class="auth-input auth-input-mono" type="number" name="session_days" min="1" value="{}"></label>
    <label class="auth-field"><span class="auth-label">Second-factor window, minutes</span>
      <input class="auth-input auth-input-mono" type="number" name="pending_minutes" min="1" value="{}"></label>
    <label class="auth-field"><span class="auth-label">Reset link, minutes</span>
      <input class="auth-input auth-input-mono" type="number" name="reset_minutes" min="1" value="{}"></label>
    <label class="auth-field"><span class="auth-label">Failed sign-ins per address per hour</span>
      <input class="auth-input auth-input-mono" type="number" name="login_attempts_per_hour" min="1" value="{}"></label>
    <button class="auth-submit admin-action-wide" type="submit"><span class="auth-submit-text">Save</span></button>
  </form>
</div>"#,
        policy.invite_days,
        policy.session_days,
        policy.pending_minutes,
        policy.reset_minutes,
        policy.login_attempts_per_hour,
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

async fn mail_section(cx: &Cx) -> Result<String, topcoat::Error> {
    let store = &app(cx).store;
    let smtp = settings::smtp(store).await?;
    let password_note = if smtp.password.is_some() {
        "password is set — fill to replace, leave empty to keep"
    } else {
        "no password set"
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
            "not configured".to_string(),
            String::new(),
        ),
        settings::Standing::Unchecked => (
            "chip chip-muted",
            "unchecked".to_string(),
            "Saved, but never checked — the check dials the server and stops before sending."
                .to_string(),
        ),
        settings::Standing::Connected { at, took_ms } => (
            "chip chip-connected",
            format!("connected · {took_ms} ms"),
            format!(
                "Checked {} — TLS, hello, password: all accepted.",
                stamp(at)
            ),
        ),
        settings::Standing::Refused { at, said } => (
            "chip chip-refused",
            "refused".to_string(),
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
  <div class="admin-card-head"><div class="auth-title">Mail</div><span class="{chip_class}">{chip_text}</span></div>
  <div class="auth-sub">Invites go out through this sender. The password is sealed under <span class="mono">im.key</span>; without a sender, invite links are shown here instead of mailed.</div>
  <form method="post" action="/admin/smtp" class="admin-form">
    <label class="auth-field"><span class="auth-label">Host</span>
      <input class="auth-input auth-input-mono" type="text" name="host" value="{}" placeholder="smtp.example.com"></label>
    <label class="auth-field"><span class="auth-label">Port</span>
      <input class="auth-input auth-input-mono" type="number" name="port" value="{}"></label>
    <label class="auth-field"><span class="auth-label">Username</span>
      <input class="auth-input auth-input-mono" type="text" name="username" value="{}"></label>
    <label class="auth-field"><span class="auth-label">Password</span>
      <input class="auth-input auth-input-mono" type="password" name="password" placeholder="{password_note}" autocomplete="off"></label>
    <label class="auth-field"><span class="auth-label">From name</span>
      <input class="auth-input auth-input-mono" type="text" name="from_name" value="{}" placeholder="im"></label>
    <label class="auth-field"><span class="auth-label">From address</span>
      <input class="auth-input auth-input-mono" type="text" name="from" value="{}" placeholder="auth@example.com"></label>
    <button class="auth-submit admin-action-wide" type="submit"><span class="auth-submit-text">Save</span></button>
  </form>
  {lede_html}
  <div class="admin-pair">
    <form method="post" action="/admin/smtp_check"><button class="admin-action" type="submit">Check connection</button></form>
    <form method="post" action="/admin/smtp_test"><button class="admin-action" type="submit">Send a test mail to myself</button></form>
  </div>
</div>"#,
        escape(&smtp.host),
        smtp.port,
        escape(&smtp.username),
        escape(&smtp.from_name),
        escape(&smtp.from)
    ))
}

async fn logs_section(cx: &Cx) -> Result<String, topcoat::Error> {
    let entries = events::list(&app(cx).store, 200).await?;
    let mut rows = String::new();
    for event in &entries {
        rows.push_str(&format!(
            "<tr><td class=\"mono muted\">{}</td><td class=\"mono\">{}</td><td>{}</td><td class=\"muted\">{}</td></tr>",
            escape(&event.at.format(&time::macros::format_description!("[year]-[month]-[day] [hour]:[minute]:[second]")).unwrap_or_default()),
            escape(&event.kind),
            escape(event.actor.as_deref().unwrap_or("")),
            escape(event.detail.as_deref().unwrap_or("")),
        ));
    }
    Ok(format!(
        r#"<div class="admin-card">
  <div class="auth-title">Logs</div>
  <div class="auth-sub">Everything identity did, newest first. Introspection is not logged — it runs per request and would drown the rest.</div>
  <table class="admin-table">
    <thead><tr><th>When</th><th>What</th><th>Who</th><th>Detail</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
</div>"#
    ))
}

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
struct PasswordForm {
    current: String,
    password: String,
    password_confirm: String,
}

#[route(POST "/admin/password")]
async fn password(cx: &Cx, Form(input): Form<PasswordForm>) -> Result<Response> {
    let me = match require_admin(cx).await {
        Ok(me) => me,
        Err(redirect) => return Ok(redirect),
    };
    if input.password != input.password_confirm {
        return back(cx, "account", "&error=passwords_differ");
    }
    let store = &app(cx).store;
    match accounts::change_password(store, &me, &input.current, &input.password).await {
        Ok(()) => {}
        Err(accounts::AccountError::Password(problem)) => {
            use im_core::accounts::PasswordProblem::*;
            let code = match problem {
                TooShort => "password_too_short",
                LooksLikeYou => "password_personal",
                WrongCurrent => "password_wrong",
                IsCurrent => "password_same",
            };
            return back(cx, "account", &format!("&error={code}"));
        }
        Err(e) => return Err(topcoat::Error::from(std::io::Error::other(e.to_string()))),
    }
    // Every other device is out; the browser holding this form proved the
    // old password and keeps its session.
    if let Some(token) = server::presented_session(cx) {
        im_core::sessions::revoke_user_sessions_except(store, &me.id, &token).await?;
    }
    server::log_event(cx, "password_changed", Some(&me.email), None).await;
    back(cx, "account", "&ok=password")
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
    match mailer::send_test(&app(cx).store, &me.email).await {
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
/// Dials the mail server without sending, on an admin's say-so, and writes
/// down what it said. The result shows on the Mail section as the standing
/// line; the panel redirects straight back.
#[route(POST "/admin/smtp_check")]
async fn smtp_check(cx: &Cx) -> Result<Response> {
    let me = match require_admin(cx).await {
        Ok(me) => me,
        Err(redirect) => return Ok(redirect),
    };
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
