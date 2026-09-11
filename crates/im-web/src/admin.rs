//! The admin panel: users, services, mail, settings, logs. One page, every
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
use topcoat::view::{Child, ViewExt, view};

use crate::health::{Probe, probe_family};
use crate::i18n::{self, Key, lang_of, t};
use crate::layout::shell;
use crate::mailer;
use crate::pages::{error_text, query_value};
use crate::server::{self, App};

fn app(cx: &Cx) -> &App {
    server::app(cx)
}

/// The admin behind this request, or the redirect the request gets instead.
async fn require_admin(cx: &Cx) -> std::result::Result<User, Box<Response>> {
    match server::current_user(cx).await {
        Some(user) if user.admin => Ok(user),
        _ => Err(Box::new(
            (
                StatusCode::SEE_OTHER,
                [(header::LOCATION, HeaderValue::from_static("/"))],
            )
                .into_response(cx)
                .expect("a redirect can always be built"),
        )),
    }
}

/// Everything user-controlled crosses the panel escaped — a display name is
/// free text and the panel renders raw HTML.
fn escape(raw: &str) -> String {
    raw.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// One row action as a two-step disclosure — iz's `confirm-details` idiom:
/// the summary is the word ("Delete"), the opened panel says what it costs
/// and holds the button that actually does it. The eight `&str`s travel as
/// named fields: eight positional parameters tripped the too-many-arguments
/// lint, and the names read better at the call sites anyway.
struct ConfirmAction<'a> {
    field: &'a str,
    id: &'a str,
    action: &'a str,
    word: &'a str,
    extra_class: &'a str,
    title: &'a str,
    cost: &'a str,
    confirm: &'a str,
}
fn confirm_action(ask: ConfirmAction<'_>) -> String {
    let ConfirmAction {
        field,
        id,
        action,
        word,
        extra_class,
        title,
        cost,
        confirm,
    } = ask;
    format!(
        r#"<details class="admin-confirm"><summary class="admin-action{extra_class}">{word}</summary><div class="admin-confirm-pop"><div class="admin-confirm-title">{title}</div><div class="muted">{cost}</div><form method="post" action="{action}"><input type="hidden" name="{field}" value="{id}"><button class="admin-action{extra_class}" type="submit">{confirm}</button></form></div></details>"#
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
  // The show-once banner's copy button: copies the secret beside it, flips
  // its label, and works without script too — the value is selectable text.
  document.addEventListener('click', function (e) {
    var b = e.target.closest && e.target.closest('.admin-copy');
    if (!b) { return; }
    var row = b.closest('.admin-copy-row');
    var v = row && row.querySelector('.admin-copy-value');
    if (!v) { return; }
    var done = function () { b.textContent = b.getAttribute('data-copied-label'); };
    if (navigator.clipboard && navigator.clipboard.writeText) { navigator.clipboard.writeText(v.textContent).then(done, done); } else { try { document.execCommand('copy'); } catch (err) {} done(); }
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
        Err(redirect) => return Ok(*redirect),
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
    // The one read that takes a stashed client secret off the shelf: a
    // replayed, reloaded, or forged ticket finds the shelf empty.
    let shown = query_value(&query, "shown")
        .as_deref()
        .and_then(server::take_shown_secret);

    let nav = |current: &str| {
        [
            ("users", t(lang, Key::NavUsers)),
            ("services", t(lang, Key::NavServices)),
            ("message", t(lang, Key::NavMessage)),
            ("settings", t(lang, Key::NavSettings)),
            ("logs", t(lang, Key::NavLogs)),
            ("health", t(lang, Key::NavHealth)),
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
        "health" => health_section(cx, lang).await?,
        // `section=clients` lands here too — the sections are one table
        // now, and the old address keeps working.
        "services" | "clients" => services_section(cx, shown, lang).await?,
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
                "services" => t(lang, Key::OkServicesSaved),
                "email_changed" => t(lang, Key::OkEmailChanged),
                "client_revoked" => t(lang, Key::OkClientRevoked),
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

    let my_email = me.email.clone();
    let stage = view! {
        cx =>
        <main class="admin-shell">
            <div class="admin-column">
                <div class="admin-bar">
                    // The brand is the way back to the landing, as in iz's
                    // topbar; the address stays a link too.
                    <a class="wordmark-text wordmark-home" href="/">"im"</a>
                    <nav class="admin-tabs">(topcoat::view::Unescaped::new_unchecked(nav(&section)))</nav>
                    <a class="auth-alt" href="/">(my_email)</a>
                </div>
                if let Some(banner) = banner {
                    (topcoat::view::Unescaped::new_unchecked(banner))
                }
                (topcoat::view::Unescaped::new_unchecked(section_html))
                (topcoat::view::Unescaped::new_unchecked(ADMIN_SCRIPT.to_string()))
            </div>
        </main>
    };
    shell(cx, t(lang, Key::TitleAdmin), Some(me), Child::new(stage))
        .await?
        .first()
        .await?
        .into_response(cx)
}

/// One person's folded strip under their row: the live sessions — a small
/// table with a per-session revoke, or the muted line when nothing is live —
/// and, beside it, the address edit. The admin's own row gets both: "you"
/// still signs in from somewhere, and the rescue reaches their own address.
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
            let created = session
                .created_at
                .format(&time::macros::format_description!(
                    "[year]-[month]-[day] [hour]:[minute]"
                ))
                .unwrap_or_else(|_| session.created_at.date().to_string());
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
                created,
                seen,
                escape(&session.token_hash),
                t(lang, Key::RevokeButton),
                id = id,
            ));
        }
        format!(
            concat!(
                r#"<div class="admin-table-wrap"><table class="admin-table"><thead><tr>"#,
                r#"<th>{device}</th><th>{address}</th><th>{signed_in}</th><th>{last_seen}</th><th></th>"#,
                r#"</tr></thead><tbody>{rows}</tbody></table></div>"#
            ),
            device = t(lang, Key::DeviceLabel),
            address = t(lang, Key::AddressLabel),
            signed_in = t(lang, Key::SignedInLabel),
            last_seen = t(lang, Key::LastSeenLabel),
            rows = rows,
        )
    };
    format!(
        concat!(
            r#"<tr><td colspan="4">"#,
            r#"<details class="admin-sessions"><summary class="muted">{sessions_summary}</summary>{body}</details>"#,
            r#"<details class="admin-sessions"><summary class="muted">{email_summary}</summary>"#,
            r#"<div class="admin-fold-form"><form method="post" action="/admin/user_email" class="admin-form"><input type="hidden" name="user" value="{id}"><label class="auth-field"><span class="auth-label">{email_label}</span><input class="auth-input auth-input-mono" type="email" name="email" value="{email}" required></label><button class="admin-action" type="submit">{save}</button></form></div>"#,
            r#"</details></td></tr>"#
        ),
        body = body,
        sessions_summary = i18n::sessions_summary(lang, sessions.len()),
        email_summary = i18n::email_fold_summary(lang),
        id = id,
        email_label = t(lang, Key::EmailCol),
        email = escape(&user.email),
        save = t(lang, Key::SaveButton),
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
        let id = escape(&user.id.to_string());
        let email = escape(&user.email);
        let actions = if user.id == me.id {
            format!(r#"<span class="muted">{}</span>"#, t(lang, Key::YouWord))
        } else {
            // Every row action is a two-step disclosure — iz's
            // confirm-details idiom: the summary is the word, the panel holds
            // the button that actually does it. No script required; the live
            // script adds outside-click closing on top.
            let toggle = if user.disabled {
                confirm_action(ConfirmAction {
                    field: "user",
                    id: &id,
                    action: "/admin/enable",
                    word: t(lang, Key::EnableWord),
                    extra_class: "",
                    title: &i18n::enable_title(lang, &email),
                    cost: t(lang, Key::EnableCost),
                    confirm: t(lang, Key::ConfirmEnable),
                })
            } else {
                confirm_action(ConfirmAction {
                    field: "user",
                    id: &id,
                    action: "/admin/disable",
                    word: t(lang, Key::DisableWord),
                    extra_class: "",
                    title: &i18n::disable_title(lang, &email),
                    cost: t(lang, Key::DisableCost),
                    confirm: t(lang, Key::ConfirmDisable),
                })
            };
            let remove = confirm_action(ConfirmAction {
                field: "user",
                id: &id,
                action: "/admin/delete",
                word: t(lang, Key::DeleteWord),
                extra_class: " admin-danger",
                title: &i18n::delete_title(lang, &email),
                cost: t(lang, Key::DeleteCost),
                confirm: t(lang, Key::ConfirmDelete),
            });
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
  <div class="admin-table-wrap">
  <table class="admin-table">
    <thead><tr><th>{email}</th><th>{name}</th><th></th><th></th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
  </div>
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

/// The family registry, wordmarks and credentials as one table. Every
/// service row carries its client half beside it — client id, redirect
/// URIs, registered date, Rotate/Revoke — joined by the client id its
/// `POST /family/register` authenticated; a client with no service row (a
/// test or stray credential) renders as a credential-only row, and a row
/// with no client yet shows the dash. The wordmark controls stay the
/// panel's on rows no app keeps, and the two add lines — a service, a
/// client — sit under the table.
async fn services_section(
    cx: &Cx,
    shown: Option<(String, String)>,
    lang: i18n::Lang,
) -> Result<String, topcoat::Error> {
    let services = im_core::services::list(&app(cx).store).await?;
    let clients = im_core::oidc::list_clients(&app(cx).store).await?;
    // The join: a service row's client id names the client whose wordmark
    // half and credential half render as one.
    let linked = |id: Option<&String>| {
        id.and_then(|cid| clients.iter().find(|client| &client.client_id.to_string() == cid))
    };
    let mut rows = String::new();
    for service in &services {
        let key = escape(&service.key);
        let name = escape(&service.name);
        let url = escape(&service.url);
        // A row its app keeps: the address is written on that app's every
        // boot, so the panel neither edits it nor takes the row away — the
        // name and the order stay the admin's.
        let kept = service.owner.is_some();
        // The edit disclosure: the opened pop carries the name (and, on an
        // unkept row, the address); the key travels hidden, like every
        // row's write.
        // A kept row posts the stored address back in a hidden field: the
        // form's name change is accepted, and the store refuses only a
        // *changed* address.
        // The storage limit: the panel's field on every row — a kept
        // row's cap is im's to set, like its name. An empty amount posts
        // no limit; the unit pairs with the amount it edits.
        let address_field = if kept {
            format!(
                r#"<input type="hidden" name="url" value="{url}">"#,
                url = url
            )
        } else {
            format!(
                r#"<label class="auth-field"><span class="auth-label">{url_label}</span><input class="auth-input auth-input-mono" type="text" name="url" value="{url}" required></label>"#,
                url_label = t(lang, Key::AddressLabel),
                url = url,
            )
        };
        let (limit_amount, limit_unit) = service
            .storage_limit_bytes
            .map(bytes_as_unit)
            .unwrap_or_default();
        let limit_field = format!(
            r#"<label class="auth-field"><span class="auth-label">{limit_label}</span><input class="auth-input auth-input-mono" type="number" name="limit_amount" min="0" step="any" value="{limit_amount}"></label><select class="auth-input admin-role" name="limit_unit" aria-label="{limit_label}"><option value="MiB"{mib}>MiB</option><option value="GiB"{gib}>GiB</option></select>"#,
            limit_label = t(lang, Key::ServicesStorageLimit),
            limit_amount = limit_amount,
            mib = if limit_unit == "MiB" { " selected" } else { "" },
            gib = if limit_unit == "GiB" { " selected" } else { "" },
        );
        let edit = format!(
            r#"<details class="admin-confirm"><summary class="admin-action">{edit_word}</summary><div class="admin-confirm-pop"><div class="admin-confirm-title">{edit_title}</div><form method="post" action="/admin/services_edit" class="admin-form"><input type="hidden" name="key" value="{key}"><label class="auth-field"><span class="auth-label">{name_label}</span><input class="auth-input auth-input-mono" type="text" name="name" value="{name}" required></label>{address_field}{limit_field}<button class="admin-action" type="submit">{save}</button></form></div></details>"#,
            edit_word = t(lang, Key::EditWord),
            edit_title = i18n::edit_service_title(lang, &name),
            key = key,
            name = name,
            name_label = t(lang, Key::NameCol),
            save = t(lang, Key::SaveButton),
        );
        let up = format!(
            r#"<form method="post" action="/admin/services_move"><input type="hidden" name="key" value="{key}"><input type="hidden" name="dir" value="up"><button class="admin-action" type="submit" aria-label="{up_label}">&#8593;</button></form>"#,
            key = key,
            up_label = t(lang, Key::ServiceMoveUp),
        );
        let down = format!(
            r#"<form method="post" action="/admin/services_move"><input type="hidden" name="key" value="{key}"><input type="hidden" name="dir" value="down"><button class="admin-action" type="submit" aria-label="{down_label}">&#8595;</button></form>"#,
            key = key,
            down_label = t(lang, Key::ServiceMoveDown),
        );
        let remove = if kept {
            format!(
                r#"<span class="muted">{kept_word}</span>"#,
                kept_word = t(lang, Key::ServiceKept),
            )
        } else {
            confirm_action(ConfirmAction {
                field: "key",
                id: &key,
                action: "/admin/services_remove",
                word: t(lang, Key::Remove),
                extra_class: " admin-danger",
                title: &i18n::remove_service_title(lang, &name),
                cost: t(lang, Key::RemoveCost),
                confirm: t(lang, Key::ConfirmRemove),
            })
        };
        let (client_cell, uris_cell, registered_cell, client_actions) =
            match linked(service.client_id.as_ref()) {
                Some(client) => {
                    let id = escape(&client.client_id.to_string());
                    let uris = client
                        .redirect_uris
                        .iter()
                        .map(|uri| escape(uri))
                        .collect::<Vec<_>>()
                        .join("<br>");
                    let registered = client
                        .created_at
                        .format(&time::macros::format_description!(
                            "[year]-[month]-[day]"
                        ))
                        .unwrap_or_default();
                    let controls = client_controls(
                        &id,
                        &escape(&client.name),
                        lang,
                    );
                    (id, uris, registered, controls)
                }
                None => ("—".to_string(), "—".to_string(), "—".to_string(), String::new()),
            };
        rows.push_str(&format!(
            r#"<tr><td class="mono">{key}</td><td>{name}</td><td class="mono">{url}</td><td class="mono">{client_cell}</td><td class="mono">{uris_cell}</td><td class="muted">{registered_cell}</td><td class="actions">{edit}{up}{down}{remove}{client_actions}</td></tr>"#,
        ));
    }
    // Clients no service row answers for — the CLI's or the panel's test
    // credentials — still sit in the table, their credential half alone.
    for client in &clients {
        let id = client.client_id.to_string();
        if services
            .iter()
            .any(|service| service.client_id.as_deref() == Some(id.as_str()))
        {
            continue;
        }
        let name = escape(&client.name);
        let uris = client
            .redirect_uris
            .iter()
            .map(|uri| escape(uri))
            .collect::<Vec<_>>()
            .join("<br>");
        let registered = client
            .created_at
            .format(&time::macros::format_description!("[year]-[month]-[day]"))
            .unwrap_or_default();
        let controls = client_controls(&id, &name, lang);
        rows.push_str(&format!(
            r#"<tr><td class="muted">—</td><td>{name}</td><td class="muted">—</td><td class="mono">{}</td><td class="mono">{uris}</td><td class="muted">{registered}</td><td class="actions">{controls}</td></tr>"#,
            escape(&id),
        ));
    }
    // The show-once banner: the note says what to do with it, the value is
    // click-to-copy, and the shelf behind it has already handed it over.
    let shown_html = shown
        .map(|(client_id, secret)| {
            format!(
                r#"<div class="auth-note">{note}<div class="admin-copy-row"><div class="muted">{id_label}: <span class="mono">{client_id}</span></div><div class="auth-secret admin-copy-value">{secret}</div><button class="admin-action admin-copy" type="button" data-copied-label="{copied}">{copy}</button></div></div>"#,
                note = t(lang, Key::SecretShownNote),
                id_label = t(lang, Key::ClientIdLabel),
                client_id = escape(&client_id),
                secret = escape(&secret),
                copied = t(lang, Key::CopiedWord),
                copy = t(lang, Key::CopyWord),
            )
        })
        .unwrap_or_default();
    Ok(format!(
        r#"<div class="admin-card">
  <div class="auth-title">{title}</div>
  {shown_html}
  <div class="admin-table-wrap">
  <table class="admin-table admin-clients">
    <thead><tr><th>{key_label}</th><th>{name_label}</th><th>{url_label}</th><th>{id_label}</th><th>{uris_label}</th><th>{registered_label}</th><th></th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
  </div>
  <div class="muted">{service_add_label}</div>
  <form method="post" action="/admin/services_add" class="admin-invite">
    <input class="auth-input auth-input-mono" type="text" name="key" placeholder="in" aria-label="{key_label}" required>
    <input class="auth-input" type="text" name="name" placeholder="{name_label}" aria-label="{name_label}" required>
    <input class="auth-input auth-input-mono" type="text" name="url" placeholder="{url_placeholder}" aria-label="{url_label}" required>
    <button class="auth-submit admin-invite-go" type="submit"><span class="auth-submit-text">{add}</span></button>
  </form>
  <div class="muted">{client_add_label}</div>
  <form method="post" action="/admin/clients_add" class="admin-invite">
    <input class="auth-input" type="text" name="name" placeholder="drive" aria-label="{name_label}" required>
    <input class="auth-input auth-input-mono" type="text" name="redirect_uris" placeholder="{uris_placeholder}" aria-label="{uris_label}" required>
    <button class="auth-submit admin-invite-go" type="submit"><span class="auth-submit-text">{client_add}</span></button>
  </form>
</div>"#,
        title = t(lang, Key::ServicesTitle),
        key_label = t(lang, Key::ServiceKeyLabel),
        name_label = t(lang, Key::NameCol),
        url_label = t(lang, Key::AddressLabel),
        url_placeholder = t(lang, Key::ServiceUrlPlaceholder),
        id_label = t(lang, Key::ClientIdLabel),
        uris_label = t(lang, Key::RedirectUrisLabel),
        uris_placeholder = t(lang, Key::RedirectUrisPlaceholder),
        registered_label = t(lang, Key::RegisteredCol),
        service_add_label = t(lang, Key::ServiceAdd),
        add = t(lang, Key::ServiceAdd),
        client_add_label = t(lang, Key::ClientAdd),
        client_add = t(lang, Key::ClientAdd),
    ))
}

/// A client's Rotate/Revoke pair, as the two-step disclosures — the same
/// controls on a linked service row and on a credential-only row.
fn client_controls(client_id: &str, name_html: &str, lang: i18n::Lang) -> String {
    let rotate = confirm_action(ConfirmAction {
        field: "client",
        id: client_id,
        action: "/admin/clients_rotate",
        word: t(lang, Key::RotateWord),
        extra_class: "",
        title: &i18n::rotate_client_title(lang, name_html),
        cost: t(lang, Key::RotateCost),
        confirm: t(lang, Key::ConfirmRotate),
    });
    let revoke_action = confirm_action(ConfirmAction {
        field: "client",
        id: client_id,
        action: "/admin/clients_revoke",
        word: t(lang, Key::RevokeWord),
        extra_class: " admin-danger",
        title: &i18n::revoke_client_title(lang, name_html),
        cost: t(lang, Key::RevokeCost),
        confirm: t(lang, Key::ConfirmRevoke),
    });
    format!("{rotate}{revoke_action}")
}

/// One mebibyte / gibibyte in bytes: the only two units the limit field
/// speaks. Raw bytes never reach the browser — the form posts a decimal
/// amount plus one of these units, converted back here.
const MIB_BYTES: f64 = 1_048_576.0;
const GIB_BYTES: f64 = 1_073_741_824.0;

/// The `(amount, unit)` pair a stored limit edits as: gibibytes once the
/// value reaches one, mebibytes below it, so `2 GiB` edits as `2` GiB
/// rather than `2048` MiB, while a small `512 MiB` cap stays addressable.
fn bytes_as_unit(bytes: u64) -> (String, &'static str) {
    if bytes >= GIB_BYTES as u64 {
        (trim_amount(bytes as f64 / GIB_BYTES), "GiB")
    } else {
        (trim_amount(bytes as f64 / MIB_BYTES), "MiB")
    }
}

/// A form amount for a number input: two decimals at most, trailing zeros
/// (and a bare point) trimmed, so the field reads `2` and `2.5`, never
/// `2.00` or `2.5000000001`.
fn trim_amount(value: f64) -> String {
    let rounded = (value * 100.0).round() / 100.0;
    let text = format!("{rounded:.2}");
    text.trim_end_matches('0').trim_end_matches('.').to_string()
}

/// The bytes an `(amount, unit)` pair names, or `None` when the pair is
/// not a usable limit: an unknown unit, or an amount that is not a finite
/// non-negative number.
fn unit_bytes(amount: &str, unit: &str) -> Option<u64> {
    let per = match unit {
        "MiB" => MIB_BYTES,
        "GiB" => GIB_BYTES,
        _ => return None,
    };
    let value: f64 = amount.trim().parse().ok()?;
    if !value.is_finite() || value < 0.0 {
        return None;
    }
    Some((value * per).round() as u64)
}

/// The limit a services form posts, in bytes: `Ok(None)` when the amount
/// is blank — the field empties to clear the limit — `Ok(Some(bytes))`
/// when it parses, and `Err` when a non-blank amount is not a usable
/// number against its unit, which is the panel's refusal.
fn posted_limit(
    amount: &Option<String>,
    unit: &Option<String>,
) -> Result<Option<u64>, ()> {
    let Some(amount) = amount
        .as_deref()
        .map(str::trim)
        .filter(|amount| !amount.is_empty())
    else {
        return Ok(None);
    };
    match unit_bytes(amount, unit.as_deref().unwrap_or_default()) {
        Some(bytes) => Ok(Some(bytes)),
        None => Err(()),
    }
}

/// One user of the services forms: key, name, address — and, on the edit
/// form, the storage limit as an amount plus its unit. The add form posts
/// neither limit field; the empty amount clears.
#[derive(Deserialize)]
struct ServiceForm {
    key: String,
    name: String,
    url: String,
    limit_amount: Option<String>,
    limit_unit: Option<String>,
}

#[route(POST "/admin/services_add")]
async fn services_add(cx: &Cx, Form(input): Form<ServiceForm>) -> Result<Response> {
    let me = match require_admin(cx).await {
        Ok(me) => me,
        Err(redirect) => return Ok(*redirect),
    };
    let limit = match posted_limit(&input.limit_amount, &input.limit_unit) {
        Ok(limit) => limit,
        Err(()) => return back(cx, "services", "&error=bad_service"),
    };
    let outcome = im_core::services::add(
        &app(cx).store,
        &im_core::services::Service {
            key: input.key,
            name: input.name,
            url: input.url,
            owner: None,
            client_id: None,
            storage_limit_bytes: limit,
        },
    )
    .await;
    service_outcome(cx, &me, outcome).await
}

#[route(POST "/admin/services_edit")]
async fn services_edit(cx: &Cx, Form(input): Form<ServiceForm>) -> Result<Response> {
    let me = match require_admin(cx).await {
        Ok(me) => me,
        Err(redirect) => return Ok(*redirect),
    };
    let limit = match posted_limit(&input.limit_amount, &input.limit_unit) {
        Ok(limit) => limit,
        Err(()) => return back(cx, "services", "&error=bad_service"),
    };
    let outcome = im_core::services::edit(
        &app(cx).store,
        &input.key,
        &input.name,
        &input.url,
        limit,
    )
    .await;
    service_outcome(cx, &me, outcome).await
}

#[derive(Deserialize)]
struct ServiceKeyForm {
    key: String,
}

#[route(POST "/admin/services_remove")]
async fn services_remove(cx: &Cx, Form(input): Form<ServiceKeyForm>) -> Result<Response> {
    let me = match require_admin(cx).await {
        Ok(me) => me,
        Err(redirect) => return Ok(*redirect),
    };
    let outcome = im_core::services::remove(&app(cx).store, &input.key).await;
    service_outcome(cx, &me, outcome).await
}

#[derive(Deserialize)]
struct ServiceMoveForm {
    key: String,
    dir: String,
}

/// Up or down one slot; anything else in `dir` is the panel's refusal.
#[route(POST "/admin/services_move")]
async fn services_move(cx: &Cx, Form(input): Form<ServiceMoveForm>) -> Result<Response> {
    let me = match require_admin(cx).await {
        Ok(me) => me,
        Err(redirect) => return Ok(*redirect),
    };
    let up = match input.dir.as_str() {
        "up" => true,
        "down" => false,
        _ => return back(cx, "services", "&error=bad_service"),
    };
    let outcome = im_core::services::move_service(&app(cx).store, &input.key, up).await;
    service_outcome(cx, &me, outcome).await
}

/// The panel's answer to a services write: back to the section with the
/// good news, or with the section's one refusal when the store said the
/// value is against the rules. Anything else is a real failure and travels
/// as one.
async fn service_outcome(
    cx: &Cx,
    me: &User,
    outcome: im_core::store::Result<()>,
) -> Result<Response> {
    match outcome {
        Ok(()) => {
            server::log_event(cx, "services_updated", Some(&me.email), None).await;
            back(cx, "services", "&ok=services")
        }
        Err(im_core::store::StoreError::Invalid(_) | im_core::store::StoreError::Conflict(_)) => {
            back(cx, "services", "&error=bad_service")
        }
        Err(e) => Err(e.into()),
    }
}

/// One user of the clients forms: the name, and one or more redirect URIs
/// — whitespace- or comma-separated, as loose as the CLI's argument list,
/// because a family dev's `http://127.0.0.1` redirect is a legitimate row.
#[derive(Deserialize)]
struct ClientForm {
    name: String,
    redirect_uris: String,
}

#[route(POST "/admin/clients_add")]
async fn clients_add(cx: &Cx, Form(input): Form<ClientForm>) -> Result<Response> {
    let me = match require_admin(cx).await {
        Ok(me) => me,
        Err(redirect) => return Ok(*redirect),
    };
    let name = input.name.trim().to_string();
    let uris: Vec<String> = input
        .redirect_uris
        .split(|c: char| c.is_whitespace() || c == ',')
        .map(str::trim)
        .filter(|uri| !uri.is_empty())
        .map(str::to_string)
        .collect();
    if name.is_empty() || uris.is_empty() {
        return back(cx, "clients", "&error=bad_client");
    }
    let (id, secret) = im_core::oidc::create_client(&app(cx).store, &name, uris).await?;
    server::log_event(cx, "client_created", Some(&me.email), Some(&name)).await;
    let shown = server::stash_shown_secret(id.to_string(), secret.expose().to_string());
    back(cx, "clients", &format!("&shown={shown}"))
}

#[derive(Deserialize)]
struct ClientAction {
    client: String,
}

#[route(POST "/admin/clients_rotate")]
async fn clients_rotate(cx: &Cx, Form(input): Form<ClientAction>) -> Result<Response> {
    let me = match require_admin(cx).await {
        Ok(me) => me,
        Err(redirect) => return Ok(*redirect),
    };
    // The log line names the client like a person, so the name comes off
    // the row before the secret under it moves.
    let name = match im_core::oidc::client_by_id(&app(cx).store, &input.client).await? {
        Some(client) => client.name,
        None => return back(cx, "clients", "&error=no_such_client"),
    };
    match im_core::oidc::rotate_client_secret(&app(cx).store, &input.client).await? {
        Some(secret) => {
            server::log_event(cx, "client_rotated", Some(&me.email), Some(&name)).await;
            let shown =
                server::stash_shown_secret(input.client.clone(), secret.expose().to_string());
            back(cx, "clients", &format!("&shown={shown}"))
        }
        None => back(cx, "clients", "&error=no_such_client"),
    }
}

#[route(POST "/admin/clients_revoke")]
async fn clients_revoke(cx: &Cx, Form(input): Form<ClientAction>) -> Result<Response> {
    let me = match require_admin(cx).await {
        Ok(me) => me,
        Err(redirect) => return Ok(*redirect),
    };
    let name = match im_core::oidc::client_by_id(&app(cx).store, &input.client).await? {
        Some(client) => client.name,
        None => return back(cx, "clients", "&error=no_such_client"),
    };
    if !im_core::oidc::revoke_client(&app(cx).store, &input.client).await? {
        return back(cx, "clients", "&error=no_such_client");
    }
    server::log_event(cx, "client_revoked", Some(&me.email), Some(&name)).await;
    back(cx, "clients", "&ok=client_revoked")
}

/// The knobs the code shipped with, now the panel's: invite and reset link
/// lifetimes, the sign-in session's days and per-user ceiling, the pending
/// marker's minutes, and the sign-in failure ceiling. Same form skin as Mail.
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
    <label class="auth-field"><span class="auth-label">{max_sessions}</span>
      <input class="auth-input auth-input-mono" type="number" name="max_sessions" min="1" value="{}"></label>
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
        policy.max_sessions,
        policy.pending_minutes,
        policy.reset_minutes,
        policy.login_attempts_per_hour,
        title = t(lang, Key::SettingsTitle),
        sub = t(lang, Key::SettingsSub),
        invite_days = t(lang, Key::InviteDaysLabel),
        session_days = t(lang, Key::SessionDaysLabel),
        max_sessions = t(lang, Key::MaxSessionsLabel),
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
    max_sessions: i64,
    pending_minutes: i64,
    reset_minutes: i64,
    login_attempts_per_hour: i64,
}

#[route(POST "/admin/settings")]
async fn settings_save(cx: &Cx, Form(input): Form<PolicyForm>) -> Result<Response> {
    let me = match require_admin(cx).await {
        Ok(me) => me,
        Err(redirect) => return Ok(*redirect),
    };
    let store = &app(cx).store;
    settings::set_policy(
        store,
        &settings::Policy {
            invite_days: input.invite_days,
            session_days: input.session_days,
            max_sessions: input.max_sessions,
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
            r#"<div class="admin-table-wrap"><table class="admin-table log-list" data-rows="{limit}" data-section="logs">
    <thead><tr><th>{when}</th><th>{what}</th><th>{who}</th><th>{detail}</th></tr></thead>
    <tbody>{rows}</tbody>
  </table></div>"#,
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

    let dir_options = format!(
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
    );

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
        dir_options = dir_options,
    ))
    .map(|card| card + LOG_FIT_SCRIPT)
}

/// The read-only family health panel. One row per services-table entry —
/// self included, im's own row lives on the same table — probed where it
/// stands: `GET {url}/healthz`, no credentials, two seconds to answer.
/// A fourth registered service appears here on its own; nothing on this
/// section takes input, and the live morph brings the next reading the
/// way it refreshes every other section.
async fn health_section(cx: &Cx, lang: i18n::Lang) -> Result<String, topcoat::Error> {
    let services = im_core::services::list(&app(cx).store).await?;
    // One shared reading: this table and the chrome's flyout share the
    // cached probe round, so a family member that is down costs its two
    // seconds once per window, not once per page view.
    let urls = services
        .iter()
        .map(|service| format!("{}/healthz", service.url.trim_end_matches('/')))
        .collect::<Vec<_>>();
    let probes = probe_family(&urls).await;

    let mut rows = String::new();
    for (service, probe) in services.iter().zip(probes) {
        let key = escape(&service.key);
        let name = escape(&service.name);
        let url = escape(&service.url);
        let state = match probe {
            Probe::Up { body, ms } => format!(
                r#"<span class="health-dot health-on"></span>{} <span class="muted">· {ms} ms</span>"#,
                escape(&body)
            ),
            Probe::Down => format!(
                r#"<span class="health-dot health-off"></span><span class="muted">{}</span>"#,
                t(lang, Key::HealthUnreachable),
            ),
        };
        rows.push_str(&format!(
            r#"<tr><td class="mono">{key}</td><td>{name}</td><td class="mono"><a href="{url}" target="_blank" rel="noopener noreferrer">{url}</a></td><td>{state}</td></tr>"#,
        ));
    }
    Ok(format!(
        r#"<div class="admin-card">
  <div class="auth-title">{title}</div>
  <div class="admin-table-wrap">
  <table class="admin-table">
    <thead><tr><th>{key_label}</th><th>{name_label}</th><th>{url_label}</th><th>{state_label}</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
  </div>
</div>"#,
        title = t(lang, Key::HealthTitle),
        key_label = t(lang, Key::ServiceKeyLabel),
        name_label = t(lang, Key::NameCol),
        url_label = t(lang, Key::AddressLabel),
        state_label = t(lang, Key::HealthStateCol),
    ))
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
  // the next firing. A resize also re-opens the reload budget — the hops
  // spent against the old geometry say nothing about the new one.
  var timer = null;
  function schedule() {
    if (timer) { clearTimeout(timer); }
    timer = setTimeout(function () { timer = null; measure(); }, 200);
  }
  var row = document.querySelector('.log-list[data-rows] tbody tr');
  if (row && window.ResizeObserver) { new ResizeObserver(schedule).observe(row); }
  window.addEventListener('resize', function () { window.sessionStorage.removeItem('imLogFitHops'); schedule(); });
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
        Err(redirect) => return Ok(*redirect),
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
struct UserEmailForm {
    user: String,
    email: String,
}

/// The users section's direct address edit — the admin's rescue for a
/// typo'd or unreachable mailbox, applied outright: email is contact
/// metadata, not a key, so the id stays and every reader of the address
/// follows on its next read.
#[route(POST "/admin/user_email")]
async fn user_email(cx: &Cx, Form(input): Form<UserEmailForm>) -> Result<Response> {
    let me = match require_admin(cx).await {
        Ok(me) => me,
        Err(redirect) => return Ok(*redirect),
    };
    let store = &app(cx).store;
    let user_id = UserId::from(input.user);
    match accounts::set_email(store, &user_id, &input.email).await {
        Ok(()) => server::notify_profile(cx, &user_id).await,
        Err(accounts::AccountError::EmailTaken) => return back(cx, "users", "&error=email_taken"),
        Err(accounts::AccountError::InvalidEmail) => return back(cx, "users", "&error=bad_email"),
        Err(e) => return Err(topcoat::Error::from(std::io::Error::other(e.to_string()))),
    }
    let email = input.email.trim().to_lowercase();
    server::log_event(cx, "email_changed", Some(&me.email), Some(&email)).await;
    back(cx, "users", "&ok=email_changed")
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
        Err(redirect) => return Ok(*redirect),
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
        Err(redirect) => return Ok(*redirect),
    };
    let store = &app(cx).store;
    let user_id = UserId::from(input.user);
    let email = accounts::user_by_id(store, &user_id)
        .await?
        .map(|u| u.email);
    accounts::delete_user(store, &user_id).await?;
    // The person is gone; their sessions went with them, and their tabs
    // hear it here.
    server::note_revoked(cx, user_id.as_str(), None).await;
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
        Err(redirect) => return Ok(*redirect),
    };
    let store = &app(cx).store;
    let user_id = UserId::from(input.user);
    let sessions = im_core::sessions::revoke_user_sessions(store, &user_id).await?;
    // Every session of theirs died; their open tabs each hear it and leave.
    server::note_revoked(cx, user_id.as_str(), None).await;
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
        Err(redirect) => return Ok(*redirect),
    };
    let user_id = UserId::from(input.user.clone());
    if !im_core::sessions::revoke_owned_session(&app(cx).store, &user_id, &input.session).await? {
        return back(cx, "users", "&error=session_unknown");
    }
    server::note_revoked(cx, user_id.as_str(), Some(&input.session)).await;
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
        Err(redirect) => return Ok(*redirect),
    };
    let store = &app(cx).store;
    let user_id = UserId::from(input.user);
    // The flag moves first: the announcements below — the eviction news and
    // the member's row — must describe the account as it now stands.
    accounts::set_disabled(store, &user_id, disabled).await?;
    if disabled {
        // A disabled account keeps no sessions either.
        im_core::sessions::revoke_user_sessions(store, &user_id).await?;
        // The disable ends every session; the disabled flag itself rides the
        // Profile announcement right below.
        server::note_revoked(cx, user_id.as_str(), None).await;
    }
    // Announced whether the flag moved either way: the disable drops the
    // member from the next roster read, the enable restores it.
    server::notify_profile(cx, &user_id).await;
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
        Err(redirect) => return Ok(*redirect),
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
        Err(redirect) => return Ok(*redirect),
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
        Err(redirect) => return Ok(*redirect),
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
        Err(redirect) => return Ok(*redirect),
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
    live: tokio::sync::broadcast::Sender<server::LiveEvent>,
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
    let _ = live.send(server::LiveEvent::Tick);
}

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::sync::Arc;

    use im_core::accounts::{create_invite, create_user_from_invite};
    use im_core::model::{ClientId, UserId};
    use im_core::oidc::{introspect_app_session, issue_app_session, list_clients};
    use im_core::sessions::{SessionMeta, create_session};
    use im_core::store::Store;
    use topcoat::asset::RouterBuilderAssetExt as _;
    use topcoat::cookie::RouterBuilderCookieExt as _;
    use topcoat::router::{
        Body, Router, RouterBuilderDiscoverExt as _, StatusCode, header, to_bytes,
    };

    use crate::config::Config;
    use crate::health::Probe;
    use crate::server::{self, SESSION_COOKIE};

    struct Setup {
        router: Router,
        store: Arc<Store>,
        admin_id: UserId,
        admin_cookie: String,
        plain_cookie: String,
        /// Whether the built asset bundle was found beside the target
        /// directory and rides this router — page renders are then
        /// assertable. It is a build artifact, not a source file, so its
        /// absence skips render assertions instead of failing them.
        assets: bool,
    }

    async fn setup() -> Setup {
        let store = Store::open(Path::new(":memory:")).await.unwrap();
        let invite = create_invite(&store, "root@example.com", None, true)
            .await
            .unwrap();
        let admin = create_user_from_invite(&store, invite.expose(), "Root", "tDLr9!mZQ2xv")
            .await
            .unwrap();
        let bare = create_invite(&store, "sid@example.com", None, false)
            .await
            .unwrap();
        let plain = create_user_from_invite(&store, bare.expose(), "Sid", "tDLr9!mZQ2xv")
            .await
            .unwrap();
        let admin_session = create_session(&store, &admin.id, &SessionMeta::default())
            .await
            .unwrap();
        let plain_session = create_session(&store, &plain.id, &SessionMeta::default())
            .await
            .unwrap();
        let (live, _) = tokio::sync::broadcast::channel(64);
        let store = Arc::new(store);
        let app = server::App {
            store: store.clone(),
            config: Config {
                database: ":memory:".into(),
                listen: "127.0.0.1:7650".parse().unwrap(),
                issuer: "http://127.0.0.1:7650".into(),
                services: Vec::new(),
            },
            live,
        };
        // The bundle lives at `target/<profile>/assets`, two hops up from
        // this test binary — exactly where `AssetBundle::load` would look
        // for the server executable.
        let bundle = std::env::current_exe()
            .ok()
            .and_then(|exe| exe.parent().and_then(|deps| deps.parent()).map(|p| p.join("assets")))
            .and_then(|dir| topcoat::asset::AssetBundle::load_dir(dir).ok());
        let assets = bundle.is_some();
        let mut builder = Router::builder().discover().cookies();
        if let Some(bundle) = bundle {
            builder = builder.assets(bundle);
        }
        let router = builder.app_context(app).build();
        Setup {
            router,
            store,
            admin_id: admin.id,
            admin_cookie: format!("{SESSION_COOKIE}={}", admin_session.expose()),
            plain_cookie: format!("{SESSION_COOKIE}={}", plain_session.expose()),
            assets,
        }
    }

    /// A form post through the router, answered as (status, Location, body).
    async fn post_form(
        router: &Router,
        uri: &str,
        body: &str,
        cookie: Option<&str>,
    ) -> (StatusCode, Option<String>, String) {
        let mut builder = http::Request::builder()
            .method(http::Method::POST)
            .uri(uri)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
        if let Some(cookie) = cookie {
            builder = builder.header(header::COOKIE, cookie);
        }
        let response = router
            .handle(builder.body(Body::from(body.to_string())).unwrap())
            .await;
        let (parts, body) = response.into_parts();
        let location = parts
            .headers
            .get(header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let bytes = to_bytes(body, usize::MAX).await.unwrap().to_vec();
        (parts.status, location, String::from_utf8(bytes).unwrap())
    }

    /// A GET with (maybe) a session cookie, answered as
    /// (status, Location, body).
    async fn get_full(
        router: &Router,
        uri: &str,
        cookie: Option<&str>,
    ) -> (StatusCode, Option<String>, String) {
        let mut builder = http::Request::builder().uri(uri);
        if let Some(cookie) = cookie {
            builder = builder.header(header::COOKIE, cookie);
        }
        let response = router.handle(builder.body(Body::empty()).unwrap()).await;
        let (parts, body) = response.into_parts();
        let location = parts
            .headers
            .get(header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let bytes = to_bytes(body, usize::MAX).await.unwrap().to_vec();
        (
            parts.status,
            location,
            String::from_utf8(bytes).unwrap(),
        )
    }

    fn basic(client_id: &str, secret: &str) -> String {
        use base64::Engine as _;
        format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(format!("{client_id}:{secret}"))
        )
    }

    /// Registers a client through the panel itself and returns the pair the
    /// one show-once render would carry: the 303's claim ticket, taken off
    /// the shelf — first reader wins.
    async fn create_via_panel(setup: &Setup, name: &str) -> (String, String) {
        let (status, location, _) = post_form(
            &setup.router,
            "/admin/clients_add",
            &format!("name={name}&redirect_uris=http://127.0.0.1:9000/callback"),
            Some(&setup.admin_cookie),
        )
        .await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        let location = location.expect("a 303 back to the section");
        assert!(location.starts_with("/admin?section=clients&shown="));
        let ticket = location.trim_start_matches("/admin?section=clients&shown=");
        let (id, secret) = server::take_shown_secret(ticket).expect("the one showing");
        let stored = list_clients(&setup.store).await.unwrap();
        let row = stored
            .iter()
            .find(|client| client.name == name)
            .expect("the fresh row");
        assert_eq!(id, row.client_id.to_string());
        (id, secret)
    }

    /// GETs `/directory` with an app's Basic pair.
    async fn directory(router: &Router, authorization: String) -> StatusCode {
        let response = router
            .handle(
                http::Request::builder()
                    .uri("/directory")
                    .header(header::AUTHORIZATION, authorization)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
        response.into_parts().0.status
    }

    #[tokio::test]
    async fn clients_add_shows_the_secret_once_and_the_pair_authenticates() {
        let setup = setup().await;

        // The add answers a 303 whose query carries only a claim ticket —
        // never the secret itself.
        let (status, location, _) = post_form(
            &setup.router,
            "/admin/clients_add",
            "name=drive&redirect_uris=http://127.0.0.1:9000/callback",
            Some(&setup.admin_cookie),
        )
        .await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        let location = location.expect("a 303 back to the section");
        assert!(location.starts_with("/admin?section=clients&shown="));
        assert!(!location.contains("secret"));

        // First reader wins: the ticket yields the pair exactly once, then
        // the shelf is empty — a replayed or reloaded URL shows nothing.
        let ticket = location.trim_start_matches("/admin?section=clients&shown=");
        let (id, secret) = server::take_shown_secret(ticket).expect("the one showing");
        assert!(server::take_shown_secret(ticket).is_none());
        assert!(
            server::take_shown_secret("a-forged-ticket").is_none(),
            "a forged ticket shows nothing"
        );

        // The pair the one render showed authenticates on /directory.
        assert_eq!(
            directory(&setup.router, basic(&id, &secret)).await,
            StatusCode::OK
        );

        // The registry row carries the digest only — the listing can never
        // leak the secret.
        let rows = list_clients(&setup.store).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].name, "drive");
        assert_ne!(rows[0].client_id.to_string(), secret);
    }

    #[tokio::test]
    async fn clients_rotate_kills_the_old_pair_and_shows_a_new_secret_once() {
        let setup = setup().await;
        let (id, old_secret) = create_via_panel(&setup, "drive").await;

        let (status, location, _) = post_form(
            &setup.router,
            "/admin/clients_rotate",
            &format!("client={id}"),
            Some(&setup.admin_cookie),
        )
        .await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        let location = location.expect("a 303 back to the section");
        assert!(location.starts_with("/admin?section=clients&shown="));
        let ticket = location.trim_start_matches("/admin?section=clients&shown=");
        let (rotated_id, new_secret) = server::take_shown_secret(ticket).expect("the one showing");
        assert_eq!(rotated_id, id, "the shelf names the same client");
        assert_ne!(old_secret, new_secret);

        // The old pair is dead; the new one authenticates.
        assert_eq!(
            directory(&setup.router, basic(&id, &old_secret)).await,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            directory(&setup.router, basic(&id, &new_secret)).await,
            StatusCode::OK
        );

        // An unknown client is the section's refusal, not a minted secret.
        let (status, location, _) = post_form(
            &setup.router,
            "/admin/clients_rotate",
            "client=no-such-client",
            Some(&setup.admin_cookie),
        )
        .await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        assert_eq!(
            location.as_deref(),
            Some("/admin?section=clients&error=no_such_client")
        );
    }

    #[tokio::test]
    async fn clients_revoke_kills_the_pair_and_its_tokens() {
        let setup = setup().await;
        let (id, secret) = create_via_panel(&setup, "drive").await;
        let client_id = ClientId::from(id.clone());

        // An app session minted under the client, alive until revoked.
        let session = create_session(&setup.store, &setup.admin_id, &SessionMeta::default())
            .await
            .unwrap();
        let app_token =
            issue_app_session(&setup.store, &setup.admin_id, &client_id, &session.hash())
                .await
                .unwrap();
        assert!(
            introspect_app_session(&setup.store, app_token.expose(), &id)
                .await
                .unwrap()
                .is_some()
        );

        let (status, location, _) = post_form(
            &setup.router,
            "/admin/clients_revoke",
            &format!("client={id}"),
            Some(&setup.admin_cookie),
        )
        .await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        assert_eq!(
            location.as_deref(),
            Some("/admin?section=clients&ok=client_revoked")
        );

        // The pair no longer authenticates, and the app session it minted
        // no longer introspects — while the admin's own sign-in session
        // lives on.
        assert_eq!(
            directory(&setup.router, basic(&id, &secret)).await,
            StatusCode::UNAUTHORIZED
        );
        assert!(
            introspect_app_session(&setup.store, app_token.expose(), &id)
                .await
                .unwrap()
                .is_none(),
            "no ghost app session after revocation"
        );
        assert_eq!(
            im_core::sessions::list_sessions(&setup.store, &setup.admin_id)
                .await
                .unwrap()
                .len(),
            2,
            "the admin's two sign-in sessions — the cookie's and the one that \
             minted the app token — both stay"
        );
    }

    #[tokio::test]
    async fn client_routes_refuse_non_admins() {
        let setup = setup().await;

        // Every client write answers a non-admin with the panel's plain
        // redirect home; nothing is created, rotated, or revoked.
        let (status, location, _) = post_form(
            &setup.router,
            "/admin/clients_add",
            "name=drive&redirect_uris=http://127.0.0.1:9000/callback",
            Some(&setup.plain_cookie),
        )
        .await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        assert_eq!(location.as_deref(), Some("/"));
        let (status, location, _) = post_form(
            &setup.router,
            "/admin/clients_revoke",
            "client=no-such-client",
            Some(&setup.plain_cookie),
        )
        .await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        assert_eq!(location.as_deref(), Some("/"));
        assert!(list_clients(&setup.store).await.unwrap().is_empty());

        // The section read is gated the same way.
        let (status, location, _) = get_full(
            &setup.router,
            "/admin?section=clients",
            Some(&setup.plain_cookie),
        )
        .await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        assert_eq!(location.as_deref(), Some("/"));
        // And a signed-out visitor cannot even create.
        let (status, _, _) = post_form(
            &setup.router,
            "/admin/clients_add",
            "name=drive&redirect_uris=http://127.0.0.1:9000/callback",
            None,
        )
        .await;
        assert_eq!(status, StatusCode::SEE_OTHER);
    }

    #[tokio::test]
    async fn shown_ticket_renders_the_banner_exactly_once() {
        let setup = setup().await;
        let (status, location, _) = post_form(
            &setup.router,
            "/admin/clients_add",
            "name=drive&redirect_uris=http://127.0.0.1:9000/callback",
            Some(&setup.admin_cookie),
        )
        .await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        let location = location.expect("a 303 back to the section");

        // Rendering needs the built asset bundle; without it the page
        // cannot render by design, and the ticket's once-only delivery
        // stays covered by the shelf tests above.
        if !setup.assets {
            return;
        }

        // The one render: the page GET itself consumes the ticket, and the
        // banner carries the secret plain.
        let (page, _, body) =
            get_full(&setup.router, &location, Some(&setup.admin_cookie)).await;
        assert_eq!(page, StatusCode::OK);
        assert!(
            body.contains("<div class=\"auth-secret admin-copy-value\">"),
            "banner renders"
        );
        let secret = body
            .split("admin-copy-value\">")
            .nth(1)
            .expect("the banner's value box")
            .split("</div>")
            .next()
            .unwrap()
            .to_string();
        assert!(!secret.is_empty());
        let id = list_clients(&setup.store).await.unwrap()[0]
            .client_id
            .to_string();
        assert!(body.contains(&id), "the client id rides the banner too");
        // Spent: the same URL — the live tick's morph, a reload — renders
        // the section with no banner, and a forged ticket renders nothing.
        let (_, _, replay) =
            get_full(&setup.router, &location, Some(&setup.admin_cookie)).await;
        assert!(!replay.contains("<div class=\"auth-secret"));
        let (_, _, forged) = get_full(
            &setup.router,
            "/admin?section=clients&shown=forged-ticket",
            Some(&setup.admin_cookie),
        )
        .await;
        assert!(!forged.contains("<div class=\"auth-secret"));
    }

    #[tokio::test]
    async fn merged_section_renders_linked_unlinked_and_bare_rows() {
        let setup = setup().await;

        // A client registered through the panel, then the service row its
        // app writes with that pair: the two halves link.
        let (id, _secret) = create_via_panel(&setup, "drive").await;
        im_core::services::register(
            &setup.store,
            "drive",
            "Drive",
            "https://drive.dizey.sh",
            &id,
            Some(&id),
        )
        .await
        .unwrap();
        // A second client no service row answers for, and a service row
        // with no client yet.
        create_via_panel(&setup, "stray").await;
        im_core::services::add(
            &setup.store,
            &im_core::services::Service {
                key: "wiki".into(),
                name: "Wiki".into(),
                url: "https://wiki.dizey.sh".into(),
                owner: None,
                client_id: None,
                storage_limit_bytes: None,
            },
        )
        .await
        .unwrap();

        // Rendering needs the built asset bundle; without it the render
        // assertions stay skipped (the routes themselves are covered).
        if !setup.assets {
            return;
        }
        let (status, _, body) = get_full(
            &setup.router,
            "/admin?section=services",
            Some(&setup.admin_cookie),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        // The linked row: wordmark half and credential half, one row.
        assert!(body.contains(">Drive</td>"), "the service name renders");
        assert!(body.contains(&id), "the linked client id renders");
        assert!(body.contains("https://drive.dizey.sh"), "the url renders");
        assert!(body.contains("http://127.0.0.1:9000/callback"), "uris render");
        // The credential-only row: the stray client's name, no key or url.
        assert!(body.contains(">stray</td>"), "the stray client renders");
        // The bare service row and the unlinked client carry the dash.
        assert!(body.contains(">Wiki</td>"), "the bare service renders");
        assert!(
            body.contains("<td class=\"muted\">—</td>"),
            "client-less halves read as the dash"
        );

        // The old address lands on the merged section too.
        let (status, _, alias) = get_full(
            &setup.router,
            "/admin?section=clients",
            Some(&setup.admin_cookie),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(alias.contains(">Drive</td>"), body.contains(">Drive</td>"));
    }

    #[tokio::test]
    async fn services_edit_saves_the_limit_and_the_rest_is_refused() {
        let setup = setup().await;
        im_core::services::add(
            &setup.store,
            &im_core::services::Service {
                key: "in".into(),
                name: "Files".into(),
                url: "https://in.dizey.sh".into(),
                owner: None,
                client_id: None,
                storage_limit_bytes: None,
            },
        )
        .await
        .unwrap();

        // The edit posts an amount plus its unit; the row stores bytes.
        let (status, location, _) = post_form(
            &setup.router,
            "/admin/services_edit",
            "key=in&name=Files&url=https://in.dizey.sh&limit_amount=2&limit_unit=GiB",
            Some(&setup.admin_cookie),
        )
        .await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        assert_eq!(
            location.as_deref(),
            Some("/admin?section=services&ok=services")
        );
        assert_eq!(
            im_core::services::list(&setup.store).await.unwrap()[0].storage_limit_bytes,
            Some(2 * 1024 * 1024 * 1024)
        );

        // An empty amount clears the limit — no limit stated.
        let (status, location, _) = post_form(
            &setup.router,
            "/admin/services_edit",
            "key=in&name=Files&url=https://in.dizey.sh&limit_amount=&limit_unit=GiB",
            Some(&setup.admin_cookie),
        )
        .await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        assert_eq!(
            location.as_deref(),
            Some("/admin?section=services&ok=services")
        );
        assert_eq!(
            im_core::services::list(&setup.store).await.unwrap()[0].storage_limit_bytes,
            None
        );

        // A non-blank amount that is not a usable number is the section's
        // refusal, and the stored limit is left alone.
        let (status, location, _) = post_form(
            &setup.router,
            "/admin/services_edit",
            "key=in&name=Files&url=https://in.dizey.sh&limit_amount=abc&limit_unit=GiB",
            Some(&setup.admin_cookie),
        )
        .await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        assert_eq!(
            location.as_deref(),
            Some("/admin?section=services&error=bad_service")
        );
        assert_eq!(
            im_core::services::list(&setup.store).await.unwrap()[0].storage_limit_bytes,
            None
        );

        // A non-admin gets the panel's plain redirect; the row never moves.
        let (status, location, _) = post_form(
            &setup.router,
            "/admin/services_edit",
            "key=in&name=Files&url=https://in.dizey.sh&limit_amount=2&limit_unit=GiB",
            Some(&setup.plain_cookie),
        )
        .await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        assert_eq!(location.as_deref(), Some("/"));
        assert_eq!(
            im_core::services::list(&setup.store).await.unwrap()[0].storage_limit_bytes,
            None
        );

        // The section renders the amount and its unit pair, empty on a
        // row with no limit (bundle permitting).
        if setup.assets {
            let (status, _, body) = get_full(
                &setup.router,
                "/admin?section=services",
                Some(&setup.admin_cookie),
            )
            .await;
            assert_eq!(status, StatusCode::OK);
            assert!(body.contains("name=\"limit_amount\""), "{body}");
            assert!(body.contains("name=\"limit_unit\""), "{body}");
            assert!(body.contains(">GiB</option>"), "{body}");
            assert!(
                body.contains("name=\"limit_amount\" min=\"0\" step=\"any\" value=\"\""),
                "a no-limit row edits empty: {body}"
            );
        }
    }

    /// The deploy asserts this body after the restart — the answer must
    /// carry the baked build sha, `dev` in a plain build.
    #[tokio::test]
    async fn healthz_answers_the_baked_sha() {
        let setup = setup().await;
        let (status, _, body) = get_full(&setup.router, "/healthz", None).await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            body.starts_with("ok "),
            "healthz must answer `ok <build sha>`, got {body:?}"
        );
    }

    /// The probe reads a service answering the deploy body as Up with the
    /// body carried, and a service with nobody home as Down — not a hang,
    /// not an error.
    #[tokio::test]
    async fn health_probe_reads_ok_and_refuses_the_rest() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let http = reqwest::Client::new();

        // A stand-in service answering the deploy body.
        use crate::health::probe_healthz;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();

        let addr = listener.local_addr().unwrap();
        let talker = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            let _ = sock.read(&mut buf).await;
            sock.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 6\r\n\r\nok dev")
                .await
                .unwrap();
        });
        let probe = probe_healthz(&http, &format!("http://{addr}/healthz")).await;
        talker.await.unwrap();
        let Probe::Up { body, .. } = probe else {
            panic!("a service answering `ok dev` must read Up");
        };
        assert_eq!(body, "ok dev");

        // Nobody home: refused connection, Down.
        let dark = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = dark.local_addr().unwrap();
        drop(dark);
        let probe = probe_healthz(&http, &format!("http://{addr}/healthz")).await;
        assert!(matches!(probe, Probe::Down), "a dark port must read Down");
    }

    /// The section is admin-only and, a bundle permitting, renders the
    /// health table with its nav slot.
    #[tokio::test]
    async fn health_section_is_admin_only_and_renders() {
        let setup = setup().await;
        // A family row to render: a port nobody listens on refuses the
        // probe instantly, so the row reads Down without waiting it out.
        // A fixture key, not a sibling's — the panel renders whatever the
        // table holds.
        let dark = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead_url = format!("http://{}", dark.local_addr().unwrap());
        drop(dark);
        im_core::services::add(
            &setup.store,
            &im_core::services::Service {
                key: "xy".into(),
                name: "Fixture".into(),
                url: dead_url,
                owner: None,
                client_id: None,
                storage_limit_bytes: None,
            },
        )
        .await
        .unwrap();
        let (status, location, _) =
            get_full(&setup.router, "/admin?section=health", Some(&setup.plain_cookie)).await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        assert_eq!(location.as_deref(), Some("/"));
        if setup.assets {
            let (status, _, body) =
                get_full(&setup.router, "/admin?section=health", Some(&setup.admin_cookie)).await;
            assert_eq!(status, StatusCode::OK);
            assert!(body.contains("Family health"), "{body}");
            assert!(body.contains("/admin?section=health"), "the nav carries the section: {body}");
            assert!(body.contains("health-dot"), "{body}");
            assert!(body.contains(">xy</td>"), "the fixture row renders: {body}");
            assert!(body.contains("Unreachable"), "the dark row reads Down: {body}");
        }
    }

    /// The signed-in flyout marks each sibling with the same health the
    /// admin table reads: a sibling answering `ok` renders `health-on`,
    /// a dark port `health-off`, dots only — no body, no latency — and
    /// im's own row stays out of the flyout. The render needs the asset
    /// bundle; the markup itself is pinned router-free in
    /// `family_flyout_marks_pure_html` below.
    #[tokio::test]
    async fn family_flyout_marks_siblings_with_health_dots() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let setup = setup().await;

        // A live sibling answering the deploy body, and a dark one.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let live_url = format!("http://{}", listener.local_addr().unwrap());
        let dark = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dark_url = format!("http://{}", dark.local_addr().unwrap());
        drop(dark);
        // `im` gets a row too — one the flyout must leave out.
        for (key, url) in [("iz", live_url), ("in", dark_url.clone()), ("im", dark_url)] {
            im_core::services::add(
                &setup.store,
                &im_core::services::Service {
                    key: key.into(),
                    name: "Fixture".into(),
                    url,
                    owner: None,
                    client_id: None,
                    storage_limit_bytes: None,
                },
            )
            .await
            .unwrap();
        }
        // The render needs the asset bundle; without one `GET /` has no
        // asset config to draw from. The markup itself is pinned
        // router-free in `family_flyout_marks_pure_html` below.
        if setup.assets {
            let talker = tokio::spawn(async move {
                let (mut sock, _) = listener.accept().await.unwrap();
                let mut buf = [0u8; 1024];
                let _ = sock.read(&mut buf).await;
                sock.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 6\r\n\r\nok dev")
                    .await
                    .unwrap();
            });
            let (_, _, body) = get_full(&setup.router, "/", Some(&setup.plain_cookie)).await;
            talker.await.unwrap();
            assert!(body.contains("service-trio"), "{body}");
            assert!(
                body.contains(r#"<a class="trio-mark" href="http://127.0.0.1:"#),
                "the marks stay links: {body}"
            );
            assert!(body.contains("health-dot health-on"), "the ok sibling reads on: {body}");
            assert!(body.contains(">iz</a>"), "the live sibling renders: {body}");
            assert!(body.contains("health-dot health-off"), "the dark sibling reads off: {body}");
            assert!(body.contains(">in</a>"), "the dark sibling renders: {body}");
            assert!(!body.contains(">im</a>"), "im's own row stays out: {body}");
            assert!(!body.contains("ok dev"), "the flyout carries dots only: {body}");
            assert!(!body.contains(" ms</span>"), "the flyout carries no latency: {body}");
        }

    }

    /// A family with no siblings is the bare mark: no flyout in the DOM
    /// at all, so there is nothing to reveal and nothing to probe.
    #[tokio::test]
    async fn family_flyout_without_siblings_is_the_bare_mark() {
        let setup = setup().await;
        if setup.assets {
            let (_, _, body) = get_full(&setup.router, "/", Some(&setup.plain_cookie)).await;
            assert!(!body.contains("service-trio"), "{body}");
            assert!(!body.contains("wordmark-family"), "{body}");
            assert!(!body.contains("health-dot"), "{body}");
            assert!(body.contains("wordmark-text"), "the bare mark stays: {body}");
        } else {
            // No bundle, no render. The empty family stays pinned
            // router-free: only im's own row exists, so there is
            // nothing to reveal and nothing to probe — no marks at all.
            let marks = crate::layout::trio_marks([(
                "im",
                "http://127.0.0.1:7650",
                Probe::Up { body: "ok dev".into(), ms: 1 },
            )]);
            assert!(marks.is_empty(), "an im-only family has no flyout: {marks}");
        }
    }

    /// The CI gate for the flyout markup: `trio_marks` is the exact
    /// HTML the flyout renders, so the probe-to-dot mapping and im's
    /// omission are pinned without a router or an asset bundle — which
    /// is where the renders above get skipped. Up reads `health-on`,
    /// Down `health-off`, the keys stay links, and the probe's body and
    /// latency never leave the admin table.
    #[test]
    fn family_flyout_marks_pure_html() {
        let marks = crate::layout::trio_marks([
            ("iz", "http://127.0.0.1:9001", Probe::Up { body: "ok dev".into(), ms: 12 }),
            ("in", "http://127.0.0.1:9002", Probe::Down),
            // im's own row goes in; it must not come back out.
            ("im", "http://127.0.0.1:7650", Probe::Up { body: "ok dev".into(), ms: 1 }),
        ]);
        assert!(
            marks.contains(r#"<a class="trio-mark" href="http://127.0.0.1:9001">"#),
            "the marks stay links: {marks}"
        );
        assert!(marks.contains("health-dot health-on"), "the ok sibling reads on: {marks}");
        assert!(marks.contains(">iz</a>"), "the live sibling renders: {marks}");
        assert!(marks.contains("health-dot health-off"), "the dark sibling reads off: {marks}");
        assert!(marks.contains(">in</a>"), "the dark sibling renders: {marks}");
        assert!(!marks.contains(">im</a>"), "im's own row stays out: {marks}");
        assert!(!marks.contains("ok dev"), "the flyout carries dots only: {marks}");
        assert!(!marks.contains(" ms</span>"), "the flyout carries no latency: {marks}");
        assert!(
            marks.contains(r#"<span class="trio-sep">·</span>"#),
            "the marks join on middots: {marks}"
        );
    }
}
