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
    let section = query_value(&query, "section").unwrap_or_else(|| "users".to_string());
    let error = query_value(&query, "error");
    let ok = query_value(&query, "ok");
    let invited = query_value(&query, "invited");

    let nav = |current: &str| {
        [("users", "Users"), ("mail", "Mail"), ("logs", "Logs")]
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
        "logs" => logs_section(cx).await?,
        _ => users_section(cx, &me, invited.as_deref()).await?,
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
                _ => "Done.",
            }
        )),
        (_, Some(code)) => Some(format!(
            r#"<div class="auth-problem">{}</div>"#,
            error_text(code)
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
            </div>
        </main>
    };
    shell(cx, "Admin · im", stage).await?.into_response(cx)
}

async fn users_section(
    cx: &Cx,
    me: &User,
    invited: Option<&str>,
) -> Result<String, topcoat::Error> {
    let users = accounts::list_users(&app(cx).store).await?;
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
            let toggle = if user.disabled {
                format!(
                    r#"<form method="post" action="/admin/enable"><input type="hidden" name="user" value="{id}"><button class="admin-action" type="submit">Enable</button></form>"#
                )
            } else {
                format!(
                    r#"<form method="post" action="/admin/disable"><input type="hidden" name="user" value="{id}"><button class="admin-action" type="submit">Disable</button></form>"#
                )
            };
            format!(
                r#"{toggle}<form method="post" action="/admin/revoke"><input type="hidden" name="user" value="{id}"><button class="admin-action" type="submit">Sign out everywhere</button></form>"#
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
    <label class="admin-check"><input type="checkbox" name="admin" value="yes"> admin</label>
    <button class="auth-submit admin-action-wide" type="submit"><span class="auth-submit-text">Invite</span></button>
  </form>
</div>"#
    ))
}

async fn mail_section(cx: &Cx) -> Result<String, topcoat::Error> {
    let smtp = settings::smtp(&app(cx).store).await?;
    let password_note = if smtp.password.is_some() {
        "password is set — fill to replace, leave empty to keep"
    } else {
        "no password set"
    };
    Ok(format!(
        r#"<div class="admin-card">
  <div class="auth-title">Mail</div>
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
    <label class="auth-field"><span class="auth-label">From</span>
      <input class="auth-input auth-input-mono" type="text" name="from" value="{}" placeholder="im &lt;auth@example.com&gt;"></label>
    <button class="auth-submit admin-action-wide" type="submit"><span class="auth-submit-text">Save</span></button>
  </form>
  <form method="post" action="/admin/smtp_test" class="admin-form">
    <button class="admin-action" type="submit">Send a test mail to myself</button>
  </form>
</div>"#,
        escape(&smtp.host),
        smtp.port,
        escape(&smtp.username),
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
    admin: Option<String>,
}

#[route(POST "/admin/invite")]
async fn invite(cx: &Cx, Form(input): Form<InviteForm>) -> Result<Response> {
    let me = match require_admin(cx).await {
        Ok(me) => me,
        Err(redirect) => return Ok(redirect),
    };
    let store = &app(cx).store;
    let email = input.email.trim().to_string();
    let admin = input.admin.as_deref() == Some("yes");
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
    events::log(
        store,
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
    events::log(
        store,
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
    events::log(
        store,
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
        password: None,
    };
    settings::set_smtp(store, &value, input.password.as_deref()).await?;
    events::log(store, "smtp_updated", Some(&me.email), None).await;
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
            events::log(&app(cx).store, "smtp_test_sent", Some(&me.email), None).await;
            back(cx, "mail", "&ok=smtp_test")
        }
        Err(e) => {
            events::log(
                &app(cx).store,
                "smtp_test_failed",
                Some(&me.email),
                Some(&e.to_string()),
            )
            .await;
            back(cx, "mail", "&error=smtp_test")
        }
    }
}
