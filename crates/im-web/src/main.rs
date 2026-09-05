//! im — the Dizey SSO. Server by default; the CLI covers bootstrapping
//! (the first admin invite) and the two admin actions that must work even
//! when the panel cannot be reached. Everything else lives in /admin.

use std::sync::Arc;

use im_core::store::Store;
use topcoat::Result;
use topcoat::asset::RouterBuilderAssetExt;
use topcoat::cookie::RouterBuilderCookieExt;
use topcoat::router::{BodyLimit, Router, RouterBuilderDiscoverExt, route};

mod admin;
mod auth;
mod config;
mod dropdown;
mod i18n;
mod layout;
mod live;
mod mailer;
mod oidc;
mod pages;
mod people;
mod photo;
mod server;

use config::Config;

#[route(GET "/healthz")]
async fn healthz() -> Result<&'static str> {
    Ok("ok")
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let config = match Config::load() {
        Ok(config) => config,
        Err(problem) => {
            eprintln!("im: {problem}");
            std::process::exit(2);
        }
    };

    match args.get(1).map(String::as_str) {
        None => serve(config).await,
        Some("invite") => {
            let mut email = None;
            let mut admin = false;
            for arg in &args[2..] {
                match arg.as_str() {
                    "--admin" => admin = true,
                    other if email.is_none() => email = Some(other.to_string()),
                    other => {
                        eprintln!("usage: im-web invite <email> [--admin]");
                        eprintln!("im: unexpected argument {other}");
                        std::process::exit(2);
                    }
                }
            }
            let Some(email) = email else {
                eprintln!("usage: im-web invite <email> [--admin]");
                std::process::exit(2);
            };
            invite(config, &email, admin).await;
        }
        Some("revoke") => {
            let Some(email) = args.get(2) else {
                eprintln!("usage: im-web revoke <email>");
                std::process::exit(2);
            };
            revoke(config, email).await;
        }
        Some("create-client") => {
            let (Some(name), uris) = (args.get(2), args.get(3..).unwrap_or(&[])) else {
                eprintln!("usage: im-web create-client <name> <redirect-uri> [more-uris...]");
                std::process::exit(2);
            };
            if uris.is_empty() {
                eprintln!("usage: im-web create-client <name> <redirect-uri> [more-uris...]");
                std::process::exit(2);
            }
            create_client(config, name, uris).await;
        }
        Some("promote") => {
            let Some(email) = args.get(2) else {
                eprintln!("usage: im-web promote <email>");
                std::process::exit(2);
            };
            set_admin_cli(config, email, true).await;
        }
        Some("demote") => {
            let Some(email) = args.get(2) else {
                eprintln!("usage: im-web demote <email>");
                std::process::exit(2);
            };
            set_admin_cli(config, email, false).await;
        }
        Some(other) => {
            eprintln!(
                "im: unknown command {other:?} (expected: invite, revoke, promote, demote, create-client, or none to serve)"
            );
            std::process::exit(2);
        }
    }
}

/// `im-web promote|demote <email>`: the admin flag for an account that
/// already exists — the migration path's way in, since invites refuse
/// addresses with accounts.
async fn set_admin_cli(config: Config, email: &str, admin: bool) {
    let store = open_store(&config).await;
    let Some(user) = im_core::accounts::user_by_email(&store, email)
        .await
        .expect("failed to read users")
    else {
        eprintln!("im: no account for {email}");
        std::process::exit(1);
    };
    im_core::accounts::set_admin(&store, &user.id, admin)
        .await
        .expect("failed to update");
    im_core::events::log(
        &store,
        if admin {
            "user_promoted"
        } else {
            "user_demoted"
        },
        Some("cli"),
        Some(email),
    )
    .await;
    println!("im      {email}: admin = {admin}");
}

async fn open_store(config: &Config) -> Arc<Store> {
    Arc::new(
        Store::open(&config.database)
            .await
            .expect("failed to open the database"),
    )
}

/// `im-web invite <email> [--admin]`: creates the invite, mails it when the
/// panel has configured a sender, prints the link otherwise (dev mode).
///
/// Needs the server stopped: Turso is a single-writer engine, and this
/// process would hold the same file.
async fn invite(config: Config, email: &str, admin: bool) {
    let store = open_store(&config).await;
    let token = match im_core::accounts::create_invite(&store, email, None, admin).await {
        Ok(token) => token,
        Err(im_core::accounts::AccountError::EmailTaken) => {
            eprintln!(
                "im: {email} already has an account — `im-web promote {email}` if you mean admin"
            );
            std::process::exit(1);
        }
        Err(e) => panic!("failed to create the invite: {e}"),
    };
    im_core::events::log(
        &store,
        "invite_created",
        Some("cli"),
        Some(&format!(
            "for {email}{}",
            if admin { " (admin)" } else { "" }
        )),
    )
    .await;
    match mailer::send_invite(&store, &config.issuer, email, token.expose()).await {
        Ok(link) => println!("im      invite mailed to {email}\nim      {link}"),
        Err(_) => println!(
            "im      invite for {email}: {}/invite/{}",
            config.issuer,
            token.expose()
        ),
    }
}

/// `im-web revoke <email>`: signs the person out everywhere — central
/// sessions, refresh tokens, and the app sessions introspection answers for.
async fn revoke(config: Config, email: &str) {
    let store = open_store(&config).await;
    let Some(user) = im_core::accounts::user_by_email(&store, email)
        .await
        .expect("failed to read users")
    else {
        eprintln!("im: no account for {email}");
        std::process::exit(1);
    };
    let count = im_core::sessions::revoke_user_sessions(&store, &user.id)
        .await
        .expect("failed to revoke");
    im_core::events::log(&store, "sessions_revoked", Some("cli"), Some(email)).await;
    println!("im      {email}: {count} session(s) revoked, everywhere, now");
}

/// `im-web create-client <name> <uris...>`: registers a relying party and
/// prints the secret exactly once.
async fn create_client(config: Config, name: &str, uris: &[String]) {
    let store = open_store(&config).await;
    let (id, secret) = im_core::oidc::create_client(&store, name, uris.to_vec())
        .await
        .expect("failed to create the client");
    println!("im      client {name}");
    println!("  client_id     {id}");
    println!("  client_secret {}", secret.expose());
    println!("  (the secret is shown once; its digest is all the database keeps)");
}
async fn serve(config: Config) {
    for line in config.report() {
        println!("im      {line}");
    }
    let store = open_store(&config).await;
    let (live, _) = tokio::sync::broadcast::channel(64);
    // Told when the process is stopping, so the live streams end instead of
    // being waited out — see `live::Shutdown`.
    let (stop, stopping) = tokio::sync::watch::channel(false);
    let app = server::App {
        store,
        config: config.clone(),
        live,
    };

    let bundle = topcoat::asset::AssetBundle::load().unwrap_or_else(|err| {
        eprintln!("im: the asset bundle beside the executable failed to load: {err}");
        eprintln!("im: run `topcoat asset bundle -p im-web` first");
        std::process::exit(2);
    });

    let router = Router::builder()
        .discover()
        // Headroom over the photo cap: the boundary and part headers ride
        // inside the body limit, so the handler's byte cap — not this layer —
        // stays the one that says "over 5 MB".
        .layer(BodyLimit::max(photo::PHOTO_LIMIT_BYTES as usize + 4096).at("/api/profile_photo"))
        .cookies()
        .assets(bundle)
        .app_context(app)
        .app_context(photo::PhotoStamps::default())
        .app_context(live::Shutdown(stopping))
        .build();

    // `topcoat::start` binds HOST/PORT from the environment; the listen
    // address is a config/im.toml decision, so the listener is bound
    // explicitly against the same value the boot log just printed.
    let listener = tokio::net::TcpListener::bind(config.listen)
        .await
        .expect("failed to bind the listen address");
    topcoat::serve_until(listener, router, shutdown_signal(stop))
        .await
        .expect("server error");
}

/// Resolves when the process is asked to stop: Ctrl+C, or `SIGTERM` from a
/// service manager. The live streams hear it first, so the graceful shutdown
/// does not sit waiting on one long-lived connection per open tab.
async fn shutdown_signal(stop: tokio::sync::watch::Sender<bool>) {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install the Ctrl+C handler");
    };
    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install the SIGTERM handler")
            .recv()
            .await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
    // Streams end on their own; the browser reconnects when we are back.
    let _ = stop.send(true);
}
