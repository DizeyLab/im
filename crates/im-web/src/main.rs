//! im — the IzlekLab SSO. Server by default; `invite` and `create-client`
//! are the admin surface until there is a settings screen.

use std::sync::Arc;

use im_core::store::Store;
use topcoat::Result;
use topcoat::asset::RouterBuilderAssetExt;
use topcoat::cookie::RouterBuilderCookieExt;
use topcoat::router::{Router, RouterBuilderDiscoverExt, route};

mod auth;
mod config;
mod layout;
mod oidc;
mod pages;
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
            let Some(email) = args.get(2) else {
                eprintln!("usage: im-web invite <email>");
                std::process::exit(2);
            };
            invite(config, email).await;
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
        Some(other) => {
            eprintln!(
                "im: unknown command {other:?} (expected: invite, create-client, or none to serve)"
            );
            std::process::exit(2);
        }
    }
}

async fn open_store(config: &Config) -> Arc<Store> {
    Arc::new(
        Store::open(&config.database)
            .await
            .expect("failed to open the database"),
    )
}

/// `im-web invite <email>`: creates the invite, mails it when SMTP is
/// configured, prints the link otherwise (dev mode).
async fn invite(config: Config, email: &str) {
    let store = open_store(&config).await;
    let token = im_core::accounts::create_invite(&store, email, None)
        .await
        .expect("failed to create the invite");
    let link = format!("{}/invite/{}", config.issuer, token.expose());
    match build_mailer(&config) {
        Some(mailer) => {
            let message = lettre::Message::builder()
                .from(
                    config
                        .smtp
                        .as_ref()
                        .unwrap()
                        .from
                        .parse()
                        .expect("smtp.from"),
                )
                .to(email.parse().expect("invite email"))
                .subject("You're invited")
                .body(format!(
                    "You've been invited. This link is yours for {} days:\n\n{link}\n",
                    im_core::accounts::INVITE_DAYS
                ))
                .expect("invite mail");
            use lettre::AsyncTransport;
            mailer
                .send(message)
                .await
                .expect("failed to send the invite");
            println!("im      invite mailed to {email}");
        }
        None => println!("im      invite for {email}: {link}"),
    }
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

fn build_mailer(config: &Config) -> Option<lettre::AsyncSmtpTransport<lettre::Tokio1Executor>> {
    let smtp = config.smtp.as_ref()?;
    let creds = lettre::transport::smtp::authentication::Credentials::new(
        smtp.username.clone(),
        smtp.password.clone(),
    );
    Some(
        lettre::AsyncSmtpTransport::<lettre::Tokio1Executor>::relay(&smtp.host)
            .expect("smtp relay")
            .port(smtp.port)
            .credentials(creds)
            .build(),
    )
}

async fn serve(config: Config) {
    for line in config.report() {
        println!("im      {line}");
    }
    let store = open_store(&config).await;
    let app = server::App {
        store,
        config: config.clone(),
    };

    // The bundle beside the executable is the only stylesheet this process
    // can serve — `topcoat asset bundle -p im-web` produces it.
    let bundle = topcoat::asset::AssetBundle::load().unwrap_or_else(|err| {
        eprintln!("im: the asset bundle beside the executable failed to load: {err}");
        eprintln!("im: run `topcoat asset bundle -p im-web` first");
        std::process::exit(2);
    });

    let router = Router::builder()
        .discover()
        .cookies()
        .assets(bundle)
        .app_context(app)
        .build();

    // `topcoat::start` binds HOST/PORT from the environment; the listen
    // address is a config/im.toml decision, so the listener is bound
    // explicitly against the same value the boot log just printed.
    let listener = tokio::net::TcpListener::bind(config.listen)
        .await
        .expect("failed to bind the listen address");
    topcoat::serve_until(listener, router, shutdown_signal())
        .await
        .expect("server error");
}

/// Resolves when the process is asked to stop: Ctrl+C, or `SIGTERM` from a
/// service manager.
async fn shutdown_signal() {
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
}
