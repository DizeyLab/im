//! `config/im.toml`: read before anything is opened, written with development
//! defaults if it is not there yet — the same contract izlek-core's `Config`
//! keeps. A broken key stops the boot with its name in the message.
//!
//! TOML holds deployment facts only — database, listen, issuer. Secrets an
//! admin rotates (the SMTP password) live sealed in the database under
//! `im.key`, set from the admin panel; nothing in this file is worth
//! stealing, which is what lets it stay in git.

use std::path::{Path, PathBuf};

use serde::Deserialize;

const PATH: &str = "config/im.toml";

const DEFAULTS: &str = r#"database = "im.db"
listen = "127.0.0.1:7650"
issuer = "http://127.0.0.1:7650"
"#;

#[derive(Clone)]
pub struct Config {
    pub database: PathBuf,
    pub listen: std::net::SocketAddr,
    /// The OIDC issuer — the public base URL every endpoint address and every
    /// `iss` claim derives from.
    pub issuer: String,
    pub services: Vec<Service>,
}

/// One sibling app in the switcher and on the landing's services home:
/// the wordmark `key` ("in", "im", "iz" — im's own), a human `name`, and
/// the absolute base `url` without a trailing slash.
#[derive(Clone)]
pub struct Service {
    pub key: String,
    pub name: String,
    pub url: String,
}

#[derive(Deserialize)]
struct RawService {
    key: String,
    name: String,
    url: String,
}

#[derive(Deserialize)]
struct Raw {
    database: Option<String>,
    listen: Option<String>,
    issuer: Option<String>,
    #[serde(default)]
    services: Vec<RawService>,
}

impl Config {
    pub fn load() -> std::result::Result<Config, String> {
        let path = Path::new(PATH);
        if !path.exists() {
            if let Some(dir) = path.parent() {
                std::fs::create_dir_all(dir)
                    .map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
            }
            std::fs::write(path, DEFAULTS).map_err(|e| format!("cannot write {PATH}: {e}"))?;
        }
        let text = std::fs::read_to_string(path).map_err(|e| format!("cannot read {PATH}: {e}"))?;
        let raw: Raw = toml::from_str(&text).map_err(|e| format!("{PATH}: {e}"))?;
        let issuer = raw
            .issuer
            .unwrap_or_else(|| "http://127.0.0.1:7650".to_string());
        if !issuer.starts_with("http://") && !issuer.starts_with("https://") {
            return Err(format!("{PATH}: issuer {issuer:?} must be an http(s) URL"));
        }
        let mut services = Vec::new();
        for service in raw.services {
            if !matches!(service.key.as_str(), "in" | "im" | "iz") {
                return Err(format!(
                    "{PATH}: services: key {:?} must be in, im, or iz",
                    service.key
                ));
            }
            if !service.url.starts_with("http://") && !service.url.starts_with("https://") {
                return Err(format!(
                    "{PATH}: services.{}.url {:?} must be an http(s) URL",
                    service.key, service.url
                ));
            }
            services.push(Service {
                key: service.key,
                name: service.name,
                url: service.url.trim_end_matches('/').to_string(),
            });
        }
        Ok(Config {
            database: PathBuf::from(raw.database.unwrap_or_else(|| "im.db".to_string())),
            listen: raw
                .listen
                .unwrap_or_else(|| "127.0.0.1:7650".to_string())
                .parse()
                .map_err(|e| format!("{PATH}: listen: {e}"))?,
            issuer: issuer.trim_end_matches('/').to_string(),
            services,
        })
    }

    /// Cookies are `Secure` only when the issuer is https — the dev issuer is
    /// plain http, and a Secure cookie over it would never stick.
    pub fn is_secure(&self) -> bool {
        self.issuer.starts_with("https://")
    }

    /// The startup log lines: which file, which address, which issuer.
    pub fn report(&self) -> Vec<String> {
        vec![
            format!("database {}", self.database.display()),
            format!("listen   {}", self.listen),
            format!("issuer   {}", self.issuer),
        ]
    }
}
