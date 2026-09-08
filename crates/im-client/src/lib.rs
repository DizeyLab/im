//! im-client: the app-side SDK for im, in two halves.
//!
//! **The directory SDK** ([`directory`], always compiled): a consumer with
//! its own OIDC client crate takes this and nothing else —
//! [`directory::DirectoryClient`] pulls the roster and the photos and
//! follows [`directory::DirectoryEvent`]s off the live stream, and
//! [`directory::spawn_sync`] keeps a local mirror in step with backoff and
//! resync. Build it with `default-features = false`.
//!
//! **The drop-in OIDC client** (the `oidc` feature, on by default):
//! `im_client::mount(builder, config)` when it builds its router,
//! `.discover()` as usual (the `/auth/login`, `/auth/callback`,
//! `/auth/logout` routes register themselves), and
//! `im_client::current_user(cx)` wherever it needs the person. im holds the
//! central session; this half holds the app's side of it — an encrypted
//! cookie holding the opaque session token, introspected against im on
//! every request.
//!
//! The two halves share the crate's [`Error`]/[`Result`]. The OIDC half's
//! routes register through the grammar's inventory, so a binary that also
//! speaks OIDC through its own client crate must build this crate with
//! `default-features = false`, or the two route sets collide at router
//! build.

pub mod directory;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("http: {0}")]
    Http(String),
    #[error("im refused: {0}")]
    Refused(String),
    #[error("bad token: {0}")]
    Token(String),
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[cfg(feature = "oidc")]
mod oidc;

#[cfg(feature = "oidc")]
pub use oidc::{Config, ImClient, User, current_user, mount};
