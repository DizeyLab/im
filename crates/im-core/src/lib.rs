//! im-core: domain model and storage for im, the IzlekLab SSO.
//!
//! `model` is the shared vocabulary (id wrappers, record shapes) and compiles
//! anywhere. Everything that touches a database, a password, a signing key or
//! a CSPRNG lives behind the `server` feature so none of it can ship to a
//! browser bundle — the same contract izlek-core keeps.

#[cfg(feature = "server")]
pub mod accounts;
#[cfg(feature = "server")]
pub mod events;
#[cfg(feature = "server")]
pub mod keys;
#[cfg(feature = "server")]
pub mod oidc;
#[cfg(feature = "server")]
mod secret;
#[cfg(feature = "server")]
pub mod sessions;
#[cfg(feature = "server")]
pub mod settings;
#[cfg(feature = "server")]
pub mod store;
#[cfg(feature = "server")]
pub mod totp;

pub mod model;
