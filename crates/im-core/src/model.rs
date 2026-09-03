//! Record shapes shared by every im crate.
//!
//! No crypto, no database, no CSPRNG here: this module compiles anywhere,
//! including a browser bundle. Id wrappers are plain newtypes; minting lives
//! behind the `server` feature where `ulid` is available.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

macro_rules! id_wrapper {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(pub String);

        impl $name {
            /// A fresh ULID — sortable, URL-safe, unguessable enough for an id.
            #[cfg(feature = "server")]
            pub fn mint() -> Self {
                Self(ulid::Ulid::new().to_string())
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl From<String> for $name {
            fn from(raw: String) -> Self {
                Self(raw)
            }
        }
    };
}

id_wrapper!(UserId, "A user's id — the OIDC `sub` claim.");
id_wrapper!(ClientId, "An OIDC client's id.");

/// A registered user. `password_hash` and the TOTP material never leave
/// `accounts`/`totp` — this shape is what the rest of the system sees.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: UserId,
    pub email: String,
    pub name: String,
    pub totp_confirmed: bool,
    /// im's own admin flag — never crosses a token; AuthN stays the only
    /// thing apps receive.
    pub admin: bool,
    pub disabled: bool,
    pub created_at: OffsetDateTime,
}

/// An outstanding (or spent) invite, as stored. The raw token exists only in
/// the mail that carried it; the row holds its digest.
#[derive(Debug, Clone)]
pub struct Invite {
    pub email: String,
    pub invited_by: Option<UserId>,
    /// An admin invite mints an admin.
    pub admin: bool,
    pub created_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
    pub accepted_at: Option<OffsetDateTime>,
}

/// An OIDC relying party registered with im.
#[derive(Debug, Clone)]
pub struct OidcClient {
    pub client_id: ClientId,
    pub name: String,
    pub secret_hash: String,
    pub redirect_uris: Vec<String>,
    pub created_at: OffsetDateTime,
}

/// An authorization code mid-exchange. Consumed exactly once.
#[derive(Debug, Clone)]
pub struct AuthCode {
    pub client_id: ClientId,
    pub user_id: UserId,
    pub redirect_uri: String,
    pub nonce: Option<String>,
    pub code_challenge: String,
    /// The central session that minted this code — the refresh token issued
    /// off it binds to the same session, so logout kills the chain.
    pub session_hash: String,
    pub expires_at: OffsetDateTime,
}

/// A refresh token row, post-lookup.
#[derive(Debug, Clone)]
pub struct RefreshToken {
    pub user_id: UserId,
    pub client_id: ClientId,
    pub session_hash: String,
    pub expires_at: OffsetDateTime,
}
