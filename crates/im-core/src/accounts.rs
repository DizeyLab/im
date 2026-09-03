//! Accounts: passwords, invites, and the rules around them. Ported from
//! izlek-core's `auth.rs`/`accounts.rs` — same product family, same author.
//!
//! Two different jobs, deliberately kept apart:
//!
//! * **Passwords** are low-entropy and chosen by a person, so they go through
//!   Argon2id with deliberately expensive parameters.
//! * **Tokens** — invites, session cookies, client secrets, auth codes — are
//!   256 bits from a CSPRNG. There is nothing to brute-force, so they are
//!   stored as a plain SHA-256 digest.

use argon2::password_hash::phc::PasswordHash;
use argon2::password_hash::{PasswordHasher, PasswordVerifier};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as base64url;
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use time::OffsetDateTime;

use crate::model::{Invite, User, UserId};
use crate::store::{self, Result, Store, StoreError, backend};

/// Argon2id at the OWASP Password Storage Cheat Sheet's recommended second
/// configuration: 19 MiB of memory, two iterations, one lane.
pub const ARGON2_MEMORY_KIB: u32 = 19 * 1024;
pub const ARGON2_ITERATIONS: u32 = 2;
pub const ARGON2_PARALLELISM: u32 = 1;

/// How many bytes of randomness every token carries.
pub const TOKEN_BYTES: usize = 32;

/// The shortest password this service accepts.
///
/// Named because the form that takes a new password carries it too — as
/// `minlength`, so the browser enforces the rule where it is being broken
/// rather than the server explaining it afterwards. Two places, one number.
pub const MIN_PASSWORD_CHARS: usize = 10;

/// How long an invite stays valid.
pub const INVITE_DAYS: i64 = 7;

/// A password rule the person's choice broke. The wording is the wording on
/// the invite-acceptance screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
pub enum PasswordProblem {
    #[error("at least 10 characters")]
    TooShort,
    #[error("not your address or your name")]
    LooksLikeYou,
    /// The current password given at change time is not the one in force.
    #[error("that's not your current password")]
    WrongCurrent,
    /// The "new" password is the one already in force — the walk-away
    /// mistake, refused by name rather than silently succeeding.
    #[error("that's your current password")]
    IsCurrent,
}

#[derive(Debug, thiserror::Error)]
pub enum AccountError {
    #[error("database: {0}")]
    Backend(String),
    #[error("wrong email or password")]
    InvalidCredentials,
    #[error("this invite is not valid")]
    InviteInvalid,
    /// Unknown, spent or expired — one refusal for all three, so the page
    /// never says which.
    #[error("this reset link is not valid")]
    ResetInvalid,
    #[error("this invite was already used")]
    InviteSpent,
    #[error("this invite has expired")]
    InviteExpired,
    #[error("an account with this address already exists")]
    EmailTaken,
    #[error("password: {0}")]
    Password(#[from] PasswordProblem),
    #[error("password hashing failed: {0}")]
    Hashing(String),
}

impl From<StoreError> for AccountError {
    fn from(e: StoreError) -> Self {
        AccountError::Backend(e.to_string())
    }
}

fn argon2() -> Argon2<'static> {
    let params = Params::new(
        ARGON2_MEMORY_KIB,
        ARGON2_ITERATIONS,
        ARGON2_PARALLELISM,
        None,
    )
    .expect("argon2 parameters are constants and are in range");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

/// Hashes a password into a PHC string, salt included.
pub fn hash_password(password: &str) -> std::result::Result<String, AccountError> {
    argon2()
        .hash_password(password.as_bytes())
        .map(|h| h.to_string())
        .map_err(|e| AccountError::Hashing(e.to_string()))
}

/// Checks a password against a stored PHC string.
///
/// The parameters come from the stored hash, not from [`argon2`], so raising
/// the cost later does not lock anyone out — and hashes migrated from İzlek
/// verify unchanged.
pub fn verify_password(password: &str, phc: &str) -> bool {
    match PasswordHash::new(phc) {
        Ok(parsed) => argon2()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok(),
        Err(_) => false,
    }
}

/// A PHC string for a password nobody knows, used to keep the miss path as
/// expensive as the hit path.
///
/// Without this, "no such address" answers before Argon2 would have finished
/// and the response time tells an attacker what the wording refuses to.
pub fn dummy_password_hash() -> &'static str {
    // Minted once over 256 bits of randomness that was never written down.
    "$argon2id$v=19$m=19456,t=2,p=1$0JjUMrLBpJG7lzg5bxZhMQ$iGpGXBNDAaHV9jqDxDcCyuIEIV33kJ1IAPt0XCh753Q"
}

/// Burns the same work a real verify would, and always fails.
///
/// Call this on every path where a lookup missed, before answering.
pub fn dummy_verify(password: &str) {
    let _ = verify_password(password, dummy_password_hash());
}

/// A freshly minted secret. The plaintext exists only here and in the one
/// place that shows it; the database gets [`Token::hash`].
#[derive(Clone)]
pub struct Token {
    plaintext: String,
}

impl Token {
    /// 256 bits from the thread CSPRNG, base64url-no-pad encoded.
    pub fn mint() -> Self {
        let mut bytes = [0u8; TOKEN_BYTES];
        rand::rng().fill_bytes(&mut bytes);
        Self {
            plaintext: base64url.encode(bytes),
        }
    }

    /// The value that goes in the link or the cookie. Shown exactly once.
    pub fn expose(&self) -> &str {
        &self.plaintext
    }

    /// The value that goes in the database.
    pub fn hash(&self) -> String {
        hash_token(&self.plaintext)
    }
}

impl std::fmt::Debug for Token {
    /// A token must not reach a log through a stray `{:?}`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Token(redacted)")
    }
}

/// SHA-256 of a token, hex encoded. Tokens are full-entropy, so a fast digest
/// is the right primitive here.
pub fn hash_token(plaintext: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(plaintext.as_bytes());
    hex(&hasher.finalize())
}

/// Compares two token digests without leaking where they diverge.
pub fn digests_match(a: &str, b: &str) -> bool {
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// The rules the invite-acceptance screen states, checked server-side.
pub fn check_password(
    password: &str,
    email: &str,
    display_name: &str,
) -> std::result::Result<(), PasswordProblem> {
    // Counted in characters, not bytes: a ten-character password is ten
    // characters whatever alphabet it is in.
    if password.chars().count() < MIN_PASSWORD_CHARS {
        return Err(PasswordProblem::TooShort);
    }

    let folded = password.to_lowercase();
    let local_part = email.split('@').next().unwrap_or(email);
    let mut forbidden = vec![email.to_lowercase(), local_part.to_lowercase()];
    forbidden.extend(
        display_name
            .split_whitespace()
            .map(|word| word.to_lowercase()),
    );
    for needle in forbidden {
        // Short words ("de", "van") would forbid too much to be useful.
        if needle.chars().count() >= 3 && folded.contains(&needle) {
            return Err(PasswordProblem::LooksLikeYou);
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Invites and users
// ---------------------------------------------------------------------------

/// Creates an invite for `email`, returning the raw token to put in the mail.
/// The row holds only its digest.
pub async fn create_invite(
    store: &Store,
    email: &str,
    invited_by: Option<UserId>,
    admin: bool,
) -> std::result::Result<Token, AccountError> {
    // Inviting an address that already has an account is refused here, not
    // at acceptance time — the admin learns immediately, and the account is
    // never shadowed by a pending invite.
    if user_by_email(store, email).await?.is_some() {
        return Err(AccountError::EmailTaken);
    }
    let token = Token::mint();
    let now = store::now();
    // The panel's Settings section owns this number now; the constant is the
    // fresh-database default, not the value.
    let expires = now + time::Duration::days(crate::settings::invite_days(store).await?);
    let conn = store.conn.lock().await;
    conn.execute(
        "INSERT INTO invites (token, email, invited_by, admin, created_at, expires_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        turso::params![
            token.hash(),
            email,
            invited_by.map(|id| id.to_string()),
            admin as i64,
            store::stamp(now)?,
            store::stamp(expires)?,
        ],
    )
    .await
    .map_err(backend)?;
    Ok(token)
}

/// Looks an invite up by its raw token. Expiry and spent-ness are the
/// caller's to rule on — this answers what the row says.
pub async fn invite_by_token(store: &Store, token: &str) -> Result<Option<Invite>> {
    let conn = store.conn.lock().await;
    let mut rows = conn
        .query(
            "SELECT email, invited_by, admin, created_at, expires_at, accepted_at \
             FROM invites WHERE token = ?1",
            turso::params![hash_token(token)],
        )
        .await
        .map_err(backend)?;
    let Some(row) = rows.next().await.map_err(backend)? else {
        return Ok(None);
    };
    Ok(Some(Invite {
        email: store::text(&row, 0)?,
        invited_by: store::opt_text(&row, 1)?.map(UserId::from),
        admin: store::int(&row, 2)? != 0,
        created_at: store::parse_stamp(&store::text(&row, 3)?)?,
        expires_at: store::parse_stamp(&store::text(&row, 4)?)?,
        accepted_at: match store::opt_text(&row, 5)? {
            Some(raw) => Some(store::parse_stamp(&raw)?),
            None => None,
        },
    }))
}

/// An invite still waiting on its person, as the People section lists it.
/// `token_hash` is the row's identity — the digest, never the raw token, so
/// the panel can carry it in a form without a live invite leaking into HTML
/// anyone can view-source.
#[derive(Debug, Clone)]
pub struct PendingInvite {
    pub token_hash: String,
    pub email: String,
    pub admin: bool,
    pub created_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
}

/// Invites not yet accepted and not yet expired, oldest first.
pub async fn list_pending_invites(store: &Store) -> Result<Vec<PendingInvite>> {
    let conn = store.conn.lock().await;
    let mut rows = conn
        .query(
            "SELECT token, email, admin, created_at, expires_at FROM invites \
             WHERE accepted_at IS NULL AND expires_at > ?1 ORDER BY created_at",
            turso::params![store::stamp(store::now())?],
        )
        .await
        .map_err(backend)?;
    let mut pending = Vec::new();
    while let Some(row) = rows.next().await.map_err(backend)? {
        pending.push(PendingInvite {
            token_hash: store::text(&row, 0)?,
            email: store::text(&row, 1)?,
            admin: store::int(&row, 2)? != 0,
            created_at: store::parse_stamp(&store::text(&row, 3)?)?,
            expires_at: store::parse_stamp(&store::text(&row, 4)?)?,
        });
    }
    Ok(pending)
}

/// Invalidates an invite: the row is gone, the link reads "not valid" from
/// that moment on. Returns the address it was made out to, for the log line.
pub async fn revoke_invite(store: &Store, token_hash: &str) -> Result<Option<String>> {
    let conn = store.conn.lock().await;
    let mut rows = conn
        .query(
            "SELECT email FROM invites WHERE token = ?1",
            turso::params![token_hash],
        )
        .await
        .map_err(backend)?;
    let Some(row) = rows.next().await.map_err(backend)? else {
        return Ok(None);
    };
    let email = store::text(&row, 0)?;
    conn.execute(
        "DELETE FROM invites WHERE token = ?1",
        turso::params![token_hash],
    )
    .await
    .map_err(backend)?;
    Ok(Some(email))
}

/// Turns a valid invite into a user. The invite is marked accepted in the
/// same transaction as the user insert, so a token can never mint two
/// accounts.
pub async fn create_user_from_invite(
    store: &Store,
    token: &str,
    name: &str,
    password: &str,
) -> std::result::Result<User, AccountError> {
    let invite = invite_by_token(store, token)
        .await?
        .ok_or(AccountError::InviteInvalid)?;
    if invite.accepted_at.is_some() {
        return Err(AccountError::InviteSpent);
    }
    if invite.expires_at < store::now() {
        return Err(AccountError::InviteExpired);
    }
    check_password(password, &invite.email, name)?;
    let user = User {
        id: UserId::mint(),
        email: invite.email.clone(),
        name: name.to_string(),
        totp_confirmed: false,
        admin: invite.admin,
        disabled: false,
        created_at: store::now(),
    };
    let password_hash = hash_password(password)?;
    // The lock is taken only now — the reads above (`invite_by_token`) lock
    // for themselves, and the transaction holds it alone.
    let conn = store.conn.lock().await;

    conn.execute("BEGIN IMMEDIATE", ()).await.map_err(backend)?;
    let outcome = async {
        conn.execute(
            "INSERT INTO users (id, email, name, password_hash, admin, created_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            turso::params![
                user.id.to_string(),
                user.email.clone(),
                user.name.clone(),
                password_hash,
                user.admin as i64,
                store::stamp(user.created_at)?,
            ],
        )
        .await
        .map_err(|e| {
            let text = e.to_string().to_lowercase();
            if text.contains("constraint") || text.contains("unique") {
                AccountError::EmailTaken
            } else {
                AccountError::Backend(e.to_string())
            }
        })?;
        conn.execute(
            "UPDATE invites SET accepted_at = ?1 WHERE token = ?2 AND accepted_at IS NULL",
            turso::params![store::stamp(store::now())?, hash_token(token)],
        )
        .await
        .map_err(|e| AccountError::Backend(e.to_string()))?;
        Ok::<_, AccountError>(())
    }
    .await;
    match outcome {
        Ok(()) => {
            conn.execute("COMMIT", ()).await.map_err(backend)?;
            Ok(user)
        }
        Err(e) => {
            let _ = conn.execute("ROLLBACK", ()).await;
            Err(e)
        }
    }
}

// ---------------------------------------------------------------------------
// Password reset
// ---------------------------------------------------------------------------

/// Mints a reset link for the account at `email`, retiring every previous
/// live one first: two reset mails means the first is already dead — the
/// newest link is the only door. `None` for an address with no account, so
/// the web layer can answer every address identically.
pub async fn create_reset(
    store: &Store,
    email: &str,
) -> std::result::Result<Option<Token>, AccountError> {
    let Some(user) = user_by_email(store, email).await? else {
        return Ok(None);
    };
    let token = Token::mint();
    let now = store::now();
    let expires = now + time::Duration::minutes(crate::settings::reset_minutes(store).await?);
    let conn = store.conn.lock().await;
    conn.execute(
        "DELETE FROM reset_links WHERE user_id = ?1 AND used_at IS NULL",
        turso::params![user.id.to_string()],
    )
    .await
    .map_err(backend)?;
    conn.execute(
        "INSERT INTO reset_links (token, user_id, created_at, expires_at) \
             VALUES (?1, ?2, ?3, ?4)",
        turso::params![
            token.hash(),
            user.id.to_string(),
            store::stamp(now)?,
            store::stamp(expires)?,
        ],
    )
    .await
    .map_err(backend)?;
    Ok(Some(token))
}

/// Turns a valid reset link into a new password. The link is spent, the hash
/// replaced, and every session revoked in one transaction — the old
/// password's doors close the moment the new one exists.
pub async fn redeem_reset(
    store: &Store,
    token: &str,
    password: &str,
) -> std::result::Result<User, AccountError> {
    let hash = hash_token(token);
    // Short-held read first: the row says whether the link may be redeemed.
    let (user_id, expires_at, used) = {
        let conn = store.conn.lock().await;
        let mut rows = conn
            .query(
                "SELECT user_id, expires_at, used_at FROM reset_links WHERE token = ?1",
                turso::params![hash.clone()],
            )
            .await
            .map_err(backend)?;
        let Some(row) = rows.next().await.map_err(backend)? else {
            return Err(AccountError::ResetInvalid);
        };
        (
            UserId::from(store::text(&row, 0)?),
            store::parse_stamp(&store::text(&row, 1)?)?,
            store::opt_text(&row, 2)?.is_some(),
        )
    };
    if used || expires_at < store::now() {
        return Err(AccountError::ResetInvalid);
    }
    let user = user_by_id(store, &user_id)
        .await?
        .ok_or(AccountError::ResetInvalid)?;
    check_password(password, &user.email, &user.name)?;
    let password_hash = hash_password(password)?;

    // The write half holds the lock across its transaction; revocation comes
    // after COMMIT because `revoke_user_sessions` locks for itself.
    let conn = store.conn.lock().await;
    conn.execute("BEGIN IMMEDIATE", ()).await.map_err(backend)?;
    let outcome = async {
        conn.execute(
            "UPDATE reset_links SET used_at = ?1 WHERE token = ?2 AND used_at IS NULL",
            turso::params![store::stamp(store::now())?, hash],
        )
        .await
        .map_err(|e| AccountError::Backend(e.to_string()))?;
        conn.execute(
            "UPDATE users SET password_hash = ?1 WHERE id = ?2",
            turso::params![password_hash, user.id.to_string()],
        )
        .await
        .map_err(|e| AccountError::Backend(e.to_string()))?;
        Ok::<_, AccountError>(())
    }
    .await;
    match outcome {
        Ok(()) => {
            conn.execute("COMMIT", ()).await.map_err(backend)?;
            drop(conn);
            crate::sessions::revoke_user_sessions(store, &user.id)
                .await
                .map_err(|e| AccountError::Backend(e.to_string()))?;
            // Owning the mailbox is the proof; past failures stop counting.
            clear_login_failures(store, &user.email).await?;
            Ok(user)
        }
        Err(e) => {
            let _ = conn.execute("ROLLBACK", ()).await;
            Err(e)
        }
    }
}

// ---------------------------------------------------------------------------
// Sign-in rate limiting
// ---------------------------------------------------------------------------

/// The counter is a rolling hour of failures per key — the address for
/// passwords, `totp:{user}` for second factors. Reads and writes both sweep
/// their own key's stale rows, so the table never grows without bound.
async fn sweep_attempts(store: &Store, key: &str) -> Result<()> {
    let conn = store.conn.lock().await;
    let cutoff = store::stamp(store::now() - time::Duration::hours(1))?;
    conn.execute(
        "DELETE FROM login_attempts WHERE key = ?1 AND at < ?2",
        turso::params![key, cutoff],
    )
    .await
    .map_err(backend)?;
    Ok(())
}

/// True when the key has burned through the panel's per-hour allowance.
pub async fn login_blocked(store: &Store, key: &str) -> Result<bool> {
    sweep_attempts(store, key).await?;
    let cutoff = store::stamp(store::now() - time::Duration::hours(1))?;
    let count = {
        let conn = store.conn.lock().await;
        let mut rows = conn
            .query(
                "SELECT COUNT(*) FROM login_attempts WHERE key = ?1 AND at >= ?2",
                turso::params![key, cutoff],
            )
            .await
            .map_err(backend)?;
        match rows.next().await.map_err(backend)? {
            Some(row) => store::int(&row, 0)?,
            None => 0,
        }
    };
    // The limit reads settings, which locks for itself — the count's guard is
    // already gone.
    Ok(count >= crate::settings::login_attempts_per_hour(store).await?)
}

/// Writes down a failure. Success is the caller's job to record too — by
/// clearing, with [`clear_login_failures`].
pub async fn record_login_failure(store: &Store, key: &str) -> Result<()> {
    sweep_attempts(store, key).await?;
    let conn = store.conn.lock().await;
    conn.execute(
        "INSERT INTO login_attempts (key, at) VALUES (?1, ?2)",
        turso::params![key, store::stamp(store::now())?],
    )
    .await
    .map_err(backend)?;
    Ok(())
}

/// A success wipes the slate: the next failure starts from zero.
pub async fn clear_login_failures(store: &Store, key: &str) -> Result<()> {
    let conn = store.conn.lock().await;
    conn.execute(
        "DELETE FROM login_attempts WHERE key = ?1",
        turso::params![key],
    )
    .await
    .map_err(backend)?;
    Ok(())
}

/// Whether the reset page may stand: the link exists, unspent, unexpired.
/// Redemption re-checks in its transaction — this is only the page's
/// early answer, so a dead link never shows a working form.
pub async fn reset_link_valid(store: &Store, token: &str) -> Result<bool> {
    let conn = store.conn.lock().await;
    let mut rows = conn
        .query(
            "SELECT expires_at, used_at FROM reset_links WHERE token = ?1",
            turso::params![hash_token(token)],
        )
        .await
        .map_err(backend)?;
    let Some(row) = rows.next().await.map_err(backend)? else {
        return Ok(false);
    };
    let expires_at = store::parse_stamp(&store::text(&row, 0)?)?;
    Ok(store::opt_text(&row, 1)?.is_none() && expires_at >= store::now())
}

/// Verifies an email+password pair, returning the user on success. Disabled
/// accounts are refused with the same wording as a wrong password, and every
/// miss path burns an Argon2 run so timing does not say which one it was.
pub async fn verify_login(
    store: &Store,
    email: &str,
    password: &str,
) -> std::result::Result<User, AccountError> {
    let conn = store.conn.lock().await;
    let mut rows = conn
        .query(
            "SELECT id, email, name, password_hash, totp_confirmed, admin, disabled, created_at \
             FROM users WHERE email = ?1 COLLATE NOCASE",
            turso::params![email],
        )
        .await
        .map_err(backend)?;
    let Some(row) = rows.next().await.map_err(backend)? else {
        dummy_verify(password);
        return Err(AccountError::InvalidCredentials);
    };
    let user = User {
        id: UserId::from(store::text(&row, 0)?),
        email: store::text(&row, 1)?,
        name: store::text(&row, 2)?,
        totp_confirmed: store::int(&row, 4)? != 0,
        admin: store::int(&row, 5)? != 0,
        disabled: store::int(&row, 6)? != 0,
        created_at: store::parse_stamp(&store::text(&row, 7)?)?,
    };
    let phc = store::text(&row, 3)?;
    if !verify_password(password, &phc) || user.disabled {
        return Err(AccountError::InvalidCredentials);
    }
    Ok(user)
}

/// The panel's "change password": proves the current one, enforces the same
/// rules the invite screen does, refuses the walk-away "new = old", then
/// hashes and stores. Sessions are the caller's business — the web layer
/// revokes every session but the one holding the form, so a stolen device
/// loses its access the moment the password moves.
pub async fn change_password(
    store: &Store,
    user: &User,
    current: &str,
    new: &str,
) -> std::result::Result<(), AccountError> {
    let conn = store.conn.lock().await;
    let mut rows = conn
        .query(
            "SELECT password_hash FROM users WHERE id = ?1",
            turso::params![user.id.to_string()],
        )
        .await
        .map_err(backend)?;
    let Some(row) = rows.next().await.map_err(backend)? else {
        return Err(AccountError::InvalidCredentials);
    };
    let phc = store::text(&row, 0)?;
    if !verify_password(current, &phc) {
        return Err(PasswordProblem::WrongCurrent.into());
    }
    check_password(new, &user.email, &user.name)?;
    if verify_password(new, &phc) {
        return Err(PasswordProblem::IsCurrent.into());
    }
    conn.execute(
        "UPDATE users SET password_hash = ?1 WHERE id = ?2",
        turso::params![hash_password(new)?, user.id.to_string()],
    )
    .await
    .map_err(backend)?;
    Ok(())
}

/// Looks a user up by email — the CLI's revoke path resolves names this way.
pub async fn user_by_email(store: &Store, email: &str) -> Result<Option<User>> {
    let id = {
        let conn = store.conn.lock().await;
        let mut rows = conn
            .query(
                "SELECT id FROM users WHERE email = ?1 COLLATE NOCASE",
                turso::params![email],
            )
            .await
            .map_err(backend)?;
        match rows.next().await.map_err(backend)? {
            Some(row) => UserId::from(store::text(&row, 0)?),
            None => return Ok(None),
        }
    };
    // The id is in hand; the full row's lookup locks for itself.
    user_by_id(store, &id).await
}

pub async fn user_by_id(store: &Store, id: &UserId) -> Result<Option<User>> {
    let conn = store.conn.lock().await;
    let mut rows = conn
        .query(
            "SELECT id, email, name, totp_confirmed, admin, disabled, created_at \
             FROM users WHERE id = ?1",
            turso::params![id.to_string()],
        )
        .await
        .map_err(backend)?;
    let Some(row) = rows.next().await.map_err(backend)? else {
        return Ok(None);
    };
    Ok(Some(User {
        id: UserId::from(store::text(&row, 0)?),
        email: store::text(&row, 1)?,
        name: store::text(&row, 2)?,
        totp_confirmed: store::int(&row, 3)? != 0,
        admin: store::int(&row, 4)? != 0,
        disabled: store::int(&row, 5)? != 0,
        created_at: store::parse_stamp(&store::text(&row, 6)?)?,
    }))
}

/// Deletes an account outright: the user row, its sessions, and every app
/// token born of them. Disable is the reversible door; this is for "this
/// account should not exist" — the OIDC subject dies with it, and if the
/// person returns they get a fresh one.
pub async fn delete_user(store: &Store, user: &UserId) -> Result<()> {
    let conn = store.conn.lock().await;
    let id = user.to_string();
    for sql in [
        "DELETE FROM app_sessions WHERE user_id = ?1",
        "DELETE FROM refresh_tokens WHERE user_id = ?1",
        "DELETE FROM sessions WHERE user_id = ?1",
        "UPDATE invites SET invited_by = NULL WHERE invited_by = ?1",
        "DELETE FROM users WHERE id = ?1",
    ] {
        conn.execute(sql, turso::params![id.clone()])
            .await
            .map_err(backend)?;
    }
    Ok(())
}

/// Every user, oldest first — the admin panel's roster.
pub async fn list_users(store: &Store) -> Result<Vec<User>> {
    let conn = store.conn.lock().await;
    let mut rows = conn
        .query(
            "SELECT id, email, name, totp_confirmed, admin, disabled, created_at \
             FROM users ORDER BY created_at",
            (),
        )
        .await
        .map_err(backend)?;
    let mut users = Vec::new();
    while let Some(row) = rows.next().await.map_err(backend)? {
        users.push(User {
            id: UserId::from(store::text(&row, 0)?),
            email: store::text(&row, 1)?,
            name: store::text(&row, 2)?,
            totp_confirmed: store::int(&row, 3)? != 0,
            admin: store::int(&row, 4)? != 0,
            disabled: store::int(&row, 5)? != 0,
            created_at: store::parse_stamp(&store::text(&row, 6)?)?,
        });
    }
    Ok(users)
}

/// Enables or disables an account. A disabled account cannot log in, its
/// sessions resolve to nobody, and introspection says inactive — every door
/// closes on the same flag.
pub async fn set_disabled(store: &Store, user: &UserId, disabled: bool) -> Result<()> {
    let conn = store.conn.lock().await;
    conn.execute(
        "UPDATE users SET disabled = ?1 WHERE id = ?2",
        turso::params![disabled as i64, user.to_string()],
    )
    .await
    .map_err(backend)?;
    Ok(())
}

/// Grants or revokes im's admin flag. Never crosses a token — this is im's
/// own panel, not a claim apps ever see.
pub async fn set_admin(store: &Store, user: &UserId, admin: bool) -> Result<()> {
    let conn = store.conn.lock().await;
    conn.execute(
        "UPDATE users SET admin = ?1 WHERE id = ?2",
        turso::params![admin as i64, user.to_string()],
    )
    .await
    .map_err(backend)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn fixture() -> Store {
        Store::open(Path::new(":memory:")).await.unwrap()
    }

    use std::path::Path;
    #[tokio::test]
    async fn invite_refuses_existing_account_and_admin_toggles() {
        let store = fixture().await;
        let invite = create_invite(&store, "ann@example.com", None, false)
            .await
            .unwrap();
        let user = create_user_from_invite(&store, invite.expose(), "Ann", "tDLr9!mZQ2xv")
            .await
            .unwrap();
        assert!(!user.admin);

        // Inviting an address that already has an account is refused at
        // creation, not at acceptance.
        assert!(matches!(
            create_invite(&store, "ann@example.com", None, false).await,
            Err(AccountError::EmailTaken)
        ));

        set_admin(&store, &user.id, true).await.unwrap();
        let promoted = user_by_id(&store, &user.id).await.unwrap().unwrap();
        assert!(promoted.admin);
        set_admin(&store, &user.id, false).await.unwrap();
        assert!(!user_by_id(&store, &user.id).await.unwrap().unwrap().admin);
    }

    #[test]
    fn password_roundtrip() {
        let phc = hash_password("correct horse battery staple").unwrap();
        assert!(verify_password("correct horse battery staple", &phc));
        assert!(!verify_password("wrong horse battery staple", &phc));
    }

    #[test]
    fn password_rules() {
        assert_eq!(
            check_password("short", "a@b.c", "Ann"),
            Err(PasswordProblem::TooShort)
        );
        assert_eq!(
            check_password("ann.smith-99", "ann.smith@x.y", "Ann Smith"),
            Err(PasswordProblem::LooksLikeYou)
        );
        assert!(check_password("tDLr9!mZQ2xv", "ann.smith@x.y", "Ann Smith").is_ok());
    }

    #[test]
    fn token_hash_is_not_the_token() {
        let token = Token::mint();
        assert_ne!(token.expose(), token.hash());
        assert_eq!(token.hash().len(), 64, "sha256 hex");
    }

    #[tokio::test]
    async fn invite_to_user_to_login() {
        let store = fixture().await;
        let token = create_invite(&store, "ann@example.com", None, false)
            .await
            .unwrap();
        let invite = invite_by_token(&store, token.expose())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(invite.email, "ann@example.com");
        assert!(invite.accepted_at.is_none());

        let user = create_user_from_invite(&store, token.expose(), "Ann", "tDLr9!mZQ2xv")
            .await
            .unwrap();
        assert_eq!(user.email, "ann@example.com");

        // The invite is spent: a second use is refused.
        assert!(matches!(
            create_user_from_invite(&store, token.expose(), "Ann", "tDLr9!mZQ2xv").await,
            Err(AccountError::InviteSpent)
        ));

        let logged = verify_login(&store, "ANN@example.com", "tDLr9!mZQ2xv")
            .await
            .unwrap();
        assert_eq!(logged.id, user.id);
        assert!(matches!(
            verify_login(&store, "ann@example.com", "wrong-password").await,
            Err(AccountError::InvalidCredentials)
        ));
        assert!(matches!(
            verify_login(&store, "nobody@example.com", "tDLr9!mZQ2xv").await,
            Err(AccountError::InvalidCredentials)
        ));
    }

    #[tokio::test]
    async fn change_password_proves_current_and_applies_rules() {
        let store = fixture().await;
        let invite = create_invite(&store, "ann@example.com", None, false)
            .await
            .unwrap();
        let user = create_user_from_invite(&store, invite.expose(), "Ann", "tDLr9!mZQ2xv")
            .await
            .unwrap();

        // Wrong current password is refused by name.
        assert!(matches!(
            change_password(&store, &user, "not-the-password", "Xk9#mQ2vLpR7").await,
            Err(AccountError::Password(PasswordProblem::WrongCurrent))
        ));
        // The rules the invite screen enforces apply here too.
        assert!(matches!(
            change_password(&store, &user, "tDLr9!mZQ2xv", "short").await,
            Err(AccountError::Password(PasswordProblem::TooShort))
        ));
        // New = old is the walk-away mistake, refused.
        assert!(matches!(
            change_password(&store, &user, "tDLr9!mZQ2xv", "tDLr9!mZQ2xv").await,
            Err(AccountError::Password(PasswordProblem::IsCurrent))
        ));

        change_password(&store, &user, "tDLr9!mZQ2xv", "Xk9#mQ2vLpR7")
            .await
            .unwrap();
        assert!(
            verify_login(&store, "ann@example.com", "Xk9#mQ2vLpR7")
                .await
                .is_ok()
        );
        assert!(
            verify_login(&store, "ann@example.com", "tDLr9!mZQ2xv")
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn duplicate_email_is_refused() {
        let store = fixture().await;
        let first = create_invite(&store, "ann@example.com", None, false)
            .await
            .unwrap();
        create_user_from_invite(&store, first.expose(), "Ann", "tDLr9!mZQ2xv")
            .await
            .unwrap();
        // The second invite never exists: the refusal moved from acceptance
        // time to creation time.
        assert!(matches!(
            create_invite(&store, "ann@example.com", None, false).await,
            Err(AccountError::EmailTaken)
        ));
    }

    #[tokio::test]
    async fn pending_invites_list_and_revoke() {
        let store = fixture().await;
        let token = create_invite(&store, "bob@example.com", None, true)
            .await
            .unwrap();

        let pending = list_pending_invites(&store).await.unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].email, "bob@example.com");
        assert!(pending[0].admin);

        let email = revoke_invite(&store, &pending[0].token_hash).await.unwrap();
        assert_eq!(email.as_deref(), Some("bob@example.com"));
        assert!(list_pending_invites(&store).await.unwrap().is_empty());
        // The link is dead: the token resolves to nothing.
        assert!(
            invite_by_token(&store, token.expose())
                .await
                .unwrap()
                .is_none()
        );
        // Revoking the same invite twice is a quiet no-op.
        assert!(
            revoke_invite(&store, &pending[0].token_hash)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn delete_user_takes_sessions_with_it() {
        let store = fixture().await;
        let invite = create_invite(&store, "ann@example.com", None, false)
            .await
            .unwrap();
        let user = create_user_from_invite(&store, invite.expose(), "Ann", "tDLr9!mZQ2xv")
            .await
            .unwrap();
        let session = crate::sessions::create_session(&store, &user.id)
            .await
            .unwrap();

        delete_user(&store, &user.id).await.unwrap();
        assert!(user_by_id(&store, &user.id).await.unwrap().is_none());
        assert!(
            crate::sessions::resolve_session(&store, session.expose())
                .await
                .unwrap()
                .is_none()
        );
        // The address is free again: a fresh invite can be made for it.
        assert!(
            create_invite(&store, "ann@example.com", None, false)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn a_second_reset_link_kills_the_first() {
        let store = fixture().await;
        let invite = create_invite(&store, "ann@example.com", None, false)
            .await
            .unwrap();
        let user = create_user_from_invite(&store, invite.expose(), "Ann", "tDLr9!mZQ2xv")
            .await
            .unwrap();
        let session = crate::sessions::create_session(&store, &user.id)
            .await
            .unwrap();

        // No account, no link — and nothing learned.
        assert!(
            create_reset(&store, "nobody@example.com")
                .await
                .unwrap()
                .is_none()
        );

        let first = create_reset(&store, "ann@example.com")
            .await
            .unwrap()
            .unwrap();
        let second = create_reset(&store, "ann@example.com")
            .await
            .unwrap()
            .unwrap();
        // The first mail's link died the moment the second was minted.
        assert!(matches!(
            redeem_reset(&store, first.expose(), "Xk9#mQ2vLpR7").await,
            Err(AccountError::ResetInvalid)
        ));

        let changed = redeem_reset(&store, second.expose(), "Xk9#mQ2vLpR7")
            .await
            .unwrap();
        assert_eq!(changed.id, user.id);
        // Spent links cannot be replayed, and the old password's sessions
        // died with the change.
        assert!(matches!(
            redeem_reset(&store, second.expose(), "an0ther!Pass99").await,
            Err(AccountError::ResetInvalid)
        ));
        assert!(
            crate::sessions::resolve_session(&store, session.expose())
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            verify_login(&store, "ann@example.com", "Xk9#mQ2vLpR7")
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn rate_limit_blocks_and_success_clears() {
        let store = fixture().await;
        crate::settings::set_policy(
            &store,
            &crate::settings::Policy {
                login_attempts_per_hour: 3,
                ..Default::default()
            },
        )
        .await
        .unwrap();

        assert!(!login_blocked(&store, "ann@example.com").await.unwrap());
        for _ in 0..3 {
            record_login_failure(&store, "ann@example.com")
                .await
                .unwrap();
        }
        assert!(login_blocked(&store, "ann@example.com").await.unwrap());
        // A different address is untouched.
        assert!(!login_blocked(&store, "bob@example.com").await.unwrap());

        clear_login_failures(&store, "ann@example.com")
            .await
            .unwrap();
        assert!(!login_blocked(&store, "ann@example.com").await.unwrap());
    }
}
