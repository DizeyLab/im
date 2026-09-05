//! im-client: drop-in OIDC client for topcoat apps authenticating against im.
//!
//! An app adds three things: `im_client::mount(builder, config)` when it
//! builds its router, `.discover()` as usual (the `/auth/login`,
//! `/auth/callback`, `/auth/logout` routes register themselves), and
//! `im_client::current_user(cx)` wherever it needs the person.
//!
//! The model: im holds the central session; this crate holds the app's side
//! of it — an encrypted cookie holding the opaque session token, introspected
//! against im on every request.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as b64url;
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use time::OffsetDateTime;
use topcoat::context::{Cx, try_app_context};
use topcoat::cookie::{Cookie, Cookies, cookie, cookies};
use topcoat::router::response::{IntoResponse, Response};
use topcoat::router::{HeaderValue, RouterBuilder, StatusCode, header, route};

// ---------------------------------------------------------------------------
// Configuration and state
// ---------------------------------------------------------------------------

/// Everything the app knows about its im registration. `client_secret` and
/// `cookie_key` are secrets: the first authenticates the app to im, the
/// second seals the browser cookies this crate writes.
#[derive(Clone)]
pub struct Config {
    /// im's base URL, e.g. `http://127.0.0.1:7650` or `https://auth.example.com`.
    pub issuer: String,
    pub client_id: String,
    pub client_secret: String,
    /// Must exactly match one of the URIs registered with im.
    pub redirect_uri: String,
    /// The app's session cookie name, e.g. `izlek_session`.
    pub cookie_name: String,
    /// 32 bytes, generated once per app and kept out of the repository.
    pub cookie_key: [u8; 32],
}

/// The registered state: the config, one HTTP client, and the JWKS cache.
pub struct ImClient {
    config: Config,
    http: reqwest::Client,
    jwks: tokio::sync::RwLock<Option<JwksCache>>,
}

struct JwksCache {
    fetched_at: OffsetDateTime,
    /// kid -> public key
    keys: Vec<(String, rsa::RsaPublicKey)>,
}

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

impl ImClient {
    pub fn new(config: Config) -> Self {
        ImClient {
            config,
            http: reqwest::Client::new(),
            jwks: tokio::sync::RwLock::new(None),
        }
    }
}

/// Registers the client state on the router. The routes themselves register
/// through `discover()` — call it as usual.
pub fn mount(builder: RouterBuilder, config: Config) -> RouterBuilder {
    builder.app_context(ImClient::new(config))
}

fn client(cx: &Cx) -> &ImClient {
    try_app_context::<ImClient>(cx).expect("im_client::mount was called on the router")
}

/// The authenticated person, if this browser has one. Every call asks im:
/// the cookie holds an opaque session token, introspected per request, so an
/// admin revoking the person signs them out of this app immediately — there
/// is no token-validity window in which a ghost lives.
pub async fn current_user(cx: &Cx) -> Option<User> {
    let state = client(cx);
    let sealed = cookies(cx).get(&state.config.cookie_name)?;
    let session: Session = open_json(&state.config.cookie_key, sealed.value())?;
    if session.exp <= OffsetDateTime::now_utc().unix_timestamp() {
        clear_cookie(cx, &state.config.cookie_name);
        return None;
    }
    match introspect(state, &session.app_session).await {
        Some((user, _exp)) => Some(user),
        None => {
            clear_cookie(cx, &state.config.cookie_name);
            None
        }
    }
}

/// POSTs the session token to im's `/introspect` with this app's credentials.
/// Network failure reads as signed-out for this request — the cookie stays,
/// so the next request tries again.
async fn introspect(state: &ImClient, token: &str) -> Option<(User, i64)> {
    let answer: serde_json::Value = state
        .http
        .post(format!("{}/introspect", state.config.issuer))
        .form(&[
            ("token", token),
            ("client_id", &state.config.client_id),
            ("client_secret", &state.config.client_secret),
        ])
        .send()
        .await
        .ok()?
        .json()
        .await
        .ok()?;
    if answer["active"] != true {
        return None;
    }
    Some((
        User {
            sub: answer["sub"].as_str()?.to_string(),
            email: answer["email"].as_str()?.to_string(),
            name: answer["name"].as_str()?.to_string(),
            admin: answer["admin"].as_bool().unwrap_or(false),
        },
        answer["exp"].as_i64()?,
    ))
}

/// Who this browser is, from the claims.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub sub: String,
    pub email: String,
    pub name: String,
    #[serde(default)]
    pub admin: bool,
}

// ---------------------------------------------------------------------------
// The app session cookie
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
struct Session {
    /// The opaque token im issued at the code exchange; introspected per
    /// request, never trusted on its own.
    app_session: String,
    exp: i64,
}

/// The in-flight login: PKCE verifier, state, nonce, and where to land after.
#[derive(Serialize, Deserialize)]
struct InFlight {
    verifier: String,
    state: String,
    nonce: String,
    next: String,
    exp: i64,
}

const IN_FLIGHT_MINUTES: i64 = 10;

fn seal(key: &[u8; 32], plaintext: &[u8]) -> String {
    let cipher = XChaCha20Poly1305::new(key.into());
    let mut nonce_bytes = [0u8; 24];
    rand::rng().fill_bytes(&mut nonce_bytes);
    let ciphertext = cipher
        .encrypt(XNonce::from_slice(&nonce_bytes), plaintext)
        .expect("XChaCha20-Poly1305 cannot fail on a payload this small");
    let mut payload = nonce_bytes.to_vec();
    payload.extend_from_slice(&ciphertext);
    b64url.encode(payload)
}

fn open(key: &[u8; 32], sealed: &str) -> Option<Vec<u8>> {
    let payload = b64url.decode(sealed).ok()?;
    if payload.len() < 24 {
        return None;
    }
    let (nonce_bytes, ciphertext) = payload.split_at(24);
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(XNonce::from_slice(nonce_bytes), ciphertext)
        .ok()
}

fn seal_json<T: Serialize>(key: &[u8; 32], value: &T) -> String {
    seal(key, &serde_json::to_vec(value).expect("plain data"))
}

fn open_json<T: for<'de> Deserialize<'de>>(key: &[u8; 32], sealed: &str) -> Option<T> {
    serde_json::from_slice(&open(key, sealed)?).ok()
}

fn app_cookies(cx: &Cx) -> impl Cookies {
    cookies(cx)
        .default_secure(client(cx).config.issuer.starts_with("https://"))
        .default_http_only(true)
        .default_same_site(topcoat::cookie::SameSite::Lax)
        .default_path("/")
}

fn set_session_cookie(cx: &Cx, state: &ImClient, session: &Session) {
    let name = state.config.cookie_name.clone();
    app_cookies(cx).add(cookie! {
        name = seal_json(&state.config.cookie_key, session);
        Path = "/";
        HttpOnly;
        SameSite = Lax;
        MaxAge = time::Duration::days(30)
    });
}

fn clear_cookie(cx: &Cx, name: &str) {
    app_cookies(cx).remove(Cookie::build((name.to_string(), "")).path("/").build());
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

fn see(cx: &Cx, location: &str) -> Result<Response, topcoat::Error> {
    (
        StatusCode::SEE_OTHER,
        [(header::LOCATION, HeaderValue::from_str(location).unwrap())],
    )
        .into_response(cx)
}

/// A `next` worth honoring: a local absolute path, never `//elsewhere`.
fn safe_next(raw: &str) -> &str {
    if raw.starts_with('/') && !raw.starts_with("//") {
        raw
    } else {
        "/"
    }
}

/// A JWKS older than this is refreshed before the next validation.
const JWKS_TTL_SECONDS: i64 = 3600;

async fn jwks_stale(state: &ImClient) -> bool {
    match state.jwks.read().await.as_ref() {
        None => true,
        Some(cache) => {
            cache.fetched_at < OffsetDateTime::now_utc() - time::Duration::seconds(JWKS_TTL_SECONDS)
        }
    }
}

fn query_value(query: &str, key: &str) -> Option<String> {
    query.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        (k == key).then(|| urldecode(v))
    })
}

/// Percent-decodes a query value (`+` is a space, form-style).
fn urldecode(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("");
                match u8::from_str_radix(hex, 16) {
                    Ok(byte) => {
                        out.push(byte);
                        i += 3;
                    }
                    Err(_) => {
                        out.push(b'%');
                        i += 1;
                    }
                }
            }
            byte => {
                out.push(byte);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn random_b64(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    rand::rng().fill_bytes(&mut buf);
    b64url.encode(buf)
}

/// Sends the browser to im's `/authorize` with a fresh PKCE pair.
#[route(GET "/auth/login")]
async fn im_login(cx: &Cx) -> Result<Response, topcoat::Error> {
    let state = client(cx);
    let query = topcoat::router::request::uri(cx)
        .query()
        .unwrap_or("")
        .to_string();
    let next = safe_next(query_value(&query, "next").as_deref().unwrap_or("/")).to_string();

    let flight = InFlight {
        verifier: random_b64(32),
        state: random_b64(16),
        nonce: random_b64(16),
        next,
        exp: OffsetDateTime::now_utc().unix_timestamp() + IN_FLIGHT_MINUTES * 60,
    };
    let challenge = b64url.encode(Sha256::digest(flight.verifier.as_bytes()));
    let cookie_name = format!("{}_pkce", state.config.cookie_name);
    app_cookies(cx).add(cookie! {
        cookie_name = seal_json(&state.config.cookie_key, &flight);
        Path = "/";
        HttpOnly;
        SameSite = Lax;
        MaxAge = time::Duration::minutes(IN_FLIGHT_MINUTES)
    });

    let url = format!(
        "{}/authorize?response_type=code&client_id={}&redirect_uri={}&scope=openid%20profile%20email&state={}&nonce={}&code_challenge={}&code_challenge_method=S256",
        state.config.issuer,
        state.config.client_id,
        urlencoded(&state.config.redirect_uri),
        flight.state,
        flight.nonce,
        challenge,
    );
    see(cx, &url)
}

/// im's answer lands here: exchange the code, validate the id_token, mint
/// the app session.
#[route(GET "/auth/callback")]
async fn im_callback(cx: &Cx) -> Result<Response, topcoat::Error> {
    let state = client(cx);
    let query = topcoat::router::request::uri(cx)
        .query()
        .unwrap_or("")
        .to_string();
    if let Some(error) = query_value(&query, "error") {
        return see(cx, &format!("/?auth_error={error}"));
    }
    let (Some(code), Some(presented_state)) =
        (query_value(&query, "code"), query_value(&query, "state"))
    else {
        return see(cx, "/?auth_error=invalid_request");
    };
    let cookie_name = format!("{}_pkce", state.config.cookie_name);
    let flight: Option<InFlight> = cookies(cx)
        .get(&cookie_name)
        .and_then(|c| open_json(&state.config.cookie_key, c.value()));
    let Some(flight) = flight else {
        return see(cx, "/?auth_error=invalid_request");
    };
    clear_cookie(cx, &cookie_name);
    if flight.exp <= OffsetDateTime::now_utc().unix_timestamp()
        || flight
            .state
            .as_bytes()
            .ct_eq(presented_state.as_bytes())
            .unwrap_u8()
            != 1
    {
        return see(cx, "/?auth_error=invalid_state");
    }

    match exchange_code(state, &code, &flight).await {
        Ok(session) => {
            set_session_cookie(cx, state, &session);
            see(cx, &flight.next)
        }
        Err(_) => see(cx, "/?auth_error=exchange_failed"),
    }
}

/// Signs out of the app only. To end the central session too, post to im's
/// `/logout` — a link there is a silent re-login, by design.
#[route(GET "/auth/logout")]
async fn im_logout(cx: &Cx) -> Result<Response, topcoat::Error> {
    clear_cookie(cx, &client(cx).config.cookie_name);
    see(cx, "/")
}

fn urlencoded(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for byte in raw.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Token exchange, refresh, validation
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct TokenAnswer {
    /// Validated for its nonce and signature; the identity the app serves
    /// comes from introspection, not from these claims.
    id_token: String,
    /// Not OIDC — im's own: the opaque session this crate introspects per
    /// request. Absent means the issuer is not a current im.
    app_session: Option<String>,
}

async fn exchange_code(state: &ImClient, code: &str, flight: &InFlight) -> Result<Session> {
    let answer: TokenAnswer = state
        .http
        .post(format!("{}/token", state.config.issuer))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", &state.config.redirect_uri),
            ("client_id", &state.config.client_id),
            ("client_secret", &state.config.client_secret),
            ("code_verifier", &flight.verifier),
        ])
        .send()
        .await
        .map_err(|e| Error::Http(e.to_string()))?
        .error_for_status()
        .map_err(|e| Error::Refused(e.to_string()))?
        .json()
        .await
        .map_err(|e| Error::Http(e.to_string()))?;
    let claims = validate_id_token(state, &answer.id_token).await?;
    if claims["nonce"].as_str() != Some(flight.nonce.as_str()) {
        return Err(Error::Token("nonce mismatch".into()));
    }
    let app_session = answer
        .app_session
        .ok_or_else(|| Error::Token("issuer gave no app session".into()))?;
    // The session's expiry and identity come from a live introspection, not
    // from the token answer — the same check every later request will make.
    let (_user, exp) = introspect(state, &app_session)
        .await
        .ok_or_else(|| Error::Refused("fresh app session does not introspect".into()))?;
    Ok(Session { app_session, exp })
}

/// Validates an id_token: RS256 against im's JWKS, issuer, audience, expiry.
/// The nonce is the caller's to check (only the callback holds one).
async fn validate_id_token(state: &ImClient, token: &str) -> Result<serde_json::Value> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(Error::Token("not a compact JWT".into()));
    }
    let header: serde_json::Value = serde_json::from_slice(
        &b64url
            .decode(parts[0])
            .map_err(|e| Error::Token(e.to_string()))?,
    )
    .map_err(|e| Error::Token(e.to_string()))?;
    if header["alg"] != "RS256" {
        return Err(Error::Token("unexpected alg".into()));
    }
    let kid = header["kid"]
        .as_str()
        .ok_or_else(|| Error::Token("no kid".into()))?
        .to_string();

    if jwks_stale(state).await {
        refetch_jwks(state).await?;
    }
    let key = match cached_key(state, &kid).await {
        Some(key) => key,
        None => {
            refetch_jwks(state).await?;
            cached_key(state, &kid)
                .await
                .ok_or_else(|| Error::Token("unknown kid after refetch".into()))?
        }
    };

    verify_claims(&parts, &key, &state.config.issuer, &state.config.client_id)
}

/// The pure half of [`validate_id_token`]: signature, issuer, audience,
/// expiry. Split out so the test suite signs its own tokens without standing
/// a server up.
fn verify_claims(
    parts: &[&str],
    key: &rsa::RsaPublicKey,
    issuer: &str,
    client_id: &str,
) -> Result<serde_json::Value> {
    use rsa::signature::Verifier;
    let signature_bytes = b64url
        .decode(parts[2])
        .map_err(|e| Error::Token(e.to_string()))?;
    let signature = rsa::pkcs1v15::Signature::try_from(signature_bytes.as_slice())
        .map_err(|e| Error::Token(e.to_string()))?;
    let verifying = rsa::pkcs1v15::VerifyingKey::<sha2_for_rsa::Sha256>::new(key.clone());
    verifying
        .verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &signature)
        .map_err(|_| Error::Token("bad signature".into()))?;

    let claims: serde_json::Value = serde_json::from_slice(
        &b64url
            .decode(parts[1])
            .map_err(|e| Error::Token(e.to_string()))?,
    )
    .map_err(|e| Error::Token(e.to_string()))?;
    if claims["iss"].as_str() != Some(issuer) {
        return Err(Error::Token("wrong issuer".into()));
    }
    if claims["aud"].as_str() != Some(client_id) {
        return Err(Error::Token("wrong audience".into()));
    }
    match claims["exp"].as_i64() {
        Some(exp) if exp > OffsetDateTime::now_utc().unix_timestamp() => {}
        _ => return Err(Error::Token("expired".into())),
    }
    Ok(claims)
}

async fn cached_key(state: &ImClient, kid: &str) -> Option<rsa::RsaPublicKey> {
    state
        .jwks
        .read()
        .await
        .as_ref()?
        .keys
        .iter()
        .find(|(k, _)| k == kid)
        .map(|(_, key)| key.clone())
}

/// Fetches and caches im's JWKS. Cached for an hour at most; an unknown kid
/// forces an immediate refetch above.
async fn refetch_jwks(state: &ImClient) -> Result<()> {
    let doc: serde_json::Value = state
        .http
        .get(format!("{}/jwks.json", state.config.issuer))
        .send()
        .await
        .map_err(|e| Error::Http(e.to_string()))?
        .error_for_status()
        .map_err(|e| Error::Refused(e.to_string()))?
        .json()
        .await
        .map_err(|e| Error::Http(e.to_string()))?;
    let mut keys = Vec::new();
    for jwk in doc["keys"].as_array().into_iter().flatten() {
        let (Some(kid), Some(n), Some(e)) =
            (jwk["kid"].as_str(), jwk["n"].as_str(), jwk["e"].as_str())
        else {
            continue;
        };
        let (Ok(n), Ok(e)) = (b64url.decode(n), b64url.decode(e)) else {
            continue;
        };
        let key = rsa::RsaPublicKey::new(
            rsa::BigUint::from_bytes_be(&n),
            rsa::BigUint::from_bytes_be(&e),
        )
        .map_err(|err| Error::Token(format!("bad jwk {kid}: {err}")))?;
        keys.push((kid.to_string(), key));
    }
    *state.jwks.write().await = Some(JwksCache {
        fetched_at: OffsetDateTime::now_utc(),
        keys,
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::signature::{SignatureEncoding, Signer};

    fn keypair() -> (rsa::RsaPrivateKey, rsa::RsaPublicKey) {
        // 2048-bit generation is slow for a unit test; 1024 is the smallest
        // rsa 0.9 accepts and the signature math under test is identical.
        let private = rsa::RsaPrivateKey::new(&mut rand_core06::OsRng, 1024).unwrap();
        let public = private.to_public_key();
        (private, public)
    }

    fn sign(claims: serde_json::Value, key: &rsa::RsaPrivateKey) -> String {
        let header = serde_json::json!({"alg": "RS256", "typ": "JWT", "kid": "test"});
        let mut out = b64url.encode(header.to_string());
        out.push('.');
        out.push_str(&b64url.encode(claims.to_string()));
        let signing = rsa::pkcs1v15::SigningKey::<sha2_for_rsa::Sha256>::new(key.clone());
        let signature = signing.sign(out.as_bytes());
        format!("{}.{}", out, b64url.encode(signature.to_bytes()))
    }

    fn good_claims() -> serde_json::Value {
        serde_json::json!({
            "iss": "http://im.test",
            "sub": "user-1",
            "aud": "client-1",
            "exp": OffsetDateTime::now_utc().unix_timestamp() + 600,
            "iat": OffsetDateTime::now_utc().unix_timestamp(),
            "email": "ann@example.com",
            "name": "Ann",
        })
    }

    #[test]
    fn valid_token_validates() {
        let (private, public) = keypair();
        let token = sign(good_claims(), &private);
        let parts: Vec<&str> = token.split('.').collect();
        let claims = verify_claims(&parts, &public, "http://im.test", "client-1").unwrap();
        assert_eq!(claims["sub"], "user-1");
    }

    #[test]
    fn tampered_payload_rejected() {
        let (private, public) = keypair();
        let token = sign(good_claims(), &private);
        let parts: Vec<&str> = token.split('.').collect();
        let forged_payload = b64url.encode(r#"{"sub":"mallory"}"#);
        let forged = vec![parts[0], forged_payload.as_str(), parts[2]];
        assert!(verify_claims(&forged, &public, "http://im.test", "client-1").is_err());
    }

    #[test]
    fn wrong_key_rejected() {
        let (private, _) = keypair();
        let (_, other_public) = keypair();
        let token = sign(good_claims(), &private);
        let parts: Vec<&str> = token.split('.').collect();
        assert!(verify_claims(&parts, &other_public, "http://im.test", "client-1").is_err());
    }

    #[test]
    fn wrong_audience_rejected() {
        let (private, public) = keypair();
        let token = sign(good_claims(), &private);
        let parts: Vec<&str> = token.split('.').collect();
        assert!(verify_claims(&parts, &public, "http://im.test", "another-app").is_err());
    }

    #[test]
    fn wrong_issuer_rejected() {
        let (private, public) = keypair();
        let token = sign(good_claims(), &private);
        let parts: Vec<&str> = token.split('.').collect();
        assert!(verify_claims(&parts, &public, "https://elsewhere.example", "client-1").is_err());
    }

    #[test]
    fn expired_rejected() {
        let (private, public) = keypair();
        let mut claims = good_claims();
        claims["exp"] = (OffsetDateTime::now_utc().unix_timestamp() - 10).into();
        let token = sign(claims, &private);
        let parts: Vec<&str> = token.split('.').collect();
        assert!(verify_claims(&parts, &public, "http://im.test", "client-1").is_err());
    }

    #[test]
    fn pkce_rfc7636_vector() {
        // RFC 7636 Appendix B.
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = b64url.encode(Sha256::digest(verifier.as_bytes()));
        assert_eq!(challenge, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
    }

    #[test]
    fn cookie_seal_roundtrip() {
        let key = [7u8; 32];
        let session = Session {
            app_session: "opaque-token".into(),
            exp: 1,
        };
        let sealed = seal_json(&key, &session);
        let back: Session = open_json(&key, &sealed).unwrap();
        assert_eq!(back.app_session, "opaque-token");
        assert!(open_json::<Session>(&[8u8; 32], &sealed).is_none());
        assert!(open_json::<Session>(&key, "garbage").is_none());
    }
}
