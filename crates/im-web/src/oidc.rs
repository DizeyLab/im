//! The OIDC surface: discovery, JWKS, authorize, token, userinfo. The pages
//! are for people; these are for apps — im-client first, any OIDC-speaking
//! client after.

use im_core::model::{ClientId, UserId};
use im_core::oidc;
use serde::Deserialize;
use topcoat::Result;
use topcoat::context::Cx;
use topcoat::router::content::{Form, Json};
use topcoat::router::request::{headers, uri};
use topcoat::router::response::{IntoResponse, Response};
use topcoat::router::{HeaderValue, StatusCode, header, route};

use crate::server::{self, App};

fn app(cx: &Cx) -> &App {
    server::app(cx)
}

/// A JSON OIDC error: `{"error": code}` with the matching status.
fn oidc_error(cx: &Cx, status: StatusCode, code: &str) -> Result<Response> {
    (status, Json(serde_json::json!({ "error": code }))).into_response(cx)
}

#[route(GET "/.well-known/openid-configuration")]
async fn discovery(cx: &Cx) -> Result<Json<serde_json::Value>> {
    let issuer = &app(cx).config.issuer;
    Ok(Json(serde_json::json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{issuer}/authorize"),
        "token_endpoint": format!("{issuer}/token"),
        "userinfo_endpoint": format!("{issuer}/userinfo"),
        "jwks_uri": format!("{issuer}/jwks.json"),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": ["openid", "profile", "email"],
        "claims_supported": ["iss", "sub", "aud", "exp", "iat", "nonce", "email", "name"],
        "code_challenge_methods_supported": ["S256"],
    })))
}

#[route(GET "/jwks.json")]
async fn jwks(cx: &Cx) -> Result<Json<serde_json::Value>> {
    Ok(Json(im_core::keys::jwks(&app(cx).store).await?))
}

// ---------------------------------------------------------------------------
// /authorize
// ---------------------------------------------------------------------------

/// The OIDC error redirect: only ever sent after the client AND the exact
/// redirect_uri have checked out — otherwise the answer is a bare 400, never
// a redirect to an address a stranger supplied.
fn authorize_error(
    cx: &Cx,
    redirect_uri: &str,
    state: Option<&str>,
    error: &str,
) -> Result<Response> {
    let sep = if redirect_uri.contains('?') { '&' } else { '?' };
    let mut location = format!("{redirect_uri}{sep}error={error}");
    if let Some(state) = state {
        // The state is the caller's bytes: encoded as a query pair or it
        // could carry `&`, `=`, or a whole second parameter of its own.
        location.push_str(&format!("&state={}", urlencode(state)));
    }
    (
        StatusCode::SEE_OTHER,
        [(
            header::LOCATION,
            HeaderValue::from_str(&location).unwrap_or_else(|_| HeaderValue::from_static("/")),
        )],
    )
        .into_response(cx)
}

fn bad_request(cx: &Cx) -> Result<Response> {
    (StatusCode::BAD_REQUEST, "invalid request").into_response(cx)
}

/// Percent-encodes a value for a query pair — the `back` a login carries is
/// a local `/authorize?...` URL, full of `?&=` of its own.
pub(crate) fn urlencode(raw: &str) -> String {
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

#[route(GET "/authorize")]
async fn authorize(cx: &Cx) -> Result<Response> {
    let query = uri(cx).query().unwrap_or("").to_string();
    let get = |key: &str| crate::pages::query_value(&query, key);

    // Client identity first: nothing redirects anywhere until both the client
    // and the exact redirect_uri are known-good.
    let Some(client_id) = get("client_id") else {
        return bad_request(cx);
    };
    let Some(client) = oidc::client_by_id(&app(cx).store, &client_id).await? else {
        return bad_request(cx);
    };
    let Some(redirect_uri) = get("redirect_uri") else {
        return bad_request(cx);
    };
    if !client.redirect_uris.contains(&redirect_uri) {
        return bad_request(cx);
    }
    let state = get("state");

    if get("response_type").as_deref() != Some("code") {
        return authorize_error(
            cx,
            &redirect_uri,
            state.as_deref(),
            "unsupported_response_type",
        );
    }
    let scope = get("scope").unwrap_or_default();
    let scopes: Vec<&str> = scope.split(' ').collect();
    if !scopes.contains(&"openid")
        || !scopes
            .iter()
            .all(|s| ["openid", "profile", "email"].contains(s))
    {
        return authorize_error(cx, &redirect_uri, state.as_deref(), "invalid_scope");
    }
    let Some(challenge) = get("code_challenge") else {
        return authorize_error(cx, &redirect_uri, state.as_deref(), "invalid_request");
    };
    if get("code_challenge_method").as_deref() != Some("S256") {
        return authorize_error(cx, &redirect_uri, state.as_deref(), "invalid_request");
    }

    // The central session is the whole point: a browser that already signed
    // in (password and second factor both behind it) gets its code without
    // seeing a form at all.
    let presented = server::presented_session(cx);
    let user = match &presented {
        Some(token) => im_core::sessions::resolve_session(&app(cx).store, token).await?,
        None => None,
    };
    let Some(user) = user else {
        let back = format!("/authorize?{query}");
        let location = format!("/login?back={}", urlencode(&back));
        let location = HeaderValue::from_str(&location)?;
        return (
            StatusCode::SEE_OTHER,
            [(header::LOCATION, location)],
        )
            .into_response(cx);
    };
    let session_hash = im_core::accounts::hash_token(presented.as_deref().unwrap_or_default());
    let code = oidc::create_auth_code(
        &app(cx).store,
        &client.client_id,
        &user.id,
        &redirect_uri,
        get("nonce"),
        &challenge,
        &session_hash,
    )
    .await?;
    let sep = if redirect_uri.contains('?') { '&' } else { '?' };
    let mut location = format!("{redirect_uri}{sep}code={}", code.expose());
    if let Some(state) = state {
        // Same pair discipline as [`authorize_error`]: the caller's state
        // is a value, never raw query syntax.
        location.push_str(&format!("&state={}", urlencode(&state)));
    }
    let location = HeaderValue::from_str(&location)?;
    (
        StatusCode::SEE_OTHER,
        [(header::LOCATION, location)],
    )
        .into_response(cx)
}

// ---------------------------------------------------------------------------
// /token
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct TokenForm {
    grant_type: String,
    code: Option<String>,
    redirect_uri: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
    code_verifier: Option<String>,
    refresh_token: Option<String>,
}

/// Signs the pair of tokens for `user` toward `client`.
async fn mint_tokens(
    cx: &Cx,
    user: &im_core::model::User,
    client_id: &ClientId,
    nonce: Option<String>,
) -> Result<(String, String)> {
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let issuer = &app(cx).config.issuer;
    let (kid, key) = im_core::keys::active_signing_key(&app(cx).store).await?;
    let id_claims = serde_json::json!({
        "iss": issuer,
        "sub": user.id.as_str(),
        "aud": client_id.as_str(),
        "exp": now + oidc::TOKEN_SECONDS,
        "iat": now,
        "email": user.email,
        "name": user.name,
        "nonce": nonce,
    });
    let access_claims = serde_json::json!({
        "iss": issuer,
        "sub": user.id.as_str(),
        "aud": client_id.as_str(),
        "exp": now + oidc::TOKEN_SECONDS,
        "iat": now,
        "scope": "openid profile email",
    });
    Ok((
        oidc::sign_jwt(&access_claims, &kid, &key),
        oidc::sign_jwt(&id_claims, &kid, &key),
    ))
}

fn token_answer(
    cx: &Cx,
    access: String,
    id: String,
    refresh: String,
    app_session: Option<String>,
) -> Result<Response> {
    Json(serde_json::json!({
        "access_token": access,
        "token_type": "Bearer",
        "expires_in": oidc::TOKEN_SECONDS,
        "refresh_token": refresh,
        "id_token": id,
        // Not OIDC — ours: the opaque, introspected session im-client holds.
        // Standard clients ignore it; ours never leaves its ghost window.
        "app_session": app_session,
    }))
    .into_response(cx)
}

#[route(POST "/token")]
async fn exchange(cx: &Cx, Form(input): Form<TokenForm>) -> Result<Response> {
    let Some(client_id) = input.client_id else {
        return oidc_error(cx, StatusCode::BAD_REQUEST, "invalid_request");
    };
    let Some(client) = oidc::client_by_id(&app(cx).store, &client_id).await? else {
        return oidc_error(cx, StatusCode::UNAUTHORIZED, "invalid_client");
    };
    let Some(secret) = input.client_secret else {
        return oidc_error(cx, StatusCode::UNAUTHORIZED, "invalid_client");
    };
    if !oidc::verify_client_secret(&client, &secret) {
        return oidc_error(cx, StatusCode::UNAUTHORIZED, "invalid_client");
    }

    match input.grant_type.as_str() {
        "authorization_code" => {
            let (Some(code), Some(redirect_uri), Some(verifier)) =
                (input.code, input.redirect_uri, input.code_verifier)
            else {
                return oidc_error(cx, StatusCode::BAD_REQUEST, "invalid_request");
            };
            // Judge before spending: the peek says what the code is, and a
            // presentation that fails its client, redirect, or PKCE check
            // leaves the code alive for its rightful holder. `consume` is
            // still the atomic exactly-once act that settles a race.
            let Some(staged) = oidc::peek_auth_code(&app(cx).store, &code).await? else {
                return oidc_error(cx, StatusCode::BAD_REQUEST, "invalid_grant");
            };
            if staged.client_id != client.client_id
                || staged.redirect_uri != redirect_uri
                || !oidc::pkce_matches(&staged.code_challenge, &verifier)
            {
                return oidc_error(cx, StatusCode::BAD_REQUEST, "invalid_grant");
            }
            let Some(consumed) = oidc::consume_auth_code(&app(cx).store, &code).await? else {
                return oidc_error(cx, StatusCode::BAD_REQUEST, "invalid_grant");
            };
            let Some(user) =
                im_core::accounts::user_by_id(&app(cx).store, &consumed.user_id).await?
            else {
                return oidc_error(cx, StatusCode::BAD_REQUEST, "invalid_grant");
            };
            if user.disabled {
                return oidc_error(cx, StatusCode::BAD_REQUEST, "invalid_grant");
            }
            let (access, id) = mint_tokens(cx, &user, &client.client_id, consumed.nonce).await?;
            let refresh = oidc::issue_refresh(
                &app(cx).store,
                &user.id,
                &client.client_id,
                &consumed.session_hash,
            )
            .await?;
            let app_session = oidc::issue_app_session(
                &app(cx).store,
                &user.id,
                &client.client_id,
                &consumed.session_hash,
            )
            .await?;
            server::log_event(
                cx,
                "code_exchanged",
                Some(&user.email),
                Some(&format!("via {}", client.name)),
            )
            .await;
            token_answer(
                cx,
                access,
                id,
                refresh.expose().to_string(),
                Some(app_session.expose().to_string()),
            )
        }
        "refresh_token" => {
            let Some(presented) = input.refresh_token else {
                return oidc_error(cx, StatusCode::BAD_REQUEST, "invalid_request");
            };
            // Ownership before rotation: a token presented by a client it
            // was never issued to is judged by the peek, so a wrong-client
            // presentation cannot burn the rightful holder's chain. The
            // rotate that follows re-checks everything atomically and
            // settles a race between two refreshes of the same client.
            let Some(record) = oidc::peek_refresh(&app(cx).store, &presented).await? else {
                return oidc_error(cx, StatusCode::BAD_REQUEST, "invalid_grant");
            };
            if record.client_id != client.client_id {
                return oidc_error(cx, StatusCode::BAD_REQUEST, "invalid_grant");
            }
            let Some(user) = im_core::accounts::user_by_id(&app(cx).store, &record.user_id).await?
            else {
                return oidc_error(cx, StatusCode::BAD_REQUEST, "invalid_grant");
            };
            if user.disabled {
                return oidc_error(cx, StatusCode::BAD_REQUEST, "invalid_grant");
            }
            let Some((fresh, _)) = oidc::rotate_refresh(&app(cx).store, &presented).await? else {
                return oidc_error(cx, StatusCode::BAD_REQUEST, "invalid_grant");
            };
            let (access, id) = mint_tokens(cx, &user, &client.client_id, None).await?;
            token_answer(cx, access, id, fresh.expose().to_string(), None)
        }
        _ => oidc_error(cx, StatusCode::BAD_REQUEST, "unsupported_grant_type"),
    }
}

// ---------------------------------------------------------------------------
// /introspect (RFC 7662): the per-request liveness check im-client makes
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct IntrospectForm {
    token: String,
    client_id: Option<String>,
    client_secret: Option<String>,
}

/// The app asks, per request: is this session alive, and whose is it? The
/// answer is never cached server-side, so a revoked user is inactive on the
/// very next call.
#[route(POST "/introspect")]
async fn introspect(cx: &Cx, Form(input): Form<IntrospectForm>) -> Result<Response> {
    let (Some(client_id), Some(secret)) = (input.client_id, input.client_secret) else {
        return oidc_error(cx, StatusCode::UNAUTHORIZED, "invalid_client");
    };
    let Some(client) = oidc::client_by_id(&app(cx).store, &client_id).await? else {
        return oidc_error(cx, StatusCode::UNAUTHORIZED, "invalid_client");
    };
    if !oidc::verify_client_secret(&client, &secret) {
        return oidc_error(cx, StatusCode::UNAUTHORIZED, "invalid_client");
    }
    let answer = oidc::introspect_app_session(&app(cx).store, &input.token, &client_id)
        .await?
        .unwrap_or_else(|| serde_json::json!({ "active": false }));
    Json(answer).into_response(cx)
}

// ---------------------------------------------------------------------------
// /userinfo
// ---------------------------------------------------------------------------

#[route(GET "/userinfo")]
async fn userinfo(cx: &Cx) -> Result<Response> {
    let presented = headers(cx)
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(str::to_string);
    let Some(presented) = presented else {
        return (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"))],
        )
            .into_response(cx);
    };
    // Signature and expiry first; the audience is checked against the client
    // registry, not a fixed value — any registered app may ask.
    let Some(claims) = oidc::verify_jwt(&app(cx).store, &presented, None).await? else {
        return oidc_error(cx, StatusCode::UNAUTHORIZED, "invalid_token");
    };
    let Some(aud) = claims["aud"].as_str() else {
        return oidc_error(cx, StatusCode::UNAUTHORIZED, "invalid_token");
    };
    if oidc::client_by_id(&app(cx).store, aud).await?.is_none() {
        return oidc_error(cx, StatusCode::UNAUTHORIZED, "invalid_token");
    }
    let Some(sub) = claims["sub"].as_str() else {
        return oidc_error(cx, StatusCode::UNAUTHORIZED, "invalid_token");
    };
    let Some(user) =
        im_core::accounts::user_by_id(&app(cx).store, &UserId::from(sub.to_string())).await?
    else {
        return oidc_error(cx, StatusCode::UNAUTHORIZED, "invalid_token");
    };
    if user.disabled {
        return oidc_error(cx, StatusCode::UNAUTHORIZED, "invalid_token");
    }
    Json(serde_json::json!({
        "sub": user.id.as_str(),
        "email": user.email,
        "name": user.name,
    }))
    .into_response(cx)
}

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::sync::Arc;

    use topcoat::cookie::RouterBuilderCookieExt as _;
    use topcoat::router::{Body, Router, RouterBuilderDiscoverExt as _, StatusCode, header, to_bytes};
    use im_core::accounts::{create_invite, create_user_from_invite};
    use im_core::oidc::{create_auth_code, create_client, issue_refresh};
    use im_core::sessions::{SessionMeta, create_session};
    use im_core::store::Store;

    use crate::config::Config;
    use crate::server::{self, SESSION_COOKIE};

    /// The RFC 7636 Appendix B pair: `challenge` is `S256(verifier)`.
    const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    struct Setup {
        router: Router,
        store: Arc<Store>,
        // The rightful client, its credential, and what it holds.
        client_id: String,
        secret: String,
        // A second registered client — the attacker's seat.
        other_id: String,
        other_secret: String,
        session_cookie: String,
    }

    async fn setup() -> Setup {
        let store = Store::open(Path::new(":memory:")).await.unwrap();
        let (client_id, secret) =
            create_client(&store, "drive", vec!["http://app/callback".into()])
                .await
                .unwrap();
        let (other_id, other_secret) =
            create_client(&store, "stranger", vec!["http://stranger/cb".into()])
                .await
                .unwrap();
        let invite = create_invite(&store, "ann@example.com", None, false)
            .await
            .unwrap();
        let user = create_user_from_invite(&store, invite.expose(), "Ann", "tDLr9!mZQ2xv")
            .await
            .unwrap();
        let session = create_session(&store, &user.id, &SessionMeta::default())
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
        let router = Router::builder()
            .discover()
            .cookies()
            .app_context(app)
            .build();
        Setup {
            router,
            store,
            client_id: client_id.to_string(),
            secret: secret.expose().to_string(),
            other_id: other_id.to_string(),
            other_secret: other_secret.expose().to_string(),
            session_cookie: format!("{SESSION_COOKIE}={}", session.expose()),
        }
    }

    /// POSTs a token form, answered as (status, body).
    async fn post_token(router: &Router, form: &str) -> (StatusCode, String) {
        let response = router
            .handle(
                http::Request::builder()
                    .method(http::Method::POST)
                    .uri("/token")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(form.to_string()))
                    .unwrap(),
            )
            .await;
        let (parts, body) = response.into_parts();
        let bytes = to_bytes(body, usize::MAX).await.unwrap().to_vec();
        (parts.status, String::from_utf8(bytes).unwrap())
    }

    /// A `/authorize` GET carrying the central session, answered as
    /// (status, Location) — the code handout for the signed-in browser.
    async fn get_authorize(setup: &Setup) -> (StatusCode, Option<String>) {
        let query = format!(
            "response_type=code&client_id={}&redirect_uri=http%3A%2F%2Fapp%2Fcallback\
             &scope=openid&state=st%26ate&code_challenge={}&code_challenge_method=S256",
            setup.client_id, CHALLENGE
        );
        let response = setup
            .router
            .handle(
                http::Request::builder()
                    .uri(format!("/authorize?{query}"))
                    .header(header::COOKIE, &setup.session_cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
        let (parts, _) = response.into_parts();
        let location = parts
            .headers
            .get(header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        (parts.status, location)
    }

    #[tokio::test]
    async fn wrong_client_presentation_leaves_the_refresh_chain_alive() {
        let setup = setup().await;
        let token = issue_refresh(
            &setup.store,
            &announce_user(&setup).await,
            &im_core::model::ClientId::from(setup.client_id.clone()),
            &session_hash(&setup).await,
        )
        .await
        .unwrap();

        // The stranger presents the victim's token: refused — and, the
        // point, nothing burns.
        let form = format!(
            "grant_type=refresh_token&client_id={}&client_secret={}\
             &refresh_token={}",
            setup.other_id,
            setup.other_secret,
            token.expose()
        );
        let (status, body) = post_token(&setup.router, &form).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&body).unwrap()["error"],
            "invalid_grant"
        );

        // The rightful client refreshes with the very same token: the
        // chain stands. (Before the peek-first ordering this burned.)
        let form = format!(
            "grant_type=refresh_token&client_id={}&client_secret={}\
             &refresh_token={}",
            setup.client_id,
            setup.secret,
            token.expose()
        );
        let (status, body) = post_token(&setup.router, &form).await;
        assert_eq!(status, StatusCode::OK);
        let answer: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert!(answer["refresh_token"].as_str().is_some());
    }

    #[tokio::test]
    async fn wrong_client_presentation_leaves_the_code_redeemable() {
        let setup = setup().await;
        let user = announce_user(&setup).await;
        let code = create_auth_code(
            &setup.store,
            &im_core::model::ClientId::from(setup.client_id.clone()),
            &user,
            "http://app/callback",
            None,
            CHALLENGE,
            &session_hash(&setup).await,
        )
        .await
        .unwrap();

        // The stranger presents the victim's code with its redirect and
        // PKCE pair complete: refused without spending it.
        let form = format!(
            "grant_type=authorization_code&client_id={}&client_secret={}\
             &code={}&redirect_uri=http%3A%2F%2Fapp%2Fcallback&code_verifier={}",
            setup.other_id,
            setup.other_secret,
            code.expose(),
            VERIFIER
        );
        let (status, body) = post_token(&setup.router, &form).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&body).unwrap()["error"],
            "invalid_grant"
        );

        // The rightful client exchanges the very same code.
        let form = format!(
            "grant_type=authorization_code&client_id={}&client_secret={}\
             &code={}&redirect_uri=http%3A%2F%2Fapp%2Fcallback&code_verifier={}",
            setup.client_id,
            setup.secret,
            code.expose(),
            VERIFIER
        );
        let (status, body) = post_token(&setup.router, &form).await;
        assert_eq!(status, StatusCode::OK);
        let answer: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert!(answer["access_token"].as_str().is_some());
    }

    #[tokio::test]
    async fn authorize_encodes_the_state_it_hands_back() {
        let setup = setup().await;
        let (status, location) = get_authorize(&setup).await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        let location = location.unwrap();
        assert!(location.starts_with("http://app/callback?code="));
        // The decoded `st&ate` rides back as one pair's value, not two.
        assert!(location.ends_with("&state=st%26ate"), "{location}");
        assert!(!location.contains("&ate="), "{location}");
    }

    /// The signed-in person behind the fixture session.
    async fn announce_user(setup: &Setup) -> im_core::model::UserId {
        im_core::accounts::user_by_email(&setup.store, "ann@example.com")
            .await
            .unwrap()
            .unwrap()
            .id
    }

    /// The fixture session's hash — the binding refresh tokens and codes
    /// carry toward the central session.
    async fn session_hash(setup: &Setup) -> String {
        im_core::accounts::hash_token(
            setup
                .session_cookie
                .strip_prefix(&format!("{SESSION_COOKIE}="))
                .unwrap(),
        )
    }
}
