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
        location.push_str(&format!("&state={state}"));
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
        return (
            StatusCode::SEE_OTHER,
            [(header::LOCATION, HeaderValue::from_str(&location).unwrap())],
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
        location.push_str(&format!("&state={state}"));
    }
    (
        StatusCode::SEE_OTHER,
        [(header::LOCATION, HeaderValue::from_str(&location).unwrap())],
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
            let Some(consumed) = oidc::consume_auth_code(&app(cx).store, &code).await? else {
                return oidc_error(cx, StatusCode::BAD_REQUEST, "invalid_grant");
            };
            if consumed.client_id != client.client_id
                || consumed.redirect_uri != redirect_uri
                || !oidc::pkce_matches(&consumed.code_challenge, &verifier)
            {
                return oidc_error(cx, StatusCode::BAD_REQUEST, "invalid_grant");
            }
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
            im_core::events::log(
                &app(cx).store,
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
            let Some((fresh, old)) = oidc::rotate_refresh(&app(cx).store, &presented).await? else {
                return oidc_error(cx, StatusCode::BAD_REQUEST, "invalid_grant");
            };
            if old.client_id != client.client_id {
                return oidc_error(cx, StatusCode::BAD_REQUEST, "invalid_grant");
            }
            let Some(user) = im_core::accounts::user_by_id(&app(cx).store, &old.user_id).await?
            else {
                return oidc_error(cx, StatusCode::BAD_REQUEST, "invalid_grant");
            };
            if user.disabled {
                return oidc_error(cx, StatusCode::BAD_REQUEST, "invalid_grant");
            }
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
