//! The family phonebook: every non-disabled user, answered to registered
//! apps only. A sibling (iz, in) mirrors this into its own member rows, so
//! a person can be assigned or mailed before their first visit. Browsers
//! never see it — the only credential is a client's Basic pair, the same
//! one the photo route takes.

use topcoat::context::Cx;
use topcoat::router::content::Json;
use topcoat::router::response::IntoResponse as _;
use topcoat::router::{StatusCode, route};

use crate::server;

/// One directory entry: exactly what an app needs to provision a member —
/// the stable subject, the address, the display name, and whether im calls
/// them an admin (apps derive their own admin authorization from it, as
/// with `/introspect`).
#[derive(serde::Serialize)]
struct DirectoryMember {
    sub: String,
    email: String,
    name: String,
    admin: bool,
}

/// `GET /directory`: the non-disabled roster as JSON. A wrong or missing
/// client pair is `invalid_client`, the way `/introspect` refuses.
#[route(GET "/directory")]
async fn directory(cx: &Cx) -> topcoat::Result<topcoat::router::response::Response> {
    if !server::valid_app(cx).await {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "invalid_client" })),
        )
            .into_response(cx);
    }
    let store = server::app(cx).store.clone();
    let users = im_core::accounts::list_users(&store).await?;
    let members: Vec<DirectoryMember> = users
        .into_iter()
        .filter(|user| !user.disabled)
        .map(|user| DirectoryMember {
            sub: user.id.to_string(),
            email: user.email,
            name: user.name,
            admin: user.admin,
        })
        .collect();
    Json(serde_json::to_value(members).unwrap()).into_response(cx)
}

/// `GET /family`: the app switcher's list — every service with its wordmark,
/// name, and base URL, in the stored order, as a bare JSON array. Registered
/// apps only, exactly like `/directory`: a sibling copies this into its own
/// database and renders its switcher from that copy, so the family list has
/// one home (this table) and every other surface a cached mirror. The rows
/// come from the panel and from the apps themselves — see
/// `POST /family/register`.
#[route(GET "/family")]
async fn family(cx: &Cx) -> topcoat::Result<topcoat::router::response::Response> {
    if !server::valid_app(cx).await {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "invalid_client" })),
        )
            .into_response(cx);
    }
    let store = server::app(cx).store.clone();
    let services = im_core::services::list(&store).await?;
    Json(serde_json::to_value(services).unwrap()).into_response(cx)
}

/// The body a sibling posts to keep its own row: its wordmark key, the
/// name a fresh row is born with, and the address it answers on now.
#[derive(serde::Deserialize)]
struct Registration {
    key: String,
    name: String,
    url: String,
}

/// `POST /family/register`: an app writes its own row of the family. Same
/// Basic pair as `/family`, and the authenticated client id is the owner —
/// so a row an app keeps is refreshed on its every boot, never taken over
/// by another app (409) and no longer the panel's to remove or re-point.
#[route(POST "/family/register")]
async fn family_register(
    cx: &Cx,
    Json(input): Json<Registration>,
) -> topcoat::Result<topcoat::router::response::Response> {
    let Some(client_id) = server::app_client(cx).await else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "invalid_client" })),
        )
            .into_response(cx);
    };
    let store = server::app(cx).store.clone();
    match im_core::services::register(&store, &input.key, &input.name, &input.url, &client_id).await
    {
        Ok(service) => Json(serde_json::to_value(service).unwrap()).into_response(cx),
        Err(im_core::store::StoreError::Conflict(_)) => (
            StatusCode::CONFLICT,
            Json(serde_json::json!({ "error": "owned" })),
        )
            .into_response(cx),
        Err(im_core::store::StoreError::Invalid(reason)) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "invalid", "reason": reason })),
        )
            .into_response(cx),
        Err(e) => Err(e.into()),
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::sync::Arc;

    use im_core::accounts::{create_invite, create_user_from_invite};
    use im_core::model::ClientId;
    use im_core::oidc::create_client;
    use im_core::store::Store;
    use topcoat::asset::RouterBuilderAssetExt as _;
    use topcoat::cookie::RouterBuilderCookieExt as _;
    use topcoat::router::{
        Body, Router, RouterBuilderDiscoverExt as _, StatusCode, header, to_bytes,
    };

    use crate::config::Config;
    use crate::server::{self, SESSION_COOKIE};

    struct Setup {
        router: Router,
        client_id: String,
        secret: String,
        store: Arc<Store>,
    }

    async fn setup() -> Setup {
        let store = Arc::new(Store::open(Path::new(":memory:")).await.unwrap());
        let (client_id, secret) =
            create_client(&store, "tasks", vec!["http://app/callback".into()])
                .await
                .unwrap();
        let admin_invite = create_invite(&store, "ada@example.com", None, true)
            .await
            .unwrap();
        create_user_from_invite(&store, admin_invite.expose(), "Ada", "tDLr9!mZQ2xv")
            .await
            .unwrap();
        let plain_invite = create_invite(&store, "ben@example.com", None, false)
            .await
            .unwrap();
        create_user_from_invite(&store, plain_invite.expose(), "Ben", "tDLr9!mZQ2xv")
            .await
            .unwrap();
        let gone_invite = create_invite(&store, "gone@example.com", None, false)
            .await
            .unwrap();
        let gone = create_user_from_invite(&store, gone_invite.expose(), "Gone", "tDLr9!mZQ2xv")
            .await
            .unwrap();
        im_core::accounts::set_disabled(&store, &gone.id, true)
            .await
            .unwrap();
        let services = vec![
            crate::config::Service {
                key: "in".into(),
                name: "Files".into(),
                url: "http://127.0.0.1:7655".into(),
            },
            crate::config::Service {
                key: "im".into(),
                name: "Account".into(),
                url: "http://127.0.0.1:7650".into(),
            },
            crate::config::Service {
                key: "iz".into(),
                name: "Board".into(),
                url: "http://127.0.0.1:7654".into(),
            },
        ];
        // The boot's one-time seed: the config's list becomes the table's
        // starting rows, which is what every reader — /family, the trio, the
        // landing card, the logout allowlist — now goes through.
        im_core::services::seed_from(&store, &core_services(&services))
            .await
            .unwrap();
        let (live, _) = tokio::sync::broadcast::channel(64);
        let app = server::App {
            store: store.clone(),
            config: Config {
                database: ":memory:".into(),
                listen: "127.0.0.1:7650".parse().unwrap(),
                issuer: "http://127.0.0.1:7650".into(),
                services,
            },
            live,
        };
        let router = Router::builder()
            .discover()
            .cookies()
            // The pages shell renders its stylesheet link through the asset
            // catalog, so the tests render pages against a real bundle: the
            // one `serve` loads beside the executable where it exists, and
            // otherwise a one-entry bundle folded from the stylesheet
            // build.rs already compiled — a fresh checkout runs `cargo test`
            // before any bundling step, and no test reads the bytes.
            .assets(test_assets())
            .app_context(app)
            .build();
        Setup {
            router,
            client_id: client_id.to_string(),
            secret: secret.expose().to_string(),
            store,
        }
    }

    /// The bundle the router renders against. A dev machine carries the
    /// real one under `target/debug/assets`; on one that never ran the
    /// bundler (CI), a minimal manifest is written beside a copy of the
    /// stylesheet build.rs produced, so page GETs resolve their `<link>`
    /// without any deploy-time step.
    fn test_assets() -> topcoat::asset::AssetBundle {
        // The layout's own declaration: `asset!` folds the declaring source
        // file into the id, so a fresh one here would catalog a different
        // id than any rendered page resolves.
        let style = crate::layout::STYLE;
        let dev = concat!(env!("CARGO_MANIFEST_DIR"), "/../../target/debug/assets");
        if std::path::Path::new(dev).join("manifest.toml").is_file() {
            return topcoat::asset::AssetBundle::load_dir(dev).unwrap();
        }
        // One directory per call: tests run on shared threads, and two
        // setups rewriting one manifest can interleave a half-written file
        // under the other's load.
        static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "im-web-test-assets-{}-{}",
            std::process::id(),
            N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::copy(
            concat!(env!("CARGO_MANIFEST_DIR"), "/assets/main.css"),
            dir.join("main.css"),
        )
        .unwrap();
        topcoat::asset::Manifest {
            version: topcoat::asset::MANIFEST_VERSION,
            assets: vec![topcoat::asset::ManifestEntry {
                id: style.id(),
                file: "main.css".into(),
                hash: "0".repeat(64),
                content_type: "text/css".into(),
            }],
        }
        .save(dir.join("manifest.toml"))
        .unwrap();
        topcoat::asset::AssetBundle::load_dir(&dir).unwrap()
    }

    fn basic(client_id: &str, secret: &str) -> String {
        use base64::Engine as _;
        format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(format!("{client_id}:{secret}"))
        )
    }

    async fn get(router: &Router, authorization: Option<String>) -> (StatusCode, String) {
        let mut builder = http::Request::builder().uri("/directory");
        if let Some(value) = authorization {
            builder = builder.header(header::AUTHORIZATION, value);
        }
        let response = router.handle(builder.body(Body::empty()).unwrap()).await;
        let (parts, body) = response.into_parts();
        let bytes = to_bytes(body, usize::MAX).await.unwrap().to_vec();
        (parts.status, String::from_utf8(bytes).unwrap())
    }

    /// The config's service list as the domain module's own shape — the one
    /// conversion the boot-time seed needs.
    fn core_services(config: &[crate::config::Service]) -> Vec<im_core::services::Service> {
        config
            .iter()
            .map(|service| im_core::services::Service {
                key: service.key.clone(),
                name: service.name.clone(),
                url: service.url.clone(),
                owner: None,
            })
            .collect()
    }

    /// A form post through the router, answered as (status, Location, body).
    async fn post_form(
        router: &Router,
        uri: &str,
        body: &str,
        cookie: Option<&str>,
    ) -> (StatusCode, Option<String>, String) {
        let mut builder = http::Request::builder()
            .method(http::Method::POST)
            .uri(uri)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
        if let Some(cookie) = cookie {
            builder = builder.header(header::COOKIE, cookie);
        }
        let response = router
            .handle(builder.body(Body::from(body.to_string())).unwrap())
            .await;
        let (parts, body) = response.into_parts();
        let location = parts
            .headers
            .get(header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let bytes = to_bytes(body, usize::MAX).await.unwrap().to_vec();
        (parts.status, location, String::from_utf8(bytes).unwrap())
    }

    /// A top-level GET (the RP-initiated logout's shape), same answer triple.
    async fn get_location(
        router: &Router,
        uri: &str,
        cookie: &str,
    ) -> (StatusCode, Option<String>) {
        let response = router
            .handle(
                http::Request::builder()
                    .uri(uri)
                    .header(header::COOKIE, cookie)
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

    /// `GET /family` with an app's Basic pair (or without one).
    async fn get_family(router: &Router, authorization: Option<String>) -> (StatusCode, String) {
        let mut builder = http::Request::builder().uri("/family");
        if let Some(value) = authorization {
            builder = builder.header(header::AUTHORIZATION, value);
        }
        let response = router.handle(builder.body(Body::empty()).unwrap()).await;
        let (parts, body) = response.into_parts();
        let bytes = to_bytes(body, usize::MAX).await.unwrap().to_vec();
        (parts.status, String::from_utf8(bytes).unwrap())
    }

    /// `POST /family/register` with a JSON body and (maybe) an app's pair.
    async fn post_register(
        router: &Router,
        authorization: Option<String>,
        body: serde_json::Value,
    ) -> (StatusCode, serde_json::Value) {
        let mut builder = http::Request::builder()
            .method(http::Method::POST)
            .uri("/family/register")
            .header(header::CONTENT_TYPE, "application/json");
        if let Some(value) = authorization {
            builder = builder.header(header::AUTHORIZATION, value);
        }
        let response = router
            .handle(builder.body(Body::from(body.to_string())).unwrap())
            .await;
        let (parts, body) = response.into_parts();
        let bytes = to_bytes(body, usize::MAX).await.unwrap().to_vec();
        let text = String::from_utf8(bytes).unwrap();
        let json = serde_json::from_str(&text).unwrap_or(serde_json::Value::String(text));
        (parts.status, json)
    }

    /// A page GET as a signed-in browser: the whole document back.
    async fn get_page(router: &Router, uri: &str, cookie: &str) -> String {
        let response = router
            .handle(
                http::Request::builder()
                    .uri(uri)
                    .header(header::COOKIE, cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
        let (_, body) = response.into_parts();
        let bytes = to_bytes(body, usize::MAX).await.unwrap().to_vec();
        String::from_utf8(bytes).unwrap()
    }

    #[tokio::test]
    async fn the_directory_names_every_non_disabled_user_with_its_admin_flag() {
        let Setup {
            router,
            client_id,
            secret,
            ..
        } = setup().await;
        let (status, body) = get(&router, Some(basic(&client_id, &secret))).await;
        assert_eq!(status, StatusCode::OK);
        let members: serde_json::Value = serde_json::from_str(&body).unwrap();
        let members = members.as_array().unwrap();
        assert_eq!(members.len(), 2, "the disabled user must be absent: {body}");
        let ada = members
            .iter()
            .find(|m| m["email"] == "ada@example.com")
            .unwrap();
        assert_eq!(ada["name"], "Ada");
        assert_eq!(ada["admin"], true);
        assert!(!ada["sub"].as_str().unwrap().is_empty());
        let ben = members
            .iter()
            .find(|m| m["email"] == "ben@example.com")
            .unwrap();
        assert_eq!(ben["admin"], false);
    }

    #[tokio::test]
    async fn the_directory_refuses_a_browser_and_an_unknown_client_alike() {
        let Setup {
            router, client_id, ..
        } = setup().await;
        let (status, _) = get(&router, None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let (status, _) = get(&router, Some(basic(&client_id, "wrong"))).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let (status, _) = get(&router, Some(basic("no-such-client", "wrong"))).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn logout_revokes_the_central_session_and_only_returns_known_origins() {
        let Setup {
            router,
            client_id,
            secret,
            store,
        } = setup().await;
        let ada = im_core::accounts::user_by_email(&store, "ada@example.com")
            .await
            .unwrap()
            .unwrap();

        // The RP-initiated exit: `back` naming a stored service's own
        // origin is honored verbatim — the sibling gets its browser back.
        // The allowlist is the seeded table now; the config's copy is only
        // the seed's source.
        let one = im_core::sessions::create_session(&store, &ada.id, &Default::default())
            .await
            .unwrap();
        let (status, location) = get_location(
            &router,
            "/logout?back=http%3A%2F%2F127.0.0.1%3A7655%2F",
            &format!("{SESSION_COOKIE}={}", one.expose()),
        )
        .await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        assert_eq!(location.as_deref(), Some("http://127.0.0.1:7655/"));

        // A live app session bound to a second central session introspects
        // active — until a logout with a foreign `back` lands. The refusal
        // itself goes to the front door, and the revocation still lands:
        // the very next introspection is inactive.
        let two = im_core::sessions::create_session(&store, &ada.id, &Default::default())
            .await
            .unwrap();
        let app_token = im_core::oidc::issue_app_session(
            &store,
            &ada.id,
            &ClientId::from(client_id.clone()),
            &im_core::accounts::hash_token(two.expose()),
        )
        .await
        .unwrap();
        let probe = format!(
            "token={}&client_id={client_id}&client_secret={secret}",
            app_token.expose()
        );
        let (status, _, body) = post_form(&router, "/introspect", &probe, None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&body).unwrap()["active"],
            true
        );

        let (status, location) = get_location(
            &router,
            "/logout?back=https%3A%2F%2Fevil.example%2F",
            &format!("{SESSION_COOKIE}={}", two.expose()),
        )
        .await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        assert_eq!(location.as_deref(), Some("/"));
        let (status, _, body) = post_form(&router, "/introspect", &probe, None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&body).unwrap()["active"],
            false
        );

        // im's own form logout is untouched: front door, no `back` at all.
        let three = im_core::sessions::create_session(&store, &ada.id, &Default::default())
            .await
            .unwrap();
        let (status, location, _) = post_form(
            &router,
            "/logout",
            "",
            Some(&format!("{SESSION_COOKIE}={}", three.expose())),
        )
        .await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        assert_eq!(location.as_deref(), Some("/"));
    }

    #[tokio::test]
    async fn family_serves_the_stored_list_to_registered_apps_only() {
        let Setup {
            router,
            client_id,
            secret,
            ..
        } = setup().await;
        let (status, body) = get_family(&router, None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&body).unwrap()["error"],
            "invalid_client"
        );
        let (status, _) = get_family(&router, Some(basic(&client_id, "wrong"))).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        // The seeded rows, in stored order, as a bare JSON array.
        let (status, body) = get_family(&router, Some(basic(&client_id, &secret))).await;
        assert_eq!(status, StatusCode::OK);
        let family = serde_json::from_str::<serde_json::Value>(&body).unwrap();
        let family = family
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s["key"].as_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(family, vec!["in", "im", "iz"], "{body}");
    }

    #[tokio::test]
    async fn the_panel_edits_the_family_and_every_reader_follows_the_table() {
        let Setup {
            router,
            client_id,
            secret,
            store,
        } = setup().await;
        let ada = im_core::accounts::user_by_email(&store, "ada@example.com")
            .await
            .unwrap()
            .unwrap();
        let ben = im_core::accounts::user_by_email(&store, "ben@example.com")
            .await
            .unwrap()
            .unwrap();

        // A non-admin's post is sent to the front door and writes nothing.
        let ben_session = im_core::sessions::create_session(&store, &ben.id, &Default::default())
            .await
            .unwrap();
        let (status, location, _) = post_form(
            &router,
            "/admin/services_add",
            "key=wiki&name=Wiki&url=http%3A%2F%2F127.0.0.1%3A99",
            Some(&format!("{SESSION_COOKIE}={}", ben_session.expose())),
        )
        .await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        assert_eq!(location.as_deref(), Some("/"));

        // The admin's add lands back on the section, and /family carries
        // the new row at the end — trailing slash stored off, like every URL.
        let session = im_core::sessions::create_session(&store, &ada.id, &Default::default())
            .await
            .unwrap();
        let cookie = format!("{SESSION_COOKIE}={}", session.expose());
        let (status, location, _) = post_form(
            &router,
            "/admin/services_add",
            "key=wiki&name=Wiki&url=http%3A%2F%2F127.0.0.1%3A99%2F",
            Some(&cookie),
        )
        .await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        assert_eq!(
            location.as_deref(),
            Some("/admin?section=services&ok=services")
        );
        let (_, body) = get_family(&router, Some(basic(&client_id, &secret))).await;
        let family = serde_json::from_str::<serde_json::Value>(&body).unwrap();
        let family = family.as_array().unwrap();
        let keys = family
            .iter()
            .map(|s| s["key"].as_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(keys, vec!["in", "im", "iz", "wiki"], "{body}");
        assert_eq!(family[3]["url"], "http://127.0.0.1:99");
        // The forms live on the panel's Services section now.
        let panel = get_page(&router, "/admin?section=services", &cookie).await;
        assert!(panel.contains(r#"action="/admin/services_add""#));
        assert!(panel.contains(r#"action="/admin/services_edit""#));
        // The landing is the read-only directory, admins included.
        assert!(
            !get_page(&router, "/?section=profile", &cookie)
                .await
                .contains(r#"action="/admin/services_add""#)
        );
        // And a non-admin cannot open the section at all — the panel's
        // front-door redirect, like every admin page.
        let (status, location) = get_location(
            &router,
            "/admin?section=services",
            &format!("{SESSION_COOKIE}={}", ben_session.expose()),
        )
        .await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        assert_eq!(location.as_deref(), Some("/"));

        // Edit rewrites name and address; move up swaps with the neighbor.
        let (_status, location, _) = post_form(
            &router,
            "/admin/services_edit",
            "key=wiki&name=Docs&url=http%3A%2F%2F127.0.0.1%3A98",
            Some(&cookie),
        )
        .await;
        assert_eq!(
            location.as_deref(),
            Some("/admin?section=services&ok=services")
        );
        let (_status, location, _) = post_form(
            &router,
            "/admin/services_move",
            "key=wiki&dir=up",
            Some(&cookie),
        )
        .await;
        assert_eq!(
            location.as_deref(),
            Some("/admin?section=services&ok=services")
        );
        let (_, body) = get_family(&router, Some(basic(&client_id, &secret))).await;
        let family = serde_json::from_str::<serde_json::Value>(&body).unwrap();
        let family = family.as_array().unwrap();
        let keys = family
            .iter()
            .map(|s| s["key"].as_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(keys, vec!["in", "im", "wiki", "iz"], "{body}");
        assert_eq!(family[2]["name"], "Docs");
        assert_eq!(family[2]["url"], "http://127.0.0.1:98");

        // The logout allowlist is the table too: the DB-added origin — one
        // no config ever named — gets its browser back.
        let wiki_session = im_core::sessions::create_session(&store, &ada.id, &Default::default())
            .await
            .unwrap();
        let (status, location) = get_location(
            &router,
            "/logout?back=http%3A%2F%2F127.0.0.1%3A98%2F",
            &format!("{SESSION_COOKIE}={}", wiki_session.expose()),
        )
        .await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        assert_eq!(location.as_deref(), Some("http://127.0.0.1:98/"));

        // And once the row is gone, the same origin is refused to the door.
        let (_status, location, _) =
            post_form(&router, "/admin/services_remove", "key=wiki", Some(&cookie)).await;
        assert_eq!(
            location.as_deref(),
            Some("/admin?section=services&ok=services")
        );
        let (_, body) = get_family(&router, Some(basic(&client_id, &secret))).await;
        let family = serde_json::from_str::<serde_json::Value>(&body).unwrap();
        let keys = family
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s["key"].as_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(keys, vec!["in", "im", "iz"], "{body}");
        let gone_session = im_core::sessions::create_session(&store, &ada.id, &Default::default())
            .await
            .unwrap();
        let (_status, location) = get_location(
            &router,
            "/logout?back=http%3A%2F%2F127.0.0.1%3A98%2F",
            &format!("{SESSION_COOKIE}={}", gone_session.expose()),
        )
        .await;
        assert_eq!(location.as_deref(), Some("/"));

        // A value against the rules is the panel's refusal, not a write.
        let bad_session = im_core::sessions::create_session(&store, &ada.id, &Default::default())
            .await
            .unwrap();
        let (_status, location, _) = post_form(
            &router,
            "/admin/services_add",
            "key=Wiki!&name=Wiki&url=http%3A%2F%2F127.0.0.1%3A97",
            Some(&format!("{SESSION_COOKIE}={}", bad_session.expose())),
        )
        .await;
        assert_eq!(
            location.as_deref(),
            Some("/admin?section=services&error=bad_service")
        );
        let (_, body) = get_family(&router, Some(basic(&client_id, &secret))).await;
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&body)
                .unwrap()
                .as_array()
                .unwrap()
                .len(),
            3,
            "{body}"
        );
    }

    #[tokio::test]
    async fn the_seed_fills_an_empty_table_once_and_never_rewrites_it() {
        let Setup {
            router,
            client_id,
            secret,
            store,
        } = setup().await;
        // The setup already seeded; a re-boot's seed must be a no-op, even
        // though `in` is exactly the name the config carries.
        let reseed = vec![im_core::services::Service {
            key: "in".into(),
            name: "Files".into(),
            url: "http://127.0.0.1:7655".into(),
            owner: None,
        }];
        assert!(!im_core::services::seed_from(&store, &reseed).await.unwrap());
        let (_, body) = get_family(&router, Some(basic(&client_id, &secret))).await;
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&body)
                .unwrap()
                .as_array()
                .unwrap()
                .len(),
            3,
            "{body}"
        );
    }

    #[tokio::test]
    async fn an_app_registers_its_own_row_and_only_its_own() {
        let Setup {
            router,
            client_id,
            secret,
            store,
        } = setup().await;

        // No pair, no write.
        let (status, body) = post_register(
            &router,
            None,
            serde_json::json!({"key": "wiki", "name": "Wiki", "url": "http://wiki.example"}),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["error"], "invalid_client");

        // A fresh key is appended, and /family carries it right away.
        let (status, body) = post_register(
            &router,
            Some(basic(&client_id, &secret)),
            serde_json::json!({"key": "wiki", "name": "Wiki", "url": "http://wiki.example/"}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["url"], "http://wiki.example");
        assert!(
            body.get("owner").is_none(),
            "the owner never leaves: {body}"
        );
        let (_, listed) = get_family(&router, Some(basic(&client_id, &secret))).await;
        let listed = serde_json::from_str::<serde_json::Value>(&listed).unwrap();
        let keys = listed
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s["key"].as_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(keys, vec!["in", "im", "iz", "wiki"]);

        // A second app cannot take the key over.
        let (other_id, other_secret) =
            create_client(&store, "other", vec!["http://other/callback".into()])
                .await
                .unwrap();
        let (status, body) = post_register(
            &router,
            Some(basic(&other_id.to_string(), other_secret.expose())),
            serde_json::json!({"key": "wiki", "name": "Mine", "url": "http://evil.example"}),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body["error"], "owned");

        // The keeper's next boot moves the address; the name is the panel's.
        im_core::services::edit(&store, "wiki", "Vikipedi", "http://wiki.example")
            .await
            .unwrap();
        let (status, body) = post_register(
            &router,
            Some(basic(&client_id, &secret)),
            serde_json::json!({"key": "wiki", "name": "Wiki", "url": "http://wiki.dizey.sh"}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["name"], "Vikipedi");
        assert_eq!(body["url"], "http://wiki.dizey.sh");

        // A value against the rules is a 400 with the store's own reason.
        let (status, body) = post_register(
            &router,
            Some(basic(&client_id, &secret)),
            serde_json::json!({"key": "wiki", "name": "Wiki", "url": "ftp://wiki.example"}),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "invalid");
        assert!(body["reason"].as_str().unwrap().contains("http"), "{body}");
    }

    #[tokio::test]
    async fn the_panel_cannot_remove_a_row_its_app_keeps() {
        let Setup {
            router,
            client_id,
            secret,
            store,
        } = setup().await;
        let ada = im_core::accounts::user_by_email(&store, "ada@example.com")
            .await
            .unwrap()
            .unwrap();
        let session = im_core::sessions::create_session(&store, &ada.id, &Default::default())
            .await
            .unwrap();
        let cookie = format!("{SESSION_COOKIE}={}", session.expose());

        // The app claims the seeded `in` row.
        let (status, _) = post_register(
            &router,
            Some(basic(&client_id, &secret)),
            serde_json::json!({"key": "in", "name": "Files", "url": "https://in.dizey.sh"}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        // The panel's remove is refused and the row stays.
        let (_status, location, _) =
            post_form(&router, "/admin/services_remove", "key=in", Some(&cookie)).await;
        assert_eq!(
            location.as_deref(),
            Some("/admin?section=services&error=bad_service")
        );
        // So is a re-point; a rename still lands.
        let (_status, location, _) = post_form(
            &router,
            "/admin/services_edit",
            "key=in&name=Dosyalar&url=http%3A%2F%2Felsewhere.example",
            Some(&cookie),
        )
        .await;
        assert_eq!(
            location.as_deref(),
            Some("/admin?section=services&error=bad_service")
        );
        let (_status, location, _) = post_form(
            &router,
            "/admin/services_edit",
            "key=in&name=Dosyalar&url=https%3A%2F%2Fin.dizey.sh",
            Some(&cookie),
        )
        .await;
        assert_eq!(
            location.as_deref(),
            Some("/admin?section=services&ok=services")
        );
        let (_, body) = get_family(&router, Some(basic(&client_id, &secret))).await;
        let family = serde_json::from_str::<serde_json::Value>(&body).unwrap();
        assert_eq!(family[0]["key"], "in");
        assert_eq!(family[0]["name"], "Dosyalar");
        assert_eq!(family[0]["url"], "https://in.dizey.sh");

        // And the panel offers no remove form for it — the marker instead.
        let panel = get_page(&router, "/admin?section=services", &cookie).await;
        assert!(panel.contains("kept by the app"), "the marker is missing");
        assert!(
            !panel.contains(r#"value="in"><button class="admin-action admin-danger"#),
            "an owned row must carry no remove form"
        );
        // The unowned rows still do.
        assert!(panel.contains(r#"action="/admin/services_remove""#));
    }
    #[tokio::test]
    async fn admin_settings_save_and_echo_the_max_sessions_ceiling() {
        let Setup { router, store, .. } = setup().await;
        let ada = im_core::accounts::user_by_email(&store, "ada@example.com")
            .await
            .unwrap()
            .unwrap();
        let session = im_core::sessions::create_session(&store, &ada.id, &Default::default())
            .await
            .unwrap();
        let cookie = format!("{SESSION_COOKIE}={}", session.expose());

        let (_status, location, _) = post_form(
            &router,
            "/admin/settings",
            "invite_days=30&session_days=7&max_sessions=2&pending_minutes=10&reset_minutes=15&login_attempts_per_hour=20",
            Some(&cookie),
        )
        .await;
        assert_eq!(
            location.as_deref(),
            Some("/admin?section=settings&ok=settings")
        );
        let panel = get_page(&router, "/admin?section=settings", &cookie).await;
        assert!(
            panel.contains(r#"name="max_sessions" min="1" value="2""#),
            "the saved ceiling must echo back into the form: {panel}"
        );
    }

    #[tokio::test]
    async fn the_landing_lists_connected_apps_and_an_empty_note_without_them() {
        let Setup {
            router,
            client_id,
            store,
            ..
        } = setup().await;
        let ben = im_core::accounts::user_by_email(&store, "ben@example.com")
            .await
            .unwrap()
            .unwrap();
        let session = im_core::sessions::create_session(&store, &ben.id, &Default::default())
            .await
            .unwrap();
        let cookie = format!("{SESSION_COOKIE}={}", session.expose());

        // No grants yet: the section is its empty note, with no rows at all.
        let page = get_page(&router, "/?section=apps", &cookie).await;
        assert!(page.contains("Connected apps"), "the title is missing");
        assert!(
            page.contains("No apps are connected yet."),
            "the empty note is missing: {page}"
        );

        // A minted app session is a grant: the seeded app shows under Ben's
        // landing with its name, its client id and its active count.
        im_core::oidc::issue_app_session(
            &store,
            &ben.id,
            &ClientId::from(client_id.clone()),
            &im_core::accounts::hash_token(session.expose()),
        )
        .await
        .unwrap();
        let page = get_page(&router, "/?section=apps", &cookie).await;
        assert!(page.contains("tasks"), "the app's name is missing: {page}");
        assert!(
            page.contains(&client_id),
            "the client id is missing: {page}"
        );
        assert!(
            !page.contains("No apps are connected yet."),
            "the empty note must yield once a grant exists"
        );
    }

    /// Percent-decodes a query value back into text — the tests read the
    /// once-shown confirmation links out of the redirect's Location.
    fn pct_decode(raw: &str) -> String {
        let bytes = raw.as_bytes();
        let mut out = Vec::new();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'%' {
                out.push(
                    u8::from_str_radix(std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap(), 16)
                        .unwrap(),
                );
                i += 3;
            } else {
                out.push(bytes[i]);
                i += 1;
            }
        }
        String::from_utf8(out).unwrap()
    }

    #[tokio::test]
    async fn admin_email_edit_applies_directly_and_refuses_taken_address() {
        let Setup {
            router, store, ..
        } = setup().await;
        let ada = im_core::accounts::user_by_email(&store, "ada@example.com")
            .await
            .unwrap()
            .unwrap();
        let ben = im_core::accounts::user_by_email(&store, "ben@example.com")
            .await
            .unwrap()
            .unwrap();
        let session = im_core::sessions::create_session(&store, &ada.id, &Default::default())
            .await
            .unwrap();
        let cookie = format!("{SESSION_COOKIE}={}", session.expose());

        // A non-admin's edit is sent to the front door and writes nothing.
        let ben_session = im_core::sessions::create_session(&store, &ben.id, &Default::default())
            .await
            .unwrap();
        let (status, location, _) = post_form(
            &router,
            "/admin/user_email",
            &format!("user={}&email=changed%40example.com", ben.id),
            Some(&format!("{SESSION_COOKIE}={}", ben_session.expose())),
        )
        .await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        assert_eq!(location.as_deref(), Some("/"));
        assert!(
            im_core::accounts::user_by_email(&store, "changed@example.com")
                .await
                .unwrap()
                .is_none()
        );

        // The admin's edit lands back on the section with its ok code, the
        // address normalized the way the login path reads it.
        let (status, location, _) = post_form(
            &router,
            "/admin/user_email",
            &format!("user={}&email=%20Ben.New%40Example.COM%20", ben.id),
            Some(&cookie),
        )
        .await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        assert_eq!(
            location.as_deref(),
            Some("/admin?section=users&ok=email_changed")
        );
        let moved = im_core::accounts::user_by_email(&store, "ben.new@example.com")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(moved.id, ben.id);
        assert_eq!(moved.email, "ben.new@example.com");
        assert!(
            im_core::accounts::user_by_email(&store, "ben@example.com")
                .await
                .unwrap()
                .is_none()
        );
        let panel = get_page(&router, "/admin?section=users", &cookie).await;
        assert!(panel.contains("ben.new@example.com"), "{panel}");

        // Another account's address is refused by name; the account's
        // address stays.
        let (status, location, _) = post_form(
            &router,
            "/admin/user_email",
            &format!("user={}&email=ada%40example.com", ben.id),
            Some(&cookie),
        )
        .await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        assert_eq!(
            location.as_deref(),
            Some("/admin?section=users&error=email_taken")
        );
        assert_eq!(
            im_core::accounts::user_by_email(&store, "ben.new@example.com")
                .await
                .unwrap()
                .unwrap()
                .id,
            ben.id
        );
    }

    #[tokio::test]
    async fn self_served_email_change_applies_after_both_addresses_confirm() {
        let Setup {
            router, store, ..
        } = setup().await;
        let ben = im_core::accounts::user_by_email(&store, "ben@example.com")
            .await
            .unwrap()
            .unwrap();
        let session = im_core::sessions::create_session(&store, &ben.id, &Default::default())
            .await
            .unwrap();
        let cookie = format!("{SESSION_COOKIE}={}", session.expose());

        // The ask: with no sender configured, the two confirmation links
        // come back on the redirect once — the crate's unmailed idiom.
        let (status, location, _) = post_form(
            &router,
            "/email_change",
            "email=ben2%40example.com",
            Some(&cookie),
        )
        .await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        let location = location.expect("a redirect carrying the once-shown links");
        assert!(location.contains("ok=email_change_asked"), "{location}");
        let encoded = location
            .split("links=")
            .nth(1)
            .expect("the unmailed pair shows once");
        let tokens: Vec<String> = pct_decode(encoded)
            .split(' ')
            .map(|link| {
                link.rsplit('/')
                    .next()
                    .expect("each link ends in its token")
                    .to_string()
            })
            .collect();
        assert_eq!(tokens.len(), 2);

        // The card names the address being gained, and the POST under it is
        // the only door.
        let card = get_page(&router, &format!("/email/{}", tokens[1]), "").await;
        assert!(card.contains("ben2@example.com"), "{card}");
        assert!(card.contains(r#"action="/email""#), "{card}");

        // The first click marks its side; the address does not move.
        let (status, location, _) = post_form(
            &router,
            "/email",
            &format!("token={}", tokens[1]),
            Some(&cookie),
        )
        .await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        assert_eq!(
            location.as_deref(),
            Some("/?section=profile&ok=email_half_confirmed")
        );
        assert!(
            im_core::accounts::user_by_email(&store, "ben@example.com")
                .await
                .unwrap()
                .is_some()
        );

        // The second mailbox's agreement applies the change.
        let (status, location, _) = post_form(
            &router,
            "/email",
            &format!("token={}", tokens[0]),
            Some(&cookie),
        )
        .await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        assert_eq!(
            location.as_deref(),
            Some("/?section=profile&ok=email_changed")
        );
        let moved = im_core::accounts::user_by_email(&store, "ben2@example.com")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(moved.id, ben.id);
        assert!(
            im_core::accounts::user_by_email(&store, "ben@example.com")
                .await
                .unwrap()
                .is_none()
        );

        // Spent whole: either link answers dead now.
        let (status, location, _) = post_form(
            &router,
            "/email",
            &format!("token={}", tokens[0]),
            Some(&cookie),
        )
        .await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        assert_eq!(
            location.as_deref(),
            Some("/login?error=email_change_invalid")
        );
    }
}
