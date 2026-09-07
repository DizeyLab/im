//! The family phonebook: every non-disabled user, answered to registered
//! apps only. A sibling (İz, İn) mirrors this into its own member rows, so
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
/// one home (the admin panel here) and every other surface a cached mirror.
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
            "/services/add",
            "key=wiki&name=Wiki&url=http%3A%2F%2F127.0.0.1%3A99",
            Some(&format!("{SESSION_COOKIE}={}", ben_session.expose())),
        )
        .await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        assert_eq!(location.as_deref(), Some("/"));

        // The admin's add lands back on the card, and /family carries the
        // new row at the end — trailing slash stored off, like every URL.
        let session = im_core::sessions::create_session(&store, &ada.id, &Default::default())
            .await
            .unwrap();
        let cookie = format!("{SESSION_COOKIE}={}", session.expose());
        let (status, location, _) = post_form(
            &router,
            "/services/add",
            "key=wiki&name=Wiki&url=http%3A%2F%2F127.0.0.1%3A99%2F",
            Some(&cookie),
        )
        .await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        assert_eq!(location.as_deref(), Some("/?ok=services"));
        let (_, body) = get_family(&router, Some(basic(&client_id, &secret))).await;
        let family = serde_json::from_str::<serde_json::Value>(&body).unwrap();
        let family = family.as_array().unwrap();
        let keys = family
            .iter()
            .map(|s| s["key"].as_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(keys, vec!["in", "im", "iz", "wiki"], "{body}");
        assert_eq!(family[3]["url"], "http://127.0.0.1:99");
        assert!(
            get_page(&router, "/?section=profile", &cookie)
                .await
                .contains(r#"action="/services/add""#)
        );
        assert!(
            !get_page(
                &router,
                "/?section=profile",
                &format!("{SESSION_COOKIE}={}", ben_session.expose())
            )
            .await
            .contains(r#"action="/services/add""#)
        );

        // Edit rewrites name and address; move up swaps with the neighbor.
        let (_status, location, _) = post_form(
            &router,
            "/services/edit",
            "key=wiki&name=Docs&url=http%3A%2F%2F127.0.0.1%3A98",
            Some(&cookie),
        )
        .await;
        assert_eq!(location.as_deref(), Some("/?ok=services"));
        let (_status, location, _) =
            post_form(&router, "/services/move", "key=wiki&dir=up", Some(&cookie)).await;
        assert_eq!(location.as_deref(), Some("/?ok=services"));
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
            post_form(&router, "/services/remove", "key=wiki", Some(&cookie)).await;
        assert_eq!(location.as_deref(), Some("/?ok=services"));
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

        // A value against the rules is the card's refusal, not a write.
        let bad_session = im_core::sessions::create_session(&store, &ada.id, &Default::default())
            .await
            .unwrap();
        let (_status, location, _) = post_form(
            &router,
            "/services/add",
            "key=Wiki!&name=Wiki&url=http%3A%2F%2F127.0.0.1%3A97",
            Some(&format!("{SESSION_COOKIE}={}", bad_session.expose())),
        )
        .await;
        assert_eq!(location.as_deref(), Some("/?error=bad_service"));
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
}
