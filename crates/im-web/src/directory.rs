//! The family phonebook: every non-disabled user, answered to registered
//! apps only. A sibling (İz, İn) mirrors this into its own member rows, so
//! a person can be assigned or mailed before their first visit. Browsers
//! never see it — the only credential is a client's Basic pair, the same
//! one the photo route takes.

use topcoat::context::Cx;
use topcoat::router::content::Json;
use topcoat::router::{StatusCode, route};
use topcoat::router::response::IntoResponse as _;

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
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({ "error": "invalid_client" })))
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

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::sync::Arc;

    use im_core::accounts::{create_invite, create_user_from_invite};
    use im_core::oidc::create_client;
    use im_core::store::Store;
    use topcoat::cookie::RouterBuilderCookieExt as _;
    use topcoat::router::{Body, Router, RouterBuilderDiscoverExt as _, StatusCode, header, to_bytes};

    use crate::config::Config;
    use crate::server;

    struct Setup {
        router: Router,
        client_id: String,
        secret: String,
    }

    async fn setup() -> Setup {
        let store = Store::open(Path::new(":memory:")).await.unwrap();
        let (client_id, secret) = create_client(&store, "tasks", vec!["http://app/callback".into()])
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
        let (live, _) = tokio::sync::broadcast::channel(64);
        let app = server::App {
            store: Arc::new(store),
            config: Config {
                database: ":memory:".into(),
                listen: "127.0.0.1:7650".parse().unwrap(),
                issuer: "http://127.0.0.1:7650".into(),
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
            client_id: client_id.to_string(),
            secret: secret.expose().to_string(),
        }
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

    #[tokio::test]
    async fn the_directory_names_every_non_disabled_user_with_its_admin_flag() {
        let Setup {
            router,
            client_id,
            secret,
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
            router,
            client_id,
            ..
        } = setup().await;
        let (status, _) = get(&router, None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let (status, _) = get(&router, Some(basic(&client_id, "wrong"))).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let (status, _) = get(&router, Some(basic("no-such-client", "wrong"))).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
}
