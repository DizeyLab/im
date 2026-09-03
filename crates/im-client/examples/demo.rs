//! The smallest topcoat app that signs in through im. Used by the
//! integration smoke test, and the reference for every app that follows.
//!
//! ```sh
//! IM_ISSUER=http://127.0.0.1:7650 \
//! IM_CLIENT_ID=<from im-web create-client> \
//! IM_CLIENT_SECRET=<same> \
//! cargo run -p im-client --example demo
//! ```
//!
//! The cookie key below is a fixed development value so restarts keep
use topcoat::Result;
use topcoat::context::Cx;
use topcoat::cookie::RouterBuilderCookieExt;
use topcoat::router::response::{IntoResponse, Response};
use topcoat::router::{HeaderValue, Router, RouterBuilderDiscoverExt, StatusCode, header, route};

const DEV_COOKIE_KEY: [u8; 32] = [42u8; 32];

#[route(GET "/")]
async fn home(cx: &Cx) -> Result<String> {
    Ok(match im_client::current_user(cx).await {
        Some(user) => format!(
            "signed in as {} <{}>\n/me shows the claims, /auth/logout signs out of this app\n",
            user.name, user.email
        ),
        None => "not signed in\n/auth/login?next=/me to begin\n".to_string(),
    })
}

#[route(GET "/me")]
async fn me(cx: &Cx) -> Result<Response> {
    match im_client::current_user(cx).await {
        Some(user) => {
            topcoat::router::content::Json(serde_json::to_value(user).unwrap()).into_response(cx)
        }
        None => (
            StatusCode::SEE_OTHER,
            [(
                header::LOCATION,
                HeaderValue::from_static("/auth/login?next=/me"),
            )],
        )
            .into_response(cx),
    }
}

#[tokio::main]
async fn main() {
    let config = im_client::Config {
        issuer: std::env::var("IM_ISSUER").unwrap_or("http://127.0.0.1:7650".into()),
        client_id: std::env::var("IM_CLIENT_ID").expect("IM_CLIENT_ID"),
        client_secret: std::env::var("IM_CLIENT_SECRET").expect("IM_CLIENT_SECRET"),
        redirect_uri: "http://127.0.0.1:7656/auth/callback".into(),
        cookie_name: "demo_session".into(),
        cookie_key: DEV_COOKIE_KEY,
    };
    let router = im_client::mount(Router::builder().discover().cookies(), config).build();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:7656")
        .await
        .expect("failed to bind 127.0.0.1:7656");
    println!("demo    listening on http://127.0.0.1:7656");
    topcoat::serve_until(listener, router, std::future::pending())
        .await
        .expect("server error");
}
