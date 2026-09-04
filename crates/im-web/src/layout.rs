//! The document shell every im page renders through. No hydration, no
//! runtime script: pages are plain HTML forms, posted hard.

use topcoat::Result;
use topcoat::asset::{Asset, asset};
use topcoat::context::Cx;
use topcoat::view::view;

/// `style/main.scss`, compiled by `build.rs` into `assets/main.css`.
const STYLE: Asset = asset!("assets/main.css");

/// The mark, in the word as it is in the name: lower case, the Turkish
/// tittle. Text-only here — the auth card is the whole chrome.
pub async fn wordmark(cx: &Cx) -> Result {
    view! {
        cx =>
        <span class="wordmark">
            <span class="wordmark-text">"im"</span>
        </span>
    }
}

/// The profile card's face: the photo when the account has one, the name's
/// first letter on a quiet tile when it does not. The URL's stamp comes from
/// `photo::PhotoStamps`, so a changed photo is a changed URL.
pub async fn avatar(cx: &Cx, user: &im_core::model::User) -> Result {
    if user.has_photo {
        let src = format!(
            "/photo/{}?v={}",
            user.id,
            crate::photo::photo_stamp(cx, &user.id.to_string())
        );
        view! {
            cx =>
            <img class="profile-avatar" src=(src) alt=(user.name.clone())>
        }
    } else {
        let initial = user
            .name
            .chars()
            .next()
            .unwrap_or('?')
            .to_uppercase()
            .to_string();
        view! {
            cx =>
            <span class="profile-avatar profile-avatar-initial">(initial)</span>
        }
    }
}

/// A full document around an already-rendered stage — the same way
/// izlek-web's `#[layout]` receives its slot.
pub async fn shell(cx: &Cx, title: &str, stage: Result) -> Result {
    let stage = stage?;
    view! {
        cx =>
        <!DOCTYPE html>
        <html lang="en">
            <head>
                <meta charset="utf-8">
                <meta name="viewport" content="width=device-width, initial-scale=1">
                <link rel="preconnect" href="https://fonts.googleapis.com">
                <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin="">
                <link
                    rel="stylesheet"
                    href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500&display=swap"
                >
                <title>(title)</title>
                <link rel="stylesheet" href=(STYLE)>
            </head>
            <body>
                (stage)
            </body>
        </html>
    }
}
