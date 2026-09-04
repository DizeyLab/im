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

/// The one script im serves, and the only behavior it carries: the avatar
/// overlay and the picker's autosubmit. A click on a photo `.avatar-view`
/// opens a `.viewer-scrim` around the same `/photo/{id}?v=` URL the avatar
/// reads — the overlay has no server state behind it, so it is client-built
/// and client-closed (scrim click or Escape). A `data-autosubmit` input
/// posts its form on change: choosing a file IS the upload, no Save button.
/// Both are delegated document listeners, so the hard-post re-render never
/// needs rewiring. Emitted by the landing and the person page — every
/// surface that draws a clickable face.
pub async fn avatar_script(cx: &Cx) -> Result {
    use topcoat::view::Unescaped;
    const JS: &str = "\
        (function () { \
            if (window.__imAvatar) { return; } \
            window.__imAvatar = true; \
            document.addEventListener('click', function (e) { \
                var view = e.target.closest ? e.target.closest('.avatar-view') : null; \
                if (view) { \
                    var img = view.querySelector('img.profile-avatar'); \
                    if (!img || document.querySelector('.viewer-scrim')) { return; } \
                    var scrim = document.createElement('div'); \
                    scrim.className = 'viewer-scrim'; \
                    var media = document.createElement('img'); \
                    media.className = 'viewer-media'; \
                    media.src = img.src; \
                    media.alt = img.alt; \
                    var box = document.createElement('div'); \
                    box.className = 'viewer'; \
                    box.tabIndex = -1; \
                    box.appendChild(media); \
                    scrim.appendChild(box); \
                    document.body.appendChild(scrim); \
                    box.focus(); \
                    return; \
                } \
                if (e.target.classList && e.target.classList.contains('viewer-scrim')) { \
                    e.target.remove(); \
                } \
            }); \
            document.addEventListener('keydown', function (e) { \
                if (e.key !== 'Escape') { return; } \
                var scrim = document.querySelector('.viewer-scrim'); \
                if (scrim) { scrim.remove(); } \
            }); \
            document.addEventListener('change', function (e) { \
                var input = e.target.closest ? e.target.closest('[data-autosubmit]') : null; \
                if (input && input.form) { input.form.submit(); } \
            }); \
        })();";
    view! { cx => <script>(Unescaped::new_unchecked(JS))</script> }
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
