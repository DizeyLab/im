//! The document shell every im page renders through. No hydration, no
//! runtime script: pages are plain HTML forms, posted hard.

use im_core::model::User;
use topcoat::Result;
use topcoat::asset::{Asset, asset};
use topcoat::context::Cx;
use topcoat::view::view;

use crate::i18n::{Key, Lang, lang_of, t};

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
/// and client-closed (scrim click or Escape). A face marked `data-own` gets
/// the photo's Change/Remove inside the viewer, so the page itself carries
/// no buttons for a picture. A `data-autosubmit` input posts its form on
/// change: choosing a file IS the upload, no Save button. Both are delegated
/// document listeners, so the hard-post re-render never needs rewiring.
/// Emitted by the landing and the person page — every surface that draws a
/// clickable face.
pub async fn avatar_script(cx: &Cx, lang: Lang) -> Result {
    use topcoat::view::Unescaped;
    /// Single-quoted into the script below; the staged strings carry no
    /// quoting of their own, and this keeps it true if one ever does.
    fn js_escape(raw: &str) -> String {
        raw.replace('\\', "\\\\").replace('\'', "\\'")
    }
    const JS_TEMPLATE: &str = "\
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
                    if (view.hasAttribute('data-own')) { \
                        var actions = document.createElement('div'); \
                        actions.className = 'viewer-actions'; \
                        var change = document.createElement('label'); \
                        change.className = 'admin-action'; \
                        change.setAttribute('for', 'profile-photo-input'); \
                        change.textContent = '__IM_CHANGE__'; \
                        var remove = document.createElement('button'); \
                        remove.type = 'submit'; \
                        remove.className = 'admin-action admin-danger'; \
                        remove.setAttribute('form', 'profile-photo-remove'); \
                        remove.textContent = '__IM_REMOVE__'; \
                        actions.appendChild(change); \
                        actions.appendChild(remove); \
                        box.appendChild(actions); \
                    } \
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
                var openSession = document.querySelector('.session-item[open]'); \
                if (openSession) { openSession.removeAttribute('open'); } \
            }); \
            document.addEventListener('change', function (e) { \
                var input = e.target.closest ? e.target.closest('[data-autosubmit]') : null; \
                if (!input || !input.form || input.form.__imUploading) { return; } \
                var form = input.form; \
                var head = input.closest('.profile-head'); \
                if (!head) { form.submit(); return; } \
                /* Captured before the input is disabled — a disabled control \
                   is no longer listed, and the post would carry no file. */ \
                var data = new FormData(form); \
                form.__imUploading = true; \
                input.disabled = true; \
                /* The picker may have fired from the viewer's Change — the \
                   overlay steps aside so the progress row is the thing seen. */ \
                var openScrim = document.querySelector('.viewer-scrim'); \
                if (openScrim) { openScrim.remove(); } \
                var row = document.createElement('div'); \
                row.className = 'profile-upload-row'; \
                var bar = document.createElement('div'); \
                bar.className = 'upload-progress'; \
                var fill = document.createElement('div'); \
                fill.className = 'upload-progress-fill'; \
                bar.appendChild(fill); \
                row.appendChild(bar); \
                var cancel = document.createElement('button'); \
                cancel.type = 'button'; \
                cancel.className = 'admin-action upload-cancel'; \
                cancel.textContent = '\\u00d7'; \
                cancel.setAttribute('aria-label', '__IM_CANCEL_UPLOAD__'); \
                row.appendChild(cancel); \
                head.insertAdjacentElement('afterend', row); \
                var settle = function () { \
                    form.__imUploading = false; \
                    input.disabled = false; \
                    if (row.parentNode) { row.parentNode.removeChild(row); } \
                }; \
                var x = new XMLHttpRequest(); \
                x.open('POST', form.getAttribute('action')); \
                x.upload.onprogress = function (ev) { \
                    if (ev.lengthComputable && ev.total > 0) { \
                        fill.style.width = Math.min(100, Math.round((ev.loaded / ev.total) * 100)) + '%'; \
                    } \
                }; \
                x.onload = function () { \
                    settle(); \
                    if (window.__imRefresh) { window.__imRefresh(); return; } \
                    window.location.href = x.responseURL || form.getAttribute('action'); \
                }; \
                x.onerror = function () { settle(); form.submit(); }; \
                x.onabort = function () { input.value = ''; settle(); }; \
                cancel.addEventListener('click', function () { x.abort(); }); \
                x.send(data); \
            }); \
        })();";
    let js = JS_TEMPLATE
        .replace("__IM_CHANGE__", &js_escape(t(lang, Key::Change)))
        .replace("__IM_REMOVE__", &js_escape(t(lang, Key::Remove)))
        .replace(
            "__IM_CANCEL_UPLOAD__",
            &js_escape(t(lang, Key::CancelUploadLabel)),
        );
    view! { cx => <script>(Unescaped::new_unchecked(js))</script> }
}

/// Soft navigation, iz's model cut to im's shape: same-app links and form
/// posts are fetched and swapped in place — no full reload, no white flash,
/// no lost scroll on a save. Session-changing forms (sign-in, enroll,
/// redeem, sign-out) carry `data-hard` and post natively; multipart forms
/// belong to the avatar script above and are left to it. Global listeners
/// live on document/window and survive every swap; the guard makes the
/// re-created script a no-op.
pub async fn soft_nav_script(cx: &Cx) -> Result {
    use topcoat::view::Unescaped;
    const JS: &str = r#"(function () {
  if (window.__imSoft) { return; }
  window.__imSoft = true;
  var nav = 0;
  function step() { nav += 1; return nav; }

  function adopt(doc, preserve) {
    document.title = doc.title;
    var root = doc.documentElement;
    ['lang', 'data-theme', 'data-ui'].forEach(function (a) {
      if (root.hasAttribute(a)) { document.documentElement.setAttribute(a, root.getAttribute(a)); }
      else { document.documentElement.removeAttribute(a); }
    });
    var fields = null;
    if (preserve) {
      fields = {};
      document.querySelectorAll('input[name], select[name], textarea[name]').forEach(function (f) {
        if (f.type === 'password' || f.type === 'file' || f.type === 'hidden') { return; }
        fields[f.name] = f.value;
      });
    }
    document.body.replaceChildren();
    Array.from(doc.body.childNodes).forEach(function (n) { document.body.appendChild(document.importNode(n, true)); });
    document.querySelectorAll('script').forEach(function (old) {
      var s = document.createElement('script');
      s.textContent = old.textContent;
      old.replaceWith(s);
    });
    if (fields) {
      document.querySelectorAll('input[name], select[name], textarea[name]').forEach(function (f) {
        if (Object.prototype.hasOwnProperty.call(fields, f.name)) { f.value = fields[f.name]; }
      });
    }
  }

  function swap(html, url, fresh, push) {
    var doc = new DOMParser().parseFromString(html, 'text/html');
    if (!doc.body) { location.assign(url); return; }
    var x = window.scrollX, y = window.scrollY;
    adopt(doc, false);
    if (push) { history.pushState(null, '', url); } else { history.replaceState(null, '', url); }
    if (fresh) { window.scrollTo(0, 0); } else { window.scrollTo(x, y); }
  }

  function go(url, fresh, push) {
    var mark = step();
    fetch(url, { headers: { accept: 'text/html' } })
      .then(function (r) { return r.text().then(function (text) { return { text: text, url: r.url }; }); })
      .then(function (res) { if (mark === nav) { swap(res.text, res.url, fresh, push); } })
      .catch(function () { location.assign(url); });
  }

  document.addEventListener('click', function (e) {
    if (e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) { return; }
    var a = e.target.closest ? e.target.closest('a') : null;
    if (!a || a.target || a.hasAttribute('download') || a.hasAttribute('data-hard')) { return; }
    var href = a.getAttribute('href') || '';
    if (href.indexOf('/') !== 0) { return; }
    e.preventDefault();
    go(href, true, true);
  }, true);

  document.addEventListener('submit', function (e) {
    var form = e.target;
    if (!form || !form.action || form.hasAttribute('data-hard')) { return; }
    if ((form.enctype || '').indexOf('multipart') === 0) { return; }
    if ((form.method || 'get').toLowerCase() === 'get') {
      e.preventDefault();
      var q = new URLSearchParams(new FormData(form)).toString();
      go(form.action.split('?')[0] + (q ? '?' + q : ''), true, true);
      return;
    }
    e.preventDefault();
    var mark = step();
    var data = new FormData(form);
    if (e.submitter && e.submitter.name) { data.append(e.submitter.name, e.submitter.value); }
    fetch(form.action, { method: 'POST', headers: { accept: 'text/html' }, body: new URLSearchParams(data) })
      .then(function (r) { return r.text().then(function (text) { return { text: text, url: r.url }; }); })
      .then(function (res) { if (mark === nav) { swap(res.text, res.url, false, false); } })
      .catch(function () { form.submit(); });
  });

  window.addEventListener('popstate', function () { go(location.pathname + location.search, false, false); });

  window.__imRefresh = function () {
    var active = document.activeElement;
    if (active && /^(INPUT|SELECT|TEXTAREA)$/.test(active.tagName)) { return; }
    fetch(location.href, { headers: { accept: 'text/html' } })
      .then(function (r) { return r.text(); })
      .then(function (html) {
        var doc = new DOMParser().parseFromString(html, 'text/html');
        if (!doc.body) { return; }
        var x = window.scrollX, y = window.scrollY;
        adopt(doc, true);
        window.scrollTo(x, y);
      })
      .catch(function () {});
  };
})();"#;
    view! { cx => <script>(Unescaped::new_unchecked(JS))</script> }
}

/// The live channel's client, iz's shape: a bare tick says *something*
/// moved; the page re-fetches itself through the ordinary route — where the
/// ordinary gate answers — and morphs with fields and scroll intact. A
/// focused field freezes the refresh mid-typing. Mounted only for a signed-in
/// viewer, so auth screens never reconnect against a 401.
pub async fn live_script(cx: &Cx) -> Result {
    use topcoat::view::Unescaped;
    const JS: &str = r#"(function () {
  if (window.__imLive) { return; }
  window.__imLive = true;
  var timer = null;
  function schedule() {
    if (timer) { clearTimeout(timer); }
    timer = setTimeout(function () { timer = null; if (window.__imRefresh) { window.__imRefresh(); } }, 200);
  }
  try {
    var src = new EventSource('/live');
    src.onmessage = function () { schedule(); };
  } catch (err) {}
})();"#;
    view! { cx => <script>(Unescaped::new_unchecked(JS))</script> }
}

/// A full document around an already-rendered stage — the same way
/// izlek-web's `#[layout]` receives its slot. The viewer stamps the chrome:
/// their theme/language/ui when signed in, English/light/instrument when
/// not — mirroring iz's root_layout, minus its build stamp.
pub async fn shell(cx: &Cx, title: &str, viewer: Option<&User>, stage: Result) -> Result {
    let stage = stage?;
    let lang = lang_of(viewer);
    let dark = viewer.is_some_and(|user| user.theme == "dark");
    let ui = viewer.map_or("instrument", |user| user.ui.as_str());
    view! {
        cx =>
        <!DOCTYPE html>
        <html lang=(lang.code()) data-theme=(dark.then_some("dark")) data-ui=(ui)>
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
                (soft_nav_script(cx).await?)
                if viewer.is_some() {
                    (live_script(cx).await?)
                }
            </body>
        </html>
    }
}
