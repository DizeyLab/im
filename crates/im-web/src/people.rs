//! A member's public profile: who they are, and what their identity has
//! done here. Any signed-in member may read it, and nothing on the page
//! writes — the one editor a profile has is the landing, which the page
//! links to for its own person and nowhere else. A stranger and a missing
//! id read the same: the router's own not-found, never a `403` —
//! `photo.rs` keeps the same rule for bytes.

use topcoat::Result;
use topcoat::context::Cx;
use topcoat::router::error::not_found;
use topcoat::router::{page, path_param};
use topcoat::view::view;

use im_core::accounts;

use crate::i18n::{Key, lang_of, t};
use crate::layout::{avatar, shell, wordmark};
use crate::server;

path_param!(user_id);

/// A person's page. `/people/{user_id}`.
#[page("/people/{user_id}")]
async fn people_page(cx: &Cx) -> Result {
    let Some(viewer) = server::current_user(cx).await else {
        return Err(not_found().into());
    };
    let lang = lang_of(Some(&viewer));
    let target_id: &str = path_param::<UserId>(cx);
    let store = server::app(cx).store.clone();
    let target = im_core::model::UserId::from(target_id.to_string());
    let Some(person) = accounts::user_by_id(store.as_ref(), &target).await? else {
        return Err(not_found().into());
    };
    let mine = person.id == viewer.id;
    let stats = im_core::stats::profile_stats(&store, &person.id).await?;
    let joined = person.created_at.date().to_string();
    let stage = view! {
        cx =>
        <main class="auth-stage">
            <div class="auth-column">
                (wordmark(cx).await?)
                <div class="auth-card">
                    <div class="profile-head">
                        if person.has_photo {
                            // The face opens the viewer here too — same as
                            // the landing, same as iz's person page.
                            <button class="avatar-view" type="button" aria-label=(t(lang, Key::ViewPhotoAria))>
                                (avatar(cx, &person).await?)
                            </button>
                        } else {
                            (avatar(cx, &person).await?)
                        }
                        <div class="profile-heading">
                            <div class="auth-title">(person.name.clone())</div>
                            <div class="profile-marks">
                                if person.totp_confirmed {
                                    <span class="chip chip-connected">(t(lang, Key::TwoFaOn))</span>
                                } else {
                                    <span class="chip chip-muted">(t(lang, Key::TwoFaOff))</span>
                                }
                                if person.admin {
                                    <span class="chip chip-accent">(t(lang, Key::AdminChip))</span>
                                }
                            </div>
                        </div>
                    </div>
                    <dl class="profile-fields">
                        <div class="profile-field">
                            <dt class="auth-label">(t(lang, Key::EmailLabel))</dt>
                            <dd class="profile-value mono">(person.email.clone())</dd>
                        </div>
                        <div class="profile-field">
                            <dt class="auth-label">(t(lang, Key::MemberSinceLabel))</dt>
                            <dd class="profile-value">(joined)</dd>
                        </div>
                    </dl>
                    if mine {
                        <a class="auth-alt" href="/">(t(lang, Key::EditProfileLink))</a>
                    }
                </div>
                <div class="auth-card">
                    <dl class="profile-stats">
                        <div class="profile-stat">
                            <dd class="profile-stat-value">(stats.sign_ins)</dd>
                            <dt class="auth-label">(t(lang, Key::StatSignIns))</dt>
                        </div>
                        <div class="profile-stat">
                            <dd class="profile-stat-value">(stats.active_sessions)</dd>
                            <dt class="auth-label">(t(lang, Key::StatActiveSessions))</dt>
                        </div>
                        <div class="profile-stat">
                            <dd class="profile-stat-value">(stats.connected_apps)</dd>
                            <dt class="auth-label">(t(lang, Key::StatConnectedApps))</dt>
                        </div>
                    </dl>
                </div>
                <div class="auth-footer">(t(lang, Key::BrandFooter))</div>
            </div>
        </main>
        (crate::layout::avatar_script(cx, lang).await?)
    };
    shell(cx, &format!("{} · im", person.name), Some(&viewer), stage).await
}
