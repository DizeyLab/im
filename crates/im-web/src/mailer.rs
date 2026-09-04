//! Sending mail with the sender the admin panel configured. The transport is
//! built per send: settings can change at any moment, and invites are rare —
//! the pool a long-lived transport would buy serves nothing here.

use im_core::settings::{self, Smtp};
use im_core::store::Store;
use crate::i18n::{self, Lang};

#[derive(Debug, thiserror::Error)]
pub enum MailError {
    #[error("no sender configured")]
    NotConfigured,
    #[error("mail: {0}")]
    Backend(String),
    #[error("settings: {0}")]
    Settings(#[from] im_core::store::StoreError),
}

/// How long to wait on a mail server before writing the attempt off. Long
/// enough for a slow but healthy server on a bad link, short enough that an
/// admin who mistyped the port is told while still looking at the screen.
/// izlek measured that lettre's own timeout does not catch a socket that
/// accepts and then says nothing — this outer bound is the backstop.
const PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

pub type Result<T, E = MailError> = std::result::Result<T, E>;

fn transport(smtp: &Smtp) -> Result<lettre::AsyncSmtpTransport<lettre::Tokio1Executor>> {
    if !smtp.configured() {
        return Err(MailError::NotConfigured);
    }
    // 465 is implicit TLS — the handshake wraps the connection from the first
    // byte. Everything else (587 above all) is submission: the session starts
    // in the clear and STARTTLS upgrades it. Picking the wrong one is the
    // classic "something went wrong": relay() against a 587 port hangs the TLS
    // handshake on a server waiting for plaintext EHLO.
    let mut builder = if smtp.port == 465 {
        lettre::AsyncSmtpTransport::<lettre::Tokio1Executor>::relay(&smtp.host)
    } else {
        lettre::AsyncSmtpTransport::<lettre::Tokio1Executor>::starttls_relay(&smtp.host)
    }
    .map_err(|e| MailError::Backend(e.to_string()))?
    .port(smtp.port);
    if !smtp.username.is_empty() {
        builder = builder.credentials(lettre::transport::smtp::authentication::Credentials::new(
            smtp.username.clone(),
            smtp.password.clone().unwrap_or_default(),
        ));
    }
    Ok(builder.build())
}

async fn send(store: &Store, to: &str, subject: &str, body: String) -> Result<()> {
    let smtp = settings::smtp(store).await?;
    let message = lettre::Message::builder()
        .from(
            smtp.from_header()
                .parse()
                .map_err(|e| MailError::Backend(format!("smtp from: {e}")))?,
        )
        .to(to
            .parse()
            .map_err(|e| MailError::Backend(format!("to: {e}")))?)
        .subject(subject)
        .body(body)
        .map_err(|e| MailError::Backend(e.to_string()))?;
    use lettre::AsyncTransport;
    transport(&smtp)?
        .send(message)
        .await
        .map_err(|e| MailError::Backend(e.to_string()))?;
    Ok(())
}

/// The invite mail: the link is the whole payload. The invitee has no
/// account and no preference yet, so this stays English — iz does the same.
pub async fn send_invite(store: &Store, issuer: &str, email: &str, token: &str) -> Result<String> {
    let link = format!("{issuer}/invite/{token}");
    let (subject, body) = i18n::invite_mail(&link, im_core::accounts::INVITE_DAYS);
    send(store, email, &subject, body).await?;
    Ok(link)
}

/// The reset mail: the link is the whole payload, and sending it retires
/// every previous link for the address (see `accounts::create_reset`). The
/// subject and body follow the account's language — mirroring iz's
/// `reset_mail` TR/EN branch.
pub async fn send_reset(
    store: &Store,
    issuer: &str,
    email: &str,
    token: &str,
    lang: Lang,
) -> Result<String> {
    let link = format!("{issuer}/reset/{token}");
    let minutes = settings::reset_minutes(store).await?;
    let (subject, body) = i18n::reset_mail(lang, &link, minutes);
    send(store, email, &subject, body).await?;
    Ok(link)
}

/// Dials the mail server without sending anything: connect, TLS, hello,
/// authenticate, NOOP, hang up. A pass proves the host, the port, the
/// encryption and the password; it says nothing about whether the
/// from-address may send — a server that accepts the login can still refuse
/// the envelope, which is what the test mail is for.
///
/// Returns the handshake's milliseconds on a pass. The error text is built
/// from what the server said, never from what we sent it, so it is safe to
/// store and show.
pub async fn check(store: &Store) -> Result<u64> {
    let smtp = settings::smtp(store).await?;
    let transport = transport(&smtp)?;
    let started = std::time::Instant::now();
    match tokio::time::timeout(PROBE_TIMEOUT, transport.test_connection()).await {
        Ok(Ok(true)) => Ok(started.elapsed().as_millis() as u64),
        // Connected, then would not answer a NOOP — nothing about the
        // settings is proven wrong, but nothing is proven right either.
        Ok(Ok(false)) => Err(MailError::Backend(
            "the mail server accepted the connection and then went quiet".into(),
        )),
        Ok(Err(e)) => Err(MailError::Backend(e.to_string())),
        Err(_) => Err(MailError::Backend(
            "the mail server did not answer in time".into(),
        )),
    }
}

/// The panel's test button: proves the sender end to end, to the admin's own
/// address, in the admin's language.
pub async fn send_test(store: &Store, to: &str, lang: Lang) -> Result<()> {
    send(
        store,
        to,
        i18n::t(lang, i18n::Key::TestMailSubject),
        i18n::t(lang, i18n::Key::TestMailBody).to_string(),
    )
    .await
}
