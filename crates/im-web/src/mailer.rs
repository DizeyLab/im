//! Sending mail with the sender the admin panel configured. The transport is
//! built per send: settings can change at any moment, and invites are rare —
//! the pool a long-lived transport would buy serves nothing here.

use im_core::settings::{self, Smtp};
use im_core::store::Store;

#[derive(Debug, thiserror::Error)]
pub enum MailError {
    #[error("no sender configured")]
    NotConfigured,
    #[error("mail: {0}")]
    Backend(String),
    #[error("settings: {0}")]
    Settings(#[from] im_core::store::StoreError),
}

pub type Result<T, E = MailError> = std::result::Result<T, E>;

fn transport(smtp: &Smtp) -> Result<lettre::AsyncSmtpTransport<lettre::Tokio1Executor>> {
    if !smtp.configured() {
        return Err(MailError::NotConfigured);
    }
    let mut builder = lettre::AsyncSmtpTransport::<lettre::Tokio1Executor>::relay(&smtp.host)
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
            smtp.from
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

/// The invite mail: the link is the whole payload.
pub async fn send_invite(store: &Store, issuer: &str, email: &str, token: &str) -> Result<String> {
    let link = format!("{issuer}/invite/{token}");
    send(
        store,
        email,
        "You're invited",
        format!(
            "You've been invited. This link is yours for {} days:\n\n{link}\n",
            im_core::accounts::INVITE_DAYS
        ),
    )
    .await?;
    Ok(link)
}

/// The panel's test button: proves the sender end to end, to the admin's own
/// address.
pub async fn send_test(store: &Store, to: &str) -> Result<()> {
    send(
        store,
        to,
        "im mail test",
        "im can send mail from this sender.\n".into(),
    )
    .await
}
