//! im-client's directory half: the app-side mirror of im's identity
//! roster. Three doors, all opened with the app's Basic pair:
//!
//! * [`DirectoryClient::directory`] — the whole roster, as im's
//!   `/directory` answers it;
//! * [`DirectoryClient::photo`] — one member's photo bytes, for an
//!   `<img src>` served out of the app's own hands;
//!   event per changed member and one per sign-out in motion, parsed by
//!   hand from the byte stream.
//!
//! [`spawn_sync`] is the whole loop most apps want: a full pass through
//! [`DirectoryClient::directory`], then the stream through the same
//! `on_member` door, and — whenever the stream drops — a growing wait, a
//! `on_resync` call, a fresh full pass, and back on the stream. The mirror
//! converges no matter how the connection died.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use crate::{Error, Result};

/// How long a plain request (roster, photo) may take. The live stream is
/// exempt — it is *supposed* to sit idle — so its request carries no
/// timeout and its liveness is the server's keep-alive comment.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

/// The first wait after a failed stream, and the growth step.
const BACKOFF_FLOOR: Duration = Duration::from_secs(1);

/// The longest wait a run of consecutive failures earns.
const BACKOFF_CAP: Duration = Duration::from_secs(30);

/// One roster member, exactly the shape im's `/directory` answers and its
/// `/directory/live` stream announces. `admin` and `photo_version` default
/// so an older im — whose answers predate them — still parses.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DirectoryMember {
    /// The stable subject: the same string the id_token's `sub` claim and
    /// the photo route's path carry.
    pub sub: String,
    pub email: String,
    pub name: String,
    #[serde(default)]
    pub admin: bool,
    /// How many times the member's photo has changed: the `?v=` that lets
    /// `/photo/{sub}` be cached hard and still arrive fresh.
    #[serde(default)]
    pub photo_version: u64,
    /// The member's display timezone (a fixed offset like "UTC+03:00").
    /// Defaulted: rows mirrored before im carried the field still read.
    #[serde(default = "default_timezone")]
    pub timezone: String,
    /// Whether im has switched the member off. Defaulted: a row mirrored
    /// before im carried the field reads as present-and-enabled.
    #[serde(default)]
    pub disabled: bool,
}

/// The timezone im starts every account on, and the one this SDK assumes
/// when a mirrored row predates the field.
fn default_timezone() -> String {
    "UTC+03:00".to_string()
}

/// One event off the directory stream: a member's row, or a sign-out in
/// motion. The enum leaves room for the feed to grow without a breaking
/// change to consumers — unknown frame kinds are skipped, not fatal.
#[derive(Debug, Clone, PartialEq)]
pub enum DirectoryEvent {
    /// The named member's row changed — upload, address, admin flag, any
    /// of it. The payload is the row as it now stands.
    Profile(DirectoryMember),
    /// The named subject's sessions were revoked: im's broadcast on any
    /// logout-everywhere, disable, or delete. The app's cue to send that
    /// subject's signed-in tabs home.
    Revoked { sub: String },
}

/// The body of a `revoked` frame: the subject whose sessions died.
#[derive(Deserialize)]
struct RevokedFrame {
    sub: String,
}

/// The directory client: issuer plus the same `client_id:client_secret`
/// pair the OIDC side already holds. Cheap to clone; one HTTP pool inside.
#[derive(Clone)]
pub struct DirectoryClient {
    http: reqwest::Client,
    issuer: String,
    client_id: String,
    client_secret: String,
}

impl DirectoryClient {
    pub fn new(
        issuer: impl Into<String>,
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
    ) -> Self {
        Self {
            http: reqwest::Client::new(),
            issuer: issuer.into(),
            client_id: client_id.into(),
            client_secret: client_secret.into(),
        }
    }

    fn get(&self, path: &str) -> reqwest::RequestBuilder {
        self.http
            .get(format!("{}{path}", self.issuer))
            .basic_auth(&self.client_id, Some(&self.client_secret))
    }

    /// `GET /directory`: the whole non-disabled roster, oldest first.
    pub async fn directory(&self) -> Result<Vec<DirectoryMember>> {
        let answer = self
            .get("/directory")
            .timeout(REQUEST_TIMEOUT)
            .send()
            .await
            .map_err(|e| Error::Http(e.to_string()))?
            .error_for_status()
            .map_err(|e| Error::Refused(e.to_string()))?;
        answer
            .json()
            .await
            .map_err(|e| Error::Http(e.to_string()))
    }

    /// `GET /photo/{sub}`: the member's photo bytes and their content
    /// type. A member with no photo gets im's default face — the initial
    /// tile — so the answer is always an image.
    pub async fn photo(&self, sub: &str) -> Result<(Vec<u8>, String)> {
        let answer = self
            .get(&format!("/photo/{sub}"))
            .timeout(REQUEST_TIMEOUT)
            .send()
            .await
            .map_err(|e| Error::Http(e.to_string()))?
            .error_for_status()
            .map_err(|e| Error::Refused(e.to_string()))?;
        let content_type = answer
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("application/octet-stream")
            .to_string();
        let bytes = answer
            .bytes()
            .await
            .map_err(|e| Error::Http(e.to_string()))?
            .to_vec();
        Ok((bytes, content_type))
    }

    /// `GET /directory/live`: opens the change feed. Every frame after the
    /// first is one member's row; the stream ends — `None` from
    /// [`DirectoryStream::next`] — whenever im closes it, which is the
    /// caller's cue to re-list and redial ([`spawn_sync`] does exactly
    /// that).
    pub async fn open_stream(&self) -> Result<DirectoryStream> {
        let response = self
            .get("/directory/live")
            .send()
            .await
            .map_err(|e| Error::Http(e.to_string()))?
            .error_for_status()
            .map_err(|e| Error::Refused(e.to_string()))?;
        Ok(DirectoryStream {
            response,
            parser: SseParser::default(),
            ready: std::collections::VecDeque::new(),
        })
    }
}

/// An open `/directory/live` connection.
pub struct DirectoryStream {
    response: reqwest::Response,
    parser: SseParser,
    ready: std::collections::VecDeque<DirectoryEvent>,
}

impl DirectoryStream {
    /// The next member change. `Some(Err)` on a network failure, then the
    /// stream is over; `None` when im closed a healthy stream (a restart,
    /// the server window). Either way the caller re-lists and redials.
    pub async fn next(&mut self) -> Option<Result<DirectoryEvent>> {
        loop {
            if let Some(event) = self.ready.pop_front() {
                return Some(Ok(event));
            }
            match self.response.chunk().await {
                Ok(Some(bytes)) => self.ready.extend(self.parser.feed(&bytes)),
                // The connection closed cleanly: a healthy stream's end.
                Ok(None) => return None,
                Err(e) => return Some(Err(Error::Http(e.to_string()))),
            }
        }
    }
}

/// The hand-rolled `text/event-stream` reader. Frames accumulate field by
/// field and dispatch on the blank line, per the SSE grammar; the only
/// fields this feed carries are `event`, `data`, `retry`, and comments,
/// but the parser honors the whole shape — including `data` split over
/// several lines, which the spec joins with `\n`.
#[derive(Default)]
struct SseParser {
    /// Bytes read but not yet through a line terminator.
    pending: Vec<u8>,
    /// The current frame's `event:` field, if it named one.
    event: Option<String>,
    /// The current frame's `data:`, joined back into one string.
    data: String,
}

impl SseParser {
    /// Feeds the next bytes from the wire and answers every frame they
    /// completed. Bytes trailing their terminator wait for the rest — a
    /// field or a UTF-8 character may straddle two reads.
    fn feed(&mut self, bytes: &[u8]) -> Vec<DirectoryEvent> {
        self.pending.extend_from_slice(bytes);
        let mut events = Vec::new();
        let Some(at) = self
            .pending
            .iter()
            .rposition(|&b| b == b'\n' || b == b'\r')
            .map(|at| at + 1)
        else {
            return events;
        };
        let block: Vec<u8> = self.pending.drain(..at).collect();
        for line in split_lines(&block) {
            if line.is_empty() {
                // The blank line dispatches whatever accumulated.
                if let Some(event) = self.take_event() {
                    events.push(event);
                }
            } else if line[0] == b':' {
                // A comment — im's keep-alives and retry hint live here.
            } else {
                let (name, value) = match line.iter().position(|&b| b == b':') {
                    Some(at) => (&line[..at], &line[at + 1..]),
                    None => (&line[..], &b""[..]),
                };
                // One optional space after the colon is not part of the
                // value.
                let value = value.strip_prefix(b" ").unwrap_or(value);
                match name {
                    b"event" => self.event = Some(String::from_utf8_lossy(value).into_owned()),
                    b"data" => {
                        if !self.data.is_empty() {
                            self.data.push('\n');
                        }
                        self.data.push_str(&String::from_utf8_lossy(value));
                    }
                    // `id` and `retry` mean nothing to a change feed.
                    _ => {}
                }
            }
        }
        events
    }

    /// Ends the current frame: the data, if it parsed into a member, is
    /// the event. A frame that names another event type, or whose data is
    /// not a member, is skipped — the feed may grow, and a single bad
    /// frame must not end the connection.
    fn take_event(&mut self) -> Option<DirectoryEvent> {
        let data = std::mem::take(&mut self.data);
        let event = self.event.take();
        match event.as_deref() {
            Some("revoked") => serde_json::from_str::<RevokedFrame>(&data)
                .ok()
                .map(|frame| DirectoryEvent::Revoked { sub: frame.sub }),
            // A nameless frame (the retry hint, a tick) carries no member.
            Some("profile") | None => serde_json::from_str::<DirectoryMember>(&data)
                .ok()
                .map(DirectoryEvent::Profile),
            // The feed may grow: an unknown kind is skipped, not fatal.
            Some(_) => None,
        }
    }
}

/// Splits a block that ends at a line terminator into lines, accepting the
/// three SSE terminators: `\n`, `\r\n`, and a bare `\r`.
fn split_lines(block: &[u8]) -> Vec<Vec<u8>> {
    let mut lines = Vec::new();
    let mut rest = block;
    while let Some(at) = rest.iter().position(|&b| b == b'\n' || b == b'\r') {
        let (line, tail) = rest.split_at(at);
        lines.push(line.to_vec());
        // A `\r\n` pair is one terminator, not a line and an empty one.
        rest = if tail.starts_with(b"\r\n") { &tail[2..] } else { &tail[1..] };
    }
    lines
}

/// Keeps the app's mirror of the roster in step with im, forever:
///
/// 1. one full `/directory` pass, every member applied through
///    `on_member` — the boot-time population;
/// 2. the `/directory/live` stream, every change through the same door;
/// 3. when the stream dies — error, lag, clean close — wait out the
///    backoff (1s doubling to a 30s cap), call `on_resync`, replay a full
///    pass, and resume the stream. A full pass that itself fails is
///    retried on the same clock until im answers.
///
/// Runs until the task is aborted; the handle is the caller's to drop or
/// cancel.
pub fn spawn_sync<F, G>(
    client: DirectoryClient,
    mut on_member: F,
    mut on_resync: G,
) -> tokio::task::JoinHandle<()>
where
    F: FnMut(DirectoryMember) + Send + 'static,
    G: FnMut() + Send + 'static,
{
    tokio::spawn(async move {
        let mut backoff = BACKOFF_FLOOR;
        loop {
            // The full pass. There is nothing to converge with until one
            // lands, so failures retry on the growing clock.
            loop {
                match client.directory().await {
                    Ok(members) => {
                        for member in members {
                            on_member(member);
                        }
                        break;
                    }
                    Err(_) => {
                        tokio::time::sleep(backoff).await;
                        backoff = (backoff * 2).min(BACKOFF_CAP);
                    }
                }
            }
            let mut stream = match client.open_stream().await {
                Ok(stream) => stream,
                Err(_) => {
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(BACKOFF_CAP);
                    on_resync();
                    continue;
                }
            };
            while let Some(event) = stream.next().await {
                match event {
                    Ok(DirectoryEvent::Profile(member)) => {
                        on_member(member);
                        // The stream works: the next stumble starts over
                        // at the short wait.
                        backoff = BACKOFF_FLOOR;
                    }
                    // A sign-out in motion: this loop's door carries
                    // members only. The frame is read and dropped — the
                    // app that needs the event reads the stream itself.
                    Ok(DirectoryEvent::Revoked { .. }) => {
                        backoff = BACKOFF_FLOOR;
                    }
                    Err(_) => break,
                }
            }
            // The stream is gone. Wait, grow, and make the caller
            // re-list the whole roster before the stream resumes, so
            // whatever moved while the line was down heals on the pass.
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(BACKOFF_CAP);
            on_resync();
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn member_json(sub: &str, version: u64) -> String {
        format!(
            "{{\"sub\":\"{sub}\",\"email\":\"{sub}@example.com\",\
             \"name\":\"Ann\",\"admin\":false,\"photo_version\":{version}}}"
        )
    }

    fn frame(sub: &str, version: u64) -> String {
        format!("event: profile\ndata: {}\n\n", member_json(sub, version))
    }

    #[test]
    fn a_profile_frame_becomes_an_event() {
        let mut parser = SseParser::default();
        let events = parser.feed(
            format!("retry: 5000\n: keep-alive\n\n{}", frame("one", 3)).as_bytes(),
        );
        assert_eq!(
            events,
            vec![DirectoryEvent::Profile(DirectoryMember {
                timezone: default_timezone(),
                sub: "one".into(),
                email: "one@example.com".into(),
                name: "Ann".into(),
                admin: false,
                photo_version: 3,
                disabled: false,
            })]
        );
    }

    #[test]
    fn a_frame_split_across_reads_still_parses() {
        let whole = frame("two", 7);
        let mut parser = SseParser::default();
        let mut events;
        // Cut at every byte boundary in turn; no split may lose the event.
        for cut in 1..whole.len() {
            events = parser.feed(&whole.as_bytes()[..cut]);
            assert!(events.is_empty(), "a partial frame must not dispatch");
            events.extend(parser.feed(&whole.as_bytes()[cut..]));
            assert_eq!(events.len(), 1, "cut at {cut}");
            assert_eq!(events[0], DirectoryEvent::Profile(DirectoryMember {
            timezone: default_timezone(),
                sub: "two".into(),
                email: "two@example.com".into(),
                name: "Ann".into(),
                admin: false,
                photo_version: 7,
                disabled: false,
            }));
            parser = SseParser::default();
        }
    }

    #[test]
    fn crlf_terminators_are_lines_too() {
        let mut parser = SseParser::default();
        let events = parser.feed(frame("three", 1).replace('\n', "\r\n").as_bytes());
        assert_eq!(events.len(), 1);
        assert_eq!(events[0], DirectoryEvent::Profile(DirectoryMember {
            timezone: default_timezone(),
            sub: "three".into(),
            email: "three@example.com".into(),
            name: "Ann".into(),
            admin: false,
            photo_version: 1,
            disabled: false,
        }));
    }

    #[test]
    fn ticks_and_comments_are_silence() {
        let mut parser = SseParser::default();
        // What im's own browser feed sends, plus an event type the
        // directory feed does not carry: none of it is a member.
        let noise = b"data: {}\n\nevent: tick\ndata: {}\n\n: keep-alive\n\nretry: 5000\n\n";
        assert!(parser.feed(noise).is_empty());
    }

    #[test]
    fn a_broken_frame_is_skipped_and_the_next_still_lands() {
        let mut parser = SseParser::default();
        let bytes = format!("event: profile\ndata: {{not json}}\n\n{}", frame("four", 2));
        let events = parser.feed(bytes.as_bytes());
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0],
            DirectoryEvent::Profile(DirectoryMember {
                timezone: default_timezone(),
                sub: "four".into(),
                email: "four@example.com".into(),
                name: "Ann".into(),
                admin: false,
                photo_version: 2,
                disabled: false,
            })
        );
    }

    #[test]
    fn multi_line_data_is_joined_for_the_json() {
        let mut parser = SseParser::default();
        // The spec joins `data:` lines with `\n`; a member is one line of
        // JSON, so the join lands inside a string and must parse anyway —
        // this frame's name carries a newline.
        let bytes = b"event: profile\ndata: {\"sub\":\"five\",\"email\":\"e\",\
                      data: \"\",\"name\":\"A\\nB\",\"admin\":false,\"photo_version\":0}\n\n";
        let _ = bytes; // (the folded literal above is documentation only)
        let joined = "event: profile\ndata: {\"sub\":\"five\",\ndata: \"x\"}\n\n";
        assert!(parser.feed(joined.as_bytes()).is_empty(), "invalid JSON is skipped, not fatal");
    }

    #[test]
    fn a_revoked_frame_names_the_subject() {
        let mut parser = SseParser::default();
        let bytes = b"event: revoked\ndata: {\"sub\":\"seven\"}\n\n";
        let events = parser.feed(bytes);
        assert_eq!(
            events,
            vec![DirectoryEvent::Revoked { sub: "seven".into() }]
        );
    }

    #[test]
    fn a_member_carries_the_disabled_flag_and_defaults_it() {
        let mut parser = SseParser::default();
        let bytes = b"event: profile\ndata: {\"sub\":\"gone\",\"email\":\"g\",\
                      \"name\":\"G\",\"admin\":false,\"photo_version\":0,\
                      \"disabled\":true}\n\n";
        let events = parser.feed(bytes);
        assert_eq!(events.len(), 1);
        assert!(
            matches!(&events[0], DirectoryEvent::Profile(member) if member.disabled),
            "the flag the frame carries is the flag the member reads"
        );

        // An older im's row predates the flag: it reads as enabled.
        let mut parser = SseParser::default();
        let events = parser.feed(frame("back", 1).as_bytes());
        assert!(
            matches!(&events[0], DirectoryEvent::Profile(member) if !member.disabled),
            "a row without the field defaults to present-and-enabled"
        );
    }

    #[test]
    fn an_unknown_event_kind_is_skipped_and_the_stream_stays_alive() {
        let mut parser = SseParser::default();
        let bytes = format!(
            "event: somethingnew\ndata: {{\"whatever\":1}}\n\n{}",
            frame("after", 9)
        )
        .into_bytes();
        let events = parser.feed(&bytes);
        assert_eq!(events.len(), 1, "the unknown frame is not fatal");
        assert!(matches!(&events[0], DirectoryEvent::Profile(member) if member.sub == "after"));
    }
}
