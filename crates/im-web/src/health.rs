//! The one family-health probe, shared by the admin panel's health table
//! and the signed-in wordmark's flyout: a service is asked
//! `GET {url}/healthz` where it stands — no credentials, two seconds to
//! answer — and the callers fan the probes out concurrently, so a family
//! member that is down costs its two seconds, not two seconds each.
//! [`probe_family`] sits over that with the two things a per-render probe
//! used to pay again and again: one shared client, and a short-lived
//! cache so a burst of renders reuses the last reading instead of
//! re-stalling on a down sibling.

use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

/// One `/healthz` reading. `Up` carries the body — the deploy contract's
/// `ok <build sha>` — and the answer's latency; everything else, refused
/// or wrong status or a body that does not begin ok or the two-second
/// ceiling, is `Down`.
#[derive(Clone)]
pub(crate) enum Probe {
    Up { body: String, ms: u128 },
    Down,
}

pub(crate) async fn probe_healthz(http: &reqwest::Client, url: &str) -> Probe {
    let started = std::time::Instant::now();
    let Ok(answer) = http
        .get(url)
        .timeout(std::time::Duration::from_secs(2))
        .send()
        .await
    else {
        return Probe::Down;
    };
    if !answer.status().is_success() {
        return Probe::Down;
    }
    let body = answer.text().await.unwrap_or_default();
    let body = body.trim();
    if body.starts_with("ok") {
        Probe::Up {
            body: body.chars().take(64).collect(),
            ms: started.elapsed().as_millis(),
        }
    } else {
        Probe::Down
    }
}

/// How long one family reading stands in for fresh probes. Long enough
/// that paging the panel does not re-stall on a dark sibling, short
/// enough that a service coming back is noticed within half a minute.
const CACHE_TTL: Duration = Duration::from_secs(30);

/// The probe client every reader shares: one connection pool built once
/// per process, not a fresh client — and fresh sockets — per render.
static HTTP: LazyLock<reqwest::Client> = LazyLock::new(reqwest::Client::new);

/// The last family reading: when it was taken, and what each probed
/// `/healthz` answered, keyed by URL.
static CACHE: LazyLock<Mutex<(Instant, Vec<(String, Probe)>)>> =
    LazyLock::new(|| Mutex::new((Instant::now(), Vec::new())));

/// One reading per URL, in order. A reading younger than [`CACHE_TTL`]
/// that already covers every URL asked is reused whole — the chrome and
/// the panel can share a render without doubling the probes, and a down
/// sibling's two-second ceiling is paid once per window, not once per
/// page view. Otherwise every URL is probed at once and the reading is
/// remembered. A family that gained or lost a row reads fresh; a lost
/// probe task reads `Down`, and the next window re-probes.
pub(crate) async fn probe_family(urls: &[String]) -> Vec<Probe> {
    if let Some(cached) = fresh(urls) {
        return cached;
    }
    let probes: Vec<_> = urls
        .iter()
        .map(|url| {
            let url = url.clone();
            tokio::spawn(async move { probe_healthz(&HTTP, &url).await })
        })
        .collect();
    let mut readings: Vec<(String, Probe)> = Vec::with_capacity(urls.len());
    for (url, probe) in urls.iter().zip(probes) {
        readings.push((url.clone(), probe.await.unwrap_or(Probe::Down)));
    }
    if let Ok(mut slot) = CACHE.lock() {
        *slot = (Instant::now(), readings.clone());
    }
    readings.into_iter().map(|(_, probe)| probe).collect()
}

/// The cached reading, when it is young enough to stand and covers every
/// URL asked. A poisoned cache is a miss — the next round re-probes.
fn fresh(urls: &[String]) -> Option<Vec<Probe>> {
    let cache = CACHE.lock().ok()?;
    let (at, readings) = &*cache;
    if at.elapsed() >= CACHE_TTL {
        return None;
    }
    urls.iter()
        .map(|url| {
            readings
                .iter()
                .find(|(seen, _)| seen == url)
                .map(|(_, probe)| probe.clone())
        })
        .collect()
}
