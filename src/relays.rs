//! SimpleDesk: several relay servers (RELAY_SERVERS), each reachable like the main server, over
//! wss on port 443 (`wss://<relay>/ws/relay`). With more than one, hbbs checks them every 30
//! seconds and picks one for every connection by a simple rule:
//!
//! 1. RELAY_NETWORKS (`10.1.0.0/16=relay-a.example.org,192.0.2.0/24=relay-b.example.org`): if
//!    a device is in one of these networks, its relay, if that one is up. The device that is
//!    controlled counts first, then the one that controls.
//! 2. Else the relay that is up and has the fewest connections: what hbbr reported at the last
//!    check plus what hbbs handed out since. With the same number the one listed first.
//! 3. If none is up, one after the other, as before.
//!
//! The check asks hbbr for `/ws/relay/status` (a WebSocket request that hbbr answers with its
//! number of connections). No GeoIP. With one relay or none nothing is checked and everything
//! works as before.

use crate::panel::{admin_of, html, Panel};
use askama::Template;
use axum::{extract::Extension, http::{HeaderMap, StatusCode}, response::Response};
use hbb_common::{futures::future::join_all, log, ResultType};
use ipnetwork::IpNetwork;
use serde_json::Value;
use sodiumoxide::randombytes::randombytes;
use std::{
    net::IpAddr,
    sync::{Arc, Mutex, MutexGuard},
    time::Duration,
};

/// How often the relays are checked.
pub(crate) const CHECK_SECS: u64 = 30;
const CHECK_TIMEOUT: Duration = Duration::from_secs(5);

/// One configured relay and what the last check found.
#[derive(Clone, Debug, Default)]
pub(crate) struct RelayState {
    pub(crate) name: String,
    /// None until the first check.
    pub(crate) up: Option<bool>,
    /// Connections hbbr reported at the last check.
    pub(crate) connections: u64,
    /// Connections hbbs handed this relay since the last check.
    pub(crate) handed_out: u64,
    /// Unix seconds of the last check, 0 for never.
    pub(crate) checked_at: u64,
    pub(crate) error: String,
}

#[derive(Default)]
struct PoolState {
    relays: Vec<RelayState>,
    networks: Vec<(IpNetwork, String)>,
    /// Entries of RELAY_NETWORKS that cannot be used, for the panel.
    problems: Vec<String>,
}

pub(crate) struct RelayPool {
    state: Mutex<PoolState>,
    http: Option<reqwest::Client>,
}

impl Default for RelayPool {
    fn default() -> Self {
        // HTTP/1.1: the check is a WebSocket request, which HTTP/2 does not have.
        let http = match reqwest::Client::builder().timeout(CHECK_TIMEOUT).http1_only().build() {
            Ok(http) => Some(http),
            Err(err) => {
                log::error!("The relays cannot be checked: {}", err);
                None
            }
        };
        Self {
            state: Default::default(),
            http,
        }
    }
}

/// The networks of RELAY_NETWORKS that point to one of `relays`; the rest as problems.
fn parse_networks(text: &str, relays: &[String]) -> (Vec<(IpNetwork, String)>, Vec<String>) {
    let mut networks = Vec::new();
    let mut problems = Vec::new();
    for entry in text.split(|c: char| c == ',' || c == ';' || c.is_whitespace()) {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        let Some((network, relay)) = entry.split_once('=') else {
            problems.push(format!("{}: Bitte als Netz=Relay schreiben, zum Beispiel 10.1.0.0/16=relay.example.org.", entry));
            continue;
        };
        let Ok(network) = network.trim().parse::<IpNetwork>() else {
            problems.push(format!("{}: {} ist kein Netz wie 10.1.0.0/16.", entry, network.trim()));
            continue;
        };
        let relay = relay.trim();
        match relays.iter().find(|known| known.eq_ignore_ascii_case(relay)) {
            Some(known) => networks.push((network, known.clone())),
            None => problems.push(format!("{}: Das Relay {} steht nicht in RELAY_SERVERS.", entry, relay)),
        }
    }
    (networks, problems)
}

/// Host and port of a relay entry (`host`, `host:port`, `[v6]:port`).
fn split_relay(relay: &str) -> (String, Option<u16>) {
    let relay = relay.trim();
    if let Some(rest) = relay.strip_prefix('[') {
        if let Some((host, port)) = rest.split_once(']') {
            return (host.to_owned(), port.trim_start_matches(':').parse().ok());
        }
    }
    match relay.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') => (host.to_owned(), port.parse().ok()),
        _ => (relay.to_owned(), None),
    }
}

/// Where hbbr answers with its number of connections, the way clients reach the relay: a
/// domain over wss on port 443, an IP address on the WebSocket port (relay port + 2).
pub(crate) fn status_url(relay: &str) -> String {
    let (host, port) = split_relay(relay);
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V6(ip)) => format!("http://[{}]:{}/ws/relay/status", ip, port.unwrap_or(hbb_common::config::RELAY_PORT as u16) + 2),
        Ok(ip) => format!("http://{}:{}/ws/relay/status", ip, port.unwrap_or(hbb_common::config::RELAY_PORT as u16) + 2),
        Err(_) => format!("https://{}/ws/relay/status", host),
    }
}

/// Asks one relay for its number of connections.
async fn ask(http: &reqwest::Client, relay: &str) -> ResultType<u64> {
    let key = base64::encode(randombytes(16));
    let res = http
        .get(status_url(relay))
        .header("Connection", "Upgrade")
        .header("Upgrade", "websocket")
        .header("Sec-WebSocket-Version", "13")
        .header("Sec-WebSocket-Key", key)
        .send()
        .await?;
    let code = res.status();
    // hbbr answers with 400 and this JSON, see relay_status.rs.
    let status: Value = match res.json().await {
        Ok(status) => status,
        Err(_) => hbb_common::bail!("answer {} is not from a SimpleDesk relay", code),
    };
    if status.get("simpledesk_relay").and_then(Value::as_bool) != Some(true) {
        hbb_common::bail!("answer {} is not from a SimpleDesk relay", code);
    }
    match status.get("connections").and_then(Value::as_u64) {
        Some(connections) => Ok(connections),
        None => hbb_common::bail!("no number of connections in the answer"),
    }
}

impl RelayPool {
    fn lock(&self) -> MutexGuard<'_, PoolState> {
        // A panic elsewhere while holding the lock leaves usable data.
        self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Takes the relays of RELAY_SERVERS and the networks of RELAY_NETWORKS. Relays that stay
    /// keep what their last check found.
    pub(crate) fn configure(&self, relays: &[String], networks: &str) {
        let (networks, problems) = parse_networks(networks, relays);
        for problem in &problems {
            log::warn!("RELAY_NETWORKS: {}", problem);
        }
        if !networks.is_empty() {
            log::info!("RELAY_NETWORKS={:?}", networks.iter().map(|(net, relay)| format!("{}={}", net, relay)).collect::<Vec<_>>());
        }
        let mut state = self.lock();
        let old = std::mem::take(&mut state.relays);
        state.relays = relays
            .iter()
            .map(|name| {
                old.iter()
                    .find(|relay| relay.name == *name)
                    .cloned()
                    .unwrap_or_else(|| RelayState { name: name.clone(), ..Default::default() })
            })
            .collect();
        state.networks = networks;
        state.problems = problems;
    }

    /// The relay for a connection between a controlled and a controlling device. None with
    /// one relay or none, or when no relay is up; then the caller goes on as before.
    pub(crate) fn pick(&self, controlled: IpAddr, controlling: IpAddr) -> Option<String> {
        let mut state = self.lock();
        if state.relays.len() < 2 {
            return None;
        }
        let up = |relay: &RelayState| relay.up != Some(false);
        let by_network = [controlled, controlling].iter().find_map(|ip| {
            let ip = match ip {
                IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(*ip),
                _ => *ip,
            };
            state
                .networks
                .iter()
                .filter(|(network, _)| network.contains(ip))
                .find_map(|(_, name)| state.relays.iter().position(|relay| relay.name == *name && up(relay)))
        });
        let index = by_network.or_else(|| {
            state
                .relays
                .iter()
                .enumerate()
                .filter(|(_, relay)| up(relay))
                .min_by_key(|(index, relay)| (relay.connections + relay.handed_out, *index))
                .map(|(index, _)| index)
        })?;
        let relay = &mut state.relays[index];
        relay.handed_out += 1;
        Some(relay.name.clone())
    }

    /// Checks every relay once (only with more than one).
    pub(crate) async fn check(&self) {
        let Some(http) = self.http.as_ref() else {
            return;
        };
        let names: Vec<String> = {
            let state = self.lock();
            if state.relays.len() < 2 {
                return;
            }
            state.relays.iter().map(|relay| relay.name.clone()).collect()
        };
        let answers = join_all(names.iter().map(|name| ask(http, name))).await;
        let now = crate::api::unix_now();
        let mut state = self.lock();
        for (name, answer) in names.iter().zip(answers) {
            let Some(relay) = state.relays.iter_mut().find(|relay| relay.name == *name) else {
                continue;
            };
            let was_up = relay.up;
            relay.checked_at = now;
            relay.handed_out = 0;
            match answer {
                Ok(connections) => {
                    relay.up = Some(true);
                    relay.connections = connections;
                    relay.error.clear();
                    if was_up != Some(true) {
                        log::info!("Relay {} is up ({} connections)", name, connections);
                    }
                }
                Err(err) => {
                    relay.up = Some(false);
                    relay.error = err.to_string();
                    if was_up != Some(false) {
                        log::warn!("Relay {} is not reachable: {}", name, err);
                    }
                }
            }
        }
    }

    /// What the panel shows: the relays, the networks per relay and the problems.
    pub(crate) fn snapshot(&self) -> (Vec<(RelayState, Vec<String>)>, Vec<String>) {
        let state = self.lock();
        let relays = state
            .relays
            .iter()
            .map(|relay| {
                let networks = state
                    .networks
                    .iter()
                    .filter(|(_, name)| *name == relay.name)
                    .map(|(network, _)| network.to_string())
                    .collect();
                (relay.clone(), networks)
            })
            .collect();
        (relays, state.problems.clone())
    }

    #[cfg(test)]
    fn set(&self, name: &str, up: bool, connections: u64) {
        let mut state = self.lock();
        if let Some(relay) = state.relays.iter_mut().find(|relay| relay.name == name) {
            relay.up = Some(up);
            relay.connections = connections;
            relay.handed_out = 0;
        }
    }
}

// The page "Relays".

pub(crate) struct RelayView {
    pub(crate) name: String,
    /// "up", "down" or "unknown", for the dot.
    pub(crate) state: &'static str,
    pub(crate) state_text: String,
    pub(crate) connections: String,
    pub(crate) networks: String,
    pub(crate) checked: String,
}

#[derive(Template)]
#[template(path = "panel/relays.html")]
struct RelaysPage<'a> {
    user: &'a str,
    admin: bool,
    active: &'a str,
    update: &'a str,
    relays: &'a [RelayView],
    problems: &'a [String],
}

fn relay_view(relay: RelayState, networks: Vec<String>, several: bool, now: u64) -> RelayView {
    let (state, state_text) = match (several, relay.up) {
        (false, _) => ("unknown", "wird nicht geprüft".to_owned()),
        (true, None) => ("unknown", "noch nicht geprüft".to_owned()),
        (true, Some(true)) => ("up", "erreichbar".to_owned()),
        (true, Some(false)) => ("down", format!("nicht erreichbar ({})", relay.error)),
    };
    let checked = match (several, relay.checked_at) {
        (true, at) if at > 0 => format!("vor {} s", now.saturating_sub(at)),
        _ => "–".to_owned(),
    };
    RelayView {
        state,
        state_text,
        connections: if several && relay.up == Some(true) {
            (relay.connections + relay.handed_out).to_string()
        } else {
            "–".to_owned()
        },
        networks: if networks.is_empty() { "–".to_owned() } else { networks.join(", ") },
        checked,
        name: relay.name,
    }
}

pub(crate) async fn relays_page(Extension(panel): Extension<Arc<Panel>>, headers: HeaderMap) -> Response {
    let admin = match admin_of(&panel, &headers).await {
        Ok(admin) => admin,
        Err(res) => return res,
    };
    let (relays, problems) = panel.relays.snapshot();
    let several = relays.len() > 1;
    let now = crate::api::unix_now();
    let relays: Vec<RelayView> = relays
        .into_iter()
        .map(|(relay, networks)| relay_view(relay, networks, several, now))
        .collect();
    let update = panel.update_notice(&admin).await;
    let page = RelaysPage {
        user: &admin,
        admin: true,
        active: "relays",
        update: &update,
        relays: &relays,
        problems: &problems,
    };
    html(StatusCode::OK, page.render())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pool(relays: &[&str], networks: &str) -> RelayPool {
        let pool = RelayPool::default();
        let relays: Vec<String> = relays.iter().map(|relay| relay.to_string()).collect();
        pool.configure(&relays, networks);
        pool
    }

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    #[test]
    fn one_relay_or_none_changes_nothing() {
        assert_eq!(pool(&[], "").pick(ip("10.0.0.1"), ip("10.0.0.2")), None);
        assert_eq!(pool(&["relay.example.org"], "10.0.0.0/8=relay.example.org").pick(ip("10.0.0.1"), ip("10.0.0.2")), None);
    }

    #[test]
    fn networks_first_then_the_fewest_connections() {
        let pool = pool(&["a.example.org", "b.example.org", "c.example.org"], "10.1.0.0/16=b.example.org; 192.0.2.0/24=c.example.org");
        pool.set("a.example.org", true, 5);
        pool.set("b.example.org", true, 9);
        pool.set("c.example.org", true, 1);
        // The controlled device counts first, then the one that controls.
        assert_eq!(pool.pick(ip("10.1.2.3"), ip("192.0.2.7")).as_deref(), Some("b.example.org"));
        assert_eq!(pool.pick(ip("203.0.113.1"), ip("192.0.2.7")).as_deref(), Some("c.example.org"));
        // IPv4 as the dual-stack listener reports it.
        assert_eq!(pool.pick(ip("::ffff:10.1.0.9"), ip("203.0.113.1")).as_deref(), Some("b.example.org"));
        // Elsewhere: the fewest connections, counting what was handed out since the check.
        pool.set("c.example.org", true, 1);
        let picks: Vec<String> = (0..6).filter_map(|_| pool.pick(ip("203.0.113.1"), ip("203.0.113.2"))).collect();
        assert_eq!(picks[..4], ["c.example.org", "c.example.org", "c.example.org", "c.example.org"]);
        assert_eq!(picks[4..], ["a.example.org", "c.example.org"]);
        // A relay that is down is skipped, also for its network.
        pool.set("b.example.org", false, 0);
        pool.set("a.example.org", true, 0);
        pool.set("c.example.org", true, 3);
        assert_eq!(pool.pick(ip("10.1.2.3"), ip("203.0.113.1")).as_deref(), Some("a.example.org"));
        // None up: the caller goes on as before.
        pool.set("a.example.org", false, 0);
        pool.set("c.example.org", false, 0);
        assert_eq!(pool.pick(ip("10.1.2.3"), ip("203.0.113.1")), None);
    }

    #[test]
    fn bad_networks_are_named_and_urls_follow_the_client() {
        let (networks, problems) = parse_networks("10.0.0.0/8=a, falsch, 300.0.0.0/8=a, 10.2.0.0/16=x", &["a".to_owned()]);
        assert_eq!(networks.len(), 1);
        assert_eq!(problems.len(), 3, "{problems:?}");
        assert!(problems[2].contains("nicht in RELAY_SERVERS"));
        assert_eq!(status_url("relay.example.org"), "https://relay.example.org/ws/relay/status");
        assert_eq!(status_url("relay.example.org:21117"), "https://relay.example.org/ws/relay/status");
        assert_eq!(status_url("192.0.2.5"), "http://192.0.2.5:21119/ws/relay/status");
        assert_eq!(status_url("192.0.2.5:31117"), "http://192.0.2.5:31119/ws/relay/status");
        assert_eq!(status_url("[2001:db8::1]:21117"), "http://[2001:db8::1]:21119/ws/relay/status");
    }

    /// The handshake of hbbr's WebSocket port (make_pair in relay_server.rs).
    async fn answer_like_hbbr(stream: tokio::net::TcpStream, _addr: std::net::SocketAddr) {
        use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};
        let callback = |req: &Request, response: Response| match crate::relay_status::status_answer(req) {
            Some(answer) => Err(answer),
            None => Ok(response),
        };
        let _ = tokio_tungstenite::accept_hdr_async(stream, callback).await;
    }

    use hbb_common::tokio;

    #[hbb_common::tokio::test]
    async fn the_panel_shows_the_relays_to_admins() {
        use axum::{body::Body, http::{header, Request}};
        use tower::ServiceExt;
        let dir = tempfile::tempdir().unwrap();
        let mut pm = crate::peer::test_peer_map(&dir).await;
        pm.accounts = std::sync::Arc::new(crate::accounts::Accounts::with_admins("felix"));
        let relays = std::sync::Arc::new(pool(&["a.example.org", "b.example.org"], "10.1.0.0/16=b.example.org,10.9.0.0/16=x"));
        relays.set("a.example.org", true, 4);
        relays.set("b.example.org", false, 0);
        let panel = std::sync::Arc::new(Panel::new(pm, Default::default()).await.unwrap().with_relays(relays));
        let mut cookies = Vec::new();
        for user in ["felix", "anna"] {
            panel.pm.db.ensure_external_user(user).await.unwrap();
            cookies.push(format!("simpledesk_session={}", panel.start_session(user).await.unwrap()));
        }
        let get = |cookie: &str| Request::get("/relays").header(header::COOKIE, cookie).body(Body::empty()).unwrap();
        let res = crate::panel::router(panel.clone()).oneshot(get(&cookies[1])).await.unwrap();
        assert_eq!(res.status(), StatusCode::FORBIDDEN);
        let res = crate::panel::router(panel.clone()).oneshot(get(&cookies[0])).await.unwrap();
        let page = String::from_utf8(hyper::body::to_bytes(res.into_body()).await.unwrap().to_vec()).unwrap();
        assert!(page.contains("a.example.org") && page.contains("<span class=\"dot on\"></span>erreichbar"), "{page}");
        assert!(page.contains("<span class=\"dot down\"></span>nicht erreichbar"), "{page}");
        assert!(page.contains("<td>4</td>") && page.contains("<td>10.1.0.0/16</td>"), "{page}");
        assert!(page.contains("Das Relay x steht nicht in RELAY_SERVERS"), "{page}");
        assert!(page.contains("wenigsten Verbindungen"), "{page}");
    }

    #[hbb_common::tokio::test]
    async fn hbbr_answers_the_check_with_its_connections() {
        // A relay on a free port, answering like hbbr behind the proxy.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ws_port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let Ok((stream, addr)) = listener.accept().await else { return };
                tokio::spawn(answer_like_hbbr(stream, addr));
            }
        });
        let up = format!("127.0.0.1:{}", ws_port - 2);
        let down = "127.0.0.1:1".to_owned();
        let pool = RelayPool::default();
        pool.configure(&[up.clone(), down.clone()], "");
        pool.check().await;
        let (relays, _) = pool.snapshot();
        assert_eq!(relays[0].0.up, Some(true), "{:?}", relays[0].0);
        assert_eq!(relays[0].0.connections, 0);
        assert_eq!(relays[1].0.up, Some(false));
        assert!(relays[1].0.checked_at > 0 && !relays[1].0.error.is_empty());
        assert_eq!(pool.pick(ip("203.0.113.1"), ip("203.0.113.2")), Some(up));
    }
}
