//! SimpleDesk web panel inside hbbs: login, the device list and the address book.
//!
//! It listens on the API port (port - 2, normally 21114) next to the WebSocket port, so the
//! reverse proxy can serve it on port 443. There are no accounts with a password here: everybody
//! signs in through the OIDC provider (Eider), which checks password, second factor and Lizenz.

use crate::common::get_arg;
use crate::oidc::{Oidc, OidcConfig, Purpose};
use crate::peer::PeerMap;
use crate::rendezvous_server::{TcpPeers, REG_TIMEOUT};
use askama::Template;
use axum::{
    extract::{Extension, Form, Query},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Router,
};
use crate::api::token_hash;
use hbb_common::{log, ResultType};
use serde_derive::Deserialize;
use sodiumoxide::randombytes::randombytes;
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
};

const COOKIE_NAME: &str = "simpledesk_session";
const MAX_ID_LEN: usize = 100;
// Color of tags created in the panel (ARGB, the panel's blue).
const DEFAULT_TAG_COLOR: i64 = 0xFF1F6FEB;

const PANEL_CSS: &str = include_str!("../templates/panel/panel.css");

pub(crate) struct Panel {
    pub(crate) pm: PeerMap,
    tcp_peers: TcpPeers,
    /// Login through an OIDC provider such as Eider. Without it nobody can sign in.
    pub(crate) oidc: Option<Oidc>,
    /// The key clients need, the same text as id_ed25519.pub.
    pub(crate) public_key: String,
}

impl Panel {
    pub(crate) async fn new(pm: PeerMap, tcp_peers: TcpPeers) -> ResultType<Self> {
        let _ = sodiumoxide::init();
        let oidc = OidcConfig::from_args().and_then(|config| match Oidc::new(config) {
            Ok(oidc) => {
                log::info!("SimpleDesk web panel: login through {} ({})", oidc.config.name, oidc.config.issuer);
                Some(oidc)
            }
            Err(err) => {
                log::error!("SimpleDesk OIDC is off: {}", err);
                None
            }
        });
        if oidc.is_none() {
            log::warn!("SimpleDesk web panel: no OIDC provider (OIDC_ISSUER), so nobody can sign in");
        }
        Ok(Self {
            pm,
            tcp_peers,
            oidc,
            public_key: String::new(),
        })
    }

    pub(crate) fn with_public_key(mut self, key: String) -> Self {
        self.public_key = key;
        self
    }

    #[cfg(test)]
    pub(crate) fn with_oidc(mut self, oidc: Oidc) -> Self {
        self.oidc = Some(oidc);
        self
    }

    pub(crate) fn oidc_name(&self) -> &str {
        self.oidc.as_ref().map(|oidc| oidc.config.name.as_str()).unwrap_or_default()
    }

    /// The user of the session cookie, if the session is younger than PANEL_SESSION_HOURS.
    async fn user(&self, headers: &HeaderMap) -> Option<String> {
        let token = session_token(headers)?;
        match self
            .pm
            .db
            .get_panel_session_user(&token_hash(&token), self.pm.accounts.session_hours)
            .await
        {
            Ok(user) => user,
            Err(err) => {
                log::error!("SimpleDesk web panel: reading the session failed: {}", err);
                None
            }
        }
    }

    /// A new session for the user; the database keeps only its hash.
    async fn start_session(&self, user: &str) -> ResultType<String> {
        let accounts = &self.pm.accounts;
        if let Err(err) = self
            .pm
            .db
            .delete_expired_logins(accounts.token_days, accounts.session_hours)
            .await
        {
            log::warn!("SimpleDesk web panel: removing expired logins failed: {}", err);
        }
        let token = hex(&randombytes(32));
        self.pm.db.insert_panel_session(&token_hash(&token), user).await?;
        Ok(token)
    }

    async fn ab_entries(&self, user: &str) -> ResultType<Vec<AbEntry>> {
        let guid = self.pm.db.personal_ab(user).await?;
        let mut entries = Vec::new();
        for data in self.pm.db.list_ab_peers(&guid).await? {
            let Ok(serde_json::Value::Object(peer)) = serde_json::from_str(&data) else {
                continue;
            };
            let text = |key: &str| {
                peer.get(key)
                    .and_then(|value| value.as_str())
                    .unwrap_or_default()
                    .to_owned()
            };
            let tags = peer
                .get("tags")
                .and_then(|tags| tags.as_array())
                .map(|tags| {
                    tags.iter()
                        .filter_map(|tag| tag.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_default();
            entries.push(AbEntry {
                id: text("id"),
                alias: text("alias"),
                tags,
                note: text("note"),
            });
        }
        Ok(entries)
    }

    async fn devices(&self) -> ResultType<Vec<Device>> {
        let mut devices = Vec::new();
        for (id, info, registered) in self.pm.db.list_peers().await? {
            let ip = serde_json::from_str::<serde_json::Value>(&info)
                .ok()
                .and_then(|info| info.get("ip").and_then(|ip| ip.as_str()).map(str::to_owned))
                .unwrap_or_default();
            let (online, websocket) = match self.pm.get_in_memory(&id).await {
                Some(peer) => {
                    let peer = peer.read().await;
                    let online = (peer.last_reg_time.elapsed().as_millis() as i64) < REG_TIMEOUT;
                    let websocket =
                        online && self.tcp_peers.lock().await.contains_key(&peer.socket_addr);
                    (online, websocket)
                }
                None => (false, false),
            };
            devices.push(Device {
                id,
                online,
                websocket,
                ip,
                registered,
            });
        }
        Ok(devices)
    }
}

pub(crate) struct Device {
    pub(crate) id: String,
    pub(crate) online: bool,
    pub(crate) websocket: bool,
    pub(crate) ip: String,
    pub(crate) registered: String,
}

#[derive(Template)]
#[template(path = "panel/login.html")]
struct LoginPage<'a> {
    /// Name of the OIDC provider for the button, empty without one.
    oidc_name: &'a str,
}

/// The end of a login through the provider that the panel does not continue: a client's
/// login, or an error.
#[derive(Template)]
#[template(path = "panel/oidc_done.html")]
struct OidcDonePage<'a> {
    ok: bool,
    message: &'a str,
}

#[derive(Deserialize)]
struct CallbackQuery {
    #[serde(default)]
    code: String,
    #[serde(default)]
    state: String,
    #[serde(default)]
    error: String,
}

#[derive(Template)]
#[template(path = "panel/devices.html")]
struct DevicesPage<'a> {
    user: &'a str,
    active: &'a str,
    devices: &'a [Device],
    online: usize,
}

pub(crate) struct AbEntry {
    pub(crate) id: String,
    pub(crate) alias: String,
    pub(crate) tags: String,
    pub(crate) note: String,
}

#[derive(Template)]
#[template(path = "panel/ab.html")]
struct AbPage<'a> {
    user: &'a str,
    active: &'a str,
    entries: &'a [AbEntry],
    error: &'a str,
}

#[derive(Deserialize)]
struct AbAddForm {
    id: String,
    #[serde(default)]
    alias: String,
    #[serde(default)]
    tags: String,
    #[serde(default)]
    note: String,
}

#[derive(Deserialize)]
struct AbDeleteForm {
    id: String,
}

/// Starts the panel unless PANEL=N. Errors are logged; the rest of hbbs keeps running.
pub(crate) async fn start(
    bind_addr: Option<IpAddr>,
    port: u16,
    pm: PeerMap,
    tcp_peers: TcpPeers,
    public_key: String,
) {
    if get_arg("PANEL").to_uppercase() == "N" {
        log::info!("SimpleDesk web panel is off (PANEL=N)");
        return;
    }
    let panel = match Panel::new(pm, tcp_peers).await {
        Ok(panel) => Arc::new(panel.with_public_key(public_key)),
        Err(err) => {
            log::error!("SimpleDesk web panel failed to start: {}", err);
            return;
        }
    };
    let addr = SocketAddr::new(bind_addr.unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED)), port);
    match axum::Server::try_bind(&addr) {
        Ok(server) => {
            log::info!("SimpleDesk web panel listening on http://{}", addr);
            if let Err(err) = server.serve(router(panel).into_make_service()).await {
                log::error!("SimpleDesk web panel stopped: {}", err);
            }
        }
        Err(err) => log::error!("SimpleDesk web panel could not listen on {}: {}", addr, err),
    }
}

pub(crate) fn router(panel: Arc<Panel>) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/login", get(login_page))
        .route("/logout", post(logout))
        .route("/ab", get(ab_page))
        .route("/ab/add", post(ab_add))
        .route("/ab/delete", post(ab_delete))
        .route("/oidc/login", get(oidc_login))
        .route("/oidc/callback", get(oidc_callback))
        .route("/panel.css", get(css))
        .merge(crate::api::routes())
        .layer(Extension(panel))
}

async fn index(Extension(panel): Extension<Arc<Panel>>, headers: HeaderMap) -> Response {
    let Some(user) = panel.user(&headers).await else {
        return redirect("/login", None);
    };
    let devices = match panel.devices().await {
        Ok(devices) => devices,
        Err(err) => {
            log::error!("SimpleDesk web panel: reading devices failed: {}", err);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Geräte konnten nicht gelesen werden.")
                .into_response();
        }
    };
    let online = devices.iter().filter(|device| device.online).count();
    html(
        StatusCode::OK,
        DevicesPage {
            user: &user,
            active: "devices",
            devices: &devices,
            online,
        }
        .render(),
    )
}

async fn render_ab(panel: &Panel, user: &str, status: StatusCode, error: &str) -> Response {
    match panel.ab_entries(user).await {
        Ok(entries) => html(
            status,
            AbPage {
                user,
                active: "ab",
                entries: &entries,
                error,
            }
            .render(),
        ),
        Err(err) => {
            log::error!("SimpleDesk web panel: reading the address book failed: {}", err);
            (StatusCode::INTERNAL_SERVER_ERROR, "Adressbuch konnte nicht gelesen werden.")
                .into_response()
        }
    }
}

async fn ab_page(Extension(panel): Extension<Arc<Panel>>, headers: HeaderMap) -> Response {
    let Some(user) = panel.user(&headers).await else {
        return redirect("/login", None);
    };
    render_ab(&panel, &user, StatusCode::OK, "").await
}

/// Adds an entry to the personal address book or changes alias, tags and note of an
/// existing one. Other fields the client stored (hash, username, ...) are kept.
async fn ab_add(
    Extension(panel): Extension<Arc<Panel>>,
    headers: HeaderMap,
    Form(form): Form<AbAddForm>,
) -> Response {
    let Some(user) = panel.user(&headers).await else {
        return redirect("/login", None);
    };
    let id = form.id.trim();
    if id.is_empty() || id.len() > MAX_ID_LEN || id.contains(char::is_whitespace) {
        let error = "Bitte eine gültige ID eingeben (ohne Leerzeichen).";
        return render_ab(&panel, &user, StatusCode::BAD_REQUEST, error).await;
    }
    let tags: Vec<String> = form
        .tags
        .split(',')
        .map(str::trim)
        .filter(|tag| !tag.is_empty())
        .map(str::to_owned)
        .collect();
    let result: ResultType<()> = async {
        let db = &panel.pm.db;
        let guid = db.personal_ab(&user).await?;
        let mut peer = match db.get_ab_peer(&guid, id).await? {
            Some(data) => match serde_json::from_str(&data) {
                Ok(serde_json::Value::Object(peer)) => peer,
                _ => serde_json::Map::new(),
            },
            None => serde_json::Map::new(),
        };
        peer.insert("id".to_owned(), id.into());
        peer.insert("alias".to_owned(), form.alias.trim().into());
        peer.insert("tags".to_owned(), tags.clone().into());
        peer.insert("note".to_owned(), form.note.trim().into());
        db.upsert_ab_peer(&guid, id, &serde_json::Value::Object(peer).to_string())
            .await?;
        let known: Vec<String> = db
            .list_ab_tags(&guid)
            .await?
            .into_iter()
            .map(|(name, _)| name)
            .collect();
        for tag in tags.iter().filter(|tag| !known.contains(tag)) {
            db.upsert_ab_tag(&guid, tag, DEFAULT_TAG_COLOR).await?;
        }
        Ok(())
    }
    .await;
    if let Err(err) = result {
        log::error!("SimpleDesk web panel: saving the entry failed: {}", err);
        return render_ab(&panel, &user, StatusCode::INTERNAL_SERVER_ERROR, "Speichern hat nicht geklappt.").await;
    }
    redirect("/ab", None)
}

async fn ab_delete(
    Extension(panel): Extension<Arc<Panel>>,
    headers: HeaderMap,
    Form(form): Form<AbDeleteForm>,
) -> Response {
    let Some(user) = panel.user(&headers).await else {
        return redirect("/login", None);
    };
    let result: ResultType<()> = async {
        let guid = panel.pm.db.personal_ab(&user).await?;
        panel.pm.db.delete_ab_peer(&guid, form.id.trim()).await
    }
    .await;
    if let Err(err) = result {
        log::error!("SimpleDesk web panel: deleting the entry failed: {}", err);
    }
    redirect("/ab", None)
}

async fn login_page(Extension(panel): Extension<Arc<Panel>>, headers: HeaderMap) -> Response {
    if panel.user(&headers).await.is_some() {
        return redirect("/", None);
    }
    let page = LoginPage {
        oidc_name: panel.oidc_name(),
    };
    html(StatusCode::OK, page.render())
}

/// "Mit Eider anmelden": off to the provider.
async fn oidc_login(Extension(panel): Extension<Arc<Panel>>) -> Response {
    let Some(oidc) = panel.oidc.as_ref() else {
        return redirect("/login", None);
    };
    match oidc.start(Purpose::Panel).await {
        Ok(url) => redirect_to(&url, None),
        Err(err) => {
            log::error!("SimpleDesk OIDC: starting the login failed: {}", err);
            oidc_done(false, "Die Anmeldung ist gerade nicht erreichbar. Bitte später noch einmal.")
        }
    }
}

/// The provider sends the browser back here, for the panel and for clients.
async fn oidc_callback(
    Extension(panel): Extension<Arc<Panel>>,
    Query(query): Query<CallbackQuery>,
) -> Response {
    let Some(oidc) = panel.oidc.as_ref() else {
        return redirect("/login", None);
    };
    if !query.error.is_empty() || query.code.is_empty() || query.state.is_empty() {
        return oidc_done(false, "Die Anmeldung wurde abgebrochen oder abgelehnt.");
    }
    let (user, purpose) = match oidc.finish(&query.code, &query.state).await {
        Ok(done) => done,
        Err(err) => {
            log::warn!("SimpleDesk OIDC: login failed: {}", err);
            return oidc_done(false, "Die Anmeldung hat nicht geklappt. Bitte noch einmal versuchen.");
        }
    };
    // An account from the provider has no password of its own here.
    if let Err(err) = panel.pm.db.ensure_external_user(&user).await {
        log::error!("SimpleDesk OIDC: saving user {} failed: {}", user, err);
        return oidc_done(false, "Fehler beim Speichern.");
    }
    match purpose {
        Purpose::Panel => match panel.start_session(&user).await {
            Ok(token) => {
                log::info!("SimpleDesk web panel: {} signed in through {}", user, oidc.config.name);
                let hours = panel.pm.accounts.session_hours;
                redirect("/", Some(session_cookie(&token, hours)))
            }
            Err(err) => {
                log::error!("SimpleDesk web panel: saving the session of {} failed: {}", user, err);
                oidc_done(false, "Fehler beim Speichern.")
            }
        },
        Purpose::Client(code) => match oidc.client_login_done(&code, &user).await {
            // Naming the device makes a login for somebody else's device stand out.
            Some(device) => oidc_done(
                true,
                &format!(
                    "Das Gerät {} ist jetzt mit deinem Konto angemeldet. Du kannst dieses Fenster schließen. Ist das nicht dein Gerät, sag bitte sofort der IT Bescheid.",
                    device
                ),
            ),
            None => oidc_done(false, "Die Anmeldung hat zu lange gedauert. Bitte im Programm noch einmal starten."),
        },
    }
}

fn oidc_done(ok: bool, message: &str) -> Response {
    let status = if ok { StatusCode::OK } else { StatusCode::BAD_REQUEST };
    html(status, OidcDonePage { ok, message }.render())
}

async fn logout(Extension(panel): Extension<Arc<Panel>>, headers: HeaderMap) -> Response {
    if let Some(token) = session_token(&headers) {
        if let Err(err) = panel.pm.db.delete_panel_session(&token_hash(&token)).await {
            log::error!("SimpleDesk web panel: deleting the session failed: {}", err);
        }
    }
    redirect(
        "/login",
        Some(format!(
            "{}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0",
            COOKIE_NAME
        )),
    )
}

async fn css() -> Response {
    let mut res = PANEL_CSS.into_response();
    res.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/css; charset=utf-8"),
    );
    res
}

fn html(status: StatusCode, page: askama::Result<String>) -> Response {
    match page {
        Ok(page) => (status, Html(page)).into_response(),
        Err(err) => {
            log::error!("SimpleDesk web panel: rendering failed: {}", err);
            (StatusCode::INTERNAL_SERVER_ERROR, "Fehler beim Anzeigen.").into_response()
        }
    }
}

fn redirect(to: &'static str, cookie: Option<String>) -> Response {
    redirect_to(to, cookie)
}

fn redirect_to(to: &str, cookie: Option<String>) -> Response {
    let Ok(location) = HeaderValue::from_str(to) else {
        return (StatusCode::INTERNAL_SERVER_ERROR, "Ungültige Weiterleitung.").into_response();
    };
    let mut res = StatusCode::SEE_OTHER.into_response();
    res.headers_mut().insert(header::LOCATION, location);
    if let Some(cookie) = cookie.and_then(|cookie| HeaderValue::from_str(&cookie).ok()) {
        res.headers_mut().insert(header::SET_COOKIE, cookie);
    }
    res
}

/// Lax, not Strict: after the login at the provider the browser comes back from another site,
/// and a Strict cookie set on the callback would not go along with the redirect to "/", so the
/// login would end on the login page again. Lax still keeps the cookie off cross-site POSTs.
fn session_cookie(token: &str, hours: i64) -> String {
    format!(
        "{}={}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age={}",
        COOKIE_NAME,
        token,
        hours * 60 * 60
    )
}

fn session_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .find_map(|pair| {
            let (name, value) = pair.trim().split_once('=')?;
            (name == COOKIE_NAME && !value.is_empty()).then(|| value.to_owned())
        })
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{:02x}", byte)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use hbb_common::tokio;
    use tower::ServiceExt;

    async fn test_panel(dir: &tempfile::TempDir) -> Arc<Panel> {
        let pm = crate::peer::test_peer_map(dir).await;
        Arc::new(Panel::new(pm, Default::default()).await.unwrap())
    }

    async fn send(panel: &Arc<Panel>, req: Request<Body>) -> Response {
        router(panel.clone()).oneshot(req).await.unwrap()
    }

    fn get(path: &str, cookie: Option<&str>) -> Request<Body> {
        let mut req = Request::get(path);
        if let Some(cookie) = cookie {
            req = req.header(header::COOKIE, cookie);
        }
        req.body(Body::empty()).unwrap()
    }

    fn post_form(path: &str, form: &str) -> Request<Body> {
        Request::post(path)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(form.to_owned()))
            .unwrap()
    }

    async fn body(res: Response) -> String {
        let bytes = hyper::body::to_bytes(res.into_body()).await.unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    fn location(res: &Response) -> &str {
        res.headers()[header::LOCATION].to_str().unwrap()
    }

    /// A session as the provider login leaves it (the login itself is tested in oidc.rs).
    async fn signed_in(panel: &Arc<Panel>, user: &str) -> String {
        panel.pm.db.ensure_external_user(user).await.unwrap();
        format!("{}={}", COOKIE_NAME, panel.start_session(user).await.unwrap())
    }

    #[hbb_common::tokio::test]
    async fn no_password_login_and_device_list_needs_a_session() {
        let dir = tempfile::tempdir().unwrap();
        let panel = test_panel(&dir).await;

        // Without a session everything leads to the login page.
        let res = send(&panel, get("/", None)).await;
        assert_eq!(res.status(), StatusCode::SEE_OTHER);
        assert_eq!(location(&res), "/login");

        // There is nothing to type in: no user name, no password, no setup.
        let page = body(send(&panel, get("/login", None)).await).await;
        assert!(!page.contains("<input") && !page.contains("Passwort"), "{page}");
        assert!(page.contains("nicht eingerichtet"), "{page}");
        let res = send(&panel, post_form("/login", "name=felix&password=lang-genug-123")).await;
        assert_eq!(res.status(), StatusCode::METHOD_NOT_ALLOWED);
        let res = send(&panel, post_form("/setup", "code=ABCD-EFGH&name=felix")).await;
        assert_eq!(res.status(), StatusCode::NOT_FOUND);

        // With a session the device list shows a registered device.
        let cookie = signed_in(&panel, "felix").await;
        panel
            .pm
            .db
            .insert_peer("Felix-Work-PC", b"uuid", b"pk", r#"{"ip":"203.0.113.7"}"#)
            .await
            .unwrap();
        let res = send(&panel, get("/", Some(&cookie))).await;
        assert_eq!(res.status(), StatusCode::OK);
        let page = body(res).await;
        assert!(page.contains("Felix-Work-PC") && page.contains("203.0.113.7"), "{page}");
        assert!(page.contains("offline"));

        // Logout ends the session.
        let mut req = post_form("/logout", "");
        req.headers_mut()
            .insert(header::COOKIE, HeaderValue::from_str(&cookie).unwrap());
        send(&panel, req).await;
        let res = send(&panel, get("/", Some(&cookie))).await;
        assert_eq!(location(&res), "/login");
    }

    #[hbb_common::tokio::test]
    async fn address_book_page_adds_changes_and_deletes() {
        let dir = tempfile::tempdir().unwrap();
        let panel = test_panel(&dir).await;
        let cookie = signed_in(&panel, "felix").await;
        let with_cookie = |mut req: Request<Body>| {
            req.headers_mut()
                .insert(header::COOKIE, HeaderValue::from_str(&cookie).unwrap());
            req
        };

        // Without a session the page leads to the login.
        assert_eq!(location(&send(&panel, get("/ab", None)).await), "/login");

        let form = "id=Felix-Home-PC&alias=Zuhause&tags=Amt%2C+Server&note=B%C3%BCro";
        let res = send(&panel, with_cookie(post_form("/ab/add", form))).await;
        assert_eq!(location(&res), "/ab");
        let page = body(send(&panel, get("/ab", Some(&cookie))).await).await;
        assert!(page.contains("Felix-Home-PC") && page.contains("Zuhause"), "{page}");
        assert!(page.contains("Amt, Server") && page.contains("Büro"), "{page}");

        // The client sees the entry and its tags; a hash it stored is kept on change.
        let guid = panel.pm.db.personal_ab("felix").await.unwrap();
        let tags = panel.pm.db.list_ab_tags(&guid).await.unwrap();
        assert_eq!(tags.len(), 2);
        let stored = r#"{"id":"Felix-Home-PC","alias":"Zuhause","tags":["Amt"],"hash":"abc"}"#;
        panel.pm.db.upsert_ab_peer(&guid, "Felix-Home-PC", stored).await.unwrap();
        let form = "id=Felix-Home-PC&alias=Daheim&tags=Amt&note=";
        send(&panel, with_cookie(post_form("/ab/add", form))).await;
        let data = panel.pm.db.get_ab_peer(&guid, "Felix-Home-PC").await.unwrap().unwrap();
        let data: serde_json::Value = serde_json::from_str(&data).unwrap();
        assert_eq!(data["alias"], "Daheim");
        assert_eq!(data["hash"], "abc");

        // An ID with spaces is refused, deleting removes the entry.
        let res = send(&panel, with_cookie(post_form("/ab/add", "id=mit+leerzeichen"))).await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
        send(&panel, with_cookie(post_form("/ab/delete", "id=Felix-Home-PC"))).await;
        assert!(panel.pm.db.list_ab_peers(&guid).await.unwrap().is_empty());
    }

    #[hbb_common::tokio::test]
    async fn panel_session_ends_after_the_configured_hours() {
        let dir = tempfile::tempdir().unwrap();
        let panel = test_panel(&dir).await;
        let cookie = signed_in(&panel, "felix").await;
        assert_eq!(send(&panel, get("/", Some(&cookie))).await.status(), StatusCode::OK);
        // The session is in the database, so it survives a restart of hbbs.
        let restarted = Arc::new(Panel::new(panel.pm.clone(), Default::default()).await.unwrap());
        assert_eq!(send(&restarted, get("/", Some(&cookie))).await.status(), StatusCode::OK);
        // One hour before the end it still works, after the end it leads to the login.
        let hours = panel.pm.accounts.session_hours;
        panel.pm.db.age_logins("felix", hours - 1).await.unwrap();
        assert_eq!(send(&panel, get("/", Some(&cookie))).await.status(), StatusCode::OK);
        panel.pm.db.age_logins("felix", 2).await.unwrap();
        let res = send(&panel, get("/", Some(&cookie))).await;
        assert_eq!(location(&res), "/login");
    }

    #[test]
    fn cookie_helpers() {
        let cookie = session_cookie("abc", 8);
        assert!(cookie.contains("HttpOnly") && cookie.contains("Secure") && cookie.contains("SameSite=Lax"));
        assert!(cookie.contains("Max-Age=28800"), "{cookie}");
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("a=1; simpledesk_session=abc; b=2"),
        );
        assert_eq!(session_token(&headers).as_deref(), Some("abc"));
        assert_eq!(hex(&[0, 15, 255]), "000fff");
    }
}
