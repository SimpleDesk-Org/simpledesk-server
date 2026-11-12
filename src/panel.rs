//! SimpleDesk web panel inside hbbs: first-time setup, login and the device list.
//!
//! It listens on the API port (port - 2, normally 21114) next to the WebSocket port, so the
//! reverse proxy can serve it on port 443. Without an admin the server logs a setup code;
//! only who can read the log can create the first admin.

use crate::common::get_arg;
use crate::peer::PeerMap;
use crate::rendezvous_server::{TcpPeers, REG_TIMEOUT};
use askama::Template;
use axum::{
    extract::{Extension, Form},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Router,
};
use hbb_common::{log, tokio, ResultType};
use serde_derive::Deserialize;
use sodiumoxide::randombytes::randombytes;
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::Mutex;

const COOKIE_NAME: &str = "simpledesk_session";
const SESSION_DURATION: Duration = Duration::from_secs(8 * 60 * 60);
const MIN_PASSWORD_LEN: usize = 12;
const MAX_NAME_LEN: usize = 100;
// Wait after a failed login, so guessing passwords is slow.
pub(crate) const FAILED_LOGIN_DELAY: Duration = Duration::from_secs(1);
// Color of tags created in the panel (ARGB, the panel's blue).
const DEFAULT_TAG_COLOR: i64 = 0xFF1F6FEB;
#[cfg(not(test))]
const BCRYPT_COST: u32 = 12;
#[cfg(test)]
const BCRYPT_COST: u32 = 4;
const SETUP_CODE_CHARS: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

const PANEL_CSS: &str = include_str!("../templates/panel/panel.css");

struct Session {
    user: String,
    expires: Instant,
}

pub(crate) struct Panel {
    pub(crate) pm: PeerMap,
    tcp_peers: TcpPeers,
    sessions: Mutex<HashMap<String, Session>>,
    // Set while no admin exists.
    setup_code: Mutex<Option<String>>,
}

impl Panel {
    pub(crate) async fn new(pm: PeerMap, tcp_peers: TcpPeers) -> ResultType<Self> {
        let _ = sodiumoxide::init();
        let setup_code = if pm.db.count_panel_users().await? == 0 {
            let code = new_setup_code();
            log::info!(
                "SimpleDesk web panel: no admin yet. Setup code: {} (enter it on the panel's first page)",
                code
            );
            Some(code)
        } else {
            None
        };
        Ok(Self {
            pm,
            tcp_peers,
            sessions: Default::default(),
            setup_code: Mutex::new(setup_code),
        })
    }

    async fn user(&self, headers: &HeaderMap) -> Option<String> {
        let token = session_token(headers)?;
        let mut sessions = self.sessions.lock().await;
        sessions.retain(|_, session| session.expires > Instant::now());
        sessions.get(&token).map(|session| session.user.clone())
    }

    async fn start_session(&self, user: String) -> String {
        let token = hex(&randombytes(32));
        self.sessions.lock().await.insert(
            token.clone(),
            Session {
                user,
                expires: Instant::now() + SESSION_DURATION,
            },
        );
        token
    }

    /// Checks a user's password; used by the panel and by the client login.
    pub(crate) async fn check_password(&self, name: &str, password: String) -> bool {
        let hash = match self.pm.db.get_panel_password_hash(name).await {
            Ok(hash) => hash,
            Err(err) => {
                log::error!("SimpleDesk web panel: reading user failed: {}", err);
                None
            }
        };
        let Some(hash) = hash else {
            return false;
        };
        tokio::task::spawn_blocking(move || bcrypt::verify(password, &hash).unwrap_or(false))
            .await
            .unwrap_or(false)
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
    error: &'a str,
}

#[derive(Template)]
#[template(path = "panel/setup.html")]
struct SetupPage<'a> {
    error: &'a str,
    name: &'a str,
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

#[derive(Deserialize)]
struct LoginForm {
    name: String,
    password: String,
}

#[derive(Deserialize)]
struct SetupForm {
    code: String,
    name: String,
    password: String,
    password2: String,
}

/// Starts the panel unless PANEL=N. Errors are logged; the rest of hbbs keeps running.
pub(crate) async fn start(bind_addr: Option<IpAddr>, port: u16, pm: PeerMap, tcp_peers: TcpPeers) {
    if get_arg("PANEL").to_uppercase() == "N" {
        log::info!("SimpleDesk web panel is off (PANEL=N)");
        return;
    }
    let panel = match Panel::new(pm, tcp_peers).await {
        Ok(panel) => Arc::new(panel),
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
        .route("/login", get(login_page).post(login))
        .route("/setup", post(setup))
        .route("/logout", post(logout))
        .route("/ab", get(ab_page))
        .route("/ab/add", post(ab_add))
        .route("/ab/delete", post(ab_delete))
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
    if id.is_empty() || id.len() > MAX_NAME_LEN || id.contains(char::is_whitespace) {
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
    if panel.setup_code.lock().await.is_some() {
        return html(StatusCode::OK, SetupPage { error: "", name: "" }.render());
    }
    html(StatusCode::OK, LoginPage { error: "" }.render())
}

async fn login(Extension(panel): Extension<Arc<Panel>>, Form(form): Form<LoginForm>) -> Response {
    if !panel.check_password(form.name.trim(), form.password).await {
        tokio::time::sleep(FAILED_LOGIN_DELAY).await;
        let page = LoginPage {
            error: "Benutzername oder Passwort ist falsch.",
        };
        return html(StatusCode::UNAUTHORIZED, page.render());
    }
    let token = panel.start_session(form.name.trim().to_owned()).await;
    redirect("/", Some(session_cookie(&token)))
}

async fn setup(Extension(panel): Extension<Arc<Panel>>, Form(form): Form<SetupForm>) -> Response {
    let mut setup_code = panel.setup_code.lock().await;
    let Some(code) = setup_code.clone() else {
        return redirect("/login", None);
    };
    let name = form.name.trim();
    let error = if normalize_code(&form.code) != normalize_code(&code) {
        Some("Der Setup-Code stimmt nicht. Er steht im Log des Servers.")
    } else if name.is_empty() || name.len() > MAX_NAME_LEN {
        Some("Bitte einen Benutzernamen eingeben.")
    } else if form.password.chars().count() < MIN_PASSWORD_LEN {
        Some("Das Passwort muss mindestens 12 Zeichen haben.")
    } else if form.password != form.password2 {
        Some("Die beiden Passwörter sind nicht gleich.")
    } else {
        None
    };
    if let Some(error) = error {
        if normalize_code(&form.code) != normalize_code(&code) {
            tokio::time::sleep(FAILED_LOGIN_DELAY).await;
        }
        return html(StatusCode::BAD_REQUEST, SetupPage { error, name }.render());
    }
    let password = form.password;
    let hash = tokio::task::spawn_blocking(move || bcrypt::hash(password, BCRYPT_COST)).await;
    let hash = match hash {
        Ok(Ok(hash)) => hash,
        _ => {
            log::error!("SimpleDesk web panel: hashing the password failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "Fehler beim Speichern.").into_response();
        }
    };
    if let Err(err) = panel.pm.db.insert_panel_user(name, &hash).await {
        log::error!("SimpleDesk web panel: saving the admin failed: {}", err);
        return (StatusCode::INTERNAL_SERVER_ERROR, "Fehler beim Speichern.").into_response();
    }
    *setup_code = None;
    drop(setup_code);
    log::info!("SimpleDesk web panel: admin {} created", name);
    let token = panel.start_session(name.to_owned()).await;
    redirect("/", Some(session_cookie(&token)))
}

async fn logout(Extension(panel): Extension<Arc<Panel>>, headers: HeaderMap) -> Response {
    if let Some(token) = session_token(&headers) {
        panel.sessions.lock().await.remove(&token);
    }
    redirect(
        "/login",
        Some(format!(
            "{}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0",
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
    let mut res = StatusCode::SEE_OTHER.into_response();
    res.headers_mut()
        .insert(header::LOCATION, HeaderValue::from_static(to));
    if let Some(cookie) = cookie.and_then(|cookie| HeaderValue::from_str(&cookie).ok()) {
        res.headers_mut().insert(header::SET_COOKIE, cookie);
    }
    res
}

fn session_cookie(token: &str) -> String {
    format!(
        "{}={}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age={}",
        COOKIE_NAME,
        token,
        SESSION_DURATION.as_secs()
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

fn new_setup_code() -> String {
    let chars: String = randombytes(8)
        .iter()
        .map(|byte| SETUP_CODE_CHARS[*byte as usize % SETUP_CODE_CHARS.len()] as char)
        .collect();
    format!("{}-{}", &chars[..4], &chars[4..])
}

fn normalize_code(code: &str) -> String {
    code.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_uppercase())
        .collect()
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{:02x}", byte)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
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

    fn cookie_of(res: &Response) -> String {
        let set_cookie = res.headers()[header::SET_COOKIE].to_str().unwrap();
        assert!(set_cookie.contains("HttpOnly") && set_cookie.contains("SameSite=Strict"));
        set_cookie.split(';').next().unwrap().to_owned()
    }

    #[hbb_common::tokio::test]
    async fn setup_then_login_then_device_list() {
        let dir = tempfile::tempdir().unwrap();
        let panel = test_panel(&dir).await;
        let code = panel.setup_code.lock().await.clone().unwrap();

        // Without a session everything leads to the setup page.
        let res = send(&panel, get("/", None)).await;
        assert_eq!(res.status(), StatusCode::SEE_OTHER);
        assert_eq!(location(&res), "/login");
        let page = body(send(&panel, get("/login", None)).await).await;
        assert!(page.contains("Setup-Code"), "{page}");

        // A wrong code or a short password creates no admin.
        let res = send(&panel, post_form("/setup", "code=XXXX-XXXX&name=felix&password=lang-genug-123&password2=lang-genug-123")).await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
        let form = format!("code={code}&name=felix&password=kurz&password2=kurz");
        let res = send(&panel, post_form("/setup", &form)).await;
        assert!(body(res).await.contains("mindestens 12 Zeichen"));
        assert_eq!(panel.pm.db.count_panel_users().await.unwrap(), 0);

        // The right code creates the admin and logs in. The code works only once.
        let lower = code.to_lowercase();
        let form = format!("code={lower}&name=felix&password=lang-genug-123&password2=lang-genug-123");
        let res = send(&panel, post_form("/setup", &form)).await;
        assert_eq!(res.status(), StatusCode::SEE_OTHER);
        let cookie = cookie_of(&res);
        assert_eq!(panel.pm.db.count_panel_users().await.unwrap(), 1);
        let res = send(&panel, post_form("/setup", &form)).await;
        assert_eq!(location(&res), "/login");

        // With the session the device list shows a registered device.
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

        // Login with the right password, not with a wrong one.
        let res = send(&panel, post_form("/login", "name=felix&password=falsch")).await;
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
        let res = send(&panel, post_form("/login", "name=felix&password=lang-genug-123")).await;
        assert_eq!(res.status(), StatusCode::SEE_OTHER);
        let res = send(&panel, get("/", Some(&cookie_of(&res)))).await;
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[hbb_common::tokio::test]
    async fn address_book_page_adds_changes_and_deletes() {
        let dir = tempfile::tempdir().unwrap();
        let panel = test_panel(&dir).await;
        let hash = bcrypt::hash("lang-genug-123", BCRYPT_COST).unwrap();
        panel.pm.db.insert_panel_user("felix", &hash).await.unwrap();
        let res = send(&panel, post_form("/login", "name=felix&password=lang-genug-123")).await;
        let cookie = cookie_of(&res);
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

    #[test]
    fn setup_code_and_cookie_helpers() {
        let code = new_setup_code();
        assert_eq!(code.len(), 9);
        assert_eq!(normalize_code(&code.to_lowercase()), normalize_code(&code));
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("a=1; simpledesk_session=abc; b=2"),
        );
        assert_eq!(session_token(&headers).as_deref(), Some("abc"));
        assert_eq!(hex(&[0, 15, 255]), "000fff");
    }
}
