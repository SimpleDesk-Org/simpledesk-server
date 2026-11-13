//! SimpleDesk web panel inside hbbs: login, the device list and the address book, and for
//! admins (ADMIN_USERS) the users, groups and owners of devices.
//!
//! It listens on the API port (port - 2, normally 21114) next to the WebSocket port, so the
//! reverse proxy can serve it on port 443. There are no accounts with a password here: everybody
//! signs in through the OIDC provider (Eider), which checks password, second factor and Lizenz.

use crate::common::get_arg;
use crate::oidc::{Oidc, OidcConfig, Purpose};
use crate::api::{RULE_FULL, RULE_READ, RULE_WRITE};
use crate::database::{AbRow, DeviceRow};
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

    /// The address book of a page or form (`book` is its guid, empty for the personal book)
    /// with the rule `user` has on it; None if the user may not read it.
    async fn book_of(&self, user: &str, book: &str) -> ResultType<Option<(AbRow, i64)>> {
        let guid = match book.trim() {
            "" => self.pm.db.personal_ab(user).await?,
            guid => guid.to_owned(),
        };
        crate::api::ab_access(&self.pm, user, &guid).await
    }

    async fn ab_entries(&self, guid: &str) -> ResultType<Vec<AbEntry>> {
        let mut entries = Vec::new();
        for data in self.pm.db.list_ab_peers(guid).await? {
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

    /// The devices `user` may see: all for an admin, else the own ones and those of the
    /// user's groups. For an admin each device also gets the choices to assign it.
    /// With IDS_BY_ADMIN, devices without an ID from an admin are listed apart as new
    /// devices, for admins only, and an old row of a device under another ID is left out.
    async fn devices(&self, user: &str) -> ResultType<(Vec<Device>, Vec<NewDevice>)> {
        let admin = self.pm.accounts.is_admin(user);
        let ids_by_admin = self.pm.accounts.ids_by_admin;
        let groups = self.pm.db.user_groups(user).await?;
        let (all_users, all_groups) = if admin {
            let users: Vec<String> = self.pm.db.list_users().await?.into_iter().map(|row| row.name).collect();
            (users, self.pm.db.list_groups().await?)
        } else {
            Default::default()
        };
        let rows = self.pm.db.list_devices().await?;
        let ids: Vec<String> = rows.iter().map(|row| row.id.clone()).collect();
        let mut devices = Vec::new();
        let mut new_devices = Vec::new();
        for row in rows {
            let sysinfo = serde_json::from_str::<serde_json::Value>(&row.sysinfo).unwrap_or_default();
            let ip = serde_json::from_str::<serde_json::Value>(&row.info)
                .ok()
                .and_then(|info| info.get("ip").and_then(|ip| ip.as_str()).map(str::to_owned))
                .unwrap_or_default();
            if ids_by_admin {
                match row.assigned_id.as_deref() {
                    None => {
                        if admin {
                            let text = |key: &str| sysinfo.get(key).and_then(|value| value.as_str()).unwrap_or_default().to_owned();
                            new_devices.push(NewDevice {
                                id: row.id,
                                hostname: text("hostname"),
                                username: text("username"),
                                os: text("os"),
                                ip,
                                first_seen: row.registered,
                            });
                        }
                        continue;
                    }
                    // The device has another row under the ID it was given.
                    Some(assigned) if assigned != row.id && ids.iter().any(|id| id == assigned) => continue,
                    Some(_) => {}
                }
            }
            let visible = admin
                || (!row.owner.is_empty() && row.owner == user)
                || (!row.group.is_empty() && groups.contains(&row.group));
            if !visible {
                continue;
            }
            let DeviceRow {
                id,
                registered,
                owner,
                group,
                assigned_id,
                ..
            } = row;
            let pending_id = assigned_id.filter(|assigned| *assigned != id).unwrap_or_default();
            let (owner_choices, group_choices) = if admin {
                (
                    choices("niemand", &all_users, &owner),
                    choices("keine", &all_groups, &group),
                )
            } else {
                Default::default()
            };
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
                owner,
                group,
                owner_choices,
                group_choices,
                pending_id,
            });
        }
        Ok((devices, new_devices))
    }
}

/// A device that has no ID from an admin yet (IDS_BY_ADMIN).
pub(crate) struct NewDevice {
    /// The ID the device made up itself.
    pub(crate) id: String,
    pub(crate) hostname: String,
    pub(crate) username: String,
    pub(crate) os: String,
    pub(crate) ip: String,
    pub(crate) first_seen: String,
}

pub(crate) struct Device {
    pub(crate) id: String,
    pub(crate) online: bool,
    pub(crate) websocket: bool,
    pub(crate) ip: String,
    pub(crate) registered: String,
    /// The ID an admin gave the device that it has not taken yet, '' for none.
    pub(crate) pending_id: String,
    /// User the device belongs to, '' for none.
    pub(crate) owner: String,
    /// Group the device belongs to, '' for none.
    pub(crate) group: String,
    /// For admins: the options of the owner and group fields.
    pub(crate) owner_choices: Vec<Choice>,
    pub(crate) group_choices: Vec<Choice>,
}

/// An option of a select field.
pub(crate) struct Choice {
    pub(crate) value: String,
    pub(crate) label: String,
    pub(crate) selected: bool,
}

/// The options for picking one of `names` or none (`none` is the label for '').
fn choices(none: &str, names: &[String], current: &str) -> Vec<Choice> {
    let mut list = vec![Choice {
        value: String::new(),
        label: format!("– {} –", none),
        selected: current.is_empty(),
    }];
    list.extend(names.iter().map(|name| Choice {
        value: name.clone(),
        label: name.clone(),
        selected: name == current,
    }));
    list
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
    admin: bool,
    active: &'a str,
    devices: &'a [Device],
    /// For admins with IDS_BY_ADMIN: devices that wait for an ID.
    new_devices: &'a [NewDevice],
    ids_by_admin: bool,
    online: usize,
    error: &'a str,
}

#[derive(Deserialize)]
struct SetIdForm {
    id: String,
    #[serde(default)]
    new_id: String,
}

#[derive(Deserialize)]
struct AssignForm {
    id: String,
    #[serde(default)]
    owner: String,
    #[serde(default)]
    group: String,
}

/// A user on the page "Benutzer".
pub(crate) struct UserView {
    pub(crate) name: String,
    pub(crate) admin: bool,
    pub(crate) blocked: bool,
    /// The user's own row: no "Sperren".
    pub(crate) me: bool,
    pub(crate) groups: Vec<String>,
    /// Groups the user is not in yet, for "hinzufügen".
    pub(crate) other_groups: Vec<String>,
    pub(crate) last_login: String,
    pub(crate) last_active: String,
}

pub(crate) struct GroupView {
    pub(crate) name: String,
    pub(crate) members: usize,
}

#[derive(Template)]
#[template(path = "panel/users.html")]
struct UsersPage<'a> {
    user: &'a str,
    admin: bool,
    active: &'a str,
    oidc_name: &'a str,
    users: &'a [UserView],
    groups: &'a [GroupView],
    error: &'a str,
}

#[derive(Deserialize)]
struct NameForm {
    name: String,
}

#[derive(Deserialize)]
struct MemberForm {
    user: String,
    group: String,
}

pub(crate) struct AbEntry {
    pub(crate) id: String,
    pub(crate) alias: String,
    pub(crate) tags: String,
    pub(crate) note: String,
}

/// A link to one of the books on the address book page.
pub(crate) struct BookLink {
    pub(crate) href: String,
    pub(crate) name: String,
    /// "lesen", "schreiben" or "voll" for shared books, '' for the personal book.
    pub(crate) right: String,
    pub(crate) current: bool,
}

/// Who a shared book is shared with.
pub(crate) struct ShareView {
    /// "user" or "group".
    pub(crate) kind: String,
    pub(crate) name: String,
    pub(crate) right: &'static str,
}

#[derive(Template)]
#[template(path = "panel/ab.html")]
struct AbPage<'a> {
    user: &'a str,
    admin: bool,
    active: &'a str,
    books: &'a [BookLink],
    book: &'a AbRow,
    /// What the user may do here: "lesen", "schreiben" or "voll".
    right: &'a str,
    can_write: bool,
    /// Shared and with full control: share, rename and delete.
    full: bool,
    entries: &'a [AbEntry],
    shares: &'a [ShareView],
    /// For sharing: all groups and users.
    groups: &'a [String],
    users: &'a [String],
    error: &'a str,
}

#[derive(Deserialize)]
struct BookQuery {
    #[serde(default)]
    book: String,
}

#[derive(Deserialize)]
struct AbAddForm {
    #[serde(default)]
    book: String,
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
    #[serde(default)]
    book: String,
    id: String,
}

#[derive(Deserialize)]
struct BookForm {
    #[serde(default)]
    book: String,
    #[serde(default)]
    name: String,
}

#[derive(Deserialize)]
struct ShareForm {
    book: String,
    /// "user:<name>" or "group:<name>".
    who: String,
    rule: i64,
}

#[derive(Deserialize)]
struct UnshareForm {
    book: String,
    kind: String,
    name: String,
}

/// Names the client already uses for its own books; a shared book with such a name would get
/// mixed up with them.
const RESERVED_BOOK_NAMES: [&str; 3] = ["My address book", "Legacy address book", "Mein Adressbuch"];

fn right_label(rule: i64) -> &'static str {
    match rule {
        RULE_READ => "lesen",
        RULE_WRITE => "schreiben",
        _ => "voll",
    }
}

fn book_href(book: &AbRow) -> String {
    if book.personal {
        "/ab".to_owned()
    } else {
        format!("/ab?book={}", book.guid)
    }
}

/// A usable name for a shared book.
fn book_name(name: &str) -> Result<&str, &'static str> {
    let name = name.trim();
    if name.is_empty() || name.chars().count() > 100 {
        return Err("Bitte einen Namen für das Adressbuch eingeben (höchstens 100 Zeichen).");
    }
    if RESERVED_BOOK_NAMES.iter().any(|reserved| reserved.eq_ignore_ascii_case(name)) {
        return Err("So heißt schon das eigene Adressbuch. Bitte einen anderen Namen wählen.");
    }
    Ok(name)
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
        .route("/ab/new", post(ab_new))
        .route("/ab/share", post(ab_share))
        .route("/ab/unshare", post(ab_unshare))
        .route("/ab/rename", post(ab_rename))
        .route("/ab/remove", post(ab_remove))
        .route("/devices/assign", post(devices_assign))
        .route("/devices/set-id", post(devices_set_id))
        .route("/users", get(users_page))
        .route("/users/signout", post(users_signout))
        .route("/users/block", post(users_block))
        .route("/users/unblock", post(users_unblock))
        .route("/groups/new", post(groups_new))
        .route("/groups/delete", post(groups_delete))
        .route("/groups/join", post(groups_join))
        .route("/groups/leave", post(groups_leave))
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
    render_devices(&panel, &user, StatusCode::OK, "").await
}

async fn render_devices(panel: &Panel, user: &str, status: StatusCode, error: &str) -> Response {
    let (devices, new_devices) = match panel.devices(user).await {
        Ok(devices) => devices,
        Err(err) => {
            log::error!("SimpleDesk web panel: reading devices failed: {}", err);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Geräte konnten nicht gelesen werden.")
                .into_response();
        }
    };
    let online = devices.iter().filter(|device| device.online).count();
    html(
        status,
        DevicesPage {
            user,
            admin: panel.pm.accounts.is_admin(user),
            active: "devices",
            devices: &devices,
            new_devices: &new_devices,
            ids_by_admin: panel.pm.accounts.ids_by_admin,
            online,
            error,
        }
        .render(),
    )
}

/// Admins give a new device its ID ("ID vergeben") or change the ID of a device
/// ("ID ändern"). The device takes it with its next heartbeat, a few seconds later.
async fn devices_set_id(
    Extension(panel): Extension<Arc<Panel>>,
    headers: HeaderMap,
    Form(form): Form<SetIdForm>,
) -> Response {
    let admin = match admin_of(&panel, &headers).await {
        Ok(admin) => admin,
        Err(res) => return res,
    };
    let id = form.id.trim();
    let result: ResultType<Result<(), &str>> = async {
        let Some(uuid) = panel.pm.db.device_uuid(id).await? else {
            return Ok(Err("Dieses Gerät gibt es nicht."));
        };
        crate::api::assign_id(&panel.pm, id, &uuid, &form.new_id).await
    }
    .await;
    match result {
        Ok(Ok(())) => {
            log::info!("SimpleDesk web panel: {} gave {} the ID {}", admin, id, form.new_id.trim());
            redirect("/", None)
        }
        Ok(Err(error)) => render_devices(&panel, &admin, StatusCode::BAD_REQUEST, error).await,
        Err(err) => {
            log::error!("SimpleDesk web panel: saving an ID failed: {}", err);
            render_devices(&panel, &admin, StatusCode::INTERNAL_SERVER_ERROR, "Speichern hat nicht geklappt.").await
        }
    }
}

/// The signed-in admin; everybody else gets the login or a refusal.
async fn admin_of(panel: &Panel, headers: &HeaderMap) -> Result<String, Response> {
    let Some(user) = panel.user(headers).await else {
        return Err(redirect("/login", None));
    };
    if !panel.pm.accounts.is_admin(&user) {
        let page = Html("<p>Das dürfen nur Admins. <a href=\"/\">Zurück zu den Geräten</a></p>");
        return Err((StatusCode::FORBIDDEN, page).into_response());
    }
    Ok(user)
}

/// Admins give a device an owner and a group.
async fn devices_assign(
    Extension(panel): Extension<Arc<Panel>>,
    headers: HeaderMap,
    Form(form): Form<AssignForm>,
) -> Response {
    let admin = match admin_of(&panel, &headers).await {
        Ok(admin) => admin,
        Err(res) => return res,
    };
    let db = &panel.pm.db;
    let result: ResultType<Result<(), &str>> = async {
        let owner = form.owner.trim();
        if !owner.is_empty() && !db.user_exists(owner).await? {
            return Ok(Err("Diesen Benutzer gibt es nicht."));
        }
        let group = match form.group.trim() {
            "" => String::new(),
            group => match db.group_name(group).await? {
                Some(group) => group,
                None => return Ok(Err("Diese Gruppe gibt es nicht.")),
            },
        };
        if !db.assign_device(form.id.trim(), owner, &group).await? {
            return Ok(Err("Dieses Gerät gibt es nicht."));
        }
        log::info!(
            "SimpleDesk web panel: {} gave {} to owner '{}' and group '{}'",
            admin,
            form.id.trim(),
            owner,
            group
        );
        Ok(Ok(()))
    }
    .await;
    match result {
        Ok(Ok(())) => redirect("/", None),
        Ok(Err(error)) => render_devices(&panel, &admin, StatusCode::BAD_REQUEST, error).await,
        Err(err) => {
            log::error!("SimpleDesk web panel: assigning a device failed: {}", err);
            render_devices(&panel, &admin, StatusCode::INTERNAL_SERVER_ERROR, "Speichern hat nicht geklappt.").await
        }
    }
}

async fn render_users(panel: &Panel, me: &str, status: StatusCode, error: &str) -> Response {
    let result: ResultType<(Vec<UserView>, Vec<GroupView>)> = async {
        let db = &panel.pm.db;
        let groups = db.list_groups().await?;
        let members = db.list_group_members().await?;
        let users = db
            .list_users()
            .await?
            .into_iter()
            .map(|row| {
                let mine: Vec<String> = members
                    .iter()
                    .filter(|(_, user)| *user == row.name)
                    .map(|(group, _)| group.clone())
                    .collect();
                UserView {
                    admin: panel.pm.accounts.is_admin(&row.name),
                    me: row.name == me,
                    other_groups: groups.iter().filter(|group| !mine.contains(group)).cloned().collect(),
                    groups: mine,
                    name: row.name,
                    blocked: row.blocked,
                    last_login: row.last_login,
                    last_active: row.last_active,
                }
            })
            .collect();
        let groups = groups
            .into_iter()
            .map(|name| GroupView {
                members: members.iter().filter(|(group, _)| *group == name).count(),
                name,
            })
            .collect();
        Ok((users, groups))
    }
    .await;
    match result {
        Ok((users, groups)) => html(
            status,
            UsersPage {
                user: me,
                admin: true,
                active: "users",
                oidc_name: panel.oidc_name(),
                users: &users,
                groups: &groups,
                error,
            }
            .render(),
        ),
        Err(err) => {
            log::error!("SimpleDesk web panel: reading users failed: {}", err);
            (StatusCode::INTERNAL_SERVER_ERROR, "Benutzer konnten nicht gelesen werden.").into_response()
        }
    }
}

async fn users_page(Extension(panel): Extension<Arc<Panel>>, headers: HeaderMap) -> Response {
    match admin_of(&panel, &headers).await {
        Ok(admin) => render_users(&panel, &admin, StatusCode::OK, "").await,
        Err(res) => res,
    }
}

/// The end of an action on the page "Benutzer": back to the page, or the page with the error.
async fn users_done(panel: &Panel, admin: &str, result: ResultType<Result<(), &str>>) -> Response {
    match result {
        Ok(Ok(())) => redirect("/users", None),
        Ok(Err(error)) => render_users(panel, admin, StatusCode::BAD_REQUEST, error).await,
        Err(err) => {
            log::error!("SimpleDesk web panel: changing users failed: {}", err);
            render_users(panel, admin, StatusCode::INTERNAL_SERVER_ERROR, "Speichern hat nicht geklappt.").await
        }
    }
}

/// "Abmelden": ends all logins of the user in clients and in the panel.
async fn users_signout(
    Extension(panel): Extension<Arc<Panel>>,
    headers: HeaderMap,
    Form(form): Form<NameForm>,
) -> Response {
    let admin = match admin_of(&panel, &headers).await {
        Ok(admin) => admin,
        Err(res) => return res,
    };
    let result: ResultType<Result<(), &str>> = async {
        panel.pm.db.delete_user_logins(&form.name).await?;
        log::info!("SimpleDesk web panel: {} signed out {} everywhere", admin, form.name);
        Ok(Ok(()))
    }
    .await;
    users_done(&panel, &admin, result).await
}

/// "Sperren": the user cannot sign in any more and loses all logins. Not for admins, they
/// come from ADMIN_USERS.
async fn users_block(
    Extension(panel): Extension<Arc<Panel>>,
    headers: HeaderMap,
    Form(form): Form<NameForm>,
) -> Response {
    let admin = match admin_of(&panel, &headers).await {
        Ok(admin) => admin,
        Err(res) => return res,
    };
    let result: ResultType<Result<(), &str>> = async {
        if panel.pm.accounts.is_admin(&form.name) {
            return Ok(Err("Admins kann man nicht sperren. Nimm sie erst aus ADMIN_USERS heraus."));
        }
        let db = &panel.pm.db;
        db.set_blocked(&form.name, true).await?;
        db.delete_user_logins(&form.name).await?;
        log::info!("SimpleDesk web panel: {} blocked {}", admin, form.name);
        Ok(Ok(()))
    }
    .await;
    users_done(&panel, &admin, result).await
}

async fn users_unblock(
    Extension(panel): Extension<Arc<Panel>>,
    headers: HeaderMap,
    Form(form): Form<NameForm>,
) -> Response {
    let admin = match admin_of(&panel, &headers).await {
        Ok(admin) => admin,
        Err(res) => return res,
    };
    let result: ResultType<Result<(), &str>> = async {
        panel.pm.db.set_blocked(&form.name, false).await?;
        log::info!("SimpleDesk web panel: {} unblocked {}", admin, form.name);
        Ok(Ok(()))
    }
    .await;
    users_done(&panel, &admin, result).await
}

async fn groups_new(
    Extension(panel): Extension<Arc<Panel>>,
    headers: HeaderMap,
    Form(form): Form<NameForm>,
) -> Response {
    let admin = match admin_of(&panel, &headers).await {
        Ok(admin) => admin,
        Err(res) => return res,
    };
    let result: ResultType<Result<(), &str>> = async {
        let name = form.name.trim();
        if name.is_empty() || name.chars().count() > 100 {
            return Ok(Err("Bitte einen Namen für die Gruppe eingeben (höchstens 100 Zeichen)."));
        }
        if !panel.pm.db.create_group(name).await? {
            return Ok(Err("Diese Gruppe gibt es schon."));
        }
        Ok(Ok(()))
    }
    .await;
    users_done(&panel, &admin, result).await
}

async fn groups_delete(
    Extension(panel): Extension<Arc<Panel>>,
    headers: HeaderMap,
    Form(form): Form<NameForm>,
) -> Response {
    let admin = match admin_of(&panel, &headers).await {
        Ok(admin) => admin,
        Err(res) => return res,
    };
    let result: ResultType<Result<(), &str>> = async {
        panel.pm.db.delete_group(&form.name).await?;
        log::info!("SimpleDesk web panel: {} deleted the group {}", admin, form.name);
        Ok(Ok(()))
    }
    .await;
    users_done(&panel, &admin, result).await
}

async fn groups_join(
    Extension(panel): Extension<Arc<Panel>>,
    headers: HeaderMap,
    Form(form): Form<MemberForm>,
) -> Response {
    let admin = match admin_of(&panel, &headers).await {
        Ok(admin) => admin,
        Err(res) => return res,
    };
    let result: ResultType<Result<(), &str>> = async {
        let db = &panel.pm.db;
        let Some(group) = db.group_name(&form.group).await? else {
            return Ok(Err("Diese Gruppe gibt es nicht."));
        };
        if !db.user_exists(&form.user).await? {
            return Ok(Err("Diesen Benutzer gibt es nicht."));
        }
        db.add_group_member(&group, &form.user).await?;
        Ok(Ok(()))
    }
    .await;
    users_done(&panel, &admin, result).await
}

async fn groups_leave(
    Extension(panel): Extension<Arc<Panel>>,
    headers: HeaderMap,
    Form(form): Form<MemberForm>,
) -> Response {
    let admin = match admin_of(&panel, &headers).await {
        Ok(admin) => admin,
        Err(res) => return res,
    };
    let result: ResultType<Result<(), &str>> = async {
        panel.pm.db.remove_group_member(&form.group, &form.user).await?;
        Ok(Ok(()))
    }
    .await;
    users_done(&panel, &admin, result).await
}

fn book_not_found() -> Response {
    let page = Html("<p>Dieses Adressbuch gibt es nicht, oder du darfst es nicht sehen. <a href=\"/ab\">Zu deinem Adressbuch</a></p>");
    (StatusCode::NOT_FOUND, page).into_response()
}

/// The address book page for `book` (its guid, empty for the personal book).
async fn render_ab(panel: &Panel, user: &str, book: &str, status: StatusCode, error: &str) -> Response {
    let result: ResultType<Option<Response>> = async {
        let Some((current, rule)) = panel.book_of(user, book).await? else {
            return Ok(None);
        };
        let db = &panel.pm.db;
        let personal = db.personal_ab(user).await?;
        let mut books = vec![BookLink {
            href: "/ab".to_owned(),
            name: "Mein Adressbuch".to_owned(),
            right: String::new(),
            current: current.guid == personal,
        }];
        for (shared, rule) in crate::api::shared_abs(&panel.pm, user).await? {
            books.push(BookLink {
                href: book_href(&shared),
                current: shared.guid == current.guid,
                name: shared.name,
                right: right_label(rule).to_owned(),
            });
        }
        let entries = panel.ab_entries(&current.guid).await?;
        let full = !current.personal && rule >= RULE_FULL;
        let (shares, groups, users) = if full {
            let shares: Vec<ShareView> = db
                .ab_rules(&current.guid)
                .await?
                .into_iter()
                .map(|(kind, name, rule)| ShareView {
                    kind,
                    name,
                    right: right_label(rule),
                })
                .collect();
            let users: Vec<String> = db.list_users().await?.into_iter().map(|row| row.name).collect();
            (shares, db.list_groups().await?, users)
        } else {
            Default::default()
        };
        let page = AbPage {
            user,
            admin: panel.pm.accounts.is_admin(user),
            active: "ab",
            books: &books,
            book: &current,
            right: right_label(rule),
            can_write: rule >= RULE_WRITE,
            full,
            entries: &entries,
            shares: &shares,
            groups: &groups,
            users: &users,
            error,
        };
        Ok(Some(html(status, page.render())))
    }
    .await;
    match result {
        Ok(Some(res)) => res,
        Ok(None) => book_not_found(),
        Err(err) => {
            log::error!("SimpleDesk web panel: reading the address book failed: {}", err);
            (StatusCode::INTERNAL_SERVER_ERROR, "Adressbuch konnte nicht gelesen werden.")
                .into_response()
        }
    }
}

async fn ab_page(
    Extension(panel): Extension<Arc<Panel>>,
    headers: HeaderMap,
    Query(query): Query<BookQuery>,
) -> Response {
    let Some(user) = panel.user(&headers).await else {
        return redirect("/login", None);
    };
    render_ab(&panel, &user, &query.book, StatusCode::OK, "").await
}

/// The book of a form if `user` has at least rule `needed` on it, else the answer to send.
async fn book_for(panel: &Panel, user: &str, book: &str, needed: i64) -> Result<AbRow, Response> {
    match panel.book_of(user, book).await {
        Ok(Some((ab, rule))) if rule >= needed && (needed < RULE_FULL || !ab.personal) => Ok(ab),
        Ok(Some(_)) => {
            let error = if needed >= RULE_FULL {
                "Teilen, umbenennen und löschen darf nur, wer volle Rechte hat."
            } else {
                "Du darfst dieses Adressbuch nur lesen."
            };
            Err(render_ab(panel, user, book, StatusCode::FORBIDDEN, error).await)
        }
        Ok(None) => Err(book_not_found()),
        Err(err) => {
            log::error!("SimpleDesk web panel: reading the address book failed: {}", err);
            Err((StatusCode::INTERNAL_SERVER_ERROR, "Adressbuch konnte nicht gelesen werden.").into_response())
        }
    }
}

/// The end of a change of a book: back to its page, or the page with the error.
async fn book_done(
    panel: &Panel,
    user: &str,
    book: &AbRow,
    result: ResultType<Result<(), &str>>,
) -> Response {
    match result {
        Ok(Ok(())) => redirect_to(&book_href(book), None),
        Ok(Err(error)) => render_ab(panel, user, &book.guid, StatusCode::BAD_REQUEST, error).await,
        Err(err) => {
            log::error!("SimpleDesk web panel: changing the address book failed: {}", err);
            render_ab(panel, user, &book.guid, StatusCode::INTERNAL_SERVER_ERROR, "Speichern hat nicht geklappt.").await
        }
    }
}

/// Adds an entry to an address book or changes alias, tags and note of an existing one.
/// Other fields the client stored (hash, password, username, ...) are kept.
async fn ab_add(
    Extension(panel): Extension<Arc<Panel>>,
    headers: HeaderMap,
    Form(form): Form<AbAddForm>,
) -> Response {
    let Some(user) = panel.user(&headers).await else {
        return redirect("/login", None);
    };
    let book = match book_for(&panel, &user, &form.book, RULE_WRITE).await {
        Ok(book) => book,
        Err(res) => return res,
    };
    let id = form.id.trim();
    if id.is_empty() || id.len() > MAX_ID_LEN || id.contains(char::is_whitespace) {
        let error = "Bitte eine gültige ID eingeben (ohne Leerzeichen).";
        return render_ab(&panel, &user, &book.guid, StatusCode::BAD_REQUEST, error).await;
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
        let guid = &book.guid;
        let mut peer = match db.get_ab_peer(guid, id).await? {
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
        db.upsert_ab_peer(guid, id, &serde_json::Value::Object(peer).to_string())
            .await?;
        let known: Vec<String> = db
            .list_ab_tags(guid)
            .await?
            .into_iter()
            .map(|(name, _)| name)
            .collect();
        for tag in tags.iter().filter(|tag| !known.contains(tag)) {
            db.upsert_ab_tag(guid, tag, DEFAULT_TAG_COLOR).await?;
        }
        Ok(())
    }
    .await;
    book_done(&panel, &user, &book, result.map(Ok)).await
}

async fn ab_delete(
    Extension(panel): Extension<Arc<Panel>>,
    headers: HeaderMap,
    Form(form): Form<AbDeleteForm>,
) -> Response {
    let Some(user) = panel.user(&headers).await else {
        return redirect("/login", None);
    };
    let book = match book_for(&panel, &user, &form.book, RULE_WRITE).await {
        Ok(book) => book,
        Err(res) => return res,
    };
    let result = panel.pm.db.delete_ab_peer(&book.guid, form.id.trim()).await;
    book_done(&panel, &user, &book, result.map(Ok)).await
}

/// A new shared book; the user who creates it owns it.
async fn ab_new(
    Extension(panel): Extension<Arc<Panel>>,
    headers: HeaderMap,
    Form(form): Form<BookForm>,
) -> Response {
    let Some(user) = panel.user(&headers).await else {
        return redirect("/login", None);
    };
    let name = match book_name(&form.name) {
        Ok(name) => name,
        Err(error) => return render_ab(&panel, &user, "", StatusCode::BAD_REQUEST, error).await,
    };
    match panel.pm.db.create_shared_ab(&user, name).await {
        Ok(Some(guid)) => {
            log::info!("SimpleDesk web panel: {} created the shared address book {}", user, name);
            redirect_to(&format!("/ab?book={}", guid), None)
        }
        Ok(None) => {
            let error = "Ein geteiltes Adressbuch mit diesem Namen gibt es schon.";
            render_ab(&panel, &user, "", StatusCode::BAD_REQUEST, error).await
        }
        Err(err) => {
            log::error!("SimpleDesk web panel: creating an address book failed: {}", err);
            render_ab(&panel, &user, "", StatusCode::INTERNAL_SERVER_ERROR, "Speichern hat nicht geklappt.").await
        }
    }
}

/// Shares a book with a user or a group, or changes the rule of an existing share.
async fn ab_share(
    Extension(panel): Extension<Arc<Panel>>,
    headers: HeaderMap,
    Form(form): Form<ShareForm>,
) -> Response {
    let Some(user) = panel.user(&headers).await else {
        return redirect("/login", None);
    };
    let book = match book_for(&panel, &user, &form.book, RULE_FULL).await {
        Ok(book) => book,
        Err(res) => return res,
    };
    let result: ResultType<Result<(), &str>> = async {
        let db = &panel.pm.db;
        if !(RULE_READ..=RULE_FULL).contains(&form.rule) {
            return Ok(Err("Bitte lesen, schreiben oder voll wählen."));
        }
        let (kind, name) = match form.who.split_once(':') {
            Some(("user", name)) => {
                if !db.user_exists(name).await? {
                    return Ok(Err("Diesen Benutzer gibt es nicht."));
                }
                ("user", name.to_owned())
            }
            Some(("group", name)) => match db.group_name(name).await? {
                Some(group) => ("group", group),
                None => return Ok(Err("Diese Gruppe gibt es nicht.")),
            },
            _ => return Ok(Err("Bitte einen Benutzer oder eine Gruppe wählen.")),
        };
        db.set_ab_rule(&book.guid, kind, &name, form.rule).await?;
        log::info!(
            "SimpleDesk web panel: {} shared the address book {} with {} {} ({})",
            user,
            book.name,
            kind,
            name,
            right_label(form.rule)
        );
        Ok(Ok(()))
    }
    .await;
    book_done(&panel, &user, &book, result).await
}

async fn ab_unshare(
    Extension(panel): Extension<Arc<Panel>>,
    headers: HeaderMap,
    Form(form): Form<UnshareForm>,
) -> Response {
    let Some(user) = panel.user(&headers).await else {
        return redirect("/login", None);
    };
    let book = match book_for(&panel, &user, &form.book, RULE_FULL).await {
        Ok(book) => book,
        Err(res) => return res,
    };
    let result = panel.pm.db.delete_ab_rule(&book.guid, &form.kind, &form.name).await;
    book_done(&panel, &user, &book, result.map(Ok)).await
}

async fn ab_rename(
    Extension(panel): Extension<Arc<Panel>>,
    headers: HeaderMap,
    Form(form): Form<BookForm>,
) -> Response {
    let Some(user) = panel.user(&headers).await else {
        return redirect("/login", None);
    };
    let book = match book_for(&panel, &user, &form.book, RULE_FULL).await {
        Ok(book) => book,
        Err(res) => return res,
    };
    let result: ResultType<Result<(), &str>> = async {
        let name = match book_name(&form.name) {
            Ok(name) => name,
            Err(error) => return Ok(Err(error)),
        };
        if !panel.pm.db.rename_shared_ab(&book.guid, name).await? {
            return Ok(Err("Ein geteiltes Adressbuch mit diesem Namen gibt es schon."));
        }
        Ok(Ok(()))
    }
    .await;
    book_done(&panel, &user, &book, result).await
}

/// Deletes a shared book with all its entries.
async fn ab_remove(
    Extension(panel): Extension<Arc<Panel>>,
    headers: HeaderMap,
    Form(form): Form<BookForm>,
) -> Response {
    let Some(user) = panel.user(&headers).await else {
        return redirect("/login", None);
    };
    let book = match book_for(&panel, &user, &form.book, RULE_FULL).await {
        Ok(book) => book,
        Err(res) => return res,
    };
    match panel.pm.db.delete_shared_ab(&book.guid).await {
        Ok(()) => {
            log::info!("SimpleDesk web panel: {} deleted the shared address book {}", user, book.name);
            redirect("/ab", None)
        }
        Err(err) => {
            log::error!("SimpleDesk web panel: deleting an address book failed: {}", err);
            render_ab(&panel, &user, &book.guid, StatusCode::INTERNAL_SERVER_ERROR, "Löschen hat nicht geklappt.").await
        }
    }
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
    let saved: ResultType<bool> = async {
        let db = &panel.pm.db;
        db.ensure_external_user(&user).await?;
        if db.is_blocked(&user).await? {
            return Ok(false);
        }
        db.record_login(&user).await?;
        Ok(true)
    }
    .await;
    match saved {
        Ok(true) => {}
        Ok(false) => {
            log::warn!("SimpleDesk OIDC: {} is blocked and may not sign in", user);
            return oidc_done(false, "Dein Konto ist für SimpleDesk gesperrt. Bitte wende dich an die IT.");
        }
        Err(err) => {
            log::error!("SimpleDesk OIDC: saving user {} failed: {}", user, err);
            return oidc_done(false, "Fehler beim Speichern.");
        }
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

    /// A panel where felix is the admin.
    async fn test_panel(dir: &tempfile::TempDir) -> Arc<Panel> {
        let mut pm = crate::peer::test_peer_map(dir).await;
        pm.accounts = Arc::new(crate::accounts::Accounts::with_admins("felix"));
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
        // Every page links to its source code (AGPL).
        assert!(page.contains("href=\"https://github.com/felixthedevgit/simpledesk-server\">Quellcode</a>"), "{page}");
        assert!(page.contains("Open Source (AGPL)"), "{page}");
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

    fn post_form_with(path: &str, form: &str, cookie: &str) -> Request<Body> {
        let mut req = post_form(path, form);
        req.headers_mut()
            .insert(header::COOKIE, HeaderValue::from_str(cookie).unwrap());
        req
    }

    #[hbb_common::tokio::test]
    async fn users_page_is_for_admins_and_signs_out_and_blocks() {
        let dir = tempfile::tempdir().unwrap();
        let panel = test_panel(&dir).await;
        let db = &panel.pm.db;
        let felix = signed_in(&panel, "felix").await;
        let anna = signed_in(&panel, "anna").await;

        // Only admins see the page and its actions; the nav shows it only to them.
        assert!(body(send(&panel, get("/", Some(&felix))).await).await.contains("href=\"/users\""));
        assert!(!body(send(&panel, get("/", Some(&anna))).await).await.contains("href=\"/users\""));
        assert_eq!(send(&panel, get("/users", Some(&anna))).await.status(), StatusCode::FORBIDDEN);
        let res = send(&panel, post_form_with("/users/block", "name=felix", &anna)).await;
        assert_eq!(res.status(), StatusCode::FORBIDDEN);
        assert_eq!(location(&send(&panel, get("/users", None)).await), "/login");
        let page = body(send(&panel, get("/users", Some(&felix))).await).await;
        assert!(page.contains("anna") && page.contains("Admin") && page.contains("Benutzer"), "{page}");

        // "Abmelden" ends the client tokens and panel sessions of anna.
        db.insert_api_token(&token_hash("token-of-anna"), "anna", "Anna-PC").await.unwrap();
        let res = send(&panel, post_form_with("/users/signout", "name=anna", &felix)).await;
        assert_eq!(location(&res), "/users");
        assert_eq!(crate::api::token_user(&panel.pm, "token-of-anna").await, None);
        assert_eq!(location(&send(&panel, get("/", Some(&anna))).await), "/login");

        // "Sperren" does the same, and anna stays out until "Entsperren".
        let anna = signed_in(&panel, "anna").await;
        db.insert_api_token(&token_hash("token-of-anna"), "anna", "Anna-PC").await.unwrap();
        send(&panel, post_form_with("/users/block", "name=anna", &felix)).await;
        assert!(db.is_blocked("anna").await.unwrap());
        assert_eq!(crate::api::token_user(&panel.pm, "token-of-anna").await, None);
        assert_eq!(location(&send(&panel, get("/", Some(&anna))).await), "/login");
        let anna = format!("{}={}", COOKIE_NAME, panel.start_session("anna").await.unwrap());
        assert_eq!(location(&send(&panel, get("/", Some(&anna))).await), "/login");
        let page = body(send(&panel, get("/users", Some(&felix))).await).await;
        assert!(page.contains("gesperrt") && page.contains("Entsperren"), "{page}");
        send(&panel, post_form_with("/users/unblock", "name=anna", &felix)).await;
        assert!(!db.is_blocked("anna").await.unwrap());

        // Admins cannot be blocked: they come from ADMIN_USERS.
        let res = send(&panel, post_form_with("/users/block", "name=FELIX", &felix)).await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
        assert!(body(res).await.contains("Admins kann man nicht sperren"));
        assert!(!db.is_blocked("felix").await.unwrap());
    }

    #[hbb_common::tokio::test]
    async fn owners_and_groups_decide_who_sees_a_device() {
        let dir = tempfile::tempdir().unwrap();
        let panel = test_panel(&dir).await;
        let db = &panel.pm.db;
        for id in ["Anna-PC", "Lager-PC", "Frei-PC"] {
            db.insert_peer(id, id.as_bytes(), b"pk", "{}").await.unwrap();
        }
        let felix = signed_in(&panel, "felix").await;
        let anna = signed_in(&panel, "anna").await;
        let ben = signed_in(&panel, "ben").await;
        let sees = |cookie: String| {
            let panel = panel.clone();
            async move {
                let page = body(send(&panel, get("/", Some(&cookie))).await).await;
                ["Anna-PC", "Lager-PC", "Frei-PC"]
                    .into_iter()
                    .filter(|id| page.contains(&format!("<td class=\"id\">{id}</td>")))
                    .collect::<Vec<_>>()
            }
        };

        // Groups: created once, in any case.
        let res = send(&panel, post_form_with("/groups/new", "name=Lager", &felix)).await;
        assert_eq!(location(&res), "/users");
        let res = send(&panel, post_form_with("/groups/new", "name=lager", &felix)).await;
        assert!(body(res).await.contains("gibt es schon"));
        send(&panel, post_form_with("/groups/join", "user=ben&group=lager", &felix)).await;
        assert_eq!(db.user_groups("ben").await.unwrap(), vec!["Lager"]);
        let res = send(&panel, post_form_with("/groups/join", "user=niemand&group=Lager", &felix)).await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);

        // Before anything is assigned only the admin sees devices.
        assert_eq!(sees(felix.clone()).await, vec!["Anna-PC", "Lager-PC", "Frei-PC"]);
        assert!(sees(anna.clone()).await.is_empty());
        assert!(body(send(&panel, get("/", Some(&anna))).await).await.contains("Dir gehört noch kein Gerät"));

        // The admin assigns an owner and a group.
        let res = send(&panel, post_form_with("/devices/assign", "id=Anna-PC&owner=anna&group=", &felix)).await;
        assert_eq!(location(&res), "/");
        send(&panel, post_form_with("/devices/assign", "id=Lager-PC&owner=&group=Lager", &felix)).await;
        assert_eq!(sees(anna.clone()).await, vec!["Anna-PC"]);
        assert_eq!(sees(ben.clone()).await, vec!["Lager-PC"]);
        let page = body(send(&panel, get("/", Some(&felix))).await).await;
        assert!(page.contains("<option value=\"anna\" selected>anna</option>"), "{page}");

        // Only admins assign, and only to users and groups that exist.
        let res = send(&panel, post_form_with("/devices/assign", "id=Frei-PC&owner=anna&group=", &anna)).await;
        assert_eq!(res.status(), StatusCode::FORBIDDEN);
        for form in ["id=Frei-PC&owner=niemand&group=", "id=Frei-PC&owner=&group=Keine", "id=Nicht-Da&owner=anna&group="] {
            let res = send(&panel, post_form_with("/devices/assign", form, &felix)).await;
            assert_eq!(res.status(), StatusCode::BAD_REQUEST, "{form}");
        }
        assert!(sees(anna.clone()).await == vec!["Anna-PC"]);

        // Leaving or deleting the group takes its devices away.
        send(&panel, post_form_with("/groups/leave", "user=ben&group=Lager", &felix)).await;
        assert!(sees(ben.clone()).await.is_empty());
        send(&panel, post_form_with("/groups/join", "user=ben&group=Lager", &felix)).await;
        send(&panel, post_form_with("/groups/delete", "name=Lager", &felix)).await;
        assert!(sees(ben.clone()).await.is_empty());
        assert_eq!(db.device_owner("Lager-PC").await.unwrap(), Some((String::new(), String::new())));
    }

    #[hbb_common::tokio::test]
    async fn shared_books_are_created_and_shared_in_the_panel() {
        let dir = tempfile::tempdir().unwrap();
        let panel = test_panel(&dir).await;
        let db = &panel.pm.db;
        let anna = signed_in(&panel, "anna").await;
        let ben = signed_in(&panel, "ben").await;
        let carl = signed_in(&panel, "carl").await;
        assert!(db.create_group("Team").await.unwrap());
        db.add_group_member("Team", "ben").await.unwrap();

        // anna creates a book and lands on its page, where she can share it.
        let res = send(&panel, post_form_with("/ab/new", "name=Server", &anna)).await;
        let page_path = location(&res).to_owned();
        assert!(page_path.starts_with("/ab?book="), "{page_path}");
        let guid = page_path.trim_start_matches("/ab?book=").to_owned();
        let page = body(send(&panel, get(&page_path, Some(&anna))).await).await;
        assert!(page.contains("<h1>Server</h1>") && page.contains("Teilen mit"), "{page}");
        assert!(page.contains("value=\"group:Team\"") && page.contains("value=\"user:ben\""), "{page}");
        for name in ["server", "Mein Adressbuch", "my address book", ""] {
            let res = send(&panel, post_form_with("/ab/new", &format!("name={name}"), &anna)).await;
            assert_eq!(res.status(), StatusCode::BAD_REQUEST, "{name}");
        }

        // Shared with the group Team to write.
        let form = format!("book={guid}&who=group%3ATeam&rule=2");
        assert_eq!(location(&send(&panel, post_form_with("/ab/share", &form, &anna)).await), page_path);
        assert_eq!(db.ab_rules(&guid).await.unwrap(), vec![("group".to_owned(), "Team".to_owned(), 2)]);
        let res = send(&panel, post_form_with("/ab/share", &format!("book={guid}&who=user%3Aniemand&rule=1"), &anna)).await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);

        // ben sees it among his books, may add entries but not share.
        let page = body(send(&panel, get("/ab", Some(&ben))).await).await;
        assert!(page.contains(&format!("href=\"{page_path}\"")) && page.contains("schreiben"), "{page}");
        let page = body(send(&panel, get(&page_path, Some(&ben))).await).await;
        assert!(page.contains("Eintrag hinzufügen") && !page.contains("Teilen mit"), "{page}");
        let form = format!("book={guid}&id=Server-1&alias=Erster&tags=Linux&note=");
        assert_eq!(location(&send(&panel, post_form_with("/ab/add", &form, &ben)).await), page_path);
        assert_eq!(db.list_ab_peers(&guid).await.unwrap().len(), 1);
        assert!(db.list_ab_peers(&db.personal_ab("ben").await.unwrap()).await.unwrap().is_empty());
        let res = send(&panel, post_form_with("/ab/share", &format!("book={guid}&who=user%3Acarl&rule=3"), &ben)).await;
        assert_eq!(res.status(), StatusCode::FORBIDDEN);

        // carl has no share: no page, no changes.
        assert_eq!(send(&panel, get(&page_path, Some(&carl))).await.status(), StatusCode::NOT_FOUND);
        let res = send(&panel, post_form_with("/ab/delete", &format!("book={guid}&id=Server-1"), &carl)).await;
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
        assert!(!body(send(&panel, get("/ab", Some(&carl))).await).await.contains(&page_path));

        // Read only: the page shows the entries, without forms to change them.
        send(&panel, post_form_with("/ab/share", &format!("book={guid}&who=user%3Acarl&rule=1"), &anna)).await;
        let page = body(send(&panel, get(&page_path, Some(&carl))).await).await;
        assert!(page.contains("Server-1") && !page.contains("Eintrag hinzufügen"), "{page}");
        let res = send(&panel, post_form_with("/ab/add", &format!("book={guid}&id=Neu"), &carl)).await;
        assert_eq!(res.status(), StatusCode::FORBIDDEN);

        // Rename, unshare, delete.
        let res = send(&panel, post_form_with("/ab/rename", &format!("book={guid}&name=Server+Amt"), &anna)).await;
        assert_eq!(location(&res), page_path);
        assert!(body(send(&panel, get(&page_path, Some(&ben))).await).await.contains("Server Amt"));
        send(&panel, post_form_with("/ab/unshare", &format!("book={guid}&kind=group&name=Team"), &anna)).await;
        assert_eq!(send(&panel, get(&page_path, Some(&ben))).await.status(), StatusCode::NOT_FOUND);
        let res = send(&panel, post_form_with("/ab/remove", &format!("book={guid}"), &anna)).await;
        assert_eq!(location(&res), "/ab");
        assert_eq!(db.get_ab(&guid).await.unwrap(), None);
        assert!(db.list_ab_peers(&guid).await.unwrap().is_empty());

        // Admins manage every shared book, but the personal books stay private.
        let felix = signed_in(&panel, "felix").await;
        let res = send(&panel, post_form_with("/ab/new", "name=Drucker", &carl)).await;
        let carls = location(&res).to_owned();
        assert!(body(send(&panel, get(&carls, Some(&felix))).await).await.contains("Teilen mit"));
        let personal = db.personal_ab("carl").await.unwrap();
        let res = send(&panel, get(&format!("/ab?book={personal}"), Some(&felix))).await;
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
        let res = send(&panel, post_form_with("/ab/remove", &format!("book={personal}"), &carl)).await;
        assert_eq!(res.status(), StatusCode::FORBIDDEN);
    }

    #[hbb_common::tokio::test]
    async fn admins_give_new_devices_their_id_in_the_panel() {
        let dir = tempfile::tempdir().unwrap();
        let mut pm = crate::peer::test_peer_map(&dir).await;
        pm.accounts = Arc::new(crate::accounts::Accounts::with_ids_by_admin("felix"));
        let panel = Arc::new(Panel::new(pm, Default::default()).await.unwrap());
        let db = &panel.pm.db;
        db.insert_peer("123456789", b"uuid-neu", b"pk", r#"{"ip":"203.0.113.8"}"#).await.unwrap();
        let info = r#"{"hostname":"BUERO-12","username":"anna","os":"windows / Windows 11"}"#;
        assert!(db.save_device_info("123456789", b"uuid-neu", info).await.unwrap());
        let felix = signed_in(&panel, "felix").await;
        let anna = signed_in(&panel, "anna").await;

        // The admin sees the new device with what it told about itself, others do not.
        let page = body(send(&panel, get("/", Some(&felix))).await).await;
        assert!(page.contains("Neue Geräte (ohne ID)") && page.contains("BUERO-12"), "{page}");
        assert!(page.contains("windows / Windows 11") && page.contains("203.0.113.8"), "{page}");
        assert!(!page.contains("<td class=\"id\">123456789"), "{page}");
        let page = body(send(&panel, get("/", Some(&anna))).await).await;
        assert!(!page.contains("Neue Geräte") && !page.contains("BUERO-12"), "{page}");

        // Only admins give IDs, and only usable ones.
        let res = send(&panel, post_form_with("/devices/set-id", "id=123456789&new_id=Rathaus-PC", &anna)).await;
        assert_eq!(res.status(), StatusCode::FORBIDDEN);
        let res = send(&panel, post_form_with("/devices/set-id", "id=123456789&new_id=1-falsch", &felix)).await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
        assert_eq!(db.id_assignment(b"uuid-neu").await.unwrap(), None);

        // "ID vergeben": the device is in the list and takes the new ID soon.
        let res = send(&panel, post_form_with("/devices/set-id", "id=123456789&new_id=Rathaus-PC", &felix)).await;
        assert_eq!(location(&res), "/");
        assert_eq!(db.id_assignment(b"uuid-neu").await.unwrap().as_deref(), Some("Rathaus-PC"));
        let page = body(send(&panel, get("/", Some(&felix))).await).await;
        assert!(page.contains("<td class=\"id\">123456789<span class=\"pending\">wird zu Rathaus-PC</span>"), "{page}");
        assert!(page.contains("ID ändern") && page.contains("Gerade wartet kein Gerät auf eine ID"), "{page}");
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
