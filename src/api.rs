//! SimpleDesk: the HTTP API the client uses for its account and address books.
//!
//! Built from the open client source (flutter/lib/models/user_model.dart, ab_model.dart and
//! src/hbbs_http/), not from any closed server. Errors are `{"error": "..."}`; address book
//! actions answer 200 with an empty body, because the client treats any body as an error.

use crate::database::{AbRow, DeviceRow};
use crate::oidc::ClientLoginState;
use crate::panel::{hex, Panel};
use crate::peer::PeerMap;
use axum::{
    body::Bytes,
    extract::{Extension, Path, Query},
    http::{header, HeaderMap, Method, StatusCode},
    response::{IntoResponse, Response},
    routing::{any, get, post},
    Json, Router,
};
use hbb_common::{log, ResultType};
use serde_derive::Deserialize;
use serde_json::{json, Map, Value};
use sodiumoxide::{crypto::hash::sha256, randombytes::randombytes};
use std::{collections::HashMap, sync::Arc};

const MAX_PAGE_SIZE: usize = 1000;

pub(crate) fn routes() -> Router {
    Router::new()
        .route("/api/simpledesk/server-info", get(server_info))
        .route("/api/simpledesk/change-id", post(change_id))
        .route("/api/simpledesk/peer-status", post(peer_status))
        .route("/api/login-options", get(login_options))
        .route("/api/login", post(login))
        .route("/api/oidc/auth", post(oidc_auth))
        .route("/api/oidc/auth-query", get(oidc_auth_query))
        .route("/api/currentUser", post(current_user))
        .route("/api/logout", post(logout))
        .route("/api/ab/*rest", any(address_book))
        .route("/api/heartbeat", post(heartbeat))
        .route("/api/sysinfo", post(sysinfo))
        // Groups are not built yet; an empty page keeps the client's group tab quiet.
        .route("/api/device-group/accessible", get(empty_page))
        .route("/api/users", get(empty_page))
        .route("/api/peers", get(empty_page))
        .route("/api/audit/*rest", any(crate::audit::audit))
}

fn api_error(status: StatusCode, msg: &str) -> Response {
    (status, Json(json!({ "error": msg }))).into_response()
}

async fn empty_page() -> Response {
    Json(json!({ "total": 0, "data": [] })).into_response()
}

pub(crate) fn token_hash(token: &str) -> String {
    hex(&sha256::hash(token.as_bytes()).0)
}

/// The user of a valid access token: known and younger than TOKEN_DAYS. Ok(None) for an
/// empty, unknown or expired token.
async fn lookup_token(pm: &PeerMap, token: &str) -> ResultType<Option<String>> {
    let token = token.trim();
    if token.is_empty() {
        return Ok(None);
    }
    pm.db
        .get_api_token_user(&token_hash(token), pm.accounts.token_days)
        .await
}

/// The user an access token belongs to; None for an empty, unknown, expired or failing lookup,
/// and for a blocked user.
pub(crate) async fn token_user(pm: &PeerMap, token: &str) -> Option<String> {
    match lookup_token(pm, token).await {
        Ok(user) => user,
        Err(err) => {
            log::error!("SimpleDesk API: reading token failed: {}", err);
            None
        }
    }
}

/// Whether `user` may see and control device `id`: admins always, everybody else only as its
/// owner or as a member of its group. A device without owner and group is for admins only.
pub(crate) async fn may_control(pm: &PeerMap, user: &str, id: &str) -> bool {
    if pm.accounts.is_admin(user) {
        return true;
    }
    let result: ResultType<bool> = async {
        let Some((owner, group)) = pm.db.device_owner(id).await? else {
            return Ok(false);
        };
        if !owner.is_empty() && owner == user {
            return Ok(true);
        }
        Ok(!group.is_empty() && pm.db.user_groups(user).await?.contains(&group))
    }
    .await;
    result.unwrap_or_else(|err| {
        log::error!("SimpleDesk API: reading the owner of {} failed: {}", id, err);
        false
    })
}

/// The registered devices `user` may see, by the same rule as may_control: all for an admin,
/// else the own ones and those of the user's groups.
pub(crate) async fn visible_devices(pm: &PeerMap, user: &str) -> ResultType<Vec<DeviceRow>> {
    let rows = pm.db.list_devices().await?;
    if pm.accounts.is_admin(user) {
        return Ok(rows);
    }
    let groups = pm.db.user_groups(user).await?;
    Ok(rows
        .into_iter()
        .filter(|row| {
            (!row.owner.is_empty() && row.owner == user)
                || (!row.group.is_empty() && groups.contains(&row.group))
        })
        .collect())
}

pub(crate) fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or_default()
}

/// What the client and the panel show for a device: "Online (Aktiv)", "AFK" or "Offline".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DeviceState {
    Active,
    Afk,
    Offline,
}

impl DeviceState {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            DeviceState::Active => "active",
            DeviceState::Afk => "afk",
            DeviceState::Offline => "offline",
        }
    }
}

/// The state of a device and since when (unix seconds). An online device is AFK once its
/// last input is `afk_secs` old, then `since` is that input. Offline, `since` is when it was
/// last seen (0 if never). Active, it is the last input, or now if the device tells none.
pub(crate) fn device_state(
    online: bool,
    last_input: Option<u64>,
    last_seen: u64,
    now: u64,
    afk_secs: u64,
) -> (DeviceState, u64) {
    if !online {
        return (DeviceState::Offline, last_seen);
    }
    match last_input {
        Some(input) if now.saturating_sub(input) >= afk_secs => (DeviceState::Afk, input),
        Some(input) => (DeviceState::Active, input.min(now)),
        None => (DeviceState::Active, now),
    }
}

/// The current state of the registered device `id`; `db_last_seen` is when the database last
/// saw it.
pub(crate) async fn current_state(pm: &PeerMap, id: &str, db_last_seen: u64) -> (DeviceState, u64) {
    let now = unix_now();
    let afk_secs = pm.accounts.afk_minutes.max(1) as u64 * 60;
    match pm.get_in_memory(id).await {
        Some(peer) => {
            let peer = peer.read().await;
            let last_seen = peer.last_seen.max(db_last_seen);
            device_state(peer.is_online(), peer.last_input, last_seen, now, afk_secs)
        }
        None => device_state(false, None, db_last_seen, now, afk_secs),
    }
}

/// "seit 12 min", "seit 3 h" or "seit 2 Tagen"; '' if `since` is unknown (0).
pub(crate) fn since_text(since: u64, now: u64) -> String {
    if since == 0 {
        return String::new();
    }
    let minutes = now.saturating_sub(since) / 60;
    if minutes < 1 {
        "seit weniger als 1 min".to_owned()
    } else if minutes < 120 {
        format!("seit {} min", minutes)
    } else if minutes < 48 * 60 {
        format!("seit {} h", minutes / 60)
    } else {
        format!("seit {} Tagen", minutes / (24 * 60))
    }
}

/// How often the time a device was last seen is written to the database at most.
const LAST_SEEN_SAVE_SECS: u64 = 60;

/// The device is alive, and its user's last input was `idle_secs` ago (None from clients that
/// do not tell). Only for the device registered with this ID and uuid, so nobody can make
/// another device look AFK.
async fn note_heartbeat(pm: &PeerMap, id: &str, uuid: &[u8], idle_secs: Option<u64>) {
    let Some(peer) = pm.get(id).await else {
        return;
    };
    let now = unix_now();
    let save = {
        let mut peer = peer.write().await;
        if peer.uuid.is_empty() || &peer.uuid[..] != uuid {
            return;
        }
        peer.last_seen = now;
        peer.last_input = idle_secs.map(|idle| now.saturating_sub(idle));
        if peer.guid.is_empty() || now.saturating_sub(peer.last_seen_saved) < LAST_SEEN_SAVE_SECS {
            None
        } else {
            peer.last_seen_saved = now;
            Some(peer.guid.clone())
        }
    };
    if let Some(guid) = save {
        if let Err(err) = pm.db.save_last_seen(&guid, now).await {
            log::error!("SimpleDesk API: saving when {} was last seen failed: {}", id, err);
        }
    }
}

#[derive(Deserialize)]
struct PeerStatusRequest {
    #[serde(default)]
    ids: Vec<String>,
}

/// More IDs than anybody has in the address book.
const MAX_STATUS_IDS: usize = 1000;

/// The client asks for the state of the devices in its lists: `{"ids": [...]}`. The answer is
/// `{"<id>": {"state": "active"|"afk"|"offline", "since": <unix seconds>}}`, only for devices
/// the user may see. Other and unknown IDs are left out.
async fn peer_status(Extension(panel): Extension<Arc<Panel>>, headers: HeaderMap, body: Bytes) -> Response {
    let user = match user_of(&panel, &headers).await {
        Ok(user) => user,
        Err(res) => return res,
    };
    let Ok(req) = serde_json::from_slice::<PeerStatusRequest>(&body) else {
        return api_error(StatusCode::BAD_REQUEST, "Ungültige Anfrage.");
    };
    if req.ids.len() > MAX_STATUS_IDS {
        return api_error(StatusCode::BAD_REQUEST, "Zu viele IDs auf einmal.");
    }
    let devices: HashMap<String, u64> = match visible_devices(&panel.pm, &user).await {
        Ok(rows) => rows.into_iter().map(|row| (row.id, row.last_seen)).collect(),
        Err(err) => {
            log::error!("SimpleDesk API: reading devices for the status failed: {}", err);
            return api_error(StatusCode::BAD_REQUEST, "Serverfehler.");
        }
    };
    let mut states = Map::new();
    for id in req.ids {
        let id = id.trim();
        let Some(&db_last_seen) = devices.get(id) else {
            continue;
        };
        if states.contains_key(id) {
            continue;
        }
        let (state, since) = current_state(&panel.pm, id, db_last_seen).await;
        states.insert(id.to_owned(), json!({ "state": state.as_str(), "since": since }));
    }
    Json(Value::Object(states)).into_response()
}

/// With IDS_BY_ADMIN: whether device `id` may be reached. Only under the ID an admin gave its
/// device; a new device without one is not reachable. An ID no device has is left to the
/// usual answer ("ID does not exist").
pub(crate) async fn id_usable(pm: &PeerMap, id: &str) -> bool {
    match pm.db.id_assignment_of(id).await {
        Ok(None) => true,
        Ok(Some(assigned)) => assigned.as_deref() == Some(id),
        Err(err) => {
            log::error!("SimpleDesk API: reading the ID of {} failed: {}", id, err);
            false
        }
    }
}

/// What an admin sees for an ID a device cannot have.
pub(crate) const ID_FORMAT_MESSAGE: &str =
    "Die ID muss mit einem Buchstaben anfangen und 6 bis 16 Zeichen lang sein (Buchstaben, Ziffern, _ oder -).";

/// An admin gives the device with `id` and `uuid` the ID `new_id`; the device takes it with
/// its next heartbeat. Keeping the current ID is fine too, then it is simply given. Err with
/// a message for the admin if it cannot be done.
pub(crate) async fn assign_id(
    pm: &PeerMap,
    id: &str,
    uuid: &[u8],
    new_id: &str,
) -> ResultType<Result<(), &'static str>> {
    let new_id = new_id.trim();
    if pm.db.device_uuid(id).await?.as_deref() != Some(uuid) {
        return Ok(Err("Dieses Gerät ist beim Server nicht angemeldet."));
    }
    if new_id != id {
        if !hbb_common::is_valid_custom_id(new_id) {
            return Ok(Err(ID_FORMAT_MESSAGE));
        }
        if pm.db.id_taken(new_id, uuid).await? {
            return Ok(Err("Diese ID ist schon vergeben."));
        }
    }
    pm.db.set_id_assignment(uuid, new_id).await?;
    log::info!("SimpleDesk: device {} gets the ID {}", id, new_id);
    Ok(Ok(()))
}

#[derive(Deserialize)]
struct ChangeIdRequest {
    #[serde(default)]
    id: String,
    #[serde(default)]
    uuid: String,
    #[serde(default)]
    new_id: String,
}

/// An admin changes a device's ID from the client. Answers 200 `{}`, or 403 with the reason.
async fn change_id(Extension(panel): Extension<Arc<Panel>>, headers: HeaderMap, body: Bytes) -> Response {
    let user = match user_of(&panel, &headers).await {
        Ok(user) => user,
        Err(res) => return res,
    };
    let refuse = |msg: &str| api_error(StatusCode::FORBIDDEN, msg);
    if !panel.pm.accounts.is_admin(&user) {
        return refuse("Nur Admins dürfen die ID eines Geräts ändern.");
    }
    let Ok(req) = serde_json::from_slice::<ChangeIdRequest>(&body) else {
        return refuse("Ungültige Anfrage.");
    };
    let Ok(uuid) = base64::decode(req.uuid.trim()) else {
        return refuse("Dieses Gerät ist beim Server nicht angemeldet.");
    };
    match assign_id(&panel.pm, req.id.trim(), &uuid, &req.new_id).await {
        Ok(Ok(())) => {
            log::info!("SimpleDesk API: {} changes the ID of {} to {}", user, req.id.trim(), req.new_id.trim());
            let detail = format!("ID geändert: {} → {}", req.id.trim(), req.new_id.trim());
            crate::audit::log_change(&panel.pm, &user, req.id.trim(), detail).await;
            Json(json!({})).into_response()
        }
        Ok(Err(msg)) => refuse(msg),
        Err(err) => {
            log::error!("SimpleDesk API: saving the new ID failed: {}", err);
            refuse("Serverfehler.")
        }
    }
}

/// After a client login, the user becomes the owner of the device the client runs on, if the
/// device ID and uuid match the registered device. A login of an admin changes nothing, so
/// helping somebody on their device does not take it from them.
async fn take_device(panel: &Panel, user: &str, id: &str, uuid: &str) {
    if id.is_empty() || panel.pm.accounts.is_admin(user) {
        return;
    }
    let Ok(uuid) = base64::decode(uuid.trim()) else {
        log::warn!("SimpleDesk API: login of {} on {} with an unreadable uuid", user, id);
        return;
    };
    match panel.pm.db.set_owner_from_login(id, &uuid, user).await {
        Ok(true) => log::info!("SimpleDesk API: device {} now belongs to {}", id, user),
        Ok(false) => log::warn!("SimpleDesk API: {} signed in on {}, but no device with this ID and uuid is registered", user, id),
        Err(err) => log::error!("SimpleDesk API: saving the owner of {} failed: {}", id, err),
    }
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .map(str::trim)
        .filter(|token| !token.is_empty())
}

/// The user of the request's token, or the 401 the client answers with a logout.
async fn user_of(panel: &Panel, headers: &HeaderMap) -> Result<String, Response> {
    let unauthorized = || api_error(StatusCode::UNAUTHORIZED, "Bitte neu anmelden.");
    let token = bearer(headers).ok_or_else(unauthorized)?;
    match lookup_token(&panel.pm, token).await {
        Ok(Some(user)) => Ok(user),
        Ok(None) => Err(unauthorized()),
        Err(err) => {
            log::error!("SimpleDesk API: reading token failed: {}", err);
            Err(api_error(StatusCode::BAD_REQUEST, "Serverfehler."))
        }
    }
}

fn user_json(panel: &Panel, name: &str) -> Value {
    json!({
        "name": name,
        "display_name": name,
        "email": "",
        "note": "",
        "status": 1,
        "is_admin": panel.pm.accounts.is_admin(name),
        "info": {},
    })
}

/// What the SimpleDesk client reads when somebody types in the server address for the first
/// time: the key it needs to trust this server. No login, the key is public anyway. Keep these
/// three fields as they are, the client depends on them.
async fn server_info(Extension(panel): Extension<Arc<Panel>>) -> Response {
    Json(json!({
        "key": panel.public_key,
        "name": "SimpleDesk",
        "version": crate::version::VERSION,
    }))
    .into_response()
}

/// The client shows a button for every "oidc/<name>".
async fn login_options(Extension(panel): Extension<Arc<Panel>>) -> Response {
    match panel.oidc.as_ref() {
        Some(oidc) => Json(json!([format!("oidc/{}", oidc.config.name)])).into_response(),
        None => Json(json!([])).into_response(),
    }
}

/// A new token for a signed-in user, as the answer the client expects after a login.
async fn token_response(panel: &Panel, name: &str, device_id: &str) -> Response {
    let token = hex(&randombytes(32));
    let db = &panel.pm.db;
    let accounts = &panel.pm.accounts;
    if let Err(err) = db
        .delete_expired_logins(accounts.token_days, accounts.session_hours)
        .await
    {
        log::warn!("SimpleDesk API: removing expired logins failed: {}", err);
    }
    if let Err(err) = db.insert_api_token(&token_hash(&token), name, device_id).await {
        log::error!("SimpleDesk API: saving token failed: {}", err);
        return api_error(StatusCode::BAD_REQUEST, "Serverfehler.");
    }
    log::info!("SimpleDesk API: {} logged in on device {}", name, device_id);
    Json(json!({
        "type": "access_token",
        "access_token": token,
        "user": user_json(panel, name),
    }))
    .into_response()
}

#[derive(Deserialize)]
struct OidcAuthRequest {
    #[serde(default)]
    id: String,
    #[serde(default)]
    uuid: String,
}

/// The client starts a login in the browser: its code and the address to open.
async fn oidc_auth(Extension(panel): Extension<Arc<Panel>>, body: Bytes) -> Response {
    let Some(oidc) = panel.oidc.as_ref() else {
        return api_error(StatusCode::NOT_FOUND, "Anmeldung im Browser ist nicht eingerichtet.");
    };
    let Ok(req) = serde_json::from_slice::<OidcAuthRequest>(&body) else {
        return api_error(StatusCode::BAD_REQUEST, "Ungültige Anfrage.");
    };
    match oidc.start_client_login(&req.id, &req.uuid).await {
        Ok((code, url)) => Json(json!({ "code": code, "url": url })).into_response(),
        Err(err) => {
            log::error!("SimpleDesk OIDC: starting a client login failed: {}", err);
            api_error(StatusCode::BAD_REQUEST, "Die Anmeldung ist gerade nicht erreichbar.")
        }
    }
}

/// The client asks every second whether its login in the browser is done. While it is not,
/// the answer must be exactly this error, or the client stops asking.
async fn oidc_auth_query(
    Extension(panel): Extension<Arc<Panel>>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    let Some(oidc) = panel.oidc.as_ref() else {
        return api_error(StatusCode::NOT_FOUND, "Anmeldung im Browser ist nicht eingerichtet.");
    };
    let field = |name: &str| query.get(name).map(String::as_str).unwrap_or_default();
    match oidc
        .client_login_state(field("code"), field("id"), field("uuid"))
        .await
    {
        ClientLoginState::Waiting => Json(json!({ "error": "No authed oidc is found" })).into_response(),
        ClientLoginState::Done(user) => {
            take_device(&panel, &user, field("id"), field("uuid")).await;
            token_response(&panel, &user, field("id")).await
        }
        ClientLoginState::Unknown => {
            api_error(StatusCode::BAD_REQUEST, "Die Anmeldung ist abgelaufen. Bitte noch einmal starten.")
        }
    }
}

/// There is no login with user name and password: the provider (Eider) manages all accounts.
/// A client that still asks gets a hint instead.
async fn login(Extension(panel): Extension<Arc<Panel>>) -> Response {
    let message = match panel.oidc_name() {
        "" => "Die Anmeldung ist auf diesem Server noch nicht eingerichtet.".to_owned(),
        name => format!("Anmelden geht nur über \"Mit {} anmelden\".", name),
    };
    api_error(StatusCode::BAD_REQUEST, &message)
}

async fn current_user(Extension(panel): Extension<Arc<Panel>>, headers: HeaderMap) -> Response {
    match user_of(&panel, &headers).await {
        Ok(user) => Json(user_json(&panel, &user)).into_response(),
        Err(res) => res,
    }
}

async fn logout(Extension(panel): Extension<Arc<Panel>>, headers: HeaderMap) -> Response {
    if let Some(token) = bearer(&headers) {
        if let Err(err) = panel.pm.db.delete_api_token(&token_hash(token)).await {
            log::error!("SimpleDesk API: deleting token failed: {}", err);
        }
    }
    StatusCode::OK.into_response()
}

#[derive(Deserialize)]
struct HeartbeatRequest {
    #[serde(default)]
    id: String,
    #[serde(default)]
    uuid: String,
    /// SimpleDesk client: seconds since the last keyboard or mouse input on the device.
    #[serde(default)]
    simpledesk_idle_secs: Option<u64>,
}

/// Every few seconds from each device (without a token). The answer tells the device the ID
/// an admin gave it: `assigned_id` differs from its ID, so it switches to it.
async fn heartbeat(Extension(panel): Extension<Arc<Panel>>, body: Bytes) -> Response {
    let pm = &panel.pm;
    let req = serde_json::from_slice::<HeartbeatRequest>(&body).ok();
    let assigned = match req
        .as_ref()
        .and_then(|req| base64::decode(req.uuid.trim()).ok().map(|uuid| (req, uuid)))
    {
        Some((req, uuid)) => {
            note_heartbeat(pm, req.id.trim(), &uuid, req.simpledesk_idle_secs).await;
            match pm.db.id_assignment(&uuid).await {
                Ok(assigned) => assigned,
                Err(err) => {
                    log::error!("SimpleDesk API: reading an ID for the heartbeat failed: {}", err);
                    None
                }
            }
        }
        None => None,
    };
    Json(json!({
        "simpledesk": {
            "id_assigned": !pm.accounts.ids_by_admin || assigned.is_some(),
            "assigned_id": assigned.unwrap_or_default(),
        }
    }))
    .into_response()
}

/// The device tells about itself (hostname, username, os, ...); the panel shows it. Only
/// for a registered device; else the client tries again in two minutes.
async fn sysinfo(Extension(panel): Extension<Arc<Panel>>, body: Bytes) -> Response {
    let Ok(Value::Object(info)) = serde_json::from_slice::<Value>(&body) else {
        return "SYSINFO_LATER".into_response();
    };
    let text = |key: &str| info.get(key).and_then(Value::as_str).unwrap_or_default().trim();
    let Ok(uuid) = base64::decode(text("uuid")) else {
        return "SYSINFO_LATER".into_response();
    };
    let keep = ["hostname", "username", "os", "version", "cpu", "memory"];
    let data: Map<String, Value> = info
        .iter()
        .filter(|(key, value)| keep.contains(&key.as_str()) && value.is_string())
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    match panel
        .pm
        .db
        .save_device_info(text("id"), &uuid, &Value::Object(data).to_string())
        .await
    {
        Ok(true) => "SYSINFO_UPDATED".into_response(),
        Ok(false) => "SYSINFO_LATER".into_response(),
        Err(err) => {
            log::error!("SimpleDesk API: saving the system info failed: {}", err);
            "SYSINFO_LATER".into_response()
        }
    }
}

/// All address book calls: /api/ab/<rest>, dispatched by method and path.
async fn address_book(
    Extension(panel): Extension<Arc<Panel>>,
    method: Method,
    Path(rest): Path<String>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let user = match user_of(&panel, &headers).await {
        Ok(user) => user,
        Err(res) => return res,
    };
    let segments: Vec<&str> = rest.trim_matches('/').split('/').collect();
    let result = match (method.as_str(), segments.as_slice()) {
        ("POST", ["settings"]) => Ok(Json(json!({ "max_peer_one_ab": 0 })).into_response()),
        ("POST", ["personal"]) => personal(&panel, &user).await,
        ("POST", ["shared", "profiles"]) => shared_profiles(&panel, &user, &query).await,
        ("POST", ["peers"]) => {
            let guid = query.get("ab").map(String::as_str).unwrap_or_default();
            peers(&panel, &user, guid, &query).await
        }
        ("POST", ["tags", guid]) => tags(&panel, &user, guid).await,
        ("POST", ["peer", "add", guid]) => add_peer(&panel, &user, guid, &body).await,
        ("PUT", ["peer", "update", guid]) => update_peer(&panel, &user, guid, &body).await,
        ("DELETE", ["peer", guid]) => delete_peers(&panel, &user, guid, &body).await,
        ("POST", ["tag", "add", guid]) | ("PUT", ["tag", "update", guid]) => {
            set_tag(&panel, &user, guid, &body).await
        }
        ("PUT", ["tag", "rename", guid]) => rename_tag(&panel, &user, guid, &body).await,
        ("DELETE", ["tag", guid]) => delete_tags(&panel, &user, guid, &body).await,
        _ => Err(api_error(StatusCode::NOT_FOUND, "Unbekannte Adressbuch-Anfrage.")),
    };
    match result {
        Ok(res) | Err(res) => res,
    }
}

type AbResult = Result<Response, Response>;

fn db_error(err: hbb_common::anyhow::Error) -> Response {
    log::error!("SimpleDesk API: address book failed: {}", err);
    api_error(StatusCode::BAD_REQUEST, "Serverfehler.")
}

fn bad_request(msg: &str) -> Response {
    api_error(StatusCode::BAD_REQUEST, msg)
}

/// Rules of a shared address book, as ShareRule in the client.
pub(crate) const RULE_READ: i64 = 1;
pub(crate) const RULE_WRITE: i64 = 2;
pub(crate) const RULE_FULL: i64 = 3;

/// The shared books `user` may read, with the rule on each: full control for the owner and
/// for admins, else the best rule a share for the user or one of the user's groups gives.
pub(crate) async fn shared_abs(pm: &PeerMap, user: &str) -> ResultType<Vec<(AbRow, i64)>> {
    let admin = pm.accounts.is_admin(user);
    Ok(pm
        .db
        .shared_abs_for(user)
        .await?
        .into_iter()
        .filter_map(|(ab, rule)| {
            let rule = if admin || ab.owner == user {
                RULE_FULL
            } else {
                rule.min(RULE_FULL)
            };
            (rule >= RULE_READ).then(|| (ab, rule))
        })
        .collect())
}

/// An address book with the rule `user` has on it; None if the user may not even read it.
/// A personal book is for its owner only, also not for admins.
pub(crate) async fn ab_access(pm: &PeerMap, user: &str, guid: &str) -> ResultType<Option<(AbRow, i64)>> {
    let Some(ab) = pm.db.get_ab(guid).await? else {
        return Ok(None);
    };
    if ab.personal {
        return Ok((ab.owner == user).then(|| (ab, RULE_FULL)));
    }
    Ok(shared_abs(pm, user)
        .await?
        .into_iter()
        .find(|(shared, _)| shared.guid == ab.guid))
}

/// The address book if `user` has at least rule `needed` on it.
async fn check_access(panel: &Panel, user: &str, guid: &str, needed: i64) -> Result<AbRow, Response> {
    match ab_access(&panel.pm, user, guid).await.map_err(db_error)? {
        Some((ab, rule)) if rule >= needed => Ok(ab),
        Some(_) => Err(api_error(StatusCode::FORBIDDEN, "Du darfst dieses Adressbuch nur lesen.")),
        None => Err(api_error(StatusCode::NOT_FOUND, "Adressbuch nicht gefunden.")),
    }
}

/// The client keeps a password hash only in the personal book and a password only in shared
/// books; the server keeps it that way too.
fn clean_peer(peer: &mut Map<String, Value>, personal: bool) {
    peer.remove(if personal { "password" } else { "hash" });
}

/// The page of `all` that the query's current and pageSize ask for.
fn page_of<'a, T>(all: &'a [T], query: &HashMap<String, String>) -> impl Iterator<Item = &'a T> {
    let current = query
        .get("current")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(1)
        .max(1);
    let size = query
        .get("pageSize")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(100)
        .clamp(1, MAX_PAGE_SIZE);
    all.iter().skip((current - 1).saturating_mul(size)).take(size)
}

async fn personal(panel: &Panel, user: &str) -> AbResult {
    let guid = panel.pm.db.personal_ab(user).await.map_err(db_error)?;
    Ok(Json(json!({ "guid": guid })).into_response())
}

/// The shared books the user may read, as the client's AbProfile.
async fn shared_profiles(panel: &Panel, user: &str, query: &HashMap<String, String>) -> AbResult {
    let books = shared_abs(&panel.pm, user).await.map_err(db_error)?;
    let data: Vec<Value> = page_of(&books, query)
        .map(|(ab, rule)| {
            json!({
                "guid": ab.guid,
                "name": ab.name,
                "owner": ab.owner,
                "note": "",
                "rule": rule,
                "info": {},
            })
        })
        .collect();
    Ok(Json(json!({ "total": books.len(), "data": data })).into_response())
}

async fn peers(panel: &Panel, user: &str, guid: &str, query: &HashMap<String, String>) -> AbResult {
    check_access(panel, user, guid, RULE_READ).await?;
    let all = panel.pm.db.list_ab_peers(guid).await.map_err(db_error)?;
    let data: Vec<Value> = page_of(&all, query)
        .filter_map(|data| serde_json::from_str(data).ok())
        .collect();
    Ok(Json(json!({ "total": all.len(), "data": data })).into_response())
}

async fn tags(panel: &Panel, user: &str, guid: &str) -> AbResult {
    check_access(panel, user, guid, RULE_READ).await?;
    let tags: Vec<Value> = panel
        .pm
        .db
        .list_ab_tags(guid)
        .await
        .map_err(db_error)?
        .into_iter()
        .map(|(name, color)| json!({ "name": name, "color": color }))
        .collect();
    Ok(Json(Value::Array(tags)).into_response())
}

/// An entry from the client: a JSON object with a non-empty string "id".
fn peer_object(body: &[u8]) -> Result<(String, Map<String, Value>), Response> {
    let Ok(Value::Object(peer)) = serde_json::from_slice::<Value>(body) else {
        return Err(bad_request("Ungültiger Eintrag."));
    };
    let id = peer
        .get("id")
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or_default()
        .to_owned();
    if id.is_empty() || id.len() > 100 {
        return Err(bad_request("Der Eintrag braucht eine ID."));
    }
    Ok((id, peer))
}

async fn add_peer(panel: &Panel, user: &str, guid: &str, body: &[u8]) -> AbResult {
    let ab = check_access(panel, user, guid, RULE_WRITE).await?;
    let (id, mut peer) = peer_object(body)?;
    clean_peer(&mut peer, ab.personal);
    peer.insert("id".to_owned(), Value::String(id.clone()));
    let data = Value::Object(peer).to_string();
    panel.pm.db.upsert_ab_peer(guid, &id, &data).await.map_err(db_error)?;
    Ok(StatusCode::OK.into_response())
}

async fn update_peer(panel: &Panel, user: &str, guid: &str, body: &[u8]) -> AbResult {
    let ab = check_access(panel, user, guid, RULE_WRITE).await?;
    let (id, mut changes) = peer_object(body)?;
    clean_peer(&mut changes, ab.personal);
    let Some(existing) = panel.pm.db.get_ab_peer(guid, &id).await.map_err(db_error)? else {
        return Err(api_error(StatusCode::NOT_FOUND, "Eintrag nicht gefunden."));
    };
    let mut peer = match serde_json::from_str::<Value>(&existing) {
        Ok(Value::Object(peer)) => peer,
        _ => Map::new(),
    };
    for (key, value) in changes {
        if key != "id" {
            peer.insert(key, value);
        }
    }
    peer.insert("id".to_owned(), Value::String(id.clone()));
    let data = Value::Object(peer).to_string();
    panel.pm.db.upsert_ab_peer(guid, &id, &data).await.map_err(db_error)?;
    Ok(StatusCode::OK.into_response())
}

fn string_list(body: &[u8]) -> Result<Vec<String>, Response> {
    serde_json::from_slice::<Vec<String>>(body).map_err(|_| bad_request("Ungültige Liste."))
}

async fn delete_peers(panel: &Panel, user: &str, guid: &str, body: &[u8]) -> AbResult {
    check_access(panel, user, guid, RULE_WRITE).await?;
    for id in string_list(body)? {
        panel.pm.db.delete_ab_peer(guid, &id).await.map_err(db_error)?;
    }
    Ok(StatusCode::OK.into_response())
}

#[derive(Deserialize)]
struct TagRequest {
    name: String,
    #[serde(default)]
    color: i64,
}

async fn set_tag(panel: &Panel, user: &str, guid: &str, body: &[u8]) -> AbResult {
    check_access(panel, user, guid, RULE_WRITE).await?;
    let Ok(tag) = serde_json::from_slice::<TagRequest>(body) else {
        return Err(bad_request("Ungültiger Tag."));
    };
    let name = tag.name.trim();
    if name.is_empty() || name.len() > 100 {
        return Err(bad_request("Der Tag braucht einen Namen."));
    }
    panel.pm.db.upsert_ab_tag(guid, name, tag.color).await.map_err(db_error)?;
    Ok(StatusCode::OK.into_response())
}

#[derive(Deserialize)]
struct RenameRequest {
    old: String,
    new: String,
}

async fn rename_tag(panel: &Panel, user: &str, guid: &str, body: &[u8]) -> AbResult {
    check_access(panel, user, guid, RULE_WRITE).await?;
    let Ok(rename) = serde_json::from_slice::<RenameRequest>(body) else {
        return Err(bad_request("Ungültige Umbenennung."));
    };
    let new = rename.new.trim();
    if new.is_empty() || new.len() > 100 {
        return Err(bad_request("Der Tag braucht einen Namen."));
    }
    let tags = panel.pm.db.list_ab_tags(guid).await.map_err(db_error)?;
    let color = tags
        .iter()
        .find(|(name, _)| *name == rename.old)
        .map(|(_, color)| *color)
        .unwrap_or_default();
    panel.pm.db.delete_ab_tag(guid, &rename.old).await.map_err(db_error)?;
    panel.pm.db.upsert_ab_tag(guid, new, color).await.map_err(db_error)?;
    edit_peer_tags(panel, guid, |tags| {
        for tag in tags.iter_mut() {
            if *tag == rename.old {
                *tag = new.to_owned();
            }
        }
    })
    .await?;
    Ok(StatusCode::OK.into_response())
}

async fn delete_tags(panel: &Panel, user: &str, guid: &str, body: &[u8]) -> AbResult {
    check_access(panel, user, guid, RULE_WRITE).await?;
    let names = string_list(body)?;
    for name in &names {
        panel.pm.db.delete_ab_tag(guid, name).await.map_err(db_error)?;
    }
    edit_peer_tags(panel, guid, |tags| tags.retain(|tag| !names.contains(tag))).await?;
    Ok(StatusCode::OK.into_response())
}

/// Applies `edit` to the tags of every entry in the address book and saves changed entries.
async fn edit_peer_tags(
    panel: &Panel,
    guid: &str,
    edit: impl Fn(&mut Vec<String>),
) -> Result<(), Response> {
    for data in panel.pm.db.list_ab_peers(guid).await.map_err(db_error)? {
        let Ok(Value::Object(mut peer)) = serde_json::from_str::<Value>(&data) else {
            continue;
        };
        let Some(id) = peer.get("id").and_then(Value::as_str).map(str::to_owned) else {
            continue;
        };
        let mut tags: Vec<String> = peer
            .get("tags")
            .and_then(Value::as_array)
            .map(|tags| tags.iter().filter_map(|tag| tag.as_str().map(str::to_owned)).collect())
            .unwrap_or_default();
        let before = tags.clone();
        edit(&mut tags);
        if tags != before {
            peer.insert("tags".to_owned(), json!(tags));
            let data = Value::Object(peer).to_string();
            panel.pm.db.upsert_ab_peer(guid, &id, &data).await.map_err(db_error)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::panel::{router, Panel};
    use axum::{
        body::Body,
        http::{header, Request, StatusCode},
        response::Response,
    };
    use hbb_common::tokio;
    use serde_json::{json, Value};
    use std::sync::Arc;
    use tower::ServiceExt;

    async fn test_panel(dir: &tempfile::TempDir) -> Arc<Panel> {
        let pm = crate::peer::test_peer_map(dir).await;
        Arc::new(Panel::new(pm, Default::default()).await.unwrap())
    }

    async fn call(panel: &Arc<Panel>, method: &str, path: &str, token: Option<&str>, body: Option<Value>) -> Response {
        let mut req = Request::builder().method(method).uri(path);
        if let Some(token) = token {
            req = req.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        let body = match body {
            Some(body) => {
                req = req.header(header::CONTENT_TYPE, "application/json");
                Body::from(body.to_string())
            }
            None => Body::empty(),
        };
        router(panel.clone()).oneshot(req.body(body).unwrap()).await.unwrap()
    }

    async fn text(res: Response) -> String {
        let bytes = hyper::body::to_bytes(res.into_body()).await.unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    async fn json_of(res: Response) -> Value {
        assert_eq!(res.status(), StatusCode::OK);
        serde_json::from_str(&text(res).await).unwrap()
    }

    /// An address book action: 200 with an empty body, as the client expects.
    async fn action(panel: &Arc<Panel>, method: &str, path: &str, token: &str, body: Value) {
        let res = call(panel, method, path, Some(token), Some(body)).await;
        assert_eq!(res.status(), StatusCode::OK, "{method} {path}");
        assert_eq!(text(res).await, "", "{method} {path}");
    }

    /// The token the client gets at the end of its login through the provider (that login
    /// itself is tested in oidc.rs).
    async fn login(panel: &Arc<Panel>, name: &str) -> String {
        panel.pm.db.ensure_external_user(name).await.unwrap();
        let res = json_of(super::token_response(panel, name, "Felix-Work-PC").await).await;
        assert_eq!(res["type"], "access_token");
        assert_eq!(res["user"]["name"], name);
        res["access_token"].as_str().unwrap().to_owned()
    }

    #[hbb_common::tokio::test]
    async fn client_logs_in_and_uses_its_address_book() {
        let dir = tempfile::tempdir().unwrap();
        let panel = test_panel(&dir).await;

        // No login with user name and password, also not for an account that exists.
        let res = call(&panel, "GET", "/api/login-options", None, None).await;
        assert_eq!(json_of(res).await, json!([]));
        panel.pm.db.ensure_external_user("felix").await.unwrap();
        for password in ["", "!", "falsch"] {
            let body = json!({"username": "felix", "password": password, "type": "account"});
            let res = call(&panel, "POST", "/api/login", None, Some(body)).await;
            assert_eq!(res.status(), StatusCode::BAD_REQUEST);
            let res = json_of_any(res).await;
            assert!(res["error"].as_str().unwrap().contains("nicht eingerichtet"), "{res}");
            assert!(res.get("access_token").is_none());
        }

        // The token from the login works for currentUser.
        let token = login(&panel, "felix").await;
        let res = call(&panel, "POST", "/api/currentUser", Some(&token), Some(json!({}))).await;
        assert_eq!(json_of(res).await["name"], "felix");
        let res = call(&panel, "POST", "/api/currentUser", Some("nope"), Some(json!({}))).await;
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

        // The personal book; the same guid every time.
        let guid = json_of(call(&panel, "POST", "/api/ab/personal", Some(&token), None).await).await
            ["guid"].as_str().unwrap().to_owned();
        let again = json_of(call(&panel, "POST", "/api/ab/personal", Some(&token), None).await).await;
        assert_eq!(again["guid"], guid.as_str());
        let res = call(&panel, "POST", "/api/ab/settings", Some(&token), None).await;
        assert_eq!(json_of(res).await["max_peer_one_ab"], 0);
        let res = call(&panel, "POST", "/api/ab/shared/profiles?current=1&pageSize=100", Some(&token), None).await;
        assert_eq!(json_of(res).await["total"], 0);

        // Tags and entries.
        action(&panel, "POST", &format!("/api/ab/tag/add/{guid}"), &token, json!({"name": "Amt", "color": 4283215696u32})).await;
        action(&panel, "POST", &format!("/api/ab/peer/add/{guid}"), &token,
            json!({"id": "Felix-Home-PC", "alias": "Zuhause", "tags": ["Amt"], "hash": "abc"})).await;
        action(&panel, "POST", &format!("/api/ab/peer/add/{guid}"), &token,
            json!({"id": "Server-PC", "alias": "", "tags": []})).await;
        action(&panel, "PUT", &format!("/api/ab/peer/update/{guid}"), &token,
            json!({"id": "Felix-Home-PC", "note": "Rechner im Büro zu Hause"})).await;
        let peers_path = format!("/api/ab/peers?current=1&pageSize=1&ab={guid}");
        let page = json_of(call(&panel, "POST", &peers_path, Some(&token), None).await).await;
        assert_eq!(page["total"], 2);
        assert_eq!(page["data"].as_array().unwrap().len(), 1);
        let first = &page["data"][0];
        assert_eq!(first["id"], "Felix-Home-PC");
        assert_eq!(first["alias"], "Zuhause");
        assert_eq!(first["note"], "Rechner im Büro zu Hause");
        assert_eq!(first["hash"], "abc");

        // Renaming a tag renames it in the entries too; deleting removes it.
        action(&panel, "PUT", &format!("/api/ab/tag/rename/{guid}"), &token, json!({"old": "Amt", "new": "Amt Eider"})).await;
        let tags = json_of(call(&panel, "POST", &format!("/api/ab/tags/{guid}"), Some(&token), None).await).await;
        assert_eq!(tags, json!([{"name": "Amt Eider", "color": 4283215696u32}]));
        let page = json_of(call(&panel, "POST", &format!("/api/ab/peers?ab={guid}"), Some(&token), None).await).await;
        assert_eq!(page["data"][0]["tags"], json!(["Amt Eider"]));
        action(&panel, "DELETE", &format!("/api/ab/tag/{guid}"), &token, json!(["Amt Eider"])).await;
        let page = json_of(call(&panel, "POST", &format!("/api/ab/peers?ab={guid}"), Some(&token), None).await).await;
        assert_eq!(page["data"][0]["tags"], json!([]));
        action(&panel, "DELETE", &format!("/api/ab/peer/{guid}"), &token, json!(["Server-PC"])).await;
        let page = json_of(call(&panel, "POST", &format!("/api/ab/peers?ab={guid}"), Some(&token), None).await).await;
        assert_eq!(page["total"], 1);

        // Another user cannot read or change this book.
        let other = login(&panel, "kollege").await;
        let res = call(&panel, "POST", &format!("/api/ab/peers?ab={guid}"), Some(&other), None).await;
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
        let res = call(&panel, "DELETE", &format!("/api/ab/peer/{guid}"), Some(&other), Some(json!(["Felix-Home-PC"]))).await;
        assert_eq!(res.status(), StatusCode::NOT_FOUND);

        // Logout ends the token.
        let res = call(&panel, "POST", "/api/logout", Some(&token), Some(json!({}))).await;
        assert_eq!(res.status(), StatusCode::OK);
        let res = call(&panel, "POST", "/api/ab/personal", Some(&token), None).await;
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    }

    async fn json_of_any(res: Response) -> Value {
        serde_json::from_str(&text(res).await).unwrap()
    }

    #[hbb_common::tokio::test]
    async fn token_ends_after_the_configured_days() {
        let dir = tempfile::tempdir().unwrap();
        let panel = test_panel(&dir).await;
        let token = login(&panel, "felix").await;
        let current_user = || call(&panel, "POST", "/api/currentUser", Some(&token), Some(json!({})));
        assert_eq!(current_user().await.status(), StatusCode::OK);

        // A day before the end it still works, then the client gets the 401 that logs it out.
        let days = panel.pm.accounts.token_days;
        panel.pm.db.age_logins("felix", (days - 1) * 24).await.unwrap();
        assert_eq!(current_user().await.status(), StatusCode::OK);
        assert_eq!(super::token_user(&panel.pm, &token).await.as_deref(), Some("felix"));
        panel.pm.db.age_logins("felix", 25).await.unwrap();
        assert_eq!(current_user().await.status(), StatusCode::UNAUTHORIZED);
        let res = call(&panel, "POST", "/api/ab/personal", Some(&token), None).await;
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(super::token_user(&panel.pm, &token).await, None);

        // The next login removes the old token from the database.
        let fresh = login(&panel, "felix").await;
        assert_eq!(super::token_user(&panel.pm, &fresh).await.as_deref(), Some("felix"));
        let hash = super::token_hash(&token);
        assert_eq!(panel.pm.db.get_api_token_user(&hash, 100_000).await.unwrap(), None);
    }

    #[hbb_common::tokio::test]
    async fn shared_books_follow_their_rules() {
        let dir = tempfile::tempdir().unwrap();
        let mut pm = crate::peer::test_peer_map(&dir).await;
        pm.accounts = Arc::new(crate::accounts::Accounts::with_admins("felix"));
        let panel = Arc::new(Panel::new(pm, Default::default()).await.unwrap());
        let db = &panel.pm.db;
        let [felix, anna, ben, carl, dora] = [
            login(&panel, "felix").await,
            login(&panel, "anna").await,
            login(&panel, "ben").await,
            login(&panel, "carl").await,
            login(&panel, "dora").await,
        ];
        // anna owns "Server"; the group Team may write, carl may read, dora nothing.
        let guid = db.create_shared_ab("anna", "Server").await.unwrap().unwrap();
        assert_eq!(db.create_shared_ab("ben", "server").await.unwrap(), None);
        assert!(db.create_group("Team").await.unwrap());
        db.add_group_member("Team", "ben").await.unwrap();
        db.set_ab_rule(&guid, "group", "Team", 2).await.unwrap();
        db.set_ab_rule(&guid, "user", "carl", 1).await.unwrap();
        // A weaker share for ben himself does not take the group's right away.
        db.set_ab_rule(&guid, "user", "ben", 1).await.unwrap();

        let profiles = |token: String| {
            let panel = panel.clone();
            async move {
                let path = "/api/ab/shared/profiles?current=1&pageSize=100";
                json_of(call(&panel, "POST", path, Some(&token), None).await).await
            }
        };
        let page = profiles(anna.clone()).await;
        assert_eq!(page["total"], 1);
        assert_eq!(
            page["data"][0],
            json!({"guid": guid, "name": "Server", "owner": "anna", "note": "", "rule": 3, "info": {}})
        );
        for (token, rule) in [(&felix, 3), (&ben, 2), (&carl, 1)] {
            assert_eq!(profiles(token.clone()).await["data"][0]["rule"], rule);
        }
        assert_eq!(profiles(dora.clone()).await, json!({"total": 0, "data": []}));

        // Writing needs "schreiben"; readers get a message the client shows.
        let add = format!("/api/ab/peer/add/{guid}");
        action(&panel, "POST", &add, &ben, json!({"id": "Server-1", "password": "geheim", "hash": "x", "tags": []})).await;
        let res = call(&panel, "POST", &add, Some(&carl), Some(json!({"id": "Server-2"}))).await;
        assert_eq!(res.status(), StatusCode::FORBIDDEN);
        assert!(json_of_any(res).await["error"].as_str().unwrap().contains("nur lesen"));
        let res = call(&panel, "POST", &format!("/api/ab/tag/add/{guid}"), Some(&carl), Some(json!({"name": "X"}))).await;
        assert_eq!(res.status(), StatusCode::FORBIDDEN);
        action(&panel, "POST", &format!("/api/ab/tag/add/{guid}"), &ben, json!({"name": "Linux", "color": 1})).await;

        // Everybody with access reads the entry; a shared book keeps no password hash.
        let peers_path = format!("/api/ab/peers?ab={guid}");
        for token in [&anna, &ben, &carl, &felix] {
            let page = json_of(call(&panel, "POST", &peers_path, Some(token), None).await).await;
            assert_eq!(page["data"][0]["id"], "Server-1");
            assert_eq!(page["data"][0]["password"], "geheim");
            assert!(page["data"][0].get("hash").is_none());
        }
        let res = call(&panel, "POST", &peers_path, Some(&dora), None).await;
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
        let res = call(&panel, "POST", &format!("/api/ab/tags/{guid}"), Some(&dora), None).await;
        assert_eq!(res.status(), StatusCode::NOT_FOUND);

        // The personal book keeps working and keeps no password.
        let personal = json_of(call(&panel, "POST", "/api/ab/personal", Some(&ben), None).await).await
            ["guid"].as_str().unwrap().to_owned();
        action(&panel, "POST", &format!("/api/ab/peer/add/{personal}"), &ben,
            json!({"id": "Ben-PC", "password": "nicht-speichern", "hash": "abc"})).await;
        let page = json_of(call(&panel, "POST", &format!("/api/ab/peers?ab={personal}"), Some(&ben), None).await).await;
        assert_eq!(page["total"], 1);
        assert_eq!(page["data"][0]["hash"], "abc");
        assert!(page["data"][0].get("password").is_none());
        // Not even an admin reads somebody's personal book.
        let res = call(&panel, "POST", &format!("/api/ab/peers?ab={personal}"), Some(&felix), None).await;
        assert_eq!(res.status(), StatusCode::NOT_FOUND);

        // Leaving the group or deleting it ends the share.
        db.remove_group_member("Team", "ben").await.unwrap();
        assert_eq!(profiles(ben.clone()).await["data"][0]["rule"], 1);
        db.delete_ab_rule(&guid, "user", "ben").await.unwrap();
        db.add_group_member("Team", "ben").await.unwrap();
        db.delete_group("Team").await.unwrap();
        assert_eq!(profiles(ben.clone()).await["total"], 0);
    }

    #[hbb_common::tokio::test]
    async fn signing_in_on_a_device_makes_it_yours_but_not_for_admins() {
        let dir = tempfile::tempdir().unwrap();
        let mut pm = crate::peer::test_peer_map(&dir).await;
        pm.accounts = Arc::new(crate::accounts::Accounts::with_admins("felix"));
        let panel = Arc::new(Panel::new(pm, Default::default()).await.unwrap());
        let db = &panel.pm.db;
        db.insert_peer("Anna-PC", b"uuid-anna", b"pk", "").await.unwrap();
        let uuid = base64::encode(b"uuid-anna");
        let owner = || async { db.device_owner("Anna-PC").await.unwrap().unwrap() };
        let none = (String::new(), String::new());

        // Only with the uuid the device registered with.
        super::take_device(&panel, "carl", "Anna-PC", &base64::encode(b"other")).await;
        super::take_device(&panel, "carl", "Anna-PC", "kein base64").await;
        assert_eq!(owner().await, none);
        super::take_device(&panel, "anna", "Anna-PC", &uuid).await;
        assert_eq!(owner().await, ("anna".to_owned(), String::new()));
        assert!(super::may_control(&panel.pm, "anna", "Anna-PC").await);
        assert!(!super::may_control(&panel.pm, "carl", "Anna-PC").await);

        // An admin who signs in to help does not take the device.
        super::take_device(&panel, "Felix", "Anna-PC", &uuid).await;
        assert_eq!(owner().await.0, "anna");
        assert!(super::may_control(&panel.pm, "felix", "Anna-PC").await);

        // The next user who signs in there becomes the owner; the group stays.
        assert!(db.create_group("Amt").await.unwrap());
        assert!(db.assign_device("Anna-PC", "anna", "Amt").await.unwrap());
        super::take_device(&panel, "ben", "Anna-PC", &uuid).await;
        assert_eq!(owner().await, ("ben".to_owned(), "Amt".to_owned()));

        // The client learns the role.
        let admin = login(&panel, "felix").await;
        let user = login(&panel, "anna").await;
        let res = call(&panel, "POST", "/api/currentUser", Some(&admin), Some(json!({}))).await;
        assert_eq!(json_of(res).await["is_admin"], true);
        let res = call(&panel, "POST", "/api/currentUser", Some(&user), Some(json!({}))).await;
        assert_eq!(json_of(res).await["is_admin"], false);
    }

    #[hbb_common::tokio::test]
    async fn heartbeat_tells_the_id_and_only_admins_change_it() {
        let dir = tempfile::tempdir().unwrap();
        let mut pm = crate::peer::test_peer_map(&dir).await;
        pm.accounts = Arc::new(crate::accounts::Accounts::with_ids_by_admin("felix"));
        let panel = Arc::new(Panel::new(pm, Default::default()).await.unwrap());
        panel.pm.db.insert_peer("123456789", b"uuid-neu", b"pk", "").await.unwrap();
        panel.pm.db.insert_peer("Kasse-PC", b"uuid-kasse", b"pk", "").await.unwrap();
        let uuid = base64::encode(b"uuid-neu");
        let heartbeat = || {
            let body = json!({"id": "123456789", "uuid": uuid, "ver": 1001017, "modified_at": 0});
            call(&panel, "POST", "/api/heartbeat", None, Some(body))
        };

        // A new device has no ID from an admin yet.
        let res = json_of(heartbeat().await).await;
        assert_eq!(res, json!({"simpledesk": {"id_assigned": false, "assigned_id": ""}}));

        // Only an admin may change it; everybody else gets a 403 with the reason.
        let admin = login(&panel, "felix").await;
        let user = login(&panel, "anna").await;
        let change = |new_id: &str| json!({"id": "123456789", "uuid": uuid, "new_id": new_id});
        let path = "/api/simpledesk/change-id";
        let res = call(&panel, "POST", path, Some(&user), Some(change("Rathaus-PC"))).await;
        assert_eq!(res.status(), StatusCode::FORBIDDEN);
        assert!(json_of_any(res).await["error"].as_str().unwrap().contains("Nur Admins"));
        let res = call(&panel, "POST", path, None, Some(change("Rathaus-PC"))).await;
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
        for new_id in ["kasse-pc", "1-falsch", "zu-lang-fuer-eine-id"] {
            let res = call(&panel, "POST", path, Some(&admin), Some(change(new_id))).await;
            assert_eq!(res.status(), StatusCode::FORBIDDEN, "{new_id}");
            assert!(json_of_any(res).await["error"].is_string());
        }
        let wrong = json!({"id": "123456789", "uuid": base64::encode(b"other"), "new_id": "Rathaus-PC"});
        let res = call(&panel, "POST", path, Some(&admin), Some(wrong)).await;
        assert_eq!(res.status(), StatusCode::FORBIDDEN);
        assert_eq!(json_of(heartbeat().await).await["simpledesk"]["id_assigned"], false);

        // The admin's change reaches the device with its next heartbeat.
        let res = call(&panel, "POST", path, Some(&admin), Some(change("Rathaus-PC"))).await;
        assert_eq!(json_of(res).await, json!({}));
        let res = json_of(heartbeat().await).await;
        assert_eq!(res, json!({"simpledesk": {"id_assigned": true, "assigned_id": "Rathaus-PC"}}));

        // A device that kept its ID gets that ID back.
        let kasse = json!({"id": "Kasse-PC", "uuid": base64::encode(b"uuid-kasse"), "new_id": "Kasse-PC"});
        let res = call(&panel, "POST", path, Some(&admin), Some(kasse)).await;
        assert_eq!(res.status(), StatusCode::OK);
        let body = json!({"id": "Kasse-PC", "uuid": base64::encode(b"uuid-kasse")});
        let res = json_of(call(&panel, "POST", "/api/heartbeat", None, Some(body)).await).await;
        assert_eq!(res["simpledesk"], json!({"id_assigned": true, "assigned_id": "Kasse-PC"}));
    }

    #[test]
    fn device_state_follows_input_and_connection() {
        use super::{device_state, since_text, DeviceState::*};
        let now = 1_000_000;
        let afk = 5 * 60;
        assert_eq!(device_state(true, None, 0, now, afk), (Active, now));
        assert_eq!(device_state(true, Some(now - 60), 0, now, afk), (Active, now - 60));
        assert_eq!(device_state(true, Some(now - afk), 0, now, afk), (Afk, now - afk));
        assert_eq!(device_state(false, Some(now - 10), now - 600, now, afk), (Offline, now - 600));
        assert_eq!(device_state(false, None, 0, now, afk), (Offline, 0));
        assert_eq!(since_text(now - 30, now), "seit weniger als 1 min");
        assert_eq!(since_text(now - 12 * 60, now), "seit 12 min");
        assert_eq!(since_text(now - 3 * 3600, now), "seit 3 h");
        assert_eq!(since_text(now - 3 * 86400, now), "seit 3 Tagen");
        assert_eq!(since_text(0, now), "");
    }

    /// Marks the registered device `id` online, as hbbs does when it registers.
    async fn come_online(panel: &Arc<Panel>, id: &str) {
        let peer = panel.pm.get(id).await.unwrap();
        peer.write().await.last_reg_time = std::time::Instant::now();
    }

    #[hbb_common::tokio::test]
    async fn peer_status_tells_active_afk_and_offline_to_who_may_see() {
        let dir = tempfile::tempdir().unwrap();
        let mut pm = crate::peer::test_peer_map(&dir).await;
        pm.accounts = Arc::new(crate::accounts::Accounts::with_admins("felix"));
        let panel = Arc::new(Panel::new(pm, Default::default()).await.unwrap());
        let db = &panel.pm.db;
        for id in ["Anna-PC", "Lager-PC", "Kasse-PC"] {
            db.insert_peer(id, id.as_bytes(), b"pk", "").await.unwrap();
        }
        let felix = login(&panel, "felix").await;
        let anna = login(&panel, "anna").await;
        assert!(db.assign_device("Anna-PC", "anna", "").await.unwrap());
        let heartbeat = |id: &str, uuid: &[u8], idle: u64| {
            json!({"id": id, "uuid": base64::encode(uuid), "ver": 1001017, "simpledesk_idle_secs": idle})
        };

        // Anna-PC was used 2 minutes ago, nobody touched Lager-PC for 12 minutes, Kasse-PC is off.
        come_online(&panel, "Anna-PC").await;
        come_online(&panel, "Lager-PC").await;
        for (id, idle) in [("Anna-PC", 120), ("Lager-PC", 12 * 60), ("Kasse-PC", 0)] {
            let res = call(&panel, "POST", "/api/heartbeat", None, Some(heartbeat(id, id.as_bytes(), idle))).await;
            assert_eq!(res.status(), StatusCode::OK);
        }
        // A heartbeat with another uuid changes nothing.
        let fake = heartbeat("Anna-PC", b"fremd", 3600);
        assert_eq!(call(&panel, "POST", "/api/heartbeat", None, Some(fake)).await.status(), StatusCode::OK);

        let ids = json!({"ids": ["Anna-PC", "Lager-PC", "Kasse-PC", "Gibt-Es-Nicht"]});
        let path = "/api/simpledesk/peer-status";
        let res = json_of(call(&panel, "POST", path, Some(&felix), Some(ids.clone())).await).await;
        let now = super::unix_now();
        let since = |id: &str| res[id]["since"].as_u64().unwrap();
        assert_eq!(res["Anna-PC"]["state"], "active");
        assert!(since("Anna-PC").abs_diff(now - 120) <= 2, "{res}");
        assert_eq!(res["Lager-PC"]["state"], "afk");
        assert!(since("Lager-PC").abs_diff(now - 12 * 60) <= 2, "{res}");
        assert_eq!(res["Kasse-PC"]["state"], "offline");
        assert!(since("Kasse-PC").abs_diff(now) <= 2, "{res}");
        assert!(res.get("Gibt-Es-Nicht").is_none(), "{res}");

        // anna sees only her own device; without a token nobody sees anything.
        let res = json_of(call(&panel, "POST", path, Some(&anna), Some(ids.clone())).await).await;
        assert_eq!(res.as_object().unwrap().keys().collect::<Vec<_>>(), ["Anna-PC"]);
        assert_eq!(call(&panel, "POST", path, None, Some(ids)).await.status(), StatusCode::UNAUTHORIZED);
        let res = call(&panel, "POST", path, Some(&anna), Some(json!("kein Objekt"))).await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    }

    #[hbb_common::tokio::test]
    async fn server_info_names_the_key_without_login() {
        let dir = tempfile::tempdir().unwrap();
        let pm = crate::peer::test_peer_map(&dir).await;
        let key = "OeVuKk5nlHiXp+APNn0Y3pC1Iwpwn44JGqrQCsWqmBw=";
        let panel = Arc::new(
            Panel::new(pm, Default::default())
                .await
                .unwrap()
                .with_public_key(key.to_owned()),
        );
        let res = call(&panel, "GET", "/api/simpledesk/server-info", None, None).await;
        assert_eq!(
            json_of(res).await,
            json!({"key": key, "name": "SimpleDesk", "version": crate::version::VERSION})
        );
    }

    #[hbb_common::tokio::test]
    async fn quiet_answers_for_heartbeat_sysinfo_and_groups() {
        let dir = tempfile::tempdir().unwrap();
        let panel = test_panel(&dir).await;
        let body = json!({"id": "Felix-Work-PC", "uuid": "dXVpZA==", "ver": 1, "modified_at": 0});
        let res = call(&panel, "POST", "/api/heartbeat", None, Some(body)).await;
        let quiet = json!({"simpledesk": {"id_assigned": true, "assigned_id": ""}});
        assert_eq!(json_of(res).await, quiet);
        // System info only for a registered device; the client tries again later.
        let info = json!({"id": "Felix-Work-PC", "uuid": "dXVpZA==", "hostname": "BUERO-12", "os": "windows / Windows 11"});
        let res = call(&panel, "POST", "/api/sysinfo", None, Some(info.clone())).await;
        assert_eq!(text(res).await, "SYSINFO_LATER");
        panel.pm.db.insert_peer("Felix-Work-PC", b"uuid", b"pk", "").await.unwrap();
        let res = call(&panel, "POST", "/api/sysinfo", None, Some(info)).await;
        assert_eq!(text(res).await, "SYSINFO_UPDATED");
        let devices = panel.pm.db.list_devices().await.unwrap();
        let sysinfo: Value = serde_json::from_str(&devices[0].sysinfo).unwrap();
        assert_eq!(sysinfo, json!({"hostname": "BUERO-12", "os": "windows / Windows 11"}));
        let res = call(&panel, "GET", "/api/peers?accessible&status=1", None, None).await;
        assert_eq!(json_of(res).await, json!({"total": 0, "data": []}));
        // Log records are stored (see audit.rs); other audit calls stay quiet.
        let res = call(&panel, "GET", "/api/audit/conn/active?id=Felix-Work-PC", None, None).await;
        assert_eq!(res.status(), StatusCode::OK);
    }
}
