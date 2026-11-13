//! SimpleDesk: the HTTP API the client uses for its account and address book.
//!
//! Built from the open client source (flutter/lib/models/user_model.dart, ab_model.dart and
//! src/hbbs_http/), not from any closed server. Errors are `{"error": "..."}`; address book
//! actions answer 200 with an empty body, because the client treats any body as an error.

use crate::oidc::ClientLoginState;
use crate::panel::{hex, Panel};
use axum::{
    body::Bytes,
    extract::{Extension, Path, Query},
    http::{header, HeaderMap, Method, StatusCode},
    response::{IntoResponse, Response},
    routing::{any, get, post},
    Json, Router,
};
use hbb_common::log;
use serde_derive::Deserialize;
use serde_json::{json, Map, Value};
use sodiumoxide::{crypto::hash::sha256, randombytes::randombytes};
use std::{collections::HashMap, sync::Arc};

const MAX_PAGE_SIZE: usize = 1000;

pub(crate) fn routes() -> Router {
    Router::new()
        .route("/api/simpledesk/server-info", get(server_info))
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
        .route("/api/audit/*rest", any(ok_empty))
}

fn api_error(status: StatusCode, msg: &str) -> Response {
    (status, Json(json!({ "error": msg }))).into_response()
}

async fn ok_empty() -> Response {
    StatusCode::OK.into_response()
}

async fn empty_page() -> Response {
    Json(json!({ "total": 0, "data": [] })).into_response()
}

pub(crate) fn token_hash(token: &str) -> String {
    hex(&sha256::hash(token.as_bytes()).0)
}

/// The user an access token belongs to; None for an empty, unknown or failing lookup.
pub(crate) async fn token_user(db: &crate::database::Database, token: &str) -> Option<String> {
    let token = token.trim();
    if token.is_empty() {
        return None;
    }
    match db.get_api_token_user(&token_hash(token)).await {
        Ok(user) => user,
        Err(err) => {
            log::error!("SimpleDesk API: reading token failed: {}", err);
            None
        }
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
    match panel.pm.db.get_api_token_user(&token_hash(token)).await {
        Ok(Some(user)) => Ok(user),
        Ok(None) => Err(unauthorized()),
        Err(err) => {
            log::error!("SimpleDesk API: reading token failed: {}", err);
            Err(api_error(StatusCode::BAD_REQUEST, "Serverfehler."))
        }
    }
}

fn user_json(name: &str) -> Value {
    json!({
        "name": name,
        "display_name": name,
        "email": "",
        "note": "",
        "status": 1,
        "is_admin": true,
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
    if let Err(err) = panel
        .pm
        .db
        .insert_api_token(&token_hash(&token), name, device_id)
        .await
    {
        log::error!("SimpleDesk API: saving token failed: {}", err);
        return api_error(StatusCode::BAD_REQUEST, "Serverfehler.");
    }
    log::info!("SimpleDesk API: {} logged in on device {}", name, device_id);
    Json(json!({
        "type": "access_token",
        "access_token": token,
        "user": user_json(name),
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
        ClientLoginState::Done(user) => token_response(&panel, &user, field("id")).await,
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
        Ok(user) => Json(user_json(&user)).into_response(),
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

async fn heartbeat() -> Response {
    Json(json!({})).into_response()
}

async fn sysinfo() -> Response {
    "SYSINFO_UPDATED".into_response()
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
        // Shared address books come later.
        ("POST", ["shared", "profiles"]) => Ok(empty_page().await),
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

/// Only the owner may use an address book.
async fn check_owner(panel: &Panel, user: &str, guid: &str) -> Result<(), Response> {
    match panel.pm.db.ab_owner(guid).await.map_err(db_error)? {
        Some(owner) if owner == user => Ok(()),
        _ => Err(api_error(StatusCode::NOT_FOUND, "Adressbuch nicht gefunden.")),
    }
}

async fn personal(panel: &Panel, user: &str) -> AbResult {
    let guid = panel.pm.db.personal_ab(user).await.map_err(db_error)?;
    Ok(Json(json!({ "guid": guid })).into_response())
}

async fn peers(panel: &Panel, user: &str, guid: &str, query: &HashMap<String, String>) -> AbResult {
    check_owner(panel, user, guid).await?;
    let all = panel.pm.db.list_ab_peers(guid).await.map_err(db_error)?;
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
    let data: Vec<Value> = all
        .iter()
        .skip((current - 1) * size)
        .take(size)
        .filter_map(|data| serde_json::from_str(data).ok())
        .collect();
    Ok(Json(json!({ "total": all.len(), "data": data })).into_response())
}

async fn tags(panel: &Panel, user: &str, guid: &str) -> AbResult {
    check_owner(panel, user, guid).await?;
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
    check_owner(panel, user, guid).await?;
    let (id, mut peer) = peer_object(body)?;
    peer.insert("id".to_owned(), Value::String(id.clone()));
    let data = Value::Object(peer).to_string();
    panel.pm.db.upsert_ab_peer(guid, &id, &data).await.map_err(db_error)?;
    Ok(StatusCode::OK.into_response())
}

async fn update_peer(panel: &Panel, user: &str, guid: &str, body: &[u8]) -> AbResult {
    check_owner(panel, user, guid).await?;
    let (id, changes) = peer_object(body)?;
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
    check_owner(panel, user, guid).await?;
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
    check_owner(panel, user, guid).await?;
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
    check_owner(panel, user, guid).await?;
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
    check_owner(panel, user, guid).await?;
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
        assert_eq!(json_of(res).await, json!({}));
        let res = call(&panel, "POST", "/api/sysinfo", None, Some(json!({"id": "Felix-Work-PC"}))).await;
        assert_eq!(text(res).await, "SYSINFO_UPDATED");
        let res = call(&panel, "GET", "/api/peers?accessible&status=1", None, None).await;
        assert_eq!(json_of(res).await, json!({"total": 0, "data": []}));
        let res = call(&panel, "POST", "/api/audit/conn", None, Some(json!({}))).await;
        assert_eq!(res.status(), StatusCode::OK);
    }
}
