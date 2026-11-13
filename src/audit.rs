//! SimpleDesk: the log behind the page "Protokoll".
//!
//! The controlled device posts what happens to /api/audit/conn, /api/audit/file and
//! /api/audit/alarm (src/server/connection.rs of the open client), without a token. Every
//! connection request that goes through hbbs gets a reference (ControlledContext.conn_audit_ref)
//! that the device sends back with its "new" record, so the log knows which signed-in user
//! connected. Changes by admins in the panel and by the API are logged here too.
//! AUDIT_DAYS says how long rows stay.

use crate::api::unix_now;
use crate::database::NewAudit;
use crate::panel::{hex, Panel};
use crate::peer::PeerMap;
use axum::{
    body::Bytes,
    extract::{Extension, Path},
    http::{Method, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use hbb_common::{
    log,
    tokio::{self, sync::Mutex},
    ResultType,
};
use serde_json::{json, Map, Value};
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

/// How long a connection reference waits for the device's records.
const REF_TTL: Duration = Duration::from_secs(10 * 60);
const MAX_REFS: usize = 10_000;
/// The client retries a record for two minutes and expects the server to know its nonce for
/// five, so a retry of a stored record is not stored twice.
const NONCE_TTL: Duration = Duration::from_secs(5 * 60);
const MAX_NONCES: usize = 100_000;
const MAX_NONCE_LEN: usize = 64;
/// The records of one connection are matched within this time.
const CONN_MAX_SECS: u64 = 7 * 24 * 3600;
/// How many file names a row keeps.
const MAX_FILES_SHOWN: usize = 5;

/// Who asked hbbs for a connection: the signed-in user ('' if none) and the address hbbs saw.
struct ConnRef {
    user: String,
    ip: String,
    at: Instant,
}

lazy_static::lazy_static! {
    static ref CONN_REFS: Mutex<HashMap<String, ConnRef>> = Default::default();
    static ref NONCES: Mutex<HashMap<String, Instant>> = Default::default();
}

/// A reference for a connection request, which hbbs passes to the device. `token` is the
/// access token of the controlling client (may be empty), `from` its address.
pub(crate) async fn new_conn_ref(pm: &PeerMap, token: &str, from: SocketAddr) -> String {
    let user = crate::api::token_user(pm, token).await.unwrap_or_default();
    let reference = hex(uuid::Uuid::new_v4().as_bytes());
    let mut refs = CONN_REFS.lock().await;
    if refs.len() >= MAX_REFS {
        refs.retain(|_, r| r.at.elapsed() < REF_TTL);
        if refs.len() >= MAX_REFS {
            return String::new();
        }
    }
    refs.insert(
        reference.clone(),
        ConnRef {
            user,
            ip: from.ip().to_string(),
            at: Instant::now(),
        },
    );
    reference
}

/// The user and address of a connection reference, if it is known and fresh.
pub(crate) async fn ref_of(reference: &str) -> Option<(String, String)> {
    if reference.is_empty() {
        return None;
    }
    let refs = CONN_REFS.lock().await;
    refs.get(reference)
        .filter(|r| r.at.elapsed() < REF_TTL)
        .map(|r| (r.user.clone(), r.ip.clone()))
}

/// Notes the nonce of a record; false if the record came before (a retry of a stored record).
async fn first_time(nonce: &str) -> bool {
    if nonce.is_empty() || nonce.len() > MAX_NONCE_LEN {
        return true;
    }
    let mut nonces = NONCES.lock().await;
    if nonces.get(nonce).is_some_and(|at| at.elapsed() < NONCE_TTL) {
        return false;
    }
    if nonces.len() >= MAX_NONCES {
        nonces.retain(|_, at| at.elapsed() < NONCE_TTL);
    }
    nonces.insert(nonce.to_owned(), Instant::now());
    true
}

/// Storing failed, so the client's retry must be stored.
async fn forget_nonce(nonce: &str) {
    NONCES.lock().await.remove(nonce);
}

/// At most `max` characters of a text from a device.
fn short(text: &str, max: usize) -> String {
    text.trim().chars().take(max).collect()
}

fn text(record: &Map<String, Value>, key: &str) -> String {
    short(record.get(key).and_then(Value::as_str).unwrap_or_default(), 1000)
}

/// The guid of the device registered with this ID and uuid.
async fn registered_guid(pm: &PeerMap, id: &str, uuid: &[u8]) -> Option<Vec<u8>> {
    let peer = pm.get(id).await?;
    let peer = peer.read().await;
    (!peer.uuid.is_empty() && &peer.uuid[..] == uuid && !peer.guid.is_empty()).then(|| peer.guid.clone())
}

#[derive(Clone, Copy)]
enum Kind {
    Conn,
    File,
    Alarm,
}

/// All /api/audit/<rest> calls. Records of conn, file and alarm are stored; anything else is
/// answered with an empty 200, as before. Success is an empty body; a failed write answers
/// `{"error": ...}`, which the client retries.
pub(crate) async fn audit(
    Extension(panel): Extension<Arc<Panel>>,
    method: Method,
    Path(rest): Path<String>,
    body: Bytes,
) -> Response {
    let kind = match (method.as_str(), rest.trim_matches('/')) {
        ("POST", "conn") => Kind::Conn,
        ("POST", "file") => Kind::File,
        ("POST", "alarm") => Kind::Alarm,
        _ => return StatusCode::OK.into_response(),
    };
    let refuse = |msg: &str| (StatusCode::BAD_REQUEST, Json(json!({ "error": msg }))).into_response();
    let Ok(Value::Object(record)) = serde_json::from_slice::<Value>(&body) else {
        return refuse("Ungültige Anfrage.");
    };
    let id = short(&text(&record, "id"), 100);
    let Ok(uuid) = base64::decode(text(&record, "uuid")) else {
        return refuse("Unbekanntes Gerät.");
    };
    let pm = &panel.pm;
    let Some(guid) = registered_guid(pm, &id, &uuid).await else {
        log::debug!("SimpleDesk audit: record of the unknown device {} dropped", id);
        return refuse("Unbekanntes Gerät.");
    };
    let nonce = text(&record, "nonce");
    if !first_time(&nonce).await {
        return StatusCode::OK.into_response();
    }
    let result = match kind {
        Kind::Conn => conn_record(pm, guid, id, &record).await,
        Kind::File => file_record(pm, guid, id, &record).await,
        Kind::Alarm => alarm_record(pm, guid, id, &record).await,
    };
    match result {
        Ok(()) => StatusCode::OK.into_response(),
        Err(err) => {
            log::error!("SimpleDesk audit: saving a record failed: {}", err);
            forget_nonce(&nonce).await;
            Json(json!({ "error": "Serverfehler." })).into_response()
        }
    }
}

fn conn_type_label(conn_type: i64) -> &'static str {
    match conn_type {
        1 => "Dateiübertragung",
        2 => "Portweiterleitung",
        3 => "Kamera",
        4 => "Terminal",
        _ => "Fernsteuerung",
    }
}

/// A connection: "new" when it comes in, then a record with "peer" once the controlling
/// device is logged in, and "close" at the end.
async fn conn_record(pm: &PeerMap, guid: Vec<u8>, id: String, record: &Map<String, Value>) -> ResultType<()> {
    let db = &pm.db;
    let now = unix_now();
    let conn_id = record.get("conn_id").and_then(Value::as_i64).unwrap_or_default();
    let action = text(record, "action");
    if action == "new" {
        let (user, ip) = match ref_of(&text(record, "conn_audit_ref")).await {
            Some(found) => found,
            None => (String::new(), text(record, "ip")),
        };
        let row = NewAudit {
            created_at: now,
            kind: "conn",
            device_guid: Some(guid),
            device_id: id,
            user,
            ip: short(&ip, 64),
            conn_id,
            ..Default::default()
        };
        db.insert_audit(&row).await?;
        return Ok(());
    }
    let open = db.open_audit_conn(&guid, conn_id, now.saturating_sub(CONN_MAX_SECS)).await?;
    if action == "close" {
        if let Some((row, _)) = open {
            db.end_audit_conn(row, now).await?;
        }
        return Ok(());
    }
    // Logged in: "peer" is [id, name] of the controlling device.
    let Some(peer) = record.get("peer").and_then(Value::as_array) else {
        return Ok(());
    };
    let part = |i: usize| short(peer.get(i).and_then(Value::as_str).unwrap_or_default(), 100);
    let (peer_id, peer_name) = (part(0), part(1));
    let detail = conn_type_label(record.get("type").and_then(Value::as_i64).unwrap_or_default());
    match open {
        Some((row, _)) => db.authorize_audit_conn(row, &peer_id, &peer_name, detail).await?,
        None => {
            let row = NewAudit {
                created_at: now,
                kind: "conn",
                device_guid: Some(guid),
                device_id: id,
                peer_id,
                peer_name,
                conn_id,
                authorized: true,
                detail: detail.to_owned(),
                ..Default::default()
            };
            db.insert_audit(&row).await?;
        }
    }
    Ok(())
}

/// "1,5 MB" and the like.
fn size_text(bytes: i64) -> String {
    let bytes = bytes.max(0) as f64;
    let (value, unit) = if bytes < 1024.0 {
        return format!("{} B", bytes as i64);
    } else if bytes < 1024.0 * 1024.0 {
        (bytes / 1024.0, "KB")
    } else if bytes < 1024.0 * 1024.0 * 1024.0 {
        (bytes / 1024.0 / 1024.0, "MB")
    } else {
        (bytes / 1024.0 / 1024.0 / 1024.0, "GB")
    };
    format!("{:.1} {}", value, unit).replace('.', ",")
}

/// Files went from the device to the controlling side (type 0) or onto the device (type 1).
async fn file_record(pm: &PeerMap, guid: Vec<u8>, id: String, record: &Map<String, Value>) -> ResultType<()> {
    let db = &pm.db;
    let now = unix_now();
    let conn_id = record.get("conn_id").and_then(Value::as_i64).unwrap_or_default();
    let info: Value = serde_json::from_str(&text(record, "info")).unwrap_or_default();
    let files: Vec<(String, i64)> = info
        .get("files")
        .and_then(Value::as_array)
        .map(|files| {
            files
                .iter()
                .filter_map(|file| {
                    let file = file.as_array()?;
                    let name = file.first()?.as_str()?;
                    Some((short(name, 200), file.get(1).and_then(Value::as_i64).unwrap_or_default()))
                })
                .collect()
        })
        .unwrap_or_default();
    let num = info
        .get("num")
        .and_then(Value::as_u64)
        .unwrap_or(files.len() as u64)
        .max(files.len() as u64);
    let direction = match record.get("type").and_then(Value::as_i64) {
        Some(1) => "auf das Gerät kopiert",
        _ => "vom Gerät geholt",
    };
    let mut detail = match num {
        1 => format!("1 Datei {}", direction),
        n => format!("{} Dateien {}", n, direction),
    };
    let path = short(&text(record, "path"), 300);
    if !path.is_empty() {
        detail.push_str(&format!(" (Ordner {})", path));
    }
    let shown: Vec<String> = files
        .iter()
        .take(MAX_FILES_SHOWN)
        .map(|(name, size)| match name.as_str() {
            "" => size_text(*size),
            name => format!("{} ({})", name, size_text(*size)),
        })
        .collect();
    if !shown.is_empty() {
        detail.push_str(": ");
        detail.push_str(&shown.join(", "));
        let more = num.saturating_sub(shown.len() as u64);
        if more > 0 {
            detail.push_str(&format!(" und {} weitere", more));
        }
    }
    let user = match db.open_audit_conn(&guid, conn_id, now.saturating_sub(CONN_MAX_SECS)).await? {
        Some((_, user)) => user,
        None => String::new(),
    };
    let info_text = |key: &str| short(info.get(key).and_then(Value::as_str).unwrap_or_default(), 100);
    let row = NewAudit {
        created_at: now,
        kind: "file",
        device_guid: Some(guid),
        device_id: id,
        user,
        peer_id: short(&text(record, "peer_id"), 100),
        peer_name: info_text("name"),
        ip: short(&info_text("ip"), 64),
        conn_id,
        detail,
        ..Default::default()
    };
    db.insert_audit(&row).await?;
    Ok(())
}

/// The kinds of alarm the client sends (AlarmAuditType in src/server/connection.rs).
pub(crate) fn alarm_label(typ: i64) -> String {
    match typ {
        0 => "Zugriff von einer nicht erlaubten IP-Adresse".to_owned(),
        1 => "Mehr als 30 falsche Passwörter".to_owned(),
        2 => "6 falsche Passwörter in einer Minute".to_owned(),
        6 => "Zu viele falsche Passwörter aus einem IPv6-Netz".to_owned(),
        7 => "Zu viele falsche Anmeldungen im Terminal".to_owned(),
        8 => "Zu viele Terminal-Anmeldungen gleichzeitig".to_owned(),
        9 => "Eine Verbindung wollte mehr, als sie darf".to_owned(),
        10 => "Zugriff von einer nicht erlaubten ID".to_owned(),
        other => format!("Alarm Nr. {}", other),
    }
}

/// An alarm of the device, such as too many wrong passwords.
async fn alarm_record(pm: &PeerMap, guid: Vec<u8>, id: String, record: &Map<String, Value>) -> ResultType<()> {
    let db = &pm.db;
    let now = unix_now();
    let conn_id = record.get("conn_id").and_then(Value::as_i64).unwrap_or_default();
    let typ = record.get("typ").and_then(Value::as_i64).unwrap_or(-1);
    let info: Value = serde_json::from_str(&text(record, "info")).unwrap_or_default();
    let info_text = |key: &str| short(info.get(key).and_then(Value::as_str).unwrap_or_default(), 100);
    let mut detail = alarm_label(typ);
    let message = info_text("message");
    if !message.is_empty() {
        detail.push_str(&format!(" ({})", message));
    }
    let (user, ip) = match ref_of(&text(record, "conn_audit_ref")).await {
        Some(found) => found,
        None => {
            let user = match db.open_audit_conn(&guid, conn_id, now.saturating_sub(CONN_MAX_SECS)).await? {
                Some((_, user)) => user,
                None => String::new(),
            };
            (user, info_text("ip"))
        }
    };
    let row = NewAudit {
        created_at: now,
        kind: "alarm",
        device_guid: Some(guid),
        device_id: id,
        user,
        peer_id: info_text("id"),
        peer_name: info_text("name"),
        ip: short(&ip, 64),
        conn_id,
        detail,
        ..Default::default()
    };
    db.insert_audit(&row).await?;
    let alarm = crate::mail::Alarm {
        device_id: &row.device_id,
        what: &row.detail,
        time: &crate::panel::time_text(now),
        user: &row.user,
        peer_id: &row.peer_id,
        peer_name: &row.peer_name,
        ip: &row.ip,
    };
    crate::mail::send_alarm(&alarm, now);
    Ok(())
}

/// Notes a change by `user` (in the panel or by the API) about device `device_id`, '' if it
/// is not about a device. A failure is only logged; the change itself is done.
pub(crate) async fn log_change(pm: &PeerMap, user: &str, device_id: &str, detail: String) {
    let device_guid = if device_id.is_empty() {
        None
    } else {
        pm.db.device_guid(device_id).await.unwrap_or_else(|err| {
            log::error!("SimpleDesk audit: reading the device {} failed: {}", device_id, err);
            None
        })
    };
    let row = NewAudit {
        created_at: unix_now(),
        kind: "admin",
        device_guid,
        device_id: device_id.to_owned(),
        user: user.to_owned(),
        detail,
        ..Default::default()
    };
    if let Err(err) = pm.db.insert_audit(&row).await {
        log::error!("SimpleDesk audit: saving a change failed: {}", err);
    }
}

/// Deletes the rows older than AUDIT_DAYS.
pub(crate) async fn clean_up(pm: &PeerMap) {
    let before = unix_now().saturating_sub(pm.accounts.audit_days.max(1) as u64 * 24 * 3600);
    match pm.db.delete_old_audit(before).await {
        Ok(0) => {}
        Ok(count) => log::info!("SimpleDesk audit: {} entries older than {} days deleted", count, pm.accounts.audit_days),
        Err(err) => log::error!("SimpleDesk audit: deleting old entries failed: {}", err),
    }
}

/// Cleans up at the start and then every hour.
pub(crate) async fn clean_up_regularly(pm: PeerMap) {
    let mut timer = tokio::time::interval(Duration::from_secs(3600));
    loop {
        timer.tick().await;
        clean_up(&pm).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::AuditFilter;
    use axum::{body::Body, http::Request};
    use tower::ServiceExt;

    async fn test_panel(dir: &tempfile::TempDir) -> Arc<Panel> {
        let mut pm = crate::peer::test_peer_map(dir).await;
        pm.accounts = Arc::new(crate::accounts::Accounts::with_admins("felix"));
        Arc::new(Panel::new(pm, Default::default()).await.unwrap())
    }

    /// Posts a record as the device does; returns status and body.
    async fn post(panel: &Arc<Panel>, path: &str, record: &Value) -> (StatusCode, String) {
        let req = Request::post(path)
            .header("content-type", "application/json")
            .body(Body::from(record.to_string()))
            .unwrap();
        let res = crate::panel::router(panel.clone()).oneshot(req).await.unwrap();
        let status = res.status();
        let bytes = hyper::body::to_bytes(res.into_body()).await.unwrap();
        (status, String::from_utf8(bytes.to_vec()).unwrap())
    }

    /// A record of Rathaus-PC for its connection 7, with its own nonce.
    fn record(fields: Value) -> Value {
        let mut record = json!({
            "id": "Rathaus-PC",
            "uuid": base64::encode(b"uuid-rathaus"),
            "conn_id": 7,
            "nonce": uuid::Uuid::new_v4().to_string(),
        });
        if let (Some(record), Value::Object(fields)) = (record.as_object_mut(), fields) {
            record.extend(fields);
        }
        record
    }

    #[hbb_common::tokio::test]
    async fn device_records_land_in_the_log_with_who_connected() {
        let dir = tempfile::tempdir().unwrap();
        let panel = test_panel(&dir).await;
        let pm = &panel.pm;
        pm.db.insert_peer("Rathaus-PC", b"uuid-rathaus", b"pk", "").await.unwrap();
        pm.db.ensure_external_user("felix").await.unwrap();
        let token = "token-of-felix";
        pm.db.insert_api_token(&crate::api::token_hash(token), "felix", "").await.unwrap();
        let stored = (StatusCode::OK, String::new());

        // felix asks hbbs for a connection; hbbs passes a reference on to the device, which
        // sends it back when the connection comes in.
        let reference = new_conn_ref(pm, token, "203.0.113.9:4000".parse().unwrap()).await;
        assert_eq!(ref_of(&reference).await, Some(("felix".to_owned(), "203.0.113.9".to_owned())));
        let new = record(json!({"action": "new", "ip": "10.0.0.5", "conn_audit_ref": reference}));
        assert_eq!(post(&panel, "/api/audit/conn", &new).await, stored);
        // A retry of a stored record (same nonce) is not stored twice.
        assert_eq!(post(&panel, "/api/audit/conn", &new).await, stored);
        let login = record(json!({"peer": ["Felix-Laptop", "FELIX-NB"], "type": 0, "primary_auth": 2}));
        assert_eq!(post(&panel, "/api/audit/conn", &login).await, stored);
        let info = json!({"ip": "203.0.113.9", "name": "FELIX-NB", "num": 7,
            "files": [["bericht.pdf", 1536], ["notiz.txt", 10]]});
        let files = record(json!({"peer_id": "Felix-Laptop", "type": 0, "path": "C:\\Berichte",
            "is_file": false, "info": info.to_string()}));
        assert_eq!(post(&panel, "/api/audit/file", &files).await, stored);
        let alarm = record(json!({"typ": 2, "info": json!({"ip": "198.51.100.66"}).to_string()}));
        assert_eq!(post(&panel, "/api/audit/alarm", &alarm).await, stored);
        assert_eq!(post(&panel, "/api/audit/conn", &record(json!({"action": "close"}))).await, stored);

        // Records of unknown devices or with another uuid are refused.
        let mut stranger = record(json!({"action": "new"}));
        stranger["uuid"] = json!(base64::encode(b"fremd"));
        assert_eq!(post(&panel, "/api/audit/conn", &stranger).await.0, StatusCode::BAD_REQUEST);
        stranger["id"] = json!("Gibt-Es-Nicht");
        assert_eq!(post(&panel, "/api/audit/alarm", &stranger).await.0, StatusCode::BAD_REQUEST);
        // Anything else is answered quietly, as before.
        assert_eq!(post(&panel, "/api/audit/conn/active", &json!({})).await.0, StatusCode::OK);

        let rows = pm.db.list_audit(&AuditFilter::default(), 100).await.unwrap();
        let kinds: Vec<&str> = rows.iter().map(|row| row.kind.as_str()).collect();
        assert_eq!(kinds, ["alarm", "file", "conn"]);
        let (alarm, files, conn) = (&rows[0], &rows[1], &rows[2]);
        assert_eq!((conn.user.as_str(), conn.ip.as_str()), ("felix", "203.0.113.9"));
        assert_eq!((conn.peer_id.as_str(), conn.peer_name.as_str()), ("Felix-Laptop", "FELIX-NB"));
        assert!(conn.authorized && conn.ended_at.is_some());
        assert_eq!(conn.detail, "Fernsteuerung");
        assert_eq!(files.user, "felix");
        assert_eq!(
            files.detail,
            "7 Dateien vom Gerät geholt (Ordner C:\\Berichte): bericht.pdf (1,5 KB), notiz.txt (10 B) und 5 weitere"
        );
        assert_eq!((alarm.user.as_str(), alarm.ip.as_str()), ("felix", "198.51.100.66"));
        assert_eq!(alarm.detail, "6 falsche Passwörter in einer Minute");
        assert!(rows.iter().all(|row| row.device_id == "Rathaus-PC"));
    }

    #[hbb_common::tokio::test]
    async fn old_entries_go_after_audit_days() {
        let dir = tempfile::tempdir().unwrap();
        let panel = test_panel(&dir).await;
        let pm = &panel.pm;
        let now = unix_now();
        let days = pm.accounts.audit_days as u64;
        for (age_days, detail) in [(days + 1, "alt"), (days - 1, "neu")] {
            let row = NewAudit {
                created_at: now - age_days * 24 * 3600,
                kind: "admin",
                detail: detail.to_owned(),
                ..Default::default()
            };
            pm.db.insert_audit(&row).await.unwrap();
        }
        clean_up(pm).await;
        let rows = pm.db.list_audit(&AuditFilter::default(), 100).await.unwrap();
        assert_eq!(rows.iter().map(|row| row.detail.as_str()).collect::<Vec<_>>(), ["neu"]);
    }

    #[test]
    fn labels_for_sizes_and_alarms() {
        assert_eq!(size_text(512), "512 B");
        assert_eq!(size_text(1536), "1,5 KB");
        assert_eq!(size_text(3 * 1024 * 1024), "3,0 MB");
        assert_eq!(alarm_label(2), "6 falsche Passwörter in einer Minute");
        assert_eq!(alarm_label(42), "Alarm Nr. 42");
        assert_eq!(short("  abcdef ", 3), "abc");
    }

    #[hbb_common::tokio::test]
    async fn nonces_are_stored_once_and_released_on_failure() {
        let nonce = uuid::Uuid::new_v4().to_string();
        assert!(first_time(&nonce).await);
        assert!(!first_time(&nonce).await);
        forget_nonce(&nonce).await;
        assert!(first_time(&nonce).await);
        // Records without a nonce are always stored.
        assert!(first_time("").await && first_time("").await);
    }
}
