//! SimpleDesk: "Zentrale Einstellungen". Admins set options for all devices, for a group or for
//! one device. The device gets them with its heartbeat, as the "strategy" the open client applies
//! (src/hbbs_http/sync.rs: `{"strategy": {"config_options": {...}}, "modified_at": n}`).
//!
//! A device's group overrides "Alle Geräte", the device's own settings override its group. Only
//! options that make sense in the slim SimpleDesk client are offered. When something changes,
//! the device gets every offered option, '' for those without a setting, so a setting an admin
//! removes goes back to the standard on the device. `modified_at` is a hash of what the device
//! should have; the client sends back the one it applied, so it gets the options only once.
//! Without any setting the answer stays as before (no strategy).

use crate::panel::{admin_of, html, redirect_to, Choice, Panel};
use crate::peer::PeerMap;
use askama::Template;
use axum::{
    extract::{Extension, Form, Query},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use hbb_common::{log, ResultType};
use serde_derive::Deserialize;
use serde_json::{Map, Value};
use sodiumoxide::crypto::hash::sha256;
use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
};

/// An option admins can set, with the values they can choose.
pub(crate) struct Setting {
    pub(crate) key: &'static str,
    pub(crate) label: &'static str,
    /// What the device does without a setting.
    pub(crate) standard: &'static str,
    pub(crate) choices: &'static [(&'static str, &'static str)],
    /// The current SimpleDesk client keeps this option fixed, a client update has to allow it.
    pub(crate) needs_new_client: bool,
}

pub(crate) struct Section {
    pub(crate) title: &'static str,
    pub(crate) hint: &'static str,
    pub(crate) settings: &'static [Setting],
}

const ALLOWED: &[(&str, &str)] = &[("Y", "erlaubt"), ("N", "verboten")];
const YES_NO: &[(&str, &str)] = &[("Y", "ja"), ("N", "nein")];

const fn permission(key: &'static str, label: &'static str) -> Setting {
    Setting {
        key,
        label,
        standard: "erlaubt",
        choices: ALLOWED,
        needs_new_client: false,
    }
}

const fn yes_no(key: &'static str, label: &'static str) -> Setting {
    Setting {
        key,
        label,
        standard: "nein",
        choices: YES_NO,
        needs_new_client: false,
    }
}

pub(crate) const SECTIONS: &[Section] = &[
    Section {
        title: "Zugriff",
        hint: "Was jemand darf, der sich mit dem Gerät verbindet.",
        settings: &[Setting {
            key: "access-mode",
            label: "Zugriff auf das Gerät",
            standard: "alles erlaubt",
            choices: &[
                ("full", "voll, alles erlaubt"),
                ("view", "nur ansehen"),
                ("custom", "einzeln (die Rechte unten)"),
            ],
            needs_new_client: false,
        }],
    },
    Section {
        title: "Rechte",
        hint: "Gelten nur, wenn der Zugriff „einzeln“ ist.",
        settings: &[
            permission("enable-keyboard", "Maus und Tastatur"),
            permission("enable-clipboard", "Zwischenablage"),
            permission("enable-file-transfer", "Dateien übertragen"),
            permission("enable-audio", "Ton übertragen"),
            permission("enable-terminal", "Terminal"),
            permission("enable-remote-restart", "Gerät neu starten"),
            permission("enable-record-session", "Sitzung aufnehmen (auf dem Gerät, das steuert)"),
            permission("enable-block-input", "Eingaben am Gerät sperren"),
        ],
    },
    Section {
        title: "Annehmen und Passwörter",
        hint: "",
        settings: &[
            Setting {
                key: "approve-mode",
                label: "Verbindungen annehmen",
                standard: "mit Passwort oder per Klick",
                choices: &[
                    ("password-click", "mit Passwort oder per Klick"),
                    ("password", "nur mit Passwort"),
                    ("click", "nur per Klick am Gerät"),
                ],
                needs_new_client: true,
            },
            Setting {
                key: "verification-method",
                label: "Welche Passwörter gelten",
                standard: "Einmal-Passwort und permanentes Passwort",
                choices: &[
                    ("use-both-passwords", "Einmal-Passwort und permanentes Passwort"),
                    ("use-temporary-password", "nur das Einmal-Passwort"),
                    ("use-permanent-password", "nur das permanente Passwort"),
                ],
                needs_new_client: true,
            },
            Setting {
                key: "temporary-password-length",
                label: "Länge des Einmal-Passworts",
                standard: "6 Zeichen",
                choices: &[("6", "6 Zeichen"), ("8", "8 Zeichen"), ("10", "10 Zeichen")],
                needs_new_client: false,
            },
            yes_no("allow-numeric-one-time-password", "Einmal-Passwort nur aus Ziffern"),
        ],
    },
    Section {
        title: "Aufnahme und Sonstiges",
        hint: "",
        settings: &[
            yes_no("allow-auto-record-incoming", "Eingehende Sitzungen auf dem Gerät aufnehmen"),
            yes_no("allow-only-conn-window-open", "Verbinden nur, wenn SimpleDesk auf dem Gerät offen ist"),
        ],
    },
];

pub(crate) fn settings() -> impl Iterator<Item = &'static Setting> {
    SECTIONS.iter().flat_map(|section| section.settings.iter())
}

fn setting(key: &str) -> Option<&'static Setting> {
    settings().find(|setting| setting.key == key)
}

fn choice_label(setting: &Setting, value: &str) -> &'static str {
    setting
        .choices
        .iter()
        .find(|(choice, _)| *choice == value)
        .map(|(_, label)| *label)
        .unwrap_or(setting.standard)
}

/// The settings of one level, with the name the page shows for it.
struct Layer {
    source: String,
    options: HashMap<String, String>,
}

/// What applies after the levels, later ones win: key -> (value, where it comes from). Only
/// offered options with a value they can have.
fn effective(layers: &[Layer]) -> BTreeMap<&'static str, (String, String)> {
    let mut result = BTreeMap::new();
    for layer in layers {
        for (key, value) in &layer.options {
            if let Some(setting) = setting(key) {
                if setting.choices.iter().any(|(choice, _)| choice == value) {
                    result.insert(setting.key, (value.clone(), layer.source.clone()));
                }
            }
        }
    }
    result
}

/// The config_options of the heartbeat answer for what applies to a device, and its
/// modified_at. With something set, every offered option is in it, '' for those without a
/// setting. Without anything set: no options and 0.
fn config_options(applies: &BTreeMap<&'static str, String>) -> (Map<String, Value>, i64) {
    if applies.is_empty() {
        return (settings().map(|setting| (setting.key.to_owned(), Value::from(""))).collect(), 0);
    }
    let mut text = String::new();
    for (key, value) in applies {
        text.push_str(key);
        text.push('=');
        text.push_str(value);
        text.push('\n');
    }
    let hash = sha256::hash(text.as_bytes()).0;
    let mut bytes = [0u8; 8];
    bytes[2..].copy_from_slice(&hash[..6]);
    let modified_at = (u64::from_be_bytes(bytes) as i64).max(1);
    let options = settings()
        .map(|setting| {
            let value = applies.get(setting.key).cloned().unwrap_or_default();
            (setting.key.to_owned(), Value::from(value))
        })
        .collect();
    (options, modified_at)
}

/// For the heartbeat of the device with this ID and uuid, which applied `modified_at` last:
/// the strategy and the new modified_at if it has to change something, else None.
pub(crate) async fn for_heartbeat(pm: &PeerMap, id: &str, uuid: &[u8], modified_at: i64) -> Option<(Value, i64)> {
    let rows = match pm.db.device_strategy(id, uuid).await {
        Ok(Some((_, rows))) => rows,
        Ok(None) => return None,
        Err(err) => {
            log::error!("SimpleDesk: reading the settings of {} failed: {}", id, err);
            return None;
        }
    };
    let mut layers: Vec<Layer> = ["all", "group", "device"]
        .iter()
        .map(|scope| Layer {
            source: scope.to_string(),
            options: HashMap::new(),
        })
        .collect();
    for (scope, key, value) in rows {
        if let Some(layer) = layers.iter_mut().find(|layer| layer.source == scope) {
            layer.options.insert(key, value);
        }
    }
    let applies = effective(&layers)
        .into_iter()
        .map(|(key, (value, _))| (key, value))
        .collect();
    let (options, new_modified_at) = config_options(&applies);
    if new_modified_at == modified_at {
        return None;
    }
    let mut strategy = Map::new();
    strategy.insert("config_options".to_owned(), Value::Object(options));
    Some((Value::Object(strategy), new_modified_at))
}

// The page "Einstellungen".

/// Characters that may stay as they are in a query value.
fn query_value(text: &str) -> String {
    text.bytes()
        .map(|byte| match byte {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => (byte as char).to_string(),
            _ => format!("%{:02X}", byte),
        })
        .collect()
}

pub(crate) struct ScopeLink {
    pub(crate) href: String,
    pub(crate) name: String,
    pub(crate) current: bool,
}

pub(crate) struct RowView {
    pub(crate) key: &'static str,
    pub(crate) label: &'static str,
    pub(crate) needs_new_client: bool,
    pub(crate) options: Vec<Choice>,
}

pub(crate) struct SectionView {
    pub(crate) title: &'static str,
    pub(crate) hint: &'static str,
    pub(crate) rows: Vec<RowView>,
}

#[derive(Template)]
#[template(path = "panel/settings.html")]
struct SettingsPage<'a> {
    user: &'a str,
    admin: bool,
    active: &'a str,
    update: &'a str,
    groups: &'a [ScopeLink],
    devices: &'a [ScopeLink],
    /// For "Gerät wählen": all devices.
    all_devices: &'a [Choice],
    title: &'a str,
    intro: &'a str,
    scope: &'a str,
    target: &'a str,
    all_href: &'a str,
    all_current: bool,
    sections: &'a [SectionView],
    saved: bool,
    error: &'a str,
}

#[derive(Deserialize)]
pub(crate) struct SettingsQuery {
    #[serde(default)]
    group: String,
    #[serde(default)]
    device: String,
    #[serde(default)]
    saved: String,
}

/// Which settings a page or form is about.
enum Scope {
    All,
    Group(String),
    /// The device ID and its uuid in hex.
    Device(String, String),
}

impl Scope {
    fn kind(&self) -> &'static str {
        match self {
            Scope::All => "all",
            Scope::Group(_) => "group",
            Scope::Device(..) => "device",
        }
    }

    fn target(&self) -> &str {
        match self {
            Scope::All => "",
            Scope::Group(group) => group,
            Scope::Device(_, uuid) => uuid,
        }
    }

    fn name(&self) -> String {
        match self {
            Scope::All => "Alle Geräte".to_owned(),
            Scope::Group(group) => format!("Gruppe {}", group),
            Scope::Device(id, _) => format!("Gerät {}", id),
        }
    }

    fn href(&self) -> String {
        match self {
            Scope::All => "/settings".to_owned(),
            Scope::Group(group) => format!("/settings?group={}", query_value(group)),
            Scope::Device(id, _) => format!("/settings?device={}", query_value(id)),
        }
    }
}

/// The scope of a page or form: a group or device that exists, else all devices. Err with a
/// message if the group or device does not exist.
async fn scope_of(panel: &Panel, group: &str, device: &str) -> ResultType<Result<Scope, &'static str>> {
    let (group, device) = (group.trim(), device.trim());
    if !device.is_empty() {
        return Ok(match panel.pm.db.device_uuid(device).await? {
            Some(uuid) => Ok(Scope::Device(device.to_owned(), crate::panel::hex(&uuid))),
            None => Err("Dieses Gerät gibt es nicht."),
        });
    }
    if !group.is_empty() {
        return Ok(match panel.pm.db.group_name(group).await? {
            Some(group) => Ok(Scope::Group(group)),
            None => Err("Diese Gruppe gibt es nicht."),
        });
    }
    Ok(Ok(Scope::All))
}

async fn layer(panel: &Panel, scope: &Scope) -> ResultType<Layer> {
    Ok(Layer {
        source: scope.name(),
        options: panel.pm.db.strategy_options(scope.kind(), scope.target()).await?.into_iter().collect(),
    })
}

/// The levels above `scope`, whose settings it takes over where it has none.
async fn levels_above(panel: &Panel, scope: &Scope) -> ResultType<Vec<Layer>> {
    let mut layers = Vec::new();
    if matches!(scope, Scope::All) {
        return Ok(layers);
    }
    layers.push(layer(panel, &Scope::All).await?);
    if let Scope::Device(id, _) = scope {
        let group = panel.pm.db.device_owner(id).await?.map(|(_, group)| group).unwrap_or_default();
        if !group.is_empty() {
            layers.push(layer(panel, &Scope::Group(group)).await?);
        }
    }
    Ok(layers)
}

async fn render(panel: &Panel, user: &str, scope: &Scope, status: StatusCode, saved: bool, error: &str) -> Response {
    let result: ResultType<String> = async {
        let db = &panel.pm.db;
        let current = scope.href();
        let groups: Vec<ScopeLink> = db
            .list_groups()
            .await?
            .into_iter()
            .map(|group| {
                let scope = Scope::Group(group.clone());
                ScopeLink { current: scope.href() == current, href: scope.href(), name: group }
            })
            .collect();
        let mut device_ids = db.devices_with_settings().await?;
        if let Scope::Device(id, _) = scope {
            if !device_ids.contains(id) {
                device_ids.push(id.clone());
            }
        }
        let devices: Vec<ScopeLink> = device_ids
            .into_iter()
            .map(|id| {
                let href = format!("/settings?device={}", query_value(&id));
                ScopeLink { current: href == current, href, name: id }
            })
            .collect();
        let all_devices: Vec<Choice> = db
            .list_devices()
            .await?
            .into_iter()
            .map(|row| Choice {
                selected: matches!(scope, Scope::Device(id, _) if *id == row.id),
                label: row.id.clone(),
                value: row.id,
            })
            .collect();
        let own = layer(panel, scope).await?;
        let above = effective(&levels_above(panel, scope).await?);
        let sections: Vec<SectionView> = SECTIONS
            .iter()
            .map(|section| SectionView {
                title: section.title,
                hint: section.hint,
                rows: section
                    .settings
                    .iter()
                    .map(|setting| {
                        let mine = own.options.get(setting.key).map(String::as_str).unwrap_or_default();
                        let inherited = match above.get(setting.key) {
                            Some((value, source)) => format!("wie {}: {}", source, choice_label(setting, value)),
                            None => format!("Standard: {}", setting.standard),
                        };
                        let mut options = vec![Choice {
                            value: String::new(),
                            label: inherited,
                            selected: mine.is_empty(),
                        }];
                        options.extend(setting.choices.iter().map(|(value, label)| Choice {
                            value: value.to_string(),
                            label: label.to_string(),
                            selected: mine == *value,
                        }));
                        RowView {
                            key: setting.key,
                            label: setting.label,
                            needs_new_client: setting.needs_new_client,
                            options,
                        }
                    })
                    .collect(),
            })
            .collect();
        let intro = match scope {
            Scope::All => "Gilt für jedes Gerät, solange seine Gruppe oder das Gerät selbst nichts anderes sagt.".to_owned(),
            Scope::Group(_) => "Gilt für die Geräte dieser Gruppe und geht vor „Alle Geräte“.".to_owned(),
            Scope::Device(id, _) => {
                let group = db.device_owner(id).await?.map(|(_, group)| group).unwrap_or_default();
                if group.is_empty() {
                    "Gilt nur für dieses Gerät und geht vor „Alle Geräte“. Das Gerät ist in keiner Gruppe.".to_owned()
                } else {
                    format!("Gilt nur für dieses Gerät und geht vor seiner Gruppe {} und „Alle Geräte“.", group)
                }
            }
        };
        let update = panel.update_notice(user).await;
        let title = scope.name();
        let target = match scope {
            Scope::Device(id, _) => id.as_str(),
            other => other.target(),
        };
        let page = SettingsPage {
            user,
            admin: true,
            active: "settings",
            update: &update,
            groups: &groups,
            devices: &devices,
            all_devices: &all_devices,
            title: &title,
            intro: &intro,
            scope: scope.kind(),
            target,
            all_href: "/settings",
            all_current: matches!(scope, Scope::All),
            sections: &sections,
            saved,
            error,
        };
        Ok(page.render()?)
    }
    .await;
    match result {
        Ok(page) => html(status, Ok(page)),
        Err(err) => {
            log::error!("SimpleDesk web panel: reading the settings failed: {}", err);
            (StatusCode::INTERNAL_SERVER_ERROR, "Die Einstellungen konnten nicht gelesen werden.").into_response()
        }
    }
}

pub(crate) async fn settings_page(
    Extension(panel): Extension<Arc<Panel>>,
    headers: HeaderMap,
    Query(query): Query<SettingsQuery>,
) -> Response {
    let admin = match admin_of(&panel, &headers).await {
        Ok(admin) => admin,
        Err(res) => return res,
    };
    match scope_of(&panel, &query.group, &query.device).await {
        Ok(Ok(scope)) => render(&panel, &admin, &scope, StatusCode::OK, !query.saved.is_empty(), "").await,
        Ok(Err(error)) => render(&panel, &admin, &Scope::All, StatusCode::NOT_FOUND, false, error).await,
        Err(err) => {
            log::error!("SimpleDesk web panel: reading the settings failed: {}", err);
            (StatusCode::INTERNAL_SERVER_ERROR, "Die Einstellungen konnten nicht gelesen werden.").into_response()
        }
    }
}

/// Saves the settings of one scope. The form has `scope` (all, group or device), `target`
/// (the group or the device ID) and a field for every offered option, '' for none.
pub(crate) async fn settings_save(
    Extension(panel): Extension<Arc<Panel>>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let admin = match admin_of(&panel, &headers).await {
        Ok(admin) => admin,
        Err(res) => return res,
    };
    let field = |name: &str| form.get(name).map(String::as_str).unwrap_or_default();
    let (group, device) = match field("scope") {
        "group" => (field("target"), ""),
        "device" => ("", field("target")),
        _ => ("", ""),
    };
    let scope = match scope_of(&panel, group, device).await {
        Ok(Ok(scope)) => scope,
        Ok(Err(error)) => return render(&panel, &admin, &Scope::All, StatusCode::BAD_REQUEST, false, error).await,
        Err(err) => {
            log::error!("SimpleDesk web panel: reading the settings failed: {}", err);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Speichern hat nicht geklappt.").into_response();
        }
    };
    let mut options = Vec::new();
    let mut summary = Vec::new();
    for setting in settings() {
        let value = field(setting.key).trim();
        if value.is_empty() {
            continue;
        }
        if !setting.choices.iter().any(|(choice, _)| *choice == value) {
            return render(&panel, &admin, &scope, StatusCode::BAD_REQUEST, false, "Bitte nur die Werte aus der Liste wählen.").await;
        }
        options.push((setting.key.to_owned(), value.to_owned()));
        summary.push(format!("{}: {}", setting.label, choice_label(setting, value)));
    }
    if let Err(err) = panel.pm.db.set_strategy_options(scope.kind(), scope.target(), &options).await {
        log::error!("SimpleDesk web panel: saving the settings failed: {}", err);
        return render(&panel, &admin, &scope, StatusCode::INTERNAL_SERVER_ERROR, false, "Speichern hat nicht geklappt.").await;
    }
    log::info!("SimpleDesk web panel: {} saved the settings of {}", admin, scope.name());
    let summary = if summary.is_empty() { "alles wie darüber".to_owned() } else { summary.join("; ") };
    let device_id = match &scope {
        Scope::Device(id, _) => id.as_str(),
        _ => "",
    };
    let detail = format!("Einstellungen für {}: {}", scope.name(), summary);
    crate::audit::log_change(&panel.pm, &admin, device_id, detail).await;
    let href = scope.href();
    let sep = if href.contains('?') { '&' } else { '?' };
    redirect_to(&format!("{}{}saved=1", href, sep), None)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn layer(source: &str, options: &[(&str, &str)]) -> Layer {
        Layer {
            source: source.to_owned(),
            options: options.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
        }
    }

    #[test]
    fn the_device_wins_over_its_group_and_the_group_over_all() {
        let applies = effective(&[
            layer("all", &[("access-mode", "view"), ("allow-auto-record-incoming", "Y")]),
            layer("group", &[("access-mode", "full"), ("enable-clipboard", "N")]),
            layer("device", &[("enable-clipboard", "Y"), ("unknown-option", "Y"), ("temporary-password-length", "7")]),
        ]);
        let values: Vec<(&str, &str, &str)> = applies.iter().map(|(k, (v, s))| (*k, v.as_str(), s.as_str())).collect();
        assert_eq!(
            values,
            vec![
                ("access-mode", "full", "group"),
                ("allow-auto-record-incoming", "Y", "all"),
                ("enable-clipboard", "Y", "device"),
            ]
        );
    }

    #[test]
    fn options_carry_every_offered_key_and_a_stable_hash() {
        let mut applies = BTreeMap::new();
        let (options, modified_at) = config_options(&applies);
        assert_eq!(modified_at, 0);
        assert_eq!(options.len(), settings().count());
        assert!(options.values().all(|value| value == ""));

        applies.insert("access-mode", "view".to_owned());
        let (options, first) = config_options(&applies);
        assert!(first > 0 && first < 1 << 48);
        assert_eq!(options["access-mode"], "view");
        assert_eq!(options["enable-keyboard"], "");
        assert_eq!(config_options(&applies).1, first);
        applies.insert("access-mode", "full".to_owned());
        assert_ne!(config_options(&applies).1, first);
        // The client must not reject any of them.
        for blocked in ["custom-rendezvous-server", "relay-server", "api-server", "key", "allow-websocket", "2fa"] {
            assert!(!options.contains_key(blocked));
        }
    }

    #[test]
    fn every_choice_has_a_label_and_keys_are_unique() {
        let keys: Vec<&str> = settings().map(|setting| setting.key).collect();
        let mut unique = keys.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(keys.len(), unique.len());
        for setting in settings() {
            assert!(!setting.choices.is_empty() && !setting.standard.is_empty(), "{}", setting.key);
            assert!(setting.choices.iter().all(|(value, label)| !value.is_empty() && !label.is_empty()));
        }
        assert_eq!(query_value("Lager Süd&x"), "Lager%20S%C3%BCd%26x");
    }

    use axum::{body::Body, http::{header, Request}};
    use hbb_common::tokio;
    use serde_json::json;
    use tower::ServiceExt;

    async fn send(panel: &Arc<Panel>, req: Request<Body>) -> Response {
        crate::panel::router(panel.clone()).oneshot(req).await.unwrap()
    }

    async fn text(res: Response) -> String {
        let bytes = hyper::body::to_bytes(res.into_body()).await.unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    async fn signed_in(panel: &Arc<Panel>, user: &str) -> String {
        panel.pm.db.ensure_external_user(user).await.unwrap();
        format!("simpledesk_session={}", panel.start_session(user).await.unwrap())
    }

    fn page(path: &str, cookie: &str) -> Request<Body> {
        Request::get(path).header(header::COOKIE, cookie).body(Body::empty()).unwrap()
    }

    fn save(form: &str, cookie: &str) -> Request<Body> {
        Request::post("/settings/save")
            .header(header::COOKIE, cookie)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(form.to_owned()))
            .unwrap()
    }

    /// The heartbeat of a device that applied `modified_at` last.
    async fn heartbeat(panel: &Arc<Panel>, id: &str, uuid: &[u8], modified_at: i64) -> Value {
        let body = json!({"id": id, "uuid": base64::encode(uuid), "ver": 1001017, "modified_at": modified_at});
        let req = Request::post("/api/heartbeat")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        serde_json::from_str(&text(send(panel, req).await).await).unwrap()
    }

    fn location(res: &Response) -> &str {
        res.headers()[header::LOCATION].to_str().unwrap()
    }

    #[hbb_common::tokio::test]
    async fn admins_set_options_and_devices_get_them_with_the_heartbeat() {
        let dir = tempfile::tempdir().unwrap();
        let mut pm = crate::peer::test_peer_map(&dir).await;
        pm.accounts = Arc::new(crate::accounts::Accounts::with_admins("felix"));
        let panel = Arc::new(Panel::new(pm, Default::default()).await.unwrap());
        let db = &panel.pm.db;
        db.insert_peer("Lager-PC", b"uuid-lager", b"pk", "").await.unwrap();
        db.insert_peer("Kasse-PC", b"uuid-kasse", b"pk", "").await.unwrap();
        assert!(db.create_group("Lager").await.unwrap());
        assert!(db.assign_device("Lager-PC", "", "Lager").await.unwrap());
        let felix = signed_in(&panel, "felix").await;
        let anna = signed_in(&panel, "anna").await;

        // Nothing set: the heartbeat answer stays as before.
        let res = heartbeat(&panel, "Lager-PC", b"uuid-lager", 0).await;
        assert_eq!(res, json!({"simpledesk": {"id_assigned": true, "assigned_id": ""}}));

        // Only admins see and change the settings.
        assert_eq!(send(&panel, page("/settings", &anna)).await.status(), StatusCode::FORBIDDEN);
        let res = send(&panel, save("scope=all&target=&access-mode=view", &anna)).await;
        assert_eq!(res.status(), StatusCode::FORBIDDEN);
        let page_text = text(send(&panel, page("/settings", &felix)).await).await;
        assert!(page_text.contains("Zentrale Einstellungen") && page_text.contains("Gruppe Lager"), "{page_text}");
        assert!(page_text.contains("Standard: erlaubt") && page_text.contains("braucht neuen Client"), "{page_text}");

        // All devices: only view. Group Lager: full, but no clipboard. Kasse-PC: recording.
        let res = send(&panel, save("scope=all&target=&access-mode=view", &felix)).await;
        assert_eq!(location(&res), "/settings?saved=1");
        let res = send(&panel, save("scope=group&target=lager&access-mode=full&enable-clipboard=N", &felix)).await;
        assert_eq!(location(&res), "/settings?group=Lager&saved=1");
        let res = send(&panel, save("scope=device&target=Kasse-PC&allow-auto-record-incoming=Y", &felix)).await;
        assert_eq!(location(&res), "/settings?device=Kasse-PC&saved=1");
        for form in ["scope=all&target=&access-mode=alles", "scope=group&target=Keine&access-mode=view", "scope=device&target=Nicht-Da"] {
            assert_eq!(send(&panel, save(form, &felix)).await.status(), StatusCode::BAD_REQUEST, "{form}");
        }

        // Each device gets what applies to it, once.
        let res = heartbeat(&panel, "Lager-PC", b"uuid-lager", 0).await;
        let options = &res["strategy"]["config_options"];
        assert_eq!(options["access-mode"], "full");
        assert_eq!(options["enable-clipboard"], "N");
        assert_eq!(options["allow-auto-record-incoming"], "");
        assert_eq!(res["simpledesk"]["id_assigned"], true);
        let lager = res["modified_at"].as_i64().unwrap();
        assert!(lager > 0);
        let again = heartbeat(&panel, "Lager-PC", b"uuid-lager", lager).await;
        assert!(again.get("strategy").is_none() && again.get("modified_at").is_none(), "{again}");
        let res = heartbeat(&panel, "Kasse-PC", b"uuid-kasse", 0).await;
        assert_eq!(res["strategy"]["config_options"]["access-mode"], "view");
        assert_eq!(res["strategy"]["config_options"]["allow-auto-record-incoming"], "Y");
        // Not for a device with another uuid.
        assert!(heartbeat(&panel, "Kasse-PC", b"fremd", 0).await.get("strategy").is_none());

        // The pages show what comes from above.
        let page_text = text(send(&panel, page("/settings?device=Lager-PC", &felix)).await).await;
        assert!(page_text.contains("wie Gruppe Lager: voll, alles erlaubt"), "{page_text}");
        assert!(page_text.contains("geht vor seiner Gruppe Lager"), "{page_text}");
        let page_text = text(send(&panel, page("/settings?group=Lager&saved=1", &felix)).await).await;
        assert!(page_text.contains("<option value=\"full\" selected>"), "{page_text}");
        assert!(page_text.contains("wie Alle Geräte: nur ansehen") && page_text.contains("Gespeichert."), "{page_text}");
        let page_text = text(send(&panel, page("/settings", &felix)).await).await;
        assert!(page_text.contains("href=\"/settings?device=Kasse-PC\""), "{page_text}");
        assert_eq!(send(&panel, page("/settings?device=Nicht-Da", &felix)).await.status(), StatusCode::NOT_FOUND);

        // Removing the group's settings: the device goes back to "Alle Geräte".
        send(&panel, save("scope=group&target=Lager", &felix)).await;
        let res = heartbeat(&panel, "Lager-PC", b"uuid-lager", lager).await;
        assert_eq!(res["strategy"]["config_options"]["access-mode"], "view");
        assert_eq!(res["strategy"]["config_options"]["enable-clipboard"], "");
        let view = res["modified_at"].as_i64().unwrap();
        assert_ne!(view, lager);
        // Removing everything: every option goes back to the standard, then nothing more.
        send(&panel, save("scope=all&target=", &felix)).await;
        let res = heartbeat(&panel, "Lager-PC", b"uuid-lager", view).await;
        assert_eq!(res["modified_at"], 0);
        assert_eq!(res["strategy"]["config_options"]["access-mode"], "");
        assert!(heartbeat(&panel, "Lager-PC", b"uuid-lager", 0).await.get("strategy").is_none());

        // A deleted group takes its settings along; the log knows who changed what.
        send(&panel, save("scope=group&target=Lager&enable-audio=N", &felix)).await;
        db.delete_group("Lager").await.unwrap();
        assert!(db.strategy_options("group", "Lager").await.unwrap().is_empty());
        let log = text(send(&panel, page("/log", &felix)).await).await;
        assert!(log.contains("Einstellungen für Gruppe Lager: Zugriff auf das Gerät: voll, alles erlaubt; Zwischenablage: verboten"), "{log}");
    }
}
