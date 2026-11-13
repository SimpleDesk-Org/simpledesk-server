//! SimpleDesk: "Geräte zentral einrichten". An admin creates a deploy token in the panel that
//! is valid for a while and gets a PowerShell command for Windows. The command sets the
//! installed client up for this server and then runs the open client's `--assign`
//! (src/core_main.rs), which posts to /api/devices/cli with the token. The server gives the
//! device its owner, its group and an entry in a shared address book.
//!
//! The token only allows setting up the device the command runs on: the request carries the
//! device's ID and uuid, and both must match the registered device. The settings of a device
//! come from its group (see strategy.rs), so `--strategy_name` is not needed.

use crate::api::{bearer, token_hash, unix_now};
use crate::common::get_arg;
use crate::panel::{admin_of, hex, html, redirect_to, time_text, Choice, Panel, DEFAULT_TAG_COLOR};
use askama::Template;
use axum::{
    body::Bytes,
    extract::{Extension, Form},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use hbb_common::{log, ResultType};
use serde_derive::Deserialize;
use serde_json::{Map, Value};
use sodiumoxide::randombytes::randombytes;
use std::sync::Arc;

/// Where the SimpleDesk installer puts the client.
const CLIENT_EXE: &str = r"$env:ProgramFiles\SimpleDesk\SimpleDesk.exe";
/// How long a new token may be valid, in hours, with the label of the form.
const VALID_HOURS: [(u64, &str); 4] = [(1, "1 Stunde"), (24, "1 Tag"), (168, "7 Tage"), (720, "30 Tage")];
const DEFAULT_HOURS: u64 = 24;
/// What the server answers while the device is not registered yet; the command tries again.
const NOT_REGISTERED: &str =
    "Dieses Gerät ist beim Server noch nicht angemeldet. Warte eine Minute und versuch es noch einmal.";

/// What `--assign` sends; every field but id and uuid only when given on the command line.
#[derive(Deserialize)]
struct CliRequest {
    #[serde(default)]
    id: String,
    #[serde(default)]
    uuid: String,
    user_name: Option<String>,
    strategy_name: Option<String>,
    address_book_name: Option<String>,
    address_book_tag: Option<String>,
    address_book_alias: Option<String>,
    address_book_password: Option<String>,
    address_book_note: Option<String>,
    device_group_name: Option<String>,
    note: Option<String>,
    device_username: Option<String>,
    device_name: Option<String>,
}

/// A given, non-empty value of an option.
fn given(value: &Option<String>) -> Option<&str> {
    value.as_deref().map(str::trim).filter(|value| !value.is_empty())
}

/// The client prints the answer as it is, so it is plain German text.
fn answer(status: StatusCode, text: &str) -> Response {
    let mut res = (status, text.to_owned()).into_response();
    res.headers_mut().insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    res
}

/// `--assign` of the open client: gives the device it runs on an owner, a group and an entry in
/// a shared address book. Owner, group and book must exist; nothing changes if one is missing.
pub(crate) async fn devices_cli(Extension(panel): Extension<Arc<Panel>>, headers: HeaderMap, body: Bytes) -> Response {
    let Some(token) = bearer(&headers) else {
        return answer(StatusCode::UNAUTHORIZED, "Bitte den Token mit --token angeben.");
    };
    let hash = token_hash(token);
    match device_setup(&panel, &hash, &body).await {
        Ok(Ok(text)) => {
            if let Err(err) = panel.pm.db.count_deploy_use(&hash).await {
                log::warn!("SimpleDesk deploy: counting the use of a token failed: {}", err);
            }
            answer(StatusCode::OK, &text)
        }
        Ok(Err((status, text))) => answer(status, &text),
        Err(err) => {
            log::error!("SimpleDesk deploy: setting up a device failed: {}", err);
            answer(StatusCode::BAD_REQUEST, "Fehler auf dem Server. Bitte später noch einmal.")
        }
    }
}

type Refusal = (StatusCode, String);

async fn device_setup(panel: &Panel, hash: &str, body: &[u8]) -> ResultType<Result<String, Refusal>> {
    let pm = &panel.pm;
    let db = &pm.db;
    let refuse = |status: StatusCode, text: &str| Ok(Err((status, text.to_owned())));
    let Some(creator) = db.deploy_token_creator(hash, unix_now()).await? else {
        return refuse(
            StatusCode::UNAUTHORIZED,
            "Der Token ist ungültig oder abgelaufen. Erstell im Panel unter „Einrichten“ einen neuen.",
        );
    };
    let Ok(req) = serde_json::from_slice::<CliRequest>(body) else {
        return refuse(StatusCode::BAD_REQUEST, "Ungültige Anfrage.");
    };
    let id = req.id.trim();
    let uuid = base64::decode(req.uuid.trim()).unwrap_or_default();
    if id.is_empty() || uuid.is_empty() || db.device_uuid(id).await?.as_deref() != Some(&uuid[..]) {
        return refuse(StatusCode::BAD_REQUEST, NOT_REGISTERED);
    }
    // Check everything first, so a typo changes nothing.
    let owner = match given(&req.user_name) {
        Some(name) if !db.user_exists(name).await? => {
            let text = format!(
                "Den Benutzer {} gibt es noch nicht. Er muss sich einmal anmelden, im Panel oder im Client. Oder lass --user_name weg: Das Gerät gehört dann dem, der sich darauf anmeldet.",
                name
            );
            return Ok(Err((StatusCode::BAD_REQUEST, text)));
        }
        Some(name) => Some(name.to_owned()),
        None => None,
    };
    let group = match given(&req.device_group_name) {
        Some(name) => match db.group_name(name).await? {
            Some(group) => Some(group),
            None => {
                let text = format!("Die Gruppe {} gibt es nicht. Leg sie im Panel unter „Benutzer“ an.", name);
                return Ok(Err((StatusCode::BAD_REQUEST, text)));
            }
        },
        None => None,
    };
    let book = match given(&req.address_book_name) {
        Some(name) => match db.shared_ab_by_name(name).await? {
            Some(book) => Some(book),
            None => {
                let text = format!("Das geteilte Adressbuch {} gibt es nicht. Leg es im Panel unter „Adressbuch“ an.", name);
                return Ok(Err((StatusCode::BAD_REQUEST, text)));
            }
        },
        None => None,
    };
    let tag = given(&req.address_book_tag).filter(|_| book.is_some());
    if [given(&req.address_book_tag), given(&req.address_book_alias), given(&req.address_book_note)]
        .iter()
        .any(|value| value.map_or(false, |value| value.chars().count() > 100))
    {
        return refuse(StatusCode::BAD_REQUEST, "Tag, Name und Notiz fürs Adressbuch dürfen höchstens 100 Zeichen haben.");
    }

    // Owner and group; what is not given stays as it is.
    let (old_owner, old_group) = db.device_owner(id).await?.unwrap_or_default();
    let owner = owner.unwrap_or(old_owner);
    let group = group.unwrap_or(old_group);
    db.assign_device(id, &owner, &group).await?;
    let none = |name: &str| if name.is_empty() { "–".to_owned() } else { name.to_owned() };
    let mut lines = vec![format!("Fertig. Gerät {}: Besitzer {}, Gruppe {}.", id, none(&owner), none(&group))];
    let mut detail = format!("Gerät eingerichtet (Token von {}): Besitzer {}, Gruppe {}", creator, none(&owner), none(&group));

    // The entry in the shared address book; fields given on the command line win.
    if let Some(book) = &book {
        let mut peer = match db.get_ab_peer(&book.guid, id).await? {
            Some(data) => match serde_json::from_str(&data) {
                Ok(Value::Object(peer)) => peer,
                _ => Map::new(),
            },
            None => Map::new(),
        };
        peer.insert("id".to_owned(), Value::from(id));
        peer.remove("hash");
        for (key, value) in [
            ("alias", given(&req.address_book_alias)),
            ("note", given(&req.address_book_note)),
            ("password", given(&req.address_book_password)),
        ] {
            if let Some(value) = value {
                peer.insert(key.to_owned(), Value::from(value));
            }
        }
        let mut tags: Vec<Value> = peer.get("tags").and_then(Value::as_array).cloned().unwrap_or_default();
        if let Some(tag) = tag {
            if !tags.iter().any(|known| known.as_str() == Some(tag)) {
                tags.push(Value::from(tag));
            }
            if !db.list_ab_tags(&book.guid).await?.iter().any(|(name, _)| name == tag) {
                db.upsert_ab_tag(&book.guid, tag, DEFAULT_TAG_COLOR).await?;
            }
        }
        peer.insert("tags".to_owned(), Value::from(tags));
        db.upsert_ab_peer(&book.guid, id, &Value::Object(peer).to_string()).await?;
        lines.push(format!("Es steht jetzt im Adressbuch {}.", book.name));
        detail.push_str(&format!(", Adressbuch {}", book.name));
    }
    if pm.accounts.ids_by_admin && db.id_assignment(&uuid).await?.is_none() {
        lines.push("Gib dem Gerät im Panel unter „Geräte“ noch seine ID.".to_owned());
    }
    if given(&req.strategy_name).is_some() {
        lines.push("Hinweis: --strategy_name braucht SimpleDesk nicht. Die Einstellungen kommen über die Gruppe.".to_owned());
    }
    if [&req.note, &req.device_username, &req.device_name].iter().any(|value| given(value).is_some()) {
        lines.push("Hinweis: --note, --device_username und --device_name speichert SimpleDesk nicht.".to_owned());
    }
    log::info!("SimpleDesk deploy: {} set up with a token of {}", id, creator);
    crate::audit::log_change(pm, &creator, id, detail).await;
    Ok(Ok(lines.join("\n")))
}

// The page "Einrichten".

/// A value for PowerShell, in single quotes: nothing in it is expanded.
fn ps_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

/// The address clients use for this server: the host of PANEL_URL, else the host the browser
/// asked for. Without port, as the client takes it.
fn server_host(headers: &HeaderMap) -> String {
    let panel_url = get_arg("PANEL_URL");
    let from_url = panel_url.trim().split_once("://").map(|(_, rest)| rest).unwrap_or_default();
    let host_header = headers.get(header::HOST).and_then(|value| value.to_str().ok()).unwrap_or_default();
    let address = if from_url.is_empty() { host_header } else { from_url };
    let address = address.split('/').next().unwrap_or_default().trim();
    match address.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') && port.chars().all(|c| c.is_ascii_digit()) => host.to_owned(),
        _ => address.to_owned(),
    }
}

/// The PowerShell lines that set the client up for this server and assign the device. The
/// command runs as administrator; while the device is not registered yet it tries again.
fn windows_command(host: &str, key: &str, token: &str, assign: &[(&str, &str)]) -> String {
    let mut lines = vec![
        "# In PowerShell als Administrator ausführen. SimpleDesk muss installiert sein.".to_owned(),
        format!("$sd = \"{}\"", CLIENT_EXE),
        format!("& $sd --option custom-rendezvous-server {} | Out-Null", ps_quote(host)),
        format!("& $sd --option relay-server {} | Out-Null", ps_quote(host)),
        format!("& $sd --option api-server {} | Out-Null", ps_quote(&format!("https://{}", host))),
        format!("& $sd --option key {} | Out-Null", ps_quote(key)),
        "& $sd --option allow-websocket Y | Out-Null".to_owned(),
        "foreach ($try in 1..12) {".to_owned(),
    ];
    let args: Vec<String> = assign
        .iter()
        .map(|(flag, value)| format!("--{} {}", flag, ps_quote(value)))
        .collect();
    lines.push(format!("  $answer = & $sd --assign --token {} {} | Out-String", ps_quote(token), args.join(" ")));
    lines.push("  if ($answer -notmatch 'noch nicht angemeldet') { break }".to_owned());
    lines.push("  Start-Sleep -Seconds 10".to_owned());
    lines.push("}".to_owned());
    lines.push("Write-Output $answer".to_owned());
    lines.join("\n")
}

pub(crate) struct TokenView {
    pub(crate) id: i64,
    pub(crate) created_by: String,
    pub(crate) created: String,
    pub(crate) expires: String,
    pub(crate) expired: bool,
    pub(crate) note: String,
    pub(crate) uses: i64,
}

#[derive(Template)]
#[template(path = "panel/deploy.html")]
struct DeployPage<'a> {
    user: &'a str,
    admin: bool,
    active: &'a str,
    update: &'a str,
    tokens: &'a [TokenView],
    hours: &'a [Choice],
    users: &'a [Choice],
    groups: &'a [Choice],
    books: &'a [Choice],
    tag: &'a str,
    note: &'a str,
    /// Right after creating: the command with the token, shown only this once.
    command: &'a str,
    error: &'a str,
}

#[derive(Deserialize, Default)]
pub(crate) struct DeployForm {
    #[serde(default)]
    hours: u64,
    #[serde(default)]
    note: String,
    #[serde(default)]
    owner: String,
    #[serde(default)]
    group: String,
    #[serde(default)]
    book: String,
    #[serde(default)]
    tag: String,
}

#[derive(Deserialize)]
pub(crate) struct RevokeForm {
    id: i64,
}

/// The options of a select: none or one of `names`.
fn pick(none: &str, names: Vec<String>, current: &str) -> Vec<Choice> {
    let mut list = vec![Choice {
        value: String::new(),
        label: format!("– {} –", none),
        selected: current.is_empty(),
    }];
    list.extend(names.into_iter().map(|name| Choice {
        selected: name.eq_ignore_ascii_case(current),
        label: name.clone(),
        value: name,
    }));
    list
}

async fn render(
    panel: &Panel,
    user: &str,
    form: &DeployForm,
    command: &str,
    status: StatusCode,
    error: &str,
) -> Response {
    let result: ResultType<String> = async {
        let db = &panel.pm.db;
        let now = unix_now();
        let tokens: Vec<TokenView> = db
            .list_deploy_tokens()
            .await?
            .into_iter()
            .map(|row| TokenView {
                id: row.id,
                created_by: row.created_by,
                created: time_text(row.created_at),
                expires: time_text(row.expires_at),
                expired: row.expires_at <= now,
                note: row.note,
                uses: row.uses,
            })
            .collect();
        let hours_now = if form.hours == 0 { DEFAULT_HOURS } else { form.hours };
        let hours: Vec<Choice> = VALID_HOURS
            .iter()
            .map(|(hours, label)| Choice {
                value: hours.to_string(),
                label: label.to_string(),
                selected: *hours == hours_now,
            })
            .collect();
        let users = pick("niemand", db.list_users().await?.into_iter().map(|row| row.name).collect(), &form.owner);
        let groups = pick("keine", db.list_groups().await?, &form.group);
        let books = pick("keins", db.shared_ab_names().await?, &form.book);
        let update = panel.update_notice(user).await;
        let page = DeployPage {
            user,
            admin: true,
            active: "deploy",
            update: &update,
            tokens: &tokens,
            hours: &hours,
            users: &users,
            groups: &groups,
            books: &books,
            tag: form.tag.trim(),
            note: form.note.trim(),
            command,
            error,
        };
        Ok(page.render()?)
    }
    .await;
    match result {
        Ok(page) => html(status, Ok(page)),
        Err(err) => {
            log::error!("SimpleDesk web panel: reading the deploy tokens failed: {}", err);
            (StatusCode::INTERNAL_SERVER_ERROR, "Die Seite konnte nicht gelesen werden.").into_response()
        }
    }
}

pub(crate) async fn deploy_page(Extension(panel): Extension<Arc<Panel>>, headers: HeaderMap) -> Response {
    match admin_of(&panel, &headers).await {
        Ok(admin) => render(&panel, &admin, &DeployForm::default(), "", StatusCode::OK, "").await,
        Err(res) => res,
    }
}

/// A new token with the command for the chosen owner, group and address book.
pub(crate) async fn deploy_new(
    Extension(panel): Extension<Arc<Panel>>,
    headers: HeaderMap,
    Form(form): Form<DeployForm>,
) -> Response {
    let admin = match admin_of(&panel, &headers).await {
        Ok(admin) => admin,
        Err(res) => return res,
    };
    let result: ResultType<Result<String, &str>> = async {
        let db = &panel.pm.db;
        let Some((hours, label)) = VALID_HOURS.iter().find(|(hours, _)| *hours == form.hours) else {
            return Ok(Err("Bitte wähl, wie lange der Token gilt."));
        };
        let (owner, group, book, tag) = (form.owner.trim(), form.group.trim(), form.book.trim(), form.tag.trim());
        if owner.is_empty() && group.is_empty() && book.is_empty() {
            return Ok(Err("Wähl mindestens einen Besitzer, eine Gruppe oder ein Adressbuch."));
        }
        if form.note.trim().chars().count() > 100 || tag.chars().count() > 100 {
            return Ok(Err("Notiz und Tag dürfen höchstens 100 Zeichen haben."));
        }
        if !tag.is_empty() && book.is_empty() {
            return Ok(Err("Ein Tag geht nur mit einem Adressbuch."));
        }
        if !owner.is_empty() && !db.user_exists(owner).await? {
            return Ok(Err("Diesen Benutzer gibt es nicht."));
        }
        // The names as they are saved, not as typed.
        let group = match group {
            "" => String::new(),
            name => match db.group_name(name).await? {
                Some(group) => group,
                None => return Ok(Err("Diese Gruppe gibt es nicht.")),
            },
        };
        let book = match book {
            "" => String::new(),
            name => match db.shared_ab_by_name(name).await? {
                Some(book) => book.name,
                None => return Ok(Err("Dieses Adressbuch gibt es nicht.")),
            },
        };
        let token = hex(&randombytes(32));
        let now = unix_now();
        db.insert_deploy_token(&token_hash(&token), &admin, now, now + hours * 3600, form.note.trim()).await?;
        let mut assign = Vec::new();
        for (flag, value) in [
            ("user_name", owner),
            ("device_group_name", group.as_str()),
            ("address_book_name", book.as_str()),
            ("address_book_tag", tag),
        ] {
            if !value.is_empty() {
                assign.push((flag, value));
            }
        }
        let command = windows_command(&server_host(&headers), &panel.public_key, &token, &assign);
        log::info!("SimpleDesk web panel: {} created a deploy token for {}", admin, label);
        let detail = format!("Token zum Einrichten erstellt (gültig {})", label);
        crate::audit::log_change(&panel.pm, &admin, "", detail).await;
        Ok(Ok(command))
    }
    .await;
    match result {
        Ok(Ok(command)) => render(&panel, &admin, &form, &command, StatusCode::OK, "").await,
        Ok(Err(error)) => render(&panel, &admin, &form, "", StatusCode::BAD_REQUEST, error).await,
        Err(err) => {
            log::error!("SimpleDesk web panel: creating a deploy token failed: {}", err);
            render(&panel, &admin, &form, "", StatusCode::INTERNAL_SERVER_ERROR, "Speichern hat nicht geklappt.").await
        }
    }
}

/// "Löschen": the token stops working at once.
pub(crate) async fn deploy_revoke(
    Extension(panel): Extension<Arc<Panel>>,
    headers: HeaderMap,
    Form(form): Form<RevokeForm>,
) -> Response {
    let admin = match admin_of(&panel, &headers).await {
        Ok(admin) => admin,
        Err(res) => return res,
    };
    match panel.pm.db.delete_deploy_token(form.id).await {
        Ok(()) => {
            crate::audit::log_change(&panel.pm, &admin, "", "Token zum Einrichten gelöscht".to_owned()).await;
            redirect_to("/deploy", None)
        }
        Err(err) => {
            log::error!("SimpleDesk web panel: deleting a deploy token failed: {}", err);
            render(&panel, &admin, &DeployForm::default(), "", StatusCode::INTERNAL_SERVER_ERROR, "Löschen hat nicht geklappt.").await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use hbb_common::tokio;
    use serde_json::json;
    use tower::ServiceExt;

    #[test]
    fn the_command_quotes_its_values_and_names_the_server() {
        assert_eq!(ps_quote("it's"), "'it''s'");
        let command = windows_command("remote.example.org", "KEY=", "abc", &[("user_name", "anna"), ("device_group_name", "Lager $x")]);
        assert!(command.contains("& $sd --option custom-rendezvous-server 'remote.example.org' | Out-Null"), "{command}");
        assert!(command.contains("& $sd --option api-server 'https://remote.example.org' | Out-Null"), "{command}");
        assert!(command.contains("& $sd --option key 'KEY=' | Out-Null"), "{command}");
        assert!(command.contains("--assign --token 'abc' --user_name 'anna' --device_group_name 'Lager $x' | Out-String"), "{command}");
        assert!(!command.to_lowercase().contains("rustdesk"), "{command}");

        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, header::HeaderValue::from_static("remote.example.org:8443"));
        if get_arg("PANEL_URL").is_empty() {
            assert_eq!(server_host(&headers), "remote.example.org");
        }
    }

    async fn send(panel: &Arc<Panel>, req: Request<Body>) -> Response {
        crate::panel::router(panel.clone()).oneshot(req).await.unwrap()
    }

    async fn text(res: Response) -> String {
        let bytes = hyper::body::to_bytes(res.into_body()).await.unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    fn form(path: &str, form: &str, cookie: &str) -> Request<Body> {
        Request::post(path)
            .header(header::COOKIE, cookie)
            .header(header::HOST, "remote.example.org")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(form.to_owned()))
            .unwrap()
    }

    /// What `--assign` of the client sends.
    fn assign(token: &str, body: Value) -> Request<Body> {
        Request::post("/api/devices/cli")
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    /// The token in the command on the page.
    fn token_of(page: &str) -> String {
        let start = page.find("--assign --token &#39;").expect(page) + "--assign --token &#39;".len();
        page[start..start + 64].to_owned()
    }

    #[hbb_common::tokio::test]
    async fn admins_create_tokens_and_devices_set_themselves_up() {
        let dir = tempfile::tempdir().unwrap();
        let mut pm = crate::peer::test_peer_map(&dir).await;
        pm.accounts = Arc::new(crate::accounts::Accounts::with_ids_by_admin("felix"));
        let panel = Arc::new(Panel::new(pm, Default::default()).await.unwrap().with_public_key("S2V5".to_owned()));
        let db = &panel.pm.db;
        for user in ["felix", "anna"] {
            db.ensure_external_user(user).await.unwrap();
        }
        let felix = format!("simpledesk_session={}", panel.start_session("felix").await.unwrap());
        let anna = format!("simpledesk_session={}", panel.start_session("anna").await.unwrap());
        assert!(db.create_group("Lager").await.unwrap());
        let book = db.create_shared_ab("felix", "Rathaus").await.unwrap().unwrap();
        db.insert_peer("123456789", b"uuid-neu", b"pk", "").await.unwrap();
        let device = |extra: Value| {
            let mut body = json!({"id": "123456789", "uuid": base64::encode(b"uuid-neu")});
            for (key, value) in extra.as_object().unwrap() {
                body[key] = value.clone();
            }
            body
        };

        // Only admins see the page and create tokens.
        let page = |cookie: &str| Request::get("/deploy").header(header::COOKIE, cookie).body(Body::empty()).unwrap();
        assert_eq!(send(&panel, page(&anna)).await.status(), StatusCode::FORBIDDEN);
        let res = send(&panel, form("/deploy/new", "hours=24&group=Lager", &anna)).await;
        assert_eq!(res.status(), StatusCode::FORBIDDEN);
        let page_text = text(send(&panel, page(&felix)).await).await;
        assert!(page_text.contains("Geräte zentral einrichten") && page_text.contains("1 Tag"), "{page_text}");
        for bad in ["hours=24", "hours=5&group=Lager", "hours=24&group=Keine", "hours=24&owner=niemand", "hours=24&tag=X&group=Lager"] {
            assert_eq!(send(&panel, form("/deploy/new", bad, &felix)).await.status(), StatusCode::BAD_REQUEST, "{bad}");
        }

        // The command sets the client up for this server and assigns the device.
        let res = send(&panel, form("/deploy/new", "hours=24&note=Umzug&owner=anna&group=Lager&book=rathaus&tag=B%C3%BCro", &felix)).await;
        assert_eq!(res.status(), StatusCode::OK);
        let page_text = text(res).await;
        assert!(page_text.contains("--option custom-rendezvous-server &#39;remote.example.org&#39;"), "{page_text}");
        assert!(page_text.contains("--option key &#39;S2V5&#39;"), "{page_text}");
        assert!(page_text.contains("--user_name &#39;anna&#39; --device_group_name &#39;Lager&#39; --address_book_name &#39;Rathaus&#39; --address_book_tag &#39;Büro&#39;"), "{page_text}");
        assert!(page_text.contains("Umzug"), "{page_text}");
        let token = token_of(&page_text);

        // Without a valid token, or before the device is registered, nothing happens.
        let res = send(&panel, assign("falsch", device(json!({"device_group_name": "Lager"})))).await;
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
        assert!(text(res).await.contains("ungültig oder abgelaufen"));
        let other = json!({"id": "123456789", "uuid": base64::encode(b"fremd"), "device_group_name": "Lager"});
        let res = send(&panel, assign(&token, other)).await;
        assert!(text(res).await.contains("noch nicht angemeldet"));
        // A typo changes nothing.
        let res = send(&panel, assign(&token, device(json!({"device_group_name": "Lager", "user_name": "niemand"})))).await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
        assert!(text(res).await.contains("Den Benutzer niemand gibt es noch nicht"));
        assert_eq!(db.device_owner("123456789").await.unwrap(), Some((String::new(), String::new())));

        // The device gets owner, group and its entry in the book.
        let body = device(json!({
            "user_name": "anna", "device_group_name": "lager", "address_book_name": "Rathaus",
            "address_book_tag": "Büro", "address_book_alias": "Empfang", "strategy_name": "x",
        }));
        let res = send(&panel, assign(&token, body)).await;
        assert_eq!(res.status(), StatusCode::OK);
        let reply = text(res).await;
        assert!(reply.starts_with("Fertig. Gerät 123456789: Besitzer anna, Gruppe Lager."), "{reply}");
        assert!(reply.contains("Adressbuch Rathaus") && reply.contains("noch seine ID") && reply.contains("--strategy_name"), "{reply}");
        assert_eq!(db.device_owner("123456789").await.unwrap(), Some(("anna".to_owned(), "Lager".to_owned())));
        let entry: Value = serde_json::from_str(&db.get_ab_peer(&book, "123456789").await.unwrap().unwrap()).unwrap();
        assert_eq!(entry["alias"], "Empfang");
        assert_eq!(entry["tags"], json!(["Büro"]));
        assert_eq!(db.list_ab_tags(&book).await.unwrap().len(), 1);
        // Only the group again: the owner stays.
        let res = send(&panel, assign(&token, device(json!({"device_group_name": "Lager"})))).await;
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(db.device_owner("123456789").await.unwrap(), Some(("anna".to_owned(), "Lager".to_owned())));

        // The page lists the token with its uses; "Löschen" ends it at once.
        let page_text = text(send(&panel, page(&felix)).await).await;
        assert!(page_text.contains("<td>2</td>") && !page_text.contains(&token), "{page_text}");
        let id = db.list_deploy_tokens().await.unwrap()[0].id;
        let res = send(&panel, form("/deploy/revoke", &format!("id={id}"), &felix)).await;
        assert_eq!(res.headers()[header::LOCATION], "/deploy");
        let res = send(&panel, assign(&token, device(json!({"device_group_name": "Lager"})))).await;
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

        // An expired token does not work either.
        let hash = token_hash("alt");
        db.insert_deploy_token(&hash, "felix", unix_now() - 7200, unix_now() - 3600, "").await.unwrap();
        let res = send(&panel, assign("alt", device(json!({"device_group_name": "Lager"})))).await;
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
        let log = text(send(&panel, Request::get("/log").header(header::COOKIE, &felix).body(Body::empty()).unwrap()).await).await;
        assert!(log.contains("Gerät eingerichtet (Token von felix): Besitzer anna, Gruppe Lager, Adressbuch Rathaus"), "{log}");
    }
}
