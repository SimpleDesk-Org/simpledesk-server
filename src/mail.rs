//! SimpleDesk: short German mails to the admins on alarms of a device, and when a new device
//! waits for an ID (IDS_BY_ADMIN).
//!
//! SMTP_HOST: the mail server; without it no mails are sent.
//! SMTP_PORT: 587 by default (STARTTLS); 465 is TLS from the start. The connection is always
//! encrypted, the server needs a certificate a browser would trust.
//! SMTP_USER, SMTP_PASSWORD: the login at the mail server, empty for none. The password is
//! never logged.
//! SMTP_FROM: the sender, such as "SimpleDesk <simpledesk@amt-eider.de>" (default SMTP_USER).
//! ALARM_MAIL_TO: who gets the mails, separated by commas.

use crate::common::get_arg;
use hbb_common::{log, tokio};
use lettre::{
    message::{header::ContentType, Mailbox},
    transport::smtp::authentication::Credentials,
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
};
use once_cell::sync::Lazy;
use std::{collections::HashSet, sync::Mutex, time::Duration};

const DEFAULT_SMTP_PORT: u16 = 587;
const SMTP_TIMEOUT: Duration = Duration::from_secs(30);
/// Mails of one kind for one device at most this often, so a device under attack does not
/// flood the inbox. The log keeps every alarm.
const SAME_MAIL_SECS: u64 = 10 * 60;

/// The settings of the mails, from the environment.
#[derive(Clone, PartialEq)]
pub(crate) struct MailConfig {
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) user: String,
    pub(crate) password: String,
    pub(crate) from: Mailbox,
    pub(crate) to: Vec<Mailbox>,
}

/// Without the password, so it cannot end up in a log.
impl std::fmt::Debug for MailConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MailConfig")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("user", &self.user)
            .field("password", &"***")
            .field("from", &self.from)
            .field("to", &self.to)
            .finish()
    }
}

impl MailConfig {
    /// None without SMTP_HOST, or if the settings are not usable (that is logged).
    pub(crate) fn from_vars(get: impl Fn(&str) -> String) -> Option<Self> {
        let host = get("SMTP_HOST").trim().to_owned();
        if host.is_empty() {
            return None;
        }
        let port = match get("SMTP_PORT").trim() {
            "" => DEFAULT_SMTP_PORT,
            port => match port.parse::<u16>() {
                Ok(port) if port > 0 => port,
                _ => {
                    log::error!("SMTP_PORT={} is not a port, so no mails are sent", port);
                    return None;
                }
            },
        };
        let user = get("SMTP_USER").trim().to_owned();
        let from = match get("SMTP_FROM").trim() {
            "" => user.clone(),
            from => from.to_owned(),
        };
        let Ok(from) = from.parse::<Mailbox>() else {
            log::error!("SMTP_FROM is not a mail address, so no mails are sent");
            return None;
        };
        let mut to = Vec::new();
        for address in get("ALARM_MAIL_TO").split(',').map(str::trim).filter(|a| !a.is_empty()) {
            match address.parse::<Mailbox>() {
                Ok(mailbox) => to.push(mailbox),
                Err(_) => log::error!("ALARM_MAIL_TO: {} is not a mail address, it is left out", address),
            }
        }
        if to.is_empty() {
            log::error!("ALARM_MAIL_TO is empty, so no mails are sent");
            return None;
        }
        Some(Self {
            host,
            port,
            user,
            password: get("SMTP_PASSWORD"),
            from,
            to,
        })
    }
}

struct Mailer {
    config: MailConfig,
    transport: AsyncSmtpTransport<Tokio1Executor>,
}

impl Mailer {
    fn new(config: MailConfig) -> Option<Self> {
        let builder = if config.port == 465 {
            AsyncSmtpTransport::<Tokio1Executor>::relay(&config.host)
        } else {
            AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&config.host)
        };
        let builder = match builder {
            Ok(builder) => builder.port(config.port).timeout(Some(SMTP_TIMEOUT)),
            Err(err) => {
                log::error!("SimpleDesk mail: the mail server {} cannot be used: {}", config.host, err);
                return None;
            }
        };
        let builder = if config.user.is_empty() {
            builder
        } else {
            builder.credentials(Credentials::new(config.user.clone(), config.password.clone()))
        };
        log::info!(
            "SimpleDesk mail: alarms go to {} over {}:{} (user '{}')",
            config.to.iter().map(|to| to.to_string()).collect::<Vec<_>>().join(", "),
            config.host,
            config.port,
            config.user
        );
        Some(Self {
            transport: builder.build(),
            config,
        })
    }

    async fn send(&self, subject: &str, body: String) {
        let mut message = Message::builder()
            .from(self.config.from.clone())
            .subject(subject)
            .header(ContentType::TEXT_PLAIN);
        for to in &self.config.to {
            message = message.to(to.clone());
        }
        let message = match message.body(body) {
            Ok(message) => message,
            Err(err) => {
                log::error!("SimpleDesk mail: building the mail \"{}\" failed: {}", subject, err);
                return;
            }
        };
        match self.transport.send(message).await {
            Ok(_) => log::info!("SimpleDesk mail: sent \"{}\"", subject),
            Err(err) => log::error!("SimpleDesk mail: sending \"{}\" failed: {}", subject, err),
        }
    }
}

static MAILER: Lazy<Option<Mailer>> = Lazy::new(|| MailConfig::from_vars(get_arg).and_then(Mailer::new));

/// Whether mails are set up (SMTP_HOST and ALARM_MAIL_TO).
pub(crate) fn enabled() -> bool {
    MAILER.is_some()
}

/// When a mail of a kind for a device went out last, in unix seconds.
static SENT: Lazy<Mutex<Vec<(String, u64)>>> = Lazy::new(Default::default);
/// Devices (by uuid) the admins already got a mail about waiting for an ID.
static ANNOUNCED: Lazy<Mutex<HashSet<Vec<u8>>>> = Lazy::new(Default::default);

/// Whether a mail with this key may go out now, and notes it.
fn not_too_often(key: String, now: u64) -> bool {
    let Ok(mut sent) = SENT.lock() else {
        return true;
    };
    sent.retain(|(_, at)| now.saturating_sub(*at) < SAME_MAIL_SECS);
    if sent.iter().any(|(sent_key, _)| *sent_key == key) {
        return false;
    }
    sent.push((key, now));
    true
}

fn send_later(subject: String, body: String) {
    if MAILER.is_none() {
        return;
    }
    tokio::spawn(async move {
        if let Some(mailer) = MAILER.as_ref() {
            mailer.send(&subject, body).await;
        }
    });
}

/// What happened, for an alarm mail.
pub(crate) struct Alarm<'a> {
    pub(crate) device_id: &'a str,
    pub(crate) what: &'a str,
    pub(crate) time: &'a str,
    pub(crate) user: &'a str,
    pub(crate) peer_id: &'a str,
    pub(crate) peer_name: &'a str,
    pub(crate) ip: &'a str,
}

fn or_dash(text: &str) -> &str {
    if text.is_empty() {
        "–"
    } else {
        text
    }
}

pub(crate) fn alarm_mail(alarm: &Alarm) -> (String, String) {
    let from = match (alarm.peer_id, alarm.peer_name) {
        ("", "") => String::new(),
        (id, "") => id.to_owned(),
        ("", name) => name.to_owned(),
        (id, name) => format!("{} ({})", id, name),
    };
    let subject = format!("SimpleDesk-Alarm: {}", alarm.device_id);
    let body = format!(
        "Hallo,\n\n\
         auf dem Gerät {} gab es einen Alarm:\n\
         {}\n\n\
         Zeit: {} (UTC)\n\
         Von: {}\n\
         IP: {}\n\
         Benutzer: {}\n\n\
         Alle Einträge findest du im SimpleDesk-Panel unter „Protokoll“.\n\
         Weitere Alarme dieses Geräts kommen frühestens in 10 Minuten wieder per Mail.\n\n\
         Diese Mail kommt automatisch von SimpleDesk.\n",
        alarm.device_id,
        alarm.what,
        alarm.time,
        or_dash(&from),
        or_dash(alarm.ip),
        or_dash(alarm.user),
    );
    (subject, body)
}

pub(crate) fn new_device_mail(device_id: &str, ip: &str) -> (String, String) {
    let subject = "SimpleDesk: Neues Gerät wartet auf eine ID".to_owned();
    let body = format!(
        "Hallo,\n\n\
         ein neues Gerät hat sich bei SimpleDesk gemeldet und wartet auf eine ID.\n\n\
         ID, die sich das Gerät selbst gegeben hat: {}\n\
         IP: {}\n\n\
         Gib ihm im SimpleDesk-Panel unter „Geräte“ eine ID. Dort siehst du auch den Namen\n\
         des Rechners. Bis dahin kann sich niemand mit dem Gerät verbinden.\n\n\
         Diese Mail kommt automatisch von SimpleDesk.\n",
        device_id,
        or_dash(ip),
    );
    (subject, body)
}

/// A mail about an alarm, unless one for this device went out in the last 10 minutes.
pub(crate) fn send_alarm(alarm: &Alarm, now: u64) {
    if MAILER.is_none() || !not_too_often(format!("alarm:{}", alarm.device_id), now) {
        return;
    }
    let (subject, body) = alarm_mail(alarm);
    send_later(subject, body);
}

/// A mail that a new device waits for an ID, once per device.
pub(crate) fn send_new_device(uuid: &[u8], device_id: &str, ip: &str) {
    if MAILER.is_none() {
        return;
    }
    if let Ok(mut announced) = ANNOUNCED.lock() {
        if !announced.insert(uuid.to_vec()) {
            return;
        }
    }
    let (subject, body) = new_device_mail(device_id, ip);
    send_later(subject, body);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn config(vars: &[(&str, &str)]) -> Option<MailConfig> {
        let vars: HashMap<String, String> =
            vars.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        MailConfig::from_vars(|name| vars.get(name).cloned().unwrap_or_default())
    }

    #[test]
    fn mails_only_with_smtp_host_and_recipients() {
        assert_eq!(config(&[]), None);
        assert_eq!(config(&[("SMTP_USER", "a@example.org"), ("ALARM_MAIL_TO", "it@example.org")]), None);
        let base = [
            ("SMTP_HOST", "mail.example.org"),
            ("SMTP_USER", "simpledesk@example.org"),
            ("SMTP_PASSWORD", "geheim"),
            ("ALARM_MAIL_TO", "it@example.org, , felix@example.org"),
        ];
        let mail = config(&base).unwrap();
        assert_eq!((mail.host.as_str(), mail.port), ("mail.example.org", 587));
        assert_eq!(mail.from.to_string(), "simpledesk@example.org");
        assert_eq!(mail.to.len(), 2);
        let mut with = base.to_vec();
        with.extend([("SMTP_PORT", "465"), ("SMTP_FROM", "SimpleDesk <alarm@example.org>")]);
        let mail = config(&with).unwrap();
        assert_eq!(mail.port, 465);
        assert_eq!(mail.from.email.to_string(), "alarm@example.org");
        // Unusable settings: no mails rather than half of them.
        for (name, value) in [("SMTP_PORT", "abc"), ("SMTP_FROM", "kein Absender"), ("ALARM_MAIL_TO", " ")] {
            let mut broken = base.to_vec();
            broken.push((name, value));
            assert_eq!(config(&broken), None, "{name}={value}");
        }
        // The password is kept for the login, but never shown.
        let mail = config(&base).unwrap();
        assert_eq!(mail.password, "geheim");
        assert!(!format!("{mail:?}").contains("geheim"));
    }

    #[test]
    fn mail_texts_are_short_and_german() {
        let alarm = Alarm {
            device_id: "Rathaus-PC",
            what: "6 falsche Passwörter in einer Minute",
            time: "13.11.2026 09:41:07",
            user: "",
            peer_id: "Fremd-PC",
            peer_name: "",
            ip: "198.51.100.66",
        };
        let (subject, body) = alarm_mail(&alarm);
        assert_eq!(subject, "SimpleDesk-Alarm: Rathaus-PC");
        assert!(body.contains("auf dem Gerät Rathaus-PC gab es einen Alarm:\n6 falsche Passwörter"), "{body}");
        assert!(body.contains("Von: Fremd-PC\nIP: 198.51.100.66\nBenutzer: –"), "{body}");
        let (subject, body) = new_device_mail("123456789", "203.0.113.8");
        assert_eq!(subject, "SimpleDesk: Neues Gerät wartet auf eine ID");
        assert!(body.contains("selbst gegeben hat: 123456789\nIP: 203.0.113.8"), "{body}");
    }

    #[test]
    fn the_same_alarm_mail_at_most_every_10_minutes() {
        let key = format!("alarm:{}", uuid::Uuid::new_v4());
        assert!(not_too_often(key.clone(), 1_000_000));
        assert!(!not_too_often(key.clone(), 1_000_000 + 60));
        assert!(not_too_often(format!("{key}-anders"), 1_000_000 + 60));
        assert!(not_too_often(key, 1_000_000 + SAME_MAIL_SECS));
    }
}
