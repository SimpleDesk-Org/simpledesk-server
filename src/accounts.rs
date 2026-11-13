//! SimpleDesk: settings for signed-in users, read once at the start.
//!
//! TOKEN_DAYS: how many days a client stays signed in (default 14). The provider (Eider) has
//! no refresh tokens, so SimpleDesk only learns at the next login that somebody lost the
//! Lizenz. The default keeps that window at two weeks; "Sperren" in the panel ends it at once.
//! PANEL_SESSION_HOURS: how many hours a login in the web panel lasts (default 8).
//! ADMIN_USERS: user names at the provider, separated by commas, who are admins. Admins see and
//! control every device and manage users and groups. Everybody else is a Benutzer.
//! IDS_BY_ADMIN=Y: only admins give devices their ID. A new device can be reached only after
//! an admin gave it an ID in the panel, and a device may change its ID only to the one an
//! admin chose for it.

use crate::common::get_arg;
use hbb_common::log;

pub(crate) const DEFAULT_TOKEN_DAYS: i64 = 14;
pub(crate) const DEFAULT_SESSION_HOURS: i64 = 8;

#[derive(Clone, Debug)]
pub(crate) struct Accounts {
    /// Days an access token of the client is valid, counted from the login.
    pub(crate) token_days: i64,
    /// Hours a session of the web panel is valid, counted from the login.
    pub(crate) session_hours: i64,
    /// Names of the admins in lower case.
    pub(crate) admins: Vec<String>,
    /// IDS_BY_ADMIN=Y: device IDs come from admins only.
    pub(crate) ids_by_admin: bool,
}

impl Default for Accounts {
    fn default() -> Self {
        Self {
            token_days: DEFAULT_TOKEN_DAYS,
            session_hours: DEFAULT_SESSION_HOURS,
            admins: Vec::new(),
            ids_by_admin: false,
        }
    }
}

impl Accounts {
    pub(crate) fn from_args() -> Self {
        let accounts = Self {
            token_days: positive("TOKEN_DAYS", DEFAULT_TOKEN_DAYS),
            session_hours: positive("PANEL_SESSION_HOURS", DEFAULT_SESSION_HOURS),
            admins: parse_names(&get_arg("ADMIN_USERS")),
            ids_by_admin: get_arg("IDS_BY_ADMIN").trim().to_uppercase() == "Y",
        };
        log::info!(
            "TOKEN_DAYS={}, PANEL_SESSION_HOURS={}, IDS_BY_ADMIN={}",
            accounts.token_days,
            accounts.session_hours,
            if accounts.ids_by_admin { "Y" } else { "N" }
        );
        if accounts.admins.is_empty() {
            log::warn!("ADMIN_USERS is empty: nobody can manage users, and devices without owner cannot be controlled");
        } else {
            log::info!("ADMIN_USERS={}", accounts.admins.join(","));
        }
        accounts
    }

    /// Admins come only from ADMIN_USERS, so nobody can take the role away in the panel.
    /// Upper and lower case do not matter.
    pub(crate) fn is_admin(&self, user: &str) -> bool {
        let user = user.trim().to_lowercase();
        !user.is_empty() && self.admins.iter().any(|admin| *admin == user)
    }

    #[cfg(test)]
    pub(crate) fn with_admins(admins: &str) -> Self {
        Self {
            admins: parse_names(admins),
            ..Default::default()
        }
    }

    #[cfg(test)]
    pub(crate) fn with_ids_by_admin(admins: &str) -> Self {
        Self {
            ids_by_admin: true,
            ..Self::with_admins(admins)
        }
    }
}

/// Names separated by commas, trimmed and in lower case.
fn parse_names(list: &str) -> Vec<String> {
    list.split(',')
        .map(|name| name.trim().to_lowercase())
        .filter(|name| !name.is_empty())
        .collect()
}

/// A whole number above 0 from the arguments or environment, else the default.
fn positive(name: &str, default: i64) -> i64 {
    let value = get_arg(name);
    if value.trim().is_empty() {
        return default;
    }
    match value.trim().parse::<i64>() {
        Ok(number) if number > 0 => number,
        _ => {
            log::warn!("{}={} is not a number above 0, using {}", name, value, default);
            default
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admins_come_from_a_comma_separated_list() {
        let accounts = Accounts::with_admins(" Felix, , it-admin ");
        assert_eq!(accounts.admins, vec!["felix", "it-admin"]);
        assert!(accounts.is_admin("felix") && accounts.is_admin("FELIX") && accounts.is_admin("it-admin"));
        assert!(!accounts.is_admin("kollege") && !accounts.is_admin(""));
        assert!(!Accounts::default().is_admin("felix"));
    }
}
