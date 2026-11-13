//! SimpleDesk: settings for signed-in users, read once at the start.
//!
//! TOKEN_DAYS: how many days a client stays signed in (default 14). The provider (Eider) has
//! no refresh tokens, so SimpleDesk only learns at the next login that somebody lost the
//! Lizenz. The default keeps that window at two weeks; "Sperren" in the panel ends it at once.
//! PANEL_SESSION_HOURS: how many hours a login in the web panel lasts (default 8).

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
}

impl Default for Accounts {
    fn default() -> Self {
        Self {
            token_days: DEFAULT_TOKEN_DAYS,
            session_hours: DEFAULT_SESSION_HOURS,
        }
    }
}

impl Accounts {
    pub(crate) fn from_args() -> Self {
        let accounts = Self {
            token_days: positive("TOKEN_DAYS", DEFAULT_TOKEN_DAYS),
            session_hours: positive("PANEL_SESSION_HOURS", DEFAULT_SESSION_HOURS),
        };
        log::info!(
            "TOKEN_DAYS={}, PANEL_SESSION_HOURS={}",
            accounts.token_days,
            accounts.session_hours
        );
        accounts
    }
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
