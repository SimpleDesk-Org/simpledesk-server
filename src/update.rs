//! SimpleDesk: tells admins in the panel when a newer server image is out.
//!
//! The image knows the commit it was built from (SIMPLEDESK_COMMIT, a build argument of
//! simpledesk/Dockerfile). The panel asks GitHub whether our own repository has something newer:
//! the latest release if there are releases, else the head of the branch `simpledesk`. Only
//! GitHub, and only our repository. The answer is kept for 6 hours; errors change nothing on
//! the page. UPDATE_CHECK=N turns the check off.

use crate::common::get_arg;
use hbb_common::{bail, log, tokio, ResultType};
use serde_json::Value;
use std::{
    sync::Arc,
    time::{Duration, Instant},
};

/// The commit the server was built from, '' for a build without it.
pub(crate) const COMMIT: &str = match option_env!("SIMPLEDESK_COMMIT") {
    Some(commit) => commit,
    None => "",
};
const GITHUB_API: &str = "https://api.github.com";
const REPO: &str = "SimpleDesk-Org/simpledesk-server";
const BRANCH: &str = "simpledesk";
const CACHE_TIME: Duration = Duration::from_secs(6 * 3600);
const HTTP_TIMEOUT: Duration = Duration::from_secs(10);

pub(crate) struct UpdateCheck {
    /// The commit of this build; without one there is nothing to compare.
    commit: String,
    enabled: bool,
    api_url: String,
    http: Option<reqwest::Client>,
    state: tokio::sync::Mutex<CheckState>,
}

#[derive(Default)]
struct CheckState {
    checked: Option<Instant>,
    running: bool,
    /// What the banner says after "Neue Version verfügbar", '' for no banner.
    notice: String,
}

impl UpdateCheck {
    pub(crate) fn from_args() -> Self {
        let enabled = get_arg("UPDATE_CHECK").trim().to_uppercase() != "N";
        let check = Self::new(COMMIT, enabled, GITHUB_API);
        if !enabled {
            log::info!("SimpleDesk update check is off (UPDATE_CHECK=N)");
        } else if check.commit.is_empty() {
            log::info!("SimpleDesk update check: this build does not know its commit, no check");
        } else {
            log::info!("SimpleDesk update check: built from {}", check.commit);
        }
        check
    }

    fn new(commit: &str, enabled: bool, api_url: &str) -> Self {
        let commit = commit.trim();
        let commit = if (7..=40).contains(&commit.len()) && commit.chars().all(|c| c.is_ascii_hexdigit()) {
            commit.to_lowercase()
        } else {
            String::new()
        };
        let http = reqwest::Client::builder()
            .timeout(HTTP_TIMEOUT)
            .user_agent(concat!("SimpleDesk-Server/", env!("CARGO_PKG_VERSION")))
            .build();
        let http = match http {
            Ok(http) => Some(http),
            Err(err) => {
                log::warn!("SimpleDesk update check is off: {}", err);
                None
            }
        };
        Self {
            commit,
            enabled,
            api_url: api_url.trim_end_matches('/').to_owned(),
            http,
            state: Default::default(),
        }
    }

    fn active(&self) -> bool {
        self.enabled && !self.commit.is_empty() && self.http.is_some()
    }

    /// What the banner shows after "Neue Version verfügbar", '' for no banner. When the last
    /// answer is older than 6 hours, a new check starts in the background; the page does not
    /// wait for it.
    pub(crate) async fn notice(self: &Arc<Self>) -> String {
        if !self.active() {
            return String::new();
        }
        let mut state = self.state.lock().await;
        let due = state.checked.map_or(true, |checked| checked.elapsed() >= CACHE_TIME);
        if due && !state.running {
            state.running = true;
            let check = self.clone();
            tokio::spawn(async move { check.refresh().await });
        }
        state.notice.clone()
    }

    async fn refresh(&self) {
        let result = self.newer_version().await;
        let mut state = self.state.lock().await;
        match result {
            Ok(notice) => state.notice = notice.unwrap_or_default(),
            // Quiet: the page stays as it was, the next try is in 6 hours.
            Err(err) => log::info!("SimpleDesk update check failed: {}", err),
        }
        state.checked = Some(Instant::now());
        state.running = false;
    }

    /// Whether GitHub has something newer than this build: Some(text for the banner) or None.
    async fn newer_version(&self) -> ResultType<Option<String>> {
        let Some(http) = self.http.as_ref() else {
            bail!("no HTTP client");
        };
        let release_url = format!("{}/repos/{}/releases/latest", self.api_url, REPO);
        let res = http.get(&release_url).send().await?;
        let release = if res.status() == reqwest::StatusCode::NOT_FOUND {
            None
        } else {
            Some(res.error_for_status()?.json::<Value>().await?)
        };
        let (target, release_name) = match release.as_ref().and_then(release_tag) {
            Some((tag, name)) => (tag, Some(name)),
            None => (BRANCH.to_owned(), None),
        };
        let compare_url = format!("{}/repos/{}/compare/{}...{}", self.api_url, REPO, self.commit, target);
        let compare: Value = http.get(&compare_url).send().await?.error_for_status()?.json().await?;
        Ok(newer_text(&compare, release_name.as_deref()))
    }

    #[cfg(test)]
    pub(crate) fn with_notice(notice: &str) -> Self {
        let check = Self::new("0123456789abcdef0123456789abcdef01234567", true, "http://127.0.0.1:9");
        if let Ok(mut state) = check.state.try_lock() {
            state.checked = Some(Instant::now());
            state.notice = notice.to_owned();
        }
        check
    }
}

/// The tag and name of a release from GitHub's answer, if it has a tag.
fn release_tag(release: &Value) -> Option<(String, String)> {
    let tag = release.get("tag_name")?.as_str()?.trim();
    if tag.is_empty() {
        return None;
    }
    let name = release
        .get("name")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .unwrap_or(tag);
    Some((tag.to_owned(), name.to_owned()))
}

/// From GitHub's comparison of this build with the newest version: the text for the banner if
/// the newest version has changes this build does not have.
fn newer_text(compare: &Value, release_name: Option<&str>) -> Option<String> {
    let status = compare.get("status").and_then(Value::as_str).unwrap_or_default();
    if status != "ahead" && status != "diverged" {
        return None;
    }
    if let Some(name) = release_name {
        return Some(name.to_owned());
    }
    match compare.get("ahead_by").and_then(Value::as_u64).unwrap_or(0) {
        0 => None,
        1 => Some("1 neue Änderung".to_owned()),
        count => Some(format!("{} neue Änderungen", count)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{extract::Path, http::StatusCode, response::IntoResponse, routing::get, Json, Router};
    use serde_json::json;

    #[test]
    fn only_newer_versions_make_a_banner() {
        assert_eq!(newer_text(&json!({"status": "ahead", "ahead_by": 3}), None).as_deref(), Some("3 neue Änderungen"));
        assert_eq!(newer_text(&json!({"status": "ahead", "ahead_by": 1}), None).as_deref(), Some("1 neue Änderung"));
        assert_eq!(newer_text(&json!({"status": "diverged", "ahead_by": 2}), Some("v1.2")).as_deref(), Some("v1.2"));
        for status in ["identical", "behind", ""] {
            assert_eq!(newer_text(&json!({"status": status, "ahead_by": 0}), None), None, "{status}");
        }
        assert_eq!(release_tag(&json!({"tag_name": "v1.2", "name": ""})), Some(("v1.2".to_owned(), "v1.2".to_owned())));
        assert_eq!(release_tag(&json!({"message": "Not Found"})), None);
    }

    #[test]
    fn without_commit_or_when_off_nothing_is_checked() {
        assert!(!UpdateCheck::new("", true, GITHUB_API).active());
        assert!(!UpdateCheck::new("nicht-hex", true, GITHUB_API).active());
        assert!(!UpdateCheck::new("0123456789abcdef", false, GITHUB_API).active());
        let check = UpdateCheck::new("0123456789ABCDEF", true, GITHUB_API);
        assert!(check.active());
        assert_eq!(check.commit, "0123456789abcdef");
    }

    /// A small stand-in for GitHub's API.
    async fn fake_github(releases: bool) -> String {
        let release = move || async move {
            if releases {
                Json(json!({"tag_name": "v2.0", "name": "SimpleDesk 2.0"})).into_response()
            } else {
                (StatusCode::NOT_FOUND, Json(json!({"message": "Not Found"}))).into_response()
            }
        };
        let compare = |Path(range): Path<String>| async move {
            match range.as_str() {
                "0123456789abcdef...simpledesk" => Json(json!({"status": "ahead", "ahead_by": 2})).into_response(),
                "0123456789abcdef...v2.0" => Json(json!({"status": "behind", "ahead_by": 0})).into_response(),
                "fedcba9876543210...simpledesk" => Json(json!({"status": "identical", "ahead_by": 0})).into_response(),
                _ => StatusCode::NOT_FOUND.into_response(),
            }
        };
        let app = Router::new()
            .route(&format!("/repos/{}/releases/latest", REPO), get(release))
            .route(&format!("/repos/{}/compare/:range", REPO), get(compare));
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = axum::Server::from_tcp(listener).unwrap().serve(app.into_make_service());
        tokio::spawn(server);
        format!("http://{addr}")
    }

    #[hbb_common::tokio::test]
    async fn asks_github_for_the_branch_or_the_latest_release() {
        // No releases: the head of simpledesk has 2 changes this build does not have.
        let api = fake_github(false).await;
        let check = Arc::new(UpdateCheck::new("0123456789abcdef", true, &api));
        check.refresh().await;
        assert_eq!(check.notice().await, "2 neue Änderungen");
        // Up to date: no banner.
        let check = Arc::new(UpdateCheck::new("fedcba9876543210", true, &api));
        check.refresh().await;
        assert_eq!(check.notice().await, "");
        // A build GitHub does not know: quiet.
        let check = Arc::new(UpdateCheck::new("1111111111111111", true, &api));
        check.refresh().await;
        assert_eq!(check.notice().await, "");

        // With releases the latest release counts; this build is newer than it.
        let api = fake_github(true).await;
        let check = Arc::new(UpdateCheck::new("0123456789abcdef", true, &api));
        check.refresh().await;
        assert_eq!(check.notice().await, "");

        // GitHub unreachable: quiet, and an earlier answer stays.
        let check = Arc::new(UpdateCheck::with_notice("1 neue Änderung"));
        check.refresh().await;
        assert_eq!(check.notice().await, "1 neue Änderung");
    }
}
