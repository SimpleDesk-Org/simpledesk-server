//! SimpleDesk: hbbr tells hbbs how many relay connections it carries, so hbbs can pick the
//! relay with the fewest (see relays.rs). The question is a WebSocket request for
//! `/ws/relay/status`, so it goes through the same proxy on port 443 as the relay itself.
//! tungstenite only lets a handshake end with an error status, so the answer is a 400 with
//! `{"simpledesk_relay": true, "connections": <n>}`.
//!
//! hbbr (src/hbbr.rs) and hbbs' tests both use this file.
#![allow(dead_code)]

use std::sync::atomic::{AtomicUsize, Ordering};
use tokio_tungstenite::tungstenite::{
    handshake::server::{ErrorResponse, Request},
    http::{header, HeaderValue, StatusCode},
};

static SESSIONS: AtomicUsize = AtomicUsize::new(0);

/// A relay connection in progress; counted while it lives.
pub(crate) struct Session(());

impl Session {
    pub(crate) fn start() -> Self {
        SESSIONS.fetch_add(1, Ordering::SeqCst);
        Session(())
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        SESSIONS.fetch_sub(1, Ordering::SeqCst);
    }
}

pub(crate) fn sessions() -> usize {
    SESSIONS.load(Ordering::SeqCst)
}

/// The answer to a status request, None for every other request.
pub(crate) fn status_answer(req: &Request) -> Option<ErrorResponse> {
    if !req.uri().path().trim_end_matches('/').ends_with("/status") {
        return None;
    }
    let body = format!("{{\"simpledesk_relay\":true,\"connections\":{}}}", sessions());
    let length = HeaderValue::from_str(&body.len().to_string()).ok();
    let mut res = ErrorResponse::new(Some(body));
    *res.status_mut() = StatusCode::BAD_REQUEST;
    let headers = res.headers_mut();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
    headers.insert(header::CONNECTION, HeaderValue::from_static("close"));
    if let Some(length) = length {
        headers.insert(header::CONTENT_LENGTH, length);
    }
    Some(res)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_status_requests_get_an_answer_and_sessions_count() {
        let request = |path: &str| Request::builder().uri(path).body(()).unwrap();
        assert!(status_answer(&request("/ws/relay")).is_none());
        let before = sessions();
        let session = Session::start();
        assert_eq!(sessions(), before + 1);
        let answer = status_answer(&request("/ws/relay/status")).unwrap();
        assert_eq!(answer.status(), StatusCode::BAD_REQUEST);
        let body = answer.body().clone().unwrap();
        assert!(body.starts_with("{\"simpledesk_relay\":true,\"connections\":"), "{body}");
        assert_eq!(answer.headers()[header::CONTENT_LENGTH], body.len().to_string().as_str());
        drop(session);
        assert_eq!(sessions(), before);
        assert!(status_answer(&request("/status")).is_some());
    }
}
