//! SimpleDesk: login through an OpenID Connect provider such as Eider, for the web panel and
//! for the client.
//!
//! Authorization code flow with PKCE (S256) and a client secret. The ID token is checked with
//! HS256 and the client secret (OIDC Core 10.1): issuer, audience, expiry and nonce. The
//! provider is found with its discovery document. Configuration:
//! OIDC_ISSUER, OIDC_CLIENT_ID (default simpledesk), OIDC_CLIENT_SECRET, OIDC_NAME (default
//! Eider) and PANEL_URL, the public address of the panel; the redirect URI is
//! PANEL_URL/oidc/callback. Without OIDC_ISSUER the login through a provider is off.
//!
//! The client signs in like this (src/hbbs_http/account.rs of the client): it asks
//! /api/oidc/auth for a code and an address, opens the address in the browser and asks
//! /api/oidc/auth-query with the code every second until the login in the browser is done.

use crate::common::get_arg;
use crate::panel::hex;
use hbb_common::{bail, log, tokio, ResultType};
use serde_derive::Deserialize;
use sodiumoxide::{crypto::hash::sha256, randombytes::randombytes};
use std::{
    collections::HashMap,
    time::{Duration, Instant},
};
use tokio::sync::Mutex;

/// How long a login may take at the provider, with password and second factor.
const PENDING_LIFETIME: Duration = Duration::from_secs(10 * 60);
/// How long the client may wait for its login in the browser (it gives up after 3 minutes).
const CLIENT_LOGIN_LIFETIME: Duration = Duration::from_secs(5 * 60);
/// At most this many logins on their way, so requests without a login cannot fill the memory.
const MAX_PENDING: usize = 1000;
const HTTP_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone)]
pub(crate) struct OidcConfig {
    pub(crate) issuer: String,
    pub(crate) client_id: String,
    pub(crate) client_secret: String,
    /// Shown on the login button and in the client, e.g. "Eider".
    pub(crate) name: String,
    pub(crate) redirect_uri: String,
}

impl OidcConfig {
    /// The configuration from the arguments or environment, None if OIDC_ISSUER is not set.
    pub(crate) fn from_args() -> Option<Self> {
        let issuer = get_arg("OIDC_ISSUER").trim().trim_end_matches('/').to_owned();
        if issuer.is_empty() {
            return None;
        }
        let client_secret = get_arg("OIDC_CLIENT_SECRET");
        let panel_url = get_arg("PANEL_URL").trim().trim_end_matches('/').to_owned();
        if client_secret.is_empty() || panel_url.is_empty() {
            log::error!("SimpleDesk OIDC is off: OIDC_CLIENT_SECRET and PANEL_URL are needed with OIDC_ISSUER");
            return None;
        }
        let non_empty = |name: &str, default: &str| {
            let value = get_arg(name);
            if value.trim().is_empty() {
                default.to_owned()
            } else {
                value.trim().to_owned()
            }
        };
        Some(Self {
            issuer,
            client_id: non_empty("OIDC_CLIENT_ID", "simpledesk"),
            client_secret,
            name: non_empty("OIDC_NAME", "Eider"),
            redirect_uri: format!("{}/oidc/callback", panel_url),
        })
    }
}

/// What a login at the provider is for.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Purpose {
    /// The web panel: a session cookie afterwards.
    Panel,
    /// The client that asked /api/oidc/auth with this code.
    Client(String),
}

struct Pending {
    nonce: String,
    verifier: String,
    purpose: Purpose,
    started: Instant,
}

struct ClientLogin {
    device_id: String,
    uuid: String,
    started: Instant,
    /// Set when the login in the browser is done.
    user: Option<String>,
}

#[derive(Clone)]
struct Endpoints {
    authorization: String,
    token: String,
}

#[derive(Deserialize)]
struct Discovery {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
}

#[derive(Deserialize)]
struct TokenResponse {
    id_token: String,
}

#[derive(Deserialize)]
struct Claims {
    sub: String,
    #[serde(default)]
    nonce: String,
    #[serde(default)]
    preferred_username: String,
}

/// What /api/oidc/auth-query answers.
pub(crate) enum ClientLoginState {
    /// The browser login is not done yet.
    Waiting,
    /// Done; the client gets a token for this user. The entry is gone afterwards.
    Done(String),
    /// Unknown code, wrong device or expired.
    Unknown,
}

pub(crate) struct Oidc {
    pub(crate) config: OidcConfig,
    http: reqwest::Client,
    endpoints: Mutex<Option<Endpoints>>,
    pending: Mutex<HashMap<String, Pending>>,
    client_logins: Mutex<HashMap<String, ClientLogin>>,
}

impl Oidc {
    pub(crate) fn new(config: OidcConfig) -> ResultType<Self> {
        let http = reqwest::Client::builder().timeout(HTTP_TIMEOUT).build()?;
        Ok(Self {
            config,
            http,
            endpoints: Default::default(),
            pending: Default::default(),
            client_logins: Default::default(),
        })
    }

    /// The provider's endpoints from its discovery document, fetched once.
    async fn endpoints(&self) -> ResultType<Endpoints> {
        let mut cached = self.endpoints.lock().await;
        if let Some(endpoints) = cached.as_ref() {
            return Ok(endpoints.clone());
        }
        let url = format!("{}/.well-known/openid-configuration", self.config.issuer);
        let discovery: Discovery = self.http.get(&url).send().await?.error_for_status()?.json().await?;
        if discovery.issuer.trim_end_matches('/') != self.config.issuer {
            bail!("issuer of the discovery document is {}, not {}", discovery.issuer, self.config.issuer);
        }
        let endpoints = Endpoints {
            authorization: discovery.authorization_endpoint,
            token: discovery.token_endpoint,
        };
        *cached = Some(endpoints.clone());
        Ok(endpoints)
    }

    /// Starts a login at the provider and returns the address the browser opens.
    pub(crate) async fn start(&self, purpose: Purpose) -> ResultType<String> {
        let endpoints = self.endpoints().await?;
        let state = hex(&randombytes(32));
        let nonce = hex(&randombytes(32));
        let verifier = base64::encode_config(randombytes(32), base64::URL_SAFE_NO_PAD);
        let challenge = base64::encode_config(sha256::hash(verifier.as_bytes()).0, base64::URL_SAFE_NO_PAD);
        let url = reqwest::Url::parse_with_params(
            &endpoints.authorization,
            &[
                ("response_type", "code"),
                ("client_id", self.config.client_id.as_str()),
                ("redirect_uri", self.config.redirect_uri.as_str()),
                ("scope", "openid profile"),
                ("state", state.as_str()),
                ("nonce", nonce.as_str()),
                ("code_challenge", challenge.as_str()),
                ("code_challenge_method", "S256"),
            ],
        )?;
        let mut pending = self.pending.lock().await;
        pending.retain(|_, login| login.started.elapsed() < PENDING_LIFETIME);
        if pending.len() >= MAX_PENDING {
            bail!("too many logins on their way");
        }
        pending.insert(
            state,
            Pending {
                nonce,
                verifier,
                purpose,
                started: Instant::now(),
            },
        );
        Ok(url.to_string())
    }

    /// The provider sent the browser back: trades the code, checks the ID token and returns
    /// the user name and what the login was for. Each state works once.
    pub(crate) async fn finish(&self, code: &str, state: &str) -> ResultType<(String, Purpose)> {
        let Some(pending) = self.pending.lock().await.remove(state) else {
            bail!("unknown or used state");
        };
        if pending.started.elapsed() >= PENDING_LIFETIME {
            bail!("the login took too long");
        }
        let endpoints = self.endpoints().await?;
        let form = [
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", self.config.redirect_uri.as_str()),
            ("client_id", self.config.client_id.as_str()),
            ("client_secret", self.config.client_secret.as_str()),
            ("code_verifier", pending.verifier.as_str()),
        ];
        let res = self.http.post(&endpoints.token).form(&form).send().await?;
        if !res.status().is_success() {
            bail!("token endpoint answered {}: {}", res.status(), res.text().await.unwrap_or_default());
        }
        let token: TokenResponse = res.json().await?;
        let claims = self.check_id_token(&token.id_token)?;
        if claims.nonce != pending.nonce {
            bail!("nonce of the ID token does not match");
        }
        let user = if claims.preferred_username.trim().is_empty() {
            claims.sub
        } else {
            claims.preferred_username.trim().to_owned()
        };
        if user.is_empty() || user.len() > 100 {
            bail!("the ID token names no usable user");
        }
        Ok((user, pending.purpose))
    }

    fn check_id_token(&self, id_token: &str) -> ResultType<Claims> {
        use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_issuer(&[self.config.issuer.as_str()]);
        validation.set_audience(&[self.config.client_id.as_str()]);
        validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
        let key = DecodingKey::from_secret(self.config.client_secret.as_bytes());
        Ok(decode::<Claims>(id_token, &key, &validation)?.claims)
    }

    /// /api/oidc/auth: a client wants to sign in. Returns its code and the address to open.
    pub(crate) async fn start_client_login(&self, device_id: &str, uuid: &str) -> ResultType<(String, String)> {
        let code = hex(&randombytes(32));
        {
            let mut logins = self.client_logins.lock().await;
            logins.retain(|_, login| login.started.elapsed() < CLIENT_LOGIN_LIFETIME);
            if logins.len() >= MAX_PENDING {
                bail!("too many client logins on their way");
            }
            logins.insert(
                code.clone(),
                ClientLogin {
                    device_id: device_id.to_owned(),
                    uuid: uuid.to_owned(),
                    started: Instant::now(),
                    user: None,
                },
            );
        }
        let url = self.start(Purpose::Client(code.clone())).await?;
        Ok((code, url))
    }

    /// The browser login for a client is done. Returns the device ID, so the page can name the
    /// device that is now signed in; None if the client login is unknown or expired.
    pub(crate) async fn client_login_done(&self, code: &str, user: &str) -> Option<String> {
        match self.client_logins.lock().await.get_mut(code) {
            Some(login) if login.started.elapsed() < CLIENT_LOGIN_LIFETIME => {
                login.user = Some(user.to_owned());
                Some(login.device_id.clone())
            }
            _ => None,
        }
    }

    /// /api/oidc/auth-query: only the device that asked gets the result, and only once.
    pub(crate) async fn client_login_state(&self, code: &str, device_id: &str, uuid: &str) -> ClientLoginState {
        let mut logins = self.client_logins.lock().await;
        let Some(login) = logins.get(code) else {
            return ClientLoginState::Unknown;
        };
        if login.device_id != device_id
            || login.uuid != uuid
            || login.started.elapsed() >= CLIENT_LOGIN_LIFETIME
        {
            return ClientLoginState::Unknown;
        }
        match login.user.clone() {
            None => ClientLoginState::Waiting,
            Some(user) => {
                logins.remove(code);
                ClientLoginState::Done(user)
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod test_provider {
    //! A small OIDC provider for the tests: discovery, an authorize address that is never
    //! opened, and a token endpoint that checks code, secret and PKCE and issues an HS256
    //! ID token for the user and nonce the test set.

    use axum::{
        extract::{Extension, Form},
        http::StatusCode,
        response::IntoResponse,
        routing::{get, post},
        Json, Router,
    };
    use hbb_common::tokio::{self, sync::Mutex};
    use serde_json::json;
    use sodiumoxide::crypto::hash::sha256;
    use std::{collections::HashMap, net::SocketAddr, sync::Arc};

    pub(crate) const SECRET: &str = "test-secret-of-simpledesk";

    #[derive(Default)]
    pub(crate) struct Grant {
        pub(crate) user: String,
        pub(crate) nonce: String,
        pub(crate) challenge: String,
    }

    pub(crate) struct Provider {
        pub(crate) issuer: String,
        /// Codes the test hands out, with what the token endpoint issues for them.
        pub(crate) grants: Mutex<HashMap<String, Grant>>,
    }

    pub(crate) async fn start() -> Arc<Provider> {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr: SocketAddr = listener.local_addr().unwrap();
        let provider = Arc::new(Provider {
            issuer: format!("http://{addr}"),
            grants: Default::default(),
        });
        let app = Router::new()
            .route("/.well-known/openid-configuration", get(discovery))
            .route("/oauth/token", post(token))
            .layer(Extension(provider.clone()));
        let server = axum::Server::from_tcp(listener).unwrap().serve(app.into_make_service());
        tokio::spawn(server);
        provider
    }

    async fn discovery(Extension(provider): Extension<Arc<Provider>>) -> impl IntoResponse {
        Json(json!({
            "issuer": provider.issuer,
            "authorization_endpoint": format!("{}/oauth/authorize", provider.issuer),
            "token_endpoint": format!("{}/oauth/token", provider.issuer),
        }))
    }

    async fn token(
        Extension(provider): Extension<Arc<Provider>>,
        Form(form): Form<HashMap<String, String>>,
    ) -> impl IntoResponse {
        let field = |name: &str| form.get(name).cloned().unwrap_or_default();
        if field("client_secret") != SECRET || field("client_id") != "simpledesk" {
            return (StatusCode::UNAUTHORIZED, Json(json!({"error": "invalid_client"})));
        }
        let Some(grant) = provider.grants.lock().await.remove(&field("code")) else {
            return (StatusCode::BAD_REQUEST, Json(json!({"error": "invalid_grant"})));
        };
        let challenge = base64::encode_config(
            sha256::hash(field("code_verifier").as_bytes()).0,
            base64::URL_SAFE_NO_PAD,
        );
        if challenge != grant.challenge {
            return (StatusCode::BAD_REQUEST, Json(json!({"error": "invalid_grant"})));
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let claims = json!({
            "iss": provider.issuer, "sub": "42", "aud": "simpledesk", "iat": now, "exp": now + 300,
            "nonce": grant.nonce, "name": grant.user, "preferred_username": grant.user,
        });
        let id_token = jsonwebtoken::encode(
            &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256),
            &claims,
            &jsonwebtoken::EncodingKey::from_secret(SECRET.as_bytes()),
        )
        .unwrap();
        (
            StatusCode::OK,
            Json(json!({"access_token": "x", "token_type": "Bearer", "expires_in": 300, "id_token": id_token})),
        )
    }

    /// The fields of an authorize address SimpleDesk built.
    pub(crate) fn query_of(url: &str) -> HashMap<String, String> {
        reqwest::Url::parse(url)
            .unwrap()
            .query_pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::test_provider::{self, query_of, Grant, SECRET};
    use super::*;
    use crate::panel::{router, Panel};
    use axum::{
        body::Body,
        http::{header, Request, StatusCode},
        response::Response,
    };
    use serde_json::{json, Value};
    use std::sync::Arc;
    use tower::ServiceExt;

    async fn panel_with_oidc(dir: &tempfile::TempDir, issuer: &str) -> Arc<Panel> {
        let pm = crate::peer::test_peer_map(dir).await;
        let oidc = Oidc::new(OidcConfig {
            issuer: issuer.to_owned(),
            client_id: "simpledesk".to_owned(),
            client_secret: SECRET.to_owned(),
            name: "Eider".to_owned(),
            redirect_uri: "http://localhost:21114/oidc/callback".to_owned(),
        })
        .unwrap();
        Arc::new(Panel::new(pm, Default::default()).await.unwrap().with_oidc(oidc))
    }

    async fn call(
        panel: &Arc<Panel>,
        method: &str,
        path: &str,
        cookie: Option<&str>,
        body: Option<Value>,
    ) -> Response {
        let mut req = Request::builder().method(method).uri(path);
        if let Some(cookie) = cookie {
            req = req.header(header::COOKIE, cookie);
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
        serde_json::from_str(&text(res).await).unwrap()
    }

    fn location(res: &Response) -> String {
        res.headers()[header::LOCATION].to_str().unwrap().to_owned()
    }

    /// The provider will answer `code` for the login the authorize address belongs to.
    async fn grant(provider: &test_provider::Provider, authorize: &str, code: &str, user: &str) -> String {
        let query = query_of(authorize);
        provider.grants.lock().await.insert(
            code.to_owned(),
            Grant {
                user: user.to_owned(),
                nonce: query["nonce"].clone(),
                challenge: query["code_challenge"].clone(),
            },
        );
        query["state"].clone()
    }

    #[hbb_common::tokio::test]
    async fn panel_signs_in_through_the_provider() {
        let provider = test_provider::start().await;
        let dir = tempfile::tempdir().unwrap();
        let panel = panel_with_oidc(&dir, &provider.issuer).await;
        let login = text(call(&panel, "GET", "/login", None, None).await).await;
        assert!(login.contains("Mit Eider anmelden"), "{login}");
        assert!(!login.contains("<input"), "{login}");

        // Off to the provider with PKCE, nonce and the configured redirect URI.
        let res = call(&panel, "GET", "/oidc/login", None, None).await;
        assert_eq!(res.status(), StatusCode::SEE_OTHER);
        let authorize = location(&res);
        assert!(authorize.starts_with(&format!("{}/oauth/authorize?", provider.issuer)));
        let query = query_of(&authorize);
        assert_eq!(query["client_id"], "simpledesk");
        assert_eq!(query["redirect_uri"], "http://localhost:21114/oidc/callback");
        assert_eq!(query["scope"], "openid profile");
        assert_eq!(query["code_challenge_method"], "S256");

        // Back with the code: a session for the user from the ID token.
        let state = grant(&provider, &authorize, "code-1", "felix").await;
        let callback = format!("/oidc/callback?code=code-1&state={state}");
        let res = call(&panel, "GET", &callback, None, None).await;
        assert_eq!(location(&res), "/");
        let set_cookie = res.headers()[header::SET_COOKIE].to_str().unwrap();
        let cookie = set_cookie.split(';').next().unwrap().to_owned();
        let page = text(call(&panel, "GET", "/", Some(&cookie), None).await).await;
        assert!(page.contains("felix"), "{page}");
        // The account has no password here; the client is sent to the button.
        let body = json!({"username": "felix", "password": "!", "type": "account"});
        let res = json_of(call(&panel, "POST", "/api/login", None, Some(body)).await).await;
        assert!(res["error"].as_str().unwrap().contains("Mit Eider anmelden"), "{res}");
        assert!(res.get("access_token").is_none());

        // A state works once.
        let res = call(&panel, "GET", &callback, None, None).await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);

        // An ID token for another login (wrong nonce) is refused.
        let authorize = location(&call(&panel, "GET", "/oidc/login", None, None).await);
        let state = grant(&provider, &authorize, "code-2", "felix").await;
        provider.grants.lock().await.get_mut("code-2").unwrap().nonce = "another".to_owned();
        let callback = format!("/oidc/callback?code=code-2&state={state}");
        let res = call(&panel, "GET", &callback, None, None).await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);

        // The provider refused: no session.
        let res = call(&panel, "GET", "/oidc/callback?error=access_denied&state=x", None, None).await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    }

    #[hbb_common::tokio::test]
    async fn client_signs_in_in_the_browser() {
        let provider = test_provider::start().await;
        let dir = tempfile::tempdir().unwrap();
        let panel = panel_with_oidc(&dir, &provider.issuer).await;

        let options = json_of(call(&panel, "GET", "/api/login-options", None, None).await).await;
        assert_eq!(options, json!(["oidc/Eider"]));

        let body = json!({"op": "Eider", "id": "Felix-Work-PC", "uuid": "dXVpZA==", "deviceInfo": {"os": "windows"}});
        let started = json_of(call(&panel, "POST", "/api/oidc/auth", None, Some(body)).await).await;
        let code = started["code"].as_str().unwrap().to_owned();
        let authorize = started["url"].as_str().unwrap().to_owned();
        let query_path = format!("/api/oidc/auth-query?code={code}&id=Felix-Work-PC&uuid=dXVpZA%3D%3D");

        // Waiting: exactly the error the client keeps asking on.
        let waiting = json_of(call(&panel, "GET", &query_path, None, None).await).await;
        assert_eq!(waiting, json!({"error": "No authed oidc is found"}));
        // Another device does not get this login.
        let other = format!("/api/oidc/auth-query?code={code}&id=Someone-Else&uuid=dXVpZA%3D%3D");
        assert_eq!(call(&panel, "GET", &other, None, None).await.status(), StatusCode::BAD_REQUEST);

        // The login in the browser finishes on the callback page.
        let state = grant(&provider, &authorize, "code-3", "felix").await;
        let callback = format!("/oidc/callback?code=code-3&state={state}");
        let res = call(&panel, "GET", &callback, None, None).await;
        assert_eq!(res.status(), StatusCode::OK);
        let page = text(res).await;
        assert!(page.contains("Das Gerät Felix-Work-PC ist jetzt mit deinem Konto angemeldet"), "{page}");

        // The client gets its token once, and the token works.
        let done = json_of(call(&panel, "GET", &query_path, None, None).await).await;
        assert_eq!(done["type"], "access_token");
        assert_eq!(done["user"]["name"], "felix");
        assert_eq!(done["user"]["info"], json!({}));
        assert_eq!(call(&panel, "GET", &query_path, None, None).await.status(), StatusCode::BAD_REQUEST);
        let token = done["access_token"].as_str().unwrap();
        let req = Request::post("/api/currentUser")
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from("{}"))
            .unwrap();
        let res = router(panel.clone()).oneshot(req).await.unwrap();
        assert_eq!(json_of(res).await["name"], "felix");
    }
}
