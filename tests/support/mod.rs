//! A local fake Lock realm: just enough of the protocol endpoints to drive the client.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use aws_lc_rs::digest::{SHA256, digest};
use axum::extract::{Form, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use lock_client::testing::FakeProvider;
use serde_json::{Value, json};

pub const CLIENT_ID: &str = "my-app";
pub const SECRET: &str = "s3cret/+&";
pub const REDIRECT: &str = "https://app.example.com/callback";

type Mutator = Box<dyn Fn(&mut Value) + Send + Sync>;

pub struct Realm {
    pub signer: FakeProvider,
    pub jwks: Value,
    pub id_claims: Option<Mutator>,
    pub codes: HashMap<String, (String, String)>, // code -> (challenge, nonce)
    pub refresh_tokens: Vec<String>,
    pub jwks_hits: usize,
    pub token_hits: usize,
    pub token_status: Option<u16>,
    pub counter: usize,
    pub last_basic: Option<(String, String)>,
}

pub struct Fake {
    pub url: String,
    pub state: Arc<Mutex<Realm>>,
}

impl Fake {
    pub async fn start() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let signer = FakeProvider::new(&url);
        let state = Arc::new(Mutex::new(Realm {
            jwks: signer.jwks(),
            signer,
            id_claims: None,
            codes: HashMap::new(),
            refresh_tokens: Vec::new(),
            jwks_hits: 0,
            token_hits: 0,
            token_status: None,
            counter: 0,
            last_basic: None,
        }));
        let app = Router::new()
            .route("/.well-known/jwks.json", get(jwks))
            .route("/.well-known/openid-configuration", get(discovery))
            .route("/oauth/token", post(token))
            .route("/oauth/userinfo", get(userinfo))
            .route("/oauth/introspect", post(introspect))
            .with_state(state.clone());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        Self { url, state }
    }

    pub fn with<R>(&self, f: impl FnOnce(&mut Realm) -> R) -> R {
        f(&mut self.state.lock().unwrap())
    }

    pub fn provider(&self) -> FakeProvider {
        FakeProvider::new(&self.url)
    }

    /// Plays the browser: "approves" the authorization request and returns the callback query.
    pub fn authorize(&self, request_url: &str) -> String {
        let url = url::Url::parse(request_url).unwrap();
        let q: HashMap<_, _> = url.query_pairs().into_owned().collect();
        assert_eq!(q["client_id"], CLIENT_ID);
        assert_eq!(q["code_challenge_method"], "S256");
        assert_eq!(q["redirect_uri"], REDIRECT);
        let mut realm = self.state.lock().unwrap();
        realm.counter += 1;
        let code = format!("code-{}", realm.counter);
        realm.codes.insert(
            code.clone(),
            (q["code_challenge"].clone(), q["nonce"].clone()),
        );
        format!("code={code}&state={}&iss={}", q["state"], self.url)
    }
}

async fn jwks(State(state): State<Arc<Mutex<Realm>>>) -> Json<Value> {
    let mut realm = state.lock().unwrap();
    realm.jwks_hits += 1;
    Json(realm.jwks.clone())
}

async fn discovery(State(state): State<Arc<Mutex<Realm>>>) -> Json<Value> {
    let _ = state;
    Json(json!({
        "issuer": "x", "authorization_endpoint": "x/oauth/authorize", "token_endpoint": "x/oauth/token",
        "jwks_uri": "x/.well-known/jwks.json", "claims_supported": ["sub", "name", "email"],
        "code_challenge_methods_supported": ["S256"],
    }))
}

fn oauth_error(status: u16, error: &str) -> Response {
    (
        StatusCode::from_u16(status).unwrap(),
        Json(json!({ "error": error, "error_description": "no" })),
    )
        .into_response()
}

fn basic(headers: &HeaderMap) -> Option<(String, String)> {
    let value = headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Basic ")?;
    let decoded = String::from_utf8(STANDARD.decode(value).ok()?).ok()?;
    let (id, secret) = decoded.split_once(':')?;
    let decode = |s: &str| {
        url::form_urlencoded::parse(s.as_bytes())
            .next()
            .map(|(k, _)| k.into_owned())
            .unwrap_or_default()
    };
    Some((decode(id), decode(secret)))
}

async fn token(
    State(state): State<Arc<Mutex<Realm>>>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let mut realm = state.lock().unwrap();
    realm.token_hits += 1;
    if let Some(status) = realm.token_status {
        return oauth_error(status, "temporarily_unavailable");
    }

    let (id, secret) = match basic(&headers) {
        Some(credentials) => {
            realm.last_basic = Some(credentials.clone());
            credentials
        }
        None => (
            form.get("client_id").cloned().unwrap_or_default(),
            form.get("client_secret").cloned().unwrap_or_default(),
        ),
    };
    if id != CLIENT_ID || secret != SECRET {
        return oauth_error(401, "invalid_client");
    }

    let access = |realm: &mut Realm, n: usize| {
        realm.signer.access_token(
            CLIENT_ID,
            "https://api.example.com",
            "openid profile",
            &format!("user-{n}"),
        )
    };

    match form.get("grant_type").map(String::as_str) {
        Some("authorization_code") => {
            let Some((challenge, nonce)) =
                form.get("code").and_then(|code| realm.codes.remove(code))
            else {
                return oauth_error(400, "invalid_grant");
            };
            let verifier = form.get("code_verifier").cloned().unwrap_or_default();
            if URL_SAFE_NO_PAD.encode(digest(&SHA256, verifier.as_bytes())) != challenge
                || form.get("redirect_uri").map(String::as_str) != Some(REDIRECT)
            {
                return oauth_error(400, "invalid_grant");
            }
            let mut claims = realm.signer.id_token_claims(CLIENT_ID, &nonce, "user-1");
            if let Some(mutator) = &realm.id_claims {
                mutator(&mut claims);
            }
            let id_token = realm.signer.sign(None, &claims);
            let refresh = "refresh-1".to_owned();
            realm.refresh_tokens.push(refresh.clone());
            Json(json!({
                "access_token": access(&mut realm, 1), "token_type": "Bearer", "expires_in": 900,
                "scope": "openid profile", "refresh_token": refresh, "id_token": id_token,
            }))
            .into_response()
        }
        Some("refresh_token") => {
            let presented = form.get("refresh_token").cloned().unwrap_or_default();
            if !realm.refresh_tokens.contains(&presented) {
                return oauth_error(400, "invalid_grant");
            }
            // Rotation only on the first use; the second answer omits the refresh token.
            let mut body = json!({ "access_token": access(&mut realm, 2), "token_type": "Bearer", "expires_in": 900 });
            if presented == "refresh-1" {
                body["refresh_token"] = json!("refresh-2");
                realm.refresh_tokens.push("refresh-2".into());
            }
            Json(body).into_response()
        }
        Some("client_credentials") => {
            realm.counter += 1;
            let n = realm.counter;
            Json(json!({ "access_token": format!("machine-{n}"), "token_type": "Bearer", "expires_in": 900, "scope": form.get("scope") })).into_response()
        }
        _ => oauth_error(400, "unsupported_grant_type"),
    }
}

async fn userinfo(headers: HeaderMap) -> Response {
    match headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()) {
        Some("Bearer good") => Json(json!({ "sub": "user-1", "name": "Test User", "email": "t@example.com", "email_verified": true, "locale": "de" })).into_response(),
        _ => oauth_error(401, "invalid_token"),
    }
}

async fn introspect(headers: HeaderMap, Form(form): Form<HashMap<String, String>>) -> Response {
    if basic(&headers).is_none() && form.get("client_secret").map(String::as_str) != Some(SECRET) {
        return oauth_error(401, "invalid_client");
    }
    match form.get("token").map(String::as_str) {
        Some("good") => Json(json!({ "active": true, "scope": "openid", "client_id": CLIENT_ID, "sub": "user-1", "exp": 4_102_444_800_i64, "aud": ["a"] })).into_response(),
        _ => Json(json!({ "active": false })).into_response(),
    }
}
