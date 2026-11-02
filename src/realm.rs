//! The realm configuration and its entry points.

use std::sync::Arc;
use std::time::Duration;

use serde::Deserialize;
use serde_json::{Map, Value};

use crate::authorization::Authorization;
use crate::cache::{Cache, MemoryCache};
use crate::error::{Error, ProviderError};
use crate::jwks::JwksKeys;
use crate::tokens::{Tokens, form_encode};
use crate::validate::{
    AccessTokenValidator, IdTokenValidator, LogoutTokenReplay, LogoutTokenValidator,
};

pub(crate) struct Inner {
    pub(crate) url: String,
    pub(crate) client_id: String,
    pub(crate) client_secret: Option<String>,
    pub(crate) redirect_uri: Option<String>,
    pub(crate) basic_auth: bool,
    pub(crate) http: reqwest::Client,
    pub(crate) cache: Arc<dyn Cache>,
    pub(crate) leeway: i64,
    pub(crate) keys: JwksKeys,
}

impl Inner {
    pub(crate) fn endpoint(&self, path: &str) -> String {
        format!("{}{path}", self.url)
    }

    /// Adds the client credentials to a request: a Basic header, or form fields.
    pub(crate) fn authenticate(
        &self,
        request: reqwest::RequestBuilder,
        mut form: Vec<(&'static str, String)>,
    ) -> (reqwest::RequestBuilder, Vec<(&'static str, String)>) {
        if self.basic_auth {
            let secret = self.client_secret.as_deref().map(form_encode);
            (
                request.basic_auth(form_encode(&self.client_id), secret),
                form,
            )
        } else {
            form.push(("client_id", self.client_id.clone()));
            if let Some(secret) = &self.client_secret {
                form.push(("client_secret", secret.clone()));
            }
            (request, form)
        }
    }
}

/// A client registered in one Lock realm. The realm URL is both the host of the protocol
/// endpoints and the issuer of every token the realm mints.
///
/// Cheap to clone; clones share the HTTP client, the cache and the loaded signing keys.
#[derive(Clone)]
pub struct Realm {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for Realm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Realm")
            .field("url", &self.inner.url)
            .field("client_id", &self.inner.client_id)
            .finish_non_exhaustive()
    }
}

impl Realm {
    /// Starts a configuration for the client `client_id` of the realm at `url`.
    pub fn builder(url: impl Into<String>, client_id: impl Into<String>) -> RealmBuilder {
        RealmBuilder {
            url: url.into(),
            client_id: client_id.into(),
            client_secret: None,
            redirect_uri: None,
            basic_auth: false,
            cache: None,
            http: None,
            leeway: Duration::from_secs(60),
            jwks_ttl: Duration::from_secs(3600),
            jwks_refresh_cooldown: Duration::from_secs(10),
        }
    }

    /// The realm URL, without a trailing slash.
    pub fn url(&self) -> &str {
        &self.inner.url
    }

    /// The client id.
    pub fn client_id(&self) -> &str {
        &self.inner.client_id
    }

    /// The authorization code flow with PKCE and the logout URL. Needs a redirect URI.
    pub fn authorization(&self) -> Result<Authorization, Error> {
        if self.inner.redirect_uri.is_none() {
            return Err(Error::Config(
                "the authorization flow needs a redirect URI".into(),
            ));
        }
        Ok(Authorization {
            inner: self.inner.clone(),
        })
    }

    /// Token grants, userinfo, introspection and revocation.
    pub fn tokens(&self) -> Tokens {
        Tokens {
            inner: self.inner.clone(),
        }
    }

    /// Validates ID tokens.
    pub fn id_tokens(&self) -> IdTokenValidator {
        IdTokenValidator {
            inner: self.inner.clone(),
        }
    }

    /// Validates JWT access tokens.
    pub fn access_tokens(&self) -> AccessTokenValidator {
        AccessTokenValidator {
            inner: self.inner.clone(),
        }
    }

    /// Validates back-channel logout tokens.
    pub fn logout_tokens(&self) -> LogoutTokenValidator {
        LogoutTokenValidator {
            inner: self.inner.clone(),
        }
    }

    /// Replay protection for logout tokens, backed by the realm's cache.
    pub fn logout_token_replay(&self) -> LogoutTokenReplay {
        LogoutTokenReplay::new(self.inner.cache.clone())
    }

    /// Fetches the realm's OpenID Connect discovery document.
    pub async fn metadata(&self) -> Result<ProviderMetadata, Error> {
        let failed = |message: &str| ProviderError::new(message.to_owned());
        let response = self
            .inner
            .http
            .get(self.inner.endpoint("/.well-known/openid-configuration"))
            .send()
            .await
            .map_err(|e| failed("The discovery document could not be fetched.").with_source(e))?;
        let status = response.status();
        if !status.is_success() {
            return Err(failed("The discovery document could not be fetched.")
                .with_status(Some(status.as_u16()))
                .into());
        }
        Ok(response.json().await.map_err(|e| {
            failed("The discovery document is not valid.")
                .with_status(Some(status.as_u16()))
                .with_source(e)
        })?)
    }
}

/// The parts of the discovery document an app commonly needs.
#[derive(Debug, Clone, Deserialize)]
pub struct ProviderMetadata {
    /// The issuer.
    pub issuer: String,
    /// `/oauth/authorize`.
    pub authorization_endpoint: String,
    /// `/oauth/token`.
    pub token_endpoint: String,
    /// `/.well-known/jwks.json`.
    pub jwks_uri: String,
    /// `/oauth/userinfo`, when served.
    #[serde(default)]
    pub userinfo_endpoint: Option<String>,
    /// `/oauth/logout`, when served.
    #[serde(default)]
    pub end_session_endpoint: Option<String>,
    /// The scopes the realm offers.
    #[serde(default)]
    pub scopes_supported: Vec<String>,
    /// The claims the realm can return.
    #[serde(default)]
    pub claims_supported: Vec<String>,
    /// Everything else.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Builds a [`Realm`].
pub struct RealmBuilder {
    url: String,
    client_id: String,
    client_secret: Option<String>,
    redirect_uri: Option<String>,
    basic_auth: bool,
    cache: Option<Arc<dyn Cache>>,
    http: Option<reqwest::Client>,
    leeway: Duration,
    jwks_ttl: Duration,
    jwks_refresh_cooldown: Duration,
}

impl RealmBuilder {
    /// The client secret; omit for public clients.
    pub fn client_secret(mut self, secret: impl Into<String>) -> Self {
        self.client_secret = Some(secret.into());
        self
    }

    /// The redirect URI registered for the login flow.
    pub fn redirect_uri(mut self, uri: impl Into<String>) -> Self {
        self.redirect_uri = Some(uri.into());
        self
    }

    /// Authenticate with `client_secret_basic` instead of `client_secret_post`.
    pub fn basic_auth(mut self, enabled: bool) -> Self {
        self.basic_auth = enabled;
        self
    }

    /// Where signing keys and client credentials tokens are kept. Defaults to a process-local
    /// [`MemoryCache`](crate::MemoryCache). Share one across instances to avoid refetching.
    pub fn cache(mut self, cache: Arc<dyn Cache>) -> Self {
        self.cache = Some(cache);
        self
    }

    /// The HTTP client, to set timeouts, proxies or test transports. Defaults to a client with a
    /// 10 second timeout.
    pub fn http_client(mut self, client: reqwest::Client) -> Self {
        self.http = Some(client);
        self
    }

    /// Clock skew tolerated in `exp`, `nbf` and `iat`. Defaults to 60 seconds.
    pub fn leeway(mut self, leeway: Duration) -> Self {
        self.leeway = leeway;
        self
    }

    /// How long a fetched key set is trusted. Defaults to one hour.
    pub fn jwks_ttl(mut self, ttl: Duration) -> Self {
        self.jwks_ttl = ttl;
        self
    }

    /// The shortest time between two key set fetches caused by unknown `kid`s. Defaults to
    /// 10 seconds; a rotation is picked up at the next token after it elapses.
    pub fn jwks_refresh_cooldown(mut self, cooldown: Duration) -> Self {
        self.jwks_refresh_cooldown = cooldown;
        self
    }

    /// Validates the configuration and builds the realm.
    pub fn build(self) -> Result<Realm, Error> {
        let url = self.url.trim().trim_end_matches('/').to_owned();
        let parsed = url::Url::parse(&url)
            .map_err(|e| Error::Config(format!("the realm URL is invalid: {e}")))?;
        if !matches!(parsed.scheme(), "http" | "https") {
            return Err(Error::Config("the realm URL must be http or https".into()));
        }
        if self.client_id.is_empty() {
            return Err(Error::Config("the client id is empty".into()));
        }
        if self.basic_auth && self.client_secret.is_none() {
            return Err(Error::Config("basic auth needs a client secret".into()));
        }
        if let Some(uri) = &self.redirect_uri {
            url::Url::parse(uri)
                .map_err(|e| Error::Config(format!("the redirect URI is invalid: {e}")))?;
        }

        let http = match self.http {
            Some(http) => http,
            None => reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .map_err(|e| Error::Config(format!("the HTTP client could not be built: {e}")))?,
        };
        let cache = self.cache.unwrap_or_else(|| Arc::new(MemoryCache::new()));
        let keys = JwksKeys::new(
            http.clone(),
            &url,
            cache.clone(),
            self.jwks_ttl,
            self.jwks_refresh_cooldown,
        );

        Ok(Realm {
            inner: Arc::new(Inner {
                url,
                client_id: self.client_id,
                client_secret: self.client_secret,
                redirect_uri: self.redirect_uri,
                basic_auth: self.basic_auth,
                http,
                cache,
                leeway: i64::try_from(self.leeway.as_secs()).unwrap_or(i64::MAX),
                keys,
            }),
        })
    }
}
