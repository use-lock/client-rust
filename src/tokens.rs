//! Token grants, userinfo, introspection and revocation against a realm.

use std::sync::Arc;
use std::time::Duration;

use serde::Deserialize;
use serde_json::Value;
use url::form_urlencoded::byte_serialize;

use crate::claims::{Introspection, UserInfo};
use crate::error::{Error, ProviderError};
use crate::jwt::b64_encode;
use crate::realm::Inner;
use crate::token_set::{TokenSet, now};

#[derive(Deserialize)]
struct TokenResponse {
    #[serde(default)]
    access_token: String,
    #[serde(default)]
    expires_in: Option<i64>,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    id_token: Option<String>,
    #[serde(default)]
    scope: Option<String>,
}

#[derive(Deserialize)]
struct OAuthError {
    error: Option<String>,
}

/// The token endpoint and the other client-authenticated endpoints of a realm. The client
/// authenticates with `client_secret_post`, or `client_secret_basic` when the realm is
/// configured with [`RealmBuilder::basic_auth`](crate::RealmBuilder::basic_auth).
#[derive(Clone)]
pub struct Tokens {
    pub(crate) inner: Arc<Inner>,
}

impl Tokens {
    /// Exchanges an authorization code. [`Authorization::complete`](crate::Authorization::complete)
    /// does this and validates the ID token; call this directly only for custom flows.
    pub async fn authorization_code(
        &self,
        code: &str,
        redirect_uri: &str,
        code_verifier: &str,
    ) -> Result<TokenSet, Error> {
        self.grant(
            "authorization_code",
            vec![
                ("code", code.to_owned()),
                ("redirect_uri", redirect_uri.to_owned()),
                ("code_verifier", code_verifier.to_owned()),
            ],
            None,
        )
        .await
    }

    /// Refreshes tokens. A response without a `refresh_token` keeps the one that was used.
    pub async fn refresh(
        &self,
        refresh_token: &str,
        scopes: Option<&[&str]>,
    ) -> Result<TokenSet, Error> {
        let mut params = vec![("refresh_token", refresh_token.to_owned())];
        params.extend(scope_param(scopes));
        self.grant("refresh_token", params, Some(refresh_token))
            .await
    }

    /// RFC 8693 exchange of an access token for one aimed at another audience.
    pub async fn exchange(
        &self,
        subject_token: &str,
        audience: &str,
        scopes: Option<&[&str]>,
    ) -> Result<TokenSet, Error> {
        let mut params = vec![
            ("subject_token", subject_token.to_owned()),
            (
                "subject_token_type",
                "urn:ietf:params:oauth:token-type:access_token".to_owned(),
            ),
            ("audience", audience.to_owned()),
        ];
        params.extend(scope_param(scopes));
        self.grant(
            "urn:ietf:params:oauth:grant-type:token-exchange",
            params,
            None,
        )
        .await
    }

    /// A machine token, served from the cache until 30 seconds before it expires.
    ///
    /// `resource` is the RFC 8707 target resource.
    pub async fn client_credentials(
        &self,
        resource: Option<&str>,
        scopes: Option<&[&str]>,
    ) -> Result<TokenSet, Error> {
        let mut sorted: Vec<&str> = scopes.unwrap_or_default().to_vec();
        sorted.sort_unstable();
        sorted.dedup();

        let inner = &self.inner;
        let fingerprint = serde_json::json!([inner.url, inner.client_id, resource, sorted]);
        let key = format!(
            "lock.client-credentials.{}",
            b64_encode(fingerprint.to_string())
        );

        if let Some(cached) = inner
            .cache
            .get(&key)
            .await
            .and_then(|raw| serde_json::from_str::<TokenSet>(&raw).ok())
            && !cached.is_expired(30)
        {
            return Ok(cached);
        }

        let mut params = Vec::new();
        if let Some(resource) = resource {
            params.push(("resource", resource.to_owned()));
        }
        params.extend(scope_param(
            (!sorted.is_empty()).then_some(sorted.as_slice()),
        ));
        let tokens = self.grant("client_credentials", params, None).await?;

        let ttl = tokens.expires_at - now() - 30;
        if ttl > 0
            && let Ok(raw) = serde_json::to_string(&tokens)
        {
            inner
                .cache
                .set(&key, raw, Duration::from_secs(ttl.unsigned_abs()))
                .await;
        }

        Ok(tokens)
    }

    /// Fetches the user's profile claims with an access token carrying the `openid` scope.
    pub async fn userinfo(&self, access_token: &str) -> Result<UserInfo, Error> {
        let response = self
            .inner
            .http
            .get(self.inner.endpoint("/oauth/userinfo"))
            .bearer_auth(access_token)
            .send()
            .await;
        self.parse("The userinfo endpoint", "userinfo", response)
            .await
    }

    /// RFC 7662 introspection. Unlike local validation this sees revocations.
    pub async fn introspect(&self, token: &str) -> Result<Introspection, Error> {
        let request = self
            .inner
            .http
            .post(self.inner.endpoint("/oauth/introspect"));
        let (request, form) = self
            .inner
            .authenticate(request, vec![("token", token.to_owned())]);
        let response = request.form(&form).send().await;
        self.parse("The introspection endpoint", "introspection", response)
            .await
    }

    /// RFC 7009 revocation of an access or refresh token.
    pub async fn revoke(&self, token: &str) -> Result<(), Error> {
        let request = self.inner.http.post(self.inner.endpoint("/oauth/revoke"));
        let (request, form) = self
            .inner
            .authenticate(request, vec![("token", token.to_owned())]);
        let response = request.form(&form).send().await;
        let response = Self::checked("The revocation endpoint", "revocation", response).await?;
        drop(response);
        Ok(())
    }

    async fn grant(
        &self,
        grant_type: &str,
        mut params: Vec<(&'static str, String)>,
        previous_refresh_token: Option<&str>,
    ) -> Result<TokenSet, Error> {
        params.insert(0, ("grant_type", grant_type.to_owned()));
        let request = self.inner.http.post(self.inner.endpoint("/oauth/token"));
        let (request, form) = self.inner.authenticate(request, params);
        let response = request.form(&form).send().await;
        let subject = format!("the {grant_type} grant");
        let body: TokenResponse = self.parse("The token endpoint", &subject, response).await?;

        if body.access_token.is_empty() {
            return Err(ProviderError::new(format!(
                "The token endpoint returned no access token for {subject}."
            ))
            .into());
        }

        Ok(TokenSet {
            access_token: body.access_token,
            expires_at: now() + body.expires_in.unwrap_or(60),
            refresh_token: body
                .refresh_token
                .or_else(|| previous_refresh_token.map(str::to_owned)),
            id_token: body.id_token,
            scopes: body.scope.map(|scope| {
                scope
                    .split(' ')
                    .filter(|s| !s.is_empty())
                    .map(str::to_owned)
                    .collect()
            }),
            claims: None,
        })
    }

    async fn parse<T: serde::de::DeserializeOwned>(
        &self,
        endpoint: &str,
        subject: &str,
        response: Result<reqwest::Response, reqwest::Error>,
    ) -> Result<T, Error> {
        let response = Self::checked(endpoint, subject, response).await?;
        let status = response.status().as_u16();
        let bytes = response.bytes().await.map_err(|e| {
            ProviderError::new(format!("{endpoint} could not be read for {subject}."))
                .with_source(e)
        })?;
        serde_json::from_slice::<Value>(&bytes)
            .ok()
            .and_then(|value| serde_json::from_value(value).ok())
            .ok_or_else(|| {
                ProviderError::new(format!(
                    "{endpoint} returned an unreadable response for {subject}."
                ))
                .with_status(Some(status))
                .into()
            })
    }

    /// Turns transport errors and non-2xx responses into [`ProviderError`]s.
    async fn checked(
        endpoint: &str,
        subject: &str,
        response: Result<reqwest::Response, reqwest::Error>,
    ) -> Result<reqwest::Response, Error> {
        let response = response.map_err(|e| {
            ProviderError::new(format!("{endpoint} could not be reached for {subject}."))
                .with_source(e)
        })?;
        let status = response.status();
        if status.is_success() {
            return Ok(response);
        }

        let code = response
            .bytes()
            .await
            .ok()
            .and_then(|bytes| serde_json::from_slice::<OAuthError>(&bytes).ok())
            .and_then(|e| e.error);
        let outcome = if status.is_server_error() {
            "failed on"
        } else {
            "rejected"
        };
        let suffix = code
            .as_ref()
            .map(|code| format!(" [{code}]"))
            .unwrap_or_default();

        Err(
            ProviderError::new(format!("{endpoint} {outcome} {subject}{suffix}."))
                .with_status(Some(status.as_u16()))
                .with_error(code)
                .into(),
        )
    }
}

fn scope_param(scopes: Option<&[&str]>) -> Option<(&'static str, String)> {
    scopes
        .filter(|scopes| !scopes.is_empty())
        .map(|scopes| ("scope", scopes.join(" ")))
}

/// Lock form-urlencodes the client id and secret before building the Basic credentials.
pub(crate) fn form_encode(value: &str) -> String {
    byte_serialize(value.as_bytes()).collect()
}
