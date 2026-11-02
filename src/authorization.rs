//! The authorization code flow with PKCE and the RP-initiated logout URL.

use std::collections::HashMap;
use std::sync::Arc;

use aws_lc_rs::digest::{SHA256, digest};
use aws_lc_rs::rand::fill;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::error::Error;
use crate::jwt::b64_encode;
use crate::realm::Inner;
use crate::token_set::TokenSet;

/// The redirect URL plus the secrets the callback is checked against. Store it (for example in
/// the session) between the redirect and the callback; it serializes.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizationRequest {
    /// Where to send the browser.
    pub url: String,
    /// The `state` the callback must return.
    pub state: String,
    /// The `nonce` the ID token must carry.
    pub nonce: String,
    /// The PKCE verifier for the code exchange.
    pub code_verifier: String,
}

impl std::fmt::Debug for AuthorizationRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthorizationRequest")
            .field("url", &self.url)
            .finish_non_exhaustive()
    }
}

/// Optional authorization request parameters.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct AuthorizeOptions {
    /// `prompt`: `none`, `login`, `consent`.
    pub prompt: Option<String>,
    /// `max_age` in seconds.
    pub max_age: Option<u64>,
    /// `acr_values`.
    pub acr_values: Option<String>,
    /// `id_token_hint`.
    pub id_token_hint: Option<String>,
    /// RFC 8707 `resource` indicators.
    pub resources: Vec<String>,
}

/// The query of an authorization callback.
#[derive(Debug, Clone, Default)]
pub struct CallbackParams(HashMap<String, String>);

impl CallbackParams {
    fn get(&self, name: &str) -> Option<&str> {
        self.0.get(name).map(String::as_str)
    }
}

impl From<&str> for CallbackParams {
    /// Parses a raw query string, with or without the leading `?`.
    fn from(query: &str) -> Self {
        Self(
            url::form_urlencoded::parse(query.trim_start_matches('?').as_bytes())
                .into_owned()
                .collect(),
        )
    }
}

impl From<HashMap<String, String>> for CallbackParams {
    fn from(params: HashMap<String, String>) -> Self {
        Self(params)
    }
}

impl From<&HashMap<String, String>> for CallbackParams {
    fn from(params: &HashMap<String, String>) -> Self {
        Self(params.clone())
    }
}

impl From<Vec<(String, String)>> for CallbackParams {
    fn from(params: Vec<(String, String)>) -> Self {
        Self(params.into_iter().collect())
    }
}

/// Starts and completes logins and builds logout URLs.
#[derive(Clone)]
pub struct Authorization {
    pub(crate) inner: Arc<Inner>,
}

fn random(bytes: usize) -> Result<Vec<u8>, Error> {
    let mut buffer = vec![0u8; bytes];
    fill(&mut buffer).map_err(|_| Error::Config("the system random generator failed".into()))?;
    Ok(buffer)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn constant_time_eq(a: &str, b: &str) -> bool {
    a.len() == b.len()
        && a.bytes()
            .zip(b.bytes())
            .fold(0u8, |diff, (x, y)| diff | (x ^ y))
            == 0
}

impl Authorization {
    /// Builds the authorization request for `scopes`, with a fresh state, nonce and PKCE pair.
    pub fn begin(&self, scopes: &[&str]) -> Result<AuthorizationRequest, Error> {
        self.begin_with(scopes, &AuthorizeOptions::default())
    }

    /// [`begin`](Self::begin) with extra parameters.
    pub fn begin_with(
        &self,
        scopes: &[&str],
        options: &AuthorizeOptions,
    ) -> Result<AuthorizationRequest, Error> {
        let state = hex(&random(16)?);
        let nonce = hex(&random(16)?);
        let code_verifier = b64_encode(random(32)?);
        let challenge = b64_encode(digest(&SHA256, code_verifier.as_bytes()));
        let redirect_uri = self.redirect_uri()?;

        let mut url = Url::parse(&self.inner.endpoint("/oauth/authorize"))
            .map_err(|e| Error::Config(format!("the realm URL is invalid: {e}")))?;
        {
            let mut query = url.query_pairs_mut();
            query
                .append_pair("client_id", &self.inner.client_id)
                .append_pair("response_type", "code")
                .append_pair("code_challenge", &challenge)
                .append_pair("code_challenge_method", "S256")
                .append_pair("redirect_uri", redirect_uri)
                .append_pair("scope", &scopes.join(" "))
                .append_pair("state", &state)
                .append_pair("nonce", &nonce);
            if let Some(prompt) = &options.prompt {
                query.append_pair("prompt", prompt);
            }
            if let Some(max_age) = options.max_age {
                query.append_pair("max_age", &max_age.to_string());
            }
            if let Some(acr) = &options.acr_values {
                query.append_pair("acr_values", acr);
            }
            if let Some(hint) = &options.id_token_hint {
                query.append_pair("id_token_hint", hint);
            }
            for resource in &options.resources {
                query.append_pair("resource", resource);
            }
        }

        Ok(AuthorizationRequest {
            url: url.into(),
            state,
            nonce,
            code_verifier,
        })
    }

    /// Checks the callback, exchanges the code and validates the ID token (signature, issuer,
    /// audience, expiry, nonce). The returned [`TokenSet`] carries the validated `claims`.
    pub async fn complete(
        &self,
        request: &AuthorizationRequest,
        callback: impl Into<CallbackParams>,
    ) -> Result<TokenSet, Error> {
        let query = callback.into();

        if let Some(error) = query.get("error") {
            return Err(Error::Authorization {
                error: error.to_owned(),
                description: query.get("error_description").map(str::to_owned),
            });
        }
        if !query
            .get("state")
            .is_some_and(|state| constant_time_eq(&request.state, state))
        {
            return Err(Error::StateMismatch);
        }
        // RFC 9207: Lock announces `authorization_response_iss_parameter_supported`.
        if let Some(iss) = query.get("iss")
            && iss.trim_end_matches('/') != self.inner.url
        {
            return Err(Error::CallbackIssuerMismatch);
        }
        let code = query
            .get("code")
            .filter(|code| !code.is_empty())
            .ok_or(Error::MissingCode)?;

        let tokens = crate::Tokens {
            inner: self.inner.clone(),
        }
        .authorization_code(code, self.redirect_uri()?, &request.code_verifier)
        .await?;
        let id_token = tokens.id_token.clone().ok_or(Error::MissingIdToken)?;
        let claims = crate::IdTokenValidator {
            inner: self.inner.clone(),
        }
        .validate(&id_token, &request.nonce)
        .await?;

        Ok(TokenSet {
            claims: Some(claims),
            ..tokens
        })
    }

    /// The RP-initiated logout URL (`/oauth/logout`). Redirect the browser to it.
    pub fn logout_url(
        &self,
        id_token_hint: Option<&str>,
        post_logout_redirect_uri: Option<&str>,
        state: Option<&str>,
    ) -> Result<String, Error> {
        let mut url = Url::parse(&self.inner.endpoint("/oauth/logout"))
            .map_err(|e| Error::Config(format!("the realm URL is invalid: {e}")))?;
        {
            let mut query = url.query_pairs_mut();
            if let Some(hint) = id_token_hint {
                query.append_pair("id_token_hint", hint);
            }
            query.append_pair("client_id", &self.inner.client_id);
            if let Some(uri) = post_logout_redirect_uri {
                query.append_pair("post_logout_redirect_uri", uri);
            }
            if let Some(state) = state {
                query.append_pair("state", state);
            }
        }
        Ok(url.into())
    }

    fn redirect_uri(&self) -> Result<&str, Error> {
        self.inner
            .redirect_uri
            .as_deref()
            .ok_or_else(|| Error::Config("the authorization flow needs a redirect URI".into()))
    }
}
