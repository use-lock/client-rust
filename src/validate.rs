//! Validation of the tokens a realm issues: ID, access and back-channel logout tokens.

use std::sync::Arc;
use std::time::Duration;

use serde_json::{Map, Value};

use crate::cache::Cache;
use crate::claims::{AccessTokenClaims, IdTokenClaims, LogoutToken};
use crate::error::{Error, TokenError};
use crate::jwt::Jwt;
use crate::realm::Inner;
use crate::token_set::now;

const LOGOUT_EVENT: &str = "http://schemas.openid.net/event/backchannel-logout";

/// Parses a token, verifies its RS256 signature against the realm keys and checks the issuer.
/// The caller checks the audience and the time claims, which differ per token kind.
async fn verify(
    inner: &Inner,
    token: &str,
    name: &'static str,
    check_header: impl FnOnce(&Jwt) -> Result<(), TokenError>,
) -> Result<Jwt, Error> {
    let jwt = Jwt::parse(token, name)?;
    check_header(&jwt)?;
    let kid = jwt
        .kid()
        .ok_or(TokenError::MissingKeyId { name })?
        .to_owned();

    let (n, e) = inner.keys.public_key(&kid).await?;
    if !jwt.verify(&n, &e) {
        return Err(TokenError::InvalidSignature { name }.into());
    }

    let issuer = jwt
        .claims
        .get("iss")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if issuer.trim_end_matches('/') != inner.url.trim_end_matches('/') {
        return Err(TokenError::IssuerMismatch { name }.into());
    }

    Ok(jwt)
}

fn audiences(claims: &Map<String, Value>) -> Vec<&str> {
    match claims.get("aud") {
        Some(Value::String(one)) => vec![one.as_str()],
        Some(Value::Array(many)) => many.iter().filter_map(Value::as_str).collect(),
        _ => Vec::new(),
    }
}

fn timestamp(
    claims: &Map<String, Value>,
    claim: &'static str,
    name: &'static str,
) -> Result<Option<i64>, TokenError> {
    match claims.get(claim) {
        None | Some(Value::Null) => Ok(None),
        // `as i64` saturates for floats, which is the intended clamp for absurd values.
        Some(Value::Number(number)) => Ok(number
            .as_i64()
            .or_else(|| number.as_f64().map(|f| f as i64))),
        Some(_) => Err(TokenError::MissingClaim { name, claim }),
    }
}

fn required(
    claims: &Map<String, Value>,
    claim: &'static str,
    name: &'static str,
) -> Result<i64, TokenError> {
    timestamp(claims, claim, name)?.ok_or(TokenError::MissingClaim { name, claim })
}

fn deserialize<T: serde::de::DeserializeOwned>(
    claims: Map<String, Value>,
    name: &'static str,
) -> Result<T, TokenError> {
    serde_json::from_value(Value::Object(claims)).map_err(|_| TokenError::Malformed { name })
}

/// Validates ID tokens.
#[derive(Clone)]
pub struct IdTokenValidator {
    pub(crate) inner: Arc<Inner>,
}

impl IdTokenValidator {
    /// Checks signature, issuer, audience, `azp`, nonce and the time claims.
    pub async fn validate(
        &self,
        id_token: &str,
        expected_nonce: &str,
    ) -> Result<IdTokenClaims, Error> {
        const NAME: &str = "id_token";
        let inner = &self.inner;
        let jwt = verify(inner, id_token, NAME, |_| Ok(())).await?;
        let claims = &jwt.claims;
        let now = now();
        let leeway = inner.leeway;

        let aud = audiences(claims);
        if !aud.contains(&inner.client_id.as_str()) {
            return Err(TokenError::AudienceMismatch { name: NAME }.into());
        }

        if claims
            .get("sub")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        {
            return Err(TokenError::MissingClaim {
                name: NAME,
                claim: "sub",
            }
            .into());
        }

        let azp = claims.get("azp");
        if (aud.len() > 1 || azp.is_some())
            && azp.and_then(Value::as_str) != Some(inner.client_id.as_str())
        {
            return Err(TokenError::AuthorizedPartyMismatch { name: NAME }.into());
        }

        if claims.get("nonce").and_then(Value::as_str) != Some(expected_nonce) {
            return Err(TokenError::NonceMismatch { name: NAME }.into());
        }

        if now > required(claims, "exp", NAME)? + leeway {
            return Err(TokenError::Expired { name: NAME }.into());
        }
        if timestamp(claims, "nbf", NAME)?.is_some_and(|nbf| now + leeway < nbf) {
            return Err(TokenError::NotYetValid { name: NAME }.into());
        }
        if now + leeway < required(claims, "iat", NAME)? {
            return Err(TokenError::IssuedInFuture { name: NAME }.into());
        }

        Ok(deserialize(jwt.claims, NAME)?)
    }
}

/// Validates JWT access tokens.
///
/// A signature check cannot see a revocation: Lock keeps its access tokens in a database and
/// can revoke one before it expires. Use [`Tokens::introspect`](crate::Tokens::introspect)
/// where that matters.
#[derive(Clone)]
pub struct AccessTokenValidator {
    pub(crate) inner: Arc<Inner>,
}

impl AccessTokenValidator {
    /// Checks the `at+jwt` type, signature, issuer, expiry and that the token is addressed to
    /// one of `audiences`. Lock puts the realm's resource identifiers in `aud`, not the client id.
    pub async fn validate(
        &self,
        access_token: &str,
        audiences_accepted: &[&str],
    ) -> Result<AccessTokenClaims, Error> {
        const NAME: &str = "access_token";
        let inner = &self.inner;
        let jwt = verify(inner, access_token, NAME, |jwt| match jwt.typ() {
            Some(typ)
                if typ.eq_ignore_ascii_case("at+jwt")
                    || typ.eq_ignore_ascii_case("application/at+jwt") =>
            {
                Ok(())
            }
            _ => Err(TokenError::UnexpectedType { name: NAME }),
        })
        .await?;
        let claims = &jwt.claims;
        let now = now();
        let leeway = inner.leeway;

        if !audiences(claims)
            .iter()
            .any(|aud| audiences_accepted.contains(aud))
        {
            return Err(TokenError::AudienceMismatch { name: NAME }.into());
        }
        if now > required(claims, "exp", NAME)? + leeway {
            return Err(TokenError::Expired { name: NAME }.into());
        }
        if timestamp(claims, "nbf", NAME)?.is_some_and(|nbf| now + leeway < nbf) {
            return Err(TokenError::NotYetValid { name: NAME }.into());
        }
        if claims
            .get("sub")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        {
            return Err(TokenError::MissingClaim {
                name: NAME,
                claim: "sub",
            }
            .into());
        }

        Ok(deserialize(jwt.claims, NAME)?)
    }
}

/// Validates back-channel logout tokens.
#[derive(Clone)]
pub struct LogoutTokenValidator {
    pub(crate) inner: Arc<Inner>,
}

impl LogoutTokenValidator {
    /// Checks signature, issuer, audience, the logout event and the time claims. The caller
    /// must still reject a replayed `jti`; see [`LogoutTokenReplay`].
    pub async fn validate(&self, logout_token: &str) -> Result<LogoutToken, Error> {
        const NAME: &str = "logout_token";
        let inner = &self.inner;
        let jwt = verify(inner, logout_token, NAME, |jwt| match jwt.typ() {
            None => Ok(()),
            Some(typ) if typ.eq_ignore_ascii_case("logout+jwt") => Ok(()),
            Some(_) => Err(TokenError::UnexpectedType { name: NAME }),
        })
        .await?;
        let claims = &jwt.claims;
        let now = now();
        let leeway = inner.leeway;

        if !audiences(claims).contains(&inner.client_id.as_str()) {
            return Err(TokenError::AudienceMismatch { name: NAME }.into());
        }
        if claims.contains_key("nonce") {
            return Err(TokenError::LogoutTokenNonce.into());
        }
        if !claims
            .get("events")
            .and_then(Value::as_object)
            .is_some_and(|events| events.contains_key(LOGOUT_EVENT))
        {
            return Err(TokenError::MissingLogoutEvent.into());
        }

        let exp = required(claims, "exp", NAME)?;
        if now > exp + leeway {
            return Err(TokenError::Expired { name: NAME }.into());
        }
        if now - required(claims, "iat", NAME)? > leeway + 300 {
            return Err(TokenError::IssuedTooLongAgo { name: NAME }.into());
        }

        let sid = claims
            .get("sid")
            .and_then(Value::as_str)
            .filter(|sid| !sid.is_empty())
            .ok_or(TokenError::MissingClaim {
                name: NAME,
                claim: "sid",
            })?;
        let text = |claim| claims.get(claim).and_then(Value::as_str);

        Ok(LogoutToken {
            sid: sid.to_owned(),
            sub: text("sub").unwrap_or_default().to_owned(),
            jti: text("jti").filter(|jti| !jti.is_empty()).map(str::to_owned),
            exp,
        })
    }
}

/// Back-channel Logout section 2.6 replay protection: each logout token `jti` is accepted once.
#[derive(Clone)]
pub struct LogoutTokenReplay {
    cache: Arc<dyn Cache>,
    retention: Duration,
}

impl LogoutTokenReplay {
    /// Remembers consumed `jti`s in `cache`, for two hours at least.
    pub fn new(cache: Arc<dyn Cache>) -> Self {
        Self {
            cache,
            retention: Duration::from_secs(7200),
        }
    }

    /// Overrides the minimum time a `jti` is remembered.
    pub fn with_retention(mut self, retention: Duration) -> Self {
        self.retention = retention;
        self
    }

    /// Returns `false` when the `jti` was already consumed. It is remembered until the later of
    /// the token's `exp` and the retention window, which outlives the span in which the
    /// validator would still accept the token. Atomic only if the [`Cache::add`] is.
    pub async fn consume(&self, jti: &str, expires_at: i64) -> bool {
        let remaining = Duration::from_secs(u64::try_from(expires_at - now()).unwrap_or(0));
        let key = format!("lock.logout-jti.{}", crate::jwt::b64_encode(jti));
        self.cache
            .add(&key, "1".to_owned(), remaining.max(self.retention))
            .await
    }
}
