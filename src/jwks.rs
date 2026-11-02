//! The realm's signing keys, with a two-level cache and rotation handling.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::cache::Cache;
use crate::error::{Error, ProviderError, TokenError};
use crate::jwt::{b64_decode, b64_encode};

/// An RSA public key: big-endian modulus and exponent.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Key {
    kid: String,
    n: String,
    e: String,
}

type Keys = Arc<HashMap<String, Key>>;

#[derive(Default)]
struct State {
    keys: Option<(Keys, Instant)>,
    last_fetch: Option<Instant>,
}

pub(crate) struct JwksKeys {
    http: reqwest::Client,
    url: String,
    cache: Arc<dyn Cache>,
    cache_key: String,
    ttl: Duration,
    cooldown: Duration,
    state: Mutex<State>,
}

impl JwksKeys {
    pub(crate) fn new(
        http: reqwest::Client,
        issuer: &str,
        cache: Arc<dyn Cache>,
        ttl: Duration,
        cooldown: Duration,
    ) -> Self {
        Self {
            http,
            url: format!("{issuer}/.well-known/jwks.json"),
            cache,
            cache_key: format!("lock.jwks.{}", b64_encode(issuer)),
            ttl,
            cooldown,
            state: Mutex::new(State::default()),
        }
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// The `(n, e)` of the key with this `kid`. An unknown `kid` refetches the key set, so a
    /// rotated key is picked up; the refetch is rate limited so a flood of tokens with random
    /// `kid`s cannot turn into a flood of requests to Lock.
    pub(crate) async fn public_key(&self, kid: &str) -> Result<(Vec<u8>, Vec<u8>), Error> {
        let fresh = {
            let state = self.state();
            state
                .keys
                .as_ref()
                .filter(|(_, at)| at.elapsed() < self.ttl)
                .map(|(keys, _)| keys.clone())
        };
        if let Some(key) = fresh.as_ref().and_then(|keys| keys.get(kid)) {
            return decode(key);
        }

        if let Some(keys) = self.cached().await {
            self.state().keys = Some((keys.clone(), Instant::now()));
            if let Some(key) = keys.get(kid) {
                return decode(key);
            }
        }

        let may_fetch = self
            .state()
            .last_fetch
            .is_none_or(|at| at.elapsed() >= self.cooldown);
        if may_fetch {
            let keys = self.fetch().await?;
            if let Some(key) = keys.get(kid) {
                return decode(key);
            }
        }

        Err(TokenError::UnknownKey {
            kid: kid.to_owned(),
        }
        .into())
    }

    async fn cached(&self) -> Option<Keys> {
        let raw = self.cache.get(&self.cache_key).await?;
        let list: Vec<Key> = serde_json::from_str(&raw).ok()?;
        Some(Arc::new(
            list.into_iter().map(|key| (key.kid.clone(), key)).collect(),
        ))
    }

    async fn fetch(&self) -> Result<Keys, Error> {
        self.state().last_fetch = Some(Instant::now());

        let failed = |message: &str| ProviderError::new(message.to_owned());
        let response = self
            .http
            .get(&self.url)
            .send()
            .await
            .map_err(|e| failed("The JWKS could not be fetched.").with_source(e))?;
        let status = response.status();
        if !status.is_success() {
            return Err(failed("The JWKS could not be fetched.")
                .with_status(Some(status.as_u16()))
                .into());
        }
        let document: Jwks = response.json().await.map_err(|e| {
            failed("The JWKS is not valid JSON.")
                .with_status(Some(status.as_u16()))
                .with_source(e)
        })?;

        let mut keys = HashMap::new();
        for jwk in document.keys {
            // Lock publishes RS256 signing keys only; skip anything else a realm might add.
            if jwk.kty != "RSA"
                || jwk.alg.as_deref().is_some_and(|alg| alg != "RS256")
                || jwk.r#use.as_deref().is_some_and(|usage| usage != "sig")
            {
                continue;
            }
            let (Some(kid), Some(n), Some(e)) = (jwk.kid, jwk.n, jwk.e) else {
                continue;
            };
            keys.insert(kid.clone(), Key { kid, n, e });
        }

        let list: Vec<&Key> = keys.values().collect();
        if let Ok(raw) = serde_json::to_string(&list) {
            self.cache.set(&self.cache_key, raw, self.ttl).await;
        }
        let keys = Arc::new(keys);
        self.state().keys = Some((keys.clone(), Instant::now()));

        Ok(keys)
    }
}

fn decode(key: &Key) -> Result<(Vec<u8>, Vec<u8>), Error> {
    match (b64_decode(&key.n), b64_decode(&key.e)) {
        (Some(n), Some(e)) => Ok((n, e)),
        _ => Err(ProviderError::new(format!(
            "The JWKS key [{}] is not a valid RSA key.",
            key.kid
        ))
        .into()),
    }
}

#[derive(Deserialize)]
struct Jwks {
    keys: Vec<Jwk>,
}

#[derive(Deserialize)]
struct Jwk {
    kty: String,
    kid: Option<String>,
    alg: Option<String>,
    r#use: Option<String>,
    n: Option<String>,
    e: Option<String>,
}
