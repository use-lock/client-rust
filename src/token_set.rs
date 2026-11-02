use serde::{Deserialize, Serialize};

use crate::claims::IdTokenClaims;

pub(crate) fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX)
        })
}

/// The tokens of a grant. Serializable, so an app can keep it in its session.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct TokenSet {
    /// The access token.
    pub access_token: String,
    /// When the access token expires, seconds since the Unix epoch.
    pub expires_at: i64,
    /// The refresh token, when one was issued.
    pub refresh_token: Option<String>,
    /// The ID token, when the grant issued one.
    pub id_token: Option<String>,
    /// The scopes the token endpoint granted; `None` when the response did not say.
    pub scopes: Option<Vec<String>>,
    /// The validated ID token claims, set after a completed login.
    pub claims: Option<IdTokenClaims>,
}

impl std::fmt::Debug for TokenSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenSet")
            .field("expires_at", &self.expires_at)
            .field("scopes", &self.scopes)
            .field("claims", &self.claims)
            .finish_non_exhaustive()
    }
}

impl TokenSet {
    /// Seconds until the access token expires, zero once it has.
    pub fn expires_in(&self) -> u64 {
        u64::try_from(self.expires_at - now()).unwrap_or(0)
    }

    /// Whether the access token expires within `skew` seconds.
    pub fn is_expired(&self, skew: i64) -> bool {
        self.expires_at <= now() + skew
    }

    /// Whether `scope` was granted. False while the granted scopes are unknown.
    pub fn has_scope(&self, scope: &str) -> bool {
        self.scopes
            .as_ref()
            .is_some_and(|scopes| scopes.iter().any(|granted| granted == scope))
    }
}
